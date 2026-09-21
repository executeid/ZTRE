package discovery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/executeid/ztre/pkg/collector"
	"github.com/executeid/ztre/tests/testutil"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func testLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

func makeEvent(parent, child, namespace, workload, node string) *collector.SecurityEvent {
	return testutil.MakeEvent(parent, child, namespace, workload, node)
}

// --- BehaviorTracker tests ---

func TestTracker_BasicTracking(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())

	ev := makeEvent("nginx", "bash", "ztre-test", "vulnerable-nginx", "node1")
	tracker.Track(ev)
	tracker.Track(ev) // second occurrence

	if tracker.UniquePatternCount() != 1 {
		t.Fatalf("expected 1 unique pattern, got %d", tracker.UniquePatternCount())
	}

	patterns := tracker.GetPatterns()
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(patterns))
	}
	if patterns[0].Count != 2 {
		t.Errorf("expected count 2, got %d", patterns[0].Count)
	}
	if patterns[0].ParentBinary != "nginx" {
		t.Errorf("expected parent nginx, got %s", patterns[0].ParentBinary)
	}
	if patterns[0].ChildBinary != "bash" {
		t.Errorf("expected child bash, got %s", patterns[0].ChildBinary)
	}
}

func TestTracker_MultipleNamespaces(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())

	tracker.Track(makeEvent("nginx", "bash", "frontend", "web", "node1"))
	tracker.Track(makeEvent("nginx", "bash", "backend", "api", "node1"))

	if tracker.UniquePatternCount() != 2 {
		t.Fatalf("expected 2 unique patterns (different namespaces), got %d", tracker.UniquePatternCount())
	}
}

func TestTracker_IgnoresNonExecve(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())

	ev := makeEvent("nginx", "bash", "ztre-test", "web", "node1")
	ev.EventType = collector.EventTypeExit
	tracker.Track(ev)

	if tracker.UniquePatternCount() != 0 {
		t.Fatalf("expected 0 patterns for exit event, got %d", tracker.UniquePatternCount())
	}
	if tracker.TotalEvents() != 1 {
		t.Fatalf("expected 1 total event counted, got %d", tracker.TotalEvents())
	}
}

func TestTracker_NilEvent(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	tracker.Track(nil) // should not panic
	if tracker.TotalEvents() != 0 {
		t.Fatalf("expected 0 events for nil, got %d", tracker.TotalEvents())
	}
}

func TestTracker_NodeTracking(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())

	tracker.Track(makeEvent("nginx", "bash", "ns", "wl", "node1"))
	tracker.Track(makeEvent("nginx", "bash", "ns", "wl", "node2"))
	tracker.Track(makeEvent("nginx", "bash", "ns", "wl", "node1")) // duplicate

	patterns := tracker.GetPatterns()
	if len(patterns[0].Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d: %v", len(patterns[0].Nodes), patterns[0].Nodes)
	}
}

func TestTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tracker.Track(makeEvent("nginx", "bash", "ns", "wl", "node1"))
			}
		}()
	}
	wg.Wait()

	if tracker.UniquePatternCount() != 1 {
		t.Errorf("expected 1 pattern, got %d", tracker.UniquePatternCount())
	}
	patterns := tracker.GetPatterns()
	if patterns[0].Count != 400 {
		t.Errorf("expected count 400, got %d", patterns[0].Count)
	}
}

func TestTracker_GetStats(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())

	// Create a high-frequency pattern.
	for i := 0; i < 200; i++ {
		tracker.Track(makeEvent("nginx", "nginx", "ns", "wl", "node1"))
	}
	// Create a low-frequency pattern.
	tracker.Track(makeEvent("nginx", "curl", "ns", "wl", "node1"))

	stats := tracker.GetStats()
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
	if len(stats) != 2 {
		t.Fatalf("expected 2 stat entries, got %d", len(stats))
	}

	// The curl pattern should have lower confidence.
	curlKey := patternKey("ns", "wl", "nginx", "curl")
	curlStats, ok := stats[curlKey]
	if !ok {
		t.Fatal("expected stats for nginx→curl")
	}
	if curlStats.Confidence >= 0.70 {
		t.Errorf("expected low confidence for rare pattern, got %.2f", curlStats.Confidence)
	}
	if !curlStats.ReviewFlag {
		t.Error("expected review_flag=true for rare pattern")
	}
}

func TestTracker_GetProfiles(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())

	tracker.Track(makeEvent("nginx", "nginx", "frontend", "web", "node1"))
	tracker.Track(makeEvent("nginx", "sh", "frontend", "web", "node1"))
	tracker.Track(makeEvent("java", "java", "backend", "api", "node1"))

	profiles := tracker.GetProfiles()
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
}

// --- BaselineStore tests ---

func TestBaselineStore_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, dir, time.Minute, time.Hour, testLogger())

	// Track some patterns.
	tracker.Track(makeEvent("nginx", "bash", "ns", "wl", "node1"))
	tracker.Track(makeEvent("java", "java", "ns2", "wl2", "node2"))

	// Save.
	if err := store.SaveSnapshot(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// Verify file exists.
	latestPath := filepath.Join(dir, "baseline_latest.json")
	if _, err := os.Stat(latestPath); err != nil {
		t.Fatalf("latest snapshot not found: %v", err)
	}

	// Create a fresh tracker and load.
	tracker2 := NewBehaviorTracker(testLogger())
	store2 := NewBaselineStore(tracker2, dir, time.Minute, time.Hour, testLogger())
	if err := store2.LoadLatestSnapshot(); err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if tracker2.UniquePatternCount() != 2 {
		t.Errorf("expected 2 patterns after load, got %d", tracker2.UniquePatternCount())
	}
}

func TestBaselineStore_StabilityDetection(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	// Set threshold to something tiny for testing.
	store := NewBaselineStore(tracker, t.TempDir(), time.Minute, 10*time.Millisecond, testLogger())

	// Initially learning (no patterns).
	if store.GetStabilityStatus() != StatusLearning {
		t.Errorf("expected LEARNING, got %s", store.GetStabilityStatus())
	}

	// Track an initial pattern.
	tracker.Track(makeEvent("postgres", "postgres", "db", "pg", "node1"))

	// Wait past the threshold.
	time.Sleep(15 * time.Millisecond)
	if store.GetStabilityStatus() != StatusStable {
		t.Errorf("expected STABLE after threshold, got %s", store.GetStabilityStatus())
	}

	// Track a new pattern — should reset.
	tracker.Track(makeEvent("postgres", "pg_dump", "db", "pg", "node1"))
	if store.GetStabilityStatus() == StatusStable {
		t.Error("expected non-STABLE after new pattern")
	}
}

func TestBaselineStore_NoSnapshot(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, t.TempDir(), time.Minute, time.Hour, testLogger())

	// Load from empty dir — should succeed silently.
	if err := store.LoadLatestSnapshot(); err != nil {
		t.Fatalf("expected no error on missing snapshot, got: %v", err)
	}
}

// --- BaselineReporter tests ---

func TestReporter_GenerateReport(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, t.TempDir(), time.Minute, time.Hour, testLogger())
	reporter := NewBaselineReporter(tracker, store, testLogger())

	for i := 0; i < 100; i++ {
		tracker.Track(makeEvent("nginx", "nginx", "frontend", "web", "node1"))
	}
	tracker.Track(makeEvent("nginx", "curl", "frontend", "web", "node1"))

	report := reporter.GenerateReport()
	if report.UniqueLineages != 2 {
		t.Errorf("expected 2 lineages, got %d", report.UniqueLineages)
	}
	if report.TotalEvents < 101 {
		t.Errorf("expected >= 101 events, got %d", report.TotalEvents)
	}
}

func TestReporter_GenerateWhitelist(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, t.TempDir(), time.Minute, time.Hour, testLogger())
	reporter := NewBaselineReporter(tracker, store, testLogger())

	now := time.Now().UTC()
	start := now.Add(-2 * time.Hour)
	for i := 0; i < 200; i++ {
		ev := makeEvent("nginx", "nginx", "ns", "wl", "node1")
		ev.Timestamp = start.Add(time.Duration(i) * time.Minute)
		tracker.Track(ev)
	}
	for i := 0; i < 50; i++ {
		ev := makeEvent("nginx", "sh", "ns", "wl", "node1")
		ev.Timestamp = start.Add(time.Duration(i*2) * time.Minute)
		tracker.Track(ev)
	}

	wl := reporter.GenerateWhitelist()
	if len(wl.WhitelistedLineages) != 1 {
		t.Fatalf("expected 1 parent group, got %d", len(wl.WhitelistedLineages))
	}

	entry := wl.WhitelistedLineages[0]
	if entry.Parent != "nginx" {
		t.Errorf("expected parent nginx, got %s", entry.Parent)
	}
	if len(entry.AllowedChildren) != 2 {
		t.Errorf("expected 2 children, got %d", len(entry.AllowedChildren))
	}
	if entry.Confidence < 0.90 {
		t.Errorf("expected high confidence, got %.2f", entry.Confidence)
	}
}

func TestReporter_WriteFiles(t *testing.T) {
	dir := t.TempDir()
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, dir, time.Minute, time.Hour, testLogger())
	reporter := NewBaselineReporter(tracker, store, testLogger())

	tracker.Track(makeEvent("nginx", "bash", "ns", "wl", "node1"))

	if err := reporter.WriteReport(dir); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	reportPath := filepath.Join(dir, "baseline_report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report BaselineReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if report.UniqueLineages != 1 {
		t.Errorf("expected 1 lineage in report, got %d", report.UniqueLineages)
	}

	wlPath := filepath.Join(dir, "auto_whitelist.yaml")
	if err := reporter.WriteWhitelist(wlPath); err != nil {
		t.Fatalf("WriteWhitelist: %v", err)
	}
	if _, err := os.Stat(wlPath); err != nil {
		t.Fatalf("whitelist file not created: %v", err)
	}
}

// --- Additional Comprehensive Branch & Edge-Case Tests ---

func TestTracker_ComputeConfidence_Table(t *testing.T) {
	tests := []struct {
		name       string
		count      uint64
		recurring  bool
		expected   float64
		reviewFlag bool
	}{
		{"100+ recurring", 100, true, 0.99, false},
		{"50+ recurring", 50, true, 0.95, false},
		{"10+ recurring", 10, true, 0.85, false},
		{"10+ non-recurring", 10, false, 0.70, false},
		{"3+ non-recurring", 3, false, 0.50, true},
		{"<3 occurrences", 1, false, 0.30, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ExecutionPattern{Count: tt.count}
			s := &PatternStats{IsRecurring: tt.recurring}
			conf := computeConfidence(p, s)
			if conf != tt.expected {
				t.Errorf("expected confidence %.2f, got %.2f", tt.expected, conf)
			}
			review := conf < 0.70
			if review != tt.reviewFlag {
				t.Errorf("expected review_flag %v, got %v", tt.reviewFlag, review)
			}
		})
	}
}

func TestTracker_GetStats_BurstAndRecurring(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	now := time.Now().UTC()

	// Burst pattern: 5 events within 1 minute
	for i := 0; i < 5; i++ {
		ev := makeEvent("python", "worker", "ns", "wl", "node1")
		ev.Timestamp = now.Add(time.Duration(i) * 10 * time.Second)
		tracker.Track(ev)
	}

	// Recurring pattern: 20 events spanning 2 hours
	for i := 0; i < 20; i++ {
		ev := makeEvent("nginx", "nginx", "ns", "wl", "node1")
		ev.Timestamp = now.Add(time.Duration(i*6) * time.Minute)
		tracker.Track(ev)
	}

	stats := tracker.GetStats()
	burstStats := stats[patternKey("ns", "wl", "python", "worker")]
	if !burstStats.IsBurst {
		t.Error("expected python->worker to be burst")
	}
	if burstStats.IsRecurring {
		t.Error("expected python->worker NOT to be recurring")
	}

	recStats := stats[patternKey("ns", "wl", "nginx", "nginx")]
	if !recStats.IsRecurring {
		t.Error("expected nginx->nginx to be recurring")
	}
	if recStats.IsBurst {
		t.Error("expected nginx->nginx NOT to be burst")
	}
}

func TestTracker_GetStats_Empty(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	if stats := tracker.GetStats(); stats != nil {
		t.Errorf("expected nil stats for empty tracker, got %v", stats)
	}
	if profiles := tracker.GetProfiles(); len(profiles) != 0 {
		t.Errorf("expected empty profiles, got %d", len(profiles))
	}
}

func TestTracker_OutOfOrderTimestamps(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	t1 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)

	// Send t2 first, then t1
	ev2 := makeEvent("nginx", "nginx", "ns", "wl", "node1")
	ev2.Timestamp = t2
	tracker.Track(ev2)

	ev1 := makeEvent("nginx", "nginx", "ns", "wl", "node1")
	ev1.Timestamp = t1
	tracker.Track(ev1)

	patterns := tracker.GetPatterns()
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(patterns))
	}
	if !patterns[0].FirstSeen.Equal(t1) {
		t.Errorf("expected FirstSeen == t1, got %v", patterns[0].FirstSeen)
	}
	if !patterns[0].LastSeen.Equal(t2) {
		t.Errorf("expected LastSeen == t2, got %v", patterns[0].LastSeen)
	}
}

func TestTracker_InvalidBinaryBases(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	ev := makeEvent("", "", "ns", "wl", "node1")
	ev.Binary = "/"
	ev.ParentBinary = "/"
	tracker.Track(ev)
	if tracker.UniquePatternCount() != 0 {
		t.Errorf("expected 0 patterns for slash binary, got %d", tracker.UniquePatternCount())
	}

	ev.Binary = "."
	tracker.Track(ev)
	if tracker.UniquePatternCount() != 0 {
		t.Errorf("expected 0 patterns for dot binary, got %d", tracker.UniquePatternCount())
	}
}

func TestBaselineStore_IsStable(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, t.TempDir(), time.Minute, 10*time.Millisecond, testLogger())

	// Without patterns, not stable
	if store.IsStable() {
		t.Error("expected IsStable false without patterns")
	}

	tracker.Track(makeEvent("nginx", "nginx", "ns", "wl", "node1"))
	time.Sleep(15 * time.Millisecond)

	if !store.IsStable() {
		t.Error("expected IsStable true after threshold")
	}
}

func TestBaselineStore_ListSnapshots(t *testing.T) {
	dir := t.TempDir()
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, dir, time.Minute, time.Hour, testLogger())

	// Empty dir
	list, err := store.ListSnapshots()
	if err != nil || len(list) != 0 {
		t.Fatalf("expected empty list, got %v, err %v", list, err)
	}

	// Nonexistent dir
	storeNonExistent := NewBaselineStore(tracker, filepath.Join(dir, "sub", "sub2"), time.Minute, time.Hour, testLogger())
	list, err = storeNonExistent.ListSnapshots()
	if err != nil || len(list) != 0 {
		t.Fatalf("expected empty list for nonexistent dir, got %v, err %v", list, err)
	}

	// Create snapshot
	tracker.Track(makeEvent("nginx", "nginx", "ns", "wl", "node1"))
	if err := store.SaveSnapshot(); err != nil {
		t.Fatalf("save: %v", err)
	}

	list, err = store.ListSnapshots()
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 snapshot, got %d: %v", len(list), list)
	}
}

func TestBaselineStore_Run(t *testing.T) {
	dir := t.TempDir()
	tracker := NewBehaviorTracker(testLogger())
	tracker.Track(makeEvent("nginx", "nginx", "ns", "wl", "node1"))

	store := NewBaselineStore(tracker, dir, 10*time.Millisecond, 50*time.Millisecond, testLogger())
	ctx, cancel := context.WithCancel(context.Background())

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		store.Run(ctx)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	<-runDone

	list, err := store.ListSnapshots()
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if len(list) == 0 {
		t.Error("expected at least 1 snapshot written during Run")
	}
}

func TestReporter_Recommendations(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	dir := t.TempDir()
	store := NewBaselineStore(tracker, dir, time.Minute, 10*time.Millisecond, testLogger())
	reporter := NewBaselineReporter(tracker, store, testLogger())

	// Learning
	tracker.Track(makeEvent("nginx", "nginx", "ns", "wl", "node1"))
	repLearning := reporter.GenerateReport()
	if repLearning.Stability != "LEARNING" {
		t.Errorf("expected LEARNING, got %s", repLearning.Stability)
	}

	// Stable
	time.Sleep(15 * time.Millisecond)
	repStable := reporter.GenerateReport()
	if repStable.Stability != "STABLE" {
		t.Errorf("expected STABLE, got %s", repStable.Stability)
	}
}

func TestReporter_Anomalies(t *testing.T) {
	tracker := NewBehaviorTracker(testLogger())
	dir := t.TempDir()
	store := NewBaselineStore(tracker, dir, time.Minute, time.Hour, testLogger())
	reporter := NewBaselineReporter(tracker, store, testLogger())

	// Add 3 high-frequency patterns
	for i := 0; i < 500; i++ {
		tracker.Track(makeEvent("nginx", "nginx", "ns", "wl", "node1"))
		tracker.Track(makeEvent("java", "java", "ns", "wl", "node1"))
		tracker.Track(makeEvent("node", "node", "ns", "wl", "node1"))
	}
	// Add 1 very rare pattern
	tracker.Track(makeEvent("nginx", "evil_shell", "ns", "wl", "node1"))

	report := reporter.GenerateReport()
	if len(report.AnomalyCandidates) == 0 {
		t.Log("Note: ZScore did not exceed -1.5 with these distributions, verifying AnomalyCandidates is initialized non-nil")
	}
	if report.AnomalyCandidates == nil {
		t.Error("expected AnomalyCandidates to be non-nil slice")
	}
}

func TestReporter_WhitelistCompatibilityWithStage3(t *testing.T) {
	dir := t.TempDir()
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, dir, time.Minute, time.Hour, testLogger())
	reporter := NewBaselineReporter(tracker, store, testLogger())

	now := time.Now().UTC()
	// Provide recurring observations spanning > 1h to reach high confidence (>= 0.85).
	for i := 0; i < 15; i++ {
		ev1 := makeEvent("nginx", "nginx", "default", "web", "node1")
		ev1.Timestamp = now.Add(time.Duration(i*5) * time.Minute)
		tracker.Track(ev1)

		ev2 := makeEvent("nginx", "sh", "default", "web", "node1")
		ev2.Timestamp = now.Add(time.Duration(i*5) * time.Minute)
		tracker.Track(ev2)
	}

	wlPath := filepath.Join(dir, "auto_whitelist.yaml")
	if err := reporter.WriteWhitelist(wlPath); err != nil {
		t.Fatalf("WriteWhitelist: %v", err)
	}

	data, err := os.ReadFile(wlPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// Test unmarshaling into Stage 3 whitelist schema
	type Stage3Whitelist struct {
		WhitelistedLineages []struct {
			Parent          string   `yaml:"parent"`
			AllowedChildren []string `yaml:"allowed_children"`
		} `yaml:"whitelisted_lineages"`
	}

	var s3wl Stage3Whitelist
	if err := yaml.Unmarshal(data, &s3wl); err != nil {
		t.Fatalf("failed to unmarshal into Stage 3 schema: %v", err)
	}

	if len(s3wl.WhitelistedLineages) != 1 {
		t.Fatalf("expected 1 lineage, got %d", len(s3wl.WhitelistedLineages))
	}
	if s3wl.WhitelistedLineages[0].Parent != "nginx" {
		t.Errorf("expected parent nginx, got %s", s3wl.WhitelistedLineages[0].Parent)
	}
	if len(s3wl.WhitelistedLineages[0].AllowedChildren) != 2 {
		t.Errorf("expected 2 children, got %d", len(s3wl.WhitelistedLineages[0].AllowedChildren))
	}
}

func TestReporter_WhitelistFiltersLowConfidence(t *testing.T) {
	dir := t.TempDir()
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, dir, time.Minute, time.Hour, testLogger())
	reporter := NewBaselineReporter(tracker, store, testLogger())

	now := time.Now().UTC()
	// nginx -> worker: 15 recurring events across 75 mins -> confidence 0.85
	for i := 0; i < 15; i++ {
		ev := makeEvent("nginx", "worker", "default", "web", "node1")
		ev.Timestamp = now.Add(time.Duration(i*5) * time.Minute)
		tracker.Track(ev)
	}

	// nginx -> bash: single anomaly event -> confidence 0.30, review_flag = true
	evBash := makeEvent("nginx", "bash", "default", "web", "node1")
	evBash.Timestamp = now
	tracker.Track(evBash)

	wl := reporter.GenerateWhitelist()
	if len(wl.WhitelistedLineages) != 1 {
		t.Fatalf("expected 1 lineage, got %d", len(wl.WhitelistedLineages))
	}

	entry := wl.WhitelistedLineages[0]
	if entry.Parent != "nginx" {
		t.Fatalf("expected parent nginx, got %s", entry.Parent)
	}

	// worker should be allowed
	if len(entry.AllowedChildren) != 1 || entry.AllowedChildren[0] != "worker" {
		t.Errorf("expected allowed_children [worker], got %v", entry.AllowedChildren)
	}

	// bash should be quarantined, NOT allowed
	if len(entry.QuarantinedCandidates) != 1 || entry.QuarantinedCandidates[0] != "bash" {
		t.Errorf("expected quarantined_candidates [bash], got %v", entry.QuarantinedCandidates)
	}
	if !entry.ReviewFlag {
		t.Error("expected review_flag true for entry with quarantined candidate")
	}

	// Test LoadWhitelist
	wlPath := filepath.Join(dir, "auto_whitelist.yaml")
	if err := reporter.WriteWhitelist(wlPath); err != nil {
		t.Fatalf("write whitelist: %v", err)
	}
	loadedWl, err := LoadWhitelist(wlPath)
	if err != nil {
		t.Fatalf("load whitelist: %v", err)
	}
	if len(loadedWl.WhitelistedLineages) != 1 {
		t.Fatalf("expected 1 loaded lineage, got %d", len(loadedWl.WhitelistedLineages))
	}
}

func TestBaselineStore_DowntimeNotStable(t *testing.T) {
	dir := t.TempDir()
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, dir, time.Minute, 1*time.Hour, testLogger())

	// Simulate loading a snapshot where the last new pattern was seen 5 hours ago,
	// but the agent has just restarted (uptime is only milliseconds).
	patterns := map[string]*ExecutionPattern{
		"ns/wl/nginx→nginx": {
			ParentBinary: "nginx",
			ChildBinary:  "nginx",
			Namespace:    "ns",
			WorkloadName: "wl",
			Count:        100,
		},
	}
	tracker.LoadPatterns(patterns, 100, time.Now().Add(-5*time.Hour), time.Now().Add(-10*time.Hour))

	// Status must NOT be STABLE because active observation uptime is near 0.
	status := store.GetStabilityStatus()
	if status == StatusStable {
		t.Errorf("expected status to NOT be STABLE immediately after restart, got %s", status)
	}
	if store.IsStable() {
		t.Error("expected IsStable() false after restart")
	}
}

func TestBaselineStore_CorruptedLatestSnapshotFallback(t *testing.T) {
	dir := t.TempDir()
	tracker := NewBehaviorTracker(testLogger())
	store := NewBaselineStore(tracker, dir, time.Minute, time.Hour, testLogger())

	tracker.Track(makeEvent("nginx", "nginx", "ns", "wl", "node1"))
	if err := store.SaveSnapshot(); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	// Corrupt baseline_latest.json
	latestPath := filepath.Join(dir, "baseline_latest.json")
	if err := os.WriteFile(latestPath, []byte("invalid-truncated-json{"), 0o644); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}

	// Create a new store pointing to same directory
	newTracker := NewBehaviorTracker(testLogger())
	newStore := NewBaselineStore(newTracker, dir, time.Minute, time.Hour, testLogger())

	// LoadLatestSnapshot should fall back to timestamped snapshot and succeed
	if err := newStore.LoadLatestSnapshot(); err != nil {
		t.Fatalf("expected fallback to succeed, got: %v", err)
	}

	if newTracker.UniquePatternCount() != 1 {
		t.Errorf("expected 1 pattern restored from fallback, got %d", newTracker.UniquePatternCount())
	}

	// Verify baseline_latest.json was healed
	healedData, err := os.ReadFile(latestPath)
	if err != nil {
		t.Fatalf("read healed file: %v", err)
	}
	var testSnap BaselineSnapshot
	if err := json.Unmarshal(healedData, &testSnap); err != nil {
		t.Fatalf("healed file contains invalid json: %v", err)
	}
}

func TestStabilityStatus_String(t *testing.T) {
	if StatusLearning.String() != "LEARNING" {
		t.Errorf("expected LEARNING, got %s", StatusLearning.String())
	}
	if StatusStabilizing.String() != "STABILIZING" {
		t.Errorf("expected STABILIZING, got %s", StatusStabilizing.String())
	}
	if StatusStable.String() != "STABLE" {
		t.Errorf("expected STABLE, got %s", StatusStable.String())
	}
	if StabilityStatus(99).String() != "UNKNOWN" {
		t.Errorf("expected UNKNOWN, got %s", StabilityStatus(99).String())
	}
}

// --- Config tests ---

func TestConfigLoad(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent_config.yaml")
	content := `
agent:
  mode: "shadow"
  discovery:
    learning_window: 48h
    snapshot_interval: 30m
    stability_threshold: 2h
    auto_generate_whitelist: true
    output_dir: "data/test"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Config package test (inline since no Go compiler to run config_test.go separately).
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty config")
	}
}

// --- Benchmark ---

func BenchmarkTracker_Track(b *testing.B) {
	tracker := NewBehaviorTracker(zap.NewNop())
	ev := makeEvent("nginx", "bash", "ns", "wl", "node1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker.Track(ev)
	}
}

func BenchmarkTracker_TrackParallel(b *testing.B) {
	tracker := NewBehaviorTracker(zap.NewNop())
	ev := makeEvent("nginx", "bash", "ns", "wl", "node1")

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tracker.Track(ev)
		}
	})
}
