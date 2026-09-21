package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/executeid/ztre/pkg/collector"
	"go.uber.org/zap"
)

func TestBaselineStore_SnapshotPruning(t *testing.T) {
	dir := t.TempDir()
	logger := zap.NewNop()
	tracker := NewBehaviorTracker(logger)

	tracker.Track(&collector.SecurityEvent{
		Timestamp:    time.Now().UTC(),
		EventType:    collector.EventTypeExecve,
		PID:          100,
		Binary:       "/usr/bin/app",
		ParentBinary: "/usr/bin/init",
		Namespace:    "default",
		WorkloadName: "test-app",
	})

	store := NewBaselineStore(tracker, dir, time.Minute, time.Hour, logger)
	store.MaxSnapshots = 3

	// Save 6 snapshots with small sleep so each snapshot gets a distinct timestamp filename.
	for i := 0; i < 6; i++ {
		if i > 0 {
			time.Sleep(1050 * time.Millisecond)
		}
		if err := store.SaveSnapshot(); err != nil {
			t.Fatalf("snapshot %d failed: %v", i, err)
		}
	}

	// Verify only 3 newest timestamped snapshots remain
	snapshots, err := store.ListSnapshots()
	if err != nil {
		t.Fatalf("list snapshots failed: %v", err)
	}

	if len(snapshots) != 3 {
		t.Fatalf("expected 3 snapshots remaining, got %d: %v", len(snapshots), snapshots)
	}

	// Verify baseline_latest.json exists
	latestPath := filepath.Join(dir, "baseline_latest.json")
	if _, err := os.Stat(latestPath); err != nil {
		t.Fatalf("expected baseline_latest.json to exist, got error: %v", err)
	}

	// Verify exactly 4 json files exist in directory (3 snapshots + baseline_latest.json)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir failed: %v", err)
	}
	var jsonFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			jsonFiles = append(jsonFiles, e.Name())
		}
	}
	if len(jsonFiles) != 4 {
		t.Fatalf("expected exactly 4 json files (3 snapshots + baseline_latest.json), got %d: %v", len(jsonFiles), jsonFiles)
	}
}

func TestBaselineStore_NonSnapshotFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	logger := zap.NewNop()
	tracker := NewBehaviorTracker(logger)

	tracker.Track(&collector.SecurityEvent{
		Timestamp:    time.Now().UTC(),
		EventType:    collector.EventTypeExecve,
		PID:          100,
		Binary:       "/usr/bin/app",
		ParentBinary: "/usr/bin/init",
		Namespace:    "default",
		WorkloadName: "test-app",
	})

	store := NewBaselineStore(tracker, dir, time.Minute, time.Hour, logger)
	store.MaxSnapshots = 2

	// Create non-snapshot files in the directory
	reportPath := filepath.Join(dir, "baseline_report.json")
	if err := os.WriteFile(reportPath, []byte(`{"report": true}`), 0o644); err != nil {
		t.Fatalf("failed to write dummy report: %v", err)
	}

	randomJsonPath := filepath.Join(dir, "random_data.json")
	if err := os.WriteFile(randomJsonPath, []byte(`{"data": 123}`), 0o644); err != nil {
		t.Fatalf("failed to write dummy random json: %v", err)
	}

	// Create 3 valid snapshots
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(1050 * time.Millisecond)
		}
		if err := store.SaveSnapshot(); err != nil {
			t.Fatalf("snapshot %d failed: %v", i, err)
		}
	}

	// ListSnapshots should only return the 2 pruned timestamped snapshots (due to MaxSnapshots=2)
	snapshots, err := store.ListSnapshots()
	if err != nil {
		t.Fatalf("list snapshots failed: %v", err)
	}
	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d: %v", len(snapshots), snapshots)
	}

	// Non-snapshot files must still exist and must not be pruned
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("expected baseline_report.json to remain untouched, got err: %v", err)
	}
	if _, err := os.Stat(randomJsonPath); err != nil {
		t.Fatalf("expected random_data.json to remain untouched, got err: %v", err)
	}

	// Test fallback: corrupt baseline_latest.json and ensure fallback ignores baseline_report.json
	latestPath := filepath.Join(dir, "baseline_latest.json")
	if err := os.WriteFile(latestPath, []byte("invalid json"), 0o644); err != nil {
		t.Fatalf("failed to corrupt baseline_latest.json: %v", err)
	}

	freshTracker := NewBehaviorTracker(logger)
	freshStore := NewBaselineStore(freshTracker, dir, time.Minute, time.Hour, logger)
	if err := freshStore.LoadLatestSnapshot(); err != nil {
		t.Fatalf("fallback load failed: %v", err)
	}
	if freshTracker.UniquePatternCount() != 1 {
		t.Fatalf("expected 1 pattern restored via fallback, got %d", freshTracker.UniquePatternCount())
	}
}

