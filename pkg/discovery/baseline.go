package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/executeid/ztre/pkg/observability"
	"go.uber.org/zap"
)

const (
	snapshotTimeFormat = "20060102_150405"
	snapshotFileLayout = "baseline_20060102_150405.json"
)

func isSnapshotFilename(name string) bool {
	_, err := time.Parse(snapshotFileLayout, name)
	return err == nil
}

// BaselineStore persists behavioral snapshots and detects baseline stability.
//
// Lock ordering contract:
// BaselineStore.mu must always be acquired before BehaviorTracker.mu, never the reverse.
// Methods on BaselineStore that hold bs.mu may safely call BehaviorTracker methods (which acquire
// bt.mu), but BehaviorTracker must never call into BaselineStore while holding bt.mu.
type BaselineStore struct {
	mu                 sync.Mutex
	tracker            *BehaviorTracker
	snapshotDir        string
	snapshotInterval   time.Duration
	stabilityThreshold time.Duration
	MaxSnapshots       int
	logger             *zap.Logger
	lastStatus         StabilityStatus
}

// NewBaselineStore creates a store that persists tracker snapshots.
func NewBaselineStore(tracker *BehaviorTracker, snapshotDir string, snapshotInterval, stabilityThreshold time.Duration, logger *zap.Logger) *BaselineStore {
	if snapshotInterval <= 0 {
		snapshotInterval = 1 * time.Hour
	}
	if stabilityThreshold <= 0 {
		stabilityThreshold = 4 * time.Hour
	}
	observability.DiscoveryStabilityGauge.Set(float64(StatusLearning))
	return &BaselineStore{
		tracker:            tracker,
		snapshotDir:        snapshotDir,
		snapshotInterval:   snapshotInterval,
		stabilityThreshold: stabilityThreshold,
		MaxSnapshots:       24,
		logger:             logger,
		lastStatus:         StatusLearning,
	}
}

// GetStabilityStatus returns the current stability state of the baseline.
func (bs *BaselineStore) GetStabilityStatus() StabilityStatus {
	if bs.tracker.UniquePatternCount() == 0 {
		observability.DiscoveryStabilityGauge.Set(float64(StatusLearning))
		return StatusLearning
	}
	sinceLastNew := time.Since(bs.tracker.LastNewPatternTime())
	if active := bs.tracker.ActiveUptime(); active < sinceLastNew {
		sinceLastNew = active
	}

	var status StabilityStatus
	if sinceLastNew >= bs.stabilityThreshold {
		status = StatusStable
	} else if sinceLastNew >= bs.stabilityThreshold/2 {
		status = StatusStabilizing
	} else {
		status = StatusLearning
	}
	observability.DiscoveryStabilityGauge.Set(float64(status))
	return status
}

// IsStable returns true when no new patterns have been observed for the threshold duration.
func (bs *BaselineStore) IsStable() bool {
	return bs.GetStabilityStatus() == StatusStable
}

// SaveSnapshot serializes the current tracker state to a JSON file.
func (bs *BaselineStore) SaveSnapshot() error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if err := os.MkdirAll(bs.snapshotDir, 0o755); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}

	snap := &BaselineSnapshot{
		Timestamp:      time.Now().UTC(),
		LearningStart:  bs.tracker.Started(),
		TotalEvents:    bs.tracker.TotalEvents(),
		UniquePatterns: bs.tracker.UniquePatternCount(),
		Patterns:       bs.tracker.GetPatternsMap(),
		Stability:      bs.GetStabilityStatus(),
		LastNewPattern: bs.tracker.LastNewPatternTime(),
	}

	filename := fmt.Sprintf("baseline_%s.json", snap.Timestamp.Format(snapshotTimeFormat))
	path := filepath.Join(bs.snapshotDir, filename)

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}

	// Also write a "latest" atomic copy for easy loading.
	latestPath := filepath.Join(bs.snapshotDir, "baseline_latest.json")
	_ = writeFileAtomic(latestPath, data, 0o644)

	// Prune old snapshots, retaining newest MaxSnapshots (default: 24).
	maxKeep := bs.MaxSnapshots
	if maxKeep <= 0 {
		maxKeep = 24
	}
	if err := bs.pruneSnapshotsLocked(maxKeep); err != nil {
		bs.logger.Warn("failed to prune snapshots", zap.Error(err))
	}

	bs.logger.Info("baseline snapshot saved",
		zap.String("path", path),
		zap.Int("unique_patterns", snap.UniquePatterns),
		zap.Uint64("total_events", snap.TotalEvents),
		zap.String("stability", snap.Stability.String()),
	)
	return nil
}

// LoadLatestSnapshot restores the most recent snapshot into the tracker.
func (bs *BaselineStore) LoadLatestSnapshot() error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	latestPath := filepath.Join(bs.snapshotDir, "baseline_latest.json")

	data, err := os.ReadFile(latestPath)
	var snap BaselineSnapshot
	var loadErr error

	if err == nil {
		loadErr = json.Unmarshal(data, &snap)
	} else if !os.IsNotExist(err) {
		loadErr = err
	}

	// If latest snapshot is corrupted, unreadable, or missing, attempt fallback to newest valid timestamped snapshot.
	if loadErr != nil || (err != nil && !os.IsNotExist(err)) {
		bs.logger.Warn("baseline_latest.json corrupted or unreadable, attempting fallback to previous snapshots",
			zap.Error(loadErr),
		)
		fallbackSnap, fallbackErr := bs.loadNewestValidSnapshotLocked()
		if fallbackErr != nil {
			return fmt.Errorf("read latest snapshot: %w (fallback failed: %v)", loadErr, fallbackErr)
		}
		snap = *fallbackSnap
		// Heal baseline_latest.json atomically
		if healData, mErr := json.MarshalIndent(&snap, "", "  "); mErr == nil {
			_ = writeFileAtomic(latestPath, healData, 0o644)
		}
	} else if err != nil && os.IsNotExist(err) {
		fallbackSnap, fallbackErr := bs.loadNewestValidSnapshotLocked()
		if fallbackErr == nil && fallbackSnap != nil {
			snap = *fallbackSnap
		} else {
			bs.logger.Info("no previous baseline snapshot found, starting fresh")
			return nil
		}
	}

	bs.tracker.LoadPatterns(snap.Patterns, snap.TotalEvents, snap.LastNewPattern, snap.LearningStart)
	status := bs.GetStabilityStatus()
	bs.lastStatus = status
	observability.DiscoveryStabilityGauge.Set(float64(status))

	bs.logger.Info("baseline snapshot restored",
		zap.Int("unique_patterns", snap.UniquePatterns),
		zap.Uint64("total_events", snap.TotalEvents),
		zap.String("stability", snap.Stability.String()),
	)
	return nil
}

// loadNewestValidSnapshotLocked iterates through sorted snapshots from newest to oldest.
func (bs *BaselineStore) loadNewestValidSnapshotLocked() (*BaselineSnapshot, error) {
	names, err := bs.listSnapshotsLocked()
	if err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no timestamped snapshots available")
	}

	for i := len(names) - 1; i >= 0; i-- {
		snapPath := filepath.Join(bs.snapshotDir, names[i])
		data, err := os.ReadFile(snapPath)
		if err != nil {
			continue
		}
		var snap BaselineSnapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			continue
		}
		bs.logger.Info("recovered baseline from timestamped snapshot", zap.String("path", snapPath))
		return &snap, nil
	}

	return nil, fmt.Errorf("no valid timestamped snapshots could be decoded")
}

// Run starts the periodic snapshot loop. It blocks until ctx is canceled.
// It also logs stability transitions.
func (bs *BaselineStore) Run(ctx context.Context) {
	ticker := time.NewTicker(bs.snapshotInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check for stability transition.
			newStatus := bs.GetStabilityStatus()
			bs.mu.Lock()
			if newStatus != bs.lastStatus {
				bs.logger.Info("baseline stability transition",
					zap.String("from", bs.lastStatus.String()),
					zap.String("to", newStatus.String()),
					zap.Int("unique_patterns", bs.tracker.UniquePatternCount()),
					zap.Uint64("total_events", bs.tracker.TotalEvents()),
				)
				bs.lastStatus = newStatus
			}
			bs.mu.Unlock()

			if err := bs.SaveSnapshot(); err != nil {
				bs.logger.Error("failed to save periodic snapshot", zap.Error(err))
			}
		}
	}
}

// ListSnapshots returns sorted snapshot filenames in the snapshot directory.
func (bs *BaselineStore) ListSnapshots() ([]string, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.listSnapshotsLocked()
}

func (bs *BaselineStore) listSnapshotsLocked() ([]string, error) {
	entries, err := os.ReadDir(bs.snapshotDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && isSnapshotFilename(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// pruneSnapshotsLocked deletes all but the newest maxKeep baseline timestamped snapshot files.
func (bs *BaselineStore) pruneSnapshotsLocked(maxKeep int) error {
	if maxKeep <= 0 {
		return nil
	}

	snapshots, err := bs.listSnapshotsLocked()
	if err != nil {
		return fmt.Errorf("list snapshots for pruning: %w", err)
	}

	if len(snapshots) <= maxKeep {
		return nil
	}

	toDelete := snapshots[:len(snapshots)-maxKeep]
	for _, f := range toDelete {
		p := filepath.Join(bs.snapshotDir, f)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			bs.logger.Warn("failed to delete old snapshot", zap.String("path", p), zap.Error(err))
		}
	}
	return nil
}
