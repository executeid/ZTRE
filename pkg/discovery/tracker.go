package discovery

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/executeid/ztre/pkg/collector"
	"github.com/executeid/ztre/pkg/observability"
	"go.uber.org/zap"
)

// patternKey builds a unique map key for a parent→child pair within a workload.
func patternKey(namespace, workload, parent, child string) string {
	return fmt.Sprintf("%s/%s/%s→%s", namespace, workload, parent, child)
}

// BehaviorTracker accumulates parent→child execution patterns from SecurityEvents.
type BehaviorTracker struct {
	mu             sync.RWMutex
	patterns       map[string]*ExecutionPattern // keyed by patternKey
	started        time.Time
	sessionStarted time.Time
	lastNewPattern time.Time
	totalEvents    uint64
	logger         *zap.Logger
}

// NewBehaviorTracker creates a tracker ready to receive events.
func NewBehaviorTracker(logger *zap.Logger) *BehaviorTracker {
	now := time.Now().UTC()
	return &BehaviorTracker{
		patterns:       make(map[string]*ExecutionPattern),
		started:        now,
		sessionStarted: now,
		lastNewPattern: now,
		logger:         logger,
	}
}

// Track records a SecurityEvent's parent→child relationship.
// Only execve events carry meaningful lineage; exit/kprobe events are counted
// but don't define new lineage pairs.
func (bt *BehaviorTracker) Track(event *collector.SecurityEvent) {
	if event == nil {
		return
	}

	bt.mu.Lock()
	defer bt.mu.Unlock()

	bt.totalEvents++

	// Only execve events define a meaningful parent→child lineage.
	if event.EventType != collector.EventTypeExecve {
		return
	}

	parent := filepath.Base(event.ParentBinary)
	child := filepath.Base(event.Binary)
	if parent == "" || child == "" || parent == "." || child == "." || parent == "/" || child == "/" {
		return
	}

	key := patternKey(event.Namespace, event.WorkloadName, parent, child)
	now := event.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	pat, exists := bt.patterns[key]
	if !exists {
		nodes := make([]string, 0, 1)
		if event.NodeName != "" {
			nodes = append(nodes, event.NodeName)
		}
		bt.patterns[key] = &ExecutionPattern{
			ParentBinary: parent,
			ChildBinary:  child,
			Namespace:    event.Namespace,
			WorkloadName: event.WorkloadName,
			Count:        1,
			FirstSeen:    now,
			LastSeen:     now,
			Nodes:        nodes,
		}
		bt.lastNewPattern = time.Now().UTC()
		observability.DiscoveryPatternsTotal.Inc()
		bt.logger.Info("new execution pattern discovered",
			zap.String("parent", parent),
			zap.String("child", child),
			zap.String("namespace", event.Namespace),
			zap.String("workload", event.WorkloadName),
		)
		return
	}

	pat.Count++
	if now.Before(pat.FirstSeen) {
		pat.FirstSeen = now
	}
	if now.After(pat.LastSeen) {
		pat.LastSeen = now
	}
	// Track node if not already seen.
	if event.NodeName != "" && !containsStr(pat.Nodes, event.NodeName) {
		pat.Nodes = append(pat.Nodes, event.NodeName)
	}
}

// GetPatterns returns a snapshot of all observed patterns, sorted deterministically.
func (bt *BehaviorTracker) GetPatterns() []*ExecutionPattern {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	out := make([]*ExecutionPattern, 0, len(bt.patterns))
	for _, p := range bt.patterns {
		cp := *p
		cp.Nodes = append([]string(nil), p.Nodes...)
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].WorkloadName != out[j].WorkloadName {
			return out[i].WorkloadName < out[j].WorkloadName
		}
		if out[i].ParentBinary != out[j].ParentBinary {
			return out[i].ParentBinary < out[j].ParentBinary
		}
		return out[i].ChildBinary < out[j].ChildBinary
	})
	return out
}

// GetPatternsMap returns a copy of the internal map for snapshot persistence.
func (bt *BehaviorTracker) GetPatternsMap() map[string]*ExecutionPattern {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	out := make(map[string]*ExecutionPattern, len(bt.patterns))
	for k, p := range bt.patterns {
		cp := *p
		cp.Nodes = append([]string(nil), p.Nodes...)
		out[k] = &cp
	}
	return out
}

// LoadPatterns restores patterns from a previous snapshot (resume learning).
func (bt *BehaviorTracker) LoadPatterns(patterns map[string]*ExecutionPattern, totalEvents uint64, lastNew, started time.Time) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	for k, p := range patterns {
		bt.patterns[k] = p
	}
	bt.totalEvents = totalEvents
	if !lastNew.IsZero() {
		bt.lastNewPattern = lastNew
	}
	if !started.IsZero() {
		bt.started = started
	}
}

// UniquePatternCount returns how many distinct parent→child pairs have been observed.
func (bt *BehaviorTracker) UniquePatternCount() int {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return len(bt.patterns)
}

// TotalEvents returns the total number of events tracked.
func (bt *BehaviorTracker) TotalEvents() uint64 {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.totalEvents
}

// LastNewPatternTime returns when the most recent new pattern was discovered.
func (bt *BehaviorTracker) LastNewPatternTime() time.Time {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.lastNewPattern
}

// Started returns when tracking began.
func (bt *BehaviorTracker) Started() time.Time {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.started
}

// ActiveUptime returns how long the current tracker process has been actively running.
func (bt *BehaviorTracker) ActiveUptime() time.Duration {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return time.Since(bt.sessionStarted)
}

// GetStats computes frequency and statistical metrics for each pattern.
func (bt *BehaviorTracker) GetStats() map[string]*PatternStats {
	bt.mu.RLock()
	if len(bt.patterns) == 0 {
		bt.mu.RUnlock()
		return nil
	}

	patterns := make(map[string]*ExecutionPattern, len(bt.patterns))
	for k, p := range bt.patterns {
		cp := *p
		cp.Nodes = append([]string(nil), p.Nodes...)
		patterns[k] = &cp
	}
	bt.mu.RUnlock()

	stats := make(map[string]*PatternStats, len(patterns))

	// Compute frequencies (events per hour).
	frequencies := make([]float64, 0, len(patterns))
	for key, p := range patterns {
		duration := p.LastSeen.Sub(p.FirstSeen)
		if duration < time.Minute {
			duration = time.Since(p.FirstSeen)
		}
		hours := duration.Hours()
		if hours < 0.01 {
			hours = 0.01 // avoid division by zero
		}

		freq := float64(p.Count) / hours
		frequencies = append(frequencies, freq)

		lifespan := p.LastSeen.Sub(p.FirstSeen)
		stats[key] = &PatternStats{
			Frequency:   freq,
			IsBurst:     lifespan < 5*time.Minute && p.Count > 1,
			IsRecurring: lifespan > 1*time.Hour,
			IsCrossNode: len(p.Nodes) > 1,
		}
	}

	// Compute mean and stddev for z-scores.
	mean, stddev := meanStddev(frequencies)

	// Assign z-scores, percentiles, confidence.
	sort.Float64s(frequencies)

	for key, s := range stats {
		if stddev > 0 {
			s.ZScore = (s.Frequency - mean) / stddev
		}
		s.Percentile = percentileOf(frequencies, s.Frequency)
		s.Confidence = computeConfidence(patterns[key], s)
		s.ReviewFlag = s.Confidence < 0.70
	}

	return stats
}

// GetProfiles builds per-workload LineageProfiles from observed patterns.
func (bt *BehaviorTracker) GetProfiles() []*LineageProfile {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	profileMap := make(map[string]*LineageProfile) // key: namespace/workload
	binaries := make(map[string]map[string]bool)   // key: namespace/workload → set of binaries

	for _, p := range bt.patterns {
		wKey := fmt.Sprintf("%s/%s", p.Namespace, p.WorkloadName)
		prof, exists := profileMap[wKey]
		if !exists {
			prof = &LineageProfile{
				Namespace:    p.Namespace,
				WorkloadName: p.WorkloadName,
			}
			profileMap[wKey] = prof
			binaries[wKey] = make(map[string]bool)
		}
		cp := *p
		cp.Nodes = append([]string(nil), p.Nodes...)
		prof.Patterns = append(prof.Patterns, &cp)
		prof.TotalEvents += p.Count
		binaries[wKey][p.ParentBinary] = true
		binaries[wKey][p.ChildBinary] = true
	}

	out := make([]*LineageProfile, 0, len(profileMap))
	for wKey, prof := range profileMap {
		prof.UniqueProcesses = len(binaries[wKey])
		sort.Slice(prof.Patterns, func(i, j int) bool {
			if prof.Patterns[i].ParentBinary != prof.Patterns[j].ParentBinary {
				return prof.Patterns[i].ParentBinary < prof.Patterns[j].ParentBinary
			}
			return prof.Patterns[i].ChildBinary < prof.Patterns[j].ChildBinary
		})
		out = append(out, prof)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].WorkloadName < out[j].WorkloadName
	})
	return out
}

// --- helpers ---

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func meanStddev(vals []float64) (float64, float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	var variance float64
	for _, v := range vals {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(vals))
	return mean, math.Sqrt(variance)
}

func percentileOf(sorted []float64, val float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := sort.Search(len(sorted), func(i int) bool {
		return sorted[i] > val
	})
	return float64(idx) / float64(len(sorted))
}

func computeConfidence(p *ExecutionPattern, s *PatternStats) float64 {
	if p.Count >= 100 && s.IsRecurring {
		return 0.99
	}
	if p.Count >= 50 && s.IsRecurring {
		return 0.95
	}
	if p.Count >= 10 && s.IsRecurring {
		return 0.85
	}
	if p.Count >= 10 {
		return 0.70
	}
	if p.Count >= 3 {
		return 0.50
	}
	return 0.30
}
