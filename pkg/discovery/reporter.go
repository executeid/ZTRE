package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// BaselineReporter generates reports and auto-whitelists from tracked behavior.
type BaselineReporter struct {
	tracker *BehaviorTracker
	store   *BaselineStore
	logger  *zap.Logger
}

// NewBaselineReporter creates a reporter backed by a tracker and store.
func NewBaselineReporter(tracker *BehaviorTracker, store *BaselineStore, logger *zap.Logger) *BaselineReporter {
	return &BaselineReporter{
		tracker: tracker,
		store:   store,
		logger:  logger,
	}
}

// GenerateReport builds a BaselineReport from the current tracker state.
func (r *BaselineReporter) GenerateReport() *BaselineReport {
	patterns := r.tracker.GetPatterns()
	stats := r.tracker.GetStats()
	profiles := r.tracker.GetProfiles()
	stability := r.store.GetStabilityStatus()

	// Identify anomaly candidates: patterns with low frequency outlier (z-score < -1.5).
	anomalies := make([]*AnomalyCandidate, 0)
	for _, p := range patterns {
		key := patternKey(p.Namespace, p.WorkloadName, p.ParentBinary, p.ChildBinary)
		if s, ok := stats[key]; ok && s.ZScore < -1.5 { // low frequency outlier
			// ponytail: using negative z-score (lower than mean) as the anomaly signal
			// since rare patterns have low frequency. Switch to isolation forest if
			// simple z-score produces too many false flags.
			anomalies = append(anomalies, &AnomalyCandidate{
				ParentBinary: p.ParentBinary,
				ChildBinary:  p.ChildBinary,
				Namespace:    p.Namespace,
				Count:        p.Count,
				ZScore:       s.ZScore,
				Verdict:      fmt.Sprintf("RARE — seen %d times, z-score %.2f", p.Count, s.ZScore),
			})
		}
	}

	var recommendation string
	switch stability {
	case StatusStable:
		recommendation = "Baseline is stable. Safe to transition to shadow mode for validation."
	case StatusStabilizing:
		recommendation = "Baseline is stabilizing. New patterns slowing. Monitor before transitioning."
	default:
		recommendation = "Baseline is still learning. New patterns being discovered. Continue observation."
	}

	return &BaselineReport{
		LearningWindow: TimeWindow{
			Start: r.tracker.Started(),
			End:   time.Now().UTC(),
		},
		TotalEvents:       r.tracker.TotalEvents(),
		UniqueLineages:    r.tracker.UniquePatternCount(),
		Profiles:          profiles,
		AnomalyCandidates: anomalies,
		Stability:         stability.String(),
		Recommendation:    recommendation,
	}
}

// GenerateWhitelist converts high-confidence observed patterns into whitelist format.
// Low-confidence or flagged patterns are separated into QuarantinedCandidates.
func (r *BaselineReporter) GenerateWhitelist() *WhitelistConfig {
	patterns := r.tracker.GetPatterns()
	stats := r.tracker.GetStats()

	// Group by parent binary (across all namespaces/workloads).
	type parentGroup struct {
		allowedChildren     map[string]bool
		quarantinedChildren map[string]bool
		totalCount          uint64
		minAllowedConfidence float64
		hasAllowed          bool
		hasQuarantined      bool
	}
	groups := make(map[string]*parentGroup)

	for _, p := range patterns {
		key := patternKey(p.Namespace, p.WorkloadName, p.ParentBinary, p.ChildBinary)
		s := stats[key]

		g, exists := groups[p.ParentBinary]
		if !exists {
			g = &parentGroup{
				allowedChildren:      make(map[string]bool),
				quarantinedChildren:  make(map[string]bool),
				minAllowedConfidence: 1.0,
			}
			groups[p.ParentBinary] = g
		}

		g.totalCount += p.Count

		// High confidence threshold: >= 0.85 and no review flag.
		isHighConfidence := s != nil && s.Confidence >= 0.85 && !s.ReviewFlag
		if isHighConfidence {
			g.allowedChildren[p.ChildBinary] = true
			delete(g.quarantinedChildren, p.ChildBinary)
			if !g.hasAllowed || s.Confidence < g.minAllowedConfidence {
				g.minAllowedConfidence = s.Confidence
				g.hasAllowed = true
			}
		} else {
			if !g.allowedChildren[p.ChildBinary] {
				g.quarantinedChildren[p.ChildBinary] = true
			}
			g.hasQuarantined = true
		}
	}

	// Build sorted whitelist entries.
	entries := make([]WhitelistEntry, 0, len(groups))
	for parent, g := range groups {
		allowed := make([]string, 0, len(g.allowedChildren))
		for c := range g.allowedChildren {
			allowed = append(allowed, c)
		}
		sort.Strings(allowed)

		var quarantined []string
		if len(g.quarantinedChildren) > 0 {
			quarantined = make([]string, 0, len(g.quarantinedChildren))
			for c := range g.quarantinedChildren {
				quarantined = append(quarantined, c)
			}
			sort.Strings(quarantined)
		}

		confidence := 0.0
		if g.hasAllowed {
			confidence = g.minAllowedConfidence
		}

		reviewFlag := g.hasQuarantined || len(quarantined) > 0 || !g.hasAllowed || confidence < 0.70

		entries = append(entries, WhitelistEntry{
			Parent:                parent,
			AllowedChildren:       allowed,
			QuarantinedCandidates: quarantined,
			Confidence:            confidence,
			Source:                "auto-discovered",
			ObservedCount:         g.totalCount,
			ReviewFlag:            reviewFlag,
		})
	}

	// Sort by confidence descending, then parent name.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Confidence != entries[j].Confidence {
			return entries[i].Confidence > entries[j].Confidence
		}
		return entries[i].Parent < entries[j].Parent
	})

	return &WhitelistConfig{
		GeneratedAt: time.Now().UTC(),
		LearningWindow: TimeWindow{
			Start: r.tracker.Started(),
			End:   time.Now().UTC(),
		},
		TotalEventsObserved: r.tracker.TotalEvents(),
		WhitelistedLineages: entries,
	}
}

// WriteReport saves the baseline report to a JSON file atomically.
func (r *BaselineReporter) WriteReport(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}

	report := r.GenerateReport()
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	path := filepath.Join(dir, "baseline_report.json")
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	r.logger.Info("baseline report written",
		zap.String("path", path),
		zap.Int("unique_lineages", report.UniqueLineages),
		zap.Uint64("total_events", report.TotalEvents),
		zap.String("stability", report.Stability),
	)
	return nil
}

// WriteWhitelist saves the auto-generated whitelist to a YAML file atomically.
func (r *BaselineReporter) WriteWhitelist(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create whitelist dir: %w", err)
	}

	wl := r.GenerateWhitelist()
	data, err := yaml.Marshal(wl)
	if err != nil {
		return fmt.Errorf("marshal whitelist: %w", err)
	}

	header := fmt.Sprintf("# AUTO-GENERATED by ZTRE Discovery Engine\n# Learning window: %s → %s\n# Total events observed: %d\n# Generated at: %s\n#\n# Entries with review_flag: true should be reviewed by an operator.\n\n",
		wl.LearningWindow.Start.Format(time.RFC3339),
		wl.LearningWindow.End.Format(time.RFC3339),
		wl.TotalEventsObserved,
		wl.GeneratedAt.Format(time.RFC3339),
	)

	if err := writeFileAtomic(path, []byte(header+string(data)), 0o644); err != nil {
		return fmt.Errorf("write whitelist: %w", err)
	}

	r.logger.Info("auto-generated whitelist written",
		zap.String("path", path),
		zap.Int("entries", len(wl.WhitelistedLineages)),
	)
	return nil
}

// LoadWhitelist reads and parses a WhitelistConfig YAML file.
func LoadWhitelist(path string) (*WhitelistConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read whitelist: %w", err)
	}

	var wl WhitelistConfig
	if err := yaml.Unmarshal(data, &wl); err != nil {
		return nil, fmt.Errorf("parse whitelist: %w", err)
	}
	return &wl, nil
}
