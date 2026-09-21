package discovery

import "time"

// AgentMode controls the event processing pipeline behavior.
type AgentMode string

const (
	ModeDiscovery   AgentMode = "discovery"   // passive observe, build baseline
	ModeShadow      AgentMode = "shadow"      // classify + score but don't enforce
	ModeEnforcement AgentMode = "enforcement" // full pipeline with containment
)

// StabilityStatus describes the convergence state of the behavioral baseline.
type StabilityStatus int

const (
	StatusLearning    StabilityStatus = 0
	StatusStabilizing StabilityStatus = 1
	StatusStable      StabilityStatus = 2
)

func (s StabilityStatus) String() string {
	switch s {
	case StatusLearning:
		return "LEARNING"
	case StatusStabilizing:
		return "STABILIZING"
	case StatusStable:
		return "STABLE"
	default:
		return "UNKNOWN"
	}
}

// ExecutionPattern tracks an observed parent→child process relationship.
type ExecutionPattern struct {
	ParentBinary string    `json:"parent_binary"`
	ChildBinary  string    `json:"child_binary"`
	Namespace    string    `json:"namespace"`
	WorkloadName string    `json:"workload_name"`
	Count        uint64    `json:"count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Nodes        []string  `json:"nodes"`
}

// PatternStats holds computed statistics for an execution pattern.
type PatternStats struct {
	Frequency   float64 `json:"frequency"`     // events per hour
	IsBurst     bool    `json:"is_burst"`       // only appears in short bursts
	IsRecurring bool    `json:"is_recurring"`   // appears consistently across time windows
	IsCrossNode bool    `json:"is_cross_node"`  // appears on multiple nodes
	Percentile  float64 `json:"percentile"`     // position in frequency distribution
	ZScore      float64 `json:"z_score"`        // standard deviations from mean frequency
	Confidence  float64 `json:"confidence"`     // 0.0–1.0 whitelist confidence
	ReviewFlag  bool    `json:"review_flag"`    // true if operator should review
}

// LineageProfile is the aggregated behavioral baseline for one workload.
type LineageProfile struct {
	Namespace       string              `json:"namespace"`
	WorkloadName    string              `json:"workload_name"`
	WorkloadKind    string              `json:"workload_kind"`
	Patterns        []*ExecutionPattern `json:"patterns"`
	TotalEvents     uint64              `json:"total_events"`
	UniqueProcesses int                 `json:"unique_processes"`
}

// BaselineSnapshot captures the full discovery state at a point in time.
type BaselineSnapshot struct {
	Timestamp       time.Time                    `json:"timestamp"`
	LearningStart   time.Time                    `json:"learning_start"`
	TotalEvents     uint64                       `json:"total_events"`
	UniquePatterns  int                          `json:"unique_patterns"`
	Patterns        map[string]*ExecutionPattern `json:"patterns"`
	Stability       StabilityStatus              `json:"stability"`
	LastNewPattern  time.Time                    `json:"last_new_pattern"`
}

// BaselineReport is the human-readable output of the discovery phase.
type BaselineReport struct {
	LearningWindow  TimeWindow            `json:"learning_window"`
	TotalEvents     uint64                `json:"total_events"`
	UniqueLineages  int                   `json:"unique_lineages"`
	Profiles        []*LineageProfile     `json:"workload_profiles"`
	AnomalyCandidates []*AnomalyCandidate `json:"anomaly_candidates"`
	Stability       string                `json:"stability_status"`
	Recommendation  string                `json:"recommendation"`
}

// TimeWindow represents a start/end period.
type TimeWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// AnomalyCandidate flags a pattern that looks suspicious even during learning.
type AnomalyCandidate struct {
	ParentBinary string  `json:"parent_binary"`
	ChildBinary  string  `json:"child_binary"`
	Namespace    string  `json:"namespace"`
	Count        uint64  `json:"count"`
	ZScore       float64 `json:"z_score"`
	Verdict      string  `json:"verdict"`
}

// WhitelistEntry represents one entry in the auto-generated whitelist.
type WhitelistEntry struct {
	Parent                string   `yaml:"parent"                 json:"parent"`
	AllowedChildren       []string `yaml:"allowed_children"       json:"allowed_children"`
	QuarantinedCandidates []string `yaml:"quarantined_candidates,omitempty" json:"quarantined_candidates,omitempty"`
	Confidence            float64  `yaml:"confidence"             json:"confidence"`
	Source                string   `yaml:"source"                 json:"source"`
	ObservedCount         uint64   `yaml:"observed_count"         json:"observed_count"`
	ReviewFlag            bool     `yaml:"review_flag,omitempty"  json:"review_flag,omitempty"`
	TemporalNote          string   `yaml:"temporal_note,omitempty" json:"temporal_note,omitempty"`
}

// WhitelistConfig is the top-level auto-generated whitelist structure.
type WhitelistConfig struct {
	GeneratedAt        time.Time        `yaml:"generated_at"        json:"generated_at"`
	LearningWindow     TimeWindow       `yaml:"learning_window"     json:"learning_window"`
	TotalEventsObserved uint64          `yaml:"total_events_observed" json:"total_events_observed"`
	WhitelistedLineages []WhitelistEntry `yaml:"whitelisted_lineages" json:"whitelisted_lineages"`
}
