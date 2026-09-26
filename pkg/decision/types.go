package decision

import (
	"time"

	"github.com/executeid/ztre/pkg/risk"
	"github.com/executeid/ztre/pkg/validator"
)

// Action defines the automated response tier determined by the Decision Engine.
type Action string

const (
	ActionAllowAndLog       Action = "ALLOW_AND_LOG"
	ActionLogAndAlert       Action = "LOG_AND_ALERT"
	ActionAutoContainment   Action = "AUTO_CONTAINMENT"
)

// ThresholdConfig holds the score boundaries for the tiered response matrix.
type ThresholdConfig struct {
	GreenMax  int `yaml:"green_max" json:"green_max"`   // Default 39: < 40 -> ALLOW & LOG
	YellowMax int `yaml:"yellow_max" json:"yellow_max"` // Default 69: 40–69 -> LOG & ALERT
}

// DefaultThresholds returns the standard PRD decision thresholds.
func DefaultThresholds() ThresholdConfig {
	return ThresholdConfig{
		GreenMax:  39,
		YellowMax: 69,
	}
}

// Alert captures the full incident context emitted for Yellow or Red zone events.
type Alert struct {
	EventID           string                   `json:"event_id"`
	Timestamp         time.Time                `json:"timestamp"`
	PodName           string                   `json:"pod_name"`
	Namespace         string                   `json:"namespace"`
	ParentBinary      string                   `json:"parent_binary"`
	Binary            string                   `json:"binary"`
	Arguments         string                   `json:"arguments"`
	Classification    validator.Classification `json:"classification"`
	SeverityScore     float64                  `json:"severity_score"`
	ContextScore      float64                  `json:"context_score"`
	AssetScore        float64                  `json:"asset_score"`
	TotalRiskScore    float64                  `json:"total_risk_score"`
	Action            Action                   `json:"action"`
	RecommendedAction string                   `json:"recommended_action"`
}

// FromRiskScore creates an Alert populated from event details, classification, and score.
func NewAlert(
	eventID, namespace, pod, parent, binary, args string,
	class validator.Classification,
	score risk.RiskScore,
	action Action,
) Alert {
	var recommended string
	switch action {
	case ActionAutoContainment:
		recommended = "Immediate pod network containment triggered. Review process tree and forensic memory."
	case ActionLogAndAlert:
		recommended = "Manual security analyst review recommended. Check command line arguments and network endpoints."
	default:
		recommended = "Activity permitted by security baseline. No immediate intervention required."
	}

	return Alert{
		EventID:           eventID,
		Timestamp:         time.Now().UTC(),
		PodName:           pod,
		Namespace:         namespace,
		ParentBinary:      parent,
		Binary:            binary,
		Arguments:         args,
		Classification:    class,
		SeverityScore:     score.SeverityScore,
		ContextScore:      score.ContextScore,
		AssetScore:        score.AssetScore,
		TotalRiskScore:    score.TotalScore,
		Action:            action,
		RecommendedAction: recommended,
	}
}
