package risk

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/executeid/ztre/pkg/collector"
	"github.com/executeid/ztre/pkg/validator"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// RiskScore holds the breakdown and total of a scored event.
type RiskScore struct {
	SeverityScore float64 `json:"severity_score"`
	ContextScore  float64 `json:"context_score"`
	AssetScore    float64 `json:"asset_score"`
	TotalScore    float64 `json:"total_score"`
}

// Zone returns the tiered response zone for this score.
// Boundaries match decision.Engine.Evaluate(): Green < greenMax+1, Yellow < yellowMax+1, Red >= yellowMax+1.
func (r RiskScore) Zone(greenMax, yellowMax int) string {
	switch {
	case r.TotalScore < float64(greenMax+1):
		return "GREEN"
	case r.TotalScore < float64(yellowMax+1):
		return "YELLOW"
	default:
		return "RED"
	}
}

// PolicyConfig holds the externally-configurable risk scoring policy.
type PolicyConfig struct {
	Weights struct {
		Severity        float64 `yaml:"severity"`
		Context         float64 `yaml:"context"`
		AssetCriticality float64 `yaml:"asset_criticality"`
	} `yaml:"weights"`
	SeverityScores map[string]float64 `yaml:"severity_scores"`
	ContextScores  map[string]float64 `yaml:"context_scores"`
	AssetCriticality struct {
		Critical     AssetTier `yaml:"critical"`
		High         AssetTier `yaml:"high"`
		Medium       AssetTier `yaml:"medium"`
		Low          AssetTier `yaml:"low"`
		DefaultScore float64   `yaml:"default_score"`
	} `yaml:"asset_criticality"`
}

// AssetTier defines a criticality tier with its associated namespaces and score.
type AssetTier struct {
	Namespaces []string `yaml:"namespaces"`
	Score      float64  `yaml:"score"`
}

// Engine calculates multidimensional risk scores.
type Engine struct {
	policy       PolicyConfig
	nsScoreCache map[string]float64 // namespace → asset score
	logger       *zap.Logger
}

// NewEngine creates a risk engine from a policy YAML file.
func NewEngine(policyPath string, logger *zap.Logger) (*Engine, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("read risk policy: %w", err)
	}
	var policy PolicyConfig
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse risk policy: %w", err)
	}
	if err := validateWeights(policy); err != nil {
		return nil, err
	}
	e := &Engine{policy: policy, logger: logger}
	e.buildNamespaceCache()
	return e, nil
}

// NewEngineFromPolicy creates a risk engine from an in-memory policy.
func NewEngineFromPolicy(policy PolicyConfig, logger *zap.Logger) (*Engine, error) {
	if err := validateWeights(policy); err != nil {
		return nil, err
	}
	e := &Engine{policy: policy, logger: logger}
	e.buildNamespaceCache()
	return e, nil
}

func validateWeights(p PolicyConfig) error {
	sum := p.Weights.Severity + p.Weights.Context + p.Weights.AssetCriticality
	if math.Abs(sum-1.0) > 0.001 {
		return fmt.Errorf("policy weights must sum to 1.0, got %f", sum)
	}
	return nil
}

func (e *Engine) buildNamespaceCache() {
	e.nsScoreCache = make(map[string]float64)
	for _, ns := range e.policy.AssetCriticality.Critical.Namespaces {
		e.nsScoreCache[ns] = e.policy.AssetCriticality.Critical.Score
	}
	for _, ns := range e.policy.AssetCriticality.High.Namespaces {
		e.nsScoreCache[ns] = e.policy.AssetCriticality.High.Score
	}
	for _, ns := range e.policy.AssetCriticality.Medium.Namespaces {
		e.nsScoreCache[ns] = e.policy.AssetCriticality.Medium.Score
	}
	for _, ns := range e.policy.AssetCriticality.Low.Namespaces {
		e.nsScoreCache[ns] = e.policy.AssetCriticality.Low.Score
	}
}

// Calculate computes the risk score for an event given its classification.
// Formula: Risk = ws*S + wc*C + wa*A
func (e *Engine) Calculate(event *collector.SecurityEvent, class validator.Classification) RiskScore {
	s := e.severityScore(event)
	c := e.contextScore(class)
	a := e.assetScore(event.Namespace)

	ws := e.policy.Weights.Severity
	wc := e.policy.Weights.Context
	wa := e.policy.Weights.AssetCriticality

	total := ws*s + wc*c + wa*a

	return RiskScore{
		SeverityScore: s,
		ContextScore:  c,
		AssetScore:    a,
		TotalScore:    total,
	}
}

// severityScore maps event binary/arguments to a severity value.
func (e *Engine) severityScore(event *collector.SecurityEvent) float64 {
	bin := strings.ToLower(event.Binary)
	args := strings.ToLower(event.Arguments)

	// Check reverse shell indicators first (highest severity).
	if isReverseShell(bin, args) {
		if v, ok := e.policy.SeverityScores["reverse_shell"]; ok {
			return v
		}
	}
	// Match binary name against known severity entries.
	checks := []struct {
		key  string
		match func() bool
	}{
		{"chmod_suid", func() bool { return strings.Contains(bin, "chmod") && strings.Contains(args, "+s") }},
		{"curl_download", func() bool { return strings.Contains(bin, "curl") || strings.Contains(bin, "wget") }},
		{"bash_spawn", func() bool { return isSuspiciousShell(bin) }},
		{"nmap_scan", func() bool { return strings.Contains(bin, "nmap") }},
		{"file_write_etc", func() bool {
			return (event.EventType == collector.EventTypeKprobe || event.EventType == collector.EventTypeFileAccess) &&
				strings.Contains(args, "/etc/")
		}},
	}
	for _, c := range checks {
		if c.match() {
			if v, ok := e.policy.SeverityScores[c.key]; ok {
				return v
			}
		}
	}
	return e.policy.SeverityScores["default"]
}

func isReverseShell(bin, args string) bool {
	// Match exact binary names or path suffixes to avoid false positives on
	// binaries like "encryptor", "sync_tool", or "fence" that contain "nc" as a
	// substring. Only match: nc, ncat, netcat.
	binBase := filepath.Base(bin)
	if binBase == "nc" || binBase == "ncat" || binBase == "netcat" {
		if strings.Contains(args, "-e") || strings.Contains(args, "-c") {
			return true
		}
	}
	// bash -i >& /dev/tcp/...
	if isSuspiciousShell(bin) && strings.Contains(args, "/dev/tcp") {
		return true
	}
	return false
}

func isSuspiciousShell(bin string) bool {
	for _, s := range []string{"bash", "sh", "dash", "zsh", "ksh", "csh"} {
		if strings.HasSuffix(bin, "/"+s) || bin == s {
			return true
		}
	}
	return false
}

func (e *Engine) contextScore(class validator.Classification) float64 {
	if v, ok := e.policy.ContextScores[string(class)]; ok {
		return v
	}
	return 0
}

func (e *Engine) assetScore(namespace string) float64 {
	if v, ok := e.nsScoreCache[namespace]; ok {
		return v
	}
	return e.policy.AssetCriticality.DefaultScore
}
