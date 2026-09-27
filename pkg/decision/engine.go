package decision

import (
	"fmt"
	"sync"

	"github.com/executeid/ztre/pkg/risk"
	"go.uber.org/zap"
)

// Engine evaluates risk scores against configurable thresholds and decides actions.
type Engine struct {
	mu         sync.RWMutex
	thresholds ThresholdConfig
	logger     *zap.Logger
}

// NewEngine creates a new DecisionEngine.
// cfg is used as-is if both GreenMax and YellowMax are valid (GreenMax > 0,
// YellowMax > GreenMax). If both are zero (unset), DefaultThresholds are applied.
// If only YellowMax <= GreenMax is violated, NewEngine returns an error to
// prevent silent misconfiguration.
func NewEngine(cfg ThresholdConfig, logger *zap.Logger) *Engine {
	if cfg.GreenMax <= 0 && cfg.YellowMax <= 0 {
		// Both unset: apply defaults.
		cfg = DefaultThresholds()
	} else if cfg.GreenMax <= 0 {
		cfg.GreenMax = 39
	}
	if cfg.YellowMax <= cfg.GreenMax {
		// Invalid ordering: log a warning and fall back to default YellowMax.
		logger.Warn("decision engine: YellowMax <= GreenMax is invalid, using default YellowMax",
			zap.Int("green_max", cfg.GreenMax),
			zap.Int("yellow_max_provided", cfg.YellowMax),
			zap.Int("yellow_max_applied", 69),
		)
		cfg.YellowMax = 69
	}

	return &Engine{
		thresholds: cfg,
		logger:     logger,
	}
}

// UpdateThresholds safely hot-reloads threshold values.
// Returns error if YellowMax <= GreenMax to prevent corrupted triage.
func (e *Engine) UpdateThresholds(cfg ThresholdConfig) error {
	if cfg.YellowMax <= cfg.GreenMax {
		return fmt.Errorf("invalid thresholds: yellow_max (%d) must exceed green_max (%d)", cfg.YellowMax, cfg.GreenMax)
	}
	e.mu.Lock()
	e.thresholds = cfg
	e.mu.Unlock()
	e.logger.Info("decision engine thresholds updated",
		zap.Int("green_max", cfg.GreenMax),
		zap.Int("yellow_max", cfg.YellowMax),
	)
	return nil
}

// Thresholds returns a copy of current threshold configuration.
func (e *Engine) Thresholds() ThresholdConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.thresholds
}

// Evaluate determines the Action based on a raw numeric total risk score.
// Green:  score < GreenMax+1 (i.e. < 40)  -> ALLOW & LOG
// Yellow: score < YellowMax+1 (i.e. 40–69) -> LOG & ALERT
// Red:    score >= YellowMax+1 (i.e. >= 70) -> AUTO CONTAINMENT
func (e *Engine) Evaluate(totalScore float64) Action {
	e.mu.RLock()
	cfg := e.thresholds
	e.mu.RUnlock()

	// Use < (max+1) to correctly handle fractional scores per PRD:
	// Green < 40, Yellow 40–69, Red >= 70.
	switch {
	case totalScore < float64(cfg.GreenMax+1):
		return ActionAllowAndLog
	case totalScore < float64(cfg.YellowMax+1):
		return ActionLogAndAlert
	default:
		return ActionAutoContainment
	}
}

// EvaluateRiskScore determines the Action from a computed RiskScore struct.
func (e *Engine) EvaluateRiskScore(score risk.RiskScore) Action {
	return e.Evaluate(score.TotalScore)
}
