package validator

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Classification is the result of process lineage validation.
type Classification string

const (
	ClassNormal     Classification = "NORMAL"
	ClassSuspicious Classification = "SUSPICIOUS"
	ClassAnomalous  Classification = "ANOMALOUS"
)

// WhitelistEntry mirrors discovery.WhitelistEntry for standalone parsing.
type WhitelistEntry struct {
	Parent          string   `yaml:"parent"`
	AllowedChildren []string `yaml:"allowed_children"`
}

// WhitelistConfig is the top-level whitelist structure (compatible with both
// manually-authored and auto-generated whitelists).
type WhitelistConfig struct {
	WhitelistedLineages []WhitelistEntry `yaml:"whitelisted_lineages"`
}

// Whitelist is a concurrent-safe, hot-reloadable lookup of parent→allowed children.
type Whitelist struct {
	mu    sync.RWMutex
	allow map[string]map[string]bool // parent → set of children
	path  string
	logger *zap.Logger
}

// NewWhitelist creates a Whitelist and loads from path. Missing file → empty whitelist.
func NewWhitelist(path string, logger *zap.Logger) (*Whitelist, error) {
	w := &Whitelist{
		allow:  make(map[string]map[string]bool),
		path:   path,
		logger: logger,
	}
	if err := w.Load(); err != nil {
		if os.IsNotExist(err) {
			logger.Warn("whitelist file not found, starting with empty whitelist", zap.String("path", path))
			return w, nil
		}
		return nil, err
	}
	return w, nil
}

// Load reads and replaces the whitelist from disk.
func (w *Whitelist) Load() error {
	data, err := os.ReadFile(w.path)
	if err != nil {
		return err
	}
	var cfg WhitelistConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse whitelist %s: %w", w.path, err)
	}
	allow := make(map[string]map[string]bool, len(cfg.WhitelistedLineages))
	for _, entry := range cfg.WhitelistedLineages {
		children := make(map[string]bool, len(entry.AllowedChildren))
		for _, c := range entry.AllowedChildren {
			children[c] = true
		}
		allow[entry.Parent] = children
	}
	w.mu.Lock()
	w.allow = allow
	w.mu.Unlock()
	w.logger.Info("whitelist loaded",
		zap.String("path", w.path),
		zap.Int("parents", len(allow)),
	)
	return nil
}

// LoadMulti merges a second whitelist file on top (manual overrides).
func (w *Whitelist) LoadMulti(paths ...string) error {
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		var cfg WhitelistConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse whitelist %s: %w", p, err)
		}
		w.mu.Lock()
		for _, entry := range cfg.WhitelistedLineages {
			existing, ok := w.allow[entry.Parent]
			if !ok {
				existing = make(map[string]bool)
				w.allow[entry.Parent] = existing
			}
			for _, c := range entry.AllowedChildren {
				existing[c] = true
			}
		}
		w.mu.Unlock()
		w.logger.Info("merged override whitelist", zap.String("path", p))
	}
	return nil
}

// Classify determines if a parent→child relationship is normal, suspicious, or anomalous.
func (w *Whitelist) Classify(parent, child string) Classification {
	parent = filepath.Base(parent)
	child = filepath.Base(child)

	w.mu.RLock()
	defer w.mu.RUnlock()

	children, parentKnown := w.allow[parent]
	if !parentKnown {
		return ClassSuspicious
	}
	if children[child] {
		return ClassNormal
	}
	return ClassAnomalous
}
