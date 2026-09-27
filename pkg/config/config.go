package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// AgentConfig is the top-level configuration loaded from agent_config.yaml.
type AgentConfig struct {
	Agent struct {
		Mode        string          `yaml:"mode"`
		WorkerCount int             `yaml:"worker_count"`
		Discovery   DiscoveryConfig `yaml:"discovery"`
	} `yaml:"agent"`
	Server struct {
		MetricsPort int `yaml:"metrics_port"`
		HealthPort  int `yaml:"health_port"`
	} `yaml:"server"`
	Tetragon struct {
		SocketPath          string `yaml:"socket_path"`
		BufferSize          int    `yaml:"buffer_size"`
		ReconnectIntervalMs int    `yaml:"reconnect_interval_ms"`
	} `yaml:"tetragon"`
	DecisionEngine struct {
		Thresholds struct {
			GreenMax  int `yaml:"green_max"`
			YellowMax int `yaml:"yellow_max"`
		} `yaml:"thresholds"`
	} `yaml:"decision_engine"`
}

// DiscoveryConfig holds settings for the behavioral discovery phase.
type DiscoveryConfig struct {
	LearningWindow        Duration `yaml:"learning_window"`
	SnapshotInterval      Duration `yaml:"snapshot_interval"`
	StabilityThreshold    Duration `yaml:"stability_threshold"`
	MaxSnapshots          int      `yaml:"max_snapshots"`
	AutoGenerateWhitelist bool     `yaml:"auto_generate_whitelist"`
	OutputDir             string   `yaml:"output_dir"`
	WhitelistPath         string   `yaml:"whitelist_path"`
}

// Duration wraps time.Duration for YAML unmarshaling (e.g., "72h").
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	return d.Duration.String(), nil
}

// LoadAgentConfig reads and parses agent_config.yaml.
func LoadAgentConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg AgentConfig
	cfg.Agent.Mode = "discovery"
	cfg.Agent.WorkerCount = 4
	cfg.Agent.Discovery.LearningWindow.Duration = 72 * time.Hour
	cfg.Agent.Discovery.SnapshotInterval.Duration = 1 * time.Hour
	cfg.Agent.Discovery.StabilityThreshold.Duration = 4 * time.Hour
	cfg.Agent.Discovery.MaxSnapshots = 24
	cfg.Agent.Discovery.OutputDir = "data/discovery"
	cfg.Agent.Discovery.WhitelistPath = "data/discovery/auto_whitelist.yaml"
	cfg.Agent.Discovery.AutoGenerateWhitelist = true
	cfg.Server.MetricsPort = 9090
	cfg.Server.HealthPort = 8080
	cfg.Tetragon.SocketPath = "/var/run/tetragon/tetragon.sock"
	cfg.Tetragon.BufferSize = 50000
	cfg.Tetragon.ReconnectIntervalMs = 2000
	cfg.DecisionEngine.Thresholds.GreenMax = 39
	cfg.DecisionEngine.Thresholds.YellowMax = 69

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Validate agent mode.
	switch cfg.Agent.Mode {
	case "discovery", "shadow", "enforcement", "":
		// valid (empty falls through to default below)
	default:
		return nil, fmt.Errorf("invalid agent mode %q: must be discovery|shadow|enforcement", cfg.Agent.Mode)
	}

	// Defaults for empty or invalid values.
	if cfg.Agent.Mode == "" {
		cfg.Agent.Mode = "discovery"
	}
	if cfg.Agent.WorkerCount <= 0 {
		cfg.Agent.WorkerCount = 4
	}
	if cfg.Agent.Discovery.LearningWindow.Duration <= 0 {
		cfg.Agent.Discovery.LearningWindow.Duration = 72 * time.Hour
	}
	if cfg.Agent.Discovery.SnapshotInterval.Duration <= 0 {
		cfg.Agent.Discovery.SnapshotInterval.Duration = 1 * time.Hour
	}
	if cfg.Agent.Discovery.StabilityThreshold.Duration <= 0 {
		cfg.Agent.Discovery.StabilityThreshold.Duration = 4 * time.Hour
	}
	if cfg.Agent.Discovery.MaxSnapshots <= 0 {
		cfg.Agent.Discovery.MaxSnapshots = 24
	}
	if cfg.Agent.Discovery.OutputDir == "" {
		cfg.Agent.Discovery.OutputDir = "data/discovery"
	}
	if cfg.Agent.Discovery.WhitelistPath == "" {
		cfg.Agent.Discovery.WhitelistPath = filepath.Join(cfg.Agent.Discovery.OutputDir, "auto_whitelist.yaml")
	}

	return &cfg, nil
}
