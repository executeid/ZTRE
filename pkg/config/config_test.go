package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAgentConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent_config.yaml")
	content := `
agent:
  mode: "shadow"
  worker_count: 8
  discovery:
    learning_window: 48h
    snapshot_interval: 30m
    stability_threshold: 2h
    max_snapshots: 12
    auto_generate_whitelist: true
    output_dir: "data/test"
server:
  metrics_port: 9090
tetragon:
  socket_path: "/var/run/tetragon/tetragon.sock"
  buffer_size: 10000
decision_engine:
  thresholds:
    green_max: 39
    yellow_max: 69
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Agent.Mode != "shadow" {
		t.Errorf("expected mode shadow, got %s", cfg.Agent.Mode)
	}
	if cfg.Agent.WorkerCount != 8 {
		t.Errorf("expected worker_count 8, got %d", cfg.Agent.WorkerCount)
	}
	if cfg.Agent.Discovery.MaxSnapshots != 12 {
		t.Errorf("expected max_snapshots 12, got %d", cfg.Agent.Discovery.MaxSnapshots)
	}
	if cfg.Agent.Discovery.LearningWindow.Duration != 48*time.Hour {
		t.Errorf("expected learning_window 48h, got %v", cfg.Agent.Discovery.LearningWindow.Duration)
	}
	if cfg.Agent.Discovery.SnapshotInterval.Duration != 30*time.Minute {
		t.Errorf("expected snapshot_interval 30m, got %v", cfg.Agent.Discovery.SnapshotInterval.Duration)
	}
	if cfg.Agent.Discovery.StabilityThreshold.Duration != 2*time.Hour {
		t.Errorf("expected stability_threshold 2h, got %v", cfg.Agent.Discovery.StabilityThreshold.Duration)
	}
	if !cfg.Agent.Discovery.AutoGenerateWhitelist {
		t.Error("expected auto_generate_whitelist true")
	}
	if cfg.Agent.Discovery.OutputDir != "data/test" {
		t.Errorf("expected output_dir data/test, got %s", cfg.Agent.Discovery.OutputDir)
	}
	if cfg.Tetragon.BufferSize != 10000 {
		t.Errorf("expected buffer_size 10000, got %d", cfg.Tetragon.BufferSize)
	}
}

func TestLoadAgentConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "minimal.yaml")
	// Minimal config — all defaults should fill in.
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Agent.Mode != "discovery" {
		t.Errorf("expected default mode discovery, got %s", cfg.Agent.Mode)
	}
	if cfg.Agent.WorkerCount != 4 {
		t.Errorf("expected default worker_count 4, got %d", cfg.Agent.WorkerCount)
	}
	if cfg.Agent.Discovery.MaxSnapshots != 24 {
		t.Errorf("expected default max_snapshots 24, got %d", cfg.Agent.Discovery.MaxSnapshots)
	}
	if cfg.Agent.Discovery.LearningWindow.Duration != 72*time.Hour {
		t.Errorf("expected default learning_window 72h, got %v", cfg.Agent.Discovery.LearningWindow.Duration)
	}
	if cfg.Agent.Discovery.SnapshotInterval.Duration != 1*time.Hour {
		t.Errorf("expected default snapshot_interval 1h, got %v", cfg.Agent.Discovery.SnapshotInterval.Duration)
	}
	if cfg.Agent.Discovery.StabilityThreshold.Duration != 4*time.Hour {
		t.Errorf("expected default stability_threshold 4h, got %v", cfg.Agent.Discovery.StabilityThreshold.Duration)
	}
	if !cfg.Agent.Discovery.AutoGenerateWhitelist {
		t.Error("expected default auto_generate_whitelist true")
	}
	if cfg.Agent.Discovery.OutputDir != "data/discovery" {
		t.Errorf("expected default output_dir data/discovery, got %s", cfg.Agent.Discovery.OutputDir)
	}
	if cfg.Agent.Discovery.WhitelistPath != "data/discovery/auto_whitelist.yaml" {
		t.Errorf("expected default whitelist_path data/discovery/auto_whitelist.yaml, got %s", cfg.Agent.Discovery.WhitelistPath)
	}
}

func TestLoadAgentConfig_Missing(t *testing.T) {
	_, err := LoadAgentConfig("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestLoadAgentConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(cfgPath, []byte("agent: [broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAgentConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadAgentConfig_ExplicitFalse(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "false.yaml")
	content := `
agent:
  discovery:
    auto_generate_whitelist: false
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Agent.Discovery.AutoGenerateWhitelist {
		t.Error("expected auto_generate_whitelist false")
	}
}

func TestLoadAgentConfig_CustomWhitelistPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "custom_wl.yaml")
	content := `
agent:
  discovery:
    output_dir: "/var/data"
    whitelist_path: "/var/data/custom_whitelist.yaml"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Agent.Discovery.WhitelistPath != "/var/data/custom_whitelist.yaml" {
		t.Errorf("expected custom whitelist_path, got %s", cfg.Agent.Discovery.WhitelistPath)
	}
}

func TestDuration_MarshalUnmarshal(t *testing.T) {
	d := Duration{Duration: 30 * time.Minute}
	val, err := d.MarshalYAML()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if val != "30m0s" {
		t.Errorf("expected 30m0s, got %v", val)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad_duration.yaml")
	content := `
agent:
  discovery:
    learning_window: "not_a_duration"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadAgentConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid duration string")
	}
}

func TestIsNamespaceExcluded(t *testing.T) {
	cfg := &AgentConfig{
		ExcludeNamespaces: []string{"monitoring", "observability"},
	}

	cases := []struct {
		ns       string
		excluded bool
	}{
		{"monitoring", true},      // user-configured
		{"observability", true},   // user-configured
		{"ztre-system", true},     // built-in default
		{"kube-system", true},     // built-in default
		{"kube-public", true},     // built-in default
		{"ztre-test", false},      // test workload - enforced
		{"default", false},        // user workload - enforced
		{"frontend", false},       // user workload - enforced
	}

	for _, c := range cases {
		if got := cfg.IsNamespaceExcluded(c.ns); got != c.excluded {
			t.Errorf("IsNamespaceExcluded(%q) = %v, want %v", c.ns, got, c.excluded)
		}
	}
}

func TestIsNamespaceExcludedEmptyList(t *testing.T) {
	cfg := &AgentConfig{} // no user exclusions
	// Built-in defaults still apply.
	if !cfg.IsNamespaceExcluded("kube-system") {
		t.Error("expected kube-system to always be excluded")
	}
	// Non-default namespaces are enforced.
	if cfg.IsNamespaceExcluded("production") {
		t.Error("expected production to NOT be excluded with empty list")
	}
}
