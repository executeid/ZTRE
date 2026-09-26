package decision

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/executeid/ztre/pkg/risk"
	"github.com/executeid/ztre/pkg/validator"
	"go.uber.org/zap"
)

func TestEngine_ThresholdBoundaries(t *testing.T) {
	cfg := ThresholdConfig{
		GreenMax:  39,
		YellowMax: 69,
	}
	engine := NewEngine(cfg, zap.NewNop())

	tests := []struct {
		score      float64
		wantAction Action
	}{
		{0.0, ActionAllowAndLog},
		{20.0, ActionAllowAndLog},
		{39.0, ActionAllowAndLog},       // boundary: <= 39 -> Green
		{39.1, ActionLogAndAlert},       // > 39 -> Yellow
		{40.0, ActionLogAndAlert},       // 40 -> Yellow
		{60.0, ActionLogAndAlert},       // 60 -> Yellow
		{69.0, ActionLogAndAlert},       // boundary: <= 69 -> Yellow
		{69.1, ActionAutoContainment},   // > 69 -> Red
		{70.0, ActionAutoContainment},   // 70 -> Red
		{85.0, ActionAutoContainment},   // 85 -> Red
		{100.0, ActionAutoContainment},  // 100 -> Red
	}

	for _, tc := range tests {
		got := engine.Evaluate(tc.score)
		if got != tc.wantAction {
			t.Errorf("Evaluate(%.1f) = %s, want %s", tc.score, got, tc.wantAction)
		}
	}
}

func TestEngine_EvaluateRiskScore(t *testing.T) {
	engine := NewEngine(DefaultThresholds(), zap.NewNop())

	rs := risk.RiskScore{
		SeverityScore: 70,
		ContextScore:  100,
		AssetScore:    100,
		TotalScore:    85,
	}

	if got := engine.EvaluateRiskScore(rs); got != ActionAutoContainment {
		t.Errorf("expected AUTO_CONTAINMENT for score 85, got %s", got)
	}
}

func TestEngine_HotReloadThresholds(t *testing.T) {
	engine := NewEngine(DefaultThresholds(), zap.NewNop())

	// Score 50 is Yellow by default
	if got := engine.Evaluate(50); got != ActionLogAndAlert {
		t.Fatalf("expected LOG_AND_ALERT for 50, got %s", got)
	}

	// Tighten thresholds: Yellow max becomes 45
	engine.UpdateThresholds(ThresholdConfig{GreenMax: 30, YellowMax: 45})

	// Now score 50 becomes Red
	if got := engine.Evaluate(50); got != ActionAutoContainment {
		t.Fatalf("expected AUTO_CONTAINMENT for 50 after reload, got %s", got)
	}
}

func TestDispatcher_StdoutAndWebhook(t *testing.T) {
	var webhookCalls int32
	var lastReceivedAlert Alert

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookCalls, 1)
		if r.Header.Get("X-Custom-Header") != "ztre-test" {
			t.Errorf("expected custom header")
		}
		var al Alert
		if err := json.NewDecoder(r.Body).Decode(&al); err != nil {
			t.Errorf("failed to decode alert json: %v", err)
		}
		lastReceivedAlert = al
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	stdoutSink := NewStdoutAlertSink(logger)
	webhookSink := NewWebhookAlertSink(server.URL, 2*time.Second, map[string]string{
		"X-Custom-Header": "ztre-test",
	})

	dispatcher := NewDispatcher(logger, stdoutSink, webhookSink)

	if len(dispatcher.Sinks()) != 2 {
		t.Fatalf("expected 2 registered sinks, got %d", len(dispatcher.Sinks()))
	}

	alert := NewAlert(
		"evt-123",
		"database",
		"pg-pod-1",
		"nginx",
		"bash",
		"-i",
		validator.ClassAnomalous,
		risk.RiskScore{
			SeverityScore: 70,
			ContextScore:  100,
			AssetScore:    100,
			TotalScore:    85,
		},
		ActionAutoContainment,
	)

	dispatcher.Dispatch(context.Background(), alert)

	if atomic.LoadInt32(&webhookCalls) != 1 {
		t.Errorf("expected 1 webhook call, got %d", webhookCalls)
	}
	if lastReceivedAlert.PodName != "pg-pod-1" {
		t.Errorf("expected pod pg-pod-1, got %s", lastReceivedAlert.PodName)
	}
	if lastReceivedAlert.Action != ActionAutoContainment {
		t.Errorf("expected ActionAutoContainment, got %s", lastReceivedAlert.Action)
	}
}

func BenchmarkEngine_Evaluate(b *testing.B) {
	engine := NewEngine(DefaultThresholds(), zap.NewNop())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(75.5)
	}
}

// TestEngine_InvalidYellowMax verifies the guard logs a warning and applies default
// instead of silently using an operator-provided YellowMax <= GreenMax.
func TestEngine_InvalidYellowMax(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	// GreenMax=50, YellowMax=30 is invalid (30 <= 50).
	// Engine should warn and set YellowMax to 69.
	engine := NewEngine(ThresholdConfig{GreenMax: 50, YellowMax: 30}, logger)
	cfg := engine.Thresholds()
	if cfg.GreenMax != 50 {
		t.Errorf("expected GreenMax=50 preserved, got %d", cfg.GreenMax)
	}
	if cfg.YellowMax != 69 {
		t.Errorf("expected YellowMax defaulted to 69, got %d", cfg.YellowMax)
	}
	// Verify valid operator config is NOT changed (GreenMax=50, YellowMax=80).
	engine2 := NewEngine(ThresholdConfig{GreenMax: 50, YellowMax: 80}, zap.NewNop())
	cfg2 := engine2.Thresholds()
	if cfg2.YellowMax != 80 {
		t.Errorf("expected valid YellowMax=80 preserved, got %d", cfg2.YellowMax)
	}
}

// TestDispatcher_ZeroSinks verifies Dispatch is a no-op and does not panic when no sinks registered.
func TestDispatcher_ZeroSinks(t *testing.T) {
	d := NewDispatcher(zap.NewNop())
	alert := NewAlert("e1", "ns", "pod", "nginx", "bash", "",
		validator.ClassAnomalous,
		risk.RiskScore{TotalScore: 85},
		ActionAutoContainment,
	)
	// Must not panic.
	d.Dispatch(context.Background(), alert)
}

// TestDispatcher_SinkPanic verifies a panicking sink goroutine does NOT crash
// the process — the panic is recovered and other sinks still execute.
func TestDispatcher_SinkPanic(t *testing.T) {
	var goodSinkCalled bool

	panicSink := &mockSink{name: "panic-sink", onSend: func(Alert) error {
		panic("intentional test panic")
	}}
	goodSink := &mockSink{name: "good-sink", onSend: func(Alert) error {
		goodSinkCalled = true
		return nil
	}}

	d := NewDispatcher(zap.NewNop(), panicSink, goodSink)
	alert := NewAlert("e1", "ns", "pod", "nginx", "bash", "",
		validator.ClassAnomalous, risk.RiskScore{TotalScore: 85}, ActionAutoContainment)

	// Must not crash the process.
	d.Dispatch(context.Background(), alert)

	if !goodSinkCalled {
		t.Error("expected good sink to be called even though panic-sink panicked")
	}
}

// TestWebhookSink_Non2xxDrainsBody verifies response body is drained on non-2xx
// so the underlying TCP connection is returned to the pool.
func TestWebhookSink_Non2xxDrainsBody(t *testing.T) {
	const responseBody = "error from server"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()

	sink := NewWebhookAlertSink(server.URL, 2*time.Second, nil)
	alert := NewAlert("e1", "ns", "pod", "nginx", "bash", "",
		validator.ClassAnomalous, risk.RiskScore{TotalScore: 85}, ActionAutoContainment)

	err := sink.Send(context.Background(), alert)
	if err == nil {
		t.Error("expected error on 500 response")
	}
}

type mockSink struct {
	name   string
	onSend func(Alert) error
}

func (m *mockSink) Name() string { return m.name }
func (m *mockSink) Send(_ context.Context, alert Alert) error {
	if m.onSend != nil {
		return m.onSend(alert)
	}
	return nil
}
