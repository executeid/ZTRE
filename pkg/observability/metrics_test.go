package observability

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestMetrics_IdempotentRegistration(t *testing.T) {
	// Calling RegisterMetrics multiple times must not panic due to AlreadyRegisteredError.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RegisterMetrics panicked on re-registration: %v", r)
		}
	}()

	RegisterMetrics()
	RegisterMetrics()
}

func TestStartMetricsServer_Healthz(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := zap.NewNop()
	srv := StartMetricsServer(ctx, "127.0.0.1:0", logger)
	defer func() { _ = srv.Close() }()

	url := "http://" + srv.Addr + "/healthz"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("expected body containing 'ok', got %q", string(body))
	}
}

func TestStartMetricsServer_MetricsEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	EventsIngestedTotal.WithLabelValues("execve", "default").Inc()

	logger := zap.NewNop()
	srv := StartMetricsServer(ctx, "127.0.0.1:0", logger)
	defer func() { _ = srv.Close() }()

	url := "http://" + srv.Addr + "/metrics"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if !strings.Contains(string(body), "ztre_collector_events_ingested_total") {
		t.Fatalf("expected metrics output to contain 'ztre_collector_events_ingested_total', got: %s", string(body))
	}
}

func TestStartMetricsServer_GracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	logger := zap.NewNop()
	srv := StartMetricsServer(ctx, "127.0.0.1:0", logger)
	addr := srv.Addr

	// Verify server responds before cancellation
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("initial healthz request failed: %v", err)
	}
	_ = resp.Body.Close()

	// Cancel context to initiate graceful shutdown
	cancel()

	// Server should stop accepting requests within a short timeout
	deadline := time.Now().Add(2 * time.Second)
	stopped := false
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		r, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			stopped = true
			break
		}
		_ = r.Body.Close()
	}

	if !stopped {
		t.Fatal("server did not stop cleanly after context cancellation")
	}
}
