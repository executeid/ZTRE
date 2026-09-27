package observability

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
	if !strings.Contains(string(body), "ztre_events_ingested_total") {
		t.Fatalf("expected metrics output to contain 'ztre_events_ingested_total', got: %s", string(body))
	}
}

func TestMetrics_RequiredAndOperationalMetricNames(t *testing.T) {
	expectedMetrics := []struct {
		collector prometheus.Collector
		expected  string
	}{
		// PRD NFR-06 required metrics
		{EventsIngestedTotal, "ztre_events_ingested_total"},
		{EventsClassifiedTotal, "ztre_events_classified_total"},
		{ContainmentActionsTotal, "ztre_containment_actions_total"},
		{ApiErrorsTotal, "ztre_api_errors_total"},
		// Extra operational metrics
		{EventsDroppedTotal, "ztre_events_dropped_total"},
		{EventParseDuration, "ztre_event_parse_duration_seconds"},
		{RiskScoreHistogram, "ztre_risk_score_distribution"},
		{DiscoveryPatternsTotal, "ztre_discovery_patterns_observed_total"},
		{DiscoveryStabilityGauge, "ztre_discovery_stability_status"},
		{AgentModeGauge, "ztre_agent_mode"},
		{ShadowDecisionsTotal, "ztre_shadow_decisions_total"},
	}

	for _, tc := range expectedMetrics {
		ch := make(chan *prometheus.Desc, 10)
		tc.collector.Describe(ch)
		close(ch)

		found := false
		for desc := range ch {
			if strings.Contains(desc.String(), `fqName: "`+tc.expected+`"`) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("metric collector missing expected fqName %q", tc.expected)
		}
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
