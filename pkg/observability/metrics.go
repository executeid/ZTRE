package observability

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	EventsIngestedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ztre",
			Subsystem: "collector",
			Name:      "events_ingested_total",
			Help:      "Total number of events ingested from Tetragon.",
		},
		[]string{"event_type", "namespace"},
	)

	EventsDroppedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ztre",
			Subsystem: "collector",
			Name:      "events_dropped_total",
			Help:      "Total number of events dropped due to buffer overflow.",
		},
	)

	EventParseDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "ztre",
			Subsystem: "collector",
			Name:      "event_parse_duration_seconds",
			Help:      "Latency of parsing raw Tetragon events.",
			Buckets:   []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01}, // 10µs to 10ms
		},
	)

	// Discovery metrics (Stage 2.5)
	DiscoveryPatternsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ztre",
			Subsystem: "discovery",
			Name:      "patterns_observed_total",
			Help:      "Total unique parent→child execution patterns discovered.",
		},
	)

	DiscoveryEventsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ztre",
			Subsystem: "discovery",
			Name:      "events_tracked_total",
			Help:      "Total events processed in discovery mode.",
		},
	)

	DiscoveryStabilityGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ztre",
			Subsystem: "discovery",
			Name:      "stability_status",
			Help:      "Baseline stability status (0=LEARNING, 1=STABILIZING, 2=STABLE).",
		},
	)

	AgentModeGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ztre",
			Subsystem: "agent",
			Name:      "mode",
			Help:      "Current agent mode (0=discovery, 1=shadow, 2=enforcement).",
		},
	)

	ShadowDecisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ztre",
			Subsystem: "shadow",
			Name:      "decisions_total",
			Help:      "Shadow mode decisions — what would have happened.",
		},
		[]string{"action"},
	)

	// Stage 3 — Validation & Risk metrics
	EventsClassifiedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ztre",
			Subsystem: "validator",
			Name:      "events_classified_total",
			Help:      "Total events classified by lineage validation.",
		},
		[]string{"classification"},
	)

	RiskScoreHistogram = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "ztre",
			Subsystem: "risk",
			Name:      "score_distribution",
			Help:      "Distribution of computed risk scores.",
			Buckets:   []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		},
	)

	// Stage 4 — Decision & Containment metrics
	ContainmentActionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ztre",
			Subsystem: "containment",
			Name:      "actions_total",
			Help:      "Total number of automated network containment actions executed.",
		},
	)

	ApiErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ztre",
			Subsystem: "containment",
			Name:      "api_errors_total",
			Help:      "Total number of Kubernetes API errors encountered during containment.",
		},
	)

	AlertsDispatchedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ztre",
			Subsystem: "decision",
			Name:      "alerts_dispatched_total",
			Help:      "Total security alerts emitted by sink type.",
		},
		[]string{"sink"},
	)
)

func init() {
	RegisterMetrics()
}

// RegisterMetrics registers all Prometheus metrics with the default registry.
// It catches prometheus.AlreadyRegisteredError to ensure idempotent registration.
func RegisterMetrics() {
	registerSafe(
		EventsIngestedTotal,
		EventsDroppedTotal,
		EventParseDuration,
		DiscoveryPatternsTotal,
		DiscoveryEventsTotal,
		DiscoveryStabilityGauge,
		AgentModeGauge,
		ShadowDecisionsTotal,
		EventsClassifiedTotal,
		RiskScoreHistogram,
		ContainmentActionsTotal,
		ApiErrorsTotal,
		AlertsDispatchedTotal,
	)
}

func registerSafe(collectors ...prometheus.Collector) {
	for _, c := range collectors {
		if err := prometheus.Register(c); err != nil {
			var are prometheus.AlreadyRegisteredError
			if errors.As(err, &are) {
				continue
			}
			panic(err)
		}
	}
}

// StartMetricsServer starts an HTTP server serving Prometheus metrics on the given address.
func StartMetricsServer(ctx context.Context, addr string, logger *zap.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("failed to listen on metrics addr", zap.String("addr", addr), zap.Error(err))
		return srv
	}
	srv.Addr = ln.Addr().String()

	go func() {
		logger.Info("metrics and health server listening", zap.String("addr", srv.Addr))
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server error", zap.Error(err))
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	return srv
}
