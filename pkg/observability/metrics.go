package observability

import (
	"context"
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
)

func init() {
	prometheus.MustRegister(EventsIngestedTotal)
	prometheus.MustRegister(EventsDroppedTotal)
	prometheus.MustRegister(EventParseDuration)
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

	go func() {
		logger.Info("metrics and health server listening", zap.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server error", zap.Error(err))
		}
	}()

	return srv
}
