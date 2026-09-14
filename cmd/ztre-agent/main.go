package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/executeid/ztre/pkg/collector"
	"github.com/executeid/ztre/pkg/observability"
	"go.uber.org/zap"
)

func main() {
	var (
		socketPath  string
		metricsAddr string
		bufferSize  int
		debug       bool
	)

	flag.StringVar(&socketPath, "tetragon-socket", "/var/run/tetragon/tetragon.sock", "Path to Tetragon gRPC unix domain socket")
	flag.StringVar(&metricsAddr, "metrics-addr", ":9090", "Address to expose Prometheus metrics and health check")
	flag.IntVar(&bufferSize, "buffer-size", 50000, "In-memory event buffer capacity")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	// 1. Initialize Logger
	logger, err := observability.NewLogger(debug)
	if err != nil {
		panic(err)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("starting ZTRE Agent",
		zap.String("version", "v0.1.0"),
		zap.String("tetragon_socket", socketPath),
		zap.String("metrics_addr", metricsAddr),
		zap.Int("buffer_size", bufferSize),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. Setup Signal Handling for Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// 3. Start Metrics & Health Server (/metrics & /healthz)
	metricsServer := observability.StartMetricsServer(ctx, metricsAddr, logger)

	// 4. Initialize Event Buffer
	eventBuffer := collector.NewEventBuffer(bufferSize, logger)
	defer eventBuffer.Close()

	// 5. Start Consumer Worker Pool
	const workerCount = 4
	for i := 0; i < workerCount; i++ {
		workerID := i
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-eventBuffer.Events():
					if !ok {
						return
					}
					// Stage 2: Ingest & log received event
					logger.Info("ingested security event",
						zap.Int("worker", workerID),
						zap.String("type", string(event.EventType)),
						zap.String("namespace", event.Namespace),
						zap.String("pod", event.PodName),
						zap.String("binary", event.Binary),
						zap.Uint32("pid", event.PID),
						zap.String("parent_binary", event.ParentBinary),
					)
				}
			}
		}()
	}

	// 6. Start Tetragon Collector Client
	clientConfig := collector.ClientConfig{
		SocketPath:          socketPath,
		ReconnectInterval:   1 * time.Second,
		MaxReconnectBackoff: 10 * time.Second,
	}
	tetraClient := collector.NewClient(clientConfig, eventBuffer, logger)

	go func() {
		if err := tetraClient.Start(ctx); err != nil {
			logger.Error("Tetragon client stopped with error", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	logger.Info("received termination signal, initiating graceful shutdown", zap.String("signal", sig.String()))

	cancel()

	// Shutdown metrics server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	_ = metricsServer.Shutdown(shutdownCtx)

	logger.Info("ZTRE Agent terminated cleanly")
}
