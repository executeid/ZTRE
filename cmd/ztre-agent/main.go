package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/executeid/ztre/pkg/collector"
	"github.com/executeid/ztre/pkg/config"
	"github.com/executeid/ztre/pkg/discovery"
	"github.com/executeid/ztre/pkg/observability"
	"go.uber.org/zap"
)

func main() {
	var (
		socketPath    string
		metricsAddr   string
		bufferSize    int
		workerCount   int
		configPath    string
		mode          string
		genReport     bool
		debug         bool
		whitelistPath string
	)

	flag.StringVar(&socketPath, "tetragon-socket", "/var/run/tetragon/tetragon.sock", "Path to Tetragon gRPC unix domain socket")
	flag.StringVar(&metricsAddr, "metrics-addr", ":9090", "Address to expose Prometheus metrics and health check")
	flag.IntVar(&bufferSize, "buffer-size", 50000, "In-memory event buffer capacity")
	flag.IntVar(&workerCount, "workers", 0, "Number of consumer worker goroutines (default: from config or 4)")
	flag.StringVar(&configPath, "config", "config/agent_config.yaml", "Path to agent config YAML")
	flag.StringVar(&whitelistPath, "whitelist-path", "", "Path to process lineage whitelist YAML")
	flag.StringVar(&mode, "mode", "", "Agent mode override: discovery|shadow|enforcement")
	flag.BoolVar(&genReport, "generate-report", false, "Generate baseline report and whitelist, then exit")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	// 1. Initialize Logger
	logger, err := observability.NewLogger(debug)
	if err != nil {
		panic(err)
	}
	defer logger.Sync() //nolint:errcheck

	// 2. Load config (best-effort — fall back to defaults if missing)
	cfg, cfgErr := config.LoadAgentConfig(configPath)
	if cfgErr != nil {
		logger.Warn("failed to load config, using defaults", zap.Error(cfgErr))
		cfg = &config.AgentConfig{}
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
		cfg.Tetragon.SocketPath = "/var/run/tetragon/tetragon.sock"
		cfg.Tetragon.BufferSize = 50000
	}

	// Apply config file values if flags were not explicitly passed on CLI.
	var (
		socketPathSet    bool
		bufferSizeSet    bool
		metricsAddrSet   bool
		whitelistPathSet bool
		workerCountSet   bool
	)
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "tetragon-socket":
			socketPathSet = true
		case "buffer-size":
			bufferSizeSet = true
		case "metrics-addr":
			metricsAddrSet = true
		case "whitelist-path":
			whitelistPathSet = true
		case "workers":
			workerCountSet = true
		}
	})
	if !socketPathSet && cfg.Tetragon.SocketPath != "" {
		socketPath = cfg.Tetragon.SocketPath
	}
	if !bufferSizeSet && cfg.Tetragon.BufferSize > 0 {
		bufferSize = cfg.Tetragon.BufferSize
	}
	if !metricsAddrSet && cfg.Server.MetricsPort > 0 {
		metricsAddr = fmt.Sprintf(":%d", cfg.Server.MetricsPort)
	}
	if !whitelistPathSet && cfg.Agent.Discovery.WhitelistPath != "" {
		whitelistPath = cfg.Agent.Discovery.WhitelistPath
	}
	if whitelistPath == "" {
		whitelistPath = filepath.Join(cfg.Agent.Discovery.OutputDir, "auto_whitelist.yaml")
	}

	if !workerCountSet {
		if cfg.Agent.WorkerCount > 0 {
			workerCount = cfg.Agent.WorkerCount
		} else {
			workerCount = 4
		}
	} else if workerCount <= 0 {
		logger.Warn("invalid worker count, defaulting to 4", zap.Int("workers", workerCount))
		workerCount = 4
	}

	// CLI --mode overrides config file.
	agentMode := discovery.AgentMode(cfg.Agent.Mode)
	if mode != "" {
		agentMode = discovery.AgentMode(mode)
	}

	// Validate mode and set mode metric.
	switch agentMode {
	case discovery.ModeDiscovery:
		observability.AgentModeGauge.Set(0)
	case discovery.ModeShadow:
		observability.AgentModeGauge.Set(1)
	case discovery.ModeEnforcement:
		observability.AgentModeGauge.Set(2)
	default:
		logger.Warn("unknown agent mode, defaulting to discovery", zap.String("mode", string(agentMode)))
		agentMode = discovery.ModeDiscovery
		observability.AgentModeGauge.Set(0)
	}

	logger.Info("starting ZTRE Agent",
		zap.String("version", "v0.2.0"),
		zap.String("mode", string(agentMode)),
		zap.String("tetragon_socket", socketPath),
		zap.String("metrics_addr", metricsAddr),
		zap.Int("buffer_size", bufferSize),
		zap.Int("workers", workerCount),
	)

	// 3. Initialize Discovery Engine
	tracker := discovery.NewBehaviorTracker(logger)
	store := discovery.NewBaselineStore(
		tracker,
		cfg.Agent.Discovery.OutputDir,
		cfg.Agent.Discovery.SnapshotInterval.Duration,
		cfg.Agent.Discovery.StabilityThreshold.Duration,
		logger,
	)
	if cfg.Agent.Discovery.MaxSnapshots > 0 {
		store.MaxSnapshots = cfg.Agent.Discovery.MaxSnapshots
	}
	reporter := discovery.NewBaselineReporter(tracker, store, logger)

	// Restore previous baseline if any.
	if err := store.LoadLatestSnapshot(); err != nil {
		logger.Warn("could not load previous baseline", zap.Error(err))
	}

	// Handle --generate-report: produce report from existing data and exit.
	if genReport {
		if err := reporter.WriteReport(cfg.Agent.Discovery.OutputDir); err != nil {
			logger.Error("failed to write report", zap.Error(err))
			os.Exit(1)
		}
		if cfg.Agent.Discovery.AutoGenerateWhitelist {
			if err := reporter.WriteWhitelist(whitelistPath); err != nil {
				logger.Error("failed to write whitelist", zap.Error(err))
				os.Exit(1)
			}
		}
		logger.Info("report generated, exiting")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 4. Setup Signal Handling for Graceful Shutdown and Hot Reloading
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sighupChan := make(chan os.Signal, 1)
	signal.Notify(sighupChan, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighupChan:
				logger.Info("received SIGHUP, reloading configuration and whitelist")
				reloadedCfg, err := config.LoadAgentConfig(configPath)
				if err != nil {
					logger.Error("failed to reload configuration on SIGHUP", zap.Error(err))
				} else {
					logger.Info("configuration reloaded successfully",
						zap.String("mode", reloadedCfg.Agent.Mode),
						zap.String("output_dir", reloadedCfg.Agent.Discovery.OutputDir),
					)
				}

				targetWlPath := whitelistPath
				if reloadedCfg != nil && reloadedCfg.Agent.Discovery.WhitelistPath != "" && !whitelistPathSet {
					targetWlPath = reloadedCfg.Agent.Discovery.WhitelistPath
				}

				if wl, err := discovery.LoadWhitelist(targetWlPath); err != nil {
					if os.IsNotExist(err) {
						logger.Info("whitelist file not yet created, skipping whitelist reload", zap.String("path", targetWlPath))
					} else {
						logger.Error("failed to reload whitelist on SIGHUP", zap.String("path", targetWlPath), zap.Error(err))
					}
				} else {
					logger.Info("whitelist reloaded successfully",
						zap.String("path", targetWlPath),
						zap.Int("lineages", len(wl.WhitelistedLineages)),
					)
				}
			}
		}
	}()

	// 5. Start Metrics & Health Server (/metrics & /healthz)
	metricsServer := observability.StartMetricsServer(ctx, metricsAddr, logger)

	// 6. Initialize Event Buffer
	eventBuffer := collector.NewEventBuffer(bufferSize, logger)
	defer eventBuffer.Close()

	// 7. Start baseline snapshot loop (discovery + shadow modes).
	var storeWg sync.WaitGroup
	if agentMode == discovery.ModeDiscovery || agentMode == discovery.ModeShadow {
		storeWg.Add(1)
		go func() {
			defer storeWg.Done()
			store.Run(ctx)
		}()
	}

	// 8. Start Consumer Worker Pool with mode-aware routing.
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workerID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for event := range eventBuffer.Events() {
				switch agentMode {
				case discovery.ModeDiscovery:
					// Pure observation — track pattern, no classification.
					tracker.Track(event)
					observability.DiscoveryEventsTotal.Inc()

				case discovery.ModeShadow:
					// Continue learning + dry-run classification.
					tracker.Track(event)
					observability.DiscoveryEventsTotal.Inc()

					// Stage 3 shadow classification will be wired here.
					// For now, log what we'd do (placeholder for validator).
					logger.Debug("shadow mode event",
						zap.Int("worker", workerID),
						zap.String("type", string(event.EventType)),
						zap.String("namespace", event.Namespace),
						zap.String("pod", event.PodName),
						zap.String("binary", event.Binary),
						zap.String("parent_binary", event.ParentBinary),
					)

				case discovery.ModeEnforcement:
					// Full pipeline — Stage 3+4 will be wired here.
					logger.Debug("enforcement mode event",
						zap.Int("worker", workerID),
						zap.String("type", string(event.EventType)),
						zap.String("namespace", event.Namespace),
						zap.String("pod", event.PodName),
						zap.String("binary", event.Binary),
						zap.Uint32("pid", event.PID),
						zap.String("parent_binary", event.ParentBinary),
					)

				default:
					// Fallback: log like Stage 2 behavior.
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

	// 9. Start Tetragon Collector Client
	clientConfig := collector.ClientConfig{
		SocketPath:          socketPath,
		ReconnectInterval:   1 * time.Second,
		MaxReconnectBackoff: 10 * time.Second,
	}
	tetraClient := collector.NewClient(clientConfig, eventBuffer, logger)

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		if err := tetraClient.Start(ctx); err != nil {
			logger.Error("Tetragon client stopped with error", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	cancel() // Cancel context immediately to stop background workers and client stream
	logger.Info("received termination signal, initiating graceful shutdown", zap.String("signal", sig.String()))

	// 1. Wait for Tetragon collector client stream and background store loop to terminate
	<-clientDone
	storeWg.Wait()

	// 2. Close buffer and wait for all workers to finish draining
	eventBuffer.Close()
	wg.Wait()

	// 3. Save final baseline snapshot (discovery + shadow modes)
	if agentMode == discovery.ModeDiscovery || agentMode == discovery.ModeShadow {
		if err := store.SaveSnapshot(); err != nil {
			logger.Error("failed to save final snapshot on shutdown", zap.Error(err))
		}
	}

	// 4. Generate report on shutdown if in discovery mode and auto-generate is on.
	if agentMode == discovery.ModeDiscovery && cfg.Agent.Discovery.AutoGenerateWhitelist {
		logger.Info("generating baseline report on shutdown",
			zap.Int("patterns", tracker.UniquePatternCount()),
			zap.Uint64("events", tracker.TotalEvents()),
		)
		if err := reporter.WriteReport(cfg.Agent.Discovery.OutputDir); err != nil {
			logger.Error("failed to write shutdown report", zap.Error(err))
		}
		if err := reporter.WriteWhitelist(whitelistPath); err != nil {
			logger.Error("failed to write shutdown whitelist", zap.Error(err))
		}
	}

	// 5. Shutdown metrics server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	_ = metricsServer.Shutdown(shutdownCtx)

	logger.Info("ZTRE Agent terminated cleanly",
		zap.String("mode", string(agentMode)),
		zap.Int("patterns_discovered", tracker.UniquePatternCount()),
		zap.Uint64("total_events_tracked", tracker.TotalEvents()),
	)
}
