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
	"github.com/executeid/ztre/pkg/containment"
	"github.com/executeid/ztre/pkg/decision"
	"github.com/executeid/ztre/pkg/discovery"
	"github.com/executeid/ztre/pkg/observability"
	"github.com/executeid/ztre/pkg/risk"
	"github.com/executeid/ztre/pkg/validator"
	"go.uber.org/zap"
)

func main() {
	var (
		socketPath     string
		metricsAddr    string
		bufferSize     int
		workerCount    int
		configPath     string
		mode           string
		genReport      bool
		debug          bool
		whitelistPath  string
		riskPolicyPath string
		manualWlPath   string
		webhookURL     string
	)

	flag.StringVar(&socketPath, "tetragon-socket", "/var/run/tetragon/tetragon.sock", "Path to Tetragon gRPC unix domain socket")
	flag.StringVar(&metricsAddr, "metrics-addr", ":9090", "Address to expose Prometheus metrics and health check")
	flag.IntVar(&bufferSize, "buffer-size", 50000, "In-memory event buffer capacity")
	flag.IntVar(&workerCount, "workers", 0, "Number of consumer worker goroutines (default: from config or 4)")
	flag.StringVar(&configPath, "config", "config/agent_config.yaml", "Path to agent config YAML")
	flag.StringVar(&whitelistPath, "whitelist-path", "", "Path to auto-generated whitelist YAML")
	flag.StringVar(&manualWlPath, "manual-whitelist", "config/process_lineage_whitelist.yaml", "Path to manual whitelist overrides")
	flag.StringVar(&riskPolicyPath, "risk-policy", "config/risk_scoring_policy.yaml", "Path to risk scoring policy YAML")
	flag.StringVar(&webhookURL, "webhook-url", "", "Optional HTTP webhook endpoint for security alerts")
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
		zap.String("version", "v0.4.0"),
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

	// 4. Initialize Stage 3 & Stage 4 Engines
	var (
		whitelist           *validator.Whitelist
		riskEngine          *risk.Engine
		decisionEngine      *decision.Engine
		alertDispatcher     *decision.Dispatcher
		containmentExecutor containment.ContainmentExecutor
	)

	thresholds := decision.ThresholdConfig{
		GreenMax:  cfg.DecisionEngine.Thresholds.GreenMax,
		YellowMax: cfg.DecisionEngine.Thresholds.YellowMax,
	}
	if thresholds.GreenMax == 0 && thresholds.YellowMax == 0 {
		thresholds = decision.DefaultThresholds()
	}
	decisionEngine = decision.NewEngine(thresholds, logger)

	// Setup Alert Dispatcher
	alertDispatcher = decision.NewDispatcher(logger, decision.NewStdoutAlertSink(logger))
	if webhookURL != "" {
		alertDispatcher.RegisterSink(decision.NewWebhookAlertSink(webhookURL, 5*time.Second, nil))
	}

	if agentMode == discovery.ModeShadow || agentMode == discovery.ModeEnforcement {
		var wlErr error
		whitelist, wlErr = validator.NewWhitelist(whitelistPath, logger)
		if wlErr != nil {
			logger.Error("failed to load whitelist", zap.Error(wlErr))
			os.Exit(1)
		}
		// Merge manual overrides on top
		if err := whitelist.LoadMulti(manualWlPath); err != nil {
			logger.Warn("could not load manual whitelist overrides", zap.Error(err))
		}

		var riskErr error
		riskEngine, riskErr = risk.NewEngine(riskPolicyPath, logger)
		if riskErr != nil {
			logger.Error("failed to load risk policy", zap.Error(riskErr))
			os.Exit(1)
		}

		// In enforcement mode, initialize Kubernetes containment executor
		if agentMode == discovery.ModeEnforcement {
			var contErr error
			containmentExecutor, contErr = containment.NewInClusterExecutor(logger)
			if contErr != nil {
				logger.Error("failed to initialize containment executor", zap.Error(contErr))
				os.Exit(1)
			}
		}

		logger.Info("Stage 3 & 4 modules initialized",
			zap.String("whitelist", whitelistPath),
			zap.String("risk_policy", riskPolicyPath),
			zap.Int("green_max", thresholds.GreenMax),
			zap.Int("yellow_max", thresholds.YellowMax),
			zap.Bool("containment_active", containmentExecutor != nil),
		)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()

	metricsCtx, metricsCancel := context.WithCancel(context.Background())
	defer metricsCancel()

	// 5. Setup Signal Handling for Graceful Shutdown and Hot Reloading
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	sighupChan := make(chan os.Signal, 1)
	signal.Notify(sighupChan, syscall.SIGHUP)
	defer signal.Stop(sighupChan)

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
					if reloadedCfg.DecisionEngine.Thresholds.GreenMax > 0 && reloadedCfg.DecisionEngine.Thresholds.YellowMax > 0 {
						if err := decisionEngine.UpdateThresholds(decision.ThresholdConfig{
							GreenMax:  reloadedCfg.DecisionEngine.Thresholds.GreenMax,
							YellowMax: reloadedCfg.DecisionEngine.Thresholds.YellowMax,
						}); err != nil {
							logger.Error("failed to update decision thresholds", zap.Error(err))
						}
					}
				}

				targetWlPath := whitelistPath
				if reloadedCfg != nil && reloadedCfg.Agent.Discovery.WhitelistPath != "" && !whitelistPathSet {
					targetWlPath = reloadedCfg.Agent.Discovery.WhitelistPath
				}

				if whitelist != nil {
					if err := whitelist.Load(); err != nil {
						logger.Error("failed to reload whitelist on SIGHUP", zap.String("path", whitelistPath), zap.Error(err))
					} else {
						if err := whitelist.LoadMulti(manualWlPath); err != nil {
							logger.Warn("could not reload manual whitelist overrides", zap.Error(err))
						}
						logger.Info("validator whitelist reloaded successfully on SIGHUP")
					}
				}

				if wl, err := discovery.LoadWhitelist(targetWlPath); err != nil {
					if os.IsNotExist(err) {
						logger.Info("whitelist file not yet created, skipping whitelist reload", zap.String("path", targetWlPath))
					} else {
						logger.Error("failed to reload whitelist on SIGHUP", zap.String("path", targetWlPath), zap.Error(err))
					}
				} else {
					logger.Info("discovery whitelist reloaded successfully",
						zap.String("path", targetWlPath),
						zap.Int("lineages", len(wl.WhitelistedLineages)),
					)
				}
			}
		}
	}()

	// 6. Start Metrics & Health Server (/metrics & /healthz)
	metricsServer := observability.StartMetricsServer(metricsCtx, metricsAddr, logger)

	// 7. Initialize Event Buffer
	eventBuffer := collector.NewEventBuffer(bufferSize, logger)
	defer eventBuffer.Close()

	// 8. Start baseline snapshot loop (discovery + shadow modes).
	var storeWg sync.WaitGroup
	if agentMode == discovery.ModeDiscovery || agentMode == discovery.ModeShadow {
		storeWg.Add(1)
		go func() {
			defer storeWg.Done()
			store.Run(streamCtx)
		}()
	}

	// 9. Start Consumer Worker Pool with mode-aware routing.
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workerID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for event := range eventBuffer.Events() {
				// Skip control-plane and infrastructure namespaces (e.g. monitoring)
				// so ZTRE never quarantines dynamic infra workloads such as scrapers.
				if cfg.IsNamespaceExcluded(event.Namespace) {
					continue
				}
				switch agentMode {
				case discovery.ModeDiscovery:
					// Pure observation — track pattern, no classification.
					tracker.Track(event)
					observability.DiscoveryEventsTotal.Inc()

				case discovery.ModeShadow:
					// Continue learning + dry-run classification & scoring.
					tracker.Track(event)
					observability.DiscoveryEventsTotal.Inc()

					if event.EventType != collector.EventTypeExecve {
						break
					}
					class := whitelist.Classify(event.ParentBinary, event.Binary)
					observability.EventsClassifiedTotal.WithLabelValues(string(class)).Inc()
					if class == validator.ClassNormal {
						break
					}
					score := riskEngine.Calculate(event, class)
					observability.RiskScoreHistogram.Observe(score.TotalScore)
					action := decisionEngine.EvaluateRiskScore(score)
					zone := score.Zone(
						decisionEngine.Thresholds().GreenMax,
						decisionEngine.Thresholds().YellowMax,
					)
					observability.ShadowDecisionsTotal.WithLabelValues(string(action)).Inc()
					logger.Info("[SHADOW] classification result",
						zap.String("mode", "shadow"),
						zap.String("pod", event.PodName),
						zap.String("namespace", event.Namespace),
						zap.String("parent", event.ParentBinary),
						zap.String("child", event.Binary),
						zap.String("classification", string(class)),
						zap.Float64("severity_score", score.SeverityScore),
						zap.Float64("context_score", score.ContextScore),
						zap.Float64("asset_score", score.AssetScore),
						zap.Float64("total_risk_score", score.TotalScore),
						zap.String("zone", zone),
						zap.String("would_have_action", string(action)),
						zap.Bool("enforced", false),
					)

				case discovery.ModeEnforcement:
					// Full Stage 3 + 4 pipeline: classify → score → decide → contain/alert.
					if event.EventType != collector.EventTypeExecve {
						break
					}
					class := whitelist.Classify(event.ParentBinary, event.Binary)
					observability.EventsClassifiedTotal.WithLabelValues(string(class)).Inc()
					if class == validator.ClassNormal {
						logger.Debug("event classified NORMAL",
							zap.String("parent", event.ParentBinary),
							zap.String("child", event.Binary),
						)
						break
					}
					score := riskEngine.Calculate(event, class)
					observability.RiskScoreHistogram.Observe(score.TotalScore)
					action := decisionEngine.EvaluateRiskScore(score)

					alert := decision.NewAlert(
						fmt.Sprintf("%s-%d", event.PodName, event.PID),
						event.Namespace,
						event.PodName,
						event.ParentBinary,
						event.Binary,
						event.Arguments,
						class,
						score,
						action,
					)

					switch action {
					case decision.ActionAllowAndLog:
						logger.Info("event permitted under threshold",
							zap.String("pod", event.PodName),
							zap.String("namespace", event.Namespace),
							zap.Float64("total_risk_score", score.TotalScore),
						)

					case decision.ActionLogAndAlert:
						alertDispatcher.Dispatch(ctx, alert)

					case decision.ActionAutoContainment:
						// 1. Dispatch critical containment alert
						alertDispatcher.Dispatch(ctx, alert)

						// 2. Execute automated network isolation via Cilium label patching
						if containmentExecutor != nil {
							if err := containmentExecutor.Quarantine(ctx, event.Namespace, event.PodName, score.TotalScore); err != nil {
								logger.Error("failed to execute automated containment",
									zap.String("namespace", event.Namespace),
									zap.String("pod", event.PodName),
									zap.Error(err),
								)
							}
						} else {
							logger.Warn("containment executor not initialized, skipping pod patch",
								zap.String("namespace", event.Namespace),
								zap.String("pod", event.PodName),
							)
						}
					}

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

	// 10. Start Tetragon Collector Client
	clientConfig := collector.ClientConfig{
		SocketPath:          socketPath,
		ReconnectInterval:   1 * time.Second,
		MaxReconnectBackoff: 10 * time.Second,
	}
	tetraClient := collector.NewClient(clientConfig, eventBuffer, logger)

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		if err := tetraClient.Start(streamCtx); err != nil {
			logger.Error("Tetragon client stopped with error", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	logger.Info("received termination signal, initiating graceful shutdown", zap.String("signal", sig.String()))

	// 1. Stop intake stream: cancel streamCtx so collector client stream and store loop terminate
	streamCancel()
	<-clientDone
	storeWg.Wait()

	// 2. Close buffer and wait for all workers to finish draining in-flight events
	eventBuffer.Close()
	wg.Wait()
	cancel() // All workers drained, cancel remaining pipeline context

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
	metricsCancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	_ = metricsServer.Shutdown(shutdownCtx)

	logger.Info("ZTRE Agent terminated cleanly",
		zap.String("mode", string(agentMode)),
		zap.Int("patterns_discovered", tracker.UniquePatternCount()),
		zap.Uint64("total_events_tracked", tracker.TotalEvents()),
	)
}
