package core

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

// Engine is the main 1SEC engine that orchestrates all components.
type Engine struct {
	Config          *Config
	Bus             *EventBus
	Registry        *ModuleRegistry
	Pipeline        *AlertPipeline
	RustSidecar     *RustSidecar
	Correlator      *ThreatCorrelator
	ResponseEngine  *ResponseEngine
	RustMatchBridge *RustMatchBridge
	Archiver        *Archiver
	Dedup           *EventDedup
	Logger          zerolog.Logger
	CloudReporter   *CloudReporter
	CommandPoller   *CommandPoller
	Escalation      *EscalationManager
	ctx             context.Context
	cancel          context.CancelFunc
	configPath      string
	logBuffer       *LogRingBuffer
	stopDedup       func()
	startTime       time.Time
}

// NewEngine creates a new 1SEC engine.
func NewEngine(cfg *Config) (*Engine, error) {
	logBuffer := NewLogRingBuffer(5000)

	// Configure logger — tee output to both console/stdout and the ring buffer
	var logger zerolog.Logger
	if cfg.Logging.Format == "json" {
		logger = zerolog.New(logBuffer.MultiWriter(os.Stdout)).With().Timestamp().Logger()
	} else {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
		logger = zerolog.New(logBuffer.MultiWriter(consoleWriter)).With().Timestamp().Logger()
	}

	switch cfg.LogLevel() {
	case "debug":
		logger = logger.Level(zerolog.DebugLevel)
	case "warn":
		logger = logger.Level(zerolog.WarnLevel)
	case "error":
		logger = logger.Level(zerolog.ErrorLevel)
	default:
		logger = logger.Level(zerolog.InfoLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())

	engine := &Engine{
		Config:      cfg,
		Registry:    NewModuleRegistry(logger),
		Pipeline:    NewAlertPipeline(logger, cfg.Alerts.MaxStore),
		RustSidecar: NewRustSidecar(&cfg.RustEngine, &cfg.Bus, logger),
		Logger:      logger.With().Str("component", "engine").Logger(),
		ctx:         ctx,
		cancel:      cancel,
		logBuffer:   logBuffer,
	}

	// Add console alert handler if enabled
	if cfg.Alerts.EnableConsole {
		engine.Pipeline.AddHandler(func(alert *Alert) {
			engine.Logger.Warn().
				Str("alert_id", alert.ID).
				Str("module", alert.Module).
				Str("severity", alert.Severity.String()).
				Str("title", alert.Title).
				Str("description", alert.Description).
				Msg("SECURITY ALERT")
		})
	}

	// Add webhook alert handlers
	for _, url := range cfg.Alerts.WebhookURLs {
		webhookURL := url
		engine.Pipeline.AddHandler(func(alert *Alert) {
			go sendWebhook(webhookURL, alert, logger)
		})
	}

	return engine, nil
}

// Start initializes the event bus, starts all modules, and begins processing.
func (e *Engine) Start() error {
	e.Logger.Info().Msg("starting 1SEC engine")

	// Start event bus
	bus, err := NewEventBus(&e.Config.Bus, e.Logger)
	if err != nil {
		return fmt.Errorf("starting event bus: %w", err)
	}
	e.Bus = bus
	if e.RustSidecar != nil {
		e.RustSidecar.token = bus.token
	}

	// Wire alert pipeline to publish alerts to the bus
	e.Pipeline.AddHandler(func(alert *Alert) {
		go func() {
			if err := e.Bus.PublishAlert(alert); err != nil {
				e.Logger.Error().Err(err).Str("alert_id", alert.ID).Msg("failed to publish alert to bus")
			}
		}()
	})

	// Start cross-module threat correlator — watches alerts from all modules
	// and detects multi-stage attack chains (e.g., recon → exploit → exfil)
	e.Correlator = NewThreatCorrelator(e.Logger, e.Pipeline, e.Bus)
	e.Pipeline.AddHandler(func(alert *Alert) {
		go e.Correlator.Ingest(alert)
	})
	e.Correlator.Start(e.ctx)

	// Start escalation manager — auto-escalates unacknowledged alerts
	e.Escalation = NewEscalationManager(e.Logger, e.Config.Escalation, e.Pipeline)
	e.Pipeline.AddHandler(func(alert *Alert) {
		go e.Escalation.Track(alert)
	})

	// Start response engine (enforcement layer) — subscribes to alerts and
	// executes configured response actions (block IP, kill process, etc.)
	if e.Config.Enforcement != nil && e.Config.Enforcement.Enabled {
		e.ResponseEngine = NewResponseEngine(e.Logger, e.Bus, e.Pipeline, e.Config)
		e.ResponseEngine.Start(e.ctx)
	}

	// Start Rust match bridge — subscribes to sec.matches.> from the Rust sidecar
	// and converts pattern match results into alerts for the enforcement pipeline.
	// This closes the gap where Rust detects threats but they never reach enforcement.
	if e.Config.RustEngine.Enabled {
		e.RustMatchBridge = NewRustMatchBridge(e.Logger, e.Pipeline, e.Bus)
		if err := e.RustMatchBridge.Start(e.ctx); err != nil {
			e.Logger.Warn().Err(err).Msg("failed to start rust match bridge — Rust detections won't reach enforcement")
		}
	}

	// Start cold archiver — separate durable consumer for indefinite retention
	if e.Config.Archive.Enabled {
		archiver, err := NewArchiver(e.Config.Archive, bus, e.Logger)
		if err != nil {
			e.Logger.Warn().Err(err).Msg("failed to create cold archiver")
		} else {
			e.Archiver = archiver
			if err := e.Archiver.Start(e.ctx); err != nil {
				e.Logger.Warn().Err(err).Msg("failed to start cold archiver")
			}
		}
	}

	// Start all enabled modules
	if err := e.Registry.StartAll(e.ctx, e.Bus, e.Pipeline, e.Config); err != nil {
		return fmt.Errorf("starting modules: %w", err)
	}

	// Start event dedup cache — prevents duplicate processing when syslog
	// listener and a collector both ingest the same log line.
	e.Dedup = NewEventDedup(30*time.Second, 50000)
	e.stopDedup = e.Dedup.StartCleanup(10 * time.Second)

	// Subscribe to all events and route to interested modules only.
	// Dedup check happens here so duplicates never reach modules.
	// Rust detections remain independent; routing a Go event is not a detection.
	if err := e.Bus.SubscribeToAllEvents(func(event *SecurityEvent) {
		if e.Dedup.IsDuplicate(event) {
			e.Logger.Debug().
				Str("event_id", event.ID).
				Str("event_type", event.Type).
				Msg("duplicate event suppressed")
			return
		}
		e.Registry.RouteEvent(event, e.Logger)
	}); err != nil {
		return fmt.Errorf("subscribing to events: %w", err)
	}

	e.Logger.Info().
		Int("modules", e.Registry.Count()).
		Msg("1SEC engine started")

	// Start Rust sidecar if enabled (after bus is ready so it can connect)
	if e.Config.RustEngine.Enabled {
		if e.RustSidecar != nil {
			if err := e.RustSidecar.Start(e.ctx, e.configPath); err != nil {
				e.Logger.Warn().Err(err).Msg("failed to start rust engine sidecar")
			}
		}
	} else {
		e.Logger.Info().Msg("Rust sidecar disabled — set rust_engine.enabled: true and install the 1sec-engine binary for high-throughput pattern matching and optional packet capture")
	}

	// Start cloud reporter — sends heartbeats, enforcement records, and
	// correlations to the 1SEC cloud dashboard for remote monitoring.
	e.startTime = time.Now()
	if e.Config.Cloud.Enabled && e.Config.Cloud.APIKey != "" {
		e.CloudReporter = NewCloudReporter(e)
		e.CloudReporter.Start()

		// Start command poller — receives enforcement commands from the dashboard
		e.CommandPoller = NewCommandPoller(e)
		e.CommandPoller.Start()
	}

	return nil
}

// Run starts the engine and blocks until shutdown signal is received.
func (e *Engine) Run() error {
	if err := e.Start(); err != nil {
		return err
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		e.Logger.Info().Str("signal", sig.String()).Msg("shutdown signal received")
	case <-e.ctx.Done():
		e.Logger.Info().Msg("context cancelled")
	}

	return e.Shutdown()
}

// Shutdown gracefully stops the engine.
func (e *Engine) Shutdown() error {
	e.Logger.Info().Msg("shutting down 1SEC engine")
	e.cancel()

	// Stop cloud reporter
	if e.CloudReporter != nil {
		e.CloudReporter.Stop()
	}

	// Stop command poller
	if e.CommandPoller != nil {
		e.CommandPoller.Stop()
	}

	// Stop Rust sidecar first (it depends on the bus)
	if e.RustSidecar != nil {
		e.RustSidecar.Stop()
	}

	// Stop response engine
	if e.ResponseEngine != nil {
		e.ResponseEngine.Stop()
	}

	// Stop escalation manager
	if e.Escalation != nil {
		e.Escalation.Stop()
	}

	e.Registry.StopAll()

	// Stop dedup cleanup
	if e.stopDedup != nil {
		e.stopDedup()
	}

	if e.Bus != nil {
		if err := e.Bus.Close(); err != nil {
			e.Logger.Error().Err(err).Msg("error closing event bus")
		}
	}

	e.Logger.Info().Msg("1SEC engine stopped")
	return nil
}

// Context returns the engine's context.
func (e *Engine) Context() context.Context {
	return e.ctx
}

// SetConfigPath stores the config file path for the Rust sidecar to use.
func (e *Engine) SetConfigPath(path string) {
	e.configPath = path
}

// GetConfigPath returns the config file path.
func (e *Engine) GetConfigPath() string {
	return e.configPath
}

// Uptime returns the duration since the engine started.
func (e *Engine) Uptime() time.Duration {
	if e.startTime.IsZero() {
		return 0
	}
	return time.Since(e.startTime)
}

// SetStartTimeForTest sets the engine start time (test helper only).
func (e *Engine) SetStartTimeForTest(t time.Time) {
	e.startTime = t
}

// GetLogEntries returns the most recent n log entries from the ring buffer.
func (e *Engine) GetLogEntries(n int) []LogEntry {
	if e.logBuffer == nil {
		return []LogEntry{}
	}
	return e.logBuffer.GetEntries(n)
}

// sendWebhook sends an alert to a webhook URL.
func sendWebhook(url string, alert *Alert, logger zerolog.Logger) {
	data, err := alert.Marshal()
	if err != nil {
		logger.Error().Err(err).Msg("failed to marshal alert for webhook")
		return
	}

	resp, err := httpPost(url, "application/json", data)
	if err != nil {
		logger.Error().Err(err).Str("url", url).Msg("webhook delivery failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		logger.Warn().Int("status", resp.StatusCode).Str("url", url).Msg("webhook returned error status")
	}
}

// NewCollectorLogger creates a standalone logger for collector CLI commands.
func NewCollectorLogger(format, level string) zerolog.Logger {
	var logger zerolog.Logger
	if format == "json" {
		logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	} else {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
		logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
	}

	switch level {
	case "debug":
		logger = logger.Level(zerolog.DebugLevel)
	case "warn":
		logger = logger.Level(zerolog.WarnLevel)
	case "error":
		logger = logger.Level(zerolog.ErrorLevel)
	default:
		logger = logger.Level(zerolog.InfoLevel)
	}

	return logger
}
