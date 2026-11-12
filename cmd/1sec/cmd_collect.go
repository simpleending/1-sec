package main

// ---------------------------------------------------------------------------
// cmd_collect.go — start reference collectors (log tailers)
//
// Usage:
//   1sec collect nginx  --log-path /var/log/nginx/access.log
//   1sec collect auth   --log-path /var/log/auth.log
//   1sec collect pfsense --log-path /var/log/filterlog.log
//   1sec collect json   --log-path /var/log/cloudtrail.json
//   1sec collect all    --config configs/default.yaml
// ---------------------------------------------------------------------------

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/1sec-project/1sec/internal/collect"
	"github.com/1sec-project/1sec/internal/core"
)

func cmdCollect(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: 1sec collect <type> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Types:\n")
		fmt.Fprintf(os.Stderr, "  nginx    Tail nginx/apache combined access logs\n")
		fmt.Fprintf(os.Stderr, "  auth     Tail /var/log/auth.log (SSH, PAM, sudo)\n")
		fmt.Fprintf(os.Stderr, "  pfsense  Tail pfSense/OPNsense filterlog\n")
		fmt.Fprintf(os.Stderr, "  json     Tail JSON-line logs (CloudTrail, k8s audit)\n")
		fmt.Fprintf(os.Stderr, "  github   Poll GitHub Actions workflow runs (needs GITHUB_TOKEN)\n")
		fmt.Fprintf(os.Stderr, "  all      Start all collectors from config file\n")
		os.Exit(1)
	}

	collectorType := args[0]
	subArgs := args[1:]

	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	logPath := fs.String("log-path", "", "Path to log file to tail")
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	tag := fs.String("tag", "", "Source tag for events")
	natsURL := fs.String("nats-url", "", "NATS URL (default: from config)")
	fs.Parse(subArgs)

	*configPath = envConfig(*configPath)

	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		errorf("loading config: %v", err)
	}

	sources := cfg.Collectors
	if collectorType == "all" {
		if !sources.Enabled {
			errorf("collectors.enabled is false in %s", *configPath)
		}
		if *logPath != "" || *tag != "" {
			errorf("configure log paths and tags under collectors.sources for collect all")
		}
	} else {
		if *logPath == "" && (collectorType == "auth" || collectorType == "authlog") {
			*logPath = "/var/log/auth.log"
		}
		sources = core.CollectorsConfig{
			Enabled: true,
			Sources: []core.CollectorConfig{{Type: collectorType, LogPath: *logPath, Tag: *tag}},
		}
	}
	if err := sources.Validate(); err != nil {
		errorf("%v", err)
	}

	if *natsURL != "" {
		cfg.Bus.URL = *natsURL
		cfg.Bus.Embedded = false
	}
	if cfg.Bus.Embedded {
		cfg.Bus.Token, err = core.ReadEmbeddedBusToken(cfg.Bus.DataDir)
		if err != nil {
			errorf("%v", err)
		}
		cfg.Bus.URL = fmt.Sprintf("nats://127.0.0.1:%d", cfg.Bus.Port)
		cfg.Bus.Embedded = false
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err = runCollectors(ctx, cfg, sources)
	stopSignals()
	if err != nil {
		errorf("%v", err)
	}
	fmt.Fprintf(os.Stderr, "%s Collectors stopped.\n", green("✓"))
}

func runCollectors(ctx context.Context, cfg *core.Config, sources core.CollectorsConfig) error {
	logger := core.NewCollectorLogger(cfg.Logging.Format, cfg.LogLevel())

	bus, err := core.NewEventBus(&cfg.Bus, logger)
	if err != nil {
		return fmt.Errorf("connecting to event bus: %w\n  Make sure 1SEC engine is running (1sec up)", err)
	}
	defer bus.Close()

	mgr := collect.NewManager(logger)
	if err := mgr.StartAll(ctx, sources, bus); err != nil {
		return err
	}
	defer mgr.StopAll()

	fmt.Fprintf(os.Stderr, "%s %d collector(s) connected to 1SEC\n", green("✓"), mgr.Count())
	fmt.Fprintf(os.Stderr, "%s Press Ctrl+C to stop\n", dim("▸"))

	<-ctx.Done()
	return nil
}
