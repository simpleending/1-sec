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

	if *natsURL != "" {
		cfg.Bus.URL = *natsURL
		cfg.Bus.Embedded = false
	}
	if cfg.Bus.Embedded && collectorType != "all" {
		cfg.Bus.Token, err = core.ReadEmbeddedBusToken(cfg.Bus.DataDir)
		if err != nil {
			errorf("%v", err)
		}
		cfg.Bus.URL = fmt.Sprintf("nats://127.0.0.1:%d", cfg.Bus.Port)
	}

	// For single collector mode, connect to existing NATS (don't start embedded)
	if collectorType != "all" {
		cfg.Bus.Embedded = false
	}

	logger := core.NewCollectorLogger(cfg.Logging.Format, cfg.LogLevel())

	bus, err := core.NewEventBus(&cfg.Bus, logger)
	if err != nil {
		errorf("connecting to event bus: %v\n  Make sure 1SEC engine is running (1sec up)", err)
	}
	defer bus.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := collect.NewManager(logger)

	if collectorType == "all" {
		// Start all collectors from config — not yet wired, placeholder
		fmt.Fprintf(os.Stderr, "%s Starting all configured collectors...\n", dim("▸"))
		// TODO: read collectors config from yaml when added
		fmt.Fprintf(os.Stderr, "%s No collectors configured in config file yet. Use individual collector commands.\n", yellow("⚠"))
		return
	}

	if *logPath == "" {
		switch collectorType {
		case "auth":
			*logPath = "/var/log/auth.log"
		case "github":
			errorf("--log-path is required for github collector (use owner/repo format)")
		default:
			errorf("--log-path is required for %s collector", collectorType)
		}
	}

	cc := collect.CollectorConfig{
		Type:    collectorType,
		LogPath: *logPath,
		Tag:     *tag,
	}

	err = mgr.StartAll(ctx, collect.CollectorsConfig{
		Enabled:    true,
		Collectors: []collect.CollectorConfig{cc},
	}, bus)
	if err != nil {
		errorf("starting collector: %v", err)
	}

	fmt.Fprintf(os.Stderr, "%s Collector %s tailing %s — events publishing to NATS\n",
		green("✓"), collectorType, *logPath)
	fmt.Fprintf(os.Stderr, "%s Press Ctrl+C to stop\n", dim("▸"))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Fprintf(os.Stderr, "\n%s Stopping collector...\n", dim("▸"))
	mgr.StopAll()
	fmt.Fprintf(os.Stderr, "%s Collector stopped.\n", green("✓"))
}
