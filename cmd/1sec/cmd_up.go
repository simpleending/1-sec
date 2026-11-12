package main

// ---------------------------------------------------------------------------
// cmd_up.go — start the 1SEC engine
// ---------------------------------------------------------------------------

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/1sec-project/1sec/internal/api"
	"github.com/1sec-project/1sec/internal/collect"
	"github.com/1sec-project/1sec/internal/core"
	"github.com/1sec-project/1sec/internal/ingest"

	"github.com/1sec-project/1sec/internal/modules/aicontainment"
	"github.com/1sec-project/1sec/internal/modules/aiengine"
	"github.com/1sec-project/1sec/internal/modules/apifortress"
	"github.com/1sec-project/1sec/internal/modules/auth"
	"github.com/1sec-project/1sec/internal/modules/cloudposture"
	"github.com/1sec-project/1sec/internal/modules/datapoisoning"
	"github.com/1sec-project/1sec/internal/modules/deepfake"
	"github.com/1sec-project/1sec/internal/modules/identity"
	"github.com/1sec-project/1sec/internal/modules/injection"
	"github.com/1sec-project/1sec/internal/modules/iot"
	"github.com/1sec-project/1sec/internal/modules/llmfirewall"
	"github.com/1sec-project/1sec/internal/modules/network"
	"github.com/1sec-project/1sec/internal/modules/quantumcrypto"
	"github.com/1sec-project/1sec/internal/modules/ransomware"
	runtimemod "github.com/1sec-project/1sec/internal/modules/runtime"
	"github.com/1sec-project/1sec/internal/modules/supplychain"
)

func registerModules(engine *core.Engine) {
	modules := []core.Module{
		network.New(),
		apifortress.New(),
		iot.New(),
		injection.New(),
		supplychain.New(),
		ransomware.New(),
		auth.New(),
		deepfake.New(),
		identity.New(),
		llmfirewall.New(),
		aicontainment.New(),
		datapoisoning.New(),
		quantumcrypto.New(),
		runtimemod.New(),
		cloudposture.New(),
		aiengine.New(),
	}
	for _, mod := range modules {
		if err := engine.Registry.Register(mod); err != nil {
			engine.Logger.Warn().Err(err).Str("module", mod.Name()).Msg("failed to register module")
		}
	}
}

func cmdUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	moduleList := fs.String("modules", "", "Comma-separated list of modules to enable (disables all others)")
	logLevel := fs.String("log-level", "", "Log level override: debug, info, warn, error")
	dryRun := fs.Bool("dry-run", false, "Validate config and modules, then exit")
	quiet := fs.Bool("quiet", false, "Suppress banner and non-essential output")
	fs.BoolVar(quiet, "q", false, "Suppress banner and non-essential output")
	noColor := fs.Bool("no-color", false, "Disable color output")
	insecure := fs.Bool("insecure", false, "Allow API to run without authentication (open mode)")
	allowUnknownConfigFields := fs.Bool("allow-unknown-config-fields", false, "Allow unknown config fields for forward-compatible config files")
	fs.Parse(args)

	*configPath = envConfig(*configPath)

	if *noColor {
		os.Setenv("NO_COLOR", "1")
	}

	if !*quiet {
		fmt.Fprint(os.Stderr, bannerText())
	}

	var cfg *core.Config
	var err error
	if *allowUnknownConfigFields {
		cfg, err = core.LoadConfigWithOptions(*configPath, core.LoadConfigOptions{
			AllowUnknownFields: true,
		})
	} else {
		cfg, err = core.LoadConfig(*configPath)
	}
	if err != nil {
		errorf("loading config: %v", err)
	}
	if *insecure {
		cfg.Server.AllowUnauthenticatedRead = true
	}

	// Run config validation
	warnings, validationErrs := cfg.Validate()
	for _, w := range warnings {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "%s %s\n", yellow("⚠"), w)
		}
	}
	if len(validationErrs) > 0 {
		for _, e := range validationErrs {
			fmt.Fprintf(os.Stderr, "%s %s\n", red("✗"), e)
		}
		errorf("config validation failed with %d error(s)", len(validationErrs))
	}

	// Block startup without auth unless --insecure is explicitly passed
	if !cfg.AuthEnabled() && !*insecure {
		if !*quiet {
			if cfg.OpenReadAllowed() {
				fmt.Fprintf(os.Stderr, "%s No API keys configured. Read endpoints are unauthenticated; mutating endpoints are blocked.\n", yellow("!"))
			} else {
				fmt.Fprintf(os.Stderr, "%s No API keys configured on a non-loopback API bind. Only /health will be accessible.\n", yellow("!"))
			}
			fmt.Fprintf(os.Stderr, "    Set api_keys/read_only_keys, ONESEC_API_KEY env var, or pass --insecure to acknowledge.\n")
		}
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}

	if *moduleList != "" {
		selected := make(map[string]bool)
		for _, name := range strings.Split(*moduleList, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				selected[name] = true
			}
		}
		for key, mod := range cfg.Modules {
			mod.Enabled = selected[key]
			cfg.Modules[key] = mod
		}
	}

	engine, err := core.NewEngine(cfg)
	if err != nil {
		errorf("creating engine: %v", err)
	}

	engine.SetConfigPath(*configPath)
	registerModules(engine)

	if *dryRun {
		enabled := 0
		for _, mod := range engine.Registry.All() {
			if cfg.IsModuleEnabled(mod.Name()) {
				enabled++
			}
		}
		fmt.Fprintf(os.Stdout, "%s Config valid. %d/%d modules enabled.\n",
			green("✓"), enabled, engine.Registry.Count())
		os.Exit(0)
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "%s Starting 1SEC engine...\n", dim("▸"))
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err = runEngine(ctx, engine, *quiet)
	stopSignals()
	if err != nil {
		errorf("%v", err)
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "%s 1SEC stopped.\n", green("✓"))
	}
}

func runEngine(ctx context.Context, engine *core.Engine, quiet bool) (err error) {
	cfg := engine.Config
	defer func() { err = errors.Join(err, engine.Shutdown()) }()
	if err := engine.Start(); err != nil {
		return fmt.Errorf("starting engine: %w", err)
	}

	if cfg.Collectors.Enabled {
		collectors := collect.NewManager(engine.Logger)
		if err := collectors.StartAll(engine.Context(), cfg.Collectors, engine.Bus); err != nil {
			return fmt.Errorf("starting configured collectors: %w", err)
		}
		defer collectors.StopAll()
	}

	if cfg.Syslog.Enabled {
		syslogSrv := ingest.NewSyslogServer(&cfg.Syslog, engine.Bus, engine.Logger)
		defer func() { err = errors.Join(err, syslogSrv.Stop()) }()
		if err := syslogSrv.Start(engine.Context()); err != nil {
			return fmt.Errorf("starting syslog ingestion: %w", err)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "%s Syslog ingestion on :%d (%s)\n",
				green("✓"), cfg.Syslog.Port, cfg.Syslog.Protocol)
		}
	}

	srv := api.NewServer(engine)
	if err := srv.Start(); err != nil {
		return fmt.Errorf("starting API server: %w", err)
	}
	defer func() { err = errors.Join(err, srv.Stop()) }()

	if !quiet {
		rustStatus := ""
		if cfg.RustEngine.Enabled && engine.RustSidecar != nil && engine.RustSidecar.Running() {
			rustStatus = fmt.Sprintf(", rust engine %s", green("active"))
		}
		enforceStatus := ""
		if cfg.Enforcement != nil && cfg.Enforcement.Enabled {
			if cfg.Enforcement.GetDryRun() {
				enforceStatus = fmt.Sprintf(", enforcement %s", yellow("dry-run"))
			} else {
				enforceStatus = fmt.Sprintf(", enforcement %s", green("live"))
			}
		}
		fmt.Fprintf(os.Stderr, "%s 1SEC running — %d modules active, API on :%d%s%s\n",
			green("✓"), engine.Registry.Count(), cfg.Server.Port, rustStatus, enforceStatus)

		// Show helpful hints for new users about enforcement state
		if cfg.Enforcement != nil && cfg.Enforcement.Enabled && cfg.Enforcement.GetDryRun() {
			fmt.Fprintf(os.Stderr, "%s Enforcement is in %s mode (actions are simulated, not executed)\n",
				dim("▸"), yellow("dry-run"))
			fmt.Fprintf(os.Stderr, "%s Run %s to go live, or %s to preview policies\n",
				dim("▸"), bold("1sec enforce dry-run off"), bold("1sec enforce policies"))
		}

		fmt.Fprintf(os.Stderr, "%s Press Ctrl+C to stop\n", dim("▸"))
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-srv.ShutdownRequested():
		return err
	}
}
