package main

// ---------------------------------------------------------------------------
// cmd_config.go — show, validate, or modify configuration
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
	"gopkg.in/yaml.v3"
)

func cmdConfig(args []string) {
	if len(args) > 0 && args[0] == "set" {
		cmdConfigSet(args[1:])
		return
	}
	if len(args) > 0 && args[0] == "set-key" {
		cmdConfigSetKey(args[1:])
		return
	}

	fs := flag.NewFlagSet("config", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	validate := fs.Bool("validate", false, "Validate config and exit")
	format := fs.String("format", "table", "Output format: table, json")
	jsonOut := fs.Bool("json", false, "Output as JSON")
	output := fs.String("output", "", "Write output to file")
	showSecrets := fs.Bool("show-secrets", false, "Show secret values instead of redacting them")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))

	if *jsonOut {
		*format = "json"
	}

	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		if *validate {
			fmt.Fprintf(os.Stderr, "%s Config invalid: %v\n", red("✗"), err)
			os.Exit(1)
		}
		errorf("loading config: %v", err)
	}

	if *validate {
		issues := make([]string, 0)
		if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
			issues = append(issues, fmt.Sprintf("server.port %d is out of range (1-65535)", cfg.Server.Port))
		}
		if cfg.Bus.Port < 1 || cfg.Bus.Port > 65535 {
			issues = append(issues, fmt.Sprintf("bus.port %d is out of range (1-65535)", cfg.Bus.Port))
		}
		if cfg.Server.Port == cfg.Bus.Port {
			issues = append(issues, fmt.Sprintf("server.port and bus.port are both %d — they must differ", cfg.Server.Port))
		}
		if cfg.Alerts.MaxStore < 1 {
			issues = append(issues, "alerts.max_store must be positive")
		}
		validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
		if !validLevels[cfg.LogLevel()] {
			issues = append(issues, fmt.Sprintf("logging.level %q is not valid (debug, info, warn, error)", cfg.Logging.Level))
		}
		if cfg.Syslog.Enabled {
			if cfg.Syslog.Port == cfg.Server.Port {
				issues = append(issues, fmt.Sprintf("syslog.port and server.port are both %d", cfg.Syslog.Port))
			}
			if cfg.Syslog.Port == cfg.Bus.Port {
				issues = append(issues, fmt.Sprintf("syslog.port and bus.port are both %d", cfg.Syslog.Port))
			}
		}

		if len(issues) > 0 {
			fmt.Fprintf(os.Stderr, "%s Config has %d issue(s):\n", red("✗"), len(issues))
			for _, issue := range issues {
				fmt.Fprintf(os.Stderr, "  - %s\n", issue)
			}
			os.Exit(1)
		}

		enabledCount := 0
		for _, mod := range cfg.Modules {
			if mod.Enabled {
				enabledCount++
			}
		}
		fmt.Fprintf(os.Stdout, "%s Config valid (%s). %d/%d modules enabled.\n",
			green("✓"), *configPath, enabledCount, len(cfg.Modules))
		os.Exit(0)
	}

	w, cleanup := outputWriter(*output)
	defer cleanup()

	if parseFormat(*format) == FormatJSON {
		var rendered interface{} = core.RedactSecrets(cfg)
		if *showSecrets {
			rendered = cfg
		}
		data, err := json.MarshalIndent(rendered, "", "  ")
		if err != nil {
			errorf("marshaling config: %v", err)
		}
		fmt.Fprintln(w, string(data))
		return
	}

	var rendered interface{} = core.RedactSecrets(cfg)
	if *showSecrets {
		rendered = cfg
	}
	data, err := yaml.Marshal(rendered)
	if err != nil {
		errorf("marshaling config: %v", err)
	}
	fmt.Fprint(w, string(data))
}

func cmdConfigSet(args []string) {
	fs := flag.NewFlagSet("config-set", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))

	remaining := fs.Args()
	if len(remaining) < 2 {
		errorf("usage: 1sec config set <key> <value>\n\nExamples:\n  1sec config set server.port 8080\n  1sec config set logging.level debug\n  1sec config set modules.iot_shield.enabled false")
	}

	key := remaining[0]
	value := remaining[1]

	data, err := os.ReadFile(*configPath)
	if err != nil {
		errorf("reading config: %v", err)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		errorf("parsing config: %v", err)
	}

	parts := strings.Split(key, ".")
	if err := setNestedValue(raw, parts, value); err != nil {
		errorf("setting %s: %v", key, err)
	}

	out, err := yaml.Marshal(raw)
	if err != nil {
		errorf("marshaling config: %v", err)
	}

	if err := core.WritePrivateConfig(*configPath, out); err != nil {
		errorf("writing config: %v", err)
	}

	fmt.Fprintf(os.Stdout, "%s Set %s = %s in %s\n", green("✓"), bold(key), value, *configPath)
}

func setNestedValue(m map[string]interface{}, path []string, value string) error {
	if len(path) == 0 {
		return fmt.Errorf("empty key path")
	}

	if len(path) == 1 {
		m[path[0]] = parseValue(value)
		return nil
	}

	next, ok := m[path[0]]
	if !ok {
		next = map[string]interface{}{}
		m[path[0]] = next
	}

	nextMap, ok := next.(map[string]interface{})
	if !ok {
		return fmt.Errorf("key %q is not a map", path[0])
	}

	return setNestedValue(nextMap, path[1:], value)
}
