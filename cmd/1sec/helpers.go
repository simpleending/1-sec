package main

// ---------------------------------------------------------------------------
// helpers.go — TTY detection, color, error helpers, env-based config
// ---------------------------------------------------------------------------

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
)

// ---------------------------------------------------------------------------
// TTY / color helpers
// ---------------------------------------------------------------------------

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTTY(os.Stderr)
}

func ansi(code, s string) string {
	if !colorEnabled() {
		return s
	}
	return code + s + "\033[0m"
}

func red(s string) string    { return ansi("\033[91m", s) }
func yellow(s string) string { return ansi("\033[93m", s) }
func green(s string) string  { return ansi("\033[32m", s) }
func cyan(s string) string   { return ansi("\033[36m", s) }
func dim(s string) string    { return ansi("\033[90m", s) }
func bold(s string) string   { return ansi("\033[1m", s) }

// ---------------------------------------------------------------------------
// Error / warn helpers (always to stderr)
// ---------------------------------------------------------------------------

func errorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, red("error: ")+format+"\n", args...)
	os.Exit(1)
}

func warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, yellow("warn: ")+format+"\n", args...)
}

// ---------------------------------------------------------------------------
// Env-based configuration (Recommendation #7)
//
// Environment variables:
//   ONESEC_CONFIG  — default config file path
//   ONESEC_HOST    — API host override
//   ONESEC_PORT    — API port override
//   ONESEC_API_KEY — API key for authentication
//   ONESEC_PROFILE — named profile to load (see profiles)
// ---------------------------------------------------------------------------

// envConfig returns the config path, preferring flag > env > default.
func envConfig(flagVal string) string {
	if flagVal != "" && flagVal != "configs/default.yaml" {
		return flagVal
	}
	if e := os.Getenv("ONESEC_CONFIG"); e != "" {
		return e
	}
	return flagVal
}

// envHost returns the host, preferring flag > env.
func envHost(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("ONESEC_HOST")
}

// envPort returns the port, preferring flag > env.
func envPort(flagVal int) int {
	if flagVal != 0 {
		return flagVal
	}
	if e := os.Getenv("ONESEC_PORT"); e != "" {
		if p, err := strconv.Atoi(e); err == nil {
			return p
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// API helpers — with auth and env support
// ---------------------------------------------------------------------------

func apiBase(configPath, hostOverride string, portOverride int) string {
	host := "127.0.0.1"
	port := 1780
	scheme := "http"

	cfg, err := core.LoadConfig(configPath)
	if err == nil && cfg != nil {
		if cfg.Server.Host != "" && cfg.Server.Host != "0.0.0.0" {
			host = cfg.Server.Host
		}
		if cfg.Server.Port != 0 {
			port = cfg.Server.Port
		}
		if cfg.TLSEnabled() {
			scheme = "https"
		}
	}

	if hostOverride != "" {
		host = hostOverride
	}
	if portOverride != 0 {
		port = portOverride
	}

	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

// resolveAPIKey returns the API key from flag, env, or config (in that order).
func resolveAPIKey(flagKey, configPath string) string {
	if flagKey != "" {
		return flagKey
	}
	if envKey := os.Getenv("ONESEC_API_KEY"); envKey != "" {
		return envKey
	}
	cfg, err := core.LoadConfig(configPath)
	if err == nil && cfg != nil && len(cfg.Server.APIKeys) > 0 {
		return cfg.Server.APIKeys[0]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Suggest — typo correction for unknown commands
// ---------------------------------------------------------------------------

func suggest(input string) string {
	cmds := []string{"up", "status", "alerts", "scan", "modules", "config",
		"check", "stop", "docker", "init", "logs", "events", "completions",
		"version", "help", "export", "profile", "dashboard", "correlator",
		"threats", "rust", "enforce", "collect", "archive", "audit-collector", "setup", "doctor"}
	input = strings.ToLower(input)
	for _, c := range cmds {
		if strings.HasPrefix(c, input) || strings.HasPrefix(input, c) {
			return c
		}
	}
	for _, c := range cmds {
		if len(c) == len(input) {
			diff := 0
			for i := range c {
				if c[i] != input[i] {
					diff++
				}
			}
			if diff <= 1 {
				return c
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// parseValue converts a string to the appropriate Go type.
// ---------------------------------------------------------------------------

func parseValue(s string) interface{} {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	}
	if n, err := fmt.Sscanf(s, "%d", new(int)); n == 1 && err == nil {
		var i int
		fmt.Sscanf(s, "%d", &i)
		return i
	}
	if n, err := fmt.Sscanf(s, "%f", new(float64)); n == 1 && err == nil && strings.Contains(s, ".") {
		var f float64
		fmt.Sscanf(s, "%f", &f)
		return f
	}
	return s
}
