package main

// ---------------------------------------------------------------------------
// banner.go — ASCII art banner and version/usage printing
// ---------------------------------------------------------------------------

import (
	"fmt"
	"io"
	goruntime "runtime"
	"runtime/debug"
)

func bannerText() string {
	if !colorEnabled() {
		return `
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║     ██╗       ███████╗ ███████╗  ██████╗               ║
    ║    ███║       ██╔════╝ ██╔════╝ ██╔════╝               ║
    ║    ╚██║ █████╗███████╗ █████╗   ██║                    ║
    ║     ██║ ╚════╝╚════██║ ██╔══╝   ██║                    ║
    ║     ██║       ███████║ ███████╗ ╚██████╗               ║
    ║     ╚═╝       ╚══════╝ ╚══════╝  ╚═════╝               ║
    ║                                                          ║
    ║        ALL-IN-ONE CYBER DEFENSE PLATFORM                ║
    ║                                    Go + Rust             ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
`
	}
	return "\033[36m" + `
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║` + "\033[97m" + `     ██╗       ███████╗ ███████╗  ██████╗` + "\033[36m" + `              ║
    ║` + "\033[97m" + `    ███║       ██╔════╝ ██╔════╝ ██╔════╝` + "\033[36m" + `              ║
    ║` + "\033[91m" + `    ╚██║ █████╗███████╗ █████╗   ██║     ` + "\033[36m" + `              ║
    ║` + "\033[91m" + `     ██║ ╚════╝╚════██║ ██╔══╝   ██║     ` + "\033[36m" + `              ║
    ║` + "\033[93m" + `     ██║       ███████║ ███████╗ ╚██████╗` + "\033[36m" + `              ║
    ║` + "\033[93m" + `     ╚═╝       ╚══════╝ ╚══════╝  ╚═════╝` + "\033[36m" + `             ║
    ║                                                          ║
    ║` + "\033[97m" + `        ALL-IN-ONE CYBER DEFENSE PLATFORM` + "\033[36m" + `               ║
    ║` + "\033[90m" + `                                    Go + Rust` + "\033[36m" + `            ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝` + "\033[0m" + `
`
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "1sec v%s", version)
	if commit != "dev" {
		fmt.Fprintf(w, " (%s)", commit[:min(7, len(commit))])
	}
	if buildDate != "unknown" {
		fmt.Fprintf(w, " built %s", buildDate)
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		fmt.Fprintf(w, " %s", bi.GoVersion)
	}
	fmt.Fprintf(w, " %s/%s", goruntime.GOOS, goruntime.GOARCH)
	fmt.Fprintln(w)
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, bannerText())
	fmt.Fprintf(w, "  %s\n\n", dim("v"+version))
	fmt.Fprintf(w, "%s\n\n", bold("USAGE"))
	fmt.Fprintf(w, "  1sec <command> [flags]\n\n")
	fmt.Fprintf(w, "%s\n\n", bold("COMMANDS"))
	fmt.Fprintf(w, "  %-14s  %s\n", bold("up"), "Start the 1SEC engine with all enabled modules")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("stop"), "Gracefully stop a running instance")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("status"), "Show status of a running 1SEC instance")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("alerts"), "Fetch, acknowledge, resolve, or clear alerts")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("scan"), "Submit a payload for on-demand analysis")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("modules"), "List, inspect, enable, or disable defense modules")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("config"), "Show, validate, initialize, or set configuration")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("check"), "Run pre-flight diagnostics")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("logs"), "Fetch recent logs from a running instance")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("events"), "Submit or inspect events on the bus")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("export"), "Export alerts/events in bulk (JSON, CSV, SARIF)")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("profile"), "Manage named configuration profiles")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("dashboard"), "Launch a live TUI dashboard")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("init"), "Generate a starter configuration file")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("docker"), "Manage the 1SEC Docker deployment")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("correlator"), "Inspect the threat correlator state")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("threats"), "Query dynamic IP threat scoring")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("rust"), "Check Rust sidecar engine status")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("enforce"), "Manage automated threat response / enforcement")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("collect"), "Start reference collectors (log tailers, GitHub)")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("archive"), "Manage cold archive (status, list, restore)")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("audit-collector"), "Run a dedicated HTTPS audit receiver")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("setup"), "Guided interactive setup wizard")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("doctor"), "Comprehensive health check with fix suggestions")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("completions"), "Generate shell completion scripts")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("version"), "Print version and build info")
	fmt.Fprintf(w, "  %-14s  %s\n", bold("help"), "Show help for a command")
	fmt.Fprintf(w, "\n%s\n\n", bold("GLOBAL FLAGS"))
	fmt.Fprintf(w, "  %-22s  %s\n", "--config <path>", "Config file path (default: configs/default.yaml, env: ONESEC_CONFIG)")
	fmt.Fprintf(w, "  %-22s  %s\n", "--api-key <key>", "API key (env: ONESEC_API_KEY)")
	fmt.Fprintf(w, "  %-22s  %s\n", "--format <fmt>", "Output format: table, json, csv, sarif (default: table)")
	fmt.Fprintf(w, "  %-22s  %s\n", "--version, -V", "Print version and exit")
	fmt.Fprintf(w, "  %-22s  %s\n", "--help, -h", "Show help")
	fmt.Fprintf(w, "\n%s\n\n", bold("ENVIRONMENT VARIABLES"))
	fmt.Fprintf(w, "  %-22s  %s\n", "ONESEC_CONFIG", "Default config file path")
	fmt.Fprintf(w, "  %-22s  %s\n", "ONESEC_HOST", "API host override")
	fmt.Fprintf(w, "  %-22s  %s\n", "ONESEC_PORT", "API port override")
	fmt.Fprintf(w, "  %-22s  %s\n", "ONESEC_API_KEY", "API key for authentication")
	fmt.Fprintf(w, "  %-22s  %s\n", "ONESEC_PROFILE", "Named profile to use")
	fmt.Fprintf(w, "\n%s\n\n", bold("EXAMPLES"))
	fmt.Fprintf(w, "  %s\n", dim("# Start with defaults"))
	fmt.Fprintf(w, "  1sec up\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Start only specific modules"))
	fmt.Fprintf(w, "  1sec up --modules injection_shield,auth_fortress,network_guardian\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Check a running instance"))
	fmt.Fprintf(w, "  1sec status --format json\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Fetch critical alerts as SARIF"))
	fmt.Fprintf(w, "  1sec alerts --severity CRITICAL --format sarif --output alerts.sarif\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Export alerts as CSV"))
	fmt.Fprintf(w, "  1sec export --type alerts --format csv --output report.csv\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Tail logs in real-time"))
	fmt.Fprintf(w, "  1sec logs --follow\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Use a named profile"))
	fmt.Fprintf(w, "  1sec status --profile prod\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Launch live dashboard"))
	fmt.Fprintf(w, "  1sec dashboard\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Check enforcement status"))
	fmt.Fprintf(w, "  1sec enforce status\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Preview what a preset does before applying"))
	fmt.Fprintf(w, "  1sec enforce preset balanced --show\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Apply a preset (lax → safe → balanced → strict, or vps-agent for AI agent VPS)"))
	fmt.Fprintf(w, "  1sec enforce preset balanced\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Test what enforcement would do for a module"))
	fmt.Fprintf(w, "  1sec enforce test ransomware --severity CRITICAL\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Guided setup (config + AI keys + API auth)"))
	fmt.Fprintf(w, "  1sec setup\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Quick AI key setup"))
	fmt.Fprintf(w, "  1sec config set-key AIzaSy...\n\n")
	fmt.Fprintf(w, "  %s\n", dim("# Health check with fix suggestions"))
	fmt.Fprintf(w, "  1sec doctor\n\n")
	fmt.Fprintf(w, "Run %s for detailed help on any command.\n\n", bold("1sec help <command>"))
}
