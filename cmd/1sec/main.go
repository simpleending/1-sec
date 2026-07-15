package main

// ---------------------------------------------------------------------------
// main.go — command dispatcher for the 1SEC CLI
//
// This file is intentionally slim. All command implementations live in
// their own files (cmd_*.go). Shared helpers are in helpers.go, http.go,
// output.go, and banner.go.
// ---------------------------------------------------------------------------

import (
	"fmt"
	"os"

	"github.com/1sec-project/1sec/internal/core"
)

var (
	version   = "0.4.21"
	commit    = "dev"
	buildDate = "unknown"
)

func main() {
	// Keep every runtime surface aligned with the ldflag-injected CLI version.
	core.Version = version

	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "--version", "-V":
			printVersion(os.Stdout)
			os.Exit(0)
		case "--help", "-h", "help":
			if len(os.Args) >= 3 {
				cmdHelp(os.Args[2])
			} else {
				printUsage(os.Stdout)
			}
			os.Exit(0)
		}
	}

	if len(os.Args) < 2 {
		printUsage(os.Stdout)
		os.Exit(0)
	}

	// Check for updates on operational commands only. Read-only version/help
	// invocations must not replace the running binary as a side effect.
	quiet := hasFlag(os.Args, "-q", "--quiet")
	selfUpdate(version, quiet)

	subcmd := os.Args[1]
	args := os.Args[2:]

	// Handle -h / --help appended to any subcommand
	for _, a := range args {
		if a == "-h" || a == "--help" {
			cmdHelp(subcmd)
			os.Exit(0)
		}
	}

	switch subcmd {
	case "up":
		cmdUp(args)
	case "status":
		cmdStatus(args)
	case "alerts":
		cmdAlerts(args)
	case "scan":
		cmdScan(args)
	case "modules":
		cmdModules(args)
	case "config":
		cmdConfig(args)
	case "check":
		cmdCheck(args)
	case "stop":
		cmdStop(args)
	case "docker":
		cmdDocker(args)
	case "init":
		cmdInit(args)
	case "logs":
		cmdLogs(args)
	case "events":
		cmdEvents(args)
	case "export":
		cmdExport(args)
	case "profile":
		cmdProfile(args)
	case "dashboard":
		cmdDashboard(args)
	case "completions":
		cmdCompletions(args)
	case "version":
		printVersion(os.Stdout)
		os.Exit(0)
	case "correlator":
		cmdCorrelator(args)
	case "threats":
		cmdThreats(args)
	case "rust":
		cmdRust(args)
	case "enforce":
		cmdEnforce(args)
	case "collect":
		cmdCollect(args)
	case "archive":
		cmdArchive(args)
	case "setup":
		cmdSetup(args)
	case "doctor":
		cmdDoctor(args)
	default:
		fmt.Fprintf(os.Stderr, red("error: ")+"unknown command %q\n\n", subcmd)
		if s := suggest(subcmd); s != "" {
			fmt.Fprintf(os.Stderr, "       Did you mean %s?\n\n", bold(s))
		}
		printUsage(os.Stderr)
		os.Exit(1)
	}
}
