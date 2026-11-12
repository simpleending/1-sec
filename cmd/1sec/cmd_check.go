package main

// ---------------------------------------------------------------------------
// cmd_check.go — pre-flight diagnostics
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/1sec-project/1sec/internal/core"
)

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	format := fs.String("format", "table", "Output format: table, json")
	jsonOut := fs.Bool("json", false, "Output results as JSON")
	updates := fs.Bool("updates", false, "Check GitHub for a newer published release")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))

	if *jsonOut {
		*format = "json"
	}
	outFmt := parseFormat(*format)

	type checkResult struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail,omitempty"`
	}

	results := make([]checkResult, 0)
	pass := func(name, detail string) { results = append(results, checkResult{name, "pass", detail}) }
	fail := func(name, detail string) { results = append(results, checkResult{name, "fail", detail}) }
	warn := func(name, detail string) { results = append(results, checkResult{name, "warn", detail}) }

	if *updates {
		if os.Getenv("ONESEC_NO_UPDATE") == "1" {
			warn("updates", "release lookup disabled by ONESEC_NO_UPDATE")
		} else if release, err := fetchLatestRelease(); err != nil {
			warn("updates", fmt.Sprintf("release lookup failed: %v", err))
		} else if isNewer(release.TagName, version) {
			warn("updates", fmt.Sprintf("release %q is available. Install from https://1-sec.dev/get", release.TagName))
		} else {
			pass("updates", fmt.Sprintf("latest published release is %q", release.TagName))
		}
	}

	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		fail("config", fmt.Sprintf("failed to load %s: %v", *configPath, err))
	} else {
		pass("config", fmt.Sprintf("loaded %s", *configPath))

		// Run structural validation
		warnings, validationErrs := cfg.Validate()
		for _, w := range warnings {
			warn("config_validate", w)
		}
		for _, e := range validationErrs {
			fail("config_validate", e)
		}
		if len(validationErrs) == 0 && len(warnings) == 0 {
			pass("config_validate", "all config values are valid")
		}
	}

	if cfg != nil {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
		if err != nil {
			fail("api_port", fmt.Sprintf("port %d is already in use", cfg.Server.Port))
		} else {
			ln.Close()
			pass("api_port", fmt.Sprintf("port %d is available", cfg.Server.Port))
		}

		if cfg.Bus.Embedded {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Bus.Port))
			if err != nil {
				fail("nats_port", fmt.Sprintf("port %d is already in use", cfg.Bus.Port))
			} else {
				ln.Close()
				pass("nats_port", fmt.Sprintf("port %d is available", cfg.Bus.Port))
			}
		} else {
			pass("nats_port", "external NATS — skipped port check")
		}

		dataDir := cfg.Bus.DataDir
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			fail("data_dir", fmt.Sprintf("cannot create %s: %v", dataDir, err))
		} else {
			testFile := dataDir + "/.1sec-check"
			if err := os.WriteFile(testFile, []byte("ok"), 0644); err != nil {
				fail("data_dir", fmt.Sprintf("cannot write to %s: %v", dataDir, err))
			} else {
				os.Remove(testFile)
				pass("data_dir", fmt.Sprintf("%s is writable", dataDir))
			}
		}

		if cfg.IsModuleEnabled("ai_analysis_engine") {
			hasKey := false
			settings := cfg.GetModuleSettings("ai_analysis_engine")
			if _, ok := settings["gemini_api_key"]; ok {
				hasKey = true
			}
			if keys, ok := settings["gemini_api_keys"]; ok {
				if arr, ok := keys.([]interface{}); ok && len(arr) > 0 {
					hasKey = true
				}
			}
			for _, env := range []string{"GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API_KEY_4"} {
				if os.Getenv(env) != "" {
					hasKey = true
					break
				}
			}
			if hasKey {
				pass("ai_keys", "Gemini API key(s) found")
			} else {
				warn("ai_keys", "no Gemini API keys configured — AI engine will not function (set GEMINI_API_KEY or configure in YAML)")
			}
		} else {
			pass("ai_keys", "AI engine disabled — key check skipped")
		}

		if cfg.Server.Port == cfg.Bus.Port {
			fail("port_conflict", fmt.Sprintf("API port (%d) and NATS port (%d) are the same", cfg.Server.Port, cfg.Bus.Port))
		} else {
			pass("port_conflict", "API and NATS ports are distinct")
		}

		if cfg.Syslog.Enabled {
			if cfg.Syslog.Port == cfg.Server.Port || cfg.Syslog.Port == cfg.Bus.Port {
				fail("syslog_port", fmt.Sprintf("syslog port %d conflicts with another service", cfg.Syslog.Port))
			} else {
				pass("syslog_port", fmt.Sprintf("syslog port %d does not conflict", cfg.Syslog.Port))
			}
		}

		if cfg.RustEngine.Enabled {
			binary := cfg.RustEngine.Binary
			if binary == "" {
				binary = "1sec-engine"
			}
			if _, err := exec.LookPath(binary); err != nil {
				found := false
				for _, candidate := range []string{
					binary,
					"./1sec-engine",
					"./rust/1sec-engine/target/release/1sec-engine",
				} {
					if _, err := os.Stat(candidate); err == nil {
						found = true
						pass("rust_engine", fmt.Sprintf("binary found at %s", candidate))
						break
					}
				}
				if !found {
					warn("rust_engine", fmt.Sprintf("binary %q not found — build with: cd rust/1sec-engine && cargo build --release", binary))
				}
			} else {
				pass("rust_engine", fmt.Sprintf("binary %q found in PATH", binary))
			}
		} else {
			pass("rust_engine", "disabled — binary check skipped")
		}
	}

	// Output
	if outFmt == FormatJSON {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"checks": results,
			"total":  len(results),
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("%s Pre-flight Diagnostics\n\n", bold("🔍"))

	tbl := NewTable(os.Stdout, "CHECK", "STATUS", "DETAIL")
	failures := 0
	warnings := 0
	for _, r := range results {
		var statusStr string
		switch r.Status {
		case "pass":
			statusStr = green("PASS")
		case "fail":
			statusStr = red("FAIL")
			failures++
		case "warn":
			statusStr = yellow("WARN")
			warnings++
		}
		tbl.AddRow(r.Name, statusStr, r.Detail)
	}
	tbl.Render()
	fmt.Println()

	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%s %d check(s) failed. Fix issues before running '1sec up'.\n", red("✗"), failures)
		os.Exit(1)
	}
	if warnings > 0 {
		fmt.Printf("%s All checks passed with %d warning(s).\n", yellow("!"), warnings)
	} else {
		fmt.Printf("%s All checks passed. Ready to run '1sec up'.\n", green("✓"))
	}
}
