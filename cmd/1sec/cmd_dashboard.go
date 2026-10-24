package main

// ---------------------------------------------------------------------------
// cmd_dashboard.go — live TUI dashboard (Recommendation #3)
//
// A lightweight terminal dashboard that polls the 1SEC API and displays
// real-time module status, alert counts, and recent activity. No external
// TUI library required — uses ANSI escape codes for a clean display.
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func cmdDashboard(args []string) {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	refreshStr := fs.String("refresh", "3s", "Refresh interval")
	web := fs.Bool("web", false, "Print the optional local web dashboard URL")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))
	hostVal := envHost(*host)
	portVal := envPort(*port)

	refresh, err := time.ParseDuration(*refreshStr)
	if err != nil {
		errorf("invalid refresh interval %q: %v", *refreshStr, err)
	}

	base := apiBase(*configPath, hostVal, portVal)
	if *web {
		fmt.Printf("Local dashboard: %s/ui/\nUse a local API key in the page. The engine must be running.\n", base)
		return
	}
	if refresh <= 0 {
		errorf("refresh interval must be positive")
		return
	}
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)
	timeout := 5 * time.Second

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Hide cursor
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h")

	ticker := time.NewTicker(refresh)
	defer ticker.Stop()

	renderDashboard(base, apiKey, timeout)

	for {
		select {
		case <-sigCh:
			clearScreen()
			fmt.Print("\033[?25h")
			fmt.Fprintf(os.Stderr, "%s Dashboard closed.\n", dim("▸"))
			return
		case <-ticker.C:
			renderDashboard(base, apiKey, timeout)
		}
	}
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

// formatBytes returns a human-readable byte size string.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func boolStatus(v interface{}) string {
	if b, ok := v.(bool); ok {
		if b {
			return green("connected")
		}
		return red("disconnected")
	}
	return dim(fmt.Sprintf("%v", v))
}

func renderDashboard(base, apiKey string, timeout time.Duration) {
	clearScreen()

	now := time.Now().Format("15:04:05")

	fmt.Printf("  %s  %s  %s\n", bold("1SEC DASHBOARD"), dim("•"), dim(now))
	fmt.Printf("  %s\n\n", dim("Press Ctrl+C to exit"))

	// Fetch status
	statusBody, statusErr := apiGet(base+"/api/v1/status", apiKey, timeout)
	if statusErr != nil {
		fmt.Printf("  %s Cannot connect to 1SEC at %s\n", red("✗"), base)
		fmt.Printf("  %s %v\n\n", dim("▸"), statusErr)
		fmt.Printf("  %s Is the engine running? Try: 1sec up\n", dim("▸"))
		return
	}

	var status map[string]interface{}
	if err := json.Unmarshal(statusBody, &status); err != nil {
		fmt.Printf("  %s Error parsing status: %v\n", red("✗"), err)
		return
	}

	// Engine section
	engineStatus := fmt.Sprintf("%v", status["status"])
	statusColor := green
	if engineStatus != "running" {
		statusColor = yellow
	}

	fmt.Printf("  %s\n", bold("ENGINE"))
	fmt.Printf("  %-20s %s\n", "Status:", statusColor(engineStatus))
	fmt.Printf("  %-20s %v\n", "Version:", status["version"])
	if upSecs, ok := status["uptime_secs"].(float64); ok && upSecs > 0 {
		dur := time.Duration(int64(upSecs)) * time.Second
		fmt.Printf("  %-20s %s\n", "Uptime:", dim(dur.String()))
	}
	fmt.Printf("  %-20s %v\n", "Bus:", boolStatus(status["bus_connected"]))
	if re, ok := status["rust_engine"].(string); ok {
		reColor := dim
		if re == "running" {
			reColor = green
		}
		fmt.Printf("  %-20s %s\n", "Rust Engine:", reColor(re))
	}
	if cloud, ok := status["cloud"].(string); ok && cloud != "" {
		cloudColor := dim
		if cloud == "reporting" {
			cloudColor = green
		}
		fmt.Printf("  %-20s %s\n", "Cloud:", cloudColor(cloud))
	}
	fmt.Println()

	// Modules section
	if modules, ok := status["modules"].([]interface{}); ok && len(modules) > 0 {
		enabledCount := 0
		for _, m := range modules {
			mod, ok := m.(map[string]interface{})
			if !ok {
				continue
			}
			if enabled, ok := mod["enabled"].(bool); ok && enabled {
				enabledCount++
			}
		}

		fmt.Printf("  %s  %s\n", bold("MODULES"), dim(fmt.Sprintf("%d/%d active", enabledCount, len(modules))))

		cols := 3
		printed := 0
		for _, m := range modules {
			mod, ok := m.(map[string]interface{})
			if !ok {
				continue
			}
			name := fmt.Sprintf("%v", mod["name"])
			marker := green("●")
			if enabled, ok := mod["enabled"].(bool); ok && !enabled {
				marker = red("○")
				name = dim(name)
			}
			if len(name) > 22 {
				name = name[:19] + "..."
			}
			fmt.Printf("  %s %-22s", marker, name)
			printed++
			if printed%cols == 0 {
				fmt.Println()
			}
		}
		if printed%cols != 0 {
			fmt.Println()
		}
		fmt.Println()
	}

	// Alerts section
	alertsBody, alertsErr := apiGet(base+"/api/v1/alerts?limit=10", apiKey, timeout)
	if alertsErr == nil {
		var alertResp map[string]interface{}
		if json.Unmarshal(alertsBody, &alertResp) == nil {
			alerts, _ := alertResp["alerts"].([]interface{})
			total := 0
			if t, ok := alertResp["total"].(float64); ok {
				total = int(t)
			}

			sevCounts := map[string]int{}
			for _, a := range alerts {
				alert, ok := a.(map[string]interface{})
				if !ok {
					continue
				}
				sev := fmt.Sprintf("%v", alert["severity"])
				sevCounts[sev]++
			}

			fmt.Printf("  %s  %s\n", bold("ALERTS"), dim(fmt.Sprintf("%d total", total)))

			if total > 0 {
				parts := make([]string, 0)
				if c := sevCounts["CRITICAL"]; c > 0 {
					parts = append(parts, red(fmt.Sprintf("CRIT:%d", c)))
				}
				if c := sevCounts["HIGH"]; c > 0 {
					parts = append(parts, red(fmt.Sprintf("HIGH:%d", c)))
				}
				if c := sevCounts["MEDIUM"]; c > 0 {
					parts = append(parts, yellow(fmt.Sprintf("MED:%d", c)))
				}
				if c := sevCounts["LOW"]; c > 0 {
					parts = append(parts, cyan(fmt.Sprintf("LOW:%d", c)))
				}
				if c := sevCounts["INFO"]; c > 0 {
					parts = append(parts, dim(fmt.Sprintf("INFO:%d", c)))
				}
				fmt.Printf("  %s\n\n", strings.Join(parts, "  "))

				fmt.Printf("  %s\n", dim("Recent:"))
				shown := 5
				if len(alerts) < shown {
					shown = len(alerts)
				}
				for i := 0; i < shown; i++ {
					alert, ok := alerts[i].(map[string]interface{})
					if !ok {
						continue
					}
					sev := fmt.Sprintf("%v", alert["severity"])
					sevColor := dim
					switch sev {
					case "CRITICAL", "HIGH":
						sevColor = red
					case "MEDIUM":
						sevColor = yellow
					case "LOW":
						sevColor = cyan
					}
					title := fmt.Sprintf("%v", alert["title"])
					if len(title) > 50 {
						title = title[:47] + "..."
					}
					mod := ""
					if m, ok := alert["module"].(string); ok {
						mod = dim(fmt.Sprintf(" (%s)", m))
					}
					fmt.Printf("  %s [%-8s] %s%s\n", sevColor("●"), sev, title, mod)
				}
			} else {
				fmt.Printf("  %s\n", green("No alerts — all clear"))
			}
		}
	}

	// Threat Correlator section
	corrBody, corrErr := apiGet(base+"/api/v1/correlator", apiKey, timeout)
	if corrErr == nil {
		var corrResp map[string]interface{}
		if json.Unmarshal(corrBody, &corrResp) == nil {
			statusVal, _ := corrResp["status"].(string)
			if statusVal != "not_started" {
				activeSources := 0
				if a, ok := corrResp["active_sources"].(float64); ok {
					activeSources = int(a)
				}
				windowMin := 0
				if w, ok := corrResp["window_minutes"].(float64); ok {
					windowMin = int(w)
				}
				chainCount := 0
				if c, ok := corrResp["chain_count"].(float64); ok {
					chainCount = int(c)
				}

				fmt.Println()
				fmt.Printf("  %s\n", bold("THREAT CORRELATOR"))
				fmt.Printf("  %-20s %d chains, %dm window\n", "Config:", chainCount, windowMin)

				if activeSources > 0 {
					fmt.Printf("  %-20s %s\n", "Active Sources:", red(fmt.Sprintf("%d tracked", activeSources)))

					if sources, ok := corrResp["sources"].([]interface{}); ok {
						shown := 5
						if len(sources) < shown {
							shown = len(sources)
						}
						for i := 0; i < shown; i++ {
							src, ok := sources[i].(map[string]interface{})
							if !ok {
								continue
							}
							ip := fmt.Sprintf("%v", src["ip"])
							alertCount := 0
							if a, ok := src["alert_count"].(float64); ok {
								alertCount = int(a)
							}
							modNames := []string{}
							if mods, ok := src["modules"].(map[string]interface{}); ok {
								for m := range mods {
									modNames = append(modNames, m)
								}
							}
							modStr := strings.Join(modNames, ",")
							if len(modStr) > 30 {
								modStr = modStr[:27] + "..."
							}
							srcColor := yellow
							if len(modNames) >= 3 {
								srcColor = red
							}
							fmt.Printf("  %s %-18s %d alerts  %s\n", srcColor("▸"), ip, alertCount, dim(modStr))
						}
						if len(sources) > shown {
							fmt.Printf("  %s +%d more sources\n", dim("▸"), len(sources)-shown)
						}
					}
				} else {
					fmt.Printf("  %-20s %s\n", "Active Sources:", green("none — no correlated threats"))
				}
			}
		}
	}

	// Enforcement section
	enforceBody, enforceErr := apiGet(base+"/api/v1/enforce/status", apiKey, timeout)
	if enforceErr == nil {
		var enforceResp map[string]interface{}
		if json.Unmarshal(enforceBody, &enforceResp) == nil {
			enabled, _ := enforceResp["enabled"].(bool)
			dryRun, _ := enforceResp["dry_run"].(bool)

			fmt.Println()
			fmt.Printf("  %s\n", bold("ENFORCEMENT"))

			if enabled {
				if dryRun {
					fmt.Printf("  %-20s %s\n", "Status:", yellow("DRY RUN"))
				} else {
					fmt.Printf("  %-20s %s\n", "Status:", green("LIVE"))
				}
			} else {
				fmt.Printf("  %-20s %s\n", "Status:", dim("disabled"))
			}

			if preset, ok := enforceResp["preset"].(string); ok && preset != "" {
				fmt.Printf("  %-20s %s\n", "Preset:", preset)
			}

			if stats, ok := enforceResp["stats"].(map[string]interface{}); ok {
				if p, ok := stats["total_policies"].(float64); ok {
					fmt.Printf("  %-20s %d\n", "Policies:", int(p))
				}
				if r, ok := stats["total_records"].(float64); ok && r > 0 {
					fmt.Printf("  %-20s %d\n", "Actions:", int(r))
				}
				if byStatus, ok := stats["by_status"].(map[string]interface{}); ok && len(byStatus) > 0 {
					parts := make([]string, 0)
					for k, v := range byStatus {
						count, ok := v.(float64)
						if !ok {
							continue
						}
						switch k {
						case "SUCCESS":
							parts = append(parts, green(fmt.Sprintf("OK:%d", int(count))))
						case "FAILED":
							parts = append(parts, red(fmt.Sprintf("FAIL:%d", int(count))))
						case "DRY_RUN":
							parts = append(parts, yellow(fmt.Sprintf("DRY:%d", int(count))))
						case "COOLDOWN":
							parts = append(parts, dim(fmt.Sprintf("CD:%d", int(count))))
						case "SKIPPED":
							parts = append(parts, dim(fmt.Sprintf("SKIP:%d", int(count))))
						}
					}
					if len(parts) > 0 {
						fmt.Printf("  %-20s %s\n", "Breakdown:", strings.Join(parts, "  "))
					}
				}
			}
		}
	}

	// Pending approvals section
	approvalsBody, approvalsErr := apiGet(base+"/api/v1/enforce/approvals/stats", apiKey, timeout)
	if approvalsErr == nil {
		var approvalsResp map[string]interface{}
		if json.Unmarshal(approvalsBody, &approvalsResp) == nil {
			if enabled, _ := approvalsResp["enabled"].(bool); enabled {
				pendingCount := 0
				if p, ok := approvalsResp["pending_count"].(float64); ok {
					pendingCount = int(p)
				}
				if pendingCount > 0 {
					fmt.Printf("  %-20s %s\n", "Approvals:", red(fmt.Sprintf("%d PENDING", pendingCount)))

					// Show pending approval details
					pendingBody, pendingErr := apiGet(base+"/api/v1/enforce/approvals/pending", apiKey, timeout)
					if pendingErr == nil {
						var pendingResp map[string]interface{}
						if json.Unmarshal(pendingBody, &pendingResp) == nil {
							if items, ok := pendingResp["pending"].([]interface{}); ok {
								shown := 3
								if len(items) < shown {
									shown = len(items)
								}
								for i := 0; i < shown; i++ {
									item, ok := items[i].(map[string]interface{})
									if !ok {
										continue
									}
									action := fmt.Sprintf("%v", item["action"])
									target := fmt.Sprintf("%v", item["target"])
									module := fmt.Sprintf("%v", item["module"])
									if len(target) > 20 {
										target = target[:17] + "..."
									}
									fmt.Printf("  %s %s %s %s\n", yellow("▸"), action, target, dim(module))
								}
							}
						}
					}
				} else {
					fmt.Printf("  %-20s %s\n", "Approvals:", dim("none pending"))
				}
			}
		}
	}

	// Webhook dispatcher health
	webhookBody, webhookErr := apiGet(base+"/api/v1/enforce/webhooks/stats", apiKey, timeout)
	if webhookErr == nil {
		var webhookResp map[string]interface{}
		if json.Unmarshal(webhookBody, &webhookResp) == nil {
			parts := make([]string, 0)
			if dl, ok := webhookResp["dead_letters"].(float64); ok && dl > 0 {
				parts = append(parts, red(fmt.Sprintf("dead:%d", int(dl))))
			}
			if oc, ok := webhookResp["open_circuits"].(float64); ok && oc > 0 {
				parts = append(parts, red(fmt.Sprintf("circuits:%d", int(oc))))
			}
			if qd, ok := webhookResp["queue_depth"].(float64); ok && qd > 0 {
				parts = append(parts, yellow(fmt.Sprintf("queued:%d", int(qd))))
			}
			if len(parts) > 0 {
				fmt.Printf("  %-20s %s\n", "Webhooks:", strings.Join(parts, "  "))
			}
		}
	}

	// Enforcement history (recent actions)
	historyBody, historyErr := apiGet(base+"/api/v1/enforce/history?limit=5", apiKey, timeout)
	if historyErr == nil {
		var historyResp map[string]interface{}
		if json.Unmarshal(historyBody, &historyResp) == nil {
			if records, ok := historyResp["records"].([]interface{}); ok && len(records) > 0 {
				fmt.Printf("\n  %s\n", dim("Recent actions:"))
				shown := 5
				if len(records) < shown {
					shown = len(records)
				}
				for i := 0; i < shown; i++ {
					rec, ok := records[i].(map[string]interface{})
					if !ok {
						continue
					}
					action := fmt.Sprintf("%v", rec["action"])
					target := fmt.Sprintf("%v", rec["target"])
					recStatus := fmt.Sprintf("%v", rec["status"])
					if len(target) > 18 {
						target = target[:15] + "..."
					}
					sColor := dim
					switch recStatus {
					case "SUCCESS":
						sColor = green
					case "FAILED":
						sColor = red
					case "DRY_RUN":
						sColor = yellow
					}
					fmt.Printf("  %s %-16s %-18s %s\n", sColor("▸"), action, target, sColor(recStatus))
				}
			}
		}
	}

	// Metrics section
	metricsBody, metricsErr := apiGet(base+"/api/v1/metrics", apiKey, timeout)
	if metricsErr == nil {
		var metricsResp map[string]interface{}
		if json.Unmarshal(metricsBody, &metricsResp) == nil {
			fmt.Println()
			fmt.Printf("  %s\n", bold("METRICS"))

			if bus, ok := metricsResp["bus"].(map[string]interface{}); ok {
				evPub := int64(0)
				if v, ok := bus["events_published"].(float64); ok {
					evPub = int64(v)
				}
				alPub := int64(0)
				if v, ok := bus["alerts_published"].(float64); ok {
					alPub = int64(v)
				}
				evFail := int64(0)
				if v, ok := bus["events_failed"].(float64); ok {
					evFail = int64(v)
				}
				parts := []string{fmt.Sprintf("events:%d", evPub), fmt.Sprintf("alerts:%d", alPub)}
				if evFail > 0 {
					parts = append(parts, red(fmt.Sprintf("failed:%d", evFail)))
				}
				fmt.Printf("  %-20s %s\n", "Bus:", strings.Join(parts, "  "))
			}

			if routing, ok := metricsResp["routing"].(map[string]interface{}); ok {
				routed := int64(0)
				if v, ok := routing["events_routed"].(float64); ok {
					routed = int64(v)
				}
				dropped := int64(0)
				if v, ok := routing["events_dropped"].(float64); ok {
					dropped = int64(v)
				}
				parts := []string{fmt.Sprintf("routed:%d", routed)}
				if dropped > 0 {
					parts = append(parts, yellow(fmt.Sprintf("dropped:%d", dropped)))
				}

				// Show module errors if any
				if modErrors, ok := routing["module_errors"].(map[string]interface{}); ok && len(modErrors) > 0 {
					for mod, count := range modErrors {
						if c, ok := count.(float64); ok && c > 0 {
							parts = append(parts, red(fmt.Sprintf("%s-err:%d", mod, int(c))))
						}
					}
				}
				fmt.Printf("  %-20s %s\n", "Routing:", strings.Join(parts, "  "))

				// Top event types
				if byType, ok := routing["events_by_type"].(map[string]interface{}); ok && len(byType) > 0 {
					// Collect and sort by count (show top 5)
					type typeCount struct {
						name  string
						count int64
					}
					types := make([]typeCount, 0, len(byType))
					for name, v := range byType {
						if c, ok := v.(float64); ok {
							types = append(types, typeCount{name, int64(c)})
						}
					}
					// Simple sort descending
					for i := 0; i < len(types); i++ {
						for j := i + 1; j < len(types); j++ {
							if types[j].count > types[i].count {
								types[i], types[j] = types[j], types[i]
							}
						}
					}
					shown := 5
					if len(types) < shown {
						shown = len(types)
					}
					if shown > 0 {
						typeParts := make([]string, 0, shown)
						for i := 0; i < shown; i++ {
							typeParts = append(typeParts, fmt.Sprintf("%s:%d", types[i].name, types[i].count))
						}
						fmt.Printf("  %-20s %s\n", "Top Events:", dim(strings.Join(typeParts, "  ")))
					}
				}
			}
		}
	}

	// Archive section
	archiveBody, archiveErr := apiGet(base+"/api/v1/archive/status", apiKey, timeout)
	if archiveErr == nil {
		var archiveResp map[string]interface{}
		if json.Unmarshal(archiveBody, &archiveResp) == nil {
			if enabled, ok := archiveResp["enabled"].(bool); ok && enabled {
				fmt.Println()
				fmt.Printf("  %s\n", bold("ARCHIVE"))

				evArchived := int64(0)
				if v, ok := archiveResp["events_archived"].(float64); ok {
					evArchived = int64(v)
				}
				alArchived := int64(0)
				if v, ok := archiveResp["alerts_archived"].(float64); ok {
					alArchived = int64(v)
				}
				filesRotated := int64(0)
				if v, ok := archiveResp["files_rotated"].(float64); ok {
					filesRotated = int64(v)
				}
				bytesWritten := int64(0)
				if v, ok := archiveResp["bytes_written"].(float64); ok {
					bytesWritten = int64(v)
				}
				sampled := int64(0)
				if v, ok := archiveResp["events_sampled"].(float64); ok {
					sampled = int64(v)
				}

				fmt.Printf("  %-20s events:%d  alerts:%d  files:%d\n", "Stored:", evArchived, alArchived, filesRotated)
				bytesStr := formatBytes(bytesWritten)
				parts := []string{bytesStr}
				if sampled > 0 {
					parts = append(parts, dim(fmt.Sprintf("sampled:%d", sampled)))
				}
				fmt.Printf("  %-20s %s\n", "Written:", strings.Join(parts, "  "))
				if cur, ok := archiveResp["current_file"].(string); ok && cur != "" {
					fmt.Printf("  %-20s %s\n", "Current:", dim(cur))
				}
			}
		}
	}

	// Threats section (IP reputation)
	threatsBody, threatsErr := apiGet(base+"/api/v1/threats", apiKey, timeout)
	if threatsErr == nil {
		var threatsResp map[string]interface{}
		if json.Unmarshal(threatsBody, &threatsResp) == nil {
			totalThreats := 0
			if t, ok := threatsResp["total"].(float64); ok {
				totalThreats = int(t)
			}
			blockedCount := 0
			if b, ok := threatsResp["blocked_count"].(float64); ok {
				blockedCount = int(b)
			}
			if totalThreats > 0 {
				fmt.Println()
				fmt.Printf("  %s  %s\n", bold("THREATS"), dim(fmt.Sprintf("%d tracked, %d blocked", totalThreats, blockedCount)))

				if threats, ok := threatsResp["threats"].([]interface{}); ok {
					shown := 5
					if len(threats) < shown {
						shown = len(threats)
					}
					for i := 0; i < shown; i++ {
						threat, ok := threats[i].(map[string]interface{})
						if !ok {
							continue
						}
						ip := fmt.Sprintf("%v", threat["ip"])
						reason := fmt.Sprintf("%v", threat["reason"])
						blocked, _ := threat["blocked"].(bool)
						if len(reason) > 30 {
							reason = reason[:27] + "..."
						}
						marker := yellow("▸")
						if blocked {
							marker = red("✗")
						}
						fmt.Printf("  %s %-18s %s\n", marker, ip, dim(reason))
					}
					if totalThreats > 5 {
						fmt.Printf("  %s +%d more\n", dim("▸"), totalThreats-5)
					}
				}
			}
		}
	}

	// Escalation section
	escalationBody, escalationErr := apiGet(base+"/api/v1/escalation/status", apiKey, timeout)
	if escalationErr == nil {
		var escalationResp map[string]interface{}
		if json.Unmarshal(escalationBody, &escalationResp) == nil {
			if enabled, ok := escalationResp["enabled"].(bool); ok && enabled {
				trackedCount := 0
				if t, ok := escalationResp["tracked_alerts"].(float64); ok {
					trackedCount = int(t)
				}
				if trackedCount > 0 {
					fmt.Println()
					fmt.Printf("  %s  %s\n", bold("ESCALATION"), yellow(fmt.Sprintf("%d alerts pending escalation", trackedCount)))

					if alerts, ok := escalationResp["alerts"].([]interface{}); ok {
						shown := 3
						if len(alerts) < shown {
							shown = len(alerts)
						}
						for i := 0; i < shown; i++ {
							a, ok := alerts[i].(map[string]interface{})
							if !ok {
								continue
							}
							alertID := fmt.Sprintf("%v", a["alert_id"])
							if len(alertID) > 12 {
								alertID = alertID[:12]
							}
							sev := fmt.Sprintf("%v", a["severity"])
							mod := fmt.Sprintf("%v", a["module"])
							esc := 0
							if e, ok := a["escalations"].(float64); ok {
								esc = int(e)
							}
							fmt.Printf("  %s %s %s %s %s\n", yellow("▸"), alertID, sev, dim(mod), dim(fmt.Sprintf("esc:%d", esc)))
						}
					}
				}
			}
		}
	}

	fmt.Printf("\n  %s\n", dim("─────────────────────────────────────────────"))
	fmt.Printf("  %s %s  %s %s\n",
		dim("API:"), base,
		dim("Refresh:"), dim("auto"))
}
