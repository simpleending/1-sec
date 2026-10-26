package main

// ---------------------------------------------------------------------------
// cmd_setup.go — guided interactive setup wizard
//
// Walks users through the essential configuration in one flow:
//   1. Config file creation (if missing)
//   2. Gemini API key for AI analysis (BYOK)
//   3. API key for securing the REST endpoint
//   4. Pre-flight validation
//
// Usage:
//   1sec setup                  # full interactive wizard
//   1sec setup --ai-only        # just configure AI keys
//   1sec setup --non-interactive # use env vars, no prompts
// ---------------------------------------------------------------------------

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
	"gopkg.in/yaml.v3"
)

func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	configPath := fs.String("config", "1sec.yaml", "Config file path")
	aiOnly := fs.Bool("ai-only", false, "Only configure AI (Gemini) API keys")
	nonInteractive := fs.Bool("non-interactive", false, "Use environment variables, skip prompts")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	if *profileFlag != "" {
		*configPath = resolveProfile(*profileFlag, envConfig(*configPath))
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Printf("  %s  1SEC Setup Wizard\n", bold("⚡"))
	fmt.Printf("  %s\n\n", dim("Get up and running in under a minute."))

	if *aiOnly {
		setupAIKeys(reader, *configPath, *nonInteractive)
		return
	}

	// Step 1: Config file
	setupConfigFile(reader, *configPath, *nonInteractive)

	// Step 2: AI keys (BYOK)
	setupAIKeys(reader, *configPath, *nonInteractive)

	// Step 3: API authentication
	setupAPIKey(reader, *configPath, *nonInteractive)

	// Step 4: Validate
	setupValidate(*configPath)

	// Done
	fmt.Println()
	fmt.Printf("  %s  Setup complete.\n\n", green("✓"))
	fmt.Printf("  %s\n", bold("Next steps:"))
	fmt.Printf("    %s  Run %s to start the engine\n", dim("▸"), bold("1sec up --config "+*configPath))
	fmt.Printf("    %s  Run %s to verify everything\n", dim("▸"), bold("1sec check --config "+*configPath))
	fmt.Printf("    %s  Run %s for real-time monitoring\n", dim("▸"), bold("1sec dashboard"))
	fmt.Println()
}

func setupConfigFile(reader *bufio.Reader, configPath string, nonInteractive bool) {
	fmt.Printf("  %s  Config file\n", bold("1"))

	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("     %s Found %s\n\n", green("✓"), configPath)
		return
	}

	if nonInteractive {
		// Auto-create with defaults
		writeDefaultConfig(configPath)
		fmt.Printf("     %s Created %s with defaults\n\n", green("✓"), configPath)
		return
	}

	fmt.Printf("     No config file found at %s\n", configPath)
	fmt.Printf("     Create one now? [Y/n] ")
	answer := readLine(reader)
	if answer != "" && strings.ToLower(answer)[0] != 'y' {
		fmt.Printf("     %s Skipped — you can run %s later\n\n", dim("▸"), bold("1sec init"))
		return
	}

	fmt.Printf("     Config style — [f]ull or [m]inimal? [F/m] ")
	style := strings.ToLower(readLine(reader))
	var content string
	if style == "m" {
		content = minimalConfig()
	} else {
		content = fullConfig()
	}

	if err := core.WritePrivateConfig(configPath, []byte(content)); err != nil {
		fmt.Printf("     %s Could not write %s: %v\n\n", red("✗"), configPath, err)
		return
	}
	fmt.Printf("     %s Created %s\n\n", green("✓"), configPath)
}

func setupAIKeys(reader *bufio.Reader, configPath string, nonInteractive bool) {
	fmt.Printf("  %s  AI Analysis (Gemini BYOK)\n", bold("2"))

	// Check if keys already exist via env
	envKeys := []string{}
	for _, env := range []string{"GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API_KEY_4"} {
		if os.Getenv(env) != "" {
			envKeys = append(envKeys, env)
		}
	}

	// Check config file
	configHasKey := false
	if cfg, err := core.LoadConfig(configPath); err == nil {
		settings := cfg.GetModuleSettings("ai_analysis_engine")
		if _, ok := settings["gemini_api_key"]; ok {
			configHasKey = true
		}
		if keys, ok := settings["gemini_api_keys"]; ok {
			if arr, ok := keys.([]interface{}); ok && len(arr) > 0 {
				configHasKey = true
			}
		}
	}

	if len(envKeys) > 0 {
		fmt.Printf("     %s %d key(s) found via environment (%s)\n", green("✓"), len(envKeys), strings.Join(envKeys, ", "))
		if configHasKey {
			fmt.Printf("     %s Also found key(s) in config file\n", green("✓"))
		}
		fmt.Println()
		return
	}

	if configHasKey {
		fmt.Printf("     %s Key found in config file\n\n", green("✓"))
		return
	}

	// No keys found
	fmt.Printf("     %s No Gemini API key detected\n", yellow("!"))
	fmt.Printf("     %s AI analysis is optional — all 15 rule-based modules work without it.\n", dim(" "))
	fmt.Printf("     %s Get a free key at: %s\n", dim(" "), cyan("https://aistudio.google.com/apikey"))
	fmt.Println()

	if nonInteractive {
		fmt.Printf("     %s Set GEMINI_API_KEY to enable AI analysis\n\n", dim("▸"))
		return
	}

	fmt.Printf("     Enter Gemini API key (or press Enter to skip): ")
	key := strings.TrimSpace(readLine(reader))
	if key == "" {
		fmt.Printf("     %s Skipped — AI engine will run in passive mode\n\n", dim("▸"))
		return
	}

	if len(key) < 10 {
		fmt.Printf("     %s Key looks too short — skipping. You can set it later with:\n", yellow("!"))
		fmt.Printf("       %s\n\n", bold("1sec config set-key "+key))
		return
	}

	// Write key to config
	if err := writeAIKeyToConfig(configPath, key); err != nil {
		fmt.Printf("     %s Could not save to config: %v\n", red("✗"), err)
		fmt.Printf("     %s Set it via environment instead: %s\n\n", dim("▸"), bold("export GEMINI_API_KEY="+key))
		return
	}

	fmt.Printf("     %s Gemini API key saved to %s\n", green("✓"), configPath)

	fmt.Printf("     Add more keys for load balancing? [y/N] ")
	if strings.ToLower(readLine(reader)) == "y" {
		for i := 2; i <= 4; i++ {
			fmt.Printf("     Key %d (Enter to stop): ", i)
			extra := strings.TrimSpace(readLine(reader))
			if extra == "" {
				break
			}
			appendAIKeyToConfig(configPath, extra)
			fmt.Printf("     %s Key %d saved\n", green("✓"), i)
		}
	}
	fmt.Println()
}

func setupAPIKey(reader *bufio.Reader, configPath string, nonInteractive bool) {
	fmt.Printf("  %s  REST API Security\n", bold("3"))

	// Check if API key already set
	if os.Getenv("ONESEC_API_KEY") != "" {
		fmt.Printf("     %s API key found via ONESEC_API_KEY\n\n", green("✓"))
		return
	}

	if cfg, err := core.LoadConfig(configPath); err == nil && len(cfg.Server.APIKeys) > 0 {
		fmt.Printf("     %s API key(s) configured in %s\n\n", green("✓"), configPath)
		return
	}

	fmt.Printf("     %s API has no authentication key configured\n", yellow("!"))
	fmt.Printf("     %s Loopback read-only access is fine for local dev, but set a key for production.\n", dim(" "))

	if nonInteractive {
		fmt.Printf("     %s Set ONESEC_API_KEY for production use\n\n", dim("▸"))
		return
	}

	fmt.Printf("     Set an API key now? [y/N] ")
	if strings.ToLower(readLine(reader)) != "y" {
		fmt.Printf("     %s Skipped — API runs in open mode\n\n", dim("▸"))
		return
	}

	fmt.Printf("     Enter API key: ")
	apiKey := strings.TrimSpace(readLine(reader))
	if apiKey == "" {
		fmt.Printf("     %s Skipped\n\n", dim("▸"))
		return
	}

	if err := writeAPIKeyToConfig(configPath, apiKey); err != nil {
		fmt.Printf("     %s Could not save: %v. Set via env: %s\n\n", red("✗"), err, bold("export ONESEC_API_KEY="+apiKey))
		return
	}
	fmt.Printf("     %s API key saved to %s\n\n", green("✓"), configPath)
}

func setupValidate(configPath string) {
	fmt.Printf("  %s  Validation\n", bold("4"))

	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("     %s Could not load config: %v\n", red("✗"), err)
		return
	}

	warnings, errs := cfg.Validate()
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Printf("     %s %s\n", red("✗"), e)
		}
	}
	if len(warnings) > 0 {
		for _, w := range warnings {
			fmt.Printf("     %s %s\n", yellow("!"), w)
		}
	}

	enabledCount := 0
	for _, name := range []string{
		"network_guardian", "api_fortress", "iot_shield", "injection_shield",
		"supply_chain", "ransomware", "auth_fortress", "deepfake_shield",
		"identity_monitor", "llm_firewall", "ai_containment", "data_poisoning",
		"quantum_crypto", "runtime_watcher", "cloud_posture", "ai_analysis_engine",
	} {
		if cfg.IsModuleEnabled(name) {
			enabledCount++
		}
	}

	if len(errs) == 0 {
		fmt.Printf("     %s Config valid — %d/16 modules enabled\n", green("✓"), enabledCount)
	}
}

// ---------------------------------------------------------------------------
// Config file helpers
// ---------------------------------------------------------------------------

func readLine(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func writeDefaultConfig(path string) {
	content := fullConfig()
	core.WritePrivateConfig(path, []byte(content))
}

func writeAIKeyToConfig(configPath, key string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Config doesn't exist yet — create minimal one with the key
		content := fmt.Sprintf(`# 1SEC Configuration
# Generated by '1sec setup'

server:
  host: "127.0.0.1"
  port: 1780

modules:
  ai_analysis_engine:
    enabled: true
    settings:
      gemini_api_key: %q
`, key)
		return core.WritePrivateConfig(configPath, []byte(content))
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	// Navigate to modules.ai_analysis_engine.settings
	modules, _ := raw["modules"].(map[string]interface{})
	if modules == nil {
		modules = map[string]interface{}{}
		raw["modules"] = modules
	}
	aiMod, _ := modules["ai_analysis_engine"].(map[string]interface{})
	if aiMod == nil {
		aiMod = map[string]interface{}{"enabled": true}
		modules["ai_analysis_engine"] = aiMod
	}
	settings, _ := aiMod["settings"].(map[string]interface{})
	if settings == nil {
		settings = map[string]interface{}{}
		aiMod["settings"] = settings
	}
	settings["gemini_api_key"] = key

	out, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	return core.WritePrivateConfig(configPath, out)
}

func appendAIKeyToConfig(configPath, key string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}

	modules, _ := raw["modules"].(map[string]interface{})
	if modules == nil {
		return fmt.Errorf("no modules section")
	}
	aiMod, _ := modules["ai_analysis_engine"].(map[string]interface{})
	if aiMod == nil {
		return fmt.Errorf("no ai_analysis_engine section")
	}
	settings, _ := aiMod["settings"].(map[string]interface{})
	if settings == nil {
		return fmt.Errorf("no settings section")
	}

	// Get or create the keys list
	var keys []interface{}
	if existing, ok := settings["gemini_api_keys"]; ok {
		keys, _ = existing.([]interface{})
	}

	// If there's a single key, migrate it to the list
	if single, ok := settings["gemini_api_key"]; ok {
		if s, ok := single.(string); ok && s != "" {
			found := false
			for _, k := range keys {
				if k == s {
					found = true
					break
				}
			}
			if !found {
				keys = append(keys, s)
			}
		}
		delete(settings, "gemini_api_key")
	}

	keys = append(keys, key)
	settings["gemini_api_keys"] = keys

	out, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	return core.WritePrivateConfig(configPath, out)
}

func writeAPIKeyToConfig(configPath, apiKey string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}

	server, _ := raw["server"].(map[string]interface{})
	if server == nil {
		server = map[string]interface{}{}
		raw["server"] = server
	}
	server["api_keys"] = []interface{}{apiKey}

	out, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	return core.WritePrivateConfig(configPath, out)
}
