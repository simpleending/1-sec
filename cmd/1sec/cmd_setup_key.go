package main

// ---------------------------------------------------------------------------
// cmd_setup_key.go — shortcut commands for key management
//
// Usage:
//   1sec config set-key <gemini-api-key>          # set single AI key
//   1sec config set-key <key1> <key2> ...         # set multiple AI keys
//   1sec config set-key --env                     # import from GEMINI_API_KEY env vars
//   1sec config set-key --show                    # show current key status (masked)
// ---------------------------------------------------------------------------

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
	"gopkg.in/yaml.v3"
)

func cmdConfigSetKey(args []string) {
	fs := flag.NewFlagSet("config-set-key", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	fromEnv := fs.Bool("env", false, "Import keys from GEMINI_API_KEY environment variables")
	show := fs.Bool("show", false, "Show current AI key status (masked)")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))

	if *show {
		showKeyStatus(*configPath)
		return
	}

	if *fromEnv {
		importKeysFromEnv(*configPath)
		return
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintf(os.Stderr, "%s\n\n", bold("1sec config set-key"))
		fmt.Fprintf(os.Stderr, "Set Gemini API key(s) for AI-powered threat analysis.\n\n")
		fmt.Fprintf(os.Stderr, "%s\n\n", bold("USAGE"))
		fmt.Fprintf(os.Stderr, "  1sec config set-key <key>              Set a single key\n")
		fmt.Fprintf(os.Stderr, "  1sec config set-key <k1> <k2> <k3>    Set multiple keys (load balancing)\n")
		fmt.Fprintf(os.Stderr, "  1sec config set-key --env              Import from GEMINI_API_KEY env vars\n")
		fmt.Fprintf(os.Stderr, "  1sec config set-key --show             Show current key status\n\n")
		fmt.Fprintf(os.Stderr, "%s\n\n", bold("GET A KEY"))
		fmt.Fprintf(os.Stderr, "  %s\n\n", cyan("https://aistudio.google.com/apikey"))
		os.Exit(1)
	}

	// Validate keys
	var validKeys []string
	for _, k := range remaining {
		k = strings.TrimSpace(k)
		if len(k) < 10 {
			warnf("key %q looks too short (< 10 chars), skipping", maskKey(k))
			continue
		}
		validKeys = append(validKeys, k)
	}

	if len(validKeys) == 0 {
		errorf("no valid keys provided")
	}

	if err := writeAIKeysToConfig(*configPath, validKeys); err != nil {
		errorf("saving keys: %v", err)
	}

	fmt.Fprintf(os.Stdout, "%s %d Gemini API key(s) saved to %s\n", green("✓"), len(validKeys), *configPath)
	for i, k := range validKeys {
		fmt.Fprintf(os.Stdout, "  %s Key %d: %s\n", dim("▸"), i+1, maskKey(k))
	}
	fmt.Fprintf(os.Stdout, "\n%s AI analysis engine will use these keys on next start.\n", dim("▸"))
}

func showKeyStatus(configPath string) {
	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		errorf("loading config: %v", err)
	}

	settings := cfg.GetModuleSettings("ai_analysis_engine")
	var keys []string

	if single, ok := settings["gemini_api_key"].(string); ok && single != "" {
		keys = append(keys, single)
	}
	if list, ok := settings["gemini_api_keys"].([]interface{}); ok {
		for _, k := range list {
			if s, ok := k.(string); ok && s != "" {
				keys = append(keys, s)
			}
		}
	}

	// Also check env
	envKeys := map[string]string{}
	for _, env := range []string{"GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API_KEY_4"} {
		if v := os.Getenv(env); v != "" {
			envKeys[env] = v
		}
	}

	fmt.Printf("%s AI Key Status\n\n", bold("🔑"))

	if len(keys) == 0 && len(envKeys) == 0 {
		fmt.Printf("  %s No Gemini API keys configured\n\n", yellow("!"))
		fmt.Printf("  %s\n", bold("To add a key:"))
		fmt.Printf("    1sec config set-key <your-key>\n")
		fmt.Printf("    %s or %s\n\n", dim(""), dim("export GEMINI_API_KEY=<your-key>"))
		fmt.Printf("  %s %s\n\n", dim("Get a free key:"), cyan("https://aistudio.google.com/apikey"))
		return
	}

	if len(keys) > 0 {
		fmt.Printf("  %s Config file (%s):\n", bold("▸"), configPath)
		for i, k := range keys {
			fmt.Printf("    Key %d: %s\n", i+1, maskKey(k))
		}
		fmt.Println()
	}

	if len(envKeys) > 0 {
		fmt.Printf("  %s Environment variables:\n", bold("▸"))
		for env, v := range envKeys {
			fmt.Printf("    %s = %s\n", env, maskKey(v))
		}
		fmt.Println()
	}

	enabled := cfg.IsModuleEnabled("ai_analysis_engine")
	if enabled {
		fmt.Printf("  AI engine: %s\n", green("enabled"))
	} else {
		fmt.Printf("  AI engine: %s %s\n", red("disabled"), dim("(run: 1sec modules enable ai_analysis_engine)"))
	}
	fmt.Println()
}

func importKeysFromEnv(configPath string) {
	var keys []string
	for _, env := range []string{"GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API_KEY_4"} {
		if v := os.Getenv(env); v != "" {
			keys = append(keys, strings.TrimSpace(v))
		}
	}

	if len(keys) == 0 {
		errorf("no GEMINI_API_KEY* environment variables found")
	}

	if err := writeAIKeysToConfig(configPath, keys); err != nil {
		errorf("saving keys: %v", err)
	}

	fmt.Fprintf(os.Stdout, "%s Imported %d key(s) from environment to %s\n", green("✓"), len(keys), configPath)
}

func writeAIKeysToConfig(configPath string, keys []string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Create new config with keys
		content := "# 1SEC Configuration\n\nserver:\n  host: \"127.0.0.1\"\n  port: 1780\n\nmodules:\n  ai_analysis_engine:\n    enabled: true\n    settings:\n"
		if len(keys) == 1 {
			content += fmt.Sprintf("      gemini_api_key: %q\n", keys[0])
		} else {
			content += "      gemini_api_keys:\n"
			for _, k := range keys {
				content += fmt.Sprintf("        - %q\n", k)
			}
		}
		// #nosec G703 -- --config intentionally selects the operator-owned destination.
		return os.WriteFile(configPath, []byte(content), core.ConfigFileMode)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

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

	// Clean up old key format
	delete(settings, "gemini_api_key")

	if len(keys) == 1 {
		settings["gemini_api_key"] = keys[0]
		delete(settings, "gemini_api_keys")
	} else {
		ikeys := make([]interface{}, len(keys))
		for i, k := range keys {
			ikeys[i] = k
		}
		settings["gemini_api_keys"] = ikeys
		delete(settings, "gemini_api_key")
	}

	out, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	// #nosec G703 -- --config intentionally selects the operator-owned destination.
	return os.WriteFile(configPath, out, core.ConfigFileMode)
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", len(key)-8) + key[len(key)-4:]
}
