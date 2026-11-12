package main

// ---------------------------------------------------------------------------
// cmd_stop.go — gracefully stop a running instance via API
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func cmdStop(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKeyFlag := fs.String("api-key", "", "API key for authentication")
	timeoutStr := fs.String("timeout", "5s", "Request timeout")
	profileFlag := fs.String("profile", "", "Named profile to use")
	fs.Parse(args)

	*configPath = resolveProfile(*profileFlag, envConfig(*configPath))

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		errorf("invalid timeout %q: %v", *timeoutStr, err)
	}

	base := apiBase(*configPath, envHost(*host), envPort(*port))
	apiKey := resolveAPIKey(*apiKeyFlag, *configPath)

	_, err = apiGet(base+"/live", apiKey, timeout)
	if err != nil {
		errorf("cannot reach 1SEC instance at %s — is it running?", base)
	}

	body, err := apiPost(base+"/api/v1/shutdown", []byte("{}"), apiKey, timeout)
	if err != nil {
		if isConnectionError(err) {
			fmt.Fprintf(os.Stdout, "%s 1SEC instance is shutting down.\n", green("✓"))
			return
		}
		errorf("shutdown request failed: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stdout, "%s Shutdown signal sent.\n", green("✓"))
		return
	}

	fmt.Fprintf(os.Stdout, "%s %s\n", green("✓"), resp["message"])
}
