package core

import (
	"fmt"
	"slices"

	"github.com/rs/zerolog"
)

// ReloadConfig reloads the configuration from disk and applies changes that
// can be hot-reloaded without restarting the engine. Returns a list of what
// changed.
//
// Hot-reloadable settings:
//   - enforcement policies, preset, dry_run, global_allow_list
//   - alert webhook URLs
//   - module enable/disable (stops/starts modules)
//   - logging level
//   - archive sampling rules
//
// NOT hot-reloadable (require restart):
//   - bus config (NATS URL, port, data dir)
//   - server host/port
//   - TLS config
//   - management access policy (rejects reload before applying other changes)
func ReloadConfig(engine *Engine, configPath string, logger zerolog.Logger) ([]string, error) {
	if configPath == "" {
		return nil, fmt.Errorf("no config path set — cannot reload")
	}

	newCfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	var changes []string
	if !slices.Equal(newCfg.ManagementAccess.AllowedSources, engine.Config.ManagementAccess.AllowedSources) ||
		!slices.Equal(newCfg.ManagementAccess.AllowedOperators, engine.Config.ManagementAccess.AllowedOperators) {
		return nil, fmt.Errorf("management_access changes require an engine restart; no configuration changes applied")
	}

	// Reload logging level
	if newCfg.LogLevel() != engine.Config.LogLevel() {
		engine.Config.Logging.Level = newCfg.Logging.Level
		changes = append(changes, "logging.level → "+newCfg.LogLevel())
	}

	// Reload enforcement config
	if newCfg.Enforcement != nil {
		if engine.Config.Enforcement == nil {
			engine.Config.Enforcement = newCfg.Enforcement
			changes = append(changes, "enforcement enabled")
		} else {
			if newCfg.Enforcement.DryRun != engine.Config.Enforcement.GetDryRun() {
				engine.Config.Enforcement.SetDryRun(newCfg.Enforcement.DryRun)
				changes = append(changes, fmt.Sprintf("enforcement.dry_run → %v", newCfg.Enforcement.DryRun))
			}
			if newCfg.Enforcement.Preset != engine.Config.Enforcement.Preset {
				engine.Config.Enforcement.Preset = newCfg.Enforcement.Preset
				changes = append(changes, "enforcement.preset → "+newCfg.Enforcement.Preset)
			}
			engine.Config.Enforcement.GlobalAllowList = newCfg.Enforcement.GlobalAllowList
			engine.Config.Enforcement.Policies = newCfg.Enforcement.Policies
			changes = append(changes, "enforcement policies reloaded")
		}
	}

	// Reload alert webhook URLs
	if len(newCfg.Alerts.WebhookURLs) != len(engine.Config.Alerts.WebhookURLs) {
		engine.Config.Alerts.WebhookURLs = newCfg.Alerts.WebhookURLs
		changes = append(changes, fmt.Sprintf("alerts.webhook_urls → %d URLs", len(newCfg.Alerts.WebhookURLs)))
	}

	// Reload API keys (allows adding/removing keys without restart)
	engine.Config.Server.APIKeys = newCfg.Server.APIKeys
	engine.Config.Server.ReadOnlyKeys = newCfg.Server.ReadOnlyKeys

	// Reload CORS origins
	engine.Config.Server.CORSOrigins = newCfg.Server.CORSOrigins

	// Reload archive sampling rules
	engine.Config.Archive.SampleRules = newCfg.Archive.SampleRules
	if engine.Archiver != nil {
		engine.Archiver.cfg.SampleRules = newCfg.Archive.SampleRules
	}

	// Reload module enable/disable
	for name, newMod := range newCfg.Modules {
		oldMod, exists := engine.Config.Modules[name]
		if !exists || oldMod.Enabled != newMod.Enabled {
			engine.Config.Modules[name] = newMod
			if newMod.Enabled {
				changes = append(changes, "module "+name+" enabled")
			} else {
				changes = append(changes, "module "+name+" disabled")
			}
		}
		// Update module settings
		if exists {
			engine.Config.Modules[name] = newMod
		}
	}

	if len(changes) == 0 {
		changes = append(changes, "no changes detected")
	}

	logger.Info().Strs("changes", changes).Msg("configuration reloaded")
	return changes, nil
}
