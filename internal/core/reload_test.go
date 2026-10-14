package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func testReloadEngine() *Engine {
	cfg := DefaultConfig()
	cfg.RustEngine.Enabled = false
	logger := zerolog.Nop()
	return &Engine{
		Config:   cfg,
		Registry: NewModuleRegistry(logger),
		Pipeline: NewAlertPipeline(logger, 1000),
		Logger:   logger,
	}
}

func writeReloadConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReloadConfig_EmptyPath_Error(t *testing.T) {
	e := testReloadEngine()
	_, err := ReloadConfig(e, "", zerolog.Nop())
	if err == nil {
		t.Error("expected error for empty config path")
	}
}

func TestReloadManagementPolicyRequiresRestartBeforeMutation(t *testing.T) {
	e := testReloadEngine()
	oldLevel := e.Config.Logging.Level
	path := writeReloadConfig(t, `
logging:
  level: debug
management_access:
  allowed_sources: ["10.20.0.0/24"]
  allowed_operators: ["engineer"]
`)
	_, err := ReloadConfig(e, path, zerolog.Nop())
	if err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("expected restart error: %v", err)
	}
	if e.Config.Logging.Level != oldLevel || len(e.Config.ManagementAccess.AllowedSources) != 0 {
		t.Fatal("rejected reload partially changed active configuration")
	}
	path = writeReloadConfig(t, `
management_access:
  allowed_sources: []
  allowed_operators: []
`)
	if _, err := ReloadConfig(e, path, zerolog.Nop()); err != nil {
		t.Fatalf("empty lists and defaults should be equivalent: %v", err)
	}
}

func TestReloadConfig_NonExistentFile_UsesDefaults(t *testing.T) {
	e := testReloadEngine()
	changes, err := ReloadConfig(e, "/nonexistent/config.yaml", zerolog.Nop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should detect no changes since defaults match defaults
	if len(changes) == 0 {
		t.Error("expected at least 'no changes detected'")
	}
}

func TestReloadConfig_LogLevelChange(t *testing.T) {
	e := testReloadEngine()
	e.Config.Logging.Level = "info"

	path := writeReloadConfig(t, `
logging:
  level: "debug"
`)
	changes, err := ReloadConfig(e, path, zerolog.Nop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, c := range changes {
		if strings.Contains(c, "logging.level") && strings.Contains(c, "debug") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected logging level change in %v", changes)
	}
	if e.Config.LogLevel() != "debug" {
		t.Errorf("config not updated: level = %q", e.Config.LogLevel())
	}
}

func TestReloadConfig_EnforcementDryRunChange(t *testing.T) {
	e := testReloadEngine()
	e.Config.Enforcement = &EnforcementConfig{Enabled: true, DryRun: true}

	path := writeReloadConfig(t, `
enforcement:
  enabled: true
  dry_run: false
`)
	changes, err := ReloadConfig(e, path, zerolog.Nop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, c := range changes {
		if strings.Contains(c, "dry_run") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected dry_run change in %v", changes)
	}
	if e.Config.Enforcement.GetDryRun() {
		t.Error("dry_run should be false after reload")
	}
}

func TestReloadConfig_EnforcementPresetChange(t *testing.T) {
	e := testReloadEngine()
	e.Config.Enforcement = &EnforcementConfig{Enabled: true, Preset: "safe"}

	path := writeReloadConfig(t, `
enforcement:
  enabled: true
  preset: "strict"
`)
	changes, err := ReloadConfig(e, path, zerolog.Nop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, c := range changes {
		if strings.Contains(c, "preset") && strings.Contains(c, "strict") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected preset change in %v", changes)
	}
}

func TestReloadConfig_APIKeysReloaded(t *testing.T) {
	e := testReloadEngine()
	e.Config.Server.APIKeys = []string{"old-key"}

	path := writeReloadConfig(t, `
server:
  api_keys:
    - "new-key-1"
    - "new-key-2"
`)
	_, err := ReloadConfig(e, path, zerolog.Nop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(e.Config.Server.APIKeys) != 2 {
		t.Errorf("expected 2 API keys, got %d", len(e.Config.Server.APIKeys))
	}
	if e.Config.Server.APIKeys[0] != "new-key-1" {
		t.Errorf("expected new-key-1, got %q", e.Config.Server.APIKeys[0])
	}
}

func TestReloadConfig_ModuleEnableDisable(t *testing.T) {
	e := testReloadEngine()
	e.Config.Modules["iot_shield"] = ModuleConfig{Enabled: true}

	path := writeReloadConfig(t, `
modules:
  iot_shield:
    enabled: false
`)
	changes, err := ReloadConfig(e, path, zerolog.Nop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, c := range changes {
		if strings.Contains(c, "iot_shield") && strings.Contains(c, "disabled") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected iot_shield disabled in %v", changes)
	}
}

func TestReloadConfig_NoChanges(t *testing.T) {
	e := testReloadEngine()
	// Write a config that matches defaults
	path := writeReloadConfig(t, `
logging:
  level: "info"
`)
	changes, err := ReloadConfig(e, path, zerolog.Nop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have "no changes detected" or module reload entries
	if len(changes) == 0 {
		t.Error("expected at least one change entry")
	}
}

func TestReloadConfig_SampleRulesReloaded(t *testing.T) {
	e := testReloadEngine()
	e.Config.Archive.SampleRules = nil

	path := writeReloadConfig(t, `
archive:
  sample_rules:
    - event_type: "dns_query"
      max_severity: "INFO"
      sample_rate: 100
`)
	_, err := ReloadConfig(e, path, zerolog.Nop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(e.Config.Archive.SampleRules) != 1 {
		t.Errorf("expected 1 sample rule, got %d", len(e.Config.Archive.SampleRules))
	}
}
