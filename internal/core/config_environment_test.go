package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFallbackRetainsEnvironment(t *testing.T) {
	t.Setenv("ONESEC_API_KEY", "test-local-key")
	t.Setenv("ONESEC_CLOUD_API_KEY", "test-instance-key")
	t.Setenv("ONESEC_LOG_LEVEL", "warn")
	t.Setenv("ONESEC_RUST_ENGINE", "true")
	empty := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing.yaml"), empty} {
		t.Run(path, func(t *testing.T) {
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Server.APIKeys) != 1 || cfg.Server.APIKeys[0] != "test-local-key" {
				t.Error("environment API authentication was lost")
			}
			if !cfg.Cloud.Enabled || cfg.Cloud.APIKey != "test-instance-key" || cfg.Logging.Level != "warn" || !cfg.RustEngine.Enabled {
				t.Error("fallback skipped environment settings")
			}
		})
	}
}
