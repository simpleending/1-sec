package core

import (
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReloadRequiresRestartWithoutPartialMutation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.APIKeys = []string{"old-key"}
	engine := &Engine{Config: cfg}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("logging:\n  level: debug\nserver:\n  api_keys: [new-key]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + ".missing", ""} {
		changes, err := ReloadConfig(engine, candidate, zerolog.Nop())
		if err == nil || !strings.Contains(err.Error(), "restart") || len(changes) != 0 {
			t.Fatalf("expected restart: %v %v", changes, err)
		}
		if cfg.Server.APIKeys[0] != "old-key" || cfg.Logging.Level == "debug" {
			t.Fatal("partial mutation")
		}
	}
}
