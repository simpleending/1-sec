package core

import (
	"fmt"
	"github.com/rs/zerolog"
)

// ReloadConfig refuses partial activation. Runtime consumers retain startup
// objects; changes must be activated together by restarting the engine.
func ReloadConfig(engine *Engine, configPath string, logger zerolog.Logger) ([]string, error) {
	return nil, fmt.Errorf("configuration changes require an engine restart; no configuration changes applied")
}
