package core

import (
	"fmt"
	"os"
	"runtime"
)

func cloudInstanceID(cfg CloudConfig) string {
	if cfg.InstanceID != "" {
		return cfg.InstanceID
	}
	hostname, _ := os.Hostname()
	return fmt.Sprintf("i-%s-%s", hostname, runtime.GOARCH)
}
