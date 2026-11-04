package ingest

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	runtimewatcher "github.com/1sec-project/1sec/internal/modules/runtime"
	"github.com/rs/zerolog"
)

func TestSyslogClaimsStayObservableWithoutProcessAuthority(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Bus.Port, cfg.Bus.DataDir = -1, t.TempDir()
	cfg.Logging.Level, cfg.Alerts.EnableConsole = "error", false
	cfg.Modules[runtimewatcher.ModuleName] = core.ModuleConfig{Enabled: true, Settings: map[string]interface{}{"realtime_enabled": false}}
	cfg.Enforcement = &core.EnforcementConfig{Enabled: true, DryRun: true, Preset: core.PresetVPSAgent}
	engine, err := core.NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Registry.Register(runtimewatcher.New()); err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	defer engine.Shutdown()
	s := NewSyslogServer(&cfg.Syslog, engine.Bus, zerolog.Nop())
	hostname, _ := os.Hostname()
	for i, host := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", hostname} {
		for _, raw := range []string{
			fmt.Sprintf("<14>1 2026-11-05T00:00:00Z %s msbuild %d - process started", host, 4242+i),
			fmt.Sprintf("<14>Nov  5 00:00:00 %s MSBUILD.exe[%d]: process started", host, 5242+i),
		} {
			before := len(engine.ResponseEngine.GetRecords(1000, runtimewatcher.ModuleName))
			s.processMessage(raw, "198.51.100.8")
			deadline := time.Now().Add(3 * time.Second)
			found := false
			for time.Now().Before(deadline) && !found {
				records := engine.ResponseEngine.GetRecords(1000, runtimewatcher.ModuleName)
				if len(records) > before {
					for _, record := range records[:len(records)-before] {
						if record.Action == core.ActionKillProcess {
							found = true
							if record.Status != core.ActionStatusSkipped {
								t.Fatalf("forged syslog acquired process authority: %+v", record)
							}
						}
					}
				}
				if !found {
					time.Sleep(10 * time.Millisecond)
				}
			}
			if !found {
				t.Fatal("syslog detection disappeared instead of recording a denied response")
			}
		}
	}
	if engine.Pipeline.Count() == 0 {
		t.Fatal("lost syslog detections")
	}
}
