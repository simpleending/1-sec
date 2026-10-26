package core_test

import (
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/1sec-project/1sec/internal/modules/auth"
	"github.com/1sec-project/1sec/internal/modules/injection"
)

func TestChangedBodyReachesDetectionThroughEngineDedup(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Bus.Port = -1
	cfg.Bus.DataDir = t.TempDir()
	cfg.Logging.Level = "error"
	cfg.RustEngine.Enabled = false
	cfg.Alerts.EnableConsole = false
	cfg.Enforcement = nil
	engine, err := core.NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Registry.Register(injection.New()); err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	defer engine.Shutdown()
	for _, body := range []string{"ordinary request", "' UNION SELECT password FROM users--"} {
		e := core.NewSecurityEvent("gateway", "http_request", core.SeverityInfo, "HTTP request")
		e.SourceIP = "8.8.8.8"
		e.Details["body"] = body
		if err := engine.Bus.PublishEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, alert := range engine.Pipeline.GetAlerts(core.SeverityInfo, 100) {
			if alert.Module == "injection_shield" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("changed request body was discarded before injection detection")
}

func TestIndependentMFAAttemptsReachRateDetection(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Bus.Port = -1
	cfg.Bus.DataDir = t.TempDir()
	cfg.Logging.Level = "error"
	cfg.RustEngine.Enabled = false
	cfg.Alerts.EnableConsole = false
	cfg.Enforcement = nil
	engine, err := core.NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Registry.Register(auth.New()); err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	defer engine.Shutdown()
	for i := 0; i < 6; i++ {
		e := core.NewSecurityEvent("identity", "mfa_attempt", core.SeverityInfo, "failed push")
		e.SourceIP = "8.8.8.8"
		e.Details["success"], e.Details["method"] = "false", "push"
		if err := engine.Bus.PublishEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, alert := range engine.Pipeline.GetAlerts(core.SeverityInfo, 100) {
			if alert.Module == auth.ModuleName && alert.Title == "MFA Bypass Attempt" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("independent MFA attempts disappeared before rate detection")
}
