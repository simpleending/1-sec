package iot

import (
	"context"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

func TestManagementPolicyTelemetry(t *testing.T) {
	for _, tc := range []struct {
		name, kind, ip, operator string
		verified                 interface{}
		deny                     bool
	}{
		{"unknown source", "management_access", "198.51.100.23", "engineer", true, true},
		{"unknown operator", "management_access", "10.20.0.7", "attacker", true, true},
		{"unverified", "management_access", "10.20.0.7", "engineer", false, true},
		{"string verification", "management_access", "10.20.0.7", "engineer", "true", true},
		{"authorized", "management_access", "10.20.0.7", "engineer", true, false},
		{"OT command unknown source", "ot_command", "198.51.100.23", "engineer", true, true},
		{"OT command authorized", "ot_command", "10.20.0.7", "engineer", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := makeCapturingPipeline()
			cfg := core.DefaultConfig()
			cfg.ManagementAccess = core.ManagementAccessConfig{AllowedSources: []string{"10.20.0.0/24"}, AllowedOperators: []string{"engineer"}}
			s := New()
			if err := s.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Stop() })
			if err := sRegistryRoute(s, tc.kind, tc.ip, tc.operator, tc.verified); err != nil {
				t.Fatal(err)
			}
			if cp.hasAlertType("management_access_denied") != tc.deny {
				t.Fatalf("wrong alerts: %v", cp.alertTitles())
			}
		})
	}
}

func sRegistryRoute(s *Shield, kind, ip, operator string, verified interface{}) error {
	r := core.NewModuleRegistry(zerolog.Nop())
	if err := r.Register(s); err != nil {
		return err
	}
	e := core.NewSecurityEvent("trusted_gateway", kind, core.SeverityInfo, "access observation")
	e.SourceIP = ip
	e.Details["target"] = "device-17"
	e.Details["operator"] = operator
	e.Details["identity_verified"] = verified
	e.Details["action"] = "configure"
	e.Details["command"] = "write"
	e.Details["protocol"] = "modbus"
	r.RouteEvent(e, zerolog.Nop())
	return nil
}

func TestPublicManagementExposure(t *testing.T) {
	for _, exposed := range []interface{}{true, false, "true"} {
		cp := makeCapturingPipeline()
		s := startedModuleWithPipeline(t, cp)
		e := core.NewSecurityEvent("inventory", "management_exposure", core.SeverityInfo, "exposure")
		e.Details["target"] = "device-17"
		e.Details["publicly_reachable"] = exposed
		if err := s.HandleEvent(e); err != nil {
			t.Fatal(err)
		}
		_ = s.Stop()
		want, _ := exposed.(bool)
		if cp.hasAlertType("management_exposure") != want {
			t.Fatalf("incorrect exposure alert for %v", exposed)
		}
	}
}

func TestSegmentationRejectsInternetManagementAccess(t *testing.T) {
	s := NewSegmentationEnforcer(nil)
	for _, zone := range []string{"ot", "scada", "plc", "safety", "management", "iot"} {
		v := s.Check(" INTERNET ", " "+zone+" ", "198.51.100.23", "10.20.0.7", 443, "https")
		if v == nil {
			t.Errorf("internet->%s unexpectedly allowed", zone)
		}
	}
	if v := s.Check(" OT ", "ot", "10.20.0.7", "10.20.0.8", 502, "modbus"); v != nil {
		t.Fatal("same normalized zone should remain unchanged")
	}
}
