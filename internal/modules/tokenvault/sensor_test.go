package tokenvault

import (
	"context"
	"strings"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

func TestTokenVaultPreservesSensorRevocationBoundary(t *testing.T) {
	r, err := core.NewSensorRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	info, _, err := r.Enroll(core.SensorSpec{ID: "oauth-sensor", HostID: "127.0.0.1", AllowLocalResponse: true, Scopes: []core.SensorScope{{Module: "endpoint", Type: "oauth_grant"}}})
	if err != nil {
		t.Fatal(err)
	}
	e := core.NewSecurityEvent("endpoint", "oauth_grant", core.SeverityMedium, "observed grant")
	e.Details["username"] = "test-user"
	e.Details["scopes"] = strings.Repeat("scope ", 12)
	if err := r.BindEvent(info, e); err != nil {
		t.Fatal(err)
	}
	p := core.NewAlertPipeline(zerolog.Nop(), 10)
	cfg := core.DefaultConfig()
	tv := NewTokenVault(context.Background(), p, cfg, zerolog.Nop())
	tv.HandleEvent(e)
	alerts := p.GetAlerts(core.SeverityInfo, 10)
	if len(alerts) != 1 || alerts[0].Sensor == nil {
		t.Fatal("Token Vault lost sensor identity")
	}
	cfg.Enforcement = &core.EnforcementConfig{Enabled: true, DryRun: true, Policies: map[string]core.ResponsePolicyYAML{alertModule: {Enabled: true, Actions: []core.ResponseRuleYAML{{Action: "disable_user"}}}}}
	re := core.NewResponseEngine(zerolog.Nop(), nil, core.NewAlertPipeline(zerolog.Nop(), 10), cfg)
	re.Start(context.Background())
	defer re.Stop()
	re.HandleAlertForTest(alerts[0])
	if len(re.GetRecords(10, "")) != 1 {
		t.Fatal("valid local sensor grant failed dry-run control")
	}
	if err := r.Revoke(info.ID); err != nil {
		t.Fatal(err)
	}
	re.HandleAlertForTest(alerts[0])
	if len(re.GetRecords(10, "")) != 1 {
		t.Fatal("revoked Token Vault sensor retained containment authority")
	}
}
