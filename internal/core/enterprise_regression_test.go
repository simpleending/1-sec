package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestAlertStoreBoundsSmallCapacities(t *testing.T) {
	for _, capacity := range []int{1, 2, 9, 10, 11} {
		p := NewAlertPipeline(zerolog.Nop(), capacity)
		for i := 0; i < 100; i++ {
			p.Process(newTestAlert("module", "test", SeverityHigh))
		}
		if p.Count() > capacity {
			t.Errorf("capacity %d retained %d alerts", capacity, p.Count())
		}
	}
}

func TestRoutingMetricsBoundUnknownTypeCardinality(t *testing.T) {
	r := newRegistry()
	for i := 0; i < 1100; i++ {
		r.RouteEvent(NewSecurityEvent("input", fmt.Sprintf("custom_%d", i), SeverityInfo, "test"), zerolog.Nop())
	}
	metrics := r.GetMetrics()
	if len(metrics["events_by_type"].(map[string]int64)) != 1024 || metrics["event_type_overflow"].(int64) != 76 || metrics["events_routed"].(int64) != 1100 {
		t.Fatal("metrics lost bounds or total accounting", metrics)
	}
}

func TestDisabledModuleDoesNotReceiveEvents(t *testing.T) {
	r := newRegistry()
	disabled, enabled := newMockModule("disabled"), newMockModule("enabled")
	_ = r.Register(disabled)
	_ = r.Register(enabled)
	cfg := DefaultConfig()
	cfg.Modules["disabled"] = ModuleConfig{Enabled: false}
	cfg.Modules["enabled"] = ModuleConfig{Enabled: true}
	if err := r.StartAll(context.Background(), nil, nil, cfg); err != nil {
		t.Fatal(err)
	}
	r.RouteEvent(NewSecurityEvent("input", "test", SeverityInfo, "test"), zerolog.Nop())
	if len(disabled.eventsHandled) != 0 || len(enabled.eventsHandled) != 1 {
		t.Fatalf("disabled=%d enabled=%d", len(disabled.eventsHandled), len(enabled.eventsHandled))
	}
}

func TestApprovalExpiresAtDecisionBoundary(t *testing.T) {
	ag := NewApprovalGate(zerolog.Nop(), DefaultApprovalGateConfig())
	defer ag.Stop()
	called := false
	ag.AddHandler(func(*PendingApproval) { called = true })
	id := ag.Submit(newTestAlert("module", "test", SeverityCritical), ResponseRule{Action: ActionKillProcess}, "4242")
	ag.mu.Lock()
	ag.pending[id].ExpiresAt = time.Now().Add(-time.Second)
	ag.mu.Unlock()
	if _, err := ag.Approve(id, "operator"); err == nil || called {
		t.Fatal("expired approval executed before periodic cleanup")
	}
}

func TestApprovalRechecksCurrentExecutionControls(t *testing.T) {
	for _, mode := range []string{"valid", "global-dry-run", "policy-dry-run", "disabled", "rule-removed", "allowlisted", "cooldown", "rate-limit", "stopped"} {
		t.Run(mode, func(t *testing.T) {
			cfg := enforcementConfig("", false)
			cfg.Enforcement.ApprovalGate = DefaultApprovalGateConfig()
			cfg.Enforcement.ApprovalGate.Enabled = true
			re := testResponseEngine(t, cfg)
			defer re.Stop()
			a := testAlertWithIP("injection_shield", "198.51.100.8", SeverityCritical)
			rule := ResponseRule{Action: ActionBlockIP}
			policy := &ResponsePolicy{Enabled: true, Actions: []ResponseRule{rule}, MaxActionsPerMin: 100}
			re.policies[a.Module] = policy
			mock := &mockExecutor{}
			re.executors[ActionBlockIP] = mock
			id := re.ApprovalGate.Submit(a, rule, "198.51.100.8")
			switch mode {
			case "global-dry-run":
				cfg.Enforcement.SetDryRun(true)
			case "policy-dry-run":
				re.SetDryRun(a.Module, true)
			case "disabled":
				re.SetPolicyEnabled(a.Module, false)
			case "rule-removed":
				re.mu.Lock()
				policy.Actions = nil
				re.mu.Unlock()
			case "allowlisted":
				re.mu.Lock()
				policy.AllowList = []string{"198.51.100.8"}
				re.mu.Unlock()
			case "cooldown":
				re.mu.Lock()
				policy.Cooldown = time.Minute
				re.mu.Unlock()
				re.setCooldown("injection_shield:block_ip:198.51.100.8", time.Minute)
			case "rate-limit":
				re.mu.Lock()
				policy.MaxActionsPerMin = 1
				re.mu.Unlock()
				re.checkRateLimit(a.Module, 1)
			case "stopped":
				re.cancel()
			}
			if _, err := re.ApprovalGate.Approve(id, "operator"); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "valid" {
				want = 1
			}
			if mock.callCount != want {
				t.Fatalf("current control %s: executions=%d want=%d", mode, mock.callCount, want)
			}
		})
	}
}

func TestPolicySnapshotsAreDetached(t *testing.T) {
	re := testResponseEngine(t, enforcementConfig("balanced", false))
	defer re.Stop()
	original := re.GetPolicies()["injection_shield"]
	view := re.GetPolicies()["injection_shield"]
	view.Enabled = false
	view.Actions[0].Params = map[string]string{"command": "altered"}
	if got := re.GetPolicies()["injection_shield"]; got.Enabled != original.Enabled || got.Actions[0].Params["command"] != "" {
		t.Fatal("policy view mutated active controls")
	}
}

func TestApprovalHistoryIsBoundedWithoutLosingDecisionTotals(t *testing.T) {
	ag := NewApprovalGate(zerolog.Nop(), DefaultApprovalGateConfig())
	defer ag.Stop()
	for i := 0; i < approvalHistoryLimit+5; i++ {
		id := ag.Submit(newTestAlert("module", "test", SeverityHigh), ResponseRule{Action: ActionLog}, "target")
		if _, err := ag.Approve(id, "operator"); err != nil {
			t.Fatal(err)
		}
	}
	if len(ag.GetHistory(0)) != approvalHistoryLimit || ag.Stats()["total_approved"] != approvalHistoryLimit+5 {
		t.Fatal("history leaked or decision counts were lost")
	}
}
