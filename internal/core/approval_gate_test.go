package core

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func makeAlertForApproval() *Alert {
	return &Alert{
		ID:       uuid.New().String(),
		Module:   "test_module",
		Severity: SeverityCritical,
		Title:    "Test Alert",
		Metadata: map[string]interface{}{"source_ip": "10.0.0.1"},
	}
}

func TestApprovalNotificationKeepsSubmittedSnapshot(t *testing.T) {
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true
	ag := NewApprovalGate(zerolog.Nop(), cfg)
	defer ag.Stop()
	release := make(chan struct{})
	done := make(chan *PendingApproval, 1)
	ag.SetNotifyFunc(func(pa *PendingApproval) { <-release; done <- pa })
	ag.AddHandler(func(pa *PendingApproval) { pa.Target = "executed-target" })
	id := ag.Submit(makeAlertForApproval(), ResponseRule{Action: ActionKillProcess}, "submitted-target")
	if _, err := ag.Approve(id, "operator"); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	select {
	case notification := <-done:
		if notification.Target != "submitted-target" || notification.Status != "pending" {
			t.Fatalf("notification observed a mutated approval: %+v", notification)
		}
	case <-time.After(time.Second):
		t.Fatal("notification not delivered")
	}
}

func TestApprovalGate_RequiresApproval(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	if !ag.RequiresApproval(ActionKillProcess) {
		t.Error("expected kill_process to require approval")
	}
	if !ag.RequiresApproval(ActionQuarantineFile) {
		t.Error("expected quarantine_file to require approval")
	}
	if ag.RequiresApproval(ActionWebhook) {
		t.Error("expected webhook to NOT require approval")
	}
	if ag.RequiresApproval(ActionLog) {
		t.Error("expected log_only to NOT require approval")
	}
}

func TestApprovalGate_DisabledNoApproval(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = false

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	if ag.RequiresApproval(ActionKillProcess) {
		t.Error("expected no approval required when disabled")
	}
}

func TestApprovalGate_SubmitAndApprove(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	var executed atomic.Int32
	ag.AddHandler(func(approval *PendingApproval) {
		executed.Add(1)
	})

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess, Params: map[string]string{}}

	id := ag.Submit(alert, rule, "pid:1234")

	pending := ag.GetPending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].ID != id {
		t.Error("pending ID mismatch")
	}

	pa, err := ag.Approve(id, "admin@example.com")
	if err != nil {
		t.Fatalf("approve failed: %v", err)
	}
	if pa.Status != "approved" {
		t.Errorf("expected status=approved, got %s", pa.Status)
	}
	if pa.DecidedBy != "admin@example.com" {
		t.Errorf("expected decidedBy=admin@example.com, got %s", pa.DecidedBy)
	}

	if executed.Load() != 1 {
		t.Error("expected handler to be called on approve")
	}

	// Should be gone from pending
	pending = ag.GetPending()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending after approve, got %d", len(pending))
	}
}

func TestApprovalGate_SubmitAndReject(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	var executed atomic.Int32
	ag.AddHandler(func(approval *PendingApproval) {
		executed.Add(1)
	})

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionDisableUser}

	id := ag.Submit(alert, rule, "user:jdoe")

	pa, err := ag.Reject(id, "soc-lead")
	if err != nil {
		t.Fatalf("reject failed: %v", err)
	}
	if pa.Status != "rejected" {
		t.Errorf("expected status=rejected, got %s", pa.Status)
	}

	// Handler should NOT be called on reject
	if executed.Load() != 0 {
		t.Error("handler should not be called on reject")
	}
}

func TestApprovalGate_DoubleApproveError(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess}
	id := ag.Submit(alert, rule, "target")

	_, err := ag.Approve(id, "admin")
	if err != nil {
		t.Fatal(err)
	}

	// Second approve should fail (not found since it was removed)
	_, err = ag.Approve(id, "admin")
	if err == nil {
		t.Error("expected error on double approve")
	}
}

func TestApprovalGate_NotFoundError(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	_, err := ag.Approve("nonexistent-id", "admin")
	if err == nil {
		t.Error("expected error for nonexistent ID")
	}
}

func TestApprovalGate_MaxPendingEviction(t *testing.T) {
	logger := zerolog.Nop()
	cfg := ApprovalGateConfig{
		Enabled:         true,
		RequireApproval: []string{"kill_process"},
		TTL:             10 * time.Minute,
		MaxPending:      2,
	}

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess}

	ag.Submit(alert, rule, "target1")
	ag.Submit(alert, rule, "target2")
	// This should evict the oldest
	ag.Submit(alert, rule, "target3")

	pending := ag.GetPending()
	if len(pending) != 2 {
		t.Errorf("expected 2 pending after eviction, got %d", len(pending))
	}
}

func TestApprovalGate_Stats(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	stats := ag.Stats()
	if stats["enabled"] != true {
		t.Error("expected enabled=true")
	}
	if stats["pending_count"].(int) != 0 {
		t.Error("expected 0 pending")
	}
}

func TestApprovalGate_History(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess}

	id1 := ag.Submit(alert, rule, "target1")
	id2 := ag.Submit(alert, rule, "target2")

	ag.Approve(id1, "admin")
	ag.Reject(id2, "admin")

	history := ag.GetHistory(10)
	if len(history) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(history))
	}
}

// ─── RequiresApprovalForRule tests ───────────────────────────────────────────

func TestApprovalGate_RequiresApprovalForRule_SkipApproval(t *testing.T) {
	logger := zerolog.Nop()
	cfg := DefaultApprovalGateConfig()
	cfg.Enabled = true

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	// kill_process normally requires approval
	if !ag.RequiresApprovalForRule(ActionKillProcess, SeverityHigh, false) {
		t.Error("expected kill_process to require approval without skip flag")
	}

	// With skip_approval=true, it should bypass
	if ag.RequiresApprovalForRule(ActionKillProcess, SeverityHigh, true) {
		t.Error("expected kill_process to skip approval with skip_approval=true")
	}
}

func TestApprovalGate_RequiresApprovalForRule_AutoApproveAbove(t *testing.T) {
	logger := zerolog.Nop()
	cfg := ApprovalGateConfig{
		Enabled:          true,
		RequireApproval:  []string{"kill_process", "quarantine_file"},
		AutoApproveAbove: "CRITICAL",
		TTL:              30 * time.Minute,
		MaxPending:       100,
	}

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	// CRITICAL severity should auto-approve (bypass gate)
	if ag.RequiresApprovalForRule(ActionKillProcess, SeverityCritical, false) {
		t.Error("expected CRITICAL to auto-approve when threshold is CRITICAL")
	}

	// HIGH severity should still require approval
	if !ag.RequiresApprovalForRule(ActionKillProcess, SeverityHigh, false) {
		t.Error("expected HIGH to still require approval when threshold is CRITICAL")
	}

	// MEDIUM should still require approval
	if !ag.RequiresApprovalForRule(ActionQuarantineFile, SeverityMedium, false) {
		t.Error("expected MEDIUM to still require approval when threshold is CRITICAL")
	}
}

func TestApprovalGate_RequiresApprovalForRule_AutoApproveHigh(t *testing.T) {
	logger := zerolog.Nop()
	cfg := ApprovalGateConfig{
		Enabled:          true,
		RequireApproval:  []string{"kill_process"},
		AutoApproveAbove: "HIGH",
		TTL:              30 * time.Minute,
		MaxPending:       100,
	}

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	// CRITICAL >= HIGH, should auto-approve
	if ag.RequiresApprovalForRule(ActionKillProcess, SeverityCritical, false) {
		t.Error("expected CRITICAL to auto-approve when threshold is HIGH")
	}

	// HIGH >= HIGH, should auto-approve
	if ag.RequiresApprovalForRule(ActionKillProcess, SeverityHigh, false) {
		t.Error("expected HIGH to auto-approve when threshold is HIGH")
	}

	// MEDIUM < HIGH, should still require approval
	if !ag.RequiresApprovalForRule(ActionKillProcess, SeverityMedium, false) {
		t.Error("expected MEDIUM to require approval when threshold is HIGH")
	}
}

func TestApprovalGate_RequiresApprovalForRule_EmptyAutoApprove(t *testing.T) {
	logger := zerolog.Nop()
	cfg := ApprovalGateConfig{
		Enabled:          true,
		RequireApproval:  []string{"kill_process"},
		AutoApproveAbove: "", // disabled
		TTL:              30 * time.Minute,
		MaxPending:       100,
	}

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	// Even CRITICAL should require approval when auto_approve_above is empty
	if !ag.RequiresApprovalForRule(ActionKillProcess, SeverityCritical, false) {
		t.Error("expected CRITICAL to require approval when auto_approve_above is empty")
	}
}

func TestApprovalGate_RequiresApprovalForRule_Disabled(t *testing.T) {
	logger := zerolog.Nop()
	cfg := ApprovalGateConfig{
		Enabled:          false,
		RequireApproval:  []string{"kill_process"},
		AutoApproveAbove: "HIGH",
	}

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	// Gate disabled — nothing requires approval
	if ag.RequiresApprovalForRule(ActionKillProcess, SeverityLow, false) {
		t.Error("expected no approval required when gate is disabled")
	}
}

func TestApprovalGate_RequiresApprovalForRule_ActionNotInList(t *testing.T) {
	logger := zerolog.Nop()
	cfg := ApprovalGateConfig{
		Enabled:          true,
		RequireApproval:  []string{"kill_process"},
		AutoApproveAbove: "CRITICAL",
		TTL:              30 * time.Minute,
		MaxPending:       100,
	}

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	// webhook is not in require_approval list
	if ag.RequiresApprovalForRule(ActionWebhook, SeverityLow, false) {
		t.Error("expected webhook to not require approval (not in list)")
	}
}

func TestApprovalGate_RequiresApprovalForRule_SkipOverridesAutoApprove(t *testing.T) {
	logger := zerolog.Nop()
	cfg := ApprovalGateConfig{
		Enabled:          true,
		RequireApproval:  []string{"kill_process"},
		AutoApproveAbove: "", // no auto-approve
		TTL:              30 * time.Minute,
		MaxPending:       100,
	}

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	// LOW severity, no auto-approve, but skip_approval=true should bypass
	if ag.RequiresApprovalForRule(ActionKillProcess, SeverityLow, true) {
		t.Error("expected skip_approval to bypass even without auto_approve_above")
	}
}

func TestApprovalGate_Stats_IncludesAutoApproveAbove(t *testing.T) {
	logger := zerolog.Nop()
	cfg := ApprovalGateConfig{
		Enabled:          true,
		RequireApproval:  []string{"kill_process"},
		AutoApproveAbove: "HIGH",
		TTL:              30 * time.Minute,
		MaxPending:       100,
	}

	ag := NewApprovalGate(logger, cfg)
	defer ag.Stop()

	stats := ag.Stats()
	if stats["auto_approve_above"] != "HIGH" {
		t.Errorf("expected auto_approve_above=HIGH in stats, got %v", stats["auto_approve_above"])
	}
}
