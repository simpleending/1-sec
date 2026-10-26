package core

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
)

func TestResponseRequiresActionEvidence(t *testing.T) {
	for _, kind := range []string{"tracking_capacity", "escalation", "data_exfiltration", "compound_ransomware_prep", "mass_encryption"} {
		t.Run(kind, func(t *testing.T) {
			cfg := enforcementConfig("", false)
			re := testResponseEngine(t, cfg)
			defer re.Stop()
			a := testAlertWithIP("ransomware", "127.0.0.1", SeverityCritical)
			a.Type = kind
			a.Metadata["process_id"], a.Metadata["file_path"] = "4242", "/data/victim"
			p := &ResponsePolicy{Enabled: true, MinSeverity: SeverityInfo, MaxActionsPerMin: 100}
			mocks := make(map[ActionType]*mockExecutor)
			for _, action := range []ActionType{ActionBlockIP, ActionKillProcess, ActionQuarantineFile, ActionDropConnection, ActionDisableUser, ActionCommand, ActionLog, ActionWebhook} {
				m := &mockExecutor{}
				mocks[action], re.executors[action] = m, m
				p.Actions = append(p.Actions, ResponseRule{Action: action, MinSeverity: SeverityInfo})
			}
			re.policies[a.Module] = p
			re.handleAlert(a)
			for action, m := range mocks {
				want := 1
				if action == ActionQuarantineFile {
					want = 0
				}
				if (kind == "tracking_capacity" || kind == "escalation") && action != ActionLog && action != ActionWebhook {
					want = 0
				}
				if (kind == "data_exfiltration" || kind == "compound_ransomware_prep") && (action == ActionKillProcess || action == ActionQuarantineFile) {
					want = 0
				}
				if m.callCount != want {
					t.Errorf("%s executed %d times; want %d", action, m.callCount, want)
				}
			}
		})
	}
}

func TestApprovedActionStillRequiresEvidence(t *testing.T) {
	cfg := enforcementConfig("", false)
	cfg.Enforcement.ApprovalGate = DefaultApprovalGateConfig()
	cfg.Enforcement.ApprovalGate.Enabled = true
	re := testResponseEngine(t, cfg)
	defer re.Stop()
	for _, kind := range []string{"tracking_capacity", "escalation", "data_exfiltration", "compound_ransomware_prep"} {
		a := testAlertWithIP("ransomware", "127.0.0.1", SeverityCritical)
		a.Type = kind
		action := ActionKillProcess
		if kind == "tracking_capacity" || kind == "escalation" {
			action = ActionCommand
		}
		m := &mockExecutor{}
		re.executors[action] = m
		id := re.ApprovalGate.Submit(a, ResponseRule{Action: action}, "target")
		if _, err := re.ApprovalGate.Approve(id, "operator"); err != nil {
			t.Fatal(err)
		}
		if m.callCount != 0 {
			t.Fatalf("approved %s bypassed evidence boundary", kind)
		}
	}
}

func TestOperationalChainBranchesCannotMutate(t *testing.T) {
	executors := make(map[ActionType]ActionExecutor)
	mocks := make(map[ActionType]*mockExecutor)
	for _, action := range []ActionType{ActionCommand, ActionKillProcess, ActionLog, ActionWebhook} {
		m := &mockExecutor{}
		mocks[action] = m
		executors[action] = m
	}
	ce := NewChainExecutor(zerolog.Nop(), executors)
	if err := ce.RegisterChain(&ActionChain{Name: "health", Steps: []ChainStep{
		{Name: "command", Action: ActionCommand, OnSuccess: "kill", OnFailure: "log"},
		{Name: "log", Action: ActionLog, OnSuccess: "kill"},
		{Name: "kill", Action: ActionKillProcess, OnFailure: "notify"},
		{Name: "notify", Action: ActionWebhook},
	}}); err != nil {
		t.Fatal(err)
	}
	a := makeAlertForChain()
	a.Type = "tracking_capacity"
	if _, err := ce.Execute(context.Background(), "health", a, zerolog.Nop()); err != nil {
		t.Fatal(err)
	}
	if mocks[ActionCommand].callCount != 0 || mocks[ActionKillProcess].callCount != 0 || mocks[ActionLog].callCount != 1 || mocks[ActionWebhook].callCount != 1 {
		t.Fatal("chain branch bypassed operational action boundary")
	}
}

func TestRansomwarePresetsDoNotQuarantineVictimFiles(t *testing.T) {
	for _, preset := range ValidPresets() {
		for _, rule := range GetPresetPolicies(preset)["ransomware"].Actions {
			if rule.Action == string(ActionQuarantineFile) {
				t.Fatalf("%s quarantines victim paths", preset)
			}
		}
	}
}
