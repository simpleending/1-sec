package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func runtimeActorAlert() *Alert {
	a := NewAlert(NewSecurityEvent("runtime_watcher", "reverse_shell", SeverityCritical, "reverse shell observed"), "reverse shell", "test")
	a.Metadata["runtime_event_type"] = "process_exec"
	a.Metadata["runtime_process_evidence"] = true
	a.Metadata["process_id"] = "4242"
	a.Metadata["process_host"] = "127.0.0.1"
	a.Metadata["source_ip"] = "192.0.2.20"
	return a
}

func TestRuntimeContainmentBoundaryAcrossResponsePaths(t *testing.T) {
	for _, unsafe := range []string{"valid", "file-only", "victim", "missing-host", "remote", "conflicting-host", "container", "name-only", "no-evidence", "fractional", "init"} {
		t.Run(unsafe, func(t *testing.T) {
			a := runtimeActorAlert()
			switch unsafe {
			case "file-only":
				a.Type = "sensitive_file_change"
			case "victim":
				a.Type = "memory_injection"
				a.Metadata["runtime_event_type"] = "file_modified"
			case "missing-host":
				delete(a.Metadata, "process_host")
			case "remote":
				a.Metadata["process_host"] = "192.0.2.44"
			case "conflicting-host":
				a.Metadata["syslog_hostname"] = "remote.invalid"
			case "container":
				a.Metadata["container_id"] = "container-1"
			case "name-only":
				delete(a.Metadata, "process_id")
				a.Metadata["process_name"] = "bash"
			case "no-evidence":
				delete(a.Metadata, "runtime_process_evidence")
			case "fractional":
				a.Metadata["process_id"] = "4242.5"
			case "init":
				a.Metadata["process_id"] = "1"
			}
			// Deliberately forge a file target: neither policy nor human approval
			// can turn a victim/configuration path into a runtime artifact.
			a.Metadata["file_path"] = "/etc/shadow"
			cfg := enforcementConfig("", false)
			cfg.Enforcement.ApprovalGate = DefaultApprovalGateConfig()
			cfg.Enforcement.ApprovalGate.Enabled = true
			re := testResponseEngine(t, cfg)
			defer re.Stop()
			kill, quarantine := &mockExecutor{}, &mockExecutor{}
			re.executors[ActionKillProcess], re.executors[ActionQuarantineFile] = kill, quarantine
			re.policies[a.Module] = &ResponsePolicy{Enabled: true, MinSeverity: SeverityInfo, Actions: []ResponseRule{{Action: ActionKillProcess, SkipApproval: true}, {Action: ActionQuarantineFile, SkipApproval: true}}}
			re.handleAlert(a)
			want := 0
			if unsafe == "valid" {
				want = 1
			}
			if kill.callCount != want || quarantine.callCount != 0 {
				t.Fatalf("normal response bypass: kill=%d quarantine=%d", kill.callCount, quarantine.callCount)
			}
			for _, action := range []ActionType{ActionKillProcess, ActionQuarantineFile} {
				id := re.ApprovalGate.Submit(a, ResponseRule{Action: action}, "4242")
				if _, err := re.ApprovalGate.Approve(id, "operator"); err != nil {
					t.Fatal(err)
				}
			}
			if kill.callCount != 2*want || quarantine.callCount != 0 {
				t.Fatal("approval bypassed runtime evidence")
			}
			ce := NewChainExecutor(zerolog.Nop(), re.executors)
			if err := ce.RegisterChain(&ActionChain{Name: "runtime", Steps: []ChainStep{{Name: "kill", Action: ActionKillProcess, OnSuccess: "quarantine", OnFailure: "quarantine"}, {Name: "quarantine", Action: ActionQuarantineFile}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := ce.Execute(context.Background(), "runtime", a, zerolog.Nop()); err != nil {
				t.Fatal(err)
			}
			if kill.callCount != 3*want || quarantine.callCount != 0 {
				t.Fatal("chain bypassed runtime evidence")
			}
		})
	}
}

func TestRuntimeExecutorsRejectUnsafeTargetsBeforeSideEffects(t *testing.T) {
	a := runtimeActorAlert()
	a.Type = "sensitive_file_change"
	a.Metadata["file_path"] = "/does/not/exist"
	if _, _, err := (&KillProcessExecutor{}).Execute(context.Background(), a, ResponseRule{}, zerolog.Nop()); err == nil || !strings.Contains(err.Error(), "eligible") {
		t.Fatalf("invalid runtime process reached executor: %v", err)
	}
	if _, _, err := (&QuarantineFileExecutor{}).Execute(context.Background(), a, ResponseRule{}, zerolog.Nop()); err == nil || !strings.Contains(err.Error(), "malicious artifact") {
		t.Fatalf("runtime path reached filesystem: %v", err)
	}
	a = runtimeActorAlert()
	a.Metadata["process_name"] = "/path/with spaces/bash" // Descriptive name must not invalidate a valid PID.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if target, _, err := (&KillProcessExecutor{}).Execute(ctx, a, ResponseRule{}, zerolog.Nop()); target != "4242" || err == nil || strings.Contains(err.Error(), "invalid process name") {
		t.Fatalf("valid PID did not reach canceled command boundary: target=%q err=%v", target, err)
	}
}

func TestRuntimePresetsDoNotQuarantineAffectedFiles(t *testing.T) {
	for _, preset := range ValidPresets() {
		for _, action := range GetPresetPolicies(preset)["runtime_watcher"].Actions {
			if action.Action == "quarantine_file" {
				t.Fatalf("%s grants runtime artifact authority", preset)
			}
		}
	}
}

func TestRuntimeCooldownSeparatesProcessesOnSameSourceIP(t *testing.T) {
	cfg := enforcementConfig("", false)
	re := testResponseEngine(t, cfg)
	defer re.Stop()
	mock := &mockExecutor{}
	re.executors[ActionKillProcess] = mock
	re.policies["runtime_watcher"] = &ResponsePolicy{Enabled: true, Cooldown: time.Minute, Actions: []ResponseRule{{Action: ActionKillProcess}}}
	for _, pid := range []string{"4242", "4243", "4242"} {
		a := runtimeActorAlert()
		a.Metadata["process_id"] = pid
		re.handleAlert(a)
	}
	if mock.callCount != 2 {
		t.Fatalf("cooldown pooled independent process IDs or missed a replay: %d", mock.callCount)
	}
}

func TestProcessIdentifiersSurviveJSONWithoutRounding(t *testing.T) {
	for _, input := range []string{
		`{"type":"process_exec","details":{"pid":4242,"entropy":7.4}}`,
		`{"type":"process_exec","details":{"pid":4242.00000000000000001,"entropy":7.4}}`,
		`{"type":"memory_injection","details":{"source_pid":4242,"target_pid":9001}}`,
	} {
		var event SecurityEvent
		if err := json.Unmarshal([]byte(input), &event); err != nil {
			t.Fatal(err)
		}
		key := "pid"
		if event.Type == "memory_injection" {
			key = "source_pid"
		}
		if _, ok := event.Details[key].(json.Number); !ok {
			t.Fatalf("PID rounded during decode: %#v", event.Details[key])
		}
		if event.Type == "process_exec" {
			if _, ok := event.Details["entropy"].(float64); !ok {
				t.Fatal("changed unrelated numeric telemetry")
			}
		}
		wire, err := event.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		roundTrip, err := UnmarshalSecurityEvent(wire)
		if err != nil {
			t.Fatal(err)
		}
		if roundTrip.Details[key] != event.Details[key] {
			t.Fatal("broker round trip changed exact PID")
		}
	}
}
