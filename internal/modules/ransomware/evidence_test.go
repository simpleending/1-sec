package ransomware

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

func TestJSONProcessIDKeepsExactRansomwareAttribution(t *testing.T) {
	for _, literal := range []string{"4242", "4242.0", "4.242e3", "4242.00000000000000001"} {
		e, err := core.UnmarshalSecurityEvent([]byte(fmt.Sprintf(`{"type":"file_modified","details":{"process_id":%s}}`, literal)))
		if err != nil {
			t.Fatal(err)
		}
		want := "4242"
		if literal == "4242.00000000000000001" {
			want = ""
		}
		if got := processID(e); got != want {
			t.Fatalf("PID %s became %q, want %q", literal, got, want)
		}
	}
}

func TestFileActivityEvidence(t *testing.T) {
	t.Run("one noisy file cannot contaminate many ordinary files", func(t *testing.T) {
		ft := NewFileActivityTracker(5)
		for n := 0; n < 100; n++ {
			ft.RecordModification("writer", "/archive.zip", 7.9)
		}
		var result ActivityResult
		for n := 0; n < 5; n++ {
			result = ft.RecordModification("writer", fmt.Sprintf("/text/%d", n), 3)
		}
		if result.MassEncryption {
			t.Fatal("repeated samples of one file triggered mass encryption")
		}
	})
	t.Run("continuous activity expires", func(t *testing.T) {
		ft := NewFileActivityTracker(5)
		ft.RecordModification("writer", "/old", 7.9)
		ft.processActivity["writer"].firstSeen = time.Now().Add(-6 * time.Minute)
		if got := ft.RecordModification("writer", "/new", 7.9); got.FileCount != 1 {
			t.Fatalf("stale files remained in active window: %+v", got)
		}
	})
}

func TestRansomwareDetectionReachesResponsePolicy(t *testing.T) {
	for _, baseline := range []bool{false, true} {
		t.Run(fmt.Sprintf("entropy_baseline_%t", baseline), func(t *testing.T) {
			cfg := core.DefaultConfig()
			cfg.Enforcement = &core.EnforcementConfig{
				Enabled: true, DryRun: true,
				Policies: map[string]core.ResponsePolicyYAML{
					ModuleName: {Enabled: true, MinSeverity: "CRITICAL", Actions: []core.ResponseRuleYAML{
						{Action: "kill_process", MinSeverity: "CRITICAL"},
					}},
				},
			}
			cp := makeCapturingPipeline()
			response := core.NewResponseEngine(zerolog.Nop(), nil, cp.pipeline, cfg)
			response.Start(context.Background())
			defer response.Stop()
			i := startedModuleWithPipeline(t, cp)
			defer i.Stop()
			for n := 0; n < 5; n++ {
				ev := core.NewSecurityEvent("trusted-local-collector", "file_modified", core.SeverityInfo, "write")
				ev.Details["path"] = fmt.Sprintf("/data/%d", n)
				ev.Details["process_name"] = "encryptor"
				ev.Details["process_id"] = 4242
				ev.Details["entropy"] = 7.9
				if baseline {
					ev.Details["entropy_before"] = 4.1
				}
				i.HandleEvent(ev)
			}
			records := response.GetRecords(100, ModuleName)
			if !baseline {
				if len(records) != 0 {
					t.Fatal("absolute entropy alone triggered critical response")
				}
				return
			}
			if len(records) != 1 || records[0].Target != "4242" || records[0].Status != core.ActionStatusDryRun {
				t.Fatalf("expected policy-controlled dry-run against exact PID: %+v", records)
			}
		})
	}
}

func TestRenameUsesEventTypeAndDistinctFiles(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()
	for n := 0; n < 10; n++ {
		ev := core.NewSecurityEvent("test", "file_renamed", core.SeverityInfo, "rename")
		ev.Details["process_id"] = 123
		ev.Details["path"] = "/data/same"
		i.HandleEvent(ev)
	}
	if cp.hasAlertType("rapid_rename") {
		t.Fatal("same file counted repeatedly")
	}
	for n := 0; n < 6; n++ {
		ev := core.NewSecurityEvent("test", "file_renamed", core.SeverityInfo, "rename")
		ev.Details["process_id"] = 123
		ev.Details["path"] = fmt.Sprintf("/data/%d", n)
		i.HandleEvent(ev)
	}
	if !cp.hasAlertType("rapid_rename") {
		t.Fatal("real rename events with unfamiliar extensions were missed")
	}
}

func TestRansomwareProcessIsolationAndResponseEvidence(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()
	for n := 0; n < 6; n++ {
		ev := core.NewSecurityEvent("collector", "file_modified", core.SeverityInfo, "write")
		ev.SourceIP = "10.0.0.1"
		ev.Details["process_name"] = "writer"
		ev.Details["process_id"] = n%2 + 40
		ev.Details["path"] = fmt.Sprintf("/data/%d", n)
		ev.Details["entropy"] = 7.4
		i.HandleEvent(ev)
	}
	if cp.hasAlertType("mass_encryption") {
		t.Fatal("different PIDs were pooled by process name")
	}
	for n := 0; n < 5; n++ {
		ev := core.NewSecurityEvent("collector", "file_modified", core.SeverityInfo, "write")
		ev.SourceIP = "10.0.0.2"
		ev.Details["process_name"] = "writer"
		ev.Details["process_id"] = float64(40)
		ev.Details["path"] = fmt.Sprintf("/data/%d", n)
		ev.Details["entropy"] = 7.4
		i.HandleEvent(ev)
	}
	if !cp.hasAlertType("mass_encryption") {
		t.Fatal("distinct high-entropy files did not trigger detection")
	}
	for _, alert := range cp.alerts {
		if alert.Type == "mass_encryption" && (alert.Metadata["process_id"] != "40" || alert.Metadata["process_name"] != "writer" || alert.Metadata["affected_path"] != "/data/4" || alert.Metadata["file_path"] != nil) {
			t.Fatalf("response target was lost: %+v", alert.Metadata)
		}
	}
}

func TestOrdinaryDiskWriteIsNotAWiper(t *testing.T) {
	for _, details := range []map[string]interface{}{
		{"target": "/data/database", "bytes_written": 4096},
		{"target": "/data/database", "offset": 0, "bytes_written": 4096},
		{"target": "/dev/sda", "bytes_written": 4096},
		{"target": "/dev/null", "offset": 0, "bytes_written": 4096},
		{"target": "/dev/urandom", "offset": 0, "bytes_written": 4096},
	} {
		cp := makeCapturingPipeline()
		i := startedModuleWithPipeline(t, cp)
		ev := core.NewSecurityEvent("collector", "disk_write", core.SeverityInfo, "write")
		ev.Details = details
		i.HandleEvent(ev)
		i.Stop()
		if cp.count() != 0 {
			t.Fatalf("ordinary or incomplete write was labeled destructive: %+v", details)
		}
	}
}
