package ransomware

import (
	"fmt"
	"math"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
)

func TestAggregateAlertsDoNotAuthorizeIncidentalProcessOrFile(t *testing.T) {
	for _, kind := range []string{"data_exfiltration", "compound_ransomware_prep"} {
		t.Run(kind, func(t *testing.T) {
			cp := makeCapturingPipeline()
			i := startedModuleWithPipeline(t, cp)
			defer i.Stop()
			e := core.NewSecurityEvent("collector", "network_egress", core.SeverityInfo, "egress")
			e.SourceIP = "127.0.0.1"
			e.Details["process_id"], e.Details["process_name"], e.Details["path"] = 4242, "innocent", "/data/victim"
			if kind == "data_exfiltration" {
				i.exfilTracker.Record(e.SourceIP, "destination", i.exfilTracker.threshold)
				e.Details["bytes"] = 1
				i.HandleEvent(e)
			} else {
				i.backupTracker.RecordEvent(e.SourceIP, "vss_delete")
				i.backupTracker.RecordEvent(e.SourceIP, "backup_destroy")
				i.checkCompoundAttack(e)
			}
			found := false
			for _, a := range cp.alerts {
				if a.Type == kind {
					found = true
					for _, key := range []string{"process_id", "process_name", "file_path"} {
						if a.Metadata[key] != nil {
							t.Errorf("aggregate carried %s authority", key)
						}
					}
				}
			}
			if !found {
				t.Fatal("aggregate alert missing")
			}
		})
	}
}

func TestVictimFileDoesNotBecomeQuarantineTarget(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()
	e := core.NewSecurityEvent("collector", "file_modified", core.SeverityInfo, "write")
	e.Details["path"] = "/data/victim.locked"
	e.Details["process_id"] = 4242
	i.HandleEvent(e)
	for _, a := range cp.alerts {
		if a.Metadata["file_path"] != nil {
			t.Fatal("victim promoted to quarantine target")
		}
	}
	if cp.count() == 0 {
		t.Fatal("ransomware evidence disappeared")
	}
}

func TestEgressStateBoundsAndCounterSafety(t *testing.T) {
	et := NewExfilTracker(1024)
	for n := 0; n < 4200; n++ {
		et.Record(fmt.Sprintf("source-%d", n), "destination", 1)
	}
	if et.records.Len() > 4096 {
		t.Errorf("retained %d source records", et.records.Len())
	}
	for n := 0; n < 1000; n++ {
		et.Record("active", fmt.Sprintf("destination-%d", n), 1)
	}
	if n := et.GetStats("active").UniqueDestinations; n > 256 {
		t.Errorf("retained %d destinations", n)
	}
	if stats := et.GetStats("active"); !stats.DestinationsTruncated || stats.TotalBytes != 1000 {
		t.Fatal("bounded destination accounting lost bytes or lower-bound flag")
	}
	if _, stats := et.record("new-source", "destination", 1); !stats.CapacityEvicted {
		t.Fatal("source eviction was silent")
	}
	et.Record("overflow", "destination", math.MaxInt64)
	if !et.Record("overflow", "destination", 1) {
		t.Error("positive byte count overflow suppressed detection")
	}
	et.Record("negative", "destination", 100)
	et.Record("negative", "destination", -99)
	if et.GetStats("negative").TotalBytes != 100 {
		t.Error("negative transfer subtracted evidence")
	}
}

func TestJSONEgressCountCannotWrapBeforeAccounting(t *testing.T) {
	cp := makeCapturingPipeline()
	i := startedModuleWithPipeline(t, cp)
	defer i.Stop()
	e, err := core.UnmarshalSecurityEvent([]byte(`{"module":"collector","type":"network_egress","source_ip":"8.8.8.8","details":{"bytes":9223372036854775807}}`))
	if err != nil {
		t.Fatal(err)
	}
	i.HandleEvent(e)
	if i.exfilTracker.GetStats(e.SourceIP).TotalBytes != math.MaxInt64 || !cp.hasAlertType("data_exfiltration") {
		t.Fatal("positive JSON byte count wrapped before saturation")
	}
}

func TestEgressByteRepresentations(t *testing.T) {
	for _, value := range []interface{}{int64(math.MaxInt64), uint64(math.MaxUint64), float64(math.MaxInt64), "+9223372036854775807", "9999999999999999999999999999999999"} {
		if egressBytes(value) != math.MaxInt64 {
			t.Fatalf("wide positive value %v was lost", value)
		}
	}
	for _, value := range []interface{}{-1, int64(-1), -1.0, math.Inf(1), math.NaN(), "-1", "99999999999999999999999999999999x", "", nil} {
		if egressBytes(value) != 0 {
			t.Fatalf("invalid count %v accepted", value)
		}
	}
	for _, value := range []interface{}{42, int64(42), uint64(42), float64(42), "42"} {
		if egressBytes(value) != 42 {
			t.Fatalf("ordinary count %v changed", value)
		}
	}
}
