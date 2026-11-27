package supplychain

import (
	"github.com/1sec-project/1sec/internal/core"
	"testing"
)

func TestReportedProvenancePolicyResult(t *testing.T) {
	for _, typ := range []string{"build_artifact", "artifact_deploy"} {
		for _, tc := range []struct {
			name  string
			value any
			want  bool
		}{
			{"failed", "failed", true}, {"passed", "passed", false},
			{"absent", nil, false}, {"unevaluated", "not_evaluated", false},
			{"false is not a verdict", false, false}, {"unknown", "unknown", false},
		} {
			t.Run(typ+"/"+tc.name, func(t *testing.T) {
				cp := newCapPipeline()
				s := startedSentinel(t, cp.pipeline)
				ev := core.NewSecurityEvent("fixture", typ, core.SeverityInfo, "sample build artifact")
				ev.Details["artifact_name"] = "sample-1.0.0.tgz"
				ev.Details["signature"] = "present"
				ev.Details["provenance"] = "fixture-attestation"
				if tc.value != nil {
					ev.Details["provenance_policy_result"] = tc.value
				}
				if err := s.HandleEvent(ev); err != nil {
					t.Fatal(err)
				}
				if got := cp.hasAlertType("artifact_provenance_policy_failed"); got != tc.want {
					t.Errorf("policy alert=%v want=%v", got, tc.want)
				}
				if !tc.want && cp.count() != 0 {
					t.Error("unexpected finding for a neutral result")
				}
			})
		}
	}
}

func TestProvenancePassCannotHideMissingMetadata(t *testing.T) {
	cp := newCapPipeline()
	s := startedSentinel(t, cp.pipeline)
	ev := core.NewSecurityEvent("fixture", "build_artifact", core.SeverityInfo, "sample artifact")
	ev.Details["artifact_name"] = "sample"
	ev.Details["provenance_policy_result"] = "passed"
	if err := s.HandleEvent(ev); err != nil {
		t.Fatal(err)
	}
	if !cp.hasAlertType("unsigned_artifact") || !cp.hasAlertType("missing_provenance") || cp.hasAlertType("artifact_provenance_policy_failed") {
		t.Fatal("producer result interfered with independent evidence")
	}
}

func TestProvenanceCatalog(t *testing.T) {
	all := core.EventSchemaMap()
	for _, typ := range []string{"build_artifact", "artifact_deploy"} {
		schema, ok := all[typ]
		if !ok {
			t.Fatalf("missing %s", typ)
		}
		found := false
		for _, k := range schema.OptionalKeys {
			if k == "provenance_policy_result" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing optional verdict on %s", typ)
		}
	}
}

func TestProvenanceFailureIsObservationOnly(t *testing.T) {
	cp := newCapPipeline()
	s := startedSentinel(t, cp.pipeline)
	ev := core.NewSecurityEvent("fixture", "build_artifact", core.SeverityInfo, "sample artifact")
	ev.ObservationOnly = false
	ev.Details["artifact_name"] = "sample"
	ev.Details["provenance_policy_result"] = "failed"
	if err := s.HandleEvent(ev); err != nil {
		t.Fatal(err)
	}
	if ev.ObservationOnly {
		t.Fatal("input event mutated")
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	seen := false
	normal := false
	for _, a := range cp.alerts {
		if a.Type == "artifact_provenance_policy_failed" {
			seen = true
			if !a.ObservationOnly {
				t.Fatal("producer verdict eligible for automatic enforcement")
			}
		}
		if a.Type == "unsigned_artifact" {
			normal = true
			if a.ObservationOnly {
				t.Fatal("unrelated finding changed eligibility")
			}
		}
	}
	if !seen || !normal {
		t.Fatalf("expected independent verdict and metadata findings: %v, %v", seen, normal)
	}
}
