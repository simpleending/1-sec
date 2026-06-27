package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── Severity ───────────────────────────────────────────────────────────────

func TestSeverity_String(t *testing.T) {
	cases := []struct {
		s    Severity
		want string
	}{
		{SeverityInfo, "INFO"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestSeverity_Ordering(t *testing.T) {
	if !(SeverityInfo < SeverityLow) {
		t.Error("Info should be less than Low")
	}
	if !(SeverityLow < SeverityMedium) {
		t.Error("Low should be less than Medium")
	}
	if !(SeverityMedium < SeverityHigh) {
		t.Error("Medium should be less than High")
	}
	if !(SeverityHigh < SeverityCritical) {
		t.Error("High should be less than Critical")
	}
}

func TestSeverity_JSON_RoundTrip(t *testing.T) {
	cases := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for _, sev := range cases {
		data, err := json.Marshal(sev)
		if err != nil {
			t.Fatalf("Marshal Severity %v: %v", sev, err)
		}
		var out Severity
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("Unmarshal Severity %v: %v", sev, err)
		}
		if out != sev {
			t.Errorf("round-trip Severity: got %v, want %v", out, sev)
		}
	}
}

func TestSeverity_UnmarshalJSON_Unknown(t *testing.T) {
	var s Severity
	if err := json.Unmarshal([]byte(`"BOGUS"`), &s); err != nil {
		t.Errorf("UnmarshalJSON with unknown string should not error, got: %v", err)
	}
	if s != SeverityInfo {
		t.Errorf("unknown severity should default to Info, got %v", s)
	}
}

// ─── SecurityEvent ──────────────────────────────────────────────────────────

func TestNewSecurityEvent_Fields(t *testing.T) {
	ev := NewSecurityEvent("net_module", "port_scan", SeverityHigh, "Port scan detected")

	if ev.ID == "" {
		t.Error("ID should not be empty")
	}
	if ev.Module != "net_module" {
		t.Errorf("Module = %q, want %q", ev.Module, "net_module")
	}
	if ev.Type != "port_scan" {
		t.Errorf("Type = %q, want %q", ev.Type, "port_scan")
	}
	if ev.Severity != SeverityHigh {
		t.Errorf("Severity = %v, want High", ev.Severity)
	}
	if ev.Summary != "Port scan detected" {
		t.Errorf("Summary = %q, want 'Port scan detected'", ev.Summary)
	}
	if ev.Details == nil {
		t.Error("Details map should be initialised")
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
	if ev.Timestamp.Location().String() != "UTC" {
		t.Errorf("Timestamp should be UTC, got %v", ev.Timestamp.Location())
	}
}

func TestNewSecurityEvent_UniqueIDs(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		ev := NewSecurityEvent("m", "t", SeverityInfo, "s")
		if ids[ev.ID] {
			t.Errorf("duplicate ID generated: %s", ev.ID)
		}
		ids[ev.ID] = true
	}
}

func TestSecurityEvent_Marshal_Unmarshal(t *testing.T) {
	ev := NewSecurityEvent("module", "type", SeverityCritical, "Summary text")
	ev.SourceIP = "192.168.1.1"
	ev.DestIP = "10.0.0.1"
	ev.UserAgent = "Mozilla/5.0"
	ev.RequestID = "req-123"
	ev.Details["key"] = "value"
	ev.RawData = []byte("raw")

	data, err := ev.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	out, err := UnmarshalSecurityEvent(data)
	if err != nil {
		t.Fatalf("UnmarshalSecurityEvent() error: %v", err)
	}

	if out.ID != ev.ID {
		t.Errorf("ID: %q != %q", out.ID, ev.ID)
	}
	if out.Module != ev.Module {
		t.Errorf("Module: %q != %q", out.Module, ev.Module)
	}
	if out.Type != ev.Type {
		t.Errorf("Type: %q != %q", out.Type, ev.Type)
	}
	if out.Severity != SeverityCritical {
		t.Errorf("Severity: %v != Critical", out.Severity)
	}
	if out.Summary != ev.Summary {
		t.Errorf("Summary: %q != %q", out.Summary, ev.Summary)
	}
	if out.SourceIP != ev.SourceIP {
		t.Errorf("SourceIP: %q != %q", out.SourceIP, ev.SourceIP)
	}
	if out.DestIP != ev.DestIP {
		t.Errorf("DestIP: %q != %q", out.DestIP, ev.DestIP)
	}
}

func TestUnmarshalSecurityEvent_Invalid(t *testing.T) {
	_, err := UnmarshalSecurityEvent([]byte("not-json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSecurityEvent_JSON_TimestampPreserved(t *testing.T) {
	ev := NewSecurityEvent("m", "t", SeverityLow, "s")
	before := ev.Timestamp.Truncate(time.Second)

	data, _ := ev.Marshal()
	out, _ := UnmarshalSecurityEvent(data)

	if !out.Timestamp.Truncate(time.Second).Equal(before) {
		t.Errorf("Timestamp not preserved after round-trip: got %v, want %v",
			out.Timestamp, before)
	}
}

func TestSecurityEvent_Details_Preserved(t *testing.T) {
	ev := NewSecurityEvent("m", "t", SeverityMedium, "s")
	ev.Details["field1"] = "value1"
	ev.Details["count"] = float64(42)

	data, _ := ev.Marshal()
	out, _ := UnmarshalSecurityEvent(data)

	if out.Details["field1"] != "value1" {
		t.Errorf("Details[field1] = %v", out.Details["field1"])
	}
}

func TestSecurityEvent_EmptyDetails(t *testing.T) {
	ev := NewSecurityEvent("m", "t", SeverityInfo, "s")
	data, err := ev.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\"id\"") {
		t.Error("marshaled event should contain 'id' field")
	}
}

func TestCanonicalEventSchemas_ModelInferenceTensorMetadata(t *testing.T) {
	schema, ok := EventSchemaMap()["model_inference"]
	if !ok {
		t.Fatal("model_inference schema should be registered")
	}

	hasTensorShape := false
	for _, key := range schema.OptionalKeys {
		if key == "tensor_shape" {
			hasTensorShape = true
			break
		}
	}
	if !hasTensorShape {
		t.Fatal("model_inference schema should document tensor_shape")
	}

	ev := NewSecurityEvent("data_poisoning", "model_inference", SeverityInfo, "inference")
	ev.Details["model_id"] = "model-prod"
	ev.Details["tensor_shape"] = []int{1, 3, 224, 224}
	if missing := ValidateEvent(ev); len(missing) != 0 {
		t.Fatalf("ValidateEvent() missing keys = %v", missing)
	}
}

func TestCanonicalizeEventRouting_ValidTokensUnchanged(t *testing.T) {
	ev := NewSecurityEvent("network_guardian", "dns_query", SeverityInfo, "dns")
	CanonicalizeEventRouting(ev)

	if ev.Module != "network_guardian" {
		t.Fatalf("Module = %q, want network_guardian", ev.Module)
	}
	if ev.Type != "dns_query" {
		t.Fatalf("Type = %q, want dns_query", ev.Type)
	}
	if _, ok := ev.Details["original_module"]; ok {
		t.Fatal("valid module should not be copied to original_module")
	}
}

func TestCanonicalizeEventRouting_InvalidTokensMapped(t *testing.T) {
	ev := NewSecurityEvent("bad.module", "type.with.dots", SeverityInfo, "bad")
	CanonicalizeEventRouting(ev)

	if ev.Module != "external" {
		t.Fatalf("Module = %q, want external", ev.Module)
	}
	if ev.Type != "unknown" {
		t.Fatalf("Type = %q, want unknown", ev.Type)
	}
	if ev.Details["original_module"] != "bad.module" {
		t.Fatalf("original_module = %v", ev.Details["original_module"])
	}
	if ev.Details["original_type"] != "type.with.dots" {
		t.Fatalf("original_type = %v", ev.Details["original_type"])
	}
}
