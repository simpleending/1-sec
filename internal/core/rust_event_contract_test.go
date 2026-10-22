package core

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestRustEventFixtureMatchesGoWireFormat(t *testing.T) {
	event := NewSecurityEvent("injection_shield", "http_request", SeverityHigh, "XML request")
	event.ID = "go-rust-contract"
	event.Timestamp = time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	event.Source = "gateway"
	event.SourceIP = "192.0.2.1"
	event.Details["body"] = `<!DOCTYPE foo PUBLIC "identifier" "relative.dtd"><foo/>`
	actual, err := event.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../rust/1sec-engine/testdata/go_http_request.json")
	if err != nil {
		t.Fatal(err)
	}
	// Normalize JSON whitespace and HTML escaping without discarding fields.
	canonical := func(data []byte) []byte {
		t.Helper()
		var value any
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
		result, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if !bytes.Equal(canonical(actual), canonical(fixture)) {
		t.Fatalf("Go event format changed; update the Rust contract fixture: %s", actual)
	}
}
