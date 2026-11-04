package core

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

// CI's Rust job builds the real sidecar and sets this explicit integration input.
func TestRustResultPublicationFailureRetainsInput(t *testing.T) {
	binary := os.Getenv("ONESEC_TEST_RUST_BINARY")
	if binary == "" {
		t.Skip("set ONESEC_TEST_RUST_BINARY to a built sidecar to exercise the real broker/child contract")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatal(err)
	}
	bus, err := NewEventBus(&BusConfig{Embedded: true, Port: -1, DataDir: t.TempDir()}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	configPath := filepath.Join(t.TempDir(), "rust.yaml")
	if err := os.WriteFile(configPath, []byte("rust_engine:\n  workers: 1\n  buffer_size: 10\n  min_score: 0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--config", configPath, "--log-level", "error")
	cmd.Env = append(os.Environ(), "ONESEC_NATS_URL="+bus.ns.ClientURL(), "ONESEC_NATS_TOKEN="+bus.token)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	waitFor := func(label string, predicate func() bool) {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			if predicate() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal(label)
	}
	waitFor("Rust consumer did not start", func() bool { _, err := bus.js.ConsumerInfo("SECURITY_EVENTS", "rust-engine"); return err == nil })
	if err := bus.js.DeleteStream("SECURITY_MATCH_RESULTS"); err != nil {
		t.Fatal(err)
	}
	e := NewSecurityEvent("delivery_test", "http_request", SeverityInfo, "observed request")
	e.Source = "test"
	e.Details["body"] = "UNION SELECT password FROM users"
	payload, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ack, err := bus.js.Publish("sec.events.delivery_test.http_request", payload)
	if err != nil {
		t.Fatal(err)
	}
	waitFor("Rust input was lost instead of retried after result persistence failed", func() bool {
		info, err := bus.js.ConsumerInfo("SECURITY_EVENTS", "rust-engine")
		if err != nil {
			return false
		}
		if info.AckFloor.Stream >= ack.Sequence {
			t.Fatal("input ACK preceded a persisted detection result")
		}
		return info.Delivered.Consumer >= 2 && info.NumAckPending == 1
	})
	if _, err := bus.js.AddStream(&nats.StreamConfig{Name: "SECURITY_MATCH_RESULTS", Subjects: []string{"sec.matches.>"}, Storage: nats.FileStorage}); err != nil {
		t.Fatal(err)
	}
	waitFor("Rust did not recover after match storage returned", func() bool {
		input, e1 := bus.js.ConsumerInfo("SECURITY_EVENTS", "rust-engine")
		results, e2 := bus.js.StreamInfo("SECURITY_MATCH_RESULTS")
		return e1 == nil && e2 == nil && input.AckFloor.Stream >= ack.Sequence && results.State.Msgs >= 1
	})
	stored, err := bus.js.GetMsg("SECURITY_MATCH_RESULTS", 1)
	if err != nil {
		t.Fatal(err)
	}
	var result RustMatchResult
	if err := json.Unmarshal(stored.Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.EventID != e.ID || len(result.Matches) == 0 {
		t.Fatalf("lost detection context: %+v", result)
	}
	// Harmless and structurally invalid events have deliberate terminal outcomes.
	for _, wire := range [][]byte{
		[]byte(`{"id":"normal","timestamp":"2026-11-05T00:00:00Z","module":"delivery_test","type":"http_request","severity":"INFO","source":"test","summary":"ordinary request","details":{"body":"hello"}}`),
		[]byte(`{"invalid":"event"}`),
	} {
		ack, err := bus.js.Publish("sec.events.delivery_test.http_request", wire)
		if err != nil {
			t.Fatal(err)
		}
		waitFor("terminal input disposition did not complete", func() bool {
			info, err := bus.js.ConsumerInfo("SECURITY_EVENTS", "rust-engine")
			return err == nil && info.AckFloor.Stream >= ack.Sequence
		})
	}
}
