package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

func testSensors(t *testing.T) *SensorRegistry {
	t.Helper()
	r, err := NewSensorRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func enrollTestSensor(t *testing.T, r *SensorRegistry, id string, local bool) (SensorInfo, string) {
	t.Helper()
	info, token, err := r.Enroll(SensorSpec{ID: id, HostID: "127.0.0.1", AllowLocalResponse: local, Scopes: []SensorScope{{Module: "endpoint", Type: "process_exec"}, {Module: "endpoint", Type: "http_request"}}})
	if err != nil {
		t.Fatal(err)
	}
	return info, token
}

func signedTestEvent(t *testing.T, r *SensorRegistry, info SensorInfo) *SecurityEvent {
	t.Helper()
	e := NewSecurityEvent("endpoint", "process_exec", SeverityCritical, "observed process")
	e.SourceIP = "192.0.2.44"
	e.Details["process_id"] = "4242"
	if err := r.BindEvent(info, e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSensorGrantScopeSignatureAndPersistence(t *testing.T) {
	dir := t.TempDir()
	r, err := NewSensorRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	a, tokenA := enrollTestSensor(t, r, "a", true)
	_, tokenB := enrollTestSensor(t, r, "b", false)
	if _, err := NewSensorRegistry(dir); err == nil {
		t.Fatal("two writers acquired sensor state")
	}
	for _, spec := range []SensorSpec{
		{ID: "a", HostID: "127.0.0.1", Scopes: a.Scopes},
		{ID: "wildcard", HostID: "127.0.0.1", Scopes: []SensorScope{{Module: "endpoint", Type: ">"}}},
		{ID: "empty", HostID: "127.0.0.1"},
		{ID: "remote", HostID: "192.0.2.55", AllowLocalResponse: true, Scopes: a.Scopes},
	} {
		if _, _, err := r.Enroll(spec); err == nil {
			t.Fatalf("unsafe grant accepted: %+v", spec)
		}
	}
	for _, mode := range []string{"host", "type", "module", "identity", "reserved"} {
		e := NewSecurityEvent("endpoint", "process_exec", SeverityHigh, "test")
		switch mode {
		case "host":
			e.Details["process_host"] = "another-host"
		case "type":
			e.Type = "role_change"
		case "module":
			e.Module = "runtime_watcher"
		case "identity":
			e.Sensor = &SensorEvidence{SensorID: "b"}
		case "reserved":
			e.Details["sensor_id"] = "b"
		}
		if r.BindEvent(a, e) == nil {
			t.Fatalf("accepted %s impersonation", mode)
		}
	}
	e := signedTestEvent(t, r, a)
	wire, _ := e.Marshal()
	roundTrip, err := UnmarshalSecurityEvent(wire)
	if err != nil || !r.VerifyEvent(roundTrip) {
		t.Fatal("signed wire event did not verify")
	}
	for _, mutation := range []func(*SecurityEvent){func(e *SecurityEvent) { e.Details["process_id"] = "9999" }, func(e *SecurityEvent) { e.SourceIP = "198.51.100.99" }, func(e *SecurityEvent) { e.Sensor.SensorID = "b" }, func(e *SecurityEvent) { e.Type = "role_change" }} {
		copy, _ := UnmarshalSecurityEvent(wire)
		mutation(copy)
		if r.VerifyEvent(copy) {
			t.Fatal("tampered event acquired authority")
		}
	}
	derived := NewDerivedEvent(roundTrip, "runtime_watcher", "reverse_shell", SeverityCritical, "test")
	if derived.Sensor == nil || derived.sensorAuthority == nil {
		t.Fatal("derived event lost provenance")
	}
	stat, err := r.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, stat.Size())
	if _, err := r.file.ReadAt(data, 0); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), tokenA) || strings.Contains(string(data), tokenB) {
		t.Fatal("raw sensor token persisted")
	}
	view := r.List()
	view[0].Scopes[0].Type = "poisoned"
	if _, ok := r.Authenticate(tokenA); !ok {
		t.Fatal("active token rejected")
	}
	if err := r.Revoke("a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Authenticate(tokenA); ok || r.VerifyEvent(roundTrip) {
		t.Fatal("revoked credential still active")
	}
	if _, ok := r.Authenticate(tokenB); !ok {
		t.Fatal("revocation affected another sensor")
	}
	_ = r.Close()
	r, err = NewSensorRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Authenticate(tokenA); ok {
		t.Fatal("revocation lost on restart")
	}
	if _, ok := r.Authenticate(tokenB); !ok {
		t.Fatal("other credential lost on restart")
	}
	_, newToken, err := r.Rotate("b")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Authenticate(tokenB); ok {
		t.Fatal("rotated token still valid")
	}
	if _, ok := r.Authenticate(newToken); !ok {
		t.Fatal("new token rejected")
	}
}

func TestSensorJournalFailsClosed(t *testing.T) {
	for _, mode := range []string{"torn", "write-failure"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			r, err := NewSensorRegistry(dir)
			if err != nil {
				t.Fatal(err)
			}
			_, token := enrollTestSensor(t, r, "sensor", false)
			if mode == "write-failure" {
				_ = r.file.Close()
				if r.Revoke("sensor") == nil {
					t.Fatal("failed journal commit reported success")
				}
				if _, ok := r.Authenticate(token); ok {
					t.Fatal("failed state store remained authoritative")
				}
			} else {
				_ = r.Close()
				f, err := os.OpenFile(filepath.Join(dir, "registry.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = f.WriteString(`{"incomplete":`)
				_ = f.Close()
				if loaded, err := NewSensorRegistry(dir); err == nil {
					_ = loaded.Close()
					t.Fatal("torn journal accepted")
				}
			}
		})
	}
}

func TestSensorJournalCapacityCannotCommitAnUnreadableRestart(t *testing.T) {
	dir := t.TempDir()
	r, err := NewSensorRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, token := enrollTestSensor(t, r, "sensor", false)
	before, err := r.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the same bounded write with a small capacity, avoiding a 64MiB fixture.
	r.journalLimit = before.Size() + 1
	if _, _, err := r.Rotate("sensor"); err == nil {
		t.Fatal("write crossed supported journal capacity")
	}
	after, err := r.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() || r.Ready() {
		t.Fatal("capacity failure changed durable state or remained ready")
	}
	_ = r.Close()
	r, err = NewSensorRegistry(dir)
	if err != nil {
		t.Fatalf("rejected write prevented restart: %v", err)
	}
	defer r.Close()
	if _, ok := r.Authenticate(token); !ok {
		t.Fatal("failed rotation modified prior credential")
	}
}

func TestSensorRevocationStopsEveryContainmentPath(t *testing.T) {
	for _, mode := range []string{"active", "observation", "revoked", "rotated", "expired", "forged"} {
		t.Run(mode, func(t *testing.T) {
			r := testSensors(t)
			info, _ := enrollTestSensor(t, r, "sensor", mode != "observation")
			e := signedTestEvent(t, r, info)
			a := NewAlert(NewDerivedEvent(e, "injection_shield", "injection_detected", SeverityCritical, "test"), "test", "test")
			cfg := enforcementConfig("", false)
			cfg.Enforcement.ApprovalGate = DefaultApprovalGateConfig()
			cfg.Enforcement.ApprovalGate.Enabled = true
			re := testResponseEngine(t, cfg)
			defer re.Stop()
			rule := ResponseRule{Action: ActionBlockIP, SkipApproval: true}
			re.policies[a.Module] = &ResponsePolicy{Enabled: true, Actions: []ResponseRule{rule}}
			mock := &mockExecutor{}
			re.executors[ActionBlockIP] = mock
			pending := re.ApprovalGate.Submit(a, rule, e.SourceIP)
			switch mode {
			case "revoked":
				if err := r.Revoke("sensor"); err != nil {
					t.Fatal(err)
				}
			case "rotated":
				if _, _, err := r.Rotate("sensor"); err != nil {
					t.Fatal(err)
				}
			case "expired":
				r.mu.Lock()
				v := r.records["sensor"]
				v.ExpiresAt = time.Now().Add(-time.Second)
				r.records["sensor"] = v
				r.mu.Unlock()
			case "forged":
				a.sensorAuthority = nil
			}
			re.handleAlert(a)
			if _, err := re.ApprovalGate.Approve(pending, "operator"); err != nil {
				t.Fatal(err)
			}
			ce := NewChainExecutor(zerolog.Nop(), re.executors)
			if err := ce.RegisterChain(&ActionChain{Name: "test", Steps: []ChainStep{{Name: "block", Action: ActionBlockIP}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := ce.Execute(context.Background(), "test", a, zerolog.Nop()); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "active" {
				want = 3
			}
			if mock.callCount != want {
				t.Fatalf("%s executed %d containment actions, want %d", mode, mock.callCount, want)
			}
			if mode != "active" {
				for _, executor := range []ActionExecutor{&BlockIPExecutor{}, &KillProcessExecutor{}, &QuarantineFileExecutor{}, &DropConnectionExecutor{}, &DisableUserExecutor{}, &CommandExecutor{}} {
					if _, _, err := executor.Execute(context.Background(), a, ResponseRule{}, zerolog.Nop()); err == nil || !strings.Contains(err.Error(), "sensor") {
						t.Fatalf("direct executor bypass: %T %v", executor, err)
					}
				}
			}
			if !responseActionAllowed(a, ActionLog) || !responseActionAllowed(a, ActionWebhook) {
				t.Fatal("revocation erased investigative notifications")
			}
		})
	}
}

type revokingExecutor struct {
	registry *SensorRegistry
	calls    int
}

func (x *revokingExecutor) Validate(ResponseRule) error { return nil }
func (x *revokingExecutor) Execute(context.Context, *Alert, ResponseRule, zerolog.Logger) (string, string, error) {
	x.calls++
	_ = x.registry.Revoke("sensor")
	return "", "", fmt.Errorf("retry this action")
}

func TestSensorChainRechecksRevocationBeforeRetry(t *testing.T) {
	r := testSensors(t)
	info, _ := enrollTestSensor(t, r, "sensor", true)
	a := NewAlert(signedTestEvent(t, r, info), "test", "test")
	x := &revokingExecutor{registry: r}
	ce := NewChainExecutor(zerolog.Nop(), map[ActionType]ActionExecutor{ActionBlockIP: x})
	result := ce.executeStep(context.Background(), &ChainStep{Name: "block", Action: ActionBlockIP, MaxRetries: 2}, a, zerolog.Nop())
	if x.calls != 1 || result.Status != ActionStatusSkipped {
		t.Fatalf("retry ignored revocation: calls=%d status=%s", x.calls, result.Status)
	}
}

func TestSensorBrokerChecksSignedPayloadAndQueuedRevocation(t *testing.T) {
	r := testSensors(t)
	info, _ := enrollTestSensor(t, r, "sensor", true)
	bus, err := NewEventBus(&BusConfig{Embedded: true, Port: -1, DataDir: t.TempDir()}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	bus.sensors = r
	delivered := make(chan *SecurityEvent, 4)
	if err := bus.SubscribeToAllEvents(func(e *SecurityEvent) { delivered <- e }); err != nil {
		t.Fatal(err)
	}
	e := signedTestEvent(t, r, info)
	if err := bus.PublishEvent(e); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-delivered:
		if got.sensorAuthority == nil {
			t.Fatal("broker dropped verified authority")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("valid event not delivered")
	}
	wire, _ := e.Marshal()
	tampered, _ := UnmarshalSecurityEvent(wire)
	tampered.Details["process_id"] = "9999"
	bad, _ := tampered.Marshal()
	if _, err := bus.js.Publish("sec.events.endpoint.process_exec", bad); err != nil {
		t.Fatal(err)
	}
	if err := r.Revoke("sensor"); err != nil {
		t.Fatal(err)
	}
	if _, err := bus.js.Publish("sec.events.endpoint.process_exec", wire); err != nil {
		t.Fatal(err)
	}
	select {
	case <-delivered:
		t.Fatal("tampered or revoked event reached detectors")
	case <-time.After(200 * time.Millisecond):
	}
	// A sensor bearer token is not a broker credential.
	_, token := enrollTestSensor(t, r, "other", false)
	if nc, err := nats.Connect(bus.ns.ClientURL(), nats.Token(token), nats.NoReconnect()); err == nil {
		nc.Close()
		t.Fatal("sensor obtained broker access")
	}
}

func TestSensorConcurrentAuthenticateAndRevocation(t *testing.T) {
	r := testSensors(t)
	_, token := enrollTestSensor(t, r, "sensor", false)
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = r.Authenticate(token)
				_ = r.List()
			}
		}()
	}
	if err := r.Revoke("sensor"); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, ok := r.Authenticate(token); ok {
		t.Fatal("revocation raced with authentication")
	}
}

func TestRustSensorResultRequiresSignedOriginalAndLiveGrant(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "changed-target", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			r := testSensors(t)
			info, _ := enrollTestSensor(t, r, "sensor", true)
			e := signedTestEvent(t, r, info)
			wire, _ := e.Marshal()
			result := RustMatchResult{EventID: e.ID, HighestSeverity: "critical", Matches: []RustPatternMatch{{Category: "sqli", Severity: "critical"}}, Context: map[string]string{"source_ip": "198.51.100.99"}, SensorEvent: wire}
			switch mode {
			case "missing":
				result.SensorEvent = nil
			case "changed-target":
				e.SourceIP = "198.51.100.99"
				result.SensorEvent, _ = e.Marshal()
			case "revoked":
				_ = r.Revoke("sensor")
			}
			p := NewAlertPipeline(zerolog.Nop(), 10)
			bridge := NewRustMatchBridge(zerolog.Nop(), p, &EventBus{sensors: r})
			data, _ := json.Marshal(result)
			bridge.handleMatchResult(data)
			alerts := p.GetAlerts(SeverityInfo, 10)
			if len(alerts) != 1 {
				t.Fatal("lost investigative detection")
			}
			allowed := responseActionAllowed(alerts[0], ActionBlockIP)
			if allowed != (mode == "valid") {
				t.Fatalf("%s acquired authority=%v", mode, allowed)
			}
			if mode == "valid" && alerts[0].Metadata["source_ip"] != e.SourceIP {
				t.Fatal("unsigned Rust context replaced signed target")
			}
		})
	}
}
