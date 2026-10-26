package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

func TestEmbeddedBusRequiresCredential(t *testing.T) {
	cfg := &BusConfig{Embedded: true, Port: -1, DataDir: t.TempDir()}
	bus, err := NewEventBus(cfg, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if nc, err := nats.Connect(bus.ns.ClientURL(), nats.Timeout(time.Second)); err == nil {
		nc.Close()
		t.Fatal("unauthenticated NATS accepted")
	}
	if nc, err := nats.Connect(bus.ns.ClientURL(), nats.Token("wrong"), nats.Timeout(time.Second)); err == nil {
		nc.Close()
		t.Fatal("wrong token accepted")
	}
	token, err := ReadEmbeddedBusToken(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := nats.Connect(bus.ns.ClientURL(), nats.Token(token))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish("sec.events.test.authenticated", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(cfg.DataDir, "connection.token"))
		if info.Mode().Perm() != 0600 {
			t.Fatal("token permissions")
		}
	}
	nc.Close()
	bus.Close()
	restarted, err := NewEventBus(cfg, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	after, err := ReadEmbeddedBusToken(cfg.DataDir)
	if err != nil || after != token {
		t.Fatal("restart invalidated collector credential", err)
	}
	reconnected, err := nats.Connect(restarted.ns.ClientURL(), nats.Token(token))
	if err != nil {
		t.Fatal("collector cannot reconnect", err)
	}
	reconnected.Close()
}

func TestWebhookDNSPolicyPinsValidatedAddress(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.100.100.200", "::1", "fc00::1", "0.0.0.0", "224.0.0.1"} {
		called := false
		_, err := dialPublicWebhook(context.Background(), "tcp", "receiver.example:443", func(context.Context, string) ([]net.IPAddr, error) { return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil }, func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil })
		if err == nil || called {
			t.Fatalf("unsafe address accepted: %s", ip)
		}
	}
	lookups, dials := 0, 0
	_, err := dialPublicWebhook(context.Background(), "tcp", "receiver.example:443", func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}, func(_ context.Context, _ string, addr string) (net.Conn, error) {
		dials++
		if addr != "8.8.8.8:443" {
			t.Errorf("hostname re-resolved: %s", addr)
		}
		return nil, errors.New("test dial")
	})
	if err == nil || lookups != 1 || dials != 1 {
		t.Fatal("unexpected DNS/dial sequence")
	}
}

func TestWebhookRedirectAndDispatcherUseSafeTransport(t *testing.T) {
	client := newWebhookHTTPClient()
	if client.CheckRedirect(&http.Request{}, nil) == nil {
		t.Fatal("redirect accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("private webhook reached") }))
	defer server.Close()
	cfg := DefaultWebhookRetryConfig()
	cfg.Workers = 1
	cfg.MaxRetries = 0
	d := NewWebhookDispatcher(zerolog.Nop(), cfg)
	defer d.Stop()
	d.Enqueue(server.URL, map[string]interface{}{"test": true}, nil)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(d.GetDeadLetters(10)) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("private webhook not rejected into dead letter")
}

func TestPrivateArchiveAndExistingConfigPermissions(t *testing.T) {
	dir := t.TempDir()
	archiveDir := filepath.Join(dir, "archive")
	if err := os.Mkdir(archiveDir, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultArchiveConfig()
	cfg.Dir = archiveDir
	cfg.Compress = false
	a, err := NewArchiver(cfg, nil, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	a.writeRecord("event", []byte(`{"token":"sensitive"}`))
	a.closeFile()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateConfig(path, []byte("new-secret")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	for path, mode := range map[string]os.FileMode{archiveDir: 0700, a.currentPath: 0600, path: 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("unsafe mode %s: %v", path, err)
		}
	}
}

func TestCorrelatorBoundsActiveAndExpiredEvidence(t *testing.T) {
	tc := NewThreatCorrelator(zerolog.Nop(), nil, nil)
	tc.chains = nil
	for i := 0; i < 500; i++ {
		tc.Ingest(&Alert{Timestamp: time.Now(), Module: "auth_fortress", Metadata: map[string]interface{}{"source_ip": "192.0.2.1"}})
	}
	window := tc.sourceAlerts["192.0.2.1"]
	if len(window.alerts) > 32 {
		t.Fatal("active source unbounded")
	}
	for _, a := range window.alerts {
		a.Timestamp = time.Now().Add(-time.Hour)
	}
	tc.Ingest(&Alert{Timestamp: time.Now(), Module: "network_guardian", Metadata: map[string]interface{}{"source_ip": "192.0.2.1"}})
	if len(window.alerts) != 1 || len(window.modules) != 1 {
		t.Fatal("expired observations retained")
	}
	for i := 0; i < 1100; i++ {
		tc.Ingest(&Alert{Timestamp: time.Now(), Module: "auth_fortress", Metadata: map[string]interface{}{"source_ip": fmt.Sprint(i)}})
	}
	if len(tc.sourceAlerts) > 1024 {
		t.Fatal("source count unbounded")
	}
}

func TestEscalationNotificationsDoNotCreateRoots(t *testing.T) {
	p := NewAlertPipeline(zerolog.Nop(), 100)
	cfg := EscalationConfig{Enabled: true, Timeouts: map[string]EscalationTimer{"HIGH": {Timeout: time.Hour, EscalateTo: "HIGH", ReNotify: true, MaxEscalations: 1}}}
	em := NewEscalationManager(zerolog.Nop(), cfg, p)
	defer em.Stop()
	p.AddHandler(em.Track)
	root := &Alert{ID: "short", Severity: SeverityHigh, Status: AlertStatusOpen, Module: "auth_fortress"}
	p.Process(root)
	em.mu.Lock()
	em.tracked[root.ID].timer.Stop()
	em.mu.Unlock()
	em.escalate(root.ID, context.Background())
	em.mu.Lock()
	count := len(em.tracked)
	em.mu.Unlock()
	if count != 0 || len(p.GetAlerts(SeverityInfo, 100)) != 2 {
		t.Fatalf("notification created roots: %d", count)
	}
}

func TestRustOnlyResultSurvivesOrdinaryGoEvent(t *testing.T) {
	p := NewAlertPipeline(zerolog.Nop(), 100)
	b := NewRustMatchBridge(zerolog.Nop(), p, nil)
	data, _ := json.Marshal(RustMatchResult{EventID: "rust-only", Context: map[string]string{"source_ip": "192.0.2.1", "user_id": "user-1", "process_id": "123"}, Timestamp: time.Now(), HighestSeverity: "high", Matches: []RustPatternMatch{{PatternName: "test", Category: "sqli", Severity: "high"}}})
	b.handleMatchResult(data)
	b.handleMatchResult(data)
	if len(p.GetAlerts(SeverityInfo, 100)) != 1 {
		t.Fatal("Rust-only result missing or duplicated")
	}
	a := p.GetAlerts(SeverityInfo, 100)[0]
	if a.Metadata["source_ip"] != "192.0.2.1" || a.Metadata["user_id"] != "user-1" || a.Metadata["process_id"] != nil {
		t.Fatal("invalid Rust response context", a.Metadata)
	}
	cfg := DefaultConfig()
	cfg.Enforcement = &EnforcementConfig{Enabled: true, DryRun: true, Policies: map[string]ResponsePolicyYAML{"injection_shield": {Enabled: true, MinSeverity: "HIGH", Actions: []ResponseRuleYAML{{Action: "block_ip", MinSeverity: "HIGH"}}}}}
	re := NewResponseEngine(zerolog.Nop(), nil, p, cfg)
	defer re.Stop()
	re.handleAlert(a)
	if len(re.records) != 1 || re.records[0].Target != "192.0.2.1" {
		t.Fatal("Rust address lost before response")
	}
}

func TestEngineRoutesGoEventWithoutSuppressingRustOnlyDetection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Bus.Port = -1
	cfg.Bus.DataDir = t.TempDir()
	cfg.Logging.Level = "error"
	cfg.RustEngine.Enabled = true
	cfg.RustEngine.Binary = filepath.Join(t.TempDir(), "not-installed")
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Shutdown()
	event := NewSecurityEvent("test", "http_request", SeverityInfo, "ordinary event")
	event.Details["body"] = "<script>alert(1)</script>"
	if err := e.Bus.PublishEvent(event); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		e.Dedup.mu.Lock()
		seen := len(e.Dedup.seen) > 0
		e.Dedup.mu.Unlock()
		if seen {
			break
		}
		time.Sleep(time.Millisecond)
	}
	data, _ := json.Marshal(RustMatchResult{EventID: event.ID, Timestamp: time.Now(), HighestSeverity: "high", Matches: []RustPatternMatch{{PatternName: "xss", Category: "xss", Severity: "high"}}})
	e.RustMatchBridge.handleMatchResult(data)
	if len(e.Pipeline.GetAlerts(SeverityHigh, 100)) != 1 {
		t.Fatal("Go processing suppressed independent Rust finding")
	}
}
