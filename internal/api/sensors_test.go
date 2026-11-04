package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	runtimeModule "github.com/1sec-project/1sec/internal/modules/runtime"
)

func sensorServer(t *testing.T) (*Server, *core.Engine) {
	t.Helper()
	cfg := core.DefaultConfig()
	cfg.Server.APIKeys = []string{"operator-secret"}
	cfg.Sensors.Enabled = true
	cfg.Sensors.RequireSensorIngest = true
	cfg.Sensors.StateDir = t.TempDir()
	cfg.Bus.DataDir = t.TempDir()
	cfg.Bus.Port = -1
	cfg.Alerts.EnableConsole = false
	cfg.Logging.Level = "error"
	cfg.Modules["runtime_watcher"] = core.ModuleConfig{Enabled: true, Settings: map[string]interface{}{"realtime_enabled": false}}
	e, err := core.NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Registry.Register(runtimeModule.New())
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Shutdown() })
	return NewServer(e), e
}

func sensorRequest(s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, r)
	return w
}

func TestSensorAPIEnrollmentIsolationRotationAndRevocation(t *testing.T) {
	s, e := sensorServer(t)
	grant := `{"id":"a","host_id":"127.0.0.1","allow_local_response":true,"scopes":[{"module":"endpoint","type":"process_exec"}]}`
	w := sensorRequest(s, "POST", "/api/v1/sensors", "operator-secret", grant)
	if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	var enrolled struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &enrolled); err != nil || enrolled.Token == "" {
		t.Fatal("missing one-time credential")
	}
	token := enrolled.Token
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/v1/config"}, {"GET", "/api/v1/alerts"}, {"GET", "/api/v1/sensors"}, {"POST", "/api/v1/sensors"}, {"POST", "/api/v1/sensors/a/revoke"}, {"POST", "/api/v1/sensors/a/rotate"}, {"POST", "/api/v1/enforce/approve/test"}, {"POST", "/api/v1/enforce/dry-run/runtime_watcher"}, {"POST", "/api/v1/access/check"}, {"POST", "/api/v1/shutdown"},
	} {
		if got := sensorRequest(s, route.method, route.path, token, `{}`); got.Code != 403 {
			t.Fatalf("sensor accessed %s %s: %d", route.method, route.path, got.Code)
		}
	}
	valid := `{"id":"pretend-to-be-b","module":"endpoint","type":"process_exec","source":"syslog","severity":"HIGH","details":{"process_name":"msbuild","pid":4242,"process_host":"127.0.0.1"}}`
	if got := sensorRequest(s, "POST", "/api/v1/events", "operator-secret", valid); got.Code != 403 {
		t.Fatal("strict sensor admission allowed shared write key")
	}
	for _, bad := range []string{
		strings.Replace(valid, `"127.0.0.1"`, `"remote-host"`, 1),
		strings.Replace(valid, `"process_exec"`, `"role_change"`, 1),
		strings.Replace(valid, `"endpoint"`, `"runtime_watcher"`, 1),
		strings.Replace(valid, `"details":`, `"sensor":{"sensor_id":"b"},"details":`, 1),
	} {
		if got := sensorRequest(s, "POST", "/api/v1/events", token, bad); got.Code != 403 {
			t.Fatalf("impersonation accepted: %d %s", got.Code, got.Body)
		}
	}
	if got := sensorRequest(s, "POST", "/api/v1/events", token, valid+` {}`); got.Code != 400 {
		t.Fatal("multiple event objects accepted")
	}
	oversized := `{"module":"endpoint","type":"process_exec","summary":"` + strings.Repeat("x", 65<<10) + `"}`
	if got := sensorRequest(s, "POST", "/api/v1/events", token, oversized); got.Code != 400 {
		t.Fatal("oversized sensor event accepted")
	}
	w = sensorRequest(s, "POST", "/api/v1/events", token, valid)
	if w.Code != 202 || strings.Contains(w.Body.String(), "pretend-to-be-b") {
		t.Fatalf("ingestion: %d %s", w.Code, w.Body)
	}
	deadline := time.Now().Add(3 * time.Second)
	var found *core.Alert
	for time.Now().Before(deadline) {
		for _, alert := range e.Pipeline.GetAlerts(core.SeverityInfo, 100) {
			if alert.Sensor != nil && alert.Sensor.SensorID == "a" && alert.Type == "lolbin_abuse" {
				found = alert
				break
			}
		}
		if found != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if found == nil {
		t.Fatal("real runtime detector lost authenticated identity")
	}
	for _, path := range []string{"/api/v1/sensors", "/api/v1/config", "/api/v1/logs", "/api/v1/alerts"} {
		body := sensorRequest(s, "GET", path, "operator-secret", "").Body.Bytes()
		if bytes.Contains(body, []byte(token)) || bytes.Contains(body, []byte("credential_hash")) || bytes.Contains(body, []byte("signing_key")) {
			t.Fatalf("secret exposed through %s", path)
		}
	}
	w = sensorRequest(s, "POST", "/api/v1/sensors/a/rotate", "operator-secret", "")
	if w.Code != 200 {
		t.Fatalf("rotate: %d", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &enrolled); err != nil {
		t.Fatal(err)
	}
	if got := sensorRequest(s, "POST", "/api/v1/events", token, valid); got.Code != 403 {
		t.Fatal("old token survived rotation")
	}
	if got := sensorRequest(s, "POST", "/api/v1/events", enrolled.Token, valid); got.Code != 202 {
		t.Fatalf("replacement token failed: %d %s", got.Code, got.Body)
	}
	if got := sensorRequest(s, "POST", "/api/v1/sensors/a/revoke", "operator-secret", ""); got.Code != 200 {
		t.Fatal("revocation failed")
	}
	if got := sensorRequest(s, "POST", "/api/v1/events", enrolled.Token, valid); got.Code != 403 {
		t.Fatal("revoked token ingested event")
	}
	// Sensors never become operators when the last operator key is removed.
	e.Config.Server.APIKeys = nil
	if got := sensorRequest(s, "POST", "/api/v1/shutdown", token, ""); got.Code != 403 {
		t.Fatal("sensor gained open-mode management authority")
	}
}

func TestSensorAdmissionPreservesLegacyOptOut(t *testing.T) {
	s, e := sensorServer(t)
	e.Config.Sensors.RequireSensorIngest = false
	if got := sensorRequest(s, "POST", "/api/v1/events", "operator-secret", `{"module":"endpoint","type":"process_exec"}`); got.Code != 202 {
		t.Fatalf("legacy trusted ingress broke: %d %s", got.Code, got.Body)
	}
	if got := sensorRequest(s, "POST", "/api/v1/events", "operator-secret", `{"module":"endpoint","type":"process_exec","sensor":{"sensor_id":"forged"}}`); got.Code != 403 {
		t.Fatal("legacy key manufactured sensor identity")
	}
}

func TestSensorTransportDoesNotTrustForwardedTLSHeaders(t *testing.T) {
	s, e := sensorServer(t)
	_, token, err := e.Sensors.Enroll(core.SensorSpec{ID: "remote", HostID: "remote-host", Scopes: []core.SensorScope{{Module: "endpoint", Type: "process_exec"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, encrypted := range []bool{false, true} {
		r := httptest.NewRequest("POST", "/api/v1/events", strings.NewReader(`{"module":"endpoint","type":"process_exec"}`))
		r.RemoteAddr = "192.0.2.55:1234"
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-Forwarded-Proto", "https")
		if encrypted {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, r)
		want := 403
		if encrypted {
			want = 202
		}
		if w.Code != want {
			t.Fatalf("encrypted=%v got %d: %s", encrypted, w.Code, w.Body)
		}
	}
}

func TestSensorLifecycleRequiresOperatorWriteScope(t *testing.T) {
	s, e := sensorServer(t)
	e.Config.Server.ReadOnlyKeys = []string{"monitor"}
	if _, _, err := e.Sensors.Enroll(core.SensorSpec{ID: "original", HostID: "host", Scopes: []core.SensorScope{{Module: "endpoint", Type: "http_request"}}}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"monitor", ""} {
		if key == "" {
			e.Config.Server.APIKeys = nil
			e.Config.Server.ReadOnlyKeys = nil
		}
		for _, path := range []string{"/api/v1/sensors", "/api/v1/sensors/original/rotate", "/api/v1/sensors/original/revoke"} {
			got := sensorRequest(s, "POST", path, key, `{"id":"unauthorized","host_id":"host","scopes":[{"module":"endpoint","type":"http_request"}]}`)
			if got.Code != 403 {
				t.Fatalf("non-operator %q accessed %s: %d", key, path, got.Code)
			}
		}
	}
}
