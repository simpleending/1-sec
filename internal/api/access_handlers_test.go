package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/1sec-project/1sec/internal/modules/iot"
)

func accessTestServer(t *testing.T) *Server {
	t.Helper()
	e := testEngine()
	e.Config.ManagementAccess = core.ManagementAccessConfig{AllowedSources: []string{"127.0.0.1", "10.20.0.0/24"}, AllowedOperators: []string{"engineer"}}
	shield := iot.New()
	if err := shield.Start(context.Background(), nil, e.Pipeline, e.Config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shield.Stop() })
	if err := e.Registry.Register(shield); err != nil {
		t.Fatal(err)
	}
	return newTestServer(e)
}

const accessRequestJSON = `{"source_ip":"10.20.0.7","operator":"engineer","identity_verified":true,"target":"device-17","action":"configure"}`

func TestManagementAccessCheckHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, body, key, method string
		status                  int
	}{
		{"allow", accessRequestJSON, "test-key", "POST", 200},
		{"outside network", strings.Replace(accessRequestJSON, "10.20.0.7", "198.51.100.23", 1), "test-key", "POST", 403},
		{"unverified", strings.Replace(accessRequestJSON, "true", "false", 1), "test-key", "POST", 403},
		{"identity string", strings.Replace(accessRequestJSON, "true", `"true"`, 1), "test-key", "POST", 400},
		{"unknown operator", strings.Replace(accessRequestJSON, "engineer", "attacker", 1), "test-key", "POST", 403},
		{"missing context", `{}`, "test-key", "POST", 403},
		{"null", `null`, "test-key", "POST", 403},
		{"unknown field", strings.Replace(accessRequestJSON, `"action":`, `"admin":true,"action":`, 1), "test-key", "POST", 400},
		{"trailing JSON", accessRequestJSON + ` {}`, "test-key", "POST", 400},
		{"oversized", accessRequestJSON + strings.Repeat(" ", 16<<10), "test-key", "POST", 400},
		{"missing API key", accessRequestJSON, "", "POST", 401},
		{"read only API key", accessRequestJSON, "reader-key", "POST", 403},
		{"wrong API key", accessRequestJSON, "attacker-key", "POST", 403},
		{"wrong method", accessRequestJSON, "test-key", "GET", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := accessTestServer(t)
			s.engine.Config.Server.ReadOnlyKeys = []string{"reader-key"}
			req := httptest.NewRequest(tc.method, "/api/v1/access/check", strings.NewReader(tc.body))
			req.Header.Set("X-Forwarded-For", "10.20.0.7")
			if tc.key != "" {
				req.Header.Set("Authorization", "Bearer "+tc.key)
			}
			w := httptest.NewRecorder()
			s.server.Handler.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("got %d %s, want %d", w.Code, w.Body.String(), tc.status)
			}
			if tc.status == 200 || tc.status == 403 && tc.key == "test-key" {
				var d core.ManagementAccessDecision
				if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
					t.Fatal(err)
				}
				if d.Allowed != (tc.status == 200) {
					t.Fatalf("wrong decision %+v", d)
				}
			}
		})
	}
}

func TestManagementAccessUnavailableDenies(t *testing.T) {
	for _, state := range []string{"missing module", "disabled module", "not started", "no policy", "no API keys"} {
		t.Run(state, func(t *testing.T) {
			s := accessTestServer(t)
			want := 503
			switch state {
			case "missing module":
				s = newTestServer(testEngine())
			case "disabled module":
				s.engine.Config.Modules[iot.ModuleName] = core.ModuleConfig{Enabled: false}
			case "not started":
				e := testEngine()
				_ = e.Registry.Register(iot.New())
				s = newTestServer(e)
				want = 403
			case "no policy":
				e := testEngine()
				shield := iot.New()
				_ = shield.Start(context.Background(), nil, e.Pipeline, e.Config)
				t.Cleanup(func() { _ = shield.Stop() })
				_ = e.Registry.Register(shield)
				s = newTestServer(e)
				want = 403
			case "no API keys":
				s.engine.Config.Server.APIKeys = nil
				want = 403
			}
			w := httptest.NewRecorder()
			s.server.Handler.ServeHTTP(w, authedReq(httptest.NewRequest("POST", "/api/v1/access/check", strings.NewReader(accessRequestJSON))))
			if w.Code != want {
				t.Fatalf("got %d, want %d", w.Code, want)
			}
		})
	}
}

// A simulated gateway must obtain an explicit allow before touching its backend.
func TestGatewayStopsAccessBeforeBackend(t *testing.T) {
	s := accessTestServer(t)
	policyAPI := httptest.NewServer(s.server.Handler)
	defer policyAPI.Close()
	forwarded := 0
	gateway := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "invalid client address", 400)
			return
		}
		// A real gateway validates an identity-provider session. This fixture
		// models that result independently of client claims and device login.
		verified := r.Header.Get("Authorization") == "Bearer verified-session"
		check := core.ManagementAccessRequest{SourceIP: ip, Operator: "engineer", IdentityVerified: verified, Target: "device-17", Action: "configure"}
		body, err := json.Marshal(check)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(r.Context(), "POST", policyAPI.URL+"/api/v1/access/check", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer test-key")
		res, err := policyAPI.Client().Do(req)
		if err != nil {
			http.Error(w, "access check unavailable", http.StatusServiceUnavailable)
			return
		}
		defer res.Body.Close()
		var decision core.ManagementAccessDecision
		if err := json.NewDecoder(io.LimitReader(res.Body, 16<<10)).Decode(&decision); err != nil || res.StatusCode != 200 || !decision.Allowed {
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
		forwarded++
		w.WriteHeader(http.StatusNoContent)
	})
	for _, tc := range []struct {
		name, ip, session         string
		wantStatus, wantForwarded int
	}{
		{"internet attacker with a session", "198.51.100.23:1234", "verified-session", 403, 0},
		{"forged operator claims inside allowed network", "10.20.0.7:1234", "forged-session", 403, 0},
		{"authorized operator", "10.20.0.7:1234", "verified-session", 204, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/management/device-17/configure", nil)
			req.RemoteAddr = tc.ip
			req.Header.Set("Authorization", "Bearer "+tc.session)
			req.Header.Set("X-Forwarded-For", "10.20.0.7")
			req.Header.Set("X-Identity-Verified", "true")
			w := httptest.NewRecorder()
			gateway.ServeHTTP(w, req)
			if w.Code != tc.wantStatus || forwarded != tc.wantForwarded {
				t.Fatalf("status %d forwarded %d", w.Code, forwarded)
			}
		})
	}
	policyAPI.Close()
	req := httptest.NewRequest("POST", "/management/device-17/configure", nil)
	req.RemoteAddr = "10.20.0.7:1234"
	req.Header.Set("Authorization", "Bearer verified-session")
	w := httptest.NewRecorder()
	gateway.ServeHTTP(w, req)
	if w.Code != 503 || forwarded != 1 {
		t.Fatalf("unavailable policy forwarded access: status %d forwarded %d", w.Code, forwarded)
	}
}
