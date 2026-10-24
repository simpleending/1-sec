package api

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
)

func TestLocalDashboardClientState(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js unavailable for local dashboard client tests")
	}
	output, err := exec.Command(node, "--test", "ui/app.test.cjs").CombinedOutput()
	if err != nil {
		t.Fatalf("dashboard client regressions: %v\n%s", err, output)
	}
}

func TestLocalDashboardAssetsKeepAPIAuthentication(t *testing.T) {
	engine := testEngineWithAuth("write-fixture")
	engine.Config.Server.ReadOnlyKeys = []string{"read-fixture"}
	server := NewServer(engine)
	for _, path := range []string{"/ui/", "/ui/app.js", "/ui/style.css"} {
		response := httptest.NewRecorder()
		server.server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("asset %s: %d", path, response.Code)
		}
		if response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
			t.Fatal("dashboard assets require isolation headers")
		}
		if strings.Contains(response.Body.String(), "write-fixture") {
			t.Fatal("static shell leaked configured credentials")
		}
	}
	for _, path := range []string{"/api/v1/status", "/api/v1/ui-access", "/ui/config", "/ui/api/v1/config"} {
		response := httptest.NewRecorder()
		server.server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("public shell bypassed auth on %s: %d", path, response.Code)
		}
	}
	for key, expected := range map[string]string{"read-fixture": "read", "write-fixture": "write"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/ui-access", nil)
		request.Header.Set("Authorization", "Bearer "+key)
		server.server.Handler.ServeHTTP(response, request)
		if response.Code != 200 || !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("scope probe: %d %s", response.Code, response.Body.String())
		}
	}
	for _, key := range []string{"", "read-fixture"} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/dry-run/off", nil)
		if key != "" {
			request.Header.Set("Authorization", "Bearer "+key)
		}
		response := httptest.NewRecorder()
		server.server.Handler.ServeHTTP(response, request)
		if response.Code != 401 && response.Code != 403 {
			t.Fatal("read-only local dashboard could change enforcement")
		}
	}
}

func TestDashboardApprovalSettingsReachLiveGateAndRejectPartialChanges(t *testing.T) {
	engine := testEngine()
	engine.Config.Enforcement = &core.EnforcementConfig{Enabled: true, DryRun: true, ApprovalGate: core.DefaultApprovalGateConfig()}
	engine.Config.Enforcement.ApprovalGate.Enabled = true
	engine.Config.Enforcement.ApprovalGate.AutoApproveAbove = ""
	engine.ResponseEngine = core.NewResponseEngine(engine.Logger, nil, engine.Pipeline, engine.Config)
	defer engine.ResponseEngine.ApprovalGate.Stop()
	server := NewServer(engine)
	post := func(body string) int {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/enforce/config", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer test-key")
		response := httptest.NewRecorder()
		server.server.Handler.ServeHTTP(response, request)
		return response.Code
	}
	if post(`{"auto_approve_above":"HIGH","require_approval":["block_ip"]}`) != 200 {
		t.Fatal("valid settings rejected")
	}
	gate := engine.ResponseEngine.ApprovalGate
	if !gate.RequiresApprovalForRule(core.ActionBlockIP, core.SeverityMedium, false) || gate.RequiresApprovalForRule(core.ActionBlockIP, core.SeverityHigh, false) {
		t.Fatal("settings changed only displayed config, not live decisions")
	}
	previous := engine.Config.Enforcement.GetDryRun()
	if post(`{"dry_run":false,"auto_approve_above":"LOW","require_approval":["invalid"]}`) != 400 {
		t.Fatal("invalid settings accepted")
	}
	if engine.Config.Enforcement.GetDryRun() != previous || engine.Config.Enforcement.GetApprovalGate().AutoApproveAbove != "HIGH" {
		t.Fatal("invalid request partially changed runtime settings")
	}
}
