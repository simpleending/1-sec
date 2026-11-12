package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

// authReq adds the test API key header to a request.
func authReq(req *http.Request) *http.Request {
	req.Header.Set("Authorization", "Bearer test-key")
	return req
}

func testEngineWithEnforcement(preset string, dryRun bool) *core.Engine {
	cfg := core.DefaultConfig()
	cfg.RustEngine.Enabled = false
	cfg.Server.APIKeys = []string{"test-key"} // enable auth so mutating endpoints work
	cfg.Enforcement = &core.EnforcementConfig{
		Enabled: true,
		DryRun:  dryRun,
		Preset:  preset,
	}
	logger := zerolog.Nop()
	pipeline := core.NewAlertPipeline(logger, 1000)

	engine := &core.Engine{
		Config:         cfg,
		Registry:       core.NewModuleRegistry(logger),
		Pipeline:       pipeline,
		Logger:         logger,
		ResponseEngine: core.NewResponseEngine(logger, nil, pipeline, cfg),
	}
	return engine
}

func testEngineNoEnforcement() *core.Engine {
	cfg := core.DefaultConfig()
	cfg.RustEngine.Enabled = false
	cfg.Server.APIKeys = []string{"test-key"} // enable auth so mutating endpoints work
	logger := zerolog.Nop()
	return &core.Engine{
		Config:   cfg,
		Registry: core.NewModuleRegistry(logger),
		Pipeline: core.NewAlertPipeline(logger, 1000),
		Logger:   logger,
	}
}

func TestEnforceConfigRequiresOneBoundedJSONBody(t *testing.T) {
	const update = `{"dry_run":false}`
	const limit = 64 << 10
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"trailing JSON", update + ` {"dry_run":true}`, http.StatusBadRequest},
		{"trailing garbage", update + " invalid", http.StatusBadRequest},
		{"oversized padding", update + strings.Repeat(" ", limit+1-len(update)), http.StatusBadRequest},
		{"exact limit", update + strings.Repeat(" ", limit-len(update)), http.StatusOK},
		{"normal update", update + "\n", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := testEngineWithEnforcement("balanced", true)
			server := newTestServer(engine)
			req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/config", strings.NewReader(tc.body)))
			req.ContentLength = -1
			rec := httptest.NewRecorder()
			server.server.Handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
			if dryRun := engine.Config.Enforcement.GetDryRun(); dryRun != (tc.want != http.StatusOK) {
				t.Errorf("dry run = %t after status %d, want %t", dryRun, rec.Code, tc.want != http.StatusOK)
			}
		})
	}
}

// ─── Enforce Status ──────────────────────────────────────────────────────────

func TestHandleEnforceStatus_WithEnforcement(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	if body["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", body["enabled"])
	}
	if body["dry_run"] != true {
		t.Errorf("expected dry_run=true, got %v", body["dry_run"])
	}
	if body["stats"] == nil {
		t.Error("expected stats in response")
	}
}

func TestHandleEnforceStatus_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != false {
		t.Errorf("expected enabled=false when no enforcement, got %v", body["enabled"])
	}
}

func TestHandleEnforceStatus_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/status", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Enforce Policies ────────────────────────────────────────────────────────

func TestHandleEnforcePolicies_WithEnforcement(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/policies", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	policies, ok := body["policies"].(map[string]interface{})
	if !ok {
		t.Fatal("expected policies map in response")
	}
	if len(policies) == 0 {
		t.Error("expected non-empty policies from balanced preset")
	}
}

func TestHandleEnforcePolicies_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/policies", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	policies, _ := body["policies"].(map[string]interface{})
	if len(policies) != 0 {
		t.Errorf("expected empty policies when no enforcement, got %d", len(policies))
	}
}

// ─── Enforce History ─────────────────────────────────────────────────────────

func TestHandleEnforceHistory_Empty(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/history", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	records, _ := body["records"].([]interface{})
	if len(records) != 0 {
		t.Errorf("expected empty history, got %d records", len(records))
	}
}

func TestHandleEnforceHistory_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/history", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleEnforceHistory_WithLimitParam(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/history?limit=5", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleEnforceHistory_WithModuleFilter(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/history?module=injection_shield", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// ─── Enforce Dry-Run Toggle ──────────────────────────────────────────────────

func TestHandleEnforceDryRun_On(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", false))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/dry-run/on", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["dry_run"] != true {
		t.Errorf("expected dry_run=true after toggling on, got %v", body["dry_run"])
	}
}

func TestHandleEnforceDryRun_Off(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/dry-run/off", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["dry_run"] != false {
		t.Errorf("expected dry_run=false after toggling off, got %v", body["dry_run"])
	}
}

func TestHandleEnforceDryRun_InvalidMode(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/dry-run/maybe", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceDryRun_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/dry-run/on", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceDryRun_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/dry-run/on", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Enforce Policy Enable/Disable ───────────────────────────────────────────

func TestHandleEnforcePolicyAction_Enable(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/policies/injection_shield/enable", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", body["enabled"])
	}
}

func TestHandleEnforcePolicyAction_Disable(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/policies/injection_shield/disable", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", body["enabled"])
	}
}

func TestHandleEnforcePolicyAction_NotFound(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/policies/nonexistent_module/enable", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleEnforcePolicyAction_InvalidAction(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/policies/injection_shield/restart", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforcePolicyAction_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/policies/injection_shield/enable", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforcePolicyAction_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/policies/injection_shield/enable", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Enforce Test ────────────────────────────────────────────────────────────

func TestHandleEnforceTest_KnownModule(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/test/injection_shield?severity=HIGH", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	if body["module"] != "injection_shield" {
		t.Errorf("expected module=injection_shield, got %v", body["module"])
	}
	actions, _ := body["actions"].([]interface{})
	if len(actions) == 0 {
		t.Error("expected at least one matching action for HIGH severity on injection_shield")
	}
}

func TestHandleEnforceTest_CriticalSeverity(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/test/ransomware?severity=CRITICAL", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	actions, _ := body["actions"].([]interface{})
	// Balanced ransomware has 3 actions, all at HIGH — CRITICAL should match all
	if len(actions) < 2 {
		t.Errorf("expected multiple matching actions for CRITICAL ransomware, got %d", len(actions))
	}
}

func TestHandleEnforceTest_LowSeverity_NoMatch(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/test/injection_shield?severity=LOW", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	actions, _ := body["actions"].([]interface{})
	// Balanced injection_shield has min_severity HIGH — LOW should not match
	if len(actions) != 0 {
		t.Errorf("expected no matching actions for LOW severity, got %d", len(actions))
	}
}

func TestHandleEnforceTest_UnknownModule_FallsBackToWildcard(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/test/unknown_module?severity=CRITICAL", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	// Should fall back to wildcard policy
	actions, _ := body["actions"].([]interface{})
	if len(actions) == 0 {
		t.Error("expected wildcard policy to match for unknown module with CRITICAL severity")
	}
}

func TestHandleEnforceTest_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/test/injection_shield?severity=HIGH", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceTest_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/test/injection_shield", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Helpers for approval gate tests ─────────────────────────────────────────

func testEngineWithApprovalGate() *core.Engine {
	cfg := core.DefaultConfig()
	cfg.RustEngine.Enabled = false
	cfg.Server.APIKeys = []string{"test-key"}
	cfg.Enforcement = &core.EnforcementConfig{
		Enabled: true,
		DryRun:  false,
		Preset:  "balanced",
		ApprovalGate: core.ApprovalGateConfig{
			Enabled:         true,
			RequireApproval: []string{"kill_process", "quarantine_file", "disable_user"},
			TTL:             30 * 60 * 1000000000, // 30 min in nanoseconds (time.Duration)
			MaxPending:      100,
		},
	}
	logger := zerolog.Nop()
	pipeline := core.NewAlertPipeline(logger, 1000)

	engine := &core.Engine{
		Config:         cfg,
		Registry:       core.NewModuleRegistry(logger),
		Pipeline:       pipeline,
		Logger:         logger,
		ResponseEngine: core.NewResponseEngine(logger, nil, pipeline, cfg),
	}
	return engine
}

// ─── Enforce Approve ─────────────────────────────────────────────────────────

func TestHandleEnforceApprove_Success(t *testing.T) {
	engine := testEngineWithApprovalGate()
	defer engine.ResponseEngine.ApprovalGate.Stop()

	// Submit a pending approval
	ev := core.NewSecurityEvent("test_module", "test_type", core.SeverityCritical, "test")
	alert := core.NewAlert(ev, "Test Alert", "desc")
	rule := core.ResponseRule{Action: core.ActionKillProcess}
	id := engine.ResponseEngine.ApprovalGate.Submit(alert, rule, "pid:1234")

	s := newTestServer(engine)
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/approve/"+id, nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "approved" {
		t.Errorf("expected status=approved, got %v", body["status"])
	}
	if body["action"] != "kill_process" {
		t.Errorf("expected action=kill_process, got %v", body["action"])
	}
}

func TestHandleEnforceApprove_NotFound(t *testing.T) {
	engine := testEngineWithApprovalGate()
	defer engine.ResponseEngine.ApprovalGate.Stop()

	s := newTestServer(engine)
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/approve/nonexistent-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleEnforceApprove_NoApprovalGate(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/approve/some-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceApprove_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/approve/some-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceApprove_MethodNotAllowed(t *testing.T) {
	engine := testEngineWithApprovalGate()
	defer engine.ResponseEngine.ApprovalGate.Stop()

	s := newTestServer(engine)
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/approve/some-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleEnforceApprove_EmptyID(t *testing.T) {
	engine := testEngineWithApprovalGate()
	defer engine.ResponseEngine.ApprovalGate.Stop()

	s := newTestServer(engine)
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/approve/", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ─── Enforce Reject ──────────────────────────────────────────────────────────

func TestHandleEnforceReject_Success(t *testing.T) {
	engine := testEngineWithApprovalGate()
	defer engine.ResponseEngine.ApprovalGate.Stop()

	ev := core.NewSecurityEvent("test_module", "test_type", core.SeverityCritical, "test")
	alert := core.NewAlert(ev, "Test Alert", "desc")
	rule := core.ResponseRule{Action: core.ActionDisableUser}
	id := engine.ResponseEngine.ApprovalGate.Submit(alert, rule, "user:jdoe")

	s := newTestServer(engine)
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/reject/"+id, nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "rejected" {
		t.Errorf("expected status=rejected, got %v", body["status"])
	}
}

func TestHandleEnforceReject_NotFound(t *testing.T) {
	engine := testEngineWithApprovalGate()
	defer engine.ResponseEngine.ApprovalGate.Stop()

	s := newTestServer(engine)
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/reject/nonexistent-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleEnforceReject_NoApprovalGate(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/reject/some-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceReject_MethodNotAllowed(t *testing.T) {
	engine := testEngineWithApprovalGate()
	defer engine.ResponseEngine.ApprovalGate.Stop()

	s := newTestServer(engine)
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/reject/some-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleEnforceReject_EmptyID(t *testing.T) {
	engine := testEngineWithApprovalGate()
	defer engine.ResponseEngine.ApprovalGate.Stop()

	s := newTestServer(engine)
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/reject/", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ─── Enforce Rollback ────────────────────────────────────────────────────────

func TestHandleEnforceRollback_NoEnforcement(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/rollback/some-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleEnforceRollback_RecordNotFound(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/rollback/nonexistent-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleEnforceRollback_NotSuccessStatus(t *testing.T) {
	engine := testEngineWithEnforcement("balanced", true) // dry-run mode
	s := newTestServer(engine)

	// Generate a dry-run record
	ev := core.NewSecurityEvent("injection_shield", "test_type", core.SeverityHigh, "test")
	ev.SourceIP = "10.0.0.1"
	alert := core.NewAlert(ev, "Test Alert", "desc")
	engine.ResponseEngine.HandleAlertForTest(alert)

	records := engine.ResponseEngine.GetRecords(1, "")
	if len(records) == 0 {
		t.Fatal("expected at least one record")
	}

	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/rollback/"+records[0].ID, nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestHandleEnforceRollback_UnsupportedAction(t *testing.T) {
	// Create engine with log_only action in live mode
	cfg := core.DefaultConfig()
	cfg.RustEngine.Enabled = false
	cfg.Server.APIKeys = []string{"test-key"}
	cfg.Enforcement = &core.EnforcementConfig{
		Enabled: true,
		DryRun:  false,
		Policies: map[string]core.ResponsePolicyYAML{
			"test_module": {
				Enabled:          true,
				MinSeverity:      "LOW",
				CooldownSeconds:  0,
				MaxActionsPerMin: 100,
				Actions: []core.ResponseRuleYAML{
					{Action: "log_only", MinSeverity: "LOW"},
				},
			},
		},
	}
	logger := zerolog.Nop()
	pipeline := core.NewAlertPipeline(logger, 1000)
	engine := &core.Engine{
		Config:         cfg,
		Registry:       core.NewModuleRegistry(logger),
		Pipeline:       pipeline,
		Logger:         logger,
		ResponseEngine: core.NewResponseEngine(logger, nil, pipeline, cfg),
	}

	// Generate a SUCCESS log_only record
	ev := core.NewSecurityEvent("test_module", "test_type", core.SeverityHigh, "test")
	alert := core.NewAlert(ev, "Test Alert", "desc")
	engine.ResponseEngine.HandleAlertForTest(alert)

	records := engine.ResponseEngine.GetRecords(1, "")
	if len(records) == 0 {
		t.Fatal("expected at least one record")
	}
	if records[0].Status != core.ActionStatusSuccess {
		t.Fatalf("expected SUCCESS, got %s", records[0].Status)
	}

	s := newTestServer(engine)
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/rollback/"+records[0].ID, nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] == nil {
		t.Error("expected error in response body")
	}
}

func TestHandleEnforceRollback_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodGet, "/api/v1/enforce/rollback/some-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleEnforceRollback_EmptyID(t *testing.T) {
	s := newTestServer(testEngineWithEnforcement("balanced", true))
	req := authReq(httptest.NewRequest(http.MethodPost, "/api/v1/enforce/rollback/", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ─── Auth enforcement on new routes ──────────────────────────────────────────

func TestEnforceRoutes_RequireAuth(t *testing.T) {
	engine := testEngineWithApprovalGate()
	defer engine.ResponseEngine.ApprovalGate.Stop()
	s := newTestServer(engine)

	routes := []string{
		"/api/v1/enforce/approve/test-id",
		"/api/v1/enforce/reject/test-id",
		"/api/v1/enforce/rollback/test-id",
	}

	for _, route := range routes {
		// No auth header — should be rejected
		req := httptest.NewRequest(http.MethodPost, route, nil)
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want %d (missing auth)", route, w.Code, http.StatusUnauthorized)
		}
	}
}

func TestEnforceRoutes_ReadOnlyKeyBlocked(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.RustEngine.Enabled = false
	cfg.Server.APIKeys = []string{"write-key"}
	cfg.Server.ReadOnlyKeys = []string{"read-key"}
	cfg.Enforcement = &core.EnforcementConfig{
		Enabled: true,
		DryRun:  true,
		Preset:  "balanced",
		ApprovalGate: core.ApprovalGateConfig{
			Enabled:         true,
			RequireApproval: []string{"kill_process"},
			TTL:             30 * 60 * 1000000000,
			MaxPending:      100,
		},
	}
	logger := zerolog.Nop()
	pipeline := core.NewAlertPipeline(logger, 1000)
	engine := &core.Engine{
		Config:         cfg,
		Registry:       core.NewModuleRegistry(logger),
		Pipeline:       pipeline,
		Logger:         logger,
		ResponseEngine: core.NewResponseEngine(logger, nil, pipeline, cfg),
	}
	defer engine.ResponseEngine.ApprovalGate.Stop()

	s := newTestServer(engine)

	routes := []string{
		"/api/v1/enforce/approve/test-id",
		"/api/v1/enforce/reject/test-id",
		"/api/v1/enforce/rollback/test-id",
	}

	for _, route := range routes {
		req := httptest.NewRequest(http.MethodPost, route, nil)
		req.Header.Set("Authorization", "Bearer read-key")
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want %d (read-only key should be blocked)", route, w.Code, http.StatusForbidden)
		}
	}
}
