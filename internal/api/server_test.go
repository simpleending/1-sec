package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

// testEngine builds a minimal Engine suitable for handler tests.
// It does NOT start NATS — only the Pipeline, Registry, Config, and Logger are wired.
func testEngine() *core.Engine {
	cfg := core.DefaultConfig()
	cfg.RustEngine.Enabled = false
	cfg.Server.APIKeys = []string{"test-key"} // enable auth so mutating endpoint tests work
	logger := zerolog.Nop()

	return &core.Engine{
		Config:   cfg,
		Registry: core.NewModuleRegistry(logger),
		Pipeline: core.NewAlertPipeline(logger, 1000),
		Logger:   logger,
	}
}

// testEngineWithAuth returns an engine whose config has API keys set.
func testEngineWithAuth(keys ...string) *core.Engine {
	e := testEngine()
	e.Config.Server.APIKeys = keys
	return e
}

// newTestServer creates a Server with the given engine and returns its internal mux
// wrapped in the middleware chain, ready for httptest.
func newTestServer(engine *core.Engine) *Server {
	return NewServer(engine)
}

// authedReq adds the default test API key to a request.
func authedReq(req *http.Request) *http.Request {
	req.Header.Set("Authorization", "Bearer test-key")
	return req
}

// ─── writeJSON ────────────────────────────────────────────────────────────────

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"hello": "world"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["hello"] != "world" {
		t.Errorf("body = %v", body)
	}
}

// ─── Health endpoint ──────────────────────────────────────────────────────────

func TestHandleHealth_GET(t *testing.T) {
	s := newTestServer(testEngine())
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("unstarted engine status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "degraded" {
		t.Errorf("status = %v, want degraded", body["status"])
	}
}

func TestHandleHealth_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Health bypasses auth ─────────────────────────────────────────────────────

func TestHandleHealth_BypassesAuth(t *testing.T) {
	s := newTestServer(testEngineWithAuth("secret-key"))
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	// No auth header
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("health should bypass auth, got status %d", w.Code)
	}
}

// ─── Auth middleware ──────────────────────────────────────────────────────────

func TestAuthMiddleware_NoKeysConfigured(t *testing.T) {
	// Build an engine with no API keys to test open mode
	cfg := core.DefaultConfig()
	cfg.RustEngine.Enabled = false
	cfg.Server.APIKeys = nil // explicitly no keys = open mode
	logger := zerolog.Nop()
	openEngine := &core.Engine{
		Config:   cfg,
		Registry: core.NewModuleRegistry(logger),
		Pipeline: core.NewAlertPipeline(logger, 1000),
		Logger:   logger,
	}
	s := newTestServer(openEngine)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("open mode should allow read-only, got status %d", w.Code)
	}
}

func TestAuthMiddleware_NoKeysNonLoopbackBlocksRead(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.APIKeys = nil
	cfg.Server.ReadOnlyKeys = nil
	logger := zerolog.Nop()
	openEngine := &core.Engine{
		Config:   cfg,
		Registry: core.NewModuleRegistry(logger),
		Pipeline: core.NewAlertPipeline(logger, 1000),
		Logger:   logger,
	}

	s := newTestServer(openEngine)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("non-loopback no-key read should return 403, got %d", w.Code)
	}
}

func TestAuthMiddleware_NoKeysNonLoopbackExplicitAllowRead(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.AllowUnauthenticatedRead = true
	cfg.Server.APIKeys = nil
	cfg.Server.ReadOnlyKeys = nil
	logger := zerolog.Nop()
	openEngine := &core.Engine{
		Config:   cfg,
		Registry: core.NewModuleRegistry(logger),
		Pipeline: core.NewAlertPipeline(logger, 1000),
		Logger:   logger,
	}

	s := newTestServer(openEngine)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("explicit allow should permit read-only open mode, got %d", w.Code)
	}
}

func TestAuthMiddleware_MissingKey(t *testing.T) {
	s := newTestServer(testEngineWithAuth("my-secret"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing key should return 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_InvalidKey(t *testing.T) {
	s := newTestServer(testEngineWithAuth("my-secret"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("invalid key should return 403, got %d", w.Code)
	}
}

func TestAuthMiddleware_ValidBearerKey(t *testing.T) {
	s := newTestServer(testEngineWithAuth("my-secret"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set("Authorization", "Bearer my-secret")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("valid bearer key should return 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_XAPIKeyHeader(t *testing.T) {
	s := newTestServer(testEngineWithAuth("my-secret"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set("X-API-Key", "my-secret")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("valid X-API-Key should return 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_ReadOnlyOnlyDeployment(t *testing.T) {
	engine := testEngineWithAuth()
	engine.Config.Server.APIKeys = nil
	engine.Config.Server.ReadOnlyKeys = []string{"read-secret"}
	s := newTestServer(engine)

	readReq := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	readReq.Header.Set("Authorization", "Bearer read-secret")
	readW := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(readW, readReq)
	if readW.Code != http.StatusOK {
		t.Fatalf("read-only key should read config, got %d", readW.Code)
	}

	writeReq := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/clear", nil)
	writeReq.Header.Set("Authorization", "Bearer read-secret")
	writeW := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(writeW, writeReq)
	if writeW.Code != http.StatusForbidden {
		t.Fatalf("read-only key should not mutate, got %d", writeW.Code)
	}
}

func TestAuthMiddleware_InvalidXAPIKey(t *testing.T) {
	s := newTestServer(testEngineWithAuth("my-secret"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set("X-API-Key", "wrong")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("invalid X-API-Key should return 403, got %d", w.Code)
	}
}

// ─── Config endpoint ──────────────────────────────────────────────────────────

func TestHandleConfig_GET(t *testing.T) {
	engine := testEngine()
	engine.Config.Server.APIKeys = []string{"test-key", "write-secret"}
	engine.Config.Server.ReadOnlyKeys = []string{"read-secret"}
	engine.Config.Cloud.APIKey = "cloud-secret"
	engine.Config.TokenVault.Auth0ClientSecret = "auth0-secret"
	engine.Config.Modules["ai_analysis_engine"] = core.ModuleConfig{
		Enabled: true,
		Settings: map[string]interface{}{
			"gemini_api_key": "gemini-secret",
		},
	}
	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	for _, secret := range []string{"test-key", "write-secret", "read-secret", "cloud-secret", "auth0-secret", "gemini-secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("config response leaked secret %q in body: %s", secret, body)
		}
	}
	if !strings.Contains(body, core.RedactedValue) {
		t.Fatalf("config response should contain redaction marker, body: %s", body)
	}
}

func TestHandleConfig_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/config", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Modules endpoint ─────────────────────────────────────────────────────────

func TestHandleModules_GET(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/modules", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["modules"] == nil {
		t.Error("expected modules key in response")
	}
}

// ─── Alerts endpoint ──────────────────────────────────────────────────────────

func TestHandleAlerts_GET_Empty(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	total := body["total"].(float64)
	if total != 0 {
		t.Errorf("total = %v, want 0", total)
	}
}

func TestHandleAlerts_GET_WithAlerts(t *testing.T) {
	engine := testEngine()
	ev := core.NewSecurityEvent("test", "test_type", core.SeverityHigh, "test event")
	alert := core.NewAlert(ev, "Test Alert", "A test alert")
	engine.Pipeline.Process(alert)

	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	total := body["total"].(float64)
	if total != 1 {
		t.Errorf("total = %v, want 1", total)
	}
}

func TestHandleAlerts_GET_WithLimit(t *testing.T) {
	engine := testEngine()
	for i := 0; i < 5; i++ {
		ev := core.NewSecurityEvent("test", "test_type", core.SeverityHigh, "test")
		alert := core.NewAlert(ev, "Alert", "desc")
		engine.Pipeline.Process(alert)
	}

	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/alerts?limit=2", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	total := body["total"].(float64)
	if total != 2 {
		t.Errorf("total = %v, want 2", total)
	}
}

func TestHandleAlerts_GET_WithSeverityFilter(t *testing.T) {
	engine := testEngine()
	evLow := core.NewSecurityEvent("test", "test_type", core.SeverityLow, "low")
	engine.Pipeline.Process(core.NewAlert(evLow, "Low Alert", "low"))
	evHigh := core.NewSecurityEvent("test", "test_type", core.SeverityHigh, "high")
	engine.Pipeline.Process(core.NewAlert(evHigh, "High Alert", "high"))

	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/alerts?min_severity=HIGH", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	total := body["total"].(float64)
	if total != 1 {
		t.Errorf("total = %v, want 1 (only HIGH)", total)
	}
}

func TestHandleAlerts_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodPut, "/api/v1/alerts", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ─── Alert by ID ──────────────────────────────────────────────────────────────

func TestHandleAlertByID_GET(t *testing.T) {
	engine := testEngine()
	ev := core.NewSecurityEvent("test", "test_type", core.SeverityHigh, "test")
	alert := core.NewAlert(ev, "Test Alert", "desc")
	engine.Pipeline.Process(alert)

	s := newTestServer(engine)
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/alerts/"+alert.ID, nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleAlertByID_GET_NotFound(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/alerts/nonexistent-id", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleAlertByID_PATCH(t *testing.T) {
	engine := testEngine()
	ev := core.NewSecurityEvent("test", "test_type", core.SeverityHigh, "test")
	alert := core.NewAlert(ev, "Test Alert", "desc")
	engine.Pipeline.Process(alert)

	s := newTestServer(engine)
	body := `{"status":"ACKNOWLEDGED"}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/alerts/"+alert.ID, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleAlertByID_PATCH_InvalidStatus(t *testing.T) {
	engine := testEngine()
	ev := core.NewSecurityEvent("test", "test_type", core.SeverityHigh, "test")
	alert := core.NewAlert(ev, "Test Alert", "desc")
	engine.Pipeline.Process(alert)

	s := newTestServer(engine)
	body := `{"status":"INVALID"}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/alerts/"+alert.ID, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleAlertByID_DELETE(t *testing.T) {
	engine := testEngine()
	ev := core.NewSecurityEvent("test", "test_type", core.SeverityHigh, "test")
	alert := core.NewAlert(ev, "Test Alert", "desc")
	engine.Pipeline.Process(alert)

	s := newTestServer(engine)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/alerts/"+alert.ID, nil)
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	// Verify it's gone
	if engine.Pipeline.GetAlertByID(alert.ID) != nil {
		t.Error("alert should be deleted")
	}
}

func TestHandleAlertByID_DELETE_NotFound(t *testing.T) {
	s := newTestServer(testEngine())
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/alerts/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// ─── Alerts Clear ─────────────────────────────────────────────────────────────

func TestHandleAlertsClear(t *testing.T) {
	engine := testEngine()
	for i := 0; i < 3; i++ {
		ev := core.NewSecurityEvent("test", "test_type", core.SeverityHigh, "test")
		engine.Pipeline.Process(core.NewAlert(ev, "Alert", "desc"))
	}

	s := newTestServer(engine)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/clear", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["cleared"].(float64) != 3 {
		t.Errorf("cleared = %v, want 3", body["cleared"])
	}
}

// ─── Logs endpoint ────────────────────────────────────────────────────────────

func TestHandleLogs_GET(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/logs", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	// Engine has no logBuffer in test mode, so GetLogEntries returns empty
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// ─── CORS middleware ──────────────────────────────────────────────────────────

func TestCORSMiddleware_Wildcard(t *testing.T) {
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil) // nil = no origins configured = deny cross-origin (secure default)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("ACAO = %q, want empty (no CORS when no origins configured)", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_AllowedOrigin(t *testing.T) {
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), []string{"http://example.com"})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Errorf("ACAO = %q, want http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_BlockedOrigin(t *testing.T) {
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), []string{"http://allowed.com"})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://evil.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("blocked origin should not get ACAO header, got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_Preflight(t *testing.T) {
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), []string{"*"})

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

// ─── Token bucket ─────────────────────────────────────────────────────────────

func TestTokenBucket_Allow(t *testing.T) {
	tb := &tokenBucket{
		tokens:    10,
		maxTokens: 10,
	}
	// Should allow first request
	if !tb.allow(10) {
		t.Error("expected first request to be allowed")
	}
}

func TestTokenBucket_Exhausted(t *testing.T) {
	tb := &tokenBucket{
		tokens:    1,
		maxTokens: 10,
	}
	tb.allow(0) // consume the 1 token
	if tb.allow(0) {
		t.Error("expected exhausted bucket to deny")
	}
}

// ─── IngestEvent endpoint ─────────────────────────────────────────────────────
// Note: IngestEvent requires a working Bus (PublishEvent), so we test the
// validation path (bad JSON) which doesn't need the bus.

func TestHandleIngestEvent_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleIngestEvent_BadJSON(t *testing.T) {
	s := newTestServer(testEngine())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString("not json"))
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ─── Shutdown endpoint ────────────────────────────────────────────────────────

func TestHandleShutdown_MethodNotAllowed(t *testing.T) {
	s := newTestServer(testEngine())
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/shutdown", nil))
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}
