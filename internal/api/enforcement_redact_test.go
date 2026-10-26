package api

import (
	"github.com/1sec-project/1sec/internal/core"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadKeyCannotReadWebhookPolicySecrets(t *testing.T) {
	engine := testEngineWithEnforcement("balanced", true)
	defer engine.ResponseEngine.Stop()
	engine.Config.Server.ReadOnlyKeys = []string{"monitor"}
	for _, policy := range engine.ResponseEngine.GetPolicies() {
		policy.Actions = append(policy.Actions, core.ResponseRule{Action: core.ActionWebhook, Params: map[string]string{"url": "HTTPS://receiver.example/hooks/capability-secret?key=other-secret", "auth_token": "bearer-secret"}})
		break
	}
	s := newTestServer(engine)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enforce/policies", nil)
	req.Header.Set("Authorization", "Bearer monitor")
	s.server.Handler.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, secret := range []string{"capability-secret", "other-secret", "bearer-secret"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("secret returned to reader", secret)
		}
	}
	found := false
	for _, policy := range engine.ResponseEngine.GetPolicies() {
		for _, rule := range policy.Actions {
			if rule.Params["auth_token"] == "bearer-secret" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("internal execution credential destroyed")
	}
}

func TestDetachedEnforcementViewPreservesJSONNamesAndRetrySecrets(t *testing.T) {
	s := newTestServer(testEngineNoEnforcement())
	delivery := &core.DeadLetterEntry{Delivery: core.WebhookDelivery{URL: "HTTPS://receiver.example/cap-secret", Headers: map[string]string{"Authorization": "Bearer live-secret"}}, LastError: "failed HTTPS://receiver.example/cap-secret"}
	w := httptest.NewRecorder()
	s.writeEnforcementJSON(w, 200, map[string]interface{}{"dead_letters": []*core.DeadLetterEntry{delivery}, "record": core.ResponseRecord{DurationMs: 25}})
	if strings.Contains(w.Body.String(), "live-secret") || strings.Contains(w.Body.String(), "cap-secret") {
		t.Fatal(w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "duration_ms") || !strings.Contains(w.Body.String(), "failed_at") {
		t.Fatal("JSON contract changed", w.Body.String())
	}
	if delivery.Delivery.Headers["Authorization"] != "Bearer live-secret" {
		t.Fatal("retry credential mutated")
	}
}
