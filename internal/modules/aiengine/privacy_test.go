package aiengine

import (
	"encoding/json"
	"github.com/1sec-project/1sec/internal/core"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBothAIStagesSendOnlyAllowlistedMetadata(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		data, _ := io.ReadAll(r.Body)
		for _, secret := range []string{"summary-secret", "detail-secret", "raw-secret", "source-secret", "test-key"} {
			if strings.Contains(string(data), secret) {
				t.Errorf("outbound content includes %s", secret)
			}
		}
		if r.URL.RawQuery != "" || r.Header.Get("x-goog-api-key") == "" {
			t.Error("credential belongs in header")
		}
		response := `{"score":0.9,"category":"auth","is_false_positive":false}`
		if calls == 2 {
			response = `{"threat_level":0.9,"classification":"auth","summary":"review"}`
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"candidates": []interface{}{map[string]interface{}{"content": map[string]interface{}{"parts": []interface{}{map[string]interface{}{"text": response}}}}}})
	}))
	defer server.Close()
	e := engineWithURL(t, server.URL)
	e.triageURL = server.URL
	e.deepURL = server.URL
	event := core.NewSecurityEvent("auth_fortress", "auth_failure", core.SeverityHigh, "summary-secret")
	event.SourceIP = "source-secret"
	event.RawData = []byte("raw-secret")
	event.Details["nested"] = map[string]interface{}{"password": "detail-secret"}
	if _, _, err := e.runTriage(event); err != nil {
		t.Fatal(err)
	}
	if _, err := e.runDeepAnalysis(&analysisRequest{events: []*core.SecurityEvent{event}, category: "auth", triageScore: .9}); err != nil {
		t.Fatal(err)
	}
	if event.Summary != "summary-secret" || string(event.RawData) != "raw-secret" || len(event.Details) == 0 {
		t.Fatal("source event mutated")
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}
