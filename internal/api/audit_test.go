package api

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
)

const auditAPIToken = core.AuditTokenPrefix + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func apiAuditFixture(t *testing.T, source *Server, required bool, hook func(core.AuditRecord)) (*Server, *[]core.AuditRecord, *sync.Mutex) {
	t.Helper()
	receiver := NewServer(testEngine())
	receiver.engine.Config.AuditReceiver.Enabled = true
	r, err := core.NewAuditReceiver(core.AuditReceiverConfig{Dir: t.TempDir(), Sources: []core.AuditSource{{ID: "source-a", Token: auditAPIToken}}})
	if err != nil {
		t.Fatal(err)
	}
	receiver.engine.AuditReceiver = r
	t.Cleanup(func() { _ = r.Close() })
	var records []core.AuditRecord
	mu := &sync.Mutex{}
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		var record core.AuditRecord
		_ = json.Unmarshal(body, &record)
		if hook != nil {
			hook(record)
		}
		mu.Lock()
		records = append(records, record)
		mu.Unlock()
		receiver.server.Handler.ServeHTTP(w, req)
	}))
	t.Cleanup(sink.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sink.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	source.engine.Config.Audit = core.AuditConfig{Enabled: true, SourceID: "source-a", Dir: t.TempDir(), AuthToken: auditAPIToken, Endpoint: sink.URL + "/api/v1/audit/ingest", CAFile: ca, RequireRemoteAck: required}
	a, err := core.NewAuditService(source.engine.Config.Audit)
	if err != nil {
		t.Fatal(err)
	}
	source.engine.Audit = a
	t.Cleanup(func() { _ = a.Close() })
	return receiver, &records, mu
}

func TestDurableAuditHTTPIntentOutcomeAndSecretMinimization(t *testing.T) {
	s := operatorServer(t)
	key := operatorKey(t, s, "alice@example.com", "administrator")
	_, records, mu := apiAuditFixture(t, s, true, nil)
	secret := "payload-secret-must-not-be-logged"
	w := operatorRequest(s, "POST", "/api/v1/operators?token=query-secret", key, `{"id":"bob","role":"viewer"}`)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	var result struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Token == "" {
		t.Fatal("token not returned")
	}
	if w := operatorRequest(s, "PATCH", "/api/v1/operators/bob", key, `{"role":"viewer","unexpected_secret":"`+secret+`"}`); w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
	status := s.engine.Audit.Status()
	if err := s.engine.Audit.ExportThrough(context.Background(), status.Records); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	data, _ := json.Marshal(*records)
	copyRecords := append([]core.AuditRecord(nil), (*records)...)
	mu.Unlock()
	for _, value := range []string{key, result.Token, auditAPIToken, secret, "query-secret"} {
		if strings.Contains(string(data), value) {
			t.Fatal("secret entered durable audit")
		}
	}
	var intent, outcome *core.AuditRecord
	for i := range copyRecords {
		r := &copyRecords[i]
		if r.Event.Route == "/api/v1/operators" && r.Event.Kind == "request_intent" {
			intent = r
		}
		if r.Event.Route == "/api/v1/operators" && r.Event.Kind == "request_result" {
			outcome = r
		}
	}
	if intent == nil || outcome == nil || intent.Event.Actor != "alice@example.com" || intent.Event.CredentialID == "" || intent.Event.RequestID != outcome.Event.RequestID || outcome.Event.Status != 201 {
		t.Fatal("named attribution or intent/result link missing")
	}
	if w := operatorRequest(s, "GET", "/api/v1/audit/status", key, ""); w.Code != 200 || strings.Contains(w.Body.String(), auditAPIToken) || !strings.Contains(w.Body.String(), `"acknowledged"`) {
		t.Fatal(w.Code, w.Body)
	}
}

func TestDurableAuditHTTPRechecksAuthorityAfterBodyAndReceipt(t *testing.T) {
	for _, mode := range []string{"body", "receipt"} {
		t.Run(mode, func(t *testing.T) {
			s := operatorServer(t)
			key := operatorKey(t, s, "first", "administrator")
			_ = operatorKey(t, s, "second", "administrator")
			hook := func(record core.AuditRecord) {
				if mode == "receipt" && record.Event.Kind == "request_intent" {
					if err := s.engine.Operators.SetRole("first", "viewer"); err != nil {
						t.Error(err)
					}
				}
			}
			apiAuditFixture(t, s, true, hook)
			var body io.Reader = strings.NewReader(`{}`)
			if mode == "body" {
				body = &operatorRevokingBody{reader: strings.NewReader(`{}`), revoke: func() {
					if err := s.engine.Operators.SetRole("first", "viewer"); err != nil {
						t.Error(err)
					}
				}}
			}
			called := false
			next := s.auditMutation(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			handler := s.operatorAuthMiddleware(next, authMiddleware(next, s.engine.Config, s.logger, s.engine.Sensors))
			r := httptest.NewRequest("POST", "/api/v1/enforce/config", body)
			r.RemoteAddr = "127.0.0.1:1234"
			r.Header.Set("Authorization", "Bearer "+key)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 403 || called {
				t.Fatal("obsolete role passed mutation fence", w.Code)
			}
		})
	}
}

func TestDurableAuditHTTPStorageFailureBlocksMutationsButNotReads(t *testing.T) {
	s := operatorServer(t)
	key := operatorKey(t, s, "admin", "administrator")
	apiAuditFixture(t, s, true, nil)
	if err := s.engine.Audit.Close(); err != nil {
		t.Fatal(err)
	}
	if w := operatorRequest(s, "POST", "/api/v1/operators", key, `{"id":"new-admin","role":"administrator"}`); w.Code != 503 {
		t.Fatal(w.Code, w.Body)
	}
	if len(s.engine.Operators.List()) != 1 {
		t.Fatal("unrecorded grant committed")
	}
	if w := operatorRequest(s, "GET", "/api/v1/operators/me", key, ""); w.Code != 200 {
		t.Fatal("audit failure blocked investigative reads", w.Code)
	}
	if w := operatorRequest(s, "GET", "/api/v1/audit/status", key, ""); !strings.Contains(w.Body.String(), `"ready":false`) {
		t.Fatal("failure hidden", w.Body)
	}
}

func TestDurableAuditReceiverHTTPIsolationAndBoundaries(t *testing.T) {
	s := operatorServer(t)
	key := operatorKey(t, s, "admin", "administrator")
	receiver, records, mu := apiAuditFixture(t, s, true, nil)
	if err := s.engine.Audit.ExportThrough(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	record := (*records)[0]
	mu.Unlock()
	body, _ := json.Marshal(record)
	request := func(method, token string, payload []byte, remote string, extra bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/audit/ingest", bytes.NewReader(payload))
		r.RemoteAddr = remote
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-Forwarded-Proto", "https")
		if extra {
			r.Header.Set("X-API-Key", key)
		}
		w := httptest.NewRecorder()
		receiver.server.Handler.ServeHTTP(w, r)
		return w
	}
	if w := request("POST", auditAPIToken, body, "127.0.0.1:1234", false); w.Code != 200 {
		t.Fatal("durable retry rejected", w.Code, w.Body)
	}
	for _, token := range []string{key, "legacy-write", core.AuditTokenPrefix + strings.Repeat("x", 43)} {
		if w := request("POST", token, body, "127.0.0.1:1234", false); w.Code != 403 {
			t.Fatal("foreign credential accepted", w.Code)
		}
	}
	if w := request("POST", auditAPIToken, body, "198.51.100.4:1234", false); w.Code != 403 {
		t.Fatal("forwarded TLS spoof accepted", w.Code)
	}
	if w := request("POST", auditAPIToken, body, "127.0.0.1:1234", true); w.Code != 403 {
		t.Fatal("ambiguous headers accepted", w.Code)
	}
	if w := request("GET", auditAPIToken, nil, "127.0.0.1:1234", false); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w := request("POST", auditAPIToken, append(body, []byte(` {}`)...), "127.0.0.1:1234", false); w.Code != 400 {
		t.Fatal("trailing object accepted", w.Code)
	}
	spoofed := append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"received_at":"2000-01-01T00:00:00Z"}`)...)
	if w := request("POST", auditAPIToken, spoofed, "127.0.0.1:1234", false); w.Code != 400 {
		t.Fatal("producer supplied collector timestamp", w.Code)
	}
	if w := request("POST", auditAPIToken, []byte(strings.Repeat("x", 17000)), "127.0.0.1:1234", false); w.Code != 400 {
		t.Fatal("oversized body accepted", w.Code)
	}
	record.SourceID = "victim"
	body, _ = json.Marshal(record)
	if w := request("POST", auditAPIToken, body, "127.0.0.1:1234", false); w.Code != 403 {
		t.Fatal("source credential not bound", w.Code)
	}
	// Even an otherwise open read surface must reject this credential type.
	receiver.engine.Config.Server.APIKeys = nil
	receiver.engine.Config.Server.ReadOnlyKeys = nil
	if w := operatorRequest(receiver, "GET", "/api/v1/config", auditAPIToken, ""); w.Code != 403 {
		t.Fatal("collector credential read management API", w.Code)
	}
}

func TestDurableAuditStandaloneCollectorHasNoManagementSurface(t *testing.T) {
	s := operatorServer(t)
	receiver, records, mu := apiAuditFixture(t, s, true, nil)
	if err := s.engine.Audit.ExportThrough(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	body, _ := json.Marshal((*records)[0])
	mu.Unlock()
	collector := NewAuditCollectorServer(receiver.engine.Config, receiver.engine.AuditReceiver)
	for _, path := range []string{"/api/v1/config", "/api/v1/operators", "/api/v1/shutdown", "/api/v1/audit/status", "/ui/"} {
		r := httptest.NewRequest("POST", path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Authorization", "Bearer "+auditAPIToken)
		w := httptest.NewRecorder()
		collector.Handler.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("collector exposed control surface", path, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api/v1/audit/ingest", bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Authorization", "Bearer "+auditAPIToken)
	w := httptest.NewRecorder()
	collector.Handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	collector.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
}

func TestDurableAuditPermissionFenceAlsoAppliesWithoutAuditing(t *testing.T) {
	s := operatorServer(t)
	key := operatorKey(t, s, "first", "administrator")
	_ = operatorKey(t, s, "second", "administrator")
	body := &operatorRevokingBody{reader: strings.NewReader(`{}`), revoke: func() {
		if err := s.engine.Operators.SetRole("first", "viewer"); err != nil {
			t.Fatal(err)
		}
	}}
	called := false
	next := s.auditMutation(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	handler := s.operatorAuthMiddleware(next, authMiddleware(next, s.engine.Config, s.logger, s.engine.Sensors))
	r := httptest.NewRequest("POST", "/api/v1/enforce/config", body)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 || called {
		t.Fatal("auditing-disabled configuration retained obsolete permissions", w.Code)
	}
}
