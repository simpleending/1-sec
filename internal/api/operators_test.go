package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
)

func operatorServer(t *testing.T) *Server {
	t.Helper()
	e := testEngine()
	e.Config.Operators.Enabled = true
	r, err := core.NewOperatorRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	e.Operators = r
	return NewServer(e)
}
func operatorRequest(s *Server, method, path, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, r)
	return w
}
func operatorKey(t *testing.T, s *Server, id, role string) string {
	t.Helper()
	_, key, err := s.engine.Operators.Enroll(core.OperatorSpec{ID: id, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func TestOperatorHTTPPermissionMatrix(t *testing.T) {
	s := operatorServer(t)
	cases := []struct {
		method, path string
		roles        string
	}{
		{"GET", "/api/v1/status", "viewer analyst responder sensor_manager integration administrator"},
		{"GET", "/api/v1/config", "viewer analyst responder sensor_manager integration administrator"},
		{"POST", "/api/v1/alerts/clear", "administrator"},
		{"DELETE", "/api/v1/alerts/id", "administrator"},
		{"PATCH", "/api/v1/alerts/id", "analyst responder administrator"},
		{"POST", "/api/v1/enforce/approve/id", "responder administrator"},
		{"POST", "/api/v1/enforce/reject/id", "responder administrator"},
		{"POST", "/api/v1/enforce/rollback/id", "responder administrator"},
		{"POST", "/api/v1/enforce/config", "administrator"},
		{"POST", "/api/v1/enforce/dry-run/off", "administrator"},
		{"POST", "/api/v1/enforce/policies/runtime_watcher/disable", "administrator"},
		{"POST", "/api/v1/enforce/test/network", "analyst responder administrator"},
		{"POST", "/api/v1/enforce/webhooks/retry/id", "responder administrator"},
		{"POST", "/api/v1/sensors", "sensor_manager administrator"},
		{"POST", "/api/v1/sensors/id/rotate", "sensor_manager administrator"},
		{"POST", "/api/v1/operators", "administrator"},
		{"GET", "/api/v1/operators", "administrator"},
		{"PATCH", "/api/v1/operators/id", "administrator"},
		{"POST", "/api/v1/events", "integration administrator"},
		{"POST", "/api/v1/access/check", "integration administrator"},
		{"POST", "/api/v1/token-vault/exchange", "integration administrator"},
		{"POST", "/api/v1/config/reload", "administrator"},
		{"POST", "/api/v1/shutdown", "administrator"},
		{"POST", "/api/v1/status", ""}, {"GET", "/api/v1/new-unclassified", ""},
		{"POST", "/api/v1//enforce/approve/id", ""}, {"POST", "/api/v1/enforce%2fapprove/id", "responder administrator"},
	}
	// Use a harmless downstream spy for the complete route matrix, including
	// shutdown and live-response paths. No destructive handler is executed.
	spy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	handler := s.operatorAuthMiddleware(spy, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("named credential reached legacy auth") }))
	for _, role := range strings.Fields("viewer analyst responder sensor_manager integration administrator") {
		key := operatorKey(t, s, role, role)
		for _, tc := range cases {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.RemoteAddr = "127.0.0.1:1234"
			r.Header.Set("Authorization", "Bearer "+key)
			r.Header.Set("X-Operator-Role", "administrator")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			want := 403
			for _, allowed := range strings.Fields(tc.roles) {
				if allowed == role {
					want = 204
				}
			}
			if w.Code != want {
				t.Errorf("%s %s %s: got %d want %d", role, tc.method, tc.path, w.Code, want)
			}
		}
	}
}
func TestOperatorHTTPLifecycleAndIdentity(t *testing.T) {
	s := operatorServer(t)
	created := operatorRequest(s, "POST", "/api/v1/operators", "test-key", `{"id":"alice@example.com","role":"responder"}`)
	if created.Code != 201 || created.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(created.Code, created.Body)
	}
	var issued struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(created.Body.Bytes(), &issued) != nil || issued.Token == "" {
		t.Fatal("missing one-time token")
	}
	admin := operatorKey(t, s, "admin", "administrator")
	viewer := operatorKey(t, s, "viewer", "viewer")
	me := operatorRequest(s, "GET", "/api/v1/operators/me", issued.Token, "")
	if me.Code != 200 || !bytes.Contains(me.Body.Bytes(), []byte("alice@example.com")) || bytes.Contains(me.Body.Bytes(), []byte(issued.Token)) {
		t.Fatal(me.Code, me.Body)
	}
	if got := operatorRequest(s, "GET", "/api/v1/operators", viewer, ""); got.Code != 403 {
		t.Fatal("viewer listed operators", got.Code)
	}
	if got := operatorRequest(s, "PATCH", "/api/v1/operators/alice@example.com", admin, `{"role":"viewer"}`); got.Code != 200 {
		t.Fatal(got.Code, got.Body)
	}
	if got := operatorRequest(s, "POST", "/api/v1/enforce/approve/id", issued.Token, ""); got.Code != 403 {
		t.Fatal("downgrade did not apply", got.Code)
	}
	rotated := operatorRequest(s, "POST", "/api/v1/operators/alice@example.com/rotate", admin, "")
	if rotated.Code != 200 {
		t.Fatal(rotated.Code, rotated.Body)
	}
	if got := operatorRequest(s, "GET", "/api/v1/status", issued.Token, ""); got.Code != 403 {
		t.Fatal("rotated key accepted")
	}
	if json.Unmarshal(rotated.Body.Bytes(), &issued) != nil {
		t.Fatal("invalid rotation")
	}
	if got := operatorRequest(s, "POST", "/api/v1/operators/alice@example.com/revoke", admin, ""); got.Code != 200 {
		t.Fatal(got.Code, got.Body)
	}
	if got := operatorRequest(s, "GET", "/api/v1/status", issued.Token, ""); got.Code != 403 {
		t.Fatal("revoked key accepted")
	}
	list := operatorRequest(s, "GET", "/api/v1/operators", admin, "")
	if bytes.Contains(list.Body.Bytes(), []byte("credential_hash")) || bytes.Contains(list.Body.Bytes(), []byte(admin)) {
		t.Fatal("operator secrets disclosed")
	}
}
func TestOperatorStrictAndTransportAdmission(t *testing.T) {
	s := operatorServer(t)
	key := operatorKey(t, s, "viewer", "viewer")
	s.engine.Config.Operators.RequireNamed = true
	for _, token := range []string{"", "test-key", "bad", core.OperatorTokenPrefix + "fake"} {
		if got := operatorRequest(s, "GET", "/api/v1/status", token, ""); got.Code != 403 {
			t.Fatal("strict fallback", token, got.Code)
		}
	}
	if got := operatorRequest(s, "GET", "/api/v1/status", key, ""); got.Code != 200 {
		t.Fatal(got.Code, got.Body)
	}
	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	r.RemoteAddr = "192.0.2.1:42"
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("untrusted TLS header admitted operator")
	}
	r.RemoteAddr = "127.0.0.1:42"
	r.Header.Set("X-API-Key", key)
	w = httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("ambiguous headers admitted")
	}
	_ = s.engine.Operators.Close()
	if got := operatorRequest(s, "GET", "/api/v1/status", key, ""); got.Code != 503 {
		t.Fatal("unavailable registry accepted")
	}
	if got := operatorRequest(s, "GET", "/live", "", ""); got.Code != 200 {
		t.Fatal("liveness requires credential")
	}
}
func TestOperatorSensorGrantSeparation(t *testing.T) {
	s := operatorServer(t)
	registry, err := core.NewSensorRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	s.engine.Sensors = registry
	manager := operatorKey(t, s, "provisioner", "sensor_manager")
	admin := operatorKey(t, s, "admin", "administrator")
	body := `{"id":"observer","host_id":"remote-host","scopes":[{"module":"endpoint","type":"process_exec"}]}`
	if got := operatorRequest(s, "POST", "/api/v1/sensors", manager, body); got.Code != 201 {
		t.Fatal(got.Code, got.Body)
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	body = fmt.Sprintf(`{"id":"local","host_id":%q,"allow_local_response":true,"scopes":[{"module":"endpoint","type":"process_exec"}]}`, host)
	if got := operatorRequest(s, "POST", "/api/v1/sensors", manager, body); got.Code != 403 {
		t.Fatal("sensor manager granted containment", got.Code)
	}
	if got := operatorRequest(s, "POST", "/api/v1/sensors", admin, body); got.Code != 201 {
		t.Fatal(got.Code, got.Body)
	}
	if got := operatorRequest(s, "POST", "/api/v1/sensors/local/rotate", manager, ""); got.Code != 403 {
		t.Fatal("sensor manager obtained containment credential")
	}
	if got := operatorRequest(s, "POST", "/api/v1/sensors/local/revoke", manager, ""); got.Code != 200 {
		t.Fatal("sensor manager cannot revoke", got.Code)
	}
}
func TestOperatorEnrollmentRejectsForgedFields(t *testing.T) {
	s := operatorServer(t)
	for _, body := range []string{`{"id":"a","role":"root"}`, `{"id":"a","role":"viewer","permissions":["operators.manage"]}`, `{"id":"a","role":"viewer"}{}`, `{"id":"a","role":"viewer","credential_hash":"forged"}`} {
		if got := operatorRequest(s, "POST", "/api/v1/operators", "test-key", body); got.Code != 400 {
			t.Fatal("invalid grant accepted", got.Code, got.Body)
		}
	}
}

func TestOperatorPermissionCoverageIncludesEveryAPIRoute(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "HandleFunc" || len(call.Args) < 1 {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		path, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(path, "/api/v1/") {
			return true
		}
		if strings.HasSuffix(path, "/") {
			path += "fixture"
		}
		covered := false
		for _, method := range []string{"GET", "POST", "PATCH", "DELETE"} {
			_, ok := requiredPermission(path, method)
			covered = covered || ok
		}
		if !covered {
			t.Errorf("unclassified API route %s", path)
		}
		return true
	})
}

func TestOperatorApprovalUsesCredentialIdentity(t *testing.T) {
	s := operatorServer(t)
	gate := core.NewApprovalGate(s.engine.Logger, core.DefaultApprovalGateConfig())
	defer gate.Stop()
	s.engine.ResponseEngine = &core.ResponseEngine{ApprovalGate: gate}
	key := operatorKey(t, s, "alice@example.com", "responder")
	event := core.NewSecurityEvent("network_guardian", "test", core.SeverityHigh, "fixture")
	id := gate.Submit(core.NewAlert(event, "fixture", "fixture"), core.ResponseRule{Action: core.ActionBlockIP}, "198.51.100.4")
	r := httptest.NewRequest("POST", "/api/v1/enforce/approve/"+id, strings.NewReader(`{"decided_by":"forged-admin"}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("X-Operator-ID", "forged-admin")
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"decided_by":"operator:alice@example.com"`) {
		t.Fatal(w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "forged-admin") {
		t.Fatal("caller selected decision actor")
	}
	if got := operatorRequest(s, "GET", "/api/v1/ui-access", key, ""); got.Code != 200 || !strings.Contains(got.Body.String(), `"scope":"operator"`) || !strings.Contains(got.Body.String(), "approvals.decide") {
		t.Fatal(got.Code, got.Body)
	}
}

type operatorRevokingBody struct {
	reader io.Reader
	revoke func()
	done   bool
}

func (b *operatorRevokingBody) Read(p []byte) (int, error) {
	if !b.done {
		b.done = true
		b.revoke()
	}
	return b.reader.Read(p)
}
func TestOperatorRevocationDuringRequestBodyCannotCreateAdministrator(t *testing.T) {
	s := operatorServer(t)
	first := operatorKey(t, s, "first", "administrator")
	_ = operatorKey(t, s, "second", "administrator")
	body := &operatorRevokingBody{reader: strings.NewReader(`{"id":"backdoor","role":"administrator"}`), revoke: func() {
		if err := s.engine.Operators.Revoke("first"); err != nil {
			t.Fatal(err)
		}
	}}
	r := httptest.NewRequest("POST", "/api/v1/operators", body)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Authorization", "Bearer "+first)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("revoked in-flight administrator created credential", w.Code, w.Body)
	}
	for _, info := range s.engine.Operators.List() {
		if info.ID == "backdoor" {
			t.Fatal("backdoor identity persisted")
		}
	}
}
