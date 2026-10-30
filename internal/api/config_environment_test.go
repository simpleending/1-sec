package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
)

func TestMissingConfigEnvironmentKeyProtectsReadAPI(t *testing.T) {
	t.Setenv("ONESEC_API_KEY", "test-environment-key")
	cfg, err := core.LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	engine := testEngine()
	engine.Config = cfg
	s := newTestServer(engine)
	for _, key := range []string{"", "wrong", "test-environment-key"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, req)
		want := http.StatusUnauthorized
		if key == "wrong" {
			want = http.StatusForbidden
		}
		if key == "test-environment-key" {
			want = http.StatusOK
		}
		if w.Code != want {
			t.Errorf("key %q: got %d, want %d", key, w.Code, want)
		}
	}
}
