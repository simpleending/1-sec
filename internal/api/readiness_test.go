package api

import (
	"github.com/1sec-project/1sec/internal/core"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadinessAndLivenessHaveDifferentFailureSemantics(t *testing.T) {
	engine := testEngine()
	engine.Config.Bus.Port = -1
	engine.Config.Bus.DataDir = t.TempDir()
	bus, err := core.NewEventBus(&engine.Config.Bus, engine.Logger)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	engine.Bus = bus
	s := newTestServer(engine)
	check := func(path string, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Fatalf("%s returned %d: %s", path, w.Code, w.Body.String())
		}
	}
	check("/health", http.StatusOK)
	check("/live", http.StatusOK)
	engine.Config.Archive.Enabled = true
	archiveCfg := core.DefaultArchiveConfig()
	archiveCfg.Enabled = true
	archiveCfg.Dir = t.TempDir()
	engine.Archiver, err = core.NewArchiver(archiveCfg, bus, engine.Logger)
	if err != nil {
		t.Fatal(err)
	}
	// A constructed archive without successful consumer startup is not ready.
	check("/health", http.StatusServiceUnavailable)
	check("/live", http.StatusOK)
	engine.Config.Archive.Enabled = false
	engine.Config.RustEngine.Enabled = true
	check("/health", http.StatusServiceUnavailable)
	check("/live", http.StatusOK)
	engine.Config.RustEngine.Enabled = false
	bus.Close()
	check("/health", http.StatusServiceUnavailable)
	check("/live", http.StatusOK)
}
