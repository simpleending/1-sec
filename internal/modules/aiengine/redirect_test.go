package aiengine

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCallGeminiRejectsCredentialRedirect(t *testing.T) {
	for _, status := range []int{302, 307, 308} {
		var received atomic.Int32
		sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
		issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("x-goog-api-key") == "" {
				t.Error("missing test API key")
			}
			w.Header().Set("Location", sink.URL)
			w.WriteHeader(status)
		}))
		e := engineWithURL(t, issuer.URL)
		_, err := e.callGemini(issuer.URL, "private prompt", 256)
		issuer.Close()
		sink.Close()
		if err == nil || received.Load() != 0 {
			t.Fatal("Gemini request crossed origins")
		}
	}
}
