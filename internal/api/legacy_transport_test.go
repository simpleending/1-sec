package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestLegacyCredentialsRequireProtectedTransport(t *testing.T) {
	for _, tc := range []struct {
		name, requestURL, remote, key string
		compat                        bool
		want                          int
	}{
		{"remote HTTP", "http://service.test/api/v1/status", "192.0.2.20:1234", "test-key", false, http.StatusForbidden},
		{"remote read key HTTP", "http://service.test/api/v1/status", "192.0.2.20:1234", "read-key", false, http.StatusForbidden},
		{"remote TLS", "https://service.test/api/v1/status", "192.0.2.20:1234", "test-key", false, http.StatusNoContent},
		{"loopback proxy", "http://service.test/api/v1/status", "[::1]:1234", "test-key", false, http.StatusNoContent},
		{"explicit compatibility", "http://service.test/api/v1/status", "192.0.2.20:1234", "test-key", true, http.StatusNoContent},
		{"no credential", "http://service.test/api/v1/status", "192.0.2.20:1234", "", false, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testEngine().Config
			cfg.Server.Host = "0.0.0.0"
			cfg.Server.ReadOnlyKeys = []string{"read-key"}
			cfg.Server.AllowInsecureLegacyAPIKeys = tc.compat
			req := httptest.NewRequest(http.MethodGet, tc.requestURL, nil)
			req.RemoteAddr = tc.remote
			if tc.key != "" {
				req.Header.Set("Authorization", "Bearer "+tc.key)
			}
			rec := httptest.NewRecorder()
			authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}), cfg, zerolog.Nop()).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
