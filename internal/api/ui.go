package api

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed ui/index.html ui/app.js ui/style.css
var dashboardAssets embed.FS

func dashboardAsset(path string) (string, string) {
	switch path {
	case "/ui", "/ui/":
		return "ui/index.html", "text/html; charset=utf-8"
	case "/ui/app.js":
		return "ui/app.js", "text/javascript; charset=utf-8"
	case "/ui/style.css":
		return "ui/style.css", "text/css; charset=utf-8"
	default:
		return "", ""
	}
}

// The shell contains no engine data or credentials. API requests retain normal auth.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	file, contentType := dashboardAsset(r.URL.Path)
	if file == "" {
		http.NotFound(w, r)
		return
	}
	data, err := dashboardAssets.ReadFile(file)
	if err != nil {
		http.Error(w, "dashboard unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	w.Write(data)
}

func (s *Server) handleDashboardAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if key == "" {
		key = r.Header.Get("X-API-Key")
	}
	scope := s.engine.Config.ValidateAPIKey(key)
	if scope == "" {
		scope = "read"
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"scope": scope})
}
