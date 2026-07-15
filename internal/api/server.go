package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/1sec-project/1sec/internal/modules/aicontainment"
	"github.com/1sec-project/1sec/internal/modules/network"
	"github.com/1sec-project/1sec/internal/modules/tokenvault"
	"github.com/rs/zerolog"
)

// Server is the 1SEC REST API server.
type Server struct {
	engine *core.Engine
	server *http.Server
	logger zerolog.Logger
}

// NewServer creates a new API server.
func NewServer(engine *core.Engine) *Server {
	s := &Server{
		engine: engine,
		logger: engine.Logger.With().Str("component", "api_server").Logger(),
	}

	mux := http.NewServeMux()

	// ── Read-only endpoints (safe for dashboards) ───────────────────
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/modules", s.handleModules)
	mux.HandleFunc("/api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("/api/v1/alerts/", s.handleAlertByID)
	mux.HandleFunc("/api/v1/config", s.handleConfig)
	mux.HandleFunc("/api/v1/logs", s.handleLogs)
	mux.HandleFunc("/api/v1/correlator", s.handleCorrelator)
	mux.HandleFunc("/api/v1/threats", s.handleThreats)
	mux.HandleFunc("/api/v1/rust", s.handleRustStatus)
	mux.HandleFunc("/api/v1/enforce/status", s.handleEnforceStatus)
	mux.HandleFunc("/api/v1/enforce/policies", s.handleEnforcePolicies)
	mux.HandleFunc("/api/v1/enforce/history", s.handleEnforceHistory)
	mux.HandleFunc("/api/v1/enforce/approvals/pending", s.handleEnforceApprovalsPending)
	mux.HandleFunc("/api/v1/enforce/approvals/history", s.handleEnforceApprovalsHistory)
	mux.HandleFunc("/api/v1/enforce/approvals/stats", s.handleEnforceApprovalsStats)
	mux.HandleFunc("/api/v1/enforce/webhooks/stats", s.handleEnforceWebhookStats)
	mux.HandleFunc("/api/v1/enforce/webhooks/dead-letters", s.handleEnforceWebhookDeadLetters)
	mux.HandleFunc("/api/v1/enforce/config", s.handleEnforceConfig)
	mux.HandleFunc("/api/v1/metrics", s.handleMetrics)
	mux.HandleFunc("/api/v1/event-schemas", s.handleEventSchemas)
	mux.HandleFunc("/api/v1/archive/status", s.handleArchiveStatus)
	mux.HandleFunc("/api/v1/escalation/status", s.handleEscalationStatus)
	mux.HandleFunc("/api/v1/token-vault/status", s.handleTokenVaultStatus)
	mux.HandleFunc("/health", s.handleHealth)

	// ── Mutating endpoints (require write scope) ────────────────────
	mux.HandleFunc("/api/v1/alerts/clear", s.handleAlertsClear)
	mux.HandleFunc("/api/v1/events", s.handleIngestEvent)
	mux.HandleFunc("/api/v1/enforce/policies/", s.handleEnforcePolicyAction)
	mux.HandleFunc("/api/v1/enforce/dry-run/", s.handleEnforceDryRun)
	mux.HandleFunc("/api/v1/enforce/test/", s.handleEnforceTest)
	mux.HandleFunc("/api/v1/enforce/approve/", s.handleEnforceApprove)
	mux.HandleFunc("/api/v1/enforce/reject/", s.handleEnforceReject)
	mux.HandleFunc("/api/v1/enforce/rollback/", s.handleEnforceRollback)
	mux.HandleFunc("/api/v1/enforce/webhooks/retry/", s.handleEnforceWebhookRetry)
	mux.HandleFunc("/api/v1/token-vault/exchange", s.handleTokenVaultExchange)
	mux.HandleFunc("/api/v1/shutdown", s.handleShutdown)
	mux.HandleFunc("/api/v1/config/reload", s.handleConfigReload)

	// Build middleware chain: CORS -> logging -> rate limit -> auth -> handler
	handler := corsMiddleware(
		loggingMiddleware(
			rateLimitMiddleware(
				authMiddleware(mux, engine.Config, s.logger),
				100, // 100 requests per second per IP
			),
			s.logger,
		),
		engine.Config.Server.CORSOrigins,
	)

	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", engine.Config.Server.Host, engine.Config.Server.Port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins serving the API.
func (s *Server) Start() error {
	s.logger.Info().Str("addr", s.server.Addr).Msg("API server starting")
	if s.engine.Config.AuthEnabled() {
		s.logger.Info().
			Int("write_keys", len(s.engine.Config.Server.APIKeys)).
			Int("read_only_keys", len(s.engine.Config.Server.ReadOnlyKeys)).
			Msg("API authentication enabled")
	} else if s.engine.Config.OpenReadAllowed() {
		s.logger.Warn().Msg("API running in open read mode - mutating endpoints are blocked; set api_keys/read_only_keys before exposing beyond trusted local access")
	} else {
		s.logger.Warn().Msg("API has no keys and is bound to a non-loopback host - only /health is accessible until api_keys/read_only_keys are configured or allow_unauthenticated_read is enabled")
	}
	if s.engine.Config.TLSEnabled() {
		// Validate TLS files exist and are readable before starting
		if _, err := os.Stat(s.engine.Config.Server.TLSCert); err != nil {
			return fmt.Errorf("TLS certificate file not found: %w", err)
		}
		if _, err := os.Stat(s.engine.Config.Server.TLSKey); err != nil {
			return fmt.Errorf("TLS key file not found: %w", err)
		}
		s.logger.Info().
			Str("cert", s.engine.Config.Server.TLSCert).
			Msg("API server starting with TLS")
		go func() {
			if err := s.server.ListenAndServeTLS(
				s.engine.Config.Server.TLSCert,
				s.engine.Config.Server.TLSKey,
			); err != nil && err != http.ErrServerClosed {
				s.logger.Error().Err(err).Msg("API server TLS error")
			}
		}()
	} else {
		go func() {
			if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Error().Err(err).Msg("API server error")
			}
		}()
	}
	return nil
}

// Stop gracefully shuts down the API server.
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	checks := make(map[string]interface{})
	healthy := true

	// Check bus connection (nil bus = not yet started, not a failure)
	if s.engine.Bus != nil {
		busOK := s.engine.Bus.IsConnected()
		checks["bus_connected"] = busOK
		if !busOK {
			healthy = false
		}
	} else {
		checks["bus_connected"] = false
	}

	// Check modules registered
	moduleCount := s.engine.Registry.Count()
	checks["modules_running"] = moduleCount

	// Check archiver if enabled
	if s.engine.Config.Archive.Enabled {
		if s.engine.Archiver != nil {
			checks["archiver"] = "running"
		} else {
			checks["archiver"] = "failed"
			healthy = false
		}
	}

	// Check enforcement if enabled
	if s.engine.Config.Enforcement != nil && s.engine.Config.Enforcement.Enabled {
		if s.engine.ResponseEngine != nil {
			checks["enforcement"] = "running"
		} else {
			checks["enforcement"] = "failed"
			healthy = false
		}
	}

	status := "healthy"
	httpStatus := http.StatusOK
	if !healthy {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	checks["status"] = status
	checks["timestamp"] = time.Now().UTC()

	writeJSON(w, httpStatus, checks)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	modules := make([]map[string]interface{}, 0)
	for _, mod := range s.engine.Registry.All() {
		modInfo := map[string]interface{}{
			"name":        mod.Name(),
			"description": mod.Description(),
			"enabled":     s.engine.Config.IsModuleEnabled(mod.Name()),
		}
		if types := mod.EventTypes(); len(types) > 0 {
			modInfo["event_types"] = types
		} else {
			modInfo["event_types"] = "all"
		}
		modules = append(modules, modInfo)
	}

	rustEngineStatus := "disabled"
	if s.engine.Config.RustEngine.Enabled {
		if s.engine.RustSidecar != nil && s.engine.RustSidecar.Running() {
			rustEngineStatus = "running"
		} else {
			rustEngineStatus = "enabled_not_running"
		}
	}

	enforcementInfo := map[string]interface{}{
		"enabled": false,
		"dry_run": false,
		"preset":  "",
	}
	if s.engine.Config.Enforcement != nil && s.engine.Config.Enforcement.Enabled {
		enforcementInfo["enabled"] = true
		enforcementInfo["dry_run"] = s.engine.Config.Enforcement.GetDryRun()
		enforcementInfo["preset"] = s.engine.Config.Enforcement.Preset
	}

	cloudStatus := "disabled"
	if s.engine.Config.Cloud.Enabled && s.engine.Config.Cloud.APIKey != "" {
		cloudStatus = "reporting"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":       core.Version,
		"status":        "running",
		"uptime_secs":   int64(s.engine.Uptime().Seconds()),
		"bus_connected": s.engine.Bus != nil && s.engine.Bus.IsConnected(),
		"modules_total": s.engine.Registry.Count(),
		"alerts_total":  s.engine.Pipeline.Count(),
		"rust_engine":   rustEngineStatus,
		"enforcement":   enforcementInfo,
		"cloud":         cloudStatus,
		"modules":       modules,
		"timestamp":     time.Now().UTC(),
	})
}

func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	modules := make([]map[string]interface{}, 0)
	for _, mod := range s.engine.Registry.All() {
		modules = append(modules, map[string]interface{}{
			"name":        mod.Name(),
			"description": mod.Description(),
			"enabled":     s.engine.Config.IsModuleEnabled(mod.Name()),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"modules": modules,
		"total":   len(modules),
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	severityStr := r.URL.Query().Get("min_severity")
	minSeverity := core.SeverityInfo
	switch severityStr {
	case "LOW":
		minSeverity = core.SeverityLow
	case "MEDIUM":
		minSeverity = core.SeverityMedium
	case "HIGH":
		minSeverity = core.SeverityHigh
	case "CRITICAL":
		minSeverity = core.SeverityCritical
	}

	alerts := s.engine.Pipeline.GetAlerts(minSeverity, limit)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": alerts,
		"total":  len(alerts),
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, core.RedactConfig(s.engine.Config))
}

func (s *Server) handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	var event core.SecurityEvent
	// Limit body size to 1MB to prevent memory abuse
	limited := io.LimitReader(r.Body, 1<<20)
	if err := json.NewDecoder(limited).Decode(&event); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid event JSON: " + err.Error()})
		return
	}

	if event.ID == "" {
		event.ID = "ext-" + time.Now().Format("20060102150405.000")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Source == "" {
		event.Source = "external"
	}

	// Reject events with no type — they can't be routed to any module
	if event.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event 'type' is required"})
		return
	}

	// Validate event against canonical schema — warn on missing required keys
	// but still accept the event (graceful degradation).
	if missing := core.ValidateEvent(&event); len(missing) > 0 {
		s.logger.Warn().
			Str("event_type", event.Type).
			Strs("missing_keys", missing).
			Msg("event missing recommended Details keys — detection quality may be reduced")
	}

	if err := s.engine.Bus.PublishEvent(&event); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to publish event"})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":   "accepted",
		"event_id": event.ID,
	})
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "shutting_down",
		"message": "1SEC engine is shutting down gracefully",
	})
	go func() {
		time.Sleep(250 * time.Millisecond)
		s.logger.Info().Msg("shutdown requested via API")
		// Send SIGINT to self so the main signal handler performs full cleanup
		// (syslog stop, API server stop, engine shutdown) in the correct order.
		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			s.logger.Error().Err(err).Msg("failed to find own process for shutdown signal")
			os.Exit(0)
		}
		if err := p.Signal(syscall.SIGINT); err != nil {
			s.logger.Error().Err(err).Msg("failed to send shutdown signal")
			os.Exit(0)
		}
	}()
}

// handleConfigReload hot-reloads the configuration from disk.
func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	configPath := s.engine.GetConfigPath()
	changes, err := core.ReloadConfig(s.engine, configPath, s.logger)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "reload failed",
			"details": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "reloaded",
		"changes": changes,
	})
}

// handleAlertByID handles GET/PATCH on /api/v1/alerts/{id}
func (s *Server) handleAlertByID(w http.ResponseWriter, r *http.Request) {
	// Extract alert ID from path: /api/v1/alerts/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/")
	alertID := strings.TrimSuffix(path, "/")
	if alertID == "" || alertID == "clear" {
		// Let the clear handler or alerts handler deal with it
		return
	}

	switch r.Method {
	case http.MethodGet:
		alert := s.engine.Pipeline.GetAlertByID(alertID)
		if alert == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
			return
		}
		writeJSON(w, http.StatusOK, alert)

	case http.MethodPatch:
		var body struct {
			Status string `json:"status"`
		}
		limited := io.LimitReader(r.Body, 1<<16) // 64KB limit for status updates
		if err := json.NewDecoder(limited).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		status, ok := core.ParseAlertStatus(body.Status)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid status — use OPEN, ACKNOWLEDGED, RESOLVED, or FALSE_POSITIVE",
			})
			return
		}
		alert, found := s.engine.Pipeline.UpdateAlertStatus(alertID, status)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
			return
		}
		writeJSON(w, http.StatusOK, alert)

	case http.MethodDelete:
		deleted := s.engine.Pipeline.DeleteAlert(alertID)
		if !deleted {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": alertID})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

// handleAlertsClear handles POST /api/v1/alerts/clear
func (s *Server) handleAlertsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	count := s.engine.Pipeline.ClearAlerts()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "cleared",
		"cleared": count,
	})
}

// handleLogs streams recent log entries. The engine logs are captured in a ring buffer.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	entries := core.RedactLogEntries(s.engine.GetLogEntries(limit), s.engine.Config)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":  entries,
		"total": len(entries),
	})
}

func (s *Server) handleCorrelator(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.engine.Correlator == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "not_started",
		})
		return
	}
	writeJSON(w, http.StatusOK, s.engine.Correlator.Status())
}

func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	// Find the network_guardian module and get its IP reputation data
	var threats []network.IPThreatInfo
	for _, mod := range s.engine.Registry.All() {
		if mod.Name() == "network_guardian" {
			if g, ok := mod.(*network.Guardian); ok {
				rep := g.GetIPReputation()
				if rep != nil {
					threats = rep.AllThreats()
				}
			}
			break
		}
	}

	if threats == nil {
		threats = []network.IPThreatInfo{}
	}

	blocked := 0
	for _, t := range threats {
		if t.Blocked {
			blocked++
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"threats":       threats,
		"total":         len(threats),
		"blocked_count": blocked,
	})
}

func (s *Server) handleRustStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	status := map[string]interface{}{
		"enabled": s.engine.Config.RustEngine.Enabled,
	}

	if !s.engine.Config.RustEngine.Enabled {
		status["status"] = "disabled"
	} else if s.engine.RustSidecar != nil && s.engine.RustSidecar.Running() {
		status["status"] = "running"
		status["binary"] = s.engine.Config.RustEngine.Binary
		status["workers"] = s.engine.Config.RustEngine.Workers
		status["buffer_size"] = s.engine.Config.RustEngine.BufferSize
		status["aho_corasick"] = s.engine.Config.RustEngine.AhoCorasickPrefilter
		status["capture_enabled"] = s.engine.Config.RustEngine.Capture.Enabled
		if s.engine.Config.RustEngine.Capture.Enabled {
			status["capture_interface"] = s.engine.Config.RustEngine.Capture.Interface
		}
	} else {
		status["status"] = "stopped"
	}

	writeJSON(w, http.StatusOK, status)
}

// ---------------------------------------------------------------------------
// Metrics & Schema endpoints
// ---------------------------------------------------------------------------

// handleMetrics returns bus + routing metrics for observability.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	var busMetrics map[string]int64
	if s.engine.Bus != nil {
		busMetrics = s.engine.Bus.GetMetrics()
	} else {
		busMetrics = map[string]int64{}
	}
	routingMetrics := s.engine.Registry.GetMetrics()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"bus":     busMetrics,
		"routing": routingMetrics,
	})
}

// handleEventSchemas returns the canonical event type spec so adapters and
// users know exactly what Details keys each event type expects.
func (s *Server) handleEventSchemas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	// Optional filter by category
	category := r.URL.Query().Get("category")
	schemas := core.CanonicalEventSchemas()

	if category != "" {
		filtered := make([]core.EventSchema, 0)
		for _, s := range schemas {
			if s.Category == category {
				filtered = append(filtered, s)
			}
		}
		schemas = filtered
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version": core.Version,
		"schemas": schemas,
		"total":   len(schemas),
	})
}

// handleArchiveStatus returns cold archiver metrics.
func (s *Server) handleArchiveStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	if s.engine.Archiver == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
			"status":  "disabled",
		})
		return
	}

	writeJSON(w, http.StatusOK, s.engine.Archiver.Status())
}

// handleEscalationStatus returns escalation manager state.
func (s *Server) handleEscalationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	if s.engine.Escalation == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
			"status":  "disabled",
		})
		return
	}

	writeJSON(w, http.StatusOK, s.engine.Escalation.Stats())
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// writeError writes a structured JSON error response. Replaces http.Error()
// calls so all error responses are consistent JSON with error code.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error":  message,
		"code":   code,
		"status": status,
	})
}

// decodeJSONBody reads and decodes a JSON request body with a 64KB limit.
func decodeJSONBody(r *http.Request, dst interface{}) error {
	limited := io.LimitReader(r.Body, 1<<16)
	return json.NewDecoder(limited).Decode(dst)
}

// mutatingPaths lists URL path prefixes that require write-scope API keys.
var mutatingPaths = map[string]bool{
	"/api/v1/events":                  true,
	"/api/v1/alerts/clear":            true,
	"/api/v1/shutdown":                true,
	"/api/v1/config/reload":           true,
	"/api/v1/enforce/policies/":       true,
	"/api/v1/enforce/dry-run/":        true,
	"/api/v1/enforce/test/":           true,
	"/api/v1/enforce/approve/":        true,
	"/api/v1/enforce/reject/":         true,
	"/api/v1/enforce/rollback/":       true,
	"/api/v1/enforce/webhooks/retry/": true,
	"/api/v1/token-vault/exchange":    true,
}

// isMutatingPath returns true if the request path requires write scope.
func isMutatingPath(path, method string) bool {
	// DELETE and PATCH on alerts are mutating
	if strings.HasPrefix(path, "/api/v1/alerts/") && (method == http.MethodDelete || method == http.MethodPatch) {
		return true
	}
	// POST to enforce/config is mutating, GET is not
	if path == "/api/v1/enforce/config" && method == http.MethodPost {
		return true
	}
	for prefix := range mutatingPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// authMiddleware enforces API key authentication on all endpoints except /health.
// Keys are read from config (server.api_keys / server.read_only_keys) or env (ONESEC_API_KEY).
// If no keys are configured, mutating endpoints are blocked (safe open mode).
// Write-scope keys (api_keys) can access everything. Read-only keys are blocked from mutating endpoints.
func authMiddleware(next http.Handler, cfg *core.Config, logger zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always allow health checks without auth
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// If no API keys configured, allow read-only access but block mutating endpoints
		if !cfg.AuthEnabled() {
			if !cfg.OpenReadAllowed() {
				logger.Warn().Str("path", r.URL.Path).Str("ip", r.RemoteAddr).Msg("blocked unauthenticated request on non-loopback API bind")
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "unauthenticated read access is disabled on non-loopback binds - configure api_keys/read_only_keys or set server.allow_unauthenticated_read",
				})
				return
			}
			if isMutatingPath(r.URL.Path, r.Method) {
				logger.Warn().Str("path", r.URL.Path).Str("ip", r.RemoteAddr).Msg("blocked mutating request in open mode — configure api_keys to enable")
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "mutating endpoints are disabled in open mode — configure api_keys in config or set ONESEC_API_KEY env var",
				})
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Extract key from Authorization header: "Bearer <key>"
		authHeader := r.Header.Get("Authorization")
		key := ""
		if authHeader == "" {
			// Also check X-API-Key header as fallback
			key = r.Header.Get("X-API-Key")
			if key == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "missing authentication — provide Authorization: Bearer <key> or X-API-Key header",
				})
				return
			}
		} else {
			key = authHeader
			if strings.HasPrefix(authHeader, "Bearer ") {
				key = authHeader[7:]
			}
		}

		scope := cfg.ValidateAPIKey(key)
		if scope == "" {
			logger.Warn().Str("path", r.URL.Path).Str("ip", r.RemoteAddr).Msg("invalid API key")
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid API key"})
			return
		}

		// Enforce write scope for mutating endpoints
		if scope == "read" && isMutatingPath(r.URL.Path, r.Method) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "read-only API key cannot access mutating endpoints — use a full-access key",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware implements a simple per-IP token bucket rate limiter.
type ipLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*tokenBucket
	rate       int
	maxBuckets int // cap to prevent memory exhaustion under DDoS
}

type tokenBucket struct {
	tokens    float64
	maxTokens float64
	lastTime  time.Time
}

func (b *tokenBucket) allow(rate float64) bool {
	now := time.Now()
	elapsed := now.Sub(b.lastTime).Seconds()
	b.lastTime = now
	b.tokens += elapsed * rate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func rateLimitMiddleware(next http.Handler, requestsPerSecond int) http.Handler {
	limiter := &ipLimiter{
		buckets:    make(map[string]*tokenBucket),
		rate:       requestsPerSecond,
		maxBuckets: 100000, // cap at 100K IPs to prevent memory exhaustion
	}

	// Cleanup stale buckets every 5 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			limiter.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, bucket := range limiter.buckets {
				if bucket.lastTime.Before(cutoff) {
					delete(limiter.buckets, ip)
				}
			}
			limiter.mu.Unlock()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting for health checks
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}

		limiter.mu.Lock()
		bucket, exists := limiter.buckets[ip]
		if !exists {
			// Evict oldest entries if at capacity
			if len(limiter.buckets) >= limiter.maxBuckets {
				oldest := ""
				oldestTime := time.Now()
				for k, b := range limiter.buckets {
					if b.lastTime.Before(oldestTime) {
						oldest = k
						oldestTime = b.lastTime
					}
				}
				if oldest != "" {
					delete(limiter.buckets, oldest)
				}
			}
			bucket = &tokenBucket{
				tokens:    float64(requestsPerSecond),
				maxTokens: float64(requestsPerSecond * 2), // burst = 2x rate
				lastTime:  time.Now(),
			}
			limiter.buckets[ip] = bucket
		}
		allowed := bucket.allow(float64(requestsPerSecond))
		limiter.mu.Unlock()

		if !allowed {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "rate limit exceeded — try again shortly",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler, allowedOrigins []string) http.Handler {
	// Warn at middleware creation time if wildcard is configured
	for _, o := range allowedOrigins {
		if o == "*" {
			// Log will be visible in server startup output
			fmt.Fprintf(os.Stderr, "⚠ WARNING: CORS wildcard '*' configured — any origin can make cross-origin requests. Use specific domains in production.\n")
			break
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// If no origins configured, deny cross-origin requests (secure default)
		if len(allowedOrigins) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		allowed := ""
		for _, o := range allowedOrigins {
			if o == "*" || o == origin {
				allowed = origin
				if o == "*" {
					allowed = "*"
				}
				break
			}
		}
		if allowed == "" {
			// Origin not in allow list — skip CORS headers
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", allowed)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		if allowedOrigins[0] != "*" {
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Token Vault handlers
// ---------------------------------------------------------------------------

func (s *Server) getTokenVault() *tokenvault.TokenVault {
	mod, ok := s.engine.Registry.Get("ai_containment")
	if !ok {
		return nil
	}
	c, ok := mod.(*aicontainment.Containment)
	if !ok {
		return nil
	}
	return c.TokenVault()
}

func (s *Server) handleTokenVaultStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	tv := s.getTokenVault()
	if tv == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
			"message": "Token Vault is not enabled. Set token_vault.enabled: true in config.",
		})
		return
	}

	status := tv.GetStatus()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled": true,
		"status":  status,
	})
}

func (s *Server) handleTokenVaultExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	tv := s.getTokenVault()
	if tv == nil {
		writeError(w, http.StatusServiceUnavailable, "not_enabled", "Token Vault is not enabled — set token_vault.enabled: true")
		return
	}

	if !tv.IsConfigured() {
		writeError(w, http.StatusServiceUnavailable, "not_configured", "Auth0 Token Vault credentials not configured")
		return
	}

	var req struct {
		SubjectToken     string `json:"subject_token"`
		SubjectTokenType string `json:"subject_token_type"`
		Connection       string `json:"connection"`
		LoginHint        string `json:"login_hint,omitempty"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
		return
	}

	if req.SubjectToken == "" || req.Connection == "" {
		writeError(w, http.StatusBadRequest, "missing_params", "subject_token and connection are required")
		return
	}

	// Default to refresh token type if not specified
	if req.SubjectTokenType == "" {
		req.SubjectTokenType = tokenvault.SubjectTokenTypeRefreshToken
	}

	// Validate subject_token_type
	switch req.SubjectTokenType {
	case tokenvault.SubjectTokenTypeRefreshToken, tokenvault.SubjectTokenTypeAccessToken:
		// valid
	default:
		writeError(w, http.StatusBadRequest, "invalid_token_type",
			"subject_token_type must be urn:ietf:params:oauth:token-type:refresh_token or urn:ietf:params:oauth:token-type:access_token")
		return
	}

	resp, err := tv.ExchangeToken(req.SubjectToken, req.SubjectTokenType, req.Connection, req.LoginHint)
	if err != nil {
		if resp != nil && resp.Error != "" {
			// Auth0 returned a structured error
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":             resp.Error,
				"error_description": resp.ErrorDesc,
			})
			return
		}
		writeError(w, http.StatusBadGateway, "exchange_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": resp.AccessToken,
		"token_type":   resp.TokenType,
		"expires_in":   resp.ExpiresIn,
		"scope":        resp.Scope,
	})
}

func loggingMiddleware(next http.Handler, logger zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Dur("duration", time.Since(start)).
			Msg("request")
	})
}
