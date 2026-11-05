package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/google/uuid"
)

// auditRoute returns server-owned labels, never raw paths containing user data.
func auditRoute(path string) (string, string) {
	if path == "/api/v1/alerts/clear" {
		return path, ""
	}
	for _, prefix := range []string{"/api/v1/operators/", "/api/v1/sensors/"} {
		if strings.HasPrefix(path, prefix) {
			parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
			if len(parts) == 1 {
				return prefix + ":id", core.AuditResourceHash(parts[0])
			}
			if len(parts) == 2 && (parts[1] == "rotate" || parts[1] == "revoke") {
				return prefix + ":id/" + parts[1], core.AuditResourceHash(parts[0])
			}
			return "unclassified", ""
		}
	}
	for _, prefix := range []string{"/api/v1/operators/", "/api/v1/sensors/", "/api/v1/alerts/", "/api/v1/enforce/approve/", "/api/v1/enforce/reject/", "/api/v1/enforce/rollback/", "/api/v1/enforce/policies/", "/api/v1/enforce/dry-run/", "/api/v1/enforce/test/", "/api/v1/enforce/webhooks/retry/"} {
		if strings.HasPrefix(path, prefix) {
			return prefix + ":resource", core.AuditResourceHash(strings.TrimPrefix(path, prefix))
		}
	}
	if _, ok := requiredPermission(path, http.MethodGet); ok {
		return path, ""
	}
	if _, ok := requiredPermission(path, http.MethodPost); ok {
		return path, ""
	}
	return "unclassified", ""
}
func (s *Server) auditRecord(event core.AuditEvent, remote bool, ctx context.Context) error {
	if !s.engine.Config.Audit.Enabled {
		return nil
	}
	if s.engine.Audit == nil {
		return errors.New("audit unavailable")
	}
	_, err := s.engine.Audit.Record(ctx, event, remote)
	if err != nil {
		s.logger.Error().Str("kind", event.Kind).Msg("durable audit failed")
	}
	return err
}

// Unauthorized requests are captured outside authentication. Successful reads
// and sensor/event traffic are excluded to keep this a control-plane journal.
func (s *Server) auditDenials(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/audit/ingest" {
			next.ServeHTTP(w, r)
			return
		}
		response := &operatorResponse{ResponseWriter: w}
		next.ServeHTTP(response, r)
		if response.status == 401 || response.status == 403 {
			if s.engine.Config.Audit.Enabled && s.engine.Audit != nil {
				s.engine.Audit.Denied()
			}
		}
	})
}

// Called after authentication, including when named identity is disabled. An
// intent must commit before a protected mutation, and optional remote receipts
// gate execution. A network/body wait cannot preserve an obsolete role grant.
func (s *Server) auditMutation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, named := r.Context().Value(operatorContextKey{}).(core.OperatorInfo)
		if (!s.engine.Config.Audit.Enabled && !named) || r.Method == http.MethodGet || r.Method == http.MethodHead || !strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1/events" {
			next.ServeHTTP(w, r)
			return
		}
		permission, known := requiredPermission(r.URL.Path, r.Method)
		if !known {
			next.ServeHTTP(w, r)
			return
		}
		// Bound and finish parsing transport input before the last authority check.
		var requestBody []byte
		if r.Body != nil {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
			if err != nil {
				writeError(w, 413, "body_too_large", "bounded request body required")
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
			requestBody = body
		}
		route, resource := auditRoute(r.URL.Path)
		event := core.AuditEvent{Kind: "request_intent", RequestID: uuid.NewString(), Actor: "legacy_shared_key", Role: "legacy", Method: r.Method, Route: route, ResourceHash: resource}
		event.Action = string(permission)
		if permission == core.PermissionOperators {
			var requested struct {
				ID   string `json:"id"`
				Role string `json:"role"`
			}
			if json.Unmarshal(requestBody, &requested) == nil {
				if len(core.PermissionsForRole(requested.Role)) > 0 {
					event.Action = "operators.manage:" + requested.Role
				}
				if r.URL.Path == "/api/v1/operators" && requested.ID != "" {
					event.ResourceHash = core.AuditResourceHash(requested.ID)
				}
			}
		}
		if info, ok := r.Context().Value(operatorContextKey{}).(core.OperatorInfo); ok {
			event.Actor = info.ID
			event.Role = info.Role
			event.CredentialID = info.CredentialID
		}
		if err := s.auditRecord(event, true, r.Context()); err != nil {
			event.Kind = "request_result"
			event.Status = 503
			event.Outcome = "audit_admission_failed"
			_ = s.auditRecord(event, false, r.Context())
			writeError(w, 503, "audit_unavailable", "protected operation requires durable audit")
			return
		}
		if r.Context().Err() != nil || !s.callerMay(r, permission) {
			event.Kind = "request_result"
			event.Status = 403
			event.Outcome = "authority_changed"
			_ = s.auditRecord(event, false, r.Context())
			writeError(w, 403, "permission_denied", "current credential no longer permits this operation")
			return
		}
		response := &operatorResponse{ResponseWriter: w}
		completed := false
		defer func() {
			event.Kind = "request_result"
			event.Status = response.status
			if !completed {
				event.Status = 500
				event.Outcome = "handler_interrupted"
			} else {
				event.Outcome = "completed"
				if event.Status == 0 {
					event.Status = 200
				}
			}
			_ = s.auditRecord(event, false, context.WithoutCancel(r.Context()))
		}()
		next.ServeHTTP(response, r)
		completed = true
	})
}

func (s *Server) handleAuditStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	result := map[string]interface{}{"enabled": s.engine.Config.Audit.Enabled, "receiver_enabled": s.engine.Config.AuditReceiver.Enabled}
	if s.engine.Audit != nil {
		result["exporter"] = s.engine.Audit.Status()
	}
	if s.engine.AuditReceiver != nil {
		result["receiver_ready"] = s.engine.AuditReceiver.Ready()
	}
	writeJSON(w, 200, result)
}

// This endpoint authenticates only dedicated source credentials. Shared/operator
// keys cannot write another engine's collector, or read/delete collector files.
func (s *Server) auditReceiverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/ingest" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			writeError(w, 405, "method_not_allowed", "method not allowed")
			return
		}
		if !s.engine.Config.AuditReceiver.Enabled || s.engine.AuditReceiver == nil {
			writeError(w, 404, "audit_receiver_disabled", "audit receiver is disabled")
			return
		}
		if !sensorTransportAllowed(r) {
			writeError(w, 403, "tls_required", "audit ingest requires TLS or a trusted loopback proxy")
			return
		}
		if len(r.Header.Values("Authorization")) != 1 || r.Header.Get("X-API-Key") != "" {
			writeError(w, 403, "audit_credential_required", "supply one dedicated bearer credential")
			return
		}
		key := requestAPIKey(r)
		if !strings.HasPrefix(key, core.AuditTokenPrefix) || len(key) > 256 {
			writeError(w, 403, "audit_credential_required", "dedicated source credential required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		var record core.AuditRecord
		if d.Decode(&record) != nil || d.Decode(new(interface{})) != io.EOF {
			writeError(w, 400, "invalid_audit", "expected one bounded audit record")
			return
		}
		receipt, err := s.engine.AuditReceiver.Accept(key, record)
		if err != nil {
			status := 409
			if errors.Is(err, core.ErrOperatorPermission) {
				status = 403
			} else if !s.engine.AuditReceiver.Ready() {
				status = 503
			}
			writeError(w, status, "audit_not_committed", "audit record was not accepted")
			return
		}
		writeJSON(w, 200, receipt)
	})
}
