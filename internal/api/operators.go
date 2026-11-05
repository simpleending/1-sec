package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/1sec-project/1sec/internal/core"
)

type operatorContextKey struct{}

// Every named request has a method-specific, explicit grant. New routes fail
// closed until classified here; a role name never becomes a wildcard grant.
func requiredPermission(path, method string) (core.Permission, bool) {
	if path == "/api/v1/operators/me" && method == http.MethodGet {
		return core.PermissionRead, true
	}
	if path == "/api/v1/audit/status" && method == http.MethodGet {
		return core.PermissionRead, true
	}
	if path == "/api/v1/operators" || strings.HasPrefix(path, "/api/v1/operators/") {
		return core.PermissionOperators, method == http.MethodGet || method == http.MethodPost || method == http.MethodPatch
	}
	if path == "/api/v1/sensors" || strings.HasPrefix(path, "/api/v1/sensors/") {
		if method == http.MethodGet && path == "/api/v1/sensors" {
			return core.PermissionRead, true
		}
		return core.PermissionSensors, method == http.MethodPost
	}
	if path == "/api/v1/alerts/clear" {
		return core.PermissionAlertDelete, method == http.MethodPost
	}
	if strings.HasPrefix(path, "/api/v1/alerts/") {
		if method == http.MethodGet {
			return core.PermissionRead, true
		}
		if method == http.MethodDelete {
			return core.PermissionAlertDelete, true
		}
		return core.PermissionAlerts, method == http.MethodPatch
	}
	if path == "/api/v1/enforce/config" && method == http.MethodPost {
		return core.PermissionPolicies, true
	}
	if method == http.MethodPost {
		switch path {
		case "/api/v1/events":
			return core.PermissionEvents, true
		case "/api/v1/access/check":
			return core.PermissionAccess, true
		case "/api/v1/token-vault/exchange":
			return core.PermissionTokens, true
		case "/api/v1/shutdown", "/api/v1/config/reload":
			return core.PermissionEngine, true
		}
		for prefix, permission := range map[string]core.Permission{
			"/api/v1/enforce/approve/": core.PermissionApprovals, "/api/v1/enforce/reject/": core.PermissionApprovals,
			"/api/v1/enforce/rollback/": core.PermissionRollback, "/api/v1/enforce/test/": core.PermissionTest,
			"/api/v1/enforce/policies/": core.PermissionPolicies, "/api/v1/enforce/dry-run/": core.PermissionPolicies,
			"/api/v1/enforce/webhooks/retry/": core.PermissionWebhooks,
		} {
			if strings.HasPrefix(path, prefix) && len(path) > len(prefix) {
				return permission, true
			}
		}
	}
	if method == http.MethodGet {
		switch path {
		case "/api/v1/status", "/api/v1/modules", "/api/v1/alerts", "/api/v1/config", "/api/v1/logs", "/api/v1/correlator", "/api/v1/threats", "/api/v1/rust",
			"/api/v1/enforce/status", "/api/v1/enforce/policies", "/api/v1/enforce/history", "/api/v1/enforce/approvals/pending", "/api/v1/enforce/approvals/history", "/api/v1/enforce/approvals/stats",
			"/api/v1/enforce/webhooks/stats", "/api/v1/enforce/webhooks/dead-letters", "/api/v1/enforce/config", "/api/v1/metrics", "/api/v1/event-schemas", "/api/v1/archive/status", "/api/v1/escalation/status", "/api/v1/token-vault/status", "/api/v1/ui-access":
			return core.PermissionRead, true
		}
	}
	return "", false
}

type operatorResponse struct {
	http.ResponseWriter
	status int
}

func (w *operatorResponse) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *operatorResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(p)
}
func (w *operatorResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) operatorAuthMiddleware(named, legacy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asset, _ := dashboardAsset(r.URL.Path)
		key := requestAPIKey(r)
		if r.URL.Path == "/health" || r.URL.Path == "/live" || asset != "" || strings.HasPrefix(key, core.SensorTokenPrefix) {
			legacy.ServeHTTP(w, r)
			return
		}
		if !s.engine.Config.Operators.Enabled {
			if strings.HasPrefix(key, core.OperatorTokenPrefix) {
				writeError(w, 403, "invalid_operator", "operator identity is not enabled")
				return
			}
			legacy.ServeHTTP(w, r)
			return
		}
		if s.engine.Operators == nil || !s.engine.Operators.Ready() {
			writeError(w, 503, "operator_unavailable", "operator authorization unavailable")
			return
		}
		if len(r.Header.Values("Authorization")) > 1 || len(r.Header.Values("X-API-Key")) > 1 || r.Header.Get("Authorization") != "" && r.Header.Get("X-API-Key") != "" {
			writeError(w, 400, "ambiguous_credentials", "supply one credential header")
			return
		}
		if !strings.HasPrefix(key, core.OperatorTokenPrefix) {
			if s.engine.Config.Operators.RequireNamed {
				writeError(w, 403, "named_operator_required", "use an individual operator credential")
				return
			}
			if r.URL.Path == "/api/v1/operators" || strings.HasPrefix(r.URL.Path, "/api/v1/operators/") {
				if r.URL.Path != "/api/v1/operators/me" && (s.engine.Config.ValidateAPIKey(key) != "write" || !sensorTransportAllowed(r)) {
					writeError(w, 403, "operator_admin_required", "operator administration requires a secure administrator request")
					return
				}
			}
			s.auditOperatorRequest(legacy, w, r, "legacy:"+s.engine.Config.ValidateAPIKey(key), "legacy", "")
			return
		}
		if !sensorTransportAllowed(r) {
			writeError(w, 403, "tls_required", "operator credentials require TLS or a loopback proxy")
			return
		}
		info, ok := s.engine.Operators.Authenticate(key)
		if !ok {
			writeError(w, 403, "invalid_operator", "invalid or inactive operator credential")
			return
		}
		permission, known := requiredPermission(r.URL.Path, r.Method)
		if !known || !slices.Contains(core.PermissionsForRole(info.Role), permission) {
			s.logger.Warn().Str("operator_id", info.ID).Str("credential_id", info.CredentialID).Str("role", info.Role).Str("permission", string(permission)).Str("method", r.Method).Str("path", r.URL.Path).Msg("operator permission denied")
			writeError(w, 403, "permission_denied", "operator role does not permit this operation")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), operatorContextKey{}, info))
		s.auditOperatorRequest(named, w, r, info.ID, info.Role, info.CredentialID)
	})
}
func (s *Server) auditOperatorRequest(next http.Handler, w http.ResponseWriter, r *http.Request, id, role, credential string) {
	response := &operatorResponse{ResponseWriter: w}
	completed := false
	defer func() {
		status := response.status
		if !completed {
			status = 500
		} else if status == 0 {
			status = 200
		}
		s.logger.Info().Str("operator_id", id).Str("credential_id", credential).Str("role", role).Str("method", r.Method).Str("path", r.URL.Path).Int("status", status).Msg("operator API request")
	}()
	next.ServeHTTP(response, r)
	completed = true
}
func (s *Server) callerMay(r *http.Request, permission core.Permission) bool {
	if info, ok := r.Context().Value(operatorContextKey{}).(core.OperatorInfo); ok {
		return s.engine.Operators != nil && s.engine.Operators.Authorize(info, permission)
	}
	return !s.engine.Config.Operators.RequireNamed && s.engine.Config.ValidateAPIKey(requestAPIKey(r)) == "write"
}
func operatorDecisionActor(r *http.Request) string {
	if info, ok := r.Context().Value(operatorContextKey{}).(core.OperatorInfo); ok {
		return "operator:" + info.ID
	}
	return "api:" + r.RemoteAddr
}

func operatorActorArgs(r *http.Request) []core.OperatorInfo {
	if info, ok := r.Context().Value(operatorContextKey{}).(core.OperatorInfo); ok {
		return []core.OperatorInfo{info}
	}
	return nil
}
func writeOperatorError(w http.ResponseWriter, err error) {
	status := 400
	if errors.Is(err, core.ErrOperatorPermission) {
		status = 403
	}
	writeError(w, status, "operator_operation_failed", err.Error())
}

func (s *Server) withSensorPermission(r *http.Request, operation func(bool) error) error {
	if info, ok := r.Context().Value(operatorContextKey{}).(core.OperatorInfo); ok {
		return s.engine.Operators.WithPermission(info, core.PermissionSensors, func(current core.OperatorInfo) error {
			return operation(slices.Contains(core.PermissionsForRole(current.Role), core.PermissionContainmentGrant))
		})
	}
	if !s.callerMay(r, core.PermissionSensors) {
		return core.ErrOperatorPermission
	}
	return operation(true)
}
func (s *Server) handleOperatorMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if info, ok := r.Context().Value(operatorContextKey{}).(core.OperatorInfo); ok {
		writeJSON(w, 200, map[string]interface{}{"operator": info, "permissions": core.PermissionsForRole(info.Role)})
		return
	}
	writeJSON(w, 200, map[string]string{"identity": "legacy_shared_key", "scope": s.engine.Config.ValidateAPIKey(requestAPIKey(r))})
}
func decodeOperatorBody(w http.ResponseWriter, r *http.Request, out interface{}, empty bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	err := d.Decode(out)
	if empty && err == io.EOF {
		return true
	}
	if err != nil || d.Decode(new(interface{})) != io.EOF {
		writeError(w, 400, "invalid_request", "expected one operator request with known fields")
		return false
	}
	return true
}
func (s *Server) handleOperators(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.engine.Operators == nil || !s.callerMay(r, core.PermissionOperators) {
		writeError(w, 403, "operator_admin_required", "operator administration unavailable or forbidden")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]interface{}{"operators": s.engine.Operators.List()})
	case http.MethodPost:
		var spec core.OperatorSpec
		if !decodeOperatorBody(w, r, &spec, false) {
			return
		}
		info, token, err := s.engine.Operators.Enroll(spec, operatorActorArgs(r)...)
		if err != nil {
			writeOperatorError(w, err)
			return
		}
		s.logger.Info().Str("actor", operatorDecisionActor(r)).Str("operator_id", info.ID).Str("role", info.Role).Msg("operator enrolled")
		writeJSON(w, 201, map[string]interface{}{"operator": info, "token": token})
	default:
		writeError(w, 405, "method_not_allowed", "method not allowed")
	}
}
func (s *Server) handleOperatorAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.engine.Operators == nil || !s.callerMay(r, core.PermissionOperators) {
		writeError(w, 403, "operator_admin_required", "operator administration unavailable or forbidden")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/operators/"), "/")
	if len(parts) == 1 && parts[0] != "" && r.Method == http.MethodPatch {
		var body struct {
			Role string `json:"role"`
		}
		if !decodeOperatorBody(w, r, &body, false) {
			return
		}
		if err := s.engine.Operators.SetRole(parts[0], body.Role, operatorActorArgs(r)...); err != nil {
			writeOperatorError(w, err)
			return
		}
		s.logger.Info().Str("actor", operatorDecisionActor(r)).Str("operator_id", parts[0]).Str("role", body.Role).Msg("operator role changed")
		writeJSON(w, 200, map[string]string{"status": "updated", "operator_id": parts[0]})
		return
	}
	if len(parts) != 2 || parts[0] == "" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	switch parts[1] {
	case "revoke":
		if err := s.engine.Operators.Revoke(parts[0], operatorActorArgs(r)...); err != nil {
			writeOperatorError(w, err)
			return
		}
		s.logger.Info().Str("actor", operatorDecisionActor(r)).Str("operator_id", parts[0]).Msg("operator revoked")
		writeJSON(w, 200, map[string]string{"status": "revoked", "operator_id": parts[0]})
	case "rotate":
		var body struct {
			ExpiresAt time.Time `json:"expires_at"`
		}
		if !decodeOperatorBody(w, r, &body, true) {
			return
		}
		info, token, err := s.engine.Operators.Rotate(parts[0], body.ExpiresAt, operatorActorArgs(r)...)
		if err != nil {
			writeOperatorError(w, err)
			return
		}
		s.logger.Info().Str("actor", operatorDecisionActor(r)).Str("operator_id", info.ID).Str("credential_id", info.CredentialID).Msg("operator credential rotated")
		writeJSON(w, 200, map[string]interface{}{"operator": info, "token": token})
	default:
		http.NotFound(w, r)
	}
}
