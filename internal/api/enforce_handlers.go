package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
)

// handleEnforceStatus returns the enforcement engine status and stats.
func (s *Server) handleEnforceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
			"dry_run": false,
			"stats":   map[string]interface{}{"total_policies": 0, "total_records": 0},
			"message": "enforcement engine not configured — add 'enforcement' section to config",
		})
		return
	}

	cfg := s.engine.Config.Enforcement
	var allowList []string
	if cfg != nil {
		allowList = cfg.GlobalAllowList
	}
	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":           cfg != nil && cfg.Enabled,
		"dry_run":           cfg != nil && cfg.GetDryRun(),
		"preset":            presetName(cfg),
		"global_allow_list": allowList,
		"stats":             re.Stats(),
	})
}

// presetName returns the active preset name from config, or empty string.
func presetName(cfg *core.EnforcementConfig) string {
	if cfg == nil {
		return ""
	}
	return cfg.Preset
}

// handleEnforcePolicies returns all configured response policies.
func (s *Server) handleEnforcePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{"policies": map[string]interface{}{}})
		return
	}

	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{"policies": re.GetPolicies()})
}

// handleEnforcePolicyAction handles enable/disable for a specific module's policy.
// URL pattern: /api/v1/enforce/policies/{module}/{action}
func (s *Server) handleEnforcePolicyAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "enforcement engine not configured"})
		return
	}

	// Parse: /api/v1/enforce/policies/{module}/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/policies/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "expected /api/v1/enforce/policies/{module}/{enable|disable}"})
		return
	}

	module := parts[0]
	action := parts[1]

	switch action {
	case "enable":
		if re.SetPolicyEnabled(module, true) {
			s.logger.Warn().Str("module", module).Bool("enabled", true).Str("ip", r.RemoteAddr).Msg("enforcement policy toggled via API")
			s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{"module": module, "enabled": true})
		} else {
			s.writeEnforcementJSON(w, http.StatusNotFound, map[string]interface{}{"error": "no policy found for module: " + module})
		}
	case "disable":
		if re.SetPolicyEnabled(module, false) {
			s.logger.Warn().Str("module", module).Bool("enabled", false).Str("ip", r.RemoteAddr).Msg("enforcement policy toggled via API")
			s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{"module": module, "enabled": false})
		} else {
			s.writeEnforcementJSON(w, http.StatusNotFound, map[string]interface{}{"error": "no policy found for module: " + module})
		}
	default:
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "unknown action: " + action + " (use enable or disable)"})
	}
}

// handleEnforceHistory returns response action execution history.
func (s *Server) handleEnforceHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{"records": []interface{}{}})
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	moduleFilter := r.URL.Query().Get("module")
	records := re.GetRecords(limit, moduleFilter)

	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
		"records": records,
		"count":   len(records),
	})
}

// handleEnforceDryRun toggles global dry-run mode.
// URL pattern: /api/v1/enforce/dry-run/{on|off}
func (s *Server) handleEnforceDryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	mode := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/dry-run/")
	cfg := s.engine.Config.Enforcement
	if cfg == nil {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "enforcement not configured"})
		return
	}

	switch mode {
	case "on":
		previous := cfg.GetDryRun()
		cfg.SetDryRun(true)
		s.logger.Warn().
			Bool("previous", previous).
			Bool("new", true).
			Str("ip", r.RemoteAddr).
			Msg("enforcement dry-run toggled via API")
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{"dry_run": true, "previous": previous, "message": "global dry-run enabled"})
	case "off":
		previous := cfg.GetDryRun()
		cfg.SetDryRun(false)
		s.logger.Warn().
			Bool("previous", previous).
			Bool("new", false).
			Str("ip", r.RemoteAddr).
			Msg("enforcement dry-run toggled via API — enforcement is LIVE")
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{"dry_run": false, "previous": previous, "message": "global dry-run disabled — enforcement is LIVE"})
	default:
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "use /dry-run/on or /dry-run/off"})
	}
}

// handleEnforceTest simulates an alert for a module and returns what actions would fire.
// URL pattern: /api/v1/enforce/test/{module}?severity=HIGH
func (s *Server) handleEnforceTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "enforcement engine not configured"})
		return
	}

	module := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/test/")
	severity := core.ParseSeverity(r.URL.Query().Get("severity"))

	policies := re.GetPolicies()
	policy, ok := policies[module]
	if !ok {
		policy, ok = policies["*"]
	}
	if !ok {
		s.writeEnforcementJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "no policy found for module: " + module,
			"actions": []interface{}{},
		})
		return
	}

	matchingActions := make([]map[string]interface{}, 0)
	for _, rule := range policy.Actions {
		if severity >= rule.MinSeverity {
			matchingActions = append(matchingActions, map[string]interface{}{
				"action":       string(rule.Action),
				"min_severity": rule.MinSeverity.String(),
				"params":       rule.Params,
				"dry_run":      rule.DryRun,
				"description":  rule.Description,
			})
		}
	}

	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
		"module":         module,
		"test_severity":  severity.String(),
		"policy_enabled": policy.Enabled,
		"policy_dry_run": policy.DryRun,
		"actions":        matchingActions,
		"total_matching": len(matchingActions),
	})
}

// handleEnforceApprove approves a pending approval gate action.
// URL pattern: POST /api/v1/enforce/approve/{id}
func (s *Server) handleEnforceApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil || re.ApprovalGate == nil {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "approval gate not configured"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/approve/")
	if id == "" {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "approval ID required"})
		return
	}

	decidedBy := "api:" + r.RemoteAddr
	pa, err := re.ApprovalGate.Approve(id, decidedBy)
	if err != nil {
		s.writeEnforcementJSON(w, http.StatusNotFound, map[string]interface{}{"error": err.Error()})
		return
	}

	s.logger.Warn().
		Str("approval_id", id).
		Str("action", string(pa.Action)).
		Str("target", pa.Target).
		Str("decided_by", decidedBy).
		Msg("action approved via API")

	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
		"id":         pa.ID,
		"action":     string(pa.Action),
		"target":     pa.Target,
		"status":     pa.Status,
		"decided_by": pa.DecidedBy,
	})
}

// handleEnforceReject rejects a pending approval gate action.
// URL pattern: POST /api/v1/enforce/reject/{id}
func (s *Server) handleEnforceReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil || re.ApprovalGate == nil {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "approval gate not configured"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/reject/")
	if id == "" {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "approval ID required"})
		return
	}

	decidedBy := "api:" + r.RemoteAddr
	pa, err := re.ApprovalGate.Reject(id, decidedBy)
	if err != nil {
		s.writeEnforcementJSON(w, http.StatusNotFound, map[string]interface{}{"error": err.Error()})
		return
	}

	s.logger.Warn().
		Str("approval_id", id).
		Str("action", string(pa.Action)).
		Str("decided_by", decidedBy).
		Msg("action rejected via API")

	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
		"id":         pa.ID,
		"action":     string(pa.Action),
		"target":     pa.Target,
		"status":     pa.Status,
		"decided_by": pa.DecidedBy,
	})
}

// handleEnforceRollback rolls back a reversible enforcement action.
// URL pattern: POST /api/v1/enforce/rollback/{id}
func (s *Server) handleEnforceRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "enforcement engine not configured"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/rollback/")
	if id == "" {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "record ID required"})
		return
	}

	record := re.FindRecord(id)
	if record == nil {
		s.writeEnforcementJSON(w, http.StatusNotFound, map[string]interface{}{"error": "enforcement record not found"})
		return
	}

	if record.Status != core.ActionStatusSuccess {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":  "can only roll back successful actions",
			"status": string(record.Status),
		})
		return
	}

	switch record.Action {
	case core.ActionBlockIP:
		core.ExportedUnblockIP(record.Target, s.logger)
		record.Status = core.ActionStatusSkipped
		s.logger.Warn().
			Str("record_id", id).
			Str("action", string(record.Action)).
			Str("target", record.Target).
			Str("ip", r.RemoteAddr).
			Msg("enforcement action rolled back via API")
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
			"id":       id,
			"action":   string(record.Action),
			"target":   record.Target,
			"rollback": "completed",
		})
	case core.ActionDisableUser:
		if err := core.ExportedEnableUser(record.Target, s.logger); err != nil {
			s.writeEnforcementJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error":  "rollback failed: " + err.Error(),
				"action": string(record.Action),
				"target": record.Target,
			})
			return
		}
		record.Status = core.ActionStatusSkipped
		s.logger.Warn().
			Str("record_id", id).
			Str("action", string(record.Action)).
			Str("target", record.Target).
			Str("ip", r.RemoteAddr).
			Msg("enforcement action rolled back via API")
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
			"id":       id,
			"action":   string(record.Action),
			"target":   record.Target,
			"rollback": "completed",
		})
	case core.ActionQuarantineFile:
		if err := core.ExportedRestoreFile(record.Details, s.logger); err != nil {
			s.writeEnforcementJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error":  "rollback failed: " + err.Error(),
				"action": string(record.Action),
				"target": record.Target,
			})
			return
		}
		record.Status = core.ActionStatusSkipped
		s.logger.Warn().
			Str("record_id", id).
			Str("action", string(record.Action)).
			Str("target", record.Target).
			Str("ip", r.RemoteAddr).
			Msg("enforcement action rolled back via API")
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
			"id":       id,
			"action":   string(record.Action),
			"target":   record.Target,
			"rollback": "completed",
		})
	default:
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":  "rollback not supported for this action type",
			"action": string(record.Action),
		})
	}
}

// handleEnforceApprovalsPending returns all pending approval gate actions.
// URL pattern: GET /api/v1/enforce/approvals/pending
func (s *Server) handleEnforceApprovalsPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil || re.ApprovalGate == nil {
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
			"pending": []interface{}{},
			"count":   0,
			"message": "approval gate not configured",
		})
		return
	}

	pending := re.ApprovalGate.GetPending()
	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
		"pending": pending,
		"count":   len(pending),
	})
}

// handleEnforceApprovalsHistory returns recent approval decisions.
// URL pattern: GET /api/v1/enforce/approvals/history
func (s *Server) handleEnforceApprovalsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil || re.ApprovalGate == nil {
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
			"history": []interface{}{},
			"count":   0,
		})
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	history := re.ApprovalGate.GetHistory(limit)
	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
		"history": history,
		"count":   len(history),
	})
}

// handleEnforceApprovalsStats returns approval gate statistics.
// URL pattern: GET /api/v1/enforce/approvals/stats
func (s *Server) handleEnforceApprovalsStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil || re.ApprovalGate == nil {
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
		})
		return
	}

	s.writeEnforcementJSON(w, http.StatusOK, re.ApprovalGate.Stats())
}

// handleEnforceWebhookStats returns webhook dispatcher statistics.
// URL pattern: GET /api/v1/enforce/webhooks/stats
func (s *Server) handleEnforceWebhookStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil || re.Dispatcher == nil {
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
			"message": "webhook dispatcher not configured",
		})
		return
	}

	s.writeEnforcementJSON(w, http.StatusOK, re.Dispatcher.Stats())
}

// handleEnforceWebhookDeadLetters returns failed webhook deliveries.
// URL pattern: GET /api/v1/enforce/webhooks/dead-letters
func (s *Server) handleEnforceWebhookDeadLetters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil || re.Dispatcher == nil {
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
			"dead_letters": []interface{}{},
			"count":        0,
		})
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	dls := re.Dispatcher.GetDeadLetters(limit)
	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
		"dead_letters": dls,
		"count":        len(dls),
	})
}

// handleEnforceWebhookRetry re-enqueues a dead letter webhook delivery.
// URL pattern: POST /api/v1/enforce/webhooks/retry/{id}
func (s *Server) handleEnforceWebhookRetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	re := s.engine.ResponseEngine
	if re == nil || re.Dispatcher == nil {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "webhook dispatcher not configured"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/enforce/webhooks/retry/")
	if id == "" {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "delivery ID required"})
		return
	}

	if re.Dispatcher.RetryDeadLetter(id) {
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{"id": id, "status": "re-enqueued"})
	} else {
		s.writeEnforcementJSON(w, http.StatusNotFound, map[string]interface{}{"error": "dead letter not found or queue full"})
	}
}

// handleEnforceConfig returns the full enforcement configuration for remote
// dashboards. GET returns current config; POST updates approval gate settings.
func (s *Server) handleEnforceConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleEnforceConfigGet(w, r)
	case http.MethodPost:
		s.handleEnforceConfigPost(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleEnforceConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.engine.Config.Enforcement
	if cfg == nil {
		s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
			"message": "enforcement not configured",
		})
		return
	}

	// Build per-module policy summary
	re := s.engine.ResponseEngine
	policySummary := make([]map[string]interface{}, 0)
	if re != nil {
		for module, policy := range re.GetPolicies() {
			actions := make([]map[string]interface{}, 0, len(policy.Actions))
			for _, a := range policy.Actions {
				actions = append(actions, map[string]interface{}{
					"action":        string(a.Action),
					"min_severity":  a.MinSeverity.String(),
					"dry_run":       a.DryRun,
					"skip_approval": a.SkipApproval,
					"description":   a.Description,
				})
			}
			policySummary = append(policySummary, map[string]interface{}{
				"module":              module,
				"enabled":             policy.Enabled,
				"min_severity":        policy.MinSeverity.String(),
				"dry_run":             policy.DryRun,
				"cooldown_seconds":    int(policy.Cooldown.Seconds()),
				"max_actions_per_min": policy.MaxActionsPerMin,
				"allow_list":          policy.AllowList,
				"actions":             actions,
			})
		}
	}

	gateConfig := cfg.GetApprovalGate()
	// Approval gate config
	approvalGate := map[string]interface{}{
		"enabled":            false,
		"require_approval":   []string{},
		"auto_approve_above": "",
	}
	if gateConfig.Enabled {
		approvalGate["enabled"] = true
		approvalGate["require_approval"] = gateConfig.RequireApproval
		approvalGate["auto_approve_above"] = gateConfig.AutoApproveAbove
		approvalGate["ttl_seconds"] = int(gateConfig.TTL.Seconds())
		approvalGate["max_pending"] = gateConfig.MaxPending
	}

	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":           cfg.Enabled,
		"dry_run":           cfg.GetDryRun(),
		"preset":            cfg.Preset,
		"global_allow_list": cfg.GlobalAllowList,
		"approval_gate":     approvalGate,
		"policies":          policySummary,
		"valid_presets":     core.ValidPresets(),
		"valid_actions":     []string{"block_ip", "kill_process", "quarantine_file", "drop_connection", "disable_user", "webhook", "command", "log_only"},
	})
}

func (s *Server) handleEnforceConfigPost(w http.ResponseWriter, r *http.Request) {
	cfg := s.engine.Config.Enforcement
	if cfg == nil {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "enforcement not configured"})
		return
	}

	var body struct {
		DryRun           *bool    `json:"dry_run,omitempty"`
		AutoApproveAbove *string  `json:"auto_approve_above,omitempty"`
		RequireApproval  []string `json:"require_approval,omitempty"`
	}
	if err := decodeJSONBody(r, &body); err != nil {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}

	var gate *core.ApprovalGate
	if s.engine.ResponseEngine != nil {
		gate = s.engine.ResponseEngine.ApprovalGate
	}
	if err := core.UpdateApprovalSettings(cfg, gate, body.AutoApproveAbove, body.RequireApproval); err != nil {
		s.writeEnforcementJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	changes := make([]string, 0)
	if body.DryRun != nil {
		cfg.SetDryRun(*body.DryRun)
		changes = append(changes, "dry_run updated")
	}
	if body.AutoApproveAbove != nil {
		changes = append(changes, "auto_approve_above updated")
	}
	if body.RequireApproval != nil {
		changes = append(changes, "require_approval updated")
	}

	s.writeEnforcementJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "updated",
		"changes": changes,
	})
}
