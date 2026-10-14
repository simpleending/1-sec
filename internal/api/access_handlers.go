package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/1sec-project/1sec/internal/modules/iot"
)

// Only trusted gateways holding a write key may submit verified identity context.
func (s *Server) handleManagementAccessCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req core.ManagementAccessRequest
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid access request")
		return
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request", "expected exactly one access request")
		return
	}
	mod, ok := s.engine.Registry.Get(iot.ModuleName)
	shield, isShield := mod.(*iot.Shield)
	if !ok || !isShield || !s.engine.Config.IsModuleEnabled(iot.ModuleName) {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "management access policy unavailable")
		return
	}
	decision := shield.CheckManagementAccess(req)
	status := http.StatusForbidden
	if decision.Allowed {
		status = http.StatusOK
	}
	s.logger.Info().Str("target", req.Target).Str("operator", req.Operator).
		Str("source_ip", req.SourceIP).Bool("allowed", decision.Allowed).
		Str("reason", decision.Reason).Msg("management access decision")
	writeJSON(w, status, decision)
}
