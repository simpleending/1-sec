package api

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
)

type sensorContextKey struct{}

func sensorTransportAllowed(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	return err == nil && ip != nil && ip.IsLoopback()
}

func requestAPIKey(r *http.Request) string {
	if key := r.Header.Get("Authorization"); key != "" {
		return strings.TrimPrefix(key, "Bearer ")
	}
	return r.Header.Get("X-API-Key")
}

func (s *Server) handleSensors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.engine.Sensors == nil {
		writeError(w, 503, "unavailable", "sensor enrollment is not enabled")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]interface{}{"sensors": s.engine.Sensors.List()})
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var spec core.SensorSpec
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&spec) != nil || d.Decode(new(interface{})) != io.EOF {
			writeError(w, 400, "invalid_request", "invalid sensor grant")
			return
		}
		info, token, err := s.engine.Sensors.Enroll(spec)
		if err != nil {
			writeError(w, 400, "invalid_grant", err.Error())
			return
		}
		s.logger.Info().Str("sensor_id", info.ID).Str("credential_id", info.CredentialID).Msg("sensor enrolled")
		writeJSON(w, http.StatusCreated, map[string]interface{}{"sensor": info, "token": token})
	default:
		writeError(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (s *Server) handleSensorAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeError(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	if s.engine.Sensors == nil {
		writeError(w, 503, "unavailable", "sensor enrollment is not enabled")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/sensors/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	switch parts[1] {
	case "revoke":
		if err := s.engine.Sensors.Revoke(parts[0]); err != nil {
			writeError(w, 400, "unavailable", "sensor revocation failed")
			return
		}
		s.logger.Info().Str("sensor_id", parts[0]).Msg("sensor revoked")
		writeJSON(w, 200, map[string]string{"status": "revoked", "sensor_id": parts[0]})
	case "rotate":
		info, token, err := s.engine.Sensors.Rotate(parts[0])
		if err != nil {
			writeError(w, 400, "unavailable", "sensor rotation failed")
			return
		}
		s.logger.Info().Str("sensor_id", info.ID).Str("credential_id", info.CredentialID).Msg("sensor credential rotated")
		writeJSON(w, 200, map[string]interface{}{"sensor": info, "token": token})
	default:
		http.NotFound(w, r)
	}
}
