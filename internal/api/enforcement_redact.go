package api

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/1sec-project/1sec/internal/core"
)

var enforcementURL = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)

// Redact detached JSON so monitoring cannot change live policies or retry data.
func (s *Server) writeEnforcementJSON(w http.ResponseWriter, status int, value interface{}) {
	data, err := json.Marshal(value)
	if err != nil {
		writeError(w, 500, "serialization_error", "cannot encode enforcement view")
		return
	}
	var detached interface{}
	if err := json.Unmarshal(data, &detached); err != nil {
		writeError(w, 500, "serialization_error", "cannot encode enforcement view")
		return
	}
	secrets := core.ConfiguredSecretValues(s.engine.Config)
	var scrub func(interface{}) interface{}
	scrub = func(v interface{}) interface{} {
		switch x := v.(type) {
		case map[string]interface{}:
			for k, val := range x {
				x[k] = scrub(val)
			}
		case []interface{}:
			for i, val := range x {
				x[i] = scrub(val)
			}
		case string:
			return enforcementURL.ReplaceAllString(core.RedactString(x, secrets), core.RedactedValue)
		}
		return v
	}
	writeJSON(w, status, core.RedactSecrets(scrub(detached)))
}
