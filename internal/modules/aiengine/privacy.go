package aiengine

import (
	"encoding/json"
	"github.com/1sec-project/1sec/internal/core"
	"time"
)

// Allowlisted structural metadata only; even summaries can contain raw logs.
func aiEventMetadata(event *core.SecurityEvent) ([]byte, error) {
	eventType, category := "unknown", "unknown"
	if schema, ok := core.EventSchemaMap()[event.Type]; ok {
		eventType, category = schema.Type, schema.Category
	}
	return json.Marshal(struct {
		Timestamp time.Time     `json:"timestamp"`
		Module    string        `json:"module"`
		Type      string        `json:"type"`
		Severity  core.Severity `json:"severity"`
	}{event.Timestamp.UTC().Truncate(time.Minute), category, eventType, event.Severity})
}
