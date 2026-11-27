package core

import (
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
)

func TestUnsignedRustResultsRetainAlertsWithoutEnforcement(t *testing.T) {
	pipeline := NewAlertPipeline(zerolog.Nop(), 10)
	bridge := NewRustMatchBridge(zerolog.Nop(), pipeline, nil)
	result := RustMatchResult{
		EventID: "ordinary-observation", HighestSeverity: "high",
		Matches: []RustPatternMatch{{PatternName: "fixture", Category: "network", Severity: "high"}},
		Context: map[string]string{"source_ip": "192.0.2.10"},
	}
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	bridge.handleMatchResult(wire)
	alerts := pipeline.GetAlerts(SeverityHigh, 10)
	if len(alerts) != 1 || !alerts[0].ObservationOnly {
		t.Fatalf("unsigned match was lost or gained enforcement authority: %v", alerts)
	}
	if responseActionAllowed(alerts[0], ActionBlockIP) || !responseActionAllowed(alerts[0], ActionWebhook) {
		t.Fatal("unsigned result must be reportable without host response")
	}
}
