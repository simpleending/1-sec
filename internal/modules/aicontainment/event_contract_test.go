package aicontainment

import (
	"testing"

	"github.com/1sec-project/1sec/internal/core"
)

func TestShadowAINetworkEventAliases(t *testing.T) {
	for _, eventType := range []string{"network_request", "network_connection"} {
		for _, tc := range []struct {
			host string
			want bool
		}{
			{"api.openai.com", true},
			{"example.org", false},
			{"api.openai.com.example.org", false},
		} {
			t.Run(eventType+"/"+tc.host, func(t *testing.T) {
				cp := makeCapturingPipeline()
				module := startedModuleWithPipeline(t, cp)
				t.Cleanup(func() { _ = module.Stop() })
				event := core.NewSecurityEvent("sensor", eventType, core.SeverityInfo, "connection observed")
				event.SourceIP = "192.0.2.5"
				event.Details["dest_host"] = tc.host
				if err := module.HandleEvent(event); err != nil {
					t.Fatal(err)
				}
				if got := cp.hasAlertType("shadow_ai_detected"); got != tc.want {
					t.Fatalf("shadow AI alert = %v, want %v", got, tc.want)
				}
			})
		}
	}
}
