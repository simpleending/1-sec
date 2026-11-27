package auth

import (
	"github.com/1sec-project/1sec/internal/core"
	"testing"
)

func TestAuthDecisionLanes(t *testing.T) {
	for _, kind := range []string{"observation", "sensor without local authority"} {
		t.Run(kind, func(t *testing.T) {
			f := startedModule(t)
			ip := "192.0.2.41"
			event := func(eventType string, observed bool) {
				e := core.NewSecurityEvent("fixture", eventType, core.SeverityInfo, "ordinary auth state sample")
				e.SourceIP = ip
				e.Details["username"] = "test-account"
				if observed {
					if kind == "observation" {
						e.ObservationOnly = true
					} else {
						e.Sensor = &core.SensorEvidence{}
					}
				}
				if err := f.HandleEvent(e); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 10; i++ {
				event("login_failure", true)
			}
			if !f.observations.loginTracker.IsLockedOut(ip) || f.loginTracker.IsLockedOut(ip) {
				t.Fatal("independent observation history or eligible isolation missing")
			}
			for i := 0; i < 10; i++ {
				event("login_failure", false)
			}
			if !f.loginTracker.IsLockedOut(ip) {
				t.Fatal("ordinary eligible history not tracked")
			}
			event("login_success", true)
			if !f.loginTracker.failures.Contains(ip) || f.observations.loginTracker.failures.Contains(ip) {
				t.Fatal("success reset the wrong lane")
			}
			event("login_success", false)
			if f.loginTracker.failures.Contains(ip) {
				t.Fatal("eligible success did not reset its own lane")
			}
		})
	}
}
