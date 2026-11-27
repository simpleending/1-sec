package network

import (
	"github.com/1sec-project/1sec/internal/core"
	"testing"
)

func TestNetworkDecisionLanes(t *testing.T) {
	g := startedModule(t)
	ip := "192.0.2.45"
	report := func(module string, observed bool) {
		e := core.NewSecurityEvent(module, "network_observation", core.SeverityMedium, "ordinary source status sample")
		e.SourceIP = ip
		e.ObservationOnly = observed
		if err := g.HandleEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	report("first", true)
	report("second", true)
	report("third", false)
	eligibleScore, eligibleModules := g.GetIPReputation().GetThreatScore(ip)
	observedScore, observedModules := g.observations.ipReputation.GetThreatScore(ip)
	if eligibleScore <= 0 || eligibleModules != 1 || observedScore <= eligibleScore || observedModules != 2 {
		t.Fatalf("wrong histories: eligible %d/%d, observed %d/%d", eligibleScore, eligibleModules, observedScore, observedModules)
	}
}
