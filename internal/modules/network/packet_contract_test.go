package network

import (
	"github.com/1sec-project/1sec/internal/core"
	"os"
	"testing"
)

func TestRustPacketFixtureReachesNetworkAlerting(t *testing.T) {
	data, err := os.ReadFile("../../../rust/1sec-engine/testdata/packet_anomaly.json")
	if err != nil {
		t.Fatal(err)
	}
	event, err := core.UnmarshalSecurityEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	cp := makeCapturingPipeline()
	g := startedModuleWithPipeline(t, cp)
	defer g.Stop()
	if err := g.HandleEvent(event); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, alert := range cp.alerts {
		if alert.Type == "packet_anomaly" {
			found = true
		}
	}
	if !found {
		t.Fatal("capture anomaly did not reach alert pipeline")
	}
}

func TestPrivateNetworksAreNotBlanketBogons(t *testing.T) {
	reputation := NewIPReputation()
	for _, ip := range []string{"10.5.5.5", "172.16.0.1", "192.168.1.1"} {
		if reputation.IsMalicious(ip) {
			t.Fatal("legitimate private address treated as malicious", ip)
		}
	}
}
