package network

import (
	"fmt"
	"strings"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
)

func TestCapacityWarningsDoNotBecomeThreatEvidence(t *testing.T) {
	for _, values := range []interface{}{[]string{"tracking_capacity: history evicted"}, []interface{}{"tracking_capacity: history evicted"}} {
		cp := makeCapturingPipeline()
		g := startedModuleWithPipeline(t, cp)
		e := core.NewSecurityEvent("packet_capture", "network_connection", core.SeverityMedium, "packet")
		e.Source, e.SourceIP, e.DestIP = "packet_capture", "8.8.8.8", "1.1.1.1"
		e.Details["packet_anomalies"] = values
		if err := g.HandleEvent(e); err != nil {
			t.Fatal(err)
		}
		points, _ := g.ipReputation.GetThreatScore(e.SourceIP)
		if points != 0 {
			t.Errorf("capacity warning contributed %d threat points", points)
		}
		found := false
		for _, a := range cp.alerts {
			if a.Type == "packet_anomaly" {
				t.Error("operational warning became attack alert")
			}
			if a.Type == "tracking_capacity" {
				found = true
				if a.Metadata["source_ip"] != nil && a.Metadata["source_ip"] != "" {
					t.Error("capacity warning attributed a threat source")
				}
			}
		}
		if !found {
			t.Error("capacity loss was not reported")
		}
		if e.SourceIP != "8.8.8.8" {
			t.Error("source event mutated")
		}
		g.Stop()
	}
}

func TestMixedCapacityAndAttackKeepActualThreat(t *testing.T) {
	cp := makeCapturingPipeline()
	g := startedModuleWithPipeline(t, cp)
	defer g.Stop()
	e := core.NewSecurityEvent("packet_capture", "network_connection", core.SeverityMedium, "packet")
	e.Source, e.SourceIP, e.DestIP = "packet_capture", "8.8.8.8", "1.1.1.1"
	e.Details["packet_anomalies"] = []string{"tracking_capacity: history evicted", "websocket_invalid_frame: unmasked"}
	g.HandleEvent(e)
	found := false
	for _, a := range cp.alerts {
		if a.Type == "packet_anomaly" {
			found = true
			if strings.Contains(a.Description, "tracking_capacity") || a.Metadata["source_ip"] != e.SourceIP {
				t.Fatal("mixed warning corrupted actual attack evidence")
			}
		}
	}
	if !found {
		t.Fatal("actual packet anomaly suppressed")
	}
	points, _ := g.ipReputation.GetThreatScore(e.SourceIP)
	if points != 5 {
		t.Fatalf("actual packet threat points = %d", points)
	}
}

func TestNetworkStateBounds(t *testing.T) {
	t.Run("reputation", func(t *testing.T) {
		r := NewIPReputation()
		r.AddMalicious("pinned-source")
		for n := 0; n < 4200; n++ {
			r.RecordThreat(fmt.Sprintf("source-%d", n), "auth", core.SeverityHigh)
		}
		if n := len(r.AllThreats()); n > 4096 {
			t.Fatalf("retained %d sources", n)
		}
		if !r.IsMalicious("pinned-source") {
			t.Fatal("configured deny entry was evicted")
		}
		for n := 0; n < 100; n++ {
			r.RecordThreat("active", fmt.Sprintf("module-%d", n), core.SeverityHigh)
		}
		_, modules := r.GetThreatScore("active")
		if modules > 32 {
			t.Fatalf("retained %d module labels", modules)
		}
	})
	t.Run("DNS query types", func(t *testing.T) {
		d := NewDNSTunnelDetector()
		for n := 0; n < 1000; n++ {
			d.Analyze("8.8.8.8", "example.com", fmt.Sprintf("unknown-%d", n), 0)
		}
		p, _ := d.queries.Get("8.8.8.8")
		if len(p.queryTypes) > 3 {
			t.Fatalf("retained %d arbitrary query types", len(p.queryTypes))
		}
		for n := 0; n < 100; n++ {
			if result := d.Analyze("1.1.1.1", "data.example.com", "txt", 600); n == 99 && !result.Exfiltration {
				t.Fatal("normal TXT detection was lost")
			}
		}
	})
	t.Run("scan inner sets", func(t *testing.T) {
		d := NewPortScanDetector()
		for n := 1; n <= 2000; n++ {
			d.Record("8.8.8.8", "target", n)
			d.Record("8.8.8.8", fmt.Sprintf("host-%d", n), 443)
		}
		p, _ := d.scans.Get("8.8.8.8")
		for _, ports := range p.portsByDest {
			if len(ports) > 20 {
				t.Fatalf("retained %d ports", len(ports))
			}
		}
		for _, hosts := range p.destsByPort {
			if len(hosts) > 10 {
				t.Fatalf("retained %d hosts", len(hosts))
			}
		}
	})
}
