package ingest

import (
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

func TestNetworkSyslogPreservesAlertEvidenceWithoutAuthority(t *testing.T) {
	server := NewSyslogServer(&core.SyslogConfig{}, nil, zerolog.Nop())
	raw := "<38>1 2026-11-27T09:00:01Z edge-gateway sshd 500 - - Accepted publickey for alice from 192.0.2.18 port 49321 ssh2"
	for _, peer := range []string{"192.0.2.91", "127.0.0.1"} {
		t.Run(peer, func(t *testing.T) {
			event := server.messageEvent(raw, peer)
			if !event.ObservationOnly || event.Sensor != nil {
				t.Fatal("network log must not carry response authority")
			}
			if event.Type != "auth_success" || string(event.RawData) != raw || event.Details["syslog_transport_ip"] != peer {
				t.Fatalf("log evidence lost: type=%s; raw=%q; peer=%v", event.Type, event.RawData, event.Details["syslog_transport_ip"])
			}
			derived := core.NewDerivedEvent(event, "auth_fortress", "example_observation", core.SeverityInfo, "Observed login")
			alert := core.NewAlert(derived, "Observed login", "Fixture")
			if !alert.ObservationOnly {
				t.Fatal("derived alert lost the observation boundary")
			}
		})
	}
}
