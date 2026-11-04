package ingest

import (
	"github.com/1sec-project/1sec/internal/core"
	"testing"
)

func TestSyslogSSHPeerCannotComeFromUsername(t *testing.T) {
	for _, daemon := range []string{"sshd", "sshd-session", "sshd-auth"} {
		for _, peer := range []string{"198.51.100.8", "2001:db8::8"} {
			e := core.NewSecurityEvent("syslog", "auth_failure", core.SeverityMedium, "failure")
			e.SourceIP = "127.0.0.1"
			enrichEventFromSyslog(e, &syslogMessage{AppName: daemon, Message: "Failed password for invalid user from 192.0.2.99 from " + peer + " port 22 ssh2"})
			if e.SourceIP != peer {
				t.Fatalf("%s: poisoned peer %q", daemon, e.SourceIP)
			}
		}
	}
	for _, message := range []string{"Failed password for from 192.0.2.99 from invalid port 22 ssh2", "Failed password for from 192.0.2.99 port 22 ssh2 from 2001:db8::8 port 22 ssh2"} {
		e := core.NewSecurityEvent("syslog", "auth_failure", core.SeverityMedium, "failure")
		e.SourceIP = "127.0.0.1"
		enrichEventFromSyslog(e, &syslogMessage{AppName: "sshd", Message: message})
		if e.SourceIP != "" || e.Details["syslog_reported_ip"] != nil {
			t.Fatalf("ambiguous record acquired target: %+v", e)
		}
	}
}

func TestSSHAttributionSurvivesSyslogRepresentations(t *testing.T) {
	for _, raw := range []string{
		`<38>sshd[42]: Failed password for invalid user from 192.0.2.99 from 198.51.100.8 port 50000 ssh2`,
		`sshd[42]: Failed password for invalid user from 192.0.2.99 from 198.51.100.8 port 50000 ssh2`,
		`<38>Nov  5 00:00:00 host SSHD[42]: Failed password for invalid user from 192.0.2.99 from 198.51.100.8 port 50000 ssh2`,
		`<38>1 2026-11-05T00:00:00Z host SSHD 42 - - Failed password for root from 198.51.100.8 port 50000 ssh2`,
		`<38>1 2026-11-05T00:00:00Z host sshd 42 - [meta@1 x="from 192.0.2.99 port 22" escaped="a\]b"][other@1 a="b"] Failed password for root from 198.51.100.8 port 50000 ssh2`,
		"<38>1 2026-11-05T00:00:00Z host sshd 42 - - \xef\xbb\xbfFailed password for root from 198.51.100.8 port 50000 ssh2",
	} {
		msg := parseSyslog(raw)
		if msg == nil {
			msg = &syslogMessage{Message: raw}
		}
		e := core.NewSecurityEvent("syslog", "auth_failure", core.SeverityMedium, msg.Message)
		e.SourceIP = "127.0.0.1"
		enrichEventFromSyslog(e, msg)
		if e.SourceIP != "198.51.100.8" {
			t.Errorf("%q lost/poisoned peer: %q", raw, e.SourceIP)
		}
	}
}
