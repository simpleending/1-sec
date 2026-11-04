package collect

import "testing"

func TestAuthLogPeerCannotComeFromUsername(t *testing.T) {
	c := NewAuthLogCollector("", "")
	for _, peer := range []string{"198.51.100.8", "2001:db8::8"} {
		for _, username := range []string{"from 192.0.2.99", "src 192.0.2.99"} {
			line := "Nov  5 00:00:00 host sshd[42]: Failed password for invalid user " + username + " from " + peer + " port 50000 ssh2"
			e := c.parseLine(line)
			if e == nil || e.SourceIP != peer {
				t.Fatalf("username changed peer in %q: %+v", line, e)
			}
		}
	}
	e := c.parseLine("sshd[42]: Failed password for invalid user from 192.0.2.99 port 22 ssh2 from 2001:db8::8 port 50000 ssh2")
	if e == nil || e.SourceIP != "" {
		t.Fatalf("ambiguous peer was assigned: %+v", e)
	}
}
