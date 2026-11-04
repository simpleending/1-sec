package core

import "testing"

func TestSSHAuthPeerUsesValidatedProducerFields(t *testing.T) {
	for _, tc := range []struct{ message, want string }{
		{"Failed password for invalid user from 192.0.2.99 from 198.51.100.8 port 50000 ssh2", "198.51.100.8"},
		{"Failed password for invalid user src 192.0.2.99 from 2001:db8::8 port 50000 ssh2 [preauth]", "2001:db8::8"},
		{"Accepted publickey for alice from 2001:db8::8 port 22 ssh2: RSA SHA256:abc", "2001:db8::8"},
		{"Invalid user alice from 198.51.100.8 port 12345 [preauth]", "198.51.100.8"},
		{"Failed password for root from ::ffff:198.51.100.8 port 22", "198.51.100.8"},
		{"Failed password for from 192.0.2.99 port 22 ssh2 from 198.51.100.8 port 55 ssh2", ""},
		{"Accepted publickey for alice from 198.51.100.8 port 22 ssh2: certificate ID from 192.0.2.99 port 33 ssh2", ""},
		{"Failed password for from 192.0.2.99 from not-an-ip port 22 ssh2", ""},
		{"Failed password for root from 999.1.2.3 port 22 ssh2", ""},
		{"Failed password for root from 198.51.100.8 port 65536 ssh2", ""},
		{"Failed password for root from 198.51.100.8 port 0 ssh2", ""},
		{"Failed password for root from fe80::1%eth0 port 22 ssh2", ""},
		{"Failed password for root from 198.51.100.8 port 22 unexpected suffix", ""},
		{"arbitrary user from 198.51.100.8 port 22", ""},
	} {
		got, ok := SSHAuthPeer(tc.message)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%q: got %q/%v, want %q", tc.message, got, ok, tc.want)
		}
	}
	for _, daemon := range []string{"sshd", "sshd-session", "sshd-auth"} {
		body, ok := SSHLogMessage("Nov  5 00:00:00 host " + daemon + "[42]: Accepted password for root from 198.51.100.8 port 22 ssh2")
		if !ok {
			t.Fatal("lost daemon", daemon)
		}
		if peer, ok := SSHAuthPeer(body); !ok || peer != "198.51.100.8" {
			t.Fatal("lost ordinary peer")
		}
	}
}
