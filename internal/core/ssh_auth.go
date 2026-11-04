package core

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var (
	sshLogPrefix  = regexp.MustCompile(`(?i)(?:^|\s)(sshd(?:-session|-auth)?)(?:\[[0-9]+\])?:\s*(.*)$`)
	sshAuthPrefix = regexp.MustCompile(`(?i)^(?:(?:Failed|Accepted) \S+ for |Invalid user )`)
	sshPeerField  = regexp.MustCompile(`(?:^|\s)from (\S+) port ([0-9]+)`)
)

// SSHLogMessage extracts the body of a supported OpenSSH daemon log record.
func SSHLogMessage(line string) (string, bool) {
	m := sshLogPrefix.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[2], true
}

func IsSSHLogProgram(name string) bool {
	name = strings.ToLower(name)
	return name == "sshd" || name == "sshd-session" || name == "sshd-auth"
}

func IsSSHAuthMessage(message string) bool { return sshAuthPrefix.MatchString(message) }

// SSHAuthPeer reads OpenSSH's producer-generated peer/port field. Usernames and
// certificate descriptions are free text: multiple peer-shaped fields are
// ambiguous and must not grant an IP response target. Unknown formats stay
// observable without guessing a peer from a substring.
func SSHAuthPeer(message string) (string, bool) {
	if !sshAuthPrefix.MatchString(message) {
		return "", false
	}
	fields := sshPeerField.FindAllStringSubmatchIndex(message, -1)
	if len(fields) != 1 {
		return "", false
	}
	m := fields[0]
	peer, err := netip.ParseAddr(message[m[2]:m[3]])
	if err != nil || peer.Zone() != "" {
		return "", false
	}
	port, err := strconv.ParseUint(message[m[4]:m[5]], 10, 16)
	if err != nil || port == 0 {
		return "", false
	}
	suffix := strings.TrimSpace(message[m[1]:])
	if suffix != "" && suffix != "[preauth]" && suffix != "ssh2" && suffix != "ssh2 [preauth]" && !strings.HasPrefix(suffix, "ssh2: ") {
		return "", false
	}
	return peer.Unmap().String(), true
}
