package collect

import "testing"

func TestPfSenseIPv6UDP(t *testing.T) {
	// Netgate's filterlog format: 9 common fields, 8 IPv6 fields, 3 UDP fields.
	line := "5,,,1000000103,igb0,match,pass,in,6,0x00,0x00000,64,UDP,17,72,2001:db8::1,2001:db8::2,53000,53,32"
	event := NewPfSenseCollector("", "").parseLine(line)
	if event == nil || event.SourceIP != "2001:db8::1" || event.DestIP != "2001:db8::2" || event.Details["protocol"] != "UDP" || event.Details["dest_port"] != "53" {
		t.Fatalf("valid IPv6 UDP log lost or misparsed: %#v", event)
	}
}

func TestPfSenseIPv6WithoutPorts(t *testing.T) {
	line := "5,,,1000000103,igb0,match,block,in,6,0x00,0x00000,64,ICMPv6,58,64,2001:db8::1,2001:db8::2"
	event := NewPfSenseCollector("", "").parseLine(line)
	if event == nil || event.SourceIP != "2001:db8::1" || event.DestIP != "2001:db8::2" {
		t.Fatalf("valid IPv6 non-TCP log lost: %#v", event)
	}
	if _, ok := event.Details["dest_port"]; ok {
		t.Fatal("invented port")
	}
}

func TestPfSenseIPv4AndTruncatedLogs(t *testing.T) {
	c := NewPfSenseCollector("", "")
	line := "5,,,1000000103,igb0,match,pass,in,4,0x0,,64,123,0,none,17,udp,60,192.0.2.1,198.51.100.1,53000,53,40"
	event := c.parseLine(line)
	if event == nil || event.SourceIP != "192.0.2.1" || event.Details["dest_port"] != "53" {
		t.Fatalf("IPv4 regression: %#v", event)
	}
	for _, line := range []string{"", "1,2,3", "5,,,100,igb0,match,pass,in,6,0,0,64,UDP"} {
		if c.parseLine(line) != nil {
			t.Fatal("accepted truncated log")
		}
	}
}
