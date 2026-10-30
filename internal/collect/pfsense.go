package collect

import (
	"context"
	"strconv"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// PfSenseCollector parses pfSense/OPNsense filterlog CSV lines and emits
// network_connection canonical events with dest_port, protocol, and action.
//
// filterlog format (comma-separated):
// rule,sub-rule,anchor,tracker,interface,reason,action,direction,ip-version,...
// For IPv4 (ip-version=4): ...tos,ecn,ttl,id,offset,flags,proto-id,proto,length,src,dst,...
// TCP: ...src-port,dst-port,data-length,flags,seq,ack,window,urg,options
// UDP: ...src-port,dst-port,data-length
type PfSenseCollector struct {
	path   string
	tag    string
	cancel context.CancelFunc
}

func NewPfSenseCollector(path, tag string) *PfSenseCollector {
	if tag == "" {
		tag = "pfsense"
	}
	return &PfSenseCollector{path: path, tag: tag}
}

func (c *PfSenseCollector) Name() string { return "pfsense:" + c.path }

func (c *PfSenseCollector) Start(ctx context.Context, bus *core.EventBus, logger zerolog.Logger) error {
	ctx, c.cancel = context.WithCancel(ctx)

	return tailFile(ctx, c.path, func(line string) {
		if event := c.parseLine(line); event != nil {
			_ = bus.PublishEvent(event)
		}
	}, logger)
}

func (c *PfSenseCollector) parseLine(line string) *core.SecurityEvent {
	fields := strings.Split(line, ",")
	if len(fields) < 9 {
		return nil
	}

	action := fields[6]    // pass, block, reject
	direction := fields[7] // in, out
	ipVersion := fields[8]

	if ipVersion != "4" && ipVersion != "6" {
		return nil
	}
	if (ipVersion == "4" && len(fields) < 20) || (ipVersion == "6" && len(fields) < 17) {
		return nil
	}

	var srcIP, dstIP, proto string
	var srcPort, dstPort string

	if ipVersion == "4" && len(fields) >= 19 {
		proto = fields[16]
		srcIP = fields[18]
		dstIP = fields[19]

		protoUpper := strings.ToUpper(proto)
		if (protoUpper == "TCP" || protoUpper == "UDP") && len(fields) >= 22 {
			srcPort = fields[20]
			dstPort = fields[21]
		}
	} else if ipVersion == "6" {
		proto = fields[12]
		srcIP = fields[15]
		dstIP = fields[16]

		protoUpper := strings.ToUpper(proto)
		if (protoUpper == "TCP" || protoUpper == "UDP") && len(fields) >= 19 {
			srcPort = fields[17]
			dstPort = fields[18]
		}
	}

	severity := core.SeverityInfo
	if strings.ToLower(action) == "block" || strings.ToLower(action) == "reject" {
		severity = core.SeverityLow
	}

	summary := action + " " + proto + " " + srcIP
	if dstPort != "" {
		summary += " → " + dstIP + ":" + dstPort
	}

	event := core.NewSecurityEvent(c.tag, "network_connection", severity, summary)
	event.Source = "collector:" + c.tag
	event.SourceIP = srcIP
	event.DestIP = dstIP
	event.Details["protocol"] = proto
	event.Details["action"] = action
	event.Details["direction"] = direction

	if dstPort != "" {
		event.Details["dest_port"] = dstPort
		// Flag high-risk ports
		if p, err := strconv.Atoi(dstPort); err == nil {
			if p == 22 || p == 3389 || p == 445 || p == 23 {
				event.Severity = core.SeverityMedium
			}
		}
	}
	if srcPort != "" {
		event.Details["src_port"] = srcPort
	}

	event.RawData = []byte(line)
	return event
}

func (c *PfSenseCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
