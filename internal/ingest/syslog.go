package ingest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// SyslogServer listens for syslog messages (RFC 5424 / RFC 3164) over UDP and/or TCP,
// parses them into SecurityEvents, and publishes them to the NATS event bus.
type SyslogServer struct {
	cfg         *core.SyslogConfig
	bus         *core.EventBus
	logger      zerolog.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	udpConn     *net.UDPConn
	tcpLn       net.Listener
	mu          sync.Mutex
	connections map[net.Conn]struct{}
}

// NewSyslogServer creates a new syslog ingestion server.
func NewSyslogServer(cfg *core.SyslogConfig, bus *core.EventBus, logger zerolog.Logger) *SyslogServer {
	return &SyslogServer{
		cfg:         cfg,
		bus:         bus,
		logger:      logger.With().Str("component", "syslog_ingest").Logger(),
		connections: make(map[net.Conn]struct{}),
	}
}

// Start begins listening for syslog messages.
func (s *SyslogServer) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	proto := strings.ToLower(s.cfg.Protocol)
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	if proto == "udp" || proto == "both" {
		if err := s.startUDP(addr); err != nil {
			return fmt.Errorf("starting syslog UDP listener: %w", err)
		}
	}

	if proto == "tcp" || proto == "both" {
		if err := s.startTCP(addr); err != nil {
			return fmt.Errorf("starting syslog TCP listener: %w", err)
		}
	}

	s.logger.Info().Str("addr", addr).Str("protocol", proto).Msg("syslog ingestion started")
	return nil
}

// Stop shuts down the syslog server.
func (s *SyslogServer) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.tcpLn != nil {
		s.tcpLn.Close()
	}
	s.mu.Lock()
	for conn := range s.connections {
		conn.Close()
	}
	s.mu.Unlock()
	s.logger.Info().Msg("syslog ingestion stopped")
	return nil
}

func (s *SyslogServer) startUDP(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolving UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listening on UDP %s: %w", addr, err)
	}
	s.udpConn = conn

	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
			}

			s.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := s.udpConn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if s.ctx.Err() != nil {
					return
				}
				s.logger.Error().Err(err).Msg("UDP read error")
				continue
			}

			msg := string(buf[:n])
			sourceIP := ""
			if remoteAddr != nil {
				sourceIP = remoteAddr.IP.String()
			}
			s.processMessage(msg, sourceIP)
		}
	}()

	s.logger.Info().Str("addr", addr).Msg("syslog UDP listener started")
	return nil
}

func (s *SyslogServer) startTCP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on TCP %s: %w", addr, err)
	}
	s.tcpLn = ln

	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
			}

			conn, err := ln.Accept()
			if err != nil {
				if s.ctx.Err() != nil {
					return
				}
				s.logger.Error().Err(err).Msg("TCP accept error")
				continue
			}

			s.mu.Lock()
			limit := s.cfg.MaxConnections
			if limit <= 0 {
				limit = 128
			}
			if s.ctx.Err() != nil || len(s.connections) >= limit {
				s.mu.Unlock()
				conn.Close()
				continue
			}
			s.connections[conn] = struct{}{}
			s.mu.Unlock()
			go s.handleTCPConn(conn)
		}
	}()

	s.logger.Info().Str("addr", addr).Msg("syslog TCP listener started")
	return nil
}

func (s *SyslogServer) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
	timeout := time.Duration(s.cfg.ReadTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return
	}

	sourceIP := ""
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		sourceIP = addr.IP.String()
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 65536), 65536)

	for scanner.Scan() {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		s.processMessage(scanner.Text(), sourceIP)
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return
		}
	}

	if err := scanner.Err(); err != nil && s.ctx.Err() == nil {
		s.logger.Debug().Err(err).Str("remote", sourceIP).Msg("TCP connection read error")
	}
}

// processMessage parses a raw syslog line and publishes it as a SecurityEvent.
func (s *SyslogServer) processMessage(raw string, sourceIP string) {
	parsed := parseSyslog(raw)
	if parsed == nil {
		s.logger.Debug().Str("raw", truncate(raw, 200)).Msg("unparseable syslog message, forwarding as raw event")
		parsed = &syslogMessage{
			Severity: 6, // informational
			Facility: 1, // user
			Message:  raw,
		}
	}

	severity := syslogSeverityToCore(parsed.Severity)

	event := core.NewSecurityEvent("syslog", classifySyslogEvent(parsed), severity, parsed.Message)
	event.Source = "syslog"
	event.SourceIP = sourceIP
	event.Details["syslog_facility"] = parsed.Facility
	event.Details["syslog_severity"] = parsed.Severity
	event.Details["syslog_hostname"] = parsed.Hostname
	event.Details["syslog_app"] = parsed.AppName
	event.Details["syslog_pid"] = parsed.ProcID
	event.Details["syslog_msg_id"] = parsed.MsgID
	event.RawData = []byte(raw)

	if parsed.Timestamp != nil {
		event.Timestamp = *parsed.Timestamp
	}

	// Extract structured fields (username, source IP, process info) from message
	enrichEventFromSyslog(event, parsed)

	if err := s.bus.PublishEvent(event); err != nil {
		s.logger.Error().Err(err).Msg("failed to publish syslog event")
	}
}

// syslogMessage represents a parsed syslog message.
type syslogMessage struct {
	Facility  int
	Severity  int
	Timestamp *time.Time
	Hostname  string
	AppName   string
	ProcID    string
	MsgID     string
	Message   string
}

// RFC 5424 pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
var rfc5424Re = regexp.MustCompile(`^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$`)

// RFC 3164 pattern: <PRI>TIMESTAMP HOSTNAME MSG
var rfc3164Re = regexp.MustCompile(`^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$`)

// Bare priority pattern: <PRI>MSG
var barePriRe = regexp.MustCompile(`^<(\d{1,3})>(.+)$`)

func parseSyslog(raw string) *syslogMessage {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	// Try RFC 5424 first
	if m := rfc5424Re.FindStringSubmatch(raw); m != nil {
		pri, _ := strconv.Atoi(m[1])
		msg := &syslogMessage{
			Facility: pri / 8,
			Severity: pri % 8,
			Hostname: m[4],
			AppName:  m[5],
			ProcID:   m[6],
			MsgID:    m[7],
			Message:  m[8],
		}
		if t, err := time.Parse(time.RFC3339, m[3]); err == nil {
			msg.Timestamp = &t
		}
		return msg
	}

	// Try RFC 3164
	if m := rfc3164Re.FindStringSubmatch(raw); m != nil {
		pri, _ := strconv.Atoi(m[1])
		msg := &syslogMessage{
			Facility: pri / 8,
			Severity: pri % 8,
			Hostname: m[3],
			Message:  m[4],
		}
		// Parse BSD-style timestamp (add current year)
		tsStr := fmt.Sprintf("%d %s", time.Now().Year(), m[2])
		if t, err := time.Parse("2006 Jan  2 15:04:05", tsStr); err == nil {
			msg.Timestamp = &t
		} else if t, err := time.Parse("2006 Jan 2 15:04:05", tsStr); err == nil {
			msg.Timestamp = &t
		}
		// Extract app name from message if present (e.g., "sshd[1234]: message")
		if idx := strings.Index(msg.Message, ":"); idx > 0 {
			appPart := msg.Message[:idx]
			if pidIdx := strings.Index(appPart, "["); pidIdx > 0 {
				msg.AppName = appPart[:pidIdx]
				msg.ProcID = strings.Trim(appPart[pidIdx:], "[]")
			} else {
				msg.AppName = appPart
			}
			msg.Message = strings.TrimSpace(msg.Message[idx+1:])
		}
		return msg
	}

	// Try bare priority
	if m := barePriRe.FindStringSubmatch(raw); m != nil {
		pri, _ := strconv.Atoi(m[1])
		return &syslogMessage{
			Facility: pri / 8,
			Severity: pri % 8,
			Message:  m[2],
		}
	}

	return nil
}

// syslogSeverityToCore maps syslog severity (0=emergency..7=debug) to core.Severity.
func syslogSeverityToCore(syslogSev int) core.Severity {
	switch {
	case syslogSev <= 1: // emergency, alert
		return core.SeverityCritical
	case syslogSev <= 3: // critical, error
		return core.SeverityHigh
	case syslogSev <= 4: // warning
		return core.SeverityMedium
	case syslogSev <= 5: // notice
		return core.SeverityLow
	default: // info, debug
		return core.SeverityInfo
	}
}

// classifySyslogEvent determines the event type from syslog content for routing.
// Returns event types that match what downstream modules actually handle, so events
// are properly processed by the auth, network, and runtime modules.
var (
	authFailureRe = regexp.MustCompile(`(?i)(failed\s+password|authentication\s+failure|invalid\s+user|failed\s+login|access\s+denied|bad\s+password|account\s+locked)`)
	authSuccessRe = regexp.MustCompile(`(?i)(accepted\s+password|accepted\s+publickey|session\s+opened|successful\s+login|logged\s+in)`)
	authSessionRe = regexp.MustCompile(`(?i)(session\s+closed|session\s+expired|session\s+timeout)`)
	sudoRe        = regexp.MustCompile(`(?i)(sudo:.*COMMAND|su:|privilege|setuid|capability)`)
	firewallRe    = regexp.MustCompile(`(?i)(iptables|firewall|nftables|ufw|denied|blocked|drop|reject|connection\s+refused)`)
	kernelRe      = regexp.MustCompile(`(?i)(kernel|oom|segfault|panic|oops|bug:|call\s+trace)`)
	fileChangeRe  = regexp.MustCompile(`(?i)(file\s+changed|integrity|modified|created|deleted|inotify|auditd.*write|auditd.*unlink)`)
	processRe     = regexp.MustCompile(`(?i)(exec|process|command|started|spawned|fork)`)
	authGenericRe = regexp.MustCompile(`(?i)(sshd|login|auth|pam)`)

	// Extended classifiers for richer event routing
	dnsRe         = regexp.MustCompile(`(?i)(named|dnsmasq|unbound|bind|query|NXDOMAIN|SERVFAIL)`)
	dhcpRe        = regexp.MustCompile(`(?i)(dhcpd|dhclient|DHCPACK|DHCPREQUEST|DHCPDISCOVER)`)
	cronRe        = regexp.MustCompile(`(?i)(cron|CRON|anacron)`)
	mfaRe         = regexp.MustCompile(`(?i)(mfa|2fa|two.factor|otp|totp|yubikey|duo)`)
	pfSenseRe     = regexp.MustCompile(`(?i)(filterlog|pf:)`)
	nginxAccessRe = regexp.MustCompile(`(?i)(\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[|"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+)`)
)

// syslogUsernameRe extracts usernames from common syslog auth messages.
var syslogUsernameRe = regexp.MustCompile(`(?i)(?:for(?:\s+invalid)?\s+user\s+|user[=:\s]+|acct="?)(\S+?)(?:"|'|\s|$)`)

// syslogSrcIPRe extracts source IPs from syslog messages (e.g., "from 1.2.3.4 port 22").
var syslogSrcIPRe = regexp.MustCompile(`(?:from|src|SRC=|source[=:\s])[\s=]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// syslogDstIPRe extracts destination IPs from syslog messages.
var syslogDstIPRe = regexp.MustCompile(`(?:to|dst|DST=|dest[=:\s])[\s=]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// syslogPortRe extracts port numbers from syslog messages.
var syslogPortRe = regexp.MustCompile(`(?:port|DPT=|SPT=|dport|sport)[=:\s]*(\d{1,5})`)

// syslogProtoRe extracts protocol from syslog messages.
var syslogProtoRe = regexp.MustCompile(`(?:PROTO=|protocol[=:\s]*)(\w+)`)

// nginxFieldsRe extracts HTTP method, path, status, and size from nginx-style access logs.
var nginxFieldsRe = regexp.MustCompile(`"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\S+"\s+(\d{3})\s+(\d+)`)

func classifySyslogEvent(msg *syslogMessage) string {
	combined := msg.AppName + " " + msg.Message

	// Auth sub-classification — produce types the auth module handles
	if authFailureRe.MatchString(combined) {
		return "auth_failure"
	}
	if authSuccessRe.MatchString(combined) {
		return "auth_success"
	}
	if authSessionRe.MatchString(combined) {
		return "session_activity"
	}
	if mfaRe.MatchString(combined) {
		return "mfa_attempt"
	}
	if sudoRe.MatchString(combined) {
		return "privilege_change"
	}

	// Network/firewall events — produce types the network module handles
	if pfSenseRe.MatchString(combined) {
		return "network_connection"
	}
	if firewallRe.MatchString(combined) {
		return "network_connection"
	}
	if dnsRe.MatchString(combined) {
		return "dns_query"
	}

	// HTTP access logs — produce types the injection/API modules handle
	if nginxAccessRe.MatchString(combined) {
		return "http_request"
	}

	// Kernel/system events — produce types the runtime module handles
	if kernelRe.MatchString(combined) {
		return "process_exec"
	}
	if fileChangeRe.MatchString(combined) {
		return "file_change"
	}
	if cronRe.MatchString(combined) {
		return "scheduled_task"
	}
	if processRe.MatchString(combined) {
		return "process_exec"
	}

	// Generic auth (sshd, pam, etc.) that didn't match a specific sub-type
	if authGenericRe.MatchString(combined) {
		return "auth_attempt"
	}

	// Classify by syslog facility
	switch msg.Facility {
	case 4, 10: // auth, authpriv
		return "auth_attempt"
	case 0: // kern
		return "process_exec"
	default:
		return "syslog_event"
	}
}

// enrichEventFromSyslog extracts structured fields (username, source IP, dest IP,
// ports, protocol, HTTP fields) from syslog message content and populates the
// event's Details map so downstream modules can process the event properly.
func enrichEventFromSyslog(event *core.SecurityEvent, msg *syslogMessage) {
	combined := msg.AppName + " " + msg.Message

	// Extract username
	if m := syslogUsernameRe.FindStringSubmatch(combined); m != nil {
		event.Details["username"] = m[1]
	}

	// Extract source IP from message body (overrides UDP/TCP source if present)
	if m := syslogSrcIPRe.FindStringSubmatch(combined); m != nil {
		event.Details["syslog_reported_ip"] = m[1]
		// If the event's SourceIP is the syslog relay, use the reported IP instead
		if event.SourceIP == "" || event.SourceIP == "127.0.0.1" {
			event.SourceIP = m[1]
		}
	}

	// Extract destination IP
	if m := syslogDstIPRe.FindStringSubmatch(combined); m != nil {
		event.DestIP = m[1]
	}

	// Extract port numbers
	if ports := syslogPortRe.FindAllStringSubmatch(combined, -1); len(ports) > 0 {
		event.Details["dest_port"] = ports[0][1]
		if len(ports) > 1 {
			event.Details["src_port"] = ports[1][1]
		}
	}

	// Extract protocol
	if m := syslogProtoRe.FindStringSubmatch(combined); m != nil {
		event.Details["protocol"] = m[1]
	}

	// Extract HTTP fields from nginx/apache-style access logs
	if m := nginxFieldsRe.FindStringSubmatch(combined); m != nil {
		event.Details["method"] = m[1]
		event.Details["path"] = m[2]
		event.Details["status_code"] = m[3]
		event.Details["response_size"] = m[4]
	}

	// Extract process/command info for runtime module
	if msg.AppName != "" {
		event.Details["process_name"] = msg.AppName
	}
	if msg.ProcID != "" {
		event.Details["pid"] = msg.ProcID
	}

	// Extract command line from sudo messages
	if sudoRe.MatchString(combined) {
		if idx := strings.Index(combined, "COMMAND="); idx >= 0 {
			event.Details["command_line"] = strings.TrimSpace(combined[idx+8:])
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
