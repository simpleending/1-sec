package network

import (
	"context"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog"
)

const ModuleName = "network_guardian"

// Guardian is the Network Guardian module providing DDoS mitigation,
// rate limiting, IP reputation, geo-fencing, DNS tunneling detection,
// C2 covert channel detection, lateral movement detection, port scan
// detection, and protocol-level anomaly analysis.
type Guardian struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	cfg          *core.Config
	ctx          context.Context
	cancel       context.CancelFunc
	rateLimiter  *RateLimiter
	ipReputation *IPReputation
	geoFence     *GeoFence
	dnsTunnelDet *DNSTunnelDetector
	c2Detector   *C2Detector
	lateralMon   *LateralMovementMonitor
	portScanDet  *PortScanDetector
}

func New() *Guardian { return &Guardian{} }

func (g *Guardian) Name() string { return ModuleName }
func (g *Guardian) Description() string {
	return "DDoS mitigation, rate limiting, IP reputation, geo-fencing, DNS tunneling detection, C2 covert channel detection, lateral movement detection, and port scan detection"
}
func (g *Guardian) EventTypes() []string {
	// Network guardian is a catch-all: it needs to see events from ALL modules
	// for cross-module dynamic IP threat scoring (any event with a SourceIP and
	// severity >= MEDIUM accumulates threat points). It also handles its own
	// specific event types (DNS, connections, lateral movement, port scans).
	return nil
}

// GetIPReputation returns the IP reputation tracker for external access (API).
func (g *Guardian) GetIPReputation() *IPReputation {
	return g.ipReputation
}

func (g *Guardian) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	g.ctx, g.cancel = context.WithCancel(ctx)
	g.bus = bus
	g.pipeline = pipeline
	g.cfg = cfg
	g.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)
	maxReqPerMin := getIntSetting(settings, "max_requests_per_minute", 1000)
	burstSize := getIntSetting(settings, "burst_size", 100)
	g.rateLimiter = NewRateLimiter(maxReqPerMin, burstSize)
	g.ipReputation = NewIPReputation()
	g.geoFence = NewGeoFence(settings)
	g.dnsTunnelDet = NewDNSTunnelDetector()
	g.c2Detector = NewC2Detector()
	g.lateralMon = NewLateralMovementMonitor()
	g.portScanDet = NewPortScanDetector()

	// Cleanup loops replaced by bounded LRU caches
	// Start dynamic IP threat score cleanup
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-g.ctx.Done():
				return
			case <-ticker.C:
				g.ipReputation.CleanupScores(1 * time.Hour)
			}
		}
	}()

	g.logger.Info().
		Int("max_rpm", maxReqPerMin).
		Int("burst", burstSize).
		Msg("network guardian started")
	return nil
}

func (g *Guardian) Stop() error {
	if g.cancel != nil {
		g.cancel()
	}
	return nil
}

func (g *Guardian) HandleEvent(event *core.SecurityEvent) error {
	// Cross-module dynamic IP threat scoring: when ANY module fires an alert-worthy
	// event with a source IP, accumulate threat points. IPs that trigger multiple
	// modules get auto-blocked. This replaces the need for external TI feeds.
	packetThreats, capacityWarnings := splitPacketAnomalies(event)
	capacityOnly := len(capacityWarnings) > 0 && len(packetThreats) == 0
	if event.SourceIP != "" && event.Module != ModuleName && event.Severity >= core.SeverityMedium && !capacityOnly {
		newlyBlocked, evicted := g.ipReputation.recordThreat(event.SourceIP, event.Module, event.Severity)
		if evicted {
			g.reportCapacity(event, "IP reputation history evicted; dynamic scoring coverage reduced")
		}
		if newlyBlocked {
			points, modules := g.ipReputation.GetThreatScore(event.SourceIP)
			g.raiseAlert(event, core.SeverityCritical,
				"IP Auto-Blocked by Dynamic Threat Scoring",
				fmt.Sprintf("IP %s auto-blocked after accumulating %d threat points from %d modules. "+
					"Multiple security modules flagged this source — high confidence malicious actor.",
					event.SourceIP, points, modules),
				"dynamic_ip_block")
		}
	}

	// Route specialized event types first
	switch event.Type {
	case "dns_query", "dns_response":
		g.handleDNSEvent(event)
		return nil
	case "network_connection", "connection_established":
		g.handleConnectionEvent(event)
		return nil
	case "lateral_movement", "smb_connection", "rdp_connection", "wmi_exec",
		"psexec", "ssh_connection", "winrm_connection":
		g.handleLateralMovementEvent(event)
		return nil
	case "port_scan", "syn_scan", "connection_attempt":
		g.handlePortScanEvent(event)
		return nil
	case "amplification_attack", "reflection_attack":
		g.handleAmplificationEvent(event)
		return nil
	}

	if event.SourceIP == "" {
		return nil
	}

	// IP reputation
	if g.ipReputation.IsMalicious(event.SourceIP) {
		g.raiseAlert(event, core.SeverityHigh,
			"Malicious IP Detected",
			fmt.Sprintf("Request from known malicious IP %s", event.SourceIP),
			"ip_reputation")
	}

	// Rate limiting
	if !g.rateLimiter.Allow(event.SourceIP) {
		g.raiseAlert(event, core.SeverityMedium,
			"Rate Limit Exceeded",
			fmt.Sprintf("IP %s exceeded rate limit of %d requests/minute",
				event.SourceIP, g.rateLimiter.maxPerMinute),
			"rate_limit")
	}

	// Geo-fence
	countryCode := getStringDetail(event, "country")
	if countryCode == "" {
		countryCode = getStringDetail(event, "country_code")
	}
	if countryCode == "" {
		countryCode = getStringDetail(event, "geo_country")
	}
	if g.geoFence.IsBlockedCountry(countryCode) {
		g.raiseAlert(event, core.SeverityMedium,
			"Geo-Fence Violation",
			fmt.Sprintf("Request from geo-blocked country %s (IP: %s)", countryCode, event.SourceIP),
			"geo_fence")
	}

	// DDoS detection
	g.rateLimiter.RecordRequest(event.SourceIP)
	if g.rateLimiter.DetectDDoS() {
		g.raiseAlert(event, core.SeverityCritical,
			"Potential DDoS Attack",
			fmt.Sprintf("Abnormal traffic spike detected. Current rate: %d req/s, threshold: %d req/s",
				g.rateLimiter.CurrentRate(), g.rateLimiter.DDoSThreshold()),
			"ddos")
	}

	return nil
}

// handleDNSEvent detects DNS tunneling, DGA domains, and DNS-based exfiltration.
func (g *Guardian) handleDNSEvent(event *core.SecurityEvent) {
	domain := getStringDetail(event, "domain")
	queryType := getStringDetail(event, "query_type")
	responseSize := getIntDetail(event, "response_size")
	sourceIP := event.SourceIP

	if domain == "" || sourceIP == "" {
		return
	}

	result := g.dnsTunnelDet.Analyze(sourceIP, domain, queryType, responseSize)

	if result.Tunneling {
		g.raiseAlert(event, core.SeverityCritical,
			"DNS Tunneling Detected",
			fmt.Sprintf("IP %s is using DNS tunneling via domain %s. Indicators: %s. "+
				"Query rate: %d/min, avg subdomain length: %.0f chars, entropy: %.2f. "+
				"This is a covert C2/exfiltration channel.",
				sourceIP, result.BaseDomain, strings.Join(result.Indicators, ", "),
				result.QueryRate, result.AvgSubdomainLen, result.Entropy),
			"dns_tunneling")
	}

	if result.DGA {
		g.raiseAlert(event, core.SeverityHigh,
			"Domain Generation Algorithm Detected",
			fmt.Sprintf("IP %s is querying DGA-generated domain %s (entropy: %.2f). "+
				"This indicates malware using algorithmically generated domains for C2.",
				sourceIP, domain, result.Entropy),
			"dga_domain")
	}

	if result.Exfiltration {
		g.raiseAlert(event, core.SeverityHigh,
			"DNS Data Exfiltration Suspected",
			fmt.Sprintf("IP %s is exfiltrating data via DNS TXT/NULL queries to %s. "+
				"Large response sizes (%d bytes avg) and high query volume detected.",
				sourceIP, result.BaseDomain, responseSize),
			"dns_exfiltration")
	}
}

// handleConnectionEvent detects C2 beaconing, covert channels, and suspicious connections.
func (g *Guardian) handleConnectionEvent(event *core.SecurityEvent) {
	threats, warnings := splitPacketAnomalies(event)
	if len(warnings) > 0 {
		g.reportCapacity(event, strings.Join(warnings, "; "))
	}
	if len(threats) > 0 {
		g.raiseAlert(event, core.SeverityMedium, "Captured Packet Anomaly", strings.Join(threats, "; "), "packet_anomaly")
	}

	sourceIP := event.SourceIP
	destIP := event.DestIP
	destPort := getIntDetail(event, "dest_port")
	protocol := getStringDetail(event, "protocol")
	bytesOut := getIntDetail(event, "bytes_out")
	bytesIn := getIntDetail(event, "bytes_in")
	duration := getIntDetail(event, "duration_ms")

	if sourceIP == "" || destIP == "" {
		return
	}

	result := g.c2Detector.Analyze(sourceIP, destIP, destPort, protocol, bytesOut, bytesIn, duration)

	if result.Beaconing {
		g.raiseAlert(event, core.SeverityCritical,
			"C2 Beaconing Detected",
			fmt.Sprintf("IP %s is beaconing to %s:%d every ~%ds (jitter: %.1f%%). "+
				"Regular interval connections are a hallmark of command-and-control malware. "+
				"Beacon count: %d.",
				sourceIP, destIP, destPort, result.IntervalSec, result.JitterPct, result.BeaconCount),
			"c2_beaconing")
	}

	if result.CovertChannel {
		g.raiseAlert(event, core.SeverityHigh,
			"Covert Channel Detected",
			fmt.Sprintf("Suspicious covert channel between %s and %s:%d via %s. "+
				"Indicators: %s. Data ratio: %.2f (out/in).",
				sourceIP, destIP, destPort, protocol,
				strings.Join(result.Indicators, ", "), result.DataRatio),
			"covert_channel")
	}

	if result.SuspiciousPort {
		g.raiseAlert(event, core.SeverityMedium,
			"Suspicious Port Usage",
			fmt.Sprintf("Connection from %s to %s on unusual port %d/%s. "+
				"Non-standard ports may indicate tunneled or evasive traffic.",
				sourceIP, destIP, destPort, protocol),
			"suspicious_port")
	}
}

// handleLateralMovementEvent detects Pass-the-Hash, Kerberoasting, Golden Ticket,
// and other lateral movement techniques used by APT groups.
func (g *Guardian) handleLateralMovementEvent(event *core.SecurityEvent) {
	sourceIP := event.SourceIP
	destIP := event.DestIP
	technique := getStringDetail(event, "technique")
	user := getStringDetail(event, "username")
	authProto := getStringDetail(event, "auth_protocol")
	ticketType := getStringDetail(event, "ticket_type")
	encType := getStringDetail(event, "encryption_type")
	serviceName := getStringDetail(event, "service_name")

	if sourceIP == "" {
		return
	}

	result := g.lateralMon.Analyze(sourceIP, destIP, user, technique, authProto, ticketType, encType, serviceName, event.Type, getStringDetail(event, "ticket_lifetime"))

	if result.PassTheHash {
		g.raiseAlert(event, core.SeverityCritical,
			"Pass-the-Hash Attack Detected",
			fmt.Sprintf("IP %s is performing Pass-the-Hash lateral movement to %s as user %q. "+
				"NTLM authentication with hash reuse detected without password. "+
				"Targets reached: %d hosts. This is a MITRE ATT&CK T1550.002 technique.",
				sourceIP, destIP, user, result.TargetCount),
			"pass_the_hash")
	}

	if result.PassTheTicket {
		g.raiseAlert(event, core.SeverityCritical,
			"Pass-the-Ticket Attack Detected",
			fmt.Sprintf("IP %s is using stolen Kerberos ticket to access %s as %q. "+
				"Ticket replay from non-original host detected. "+
				"MITRE ATT&CK T1550.003.",
				sourceIP, destIP, user),
			"pass_the_ticket")
	}

	if result.Kerberoasting {
		g.raiseAlert(event, core.SeverityCritical,
			"Kerberoasting Attack Detected",
			fmt.Sprintf("IP %s requested %d TGS tickets with RC4 encryption in %s. "+
				"Mass service ticket requests with weak encryption indicate offline password cracking. "+
				"User: %q. MITRE ATT&CK T1558.003.",
				sourceIP, result.TicketCount, result.TimeWindow, user),
			"kerberoasting")
	}

	if result.GoldenTicket {
		g.raiseAlert(event, core.SeverityCritical,
			"Golden Ticket Attack Detected",
			fmt.Sprintf("IP %s is using a forged TGT (Golden Ticket) as %q. "+
				"Ticket lifetime anomaly detected: ticket valid for %s (normal max: 10h). "+
				"This grants unrestricted domain access. MITRE ATT&CK T1558.001.",
				sourceIP, user, result.TicketLifetime),
			"golden_ticket")
	}

	if result.DCSync {
		g.raiseAlert(event, core.SeverityCritical,
			"DCSync Attack Detected",
			fmt.Sprintf("IP %s is performing DCSync replication requests as %q. "+
				"Non-DC host requesting directory replication (DRS GetNCChanges). "+
				"This extracts all domain password hashes. MITRE ATT&CK T1003.006.",
				sourceIP, user),
			"dcsync")
	}

	if result.LateralSpread {
		g.raiseAlert(event, core.SeverityHigh,
			"Lateral Movement Spread Detected",
			fmt.Sprintf("IP %s has connected to %d internal hosts in %s via %s. "+
				"Rapid internal spreading pattern matches APT lateral movement. "+
				"Hosts: %s.",
				sourceIP, result.TargetCount, result.TimeWindow,
				event.Type, truncateList(result.Targets, 5)),
			"lateral_spread")
	}
}

// handlePortScanEvent detects horizontal/vertical port scanning and network reconnaissance.
func (g *Guardian) handlePortScanEvent(event *core.SecurityEvent) {
	sourceIP := event.SourceIP
	destIP := event.DestIP
	destPort := getIntDetail(event, "dest_port")

	if sourceIP == "" {
		return
	}

	result := g.portScanDet.Record(sourceIP, destIP, destPort)
	if result.CoverageReduced {
		g.reportCapacity(event, "Port-scan history evicted or reset; prior scan coverage reduced")
	}

	if result.HorizontalScan {
		g.raiseAlert(event, core.SeverityHigh,
			"Horizontal Port Scan Detected",
			fmt.Sprintf("IP %s is scanning port %d across at least %d hosts in %s. "+
				"Network reconnaissance in progress. MITRE ATT&CK T1046.",
				sourceIP, destPort, result.HostCount, result.TimeWindow),
			"horizontal_scan")
	}

	if result.VerticalScan {
		g.raiseAlert(event, core.SeverityHigh,
			"Vertical Port Scan Detected",
			fmt.Sprintf("IP %s is scanning at least %d ports on host %s in %s. "+
				"Service enumeration in progress. MITRE ATT&CK T1046.",
				sourceIP, result.PortCount, destIP, result.TimeWindow),
			"vertical_scan")
	}

	if result.StealthScan {
		g.raiseAlert(event, core.SeverityCritical,
			"Stealth Scan Detected",
			fmt.Sprintf("IP %s is performing a stealth SYN scan against %s. "+
				"Half-open connections detected across at least %d ports. "+
				"This evades connection logging. MITRE ATT&CK T1046.",
				sourceIP, destIP, result.PortCount),
			"stealth_scan")
	}
}

// handleAmplificationEvent detects DNS/NTP/memcached amplification and reflection attacks.
func (g *Guardian) handleAmplificationEvent(event *core.SecurityEvent) {
	protocol := getStringDetail(event, "protocol")
	amplificationFactor := getFloatDetail(event, "amplification_factor")
	sourceIP := event.SourceIP
	reflectorIP := getStringDetail(event, "reflector_ip")
	bytesReceived := getIntDetail(event, "bytes_received")

	severity := core.SeverityHigh
	if amplificationFactor > 50 {
		severity = core.SeverityCritical
	}

	g.raiseAlert(event, severity,
		"Amplification/Reflection Attack Detected",
		fmt.Sprintf("Amplification attack via %s detected. Reflector: %s, target: %s. "+
			"Amplification factor: %.1fx, volume: %d bytes. "+
			"Spoofed source IP used to reflect amplified traffic.",
			protocol, reflectorIP, sourceIP, amplificationFactor, bytesReceived),
		"amplification_attack")
}

// Capacity is sensor health, not evidence against the packet that triggered eviction.
func (g *Guardian) reportCapacity(event *core.SecurityEvent, description string) {
	health := *event
	health.SourceIP, health.DestIP = "", ""
	g.raiseAlert(&health, core.SeverityLow, "Tracking Capacity Reached", description, "tracking_capacity")
}

func splitPacketAnomalies(event *core.SecurityEvent) (threats, warnings []string) {
	if event.Source != "packet_capture" {
		return nil, nil
	}
	var entries []string
	switch values := event.Details["packet_anomalies"].(type) {
	case []string:
		entries = values
	case []interface{}:
		for _, value := range values {
			if text, ok := value.(string); ok {
				entries = append(entries, text)
			}
		}
	}
	for _, text := range entries {
		if strings.HasPrefix(text, "tracking_capacity:") {
			warnings = append(warnings, text)
		} else {
			threats = append(threats, text)
		}
	}
	return threats, warnings
}

func (g *Guardian) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.DestIP = event.DestIP
	newEvent.Details["original_event_id"] = event.ID

	if g.bus != nil {
		_ = g.bus.PublishEvent(newEvent)
	}
	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getNetworkMitigations(alertType)
	if g.pipeline != nil {
		g.pipeline.Process(alert)
	}
}

// ---------------------------------------------------------------------------
// RateLimiter — tracks request rates per IP
// ---------------------------------------------------------------------------

type RateLimiter struct {
	mu           sync.RWMutex
	counters     *lru.Cache[string, *ipCounter]
	maxPerMinute int
	burstSize    int
	globalCount  int64
	globalWindow time.Time
	ddosThresh   int
}

type ipCounter struct {
	count    int
	burst    int
	window   time.Time
	burstWin time.Time
	lastSeen time.Time
}

func NewRateLimiter(maxPerMinute, burstSize int) *RateLimiter {
	cache, _ := lru.New[string, *ipCounter](100000)
	return &RateLimiter{
		counters:     cache,
		maxPerMinute: maxPerMinute,
		burstSize:    burstSize,
		globalWindow: time.Now(),
		ddosThresh:   maxPerMinute * 10,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	counter, exists := rl.counters.Get(ip)
	if !exists {
		rl.counters.Add(ip, &ipCounter{count: 1, burst: 1, window: now, burstWin: now, lastSeen: now})
		return true
	}
	if now.Sub(counter.window) > time.Minute {
		counter.count = 0
		counter.window = now
	}
	if now.Sub(counter.burstWin) > time.Second {
		counter.burst = 0
		counter.burstWin = now
	}
	counter.count++
	counter.burst++
	counter.lastSeen = now
	if counter.burst > rl.burstSize {
		return false
	}
	return counter.count <= rl.maxPerMinute
}

func (rl *RateLimiter) RecordRequest(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	if now.Sub(rl.globalWindow) > time.Second {
		rl.globalCount = 0
		rl.globalWindow = now
	}
	rl.globalCount++
}

func (rl *RateLimiter) DetectDDoS() bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.globalCount > int64(rl.ddosThresh)
}

func (rl *RateLimiter) CurrentRate() int64 {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.globalCount
}

func (rl *RateLimiter) DDoSThreshold() int { return rl.ddosThresh }

// ---------------------------------------------------------------------------
// IPReputation — known malicious IP lists and bogon detection
// ---------------------------------------------------------------------------

type IPReputation struct {
	mu        sync.RWMutex
	malicious map[string]bool
	bogons    []*net.IPNet
	// Dynamic threat scoring — IPs accumulate threat points from cross-module
	// alerts and auto-promote to malicious when they exceed the threshold.
	// This replaces the need for external threat intelligence feeds.
	// shortcut: evicted/expired dynamic scores lose history; capacity warnings require load investigation.
	scores          *lru.Cache[string, *ipThreatScore]
	autoBlockThresh int
}

type ipThreatScore struct {
	Points    int
	Modules   map[string]int // which modules flagged this IP
	FirstSeen time.Time
	LastSeen  time.Time
	Blocked   bool
}

func NewIPReputation() *IPReputation {
	scores, _ := lru.New[string, *ipThreatScore](4096)
	rep := &IPReputation{
		malicious:       make(map[string]bool),
		scores:          scores,
		autoBlockThresh: 50, // 50 points = auto-block
	}
	bogonCIDRs := []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
	}
	for _, cidr := range bogonCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			rep.bogons = append(rep.bogons, network)
		}
	}
	return rep
}

func (r *IPReputation) IsMalicious(ip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.malicious[ip] {
		return true
	}
	if score, ok := r.scores.Peek(ip); ok && score.Blocked {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, bogon := range r.bogons {
		if bogon.Contains(parsed) {
			return true
		}
	}
	return false
}

func (r *IPReputation) AddMalicious(ips ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ip := range ips {
		r.malicious[ip] = true
	}
}

// RecordThreat adds threat points for an IP based on alert severity and module.
// When an IP accumulates enough points across modules, it's auto-blocked.
// Severity scoring: CRITICAL=20, HIGH=10, MEDIUM=5, LOW=2, INFO=1
func (r *IPReputation) RecordThreat(ip, module string, severity core.Severity) bool {
	blocked, _ := r.recordThreat(ip, module, severity)
	return blocked
}

func (r *IPReputation) recordThreat(ip, module string, severity core.Severity) (bool, bool) {
	if ip == "" {
		return false, false
	}

	points := 1
	switch severity {
	case core.SeverityCritical:
		points = 20
	case core.SeverityHigh:
		points = 10
	case core.SeverityMedium:
		points = 5
	case core.SeverityLow:
		points = 2
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	evicted := false
	score, exists := r.scores.Get(ip)
	if !exists {
		score = &ipThreatScore{
			Modules:   make(map[string]int),
			FirstSeen: now,
		}
		evicted = r.scores.Add(ip, score)
	}

	score.Points = min(score.Points, math.MaxInt-points) + points
	if score.Modules[module] > 0 || len(score.Modules) < 32 {
		score.Modules[module] = min(score.Modules[module], math.MaxInt-1) + 1
	}
	score.LastSeen = now

	// Auto-block if threshold exceeded and multiple modules flagged it
	if !score.Blocked && score.Points >= r.autoBlockThresh && len(score.Modules) >= 2 {
		score.Blocked = true
		return true, evicted // newly blocked
	}

	return false, evicted
}

// GetThreatScore returns the current threat score for an IP.
func (r *IPReputation) GetThreatScore(ip string) (int, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	score, exists := r.scores.Peek(ip)
	if !exists {
		return 0, 0
	}
	return score.Points, len(score.Modules)
}

// CleanupScores removes stale threat scores older than the given duration.
func (r *IPReputation) CleanupScores(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for _, ip := range r.scores.Keys() {
		score, _ := r.scores.Peek(ip)
		if score.LastSeen.Before(cutoff) {
			r.scores.Remove(ip)
		}
	}
}

// IPThreatInfo represents a tracked IP for API exposure.
type IPThreatInfo struct {
	IP        string         `json:"ip"`
	Points    int            `json:"points"`
	Modules   map[string]int `json:"modules"`
	Blocked   bool           `json:"blocked"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
}

// AllThreats returns all tracked IP threat scores.
func (r *IPReputation) AllThreats() []IPThreatInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]IPThreatInfo, 0, r.scores.Len())
	for _, ip := range r.scores.Keys() {
		score, _ := r.scores.Peek(ip)
		modules := make(map[string]int)
		for k, v := range score.Modules {
			modules[k] = v
		}
		result = append(result, IPThreatInfo{
			IP:        ip,
			Points:    score.Points,
			Modules:   modules,
			Blocked:   score.Blocked,
			FirstSeen: score.FirstSeen,
			LastSeen:  score.LastSeen,
		})
	}
	return result
}

// ---------------------------------------------------------------------------
// GeoFence — geographic access restrictions
// ---------------------------------------------------------------------------

type GeoFence struct {
	blockedCountries map[string]bool
	allowedCountries map[string]bool
	mode             string
}

func NewGeoFence(settings map[string]interface{}) *GeoFence {
	gf := &GeoFence{
		blockedCountries: make(map[string]bool),
		allowedCountries: make(map[string]bool),
		mode:             "block",
	}
	if mode, ok := settings["geo_mode"].(string); ok {
		gf.mode = mode
	}
	if blocked, ok := settings["blocked_countries"].(string); ok {
		for _, c := range strings.Split(blocked, ",") {
			c = strings.TrimSpace(strings.ToUpper(c))
			if c != "" {
				gf.blockedCountries[c] = true
			}
		}
	}
	if allowed, ok := settings["allowed_countries"].(string); ok {
		for _, c := range strings.Split(allowed, ",") {
			c = strings.TrimSpace(strings.ToUpper(c))
			if c != "" {
				gf.allowedCountries[c] = true
			}
		}
	}
	return gf
}

func (gf *GeoFence) IsBlocked(ip string) bool {
	if len(gf.blockedCountries) == 0 && len(gf.allowedCountries) == 0 {
		return false
	}
	return false
}

func (gf *GeoFence) IsBlockedCountry(countryCode string) bool {
	if countryCode == "" {
		return false
	}
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if gf.mode == "allow" {
		if len(gf.allowedCountries) == 0 {
			return false
		}
		return !gf.allowedCountries[countryCode]
	}
	return gf.blockedCountries[countryCode]
}

// ---------------------------------------------------------------------------
// DNSTunnelDetector — detects DNS tunneling, DGA domains, DNS exfiltration
// ---------------------------------------------------------------------------

type DNSTunnelDetector struct {
	mu       sync.Mutex
	queries  *lru.Cache[string, *dnsProfile] // key: sourceIP
	dgaCache *lru.Cache[string, bool]        // domain -> isDGA
}

type dnsProfile struct {
	domains       map[string]int // baseDomain -> query count
	subdomainLens []int
	queryTypes    map[string]int // TXT, NULL, CNAME, etc.
	totalQueries  int
	windowStart   time.Time
	lastSeen      time.Time
}

type DNSAnalysisResult struct {
	Tunneling       bool
	DGA             bool
	Exfiltration    bool
	BaseDomain      string
	Indicators      []string
	QueryRate       int
	AvgSubdomainLen float64
	Entropy         float64
}

func NewDNSTunnelDetector() *DNSTunnelDetector {
	qCache, _ := lru.New[string, *dnsProfile](50000)
	dCache, _ := lru.New[string, bool](100000)
	return &DNSTunnelDetector{
		queries:  qCache,
		dgaCache: dCache,
	}
}

func (d *DNSTunnelDetector) Analyze(sourceIP, domain, queryType string, responseSize int) DNSAnalysisResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	result := DNSAnalysisResult{}
	now := time.Now()

	// Extract base domain and subdomain
	parts := strings.Split(domain, ".")
	baseDomain := domain
	subdomain := ""
	if len(parts) > 2 {
		baseDomain = strings.Join(parts[len(parts)-2:], ".")
		subdomain = strings.Join(parts[:len(parts)-2], ".")
	}
	result.BaseDomain = baseDomain

	// Get or create profile
	profile, exists := d.queries.Get(sourceIP)
	if !exists || now.Sub(profile.windowStart) > 5*time.Minute {
		profile = &dnsProfile{
			domains:     make(map[string]int),
			queryTypes:  make(map[string]int),
			windowStart: now,
		}
		d.queries.Add(sourceIP, profile)
	}

	// Cap map size to prevent memory explosion per-IP
	if len(profile.domains) > 1000 {
		profile.domains = make(map[string]int) // Reset to avoid unbounded growth
	}
	if len(profile.subdomainLens) > 5000 {
		profile.subdomainLens = []int{}
	}

	profile.domains[baseDomain]++
	profile.totalQueries++
	profile.lastSeen = now
	queryType = strings.ToUpper(strings.TrimSpace(queryType))
	if queryType == "TXT" || queryType == "NULL" || queryType == "CNAME" {
		profile.queryTypes[queryType]++
	}
	if subdomain != "" {
		profile.subdomainLens = append(profile.subdomainLens, len(subdomain))
	}

	// Calculate entropy of the full domain
	result.Entropy = shannonEntropy(domain)

	// DGA detection: high entropy + no common TLD patterns
	if result.Entropy > 3.5 && len(domain) > 15 && !isCommonDomain(baseDomain) {
		consonantRatio := consonantRatio(domain)
		if consonantRatio > 0.65 || result.Entropy > 4.0 {
			result.DGA = true
			d.dgaCache.Add(domain, true)
		}
	}

	// DNS tunneling detection: multiple indicators
	var indicators []string
	domainQueries := profile.domains[baseDomain]

	// High query rate to single domain
	elapsed := now.Sub(profile.windowStart).Minutes()
	if elapsed < 1 {
		elapsed = 1
	}
	queryRate := int(float64(domainQueries) / elapsed)
	result.QueryRate = queryRate
	if queryRate > 60 {
		indicators = append(indicators, fmt.Sprintf("high query rate (%d/min)", queryRate))
	}

	// Long subdomains (data encoded in subdomain)
	if len(profile.subdomainLens) > 10 {
		avgLen := avgFloat(profile.subdomainLens)
		result.AvgSubdomainLen = avgLen
		if avgLen > 30 {
			indicators = append(indicators, fmt.Sprintf("long subdomains (avg %.0f chars)", avgLen))
		}
	}

	// Unusual query types (TXT, NULL, CNAME used for tunneling)
	txtCount := profile.queryTypes["TXT"] + profile.queryTypes["NULL"] + profile.queryTypes["CNAME"]
	if txtCount > 20 && float64(txtCount)/float64(profile.totalQueries) > 0.5 {
		indicators = append(indicators, "high TXT/NULL/CNAME ratio")
	}

	// High entropy subdomains (encoded data)
	if subdomain != "" && shannonEntropy(subdomain) > 3.8 && len(subdomain) > 20 {
		indicators = append(indicators, "high-entropy subdomain data")
	}

	if len(indicators) >= 2 {
		result.Tunneling = true
		result.Indicators = indicators
	}

	// DNS exfiltration: large TXT responses + high volume
	if (queryType == "TXT" || queryType == "NULL") && responseSize > 500 && domainQueries > 50 {
		result.Exfiltration = true
	}

	return result
}

// ---------------------------------------------------------------------------
// C2Detector — detects command-and-control beaconing and covert channels
// ---------------------------------------------------------------------------

type C2Detector struct {
	mu          sync.Mutex
	connections *lru.Cache[string, *c2Profile] // key: sourceIP:destIP:destPort
}

type c2Profile struct {
	intervals  []int64 // milliseconds between connections
	bytesOut   []int
	bytesIn    []int
	timestamps []time.Time
	protocol   string
	lastSeen   time.Time
}

type C2AnalysisResult struct {
	Beaconing      bool
	CovertChannel  bool
	SuspiciousPort bool
	IntervalSec    int
	JitterPct      float64
	BeaconCount    int
	DataRatio      float64
	Indicators     []string
}

func NewC2Detector() *C2Detector {
	cache, _ := lru.New[string, *c2Profile](100000)
	return &C2Detector{connections: cache}
}

func (c *C2Detector) Analyze(sourceIP, destIP string, destPort int, protocol string, bytesOut, bytesIn, durationMs int) C2AnalysisResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := C2AnalysisResult{}
	now := time.Now()
	key := fmt.Sprintf("%s:%s:%d", sourceIP, destIP, destPort)

	profile, exists := c.connections.Get(key)
	if !exists {
		profile = &c2Profile{protocol: protocol}
		c.connections.Add(key, profile)
	}

	// Record interval since last connection
	if len(profile.timestamps) > 0 {
		interval := now.Sub(profile.timestamps[len(profile.timestamps)-1]).Milliseconds()
		profile.intervals = append(profile.intervals, interval)
	}
	profile.timestamps = append(profile.timestamps, now)
	profile.bytesOut = append(profile.bytesOut, bytesOut)
	profile.bytesIn = append(profile.bytesIn, bytesIn)
	profile.lastSeen = now

	// Keep last 100 entries
	if len(profile.timestamps) > 100 {
		profile.timestamps = profile.timestamps[1:]
		profile.intervals = profile.intervals[1:]
		profile.bytesOut = profile.bytesOut[1:]
		profile.bytesIn = profile.bytesIn[1:]
	}

	// Beaconing detection: regular intervals with low jitter
	if len(profile.intervals) >= 5 {
		avgInterval := avgInt64(profile.intervals)
		stdDev := stdDevInt64(profile.intervals)
		if avgInterval > 0 {
			jitter := (stdDev / float64(avgInterval)) * 100
			result.JitterPct = jitter
			result.IntervalSec = int(avgInterval / 1000)
			result.BeaconCount = len(profile.timestamps)

			// Beaconing: consistent intervals (jitter < 25%) with enough samples
			if jitter < 25 && len(profile.intervals) >= 8 && avgInterval > 5000 && avgInterval < 3600000 {
				result.Beaconing = true
			}
		}
	}

	// Covert channel detection
	var indicators []string

	// Small, regular data transfers
	if len(profile.bytesOut) >= 10 {
		avgOut := avgIntSlice(profile.bytesOut)
		avgIn := avgIntSlice(profile.bytesIn)
		if avgIn > 0 {
			result.DataRatio = float64(avgOut) / float64(avgIn)
		}

		// Very small payloads (C2 commands are typically tiny)
		if avgOut < 200 && avgOut > 0 && avgIn < 500 && avgIn > 0 {
			indicators = append(indicators, "small bidirectional payloads")
		}

		// Consistent payload sizes (automated, not human)
		outStdDev := stdDevIntSlice(profile.bytesOut)
		if avgOut > 0 && outStdDev/float64(avgOut) < 0.2 {
			indicators = append(indicators, "consistent payload sizes")
		}
	}

	// Non-standard port for protocol
	if isNonStandardPort(destPort, protocol) {
		indicators = append(indicators, "non-standard port")
		result.SuspiciousPort = true
	}

	// Known C2 ports
	c2Ports := map[int]bool{
		4444: true, 5555: true, 8888: true, 1234: true,
		31337: true, 6667: true, 6697: true, 9999: true,
		12345: true, 54321: true, 7777: true, 1337: true,
	}
	if c2Ports[destPort] {
		indicators = append(indicators, "known C2 port")
		result.SuspiciousPort = true
	}

	if len(indicators) >= 2 {
		result.CovertChannel = true
		result.Indicators = indicators
	}

	return result
}

// ---------------------------------------------------------------------------
// LateralMovementMonitor — detects PtH, PtT, Kerberoasting, Golden Ticket, DCSync
// ---------------------------------------------------------------------------

type LateralMovementMonitor struct {
	mu             sync.Mutex
	movements      *lru.Cache[string, *lateralProfile] // key: sourceIP
	ticketRequests *lru.Cache[string, *ticketProfile]  // key: sourceIP
}

type lateralProfile struct {
	targets     map[string]time.Time // destIP -> first seen
	techniques  map[string]int       // technique -> count
	users       map[string]bool
	windowStart time.Time
	lastSeen    time.Time
}

type ticketProfile struct {
	tgsRequests  int
	rc4Requests  int
	tgtAnomalies int
	dcsyncCount  int
	windowStart  time.Time
	lastSeen     time.Time
}

type LateralResult struct {
	PassTheHash    bool
	PassTheTicket  bool
	Kerberoasting  bool
	GoldenTicket   bool
	DCSync         bool
	LateralSpread  bool
	TargetCount    int
	TicketCount    int
	TimeWindow     string
	TicketLifetime string
	Targets        []string
}

func NewLateralMovementMonitor() *LateralMovementMonitor {
	mCache, _ := lru.New[string, *lateralProfile](100000)
	tCache, _ := lru.New[string, *ticketProfile](100000)
	return &LateralMovementMonitor{
		movements:      mCache,
		ticketRequests: tCache,
	}
}

func (lm *LateralMovementMonitor) Analyze(sourceIP, destIP, user, technique, authProto, ticketType, encType, serviceName, eventType, ticketLifetime string) LateralResult {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	result := LateralResult{}
	now := time.Now()

	// Get or create movement profile
	mp, exists := lm.movements.Get(sourceIP)
	if !exists || now.Sub(mp.windowStart) > 30*time.Minute {
		mp = &lateralProfile{
			targets:     make(map[string]time.Time),
			techniques:  make(map[string]int),
			users:       make(map[string]bool),
			windowStart: now,
		}
		lm.movements.Add(sourceIP, mp)
	}

	// Bound internal maps to prevent memory explosion
	if len(mp.targets) > 1000 {
		mp.targets = make(map[string]time.Time)
	}
	if len(mp.techniques) > 100 {
		mp.techniques = make(map[string]int)
	}
	if len(mp.users) > 500 {
		mp.users = make(map[string]bool)
	}
	mp.lastSeen = now
	if destIP != "" {
		mp.targets[destIP] = now
	}
	if technique != "" {
		mp.techniques[technique]++
	}
	if user != "" {
		mp.users[user] = true
	}

	// Get or create ticket profile
	tp, texists := lm.ticketRequests.Get(sourceIP)
	if !texists || now.Sub(tp.windowStart) > 10*time.Minute {
		tp = &ticketProfile{windowStart: now}
		lm.ticketRequests.Add(sourceIP, tp)
	}
	tp.lastSeen = now

	// Pass-the-Hash: NTLM auth without password, multiple targets
	if strings.EqualFold(authProto, "ntlm") || technique == "pass_the_hash" || technique == "pth" {
		if len(mp.targets) >= 3 {
			result.PassTheHash = true
			result.TargetCount = len(mp.targets)
		}
	}

	// Pass-the-Ticket: Kerberos ticket reuse from unexpected host
	if technique == "pass_the_ticket" || technique == "ptt" ||
		(strings.EqualFold(authProto, "kerberos") && ticketType == "TGS" && technique == "ticket_reuse") {
		result.PassTheTicket = true
	}

	// Kerberoasting: mass TGS requests with RC4 encryption
	if ticketType == "TGS" || eventType == "tgs_request" {
		tp.tgsRequests++
		if strings.Contains(strings.ToLower(encType), "rc4") || encType == "0x17" || encType == "23" {
			tp.rc4Requests++
		}
		// 5+ TGS requests with RC4 in 10 minutes = Kerberoasting
		if tp.rc4Requests >= 5 {
			result.Kerberoasting = true
			result.TicketCount = tp.rc4Requests
			result.TimeWindow = now.Sub(tp.windowStart).Round(time.Second).String()
		}
	}

	// Golden Ticket: TGT with abnormal lifetime or from non-KDC
	if ticketType == "TGT" || technique == "golden_ticket" {
		tp.tgtAnomalies++
		if technique == "golden_ticket" || tp.tgtAnomalies >= 3 {
			result.GoldenTicket = true
			result.TicketLifetime = ticketLifetime
			if result.TicketLifetime == "" {
				result.TicketLifetime = ">10h (anomalous)"
			}
		}
	}

	// DCSync: directory replication from non-DC
	if technique == "dcsync" || technique == "drs_replication" || serviceName == "DRS_GetNCChanges" {
		tp.dcsyncCount++
		if tp.dcsyncCount >= 1 {
			result.DCSync = true
		}
	}

	// Lateral spread: many internal targets in short time
	result.TargetCount = len(mp.targets)
	result.TimeWindow = now.Sub(mp.windowStart).Round(time.Second).String()
	if len(mp.targets) >= 5 {
		result.LateralSpread = true
		result.Targets = make([]string, 0, len(mp.targets))
		for t := range mp.targets {
			result.Targets = append(result.Targets, t)
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// PortScanDetector — detects horizontal, vertical, and stealth port scans
// ---------------------------------------------------------------------------

type PortScanDetector struct {
	mu    sync.Mutex
	scans *lru.Cache[string, *scanProfile] // key: sourceIP
}

type scanProfile struct {
	// Vertical: ports per destination
	portsByDest map[string]map[int]bool // destIP -> set of ports
	// Horizontal: destinations per port
	destsByPort   map[int]map[string]bool // port -> set of destIPs
	synOnly       int                     // SYN without ACK (stealth indicator)
	totalAttempts int
	windowStart   time.Time
	lastSeen      time.Time
}

type PortScanResult struct {
	CoverageReduced bool
	HorizontalScan  bool
	VerticalScan    bool
	StealthScan     bool
	HostCount       int
	PortCount       int
	TimeWindow      string
}

func NewPortScanDetector() *PortScanDetector {
	sCache, _ := lru.New[string, *scanProfile](4096)
	return &PortScanDetector{scans: sCache}
}

func (ps *PortScanDetector) Record(sourceIP, destIP string, destPort int) PortScanResult {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	result := PortScanResult{}
	now := time.Now()

	profile, exists := ps.scans.Get(sourceIP)
	if !exists || now.Sub(profile.windowStart) > 5*time.Minute {
		profile = &scanProfile{
			portsByDest: make(map[string]map[int]bool),
			destsByPort: make(map[int]map[string]bool),
			windowStart: now,
		}
		result.CoverageReduced = ps.scans.Add(sourceIP, profile)
	}

	// Bound inner maps
	if len(profile.portsByDest) > 500 {
		profile.portsByDest = make(map[string]map[int]bool)
		result.CoverageReduced = true
	}
	if len(profile.destsByPort) > 500 {
		profile.destsByPort = make(map[int]map[string]bool)
		result.CoverageReduced = true
	}
	profile.lastSeen = now
	profile.totalAttempts++

	// Track vertical scan (many ports on one host)
	if destIP != "" {
		if profile.portsByDest[destIP] == nil {
			profile.portsByDest[destIP] = make(map[int]bool)
		}
		if len(profile.portsByDest[destIP]) < 20 {
			profile.portsByDest[destIP][destPort] = true
		}
	}

	// Track horizontal scan (one port across many hosts)
	if destPort > 0 {
		if profile.destsByPort[destPort] == nil {
			profile.destsByPort[destPort] = make(map[string]bool)
		}
		if destIP != "" {
			if len(profile.destsByPort[destPort]) < 10 {
				profile.destsByPort[destPort][destIP] = true
			}
		}
	}

	result.TimeWindow = now.Sub(profile.windowStart).Round(time.Second).String()

	// Horizontal scan: same port on 10+ hosts
	for port, dests := range profile.destsByPort {
		if len(dests) >= 10 {
			result.HorizontalScan = true
			result.HostCount = len(dests)
			_ = port
			break
		}
	}

	// Vertical scan: 20+ ports on same host
	for _, ports := range profile.portsByDest {
		if len(ports) >= 20 {
			result.VerticalScan = true
			result.PortCount = len(ports)
			break
		}
	}

	// Stealth scan: high attempt rate with many ports (SYN scan pattern)
	if profile.totalAttempts > 50 && destIP != "" {
		ports := profile.portsByDest[destIP]
		if len(ports) >= 15 {
			elapsed := now.Sub(profile.windowStart).Seconds()
			if elapsed > 0 && float64(profile.totalAttempts)/elapsed > 10 {
				result.StealthScan = true
				result.PortCount = len(ports)
			}
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func consonantRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	consonants := 0
	alpha := 0
	for _, c := range strings.ToLower(s) {
		if c >= 'a' && c <= 'z' {
			alpha++
			if !strings.ContainsRune("aeiou", c) {
				consonants++
			}
		}
	}
	if alpha == 0 {
		return 0
	}
	return float64(consonants) / float64(alpha)
}

func isCommonDomain(domain string) bool {
	common := map[string]bool{
		"google.com": true, "googleapis.com": true, "gstatic.com": true,
		"microsoft.com": true, "windows.net": true, "azure.com": true,
		"amazonaws.com": true, "cloudfront.net": true,
		"facebook.com": true, "fbcdn.net": true,
		"apple.com": true, "icloud.com": true,
		"github.com": true, "githubusercontent.com": true,
		"cloudflare.com": true, "akamai.net": true,
		"twitter.com": true, "twimg.com": true,
		"linkedin.com": true, "youtube.com": true,
		"netflix.com": true, "nflxvideo.net": true,
		"slack.com": true, "zoom.us": true,
	}
	return common[strings.ToLower(domain)]
}

func isNonStandardPort(port int, protocol string) bool {
	proto := strings.ToLower(protocol)
	standard := map[string]map[int]bool{
		"http":  {80: true, 8080: true, 8443: true},
		"https": {443: true, 8443: true},
		"dns":   {53: true},
		"ssh":   {22: true},
		"smtp":  {25: true, 587: true, 465: true},
		"ftp":   {21: true, 20: true},
		"rdp":   {3389: true},
		"smb":   {445: true, 139: true},
	}
	if ports, ok := standard[proto]; ok {
		return !ports[port]
	}
	return false
}

func avgFloat(vals []int) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0
	for _, v := range vals {
		sum += v
	}
	return float64(sum) / float64(len(vals))
}

func avgInt64(vals []int64) int64 {
	if len(vals) == 0 {
		return 0
	}
	var sum int64
	for _, v := range vals {
		sum += v
	}
	return sum / int64(len(vals))
}

func avgIntSlice(vals []int) int {
	if len(vals) == 0 {
		return 0
	}
	sum := 0
	for _, v := range vals {
		sum += v
	}
	return sum / len(vals)
}

func stdDevInt64(vals []int64) float64 {
	if len(vals) < 2 {
		return 0
	}
	avg := float64(avgInt64(vals))
	var sumSq float64
	for _, v := range vals {
		diff := float64(v) - avg
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(vals)))
}

func stdDevIntSlice(vals []int) float64 {
	if len(vals) < 2 {
		return 0
	}
	avg := float64(avgIntSlice(vals))
	var sumSq float64
	for _, v := range vals {
		diff := float64(v) - avg
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(vals)))
}

func truncateList(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" (+%d more)", len(items)-max)
}

func getIntDetail(event *core.SecurityEvent, key string) int {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	}
	return 0
}

func getFloatDetail(event *core.SecurityEvent, key string) float64 {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
}

func getIntSetting(settings map[string]interface{}, key string, defaultVal int) int {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case int64:
			return int(v)
		}
	}
	return defaultVal
}

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	return ""
}

// getNetworkMitigations returns context-specific mitigations based on alert type.
func getNetworkMitigations(alertType string) []string {
	switch alertType {
	case "ip_auto_blocked", "malicious_ip":
		return []string{
			"Block the IP at the firewall/WAF level",
			"Investigate all traffic from this IP for compromise indicators",
			"Update threat intelligence feeds with the malicious IP",
		}
	case "rate_limit_exceeded":
		return []string{
			"Implement progressive rate limiting with increasing backoff",
			"Consider temporary IP blocking for persistent violators",
			"Review rate limit thresholds for the affected endpoint",
		}
	case "geo_fence_violation":
		return []string{
			"Verify the geo-fence policy is correctly configured",
			"Investigate if the request is from a VPN or proxy",
			"Block the request and log for security review",
		}
	case "ddos_detected":
		return []string{
			"Activate DDoS mitigation services (CDN, scrubbing center)",
			"Implement traffic shaping and connection rate limiting",
			"Enable SYN cookies and connection timeouts",
			"Coordinate with upstream ISP for traffic filtering",
		}
	case "dns_tunneling":
		return []string{
			"Block the tunneling domain at the DNS resolver",
			"Implement DNS query length and frequency limits",
			"Monitor for encoded payloads in DNS queries",
			"Investigate the source host for malware",
		}
	case "dga_detected":
		return []string{
			"Block the DGA domain and investigate the source host",
			"Implement DNS sinkholing for suspected DGA domains",
			"Scan the source host for malware infection",
		}
	case "dns_exfiltration":
		return []string{
			"Block DNS queries to the exfiltration domain",
			"Implement DNS query monitoring and anomaly detection",
			"Investigate the source host for data theft malware",
		}
	case "c2_beaconing":
		return []string{
			"Isolate the beaconing host immediately",
			"Block the C2 server IP/domain at the firewall",
			"Perform forensic analysis on the compromised host",
			"Check for lateral movement from the compromised host",
		}
	case "covert_channel":
		return []string{
			"Investigate the covert channel endpoints",
			"Implement deep packet inspection for protocol anomalies",
			"Block non-standard protocol usage on standard ports",
		}
	case "suspicious_port":
		return []string{
			"Investigate the purpose of the non-standard port usage",
			"Implement egress filtering to block unauthorized outbound connections",
			"Review firewall rules for overly permissive port access",
		}
	case "pass_the_hash", "pass_the_ticket", "golden_ticket", "dcsync":
		return []string{
			"Reset credentials for the affected accounts immediately",
			"Implement Credential Guard and Protected Users group",
			"Enable NTLM auditing and restrict NTLM authentication",
			"Reset the KRBTGT account password twice for Golden Ticket attacks",
			"Implement privileged access workstations (PAWs)",
		}
	case "kerberoasting":
		return []string{
			"Use strong, long passwords for service accounts (25+ characters)",
			"Implement Group Managed Service Accounts (gMSA)",
			"Monitor for unusual TGS ticket requests with RC4 encryption",
			"Rotate service account passwords regularly",
		}
	case "lateral_movement":
		return []string{
			"Isolate the source host and investigate for compromise",
			"Implement network segmentation to limit lateral movement",
			"Enable host-based firewalls to restrict inter-host communication",
			"Deploy endpoint detection and response (EDR) on all hosts",
		}
	case "horizontal_scan", "vertical_scan", "stealth_scan":
		return []string{
			"Block the scanning IP at the firewall",
			"Investigate the scanner for reconnaissance activity",
			"Implement network intrusion detection/prevention systems",
			"Review exposed services and close unnecessary ports",
		}
	case "amplification_attack":
		return []string{
			"Implement BCP38/BCP84 source address validation",
			"Disable or restrict open DNS resolvers, NTP, and memcached",
			"Rate limit responses to prevent amplification",
			"Coordinate with upstream providers for traffic scrubbing",
		}
	default:
		return []string{
			"Investigate the network event for security implications",
			"Review firewall and IDS/IPS rules",
			"Monitor for related suspicious activity",
		}
	}
}
