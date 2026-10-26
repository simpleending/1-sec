package core

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// ThreatCorrelator watches the alert pipeline for multi-module attack patterns
// and generates high-confidence "attack chain" alerts when multiple modules
// detect activity from the same source within a time window.
//
// This is the #1 feature that separates XDR platforms (CrowdStrike, SentinelOne)
// from standalone tools. Without it, each module is an island. With it, a brute
// force attempt (auth) + SQL injection (injection_shield) + data exfiltration
// (ransomware) from the same IP becomes a single correlated incident.
//
// Pure Go, zero external dependencies.
type ThreatCorrelator struct {
	mu       sync.Mutex
	logger   zerolog.Logger
	pipeline *AlertPipeline
	bus      *EventBus

	// sourceAlerts tracks recent alerts per source IP
	sourceAlerts map[string]*sourceAlertWindow

	// Attack chain definitions — when these module combinations fire
	// for the same source, we generate a correlated alert
	chains []attackChain

	// Config
	windowDuration time.Duration // how long to track alerts per source
	minModules     int           // minimum distinct modules to trigger correlation
}

type sourceAlertWindow struct {
	fired     map[string]time.Time
	alerts    []*Alert
	modules   map[string]int // module -> count
	firstSeen time.Time
	lastSeen  time.Time
}

type attackChain struct {
	Name               string
	Description        string
	Modules            []string // required modules (all must fire)
	Severity           Severity
	MitreIDs           []string
	MaxDuration        time.Duration
	RequiredTypes      map[string][]string
	RequirePrincipal   bool
	RecommendedActions []string
}

// NewThreatCorrelator creates a correlator that watches the alert pipeline.
func NewThreatCorrelator(logger zerolog.Logger, pipeline *AlertPipeline, bus *EventBus) *ThreatCorrelator {
	tc := &ThreatCorrelator{
		logger:         logger.With().Str("component", "threat_correlator").Logger(),
		pipeline:       pipeline,
		bus:            bus,
		sourceAlerts:   make(map[string]*sourceAlertWindow),
		windowDuration: 15 * time.Minute,
		minModules:     2,
	}
	tc.chains = tc.buildChainDefinitions()
	return tc
}

func (tc *ThreatCorrelator) buildChainDefinitions() []attackChain {
	return []attackChain{
		{
			Name:        "Full Kill Chain: Recon → Exploit → Exfil",
			Description: "Attacker performed reconnaissance (network), exploited a vulnerability (injection), and exfiltrated data (ransomware/network). This is a complete attack lifecycle.",
			Modules:     []string{"network_guardian", "injection_shield", "ransomware"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"TA0043", "TA0001", "TA0010"},
		},
		{
			Name:        "Credential Attack → Lateral Movement",
			Description: "Brute force or credential stuffing (auth) followed by lateral movement indicators (network). Attacker likely obtained valid credentials and is moving through the network.",
			Modules:     []string{"auth_fortress", "network_guardian"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"T1110", "TA0008"},
		},
		{
			Name:        "Injection → Persistence",
			Description: "Injection attack (SQLi/RCE) followed by runtime persistence indicators. Attacker exploited a vulnerability and is establishing persistence.",
			Modules:     []string{"injection_shield", "runtime_watcher"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"TA0001", "TA0003"},
		},
		{
			Name:        "Supply Chain → Runtime Compromise",
			Description: "Supply chain anomaly followed by suspicious runtime activity. A compromised dependency may be executing malicious code.",
			Modules:     []string{"supply_chain", "runtime_watcher"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"T1195", "TA0002"},
		},
		{
			Name:        "Auth Bypass → Data Destruction",
			Description: "Authentication attack followed by ransomware/wiper activity. Attacker gained access and is destroying data.",
			Modules:     []string{"auth_fortress", "ransomware"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"T1110", "T1486"},
		},
		{
			Name:        "API Abuse → Injection → Exfil",
			Description: "API abuse detected alongside injection attempts and data exfiltration. Coordinated API-layer attack.",
			Modules:     []string{"api_fortress", "injection_shield", "ransomware"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"T1190", "TA0010"},
		},
		{
			Name:        "IoT Compromise → Lateral Movement",
			Description: "IoT/OT device anomaly followed by network lateral movement. Compromised IoT device being used as pivot point.",
			Modules:     []string{"iot_shield", "network_guardian"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"T1200", "TA0008"},
		},
		{
			Name:        "LLM Prompt Injection → Agent Escape",
			Description: "LLM prompt injection detected alongside AI agent containment breach. Attacker is exploiting AI systems to escape sandboxes.",
			Modules:     []string{"llm_firewall", "ai_containment"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"T1059", "TA0004"},
		},
		{
			Name:        "Content Poisoning → Agent Goal Hijack → Unauthorized Payment",
			Description: "Poisoned web content (llms.txt/markdown) detected alongside agent containment breach and API abuse. An attacker poisoned agent-facing web content to redirect agent behavior and trigger unauthorized payments via x402 or similar protocols.",
			Modules:     []string{"data_poisoning", "ai_containment", "api_fortress"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"T1195", "T1059", "T1657"},
		},
		{
			Name:        "Markdown Injection → Agent Scope Escalation",
			Description: "Prompt injection via ingested markdown content followed by agent containment breach. Attacker embedded instructions in llms.txt or markdown endpoints to escalate agent privileges.",
			Modules:     []string{"llm_firewall", "ai_containment"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"T1059", "TA0004"},
		},
		{
			Name:        "Web Content Poisoning → Data Exfiltration",
			Description: "Web content integrity violation detected alongside network exfiltration indicators. Poisoned llms.txt or markdown content may have redirected an agent to exfiltrate data.",
			Modules:     []string{"data_poisoning", "network_guardian"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"T1195", "TA0010"},
		},
		{
			Name:        "AI Support Bot Jailbreak to Account Takeover Mutation",
			Description: "Prompt anomaly in an AI support flow followed by a sensitive email, password, or recovery mutation for the same user/session. This matches modern support-bot jailbreak account takeover tradecraft.",
			Modules:     []string{"llm_firewall", "identity_monitor"},
			Severity:    SeverityCritical,
			MitreIDs:    []string{"T1059", "T1098", "TA0006"},
			MaxDuration: 5 * time.Minute,
			RequiredTypes: map[string][]string{
				"llm_firewall":     {"llm_threat_detected"},
				"identity_monitor": {"account_mutation"},
			},
			RequirePrincipal: true,
			RecommendedActions: []string{
				"disable_user",
				"block_ip",
			},
		},
		{
			Name:        "Multi-Vector Assault",
			Description: "Three or more distinct security modules triggered by the same source. This indicates a sophisticated, multi-vector attack campaign.",
			Modules:     []string{}, // special case: any 3+ modules
			Severity:    SeverityCritical,
			MitreIDs:    []string{"TA0001", "TA0002", "TA0040"},
		},
	}
}

// Ingest processes a new alert and checks for cross-module correlations.
// Called by the alert pipeline as a handler.
func (tc *ThreatCorrelator) Ingest(alert *Alert) {
	if alert.Module == "threat_correlator" || alert.Type == "escalation" {
		return
	}
	// Extract source IP from alert metadata
	sourceIP := ""
	if ip, ok := alert.Metadata["source_ip"].(string); ok && ip != "" {
		sourceIP = ip
	}
	if sourceIP == "" {
		return // can't correlate without a source
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()
	if alert.Timestamp.IsZero() {
		copy := *alert
		copy.Timestamp = now
		alert = &copy
	}

	window, exists := tc.sourceAlerts[sourceIP]
	if !exists || now.Sub(window.lastSeen) > tc.windowDuration {
		if !exists && len(tc.sourceAlerts) >= 1024 {
			oldest := ""
			var last time.Time
			for ip, w := range tc.sourceAlerts {
				if oldest == "" || w.lastSeen.Before(last) {
					oldest, last = ip, w.lastSeen
				}
			}
			delete(tc.sourceAlerts, oldest)
		}
		window = &sourceAlertWindow{
			fired:     make(map[string]time.Time),
			modules:   make(map[string]int),
			firstSeen: now,
		}
		tc.sourceAlerts[sourceIP] = window
	}
	cutoff := now.Add(-tc.windowDuration)
	kept := window.alerts[:0]
	for _, a := range window.alerts {
		if !a.Timestamp.Before(cutoff) {
			kept = append(kept, a)
		}
	}
	clear(window.alerts[len(kept):])
	window.alerts = kept
	// Keep recent evidence bounded even while an attack remains continuously active.
	if len(window.alerts) >= 32 {
		copy(window.alerts, window.alerts[len(window.alerts)-31:])
		clear(window.alerts[31:])
		window.alerts = window.alerts[:31]
	}
	window.modules = make(map[string]int)
	for _, a := range window.alerts {
		window.modules[a.Module]++
	}
	if window.fired == nil {
		window.fired = make(map[string]time.Time)
	}
	for chain, at := range window.fired {
		if at.Before(cutoff) {
			delete(window.fired, chain)
		}
	}

	window.alerts = append(window.alerts, alert)
	window.modules[alert.Module]++
	window.lastSeen = now

	// Check for attack chain matches
	tc.checkChains(sourceIP, window)
}

func (tc *ThreatCorrelator) checkChains(sourceIP string, window *sourceAlertWindow) {
	moduleCount := len(window.modules)

	for _, chain := range tc.chains {
		// Special case: multi-vector (any 3+ modules)
		if len(chain.Modules) == 0 && moduleCount >= 3 {
			tc.fireCorrelatedAlert(sourceIP, window, chain)
			continue
		}

		if len(chain.Modules) == 0 {
			continue
		}
		if tc.chainMatches(window, chain) {
			tc.fireCorrelatedAlert(sourceIP, window, chain)
		}
	}
}

func (tc *ThreatCorrelator) chainMatches(window *sourceAlertWindow, chain attackChain) bool {
	var candidateSets [][]*Alert

	for _, reqModule := range chain.Modules {
		var moduleAlerts []*Alert
		for _, alert := range window.alerts {
			if alert.Module != reqModule {
				continue
			}
			if !alertTypeAllowed(alert, chain.RequiredTypes[reqModule]) {
				continue
			}
			moduleAlerts = append(moduleAlerts, alert)
		}
		if len(moduleAlerts) == 0 {
			return false
		}
		candidateSets = append(candidateSets, moduleAlerts)
	}

	if chain.MaxDuration == 0 && !chain.RequirePrincipal {
		return true
	}

	return candidateSelectionMatches(candidateSets, 0, nil, chain)
}

func candidateSelectionMatches(candidateSets [][]*Alert, idx int, selected []*Alert, chain attackChain) bool {
	if idx == len(candidateSets) {
		return selectedAlertsMeetConstraints(selected, chain)
	}
	for _, alert := range candidateSets[idx] {
		next := append(selected, alert)
		if candidateSelectionMatches(candidateSets, idx+1, next, chain) {
			return true
		}
	}
	return false
}

func selectedAlertsMeetConstraints(matched []*Alert, chain attackChain) bool {
	if chain.MaxDuration > 0 && len(matched) > 1 {
		first, last := matched[0].Timestamp, matched[0].Timestamp
		for _, alert := range matched[1:] {
			if alert.Timestamp.Before(first) {
				first = alert.Timestamp
			}
			if alert.Timestamp.After(last) {
				last = alert.Timestamp
			}
		}
		if last.Sub(first) > chain.MaxDuration {
			return false
		}
	}

	if chain.RequirePrincipal && !alertsSharePrincipal(matched) {
		return false
	}

	return true
}

func alertTypeAllowed(alert *Alert, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, typ := range allowed {
		if alert.Type == typ {
			return true
		}
	}
	return false
}

func alertsSharePrincipal(alerts []*Alert) bool {
	if len(alerts) == 0 {
		return false
	}

	common := alertPrincipals(alerts[0])
	for _, alert := range alerts[1:] {
		next := alertPrincipals(alert)
		for principal := range common {
			if !next[principal] {
				delete(common, principal)
			}
		}
		if len(common) == 0 {
			return false
		}
	}
	return len(common) > 0
}

func alertPrincipals(alert *Alert) map[string]bool {
	principals := make(map[string]bool)
	for _, key := range []string{"user_id", "account_id", "session_id"} {
		if val, ok := alert.Metadata[key].(string); ok && strings.TrimSpace(val) != "" {
			principals[key+":"+strings.TrimSpace(val)] = true
		}
	}
	return principals
}

func (tc *ThreatCorrelator) fireCorrelatedAlert(sourceIP string, window *sourceAlertWindow, chain attackChain) {
	if window.fired == nil {
		window.fired = make(map[string]time.Time)
	}
	if _, exists := window.fired[chain.Name]; exists {
		return
	}
	window.fired[chain.Name] = time.Now()
	// Deduplicate: don't fire the same chain for the same source twice
	dedupeKey := fmt.Sprintf("correlated:%s:%s", sourceIP, chain.Name)
	for _, a := range window.alerts {
		if a.Type == dedupeKey {
			return
		}
	}

	// Collect all module names that fired
	var modules []string
	for mod := range window.modules {
		modules = append(modules, mod)
	}

	// Collect all event IDs from constituent alerts
	var eventIDs []string
	for _, a := range window.alerts {
		eventIDs = append(eventIDs, a.EventIDs...)
	}

	duration := window.lastSeen.Sub(window.firstSeen)

	event := NewSecurityEvent("threat_correlator", dedupeKey, chain.Severity,
		fmt.Sprintf("CORRELATED ATTACK CHAIN: %s — %d alerts from %d modules (%s) targeting source %s over %s. %s",
			chain.Name, len(window.alerts), len(modules),
			strings.Join(modules, ", "), sourceIP, duration.Round(time.Second), chain.Description))
	event.SourceIP = sourceIP
	event.Details["chain_name"] = chain.Name
	event.Details["module_count"] = len(modules)
	event.Details["alert_count"] = len(window.alerts)
	event.Details["modules"] = modules
	event.Details["mitre_ids"] = chain.MitreIDs
	event.Details["window_duration"] = duration.String()
	event.Details["constituent_event_ids"] = eventIDs
	if len(chain.RecommendedActions) > 0 {
		event.Details["recommended_actions"] = chain.RecommendedActions
	}

	if tc.bus != nil {
		_ = tc.bus.PublishEvent(event)
	}

	alert := NewAlert(event,
		fmt.Sprintf("⚠ ATTACK CHAIN: %s", chain.Name),
		event.Summary)
	alert.Type = dedupeKey
	alert.Mitigations = []string{
		"Immediately isolate source IP " + sourceIP + " at the network level",
		"Review all " + fmt.Sprintf("%d", len(window.alerts)) + " constituent alerts for full attack timeline",
		"Check for lateral movement from this source to other internal hosts",
		"Preserve forensic evidence across all affected modules",
		"Escalate to incident response — this is a multi-stage attack",
	}
	alert.Metadata["source_ip"] = sourceIP
	alert.Metadata["chain_name"] = chain.Name
	alert.Metadata["modules"] = modules
	if len(chain.RecommendedActions) > 0 {
		alert.Metadata["recommended_actions"] = chain.RecommendedActions
		for _, action := range chain.RecommendedActions {
			switch action {
			case "disable_user":
				alert.Mitigations = append(alert.Mitigations, "Disable or lock the affected user account until ownership is verified")
			case "block_ip":
				alert.Mitigations = append(alert.Mitigations, "Block source IP "+sourceIP+" while account takeover triage is active")
			}
		}
	}

	if tc.pipeline != nil {
		tc.pipeline.Process(alert)
	}

	tc.logger.Warn().
		Str("chain", chain.Name).
		Str("source_ip", sourceIP).
		Int("alerts", len(window.alerts)).
		Int("modules", len(modules)).
		Msg("CORRELATED ATTACK CHAIN DETECTED")
}

// Start begins the correlator's background cleanup loop.
func (tc *ThreatCorrelator) Start(ctx context.Context) {
	go tc.cleanupLoop(ctx)
	tc.logger.Info().
		Dur("window", tc.windowDuration).
		Int("chains", len(tc.chains)).
		Msg("threat correlator started")
}

func (tc *ThreatCorrelator) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tc.mu.Lock()
			cutoff := time.Now().Add(-tc.windowDuration)
			for ip, window := range tc.sourceAlerts {
				if window.lastSeen.Before(cutoff) {
					delete(tc.sourceAlerts, ip)
				}
			}
			tc.mu.Unlock()
		}
	}
}

// CorrelatorStatus represents the current state of the threat correlator for API exposure.
type CorrelatorStatus struct {
	ActiveSources int                    `json:"active_sources"`
	WindowMinutes int                    `json:"window_minutes"`
	ChainCount    int                    `json:"chain_count"`
	Sources       []CorrelatorSourceInfo `json:"sources,omitempty"`
	Chains        []CorrelatorChainInfo  `json:"chains"`
}

// CorrelatorSourceInfo represents a tracked source IP.
type CorrelatorSourceInfo struct {
	IP         string         `json:"ip"`
	AlertCount int            `json:"alert_count"`
	Modules    map[string]int `json:"modules"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

// CorrelatorChainInfo represents an attack chain definition.
type CorrelatorChainInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Modules     []string `json:"modules"`
	Severity    string   `json:"severity"`
	MitreIDs    []string `json:"mitre_ids,omitempty"`
}

// Status returns the current correlator state.
func (tc *ThreatCorrelator) Status() CorrelatorStatus {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	sources := make([]CorrelatorSourceInfo, 0, len(tc.sourceAlerts))
	for ip, window := range tc.sourceAlerts {
		modules := make(map[string]int)
		for k, v := range window.modules {
			modules[k] = v
		}
		sources = append(sources, CorrelatorSourceInfo{
			IP:         ip,
			AlertCount: len(window.alerts),
			Modules:    modules,
			FirstSeen:  window.firstSeen,
			LastSeen:   window.lastSeen,
		})
	}

	chains := make([]CorrelatorChainInfo, 0, len(tc.chains))
	for _, c := range tc.chains {
		chains = append(chains, CorrelatorChainInfo{
			Name:        c.Name,
			Description: c.Description,
			Modules:     c.Modules,
			Severity:    c.Severity.String(),
			MitreIDs:    c.MitreIDs,
		})
	}

	return CorrelatorStatus{
		ActiveSources: len(tc.sourceAlerts),
		WindowMinutes: int(tc.windowDuration.Minutes()),
		ChainCount:    len(tc.chains),
		Sources:       sources,
		Chains:        chains,
	}
}
