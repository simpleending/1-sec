package core

import "time"

// ---------------------------------------------------------------------------
// response_presets.go — built-in enforcement presets: lax, balanced, strict
//
// Each preset covers all 16 modules with appropriate severity thresholds,
// action types, cooldowns, and rate limits. Users pick a preset as a
// starting point and can override individual module policies in YAML.
//
// Preset philosophy:
//   lax      — log + webhook only, never blocks/kills. Safe for initial rollout.
//   balanced — blocks IPs on HIGH, kills processes on CRITICAL. Good default.
//   strict   — aggressive blocking on MEDIUM+, kills on HIGH, short cooldowns.
// ---------------------------------------------------------------------------

// EnforcementPreset names.
const (
	PresetLax      = "lax"
	PresetSafe     = "safe"
	PresetBalanced = "balanced"
	PresetStrict   = "strict"
	PresetVPSAgent = "vps-agent"
)

// GetPresetPolicies returns the full set of enforcement policies for a preset.
// Returns nil if the preset name is unknown.
func GetPresetPolicies(preset string) map[string]ResponsePolicyYAML {
	switch preset {
	case PresetLax:
		return laxPreset()
	case PresetSafe:
		return safePreset()
	case PresetBalanced:
		return balancedPreset()
	case PresetStrict:
		return strictPreset()
	case PresetVPSAgent:
		return vpsAgentPreset()
	default:
		return nil
	}
}

// ValidPresets returns the list of valid preset names.
func ValidPresets() []string {
	return []string{PresetLax, PresetSafe, PresetBalanced, PresetStrict, PresetVPSAgent}
}

// ---------------------------------------------------------------------------
// PresetBundle — full preset configuration including policies, escalation,
// and approval gate settings. Only presets that need non-default escalation
// or approval gate configs return a non-nil bundle.
// ---------------------------------------------------------------------------

// PresetBundle carries the full configuration for a preset beyond just policies.
type PresetBundle struct {
	Policies     map[string]ResponsePolicyYAML
	Escalation   *EscalationConfig
	ApprovalGate *ApprovalGateConfig
}

// GetPresetBundle returns the full preset bundle (policies + escalation +
// approval gate). Returns nil if the preset name is unknown. For presets
// that don't customize escalation/approval, those fields are nil (use defaults).
func GetPresetBundle(preset string) *PresetBundle {
	policies := GetPresetPolicies(preset)
	if policies == nil {
		return nil
	}

	bundle := &PresetBundle{Policies: policies}

	switch preset {
	case PresetVPSAgent:
		esc := VPSAgentEscalationConfig()
		bundle.Escalation = &esc
		ag := VPSAgentApprovalGateConfig()
		bundle.ApprovalGate = &ag
	}

	return bundle
}

// ---------------------------------------------------------------------------
// SAFE preset — recommended for production. Log everything, block_ip only for
// the highest-confidence, lowest-FP detections: brute force and port scans.
// Everything else is log + webhook. This is the "enforcement safe defaults"
// that the audit recommended.
// ---------------------------------------------------------------------------

func safePreset() map[string]ResponsePolicyYAML {
	return map[string]ResponsePolicyYAML{
		// Only auth brute force and network port scans get block_ip
		"auth_fortress": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "CRITICAL", Description: "Block confirmed brute force / credential stuffing source", Params: map[string]string{"duration": "1h"}},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on auth attacks", Params: map[string]string{"url": ""}},
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log all auth threats"},
			},
		},
		"network_guardian": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "CRITICAL", Description: "Block confirmed port scan / DDoS source", Params: map[string]string{"duration": "1h"}},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on network threats", Params: map[string]string{"url": ""}},
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log all network threats"},
			},
		},
		// Ransomware gets kill_process + block_ip on CRITICAL (confirmed mass encryption / wiper)
		"ransomware": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 60, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "kill_process", MinSeverity: "CRITICAL", Description: "Kill confirmed ransomware/wiper process"},
				{Action: "block_ip", MinSeverity: "CRITICAL", Description: "Block source of confirmed wiper/destructive activity", Params: map[string]string{"duration": "24h"}},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on ransomware indicators", Params: map[string]string{"url": ""}},
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log ransomware indicators"},
			},
		},
		// Everything else: log + webhook only
		"api_fortress":       {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"injection_shield":   {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"iot_shield":         {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"supply_chain":       {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"deepfake_shield":    {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"identity_monitor":   {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"llm_firewall":       {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"ai_containment":     {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"data_poisoning":     {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"quantum_crypto":     {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"runtime_watcher":    {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"cloud_posture":      {Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "HIGH"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"ai_analysis_engine": {Enabled: true, MinSeverity: "CRITICAL", CooldownSeconds: 600, MaxActionsPerMin: 5, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "CRITICAL"}, {Action: "webhook", MinSeverity: "CRITICAL", Params: map[string]string{"url": ""}}}},
		"*":                  {Enabled: true, MinSeverity: "CRITICAL", CooldownSeconds: 600, MaxActionsPerMin: 5, Actions: []ResponseRuleYAML{{Action: "log_only", MinSeverity: "CRITICAL"}}},
	}
}

// ---------------------------------------------------------------------------
// LAX preset — observe and notify, never enforce
// ---------------------------------------------------------------------------

func laxPreset() map[string]ResponsePolicyYAML {
	return map[string]ResponsePolicyYAML{
		// ── Tier 1: Network & Perimeter ─────────────────────────────────────
		"network_guardian": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log network threats"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on critical network events", Params: map[string]string{"url": ""}},
			},
		},
		"api_fortress": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log API abuse"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on critical API attacks", Params: map[string]string{"url": ""}},
			},
		},
		"iot_shield": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log IoT/OT anomalies"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on critical IoT compromise", Params: map[string]string{"url": ""}},
			},
		},
		// ── Tier 2: Application Layer ───────────────────────────────────────
		"injection_shield": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log injection attempts"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on critical injection attacks", Params: map[string]string{"url": ""}},
			},
		},
		"supply_chain": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log supply chain anomalies"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on supply chain compromise", Params: map[string]string{"url": ""}},
			},
		},
		"ransomware": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log ransomware indicators"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on ransomware activity", Params: map[string]string{"url": ""}},
			},
		},
		// ── Tier 3: Identity & Access ───────────────────────────────────────
		"auth_fortress": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log auth attacks"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on critical auth events", Params: map[string]string{"url": ""}},
			},
		},
		"deepfake_shield": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log deepfake detections"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on deepfake threats", Params: map[string]string{"url": ""}},
			},
		},
		"identity_monitor": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log identity anomalies"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on identity compromise", Params: map[string]string{"url": ""}},
			},
		},
		// ── Tier 4: AI-Specific Defense ─────────────────────────────────────
		"llm_firewall": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 15,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log prompt injection attempts"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on LLM attacks", Params: map[string]string{"url": ""}},
			},
		},
		"ai_containment": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log AI agent violations"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on AI escape attempts", Params: map[string]string{"url": ""}},
			},
		},
		"data_poisoning": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log data poisoning indicators"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on data integrity threats", Params: map[string]string{"url": ""}},
			},
		},
		// ── Tier 5: Cryptography ────────────────────────────────────────────
		"quantum_crypto": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log quantum-vulnerable crypto usage"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on harvest-now-decrypt-later patterns", Params: map[string]string{"url": ""}},
			},
		},
		// ── Tier 6: Runtime & Infrastructure ────────────────────────────────
		"runtime_watcher": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log runtime anomalies"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on runtime compromise", Params: map[string]string{"url": ""}},
			},
		},
		"cloud_posture": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log cloud misconfigurations"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on critical cloud posture drift", Params: map[string]string{"url": ""}},
			},
		},
		// ── Cross-Cutting ───────────────────────────────────────────────────
		"ai_analysis_engine": {
			Enabled: true, MinSeverity: "CRITICAL", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "CRITICAL", Description: "Log AI analysis engine findings"},
			},
		},
		"*": {
			Enabled: true, MinSeverity: "CRITICAL", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "CRITICAL", Description: "Log critical alerts from any module"},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// BALANCED preset — block on HIGH, kill on CRITICAL, reasonable cooldowns
// ---------------------------------------------------------------------------

func balancedPreset() map[string]ResponsePolicyYAML {
	return map[string]ResponsePolicyYAML{
		// ── Tier 1: Network & Perimeter ─────────────────────────────────────
		"network_guardian": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block source IP via firewall", Params: map[string]string{"duration": "1h"}},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify SOC on critical network threats", Params: map[string]string{"url": ""}},
			},
		},
		"api_fortress": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 120, MaxActionsPerMin: 30,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block API abuser IP", Params: map[string]string{"duration": "30m"}},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on critical API attacks", Params: map[string]string{"url": ""}},
			},
		},
		"iot_shield": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Isolate rogue IoT device IP", Params: map[string]string{"duration": "2h"}},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on IoT compromise", Params: map[string]string{"url": ""}},
			},
		},
		// ── Tier 2: Application Layer ───────────────────────────────────────
		"injection_shield": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 60, MaxActionsPerMin: 50,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block injection attack source", Params: map[string]string{"duration": "2h"}},
				{Action: "drop_connection", MinSeverity: "CRITICAL", Description: "Drop connections from injection source"},
			},
		},
		"supply_chain": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "HIGH", Description: "Alert on supply chain compromise", Params: map[string]string{"url": ""}},
				{Action: "quarantine_file", MinSeverity: "CRITICAL", Description: "Quarantine compromised package artifacts"},
			},
		},
		"ransomware": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 60, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "kill_process", MinSeverity: "HIGH", Description: "Kill process exhibiting ransomware behavior"},
				{Action: "block_ip", MinSeverity: "CRITICAL", Description: "Block data exfiltration destination", Params: map[string]string{"duration": "24h"}},
			},
		},
		// ── Tier 3: Identity & Access ───────────────────────────────────────
		"auth_fortress": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block brute force source", Params: map[string]string{"duration": "1h"}},
				{Action: "disable_user", MinSeverity: "CRITICAL", Description: "Disable compromised user account"},
			},
		},
		"deepfake_shield": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on deepfake detection", Params: map[string]string{"url": ""}},
				{Action: "block_ip", MinSeverity: "CRITICAL", Description: "Block deepfake source", Params: map[string]string{"duration": "4h"}},
			},
		},
		"identity_monitor": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on identity anomaly", Params: map[string]string{"url": ""}},
				{Action: "disable_user", MinSeverity: "CRITICAL", Description: "Disable synthetic or escalated identity"},
			},
		},
		// ── Tier 4: AI-Specific Defense ─────────────────────────────────────
		"llm_firewall": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 60, MaxActionsPerMin: 30,
			Actions: []ResponseRuleYAML{
				{Action: "drop_connection", MinSeverity: "HIGH", Description: "Drop prompt injection source connection"},
				{Action: "block_ip", MinSeverity: "CRITICAL", Description: "Block persistent prompt injection attacker", Params: map[string]string{"duration": "4h"}},
			},
		},
		"ai_containment": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 120, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on AI agent policy violation", Params: map[string]string{"url": ""}},
				{Action: "kill_process", MinSeverity: "CRITICAL", Description: "Kill escaped AI agent process"},
			},
		},
		"data_poisoning": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on data poisoning indicators", Params: map[string]string{"url": ""}},
				{Action: "quarantine_file", MinSeverity: "CRITICAL", Description: "Quarantine poisoned training data"},
			},
		},
		// ── Tier 5: Cryptography ────────────────────────────────────────────
		"quantum_crypto": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on quantum-vulnerable crypto", Params: map[string]string{"url": ""}},
				{Action: "log_only", MinSeverity: "CRITICAL", Description: "Log harvest-now-decrypt-later patterns"},
			},
		},
		// ── Tier 6: Runtime & Infrastructure ────────────────────────────────
		"runtime_watcher": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 60, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "kill_process", MinSeverity: "HIGH", Description: "Kill suspicious runtime process"},
				{Action: "quarantine_file", MinSeverity: "HIGH", Description: "Quarantine modified/injected files"},
			},
		},
		"cloud_posture": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on cloud misconfiguration", Params: map[string]string{"url": ""}},
				{Action: "log_only", MinSeverity: "CRITICAL", Description: "Log critical cloud posture drift"},
			},
		},
		// ── Cross-Cutting ───────────────────────────────────────────────────
		"ai_analysis_engine": {
			Enabled: true, MinSeverity: "CRITICAL", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on AI-correlated critical threat", Params: map[string]string{"url": ""}},
			},
		},
		"*": {
			Enabled: true, MinSeverity: "CRITICAL", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "CRITICAL", Description: "Log critical alerts from unconfigured modules"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on any critical alert", Params: map[string]string{"url": ""}},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// STRICT preset — aggressive enforcement, short cooldowns, low thresholds
// ---------------------------------------------------------------------------

func strictPreset() map[string]ResponsePolicyYAML {
	return map[string]ResponsePolicyYAML{
		// ── Tier 1: Network & Perimeter ─────────────────────────────────────
		"network_guardian": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 60, MaxActionsPerMin: 60,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "MEDIUM", Description: "Block suspicious network source", Params: map[string]string{"duration": "4h"}},
				{Action: "drop_connection", MinSeverity: "HIGH", Description: "Drop connections from threat source"},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify SOC on network threats", Params: map[string]string{"url": ""}},
			},
		},
		"api_fortress": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 30, MaxActionsPerMin: 60,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "MEDIUM", Description: "Block API abuser", Params: map[string]string{"duration": "2h"}},
				{Action: "drop_connection", MinSeverity: "HIGH", Description: "Drop abusive API connections"},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on API attacks", Params: map[string]string{"url": ""}},
			},
		},
		"iot_shield": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 60, MaxActionsPerMin: 30,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "MEDIUM", Description: "Isolate rogue IoT device", Params: map[string]string{"duration": "8h"}},
				{Action: "kill_process", MinSeverity: "HIGH", Description: "Kill compromised IoT service process"},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on IoT compromise", Params: map[string]string{"url": ""}},
			},
		},
		// ── Tier 2: Application Layer ───────────────────────────────────────
		"injection_shield": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 30, MaxActionsPerMin: 100,
			Actions: []ResponseRuleYAML{
				{Action: "drop_connection", MinSeverity: "MEDIUM", Description: "Drop injection attempt connections"},
				{Action: "block_ip", MinSeverity: "MEDIUM", Description: "Block injection source", Params: map[string]string{"duration": "8h"}},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on injection attacks", Params: map[string]string{"url": ""}},
			},
		},
		"supply_chain": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 60, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "quarantine_file", MinSeverity: "MEDIUM", Description: "Quarantine suspicious packages"},
				{Action: "kill_process", MinSeverity: "HIGH", Description: "Kill process from compromised dependency"},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on supply chain anomaly", Params: map[string]string{"url": ""}},
			},
		},
		"ransomware": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 10, MaxActionsPerMin: 30,
			Actions: []ResponseRuleYAML{
				{Action: "kill_process", MinSeverity: "MEDIUM", Description: "Kill ransomware process immediately"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block exfiltration destination", Params: map[string]string{"duration": "48h"}},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on ransomware activity", Params: map[string]string{"url": ""}},
			},
		},
		// ── Tier 3: Identity & Access ───────────────────────────────────────
		"auth_fortress": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 60, MaxActionsPerMin: 40,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "MEDIUM", Description: "Block auth attack source", Params: map[string]string{"duration": "4h"}},
				{Action: "disable_user", MinSeverity: "HIGH", Description: "Disable targeted user account"},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on auth attacks", Params: map[string]string{"url": ""}},
			},
		},
		"deepfake_shield": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 60, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "MEDIUM", Description: "Block deepfake source", Params: map[string]string{"duration": "8h"}},
				{Action: "drop_connection", MinSeverity: "HIGH", Description: "Drop deepfake communication"},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on deepfake detection", Params: map[string]string{"url": ""}},
			},
		},
		"identity_monitor": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 60, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "disable_user", MinSeverity: "HIGH", Description: "Disable anomalous identity"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block identity attack source", Params: map[string]string{"duration": "4h"}},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on identity anomaly", Params: map[string]string{"url": ""}},
			},
		},
		// ── Tier 4: AI-Specific Defense ─────────────────────────────────────
		"llm_firewall": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 30, MaxActionsPerMin: 60,
			Actions: []ResponseRuleYAML{
				{Action: "drop_connection", MinSeverity: "MEDIUM", Description: "Drop prompt injection connections"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block LLM attacker", Params: map[string]string{"duration": "8h"}},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on LLM attacks", Params: map[string]string{"url": ""}},
			},
		},
		"ai_containment": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 30, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "kill_process", MinSeverity: "HIGH", Description: "Kill rogue AI agent process"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block shadow AI service", Params: map[string]string{"duration": "8h"}},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on AI containment breach", Params: map[string]string{"url": ""}},
			},
		},
		"data_poisoning": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 60, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "quarantine_file", MinSeverity: "MEDIUM", Description: "Quarantine poisoned data"},
				{Action: "kill_process", MinSeverity: "HIGH", Description: "Kill training pipeline with poisoned data"},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on data poisoning", Params: map[string]string{"url": ""}},
			},
		},
		// ── Tier 5: Cryptography ────────────────────────────────────────────
		"quantum_crypto": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 120, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on quantum-vulnerable crypto", Params: map[string]string{"url": ""}},
				{Action: "block_ip", MinSeverity: "CRITICAL", Description: "Block harvest-now-decrypt-later source", Params: map[string]string{"duration": "24h"}},
			},
		},
		// ── Tier 6: Runtime & Infrastructure ────────────────────────────────
		"runtime_watcher": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 30, MaxActionsPerMin: 40,
			Actions: []ResponseRuleYAML{
				{Action: "kill_process", MinSeverity: "MEDIUM", Description: "Kill suspicious runtime process"},
				{Action: "quarantine_file", MinSeverity: "MEDIUM", Description: "Quarantine modified files"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block lateral movement source", Params: map[string]string{"duration": "4h"}},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on runtime compromise", Params: map[string]string{"url": ""}},
			},
		},
		"cloud_posture": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 120, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on cloud misconfiguration", Params: map[string]string{"url": ""}},
				{Action: "command", MinSeverity: "CRITICAL", Description: "Run cloud remediation script", Params: map[string]string{"command": "echo 'REMEDIATE: {{module}} {{severity}} {{alert_id}}'", "timeout": "60s"}},
			},
		},
		// ── Cross-Cutting ───────────────────────────────────────────────────
		"ai_analysis_engine": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 120, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on AI-correlated threat", Params: map[string]string{"url": ""}},
				{Action: "block_ip", MinSeverity: "CRITICAL", Description: "Block correlated attack source", Params: map[string]string{"duration": "8h"}},
			},
		},
		"*": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 120, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block source of any high-severity alert", Params: map[string]string{"duration": "2h"}},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on any high-severity alert", Params: map[string]string{"url": ""}},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// VPS-AGENT preset — purpose-built for single-service VPS deployments running
// autonomous AI agents (OpenClaw, Moltbot, Manus, etc.).
//
// Threat model: exposed gateway port, prompt injection via chat channels,
// malicious skill/plugin installations, credential exfiltration, agent scope
// escalation, and runtime file tampering (SOUL.md, MEMORY.md, .env).
//
// Philosophy: aggressive on the modules that matter most for AI agent hosts
// (auth, LLM firewall, containment, runtime, supply chain, network), relaxed
// on modules less relevant to a single-VPS agent (IoT, deepfake, quantum).
// ---------------------------------------------------------------------------

func vpsAgentPreset() map[string]ResponsePolicyYAML {
	return map[string]ResponsePolicyYAML{
		// ── Critical: Auth & Gateway Protection ─────────────────────────────
		// CVE-2026-25253 token exfiltration, brute force on gateway port,
		// stolen session tokens from compromised agents.
		"auth_fortress": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 30, MaxActionsPerMin: 60,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "MEDIUM", Description: "Block gateway auth attack source", Params: map[string]string{"duration": "4h"}},
				{Action: "disable_user", MinSeverity: "HIGH", Description: "Disable compromised agent account"},
				{Action: "drop_connection", MinSeverity: "HIGH", Description: "Drop stolen-token sessions"},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on auth attacks against agent gateway", Params: map[string]string{"url": ""}},
			},
		},

		// ── Critical: Prompt Injection Defense ──────────────────────────────
		// #1 attack vector for AI agents. Injection via WhatsApp, Telegram,
		// Discord, web chat, forwarded emails, PDFs, and browsed pages.
		"llm_firewall": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 10, MaxActionsPerMin: 100,
			Actions: []ResponseRuleYAML{
				{Action: "drop_connection", MinSeverity: "MEDIUM", Description: "Drop prompt injection source connection"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block persistent prompt injection attacker", Params: map[string]string{"duration": "8h"}},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on prompt injection attempt", Params: map[string]string{"url": ""}},
			},
		},

		// ── Critical: AI Agent Containment ──────────────────────────────────
		// Scope escalation, rogue tool usage, shadow AI calls, agent spawning
		// sub-agents with inherited permissions.
		"ai_containment": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 15, MaxActionsPerMin: 40,
			Actions: []ResponseRuleYAML{
				{Action: "kill_process", MinSeverity: "MEDIUM", SkipApproval: true, Description: "Kill agent process violating containment policy"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block shadow AI service or unauthorized endpoint", Params: map[string]string{"duration": "8h"}},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on agent containment breach", Params: map[string]string{"url": ""}},
			},
		},

		// ── Critical: Runtime & File Integrity ──────────────────────────────
		// SOUL.md, MEMORY.md, .env tampering; LOLBin usage; persistence
		// mechanisms from Atomic Stealer and similar payloads.
		"runtime_watcher": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 15, MaxActionsPerMin: 60,
			Actions: []ResponseRuleYAML{
				{Action: "kill_process", MinSeverity: "MEDIUM", SkipApproval: true, Description: "Kill process tampering with agent memory or config"},
				{Action: "quarantine_file", MinSeverity: "MEDIUM", SkipApproval: true, Description: "Quarantine modified agent files (SOUL.md, MEMORY.md, .env)"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block source of file tampering attack", Params: map[string]string{"duration": "4h"}},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on runtime file integrity violation", Params: map[string]string{"url": ""}},
			},
		},

		// ── Critical: Supply Chain (Malicious Skills) ───────────────────────
		// ClawHavoc campaign: 335 malicious SKILL.md files, Atomic Stealer,
		// typosquatting, dependency confusion, backdoored plugins.
		"supply_chain": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 30, MaxActionsPerMin: 30,
			Actions: []ResponseRuleYAML{
				{Action: "quarantine_file", MinSeverity: "MEDIUM", SkipApproval: true, Description: "Quarantine suspicious skill or plugin files"},
				{Action: "kill_process", MinSeverity: "HIGH", SkipApproval: true, Description: "Kill process spawned by malicious skill"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block C2 IP from malicious skill payload", Params: map[string]string{"duration": "24h"}},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on supply chain threat", Params: map[string]string{"url": ""}},
			},
		},

		// ── High: Network & Perimeter ───────────────────────────────────────
		// Port scanning of gateway (18789), C2 beaconing from compromised
		// agent, data exfiltration, DNS tunneling.
		"network_guardian": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 30, MaxActionsPerMin: 40,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "MEDIUM", Description: "Block network scan or C2 beaconing source", Params: map[string]string{"duration": "4h"}},
				{Action: "drop_connection", MinSeverity: "HIGH", Description: "Drop exfiltration or tunneling connections"},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on network threats against agent host", Params: map[string]string{"url": ""}},
			},
		},

		// ── High: API Fortress ──────────────────────────────────────────────
		// Gateway API abuse, unauthenticated access attempts, rate limit
		// violations on the agent control plane.
		"api_fortress": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 30, MaxActionsPerMin: 40,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "MEDIUM", Description: "Block API abuse on agent gateway", Params: map[string]string{"duration": "2h"}},
				{Action: "drop_connection", MinSeverity: "HIGH", Description: "Drop abusive gateway connections"},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on gateway API attacks", Params: map[string]string{"url": ""}},
			},
		},

		// ── High: Injection Shield ──────────────────────────────────────────
		// Command injection via agent tool execution (shell_exec, file ops).
		"injection_shield": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 30, MaxActionsPerMin: 60,
			Actions: []ResponseRuleYAML{
				{Action: "drop_connection", MinSeverity: "MEDIUM", Description: "Drop command injection attempts"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block injection source", Params: map[string]string{"duration": "4h"}},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on injection attacks", Params: map[string]string{"url": ""}},
			},
		},

		// ── High: Identity Monitor ──────────────────────────────────────────
		// Synthetic identity creation, privilege escalation within agent.
		"identity_monitor": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 60, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "disable_user", MinSeverity: "HIGH", Description: "Disable escalated or synthetic identity"},
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block identity attack source", Params: map[string]string{"duration": "4h"}},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on identity anomaly", Params: map[string]string{"url": ""}},
			},
		},

		// ── Medium: Ransomware ──────────────────────────────────────────────
		// Less common on agent VPS but still possible via compromised agent.
		"ransomware": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 30, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "kill_process", MinSeverity: "HIGH", SkipApproval: true, Description: "Kill ransomware process"},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on ransomware activity", Params: map[string]string{"url": ""}},
			},
		},

		// ── Medium: Data Poisoning ──────────────────────────────────────────
		// Memory poisoning via MEMORY.md / SOUL.md is the agent-specific
		// variant; also covers training data tampering.
		"data_poisoning": {
			Enabled: true, MinSeverity: "MEDIUM", CooldownSeconds: 60, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "quarantine_file", MinSeverity: "MEDIUM", SkipApproval: true, Description: "Quarantine poisoned agent memory files"},
				{Action: "kill_process", MinSeverity: "HIGH", SkipApproval: true, Description: "Kill process injecting poisoned data"},
				{Action: "webhook", MinSeverity: "MEDIUM", Description: "Notify on data/memory poisoning", Params: map[string]string{"url": ""}},
			},
		},

		// ── Lower priority: still enabled but higher thresholds ─────────────
		"iot_shield": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log IoT anomalies on agent host"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on IoT compromise", Params: map[string]string{"url": ""}},
			},
		},
		"deepfake_shield": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log deepfake detections"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on deepfake threats", Params: map[string]string{"url": ""}},
			},
		},
		"quantum_crypto": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 600, MaxActionsPerMin: 5,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log quantum-vulnerable crypto usage"},
				{Action: "webhook", MinSeverity: "CRITICAL", Description: "Notify on crypto vulnerability", Params: map[string]string{"url": ""}},
			},
		},
		"cloud_posture": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 300, MaxActionsPerMin: 10,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on VPS misconfiguration", Params: map[string]string{"url": ""}},
				{Action: "log_only", MinSeverity: "HIGH", Description: "Log cloud posture drift"},
			},
		},

		// ── Cross-Cutting ───────────────────────────────────────────────────
		"ai_analysis_engine": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 60, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on AI-correlated threat against agent", Params: map[string]string{"url": ""}},
				{Action: "block_ip", MinSeverity: "CRITICAL", Description: "Block correlated attack source", Params: map[string]string{"duration": "8h"}},
			},
		},
		"*": {
			Enabled: true, MinSeverity: "HIGH", CooldownSeconds: 120, MaxActionsPerMin: 20,
			Actions: []ResponseRuleYAML{
				{Action: "block_ip", MinSeverity: "HIGH", Description: "Block source of high-severity alert on agent host", Params: map[string]string{"duration": "2h"}},
				{Action: "webhook", MinSeverity: "HIGH", Description: "Notify on any high-severity alert", Params: map[string]string{"url": ""}},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// VPS-Agent Escalation Config — aggressive timeouts for autonomous hosts.
//
// AI agent VPS instances typically have no human SOC team watching in real
// time. Escalation timers are more important here, not less — if a CRITICAL
// alert sits unacknowledged, the host is likely under active attack with
// nobody watching.
//
// Timeouts are shorter than defaults:
//   CRITICAL: 3 min (default 5 min)  — re-notify up to 5 times
//   HIGH:     10 min (default 15 min) — escalate to CRITICAL, 3 times
//   MEDIUM:   20 min (default 30 min) — escalate to HIGH, 2 times
// ---------------------------------------------------------------------------

// VPSAgentEscalationConfig returns escalation settings tuned for autonomous
// AI agent hosts where no human SOC team is actively monitoring.
func VPSAgentEscalationConfig() EscalationConfig {
	return EscalationConfig{
		Enabled: true,
		Timeouts: map[string]EscalationTimer{
			"CRITICAL": {Timeout: 3 * time.Minute, EscalateTo: "CRITICAL", ReNotify: true, MaxEscalations: 5},
			"HIGH":     {Timeout: 10 * time.Minute, EscalateTo: "CRITICAL", ReNotify: true, MaxEscalations: 3},
			"MEDIUM":   {Timeout: 20 * time.Minute, EscalateTo: "HIGH", ReNotify: true, MaxEscalations: 2},
		},
	}
}

// ---------------------------------------------------------------------------
// VPS-Agent Approval Gate Config — disabled by default.
//
// Autonomous agent hosts can't wait for human approval on destructive actions.
// The critical modules already have SkipApproval: true on kill_process and
// quarantine_file rules. The gate is disabled entirely so no action is held.
//
// Operators who want a human-in-the-loop for lower-priority actions can
// re-enable the gate with a short TTL and auto-approve above CRITICAL.
// ---------------------------------------------------------------------------

// VPSAgentApprovalGateConfig returns approval gate settings for autonomous
// AI agent hosts — disabled by default since there's no human to approve.
func VPSAgentApprovalGateConfig() ApprovalGateConfig {
	return ApprovalGateConfig{
		Enabled:          false,
		RequireApproval:  []string{}, // nothing requires approval
		AutoApproveAbove: "HIGH",     // if re-enabled, auto-approve HIGH+
		TTL:              5 * time.Minute,
		MaxPending:       50,
	}
}
