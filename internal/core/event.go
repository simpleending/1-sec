package core

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Severity represents the severity level of a security event or alert.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "INFO":
		*s = SeverityInfo
	case "LOW":
		*s = SeverityLow
	case "MEDIUM":
		*s = SeverityMedium
	case "HIGH":
		*s = SeverityHigh
	case "CRITICAL":
		*s = SeverityCritical
	default:
		*s = SeverityInfo
	}
	return nil
}

// SecurityEvent is the standard event structure published to the event bus.
type SecurityEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Module    string                 `json:"module"`
	Type      string                 `json:"type"`
	Severity  Severity               `json:"severity"`
	Summary   string                 `json:"summary"`
	Details   map[string]interface{} `json:"details,omitempty"`
	RawData   []byte                 `json:"raw_data,omitempty"`
	SourceIP  string                 `json:"source_ip,omitempty"`
	DestIP    string                 `json:"dest_ip,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
}

// CanonicalizeEventRouting maps hostile routing tokens to deterministic NATS
// subject tokens while preserving original input in Details.
func CanonicalizeEventRouting(event *SecurityEvent) {
	if event == nil {
		return
	}
	if event.Details == nil {
		event.Details = make(map[string]interface{})
	}
	if !validRoutingToken(event.Module) {
		event.Details["original_module"] = event.Module
		event.Module = "external"
	}
	if !validRoutingToken(event.Type) {
		event.Details["original_type"] = event.Type
		event.Type = "unknown"
	}
}

func validRoutingToken(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// NewSecurityEvent creates a new SecurityEvent with a generated ID and current timestamp.
func NewSecurityEvent(module, eventType string, severity Severity, summary string) *SecurityEvent {
	return &SecurityEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Module:    module,
		Type:      eventType,
		Severity:  severity,
		Summary:   summary,
		Details:   make(map[string]interface{}),
	}
}

// Marshal serializes the event to JSON.
func (e *SecurityEvent) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// UnmarshalSecurityEvent deserializes a SecurityEvent from JSON.
func UnmarshalSecurityEvent(data []byte) (*SecurityEvent, error) {
	var event SecurityEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

// ---------------------------------------------------------------------------
// Canonical Event Types — the versioned telemetry contract.
// Every event type that modules accept is declared here so adapters and users
// know exactly what to send. Modules declare which types they handle via
// EventTypes() and the router only dispatches matching events.
// ---------------------------------------------------------------------------

// EventSchema describes a canonical event type: its name, the Details keys it
// requires, and which keys are optional.
type EventSchema struct {
	Type         string   `json:"type"`
	Category     string   `json:"category"`
	RequiredKeys []string `json:"required_keys"`
	OptionalKeys []string `json:"optional_keys"`
	Description  string   `json:"description"`
}

// CanonicalEventSchemas returns the full versioned event spec.
// Adapters and the /api/v1/event-schemas endpoint expose this so users can
// validate their telemetry before sending it.
func CanonicalEventSchemas() []EventSchema {
	return []EventSchema{
		// ── Auth & Identity ─────────────────────────────────────────────
		{Type: "auth_failure", Category: "auth", RequiredKeys: []string{"username"}, OptionalKeys: []string{"method", "reason"}, Description: "Failed authentication attempt"},
		{Type: "auth_success", Category: "auth", RequiredKeys: []string{"username"}, OptionalKeys: []string{"session_id", "method", "country_code"}, Description: "Successful authentication"},
		{Type: "login_attempt", Category: "auth", RequiredKeys: []string{"username"}, OptionalKeys: []string{"method"}, Description: "Login attempt (success/failure determined by details)"},
		{Type: "login_failure", Category: "auth", RequiredKeys: []string{"username"}, OptionalKeys: []string{"reason"}, Description: "Alias for auth_failure"},
		{Type: "login_success", Category: "auth", RequiredKeys: []string{"username"}, OptionalKeys: []string{"session_id", "country_code"}, Description: "Alias for auth_success"},
		{Type: "auth_attempt", Category: "auth", RequiredKeys: []string{"username"}, OptionalKeys: []string{"method"}, Description: "Generic auth attempt from syslog"},
		{Type: "session_activity", Category: "auth", RequiredKeys: []string{"session_id"}, OptionalKeys: []string{"country_code"}, Description: "Session activity for impossible travel / hijack detection"},
		{Type: "mfa_attempt", Category: "auth", RequiredKeys: []string{"success", "method"}, OptionalKeys: []string{"username"}, Description: "MFA challenge attempt"},
		{Type: "oauth_grant", Category: "auth", RequiredKeys: []string{"app_id", "scopes", "username"}, OptionalKeys: []string{"app_name", "redirect_uri", "grant_type"}, Description: "OAuth consent grant"},
		{Type: "oauth_consent", Category: "auth", RequiredKeys: []string{"app_id", "scopes", "username"}, OptionalKeys: []string{"app_name"}, Description: "OAuth consent event"},
		{Type: "oauth_token", Category: "auth", RequiredKeys: []string{"app_id", "username"}, OptionalKeys: []string{"grant_type", "scopes"}, Description: "OAuth token issuance"},
		{Type: "token_usage", Category: "auth", RequiredKeys: []string{"token_id", "action"}, OptionalKeys: []string{"username"}, Description: "API token / key usage"},
		{Type: "api_key_usage", Category: "auth", RequiredKeys: []string{"token_id", "action"}, OptionalKeys: []string{"username"}, Description: "API key usage event"},
		{Type: "password_spray", Category: "auth", RequiredKeys: []string{"username"}, OptionalKeys: []string{}, Description: "Distributed password spray indicator"},
		{Type: "distributed_auth", Category: "auth", RequiredKeys: []string{"username"}, OptionalKeys: []string{}, Description: "Distributed auth attack indicator"},

		// ── Identity ────────────────────────────────────────────────────
		{Type: "user_created", Category: "identity", RequiredKeys: []string{"user_id"}, OptionalKeys: []string{"email", "name", "source", "created_by"}, Description: "New user/identity created"},
		{Type: "user_updated", Category: "identity", RequiredKeys: []string{"user_id"}, OptionalKeys: []string{"changed_fields", "mutation_type", "session_id", "actor", "new_email", "old_email"}, Description: "User identity/profile updated"},
		{Type: "account_updated", Category: "identity", RequiredKeys: []string{"user_id"}, OptionalKeys: []string{"changed_fields", "mutation_type", "session_id", "actor", "new_email", "old_email"}, Description: "Alias for user identity/profile update"},
		{Type: "profile_updated", Category: "identity", RequiredKeys: []string{"user_id"}, OptionalKeys: []string{"changed_fields", "mutation_type", "session_id", "actor", "new_email", "old_email"}, Description: "Alias for user identity/profile update"},
		{Type: "email_changed", Category: "identity", RequiredKeys: []string{"user_id"}, OptionalKeys: []string{"old_email", "new_email", "session_id", "actor", "initiated_by"}, Description: "User account email changed"},
		{Type: "account_email_changed", Category: "identity", RequiredKeys: []string{"user_id"}, OptionalKeys: []string{"old_email", "new_email", "session_id", "actor", "initiated_by"}, Description: "Alias for user account email change"},
		{Type: "password_changed", Category: "identity", RequiredKeys: []string{"user_id"}, OptionalKeys: []string{"session_id", "actor", "initiated_by"}, Description: "User account password changed"},
		{Type: "password_reset", Category: "identity", RequiredKeys: []string{"user_id"}, OptionalKeys: []string{"session_id", "actor", "initiated_by", "recovery_channel"}, Description: "Password reset or recovery flow completed"},
		{Type: "account_recovery", Category: "identity", RequiredKeys: []string{"user_id"}, OptionalKeys: []string{"session_id", "actor", "initiated_by", "recovery_channel", "new_email"}, Description: "Account recovery or ownership transfer event"},
		{Type: "role_change", Category: "identity", RequiredKeys: []string{"new_role"}, OptionalKeys: []string{"old_role", "granted_by", "permission"}, Description: "Role or privilege change"},
		{Type: "service_account_activity", Category: "identity", RequiredKeys: []string{"account_id", "action"}, OptionalKeys: []string{"resource"}, Description: "Service account action"},
		{Type: "identity_verification", Category: "identity", RequiredKeys: []string{"user_id"}, OptionalKeys: []string{"method", "result"}, Description: "Identity verification event"},

		// ── Network ─────────────────────────────────────────────────────
		{Type: "network_connection", Category: "network", RequiredKeys: []string{}, OptionalKeys: []string{"dest_port", "protocol", "bytes_out", "bytes_in", "duration_ms"}, Description: "Network connection (flow record)"},
		{Type: "dns_query", Category: "network", RequiredKeys: []string{"domain"}, OptionalKeys: []string{"query_type", "response_size"}, Description: "DNS query"},
		{Type: "dns_response", Category: "network", RequiredKeys: []string{"domain"}, OptionalKeys: []string{"query_type", "response_size"}, Description: "DNS response"},
		{Type: "rdp_connection", Category: "network", RequiredKeys: []string{}, OptionalKeys: []string{"username", "auth_protocol"}, Description: "RDP connection for lateral movement detection"},
		{Type: "smb_connection", Category: "network", RequiredKeys: []string{}, OptionalKeys: []string{"username", "auth_protocol"}, Description: "SMB connection for lateral movement detection"},
		{Type: "kerberos_event", Category: "network", RequiredKeys: []string{}, OptionalKeys: []string{"ticket_type", "encryption_type", "service_name"}, Description: "Kerberos authentication event"},

		// ── HTTP / API ──────────────────────────────────────────────────
		{Type: "http_request", Category: "http", RequiredKeys: []string{"path", "method"}, OptionalKeys: []string{"user_id", "resource_id", "user_role", "body", "content_type", "query", "headers", "cookies"}, Description: "HTTP request for API and injection analysis"},
		{Type: "api_request", Category: "http", RequiredKeys: []string{"path", "method"}, OptionalKeys: []string{"user_id", "resource_id", "user_role", "body", "content_type"}, Description: "API request (alias for http_request)"},
		{Type: "http_response", Category: "http", RequiredKeys: []string{"status_code"}, OptionalKeys: []string{"response_size", "response_body", "path"}, Description: "HTTP response for data exposure and anomaly detection"},
		{Type: "api_response", Category: "http", RequiredKeys: []string{"status_code"}, OptionalKeys: []string{"response_size", "response_body"}, Description: "API response (alias for http_response)"},
		{Type: "graphql_request", Category: "http", RequiredKeys: []string{"query"}, OptionalKeys: []string{"operation_name", "variables"}, Description: "GraphQL request"},
		{Type: "jwt_validation", Category: "http", RequiredKeys: []string{"token"}, OptionalKeys: []string{"header", "algorithm", "claims"}, Description: "JWT token validation event"},
		{Type: "token_event", Category: "http", RequiredKeys: []string{"token"}, OptionalKeys: []string{"header", "algorithm"}, Description: "Token event (alias for jwt_validation)"},
		{Type: "query", Category: "http", RequiredKeys: []string{}, OptionalKeys: []string{"path", "body", "query"}, Description: "Generic query event for injection scanning"},
		{Type: "file_upload", Category: "http", RequiredKeys: []string{}, OptionalKeys: []string{"filename", "content_type"}, Description: "File upload for binary analysis (uses RawData)"},

		// ── Process & Runtime ───────────────────────────────────────────
		{Type: "process_start", Category: "runtime", RequiredKeys: []string{"process_name"}, OptionalKeys: []string{"command_line", "parent_process", "pid", "user"}, Description: "Process started"},
		{Type: "process_exec", Category: "runtime", RequiredKeys: []string{"process_name"}, OptionalKeys: []string{"command_line", "parent_process", "path", "executable_path", "hash", "expected_hash", "validated_hash", "executed_hash", "validated_path", "executed_path"}, Description: "Process execution"},
		{Type: "file_change", Category: "runtime", RequiredKeys: []string{"path"}, OptionalKeys: []string{"action", "hash", "old_hash"}, Description: "File modification detected"},
		{Type: "file_modified", Category: "runtime", RequiredKeys: []string{"path"}, OptionalKeys: []string{"process_name", "entropy"}, Description: "File modified (with optional entropy for ransomware)"},
		{Type: "file_created", Category: "runtime", RequiredKeys: []string{"path"}, OptionalKeys: []string{"process_name"}, Description: "File created"},
		{Type: "file_deleted", Category: "runtime", RequiredKeys: []string{"path"}, OptionalKeys: []string{"process_name"}, Description: "File deleted"},
		{Type: "file_renamed", Category: "runtime", RequiredKeys: []string{"path"}, OptionalKeys: []string{"process_name", "new_path"}, Description: "File renamed"},
		{Type: "privilege_change", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"user", "action", "target"}, Description: "Privilege escalation event"},
		{Type: "setuid", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"user", "target"}, Description: "Setuid change"},
		{Type: "capability_change", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"user", "action"}, Description: "Linux capability change"},
		{Type: "container_event", Category: "runtime", RequiredKeys: []string{"action"}, OptionalKeys: []string{"container_id"}, Description: "Container lifecycle event"},
		{Type: "memory_injection", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"technique", "target_process", "source_process", "target_pid"}, Description: "Memory injection detected"},
		{Type: "process_hollowing", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"target_process", "source_process"}, Description: "Process hollowing detected"},
		{Type: "dll_injection", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"target_process", "source_process"}, Description: "DLL injection detected"},
		{Type: "persistence_created", Category: "runtime", RequiredKeys: []string{"name"}, OptionalKeys: []string{"command", "user", "path"}, Description: "Persistence mechanism created"},
		{Type: "scheduled_task", Category: "runtime", RequiredKeys: []string{"name"}, OptionalKeys: []string{"command", "user"}, Description: "Scheduled task created/modified"},
		{Type: "wmi_subscription", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"name", "command"}, Description: "WMI event subscription"},
		{Type: "registry_run_key", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"path", "command"}, Description: "Registry run key modification"},
		{Type: "startup_item", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"name", "command"}, Description: "Startup item created"},
		{Type: "cron_job", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"name", "command"}, Description: "Cron job created/modified"},
		{Type: "systemd_service", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"name", "command"}, Description: "Systemd service created/modified"},
		{Type: "firmware_event", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"component", "hash", "expected_hash", "secure_boot", "action"}, Description: "Firmware/UEFI event"},
		{Type: "uefi_event", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"component", "hash", "expected_hash"}, Description: "UEFI event"},
		{Type: "bootloader_change", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"component", "hash"}, Description: "Bootloader modification"},
		{Type: "fileless_execution", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"process_name", "command_line"}, Description: "Fileless execution detected"},
		{Type: "powershell_exec", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"command_line"}, Description: "PowerShell execution"},
		{Type: "wmi_exec", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"command_line"}, Description: "WMI execution"},
		{Type: "mshta_exec", Category: "runtime", RequiredKeys: []string{}, OptionalKeys: []string{"command_line"}, Description: "MSHTA execution"},

		// ── Ransomware ──────────────────────────────────────────────────
		{Type: "network_egress", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"bytes", "destination"}, Description: "Network egress for exfiltration detection"},
		{Type: "data_transfer", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"bytes", "destination"}, Description: "Data transfer event"},
		{Type: "upload", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"bytes", "destination"}, Description: "Upload event"},
		{Type: "canary_triggered", Category: "ransomware", RequiredKeys: []string{"canary_path"}, OptionalKeys: []string{"process_name"}, Description: "Canary file accessed"},
		{Type: "process_execution", Category: "ransomware", RequiredKeys: []string{"command_line"}, OptionalKeys: []string{"process_name"}, Description: "Process execution for ransomware command detection"},
		{Type: "command_execution", Category: "ransomware", RequiredKeys: []string{"command_line"}, OptionalKeys: []string{"process_name"}, Description: "Command execution event"},
		{Type: "shadow_copy_delete", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"method", "command_line"}, Description: "Shadow copy / VSS deletion"},
		{Type: "vss_manipulation", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"method"}, Description: "VSS manipulation"},
		{Type: "backup_destruction", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"target", "method"}, Description: "Backup destruction detected"},
		{Type: "backup_delete", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"target"}, Description: "Backup deletion"},
		{Type: "wiper_activity", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"target", "method"}, Description: "Wiper activity detected"},
		{Type: "disk_write", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"target"}, Description: "Direct disk write"},
		{Type: "mbr_write", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"target"}, Description: "MBR write detected"},
		{Type: "partition_write", Category: "ransomware", RequiredKeys: []string{}, OptionalKeys: []string{"target"}, Description: "Partition table write"},

		// ── IoT / OT ────────────────────────────────────────────────────
		{Type: "device_connect", Category: "iot", RequiredKeys: []string{"device_id"}, OptionalKeys: []string{"device_type", "mac_address", "firmware_version", "vendor", "protocol"}, Description: "IoT device connection"},
		{Type: "device_activity", Category: "iot", RequiredKeys: []string{"device_id"}, OptionalKeys: []string{"device_type", "protocol"}, Description: "IoT device activity"},
		{Type: "iot_traffic", Category: "iot", RequiredKeys: []string{}, OptionalKeys: []string{"device_id", "protocol"}, Description: "IoT network traffic"},
		{Type: "protocol_message", Category: "iot", RequiredKeys: []string{"protocol"}, OptionalKeys: []string{"payload", "payload_size", "function_code"}, Description: "OT protocol message (Modbus/DNP3/OPCUA/BACnet/MQTT/CoAP)"},
		{Type: "firmware_update", Category: "iot", RequiredKeys: []string{"device_id"}, OptionalKeys: []string{"firmware_version", "firmware_hash", "expected_hash"}, Description: "Firmware update event"},
		{Type: "firmware_check", Category: "iot", RequiredKeys: []string{"device_id"}, OptionalKeys: []string{"firmware_version", "firmware_hash"}, Description: "Firmware integrity check"},
		{Type: "ot_command", Category: "iot", RequiredKeys: []string{"protocol"}, OptionalKeys: []string{"command", "function_code", "target", "value", "operator"}, Description: "OT/SCADA command"},
		{Type: "scada_command", Category: "iot", RequiredKeys: []string{"protocol"}, OptionalKeys: []string{"command", "target", "value"}, Description: "SCADA command"},
		{Type: "plc_command", Category: "iot", RequiredKeys: []string{"protocol"}, OptionalKeys: []string{"command", "target"}, Description: "PLC command"},
		{Type: "network_flow", Category: "iot", RequiredKeys: []string{}, OptionalKeys: []string{"src_zone", "dst_zone", "dest_port", "protocol"}, Description: "Network flow for segmentation enforcement"},
		{Type: "iot_network", Category: "iot", RequiredKeys: []string{}, OptionalKeys: []string{"src_zone", "dst_zone"}, Description: "IoT network flow"},

		// ── Supply Chain ────────────────────────────────────────────────
		{Type: "package_install", Category: "supply_chain", RequiredKeys: []string{"package_name"}, OptionalKeys: []string{"version", "registry", "hash", "expected_hash", "scope"}, Description: "Package installation"},
		{Type: "build_artifact", Category: "supply_chain", RequiredKeys: []string{"artifact_name"}, OptionalKeys: []string{"signature", "provenance", "hash"}, Description: "Build artifact event"},
		{Type: "cicd_event", Category: "supply_chain", RequiredKeys: []string{"action"}, OptionalKeys: []string{"pipeline_name", "user"}, Description: "CI/CD pipeline event"},
		{Type: "sbom_scan", Category: "supply_chain", RequiredKeys: []string{}, OptionalKeys: []string{"vulnerability_count", "critical_count", "high_count"}, Description: "SBOM vulnerability scan result"},

		// ── Cloud Posture ───────────────────────────────────────────────
		{Type: "config_change", Category: "cloud", RequiredKeys: []string{"resource"}, OptionalKeys: []string{"resource_type", "change_type", "user", "old_value", "new_value"}, Description: "Cloud resource configuration change"},
		{Type: "resource_update", Category: "cloud", RequiredKeys: []string{"resource"}, OptionalKeys: []string{"resource_type", "change_type"}, Description: "Cloud resource update"},
		{Type: "iac_deploy", Category: "cloud", RequiredKeys: []string{"resource"}, OptionalKeys: []string{"resource_type"}, Description: "Infrastructure-as-code deployment"},
		{Type: "config_scan", Category: "cloud", RequiredKeys: []string{}, OptionalKeys: []string{"findings", "critical_count", "high_count"}, Description: "Cloud configuration scan"},
		{Type: "posture_check", Category: "cloud", RequiredKeys: []string{}, OptionalKeys: []string{"resource_type", "acl", "public_access", "ingress_cidr", "port", "publicly_accessible", "policy"}, Description: "Cloud posture check"},
		{Type: "secret_detected", Category: "cloud", RequiredKeys: []string{"secret_type"}, OptionalKeys: []string{"location", "file"}, Description: "Secret/credential detected in code or config"},
		{Type: "credential_found", Category: "cloud", RequiredKeys: []string{"secret_type"}, OptionalKeys: []string{"location"}, Description: "Credential found"},
		{Type: "log_entry", Category: "cloud", RequiredKeys: []string{"content"}, OptionalKeys: []string{}, Description: "Log entry for secret scanning"},
		{Type: "audit_log", Category: "cloud", RequiredKeys: []string{"content"}, OptionalKeys: []string{}, Description: "Audit log entry"},
		{Type: "policy_check", Category: "cloud", RequiredKeys: []string{}, OptionalKeys: []string{"framework", "pass_count", "fail_count", "total_checks"}, Description: "Compliance policy check"},
		{Type: "compliance_scan", Category: "cloud", RequiredKeys: []string{}, OptionalKeys: []string{"framework", "pass_count", "fail_count"}, Description: "Compliance scan result"},

		// ── LLM / AI ────────────────────────────────────────────────────
		{Type: "llm_input", Category: "ai", RequiredKeys: []string{"prompt"}, OptionalKeys: []string{"session_id", "user_id", "system_prompt", "context", "rag_context"}, Description: "LLM prompt input for injection/jailbreak scanning"},
		{Type: "llm_output", Category: "ai", RequiredKeys: []string{"output"}, OptionalKeys: []string{"session_id"}, Description: "LLM output for data leakage scanning"},
		{Type: "llm_token_usage", Category: "ai", RequiredKeys: []string{"user_id", "tokens_used"}, OptionalKeys: []string{}, Description: "LLM token budget tracking"},
		{Type: "tool_call", Category: "ai", RequiredKeys: []string{"agent_id", "tool"}, OptionalKeys: []string{"target", "action"}, Description: "AI agent tool call"},
		{Type: "function_call", Category: "ai", RequiredKeys: []string{"agent_id", "tool"}, OptionalKeys: []string{"target"}, Description: "AI agent function call"},

		// ── AI Containment ──────────────────────────────────────────────
		{Type: "agent_action", Category: "ai_containment", RequiredKeys: []string{"agent_id", "action"}, OptionalKeys: []string{"tool", "target"}, Description: "AI agent action for policy enforcement"},
		{Type: "ai_api_call", Category: "ai_containment", RequiredKeys: []string{"endpoint"}, OptionalKeys: []string{"model", "user", "authorized"}, Description: "AI API call for shadow AI detection"},
		{Type: "agent_spawn", Category: "ai_containment", RequiredKeys: []string{"agent_id"}, OptionalKeys: []string{"parent_id", "capabilities"}, Description: "AI agent spawned"},

		// ── Agentic Web Access ──────────────────────────────────────────
		{Type: "agent_web_fetch", Category: "agentic_web", RequiredKeys: []string{"agent_id", "url"}, OptionalKeys: []string{"method", "accept_header", "response_content_type", "status_code", "content_hash", "domain", "response_size"}, Description: "AI agent fetching web content (HTML, markdown, llms.txt)"},
		{Type: "agent_markdown_ingest", Category: "agentic_web", RequiredKeys: []string{"agent_id", "content"}, OptionalKeys: []string{"source_url", "domain", "content_hash", "content_length", "endpoint_type"}, Description: "AI agent ingesting markdown content from llms.txt or Accept: text/markdown endpoints"},
		{Type: "agent_payment", Category: "agentic_web", RequiredKeys: []string{"agent_id", "amount", "recipient"}, OptionalKeys: []string{"currency", "protocol", "merchant_id", "network", "delegated_by", "spending_limit", "wallet_id"}, Description: "AI agent initiating a payment (x402, crypto, or other)"},
		{Type: "agent_identity_delegation", Category: "agentic_web", RequiredKeys: []string{"agent_id", "delegated_by"}, OptionalKeys: []string{"scopes", "expires_at", "delegation_chain", "attestation"}, Description: "AI agent acting on behalf of a human via delegation"},
		{Type: "x402_payment", Category: "agentic_web", RequiredKeys: []string{"amount", "recipient"}, OptionalKeys: []string{"agent_id", "currency", "network", "status_code", "merchant_id", "wallet_id"}, Description: "HTTP 402 payment protocol transaction"},
		{Type: "llms_txt_access", Category: "agentic_web", RequiredKeys: []string{"domain"}, OptionalKeys: []string{"agent_id", "endpoint_url", "content_hash", "response_size"}, Description: "Access to a site's llms.txt or llms-full.txt endpoint"},

		// ── Token Vault (Auth0) ────────────────────────────────────────
		{Type: "token_exchange", Category: "token_vault", RequiredKeys: []string{"connection"}, OptionalKeys: []string{"agent_id", "subject_token_type", "scopes", "user_id"}, Description: "Auth0 Token Vault token exchange request (RFC 8693)"},
		{Type: "token_exchange_request", Category: "token_vault", RequiredKeys: []string{"connection"}, OptionalKeys: []string{"agent_id", "subject_token_type", "grant_type"}, Description: "Token exchange request initiated"},
		{Type: "token_exchange_response", Category: "token_vault", RequiredKeys: []string{"connection", "success"}, OptionalKeys: []string{"error", "error_description", "scopes", "expires_in"}, Description: "Token exchange response received"},
		{Type: "connected_account_link", Category: "token_vault", RequiredKeys: []string{"user_id", "connection"}, OptionalKeys: []string{"scopes", "access_type"}, Description: "User linked a third-party account via Auth0 Connected Accounts"},
		{Type: "connected_account_unlink", Category: "token_vault", RequiredKeys: []string{"user_id", "connection"}, OptionalKeys: []string{}, Description: "User unlinked a third-party account"},
		{Type: "connected_account_usage", Category: "token_vault", RequiredKeys: []string{"user_id", "connection"}, OptionalKeys: []string{"agent_id", "action", "scopes"}, Description: "Connected account token used by an agent or application"},

		// ── Data Poisoning ──────────────────────────────────────────────
		{Type: "training_update", Category: "data_poisoning", RequiredKeys: []string{"dataset_id"}, OptionalKeys: []string{"hash", "change_percent", "record_count", "source"}, Description: "Training data update"},
		{Type: "dataset_update", Category: "data_poisoning", RequiredKeys: []string{"dataset_id"}, OptionalKeys: []string{"hash", "change_percent", "record_count"}, Description: "Dataset update"},
		{Type: "rag_retrieval", Category: "data_poisoning", RequiredKeys: []string{"query"}, OptionalKeys: []string{"retrieved_content", "sources"}, Description: "RAG retrieval for injection detection"},
		{Type: "inference_result", Category: "data_poisoning", RequiredKeys: []string{"model_id"}, OptionalKeys: []string{"confidence", "input_hash", "tensor_shape", "embedding_shape", "tensor_elements", "embedding_elements", "sparsity_ratio", "body"}, Description: "Model inference result for drift and tensor metadata validation"},
		{Type: "model_inference", Category: "data_poisoning", RequiredKeys: []string{"model_id"}, OptionalKeys: []string{"confidence", "input_hash", "tensor_shape", "embedding_shape", "tensor_elements", "embedding_elements", "sparsity_ratio", "body"}, Description: "Model inference request/result for drift and tensor metadata validation"},
		{Type: "prediction", Category: "data_poisoning", RequiredKeys: []string{"model_id"}, OptionalKeys: []string{"confidence", "input_hash", "tensor_shape", "embedding_shape", "tensor_elements", "embedding_elements", "sparsity_ratio", "body"}, Description: "Prediction event for drift and tensor metadata validation"},
		{Type: "model_update", Category: "data_poisoning", RequiredKeys: []string{"model_id"}, OptionalKeys: []string{"weight_hash", "expected_hash", "version", "source"}, Description: "Model weight update"},

		// ── Quantum / Crypto ────────────────────────────────────────────
		{Type: "tls_handshake", Category: "crypto", RequiredKeys: []string{}, OptionalKeys: []string{"tls_version", "cipher_suite", "key_exchange", "server_name"}, Description: "TLS handshake for weak crypto detection"},
		{Type: "tls_connection", Category: "crypto", RequiredKeys: []string{}, OptionalKeys: []string{"tls_version", "cipher_suite", "key_exchange"}, Description: "TLS connection event"},
		{Type: "crypto_usage", Category: "crypto", RequiredKeys: []string{"algorithm"}, OptionalKeys: []string{"key_size", "purpose", "component"}, Description: "Cryptographic algorithm usage"},
		{Type: "certificate_event", Category: "crypto", RequiredKeys: []string{"domain"}, OptionalKeys: []string{"days_until_expiry", "key_algorithm", "key_size", "issuer"}, Description: "Certificate event"},
		{Type: "crypto_inventory", Category: "crypto", RequiredKeys: []string{}, OptionalKeys: []string{"algorithm", "key_size", "component"}, Description: "Crypto inventory scan"},
		{Type: "bulk_transfer", Category: "crypto", RequiredKeys: []string{"bytes_transferred"}, OptionalKeys: []string{"protocol", "cipher_suite", "key_exchange", "capture_type"}, Description: "Bulk data transfer for HNDL detection"},

		// ── Deepfake ────────────────────────────────────────────────────
		{Type: "audio_analysis", Category: "deepfake", RequiredKeys: []string{}, OptionalKeys: []string{"sample_rate", "caller_id", "claimed_identity"}, Description: "Audio for deepfake analysis (uses RawData)"},
		{Type: "video_analysis", Category: "deepfake", RequiredKeys: []string{}, OptionalKeys: []string{"frames", "codec", "fps"}, Description: "Video for deepfake analysis (uses RawData or Details.frames)"},
		{Type: "email_received", Category: "deepfake", RequiredKeys: []string{"sender"}, OptionalKeys: []string{"subject", "body", "sender_domain", "headers"}, Description: "Email for phishing/BEC detection"},
		{Type: "message_received", Category: "deepfake", RequiredKeys: []string{"sender"}, OptionalKeys: []string{"body", "sender_domain"}, Description: "Message for phishing detection"},
		{Type: "high_value_request", Category: "deepfake", RequiredKeys: []string{"request_type"}, OptionalKeys: []string{"amount", "requester", "claimed_identity"}, Description: "High-value request for deepfake-assisted fraud"},

		// ── Syslog (catch-all) ──────────────────────────────────────────
		{Type: "syslog_event", Category: "syslog", RequiredKeys: []string{}, OptionalKeys: []string{"syslog_facility", "syslog_severity", "syslog_hostname", "syslog_app"}, Description: "Unclassified syslog event"},
	}
}

// EventSchemaMap returns schemas indexed by event type for fast lookup.
func EventSchemaMap() map[string]EventSchema {
	schemas := CanonicalEventSchemas()
	m := make(map[string]EventSchema, len(schemas))
	for _, s := range schemas {
		m[s.Type] = s
	}
	return m
}

// ValidateEvent checks that a SecurityEvent has the required Details keys for
// its declared Type. Returns a list of missing keys (empty = valid).
func ValidateEvent(event *SecurityEvent) []string {
	schemas := EventSchemaMap()
	schema, ok := schemas[event.Type]
	if !ok {
		return nil // unknown type — no schema to validate against
	}
	var missing []string
	for _, key := range schema.RequiredKeys {
		if event.Details == nil {
			missing = append(missing, key)
			continue
		}
		val, exists := event.Details[key]
		if !exists {
			missing = append(missing, key)
			continue
		}
		// Check for empty string values
		if str, ok := val.(string); ok && str == "" {
			missing = append(missing, key)
		}
	}
	return missing
}
