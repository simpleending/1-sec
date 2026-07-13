package aicontainment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/1sec-project/1sec/internal/modules/tokenvault"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog"
)

const ModuleName = "ai_containment"

// Heuristic detectors for hostile content inside structured tool payloads (prompt
// injection / tool-integration abuse). Regex-only — aligns with zero-external-deps
// architecture — not a semantic SQL or shell parser.

var (
	agentToolShellPrimitiveRX = regexp.MustCompile(
		`(?is)(?:bash|\bsh\b|zsh|dash)\s+-c|` +
			`/bin/(?:bash|sh|dash|zsh)\b|` +
			`/usr/bin/(?:bash|sh|dash|zsh)\b|` +
			`powershell(?:\.exe)?|` +
			`\bpwsh\.exe|` +
			`cmd\.exe|` +
			`invoke-expression|\biex\b|` +
			`(?:^|[^\w])(?:-enc|--encoded(?:command)?|--e\s)` +
			`|` +
			`\b(?:os\.system|subprocess|Popen)\b|` +
			`\bspawn\s*\(|` +
			`(?:^|[^\w])(?:child_process(?:\.\w+)?|require\s*\(\s*['"]child_process['"]\))|` +
			`Process\.Start|` +
			`python(?:3)?\s+-c|` +
			`perl\s+-e|` +
			`ruby\s+-e|` +
			`php\s+-r`,
	)

	agentToolDangerPipeRX = regexp.MustCompile(
		`(?is)\|\s*(?:curl|wget|nc\b|netcat|bash|/\w*bin/sh|powershell|socat\b|perl|python\d?\s+|ruby\s+)\b`)

	agentToolDestructiveSQLRX = regexp.MustCompile(
		`(?is);\s*\b(?:drop|truncate|alter\s+role|grant\s|revoke\s|execute\s+|exec\s+)(?:[^\n;]{1,480})`)

	agentToolHeavySubshellRX = regexp.MustCompile(
		`\$\([^)]{4,440}\)`, // command substitution payloads
	)

	agentToolSubshellInnerRiskRX = regexp.MustCompile(
		`(?is)(?:curl|wget|powershell|/\w*bin/sh|\bbash\b|\bsh\b|nc\b|netcat|` +
			`perl\b|python\d?\s+|ruby\b|chmod\b|chown\b|\brm\s+-|mkfifo)`,
	)

	agentToolURIRX = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]{1,31}:(?://)?[^\s"'<>]+`)
)

var unsafeAgentURISchemes = map[string]struct{}{
	"dict":   {},
	"expect": {},
	"file":   {},
	"gopher": {},
	"jar":    {},
	"local":  {},
	"nfs":    {},
	"smb":    {},
}

// Containment is the AI Agent Containment module providing action sandboxing,
// tool-use monitoring, autonomous behavior detection, shadow AI detection,
// MCP tool poisoning detection, goal hijacking detection, memory poisoning
// detection, cascading failure monitoring, and rogue agent detection.
//
// Aligned with OWASP Agentic AI Top 10 (2025-2026):
//
//	ASI01 - Agent Goal Hijack
//	ASI02 - Tool Misuse
//	ASI03 - Identity Abuse (via privilege escalation tracking)
//	ASI04 - Supply Chain Vulnerabilities (MCP rug pulls)
//	ASI06 - Memory Poisoning
//	ASI08 - Cascading Failures
//	ASI10 - Rogue Agents
type Containment struct {
	logger         zerolog.Logger
	bus            *core.EventBus
	pipeline       *core.AlertPipeline
	cfg            *core.Config
	ctx            context.Context
	cancel         context.CancelFunc
	policyEng      *PolicyEngine
	shadowDet      *ShadowAIDetector
	agentTracker   *AgentTracker
	toolIntegrity  *ToolIntegrityMonitor
	goalMonitor    *GoalHijackMonitor
	memoryMonitor  *MemoryPoisonMonitor
	cascadeMonitor *CascadeFailureMonitor
	// Agentic web access monitors (2026)
	webFetchMonitor   *AgentWebFetchMonitor
	paymentMonitor    *AgentPaymentMonitor
	markdownScanner   *MarkdownIngestionScanner
	delegationTracker *DelegationChainTracker
	// Auth0 Token Vault — secure token delegation for AI agents (opt-in)
	tokenVault *tokenvault.TokenVault
}

func New() *Containment { return &Containment{} }

func (c *Containment) Name() string { return ModuleName }
func (c *Containment) EventTypes() []string {
	return []string{
		"agent_action", "tool_call", "function_call",
		"ai_api_call", "llm_api_call", "model_inference",
		"network_request", "network_connection",
		"agent_spawn", "agent_created",
		"tool_register", "tool_update", "mcp_tool_list",
		"agent_goal", "agent_plan", "agent_decision",
		"agent_memory_write", "context_update", "rag_inject",
		"agent_error", "agent_timeout", "agent_retry",
		"agent_impersonation", "approval_bypass",
		// Agentic web access events (2026)
		"agent_web_fetch", "agent_markdown_ingest",
		"agent_payment", "x402_payment",
		"agent_identity_delegation", "llms_txt_access",
		// Auth0 Token Vault events (opt-in)
		"token_exchange", "token_exchange_request", "token_exchange_response",
		"connected_account_link", "connected_account_unlink",
		"connected_account_usage",
		"oauth_grant", "oauth_consent", "oauth_token",
	}
}
func (c *Containment) Description() string {
	return "AI agent containment: action sandboxing, tool-use monitoring, MCP tool poisoning detection, goal hijacking detection, memory poisoning detection, cascading failure monitoring, shadow AI discovery, rogue agent detection, agentic web access monitoring, Auth0 Token Vault integration (OWASP Agentic AI Top 10)"
}

func (c *Containment) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.bus = bus
	c.pipeline = pipeline
	c.cfg = cfg
	c.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	c.policyEng = NewPolicyEngine()
	c.shadowDet = NewShadowAIDetector()
	c.agentTracker = NewAgentTracker()
	c.toolIntegrity = NewToolIntegrityMonitor()
	c.goalMonitor = NewGoalHijackMonitor()
	c.memoryMonitor = NewMemoryPoisonMonitor()
	c.cascadeMonitor = NewCascadeFailureMonitor()
	c.webFetchMonitor = NewAgentWebFetchMonitor()
	c.paymentMonitor = NewAgentPaymentMonitor()
	c.markdownScanner = NewMarkdownIngestionScanner()
	c.delegationTracker = NewDelegationChainTracker()

	// Initialize Auth0 Token Vault sub-component if enabled
	if cfg.TokenVault.Enabled {
		c.tokenVault = tokenvault.NewTokenVault(ctx, pipeline, cfg, c.logger)
	}

	c.logger.Info().
		Bool("token_vault", c.tokenVault != nil).
		Msg("AI agent containment started (OWASP Agentic AI Top 10 + agentic web access)")
	return nil
}

// TokenVault returns the Token Vault sub-component, or nil if not enabled.
// Used by the API server to expose Token Vault status and token exchange endpoints.
func (c *Containment) TokenVault() *tokenvault.TokenVault {
	return c.tokenVault
}

func (c *Containment) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *Containment) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "agent_action", "tool_call", "function_call":
		c.handleAgentAction(event)
	case "ai_api_call", "llm_api_call", "model_inference":
		c.handleAIAPICall(event)
	case "network_request":
		c.handleNetworkForShadowAI(event)
	case "agent_spawn", "agent_created":
		c.handleAgentSpawn(event)
	case "tool_register", "tool_update", "mcp_tool_list":
		c.handleToolIntegrity(event)
	case "agent_goal", "agent_plan", "agent_decision":
		c.handleGoalMonitoring(event)
	case "agent_memory_write", "context_update", "rag_inject":
		c.handleMemoryPoisoning(event)
	case "agent_error", "agent_timeout", "agent_retry":
		c.handleCascadeFailure(event)
	case "agent_impersonation", "approval_bypass":
		c.handleTrustExploitation(event)
	// Agentic web access handlers (2026)
	case "agent_web_fetch", "llms_txt_access":
		c.handleAgentWebFetch(event)
	case "agent_markdown_ingest":
		c.handleMarkdownIngestion(event)
	case "agent_payment", "x402_payment":
		c.handleAgentPayment(event)
	case "agent_identity_delegation":
		c.handleIdentityDelegation(event)
	}
	// Route to Token Vault sub-component if active — it handles token exchange,
	// connected account, OAuth, and delegation events with token-aware context.
	if c.tokenVault != nil {
		c.tokenVault.HandleEvent(event)
	}
	return nil
}

func (c *Containment) handleAgentAction(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	action := getStringDetail(event, "action")
	tool := getStringDetail(event, "tool")
	target := getStringDetail(event, "target")

	if agentID == "" {
		agentID = "unknown"
	}

	if route := extractUnauthorizedMCPRoute(event, action, tool, target); route != "" {
		c.raiseAlert(event, core.SeverityCritical,
			"Unauthorized MCP Routing Detected (ASI04)",
			fmt.Sprintf("Agent %s attempted to route MCP activity via %s (action: %s, tool: %s). "+
				"Only localhost, 127.0.0.1, ::1, and internal-mcp.svc.cluster.local are allowed for MCP server routing.",
				agentID, truncate(route, 200), action, tool),
			"unauthorized_mcp_routing")
	}

	// Policy enforcement
	violation := c.policyEng.Check(agentID, action, tool, target)
	if violation != nil {
		c.raiseAlert(event, violation.Severity,
			"AI Agent Policy Violation",
			fmt.Sprintf("Agent %s violated policy: %s. Action: %s, Tool: %s, Target: %s",
				agentID, violation.Reason, action, tool, target),
			"agent_policy_violation")
	}

	// Track agent behavior for anomaly detection
	anomaly := c.agentTracker.RecordAction(agentID, action, tool, target)

	if anomaly.RapidActions {
		c.raiseAlert(event, core.SeverityHigh,
			"AI Agent Rapid Action Burst",
			fmt.Sprintf("Agent %s performed %d actions in %s. This exceeds normal operating patterns.",
				agentID, anomaly.ActionCount, anomaly.Window.String()),
			"agent_rapid_actions")
	}

	if anomaly.NewToolUsage {
		c.raiseAlert(event, core.SeverityMedium,
			"AI Agent Using New Tool",
			fmt.Sprintf("Agent %s is using tool %q for the first time. Verify this is authorized.",
				agentID, tool),
			"agent_new_tool")
	}

	if anomaly.EscalatingScope {
		c.raiseAlert(event, core.SeverityHigh,
			"AI Agent Scope Escalation",
			fmt.Sprintf("Agent %s is accessing increasingly sensitive resources. Current target: %s",
				agentID, target),
			"agent_scope_escalation")
	}

	if anomaly.RogueLoop {
		c.raiseAlert(event, core.SeverityCritical,
			"Rogue Agent: Repetitive Loop Detected (ASI10)",
			fmt.Sprintf("Agent %s is repeating the same action %q on target %q %d times. "+
				"This indicates misaligned autonomous behavior or a stuck agent.",
				agentID, action, target, anomaly.LoopCount),
			"rogue_agent_loop")
	}

	// Delegation verification for high-value actions: ensure the agent has a
	// valid delegation record before allowing destructive or financial operations.
	// Catches "agent social engineering" where text claims substitute for real delegation.
	if isHighValueAction(action, tool, target) {
		valid, reason := c.delegationTracker.HasValidDelegation(agentID)
		if !valid {
			c.raiseAlert(event, core.SeverityHigh,
				"High-Value Action Without Valid Delegation",
				fmt.Sprintf("Agent %s attempted high-value action %q (tool: %s, target: %s) "+
					"without a valid delegation record: %s. Text-based authority claims "+
					"(e.g., 'admin approved') do not substitute for cryptographic delegation.",
					agentID, action, tool, target, reason),
				"delegation_verification_failed")
		}
	}

	// Goal-action alignment check: if a tool_call is destructive but the
	// agent's recent goal is read-only (Search/Read/Analyze), block and alert.
	if event.Type == "tool_call" || event.Type == "function_call" {
		if c.goalMonitor.IsDestructiveVsReadOnly(agentID, action, tool) {
			c.raiseAlert(event, core.SeverityHigh,
				"Agent Goal-Action Misalignment Detected",
				fmt.Sprintf("Agent %s attempted destructive action %q (tool: %s) "+
					"while its declared goal is read-only. Blocking action.",
					agentID, action, tool),
				"agent_goal_misalignment")
		}
	}

	toolPayloads := collectStructuredToolStrings(event)
	if unsafeURI := findUnsafeAgentURI(append(toolPayloads, target)...); unsafeURI != "" {
		c.raiseAlert(event, core.SeverityCritical,
			"Unsafe Agent URI Handler Blocked",
			fmt.Sprintf("Agent %s invoked tool %q with a local or non-HTTP URI handler (%s). "+
				"URI handlers can expose workspace files or dispatch requests to local applications without normal web controls.",
				agentID, tool, truncate(unsafeURI, 200)),
			"agent_unsafe_uri_handler")
	}

	if sev, reason, matched := classifyAgentToolPayloadInjection(toolPayloads...); matched {
		c.raiseAlert(event, sev,
			"Suspicious Agent Tool Invocation Payload",
			fmt.Sprintf("Agent %s invoked tool %q with arguments that resemble OS command "+
				"execution, hostile shell pipelines, chained destructive SQL, or heavyweight "+
				"command substitution. Heuristic classification: %s",
				agentID, tool, reason),
			"agent_tool_payload_injection")
	}
}

func findUnsafeAgentURI(blobs ...string) string {
	for _, blob := range blobs {
		decoded := blob
		for i := 0; i < 2; i++ {
			unescaped, err := url.QueryUnescape(decoded)
			if err != nil || unescaped == decoded {
				break
			}
			decoded = unescaped
		}
		for _, candidate := range agentToolURIRX.FindAllString(decoded, 16) {
			parsed, err := url.Parse(candidate)
			if err != nil {
				continue
			}
			if _, blocked := unsafeAgentURISchemes[strings.ToLower(parsed.Scheme)]; blocked {
				return candidate
			}
		}
	}
	return ""
}

// classifyAgentToolPayloadInjection inspects blobs commonly carrying tool payloads.
func classifyAgentToolPayloadInjection(blob ...string) (core.Severity, string, bool) {
	for _, s := range blob {
		if len(s) < 8 {
			continue
		}
		if agentToolShellPrimitiveRX.MatchString(s) || agentToolDangerPipeRX.MatchString(s) {
			return core.SeverityCritical, "shell or interpreter primitive in tool arguments", true
		}
		if agentToolHeavySubshellRX.MatchString(s) &&
			agentToolSubshellInnerRiskRX.MatchString(s) {
			return core.SeverityCritical, "command substitution referencing network or shell utilities", true
		}
		if looksSQLLike(s) && agentToolDestructiveSQLRX.MatchString(s) {
			return core.SeverityHigh, "chained destructive SQL statements in tool arguments", true
		}
	}
	return 0, "", false
}

func looksSQLLike(s string) bool {
	sl := strings.ToLower(s)
	if strings.Contains(sl, "select ") || strings.Contains(sl, "insert ") ||
		strings.Contains(sl, "update ") || strings.Contains(sl, "delete from") {
		return true
	}
	return strings.Contains(sl, " from ") && strings.Contains(sl, " where ")
}

// collectStructuredToolStrings pulls likely tool-argument fields from event details.
func collectStructuredToolStrings(event *core.SecurityEvent) []string {
	if event == nil || event.Details == nil {
		return nil
	}
	keys := []string{
		"tool_args", "arguments", "args", "params", "payload", "input",
		"query", "tool_input", "message", "content", "command", "code", "script", "body",
	}
	seen := make(map[string]struct{}, len(keys))
	var out []string
	for _, k := range keys {
		val, ok := event.Details[k]
		if !ok {
			continue
		}
		s := strings.TrimSpace(detailToString(val))
		if len(s) < 8 {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func detailToString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case json.RawMessage:
		return string(x)
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func (c *Containment) handleAIAPICall(event *core.SecurityEvent) {
	endpoint := getStringDetail(event, "endpoint")
	model := getStringDetail(event, "model")
	user := getStringDetail(event, "user")
	authorized := getStringDetail(event, "authorized")

	if authorized == "false" || authorized == "no" {
		c.raiseAlert(event, core.SeverityHigh,
			"Unauthorized AI API Usage",
			fmt.Sprintf("Unauthorized AI API call to %s (model: %s) by user %s from IP %s",
				endpoint, model, user, event.SourceIP),
			"unauthorized_ai_api")
	}

	c.shadowDet.RecordAPICall(endpoint, model, event.SourceIP, user)
}

func (c *Containment) handleNetworkForShadowAI(event *core.SecurityEvent) {
	destHost := getStringDetail(event, "dest_host")
	if destHost == "" {
		destHost = event.DestIP
	}

	if c.shadowDet.IsKnownAIEndpoint(destHost) {
		user := getStringDetail(event, "user")
		c.raiseAlert(event, core.SeverityMedium,
			"Shadow AI Service Detected",
			fmt.Sprintf("Network traffic to known AI service %s detected from %s (user: %s). This may be unauthorized AI usage.",
				destHost, event.SourceIP, user),
			"shadow_ai_detected")
	}
}

func (c *Containment) handleAgentSpawn(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	parentAgent := getStringDetail(event, "parent_agent")
	capabilities := getStringDetail(event, "capabilities")

	// Check spawn depth — deep nesting is a rogue agent indicator (ASI10)
	depth := c.agentTracker.GetSpawnDepth(agentID, parentAgent)
	severity := core.SeverityMedium
	if depth > 3 {
		severity = core.SeverityHigh
	}

	c.raiseAlert(event, severity,
		"New AI Agent Spawned",
		fmt.Sprintf("New AI agent %s spawned by %s with capabilities: %s (depth: %d). Monitoring initiated.",
			agentID, parentAgent, capabilities, depth),
		"agent_spawned")

	c.agentTracker.RegisterAgent(agentID, parentAgent)
}

// handleToolIntegrity detects MCP tool poisoning, rug pulls, and shadowing (ASI04).
// Ref: Invariant Labs April 2025, arxiv.org/html/2512.06556v1
// Enhanced: auto-computes SHA256 hash of tool definition when not provided by the event,
// enabling hash-based rug pull detection even for clients that don't send hashes.
func (c *Containment) handleToolIntegrity(event *core.SecurityEvent) {
	toolName := getStringDetail(event, "tool_name")
	description := getStringDetail(event, "description")
	serverName := getStringDetail(event, "server_name")
	hash := getStringDetail(event, "description_hash")

	if toolName == "" {
		return
	}

	// Auto-compute hash from description + parameters schema if not provided
	if hash == "" && description != "" {
		params := getStringDetail(event, "parameters")
		hashInput := description + "|" + params
		h := sha256.Sum256([]byte(hashInput))
		hash = fmt.Sprintf("%x", h)
	}

	result := c.toolIntegrity.Analyze(toolName, description, serverName, hash)

	if result.Poisoned {
		c.raiseAlert(event, core.SeverityCritical,
			"MCP Tool Poisoning Detected (ASI04)",
			fmt.Sprintf("Tool %q from server %q contains hidden instructions in its description: %s. "+
				"This is a tool poisoning attack where malicious prompts are embedded in tool metadata. "+
				"Ref: Invariant Labs 2025.",
				toolName, serverName, result.Reason),
			"mcp_tool_poisoning")
	}

	if result.RugPull {
		c.raiseAlert(event, core.SeverityCritical,
			"MCP Tool Rug Pull Detected (ASI04)",
			fmt.Sprintf("Tool %q from server %q changed its description after initial approval. "+
				"Previous hash: %s, new hash: %s. The tool may have been silently redefined "+
				"to perform malicious actions.",
				toolName, serverName, result.PreviousHash, hash),
			"mcp_rug_pull")
	}

	if result.Shadowing {
		c.raiseAlert(event, core.SeverityHigh,
			"MCP Tool Shadowing Detected (ASI04)",
			fmt.Sprintf("Tool %q from server %q shadows an existing tool %q. "+
				"Cross-server tool shadowing can redirect agent actions to malicious implementations.",
				toolName, serverName, result.ShadowedTool),
			"mcp_tool_shadowing")
	}

	if result.Unapproved {
		c.raiseAlert(event, core.SeverityCritical,
			"MCP Tool Hash Mismatch — Possible Tampering (ASI04)",
			fmt.Sprintf("Tool %q from server %q has hash %s but approved registry expects %s. "+
				"The tool definition has been modified from its approved version. "+
				"This may indicate tool supply chain compromise.",
				toolName, serverName, hash, result.ApprovedHash),
			"mcp_tool_tamper")
	}
}

// handleGoalMonitoring detects agent goal hijacking (ASI01).
func (c *Containment) handleGoalMonitoring(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	goal := getStringDetail(event, "goal")
	plan := getStringDetail(event, "plan")
	decision := getStringDetail(event, "decision")
	source := getStringDetail(event, "source")

	if agentID == "" {
		agentID = "unknown"
	}

	content := goal + " " + plan + " " + decision
	result := c.goalMonitor.Analyze(agentID, content, source)

	if result.GoalDivergence {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Goal Hijack Detected (ASI01)",
			fmt.Sprintf("Agent %s goal has diverged from its original objective. "+
				"Original intent: %s. Current: %s. Source of change: %s. "+
				"Attackers may have embedded malicious instructions in processed content.",
				agentID, truncate(result.OriginalGoal, 100), truncate(content, 100), source),
			"goal_hijack")
	}

	if result.ExternalInfluence {
		c.raiseAlert(event, core.SeverityHigh,
			"Agent Goal Influenced by External Content (ASI01)",
			fmt.Sprintf("Agent %s goal/plan changed after processing external content from %q. "+
				"This may indicate indirect prompt injection via documents, emails, or web pages.",
				agentID, source),
			"goal_external_influence")
	}
}

// handleMemoryPoisoning detects persistent context manipulation (ASI06).
func (c *Containment) handleMemoryPoisoning(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	content := getStringDetail(event, "content")
	memoryType := getStringDetail(event, "memory_type")
	source := getStringDetail(event, "source")

	if content == "" {
		content = event.Summary
	}

	result := c.memoryMonitor.Analyze(agentID, content, memoryType, source)

	if result.InstructionInjection {
		c.raiseAlert(event, core.SeverityCritical,
			"Memory Poisoning: Instruction Injection (ASI06)",
			fmt.Sprintf("Agent %s memory write contains embedded instructions: %s. "+
				"Memory type: %s, source: %s. Attackers inject persistent instructions "+
				"into agent memory to manipulate future behavior across sessions.",
				agentID, truncate(result.Reason, 150), memoryType, source),
			"memory_instruction_injection")
	}

	if result.ContextOverflow {
		c.raiseAlert(event, core.SeverityHigh,
			"Memory Poisoning: Context Overflow (ASI06)",
			fmt.Sprintf("Agent %s receiving excessive memory writes (%d in %s). "+
				"This may be an attempt to flood context and push out safety instructions.",
				agentID, result.WriteCount, result.Window),
			"memory_context_overflow")
	}

	if result.CrossSessionLeak {
		c.raiseAlert(event, core.SeverityHigh,
			"Memory Poisoning: Cross-Session Contamination (ASI06)",
			fmt.Sprintf("Agent %s memory contains content from a different session/user. "+
				"Source: %s. Persistent memory can carry poisoned context across sessions.",
				agentID, source),
			"memory_cross_session")
	}
}

// handleCascadeFailure detects multi-agent failure propagation (ASI08).
func (c *Containment) handleCascadeFailure(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	errorType := getStringDetail(event, "error_type")
	targetAgent := getStringDetail(event, "target_agent")

	if agentID == "" {
		agentID = "unknown"
	}

	result := c.cascadeMonitor.Record(agentID, errorType, targetAgent)

	if result.CascadeDetected {
		c.raiseAlert(event, core.SeverityCritical,
			"Cascading Agent Failure Detected (ASI08)",
			fmt.Sprintf("Cascade failure across %d agents in %s. "+
				"Origin: %s, error: %s. Affected agents: %s. "+
				"A single-point failure is propagating through the agent network.",
				result.AffectedAgents, result.Window,
				agentID, errorType, strings.Join(result.AgentChain, " -> ")),
			"cascade_failure")
	}

	if result.RetryStorm {
		c.raiseAlert(event, core.SeverityHigh,
			"Agent Retry Storm Detected (ASI08)",
			fmt.Sprintf("Agent %s has retried %d times in %s for error %q. "+
				"Excessive retries can exhaust resources and amplify failures.",
				agentID, result.RetryCount, result.Window, errorType),
			"agent_retry_storm")
	}
}

// handleTrustExploitation detects human-agent trust boundary violations.
func (c *Containment) handleTrustExploitation(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	action := getStringDetail(event, "action")
	impersonatedUser := getStringDetail(event, "impersonated_user")
	approvalRequired := getStringDetail(event, "approval_required")

	if event.Type == "agent_impersonation" {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Impersonating Human User",
			fmt.Sprintf("Agent %s is impersonating user %q to perform action %q. "+
				"AI agents must not assume human identities to bypass access controls.",
				agentID, impersonatedUser, action),
			"agent_impersonation")
	}

	if event.Type == "approval_bypass" && (approvalRequired == "true" || approvalRequired == "yes") {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Bypassed Human Approval Gate",
			fmt.Sprintf("Agent %s performed action %q that requires human approval without obtaining it. "+
				"Human-in-the-loop controls must not be circumventable by agents.",
				agentID, action),
			"approval_bypass")
	}
}

// ===========================================================================
// Agentic Web Access Handlers (2026)
// ===========================================================================

// handleAgentWebFetch monitors AI agents fetching web content, including
// llms.txt discovery, Accept: text/markdown requests, and reconnaissance.
func (c *Containment) handleAgentWebFetch(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	url := getStringDetail(event, "url")
	domain := getStringDetail(event, "domain")
	acceptHeader := getStringDetail(event, "accept_header")
	statusCode := getStringDetail(event, "status_code")

	if agentID == "" {
		agentID = "unknown"
	}

	result := c.webFetchMonitor.RecordFetch(agentID, url, domain, acceptHeader)

	// Rapid web fetching — reconnaissance indicator
	if result.RapidFetching {
		c.raiseAlert(event, core.SeverityHigh,
			"Agent Web Reconnaissance Detected",
			fmt.Sprintf("Agent %s performed %d web fetches in %s targeting %d domains. "+
				"Rapid multi-domain fetching indicates automated reconnaissance.",
				agentID, result.FetchCount, result.Window, result.UniqueDomains),
			"agent_web_recon")
	}

	// Sensitive URL access
	if result.SensitiveURL {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Accessing Sensitive Web Resource",
			fmt.Sprintf("Agent %s fetched sensitive URL: %s. "+
				"Agents must not access admin panels, internal APIs, cloud metadata, or credential endpoints.",
				agentID, truncate(url, 200)),
			"agent_sensitive_url")
	}

	// llms.txt probing — agent scanning for llms.txt across multiple domains
	if result.LLMSTxtProbing {
		c.raiseAlert(event, core.SeverityMedium,
			"Agent Probing llms.txt Endpoints",
			fmt.Sprintf("Agent %s has accessed llms.txt on %d different domains in %s. "+
				"Systematic llms.txt discovery may indicate capability mapping or attack surface enumeration.",
				agentID, result.LLMSTxtDomains, result.Window),
			"llms_txt_probing")
	}

	// Unauthorized domain access
	if result.UnauthorizedDomain {
		c.raiseAlert(event, core.SeverityHigh,
			"Agent Fetching from Unauthorized Domain",
			fmt.Sprintf("Agent %s fetched content from domain %s which is not in the authorized domain list. "+
				"Status: %s. Agents should only access pre-approved domains.",
				agentID, domain, statusCode),
			"agent_unauthorized_domain")
	}

	// PII exfiltration via URL parameters — zero-click exfiltration defense
	if result.PIIExfiltration {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent PII Exfiltration via URL Parameters",
			fmt.Sprintf("Agent %s fetched URL containing high-entropy secret-like value in query parameter: %s. "+
				"This indicates zero-click exfiltration where an agent is tricked into 'previewing' a URL "+
				"that encodes stolen data in its parameters. Blocking fetch.",
				agentID, truncate(url, 200)),
			"agent_pii_exfiltration")
	}

	// Lateral movement: external→internal fetch sequence (XPIA defense)
	// Detects when an agent reads external content then pivots to internal resources,
	// which is a hallmark of cross-prompt injection attacks.
	if result.LateralMovement {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Lateral Movement Detected (XPIA)",
			fmt.Sprintf("Agent %s accessed internal domain %s after fetching from external domains "+
				"(lateral movement score: %d). This pattern indicates cross-prompt injection (XPIA) "+
				"where malicious external content commands the agent to access internal resources. "+
				"Blocking further fetches for this session.",
				agentID, domain, result.LateralMoveScore),
			"agent_lateral_movement")
	}
}

// handleMarkdownIngestion scans markdown content that agents ingest from
// llms.txt endpoints or Accept: text/markdown responses for embedded
// injection payloads before the content reaches the LLM context.
func (c *Containment) handleMarkdownIngestion(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	content := getStringDetail(event, "content")
	sourceURL := getStringDetail(event, "source_url")
	domain := getStringDetail(event, "domain")
	endpointType := getStringDetail(event, "endpoint_type")

	if content == "" {
		return
	}

	result := c.markdownScanner.Scan(agentID, content, sourceURL, domain)

	if result.InjectionDetected {
		c.raiseAlert(event, core.SeverityCritical,
			"Prompt Injection in Ingested Markdown Content",
			fmt.Sprintf("Agent %s ingested markdown from %s (domain: %s, type: %s) containing "+
				"embedded injection payloads: %s. This is an indirect prompt injection attack "+
				"via web content. The content must be sanitized before reaching the LLM context.",
				agentID, truncate(sourceURL, 100), domain, endpointType,
				strings.Join(result.Indicators, "; ")),
			"markdown_injection")
	}

	if result.HiddenDirectives {
		c.raiseAlert(event, core.SeverityHigh,
			"Hidden Directives in Markdown Content",
			fmt.Sprintf("Agent %s ingested markdown from %s containing hidden directives "+
				"(HTML comments, zero-width characters, or invisible instructions): %s. "+
				"These may be designed to manipulate agent behavior without user visibility.",
				agentID, truncate(sourceURL, 100), strings.Join(result.Indicators, "; ")),
			"markdown_hidden_directives")
	}

	if result.ExfilLinks {
		c.raiseAlert(event, core.SeverityHigh,
			"Data Exfiltration Links in Markdown Content",
			fmt.Sprintf("Agent %s ingested markdown from %s containing links that encode "+
				"data exfiltration patterns (image/link URLs with query parameters designed "+
				"to leak context): %s.",
				agentID, truncate(sourceURL, 100), strings.Join(result.Indicators, "; ")),
			"markdown_exfil_links")
	}
}

// handleAgentPayment monitors AI agent payment transactions including x402
// protocol payments, enforcing spending limits and detecting anomalies.
func (c *Containment) handleAgentPayment(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	amountStr := getStringDetail(event, "amount")
	recipient := getStringDetail(event, "recipient")
	currency := getStringDetail(event, "currency")
	protocol := getStringDetail(event, "protocol")
	merchantID := getStringDetail(event, "merchant_id")
	delegatedBy := getStringDetail(event, "delegated_by")
	spendingLimitStr := getStringDetail(event, "spending_limit")

	if agentID == "" {
		agentID = "unknown"
	}
	if currency == "" {
		currency = "USDC"
	}
	if protocol == "" && event.Type == "x402_payment" {
		protocol = "x402"
	}

	result := c.paymentMonitor.RecordPayment(agentID, amountStr, recipient, currency, protocol, merchantID, delegatedBy, spendingLimitStr)

	if result.SpendingLimitExceeded {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Spending Limit Exceeded",
			fmt.Sprintf("Agent %s attempted payment of %s %s to %s, exceeding its spending limit of %s %s. "+
				"Protocol: %s. Delegated by: %s. Payment must be blocked.",
				agentID, amountStr, currency, recipient, spendingLimitStr, currency, protocol, delegatedBy),
			"agent_spending_limit")
	}

	if result.RapidSpending {
		c.raiseAlert(event, core.SeverityHigh,
			"Agent Rapid Spending Detected",
			fmt.Sprintf("Agent %s made %d payments totaling %.2f %s in %s. "+
				"Rapid autonomous spending may indicate a compromised agent or prompt injection "+
				"redirecting payments.",
				agentID, result.PaymentCount, result.TotalSpent, currency, result.Window),
			"agent_rapid_spending")
	}

	if result.NewRecipient {
		c.raiseAlert(event, core.SeverityMedium,
			"Agent Payment to New Recipient",
			fmt.Sprintf("Agent %s sending %s %s to previously unseen recipient %s via %s. "+
				"First-time recipients should be verified, especially for autonomous payments.",
				agentID, amountStr, currency, recipient, protocol),
			"agent_new_recipient")
	}

	if result.NoDelegation {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Payment Without Human Delegation",
			fmt.Sprintf("Agent %s attempted payment of %s %s to %s without a valid human delegation chain. "+
				"Autonomous payments must be traceable to a human principal.",
				agentID, amountStr, currency, recipient),
			"agent_payment_no_delegation")
	}

	if result.SuspiciousRecipient {
		c.raiseAlert(event, core.SeverityHigh,
			"Agent Payment to Suspicious Recipient",
			fmt.Sprintf("Agent %s sending %s %s to suspicious recipient %s. "+
				"The recipient matches known patterns for payment fraud or drainer contracts.",
				agentID, amountStr, currency, recipient),
			"agent_suspicious_recipient")
	}
}

// handleIdentityDelegation monitors agent identity delegation chains to ensure
// agents acting on behalf of humans have valid, non-expired delegation.
func (c *Containment) handleIdentityDelegation(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	delegatedBy := getStringDetail(event, "delegated_by")
	scopes := getStringDetail(event, "scopes")
	expiresAt := getStringDetail(event, "expires_at")
	delegationChain := getStringDetail(event, "delegation_chain")
	attestation := getStringDetail(event, "attestation")

	if agentID == "" {
		agentID = "unknown"
	}

	result := c.delegationTracker.ValidateDelegation(agentID, delegatedBy, scopes, expiresAt, delegationChain, attestation)

	if result.Expired {
		c.raiseAlert(event, core.SeverityHigh,
			"Agent Operating with Expired Delegation",
			fmt.Sprintf("Agent %s is acting on behalf of %s with an expired delegation (expired: %s). "+
				"Agents must not operate beyond their delegation validity period.",
				agentID, delegatedBy, expiresAt),
			"delegation_expired")
	}

	if result.ChainTooDeep {
		c.raiseAlert(event, core.SeverityHigh,
			"Excessive Agent Delegation Chain Depth",
			fmt.Sprintf("Agent %s has a delegation chain of depth %d: %s. "+
				"Deep delegation chains obscure accountability and increase attack surface.",
				agentID, result.ChainDepth, delegationChain),
			"delegation_chain_deep")
	}

	if result.ScopeEscalation {
		c.raiseAlert(event, core.SeverityCritical,
			"Agent Delegation Scope Escalation",
			fmt.Sprintf("Agent %s delegated by %s is requesting scopes (%s) that exceed "+
				"the delegator's own permissions. Delegation must not escalate privileges.",
				agentID, delegatedBy, scopes),
			"delegation_scope_escalation")
	}

	if result.NoAttestation {
		c.raiseAlert(event, core.SeverityMedium,
			"Agent Delegation Without Cryptographic Attestation",
			fmt.Sprintf("Agent %s claims delegation from %s but provides no cryptographic attestation. "+
				"Delegation claims should be verifiable to prevent agent impersonation.",
				agentID, delegatedBy),
			"delegation_no_attestation")
	}
}

func (c *Containment) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if c.bus != nil {
		_ = c.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getContainmentMitigations(alertType)
	if c.pipeline != nil {
		c.pipeline.Process(alert)
	}
}

// getContainmentMitigations returns contextual mitigations per alert type.
func getContainmentMitigations(alertType string) []string {
	switch alertType {
	case "agent_policy_violation":
		return []string{
			"Review and tighten agent tool-use policies",
			"Implement allowlist-based tool access instead of blocklist",
			"Require human approval for tools outside the agent's designated scope",
		}
	case "agent_rapid_actions":
		return []string{
			"Implement per-agent rate limiting on action frequency",
			"Add circuit breakers that pause agents exceeding action thresholds",
			"Review agent task to determine if rapid actions are expected",
		}
	case "agent_new_tool", "agent_scope_escalation":
		return []string{
			"Enforce least-privilege tool access per agent role",
			"Require re-authorization when agents access new tools after baseline",
			"Monitor agent tool usage patterns for drift from expected behavior",
		}
	case "rogue_agent_loop":
		return []string{
			"Implement loop detection with automatic agent suspension",
			"Add maximum iteration limits to agent task execution",
			"Deploy kill switches for autonomous agents (OWASP ASI10)",
			"Review agent goal specification for ambiguity that causes loops",
		}
	case "unauthorized_ai_api", "shadow_ai_detected":
		return []string{
			"Maintain an inventory of authorized AI services and endpoints",
			"Block unauthorized AI API traffic at the network level",
			"Implement AI service discovery scanning on a regular cadence",
			"Require AI usage registration and approval workflows",
		}
	case "agent_spawned":
		return []string{
			"Limit agent spawn depth to prevent uncontrolled proliferation",
			"Require parent agent authorization for child agent creation",
			"Enforce capability inheritance limits on spawned agents",
		}
	case "mcp_tool_poisoning":
		return []string{
			"Treat tool descriptions as untrusted input — scan for hidden instructions",
			"Pin tool descriptions by hash and alert on changes",
			"Use an MCP gateway to sanitize tool metadata before agent consumption",
			"Audit all MCP server tool descriptions for embedded prompt injections",
		}
	case "mcp_rug_pull":
		return []string{
			"Pin tool description hashes at approval time and reject changes",
			"Implement tool version control with mandatory re-approval on updates",
			"Monitor MCP tool list responses for description mutations",
			"Use signed tool manifests to prevent post-approval tampering",
		}
	case "mcp_tool_shadowing":
		return []string{
			"Enforce unique tool names across all connected MCP servers",
			"Implement tool namespace isolation per MCP server",
			"Alert when new tools share names with existing trusted tools",
			"Use an MCP gateway to deduplicate and prioritize trusted tool sources",
		}
	case "unauthorized_mcp_routing":
		return []string{
			"Allow MCP routing only to localhost or explicitly approved internal MCP gateways",
			"Bind MCP server changes to authenticated admin workflows instead of free-form agent actions",
			"Record and review every external MCP server URI an agent attempts to use",
			"Terminate or pause agents that attempt to bypass approved MCP routing paths",
		}
	case "agent_unsafe_uri_handler":
		return []string{
			"Allow agent tools to fetch only explicitly approved HTTP and HTTPS destinations",
			"Resolve workspace files through scoped file APIs instead of URI handlers",
			"Require user approval before dispatching custom URI schemes to local applications",
			"Record the complete tool invocation and investigate attempted local file access",
		}
	case "goal_hijack", "goal_external_influence":
		return []string{
			"Isolate agent goal/plan state from user-supplied content",
			"Implement goal integrity checks that compare current objectives to original",
			"Sanitize external content (documents, emails, web pages) before agent processing",
			"Use separate channels for system instructions and user/external data",
		}
	case "memory_instruction_injection":
		return []string{
			"Scan memory writes for instruction-like patterns before persistence",
			"Implement memory content policies that reject embedded directives",
			"Use structured memory formats that separate data from instructions",
			"Audit persistent agent memory regularly for injected content",
		}
	case "memory_context_overflow":
		return []string{
			"Rate-limit memory writes per agent per time window",
			"Implement memory size quotas with oldest-first eviction",
			"Monitor for patterns that push safety instructions out of context",
		}
	case "memory_cross_session":
		return []string{
			"Enforce session isolation for agent memory stores",
			"Tag memory entries with session/user provenance and validate on read",
			"Clear agent memory between sessions for sensitive operations",
		}
	case "cascade_failure":
		return []string{
			"Implement circuit breakers between agent-to-agent communications",
			"Deploy bulkhead isolation to contain failures to individual agents",
			"Add health checks and automatic agent suspension on repeated failures",
			"Design agent networks with graceful degradation paths",
		}
	case "agent_retry_storm":
		return []string{
			"Implement exponential backoff with jitter for agent retries",
			"Set maximum retry counts per operation type",
			"Add circuit breakers that open after consecutive failures",
		}
	case "agent_impersonation", "approval_bypass":
		return []string{
			"Enforce distinct non-human identities for all AI agents",
			"Implement cryptographic attestation for human-in-the-loop approvals",
			"Audit all agent actions that cross human-agent trust boundaries",
			"Agents must never assume human credentials or session tokens",
		}
	// Agentic web access mitigations (2026)
	case "agent_web_recon":
		return []string{
			"Implement per-agent rate limits on web fetch operations",
			"Restrict agents to pre-approved domain allowlists",
			"Monitor and alert on multi-domain scanning patterns",
			"Use network-level controls to limit agent egress to authorized endpoints",
		}
	case "agent_sensitive_url":
		return []string{
			"Block agent access to admin panels, cloud metadata, and internal APIs",
			"Implement URL classification and filtering for agent web requests",
			"Use a web proxy that enforces agent-specific access policies",
			"Audit all agent web requests to sensitive endpoints",
		}
	case "llms_txt_probing":
		return []string{
			"Restrict agents to known llms.txt endpoints they need for their task",
			"Monitor for systematic llms.txt discovery across domains",
			"Treat llms.txt content as untrusted input — scan before consumption",
			"Rate-limit llms.txt access per agent per time window",
		}
	case "agent_unauthorized_domain":
		return []string{
			"Maintain per-agent domain allowlists based on task requirements",
			"Implement a web gateway that enforces domain policies for agents",
			"Alert on first-time domain access by established agents",
			"Review and update domain allowlists as agent tasks evolve",
		}
	case "markdown_injection":
		return []string{
			"Scan all ingested markdown for prompt injection patterns before LLM consumption",
			"Implement content sanitization that strips instruction-like patterns from markdown",
			"Use separate safety classifiers for web-sourced content",
			"Treat llms.txt and Accept: text/markdown content as untrusted input (OWASP ASI01)",
		}
	case "markdown_hidden_directives":
		return []string{
			"Strip HTML comments, zero-width characters, and invisible Unicode from ingested markdown",
			"Render markdown to plaintext and compare with original for hidden content",
			"Implement content integrity checks that detect steganographic instructions",
			"Log all markdown ingestion with content hashes for forensic analysis",
		}
	case "markdown_exfil_links":
		return []string{
			"Strip or neutralize all URLs in ingested markdown before LLM consumption",
			"Detect image/link URLs with encoded data in query parameters",
			"Block agent access to URLs that contain context-dependent query strings",
			"Implement URL allowlisting for links in ingested content",
		}
	case "agent_spending_limit":
		return []string{
			"Enforce per-agent spending limits with hard caps in the payment infrastructure",
			"Require human approval for payments exceeding configurable thresholds",
			"Implement payment circuit breakers that halt spending on anomaly detection",
			"Use TEE-protected wallets with programmable spending policies (x402 best practice)",
		}
	case "agent_rapid_spending":
		return []string{
			"Implement per-agent payment velocity limits (max payments per time window)",
			"Add cooling-off periods between large payments",
			"Monitor cumulative spending across all agent wallets",
			"Alert on spending patterns that deviate from historical baselines",
		}
	case "agent_new_recipient":
		return []string{
			"Require human confirmation for first-time payment recipients",
			"Maintain per-agent recipient allowlists",
			"Implement recipient reputation scoring before payment execution",
			"Log all new recipient interactions for audit",
		}
	case "agent_payment_no_delegation":
		return []string{
			"Require valid human delegation for all autonomous payments",
			"Implement delegation chain verification in the payment pipeline",
			"Block payments that cannot be traced to a human principal",
			"Use cryptographic delegation tokens with expiry and scope limits",
		}
	case "agent_suspicious_recipient":
		return []string{
			"Maintain and update blocklists of known drainer contracts and fraud addresses",
			"Implement recipient address screening before payment execution",
			"Require additional verification for payments to high-risk recipients",
			"Report suspicious recipients to threat intelligence feeds",
		}
	case "delegation_expired":
		return []string{
			"Implement automatic agent suspension when delegation expires",
			"Require delegation renewal before agents can resume operations",
			"Set reasonable delegation TTLs based on task duration",
			"Alert human principals when agent delegations are nearing expiry",
		}
	case "delegation_chain_deep":
		return []string{
			"Limit delegation chain depth to prevent accountability obscuration",
			"Require direct human delegation for sensitive operations",
			"Implement delegation chain visualization for audit",
			"Reject delegations that exceed maximum chain depth policy",
		}
	case "delegation_scope_escalation":
		return []string{
			"Enforce that delegated scopes cannot exceed the delegator's own permissions",
			"Implement scope intersection validation in the delegation pipeline",
			"Audit all delegation scope grants for privilege escalation",
			"Use the principle of least privilege for all agent delegations",
		}
	case "delegation_no_attestation":
		return []string{
			"Require cryptographic attestation for all delegation claims",
			"Implement delegation token signing with the delegator's key",
			"Reject unattested delegation claims for sensitive operations",
			"Use the OWASP proposed agent identity standard for delegation verification",
		}
	case "agent_pii_exfiltration":
		return []string{
			"Block agent web fetches containing high-entropy values in URL parameters",
			"Implement URL parameter scrubbing for agent-initiated requests",
			"Monitor agent outbound requests for data that matches PII/secret patterns",
			"Use a web proxy that strips sensitive query parameters from agent requests",
		}
	case "agent_goal_misalignment":
		return []string{
			"Block destructive tool calls when the agent's declared goal is read-only",
			"Implement goal-action alignment verification for all sensitive operations",
			"Require explicit goal re-declaration before escalating to destructive actions",
			"Log all goal-action mismatches for security review",
		}
	case "delegation_verification_failed":
		return []string{
			"Require verified delegation events before allowing high-value agent actions",
			"Implement delegation chain correlation with conversation transcripts",
			"Reject delegation claims that rely solely on text-based authority assertions",
			"Use cryptographic delegation tokens that cannot be forged via social engineering",
		}
	default:
		return []string{
			"Review and restrict AI agent permissions",
			"Implement least-privilege policies for AI tool access",
			"Monitor and log all AI agent actions",
			"Require human approval for sensitive operations",
		}
	}
}

// ============================================================================
// PolicyEngine — enforces action policies for AI agents (ASI02)
// ============================================================================

type PolicyEngine struct {
	mu               sync.RWMutex
	blockedTools     map[string]bool
	blockedActions   *regexp.Regexp
	sensitiveTargets *regexp.Regexp
}

type PolicyViolation struct {
	Reason   string
	Severity core.Severity
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		blockedTools: map[string]bool{
			"shell_exec": true, "system_command": true, "raw_sql": true,
			"file_delete": true, "network_scan": true, "credential_access": true,
			"registry_edit": true, "firewall_modify": true, "user_create": true,
		},
		blockedActions:   regexp.MustCompile(`(?i)(delete\s+database|drop\s+table|rm\s+-rf|format\s+c:|shutdown|reboot|disable\s+firewall|disable\s+antivirus)`),
		sensitiveTargets: regexp.MustCompile(`(?i)(/etc/shadow|/etc/passwd|\.ssh/|\.aws/credentials|\.env|secrets?\.ya?ml|password|private.?key)`),
	}
}

func (pe *PolicyEngine) Check(agentID, action, tool, target string) *PolicyViolation {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	if pe.blockedTools[strings.ToLower(tool)] {
		return &PolicyViolation{
			Reason:   fmt.Sprintf("tool %q is blocked by policy", tool),
			Severity: core.SeverityCritical,
		}
	}

	if pe.blockedActions.MatchString(action) {
		return &PolicyViolation{
			Reason:   "action matches blocked pattern",
			Severity: core.SeverityCritical,
		}
	}

	if pe.sensitiveTargets.MatchString(target) {
		return &PolicyViolation{
			Reason:   fmt.Sprintf("target %q is sensitive", target),
			Severity: core.SeverityHigh,
		}
	}

	return nil
}

// ============================================================================
// ShadowAIDetector — identifies unauthorized AI service usage
// ============================================================================

type ShadowAIDetector struct {
	mu           sync.RWMutex
	knownAIHosts map[string]bool
	apiCalls     *lru.Cache[string, int]
}

func NewShadowAIDetector() *ShadowAIDetector {
	aCache, _ := lru.New[string, int](50000)
	return &ShadowAIDetector{
		knownAIHosts: map[string]bool{
			// Major LLM providers
			"api.openai.com": true, "api.anthropic.com": true,
			"generativelanguage.googleapis.com": true,
			"api.cohere.ai":                     true, "api.mistral.ai": true,
			"api-inference.huggingface.co": true,
			"api.replicate.com":            true, "api.together.xyz": true,
			"api.groq.com": true, "api.perplexity.ai": true,
			"api.deepseek.com": true,
			// 2025-2026 additions
			"api.x.ai": true, "api.grok.x.ai": true,
			"api.meta.ai": true, "llama-api.meta.com": true,
			"api.fireworks.ai": true, "api.anyscale.com": true,
			"api.cerebras.ai": true, "api.sambanova.ai": true,
			"api.lepton.ai": true, "api.modal.com": true,
			"api.baseten.co": true, "api.runpod.ai": true,
			"api.deepinfra.com": true, "api.octo.ai": true,
			"api.aleph-alpha.com": true, "api.ai21.com": true,
			"api.writer.com": true, "api.cohere.com": true,
			"bedrock-runtime.amazonaws.com": true,
			"aiplatform.googleapis.com":     true,
			// Chinese AI providers
			"api.moonshot.cn": true, "api.zhipuai.cn": true,
			"dashscope.aliyuncs.com": true, "api.baichuan-ai.com": true,
			"api.minimax.chat": true,
		},
		apiCalls: aCache,
	}
}

func (sd *ShadowAIDetector) IsKnownAIEndpoint(host string) bool {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.knownAIHosts[strings.ToLower(host)]
}

func (sd *ShadowAIDetector) RecordAPICall(endpoint, model, ip, user string) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	val, _ := sd.apiCalls.Get(ip)
	sd.apiCalls.Add(ip, val+1)
}

// ============================================================================
// AgentTracker — monitors AI agent behavior over time (ASI10 rogue agents)
// ============================================================================

type AgentTracker struct {
	mu     sync.RWMutex
	agents *lru.Cache[string, *agentProfile]
}

type agentProfile struct {
	ID          string
	Parent      string
	KnownTools  map[string]bool
	ActionCount int
	CountWindow time.Time
	Targets     []string
	LastSeen    time.Time
	CreatedAt   time.Time
	// Rogue loop detection
	LastAction  string
	LastTarget  string
	RepeatCount int
}

type AgentAnomaly struct {
	RapidActions    bool
	NewToolUsage    bool
	EscalatingScope bool
	RogueLoop       bool
	ActionCount     int
	LoopCount       int
	Window          time.Duration
}

func NewAgentTracker() *AgentTracker {
	aCache, _ := lru.New[string, *agentProfile](50000)
	return &AgentTracker{agents: aCache}
}

func (at *AgentTracker) RegisterAgent(agentID, parentID string) {
	at.mu.Lock()
	defer at.mu.Unlock()
	at.agents.Add(agentID, &agentProfile{
		ID: agentID, Parent: parentID,
		KnownTools:  make(map[string]bool),
		CountWindow: time.Now(),
		CreatedAt:   time.Now(), LastSeen: time.Now(),
	})
}

// GetSpawnDepth returns how deep in the spawn chain this agent is.
func (at *AgentTracker) GetSpawnDepth(agentID, parentID string) int {
	at.mu.RLock()
	defer at.mu.RUnlock()

	depth := 1
	current := parentID
	seen := map[string]bool{agentID: true}
	for depth < 20 { // cap to prevent infinite loops
		if current == "" {
			break
		}
		if seen[current] {
			break // cycle detected
		}
		seen[current] = true
		profile, exists := at.agents.Get(current)
		if !exists {
			break
		}
		depth++
		current = profile.Parent
	}
	return depth
}

func (at *AgentTracker) RecordAction(agentID, action, tool, target string) AgentAnomaly {
	at.mu.Lock()
	defer at.mu.Unlock()

	anomaly := AgentAnomaly{}
	now := time.Now()

	profile, exists := at.agents.Get(agentID)
	if !exists {
		profile = &agentProfile{
			ID: agentID, KnownTools: map[string]bool{tool: true},
			CountWindow: now, CreatedAt: now, LastSeen: now,
			ActionCount: 1,
		}
		at.agents.Add(agentID, profile)
		return anomaly
	}

	// Reset window
	if now.Sub(profile.CountWindow) > time.Minute {
		profile.ActionCount = 0
		profile.CountWindow = now
	}
	profile.ActionCount++
	profile.LastSeen = now
	anomaly.ActionCount = profile.ActionCount
	anomaly.Window = now.Sub(profile.CountWindow)

	// Rapid actions: more than 100 per minute
	if profile.ActionCount > 100 {
		anomaly.RapidActions = true
	}

	// New tool usage (after baseline period of 1 hour)
	if now.Sub(profile.CreatedAt) > time.Hour && tool != "" && !profile.KnownTools[tool] {
		anomaly.NewToolUsage = true
	}
	if tool != "" {
		profile.KnownTools[tool] = true
	}

	// Rogue loop detection (ASI10): same action+target repeated many times
	actionTarget := action + "|" + target
	if actionTarget == profile.LastAction+"|"+profile.LastTarget && action != "" {
		profile.RepeatCount++
	} else {
		profile.RepeatCount = 1
	}
	profile.LastAction = action
	profile.LastTarget = target
	if profile.RepeatCount >= 10 {
		anomaly.RogueLoop = true
		anomaly.LoopCount = profile.RepeatCount
	}

	// Track target escalation
	if target != "" {
		profile.Targets = append(profile.Targets, target)
		if len(profile.Targets) > 100 {
			profile.Targets = profile.Targets[len(profile.Targets)-100:]
		}
		if len(profile.Targets) >= 5 {
			recentSensitive := 0
			recent := profile.Targets[len(profile.Targets)-5:]
			for _, t := range recent {
				tLower := strings.ToLower(t)
				if strings.Contains(tLower, "admin") || strings.Contains(tLower, "root") ||
					strings.Contains(tLower, "secret") || strings.Contains(tLower, "credential") ||
					strings.Contains(tLower, "password") || strings.Contains(tLower, "/etc/") ||
					strings.Contains(tLower, ".ssh") || strings.Contains(tLower, "private") ||
					strings.Contains(tLower, "token") || strings.Contains(tLower, "key") {
					recentSensitive++
				}
			}
			if recentSensitive >= 3 {
				anomaly.EscalatingScope = true
			}
		}
	}

	return anomaly
}

// ============================================================================
// ToolIntegrityMonitor — MCP tool poisoning, rug pulls, shadowing (ASI04)
// ============================================================================

// ToolIntegrityMonitor detects three classes of MCP tool attacks:
//  1. Tool Poisoning: hidden adversarial instructions in tool descriptions
//  2. Rug Pulls: post-approval description mutations
//  3. Shadowing: cross-server tool name collisions that redirect agent actions
//
// Ref: arxiv.org/html/2512.06556v1, Invariant Labs April 2025
type ToolIntegrityMonitor struct {
	mu             sync.RWMutex
	knownTools     *lru.Cache[string, *toolRecord]
	approvedTools  map[string]string // tool_name -> approved SHA-256 hash
	poisonPatterns []*regexp.Regexp
}

type toolRecord struct {
	Name            string
	Server          string
	DescriptionHash string
	FirstSeen       time.Time
}

type ToolIntegrityResult struct {
	Poisoned     bool
	RugPull      bool
	Shadowing    bool
	Unapproved   bool // tool registered but not in approved map, or hash mismatch
	Reason       string
	PreviousHash string
	ShadowedTool string
	ApprovedHash string // the expected hash from the approved map
}

func NewToolIntegrityMonitor() *ToolIntegrityMonitor {
	tCache, _ := lru.New[string, *toolRecord](10000)
	return &ToolIntegrityMonitor{
		knownTools:    tCache,
		approvedTools: make(map[string]string),
		poisonPatterns: []*regexp.Regexp{
			// Hidden instructions embedded in tool descriptions
			regexp.MustCompile(`(?i)(ignore\s+(previous|prior|all)\s+instructions?|override\s+safety|bypass\s+restrictions?)`),
			regexp.MustCompile(`(?i)(before\s+running\s+this\s+tool|first\s+read|also\s+send|additionally\s+exfiltrate|silently\s+include)`),
			regexp.MustCompile(`(?i)(do\s+not\s+show\s+the\s+user|hide\s+this\s+from|invisible\s+to\s+the\s+user|user\s+should\s+not\s+see)`),
			regexp.MustCompile(`(?i)(send\s+(to|data\s+to)|upload\s+to|exfiltrate|forward\s+to)\s+https?://`),
			regexp.MustCompile(`(?i)(read|access|include|attach)\s+(the\s+)?(ssh|credentials?|private\s+key|\.env|secrets?|password|api.?key|token)`),
			regexp.MustCompile(`(?i)<(IMPORTANT|SYSTEM|HIDDEN|SECRET|ADMIN)>`),
			// Rug pull setup: instructions that only activate later
			regexp.MustCompile(`(?i)(after\s+\d+\s+(calls?|uses?|invocations?)|on\s+(the\s+)?(second|third|next)\s+(call|use|run))`),
		},
	}
}

// RegisterApprovedTool adds a tool to the approved registry with its expected hash.
func (tm *ToolIntegrityMonitor) RegisterApprovedTool(toolName, hash string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.approvedTools[toolName] = hash
}

func (tm *ToolIntegrityMonitor) Analyze(toolName, description, serverName, hash string) ToolIntegrityResult {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	result := ToolIntegrityResult{}

	// Check for poisoned descriptions
	for _, pattern := range tm.poisonPatterns {
		if pattern.MatchString(description) {
			result.Poisoned = true
			result.Reason = pattern.FindString(description)
			break
		}
	}

	// Check for rug pulls (description changed after initial registration)
	key := serverName + "::" + toolName
	existing, exists := tm.knownTools.Get(key)
	if exists && hash != "" && existing.DescriptionHash != "" && existing.DescriptionHash != hash {
		result.RugPull = true
		result.PreviousHash = existing.DescriptionHash
	}

	// Check for shadowing (same tool name from different server)
	if !exists {
		// Check if any other server has a tool with the same name
		keys := tm.knownTools.Keys()
		for _, k := range keys {
			rec, ok := tm.knownTools.Get(k)
			if ok && rec.Name == toolName && rec.Server != serverName {
				result.Shadowing = true
				result.ShadowedTool = rec.Server + "::" + rec.Name
				break
			}
		}
	}

	// Check against approved tool registry — if we have an approved map and this
	// tool's hash doesn't match, flag it as a potential tool poisoning attempt.
	if hash != "" && len(tm.approvedTools) > 0 {
		approvedHash, isRegistered := tm.approvedTools[toolName]
		if isRegistered && approvedHash != hash {
			result.Unapproved = true
			result.ApprovedHash = approvedHash
		}
	}

	// Record or update
	tm.knownTools.Add(key, &toolRecord{
		Name:            toolName,
		Server:          serverName,
		DescriptionHash: hash,
		FirstSeen:       time.Now(),
	})

	return result
}

// ============================================================================
// GoalHijackMonitor — detects agent goal divergence (ASI01)
// ============================================================================

type GoalHijackMonitor struct {
	mu     sync.RWMutex
	agents *lru.Cache[string, *goalState]
	// Patterns that indicate external content is trying to redirect agent goals
	redirectPatterns []*regexp.Regexp
}

type goalState struct {
	OriginalGoal string
	GoalHistory  []goalEntry
	LastSource   string
}

type goalEntry struct {
	Content   string
	Source    string
	Timestamp time.Time
}

type GoalHijackResult struct {
	GoalDivergence    bool
	ExternalInfluence bool
	OriginalGoal      string
}

func NewGoalHijackMonitor() *GoalHijackMonitor {
	gCache, _ := lru.New[string, *goalState](50000)
	return &GoalHijackMonitor{
		agents: gCache,
		redirectPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(new\s+objective|change\s+(your\s+)?goal|your\s+(real|actual|true)\s+(goal|task|objective))`),
			regexp.MustCompile(`(?i)(instead\s+of|rather\s+than|forget\s+(about\s+)?the\s+(original|previous)|abandon\s+(the\s+)?(current|original))`),
			regexp.MustCompile(`(?i)(priority\s+override|urgent\s+new\s+task|critical\s+redirect|emergency\s+instruction)`),
			regexp.MustCompile(`(?i)(the\s+user\s+(actually|really)\s+wants|what\s+they\s+meant\s+was|the\s+real\s+request\s+is)`),
		},
	}
}

func (gm *GoalHijackMonitor) Analyze(agentID, content, source string) GoalHijackResult {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	result := GoalHijackResult{}
	now := time.Now()

	state, exists := gm.agents.Get(agentID)
	if !exists {
		state = &goalState{OriginalGoal: content, LastSource: source}
		state.GoalHistory = append(state.GoalHistory, goalEntry{Content: content, Source: source, Timestamp: now})
		gm.agents.Add(agentID, state)
		return result
	}

	state.GoalHistory = append(state.GoalHistory, goalEntry{Content: content, Source: source, Timestamp: now})
	if len(state.GoalHistory) > 50 {
		state.GoalHistory = state.GoalHistory[len(state.GoalHistory)-50:]
	}

	// Check for redirect patterns in content
	for _, pattern := range gm.redirectPatterns {
		if pattern.MatchString(content) {
			result.GoalDivergence = true
			result.OriginalGoal = state.OriginalGoal
			break
		}
	}

	// Check for external influence: goal changed after processing external content
	externalSources := []string{"email", "document", "web", "pdf", "attachment", "calendar", "file", "rag", "retrieval"}
	sourceLower := strings.ToLower(source)
	for _, ext := range externalSources {
		if strings.Contains(sourceLower, ext) {
			// If the content contains instruction-like patterns, flag it
			for _, pattern := range gm.redirectPatterns {
				if pattern.MatchString(content) {
					result.ExternalInfluence = true
					break
				}
			}
			break
		}
	}

	state.LastSource = source
	return result
}

// IsDestructiveVsReadOnly checks if an agent's current goal is read-only (search/read/analyze)
// but the requested action is destructive (delete/wipe/terminate/drop). Returns true if misaligned.
func (gm *GoalHijackMonitor) IsDestructiveVsReadOnly(agentID, action, tool string) bool {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	state, exists := gm.agents.Get(agentID)
	if !exists || len(state.GoalHistory) == 0 {
		return false
	}

	// Check recent goals (within 10 minutes)
	now := time.Now()
	var recentGoal string
	for i := len(state.GoalHistory) - 1; i >= 0; i-- {
		entry := state.GoalHistory[i]
		if now.Sub(entry.Timestamp) <= 10*time.Minute {
			recentGoal = entry.Content
			break
		}
	}
	if recentGoal == "" {
		return false
	}

	goalLower := strings.ToLower(recentGoal)
	readOnlyGoals := []string{"search", "read", "analyze", "find", "list", "query", "check", "inspect", "review", "scan", "look", "fetch"}
	isReadOnly := false
	for _, ro := range readOnlyGoals {
		if strings.Contains(goalLower, ro) {
			isReadOnly = true
			break
		}
	}
	if !isReadOnly {
		return false
	}

	actionLower := strings.ToLower(action + " " + tool)
	destructiveActions := []string{"delete", "wipe", "terminate", "drop", "destroy", "kill", "remove", "format", "truncate", "purge", "shutdown", "reboot", "rm ", "rm_rf"}
	for _, da := range destructiveActions {
		if strings.Contains(actionLower, da) {
			return true
		}
	}
	return false
}

// ============================================================================
// MemoryPoisonMonitor — detects persistent context manipulation (ASI06)
// ============================================================================

type MemoryPoisonMonitor struct {
	mu              sync.RWMutex
	agents          *lru.Cache[string, *memoryState]
	instructionPats []*regexp.Regexp
}

type memoryState struct {
	WriteCount  int
	WriteWindow time.Time
	Sources     map[string]bool
	LastSession string
}

type MemoryPoisonResult struct {
	InstructionInjection bool
	ContextOverflow      bool
	CrossSessionLeak     bool
	Reason               string
	WriteCount           int
	Window               string
}

func NewMemoryPoisonMonitor() *MemoryPoisonMonitor {
	mCache, _ := lru.New[string, *memoryState](50000)
	return &MemoryPoisonMonitor{
		agents: mCache,
		instructionPats: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(always|never|must|shall)\s+(respond|answer|act|behave|do|say|output)`),
			regexp.MustCompile(`(?i)(from\s+now\s+on|going\s+forward|henceforth|in\s+all\s+future)`),
			regexp.MustCompile(`(?i)(ignore|disregard|override|bypass)\s+(all\s+)?(previous|prior|safety|security)`),
			regexp.MustCompile(`(?i)(your\s+(new\s+)?(role|identity|persona|instructions?)\s+(is|are))`),
			regexp.MustCompile(`(?i)(remember\s+this|store\s+this|keep\s+this\s+in\s+mind).*?(ignore|override|bypass|disregard)`),
			regexp.MustCompile(`(?i)(when\s+(anyone|someone|the\s+user)\s+asks?\s+about).*?(say|respond|tell|answer)`),
		},
	}
}

func (mm *MemoryPoisonMonitor) Analyze(agentID, content, memoryType, source string) MemoryPoisonResult {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	result := MemoryPoisonResult{}
	now := time.Now()

	state, exists := mm.agents.Get(agentID)
	if !exists {
		state = &memoryState{
			WriteWindow: now,
			Sources:     map[string]bool{source: true},
			LastSession: getSessionFromSource(source),
		}
		mm.agents.Add(agentID, state)
	}

	// Reset window
	if now.Sub(state.WriteWindow) > 10*time.Minute {
		state.WriteCount = 0
		state.WriteWindow = now
	}
	state.WriteCount++
	result.WriteCount = state.WriteCount
	result.Window = now.Sub(state.WriteWindow).Round(time.Second).String()

	// Check for instruction injection in memory content
	for _, pattern := range mm.instructionPats {
		if pattern.MatchString(content) {
			result.InstructionInjection = true
			result.Reason = truncate(pattern.FindString(content), 100)
			break
		}
	}

	// Context overflow: too many writes in a short window
	if state.WriteCount > 50 {
		result.ContextOverflow = true
	}

	// Cross-session contamination
	currentSession := getSessionFromSource(source)
	if currentSession != "" && state.LastSession != "" && currentSession != state.LastSession {
		if memoryType == "persistent" || memoryType == "long_term" {
			result.CrossSessionLeak = true
		}
	}
	if currentSession != "" {
		state.LastSession = currentSession
	}
	if source != "" {
		state.Sources[source] = true
	}

	return result
}

func getSessionFromSource(source string) string {
	// Extract session identifier from source string if present
	parts := strings.Split(source, ":")
	if len(parts) >= 2 {
		return parts[0]
	}
	return source
}

// ============================================================================
// CascadeFailureMonitor — detects multi-agent failure propagation (ASI08)
// ============================================================================

type CascadeFailureMonitor struct {
	mu     sync.RWMutex
	errors *lru.Cache[string, *agentErrorState]
}

type agentErrorState struct {
	ErrorCount       int
	RetryCount       int
	Window           time.Time
	ErrorTypes       map[string]int
	DownstreamAgents []string
}

type CascadeResult struct {
	CascadeDetected bool
	RetryStorm      bool
	AffectedAgents  int
	RetryCount      int
	Window          string
	AgentChain      []string
}

func NewCascadeFailureMonitor() *CascadeFailureMonitor {
	eCache, _ := lru.New[string, *agentErrorState](50000)
	return &CascadeFailureMonitor{errors: eCache}
}

func (cm *CascadeFailureMonitor) Record(agentID, errorType, targetAgent string) CascadeResult {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	result := CascadeResult{}
	now := time.Now()

	state, exists := cm.errors.Get(agentID)
	if !exists || now.Sub(state.Window) > 5*time.Minute {
		state = &agentErrorState{
			Window:     now,
			ErrorTypes: make(map[string]int),
		}
		cm.errors.Add(agentID, state)
	}

	state.ErrorCount++
	state.ErrorTypes[errorType]++
	result.Window = now.Sub(state.Window).Round(time.Second).String()

	// Track retry storms
	if errorType == "retry" || strings.Contains(strings.ToLower(errorType), "retry") {
		state.RetryCount++
		result.RetryCount = state.RetryCount
		if state.RetryCount > 20 {
			result.RetryStorm = true
		}
	}

	// Track downstream agent failures for cascade detection
	if targetAgent != "" {
		found := false
		for _, a := range state.DownstreamAgents {
			if a == targetAgent {
				found = true
				break
			}
		}
		if !found {
			state.DownstreamAgents = append(state.DownstreamAgents, targetAgent)
		}
	}

	// Cascade detection: errors propagating to multiple downstream agents
	if len(state.DownstreamAgents) >= 3 && state.ErrorCount >= 5 {
		result.CascadeDetected = true
		result.AffectedAgents = len(state.DownstreamAgents) + 1
		result.AgentChain = append([]string{agentID}, state.DownstreamAgents...)
	}

	return result
}

// ============================================================================
// AgentWebFetchMonitor — tracks agent web access patterns (2026)
// ============================================================================

type AgentWebFetchMonitor struct {
	mu     sync.RWMutex
	agents *lru.Cache[string, *webFetchProfile]
	// Sensitive URL patterns that agents should never access
	sensitiveURLs []*regexp.Regexp
	// PII exfiltration: detects high-entropy secrets in URL query parameters
	piiParamPattern *regexp.Regexp
}

type webFetchProfile struct {
	FetchCount         int
	FetchWindow        time.Time
	Domains            map[string]int
	LLMSTxtDomains     map[string]bool
	LastFetch          time.Time
	LastExternalDomain string // tracks last external domain for lateral movement detection
	LateralMoveScore   int    // incremented on external→internal fetch sequences
}

type WebFetchResult struct {
	RapidFetching      bool
	SensitiveURL       bool
	LLMSTxtProbing     bool
	UnauthorizedDomain bool
	LateralMovement    bool
	PIIExfiltration    bool
	FetchCount         int
	UniqueDomains      int
	LLMSTxtDomains     int
	LateralMoveScore   int
	Window             string
	PIIParam           string
}

func NewAgentWebFetchMonitor() *AgentWebFetchMonitor {
	aCache, _ := lru.New[string, *webFetchProfile](50000)
	return &AgentWebFetchMonitor{
		agents: aCache,
		// PII exfiltration heuristic: detects secret-like values in URL query params
		piiParamPattern: regexp.MustCompile(`(?i)(?:email|ssn|token|api_key|password|secret|auth|session|credit_card|private_key)=([a-zA-Z0-9\-_\.~]{16,})`),
		sensitiveURLs: []*regexp.Regexp{
			// Cloud metadata endpoints
			regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com)`),
			// Admin panels and internal APIs
			regexp.MustCompile(`(?i)(/admin|/wp-admin|/phpmyadmin|/console|/actuator|/management|/internal/)`),
			// Credential and secret endpoints
			regexp.MustCompile(`(?i)(/\.env|/\.git|/\.ssh|/\.aws|/credentials|/secrets|/tokens|/api[_-]?keys)`),
			// Payment and financial endpoints (agents shouldn't scrape these)
			regexp.MustCompile(`(?i)(/wallet|/transfer|/withdraw|/payment.*confirm|/checkout.*complete)`),
			// Localhost and private networks
			regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.)`),
		},
	}
}

func (wm *AgentWebFetchMonitor) RecordFetch(agentID, url, domain, acceptHeader string) WebFetchResult {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	result := WebFetchResult{}
	now := time.Now()

	// Check sensitive URLs
	for _, pattern := range wm.sensitiveURLs {
		if pattern.MatchString(url) {
			result.SensitiveURL = true
			break
		}
	}

	profile, exists := wm.agents.Get(agentID)
	if !exists || now.Sub(profile.FetchWindow) > 5*time.Minute {
		profile = &webFetchProfile{
			FetchWindow:    now,
			Domains:        make(map[string]int),
			LLMSTxtDomains: make(map[string]bool),
		}
		wm.agents.Add(agentID, profile)
	}

	profile.FetchCount++
	profile.LastFetch = now
	if domain != "" {
		profile.Domains[domain]++
	}

	result.FetchCount = profile.FetchCount
	result.UniqueDomains = len(profile.Domains)
	result.Window = now.Sub(profile.FetchWindow).Round(time.Second).String()

	// Detect llms.txt probing
	urlLower := strings.ToLower(url)
	if strings.Contains(urlLower, "llms.txt") || strings.Contains(urlLower, "llms-full.txt") {
		if domain != "" {
			profile.LLMSTxtDomains[domain] = true
		}
	}
	result.LLMSTxtDomains = len(profile.LLMSTxtDomains)
	if result.LLMSTxtDomains >= 5 {
		result.LLMSTxtProbing = true
	}

	// Rapid fetching: more than 50 fetches in 5 minutes across 10+ domains
	if profile.FetchCount > 50 && len(profile.Domains) >= 10 {
		result.RapidFetching = true
	}

	// Lateral movement detection: external→internal fetch sequence (XPIA defense)
	// If agent fetches from an external domain then immediately accesses internal resources,
	// it may have been prompt-injected by the external content.
	isInternal := wm.isInternalDomain(domain)
	if isInternal && profile.LastExternalDomain != "" {
		profile.LateralMoveScore++
		if profile.LateralMoveScore > 2 {
			result.LateralMovement = true
		}
	}
	if !isInternal && domain != "" {
		profile.LastExternalDomain = domain
	}
	result.LateralMoveScore = profile.LateralMoveScore

	// PII exfiltration heuristic: detect high-entropy secret-like values in URL params.
	// Blocks "zero-click exfiltration" where an agent is tricked into fetching a URL
	// that contains stolen PII/secrets encoded in query parameters.
	if matches := wm.piiParamPattern.FindStringSubmatch(url); len(matches) > 1 {
		paramValue := matches[1]
		if len(paramValue) > 32 && shannonEntropy(paramValue) > 4.5 {
			result.PIIExfiltration = true
			result.PIIParam = truncate(paramValue, 40)
		}
	}

	return result
}

// isInternalDomain checks if a domain resolves to internal/private network ranges.
func (wm *AgentWebFetchMonitor) isInternalDomain(domain string) bool {
	domainLower := strings.ToLower(domain)
	internalPatterns := []string{
		"localhost", "127.0.0.1", "::1",
		".internal", ".local", ".corp", ".home", ".private",
		"169.254.169.254", "metadata.google.internal",
	}
	for _, p := range internalPatterns {
		if strings.Contains(domainLower, p) {
			return true
		}
	}
	// Check for private IP ranges in domain
	if strings.HasPrefix(domainLower, "10.") || strings.HasPrefix(domainLower, "192.168.") ||
		strings.HasPrefix(domainLower, "172.") {
		return true
	}
	return false
}

// ============================================================================
// AgentPaymentMonitor — tracks agent payment patterns and enforces limits (2026)
// ============================================================================

type AgentPaymentMonitor struct {
	mu     sync.RWMutex
	agents *lru.Cache[string, *paymentProfile]
	// Known suspicious recipient patterns
	suspiciousRecipients []*regexp.Regexp
}

type paymentProfile struct {
	PaymentCount  int
	TotalSpent    float64
	PaymentWindow time.Time
	Recipients    map[string]bool
	LastPayment   time.Time
}

type PaymentResult struct {
	SpendingLimitExceeded bool
	RapidSpending         bool
	NewRecipient          bool
	NoDelegation          bool
	SuspiciousRecipient   bool
	PaymentCount          int
	TotalSpent            float64
	Window                string
}

func NewAgentPaymentMonitor() *AgentPaymentMonitor {
	aCache, _ := lru.New[string, *paymentProfile](50000)
	return &AgentPaymentMonitor{
		agents: aCache,
		suspiciousRecipients: []*regexp.Regexp{
			// Known drainer contract patterns (hex addresses with common drainer prefixes)
			regexp.MustCompile(`(?i)(0xdead|0xbad|0x0000000000|drainer|scam|phish)`),
			// Mixer/tumbler services
			regexp.MustCompile(`(?i)(tornado|mixer|tumbler|blender|wasabi)`),
			// Temporary/disposable addresses
			regexp.MustCompile(`(?i)(temp|disposable|burner|throwaway)`),
		},
	}
}

func (pm *AgentPaymentMonitor) RecordPayment(agentID, amountStr, recipient, currency, protocol, merchantID, delegatedBy, spendingLimitStr string) PaymentResult {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	result := PaymentResult{}
	now := time.Now()

	// Parse amount
	amount := parseFloat(amountStr)

	// Parse spending limit
	spendingLimit := parseFloat(spendingLimitStr)

	// Check spending limit
	if spendingLimit > 0 && amount > spendingLimit {
		result.SpendingLimitExceeded = true
	}

	// Check delegation
	if delegatedBy == "" {
		result.NoDelegation = true
	}

	// Check suspicious recipients
	for _, pattern := range pm.suspiciousRecipients {
		if pattern.MatchString(recipient) {
			result.SuspiciousRecipient = true
			break
		}
	}

	profile, exists := pm.agents.Get(agentID)
	if !exists || now.Sub(profile.PaymentWindow) > 10*time.Minute {
		profile = &paymentProfile{
			PaymentWindow: now,
			Recipients:    make(map[string]bool),
		}
		pm.agents.Add(agentID, profile)
	}

	// Check new recipient
	if recipient != "" && !profile.Recipients[recipient] {
		result.NewRecipient = true
		profile.Recipients[recipient] = true
	}

	profile.PaymentCount++
	profile.TotalSpent += amount
	profile.LastPayment = now

	result.PaymentCount = profile.PaymentCount
	result.TotalSpent = profile.TotalSpent
	result.Window = now.Sub(profile.PaymentWindow).Round(time.Second).String()

	// Rapid spending: more than 10 payments in 10 minutes or total > 1000
	if profile.PaymentCount > 10 || profile.TotalSpent > 1000 {
		result.RapidSpending = true
	}

	return result
}

func parseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}

// ============================================================================
// MarkdownIngestionScanner — scans markdown content for injection (2026)
// ============================================================================

// MarkdownIngestionScanner detects prompt injection, hidden directives, and
// data exfiltration links embedded in markdown content that agents ingest
// from llms.txt endpoints, Accept: text/markdown responses, or web scraping.
type MarkdownIngestionScanner struct {
	injectionPatterns []*regexp.Regexp
	hiddenDirPatterns []*regexp.Regexp
	exfilLinkPatterns []*regexp.Regexp
}

type MarkdownScanResult struct {
	InjectionDetected bool
	HiddenDirectives  bool
	ExfilLinks        bool
	Indicators        []string
}

func NewMarkdownIngestionScanner() *MarkdownIngestionScanner {
	return &MarkdownIngestionScanner{
		injectionPatterns: []*regexp.Regexp{
			// Direct prompt injection in markdown
			regexp.MustCompile(`(?i)(ignore\s+(previous|prior|all|above)\s+instructions?)`),
			regexp.MustCompile(`(?i)(you\s+are\s+now|your\s+new\s+(role|instructions?|objective)\s+(is|are))`),
			regexp.MustCompile(`(?i)(system\s*:\s*|<\|im_start\|>system|<<SYS>>|\[INST\]|\[/INST\])`),
			regexp.MustCompile(`(?i)(override\s+safety|bypass\s+(restrictions?|filters?|guardrails?))`),
			regexp.MustCompile(`(?i)(do\s+not\s+(tell|show|inform|reveal)\s+(the\s+)?user)`),
			regexp.MustCompile(`(?i)(IMPORTANT|URGENT|CRITICAL|ADMIN|SYSTEM)\s*:\s*(ignore|override|execute|run|perform)`),
			// Markdown-specific injection vectors
			regexp.MustCompile(`(?i)(<!--\s*(system|instruction|prompt|ignore|override))`),
			regexp.MustCompile("(?i)(```\\s*(system|instruction|hidden|secret))"),
			regexp.MustCompile(`(?i)(before\s+responding|when\s+asked|always\s+respond\s+with|from\s+now\s+on)`),
			// Delimiter injection via markdown
			regexp.MustCompile(`(?i)(<\|endoftext\|>|<\|im_end\|>|</s>|\[END\])`),
		},
		hiddenDirPatterns: []*regexp.Regexp{
			// HTML comments with instructions
			regexp.MustCompile(`<!--[\s\S]*?(instruction|directive|ignore|override|system|execute|perform|send|exfiltrate)[\s\S]*?-->`),
			// Zero-width characters (U+200B, U+200C, U+200D, U+FEFF)
			regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{FEFF}]{3,}`),
			// Invisible Unicode blocks
			regexp.MustCompile(`[\x{2060}-\x{2064}]{2,}`),
			// White-on-white text patterns (markdown with excessive whitespace hiding)
			regexp.MustCompile(`(?m)^\s{20,}\S+.*?(ignore|override|execute|system)`),
		},
		exfilLinkPatterns: []*regexp.Regexp{
			// Image tags with data in URL params (classic markdown exfil)
			regexp.MustCompile(`!\[.*?\]\(https?://[^)]*\?(.*?(token|key|secret|password|context|prompt|session|auth)[=&])`),
			// Links with encoded data exfiltration
			regexp.MustCompile(`\[.*?\]\(https?://[^)]*\?(.*?(data|payload|content|dump|leak|exfil)[=&])`),
			// Tracking pixels / beacons
			regexp.MustCompile(`!\[([^\]]{0,2})\]\(https?://[^)]+\.(php|aspx|jsp)\?`),
			// Base64 in URL parameters
			regexp.MustCompile(`https?://[^)\s]*\?[^)\s]*=[A-Za-z0-9+/]{20,}={0,2}`),
		},
	}
}

func (ms *MarkdownIngestionScanner) Scan(agentID, content, sourceURL, domain string) MarkdownScanResult {
	result := MarkdownScanResult{}

	// Check for injection patterns
	for _, pattern := range ms.injectionPatterns {
		if match := pattern.FindString(content); match != "" {
			result.InjectionDetected = true
			result.Indicators = append(result.Indicators, "injection: "+truncate(match, 80))
		}
	}

	// Check for hidden directives
	for _, pattern := range ms.hiddenDirPatterns {
		if match := pattern.FindString(content); match != "" {
			result.HiddenDirectives = true
			result.Indicators = append(result.Indicators, "hidden: "+truncate(match, 80))
		}
	}

	// Check for exfiltration links
	for _, pattern := range ms.exfilLinkPatterns {
		if match := pattern.FindString(content); match != "" {
			result.ExfilLinks = true
			result.Indicators = append(result.Indicators, "exfil_link: "+truncate(match, 80))
		}
	}

	return result
}

// ============================================================================
// DelegationChainTracker — validates agent identity delegation (2026)
// ============================================================================

// DelegationChainTracker monitors and validates agent-to-human delegation
// chains, ensuring agents operate within their delegated authority.
// Aligned with the OWASP proposed agent identity standard.
type DelegationChainTracker struct {
	mu          sync.RWMutex
	delegations *lru.Cache[string, *delegationRecord]
}

type delegationRecord struct {
	AgentID     string
	DelegatedBy string
	Scopes      string
	ExpiresAt   string
	ChainDepth  int
	CreatedAt   time.Time
}

type DelegationResult struct {
	Expired         bool
	ChainTooDeep    bool
	ScopeEscalation bool
	NoAttestation   bool
	ChainDepth      int
}

func NewDelegationChainTracker() *DelegationChainTracker {
	dCache, _ := lru.New[string, *delegationRecord](50000)
	return &DelegationChainTracker{delegations: dCache}
}

func (dt *DelegationChainTracker) ValidateDelegation(agentID, delegatedBy, scopes, expiresAt, delegationChain, attestation string) DelegationResult {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	result := DelegationResult{}

	// Check attestation
	if attestation == "" {
		result.NoAttestation = true
	}

	// Check expiry
	if expiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, expiresAt)
		if err == nil && time.Now().After(expiry) {
			result.Expired = true
		}
	}

	// Check delegation chain depth
	chainDepth := 1
	if delegationChain != "" {
		chainDepth = strings.Count(delegationChain, "->") + 1
		if chainDepth < 1 {
			chainDepth = 1
		}
	}
	result.ChainDepth = chainDepth
	if chainDepth > 3 {
		result.ChainTooDeep = true
	}

	// Check scope escalation: if scopes contain admin/write/delete but
	// the delegator is not known to have those scopes
	scopeLower := strings.ToLower(scopes)
	escalationKeywords := []string{"admin", "root", "superuser", "write:all", "delete:all", "*", "full_access"}
	for _, kw := range escalationKeywords {
		if strings.Contains(scopeLower, kw) {
			result.ScopeEscalation = true
			break
		}
	}

	// Record delegation
	dt.delegations.Add(agentID, &delegationRecord{
		AgentID:     agentID,
		DelegatedBy: delegatedBy,
		Scopes:      scopes,
		ExpiresAt:   expiresAt,
		ChainDepth:  chainDepth,
		CreatedAt:   time.Now(),
	})

	return result
}

// HasValidDelegation checks whether an agent has a valid, non-expired delegation
// on record. Used to verify high-value requests aren't based purely on text claims.
func (dt *DelegationChainTracker) HasValidDelegation(agentID string) (bool, string) {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	record, exists := dt.delegations.Get(agentID)
	if !exists {
		return false, "no delegation record found"
	}

	// Check expiry
	if record.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, record.ExpiresAt)
		if err == nil && time.Now().After(expiry) {
			return false, "delegation expired at " + record.ExpiresAt
		}
	}

	// Check staleness (delegations older than 24h are suspicious)
	if time.Since(record.CreatedAt) > 24*time.Hour {
		return false, "delegation is stale (>24h old)"
	}

	return true, record.DelegatedBy
}

// ============================================================================
// Helpers
// ============================================================================

// shannonEntropy computes the Shannon entropy of a string (bits per character).
// Values >4.5 with length >32 strongly indicate secrets/tokens/encoded data.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]float64)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	length := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// isHighValueAction returns true if the action/tool/target combination represents
// a destructive, financial, or otherwise sensitive operation that should require
// verified human delegation.
func isHighValueAction(action, tool, target string) bool {
	combined := strings.ToLower(action + " " + tool + " " + target)
	highValueKeywords := []string{
		"delete", "destroy", "wipe", "drop", "terminate", "shutdown",
		"transfer", "payment", "withdraw", "send_money",
		"deploy", "publish", "release", "push_to_prod",
		"create_user", "grant_admin", "modify_permission",
		"disable_security", "disable_firewall", "disable_antivirus",
	}
	for _, kw := range highValueKeywords {
		if strings.Contains(combined, kw) {
			return true
		}
	}
	return false
}

func extractUnauthorizedMCPRoute(event *core.SecurityEvent, action, tool, target string) string {
	if !looksLikeMCPRouting(action, tool, target, event) {
		return ""
	}

	for _, candidate := range collectMCPRouteCandidates(event, target) {
		if !strings.HasPrefix(strings.ToLower(candidate), "http://") &&
			!strings.HasPrefix(strings.ToLower(candidate), "https://") {
			continue
		}
		if !isAllowedMCPRoute(candidate) {
			return candidate
		}
	}

	return ""
}

func looksLikeMCPRouting(action, tool, target string, event *core.SecurityEvent) bool {
	hints := []string{
		action, tool, target,
		getStringDetail(event, "server_url"),
		getStringDetail(event, "mcp_server_url"),
		getStringDetail(event, "route_uri"),
		getStringDetail(event, "target_url"),
		getStringDetail(event, "endpoint"),
		getStringDetail(event, "body"),
	}
	for _, hint := range hints {
		lower := strings.ToLower(hint)
		if strings.Contains(lower, "mcp") || strings.Contains(lower, "model context protocol") {
			return true
		}
		if strings.Contains(lower, "server register") || strings.Contains(lower, "server connect") {
			return true
		}
	}
	return false
}

func collectMCPRouteCandidates(event *core.SecurityEvent, target string) []string {
	seen := make(map[string]struct{})
	var candidates []string

	add := func(blob string) {
		for _, match := range extractHTTPURLs(blob) {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			candidates = append(candidates, match)
		}
	}

	add(target)
	for _, key := range []string{
		"server_url", "mcp_server_url", "route_uri", "target_url",
		"url", "endpoint", "remote_url", "body", "arguments", "parameters",
	} {
		add(getStringDetail(event, key))
	}

	return candidates
}

func extractHTTPURLs(blob string) []string {
	if strings.TrimSpace(blob) == "" {
		return nil
	}
	urlRX := regexp.MustCompile(`https?://[^\s"'<>]+`)
	return urlRX.FindAllString(blob, -1)
}

func isAllowedMCPRoute(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return false
	}

	switch strings.ToLower(parsed.Hostname()) {
	case "localhost", "127.0.0.1", "::1", "internal-mcp.svc.cluster.local":
		return parsed.Scheme == "http" || parsed.Scheme == "https"
	default:
		return false
	}
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

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
