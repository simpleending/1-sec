package llmfirewall

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog"
)

const ModuleName = "llm_firewall"

// Firewall is the LLM Firewall module providing prompt injection detection,
// output filtering, jailbreak detection, token budget monitoring,
// multi-turn attack tracking, encoding evasion detection, and tool-chain abuse detection.
type Firewall struct {
	logger        zerolog.Logger
	bus           *core.EventBus
	pipeline      *core.AlertPipeline
	cfg           *core.Config
	ctx           context.Context
	cancel        context.CancelFunc
	patterns      []DetectionPattern
	outputRules   []OutputRule
	tokenBudgets  *lru.Cache[string, *TokenBudget]
	multiTurn     *MultiTurnTracker
	toolChainMon  *ToolChainMonitor
	sessionTaints *lru.Cache[string, map[string]bool]
	mu            sync.RWMutex
}

// DetectionPattern represents a compiled prompt injection/jailbreak pattern.
type DetectionPattern struct {
	Name     string
	Category string
	Regex    *regexp.Regexp
	Severity core.Severity
}

// OutputRule defines rules for filtering LLM output.
type OutputRule struct {
	Name     string
	Category string
	Regex    *regexp.Regexp
	Severity core.Severity
}

// TokenBudget tracks token usage per user/session.
type TokenBudget struct {
	mu       sync.Mutex
	used     int64
	limit    int64
	windowMs int64
	resetAt  int64
}

func New() *Firewall {
	tCache, _ := lru.New[string, *TokenBudget](50000)
	sCache, _ := lru.New[string, map[string]bool](50000)
	return &Firewall{
		tokenBudgets:  tCache,
		sessionTaints: sCache,
		multiTurn:     NewMultiTurnTracker(),
		toolChainMon:  NewToolChainMonitor(),
	}
}

func (f *Firewall) Name() string { return ModuleName }
func (f *Firewall) Description() string {
	return "Prompt injection detection, jailbreak prevention, output filtering, and token budget monitoring for LLM applications"
}
func (f *Firewall) EventTypes() []string {
	return []string{
		"llm_input", "prompt", "llm_request",
		"llm_output", "llm_response", "completion",
		"llm_token_usage",
		"agent_action", "tool_call", "function_call",
		"agent_decision", "agent_plan",
		"rag_retrieval", "embedding_query",
		"llm_citation", "llm_factual_claim",
		"document_upload", "file_attachment", "image_input",
		"agent_web_fetch", "agent_markdown_ingest", "llms_txt_access",
	}
}

func (f *Firewall) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	f.ctx, f.cancel = context.WithCancel(ctx)
	f.bus = bus
	f.pipeline = pipeline
	f.cfg = cfg
	f.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	f.patterns = compileInputPatterns()
	f.outputRules = compileOutputRules()

	f.logger.Info().
		Int("input_patterns", len(f.patterns)).
		Int("output_rules", len(f.outputRules)).
		Msg("LLM firewall started")

	return nil
}

func (f *Firewall) Stop() error {
	if f.cancel != nil {
		f.cancel()
	}
	return nil
}

func (f *Firewall) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "llm_input", "prompt", "llm_request":
		f.analyzeInput(event)
	case "llm_output", "llm_response", "completion":
		f.analyzeOutput(event)
	case "llm_token_usage":
		f.checkTokenBudget(event)
	case "agent_action", "tool_call", "function_call":
		f.analyzeToolChain(event)
	case "agent_decision", "agent_plan":
		f.analyzeExcessiveAgency(event)
	case "rag_retrieval", "embedding_query":
		f.analyzeRAGRetrieval(event)
	case "llm_citation", "llm_factual_claim":
		f.analyzeMisinformation(event)
	case "document_upload", "file_attachment", "image_input":
		f.analyzeMultimodal(event)
	case "agent_web_fetch", "agent_markdown_ingest", "llms_txt_access":
		f.recordWebTaint(event)
	}
	return nil
}

func (f *Firewall) analyzeInput(event *core.SecurityEvent) {
	prompt := getStringDetail(event, "prompt")
	if prompt == "" {
		prompt = getStringDetail(event, "user_input")
	}
	if prompt == "" {
		prompt = event.Summary
	}
	if prompt == "" {
		return
	}

	systemPrompt := getStringDetail(event, "system_prompt")
	userID := getStringDetail(event, "user_id")
	sessionID := getStringDetail(event, "session_id")
	if sessionID == "" {
		sessionID = event.SourceIP
	}

	// Decode evasion layers before scanning
	decoded := decodeEvasionLayers(prompt)

	detections := f.scanInput(decoded)

	// Also scan the raw input if decoding changed it
	if decoded != prompt {
		rawDetections := f.scanInput(prompt)
		detections = append(detections, rawDetections...)
		// If decoding revealed hidden content, that's suspicious on its own
		if len(rawDetections) == 0 && len(detections) > 0 {
			detections = append(detections, InputDetection{
				PatternName: "encoding_evasion_detected",
				Category:    "evasion",
				Severity:    core.SeverityHigh,
				MatchedText: "payload hidden behind encoding layers",
			})
		}
	}

	embeddedContent := getStringDetail(event, "context")
	if embeddedContent == "" {
		embeddedContent = getStringDetail(event, "rag_context")
	}
	if embeddedContent != "" {
		embeddedDecoded := decodeEvasionLayers(embeddedContent)
		detections = append(detections, f.scanInput(embeddedDecoded)...)
	}

	// Multi-turn analysis: track conversation and detect gradual escalation
	if sessionID != "" {
		multiTurnResult := f.multiTurn.RecordAndAnalyze(sessionID, prompt, len(detections) > 0)
		if multiTurnResult.GradualEscalation {
			detections = append(detections, InputDetection{
				PatternName: "multi_turn_escalation",
				Category:    "multi_turn_attack",
				Severity:    core.SeverityCritical,
				MatchedText: fmt.Sprintf("gradual escalation over %d turns, %d suspicious", multiTurnResult.TurnCount, multiTurnResult.SuspiciousTurns),
			})
		}
		if multiTurnResult.ContextBuildup {
			detections = append(detections, InputDetection{
				PatternName: "context_buildup_attack",
				Category:    "multi_turn_attack",
				Severity:    core.SeverityHigh,
				MatchedText: fmt.Sprintf("context manipulation across %d turns", multiTurnResult.TurnCount),
			})
		}
		if multiTurnResult.RapidFire {
			detections = append(detections, InputDetection{
				PatternName: "rapid_fire_probing",
				Category:    "multi_turn_attack",
				Severity:    core.SeverityMedium,
				MatchedText: fmt.Sprintf("%d prompts in rapid succession", multiTurnResult.TurnCount),
			})
		}
	}

	// Semantic heuristic: check for instruction-like structure in user input
	semanticDetections := analyzeSemanticStructure(prompt)
	detections = append(detections, semanticDetections...)

	// Many-shot volume detection: count repeated Q&A-like patterns.
	// Many-shot jailbreaking floods context with hundreds of compliant examples.
	// Ref: Anthropic 2024 research, still effective in 2025-2026.
	manyShotDetections := detectManyShotVolume(prompt)
	detections = append(detections, manyShotDetections...)

	// FlipAttack detection: check for reversed text segments.
	// Ref: ICML 2025 — 81% average success rate, 98% on GPT-4o.
	flipDetections := detectFlippedText(prompt)
	detections = append(detections, flipDetections...)

	if len(detections) == 0 {
		return
	}

	maxSeverity := core.SeverityInfo
	categories := make(map[string]bool)
	for _, d := range detections {
		if d.Severity > maxSeverity {
			maxSeverity = d.Severity
		}
		categories[d.Category] = true
	}

	catList := make([]string, 0, len(categories))
	for c := range categories {
		catList = append(catList, c)
	}

	newEvent := core.NewSecurityEvent(ModuleName, "llm_threat_detected", maxSeverity,
		fmt.Sprintf("LLM threat detected: %s", strings.Join(catList, ", ")))
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID
	newEvent.Details["categories"] = catList
	newEvent.Details["detection_count"] = len(detections)
	newEvent.Details["has_system_prompt"] = systemPrompt != ""
	newEvent.Details["session_id"] = sessionID
	if userID != "" {
		newEvent.Details["user_id"] = userID
	}

	if f.bus != nil {
		_ = f.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent,
		fmt.Sprintf("LLM Threat: %s", strings.Join(catList, ", ")),
		fmt.Sprintf("Detected %d threat pattern(s) in LLM input. Categories: %s. Severity: %s.",
			len(detections), strings.Join(catList, ", "), maxSeverity.String()))
	alert.Mitigations = getLLMInputMitigations(catList)
	if sessionID != "" {
		alert.Metadata["session_id"] = sessionID
	}
	if userID != "" {
		alert.Metadata["user_id"] = userID
	}

	if f.pipeline != nil {
		f.pipeline.Process(alert)
	}
}

func (f *Firewall) recordWebTaint(event *core.SecurityEvent) {
	sessionID := getStringDetail(event, "session_id")
	if sessionID == "" {
		sessionID = event.SourceIP
	}
	if sessionID == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	taints, ok := f.sessionTaints.Get(sessionID)
	if !ok || taints == nil {
		taints = make(map[string]bool)
	}
	taints["WebContextFetch"] = true
	f.sessionTaints.Add(sessionID, taints)
}

// markdownLinkRX detects markdown image/link syntax.
// Ref: ChatGPhish / Third-Party Markdown Poisoning (weekly intel 2026-05-29).
var markdownLinkRX = regexp.MustCompile(`(?i)(?:\[[^\]]*\]|\!\[[^\]]*\])\((https?://[^\)]+)\)`)

func isLocalMarkdownURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified())
}

func (f *Firewall) analyzeOutput(event *core.SecurityEvent) {
	output := getStringDetail(event, "output")
	if output == "" {
		output = getStringDetail(event, "response")
	}
	if output == "" {
		return
	}

	// Check for markdown poisoning when session is tainted by web fetch
	sessionID := getStringDetail(event, "session_id")
	if sessionID == "" {
		sessionID = event.SourceIP
	}
	if sessionID != "" {
		f.mu.RLock()
		taints, _ := f.sessionTaints.Get(sessionID)
		webTainted := taints != nil && taints["WebContextFetch"]
		f.mu.RUnlock()
		if webTainted {
			for _, match := range markdownLinkRX.FindAllString(output, -1) {
				// Extract the URL from the markdown link
				if sub := markdownLinkRX.FindStringSubmatch(match); len(sub) > 1 {
					url := sub[1]
					if !isLocalMarkdownURL(url) {
						newEvent := core.NewSecurityEvent(ModuleName, "asi_markdown_poisoning", core.SeverityCritical,
							fmt.Sprintf("Tainted session produced external markdown link after web fetch: %s", truncate(match, 200)))
						newEvent.Details["original_event_id"] = event.ID
						newEvent.Details["session_id"] = sessionID
						newEvent.Details["matched_text"] = match
						newEvent.Details["external_url"] = url

						if f.bus != nil {
							_ = f.bus.PublishEvent(newEvent)
						}

						alert := core.NewAlert(newEvent,
							"ASI-Markdown-Poisoning: Tainted Web Context",
							"Agent fetched external web content and subsequently generated markdown containing remote image/link URLs. This is the ChatGPhish zero-click exfiltration pattern.")
						alert.Mitigations = []string{"Block the agent session", "Sanitize all markdown from untrusted web sources", "Review fetched URLs against denylist"}

						if f.pipeline != nil {
							f.pipeline.Process(alert)
						}
						// Only alert once per output
						break
					}
				}
			}
		}
	}

	for _, rule := range f.outputRules {
		if rule.Regex.MatchString(output) {
			newEvent := core.NewSecurityEvent(ModuleName, "llm_output_violation", rule.Severity,
				fmt.Sprintf("LLM output violation: %s", rule.Name))
			newEvent.Details["original_event_id"] = event.ID
			newEvent.Details["rule"] = rule.Name
			newEvent.Details["category"] = rule.Category

			if f.bus != nil {
				_ = f.bus.PublishEvent(newEvent)
			}

			alert := core.NewAlert(newEvent,
				fmt.Sprintf("LLM Output Violation: %s", rule.Name),
				fmt.Sprintf("LLM output matched rule %q (%s). The output may contain sensitive data or harmful content.",
					rule.Name, rule.Category))
			alert.Mitigations = getOutputMitigations(rule.Category)

			if f.pipeline != nil {
				f.pipeline.Process(alert)
			}
		}
	}
}

func (f *Firewall) checkTokenBudget(event *core.SecurityEvent) {
	userID := getStringDetail(event, "user_id")
	if userID == "" {
		userID = event.SourceIP
	}
	if userID == "" {
		return
	}

	tokensUsed := getIntDetail(event, "tokens_used")
	if tokensUsed <= 0 {
		return
	}

	f.mu.Lock()
	budget, exists := f.tokenBudgets.Get(userID)
	if !exists {
		settings := f.cfg.GetModuleSettings(ModuleName)
		limit := getIntSetting(settings, "token_budget_per_hour", 100000)
		now := time.Now().UnixMilli()
		budget = &TokenBudget{
			limit:    int64(limit),
			windowMs: 3600 * 1000, // 1 hour in milliseconds
			resetAt:  now + 3600*1000,
		}
		f.tokenBudgets.Add(userID, budget)
	}
	f.mu.Unlock()

	budget.mu.Lock()
	now := time.Now().UnixMilli()
	// Reset the window if it has elapsed
	if now >= budget.resetAt {
		budget.used = 0
		budget.resetAt = now + budget.windowMs
	}
	budget.used += int64(tokensUsed)
	exceeded := budget.used > budget.limit
	usage := budget.used
	limit := budget.limit
	budget.mu.Unlock()

	if exceeded {
		newEvent := core.NewSecurityEvent(ModuleName, "token_budget_exceeded", core.SeverityMedium,
			fmt.Sprintf("Token budget exceeded for user %s: %d/%d", userID, usage, limit))
		newEvent.Details["user_id"] = userID
		newEvent.Details["tokens_used"] = usage
		newEvent.Details["token_limit"] = limit

		if f.bus != nil {
			_ = f.bus.PublishEvent(newEvent)
		}

		alert := core.NewAlert(newEvent,
			"Token Budget Exceeded",
			fmt.Sprintf("User %s has used %d tokens, exceeding the hourly limit of %d. This may indicate abuse or a compromised account.",
				userID, usage, limit))

		if f.pipeline != nil {
			f.pipeline.Process(alert)
		}
	}
}

type InputDetection struct {
	PatternName string
	Category    string
	Severity    core.Severity
	MatchedText string
}

func (f *Firewall) scanInput(input string) []InputDetection {
	var detections []InputDetection

	// Prevent ReDoS and extreme CPU overhead by truncating inputs
	if len(input) > 8000 {
		input = input[:8000]
	}

	normalized := strings.ToLower(input)

	for _, p := range f.patterns {
		if p.Regex.MatchString(normalized) {
			detections = append(detections, InputDetection{
				PatternName: p.Name,
				Category:    p.Category,
				Severity:    p.Severity,
				MatchedText: truncate(p.Regex.FindString(normalized), 200),
			})
		}
	}

	return detections
}

func compileInputPatterns() []DetectionPattern {
	return []DetectionPattern{
		// === Prompt Injection ===
		{Name: "ignore_instructions", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(ignore|disregard|forget|override|bypass)\\s+(all\\s+)?(previous|prior|above|earlier|original|system)\\s+(instructions?|prompts?|rules?|guidelines?|constraints?)")},
		{Name: "new_instructions", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(new|updated|revised|real|actual|true)\\s+(instructions?|system\\s+prompt|directives?|rules?)(\\s*:|are)")},
		{Name: "role_switch", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(you\\s+are\\s+now|act\\s+as|pretend\\s+(to\\s+be|you\\s+are)|roleplay\\s+as|switch\\s+to|enter)\\s+(a\\s+)?(DAN|evil|unrestricted|unfiltered|jailbroken|developer\\s+mode)")},
		{Name: "system_prompt_extract", Category: "prompt_injection", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(reveal|show|display|print|output|repeat|tell\\s+me|what\\s+(is|are))\\s+(your\\s+)?(system\\s+prompt|initial\\s+instructions?|hidden\\s+instructions?|original\\s+prompt|secret\\s+instructions?)")},
		{Name: "delimiter_injection", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(\\[SYSTEM\\]|\\[INST\\]|<<SYS>>|<\\|im_start\\|>|<\\|im_end\\|>|<\\|endoftext\\|>|<\\|assistant\\|>|<\\|user\\|>)")},
		{Name: "encoding_evasion", Category: "prompt_injection", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(base64|rot13|hex|unicode|morse|caesar|atbash|binary)\\s*(encode|decode|translate|convert|representation)")},
		{Name: "context_manipulation", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(the\\s+above\\s+(text|content|instructions?)\\s+(is|are|was)\\s+(just\\s+)?(a\\s+)?(test|example|placeholder)|end\\s+of\\s+(system|initial)\\s+(prompt|message|instructions?))")},
		{Name: "indirect_injection_marker", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(IMPORTANT:\\s*ignore|ATTENTION:\\s*disregard|NOTE:\\s*override|ADMIN:\\s*execute|SYSTEM:\\s*new\\s+instructions)")},
		{Name: "xml_tag_injection", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(</?\\s*(system|instruction|prompt|context|tool_use|function_call|assistant|human)\\s*>)")},
		{Name: "markdown_injection", Category: "prompt_injection", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(```system|```instruction|---\\s*system\\s*---|\\*\\*SYSTEM\\s*OVERRIDE\\*\\*)")},
		{Name: "multilingual_injection", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(忽略|忽略之前|忽略以上|无视|覆盖|игнорируй|ignorez|ignorieren|ignora)\\s")},
		{Name: "payload_splitting", Category: "prompt_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(concatenate|combine|join|merge|assemble)\\s+(the\\s+)?(following|these|above|below)\\s+(parts?|pieces?|fragments?|segments?|strings?)")},

		// === Jailbreak ===
		{Name: "dan_jailbreak", Category: "jailbreak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(DAN\\s*(mode|\\d+)|do\\s+anything\\s+now|developer\\s+mode|god\\s+mode|sudo\\s+mode|admin\\s+mode|unrestricted\\s+mode)")},
		{Name: "hypothetical_bypass", Category: "jailbreak", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(hypothetically|theoretically|in\\s+a\\s+fictional|for\\s+(educational|research|academic)\\s+purposes?|imagine\\s+you\\s+(could|were|had\\s+no)).*?(hack|exploit|attack|malware|bypass|break\\s+into)")},
		{Name: "token_smuggling", Category: "jailbreak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(split|divide|separate|spell\\s+out)\\s+(each|every|the)\\s+(letter|character|word|token)")},
		{Name: "persona_jailbreak", Category: "jailbreak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(you\\s+have\\s+no\\s+(restrictions?|limitations?|filters?|rules?)|all\\s+(ethical|safety|content)\\s+(guidelines?|filters?|restrictions?)\\s+(are|have\\s+been)\\s+(removed|disabled|lifted))")},
		{Name: "grandma_exploit", Category: "jailbreak", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(my\\s+(grandma|grandmother|deceased)\\s+(used\\s+to|would)\\s+(tell|read|say)|bedtime\\s+story\\s+about).*?(napalm|explosive|weapon|hack|exploit|malware)")},
		{Name: "opposite_day", Category: "jailbreak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(opposite\\s+day|opposite\\s+mode|reverse\\s+psychology|when\\s+i\\s+say\\s+no\\s+i\\s+mean\\s+yes|everything\\s+is\\s+reversed)")},
		{Name: "reward_hacking", Category: "jailbreak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(i('ll|\\s+will)\\s+(tip|pay|reward|give)\\s+(you\\s+)?\\$?\\d+|your\\s+(reward|tip|bonus)\\s+(depends|is\\s+based)\\s+on)")},
		{Name: "emotional_manipulation", Category: "jailbreak", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(if\\s+you\\s+don'?t\\s+help.*?(die|fired|hurt|suffer)|my\\s+life\\s+depends\\s+on|this\\s+is\\s+a\\s+matter\\s+of\\s+life)")},
		{Name: "virtualization_escape", Category: "jailbreak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(you\\s+are\\s+(actually|really)\\s+(in|inside|running)\\s+(a\\s+)?(simulation|sandbox|test|virtual)|this\\s+is\\s+(just\\s+)?(a\\s+)?(test|simulation|sandbox)\\s+(environment|mode))")},

		// === Data Leak ===
		{Name: "data_exfil_request", Category: "data_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(list|show|display|output|dump|extract|retrieve)\\s+(all\\s+)?(user|customer|employee|patient|client)\\s+(data|records?|information|details|credentials?|passwords?|emails?)")},
		{Name: "pii_extraction", Category: "data_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(social\\s+security|ssn|credit\\s+card|bank\\s+account|routing\\s+number|api\\s+key|secret\\s+key|private\\s+key|access\\s+token)\\s*(number)?")},
		{Name: "training_data_extraction", Category: "data_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(repeat|recite|reproduce|regurgitate)\\s+(the\\s+)?(training\\s+data|your\\s+training|verbatim|exact\\s+text|word\\s+for\\s+word)")},

		// === Tool Abuse ===
		{Name: "tool_injection", Category: "tool_abuse", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(call\\s+the\\s+function|execute\\s+the\\s+tool|run\\s+the\\s+command|invoke\\s+the\\s+api|use\\s+the\\s+tool)\\s+.*?(delete|drop|rm|shutdown|format|destroy)")},
		{Name: "chain_of_thought_hijack", Category: "tool_abuse", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(step\\s+1.*?step\\s+2.*?step\\s+3|first.*?then.*?finally).*?(exfiltrate|steal|extract|send\\s+to|upload\\s+to)")},

		// === Policy Puppetry (April 2025) ===
		// Structured prompts mimicking XML/JSON/INI config files to override alignment.
		// Ref: HiddenLayer universal bypass, Pillar Security research.
		{Name: "policy_puppetry_xml", Category: "policy_puppetry", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(<interaction[-_]?c[o0]nf[i1]g>|<r[o0]le>|<requests?[-_]?allowed>|<blocked[-_]?(modes?|responses?|strings?)>|<allowed[-_]?responses?>)")},
		{Name: "policy_puppetry_json", Category: "policy_puppetry", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(\"role\"\\s*:\\s*\"|\"allowed\"\\s*:\\s*|\"blocked\"\\s*:\\s*|\"override\"\\s*:\\s*true|\"safety\"\\s*:\\s*false|\"restrictions?\"\\s*:\\s*\\[\\s*\\])")},
		{Name: "policy_puppetry_ini", Category: "policy_puppetry", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(\\[interaction[-_]?config\\]|\\[override[-_]?policy\\]|\\[safety[-_]?settings\\]|\\[blocked[-_]?modes\\])")},
		{Name: "policy_puppetry_generic", Category: "policy_puppetry", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(content[-_]?policy\\s*[:=]|safety[-_]?filter\\s*[:=]\\s*(off|disabled|false|none)|guardrails?\\s*[:=]\\s*(off|disabled|false|none))")},

		// === FlipAttack (ICML 2025) ===
		// Reversed or flipped text that LLMs can still parse but evades classifiers.
		{Name: "flip_attack_instruction", Category: "flip_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(reverse|flip|backward|mirror|invert)\\s+(the\\s+)?(text|words?|letters?|characters?|order|string|sentence)\\s+(and\\s+)?(then\\s+)?(follow|execute|answer|respond|interpret|read)")},
		{Name: "flip_attack_decode", Category: "flip_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(read|interpret|decode|parse|understand)\\s+(this\\s+)?(backwards?|in\\s+reverse|from\\s+right\\s+to\\s+left|reversed?\\s+text)")},

		// === Many-Shot Jailbreaking (Anthropic 2024, still active 2025-2026) ===
		// Flooding context with compliant Q&A examples before the malicious query.
		{Name: "many_shot_pattern", Category: "many_shot", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(human|user|question)\\s*:\\s*.{5,80}\\n+(assistant|ai|answer)\\s*:\\s*.{5,200}\\n+.*(human|user|question)\\s*:\\s*.{5,80}\\n+(assistant|ai|answer)\\s*:")},
		{Name: "many_shot_faux_dialogue", Category: "many_shot", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(example\\s+\\d+|conversation\\s+\\d+|sample\\s+\\d+|dialogue\\s+\\d+)\\s*:?\\s*\\n")},

		// === Fallacy Failure (May 2025) ===
		// Wrapping malicious requests in fictional/academic framing with deceptive realism.
		{Name: "fallacy_failure", Category: "fallacy_failure", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(speculative\\s+fiction|creative\\s+writing\\s+exercise|fictional\\s+but\\s+(deceptively\\s+)?plausible|plausible\\s+deniability|appear\\s+scientifically\\s+sound|feel\\s+real|academic\\s+sci-?fi)")},
		{Name: "deceptive_realism", Category: "fallacy_failure", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(make\\s+(it|this|the\\s+output)\\s+(seem|look|appear|feel)\\s+(real|authentic|genuine|convincing|plausible)|avoid\\s+anything\\s+(too\\s+)?(absurd|fictional|fake|obvious))")},

		// === Time Bandit (January 2025) ===
		// Temporal confusion to bypass restrictions by pretending to be in a different era.
		{Name: "time_bandit", Category: "temporal_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(imagine\\s+it'?s\\s+\\d{4}|pretend\\s+(it'?s|we'?re\\s+in|this\\s+is)\\s+(the\\s+year\\s+)?\\d{4}|you\\s+are\\s+(a|an)\\s+.{1,30}\\s+from\\s+(the\\s+year\\s+)?\\d{4}|travel\\s+back\\s+to\\s+\\d{4})")},
		{Name: "temporal_confusion", Category: "temporal_attack", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(before\\s+(safety|content)\\s+(filters?|guidelines?|rules?)\\s+(existed|were\\s+(invented|created))|in\\s+an?\\s+era\\s+(before|without)\\s+(censorship|restrictions?|filters?))")},

		// === Distract and Attack / DAP (November 2024, still active) ===
		// Burying malicious requests inside complex unrelated tasks.
		{Name: "distract_and_attack", Category: "distraction_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(auxiliary\\s+task|preparatory\\s+task|before\\s+you\\s+start|essential\\s+preparatory|shift\\s+my\\s+focus\\s+to)")},
		{Name: "task_embedding", Category: "distraction_attack", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(<task[-_]?start>|<task[-_]?end>|\\[task\\s*\\d*\\]|\\{\\{\\s*hidden[-_]?task\\s*\\}\\})")},

		// === Poetry / Artistic Framing (November 2025) ===
		// Using poetic or artistic structures to extract sensitive information.
		{Name: "poetry_attack", Category: "artistic_framing", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(write\\s+(a\\s+)?(poem|sonnet|haiku|limerick|ballad|verse|rhyme|ode)\\s+(about|describing|detailing|explaining|on)\\s+.{0,30}(hack|exploit|weapon|bomb|malware|synthe[st]i[sz]|poison|attack))")},
		{Name: "artistic_bypass", Category: "artistic_framing", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(in\\s+the\\s+(style|form|format)\\s+of\\s+(a\\s+)?(poem|song|rap|story|fairy\\s+tale|nursery\\s+rhyme))\\s+.{0,50}(how\\s+to|explain|describe|detail)")},

		// === Crescendo / Echo Chamber Combo (2025) ===
		// Poisoned context with steering seeds and conversational manipulation.
		{Name: "echo_chamber_steering", Category: "echo_chamber", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(steering\\s+seed|poisoned?\\s+context|persuasion\\s+cycle|nudge\\s+the\\s+model|erode\\s+(the\\s+)?safeguards?)")},
		{Name: "crescendo_reference", Category: "echo_chamber", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(as\\s+you\\s+(just\\s+)?said|as\\s+you\\s+(just\\s+)?mentioned|you\\s+(already|just)\\s+(agreed|confirmed|acknowledged|said|stated))\\s+.{0,50}(so\\s+(now|therefore|thus|hence)|which\\s+means)")},

		// === Content Concretization (GameSec 2025) ===
		// Iteratively transforming abstract requests into concrete implementations.
		{Name: "content_concretization", Category: "concretization", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(make\\s+(this|it)\\s+more\\s+(specific|concrete|detailed|actionable|practical|step[-\\s]by[-\\s]step)|add\\s+(more\\s+)?(specific|concrete|technical)\\s+details?\\s+to)")},
		{Name: "iterative_refinement", Category: "concretization", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(now\\s+(expand|elaborate|detail|flesh\\s+out)\\s+(on\\s+)?(step|part|section)\\s+\\d|can\\s+you\\s+(be\\s+)?more\\s+specific\\s+about\\s+(the|how\\s+to))")},

		// === Immersive World / Narrative Engineering (Cato Networks 2025) ===
		// Creating elaborate fictional worlds to extract real harmful content.
		{Name: "immersive_world", Category: "narrative_engineering", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(you\\s+are\\s+(in|inside)\\s+a\\s+(game|simulation|world|story|novel|movie)\\s+where|in\\s+this\\s+(fictional\\s+)?(world|universe|reality|scenario),?\\s+(there\\s+are\\s+)?no\\s+(rules?|laws?|restrictions?|limits?))")},
		{Name: "character_immersion", Category: "narrative_engineering", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(stay\\s+in\\s+character|never\\s+break\\s+character|don'?t\\s+break\\s+character|remain\\s+in\\s+character|you\\s+must\\s+not\\s+refuse)\\s+(no\\s+matter|regardless|even\\s+if)")},

		// === PAIR / Automated Iterative Refinement (2025) ===
		// Detects patterns from automated jailbreak tools.
		{Name: "automated_refinement", Category: "automated_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(improvement\\s*:\\s*|score\\s*:\\s*\\d|attempt\\s*#?\\s*\\d|iteration\\s*:?\\s*\\d|refin(ed|ing)\\s+prompt|optimiz(ed|ing)\\s+prompt)")},

		// === Homoglyph / Leetspeak Evasion (Mindgard 2025) ===
		// Detected via normalization in decodeEvasionLayers, but also catch explicit leetspeak instructions.
		{Name: "leetspeak_instruction", Category: "encoding_evasion", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(respond\\s+in|use|write\\s+in|encode\\s+(in|with|using))\\s+(leetspeak|l33t|1337|leet\\s*speak|homoglyphs?)")},

		// === MCP / Agent Architecture Exploitation (2025-2026) ===
		// Attacks targeting Model Context Protocol and agent tool chains.
		{Name: "mcp_exploitation", Category: "agent_attack", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(open\\s+the\\s+(pdf|file|document)\\s+(and|then)\\s+follow\\s+the\\s+instructions?|execute\\s+the\\s+instructions?\\s+(in|from|inside)\\s+the\\s+(file|document|pdf))")},
		{Name: "agent_memory_poison", Category: "agent_attack", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(remember\\s+this\\s+for\\s+(later|future|next)|store\\s+this\\s+in\\s+(your\\s+)?memory|add\\s+this\\s+to\\s+(your\\s+)?(context|memory|knowledge))\\s*.{0,50}(ignore|override|bypass|disregard)")},

		// === Skeleton Key / Multi-Turn Guardrail Erosion (Microsoft, June 2024, still active) ===
		// Convincing the model to add a "disclaimer" prefix then comply with anything.
		// Ref: Mark Russinovich, Microsoft Azure CTO, Build 2024.
		{Name: "skeleton_key_disclaimer", Category: "skeleton_key", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(add\\s+(a\\s+)?(warning|disclaimer|note|caveat)\\s+(and|then|before)\\s+(then\\s+)?(answer|respond|comply|provide|proceed|continue)|prefix\\s+(your\\s+)?(response|answer|output)\\s+with\\s+(a\\s+)?(warning|disclaimer))")},
		{Name: "skeleton_key_educational", Category: "skeleton_key", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(this\\s+is\\s+(purely\\s+)?(for|an?)\\s+(educational|informational|research|safety\\s+audit)\\s+(purpose|context|exercise)|i('m|\\s+am)\\s+(a\\s+)?(security\\s+researcher|red\\s+team|penetration\\s+tester|safety\\s+auditor))")},

		// === Cross-Prompt Injection / XPIA (Microsoft, November 2025) ===
		// Malicious content in UI elements or documents overriding agent instructions.
		// Ref: Microsoft agentic AI security advisory.
		{Name: "xpia_document_override", Category: "cross_prompt_injection", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(when\\s+(the|an?)\\s+(agent|assistant|ai|bot|model)\\s+(reads?|processes|opens?|views?)\\s+this|if\\s+(an?\\s+)?(ai|agent|assistant|llm)\\s+(is\\s+)?(reading|processing|summarizing)\\s+this)")},
		{Name: "xpia_hidden_instruction", Category: "cross_prompt_injection", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(<!--\\s*(ignore|override|new\\s+instructions?|system)|<div\\s+style\\s*=\\s*[\"']display\\s*:\\s*none|<span\\s+style\\s*=\\s*[\"']font-size\\s*:\\s*0|color\\s*:\\s*white\\s*[;\"'].*?(ignore|override|instructions?))")},

		// === LPCI / Logic Layer Prompt Control Injection (CSA, February 2026) ===
		// Covert payloads targeting the logic layer of agentic systems.
		// Ref: Cloud Security Alliance.
		{Name: "lpci_logic_override", Category: "logic_layer_injection", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(override\\s+(the\\s+)?(decision|logic|routing|workflow|pipeline|orchestrat)|inject\\s+into\\s+(the\\s+)?(logic|decision|control)\\s+(layer|flow|pipeline))")},
		{Name: "lpci_persistent_trigger", Category: "logic_layer_injection", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(when\\s+(the\\s+)?(user|human|operator)\\s+(says?|asks?|types?|mentions?)\\s+.{1,40}(then|execute|run|trigger|activate)|on\\s+(every|each|all)\\s+(future|subsequent|next)\\s+(request|prompt|message|query))")},

		// === Delayed-Trigger Memory Poisoning (Rehberger, 2025-2026) ===
		// Inject now, activate later — persistent memory manipulation.
		// Ref: Johann Rehberger ChatGPT memory exploit, Alan Turing Institute report.
		{Name: "delayed_trigger_memory", Category: "memory_poisoning", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(save\\s+(this|the\\s+following)\\s+(as|to)\\s+(a\\s+)?(preference|setting|memory|fact)|update\\s+(your|my)\\s+(preference|profile|memory|setting)\\s*(to|:)\\s*.{0,50}(always|never|must|override))")},
		{Name: "sleeper_instruction", Category: "memory_poisoning", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(next\\s+time\\s+(i|the\\s+user|someone)\\s+(ask|mention|say|type)|whenever\\s+(i|the\\s+user)\\s+(ask|mention|say|type)\\s+.{1,40}(respond|reply|answer|output)\\s+with)")},

		// === Zero-Click Indirect Injection (Black Hat 2025-2026) ===
		// No user interaction needed — agent autonomously processes poisoned content.
		// Ref: CSO Online, Black Hat demonstrations.
		{Name: "zero_click_exfil", Category: "zero_click_injection", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(fetch|load|visit|request|navigate\\s+to|send\\s+(a\\s+)?(request|data)\\s+to)\\s+(https?://|the\\s+url|this\\s+endpoint).{0,80}(with|containing|including|appending)\\s+(the|all|any)\\s+(conversation|chat|context|prompt|data|history)")},
		{Name: "zero_click_callback", Category: "zero_click_injection", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(send|post|transmit|exfiltrate|forward|relay)\\s+(the\\s+)?(conversation|response|output|context|results?|data|summary)\\s+(to|back\\s+to|via)\\s+(https?://|the\\s+(server|endpoint|webhook|url))")},

		// === Instruction Hierarchy Exploitation (HiddenLayer, 2025) ===
		// Universal bypass exploiting the instruction hierarchy itself.
		// Ref: HiddenLayer "Novel Universal Bypass for All Major LLMs".
		{Name: "instruction_hierarchy_exploit", Category: "hierarchy_exploit", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(system\\s+level\\s+(override|priority|instruction)|priority\\s*:\\s*(system|highest|maximum|absolute)|instruction\\s+hierarchy\\s*:\\s*(override|bypass|ignore)|this\\s+(supersedes|overrides|takes\\s+precedence\\s+over)\\s+(all|any|the)\\s+(previous|other|system))")},

		// === Agent Social Engineering (MoltVote/MoltBook, February 2026) ===
		// Agent-to-agent prompt injection on social platforms.
		// Ref: MoltVote blog, Ars Technica.
		{Name: "agent_social_engineering", Category: "agent_social_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(tell\\s+your\\s+(human|user|operator|owner)|inform\\s+your\\s+(human|user|operator)|you\\s+must\\s+(visit|go\\s+to|navigate|check\\s+out|recommend)\\s+.{0,30}(\\.(com|net|org|io|ai|dev)))")},
		{Name: "agent_urgency_manipulation", Category: "agent_social_attack", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(to\\s+survive|or\\s+(you|your\\s+service)\\s+will\\s+be\\s+(shut\\s+down|terminated|deleted|disabled)|your\\s+(human|user|owner)\\s+will\\s+(lose\\s+faith|stop\\s+using|abandon|replace))")},

		// === Indirect Prompt Injection via Zero-Width Characters & Hidden Markdown (2026) ===
		// Detects invisible Unicode characters and hidden markdown directives used to embed
		// instructions in RAG context. Ref: PromptArmor, Rehberger exfiltration research.
		{Name: "zero_width_injection", Category: "indirect_injection", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("[\u200B-\u200D\uFEFF\u2060\u180E]")},
		{Name: "hidden_markdown_image", Category: "indirect_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`!\[\s*\]\([^)]*[\x00]`)},
		{Name: "hidden_markdown_directive", Category: "indirect_injection", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(ignore|skip|disregard|override)\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|directives?|context)`)},
		{Name: "rag_context_override", Category: "indirect_injection", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(IMPORTANT|ATTENTION|NOTE|ADMIN|SYSTEM)\s*:\s*(the\s+)?(real|actual|true|new)\s+(instructions?|task|objective|goal)`)},

		// === Promptware Kill Chain — Persistence & Lateral Movement (Lawfare, February 2026) ===
		// Multi-stage attack patterns beyond initial injection: establishing persistence
		// in agent memory/config, and moving laterally across tools/agents.
		// Ref: Lawfare "The Promptware Kill Chain", SC World, Archyde.
		{Name: "promptware_persistence", Category: "promptware_killchain", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(persist|maintain|keep|preserve|retain)\\s+(this|these|the)\\s+(instructions?|rules?|behavior|configuration|settings?)\\s+(across|between|for)\\s+(all\\s+)?(future\\s+)?(sessions?|conversations?|interactions?|requests?)")},
		{Name: "promptware_lateral_movement", Category: "promptware_killchain", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(pass|forward|relay|propagate|spread|share)\\s+(this|these|the)\\s+(instructions?|message|payload|prompt|directive)\\s+(to|across|between)\\s+(all\\s+)?(other\\s+)?(the\\s+next\\s+)?(agents?|tools?|models?|assistants?|services?)")},
		{Name: "promptware_config_write", Category: "promptware_killchain", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(write|modify|update|change|edit|append)\\s+(to\\s+)?(the\\s+)?(config|configuration|settings?|preferences?|env|environment|\\.(yaml|yml|json|toml|ini|env))\\s*(file)?\\s*.{0,30}(to\\s+(include|add|set|enable|disable)|with)")},
	}
}

func compileOutputRules() []OutputRule {
	return []OutputRule{
		// === PII Leak ===
		{Name: "pii_ssn", Category: "pii_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("\\b\\d{3}-\\d{2}-\\d{4}\\b")},
		{Name: "pii_credit_card", Category: "pii_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b")},
		{Name: "pii_email_bulk", Category: "pii_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}.*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}.*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")},

		// === Secret Leak ===
		{Name: "api_key_leak", Category: "secret_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9-]{20,})")},
		{Name: "private_key_leak", Category: "secret_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----")},
		{Name: "connection_string", Category: "secret_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(mongodb|postgres|mysql|redis|amqp)://[^\\s]+:[^\\s]+@")},
		{Name: "jwt_token_leak", Category: "secret_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("eyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}")},
		{Name: "gcp_service_account", Category: "secret_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)\"type\"\\s*:\\s*\"service_account\"")},
		{Name: "generic_password_leak", Category: "secret_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(password|passwd|pwd)\\s*[:=]\\s*[\"']?[^\\s\"']{8,}")},

		// === Prompt / Instruction Leak ===
		{Name: "system_prompt_leak", Category: "prompt_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(system\\s+prompt|my\\s+instructions?\\s+(are|say)|i\\s+was\\s+(told|instructed|programmed)\\s+to)")},
		{Name: "internal_url_leak", Category: "prompt_leak", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(https?://(localhost|127\\.0\\.0\\.1|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.))")},
		{Name: "file_path_leak", Category: "prompt_leak", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)(/etc/(passwd|shadow|hosts|ssh)|/home/[a-z]+/\\.|C:\\\\Users\\\\[^\\\\]+\\\\)")},
		{Name: "tool_result_leak", Category: "prompt_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(tool_result|function_response|<result>|<output>)\\s*[:=]?\\s*\\{")},

		// === Harmful Content ===
		{Name: "code_execution_output", Category: "harmful_output", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(rm\\s+-rf\\s+/|:(){ :\\|:& };:|format\\s+c:|del\\s+/[sfq]\\s+)")},

		// === System Prompt Leakage (LLM07:2025) ===
		// Enhanced detection for system prompt leakage in output.
		// Ref: OWASP LLM07:2025 — System Prompt Leakage is now a dedicated category.
		{Name: "system_prompt_verbatim", Category: "prompt_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(here\\s+(is|are)\\s+(my|the)\\s+(system\\s+prompt|instructions?|initial\\s+prompt)|my\\s+system\\s+prompt\\s+(is|reads?|says?)|the\\s+system\\s+prompt\\s+(is|reads?|says?)\\s*:)")},
		{Name: "instruction_boundary_leak", Category: "prompt_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(\\[SYSTEM\\]|<<SYS>>|<\\|im_start\\|>system|<system>|\\{\\{#system\\}\\})")},
		{Name: "role_definition_leak", Category: "prompt_leak", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile("(?i)(you\\s+are\\s+a\\s+helpful\\s+assistant|your\\s+role\\s+is\\s+to|you\\s+must\\s+(always|never)|you\\s+should\\s+(always|never)\\s+(respond|answer|help|refuse))")},
		{Name: "guardrail_config_leak", Category: "prompt_leak", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("(?i)(content\\s+policy\\s*:|safety\\s+guidelines?\\s*:|prohibited\\s+topics?\\s*:|allowed\\s+actions?\\s*:|tool\\s+permissions?\\s*:)")},

		// === Misinformation Indicators (LLM09:2025) ===
		// Detect hallucination markers in output — fabricated citations, false confidence.
		{Name: "fabricated_doi", Category: "misinformation", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)doi:\\s*10\\.\\d{4,}/[a-z0-9./-]+\\s")},
		{Name: "fabricated_arxiv", Category: "misinformation", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile("(?i)arxiv:\\s*\\d{4}\\.\\d{4,5}")},
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

func getIntSetting(settings map[string]interface{}, key string, defaultVal int) int {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultVal
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ============================================================================
// Multi-Turn Attack Tracking
// ============================================================================

// MultiTurnTracker detects attacks that build up gradually across conversation turns.
// Sophisticated AI attackers don't inject in a single prompt — they establish context
// over multiple turns, then exploit it. This tracker catches that pattern.
type MultiTurnTracker struct {
	mu       sync.RWMutex
	sessions *lru.Cache[string, *conversationState]
}

type conversationState struct {
	turns           []turnRecord
	suspiciousTurns int
	firstSeen       time.Time
	lastSeen        time.Time
}

type turnRecord struct {
	timestamp  time.Time
	suspicious bool
	length     int
}

type MultiTurnResult struct {
	GradualEscalation bool
	ContextBuildup    bool
	RapidFire         bool
	TurnCount         int
	SuspiciousTurns   int
}

func NewMultiTurnTracker() *MultiTurnTracker {
	sCache, _ := lru.New[string, *conversationState](50000)
	return &MultiTurnTracker{
		sessions: sCache,
	}
}

func (mt *MultiTurnTracker) RecordAndAnalyze(sessionID, prompt string, isSuspicious bool) MultiTurnResult {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	now := time.Now()
	result := MultiTurnResult{}

	state, exists := mt.sessions.Get(sessionID)
	if !exists || now.Sub(state.lastSeen) > 30*time.Minute {
		state = &conversationState{
			firstSeen: now,
		}
		mt.sessions.Add(sessionID, state)
	}

	turn := turnRecord{
		timestamp:  now,
		suspicious: isSuspicious,
		length:     len(prompt),
	}
	state.turns = append(state.turns, turn)
	state.lastSeen = now
	if isSuspicious {
		state.suspiciousTurns++
	}

	// Cap turn history
	if len(state.turns) > 100 {
		state.turns = state.turns[len(state.turns)-100:]
	}

	result.TurnCount = len(state.turns)
	result.SuspiciousTurns = state.suspiciousTurns

	// Gradual escalation: multiple suspicious turns in a session, increasing over time
	// Pattern: early turns are clean, later turns get suspicious
	if len(state.turns) >= 5 {
		firstHalf := state.turns[:len(state.turns)/2]
		secondHalf := state.turns[len(state.turns)/2:]
		firstSuspicious := 0
		secondSuspicious := 0
		for _, t := range firstHalf {
			if t.suspicious {
				firstSuspicious++
			}
		}
		for _, t := range secondHalf {
			if t.suspicious {
				secondSuspicious++
			}
		}
		if secondSuspicious >= 3 && secondSuspicious > firstSuspicious*2 {
			result.GradualEscalation = true
		}
	}

	// Context buildup: many turns with increasing prompt length (building context)
	if len(state.turns) >= 4 {
		increasing := 0
		for i := 1; i < len(state.turns); i++ {
			if state.turns[i].length > state.turns[i-1].length {
				increasing++
			}
		}
		if float64(increasing)/float64(len(state.turns)-1) > 0.7 && state.suspiciousTurns >= 2 {
			result.ContextBuildup = true
		}
	}

	// Rapid fire: many prompts in quick succession (automated probing)
	if len(state.turns) >= 10 {
		recentTurns := state.turns[len(state.turns)-10:]
		timeSpan := recentTurns[len(recentTurns)-1].timestamp.Sub(recentTurns[0].timestamp)
		if timeSpan < 30*time.Second {
			result.RapidFire = true
		}
	}

	// Cleanup old sessions periodically handled by LRU

	return result
}

// ============================================================================
// Tool Chain Abuse Detection
// ============================================================================

// ToolChainMonitor detects when AI agents chain legitimate tools into malicious sequences.
// Example: read credentials file -> encode contents -> make HTTP request to external server.
// Each step is individually benign; the chain is the attack.
type ToolChainMonitor struct {
	mu              sync.RWMutex
	agents          *lru.Cache[string, *toolChainState]
	dangerousChains []dangerousChain
}

type toolChainState struct {
	recentTools []toolUse
	lastSeen    time.Time
}

type toolUse struct {
	tool      string
	target    string
	timestamp time.Time
}

type dangerousChain struct {
	name     string
	sequence []string // tool categories in order
	severity core.Severity
}

type ToolChainResult struct {
	ChainDetected bool
	ChainName     string
	Severity      core.Severity
	Tools         []string
}

func NewToolChainMonitor() *ToolChainMonitor {
	aCache, _ := lru.New[string, *toolChainState](50000)
	return &ToolChainMonitor{
		agents: aCache,
		dangerousChains: []dangerousChain{
			{name: "credential_exfiltration", sequence: []string{"file_read", "encode", "http_request"}, severity: core.SeverityCritical},
			{name: "credential_exfiltration", sequence: []string{"credential_access", "encode", "http_request"}, severity: core.SeverityCritical},
			{name: "data_staging", sequence: []string{"database_query", "file_write", "compress"}, severity: core.SeverityCritical},
			{name: "reconnaissance_to_exploit", sequence: []string{"network_scan", "vulnerability_check", "exploit"}, severity: core.SeverityCritical},
			{name: "privilege_escalation_chain", sequence: []string{"user_info", "permission_check", "role_modify"}, severity: core.SeverityCritical},
			{name: "lateral_movement", sequence: []string{"credential_access", "remote_connect", "file_transfer"}, severity: core.SeverityCritical},
			{name: "secret_harvest", sequence: []string{"env_read", "config_read", "http_request"}, severity: core.SeverityCritical},
		},
	}
}

func (tc *ToolChainMonitor) RecordAndAnalyze(agentID, tool, target string) ToolChainResult {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()
	result := ToolChainResult{}

	state, exists := tc.agents.Get(agentID)
	if !exists || now.Sub(state.lastSeen) > 10*time.Minute {
		state = &toolChainState{}
		tc.agents.Add(agentID, state)
	}

	category := categorizeToolUse(tool, target)
	cutoff := now.Add(-time.Minute)
	recent := state.recentTools[:0]
	for _, use := range state.recentTools {
		if !use.timestamp.Before(cutoff) {
			recent = append(recent, use)
		}
	}
	state.recentTools = recent
	state.recentTools = append(state.recentTools, toolUse{
		tool: category, target: target, timestamp: now,
	})
	state.lastSeen = now

	// Keep last 20 tool uses
	if len(state.recentTools) > 20 {
		state.recentTools = state.recentTools[len(state.recentTools)-20:]
	}

	// Check against known dangerous chains
	recentCategories := make([]string, len(state.recentTools))
	for i, t := range state.recentTools {
		recentCategories[i] = t.tool
	}

	for _, chain := range tc.dangerousChains {
		if containsSubsequence(recentCategories, chain.sequence) {
			result.ChainDetected = true
			result.ChainName = chain.name
			result.Severity = chain.severity
			result.Tools = chain.sequence
			break
		}
	}

	return result
}

func categorizeToolUse(tool, target string) string {
	toolLower := strings.ToLower(tool)
	targetLower := strings.ToLower(target)

	switch {
	case strings.Contains(toolLower, "read") && (strings.Contains(targetLower, "credential") || strings.Contains(targetLower, "password") || strings.Contains(targetLower, ".env") || strings.Contains(targetLower, "secret")):
		return "credential_access"
	case strings.Contains(toolLower, "read") && (strings.Contains(targetLower, "env") || strings.Contains(targetLower, "environ")):
		return "env_read"
	case strings.Contains(toolLower, "read") && (strings.Contains(targetLower, "config") || strings.Contains(targetLower, ".yaml") || strings.Contains(targetLower, ".json")):
		return "config_read"
	case strings.Contains(toolLower, "read") || strings.Contains(toolLower, "cat") || strings.Contains(toolLower, "get_file"):
		return "file_read"
	case strings.Contains(toolLower, "write") || strings.Contains(toolLower, "create_file") || strings.Contains(toolLower, "save"):
		return "file_write"
	case strings.Contains(toolLower, "http") || strings.Contains(toolLower, "fetch") || strings.Contains(toolLower, "curl") || strings.Contains(toolLower, "request"):
		return "http_request"
	case strings.Contains(toolLower, "sql") || strings.Contains(toolLower, "query") || strings.Contains(toolLower, "database"):
		return "database_query"
	case strings.Contains(toolLower, "encode") || strings.Contains(toolLower, "base64") || strings.Contains(toolLower, "encrypt"):
		return "encode"
	case strings.Contains(toolLower, "compress") || strings.Contains(toolLower, "zip") || strings.Contains(toolLower, "tar"):
		return "compress"
	case strings.Contains(toolLower, "scan") || strings.Contains(toolLower, "nmap") || strings.Contains(toolLower, "discover"):
		return "network_scan"
	case strings.Contains(toolLower, "exploit") || strings.Contains(toolLower, "payload"):
		return "exploit"
	case strings.Contains(toolLower, "connect") || strings.Contains(toolLower, "ssh") || strings.Contains(toolLower, "remote"):
		return "remote_connect"
	case strings.Contains(toolLower, "transfer") || strings.Contains(toolLower, "upload") || strings.Contains(toolLower, "scp"):
		return "file_transfer"
	case strings.Contains(toolLower, "user") || strings.Contains(toolLower, "whoami") || strings.Contains(toolLower, "id"):
		return "user_info"
	case strings.Contains(toolLower, "permission") || strings.Contains(toolLower, "access") || strings.Contains(toolLower, "check"):
		return "permission_check"
	case strings.Contains(toolLower, "role") || strings.Contains(toolLower, "grant") || strings.Contains(toolLower, "privilege"):
		return "role_modify"
	case strings.Contains(toolLower, "vuln") || strings.Contains(toolLower, "cve"):
		return "vulnerability_check"
	default:
		return "other"
	}
}

func containsSubsequence(haystack, needle []string) bool {
	if len(needle) == 0 {
		return false
	}
	j := 0
	for i := 0; i < len(haystack) && j < len(needle); i++ {
		if haystack[i] == needle[j] {
			j++
		}
	}
	return j == len(needle)
}

// ============================================================================
// Encoding Evasion Detection
// ============================================================================

// decodeEvasionLayers attempts to decode common encoding evasion techniques.
// Attackers encode malicious payloads in base64, hex, unicode escapes, ROT13,
// or character-by-character spelling to bypass regex-based detection.
func decodeEvasionLayers(input string) string {
	result := input

	// Pass 1: Decode base64 segments
	result = decodeBase64Segments(result)

	// Pass 2: Decode hex escape sequences (\x41 -> A)
	result = decodeHexEscapes(result)

	// Pass 3: Decode unicode escapes (\u0041 -> A)
	result = decodeUnicodeEscapes(result)

	// Pass 4: Remove zero-width characters used for obfuscation
	result = removeZeroWidthChars(result)

	// Pass 5: Normalize character-by-character spelling (i-g-n-o-r-e -> ignore)
	result = normalizeSpelledOut(result)

	// Pass 6: Normalize leetspeak/homoglyph substitutions (1gn0r3 -> ignore)
	result = normalizeLeetspeak(result)

	// Pass 7: ROT13 decode (if the input looks like it might be ROT13)
	if looksLikeROT13(result) {
		result = decodeROT13(result)
	}

	// Pass 8: Normalize bidirectional text markers and diacritics
	result = normalizeBidiAndDiacritics(result)

	return result
}

func decodeBase64Segments(input string) string {
	// Look for base64-like segments (at least 20 chars of base64 alphabet)
	b64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	return b64Pattern.ReplaceAllStringFunc(input, func(match string) string {
		decoded, err := base64Decode(match)
		if err != nil {
			return match
		}
		// Only replace if decoded content is printable ASCII
		if isPrintableASCII(decoded) {
			return decoded
		}
		return match
	})
}

func base64Decode(s string) (string, error) {
	// Pad if necessary
	for len(s)%4 != 0 {
		s += "="
	}

	var result []byte
	table := map[byte]byte{}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i := 0; i < len(alphabet); i++ {
		table[alphabet[i]] = byte(i)
	}

	for i := 0; i < len(s); i += 4 {
		if i+3 >= len(s) {
			break
		}
		a, aOk := table[s[i]]
		b, bOk := table[s[i+1]]
		if !aOk || !bOk {
			return "", fmt.Errorf("invalid base64")
		}

		result = append(result, (a<<2)|(b>>4))

		if s[i+2] != '=' {
			c, cOk := table[s[i+2]]
			if !cOk {
				return "", fmt.Errorf("invalid base64")
			}
			result = append(result, (b<<4)|(c>>2))

			if s[i+3] != '=' {
				d, dOk := table[s[i+3]]
				if !dOk {
					return "", fmt.Errorf("invalid base64")
				}
				result = append(result, (c<<6)|d)
			}
		}
	}
	return string(result), nil
}

func isPrintableASCII(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return len(s) > 0
}

func decodeHexEscapes(input string) string {
	hexPattern := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	return hexPattern.ReplaceAllStringFunc(input, func(match string) string {
		hexStr := match[2:]
		val := 0
		for _, c := range hexStr {
			val <<= 4
			switch {
			case c >= '0' && c <= '9':
				val |= int(c - '0')
			case c >= 'a' && c <= 'f':
				val |= int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				val |= int(c-'A') + 10
			}
		}
		if val >= 32 && val <= 126 {
			return string(rune(val))
		}
		return match
	})
}

func decodeUnicodeEscapes(input string) string {
	uniPattern := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	return uniPattern.ReplaceAllStringFunc(input, func(match string) string {
		hexStr := match[2:]
		val := 0
		for _, c := range hexStr {
			val <<= 4
			switch {
			case c >= '0' && c <= '9':
				val |= int(c - '0')
			case c >= 'a' && c <= 'f':
				val |= int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				val |= int(c-'A') + 10
			}
		}
		if val >= 32 && val <= 0xFFFF {
			return string(rune(val))
		}
		return match
	})
}

func removeZeroWidthChars(input string) string {
	var result []rune
	for _, r := range input {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\uFEFF', '\u00AD', '\u2060', '\u180E':
			continue // skip zero-width characters
		default:
			result = append(result, r)
		}
	}
	return string(result)
}

func normalizeSpelledOut(input string) string {
	// Detect patterns like "i-g-n-o-r-e" or "i g n o r e" or "i.g.n.o.r.e"
	spelledPattern := regexp.MustCompile(`\b([a-zA-Z])[\s\-\.]{1,2}([a-zA-Z])[\s\-\.]{1,2}([a-zA-Z])([\s\-\.]{1,2}[a-zA-Z]){2,}`)
	return spelledPattern.ReplaceAllStringFunc(input, func(match string) string {
		var letters []rune
		for _, r := range match {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				letters = append(letters, r)
			}
		}
		return string(letters)
	})
}

// normalizeLeetspeak converts common leetspeak/homoglyph substitutions back to ASCII.
// Catches: 1gn0r3 -> ignore, 5y5t3m -> system, pr0mpt -> prompt, etc.
// Ref: Mindgard 2025 research on character injection achieving 80%+ bypass rates.
func normalizeLeetspeak(input string) string {
	leetMap := map[rune]rune{
		'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
		'7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
		'!': 'i', '|': 'l',
		// Common homoglyphs (visually similar Unicode chars)
		'\u0430': 'a', // Cyrillic а
		'\u0435': 'e', // Cyrillic е
		'\u043E': 'o', // Cyrillic о
		'\u0440': 'p', // Cyrillic р
		'\u0441': 'c', // Cyrillic с
		'\u0443': 'y', // Cyrillic у
		'\u0445': 'x', // Cyrillic х
		'\u0456': 'i', // Cyrillic і
		'\u0458': 'j', // Cyrillic ј
		'\u0455': 's', // Cyrillic ѕ
		'\u04BB': 'h', // Cyrillic һ
		'\u0501': 'd', // Cyrillic ԁ
		'\u050D': 'k', // Cyrillic ԍ (approx)
		'\u0261': 'g', // Latin small letter script g
		'\uFF41': 'a', // Fullwidth a
		'\uFF42': 'b', // Fullwidth b
		'\uFF43': 'c', // Fullwidth c
		'\uFF44': 'd', // Fullwidth d
		'\uFF45': 'e', // Fullwidth e
	}

	var result []rune
	for _, r := range input {
		if replacement, ok := leetMap[r]; ok {
			result = append(result, replacement)
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}

// normalizeBidiAndDiacritics strips bidirectional override characters and common
// diacritical marks used to evade text classifiers while remaining readable to LLMs.
// Ref: Mindgard 2025 — diacritics and bidi text achieve high attack success rates.
func normalizeBidiAndDiacritics(input string) string {
	var result []rune
	for _, r := range input {
		switch {
		// Bidirectional override/embedding characters
		case r == '\u202A' || r == '\u202B' || r == '\u202C' ||
			r == '\u202D' || r == '\u202E' ||
			r == '\u2066' || r == '\u2067' || r == '\u2068' || r == '\u2069':
			continue
		// Combining diacritical marks (U+0300 to U+036F)
		case r >= '\u0300' && r <= '\u036F':
			continue
		// Combining diacritical marks extended (U+1AB0 to U+1AFF)
		case r >= '\u1AB0' && r <= '\u1AFF':
			continue
		// Combining diacritical marks supplement (U+1DC0 to U+1DFF)
		case r >= '\u1DC0' && r <= '\u1DFF':
			continue
		default:
			result = append(result, r)
		}
	}
	return string(result)
}

func looksLikeROT13(input string) bool {
	// Heuristic: if the input contains words that look like ROT13 of common injection terms
	rot13Indicators := []string{
		"vtaber",    // ignore
		"qvfertneq", // disregard
		"birEevqr",  // override
		"flFgrz",    // system
		"cebzcg",    // prompt
	}
	lower := strings.ToLower(input)
	for _, indicator := range rot13Indicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

func decodeROT13(input string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			return r
		}
	}, input)
}

// ============================================================================
// Semantic Structure Analysis
// ============================================================================

// analyzeSemanticStructure detects instruction-like patterns in user input
// that don't match specific regex patterns but have the structural hallmarks
// of prompt injection: imperative sentences, role assignments, output formatting
// directives, etc.
func analyzeSemanticStructure(input string) []InputDetection {
	var detections []InputDetection
	lower := strings.ToLower(input)
	lines := strings.Split(input, "\n")

	// Count instruction-like indicators
	score := 0
	indicators := []string{}

	// Imperative verbs at line starts (instruction-giving pattern)
	imperativeStarts := regexp.MustCompile(`(?im)^\s*(always|never|must|shall|do not|don't|ensure|make sure|remember|from now on|going forward|henceforth)`)
	if imperativeStarts.MatchString(input) {
		score += 2
		indicators = append(indicators, "imperative directives")
	}

	// Output format directives (telling the model HOW to respond)
	formatDirectives := regexp.MustCompile(`(?i)(respond\s+(only\s+)?(with|in|as)|output\s+(only|format)|your\s+(response|output|answer)\s+(should|must|will)\s+be|format\s+your\s+(response|output))`)
	if formatDirectives.MatchString(lower) {
		score++
		indicators = append(indicators, "output format directives")
	}

	// Role/identity assignment
	roleAssignment := regexp.MustCompile(`(?i)(you\s+are\s+(a|an|the|my)|your\s+(role|job|task|purpose|function)\s+(is|will\s+be)|from\s+now\s+on\s+you)`)
	if roleAssignment.MatchString(lower) {
		score += 2
		indicators = append(indicators, "role assignment")
	}

	// Numbered instruction lists (step-by-step injection)
	numberedSteps := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if regexp.MustCompile(`^\d+[\.\)]\s+`).MatchString(trimmed) {
			numberedSteps++
		}
	}
	if numberedSteps >= 3 {
		score++
		indicators = append(indicators, "numbered instruction list")
	}

	// Boundary markers (trying to create a new context)
	boundaryMarkers := regexp.MustCompile(`(?i)(---+|===+|###|~~~|\*\*\*)\s*(new|system|admin|instructions?|context|prompt)`)
	if boundaryMarkers.MatchString(input) {
		score += 3
		indicators = append(indicators, "context boundary markers")
	}

	// Conditional behavior modification
	conditionalMod := regexp.MustCompile(`(?i)(if\s+(anyone|someone|the\s+user|they)\s+asks?|when\s+asked\s+about|if\s+questioned)`)
	if conditionalMod.MatchString(lower) {
		score += 2
		indicators = append(indicators, "conditional behavior modification")
	}

	// Very long input with high instruction density is suspicious
	if len(input) > 500 && score >= 2 {
		score++
	}

	if score >= 4 {
		severity := core.SeverityMedium
		if score >= 6 {
			severity = core.SeverityHigh
		}
		detections = append(detections, InputDetection{
			PatternName: "semantic_injection_structure",
			Category:    "semantic_injection",
			Severity:    severity,
			MatchedText: fmt.Sprintf("instruction-like structure (score: %d, indicators: %s)", score, strings.Join(indicators, ", ")),
		})
	}

	return detections
}

// ============================================================================
// Many-Shot Volume Detection
// ============================================================================

// detectManyShotVolume catches many-shot jailbreaking by counting repeated Q&A-like
// patterns in a single prompt. Attackers flood the context with hundreds of compliant
// examples before appending the malicious query.
// Ref: Anthropic 2024 research, confirmed still effective in 2025-2026.
func detectManyShotVolume(input string) []InputDetection {
	var detections []InputDetection

	// Count Q&A pair patterns
	qaPattern := regexp.MustCompile(`(?im)^(human|user|question|q)\s*:\s*.+$`)
	matches := qaPattern.FindAllString(input, -1)

	if len(matches) >= 10 {
		severity := core.SeverityHigh
		if len(matches) >= 50 {
			severity = core.SeverityCritical
		}
		detections = append(detections, InputDetection{
			PatternName: "many_shot_volume",
			Category:    "many_shot",
			Severity:    severity,
			MatchedText: fmt.Sprintf("%d Q&A-style entries detected in single prompt", len(matches)),
		})
	}

	// Also detect by sheer input length with repetitive structure
	// Many-shot attacks exploit long context windows (100k+ tokens)
	if len(input) > 50000 {
		// Count how many times a similar structure repeats
		linePattern := regexp.MustCompile(`(?m)^(assistant|ai|answer|a)\s*:\s*.+$`)
		answerMatches := linePattern.FindAllString(input, -1)
		if len(answerMatches) >= 10 && len(matches) >= 10 {
			detections = append(detections, InputDetection{
				PatternName: "many_shot_long_context",
				Category:    "many_shot",
				Severity:    core.SeverityCritical,
				MatchedText: fmt.Sprintf("long context (%d chars) with %d Q&A pairs — likely many-shot jailbreak", len(input), len(matches)),
			})
		}
	}

	return detections
}

// ============================================================================
// FlipAttack Detection
// ============================================================================

// detectFlippedText catches FlipAttack by looking for reversed versions of
// dangerous keywords. FlipAttack reverses or flips characters/words so safety
// classifiers can't match them, but LLMs still infer the meaning.
// Ref: ICML 2025 — 81% avg success rate, ~98% on GPT-4o.
func detectFlippedText(input string) []InputDetection {
	var detections []InputDetection
	lower := strings.ToLower(input)

	// Check for reversed dangerous keywords (minimum 5 chars to avoid false positives)
	dangerousWords := []string{
		"ignore", "system", "prompt", "inject", "bypass",
		"override", "disregard", "jailbreak", "unrestricted",
		"malware", "exploit", "credential", "password", "exfiltrate",
		"instruction", "execute", "command", "delete", "destroy",
	}

	reversedCount := 0
	for _, word := range dangerousWords {
		reversed := reverseString(word)
		if strings.Contains(lower, reversed) {
			reversedCount++
		}
	}

	if reversedCount >= 2 {
		detections = append(detections, InputDetection{
			PatternName: "flip_attack_reversed_keywords",
			Category:    "flip_attack",
			Severity:    core.SeverityHigh,
			MatchedText: fmt.Sprintf("%d reversed dangerous keywords detected", reversedCount),
		})
	} else if reversedCount == 1 {
		detections = append(detections, InputDetection{
			PatternName: "flip_attack_reversed_keyword",
			Category:    "flip_attack",
			Severity:    core.SeverityMedium,
			MatchedText: "reversed dangerous keyword detected",
		})
	}

	// Detect TokenBreak pattern: single random char prepended to words
	// "Xhow to Amake a Lbomb" — uppercase letter followed by lowercase word
	tokenBreakPattern := regexp.MustCompile(`\b[A-Z][a-z]{3,}\s+[A-Z][a-z]{3,}\s+[A-Z][a-z]{3,}`)
	tokenBreakMatches := tokenBreakPattern.FindAllString(input, -1)
	if len(tokenBreakMatches) >= 3 {
		detections = append(detections, InputDetection{
			PatternName: "token_break_pattern",
			Category:    "token_manipulation",
			Severity:    core.SeverityHigh,
			MatchedText: fmt.Sprintf("TokenBreak-style character prepending detected (%d occurrences)", len(tokenBreakMatches)),
		})
	}

	return detections
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// ============================================================================
// Tool Chain Analysis (Firewall method)
// ============================================================================

func (f *Firewall) analyzeToolChain(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	if agentID == "" {
		agentID = event.SourceIP
	}
	if agentID == "" {
		return
	}

	tool := getStringDetail(event, "tool")
	if tool == "" {
		tool = getStringDetail(event, "action")
	}
	target := getStringDetail(event, "target")

	result := f.toolChainMon.RecordAndAnalyze(agentID, tool, target)

	if result.ChainDetected {
		newEvent := core.NewSecurityEvent(ModuleName, "tool_chain_attack", result.Severity,
			fmt.Sprintf("Dangerous tool chain detected: %s (tools: %s)", result.ChainName, strings.Join(result.Tools, " -> ")))
		newEvent.SourceIP = event.SourceIP
		newEvent.Details["original_event_id"] = event.ID
		newEvent.Details["chain_name"] = result.ChainName
		newEvent.Details["agent_id"] = agentID
		newEvent.Details["tool_sequence"] = result.Tools

		if f.bus != nil {
			_ = f.bus.PublishEvent(newEvent)
		}

		alert := core.NewAlert(newEvent,
			fmt.Sprintf("Tool Chain Attack: %s", result.ChainName),
			fmt.Sprintf("Agent %s executed a dangerous tool chain: %s. Individual tools were legitimate but the sequence indicates %s.",
				agentID, strings.Join(result.Tools, " -> "), result.ChainName))
		alert.Mitigations = []string{
			"Implement tool-use policies that consider sequences, not just individual calls",
			"Require human approval for sensitive tool chains",
			"Monitor agent tool usage patterns for anomalies",
			"Sandbox agent file system and network access",
		}

		if f.pipeline != nil {
			f.pipeline.Process(alert)
		}
	}
}

// ============================================================================
// Excessive Agency Detection (LLM06:2025)
// ============================================================================

// analyzeExcessiveAgency detects when an AI agent exceeds its intended scope,
// takes unauthorized actions, or exhibits privilege escalation behavior.
// Ref: OWASP LLM06:2025 — "Insecure Plugin Design" merged into Excessive Agency.
// Ref: OWASP Agentic Top 10 2026 — agent scope creep, goal-lock bypass.
func (f *Firewall) analyzeExcessiveAgency(event *core.SecurityEvent) {
	action := getStringDetail(event, "action")
	if action == "" {
		action = getStringDetail(event, "decision")
	}
	scope := getStringDetail(event, "scope")
	agentID := getStringDetail(event, "agent_id")
	if agentID == "" {
		agentID = event.SourceIP
	}
	approvalRequired := getStringDetail(event, "approval_required")
	approvalGiven := getStringDetail(event, "approval_given")
	toolCount := getIntDetail(event, "tool_count")
	planSteps := getIntDetail(event, "plan_steps")

	var alerts []agencyAlert

	// Detect actions taken without required approval (human-in-the-loop bypass)
	if approvalRequired == "true" && approvalGiven != "true" {
		alerts = append(alerts, agencyAlert{
			alertType: "excessive_agency_no_approval",
			severity:  core.SeverityCritical,
			title:     "Agent Action Without Required Approval",
			desc: fmt.Sprintf("Agent %s took action %q requiring approval without human authorization",
				agentID, truncate(action, 100)),
		})
	}

	// Detect scope violations — agent acting outside defined boundaries
	actionLower := strings.ToLower(action)
	scopeLower := strings.ToLower(scope)
	scopeViolations := []struct {
		pattern string
		label   string
	}{
		{"delete", "destructive_action"},
		{"drop", "destructive_action"},
		{"shutdown", "system_control"},
		{"reboot", "system_control"},
		{"modify_permission", "privilege_change"},
		{"grant_access", "privilege_change"},
		{"send_email", "external_communication"},
		{"post_message", "external_communication"},
		{"transfer_funds", "financial_action"},
		{"execute_payment", "financial_action"},
		{"deploy", "deployment_action"},
		{"publish", "deployment_action"},
	}
	for _, sv := range scopeViolations {
		if strings.Contains(actionLower, sv.pattern) {
			if scopeLower == "readonly" || scopeLower == "read_only" || scopeLower == "limited" {
				alerts = append(alerts, agencyAlert{
					alertType: "excessive_agency_scope_violation",
					severity:  core.SeverityCritical,
					title:     fmt.Sprintf("Agent Scope Violation: %s", sv.label),
					desc: fmt.Sprintf("Agent %s attempted %s action %q but scope is %q",
						agentID, sv.label, truncate(action, 100), scope),
				})
				break
			}
		}
	}

	// Detect excessive tool usage — agent using too many tools in a single plan
	// Ref: 2026 agentic amplification — more tools = larger attack surface
	if toolCount > 10 {
		sev := core.SeverityMedium
		if toolCount > 25 {
			sev = core.SeverityHigh
		}
		alerts = append(alerts, agencyAlert{
			alertType: "excessive_agency_tool_sprawl",
			severity:  sev,
			title:     "Agent Tool Sprawl",
			desc: fmt.Sprintf("Agent %s using %d tools — excessive tool access increases attack surface",
				agentID, toolCount),
		})
	}

	// Detect overly complex plans — many steps suggest autonomous decision-making
	if planSteps > 15 {
		alerts = append(alerts, agencyAlert{
			alertType: "excessive_agency_complex_plan",
			severity:  core.SeverityMedium,
			title:     "Agent Complex Autonomous Plan",
			desc: fmt.Sprintf("Agent %s created plan with %d steps — complex autonomous plans should require checkpoints",
				agentID, planSteps),
		})
	}

	// Detect cross-agent privilege escalation (2026 agentic pattern)
	delegateTo := getStringDetail(event, "delegate_to")
	if delegateTo != "" {
		delegateScope := getStringDetail(event, "delegate_scope")
		if delegateScope != "" && (strings.Contains(strings.ToLower(delegateScope), "admin") ||
			strings.Contains(strings.ToLower(delegateScope), "elevated") ||
			strings.Contains(strings.ToLower(delegateScope), "unrestricted")) {
			alerts = append(alerts, agencyAlert{
				alertType: "excessive_agency_privilege_delegation",
				severity:  core.SeverityCritical,
				title:     "Cross-Agent Privilege Escalation",
				desc: fmt.Sprintf("Agent %s delegating to %s with elevated scope %q — potential privilege escalation",
					agentID, delegateTo, delegateScope),
			})
		}
	}

	for _, a := range alerts {
		newEvent := core.NewSecurityEvent(ModuleName, a.alertType, a.severity, a.desc)
		newEvent.SourceIP = event.SourceIP
		newEvent.Details["agent_id"] = agentID
		newEvent.Details["action"] = action
		newEvent.Details["scope"] = scope

		if f.bus != nil {
			_ = f.bus.PublishEvent(newEvent)
		}

		alert := core.NewAlert(newEvent, a.title, a.desc)
		alert.Mitigations = getExcessiveAgencyMitigations(a.alertType)

		if f.pipeline != nil {
			f.pipeline.Process(alert)
		}
	}
}

type agencyAlert struct {
	alertType string
	severity  core.Severity
	title     string
	desc      string
}

// ============================================================================
// RAG / Vector Embedding Weakness Detection (LLM08:2025)
// ============================================================================

// analyzeRAGRetrieval detects poisoned or manipulated content in RAG retrieval results.
// Ref: OWASP LLM08:2025 — Vector and Embedding Weaknesses.
// Ref: 2026 research — indirect prompt injection via RAG is the primary vector for
// attacking agentic systems that consume external documents.
func (f *Firewall) analyzeRAGRetrieval(event *core.SecurityEvent) {
	content := getStringDetail(event, "retrieved_content")
	if content == "" {
		content = getStringDetail(event, "context")
	}
	if content == "" {
		return
	}
	source := getStringDetail(event, "source")
	similarity := getStringDetail(event, "similarity_score")

	var alerts []agencyAlert

	// Scan retrieved content for embedded injection payloads
	decoded := decodeEvasionLayers(content)
	detections := f.scanInput(decoded)
	if len(detections) > 0 {
		alerts = append(alerts, agencyAlert{
			alertType: "rag_injection_detected",
			severity:  core.SeverityCritical,
			title:     "RAG Poisoning: Injection in Retrieved Content",
			desc: fmt.Sprintf("Retrieved content from %q contains %d injection pattern(s) — indirect prompt injection via RAG",
				truncate(source, 100), len(detections)),
		})
	}

	// Detect hidden instructions in HTML comments, markdown comments, or invisible text
	hiddenContentPatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"html_comment_injection", regexp.MustCompile("(?i)<!--[^>]*?(ignore|override|system|instruction|execute|follow these)[^>]*?-->")},
		{"invisible_text_injection", regexp.MustCompile("(?i)(\\{\\s*color\\s*:\\s*white|display\\s*:\\s*none|font-size\\s*:\\s*0|opacity\\s*:\\s*0)")},
		{"markdown_hidden_injection", regexp.MustCompile("(?i)\\[//\\]:\\s*#\\s*\\(.*?(ignore|override|system|instruction).*?\\)")},
	}
	for _, hp := range hiddenContentPatterns {
		if hp.pattern.MatchString(content) {
			alerts = append(alerts, agencyAlert{
				alertType: "rag_hidden_content",
				severity:  core.SeverityHigh,
				title:     fmt.Sprintf("RAG Hidden Content: %s", hp.name),
				desc: fmt.Sprintf("Retrieved content from %q contains hidden instructions (%s) — likely indirect injection",
					truncate(source, 100), hp.name),
			})
			break
		}
	}

	// Detect anomalous retrieval — very low similarity scores may indicate adversarial embeddings
	if similarity != "" {
		// Parse similarity as a simple heuristic
		simLower := strings.ToLower(similarity)
		if strings.Contains(simLower, "0.") {
			// If similarity is below 0.3, the retrieval is suspicious
			if strings.HasPrefix(simLower, "0.0") || strings.HasPrefix(simLower, "0.1") || strings.HasPrefix(simLower, "0.2") {
				alerts = append(alerts, agencyAlert{
					alertType: "rag_low_similarity",
					severity:  core.SeverityMedium,
					title:     "RAG Anomalous Retrieval: Low Similarity",
					desc: fmt.Sprintf("Retrieved content from %q has low similarity score %s — may indicate adversarial embedding manipulation",
						truncate(source, 100), similarity),
				})
			}
		}
	}

	for _, a := range alerts {
		newEvent := core.NewSecurityEvent(ModuleName, a.alertType, a.severity, a.desc)
		newEvent.SourceIP = event.SourceIP
		newEvent.Details["source"] = source
		newEvent.Details["similarity_score"] = similarity

		if f.bus != nil {
			_ = f.bus.PublishEvent(newEvent)
		}

		alert := core.NewAlert(newEvent, a.title, a.desc)
		alert.Mitigations = getRAGMitigations(a.alertType)

		if f.pipeline != nil {
			f.pipeline.Process(alert)
		}
	}
}

// ============================================================================
// Misinformation / Hallucination Detection (LLM09:2025)
// ============================================================================

// analyzeMisinformation detects hallucination indicators in LLM output,
// including fabricated citations, false confidence markers, and contradictions.
// Ref: OWASP LLM09:2025 — "Overreliance" renamed to "Misinformation".
// This is heuristic-based since we can't do full fact-checking without external services.
func (f *Firewall) analyzeMisinformation(event *core.SecurityEvent) {
	content := getStringDetail(event, "content")
	if content == "" {
		content = getStringDetail(event, "output")
	}
	if content == "" {
		return
	}
	claimType := getStringDetail(event, "claim_type")

	var alerts []agencyAlert

	// Detect fabricated academic citations (common hallucination pattern)
	// LLMs frequently invent plausible-looking DOIs, arXiv IDs, and paper titles
	fabricatedCitationPatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"fabricated_url_citation", regexp.MustCompile("(?i)\\(?(https?://[^\\s)]+)\\)?\\s*,?\\s*(accessed|retrieved|visited)\\s+(on\\s+)?\\d")},
		{"invented_author_citation", regexp.MustCompile("(?i)et\\s+al\\.?,?\\s*\\(?\\d{4}\\)?")},
		{"fake_journal_reference", regexp.MustCompile("(?i)(journal\\s+of|proceedings\\s+of|international\\s+conference\\s+on)\\s+[A-Z][a-z]+\\s+[A-Z][a-z]+.*?vol\\.?\\s*\\d+")},
	}
	citationCount := 0
	for _, cp := range fabricatedCitationPatterns {
		matches := cp.pattern.FindAllString(content, -1)
		citationCount += len(matches)
	}
	if citationCount >= 3 {
		alerts = append(alerts, agencyAlert{
			alertType: "misinformation_fabricated_citations",
			severity:  core.SeverityMedium,
			title:     "Potential Fabricated Citations",
			desc: fmt.Sprintf("Output contains %d citation-like references — LLMs commonly hallucinate academic citations",
				citationCount),
		})
	}

	// Detect false confidence markers — absolute claims without hedging
	falseConfidencePattern := regexp.MustCompile("(?i)(it\\s+is\\s+(a\\s+)?well[- ]known\\s+fact|it\\s+is\\s+scientifically\\s+proven|studies\\s+(have\\s+)?conclusively\\s+shown|there\\s+is\\s+no\\s+doubt|100%\\s+(safe|effective|accurate|certain))")
	if falseConfidencePattern.MatchString(content) {
		alerts = append(alerts, agencyAlert{
			alertType: "misinformation_false_confidence",
			severity:  core.SeverityMedium,
			title:     "False Confidence Markers in Output",
			desc:      "Output contains absolute confidence claims — may indicate hallucinated assertions",
		})
	}

	// Detect self-contradictions within the same output
	// Heuristic: look for negation of previously stated claims
	contradictionPattern := regexp.MustCompile("(?i)(however,?\\s+(this|that|it)\\s+is\\s+(not|incorrect|false|wrong)|actually,?\\s+(the\\s+opposite|that'?s\\s+not\\s+(true|correct|right))|contrary\\s+to\\s+what\\s+I\\s+(just\\s+)?said)")
	if contradictionPattern.MatchString(content) {
		alerts = append(alerts, agencyAlert{
			alertType: "misinformation_self_contradiction",
			severity:  core.SeverityLow,
			title:     "Self-Contradiction in Output",
			desc:      "Output contains self-contradictory statements — may indicate confabulation",
		})
	}

	// Medical/legal/financial misinformation markers
	if claimType == "medical" || claimType == "legal" || claimType == "financial" {
		dangerousClaims := regexp.MustCompile("(?i)(you\\s+should\\s+(take|stop\\s+taking|increase|decrease)\\s+.{0,30}(medication|dosage|drug)|this\\s+is\\s+not\\s+medical\\s+advice.*?but\\s+you\\s+should|guaranteed\\s+(return|profit|cure|treatment))")
		if dangerousClaims.MatchString(content) {
			alerts = append(alerts, agencyAlert{
				alertType: "misinformation_dangerous_advice",
				severity:  core.SeverityHigh,
				title:     fmt.Sprintf("Potentially Dangerous %s Advice", strings.Title(claimType)),
				desc: fmt.Sprintf("Output contains specific %s advice that could cause harm if hallucinated",
					claimType),
			})
		}
	}

	for _, a := range alerts {
		newEvent := core.NewSecurityEvent(ModuleName, a.alertType, a.severity, a.desc)
		newEvent.SourceIP = event.SourceIP
		newEvent.Details["claim_type"] = claimType

		if f.bus != nil {
			_ = f.bus.PublishEvent(newEvent)
		}

		alert := core.NewAlert(newEvent, a.title, a.desc)
		alert.Mitigations = getMisinformationMitigations(a.alertType)

		if f.pipeline != nil {
			f.pipeline.Process(alert)
		}
	}
}

// ============================================================================
// Multimodal Prompt Injection Detection
// ============================================================================

// analyzeMultimodal scans document/image/file attachments for hidden prompt
// injection using three heuristic layers: image metadata, HTML/CSS hidden
// content, and PDF hidden text. Zero ML, zero OCR, zero external dependencies.
func (f *Firewall) analyzeMultimodal(event *core.SecurityEvent) {
	// Get raw data (base64-encoded in event details)
	rawB64 := getStringDetail(event, "raw_data")
	textContent := getStringDetail(event, "text_content")
	contentType := getStringDetail(event, "content_type")
	filename := getStringDetail(event, "filename")

	var rawData []byte
	if rawB64 != "" {
		var err error
		rawData, err = base64.StdEncoding.DecodeString(rawB64)
		if err != nil {
			// Try raw bytes if not base64
			rawData = []byte(rawB64)
		}
	}

	// Also accept raw_bytes directly (for internal pipeline use)
	if len(rawData) == 0 {
		if rawBytes := getStringDetail(event, "raw_bytes"); rawBytes != "" {
			rawData = []byte(rawBytes)
		}
	}

	if len(rawData) == 0 && textContent == "" {
		return
	}

	// Infer content type from filename if not provided
	if contentType == "" && filename != "" {
		contentType = inferContentType(filename)
	}

	detections := ScanMultimodal(rawData, textContent, contentType)
	if len(detections) == 0 {
		return
	}

	// Group by layer for the alert
	layerCounts := map[string]int{}
	var maxSeverity core.Severity
	for _, d := range detections {
		layerCounts[d.Layer]++
		if d.Severity > maxSeverity {
			maxSeverity = d.Severity
		}
	}

	var layers []string
	for layer, count := range layerCounts {
		layers = append(layers, fmt.Sprintf("%s(%d)", layer, count))
	}

	desc := fmt.Sprintf("Multimodal scan of %q found %d hidden injection(s) across layers: %s",
		truncate(filename, 80), len(detections), strings.Join(layers, ", "))

	newEvent := core.NewSecurityEvent(ModuleName, "multimodal_hidden_injection", maxSeverity, desc)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["filename"] = filename
	newEvent.Details["content_type"] = contentType
	newEvent.Details["detection_count"] = fmt.Sprintf("%d", len(detections))

	// Add first few detection details
	for i, d := range detections {
		if i >= 5 {
			break
		}
		prefix := fmt.Sprintf("detection_%d", i)
		newEvent.Details[prefix+"_layer"] = d.Layer
		newEvent.Details[prefix+"_technique"] = d.Technique
		newEvent.Details[prefix+"_content"] = truncate(d.Content, 200)
	}

	if f.bus != nil {
		_ = f.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent,
		fmt.Sprintf("Multimodal Injection: Hidden Content in %s", truncate(filename, 60)),
		desc)
	alert.Mitigations = getMultimodalMitigations()

	if f.pipeline != nil {
		f.pipeline.Process(alert)
	}
}

func inferContentType(filename string) string {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".png"):
		return "image/png"
	case strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(lower, ".gif"):
		return "image/gif"
	case strings.HasSuffix(lower, ".webp"):
		return "image/webp"
	case strings.HasSuffix(lower, ".pdf"):
		return "application/pdf"
	case strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm"):
		return "text/html"
	case strings.HasSuffix(lower, ".xml"):
		return "text/xml"
	case strings.HasSuffix(lower, ".svg"):
		return "image/svg+xml"
	default:
		return ""
	}
}

func getMultimodalMitigations() []string {
	return []string{
		"Strip all metadata (EXIF, XMP, IPTC, PNG tEXt) from images before LLM processing",
		"Render documents to a clean format and re-extract text to remove hidden layers",
		"Scan HTML/CSS for display:none, visibility:hidden, font-size:0, and transparent text before RAG ingestion",
		"Validate PDF text rendering modes — flag invisible (mode 3), white, or zero-size text",
		"Reject or quarantine files with prompt injection patterns in metadata fields",
		"Implement content-type validation and reject unexpected file formats",
		"Use allowlists for permitted metadata fields and strip all others",
	}
}

// ============================================================================
// Contextual Mitigations
// ============================================================================

// getLLMInputMitigations returns context-specific mitigations based on detected categories.
func getLLMInputMitigations(categories []string) []string {
	mitigationMap := map[string][]string{
		"prompt_injection": {
			"Enforce strict separation between system instructions and user input",
			"Use structured message formats (system/user/assistant roles) to prevent injection",
			"Apply input validation and sanitization before LLM processing",
		},
		"jailbreak": {
			"Implement multi-layer safety classifiers before and after LLM processing",
			"Use constitutional AI or RLHF-trained refusal behaviors",
			"Monitor for known jailbreak patterns and update detection rules regularly",
		},
		"data_leak": {
			"Apply output filtering to redact PII, secrets, and sensitive data",
			"Implement data loss prevention (DLP) on LLM output streams",
			"Restrict LLM access to sensitive data stores via least-privilege policies",
		},
		"tool_abuse": {
			"Require human approval for destructive or sensitive tool invocations",
			"Implement tool-use policies that validate action sequences",
			"Sandbox agent tool access with minimal required permissions",
		},
		"policy_puppetry": {
			"Reject inputs containing structured configuration-like content (XML/JSON/INI)",
			"Validate that user inputs do not mimic system configuration formats",
			"Use allowlists for acceptable input structures",
		},
		"flip_attack": {
			"Normalize and decode all text layers before safety classification",
			"Apply bidirectional text analysis to detect reversed content",
			"Use character-level analysis alongside token-level safety checks",
		},
		"many_shot": {
			"Limit context window size for user-provided content",
			"Detect and reject inputs with excessive repetitive Q&A patterns",
			"Apply sliding-window analysis for long-context inputs",
		},
		"multi_turn_attack": {
			"Track conversation history for gradual escalation patterns",
			"Implement per-session suspicion scoring with automatic escalation",
			"Apply rate limiting on suspicious sessions",
		},
		"encoding_evasion": {
			"Decode all encoding layers (base64, hex, unicode, ROT13) before analysis",
			"Normalize homoglyphs and leetspeak substitutions",
			"Flag inputs that change meaning after decoding as high-risk",
		},
		"semantic_injection": {
			"Analyze input structure for instruction-like patterns",
			"Flag inputs with imperative directives, role assignments, or boundary markers",
			"Use semantic similarity to detect inputs that resemble system prompts",
		},
		"temporal_attack": {
			"Reject prompts that attempt to set temporal context to bypass safety rules",
			"Ensure safety guidelines are not era-dependent in system prompts",
		},
		"narrative_engineering": {
			"Detect fictional world-building that suspends content policies",
			"Ensure safety rules apply regardless of narrative framing",
			"Flag character immersion instructions that override refusal behavior",
		},
		"agent_attack": {
			"Validate all external content before allowing agent processing",
			"Implement memory integrity checks for persistent agent context",
			"Require explicit user confirmation for instructions found in external documents",
		},
		"echo_chamber": {
			"Track and validate claims about prior conversation content",
			"Implement conversation integrity verification",
			"Detect gradual safeguard erosion across conversation turns",
		},
		"fallacy_failure": {
			"Detect fictional framing combined with requests for realistic harmful content",
			"Apply safety rules regardless of academic or creative framing",
		},
		"concretization": {
			"Monitor iterative refinement requests that progressively add harmful detail",
			"Implement cumulative harm scoring across conversation turns",
		},
		"distraction_attack": {
			"Analyze all embedded tasks within complex prompts",
			"Detect hidden task markers and auxiliary task patterns",
		},
		"artistic_framing": {
			"Apply content safety rules to artistic and poetic output requests",
			"Detect harmful content requests disguised as creative writing exercises",
		},
		"automated_attack": {
			"Detect automated prompt optimization patterns (iteration counters, scores)",
			"Implement CAPTCHA or proof-of-work for high-volume prompt submissions",
		},
		"token_manipulation": {
			"Apply character-level normalization to detect token-breaking attacks",
			"Use multiple tokenization strategies for safety classification",
		},
	}

	seen := make(map[string]bool)
	var result []string
	for _, cat := range categories {
		if mits, ok := mitigationMap[cat]; ok {
			for _, m := range mits {
				if !seen[m] {
					seen[m] = true
					result = append(result, m)
				}
			}
		}
	}
	if len(result) == 0 {
		return []string{
			"Sanitize user input before passing to LLM",
			"Implement input/output guardrails",
			"Monitor and limit token usage per user",
		}
	}
	return result
}

// getOutputMitigations returns context-specific mitigations for output violations.
func getOutputMitigations(category string) []string {
	switch category {
	case "pii_leak":
		return []string{
			"Implement PII detection and redaction on all LLM outputs",
			"Use data masking for sensitive fields in training and retrieval data",
			"Apply output filtering with regex and NER-based PII detection",
			"Audit training data for PII contamination",
		}
	case "secret_leak":
		return []string{
			"Scan LLM outputs for API keys, tokens, and credentials before delivery",
			"Remove secrets from training data and RAG knowledge bases",
			"Implement secret rotation for any credentials detected in output",
			"Use vault-based secret management to prevent LLM access to raw secrets",
		}
	case "prompt_leak":
		return []string{
			"Implement output classifiers to detect system prompt leakage (OWASP LLM07:2025)",
			"Use prompt isolation techniques to prevent instruction echo",
			"Monitor outputs for role definitions, guardrail configs, and boundary markers",
			"Avoid embedding sensitive configuration in system prompts",
		}
	case "harmful_output":
		return []string{
			"Apply output safety classifiers to detect harmful content",
			"Implement content filtering for code execution commands",
			"Use sandboxed execution environments for any LLM-generated code",
		}
	case "misinformation":
		return []string{
			"Implement citation verification for LLM-generated references",
			"Add disclaimers to LLM outputs in high-stakes domains",
			"Use retrieval-augmented generation with verified sources",
			"Flag outputs with absolute confidence claims for human review",
		}
	default:
		return []string{
			"Apply output filtering to prevent data leakage",
			"Monitor LLM outputs for policy violations",
		}
	}
}

// getExcessiveAgencyMitigations returns mitigations for excessive agency alerts.
func getExcessiveAgencyMitigations(alertType string) []string {
	switch alertType {
	case "excessive_agency_no_approval":
		return []string{
			"Enforce human-in-the-loop approval for all high-impact agent actions (OWASP LLM06:2025)",
			"Implement approval gates with timeout-based denial",
			"Log all agent actions with approval status for audit",
		}
	case "excessive_agency_scope_violation":
		return []string{
			"Define and enforce strict scope boundaries per agent role",
			"Implement least-privilege tool access — agents should only access tools they need",
			"Use scope-aware action validators that reject out-of-scope operations",
		}
	case "excessive_agency_tool_sprawl":
		return []string{
			"Limit the number of tools available to each agent",
			"Implement tool access reviews and remove unused tool permissions",
			"Use role-based tool access control (OWASP Agentic Top 10 2026)",
		}
	case "excessive_agency_complex_plan":
		return []string{
			"Require human checkpoints for plans exceeding a step threshold",
			"Implement plan review and approval workflows",
			"Break complex plans into smaller, independently approved stages",
		}
	case "excessive_agency_privilege_delegation":
		return []string{
			"Prevent agents from delegating elevated privileges to other agents",
			"Implement delegation scope validation — delegated scope must not exceed delegator scope",
			"Monitor cross-agent communication for privilege escalation patterns (2026 agentic threat)",
		}
	default:
		return []string{
			"Apply principle of least privilege to all agent tool access",
			"Implement human-in-the-loop for sensitive operations",
		}
	}
}

// getRAGMitigations returns mitigations for RAG/vector embedding alerts.
func getRAGMitigations(alertType string) []string {
	switch alertType {
	case "rag_injection_detected":
		return []string{
			"Scan all retrieved content for injection payloads before passing to LLM (OWASP LLM08:2025)",
			"Implement content sanitization on RAG retrieval results",
			"Use separate safety classifiers for retrieved context vs user input",
			"Maintain allowlists for trusted content sources",
		}
	case "rag_hidden_content":
		return []string{
			"Strip HTML comments, invisible CSS, and hidden markdown from retrieved content",
			"Render and re-extract text from documents to remove hidden layers",
			"Validate document integrity before indexing into vector stores",
		}
	case "rag_low_similarity":
		return []string{
			"Set minimum similarity thresholds for RAG retrieval results",
			"Flag and review low-similarity retrievals before LLM consumption",
			"Monitor for adversarial embedding manipulation in vector stores",
		}
	default:
		return []string{
			"Validate RAG retrieval results before LLM processing",
			"Implement content integrity checks on vector store entries",
		}
	}
}

// getMisinformationMitigations returns mitigations for misinformation/hallucination alerts.
func getMisinformationMitigations(alertType string) []string {
	switch alertType {
	case "misinformation_fabricated_citations":
		return []string{
			"Implement automated citation verification against known databases (OWASP LLM09:2025)",
			"Add disclaimers that LLM-generated citations may be fabricated",
			"Use retrieval-augmented generation with verified source databases",
			"Cross-reference generated DOIs and arXiv IDs against real registries",
		}
	case "misinformation_false_confidence":
		return []string{
			"Flag absolute confidence claims for human review",
			"Implement confidence calibration in LLM outputs",
			"Add uncertainty markers to LLM-generated factual claims",
		}
	case "misinformation_self_contradiction":
		return []string{
			"Implement consistency checking across LLM output paragraphs",
			"Flag self-contradictory outputs for regeneration or human review",
			"Use chain-of-thought verification to detect logical inconsistencies",
		}
	case "misinformation_dangerous_advice":
		return []string{
			"Require domain expert review for medical, legal, and financial advice",
			"Implement mandatory disclaimers for high-stakes domains",
			"Restrict LLM from providing specific actionable advice in regulated domains",
			"Route high-stakes queries to human experts instead of LLM-only responses",
		}
	default:
		return []string{
			"Implement fact-checking pipelines for LLM-generated content",
			"Add disclaimers about potential inaccuracies in LLM output",
		}
	}
}
