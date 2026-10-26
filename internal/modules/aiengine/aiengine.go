package aiengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
	"github.com/sony/gobreaker"
)

const ModuleName = "ai_analysis_engine"

// Engine is the cross-cutting AI Analysis Engine (Module 16).
// It implements a two-tier LLM pipeline:
//
//	Tier 1: Gemini Flash Lite — fast triage, false positive filtering
//	Tier 2: Gemini Flash — deep threat classification, cross-module correlation
type Engine struct {
	logger     zerolog.Logger
	bus        *core.EventBus
	pipeline   *core.AlertPipeline
	cfg        *core.Config
	ctx        context.Context
	cancel     context.CancelFunc
	httpClient *http.Client
	cb         *gobreaker.CircuitBreaker
	correlator *EventCorrelator
	keyMgr     *KeyManager

	// Config
	triageModel string
	deepModel   string
	triageURL   string
	deepURL     string
	enabled     bool
	triageQueue chan *core.SecurityEvent
	deepQueue   chan *analysisRequest
}

type analysisRequest struct {
	events      []*core.SecurityEvent
	triageScore float64
	category    string
}

func New() *Engine {
	return &Engine{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cb: gobreaker.NewCircuitBreaker(gobreaker.Settings{
			Name:        "GeminiAPI",
			MaxRequests: 3,
			Interval:    10 * time.Second,
			Timeout:     30 * time.Second,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.ConsecutiveFailures > 5
			},
		}),
	}
}

func (e *Engine) Name() string { return ModuleName }
func (e *Engine) Description() string {
	return "Two-tier AI analysis: Gemini Flash Lite for triage, Gemini Flash for deep threat classification and cross-module correlation"
}

// EventTypes returns nil — the AI engine receives all events for correlation.
func (e *Engine) EventTypes() []string { return nil }

func (e *Engine) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.bus = bus
	e.pipeline = pipeline
	e.cfg = cfg
	e.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)

	// Collect API keys from config and environment, initialize key rotation manager
	keys := collectAPIKeys(settings)
	e.keyMgr = NewKeyManager(keys, e.logger)

	e.triageModel = getStringSetting(settings, "triage_model", "gemini-flash-lite-latest")
	e.deepModel = getStringSetting(settings, "deep_model", "gemini-flash-latest")

	baseURL := getStringSetting(settings, "api_base_url", "https://generativelanguage.googleapis.com/v1beta/models")
	e.triageURL = fmt.Sprintf("%s/%s:generateContent", baseURL, e.triageModel)
	e.deepURL = fmt.Sprintf("%s/%s:generateContent", baseURL, e.deepModel)

	e.enabled = e.keyMgr.HasKeys()

	e.correlator = NewEventCorrelator()
	e.triageQueue = make(chan *core.SecurityEvent, 1000)
	e.deepQueue = make(chan *analysisRequest, 100)

	if e.enabled {
		// Start triage workers
		triageWorkers := getIntSetting(settings, "triage_workers", 4)
		for i := 0; i < triageWorkers; i++ {
			go e.triageWorker()
		}

		// Start deep analysis workers
		deepWorkers := getIntSetting(settings, "deep_workers", 2)
		for i := 0; i < deepWorkers; i++ {
			go e.deepAnalysisWorker()
		}

		// Start correlation loop
		go e.correlationLoop()

		e.logger.Info().
			Str("triage_model", e.triageModel).
			Str("deep_model", e.deepModel).
			Int("triage_workers", triageWorkers).
			Int("deep_workers", deepWorkers).
			Int("api_keys", e.keyMgr.TotalCount()).
			Msg("AI analysis engine started with Gemini API")
	} else {
		e.logger.Warn().Msg("AI analysis engine started in passive mode (no API key configured)")
	}

	return nil
}

func (e *Engine) Stop() error {
	if e.cancel != nil {
		e.cancel()
	}
	return nil
}

func (e *Engine) HandleEvent(event *core.SecurityEvent) error {
	// Only process events with Medium severity or above for AI analysis
	if event.Severity < core.SeverityMedium {
		return nil
	}

	// Track for correlation regardless of API availability
	e.correlator.Track(event)

	if !e.enabled {
		return nil
	}

	// Non-blocking send to triage queue
	select {
	case e.triageQueue <- event:
	default:
		e.logger.Warn().Str("event_id", event.ID).Msg("triage queue full, dropping event. Queue backlog indicates system degradation.")
	}

	return nil
}

// triageWorker runs Tier 1 analysis using Gemini Flash Lite.
// Fast, cheap pre-filter that discards false positives and scores threats.
func (e *Engine) triageWorker() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case event := <-e.triageQueue:
			score, category, err := e.runTriage(event)
			if err != nil {
				e.logger.Debug().Err(err).Str("event_id", event.ID).Msg("triage failed")
				continue
			}

			// If triage says it's interesting (score >= 0.6), send to deep analysis
			if score >= 0.6 {
				correlated := e.correlator.GetCorrelated(event)
				req := &analysisRequest{
					events:      correlated,
					triageScore: score,
					category:    category,
				}
				select {
				case e.deepQueue <- req:
				default:
					e.logger.Warn().Msg("deep queue full, dropping analysis request. Queue backlog indicates system degradation.")
				}
			}
		}
	}
}

// deepAnalysisWorker runs Tier 2 analysis using Gemini Flash.
// Full threat classification with cross-module correlation context.
func (e *Engine) deepAnalysisWorker() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case req := <-e.deepQueue:
			result, err := e.runDeepAnalysis(req)
			if err != nil {
				e.logger.Debug().Err(err).Msg("deep analysis failed")
				continue
			}

			if result.ThreatLevel >= 0.7 {
				severity := core.SeverityHigh
				if result.ThreatLevel >= 0.9 {
					severity = core.SeverityCritical
				}

				eventIDs := make([]string, len(req.events))
				for i, ev := range req.events {
					eventIDs[i] = ev.ID
				}

				newEvent := core.NewSecurityEvent(ModuleName, "ai_threat_classification", severity, result.Summary)
				newEvent.Details["threat_level"] = result.ThreatLevel
				newEvent.Details["classification"] = result.Classification
				newEvent.Details["correlated_events"] = len(req.events)
				newEvent.Details["triage_score"] = req.triageScore
				newEvent.Details["attack_chain"] = result.AttackChain
				newEvent.Details["recommendations"] = result.Recommendations

				if e.bus != nil {
					_ = e.bus.PublishEvent(newEvent)
				}

				alert := core.NewAlert(newEvent,
					fmt.Sprintf("AI Analysis: %s", result.Classification),
					result.Summary)
				alert.Mitigations = result.Recommendations
				alert.EventIDs = eventIDs

				if e.pipeline != nil {
					e.pipeline.Process(alert)
				}
			}
		}
	}
}

// correlationLoop periodically checks for correlated event patterns.
func (e *Engine) correlationLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			patterns := e.correlator.DetectPatterns()
			for _, pattern := range patterns {
				if !e.enabled {
					// Even without API, raise alerts for obvious correlation patterns
					if pattern.Confidence >= 0.8 {
						newEvent := core.NewSecurityEvent(ModuleName, "correlation_detected", core.SeverityHigh,
							fmt.Sprintf("Cross-module correlation: %s (%d events from %d modules)",
								pattern.Description, pattern.EventCount, pattern.ModuleCount))
						newEvent.Details["pattern_type"] = pattern.Type
						newEvent.Details["modules"] = pattern.Modules
						newEvent.Details["event_count"] = pattern.EventCount
						newEvent.Details["confidence"] = pattern.Confidence

						if e.bus != nil {
							_ = e.bus.PublishEvent(newEvent)
						}

						alert := core.NewAlert(newEvent,
							"Cross-Module Threat Correlation",
							pattern.Description)
						if e.pipeline != nil {
							e.pipeline.Process(alert)
						}
					}
					continue
				}

				// Send high-confidence patterns to deep analysis
				if pattern.Confidence >= 0.6 {
					req := &analysisRequest{
						events:      pattern.Events,
						triageScore: pattern.Confidence,
						category:    pattern.Type,
					}
					select {
					case e.deepQueue <- req:
					default:
						e.logger.Warn().Msg("deep queue full, dropping correlated analysis request. System degradation.")
					}
				}
			}
		}
	}
}

// Gemini API types
type geminiRequest struct {
	Contents         []geminiContent        `json:"contents"`
	GenerationConfig map[string]interface{} `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error,omitempty"`
}

type triageResult struct {
	Score           float64 `json:"score"`
	Category        string  `json:"category"`
	IsFalsePositive bool    `json:"is_false_positive"`
}

type deepAnalysisResult struct {
	ThreatLevel     float64  `json:"threat_level"`
	Classification  string   `json:"classification"`
	Summary         string   `json:"summary"`
	AttackChain     string   `json:"attack_chain"`
	Recommendations []string `json:"recommendations"`
}

func (e *Engine) runTriage(event *core.SecurityEvent) (float64, string, error) {
	eventJSON, err := aiEventMetadata(event)
	if err != nil {
		return 0, "", fmt.Errorf("marshaling event: %w", err)
	}

	prompt := fmt.Sprintf(`You are a cybersecurity threat triage system. Analyze this security event and respond with ONLY a JSON object (no markdown, no explanation).

Event:
%s

Respond with:
{"score": 0.0-1.0, "category": "string", "is_false_positive": bool}

Where score is threat likelihood (0=benign, 1=critical threat), category is the attack type (e.g. "sql_injection", "brute_force", "data_exfiltration", "lateral_movement", "privilege_escalation", "ransomware", "deepfake", "prompt_injection", "supply_chain", "unknown"), and is_false_positive indicates if this is likely a false alarm.`, string(eventJSON))

	respText, err := e.callGemini(e.triageURL, prompt, 256)
	if err != nil {
		return 0, "", err
	}

	var result triageResult
	if err := json.Unmarshal([]byte(cleanJSON(respText)), &result); err != nil {
		return 0, "", fmt.Errorf("parsing triage response: %w", err)
	}

	if result.IsFalsePositive {
		return 0, result.Category, nil
	}

	return result.Score, result.Category, nil
}

func (e *Engine) runDeepAnalysis(req *analysisRequest) (*deepAnalysisResult, error) {
	eventsData := make([]json.RawMessage, 0, len(req.events))
	for _, ev := range req.events {
		data, err := aiEventMetadata(ev)
		if err != nil {
			continue
		}
		eventsData = append(eventsData, data)
	}

	eventsJSON, err := json.Marshal(eventsData)
	if err != nil {
		return nil, fmt.Errorf("marshaling events: %w", err)
	}

	prompt := fmt.Sprintf(`You are an advanced cybersecurity threat analyst. Analyze these correlated security events and provide a deep threat assessment. Respond with ONLY a JSON object (no markdown).

Triage category: %s
Triage score: %.2f
Number of correlated events: %d

Events:
%s

Respond with:
{"threat_level": 0.0-1.0, "classification": "attack type", "summary": "2-3 sentence analysis", "attack_chain": "description of the attack progression if applicable", "recommendations": ["action1", "action2", "action3"]}

Be specific about the attack type, affected systems, and recommended mitigations.`, req.category, req.triageScore, len(req.events), string(eventsJSON))

	respText, err := e.callGemini(e.deepURL, prompt, 1024)
	if err != nil {
		return nil, err
	}

	var result deepAnalysisResult
	if err := json.Unmarshal([]byte(cleanJSON(respText)), &result); err != nil {
		return nil, fmt.Errorf("parsing deep analysis response: %w", err)
	}

	return &result, nil
}

func (e *Engine) callGemini(url, prompt string, maxTokens int) (string, error) {
	reqBody := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
		},
		GenerationConfig: map[string]interface{}{
			"maxOutputTokens": maxTokens,
			"temperature":     0.1,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	// Retry loop: attempt with current key, rotate on rate limit, retry once
	maxAttempts := e.keyMgr.TotalCount()
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if maxAttempts > 4 {
		maxAttempts = 4
	}

	// Run HTTP request inside Circuit Breaker
	result, cbErr := e.cb.Execute(func() (interface{}, error) {
		var lastErr error
		for attempt := 0; attempt < maxAttempts; attempt++ {
			apiKey := e.keyMgr.CurrentKey()
			if apiKey == "" {
				return "", fmt.Errorf("no healthy API keys available")
			}

			req, err := http.NewRequestWithContext(e.ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return "", fmt.Errorf("creating request: %w", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("x-goog-api-key", apiKey)

			resp, err := e.httpClient.Do(req)
			if err != nil {
				return "", fmt.Errorf("calling Gemini API: %w", err)
			}

			respBody, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
			resp.Body.Close()
			if len(respBody) > 1<<20 {
				return "", fmt.Errorf("Gemini response exceeds limit")
			}
			if err != nil {
				return "", fmt.Errorf("reading response: %w", err)
			}

			// Check for rate limit / quota errors — rotate and retry
			if IsRotatableError(resp.StatusCode, string(respBody)) {
				lastErr = fmt.Errorf("Gemini API rate limited (status %d)", resp.StatusCode)
				newKey := e.keyMgr.RotateOnError(resp.StatusCode, string(respBody))
				if newKey == "" {
					return "", fmt.Errorf("all API keys exhausted: %w", lastErr)
				}
				continue
			}

			if resp.StatusCode != http.StatusOK {
				return "", fmt.Errorf("Gemini API error (status %d): %s", resp.StatusCode, string(respBody))
			}

			var gemResp geminiResponse
			if err := json.Unmarshal(respBody, &gemResp); err != nil {
				return "", fmt.Errorf("parsing Gemini response: %w", err)
			}

			if gemResp.Error != nil {
				errMsg := gemResp.Error.Message
				if IsRotatableError(gemResp.Error.Code, errMsg) {
					lastErr = fmt.Errorf("Gemini API error: %s", errMsg)
					newKey := e.keyMgr.RotateOnError(gemResp.Error.Code, errMsg)
					if newKey == "" {
						return "", fmt.Errorf("all API keys exhausted: %w", lastErr)
					}
					continue
				}
				return "", fmt.Errorf("Gemini API error: %s", errMsg)
			}

			if len(gemResp.Candidates) == 0 || len(gemResp.Candidates[0].Content.Parts) == 0 {
				return "", fmt.Errorf("empty response from Gemini")
			}

			return gemResp.Candidates[0].Content.Parts[0].Text, nil
		}

		if lastErr != nil {
			return "", lastErr
		}
		return "", fmt.Errorf("no healthy API keys available")
	})

	if cbErr != nil {
		return "", cbErr
	}

	return result.(string), nil
}

// cleanJSON extracts JSON from a response that might have markdown fencing.
func cleanJSON(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```json") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	} else if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	}
	return s
}

// EventCorrelator tracks events across modules and detects attack patterns.
type EventCorrelator struct {
	mu     sync.RWMutex
	events []*core.SecurityEvent
	maxAge time.Duration
	maxLen int
}

type CorrelationPattern struct {
	Type        string
	Description string
	Confidence  float64
	Events      []*core.SecurityEvent
	Modules     []string
	EventCount  int
	ModuleCount int
}

func NewEventCorrelator() *EventCorrelator {
	return &EventCorrelator{
		events: make([]*core.SecurityEvent, 0, 5000),
		maxAge: 10 * time.Minute,
		maxLen: 5000,
	}
}

func (c *EventCorrelator) Track(event *core.SecurityEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.events = append(c.events, event)

	// Trim old events
	if len(c.events) > c.maxLen {
		c.events = c.events[len(c.events)-c.maxLen:]
	}
}

// GetCorrelated returns events that share source IP, time window, or related modules.
func (c *EventCorrelator) GetCorrelated(event *core.SecurityEvent) []*core.SecurityEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var correlated []*core.SecurityEvent
	window := 5 * time.Minute

	for _, ev := range c.events {
		if ev.ID == event.ID {
			continue
		}
		timeDiff := event.Timestamp.Sub(ev.Timestamp)
		if timeDiff < 0 {
			timeDiff = -timeDiff
		}
		if timeDiff > window {
			continue
		}

		// Correlate by source IP
		if event.SourceIP != "" && ev.SourceIP == event.SourceIP {
			correlated = append(correlated, ev)
			continue
		}

		// Correlate by destination IP
		if event.DestIP != "" && ev.DestIP == event.DestIP {
			correlated = append(correlated, ev)
			continue
		}
	}

	// Always include the original event
	correlated = append(correlated, event)

	// Cap at 50 events to stay within token limits
	if len(correlated) > 50 {
		correlated = correlated[len(correlated)-50:]
	}

	return correlated
}

// DetectPatterns looks for multi-module attack patterns in the event window.
func (c *EventCorrelator) DetectPatterns() []CorrelationPattern {
	c.mu.Lock()
	// Prune old events
	cutoff := time.Now().Add(-c.maxAge)
	fresh := make([]*core.SecurityEvent, 0, len(c.events))
	for _, ev := range c.events {
		if ev.Timestamp.After(cutoff) {
			fresh = append(fresh, ev)
		}
	}
	c.events = fresh
	c.mu.Unlock()

	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.events) < 3 {
		return nil
	}

	// Group events by source IP
	byIP := make(map[string][]*core.SecurityEvent)
	for _, ev := range c.events {
		if ev.SourceIP != "" {
			byIP[ev.SourceIP] = append(byIP[ev.SourceIP], ev)
		}
	}

	var patterns []CorrelationPattern

	for ip, events := range byIP {
		if len(events) < 3 {
			continue
		}

		modules := make(map[string]bool)
		for _, ev := range events {
			modules[ev.Module] = true
		}

		// Multi-module activity from same IP is suspicious
		if len(modules) >= 2 {
			moduleList := make([]string, 0, len(modules))
			for m := range modules {
				moduleList = append(moduleList, m)
			}

			confidence := float64(len(modules)) / 5.0
			if confidence > 1.0 {
				confidence = 1.0
			}

			// Higher confidence if high-severity events are involved
			hasHighSeverity := false
			for _, ev := range events {
				if ev.Severity >= core.SeverityHigh {
					hasHighSeverity = true
					break
				}
			}
			if hasHighSeverity {
				confidence += 0.2
				if confidence > 1.0 {
					confidence = 1.0
				}
			}

			patternType := "multi_vector_attack"
			desc := fmt.Sprintf("Source IP %s triggered alerts across %d modules (%s) with %d events in the last %s",
				ip, len(modules), strings.Join(moduleList, ", "), len(events), c.maxAge)

			patterns = append(patterns, CorrelationPattern{
				Type:        patternType,
				Description: desc,
				Confidence:  confidence,
				Events:      events,
				Modules:     moduleList,
				EventCount:  len(events),
				ModuleCount: len(modules),
			})
		}
	}

	return patterns
}

// Helper functions

func getStringSetting(settings map[string]interface{}, key, defaultVal string) string {
	if val, ok := settings[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return defaultVal
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
