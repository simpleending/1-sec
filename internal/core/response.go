package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Response Action Types — the enforcement primitives
// ---------------------------------------------------------------------------

// ActionType enumerates the kinds of automated response actions.
type ActionType string

const (
	ActionBlockIP        ActionType = "block_ip"
	ActionKillProcess    ActionType = "kill_process"
	ActionQuarantineFile ActionType = "quarantine_file"
	ActionDropConnection ActionType = "drop_connection"
	ActionDisableUser    ActionType = "disable_user"
	ActionWebhook        ActionType = "webhook"
	ActionCommand        ActionType = "command"
	ActionLog            ActionType = "log_only"
)

// ActionStatus tracks the lifecycle of a response action execution.
type ActionStatus string

const (
	ActionStatusPending   ActionStatus = "PENDING"
	ActionStatusExecuting ActionStatus = "EXECUTING"
	ActionStatusSuccess   ActionStatus = "SUCCESS"
	ActionStatusFailed    ActionStatus = "FAILED"
	ActionStatusDryRun    ActionStatus = "DRY_RUN"
	ActionStatusSkipped   ActionStatus = "SKIPPED"
	ActionStatusCooldown  ActionStatus = "COOLDOWN"
)

// ---------------------------------------------------------------------------
// Response Policy — configurable per-module enforcement rules
// ---------------------------------------------------------------------------

// ResponsePolicy defines when and how to respond to alerts from a module.
type ResponsePolicy struct {
	Module           string         `json:"module" yaml:"module"`
	Enabled          bool           `json:"enabled" yaml:"enabled"`
	MinSeverity      Severity       `json:"min_severity" yaml:"min_severity"`
	Actions          []ResponseRule `json:"actions" yaml:"actions"`
	Cooldown         time.Duration  `json:"cooldown" yaml:"cooldown"`
	DryRun           bool           `json:"dry_run" yaml:"dry_run"`
	AllowList        []string       `json:"allow_list,omitempty" yaml:"allow_list"`
	MaxActionsPerMin int            `json:"max_actions_per_min" yaml:"max_actions_per_min"`
}

// ResponseRule maps an alert condition to a specific action.
type ResponseRule struct {
	Action       ActionType        `json:"action" yaml:"action"`
	MinSeverity  Severity          `json:"min_severity" yaml:"min_severity"`
	Params       map[string]string `json:"params,omitempty" yaml:"params"`
	DryRun       bool              `json:"dry_run" yaml:"dry_run"`
	SkipApproval bool              `json:"skip_approval,omitempty" yaml:"skip_approval"` // bypass approval gate
	Description  string            `json:"description,omitempty" yaml:"description"`
}

// ResponseRecord is the audit log entry for an executed (or skipped) action.
type ResponseRecord struct {
	ID         string       `json:"id"`
	Timestamp  time.Time    `json:"timestamp"`
	AlertID    string       `json:"alert_id"`
	Module     string       `json:"module"`
	Action     ActionType   `json:"action"`
	Status     ActionStatus `json:"status"`
	Severity   string       `json:"severity"`
	Target     string       `json:"target"`
	Details    string       `json:"details"`
	DurationMs int64        `json:"duration_ms"`
	Error      string       `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// Response Engine — the SOAR-lite enforcement layer
// ---------------------------------------------------------------------------

// ResponseEngine subscribes to alerts and executes configured response actions.
type ResponseEngine struct {
	logger       zerolog.Logger
	bus          *EventBus
	pipeline     *AlertPipeline
	cfg          *Config
	policies     map[string]*ResponsePolicy // keyed by module name
	executors    map[ActionType]ActionExecutor
	records      []*ResponseRecord
	maxRecords   int
	cooldowns    map[string]time.Time // "module:action:target" → last fired
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	actionRate   map[string]int // per-minute action counter per module
	rateReset    time.Time
	ApprovalGate *ApprovalGate      // exported for command poller access
	Dispatcher   *WebhookDispatcher // reliable webhook delivery with retry + dead letter
}

// ActionExecutor is the interface for pluggable response action handlers.
type ActionExecutor interface {
	Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (target string, details string, err error)
	Validate(rule ResponseRule) error
}

// NewResponseEngine creates a new enforcement engine.
func NewResponseEngine(logger zerolog.Logger, bus *EventBus, pipeline *AlertPipeline, cfg *Config) *ResponseEngine {
	ctx, cancel := context.WithCancel(context.Background())
	re := &ResponseEngine{
		logger:     logger.With().Str("component", "response_engine").Logger(),
		bus:        bus,
		pipeline:   pipeline,
		cfg:        cfg,
		policies:   make(map[string]*ResponsePolicy),
		executors:  make(map[ActionType]ActionExecutor),
		records:    make([]*ResponseRecord, 0, 10000),
		maxRecords: 10000,
		cooldowns:  make(map[string]time.Time),
		ctx:        ctx,
		cancel:     cancel,
		actionRate: make(map[string]int),
		rateReset:  time.Now(),
	}

	// Initialize reliable webhook dispatcher with retry + dead letter + circuit breaker
	re.Dispatcher = NewWebhookDispatcher(logger, DefaultWebhookRetryConfig())

	// Register built-in executors
	re.executors[ActionBlockIP] = &BlockIPExecutor{}
	re.executors[ActionKillProcess] = &KillProcessExecutor{}
	re.executors[ActionQuarantineFile] = &QuarantineFileExecutor{}
	re.executors[ActionDropConnection] = &DropConnectionExecutor{}
	re.executors[ActionDisableUser] = &DisableUserExecutor{}
	re.executors[ActionWebhook] = &WebhookExecutor{Dispatcher: re.Dispatcher}
	re.executors[ActionCommand] = &CommandExecutor{}
	re.executors[ActionLog] = &LogOnlyExecutor{}

	// Load policies from config
	re.loadPolicies()

	// Initialize approval gate if configured
	if cfg.Enforcement != nil && cfg.Enforcement.ApprovalGate.Enabled {
		re.ApprovalGate = NewApprovalGate(logger, cfg.Enforcement.ApprovalGate)
		// When an action is approved, re-execute it
		re.ApprovalGate.AddHandler(func(pa *PendingApproval) {
			if !responseActionAllowed(pa.Alert, pa.Action) {
				re.recordAction(pa.Alert, pa.Rule, pa.Target, ActionStatusSkipped, "alert does not authorize this action", 0, nil)
				return
			}
			executor, exists := re.executors[pa.Action]
			if !exists {
				re.logger.Error().Str("action", string(pa.Action)).Msg("approved action has no executor")
				return
			}
			start := time.Now()
			target, details, err := executor.Execute(re.ctx, pa.Alert, pa.Rule, re.logger)
			durationMs := time.Since(start).Milliseconds()
			if target != "" {
				pa.Target = target
			}
			if err != nil {
				re.recordAction(pa.Alert, pa.Rule, pa.Target, ActionStatusFailed, details, durationMs, err)
			} else {
				re.recordAction(pa.Alert, pa.Rule, pa.Target, ActionStatusSuccess, details, durationMs, nil)
			}
		})
		// Notify SOC team via webhook dispatcher when an action enters the approval gate
		if re.Dispatcher != nil {
			re.ApprovalGate.SetNotifyFunc(func(pa *PendingApproval) {
				// Find any webhook URL from the module's policy to send the notification
				webhookURLs := re.findWebhookURLs(pa.Module)
				payload := map[string]interface{}{
					"type":        "approval_required",
					"approval_id": pa.ID,
					"alert_id":    pa.AlertID,
					"module":      pa.Module,
					"action":      string(pa.Action),
					"target":      pa.Target,
					"severity":    pa.Alert.Severity.String(),
					"title":       pa.Alert.Title,
					"expires_at":  pa.ExpiresAt,
					"source":      "1sec-approval-gate",
					"message":     fmt.Sprintf("⚠ Action %s on %s requires human approval (expires %s)", pa.Action, pa.Target, pa.ExpiresAt.Format("15:04:05 UTC")),
				}
				for _, url := range webhookURLs {
					re.Dispatcher.Enqueue(url, payload, map[string]string{
						"Content-Type": "application/json",
						"User-Agent":   "1sec-approval-gate/1.0",
					})
				}
			})
		}
	}

	return re
}

// loadPolicies reads response policies from the config's enforcement section
// and converts from YAML-friendly types to internal types.
// If a preset is specified, it loads the preset first, then overlays user policies.
func (re *ResponseEngine) loadPolicies() {
	if re.cfg.Enforcement == nil || !re.cfg.Enforcement.Enabled {
		return
	}

	// Start with preset policies if specified
	mergedPolicies := make(map[string]ResponsePolicyYAML)
	if preset := re.cfg.Enforcement.Preset; preset != "" {
		presetPolicies := GetPresetPolicies(preset)
		if presetPolicies != nil {
			for k, v := range presetPolicies {
				mergedPolicies[k] = v
			}
			re.logger.Info().Str("preset", preset).Int("policies", len(presetPolicies)).Msg("loaded enforcement preset")
		} else {
			re.logger.Warn().Str("preset", preset).Msg("unknown enforcement preset, ignoring")
		}
	}

	// Overlay user-defined policies (these override preset values)
	for k, v := range re.cfg.Enforcement.Policies {
		mergedPolicies[k] = v
	}

	// Convert YAML policies to internal types
	for module, yamlPolicy := range mergedPolicies {
		actions := make([]ResponseRule, 0, len(yamlPolicy.Actions))
		for _, ya := range yamlPolicy.Actions {
			actions = append(actions, ResponseRule{
				Action:       ActionType(ya.Action),
				MinSeverity:  ParseSeverity(ya.MinSeverity),
				Params:       ya.Params,
				DryRun:       ya.DryRun,
				SkipApproval: ya.SkipApproval,
				Description:  ya.Description,
			})
		}
		p := &ResponsePolicy{
			Module:           module,
			Enabled:          yamlPolicy.Enabled,
			MinSeverity:      ParseSeverity(yamlPolicy.MinSeverity),
			Actions:          actions,
			Cooldown:         time.Duration(yamlPolicy.CooldownSeconds) * time.Second,
			DryRun:           yamlPolicy.DryRun,
			AllowList:        yamlPolicy.AllowList,
			MaxActionsPerMin: yamlPolicy.MaxActionsPerMin,
		}
		re.policies[module] = p
		re.logger.Info().
			Str("module", module).
			Bool("enabled", p.Enabled).
			Bool("dry_run", p.DryRun).
			Int("actions", len(p.Actions)).
			Msg("response policy loaded")

		// Warn about webhook actions with empty URLs so operators don't miss
		// critical notifications silently failing in production.
		for _, rule := range p.Actions {
			if rule.Action == ActionWebhook {
				if err := validateWebhookURL(rule.Params["url"]); err != nil {
					re.logger.Warn().
						Str("module", module).
						Str("action", string(rule.Action)).
						Str("issue", err.Error()).
						Msg("⚠ webhook action has invalid URL — notifications will fail until configured")
				}
			}
		}
	}
}

// Start begins listening for alerts and executing response actions.
func (re *ResponseEngine) Start(ctx context.Context) {
	re.ctx = ctx
	re.pipeline.AddHandler(func(alert *Alert) {
		re.handleAlert(alert)
	})
	go re.cleanupLoop(ctx)
	re.logger.Info().
		Int("policies", len(re.policies)).
		Bool("global_dry_run", re.cfg.Enforcement != nil && re.cfg.Enforcement.GetDryRun()).
		Msg("response engine started")
}

// Stop shuts down the response engine.
func (re *ResponseEngine) Stop() {
	re.cancel()
	if re.ApprovalGate != nil {
		re.ApprovalGate.Stop()
	}
	if re.Dispatcher != nil {
		re.Dispatcher.Stop()
	}
	re.logger.Info().Msg("response engine stopped")
}

// handleAlert is the core decision loop: check policies, enforce cooldowns/rate limits, execute actions.
func (re *ResponseEngine) handleAlert(alert *Alert) {
	policy, ok := re.policies[alert.Module]
	if !ok {
		// Check for wildcard/default policy
		policy, ok = re.policies["*"]
		if !ok {
			return
		}
	}

	if !policy.Enabled {
		return
	}

	if alert.Severity < policy.MinSeverity {
		return
	}

	// Check allow list
	sourceIP, _ := alert.Metadata["source_ip"].(string)
	if re.isAllowListed(policy, sourceIP) {
		re.logger.Debug().Str("alert_id", alert.ID).Str("source_ip", sourceIP).Msg("source in allow list, skipping enforcement")
		return
	}

	globalDryRun := re.cfg.Enforcement != nil && re.cfg.Enforcement.GetDryRun()

	for _, rule := range policy.Actions {
		if !responseActionAllowed(alert, rule.Action) {
			continue
		}
		if alert.Severity < rule.MinSeverity {
			continue
		}

		target := re.resolveTarget(alert, rule)
		cooldownKey := fmt.Sprintf("%s:%s:%s", alert.Module, rule.Action, target)

		// Check cooldown
		if re.isOnCooldown(cooldownKey, policy.Cooldown) {
			re.recordAction(alert, rule, target, ActionStatusCooldown, "", 0, nil)
			continue
		}

		// Check rate limit
		if !re.checkRateLimit(alert.Module, policy.MaxActionsPerMin) {
			re.logger.Warn().Str("module", alert.Module).Msg("rate limit exceeded, skipping action")
			re.recordAction(alert, rule, target, ActionStatusSkipped, "rate limit exceeded", 0, nil)
			continue
		}

		isDryRun := globalDryRun || policy.DryRun || rule.DryRun

		if isDryRun {
			re.logger.Info().
				Str("alert_id", alert.ID).
				Str("module", alert.Module).
				Str("action", string(rule.Action)).
				Str("target", target).
				Msg("[DRY RUN] would execute response action")
			re.recordAction(alert, rule, target, ActionStatusDryRun, "dry run — no action taken", 0, nil)
			continue
		}

		// Check if this action requires human approval before execution
		if re.ApprovalGate != nil && re.ApprovalGate.RequiresApprovalForRule(rule.Action, alert.Severity, rule.SkipApproval) {
			approvalID := re.ApprovalGate.Submit(alert, rule, target)
			re.logger.Warn().
				Str("alert_id", alert.ID).
				Str("action", string(rule.Action)).
				Str("target", target).
				Str("approval_id", approvalID).
				Msg("action held for human approval — approve via dashboard or CLI")
			re.recordAction(alert, rule, target, ActionStatusSkipped, "held for approval: "+approvalID, 0, nil)
			continue
		}

		// Execute the action
		executor, exists := re.executors[rule.Action]
		if !exists {
			re.logger.Error().Str("action", string(rule.Action)).Msg("unknown action type")
			continue
		}

		re.logger.Info().
			Str("alert_id", alert.ID).
			Str("module", alert.Module).
			Str("action", string(rule.Action)).
			Str("target", target).
			Str("severity", alert.Severity.String()).
			Msg("executing response action")

		start := time.Now()
		actionTarget, details, err := executor.Execute(re.ctx, alert, rule, re.logger)
		durationMs := time.Since(start).Milliseconds()

		if actionTarget != "" {
			target = actionTarget
		}

		if err != nil {
			re.logger.Error().Err(err).
				Str("action", string(rule.Action)).
				Str("target", target).
				Msg("response action failed")
			re.recordAction(alert, rule, target, ActionStatusFailed, details, durationMs, err)
		} else {
			re.logger.Info().
				Str("action", string(rule.Action)).
				Str("target", target).
				Int64("duration_ms", durationMs).
				Msg("response action succeeded")
			re.recordAction(alert, rule, target, ActionStatusSuccess, details, durationMs, nil)
			re.setCooldown(cooldownKey, policy.Cooldown)
		}
	}
}

// Operational status and aggregate observations do not establish executable targets.
func responseActionAllowed(alert *Alert, action ActionType) bool {
	if alert.Type == "escalation" || alert.Type == "tracking_capacity" {
		return action == ActionWebhook || action == ActionLog
	}
	if alert.Module == "ransomware" {
		if action == ActionQuarantineFile {
			return false // Its file paths identify victims, not verified malicious artifacts.
		}
		if action == ActionKillProcess && (alert.Type == "data_exfiltration" || alert.Type == "compound_ransomware_prep") {
			return false
		}
	}
	return true
}

func (re *ResponseEngine) resolveTarget(alert *Alert, rule ResponseRule) string {
	if ip, ok := alert.Metadata["source_ip"].(string); ok && ip != "" {
		return ip
	}
	if pid, ok := alert.Metadata["process_id"].(string); ok && pid != "" {
		return pid
	}
	if path, ok := alert.Metadata["file_path"].(string); ok && path != "" {
		return path
	}
	return alert.ID
}

func (re *ResponseEngine) isAllowListed(policy *ResponsePolicy, sourceIP string) bool {
	if sourceIP == "" {
		return false
	}
	for _, allowed := range policy.AllowList {
		if allowed == sourceIP {
			return true
		}
	}
	if re.cfg.Enforcement != nil {
		for _, allowed := range re.cfg.Enforcement.GlobalAllowList {
			if allowed == sourceIP {
				return true
			}
		}
	}
	return false
}

func (re *ResponseEngine) isOnCooldown(key string, cooldown time.Duration) bool {
	if cooldown == 0 {
		return false
	}
	re.mu.RLock()
	defer re.mu.RUnlock()
	if last, ok := re.cooldowns[key]; ok {
		return time.Since(last) < cooldown
	}
	return false
}

func (re *ResponseEngine) setCooldown(key string, cooldown time.Duration) {
	if cooldown == 0 {
		return
	}
	re.mu.Lock()
	defer re.mu.Unlock()
	re.cooldowns[key] = time.Now()
}

func (re *ResponseEngine) checkRateLimit(module string, maxPerMin int) bool {
	if maxPerMin <= 0 {
		return true
	}
	re.mu.Lock()
	defer re.mu.Unlock()
	if time.Since(re.rateReset) > time.Minute {
		re.actionRate = make(map[string]int)
		re.rateReset = time.Now()
	}
	re.actionRate[module]++
	return re.actionRate[module] <= maxPerMin
}

func (re *ResponseEngine) recordAction(alert *Alert, rule ResponseRule, target string, status ActionStatus, details string, durationMs int64, err error) {
	record := &ResponseRecord{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC(),
		AlertID:    alert.ID,
		Module:     alert.Module,
		Action:     rule.Action,
		Status:     status,
		Severity:   alert.Severity.String(),
		Target:     target,
		Details:    details,
		DurationMs: durationMs,
	}
	if err != nil {
		record.Error = err.Error()
	}

	re.mu.Lock()
	if len(re.records) >= re.maxRecords {
		drop := re.maxRecords / 10
		re.records = re.records[drop:]
	}
	re.records = append(re.records, record)
	re.mu.Unlock()

	// Publish to bus for external consumption
	if re.bus != nil {
		data, err := json.Marshal(record)
		if err != nil {
			re.logger.Error().Err(err).Msg("failed to marshal response record for bus")
		} else {
			subject := fmt.Sprintf("sec.responses.%s.%s", alert.Module, string(rule.Action))
			if _, pubErr := re.bus.js.Publish(subject, data); pubErr != nil {
				re.logger.Error().Err(pubErr).Msg("failed to publish response record")
			}
		}
	}
}

// GetRecords returns recent response records, optionally filtered.
func (re *ResponseEngine) GetRecords(limit int, moduleFilter string) []*ResponseRecord {
	re.mu.RLock()
	defer re.mu.RUnlock()

	result := make([]*ResponseRecord, 0)
	count := 0
	for i := len(re.records) - 1; i >= 0 && count < limit; i-- {
		r := re.records[i]
		if moduleFilter != "" && r.Module != moduleFilter {
			continue
		}
		result = append(result, r)
		count++
	}
	return result
}

// FindRecord returns a single record by ID, or nil if not found.
func (re *ResponseEngine) FindRecord(id string) *ResponseRecord {
	re.mu.RLock()
	defer re.mu.RUnlock()

	for _, r := range re.records {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// HandleAlertForTest is an exported wrapper around handleAlert for use in tests
// from other packages (e.g., api tests). Not intended for production use.
func (re *ResponseEngine) HandleAlertForTest(alert *Alert) {
	re.handleAlert(alert)
}

// GetPolicies returns all loaded response policies.
func (re *ResponseEngine) GetPolicies() map[string]*ResponsePolicy {
	re.mu.RLock()
	defer re.mu.RUnlock()
	out := make(map[string]*ResponsePolicy, len(re.policies))
	for k, v := range re.policies {
		out[k] = v
	}
	return out
}

// SetPolicyEnabled enables or disables a module's response policy at runtime.
func (re *ResponseEngine) SetPolicyEnabled(module string, enabled bool) bool {
	re.mu.Lock()
	defer re.mu.Unlock()
	if p, ok := re.policies[module]; ok {
		p.Enabled = enabled
		return true
	}
	return false
}

// SetDryRun toggles dry-run mode for a module's policy at runtime.
func (re *ResponseEngine) SetDryRun(module string, dryRun bool) bool {
	re.mu.Lock()
	defer re.mu.Unlock()
	if p, ok := re.policies[module]; ok {
		p.DryRun = dryRun
		return true
	}
	return false
}

// Stats returns summary statistics for the response engine.
func (re *ResponseEngine) Stats() map[string]interface{} {
	re.mu.RLock()
	defer re.mu.RUnlock()

	byStatus := make(map[string]int)
	byModule := make(map[string]int)
	byAction := make(map[string]int)
	for _, r := range re.records {
		byStatus[string(r.Status)]++
		byModule[r.Module]++
		byAction[string(r.Action)]++
	}

	return map[string]interface{}{
		"total_records":  len(re.records),
		"total_policies": len(re.policies),
		"by_status":      byStatus,
		"by_module":      byModule,
		"by_action":      byAction,
	}
}

// findWebhookURLs extracts configured webhook URLs from a module's policy
// (and the wildcard policy) for use in approval gate notifications.
func (re *ResponseEngine) findWebhookURLs(module string) []string {
	re.mu.RLock()
	defer re.mu.RUnlock()

	seen := make(map[string]bool)
	var urls []string
	for _, policyKey := range []string{module, "*"} {
		if p, ok := re.policies[policyKey]; ok {
			for _, rule := range p.Actions {
				if rule.Action == ActionWebhook {
					if u := rule.Params["url"]; u != "" && !seen[u] {
						seen[u] = true
						urls = append(urls, u)
					}
				}
			}
		}
	}
	return urls
}

func (re *ResponseEngine) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			re.mu.Lock()
			// Purge expired cooldowns
			now := time.Now()
			for key, last := range re.cooldowns {
				if now.Sub(last) > 30*time.Minute {
					delete(re.cooldowns, key)
				}
			}
			re.mu.Unlock()
		}
	}
}
