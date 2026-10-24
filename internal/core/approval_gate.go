package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// approval_gate.go — human approval gate for destructive response actions.
//
// Actions like kill_process, quarantine_file, disable_user are irreversible.
// SOC teams need a human-in-the-loop before these fire in production.
//
// Design:
//   - Configurable list of actions requiring approval
//   - Pending actions held in memory with configurable TTL
//   - API endpoints for approve/reject (handled in enforce_handlers.go)
//   - Auto-expire after TTL (default 30 minutes)
//   - Pure Go, zero external dependencies
// ---------------------------------------------------------------------------

// ApprovalGateConfig controls which actions need human approval.
type ApprovalGateConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	RequireApproval  []string      `yaml:"require_approval" json:"require_approval"`                         // action types
	AutoApproveAbove string        `yaml:"auto_approve_above,omitempty" json:"auto_approve_above,omitempty"` // severity threshold: auto-approve at or above this level
	TTL              time.Duration `yaml:"ttl" json:"ttl"`
	MaxPending       int           `yaml:"max_pending" json:"max_pending"`
}

// DefaultApprovalGateConfig returns sane defaults.
func DefaultApprovalGateConfig() ApprovalGateConfig {
	return ApprovalGateConfig{
		Enabled:         false,
		RequireApproval: []string{"kill_process", "quarantine_file", "disable_user"},
		TTL:             30 * time.Minute,
		MaxPending:      100,
	}
}

// PendingApproval represents an action awaiting human approval.
type PendingApproval struct {
	ID        string       `json:"id"`
	AlertID   string       `json:"alert_id"`
	Module    string       `json:"module"`
	Action    ActionType   `json:"action"`
	Target    string       `json:"target"`
	Rule      ResponseRule `json:"rule"`
	Alert     *Alert       `json:"alert"`
	CreatedAt time.Time    `json:"created_at"`
	ExpiresAt time.Time    `json:"expires_at"`
	Status    string       `json:"status"` // "pending", "approved", "rejected", "expired"
	DecidedBy string       `json:"decided_by,omitempty"`
	DecidedAt *time.Time   `json:"decided_at,omitempty"`
}

// ApprovalHandler is called when an action is approved and should be executed.
type ApprovalHandler func(approval *PendingApproval)

// ApprovalGate holds destructive actions pending human approval.
type ApprovalGate struct {
	mu       sync.Mutex
	logger   zerolog.Logger
	cfg      ApprovalGateConfig
	pending  map[string]*PendingApproval
	history  []*PendingApproval
	handlers []ApprovalHandler
	notifyFn func(pa *PendingApproval) // called when action enters pending state
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewApprovalGate creates a new approval gate.
func NewApprovalGate(logger zerolog.Logger, cfg ApprovalGateConfig) *ApprovalGate {
	ctx, cancel := context.WithCancel(context.Background())
	ag := &ApprovalGate{
		logger:   logger.With().Str("component", "approval_gate").Logger(),
		cfg:      cfg,
		pending:  make(map[string]*PendingApproval),
		history:  make([]*PendingApproval, 0, 100),
		handlers: make([]ApprovalHandler, 0),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Start expiry checker
	go ag.expiryLoop()

	return ag
}

// AddHandler registers a callback for when actions are approved.
func (ag *ApprovalGate) AddHandler(handler ApprovalHandler) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	ag.handlers = append(ag.handlers, handler)
}

// SetNotifyFunc registers a callback invoked when an action enters the pending
// state. Use this to send webhook notifications so SOC teams know a decision
// is needed before the TTL expires.
func (ag *ApprovalGate) SetNotifyFunc(fn func(pa *PendingApproval)) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	ag.notifyFn = fn
}

// RequiresApproval checks if an action type needs human approval.
// It considers the global require list, per-rule skip_approval flag,
// and the auto_approve_above severity threshold.
func (ag *ApprovalGate) RequiresApproval(action ActionType) bool {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	if !ag.cfg.Enabled {
		return false
	}
	for _, a := range ag.cfg.RequireApproval {
		if a == string(action) {
			return true
		}
	}
	return false
}

// RequiresApprovalForRule is the full decision: considers the rule's
// SkipApproval flag and the severity-based auto-approve threshold.
func (ag *ApprovalGate) RequiresApprovalForRule(action ActionType, severity Severity, skipApproval bool) bool {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	if !ag.cfg.Enabled {
		return false
	}

	// Per-rule skip_approval overrides the gate entirely
	if skipApproval {
		return false
	}

	// Check if this action type is in the require list at all
	found := false
	for _, a := range ag.cfg.RequireApproval {
		if a == string(action) {
			found = true
			break
		}
	}
	if !found {
		return false
	}

	// Severity-based auto-approve: if alert severity >= threshold, skip approval
	if ag.cfg.AutoApproveAbove != "" {
		threshold := ParseSeverity(ag.cfg.AutoApproveAbove)
		if severity >= threshold {
			return false
		}
	}

	return true
}

// Submit holds an action for approval. Returns the pending approval ID.
func (ag *ApprovalGate) Submit(alert *Alert, rule ResponseRule, target string) string {
	ag.mu.Lock()

	// Enforce max pending limit
	if len(ag.pending) >= ag.cfg.MaxPending {
		ag.logger.Warn().Msg("approval gate at capacity — oldest pending action will be expired")
		ag.expireOldest()
	}

	id := uuid.New().String()
	pa := &PendingApproval{
		ID:        id,
		AlertID:   alert.ID,
		Module:    alert.Module,
		Action:    rule.Action,
		Target:    target,
		Rule:      rule,
		Alert:     alert,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(ag.cfg.TTL),
		Status:    "pending",
	}

	ag.pending[id] = pa
	ag.logger.Warn().
		Str("approval_id", id).
		Str("alert_id", alert.ID).
		Str("action", string(rule.Action)).
		Str("target", target).
		Time("expires_at", pa.ExpiresAt).
		Msg("⚠ action held for human approval")

	notifyFn := ag.notifyFn
	ag.mu.Unlock()

	// Notify SOC team asynchronously that a decision is needed
	if notifyFn != nil {
		go notifyFn(pa)
	}

	return id
}

// Approve approves a pending action and triggers execution.
func (ag *ApprovalGate) Approve(id string, decidedBy string) (*PendingApproval, error) {
	ag.mu.Lock()
	pa, ok := ag.pending[id]
	if !ok {
		ag.mu.Unlock()
		return nil, fmt.Errorf("pending approval %s not found", id)
	}

	if pa.Status != "pending" {
		ag.mu.Unlock()
		return nil, fmt.Errorf("approval %s already %s", id, pa.Status)
	}

	now := time.Now().UTC()
	pa.Status = "approved"
	pa.DecidedBy = decidedBy
	pa.DecidedAt = &now

	delete(ag.pending, id)
	ag.history = append(ag.history, pa)

	handlers := make([]ApprovalHandler, len(ag.handlers))
	copy(handlers, ag.handlers)
	ag.mu.Unlock()

	ag.logger.Info().
		Str("approval_id", id).
		Str("action", string(pa.Action)).
		Str("decided_by", decidedBy).
		Msg("action approved — executing")

	for _, handler := range handlers {
		handler(pa)
	}

	return pa, nil
}

// Reject rejects a pending action.
func (ag *ApprovalGate) Reject(id string, decidedBy string) (*PendingApproval, error) {
	ag.mu.Lock()
	defer ag.mu.Unlock()

	pa, ok := ag.pending[id]
	if !ok {
		return nil, fmt.Errorf("pending approval %s not found", id)
	}

	if pa.Status != "pending" {
		return nil, fmt.Errorf("approval %s already %s", id, pa.Status)
	}

	now := time.Now().UTC()
	pa.Status = "rejected"
	pa.DecidedBy = decidedBy
	pa.DecidedAt = &now

	delete(ag.pending, id)
	ag.history = append(ag.history, pa)

	ag.logger.Info().
		Str("approval_id", id).
		Str("action", string(pa.Action)).
		Str("decided_by", decidedBy).
		Msg("action rejected")

	return pa, nil
}

// GetPending returns all pending approvals.
func (ag *ApprovalGate) GetPending() []*PendingApproval {
	ag.mu.Lock()
	defer ag.mu.Unlock()

	result := make([]*PendingApproval, 0, len(ag.pending))
	for _, pa := range ag.pending {
		result = append(result, pa)
	}
	return result
}

// GetHistory returns recent approval decisions.
func (ag *ApprovalGate) GetHistory(limit int) []*PendingApproval {
	ag.mu.Lock()
	defer ag.mu.Unlock()

	if limit <= 0 || limit > len(ag.history) {
		limit = len(ag.history)
	}
	start := len(ag.history) - limit
	if start < 0 {
		start = 0
	}
	result := make([]*PendingApproval, 0, limit)
	for i := start; i < len(ag.history); i++ {
		result = append(result, ag.history[i])
	}
	return result
}

// Stats returns approval gate statistics.
func (ag *ApprovalGate) Stats() map[string]interface{} {
	ag.mu.Lock()
	defer ag.mu.Unlock()

	approved := 0
	rejected := 0
	expired := 0
	for _, pa := range ag.history {
		switch pa.Status {
		case "approved":
			approved++
		case "rejected":
			rejected++
		case "expired":
			expired++
		}
	}

	return map[string]interface{}{
		"enabled":            ag.cfg.Enabled,
		"pending_count":      len(ag.pending),
		"max_pending":        ag.cfg.MaxPending,
		"ttl_seconds":        ag.cfg.TTL.Seconds(),
		"require_approval":   ag.cfg.RequireApproval,
		"auto_approve_above": ag.cfg.AutoApproveAbove,
		"total_approved":     approved,
		"total_rejected":     rejected,
		"total_expired":      expired,
	}
}

func (ag *ApprovalGate) expireOldest() {
	var oldest *PendingApproval
	for _, pa := range ag.pending {
		if oldest == nil || pa.CreatedAt.Before(oldest.CreatedAt) {
			oldest = pa
		}
	}
	if oldest != nil {
		now := time.Now().UTC()
		oldest.Status = "expired"
		oldest.DecidedAt = &now
		delete(ag.pending, oldest.ID)
		ag.history = append(ag.history, oldest)
	}
}

func (ag *ApprovalGate) expiryLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ag.ctx.Done():
			return
		case <-ticker.C:
			ag.mu.Lock()
			now := time.Now()
			for id, pa := range ag.pending {
				if now.After(pa.ExpiresAt) {
					pa.Status = "expired"
					expTime := now.UTC()
					pa.DecidedAt = &expTime
					delete(ag.pending, id)
					ag.history = append(ag.history, pa)
					ag.logger.Warn().
						Str("approval_id", id).
						Str("action", string(pa.Action)).
						Msg("pending approval expired")
				}
			}
			ag.mu.Unlock()
		}
	}
}

// Stop shuts down the approval gate.
func (ag *ApprovalGate) Stop() {
	ag.cancel()
	ag.logger.Info().Msg("approval gate stopped")
}
