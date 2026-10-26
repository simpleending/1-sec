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
// escalation.go — escalation timers for unacknowledged alerts.
//
// If a CRITICAL alert sits unacknowledged for 5 minutes, SOC teams need
// automatic escalation: bump severity, re-notify, page the on-call.
//
// Design:
//   - Watches alerts via pipeline handler
//   - Configurable timeout per severity level
//   - On timeout: escalates severity, fires EscalationHandler callbacks
//   - Respects acknowledgement — if alert is ACK'd, timer cancels
//   - Pure Go, zero external dependencies
// ---------------------------------------------------------------------------

// EscalationConfig controls escalation behavior.
type EscalationConfig struct {
	Enabled  bool                       `yaml:"enabled" json:"enabled"`
	Timeouts map[string]EscalationTimer `yaml:"timeouts" json:"timeouts"` // keyed by severity
}

// EscalationTimer defines timeout and action for a severity level.
type EscalationTimer struct {
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	EscalateTo     string        `yaml:"escalate_to" json:"escalate_to"` // target severity
	ReNotify       bool          `yaml:"re_notify" json:"re_notify"`
	MaxEscalations int           `yaml:"max_escalations" json:"max_escalations"`
}

// DefaultEscalationConfig returns sane defaults.
func DefaultEscalationConfig() EscalationConfig {
	return EscalationConfig{
		Enabled: false,
		Timeouts: map[string]EscalationTimer{
			"CRITICAL": {Timeout: 5 * time.Minute, EscalateTo: "CRITICAL", ReNotify: true, MaxEscalations: 3},
			"HIGH":     {Timeout: 15 * time.Minute, EscalateTo: "CRITICAL", ReNotify: true, MaxEscalations: 2},
			"MEDIUM":   {Timeout: 30 * time.Minute, EscalateTo: "HIGH", ReNotify: true, MaxEscalations: 1},
		},
	}
}

// EscalationEvent is emitted when an alert escalates.
type EscalationEvent struct {
	AlertID     string    `json:"alert_id"`
	Module      string    `json:"module"`
	OldSeverity string    `json:"old_severity"`
	NewSeverity string    `json:"new_severity"`
	EscalationN int       `json:"escalation_number"`
	Timestamp   time.Time `json:"timestamp"`
}

// EscalationHandler is called when an alert escalates.
type EscalationHandler func(event *EscalationEvent, alert *Alert)

type trackedAlert struct {
	alert       *Alert
	timer       *time.Timer
	escalations int
	cancel      context.CancelFunc
}

// EscalationManager watches unacknowledged alerts and escalates after timeout.
type EscalationManager struct {
	mu       sync.Mutex
	logger   zerolog.Logger
	cfg      EscalationConfig
	pipeline *AlertPipeline
	tracked  map[string]*trackedAlert // alert ID → tracked state
	handlers []EscalationHandler
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewEscalationManager creates a new escalation manager.
func NewEscalationManager(logger zerolog.Logger, cfg EscalationConfig, pipeline *AlertPipeline) *EscalationManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &EscalationManager{
		logger:   logger.With().Str("component", "escalation_manager").Logger(),
		cfg:      cfg,
		pipeline: pipeline,
		tracked:  make(map[string]*trackedAlert),
		handlers: make([]EscalationHandler, 0),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// AddHandler registers a callback for escalation events.
func (em *EscalationManager) AddHandler(handler EscalationHandler) {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.handlers = append(em.handlers, handler)
}

// Track begins watching an alert for escalation.
func (em *EscalationManager) Track(alert *Alert) {
	if !em.cfg.Enabled || alert.Type == "escalation" {
		return
	}

	sevStr := alert.Severity.String()
	timerCfg, ok := em.cfg.Timeouts[sevStr]
	if !ok {
		return // no escalation configured for this severity
	}

	em.mu.Lock()
	defer em.mu.Unlock()

	// Don't re-track already tracked alerts
	if _, exists := em.tracked[alert.ID]; exists {
		return
	}

	ctx, cancel := context.WithCancel(em.ctx)
	ta := &trackedAlert{
		alert:  alert,
		cancel: cancel,
	}

	ta.timer = time.AfterFunc(timerCfg.Timeout, func() {
		em.escalate(alert.ID, ctx)
	})

	em.tracked[alert.ID] = ta
	em.logger.Debug().
		Str("alert_id", alert.ID).
		Str("severity", sevStr).
		Dur("timeout", timerCfg.Timeout).
		Msg("alert tracked for escalation")
}

// Acknowledge cancels escalation for an alert (it's been handled).
func (em *EscalationManager) Acknowledge(alertID string) {
	em.mu.Lock()
	defer em.mu.Unlock()

	if ta, ok := em.tracked[alertID]; ok {
		ta.timer.Stop()
		ta.cancel()
		delete(em.tracked, alertID)
		em.logger.Debug().Str("alert_id", alertID).Msg("escalation cancelled — alert acknowledged")
	}
}

func (em *EscalationManager) escalate(alertID string, ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	em.mu.Lock()
	ta, ok := em.tracked[alertID]
	if !ok {
		em.mu.Unlock()
		return
	}

	// Check if alert has been acknowledged in the pipeline
	pipelineAlert := em.pipeline.GetAlertByID(alertID)
	if pipelineAlert == nil || pipelineAlert.Status != AlertStatusOpen {
		ta.timer.Stop()
		ta.cancel()
		delete(em.tracked, alertID)
		em.mu.Unlock()
		return
	}

	sevStr := ta.alert.Severity.String()
	timerCfg, ok := em.cfg.Timeouts[sevStr]
	if !ok {
		em.mu.Unlock()
		return
	}

	ta.escalations++
	if ta.escalations > timerCfg.MaxEscalations {
		ta.cancel()
		delete(em.tracked, alertID)
		em.mu.Unlock()
		em.logger.Warn().Str("alert_id", alertID).Int("escalations", ta.escalations-1).Msg("max escalations reached")
		return
	}

	oldSev := ta.alert.Severity
	newSev := ParseSeverity(timerCfg.EscalateTo)
	if newSev > ta.alert.Severity {
		ta.alert.Severity = newSev
		// Update in pipeline too
		if pipelineAlert != nil {
			pipelineAlert.Severity = newSev
		}
	}

	event := &EscalationEvent{
		AlertID:     alertID,
		Module:      ta.alert.Module,
		OldSeverity: oldSev.String(),
		NewSeverity: newSev.String(),
		EscalationN: ta.escalations,
		Timestamp:   time.Now().UTC(),
	}

	handlers := make([]EscalationHandler, len(em.handlers))
	copy(handlers, em.handlers)

	// Schedule next escalation if we haven't hit max
	if ta.escalations < timerCfg.MaxEscalations {
		ta.timer = time.AfterFunc(timerCfg.Timeout, func() {
			em.escalate(alertID, ctx)
		})
	} else {
		delete(em.tracked, alertID)
		defer ta.cancel()
	}

	em.mu.Unlock()

	em.logger.Warn().
		Str("alert_id", alertID).
		Str("module", ta.alert.Module).
		Str("old_severity", oldSev.String()).
		Str("new_severity", newSev.String()).
		Int("escalation", event.EscalationN).
		Msg("alert escalated — unacknowledged timeout")

	for _, handler := range handlers {
		handler(event, ta.alert)
	}

	// Re-process through pipeline if re-notify is enabled
	if timerCfg.ReNotify && em.pipeline != nil {
		escalationAlert := &Alert{
			ID:          uuid.New().String(),
			Timestamp:   time.Now().UTC(),
			Module:      ta.alert.Module,
			Type:        "escalation",
			Severity:    newSev,
			Status:      AlertStatusOpen,
			Title:       fmt.Sprintf("[ESCALATION #%d] %s", event.EscalationN, ta.alert.Title),
			Description: fmt.Sprintf("Alert %s was not acknowledged within %s. Escalated from %s to %s.", alertID, timerCfg.Timeout, oldSev.String(), newSev.String()),
			Metadata:    ta.alert.Metadata,
			Mitigations: ta.alert.Mitigations,
		}
		em.pipeline.Process(escalationAlert)
	}
}

// Stats returns current escalation state.
func (em *EscalationManager) Stats() map[string]interface{} {
	em.mu.Lock()
	defer em.mu.Unlock()

	tracked := make([]map[string]interface{}, 0, len(em.tracked))
	for id, ta := range em.tracked {
		tracked = append(tracked, map[string]interface{}{
			"alert_id":    id,
			"module":      ta.alert.Module,
			"severity":    ta.alert.Severity.String(),
			"escalations": ta.escalations,
		})
	}

	return map[string]interface{}{
		"enabled":        em.cfg.Enabled,
		"tracked_alerts": len(em.tracked),
		"alerts":         tracked,
	}
}

// Stop cancels all pending escalation timers.
func (em *EscalationManager) Stop() {
	em.cancel()
	em.mu.Lock()
	defer em.mu.Unlock()
	for _, ta := range em.tracked {
		ta.timer.Stop()
		ta.cancel()
	}
	em.tracked = make(map[string]*trackedAlert)
	em.logger.Info().Msg("escalation manager stopped")
}
