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
// action_chain.go — conditional action chaining (basic playbook logic).
//
// SOC teams need "if action A succeeds, do B; if it fails, do C" logic.
// This is the building block for automated playbooks without an external
// orchestrator.
//
// Design:
//   - ActionChain defines a sequence of steps with on_success/on_failure
//   - Each step references an ActionType + params
//   - ChainExecutor runs chains against alerts using registered executors
//   - Execution records kept for audit trail
//   - Pure Go, zero external dependencies
// ---------------------------------------------------------------------------

// ChainStep defines a single step in an action chain.
type ChainStep struct {
	Name       string            `json:"name" yaml:"name"`
	Action     ActionType        `json:"action" yaml:"action"`
	Params     map[string]string `json:"params,omitempty" yaml:"params"`
	OnSuccess  string            `json:"on_success,omitempty" yaml:"on_success"` // next step name
	OnFailure  string            `json:"on_failure,omitempty" yaml:"on_failure"` // next step name on failure
	MaxRetries int               `json:"max_retries,omitempty" yaml:"max_retries"`
	Timeout    time.Duration     `json:"timeout,omitempty" yaml:"timeout"`
}

// ActionChain defines a named sequence of conditional steps.
type ActionChain struct {
	Name        string      `json:"name" yaml:"name"`
	Description string      `json:"description,omitempty" yaml:"description"`
	Steps       []ChainStep `json:"steps" yaml:"steps"`
	EntryPoint  string      `json:"entry_point" yaml:"entry_point"` // first step name
}

// ChainExecutionRecord tracks the result of a chain execution.
type ChainExecutionRecord struct {
	ID         string                `json:"id"`
	ChainName  string                `json:"chain_name"`
	AlertID    string                `json:"alert_id"`
	StartedAt  time.Time             `json:"started_at"`
	FinishedAt time.Time             `json:"finished_at"`
	Status     string                `json:"status"` // "completed", "failed", "partial"
	Steps      []StepExecutionRecord `json:"steps"`
}

// StepExecutionRecord tracks a single step's execution.
type StepExecutionRecord struct {
	StepName   string       `json:"step_name"`
	Action     ActionType   `json:"action"`
	Status     ActionStatus `json:"status"`
	Target     string       `json:"target"`
	Details    string       `json:"details"`
	Error      string       `json:"error,omitempty"`
	DurationMs int64        `json:"duration_ms"`
	NextStep   string       `json:"next_step,omitempty"`
}

// ChainExecutor runs action chains against alerts.
type ChainExecutor struct {
	mu         sync.RWMutex
	logger     zerolog.Logger
	chains     map[string]*ActionChain
	executors  map[ActionType]ActionExecutor
	records    []*ChainExecutionRecord
	maxRecords int
}

// NewChainExecutor creates a new chain executor.
func NewChainExecutor(logger zerolog.Logger, executors map[ActionType]ActionExecutor) *ChainExecutor {
	return &ChainExecutor{
		logger:     logger.With().Str("component", "chain_executor").Logger(),
		chains:     make(map[string]*ActionChain),
		executors:  executors,
		records:    make([]*ChainExecutionRecord, 0, 500),
		maxRecords: 500,
	}
}

// RegisterChain adds an action chain.
func (ce *ChainExecutor) RegisterChain(chain *ActionChain) error {
	if chain.Name == "" {
		return fmt.Errorf("chain must have a name")
	}
	if len(chain.Steps) == 0 {
		return fmt.Errorf("chain %q has no steps", chain.Name)
	}

	// Validate entry point exists
	stepMap := make(map[string]*ChainStep)
	for i := range chain.Steps {
		stepMap[chain.Steps[i].Name] = &chain.Steps[i]
	}

	entry := chain.EntryPoint
	if entry == "" {
		entry = chain.Steps[0].Name
		chain.EntryPoint = entry
	}
	if _, ok := stepMap[entry]; !ok {
		return fmt.Errorf("chain %q entry point %q not found in steps", chain.Name, entry)
	}

	// Validate step references
	for _, step := range chain.Steps {
		if step.OnSuccess != "" {
			if _, ok := stepMap[step.OnSuccess]; !ok {
				return fmt.Errorf("chain %q step %q references unknown on_success step %q", chain.Name, step.Name, step.OnSuccess)
			}
		}
		if step.OnFailure != "" {
			if _, ok := stepMap[step.OnFailure]; !ok {
				return fmt.Errorf("chain %q step %q references unknown on_failure step %q", chain.Name, step.Name, step.OnFailure)
			}
		}
	}

	ce.mu.Lock()
	ce.chains[chain.Name] = chain
	ce.mu.Unlock()

	ce.logger.Info().Str("chain", chain.Name).Int("steps", len(chain.Steps)).Msg("action chain registered")
	return nil
}

// Execute runs a named chain against an alert.
func (ce *ChainExecutor) Execute(ctx context.Context, chainName string, alert *Alert, logger zerolog.Logger) (*ChainExecutionRecord, error) {
	ce.mu.RLock()
	chain, ok := ce.chains[chainName]
	ce.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("chain %q not found", chainName)
	}

	record := &ChainExecutionRecord{
		ID:        uuid.New().String(),
		ChainName: chainName,
		AlertID:   alert.ID,
		StartedAt: time.Now().UTC(),
		Steps:     make([]StepExecutionRecord, 0),
	}

	// Build step lookup
	stepMap := make(map[string]*ChainStep)
	for i := range chain.Steps {
		stepMap[chain.Steps[i].Name] = &chain.Steps[i]
	}

	currentStep := chain.EntryPoint
	maxSteps := len(chain.Steps) * 3 // prevent infinite loops
	stepsExecuted := 0

	for currentStep != "" && stepsExecuted < maxSteps {
		stepsExecuted++
		step, ok := stepMap[currentStep]
		if !ok {
			record.Status = "failed"
			record.FinishedAt = time.Now().UTC()
			break
		}

		stepRecord := ce.executeStep(ctx, step, alert, logger)
		record.Steps = append(record.Steps, stepRecord)

		if stepRecord.Status == ActionStatusSuccess {
			currentStep = step.OnSuccess
			stepRecord.NextStep = step.OnSuccess
		} else {
			currentStep = step.OnFailure
			stepRecord.NextStep = step.OnFailure
		}
	}

	// Determine overall status
	allSuccess := true
	anySuccess := false
	for _, sr := range record.Steps {
		if sr.Status == ActionStatusSuccess {
			anySuccess = true
		} else {
			allSuccess = false
		}
	}

	if allSuccess {
		record.Status = "completed"
	} else if anySuccess {
		record.Status = "partial"
	} else {
		record.Status = "failed"
	}

	record.FinishedAt = time.Now().UTC()

	// Store record
	ce.mu.Lock()
	if len(ce.records) >= ce.maxRecords {
		ce.records = ce.records[ce.maxRecords/10:]
	}
	ce.records = append(ce.records, record)
	ce.mu.Unlock()

	ce.logger.Info().
		Str("chain", chainName).
		Str("alert_id", alert.ID).
		Str("status", record.Status).
		Int("steps", len(record.Steps)).
		Msg("action chain completed")

	return record, nil
}

func (ce *ChainExecutor) executeStep(ctx context.Context, step *ChainStep, alert *Alert, logger zerolog.Logger) StepExecutionRecord {
	if !responseActionAllowed(alert, step.Action) {
		return StepExecutionRecord{StepName: step.Name, Action: step.Action, Status: ActionStatusSkipped, Error: "alert does not authorize this action"}
	}
	executor, ok := ce.executors[step.Action]
	if !ok {
		return StepExecutionRecord{
			StepName: step.Name,
			Action:   step.Action,
			Status:   ActionStatusFailed,
			Error:    fmt.Sprintf("no executor for action %s", step.Action),
		}
	}

	rule := ResponseRule{
		Action: step.Action,
		Params: step.Params,
	}

	timeout := step.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	stepCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	retries := step.MaxRetries
	if retries <= 0 {
		retries = 0
	}

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		start := time.Now()
		target, details, err := executor.Execute(stepCtx, alert, rule, logger)
		durationMs := time.Since(start).Milliseconds()

		if err == nil {
			return StepExecutionRecord{
				StepName:   step.Name,
				Action:     step.Action,
				Status:     ActionStatusSuccess,
				Target:     target,
				Details:    details,
				DurationMs: durationMs,
			}
		}

		lastErr = err
		if attempt < retries {
			ce.logger.Debug().
				Str("step", step.Name).
				Int("attempt", attempt+1).
				Err(err).
				Msg("step failed, retrying")
		}
	}

	return StepExecutionRecord{
		StepName: step.Name,
		Action:   step.Action,
		Status:   ActionStatusFailed,
		Error:    lastErr.Error(),
	}
}

// GetChains returns all registered chains.
func (ce *ChainExecutor) GetChains() map[string]*ActionChain {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	out := make(map[string]*ActionChain, len(ce.chains))
	for k, v := range ce.chains {
		out[k] = v
	}
	return out
}

// GetRecords returns recent chain execution records.
func (ce *ChainExecutor) GetRecords(limit int) []*ChainExecutionRecord {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	if limit <= 0 || limit > len(ce.records) {
		limit = len(ce.records)
	}
	start := len(ce.records) - limit
	if start < 0 {
		start = 0
	}
	result := make([]*ChainExecutionRecord, 0, limit)
	for i := start; i < len(ce.records); i++ {
		result = append(result, ce.records[i])
	}
	return result
}

// Stats returns chain executor statistics.
func (ce *ChainExecutor) Stats() map[string]interface{} {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	byStatus := make(map[string]int)
	for _, r := range ce.records {
		byStatus[r.Status]++
	}

	return map[string]interface{}{
		"registered_chains": len(ce.chains),
		"total_executions":  len(ce.records),
		"by_status":         byStatus,
	}
}
