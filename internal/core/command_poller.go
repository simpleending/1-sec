package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// command_poller.go — polls the cloud dashboard for remote commands.
//
// The cloud dashboard (Netlify) stores commands in a queue (Netlify Blobs).
// This poller fetches pending commands, executes them locally, and ACKs back.
//
// Supported commands:
//   - approve:     approve a pending approval gate action
//   - reject:      reject a pending approval gate action
//   - rollback:    roll back a reversible enforcement action (block_ip → unblock)
//   - set_dry_run: toggle global dry-run mode on/off
//   - set_policy:  enable/disable a per-module enforcement policy
// ---------------------------------------------------------------------------

// CloudCommand mirrors the RemoteCommand type from the dashboard API.
type CloudCommand struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Status         string `json:"status"`
	CreatedAt      string `json:"createdAt"`
	ExpiresAt      string `json:"expiresAt"`
	IssuedBy       string `json:"issuedBy"`
	AcknowledgedAt string `json:"acknowledgedAt,omitempty"`
	ExecutedAt     string `json:"executedAt,omitempty"`
	Result         string `json:"result,omitempty"`
	Error          string `json:"error,omitempty"`
	// Command-specific fields
	ApprovalID       string   `json:"approvalId,omitempty"`
	RecordID         string   `json:"recordId,omitempty"`
	DryRun           *bool    `json:"dryRun,omitempty"`
	Module           string   `json:"module,omitempty"`
	Enabled          *bool    `json:"enabled,omitempty"`
	AutoApproveAbove *string  `json:"autoApproveAbove,omitempty"`
	RequireApproval  []string `json:"requireApproval,omitempty"`
}

// CloudCommandsResponse is the shape returned by GET /api/v1/commands?status=pending.
type CloudCommandsResponse struct {
	Commands []CloudCommand `json:"commands"`
}

// CommandPoller polls the cloud dashboard for pending commands and executes them.
type CommandPoller struct {
	cfg    *Config
	engine *Engine
	logger zerolog.Logger
	ctx    context.Context
	cancel context.CancelFunc
}

// NewCommandPoller creates a new command poller.
func NewCommandPoller(engine *Engine) *CommandPoller {
	ctx, cancel := context.WithCancel(context.Background())
	return &CommandPoller{
		cfg:    engine.Config,
		engine: engine,
		logger: engine.Logger.With().Str("component", "command_poller").Logger(),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins the polling loop.
func (cp *CommandPoller) Start() {
	if !cp.cfg.Cloud.Enabled || cp.cfg.Cloud.APIKey == "" {
		cp.logger.Info().Msg("command polling disabled (cloud not configured)")
		return
	}

	interval := cp.cfg.Cloud.CommandPollInterval
	if interval <= 0 {
		interval = 15 // default 15 seconds
	}

	cp.logger.Info().
		Int("poll_interval_seconds", interval).
		Msg("command polling started — dashboard can now send enforcement commands")

	go cp.pollLoop(time.Duration(interval) * time.Second)
}

// Stop terminates the command poller.
func (cp *CommandPoller) Stop() {
	if cp.cancel != nil {
		cp.cancel()
	}
}

func (cp *CommandPoller) pollLoop(interval time.Duration) {
	// Initial delay to let the engine fully start
	time.Sleep(10 * time.Second)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-cp.ctx.Done():
			return
		case <-ticker.C:
			cp.poll()
		}
	}
}

func (cp *CommandPoller) poll() {
	commands, err := cp.fetchPendingCommands()
	if err != nil {
		cp.logger.Debug().Err(err).Msg("failed to fetch pending commands")
		return
	}

	if len(commands) == 0 {
		return
	}

	cp.logger.Info().Int("count", len(commands)).Msg("received remote commands from dashboard")

	for _, cmd := range commands {
		// ACK immediately so the dashboard knows we picked it up
		if err := cp.ackCommand(cmd.ID, "acknowledged", "", ""); err != nil {
			cp.logger.Warn().Err(err).Str("cmd_id", cmd.ID).Msg("failed to ACK command")
			continue
		}

		// Execute the command
		result, execErr := cp.executeCommand(cmd)
		if execErr != nil {
			cp.logger.Warn().
				Err(execErr).
				Str("cmd_id", cmd.ID).
				Str("type", cmd.Type).
				Msg("remote command failed")
			_ = cp.ackCommand(cmd.ID, "failed", "", execErr.Error())
		} else {
			cp.logger.Info().
				Str("cmd_id", cmd.ID).
				Str("type", cmd.Type).
				Str("result", result).
				Str("issued_by", cmd.IssuedBy).
				Msg("remote command executed")
			_ = cp.ackCommand(cmd.ID, "executed", result, "")
		}
	}
}

func (cp *CommandPoller) fetchPendingCommands() ([]CloudCommand, error) {
	url := strings.TrimRight(cp.cfg.Cloud.APIURL, "/") + "/commands?status=pending"
	req, err := newAuthRequest("GET", url, nil, cp.cfg.Cloud.APIKey)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching commands: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("cloud API returned %d: %s", resp.StatusCode, string(body))
	}

	var result CloudCommandsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return result.Commands, nil
}

func (cp *CommandPoller) ackCommand(cmdID, status, result, errMsg string) error {
	payload := map[string]string{
		"id":     cmdID,
		"status": status,
	}
	if result != "" {
		payload["result"] = result
	}
	if errMsg != "" {
		payload["error"] = errMsg
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := strings.TrimRight(cp.cfg.Cloud.APIURL, "/") + "/commands"
	req, err := newAuthRequest("PATCH", url, body, cp.cfg.Cloud.APIKey)
	if err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("ACK returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (cp *CommandPoller) executeCommand(cmd CloudCommand) (string, error) {
	switch cmd.Type {
	case "approve":
		return cp.executeApprove(cmd)
	case "reject":
		return cp.executeReject(cmd)
	case "rollback":
		return cp.executeRollback(cmd)
	case "set_dry_run":
		return cp.executeSetDryRun(cmd)
	case "set_policy":
		return cp.executeSetPolicy(cmd)
	case "set_approval_config":
		return cp.executeSetApprovalConfig(cmd)
	default:
		return "", fmt.Errorf("unknown command type: %s", cmd.Type)
	}
}

func (cp *CommandPoller) executeApprove(cmd CloudCommand) (string, error) {
	re := cp.engine.ResponseEngine
	if re == nil {
		return "", fmt.Errorf("enforcement engine not configured")
	}

	if re.ApprovalGate == nil {
		return "", fmt.Errorf("approval gate not configured")
	}

	decidedBy := fmt.Sprintf("dashboard:%s", cmd.IssuedBy)
	pa, err := re.ApprovalGate.Approve(cmd.ApprovalID, decidedBy)
	if err != nil {
		return "", fmt.Errorf("approve failed: %w", err)
	}

	return fmt.Sprintf("approved action %s on %s (alert: %s)", pa.Action, pa.Target, pa.AlertID), nil
}

func (cp *CommandPoller) executeReject(cmd CloudCommand) (string, error) {
	re := cp.engine.ResponseEngine
	if re == nil {
		return "", fmt.Errorf("enforcement engine not configured")
	}

	if re.ApprovalGate == nil {
		return "", fmt.Errorf("approval gate not configured")
	}

	decidedBy := fmt.Sprintf("dashboard:%s", cmd.IssuedBy)
	pa, err := re.ApprovalGate.Reject(cmd.ApprovalID, decidedBy)
	if err != nil {
		return "", fmt.Errorf("reject failed: %w", err)
	}

	return fmt.Sprintf("rejected action %s on %s", pa.Action, pa.Target), nil
}

func (cp *CommandPoller) executeRollback(cmd CloudCommand) (string, error) {
	re := cp.engine.ResponseEngine
	if re == nil {
		return "", fmt.Errorf("enforcement engine not configured")
	}

	record := re.FindRecord(cmd.RecordID)
	if record == nil {
		return "", fmt.Errorf("enforcement record %s not found", cmd.RecordID)
	}

	if record.Status != ActionStatusSuccess {
		return "", fmt.Errorf("can only roll back successful actions (current status: %s)", record.Status)
	}

	// Execute rollback based on action type
	switch record.Action {
	case ActionBlockIP:
		ip := record.Target
		if ip == "" {
			return "", fmt.Errorf("no target IP to unblock")
		}
		unblockIP(ip, cp.logger)
		record.Status = ActionStatusSkipped // mark as rolled back
		return fmt.Sprintf("unblocked IP %s (record %s)", ip, cmd.RecordID), nil

	default:
		return "", fmt.Errorf("rollback not supported for action type: %s — use CLI for manual rollback", record.Action)
	}
}

func (cp *CommandPoller) executeSetDryRun(cmd CloudCommand) (string, error) {
	cfg := cp.engine.Config.Enforcement
	if cfg == nil {
		return "", fmt.Errorf("enforcement not configured")
	}

	if cmd.DryRun == nil {
		return "", fmt.Errorf("dryRun value missing")
	}

	previous := cfg.GetDryRun()
	cfg.SetDryRun(*cmd.DryRun)

	cp.logger.Warn().
		Bool("previous", previous).
		Bool("new", *cmd.DryRun).
		Str("issued_by", cmd.IssuedBy).
		Msg("enforcement dry-run toggled via dashboard command")

	mode := "disabled (enforcement is LIVE)"
	if *cmd.DryRun {
		mode = "enabled (simulation mode)"
	}
	return fmt.Sprintf("dry-run %s (was: %v)", mode, previous), nil
}

func (cp *CommandPoller) executeSetPolicy(cmd CloudCommand) (string, error) {
	re := cp.engine.ResponseEngine
	if re == nil {
		return "", fmt.Errorf("enforcement engine not configured")
	}

	if cmd.Enabled == nil {
		return "", fmt.Errorf("enabled value missing")
	}

	module := strings.TrimSpace(cmd.Module)
	if module == "" {
		return "", fmt.Errorf("module name missing")
	}

	if re.SetPolicyEnabled(module, *cmd.Enabled) {
		cp.logger.Warn().
			Str("module", module).
			Bool("enabled", *cmd.Enabled).
			Str("issued_by", cmd.IssuedBy).
			Msg("enforcement policy toggled via dashboard command")

		state := "disabled"
		if *cmd.Enabled {
			state = "enabled"
		}
		return fmt.Sprintf("policy for %s %s", module, state), nil
	}

	return "", fmt.Errorf("no policy found for module: %s", module)
}

func (cp *CommandPoller) executeSetApprovalConfig(cmd CloudCommand) (string, error) {
	cfg := cp.engine.Config.Enforcement
	if cfg == nil {
		return "", fmt.Errorf("enforcement not configured")
	}

	if !cfg.ApprovalGate.Enabled {
		return "", fmt.Errorf("approval gate not enabled")
	}

	changes := make([]string, 0, 2)

	if cmd.AutoApproveAbove != nil {
		validSeverities := map[string]bool{"": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
		val := strings.ToUpper(*cmd.AutoApproveAbove)
		if !validSeverities[val] {
			return "", fmt.Errorf("invalid auto_approve_above value: %s", *cmd.AutoApproveAbove)
		}
		cfg.ApprovalGate.AutoApproveAbove = val
		if val == "" {
			changes = append(changes, "auto_approve_above disabled")
		} else {
			changes = append(changes, "auto_approve_above set to "+val)
		}
	}

	if cmd.RequireApproval != nil {
		validActions := map[string]bool{
			"block_ip": true, "kill_process": true, "quarantine_file": true,
			"drop_connection": true, "disable_user": true, "webhook": true,
			"command": true, "log_only": true,
		}
		for _, a := range cmd.RequireApproval {
			if !validActions[a] {
				return "", fmt.Errorf("unknown action in require_approval: %s", a)
			}
		}
		cfg.ApprovalGate.RequireApproval = cmd.RequireApproval
		changes = append(changes, fmt.Sprintf("require_approval updated (%d actions)", len(cmd.RequireApproval)))
	}

	if len(changes) == 0 {
		return "", fmt.Errorf("no changes specified (provide autoApproveAbove or requireApproval)")
	}

	cp.logger.Warn().
		Strs("changes", changes).
		Str("issued_by", cmd.IssuedBy).
		Msg("approval gate config updated via dashboard command")

	return fmt.Sprintf("approval config updated: %s", strings.Join(changes, ", ")), nil
}
