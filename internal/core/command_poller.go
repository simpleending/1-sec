package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
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
	InstanceID     string `json:"instanceId"`
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
	Commands   []CloudCommand `json:"commands"`
	NextCursor string         `json:"nextCursor"`
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
	if !cp.cfg.Cloud.Enabled || cp.cfg.Cloud.APIKey == "" || !cp.cfg.Cloud.RemoteCommandsEnabled || cp.cfg.Cloud.InstanceID == "" {
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
	select {
	case <-cp.ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}

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
	if !cp.cfg.Cloud.RemoteCommandsEnabled || !cp.cfg.Cloud.Enabled || cp.cfg.Cloud.InstanceID == "" {
		return
	}
	commands, err := cp.fetchPendingCommands()
	if err != nil {
		cp.logger.Debug().Err(err).Msg("failed to fetch pending commands")
		return
	}

	if len(commands) == 0 {
		return
	}

	cp.logger.Info().Int("count", len(commands)).Msg("received remote commands from dashboard")
	sort.SliceStable(commands, func(i, j int) bool { return commands[i].CreatedAt < commands[j].CreatedAt })

	for _, cmd := range commands {
		expires, parseErr := time.Parse(time.RFC3339, cmd.ExpiresAt)
		if cmd.InstanceID != cp.cfg.Cloud.InstanceID || cmd.Status != "pending" || parseErr != nil || !time.Now().Before(expires) {
			continue
		}
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			continue
		}
		token := base64.RawURLEncoding.EncodeToString(random[:])
		// ACK immediately so the dashboard knows we picked it up
		if err := cp.ackCommand(cmd.ID, "acknowledged", "", "", token); err != nil {
			cp.logger.Warn().Err(err).Str("cmd_id", cmd.ID).Msg("failed to ACK command")
			continue
		}

		// Do not execute a command that expired or was disabled while claiming it.
		if !cp.cfg.Cloud.RemoteCommandsEnabled || !time.Now().Before(expires) {
			_ = cp.ackCommand(cmd.ID, "failed", "", "Remote control disabled or command expired before execution", token)
			continue
		}
		result, execErr := cp.executeCommand(cmd)
		if execErr != nil {
			cp.logger.Warn().
				Err(execErr).
				Str("cmd_id", cmd.ID).
				Str("type", cmd.Type).
				Msg("remote command failed")
			_ = cp.ackCommand(cmd.ID, "failed", "", execErr.Error(), token)
		} else {
			cp.logger.Info().
				Str("cmd_id", cmd.ID).
				Str("type", cmd.Type).
				Str("result", result).
				Str("issued_by", cmd.IssuedBy).
				Msg("remote command executed")
			_ = cp.ackCommand(cmd.ID, "executed", result, "", token)
		}
	}
}

func (cp *CommandPoller) fetchPendingCommands() ([]CloudCommand, error) {
	ctx, cancel := context.WithTimeout(cp.ctx, 30*time.Second)
	defer cancel()
	query := url.Values{"status": {"pending"}, "instanceId": {cp.cfg.Cloud.InstanceID}, "limit": {"200"}}
	var commands []CloudCommand
	seen := make(map[string]bool)
	for {
		endpoint := strings.TrimRight(cp.cfg.Cloud.APIURL, "/") + "/commands?" + query.Encode()
		req, err := newAuthRequest("GET", endpoint, nil, cp.cfg.Cloud.APIKey)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		resp, err := httpClient.Do(req.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("fetching commands: %w", err)
		}
		var page CloudCommandsResponse
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("cloud API returned %d", resp.StatusCode)
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decoding response: %w", err)
		}
		commands = append(commands, page.Commands...)
		if page.NextCursor == "" {
			break
		}
		if seen[page.NextCursor] {
			return nil, fmt.Errorf("repeated command pagination cursor")
		}
		seen[page.NextCursor] = true
		query.Set("cursor", page.NextCursor)
	}
	return commands, nil
}

func (cp *CommandPoller) ackCommand(cmdID, status, result, errMsg string, claimToken ...string) error {
	payload := map[string]string{
		"id":         cmdID,
		"status":     status,
		"instanceId": cp.cfg.Cloud.InstanceID,
	}
	if len(claimToken) == 1 {
		payload["claimToken"] = claimToken[0]
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
	if !cfg.GetApprovalGate().Enabled {
		return "", fmt.Errorf("approval gate not enabled")
	}
	if cmd.AutoApproveAbove == nil && cmd.RequireApproval == nil {
		return "", fmt.Errorf("no approval settings supplied")
	}
	var gate *ApprovalGate
	if cp.engine.ResponseEngine != nil {
		gate = cp.engine.ResponseEngine.ApprovalGate
	}
	if err := UpdateApprovalSettings(cfg, gate, cmd.AutoApproveAbove, cmd.RequireApproval); err != nil {
		return "", err
	}
	cp.logger.Warn().Str("issued_by", cmd.IssuedBy).Msg("approval gate configuration updated")
	return "approval configuration updated on the live gate; edit config to persist across restart", nil
}
