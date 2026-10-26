package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// shellUnsafe matches characters that could be used for shell injection.
var shellUnsafe = regexp.MustCompile(`[;&|$` + "`" + `\\'"(){}<>\n\r!#~]`)

// sanitizeShellArg strips shell metacharacters from a string before it is
// interpolated into a command template. This prevents attacker-controlled
// alert fields (e.g., title, source_ip) from injecting arbitrary commands.
// Also strips null bytes and limits length to prevent abuse.
func sanitizeShellArg(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = shellUnsafe.ReplaceAllString(s, "_")
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

// validateWebhookURL checks that a webhook URL is a valid HTTPS (or HTTP for
// local dev) endpoint. Returns an error if the URL is empty, unparseable,
// uses a dangerous scheme, or points to a private/loopback address (SSRF).
func validateWebhookURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("webhook URL is empty — configure the 'url' param in your enforcement policy")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("webhook URL must use http or https scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook URL has no host: %q", rawURL)
	}
	// Block private/loopback addresses to prevent SSRF
	host := u.Hostname()
	if isPrivateHost(host) {
		return fmt.Errorf("webhook URL must not point to private or loopback addresses: %q", host)
	}
	return nil
}

// isPrivateHost returns true if the host is a loopback, private, or link-local address.
func isPrivateHost(host string) bool {
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || strings.HasSuffix(lower, ".local") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // hostname — can't check statically, but DNS rebinding is a separate concern
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// validateIPAddress checks that a string is a valid IPv4 or IPv6 address
// and is not a reserved/broadcast/multicast address that should never be blocked.
func validateIPAddress(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}
	if parsed.IsUnspecified() {
		return fmt.Errorf("cannot target unspecified address: %q", ip)
	}
	if parsed.IsMulticast() {
		return fmt.Errorf("cannot target multicast address: %q", ip)
	}
	if parsed.IsLoopback() {
		return fmt.Errorf("cannot target loopback address: %q", ip)
	}
	// Block broadcast 255.255.255.255
	if parsed.Equal(net.IPv4bcast) {
		return fmt.Errorf("cannot target broadcast address: %q", ip)
	}
	return nil
}

// safeProcessName matches only safe process name characters (alphanumeric, dots, dashes, underscores).
var safeProcessName = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

// validateProcessName checks that a process name contains only safe characters.
func validateProcessName(name string) error {
	if !safeProcessName.MatchString(name) {
		return fmt.Errorf("invalid process name (must be alphanumeric/dots/dashes/underscores): %q", name)
	}
	return nil
}

// validatePID checks that a process ID is a positive integer.
func validatePID(pid string) error {
	n, err := strconv.Atoi(pid)
	if err != nil || n <= 0 {
		return fmt.Errorf("invalid process ID (must be a positive integer): %q", pid)
	}
	return nil
}

// ---------------------------------------------------------------------------
// BlockIPExecutor — adds IP to system firewall deny rules
// ---------------------------------------------------------------------------

type BlockIPExecutor struct{}

func (e *BlockIPExecutor) Validate(rule ResponseRule) error {
	return nil
}

func (e *BlockIPExecutor) Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (string, string, error) {
	ip, _ := alert.Metadata["source_ip"].(string)
	if ip == "" {
		return "", "", fmt.Errorf("no source_ip in alert metadata")
	}
	if err := validateIPAddress(ip); err != nil {
		return "", "", fmt.Errorf("BlockIPExecutor: %w", err)
	}

	duration := rule.Params["duration"]
	if duration == "" {
		duration = "1h"
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// Use iptables to block the IP
		cmd = exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	case "darwin":
		cmd = exec.CommandContext(ctx, "pfctl", "-t", "1sec_blocked", "-T", "add", ip)
	case "windows":
		ruleName := fmt.Sprintf("1SEC-Block-%s", strings.ReplaceAll(ip, ".", "-"))
		cmd = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=in", "action=block", "remoteip="+ip)
	default:
		return ip, "", fmt.Errorf("unsupported OS for IP blocking: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()
	details := fmt.Sprintf("blocked IP %s for %s (os=%s)", ip, duration, runtime.GOOS)
	if err != nil {
		return ip, details, fmt.Errorf("firewall command failed: %w — output: %s", err, string(output))
	}

	// Schedule unblock if duration is set
	if dur, parseErr := time.ParseDuration(duration); parseErr == nil && dur > 0 {
		go func() {
			timer := time.NewTimer(dur)
			defer timer.Stop()
			select {
			case <-timer.C:
				unblockIP(ip, logger)
			case <-ctx.Done():
			}
		}()
		details += " (auto-unblock scheduled)"
	}

	return ip, details, nil
}

func unblockIP(ip string, logger zerolog.Logger) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	case "darwin":
		cmd = exec.Command("pfctl", "-t", "1sec_blocked", "-T", "delete", ip)
	case "windows":
		ruleName := fmt.Sprintf("1SEC-Block-%s", strings.ReplaceAll(ip, ".", "-"))
		cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	default:
		return
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Warn().Err(err).Str("ip", ip).Str("output", string(output)).Msg("failed to unblock IP")
	} else {
		logger.Info().Str("ip", ip).Msg("IP unblocked after cooldown")
	}
}

// ExportedUnblockIP is the exported version of unblockIP for use by the API layer.
func ExportedUnblockIP(ip string, logger zerolog.Logger) {
	unblockIP(ip, logger)
}

// ExportedEnableUser re-enables a previously disabled user account.
func ExportedEnableUser(username string, logger zerolog.Logger) error {
	username = sanitizeShellArg(username)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("usermod", "-U", username)
	case "windows":
		cmd = exec.Command("net", "user", username, "/active:yes")
	default:
		return fmt.Errorf("unsupported OS for user enable: %s", runtime.GOOS)
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Warn().Err(err).Str("username", username).Str("output", string(output)).Msg("failed to re-enable user")
		return fmt.Errorf("enable user failed: %w — output: %s", err, string(output))
	}
	logger.Info().Str("username", username).Msg("user re-enabled via rollback")
	return nil
}

// ExportedRestoreFile moves a quarantined file back to its original path.
// The target field is expected to be the original file path, and the details
// field contains "quarantined <original> → <quarantine_path>".
func ExportedRestoreFile(details string, logger zerolog.Logger) error {
	// Parse "quarantined /original/path → /quarantine/path" from details
	const prefix = "quarantined "
	const sep = " → "
	if !strings.HasPrefix(details, prefix) {
		return fmt.Errorf("cannot parse quarantine details: %q", details)
	}
	rest := details[len(prefix):]
	idx := strings.Index(rest, sep)
	if idx < 0 {
		return fmt.Errorf("cannot parse quarantine details: %q", details)
	}
	originalPath := rest[:idx]
	quarantinePath := rest[idx+len(sep):]

	if err := os.Rename(quarantinePath, originalPath); err != nil {
		logger.Warn().Err(err).Str("from", quarantinePath).Str("to", originalPath).Msg("failed to restore quarantined file")
		return fmt.Errorf("restore file failed: %w", err)
	}
	logger.Info().Str("from", quarantinePath).Str("to", originalPath).Msg("quarantined file restored via rollback")
	return nil
}

// ---------------------------------------------------------------------------
// KillProcessExecutor — terminates a malicious process by PID or name
// ---------------------------------------------------------------------------

type KillProcessExecutor struct{}

func (e *KillProcessExecutor) Validate(rule ResponseRule) error { return nil }

func (e *KillProcessExecutor) Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (string, string, error) {
	if host, _ := alert.Metadata["process_host"].(string); host != "" {
		if err := validateLocalProcessHost(host); err != nil {
			return "", "", err
		}
	}
	pid, _ := alert.Metadata["process_id"].(string)
	procName, _ := alert.Metadata["process_name"].(string)

	if pid == "" && procName == "" {
		return "", "", fmt.Errorf("no process_id or process_name in alert metadata")
	}

	// Validate inputs to prevent killing unintended processes
	if pid != "" {
		if err := validatePID(pid); err != nil {
			return "", "", fmt.Errorf("KillProcessExecutor: %w", err)
		}
	}
	if procName != "" {
		if err := validateProcessName(procName); err != nil {
			return "", "", fmt.Errorf("KillProcessExecutor: %w", err)
		}
	}

	target := pid
	if target == "" {
		target = procName
	}

	var cmd *exec.Cmd
	if pid != "" {
		switch runtime.GOOS {
		case "windows":
			cmd = exec.CommandContext(ctx, "taskkill", "/F", "/PID", pid)
		default:
			cmd = exec.CommandContext(ctx, "kill", "-9", pid)
		}
	} else {
		switch runtime.GOOS {
		case "windows":
			cmd = exec.CommandContext(ctx, "taskkill", "/F", "/IM", procName)
		default:
			cmd = exec.CommandContext(ctx, "pkill", "-9", procName)
		}
	}

	output, err := cmd.CombinedOutput()
	details := fmt.Sprintf("killed process %s", target)
	if err != nil {
		return target, details, fmt.Errorf("kill command failed: %w — output: %s", err, string(output))
	}
	return target, details, nil
}

// A PID reported by a remote sensor must never target an unrelated local process.
// Compare local identities directly; resolving arbitrary hostnames can redirect us.
func validateLocalProcessHost(host string) error {
	if local, err := os.Hostname(); err == nil && strings.EqualFold(host, local) {
		return nil
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() {
			return nil
		}
		addresses, err := net.InterfaceAddrs()
		if err == nil {
			for _, address := range addresses {
				local, _, err := net.ParseCIDR(address.String())
				if err == nil && ip.Equal(local) {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("process host %q is not local; route response to an executor on the reporting host", host)
}

// ---------------------------------------------------------------------------
// QuarantineFileExecutor — moves a suspicious file to quarantine directory
// ---------------------------------------------------------------------------

type QuarantineFileExecutor struct{}

func (e *QuarantineFileExecutor) Validate(rule ResponseRule) error { return nil }

func (e *QuarantineFileExecutor) Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (string, string, error) {
	if host, _ := alert.Metadata["process_host"].(string); host != "" {
		if err := validateLocalProcessHost(host); err != nil {
			return "", "", err
		}
	}
	filePath, _ := alert.Metadata["file_path"].(string)
	if filePath == "" {
		return "", "", fmt.Errorf("no file_path in alert metadata")
	}

	// Resolve symlinks and clean the path to prevent traversal attacks
	resolvedPath, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		return filePath, "", fmt.Errorf("resolving file path: %w", err)
	}
	cleanPath := filepath.Clean(resolvedPath)

	// Block paths containing ".." after resolution (defense in depth)
	if strings.Contains(cleanPath, "..") {
		return filePath, "", fmt.Errorf("file path contains traversal sequence: %q", filePath)
	}

	quarantineDir := rule.Params["quarantine_dir"]
	if quarantineDir == "" {
		quarantineDir = "/var/lib/1sec/quarantine"
		if runtime.GOOS == "windows" {
			quarantineDir = `C:\ProgramData\1sec\quarantine`
		}
	}

	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return cleanPath, "", fmt.Errorf("creating quarantine dir: %w", err)
	}

	baseName := filepath.Base(cleanPath)
	destPath := filepath.Join(quarantineDir, fmt.Sprintf("%d_%s", time.Now().UnixNano(), baseName))

	if err := os.Rename(cleanPath, destPath); err != nil {
		return cleanPath, "", fmt.Errorf("quarantining file: %w", err)
	}

	details := fmt.Sprintf("quarantined %s → %s", cleanPath, destPath)
	return cleanPath, details, nil
}

// ---------------------------------------------------------------------------
// DropConnectionExecutor — resets/drops active network connections
// ---------------------------------------------------------------------------

type DropConnectionExecutor struct{}

func (e *DropConnectionExecutor) Validate(rule ResponseRule) error { return nil }

func (e *DropConnectionExecutor) Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (string, string, error) {
	ip, _ := alert.Metadata["source_ip"].(string)
	port, _ := alert.Metadata["dest_port"].(string)

	if ip == "" {
		return "", "", fmt.Errorf("no source_ip in alert metadata for connection drop")
	}
	if err := validateIPAddress(ip); err != nil {
		return "", "", fmt.Errorf("DropConnectionExecutor: %w", err)
	}
	if port != "" {
		if _, err := strconv.Atoi(port); err != nil {
			return "", "", fmt.Errorf("DropConnectionExecutor: invalid port %q", port)
		}
	}

	target := ip
	if port != "" {
		target = fmt.Sprintf("%s:%s", ip, port)
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// Use ss or conntrack to drop established connections
		cmd = exec.CommandContext(ctx, "ss", "-K", "dst", ip)
	case "windows":
		// No direct equivalent; block via firewall as fallback
		ruleName := fmt.Sprintf("1SEC-Drop-%s", strings.ReplaceAll(ip, ".", "-"))
		cmd = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=in", "action=block", "remoteip="+ip)
	default:
		return target, "", fmt.Errorf("unsupported OS for connection drop: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()
	details := fmt.Sprintf("dropped connections from %s", target)
	if err != nil {
		return target, details, fmt.Errorf("drop command failed: %w — output: %s", err, string(output))
	}
	return target, details, nil
}

// ---------------------------------------------------------------------------
// DisableUserExecutor — disables a user account (OS-level or via custom command)
// ---------------------------------------------------------------------------

type DisableUserExecutor struct{}

func (e *DisableUserExecutor) Validate(rule ResponseRule) error { return nil }

func (e *DisableUserExecutor) Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (string, string, error) {
	username, _ := alert.Metadata["username"].(string)
	if username == "" {
		return "", "", fmt.Errorf("no username in alert metadata")
	}

	// Sanitize username to prevent injection in both custom and OS commands
	username = sanitizeShellArg(username)

	// If a custom command is provided, use it (e.g., for LDAP/AD integration)
	if customCmd := rule.Params["command"]; customCmd != "" {
		expanded := strings.ReplaceAll(customCmd, "{{username}}", username)
		parts := strings.Fields(expanded)
		if len(parts) == 0 {
			return username, "", fmt.Errorf("custom command is empty after expansion")
		}
		cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
		output, err := cmd.CombinedOutput()
		details := fmt.Sprintf("disabled user %s via custom command", username)
		if err != nil {
			return username, details, fmt.Errorf("custom disable command failed: %w — output: %s", err, string(output))
		}
		return username, details, nil
	}

	// OS-level user disable
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, "usermod", "-L", username)
	case "windows":
		cmd = exec.CommandContext(ctx, "net", "user", username, "/active:no")
	default:
		return username, "", fmt.Errorf("unsupported OS for user disable: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()
	details := fmt.Sprintf("disabled user account %s", username)
	if err != nil {
		return username, details, fmt.Errorf("user disable failed: %w — output: %s", err, string(output))
	}
	return username, details, nil
}

// ---------------------------------------------------------------------------
// WebhookExecutor — sends alert + action context to a webhook URL
// ---------------------------------------------------------------------------

type WebhookExecutor struct {
	Dispatcher *WebhookDispatcher
}

func (e *WebhookExecutor) Validate(rule ResponseRule) error {
	if rule.Params["url"] == "" {
		return fmt.Errorf("webhook action requires 'url' param")
	}
	return validateWebhookURL(rule.Params["url"])
}

func (e *WebhookExecutor) Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (string, string, error) {
	webhookURL := rule.Params["url"]
	if err := validateWebhookURL(webhookURL); err != nil {
		return "", "", err
	}

	payload := map[string]interface{}{
		"alert":     alert,
		"action":    string(rule.Action),
		"timestamp": time.Now().UTC(),
		"source":    "1sec-response-engine",
	}

	// Use the reliable dispatcher with retry + dead letter + circuit breaker
	// if available, otherwise fall back to direct HTTP.
	if e.Dispatcher != nil {
		headers := map[string]string{
			"Content-Type": "application/json",
			"User-Agent":   "1sec-response-engine/1.0",
		}
		if token := rule.Params["auth_token"]; token != "" {
			headers["Authorization"] = "Bearer " + token
		}
		deliveryID := e.Dispatcher.Enqueue(webhookURL, payload, headers)
		details := fmt.Sprintf("webhook enqueued to %s (delivery_id=%s, retries enabled)", webhookURL, deliveryID)
		return webhookURL, details, nil
	}

	// Fallback: direct HTTP (no retry)
	data, err := json.Marshal(payload)
	if err != nil {
		return webhookURL, "", fmt.Errorf("marshaling webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(data))
	if err != nil {
		return webhookURL, "", fmt.Errorf("creating webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "1sec-response-engine/1.0")

	if token := rule.Params["auth_token"]; token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := newWebhookHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return webhookURL, "", fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	details := fmt.Sprintf("webhook sent to %s (status=%d)", webhookURL, resp.StatusCode)
	if resp.StatusCode >= 400 {
		return webhookURL, details, fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return webhookURL, details, nil
}

// ---------------------------------------------------------------------------
// CommandExecutor — runs an arbitrary shell command with alert context
// ---------------------------------------------------------------------------

type CommandExecutor struct{}

func (e *CommandExecutor) Validate(rule ResponseRule) error {
	if rule.Params["command"] == "" {
		return fmt.Errorf("command action requires 'command' param")
	}
	return nil
}

func (e *CommandExecutor) Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (string, string, error) {
	cmdStr := rule.Params["command"]
	if cmdStr == "" {
		return "", "", fmt.Errorf("no command configured")
	}

	// Template substitution for common alert fields.
	// Sanitize values to prevent injection via attacker-controlled metadata.
	replacer := strings.NewReplacer(
		"{{alert_id}}", sanitizeShellArg(alert.ID),
		"{{module}}", sanitizeShellArg(alert.Module),
		"{{severity}}", sanitizeShellArg(alert.Severity.String()),
		"{{source_ip}}", sanitizeShellArg(fmt.Sprintf("%v", alert.Metadata["source_ip"])),
		"{{title}}", sanitizeShellArg(alert.Title),
	)
	cmdStr = replacer.Replace(cmdStr)

	timeout := 30 * time.Second
	if t := rule.Params["timeout"]; t != "" {
		if parsed, err := time.ParseDuration(t); err == nil {
			timeout = parsed
		}
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Use explicit argument array to avoid shell injection.
	// The command string is split on whitespace; for complex commands,
	// operators should use a wrapper script instead of inline shell.
	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return "", "", fmt.Errorf("command is empty after parsing")
	}
	cmd := exec.CommandContext(cmdCtx, parts[0], parts[1:]...)

	output, err := cmd.CombinedOutput()
	target := cmdStr
	if len(target) > 80 {
		target = target[:80] + "..."
	}
	details := fmt.Sprintf("command output: %s", strings.TrimSpace(string(output)))
	if len(details) > 500 {
		details = details[:500] + "..."
	}

	if err != nil {
		return target, details, fmt.Errorf("command failed: %w", err)
	}
	return target, details, nil
}

// ---------------------------------------------------------------------------
// LogOnlyExecutor — records the alert without taking any enforcement action
// ---------------------------------------------------------------------------

type LogOnlyExecutor struct{}

func (e *LogOnlyExecutor) Validate(rule ResponseRule) error { return nil }

func (e *LogOnlyExecutor) Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (string, string, error) {
	logger.Info().
		Str("alert_id", alert.ID).
		Str("module", alert.Module).
		Str("severity", alert.Severity.String()).
		Str("title", alert.Title).
		Msg("enforcement log: alert recorded (no action taken)")
	return alert.ID, "logged only — no enforcement action", nil
}
