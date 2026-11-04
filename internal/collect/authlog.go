package collect

import (
	"context"
	"regexp"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// AuthLogCollector tails /var/log/auth.log (or similar) and emits
// auth_failure, auth_success, and session_activity canonical events.
type AuthLogCollector struct {
	path   string
	tag    string
	cancel context.CancelFunc
}

var (
	// sshd: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2
	authFailRe = regexp.MustCompile(`(?i)(?:failed\s+password|authentication\s+failure|invalid\s+user|access\s+denied)`)
	// sshd: Accepted publickey for user from 1.2.3.4 port 22 ssh2
	authSuccRe = regexp.MustCompile(`(?i)(?:accepted\s+password|accepted\s+publickey|session\s+opened|successful\s+login)`)
	// session closed/expired
	authSessRe = regexp.MustCompile(`(?i)(?:session\s+closed|session\s+expired|session\s+timeout)`)
	// sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash
	sudoCmdRe = regexp.MustCompile(`(?i)sudo:.*COMMAND=(.+)`)
	// Extract user from "for user X" or "user=X"
	userExtractRe = regexp.MustCompile(`(?i)(?:for(?:\s+invalid)?\s+user\s+|user[=:\s]+)(\S+?)(?:\s|$|"|')`)
)

func NewAuthLogCollector(path, tag string) *AuthLogCollector {
	if tag == "" {
		tag = "authlog"
	}
	if path == "" {
		path = "/var/log/auth.log"
	}
	return &AuthLogCollector{path: path, tag: tag}
}

func (c *AuthLogCollector) Name() string { return "authlog:" + c.path }

func (c *AuthLogCollector) Start(ctx context.Context, bus *core.EventBus, logger zerolog.Logger) error {
	ctx, c.cancel = context.WithCancel(ctx)

	return tailFile(ctx, c.path, func(line string) {
		if event := c.parseLine(line); event != nil {
			if err := bus.PublishEvent(event); err != nil {
				logger.Error().Err(err).Msg("failed to publish authentication log event")
			}
		}
	}, logger)
}

func (c *AuthLogCollector) parseLine(line string) *core.SecurityEvent {
	var eventType string
	var severity core.Severity
	var summary string

	switch {
	case authFailRe.MatchString(line):
		eventType = "auth_failure"
		severity = core.SeverityMedium
		summary = "authentication failure"
	case authSuccRe.MatchString(line):
		eventType = "auth_success"
		severity = core.SeverityInfo
		summary = "authentication success"
	case authSessRe.MatchString(line):
		eventType = "session_activity"
		severity = core.SeverityInfo
		summary = "session activity"
	case sudoCmdRe.MatchString(line):
		eventType = "privilege_change"
		severity = core.SeverityMedium
		summary = "sudo command execution"
	default:
		// Skip lines that don't match known auth patterns
		return nil
	}

	event := core.NewSecurityEvent(c.tag, eventType, severity, summary)
	event.Source = "collector:" + c.tag

	// Extract username
	if m := userExtractRe.FindStringSubmatch(line); m != nil {
		event.Details["username"] = m[1]
		summary += " user=" + m[1]
	}

	// The daemon owns the peer field; username substrings do not identify it.
	if message, ok := core.SSHLogMessage(line); ok {
		if peer, valid := core.SSHAuthPeer(message); valid {
			event.SourceIP = peer
		}
	}

	// Extract sudo command
	if m := sudoCmdRe.FindStringSubmatch(line); m != nil {
		event.Details["command_line"] = strings.TrimSpace(m[1])
	}

	event.Summary = summary
	event.RawData = []byte(line)

	return event
}

func (c *AuthLogCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
