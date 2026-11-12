package collect

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// JSONLogCollector tails JSON-line log files (CloudTrail, k8s audit, etc.)
// and emits canonical events. It auto-detects the log format from field names.
type JSONLogCollector struct {
	path string
	tag  string
	stop func()
}

func NewJSONLogCollector(path, tag string) *JSONLogCollector {
	if tag == "" {
		tag = "jsonlog"
	}
	return &JSONLogCollector{path: path, tag: tag}
}

func (c *JSONLogCollector) Name() string { return "jsonlog:" + c.path }

func (c *JSONLogCollector) Start(ctx context.Context, bus *core.EventBus, logger zerolog.Logger) error {
	stop, err := tailFile(ctx, c.path, func(line string) {
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return // skip non-JSON lines
		}

		event := c.classifyAndBuild(raw)
		if event == nil {
			return
		}

		event.Source = "collector:" + c.tag
		event.RawData = []byte(line)
		publishCollectedEvent(bus, event, logger)
	}, logger)
	c.stop = stop
	return err
}

func (c *JSONLogCollector) classifyAndBuild(raw map[string]interface{}) *core.SecurityEvent {
	// CloudTrail detection: has "eventSource" and "eventName"
	if eventName, ok := raw["eventName"].(string); ok {
		return c.buildCloudTrailEvent(raw, eventName)
	}

	// Kubernetes audit: has "kind" == "Event" and "verb"
	if kind, ok := raw["kind"].(string); ok && kind == "Event" {
		return c.buildK8sAuditEvent(raw)
	}

	// Kubernetes audit v2: has "apiVersion" containing "audit"
	if apiVer, ok := raw["apiVersion"].(string); ok && strings.Contains(apiVer, "audit") {
		return c.buildK8sAuditEvent(raw)
	}

	// Generic: just forward as syslog_event with all fields in Details
	event := core.NewSecurityEvent(c.tag, "syslog_event", core.SeverityInfo, "json log entry")
	for k, v := range raw {
		event.Details[k] = v
	}
	return event
}

func (c *JSONLogCollector) buildCloudTrailEvent(raw map[string]interface{}, eventName string) *core.SecurityEvent {
	eventType := "config_change"
	severity := core.SeverityInfo
	summary := eventName

	lowerName := strings.ToLower(eventName)

	// Classify by CloudTrail event name
	switch {
	case strings.HasPrefix(lowerName, "console") && strings.Contains(lowerName, "login"):
		eventType = "auth_success"
		if errCode, ok := raw["errorCode"].(string); ok && errCode != "" {
			eventType = "auth_failure"
			severity = core.SeverityMedium
		}
	case strings.Contains(lowerName, "createuser") || strings.Contains(lowerName, "attachpolicy"):
		eventType = "role_change"
		severity = core.SeverityMedium
	case strings.Contains(lowerName, "authorize") || strings.Contains(lowerName, "security"):
		eventType = "config_change"
		severity = core.SeverityMedium
	case strings.Contains(lowerName, "delete") || strings.Contains(lowerName, "terminate"):
		eventType = "config_change"
		severity = core.SeverityMedium
	}

	event := core.NewSecurityEvent(c.tag, eventType, severity, summary)

	// Extract common CloudTrail fields
	if src, ok := raw["sourceIPAddress"].(string); ok {
		event.SourceIP = src
	}
	if ua, ok := raw["userAgent"].(string); ok {
		event.UserAgent = ua
	}
	if res, ok := raw["eventSource"].(string); ok {
		event.Details["resource"] = res
	}
	event.Details["change_type"] = eventName

	// Extract user identity
	if identity, ok := raw["userIdentity"].(map[string]interface{}); ok {
		if arn, ok := identity["arn"].(string); ok {
			event.Details["user"] = arn
		}
		if utype, ok := identity["type"].(string); ok {
			event.Details["identity_type"] = utype
		}
	}

	return event
}

func (c *JSONLogCollector) buildK8sAuditEvent(raw map[string]interface{}) *core.SecurityEvent {
	verb, _ := raw["verb"].(string)
	severity := core.SeverityInfo

	eventType := "config_change"
	summary := "k8s " + verb

	// Extract resource info
	if objRef, ok := raw["objectRef"].(map[string]interface{}); ok {
		resource, _ := objRef["resource"].(string)
		ns, _ := objRef["namespace"].(string)
		name, _ := objRef["name"].(string)
		summary = "k8s " + verb + " " + resource + "/" + name
		if ns != "" {
			summary += " in " + ns
		}
	}

	// Classify sensitive operations
	lowerVerb := strings.ToLower(verb)
	switch {
	case lowerVerb == "delete":
		severity = core.SeverityMedium
	case lowerVerb == "create" || lowerVerb == "patch" || lowerVerb == "update":
		severity = core.SeverityLow
	}

	// Detect sensitive resources
	if objRef, ok := raw["objectRef"].(map[string]interface{}); ok {
		resource, _ := objRef["resource"].(string)
		lowerRes := strings.ToLower(resource)
		if lowerRes == "secrets" || lowerRes == "clusterroles" || lowerRes == "clusterrolebindings" {
			severity = core.SeverityMedium
			if lowerVerb == "delete" || lowerVerb == "create" {
				severity = core.SeverityHigh
			}
		}
	}

	event := core.NewSecurityEvent(c.tag, eventType, severity, summary)

	// Copy all fields to Details
	for k, v := range raw {
		event.Details[k] = v
	}

	// Extract user
	if user, ok := raw["user"].(map[string]interface{}); ok {
		if username, ok := user["username"].(string); ok {
			event.Details["user"] = username
		}
	}

	// Extract source IP
	if ips, ok := raw["sourceIPs"].([]interface{}); ok && len(ips) > 0 {
		if ip, ok := ips[0].(string); ok {
			event.SourceIP = ip
		}
	}

	return event
}

func (c *JSONLogCollector) Stop() error {
	if c.stop != nil {
		c.stop()
	}
	return nil
}
