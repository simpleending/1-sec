package collect

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// NginxCollector tails nginx/apache combined access logs and emits
// http_request canonical events.
type NginxCollector struct {
	path string
	tag  string
	stop func()
}

// nginx combined log format:
// 1.2.3.4 - user [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.1" 200 2326 "referer" "user-agent"
var nginxLogRe = regexp.MustCompile(
	`^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+)(?:\s+"([^"]*)")?\s*(?:"([^"]*)")?`,
)

func NewNginxCollector(path, tag string) *NginxCollector {
	if tag == "" {
		tag = "nginx"
	}
	return &NginxCollector{path: path, tag: tag}
}

func (c *NginxCollector) Name() string { return "nginx:" + c.path }

func (c *NginxCollector) Start(ctx context.Context, bus *core.EventBus, logger zerolog.Logger) error {
	stop, err := tailFile(ctx, c.path, func(line string) {
		m := nginxLogRe.FindStringSubmatch(line)
		if m == nil {
			return
		}

		srcIP := m[1]
		user := m[2]
		method := m[4]
		path := m[5]
		statusStr := m[6]
		sizeStr := m[7]
		referer := ""
		userAgent := ""
		if len(m) > 8 {
			referer = m[8]
		}
		if len(m) > 9 {
			userAgent = m[9]
		}

		status, _ := strconv.Atoi(statusStr)
		size, _ := strconv.Atoi(sizeStr)

		severity := core.SeverityInfo
		if status >= 400 && status < 500 {
			severity = core.SeverityLow
		} else if status >= 500 {
			severity = core.SeverityMedium
		}

		event := core.NewSecurityEvent(c.tag, "http_request", severity,
			method+" "+path+" → "+statusStr)
		event.Source = "collector:" + c.tag
		event.SourceIP = srcIP
		event.UserAgent = userAgent
		event.Details["method"] = method
		event.Details["path"] = path
		event.Details["status_code"] = statusStr
		event.Details["response_size"] = sizeStr

		if user != "-" && user != "" {
			event.Details["user_id"] = user
		}
		if referer != "" && referer != "-" {
			event.Details["referer"] = referer
		}

		// Also emit http_response for status-based analysis
		if status >= 400 {
			respEvent := core.NewSecurityEvent(c.tag, "http_response", severity,
				"HTTP "+statusStr+" on "+path)
			respEvent.Source = "collector:" + c.tag
			respEvent.SourceIP = srcIP
			respEvent.Details["status_code"] = statusStr
			respEvent.Details["response_size"] = sizeStr
			respEvent.Details["path"] = path
			publishCollectedEvent(bus, respEvent, logger)
		}

		// Detect suspicious paths
		lowerPath := strings.ToLower(path)
		for _, pattern := range []string{"/wp-admin", "/phpmyadmin", "/.env", "/etc/passwd", "/shell", "/cmd", "/../"} {
			if strings.Contains(lowerPath, pattern) {
				event.Severity = core.SeverityMedium
				event.Summary = "suspicious path probe: " + path
				break
			}
		}

		publishCollectedEvent(bus, event, logger)
		_ = size // used above
	}, logger)
	c.stop = stop
	return err
}

func (c *NginxCollector) Stop() error {
	if c.stop != nil {
		c.stop()
	}
	return nil
}
