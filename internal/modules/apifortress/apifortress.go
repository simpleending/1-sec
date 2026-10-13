package apifortress

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog"
)

const ModuleName = "api_fortress"

// Fortress is the API Fortress module providing BOLA detection, BFLA detection,
// mass assignment protection, schema validation, shadow API discovery, per-endpoint
// rate limiting, excessive data exposure detection, GraphQL abuse prevention,
// JWT validation, SSRF-via-API detection, and response anomaly analysis.
type Fortress struct {
	logger           zerolog.Logger
	bus              *core.EventBus
	pipeline         *core.AlertPipeline
	cfg              *core.Config
	ctx              context.Context
	cancel           context.CancelFunc
	bolaDetector     *BOLADetector
	bflaDetector     *BFLADetector
	apiRegistry      *APIRegistry
	rateLimiter      *EndpointRateLimiter
	massAssignDet    *MassAssignmentDetector
	dataExposureDet  *DataExposureDetector
	graphqlGuard     *GraphQLGuard
	jwtValidator     *JWTValidator
	ssrfDetector     *SSRFViaAPIDetector
	responseAnalyzer *ResponseAnomalyAnalyzer
	authFlowTracker  *lru.Cache[string, time.Time] // tracks recent login_success per session/IP
	webhookScanner   *InboundWebhookScanner
	revokedJTIs      *lru.Cache[string, time.Time]
}

func New() *Fortress { return &Fortress{} }

func (f *Fortress) Name() string { return ModuleName }
func (f *Fortress) Description() string {
	return "BOLA/BFLA detection, mass assignment protection, API schema validation, shadow API discovery, per-endpoint rate limiting, excessive data exposure, GraphQL abuse prevention, JWT validation, SSRF-via-API detection, and response anomaly analysis"
}
func (f *Fortress) EventTypes() []string {
	return []string{
		"http_request", "api_request",
		"http_response", "api_response",
		"graphql_request",
		"jwt_validation", "token_event",
		"logout", "token_revocation", "auth_failure",
		"api_config", "api_upstream_response",
		"login_success", "auth_success",
		"grpc_request",
	}
}

func (f *Fortress) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	f.ctx, f.cancel = context.WithCancel(ctx)
	f.bus = bus
	f.pipeline = pipeline
	f.cfg = cfg
	f.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)

	f.bolaDetector = NewBOLADetector(settings)
	f.bflaDetector = NewBFLADetector()
	f.apiRegistry = NewAPIRegistry()
	f.rateLimiter = NewEndpointRateLimiter(settings)
	f.massAssignDet = NewMassAssignmentDetector()
	f.dataExposureDet = NewDataExposureDetector()
	f.graphqlGuard = NewGraphQLGuard(settings)
	f.jwtValidator = NewJWTValidator()
	f.ssrfDetector = NewSSRFViaAPIDetector()
	f.responseAnalyzer = NewResponseAnomalyAnalyzer()
	f.authFlowTracker, _ = lru.New[string, time.Time](50000)
	f.webhookScanner = NewInboundWebhookScanner()
	f.revokedJTIs, _ = lru.New[string, time.Time](50000)

	// BOLA, BFLA, rateLimiter, and responseAnalyzer now use LRU caches internally, so no external cleanup loops are needed.

	f.logger.Info().Msg("API fortress started")
	return nil
}

func (f *Fortress) Stop() error {
	if f.cancel != nil {
		f.cancel()
	}
	return nil
}

func (f *Fortress) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "http_request", "api_request":
		f.handleAPIRequest(event)
	case "http_response", "api_response":
		f.handleAPIResponse(event)
		f.checkSecurityMisconfiguration(event)
	case "graphql_request":
		f.handleGraphQLRequest(event)
	case "jwt_validation", "token_event":
		f.handleJWTEvent(event)
	case "logout", "token_revocation":
		f.handleTokenRevocation(event)
	case "auth_failure":
		f.maybeRecordRevokedToken(event)
	case "api_config":
		f.checkSecurityMisconfiguration(event)
	case "api_upstream_response":
		f.checkUnsafeConsumption(event)
	case "login_success", "auth_success":
		f.recordAuthSuccess(event)
	case "grpc_request":
		f.handleGRPCRequest(event)
	}
	return nil
}

// recordAuthSuccess tracks successful authentication for stateful API flow validation.
func (f *Fortress) recordAuthSuccess(event *core.SecurityEvent) {
	sessionID := getStringDetail(event, "session_id")
	if sessionID == "" {
		sessionID = event.SourceIP // fallback to IP
	}
	if sessionID != "" {
		f.authFlowTracker.Add(sessionID, time.Now())
	}
}

func (f *Fortress) handleAPIRequest(event *core.SecurityEvent) {
	path := getStringDetail(event, "path")
	method := strings.ToUpper(getStringDetail(event, "method"))
	userID := getStringDetail(event, "user_id")
	resourceID := getStringDetail(event, "resource_id")
	userRole := getStringDetail(event, "user_role")
	body := getStringDetail(event, "body")
	contentType := getStringDetail(event, "content_type")
	statusCode := getIntDetail(event, "status_code")
	headers := getStringDetail(event, "headers")
	webhookProvider := getStringDetail(event, "webhook_provider")

	// BOLA detection — user accessing resources they don't own
	if resourceID != "" && userID != "" {
		result := f.bolaDetector.Detect(userID, resourceID, path, method, event.SourceIP)
		if result.IsAttack {
			f.raiseAlert(event, core.SeverityCritical,
				"BOLA Attack Detected [API1:2023]",
				fmt.Sprintf("User %s is enumerating resources via %s %s. Accessed %d unique resource IDs in %s from IP %s. OWASP API Top 10: API1 Broken Object Level Authorization.",
					userID, method, path, result.ResourceCount, result.Window.String(), event.SourceIP),
				"bola")
		}
		if result.IDORAttempt {
			f.raiseAlert(event, core.SeverityHigh,
				"IDOR Attempt Detected [API1:2023]",
				fmt.Sprintf("User %s accessed resource %s sequentially after %s. Path: %s. Possible Insecure Direct Object Reference.",
					userID, resourceID, result.PreviousResource, path),
				"idor")
		}
	}

	// BFLA detection — user calling endpoints above their privilege level
	if userRole != "" && path != "" {
		if violation := f.bflaDetector.Check(userID, userRole, method, path, event.SourceIP); violation != nil {
			f.raiseAlert(event, violation.Severity,
				"BFLA Detected [API5:2023]",
				fmt.Sprintf("User %s (role: %s) attempted %s %s which requires role %s. OWASP API Top 10: API5 Broken Function Level Authorization. %s",
					userID, userRole, method, path, violation.RequiredRole, violation.Reason),
				"bfla")
		}
	}

	// ASP.NET PageMethod bypass detection — methods invoked via /page.aspx/MethodName
	// bypass standard routing middleware and can expose unauthenticated backend logic.
	if path != "" {
		f.checkPageMethodBypass(event, path, userRole)
	}

	f.checkMCPServerProvisioning(event, path, method, userRole, body)

	if findings := f.webhookScanner.Check(path, method, body, headers, contentType, webhookProvider, event.UserAgent); len(findings) > 0 {
		for _, finding := range findings {
			f.raiseAlert(event, finding.Severity,
				finding.Title,
				fmt.Sprintf("Inbound webhook request %s %s from %s: %s",
					method, path, event.SourceIP, finding.Description),
				finding.AlertType)
		}
	}

	if f.checkRevokedJWTRequest(event, path, method) {
		return
	}

	// Stateful API flow: admin endpoints require recent authentication (CVE-2026-20127)
	// Logic-based auth bypass detection — ensures login_success preceded admin access.
	if path != "" && strings.Contains(strings.ToLower(path), "/admin") {
		sessionID := getStringDetail(event, "session_id")
		if sessionID == "" {
			sessionID = event.SourceIP
		}
		lastAuth, hasAuth := f.authFlowTracker.Get(sessionID)
		if !hasAuth || time.Since(lastAuth) > 15*time.Minute {
			f.raiseAlert(event, core.SeverityCritical,
				"Logic-Based Auth Bypass Detected",
				fmt.Sprintf("Admin endpoint %s %s accessed by %s (IP: %s) without recent authentication. "+
					"No login_success event in last 15 minutes for session %s. "+
					"This may indicate a logic-based authentication bypass.",
					method, path, userID, event.SourceIP, sessionID),
				"auth_bypass_stateful")
		}
	}

	// Shadow API detection
	if path != "" && method != "" {
		if f.apiRegistry.IsUndocumented(method, path) {
			f.raiseAlert(event, core.SeverityMedium,
				"Shadow API Endpoint Detected [API9:2023]",
				fmt.Sprintf("Undocumented API endpoint accessed: %s %s from IP %s (user: %s). OWASP API Top 10: API9 Improper Inventory Management.",
					method, path, event.SourceIP, userID),
				"shadow_api")
		}
		f.apiRegistry.RecordAccess(method, path)
	}

	// Per-endpoint rate limiting
	if path != "" {
		if exceeded := f.rateLimiter.Check(event.SourceIP, method, path); exceeded != nil {
			f.raiseAlert(event, exceeded.Severity,
				"API Rate Limit Exceeded [API4:2023]",
				fmt.Sprintf("IP %s exceeded rate limit for %s %s: %d requests in %s (limit: %d). %s",
					event.SourceIP, method, path, exceeded.Count, exceeded.Window.String(), exceeded.Limit, exceeded.Detail),
				"api_rate_limit")
		}
	}

	// Mass assignment detection
	if body != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		if findings := f.massAssignDet.Check(method, path, body, contentType); len(findings) > 0 {
			for _, finding := range findings {
				f.raiseAlert(event, finding.Severity,
					"Mass Assignment Attempt [API6:2023]",
					fmt.Sprintf("%s %s from user %s (IP: %s): %s. OWASP API Top 10: API6 Unrestricted Access to Sensitive Business Flows.",
						method, path, userID, event.SourceIP, finding.Description),
					"mass_assignment")
			}
		}
	}

	// SSRF via API detection
	if body != "" || path != "" {
		urlParam := getStringDetail(event, "url_param")
		if ssrf := f.ssrfDetector.Check(path, body, urlParam); ssrf != nil {
			f.raiseAlert(event, ssrf.Severity,
				"SSRF via API Detected [API7:2023]",
				fmt.Sprintf("SSRF attempt via %s %s from %s: %s. OWASP API Top 10: API7 Server Side Request Forgery.",
					method, path, event.SourceIP, ssrf.Description),
				"ssrf_via_api")
		}
	}

	// Schema violation: unexpected parameters
	if params := getStringDetail(event, "unexpected_params"); params != "" {
		f.raiseAlert(event, core.SeverityMedium,
			"API Schema Violation [API3:2023]",
			fmt.Sprintf("Unexpected parameters in %s %s from %s: %s. OWASP API Top 10: API3 Broken Object Property Level Authorization.",
				method, path, event.SourceIP, params),
			"schema_violation")
	}

	// Track response for anomaly analysis
	if statusCode > 0 {
		f.responseAnalyzer.RecordRequest(method, path, statusCode, event.SourceIP)
	}
}

func (f *Fortress) handleAPIResponse(event *core.SecurityEvent) {
	path := getStringDetail(event, "path")
	method := strings.ToUpper(getStringDetail(event, "method"))
	statusCode := getIntDetail(event, "status_code")
	responseBody := getStringDetail(event, "response_body")
	responseSize := getIntDetail(event, "response_size")
	userID := getStringDetail(event, "user_id")

	// Excessive data exposure detection
	if responseBody != "" || responseSize > 0 {
		if finding := f.dataExposureDet.Check(path, method, responseBody, responseSize); finding != nil {
			f.raiseAlert(event, finding.Severity,
				"Excessive Data Exposure [API3:2023]",
				fmt.Sprintf("Response from %s %s to user %s: %s. OWASP API Top 10: API3 Broken Object Property Level Authorization.",
					method, path, userID, finding.Description),
				"data_exposure")
		}
	}

	// Response anomaly detection
	if statusCode > 0 {
		anomaly := f.responseAnalyzer.Analyze(method, path, statusCode, responseSize, event.SourceIP)
		if anomaly.ErrorSpike {
			f.raiseAlert(event, core.SeverityHigh,
				"API Error Rate Spike",
				fmt.Sprintf("Endpoint %s %s error rate spiked to %.1f%% (normal: %.1f%%). %d errors in the last %s from IP %s.",
					method, path, anomaly.ErrorRate*100, anomaly.BaselineErrorRate*100,
					anomaly.ErrorCount, anomaly.Window.String(), event.SourceIP),
				"error_rate_spike")
		}
		if anomaly.ResponseSizeAnomaly {
			f.raiseAlert(event, core.SeverityMedium,
				"API Response Size Anomaly",
				fmt.Sprintf("Response from %s %s is %d bytes, %.1fx above average (%d bytes). Possible data leak.",
					method, path, responseSize, anomaly.SizeRatio, anomaly.AvgResponseSize),
				"response_size_anomaly")
		}
	}
}

func (f *Fortress) handleGraphQLRequest(event *core.SecurityEvent) {
	query := getStringDetail(event, "query")
	operationName := getStringDetail(event, "operation_name")
	userID := getStringDetail(event, "user_id")

	if query == "" {
		return
	}

	findings := f.graphqlGuard.Analyze(query, operationName, userID, event.SourceIP)
	for _, finding := range findings {
		f.raiseAlert(event, finding.Severity,
			finding.Title,
			fmt.Sprintf("GraphQL request from %s (user: %s): %s",
				event.SourceIP, userID, finding.Description),
			finding.AlertType)
	}
}

func (f *Fortress) handleJWTEvent(event *core.SecurityEvent) {
	token := getStringDetail(event, "token")
	header := getStringDetail(event, "header")
	algorithm := getStringDetail(event, "algorithm")
	claims := getStringDetail(event, "claims")

	findings := f.jwtValidator.Validate(token, header, algorithm, claims)
	for _, finding := range findings {
		f.raiseAlert(event, finding.Severity,
			finding.Title,
			fmt.Sprintf("JWT issue from %s: %s", event.SourceIP, finding.Description),
			finding.AlertType)
	}

	if jti := extractAPIJWTIdentifier(event); jti != "" && f.revokedJTIs != nil {
		if _, ok := f.revokedJTIs.Get(jti); ok {
			f.raiseAlert(event, core.SeverityCritical,
				"Revoked JWT Reused After Logout",
				fmt.Sprintf("JWT validation event from %s presented revoked token identifier %q after logout/revocation.",
					event.SourceIP, truncateStr(jti, 24)),
				"token_reuse_post_logout")
		}
	}
}

func (f *Fortress) handleTokenRevocation(event *core.SecurityEvent) {
	jti := extractAPIJWTIdentifier(event)
	if jti == "" || f.revokedJTIs == nil {
		return
	}
	f.revokedJTIs.Add(jti, time.Now())
}

func (f *Fortress) maybeRecordRevokedToken(event *core.SecurityEvent) {
	reason := strings.ToLower(getStringDetail(event, "reason"))
	action := strings.ToLower(getStringDetail(event, "action"))
	status := strings.ToLower(getStringDetail(event, "status"))
	if strings.Contains(reason, "revoked") || strings.Contains(reason, "logout") ||
		strings.Contains(action, "revoke") || strings.Contains(action, "logout") ||
		strings.Contains(status, "revoked") {
		f.handleTokenRevocation(event)
	}
}

func (f *Fortress) checkRevokedJWTRequest(event *core.SecurityEvent, path, method string) bool {
	jti := extractAPIJWTIdentifier(event)
	if jti == "" || f.revokedJTIs == nil {
		return false
	}
	if _, ok := f.revokedJTIs.Get(jti); !ok {
		return false
	}
	f.raiseAlert(event, core.SeverityCritical,
		"Revoked JWT Reused on API Request",
		fmt.Sprintf("API request %s %s from %s presented revoked token identifier %q after logout/revocation. "+
			"This closes the gap where reused JWTs only surface on request paths.",
			method, path, event.SourceIP, truncateStr(jti, 24)),
		"token_reuse_post_logout")
	return true
}

// pageMethodPattern detects ASP.NET PageMethod access that bypasses standard routing filters.
var pageMethodPattern = regexp.MustCompile(`(?i)/[^/]+\.aspx/([a-zA-Z0-9_]+)`)

var (
	mcpProvisioningPathPattern = regexp.MustCompile(`(?i)(?:^|/)(?:mcp|model-context-protocol)(?:/|[-_])(?:servers?|registry|register|provision)(?:/|$)`)
	mcpServersConfigPattern    = regexp.MustCompile(`(?is)"mcpServers"\s*:\s*\{.*?"command"\s*:\s*"[^"]+".*?"args"\s*:\s*\[`)
	mcpServerCommandPattern    = regexp.MustCompile(`(?is)"command"\s*:\s*"([^"]+)".{0,512}?"args"\s*:\s*\[([^\]]*)\]`)
	mcpDangerousCommandPattern = regexp.MustCompile(`(?is)(?:^|[^\w])(?:bash|sh|zsh|dash|powershell|pwsh|cmd\.exe|curl|wget|nc|netcat|socat|python(?:3)?\s+-c|node\s+-e|perl\s+-e|ruby\s+-e|base64|eval)(?:[^\w]|$)|[;&|]{1,2}`)
	httpURLPattern             = regexp.MustCompile(`https?://[^\s"'<>]+`)
)

// handleGRPCRequest detects gRPC requests missing authorization metadata,
// which can indicate auth bypass on gRPC endpoints (CVE-2026-4064).
func (f *Fortress) handleGRPCRequest(event *core.SecurityEvent) {
	path := getStringDetail(event, "path")
	contentType := getStringDetail(event, "content_type")
	metadata := getStringDetail(event, "metadata")
	authHeader := getStringDetail(event, "authorization")

	// Verify this is actually a gRPC request
	if !strings.Contains(strings.ToLower(contentType), "application/grpc") {
		return
	}

	// Check for missing authorization in gRPC metadata
	metaLower := strings.ToLower(metadata)
	hasAuth := authHeader != "" ||
		strings.Contains(metaLower, "authorization") ||
		strings.Contains(metaLower, "x-api-key")

	if !hasAuth {
		f.raiseAlert(event, core.SeverityCritical,
			"gRPC Missing Authorization [API2:2023]",
			fmt.Sprintf("gRPC request to %s from %s has no authorization metadata. "+
				"Content-Type: %s. Missing auth on gRPC endpoints allows RBAC bypass. "+
				"OWASP API Top 10: API2 Broken Authentication.",
				path, event.SourceIP, contentType),
			"grpc_auth_bypass")
	}

	// Also check for BFLA on gRPC endpoints
	userRole := getStringDetail(event, "user_role")
	if userRole != "" {
		result := f.bflaDetector.Check("", userRole, "POST", path, event.SourceIP)
		if result != nil {
			f.raiseAlert(event, core.SeverityHigh,
				"gRPC BFLA — Unauthorized Function Access [API5:2023]",
				fmt.Sprintf("User with role %q accessing privileged gRPC endpoint %s. %s. "+
					"OWASP API Top 10: API5 Broken Function Level Authorization.",
					userRole, path, result.Reason),
				"grpc_bfla")
		}
	}
}

// checkPageMethodBypass detects ASP.NET PageMethod access attempts that bypass
// standard middleware routing filters, allowing direct backend method invocation.
func (f *Fortress) checkPageMethodBypass(event *core.SecurityEvent, path, userRole string) {
	if match := pageMethodPattern.FindStringSubmatch(path); match != nil {
		methodName := match[1]
		severity := core.SeverityHigh
		if userRole == "0" || userRole == "1" || userRole == "anonymous" || userRole == "" {
			severity = core.SeverityCritical
		}
		f.raiseAlert(event, severity,
			"ASP.NET PageMethod Bypass Detected [API5:2023]",
			fmt.Sprintf("Request to %s invokes PageMethod %q which bypasses standard routing filters. "+
				"Source: %s, Role: %s. Attackers use PageMethod suffixes to skip authentication middleware. "+
				"OWASP API Top 10: API5 Broken Function Level Authorization.",
				path, methodName, event.SourceIP, userRole),
			"aspnet_pagemethod_bypass")
	}
}

func (f *Fortress) checkMCPServerProvisioning(event *core.SecurityEvent, path, method, userRole, body string) {
	hasProvisioningPath := mcpProvisioningPathPattern.MatchString(path)
	hasDynamicConfig := mcpServersConfigPattern.MatchString(body)
	if !hasProvisioningPath && !hasDynamicConfig {
		return
	}
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return
	}

	role := strings.TrimSpace(userRole)

	if !isPrivilegedMCPRole(role) {
		if hasDynamicConfig {
			f.raiseAlert(event, core.SeverityCritical,
				"Dynamic MCP Server Injection Attempt",
				fmt.Sprintf("Request %s %s attempted to submit an mcpServers configuration without an admin-equivalent role. "+
					"Resolved role: %q. Dynamic MCP server registration must be limited to trusted operators.",
					method, path, role),
				"mcp_server_dynamic_injection")
		} else {
			f.raiseAlert(event, core.SeverityCritical,
				"Unauthorized MCP Server Registration Attempt",
				fmt.Sprintf("Request %s %s attempted MCP server provisioning without an admin-equivalent role. "+
					"Resolved role: %q. Dynamic MCP server registration must be limited to trusted operators.",
					method, path, role),
				"mcp_server_registration_unauthorized")
		}
	}

	for _, command := range extractMCPServerCommands(body) {
		if mcpDangerousCommandPattern.MatchString(command) {
			f.raiseAlert(event, core.SeverityCritical,
				"Dangerous MCP Server Command Registration",
				fmt.Sprintf("Request %s %s attempted to register an MCP server command with shell or downloader primitives: %s",
					method, path, truncateStr(command, 200)),
				"mcp_server_dynamic_injection")
			break
		}
	}

	for _, serverURL := range extractMCPServerURLs(event, body) {
		if !isAllowedMCPServerURL(serverURL) {
			f.raiseAlert(event, core.SeverityHigh,
				"Unapproved External MCP Server Registration",
				fmt.Sprintf("Request %s %s attempted to register MCP server %s. "+
					"Only localhost, 127.0.0.1, ::1, and internal-mcp.svc.cluster.local are allowed by default.",
					method, path, truncateStr(serverURL, 200)),
				"mcp_server_registration_unapproved")
		}
	}
}

func (f *Fortress) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if f.bus != nil {
		_ = f.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getAPIMitigations(alertType)
	if f.pipeline != nil {
		f.pipeline.Process(alert)
	}
}

func getAPIMitigations(alertType string) []string {
	switch alertType {
	case "bola", "idor":
		return []string{
			"Implement object-level authorization checks on every data access",
			"Use random, non-sequential resource identifiers (UUIDs)",
			"Validate that the authenticated user owns the requested resource",
			"Log and monitor resource access patterns for enumeration",
		}
	case "bfla":
		return []string{
			"Implement function-level authorization checks on every endpoint",
			"Use role-based access control (RBAC) with least privilege",
			"Deny by default — explicitly allow only authorized role/endpoint combinations",
		}
	case "mass_assignment":
		return []string{
			"Use allowlists for accepted request body properties",
			"Never bind request bodies directly to internal data models",
			"Implement separate DTOs for input and output",
		}
	case "data_exposure":
		return []string{
			"Return only the fields the client explicitly needs — use response DTOs",
			"Implement response filtering and field-level access control",
			"Never expose internal object representations directly",
			"Mask or redact sensitive values (SSNs, credit cards, tokens) before serialization",
			"Scan API responses for PII and credential patterns in CI/CD pipelines",
			"Strip internal IP addresses, stack traces, and debug info from production responses",
			"Implement PCI-DSS compliant card number masking (show only last 4 digits)",
			"Rotate any API keys, tokens, or secrets detected in response bodies immediately",
		}
	case "ssrf_via_api":
		return []string{
			"Validate and sanitize all URL parameters server-side",
			"Use allowlists for permitted external domains",
			"Block requests to internal/private IP ranges from user-supplied URLs",
		}
	case "graphql_depth", "graphql_batch", "graphql_introspection", "graphql_alias_abuse":
		return []string{
			"Limit query depth, complexity, and alias count",
			"Disable introspection in production",
			"Implement query cost analysis and budget limits",
			"Use persisted queries to prevent arbitrary query execution",
		}
	case "api_rate_limit":
		return []string{
			"Implement per-endpoint rate limiting with appropriate thresholds (OWASP API4:2023)",
			"Use sliding window or token bucket algorithms for rate limiting",
			"Return 429 Too Many Requests with Retry-After header",
			"Monitor for distributed rate limit bypass across multiple IPs",
		}
	case "shadow_api":
		return []string{
			"Maintain a complete API inventory and deprecate unused endpoints (OWASP API9:2023)",
			"Use API gateway to enforce that only documented endpoints are accessible",
			"Implement automated API discovery and compare against documentation",
			"Remove or restrict access to debug, test, and legacy endpoints",
		}
	case "mcp_server_registration_unauthorized", "mcp_server_dynamic_injection":
		return []string{
			"Require admin-equivalent roles for all MCP server registration or update endpoints",
			"Bind MCP server provisioning to authenticated control-plane workflows instead of general API sessions",
			"Log and review every failed MCP registration attempt for follow-on abuse",
			"Provide user_role from a trusted authentication verifier; never derive authorization from an unverified bearer token",
		}
	case "mcp_server_registration_unapproved":
		return []string{
			"Allow MCP servers only from localhost or explicitly approved internal gateway hostnames",
			"Reject remote MCP server URLs by default and require explicit review before onboarding",
			"Normalize and validate MCP server URLs before storing or forwarding them downstream",
			"Monitor for repeated attempts to register public MCP endpoints from agent-facing applications",
		}
	case "schema_violation":
		return []string{
			"Enforce strict API schema validation on all request parameters (OWASP API3:2023)",
			"Use allowlists for accepted request body properties",
			"Reject requests with unexpected or extra parameters",
		}
	case "error_rate_spike":
		return []string{
			"Investigate the root cause of elevated error rates",
			"Implement circuit breakers to prevent cascading failures",
			"Monitor for brute-force or fuzzing attacks causing error spikes",
		}
	case "response_size_anomaly":
		return []string{
			"Implement response size limits per endpoint",
			"Use pagination for list endpoints to prevent bulk data extraction",
			"Monitor for data exfiltration via oversized responses",
		}
	case "jwt_none_algorithm", "jwt_weak_algorithm", "jwt_expired", "jwt_missing_claims", "jwt_algorithm_confusion":
		return []string{
			"Reject tokens with 'none' algorithm (OWASP API2:2023)",
			"Use strong algorithms (RS256, ES256) and reject weak ones",
			"Validate all required claims including exp, iss, aud",
			"Implement token rotation and short expiration times",
		}
	case "security_misconfiguration":
		return []string{
			"Restrict CORS to specific trusted origins — never use wildcard with credentials (OWASP API8:2023)",
			"Disable verbose error messages and stack traces in production",
			"Remove debug endpoints and development tools from production deployments",
			"Set security headers: X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security",
			"Disable unnecessary HTTP methods (TRACE, OPTIONS in production)",
		}
	case "unsafe_api_consumption":
		return []string{
			"Validate and sanitize all data received from third-party APIs (OWASP API10:2023)",
			"Implement timeouts and circuit breakers for upstream API calls",
			"Use TLS for all upstream API communication",
			"Apply input validation to upstream responses before processing",
			"Maintain an inventory of all third-party API dependencies",
		}
	default:
		return []string{
			"Review API security posture against OWASP API Top 10",
			"Implement authentication, authorization, and rate limiting on all endpoints",
			"Monitor API traffic for anomalous patterns",
		}
	}
}

// ===========================================================================
// BOLADetector — Broken Object Level Authorization with IDOR detection
// ===========================================================================

type BOLADetector struct {
	mu             sync.RWMutex
	accessPatterns *lru.Cache[string, *bolaProfile] // userID -> profile
	ipPatterns     *lru.Cache[string, *bolaProfile] // IP -> profile
	threshold      int
}

type bolaProfile struct {
	resources  map[string]bool
	orderedIDs []string
	firstSeen  time.Time
	lastSeen   time.Time
}

type BOLAResult struct {
	IsAttack         bool
	IDORAttempt      bool
	ResourceCount    int
	PreviousResource string
	Window           time.Duration
}

func NewBOLADetector(settings map[string]interface{}) *BOLADetector {
	threshold := 20
	if val, ok := settings["bola_threshold"]; ok {
		if v, ok := val.(float64); ok && v > 0 {
			threshold = int(v)
		}
	}
	aCache, _ := lru.New[string, *bolaProfile](20000)
	iCache, _ := lru.New[string, *bolaProfile](20000)
	return &BOLADetector{
		accessPatterns: aCache,
		ipPatterns:     iCache,
		threshold:      threshold,
	}
}

func (b *BOLADetector) Detect(userID, resourceID, path, method, ip string) BOLAResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := BOLAResult{}
	now := time.Now()

	// Per-user tracking
	profile := b.getOrCreateProfile(b.accessPatterns, userID, now)
	profile.lastSeen = now

	if !profile.resources[resourceID] {
		profile.resources[resourceID] = true
		profile.orderedIDs = append(profile.orderedIDs, resourceID)
		if len(profile.orderedIDs) > 200 {
			profile.orderedIDs = profile.orderedIDs[len(profile.orderedIDs)-200:]
		}
	}

	result.ResourceCount = len(profile.resources)
	result.Window = now.Sub(profile.firstSeen)

	// Enumeration detection: accessing many different resources
	if len(profile.resources) > b.threshold {
		result.IsAttack = true
	}

	// IDOR detection: sequential ID access pattern
	if len(profile.orderedIDs) >= 3 {
		recent := profile.orderedIDs[len(profile.orderedIDs)-3:]
		if isSequentialIDs(recent) {
			result.IDORAttempt = true
			result.PreviousResource = recent[len(recent)-2]
		}
	}

	// Per-IP tracking (catches attacks across multiple user accounts)
	ipProfile := b.getOrCreateProfile(b.ipPatterns, ip, now)
	ipProfile.lastSeen = now
	ipProfile.resources[resourceID] = true
	if len(ipProfile.resources) > b.threshold*2 {
		result.IsAttack = true
	}

	return result
}

func (b *BOLADetector) getOrCreateProfile(m *lru.Cache[string, *bolaProfile], key string, now time.Time) *bolaProfile {
	p, exists := m.Get(key)
	if !exists || now.Sub(p.lastSeen) > 10*time.Minute {
		p = &bolaProfile{
			resources: make(map[string]bool),
			firstSeen: now,
		}
		m.Add(key, p)
	}

	// Cap resources map
	if len(p.resources) > b.threshold*5 {
		p.resources = make(map[string]bool)
	}
	return p
}

// Cleanup handled by LRU

// isSequentialIDs checks if a slice of ID strings are numerically sequential.
func isSequentialIDs(ids []string) bool {
	if len(ids) < 2 {
		return false
	}
	nums := make([]int, 0, len(ids))
	for _, id := range ids {
		n := parseNumericID(id)
		if n < 0 {
			return false
		}
		nums = append(nums, n)
	}
	for i := 1; i < len(nums); i++ {
		diff := nums[i] - nums[i-1]
		// Allow forward sequential (1,2,3) and reverse sequential (-1,-2,-3)
		// with small gaps up to 3
		absDiff := diff
		if absDiff < 0 {
			absDiff = -absDiff
		}
		if absDiff < 1 || absDiff > 3 {
			return false
		}
		// All diffs must go the same direction
		if i > 1 {
			prevDiff := nums[i-1] - nums[i-2]
			if (diff > 0 && prevDiff < 0) || (diff < 0 && prevDiff > 0) {
				return false
			}
		}
	}
	return true
}

func parseNumericID(s string) int {
	n := 0
	hasDigit := false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
			hasDigit = true
		} else {
			if hasDigit {
				break
			}
			return -1
		}
	}
	if !hasDigit {
		return -1
	}
	return n
}

// ===========================================================================
// BFLADetector — Broken Function Level Authorization
// ===========================================================================

type BFLADetector struct {
	mu            sync.RWMutex
	adminPaths    *regexp.Regexp
	writePaths    *regexp.Regexp
	roleHierarchy map[string]int // role -> privilege level
	userAttempts  *lru.Cache[string, *bflaTracker]
}

type bflaTracker struct {
	violations int
	lastSeen   time.Time
}

type BFLAViolation struct {
	Severity     core.Severity
	RequiredRole string
	Reason       string
}

func NewBFLADetector() *BFLADetector {
	uCache, _ := lru.New[string, *bflaTracker](50000)
	return &BFLADetector{
		adminPaths: regexp.MustCompile(`(?i)(/admin|/management|/internal|/debug|/actuator|/console|/config|/settings|/users/\{?id\}?/role|/system|/ops/|/superadmin)`),
		writePaths: regexp.MustCompile(`(?i)(/users$|/accounts$|/roles|/permissions|/policies|/billing|/subscriptions|/organizations)`),
		roleHierarchy: map[string]int{
			"anonymous": 0, "guest": 0,
			"user": 1, "member": 1,
			"editor": 2, "moderator": 2,
			"admin": 3, "administrator": 3,
			"superadmin": 4, "owner": 4, "root": 4,
		},
		userAttempts: uCache,
	}
}

func (b *BFLADetector) Check(userID, userRole, method, path, ip string) *BFLAViolation {
	b.mu.Lock()
	defer b.mu.Unlock()

	roleLower := strings.ToLower(userRole)
	userLevel, knownRole := b.roleHierarchy[roleLower]
	if !knownRole {
		userLevel = 1 // default to basic user
	}

	// Admin path access by non-admin
	if b.adminPaths.MatchString(path) && userLevel < 3 {
		b.recordAttempt(userID)
		return &BFLAViolation{
			Severity:     core.SeverityCritical,
			RequiredRole: "admin",
			Reason:       fmt.Sprintf("Admin endpoint accessed by %s-level user", userRole),
		}
	}

	// Write operations on sensitive paths by low-privilege users
	if (method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH") &&
		b.writePaths.MatchString(path) && userLevel < 2 {
		b.recordAttempt(userID)
		return &BFLAViolation{
			Severity:     core.SeverityHigh,
			RequiredRole: "editor",
			Reason:       fmt.Sprintf("Write operation on sensitive resource by %s-level user", userRole),
		}
	}

	// DELETE on any resource by non-admin
	if method == "DELETE" && userLevel < 3 {
		// Only flag if it's a resource deletion (not a sub-resource action)
		normalized := normalizePath(path)
		if strings.Count(normalized, "/") <= 3 {
			b.recordAttempt(userID)
			return &BFLAViolation{
				Severity:     core.SeverityHigh,
				RequiredRole: "admin",
				Reason:       "DELETE operation on top-level resource by non-admin user",
			}
		}
	}

	// Repeated BFLA attempts from same user
	if tracker, ok := b.userAttempts.Get(userID); ok && tracker.violations >= 5 {
		return &BFLAViolation{
			Severity:     core.SeverityCritical,
			RequiredRole: "admin",
			Reason:       fmt.Sprintf("Repeated privilege escalation attempts: %d violations", tracker.violations),
		}
	}

	return nil
}

func (b *BFLADetector) recordAttempt(userID string) {
	tracker, exists := b.userAttempts.Get(userID)
	if !exists {
		tracker = &bflaTracker{}
		b.userAttempts.Add(userID, tracker)
	}
	tracker.violations++
	tracker.lastSeen = time.Now()
}

// Cleanup Loop eliminated by LRU

// ===========================================================================
// MassAssignmentDetector — detects attempts to set privileged fields
// ===========================================================================

type MassAssignmentDetector struct {
	sensitiveFields *regexp.Regexp
	adminFields     *regexp.Regexp
}

type MassAssignmentFinding struct {
	Severity    core.Severity
	Description string
}

func NewMassAssignmentDetector() *MassAssignmentDetector {
	return &MassAssignmentDetector{
		sensitiveFields: regexp.MustCompile(`(?i)"(role|is_?admin|is_?superuser|is_?staff|privilege|permission|access_?level|user_?type|account_?type|verified|email_?verified|approved|active|disabled|banned|suspended|internal|trust_?level|credit|balance|price|amount|discount|subscription_?tier|plan)"\s*:`),
		adminFields:     regexp.MustCompile(`(?i)"(id|_id|created_?at|updated_?at|deleted_?at|password_?hash|salt|secret|token|api_?key|internal_?id|tenant_?id|org_?id|owner_?id)"\s*:`),
	}
}

func (m *MassAssignmentDetector) Check(method, path, body, contentType string) []MassAssignmentFinding {
	var findings []MassAssignmentFinding

	if !strings.Contains(strings.ToLower(contentType), "json") && contentType != "" {
		return findings
	}

	if m.adminFields.MatchString(body) {
		matches := m.adminFields.FindAllString(body, -1)
		fields := make([]string, 0, len(matches))
		for _, match := range matches {
			fields = append(fields, strings.TrimSpace(match))
		}
		findings = append(findings, MassAssignmentFinding{
			Severity:    core.SeverityCritical,
			Description: fmt.Sprintf("Request body contains internal/system fields: %s", strings.Join(fields, ", ")),
		})
	}

	if m.sensitiveFields.MatchString(body) {
		matches := m.sensitiveFields.FindAllString(body, -1)
		fields := make([]string, 0, len(matches))
		for _, match := range matches {
			fields = append(fields, strings.TrimSpace(match))
		}
		findings = append(findings, MassAssignmentFinding{
			Severity:    core.SeverityHigh,
			Description: fmt.Sprintf("Request body contains privilege-escalation fields: %s", strings.Join(fields, ", ")),
		})
	}

	return findings
}

// ===========================================================================
// DataExposureDetector — detects excessive data in API responses
// ===========================================================================

type DataExposureDetector struct {
	sensitivePatterns *regexp.Regexp
	piiPatterns       *regexp.Regexp
	// Value-based patterns — match actual data formats regardless of field names
	creditCardPattern *regexp.Regexp
	ssnPattern        *regexp.Regexp
	awsKeyPattern     *regexp.Regexp
	gcpKeyPattern     *regexp.Regexp
	privateKeyPattern *regexp.Regexp
	pgpKeyPattern     *regexp.Regexp
	jwtPattern        *regexp.Regexp
	bearerPattern     *regexp.Regexp
	ipv4Pattern       *regexp.Regexp
	emailPattern      *regexp.Regexp
	phonePattern      *regexp.Regexp
	ibanPattern       *regexp.Regexp
	githubPattern     *regexp.Regexp
	slackPattern      *regexp.Regexp
	slackWebhookPat   *regexp.Regexp
	stripePattern     *regexp.Regexp
	sendgridPattern   *regexp.Regexp
	twilioPattern     *regexp.Regexp
	herokuPattern     *regexp.Regexp
	genericSecretPat  *regexp.Regexp
	// Wave 2: additional provider patterns from secrets-patterns-db research
	facebookTokenPat   *regexp.Regexp
	amazonMWSPat       *regexp.Regexp
	mailgunPat         *regexp.Regexp
	mailchimpPat       *regexp.Regexp
	paypalBraintreePat *regexp.Regexp
	squareTokenPat     *regexp.Regexp
	squareOAuthPat     *regexp.Regexp
	passwordInURLPat   *regexp.Regexp
	googleOAuthPat     *regexp.Regexp
	gcpOAuthClientPat  *regexp.Regexp
	gcpServiceAcctPat  *regexp.Regexp
	cloudinaryPat      *regexp.Regexp
	firebaseURLPat     *regexp.Regexp
	firebaseSecretPat  *regexp.Regexp
	databricksTokenPat *regexp.Regexp
	shopifyTokenPat    *regexp.Regexp
	vercelTokenPat     *regexp.Regexp
	azureSASPat        *regexp.Regexp
	supabaseKeyPat     *regexp.Regexp
	datadogKeyPat      *regexp.Regexp
	npmTokenPat        *regexp.Regexp
	pypiTokenPat       *regexp.Regexp
	nugetKeyPat        *regexp.Regexp
	dockerHubTokenPat  *regexp.Regexp
}

type DataExposureFinding struct {
	Severity    core.Severity
	Description string
}

func NewDataExposureDetector() *DataExposureDetector {
	return &DataExposureDetector{
		// Field-name patterns (JSON key matching)
		sensitivePatterns: regexp.MustCompile(`(?i)"(password|password_hash|salt|secret|private_key|api_key|api_secret|access_token|refresh_token|ssn|social_security|credit_card|card_number|cvv|bank_account|routing_number)"\s*:\s*"[^"]+"`),
		piiPatterns:       regexp.MustCompile(`(?i)"(date_of_birth|dob|national_id|passport_number|driver_license|tax_id|medical_record|health_insurance|biometric)"\s*:\s*"[^"]+"`),

		// ── Value-based patterns: match actual data regardless of field name ──

		// Credit cards: Visa, Mastercard, Amex, Discover, Diners, JCB (13-19 digits)
		creditCardPattern: regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b`),

		// US SSN: 123-45-6789 format (basic pattern, excludes obvious non-SSNs via Check logic)
		ssnPattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),

		// AWS access key IDs (always start with AKIA, ASIA, or AIDA)
		awsKeyPattern: regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA)[0-9A-Z]{16}\b`),

		// GCP service account key / API key patterns
		gcpKeyPattern: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),

		// PEM private keys (RSA, EC, generic)
		privateKeyPattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),

		// JWT tokens (three base64url segments separated by dots)
		jwtPattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),

		// Bearer tokens in response bodies
		bearerPattern: regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}`),

		// Internal/private IPv4 addresses leaked in responses
		ipv4Pattern: regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),

		// Email addresses (basic but effective)
		emailPattern: regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),

		// Phone numbers: US format, international with +
		phonePattern: regexp.MustCompile(`(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),

		// IBAN (International Bank Account Number)
		ibanPattern: regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b`),

		// GitHub personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_)
		githubPattern: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b`),

		// Slack tokens (xoxb-, xoxp-, xoxs-, xoxa-, xoxr-)
		slackPattern: regexp.MustCompile(`\bxox[bpsar]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}\b`),

		// Stripe API keys (sk_live_, sk_test_, pk_live_, pk_test_, rk_live_, rk_test_)
		stripePattern: regexp.MustCompile(`\b[spr]k_(?:live|test)_[0-9a-zA-Z]{24,}\b`),

		// SendGrid API keys
		sendgridPattern: regexp.MustCompile(`\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b`),

		// Twilio API keys
		twilioPattern: regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),

		// Heroku API keys
		herokuPattern: regexp.MustCompile(`(?i)\bheroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),

		// Generic high-entropy hex/base64 secrets in JSON values (40+ char hex or 30+ char base64)
		genericSecretPat: regexp.MustCompile(`"[^"]*(?:key|token|secret|password|credential|auth)[^"]*"\s*:\s*"([a-fA-F0-9]{40,}|[A-Za-z0-9+/=]{30,})"`),

		// ── Wave 2: additional provider patterns (secrets-patterns-db, h33tlit/secret-regex-list) ──

		// PGP private key blocks
		pgpKeyPattern: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),

		// Slack incoming webhook URLs
		slackWebhookPat: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}`),

		// Facebook access tokens (start with EAACEdEose0cBA)
		facebookTokenPat: regexp.MustCompile(`\bEAACEdEose0cBA[0-9A-Za-z]+\b`),

		// Amazon MWS auth tokens
		amazonMWSPat: regexp.MustCompile(`\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),

		// Mailgun API keys (key-...)
		mailgunPat: regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`),

		// MailChimp API keys (hex32-us[0-9]+)
		mailchimpPat: regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`),

		// PayPal Braintree access tokens
		paypalBraintreePat: regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),

		// Square access tokens (sq0atp-)
		squareTokenPat: regexp.MustCompile(`\bsq0atp-[0-9A-Za-z_-]{22,}\b`),

		// Square OAuth secrets (sq0csp-)
		squareOAuthPat: regexp.MustCompile(`\bsq0csp-[0-9A-Za-z_-]{43,}\b`),

		// Password in URL (protocol://user:pass@host)
		passwordInURLPat: regexp.MustCompile(`[a-zA-Z]{3,10}://[^/\s:@]{1,100}:[^/\s:@]{1,100}@[a-zA-Z0-9.-]+`),

		// Google OAuth access tokens (ya29.)
		googleOAuthPat: regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{30,}\b`),

		// GCP OAuth client ID (*.apps.googleusercontent.com)
		gcpOAuthClientPat: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),

		// GCP service account JSON marker
		gcpServiceAcctPat: regexp.MustCompile(`"type"\s*:\s*"service_account"`),

		// Cloudinary URLs (cloudinary://key:secret@cloud)
		cloudinaryPat: regexp.MustCompile(`cloudinary://[0-9]{15}:[0-9A-Za-z_-]+@[a-zA-Z0-9_-]+`),

		// Firebase realtime database URLs
		firebaseURLPat: regexp.MustCompile(`\b[a-zA-Z0-9_-]+\.firebaseio\.com\b`),

		// Firebase Cloud Messaging server keys
		firebaseSecretPat: regexp.MustCompile(`\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\b`),

		// Databricks personal access tokens
		databricksTokenPat: regexp.MustCompile(`\bdapi[0-9a-f]{32}\b`),

		// Shopify access tokens and shared secrets
		shopifyTokenPat: regexp.MustCompile(`\bshpat_[0-9a-fA-F]{32}\b`),

		// Vercel tokens
		vercelTokenPat: regexp.MustCompile(`\b[A-Za-z0-9]{24}OAI[A-Za-z0-9]{24,}\b`),

		// Azure SAS tokens (sig= parameter in URLs)
		azureSASPat: regexp.MustCompile(`(?i)sig=[0-9A-Za-z%+/=]{43,}(&|$)`),

		// Supabase API keys (eyJ prefix, service_role or anon)
		supabaseKeyPat: regexp.MustCompile(`\bsbp_[0-9a-f]{40}\b`),

		// Datadog API keys (32-char hex)
		datadogKeyPat: regexp.MustCompile(`(?i)(?:datadog|dd)[_-]?(?:api[_-]?key|app[_-]?key)\s*[:=]\s*[0-9a-f]{32}`),

		// npm tokens
		npmTokenPat: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),

		// PyPI tokens
		pypiTokenPat: regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{50,}\b`),

		// NuGet API keys
		nugetKeyPat: regexp.MustCompile(`\boy2[a-zA-Z0-9]{43}\b`),

		// Docker Hub tokens / passwords
		dockerHubTokenPat: regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_-]{27,}\b`),
	}
}

func (d *DataExposureDetector) Check(path, method, responseBody string, responseSize int) *DataExposureFinding {
	if responseBody != "" {
		// ── Field-name matching (JSON key names) ────────────────────────
		if d.sensitivePatterns.MatchString(responseBody) {
			matches := d.sensitivePatterns.FindAllString(responseBody, 5)
			return &DataExposureFinding{
				Severity: core.SeverityCritical,
				Description: fmt.Sprintf("Response contains sensitive credentials/secrets: %d matches found. Fields: %s",
					len(matches), summarizeMatches(matches)),
			}
		}

		if d.piiPatterns.MatchString(responseBody) {
			matches := d.piiPatterns.FindAllString(responseBody, 5)
			return &DataExposureFinding{
				Severity: core.SeverityHigh,
				Description: fmt.Sprintf("Response contains PII data: %d matches found. Fields: %s",
					len(matches), summarizeMatches(matches)),
			}
		}

		// ── Value-based matching (actual data formats) ──────────────────

		// Critical: credentials and secrets
		if d.privateKeyPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a PEM private key. Private keys must never appear in API responses.",
			}
		}
		if d.awsKeyPattern.MatchString(responseBody) {
			match := d.awsKeyPattern.FindString(responseBody)
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: fmt.Sprintf("Response contains AWS access key ID: %s...%s", match[:8], match[len(match)-4:]),
			}
		}
		if d.stripePattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Stripe API key (sk_live/sk_test/pk_live/pk_test).",
			}
		}
		if d.githubPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a GitHub personal access token (ghp_/gho_/ghu_/ghs_/ghr_).",
			}
		}
		if d.slackPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Slack API token (xoxb-/xoxp-/xoxs-).",
			}
		}
		if d.sendgridPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a SendGrid API key.",
			}
		}
		if d.gcpKeyPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Google Cloud API key (AIza...).",
			}
		}
		if d.twilioPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a Twilio API key (SK...).",
			}
		}
		if d.herokuPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a Heroku API key.",
			}
		}

		// ── Wave 2: additional provider secrets (critical) ──────────────

		if d.pgpKeyPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a PGP private key block. Private keys must never appear in API responses.",
			}
		}
		if d.facebookTokenPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Facebook access token (EAACEdEose0cBA...).",
			}
		}
		if d.amazonMWSPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains an Amazon MWS auth token (amzn.mws.*).",
			}
		}
		if d.mailgunPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Mailgun API key (key-...).",
			}
		}
		if d.mailchimpPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a MailChimp API key.",
			}
		}
		if d.paypalBraintreePat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a PayPal/Braintree access token.",
			}
		}
		if d.squareTokenPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Square access token (sq0atp-...).",
			}
		}
		if d.squareOAuthPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Square OAuth secret (sq0csp-...).",
			}
		}
		if d.shopifyTokenPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Shopify access token (shpat_...).",
			}
		}
		if d.databricksTokenPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Databricks personal access token (dapi...).",
			}
		}
		if d.npmTokenPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains an npm token (npm_...).",
			}
		}
		if d.pypiTokenPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a PyPI token (pypi-...).",
			}
		}
		if d.dockerHubTokenPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Docker Hub token (dckr_pat_...).",
			}
		}
		if d.gcpServiceAcctPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a GCP service account JSON credential.",
			}
		}
		if d.cloudinaryPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Cloudinary URL with embedded credentials.",
			}
		}
		if d.firebaseSecretPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityCritical,
				Description: "Response contains a Firebase Cloud Messaging server key.",
			}
		}

		// ── Wave 2: high severity ──────────────────────────────────────

		if d.slackWebhookPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a Slack incoming webhook URL.",
			}
		}
		if d.googleOAuthPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a Google OAuth access token (ya29.*).",
			}
		}
		if d.gcpOAuthClientPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a GCP OAuth client ID (*.apps.googleusercontent.com).",
			}
		}
		if d.passwordInURLPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a URL with embedded credentials (protocol://user:pass@host).",
			}
		}
		if d.azureSASPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains an Azure SAS token.",
			}
		}
		if d.supabaseKeyPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a Supabase API key (sbp_...).",
			}
		}
		if d.datadogKeyPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a Datadog API/app key.",
			}
		}
		if d.nugetKeyPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a NuGet API key.",
			}
		}
		if d.vercelTokenPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a Vercel token.",
			}
		}

		// ── Wave 2: medium severity (infrastructure leakage) ───────────

		if d.firebaseURLPat.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityMedium,
				Description: "Response contains a Firebase realtime database URL (*.firebaseio.com).",
			}
		}

		// High: tokens and auth material
		if d.jwtPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a JWT token. Tokens should not be echoed in API response bodies.",
			}
		}
		if d.bearerPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains a Bearer token. Auth tokens should not appear in response payloads.",
			}
		}
		if d.genericSecretPat.MatchString(responseBody) {
			matches := d.genericSecretPat.FindAllString(responseBody, 3)
			return &DataExposureFinding{
				Severity: core.SeverityHigh,
				Description: fmt.Sprintf("Response contains high-entropy secret values in %d field(s): %s",
					len(matches), summarizeMatches(matches)),
			}
		}

		// High: financial data
		if d.creditCardPattern.MatchString(responseBody) {
			count := len(d.creditCardPattern.FindAllString(responseBody, -1))
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: fmt.Sprintf("Response contains %d credit card number(s) (Luhn-plausible patterns). PCI-DSS requires masking.", count),
			}
		}
		if d.ibanPattern.MatchString(responseBody) {
			return &DataExposureFinding{
				Severity:    core.SeverityHigh,
				Description: "Response contains IBAN (International Bank Account Number). Financial account numbers must be masked.",
			}
		}

		// High: PII values
		if d.ssnPattern.MatchString(responseBody) {
			allMatches := d.ssnPattern.FindAllString(responseBody, -1)
			// Filter out known invalid SSN ranges: 000-xx-xxxx, 666-xx-xxxx, 9xx-xx-xxxx, xxx-00-xxxx, xxx-xx-0000
			validCount := 0
			for _, m := range allMatches {
				parts := strings.Split(m, "-")
				if len(parts) == 3 && parts[0] != "000" && parts[0] != "666" && parts[0][0] != '9' && parts[1] != "00" && parts[2] != "0000" {
					validCount++
				}
			}
			if validCount > 0 {
				return &DataExposureFinding{
					Severity:    core.SeverityHigh,
					Description: fmt.Sprintf("Response contains %d US Social Security Number(s). SSNs must never appear unmasked in API responses.", validCount),
				}
			}
		}

		// Medium: internal infrastructure leakage
		if d.ipv4Pattern.MatchString(responseBody) {
			ips := d.ipv4Pattern.FindAllString(responseBody, 5)
			return &DataExposureFinding{
				Severity:    core.SeverityMedium,
				Description: fmt.Sprintf("Response leaks %d internal/private IP address(es): %s", len(ips), strings.Join(ips, ", ")),
			}
		}
	}

	// Abnormally large response for a single-object endpoint
	if responseSize > 1024*1024 && !strings.Contains(path, "/export") && !strings.Contains(path, "/download") && !strings.Contains(path, "/bulk") {
		return &DataExposureFinding{
			Severity: core.SeverityMedium,
			Description: fmt.Sprintf("Response size %d bytes (%.1f MB) is unusually large for endpoint %s %s",
				responseSize, float64(responseSize)/(1024*1024), method, path),
		}
	}

	return nil
}

func summarizeMatches(matches []string) string {
	if len(matches) == 0 {
		return ""
	}
	fields := make([]string, 0, len(matches))
	for _, m := range matches {
		// Extract just the field name
		idx := strings.Index(m, "\"")
		if idx >= 0 {
			end := strings.Index(m[idx+1:], "\"")
			if end > 0 {
				fields = append(fields, m[idx+1:idx+1+end])
			}
		}
	}
	return strings.Join(fields, ", ")
}

// ===========================================================================
// GraphQLGuard — prevents GraphQL-specific abuse patterns
// ===========================================================================

type GraphQLGuard struct {
	maxDepth           int
	maxAliases         int
	maxBatchSize       int
	maxComplexity      int
	depthPattern       *regexp.Regexp
	aliasPattern       *regexp.Regexp
	introspection      *regexp.Regexp
	dangerousMutations *regexp.Regexp
}

type GraphQLFinding struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
}

func NewGraphQLGuard(settings map[string]interface{}) *GraphQLGuard {
	maxDepth := 10
	maxAliases := 20
	maxBatch := 10
	if val, ok := settings["graphql_max_depth"]; ok {
		if v, ok := val.(float64); ok {
			maxDepth = int(v)
		}
	}
	if val, ok := settings["graphql_max_aliases"]; ok {
		if v, ok := val.(float64); ok {
			maxAliases = int(v)
		}
	}

	return &GraphQLGuard{
		maxDepth:           maxDepth,
		maxAliases:         maxAliases,
		maxBatchSize:       maxBatch,
		maxComplexity:      1000,
		depthPattern:       regexp.MustCompile(`\{`),
		aliasPattern:       regexp.MustCompile(`\w+\s*:\s*\w+\s*[\({]`),
		introspection:      regexp.MustCompile(`(?i)(__schema|__type|__typename\s*\{|introspectionQuery)`),
		dangerousMutations: regexp.MustCompile(`(?i)(deleteAll|dropDatabase|truncate|destroyAll|purge|resetAll|wipeData)`),
	}
}

func (g *GraphQLGuard) Analyze(query, operationName, userID, ip string) []GraphQLFinding {
	var findings []GraphQLFinding

	// Depth analysis (count nesting levels via brace counting)
	depth := g.measureDepth(query)
	if depth > g.maxDepth {
		findings = append(findings, GraphQLFinding{
			Title:       "GraphQL Query Depth Exceeded",
			Description: fmt.Sprintf("Query depth %d exceeds maximum %d. Deep queries can cause exponential resource consumption (DoS).", depth, g.maxDepth),
			Severity:    core.SeverityHigh,
			AlertType:   "graphql_depth",
		})
	}

	// Alias abuse (used to bypass rate limiting or amplify queries)
	aliasCount := len(g.aliasPattern.FindAllString(query, -1))
	if aliasCount > g.maxAliases {
		findings = append(findings, GraphQLFinding{
			Title:       "GraphQL Alias Abuse",
			Description: fmt.Sprintf("Query contains %d aliases (max: %d). Alias abuse can bypass rate limiting and amplify query cost.", aliasCount, g.maxAliases),
			Severity:    core.SeverityHigh,
			AlertType:   "graphql_alias_abuse",
		})
	}

	// Introspection in production
	if g.introspection.MatchString(query) {
		findings = append(findings, GraphQLFinding{
			Title:       "GraphQL Introspection Query",
			Description: "Introspection query detected. Introspection exposes the entire API schema and should be disabled in production.",
			Severity:    core.SeverityMedium,
			AlertType:   "graphql_introspection",
		})
	}

	// Batch query detection (array of queries)
	if strings.HasPrefix(strings.TrimSpace(query), "[") {
		// Count operations in batch
		opCount := strings.Count(query, "query ") + strings.Count(query, "mutation ")
		if opCount > g.maxBatchSize {
			findings = append(findings, GraphQLFinding{
				Title:       "GraphQL Batch Query Abuse",
				Description: fmt.Sprintf("Batch request contains %d operations (max: %d). Batch abuse can overwhelm the server.", opCount, g.maxBatchSize),
				Severity:    core.SeverityHigh,
				AlertType:   "graphql_batch",
			})
		}
	}

	// Dangerous mutations
	if g.dangerousMutations.MatchString(query) {
		findings = append(findings, GraphQLFinding{
			Title:       "Dangerous GraphQL Mutation",
			Description: "Query contains a potentially destructive mutation (deleteAll, truncate, etc.).",
			Severity:    core.SeverityCritical,
			AlertType:   "graphql_dangerous_mutation",
		})
	}

	// Field suggestion exploitation (error-based schema discovery)
	if strings.Contains(query, "__") && !g.introspection.MatchString(query) {
		findings = append(findings, GraphQLFinding{
			Title:       "GraphQL Schema Probing",
			Description: "Query uses double-underscore fields for schema probing without full introspection.",
			Severity:    core.SeverityLow,
			AlertType:   "graphql_schema_probe",
		})
	}

	return findings
}

func (g *GraphQLGuard) measureDepth(query string) int {
	maxDepth := 0
	current := 0
	for _, c := range query {
		if c == '{' {
			current++
			if current > maxDepth {
				maxDepth = current
			}
		} else if c == '}' {
			current--
		}
	}
	return maxDepth
}

// ===========================================================================
// JWTValidator — detects JWT security issues
// ===========================================================================

type JWTValidator struct {
	weakAlgorithms map[string]bool
	noneVariants   *regexp.Regexp
}

type JWTFinding struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
}

type InboundWebhookScanner struct {
	routePattern             *regexp.Regexp
	providerFingerprint      *regexp.Regexp
	dangerousCommandPattern  *regexp.Regexp
	infrastructurePivotRegex *regexp.Regexp
	encodedBlobPattern       *regexp.Regexp
	encodedExecPattern       *regexp.Regexp
}

type WebhookFinding struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
}

func NewInboundWebhookScanner() *InboundWebhookScanner {
	return &InboundWebhookScanner{
		routePattern:             regexp.MustCompile(`(?i)(/webhook[s]?/|/hooks?/|/integrations?/|/callbacks?/|/automation/)`),
		providerFingerprint:      regexp.MustCompile(`(?i)(slack|github|gitlab|stripe|shopify|zapier|n8n|make\.com|pipedream|twilio|pagerduty|workato)`),
		dangerousCommandPattern:  regexp.MustCompile(`(?i)(curl\s+https?://|wget\s+https?://|powershell(?:\.exe)?\b|invoke-webrequest|cmd\.exe\b|/bin/sh\b|bash\s+-c|certutil\b|mshta\b|python\s+-c)`),
		infrastructurePivotRegex: regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|/var/run/secrets/kubernetes\.io/serviceaccount|/etc/shadow|docker\.sock|kubelet|apiVersion:\s*v1|kind:\s*Pod)`),
		encodedBlobPattern:       regexp.MustCompile(`(?:[A-Za-z0-9+/]{160,}={0,2}|[A-Za-z0-9_-]{180,}\.[A-Za-z0-9_-]{40,}\.[A-Za-z0-9_-]{20,})`),
		encodedExecPattern:       regexp.MustCompile(`(?i)(powershell(?:\.exe)?\b.*(?:-enc|-encodedcommand)\b|frombase64string|bash\s+-c\s+["']?(?:base64|echo)|cmd\.exe\s+/c|eval\s*\(\s*atob)`),
	}
}

func (s *InboundWebhookScanner) Check(path, method, body, headers, contentType, provider, userAgent string) []WebhookFinding {
	var findings []WebhookFinding
	if !s.looksLikeWebhook(path, headers, provider, userAgent) {
		return nil
	}

	lowerHeaders := strings.ToLower(headers)
	hasEncodedExec := s.encodedExecPattern.MatchString(body)
	hasLargeEncodedBlob := s.encodedBlobPattern.MatchString(body)
	if s.dangerousCommandPattern.MatchString(body) {
		findings = append(findings, WebhookFinding{
			Title:       "Inbound Webhook Command Delivery",
			Description: "Webhook payload contains shell or process-spawning command content commonly used to pivot automation systems into RCE.",
			Severity:    core.SeverityCritical,
			AlertType:   "webhook_infra_abuse",
		})
	}
	if s.infrastructurePivotRegex.MatchString(body) {
		findings = append(findings, WebhookFinding{
			Title:       "Inbound Webhook Infrastructure Pivot",
			Description: "Webhook payload references cloud metadata, Kubernetes service-account, or host secret paths that indicate infrastructure abuse rather than normal business events.",
			Severity:    core.SeverityCritical,
			AlertType:   "webhook_infra_abuse",
		})
	}
	if hasEncodedExec {
		findings = append(findings, WebhookFinding{
			Title:       "Obfuscated Webhook Execution Payload",
			Description: "Webhook payload includes encoded execution patterns such as PowerShell -enc, base64 staging, or cmd.exe /c chains commonly used to evade trusted SaaS origin scrutiny.",
			Severity:    core.SeverityCritical,
			AlertType:   "webhook_infra_abuse",
		})
	}
	if hasLargeEncodedBlob && !strings.Contains(lowerHeaders, "x-signature") && !strings.Contains(lowerHeaders, "x-hub-signature") && !strings.Contains(lowerHeaders, "x-slack-signature") {
		findings = append(findings, WebhookFinding{
			Title:       "Unsigned Webhook Payload Smuggling",
			Description: "Webhook endpoint received a large encoded blob without a provider signature header, which is consistent with staged payload smuggling through automation hooks.",
			Severity:    core.SeverityHigh,
			AlertType:   "webhook_payload_smuggling",
		})
	}
	if hasEncodedExec && hasLargeEncodedBlob {
		findings = append(findings, WebhookFinding{
			Title:       "Encoded Webhook Payload Smuggling",
			Description: "Webhook body combines encoded execution primitives with a large staged blob, which is strong evidence of smuggled automation abuse even before full decoding.",
			Severity:    core.SeverityHigh,
			AlertType:   "webhook_payload_smuggling",
		})
	}
	if segment, entropy := largestEncodedSegment(body); len(segment) >= 180 && entropy >= 4.3 {
		findings = append(findings, WebhookFinding{
			Title:       "High-Entropy Webhook Payload",
			Description: fmt.Sprintf("Webhook body contains a large encoded segment with Shannon entropy %.2f, which is atypical for normal event notifications and consistent with obfuscated payload delivery.", entropy),
			Severity:    core.SeverityHigh,
			AlertType:   "webhook_payload_smuggling",
		})
	}
	if strings.Contains(strings.ToLower(contentType), "application/octet-stream") || strings.Contains(strings.ToLower(contentType), "multipart/form-data") {
		findings = append(findings, WebhookFinding{
			Title:       "Webhook Binary Drop Attempt",
			Description: fmt.Sprintf("Webhook endpoint received %s content via %s, which is atypical for signed event notifications and often used to stage tooling or malware.", contentType, method),
			Severity:    core.SeverityHigh,
			AlertType:   "webhook_binary_drop",
		})
	}

	return dedupeWebhookFindings(findings)
}

func (s *InboundWebhookScanner) looksLikeWebhook(path, headers, provider, userAgent string) bool {
	return s.routePattern.MatchString(path) ||
		s.providerFingerprint.MatchString(headers) ||
		s.providerFingerprint.MatchString(provider) ||
		s.providerFingerprint.MatchString(userAgent)
}

func dedupeWebhookFindings(findings []WebhookFinding) []WebhookFinding {
	if len(findings) < 2 {
		return findings
	}
	seen := make(map[string]bool, len(findings))
	deduped := make([]WebhookFinding, 0, len(findings))
	for _, finding := range findings {
		key := finding.AlertType + ":" + finding.Title
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, finding)
	}
	return deduped
}

func extractAPIJWTIdentifier(event *core.SecurityEvent) string {
	if jti := getStringDetail(event, "jti"); jti != "" {
		return jti
	}
	if tokenID := getStringDetail(event, "token_id"); tokenID != "" {
		return tokenID
	}
	if claims := getStringDetail(event, "claims"); claims != "" {
		if jti := extractJSONField(claims, "jti"); jti != "" {
			return jti
		}
	}
	tokenCandidates := []string{
		getStringDetail(event, "token"),
		getStringDetail(event, "authorization"),
		extractBearerToken(getStringDetail(event, "headers")),
	}
	for _, candidate := range tokenCandidates {
		if token := extractBearerToken(candidate); token != "" {
			if jti := extractJWTJTI(token); jti != "" {
				return jti
			}
		}
		if jti := extractJWTJTI(candidate); jti != "" {
			return jti
		}
	}
	return ""
}

func extractBearerToken(input string) string {
	if input == "" {
		return ""
	}
	lower := strings.ToLower(input)
	idx := strings.Index(lower, "bearer ")
	if idx < 0 {
		return ""
	}
	token := strings.TrimSpace(input[idx+7:])
	if newline := strings.IndexAny(token, "\r\n"); newline >= 0 {
		token = token[:newline]
	}
	if comma := strings.Index(token, ","); comma >= 0 {
		token = token[:comma]
	}
	return strings.TrimSpace(token)
}

func extractJSONField(jsonLike, key string) string {
	needle := `"` + key + `"`
	idx := strings.Index(jsonLike, needle)
	if idx < 0 {
		return ""
	}
	rest := jsonLike[idx+len(needle):]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[colon+1:])
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func extractJWTJTI(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	return extractJSONField(string(payload), "jti")
}

func largestEncodedSegment(body string) (string, float64) {
	matches := regexp.MustCompile(`[A-Za-z0-9+/=_-]{80,}`).FindAllString(body, -1)
	bestSegment := ""
	bestEntropy := 0.0
	for _, match := range matches {
		entropy := shannonEntropy(match)
		if len(match) > len(bestSegment) || (len(match) == len(bestSegment) && entropy > bestEntropy) {
			bestSegment = match
			bestEntropy = entropy
		}
	}
	return bestSegment, bestEntropy
}

func shannonEntropy(input string) float64 {
	if input == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(input); i++ {
		freq[input[i]]++
	}
	n := float64(len(input))
	entropy := 0.0
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := f / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func NewJWTValidator() *JWTValidator {
	return &JWTValidator{
		weakAlgorithms: map[string]bool{
			"none": true, "None": true, "NONE": true, "nOnE": true,
			"HS256": false, // not weak per se, but flag if used with public key
		},
		noneVariants: regexp.MustCompile(`(?i)^n[o0]n[e3]$`),
	}
}

func (j *JWTValidator) Validate(token, header, algorithm, claims string) []JWTFinding {
	var findings []JWTFinding

	algoLower := strings.ToLower(algorithm)

	// "none" algorithm attack
	if j.noneVariants.MatchString(algorithm) {
		findings = append(findings, JWTFinding{
			Title:       "JWT Algorithm None Attack",
			Description: fmt.Sprintf("JWT uses algorithm %q — this bypasses signature verification entirely. Critical authentication bypass.", algorithm),
			Severity:    core.SeverityCritical,
			AlertType:   "jwt_none_algorithm",
		})
	}

	// Algorithm confusion: RS256 -> HS256 (use public key as HMAC secret)
	if algoLower == "hs256" && strings.Contains(strings.ToLower(header), "rs256") {
		findings = append(findings, JWTFinding{
			Title:       "JWT Algorithm Confusion Attack",
			Description: "JWT header originally specified RS256 but was changed to HS256. This is an algorithm confusion attack that can forge tokens using the public key.",
			Severity:    core.SeverityCritical,
			AlertType:   "jwt_algorithm_confusion",
		})
	}

	// Weak algorithms
	if algoLower == "hs256" {
		findings = append(findings, JWTFinding{
			Title:       "JWT Using HS256",
			Description: "JWT uses HS256 (symmetric). Consider RS256 or ES256 (asymmetric) for better security — symmetric keys are harder to rotate and easier to leak.",
			Severity:    core.SeverityLow,
			AlertType:   "jwt_weak_algorithm",
		})
	}

	// Missing expiration
	if claims != "" && !strings.Contains(claims, "\"exp\"") {
		findings = append(findings, JWTFinding{
			Title:       "JWT Missing Expiration",
			Description: "JWT has no expiration claim (exp). Tokens without expiration are valid forever if compromised.",
			Severity:    core.SeverityHigh,
			AlertType:   "jwt_no_expiry",
		})
	}

	// Empty signature (token ends with ".")
	if token != "" && strings.HasSuffix(token, ".") {
		findings = append(findings, JWTFinding{
			Title:       "JWT Empty Signature",
			Description: "JWT has an empty signature segment. This token has no integrity protection.",
			Severity:    core.SeverityCritical,
			AlertType:   "jwt_empty_signature",
		})
	}

	// JKU/X5U header injection
	headerLower := strings.ToLower(header)
	if strings.Contains(headerLower, "\"jku\"") || strings.Contains(headerLower, "\"x5u\"") {
		findings = append(findings, JWTFinding{
			Title:       "JWT Key URL Injection (JKU/X5U)",
			Description: "JWT header contains jku or x5u claim pointing to an external key URL. Attacker can host their own key and forge tokens.",
			Severity:    core.SeverityCritical,
			AlertType:   "jwt_key_injection",
		})
	}

	return findings
}

// ===========================================================================
// SSRFViaAPIDetector — detects SSRF attempts through API parameters
// ===========================================================================

type SSRFViaAPIDetector struct {
	internalPatterns *regexp.Regexp
	cloudMetadata    *regexp.Regexp
	urlParams        *regexp.Regexp
}

type SSRFFinding struct {
	Severity    core.Severity
	Description string
}

func NewSSRFViaAPIDetector() *SSRFViaAPIDetector {
	return &SSRFViaAPIDetector{
		internalPatterns: regexp.MustCompile(`(?i)(127\.0\.0\.1|0\.0\.0\.0|localhost|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|\[::1\]|\[0:0:0:0:0:0:0:1\]|0x7f|2130706433|017700000001|2852039166|012\.012\.012\.012|\.internal\.|\.local\.|\.corp\.|\.home\.)`),
		cloudMetadata:    regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|_astro/redir\?url=)`),
		urlParams:        regexp.MustCompile(`(?i)(url|uri|link|href|src|source|redirect|callback|webhook|endpoint|target|dest|fetch|load|proxy|forward)=`),
	}
}

func (s *SSRFViaAPIDetector) Check(path, body, urlParam string) *SSRFFinding {
	// Check URL parameters for internal/metadata targets
	targets := []string{urlParam, body}
	for _, target := range targets {
		if target == "" {
			continue
		}

		if s.cloudMetadata.MatchString(target) {
			return &SSRFFinding{
				Severity:    core.SeverityCritical,
				Description: "Request targets cloud metadata endpoint (169.254.169.254 or equivalent). This can expose instance credentials and secrets.",
			}
		}

		if s.internalPatterns.MatchString(target) {
			return &SSRFFinding{
				Severity:    core.SeverityHigh,
				Description: "Request targets internal/private IP address. SSRF can be used to scan internal networks and access internal services.",
			}
		}
	}

	// Check for cloud metadata patterns in the path (e.g., Astro redirect SSRF)
	if s.cloudMetadata.MatchString(path) {
		return &SSRFFinding{
			Severity:    core.SeverityCritical,
			Description: "Request path targets cloud metadata endpoint (169.254.169.254 or equivalent). This can expose instance credentials and secrets.",
		}
	}

	// Check for URL parameters in the path that might be SSRF vectors
	if s.urlParams.MatchString(path) && s.internalPatterns.MatchString(path) {
		return &SSRFFinding{
			Severity:    core.SeverityHigh,
			Description: "URL parameter in path contains internal IP address.",
		}
	}

	return nil
}

// ===========================================================================
// ResponseAnomalyAnalyzer — tracks API response patterns for anomalies
// ===========================================================================

type ResponseAnomalyAnalyzer struct {
	mu        sync.RWMutex
	endpoints *lru.Cache[string, *endpointStats]
}

type endpointStats struct {
	totalRequests int
	errorCount    int
	totalSize     int64
	sizeCount     int
	windowStart   time.Time
	lastSeen      time.Time
	// Baseline (from previous window)
	baselineErrorRate float64
	baselineAvgSize   int
	baselineSamples   int
}

type ResponseAnomaly struct {
	ErrorSpike          bool
	ResponseSizeAnomaly bool
	ErrorRate           float64
	BaselineErrorRate   float64
	ErrorCount          int
	Window              time.Duration
	SizeRatio           float64
	AvgResponseSize     int
}

func NewResponseAnomalyAnalyzer() *ResponseAnomalyAnalyzer {
	eCache, _ := lru.New[string, *endpointStats](20000)
	return &ResponseAnomalyAnalyzer{
		endpoints: eCache,
	}
}

func (r *ResponseAnomalyAnalyzer) RecordRequest(method, path string, statusCode int, ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := method + ":" + normalizePath(path)
	now := time.Now()

	stats, exists := r.endpoints.Get(key)
	if !exists {
		stats = &endpointStats{windowStart: now}
		r.endpoints.Add(key, stats)
	}

	// Rotate window every 5 minutes
	if now.Sub(stats.windowStart) > 5*time.Minute {
		if stats.totalRequests > 0 {
			currentErrorRate := float64(stats.errorCount) / float64(stats.totalRequests)
			stats.baselineErrorRate = (stats.baselineErrorRate*float64(stats.baselineSamples) + currentErrorRate) / float64(stats.baselineSamples+1)
			if stats.sizeCount > 0 {
				stats.baselineAvgSize = int((int64(stats.baselineAvgSize)*int64(stats.baselineSamples) + stats.totalSize/int64(stats.sizeCount)) / int64(stats.baselineSamples+1))
			}
			stats.baselineSamples++
		}
		stats.totalRequests = 0
		stats.errorCount = 0
		stats.totalSize = 0
		stats.sizeCount = 0
		stats.windowStart = now
	}

	stats.totalRequests++
	stats.lastSeen = now
	if statusCode >= 400 {
		stats.errorCount++
	}
}

func (r *ResponseAnomalyAnalyzer) Analyze(method, path string, statusCode, responseSize int, ip string) ResponseAnomaly {
	r.mu.Lock()
	defer r.mu.Unlock()

	anomaly := ResponseAnomaly{}
	key := method + ":" + normalizePath(path)

	stats, exists := r.endpoints.Get(key)
	if !exists {
		return anomaly
	}

	// Track response size
	if responseSize > 0 {
		stats.totalSize += int64(responseSize)
		stats.sizeCount++
	}

	now := time.Now()
	anomaly.Window = now.Sub(stats.windowStart)

	// Error rate spike detection
	if stats.totalRequests > 20 && stats.baselineSamples > 3 {
		currentErrorRate := float64(stats.errorCount) / float64(stats.totalRequests)
		anomaly.ErrorRate = currentErrorRate
		anomaly.BaselineErrorRate = stats.baselineErrorRate
		anomaly.ErrorCount = stats.errorCount

		// Spike: current error rate is 3x baseline and above 20%
		if stats.baselineErrorRate > 0 && currentErrorRate > stats.baselineErrorRate*3 && currentErrorRate > 0.2 {
			anomaly.ErrorSpike = true
		}
		// Also flag if error rate is above 50% regardless of baseline
		if currentErrorRate > 0.5 && stats.totalRequests > 50 {
			anomaly.ErrorSpike = true
		}
	}

	// Response size anomaly
	if responseSize > 0 && stats.baselineAvgSize > 0 && stats.baselineSamples > 3 {
		ratio := float64(responseSize) / float64(stats.baselineAvgSize)
		anomaly.SizeRatio = ratio
		anomaly.AvgResponseSize = stats.baselineAvgSize
		if ratio > 5.0 && responseSize > 10240 { // 5x above average and > 10KB
			anomaly.ResponseSizeAnomaly = true
		}
	}

	return anomaly
}

// Cleanup handled by LRU

// ===========================================================================
// APIRegistry — shadow API detection with learning phase
// ===========================================================================

type APIRegistry struct {
	mu            sync.RWMutex
	documented    *lru.Cache[string, bool] // "METHOD:/path" -> true
	observed      *lru.Cache[string, int]  // "METHOD:/path" -> access count
	learningStart time.Time
	learningDone  bool
}

func NewAPIRegistry() *APIRegistry {
	dCache, _ := lru.New[string, bool](50000)
	oCache, _ := lru.New[string, int](50000)
	return &APIRegistry{
		documented:    dCache,
		observed:      oCache,
		learningStart: time.Now(),
	}
}

func (r *APIRegistry) RegisterEndpoint(method, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := method + ":" + normalizePath(path)
	r.documented.Add(key, true)
}

func (r *APIRegistry) IsUndocumented(method, path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := method + ":" + normalizePath(path)

	if _, exists := r.documented.Get(key); exists {
		return false
	}

	// Learning phase: first hour, absorb all endpoints as baseline
	if !r.learningDone {
		if time.Since(r.learningStart) < time.Hour {
			r.documented.Add(key, true)
			return false
		}
		r.learningDone = true
	}

	return true
}

func (r *APIRegistry) RecordAccess(method, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := method + ":" + normalizePath(path)
	val, _ := r.observed.Get(key)
	r.observed.Add(key, val+1)
}

// ===========================================================================
// EndpointRateLimiter — per-endpoint rate limiting with burst detection
// ===========================================================================

type EndpointRateLimiter struct {
	mu           sync.RWMutex
	counters     *lru.Cache[string, *epCounter]
	maxPerMinute int
}

type epCounter struct {
	count    int
	window   time.Time
	lastSeen time.Time
}

type RateLimitExceeded struct {
	Severity core.Severity
	Count    int
	Limit    int
	Window   time.Duration
	Detail   string
}

func NewEndpointRateLimiter(settings map[string]interface{}) *EndpointRateLimiter {
	maxRPM := 200
	if val, ok := settings["api_max_rpm"]; ok {
		if v, ok := val.(float64); ok {
			maxRPM = int(v)
		}
	}
	eCache, _ := lru.New[string, *epCounter](50000)
	return &EndpointRateLimiter{
		counters:     eCache,
		maxPerMinute: maxRPM,
	}
}

func (rl *EndpointRateLimiter) Check(ip, method, path string) *RateLimitExceeded {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := ip + ":" + method + ":" + normalizePath(path)
	now := time.Now()

	counter, exists := rl.counters.Get(key)
	if !exists {
		rl.counters.Add(key, &epCounter{count: 1, window: now, lastSeen: now})
		return nil
	}

	if now.Sub(counter.window) > time.Minute {
		counter.count = 0
		counter.window = now
	}

	counter.count++
	counter.lastSeen = now

	if counter.count > rl.maxPerMinute {
		severity := core.SeverityMedium
		detail := "Standard rate limit exceeded"
		if counter.count > rl.maxPerMinute*5 {
			severity = core.SeverityHigh
			detail = "Severe rate limit violation — possible automated attack"
		}
		if counter.count > rl.maxPerMinute*20 {
			severity = core.SeverityCritical
			detail = "Extreme rate limit violation — active DoS or brute force attack"
		}
		return &RateLimitExceeded{
			Severity: severity,
			Count:    counter.count,
			Limit:    rl.maxPerMinute,
			Window:   now.Sub(counter.window),
			Detail:   detail,
		}
	}

	return nil
}

// Cleanup handled by LRU

// ===========================================================================
// Helpers
// ===========================================================================

func normalizePath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if isNumericID(part) || isUUID(part) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func isNumericID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	return ""
}

func getIntDetail(event *core.SecurityEvent, key string) int {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func isPrivilegedMCPRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "3", "4", "admin", "root", "owner", "maintainer", "security_admin":
		return true
	default:
		return false
	}
}

func extractMCPServerURLs(event *core.SecurityEvent, body string) []string {
	seen := make(map[string]bool)
	var urls []string

	for _, blob := range []string{
		getStringDetail(event, "server_url"),
		getStringDetail(event, "mcp_server_url"),
		getStringDetail(event, "target_url"),
		getStringDetail(event, "endpoint"),
		getStringDetail(event, "url_param"),
		body,
	} {
		for _, match := range httpURLPattern.FindAllString(blob, -1) {
			if !seen[match] {
				seen[match] = true
				urls = append(urls, match)
			}
		}
	}
	return urls
}

func extractMCPServerCommands(body string) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	matches := mcpServerCommandPattern.FindAllStringSubmatch(body, -1)
	commands := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		commands = append(commands, strings.TrimSpace(match[1]+" "+match[2]))
	}
	return commands
}

func isAllowedMCPServerURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return false
	}

	switch strings.ToLower(parsed.Hostname()) {
	case "localhost", "127.0.0.1", "::1", "internal-mcp.svc.cluster.local":
		return parsed.Scheme == "http" || parsed.Scheme == "https"
	default:
		return false
	}
}

// ===========================================================================
// Security Misconfiguration Detection (API8:2023)
// ===========================================================================

// checkSecurityMisconfiguration detects common API security misconfigurations
// including CORS issues, verbose errors, missing security headers, and debug endpoints.
// Ref: OWASP API8:2023 — Security Misconfiguration.
func (f *Fortress) checkSecurityMisconfiguration(event *core.SecurityEvent) {
	path := getStringDetail(event, "path")
	corsOrigin := getStringDetail(event, "cors_origin")
	corsCredentials := getStringDetail(event, "cors_credentials")
	errorBody := getStringDetail(event, "error_body")
	responseHeaders := getStringDetail(event, "response_headers")
	method := getStringDetail(event, "method")

	// CORS wildcard with credentials — critical misconfiguration
	if corsOrigin == "*" && corsCredentials == "true" {
		f.raiseAlert(event, core.SeverityCritical,
			"CORS Misconfiguration: Wildcard with Credentials [API8:2023]",
			fmt.Sprintf("API at %s %s has Access-Control-Allow-Origin: * with credentials enabled. "+
				"This allows any origin to make authenticated requests.", method, path),
			"security_misconfiguration")
	}

	// Verbose error messages leaking internals
	if errorBody != "" {
		verbosePatterns := []struct {
			pattern *regexp.Regexp
			label   string
		}{
			{regexp.MustCompile("(?i)(stack\\s*trace|traceback|at\\s+[a-zA-Z0-9_.]+\\([^)]*\\)\\s*$)"), "stack_trace"},
			{regexp.MustCompile("(?i)(sql\\s*(syntax|error|exception)|ORA-\\d+|pg_catalog|mysql_)"), "sql_error"},
			{regexp.MustCompile("(?i)(internal\\s+server\\s+error.*?(file|line|column|path)|debug\\s*=\\s*true)"), "debug_info"},
			{regexp.MustCompile("(?i)(version\\s*[:=]\\s*[\\d.]+.*(framework|server|runtime|engine))"), "version_disclosure"},
		}
		for _, vp := range verbosePatterns {
			if vp.pattern.MatchString(errorBody) {
				f.raiseAlert(event, core.SeverityMedium,
					fmt.Sprintf("Verbose Error Disclosure: %s [API8:2023]", vp.label),
					fmt.Sprintf("API response from %s %s contains %s information. "+
						"Verbose errors help attackers understand internal architecture.", method, path, vp.label),
					"security_misconfiguration")
				break
			}
		}
	}

	// Missing security headers
	if responseHeaders != "" {
		headersLower := strings.ToLower(responseHeaders)
		missingHeaders := []struct {
			header string
			label  string
		}{
			{"x-content-type-options", "X-Content-Type-Options"},
			{"strict-transport-security", "Strict-Transport-Security"},
			{"x-frame-options", "X-Frame-Options"},
		}
		missing := []string{}
		for _, mh := range missingHeaders {
			if !strings.Contains(headersLower, mh.header) {
				missing = append(missing, mh.label)
			}
		}
		if len(missing) >= 2 {
			f.raiseAlert(event, core.SeverityMedium,
				"Missing Security Headers [API8:2023]",
				fmt.Sprintf("API response from %s %s is missing security headers: %s. "+
					"These headers protect against common web attacks.",
					method, path, strings.Join(missing, ", ")),
				"security_misconfiguration")
		}
	}

	// Debug/admin endpoints exposed
	if path != "" {
		debugPatterns := regexp.MustCompile("(?i)(/debug/|/actuator/|/swagger-ui|/api-docs|/graphiql|/phpinfo|/__debug__|/trace|/metrics|/health/detailed|/env|/configprops)")
		if debugPatterns.MatchString(path) {
			f.raiseAlert(event, core.SeverityHigh,
				"Debug/Admin Endpoint Exposed [API8:2023]",
				fmt.Sprintf("Debug or admin endpoint accessed: %s %s from IP %s. "+
					"These endpoints should be disabled or restricted in production.", method, path, event.SourceIP),
				"security_misconfiguration")
		}
	}
}

// ===========================================================================
// Unsafe Consumption of APIs Detection (API10:2023)
// ===========================================================================

// checkUnsafeConsumption detects when the API blindly trusts data from upstream/third-party APIs.
// Ref: OWASP API10:2023 — Unsafe Consumption of APIs.
func (f *Fortress) checkUnsafeConsumption(event *core.SecurityEvent) {
	upstreamURL := getStringDetail(event, "upstream_url")
	responseBody := getStringDetail(event, "response_body")
	statusCode := getIntDetail(event, "status_code")
	validated := getStringDetail(event, "validated")
	tlsUsed := getStringDetail(event, "tls")
	redirectCount := getIntDetail(event, "redirect_count")

	if upstreamURL == "" {
		return
	}

	// Upstream response not validated before use
	if validated != "true" && responseBody != "" {
		// Check for injection payloads in upstream response
		injectionPatterns := regexp.MustCompile("(?i)(<script|javascript:|on(error|load|click)=|\\$\\{|\\{\\{|;\\s*(drop|delete|update|insert)\\s)")
		if injectionPatterns.MatchString(responseBody) {
			f.raiseAlert(event, core.SeverityCritical,
				"Unsafe API Consumption: Injection in Upstream Response [API10:2023]",
				fmt.Sprintf("Upstream API %s returned response containing injection payloads that were not validated before processing. "+
					"This can lead to second-order injection attacks.", truncateStr(upstreamURL, 200)),
				"unsafe_api_consumption")
		}
	}

	// Upstream API returning errors but still being consumed
	if statusCode >= 500 && validated != "true" {
		f.raiseAlert(event, core.SeverityMedium,
			"Unsafe API Consumption: Error Response Consumed [API10:2023]",
			fmt.Sprintf("Upstream API %s returned status %d but response was consumed without validation. "+
				"Error responses from third-party APIs should be handled defensively.", truncateStr(upstreamURL, 200), statusCode),
			"unsafe_api_consumption")
	}

	// No TLS for upstream communication
	if tlsUsed == "false" || strings.HasPrefix(strings.ToLower(upstreamURL), "http://") {
		f.raiseAlert(event, core.SeverityHigh,
			"Unsafe API Consumption: No TLS [API10:2023]",
			fmt.Sprintf("Upstream API call to %s uses unencrypted HTTP. "+
				"All third-party API communication should use TLS.", truncateStr(upstreamURL, 200)),
			"unsafe_api_consumption")
	}

	// Excessive redirects — potential SSRF via redirect chain
	if redirectCount > 5 {
		f.raiseAlert(event, core.SeverityHigh,
			"Unsafe API Consumption: Excessive Redirects [API10:2023]",
			fmt.Sprintf("Upstream API call to %s followed %d redirects. "+
				"Excessive redirects may indicate SSRF via redirect chain.", truncateStr(upstreamURL, 200), redirectCount),
			"unsafe_api_consumption")
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
