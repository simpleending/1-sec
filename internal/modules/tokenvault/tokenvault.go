package tokenvault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// TokenVault is the Auth0 Token Vault sub-component of AI Containment (Module 11).
// It enables secure OAuth 2.0 token delegation for AI agents via Auth0's
// Token Vault, allowing agents to access third-party APIs (Google, GitHub,
// Slack, etc.) on behalf of users without handling raw credentials.
//
// Capabilities:
//   - Monitors token exchange events for anomalous patterns
//   - Detects scope escalation and unauthorized token usage
//   - Tracks connected account lifecycle (link, unlink, usage)
//   - Provides token exchange proxy for agent tool calls
//   - Enriches AI Containment with token-aware security context
//
// Auth0 Token Vault uses RFC 8693 (OAuth 2.0 Token Exchange) with:
//
//	Grant type:          urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token
//	Subject token types: urn:ietf:params:oauth:token-type:refresh_token
//	                     urn:ietf:params:oauth:token-type:access_token
//	Requested type:      http://auth0.com/oauth/token-type/federated-connection-access-token
type TokenVault struct {
	logger   zerolog.Logger
	pipeline *core.AlertPipeline
	ctx      context.Context

	// Auth0 configuration
	auth0Domain       string
	auth0ClientID     string
	auth0ClientSecret string

	// Monitoring state
	exchangeTracker *ExchangeTracker
	accountTracker  *ConnectedAccountTracker
}

// NewTokenVault creates and initializes a Token Vault sub-component.
// Called by AI Containment's Start() when Token Vault is enabled.
func NewTokenVault(ctx context.Context, pipeline *core.AlertPipeline, cfg *core.Config, logger zerolog.Logger) *TokenVault {
	tv := &TokenVault{
		logger:          logger.With().Str("subsystem", "token_vault").Logger(),
		pipeline:        pipeline,
		ctx:             ctx,
		exchangeTracker: NewExchangeTracker(),
		accountTracker:  NewConnectedAccountTracker(),
	}

	tv.loadAuth0Config(cfg)

	if tv.auth0Domain != "" {
		tv.logger.Info().
			Str("domain", tv.auth0Domain).
			Bool("client_configured", tv.auth0ClientID != "").
			Msg("Token Vault active — token exchange monitoring enabled")
	} else {
		tv.logger.Info().
			Msg("Token Vault active — monitoring mode (no Auth0 domain configured)")
	}

	return tv
}

// EventTypes returns the event types Token Vault handles.
// AI Containment appends these to its own EventTypes().
func EventTypes() []string {
	return []string{
		"token_exchange", "token_exchange_request", "token_exchange_response",
		"connected_account_link", "connected_account_unlink",
		"connected_account_usage",
		"oauth_grant", "oauth_consent", "oauth_token",
	}
}

// HandleEvent processes a security event relevant to Token Vault.
// Returns true if the event was handled, false if not a Token Vault event.
func (tv *TokenVault) HandleEvent(event *core.SecurityEvent) bool {
	switch event.Type {
	case "token_exchange", "token_exchange_request":
		tv.handleTokenExchange(event)
	case "token_exchange_response":
		tv.handleTokenExchangeResponse(event)
	case "connected_account_link":
		tv.handleAccountLink(event)
	case "connected_account_unlink":
		tv.handleAccountUnlink(event)
	case "connected_account_usage":
		tv.handleAccountUsage(event)
	case "agent_identity_delegation":
		tv.handleAgentDelegation(event)
	case "agent_action", "tool_call", "function_call":
		tv.handleAgentToolCall(event)
	case "oauth_grant", "oauth_consent", "oauth_token":
		tv.handleOAuthEvent(event)
	default:
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Auth0 configuration
// ---------------------------------------------------------------------------

const alertModule = "ai_containment"

func (tv *TokenVault) loadAuth0Config(cfg *core.Config) {
	// Read from the top-level token_vault config
	tv.auth0Domain = cfg.TokenVault.Auth0Domain
	tv.auth0ClientID = cfg.TokenVault.Auth0ClientID
	tv.auth0ClientSecret = cfg.TokenVault.Auth0ClientSecret

	// Environment variable overrides (consistent with 1SEC patterns)
	if env := os.Getenv("AUTH0_DOMAIN"); env != "" {
		tv.auth0Domain = env
	}
	if env := os.Getenv("AUTH0_CLIENT_ID"); env != "" {
		tv.auth0ClientID = env
	}
	if env := os.Getenv("AUTH0_CLIENT_SECRET"); env != "" {
		tv.auth0ClientSecret = env
	}
}

// IsConfigured returns true if Auth0 credentials are set for active token exchange.
func (tv *TokenVault) IsConfigured() bool {
	return tv.auth0Domain != "" && tv.auth0ClientID != ""
}

// ---------------------------------------------------------------------------
// Token Exchange — RFC 8693 via Auth0 Token Vault
// ---------------------------------------------------------------------------

// Auth0 Token Vault grant type and token type URNs (from official SDK).
const (
	GrantTypeFederatedConnectionAccessToken = "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"
	SubjectTokenTypeRefreshToken            = "urn:ietf:params:oauth:token-type:refresh_token"
	SubjectTokenTypeAccessToken             = "urn:ietf:params:oauth:token-type:access_token"
	RequestedTokenTypeFederatedConnection   = "http://auth0.com/oauth/token-type/federated-connection-access-token"
)

// TokenExchangeRequest represents an Auth0 Token Vault exchange request.
type TokenExchangeRequest struct {
	GrantType          string `json:"grant_type"`
	ClientID           string `json:"client_id"`
	ClientSecret       string `json:"client_secret,omitempty"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	RequestedTokenType string `json:"requested_token_type"`
	Connection         string `json:"connection"`
	LoginHint          string `json:"login_hint,omitempty"`
}

// TokenExchangeResponse represents the Auth0 token exchange response.
type TokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

// ExchangeToken performs a Token Vault token exchange with Auth0.
// This exchanges an Auth0 refresh token or access token for an external
// provider's access token (e.g., Google, GitHub, Slack).
func (tv *TokenVault) ExchangeToken(subjectToken, subjectTokenType, connection string, loginHint string) (*TokenExchangeResponse, error) {
	if !tv.IsConfigured() {
		return nil, fmt.Errorf("Auth0 Token Vault not configured: set auth0_domain and auth0_client_id")
	}

	reqBody := TokenExchangeRequest{
		GrantType:          GrantTypeFederatedConnectionAccessToken,
		ClientID:           tv.auth0ClientID,
		ClientSecret:       tv.auth0ClientSecret,
		SubjectToken:       subjectToken,
		SubjectTokenType:   subjectTokenType,
		RequestedTokenType: RequestedTokenTypeFederatedConnection,
		Connection:         connection,
		LoginHint:          loginHint,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling token exchange request: %w", err)
	}

	url := fmt.Sprintf("https://%s/oauth/token", tv.auth0Domain)
	req, err := http.NewRequestWithContext(tv.ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Track the exchange
	exchangeID := tv.exchangeTracker.RecordRequest(connection, subjectTokenType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tv.exchangeTracker.RecordFailure(exchangeID, err.Error())
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tv.exchangeTracker.RecordFailure(exchangeID, "failed to read response")
		return nil, fmt.Errorf("reading token exchange response: %w", err)
	}

	var tokenResp TokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		tv.exchangeTracker.RecordFailure(exchangeID, "invalid response JSON")
		return nil, fmt.Errorf("parsing token exchange response: %w", err)
	}

	if tokenResp.Error != "" {
		tv.exchangeTracker.RecordFailure(exchangeID, tokenResp.Error)

		alert := newAlert(core.SeverityMedium,
			fmt.Sprintf("Token Vault exchange failed: %s", tokenResp.Error),
			fmt.Sprintf("Auth0 Token Vault exchange for connection %q failed: %s", connection, tokenResp.ErrorDesc),
			map[string]interface{}{
				"connection":         connection,
				"error":              tokenResp.Error,
				"error_description":  tokenResp.ErrorDesc,
				"subject_token_type": subjectTokenType,
			})
		tv.pipeline.Process(alert)

		return &tokenResp, fmt.Errorf("token exchange error: %s — %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	tv.exchangeTracker.RecordSuccess(exchangeID, tokenResp.Scope)

	tv.logger.Debug().
		Str("connection", connection).
		Int("expires_in", tokenResp.ExpiresIn).
		Msg("token exchange successful")

	return &tokenResp, nil
}

// ---------------------------------------------------------------------------
// Event Handlers — Security Monitoring
// ---------------------------------------------------------------------------

func (tv *TokenVault) handleTokenExchange(event *core.SecurityEvent) {
	connection := getStringDetail(event, "connection")
	agentID := getStringDetail(event, "agent_id")
	subjectTokenType := getStringDetail(event, "subject_token_type")
	requestedScopes := getStringDetail(event, "scopes")

	tv.exchangeTracker.RecordRequest(connection, subjectTokenType)

	// Detect rapid token exchanges from a single agent (possible token abuse)
	if agentID != "" {
		count := tv.exchangeTracker.RecentExchangeCount(agentID, 5*time.Minute)
		threshold := 20
		if count > threshold {
			alert := newAlert(core.SeverityHigh,
				"Excessive token exchanges detected",
				fmt.Sprintf("Agent %q performed %d token exchanges in 5 minutes (threshold: %d) for connection %q", agentID, count, threshold, connection),
				map[string]interface{}{
					"agent_id":           agentID,
					"connection":         connection,
					"exchange_count":     count,
					"threshold":          threshold,
					"window":             "5m",
					"subject_token_type": subjectTokenType,
				})
			tv.pipeline.Process(alert)
		}
	}

	// Detect scope escalation — agent requesting broader scopes than previously granted
	if agentID != "" && requestedScopes != "" {
		if escalation := tv.exchangeTracker.DetectScopeEscalation(agentID, connection, requestedScopes); escalation != "" {
			alert := newAlert(core.SeverityHigh,
				"Token Vault scope escalation detected",
				fmt.Sprintf("Agent %q requested new scopes for %q: %s", agentID, connection, escalation),
				map[string]interface{}{
					"agent_id":         agentID,
					"connection":       connection,
					"new_scopes":       escalation,
					"requested_scopes": requestedScopes,
				})
			tv.pipeline.Process(alert)
		}
	}
}

func (tv *TokenVault) handleTokenExchangeResponse(event *core.SecurityEvent) {
	success := getStringDetail(event, "success")
	connection := getStringDetail(event, "connection")
	errorCode := getStringDetail(event, "error")

	if success == "false" || errorCode != "" {
		tv.logger.Warn().
			Str("connection", connection).
			Str("error", errorCode).
			Msg("token exchange failed")
	}
}

func (tv *TokenVault) handleAccountLink(event *core.SecurityEvent) {
	userID := getStringDetail(event, "user_id")
	connection := getStringDetail(event, "connection")
	scopes := getStringDetail(event, "scopes")

	tv.accountTracker.RecordLink(userID, connection, scopes)

	tv.logger.Info().
		Str("user_id", userID).
		Str("connection", connection).
		Msg("connected account linked")
}

func (tv *TokenVault) handleAccountUnlink(event *core.SecurityEvent) {
	userID := getStringDetail(event, "user_id")
	connection := getStringDetail(event, "connection")

	tv.accountTracker.RecordUnlink(userID, connection)

	tv.logger.Info().
		Str("user_id", userID).
		Str("connection", connection).
		Msg("connected account unlinked")
}

func (tv *TokenVault) handleAccountUsage(event *core.SecurityEvent) {
	userID := getStringDetail(event, "user_id")
	connection := getStringDetail(event, "connection")
	agentID := getStringDetail(event, "agent_id")
	action := getStringDetail(event, "action")

	tv.accountTracker.RecordUsage(userID, connection, agentID, action)

	// Detect usage of connected accounts by unauthorized agents
	if agentID != "" && !tv.accountTracker.IsAgentAuthorized(userID, connection, agentID) {
		alert := newAlert(core.SeverityCritical,
			"Unauthorized agent accessing connected account",
			fmt.Sprintf("Agent %q accessed connected account %q for user %q without prior authorization", agentID, connection, userID),
			map[string]interface{}{
				"agent_id":   agentID,
				"user_id":    userID,
				"connection": connection,
				"action":     action,
			})
		tv.pipeline.Process(alert)
	}
}

func (tv *TokenVault) handleAgentDelegation(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	delegatedBy := getStringDetail(event, "delegated_by")
	scopes := getStringDetail(event, "scopes")
	connection := getStringDetail(event, "connection")
	verified, _ := event.Details["attestation_verified"].(bool)
	expiry, err := time.Parse(time.RFC3339, getStringDetail(event, "expires_at"))
	if !verified || strings.TrimSpace(getStringDetail(event, "attestation")) == "" || err != nil || !time.Now().Before(expiry) {
		return
	}

	// Track which agents are authorized to use which connections
	if tv.accountTracker.AuthorizeAgent(delegatedBy, connection, agentID, scopes, expiry) {

		tv.logger.Info().
			Str("agent_id", agentID).
			Str("delegated_by", delegatedBy).
			Str("connection", connection).
			Msg("agent authorized for Token Vault connection")
	}
}

func (tv *TokenVault) handleAgentToolCall(event *core.SecurityEvent) {
	agentID := getStringDetail(event, "agent_id")
	tool := getStringDetail(event, "tool")
	connection := getStringDetail(event, "connection")

	// Only process tool calls that reference a Token Vault connection
	if connection == "" {
		return
	}

	// Check if the agent is using a token for a connection it wasn't delegated
	userID := getStringDetail(event, "user_id")
	if agentID == "" || userID == "" || !tv.accountTracker.IsAgentAuthorized(userID, connection, agentID) {
		alert := newAlert(core.SeverityHigh,
			"Agent using undelegated Token Vault connection",
			fmt.Sprintf("Agent %q invoked tool %q using connection %q without delegation from user %q", agentID, tool, connection, userID),
			map[string]interface{}{
				"agent_id":   agentID,
				"tool":       tool,
				"connection": connection,
				"user_id":    userID,
			})
		tv.pipeline.Process(alert)
	}
}

func (tv *TokenVault) handleOAuthEvent(event *core.SecurityEvent) {
	appID := getStringDetail(event, "app_id")
	scopes := getStringDetail(event, "scopes")
	username := getStringDetail(event, "username")

	// Detect overly broad OAuth grants that may indicate consent phishing
	if scopes != "" {
		scopeList := strings.Split(scopes, " ")
		if len(scopeList) > 10 {
			alert := newAlert(core.SeverityMedium,
				"Broad OAuth scope grant detected",
				fmt.Sprintf("OAuth grant for app %q by user %q includes %d scopes — review for consent phishing", appID, username, len(scopeList)),
				map[string]interface{}{
					"app_id":      appID,
					"username":    username,
					"scope_count": len(scopeList),
					"scopes":      scopes,
				})
			tv.pipeline.Process(alert)
		}
	}
}

// ---------------------------------------------------------------------------
// Status — exposed to API handlers
// ---------------------------------------------------------------------------

// Status returns the current Token Vault status.
type Status struct {
	Configured        bool          `json:"configured"`
	Auth0Domain       string        `json:"auth0_domain,omitempty"`
	ExchangeStats     ExchangeStats `json:"exchange_stats"`
	ConnectedAccounts int           `json:"connected_accounts"`
	AuthorizedAgents  int           `json:"authorized_agents"`
}

// GetStatus returns the current status for the API.
func (tv *TokenVault) GetStatus() Status {
	domain := ""
	if tv.auth0Domain != "" {
		// Mask domain partially for security
		parts := strings.SplitN(tv.auth0Domain, ".", 2)
		if len(parts) == 2 {
			domain = parts[0][:min(4, len(parts[0]))] + "***." + parts[1]
		}
	}

	return Status{
		Configured:        tv.IsConfigured(),
		Auth0Domain:       domain,
		ExchangeStats:     tv.exchangeTracker.Stats(),
		ConnectedAccounts: tv.accountTracker.AccountCount(),
		AuthorizedAgents:  tv.accountTracker.AgentCount(),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newAlert creates a properly initialized alert with ID, timestamp, and status.
func newAlert(severity core.Severity, title, description string, metadata map[string]interface{}) *core.Alert {
	return &core.Alert{
		ID:          uuid.New().String(),
		Timestamp:   time.Now().UTC(),
		Module:      alertModule,
		Severity:    severity,
		Status:      core.AlertStatusOpen,
		Title:       title,
		Description: description,
		Metadata:    metadata,
	}
}

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	val, ok := event.Details[key]
	if !ok {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// ExchangeTracker — monitors token exchange patterns
// ---------------------------------------------------------------------------

// ExchangeStats holds aggregate token exchange statistics.
type ExchangeStats struct {
	TotalExchanges int64            `json:"total_exchanges"`
	SuccessCount   int64            `json:"success_count"`
	FailureCount   int64            `json:"failure_count"`
	ByConnection   map[string]int64 `json:"by_connection"`
	RecentFailures int              `json:"recent_failures"`
}

type exchangeRecord struct {
	ID               string
	Connection       string
	SubjectTokenType string
	Timestamp        time.Time
	Success          bool
	Error            string
	Scopes           string
	AgentID          string
}

// ExchangeTracker monitors token exchange patterns for anomaly detection.
type ExchangeTracker struct {
	mu      sync.Mutex
	records []exchangeRecord
	byAgent map[string][]time.Time                // agent_id → exchange timestamps
	scopes  map[string]map[string]map[string]bool // agent_id → connection → scopes seen
	stats   ExchangeStats
}

// NewExchangeTracker creates a new ExchangeTracker.
func NewExchangeTracker() *ExchangeTracker {
	return &ExchangeTracker{
		records: make([]exchangeRecord, 0, 1000),
		byAgent: make(map[string][]time.Time),
		scopes:  make(map[string]map[string]map[string]bool),
		stats: ExchangeStats{
			ByConnection: make(map[string]int64),
		},
	}
}

func (et *ExchangeTracker) RecordRequest(connection, subjectTokenType string) string {
	et.mu.Lock()
	defer et.mu.Unlock()

	id := fmt.Sprintf("exc_%d", time.Now().UnixNano())
	et.records = append(et.records, exchangeRecord{
		ID:               id,
		Connection:       connection,
		SubjectTokenType: subjectTokenType,
		Timestamp:        time.Now(),
	})
	et.stats.TotalExchanges++
	et.stats.ByConnection[connection]++

	// Cap records at 10000
	if len(et.records) > 10000 {
		et.records = et.records[len(et.records)-5000:]
	}

	return id
}

func (et *ExchangeTracker) RecordSuccess(id, scopes string) {
	et.mu.Lock()
	defer et.mu.Unlock()
	et.stats.SuccessCount++
}

func (et *ExchangeTracker) RecordFailure(id, errMsg string) {
	et.mu.Lock()
	defer et.mu.Unlock()
	et.stats.FailureCount++
}

func (et *ExchangeTracker) RecentExchangeCount(agentID string, window time.Duration) int {
	et.mu.Lock()
	defer et.mu.Unlock()

	cutoff := time.Now().Add(-window)
	timestamps := et.byAgent[agentID]
	count := 0
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			count++
		}
	}
	return count
}

// DetectScopeEscalation checks if an agent is requesting scopes it hasn't used before.
// Returns a comma-separated list of new scopes, or "" if no escalation.
func (et *ExchangeTracker) DetectScopeEscalation(agentID, connection, requestedScopes string) string {
	et.mu.Lock()
	defer et.mu.Unlock()

	if _, ok := et.scopes[agentID]; !ok {
		et.scopes[agentID] = make(map[string]map[string]bool)
	}
	if _, ok := et.scopes[agentID][connection]; !ok {
		// First request — establish baseline, no escalation
		et.scopes[agentID][connection] = make(map[string]bool)
		for _, s := range strings.Fields(requestedScopes) {
			et.scopes[agentID][connection][s] = true
		}
		return ""
	}

	var newScopes []string
	for _, s := range strings.Fields(requestedScopes) {
		if !et.scopes[agentID][connection][s] {
			newScopes = append(newScopes, s)
			et.scopes[agentID][connection][s] = true
		}
	}

	if len(newScopes) > 0 {
		return strings.Join(newScopes, ", ")
	}
	return ""
}

// Stats returns aggregate exchange statistics.
func (et *ExchangeTracker) Stats() ExchangeStats {
	et.mu.Lock()
	defer et.mu.Unlock()

	// Count recent failures (last 15 minutes)
	cutoff := time.Now().Add(-15 * time.Minute)
	recent := 0
	for i := len(et.records) - 1; i >= 0; i-- {
		if et.records[i].Timestamp.Before(cutoff) {
			break
		}
		if et.records[i].Error != "" {
			recent++
		}
	}

	byConn := make(map[string]int64, len(et.stats.ByConnection))
	for k, v := range et.stats.ByConnection {
		byConn[k] = v
	}

	return ExchangeStats{
		TotalExchanges: et.stats.TotalExchanges,
		SuccessCount:   et.stats.SuccessCount,
		FailureCount:   et.stats.FailureCount,
		ByConnection:   byConn,
		RecentFailures: recent,
	}
}

// ---------------------------------------------------------------------------
// ConnectedAccountTracker — tracks linked accounts and agent authorization
// ---------------------------------------------------------------------------

type connectedAccount struct {
	UserID     string
	Connection string
	Scopes     string
	LinkedAt   time.Time
}

type agentAuth struct {
	AgentID    string
	Connection string
	Scopes     string
	GrantedAt  time.Time
	GrantedBy  string // user_id who delegated
	ExpiresAt  time.Time
}

// ConnectedAccountTracker monitors connected account state and agent authorization.
type ConnectedAccountTracker struct {
	mu       sync.Mutex
	accounts map[string][]connectedAccount // user_id → connected accounts
	agents   map[string][]agentAuth        // user_id → authorized agents
	usage    map[string]int64              // connection → usage count
}

// NewConnectedAccountTracker creates a new ConnectedAccountTracker.
func NewConnectedAccountTracker() *ConnectedAccountTracker {
	return &ConnectedAccountTracker{
		accounts: make(map[string][]connectedAccount),
		agents:   make(map[string][]agentAuth),
		usage:    make(map[string]int64),
	}
}

func (cat *ConnectedAccountTracker) RecordLink(userID, connection, scopes string) {
	cat.mu.Lock()
	defer cat.mu.Unlock()

	cat.accounts[userID] = append(cat.accounts[userID], connectedAccount{
		UserID:     userID,
		Connection: connection,
		Scopes:     scopes,
		LinkedAt:   time.Now(),
	})
}

func (cat *ConnectedAccountTracker) RecordUnlink(userID, connection string) {
	cat.mu.Lock()
	defer cat.mu.Unlock()

	accts := cat.accounts[userID]
	filtered := accts[:0]
	for _, a := range accts {
		if a.Connection != connection {
			filtered = append(filtered, a)
		}
	}
	cat.accounts[userID] = filtered

	// Also revoke any agent authorizations for this connection
	auths := cat.agents[userID]
	filteredAuths := auths[:0]
	for _, a := range auths {
		if a.Connection != connection {
			filteredAuths = append(filteredAuths, a)
		}
	}
	cat.agents[userID] = filteredAuths
}

func (cat *ConnectedAccountTracker) RecordUsage(userID, connection, agentID, action string) {
	cat.mu.Lock()
	defer cat.mu.Unlock()
	cat.usage[connection]++
}

func (cat *ConnectedAccountTracker) AuthorizeAgent(userID, connection, agentID, scopes string, expiresAt time.Time) bool {
	cat.mu.Lock()
	defer cat.mu.Unlock()
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(connection) == "" || strings.TrimSpace(agentID) == "" || agentID == "unknown" || !time.Now().Before(expiresAt) {
		return false
	}

	auth := agentAuth{
		AgentID:    agentID,
		Connection: connection,
		Scopes:     scopes,
		GrantedAt:  time.Now(),
		GrantedBy:  userID,
		ExpiresAt:  expiresAt,
	}
	for i, previous := range cat.agents[userID] {
		if previous.AgentID == agentID && previous.Connection == connection {
			cat.agents[userID][i] = auth
			return true
		}
	}
	cat.agents[userID] = append(cat.agents[userID], auth)
	return true
}

func (cat *ConnectedAccountTracker) IsAgentAuthorized(userID, connection, agentID string) bool {
	cat.mu.Lock()
	defer cat.mu.Unlock()

	for _, auth := range cat.agents[userID] {
		if auth.AgentID == agentID && auth.Connection == connection && time.Now().Before(auth.ExpiresAt) {
			return true
		}
	}
	return false
}

func (cat *ConnectedAccountTracker) AccountCount() int {
	cat.mu.Lock()
	defer cat.mu.Unlock()

	total := 0
	for _, accts := range cat.accounts {
		total += len(accts)
	}
	return total
}

func (cat *ConnectedAccountTracker) AgentCount() int {
	cat.mu.Lock()
	defer cat.mu.Unlock()

	total := 0
	for _, auths := range cat.agents {
		for _, auth := range auths {
			if time.Now().Before(auth.ExpiresAt) {
				total++
			}
		}
	}
	return total
}
