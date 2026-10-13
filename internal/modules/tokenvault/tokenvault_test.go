package tokenvault

import (
	"testing"
	"time"
)

func TestEventTypes(t *testing.T) {
	types := EventTypes()
	if len(types) == 0 {
		t.Fatal("expected non-empty event types")
	}

	required := []string{
		"token_exchange", "connected_account_link", "connected_account_unlink",
		"oauth_grant",
	}
	typeSet := make(map[string]bool, len(types))
	for _, et := range types {
		typeSet[et] = true
	}
	for _, r := range required {
		if !typeSet[r] {
			t.Errorf("missing required event type: %s", r)
		}
	}
}

func TestExchangeTracker(t *testing.T) {
	et := NewExchangeTracker()

	id1 := et.RecordRequest("google-oauth2", SubjectTokenTypeRefreshToken)
	et.RecordSuccess(id1, "openid profile email")

	id2 := et.RecordRequest("github", SubjectTokenTypeAccessToken)
	et.RecordFailure(id2, "invalid_grant")

	stats := et.Stats()
	if stats.TotalExchanges != 2 {
		t.Errorf("expected 2 total exchanges, got %d", stats.TotalExchanges)
	}
	if stats.SuccessCount != 1 {
		t.Errorf("expected 1 success, got %d", stats.SuccessCount)
	}
	if stats.FailureCount != 1 {
		t.Errorf("expected 1 failure, got %d", stats.FailureCount)
	}
	if stats.ByConnection["google-oauth2"] != 1 {
		t.Errorf("expected 1 google-oauth2 exchange, got %d", stats.ByConnection["google-oauth2"])
	}
}

func TestScopeEscalation(t *testing.T) {
	et := NewExchangeTracker()

	// First request — baseline
	esc := et.DetectScopeEscalation("agent-1", "google-oauth2", "openid profile")
	if esc != "" {
		t.Errorf("expected no escalation for first request, got %q", esc)
	}

	// Same scopes — no escalation
	esc = et.DetectScopeEscalation("agent-1", "google-oauth2", "openid profile")
	if esc != "" {
		t.Errorf("expected no escalation for same scopes, got %q", esc)
	}

	// New scope — escalation
	esc = et.DetectScopeEscalation("agent-1", "google-oauth2", "openid profile email calendar")
	if esc == "" {
		t.Error("expected escalation for new scopes")
	}
	if esc != "email, calendar" {
		t.Errorf("expected escalation %q, got %q", "email, calendar", esc)
	}
}

func TestConnectedAccountTracker(t *testing.T) {
	cat := NewConnectedAccountTracker()

	cat.RecordLink("user-1", "google-oauth2", "openid profile email")
	cat.RecordLink("user-1", "github", "repo read:user")

	if cat.AccountCount() != 2 {
		t.Errorf("expected 2 accounts, got %d", cat.AccountCount())
	}

	// Agent not authorized yet
	if cat.IsAgentAuthorized("user-1", "google-oauth2", "agent-1") {
		t.Error("agent should not be authorized before delegation")
	}

	// Authorize agent
	cat.AuthorizeAgent("user-1", "google-oauth2", "agent-1", "openid profile", time.Now().Add(time.Hour))
	if !cat.IsAgentAuthorized("user-1", "google-oauth2", "agent-1") {
		t.Error("agent should be authorized after delegation")
	}

	// Different connection — not authorized
	if cat.IsAgentAuthorized("user-1", "github", "agent-1") {
		t.Error("agent should not be authorized for unlinked connection")
	}

	if cat.AgentCount() != 1 {
		t.Errorf("expected 1 authorized agent, got %d", cat.AgentCount())
	}

	// Unlink revokes agent authorization
	cat.RecordUnlink("user-1", "google-oauth2")
	if cat.IsAgentAuthorized("user-1", "google-oauth2", "agent-1") {
		t.Error("agent authorization should be revoked after unlink")
	}
	if cat.AccountCount() != 1 {
		t.Errorf("expected 1 account after unlink, got %d", cat.AccountCount())
	}
}

func TestRecentExchangeCount(t *testing.T) {
	et := NewExchangeTracker()

	et.mu.Lock()
	now := time.Now()
	et.byAgent["agent-1"] = []time.Time{
		now.Add(-1 * time.Minute),
		now.Add(-2 * time.Minute),
		now.Add(-10 * time.Minute), // outside 5-min window
	}
	et.mu.Unlock()

	count := et.RecentExchangeCount("agent-1", 5*time.Minute)
	if count != 2 {
		t.Errorf("expected 2 recent exchanges, got %d", count)
	}
}

func TestTokenExchangeConstants(t *testing.T) {
	// Verify constants match Auth0 official SDK values
	if GrantTypeFederatedConnectionAccessToken != "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token" {
		t.Error("grant type does not match Auth0 SDK")
	}
	if SubjectTokenTypeRefreshToken != "urn:ietf:params:oauth:token-type:refresh_token" {
		t.Error("refresh token type does not match RFC 8693")
	}
	if SubjectTokenTypeAccessToken != "urn:ietf:params:oauth:token-type:access_token" {
		t.Error("access token type does not match RFC 8693")
	}
	if RequestedTokenTypeFederatedConnection != "http://auth0.com/oauth/token-type/federated-connection-access-token" {
		t.Error("requested token type does not match Auth0 SDK")
	}
}
