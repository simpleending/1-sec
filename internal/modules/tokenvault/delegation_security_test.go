package tokenvault

import (
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

func TestTokenVault_DelegationRequiresVerifiedIdentityAndExpiry(t *testing.T) {
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	for _, tt := range []struct {
		name, expiry string
		verified     interface{}
		authorized   bool
	}{
		{"verified", future, true, true},
		{"unverified", future, false, false},
		{"string verification is untrusted", future, "true", false},
		{"missing expiry", "", true, false},
		{"invalid expiry", "never", true, false},
		{"expired", time.Now().Add(-time.Hour).Format(time.RFC3339), true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tv := &TokenVault{logger: zerolog.Nop(), accountTracker: NewConnectedAccountTracker()}
			event := core.NewSecurityEvent("test", "agent_identity_delegation", core.SeverityInfo, "delegation")
			event.Details["agent_id"] = "agent"
			event.Details["delegated_by"] = "owner"
			event.Details["connection"] = "github"
			event.Details["attestation"] = "attestation"
			event.Details["attestation_verified"] = tt.verified
			event.Details["expires_at"] = tt.expiry
			tv.HandleEvent(event)
			if authorized := tv.accountTracker.IsAgentAuthorized("owner", "github", "agent"); authorized != tt.authorized {
				t.Fatalf("authorization = %v, want %v", authorized, tt.authorized)
			}
		})
	}
}

func TestConnectedAccountTracker_ExpiryAndRenewal(t *testing.T) {
	cat := NewConnectedAccountTracker()
	if !cat.AuthorizeAgent("owner", "github", "agent", "read", time.Now().Add(time.Hour)) {
		t.Fatal("valid authorization rejected")
	}
	cat.AuthorizeAgent("owner", "github", "agent", "read", time.Now().Add(time.Minute))
	if len(cat.agents["owner"]) != 1 {
		t.Fatal("renewal left an older authorization active")
	}
	cat.agents["owner"][0].ExpiresAt = time.Now().Add(-time.Second)
	if cat.IsAgentAuthorized("owner", "github", "agent") || cat.AgentCount() != 0 {
		t.Fatal("expired delegation remained authorized")
	}
	if cat.AuthorizeAgent("", "github", "agent", "read", time.Now().Add(time.Hour)) {
		t.Fatal("missing principal granted authorization")
	}
}

func TestTokenVault_ToolUseRequiresBothIdentities(t *testing.T) {
	for _, field := range []string{"user_id", "agent_id"} {
		t.Run(field, func(t *testing.T) {
			pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
			alerts := 0
			pipeline.AddHandler(func(*core.Alert) { alerts++ })
			tv := &TokenVault{logger: zerolog.Nop(), pipeline: pipeline, accountTracker: NewConnectedAccountTracker()}
			tv.accountTracker.AuthorizeAgent("owner", "github", "agent", "read", time.Now().Add(time.Hour))
			event := core.NewSecurityEvent("test", "tool_call", core.SeverityInfo, "tool")
			event.Details["connection"] = "github"
			event.Details["user_id"] = "owner"
			event.Details["agent_id"] = "agent"
			delete(event.Details, field)
			tv.HandleEvent(event)
			if alerts == 0 {
				t.Fatal("missing identity suppressed the undelegated tool-use alert")
			}
		})
	}
}
