package aicontainment

import (
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/1sec-project/1sec/internal/modules/tokenvault"
	"github.com/rs/zerolog"
)

func TestDelegationTracker_RejectsUnverifiedRecords(t *testing.T) {
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	for _, tt := range []struct {
		name, principal, expiry, attestation, scopes, chain string
		verified                                            bool
	}{
		{name: "missing attestation", principal: "owner", expiry: future, verified: true},
		{name: "forged attestation", principal: "owner", expiry: future, attestation: "fake-signature"},
		{name: "missing principal", expiry: future, attestation: "signature", verified: true},
		{name: "missing expiry", principal: "owner", attestation: "signature", verified: true},
		{name: "malformed expiry", principal: "owner", expiry: "never", attestation: "signature", verified: true},
		{name: "expired", principal: "owner", expiry: time.Now().Add(-time.Hour).Format(time.RFC3339), attestation: "signature", verified: true},
		{name: "broad scopes", principal: "owner", expiry: future, attestation: "signature", verified: true, scopes: "admin:*"},
		{name: "deep chain", principal: "owner", expiry: future, attestation: "signature", verified: true, chain: "owner->a->b->c"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dt := NewDelegationChainTracker()
			dt.ValidateDelegation("agent", tt.principal, tt.scopes, tt.expiry, tt.chain, tt.attestation, tt.verified)
			if valid, _ := dt.HasValidDelegation("agent"); valid {
				t.Fatal("unverified or invalid record authorized an agent")
			}
		})
	}
}

func TestContainment_ForgedDelegationDoesNotSuppressSensitiveActionAlert(t *testing.T) {
	cp := makeCapturingPipeline()
	c := startedModuleWithPipeline(t, cp)
	defer c.Stop()
	delegation := core.NewSecurityEvent("test", "agent_identity_delegation", core.SeverityInfo, "delegation")
	delegation.Details["agent_id"] = "agent"
	delegation.Details["delegated_by"] = "owner"
	delegation.Details["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	delegation.Details["attestation"] = "attacker-supplied-text"
	c.HandleEvent(delegation)
	action := core.NewSecurityEvent("test", "agent_action", core.SeverityInfo, "delete")
	action.Details["agent_id"] = "agent"
	action.Details["action"] = "delete_database"
	c.HandleEvent(action)
	if !cp.hasAlertType("delegation_verification_failed") {
		t.Fatal("forged delegation suppressed the high-value action alert")
	}
}

func TestContainment_InvalidDelegationDoesNotAuthorizeTokenVault(t *testing.T) {
	for _, tt := range []struct {
		name, scopes string
		verified     bool
		authorized   bool
	}{
		{"verified read", "read", true, true},
		{"forged", "read", false, false},
		{"flagged broad scope", "admin:*", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cp := makeCapturingPipeline()
			c := startedModuleWithPipeline(t, cp)
			defer c.Stop()
			c.tokenVault = tokenvault.NewTokenVault(c.ctx, cp.pipeline, core.DefaultConfig(), zerolog.Nop())
			delegation := core.NewSecurityEvent("test", "agent_identity_delegation", core.SeverityInfo, "delegation")
			delegation.Details["agent_id"] = "agent"
			delegation.Details["delegated_by"] = "owner"
			delegation.Details["connection"] = "github"
			delegation.Details["scopes"] = tt.scopes
			delegation.Details["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
			delegation.Details["attestation"] = "attestation"
			delegation.Details["attestation_verified"] = tt.verified
			c.HandleEvent(delegation)
			before := cp.count()
			usage := core.NewSecurityEvent("test", "connected_account_usage", core.SeverityInfo, "usage")
			usage.Details["agent_id"] = "agent"
			usage.Details["user_id"] = "owner"
			usage.Details["connection"] = "github"
			c.HandleEvent(usage)
			if alerted := cp.count() > before; alerted == tt.authorized {
				t.Fatalf("undelegated account alert = %v, authorized = %v", alerted, tt.authorized)
			}
		})
	}
}
