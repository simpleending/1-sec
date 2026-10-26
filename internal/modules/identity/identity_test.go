package identity

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

type capPipeline struct {
	pipeline *core.AlertPipeline
	mu       sync.Mutex
	alerts   []*core.Alert
}

func newCapPipeline() *capPipeline {
	cp := &capPipeline{}
	cp.pipeline = core.NewAlertPipeline(zerolog.Nop(), 10000)
	cp.pipeline.AddHandler(func(a *core.Alert) {
		cp.mu.Lock()
		cp.alerts = append(cp.alerts, a)
		cp.mu.Unlock()
	})
	return cp
}

func (cp *capPipeline) count() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.alerts)
}

func (cp *capPipeline) hasAlertType(alertType string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, a := range cp.alerts {
		if a.Type == alertType {
			return true
		}
	}
	return false
}

func startedMonitor(t *testing.T, pipeline *core.AlertPipeline) *Monitor {
	t.Helper()
	m := New()
	cfg := core.DefaultConfig()
	if err := m.Start(context.Background(), nil, pipeline, cfg); err != nil {
		t.Fatalf("Monitor.Start() error: %v", err)
	}
	t.Cleanup(func() { m.Stop() })
	return m
}

// ─── Module Interface ─────────────────────────────────────────────────────────

var _ core.Module = (*Monitor)(nil)

func TestMonitor_Name(t *testing.T) {
	m := New()
	if m.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", m.Name(), ModuleName)
	}
}

func TestMonitor_Description(t *testing.T) {
	m := New()
	if m.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestMonitor_Start_Stop(t *testing.T) {
	m := New()
	cfg := core.DefaultConfig()
	if err := m.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if m.identityDB == nil {
		t.Error("identityDB should be initialized after Start()")
	}
	if m.privMonitor == nil {
		t.Error("privMonitor should be initialized after Start()")
	}
	if m.svcAcctMon == nil {
		t.Error("svcAcctMon should be initialized after Start()")
	}
	if err := m.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
}

// ─── IdentityDatabase ─────────────────────────────────────────────────────────

func TestIdentityDatabase_AnalyzeNewIdentity_Normal(t *testing.T) {
	db := NewIdentityDatabase()
	score := db.AnalyzeNewIdentity("user1", "alice@company.com", "Alice Smith", "web", "10.0.0.1")
	if score.IsSynthetic {
		t.Errorf("normal identity should not be synthetic, score=%.2f", score.Score)
	}
	if score.BulkCreation {
		t.Error("single creation should not trigger BulkCreation")
	}
}

func TestIdentityDatabase_AnalyzeNewIdentity_BulkCreation(t *testing.T) {
	db := NewIdentityDatabase()
	ip := "10.0.0.99"
	// Create >10 accounts from the same IP
	for i := 0; i < 11; i++ {
		db.AnalyzeNewIdentity(
			fmt.Sprintf("user%d", i),
			fmt.Sprintf("user%d@example.com", i),
			fmt.Sprintf("User %d", i),
			"api", ip,
		)
	}
	score := db.AnalyzeNewIdentity("user_final", "final@example.com", "Final User", "api", ip)
	if !score.BulkCreation {
		t.Error("expected BulkCreation=true after >10 accounts from same IP")
	}
	if score.RecentCount <= 10 {
		t.Errorf("RecentCount = %d, want > 10", score.RecentCount)
	}
}

func TestIdentityDatabase_AnalyzeNewIdentity_HighEntropyEmail(t *testing.T) {
	db := NewIdentityDatabase()
	// Email with >40% digits and >15 chars in local part
	score := db.AnalyzeNewIdentity("user1", "abc123456789012345@example.com", "Test User", "web", "10.0.0.1")
	hasEntropy := false
	for _, ind := range score.Indicators {
		if ind == "high-entropy email local part" {
			hasEntropy = true
		}
	}
	if !hasEntropy {
		t.Error("expected 'high-entropy email local part' indicator for digit-heavy email")
	}
}

func TestIdentityDatabase_AnalyzeNewIdentity_DisposableDomain(t *testing.T) {
	db := NewIdentityDatabase()
	disposableDomains := []string{
		"tempmail.com", "throwaway.email", "guerrillamail.com",
		"mailinator.com", "yopmail.com", "10minutemail.com",
		"trashmail.com", "fakeinbox.com", "sharklasers.com",
		"guerrillamailblock.com", "grr.la", "dispostable.com",
		"temp-mail.org", "tempail.com", "mohmal.com",
	}
	for _, domain := range disposableDomains {
		score := db.AnalyzeNewIdentity("u", "test@"+domain, "Test", "web", fmt.Sprintf("10.0.%d.1", len(domain)))
		hasDisposable := false
		for _, ind := range score.Indicators {
			if ind == "disposable email domain" {
				hasDisposable = true
			}
		}
		if !hasDisposable {
			t.Errorf("expected 'disposable email domain' indicator for %s", domain)
		}
	}
}

func TestIdentityDatabase_AnalyzeNewIdentity_GeneratedName(t *testing.T) {
	db := NewIdentityDatabase()
	score := db.AnalyzeNewIdentity("user1", "test@example.com", "User12345 Bot6789", "web", "10.0.0.1")
	hasGenerated := false
	for _, ind := range score.Indicators {
		if ind == "generated-looking name" {
			hasGenerated = true
		}
	}
	if !hasGenerated {
		t.Error("expected 'generated-looking name' indicator for name with many digits")
	}
}

func TestIdentityDatabase_SyntheticScore(t *testing.T) {
	db := NewIdentityDatabase()
	ip := "10.0.0.50"
	// Create >10 accounts to trigger bulk creation (0.3)
	for i := 0; i < 11; i++ {
		db.AnalyzeNewIdentity(fmt.Sprintf("u%d", i), fmt.Sprintf("u%d@example.com", i), "Name", "api", ip)
	}
	// Now create one with disposable domain (0.2) + bulk (0.3) = 0.5 → IsSynthetic
	score := db.AnalyzeNewIdentity("synth", "test@mailinator.com", "Normal Name", "api", ip)
	if !score.IsSynthetic {
		t.Errorf("expected IsSynthetic=true for combined indicators, score=%.2f", score.Score)
	}
	if score.Score < 0.5 {
		t.Errorf("Score = %f, want >= 0.5", score.Score)
	}
}

// ─── hasHighEntropy ───────────────────────────────────────────────────────────

func TestHasHighEntropy(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"abc12345678", true}, // >40% digits, len > 8
		{"abcdefghij", false}, // no digits
		{"a1b2c3d4e5", true},  // 50% digits
		{"short1", false},     // too short (< 8)
		{"abcdefgh", false},   // no digits
		{"12345678901", true}, // all digits
	}
	for _, tc := range cases {
		got := hasHighEntropy(tc.s)
		if got != tc.want {
			t.Errorf("hasHighEntropy(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

// ─── isDisposableDomain ───────────────────────────────────────────────────────

func TestIsDisposableDomain(t *testing.T) {
	// Known disposable
	if !isDisposableDomain("test@mailinator.com") {
		t.Error("expected true for mailinator.com")
	}
	if !isDisposableDomain("test@yopmail.com") {
		t.Error("expected true for yopmail.com")
	}
	// Normal domain
	if isDisposableDomain("test@gmail.com") {
		t.Error("expected false for gmail.com")
	}
	if isDisposableDomain("test@company.com") {
		t.Error("expected false for company.com")
	}
	// Invalid email
	if isDisposableDomain("noemail") {
		t.Error("expected false for invalid email")
	}
}

// ─── looksGenerated ───────────────────────────────────────────────────────────

func TestLooksGenerated(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"User12345 Bot6789", true}, // digits > 2 in a part
		{"Alice Smith", false},      // normal name
		{"John Doe", false},         // normal name
		{"Bot", false},              // single part
		{"Test1234 Account", true},  // digits > 2
		{"A B", false},              // short parts, no digits
	}
	for _, tc := range cases {
		got := looksGenerated(tc.name)
		if got != tc.want {
			t.Errorf("looksGenerated(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ─── PrivilegeMonitor ─────────────────────────────────────────────────────────

func TestPrivilegeMonitor_Escalation(t *testing.T) {
	pm := NewPrivilegeMonitor()
	result := pm.Analyze("user1", "viewer", "admin", "", "admin_user")
	if !result.IsEscalation {
		t.Error("expected IsEscalation=true for viewer→admin")
	}
	// Non-admin to admin variants
	for _, newRole := range []string{"admin", "administrator", "root", "superadmin", "owner", "org_admin"} {
		r := pm.Analyze("user1", "user", newRole, "", "admin_user")
		if !r.IsEscalation {
			t.Errorf("expected IsEscalation=true for user→%s", newRole)
		}
	}
}

func TestPrivilegeMonitor_SelfGrant(t *testing.T) {
	pm := NewPrivilegeMonitor()
	result := pm.Analyze("user1", "user", "admin", "", "user1")
	if !result.SelfGrant {
		t.Error("expected SelfGrant=true when userID == grantedBy")
	}
}

func TestPrivilegeMonitor_SensitivePermission(t *testing.T) {
	pm := NewPrivilegeMonitor()
	sensitivePerms := []string{
		"admin", "root", "superuser",
		"iam:*", "s3:*", "ec2:*",
		"delete:*", "write:*", "manage:*",
		"org:admin", "billing:admin",
	}
	for _, perm := range sensitivePerms {
		result := pm.Analyze("user1", "user", "user", perm, "admin")
		if !result.SensitivePermission {
			t.Errorf("expected SensitivePermission=true for %q", perm)
		}
	}
}

func TestPrivilegeMonitor_NormalChange(t *testing.T) {
	pm := NewPrivilegeMonitor()
	result := pm.Analyze("user1", "viewer", "editor", "", "admin_user")
	if result.IsEscalation {
		t.Error("viewer→editor should not be flagged as escalation")
	}
	if result.SelfGrant {
		t.Error("different user granting should not be SelfGrant")
	}
}

// ─── ServiceAccountMonitor ────────────────────────────────────────────────────

func TestServiceAccountMonitor_FirstAction(t *testing.T) {
	sm := NewServiceAccountMonitor()
	anomaly := sm.RecordAndAnalyze("svc-1", "read", "/api/data", "10.0.0.1")
	if anomaly.UnusualAction {
		t.Error("first action should not trigger UnusualAction")
	}
	if anomaly.UnusualIP {
		t.Error("first action should not trigger UnusualIP")
	}
	if anomaly.HighVolume {
		t.Error("first action should not trigger HighVolume")
	}
}

func TestServiceAccountMonitor_UnusualAction(t *testing.T) {
	sm := NewServiceAccountMonitor()
	sm.RecordAndAnalyze("svc-2", "read", "/api/data", "10.0.0.1")

	// Simulate baseline period by manipulating internal state
	sm.mu.Lock()
	profile := sm.accounts["svc-2"]
	profile.BaselineStart = time.Now().Add(-48 * time.Hour)
	profile.LastSeen = time.Now()
	sm.mu.Unlock()

	anomaly := sm.RecordAndAnalyze("svc-2", "delete_all", "/api/data", "10.0.0.1")
	if !anomaly.UnusualAction {
		t.Error("expected UnusualAction=true for new action after baseline period")
	}
}

func TestServiceAccountMonitor_UnusualIP(t *testing.T) {
	sm := NewServiceAccountMonitor()
	sm.RecordAndAnalyze("svc-3", "read", "/api/data", "10.0.0.1")

	// Simulate baseline period
	sm.mu.Lock()
	profile := sm.accounts["svc-3"]
	profile.BaselineStart = time.Now().Add(-48 * time.Hour)
	profile.LastSeen = time.Now()
	sm.mu.Unlock()

	anomaly := sm.RecordAndAnalyze("svc-3", "read", "/api/data", "192.168.1.100")
	if !anomaly.UnusualIP {
		t.Error("expected UnusualIP=true for new IP after baseline period")
	}
	if len(anomaly.KnownIPs) == 0 {
		t.Error("expected KnownIPs to contain the original IP")
	}
}

func TestServiceAccountMonitor_HighVolume(t *testing.T) {
	sm := NewServiceAccountMonitor()
	sm.RecordAndAnalyze("svc-4", "read", "/api/data", "10.0.0.1")

	// Directly set action count to simulate high volume
	sm.mu.Lock()
	profile := sm.accounts["svc-4"]
	profile.ActionCount = 1000
	profile.CountWindow = time.Now() // within the hour window
	sm.mu.Unlock()

	anomaly := sm.RecordAndAnalyze("svc-4", "read", "/api/data", "10.0.0.1")
	if !anomaly.HighVolume {
		t.Errorf("expected HighVolume=true when ActionCount > 1000, got ActionCount=%d", anomaly.ActionCount)
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestMonitor_HandleEvent_IdentityCreation(t *testing.T) {
	cp := newCapPipeline()
	m := startedMonitor(t, cp.pipeline)

	// Create >10 accounts from same IP to trigger bulk creation
	ip := "10.0.0.42"
	for i := 0; i < 12; i++ {
		ev := core.NewSecurityEvent("test", "user_created", core.SeverityInfo, "new user")
		ev.Details["user_id"] = fmt.Sprintf("user_%d", i)
		ev.Details["email"] = fmt.Sprintf("user%d@example.com", i)
		ev.Details["name"] = fmt.Sprintf("User %d", i)
		ev.Details["created_by"] = "system"
		ev.SourceIP = ip
		m.HandleEvent(ev)
	}

	if cp.count() == 0 {
		t.Error("expected alert for bulk identity creation")
	}
	if !cp.hasAlertType("bulk_identity_creation") {
		t.Error("expected bulk_identity_creation alert type")
	}
}

func TestMonitor_HandleEvent_PrivilegeChange(t *testing.T) {
	cp := newCapPipeline()
	m := startedMonitor(t, cp.pipeline)

	ev := core.NewSecurityEvent("test", "privilege_change", core.SeverityInfo, "role change")
	ev.Details["user_id"] = "user1"
	ev.Details["old_role"] = "viewer"
	ev.Details["new_role"] = "admin"
	ev.Details["granted_by"] = "user1" // self-grant
	ev.SourceIP = "10.0.0.1"

	if err := m.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for privilege escalation + self-grant")
	}
	if !cp.hasAlertType("privilege_escalation") {
		t.Error("expected privilege_escalation alert type")
	}
	if !cp.hasAlertType("self_privilege_grant") {
		t.Error("expected self_privilege_grant alert type")
	}
}

func TestMonitor_HandleEvent_ServiceAccountActivity(t *testing.T) {
	cp := newCapPipeline()
	m := startedMonitor(t, cp.pipeline)

	// First action — establishes baseline
	ev1 := core.NewSecurityEvent("test", "service_account_activity", core.SeverityInfo, "svc activity")
	ev1.Details["account_id"] = "svc-test"
	ev1.Details["action"] = "read"
	ev1.Details["resource"] = "/api/data"
	ev1.SourceIP = "10.0.0.1"
	m.HandleEvent(ev1)

	// Simulate baseline period
	m.svcAcctMon.mu.Lock()
	profile := m.svcAcctMon.accounts["svc-test"]
	profile.BaselineStart = time.Now().Add(-48 * time.Hour)
	profile.LastSeen = time.Now()
	m.svcAcctMon.mu.Unlock()

	// Unusual action from new IP
	ev2 := core.NewSecurityEvent("test", "service_account_activity", core.SeverityInfo, "svc activity")
	ev2.Details["account_id"] = "svc-test"
	ev2.Details["action"] = "delete_everything"
	ev2.Details["resource"] = "/api/data"
	ev2.SourceIP = "192.168.99.99"
	m.HandleEvent(ev2)

	if cp.count() == 0 {
		t.Error("expected alert for unusual service account activity")
	}
}

func TestMonitor_HandleEvent_VerificationFailed(t *testing.T) {
	cp := newCapPipeline()
	m := startedMonitor(t, cp.pipeline)

	ev := core.NewSecurityEvent("test", "identity_verification", core.SeverityInfo, "verification")
	ev.Details["user_id"] = "suspect_user"
	ev.Details["result"] = "failed"
	ev.Details["method"] = "document_check"
	ev.SourceIP = "10.0.0.1"

	if err := m.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for failed identity verification")
	}
	if !cp.hasAlertType("verification_failed") {
		t.Error("expected verification_failed alert type")
	}
}

func TestMonitor_HandleEvent_AccountMutation(t *testing.T) {
	cp := newCapPipeline()
	m := startedMonitor(t, cp.pipeline)

	ev := core.NewSecurityEvent("test", "email_changed", core.SeverityInfo, "email changed")
	ev.Details["user_id"] = "user-ato"
	ev.Details["session_id"] = "sess-ato"
	ev.Details["old_email"] = "victim@example.com"
	ev.Details["new_email"] = "attacker@mailinator.com"
	ev.SourceIP = "10.0.0.9"

	if err := m.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if !cp.hasAlertType("account_mutation") {
		t.Fatal("expected account_mutation alert type")
	}
	foundMetadata := false
	for _, alert := range cp.alerts {
		if alert.Type == "account_mutation" &&
			alert.Metadata["user_id"] == "user-ato" &&
			alert.Metadata["session_id"] == "sess-ato" &&
			alert.Metadata["mutation_type"] == "email_change" {
			foundMetadata = true
		}
	}
	if !foundMetadata {
		t.Fatalf("expected account_mutation alert metadata to include user/session/mutation, got %#v", cp.alerts)
	}
}

// Suppress unused import warnings
var _ = time.Second
