package identity

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "identity_monitor"

// Monitor is the Identity Fabric Monitor module providing synthetic identity detection,
// privilege escalation monitoring, and service account behavior analysis.
type Monitor struct {
	logger      zerolog.Logger
	bus         *core.EventBus
	pipeline    *core.AlertPipeline
	cfg         *core.Config
	ctx         context.Context
	cancel      context.CancelFunc
	identityDB  *IdentityDatabase
	privMonitor *PrivilegeMonitor
	svcAcctMon  *ServiceAccountMonitor
}

func New() *Monitor { return &Monitor{} }

func (m *Monitor) Name() string { return ModuleName }
func (m *Monitor) EventTypes() []string {
	return []string{
		"user_created", "identity_created", "account_created",
		"user_updated", "account_updated", "profile_updated",
		"email_changed", "account_email_changed",
		"password_changed", "password_reset", "account_recovery",
		"role_change", "privilege_change", "permission_grant",
		"service_account_activity", "api_key_usage",
		"identity_verification", "kyc_check",
	}
}
func (m *Monitor) Description() string {
	return "Synthetic identity detection, privilege escalation monitoring, service account behavior analysis, and identity lifecycle anomalies"
}

func (m *Monitor) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.bus = bus
	m.pipeline = pipeline
	m.cfg = cfg
	m.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	m.identityDB = NewIdentityDatabase()
	m.privMonitor = NewPrivilegeMonitor()
	m.svcAcctMon = NewServiceAccountMonitor()

	go m.identityDB.CleanupLoop(m.ctx)
	go m.svcAcctMon.CleanupLoop(m.ctx)

	m.logger.Info().Msg("identity fabric monitor started")
	return nil
}

func (m *Monitor) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

func (m *Monitor) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "user_created", "identity_created", "account_created":
		m.handleIdentityCreation(event)
	case "user_updated", "account_updated", "profile_updated",
		"email_changed", "account_email_changed",
		"password_changed", "password_reset", "account_recovery":
		m.handleAccountMutation(event)
	case "privilege_change", "role_change", "permission_grant":
		m.handlePrivilegeChange(event)
	case "service_account_activity", "api_key_usage":
		m.handleServiceAccountActivity(event)
	case "identity_verification", "kyc_check":
		m.handleVerification(event)
	}
	return nil
}

func (m *Monitor) handleAccountMutation(event *core.SecurityEvent) {
	userID := getStringDetail(event, "user_id")
	if userID == "" {
		userID = getStringDetail(event, "account_id")
	}

	mutation := classifyAccountMutation(event)
	if mutation == "" {
		return
	}

	newEmail := getStringDetail(event, "new_email")
	if newEmail == "" {
		newEmail = getStringDetail(event, "email")
	}

	severity := core.SeverityHigh
	if event.Type == "account_recovery" || event.Type == "password_reset" || isDisposableDomain(newEmail) {
		severity = core.SeverityCritical
	}

	m.raiseAlert(event, severity,
		"Sensitive Identity Mutation Detected",
		fmt.Sprintf("Sensitive account mutation %q detected for user %s from %s. "+
			"Email/password recovery changes are high-risk when preceded by AI support-bot prompt anomalies.",
			mutation, userID, event.SourceIP),
		"account_mutation")
}

func (m *Monitor) handleIdentityCreation(event *core.SecurityEvent) {
	userID := getStringDetail(event, "user_id")
	email := getStringDetail(event, "email")
	name := getStringDetail(event, "name")
	createdBy := getStringDetail(event, "created_by")
	source := getStringDetail(event, "source")

	if userID == "" {
		return
	}

	score := m.identityDB.AnalyzeNewIdentity(userID, email, name, source, event.SourceIP)

	if score.IsSynthetic {
		m.raiseAlert(event, core.SeverityCritical,
			"Synthetic Identity Detected",
			fmt.Sprintf("New identity %s (%s) has synthetic identity indicators (score: %.2f). Indicators: %s. Created by: %s",
				userID, email, score.Score, strings.Join(score.Indicators, ", "), createdBy),
			"synthetic_identity")
	}

	// Bulk creation detection
	if score.BulkCreation {
		m.raiseAlert(event, core.SeverityHigh,
			"Bulk Identity Creation",
			fmt.Sprintf("Rapid identity creation detected from %s: %d accounts in the last hour. Possible automated account creation.",
				event.SourceIP, score.RecentCount),
			"bulk_identity_creation")
	}
}

func (m *Monitor) handlePrivilegeChange(event *core.SecurityEvent) {
	userID := getStringDetail(event, "user_id")
	oldRole := getStringDetail(event, "old_role")
	newRole := getStringDetail(event, "new_role")
	grantedBy := getStringDetail(event, "granted_by")
	permission := getStringDetail(event, "permission")

	result := m.privMonitor.Analyze(userID, oldRole, newRole, permission, grantedBy)

	if result.IsEscalation {
		m.raiseAlert(event, core.SeverityHigh,
			"Privilege Escalation Detected",
			fmt.Sprintf("User %s escalated from %q to %q by %s. %s",
				userID, oldRole, newRole, grantedBy, result.Reason),
			"privilege_escalation")
	}

	if result.SelfGrant {
		m.raiseAlert(event, core.SeverityCritical,
			"Self-Granted Privilege",
			fmt.Sprintf("User %s granted themselves elevated privileges: %s -> %s",
				userID, oldRole, newRole),
			"self_privilege_grant")
	}

	if result.SensitivePermission {
		m.raiseAlert(event, core.SeverityHigh,
			"Sensitive Permission Granted",
			fmt.Sprintf("Sensitive permission %q granted to %s by %s", permission, userID, grantedBy),
			"sensitive_permission")
	}
}

func (m *Monitor) handleServiceAccountActivity(event *core.SecurityEvent) {
	accountID := getStringDetail(event, "account_id")
	action := getStringDetail(event, "action")
	resource := getStringDetail(event, "resource")

	if accountID == "" {
		return
	}

	anomaly := m.svcAcctMon.RecordAndAnalyze(accountID, action, resource, event.SourceIP)

	if anomaly.UnusualAction {
		m.raiseAlert(event, core.SeverityHigh,
			"Unusual Service Account Activity",
			fmt.Sprintf("Service account %s performed unusual action %q on %s from IP %s. This action hasn't been seen before.",
				accountID, action, resource, event.SourceIP),
			"unusual_svc_activity")
	}

	if anomaly.UnusualIP {
		m.raiseAlert(event, core.SeverityHigh,
			"Service Account Used from New IP",
			fmt.Sprintf("Service account %s accessed from new IP %s. Known IPs: %s",
				accountID, event.SourceIP, strings.Join(anomaly.KnownIPs, ", ")),
			"svc_unusual_ip")
	}

	if anomaly.HighVolume {
		m.raiseAlert(event, core.SeverityMedium,
			"High Volume Service Account Activity",
			fmt.Sprintf("Service account %s has %d actions in the last hour, exceeding normal baseline.",
				accountID, anomaly.ActionCount),
			"svc_high_volume")
	}
}

func (m *Monitor) handleVerification(event *core.SecurityEvent) {
	userID := getStringDetail(event, "user_id")
	result := getStringDetail(event, "result")
	method := getStringDetail(event, "method")

	if result == "failed" || result == "rejected" {
		m.raiseAlert(event, core.SeverityHigh,
			"Identity Verification Failed",
			fmt.Sprintf("Identity verification failed for %s using method %s. Possible synthetic or stolen identity.",
				userID, method),
			"verification_failed")
	}
}

func (m *Monitor) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID
	for _, key := range []string{
		"user_id", "account_id", "session_id", "mutation_type",
		"email", "old_email", "new_email", "actor", "initiated_by",
	} {
		if val := getStringDetail(event, key); val != "" {
			newEvent.Details[key] = val
		}
	}
	if alertType == "account_mutation" {
		if mutation := classifyAccountMutation(event); mutation != "" {
			newEvent.Details["mutation_type"] = mutation
		}
	}

	if m.bus != nil {
		_ = m.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	for _, key := range []string{"user_id", "account_id", "session_id", "mutation_type"} {
		if val, ok := newEvent.Details[key].(string); ok && val != "" {
			alert.Metadata[key] = val
		}
	}
	alert.Mitigations = getIdentityMitigations(alertType)
	if m.pipeline != nil {
		m.pipeline.Process(alert)
	}
}

// IdentityDatabase tracks identities and detects synthetic ones.
type IdentityDatabase struct {
	mu         sync.RWMutex
	identities map[string]*IdentityRecord
	ipCreation map[string]*creationTracker
}

type IdentityRecord struct {
	UserID    string
	Email     string
	Name      string
	Source    string
	IP        string
	CreatedAt time.Time
}

type creationTracker struct {
	count  int
	window time.Time
}

type SyntheticScore struct {
	Score        float64
	IsSynthetic  bool
	BulkCreation bool
	RecentCount  int
	Indicators   []string
}

func NewIdentityDatabase() *IdentityDatabase {
	return &IdentityDatabase{
		identities: make(map[string]*IdentityRecord),
		ipCreation: make(map[string]*creationTracker),
	}
}

func (db *IdentityDatabase) AnalyzeNewIdentity(userID, email, name, source, ip string) SyntheticScore {
	db.mu.Lock()
	defer db.mu.Unlock()

	score := SyntheticScore{}
	now := time.Now()

	// Track creation rate per IP
	tracker, exists := db.ipCreation[ip]
	if !exists || now.Sub(tracker.window) > time.Hour {
		tracker = &creationTracker{window: now}
		db.ipCreation[ip] = tracker
	}
	tracker.count++
	score.RecentCount = tracker.count

	if tracker.count > 10 {
		score.BulkCreation = true
		score.Score += 0.3
		score.Indicators = append(score.Indicators, fmt.Sprintf("bulk creation: %d accounts/hour from same IP", tracker.count))
	}

	// Check for patterns common in synthetic identities
	if email != "" {
		// Random-looking email addresses
		localPart := strings.Split(email, "@")[0]
		if len(localPart) > 15 && hasHighEntropy(localPart) {
			score.Score += 0.2
			score.Indicators = append(score.Indicators, "high-entropy email local part")
		}
		// Disposable email domains
		if isDisposableDomain(email) {
			score.Score += 0.2
			score.Indicators = append(score.Indicators, "disposable email domain")
		}
	}

	// Sequential or pattern-based names
	if name != "" && looksGenerated(name) {
		score.Score += 0.2
		score.Indicators = append(score.Indicators, "generated-looking name")
	}

	if score.Score >= 0.5 {
		score.IsSynthetic = true
	}

	db.identities[userID] = &IdentityRecord{
		UserID: userID, Email: email, Name: name,
		Source: source, IP: ip, CreatedAt: now,
	}

	return score
}

func (db *IdentityDatabase) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			db.mu.Lock()
			cutoff := time.Now().Add(-2 * time.Hour)
			for ip, tracker := range db.ipCreation {
				if tracker.window.Before(cutoff) {
					delete(db.ipCreation, ip)
				}
			}
			db.mu.Unlock()
		}
	}
}

// PrivilegeMonitor analyzes privilege changes.
type PrivilegeMonitor struct {
	sensitivePerms map[string]bool
	adminRoles     map[string]bool
}

type PrivilegeResult struct {
	IsEscalation        bool
	SelfGrant           bool
	SensitivePermission bool
	Reason              string
}

func NewPrivilegeMonitor() *PrivilegeMonitor {
	return &PrivilegeMonitor{
		sensitivePerms: map[string]bool{
			"admin": true, "root": true, "superuser": true,
			"iam:*": true, "s3:*": true, "ec2:*": true,
			"delete:*": true, "write:*": true, "manage:*": true,
			"org:admin": true, "billing:admin": true,
		},
		adminRoles: map[string]bool{
			"admin": true, "administrator": true, "root": true,
			"superadmin": true, "owner": true, "org_admin": true,
		},
	}
}

func (pm *PrivilegeMonitor) Analyze(userID, oldRole, newRole, permission, grantedBy string) PrivilegeResult {
	result := PrivilegeResult{}

	newRoleLower := strings.ToLower(newRole)
	oldRoleLower := strings.ToLower(oldRole)

	if pm.adminRoles[newRoleLower] && !pm.adminRoles[oldRoleLower] {
		result.IsEscalation = true
		result.Reason = fmt.Sprintf("Escalated to admin role %q from %q", newRole, oldRole)
	}

	if userID == grantedBy && newRole != oldRole {
		result.SelfGrant = true
	}

	if permission != "" && pm.sensitivePerms[strings.ToLower(permission)] {
		result.SensitivePermission = true
	}

	return result
}

// ServiceAccountMonitor tracks service account behavior baselines.
type ServiceAccountMonitor struct {
	mu       sync.RWMutex
	accounts map[string]*svcAccountProfile
}

type svcAccountProfile struct {
	BaselineStart time.Time
	KnownActions  map[string]bool
	KnownIPs      map[string]bool
	ActionCount   int
	CountWindow   time.Time
	LastSeen      time.Time
}

type SvcAnomaly struct {
	UnusualAction bool
	UnusualIP     bool
	HighVolume    bool
	ActionCount   int
	KnownIPs      []string
}

func NewServiceAccountMonitor() *ServiceAccountMonitor {
	return &ServiceAccountMonitor{accounts: make(map[string]*svcAccountProfile)}
}

func (sm *ServiceAccountMonitor) RecordAndAnalyze(accountID, action, resource, ip string) SvcAnomaly {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	anomaly := SvcAnomaly{}
	now := time.Now()

	profile, exists := sm.accounts[accountID]
	if !exists {
		sm.accounts[accountID] = &svcAccountProfile{
			BaselineStart: now,
			KnownActions:  map[string]bool{action: true},
			KnownIPs:      map[string]bool{ip: true},
			ActionCount:   1,
			CountWindow:   now,
			LastSeen:      now,
		}
		return anomaly
	}

	// Check for unusual action (only after baseline period)
	baselineComplete := now.Sub(profile.BaselineStart) > 24*time.Hour
	if baselineComplete {
		if !profile.KnownActions[action] {
			anomaly.UnusualAction = true
		}
		if ip != "" && !profile.KnownIPs[ip] {
			anomaly.UnusualIP = true
			for knownIP := range profile.KnownIPs {
				anomaly.KnownIPs = append(anomaly.KnownIPs, knownIP)
			}
		}
	}

	// Track action volume
	if now.Sub(profile.CountWindow) > time.Hour {
		profile.ActionCount = 0
		profile.CountWindow = now
	}
	profile.ActionCount++
	anomaly.ActionCount = profile.ActionCount

	if profile.ActionCount > 1000 {
		anomaly.HighVolume = true
	}

	if !baselineComplete {
		profile.KnownActions[action] = true
		if ip != "" {
			profile.KnownIPs[ip] = true
		}
	}
	profile.LastSeen = now

	return anomaly
}

func (sm *ServiceAccountMonitor) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.mu.Lock()
			cutoff := time.Now().Add(-7 * 24 * time.Hour)
			for id, profile := range sm.accounts {
				if profile.LastSeen.Before(cutoff) {
					delete(sm.accounts, id)
				}
			}
			sm.mu.Unlock()
		}
	}
}

func hasHighEntropy(s string) bool {
	if len(s) < 8 {
		return false
	}
	digits := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	return float64(digits)/float64(len(s)) > 0.4
}

func isDisposableDomain(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])
	disposable := map[string]bool{
		"tempmail.com": true, "throwaway.email": true, "guerrillamail.com": true,
		"mailinator.com": true, "yopmail.com": true, "10minutemail.com": true,
		"trashmail.com": true, "fakeinbox.com": true, "sharklasers.com": true,
		"guerrillamailblock.com": true, "grr.la": true, "dispostable.com": true,
		"temp-mail.org": true, "tempail.com": true, "mohmal.com": true,
	}
	return disposable[domain]
}

func looksGenerated(name string) bool {
	parts := strings.Fields(name)
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		digits := 0
		for _, c := range part {
			if c >= '0' && c <= '9' {
				digits++
			}
		}
		if digits > 2 {
			return true
		}
	}
	return false
}

func classifyAccountMutation(event *core.SecurityEvent) string {
	switch event.Type {
	case "email_changed", "account_email_changed":
		return "email_change"
	case "password_changed", "password_reset":
		return "password_change"
	case "account_recovery":
		return "account_recovery"
	}

	mutation := strings.ToLower(getStringDetail(event, "mutation_type"))
	if mutation == "" {
		mutation = strings.ToLower(getStringDetail(event, "action"))
	}
	if mutation != "" {
		switch {
		case strings.Contains(mutation, "email"):
			return "email_change"
		case strings.Contains(mutation, "password") || strings.Contains(mutation, "credential"):
			return "password_change"
		case strings.Contains(mutation, "recover"):
			return "account_recovery"
		}
	}

	changed := strings.ToLower(strings.Join([]string{
		getStringDetail(event, "changed_fields"),
		getStringDetail(event, "fields"),
		getStringDetail(event, "new_email"),
		getStringDetail(event, "email"),
	}, " "))
	switch {
	case strings.Contains(changed, "email"):
		return "email_change"
	case strings.Contains(changed, "password") || strings.Contains(changed, "credential"):
		return "password_change"
	}
	return ""
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

// getIdentityMitigations returns context-specific mitigations based on alert type.
func getIdentityMitigations(alertType string) []string {
	switch alertType {
	case "synthetic_identity":
		return []string{
			"Require additional identity verification (document check, biometric)",
			"Flag the account for manual review before granting access",
			"Check for correlated synthetic identity indicators across accounts",
			"Implement progressive trust — limit new account capabilities initially",
		}
	case "bulk_identity_creation":
		return []string{
			"Implement CAPTCHA or proof-of-work for account creation",
			"Rate limit account creation per IP address and email domain",
			"Block disposable email domains for account registration",
			"Investigate the source IP for bot activity indicators",
		}
	case "privilege_escalation":
		return []string{
			"Review and revert the privilege change if unauthorized",
			"Implement multi-party approval for privilege escalations",
			"Enforce separation of duties — users should not approve their own escalations",
			"Audit all privilege changes with immutable logging",
		}
	case "self_granted_privilege":
		return []string{
			"Immediately revert the self-granted privilege",
			"Investigate the account for compromise indicators",
			"Implement controls preventing self-service privilege escalation",
			"Require a different administrator to approve privilege changes",
		}
	case "sensitive_permission_grant":
		return []string{
			"Verify the permission grant was authorized through proper channels",
			"Implement just-in-time access for sensitive permissions",
			"Set expiration times on sensitive permission grants",
			"Monitor usage of sensitive permissions for anomalies",
		}
	case "unusual_service_account_activity":
		return []string{
			"Investigate the unusual action for signs of compromise",
			"Review service account permissions — apply least privilege",
			"Implement behavioral baselines for service accounts",
			"Rotate service account credentials if compromise is suspected",
		}
	case "service_account_new_ip":
		return []string{
			"Verify the new IP is a legitimate infrastructure change",
			"Implement IP allowlisting for service accounts",
			"Check for credential theft or lateral movement indicators",
		}
	case "service_account_high_volume":
		return []string{
			"Investigate the cause of elevated activity",
			"Implement rate limiting on service account API calls",
			"Check for automated abuse or credential compromise",
		}
	case "verification_failed":
		return []string{
			"Lock the account pending manual identity verification",
			"Investigate for stolen or synthetic identity indicators",
			"Require step-up authentication before allowing access",
		}
	case "account_mutation":
		return []string{
			"Require step-up authentication for email, password, and recovery changes",
			"Temporarily lock the account when mutation follows support-bot or LLM anomalies",
			"Notify the previous email address before finalizing identity changes",
			"Review actor, session, and source IP telemetry for account takeover indicators",
		}
	default:
		return []string{
			"Review the identity event and investigate for anomalies",
			"Implement multi-factor authentication for sensitive operations",
			"Monitor identity lifecycle events for suspicious patterns",
		}
	}
}
