package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog"
)

const ModuleName = "auth_fortress"

// Fortress is the Auth Fortress module providing brute force detection,
// credential stuffing, session theft, impossible travel, MFA bypass,
// password spraying, OAuth token abuse, consent phishing detection,
// passkey/FIDO2 downgrade detection, AitM proxy detection, and
// session token binding verification.
type Fortress struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	cfg          *core.Config
	ctx          context.Context
	cancel       context.CancelFunc
	loginTracker *LoginTracker
	sessionMon   *SessionMonitor
	oauthMon     *OAuthMonitor
	sprayDet     *PasswordSprayDetector
	aitmDet      *AitMDetector
	revokedJTIs  *lru.Cache[string, time.Time]
}

func New() *Fortress { return &Fortress{} }

func (f *Fortress) Name() string { return ModuleName }
func (f *Fortress) Description() string {
	return "Brute force, credential stuffing, session theft, impossible travel, MFA bypass, password spraying, OAuth token abuse, consent phishing, passkey/FIDO2 downgrade, AitM proxy, session token binding, and SAML response structure detection"
}
func (f *Fortress) EventTypes() []string {
	return []string{
		"login_attempt", "auth_attempt",
		"login_success", "auth_success",
		"login_failure", "auth_failure",
		"logout", "token_revocation",
		"session_activity",
		"mfa_attempt",
		"oauth_grant", "oauth_consent", "oauth_token",
		"token_usage", "api_key_usage",
		"jwt_validation", "token_event",
		"password_spray", "distributed_auth",
		"passkey_register", "passkey_auth", "webauthn_ceremony",
		"auth_downgrade",
		"saml_response",
	}
}

func (f *Fortress) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	f.ctx, f.cancel = context.WithCancel(ctx)
	f.bus = bus
	f.pipeline = pipeline
	f.cfg = cfg
	f.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)
	maxFailures := getIntSetting(settings, "max_failures_per_minute", 10)
	lockoutDuration := getIntSetting(settings, "lockout_duration_seconds", 300)
	stuffingThreshold := getIntSetting(settings, "stuffing_threshold", 50)

	f.loginTracker = NewLoginTracker(maxFailures, stuffingThreshold, time.Duration(lockoutDuration)*time.Second)
	f.sessionMon = NewSessionMonitor()
	f.oauthMon = NewOAuthMonitor()
	f.sprayDet = NewPasswordSprayDetector()
	f.aitmDet = NewAitMDetector()
	f.revokedJTIs, _ = lru.New[string, time.Time](50000)

	go f.oauthMon.CleanupLoop(f.ctx)
	go f.sprayDet.CleanupLoop(f.ctx)

	f.logger.Info().
		Int("max_failures", maxFailures).
		Int("lockout_sec", lockoutDuration).
		Msg("auth fortress started")
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
	case "login_attempt", "auth_attempt":
		f.handleLoginAttempt(event)
	case "login_success", "auth_success":
		f.handleLoginSuccess(event)
	case "login_failure", "auth_failure":
		f.handleLoginFailure(event)
	case "logout", "token_revocation":
		f.handleTokenRevocation(event)
	case "session_activity":
		f.handleSessionActivity(event)
	case "mfa_attempt":
		f.handleMFAAttempt(event)
	case "oauth_grant", "oauth_consent", "oauth_token":
		f.handleOAuthEvent(event)
	case "token_usage", "api_key_usage":
		f.handleTokenUsage(event)
	case "jwt_validation", "token_event":
		f.handleJWTValidation(event)
	case "password_spray", "distributed_auth":
		f.handlePasswordSpray(event)
	case "passkey_register", "passkey_auth", "webauthn_ceremony":
		f.handlePasskeyEvent(event)
	case "auth_downgrade":
		f.handleAuthDowngrade(event)
	case "saml_response":
		f.handleSAMLResponse(event)
	}
	return nil
}

func (f *Fortress) handleLoginFailure(event *core.SecurityEvent) {
	ip := event.SourceIP
	username := getStringDetail(event, "username")
	f.maybeRecordRevokedToken(event)

	// Also feed into spray detector
	f.sprayDet.RecordFailure(ip, username)
	if spray := f.sprayDet.Check(); spray.Detected {
		f.raiseAlert(event, core.SeverityCritical,
			"Password Spraying Attack Detected",
			fmt.Sprintf("Distributed password spray detected: %d unique IPs targeting %d accounts "+
				"with %d common passwords in %s. This is a coordinated low-and-slow attack "+
				"designed to evade per-IP lockout. MITRE ATT&CK T1110.003.",
				spray.UniqueIPs, spray.UniqueUsers, spray.UniquePasswords, spray.TimeWindow),
			"password_spray")
	}

	result := f.loginTracker.RecordFailure(ip, username)

	if result.BruteForce {
		f.raiseAlert(event, core.SeverityHigh,
			"Brute Force Attack Detected",
			fmt.Sprintf("IP %s has %d failed login attempts in the last minute for user %q. Account locked for %s.",
				ip, result.FailureCount, username, f.loginTracker.lockoutDuration),
			"brute_force")
	}

	if result.CredentialStuffing {
		f.raiseAlert(event, core.SeverityCritical,
			"Credential Stuffing Attack Detected",
			fmt.Sprintf("IP %s is attempting logins against %d different usernames. This indicates a credential stuffing attack.",
				ip, result.UniqueUsers),
			"credential_stuffing")
	}
}

func (f *Fortress) handleLoginSuccess(event *core.SecurityEvent) {
	ip := event.SourceIP
	username := getStringDetail(event, "username")
	sessionID := getStringDetail(event, "session_id")
	authMethod := getStringDetail(event, "auth_method")

	if f.loginTracker.WasRecentlyBlocked(ip) {
		f.raiseAlert(event, core.SeverityHigh,
			"Successful Login After Brute Force",
			fmt.Sprintf("IP %s successfully logged in as %q after previous brute force attempts. Possible credential compromise.",
				ip, username),
			"post_bruteforce_login")
	}

	// AitM detection: check for proxy indicators on successful login
	tlsFingerprint := getStringDetail(event, "tls_fingerprint")
	proxyHeaders := getStringDetail(event, "proxy_headers")
	loginLatency := getStringDetail(event, "login_latency_ms")
	aitmResult := f.aitmDet.AnalyzeLogin(ip, username, event.UserAgent, tlsFingerprint, proxyHeaders, loginLatency, authMethod)
	if aitmResult.Detected {
		f.raiseAlert(event, core.SeverityCritical,
			"Adversary-in-the-Middle (AitM) Proxy Detected",
			fmt.Sprintf("Login for user %q from %s shows AitM proxy indicators: %s. "+
				"Session tokens may be stolen in real-time. MITRE ATT&CK T1557.",
				username, ip, aitmResult.Reason),
			"aitm_proxy_detected")
	}

	if sessionID != "" {
		country := getStringDetail(event, "country")
		if country == "" {
			country = getStringDetail(event, "country_code")
		}
		f.sessionMon.RegisterSession(sessionID, username, ip, country, event.UserAgent)
	}

	// PTR record validation — CVE-2026-1490 defense
	hostname := getStringDetail(event, "hostname")
	if hostname != "" && !f.verifyPTR(ip, hostname) {
		f.raiseAlert(event, core.SeverityHigh,
			"PTR Record Spoofing Detected",
			fmt.Sprintf("Login from IP %s claims hostname %q but reverse DNS does not match. "+
				"Possible authorization bypass via PTR record spoofing. Ref: CVE-2026-1490.",
				ip, hostname),
			"ptr_spoofing")
	}

	f.loginTracker.ClearFailures(ip, username)
}

func (f *Fortress) handleLoginAttempt(event *core.SecurityEvent) {
	ip := event.SourceIP
	if f.loginTracker.IsLockedOut(ip) {
		f.raiseAlert(event, core.SeverityMedium,
			"Login Attempt During Lockout",
			fmt.Sprintf("IP %s attempted login while locked out", ip),
			"lockout_violation")
	}
}

// verifyPTR performs reverse DNS validation on an IP address and checks whether
// the claimed hostname matches any PTR record. Detects CVE-2026-1490 style
// authorization bypass via PTR record spoofing.
func (f *Fortress) verifyPTR(ip, claimedHostname string) bool {
	if ip == "" || claimedHostname == "" {
		return true // nothing to verify
	}
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		// No PTR record at all — suspicious but not necessarily spoofing
		return false
	}
	claimed := strings.TrimSuffix(strings.ToLower(claimedHostname), ".")
	for _, name := range names {
		ptr := strings.TrimSuffix(strings.ToLower(name), ".")
		if ptr == claimed {
			return true
		}
	}
	return false
}

func (f *Fortress) handleSessionActivity(event *core.SecurityEvent) {
	sessionID := getStringDetail(event, "session_id")
	if sessionID == "" {
		return
	}

	currentIP := event.SourceIP
	currentUA := event.UserAgent
	currentCountry := getStringDetail(event, "country")
	if currentCountry == "" {
		currentCountry = getStringDetail(event, "country_code")
	}

	anomaly := f.sessionMon.CheckAnomaly(sessionID, currentIP, currentCountry, currentUA)

	if anomaly.IPChanged {
		f.raiseAlert(event, core.SeverityHigh,
			"Session Hijacking Suspected",
			fmt.Sprintf("Session %s changed IP from %s to %s. Possible session theft via cookie/token hijacking.",
				truncate(sessionID, 16), anomaly.OriginalIP, currentIP),
			"session_hijack")
	}

	if anomaly.UAChanged {
		f.raiseAlert(event, core.SeverityMedium,
			"Session User-Agent Changed",
			fmt.Sprintf("Session %s user-agent changed. Original: %s, Current: %s",
				truncate(sessionID, 16), truncate(anomaly.OriginalUA, 50), truncate(currentUA, 50)),
			"session_ua_change")
	}

	if anomaly.ImpossibleTravel {
		f.raiseAlert(event, core.SeverityCritical,
			"Impossible Travel Detected",
			fmt.Sprintf("Session %s accessed from %s and %s within %s. Geographic distance makes this physically impossible.",
				truncate(sessionID, 16), anomaly.OriginalIP, currentIP, anomaly.TimeDelta.String()),
			"impossible_travel")
	}
}

func (f *Fortress) handleMFAAttempt(event *core.SecurityEvent) {
	ip := event.SourceIP
	success := getStringDetail(event, "success") == "true"
	method := getStringDetail(event, "method")

	if !success {
		failures := f.loginTracker.RecordMFAFailure(ip)
		if failures > 5 {
			f.raiseAlert(event, core.SeverityHigh,
				"MFA Bypass Attempt",
				fmt.Sprintf("IP %s has %d failed MFA attempts using method %q. Possible MFA bypass attack.",
					ip, failures, method),
				"mfa_bypass")
		}
		// MFA fatigue detection: rapid repeated push notifications
		if method == "push" && failures > 10 {
			f.raiseAlert(event, core.SeverityCritical,
				"MFA Fatigue Attack Detected",
				fmt.Sprintf("IP %s sent %d push MFA requests. Attacker is bombarding user with "+
					"push notifications hoping for accidental approval. MITRE ATT&CK T1621.",
					ip, failures),
				"mfa_fatigue")
		}
	}
}

// handleOAuthEvent detects OAuth token abuse, consent phishing, and token theft.
func (f *Fortress) handleOAuthEvent(event *core.SecurityEvent) {
	ip := event.SourceIP
	appID := getStringDetail(event, "app_id")
	appName := getStringDetail(event, "app_name")
	scopes := getStringDetail(event, "scopes")
	user := getStringDetail(event, "username")
	grantType := getStringDetail(event, "grant_type")
	redirectURI := getStringDetail(event, "redirect_uri")

	result := f.oauthMon.Analyze(ip, appID, appName, scopes, user, grantType, redirectURI)

	if result.ConsentPhishing {
		f.raiseAlert(event, core.SeverityCritical,
			"OAuth Consent Phishing Detected",
			fmt.Sprintf("Suspicious OAuth consent request from app %q (ID: %s) to user %q. "+
				"Requesting excessive scopes: %s. Redirect URI: %s. "+
				"This may be a malicious app tricking users into granting access. MITRE ATT&CK T1528.",
				appName, appID, user, scopes, redirectURI),
			"consent_phishing")
	}

	if result.TokenAbuse {
		f.raiseAlert(event, core.SeverityHigh,
			"OAuth Token Abuse Detected",
			fmt.Sprintf("App %q (ID: %s) is abusing OAuth tokens. %s. "+
				"Token used from %s. MITRE ATT&CK T1528.",
				appName, appID, result.Reason, ip),
			"oauth_token_abuse")
	}

	if result.ExcessiveScopes {
		f.raiseAlert(event, core.SeverityMedium,
			"Excessive OAuth Scope Request",
			fmt.Sprintf("App %q requesting broad OAuth scopes: %s for user %q. "+
				"Review whether this app needs this level of access.",
				appName, scopes, user),
			"excessive_oauth_scopes")
	}
}

// handleTokenUsage detects stolen token replay and API key abuse.
func (f *Fortress) handleTokenUsage(event *core.SecurityEvent) {
	if f.handleRevokedTokenReuse(event, "token_reuse_post_logout") {
		return
	}

	tokenID := getStringDetail(event, "token_id")
	ip := event.SourceIP
	user := getStringDetail(event, "username")
	action := getStringDetail(event, "action")

	if tokenID == "" {
		return
	}

	result := f.oauthMon.TrackTokenUsage(tokenID, ip, user, action)

	if result.MultiIPUsage {
		f.raiseAlert(event, core.SeverityCritical,
			"Stolen Token Detected",
			fmt.Sprintf("Token %s for user %q is being used from %d different IPs in %s. "+
				"Original IP: %s, current: %s. Token has likely been stolen. MITRE ATT&CK T1528.",
				truncate(tokenID, 16), user, result.IPCount, result.TimeWindow,
				result.OriginalIP, ip),
			"stolen_token")
	}

	if result.AnomalousAction {
		f.raiseAlert(event, core.SeverityHigh,
			"Anomalous Token Activity",
			fmt.Sprintf("Token %s for user %q performing unusual action %q from %s. "+
				"This action has not been seen from this token before.",
				truncate(tokenID, 16), user, action, ip),
			"anomalous_token_activity")
	}
}

func (f *Fortress) handleJWTValidation(event *core.SecurityEvent) {
	f.handleRevokedTokenReuse(event, "token_reuse_post_logout")
}

func (f *Fortress) handleTokenRevocation(event *core.SecurityEvent) {
	jti := extractTokenIdentifier(event)
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

func (f *Fortress) handleRevokedTokenReuse(event *core.SecurityEvent, alertType string) bool {
	jti := extractTokenIdentifier(event)
	if jti == "" || f.revokedJTIs == nil {
		return false
	}
	if _, ok := f.revokedJTIs.Get(jti); !ok {
		return false
	}

	f.raiseAlert(event, core.SeverityCritical,
		"Revoked JWT Reused After Logout",
		fmt.Sprintf("Token identifier %q was observed after explicit revocation/logout. "+
			"This indicates stateful JWT non-invalidation or token replay after session termination.",
			truncate(jti, 24)),
		alertType)
	return true
}

// handlePasswordSpray handles explicit password spray events from external detectors.
func (f *Fortress) handlePasswordSpray(event *core.SecurityEvent) {
	ip := event.SourceIP
	username := getStringDetail(event, "username")
	f.sprayDet.RecordFailure(ip, username)
}

// handlePasskeyEvent detects passkey/FIDO2/WebAuthn security issues.
// Post-passkey, the attack surface shifts to session hijacking, downgrade
// attacks, and WebAuthn API hijacking.
// Ref: DEF CON 33 WebAuthn API hijacking, BleepingComputer FIDO downgrade 2025
func (f *Fortress) handlePasskeyEvent(event *core.SecurityEvent) {
	action := getStringDetail(event, "action")
	method := getStringDetail(event, "method")
	origin := getStringDetail(event, "origin")
	ip := event.SourceIP
	username := getStringDetail(event, "username")
	attestation := getStringDetail(event, "attestation")

	// Detect passkey registration from suspicious context
	if action == "register" || event.Type == "passkey_register" {
		// Multiple passkey registrations from same IP for different users = suspicious
		f.aitmDet.RecordPasskeyRegistration(ip, username)
		if f.aitmDet.IsPasskeyRegistrationAnomaly(ip) {
			f.raiseAlert(event, core.SeverityHigh,
				"Suspicious Passkey Registration Pattern",
				fmt.Sprintf("IP %s has registered passkeys for multiple users. "+
					"This may indicate an attacker registering rogue passkeys via compromised sessions.",
					ip),
				"suspicious_passkey_registration")
		}

		// No attestation = self-attestation, lower trust
		if attestation == "none" || attestation == "self" {
			f.raiseAlert(event, core.SeverityLow,
				"Passkey Registered Without Attestation",
				fmt.Sprintf("User %q registered a passkey from %s without hardware attestation. "+
					"Self-attested passkeys provide weaker device binding guarantees.",
					username, ip),
				"passkey_no_attestation")
		}
	}

	// Detect origin mismatch (WebAuthn API hijacking indicator)
	expectedOrigin := getStringDetail(event, "expected_origin")
	if origin != "" && expectedOrigin != "" && origin != expectedOrigin {
		f.raiseAlert(event, core.SeverityCritical,
			"WebAuthn Origin Mismatch Detected",
			fmt.Sprintf("Passkey ceremony for user %q has origin mismatch: expected %q, got %q. "+
				"This indicates a WebAuthn API hijacking attack. Ref: DEF CON 33.",
				username, expectedOrigin, origin),
			"webauthn_origin_mismatch")
	}

	// Detect downgrade from passkey to weaker method
	if method != "" && (method == "password" || method == "otp" || method == "sms") {
		previousMethod := getStringDetail(event, "previous_method")
		if previousMethod == "passkey" || previousMethod == "fido2" || previousMethod == "webauthn" {
			f.raiseAlert(event, core.SeverityHigh,
				"Authentication Downgrade from Passkey",
				fmt.Sprintf("User %q downgraded from %s to %s. "+
					"AitM proxies force downgrades by spoofing unsupported user agents. "+
					"Ref: Silverfort FIDO downgrade research 2025.",
					username, previousMethod, method),
				"passkey_downgrade")
		}
	}
}

// handleAuthDowngrade detects forced authentication method downgrades.
func (f *Fortress) handleAuthDowngrade(event *core.SecurityEvent) {
	username := getStringDetail(event, "username")
	fromMethod := getStringDetail(event, "from_method")
	toMethod := getStringDetail(event, "to_method")
	reason := getStringDetail(event, "reason")
	ip := event.SourceIP

	severity := core.SeverityMedium
	// Downgrade from phishing-resistant to phishable = high severity
	phishingResistant := map[string]bool{"passkey": true, "fido2": true, "webauthn": true, "hardware_key": true}
	if phishingResistant[strings.ToLower(fromMethod)] && !phishingResistant[strings.ToLower(toMethod)] {
		severity = core.SeverityHigh
	}

	f.raiseAlert(event, severity,
		"Authentication Method Downgrade",
		fmt.Sprintf("User %q authentication downgraded from %s to %s (reason: %s) from IP %s. "+
			"Forced downgrades are a common AitM proxy technique.",
			username, fromMethod, toMethod, reason, ip),
		"auth_method_downgrade")
}

func (f *Fortress) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.UserAgent = event.UserAgent
	newEvent.Details["original_event_id"] = event.ID

	if f.bus != nil {
		_ = f.bus.PublishEvent(newEvent)
	}
	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getAuthMitigations(alertType)
	if f.pipeline != nil {
		f.pipeline.Process(alert)
	}
}

// ---------------------------------------------------------------------------
// LoginTracker — brute force and credential stuffing detection
// ---------------------------------------------------------------------------

type LoginTracker struct {
	mu                sync.RWMutex
	failures          *lru.Cache[string, *failureRecord]
	userFailures      *lru.Cache[string, *failureRecord]
	mfaFailures       *lru.Cache[string, int]
	lockouts          *lru.Cache[string, time.Time]
	maxPerMinute      int
	stuffingThreshold int
	lockoutDuration   time.Duration
}

type failureRecord struct {
	count       int
	uniqueUsers map[string]bool
	window      time.Time
	lastSeen    time.Time
}

type LoginResult struct {
	BruteForce         bool
	CredentialStuffing bool
	FailureCount       int
	UniqueUsers        int
}

func NewLoginTracker(maxPerMinute, stuffingThreshold int, lockoutDuration time.Duration) *LoginTracker {
	fCache, _ := lru.New[string, *failureRecord](50000)
	uCache, _ := lru.New[string, *failureRecord](50000)
	mCache, _ := lru.New[string, int](50000)
	lCache, _ := lru.New[string, time.Time](50000)
	return &LoginTracker{
		failures:          fCache,
		userFailures:      uCache,
		mfaFailures:       mCache,
		lockouts:          lCache,
		maxPerMinute:      maxPerMinute,
		stuffingThreshold: stuffingThreshold,
		lockoutDuration:   lockoutDuration,
	}
}

func (lt *LoginTracker) RecordFailure(ip, username string) LoginResult {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	now := time.Now()
	result := LoginResult{}

	rec, exists := lt.failures.Get(ip)
	if !exists || now.Sub(rec.window) > time.Minute {
		rec = &failureRecord{uniqueUsers: make(map[string]bool), window: now}
		lt.failures.Add(ip, rec)
	}

	if len(rec.uniqueUsers) > 100 { // Cap unique users to prevent OOM
		rec.uniqueUsers = make(map[string]bool)
	}
	if username != "" {
		rec.uniqueUsers[username] = true
	}

	rec.count++
	rec.lastSeen = now

	result.FailureCount = rec.count
	result.UniqueUsers = len(rec.uniqueUsers)

	if rec.count >= lt.maxPerMinute {
		result.BruteForce = true
		lt.lockouts.Add(ip, now.Add(lt.lockoutDuration))
	}
	if len(rec.uniqueUsers) >= lt.stuffingThreshold {
		result.CredentialStuffing = true
	}
	return result
}

func (lt *LoginTracker) RecordMFAFailure(ip string) int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	val, _ := lt.mfaFailures.Get(ip) // Use ip as key
	val++
	lt.mfaFailures.Add(ip, val) // Use ip as key
	return val
}

func (lt *LoginTracker) IsLockedOut(ip string) bool {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	lockoutEnd, exists := lt.lockouts.Get(ip)
	return exists && time.Now().Before(lockoutEnd)
}

func (lt *LoginTracker) WasRecentlyBlocked(ip string) bool {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	rec, exists := lt.failures.Get(ip)
	if !exists {
		return false
	}
	return rec.count >= lt.maxPerMinute && time.Since(rec.lastSeen) < 10*time.Minute
}

func (lt *LoginTracker) ClearFailures(ip, username string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.failures.Remove(ip)
	lt.mfaFailures.Remove(ip)
}

// ---------------------------------------------------------------------------
// SessionMonitor — session hijacking and impossible travel detection
// ---------------------------------------------------------------------------

type SessionMonitor struct {
	mu       sync.RWMutex
	sessions *lru.Cache[string, *sessionRecord]
}

type sessionRecord struct {
	username  string
	ip        string
	country   string
	userAgent string
	created   time.Time
	lastSeen  time.Time
}

type SessionAnomaly struct {
	IPChanged        bool
	UAChanged        bool
	ImpossibleTravel bool
	OriginalIP       string
	OriginalUA       string
	TimeDelta        time.Duration
}

func NewSessionMonitor() *SessionMonitor {
	sCache, _ := lru.New[string, *sessionRecord](100000)
	return &SessionMonitor{sessions: sCache}
}

func (sm *SessionMonitor) RegisterSession(sessionID, username, ip, country, userAgent string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions.Add(sessionID, &sessionRecord{
		username: username, ip: ip, country: country,
		userAgent: userAgent, created: time.Now(), lastSeen: time.Now(),
	})
}

func (sm *SessionMonitor) CheckAnomaly(sessionID, currentIP, currentCountry, currentUA string) SessionAnomaly {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	anomaly := SessionAnomaly{}
	rec, exists := sm.sessions.Get(sessionID)
	if !exists {
		return anomaly
	}

	timeDelta := time.Since(rec.lastSeen)
	anomaly.OriginalIP = rec.ip
	anomaly.OriginalUA = rec.userAgent
	anomaly.TimeDelta = timeDelta

	if currentIP != "" && rec.ip != "" && currentIP != rec.ip {
		anomaly.IPChanged = true
		prevCountry := rec.country
		if prevCountry != "" && currentCountry != "" && prevCountry != currentCountry {
			prevLat, prevLon, prevOk := countryCentroid(prevCountry)
			curLat, curLon, curOk := countryCentroid(currentCountry)
			if prevOk && curOk {
				distKm := haversineDistance(prevLat, prevLon, curLat, curLon)
				maxTravelKm := timeDelta.Hours() * 1000
				if distKm > maxTravelKm && distKm > 500 {
					anomaly.ImpossibleTravel = true
				}
			} else if timeDelta < 5*time.Minute {
				anomaly.ImpossibleTravel = true
			}
		} else if prevCountry == "" || currentCountry == "" {
			if timeDelta < 5*time.Minute {
				anomaly.ImpossibleTravel = true
			}
		}
	}

	if currentUA != "" && rec.userAgent != "" && currentUA != rec.userAgent {
		anomaly.UAChanged = true
	}

	rec.ip = currentIP
	rec.userAgent = currentUA
	rec.lastSeen = time.Now()
	if currentCountry != "" {
		rec.country = currentCountry
	}
	sm.sessions.Add(sessionID, rec) // Update the LRU cache with the modified record
	return anomaly
}

func (sm *SessionMonitor) CleanupLoop(ctx context.Context) {
	// LRU cache handles cleanup automatically based on size.
	// No explicit time-based cleanup loop needed for sessions.
}

// ---------------------------------------------------------------------------
// OAuthMonitor — OAuth token abuse, consent phishing, token theft detection
// ---------------------------------------------------------------------------

type OAuthMonitor struct {
	mu         sync.Mutex
	appGrants  map[string]*oauthAppProfile // key: appID
	tokenUsage map[string]*tokenProfile    // key: tokenID
}

type oauthAppProfile struct {
	grantCount   int
	uniqueUsers  map[string]bool
	scopes       map[string]bool
	redirectURIs map[string]bool
	firstSeen    time.Time
	lastSeen     time.Time
}

type tokenProfile struct {
	user      string
	ips       map[string]time.Time
	actions   map[string]bool
	firstIP   string
	firstSeen time.Time
	lastSeen  time.Time
}

type OAuthResult struct {
	ConsentPhishing bool
	TokenAbuse      bool
	ExcessiveScopes bool
	Reason          string
}

type TokenUsageResult struct {
	MultiIPUsage    bool
	AnomalousAction bool
	IPCount         int
	OriginalIP      string
	TimeWindow      string
}

func NewOAuthMonitor() *OAuthMonitor {
	return &OAuthMonitor{
		appGrants:  make(map[string]*oauthAppProfile),
		tokenUsage: make(map[string]*tokenProfile),
	}
}

func (om *OAuthMonitor) Analyze(ip, appID, appName, scopes, user, grantType, redirectURI string) OAuthResult {
	om.mu.Lock()
	defer om.mu.Unlock()

	result := OAuthResult{}
	now := time.Now()

	// Track app grants
	profile, exists := om.appGrants[appID]
	if !exists {
		profile = &oauthAppProfile{
			uniqueUsers:  make(map[string]bool),
			scopes:       make(map[string]bool),
			redirectURIs: make(map[string]bool),
			firstSeen:    now,
		}
		om.appGrants[appID] = profile
	}
	profile.grantCount++
	profile.lastSeen = now
	if user != "" {
		profile.uniqueUsers[user] = true
	}
	if redirectURI != "" {
		profile.redirectURIs[redirectURI] = true
	}
	for _, s := range strings.Split(scopes, " ") {
		s = strings.TrimSpace(s)
		if s != "" {
			profile.scopes[s] = true
		}
	}

	// Consent phishing: new app requesting dangerous scopes from many users quickly
	dangerousScopes := map[string]bool{
		"mail.read": true, "mail.readwrite": true, "mail.send": true,
		"files.readwrite.all": true, "directory.readwrite.all": true,
		"user.readwrite.all": true, "sites.readwrite.all": true,
		"mailboxsettings.readwrite": true, "contacts.readwrite": true,
		"calendars.readwrite": true, "offline_access": true,
	}

	dangerousCount := 0
	for s := range profile.scopes {
		if dangerousScopes[strings.ToLower(s)] {
			dangerousCount++
		}
	}

	if dangerousCount >= 3 && profile.grantCount >= 3 &&
		now.Sub(profile.firstSeen) < 1*time.Hour {
		result.ConsentPhishing = true
	}

	// Excessive scopes
	if dangerousCount >= 4 || len(profile.scopes) >= 8 {
		result.ExcessiveScopes = true
	}

	// Token abuse: rapid grants to many users
	if profile.grantCount > 20 && len(profile.uniqueUsers) > 10 &&
		now.Sub(profile.firstSeen) < 30*time.Minute {
		result.TokenAbuse = true
		result.Reason = fmt.Sprintf("Rapid OAuth grants: %d grants to %d users in %s",
			profile.grantCount, len(profile.uniqueUsers),
			now.Sub(profile.firstSeen).Round(time.Second))
	}

	return result
}

func (om *OAuthMonitor) TrackTokenUsage(tokenID, ip, user, action string) TokenUsageResult {
	om.mu.Lock()
	defer om.mu.Unlock()

	result := TokenUsageResult{}
	now := time.Now()

	profile, exists := om.tokenUsage[tokenID]
	if !exists {
		profile = &tokenProfile{
			user:      user,
			ips:       make(map[string]time.Time),
			actions:   make(map[string]bool),
			firstIP:   ip,
			firstSeen: now,
		}
		om.tokenUsage[tokenID] = profile
	}
	profile.lastSeen = now
	if ip != "" {
		profile.ips[ip] = now
	}

	// Check for anomalous action (new action not seen before)
	if action != "" {
		if len(profile.actions) > 5 && !profile.actions[action] {
			result.AnomalousAction = true
		}
		profile.actions[action] = true
	}

	// Multi-IP usage: token used from 3+ IPs
	result.IPCount = len(profile.ips)
	result.OriginalIP = profile.firstIP
	result.TimeWindow = now.Sub(profile.firstSeen).Round(time.Second).String()
	if len(profile.ips) >= 3 {
		result.MultiIPUsage = true
	}

	return result
}

func (om *OAuthMonitor) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			om.mu.Lock()
			cutoff := time.Now().Add(-1 * time.Hour)
			for id, p := range om.appGrants {
				if p.lastSeen.Before(cutoff) {
					delete(om.appGrants, id)
				}
			}
			tokenCutoff := time.Now().Add(-24 * time.Hour)
			for id, p := range om.tokenUsage {
				if p.lastSeen.Before(tokenCutoff) {
					delete(om.tokenUsage, id)
				}
			}
			om.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// PasswordSprayDetector — detects distributed low-and-slow password spraying
// ---------------------------------------------------------------------------

type PasswordSprayDetector struct {
	mu          sync.Mutex
	attempts    []sprayAttempt
	windowStart time.Time
}

type sprayAttempt struct {
	ip       string
	username string
	time     time.Time
}

type SprayResult struct {
	Detected        bool
	UniqueIPs       int
	UniqueUsers     int
	UniquePasswords int
	TimeWindow      string
}

func NewPasswordSprayDetector() *PasswordSprayDetector {
	return &PasswordSprayDetector{windowStart: time.Now()}
}

func (ps *PasswordSprayDetector) RecordFailure(ip, username string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.attempts = append(ps.attempts, sprayAttempt{ip: ip, username: username, time: time.Now()})
	const maxSprayAttempts = 10000
	if len(ps.attempts) > maxSprayAttempts {
		copy(ps.attempts, ps.attempts[len(ps.attempts)-maxSprayAttempts:])
		clear(ps.attempts[maxSprayAttempts:])
		ps.attempts = ps.attempts[:maxSprayAttempts]
	}
}

func (ps *PasswordSprayDetector) Check() SprayResult {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	result := SprayResult{}
	now := time.Now()

	// Only look at last 10 minutes
	cutoff := now.Add(-10 * time.Minute)
	var recent []sprayAttempt
	for _, a := range ps.attempts {
		if a.time.After(cutoff) {
			recent = append(recent, a)
		}
	}
	ps.attempts = recent

	if len(recent) < 20 {
		return result
	}

	ips := make(map[string]bool)
	users := make(map[string]bool)
	ipUsers := make(map[string]map[string]bool)
	for _, a := range recent {
		ips[a.ip] = true
		users[a.username] = true
		if ipUsers[a.ip] == nil {
			ipUsers[a.ip] = make(map[string]bool)
		}
		ipUsers[a.ip][a.username] = true
	}

	result.UniqueIPs = len(ips)
	result.UniqueUsers = len(users)
	result.UniquePasswords = 1 // We can't see passwords, but spray = 1-2 passwords across many users
	result.TimeWindow = now.Sub(ps.windowStart).Round(time.Second).String()

	// Password spray pattern: many IPs, many users, low attempts per IP
	// Typical spray: 1-2 attempts per IP across 10+ users from 5+ IPs
	if len(ips) >= 5 && len(users) >= 10 {
		avgAttemptsPerIP := float64(len(recent)) / float64(len(ips))
		if avgAttemptsPerIP <= 3 {
			result.Detected = true
		}
	}

	// Also detect single-IP spray: one IP, many users, 1 attempt each
	for _, perIP := range ipUsers {
		if len(perIP) >= 20 {
			result.Detected = true
			result.UniqueUsers = len(perIP)
		}
	}

	return result
}

func (ps *PasswordSprayDetector) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ps.mu.Lock()
			cutoff := time.Now().Add(-15 * time.Minute)
			var kept []sprayAttempt
			for _, a := range ps.attempts {
				if a.time.After(cutoff) {
					kept = append(kept, a)
				}
			}
			ps.attempts = kept
			ps.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// AitMDetector — Adversary-in-the-Middle proxy detection
// ---------------------------------------------------------------------------

// AitMDetector identifies AitM/reverse-proxy phishing attacks that intercept
// session tokens in real-time. These attacks bypass MFA including passkeys by
// proxying the entire authentication flow.
// Ref: keepnetlabs.com AitM research 2025, Silverfort FIDO downgrade 2025
type AitMDetector struct {
	mu                   sync.Mutex
	passkeyRegistrations *lru.Cache[string, *passkeyRegRecord]
	// Known AitM proxy TLS fingerprints and indicators
	suspiciousFingerprints map[string]bool
}

type passkeyRegRecord struct {
	Users     map[string]bool
	FirstSeen time.Time
}

type AitMResult struct {
	Detected bool
	Reason   string
}

func NewAitMDetector() *AitMDetector {
	pCache, _ := lru.New[string, *passkeyRegRecord](50000)
	return &AitMDetector{
		passkeyRegistrations: pCache,
		suspiciousFingerprints: map[string]bool{
			// Known AitM toolkit fingerprints (Evilginx, Modlishka, Muraena, EvilnoVNC)
			"evilginx": true, "modlishka": true, "muraena": true,
			"evilnovnc": true, "caffeine": true, "greatness": true,
			"tycoon2fa": true, "dadsec": true, "storm-1575": true,
		},
	}
}

func (ad *AitMDetector) AnalyzeLogin(ip, username, userAgent, tlsFingerprint, proxyHeaders, loginLatency, authMethod string) AitMResult {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	result := AitMResult{}
	indicators := []string{}

	// Check for known AitM proxy TLS fingerprints
	if tlsFingerprint != "" && ad.suspiciousFingerprints[strings.ToLower(tlsFingerprint)] {
		indicators = append(indicators, "known AitM proxy TLS fingerprint: "+tlsFingerprint)
	}

	// Check for proxy header artifacts
	proxyLower := strings.ToLower(proxyHeaders)
	if strings.Contains(proxyLower, "x-forwarded-for") && strings.Contains(proxyLower, "x-real-ip") {
		indicators = append(indicators, "dual proxy headers (X-Forwarded-For + X-Real-IP)")
	}
	if strings.Contains(proxyLower, "via:") {
		indicators = append(indicators, "Via header present indicating proxy")
	}

	// Abnormal login latency (AitM proxies add measurable latency)
	if loginLatency != "" {
		latencyMs := 0
		fmt.Sscanf(loginLatency, "%d", &latencyMs)
		if latencyMs > 2000 {
			indicators = append(indicators, fmt.Sprintf("high login latency: %dms (AitM proxy overhead)", latencyMs))
		}
	}

	if len(indicators) >= 2 {
		result.Detected = true
		result.Reason = strings.Join(indicators, "; ")
	}

	return result
}

func (ad *AitMDetector) RecordPasskeyRegistration(ip, username string) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	rec, exists := ad.passkeyRegistrations.Get(ip)
	if !exists || time.Since(rec.FirstSeen) > time.Hour {
		rec = &passkeyRegRecord{Users: make(map[string]bool), FirstSeen: time.Now()}
		ad.passkeyRegistrations.Add(ip, rec)
	}
	rec.Users[username] = true
}

func (ad *AitMDetector) IsPasskeyRegistrationAnomaly(ip string) bool {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	rec, exists := ad.passkeyRegistrations.Get(ip)
	if !exists {
		return false
	}
	return len(rec.Users) >= 3
}

// ---------------------------------------------------------------------------
// Contextual Mitigations
// ---------------------------------------------------------------------------

func getAuthMitigations(alertType string) []string {
	switch alertType {
	case "saml_structure_violation":
		return []string{
			"Reject ambiguous SAML structures and validate against trusted local schemas",
			"Verify the exact Response or Assertion signature with the configured IdP key before using claims",
			"Validate issuer, audience, destination, request binding, expiry, and replay at the service provider",
		}
	case "brute_force":
		return []string{
			"Implement progressive account lockout with exponential backoff",
			"Deploy CAPTCHA after repeated failures",
			"Consider IP-based rate limiting at the WAF/load balancer level",
		}
	case "credential_stuffing":
		return []string{
			"Deploy credential breach detection (check passwords against known breach databases)",
			"Require MFA for all accounts, preferably passkeys/FIDO2",
			"Implement bot detection and device fingerprinting",
		}
	case "post_bruteforce_login":
		return []string{
			"Force password reset for the compromised account",
			"Review account activity for unauthorized changes",
			"Enable MFA if not already active",
		}
	case "session_hijack", "session_ua_change":
		return []string{
			"Implement session token binding to TLS channel (RFC 8471)",
			"Use short-lived session tokens with frequent rotation",
			"Bind sessions to device fingerprint and IP range",
		}
	case "impossible_travel":
		return []string{
			"Require step-up authentication for geographically anomalous access",
			"Implement risk-based authentication that considers location history",
			"Alert the user about access from an unexpected location",
		}
	case "mfa_bypass", "mfa_fatigue":
		return []string{
			"Migrate from push-based MFA to phishing-resistant methods (passkeys/FIDO2)",
			"Implement number matching for push notifications",
			"Rate-limit MFA push notifications per user",
		}
	case "consent_phishing", "oauth_token_abuse", "excessive_oauth_scopes":
		return []string{
			"Restrict OAuth app registrations to admin-approved apps only",
			"Implement OAuth scope review and approval workflows",
			"Monitor for apps requesting dangerous scope combinations",
		}
	case "stolen_token", "anomalous_token_activity":
		return []string{
			"Implement token binding to prevent replay from different IPs",
			"Use short-lived tokens with refresh token rotation",
			"Deploy token revocation on anomaly detection",
		}
	case "password_spray":
		return []string{
			"Implement smart lockout that locks the password, not the account",
			"Deploy IP reputation scoring for authentication endpoints",
			"Require passkeys/FIDO2 to eliminate password-based attacks entirely",
		}
	case "aitm_proxy_detected":
		return []string{
			"Deploy phishing-resistant authentication (passkeys/FIDO2 with origin binding)",
			"Implement TLS token binding (RFC 8471) to prevent session token theft",
			"Monitor for known AitM proxy TLS fingerprints at the network edge",
			"Enforce Conditional Access policies that block legacy auth protocols",
		}
	case "suspicious_passkey_registration":
		return []string{
			"Require identity verification before passkey registration",
			"Limit passkey registrations per IP per time window",
			"Send out-of-band notification to user on new passkey registration",
		}
	case "passkey_no_attestation":
		return []string{
			"Consider requiring hardware attestation for high-privilege accounts",
			"Log attestation level for audit and risk scoring purposes",
		}
	case "webauthn_origin_mismatch":
		return []string{
			"Reject WebAuthn ceremonies with origin mismatches immediately",
			"Implement strict origin validation in the relying party",
			"Alert security team — this is a strong indicator of active attack",
		}
	case "passkey_downgrade", "auth_method_downgrade":
		return []string{
			"Block authentication downgrades for accounts with passkeys enrolled",
			"If downgrade is necessary, require additional verification step",
			"Monitor for user-agent spoofing that triggers downgrade paths",
		}
	case "ptr_spoofing":
		return []string{
			"Validate PTR records against forward DNS (A/AAAA) before trusting hostname claims",
			"Do not use reverse DNS for authorization decisions without forward confirmation",
			"Implement allowlists for trusted hostnames in authentication policies",
		}
	default:
		return []string{
			"Review authentication logs for suspicious patterns",
			"Enforce multi-factor authentication",
			"Monitor for credential compromise indicators",
		}
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	return ""
}

func extractTokenIdentifier(event *core.SecurityEvent) string {
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
	if token := getStringDetail(event, "token"); token != "" {
		if jti := extractJWTJTI(token); jti != "" {
			return jti
		}
	}
	return ""
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

func getIntSetting(settings map[string]interface{}, key string, defaultVal int) int {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultVal
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371.0
	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c
}

func countryCentroid(code string) (lat, lon float64, ok bool) {
	centroids := map[string][2]float64{
		"US": {39.8, -98.5}, "CN": {35.9, 104.2}, "IN": {20.6, 78.9},
		"BR": {-14.2, -51.9}, "RU": {61.5, 105.3}, "JP": {36.2, 138.3},
		"DE": {51.2, 10.5}, "GB": {55.4, -3.4}, "FR": {46.2, 2.2},
		"KR": {35.9, 127.8}, "CA": {56.1, -106.3}, "IT": {41.9, 12.6},
		"AU": {-25.3, 133.8}, "ES": {40.5, -3.7}, "MX": {23.6, -102.6},
		"ID": {-0.8, 113.9}, "NL": {52.1, 5.3}, "TR": {39.0, 35.2},
		"SA": {23.9, 45.1}, "CH": {46.8, 8.2}, "PL": {51.9, 19.1},
		"SE": {60.1, 18.6}, "BE": {50.5, 4.5}, "TH": {15.9, 100.9},
		"AT": {47.5, 14.6}, "NO": {60.5, 8.5}, "IL": {31.0, 34.9},
		"NG": {9.1, 8.7}, "ZA": {-30.6, 22.9}, "AR": {-38.4, -63.6},
		"EG": {26.8, 30.8}, "PH": {12.9, 121.8}, "MY": {4.2, 101.9},
		"SG": {1.4, 103.8}, "AE": {23.4, 53.8}, "IE": {53.1, -8.2},
		"DK": {56.3, 9.5}, "FI": {61.9, 25.7}, "PT": {39.4, -8.2},
		"CZ": {49.8, 15.5}, "RO": {45.9, 25.0}, "NZ": {-40.9, 174.9},
		"CL": {-35.7, -71.5}, "CO": {4.6, -74.3}, "UA": {48.4, 31.2},
		"PK": {30.4, 69.3}, "VN": {14.1, 108.3}, "HK": {22.4, 114.1},
		"TW": {23.7, 121.0}, "BD": {23.7, 90.4}, "PE": {-9.2, -75.0},
	}
	if c, found := centroids[code]; found {
		return c[0], c[1], true
	}
	return 0, 0, false
}
