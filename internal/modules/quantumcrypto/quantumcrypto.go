package quantumcrypto

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "quantum_crypto"

// Monitor is the Quantum-Ready Crypto module providing cryptographic inventory scanning,
// PQC migration tooling, crypto-agility assessment, TLS configuration auditing,
// and harvest-now-decrypt-later (HNDL) traffic pattern detection.
type Monitor struct {
	logger     zerolog.Logger
	bus        *core.EventBus
	pipeline   *core.AlertPipeline
	cfg        *core.Config
	ctx        context.Context
	cancel     context.CancelFunc
	inventory  *CryptoInventory
	tlsAuditor *TLSAuditor
	hndlDet    *HNDLDetector
}

func New() *Monitor { return &Monitor{} }

func (m *Monitor) Name() string { return ModuleName }
func (m *Monitor) EventTypes() []string {
	return []string{
		"tls_handshake", "tls_connection", "ssl_connection",
		"crypto_usage", "encryption_operation", "key_generation",
		"certificate_event", "cert_expiry", "cert_issued",
		"crypto_scan", "crypto_inventory",
		"traffic_capture", "bulk_data_transfer", "bulk_transfer", "encrypted_exfiltration",
	}
}
func (m *Monitor) Description() string {
	return "Cryptographic inventory, post-quantum migration assessment, TLS configuration auditing, and capture telemetry risk indicators; does not migrate encryption or prove interception intent"
}

func (m *Monitor) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.bus = bus
	m.pipeline = pipeline
	m.cfg = cfg
	m.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	m.inventory = NewCryptoInventory()
	m.tlsAuditor = NewTLSAuditor()
	m.hndlDet = NewHNDLDetector()

	go m.hndlDet.CleanupLoop(m.ctx)

	m.logger.Info().Msg("quantum-ready crypto monitor started")
	return nil
}

func (m *Monitor) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

// HandleEvent routes events — fix #9: "bulk_transfer" now handled.
func (m *Monitor) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "tls_handshake", "tls_connection", "ssl_connection":
		m.handleTLSEvent(event)
	case "crypto_usage", "encryption_operation", "key_generation":
		m.handleCryptoUsage(event)
	case "certificate_event", "cert_expiry", "cert_issued":
		m.handleCertEvent(event)
	case "crypto_scan", "crypto_inventory":
		m.handleInventoryScan(event)
	case "traffic_capture", "bulk_data_transfer", "bulk_transfer", "encrypted_exfiltration":
		m.handleHNDLEvent(event)
	}
	return nil
}

func (m *Monitor) handleTLSEvent(event *core.SecurityEvent) {
	version := getStringDetail(event, "tls_version")
	cipherSuite := getStringDetail(event, "cipher_suite")
	keyExchange := getStringDetail(event, "key_exchange")
	serverName := getStringDetail(event, "server_name")

	findings := m.tlsAuditor.Audit(version, cipherSuite, keyExchange)

	for _, f := range findings {
		m.raiseAlert(event, f.Severity,
			f.Title,
			fmt.Sprintf("TLS connection to %s: %s (version: %s, cipher: %s, key exchange: %s)",
				serverName, f.Description, version, cipherSuite, keyExchange),
			f.AlertType,
			f.Mitigations)
	}

	// HNDL defense: flag TLS handshakes proposing only classical curves without PQ combinations.
	// Ref: "Harvest Now, Decrypt Later" — identifying infrastructure that is not crypto-agile.
	proposedCurves := getStringDetail(event, "supported_groups")
	if proposedCurves == "" {
		proposedCurves = getStringDetail(event, "proposed_curves")
	}
	if proposedCurves != "" {
		hasPQ, hasClassical := false, false
		for _, group := range strings.FieldsFunc(proposedCurves, func(r rune) bool {
			return r == ',' || r == ':' || r == ';' || r == ' ' || r == '[' || r == ']' || r == '"'
		}) {
			group = strings.ToLower(group)
			hasPQ = hasPQ || isPQKeyExchange(group)
			hasClassical = hasClassical || isClassicalKeyExchange(group)
		}
		if hasClassical && !hasPQ {
			m.raiseAlert(event, core.SeverityInfo,
				"TLS Handshake Without PQ Curves",
				fmt.Sprintf("TLS handshake to %s proposes only classical curves (%s) without any post-quantum "+
					"recognized hybrid groups. This describes offered capabilities, not the negotiated exchange. "+
					"Consider adding X25519MLKEM768 to supported groups.",
					serverName, proposedCurves),
				"no_pq_curves",
				[]string{
					"Add post-quantum hybrid curves (e.g., X25519MLKEM768) to the TLS supported_groups extension",
					"Classical-only TLS is vulnerable to future quantum decryption of captured traffic",
				})
		}
	}

	// Track crypto usage in inventory
	if cipherSuite != "" {
		m.inventory.RecordUsage("tls_cipher", cipherSuite, serverName)
	}
	if keyExchange != "" {
		m.inventory.RecordUsage("key_exchange", keyExchange, serverName)
	}
}

func (m *Monitor) handleCryptoUsage(event *core.SecurityEvent) {
	algorithm := getStringDetail(event, "algorithm")
	keySize := getIntDetail(event, "key_size")
	purpose := getStringDetail(event, "purpose")
	component := getStringDetail(event, "component")

	if algorithm == "" {
		return
	}

	m.inventory.RecordUsage(purpose, algorithm, component)

	// Check for quantum-vulnerable algorithms — fix #6: severity varies by purpose
	vuln := classifyQuantumVulnerability(algorithm, keySize, purpose)
	if vuln.Vulnerable {
		m.raiseAlert(event, vuln.Severity,
			"Quantum-Vulnerable Cryptography Detected",
			fmt.Sprintf("Component %s uses %s (%d-bit) for %s. %s",
				component, algorithm, keySize, purpose, vuln.Recommendation),
			"quantum_vulnerable_crypto",
			[]string{vuln.Recommendation})
	}

	// Check for weak key sizes
	if isWeakKeySize(algorithm, keySize) {
		m.raiseAlert(event, core.SeverityHigh,
			"Weak Cryptographic Key Size",
			fmt.Sprintf("Component %s uses %s with %d-bit key for %s. This is below recommended minimum.",
				component, algorithm, keySize, purpose),
			"weak_key_size",
			[]string{
				fmt.Sprintf("Increase %s key size to meet current minimum requirements", algorithm),
				"For RSA use at least 2048-bit, for ECC at least 256-bit, for AES at least 128-bit",
			})
	}
}

// handleCertEvent — fix #8: now also checks signature algorithm.
func (m *Monitor) handleCertEvent(event *core.SecurityEvent) {
	certDomain := getStringDetail(event, "domain")
	expiryDays := getIntDetail(event, "days_until_expiry")
	keyAlgo := getStringDetail(event, "key_algorithm")
	keySize := getIntDetail(event, "key_size")
	issuer := getStringDetail(event, "issuer")
	sigAlgo := getStringDetail(event, "signature_algorithm")

	if expiryDays > 0 && expiryDays <= 30 {
		severity := core.SeverityMedium
		if expiryDays <= 7 {
			severity = core.SeverityHigh
		}
		if expiryDays <= 1 {
			severity = core.SeverityCritical
		}
		m.raiseAlert(event, severity,
			"Certificate Expiring Soon",
			fmt.Sprintf("Certificate for %s expires in %d days (issuer: %s)", certDomain, expiryDays, issuer),
			"cert_expiry",
			[]string{
				fmt.Sprintf("Renew certificate for %s immediately", certDomain),
				"Consider automating certificate renewal with ACME/Let's Encrypt",
			})
	}

	if keyAlgo != "" {
		vuln := classifyQuantumVulnerability(keyAlgo, keySize, "certificate")
		if vuln.Vulnerable {
			m.raiseAlert(event, core.SeverityMedium,
				"Certificate Uses Quantum-Vulnerable Key Algorithm",
				fmt.Sprintf("Certificate for %s uses %s (%d-bit) key. %s", certDomain, keyAlgo, keySize, vuln.Recommendation),
				"cert_quantum_vulnerable",
				[]string{vuln.Recommendation})
		}
	}

	// Fix #8: check signature algorithm on the certificate
	if sigAlgo != "" {
		sigLower := strings.ToLower(sigAlgo)
		if strings.Contains(sigLower, "sha1") || strings.Contains(sigLower, "md5") {
			m.raiseAlert(event, core.SeverityHigh,
				"Certificate Uses Weak Signature Algorithm",
				fmt.Sprintf("Certificate for %s is signed with %s which is cryptographically broken.", certDomain, sigAlgo),
				"cert_weak_signature",
				[]string{
					"Reissue the certificate with SHA-256 or stronger signature algorithm",
					"SHA-1 and MD5 signatures are vulnerable to collision attacks",
				})
		}
		sigVuln := classifyQuantumVulnerability(sigAlgo, 0, "signature")
		if sigVuln.Vulnerable {
			m.raiseAlert(event, core.SeverityMedium,
				"Certificate Uses Quantum-Vulnerable Signature Algorithm",
				fmt.Sprintf("Certificate for %s is signed with %s. %s", certDomain, sigAlgo, sigVuln.Recommendation),
				"cert_sig_quantum_vulnerable",
				[]string{sigVuln.Recommendation})
		}
	}
}

func (m *Monitor) handleInventoryScan(event *core.SecurityEvent) {
	totalAlgorithms := getIntDetail(event, "total_algorithms")
	vulnerableCount := getIntDetail(event, "vulnerable_count")
	pqcReadyCount := getIntDetail(event, "pqc_ready_count")

	if vulnerableCount > 0 {
		severity := core.SeverityMedium
		if vulnerableCount > 10 {
			severity = core.SeverityHigh
		}
		pctVulnerable := 0.0
		if totalAlgorithms > 0 {
			pctVulnerable = float64(vulnerableCount) / float64(totalAlgorithms) * 100
		}
		m.raiseAlert(event, severity,
			"Quantum-Vulnerable Crypto Inventory Report",
			fmt.Sprintf("Crypto inventory scan: %d/%d algorithms (%.1f%%) are quantum-vulnerable. %d are PQC-ready. Begin migration planning.",
				vulnerableCount, totalAlgorithms, pctVulnerable, pqcReadyCount),
			"crypto_inventory_report",
			[]string{
				"Inventory all cryptographic algorithm usage across your infrastructure",
				"Prioritize migration of key exchange and long-term confidentiality to PQC algorithms",
				"Adopt NIST-approved post-quantum standards: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)",
				"Implement crypto-agility to enable algorithm swaps without code changes",
				"Consider hybrid PQ/classical key exchange (e.g., X25519MLKEM768) as a transition step",
			})
	}
}

// raiseAlert — fix #11: mitigations are now per-alert-type instead of hardcoded.
func (m *Monitor) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string, mitigations []string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if m.bus != nil {
		_ = m.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	if len(mitigations) > 0 {
		alert.Mitigations = mitigations
	} else {
		alert.Mitigations = []string{
			"Review and remediate the detected cryptographic issue",
			"Consult NIST PQC migration guidance for your use case",
		}
	}
	if m.pipeline != nil {
		m.pipeline.Process(alert)
	}
}

// ---------------------------------------------------------------------------
// CryptoInventory — fix #10: added Summary() for querying inventory state.
// ---------------------------------------------------------------------------

// CryptoInventory tracks all cryptographic algorithm usage.
type CryptoInventory struct {
	mu      sync.RWMutex
	entries map[string]*cryptoEntry
}

type cryptoEntry struct {
	Purpose    string
	Algorithm  string
	Components map[string]bool
	FirstSeen  time.Time
	LastSeen   time.Time
	UsageCount int
}

// InventorySummary is a snapshot of a single crypto inventory entry.
type InventorySummary struct {
	Purpose        string
	Algorithm      string
	Components     []string
	FirstSeen      time.Time
	LastSeen       time.Time
	UsageCount     int
	QuantumSafe    bool
	Assessment     string // recognized_pqc, symmetric, classical, unknown; not a security certification
	Recommendation string
}

func NewCryptoInventory() *CryptoInventory {
	return &CryptoInventory{entries: make(map[string]*cryptoEntry)}
}

func (ci *CryptoInventory) RecordUsage(purpose, algorithm, component string) {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	key := purpose + ":" + algorithm
	entry, exists := ci.entries[key]
	if !exists {
		entry = &cryptoEntry{
			Purpose:    purpose,
			Algorithm:  algorithm,
			Components: make(map[string]bool),
			FirstSeen:  time.Now(),
		}
		ci.entries[key] = entry
	}
	if component != "" {
		entry.Components[component] = true
	}
	entry.LastSeen = time.Now()
	entry.UsageCount++
}

// Summary returns a read-only snapshot of the entire inventory with quantum
// vulnerability classification for each entry.
func (ci *CryptoInventory) Summary() []InventorySummary {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	out := make([]InventorySummary, 0, len(ci.entries))
	for _, e := range ci.entries {
		comps := make([]string, 0, len(e.Components))
		for c := range e.Components {
			comps = append(comps, c)
		}
		vuln := classifyQuantumVulnerability(e.Algorithm, 0, e.Purpose)
		assessment := "unknown"
		if vuln.KnownPQ {
			assessment = "recognized_pqc"
		} else if vuln.Resistant {
			assessment = "symmetric"
		} else if vuln.Vulnerable {
			assessment = "classical"
		}
		out = append(out, InventorySummary{
			Purpose:        e.Purpose,
			Algorithm:      e.Algorithm,
			Components:     comps,
			FirstSeen:      e.FirstSeen,
			LastSeen:       e.LastSeen,
			UsageCount:     e.UsageCount,
			QuantumSafe:    vuln.KnownPQ || vuln.Resistant,
			Assessment:     assessment,
			Recommendation: vuln.Recommendation,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// TLSAuditor — fix #1: CBC separated at lower severity; fix #2: hybrid key
// exchange awareness; fix #4: TLS 1.2 flagged as legacy.
// ---------------------------------------------------------------------------

// TLSAuditor checks TLS configurations for security issues.
type TLSAuditor struct {
	insecureCiphers   *regexp.Regexp // truly broken: RC4, DES, NULL, EXPORT, anon, MD5
	deprecatedCiphers *regexp.Regexp // weaker but not broken: CBC mode
	weakVersions      map[string]bool
	legacyVersions    map[string]bool // TLS 1.2 — not weak but legacy
	weakKeyExchange   map[string]bool
}

type TLSFinding struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
	Mitigations []string
}

func NewTLSAuditor() *TLSAuditor {
	return &TLSAuditor{
		// Fix #1: truly insecure ciphers (high severity)
		insecureCiphers: regexp.MustCompile(`(?i)(RC4|DES\b|3DES|NULL|EXPORT|anon|MD5)`),
		// Fix #1: deprecated ciphers (medium severity) — CBC padding oracle risk
		deprecatedCiphers: regexp.MustCompile(`(?i)_CBC_`),
		weakVersions: map[string]bool{
			"SSLv2": true, "SSLv3": true, "TLSv1.0": true, "TLSv1.1": true,
			"ssl2": true, "ssl3": true, "tls1.0": true, "tls1.1": true,
		},
		// Fix #4: TLS 1.2 is legacy — not insecure but should migrate to 1.3
		legacyVersions: map[string]bool{
			"TLSv1.2": true, "tls1.2": true,
		},
		weakKeyExchange: map[string]bool{
			"RSA": true, "DHE-1024": true, "DH-1024": true,
		},
	}
}

func (ta *TLSAuditor) Audit(version, cipherSuite, keyExchange string) []TLSFinding {
	var findings []TLSFinding

	// Deprecated TLS versions (SSLv2, SSLv3, TLS 1.0, 1.1)
	if ta.weakVersions[version] {
		findings = append(findings, TLSFinding{
			Title:       "Deprecated TLS Version",
			Description: fmt.Sprintf("TLS version %s is deprecated and insecure", version),
			Severity:    core.SeverityHigh,
			AlertType:   "weak_tls_version",
			Mitigations: []string{
				"Upgrade to TLS 1.3 which provides stronger security and PQ hybrid key exchange support",
				fmt.Sprintf("Disable %s on all endpoints immediately", version),
			},
		})
	}

	// Fix #4: TLS 1.2 flagged as legacy
	if ta.legacyVersions[version] {
		findings = append(findings, TLSFinding{
			Title:       "Legacy TLS Version",
			Description: fmt.Sprintf("TLS version %s is functional but lacks post-quantum hybrid key exchange support", version),
			Severity:    core.SeverityLow,
			AlertType:   "legacy_tls_version",
			Mitigations: []string{
				"Migrate to TLS 1.3 to enable post-quantum hybrid key exchange (e.g., X25519MLKEM768)",
				"TLS 1.2 cannot negotiate PQ-safe key exchange, leaving traffic vulnerable to harvest-now-decrypt-later",
			},
		})
	}

	// Fix #1: separate insecure ciphers (high) from deprecated CBC (medium)
	if cipherSuite != "" {
		if ta.insecureCiphers.MatchString(cipherSuite) {
			findings = append(findings, TLSFinding{
				Title:       "Insecure Cipher Suite",
				Description: fmt.Sprintf("Cipher suite %s uses broken cryptographic algorithms", cipherSuite),
				Severity:    core.SeverityHigh,
				AlertType:   "weak_cipher",
				Mitigations: []string{
					"Remove this cipher suite from your TLS configuration immediately",
					"Use only AEAD cipher suites: AES-GCM or ChaCha20-Poly1305",
				},
			})
		} else if ta.deprecatedCiphers.MatchString(cipherSuite) {
			findings = append(findings, TLSFinding{
				Title:       "Deprecated Cipher Mode (CBC)",
				Description: fmt.Sprintf("Cipher suite %s uses CBC mode which is vulnerable to padding oracle attacks", cipherSuite),
				Severity:    core.SeverityMedium,
				AlertType:   "deprecated_cipher_cbc",
				Mitigations: []string{
					"Replace CBC cipher suites with AEAD alternatives (AES-GCM, ChaCha20-Poly1305)",
					"CBC mode in TLS is susceptible to Lucky13 and similar padding oracle attacks",
				},
			})
		}
	}

	// Weak key exchange
	if ta.weakKeyExchange[keyExchange] {
		findings = append(findings, TLSFinding{
			Title:       "Weak Key Exchange",
			Description: fmt.Sprintf("Key exchange %s is vulnerable to quantum attacks and lacks forward secrecy", keyExchange),
			Severity:    core.SeverityMedium,
			AlertType:   "weak_key_exchange",
			Mitigations: []string{
				"Use ephemeral key exchange with forward secrecy (ECDHE)",
				"For quantum resistance, adopt hybrid PQ key exchange such as X25519MLKEM768",
			},
		})
	}

	// Fix #2: recommend hybrid PQ key exchange when not already using one
	if isClassicalKeyExchange(keyExchange) && !ta.weakKeyExchange[keyExchange] {
		// Using a classical ephemeral exchange (e.g., X25519, ECDHE) — good but not PQ-safe
		findings = append(findings, TLSFinding{
			Title:       "No Post-Quantum Key Exchange",
			Description: fmt.Sprintf("Key exchange %s provides forward secrecy but is not quantum-resistant", keyExchange),
			Severity:    core.SeverityLow,
			AlertType:   "no_pq_key_exchange",
			Mitigations: []string{
				"Upgrade to a hybrid PQ/classical key exchange such as X25519MLKEM768",
				"Hybrid key exchange protects against harvest-now-decrypt-later while maintaining classical security",
			},
		})
	}
	if keyExchange != "" && !isClassicalKeyExchange(keyExchange) && !isPQKeyExchange(keyExchange) {
		findings = append(findings, TLSFinding{
			Title:       "Unrecognized Key Exchange",
			Description: fmt.Sprintf("Key exchange %s is not in the recognized algorithm set; quantum resistance has not been assessed", keyExchange),
			Severity:    core.SeverityInfo,
			AlertType:   "unknown_key_exchange",
			Mitigations: []string{"Report the exact negotiated group name and review its specification and implementation"},
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Quantum vulnerability classification — fix #3: accurate PQC safe list;
// fix #5: exact matching instead of substring; fix #6: purpose-aware severity.
// ---------------------------------------------------------------------------

type quantumVuln struct {
	Vulnerable     bool
	KnownPQ        bool
	Resistant      bool
	Severity       core.Severity
	Recommendation string
}

// classifyQuantumVulnerability determines if an algorithm is quantum-vulnerable.
// Fix #5: uses exact match on normalized names instead of substring Contains.
// Fix #6: severity varies by purpose (key exchange/encryption > signatures on ephemeral data).
func classifyQuantumVulnerability(algorithm string, keySize int, purpose string) quantumVuln {
	algoLower := strings.ToLower(strings.TrimSpace(algorithm))

	// Fix #3: accurate PQC-safe algorithms — only NIST-finalized standards (FIPS 203/204/205).
	// Falcon (FN-DSA / FIPS 206) is NOT yet finalized (expected late 2026/early 2027).
	// BIKE was not selected. HQC was selected March 2025 but draft not expected until 2026.
	pqcSafe := map[string]bool{
		// FIPS 203 — ML-KEM (key encapsulation)
		"ml-kem": true, "ml-kem-512": true, "ml-kem-768": true, "ml-kem-1024": true,
		// FIPS 204 — ML-DSA (digital signatures)
		"ml-dsa": true, "ml-dsa-44": true, "ml-dsa-65": true, "ml-dsa-87": true,
		// FIPS 205 — SLH-DSA (stateless hash-based signatures)
		"slh-dsa":            true,
		"slh-dsa-shake-128s": true, "slh-dsa-shake-128f": true,
		"slh-dsa-shake-192s": true, "slh-dsa-shake-192f": true,
		"slh-dsa-shake-256s": true, "slh-dsa-shake-256f": true,
		"slh-dsa-sha2-128s": true, "slh-dsa-sha2-128f": true,
		"slh-dsa-sha2-192s": true, "slh-dsa-sha2-192f": true,
		"slh-dsa-sha2-256s": true, "slh-dsa-sha2-256f": true,
		// Hybrid PQ/classical schemes
		"x25519mlkem768": true, "secp256r1mlkem768": true,
	}

	// Algorithms not yet finalized — recognized but flagged as draft
	pqcDraft := map[string]bool{
		"falcon": true, "fn-dsa": true, // FIPS 206 — expected late 2026/early 2027
		"hqc":  true, // Selected March 2025, draft expected 2026
		"bike": true, // Round 4 candidate, NOT selected for standardization
	}

	if pqcSafe[algoLower] {
		return quantumVuln{KnownPQ: true}
	}

	if pqcDraft[algoLower] {
		return quantumVuln{Recommendation: "Review the exact algorithm revision and parameter set; this name is not in the recognized finalized PQC set."}
	}

	// Fix #5: exact match on normalized algorithm names for quantum-broken detection.
	// We normalize by extracting the base algorithm name.
	quantumBroken := map[string]bool{
		"rsa": true, "ecdsa": true, "ecdh": true, "ecdhe": true,
		"dsa": true, "dh": true, "dhe": true, "elgamal": true,
		"ed25519": true, "ed448": true, "x25519": true, "x448": true,
		"secp256r1": true, "secp384r1": true, "secp521r1": true,
		"p-256": true, "p-384": true, "p-521": true,
	}

	// Try exact match first
	if quantumBroken[algoLower] {
		sev := quantumSeverityForPurpose(purpose)
		return quantumVuln{
			Vulnerable:     true,
			Severity:       sev,
			Recommendation: fmt.Sprintf("Migrate from %s to a NIST-approved PQC algorithm (ML-KEM for key exchange, ML-DSA for signatures).", algorithm),
		}
	}

	// For compound names like "ECDHE-RSA-AES128-GCM-SHA256", check each component.
	// Split on common delimiters: hyphen, underscore, plus, slash, space.
	parts := splitAlgorithmName(algoLower)
	for _, part := range parts {
		if quantumBroken[part] {
			sev := quantumSeverityForPurpose(purpose)
			return quantumVuln{
				Vulnerable:     true,
				Severity:       sev,
				Recommendation: fmt.Sprintf("Migrate from %s to a NIST-approved PQC algorithm (ML-KEM for key exchange, ML-DSA for signatures).", algorithm),
			}
		}
	}

	// NIST does not classify AES-128 as broken by practical Grover attacks.
	// Recognize complete symmetric names; a TLS 1.3 suite alone says nothing
	// about the connection's negotiated key establishment.
	symmetricSize := map[string]int{
		"aes-128": 128, "aes-128-gcm": 128, "aes-128-cbc": 128,
		"aes-192": 192, "aes-192-gcm": 192, "aes-192-cbc": 192,
		"aes-256": 256, "aes-256-gcm": 256, "aes-256-cbc": 256,
		"chacha20": 256, "chacha20-poly1305": 256,
	}
	if size := symmetricSize[algoLower]; size > 0 && (keySize == 0 || keySize == size) {
		return quantumVuln{Resistant: true}
	}
	if (algoLower == "aes" || algoLower == "aes-gcm" || algoLower == "aes-cbc") &&
		(keySize == 128 || keySize == 192 || keySize == 256) {
		return quantumVuln{Resistant: true}
	}

	return quantumVuln{Vulnerable: false}
}

// splitAlgorithmName breaks a compound algorithm string into its component parts.
func splitAlgorithmName(algo string) []string {
	// Replace common delimiters with a single separator
	r := strings.NewReplacer("_", " ", "-", " ", "+", " ", "/", " ", "with", " ")
	normalized := r.Replace(algo)
	parts := strings.Fields(normalized)
	return parts
}

// quantumSeverityForPurpose returns higher severity for key exchange and
// long-term confidentiality (directly exploitable by HNDL) vs lower severity
// for ephemeral signatures.
func quantumSeverityForPurpose(purpose string) core.Severity {
	p := strings.ToLower(purpose)
	switch {
	case strings.Contains(p, "key_exchange"), strings.Contains(p, "key exchange"),
		strings.Contains(p, "encryption"), strings.Contains(p, "confidentiality"),
		strings.Contains(p, "kem"), strings.Contains(p, "wrap"):
		return core.SeverityHigh
	case strings.Contains(p, "certificate"), strings.Contains(p, "signing"),
		strings.Contains(p, "signature"):
		return core.SeverityMedium
	default:
		return core.SeverityMedium
	}
}

func isWeakKeySize(algorithm string, keySize int) bool {
	if keySize <= 0 {
		return false
	}
	algoLower := strings.ToLower(algorithm)
	if strings.Contains(algoLower, "rsa") && keySize < 2048 {
		return true
	}
	if (strings.Contains(algoLower, "ec") || strings.Contains(algoLower, "ed")) && keySize < 256 {
		return true
	}
	if strings.Contains(algoLower, "aes") && keySize < 128 {
		return true
	}
	return false
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

// handleHNDLEvent detects harvest-now-decrypt-later patterns: bulk encrypted
// traffic capture targeting quantum-vulnerable encryption.
func (m *Monitor) handleHNDLEvent(event *core.SecurityEvent) {
	sourceIP := event.SourceIP
	destIP := event.DestIP
	bytesTransferred := getIntDetail(event, "bytes_transferred")
	protocol := getStringDetail(event, "protocol")
	cipherSuite := getStringDetail(event, "cipher_suite")
	keyExchange := getStringDetail(event, "key_exchange")
	captureType := getStringDetail(event, "capture_type")

	result := m.hndlDet.Analyze(sourceIP, destIP, bytesTransferred, protocol, cipherSuite, keyExchange, captureType)

	if result.HNDLSuspected {
		m.raiseAlert(event, core.SeverityHigh,
			"Harvest-Now-Decrypt-Later Attack Suspected",
			fmt.Sprintf("Bulk encrypted traffic capture detected from %s to %s. "+
				"Volume: %s in %s. Cipher: %s (key exchange: %s). "+
				"Reported capture includes classical key establishment at scale. "+
				"This is an investigation signal; telemetry cannot establish authorization, adversary intent, or future decryption. "+
				"Indicators: %s.",
				sourceIP, destIP, result.VolumeStr, result.TimeWindow,
				cipherSuite, keyExchange, strings.Join(result.Indicators, ", ")),
			"hndl_attack",
			[]string{
				"Immediately investigate the source of bulk traffic capture",
				"Migrate affected connections to PQ hybrid key exchange (X25519MLKEM768)",
				"Enable TLS 1.3 with post-quantum key exchange to protect against future decryption",
				"Review network for unauthorized taps, mirrors, or SPAN ports",
				"Classify captured data by sensitivity and retention requirements",
			})
	}

	if result.BulkCapture {
		m.raiseAlert(event, core.SeverityHigh,
			"Bulk Encrypted Traffic Capture Detected",
			fmt.Sprintf("Unusual bulk traffic capture from %s: %s transferred in %s. "+
				"Capture type: %s. This may indicate passive interception for future decryption.",
				sourceIP, result.VolumeStr, result.TimeWindow, captureType),
			"bulk_traffic_capture",
			[]string{
				"Investigate the source and purpose of bulk traffic capture",
				"Verify all network capture points are authorized",
				"Ensure captured traffic uses quantum-resistant encryption",
			})
	}
}

// ---------------------------------------------------------------------------
// HNDLDetector — fix #7: extended window from 1h to 24h, cleanup from 2h to 72h.
// ---------------------------------------------------------------------------

type HNDLDetector struct {
	mu       sync.Mutex
	captures map[string]*hndlProfile // key: sourceIP
}

type hndlProfile struct {
	destinations          map[string]int64 // destIP -> bytes
	totalBytes            int64
	classicalCaptureBytes int64
	eventCount            int
	windowStart           time.Time
	lastSeen              time.Time
}

type HNDLResult struct {
	HNDLSuspected bool
	BulkCapture   bool
	VolumeStr     string
	TimeWindow    string
	Indicators    []string
}

func NewHNDLDetector() *HNDLDetector {
	return &HNDLDetector{captures: make(map[string]*hndlProfile)}
}

func (h *HNDLDetector) Analyze(sourceIP, destIP string, bytes int, protocol, cipher, keyExchange, captureType string) HNDLResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	result := HNDLResult{}
	if sourceIP == "" || bytes <= 0 || !isPassiveCapture(captureType) {
		return result
	}
	now := time.Now()

	profile, exists := h.captures[sourceIP]
	// Fix #7: extended aggregation window from 1 hour to 24 hours
	if !exists || now.Sub(profile.windowStart) > 24*time.Hour {
		profile = &hndlProfile{
			destinations: make(map[string]int64),
			windowStart:  now,
		}
		h.captures[sourceIP] = profile
	}

	profile.lastSeen = now
	profile.totalBytes += int64(bytes)
	// Count classical capture bytes from the same observation. TLS 1.3 cipher
	// suites do not identify key establishment (RFC 8446 section 4.1.2).
	classical := isClassicalKeyExchange(keyExchange)
	if keyExchange == "" {
		for _, part := range splitAlgorithmName(strings.ToLower(cipher)) {
			if part == "rsa" || part == "ecdhe" || part == "ecdh" || part == "dhe" || part == "dh" {
				classical = true
			}
		}
	}
	if classical {
		profile.classicalCaptureBytes += int64(bytes)
	}
	profile.eventCount++
	if destIP != "" {
		profile.destinations[destIP] += int64(bytes)
	}

	result.VolumeStr = formatBytes(profile.totalBytes)
	result.TimeWindow = now.Sub(profile.windowStart).Round(time.Second).String()

	var indicators []string

	// High volume capture
	if profile.totalBytes > 1<<30 { // > 1 GB
		indicators = append(indicators, fmt.Sprintf("high volume (%s)", formatBytes(profile.totalBytes)))
	}

	// Many destinations (broad interception)
	if len(profile.destinations) > 20 {
		indicators = append(indicators, fmt.Sprintf("broad targeting (%d destinations)", len(profile.destinations)))
	}

	// Quantum-vulnerable ciphers being captured
	if profile.classicalCaptureBytes > 0 {
		indicators = append(indicators, fmt.Sprintf("reported classical key-establishment capture (%s)", formatBytes(profile.classicalCaptureBytes)))
	}

	indicators = append(indicators, "passive network capture reported")

	// This is a capture-risk signal, not proof of an attacker's intent.
	if profile.classicalCaptureBytes > 100<<20 { // > 100 MB of matching capture evidence
		result.HNDLSuspected = true
	}
	result.Indicators = indicators

	// Bulk capture: any large-scale capture
	if profile.totalBytes > 500<<20 && profile.eventCount > 100 { // > 500 MB, 100+ events
		result.BulkCapture = true
	}

	return result
}

func isPassiveCapture(captureType string) bool {
	switch strings.ToLower(strings.TrimSpace(captureType)) {
	case "mirror", "tap", "pcap", "span":
		return true
	}
	return false
}

func isPQKeyExchange(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024", "ml-kem-512", "ml-kem-768", "ml-kem-1024":
		return true
	}
	return false
}

func isClassicalKeyExchange(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "rsa", "ecdh", "ecdhe", "dh", "dhe", "dhe-1024", "dh-1024", "x25519", "x448",
		"secp256r1", "secp384r1", "secp521r1", "p-256", "p-384", "p-521":
		return true
	}
	return false
}

// CleanupLoop — fix #7: extended cleanup cutoff from 2 hours to 72 hours.
func (h *HNDLDetector) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.mu.Lock()
			cutoff := time.Now().Add(-72 * time.Hour)
			for ip, p := range h.captures {
				if p.lastSeen.Before(cutoff) {
					delete(h.captures, ip)
				}
			}
			h.mu.Unlock()
		}
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
