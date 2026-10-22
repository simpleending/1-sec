package quantumcrypto

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

type capturingPipeline struct {
	pipeline *core.AlertPipeline
	mu       sync.Mutex
	alerts   []*core.Alert
}

func makeCapturingPipeline() *capturingPipeline {
	cp := &capturingPipeline{}
	cp.pipeline = core.NewAlertPipeline(zerolog.Nop(), 10000)
	cp.pipeline.AddHandler(func(a *core.Alert) {
		cp.mu.Lock()
		cp.alerts = append(cp.alerts, a)
		cp.mu.Unlock()
	})
	return cp
}

func (cp *capturingPipeline) count() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.alerts)
}

func (cp *capturingPipeline) alertTitles() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	titles := make([]string, len(cp.alerts))
	for i, a := range cp.alerts {
		titles[i] = a.Title
	}
	return titles
}

func (cp *capturingPipeline) hasTitle(title string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, a := range cp.alerts {
		if a.Title == title {
			return true
		}
	}
	return false
}

func (cp *capturingPipeline) hasAlertType(alertType string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, a := range cp.alerts {
		if a.Type == alertType {
			return true
		}
	}
	return false
}

func startedModule(t *testing.T) *Monitor {
	t.Helper()
	m := New()
	cfg := core.DefaultConfig()
	if err := m.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Monitor.Start() error: %v", err)
	}
	return m
}

func startedModuleWithPipeline(t *testing.T, cp *capturingPipeline) *Monitor {
	t.Helper()
	m := New()
	cfg := core.DefaultConfig()
	if err := m.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Monitor.Start() error: %v", err)
	}
	return m
}

// ─── Module Interface ─────────────────────────────────────────────────────────

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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx, nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if m.inventory == nil {
		t.Error("inventory should be initialized")
	}
	if m.tlsAuditor == nil {
		t.Error("tlsAuditor should be initialized")
	}
	if m.hndlDet == nil {
		t.Error("hndlDet should be initialized")
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

// ─── TLSAuditor ───────────────────────────────────────────────────────────────

func TestTLSAuditor_WeakVersions(t *testing.T) {
	ta := NewTLSAuditor()
	weakVersions := []string{"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "ssl2", "ssl3", "tls1.0", "tls1.1"}
	for _, v := range weakVersions {
		findings := ta.Audit(v, "", "")
		found := false
		for _, f := range findings {
			if f.AlertType == "weak_tls_version" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected weak_tls_version for %q", v)
		}
	}
}

func TestTLSAuditor_StrongVersions(t *testing.T) {
	ta := NewTLSAuditor()
	strongVersions := []string{"TLSv1.3"}
	for _, v := range strongVersions {
		findings := ta.Audit(v, "", "")
		for _, f := range findings {
			if f.AlertType == "weak_tls_version" {
				t.Errorf("TLS %s should not be flagged as weak", v)
			}
		}
	}
}

// Fix #4: TLS 1.2 flagged as legacy (not weak)
func TestTLSAuditor_LegacyTLS12(t *testing.T) {
	ta := NewTLSAuditor()
	findings := ta.Audit("TLSv1.2", "", "")
	foundLegacy := false
	for _, f := range findings {
		if f.AlertType == "legacy_tls_version" {
			foundLegacy = true
			if f.Severity != core.SeverityLow {
				t.Errorf("legacy TLS 1.2 severity = %v, want Low", f.Severity)
			}
		}
		if f.AlertType == "weak_tls_version" {
			t.Error("TLS 1.2 should not be flagged as weak_tls_version")
		}
	}
	if !foundLegacy {
		t.Error("expected legacy_tls_version finding for TLSv1.2")
	}
}

// Fix #1: insecure ciphers (high severity)
func TestTLSAuditor_InsecureCiphers(t *testing.T) {
	ta := NewTLSAuditor()
	insecure := []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_NULL_SHA",
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		"TLS_DH_anon_WITH_AES_128_CBC_SHA",
	}
	for _, c := range insecure {
		findings := ta.Audit("TLSv1.2", c, "")
		found := false
		for _, f := range findings {
			if f.AlertType == "weak_cipher" {
				found = true
				if f.Severity != core.SeverityHigh {
					t.Errorf("insecure cipher %q severity = %v, want High", c, f.Severity)
				}
				break
			}
		}
		if !found {
			t.Errorf("expected weak_cipher for %q", c)
		}
	}
}

// Fix #1: CBC-only ciphers get medium severity, not high
func TestTLSAuditor_DeprecatedCBC(t *testing.T) {
	ta := NewTLSAuditor()
	// A cipher that uses CBC but not RC4/DES/NULL/EXPORT/anon/MD5
	findings := ta.Audit("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE")
	foundCBC := false
	for _, f := range findings {
		if f.AlertType == "deprecated_cipher_cbc" {
			foundCBC = true
			if f.Severity != core.SeverityMedium {
				t.Errorf("CBC cipher severity = %v, want Medium", f.Severity)
			}
		}
		if f.AlertType == "weak_cipher" {
			t.Error("pure CBC cipher should not be flagged as weak_cipher (insecure)")
		}
	}
	if !foundCBC {
		t.Error("expected deprecated_cipher_cbc for CBC-only cipher suite")
	}
}

func TestTLSAuditor_StrongCipher(t *testing.T) {
	ta := NewTLSAuditor()
	findings := ta.Audit("TLSv1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768")
	for _, f := range findings {
		if f.AlertType == "weak_cipher" || f.AlertType == "deprecated_cipher_cbc" {
			t.Error("TLS_AES_256_GCM_SHA384 should not be flagged")
		}
	}
}

func TestTLSAuditor_WeakKeyExchange(t *testing.T) {
	ta := NewTLSAuditor()
	weakKE := []string{"RSA", "DHE-1024", "DH-1024"}
	for _, ke := range weakKE {
		findings := ta.Audit("TLSv1.2", "TLS_AES_128_GCM_SHA256", ke)
		found := false
		for _, f := range findings {
			if f.AlertType == "weak_key_exchange" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected weak_key_exchange for %q", ke)
		}
	}
}

// Fix #2: hybrid PQ key exchange recognized — no "no_pq_key_exchange" finding
func TestTLSAuditor_HybridPQKeyExchange(t *testing.T) {
	ta := NewTLSAuditor()
	hybrids := []string{"X25519MLKEM768", "x25519mlkem768", "SecP256r1MLKEM768", "X25519Kyber768"}
	for _, ke := range hybrids {
		findings := ta.Audit("TLSv1.3", "TLS_AES_256_GCM_SHA384", ke)
		for _, f := range findings {
			if f.AlertType == "no_pq_key_exchange" || f.AlertType == "weak_key_exchange" {
				t.Errorf("hybrid PQ key exchange %q should not be flagged, got %s", ke, f.AlertType)
			}
		}
	}
}

// Fix #2: classical ephemeral key exchange gets low-severity PQ recommendation
func TestTLSAuditor_ClassicalEphemeralKeyExchange(t *testing.T) {
	ta := NewTLSAuditor()
	findings := ta.Audit("TLSv1.3", "TLS_AES_256_GCM_SHA384", "X25519")
	found := false
	for _, f := range findings {
		if f.AlertType == "no_pq_key_exchange" {
			found = true
			if f.Severity != core.SeverityLow {
				t.Errorf("no_pq_key_exchange severity = %v, want Low", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected no_pq_key_exchange for classical X25519")
	}
}

// ─── classifyQuantumVulnerability ─────────────────────────────────────────────

func TestClassifyQuantumVulnerability_Broken(t *testing.T) {
	broken := []string{"RSA", "ECDSA", "ECDH", "ECDHE", "DSA", "DH", "Ed25519", "X25519"}
	for _, algo := range broken {
		v := classifyQuantumVulnerability(algo, 2048, "encryption")
		if !v.Vulnerable {
			t.Errorf("expected %s to be quantum-vulnerable", algo)
		}
		if v.Recommendation == "" {
			t.Errorf("expected recommendation for %s", algo)
		}
	}
}

// Fix #3: finalized NIST PQC algorithms are safe
func TestClassifyQuantumVulnerability_PQCSafe(t *testing.T) {
	safe := []string{
		"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
		"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
		"SLH-DSA", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHA2-256s",
		"Kyber", "Dilithium", "SPHINCS+",
		"X25519MLKEM768",
	}
	for _, algo := range safe {
		v := classifyQuantumVulnerability(algo, 0, "")
		if v.Vulnerable {
			t.Errorf("%s should not be quantum-vulnerable", algo)
		}
	}
}

// Fix #3: draft/non-finalized algorithms recognized but not flagged
func TestClassifyQuantumVulnerability_DraftAlgorithms(t *testing.T) {
	draft := []string{"Falcon", "FN-DSA", "HQC", "BIKE"}
	for _, algo := range draft {
		v := classifyQuantumVulnerability(algo, 0, "")
		if v.Vulnerable {
			t.Errorf("draft algorithm %s should not be flagged as vulnerable", algo)
		}
	}
}

func TestClassifyQuantumVulnerability_AES128(t *testing.T) {
	v := classifyQuantumVulnerability("AES", 128, "encryption")
	if v.Vulnerable || !v.Resistant {
		t.Error("AES-128 must not be labeled broken by a theoretical Grover speedup; see NIST PQC FAQ")
	}
}

func TestClassifyQuantumVulnerability_SymmetricStrong(t *testing.T) {
	v := classifyQuantumVulnerability("AES", 256, "encryption")
	if v.Vulnerable {
		t.Error("AES-256 should be quantum-safe")
	}
}

func TestClassifyQuantumVulnerability_Unknown(t *testing.T) {
	v := classifyQuantumVulnerability("UnknownAlgo", 256, "")
	if v.Vulnerable {
		t.Error("unknown algorithm should not be flagged as vulnerable")
	}
}

// Fix #5: compound algorithm names are parsed correctly
func TestClassifyQuantumVulnerability_CompoundName(t *testing.T) {
	v := classifyQuantumVulnerability("ECDHE-RSA-AES128-GCM-SHA256", 0, "key_exchange")
	if !v.Vulnerable {
		t.Error("ECDHE-RSA-AES128-GCM-SHA256 should be quantum-vulnerable (contains RSA and ECDHE)")
	}
}

// Fix #5: no false positives on names that merely contain substrings
func TestClassifyQuantumVulnerability_NoFalsePositive(t *testing.T) {
	// "SLDH" should not match "dh" because we split on delimiters
	v := classifyQuantumVulnerability("SLDH-CUSTOM", 256, "")
	// "sldh" is not in the broken map, "custom" is not either
	// This should NOT be vulnerable (no exact match for "dh" as a standalone part)
	if v.Vulnerable {
		t.Error("SLDH-CUSTOM should not be flagged as quantum-vulnerable")
	}
}

// Fix #6: key exchange gets higher severity than signatures
func TestClassifyQuantumVulnerability_PurposeSeverity(t *testing.T) {
	vKE := classifyQuantumVulnerability("RSA", 2048, "key_exchange")
	vSig := classifyQuantumVulnerability("RSA", 2048, "signature")

	if vKE.Severity != core.SeverityHigh {
		t.Errorf("key_exchange severity = %v, want High", vKE.Severity)
	}
	if vSig.Severity != core.SeverityMedium {
		t.Errorf("signature severity = %v, want Medium", vSig.Severity)
	}
}

// ─── isWeakKeySize ────────────────────────────────────────────────────────────

func TestIsWeakKeySize(t *testing.T) {
	tests := []struct {
		algo    string
		keySize int
		want    bool
	}{
		{"RSA", 1024, true},
		{"RSA", 2048, false},
		{"RSA", 4096, false},
		{"ECDSA", 128, true},
		{"ECDSA", 256, false},
		{"AES", 64, true},
		{"AES", 128, false},
		{"AES", 256, false},
		{"RSA", 0, false},  // zero key size = not weak
		{"RSA", -1, false}, // negative = not weak
	}
	for _, tc := range tests {
		got := isWeakKeySize(tc.algo, tc.keySize)
		if got != tc.want {
			t.Errorf("isWeakKeySize(%q, %d) = %v, want %v", tc.algo, tc.keySize, got, tc.want)
		}
	}
}

// ─── CryptoInventory ──────────────────────────────────────────────────────────

func TestCryptoInventory_RecordUsage(t *testing.T) {
	ci := NewCryptoInventory()
	ci.RecordUsage("encryption", "AES-256-GCM", "api-server")
	ci.RecordUsage("encryption", "AES-256-GCM", "api-server")
	ci.RecordUsage("encryption", "AES-256-GCM", "web-server")

	ci.mu.RLock()
	defer ci.mu.RUnlock()

	entry, ok := ci.entries["encryption:AES-256-GCM"]
	if !ok {
		t.Fatal("expected entry for encryption:AES-256-GCM")
	}
	if entry.UsageCount != 3 {
		t.Errorf("UsageCount = %d, want 3", entry.UsageCount)
	}
	if len(entry.Components) != 2 {
		t.Errorf("Components count = %d, want 2", len(entry.Components))
	}
}

// Fix #10: inventory Summary() returns queryable snapshots
func TestCryptoInventory_Summary(t *testing.T) {
	ci := NewCryptoInventory()
	ci.RecordUsage("encryption", "AES-256-GCM", "api-server")
	ci.RecordUsage("key_exchange", "RSA", "auth-service")
	ci.RecordUsage("key_exchange", "ML-KEM-768", "pq-service")

	summary := ci.Summary()
	if len(summary) != 3 {
		t.Fatalf("Summary() returned %d entries, want 3", len(summary))
	}

	// Check that quantum safety is classified correctly
	for _, s := range summary {
		switch s.Algorithm {
		case "AES-256-GCM":
			if !s.QuantumSafe {
				t.Error("AES-256-GCM should be quantum-safe in summary")
			}
		case "RSA":
			if s.QuantumSafe {
				t.Error("RSA should not be quantum-safe in summary")
			}
			if s.Recommendation == "" {
				t.Error("RSA should have a recommendation in summary")
			}
		case "ML-KEM-768":
			if !s.QuantumSafe {
				t.Error("ML-KEM-768 should be quantum-safe in summary")
			}
		}
	}
}

// ─── HNDLDetector ─────────────────────────────────────────────────────────────

func TestHNDLDetector_BulkCapture(t *testing.T) {
	h := NewHNDLDetector()
	var result HNDLResult
	// Send 150 events with 5MB each = 750MB total
	for i := 0; i < 150; i++ {
		result = h.Analyze("10.0.0.1", "10.0.0.2", 5*1024*1024, "tls", "RSA_AES_128", "RSA", "mirror")
	}
	if !result.BulkCapture {
		t.Error("expected BulkCapture for >500MB and 100+ events")
	}
}

func TestHNDLDetector_HNDLSuspected(t *testing.T) {
	h := NewHNDLDetector()
	var result HNDLResult
	// Send traffic to many destinations with quantum-vulnerable ciphers
	for i := 0; i < 50; i++ {
		dest := "10.0.0." + string(rune('1'+i%26))
		result = h.Analyze("10.0.0.1", dest, 10*1024*1024, "tls", "ECDHE_RSA_AES_128", "ECDHE", "tap")
	}
	if !result.HNDLSuspected {
		t.Error("expected HNDLSuspected for high volume + quantum-vulnerable + broad targeting")
	}
}

func TestHNDLDetector_SmallTraffic(t *testing.T) {
	h := NewHNDLDetector()
	result := h.Analyze("10.0.0.1", "10.0.0.2", 1024, "tls", "AES_256_GCM", "X25519", "")
	if result.HNDLSuspected {
		t.Error("small traffic should not trigger HNDL")
	}
	if result.BulkCapture {
		t.Error("small traffic should not trigger BulkCapture")
	}
}

func TestHNDLDetector_CleanupLoop(t *testing.T) {
	h := NewHNDLDetector()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.CleanupLoop(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("CleanupLoop did not exit after context cancellation")
	}
}

// ─── formatBytes ──────────────────────────────────────────────────────────────

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
	}
	for _, tc := range tests {
		got := formatBytes(tc.input)
		if got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestMonitor_HandleEvent_WeakTLS(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "tls_handshake", core.SeverityInfo, "TLS handshake")
	ev.Details["tls_version"] = "SSLv3"
	ev.Details["cipher_suite"] = "TLS_RSA_WITH_RC4_128_SHA"
	ev.Details["key_exchange"] = "RSA"
	ev.Details["server_name"] = "legacy.example.com"
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	if cp.count() == 0 {
		t.Error("expected alerts for weak TLS configuration")
	}
	// Should have at least: weak version, insecure cipher, weak key exchange
	if cp.count() < 3 {
		t.Errorf("expected at least 3 alerts, got %d", cp.count())
	}
}

func TestMonitor_HandleEvent_QuantumVulnerableCrypto(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "crypto_usage", core.SeverityInfo, "crypto usage")
	ev.Details["algorithm"] = "RSA"
	ev.Details["key_size"] = 2048
	ev.Details["purpose"] = "encryption"
	ev.Details["component"] = "payment-service"
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	if !cp.hasTitle("Quantum-Vulnerable Cryptography Detected") {
		t.Errorf("expected quantum-vulnerable crypto alert, got: %v", cp.alertTitles())
	}
}

func TestMonitor_HandleEvent_WeakKeySize(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "crypto_usage", core.SeverityInfo, "crypto usage")
	ev.Details["algorithm"] = "RSA"
	ev.Details["key_size"] = 1024
	ev.Details["purpose"] = "signing"
	ev.Details["component"] = "auth-service"
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	if !cp.hasTitle("Weak Cryptographic Key Size") {
		t.Errorf("expected weak key size alert, got: %v", cp.alertTitles())
	}
}

func TestMonitor_HandleEvent_CertExpiry(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "cert_expiry", core.SeverityInfo, "cert expiry")
	ev.Details["domain"] = "api.example.com"
	ev.Details["days_until_expiry"] = 3
	ev.Details["key_algorithm"] = "RSA"
	ev.Details["key_size"] = 2048
	ev.Details["issuer"] = "Let's Encrypt"
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	if !cp.hasTitle("Certificate Expiring Soon") {
		t.Errorf("expected cert expiry alert, got: %v", cp.alertTitles())
	}
}

// Fix #8: certificate signature algorithm checking
func TestMonitor_HandleEvent_CertWeakSignature(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "certificate_event", core.SeverityInfo, "cert event")
	ev.Details["domain"] = "old.example.com"
	ev.Details["key_algorithm"] = "RSA"
	ev.Details["key_size"] = 2048
	ev.Details["signature_algorithm"] = "SHA1WithRSA"
	ev.Details["issuer"] = "OldCA"
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	if !cp.hasTitle("Certificate Uses Weak Signature Algorithm") {
		t.Errorf("expected weak signature alert, got: %v", cp.alertTitles())
	}
}

func TestMonitor_HandleEvent_CryptoInventoryScan(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "crypto_scan", core.SeverityInfo, "crypto scan")
	ev.Details["total_algorithms"] = 20
	ev.Details["vulnerable_count"] = 15
	ev.Details["pqc_ready_count"] = 2
	ev.SourceIP = "10.0.0.1"

	m.HandleEvent(ev)

	if !cp.hasTitle("Quantum-Vulnerable Crypto Inventory Report") {
		t.Errorf("expected crypto inventory report alert, got: %v", cp.alertTitles())
	}
}

func TestMonitor_HandleEvent_HNDL(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	// Send enough traffic to trigger bulk capture
	for i := 0; i < 150; i++ {
		ev := core.NewSecurityEvent("test", "traffic_capture", core.SeverityInfo, "capture")
		ev.SourceIP = "10.0.0.1"
		ev.DestIP = "10.0.0.2"
		ev.Details["bytes_transferred"] = 5 * 1024 * 1024
		ev.Details["cipher_suite"] = "ECDHE_RSA_AES_128"
		ev.Details["key_exchange"] = "ECDHE"
		ev.Details["capture_type"] = "mirror"
		m.HandleEvent(ev)
	}

	if cp.count() == 0 {
		t.Error("expected HNDL/bulk capture alerts")
	}
}

// Fix #9: bulk_transfer event type is now routed correctly
func TestMonitor_HandleEvent_BulkTransfer(t *testing.T) {
	m := startedModule(t)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "bulk_transfer", core.SeverityInfo, "bulk transfer")
	ev.Details["bytes_transferred"] = 1024
	ev.SourceIP = "10.0.0.1"

	// Should not panic or error — previously this fell through silently
	if err := m.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent(bulk_transfer) error: %v", err)
	}
}

func TestMonitor_HandleEvent_EmptyAlgorithm(t *testing.T) {
	m := startedModule(t)
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "crypto_usage", core.SeverityInfo, "crypto usage")
	ev.Details["algorithm"] = ""
	ev.SourceIP = "10.0.0.1"

	if err := m.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() should not error on empty algorithm: %v", err)
	}
}

// Fix #11: verify mitigations are contextual (not all the same)
func TestMonitor_AlertMitigationsAreContextual(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()

	// Trigger a cert expiry alert
	ev1 := core.NewSecurityEvent("test", "cert_expiry", core.SeverityInfo, "cert")
	ev1.Details["domain"] = "a.example.com"
	ev1.Details["days_until_expiry"] = 5
	ev1.Details["issuer"] = "TestCA"
	ev1.SourceIP = "10.0.0.1"
	m.HandleEvent(ev1)

	// Trigger a quantum-vulnerable crypto alert
	ev2 := core.NewSecurityEvent("test", "crypto_usage", core.SeverityInfo, "crypto")
	ev2.Details["algorithm"] = "RSA"
	ev2.Details["key_size"] = 2048
	ev2.Details["purpose"] = "encryption"
	ev2.Details["component"] = "svc"
	ev2.SourceIP = "10.0.0.1"
	m.HandleEvent(ev2)

	cp.mu.Lock()
	defer cp.mu.Unlock()

	if len(cp.alerts) < 2 {
		t.Fatalf("expected at least 2 alerts, got %d", len(cp.alerts))
	}

	// Mitigations should differ between alert types
	m1 := cp.alerts[0].Mitigations
	m2 := cp.alerts[1].Mitigations
	if len(m1) > 0 && len(m2) > 0 && m1[0] == m2[0] {
		t.Error("mitigations should be contextual per alert type, but first mitigation is identical")
	}
}

// ─── splitAlgorithmName ───────────────────────────────────────────────────────

func TestSplitAlgorithmName(t *testing.T) {
	tests := []struct {
		input string
		want  int // expected number of parts
	}{
		{"ECDHE-RSA-AES128-GCM-SHA256", 5},
		{"AES_256_GCM", 3},
		{"ML-KEM-768", 3},
		{"RSA", 1},
		{"", 0},
	}
	for _, tc := range tests {
		parts := splitAlgorithmName(tc.input)
		if len(parts) != tc.want {
			t.Errorf("splitAlgorithmName(%q) = %d parts %v, want %d", tc.input, len(parts), parts, tc.want)
		}
	}
}

// ─── TLS PQ Curve Inventory ──────────────────────────────────────────────────

func TestTLSAudit_ClassicalOnlyKeyExchange_FlagsPQ(t *testing.T) {
	cp := makeCapturingPipeline()
	m := &Monitor{}
	cfg := core.DefaultConfig()
	if err := m.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "tls_handshake", core.SeverityInfo, "TLS handshake")
	ev.Details["tls_version"] = "TLSv1.3"
	ev.Details["cipher_suite"] = "TLS_AES_256_GCM_SHA384"
	ev.Details["key_exchange"] = "X25519"
	ev.Details["server_name"] = "api.example.com"
	ev.Details["supported_groups"] = "X25519,secp256r1,secp384r1"
	m.HandleEvent(ev)
	time.Sleep(10 * time.Millisecond)

	if !cp.hasTitle("TLS Handshake Without PQ Curves") {
		t.Error("expected 'TLS Handshake Without PQ Curves' alert for classical-only supported_groups")
	}
}

func TestTLSAudit_HybridPQ_NoAlert(t *testing.T) {
	cp := makeCapturingPipeline()
	m := &Monitor{}
	cfg := core.DefaultConfig()
	if err := m.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer m.Stop()

	ev := core.NewSecurityEvent("test", "tls_handshake", core.SeverityInfo, "TLS handshake")
	ev.Details["tls_version"] = "TLSv1.3"
	ev.Details["cipher_suite"] = "TLS_AES_256_GCM_SHA384"
	ev.Details["key_exchange"] = "X25519MLKEM768"
	ev.Details["server_name"] = "secure.example.com"
	ev.Details["supported_groups"] = "X25519MLKEM768,X25519,secp256r1"
	m.HandleEvent(ev)
	time.Sleep(10 * time.Millisecond)

	if cp.hasTitle("TLS Handshake Without PQ Curves") {
		t.Error("should NOT alert when PQ curves are in supported_groups")
	}
}

// ─── Compile-time interface check ─────────────────────────────────────────────

var _ core.Module = (*Monitor)(nil)
