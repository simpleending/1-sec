package quantumcrypto

import (
	"testing"

	"github.com/1sec-project/1sec/internal/core"
)

func TestHNDLRequiresCaptureAndClassicalKeyExchange(t *testing.T) {
	for _, tt := range []struct {
		name, cipher, exchange, capture string
		want                            bool
	}{
		{"ordinary transfer", "ECDHE_RSA_AES_128", "ECDHE", "", false},
		{"hybrid capture", "ECDHE_RSA_AES_128", "X25519MLKEM768", "tap", false},
		{"unknown key exchange", "TLS_AES_256_GCM_SHA384", "", "tap", false},
		{"TLS 1.3 classical capture", "TLS_AES_256_GCM_SHA384", "X25519", "tap", true},
		{"legacy classical capture", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "", "pcap", true},
		{"unknown exchange overrides legacy cipher", "ECDHE_RSA_AES_128", "custom", "tap", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHNDLDetector()
			got := h.Analyze("10.0.0.1", "10.0.0.2", 1100<<20, "tls", tt.cipher, tt.exchange, tt.capture)
			if got.HNDLSuspected != tt.want {
				t.Fatalf("HNDLSuspected=%v, want %v; %+v", got.HNDLSuspected, tt.want, got)
			}
		})
	}
}

func TestHNDLDoesNotMixUnrelatedEvidence(t *testing.T) {
	h := NewHNDLDetector()
	h.Analyze("source", "legacy", 1024, "tls", "", "X25519", "tap")
	if got := h.Analyze("source", "hybrid", 1100<<20, "tls", "", "X25519MLKEM768", "tap"); got.HNDLSuspected {
		t.Fatal("large hybrid capture was combined with unrelated small classical capture")
	}
	h.Analyze("source", "legacy", -2000<<20, "tls", "", "X25519", "tap")
	if got := h.Analyze("source", "legacy", 150<<20, "tls", "", "X25519", "tap"); !got.HNDLSuspected {
		t.Fatal("negative traffic counter suppressed actual captured volume")
	}
}

func TestInventoryDoesNotCertifyUnknownAlgorithms(t *testing.T) {
	for _, algorithm := range []string{"custom-magic", "TLS_AES_256_GCM_SHA384", "BIKE", "Kyber"} {
		inventory := NewCryptoInventory()
		inventory.RecordUsage("key_exchange", algorithm, "service")
		if inventory.Summary()[0].QuantumSafe {
			t.Fatalf("unverified algorithm %q labeled quantum safe", algorithm)
		}
	}
}

func TestTLSOfferDoesNotProveNegotiatedQuantumResistance(t *testing.T) {
	cp := makeCapturingPipeline()
	m := startedModuleWithPipeline(t, cp)
	defer m.Stop()
	ev := core.NewSecurityEvent("collector", "tls_handshake", core.SeverityInfo, "TLS")
	ev.Details["tls_version"] = "TLSv1.3"
	ev.Details["supported_groups"] = "X25519, X25519MLKEM768"
	ev.Details["key_exchange"] = "X25519"
	m.HandleEvent(ev)
	if !cp.hasAlertType("no_pq_key_exchange") {
		t.Fatal("offered hybrid group suppressed actual classical negotiation")
	}
	ev.Details["supported_groups"] = "X25519, not-a-real-mlkem-group"
	m.HandleEvent(ev)
	if !cp.hasAlertType("no_pq_curves") {
		t.Fatal("substring was accepted as proof of PQ capability")
	}
}
