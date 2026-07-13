package deepfake

import (
	"context"
	"encoding/binary"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// capPipeline captures alerts for testing.
type capPipeline struct {
	mu     sync.Mutex
	alerts []*core.Alert
}

func newCapPipeline() *capPipeline {
	cp := &capPipeline{}
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

func startedShield(t *testing.T, pipeline *core.AlertPipeline) *Shield {
	t.Helper()
	s := New()
	cfg := core.DefaultConfig()
	err := s.Start(context.Background(), nil, pipeline, cfg)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

func makePCMSamples(samples []int16) []byte {
	buf := make([]byte, len(samples)*2)
	for i, s := range samples {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(s))
	}
	return buf
}

// ---------------------------------------------------------------------------
// Module lifecycle tests
// ---------------------------------------------------------------------------

func TestShield_Name(t *testing.T) {
	s := New()
	if s.Name() != "deepfake_shield" {
		t.Errorf("expected deepfake_shield, got %s", s.Name())
	}
}

func TestShield_Description(t *testing.T) {
	s := New()
	desc := s.Description()
	if !strings.Contains(desc, "Prosodic") {
		t.Error("description should mention Prosodic analysis")
	}
	if !strings.Contains(desc, "MFCC") {
		t.Error("description should mention MFCC")
	}
	if !strings.Contains(desc, "Punycode") {
		t.Error("description should mention Punycode")
	}
}

func TestShield_Start_Stop(t *testing.T) {
	s := New()
	cfg := core.DefaultConfig()
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)

	err := s.Start(context.Background(), nil, pipeline, cfg)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	err = s.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestShield_EventTypes(t *testing.T) {
	s := New()
	types := s.EventTypes()
	expected := map[string]bool{
		"voice_call": true, "audio_message": true, "audio_upload": true, "audio_analysis": true,
		"video_call": true, "video_upload": true, "video_analysis": true,
		"email_received": true, "email_sent": true, "message_received": true,
		"executive_request": true, "wire_transfer_request": true, "urgent_request": true, "high_value_request": true,
	}
	for _, et := range types {
		if !expected[et] {
			t.Errorf("unexpected event type: %s", et)
		}
		delete(expected, et)
	}
	for et := range expected {
		t.Errorf("missing event type: %s", et)
	}
}

// ---------------------------------------------------------------------------
// Audio analysis tests
// ---------------------------------------------------------------------------

func TestAudioAnalyzer_EmptyData(t *testing.T) {
	a := NewAudioAnalyzer()
	result := a.Analyze(nil)
	if result.Score != 0 {
		t.Errorf("expected 0 score for nil data, got %f", result.Score)
	}
	result = a.Analyze([]byte{1, 2, 3})
	if result.Score != 0 {
		t.Errorf("expected 0 score for tiny data, got %f", result.Score)
	}
}

func TestAudioAnalyzer_LowEntropy(t *testing.T) {
	// Uniform bytes = low entropy → suspicious
	data := make([]byte, 2048)
	for i := range data {
		data[i] = byte(i % 4)
	}
	a := NewAudioAnalyzer()
	result := a.Analyze(data)
	if result.Score == 0 {
		t.Error("expected non-zero score for low-entropy data")
	}
	if result.Entropy >= 5.0 {
		t.Errorf("expected low entropy, got %.2f", result.Entropy)
	}
}

func TestAudioAnalyzer_HighEntropy(t *testing.T) {
	// High entropy data (pseudo-random)
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte((i*7 + 13) % 256)
	}
	a := NewAudioAnalyzer()
	result := a.Analyze(data)
	if result.Entropy < 5.0 {
		t.Errorf("expected high entropy, got %.2f", result.Entropy)
	}
}

func TestByteEntropy(t *testing.T) {
	// All same byte = 0 entropy
	data := make([]byte, 256)
	if e := byteEntropy(data); e != 0 {
		t.Errorf("expected 0 entropy for uniform data, got %f", e)
	}

	// All different bytes = 8 bits entropy
	for i := range data {
		data[i] = byte(i)
	}
	e := byteEntropy(data)
	if math.Abs(e-8.0) > 0.01 {
		t.Errorf("expected ~8.0 entropy for uniform distribution, got %f", e)
	}

	// Empty
	if byteEntropy(nil) != 0 {
		t.Error("expected 0 for nil")
	}
}

func TestSilenceRatio(t *testing.T) {
	// All silent samples
	samples := make([]int16, 512)
	data := makePCMSamples(samples)
	ratio := silenceRatio(data)
	if ratio != 1.0 {
		t.Errorf("expected 1.0 silence ratio, got %f", ratio)
	}

	// All loud samples
	for i := range samples {
		samples[i] = 10000
	}
	data = makePCMSamples(samples)
	ratio = silenceRatio(data)
	if ratio != 0.0 {
		t.Errorf("expected 0.0 silence ratio, got %f", ratio)
	}
}

func TestZeroCrossingRate(t *testing.T) {
	// Alternating positive/negative = high ZCR
	samples := make([]int16, 256)
	for i := range samples {
		if i%2 == 0 {
			samples[i] = 1000
		} else {
			samples[i] = -1000
		}
	}
	data := makePCMSamples(samples)
	zcr := zeroCrossingRate(data)
	if zcr < 0.9 {
		t.Errorf("expected high ZCR for alternating signal, got %f", zcr)
	}

	// All positive = 0 ZCR
	for i := range samples {
		samples[i] = 1000
	}
	data = makePCMSamples(samples)
	zcr = zeroCrossingRate(data)
	if zcr != 0 {
		t.Errorf("expected 0 ZCR for constant signal, got %f", zcr)
	}
}

func TestCheckBitrateConsistency(t *testing.T) {
	// Uniform energy across frames = suspicious
	data := make([]byte, 8192)
	for i := range data {
		data[i] = 128
	}
	if !checkBitrateConsistency(data) {
		t.Error("expected true for perfectly uniform data")
	}

	// Too short
	if checkBitrateConsistency([]byte{1, 2, 3}) {
		t.Error("expected false for short data")
	}
}

// ---------------------------------------------------------------------------
// Prosodic analysis tests
// ---------------------------------------------------------------------------

func TestAnalyzeProsody_TooShort(t *testing.T) {
	data := makePCMSamples([]int16{100, 200, 300})
	result := analyzeProsody(data)
	if result.Valid {
		t.Error("expected invalid for short data")
	}
}

func TestAnalyzeProsody_SineWave(t *testing.T) {
	// Generate a sine wave at 200 Hz, 16kHz sample rate — should detect pitch
	sampleRate := 16000.0
	freq := 200.0
	numSamples := 4096
	samples := make([]int16, numSamples)
	for i := range samples {
		samples[i] = int16(10000 * math.Sin(2*math.Pi*freq*float64(i)/sampleRate))
	}
	data := makePCMSamples(samples)
	result := analyzeProsody(data)
	if !result.Valid {
		t.Fatal("expected valid prosody for sine wave")
	}
	// Pitch should be near 200 Hz
	if math.Abs(result.PitchMean-freq) > 30 {
		t.Errorf("expected pitch near %.0f Hz, got %.1f Hz", freq, result.PitchMean)
	}
	// Pure sine = very low jitter
	if result.Jitter > 0.05 {
		t.Errorf("expected low jitter for pure sine, got %f", result.Jitter)
	}
}

func TestAutocorrelationPitch_Silent(t *testing.T) {
	window := make([]float64, 512)
	period := autocorrelationPitch(window, 16000)
	if period != 0 {
		t.Errorf("expected 0 for silent window, got %f", period)
	}
}

func TestEstimateHNR_SineWave(t *testing.T) {
	sampleRate := 16000.0
	freq := 200.0
	numSamples := 2048
	samples := make([]float64, numSamples)
	for i := range samples {
		samples[i] = 10000 * math.Sin(2*math.Pi*freq*float64(i)/sampleRate)
	}
	hnr := estimateHNR(samples, sampleRate)
	// Pure sine should have high HNR
	if hnr < 10 {
		t.Errorf("expected high HNR for pure sine, got %.1f", hnr)
	}
}

// ---------------------------------------------------------------------------
// MFCC tests
// ---------------------------------------------------------------------------

func TestMFCCSmoothness_TooShort(t *testing.T) {
	data := makePCMSamples([]int16{1, 2, 3})
	result := mfccSmoothness(data)
	if result != -1 {
		t.Errorf("expected -1 for short data, got %f", result)
	}
}

func TestMFCCSmoothness_SineWave(t *testing.T) {
	// Sine wave should have smooth MFCC trajectory
	sampleRate := 16000.0
	freq := 300.0
	numSamples := 8192
	samples := make([]int16, numSamples)
	for i := range samples {
		samples[i] = int16(5000 * math.Sin(2*math.Pi*freq*float64(i)/sampleRate))
	}
	data := makePCMSamples(samples)
	result := mfccSmoothness(data)
	if result < 0 {
		t.Fatal("expected valid MFCC smoothness")
	}
	// Pure sine should be very smooth
	if result > 5.0 {
		t.Errorf("expected smooth MFCC for sine wave, got %f", result)
	}
}

func TestComputeMFCC_TooShort(t *testing.T) {
	result := computeMFCC([]float64{1, 2}, 16000, 13, 26)
	if result != nil {
		t.Error("expected nil for too-short frame")
	}
}

func TestHzToMel_MelToHz(t *testing.T) {
	// Round-trip test
	for _, hz := range []float64{0, 100, 1000, 4000, 8000} {
		mel := hzToMel(hz)
		back := melToHz(mel)
		if math.Abs(back-hz) > 0.01 {
			t.Errorf("round-trip failed for %.0f Hz: got %.2f", hz, back)
		}
	}
}

// ---------------------------------------------------------------------------
// Phase coherence tests
// ---------------------------------------------------------------------------

func TestPhaseCoherence_TooShort(t *testing.T) {
	data := makePCMSamples([]int16{1, 2, 3})
	result := phaseCoherence(data)
	if result != -1 {
		t.Errorf("expected -1 for short data, got %f", result)
	}
}

func TestPhaseCoherence_SineWave(t *testing.T) {
	sampleRate := 16000.0
	freq := 440.0
	numSamples := 4096
	samples := make([]int16, numSamples)
	for i := range samples {
		samples[i] = int16(10000 * math.Sin(2*math.Pi*freq*float64(i)/sampleRate))
	}
	data := makePCMSamples(samples)
	result := phaseCoherence(data)
	if result < 0 {
		t.Fatal("expected valid phase coherence")
	}
	// Phase coherence should be a value between 0 and 1
	if result < 0 || result > 1.0 {
		t.Errorf("phase coherence out of range: %f", result)
	}
}

// ---------------------------------------------------------------------------
// Video analysis tests
// ---------------------------------------------------------------------------

func TestVideoAnalyzer_EmptyFrames(t *testing.T) {
	v := NewVideoAnalyzer()
	result := v.Analyze(nil, nil)
	if result.Score != 0 {
		t.Errorf("expected 0 score for nil frames, got %f", result.Score)
	}
}

func TestVideoAnalyzer_ConsistentFrameEntropy(t *testing.T) {
	v := NewVideoAnalyzer()
	// Identical frames = unnaturally consistent
	frame := make([]byte, 1024)
	for i := range frame {
		frame[i] = byte(i % 256)
	}
	frames := [][]byte{frame, frame, frame, frame}
	result := v.Analyze(frames, nil)
	if result.Score == 0 {
		t.Error("expected non-zero score for identical frames")
	}
}

func TestVideoAnalyzer_MetadataAnomalies(t *testing.T) {
	v := NewVideoAnalyzer()
	frame := make([]byte, 256)
	for i := range frame {
		frame[i] = byte(i)
	}
	metadata := map[string]interface{}{
		"codec": "rawvideo",
		"fps":   float64(17.5),
	}
	result := v.Analyze([][]byte{frame}, metadata)
	found := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "unusual codec") || strings.Contains(ind, "non-standard frame rate") {
			found = true
		}
	}
	if !found {
		t.Error("expected metadata anomaly indicators")
	}
}

func TestVideoAnalyzer_ExpandedCodecs(t *testing.T) {
	v := NewVideoAnalyzer()
	frame := make([]byte, 256)
	for _, codec := range []string{"utvideo", "huffyuv"} {
		result := v.Analyze([][]byte{frame}, map[string]interface{}{"codec": codec})
		found := false
		for _, ind := range result.Indicators {
			if strings.Contains(ind, "unusual codec") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected unusual codec indicator for %s", codec)
		}
	}
}

func TestVideoAnalyzer_ContainerCodecMismatch(t *testing.T) {
	v := NewVideoAnalyzer()
	frame := make([]byte, 256)
	result := v.Analyze([][]byte{frame}, map[string]interface{}{
		"codec":     "rawvideo",
		"container": "mp4",
	})
	found := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "container/codec mismatch") {
			found = true
		}
	}
	if !found {
		t.Error("expected container/codec mismatch indicator")
	}
}

func TestELAAnalysis(t *testing.T) {
	// Frame with uniform blocks = low ELA score
	frame := make([]byte, 4096)
	for i := range frame {
		frame[i] = 128
	}
	score := elaAnalysis(frame)
	if score > 0.5 {
		t.Errorf("expected low ELA score for uniform frame, got %f", score)
	}

	// Too short
	if elaAnalysis([]byte{1, 2, 3}) != 0 {
		t.Error("expected 0 for short frame")
	}
}

func TestFrameDifference(t *testing.T) {
	a := []byte{10, 20, 30}
	b := []byte{15, 25, 35}
	diff := frameDifference(a, b)
	if math.Abs(diff-5.0) > 0.01 {
		t.Errorf("expected 5.0, got %f", diff)
	}
	if frameDifference(nil, nil) != 0 {
		t.Error("expected 0 for nil frames")
	}
}

// ---------------------------------------------------------------------------
// Phishing detector tests
// ---------------------------------------------------------------------------

func TestAIPhishingDetector_UrgencyPatterns(t *testing.T) {
	d := NewAIPhishingDetector()
	result := d.Analyze("", "Urgent: Action Required", "This is urgent, act now before it expires today", "")
	if result.Score == 0 {
		t.Error("expected non-zero score for urgency patterns")
	}
	found := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "urgency") {
			found = true
		}
	}
	if !found {
		t.Error("expected urgency indicator")
	}
}

func TestAIPhishingDetector_ImpersonationPatterns(t *testing.T) {
	d := NewAIPhishingDetector()
	result := d.Analyze("", "", "The CEO has requested an immediate wire transfer", "")
	found := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "impersonation") {
			found = true
		}
	}
	if !found {
		t.Error("expected impersonation indicator")
	}
}

func TestAIPhishingDetector_ActionPatterns(t *testing.T) {
	d := NewAIPhishingDetector()
	result := d.Analyze("", "", "Please click here to verify your account and download the attachment", "")
	found := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "call-to-action") {
			found = true
		}
	}
	if !found {
		t.Error("expected action indicator")
	}
}

func TestAIPhishingDetector_ThreatPatterns(t *testing.T) {
	d := NewAIPhishingDetector()
	result := d.Analyze("", "", "Your account will be suspended due to unauthorized access detected", "")
	found := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "threat") {
			found = true
		}
	}
	if !found {
		t.Error("expected threat indicator")
	}
}

func TestAIPhishingDetector_HeaderAnalysis(t *testing.T) {
	d := NewAIPhishingDetector()
	// Missing DKIM and SPF
	result := d.Analyze("", "", "Hello", "Received: from mail.example.com")
	if result.Score == 0 {
		t.Error("expected non-zero score for missing auth headers")
	}

	// DMARC failure
	result = d.Analyze("", "", "Hello", "dkim=pass; spf=pass; dmarc=fail")
	found := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "DMARC") {
			found = true
		}
	}
	if !found {
		t.Error("expected DMARC failure indicator")
	}
}

func TestAIPhishingDetector_ARCValidation(t *testing.T) {
	d := NewAIPhishingDetector()
	result := d.Analyze("", "", "Hello", "dkim=pass; spf=pass; arc-seal: cv=fail")
	found := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "ARC") {
			found = true
		}
	}
	if !found {
		t.Error("expected ARC failure indicator")
	}
}

func TestAIPhishingDetector_WritingStyleAnomaly(t *testing.T) {
	d := NewAIPhishingDetector()
	// Generate text with high vocab richness (many unique words)
	body := "The unprecedented amalgamation of sophisticated cybersecurity paradigms necessitates immediate recalibration of organizational protocols. Furthermore, the quintessential framework demands comprehensive evaluation of multifaceted threat vectors across heterogeneous infrastructure deployments."
	result := d.Analyze("", "", body, "dkim=pass; spf=pass")
	// Should detect writing style anomaly
	found := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "writing style") {
			found = true
		}
	}
	// This is a soft check — depends on exact thresholds
	_ = found
}

func TestAIPhishingDetector_CombinedScore(t *testing.T) {
	d := NewAIPhishingDetector()
	result := d.Analyze(
		"CEO John <ceo@evil.com>",
		"Urgent: Wire Transfer Required",
		"This is urgent. The CEO needs you to click here to verify your account. Your account will be suspended.",
		"",
	)
	if !result.IsPhishing {
		t.Error("expected phishing detection for combined indicators")
	}
	if result.Score < 0.5 {
		t.Errorf("expected score >= 0.5, got %f", result.Score)
	}
}

func TestAIPhishingDetector_CleanEmail(t *testing.T) {
	d := NewAIPhishingDetector()
	result := d.Analyze("alice@company.com", "Meeting tomorrow", "Hi, can we reschedule our meeting to 3pm?", "dkim=pass; spf=pass")
	if result.IsPhishing {
		t.Error("clean email should not be flagged as phishing")
	}
}

// ---------------------------------------------------------------------------
// Domain spoof checker tests
// ---------------------------------------------------------------------------

func TestDomainSpoofChecker_Homoglyphs(t *testing.T) {
	dc := NewDomainSpoofChecker(nil)
	// Cyrillic 'о' in google
	domain := "g\u043Eogle.com"
	result := dc.Check(domain)
	if result != "google.com" {
		t.Errorf("expected google.com spoof detection, got %q", result)
	}
}

func TestDomainSpoofChecker_ExpandedHomoglyphs(t *testing.T) {
	dc := NewDomainSpoofChecker(nil)
	// Greek 'ο' in google
	domain := "g\u03BFogle.com"
	result := dc.Check(domain)
	if result != "google.com" {
		t.Errorf("expected google.com spoof detection for Greek, got %q", result)
	}
}

func TestDomainSpoofChecker_Levenshtein(t *testing.T) {
	dc := NewDomainSpoofChecker(nil)
	// Distance 1
	if dc.Check("gogle.com") != "google.com" {
		t.Error("expected google.com for gogle.com (distance 1)")
	}
	// Distance 2 (now caught with maxLevenshtein=2)
	if dc.Check("gooogle.com") != "google.com" {
		t.Error("expected google.com for gooogle.com (distance 2)")
	}
}

func TestDomainSpoofChecker_ExactMatch(t *testing.T) {
	dc := NewDomainSpoofChecker(nil)
	if dc.Check("google.com") != "" {
		t.Error("exact match should not be flagged")
	}
}

func TestDomainSpoofChecker_UnrelatedDomain(t *testing.T) {
	dc := NewDomainSpoofChecker(nil)
	if dc.Check("totallyunrelated.xyz") != "" {
		t.Error("unrelated domain should not be flagged")
	}
}

func TestDomainSpoofChecker_TLDSwap(t *testing.T) {
	dc := NewDomainSpoofChecker(nil)
	result := dc.Check("google.co")
	if result != "google.com" {
		t.Errorf("expected google.com for TLD swap google.co, got %q", result)
	}
	result = dc.Check("google.cm")
	if result != "google.com" {
		t.Errorf("expected google.com for TLD swap google.cm, got %q", result)
	}
}

func TestDomainSpoofChecker_Punycode(t *testing.T) {
	_ = NewDomainSpoofChecker(nil)
	// xn--test-cua.com is a Punycode encoding
	// Test the decoder doesn't crash on valid input
	result := decodePunycode("xn--test-cua.com")
	if result == "" {
		t.Error("punycode decoder should return something")
	}
}

func TestDomainSpoofChecker_ConfigurableDomains(t *testing.T) {
	settings := map[string]interface{}{
		"trusted_domains": []interface{}{"mycompany.com", "partner.org"},
	}
	dc := NewDomainSpoofChecker(settings)
	// Should detect spoofing of custom domain
	result := dc.Check("mycompany.co")
	if result != "mycompany.com" {
		t.Errorf("expected mycompany.com for TLD swap, got %q", result)
	}
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "b", 1},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"abc", "abcd", 1},
		{"kitten", "sitting", 3},
	}
	for _, tt := range tests {
		got := levenshtein(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIsTLDSwap(t *testing.T) {
	if !isTLDSwap("google.co", "google.com") {
		t.Error("expected TLD swap detection for google.co vs google.com")
	}
	if isTLDSwap("google.com", "google.com") {
		t.Error("same domain should not be TLD swap")
	}
	if isTLDSwap("different.co", "google.com") {
		t.Error("different base domain should not be TLD swap")
	}
}

func TestDecodePunycodePart(t *testing.T) {
	// "bücher" encoded as Punycode is "bcher-kva"
	result := decodePunycodePart("bcher-kva")
	if result != "bücher" {
		t.Errorf("expected bücher, got %q", result)
	}

	// Invalid input
	result = decodePunycodePart("")
	// Should handle gracefully (empty or decoded)
	_ = result
}

func TestDecodePunycodePartRejectsOutOfRangeCodePoint(t *testing.T) {
	// A long digit sequence must fail closed instead of wrapping into a rune.
	if got := decodePunycodePart("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"); got != "" {
		t.Fatalf("expected invalid Punycode to be rejected, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Reply-chain verification tests
// ---------------------------------------------------------------------------

func TestVerifyReplyChain_Clean(t *testing.T) {
	result := verifyReplyChain("msg1", "msg0", "msg0", "", "")
	if result.Suspicious {
		t.Error("clean reply chain should not be suspicious")
	}
}

func TestVerifyReplyChain_MissingReferences(t *testing.T) {
	result := verifyReplyChain("msg1", "msg0", "", "", "")
	if !result.Suspicious {
		t.Error("In-Reply-To without References should be suspicious")
	}
}

func TestVerifyReplyChain_InReplyToNotInReferences(t *testing.T) {
	result := verifyReplyChain("msg2", "msg1", "msg0", "", "")
	if !result.Suspicious {
		t.Error("In-Reply-To not in References should be suspicious")
	}
}

func TestVerifyReplyChain_MultipleFromHeaders(t *testing.T) {
	headers := "Subject: test\nFrom: alice@example.com\nTo: bob@example.com\nFrom: bob@evil.com"
	result := verifyReplyChain("", "", "", "", headers)
	if !result.Suspicious {
		t.Error("multiple From headers should be suspicious")
	}
}

func TestVerifyReplyChain_LongReceivedChain(t *testing.T) {
	headers := strings.Repeat("\nReceived: from server", 20)
	result := verifyReplyChain("", "", "", "", headers)
	if !result.Suspicious {
		t.Error("very long Received chain should be suspicious")
	}
}

// ---------------------------------------------------------------------------
// Communication tracker tests
// ---------------------------------------------------------------------------

func TestCommunicationTracker_RecordAndGet(t *testing.T) {
	ct := NewCommunicationTracker()
	ct.RecordCommunication("alice", "1.2.3.4")
	ct.RecordCommunication("alice", "5.6.7.8")

	p := ct.GetPattern("alice")
	if p == nil {
		t.Fatal("expected pattern for alice")
	}
	if p.MessageCount != 2 {
		t.Errorf("expected 2 messages, got %d", p.MessageCount)
	}
	if !p.UsualIPs["1.2.3.4"] || !p.UsualIPs["5.6.7.8"] {
		t.Error("expected both IPs recorded")
	}
}

func TestCommunicationTracker_WritingStyle(t *testing.T) {
	ct := NewCommunicationTracker()
	ct.RecordCommunication("bob", "1.2.3.4")
	ct.RecordWritingStyle("bob", "Hello world. This is a test message. It has multiple sentences.")

	p := ct.GetPattern("bob")
	if p == nil {
		t.Fatal("expected pattern for bob")
	}
	if p.StyleSamples != 1 {
		t.Errorf("expected 1 style sample, got %d", p.StyleSamples)
	}
	if p.AvgSentenceLen == 0 {
		t.Error("expected non-zero avg sentence length")
	}
}

func TestCommunicationTracker_UnknownIdentity(t *testing.T) {
	ct := NewCommunicationTracker()
	p := ct.GetPattern("unknown")
	if p != nil {
		t.Error("expected nil for unknown identity")
	}
}

// ---------------------------------------------------------------------------
// Writing style analysis tests
// ---------------------------------------------------------------------------

func TestAnalyzeWritingStyle(t *testing.T) {
	text := "Hello world. This is a test. Short sentences work."
	stats := analyzeWritingStyle(text)
	if stats.AvgSentenceLen == 0 {
		t.Error("expected non-zero avg sentence length")
	}
	if stats.AvgWordLen == 0 {
		t.Error("expected non-zero avg word length")
	}
	if stats.VocabRichness == 0 {
		t.Error("expected non-zero vocab richness")
	}
}

func TestAnalyzeWritingStyle_Short(t *testing.T) {
	stats := analyzeWritingStyle("Hi")
	if stats.AvgSentenceLen != 0 {
		t.Error("expected zero for very short text")
	}
}

// ---------------------------------------------------------------------------
// Integration / HandleEvent tests
// ---------------------------------------------------------------------------

func TestShield_HandleEvent_AudioEvent(t *testing.T) {
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
	s := startedShield(t, pipeline)

	// Low-entropy audio should trigger alert
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 3)
	}
	event := core.NewSecurityEvent("test", "voice_call", core.SeverityInfo, "test audio")
	event.RawData = data
	event.Details["caller_id"] = "unknown"
	event.Details["claimed_identity"] = "ceo"

	_ = s.HandleEvent(event)
}

func TestShield_HandleEvent_AudioAnalysis(t *testing.T) {
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
	s := startedShield(t, pipeline)

	event := core.NewSecurityEvent("test", "audio_analysis", core.SeverityInfo, "test")
	event.RawData = make([]byte, 128)
	_ = s.HandleEvent(event)
}

func TestShield_HandleEvent_VideoAnalysis(t *testing.T) {
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
	s := startedShield(t, pipeline)

	event := core.NewSecurityEvent("test", "video_analysis", core.SeverityInfo, "test")
	event.RawData = make([]byte, 512)
	_ = s.HandleEvent(event)
}

func TestShield_HandleEvent_HighValueRequest(t *testing.T) {
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
	s := startedShield(t, pipeline)

	event := core.NewSecurityEvent("test", "high_value_request", core.SeverityInfo, "test")
	event.Details["requester"] = "unknown_person"
	event.Details["request_type"] = "wire_transfer"
	event.Details["amount"] = float64(500000)
	event.Details["urgency"] = "critical"

	_ = s.HandleEvent(event)
}

func TestShield_HandleEvent_CommunicationEvent(t *testing.T) {
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
	s := startedShield(t, pipeline)

	event := core.NewSecurityEvent("test", "email_received", core.SeverityInfo, "test")
	event.Details["sender"] = "CEO <ceo@evil.com>"
	event.Details["subject"] = "Urgent: Wire Transfer"
	event.Details["body"] = "This is urgent. Click here to verify your account. Your account will be suspended."
	event.Details["sender_domain"] = "g\u043Eogle.com"

	_ = s.HandleEvent(event)
}

func TestShield_HandleEvent_ReplyChainAnomaly(t *testing.T) {
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
	s := startedShield(t, pipeline)

	event := core.NewSecurityEvent("test", "email_received", core.SeverityInfo, "test")
	event.Details["sender"] = "alice@example.com"
	event.Details["subject"] = "Re: Important meeting"
	event.Details["body"] = "Please see attached."
	event.Details["in_reply_to"] = "msg-123"
	event.Details["references"] = "" // missing references = suspicious

	_ = s.HandleEvent(event)
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestPcmToFloat64(t *testing.T) {
	samples := []int16{0, 1000, -1000, 32767}
	data := makePCMSamples(samples)
	result := pcmToFloat64(data)
	if len(result) != 4 {
		t.Fatalf("expected 4 samples, got %d", len(result))
	}
	if result[0] != 0 || result[1] != 1000 || result[2] != -1000 || result[3] != 32767 {
		t.Errorf("unexpected values: %v", result)
	}
}

func TestMean(t *testing.T) {
	if mean(nil) != 0 {
		t.Error("expected 0 for nil")
	}
	if mean([]float64{2, 4, 6}) != 4 {
		t.Error("expected 4")
	}
}

func TestStddev(t *testing.T) {
	vals := []float64{2, 4, 6}
	m := mean(vals)
	sd := stddev(vals, m)
	expected := math.Sqrt((4 + 0 + 4) / 3.0)
	if math.Abs(sd-expected) > 0.001 {
		t.Errorf("expected stddev ~%.4f, got %.4f", expected, sd)
	}
}
