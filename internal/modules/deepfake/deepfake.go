package deepfake

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "deepfake_shield"

// Shield is the Deepfake Shield module providing:
// - Heuristic audio analysis (entropy, spectral flatness, silence ratio, bitrate consistency)
// - Prosodic feature analysis (pitch/F0, jitter, shimmer, HNR)
// - MFCC trajectory smoothness detection
// - Phase coherence analysis between audio frames
// - Heuristic video frame analysis (temporal consistency, metadata anomalies, ELA)
// - AI-generated phishing/BEC detection (regex + writing style statistics)
// - Reply-chain context verification
// - Domain homoglyph spoofing detection (expanded Unicode confusables + Punycode)
// - Communication pattern anomaly tracking
type Shield struct {
	logger      zerolog.Logger
	bus         *core.EventBus
	pipeline    *core.AlertPipeline
	cfg         *core.Config
	ctx         context.Context
	cancel      context.CancelFunc
	commTracker *CommunicationTracker
	phishDet    *AIPhishingDetector
	domainCheck *DomainSpoofChecker
	audioAnal   *AudioAnalyzer
	videoAnal   *VideoAnalyzer
}

func New() *Shield { return &Shield{} }

func (s *Shield) Name() string { return ModuleName }
func (s *Shield) EventTypes() []string {
	return []string{
		"voice_call", "audio_message", "audio_upload", "audio_analysis",
		"video_call", "video_upload", "video_analysis",
		"email_received", "email_sent", "message_received",
		"executive_request", "wire_transfer_request", "urgent_request", "high_value_request",
	}
}
func (s *Shield) Description() string {
	return "Prosodic and spectral audio deepfake detection, MFCC trajectory analysis, phase coherence checks, ELA-based video forensics, AI-generated phishing detection with writing style analysis, expanded Unicode homoglyph and Punycode domain spoofing, and communication anomaly tracking"
}

func (s *Shield) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.bus = bus
	s.pipeline = pipeline
	s.cfg = cfg
	s.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)

	s.commTracker = NewCommunicationTracker()
	s.phishDet = NewAIPhishingDetector()
	s.domainCheck = NewDomainSpoofChecker(settings)
	s.audioAnal = NewAudioAnalyzer()
	s.videoAnal = NewVideoAnalyzer()

	go s.commTracker.CleanupLoop(s.ctx)

	s.logger.Info().Msg("deepfake shield started")
	return nil
}

func (s *Shield) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Shield) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "voice_call", "audio_message", "audio_upload", "audio_analysis":
		s.handleAudioEvent(event)
	case "video_call", "video_upload", "video_analysis":
		s.handleVideoEvent(event)
	case "email_received", "email_sent", "message_received":
		s.handleCommunicationEvent(event)
	case "executive_request", "wire_transfer_request", "urgent_request", "high_value_request":
		s.handleHighValueRequest(event)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Audio Analysis — heuristic + prosodic deepfake detection on raw bytes (no ML)
// ---------------------------------------------------------------------------

// AudioAnalyzer performs statistical and prosodic analysis on raw audio data to
// detect synthetic speech. Works on raw PCM bytes or any audio payload.
type AudioAnalyzer struct{}

func NewAudioAnalyzer() *AudioAnalyzer { return &AudioAnalyzer{} }

// AudioResult holds the results of heuristic audio analysis.
type AudioResult struct {
	Score          float64
	Entropy        float64
	SpectralFlat   float64
	SilenceRatio   float64
	ZeroCrossRate  float64
	BitrateStable  bool
	PitchMean      float64
	PitchStdDev    float64
	Jitter         float64
	Shimmer        float64
	HNR            float64
	MFCCSmoothness float64
	PhaseCoherence float64
	Indicators     []string
}

// Analyze performs heuristic analysis on raw audio bytes.
// It computes byte-level entropy, spectral flatness from PCM samples,
// silence ratio, zero-crossing rate, bitrate consistency, prosodic features
// (pitch, jitter, shimmer, HNR), MFCC trajectory smoothness, and phase coherence.
func (a *AudioAnalyzer) Analyze(raw []byte) AudioResult {
	result := AudioResult{}
	if len(raw) < 64 {
		return result
	}

	// 1. Byte-level Shannon entropy — synthetic audio tends toward lower entropy
	result.Entropy = byteEntropy(raw)
	if result.Entropy < 5.0 {
		result.Score += 0.20
		result.Indicators = append(result.Indicators, fmt.Sprintf("low byte entropy (%.2f)", result.Entropy))
	} else if result.Entropy < 5.5 {
		result.Score += 0.08
		result.Indicators = append(result.Indicators, fmt.Sprintf("below-average entropy (%.2f)", result.Entropy))
	}

	// 2. Spectral flatness estimation from PCM-like interpretation of bytes
	result.SpectralFlat = estimateSpectralFlatness(raw)
	if result.SpectralFlat > 0.85 {
		result.Score += 0.15
		result.Indicators = append(result.Indicators, fmt.Sprintf("high spectral flatness (%.3f)", result.SpectralFlat))
	} else if result.SpectralFlat < 0.05 {
		result.Score += 0.10
		result.Indicators = append(result.Indicators, fmt.Sprintf("very low spectral flatness (%.3f)", result.SpectralFlat))
	}

	// 3. Silence ratio — deepfake audio often has unnatural silence patterns
	result.SilenceRatio = silenceRatio(raw)
	if result.SilenceRatio < 0.10 {
		result.Score += 0.10
		result.Indicators = append(result.Indicators, fmt.Sprintf("almost no silence (%.1f%%)", result.SilenceRatio*100))
	} else if result.SilenceRatio > 0.80 {
		result.Score += 0.08
		result.Indicators = append(result.Indicators, fmt.Sprintf("excessive silence (%.1f%%)", result.SilenceRatio*100))
	}

	// 4. Zero-crossing rate
	result.ZeroCrossRate = zeroCrossingRate(raw)
	if result.ZeroCrossRate < 0.005 || result.ZeroCrossRate > 0.30 {
		result.Score += 0.10
		result.Indicators = append(result.Indicators, fmt.Sprintf("abnormal zero-crossing rate (%.4f)", result.ZeroCrossRate))
	}

	// 5. Bitrate consistency
	result.BitrateStable = checkBitrateConsistency(raw)
	if result.BitrateStable {
		result.Score += 0.08
		result.Indicators = append(result.Indicators, "suspiciously uniform bitrate pattern")
	}

	// 6. Prosodic features — pitch (F0), jitter, shimmer, HNR
	prosody := analyzeProsody(raw)
	result.PitchMean = prosody.PitchMean
	result.PitchStdDev = prosody.PitchStdDev
	result.Jitter = prosody.Jitter
	result.Shimmer = prosody.Shimmer
	result.HNR = prosody.HNR

	if prosody.Valid {
		// Abnormally low jitter suggests synthetic speech (too perfect)
		if prosody.Jitter < 0.002 && prosody.Jitter > 0 {
			result.Score += 0.15
			result.Indicators = append(result.Indicators, fmt.Sprintf("unnaturally low jitter (%.4f) — too perfect pitch", prosody.Jitter))
		}
		// Abnormally low shimmer
		if prosody.Shimmer < 0.01 && prosody.Shimmer > 0 {
			result.Score += 0.10
			result.Indicators = append(result.Indicators, fmt.Sprintf("unnaturally low shimmer (%.4f) — too stable amplitude", prosody.Shimmer))
		}
		// Very low pitch variation (monotone)
		if prosody.PitchStdDev < 5.0 && prosody.PitchMean > 0 {
			result.Score += 0.10
			result.Indicators = append(result.Indicators, fmt.Sprintf("monotone pitch (stddev=%.1f Hz)", prosody.PitchStdDev))
		}
		// Abnormal HNR (too clean = synthetic)
		if prosody.HNR > 35.0 {
			result.Score += 0.10
			result.Indicators = append(result.Indicators, fmt.Sprintf("unnaturally high HNR (%.1f dB) — too clean signal", prosody.HNR))
		}
	}

	// 7. MFCC trajectory smoothness
	result.MFCCSmoothness = mfccSmoothness(raw)
	if result.MFCCSmoothness > 0 && result.MFCCSmoothness < 0.5 {
		result.Score += 0.10
		result.Indicators = append(result.Indicators, fmt.Sprintf("unnaturally smooth MFCC trajectory (%.3f)", result.MFCCSmoothness))
	}

	// 8. Phase coherence between frames
	result.PhaseCoherence = phaseCoherence(raw)
	if result.PhaseCoherence > 0.95 {
		result.Score += 0.10
		result.Indicators = append(result.Indicators, fmt.Sprintf("abnormally high phase coherence (%.3f)", result.PhaseCoherence))
	}

	// Cap at 1.0
	if result.Score > 1.0 {
		result.Score = 1.0
	}

	return result
}

// ---------------------------------------------------------------------------
// Prosodic Analysis — pitch, jitter, shimmer, HNR (pure Go, no ML)
// ---------------------------------------------------------------------------

// ProsodyResult holds prosodic feature values.
type ProsodyResult struct {
	Valid       bool
	PitchMean   float64
	PitchStdDev float64
	Jitter      float64
	Shimmer     float64
	HNR         float64
}

// analyzeProsody extracts prosodic features from 16-bit PCM audio.
// Uses autocorrelation-based pitch detection and derives jitter/shimmer/HNR.
func analyzeProsody(data []byte) ProsodyResult {
	result := ProsodyResult{}
	numSamples := len(data) / 2
	if numSamples < 512 {
		return result
	}

	samples := pcmToFloat64(data)

	// Extract pitch periods using autocorrelation on overlapping windows
	windowSize := 512
	hopSize := 256
	sampleRate := 16000.0 // assume 16kHz; common for telephony/voice

	var pitchPeriods []float64
	var amplitudes []float64

	for start := 0; start+windowSize <= len(samples); start += hopSize {
		window := samples[start : start+windowSize]
		period := autocorrelationPitch(window, sampleRate)
		if period > 0 {
			pitchPeriods = append(pitchPeriods, period)
			// Compute RMS amplitude for this window
			rms := 0.0
			for _, s := range window {
				rms += s * s
			}
			rms = math.Sqrt(rms / float64(len(window)))
			amplitudes = append(amplitudes, rms)
		}
	}

	if len(pitchPeriods) < 3 {
		return result
	}

	result.Valid = true

	// Convert periods to frequencies for pitch stats
	pitchFreqs := make([]float64, len(pitchPeriods))
	for i, p := range pitchPeriods {
		pitchFreqs[i] = sampleRate / p
	}

	result.PitchMean = mean(pitchFreqs)
	result.PitchStdDev = stddev(pitchFreqs, result.PitchMean)

	// Jitter: average absolute difference between consecutive pitch periods / mean period
	meanPeriod := mean(pitchPeriods)
	if meanPeriod > 0 {
		jitterSum := 0.0
		for i := 1; i < len(pitchPeriods); i++ {
			jitterSum += math.Abs(pitchPeriods[i] - pitchPeriods[i-1])
		}
		result.Jitter = (jitterSum / float64(len(pitchPeriods)-1)) / meanPeriod
	}

	// Shimmer: average absolute difference between consecutive amplitudes / mean amplitude
	if len(amplitudes) >= 2 {
		meanAmp := mean(amplitudes)
		if meanAmp > 0 {
			shimmerSum := 0.0
			for i := 1; i < len(amplitudes); i++ {
				shimmerSum += math.Abs(amplitudes[i] - amplitudes[i-1])
			}
			result.Shimmer = (shimmerSum / float64(len(amplitudes)-1)) / meanAmp
		}
	}

	// HNR: Harmonics-to-Noise Ratio (dB) — estimated from autocorrelation peak
	result.HNR = estimateHNR(samples, sampleRate)

	return result
}

// autocorrelationPitch estimates the pitch period (in samples) of a windowed signal
// using normalized autocorrelation. Returns 0 if no clear pitch found.
func autocorrelationPitch(window []float64, sampleRate float64) float64 {
	n := len(window)
	minLag := int(sampleRate / 500) // max 500 Hz
	maxLag := int(sampleRate / 60)  // min 60 Hz

	if maxLag >= n {
		maxLag = n - 1
	}
	if minLag >= maxLag {
		return 0
	}

	// Compute energy
	energy := 0.0
	for _, s := range window {
		energy += s * s
	}
	if energy < 1e-10 {
		return 0
	}

	bestLag := 0
	bestCorr := 0.0

	for lag := minLag; lag <= maxLag; lag++ {
		corr := 0.0
		lagEnergy := 0.0
		for i := 0; i < n-lag; i++ {
			corr += window[i] * window[i+lag]
			lagEnergy += window[i+lag] * window[i+lag]
		}
		if lagEnergy < 1e-10 {
			continue
		}
		// Normalized correlation
		normCorr := corr / math.Sqrt(energy*lagEnergy)
		if normCorr > bestCorr {
			bestCorr = normCorr
			bestLag = lag
		}
	}

	// Require a minimum correlation to consider it voiced
	if bestCorr < 0.3 || bestLag == 0 {
		return 0
	}

	return float64(bestLag)
}

// estimateHNR estimates the Harmonics-to-Noise Ratio in dB.
func estimateHNR(samples []float64, sampleRate float64) float64 {
	n := len(samples)
	if n < 512 {
		return 0
	}

	// Use a central window
	start := n / 4
	end := start + 512
	if end > n {
		end = n
	}
	window := samples[start:end]

	period := autocorrelationPitch(window, sampleRate)
	if period == 0 {
		return 0
	}

	// Compute autocorrelation at the pitch period
	wn := len(window)
	lag := int(period)
	if lag >= wn {
		return 0
	}

	corr := 0.0
	energy := 0.0
	for i := 0; i < wn-lag; i++ {
		corr += window[i] * window[i+lag]
		energy += window[i] * window[i]
	}

	if energy < 1e-10 {
		return 0
	}

	r := corr / energy
	if r >= 1.0 {
		r = 0.999
	}
	if r <= 0 {
		return 0
	}

	// HNR = 10 * log10(r / (1 - r))
	return 10.0 * math.Log10(r/(1.0-r))
}

// ---------------------------------------------------------------------------
// MFCC Trajectory Smoothness (pure Go)
// ---------------------------------------------------------------------------

// mfccSmoothness computes a smoothness metric for MFCC trajectories.
// Synthetic speech tends to have unnaturally smooth MFCC transitions.
// Returns a value where lower = smoother (more suspicious).
func mfccSmoothness(data []byte) float64 {
	numSamples := len(data) / 2
	if numSamples < 512 {
		return -1 // not enough data
	}

	samples := pcmToFloat64(data)

	windowSize := 256
	hopSize := 128
	numCoeffs := 13
	numFilters := 26

	var mfccFrames [][]float64

	for start := 0; start+windowSize <= len(samples); start += hopSize {
		window := samples[start : start+windowSize]
		coeffs := computeMFCC(window, 16000.0, numCoeffs, numFilters)
		if coeffs != nil {
			mfccFrames = append(mfccFrames, coeffs)
		}
		if len(mfccFrames) >= 64 {
			break // enough frames for analysis
		}
	}

	if len(mfccFrames) < 4 {
		return -1
	}

	// Compute average frame-to-frame delta across all coefficients
	totalDelta := 0.0
	count := 0
	for i := 1; i < len(mfccFrames); i++ {
		for j := 1; j < numCoeffs; j++ { // skip c0 (energy)
			delta := math.Abs(mfccFrames[i][j] - mfccFrames[i-1][j])
			totalDelta += delta
			count++
		}
	}

	if count == 0 {
		return -1
	}

	return totalDelta / float64(count)
}

// computeMFCC computes Mel-Frequency Cepstral Coefficients for a single frame.
func computeMFCC(frame []float64, sampleRate float64, numCoeffs, numFilters int) []float64 {
	n := len(frame)
	if n < 16 {
		return nil
	}

	// Apply Hamming window
	windowed := make([]float64, n)
	for i := range frame {
		windowed[i] = frame[i] * (0.54 - 0.46*math.Cos(2.0*math.Pi*float64(i)/float64(n-1)))
	}

	// Compute power spectrum via DFT (half spectrum)
	halfN := n / 2
	powerSpec := make([]float64, halfN)
	for k := 0; k < halfN; k++ {
		realPart := 0.0
		imagPart := 0.0
		for i := 0; i < n; i++ {
			angle := -2.0 * math.Pi * float64(k) * float64(i) / float64(n)
			realPart += windowed[i] * math.Cos(angle)
			imagPart += windowed[i] * math.Sin(angle)
		}
		powerSpec[k] = (realPart*realPart + imagPart*imagPart) / float64(n)
	}

	// Mel filterbank
	melLow := hzToMel(0)
	melHigh := hzToMel(sampleRate / 2)
	melPoints := make([]float64, numFilters+2)
	for i := range melPoints {
		melPoints[i] = melLow + float64(i)*(melHigh-melLow)/float64(numFilters+1)
	}
	hzPoints := make([]float64, len(melPoints))
	for i, m := range melPoints {
		hzPoints[i] = melToHz(m)
	}
	binPoints := make([]int, len(hzPoints))
	for i, hz := range hzPoints {
		binPoints[i] = int(math.Floor(hz / sampleRate * float64(n)))
		if binPoints[i] >= halfN {
			binPoints[i] = halfN - 1
		}
	}

	// Apply filterbank
	filterEnergies := make([]float64, numFilters)
	for m := 0; m < numFilters; m++ {
		for k := binPoints[m]; k < binPoints[m+1]; k++ {
			if k >= halfN {
				break
			}
			denom := float64(binPoints[m+1] - binPoints[m])
			if denom > 0 {
				filterEnergies[m] += powerSpec[k] * float64(k-binPoints[m]) / denom
			}
		}
		for k := binPoints[m+1]; k < binPoints[m+2]; k++ {
			if k >= halfN {
				break
			}
			denom := float64(binPoints[m+2] - binPoints[m+1])
			if denom > 0 {
				filterEnergies[m] += powerSpec[k] * float64(binPoints[m+2]-k) / denom
			}
		}
		if filterEnergies[m] < 1e-10 {
			filterEnergies[m] = 1e-10
		}
		filterEnergies[m] = math.Log(filterEnergies[m])
	}

	// DCT to get MFCCs
	coeffs := make([]float64, numCoeffs)
	for i := 0; i < numCoeffs; i++ {
		for j := 0; j < numFilters; j++ {
			coeffs[i] += filterEnergies[j] * math.Cos(math.Pi*float64(i)*(float64(j)+0.5)/float64(numFilters))
		}
	}

	return coeffs
}

func hzToMel(hz float64) float64  { return 2595.0 * math.Log10(1.0+hz/700.0) }
func melToHz(mel float64) float64 { return 700.0 * (math.Pow(10.0, mel/2595.0) - 1.0) }

// ---------------------------------------------------------------------------
// Phase Coherence Analysis
// ---------------------------------------------------------------------------

// phaseCoherence measures inter-frame phase consistency.
// Most vocoders struggle with phase coherence; paradoxically, some produce
// unnaturally high coherence (neural vocoders) while others show discontinuities.
func phaseCoherence(data []byte) float64 {
	numSamples := len(data) / 2
	if numSamples < 512 {
		return -1
	}

	samples := pcmToFloat64(data)
	windowSize := 256
	hopSize := 128

	var prevPhases []float64
	var coherences []float64

	for start := 0; start+windowSize <= len(samples); start += hopSize {
		window := samples[start : start+windowSize]
		halfN := windowSize / 2
		phases := make([]float64, halfN)

		for k := 0; k < halfN; k++ {
			realPart := 0.0
			imagPart := 0.0
			for i := 0; i < windowSize; i++ {
				angle := -2.0 * math.Pi * float64(k) * float64(i) / float64(windowSize)
				realPart += window[i] * math.Cos(angle)
				imagPart += window[i] * math.Sin(angle)
			}
			phases[k] = math.Atan2(imagPart, realPart)
		}

		if prevPhases != nil {
			// Compute phase difference consistency
			consistent := 0
			total := 0
			expectedAdvance := 2.0 * math.Pi * float64(hopSize) / float64(windowSize)
			for k := 1; k < halfN; k++ {
				expected := prevPhases[k] + expectedAdvance*float64(k)
				diff := phases[k] - expected
				// Wrap to [-pi, pi]
				diff = math.Mod(diff+math.Pi, 2*math.Pi) - math.Pi
				if math.Abs(diff) < 0.5 {
					consistent++
				}
				total++
			}
			if total > 0 {
				coherences = append(coherences, float64(consistent)/float64(total))
			}
		}
		prevPhases = phases

		if len(coherences) >= 32 {
			break
		}
	}

	if len(coherences) == 0 {
		return -1
	}

	return mean(coherences)
}

// ---------------------------------------------------------------------------
// Core signal processing helpers
// ---------------------------------------------------------------------------

func pcmToFloat64(data []byte) []float64 {
	numSamples := len(data) / 2
	samples := make([]float64, numSamples)
	for i := 0; i < numSamples; i++ {
		samples[i] = float64(decodePCM16(data[i*2 : i*2+2]))
	}
	return samples
}

func decodePCM16(data []byte) int16 {
	// #nosec G115 -- PCM16 uses two's-complement bit reinterpretation by definition.
	return int16(binary.LittleEndian.Uint16(data))
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stddev(vals []float64, m float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	variance := 0.0
	for _, v := range vals {
		d := v - m
		variance += d * d
	}
	return math.Sqrt(variance / float64(len(vals)))
}

// byteEntropy computes Shannon entropy of a byte stream.
func byteEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, f := range freq {
		if f > 0 {
			p := f / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// estimateSpectralFlatness computes a spectral flatness estimate by interpreting
// raw bytes as 16-bit PCM samples and computing the ratio of geometric mean
// to arithmetic mean of the magnitude spectrum (via DFT on small windows).
func estimateSpectralFlatness(data []byte) float64 {
	numSamples := len(data) / 2
	if numSamples < 256 {
		return byteSpectralFlatness(data)
	}

	samples := pcmToFloat64(data)

	windowSize := 256
	if len(samples) < windowSize {
		windowSize = len(samples)
	}

	numWindows := len(samples) / windowSize
	if numWindows == 0 {
		numWindows = 1
	}
	if numWindows > 16 {
		numWindows = 16
	}

	totalFlatness := 0.0
	for w := 0; w < numWindows; w++ {
		offset := w * windowSize
		if offset+windowSize > len(samples) {
			break
		}
		window := samples[offset : offset+windowSize]

		halfN := windowSize / 2
		magnitudes := make([]float64, halfN)
		for k := 0; k < halfN; k++ {
			realPart := 0.0
			imagPart := 0.0
			for n := 0; n < windowSize; n++ {
				angle := -2.0 * math.Pi * float64(k) * float64(n) / float64(windowSize)
				realPart += window[n] * math.Cos(angle)
				imagPart += window[n] * math.Sin(angle)
			}
			magnitudes[k] = math.Sqrt(realPart*realPart+imagPart*imagPart) + 1e-10
		}

		logSum := 0.0
		arithSum := 0.0
		for _, m := range magnitudes {
			logSum += math.Log(m)
			arithSum += m
		}
		geoMean := math.Exp(logSum / float64(halfN))
		arithMean := arithSum / float64(halfN)

		if arithMean > 0 {
			totalFlatness += geoMean / arithMean
		}
	}

	return totalFlatness / float64(numWindows)
}

func byteSpectralFlatness(data []byte) float64 {
	if len(data) < 16 {
		return 0.5
	}
	logSum := 0.0
	arithSum := 0.0
	for _, b := range data {
		v := float64(b) + 1.0
		logSum += math.Log(v)
		arithSum += v
	}
	n := float64(len(data))
	geoMean := math.Exp(logSum / n)
	arithMean := arithSum / n
	if arithMean == 0 {
		return 0
	}
	return geoMean / arithMean
}

// silenceRatio estimates the fraction of the audio that is near-silent.
func silenceRatio(data []byte) float64 {
	numSamples := len(data) / 2
	if numSamples == 0 {
		return 0
	}

	silentCount := 0
	threshold := 500.0

	for i := 0; i < numSamples; i++ {
		sample := math.Abs(float64(decodePCM16(data[i*2 : i*2+2])))
		if sample < threshold {
			silentCount++
		}
	}

	return float64(silentCount) / float64(numSamples)
}

// zeroCrossingRate computes how often the signal crosses zero.
func zeroCrossingRate(data []byte) float64 {
	numSamples := len(data) / 2
	if numSamples < 2 {
		return 0
	}

	crossings := 0
	prevSample := decodePCM16(data[0:2])
	for i := 1; i < numSamples; i++ {
		sample := decodePCM16(data[i*2 : i*2+2])
		if (prevSample >= 0 && sample < 0) || (prevSample < 0 && sample >= 0) {
			crossings++
		}
		prevSample = sample
	}

	return float64(crossings) / float64(numSamples-1)
}

// checkBitrateConsistency checks if byte patterns repeat at suspiciously regular intervals.
func checkBitrateConsistency(data []byte) bool {
	if len(data) < 4096 {
		return false
	}

	frameSizes := []int{160, 320, 480, 640, 960, 1024, 2048}
	for _, frameSize := range frameSizes {
		if len(data) < frameSize*4 {
			continue
		}
		numFrames := len(data) / frameSize
		if numFrames > 32 {
			numFrames = 32
		}
		energies := make([]float64, numFrames)
		for f := 0; f < numFrames; f++ {
			offset := f * frameSize
			energy := 0.0
			for i := 0; i < frameSize && offset+i < len(data); i++ {
				energy += float64(data[offset+i]) * float64(data[offset+i])
			}
			energies[f] = energy / float64(frameSize)
		}

		m := mean(energies)
		if m > 0 {
			variance := 0.0
			for _, e := range energies {
				diff := e - m
				variance += diff * diff
			}
			variance /= float64(len(energies))
			cv := math.Sqrt(variance) / m
			if cv < 0.02 {
				return true
			}
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// Video Analysis — heuristic deepfake detection on raw frame bytes (no ML)
// ---------------------------------------------------------------------------

// VideoAnalyzer performs statistical analysis on video frame data.
type VideoAnalyzer struct{}

func NewVideoAnalyzer() *VideoAnalyzer { return &VideoAnalyzer{} }

// VideoResult holds the results of heuristic video analysis.
type VideoResult struct {
	Score      float64
	Indicators []string
}

// Analyze performs heuristic analysis on raw video frame bytes.
// Checks temporal consistency, frame entropy patterns, metadata anomalies,
// and Error Level Analysis (ELA) for compression artifact detection.
func (v *VideoAnalyzer) Analyze(frames [][]byte, metadata map[string]interface{}) VideoResult {
	result := VideoResult{}

	if len(frames) == 0 {
		return result
	}

	// 1. Frame entropy consistency
	if len(frames) >= 3 {
		entropies := make([]float64, len(frames))
		for i, frame := range frames {
			entropies[i] = byteEntropy(frame)
		}

		m := mean(entropies)
		if m > 0 {
			sd := stddev(entropies, m)
			cv := sd / m
			if cv < 0.01 {
				result.Score += 0.25
				result.Indicators = append(result.Indicators, fmt.Sprintf("unnaturally consistent frame entropy (CV=%.4f)", cv))
			} else if cv < 0.03 {
				result.Score += 0.10
				result.Indicators = append(result.Indicators, fmt.Sprintf("low frame entropy variation (CV=%.4f)", cv))
			}
		}
	}

	// 2. Inter-frame difference analysis
	if len(frames) >= 2 {
		diffs := make([]float64, 0, len(frames)-1)
		for i := 1; i < len(frames); i++ {
			d := frameDifference(frames[i-1], frames[i])
			diffs = append(diffs, d)
		}

		if len(diffs) >= 2 {
			m := mean(diffs)
			if m > 0 {
				sd := stddev(diffs, m)
				cv := sd / m
				if cv < 0.05 {
					result.Score += 0.20
					result.Indicators = append(result.Indicators, "unnaturally uniform frame transitions")
				}
			}
			if m < 0.5 {
				result.Score += 0.15
				result.Indicators = append(result.Indicators, "suspiciously low inter-frame variation")
			}
		}
	}

	// 3. Metadata anomaly checks
	if metadata != nil {
		if codec, ok := metadata["codec"].(string); ok {
			codec = strings.ToLower(codec)
			suspiciousCodecs := []string{"rawvideo", "ffv1", "lagarith", "utvideo", "huffyuv"}
			for _, sc := range suspiciousCodecs {
				if strings.Contains(codec, sc) {
					result.Score += 0.10
					result.Indicators = append(result.Indicators, fmt.Sprintf("unusual codec: %s", codec))
					break
				}
			}

			// Container/codec mismatch detection
			if container, ok := metadata["container"].(string); ok {
				container = strings.ToLower(container)
				if (container == "mp4" || container == "mov") && (codec == "rawvideo" || codec == "huffyuv") {
					result.Score += 0.10
					result.Indicators = append(result.Indicators, fmt.Sprintf("container/codec mismatch: %s in %s", codec, container))
				}
			}
		}

		if faceRes, ok := metadata["face_resolution"].(float64); ok {
			if frameRes, ok := metadata["frame_resolution"].(float64); ok {
				if faceRes > 0 && frameRes > 0 {
					ratio := faceRes / frameRes
					if ratio < 0.3 || ratio > 3.0 {
						result.Score += 0.15
						result.Indicators = append(result.Indicators, "face/frame resolution mismatch")
					}
				}
			}
		}

		if fps, ok := metadata["fps"].(float64); ok {
			standardFPS := []float64{23.976, 24, 25, 29.97, 30, 50, 59.94, 60}
			isStandard := false
			for _, std := range standardFPS {
				if math.Abs(fps-std) < 0.1 {
					isStandard = true
					break
				}
			}
			if !isStandard && fps > 0 {
				result.Score += 0.10
				result.Indicators = append(result.Indicators, fmt.Sprintf("non-standard frame rate: %.2f", fps))
			}
		}
	}

	// 4. ELA-style analysis: compare entropy of sub-regions within frames
	// Manipulated regions show different statistical properties than surrounding areas
	if len(frames) > 0 && len(frames[0]) >= 256 {
		elaScore := elaAnalysis(frames[0])
		if elaScore > 0.7 {
			result.Score += 0.15
			result.Indicators = append(result.Indicators, fmt.Sprintf("ELA anomaly detected (score=%.3f)", elaScore))
		}
	}

	if result.Score > 1.0 {
		result.Score = 1.0
	}
	return result
}

// elaAnalysis performs a simplified Error Level Analysis on frame bytes.
// Divides the frame into blocks and checks for entropy variance anomalies.
func elaAnalysis(frame []byte) float64 {
	blockSize := 64
	if len(frame) < blockSize*4 {
		return 0
	}

	numBlocks := len(frame) / blockSize
	if numBlocks > 64 {
		numBlocks = 64
	}

	entropies := make([]float64, numBlocks)
	for i := 0; i < numBlocks; i++ {
		start := i * blockSize
		end := start + blockSize
		if end > len(frame) {
			break
		}
		entropies[i] = byteEntropy(frame[start:end])
	}

	m := mean(entropies)
	if m == 0 {
		return 0
	}

	// Look for blocks that deviate significantly from the mean
	outliers := 0
	for _, e := range entropies {
		if math.Abs(e-m) > 2.0 {
			outliers++
		}
	}

	return float64(outliers) / float64(numBlocks)
}

// frameDifference computes the mean absolute difference between two frames.
func frameDifference(a, b []byte) float64 {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	if minLen == 0 {
		return 0
	}

	totalDiff := 0.0
	for i := 0; i < minLen; i++ {
		totalDiff += math.Abs(float64(a[i]) - float64(b[i]))
	}
	return totalDiff / float64(minLen)
}

// ---------------------------------------------------------------------------
// Event Handlers
// ---------------------------------------------------------------------------

func (s *Shield) handleAudioEvent(event *core.SecurityEvent) {
	callerID := getStringDetail(event, "caller_id")
	claimedIdentity := getStringDetail(event, "claimed_identity")

	audioResult := s.audioAnal.Analyze(event.RawData)

	metaScore := 0.0
	sampleRate := getFloatDetail(event, "sample_rate")
	if sampleRate > 0 && sampleRate != 8000 && sampleRate != 16000 && sampleRate != 22050 && sampleRate != 44100 && sampleRate != 48000 {
		metaScore += 0.15
		audioResult.Indicators = append(audioResult.Indicators, fmt.Sprintf("unusual sample rate: %.0f Hz", sampleRate))
	}

	// Duration checks
	duration := getFloatDetail(event, "duration_seconds")
	if duration > 0 && duration < 1.0 {
		metaScore += 0.10
		audioResult.Indicators = append(audioResult.Indicators, "very short audio clip (<1s)")
	}

	if claimedIdentity != "" {
		pattern := s.commTracker.GetPattern(claimedIdentity)
		if pattern != nil && callerID != "" && callerID != pattern.UsualCallerID {
			metaScore += 0.25
			audioResult.Indicators = append(audioResult.Indicators, "caller ID mismatch for claimed identity")
		}
	}

	totalScore := audioResult.Score + metaScore
	if totalScore > 1.0 {
		totalScore = 1.0
	}

	if totalScore >= 0.4 {
		severity := core.SeverityMedium
		if totalScore >= 0.7 {
			severity = core.SeverityCritical
		} else if totalScore >= 0.5 {
			severity = core.SeverityHigh
		}
		s.raiseAlert(event, severity,
			"Potential Deepfake Audio Detected",
			fmt.Sprintf("Audio from %s (claiming to be %s) has synthetic indicators (score: %.2f). Indicators: %s",
				callerID, claimedIdentity, totalScore, strings.Join(audioResult.Indicators, "; ")),
			"deepfake_audio")
	}
}

func (s *Shield) handleVideoEvent(event *core.SecurityEvent) {
	var frames [][]byte
	if event.RawData != nil && len(event.RawData) > 0 {
		frames = [][]byte{event.RawData}
	}
	if frameData, ok := event.Details["frames"].([]interface{}); ok {
		for _, f := range frameData {
			if bs, ok := f.([]byte); ok {
				frames = append(frames, bs)
			}
		}
	}

	videoResult := s.videoAnal.Analyze(frames, event.Details)

	claimedIdentity := getStringDetail(event, "claimed_identity")
	if claimedIdentity != "" {
		pattern := s.commTracker.GetPattern(claimedIdentity)
		if pattern != nil {
			channel := getStringDetail(event, "channel")
			if channel != "" && channel != pattern.UsualChannel {
				videoResult.Score += 0.15
				videoResult.Indicators = append(videoResult.Indicators, "unusual communication channel for claimed identity")
			}
		}
	}

	if videoResult.Score > 1.0 {
		videoResult.Score = 1.0
	}

	if videoResult.Score >= 0.4 {
		severity := core.SeverityMedium
		if videoResult.Score >= 0.7 {
			severity = core.SeverityCritical
		} else if videoResult.Score >= 0.5 {
			severity = core.SeverityHigh
		}
		s.raiseAlert(event, severity,
			"Potential Deepfake Video Detected",
			fmt.Sprintf("Video content has synthetic indicators (score: %.2f). Indicators: %s",
				videoResult.Score, strings.Join(videoResult.Indicators, "; ")),
			"deepfake_video")
	}
}

func (s *Shield) handleCommunicationEvent(event *core.SecurityEvent) {
	sender := getStringDetail(event, "sender")
	subject := getStringDetail(event, "subject")
	body := getStringDetail(event, "body")
	domain := getStringDetail(event, "sender_domain")
	headers := getStringDetail(event, "headers")
	messageID := getStringDetail(event, "message_id")
	inReplyTo := getStringDetail(event, "in_reply_to")
	references := getStringDetail(event, "references")
	quotedContent := getStringDetail(event, "quoted_content")

	if sender == "" && body == "" {
		return
	}

	// AI phishing detection (regex + writing style)
	phishScore := s.phishDet.Analyze(sender, subject, body, headers)
	if phishScore.IsPhishing {
		severity := core.SeverityHigh
		if phishScore.Score >= 0.8 {
			severity = core.SeverityCritical
		}
		s.raiseAlert(event, severity,
			"AI-Generated Phishing Detected",
			fmt.Sprintf("Email from %s flagged as AI-generated phishing (score: %.2f). Indicators: %s",
				sender, phishScore.Score, strings.Join(phishScore.Indicators, ", ")),
			"ai_phishing")
	}

	// Reply-chain verification
	if inReplyTo != "" || strings.HasPrefix(strings.ToLower(subject), "re:") {
		chainResult := verifyReplyChain(messageID, inReplyTo, references, quotedContent, headers)
		if chainResult.Suspicious {
			s.raiseAlert(event, core.SeverityHigh,
				"Reply-Chain Anomaly Detected",
				fmt.Sprintf("Email from %s has reply-chain inconsistencies: %s",
					sender, strings.Join(chainResult.Indicators, ", ")),
				"reply_chain_anomaly")
		}
	}

	// Domain spoofing check
	if domain != "" {
		if spoof := s.domainCheck.Check(domain); spoof != "" {
			s.raiseAlert(event, core.SeverityHigh,
				"Domain Spoofing Detected",
				fmt.Sprintf("Sender domain %q appears to spoof legitimate domain %q using homoglyph or similar techniques.",
					domain, spoof),
				"domain_spoof")
		}
	}

	// Track communication patterns (including writing style baseline)
	if sender != "" {
		s.commTracker.RecordCommunication(sender, event.SourceIP)
		if body != "" {
			s.commTracker.RecordWritingStyle(sender, body)
		}
	}
}

func (s *Shield) handleHighValueRequest(event *core.SecurityEvent) {
	requester := getStringDetail(event, "requester")
	requestType := getStringDetail(event, "request_type")
	amount := getFloatDetail(event, "amount")
	urgency := getStringDetail(event, "urgency")
	channel := getStringDetail(event, "channel")

	riskScore := 0.0

	if urgency == "high" || urgency == "critical" || urgency == "immediate" {
		riskScore += 0.3
	}

	if amount > 10000 {
		riskScore += 0.2
	}
	if amount > 100000 {
		riskScore += 0.2
	}

	pattern := s.commTracker.GetPattern(requester)
	if pattern != nil {
		if !pattern.TypicalRequestTypes[requestType] {
			riskScore += 0.2
		}
		if channel != "" && channel != pattern.UsualChannel {
			riskScore += 0.2
		}
	} else {
		riskScore += 0.3
	}

	if riskScore >= 0.5 {
		severity := core.SeverityHigh
		if riskScore >= 0.7 {
			severity = core.SeverityCritical
		}
		s.raiseAlert(event, severity,
			"Suspicious High-Value Request",
			fmt.Sprintf("Request from %s for %s (amount: $%.2f) has BEC/deepfake risk indicators (score: %.2f). Verify identity through a separate channel.",
				requester, requestType, amount, riskScore),
			"suspicious_request")
	}
}

func (s *Shield) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if s.bus != nil {
		_ = s.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getDeepfakeMitigations(alertType)
	if s.pipeline != nil {
		s.pipeline.Process(alert)
	}
}

// ---------------------------------------------------------------------------
// Reply-Chain Verification
// ---------------------------------------------------------------------------

// ReplyChainResult holds the result of reply-chain analysis.
type ReplyChainResult struct {
	Suspicious bool
	Indicators []string
}

// verifyReplyChain checks for thread hijacking indicators.
func verifyReplyChain(messageID, inReplyTo, references, quotedContent, headers string) ReplyChainResult {
	result := ReplyChainResult{}

	// Check if reply claims a parent but has no References header
	if inReplyTo != "" && references == "" {
		result.Suspicious = true
		result.Indicators = append(result.Indicators, "In-Reply-To set but no References header")
	}

	// Check if In-Reply-To is not in References chain
	if inReplyTo != "" && references != "" {
		if !strings.Contains(references, inReplyTo) {
			result.Suspicious = true
			result.Indicators = append(result.Indicators, "In-Reply-To not found in References chain")
		}
	}

	// Check for quoted content that looks fabricated (very short or generic)
	if quotedContent != "" {
		lines := strings.Split(quotedContent, "\n")
		quotedLines := 0
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), ">") {
				quotedLines++
			}
		}
		if quotedLines == 0 && strings.Contains(strings.ToLower(quotedContent), "original message") {
			result.Indicators = append(result.Indicators, "claims to quote original message but no quoted lines found")
			result.Suspicious = true
		}
	}

	// Check for header injection patterns
	if headers != "" {
		headerLower := strings.ToLower(headers)
		// Multiple From headers
		if strings.Count(headerLower, "\nfrom:") > 1 {
			result.Suspicious = true
			result.Indicators = append(result.Indicators, "multiple From headers detected")
		}
		// Received chain with impossible geographic hops (simplified check)
		receivedCount := strings.Count(headerLower, "\nreceived:")
		if receivedCount > 15 {
			result.Indicators = append(result.Indicators, fmt.Sprintf("unusually long Received chain (%d hops)", receivedCount))
			result.Suspicious = true
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// Communication Pattern Tracker (enhanced with writing style baselines)
// ---------------------------------------------------------------------------

// CommunicationTracker tracks communication patterns per identity.
type CommunicationTracker struct {
	mu       sync.RWMutex
	patterns map[string]*CommPattern
}

// CommPattern holds communication baseline data for an identity.
type CommPattern struct {
	Identity            string
	UsualCallerID       string
	UsualChannel        string
	UsualIPs            map[string]bool
	TypicalRequestTypes map[string]bool
	LastSeen            time.Time
	MessageCount        int
	// Writing style baseline
	AvgSentenceLen float64
	AvgWordLen     float64
	VocabRichness  float64 // type-token ratio
	PuncDensity    float64
	StyleSamples   int
}

func NewCommunicationTracker() *CommunicationTracker {
	return &CommunicationTracker{patterns: make(map[string]*CommPattern)}
}

func (ct *CommunicationTracker) RecordCommunication(identity, ip string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	p, exists := ct.patterns[identity]
	if !exists {
		p = &CommPattern{
			Identity:            identity,
			UsualIPs:            make(map[string]bool),
			TypicalRequestTypes: make(map[string]bool),
		}
		ct.patterns[identity] = p
	}
	if ip != "" {
		p.UsualIPs[ip] = true
	}
	p.LastSeen = time.Now()
	p.MessageCount++
}

// RecordWritingStyle updates the writing style baseline for an identity.
func (ct *CommunicationTracker) RecordWritingStyle(identity, body string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	p, exists := ct.patterns[identity]
	if !exists {
		return
	}

	stats := analyzeWritingStyle(body)
	n := float64(p.StyleSamples)
	p.AvgSentenceLen = (p.AvgSentenceLen*n + stats.AvgSentenceLen) / (n + 1)
	p.AvgWordLen = (p.AvgWordLen*n + stats.AvgWordLen) / (n + 1)
	p.VocabRichness = (p.VocabRichness*n + stats.VocabRichness) / (n + 1)
	p.PuncDensity = (p.PuncDensity*n + stats.PuncDensity) / (n + 1)
	p.StyleSamples++
}

func (ct *CommunicationTracker) GetPattern(identity string) *CommPattern {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.patterns[identity]
}

func (ct *CommunicationTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ct.mu.Lock()
			cutoff := time.Now().Add(-30 * 24 * time.Hour)
			for id, p := range ct.patterns {
				if p.LastSeen.Before(cutoff) {
					delete(ct.patterns, id)
				}
			}
			ct.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// Writing Style Analysis
// ---------------------------------------------------------------------------

// WritingStyleStats holds statistical features of text.
type WritingStyleStats struct {
	AvgSentenceLen float64
	AvgWordLen     float64
	VocabRichness  float64 // type-token ratio
	PuncDensity    float64
}

// analyzeWritingStyle computes statistical features of text for style comparison.
func analyzeWritingStyle(text string) WritingStyleStats {
	stats := WritingStyleStats{}
	if len(text) < 10 {
		return stats
	}

	// Sentence count (split on . ! ?)
	sentences := regexp.MustCompile(`[.!?]+`).Split(text, -1)
	sentCount := 0
	totalWords := 0
	wordSet := make(map[string]bool)
	totalWordLen := 0
	puncCount := 0

	for _, sent := range sentences {
		words := strings.Fields(strings.TrimSpace(sent))
		if len(words) == 0 {
			continue
		}
		sentCount++
		totalWords += len(words)
		for _, w := range words {
			clean := strings.ToLower(strings.Trim(w, ".,;:!?\"'()[]{}"))
			if clean != "" {
				wordSet[clean] = true
				totalWordLen += len(clean)
			}
		}
	}

	for _, r := range text {
		if unicode.IsPunct(r) {
			puncCount++
		}
	}

	if sentCount > 0 {
		stats.AvgSentenceLen = float64(totalWords) / float64(sentCount)
	}
	if totalWords > 0 {
		stats.AvgWordLen = float64(totalWordLen) / float64(totalWords)
		stats.VocabRichness = float64(len(wordSet)) / float64(totalWords)
	}
	if len(text) > 0 {
		stats.PuncDensity = float64(puncCount) / float64(len(text))
	}

	return stats
}

// ---------------------------------------------------------------------------
// AI Phishing Detector (regex + writing style analysis)
// ---------------------------------------------------------------------------

// AIPhishingDetector analyzes emails for AI-generated phishing indicators.
type AIPhishingDetector struct {
	urgencyPatterns *regexp.Regexp
	impersonation   *regexp.Regexp
	actionPatterns  *regexp.Regexp
	threatPatterns  *regexp.Regexp
}

// PhishingScore holds the result of phishing analysis.
type PhishingScore struct {
	Score      float64
	IsPhishing bool
	Indicators []string
}

func NewAIPhishingDetector() *AIPhishingDetector {
	return &AIPhishingDetector{
		urgencyPatterns: regexp.MustCompile(`(?i)(urgent|immediate\s+action|act\s+now|expires?\s+today|within\s+\d+\s+hours?|time.?sensitive|asap|right\s+away|don'?t\s+delay)`),
		impersonation:   regexp.MustCompile(`(?i)(ceo|cfo|cto|chief|director|president|vice\s+president|board\s+member|it\s+department|helpdesk|support\s+team|security\s+team)`),
		actionPatterns:  regexp.MustCompile(`(?i)(click\s+(here|this\s+link|below)|download\s+the\s+attachment|verify\s+your\s+(account|identity|password)|update\s+your\s+(payment|billing)|confirm\s+your\s+(details|information)|wire\s+transfer|send\s+funds)`),
		threatPatterns:  regexp.MustCompile(`(?i)(account\s+(will\s+be\s+)?(suspended|terminated|locked|closed)|legal\s+action|unauthorized\s+access\s+detected|security\s+breach|compromised|violation)`),
	}
}

func (d *AIPhishingDetector) Analyze(sender, subject, body, headers string) PhishingScore {
	result := PhishingScore{}
	combined := subject + " " + body

	if d.urgencyPatterns.MatchString(combined) {
		result.Score += 0.2
		result.Indicators = append(result.Indicators, "urgency language")
	}

	if d.impersonation.MatchString(combined) {
		result.Score += 0.2
		result.Indicators = append(result.Indicators, "executive impersonation")
	}

	if d.actionPatterns.MatchString(combined) {
		result.Score += 0.25
		result.Indicators = append(result.Indicators, "suspicious call-to-action")
	}

	if d.threatPatterns.MatchString(combined) {
		result.Score += 0.2
		result.Indicators = append(result.Indicators, "threat/fear language")
	}

	// Display name impersonation
	if sender != "" && strings.Contains(sender, "<") {
		parts := strings.SplitN(sender, "<", 2)
		if len(parts) == 2 {
			displayName := strings.ToLower(strings.TrimSpace(parts[0]))
			if d.impersonation.MatchString(displayName) {
				result.Score += 0.15
				result.Indicators = append(result.Indicators, "display name impersonation")
			}
		}
	}

	// Header analysis (expanded: DKIM, SPF, DMARC, ARC)
	if headers != "" {
		headerLower := strings.ToLower(headers)
		if !strings.Contains(headerLower, "dkim=pass") {
			result.Score += 0.1
			result.Indicators = append(result.Indicators, "missing DKIM")
		}
		if !strings.Contains(headerLower, "spf=pass") {
			result.Score += 0.1
			result.Indicators = append(result.Indicators, "missing SPF")
		}
		if strings.Contains(headerLower, "dmarc=fail") {
			result.Score += 0.2
			result.Indicators = append(result.Indicators, "DMARC failure")
		}
		// ARC validation
		if strings.Contains(headerLower, "arc-seal") && strings.Contains(headerLower, "cv=fail") {
			result.Score += 0.15
			result.Indicators = append(result.Indicators, "ARC chain validation failure")
		}
	}

	// Writing style anomaly: AI-generated text tends to have very uniform sentence
	// lengths and high vocabulary richness
	if len(body) > 100 {
		style := analyzeWritingStyle(body)
		// AI text often has very consistent sentence lengths (low variance)
		// and unusually high type-token ratio for short texts
		if style.VocabRichness > 0.85 && style.AvgSentenceLen > 15 {
			result.Score += 0.10
			result.Indicators = append(result.Indicators, "writing style consistent with AI generation")
		}
	}

	result.Score = math.Min(result.Score, 1.0)
	result.IsPhishing = result.Score >= 0.5

	return result
}

// ---------------------------------------------------------------------------
// Domain Spoof Checker (expanded Unicode confusables + Punycode + configurable)
// ---------------------------------------------------------------------------

// DomainSpoofChecker detects homoglyph, Punycode, and typosquatting domain spoofing.
type DomainSpoofChecker struct {
	trustedDomains []string
	homoglyphs     map[rune]rune
	maxLevenshtein int
}

func NewDomainSpoofChecker(settings map[string]interface{}) *DomainSpoofChecker {
	dc := &DomainSpoofChecker{
		maxLevenshtein: 2,
		homoglyphs: map[rune]rune{
			// Cyrillic
			'\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
			'\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
			'\u0501': 'd', '\u050D': 'n', '\u0455': 's', '\u0460': 'w',
			'\u04BB': 'h', '\u0458': 'j', '\u043A': 'k', '\u043C': 'm',
			'\u0442': 't', '\u0432': 'v', '\u0437': 'z',
			// Greek
			'\u03B1': 'a', '\u03B5': 'e', '\u03BF': 'o', '\u03C1': 'p',
			'\u03B9': 'i', '\u03BA': 'k', '\u03BD': 'v', '\u03C4': 't',
			'\u03C5': 'u', '\u03C9': 'w',
			// Latin extended / look-alikes
			'\u0131': 'i', '\u0142': 'l', '\u00F0': 'd', '\u00F8': 'o',
			'\u0111': 'd', '\u0127': 'h',
			// Fullwidth
			'\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd',
			'\uFF45': 'e', '\uFF46': 'f', '\uFF47': 'g',
		},
	}

	// Default trusted domains
	dc.trustedDomains = []string{
		"google.com", "microsoft.com", "apple.com", "amazon.com",
		"github.com", "gitlab.com", "slack.com", "zoom.us",
		"dropbox.com", "salesforce.com", "oracle.com", "adobe.com",
		"paypal.com", "stripe.com", "twilio.com",
	}

	// Load custom trusted domains from config
	if settings != nil {
		if domains, ok := settings["trusted_domains"].([]interface{}); ok {
			for _, d := range domains {
				if ds, ok := d.(string); ok && ds != "" {
					dc.trustedDomains = append(dc.trustedDomains, ds)
				}
			}
		}
		if maxLev, ok := settings["max_levenshtein"].(int); ok && maxLev > 0 {
			dc.maxLevenshtein = maxLev
		}
		if maxLev, ok := settings["max_levenshtein"].(float64); ok && maxLev > 0 {
			dc.maxLevenshtein = int(maxLev)
		}
	}

	return dc
}

func (dc *DomainSpoofChecker) Check(domain string) string {
	normalized := dc.normalizeHomoglyphs(strings.ToLower(domain))

	// Punycode detection: decode xn-- prefixed domains
	if strings.HasPrefix(strings.ToLower(domain), "xn--") {
		decoded := decodePunycode(domain)
		if decoded != domain {
			normalized = dc.normalizeHomoglyphs(strings.ToLower(decoded))
		}
	}

	for _, trusted := range dc.trustedDomains {
		if domain == trusted {
			continue
		}
		// Exact match after normalization
		if normalized == trusted && domain != trusted {
			return trusted
		}
		// Levenshtein distance check (configurable, default 2)
		dist := levenshtein(normalized, trusted)
		if dist > 0 && dist <= dc.maxLevenshtein {
			return trusted
		}
		// TLD swap detection
		if isTLDSwap(normalized, trusted) {
			return trusted
		}
	}
	return ""
}

// isTLDSwap checks if two domains differ only in their TLD.
func isTLDSwap(domain, trusted string) bool {
	dParts := strings.SplitN(domain, ".", 2)
	tParts := strings.SplitN(trusted, ".", 2)
	if len(dParts) != 2 || len(tParts) != 2 {
		return false
	}
	if dParts[0] == tParts[0] && dParts[1] != tParts[1] {
		// Check common confusable TLDs
		confusableTLDs := map[string][]string{
			"com": {"co", "cm", "corn", "con", "om", "comm"},
			"org": {"og", "orq"},
			"net": {"ner", "met"},
		}
		if confusables, ok := confusableTLDs[tParts[1]]; ok {
			for _, c := range confusables {
				if dParts[1] == c {
					return true
				}
			}
		}
	}
	return false
}

func (dc *DomainSpoofChecker) normalizeHomoglyphs(s string) string {
	var result []rune
	for _, r := range s {
		if replacement, ok := dc.homoglyphs[r]; ok {
			result = append(result, replacement)
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}

// decodePunycode performs basic Punycode decoding for xn-- domains.
// This is a simplified decoder for the most common cases.
func decodePunycode(encoded string) string {
	parts := strings.Split(encoded, ".")
	var decoded []string
	for _, part := range parts {
		if strings.HasPrefix(strings.ToLower(part), "xn--") {
			d := decodePunycodePart(part[4:])
			if d != "" {
				decoded = append(decoded, d)
				continue
			}
		}
		decoded = append(decoded, part)
	}
	return strings.Join(decoded, ".")
}

// decodePunycodePart decodes a single Punycode label (without the xn-- prefix).
func decodePunycodePart(input string) string {
	const (
		base        = 36
		tmin        = 1
		tmax        = 26
		skew        = 38
		damp        = 700
		initialBias = 72
		initialN    = 128
	)

	// Find the last delimiter
	lastDelim := strings.LastIndex(input, "-")
	var output []rune
	pos := 0
	if lastDelim >= 0 {
		for _, r := range input[:lastDelim] {
			output = append(output, r)
		}
		pos = lastDelim + 1
	}

	n := initialN
	i := 0
	bias := initialBias

	for pos < len(input) {
		oldi := i
		w := 1
		for k := base; ; k += base {
			if pos >= len(input) {
				return "" // invalid
			}
			digit := punycodeDigit(rune(input[pos]))
			pos++
			if digit < 0 {
				return ""
			}
			i += digit * w
			t := k - bias
			if t < tmin {
				t = tmin
			}
			if t > tmax {
				t = tmax
			}
			if digit < t {
				break
			}
			w *= base - t
		}

		outLen := len(output) + 1
		bias = punycodeAdapt(i-oldi, outLen, oldi == 0)
		n += i / outLen
		i = i % outLen
		if n > unicode.MaxRune || (n >= 0xD800 && n <= 0xDFFF) {
			return ""
		}

		// Insert character at position i
		newOutput := make([]rune, len(output)+1)
		copy(newOutput, output[:i])
		// #nosec G115 -- n is constrained to valid Unicode scalar values above.
		newOutput[i] = rune(n)
		copy(newOutput[i+1:], output[i:])
		output = newOutput
		i++
	}

	return string(output)
}

func punycodeDigit(r rune) int {
	if r >= 'a' && r <= 'z' {
		return int(r - 'a')
	}
	if r >= 'A' && r <= 'Z' {
		return int(r - 'A')
	}
	if r >= '0' && r <= '9' {
		return int(r-'0') + 26
	}
	return -1
}

func punycodeAdapt(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= 700
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > 455 { // (base-tmin)*tmax/2
		delta /= 35 // base - tmin
		k += 36
	}
	return k + 36*delta/(delta+38)
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	matrix := make([][]int, la+1)
	for i := range matrix {
		matrix[i] = make([]int, lb+1)
		matrix[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		matrix[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = minInt(matrix[i-1][j]+1, minInt(matrix[i][j-1]+1, matrix[i-1][j-1]+cost))
		}
	}
	return matrix[la][lb]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
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

func getFloatDetail(event *core.SecurityEvent, key string) float64 {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
}

// getDeepfakeMitigations returns context-specific mitigations based on alert type.
func getDeepfakeMitigations(alertType string) []string {
	switch alertType {
	case "audio_deepfake", "audio_deepfake_high_confidence":
		return []string{
			"Verify the speaker's identity through a separate, trusted communication channel",
			"Use voice biometric verification with liveness detection",
			"Never approve financial transactions based solely on voice requests",
			"Implement callback verification for voice-initiated requests",
		}
	case "video_deepfake", "video_deepfake_high_confidence":
		return []string{
			"Verify identity through a separate channel — do not trust video alone",
			"Look for visual artifacts: inconsistent lighting, blurring around face edges",
			"Implement multi-factor verification for video-based approvals",
			"Use certified video conferencing platforms with deepfake detection",
		}
	case "ai_phishing", "ai_phishing_high_confidence":
		return []string{
			"Check email headers for SPF, DKIM, and DMARC authentication failures",
			"Verify sender identity through a known, trusted contact method",
			"Report the email to your security team for analysis",
			"Do not click links or download attachments from suspicious emails",
		}
	case "domain_spoof":
		return []string{
			"Verify the sender domain against known trusted domains",
			"Check for homoglyph substitutions and punycode in domain names",
			"Implement domain allowlisting for sensitive communications",
		}
	case "reply_chain_hijack":
		return []string{
			"Verify the conversation thread through a separate channel",
			"Check email headers for thread integrity (References, In-Reply-To)",
			"Be suspicious of urgent requests in existing email threads",
		}
	case "writing_style_anomaly":
		return []string{
			"Compare the message style against known communication patterns",
			"Verify the sender's identity through a separate channel",
			"Flag messages with significant style deviations for manual review",
		}
	case "high_value_deepfake_risk":
		return []string{
			"Implement multi-person approval for high-value transactions",
			"Require in-person or multi-factor verification for financial requests",
			"Never approve wire transfers based solely on voice or video requests",
			"Establish code words or verification protocols for sensitive operations",
		}
	case "communication_pattern_anomaly":
		return []string{
			"Investigate unusual communication patterns from known identities",
			"Check for account compromise indicators",
			"Verify the sender through an independent channel",
		}
	default:
		return []string{
			"Verify the identity through a separate, trusted communication channel",
			"Never approve financial transactions based solely on voice/video requests",
			"Report suspected deepfake attempts to your security team",
		}
	}
}
