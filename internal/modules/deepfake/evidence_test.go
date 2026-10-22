package deepfake

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

func TestEncodedAudioIsNotInterpretedAsPCM(t *testing.T) {
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
	s := startedShield(t, pipeline)
	ev := core.NewSecurityEvent("collector", "audio_upload", core.SeverityInfo, "upload")
	ev.RawData = make([]byte, 8192)
	copy(ev.RawData, "ID3")
	ev.Details["content_type"] = "audio/mpeg"
	s.HandleEvent(ev)
	if alerts := pipeline.GetAlerts(core.SeverityInfo, 100); len(alerts) != 1 || alerts[0].Type != "audio_analysis_unavailable" || alerts[0].Severity != core.SeverityInfo {
		t.Fatalf("compressed bytes must produce an unavailable status, not a synthetic speech finding: %+v", alerts)
	}
}

func pcmWAVE(pcm []byte) []byte {
	raw := make([]byte, 44+len(pcm))
	copy(raw, "RIFF")
	binary.LittleEndian.PutUint32(raw[4:], uint32(len(raw)-8))
	copy(raw[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(raw[16:], 16)
	binary.LittleEndian.PutUint16(raw[20:], 1)
	binary.LittleEndian.PutUint16(raw[22:], 1)
	binary.LittleEndian.PutUint32(raw[24:], 16000)
	binary.LittleEndian.PutUint32(raw[28:], 32000)
	binary.LittleEndian.PutUint16(raw[32:], 2)
	binary.LittleEndian.PutUint16(raw[34:], 16)
	copy(raw[36:], "data")
	binary.LittleEndian.PutUint32(raw[40:], uint32(len(pcm)))
	copy(raw[44:], pcm)
	return raw
}

func TestAudioFormatValidation(t *testing.T) {
	pcm := make([]byte, 4096)
	for _, tt := range []struct {
		name   string
		mutate func([]byte) []byte
		valid  bool
	}{
		{"PCM WAVE", func(raw []byte) []byte { return raw }, true},
		{"truncated", func(raw []byte) []byte { return raw[:50] }, false},
		{"unsupported stereo", func(raw []byte) []byte { raw[22] = 2; return raw }, false},
		{"unsupported sample rate", func(raw []byte) []byte { binary.LittleEndian.PutUint32(raw[24:], 48000); return raw }, false},
		{"invalid alignment", func(raw []byte) []byte { raw[32] = 4; return raw }, false},
		{"overflowing chunk", func(raw []byte) []byte { binary.LittleEndian.PutUint32(raw[40:], math.MaxUint32); return raw }, false},
		{"odd sample bytes", func(raw []byte) []byte { binary.LittleEndian.PutUint32(raw[40:], 4095); return raw }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ev := core.NewSecurityEvent("test", "audio_upload", core.SeverityInfo, "audio")
			ev.RawData = tt.mutate(pcmWAVE(pcm))
			got, err := audioPCM(ev)
			if (err == nil) != tt.valid || (tt.valid && !bytes.Equal(got, pcm)) {
				t.Fatalf("valid=%t, bytes=%d, error=%v", tt.valid, len(got), err)
			}
		})
	}
	ev := core.NewSecurityEvent("test", "audio_upload", core.SeverityInfo, "raw")
	ev.RawData = pcm
	if _, err := audioPCM(ev); err == nil {
		t.Fatal("undeclared raw format accepted")
	}
	ev.Details["audio_format"], ev.Details["sample_rate"], ev.Details["channels"] = "pcm_s16le", 16000, 1
	if got, err := audioPCM(ev); err != nil || !bytes.Equal(got, pcm) {
		t.Fatalf("explicit raw PCM rejected: %v", err)
	}
}

func TestAudioScreeningBoundsAndUncertainty(t *testing.T) {
	a := NewAudioAnalyzer()
	if got := a.Analyze(make([]byte, 100000)); got.Score != 0 || !got.Truncated || got.AnalyzedBytes != 32000 {
		t.Fatalf("silence was scored or analysis was not bounded: %+v", got)
	}
	samples := make([]int16, 16000)
	for n := range samples {
		samples[n] = 12000
		if n%2 == 0 {
			samples[n] = -12000
		}
	}
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
	s := startedShield(t, pipeline)
	ev := core.NewSecurityEvent("test", "audio_upload", core.SeverityInfo, "test tone")
	ev.RawData = pcmWAVE(makePCMSamples(samples))
	s.HandleEvent(ev)
	alerts := pipeline.GetAlerts(core.SeverityInfo, 100)
	if len(alerts) != 1 || alerts[0].Type != "deepfake_audio" || alerts[0].Severity != core.SeverityMedium {
		t.Fatalf("expected a screening alert without a critical authenticity claim: %+v", alerts)
	}
}

func TestVideoUsesDecodedPixelsAndJSONFrames(t *testing.T) {
	img := image.NewGray(image.Rect(0, 0, 16, 16))
	for n := range img.Pix {
		img.Pix[n] = byte(n)
	}
	img.SetGray(0, 0, color.Gray{Y: 42})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	ev := core.NewSecurityEvent("test", "video_analysis", core.SeverityInfo, "frames")
	ev.RawData = []byte("not a decoded video container")
	if frames := decodedVideoFrames(ev); len(frames) != 0 {
		t.Fatal("encoded video bytes were accepted as pixels")
	}
	values := make([]interface{}, 20)
	for n := range values {
		values[n] = base64.StdEncoding.EncodeToString(buf.Bytes())
	}
	ev.Details["frames"] = values
	frames := decodedVideoFrames(ev)
	if len(frames) != 8 || len(frames[0]) != 4096 || frames[0][0] != 42 {
		t.Fatalf("expected bounded decoded grayscale pixels, got %d frames", len(frames))
	}
}

func FuzzAudioContainer(f *testing.F) {
	f.Add(pcmWAVE(make([]byte, 128)))
	f.Add([]byte("RIFF\xff\xff\xff\xffWAVE"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		ev := core.NewSecurityEvent("fuzz", "audio_upload", core.SeverityInfo, "audio")
		ev.RawData = raw
		pcm, err := audioPCM(ev)
		if err == nil && (len(pcm) < 64 || len(pcm)%2 != 0) {
			t.Fatal("accepted malformed PCM sample boundaries")
		}
	})
}
