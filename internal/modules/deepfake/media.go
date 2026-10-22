package deepfake

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	_ "image/png"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
)

// audioPCM accepts the format the feature extractor actually understands.
// Compressed/container bytes must never be interpreted as waveform samples.
func audioPCM(event *core.SecurityEvent) ([]byte, error) {
	raw := event.RawData
	if len(raw) >= 12 && string(raw[:4]) == "RIFF" && string(raw[8:12]) == "WAVE" {
		end := uint64(binary.LittleEndian.Uint32(raw[4:8])) + 8
		if end < 12 || end > uint64(len(raw)) {
			return nil, fmt.Errorf("truncated RIFF container")
		}
		var pcm []byte
		formatOK, seenFormat, seenData := false, false, false
		offset := uint64(12)
		for chunks := 0; offset < end && chunks < 128; chunks++ {
			if end-offset < 8 {
				return nil, fmt.Errorf("truncated WAVE chunk header")
			}
			size := uint64(binary.LittleEndian.Uint32(raw[offset+4 : offset+8]))
			start := offset + 8
			if size > end-start || start+size+size%2 > end {
				return nil, fmt.Errorf("truncated WAVE chunk")
			}
			chunk := raw[start : start+size]
			switch string(raw[offset : offset+4]) {
			case "fmt ":
				if seenFormat || len(chunk) < 16 {
					return nil, fmt.Errorf("invalid WAVE format chunk")
				}
				seenFormat = true
				formatOK = binary.LittleEndian.Uint16(chunk[0:2]) == 1 &&
					binary.LittleEndian.Uint16(chunk[2:4]) == 1 &&
					binary.LittleEndian.Uint32(chunk[4:8]) == 16000 &&
					binary.LittleEndian.Uint32(chunk[8:12]) == 32000 &&
					binary.LittleEndian.Uint16(chunk[12:14]) == 2 &&
					binary.LittleEndian.Uint16(chunk[14:16]) == 16
			case "data":
				if seenData || size%2 != 0 {
					return nil, fmt.Errorf("invalid WAVE sample data")
				}
				seenData = true
				pcm = chunk
			}
			offset = start + size + size%2
		}
		if offset != end || !formatOK || len(pcm) < 64 {
			return nil, fmt.Errorf("screening requires mono PCM16LE WAVE at 16000 Hz")
		}
		return pcm, nil
	}
	if strings.EqualFold(getStringDetail(event, "audio_format"), "pcm_s16le") &&
		getFloatDetail(event, "sample_rate") == 16000 && getFloatDetail(event, "channels") == 1 &&
		len(raw) >= 64 && len(raw)%2 == 0 {
		return raw, nil
	}
	return nil, fmt.Errorf("supply PCM16LE mono at 16000 Hz or a matching WAVE file")
}

// decodedVideoFrames samples bounded JPEG/PNG frames, including JSON base64.
// Video containers require an upstream decoder; their encoded bytes are not pixels.
func decodedVideoFrames(event *core.SecurityEvent) [][]byte {
	var frames [][]byte
	add := func(value interface{}) {
		var raw []byte
		switch v := value.(type) {
		case []byte:
			raw = v
		case string:
			if len(v) > 12<<20 {
				return
			}
			var err error
			raw, err = base64.StdEncoding.DecodeString(v)
			if err != nil {
				return
			}
		}
		if len(raw) == 0 || len(raw) > 8<<20 {
			return
		}
		cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
		if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > 1920 || cfg.Height > 1080 {
			return
		}
		img, _, err := image.Decode(bytes.NewReader(raw))
		if err != nil {
			return
		}
		const side = 64
		pixels := make([]byte, side*side)
		for y := 0; y < side; y++ {
			for x := 0; x < side; x++ {
				pixels[y*side+x] = color.GrayModel.Convert(img.At(x*cfg.Width/side, y*cfg.Height/side)).(color.Gray).Y
			}
		}
		frames = append(frames, pixels)
	}
	add(event.RawData)
	if values, ok := event.Details["frames"].([]interface{}); ok {
		for index, value := range values {
			if index >= 8 || len(frames) >= 8 {
				break
			}
			add(value)
		}
	}
	return frames
}
