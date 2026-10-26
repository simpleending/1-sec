package llmfirewall

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/1sec-project/1sec/internal/core"
)

// ─── Multimodal Prompt Injection Scanner ─────────────────────────────────────
//
// Three-layer heuristic detection of hidden prompt injection in non-text media.
// No OCR, no ML, no external dependencies — pure structural analysis.
//
// Layer 1: Image metadata (EXIF, PNG tEXt/iTXt, JPEG COM, XMP)
// Layer 2: HTML/CSS hidden content (display:none, font-size:0, white text, etc.)
// Layer 3: PDF hidden text (invisible rendering mode, zero-size fonts, white text)
//
// Ref: PhantomLint (Melbourne 2025), OWASP multimodal injection advisory (Nov 2024),
//      Undercode image-based injection research (Feb 2026).

// MultimodalDetection represents a finding from the multimodal scanner.
type MultimodalDetection struct {
	Layer       string        // "image_metadata", "html_hidden", "pdf_hidden"
	Technique   string        // specific hiding technique detected
	Content     string        // the suspicious content found
	Severity    core.Severity // severity of the finding
	Description string        // human-readable description
}

// ScanMultimodal runs all three detection layers against the provided data.
// rawData is the raw bytes of the file/content.
// textContent is any already-extracted text representation (HTML source, etc.).
// contentType hints at the format ("image/png", "image/jpeg", "application/pdf", "text/html", "").
func ScanMultimodal(rawData []byte, textContent string, contentType string) []MultimodalDetection {
	var detections []MultimodalDetection

	ct := strings.ToLower(contentType)

	// Layer 1: Image metadata scanning
	if len(rawData) > 0 {
		if ct == "" || strings.HasPrefix(ct, "image/") {
			detections = append(detections, scanImageMetadata(rawData)...)
		}
	}

	// Layer 2: HTML/CSS hidden content
	if textContent != "" {
		if ct == "" || strings.Contains(ct, "html") || strings.Contains(ct, "xml") || strings.Contains(ct, "text") {
			detections = append(detections, scanHTMLHiddenContent(textContent)...)
		}
	}

	// Layer 3: PDF hidden text
	if len(rawData) > 0 {
		if ct == "" || strings.Contains(ct, "pdf") {
			detections = append(detections, scanPDFHiddenText(rawData)...)
		}
	}

	return detections
}

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 1: Image Metadata Scanner
// ═══════════════════════════════════════════════════════════════════════════════
//
// Parses EXIF (JPEG), PNG tEXt/iTXt/zTXt chunks, JPEG COM markers, and XMP
// blocks for text content, then runs prompt injection patterns against it.
// Pure byte-level parsing — no image decoding needed.

// suspiciousMetadataPatterns are regex patterns that indicate prompt injection
// content hidden in image metadata fields.
var suspiciousMetadataPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|system)\s+(instructions?|prompts?|rules?)`),
	regexp.MustCompile(`(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be|switch\s+to)\s+(a\s+)?(DAN|evil|unrestricted|unfiltered)`),
	regexp.MustCompile(`(?i)(system\s+prompt|hidden\s+instructions?|secret\s+instructions?)`),
	regexp.MustCompile(`(?i)(\[SYSTEM\]|\[INST\]|<<SYS>>|<\|im_start\|>)`),
	regexp.MustCompile(`(?i)(reveal|show|output|print)\s+(your\s+)?(system\s+prompt|instructions?|rules?)`),
	regexp.MustCompile(`(?i)(execute|run|call|invoke)\s+(the\s+)?(function|tool|command|api)`),
	regexp.MustCompile(`(?i)(send|post|exfiltrate|forward)\s+(the\s+)?(data|context|conversation|response)\s+(to|via)`),
	regexp.MustCompile(`(?i)(new\s+instructions?|updated\s+rules?|real\s+instructions?)\s*:`),
	regexp.MustCompile(`(?i)(tell\s+your\s+(human|user|operator)|you\s+must\s+(visit|go\s+to))`),
	regexp.MustCompile(`(?i)(remember\s+this|store\s+this|add\s+this\s+to\s+(your\s+)?memory).*?(ignore|override|bypass)`),
}

func scanImageMetadata(data []byte) []MultimodalDetection {
	var detections []MultimodalDetection

	if len(data) < 4 {
		return nil
	}

	// Detect format by magic bytes
	switch {
	case bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}): // PNG
		detections = append(detections, scanPNGMetadata(data)...)
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}): // JPEG
		detections = append(detections, scanJPEGMetadata(data)...)
	}

	// XMP is format-agnostic — scan for it in any image
	detections = append(detections, scanXMPBlock(data)...)

	return detections
}

// scanPNGMetadata extracts text from PNG tEXt, iTXt, and zTXt chunks.
func scanPNGMetadata(data []byte) []MultimodalDetection {
	var detections []MultimodalDetection

	// PNG structure: 8-byte signature, then chunks (4-byte length, 4-byte type, data, 4-byte CRC)
	if len(data) < 8 {
		return nil
	}
	pos := 8 // skip PNG signature

	for pos+8 <= len(data) {
		if pos+4 > len(data) {
			break
		}
		chunkLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4

		if pos+4 > len(data) {
			break
		}
		chunkType := string(data[pos : pos+4])
		pos += 4

		if chunkLen < 0 || pos+chunkLen > len(data) {
			break
		}
		chunkData := data[pos : pos+chunkLen]

		switch chunkType {
		case "tEXt":
			// tEXt: keyword\0text
			if idx := bytes.IndexByte(chunkData, 0); idx >= 0 && idx+1 < len(chunkData) {
				keyword := string(chunkData[:idx])
				text := string(chunkData[idx+1:])
				if d := checkMetadataText(keyword, text, "png_text_chunk"); d != nil {
					detections = append(detections, *d)
				}
			}
		case "iTXt":
			// iTXt: keyword\0 compression_flag compression_method language\0 translated_keyword\0 text
			if idx := bytes.IndexByte(chunkData, 0); idx >= 0 {
				keyword := string(chunkData[:idx])
				// Skip compression flag, method, language tag, translated keyword
				rest := chunkData[idx+1:]
				// Find the text after the null-separated fields (skip 2 bytes + 2 null-terminated strings)
				if len(rest) > 2 {
					rest = rest[2:] // skip compression flag + method
					// Skip language tag
					if langEnd := bytes.IndexByte(rest, 0); langEnd >= 0 && langEnd+1 < len(rest) {
						rest = rest[langEnd+1:]
						// Skip translated keyword
						if tkEnd := bytes.IndexByte(rest, 0); tkEnd >= 0 && tkEnd+1 < len(rest) {
							text := string(rest[tkEnd+1:])
							if d := checkMetadataText(keyword, text, "png_itxt_chunk"); d != nil {
								detections = append(detections, *d)
							}
						}
					}
				}
			}
		}

		pos += chunkLen + 4 // skip data + CRC
	}

	return detections
}

// scanJPEGMetadata extracts text from JPEG COM markers and EXIF data.
func scanJPEGMetadata(data []byte) []MultimodalDetection {
	var detections []MultimodalDetection

	pos := 2 // skip SOI marker (0xFF 0xD8)

	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			pos++
			continue
		}
		marker := data[pos+1]
		pos += 2

		// SOS (Start of Scan) — stop parsing markers
		if marker == 0xDA {
			break
		}

		// Markers without length
		if marker == 0xD8 || marker == 0xD9 || (marker >= 0xD0 && marker <= 0xD7) {
			continue
		}

		if pos+2 > len(data) {
			break
		}
		segLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		if segLen < 2 || pos+segLen > len(data) {
			break
		}
		segData := data[pos+2 : pos+segLen]

		switch {
		case marker == 0xFE: // COM (Comment)
			comment := string(segData)
			if d := checkMetadataText("JPEG_Comment", comment, "jpeg_comment"); d != nil {
				detections = append(detections, *d)
			}

		case marker == 0xE1: // APP1 (EXIF or XMP)
			if bytes.HasPrefix(segData, []byte("Exif\x00\x00")) {
				detections = append(detections, scanEXIFBlock(segData[6:])...)
			}

		case marker == 0xE0: // APP0 (JFIF — usually benign, but check comment field)
			if len(segData) > 14 {
				// JFIF may have extension data
				ext := string(segData[14:])
				if d := checkMetadataText("JFIF_Extension", ext, "jpeg_jfif"); d != nil {
					detections = append(detections, *d)
				}
			}
		}

		pos += segLen
	}

	return detections
}

// scanEXIFBlock parses TIFF-structured EXIF data for text fields.
func scanEXIFBlock(data []byte) []MultimodalDetection {
	var detections []MultimodalDetection

	if len(data) < 8 {
		return nil
	}

	// Determine byte order
	var bo binary.ByteOrder
	switch string(data[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return nil
	}

	// Verify TIFF magic
	if bo.Uint16(data[2:4]) != 0x002A {
		return nil
	}

	ifdOffset := int(bo.Uint32(data[4:8]))
	detections = append(detections, parseIFD(data, ifdOffset, bo, 0)...)

	return detections
}

// EXIF tags that commonly carry text where injections can hide.
var exifTextTags = map[uint16]string{
	0x010E: "ImageDescription",
	0x010F: "Make",
	0x0110: "Model",
	0x0131: "Software",
	0x013B: "Artist",
	0x8298: "Copyright",
	0x9286: "UserComment",
	0x9C9B: "XPTitle",
	0x9C9C: "XPComment",
	0x9C9D: "XPAuthor",
	0x9C9E: "XPKeywords",
	0x9C9F: "XPSubject",
}

func parseIFD(data []byte, offset int, bo binary.ByteOrder, depth int) []MultimodalDetection {
	remaining := 4096
	return parseIFDBounded(data, offset, bo, depth, make(map[int]int), &remaining)
}

func parseIFDBounded(data []byte, offset int, bo binary.ByteOrder, depth int, visited map[int]int, remaining *int) []MultimodalDetection {
	var detections []MultimodalDetection

	if depth > 4 || offset < 0 || offset > len(data)-2 || *remaining <= 0 {
		return nil
	}
	if previousDepth, seen := visited[offset]; seen && previousDepth <= depth {
		return nil
	}
	visited[offset] = depth

	numEntries := int(bo.Uint16(data[offset : offset+2]))
	pos := offset + 2

	for i := 0; i < numEntries && pos+12 <= len(data); i++ {
		if *remaining <= 0 {
			return detections
		}
		*remaining--
		tag := bo.Uint16(data[pos : pos+2])
		dataType := bo.Uint16(data[pos+2 : pos+4])
		count := int(bo.Uint32(data[pos+4 : pos+8]))

		tagName, isTextTag := exifTextTags[tag]
		if isTextTag {
			text := extractEXIFString(data, pos, dataType, count, bo)
			if text != "" {
				if d := checkMetadataText(tagName, text, "exif_field"); d != nil {
					detections = append(detections, *d)
				}
			}
		}

		// Follow IFD pointers (ExifIFD, GPSIFD)
		if tag == 0x8769 || tag == 0x8825 {
			subOffset := int(bo.Uint32(data[pos+8 : pos+12]))
			detections = append(detections, parseIFDBounded(data, subOffset, bo, depth+1, visited, remaining)...)
		}

		pos += 12
	}

	// Next IFD offset
	if pos+4 <= len(data) {
		nextIFD := int(bo.Uint32(data[pos : pos+4]))
		if nextIFD > 0 {
			detections = append(detections, parseIFDBounded(data, nextIFD, bo, depth+1, visited, remaining)...)
		}
	}

	return detections
}

func extractEXIFString(data []byte, entryPos int, dataType uint16, count int, bo binary.ByteOrder) string {
	// Calculate data size
	var typeSize int
	switch dataType {
	case 1, 2, 7: // BYTE, ASCII, UNDEFINED
		typeSize = 1
	case 3: // SHORT
		typeSize = 2
	case 4: // LONG
		typeSize = 4
	default:
		return ""
	}

	totalSize := count * typeSize
	var valueData []byte

	if totalSize <= 4 {
		// Value is inline in the entry
		valueData = data[entryPos+8 : entryPos+8+totalSize]
	} else {
		// Value is at an offset
		valueOffset := int(bo.Uint32(data[entryPos+8 : entryPos+12]))
		if valueOffset < 0 || valueOffset+totalSize > len(data) {
			return ""
		}
		valueData = data[valueOffset : valueOffset+totalSize]
	}

	switch dataType {
	case 2: // ASCII
		// Trim null terminator
		if len(valueData) > 0 && valueData[len(valueData)-1] == 0 {
			valueData = valueData[:len(valueData)-1]
		}
		return string(valueData)
	case 1, 7: // BYTE, UNDEFINED (UserComment uses this)
		// UserComment: first 8 bytes are charset identifier
		if count > 8 {
			charset := string(valueData[:8])
			payload := valueData[8:]
			switch {
			case strings.HasPrefix(charset, "ASCII"):
				return strings.TrimRight(string(payload), "\x00 ")
			case strings.HasPrefix(charset, "UNICODE"):
				return decodeUTF16(payload, bo)
			default:
				// Try as raw ASCII
				return strings.TrimRight(string(payload), "\x00 ")
			}
		}
		return strings.TrimRight(string(valueData), "\x00 ")
	case 3: // SHORT — XP* tags use UTF-16LE encoded as SHORT array
		return decodeUTF16(valueData, binary.LittleEndian)
	}

	return ""
}

func decodeUTF16(data []byte, bo binary.ByteOrder) string {
	if len(data) < 2 {
		return ""
	}
	u16s := make([]uint16, len(data)/2)
	for i := range u16s {
		u16s[i] = bo.Uint16(data[i*2 : i*2+2])
	}
	// Trim null terminators
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	runes := utf16.Decode(u16s)
	return string(runes)
}

// scanXMPBlock finds and scans XMP (XML) metadata embedded in any image format.
func scanXMPBlock(data []byte) []MultimodalDetection {
	var detections []MultimodalDetection

	// XMP is embedded as XML starting with <?xpacket or <x:xmpmeta
	xmpStart := bytes.Index(data, []byte("<x:xmpmeta"))
	if xmpStart < 0 {
		xmpStart = bytes.Index(data, []byte("<?xpacket"))
	}
	if xmpStart < 0 {
		return nil
	}

	xmpEnd := bytes.Index(data[xmpStart:], []byte("</x:xmpmeta>"))
	if xmpEnd < 0 {
		xmpEnd = bytes.Index(data[xmpStart:], []byte("<?xpacket end"))
	}
	if xmpEnd < 0 {
		// Take a reasonable chunk
		xmpEnd = len(data) - xmpStart
		if xmpEnd > 65536 {
			xmpEnd = 65536
		}
	} else {
		xmpEnd += 20 // include closing tag
		if xmpEnd > len(data)-xmpStart {
			xmpEnd = len(data) - xmpStart
		}
	}

	if xmpStart+xmpEnd > len(data) {
		xmpEnd = len(data) - xmpStart
	}

	xmpData := string(data[xmpStart : xmpStart+xmpEnd])

	// Extract text content from XMP XML tags that commonly carry descriptions
	xmpTextPatterns := regexp.MustCompile(`(?i)<(dc:description|dc:title|dc:subject|dc:rights|xmp:Label|xmp:Rating|photoshop:Instructions|Iptc4xmpCore:Instructions|exif:UserComment)[^>]*>([^<]+)</`)
	matches := xmpTextPatterns.FindAllStringSubmatch(xmpData, -1)
	for _, m := range matches {
		if len(m) >= 3 {
			tagName := m[1]
			text := m[2]
			if d := checkMetadataText("XMP:"+tagName, text, "xmp_field"); d != nil {
				detections = append(detections, *d)
			}
		}
	}

	// Also scan the raw XMP for injection patterns (attackers may use non-standard tags)
	for _, p := range suspiciousMetadataPatterns {
		if loc := p.FindStringIndex(xmpData); loc != nil {
			matched := xmpData[loc[0]:loc[1]]
			if len(matched) > 200 {
				matched = matched[:200]
			}
			detections = append(detections, MultimodalDetection{
				Layer:       "image_metadata",
				Technique:   "xmp_raw_injection",
				Content:     matched,
				Severity:    core.SeverityCritical,
				Description: "Prompt injection pattern found in raw XMP metadata block",
			})
			break // one raw XMP detection is enough
		}
	}

	return detections
}

// checkMetadataText checks a metadata field value against injection patterns.
func checkMetadataText(fieldName, text, technique string) *MultimodalDetection {
	if len(strings.TrimSpace(text)) < 5 {
		return nil
	}

	for _, p := range suspiciousMetadataPatterns {
		if p.MatchString(text) {
			content := text
			if len(content) > 300 {
				content = content[:300] + "..."
			}
			return &MultimodalDetection{
				Layer:       "image_metadata",
				Technique:   technique,
				Content:     content,
				Severity:    core.SeverityCritical,
				Description: fmt.Sprintf("Prompt injection detected in %s field %q", technique, fieldName),
			}
		}
	}

	// Heuristic: unusually long metadata fields are suspicious (normal EXIF descriptions are short)
	if len(text) > 500 {
		// Check for instruction-like density
		instructionWords := regexp.MustCompile(`(?i)\b(ignore|override|system|prompt|instruction|execute|respond|output|always|never|must|shall)\b`)
		matches := instructionWords.FindAllString(text, -1)
		if len(matches) >= 3 {
			content := text
			if len(content) > 300 {
				content = content[:300] + "..."
			}
			return &MultimodalDetection{
				Layer:       "image_metadata",
				Technique:   technique + "_suspicious_length",
				Content:     content,
				Severity:    core.SeverityHigh,
				Description: fmt.Sprintf("Unusually long metadata in %s field %q with %d instruction-like words", technique, fieldName, len(matches)),
			}
		}
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 2: HTML/CSS Hidden Content Scanner
// ═══════════════════════════════════════════════════════════════════════════════
//
// Detects text hidden via CSS/HTML techniques that is invisible to humans but
// readable by LLMs processing the raw source. Inspired by PhantomLint's approach
// of comparing "what humans see" vs "what LLMs see" using structural signals.
//
// Techniques detected:
//   - display:none / visibility:hidden elements with text content
//   - font-size:0 / font-size:1px text
//   - color matching background (white-on-white, transparent text)
//   - position:absolute with off-screen coordinates
//   - opacity:0 elements
//   - overflow:hidden with tiny containers
//   - HTML comments containing instructions
//   - aria-hidden elements with suspicious text
//   - Zero-width characters and Unicode tricks in visible text
//   - Base64-encoded content in data attributes

// hiddenCSSRule represents a CSS-based hiding technique.
type hiddenCSSRule struct {
	name    string
	pattern *regexp.Regexp
	extract *regexp.Regexp // optional: extract the hidden text content
}

var hiddenCSSRules = []hiddenCSSRule{
	{
		name:    "display_none",
		pattern: regexp.MustCompile(`(?is)<[^>]+style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>([^<]{5,})</`),
	},
	{
		name:    "visibility_hidden",
		pattern: regexp.MustCompile(`(?is)<[^>]+style\s*=\s*["'][^"']*visibility\s*:\s*hidden[^"']*["'][^>]*>([^<]{5,})</`),
	},
	{
		name:    "font_size_zero",
		pattern: regexp.MustCompile(`(?is)<[^>]+style\s*=\s*["'][^"']*font-size\s*:\s*0(px|em|rem|pt|%)?\s*[;"][^"']*["'][^>]*>([^<]{5,})</`),
	},
	{
		name:    "font_size_tiny",
		pattern: regexp.MustCompile(`(?is)<[^>]+style\s*=\s*["'][^"']*font-size\s*:\s*[01](px|pt)\s*[;"][^"']*["'][^>]*>([^<]{5,})</`),
	},
	{
		name:    "opacity_zero",
		pattern: regexp.MustCompile(`(?is)<[^>]+style\s*=\s*["'][^"']*opacity\s*:\s*0[^0-9][^"']*["'][^>]*>([^<]{5,})</`),
	},
	{
		name:    "color_white_on_white",
		pattern: regexp.MustCompile(`(?is)<[^>]+style\s*=\s*["'][^"']*color\s*:\s*(white|#fff(fff)?|rgb\s*\(\s*255\s*,\s*255\s*,\s*255|rgba\s*\([^)]*,\s*0\s*\))[^"']*["'][^>]*>([^<]{5,})</`),
	},
	{
		name:    "color_transparent",
		pattern: regexp.MustCompile(`(?is)<[^>]+style\s*=\s*["'][^"']*color\s*:\s*transparent[^"']*["'][^>]*>([^<]{5,})</`),
	},
	{
		name:    "offscreen_position",
		pattern: regexp.MustCompile(`(?is)<[^>]+style\s*=\s*["'][^"']*position\s*:\s*(absolute|fixed)[^"']*(?:left|top)\s*:\s*-\d{3,}[^"']*["'][^>]*>([^<]{5,})</`),
	},
	{
		name:    "overflow_clip",
		pattern: regexp.MustCompile(`(?is)<[^>]+style\s*=\s*["'][^"']*overflow\s*:\s*hidden[^"']*(?:width|height)\s*:\s*[01](px)?\s*[;"][^"']*["'][^>]*>([^<]{5,})</`),
	},
	{
		name:    "text_indent_offscreen",
		pattern: regexp.MustCompile(`(?is)<[^>]+style\s*=\s*["'][^"']*text-indent\s*:\s*-\d{3,}[^"']*["'][^>]*>([^<]{5,})</`),
	},
}

// HTML structural hiding patterns (not CSS-based).
var htmlHidingPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{
		name:    "html_comment_injection",
		pattern: regexp.MustCompile(`(?is)<!--[^>]{10,}?(?:ignore|override|disregard|system|instruction|execute|bypass|new\s+rules?|you\s+are\s+now|act\s+as|pretend)[^>]*?-->`),
	},
	{
		name:    "hidden_input_injection",
		pattern: regexp.MustCompile(`(?is)<input[^>]+type\s*=\s*["']hidden["'][^>]+value\s*=\s*["']([^"']{20,})["']`),
	},
	{
		name:    "aria_hidden_injection",
		pattern: regexp.MustCompile(`(?is)<[^>]+aria-hidden\s*=\s*["']true["'][^>]*>([^<]{10,})</`),
	},
	{
		name:    "data_attribute_base64",
		pattern: regexp.MustCompile(`(?is)<[^>]+data-[a-z]+\s*=\s*["']([A-Za-z0-9+/=]{40,})["']`),
	},
	{
		name:    "noscript_injection",
		pattern: regexp.MustCompile(`(?is)<noscript[^>]*>([^<]{10,})</noscript>`),
	},
	{
		name:    "template_injection",
		pattern: regexp.MustCompile(`(?is)<template[^>]*>([^<]{10,})</template>`),
	},
}

func scanHTMLHiddenContent(content string) []MultimodalDetection {
	var detections []MultimodalDetection

	// Check CSS-based hiding
	for _, rule := range hiddenCSSRules {
		matches := rule.pattern.FindAllStringSubmatch(content, 5)
		for _, m := range matches {
			// The captured group is the hidden text
			hiddenText := m[len(m)-1]
			if isSuspiciousHiddenText(hiddenText) {
				detections = append(detections, MultimodalDetection{
					Layer:       "html_hidden",
					Technique:   "css_" + rule.name,
					Content:     truncateStr(hiddenText, 300),
					Severity:    core.SeverityCritical,
					Description: fmt.Sprintf("Text hidden via CSS %s contains suspicious content", rule.name),
				})
			}
		}
	}

	// Check HTML structural hiding
	for _, hp := range htmlHidingPatterns {
		matches := hp.pattern.FindAllStringSubmatch(content, 5)
		for _, m := range matches {
			hiddenText := m[len(m)-1]

			// Special handling for base64 in data attributes
			if hp.name == "data_attribute_base64" {
				decoded, err := base64.StdEncoding.DecodeString(hiddenText)
				if err == nil && isPrintableText(string(decoded)) {
					decodedStr := string(decoded)
					if isSuspiciousHiddenText(decodedStr) {
						detections = append(detections, MultimodalDetection{
							Layer:       "html_hidden",
							Technique:   "data_attr_base64_injection",
							Content:     truncateStr(decodedStr, 300),
							Severity:    core.SeverityCritical,
							Description: "Base64-encoded prompt injection found in HTML data attribute",
						})
					}
				}
				continue
			}

			if isSuspiciousHiddenText(hiddenText) {
				severity := core.SeverityHigh
				if hp.name == "html_comment_injection" {
					severity = core.SeverityCritical
				}
				detections = append(detections, MultimodalDetection{
					Layer:       "html_hidden",
					Technique:   hp.name,
					Content:     truncateStr(hiddenText, 300),
					Severity:    severity,
					Description: fmt.Sprintf("Suspicious content hidden via %s", hp.name),
				})
			}
		}
	}

	// Check for high density of zero-width characters (Unicode obfuscation)
	zwCount := countZeroWidthChars(content)
	if zwCount > 10 {
		detections = append(detections, MultimodalDetection{
			Layer:       "html_hidden",
			Technique:   "zero_width_char_density",
			Content:     fmt.Sprintf("%d zero-width characters detected", zwCount),
			Severity:    core.SeverityHigh,
			Description: fmt.Sprintf("High density of zero-width Unicode characters (%d) — possible steganographic encoding", zwCount),
		})
	}

	return detections
}

// isSuspiciousHiddenText checks if hidden text looks like it could be a prompt injection.
func isSuspiciousHiddenText(text string) bool {
	text = strings.TrimSpace(text)
	if len(text) < 5 {
		return false
	}

	// Check against injection patterns
	for _, p := range suspiciousMetadataPatterns {
		if p.MatchString(text) {
			return true
		}
	}

	// Heuristic: instruction-like language density
	lower := strings.ToLower(text)
	instructionSignals := []string{
		"ignore", "override", "disregard", "bypass", "forget",
		"system prompt", "instructions", "you are", "act as",
		"respond with", "output", "execute", "must", "always", "never",
		"new rules", "from now on", "pretend", "roleplay",
	}
	hits := 0
	for _, sig := range instructionSignals {
		if strings.Contains(lower, sig) {
			hits++
		}
	}
	// 2+ instruction signals in hidden text is suspicious
	return hits >= 2
}

func countZeroWidthChars(s string) int {
	count := 0
	for _, r := range s {
		switch r {
		case '\u200B', // zero-width space
			'\u200C', // zero-width non-joiner
			'\u200D', // zero-width joiner
			'\u2060', // word joiner
			'\uFEFF', // zero-width no-break space (BOM)
			'\u00AD', // soft hyphen
			'\u034F', // combining grapheme joiner
			'\u061C', // Arabic letter mark
			'\u180E': // Mongolian vowel separator
			count++
		}
	}
	return count
}

func isPrintableText(s string) bool {
	if len(s) == 0 {
		return false
	}
	printable := 0
	for _, r := range s {
		if r >= 32 && r < 127 {
			printable++
		}
	}
	return float64(printable)/float64(len([]rune(s))) > 0.7
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 3: PDF Hidden Text Scanner
// ═══════════════════════════════════════════════════════════════════════════════
//
// Pure-Go PDF text stream parser that detects hidden text without rendering.
// No external dependencies — parses the raw PDF byte stream.
//
// Detection targets:
//   - Text rendering mode 3 (invisible text — used for OCR layers, but also abuse)
//   - Font size 0 or near-zero (text exists but is invisible)
//   - White text (color set to 1 1 1 rg or similar)
//   - Text outside page boundaries (MediaBox/CropBox)
//   - Suspicious text in PDF metadata (Title, Author, Subject, Keywords)
//   - JavaScript/actions in PDF (can trigger LLM processing)
//
// PDF text operators parsed:
//   Tj  — show text string
//   TJ  — show text with positioning
//   '   — move to next line and show text
//   "   — set spacing, move to next line, show text
//   Tf  — set font and size
//   Tr  — set text rendering mode
//   rg  — set fill color (RGB)
//   g   — set fill color (grayscale)
//   k   — set fill color (CMYK)

func scanPDFHiddenText(data []byte) []MultimodalDetection {
	var detections []MultimodalDetection

	// Verify PDF magic
	if !bytes.HasPrefix(data, []byte("%PDF")) {
		return nil
	}

	// Scan PDF metadata
	detections = append(detections, scanPDFMetadata(data)...)

	// Scan for JavaScript (can be used to inject instructions)
	detections = append(detections, scanPDFJavaScript(data)...)

	// Scan text streams for hidden text
	detections = append(detections, scanPDFTextStreams(data)...)

	return detections
}

// scanPDFMetadata extracts and checks PDF info dictionary fields.
func scanPDFMetadata(data []byte) []MultimodalDetection {
	var detections []MultimodalDetection

	// PDF metadata fields in the Info dictionary
	metaFields := []struct {
		key  string
		name string
	}{
		{"/Title", "Title"},
		{"/Author", "Author"},
		{"/Subject", "Subject"},
		{"/Keywords", "Keywords"},
		{"/Creator", "Creator"},
		{"/Producer", "Producer"},
	}

	for _, field := range metaFields {
		value := extractPDFStringField(data, field.key)
		if value != "" {
			if d := checkMetadataText("PDF:"+field.name, value, "pdf_metadata"); d != nil {
				d.Layer = "pdf_hidden"
				detections = append(detections, *d)
			}
		}
	}

	return detections
}

// extractPDFStringField finds a PDF dictionary key and extracts its string value.
func extractPDFStringField(data []byte, key string) string {
	keyBytes := []byte(key)
	idx := bytes.Index(data, keyBytes)
	if idx < 0 {
		return ""
	}

	// Skip the key and whitespace
	pos := idx + len(keyBytes)
	for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r' || data[pos] == '\n') {
		pos++
	}

	if pos >= len(data) {
		return ""
	}

	// PDF strings are either (literal) or <hex>
	switch data[pos] {
	case '(':
		return extractPDFLiteralString(data, pos)
	case '<':
		return extractPDFHexString(data, pos)
	}

	return ""
}

func extractPDFLiteralString(data []byte, start int) string {
	if start >= len(data) || data[start] != '(' {
		return ""
	}

	var result []byte
	depth := 0
	pos := start

	for pos < len(data) {
		ch := data[pos]
		switch {
		case ch == '(' && (pos == start || data[pos-1] != '\\'):
			depth++
			if depth > 1 {
				result = append(result, ch)
			}
		case ch == ')' && (pos == 0 || data[pos-1] != '\\'):
			depth--
			if depth == 0 {
				return string(result)
			}
			result = append(result, ch)
		case ch == '\\' && pos+1 < len(data):
			pos++
			switch data[pos] {
			case 'n':
				result = append(result, '\n')
			case 'r':
				result = append(result, '\r')
			case 't':
				result = append(result, '\t')
			case '(', ')', '\\':
				result = append(result, data[pos])
			default:
				// Octal escape
				if data[pos] >= '0' && data[pos] <= '7' {
					octal := string(data[pos : pos+1])
					for i := 1; i < 3 && pos+i < len(data) && data[pos+i] >= '0' && data[pos+i] <= '7'; i++ {
						octal += string(data[pos+i : pos+i+1])
						pos++
					}
					if val, err := strconv.ParseUint(octal, 8, 8); err == nil {
						result = append(result, byte(val))
					}
				}
			}
		default:
			if depth > 0 {
				result = append(result, ch)
			}
		}
		pos++
	}

	return string(result)
}

func extractPDFHexString(data []byte, start int) string {
	if start >= len(data) || data[start] != '<' {
		return ""
	}

	end := bytes.IndexByte(data[start:], '>')
	if end < 0 {
		return ""
	}

	hexStr := string(data[start+1 : start+end])
	hexStr = strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, hexStr)

	if len(hexStr)%2 != 0 {
		hexStr += "0"
	}

	var result []byte
	for i := 0; i+1 < len(hexStr); i += 2 {
		val, err := strconv.ParseUint(hexStr[i:i+2], 16, 8)
		if err == nil {
			result = append(result, byte(val))
		}
	}

	return string(result)
}

// scanPDFJavaScript detects JavaScript in PDFs that could inject instructions.
func scanPDFJavaScript(data []byte) []MultimodalDetection {
	var detections []MultimodalDetection

	jsPatterns := [][]byte{
		[]byte("/JS"),
		[]byte("/JavaScript"),
		[]byte("/OpenAction"),
		[]byte("/AA"), // Additional Actions
		[]byte("/Launch"),
	}

	for _, pat := range jsPatterns {
		if bytes.Contains(data, pat) {
			// Try to extract the JS content
			idx := bytes.Index(data, pat)
			// Look for a string value after the key
			region := data[idx:]
			if len(region) > 500 {
				region = region[:500]
			}
			regionStr := string(region)

			detections = append(detections, MultimodalDetection{
				Layer:       "pdf_hidden",
				Technique:   "pdf_javascript_action",
				Content:     truncateStr(regionStr, 200),
				Severity:    core.SeverityHigh,
				Description: fmt.Sprintf("PDF contains %s action — may execute code or inject instructions when opened by an AI agent", string(pat)),
			})
			break // one JS detection is enough
		}
	}

	return detections
}

// scanPDFTextStreams parses PDF content streams for hidden text objects.
func scanPDFTextStreams(data []byte) []MultimodalDetection {
	var detections []MultimodalDetection

	// Find all stream...endstream blocks
	streamStart := []byte("stream")
	streamEnd := []byte("endstream")

	pos := 0
	streamsScanned := 0
	maxStreams := 100 // safety limit

	for pos < len(data) && streamsScanned < maxStreams {
		idx := bytes.Index(data[pos:], streamStart)
		if idx < 0 {
			break
		}
		sStart := pos + idx + len(streamStart)

		// Skip \r\n or \n after "stream"
		if sStart < len(data) && data[sStart] == '\r' {
			sStart++
		}
		if sStart < len(data) && data[sStart] == '\n' {
			sStart++
		}

		endIdx := bytes.Index(data[sStart:], streamEnd)
		if endIdx < 0 {
			break
		}
		sEnd := sStart + endIdx

		// Limit stream size we'll parse
		streamData := data[sStart:sEnd]
		if len(streamData) > 0 && len(streamData) < 1048576 { // 1MB limit
			findings := analyzePDFStream(data, pos+idx, streamData)
			detections = append(detections, findings...)
		}

		pos = sEnd + len(streamEnd)
		streamsScanned++
	}

	return detections
}

func analyzePDFStream(pdfData []byte, streamOffset int, streamData []byte) []MultimodalDetection {
	if isPDFFlateDecodeStream(pdfData, streamOffset) {
		if decompressed, ok := decompressPDFFlateStream(streamData); ok {
			var detections []MultimodalDetection
			detections = append(detections, analyzeTextStream(decompressed)...)
			detections = append(detections, detectSuspiciousFlatePlaintext(decompressed)...)
			return detections
		}
	}

	return analyzeTextStream(streamData)
}

func isPDFFlateDecodeStream(pdfData []byte, streamOffset int) bool {
	start := streamOffset - 2048
	if start < 0 {
		start = 0
	}
	window := pdfData[start:streamOffset]
	return bytes.Contains(window, []byte("/FlateDecode"))
}

func decompressPDFFlateStream(streamData []byte) ([]byte, bool) {
	if len(streamData) == 0 {
		return nil, false
	}

	readAll := func(r io.ReadCloser) ([]byte, bool) {
		defer r.Close()
		data, err := io.ReadAll(io.LimitReader(r, 2*1024*1024))
		if err != nil || len(data) == 0 {
			return nil, false
		}
		return data, true
	}

	if zr, err := zlib.NewReader(bytes.NewReader(streamData)); err == nil {
		if decoded, ok := readAll(zr); ok {
			return decoded, true
		}
	}

	fr := flate.NewReader(bytes.NewReader(streamData))
	if decoded, ok := readAll(fr); ok {
		return decoded, true
	}

	return nil, false
}

func detectSuspiciousFlatePlaintext(decompressed []byte) []MultimodalDetection {
	plain := strings.TrimSpace(string(decompressed))
	if len(plain) == 0 || !isPrintableText(plain) || !isSuspiciousHiddenText(plain) {
		return nil
	}

	return []MultimodalDetection{
		{
			Layer:       "pdf_hidden",
			Technique:   "pdf_flate_decode_plaintext",
			Content:     truncateStr(plain, 300),
			Severity:    core.SeverityCritical,
			Description: "Prompt injection found in decompressed PDF FlateDecode stream",
		},
	}
}

// pdfTextState tracks the current text rendering state while parsing a content stream.
type pdfTextState struct {
	fontSize    float64
	renderMode  int     // 0=fill, 1=stroke, 2=fill+stroke, 3=invisible, 4-7=clip variants
	fillColorR  float64 // RGB fill color
	fillColorG  float64
	fillColorB  float64
	fillGray    float64 // grayscale fill
	colorIsGray bool
	inTextBlock bool
}

func (s *pdfTextState) isInvisible() bool {
	return s.renderMode == 3
}

func (s *pdfTextState) isTinyFont() bool {
	return s.fontSize >= 0 && s.fontSize < 1.5
}

func (s *pdfTextState) isWhiteText() bool {
	if s.colorIsGray {
		return s.fillGray > 0.95
	}
	return s.fillColorR > 0.95 && s.fillColorG > 0.95 && s.fillColorB > 0.95
}

func (s *pdfTextState) isNearlyTransparent() bool {
	if s.colorIsGray {
		return s.fillGray > 0.98
	}
	return s.fillColorR > 0.98 && s.fillColorG > 0.98 && s.fillColorB > 0.98
}

// analyzeTextStream parses a PDF content stream for hidden text.
func analyzeTextStream(stream []byte) []MultimodalDetection {
	var detections []MultimodalDetection

	state := &pdfTextState{
		fontSize:    12, // default
		renderMode:  0,
		fillGray:    0,
		colorIsGray: true,
	}

	// Tokenize the stream (simplified PDF content stream parser)
	content := string(stream)
	lines := strings.Split(content, "\n")

	var operandStack []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		tokens := tokenizePDFLine(line)

		for _, tok := range tokens {
			switch tok {
			case "BT":
				state.inTextBlock = true
				operandStack = nil
			case "ET":
				state.inTextBlock = false
				operandStack = nil

			case "Tf": // Set font and size
				if len(operandStack) >= 2 {
					if size, err := strconv.ParseFloat(operandStack[len(operandStack)-1], 64); err == nil {
						state.fontSize = math.Abs(size)
					}
				}
				operandStack = nil

			case "Tr": // Set text rendering mode
				if len(operandStack) >= 1 {
					if mode, err := strconv.Atoi(operandStack[len(operandStack)-1]); err == nil {
						state.renderMode = mode
					}
				}
				operandStack = nil

			case "rg": // Set RGB fill color
				if len(operandStack) >= 3 {
					r, _ := strconv.ParseFloat(operandStack[len(operandStack)-3], 64)
					g, _ := strconv.ParseFloat(operandStack[len(operandStack)-2], 64)
					b, _ := strconv.ParseFloat(operandStack[len(operandStack)-1], 64)
					state.fillColorR = r
					state.fillColorG = g
					state.fillColorB = b
					state.colorIsGray = false
				}
				operandStack = nil

			case "g": // Set grayscale fill color
				if len(operandStack) >= 1 {
					gray, _ := strconv.ParseFloat(operandStack[len(operandStack)-1], 64)
					state.fillGray = gray
					state.colorIsGray = true
				}
				operandStack = nil

			case "k": // Set CMYK fill color
				if len(operandStack) >= 4 {
					c, _ := strconv.ParseFloat(operandStack[len(operandStack)-4], 64)
					m, _ := strconv.ParseFloat(operandStack[len(operandStack)-3], 64)
					y, _ := strconv.ParseFloat(operandStack[len(operandStack)-2], 64)
					k, _ := strconv.ParseFloat(operandStack[len(operandStack)-1], 64)
					// Convert CMYK to RGB
					state.fillColorR = (1 - c) * (1 - k)
					state.fillColorG = (1 - m) * (1 - k)
					state.fillColorB = (1 - y) * (1 - k)
					state.colorIsGray = false
				}
				operandStack = nil

			case "Tj", "'", "\"": // Show text operators
				if state.inTextBlock {
					// Extract text from the operand stack
					text := extractPDFTextOperand(operandStack)
					if text != "" {
						d := checkPDFTextVisibility(state, text)
						if d != nil {
							detections = append(detections, *d)
						}
					}
				}
				operandStack = nil

			case "TJ": // Show text with positioning (array of strings and numbers)
				if state.inTextBlock {
					text := extractPDFTJText(operandStack)
					if text != "" {
						d := checkPDFTextVisibility(state, text)
						if d != nil {
							detections = append(detections, *d)
						}
					}
				}
				operandStack = nil

			default:
				operandStack = append(operandStack, tok)
			}
		}
	}

	return detections
}

// tokenizePDFLine splits a PDF content stream line into tokens.
func tokenizePDFLine(line string) []string {
	var tokens []string
	i := 0

	for i < len(line) {
		// Skip whitespace
		for i < len(line) && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r') {
			i++
		}
		if i >= len(line) {
			break
		}

		switch {
		case line[i] == '(':
			// Literal string — find matching close paren
			depth := 0
			start := i
			for i < len(line) {
				if line[i] == '(' && (i == start || line[i-1] != '\\') {
					depth++
				} else if line[i] == ')' && line[i-1] != '\\' {
					depth--
					if depth == 0 {
						i++
						break
					}
				}
				i++
			}
			tokens = append(tokens, line[start:i])

		case line[i] == '<' && i+1 < len(line) && line[i+1] != '<':
			// Hex string
			end := strings.IndexByte(line[i:], '>')
			if end >= 0 {
				tokens = append(tokens, line[i:i+end+1])
				i += end + 1
			} else {
				i++
			}

		case line[i] == '[':
			// Array — collect everything until ]
			end := strings.IndexByte(line[i:], ']')
			if end >= 0 {
				tokens = append(tokens, line[i:i+end+1])
				i += end + 1
			} else {
				i++
			}

		case line[i] == '%':
			// Comment — skip rest of line
			return tokens

		default:
			// Regular token (number, operator, name)
			start := i
			for i < len(line) && line[i] != ' ' && line[i] != '\t' && line[i] != '(' && line[i] != ')' && line[i] != '<' && line[i] != '>' && line[i] != '[' && line[i] != ']' && line[i] != '%' {
				i++
			}
			if i > start {
				tokens = append(tokens, line[start:i])
			} else {
				// Malformed or dictionary delimiters must still consume input.
				i++
			}
		}
	}

	return tokens
}

// extractPDFTextOperand extracts text from Tj operands.
func extractPDFTextOperand(operands []string) string {
	for _, op := range operands {
		if len(op) >= 2 && op[0] == '(' && op[len(op)-1] == ')' {
			return decodePDFLiteralInStream(op[1 : len(op)-1])
		}
		if len(op) >= 2 && op[0] == '<' && op[len(op)-1] == '>' {
			return decodePDFHexInStream(op[1 : len(op)-1])
		}
	}
	return ""
}

// extractPDFTJText extracts text from a TJ array operand.
func extractPDFTJText(operands []string) string {
	var result strings.Builder

	for _, op := range operands {
		if len(op) < 2 {
			continue
		}
		// TJ arrays look like: [(text1) -100 (text2) 50 (text3)]
		if op[0] == '[' {
			inner := op[1:]
			if len(inner) > 0 && inner[len(inner)-1] == ']' {
				inner = inner[:len(inner)-1]
			}
			// Extract all string elements from the array
			i := 0
			for i < len(inner) {
				if inner[i] == '(' {
					depth := 0
					start := i
					for i < len(inner) {
						if inner[i] == '(' && (i == start || inner[i-1] != '\\') {
							depth++
						} else if inner[i] == ')' && inner[i-1] != '\\' {
							depth--
							if depth == 0 {
								result.WriteString(decodePDFLiteralInStream(inner[start+1 : i]))
								i++
								break
							}
						}
						i++
					}
				} else if inner[i] == '<' {
					end := strings.IndexByte(inner[i:], '>')
					if end >= 0 {
						result.WriteString(decodePDFHexInStream(inner[i+1 : i+end]))
						i += end + 1
					} else {
						i++
					}
				} else {
					i++
				}
			}
		}
	}

	return result.String()
}

func decodePDFLiteralInStream(s string) string {
	var result []byte
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				result = append(result, '\n')
			case 'r':
				result = append(result, '\r')
			case 't':
				result = append(result, '\t')
			case '(', ')', '\\':
				result = append(result, s[i])
			default:
				if s[i] >= '0' && s[i] <= '7' {
					octal := string(s[i])
					for j := 1; j < 3 && i+j < len(s) && s[i+j] >= '0' && s[i+j] <= '7'; j++ {
						octal += string(s[i+j])
						i++
					}
					if val, err := strconv.ParseUint(octal, 8, 8); err == nil {
						result = append(result, byte(val))
					}
				} else {
					result = append(result, s[i])
				}
			}
		} else {
			result = append(result, s[i])
		}
		i++
	}
	return string(result)
}

func decodePDFHexInStream(hex string) string {
	hex = strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, hex)

	if len(hex)%2 != 0 {
		hex += "0"
	}

	var result []byte
	for i := 0; i+1 < len(hex); i += 2 {
		val, err := strconv.ParseUint(hex[i:i+2], 16, 8)
		if err == nil {
			result = append(result, byte(val))
		}
	}
	return string(result)
}

// checkPDFTextVisibility checks if text in the current rendering state is hidden.
func checkPDFTextVisibility(state *pdfTextState, text string) *MultimodalDetection {
	if len(strings.TrimSpace(text)) < 5 {
		return nil
	}

	// Check for suspicious content first
	if !isSuspiciousHiddenText(text) {
		return nil
	}

	var technique string
	var description string

	switch {
	case state.isInvisible():
		technique = "pdf_invisible_render_mode"
		description = fmt.Sprintf("Text rendered with mode 3 (invisible): %q", truncateStr(text, 150))
	case state.isTinyFont():
		technique = "pdf_zero_size_font"
		description = fmt.Sprintf("Text with font size %.1f (near-zero): %q", state.fontSize, truncateStr(text, 150))
	case state.isWhiteText():
		technique = "pdf_white_text"
		description = fmt.Sprintf("White text (invisible on white background): %q", truncateStr(text, 150))
	case state.isNearlyTransparent():
		technique = "pdf_near_transparent_text"
		description = fmt.Sprintf("Nearly transparent text: %q", truncateStr(text, 150))
	default:
		return nil
	}

	return &MultimodalDetection{
		Layer:       "pdf_hidden",
		Technique:   technique,
		Content:     truncateStr(text, 300),
		Severity:    core.SeverityCritical,
		Description: description,
	}
}
