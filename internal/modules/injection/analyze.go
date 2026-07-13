package injection

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/1sec-project/1sec/internal/core"
)

// AnalyzeInput scans a string for injection patterns and returns detected threats.
func (s *Shield) AnalyzeInput(input, source string) []Detection {
	if input == "" {
		return nil
	}

	atomic.AddInt64(&s.stats.TotalScanned, 1)

	var detections []Detection
	normalized := normalizeInput(input)
	seen := make(map[string]bool)

	// Scan normalized input — catches decoded/deobfuscated payloads
	for _, p := range s.patterns {
		if p.Regex.MatchString(normalized) {
			seen[p.Name] = true
			d := Detection{
				PatternName: p.Name,
				Category:    p.Category,
				Severity:    p.Severity,
				MatchedText: truncate(p.Regex.FindString(normalized), 200),
				Input:       truncate(input, 500),
				Source:      source,
			}
			detections = append(detections, d)
			s.incrementStat(p.Category)
		}
	}

	// Also scan original input — catches evasion markers (%00, encoded sequences)
	// that are removed during normalization but are themselves indicators of attack
	if normalized != input {
		for _, p := range s.patterns {
			if !seen[p.Name] && p.Regex.MatchString(input) {
				d := Detection{
					PatternName: p.Name,
					Category:    p.Category,
					Severity:    p.Severity,
					MatchedText: truncate(p.Regex.FindString(input), 200),
					Input:       truncate(input, 500),
					Source:      source,
				}
				detections = append(detections, d)
				s.incrementStat(p.Category)
			}
		}
	}

	return detections
}

// Detection represents a detected injection attempt.
type Detection struct {
	PatternName string        `json:"pattern_name"`
	Category    string        `json:"category"`
	Severity    core.Severity `json:"severity"`
	MatchedText string        `json:"matched_text"`
	Input       string        `json:"input"`
	Source      string        `json:"source"`
}

func (s *Shield) analyzeEvent(event *core.SecurityEvent) {
	fieldsToScan := extractScanFields(event)

	for fieldName, value := range fieldsToScan {
		detections := s.AnalyzeInput(value, fieldName)
		if len(detections) == 0 {
			continue
		}

		// Find highest severity among detections
		maxSeverity := core.SeverityInfo
		categories := make(map[string]bool)
		for _, d := range detections {
			if d.Severity > maxSeverity {
				maxSeverity = d.Severity
			}
			categories[d.Category] = true
		}

		catList := make([]string, 0, len(categories))
		for c := range categories {
			catList = append(catList, categoryLabel(c))
		}

		newEvent := core.NewSecurityEvent(
			ModuleName,
			"injection_detected",
			maxSeverity,
			fmt.Sprintf("Injection attempt detected: %s in field %q", strings.Join(catList, ", "), fieldName),
		)
		newEvent.SourceIP = event.SourceIP
		newEvent.UserAgent = event.UserAgent
		newEvent.RequestID = event.RequestID
		newEvent.Details["original_event_id"] = event.ID
		newEvent.Details["field"] = fieldName
		newEvent.Details["categories"] = catList
		newEvent.Details["detection_count"] = len(detections)
		newEvent.Details["detections"] = detections

		if s.bus != nil {
			if err := s.bus.PublishEvent(newEvent); err != nil {
				s.logger.Error().Err(err).Msg("failed to publish injection event")
			}
		}

		alert := core.NewAlert(newEvent,
			fmt.Sprintf("Injection Attack Detected: %s", strings.Join(catList, ", ")),
			fmt.Sprintf("Detected %d injection pattern(s) in field %q from IP %s. Categories: %s. Highest severity: %s.",
				len(detections), fieldName, event.SourceIP, strings.Join(catList, ", "), maxSeverity.String()),
		)
		rawCategories := make([]string, 0, len(categories))
		for category := range categories {
			rawCategories = append(rawCategories, category)
		}
		alert.Mitigations = getInjectionMitigations(rawCategories)

		if s.pipeline != nil {
			s.pipeline.Process(alert)
		}
	}
}

func extractScanFields(event *core.SecurityEvent) map[string]string {
	fields := make(map[string]string)

	if event.Details == nil {
		return fields
	}

	// Extract common fields that may contain user input
	stringFields := []string{
		"url", "path", "query", "body", "header", "cookie",
		"user_input", "payload", "request_body", "query_string",
		"form_data", "json_body", "xml_body", "parameter",
		"username", "password", "email", "search", "filter",
		"sort", "order_by", "filename", "redirect_url", "callback",
		"template", "expression", "command", "sql", "ldap_filter",
		"archive_entry", "file_path", "upload_name", "content_disposition",
	}

	for _, field := range stringFields {
		if val, ok := event.Details[field]; ok {
			switch v := val.(type) {
			case string:
				if v != "" {
					fields[field] = v
				}
			}
		}
	}

	// Also scan the summary if it looks like it contains request data
	if event.Summary != "" {
		fields["summary"] = event.Summary
	}

	return fields
}

func normalizeInput(input string) string {
	if len(input) == 0 {
		return input
	}

	result := input

	// Phase 1: Full hex URL decoding (%XX) — handles arbitrary encoded chars,
	// not just a hardcoded list. This is the #1 evasion technique in the wild.
	result = decodeURLPercent(result)
	// Second pass catches double encoding (%2527 → %27 → ')
	result = decodeURLPercent(result)
	// Third pass for triple encoding (rare but seen in CTF/advanced attacks)
	result = decodeURLPercent(result)

	// Phase 2: HTML entity decoding — catches &#x3C; &#60; &lt; evasion
	result = decodeHTMLEntities(result)

	// Phase 3: Backslash escape decoding — catches \x3C, \u003C, \073 (octal)
	result = decodeBackslashEscapes(result)

	// Phase 4: Strip null bytes — used to terminate strings in C-based parsers
	result = strings.ReplaceAll(result, "\x00", "")

	// Phase 5: Collapse SQL/C-style comments used to break up keywords
	// e.g., SEL/**/ECT, UN/**/ION — extremely common SQLi evasion
	result = stripInlineComments(result)

	// Phase 6: Normalize whitespace variants (tabs, newlines, vertical tabs,
	// non-breaking spaces) to regular spaces — catches keyword splitting
	result = normalizeWhitespace(result)

	// Phase 7: Unicode homoglyph normalization — Cyrillic/fullwidth substitutions
	result = normalizeHomoglyphs(result)

	// Phase 8: Unicode NFKC folding — fullwidth/halfwidth/mathematical chars to ASCII
	// Mitigates CVE-2026-25673 class bypasses where frameworks normalize after filters
	result = foldUnicode(result)

	// Phase 9: Collapse redundant whitespace to single space
	result = collapseSpaces(result)

	return result
}

// decodeURLPercent performs full percent-decoding of %XX sequences.
// Unlike the previous hardcoded replacer, this handles ANY hex pair.
func decodeURLPercent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			hi := unhex(s[i+1])
			lo := unhex(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// decodeHTMLEntities handles named entities (&lt; &gt; &amp; &quot; &apos;)
// and numeric entities (&#60; &#x3C;) used to evade XSS/injection filters.
func decodeHTMLEntities(s string) string {
	// Named entities
	r := strings.NewReplacer(
		"&lt;", "<", "&LT;", "<",
		"&gt;", ">", "&GT;", ">",
		"&amp;", "&", "&AMP;", "&",
		"&quot;", "\"", "&QUOT;", "\"",
		"&apos;", "'", "&APOS;", "'",
		"&sol;", "/", "&bsol;", "\\",
		"&lpar;", "(", "&rpar;", ")",
		"&semi;", ";", "&comma;", ",",
		"&equals;", "=", "&plus;", "+",
		"&num;", "#", "&excl;", "!",
		"&colon;", ":", "&Tab;", "\t",
		"&NewLine;", "\n",
	)
	result := r.Replace(s)

	// Numeric entities: &#60; &#x3C; &#X3c;
	var b strings.Builder
	b.Grow(len(result))
	i := 0
	for i < len(result) {
		if result[i] == '&' && i+2 < len(result) && result[i+1] == '#' {
			end := strings.IndexByte(result[i:], ';')
			if end > 0 && end < 10 {
				numStr := result[i+2 : i+end]
				var val int
				if len(numStr) > 0 && (numStr[0] == 'x' || numStr[0] == 'X') {
					// Hex: &#x3C;
					for _, c := range numStr[1:] {
						h := unhex(byte(c))
						if h < 0 {
							val = -1
							break
						}
						val = val*16 + h
					}
				} else {
					// Decimal: &#60;
					for _, c := range numStr {
						if c < '0' || c > '9' {
							val = -1
							break
						}
						val = val*10 + int(c-'0')
					}
				}
				if val >= 0 && val < 128 {
					b.WriteByte(byte(val))
					i += end + 1
					continue
				}
			}
		}
		b.WriteByte(result[i])
		i++
	}
	return b.String()
}

// decodeBackslashEscapes handles \xHH, \uHHHH, and \OOO sequences
// commonly used in JavaScript/JSON payloads to evade detection.
func decodeBackslashEscapes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'x', 'X':
				// \x3C → <
				if i+3 < len(s) {
					hi := unhex(s[i+2])
					lo := unhex(s[i+3])
					if hi >= 0 && lo >= 0 {
						b.WriteByte(byte(hi<<4 | lo))
						i += 4
						continue
					}
				}
			case 'u', 'U':
				// \u003C → < (only handle ASCII range for injection detection)
				if i+5 < len(s) {
					val := 0
					valid := true
					for j := 2; j < 6; j++ {
						h := unhex(s[i+j])
						if h < 0 {
							valid = false
							break
						}
						val = val*16 + h
					}
					if valid && val < 128 {
						b.WriteByte(byte(val))
						i += 6
						continue
					}
				}
			case 'n':
				b.WriteByte('\n')
				i += 2
				continue
			case 'r':
				b.WriteByte('\r')
				i += 2
				continue
			case 't':
				b.WriteByte('\t')
				i += 2
				continue
			case '0':
				// Octal: \073 → ;
				if i+3 < len(s) && s[i+2] >= '0' && s[i+2] <= '7' && s[i+3] >= '0' && s[i+3] <= '7' {
					val := int(s[i+1]-'0')*64 + int(s[i+2]-'0')*8 + int(s[i+3]-'0')
					if val < 128 {
						b.WriteByte(byte(val))
						i += 4
						continue
					}
				}
				b.WriteByte(0)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// stripInlineComments removes SQL/C-style inline comments used to break up
// keywords: SEL/**/ECT → SELECT, UN/*comment*/ION → UNION
func stripInlineComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			// Find closing */
			end := strings.Index(s[i+2:], "*/")
			if end >= 0 {
				i += end + 4 // skip past */
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// normalizeWhitespace replaces all whitespace variants with regular spaces.
// Attackers use tabs, newlines, vertical tabs, non-breaking spaces, and
// zero-width characters to split keywords past regex patterns.
func normalizeWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\t', '\n', '\r', '\v', '\f',
			'\u00A0',                               // non-breaking space
			'\u2000', '\u2001', '\u2002', '\u2003', // en/em spaces
			'\u2004', '\u2005', '\u2006', '\u2007',
			'\u2008', '\u2009', '\u200A', // hair/thin spaces
			'\u200B',           // zero-width space
			'\u200C', '\u200D', // zero-width non-joiner/joiner
			'\u2028', '\u2029', // line/paragraph separator
			'\u202F', // narrow no-break space
			'\u205F', // medium mathematical space
			'\u3000', // ideographic space
			'\uFEFF': // BOM / zero-width no-break space
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// normalizeHomoglyphs maps Unicode characters commonly used to visually
// impersonate ASCII characters in injection payloads.
func normalizeHomoglyphs(s string) string {
	r := strings.NewReplacer(
		// Quotation marks
		"\u2018", "'", "\u2019", "'", // curly single quotes
		"\u201C", "\"", "\u201D", "\"", // curly double quotes
		"\u0060", "'", "\u00B4", "'", // grave/acute accent
		// Brackets and parens
		"\uFF08", "(", "\uFF09", ")", // fullwidth parens
		"\uFF3B", "[", "\uFF3D", "]", // fullwidth brackets
		"\uFF5B", "{", "\uFF5D", "}", // fullwidth braces
		// Operators and punctuation
		"\uFF1C", "<", "\uFF1E", ">", // fullwidth angle brackets
		"\uFF0F", "/", "\uFF3C", "\\", // fullwidth slashes
		"\u2024", ".", "\uFF0E", ".", // one dot leader, fullwidth period
		"\uFF1A", ":", "\uFF1B", ";", // fullwidth colon/semicolon
		"\uFF0C", ",", "\uFF01", "!", // fullwidth comma/exclamation
		"\uFF1D", "=", "\uFF0B", "+", // fullwidth equals/plus
		"\uFF05", "%", "\uFF03", "#", // fullwidth percent/hash
		"\uFF20", "@", "\uFF06", "&", // fullwidth at/ampersand
		"\uFF5C", "|", "\uFF3E", "^", // fullwidth pipe/caret
		"\uFF5E", "~", "\uFF0D", "-", // fullwidth tilde/hyphen
		"\uFF3F", "_", "\uFF04", "$", // fullwidth underscore/dollar
		"\uFF07", "'", "\uFF02", "\"", // fullwidth apostrophe/quotation
		// Cyrillic lookalikes (used in domain spoofing and payload obfuscation)
		"\u0410", "A", "\u0430", "a", // Cyrillic A
		"\u0412", "B", "\u0432", "b", // Cyrillic Ve (looks like B)
		"\u0421", "C", "\u0441", "c", // Cyrillic Es
		"\u0415", "E", "\u0435", "e", // Cyrillic Ie
		"\u041D", "H", "\u043D", "h", // Cyrillic En
		"\u041A", "K", "\u043A", "k", // Cyrillic Ka
		"\u041C", "M", "\u043C", "m", // Cyrillic Em
		"\u041E", "O", "\u043E", "o", // Cyrillic O
		"\u0420", "P", "\u0440", "p", // Cyrillic Er
		"\u0422", "T", "\u0442", "t", // Cyrillic Te
		"\u0425", "X", "\u0445", "x", // Cyrillic Kha
		"\u0423", "Y", "\u0443", "y", // Cyrillic U
	)
	return r.Replace(s)
}

// foldUnicode performs NFKC-style folding of fullwidth, halfwidth, and mathematical
// alphanumeric symbols to their ASCII equivalents. This prevents bypasses where
// payloads use U+FF0E (fullwidth period) instead of '.' etc — the target framework
// normalizes them after our filter has already passed the input through.
// Covers: Fullwidth ASCII (U+FF01–U+FF5E), Halfwidth Katakana forms, and
// Mathematical Alphanumeric Symbols (U+1D400–U+1D7FF, common subset).
func foldUnicode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		// Fullwidth ASCII variants: U+FF01 '!' .. U+FF5E '~'
		// These map directly to ASCII 0x21..0x7E
		case r >= 0xFF01 && r <= 0xFF5E:
			b.WriteByte(byte(r - 0xFF01 + 0x21))
		// Fullwidth digit zero: U+FF10 is caught above, but be explicit for clarity
		// Halfwidth forms that are letter-like are less common in injection; skip for now
		// Mathematical Bold capitals A-Z: U+1D400..U+1D419
		case r >= 0x1D400 && r <= 0x1D419:
			b.WriteByte(byte('A' + (r - 0x1D400)))
		// Mathematical Bold lowercase a-z: U+1D41A..U+1D433
		case r >= 0x1D41A && r <= 0x1D433:
			b.WriteByte(byte('a' + (r - 0x1D41A)))
		// Mathematical Italic capitals A-Z: U+1D434..U+1D44D
		case r >= 0x1D434 && r <= 0x1D44D:
			b.WriteByte(byte('A' + (r - 0x1D434)))
		// Mathematical Italic lowercase a-z: U+1D44E..U+1D467
		case r >= 0x1D44E && r <= 0x1D467:
			b.WriteByte(byte('a' + (r - 0x1D44E)))
		// Mathematical Bold digits 0-9: U+1D7CE..U+1D7D7
		case r >= 0x1D7CE && r <= 0x1D7D7:
			b.WriteByte(byte('0' + (r - 0x1D7CE)))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// collapseSpaces reduces runs of multiple spaces to a single space.
// After all normalization, redundant whitespace can hide keyword boundaries.
func collapseSpaces(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			if !prevSpace {
				b.WriteByte(' ')
			}
			prevSpace = true
		} else {
			b.WriteByte(s[i])
			prevSpace = false
		}
	}
	return b.String()
}

func (s *Shield) incrementStat(category string) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()
	switch category {
	case "sqli":
		s.stats.SQLiDetected++
	case "xss":
		s.stats.XSSDetected++
	case "cmdi":
		s.stats.CMDiDetected++
	case "ssrf":
		s.stats.SSRFDetected++
	case "ldapi":
		s.stats.LDAPiDetected++
	case "template":
		s.stats.TemplDetected++
	case "nosql":
		s.stats.NoSQLDetected++
	case "path":
		s.stats.PathDetected++
	case "upload":
		s.stats.UploadDetected++
	case "deser":
		s.stats.DeserDetected++
	case "canary":
		s.stats.CanaryDetected++
	}
}

func categoryLabel(cat string) string {
	switch cat {
	case "sqli":
		return "SQL Injection"
	case "xss":
		return "Cross-Site Scripting"
	case "cmdi":
		return "Command Injection"
	case "ssrf":
		return "Server-Side Request Forgery"
	case "ldapi":
		return "LDAP Injection"
	case "template":
		return "Template Injection"
	case "nosql":
		return "NoSQL Injection"
	case "path":
		return "Path Traversal"
	case "upload":
		return "Malicious File Upload"
	case "deser":
		return "Deserialization Attack"
	case "canary":
		return "Canary Token / Leaked Credential"
	case "metric":
		return "CRLF Metric Injection"
	default:
		return cat
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// analyzeFileUpload inspects file upload events for binary structure anomalies
// using the FileSentinel. This catches polyglot files, embedded executables,
// shellcode, and malformed headers that regex patterns can't detect.
func (s *Shield) analyzeFileUpload(event *core.SecurityEvent) {
	if event.RawData == nil || len(event.RawData) == 0 {
		return
	}

	filename := ""
	if event.Details != nil {
		if fn, ok := event.Details["filename"].(string); ok {
			filename = fn
		}
	}
	contentType := ""
	if event.Details != nil {
		if ct, ok := event.Details["content_type"].(string); ok {
			contentType = ct
		}
	}

	// Extract extension from filename
	ext := ""
	if idx := strings.LastIndex(filename, "."); idx >= 0 {
		ext = filename[idx:]
	}

	findings := s.fileSentinel.Analyze(event.RawData, ext, contentType)
	if len(findings) == 0 {
		return
	}

	// Find highest severity
	maxSeverity := core.SeverityInfo
	var descriptions []string
	for _, f := range findings {
		if f.Severity > maxSeverity {
			maxSeverity = f.Severity
		}
		descriptions = append(descriptions, f.Description)
	}

	newEvent := core.NewSecurityEvent(
		ModuleName,
		"malicious_file_upload",
		maxSeverity,
		fmt.Sprintf("Suspicious file upload detected: %s (%d anomalies found)", filename, len(findings)),
	)
	newEvent.SourceIP = event.SourceIP
	newEvent.UserAgent = event.UserAgent
	newEvent.RequestID = event.RequestID
	newEvent.Details["original_event_id"] = event.ID
	newEvent.Details["filename"] = filename
	newEvent.Details["content_type"] = contentType
	newEvent.Details["file_size"] = len(event.RawData)
	newEvent.Details["finding_count"] = len(findings)
	newEvent.Details["findings"] = descriptions

	if s.bus != nil {
		if err := s.bus.PublishEvent(newEvent); err != nil {
			s.logger.Error().Err(err).Msg("failed to publish file sentinel event")
		}
	}

	alert := core.NewAlert(newEvent,
		fmt.Sprintf("Malicious File Upload Detected: %s", filename),
		fmt.Sprintf("File sentinel detected %d anomalies in uploaded file %q (%d bytes) from IP %s: %s",
			len(findings), filename, len(event.RawData), event.SourceIP,
			strings.Join(descriptions, "; ")),
	)
	alert.Mitigations = []string{
		"Block the file upload and quarantine the file",
		"Verify file content matches declared Content-Type using magic bytes",
		"Restrict allowed file extensions and MIME types at the application layer",
		"Scan uploaded files in a sandboxed environment before processing",
		"Implement file size limits and content validation",
	}

	if s.pipeline != nil {
		s.pipeline.Process(alert)
	}
}

// getInjectionMitigations returns context-specific mitigations based on detected categories.
func getInjectionMitigations(categories []string) []string {
	mitigationMap := map[string][]string{
		"sqli": {
			"Use parameterized queries or prepared statements for all database operations",
			"Implement input validation with strict type checking",
			"Apply least-privilege database permissions",
			"Use an ORM or query builder that auto-parameterizes",
		},
		"xss": {
			"Implement Content Security Policy (CSP) headers",
			"Use context-aware output encoding (HTML, JS, URL, CSS)",
			"Sanitize user input with a proven library (e.g., DOMPurify)",
			"Enable HttpOnly and Secure flags on session cookies",
		},
		"cmdi": {
			"Avoid passing user input to shell commands",
			"Use language-native APIs instead of shell execution",
			"Implement strict input validation with allowlists",
			"Run processes with minimal privileges in sandboxed environments",
		},
		"ssrf": {
			"Validate and allowlist permitted URL schemes and domains",
			"Block requests to internal/private IP ranges (RFC 1918, link-local)",
			"Implement network-level egress filtering",
			"Use a dedicated HTTP client with SSRF protections",
		},
		"ldapi": {
			"Use parameterized LDAP queries",
			"Validate and escape special LDAP characters in user input",
			"Implement input length limits for LDAP query parameters",
		},
		"template": {
			"Use logic-less templates or sandboxed template engines",
			"Never pass user input directly into template expressions",
			"Implement strict input validation before template rendering",
		},
		"nosql": {
			"Validate input types — reject objects where strings are expected",
			"Use query builders that prevent operator injection",
			"Implement schema validation on all database inputs",
		},
		"path": {
			"Normalize and validate file paths against a base directory",
			"Use chroot or containerized file access",
			"Reject paths containing .. or absolute path components",
		},
		"deser": {
			"Avoid deserializing untrusted data",
			"Use safe serialization formats (JSON) instead of native serialization",
			"Implement integrity checks on serialized data",
		},
		"canary": {
			"Investigate the source of the canary token trigger",
			"Review access logs for the affected resource",
			"Rotate any credentials associated with the triggered canary",
		},
		"metric": {
			"Reject carriage returns and line feeds in metric names, values, and tags",
			"Construct telemetry packets from typed fields instead of string concatenation",
			"Allowlist metric names and StatsD value types before forwarding",
			"Separate untrusted request data from backend telemetry channels",
		},
	}

	seen := make(map[string]bool)
	var result []string
	for _, cat := range categories {
		if mits, ok := mitigationMap[cat]; ok {
			for _, m := range mits {
				if !seen[m] {
					seen[m] = true
					result = append(result, m)
				}
			}
		}
	}
	if len(result) == 0 {
		return []string{
			"Block the source IP if repeated attempts are detected",
			"Review and sanitize the affected input field",
			"Implement input validation and output encoding",
		}
	}
	return result
}
