package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
)

func TestProfilePathValidation(t *testing.T) {
	for _, name := range []string{"default", "prod-us_2", "A1"} {
		path, err := profilePath(name)
		if err != nil {
			t.Fatalf("profilePath(%q) returned error: %v", name, err)
		}
		if !strings.HasSuffix(path, name+".yaml") {
			t.Fatalf("profilePath(%q) = %q", name, path)
		}
	}

	for _, name := range []string{"", "../escape", "a/b", `a\b`, "has space", "profile.yaml", "prod;rm"} {
		if _, err := profilePath(name); err == nil {
			t.Errorf("profilePath(%q) unexpectedly succeeded", name)
		}
	}
}

// ─── suggest ──────────────────────────────────────────────────────────────────

func TestSuggest_PrefixMatch(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"sta", "status"},
		{"aler", "alerts"},
		{"mod", "modules"},
		{"con", "config"},
		{"hel", "help"},
		{"ver", "version"},
		{"doc", "docker"},
		{"exp", "export"},
		{"das", "dashboard"},
		{"comp", "completions"},
	}
	for _, tc := range tests {
		got := suggest(tc.input)
		if got != tc.want {
			t.Errorf("suggest(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSuggest_TypoCorrection(t *testing.T) {
	// Single character difference
	got := suggest("statux")
	if got != "status" {
		t.Errorf("suggest('statux') = %q, want 'status'", got)
	}
}

func TestSuggest_NoMatch(t *testing.T) {
	got := suggest("zzzzzzzzz")
	if got != "" {
		t.Errorf("suggest('zzzzzzzzz') = %q, want empty", got)
	}
}

func TestSuggest_CaseInsensitive(t *testing.T) {
	got := suggest("STATUS")
	if got != "status" {
		t.Errorf("suggest('STATUS') = %q, want 'status'", got)
	}
}

// ─── parseValue ───────────────────────────────────────────────────────────────

func TestParseValue(t *testing.T) {
	tests := []struct {
		input string
		want  interface{}
	}{
		{"true", true},
		{"false", false},
		{"True", true},
		{"False", false},
		{"42", 42},
		{"hello", "hello"},
		{"", ""},
	}
	for _, tc := range tests {
		got := parseValue(tc.input)
		switch expected := tc.want.(type) {
		case bool:
			if got != expected {
				t.Errorf("parseValue(%q) = %v (%T), want %v", tc.input, got, got, expected)
			}
		case int:
			if got != expected {
				t.Errorf("parseValue(%q) = %v (%T), want %v", tc.input, got, got, expected)
			}
		case float64:
			if got != expected {
				t.Errorf("parseValue(%q) = %v (%T), want %v", tc.input, got, got, expected)
			}
		case string:
			if got != expected {
				t.Errorf("parseValue(%q) = %v (%T), want %v", tc.input, got, got, expected)
			}
		}
	}
}

// ─── setNestedValue ───────────────────────────────────────────────────────────

func TestSetNestedValue_SingleLevel(t *testing.T) {
	m := map[string]interface{}{}
	err := setNestedValue(m, []string{"key"}, "value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m["key"] != "value" {
		t.Errorf("m[key] = %v, want 'value'", m["key"])
	}
}

func TestSetNestedValue_MultiLevel(t *testing.T) {
	m := map[string]interface{}{
		"server": map[string]interface{}{
			"host": "0.0.0.0",
		},
	}
	err := setNestedValue(m, []string{"server", "port"}, "8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	server := m["server"].(map[string]interface{})
	if server["port"] != 8080 {
		t.Errorf("server.port = %v, want 8080", server["port"])
	}
}

func TestSetNestedValue_CreateIntermediate(t *testing.T) {
	m := map[string]interface{}{}
	err := setNestedValue(m, []string{"a", "b", "c"}, "deep")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a := m["a"].(map[string]interface{})
	b := a["b"].(map[string]interface{})
	if b["c"] != "deep" {
		t.Errorf("a.b.c = %v, want 'deep'", b["c"])
	}
}

func TestSetNestedValue_EmptyPath(t *testing.T) {
	m := map[string]interface{}{}
	err := setNestedValue(m, []string{}, "value")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestSetNestedValue_NotAMap(t *testing.T) {
	m := map[string]interface{}{
		"key": "string_value",
	}
	err := setNestedValue(m, []string{"key", "sub"}, "value")
	if err == nil {
		t.Error("expected error when intermediate is not a map")
	}
}

// ─── envConfig ────────────────────────────────────────────────────────────────

func TestEnvConfig_FlagOverride(t *testing.T) {
	got := envConfig("/custom/path.yaml")
	if got != "/custom/path.yaml" {
		t.Errorf("envConfig = %q, want /custom/path.yaml", got)
	}
}

func TestEnvConfig_Default(t *testing.T) {
	got := envConfig("configs/default.yaml")
	// Without env var set, should return the default
	if got != "configs/default.yaml" {
		t.Errorf("envConfig = %q, want configs/default.yaml", got)
	}
}

// ─── envPort ──────────────────────────────────────────────────────────────────

func TestEnvPort_FlagOverride(t *testing.T) {
	got := envPort(8080)
	if got != 8080 {
		t.Errorf("envPort = %d, want 8080", got)
	}
}

func TestEnvPort_Zero(t *testing.T) {
	got := envPort(0)
	// Without env var, returns 0
	if got != 0 {
		t.Errorf("envPort = %d, want 0", got)
	}
}

// ─── envHost ──────────────────────────────────────────────────────────────────

func TestEnvHost_FlagOverride(t *testing.T) {
	got := envHost("10.0.0.1")
	if got != "10.0.0.1" {
		t.Errorf("envHost = %q, want 10.0.0.1", got)
	}
}

func TestEnvHost_Empty(t *testing.T) {
	got := envHost("")
	// Without env var, returns empty
	if got != "" {
		t.Errorf("envHost = %q, want empty", got)
	}
}

// ─── isConnectionError ────────────────────────────────────────────────────────

func TestIsConnectionError(t *testing.T) {
	if isConnectionError(nil) {
		t.Error("nil should not be a connection error")
	}
	tests := []struct {
		msg  string
		want bool
	}{
		{"connection reset by peer", true},
		{"unexpected EOF", true},
		{"connection refused", true},
		{"timeout waiting for response", false},
		{"some other error", false},
	}
	for _, tc := range tests {
		err := &testError{msg: tc.msg}
		got := isConnectionError(err)
		if got != tc.want {
			t.Errorf("isConnectionError(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// ─── OutputFormat ─────────────────────────────────────────────────────────────

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input string
		want  OutputFormat
	}{
		{"json", FormatJSON},
		{"JSON", FormatJSON},
		{"csv", FormatCSV},
		{"CSV", FormatCSV},
		{"sarif", FormatSARIF},
		{"SARIF", FormatSARIF},
		{"table", FormatTable},
		{"", FormatTable},
		{"unknown", FormatTable},
	}
	for _, tc := range tests {
		got := parseFormat(tc.input)
		if got != tc.want {
			t.Errorf("parseFormat(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestFormatName(t *testing.T) {
	tests := []struct {
		input OutputFormat
		want  string
	}{
		{FormatJSON, "json"},
		{FormatCSV, "csv"},
		{FormatSARIF, "sarif"},
		{FormatTable, "table"},
	}
	for _, tc := range tests {
		got := formatName(tc.input)
		if got != tc.want {
			t.Errorf("formatName(%v) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ─── Table ────────────────────────────────────────────────────────────────────

func TestTable_Render(t *testing.T) {
	var buf bytes.Buffer
	tbl := NewTable(&buf, "Name", "Value")
	tbl.AddRow("key1", "val1")
	tbl.AddRow("key2", "val2")
	tbl.Render()

	output := buf.String()
	if !strings.Contains(output, "key1") {
		t.Error("table should contain 'key1'")
	}
	if !strings.Contains(output, "val2") {
		t.Error("table should contain 'val2'")
	}
	// Should have box-drawing characters
	if !strings.Contains(output, "┌") {
		t.Error("table should have box-drawing borders")
	}
}

func TestTable_EmptyHeaders(t *testing.T) {
	var buf bytes.Buffer
	tbl := NewTable(&buf)
	tbl.Render()
	if buf.Len() != 0 {
		t.Error("empty headers should produce no output")
	}
}

func TestTable_PadShortRow(t *testing.T) {
	var buf bytes.Buffer
	tbl := NewTable(&buf, "A", "B", "C")
	tbl.AddRow("only_one") // fewer values than headers
	tbl.Render()
	// Should not panic
	if !strings.Contains(buf.String(), "only_one") {
		t.Error("table should contain the short row value")
	}
}

// ─── writeCSV ─────────────────────────────────────────────────────────────────

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	writeCSV(&buf, []string{"Name", "Age"}, [][]string{
		{"Alice", "30"},
		{"Bob", "25"},
	})

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("CSV parse error: %v", err)
	}
	if len(records) != 3 { // header + 2 rows
		t.Errorf("expected 3 records, got %d", len(records))
	}
	if records[1][0] != "Alice" {
		t.Errorf("first data row = %v", records[1])
	}
}

// ─── SARIF ────────────────────────────────────────────────────────────────────

func TestSarifLevel(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"INFO", "note"},
	}
	for _, tc := range tests {
		got := sarifLevel(tc.input)
		if got != tc.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	alerts := []interface{}{
		map[string]interface{}{
			"module":   "test_module",
			"type":     "test_type",
			"severity": "HIGH",
			"title":    "Test Alert",
		},
	}
	writeSARIF(&buf, alerts, "1.0.0")

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("SARIF parse error: %v", err)
	}
	if report.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}
	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Runs[0].Results))
	}
	if report.Runs[0].Results[0].Level != "error" {
		t.Errorf("level = %q, want error", report.Runs[0].Results[0].Level)
	}
}

// ─── Shell completions ───────────────────────────────────────────────────────

func TestBashCompletions(t *testing.T) {
	s := bashCompletions()
	if !strings.Contains(s, "1sec") {
		t.Error("bash completions should reference '1sec'")
	}
	if !strings.Contains(s, "complete") {
		t.Error("bash completions should contain 'complete' directive")
	}
}

func TestZshCompletions(t *testing.T) {
	s := zshCompletions()
	if !strings.Contains(s, "1sec") {
		t.Error("zsh completions should reference '1sec'")
	}
}

func TestFishCompletions(t *testing.T) {
	s := fishCompletions()
	if !strings.Contains(s, "1sec") {
		t.Error("fish completions should reference '1sec'")
	}
}

func TestPowershellCompletions(t *testing.T) {
	s := powershellCompletions()
	if !strings.Contains(s, "1sec") {
		t.Error("powershell completions should reference '1sec'")
	}
}

// ─── Banner ───────────────────────────────────────────────────────────────────

func TestBannerText(t *testing.T) {
	b := bannerText()
	if !strings.Contains(b, "CYBER DEFENSE") {
		t.Error("banner should contain tagline")
	}
}

func TestPrintVersion(t *testing.T) {
	var buf bytes.Buffer
	printVersion(&buf)
	output := buf.String()
	if !strings.Contains(output, "1sec") {
		t.Error("version output should contain '1sec'")
	}
	if !strings.Contains(output, version) {
		t.Errorf("version output should contain version %q", version)
	}
}

func TestPrintUsage(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf)
	output := buf.String()
	if !strings.Contains(output, "COMMANDS") {
		t.Error("usage should contain COMMANDS section")
	}
	if !strings.Contains(output, "up") {
		t.Error("usage should list 'up' command")
	}
}
