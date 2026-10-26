package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type releaseTransport func(*http.Request) (*http.Response, error)

func (f releaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestUpdateCheckDoesNotDownloadOrReplaceCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv(updateEnvDisable, "")
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	calls := 0
	http.DefaultTransport = releaseTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if !strings.HasSuffix(r.URL.Path, "/releases/latest") {
			t.Fatal("executable download attempted", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"tag_name":"v999.0.0","assets":[{"name":"binary","browser_download_url":"https://malicious.example/binary"}]}`)), Header: make(http.Header)}, nil
	})
	if selfUpdate("0.0.1", true) {
		t.Fatal("unexpected binary replacement")
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}

func TestIsNewer(t *testing.T) {
	tests := []struct {
		latest, current string
		want            bool
	}{
		{"0.3.7", "0.3.6", true},
		{"0.4.0", "0.3.6", true},
		{"1.0.0", "0.9.9", true},
		{"0.3.6", "0.3.6", false},
		{"0.3.5", "0.3.6", false},
		{"0.2.9", "0.3.0", false},
		{"v1.0.0", "0.3.6", true},
		{"0.3.7", "v0.3.6", true},
	}
	for _, tt := range tests {
		got := isNewer(tt.latest, tt.current)
		if got != tt.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
		}
	}
}

func TestHasFlag(t *testing.T) {
	args := []string{"up", "--quiet", "--config", "foo.yaml"}
	if !hasFlag(args, "-q", "--quiet") {
		t.Error("expected hasFlag to find --quiet")
	}
	if hasFlag(args, "-v", "--verbose") {
		t.Error("expected hasFlag to not find --verbose")
	}
}
