package collect

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

type githubResponseTransport func(*http.Request) (*http.Response, error)

func (f githubResponseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGitHubResponseBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		valid      bool
	}{
		{"ordinary", `{"workflow_runs":[{"id":42}]}`, 200, true},
		{"padding", `{"workflow_runs":[]}` + strings.Repeat(" ", 4<<20), 200, false},
		{"trailing-json", `{"workflow_runs":[]}{}`, 200, false},
		{"error", "sensitive-reflected-provider-body", 500, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewGitHubCollector("owner/repo", "")
			c.token = "test-token"
			c.httpClient.Transport = githubResponseTransport(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing credential")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header), Request: req}, nil
			})
			runs, err := c.fetchWorkflowRuns(t.Context())
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected result: %v", err)
			}
			if tc.valid && len(runs) != 1 {
				t.Fatal("workflow run missing")
			}
			if err != nil && strings.Contains(err.Error(), tc.body) {
				t.Fatal("untrusted response reflected in error")
			}
		})
	}
}

func TestGitHubRedirectBoundary(t *testing.T) {
	for _, target := range []string{"https://api.github.com/repos/new/runs", "https://api.github.com:444/leak", "https://other.example/leak"} {
		c := NewGitHubCollector("old/repo", "")
		calls := 0
		c.httpClient.Transport = githubResponseTransport(func(req *http.Request) (*http.Response, error) {
			calls++
			status, body := 200, `{"workflow_runs":[]}`
			header := make(http.Header)
			if calls == 1 {
				status = 301
				header.Set("Location", target)
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: header, Request: req}, nil
		})
		_, err := c.fetchWorkflowRuns(t.Context())
		allowed := target == "https://api.github.com/repos/new/runs"
		if (err == nil) != allowed || (!allowed && calls != 1) {
			t.Fatalf("redirect %s: calls=%d err=%v", target, calls, err)
		}
	}
}

func TestGitHubPollProcessesNewestFirstResponseWithoutSkipping(t *testing.T) {
	cfg := &core.BusConfig{Embedded: true, Port: -1, DataDir: t.TempDir()}
	bus, err := core.NewEventBus(cfg, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()

	c := NewGitHubCollector("owner/repo", "")
	c.httpClient.Transport = githubResponseTransport(func(req *http.Request) (*http.Response, error) {
		body := `{"workflow_runs":[{"id":43},{"id":42}]}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
	})
	c.poll(t.Context(), bus, zerolog.Nop())
	c.poll(t.Context(), bus, zerolog.Nop())
	if count := bus.GetMetrics()["events_published"]; count != 2 || c.lastSeen != 43 {
		t.Fatalf("published %d events with cursor %d", count, c.lastSeen)
	}
}
