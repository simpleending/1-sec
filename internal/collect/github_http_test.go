package collect

import (
	"errors"
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
			runs, err := c.fetchWorkflowPage(t.Context(), 1)
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
		_, err := c.fetchWorkflowPage(t.Context(), 1)
		allowed := target == "https://api.github.com/repos/new/runs"
		if (err == nil) != allowed || (!allowed && calls != 1) {
			t.Fatalf("redirect %s: calls=%d err=%v", target, calls, err)
		}
	}
}

func TestGitHubPollTracksAttemptsStatesAndRestart(t *testing.T) {
	body := `{"workflow_runs":[{"id":43,"run_attempt":1,"status":"queued"},{"id":42,"run_attempt":1,"status":"completed","conclusion":"success"}]}`
	integration := githubResponseTransport(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
	})
	dir := t.TempDir()
	makeCollector := func() *GitHubCollector {
		c := NewGitHubCollector("owner/repo", "")
		c.httpClient.Transport = integration
		c.useCheckpointDir(dir)
		if err := c.loadCheckpoint(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := makeCollector()
	var got []*core.SecurityEvent
	publish := func(e *core.SecurityEvent) error {
		got = append(got, e)
		return nil
	}
	logger := zerolog.Nop()
	c.poll(t.Context(), publish, logger)
	c.poll(t.Context(), publish, logger)
	if len(got) != 2 || got[0].Details["run_id"] != "42" || got[1].Details["run_id"] != "43" {
		t.Fatalf("first snapshots not published once in deterministic order: %+v", got)
	}

	body = `{"workflow_runs":[{"id":43,"run_attempt":1,"status":"completed","conclusion":"failure"}]}`
	c.poll(t.Context(), func(*core.SecurityEvent) error { return errors.New("ordinary temporary publisher failure") }, logger)
	c.poll(t.Context(), publish, logger)
	if len(got) != 3 || got[2].Details["action"] != "failure" || got[2].Severity != core.SeverityMedium {
		t.Fatal("same-run failure was not retried and emitted")
	}
	c = makeCollector()
	c.poll(t.Context(), publish, logger)
	if len(got) != 3 {
		t.Fatal("restart replayed a checkpointed state")
	}
	body = `{"workflow_runs":[{"id":43,"run_attempt":2,"status":"queued"}]}`
	c.poll(t.Context(), publish, logger)
	if len(got) != 4 || got[3].Details["run_attempt"] != 2 {
		t.Fatal("new attempt was not emitted")
	}
}
