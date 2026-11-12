package collect

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// GitHubCollector polls GitHub Actions workflow runs and emits cicd_event and
// package_install canonical events. Requires a GitHub token with actions:read.
//
// Config:
//
//	type: github
//	log_path: "owner/repo"  (reused as repo identifier)
//	tag: "github"
//
// Environment:
//
//	GITHUB_TOKEN — personal access token or fine-grained token with actions:read
type GitHubCollector struct {
	repo       string // "owner/repo"
	tag        string
	token      string
	interval   time.Duration
	cancel     context.CancelFunc
	done       chan struct{}
	lastSeen   int64 // last workflow run ID we've processed
	httpClient *http.Client
}

func NewGitHubCollector(repo, tag string) *GitHubCollector {
	if tag == "" {
		tag = "github"
	}
	return &GitHubCollector{
		repo:       repo,
		tag:        tag,
		interval:   60 * time.Second, // poll every 60s
		httpClient: core.NewAuthenticatedHTTPClient(15 * time.Second),
	}
}

func (c *GitHubCollector) Name() string { return "github:" + c.repo }

func (c *GitHubCollector) Start(ctx context.Context, bus *core.EventBus, logger zerolog.Logger) error {
	// Get token from environment
	c.token = os.Getenv("GITHUB_TOKEN")
	if c.token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable required for GitHub collector")
	}

	ctx, c.cancel = context.WithCancel(ctx)
	c.done = make(chan struct{})

	go func() {
		defer close(c.done)
		c.poll(ctx, bus, logger)

		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.poll(ctx, bus, logger)
			}
		}
	}()

	return nil
}

func (c *GitHubCollector) poll(ctx context.Context, bus *core.EventBus, logger zerolog.Logger) {
	runs, err := c.fetchWorkflowRuns(ctx)
	if err != nil {
		if ctx.Err() == nil {
			logger.Error().Err(err).Str("repo", c.repo).Msg("failed to fetch GitHub workflow runs")
		}
		return
	}

	slices.SortStableFunc(runs, func(a, b map[string]interface{}) int {
		aID, _ := a["id"].(float64)
		bID, _ := b["id"].(float64)
		return cmp.Compare(aID, bID)
	})
	for _, run := range runs {
		if ctx.Err() != nil {
			return
		}
		runID, _ := run["id"].(float64)
		if int64(runID) <= c.lastSeen {
			continue
		}

		if err := bus.PublishEvent(c.buildEvent(run)); err != nil {
			logger.Error().Err(err).Str("repo", c.repo).Msg("failed to publish GitHub workflow run")
			return
		}
		c.lastSeen = int64(runID)
	}
}

func (c *GitHubCollector) fetchWorkflowRuns(ctx context.Context) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs?per_page=20", c.repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}
	body, err := core.ReadBoundedResponse(resp.Body, 4<<20)
	if err != nil {
		return nil, fmt.Errorf("reading GitHub response: %w", err)
	}

	var result struct {
		WorkflowRuns []map[string]interface{} `json:"workflow_runs"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.WorkflowRuns, nil
}

func (c *GitHubCollector) buildEvent(run map[string]interface{}) *core.SecurityEvent {
	name, _ := run["name"].(string)
	status, _ := run["status"].(string)
	conclusion, _ := run["conclusion"].(string)
	branch, _ := run["head_branch"].(string)
	event, _ := run["event"].(string) // push, pull_request, etc.

	severity := core.SeverityInfo
	summary := fmt.Sprintf("workflow %s: %s (%s)", name, conclusion, event)

	// Flag failures
	if conclusion == "failure" {
		severity = core.SeverityMedium
		summary = fmt.Sprintf("workflow FAILED: %s on %s (%s)", name, branch, event)
	}

	// Flag suspicious triggers
	lowerEvent := strings.ToLower(event)
	if lowerEvent == "workflow_dispatch" || lowerEvent == "repository_dispatch" {
		severity = core.SeverityLow // manual/external triggers are worth noting
	}

	secEvent := core.NewSecurityEvent(c.tag, "cicd_event", severity, summary)
	secEvent.Source = "collector:" + c.tag
	secEvent.Details["action"] = conclusion
	secEvent.Details["pipeline_name"] = name
	secEvent.Details["branch"] = branch
	secEvent.Details["trigger"] = event
	secEvent.Details["status"] = status

	if actor, ok := run["actor"].(map[string]interface{}); ok {
		if login, ok := actor["login"].(string); ok {
			secEvent.Details["user"] = login
		}
	}

	if runID, ok := run["id"].(float64); ok {
		secEvent.Details["run_id"] = fmt.Sprintf("%.0f", runID)
	}

	if htmlURL, ok := run["html_url"].(string); ok {
		secEvent.Details["url"] = htmlURL
	}

	return secEvent
}

func (c *GitHubCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
		<-c.done
	}
	return nil
}
