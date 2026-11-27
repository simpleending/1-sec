package collect

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	stateFile  string
	recent     map[workflowKey]workflowState
	dirty      bool
	httpClient *http.Client
}

const (
	githubRunPageSize       = 20
	githubMaxPages          = 3
	githubMaxRecentAttempts = 256
)

type workflowRun struct {
	ID         int64  `json:"id"`
	RunAttempt int    `json:"run_attempt"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	HeadBranch string `json:"head_branch"`
	HeadSHA    string `json:"head_sha"`
	Trigger    string `json:"event"`
	HTMLURL    string `json:"html_url"`
	Actor      struct {
		Login string `json:"login"`
	} `json:"actor"`
}

type workflowKey struct {
	ID      int64 `json:"id"`
	Attempt int   `json:"attempt"`
}

type workflowState struct {
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

type workflowCheckpoint struct {
	workflowKey
	workflowState
}

func compareWorkflowKeys(a, b workflowKey) int {
	if x := cmp.Compare(a.ID, b.ID); x != 0 {
		return x
	}
	return cmp.Compare(a.Attempt, b.Attempt)
}

func (r workflowRun) key() workflowKey {
	return workflowKey{r.ID, max(1, r.RunAttempt)}
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
		recent:     make(map[workflowKey]workflowState),
	}
}

func (c *GitHubCollector) Name() string { return "github:" + c.repo }

func (c *GitHubCollector) Start(ctx context.Context, bus *core.EventBus, logger zerolog.Logger) error {
	// Get token from environment
	c.token = os.Getenv("GITHUB_TOKEN")
	if c.token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable required for GitHub collector")
	}

	if err := c.loadCheckpoint(); err != nil {
		return err
	}
	ctx, c.cancel = context.WithCancel(ctx)
	c.done = make(chan struct{})

	go func() {
		defer close(c.done)
		c.poll(ctx, bus.PublishEvent, logger)

		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.poll(ctx, bus.PublishEvent, logger)
			}
		}
	}()

	return nil
}

func (c *GitHubCollector) poll(ctx context.Context, publish func(*core.SecurityEvent) error, logger zerolog.Logger) {
	var runs []workflowRun
	for page := 1; page <= githubMaxPages; page++ {
		batch, err := c.fetchWorkflowPage(ctx, page)
		if err != nil {
			if ctx.Err() == nil {
				logger.Error().Err(err).Str("repo", c.repo).Msg("failed to fetch GitHub workflow runs")
			}
			return
		}
		runs = append(runs, batch...)
		if len(batch) < githubRunPageSize {
			break
		}
		if page == githubMaxPages {
			overlap := false
			for _, run := range runs {
				if _, ok := c.recent[run.key()]; ok {
					overlap = true
					break
				}
			}
			if !overlap {
				logger.Warn().Str("repo", c.repo).Msg("GitHub poll reached lookback limit without overlapping known runs; older workflow history may be missing")
			}
		}
	}

	slices.SortStableFunc(runs, func(a, b workflowRun) int {
		return compareWorkflowKeys(a.key(), b.key())
	})
	defer func() {
		if err := c.saveCheckpoint(); err != nil {
			logger.Error().Err(err).Str("repo", c.repo).Msg("failed to save GitHub checkpoint; events may replay after restart")
		}
	}()
	for _, run := range runs {
		if ctx.Err() != nil {
			return
		}
		if run.ID <= 0 {
			continue
		}
		key, state := run.key(), workflowState{run.Status, run.Conclusion}
		previous, known := c.recent[key]
		// A stale in-flight snapshot must not overwrite a terminal attempt.
		if known && (previous == state || (previous.Status == "completed" && state.Status != "completed")) {
			continue
		}
		if err := publish(c.buildEvent(run)); err != nil {
			logger.Error().Err(err).Str("repo", c.repo).Msg("failed to publish GitHub workflow run; will retry within poll window")
			return
		}
		c.recent[key] = state
		c.dirty = true
	}
}

func (c *GitHubCollector) useCheckpointDir(dir string) {
	if dir != "" {
		hash := sha256.Sum256([]byte(strings.ToLower(c.repo) + "\x00" + c.tag))
		c.stateFile = filepath.Join(dir, fmt.Sprintf("github-%x.json", hash[:16]))
	}
}

func (c *GitHubCollector) loadCheckpoint() error {
	if c.stateFile == "" {
		return nil
	}
	dir := filepath.Dir(c.stateFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating checkpoint directory: %w", err)
	}
	if err := core.RestrictPrivatePath(dir, true); err != nil {
		return fmt.Errorf("securing checkpoint directory: %w", err)
	}
	f, err := os.Open(c.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening GitHub checkpoint: %w", err)
	}
	defer f.Close()
	data, err := core.ReadBoundedResponse(f, 128<<10)
	if err != nil {
		return fmt.Errorf("reading GitHub checkpoint: %w", err)
	}
	var checkpoint []workflowCheckpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil || len(checkpoint) > githubMaxRecentAttempts {
		return fmt.Errorf("invalid GitHub checkpoint; preserve it before starting with an empty state directory")
	}
	for _, entry := range checkpoint {
		if entry.ID <= 0 || entry.Attempt <= 0 {
			return fmt.Errorf("invalid GitHub workflow identity in checkpoint")
		}
		c.recent[entry.workflowKey] = entry.workflowState
	}
	return nil
}

func (c *GitHubCollector) saveCheckpoint() error {
	if !c.dirty {
		return nil
	}
	c.dirty = false
	keys := make([]workflowKey, 0, len(c.recent))
	for key := range c.recent {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareWorkflowKeys)
	for len(keys) > githubMaxRecentAttempts {
		delete(c.recent, keys[0])
		keys = keys[1:]
	}
	if c.stateFile == "" {
		return nil
	}
	if err := c.writeCheckpoint(keys); err != nil {
		c.dirty = true // keep retrying persistence without suppressing failures
		return err
	}
	return nil
}

func (c *GitHubCollector) writeCheckpoint(keys []workflowKey) error {
	checkpoint := make([]workflowCheckpoint, 0, len(keys))
	for _, key := range keys {
		checkpoint = append(checkpoint, workflowCheckpoint{key, c.recent[key]})
	}
	f, err := os.CreateTemp(filepath.Dir(c.stateFile), ".github-checkpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := core.RestrictPrivatePath(f.Name(), false); err != nil {
		f.Close()
		return err
	}
	if err := json.NewEncoder(f).Encode(checkpoint); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), c.stateFile)
}

func (c *GitHubCollector) fetchWorkflowPage(ctx context.Context, page int) ([]workflowRun, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs?per_page=%d&page=%d", c.repo, githubRunPageSize, page)
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
		WorkflowRuns []workflowRun `json:"workflow_runs"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if len(result.WorkflowRuns) > githubRunPageSize {
		return nil, fmt.Errorf("GitHub API exceeded workflow page size")
	}
	return result.WorkflowRuns, nil
}

func (c *GitHubCollector) buildEvent(run workflowRun) *core.SecurityEvent {
	severity := core.SeverityInfo
	summary := fmt.Sprintf("workflow %s: %s (%s)", run.Name, run.Conclusion, run.Trigger)
	if run.Conclusion == "failure" {
		severity = core.SeverityMedium
		summary = fmt.Sprintf("workflow FAILED: %s on %s (%s)", run.Name, run.HeadBranch, run.Trigger)
	} else if event := strings.ToLower(run.Trigger); event == "workflow_dispatch" || event == "repository_dispatch" {
		severity = core.SeverityLow
	}

	event := core.NewSecurityEvent(c.tag, "cicd_event", severity, summary)
	event.Source = "collector:" + c.tag
	event.Details["action"] = run.Conclusion
	event.Details["pipeline_name"] = run.Name
	event.Details["branch"] = run.HeadBranch
	event.Details["trigger"] = run.Trigger
	event.Details["status"] = run.Status
	event.Details["run_id"] = fmt.Sprint(run.ID)
	event.Details["run_attempt"] = run.key().Attempt
	if run.HeadSHA != "" {
		event.Details["head_sha"] = run.HeadSHA
	}
	if run.Actor.Login != "" {
		event.Details["user"] = run.Actor.Login
	}
	if run.HTMLURL != "" {
		event.Details["url"] = run.HTMLURL
	}
	return event
}

func (c *GitHubCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
		<-c.done
	}
	return nil
}
