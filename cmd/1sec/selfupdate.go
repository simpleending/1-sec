package main

// ---------------------------------------------------------------------------
// selfupdate.go — release metadata lookup for the explicit diagnostics option
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/1sec-project/1sec/internal/core"
)

const (
	githubRepo = "simpleending/1-sec"
)

// githubRelease is the minimal shape we need from the GitHub API.
type githubRelease struct {
	TagName string `json:"tag_name"`
}

// fetchLatestRelease queries the GitHub releases API.
func fetchLatestRelease() (*githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	client := core.NewAuthenticatedHTTPClient(5 * time.Second)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github API returned %d", resp.StatusCode)
	}

	body, err := core.ReadBoundedResponse(resp.Body, 1<<20)
	if err != nil {
		return nil, err
	}
	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, err
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return nil, fmt.Errorf("GitHub release has no tag")
	}
	return &rel, nil
}

// isNewer returns true if latest is a higher semver than current.
// Simple numeric comparison of major.minor.patch.
func isNewer(latest, current string) bool {
	parse := func(v string) (int, int, int) {
		v = strings.TrimPrefix(v, "v")
		var major, minor, patch int
		fmt.Sscanf(v, "%d.%d.%d", &major, &minor, &patch)
		return major, minor, patch
	}
	lMaj, lMin, lPat := parse(latest)
	cMaj, cMin, cPat := parse(current)
	if lMaj != cMaj {
		return lMaj > cMaj
	}
	if lMin != cMin {
		return lMin > cMin
	}
	return lPat > cPat
}
