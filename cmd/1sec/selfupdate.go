package main

// ---------------------------------------------------------------------------
// selfupdate.go — automatic self-update on CLI launch
//
// On every invocation the CLI spawns a lightweight goroutine that checks
// the latest GitHub release tag and announces verified installation options.
// It never downloads executable code. The check is non-blocking and
// respects ONESEC_NO_UPDATE=1 to opt out.
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	githubRepo       = "simpleending/1-sec"
	updateEnvDisable = "ONESEC_NO_UPDATE"
	updateCheckFile  = ".1sec_last_update_check"
	checkInterval    = 24 * time.Hour
)

// githubRelease is the minimal shape we need from the GitHub API.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// selfUpdate checks for a newer release without replacing executable code.
// It prints a short message to stderr so the user knows what happened.
// Returns false; installation requires the signed release installer.
func selfUpdate(currentVersion string, quiet bool) bool {
	if os.Getenv(updateEnvDisable) == "1" {
		return false
	}

	if !shouldCheck() {
		return false
	}

	rel, err := fetchLatestRelease()
	if err != nil {
		// Network issues are not fatal — just skip silently.
		return false
	}

	latestVer := strings.TrimPrefix(rel.TagName, "v")
	if !isNewer(latestVer, currentVersion) {
		touchCheckFile()
		return false
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "%s New version available: %s to %s\n", cyan("Update"), currentVersion, latestVer)
		fmt.Fprintln(os.Stderr, "  Install a verified release: https://1-sec.dev/get")
	}
	touchCheckFile()
	return false
}

// shouldCheck returns true if enough time has passed since the last check.
func shouldCheck() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return true
	}
	path := filepath.Join(home, updateCheckFile)
	info, err := os.Stat(path)
	if err != nil {
		return true // file doesn't exist yet
	}
	return time.Since(info.ModTime()) >= checkInterval
}

// touchCheckFile updates the timestamp of the check marker file.
func touchCheckFile() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	path := filepath.Join(home, updateCheckFile)
	f, err := os.Create(path)
	if err == nil {
		f.Close()
	}
}

// fetchLatestRelease queries the GitHub releases API.
func fetchLatestRelease() (*githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github API returned %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
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
