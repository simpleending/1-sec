package main

// ---------------------------------------------------------------------------
// selfupdate.go — automatic self-update on CLI launch
//
// On every invocation the CLI spawns a lightweight goroutine that checks
// the latest GitHub release tag. If a newer version exists it downloads
// the matching archive, extracts the binary, and replaces the running
// executable in-place. The check is non-blocking for normal commands and
// respects ONESEC_NO_UPDATE=1 to opt out.
// ---------------------------------------------------------------------------

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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

// selfUpdate checks for a newer release and replaces the binary if found.
// It prints a short message to stderr so the user knows what happened.
// Returns true if an update was applied.
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
		fmt.Fprintf(os.Stderr, "%s New version available: %s → %s\n", cyan("⬆"), currentVersion, latestVer)
		fmt.Fprintf(os.Stderr, "%s Updating...\n", cyan("⬆"))
	}

	if err := applyUpdate(rel); err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "%s Auto-update failed: %v\n", yellow("⚠"), err)
			fmt.Fprintf(os.Stderr, "  Run: curl -fsSL https://1-sec.dev/get | sh\n")
		}
		return false
	}

	touchCheckFile()
	if !quiet {
		fmt.Fprintf(os.Stderr, "%s Updated to v%s\n", green("✓"), latestVer)
	}
	return true
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

// applyUpdate downloads the correct archive and replaces the running binary.
func applyUpdate(rel *githubRelease) error {
	osName := runtime.GOOS
	archName := runtime.GOARCH
	verNum := strings.TrimPrefix(rel.TagName, "v")

	// Match GoReleaser naming: 1sec_0.3.7_linux_amd64.tar.gz
	var ext string
	if osName == "windows" {
		ext = ".zip"
	} else {
		ext = ".tar.gz"
	}
	wantName := fmt.Sprintf("1sec_%s_%s_%s%s", verNum, osName, archName, ext)

	var assetURL string
	for _, a := range rel.Assets {
		if a.Name == wantName {
			assetURL = a.BrowserDownloadURL
			break
		}
	}
	if assetURL == "" {
		return fmt.Errorf("no release asset found for %s/%s (%s)", osName, archName, wantName)
	}

	// Download to temp file
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(assetURL)
	if err != nil {
		return fmt.Errorf("downloading release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	tmpDir, err := os.MkdirTemp("", "1sec-update-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, wantName)
	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()

	// Extract the binary
	binaryName := "1sec"
	if osName == "windows" {
		binaryName = "1sec.exe"
	}

	extractedPath := filepath.Join(tmpDir, binaryName)
	if ext == ".zip" {
		err = extractFromZip(archivePath, binaryName, extractedPath)
	} else {
		err = extractFromTarGz(archivePath, binaryName, extractedPath)
	}
	if err != nil {
		return fmt.Errorf("extracting binary: %w", err)
	}

	// Replace the running executable
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding current executable: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("resolving symlinks: %w", err)
	}

	// On Windows we can't overwrite a running exe, so rename-then-move.
	oldPath := execPath + ".old"
	os.Remove(oldPath) // clean up any previous .old file

	if err := os.Rename(execPath, oldPath); err != nil {
		return fmt.Errorf("backing up current binary: %w", err)
	}

	if err := copyFile(extractedPath, execPath); err != nil {
		// Try to restore the old binary
		os.Rename(oldPath, execPath)
		return fmt.Errorf("installing new binary: %w", err)
	}

	if runtime.GOOS != "windows" {
		os.Chmod(execPath, 0755)
	}

	// Clean up old binary (best-effort)
	os.Remove(oldPath)
	return nil
}

func extractFromTarGz(archivePath, targetName, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// The binary might be at the root or in a subdirectory
		if filepath.Base(hdr.Name) == targetName && hdr.Typeflag == tar.TypeReg {
			out, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer out.Close()
			_, err = io.Copy(out, tr)
			return err
		}
	}
	return fmt.Errorf("%s not found in archive", targetName)
}

func extractFromZip(archivePath, targetName, destPath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, zf := range r.File {
		if filepath.Base(zf.Name) == targetName {
			src, err := zf.Open()
			if err != nil {
				return err
			}
			defer src.Close()
			out, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer out.Close()
			_, err = io.Copy(out, src)
			return err
		}
	}
	return fmt.Errorf("%s not found in archive", targetName)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
