package main

// ---------------------------------------------------------------------------
// cmd_archive.go — cold archive management (status, restore)
//
// Usage:
//   1sec archive status                          Show archiver metrics
//   1sec archive restore --from 2026-02-20       Restore events from archive
//   1sec archive ls                              List archive files
// ---------------------------------------------------------------------------

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/1sec-project/1sec/internal/core"
)

func cmdArchive(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: 1sec archive <subcommand> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Subcommands:\n")
		fmt.Fprintf(os.Stderr, "  status    Show archiver metrics from running instance\n")
		fmt.Fprintf(os.Stderr, "  ls        List archive files on disk\n")
		fmt.Fprintf(os.Stderr, "  restore   Replay archived events back into the engine\n")
		os.Exit(1)
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "status":
		cmdArchiveStatus(subArgs)
	case "ls":
		cmdArchiveList(subArgs)
	case "restore":
		cmdArchiveRestore(subArgs)
	default:
		fmt.Fprintf(os.Stderr, red("error: ")+"unknown archive subcommand %q\n", subcmd)
		os.Exit(1)
	}
}

func cmdArchiveStatus(args []string) {
	fs := flag.NewFlagSet("archive status", flag.ExitOnError)
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKey := fs.String("api-key", "", "API key")
	fs.Parse(args)

	*configPath = envConfig(*configPath)
	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	resp, err := doGet(base+"/api/v1/archive/status", key)
	if err != nil {
		errorf("fetching archive status: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		errorf("decoding archive status response: %v", err)
	}

	if enabled, ok := result["enabled"].(bool); ok && !enabled {
		fmt.Printf("%s Archive is disabled. Enable it in config: archive.enabled: true\n", yellow("⚠"))
		return
	}

	fmt.Printf("%s Cold Archiver Status\n\n", bold("📦"))
	fmt.Printf("  %-22s %v\n", "Directory:", result["dir"])
	fmt.Printf("  %-22s %v\n", "Compress:", result["compress"])
	fmt.Printf("  %-22s %v\n", "Current file:", result["current_file"])
	fmt.Printf("  %-22s %v bytes\n", "Current file size:", result["current_bytes"])
	fmt.Printf("  %-22s %v\n", "Events archived:", result["events_archived"])
	fmt.Printf("  %-22s %v\n", "Alerts archived:", result["alerts_archived"])
	if sampled, ok := result["events_sampled"]; ok {
		fmt.Printf("  %-22s %v\n", "Events sampled out:", sampled)
	}
	fmt.Printf("  %-22s %v\n", "Files rotated:", result["files_rotated"])
	fmt.Printf("  %-22s %v bytes\n", "Total bytes written:", result["bytes_written"])
}

func cmdArchiveList(args []string) {
	fs := flag.NewFlagSet("archive ls", flag.ExitOnError)
	dir := fs.String("dir", "./data/archive", "Archive directory")
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	fs.Parse(args)

	// Try to get dir from config
	*configPath = envConfig(*configPath)
	if cfg, err := core.LoadConfig(*configPath); err == nil && cfg.Archive.Dir != "" {
		*dir = cfg.Archive.Dir
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		errorf("reading archive dir %s: %v", *dir, err)
	}

	type fileInfo struct {
		name string
		size int64
	}
	var files []fileInfo
	var totalSize int64

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), "1sec-archive-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{name: e.Name(), size: info.Size()})
		totalSize += info.Size()
	}

	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })

	fmt.Printf("%s Archive files in %s\n\n", bold("📦"), *dir)
	for _, f := range files {
		fmt.Printf("  %-50s  %s\n", f.name, humanBytes(f.size))
	}
	fmt.Printf("\n  %d files, %s total\n", len(files), humanBytes(totalSize))
}

func cmdArchiveRestore(args []string) {
	fs := flag.NewFlagSet("archive restore", flag.ExitOnError)
	dir := fs.String("dir", "./data/archive", "Archive directory")
	configPath := fs.String("config", "configs/default.yaml", "Config file path")
	from := fs.String("from", "", "Start date (YYYY-MM-DD or YYYYMMDD)")
	to := fs.String("to", "", "End date (YYYY-MM-DD or YYYYMMDD, default: now)")
	host := fs.String("host", "", "API host override")
	port := fs.Int("port", 0, "API port override")
	apiKey := fs.String("api-key", "", "API key")
	dryRun := fs.Bool("dry-run", false, "Count events without actually restoring")
	typesOnly := fs.String("types", "", "Comma-separated event types to restore (default: all)")
	fs.Parse(args)

	if *from == "" {
		errorf("--from is required (e.g., --from 2026-02-20)")
	}

	*configPath = envConfig(*configPath)
	if cfg, err := core.LoadConfig(*configPath); err == nil && cfg.Archive.Dir != "" {
		*dir = cfg.Archive.Dir
	}

	base := apiBase(*configPath, envHost(*host), envPort(*port))
	key := resolveAPIKey(*apiKey, *configPath)

	// Parse date range
	fromDate := parseArchiveDate(*from)
	toDate := time.Now().UTC()
	if *to != "" {
		toDate = parseArchiveDate(*to).Add(24 * time.Hour) // include the end date
	}

	// Build type filter
	typeFilter := make(map[string]bool)
	if *typesOnly != "" {
		for _, t := range strings.Split(*typesOnly, ",") {
			typeFilter[strings.TrimSpace(t)] = true
		}
	}

	// Find matching archive files
	entries, err := os.ReadDir(*dir)
	if err != nil {
		errorf("reading archive dir: %v", err)
	}

	var matchingFiles []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "1sec-archive-") {
			continue
		}
		fileTime, err := archiveFileTime(e.Name())
		if err != nil {
			continue
		}

		if !fileTime.Before(fromDate) && fileTime.Before(toDate) {
			matchingFiles = append(matchingFiles, filepath.Join(*dir, e.Name()))
		}
	}

	sort.Strings(matchingFiles)

	if len(matchingFiles) == 0 {
		fmt.Printf("%s No archive files found for date range %s to %s\n",
			yellow("⚠"), fromDate.Format("2006-01-02"), toDate.Format("2006-01-02"))
		return
	}

	fmt.Printf("%s Restoring from %d archive files (%s to %s)\n",
		dim("▸"), len(matchingFiles), fromDate.Format("2006-01-02"), toDate.Format("2006-01-02"))

	if *dryRun {
		fmt.Printf("%s Dry-run mode — counting events only\n", dim("▸"))
	}

	var totalEvents, totalAlerts, totalSkipped int

	for _, path := range matchingFiles {
		events, alerts, skipped, err := restoreFile(path, base, key, *dryRun, typeFilter)
		if err != nil {
			warnf("error restoring %s: %v", filepath.Base(path), err)
			continue
		}
		totalEvents += events
		totalAlerts += alerts
		totalSkipped += skipped
		fmt.Printf("  %s: %d events, %d alerts restored, %d skipped\n",
			filepath.Base(path), events, alerts, skipped)
	}

	fmt.Printf("\n%s Restore complete: %d events, %d alerts restored, %d skipped\n",
		green("✓"), totalEvents, totalAlerts, totalSkipped)
}

// Read both historical second-resolution names and unique committed-archive names.
func archiveFileTime(name string) (time.Time, error) {
	if !strings.HasPrefix(name, "1sec-archive-") || (!strings.HasSuffix(name, ".ndjson") && !strings.HasSuffix(name, ".ndjson.gz")) {
		return time.Time{}, fmt.Errorf("invalid archive filename")
	}
	stamp := strings.TrimPrefix(name, "1sec-archive-")
	stamp = strings.TrimSuffix(strings.TrimSuffix(stamp, ".gz"), ".ndjson")
	end := strings.IndexByte(stamp, 'Z')
	if end < 0 {
		return time.Time{}, fmt.Errorf("archive filename has no UTC timestamp")
	}
	if suffix := stamp[end+1:]; suffix != "" {
		if len(suffix) < 2 || suffix[0] != '-' {
			return time.Time{}, fmt.Errorf("invalid archive uniqueness suffix")
		}
		for _, ch := range suffix[1:] {
			if ch < '0' || ch > '9' {
				return time.Time{}, fmt.Errorf("invalid archive uniqueness suffix")
			}
		}
	}
	return time.Parse("20060102T150405.999999999Z", stamp[:end+1])
}

func restoreFile(path, apiBase, apiKey string, dryRun bool, typeFilter map[string]bool) (events, alerts, skipped int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, 0, err
	}
	defer f.Close()

	var reader io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("opening gzip: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1MB line buffer

	for scanner.Scan() {
		line := scanner.Bytes()

		var rec struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			skipped++
			continue
		}

		// Apply type filter for events
		if rec.Type == "event" && len(typeFilter) > 0 {
			var partial struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(rec.Data, &partial); err == nil {
				if !typeFilter[partial.Type] {
					skipped++
					continue
				}
			}
		}

		if dryRun {
			switch rec.Type {
			case "event":
				events++
			case "alert":
				alerts++
			}
			continue
		}

		// POST event back to the engine
		if rec.Type == "event" {
			if err := postRestore(apiBase+"/api/v1/events", apiKey, rec.Data); err != nil {
				skipped++
				continue
			}
			events++
		} else if rec.Type == "alert" {
			alerts++ // alerts are informational in restore — they'll be re-generated
		} else {
			skipped++
		}
	}

	return events, alerts, skipped, scanner.Err()
}

func postRestore(url, apiKey string, data []byte) error {
	req, err := http.NewRequest("POST", url, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := core.NewAuthenticatedHTTPClient(30 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func parseArchiveDate(s string) time.Time {
	s = strings.ReplaceAll(s, "-", "")
	t, err := time.Parse("20060102", s)
	if err != nil {
		errorf("invalid date %q — use YYYY-MM-DD or YYYYMMDD format", s)
	}
	return t
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
