package main

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveFilenameCompatibility(t *testing.T) {
	for _, name := range []string{"1sec-archive-20261105T000000Z.ndjson", "1sec-archive-20261105T000000Z.ndjson.gz", "1sec-archive-20261105T000000.123456789Z-424242.ndjson.gz"} {
		ts, err := archiveFileTime(name)
		if err != nil || ts.Year() != 2026 || ts.Day() != 5 {
			t.Fatalf("lost archive %q: %v %v", name, ts, err)
		}
	}
	for _, name := range []string{"unrelated.ndjson", "1sec-archive-invalid.ndjson", "1sec-archive-20261105T000000Z-unexpected.ndjson.gz"} {
		if _, err := archiveFileTime(name); err == nil {
			t.Fatal("accepted unrelated archive filename", name)
		}
	}
}

func TestArchiveRestoreReadsCommittedGzipMembers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1sec-archive-20261105T000000.123456789Z-424242.ndjson.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		gz := gzip.NewWriter(f)
		if _, err := gz.Write([]byte("{\"type\":\"event\",\"data\":{\"type\":\"auth_failure\"}}\n")); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	events, alerts, skipped, err := restoreFile(path, "", "", true, nil)
	if err != nil || events != 3 || alerts != 0 || skipped != 0 {
		t.Fatalf("restore lost committed members: %d/%d/%d %v", events, alerts, skipped, err)
	}
}
