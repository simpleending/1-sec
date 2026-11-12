package collect

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

func TestTailPreservesPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lines := make(chan string, 16)
	stop, err := tailFile(ctx, path, func(line string) { lines <- line }, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	appendLog := func(text string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(text); err != nil {
			t.Fatal(err)
		}
	}
	assertLine := func(want string) {
		t.Helper()
		select {
		case got := <-lines:
			if got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("lost log entry %q", want)
		}
	}
	appendLog("partial-")
	time.Sleep(600 * time.Millisecond) // Reader reaches EOF before the rest of the record arrives.
	appendLog("record\n")
	assertLine("partial-record")
}

func TestTailFollowsLargerReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows open-file sharing prevents POSIX rename rotation")
	}
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lines := make(chan string, 16)
	stop, err := tailFile(ctx, path, func(line string) { lines <- line }, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("replacement", 16)
	if err := os.WriteFile(path, []byte(want+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-lines:
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lost larger replacement file")
	}
}

func TestTailRecoversAfterOversizedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lines := make(chan string, 4)
	stop, err := tailFile(ctx, path, func(line string) { lines <- line }, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Repeat("x", 1024*1024+1) + "\nnext-event\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-lines:
		if got != "next-event" {
			t.Fatalf("oversized record or suffix emitted: length=%d", len(got))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("did not recover after oversized record")
	}
}

func TestCollectorManagerUsesAliasesAndRollsBackFailedStart(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.log")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(zerolog.Nop())
	t.Cleanup(manager.StopAll)
	cfg := core.CollectorsConfig{Sources: []core.CollectorConfig{
		{Type: "auth", LogPath: logPath},
		{Type: "json", LogPath: logPath},
	}}
	if err := manager.StartAll(t.Context(), cfg, nil); err != nil || manager.Count() != 0 {
		t.Fatalf("disabled collectors: count %d, error %v", manager.Count(), err)
	}
	cfg.Enabled = true
	if err := manager.StartAll(t.Context(), cfg, nil); err != nil || manager.Count() != 2 {
		t.Fatalf("enabled collectors: count %d, error %v", manager.Count(), err)
	}
	cfg.Sources[1].LogPath = dir
	if err := manager.StartAll(t.Context(), cfg, nil); err == nil || manager.Count() != 2 {
		t.Fatalf("failed start must roll back only the new batch: count %d, error %v", manager.Count(), err)
	}
	cfg.Sources[1].Type = "unknown"
	if err := manager.StartAll(t.Context(), cfg, nil); err == nil || manager.Count() != 2 {
		t.Fatalf("invalid source: count %d, error %v", manager.Count(), err)
	}
	manager.StopAll()
	if manager.Count() != 0 {
		t.Fatal("collector manager did not stop")
	}
}
