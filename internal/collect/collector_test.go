package collect

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
	if err := tailFile(ctx, path, func(line string) { lines <- line }, zerolog.Nop()); err != nil {
		t.Fatal(err)
	}
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
	if err := tailFile(ctx, path, func(line string) { lines <- line }, zerolog.Nop()); err != nil {
		t.Fatal(err)
	}
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
	if err := tailFile(ctx, path, func(line string) { lines <- line }, zerolog.Nop()); err != nil {
		t.Fatal(err)
	}
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
