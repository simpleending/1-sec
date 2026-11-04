package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

func waitArchive(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("archive delivery condition not reached")
}

func TestArchiveRetriesIOFailureAndCommitsReadableGzip(t *testing.T) {
	bus, err := NewEventBus(&BusConfig{Embedded: true, Port: -1, DataDir: t.TempDir()}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	cfg := DefaultArchiveConfig()
	cfg.Enabled = true
	cfg.Dir = t.TempDir()
	a, err := NewArchiver(cfg, bus, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	// Replace the configured archive directory with a regular file to force a
	// portable open failure, including on Windows and under privileged test users.
	if err := os.Remove(cfg.Dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Dir, []byte("unavailable storage"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	e := NewSecurityEvent("test", "auth_failure", SeverityHigh, "durable evidence")
	if err := bus.PublishEvent(e); err != nil {
		t.Fatal(err)
	}
	waitArchive(t, func() bool { return a.Status()["write_failures"].(int64) > 0 })
	info, err := bus.js.ConsumerInfo("SECURITY_EVENTS", "1sec-cold-archive-events")
	if err != nil {
		t.Fatal(err)
	}
	if info.NumAckPending != 1 || a.Ready() {
		t.Fatalf("failed archive delivery acknowledged/healthy: %+v", info)
	}
	if err := os.Remove(cfg.Dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfg.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	waitArchive(t, func() bool { return a.Status()["events_archived"].(int64) == 1 })
	waitArchive(t, func() bool {
		info, err := bus.js.ConsumerInfo("SECURITY_EVENTS", "1sec-cold-archive-events")
		return err == nil && info.NumAckPending == 0
	})
	if !a.Ready() {
		t.Fatal("archive did not recover")
	}
	// Read before shutdown/rotation: the acknowledged gzip member is complete.
	paths, err := filepath.Glob(filepath.Join(cfg.Dir, "*.gz"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("archive files: %v %v", paths, err)
	}
	f, err := os.Open(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	data, err := io.ReadAll(gz)
	if err != nil || !bytes.Contains(data, []byte(e.ID)) {
		t.Fatalf("acknowledged gzip incomplete: %q %v", data, err)
	}
	a.closeFile()
}

func TestBusRestartRetainsPendingDurableDelivery(t *testing.T) {
	cfg := &BusConfig{Embedded: true, Port: -1, DataDir: t.TempDir()}
	bus, err := NewEventBus(cfg, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan struct{}, 1)
	if err := bus.Subscribe("sec.events.>", "restart-test", func(msg *nats.Msg) { _ = msg.NakWithDelay(time.Second); received <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	if err := bus.PublishEvent(NewSecurityEvent("test", "test", SeverityInfo, "retry")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("no initial delivery")
	}
	if err := bus.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewEventBus(cfg, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	info, err := restarted.js.ConsumerInfo("SECURITY_EVENTS", "restart-test")
	if err != nil || info.NumAckPending != 1 {
		t.Fatalf("durable state lost on shutdown: %+v %v", info, err)
	}
	redelivered := make(chan struct{}, 1)
	if err := restarted.Subscribe("sec.events.>", "restart-test", func(msg *nats.Msg) { _ = msg.Ack(); redelivered <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-redelivered:
	case <-time.After(4 * time.Second):
		t.Fatal("pending event was not redelivered after restart")
	}
}

type footerFailWriter struct {
	bytes.Buffer
	calls int
}

func (w *footerFailWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > 1 {
		return 0, errors.New("disk full while finishing member")
	}
	return w.Buffer.Write(p)
}

func TestArchiveDetectsCompressedFooterAndSyncFailures(t *testing.T) {
	w := &footerFailWriter{}
	gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if _, err := writeArchiveLine(w, gz, []byte("small buffered record\n")); err == nil {
		t.Fatal("gzip footer failure ignored")
	}
	cfg := DefaultArchiveConfig()
	cfg.Dir = t.TempDir()
	cfg.Compress = false
	a, err := NewArchiver(cfg, nil, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.openFileLocked(); err != nil {
		t.Fatal(err)
	}
	if err := a.currentFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.writeRecord("event", []byte(`{"id":"failed"}`)); err == nil {
		t.Fatal("closed file acknowledged as archived")
	}
	if a.Status()["events_archived"].(int64) != 0 || a.Status()["write_failures"].(int64) == 0 {
		t.Fatal("failed record counted as committed")
	}
	// File.Sync on a Windows pipe may succeed; inject the commit failure
	// explicitly so this checks the same failure boundary on every platform.
	syncCalled := false
	a.syncFile = func(*os.File) error { syncCalled = true; return errors.New("injected stable-storage commit failure") }
	if err := a.writeRecord("event", []byte(`{"id":"unsynced"}`)); err == nil {
		t.Fatal("sync failure treated as committed storage")
	}
	if !syncCalled || a.Status()["events_archived"].(int64) != 0 {
		t.Fatal("unsynced record counted as committed")
	}
	a.syncFile = nil
	if err := a.writeRecord("event", []byte(`{"id":"recovered"}`)); err != nil {
		t.Fatal("archive could not reopen", err)
	}
	a.closeFile()
	entries, err := os.ReadDir(cfg.Dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("failed attempts leaked empty archives: %d %v", len(entries), err)
	}
}

func TestArchiveMultistreamAndRapidRotation(t *testing.T) {
	for _, compress := range []bool{false, true} {
		cfg := DefaultArchiveConfig()
		cfg.Dir = t.TempDir()
		cfg.Compress = compress
		cfg.RotateBytes = 1
		a, err := NewArchiver(cfg, nil, zerolog.Nop())
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if err := a.writeRecord("response", []byte(`{"id":"record"}`)); err != nil {
				t.Fatal(err)
			}
		}
		a.closeFile()
		entries, _ := os.ReadDir(cfg.Dir)
		if len(entries) != 3 {
			t.Fatalf("rotation reused a filename: %d", len(entries))
		}
		if a.Status()["responses_archived"].(int64) != 3 {
			t.Fatal("responses not counted")
		}
	}
	cfg := DefaultArchiveConfig()
	cfg.Dir = t.TempDir()
	a, err := NewArchiver(cfg, nil, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := a.writeRecord("event", []byte(`{"id":"record"}`)); err != nil {
			t.Fatal(err)
		}
	}
	a.closeFile()
	paths, _ := filepath.Glob(filepath.Join(cfg.Dir, "*.gz"))
	f, err := os.Open(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	data, err := io.ReadAll(gz)
	if err != nil || bytes.Count(data, []byte(`"id":"record"`)) != 3 {
		t.Fatalf("multistream lost records: %q %v", data, err)
	}
}
