package core

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

const auditTestToken = AuditTokenPrefix + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testAuditService(t *testing.T, handler http.Handler, required bool) *AuditService {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := NewAuditService(AuditConfig{Dir: t.TempDir(), SourceID: "engine-a", Endpoint: srv.URL + "/api/v1/audit/ingest", AuthToken: auditTestToken, CAFile: ca, RequireRemoteAck: required})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}
func testAuditReceiver(t *testing.T) *AuditReceiver {
	t.Helper()
	r, err := NewAuditReceiver(AuditReceiverConfig{Dir: t.TempDir(), Sources: []AuditSource{{ID: "engine-a", Token: auditTestToken}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
func receiptHandler(r *AuditReceiver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var record AuditRecord
		if json.NewDecoder(req.Body).Decode(&record) != nil {
			w.WriteHeader(400)
			return
		}
		a, err := r.Accept(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "), record)
		if err != nil {
			w.WriteHeader(409)
			return
		}
		_ = json.NewEncoder(w).Encode(a)
	})
}

func TestDurableAuditRestartAndReceiverDeduplication(t *testing.T) {
	r := testAuditReceiver(t)
	var lost atomic.Bool
	a := testAuditService(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var record AuditRecord
		_ = json.NewDecoder(req.Body).Decode(&record)
		receipt, err := r.Accept(auditTestToken, record)
		if err != nil {
			t.Error(err)
			w.WriteHeader(409)
			return
		}
		if !lost.Swap(true) {
			_, _ = w.Write([]byte(`{"incomplete":true}`))
			return
		}
		_ = json.NewEncoder(w).Encode(receipt)
	}), true)
	_, err := a.Record(context.Background(), AuditEvent{Kind: "request_intent", Actor: "alice", RequestID: "one"}, true)
	if err == nil || a.Status().Acknowledged != 0 {
		t.Fatal("mismatched receipt advanced cursor")
	}
	if err := a.ExportThrough(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if len(r.journals["engine-a"].records) != 2 || a.Status().Pending != 0 {
		t.Fatal("retry duplicated or lost evidence")
	}
	cfg := a.cfg
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewAuditService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Status().Acknowledged != 2 || reopened.Status().Records != 3 {
		t.Fatal("restart lost the synced receipt or startup record")
	}
	if err := reopened.ExportThrough(context.Background(), 3); err != nil {
		t.Fatal(err)
	}
	// Collector restart validates and retains its append history too.
	receiverDir := filepath.Dir(filepath.Dir(r.journals["engine-a"].file.Name()))
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	rc, err := NewAuditReceiver(AuditReceiverConfig{Dir: receiverDir, Sources: []AuditSource{{ID: "engine-a", Token: auditTestToken}}})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if len(rc.journals["engine-a"].records) != 3 || !rc.Ready() {
		t.Fatal("collector restart lost evidence")
	}
}

func TestDurableAuditJournalIntegrityOwnershipAndFailure(t *testing.T) {
	dir := t.TempDir()
	j, err := openAuditJournal(dir, "engine-a", true, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := openAuditJournal(dir, "engine-a", true, 128<<20); err == nil {
		_ = other.Close()
		t.Fatal("two writers acquired the journal")
	}
	r, err := j.append(AuditEvent{Kind: "request_intent", Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	j.syncFile = func(*os.File) error { return errors.New("disk failure") }
	if _, err := j.append(AuditEvent{Kind: "request_result", Actor: "alice"}); err == nil || !j.failed || len(j.records) != 1 {
		t.Fatal("unsynced record became authoritative")
	}
	_ = j.Close()
	// A failed sync can leave bytes on disk; a valid complete record may replay.
	// A torn tail or modified record must never be silently repaired.
	path := filepath.Join(dir, "engine-a.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, []byte(`{"record":`)...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openAuditJournal(dir, "engine-a", true, 128<<20); err == nil {
		t.Fatal("partial record accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), r.Hash, strings.Repeat("0", 64), 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openAuditJournal(dir, "engine-a", true, 128<<20); err == nil {
		t.Fatal("modified chain accepted")
	}
}

func TestDurableAuditReceiverRejectsForkGapAndFailedCommit(t *testing.T) {
	r := testAuditReceiver(t)
	j, err := openAuditJournal(t.TempDir(), "engine-a", true, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	one, _ := j.append(AuditEvent{Kind: "request_intent", Actor: "alice"})
	two, _ := j.append(AuditEvent{Kind: "request_result", Actor: "alice"})
	if _, err := r.Accept(auditTestToken, two); err == nil {
		t.Fatal("sequence gap accepted")
	}
	if _, err := r.Accept(auditTestToken, one); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accept(auditTestToken, one); err != nil {
		t.Fatal("committed retry rejected", err)
	}
	for _, mode := range []string{"content", "stream", "previous", "source"} {
		changed := two
		switch mode {
		case "content":
			changed.Event.Actor = "forged"
		case "stream":
			suffix := "0"
			if one.StreamID[35] == '0' {
				suffix = "1"
			}
			changed.StreamID = one.StreamID[:35] + suffix
		case "previous":
			changed.PreviousHash = auditZeroHash
		case "source":
			changed.SourceID = "victim"
		}
		if _, err := r.Accept(auditTestToken, changed); err == nil {
			t.Fatal(mode, "accepted")
		}
	}
	r.journals["engine-a"].syncFile = func(*os.File) error { return errors.New("full disk") }
	if _, err := r.Accept(auditTestToken, two); err == nil || r.Ready() {
		t.Fatal("failed remote sync was acknowledged")
	}
}

func TestDurableAuditRejectsFalseAndOversizedReceipts(t *testing.T) {
	for _, mode := range []string{"source", "stream", "sequence", "hash", "trailing", "oversize", "status", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			a := testAuditService(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var rec AuditRecord
				_ = json.NewDecoder(req.Body).Decode(&rec)
				receipt := AuditReceipt{rec.SourceID, rec.StreamID, rec.Sequence, rec.Hash}
				switch mode {
				case "source":
					receipt.SourceID = "victim"
				case "stream":
					receipt.StreamID = "wrong"
				case "sequence":
					receipt.Sequence++
				case "hash":
					receipt.Hash = auditZeroHash
				case "status":
					w.WriteHeader(202)
				}
				data, _ := json.Marshal(receipt)
				switch mode {
				case "trailing":
					data = append(data, []byte(` {}`)...)
				case "oversize":
					data = append(data, []byte(strings.Repeat(" ", 4096))...)
				case "unknown":
					data = append(data[:len(data)-1], []byte(`,"success":true}`)...)
				}
				_, _ = w.Write(data)
			}), true)
			if _, err := a.Record(context.Background(), AuditEvent{Kind: "request_intent"}, true); err == nil || a.Status().Acknowledged != 0 || a.Status().Ready {
				t.Fatal("false acknowledgement accepted")
			}
		})
	}
}

func TestDurableAuditNoRedirectNoUntrustedTLSAndConfigSecrets(t *testing.T) {
	var stolen atomic.Int64
	attacker := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { stolen.Add(1) }))
	defer attacker.Close()
	a := testAuditService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusTemporaryRedirect)
	}), true)
	if err := a.ExportThrough(context.Background(), 1); err == nil || stolen.Load() != 0 {
		t.Fatal("redirect leaked audit content or credentials")
	}
	cfg := a.cfg
	cfg.Dir = t.TempDir()
	cfg.CAFile = ""
	untrusted, err := NewAuditService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	if err := untrusted.ExportThrough(context.Background(), 1); err == nil {
		t.Fatal("untrusted receiver certificate accepted")
	}
	for _, endpoint := range []string{"http://collector/api/v1/audit/ingest", "https://user:secret@collector/api/v1/audit/ingest", "https://collector/api/v1/audit/ingest?secret=token", "https://collector/api/v1/audit/ingest?", "https://collector/other"} {
		cfg.Endpoint = endpoint
		cfg.Dir = t.TempDir()
		if x, err := NewAuditService(cfg); err == nil {
			_ = x.Close()
			t.Fatal("unsafe destination accepted", endpoint)
		}
	}
	config := DefaultConfig()
	config.Audit.AuthToken = auditTestToken
	config.AuditReceiver.Sources = []AuditSource{{ID: "engine-a", Token: auditTestToken}}
	data, _ := json.Marshal(RedactConfig(config))
	if strings.Contains(string(data), auditTestToken) {
		t.Fatal("audit credentials exposed by config reads")
	}
	config.Audit.Enabled = true
	config.Cloud.RemoteCommandsEnabled = true
	if _, err := NewEngine(config); err == nil {
		t.Fatal("legacy cloud command bypass allowed")
	}
	if _, err := (&CommandPoller{cfg: config}).executeCommand(CloudCommand{Type: "set_dry_run"}); err == nil {
		t.Fatal("direct cloud command bypass allowed")
	}
}

func TestDurableAuditConcurrentExportAndJournalCapacity(t *testing.T) {
	r := testAuditReceiver(t)
	a := testAuditService(t, receiptHandler(r), true)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if _, err := a.Record(context.Background(), AuditEvent{Kind: "request_intent", Actor: "alice"}, true); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if a.Status().Acknowledged != 13 || len(r.journals["engine-a"].records) != 13 {
		t.Fatal("concurrent ordering lost records")
	}
	a.journal.mu.Lock()
	a.journal.maxBytes = a.journal.bytes + 10
	a.journal.mu.Unlock()
	if _, err := a.Record(context.Background(), AuditEvent{Kind: "request_intent"}, true); err == nil || a.Status().Ready {
		t.Fatal("capacity failure silently allowed")
	}
}

func TestDurableAuditDenialAggregationAndBudget(t *testing.T) {
	a := testAuditService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }), false)
	var wg sync.WaitGroup
	for range 1000 {
		wg.Go(a.Denied)
	}
	wg.Wait()
	a.flushDenials()
	if len(a.journal.records) != 2 || a.journal.records[1].Event.Count != 1000 {
		t.Fatal("denial flood was not aggregated")
	}
	a.journal.maxBytes = 64 << 10
	for a.Status().JournalBytes < 16<<10 {
		if _, err := a.Record(context.Background(), AuditEvent{Kind: "request_intent", Actor: strings.Repeat("a", 200)}, false); err != nil {
			t.Fatal(err)
		}
	}
	before := a.Status().Records
	a.Denied()
	a.flushDenials()
	if a.Status().Records != before+1 || a.Status().DenialsUnjournaled != 0 {
		t.Fatal("legitimate traffic spent the denial quota")
	}
	for a.journal.denialBytes+1024 <= a.journal.maxBytes/4 {
		a.Denied()
		a.flushDenials()
	}
	before = a.Status().Records
	a.Denied()
	a.flushDenials()
	if a.Status().DenialsUnjournaled != 1 || a.Status().Records != before || a.Status().Ready {
		t.Fatal("denial budget loss was hidden")
	}
	if _, err := a.Record(context.Background(), AuditEvent{Kind: "request_intent"}, false); err != nil {
		t.Fatal("denials exhausted protected admission budget")
	}
}

func TestDurableAuditActionFenceAfterReceiptAndOutcome(t *testing.T) {
	r := testAuditReceiver(t)
	var permitted atomic.Bool
	permitted.Store(true)
	a := testAuditService(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		permitted.Store(false)
		receiptHandler(r).ServeHTTP(w, req)
	}), true)
	x := &mockExecutor{}
	wrapped := &auditedExecutor{inner: x, audit: a}
	alert := testAlertWithIP("injection_shield", "198.51.100.8", SeverityCritical)
	ctx := context.WithValue(context.Background(), auditAuthorityKey{}, func() bool { return permitted.Load() })
	if _, _, err := wrapped.Execute(ctx, alert, ResponseRule{Action: ActionBlockIP}, zerolog.Nop()); err == nil || x.callCount != 0 {
		t.Fatal("revoked authority executed after audit wait")
	}
	if _, _, err := wrapped.Execute(context.Background(), alert, ResponseRule{Action: ActionBlockIP}, zerolog.Nop()); err != nil || x.callCount != 1 {
		t.Fatal("active action not audited", err)
	}
	last := a.journal.records[len(a.journal.records)-1]
	if last.Event.Kind != "action_result" || last.Event.Outcome != "succeeded" {
		t.Fatal("action outcome missing")
	}
	_ = a.journal.Close()
	if _, _, err := wrapped.Execute(context.Background(), alert, ResponseRule{Action: ActionBlockIP}, zerolog.Nop()); err == nil || x.callCount != 1 {
		t.Fatal("unrecordable action executed")
	}
}

func TestDurableAuditCancelledExportDoesNotAdmit(t *testing.T) {
	a := testAuditService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }), true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Record(ctx, AuditEvent{Kind: "request_intent"}, true); err == nil || a.Status().Acknowledged != 0 {
		t.Fatal("cancelled export admitted")
	}
	// The delivery semaphore must observe cancellation rather than wait forever.
	a.delivery <- struct{}{}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if err := a.ExportThrough(ctx, 2); err == nil {
		t.Fatal("busy exporter ignored deadline")
	}
	<-a.delivery
}

func TestDurableAuditBackgroundOutageRecovery(t *testing.T) {
	r := testAuditReceiver(t)
	var attempts atomic.Int64
	a := testAuditService(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if attempts.Add(1) <= 2 {
			w.WriteHeader(503)
			return
		}
		receiptHandler(r).ServeHTTP(w, req)
	}), false)
	for range 2 {
		if _, err := a.Record(context.Background(), AuditEvent{Kind: "request_intent", Actor: "alice"}, false); err != nil {
			t.Fatal(err)
		}
	}
	a.Start(context.Background())
	deadline := time.Now().Add(10 * time.Second)
	for a.Status().Pending > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if a.Status().Pending != 0 || attempts.Load() < 3 || a.Status().LastDelivered.IsZero() {
		t.Fatal("outage retry did not drain in order", a.Status())
	}
}

func TestDurableAuditReceiptCheckpointFailureBlocksAdmission(t *testing.T) {
	r := testAuditReceiver(t)
	a := testAuditService(t, receiptHandler(r), true)
	a.journal.syncFile = func(*os.File) error { return errors.New("checkpoint sync failed") }
	if err := a.ExportThrough(context.Background(), 1); err == nil || a.Status().Acknowledged != 0 || a.Status().Ready {
		t.Fatal("failed local checkpoint considered committed")
	}
	if len(r.journals["engine-a"].records) != 1 {
		t.Fatal("remote intent was not retained for investigation")
	}
}

func TestDurableAuditOldSourceBackupCannotForkCollector(t *testing.T) {
	r := testAuditReceiver(t)
	dir := t.TempDir()
	j, err := openAuditJournal(dir, "engine-a", true, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	one, _ := j.append(AuditEvent{Kind: "request_intent", Actor: "alice"})
	_ = j.Close()
	path := filepath.Join(dir, "engine-a.jsonl")
	backup, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err = openAuditJournal(dir, "engine-a", true, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	two, _ := j.append(AuditEvent{Kind: "request_result", Actor: "alice"})
	_ = j.Close()
	for _, record := range []AuditRecord{one, two} {
		if _, err := r.Accept(auditTestToken, record); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, backup, 0600); err != nil {
		t.Fatal(err)
	}
	j, err = openAuditJournal(dir, "engine-a", true, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	fork, _ := j.append(AuditEvent{Kind: "request_intent", Actor: "intruder"})
	if _, err := r.Accept(auditTestToken, fork); err == nil {
		t.Fatal("old host backup rewrote off-host history")
	}
}

func TestDurableAuditProductionExecutorsAndChainsKeepFence(t *testing.T) {
	a := testAuditService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }), true)
	cfg := enforcementConfig("balanced", false)
	cfg.Audit.Enabled = true
	re := NewResponseEngine(zerolog.Nop(), nil, NewAlertPipeline(zerolog.Nop(), 10), cfg, a)
	defer re.Stop()
	for action, executor := range re.executors {
		if _, ok := executor.(*auditedExecutor); !ok {
			t.Fatal("executor lacks audit fence", action)
		}
	}
	chain := NewChainExecutor(zerolog.Nop(), re.executors)
	if err := chain.RegisterChain(&ActionChain{Name: "safe", Steps: []ChainStep{{Name: "log", Action: ActionLog}}}); err != nil {
		t.Fatal(err)
	}
	result, err := chain.Execute(context.Background(), "safe", makeAlertForChain(), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status == "completed" {
		t.Fatal("chain bypassed unavailable remote receipt")
	}
}
