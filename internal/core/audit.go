package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type AuditConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Dir              string `yaml:"dir"`
	SourceID         string `yaml:"source_id"`
	Endpoint         string `yaml:"endpoint"`
	AuthToken        string `yaml:"auth_token"`
	CAFile           string `yaml:"ca_file"`
	MaxBytes         int64  `yaml:"max_bytes"`
	RequireRemoteAck bool   `yaml:"require_remote_ack"`
}
type AuditSource struct {
	ID    string `yaml:"id"`
	Token string `yaml:"token"`
}
type AuditReceiverConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Dir      string        `yaml:"dir"`
	MaxBytes int64         `yaml:"max_bytes"`
	Sources  []AuditSource `yaml:"sources"`
}

func auditLimit(n int64) int64 {
	if n == 0 {
		return 128 << 20
	}
	return n
}
func validAuditToken(token string) bool {
	if !strings.HasPrefix(token, AuditTokenPrefix) || len(token) < len(AuditTokenPrefix)+43 || len(token) > 256 {
		return false
	}
	for _, c := range strings.TrimPrefix(token, AuditTokenPrefix) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// AuditService is a durable ordered exporter. Neither an HTTP success status nor
// a partial/mismatched receipt advances the synced local acknowledgement cursor.
type AuditService struct {
	cfg               AuditConfig
	journal           *auditJournal
	client            *http.Client
	delivery          chan struct{}
	mu                sync.Mutex
	lastError         string
	lastDelivered     time.Time
	cancel            context.CancelFunc
	done              chan struct{}
	closed            bool
	denied            uint64
	deniedUnjournaled uint64
}

func NewAuditService(cfg AuditConfig) (*AuditService, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Fragment != "" || u.Path != "/api/v1/audit/ingest" || !validAuditID(cfg.SourceID) || cfg.Dir == "" {
		return nil, errors.New("audit requires a source ID, private directory and HTTPS /api/v1/audit/ingest endpoint without credentials, query or fragment")
	}
	if cfg.AuthToken == "" {
		cfg.AuthToken = os.Getenv("ONESEC_AUDIT_TOKEN")
	}
	if !validAuditToken(cfg.AuthToken) {
		return nil, errors.New("audit requires a dedicated 1sec_audit_ credential with at least 43 random URL-safe characters")
	}
	client := NewAuthenticatedHTTPClient(5 * time.Second)
	// Receipt identity is bound to an exact configured endpoint, not redirects.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("audit redirects are disabled") }
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("audit requires the standard HTTP transport")
	}
	transport := base.Clone()
	transport.Proxy = nil // Do not send audit credentials through environment-selected proxies.
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, errors.New("audit CA file unavailable")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("audit CA file has no certificates")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	client.Transport = transport
	j, err := openAuditJournal(cfg.Dir, cfg.SourceID, true, auditLimit(cfg.MaxBytes))
	if err != nil {
		return nil, err
	}
	service := &AuditService{cfg: cfg, journal: j, client: client, delivery: make(chan struct{}, 1)}
	if len(j.records) < auditCountLimit {
		if _, err := j.append(AuditEvent{Kind: "engine_start", Actor: "engine", Action: Version}); err != nil {
			_ = j.Close()
			return nil, err
		}
	}
	return service, nil
}

func (a *AuditService) Record(ctx context.Context, event AuditEvent, requireReceipt bool) (AuditRecord, error) {
	if a == nil {
		return AuditRecord{}, nil
	}
	r, err := a.journal.append(event)
	if err != nil {
		return r, err
	}
	if requireReceipt && a.cfg.RequireRemoteAck {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err = a.ExportThrough(ctx, r.Sequence)
	}
	return r, err
}

func (a *AuditService) ExportThrough(ctx context.Context, sequence uint64) (exportErr error) {
	select {
	case a.delivery <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() {
		<-a.delivery
		a.mu.Lock()
		defer a.mu.Unlock()
		if exportErr != nil {
			a.lastError = "remote_delivery_failed"
		} else {
			a.lastError = ""
		}
	}()
	for {
		a.journal.mu.Lock()
		acked, failed := a.journal.acked, a.journal.failed
		a.journal.mu.Unlock()
		if failed {
			return errors.New("audit journal unavailable")
		}
		if acked >= sequence {
			return nil
		}
		record, ok := a.journal.next()
		if !ok {
			return errors.New("audit record unavailable")
		}
		data, _ := json.Marshal(record)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Endpoint, bytes.NewReader(data))
		if err != nil {
			return errors.New("audit request unavailable")
		}
		req.Header.Set("Authorization", "Bearer "+a.cfg.AuthToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := a.client.Do(req)
		if err != nil {
			return errors.New("audit receiver unavailable")
		}
		body, readErr := ReadBoundedResponse(resp.Body, 4096)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			return errors.New("audit receipt unavailable")
		}
		var receipt AuditReceipt
		if strictAuditJSON(body, &receipt) != nil || receipt != (AuditReceipt{record.SourceID, record.StreamID, record.Sequence, record.Hash}) {
			return errors.New("audit receipt mismatch")
		}
		if err := a.journal.acknowledge(receipt); err != nil {
			return err
		}
		a.mu.Lock()
		a.lastDelivered = time.Now().UTC()
		a.mu.Unlock()
	}
}

func (a *AuditService) Start(parent context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil || a.closed {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	a.cancel = cancel
	a.done = make(chan struct{})
	go func() {
		defer close(a.done)
		delay := time.Duration(0)
		for {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			a.flushDenials()
			a.journal.mu.Lock()
			target := uint64(len(a.journal.records))
			acked := a.journal.acked
			a.journal.mu.Unlock()
			if target == acked {
				delay = time.Second
				continue
			}
			// Bounded work per attempt; newer records never overtake the head.
			if target > acked+64 {
				target = acked + 64
			}
			attempt, stop := context.WithTimeout(ctx, 5*time.Second)
			err := a.ExportThrough(attempt, target)
			stop()
			if err != nil {
				if delay < time.Second {
					delay = time.Second
				} else {
					delay *= 2
				}
				if delay > time.Minute {
					delay = time.Minute
				}
			} else {
				delay = 0
			}
		}
	}()
}

type AuditStatus struct {
	Ready                bool      `json:"ready"`
	SourceID             string    `json:"source_id"`
	StreamID             string    `json:"stream_id"`
	Records              uint64    `json:"records"`
	Acknowledged         uint64    `json:"acknowledged"`
	Pending              uint64    `json:"pending"`
	OldestPendingSeconds int64     `json:"oldest_pending_seconds"`
	JournalBytes         int64     `json:"journal_bytes"`
	MaxBytes             int64     `json:"max_bytes"`
	MaxRecords           uint64    `json:"max_records"`
	RequireRemoteAck     bool      `json:"require_remote_ack"`
	LastDelivered        time.Time `json:"last_delivered"`
	LastError            string    `json:"last_error,omitempty"`
	DenialsPending       uint64    `json:"denials_pending"`
	DenialsUnjournaled   uint64    `json:"denials_unjournaled"`
}

func (a *AuditService) Status() AuditStatus {
	a.journal.mu.Lock()
	s := AuditStatus{Ready: !a.journal.failed, SourceID: a.journal.source, StreamID: a.journal.stream, Records: uint64(len(a.journal.records)), Acknowledged: a.journal.acked, JournalBytes: a.journal.bytes, MaxBytes: a.journal.maxBytes, RequireRemoteAck: a.cfg.RequireRemoteAck}
	s.Pending = s.Records - s.Acknowledged
	s.MaxRecords = auditCountLimit
	if s.Records >= auditCountLimit {
		s.Ready = false
	}
	if s.Pending > 0 {
		s.OldestPendingSeconds = int64(time.Since(a.journal.records[s.Acknowledged].Timestamp).Seconds())
		if s.OldestPendingSeconds > 60 {
			s.Ready = false
		}
	}
	a.journal.mu.Unlock()
	a.mu.Lock()
	s.LastError = a.lastError
	s.LastDelivered = a.lastDelivered
	s.DenialsPending = a.denied
	s.DenialsUnjournaled = a.deniedUnjournaled
	a.mu.Unlock()
	if s.DenialsUnjournaled > 0 {
		s.Ready = false
	}
	if s.RequireRemoteAck && (s.Acknowledged == 0 || s.LastError != "") {
		s.Ready = false
	}
	return s
}
func (a *AuditService) Close() error {
	a.mu.Lock()
	a.closed = true
	cancel, done := a.cancel, a.done
	a.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	a.flushDenials()
	a.client.CloseIdleConnections()
	return a.journal.Close()
}

// Denied counts an authorization failure for bounded aggregation. Denials are counted
// in memory and periodically summarized, with a quarter-journal budget. Missing
// denial evidence is explicitly visible in readiness; it is never called complete.
func (a *AuditService) Denied() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.denied < ^uint64(0) {
		a.denied++
	}
}
func (a *AuditService) flushDenials() {
	a.mu.Lock()
	count := a.denied
	a.denied = 0
	a.mu.Unlock()
	if count == 0 {
		return
	}
	a.journal.mu.Lock()
	room := a.journal.denialBytes+1024 <= a.journal.maxBytes/4 && a.journal.denialRecords < auditCountLimit/4 && a.journal.bytes+auditRecordLimit < a.journal.maxBytes
	a.journal.mu.Unlock()
	var err error
	if room {
		_, err = a.journal.append(AuditEvent{Kind: "request_denied", Outcome: "authorization_denied", Count: count})
	}
	if !room || err != nil {
		a.mu.Lock()
		if ^uint64(0)-a.deniedUnjournaled < count {
			a.deniedUnjournaled = ^uint64(0)
		} else {
			a.deniedUnjournaled += count
		}
		a.mu.Unlock()
	}
}

// AuditReceiver is an append-only ingest surface with source-bound credentials.
// It has no read/delete/reset HTTP operation; retention is the collector owner's responsibility.
type AuditReceiver struct {
	journals map[string]*auditJournal
	tokens   map[string][32]byte
}

func NewAuditReceiver(cfg AuditReceiverConfig) (*AuditReceiver, error) {
	if cfg.Dir == "" || len(cfg.Sources) == 0 || len(cfg.Sources) > 32 {
		return nil, errors.New("audit receiver requires a private directory and 1-32 sources")
	}
	r := &AuditReceiver{journals: make(map[string]*auditJournal), tokens: make(map[string][32]byte)}
	keep := false
	defer func() {
		if !keep {
			_ = r.Close()
		}
	}()
	seen := make(map[[32]byte]bool)
	for _, source := range cfg.Sources {
		if !validAuditID(source.ID) || !validAuditToken(source.Token) || r.journals[source.ID] != nil {
			return nil, errors.New("invalid or duplicate audit receiver source")
		}
		hash := sha256.Sum256([]byte(source.Token))
		if seen[hash] {
			return nil, errors.New("audit source credentials must be distinct")
		}
		seen[hash] = true
		j, err := openAuditJournal(filepath.Join(cfg.Dir, "sources"), source.ID, false, auditLimit(cfg.MaxBytes))
		if err != nil {
			return nil, err
		}
		r.journals[source.ID] = j
		r.tokens[source.ID] = hash
	}
	keep = true
	return r, nil
}
func (r *AuditReceiver) Accept(token string, record AuditRecord) (AuditReceipt, error) {
	if !validAuditToken(token) {
		return AuditReceipt{}, ErrOperatorPermission
	}
	hash := sha256.Sum256([]byte(token))
	want, ok := r.tokens[record.SourceID]
	if !ok || subtle.ConstantTimeCompare(hash[:], want[:]) != 1 {
		return AuditReceipt{}, ErrOperatorPermission
	}
	return r.journals[record.SourceID].accept(record)
}
func (r *AuditReceiver) Ready() bool {
	for _, j := range r.journals {
		j.mu.Lock()
		failed := j.failed || len(j.records) >= auditCountLimit
		j.mu.Unlock()
		if failed {
			return false
		}
	}
	return true
}
func (r *AuditReceiver) Close() error {
	var result error
	for _, j := range r.journals {
		result = errors.Join(result, j.Close())
	}
	return result
}

func validateAuditConfig(cfg *Config) error {
	if cfg.Audit.Enabled && cfg.Cloud.RemoteCommandsEnabled {
		return fmt.Errorf("durable audit requires cloud.remote_commands_enabled=false; legacy command execution is outside the named audit boundary")
	}
	return nil
}
