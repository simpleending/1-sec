package core

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	AuditTokenPrefix = "1sec_audit_"
	auditRecordLimit = 16 << 10
	auditCountLimit  = 100000
	auditZeroHash    = "0000000000000000000000000000000000000000000000000000000000000000"
)

// AuditEvent deliberately has no arbitrary payload, error, header or query map.
// Resource identifiers are SHA-256 digests; actor IDs are trusted identity metadata.
type AuditEvent struct {
	Kind         string `json:"kind"`
	RequestID    string `json:"request_id,omitempty"`
	Actor        string `json:"actor,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	Role         string `json:"role,omitempty"`
	Method       string `json:"method,omitempty"`
	Route        string `json:"route,omitempty"`
	ResourceHash string `json:"resource_hash,omitempty"`
	Action       string `json:"action,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	Status       int    `json:"status,omitempty"`
	Count        uint64 `json:"count,omitempty"`
}

type AuditRecord struct {
	Version      int        `json:"version"`
	SourceID     string     `json:"source_id"`
	StreamID     string     `json:"stream_id"`
	Sequence     uint64     `json:"sequence"`
	Timestamp    time.Time  `json:"timestamp"`
	PreviousHash string     `json:"previous_hash"`
	Event        AuditEvent `json:"event"`
	Hash         string     `json:"hash"`
}

type AuditReceipt struct {
	SourceID string `json:"source_id"`
	StreamID string `json:"stream_id"`
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
}

func AuditResourceHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func auditHash(record AuditRecord) string {
	record.Hash = ""
	data, _ := json.Marshal(record) // This fixed, bounded schema cannot fail to marshal.
	return AuditResourceHash(string(data))
}

func validAuditID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validAuditEvent(e AuditEvent) bool {
	switch e.Kind {
	case "request_intent", "request_result", "request_denied", "action_intent", "action_result", "engine_start":
	default:
		return false
	}
	for _, value := range []string{e.RequestID, e.Actor, e.CredentialID, e.Role, e.Method, e.Route, e.Action, e.Outcome} {
		if len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
			return false
		}
	}
	if e.ResourceHash != "" {
		b, err := hex.DecodeString(e.ResourceHash)
		if err != nil || len(b) != 32 {
			return false
		}
	}
	return e.Status >= 0 && e.Status <= 599
}

type auditHeader struct {
	Version  int    `json:"version"`
	SourceID string `json:"source_id"`
	StreamID string `json:"stream_id"`
}
type auditEntry struct {
	Record     *AuditRecord  `json:"record,omitempty"`
	Ack        *AuditReceipt `json:"ack,omitempty"`
	ReceivedAt *time.Time    `json:"received_at,omitempty"`
}

// auditJournal retains both records and receipt checkpoints. It never truncates
// or overwrites acknowledged history. Capacity failure stops future admissions.
type auditJournal struct {
	mu              sync.Mutex
	file            *os.File
	source, stream  string
	records         []AuditRecord
	acked           uint64
	bytes, maxBytes int64
	failed          bool
	receiver        bool
	denialBytes     int64
	denialRecords   int
	syncFile        func(*os.File) error // Fault injection seam; nil uses File.Sync.
}

func openAuditJournal(dir, source string, producer bool, maxBytes int64) (*auditJournal, error) {
	if !validAuditID(source) || maxBytes < 64<<10 || maxBytes > 1<<30 {
		return nil, fmt.Errorf("invalid audit journal configuration")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := RestrictPrivatePath(dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, source+".jsonl")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	if err := lockSensorRegistry(f); err != nil {
		return nil, fmt.Errorf("audit journal ownership unavailable: %w", err)
	}
	if err := RestrictPrivatePath(path, false); err != nil {
		return nil, err
	}
	j := &auditJournal{file: f, source: source, maxBytes: maxBytes, receiver: !producer}
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	j.bytes = stat.Size()
	if j.bytes >= maxBytes {
		return nil, fmt.Errorf("audit journal capacity reached")
	}
	if j.bytes == 0 {
		if producer {
			j.stream = uuid.NewString()
		}
		header, _ := json.Marshal(auditHeader{1, source, j.stream})
		if err := j.writeLocked(append(header, '\n')); err != nil {
			return nil, err
		}
		if err := syncAuditDirectory(dir); err != nil {
			return nil, err
		}
	} else {
		reader := bufio.NewReaderSize(io.LimitReader(f, maxBytes), auditRecordLimit)
		line, err := reader.ReadSlice('\n')
		var header auditHeader
		if err != nil || strictAuditJSON(line, &header) != nil || header.Version != 1 || header.SourceID != source {
			return nil, fmt.Errorf("invalid audit journal header")
		}
		j.stream = header.StreamID
		if producer && !validAuditStream(j.stream) || !producer && j.stream != "" {
			return nil, fmt.Errorf("invalid audit stream header")
		}
		for {
			line, err = reader.ReadSlice('\n')
			if err == io.EOF && len(line) == 0 {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("incomplete or oversized audit record")
			}
			var entry auditEntry
			if strictAuditJSON(line, &entry) != nil || (entry.Record == nil) == (entry.Ack == nil) {
				return nil, fmt.Errorf("invalid audit journal entry")
			}
			if entry.Record != nil {
				if producer && entry.ReceivedAt != nil || !producer && (entry.ReceivedAt == nil || entry.ReceivedAt.IsZero()) {
					return nil, errors.New("invalid collector receipt timestamp")
				}
				if err := j.validateNextLocked(*entry.Record); err != nil {
					return nil, err
				}
				j.records = append(j.records, *entry.Record)
				if entry.Record.Event.Kind == "request_denied" {
					j.denialRecords++
					j.denialBytes += int64(len(line))
				}
				j.stream = entry.Record.StreamID
			} else {
				if !producer || entry.ReceivedAt != nil || !j.receiptValidLocked(*entry.Ack) || entry.Ack.Sequence < j.acked {
					return nil, fmt.Errorf("invalid audit receipt checkpoint")
				}
				j.acked = entry.Ack.Sequence
				if j.records[entry.Ack.Sequence-1].Event.Kind == "request_denied" {
					j.denialBytes += int64(len(line))
				}
			}
		}
	}
	keep = true
	return j, nil
}

func strictAuditJSON(data []byte, out interface{}) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(interface{})) != io.EOF {
		return errors.New("expected one audit value")
	}
	return nil
}
func validAuditStream(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s && id != uuid.Nil
}
func (j *auditJournal) validateNextLocked(r AuditRecord) error {
	prev := auditZeroHash
	if len(j.records) > 0 {
		prev = j.records[len(j.records)-1].Hash
	}
	if len(j.records) >= auditCountLimit || r.Version != 1 || r.SourceID != j.source || !validAuditStream(r.StreamID) || j.stream != "" && r.StreamID != j.stream || r.Sequence != uint64(len(j.records)+1) || r.PreviousHash != prev || r.Timestamp.IsZero() || !validAuditEvent(r.Event) || r.Hash != auditHash(r) {
		return fmt.Errorf("invalid or discontinuous audit chain")
	}
	return nil
}
func (j *auditJournal) writeLocked(data []byte) error {
	if j.failed || j.file == nil {
		return errors.New("audit journal unavailable")
	}
	if j.bytes+int64(len(data)) >= j.maxBytes {
		j.failed = true
		return errors.New("audit journal capacity reached")
	}
	_, err := j.file.Seek(0, io.SeekEnd)
	if err == nil {
		var n int
		n, err = j.file.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		if j.syncFile != nil {
			err = j.syncFile(j.file)
		} else {
			err = j.file.Sync()
		}
	}
	if err != nil {
		j.failed = true
		return errors.New("audit journal commit failed")
	}
	j.bytes += int64(len(data))
	return nil
}
func (j *auditJournal) append(event AuditEvent) (AuditRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.records) >= auditCountLimit {
		return AuditRecord{}, errors.New("audit record capacity reached")
	}
	r := AuditRecord{Version: 1, SourceID: j.source, StreamID: j.stream, Sequence: uint64(len(j.records) + 1), Timestamp: time.Now().UTC(), PreviousHash: auditZeroHash, Event: event}
	if len(j.records) > 0 {
		r.PreviousHash = j.records[len(j.records)-1].Hash
	}
	r.Hash = auditHash(r)
	if err := j.validateNextLocked(r); err != nil {
		return AuditRecord{}, err
	}
	if err := j.saveRecordLocked(r); err != nil {
		return AuditRecord{}, err
	}
	return r, nil
}
func (j *auditJournal) saveRecordLocked(r AuditRecord) error {
	entry := auditEntry{Record: &r}
	if j.receiver {
		now := time.Now().UTC()
		entry.ReceivedAt = &now
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if len(data)+1 >= auditRecordLimit {
		return errors.New("audit record too large")
	}
	if err := j.writeLocked(append(data, '\n')); err != nil {
		return err
	}
	j.stream = r.StreamID
	j.records = append(j.records, r)
	if r.Event.Kind == "request_denied" {
		j.denialRecords++
		j.denialBytes += int64(len(data) + 1)
	}
	return nil
}
func (j *auditJournal) receiptValidLocked(a AuditReceipt) bool {
	return a.SourceID == j.source && a.StreamID == j.stream && a.Sequence > 0 && a.Sequence <= uint64(len(j.records)) && j.records[a.Sequence-1].Hash == a.Hash
}
func (j *auditJournal) acknowledge(a AuditReceipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.receiptValidLocked(a) || a.Sequence != j.acked+1 {
		return errors.New("audit acknowledgement does not match next record")
	}
	data, _ := json.Marshal(auditEntry{Ack: &a})
	if err := j.writeLocked(append(data, '\n')); err != nil {
		return err
	}
	j.acked = a.Sequence
	if j.records[a.Sequence-1].Event.Kind == "request_denied" {
		j.denialBytes += int64(len(data) + 1)
	}
	return nil
}
func (j *auditJournal) next() (AuditRecord, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed || j.acked >= uint64(len(j.records)) {
		return AuditRecord{}, false
	}
	return j.records[j.acked], true
}
func (j *auditJournal) accept(r AuditRecord) (AuditReceipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return AuditReceipt{}, errors.New("audit receiver storage unavailable")
	}
	if r.Sequence > 0 && r.Sequence <= uint64(len(j.records)) {
		stored := j.records[r.Sequence-1]
		// Equal hashes alone are not sufficient: validate the supplied content too.
		if r.Hash != stored.Hash || auditHash(r) != r.Hash {
			return AuditReceipt{}, errors.New("audit history conflict")
		}
	} else {
		if len(j.records) >= auditCountLimit {
			return AuditReceipt{}, errors.New("audit record capacity reached")
		}
		if err := j.validateNextLocked(r); err != nil {
			return AuditReceipt{}, err
		}
		if err := j.saveRecordLocked(r); err != nil {
			return AuditReceipt{}, err
		}
	}
	return AuditReceipt{r.SourceID, r.StreamID, r.Sequence, r.Hash}, nil
}
func (j *auditJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.failed = true
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}
