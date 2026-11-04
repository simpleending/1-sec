package core

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const SensorTokenPrefix = "1sec_sensor_"

type SensorConfig struct {
	Enabled             bool   `yaml:"enabled"`
	StateDir            string `yaml:"state_dir"`
	RequireSensorIngest bool   `yaml:"require_sensor_ingest"`
}

type SensorScope struct {
	Module string `json:"module"`
	Type   string `json:"type"`
}

// SensorSpec is an operator grant, never an assertion supplied by telemetry.
type SensorSpec struct {
	ID                 string        `json:"id"`
	HostID             string        `json:"host_id"`
	Scopes             []SensorScope `json:"scopes"`
	AllowLocalResponse bool          `json:"allow_local_response"`
	ExpiresAt          time.Time     `json:"expires_at"`
}

type SensorInfo struct {
	SensorSpec
	CredentialID string     `json:"credential_id"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

type sensorRecord struct {
	SensorInfo
	CredentialHash string `json:"credential_hash"`
}

// SensorEvidence is a signed transport envelope. A decoded field alone grants
// nothing; only verification creates the private in-process authority handle.
type SensorEvidence struct {
	SensorID     string `json:"sensor_id"`
	CredentialID string `json:"credential_id"`
	HostID       string `json:"host_id"`
	Signature    string `json:"signature,omitempty"`
}

type sensorAuthority struct {
	registry       *SensorRegistry
	id, credential string
}

// SensorRegistry has one engine owner. Journal writes are synced before a grant
// changes in memory. A torn/corrupt journal or failed write fails closed.
type SensorRegistry struct {
	mu           sync.RWMutex
	path         string
	key          []byte
	records      map[string]sensorRecord
	byCredential map[string]string
	failed       bool
	file         *os.File
	journalLimit int64
}

func NewSensorRegistry(dir string) (*SensorRegistry, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := RestrictPrivatePath(dir, true); err != nil {
		return nil, err
	}
	r := &SensorRegistry{path: filepath.Join(dir, "registry.jsonl"), records: make(map[string]sensorRecord), byCredential: make(map[string]string), journalLimit: 64 << 20}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_RDWR, 0600)
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
		return nil, fmt.Errorf("sensor registry already owned or unavailable: %w", err)
	}
	r.file = f
	if err := RestrictPrivatePath(r.path, false); err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() >= 64<<20 {
		return nil, fmt.Errorf("sensor registry exceeds supported size")
	}
	if stat.Size() == 0 {
		r.key = make([]byte, 32)
		if _, err := rand.Read(r.key); err != nil {
			return nil, err
		}
		if err := json.NewEncoder(f).Encode(map[string]interface{}{"version": 1, "signing_key": hex.EncodeToString(r.key)}); err != nil {
			return nil, err
		}
		if err := f.Sync(); err != nil {
			return nil, err
		}
		keep = true
		return r, nil
	}
	reader := bufio.NewReader(io.LimitReader(f, 64<<20))
	header, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("invalid sensor registry header")
	}
	var h struct {
		Version int    `json:"version"`
		Key     string `json:"signing_key"`
	}
	if json.Unmarshal(header, &h) != nil || h.Version != 1 {
		return nil, fmt.Errorf("invalid sensor registry version")
	}
	r.key, err = hex.DecodeString(h.Key)
	if err != nil || len(r.key) != 32 {
		return nil, fmt.Errorf("invalid sensor signing key")
	}
	for {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("incomplete sensor registry record")
		}
		var record sensorRecord
		if json.Unmarshal(line, &record) != nil || validateSensorSpec(record.SensorSpec) != nil || len(record.CredentialHash) != 64 || record.CredentialID == "" {
			return nil, fmt.Errorf("invalid sensor registry record")
		}
		r.setRecordLocked(record)
	}
	if stat.Size() >= 64<<20 || len(r.records) > 10000 {
		return nil, fmt.Errorf("sensor registry exceeds supported size")
	}
	keep = true
	return r, nil
}

func validateSensorSpec(spec SensorSpec) error {
	if !validRoutingToken(spec.ID) || len(spec.HostID) == 0 || len(spec.HostID) > 253 || strings.TrimSpace(spec.HostID) != spec.HostID || strings.ContainsAny(spec.HostID, "\r\n\x00/\\") {
		return fmt.Errorf("invalid sensor identity or host")
	}
	if len(spec.Scopes) == 0 || len(spec.Scopes) > 64 {
		return fmt.Errorf("provide 1-64 exact event scopes")
	}
	for _, scope := range spec.Scopes {
		if !validRoutingToken(scope.Module) || !validRoutingToken(scope.Type) {
			return fmt.Errorf("event scopes require literal routing tokens")
		}
	}
	if spec.AllowLocalResponse && validateLocalProcessHost(spec.HostID) != nil {
		return fmt.Errorf("local response requires this engine's host")
	}
	return nil
}

func (r *SensorRegistry) saveLocked(record sensorRecord) error {
	var data bytes.Buffer
	err := json.NewEncoder(&data).Encode(record)
	if err != nil {
		return err
	}
	end, err := r.file.Seek(0, io.SeekEnd)
	if err == nil && end+int64(data.Len()) >= r.journalLimit {
		r.failed = true
		return fmt.Errorf("sensor journal capacity reached; state was not changed")
	}
	if err == nil {
		_, err = r.file.Write(data.Bytes())
		if err == nil {
			err = r.file.Sync()
		}
	}
	if err != nil {
		r.failed = true
		return fmt.Errorf("sensor state could not be committed")
	}
	r.setRecordLocked(record)
	return nil
}

func (r *SensorRegistry) setRecordLocked(record sensorRecord) {
	if prior, ok := r.records[record.ID]; ok {
		delete(r.byCredential, prior.CredentialID)
	}
	r.records[record.ID] = record
	r.byCredential[record.CredentialID] = record.ID
}

func (r *SensorRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

func (r *SensorRegistry) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return !r.failed
}

func sensorToken() (string, string, string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", "", err
	}
	id := uuid.NewString()
	token := SensorTokenPrefix + id + "." + hex.EncodeToString(secret)
	hash := sha256.Sum256([]byte(token))
	return token, id, hex.EncodeToString(hash[:]), nil
}

func (r *SensorRegistry) Enroll(spec SensorSpec) (SensorInfo, string, error) {
	if err := validateSensorSpec(spec); err != nil {
		return SensorInfo{}, "", err
	}
	now := time.Now().UTC()
	if spec.ExpiresAt.IsZero() {
		spec.ExpiresAt = now.Add(90 * 24 * time.Hour)
	}
	if !spec.ExpiresAt.After(now) || spec.ExpiresAt.After(now.Add(365*24*time.Hour)) {
		return SensorInfo{}, "", fmt.Errorf("expiry must be within one year")
	}
	spec.Scopes = slices.Clone(spec.Scopes)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.records[spec.ID]; exists || r.failed || len(r.records) >= 10000 {
		return SensorInfo{}, "", fmt.Errorf("sensor identity unavailable")
	}
	token, credential, hash, err := sensorToken()
	if err != nil {
		return SensorInfo{}, "", err
	}
	record := sensorRecord{SensorInfo: SensorInfo{SensorSpec: spec, CredentialID: credential, CreatedAt: now}, CredentialHash: hash}
	if err := r.saveLocked(record); err != nil {
		return SensorInfo{}, "", err
	}
	return detachedSensor(record.SensorInfo), token, nil
}

func (r *SensorRegistry) Rotate(id string) (SensorInfo, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[id]
	if !ok || !r.activeLocked(record, record.CredentialID) {
		return SensorInfo{}, "", fmt.Errorf("sensor unavailable or expired")
	}
	token, credential, hash, err := sensorToken()
	if err != nil {
		return SensorInfo{}, "", err
	}
	record.CredentialID, record.CredentialHash = credential, hash
	if err := r.saveLocked(record); err != nil {
		return SensorInfo{}, "", err
	}
	return detachedSensor(record.SensorInfo), token, nil
}

func (r *SensorRegistry) Revoke(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[id]
	if !ok || r.failed {
		return fmt.Errorf("sensor unavailable")
	}
	if record.RevokedAt != nil {
		return nil
	}
	now := time.Now().UTC()
	record.RevokedAt = &now
	return r.saveLocked(record)
}

func detachedSensor(info SensorInfo) SensorInfo {
	info.Scopes = slices.Clone(info.Scopes)
	if info.RevokedAt != nil {
		t := *info.RevokedAt
		info.RevokedAt = &t
	}
	return info
}

func (r *SensorRegistry) List() []SensorInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SensorInfo, 0, len(r.records))
	for _, record := range r.records {
		out = append(out, detachedSensor(record.SensorInfo))
	}
	slices.SortFunc(out, func(a, b SensorInfo) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (r *SensorRegistry) activeLocked(record sensorRecord, credential string) bool {
	return !r.failed && record.CredentialID == credential && record.RevokedAt == nil && time.Now().Before(record.ExpiresAt)
}

func (r *SensorRegistry) Authenticate(token string) (SensorInfo, bool) {
	if !strings.HasPrefix(token, SensorTokenPrefix) || len(token) > 150 {
		return SensorInfo{}, false
	}
	parts := strings.Split(strings.TrimPrefix(token, SensorTokenPrefix), ".")
	if len(parts) != 2 {
		return SensorInfo{}, false
	}
	hash := sha256.Sum256([]byte(token))
	want := hex.EncodeToString(hash[:])
	r.mu.RLock()
	defer r.mu.RUnlock()
	if record, ok := r.records[r.byCredential[parts[0]]]; ok && r.activeLocked(record, parts[0]) && subtle.ConstantTimeCompare([]byte(record.CredentialHash), []byte(want)) == 1 {
		return detachedSensor(record.SensorInfo), true
	}
	return SensorInfo{}, false
}

func sensorPayload(event *SecurityEvent) ([]byte, error) {
	copy := *event
	if copy.Sensor != nil {
		evidence := *copy.Sensor
		evidence.Signature = ""
		copy.Sensor = &evidence
	}
	return json.Marshal(&copy)
}

func (r *SensorRegistry) signLocked(event *SecurityEvent) error {
	payload, err := sensorPayload(event)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, r.key)
	_, _ = mac.Write(payload)
	event.Sensor.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// BindEvent replaces caller identity and rejects conflicting host/scope claims.
func (r *SensorRegistry) BindEvent(info SensorInfo, event *SecurityEvent) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[info.ID]
	if !ok || !r.activeLocked(record, info.CredentialID) {
		return fmt.Errorf("sensor credential is inactive")
	}
	if !slices.Contains(record.Scopes, SensorScope{Module: event.Module, Type: event.Type}) {
		return fmt.Errorf("event outside sensor scope")
	}
	if event.Sensor != nil {
		return fmt.Errorf("sensor evidence is server managed")
	}
	if event.Details == nil {
		event.Details = make(map[string]interface{})
	}
	for _, key := range []string{"process_host", "hostname", "host_id", "syslog_hostname"} {
		if value, exists := event.Details[key]; exists && value != record.HostID {
			return fmt.Errorf("event host conflicts with sensor grant")
		}
	}
	for key := range event.Details {
		if strings.HasPrefix(key, "sensor_") || key == "runtime_process_evidence" {
			return fmt.Errorf("reserved sensor evidence field")
		}
	}
	event.ID = "sensor-" + uuid.NewString()
	event.Source = "sensor/" + record.ID
	event.Details["host_id"] = record.HostID
	event.Sensor = &SensorEvidence{SensorID: record.ID, CredentialID: record.CredentialID, HostID: record.HostID}
	event.sensorAuthority = &sensorAuthority{registry: r, id: record.ID, credential: record.CredentialID}
	return r.signLocked(event)
}

func (r *SensorRegistry) VerifyEvent(event *SecurityEvent) bool {
	if event.Sensor == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[event.Sensor.SensorID]
	if !ok || !r.activeLocked(record, event.Sensor.CredentialID) || record.HostID != event.Sensor.HostID {
		return false
	}
	payload, err := sensorPayload(event)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(event.Sensor.Signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, r.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	event.sensorAuthority = &sensorAuthority{registry: r, id: record.ID, credential: record.CredentialID}
	return true
}

// NewDerivedEvent preserves live credential authority through detector fanout.
func NewDerivedEvent(parent *SecurityEvent, module, kind string, severity Severity, summary string) *SecurityEvent {
	event := NewSecurityEvent(module, kind, severity, summary)
	event.ObservationOnly = parent.ObservationOnly
	if parent.Sensor != nil {
		evidence := *parent.Sensor
		evidence.Signature = ""
		event.Sensor, event.sensorAuthority = &evidence, parent.sensorAuthority
		event.Source = parent.Source
		event.ID = "sensor-" + event.ID
	}
	return event
}

func sensorResponseAllowed(alert *Alert, action ActionType) bool {
	if action == ActionLog || action == ActionWebhook {
		return true
	}
	if alert.ObservationOnly {
		return false
	}
	if alert.Sensor == nil {
		return true
	}
	a := alert.sensorAuthority
	if a == nil || a.registry == nil {
		return false
	}
	r := a.registry
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[a.id]
	return ok && r.activeLocked(record, a.credential) && record.AllowLocalResponse && validateLocalProcessHost(record.HostID) == nil
}
