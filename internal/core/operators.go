package core

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const OperatorTokenPrefix = "1sec_operator_"

var ErrOperatorPermission = errors.New("operator permission is no longer active")

type OperatorConfig struct {
	Enabled      bool   `yaml:"enabled"`
	StateDir     string `yaml:"state_dir"`
	RequireNamed bool   `yaml:"require_named"`
}

type Permission string

const (
	PermissionRead             Permission = "read"
	PermissionAlerts           Permission = "alerts.triage"
	PermissionAlertDelete      Permission = "alerts.delete"
	PermissionApprovals        Permission = "approvals.decide"
	PermissionRollback         Permission = "response.rollback"
	PermissionTest             Permission = "response.test"
	PermissionWebhooks         Permission = "webhooks.retry"
	PermissionPolicies         Permission = "policies.manage"
	PermissionSensors          Permission = "sensors.manage"
	PermissionContainmentGrant Permission = "containment.grant"
	PermissionOperators        Permission = "operators.manage"
	PermissionEvents           Permission = "events.write"
	PermissionAccess           Permission = "access.check"
	PermissionTokens           Permission = "tokens.exchange"
	PermissionEngine           Permission = "engine.manage"
)

// PermissionsForRole returns a detached, explicit grant. Unknown roles grant nothing.
func PermissionsForRole(role string) []Permission {
	switch role {
	case "viewer":
		return []Permission{PermissionRead}
	case "analyst":
		return []Permission{PermissionRead, PermissionAlerts, PermissionTest}
	case "responder":
		return []Permission{PermissionRead, PermissionAlerts, PermissionTest, PermissionApprovals, PermissionRollback, PermissionWebhooks}
	case "sensor_manager":
		return []Permission{PermissionRead, PermissionSensors}
	case "integration":
		return []Permission{PermissionRead, PermissionEvents, PermissionAccess, PermissionTokens}
	case "administrator":
		return []Permission{PermissionRead, PermissionAlerts, PermissionAlertDelete, PermissionApprovals, PermissionRollback, PermissionTest, PermissionWebhooks, PermissionPolicies, PermissionSensors, PermissionContainmentGrant, PermissionOperators, PermissionEvents, PermissionAccess, PermissionTokens, PermissionEngine}
	default:
		return nil
	}
}

type OperatorSpec struct {
	ID        string    `json:"id"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}
type OperatorInfo struct {
	OperatorSpec
	CredentialID string     `json:"credential_id"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}
type operatorRecord struct {
	OperatorInfo
	CredentialHash string `json:"credential_hash"`
}

// OperatorRegistry is a private, single-owner append journal. A successful write
// is synced before becoming authoritative. Failed storage disables authorization.
type OperatorRegistry struct {
	mu           sync.RWMutex
	file         *os.File
	records      map[string]operatorRecord
	byCredential map[string]string
	failed       bool
	journalLimit int64
}

func NewOperatorRegistry(dir string) (*OperatorRegistry, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := RestrictPrivatePath(dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "operators.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
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
		return nil, fmt.Errorf("operator registry already owned or unavailable: %w", err)
	}
	if err := RestrictPrivatePath(path, false); err != nil {
		return nil, err
	}
	r := &OperatorRegistry{file: f, records: make(map[string]operatorRecord), byCredential: make(map[string]string), journalLimit: 16 << 20}
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() >= r.journalLimit {
		return nil, fmt.Errorf("operator journal capacity reached")
	}
	if stat.Size() == 0 {
		if _, err := f.WriteString("{\"version\":1}\n"); err != nil {
			return nil, err
		}
		if err := f.Sync(); err != nil {
			return nil, err
		}
	} else {
		reader := bufio.NewReader(io.LimitReader(f, r.journalLimit))
		header, err := reader.ReadBytes('\n')
		var h struct {
			Version int `json:"version"`
		}
		if err != nil || json.Unmarshal(header, &h) != nil || h.Version != 1 {
			return nil, fmt.Errorf("invalid operator journal header")
		}
		for {
			line, err := reader.ReadBytes('\n')
			if err == io.EOF && len(line) == 0 {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("incomplete operator journal record")
			}
			var record operatorRecord
			d := json.NewDecoder(bytes.NewReader(line))
			d.DisallowUnknownFields()
			if d.Decode(&record) != nil || d.Decode(new(interface{})) != io.EOF || validateOperatorSpec(record.OperatorSpec) != nil || record.ExpiresAt.IsZero() || record.CreatedAt.IsZero() || record.CredentialID == "" {
				return nil, fmt.Errorf("invalid operator journal record")
			}
			hash, err := hex.DecodeString(record.CredentialHash)
			if err != nil || len(hash) != sha256.Size {
				return nil, fmt.Errorf("invalid operator credential hash")
			}
			if other, ok := r.byCredential[record.CredentialID]; ok && other != record.ID {
				return nil, fmt.Errorf("duplicate operator credential")
			}
			r.setLocked(record)
			if len(r.records) > 1000 {
				return nil, fmt.Errorf("operator identity capacity reached")
			}
		}
	}
	keep = true
	return r, nil
}

func validateOperatorSpec(spec OperatorSpec) error {
	if len(spec.ID) == 0 || len(spec.ID) > 128 || spec.ID == "." || spec.ID == ".." || spec.ID == "me" || len(PermissionsForRole(spec.Role)) == 0 {
		return fmt.Errorf("invalid operator identity or role")
	}
	for _, c := range spec.ID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._@-", c)) {
			return fmt.Errorf("operator ID must use ASCII letters, digits, dot, underscore, @ or hyphen")
		}
	}
	return nil
}
func operatorExpiry(expires time.Time) (time.Time, error) {
	now := time.Now().UTC()
	if expires.IsZero() {
		expires = now.Add(90 * 24 * time.Hour)
	}
	if !expires.After(now) || expires.After(now.Add(365*24*time.Hour)) {
		return time.Time{}, fmt.Errorf("expiry must be within one year")
	}
	return expires, nil
}
func (r *OperatorRegistry) setLocked(record operatorRecord) {
	if old, ok := r.records[record.ID]; ok {
		delete(r.byCredential, old.CredentialID)
	}
	r.records[record.ID] = record
	r.byCredential[record.CredentialID] = record.ID
}
func (r *OperatorRegistry) saveLocked(record operatorRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	end, err := r.file.Seek(0, io.SeekEnd)
	if err == nil && end+int64(len(data)) >= r.journalLimit {
		err = fmt.Errorf("operator journal capacity reached")
	}
	if err == nil {
		var n int
		n, err = r.file.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		if err == nil {
			err = r.file.Sync()
		}
	}
	if err != nil {
		r.failed = true
		return fmt.Errorf("operator state could not be committed")
	}
	r.setLocked(record)
	return nil
}
func detachedOperator(info OperatorInfo) OperatorInfo {
	if info.RevokedAt != nil {
		t := *info.RevokedAt
		info.RevokedAt = &t
	}
	return info
}
func (r *OperatorRegistry) Enroll(spec OperatorSpec, actor ...OperatorInfo) (OperatorInfo, string, error) {
	if err := validateOperatorSpec(spec); err != nil {
		return OperatorInfo{}, "", err
	}
	expires, err := operatorExpiry(spec.ExpiresAt)
	if err != nil {
		return OperatorInfo{}, "", err
	}
	spec.ExpiresAt = expires
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.adminLocked(actor) {
		return OperatorInfo{}, "", ErrOperatorPermission
	}
	if _, ok := r.records[spec.ID]; ok || r.failed || len(r.records) >= 1000 {
		return OperatorInfo{}, "", fmt.Errorf("operator identity unavailable")
	}
	token, id, hash, err := identityToken(OperatorTokenPrefix)
	if err != nil {
		return OperatorInfo{}, "", err
	}
	now := time.Now().UTC()
	record := operatorRecord{OperatorInfo: OperatorInfo{OperatorSpec: spec, CredentialID: id, CreatedAt: now, UpdatedAt: now}, CredentialHash: hash}
	if err := r.saveLocked(record); err != nil {
		return OperatorInfo{}, "", err
	}
	return detachedOperator(record.OperatorInfo), token, nil
}
func (r *OperatorRegistry) activeLocked(record operatorRecord, credential string) bool {
	return !r.failed && record.CredentialID == credential && record.RevokedAt == nil && time.Now().Before(record.ExpiresAt)
}
func (r *OperatorRegistry) Authenticate(token string) (OperatorInfo, bool) {
	if !strings.HasPrefix(token, OperatorTokenPrefix) || len(token) > 150 {
		return OperatorInfo{}, false
	}
	parts := strings.Split(strings.TrimPrefix(token, OperatorTokenPrefix), ".")
	if len(parts) != 2 {
		return OperatorInfo{}, false
	}
	hash := sha256.Sum256([]byte(token))
	want := hex.EncodeToString(hash[:])
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[r.byCredential[parts[0]]]
	if !ok || !r.activeLocked(record, parts[0]) || subtle.ConstantTimeCompare([]byte(record.CredentialHash), []byte(want)) != 1 {
		return OperatorInfo{}, false
	}
	return detachedOperator(record.OperatorInfo), true
}
func (r *OperatorRegistry) Authorize(info OperatorInfo, permission Permission) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[info.ID]
	return ok && r.activeLocked(record, info.CredentialID) && slices.Contains(PermissionsForRole(record.Role), permission)
}
func (r *OperatorRegistry) Rotate(id string, expires time.Time, actor ...OperatorInfo) (OperatorInfo, string, error) {
	expiry, err := operatorExpiry(expires)
	if err != nil {
		return OperatorInfo{}, "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.adminLocked(actor) {
		return OperatorInfo{}, "", ErrOperatorPermission
	}
	record, ok := r.records[id]
	if !ok || r.failed || record.RevokedAt != nil {
		return OperatorInfo{}, "", fmt.Errorf("operator unavailable")
	}
	token, credential, hash, err := identityToken(OperatorTokenPrefix)
	if err != nil {
		return OperatorInfo{}, "", err
	}
	record.CredentialID, record.CredentialHash, record.ExpiresAt = credential, hash, expiry
	record.UpdatedAt = time.Now().UTC()
	if err := r.saveLocked(record); err != nil {
		return OperatorInfo{}, "", err
	}
	return detachedOperator(record.OperatorInfo), token, nil
}
func (r *OperatorRegistry) hasOtherAdminLocked(id string) bool {
	for _, record := range r.records {
		if record.ID != id && record.Role == "administrator" && r.activeLocked(record, record.CredentialID) {
			return true
		}
	}
	return false
}
func (r *OperatorRegistry) SetRole(id, role string, actor ...OperatorInfo) error {
	if len(PermissionsForRole(role)) == 0 {
		return fmt.Errorf("unknown operator role")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.adminLocked(actor) {
		return ErrOperatorPermission
	}
	record, ok := r.records[id]
	if !ok || r.failed || record.RevokedAt != nil {
		return fmt.Errorf("operator unavailable")
	}
	if role != "administrator" && record.Role == "administrator" && r.activeLocked(record, record.CredentialID) && !r.hasOtherAdminLocked(id) {
		return fmt.Errorf("cannot remove the last active administrator")
	}
	record.Role = role
	record.UpdatedAt = time.Now().UTC()
	return r.saveLocked(record)
}
func (r *OperatorRegistry) Revoke(id string, actor ...OperatorInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.adminLocked(actor) {
		return ErrOperatorPermission
	}
	record, ok := r.records[id]
	if !ok || r.failed {
		return fmt.Errorf("operator unavailable")
	}
	if record.RevokedAt != nil {
		return nil
	}
	if record.Role == "administrator" && r.activeLocked(record, record.CredentialID) && !r.hasOtherAdminLocked(id) {
		return fmt.Errorf("cannot remove the last active administrator")
	}
	now := time.Now().UTC()
	record.RevokedAt = &now
	record.UpdatedAt = now
	return r.saveLocked(record)
}
func (r *OperatorRegistry) HasAdministrator() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hasOtherAdminLocked("")
}

// No actor is the trusted in-process/bootstrap path. HTTP callers pass the
// credential-bound actor so the final check and journal commit share one lock.
func (r *OperatorRegistry) adminLocked(actor []OperatorInfo) bool {
	if len(actor) == 0 {
		return true
	}
	if len(actor) != 1 {
		return false
	}
	record, ok := r.records[actor[0].ID]
	return ok && r.activeLocked(record, actor[0].CredentialID) && record.Role == "administrator"
}

// WithPermission fences short credential-issuing operations against concurrent
// revocation. The callback must not reenter this registry or read HTTP bodies.
func (r *OperatorRegistry) WithPermission(actor OperatorInfo, p Permission, operation func(OperatorInfo) error) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[actor.ID]
	if !ok || !r.activeLocked(record, actor.CredentialID) || !slices.Contains(PermissionsForRole(record.Role), p) {
		return ErrOperatorPermission
	}
	return operation(detachedOperator(record.OperatorInfo))
}
func (r *OperatorRegistry) List() []OperatorInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]OperatorInfo, 0, len(r.records))
	for _, record := range r.records {
		out = append(out, detachedOperator(record.OperatorInfo))
	}
	slices.SortFunc(out, func(a, b OperatorInfo) int { return strings.Compare(a.ID, b.ID) })
	return out
}
func (r *OperatorRegistry) Ready() bool { r.mu.RLock(); defer r.mu.RUnlock(); return !r.failed }
func (r *OperatorRegistry) Close() error {
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
