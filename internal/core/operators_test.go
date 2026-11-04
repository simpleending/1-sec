package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func operatorRegistryForTest(t *testing.T) *OperatorRegistry {
	t.Helper()
	r, err := NewOperatorRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
func enrollOperatorForTest(t *testing.T, r *OperatorRegistry, id, role string) (OperatorInfo, string) {
	t.Helper()
	info, token, err := r.Enroll(OperatorSpec{ID: id, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	return info, token
}
func TestOperatorRoleBoundaries(t *testing.T) {
	r := operatorRegistryForTest(t)
	for _, role := range []string{"viewer", "analyst", "responder", "sensor_manager", "integration", "administrator"} {
		info, key := enrollOperatorForTest(t, r, role, role)
		if _, ok := r.Authenticate(key); !ok {
			t.Fatal("credential rejected", role)
		}
		for _, p := range PermissionsForRole("administrator") {
			want := false
			switch p {
			case PermissionRead:
				want = true
			case PermissionAlerts, PermissionTest:
				want = role == "analyst" || role == "responder" || role == "administrator"
			case PermissionApprovals, PermissionRollback, PermissionWebhooks:
				want = role == "responder" || role == "administrator"
			case PermissionSensors:
				want = role == "sensor_manager" || role == "administrator"
			case PermissionEvents, PermissionAccess, PermissionTokens:
				want = role == "integration" || role == "administrator"
			default:
				want = role == "administrator"
			}
			if r.Authorize(info, p) != want {
				t.Errorf("%s %s", role, p)
			}
		}
		info.Role = "administrator"
		if role != "administrator" && r.Authorize(info, PermissionOperators) {
			t.Fatal("caller role snapshot escalated privileges")
		}
	}
	if len(PermissionsForRole("ADMIN")) != 0 {
		t.Fatal("unknown role accepted")
	}
	permissions := PermissionsForRole("viewer")
	permissions[0] = PermissionOperators
	if PermissionsForRole("viewer")[0] != PermissionRead {
		t.Fatal("role grants aliased")
	}
}
func TestOperatorDurableLifecycle(t *testing.T) {
	dir := t.TempDir()
	r, err := NewOperatorRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = enrollOperatorForTest(t, r, "admin", "administrator")
	info, old := enrollOperatorForTest(t, r, "alice@example.com", "responder")
	if _, err := NewOperatorRegistry(dir); err == nil {
		t.Fatal("multiple journal owners")
	}
	newInfo, key, err := r.Rotate(info.ID, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Authenticate(old); ok || r.Authorize(info, PermissionApprovals) {
		t.Fatal("rotation retained old authority")
	}
	if err := r.SetRole(info.ID, "viewer"); err != nil {
		t.Fatal(err)
	}
	if r.Authorize(newInfo, PermissionApprovals) {
		t.Fatal("role downgrade retained approvals")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = NewOperatorRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	current, ok := r.Authenticate(key)
	if !ok || current.Role != "viewer" {
		t.Fatal("role/rotation lost on restart")
	}
	if err := r.Revoke(info.ID); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	r, err = NewOperatorRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, ok := r.Authenticate(key); ok {
		t.Fatal("revocation lost on restart")
	}
	if _, _, err := r.Rotate(info.ID, time.Time{}); err == nil {
		t.Fatal("revoked identity restored")
	}
	if _, _, err := r.Enroll(OperatorSpec{ID: info.ID, Role: "administrator"}); err == nil {
		t.Fatal("revoked ID reused")
	}
	_ = r.Close() // Windows keeps the journal exclusively locked while owned.
	data, err := os.ReadFile(filepath.Join(dir, "operators.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(key)) || bytes.Contains(data, []byte(old)) {
		t.Fatal("plaintext credential persisted")
	}
}
func TestOperatorStateFailuresAndExpiry(t *testing.T) {
	t.Run("storage", func(t *testing.T) {
		r := operatorRegistryForTest(t)
		info, key := enrollOperatorForTest(t, r, "alice", "responder")
		_ = r.file.Close()
		if err := r.SetRole(info.ID, "viewer"); err == nil || r.Ready() {
			t.Fatal("failed write retained readiness")
		}
		if _, ok := r.Authenticate(key); ok || r.Authorize(info, PermissionApprovals) {
			t.Fatal("failed journal authorized")
		}
	})
	t.Run("capacity", func(t *testing.T) {
		r := operatorRegistryForTest(t)
		_, _ = enrollOperatorForTest(t, r, "alice", "viewer")
		r.journalLimit = 1
		if _, _, err := r.Rotate("alice", time.Time{}); err == nil || r.Ready() {
			t.Fatal("journal limit bypassed")
		}
	})
	t.Run("expiry", func(t *testing.T) {
		r := operatorRegistryForTest(t)
		info, key := enrollOperatorForTest(t, r, "alice", "responder")
		r.mu.Lock()
		record := r.records[info.ID]
		record.ExpiresAt = time.Now().Add(-time.Second)
		err := r.saveLocked(record)
		r.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := r.Authenticate(key); ok || r.Authorize(info, PermissionApprovals) {
			t.Fatal("expired credential authorized")
		}
		_, newKey, err := r.Rotate(info.ID, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := r.Authenticate(newKey); !ok {
			t.Fatal("administrator renewal failed")
		}
	})
	for _, contents := range []string{"{\"version\":1}", "{\"version\":1}\n{}\n", "{\"version\":2}\n"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "operators.jsonl"), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewOperatorRegistry(dir); err == nil {
			t.Fatal("corrupt journal accepted")
		}
	}
}
func TestOperatorValidationAndLastAdministrator(t *testing.T) {
	r := operatorRegistryForTest(t)
	for _, spec := range []OperatorSpec{{ID: "", Role: "viewer"}, {ID: "me", Role: "viewer"}, {ID: "..", Role: "viewer"}, {ID: ".", Role: "viewer"}, {ID: "alice", Role: "*"}, {ID: "a\nb", Role: "viewer"}, {ID: "admin", Role: "viewer", ExpiresAt: time.Now().Add(400 * 24 * time.Hour)}} {
		if _, _, err := r.Enroll(spec); err == nil {
			t.Fatal("invalid operator accepted", spec)
		}
	}
	_, _ = enrollOperatorForTest(t, r, "root", "administrator")
	if err := r.Revoke("root"); err == nil {
		t.Fatal("last administrator revoked")
	}
	if err := r.SetRole("root", "viewer"); err == nil {
		t.Fatal("last administrator demoted")
	}
	_, _ = enrollOperatorForTest(t, r, "second", "administrator")
	if err := r.Revoke("root"); err != nil {
		t.Fatal(err)
	}
	list := r.List()
	for i := range list {
		if list[i].RevokedAt != nil {
			*list[i].RevokedAt = time.Time{}
		}
	}
	if r.List()[0].RevokedAt != nil && r.List()[0].RevokedAt.IsZero() {
		t.Fatal("list aliases state")
	}
	if _, ok := r.Authenticate(strings.Repeat("x", 200)); ok {
		t.Fatal("oversize key")
	}
}
func TestOperatorConcurrentAuthorization(t *testing.T) {
	r := operatorRegistryForTest(t)
	info, key := enrollOperatorForTest(t, r, "alice", "responder")
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				_, _ = r.Authenticate(key)
				_ = r.Authorize(info, PermissionApprovals)
			}
		})
	}
	for range 4 {
		if err := r.SetRole(info.ID, "viewer"); err != nil {
			t.Fatal(err)
		}
		if err := r.SetRole(info.ID, "responder"); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
func TestOperatorStrictConfiguration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Operators.RequireNamed = true
	if _, err := NewEngine(cfg); err == nil {
		t.Fatal("strict without operators enabled")
	}
	cfg.Operators.Enabled = true
	cfg.Operators.StateDir = t.TempDir()
	cfg.Cloud.RemoteCommandsEnabled = true
	if _, err := NewEngine(cfg); err == nil {
		t.Fatal("strict cloud command bypass enabled")
	}
	cfg.Cloud.RemoteCommandsEnabled = false
	if _, err := NewEngine(cfg); err == nil {
		t.Fatal("strict mode bootstrapped anonymously")
	}
	r, err := NewOperatorRegistry(cfg.Operators.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = enrollOperatorForTest(t, r, "admin", "administrator")
	_ = r.Close()
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Shutdown()
	if !e.Config.AuthEnabled() {
		t.Fatal("named auth fell back to open mode")
	}
}

func TestOperatorApprovalAuthorityRecheckedAtDispatch(t *testing.T) {
	for _, mode := range []string{"active", "revoked", "rotated", "downgraded"} {
		t.Run(mode, func(t *testing.T) {
			registry := operatorRegistryForTest(t)
			info, _ := enrollOperatorForTest(t, registry, "responder", "responder")
			cfg := enforcementConfig("", false)
			cfg.Enforcement.ApprovalGate = DefaultApprovalGateConfig()
			cfg.Enforcement.ApprovalGate.Enabled = true
			re := testResponseEngine(t, cfg)
			defer re.Stop()
			alert := testAlertWithIP("injection_shield", "198.51.100.8", SeverityCritical)
			rule := ResponseRule{Action: ActionBlockIP}
			re.policies[alert.Module] = &ResponsePolicy{Enabled: true, Actions: []ResponseRule{rule}, MaxActionsPerMin: 100}
			executor := &mockExecutor{}
			re.executors[ActionBlockIP] = executor
			handlers := re.ApprovalGate.handlers
			re.ApprovalGate.handlers = append([]ApprovalHandler{func(*PendingApproval) {
				switch mode {
				case "revoked":
					if err := registry.Revoke(info.ID); err != nil {
						t.Fatal(err)
					}
				case "rotated":
					if _, _, err := registry.Rotate(info.ID, time.Time{}); err != nil {
						t.Fatal(err)
					}
				case "downgraded":
					if err := registry.SetRole(info.ID, "viewer"); err != nil {
						t.Fatal(err)
					}
				}
			}}, handlers...)
			id := re.ApprovalGate.Submit(alert, rule, "198.51.100.8")
			_, err := re.ApprovalGate.ApproveAuthorized(id, "operator:"+info.ID, func() bool { return registry.Authorize(info, PermissionApprovals) })
			if err != nil {
				t.Fatal(err)
			}
			if (executor.callCount > 0) != (mode == "active") {
				t.Fatalf("%s executed %d times", mode, executor.callCount)
			}
		})
	}
}

func TestOperatorMutationRechecksActorAtCommit(t *testing.T) {
	r := operatorRegistryForTest(t)
	actor, _ := enrollOperatorForTest(t, r, "first", "administrator")
	_, _ = enrollOperatorForTest(t, r, "second", "administrator")
	_, _ = enrollOperatorForTest(t, r, "target", "viewer")
	if err := r.SetRole(actor.ID, "viewer"); err != nil {
		t.Fatal(err)
	}
	_, _, err := r.Enroll(OperatorSpec{ID: "escalated", Role: "administrator"}, actor)
	if !errors.Is(err, ErrOperatorPermission) {
		t.Fatal("stale administrator enrolled", err)
	}
	_, _, err = r.Rotate("target", time.Time{}, actor)
	if !errors.Is(err, ErrOperatorPermission) {
		t.Fatal("stale administrator rotated", err)
	}
	if err := r.SetRole("target", "administrator", actor); !errors.Is(err, ErrOperatorPermission) {
		t.Fatal("stale administrator changed role", err)
	}
	if err := r.Revoke("target", actor); !errors.Is(err, ErrOperatorPermission) {
		t.Fatal("stale administrator revoked", err)
	}
}

func TestOperatorGrantFenceSerializesRevocation(t *testing.T) {
	r := operatorRegistryForTest(t)
	actor, _ := enrollOperatorForTest(t, r, "manager", "sensor_manager")
	entered, release, finished, revoked := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan error, 1)
	go func() {
		finished <- r.WithPermission(actor, PermissionSensors, func(OperatorInfo) error { close(entered); <-release; return nil })
	}()
	<-entered
	go func() { revoked <- r.Revoke(actor.ID) }()
	select {
	case err := <-revoked:
		t.Fatal("revocation completed inside a credential grant", err)
	default:
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if err := r.WithPermission(actor, PermissionSensors, func(OperatorInfo) error { t.Error("revoked manager issued credential"); return nil }); !errors.Is(err, ErrOperatorPermission) {
		t.Fatal(err)
	}
}

func TestOperatorStrictModeRejectsCloudCommandExecution(t *testing.T) {
	e := testEngineForPoller(t, false)
	e.Config.Operators.RequireNamed = true
	cp := NewCommandPoller(e)
	defer cp.Stop()
	if _, err := cp.executeCommand(CloudCommand{Type: "set_dry_run", DryRun: boolPtr(false), IssuedBy: "operator:forged"}); err == nil {
		t.Fatal("cloud issuer claim bypassed operator authority")
	}
}
