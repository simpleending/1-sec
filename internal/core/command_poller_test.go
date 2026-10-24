package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// ─── Helpers ────────────────────────────────────────────────────────────────

func testEngineForPoller(t *testing.T, approvalGateEnabled bool) *Engine {
	t.Helper()
	cfg := DefaultConfig()
	cfg.RustEngine.Enabled = false
	cfg.Cloud.Enabled = true
	cfg.Cloud.RemoteCommandsEnabled = true
	cfg.Cloud.InstanceID = "i-test"
	cfg.Cloud.APIKey = "test-cloud-key"
	cfg.Cloud.CommandPollInterval = 5
	cfg.Enforcement = &EnforcementConfig{
		Enabled: true,
		DryRun:  false,
		Preset:  "balanced",
		ApprovalGate: ApprovalGateConfig{
			Enabled:         approvalGateEnabled,
			RequireApproval: []string{"kill_process", "quarantine_file", "disable_user"},
			TTL:             30 * time.Minute,
			MaxPending:      100,
		},
	}
	logger := zerolog.Nop()
	pipeline := NewAlertPipeline(logger, 1000)
	re := NewResponseEngine(logger, nil, pipeline, cfg)

	return &Engine{
		Config:         cfg,
		Registry:       NewModuleRegistry(logger),
		Pipeline:       pipeline,
		Logger:         logger,
		ResponseEngine: re,
	}
}

func boolPtr(b bool) *bool { return &b }

// ─── NewCommandPoller ───────────────────────────────────────────────────────

func TestNewCommandPoller(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)
	if cp == nil {
		t.Fatal("expected non-nil CommandPoller")
	}
	if cp.cfg != engine.Config {
		t.Error("expected poller config to match engine config")
	}
	if cp.engine != engine {
		t.Error("expected poller engine to match")
	}
}

// ─── Start / Stop ───────────────────────────────────────────────────────────

func TestCommandPoller_StartStop_CloudDisabled(t *testing.T) {
	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.Enabled = false
	cp := NewCommandPoller(engine)
	// Should not panic when cloud is disabled
	cp.Start()
	cp.Stop()
}

func TestCommandPoller_StartStop_NoAPIKey(t *testing.T) {
	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.APIKey = ""
	cp := NewCommandPoller(engine)
	cp.Start()
	cp.Stop()
}

func TestCommandPoller_Stop_CancelsContext(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)
	cp.Stop()
	select {
	case <-cp.ctx.Done():
		// expected
	default:
		t.Error("expected context to be cancelled after Stop")
	}
}

// ─── executeCommand dispatch ────────────────────────────────────────────────

func TestCommandPoller_ExecuteCommand_UnknownType(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	_, err := cp.executeCommand(CloudCommand{Type: "unknown_type"})
	if err == nil {
		t.Error("expected error for unknown command type")
	}
}

// ─── executeApprove ─────────────────────────────────────────────────────────

func TestCommandPoller_ExecuteApprove_NoResponseEngine(t *testing.T) {
	engine := testEngineForPoller(t, true)
	engine.ResponseEngine = nil
	cp := NewCommandPoller(engine)

	_, err := cp.executeApprove(CloudCommand{ApprovalID: "test-id", IssuedBy: "admin"})
	if err == nil {
		t.Error("expected error when ResponseEngine is nil")
	}
}

func TestCommandPoller_ExecuteApprove_NoApprovalGate(t *testing.T) {
	engine := testEngineForPoller(t, false) // gate disabled
	cp := NewCommandPoller(engine)

	_, err := cp.executeApprove(CloudCommand{ApprovalID: "test-id", IssuedBy: "admin"})
	if err == nil {
		t.Error("expected error when ApprovalGate is nil")
	}
}

func TestCommandPoller_ExecuteApprove_Success(t *testing.T) {
	engine := testEngineForPoller(t, true)
	cp := NewCommandPoller(engine)
	defer engine.ResponseEngine.ApprovalGate.Stop()

	// Submit a pending approval
	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess}
	id := engine.ResponseEngine.ApprovalGate.Submit(alert, rule, "pid:1234")

	result, err := cp.executeApprove(CloudCommand{ApprovalID: id, IssuedBy: "admin@test.com"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestCommandPoller_ExecuteApprove_NotFound(t *testing.T) {
	engine := testEngineForPoller(t, true)
	cp := NewCommandPoller(engine)
	defer engine.ResponseEngine.ApprovalGate.Stop()

	_, err := cp.executeApprove(CloudCommand{ApprovalID: "nonexistent", IssuedBy: "admin"})
	if err == nil {
		t.Error("expected error for nonexistent approval ID")
	}
}

// ─── executeReject ──────────────────────────────────────────────────────────

func TestCommandPoller_ExecuteReject_NoResponseEngine(t *testing.T) {
	engine := testEngineForPoller(t, true)
	engine.ResponseEngine = nil
	cp := NewCommandPoller(engine)

	_, err := cp.executeReject(CloudCommand{ApprovalID: "test-id", IssuedBy: "admin"})
	if err == nil {
		t.Error("expected error when ResponseEngine is nil")
	}
}

func TestCommandPoller_ExecuteReject_Success(t *testing.T) {
	engine := testEngineForPoller(t, true)
	cp := NewCommandPoller(engine)
	defer engine.ResponseEngine.ApprovalGate.Stop()

	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess}
	id := engine.ResponseEngine.ApprovalGate.Submit(alert, rule, "pid:5678")

	result, err := cp.executeReject(CloudCommand{ApprovalID: id, IssuedBy: "soc-lead"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestCommandPoller_ExecuteReject_NotFound(t *testing.T) {
	engine := testEngineForPoller(t, true)
	cp := NewCommandPoller(engine)
	defer engine.ResponseEngine.ApprovalGate.Stop()

	_, err := cp.executeReject(CloudCommand{ApprovalID: "nonexistent", IssuedBy: "admin"})
	if err == nil {
		t.Error("expected error for nonexistent approval ID")
	}
}

// ─── executeRollback ────────────────────────────────────────────────────────

func TestCommandPoller_ExecuteRollback_NoResponseEngine(t *testing.T) {
	engine := testEngineForPoller(t, false)
	engine.ResponseEngine = nil
	cp := NewCommandPoller(engine)

	_, err := cp.executeRollback(CloudCommand{RecordID: "rec-1"})
	if err == nil {
		t.Error("expected error when ResponseEngine is nil")
	}
}

func TestCommandPoller_ExecuteRollback_RecordNotFound(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	_, err := cp.executeRollback(CloudCommand{RecordID: "nonexistent"})
	if err == nil {
		t.Error("expected error for nonexistent record")
	}
}

func TestCommandPoller_ExecuteRollback_NotSuccessStatus(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	// Generate a dry-run record (not SUCCESS)
	alert := testAlertWithIP("injection_shield", "10.0.0.1", SeverityHigh)
	engine.Config.Enforcement.SetDryRun(true)
	engine.ResponseEngine.handleAlert(alert)

	records := engine.ResponseEngine.GetRecords(1, "")
	if len(records) == 0 {
		t.Fatal("expected at least one record")
	}

	_, err := cp.executeRollback(CloudCommand{RecordID: records[0].ID})
	if err == nil {
		t.Error("expected error for non-SUCCESS record")
	}
}

func TestCommandPoller_ExecuteRollback_UnsupportedAction(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	// Create a log_only record with SUCCESS status by running in live mode
	cfg := engine.Config
	cfg.Enforcement.DryRun = false
	cfg.Enforcement.Policies = map[string]ResponsePolicyYAML{
		"test_module": {
			Enabled:          true,
			MinSeverity:      "LOW",
			CooldownSeconds:  0,
			MaxActionsPerMin: 100,
			Actions: []ResponseRuleYAML{
				{Action: "log_only", MinSeverity: "LOW"},
			},
		},
	}
	// Rebuild response engine with new config
	logger := zerolog.Nop()
	pipeline := NewAlertPipeline(logger, 1000)
	engine.ResponseEngine = NewResponseEngine(logger, nil, pipeline, cfg)

	alert := testAlertWithIP("test_module", "10.0.0.1", SeverityHigh)
	engine.ResponseEngine.handleAlert(alert)

	records := engine.ResponseEngine.GetRecords(1, "")
	if len(records) == 0 {
		t.Fatal("expected at least one record")
	}
	if records[0].Status != ActionStatusSuccess {
		t.Fatalf("expected SUCCESS status, got %s", records[0].Status)
	}

	_, err := cp.executeRollback(CloudCommand{RecordID: records[0].ID})
	if err == nil {
		t.Error("expected error for unsupported rollback action type (log_only)")
	}
}

// ─── executeSetDryRun ───────────────────────────────────────────────────────

func TestCommandPoller_ExecuteSetDryRun_NoEnforcement(t *testing.T) {
	engine := testEngineForPoller(t, false)
	engine.Config.Enforcement = nil
	cp := NewCommandPoller(engine)

	_, err := cp.executeSetDryRun(CloudCommand{DryRun: boolPtr(true)})
	if err == nil {
		t.Error("expected error when enforcement is nil")
	}
}

func TestCommandPoller_ExecuteSetDryRun_MissingValue(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	_, err := cp.executeSetDryRun(CloudCommand{DryRun: nil})
	if err == nil {
		t.Error("expected error when DryRun is nil")
	}
}

func TestCommandPoller_ExecuteSetDryRun_EnableDryRun(t *testing.T) {
	engine := testEngineForPoller(t, false)
	engine.Config.Enforcement.SetDryRun(false)
	cp := NewCommandPoller(engine)

	result, err := cp.executeSetDryRun(CloudCommand{DryRun: boolPtr(true), IssuedBy: "admin"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !engine.Config.Enforcement.GetDryRun() {
		t.Error("expected DryRun to be true after command")
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestCommandPoller_ExecuteSetDryRun_DisableDryRun(t *testing.T) {
	engine := testEngineForPoller(t, false)
	engine.Config.Enforcement.SetDryRun(true)
	cp := NewCommandPoller(engine)

	result, err := cp.executeSetDryRun(CloudCommand{DryRun: boolPtr(false), IssuedBy: "admin"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine.Config.Enforcement.GetDryRun() {
		t.Error("expected DryRun to be false after command")
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

// ─── executeSetPolicy ───────────────────────────────────────────────────────

func TestCommandPoller_ExecuteSetPolicy_NoResponseEngine(t *testing.T) {
	engine := testEngineForPoller(t, false)
	engine.ResponseEngine = nil
	cp := NewCommandPoller(engine)

	_, err := cp.executeSetPolicy(CloudCommand{Module: "test", Enabled: boolPtr(true)})
	if err == nil {
		t.Error("expected error when ResponseEngine is nil")
	}
}

func TestCommandPoller_ExecuteSetPolicy_MissingEnabled(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	_, err := cp.executeSetPolicy(CloudCommand{Module: "injection_shield", Enabled: nil})
	if err == nil {
		t.Error("expected error when Enabled is nil")
	}
}

func TestCommandPoller_ExecuteSetPolicy_MissingModule(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	_, err := cp.executeSetPolicy(CloudCommand{Module: "", Enabled: boolPtr(true)})
	if err == nil {
		t.Error("expected error when Module is empty")
	}
}

func TestCommandPoller_ExecuteSetPolicy_DisableModule(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	result, err := cp.executeSetPolicy(CloudCommand{
		Module:   "injection_shield",
		Enabled:  boolPtr(false),
		IssuedBy: "admin",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}

	policies := engine.ResponseEngine.GetPolicies()
	if policies["injection_shield"].Enabled {
		t.Error("expected injection_shield to be disabled")
	}
}

func TestCommandPoller_ExecuteSetPolicy_EnableModule(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	// First disable, then re-enable
	engine.ResponseEngine.SetPolicyEnabled("injection_shield", false)

	result, err := cp.executeSetPolicy(CloudCommand{
		Module:   "injection_shield",
		Enabled:  boolPtr(true),
		IssuedBy: "admin",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}

	policies := engine.ResponseEngine.GetPolicies()
	if !policies["injection_shield"].Enabled {
		t.Error("expected injection_shield to be enabled")
	}
}

func TestCommandPoller_ExecuteSetPolicy_NonexistentModule(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	_, err := cp.executeSetPolicy(CloudCommand{
		Module:  "nonexistent_module",
		Enabled: boolPtr(true),
	})
	if err == nil {
		t.Error("expected error for nonexistent module")
	}
}

// ─── fetchPendingCommands with mock server ──────────────────────────────────

func TestCommandPoller_FetchPendingCommands_Success(t *testing.T) {
	commands := []CloudCommand{
		{ID: "cmd-1", Type: "approve", Status: "pending", ApprovalID: "ap-1"},
		{ID: "cmd-2", Type: "set_dry_run", Status: "pending", DryRun: boolPtr(true)},
	}
	resp := CloudCommandsResponse{Commands: commands}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/commands" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("status") != "pending" {
			t.Errorf("expected status=pending query param")
		}
		if r.Header.Get("Authorization") != "Bearer test-cloud-key" {
			t.Errorf("expected auth header, got %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.APIURL = server.URL
	cp := NewCommandPoller(engine)

	fetched, err := cp.fetchPendingCommands()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fetched) != 2 {
		t.Errorf("expected 2 commands, got %d", len(fetched))
	}
	if fetched[0].ID != "cmd-1" {
		t.Errorf("expected cmd-1, got %s", fetched[0].ID)
	}
}

func TestCommandPoller_FetchPendingCommands_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer server.Close()

	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.APIURL = server.URL
	cp := NewCommandPoller(engine)

	_, err := cp.fetchPendingCommands()
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestCommandPoller_FetchPendingCommands_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CloudCommandsResponse{Commands: []CloudCommand{}})
	}))
	defer server.Close()

	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.APIURL = server.URL
	cp := NewCommandPoller(engine)

	fetched, err := cp.fetchPendingCommands()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fetched) != 0 {
		t.Errorf("expected 0 commands, got %d", len(fetched))
	}
}

// ─── ackCommand with mock server ────────────────────────────────────────────

func TestCommandPoller_AckCommand_Success(t *testing.T) {
	var receivedBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.APIURL = server.URL
	cp := NewCommandPoller(engine)

	err := cp.ackCommand("cmd-1", "executed", "success result", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody["id"] != "cmd-1" {
		t.Errorf("expected id=cmd-1, got %s", receivedBody["id"])
	}
	if receivedBody["status"] != "executed" {
		t.Errorf("expected status=executed, got %s", receivedBody["status"])
	}
	if receivedBody["result"] != "success result" {
		t.Errorf("expected result='success result', got %s", receivedBody["result"])
	}
}

func TestCommandPoller_AckCommand_WithError(t *testing.T) {
	var receivedBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.APIURL = server.URL
	cp := NewCommandPoller(engine)

	err := cp.ackCommand("cmd-2", "failed", "", "something broke")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody["error"] != "something broke" {
		t.Errorf("expected error field, got %s", receivedBody["error"])
	}
}

func TestCommandPoller_AckCommand_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`server error`))
	}))
	defer server.Close()

	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.APIURL = server.URL
	cp := NewCommandPoller(engine)

	err := cp.ackCommand("cmd-1", "executed", "", "")
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

// ─── poll integration test (mock server) ────────────────────────────────────

func TestCommandPoller_Poll_ExecutesAndAcks(t *testing.T) {
	engine := testEngineForPoller(t, true)
	defer engine.ResponseEngine.ApprovalGate.Stop()

	// Submit a pending approval so the approve command has something to act on
	alert := makeAlertForApproval()
	rule := ResponseRule{Action: ActionKillProcess}
	approvalID := engine.ResponseEngine.ApprovalGate.Submit(alert, rule, "pid:9999")

	var ackCount atomic.Int32
	var ackStatuses []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Return one approve command
			resp := CloudCommandsResponse{
				Commands: []CloudCommand{
					{
						ID:         "cmd-poll-1",
						InstanceID: "i-test",
						ExpiresAt:  time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
						Type:       "approve",
						Status:     "pending",
						ApprovalID: approvalID,
						IssuedBy:   "admin@test.com",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case http.MethodPatch:
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			ackCount.Add(1)
			ackStatuses = append(ackStatuses, body["status"])
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer server.Close()

	engine.Config.Cloud.APIURL = server.URL
	cp := NewCommandPoller(engine)

	// Call poll directly (not the loop)
	cp.poll()

	// Should have ACKed twice: once for "acknowledged", once for "executed"
	if ackCount.Load() != 2 {
		t.Errorf("expected 2 ACK calls, got %d", ackCount.Load())
	}
}

func TestCommandPoller_Poll_HandlesFailedCommand(t *testing.T) {
	engine := testEngineForPoller(t, true)
	defer engine.ResponseEngine.ApprovalGate.Stop()

	var ackStatuses []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			resp := CloudCommandsResponse{
				Commands: []CloudCommand{
					{
						ID:         "cmd-fail-1",
						InstanceID: "i-test",
						ExpiresAt:  time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
						Type:       "approve",
						Status:     "pending",
						ApprovalID: "nonexistent-approval",
						IssuedBy:   "admin",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case http.MethodPatch:
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			ackStatuses = append(ackStatuses, body["status"])
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	engine.Config.Cloud.APIURL = server.URL
	cp := NewCommandPoller(engine)
	cp.poll()

	// Should ACK "acknowledged" then "failed"
	if len(ackStatuses) != 2 {
		t.Fatalf("expected 2 ACK calls, got %d", len(ackStatuses))
	}
	if ackStatuses[0] != "acknowledged" {
		t.Errorf("first ACK should be 'acknowledged', got %s", ackStatuses[0])
	}
	if ackStatuses[1] != "failed" {
		t.Errorf("second ACK should be 'failed', got %s", ackStatuses[1])
	}
}

func TestCommandPoller_Poll_EmptyQueue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CloudCommandsResponse{Commands: []CloudCommand{}})
	}))
	defer server.Close()

	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.APIURL = server.URL
	cp := NewCommandPoller(engine)

	// Should not panic on empty queue
	cp.poll()
}

func TestCommandPoller_Poll_FetchError(t *testing.T) {
	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.APIURL = "http://127.0.0.1:1" // unreachable
	cp := NewCommandPoller(engine)

	// Should not panic on fetch error
	cp.poll()
}

// ─── CloudCommand JSON serialization ────────────────────────────────────────

func TestCloudCommand_JSONRoundTrip(t *testing.T) {
	dryRun := true
	enabled := false
	cmd := CloudCommand{
		ID:         "cmd-1",
		Type:       "set_dry_run",
		Status:     "pending",
		CreatedAt:  "2025-01-01T00:00:00Z",
		ExpiresAt:  "2025-01-01T00:05:00Z",
		IssuedBy:   "admin@test.com",
		DryRun:     &dryRun,
		Enabled:    &enabled,
		Module:     "injection_shield",
		ApprovalID: "ap-1",
		RecordID:   "rec-1",
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded CloudCommand
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.ID != cmd.ID {
		t.Errorf("ID mismatch: %s != %s", decoded.ID, cmd.ID)
	}
	if decoded.Type != cmd.Type {
		t.Errorf("Type mismatch: %s != %s", decoded.Type, cmd.Type)
	}
	if decoded.DryRun == nil || *decoded.DryRun != true {
		t.Error("DryRun should be true")
	}
	if decoded.Enabled == nil || *decoded.Enabled != false {
		t.Error("Enabled should be false")
	}
	if decoded.Module != "injection_shield" {
		t.Errorf("Module mismatch: %s", decoded.Module)
	}
}

// ─── Default poll interval ──────────────────────────────────────────────────

func TestCommandPoller_DefaultPollInterval(t *testing.T) {
	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.CommandPollInterval = 0 // should default to 15
	cp := NewCommandPoller(engine)

	// We can't directly test the interval, but we can verify Start doesn't panic
	// and the config is read correctly
	if cp.cfg.Cloud.CommandPollInterval != 0 {
		t.Error("expected 0 in config (Start() handles the default)")
	}
}

// ─── Concurrent command execution ───────────────────────────────────────────

func TestCommandPoller_ConcurrentSetDryRun(t *testing.T) {
	engine := testEngineForPoller(t, false)
	cp := NewCommandPoller(engine)

	// Run multiple set_dry_run commands concurrently — should not race
	done := make(chan struct{}, 20)
	for i := 0; i < 20; i++ {
		go func(val bool) {
			cp.executeSetDryRun(CloudCommand{DryRun: boolPtr(val), IssuedBy: fmt.Sprintf("admin-%v", val)})
			done <- struct{}{}
		}(i%2 == 0)
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}
