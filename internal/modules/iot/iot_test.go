package iot

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

type capturingPipeline struct {
	pipeline *core.AlertPipeline
	mu       sync.Mutex
	alerts   []*core.Alert
}

func makeCapturingPipeline() *capturingPipeline {
	cp := &capturingPipeline{}
	cp.pipeline = core.NewAlertPipeline(zerolog.Nop(), 10000)
	cp.pipeline.AddHandler(func(a *core.Alert) {
		cp.mu.Lock()
		cp.alerts = append(cp.alerts, a)
		cp.mu.Unlock()
	})
	return cp
}

func (cp *capturingPipeline) count() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.alerts)
}

func (cp *capturingPipeline) last() *core.Alert {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.alerts) == 0 {
		return nil
	}
	return cp.alerts[len(cp.alerts)-1]
}

func (cp *capturingPipeline) alertTitles() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	titles := make([]string, len(cp.alerts))
	for i, a := range cp.alerts {
		titles[i] = a.Title
	}
	return titles
}

func (cp *capturingPipeline) hasAlertType(alertType string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, a := range cp.alerts {
		if a.Type == alertType {
			return true
		}
	}
	return false
}

func startedModule(t *testing.T) *Shield {
	t.Helper()
	s := New()
	cfg := core.DefaultConfig()
	if err := s.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Shield.Start() error: %v", err)
	}
	return s
}

func startedModuleWithPipeline(t *testing.T, cp *capturingPipeline) *Shield {
	t.Helper()
	s := New()
	cfg := core.DefaultConfig()
	if err := s.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Shield.Start() error: %v", err)
	}
	return s
}

// ─── Module Interface ─────────────────────────────────────────────────────────

func TestShield_Name(t *testing.T) {
	s := New()
	if s.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", s.Name(), ModuleName)
	}
}

func TestShield_Description(t *testing.T) {
	s := New()
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestShield_Start_Stop(t *testing.T) {
	s := New()
	cfg := core.DefaultConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.Start(ctx, nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if s.inventory == nil {
		t.Error("inventory should be initialized after Start")
	}
	if s.anomalyDet == nil {
		t.Error("anomalyDet should be initialized after Start")
	}
	if s.behaviorMon == nil {
		t.Error("behaviorMon should be initialized after Start")
	}
	if s.otValidator == nil {
		t.Error("otValidator should be initialized after Start")
	}
	if s.credScanner == nil {
		t.Error("credScanner should be initialized after Start")
	}
	if s.fwIntegrity == nil {
		t.Error("fwIntegrity should be initialized after Start")
	}
	if s.segEnforcer == nil {
		t.Error("segEnforcer should be initialized after Start")
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

// ─── DeviceInventory ──────────────────────────────────────────────────────────

func TestDeviceInventory_Register_NewDevice(t *testing.T) {
	inv := NewDeviceInventory()
	result := inv.Register("dev-1", "camera", "AA:BB:CC:DD:EE:FF", "1.0.0", "hikvision", "10.0.0.1")
	if !result.IsNew {
		t.Error("expected IsNew=true for first registration")
	}
	if result.IPChanged {
		t.Error("expected IPChanged=false for first registration")
	}
	if result.FirmwareDowngrade {
		t.Error("expected FirmwareDowngrade=false for first registration")
	}
}

func TestDeviceInventory_Register_ExistingDevice(t *testing.T) {
	inv := NewDeviceInventory()
	inv.Register("dev-1", "camera", "AA:BB:CC:DD:EE:FF", "1.0.0", "hikvision", "10.0.0.1")
	result := inv.Register("dev-1", "camera", "AA:BB:CC:DD:EE:FF", "1.0.0", "hikvision", "10.0.0.1")
	if result.IsNew {
		t.Error("expected IsNew=false for existing device")
	}
}

func TestDeviceInventory_Register_IPChange(t *testing.T) {
	inv := NewDeviceInventory()
	inv.Register("dev-1", "camera", "AA:BB:CC:DD:EE:FF", "1.0.0", "hikvision", "10.0.0.1")
	result := inv.Register("dev-1", "camera", "AA:BB:CC:DD:EE:FF", "1.0.0", "hikvision", "10.0.0.2")
	if !result.IPChanged {
		t.Error("expected IPChanged=true when IP changes")
	}
	if result.PreviousIP != "10.0.0.1" {
		t.Errorf("PreviousIP = %q, want %q", result.PreviousIP, "10.0.0.1")
	}
}

func TestDeviceInventory_Register_FirmwareDowngrade(t *testing.T) {
	inv := NewDeviceInventory()
	inv.Register("dev-1", "camera", "AA:BB:CC:DD:EE:FF", "2.0.0", "hikvision", "10.0.0.1")
	result := inv.Register("dev-1", "camera", "AA:BB:CC:DD:EE:FF", "1.0.0", "hikvision", "10.0.0.1")
	if !result.FirmwareDowngrade {
		t.Error("expected FirmwareDowngrade=true when firmware version decreases")
	}
	if result.PreviousFirmware != "2.0.0" {
		t.Errorf("PreviousFirmware = %q, want %q", result.PreviousFirmware, "2.0.0")
	}
}

func TestDeviceInventory_Register_FirmwareUpgrade(t *testing.T) {
	inv := NewDeviceInventory()
	inv.Register("dev-1", "camera", "AA:BB:CC:DD:EE:FF", "1.0.0", "hikvision", "10.0.0.1")
	result := inv.Register("dev-1", "camera", "AA:BB:CC:DD:EE:FF", "2.0.0", "hikvision", "10.0.0.1")
	if result.FirmwareDowngrade {
		t.Error("expected FirmwareDowngrade=false for firmware upgrade")
	}
}

// ─── isVersionDowngrade ───────────────────────────────────────────────────────

func TestIsVersionDowngrade(t *testing.T) {
	tests := []struct {
		old, new string
		want     bool
	}{
		{"2.0.0", "1.0.0", true},
		{"1.0.0", "2.0.0", false},
		{"1.0.0", "1.0.0", false},
		{"1.2.3", "1.2.2", true},
		{"1.2.3", "1.2.4", false},
		{"2.0", "1.9", true},
		{"1.0", "1.1", false},
		{"10.0.0", "9.9.9", true},
	}
	for _, tc := range tests {
		got := isVersionDowngrade(tc.old, tc.new)
		if got != tc.want {
			t.Errorf("isVersionDowngrade(%q, %q) = %v, want %v", tc.old, tc.new, got, tc.want)
		}
	}
}

// ─── ProtocolAnomalyDetector ──────────────────────────────────────────────────

func TestProtocolAnomalyDetector_RateAnomaly(t *testing.T) {
	d := NewProtocolAnomalyDetector()
	var findings []ProtoFinding
	for i := 0; i < 510; i++ {
		findings = d.Check("modbus", "", "10.0.0.1", 0, 0)
	}
	found := false
	for _, f := range findings {
		if f.AlertType == "protocol_flood" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected protocol_flood finding after 500+ messages")
	}
}

func TestProtocolAnomalyDetector_PayloadSizeAnomaly(t *testing.T) {
	d := NewProtocolAnomalyDetector()
	// Build baseline with small payloads
	for i := 0; i < 110; i++ {
		d.Check("mqtt", "", "10.0.0.1", 100, 0)
	}
	// Send a huge payload
	findings := d.Check("mqtt", "", "10.0.0.1", 5000, 0)
	found := false
	for _, f := range findings {
		if f.AlertType == "abnormal_payload_size" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected abnormal_payload_size finding for oversized payload")
	}
}

func TestProtocolAnomalyDetector_ModbusWriteCommand(t *testing.T) {
	d := NewProtocolAnomalyDetector()
	dangerousFCs := []int{5, 6, 8, 15, 16, 22, 23, 43}
	for _, fc := range dangerousFCs {
		findings := d.Check("modbus", "", "10.0.0.1", 0, fc)
		found := false
		for _, f := range findings {
			if f.AlertType == "modbus_write_command" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected modbus_write_command for FC %d", fc)
		}
	}
}

func TestProtocolAnomalyDetector_ModbusBroadcast(t *testing.T) {
	d := NewProtocolAnomalyDetector()
	findings := d.Check("modbus", "unit_id=0", "10.0.0.1", 0, 1)
	found := false
	for _, f := range findings {
		if f.AlertType == "modbus_broadcast" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected modbus_broadcast finding for unit_id=0")
	}
}

func TestProtocolAnomalyDetector_DNP3ControlCommand(t *testing.T) {
	d := NewProtocolAnomalyDetector()
	criticalFCs := []int{13, 14, 18}
	for _, fc := range criticalFCs {
		findings := d.Check("dnp3", "", "10.0.0.1", 0, fc)
		found := false
		for _, f := range findings {
			if f.AlertType == "dnp3_control_command" && f.Severity == core.SeverityCritical {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected critical dnp3_control_command for FC %d", fc)
		}
	}
}

func TestProtocolAnomalyDetector_OPCUASuspiciousOps(t *testing.T) {
	d := NewProtocolAnomalyDetector()
	ops := []string{"write_value", "call_method", "add_nodes", "delete_nodes"}
	for _, op := range ops {
		findings := d.Check("opcua", op, "10.0.0.1", 0, 0)
		found := false
		for _, f := range findings {
			if f.AlertType == "opcua_suspicious_op" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected opcua_suspicious_op for payload %q", op)
		}
	}
}

func TestProtocolAnomalyDetector_BACnetControlCommand(t *testing.T) {
	d := NewProtocolAnomalyDetector()
	findings := d.Check("bacnet", "", "10.0.0.1", 0, 21)
	found := false
	for _, f := range findings {
		if f.AlertType == "bacnet_control_command" && f.Severity == core.SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected critical bacnet_control_command for FC 21 (ReinitializeDevice)")
	}
}

func TestProtocolAnomalyDetector_MQTTWildcard(t *testing.T) {
	d := NewProtocolAnomalyDetector()
	findings := d.Check("mqtt", "subscribe topic #", "10.0.0.1", 0, 0)
	found := false
	for _, f := range findings {
		if f.AlertType == "mqtt_wildcard_sub" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected mqtt_wildcard_sub for wildcard subscription")
	}
}

func TestProtocolAnomalyDetector_MQTTSysTopic(t *testing.T) {
	d := NewProtocolAnomalyDetector()
	findings := d.Check("mqtt", "$SYS/broker/info", "10.0.0.1", 0, 0)
	found := false
	for _, f := range findings {
		if f.AlertType == "mqtt_sys_topic" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected mqtt_sys_topic for $SYS access")
	}
}

func TestProtocolAnomalyDetector_CoAPDiscovery(t *testing.T) {
	d := NewProtocolAnomalyDetector()
	findings := d.Check("coap", ".well-known/core", "10.0.0.1", 0, 0)
	found := false
	for _, f := range findings {
		if f.AlertType == "coap_discovery" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected coap_discovery for .well-known/core")
	}
}

// ─── OTCommandValidator ───────────────────────────────────────────────────────

func TestOTCommandValidator_DangerousCommand_Blocked(t *testing.T) {
	v := NewOTCommandValidator()
	protocols := []struct {
		proto   string
		command string
	}{
		{"modbus", "restart device"},
		{"modbus", "factory default reset"},
		{"dnp3", "cold restart"},
		{"dnp3", "stop application"},
		{"opcua", "delete node xyz"},
		{"bacnet", "reinitialize device"},
	}
	for _, tc := range protocols {
		result := v.Validate(tc.proto, tc.command, 0, "", "", "operator1", "10.0.0.1")
		if !result.Blocked {
			t.Errorf("expected Blocked=true for %s command %q", tc.proto, tc.command)
		}
	}
}

func TestOTCommandValidator_SafeRangeViolation(t *testing.T) {
	v := NewOTCommandValidator()
	result := v.Validate("modbus", "set", 6, "temperature_sensor", "999", "operator1", "10.0.0.1")
	if !result.OutOfRange {
		t.Error("expected OutOfRange=true for temperature=999")
	}
}

func TestOTCommandValidator_SafeRangeOK(t *testing.T) {
	v := NewOTCommandValidator()
	result := v.Validate("modbus", "set", 6, "temperature_sensor", "25", "operator1", "10.0.0.1")
	if result.OutOfRange {
		t.Error("expected OutOfRange=false for temperature=25")
	}
	if result.Blocked {
		t.Error("expected Blocked=false for normal set command")
	}
}

func TestOTCommandValidator_ModbusCoil0Suspicious(t *testing.T) {
	v := NewOTCommandValidator()
	result := v.Validate("modbus", "write", 5, "coil_0", "1", "operator1", "10.0.0.1")
	if !result.Suspicious {
		t.Error("expected Suspicious=true for write to coil_0")
	}
}

func TestOTCommandValidator_DNP3DirectOperateNoAck(t *testing.T) {
	v := NewOTCommandValidator()
	result := v.Validate("dnp3", "operate", 4, "valve", "open", "operator1", "10.0.0.1")
	if !result.Suspicious {
		t.Error("expected Suspicious=true for DNP3 FC 4 (Direct Operate No Ack)")
	}
}

// ─── CredentialScanner ────────────────────────────────────────────────────────

func TestCredentialScanner_VendorDefaults(t *testing.T) {
	cs := NewCredentialScanner()
	tests := []struct {
		user, pass, devType, vendor string
		wantMatch                   bool
	}{
		{"admin", "12345", "camera", "hikvision", true},
		{"admin", "admin", "camera", "dahua", true},
		{"root", "pass", "camera", "axis", true},
		{"admin", "cisco", "switch", "cisco", true},
		{"admin", "strongP@ss!", "camera", "hikvision", false},
	}
	for _, tc := range tests {
		finding := cs.Check(tc.user, tc.pass, tc.devType, tc.vendor)
		if tc.wantMatch && finding == "" {
			t.Errorf("expected match for %s/%s on %s %s", tc.user, tc.pass, tc.vendor, tc.devType)
		}
		if !tc.wantMatch && finding != "" {
			t.Errorf("unexpected match for %s/%s on %s %s: %s", tc.user, tc.pass, tc.vendor, tc.devType, finding)
		}
	}
}

func TestCredentialScanner_GenericDefaults(t *testing.T) {
	cs := NewCredentialScanner()
	tests := []struct {
		user, pass string
		wantMatch  bool
	}{
		{"admin", "admin", true},
		{"admin", "password", true},
		{"root", "root", true},
		{"admin", "", true},
		{"pi", "raspberry", true},
		{"admin", "v3ryStr0ngP@ss!", false},
	}
	for _, tc := range tests {
		finding := cs.Check(tc.user, tc.pass, "generic", "unknown")
		if tc.wantMatch && finding == "" {
			t.Errorf("expected match for generic %s/%s", tc.user, tc.pass)
		}
		if !tc.wantMatch && finding != "" {
			t.Errorf("unexpected match for generic %s/%s: %s", tc.user, tc.pass, finding)
		}
	}
}

func TestCredentialScanner_WeakPasswords(t *testing.T) {
	cs := NewCredentialScanner()
	finding := cs.Check("customuser", "qwerty", "device", "unknown")
	if finding == "" {
		t.Error("expected weak password detection for 'qwerty'")
	}
}

func TestCredentialScanner_EmptyPassword(t *testing.T) {
	cs := NewCredentialScanner()
	finding := cs.Check("someuser", "", "device", "unknown_vendor")
	if finding == "" {
		t.Error("expected empty password detection")
	}
}

// ─── FirmwareIntegrityDB ──────────────────────────────────────────────────────

func TestFirmwareIntegrityDB_KnownGood(t *testing.T) {
	db := NewFirmwareIntegrityDB()
	db.RegisterKnownGood("hikvision", "DS-2CD2032", "abc123")

	result := db.RecordFirmware("dev-1", "hikvision", "DS-2CD2032", "1.0", "abc123")
	if result.UnknownFirmware {
		t.Error("expected UnknownFirmware=false for known-good hash")
	}

	result = db.RecordFirmware("dev-2", "hikvision", "DS-2CD2032", "1.0", "unknown_hash")
	if !result.UnknownFirmware {
		t.Error("expected UnknownFirmware=true for unknown hash")
	}
}

func TestFirmwareIntegrityDB_Vulnerable(t *testing.T) {
	db := NewFirmwareIntegrityDB()
	db.RegisterVulnerable("vuln_hash_123", "CVE-2024-1234: Remote code execution")

	result := db.RecordFirmware("dev-1", "vendor", "model", "1.0", "vuln_hash_123")
	if !result.KnownVulnerable {
		t.Error("expected KnownVulnerable=true for vulnerable hash")
	}
	if result.VulnDescription == "" {
		t.Error("expected VulnDescription to be set")
	}
}

// ─── SegmentationEnforcer ─────────────────────────────────────────────────────

func TestSegmentationEnforcer_BlockedFlows(t *testing.T) {
	se := NewSegmentationEnforcer(map[string]interface{}{})
	tests := []struct {
		src, dst string
		blocked  bool
	}{
		{"iot", "corporate", true},
		{"ot", "internet", true},
		{"scada", "internet", true},
		{"guest", "ot", true},
		{"corporate", "dmz", false},
		{"iot", "iot", false}, // same zone
	}
	for _, tc := range tests {
		v := se.Check(tc.src, tc.dst, "10.0.0.1", "10.0.1.1", 443, "tcp")
		if tc.blocked && v == nil {
			t.Errorf("expected violation for %s->%s", tc.src, tc.dst)
		}
		if !tc.blocked && v != nil {
			t.Errorf("unexpected violation for %s->%s: %s", tc.src, tc.dst, v.Reason)
		}
	}
}

func TestSegmentationEnforcer_CriticalZoneSeverity(t *testing.T) {
	se := NewSegmentationEnforcer(map[string]interface{}{})
	v := se.Check("guest", "ot", "10.0.0.1", "10.0.1.1", 502, "tcp")
	if v == nil {
		t.Fatal("expected violation for guest->ot")
	}
	if v.Severity != core.SeverityCritical {
		t.Errorf("severity = %v, want Critical for traffic to critical zone", v.Severity)
	}
}

func TestSegmentationEnforcer_PortRestrictions(t *testing.T) {
	se := NewSegmentationEnforcer(map[string]interface{}{})
	// corporate->iot only allows 443 and 8443
	v := se.Check("corporate", "iot", "10.0.0.1", "10.0.1.1", 22, "tcp")
	if v == nil {
		t.Error("expected violation for corporate->iot on port 22")
	}
	v = se.Check("corporate", "iot", "10.0.0.1", "10.0.1.1", 443, "tcp")
	if v != nil {
		t.Error("unexpected violation for corporate->iot on port 443")
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestShield_HandleEvent_NewDevice(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "device_connect", core.SeverityInfo, "device connected")
	ev.Details["device_id"] = "cam-001"
	ev.Details["device_type"] = "camera"
	ev.Details["mac_address"] = "AA:BB:CC:DD:EE:FF"
	ev.Details["firmware_version"] = "1.0.0"
	ev.Details["vendor"] = "hikvision"
	ev.SourceIP = "10.0.0.50"

	if err := s.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}

	if cp.count() == 0 {
		t.Error("expected alert for new device detection")
	}
}

func TestShield_HandleEvent_DefaultCredentials(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "device_connect", core.SeverityInfo, "device connected")
	ev.Details["device_id"] = "cam-002"
	ev.Details["device_type"] = "camera"
	ev.Details["vendor"] = "hikvision"
	ev.Details["username"] = "admin"
	ev.Details["password"] = "12345"
	ev.SourceIP = "10.0.0.51"

	s.HandleEvent(ev)

	titles := cp.alertTitles()
	foundCred := false
	for _, title := range titles {
		if title == "Default/Weak Credentials Detected" {
			foundCred = true
			break
		}
	}
	if !foundCred {
		t.Errorf("expected 'Default/Weak Credentials Detected' alert, got: %v", titles)
	}
}

func TestShield_HandleEvent_FirmwareIntegrityViolation(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "firmware_check", core.SeverityInfo, "firmware check")
	ev.Details["device_id"] = "plc-001"
	ev.Details["firmware_version"] = "2.0"
	ev.Details["firmware_hash"] = "abc123"
	ev.Details["expected_hash"] = "def456"
	ev.SourceIP = "10.0.0.100"

	s.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Firmware Integrity Violation" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Firmware Integrity Violation' alert, got: %v", titles)
	}
}

func TestShield_HandleEvent_OTCommandBlocked(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "ot_command", core.SeverityInfo, "OT command")
	ev.Details["protocol"] = "modbus"
	ev.Details["command"] = "restart device"
	ev.Details["function_code"] = 8
	ev.Details["target"] = "plc-1"
	ev.Details["operator"] = "operator1"
	ev.SourceIP = "10.0.0.200"

	s.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Dangerous OT Command Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Dangerous OT Command Detected' alert, got: %v", titles)
	}
}

func TestShield_HandleEvent_SegmentationViolation(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "iot_network", core.SeverityInfo, "network flow")
	ev.Details["device_id"] = "sensor-1"
	ev.Details["src_zone"] = "iot"
	ev.Details["dst_zone"] = "corporate"
	ev.Details["dest_port"] = 22
	ev.Details["protocol"] = "tcp"
	ev.SourceIP = "10.0.0.10"
	ev.DestIP = "10.1.0.50"

	s.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Network Segmentation Violation" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Network Segmentation Violation' alert, got: %v", titles)
	}
}

func TestShield_HandleEvent_ProtocolAnomaly(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	// Send a modbus broadcast
	ev := core.NewSecurityEvent("test", "protocol_message", core.SeverityInfo, "protocol msg")
	ev.Details["protocol"] = "modbus"
	ev.Details["payload"] = "unit_id=0 broadcast"
	ev.SourceIP = "10.0.0.30"

	s.HandleEvent(ev)

	if cp.count() == 0 {
		t.Error("expected alert for modbus broadcast")
	}
}

func TestShield_HandleEvent_UnknownEventType(t *testing.T) {
	s := startedModule(t)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "unknown_type", core.SeverityInfo, "unknown")
	if err := s.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() should not error on unknown event type: %v", err)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func TestParseFloat(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"3.14", 3.14},
		{"0", 0},
		{"-10.5", -10.5},
		{"abc", 0},
	}
	for _, tc := range tests {
		got := parseFloat(tc.input)
		if got != tc.want {
			t.Errorf("parseFloat(%q) = %f, want %f", tc.input, got, tc.want)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	// All same bytes = 0 entropy
	data := make([]byte, 100)
	if e := ShannonEntropy(data); e != 0 {
		t.Errorf("ShannonEntropy(all zeros) = %f, want 0", e)
	}

	// Empty = 0
	if e := ShannonEntropy(nil); e != 0 {
		t.Errorf("ShannonEntropy(nil) = %f, want 0", e)
	}

	// Two equally distributed bytes = 1 bit
	data2 := make([]byte, 100)
	for i := range data2 {
		data2[i] = byte(i % 2)
	}
	e := ShannonEntropy(data2)
	if e < 0.9 || e > 1.1 {
		t.Errorf("ShannonEntropy(50/50) = %f, want ~1.0", e)
	}
}

func TestGetIoTMitigations(t *testing.T) {
	types := []string{
		"default_credentials", "firmware_integrity", "ot_command_blocked",
		"segmentation_violation", "protocol_anomaly", "unknown_type",
	}
	for _, at := range types {
		m := getIoTMitigations(at)
		if len(m) == 0 {
			t.Errorf("getIoTMitigations(%q) returned empty", at)
		}
	}
}

// ─── DeviceBehaviorMonitor ────────────────────────────────────────────────────

func TestDeviceBehaviorMonitor_NewDevice(t *testing.T) {
	bm := NewDeviceBehaviorMonitor(map[string]interface{}{})
	anomaly := bm.RecordActivity("dev-1", "camera", "mqtt", "10.0.0.1")
	if anomaly.UnusualProtocol {
		t.Error("first activity should not trigger UnusualProtocol")
	}
	if anomaly.ActivitySpike {
		t.Error("first activity should not trigger ActivitySpike")
	}
}

func TestDeviceBehaviorMonitor_CustomThreshold(t *testing.T) {
	bm := NewDeviceBehaviorMonitor(map[string]interface{}{
		"behavior_spike_threshold": 5.0,
	})
	if bm.spikeThreshold != 5.0 {
		t.Errorf("spikeThreshold = %f, want 5.0", bm.spikeThreshold)
	}
}

// ─── Compile-time interface check ─────────────────────────────────────────────

var _ core.Module = (*Shield)(nil)

// ─── CleanupLoop cancellation ─────────────────────────────────────────────────

func TestDeviceInventory_CleanupLoop_Cancellation(t *testing.T) {
	inv := NewDeviceInventory()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		inv.CleanupLoop(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("CleanupLoop did not exit after context cancellation")
	}
}

// ─── New Vendor Default Credential Tests ──────────────────────────────────────

func TestCredentialScanner_DellDefaults(t *testing.T) {
	cs := NewCredentialScanner()
	result := cs.Check("root", "calvin", "server", "dell")
	if result == "" {
		t.Error("expected credential detection for Dell root/calvin")
	}
	result = cs.Check("recoverpoint", "boxmgmt", "appliance", "dell")
	if result == "" {
		t.Error("expected credential detection for Dell recoverpoint/boxmgmt (CVE-2026-22769)")
	}
}

func TestCredentialScanner_HPEDefaults(t *testing.T) {
	cs := NewCredentialScanner()
	result := cs.Check("root", "hpinvent", "server", "hpe")
	if result == "" {
		t.Error("expected credential detection for HPE root/hpinvent")
	}
}

func TestCredentialScanner_LenovoDefaults(t *testing.T) {
	cs := NewCredentialScanner()
	result := cs.Check("USERID", "PASSW0RD", "server", "lenovo")
	if result == "" {
		t.Error("expected credential detection for Lenovo USERID/PASSW0RD")
	}
}

func TestCredentialScanner_SupermicroDefaults(t *testing.T) {
	cs := NewCredentialScanner()
	result := cs.Check("ADMIN", "ADMIN", "server", "supermicro")
	if result == "" {
		t.Error("expected credential detection for Supermicro ADMIN/ADMIN")
	}
}

// ===========================================================================
// 2025-2026: Persistent Firmware Implant Detection Tests
// ===========================================================================

func TestShield_HandleEvent_BootloaderRootkit(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "firmware_boot", core.SeverityInfo, "boot event")
	ev.Details["device_id"] = "plc-100"
	ev.Details["bootloader"] = "modified-uboot"
	ev.Details["persistence_method"] = "flash_rewrite"
	ev.SourceIP = "10.0.0.100"

	if err := s.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() error: %v", err)
	}
	if !cp.hasAlertType("bootloader_rootkit") {
		t.Error("expected bootloader_rootkit alert")
	}
}

func TestShield_HandleEvent_PersistentFirmwareImplant(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "firmware_flash", core.SeverityInfo, "flash event")
	ev.Details["device_id"] = "router-001"
	ev.Details["implant_type"] = "persistent_backdoor"
	ev.Details["survives_factory_reset"] = "true"
	ev.Details["persistence_method"] = "u-boot_env_rewrite"
	ev.SourceIP = "10.0.0.101"

	s.HandleEvent(ev)
	if !cp.hasAlertType("persistent_firmware_implant") {
		t.Error("expected persistent_firmware_implant alert")
	}
}

func TestShield_HandleEvent_BootPartitionWrite(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "firmware_flash", core.SeverityInfo, "flash write")
	ev.Details["device_id"] = "switch-001"
	ev.Details["implant_type"] = "boot_partition_write"
	ev.SourceIP = "10.0.0.102"

	s.HandleEvent(ev)
	if !cp.hasAlertType("boot_partition_write") {
		t.Error("expected boot_partition_write alert")
	}
}

func TestShield_HandleEvent_SecureBootBypass(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "firmware_boot", core.SeverityInfo, "boot event")
	ev.Details["device_id"] = "gateway-001"
	ev.Details["implant_type"] = "secure_boot_bypass"
	ev.Details["bootloader"] = "unsigned_custom"
	ev.SourceIP = "10.0.0.103"

	s.HandleEvent(ev)
	if !cp.hasAlertType("secure_boot_bypass") {
		t.Error("expected secure_boot_bypass alert")
	}
}

// ===========================================================================
// 2025-2026: ICS Wiper/Destructive Malware Detection Tests
// ===========================================================================

func TestShield_HandleEvent_PLCLogicWipe(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "ot_wiper", core.SeverityInfo, "wiper event")
	ev.Details["device_id"] = "plc-200"
	ev.Details["action"] = "logic_wipe"
	ev.Details["target"] = "main_program"
	ev.Details["target_protocol"] = "modbus"
	ev.SourceIP = "10.0.0.200"

	s.HandleEvent(ev)
	if !cp.hasAlertType("plc_logic_wipe") {
		t.Error("expected plc_logic_wipe alert")
	}
}

func TestShield_HandleEvent_SafetySystemTamper(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "ics_destructive", core.SeverityInfo, "destructive event")
	ev.Details["device_id"] = "sis-001"
	ev.Details["action"] = "disable"
	ev.Details["target"] = "safety_interlock_system"
	ev.SourceIP = "10.0.0.201"

	s.HandleEvent(ev)
	if !cp.hasAlertType("safety_system_tamper") {
		t.Error("expected safety_system_tamper alert")
	}
}

func TestShield_HandleEvent_HMITamper(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "ics_destructive", core.SeverityInfo, "hmi event")
	ev.Details["device_id"] = "hmi-001"
	ev.Details["action"] = "hmi_overwrite"
	ev.SourceIP = "10.0.0.202"

	s.HandleEvent(ev)
	if !cp.hasAlertType("hmi_tamper") {
		t.Error("expected hmi_tamper alert")
	}
}

func TestShield_HandleEvent_OTConfigWipe(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "ot_wiper", core.SeverityInfo, "config wipe")
	ev.Details["device_id"] = "scada-001"
	ev.Details["action"] = "config_wipe"
	ev.Details["target"] = "historian_database"
	ev.Details["process_name"] = "malware.exe"
	ev.SourceIP = "10.0.0.203"

	s.HandleEvent(ev)
	if !cp.hasAlertType("ot_config_wipe") {
		t.Error("expected ot_config_wipe alert")
	}
}

func TestShield_HandleEvent_GenericICSWiper(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "ot_wiper", core.SeverityInfo, "wiper")
	ev.Details["device_id"] = "rtu-001"
	ev.Details["wiper_type"] = "voltruptor"
	ev.Details["action"] = "destroy"
	ev.Details["target"] = "firmware"
	ev.Details["target_protocol"] = "dnp3"
	ev.Details["process_name"] = "unknown"
	ev.SourceIP = "10.0.0.204"

	s.HandleEvent(ev)
	if !cp.hasAlertType("ics_wiper") {
		t.Error("expected ics_wiper alert")
	}
}

// ===========================================================================
// 2025-2026: Coordinated Multi-Protocol OT Attack Detection Tests
// ===========================================================================

func TestShield_HandleEvent_MultiProtocolAttack(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "ot_coordinated", core.SeverityInfo, "coordinated attack")
	ev.Details["protocols"] = "modbus,dnp3,opcua"
	ev.Details["attack_phase"] = "active_exploitation"
	ev.Details["target_count"] = 5
	ev.Details["device_id"] = "plc-300"
	ev.SourceIP = "10.0.0.300"

	s.HandleEvent(ev)
	if !cp.hasAlertType("multi_protocol_attack") {
		t.Error("expected multi_protocol_attack alert")
	}
}

func TestShield_HandleEvent_OTAttackHandoff(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "multi_protocol_attack", core.SeverityInfo, "handoff")
	ev.Details["attack_phase"] = "handoff"
	ev.Details["device_id"] = "plc-301"
	ev.Details["threat_group"] = "SYLVANITE"
	ev.SourceIP = "10.0.0.301"

	s.HandleEvent(ev)
	if !cp.hasAlertType("ot_attack_handoff") {
		t.Error("expected ot_attack_handoff alert")
	}
}

func TestShield_HandleEvent_MassOTTargeting(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "ot_coordinated", core.SeverityInfo, "mass targeting")
	ev.Details["target_count"] = 10
	ev.Details["attack_phase"] = "reconnaissance"
	ev.Details["device_id"] = "plc-302"
	ev.SourceIP = "10.0.0.302"

	s.HandleEvent(ev)
	if !cp.hasAlertType("mass_ot_targeting") {
		t.Error("expected mass_ot_targeting alert")
	}
}

func TestShield_HandleEvent_OTDestructivePhase(t *testing.T) {
	cp := makeCapturingPipeline()
	s := startedModuleWithPipeline(t, cp)
	defer s.Stop()

	ev := core.NewSecurityEvent("test", "ot_coordinated", core.SeverityInfo, "destructive phase")
	ev.Details["attack_phase"] = "destructive"
	ev.Details["target_count"] = 2
	ev.Details["device_id"] = "plc-303"
	ev.SourceIP = "10.0.0.303"

	s.HandleEvent(ev)
	if !cp.hasAlertType("ot_destructive_phase") {
		t.Error("expected ot_destructive_phase alert")
	}
}

// ===========================================================================
// 2025-2026: New Mitigation Coverage Tests
// ===========================================================================

func TestGetIoTMitigations_FirmwareImplant(t *testing.T) {
	for _, alertType := range []string{"bootloader_rootkit", "persistent_firmware_implant", "boot_partition_write", "secure_boot_bypass"} {
		m := getIoTMitigations(alertType)
		if len(m) < 3 {
			t.Errorf("expected at least 3 mitigations for %s, got %d", alertType, len(m))
		}
	}
}

func TestGetIoTMitigations_ICSWiper(t *testing.T) {
	for _, alertType := range []string{"plc_logic_wipe", "ics_wiper", "ot_config_wipe", "safety_system_tamper", "hmi_tamper"} {
		m := getIoTMitigations(alertType)
		if len(m) < 3 {
			t.Errorf("expected at least 3 mitigations for %s, got %d", alertType, len(m))
		}
	}
}

func TestGetIoTMitigations_CoordinatedAttack(t *testing.T) {
	for _, alertType := range []string{"multi_protocol_attack", "ot_attack_handoff", "mass_ot_targeting", "ot_destructive_phase"} {
		m := getIoTMitigations(alertType)
		if len(m) < 3 {
			t.Errorf("expected at least 3 mitigations for %s, got %d", alertType, len(m))
		}
	}
}
