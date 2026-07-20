package runtime

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "runtime_watcher"

// Watcher is the Runtime Watcher module providing file integrity monitoring,
// container escape detection, privilege escalation monitoring, LOLBin detection,
// fileless malware detection, UEFI/bootkit indicators, memory injection detection,
// persistence mechanism detection, and WMI/scheduled task abuse detection.
type Watcher struct {
	logger   zerolog.Logger
	bus      *core.EventBus
	pipeline *core.AlertPipeline
	cfg      *core.Config
	ctx      context.Context
	cancel   context.CancelFunc
	fim      *FileIntegrityMonitor
	procMon  *ProcessMonitor
	rtMon    realtimeFileMonitor
}

func New() *Watcher { return &Watcher{} }

func (w *Watcher) Name() string { return ModuleName }
func (w *Watcher) Description() string {
	return "File integrity monitoring, container escape detection, privilege escalation, LOLBin detection, fileless malware, UEFI/bootkit indicators, memory injection, and persistence mechanism detection"
}
func (w *Watcher) EventTypes() []string {
	return []string{
		"file_change", "file_modified", "file_created", "file_deleted",
		"process_start", "process_exec",
		"privilege_change", "setuid", "capability_change",
		"container_event",
		"memory_injection", "process_hollowing", "dll_injection",
		"persistence_created", "scheduled_task", "wmi_subscription",
		"registry_run_key", "startup_item", "cron_job", "systemd_service",
		"firmware_event", "uefi_event", "bootloader_change",
		"fileless_execution", "powershell_exec", "wmi_exec", "mshta_exec",
		"driver_load",
	}
}

func (w *Watcher) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	w.ctx, w.cancel = context.WithCancel(ctx)
	w.bus = bus
	w.pipeline = pipeline
	w.cfg = cfg
	w.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)
	watchPaths := getStringSliceSetting(settings, "watch_paths", []string{})
	realtimeEnabled := getBoolSetting(settings, "realtime_enabled", true)
	realtimeWatchPaths := getStringSliceSetting(settings, "realtime_watch_paths", defaultEphemeralWatchPaths())
	scanInterval := getIntSetting(settings, "scan_interval_seconds", 300)
	w.fim = NewFileIntegrityMonitor(watchPaths, time.Duration(scanInterval)*time.Second)
	w.procMon = NewProcessMonitor()

	if len(watchPaths) > 0 {
		go w.fimLoop()
	}
	if realtimeEnabled && len(realtimeWatchPaths) > 0 {
		w.rtMon = newRealtimeFileMonitor(realtimeWatchPaths)
		if err := w.rtMon.Start(w.ctx, func(change FileChange) {
			w.emitFileChange(change, "realtime")
		}); err != nil {
			w.logger.Debug().Err(err).Msg("real-time runtime file monitor unavailable")
		}
	}

	w.logger.Info().
		Int("watch_paths", len(watchPaths)).
		Int("realtime_watch_paths", len(realtimeWatchPaths)).
		Int("scan_interval", scanInterval).
		Msg("runtime watcher started")
	return nil
}

func (w *Watcher) Stop() error {
	if w.cancel != nil {
		w.cancel()
	}
	if w.rtMon != nil {
		return w.rtMon.Close()
	}
	return nil
}

func (w *Watcher) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "file_change", "file_modified", "file_created", "file_deleted":
		w.handleFileEvent(event)
	case "process_start", "process_exec":
		w.handleProcessEvent(event)
	case "privilege_change", "setuid", "capability_change":
		w.handlePrivilegeEvent(event)
	case "container_event":
		w.handleContainerEvent(event)
	case "memory_injection", "process_hollowing", "dll_injection":
		w.handleMemoryInjection(event)
	case "persistence_created", "scheduled_task", "wmi_subscription",
		"registry_run_key", "startup_item", "cron_job", "systemd_service":
		w.handlePersistenceEvent(event)
	case "firmware_event", "uefi_event", "bootloader_change":
		w.handleFirmwareEvent(event)
	case "fileless_execution", "powershell_exec", "wmi_exec", "mshta_exec":
		w.handleFilelessEvent(event)
	case "driver_load":
		w.handleDriverLoad(event)
	}
	return nil
}

func (w *Watcher) handleFileEvent(event *core.SecurityEvent) {
	filePath := getStringDetail(event, "path")
	if filePath == "" {
		return
	}
	if isSensitivePath(filePath) {
		w.raiseAlert(event, core.SeverityCritical,
			"Sensitive File Modified",
			fmt.Sprintf("Critical system file modified: %s. This may indicate system compromise.", filePath),
			"sensitive_file_change")
	}
	if isSuspiciousFile(filePath) {
		w.raiseAlert(event, core.SeverityHigh,
			"Suspicious File Detected",
			fmt.Sprintf("Suspicious file detected: %s", filePath),
			"suspicious_file")
	}
}

func (w *Watcher) handleProcessEvent(event *core.SecurityEvent) {
	processName := getStringDetail(event, "process_name")
	cmdLine := getStringDetail(event, "command_line")
	parentProcess := getStringDetail(event, "parent_process")

	if processName == "" && cmdLine == "" {
		return
	}

	w.checkExecutionIntegrity(event, processName, cmdLine)

	cmdLower := strings.ToLower(cmdLine)

	// LOLBin detection — Living Off the Land Binaries
	if lolbin := w.procMon.IsLOLBin(processName, cmdLine, parentProcess); lolbin.Detected {
		w.raiseAlert(event, core.SeverityHigh,
			"Living Off the Land Binary Abuse Detected",
			fmt.Sprintf("LOLBin %q used for %s. Command: %s. Parent: %s. "+
				"Attackers use legitimate system binaries to evade detection. "+
				"MITRE ATT&CK %s.",
				processName, lolbin.Technique, truncate(cmdLine, 150),
				parentProcess, lolbin.MitreID),
			"lolbin_abuse")
	}

	// Symlink / Link-following privilege escalation detection
	// Addresses BeyondTrust LPE (CVE-2026-1731) and Fortinet FortiClient LPE
	symlinkPatterns := []string{
		"mklink", "new-item -itemtype symboliclink", "new-item -type symboliclink",
		"ln -s", "ln -sf", "junction", "linkd",
	}
	for _, pattern := range symlinkPatterns {
		if strings.Contains(cmdLower, pattern) {
			// Check if the symlink targets a sensitive path
			if isSensitiveCmdTarget(cmdLower) {
				w.raiseAlert(event, core.SeverityCritical,
					"Symlink Attack on Sensitive Path Detected",
					fmt.Sprintf("Symlink creation targeting sensitive path via %s: %s. Parent: %s. "+
						"Link-following attacks exploit path resolution to escalate privileges. "+
						"MITRE ATT&CK T1547.",
						processName, truncate(cmdLine, 200), parentProcess),
					"symlink_privilege_escalation")
				break
			}
			w.raiseAlert(event, core.SeverityMedium,
				"Symlink Creation Detected",
				fmt.Sprintf("Symlink created via %s: %s. Parent: %s. "+
					"Monitor for potential link-following privilege escalation.",
					processName, truncate(cmdLine, 200), parentProcess),
				"symlink_creation")
			break
		}
	}

	// yt-dlp argument-based command injection (CVE-2026-26331)
	// Attackers exploit --netrc-cmd, --exec, and --alias-expand to execute arbitrary commands
	// within AI agent sandboxes that use yt-dlp for media processing.
	ytdlpDangerousArgs := []string{
		"--netrc-cmd", "--exec", "--alias-expand", "--exec-before-download",
		"--exec-after-download", "--plugin-dirs",
	}
	if strings.Contains(cmdLower, "yt-dlp") || strings.Contains(cmdLower, "youtube-dl") {
		for _, arg := range ytdlpDangerousArgs {
			if strings.Contains(cmdLower, arg) {
				w.raiseAlert(event, core.SeverityCritical,
					"yt-dlp Argument-Based RCE Detected (CVE-2026-26331)",
					fmt.Sprintf("Process %s using dangerous yt-dlp argument %q which allows arbitrary command execution: %s. "+
						"Parent: %s. Attackers exploit media download tools in agentic workflows for RCE. "+
						"MITRE ATT&CK T1059.",
						processName, arg, truncate(cmdLine, 200), parentProcess),
					"ytdlp_rce")
				break
			}
		}
	}

	// Library load path hijacking (LD_PRELOAD / PYTHONPATH from non-system paths)
	// Detects local privilege escalation via uncontrolled search path manipulation.
	if strings.Contains(cmdLower, "ld_preload") || strings.Contains(cmdLower, "ld_library_path") ||
		strings.Contains(cmdLower, "pythonpath") || strings.Contains(cmdLower, "dyld_insert_libraries") {
		systemPaths := []string{"/usr/lib", "/lib", "/usr/local/lib", "/lib64", "/usr/lib64"}
		isSafe := false
		for _, sp := range systemPaths {
			if strings.Contains(cmdLower, sp) && !strings.Contains(cmdLower, "/tmp/") &&
				!strings.Contains(cmdLower, "/home/") && !strings.Contains(cmdLower, "appdata") {
				isSafe = true
				break
			}
		}
		if !isSafe {
			w.raiseAlert(event, core.SeverityHigh,
				"Library Load Path Hijacking Detected",
				fmt.Sprintf("Process %s modifying library search path from non-system directory: %s. "+
					"Parent: %s. Attackers use LD_PRELOAD/PYTHONPATH to inject malicious libraries "+
					"for privilege escalation. MITRE ATT&CK T1574.006.",
					processName, truncate(cmdLine, 200), parentProcess),
				"library_path_hijack")
		}
	}

	// Suspicious process detection
	if w.procMon.IsSuspicious(processName, cmdLine, parentProcess) {
		w.raiseAlert(event, core.SeverityHigh,
			"Suspicious Process Detected",
			fmt.Sprintf("Suspicious process: %s (cmd: %s, parent: %s)",
				processName, truncate(cmdLine, 100), parentProcess),
			"suspicious_process")
	}

	// Reverse shell detection
	if w.procMon.IsReverseShell(cmdLine) {
		w.raiseAlert(event, core.SeverityCritical,
			"Reverse Shell Detected",
			fmt.Sprintf("Possible reverse shell: %s", truncate(cmdLine, 200)),
			"reverse_shell")
	}
}

func (w *Watcher) checkExecutionIntegrity(event *core.SecurityEvent, processName, cmdLine string) {
	executedPath := firstStringDetail(event, "executed_path", "executable_path", "path")
	validatedPath := firstStringDetail(event, "validated_path", "checked_path")
	executedHash := firstStringDetail(event, "executed_hash", "hash")
	expectedHash := firstStringDetail(event, "expected_hash", "validated_hash")

	if executedPath != "" && validatedPath != "" && !sameNormalizedPath(executedPath, validatedPath) {
		w.raiseAlert(event, core.SeverityCritical,
			"TOCTOU Execution Path Swap Detected",
			fmt.Sprintf("Process %s executed %s after validation covered %s. "+
				"This indicates a time-of-check/time-of-use swap in an agent workspace. Command: %s.",
				processName, truncate(executedPath, 200), truncate(validatedPath, 200), truncate(cmdLine, 200)),
			"exec_path_swap")
	}

	if executedHash != "" && expectedHash != "" && !strings.EqualFold(executedHash, expectedHash) {
		w.raiseAlert(event, core.SeverityCritical,
			"Execution-Time File Integrity Mismatch",
			fmt.Sprintf("Process %s hash mismatch immediately before execution. Expected %s, got %s. "+
				"This catches TOCTOU swaps where an allowed tool is replaced after validation.",
				processName, truncate(expectedHash, 16), truncate(executedHash, 16)),
			"exec_integrity_mismatch")
	}

	lowerPath := strings.ToLower(filepath.ToSlash(executedPath + " " + cmdLine))
	if strings.Contains(lowerPath, "memfd:") || strings.Contains(lowerPath, "/proc/self/fd/") ||
		strings.Contains(lowerPath, "/proc/") && strings.Contains(lowerPath, "/fd/") ||
		strings.Contains(lowerPath, "(deleted)") || strings.Contains(lowerPath, "o_tmpfile") {
		w.raiseAlert(event, core.SeverityHigh,
			"Transient Fileless Execution Path Detected",
			fmt.Sprintf("Process %s executed from a transient or anonymous file path: %s. Command: %s.",
				processName, truncate(executedPath, 200), truncate(cmdLine, 200)),
			"exec_transient_path")
	}
}

func (w *Watcher) handlePrivilegeEvent(event *core.SecurityEvent) {
	user := getStringDetail(event, "user")
	action := getStringDetail(event, "action")
	target := getStringDetail(event, "target")

	w.raiseAlert(event, core.SeverityHigh,
		"Privilege Escalation Detected",
		fmt.Sprintf("User %s performed privilege action %q on %s", user, action, target),
		"privilege_escalation")
}

func (w *Watcher) handleContainerEvent(event *core.SecurityEvent) {
	action := getStringDetail(event, "action")
	containerID := getStringDetail(event, "container_id")

	escapeIndicators := []string{
		"mount_host_fs", "nsenter", "privileged_exec",
		"host_pid_access", "host_network_access", "cap_sys_admin",
		"docker_socket_mount", "proc_mount", "sys_ptrace",
		"apparmor_disabled", "seccomp_disabled",
	}

	for _, indicator := range escapeIndicators {
		if strings.Contains(action, indicator) {
			w.raiseAlert(event, core.SeverityCritical,
				"Container Escape Attempt",
				fmt.Sprintf("Container %s attempted escape via %s. "+
					"MITRE ATT&CK T1611.", truncate(containerID, 12), action),
				"container_escape")
			return
		}
	}
}

// handleMemoryInjection detects process hollowing, DLL injection, reflective loading,
// and other in-memory attack techniques used by APTs.
func (w *Watcher) handleMemoryInjection(event *core.SecurityEvent) {
	technique := getStringDetail(event, "technique")
	targetProcess := getStringDetail(event, "target_process")
	sourceProcess := getStringDetail(event, "source_process")
	targetPID := getStringDetail(event, "target_pid")

	techniqueDescriptions := map[string]struct {
		title   string
		mitreID string
	}{
		"process_hollowing":     {"Process Hollowing", "T1055.012"},
		"dll_injection":         {"DLL Injection", "T1055.001"},
		"reflective_loading":    {"Reflective DLL Loading", "T1620.001"},
		"thread_hijacking":      {"Thread Execution Hijacking", "T1055.003"},
		"apc_injection":         {"APC Queue Injection", "T1055.004"},
		"atom_bombing":          {"AtomBombing Injection", "T1055"},
		"process_doppelganging": {"Process Doppelgänging", "T1055.013"},
		"veh_hooking":           {"Vectored Exception Handler Hooking", "T1055"},
		"ntfs_transaction":      {"NTFS Transaction Injection", "T1055"},
		"early_bird":            {"Early Bird APC Injection", "T1055.004"},
		"module_stomping":       {"Module Stomping", "T1055"},
	}

	desc, known := techniqueDescriptions[technique]
	if !known {
		desc.title = "Memory Injection"
		desc.mitreID = "T1055"
	}

	w.raiseAlert(event, core.SeverityCritical,
		fmt.Sprintf("%s Detected", desc.title),
		fmt.Sprintf("Process %s (PID: %s) injected into %s using %s technique. "+
			"In-memory code execution evades file-based detection. "+
			"MITRE ATT&CK %s.",
			sourceProcess, targetPID, targetProcess, technique, desc.mitreID),
		"memory_injection")
}

// handlePersistenceEvent detects malicious persistence mechanisms including
// scheduled tasks, WMI subscriptions, registry run keys, cron jobs, and systemd services.
func (w *Watcher) handlePersistenceEvent(event *core.SecurityEvent) {
	mechanism := event.Type
	name := getStringDetail(event, "name")
	command := getStringDetail(event, "command")
	user := getStringDetail(event, "user")
	path := getStringDetail(event, "path")

	// Check for suspicious persistence commands
	suspiciousPatterns := []struct {
		pattern string
		reason  string
	}{
		{"powershell", "PowerShell execution in persistence"},
		{"cmd /c", "Command shell in persistence"},
		{"certutil", "CertUtil abuse for download/decode"},
		{"bitsadmin", "BITSAdmin abuse for download"},
		{"mshta", "MSHTA script execution"},
		{"regsvr32", "Regsvr32 proxy execution"},
		{"rundll32", "Rundll32 proxy execution"},
		{"wscript", "Windows Script Host execution"},
		{"cscript", "Windows Script Host execution"},
		{"/dev/tcp/", "Network connection in persistence"},
		{"curl |", "Remote script download and execute"},
		{"wget |", "Remote script download and execute"},
		{"base64", "Encoded payload in persistence"},
		{"-enc ", "Encoded PowerShell command"},
		{"-encodedcommand", "Encoded PowerShell command"},
		{"iex(", "PowerShell Invoke-Expression"},
		{"invoke-expression", "PowerShell Invoke-Expression"},
		{"downloadstring", "Remote payload download"},
		{"downloadfile", "Remote payload download"},
		{"hidden", "Hidden window execution"},
		{"bypass", "Execution policy bypass"},
	}

	cmdLower := strings.ToLower(command)
	for _, sp := range suspiciousPatterns {
		if strings.Contains(cmdLower, sp.pattern) {
			w.raiseAlert(event, core.SeverityCritical,
				"Malicious Persistence Mechanism Detected",
				fmt.Sprintf("Suspicious %s persistence created by user %q. "+
					"Name: %s, Command: %s. Reason: %s. Path: %s. "+
					"MITRE ATT&CK T1053/T1547.",
					mechanism, user, name, truncate(command, 150), sp.reason, path),
				"malicious_persistence")
			return
		}
	}

	// Non-suspicious but still worth logging
	w.raiseAlert(event, core.SeverityMedium,
		"Persistence Mechanism Created",
		fmt.Sprintf("New %s persistence: %s by user %q. Command: %s",
			mechanism, name, user, truncate(command, 100)),
		"persistence_created")
}

// handleFirmwareEvent detects UEFI bootkit indicators, firmware tampering,
// and Secure Boot bypass attempts.
func (w *Watcher) handleFirmwareEvent(event *core.SecurityEvent) {
	action := getStringDetail(event, "action")
	component := getStringDetail(event, "component")
	hash := getStringDetail(event, "hash")
	expectedHash := getStringDetail(event, "expected_hash")
	secureBootStatus := getStringDetail(event, "secure_boot")

	// Secure Boot disabled or bypassed
	if strings.EqualFold(secureBootStatus, "disabled") || strings.EqualFold(secureBootStatus, "bypassed") {
		w.raiseAlert(event, core.SeverityCritical,
			"Secure Boot Disabled/Bypassed",
			fmt.Sprintf("Secure Boot is %s on this system. Component: %s. "+
				"This allows unsigned bootloaders and bootkits like BlackLotus to execute. "+
				"MITRE ATT&CK T1542.003.",
				secureBootStatus, component),
			"secure_boot_bypass")
	}

	// Firmware hash mismatch
	if hash != "" && expectedHash != "" && hash != expectedHash {
		w.raiseAlert(event, core.SeverityCritical,
			"Firmware Tampering Detected",
			fmt.Sprintf("Firmware component %s hash mismatch. Expected: %s, Got: %s. "+
				"This indicates a potential bootkit or firmware rootkit. "+
				"Known threats: BlackLotus, LoJax, MosaicRegressor. "+
				"MITRE ATT&CK T1542.",
				component, truncate(expectedHash, 16), truncate(hash, 16)),
			"firmware_tampering")
	}

	// UEFI variable modification
	if strings.Contains(action, "uefi_var_write") || strings.Contains(action, "efi_variable_modified") {
		w.raiseAlert(event, core.SeverityHigh,
			"UEFI Variable Modified",
			fmt.Sprintf("UEFI variable modified: %s. Action: %s. "+
				"Unauthorized UEFI variable writes can indicate bootkit installation. "+
				"MITRE ATT&CK T1542.003.",
				component, action),
			"uefi_modification")
	}

	// Boot configuration change
	if strings.Contains(action, "bootloader_change") || strings.Contains(action, "bcd_modified") {
		w.raiseAlert(event, core.SeverityCritical,
			"Boot Configuration Modified",
			fmt.Sprintf("Boot configuration changed: %s. "+
				"Bootloader modifications can enable pre-OS malware execution. "+
				"MITRE ATT&CK T1542.",
				component),
			"boot_config_change")
	}
}

// byovdBlocklist contains known vulnerable drivers abused in Bring Your Own
// Vulnerable Driver (BYOVD) attacks to disable EDR/security tools from kernel space.
// References: TeamPCP/OpenClaw campaigns, MITRE ATT&CK T1068.
var byovdBlocklist = []string{
	"huaweidriver.sys", "rtcore64.sys", "gdrv.sys", "procexp152.sys", "nal.sys",
	"dbutil_2_3.sys", "asio64.sys", "mhyprot2.sys", "kprocesshacker.sys",
	"viragt64.sys", "aswarpot.sys", "iomem64.sys", "zemana.sys", "qmudisk64.sys",
}

// handleDriverLoad detects BYOVD attacks where threat actors load known-vulnerable
// signed drivers to gain kernel access and disable security tools.
func (w *Watcher) handleDriverLoad(event *core.SecurityEvent) {
	driverName := strings.ToLower(getStringDetail(event, "driver_name"))
	driverPath := strings.ToLower(getStringDetail(event, "path"))
	processName := getStringDetail(event, "process_name")
	driverHash := getStringDetail(event, "hash")

	if driverName == "" && driverPath != "" {
		// Extract filename from path
		driverName = strings.ToLower(filepath.Base(driverPath))
	}
	if driverName == "" {
		return
	}

	for _, blocked := range byovdBlocklist {
		if driverName == blocked || strings.HasSuffix(driverPath, blocked) {
			w.raiseAlert(event, core.SeverityCritical,
				"BYOVD Attack — Vulnerable Driver Loaded [T1068]",
				fmt.Sprintf("Known-vulnerable driver %q loaded by process %s. "+
					"Path: %s. Hash: %s. "+
					"Attackers use signed vulnerable drivers to gain kernel access and disable EDR. "+
					"MITRE ATT&CK T1068: Exploitation for Privilege Escalation.",
					driverName, processName, truncate(driverPath, 200), truncate(driverHash, 64)),
				"byovd_driver_load")
			return
		}
	}
}

// handleFilelessEvent detects fileless malware execution via PowerShell, WMI,
// MSHTA, and other LOLBin-based in-memory techniques.
func (w *Watcher) handleFilelessEvent(event *core.SecurityEvent) {
	processName := getStringDetail(event, "process_name")
	cmdLine := getStringDetail(event, "command_line")
	parentProcess := getStringDetail(event, "parent_process")
	scriptContent := getStringDetail(event, "script_content")

	cmdLower := strings.ToLower(cmdLine)
	scriptLower := strings.ToLower(scriptContent)

	// Encoded PowerShell commands (extremely common in fileless attacks)
	if strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "-encodedcommand") ||
		strings.Contains(cmdLower, "frombase64string") {
		w.raiseAlert(event, core.SeverityCritical,
			"Encoded Fileless Execution Detected",
			fmt.Sprintf("Encoded fileless execution via %s. Parent: %s. "+
				"Command: %s. Base64-encoded commands are a primary fileless malware technique. "+
				"MITRE ATT&CK T1059.001.",
				processName, parentProcess, truncate(cmdLine, 200)),
			"encoded_fileless_exec")
		return
	}

	// PowerShell download cradles
	downloadPatterns := []string{
		"downloadstring", "downloadfile", "invoke-webrequest",
		"wget", "curl", "start-bitstransfer",
		"net.webclient", "invoke-restmethod",
		"[system.net.webclient]", "bitstransfer",
	}
	for _, pattern := range downloadPatterns {
		if strings.Contains(cmdLower, pattern) || strings.Contains(scriptLower, pattern) {
			w.raiseAlert(event, core.SeverityCritical,
				"Fileless Download Cradle Detected",
				fmt.Sprintf("Download cradle via %s: %s. Parent: %s. "+
					"Remote payload downloaded and executed in memory. "+
					"MITRE ATT&CK T1059.001.",
					processName, truncate(cmdLine, 200), parentProcess),
				"download_cradle")
			return
		}
	}

	// AMSI bypass attempts
	amsiPatterns := []string{
		"amsiutils", "amsiinitfailed", "amsi.dll",
		"amsiscanbuffer", "amsicontext",
		"set-mppreference -disablerealtimemonitoring",
	}
	for _, pattern := range amsiPatterns {
		if strings.Contains(cmdLower, pattern) || strings.Contains(scriptLower, pattern) {
			w.raiseAlert(event, core.SeverityCritical,
				"AMSI Bypass Attempt Detected",
				fmt.Sprintf("AMSI bypass via %s: %s. "+
					"Attacker is disabling antimalware scanning to execute malicious scripts. "+
					"MITRE ATT&CK T1562.001.",
					processName, truncate(cmdLine, 200)),
				"amsi_bypass")
			return
		}
	}

	// ETW bypass / logging evasion — ClickFix campaign technique
	etwPatterns := []string{
		"etweventwrite", "nttracevent", "etwprovider",
		"patch etw", "etw bypass", "etwi",
		"reflection.assembly", "[ref].assembly",
		"set-mppreference -disableioavprotection",
		"set-mppreference -disablescriptscanning",
	}
	for _, pattern := range etwPatterns {
		if strings.Contains(cmdLower, pattern) || strings.Contains(scriptLower, pattern) {
			w.raiseAlert(event, core.SeverityCritical,
				"ETW/Logging Evasion Detected",
				fmt.Sprintf("ETW bypass via %s: %s. "+
					"Attacker is disabling event tracing to evade detection. "+
					"MITRE ATT&CK T1562.006.",
					processName, truncate(cmdLine, 200)),
				"etw_bypass")
			return
		}
	}

	// Lua-based shellcode loader — ClickFix campaign technique
	luaShellcodePatterns := []string{
		"luajit", "lua51.dll", "lua52.dll", "lua53.dll", "lua54.dll",
		"ffi.cast", "ffi.new", "ffi.copy", "ffi.string",
		"loadstring", "load(", "dofile",
	}
	for _, pattern := range luaShellcodePatterns {
		if strings.Contains(cmdLower, pattern) || strings.Contains(scriptLower, pattern) {
			w.raiseAlert(event, core.SeverityHigh,
				"Lua-Based Shellcode Loader Detected",
				fmt.Sprintf("Lua shellcode loading via %s: %s. Parent: %s. "+
					"Lua FFI is used by ClickFix and similar campaigns to load shellcode in memory. "+
					"MITRE ATT&CK T1059.",
					processName, truncate(cmdLine, 200), parentProcess),
				"lua_shellcode_loader")
			return
		}
	}

	// WMI-based execution
	if strings.Contains(cmdLower, "wmic") || strings.Contains(cmdLower, "invoke-wmimethod") ||
		strings.Contains(cmdLower, "get-wmiobject") {
		w.raiseAlert(event, core.SeverityHigh,
			"WMI-Based Execution Detected",
			fmt.Sprintf("WMI execution via %s: %s. Parent: %s. "+
				"WMI is commonly abused for lateral movement and fileless execution. "+
				"MITRE ATT&CK T1047.",
				processName, truncate(cmdLine, 200), parentProcess),
			"wmi_execution")
		return
	}

	// Generic fileless alert
	w.raiseAlert(event, core.SeverityHigh,
		"Fileless Execution Detected",
		fmt.Sprintf("Fileless execution via %s. Parent: %s. Command: %s. "+
			"MITRE ATT&CK T1059.",
			processName, parentProcess, truncate(cmdLine, 200)),
		"fileless_execution")
}

func (w *Watcher) fimLoop() {
	w.fim.BaselineScan()
	ticker := time.NewTicker(w.fim.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			changes := w.fim.Scan()
			for _, change := range changes {
				w.emitFileChange(change, "polling")
			}
		}
	}
}

func (w *Watcher) emitFileChange(change FileChange, source string) {
	if finding := classifyRealtimeFileChange(change); source == "realtime" && finding != nil {
		event := core.NewSecurityEvent(ModuleName, finding.AlertType, finding.Severity,
			fmt.Sprintf("%s: %s (%s)", finding.Title, change.Path, change.Type))
		event.Details["path"] = change.Path
		event.Details["change_type"] = change.Type
		event.Details["monitor_source"] = source
		if w.bus != nil {
			_ = w.bus.PublishEvent(event)
		}
		alert := core.NewAlert(event, finding.Title,
			fmt.Sprintf("%s Path: %s. Change: %s.", finding.Description, change.Path, change.Type))
		alert.Mitigations = getRuntimeMitigations(finding.AlertType)
		if w.pipeline != nil {
			w.pipeline.Process(alert)
		}
		return
	}

	severity := core.SeverityMedium
	if isSensitivePath(change.Path) {
		severity = core.SeverityCritical
	}
	event := core.NewSecurityEvent(ModuleName, "file_integrity_violation", severity,
		fmt.Sprintf("File integrity change: %s (%s)", change.Path, change.Type))
	event.Details["path"] = change.Path
	event.Details["change_type"] = change.Type
	event.Details["old_hash"] = change.OldHash
	event.Details["new_hash"] = change.NewHash
	event.Details["monitor_source"] = source
	if w.bus != nil {
		_ = w.bus.PublishEvent(event)
	}
	alert := core.NewAlert(event,
		fmt.Sprintf("File Integrity Violation: %s", change.Type),
		fmt.Sprintf("File %s was %s. Old hash: %s, New hash: %s",
			change.Path, change.Type, truncate(change.OldHash, 16), truncate(change.NewHash, 16)))
	alert.Mitigations = getRuntimeMitigations("file_integrity_violation")
	if w.pipeline != nil {
		w.pipeline.Process(alert)
	}
}

func (w *Watcher) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID
	if w.bus != nil {
		_ = w.bus.PublishEvent(newEvent)
	}
	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getRuntimeMitigations(alertType)
	if w.pipeline != nil {
		w.pipeline.Process(alert)
	}
}

// ---------------------------------------------------------------------------
// FileIntegrityMonitor
// ---------------------------------------------------------------------------

type FileIntegrityMonitor struct {
	mu       sync.RWMutex
	baseline map[string]string
	paths    []string
	interval time.Duration
}

type FileChange struct {
	Path    string
	Type    string
	OldHash string
	NewHash string
}

type realtimeFileMonitor interface {
	Start(context.Context, func(FileChange)) error
	Close() error
}

type runtimeFileFinding struct {
	Title       string
	Description string
	AlertType   string
	Severity    core.Severity
}

func NewFileIntegrityMonitor(paths []string, interval time.Duration) *FileIntegrityMonitor {
	return &FileIntegrityMonitor{baseline: make(map[string]string), paths: paths, interval: interval}
}

func (fim *FileIntegrityMonitor) BaselineScan() {
	fim.mu.Lock()
	defer fim.mu.Unlock()
	for _, watchPath := range fim.paths {
		_ = filepath.Walk(watchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			hash, err := hashFile(path)
			if err == nil {
				fim.baseline[path] = hash
			}
			return nil
		})
	}
}

func (fim *FileIntegrityMonitor) Scan() []FileChange {
	fim.mu.Lock()
	defer fim.mu.Unlock()
	var changes []FileChange
	currentFiles := make(map[string]string)
	for _, watchPath := range fim.paths {
		_ = filepath.Walk(watchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			hash, err := hashFile(path)
			if err == nil {
				currentFiles[path] = hash
			}
			return nil
		})
	}
	for path, newHash := range currentFiles {
		oldHash, existed := fim.baseline[path]
		if !existed {
			changes = append(changes, FileChange{Path: path, Type: "created", NewHash: newHash})
		} else if oldHash != newHash {
			changes = append(changes, FileChange{Path: path, Type: "modified", OldHash: oldHash, NewHash: newHash})
		}
	}
	for path, oldHash := range fim.baseline {
		if _, exists := currentFiles[path]; !exists {
			changes = append(changes, FileChange{Path: path, Type: "deleted", OldHash: oldHash})
		}
	}
	fim.baseline = currentFiles
	return changes
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// ---------------------------------------------------------------------------
// ProcessMonitor — suspicious process, reverse shell, and LOLBin detection
// ---------------------------------------------------------------------------

type ProcessMonitor struct {
	suspiciousProcesses  map[string]bool
	reverseShellPatterns []string
	lolbins              map[string]lolbinInfo
}

type lolbinInfo struct {
	Techniques []lolbinTechnique
}

type lolbinTechnique struct {
	Pattern   string
	Technique string
	MitreID   string
}

type LOLBinResult struct {
	Detected  bool
	Technique string
	MitreID   string
}

func NewProcessMonitor() *ProcessMonitor {
	pm := &ProcessMonitor{
		suspiciousProcesses: map[string]bool{
			"nc": true, "ncat": true, "netcat": true,
			"nmap": true, "masscan": true, "zmap": true,
			"mimikatz": true, "lazagne": true, "hashcat": true,
			"john": true, "hydra": true, "medusa": true,
			"sqlmap": true, "nikto": true, "dirb": true,
			"gobuster": true, "wfuzz": true, "ffuf": true,
			"msfconsole": true, "msfvenom": true, "metasploit": true,
			"cobaltstrike": true, "empire": true, "sliver": true,
			"chisel": true, "socat": true, "cryptominer": true,
			"xmrig": true, "ccminer": true, "minerd": true,
			"rubeus": true, "sharphound": true, "bloodhound": true,
			"impacket": true, "crackmapexec": true, "evil-winrm": true,
			"psexec": true, "procdump": true, "nanodump": true,
			"secretsdump": true, "kerbrute": true, "responder": true,
		},
		reverseShellPatterns: []string{
			"bash -i >& /dev/tcp/", "bash -i >& /dev/udp/",
			"nc -e /bin/", "ncat -e /bin/",
			"python -c 'import socket", "python3 -c 'import socket",
			"perl -e 'use Socket", "ruby -rsocket -e",
			"php -r '$sock=fsockopen", "powershell -nop -c \"$client",
			"IEX(New-Object Net.WebClient)", "/dev/tcp/", "mkfifo /tmp/",
			"bash -c 'bash -i", "0<&196;exec 196<>/dev/tcp/",
			"exec 5<>/dev/tcp/", "lua -e \"require('socket')",
			"openssl s_client -connect",
		},
		lolbins: buildLOLBinDatabase(),
	}
	return pm
}

func buildLOLBinDatabase() map[string]lolbinInfo {
	return map[string]lolbinInfo{
		"certutil": {Techniques: []lolbinTechnique{
			{Pattern: "-urlcache", Technique: "File download", MitreID: "T1105"},
			{Pattern: "-decode", Technique: "Base64 decode", MitreID: "T1140"},
			{Pattern: "-encode", Technique: "Base64 encode", MitreID: "T1027"},
			{Pattern: "-verifyctl", Technique: "Download and execute", MitreID: "T1105"},
		}},
		"mshta": {Techniques: []lolbinTechnique{
			{Pattern: "http", Technique: "Remote HTA execution", MitreID: "T1218.005"},
			{Pattern: "vbscript", Technique: "VBScript execution", MitreID: "T1218.005"},
			{Pattern: "javascript", Technique: "JavaScript execution", MitreID: "T1218.005"},
		}},
		"regsvr32": {Techniques: []lolbinTechnique{
			{Pattern: "/s /n /u /i:http", Technique: "Squiblydoo attack", MitreID: "T1218.010"},
			{Pattern: "scrobj.dll", Technique: "COM scriptlet execution", MitreID: "T1218.010"},
		}},
		"rundll32": {Techniques: []lolbinTechnique{
			{Pattern: "javascript:", Technique: "JavaScript execution", MitreID: "T1218.011"},
			{Pattern: "shell32.dll,control_rundll", Technique: "CPL execution", MitreID: "T1218.011"},
			{Pattern: "advpack.dll,launchinf", Technique: "INF execution", MitreID: "T1218.011"},
			{Pattern: "comsvcs.dll,minidump", Technique: "Process memory dump (credential theft)", MitreID: "T1003.001"},
		}},
		"bitsadmin": {Techniques: []lolbinTechnique{
			{Pattern: "/transfer", Technique: "File download", MitreID: "T1197"},
			{Pattern: "/create", Technique: "Persistence via BITS job", MitreID: "T1197"},
		}},
		"wmic": {Techniques: []lolbinTechnique{
			{Pattern: "process call create", Technique: "Remote process creation", MitreID: "T1047"},
			{Pattern: "/node:", Technique: "Remote WMI execution", MitreID: "T1047"},
			{Pattern: "os get", Technique: "System reconnaissance", MitreID: "T1082"},
		}},
		"msiexec": {Techniques: []lolbinTechnique{
			{Pattern: "/q", Technique: "Silent MSI execution", MitreID: "T1218.007"},
			{Pattern: "http", Technique: "Remote MSI execution", MitreID: "T1218.007"},
		}},
		"cmstp": {Techniques: []lolbinTechnique{
			{Pattern: "/ni /s", Technique: "UAC bypass via CMSTP", MitreID: "T1218.003"},
		}},
		"installutil": {Techniques: []lolbinTechnique{
			{Pattern: "/logfile=", Technique: ".NET assembly execution", MitreID: "T1218.004"},
		}},
		"msbuild": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "Inline task code execution", MitreID: "T1127.001"},
		}},
		"csc": {Techniques: []lolbinTechnique{
			{Pattern: "/out:", Technique: "C# compilation and execution", MitreID: "T1127"},
		}},
		"xwizard": {Techniques: []lolbinTechnique{
			{Pattern: "runwizard", Technique: "COM object execution", MitreID: "T1218"},
		}},
		"forfiles": {Techniques: []lolbinTechnique{
			{Pattern: "/c", Technique: "Command execution via forfiles", MitreID: "T1202"},
		}},
		"pcalua": {Techniques: []lolbinTechnique{
			{Pattern: "-a", Technique: "Program Compatibility Assistant proxy", MitreID: "T1202"},
		}},
		"bash": {Techniques: []lolbinTechnique{
			{Pattern: "wsl", Technique: "WSL execution bypass", MitreID: "T1202"},
		}},
		"wsl": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "WSL execution bypass", MitreID: "T1202"},
		}},
		"explorer": {Techniques: []lolbinTechnique{
			{Pattern: "/root,", Technique: "DLL side-loading via Explorer", MitreID: "T1574.002"},
		}},
		"control": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "Control Panel item execution", MitreID: "T1218.002"},
		}},
		"esentutl": {Techniques: []lolbinTechnique{
			{Pattern: "/y", Technique: "File copy (ADS/locked file access)", MitreID: "T1003"},
		}},
		"expand": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "CAB file extraction", MitreID: "T1140"},
		}},
		"extrac32": {Techniques: []lolbinTechnique{
			{Pattern: "/y", Technique: "CAB extraction bypass", MitreID: "T1140"},
		}},
		"findstr": {Techniques: []lolbinTechnique{
			{Pattern: "/v /l", Technique: "ADS file download", MitreID: "T1105"},
		}},
		"hh": {Techniques: []lolbinTechnique{
			{Pattern: "http", Technique: "Remote CHM execution", MitreID: "T1218.001"},
		}},
		"ieexec": {Techniques: []lolbinTechnique{
			{Pattern: "http", Technique: "Remote .NET assembly execution", MitreID: "T1218"},
		}},
		"infdefaultinstall": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "INF file execution", MitreID: "T1218"},
		}},
		"makecab": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "Data staging via CAB", MitreID: "T1074"},
		}},
		"mavinject": {Techniques: []lolbinTechnique{
			{Pattern: "/injectrunning", Technique: "DLL injection into running process", MitreID: "T1055.001"},
		}},
		"replace": {Techniques: []lolbinTechnique{
			{Pattern: "/a", Technique: "File copy to restricted location", MitreID: "T1105"},
		}},
		"sc": {Techniques: []lolbinTechnique{
			{Pattern: "create", Technique: "Service creation for persistence", MitreID: "T1543.003"},
			{Pattern: "config", Technique: "Service modification", MitreID: "T1543.003"},
		}},
		"schtasks": {Techniques: []lolbinTechnique{
			{Pattern: "/create", Technique: "Scheduled task persistence", MitreID: "T1053.005"},
		}},
		"reg": {Techniques: []lolbinTechnique{
			{Pattern: "save", Technique: "Registry hive dump (credential theft)", MitreID: "T1003.002"},
			{Pattern: "add", Technique: "Registry modification", MitreID: "T1112"},
			{Pattern: "export", Technique: "Registry export", MitreID: "T1012"},
		}},
		"nltest": {Techniques: []lolbinTechnique{
			{Pattern: "/dclist", Technique: "Domain controller enumeration", MitreID: "T1018"},
			{Pattern: "/domain_trusts", Technique: "Domain trust discovery", MitreID: "T1482"},
		}},
		"dsquery": {Techniques: []lolbinTechnique{
			{Pattern: "", Technique: "Active Directory enumeration", MitreID: "T1018"},
		}},
		"net": {Techniques: []lolbinTechnique{
			{Pattern: "user /domain", Technique: "Domain user enumeration", MitreID: "T1087.002"},
			{Pattern: "group /domain", Technique: "Domain group enumeration", MitreID: "T1069.002"},
			{Pattern: "localgroup administrators", Technique: "Local admin enumeration", MitreID: "T1069.001"},
		}},
		"whoami": {Techniques: []lolbinTechnique{
			{Pattern: "/priv", Technique: "Privilege enumeration", MitreID: "T1033"},
			{Pattern: "/all", Technique: "Full identity enumeration", MitreID: "T1033"},
		}},
		"tasklist": {Techniques: []lolbinTechnique{
			{Pattern: "/svc", Technique: "Service enumeration", MitreID: "T1007"},
		}},
		"netsh": {Techniques: []lolbinTechnique{
			{Pattern: "firewall", Technique: "Firewall modification", MitreID: "T1562.004"},
			{Pattern: "advfirewall", Technique: "Firewall rule modification", MitreID: "T1562.004"},
			{Pattern: "portproxy", Technique: "Port forwarding", MitreID: "T1090"},
		}},
	}
}

func (pm *ProcessMonitor) IsLOLBin(name, cmdLine, parent string) LOLBinResult {
	nameLower := strings.ToLower(name)
	// Strip .exe extension for matching
	baseName := strings.TrimSuffix(nameLower, ".exe")

	info, isLOLBin := pm.lolbins[baseName]
	if !isLOLBin {
		return LOLBinResult{}
	}

	cmdLower := strings.ToLower(cmdLine)
	for _, tech := range info.Techniques {
		if tech.Pattern == "" || strings.Contains(cmdLower, tech.Pattern) {
			return LOLBinResult{
				Detected:  true,
				Technique: tech.Technique,
				MitreID:   tech.MitreID,
			}
		}
	}
	return LOLBinResult{}
}

func (pm *ProcessMonitor) IsSuspicious(name, cmdLine, parent string) bool {
	nameLower := strings.ToLower(name)
	if pm.suspiciousProcesses[nameLower] {
		return true
	}
	suspiciousParents := map[string][]string{
		"apache2":  {"bash", "sh", "python", "perl", "ruby"},
		"httpd":    {"bash", "sh", "python", "perl", "ruby"},
		"nginx":    {"bash", "sh", "python", "perl", "ruby"},
		"java":     {"bash", "sh", "cmd", "powershell"},
		"node":     {"bash", "sh", "cmd", "powershell"},
		"postgres": {"bash", "sh", "python"},
		"mysql":    {"bash", "sh", "python"},
		"w3wp":     {"cmd", "powershell", "bash"},
		"iis":      {"cmd", "powershell"},
		"tomcat":   {"bash", "sh", "cmd", "powershell"},
		"php-fpm":  {"bash", "sh", "python"},
	}
	parentLower := strings.ToLower(parent)
	if children, ok := suspiciousParents[parentLower]; ok {
		for _, child := range children {
			if nameLower == child {
				return true
			}
		}
	}
	return false
}

func (pm *ProcessMonitor) IsReverseShell(cmdLine string) bool {
	cmdLower := strings.ToLower(cmdLine)
	for _, pattern := range pm.reverseShellPatterns {
		if strings.Contains(cmdLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func isSensitivePath(path string) bool {
	sensitivePaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/etc/ssh/sshd_config", "/etc/crontab",
		"/root/.ssh/authorized_keys", "/root/.bashrc",
		"C:\\Windows\\System32\\config\\SAM",
		"C:\\Windows\\System32\\config\\SYSTEM",
		"C:\\Windows\\System32\\config\\SECURITY",
		"/var/spool/cron",
		"/etc/pam.d/", "/etc/ld.so.preload",
		"/boot/grub/grub.cfg", "/boot/efi/",
		"/sys/firmware/efi/",
		// Developer tool configs — sandbox escape vectors (CVE-2026-26268)
		".git/config", ".git/hooks/",
		".vscode/settings.json", ".vscode/tasks.json", ".vscode/launch.json",
		".idea/", ".cursor/",
		".npmrc", ".yarnrc", ".pypirc",
		".docker/config.json",
		".kube/config",
		".aws/credentials", ".aws/config",
	}
	pathLower := strings.ToLower(filepath.ToSlash(path))
	for _, sp := range sensitivePaths {
		if strings.Contains(pathLower, strings.ToLower(filepath.ToSlash(sp))) {
			return true
		}
	}
	return false
}

// isSensitiveCmdTarget checks if a command line string references sensitive system
// paths, used for detecting symlink/link-following privilege escalation attacks
// (CVE-2026-1731, Fortinet FortiClient LPE).
func isSensitiveCmdTarget(cmdLower string) bool {
	sensitiveTargets := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh",
		"/etc/pam.d", "/etc/ld.so.preload", "/etc/crontab",
		"/root/.ssh", "/var/spool/cron",
		"c:\\windows\\system32\\config",
		"c:\\windows\\system32\\drivers",
		"c:\\programdata",
		".aws/credentials", ".kube/config", ".docker/config.json",
		".git/config", ".git/hooks",
		"/boot/grub", "/boot/efi", "/sys/firmware",
	}
	for _, target := range sensitiveTargets {
		if strings.Contains(cmdLower, target) {
			return true
		}
	}
	return false
}

func isSuspiciousFile(path string) bool {
	suspiciousExts := []string{
		".exe", ".dll", ".so", ".dylib",
		".sh", ".bat", ".ps1", ".vbs",
		".php", ".jsp", ".asp", ".aspx",
		".py", ".pl", ".rb", ".hta",
		".scr", ".cpl", ".inf", ".msi",
		".wsf", ".wsh", ".chm",
	}
	ext := strings.ToLower(filepath.Ext(path))
	for _, se := range suspiciousExts {
		if ext == se {
			return true
		}
	}
	return false
}

func defaultEphemeralWatchPaths() []string {
	return []string{"/dev/shm", "/tmp", "/var/tmp", "/run", "/run/user"}
}

func classifyRealtimeFileChange(change FileChange) *runtimeFileFinding {
	if !isEphemeralExecutionPath(change.Path) {
		return nil
	}
	changeType := strings.ToLower(change.Type)
	if changeType != "created" && changeType != "modified" && changeType != "moved_to" &&
		changeType != "close_write" && changeType != "attrib" {
		return nil
	}

	pathLower := strings.ToLower(filepath.ToSlash(change.Path))
	criticalMarkers := []string{
		"setuid", "suid", "cap_", "capability", "ld.so.preload", "pkexec",
		"sudo", "dirty", "overlayfs", "cve-", "exploit", "rootkit",
	}
	for _, marker := range criticalMarkers {
		if strings.Contains(pathLower, marker) {
			return &runtimeFileFinding{
				Title:       "Real-Time Fileless LPE Artifact Detected",
				Description: "Runtime Watcher saw a transient privilege-escalation artifact land in an executable memory or temp-backed path before polling could miss it.",
				AlertType:   "realtime_fileless_lpe",
				Severity:    core.SeverityCritical,
			}
		}
	}
	if isSuspiciousFile(change.Path) || strings.Contains(pathLower, ".so") {
		return &runtimeFileFinding{
			Title:       "Real-Time Transient Execution Artifact Detected",
			Description: "Runtime Watcher saw a suspicious executable or script artifact in a short-lived runtime path through the real-time file monitor.",
			AlertType:   "realtime_transient_exec",
			Severity:    core.SeverityHigh,
		}
	}
	return nil
}

func isEphemeralExecutionPath(path string) bool {
	pathLower := strings.ToLower(filepath.ToSlash(path))
	ephemeralPaths := []string{
		"/dev/shm/",
		"/tmp/",
		"/var/tmp/",
		"/run/user/",
		"/run/lock/",
	}
	for _, prefix := range ephemeralPaths {
		if strings.HasPrefix(pathLower, prefix) {
			return true
		}
	}
	return false
}

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	return ""
}

func firstStringDetail(event *core.SecurityEvent, keys ...string) string {
	for _, key := range keys {
		if val := getStringDetail(event, key); val != "" {
			return val
		}
	}
	return ""
}

func sameNormalizedPath(a, b string) bool {
	normalize := func(path string) string {
		path = strings.TrimSpace(strings.ToLower(filepath.ToSlash(path)))
		path = strings.TrimSuffix(path, "/")
		return path
	}
	return normalize(a) == normalize(b)
}

func getIntSetting(settings map[string]interface{}, key string, defaultVal int) int {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultVal
}

func getBoolSetting(settings map[string]interface{}, key string, defaultVal bool) bool {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case bool:
			return v
		case string:
			return strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
		}
	}
	return defaultVal
}

func getStringSliceSetting(settings map[string]interface{}, key string, defaultVal []string) []string {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case []interface{}:
			result := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result
		case []string:
			return v
		}
	}
	return defaultVal
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// getRuntimeMitigations returns context-specific mitigations based on alert type.
func getRuntimeMitigations(alertType string) []string {
	switch alertType {
	case "file_integrity_violation":
		return []string{
			"Investigate the file change — compare against known-good baseline",
			"Restore the file from a verified backup if tampering is confirmed",
			"Implement file integrity monitoring with real-time alerting",
			"Review access logs for the modified file",
		}
	case "realtime_fileless_lpe", "realtime_transient_exec":
		return []string{
			"Isolate the host if the artifact is unauthorized",
			"Capture process ancestry and command-line telemetry around the file event",
			"Review /dev/shm, /tmp, /var/tmp, and /run activity for short-lived loaders",
			"Patch the affected privilege-escalation or sandbox-escape path",
		}
	case "exec_integrity_mismatch", "exec_path_swap", "exec_transient_path":
		return []string{
			"Kill or suspend the process until the executable path and hash are verified",
			"Recompute the binary hash from disk and compare it to the allowlisted validation hash",
			"Inspect symlink, hardlink, memfd, and /proc/fd activity around the execution timestamp",
			"Require execution-time hash validation for agent-managed tools and workspace binaries",
		}
	case "lolbin_execution":
		return []string{
			"Investigate the LOLBin usage — verify if it's legitimate administrative activity",
			"Implement application whitelisting to restrict LOLBin execution",
			"Monitor parent-child process relationships for suspicious chains",
			"Block unnecessary LOLBins via AppLocker or WDAC policies",
		}
	case "suspicious_process":
		return []string{
			"Investigate the process and its parent for malicious activity",
			"Check the process binary hash against threat intelligence",
			"Isolate the host if compromise is confirmed",
			"Review process execution logs for related suspicious activity",
		}
	case "reverse_shell":
		return []string{
			"Immediately isolate the affected host from the network",
			"Kill the reverse shell process and investigate the entry point",
			"Check for persistence mechanisms installed by the attacker",
			"Rotate all credentials accessible from the compromised host",
		}
	case "privilege_escalation":
		return []string{
			"Investigate the privilege escalation attempt",
			"Patch the vulnerability used for escalation",
			"Implement least-privilege access controls",
			"Deploy endpoint detection and response (EDR)",
		}
	case "container_escape":
		return []string{
			"Investigate the container escape attempt immediately",
			"Update container runtime to the latest patched version",
			"Implement seccomp profiles and AppArmor/SELinux policies",
			"Restrict container capabilities to the minimum required",
		}
	case "memory_injection":
		return []string{
			"Investigate the target process for compromise",
			"Implement memory protection policies (DEP, ASLR, CFG)",
			"Deploy endpoint detection with memory scanning capabilities",
			"Block known injection techniques via security policies",
		}
	case "persistence_mechanism":
		return []string{
			"Remove the persistence mechanism immediately",
			"Investigate how the persistence was established",
			"Monitor common persistence locations (startup, services, cron, registry)",
			"Implement change detection on persistence-related system files",
		}
	case "firmware_tampering":
		return []string{
			"Verify firmware integrity against vendor-provided hashes",
			"Reflash firmware from a known-good source",
			"Implement Secure Boot and firmware integrity monitoring",
			"Investigate the attack vector used for firmware modification",
		}
	case "fileless_attack", "fileless_execution":
		return []string{
			"Investigate the fileless execution chain (PowerShell, WMI, .NET)",
			"Implement script block logging and constrained language mode",
			"Deploy AMSI-aware endpoint protection",
			"Block unnecessary scripting engines via application control policies",
		}
	default:
		return []string{
			"Investigate the runtime event for security implications",
			"Implement endpoint detection and response (EDR)",
			"Review system logs for related suspicious activity",
		}
	}
}
