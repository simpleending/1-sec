package ransomware

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog"
)

const ModuleName = "ransomware"

var rawDiskTarget = regexp.MustCompile(`(?i)^(?:/dev/(?:sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+|loop[0-9]+|md[0-9]+|dm-[0-9]+)|\\\\\.\\physicaldrive[0-9]+)$`)

// Interceptor is the Ransomware Interceptor module providing encryption detection,
// canary file monitoring, data exfiltration detection, wiper detection, shadow copy
// deletion detection, and backup destruction detection.
type Interceptor struct {
	logger        zerolog.Logger
	bus           *core.EventBus
	pipeline      *core.AlertPipeline
	cfg           *core.Config
	ctx           context.Context
	cancel        context.CancelFunc
	fileTracker   *FileActivityTracker
	exfilTracker  *ExfilTracker
	wiperTracker  *WiperTracker
	backupTracker *BackupDestructionTracker
}

func New() *Interceptor { return &Interceptor{} }

func (i *Interceptor) Name() string { return ModuleName }
func (i *Interceptor) Description() string {
	return "Ransomware detection via file encryption patterns, canary files, data exfiltration monitoring, wiper detection, shadow copy deletion, and backup destruction detection"
}
func (i *Interceptor) EventTypes() []string {
	return []string{
		"file_modified", "file_change", "file_renamed", "file_created",
		"network_egress", "data_transfer", "upload",
		"canary_triggered",
		"process_execution", "command_execution",
		"shadow_copy_delete", "vss_manipulation",
		"backup_destruction", "backup_delete",
		"wiper_activity", "disk_write", "mbr_write", "partition_write",
		// 2025-2026: intermittent encryption, ESXi/hypervisor targeting, data-only extortion
		"vm_encryption", "esxi_command", "hypervisor_activity",
		"credential_dump", "credential_access",
	}
}

func (i *Interceptor) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	i.ctx, i.cancel = context.WithCancel(ctx)
	i.bus = bus
	i.pipeline = pipeline
	i.cfg = cfg
	i.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)
	encryptionThreshold := getIntSetting(settings, "encryption_threshold", 5)
	exfilMBThreshold := getIntSetting(settings, "exfil_mb_threshold", 100)

	i.fileTracker = NewFileActivityTracker(encryptionThreshold)
	i.exfilTracker = NewExfilTracker(int64(exfilMBThreshold) * 1024 * 1024)
	i.wiperTracker = NewWiperTracker()
	i.backupTracker = NewBackupDestructionTracker()

	go i.fileTracker.CleanupLoop(i.ctx)
	go i.exfilTracker.CleanupLoop(i.ctx)
	go i.wiperTracker.CleanupLoop(i.ctx)
	go i.backupTracker.CleanupLoop(i.ctx)

	i.logger.Info().
		Int("encryption_threshold", encryptionThreshold).
		Int("exfil_mb_threshold", exfilMBThreshold).
		Msg("ransomware interceptor started")

	return nil
}

func (i *Interceptor) Stop() error {
	if i.cancel != nil {
		i.cancel()
	}
	return nil
}

func (i *Interceptor) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "file_modified", "file_change", "file_renamed":
		i.handleFileActivity(event)
	case "file_created":
		i.handleFileCreated(event)
	case "network_egress", "data_transfer", "upload":
		i.handleEgress(event)
	case "canary_triggered":
		i.handleCanaryTriggered(event)
	case "process_execution", "command_execution":
		i.handleProcessExecution(event)
	case "shadow_copy_delete", "vss_manipulation":
		i.handleShadowCopyDeletion(event)
	case "backup_destruction", "backup_delete":
		i.handleBackupDestruction(event)
	case "wiper_activity", "disk_write", "mbr_write", "partition_write":
		i.handleWiperActivity(event)
	// 2025-2026: ESXi/hypervisor ransomware targeting
	case "vm_encryption", "esxi_command", "hypervisor_activity":
		i.handleHypervisorAttack(event)
	// 2025-2026: pre-ransomware credential harvesting
	case "credential_dump", "credential_access":
		i.handleCredentialHarvesting(event)
	}
	return nil
}

func (i *Interceptor) handleFileActivity(event *core.SecurityEvent) {
	path := getStringDetail(event, "path")
	processName := getStringDetail(event, "process_name")
	entropy := getFloatDetail(event, "entropy")

	if isRansomwareExtension(path) {
		i.raiseAlert(event, core.SeverityCritical,
			"Ransomware Extension Detected [T1486]",
			fmt.Sprintf("File with known ransomware extension detected: %s (process: %s). MITRE ATT&CK T1486: Data Encrypted for Impact.",
				path, processName),
			"ransomware_extension")
		return
	}

	// 2025-2026: Intermittent/partial encryption detection.
	// Modern ransomware encrypts only portions of files (first N bytes, random segments,
	// or every Nth block) to evade entropy-based detection while still rendering files unusable.
	partialEncryption := getStringDetail(event, "partial_encryption")
	bytesEncrypted := getIntDetail(event, "bytes_encrypted")
	fileSize := getIntDetail(event, "file_size")
	encryptionPattern := getStringDetail(event, "encryption_pattern")

	if partialEncryption == "true" || (bytesEncrypted > 0 && fileSize > 0 && bytesEncrypted < fileSize) {
		ratio := float64(0)
		if fileSize > 0 {
			ratio = float64(bytesEncrypted) / float64(fileSize) * 100
		}
		desc := fmt.Sprintf("Intermittent encryption detected on %s by process %s. Only %.1f%% of file encrypted (%d/%d bytes).",
			path, processName, ratio, bytesEncrypted, fileSize)
		if encryptionPattern != "" {
			desc += fmt.Sprintf(" Pattern: %s.", encryptionPattern)
		}
		desc += " Modern ransomware uses partial encryption to evade entropy-based detection while rendering files unusable."
		i.raiseAlert(event, core.SeverityCritical,
			"Intermittent Encryption Detected [T1486]",
			desc,
			"intermittent_encryption")
		return
	}

	// Scope file activity to the reporting host and process instance when supplied.
	host := getStringDetail(event, "host_id")
	if host == "" {
		host = event.SourceIP
	}
	if host == "" {
		host = event.Source
	}
	process := processName
	if pid := processID(event); pid != "" {
		process = "pid:" + pid
	}
	if process == "" || path == "" {
		return // Missing attribution must not pool unrelated file changes.
	}
	key := fmt.Sprintf("%q/%q", host, process)
	if started := getStringDetail(event, "process_start_time"); started != "" {
		key += fmt.Sprintf("/%q", started)
	}
	before, hasBefore := event.Details["entropy_before"]
	transition := false
	if hasBefore {
		switch before.(type) {
		case int, float64:
			previous := getFloatDetail(event, "entropy_before")
			transition = previous >= 0 && previous <= 8 && entropy <= 8 && entropy-previous >= 1
		}
	}
	result := i.fileTracker.recordActivity(key, path, entropy, event.Type == "file_renamed", transition)

	if result.MassEncryption {
		severity := core.SeverityHigh
		if result.EncryptionTransitions >= i.fileTracker.encryptionThreshold {
			severity = core.SeverityCritical
		}
		i.raiseAlert(event, severity,
			"Mass File Encryption Detected [T1486]",
			fmt.Sprintf("Process %s has modified %d files in %s with high entropy (avg: %.2f); %d files have reported entropy increases of at least 1 bit/byte. Compression and authorized encryption can also cause this. MITRE ATT&CK T1486: possible Data Encrypted for Impact.",
				processName, result.FileCount, result.Duration.String(), result.AvgEntropy, result.EncryptionTransitions),
			"mass_encryption")
	}

	if result.HighEntropy {
		i.raiseAlert(event, core.SeverityMedium,
			"High Entropy File Modification [T1486]",
			fmt.Sprintf("File %s modified with entropy %.2f by process %s. Compression and legitimate encryption can produce high entropy; verify context. MITRE ATT&CK T1486.",
				path, entropy, processName),
			"high_entropy")
	}

	if result.RapidRename {
		i.raiseAlert(event, core.SeverityHigh,
			"Rapid File Renaming Detected [T1486]",
			fmt.Sprintf("Process %s is rapidly renaming files (%d in %s). Common ransomware behavior. MITRE ATT&CK T1486.",
				processName, result.RenameCount, result.Duration.String()),
			"rapid_rename")
	}
}

func (i *Interceptor) handleFileCreated(event *core.SecurityEvent) {
	path := getStringDetail(event, "path")

	if isRansomNote(path) {
		i.raiseAlert(event, core.SeverityCritical,
			"Ransom Note Detected [T1491]",
			fmt.Sprintf("Possible ransom note created: %s. MITRE ATT&CK T1491: Defacement / T1486: Data Encrypted for Impact.", path),
			"ransom_note")
	}
}

func (i *Interceptor) handleEgress(event *core.SecurityEvent) {
	bytesTransferred := egressBytes(event.Details["bytes"])
	destIP := event.DestIP
	if destIP == "" {
		destIP = getStringDetail(event, "destination")
	}

	if bytesTransferred <= 0 {
		return
	}

	exceeded, stats := i.exfilTracker.record(event.SourceIP, destIP, bytesTransferred)
	if stats.CapacityEvicted {
		health := core.NewSecurityEvent(ModuleName, "tracking_capacity", core.SeverityLow, "Egress source history evicted; coverage reduced")
		i.raiseAlert(health, core.SeverityLow, "Egress Tracking Capacity Reached", health.Summary, "tracking_capacity")
	}
	if exceeded {
		i.raiseAlert(event, core.SeverityCritical,
			"Data Exfiltration Detected [T1041]",
			fmt.Sprintf("Abnormal data egress from %s: %.2f MB transferred to at least %d unique destinations in the last hour. Threshold: %.2f MB. MITRE ATT&CK T1041: Exfiltration Over C2 Channel.",
				event.SourceIP, float64(stats.TotalBytes)/(1024*1024), stats.UniqueDestinations, float64(i.exfilTracker.threshold)/(1024*1024)),
			"data_exfiltration")
	}
}

// Saturate before converting JSON floats or wide counters to a signed byte count.
func egressBytes(value interface{}) int64 {
	switch v := value.(type) {
	case int:
		return max(int64(v), 0)
	case int64:
		return max(v, 0)
	case uint64:
		if v > math.MaxInt64 {
			return math.MaxInt64
		}
		return int64(v)
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
			return 0
		}
		if v >= float64(math.MaxInt64) {
			return math.MaxInt64
		}
		return int64(v)
	case string:
		text := strings.TrimPrefix(strings.TrimSpace(v), "+")
		for _, digit := range text {
			if digit < '0' || digit > '9' {
				return 0
			}
		}
		n, _ := strconv.ParseUint(text, 10, 64) // Valid decimal overflow returns MaxUint64.
		if n > math.MaxInt64 {
			return math.MaxInt64
		}
		return int64(n)
	}
	return 0
}

func (i *Interceptor) handleCanaryTriggered(event *core.SecurityEvent) {
	canaryPath := getStringDetail(event, "canary_path")
	processName := getStringDetail(event, "process_name")

	i.raiseAlert(event, core.SeverityCritical,
		"Canary File Triggered",
		fmt.Sprintf("Canary file %s was accessed/modified by process %s. Strong indicator of ransomware or unauthorized file access.",
			canaryPath, processName),
		"canary_triggered")
}

// handleProcessExecution inspects command-line executions for shadow copy deletion,
// backup destruction, recovery disabling, and wiper-related commands.
// This catches ransomware pre-encryption preparation (T1490: Inhibit System Recovery).
func (i *Interceptor) handleProcessExecution(event *core.SecurityEvent) {
	commandLine := strings.ToLower(getStringDetail(event, "command_line"))
	processName := strings.ToLower(getStringDetail(event, "process_name"))

	if commandLine == "" && processName == "" {
		return
	}

	// Shadow copy / VSS deletion commands
	vssPatterns := []struct {
		pattern string
		desc    string
	}{
		{"vssadmin delete shadows", "vssadmin shadow copy deletion"},
		{"vssadmin resize shadowstorage", "vssadmin shadow storage resize (to zero)"},
		{"wmic shadowcopy delete", "WMI shadow copy deletion"},
		{"get-wmiobject win32_shadowcopy | foreach-object {$_.delete()}", "PowerShell WMI shadow copy deletion"},
		{"win32_shadowcopy", "WMI shadow copy manipulation"},
		{"delete shadows /all", "shadow copy bulk deletion"},
		{"delete shadows /quiet", "silent shadow copy deletion"},
	}

	for _, vp := range vssPatterns {
		if strings.Contains(commandLine, vp.pattern) {
			i.backupTracker.RecordEvent(event.SourceIP, "vss_delete")
			i.raiseAlert(event, core.SeverityCritical,
				"Shadow Copy Deletion Detected [T1490]",
				fmt.Sprintf("Command detected: %s (%s). Process: %s. MITRE ATT&CK T1490: Inhibit System Recovery. This is a critical pre-ransomware indicator.",
					vp.desc, commandLine, processName),
				"shadow_copy_delete")
			i.checkCompoundAttack(event)
			return
		}
	}

	// Backup destruction commands
	backupPatterns := []struct {
		pattern string
		desc    string
	}{
		{"wbadmin delete catalog", "Windows backup catalog deletion"},
		{"wbadmin delete systemstatebackup", "system state backup deletion"},
		{"bcdedit /set {default} recoveryenabled no", "Windows recovery disabled via bcdedit"},
		{"bcdedit /set {default} bootstatuspolicy ignoreallfailures", "boot failure recovery disabled"},
		{"bcdedit /set safeboot", "safe boot configuration tampering"},
		{"reagentc /disable", "Windows Recovery Environment disabled"},
		{"delete catalog -quiet", "quiet backup catalog deletion"},
	}

	for _, bp := range backupPatterns {
		if strings.Contains(commandLine, bp.pattern) {
			i.backupTracker.RecordEvent(event.SourceIP, "backup_destroy")
			i.raiseAlert(event, core.SeverityCritical,
				"Backup Destruction Detected [T1490]",
				fmt.Sprintf("Command detected: %s (%s). Process: %s. MITRE ATT&CK T1490: Inhibit System Recovery. Attacker is destroying recovery options.",
					bp.desc, commandLine, processName),
				"backup_destruction")
			i.checkCompoundAttack(event)
			return
		}
	}

	// Wiper / disk destruction commands
	wiperPatterns := []struct {
		pattern string
		desc    string
	}{
		{"format c:", "disk format command"},
		{"format d:", "disk format command"},
		{"cipher /w:", "disk overwrite via cipher"},
		{"sdelete", "secure deletion tool"},
		{"dd if=/dev/zero", "zero-fill disk wipe (Linux)"},
		{"dd if=/dev/urandom", "random overwrite disk wipe (Linux)"},
		{"shred -", "file shredding (Linux)"},
		{"wipefs", "filesystem signature wipe (Linux)"},
		{"mkfs.", "filesystem reformat (Linux)"},
		{"\\\\.\\.\\physicaldrive", "raw physical drive access"},
	}

	for _, wp := range wiperPatterns {
		if strings.Contains(commandLine, wp.pattern) {
			i.wiperTracker.RecordEvent(event.SourceIP, processName, "command_wipe")
			i.raiseAlert(event, core.SeverityCritical,
				"Wiper Activity Detected [T1561]",
				fmt.Sprintf("Destructive command detected: %s (%s). Process: %s. MITRE ATT&CK T1561: Disk Wipe. System destruction in progress.",
					wp.desc, commandLine, processName),
				"wiper_activity")
			return
		}
	}

	// Service stopping (often precedes ransomware encryption)
	serviceStopPatterns := []string{
		"net stop vss", "net stop sql", "net stop exchange",
		"net stop backup", "net stop veeam", "net stop sophos",
		"net stop mssql", "net stop mysql", "net stop oracle",
		"sc config vss start= disabled", "sc stop vss",
		"taskkill /f /im sqlservr", "taskkill /f /im oracle",
		"taskkill /f /im veeam", "taskkill /f /im backup",
	}

	for _, sp := range serviceStopPatterns {
		if strings.Contains(commandLine, sp) {
			i.backupTracker.RecordEvent(event.SourceIP, "service_stop")
			i.raiseAlert(event, core.SeverityHigh,
				"Critical Service Stopped [T1489]",
				fmt.Sprintf("Security/backup/database service stopped: %s. Process: %s. MITRE ATT&CK T1489: Service Stop. Ransomware often stops services before encryption.",
					commandLine, processName),
				"service_stop")
			i.checkCompoundAttack(event)
			return
		}
	}

	// 2025-2026: ESXi/hypervisor ransomware commands (Akira, ESXiArgs, etc.)
	// Hypervisor ransomware surged from 3% to 25% of encryption incidents in 2025.
	esxiPatterns := []struct {
		pattern string
		desc    string
	}{
		{"esxcli vm process kill", "ESXi VM process kill (pre-encryption)"},
		{"esxcli vm process list", "ESXi VM enumeration (reconnaissance)"},
		{"vim-cmd vmsvc/power.off", "ESXi VM power off via vim-cmd"},
		{"vim-cmd vmsvc/getallvms", "ESXi VM enumeration via vim-cmd"},
		{"esxcli storage filesystem list", "ESXi datastore enumeration"},
		{"esxcli system syslog config set", "ESXi syslog tampering (anti-forensics)"},
		{"esxcli network firewall set --enabled false", "ESXi firewall disabled"},
		{"/sbin/esxcli", "ESXi CLI tool execution"},
		{"openssl enc -aes", "OpenSSL encryption (Linux ransomware)"},
		{"chmod +x /tmp/encrypt", "Encryption binary staging in /tmp"},
	}

	for _, ep := range esxiPatterns {
		if strings.Contains(commandLine, ep.pattern) {
			i.raiseAlert(event, core.SeverityCritical,
				"ESXi/Hypervisor Ransomware Activity [T1486]",
				fmt.Sprintf("ESXi ransomware indicator: %s (%s). Process: %s. Hypervisor targeting can encrypt entire virtualized infrastructure in one strike.",
					ep.desc, commandLine, processName),
				"esxi_ransomware")
			return
		}
	}

	// 2025-2026: Linux-specific ransomware patterns
	linuxRansomPatterns := []struct {
		pattern string
		desc    string
	}{
		{"find / -name *.vmdk", "VMDK file enumeration (VM disk targeting)"},
		{"find / -name *.vmsn", "VM snapshot file enumeration"},
		{"find / -name *.vmem", "VM memory file enumeration"},
		{"chmod 777 /tmp/", "Permissive /tmp staging (ransomware deployment)"},
		{"nohup ./encrypt", "Background encryption process launch"},
		{"systemctl stop firewalld", "Linux firewall disabled"},
		{"iptables -f", "Linux iptables flushed"},
	}

	for _, lp := range linuxRansomPatterns {
		if strings.Contains(commandLine, lp.pattern) {
			i.raiseAlert(event, core.SeverityHigh,
				"Linux Ransomware Indicator [T1486]",
				fmt.Sprintf("Linux ransomware indicator: %s (%s). Process: %s.",
					lp.desc, commandLine, processName),
				"linux_ransomware")
			return
		}
	}
}

// handleShadowCopyDeletion handles direct shadow copy deletion events from OS-level monitoring.
func (i *Interceptor) handleShadowCopyDeletion(event *core.SecurityEvent) {
	method := getStringDetail(event, "method")
	processName := getStringDetail(event, "process_name")
	target := getStringDetail(event, "target")

	if method == "" {
		method = "unknown"
	}

	i.backupTracker.RecordEvent(event.SourceIP, "vss_delete")

	i.raiseAlert(event, core.SeverityCritical,
		"Shadow Copy Deletion Detected [T1490]",
		fmt.Sprintf("Volume Shadow Copy deletion detected via %s. Process: %s, Target: %s. MITRE ATT&CK T1490: Inhibit System Recovery. This is a critical pre-ransomware indicator — attackers delete shadow copies to prevent file recovery.",
			method, processName, target),
		"shadow_copy_delete")

	i.checkCompoundAttack(event)
}

// handleBackupDestruction handles backup deletion/corruption events.
func (i *Interceptor) handleBackupDestruction(event *core.SecurityEvent) {
	backupType := getStringDetail(event, "backup_type")
	processName := getStringDetail(event, "process_name")
	action := getStringDetail(event, "action")
	target := getStringDetail(event, "target")

	if backupType == "" {
		backupType = "unknown"
	}
	if action == "" {
		action = "destroyed"
	}

	i.backupTracker.RecordEvent(event.SourceIP, "backup_destroy")

	i.raiseAlert(event, core.SeverityCritical,
		"Backup Destruction Detected [T1490]",
		fmt.Sprintf("Backup %s detected. Type: %s, Target: %s, Process: %s. MITRE ATT&CK T1490: Inhibit System Recovery. Attacker is eliminating recovery options before deploying ransomware.",
			action, backupType, target, processName),
		"backup_destruction")

	i.checkCompoundAttack(event)
}

// handleWiperActivity handles disk wipe, MBR overwrite, and partition destruction events.
func (i *Interceptor) handleWiperActivity(event *core.SecurityEvent) {
	wiperType := getStringDetail(event, "wiper_type")
	processName := getStringDetail(event, "process_name")
	target := getStringDetail(event, "target")
	bytesWritten := getIntDetail(event, "bytes_written")
	writeOffset := getIntDetail(event, "offset")

	if wiperType == "" {
		wiperType = event.Type
	}

	// Missing or malformed offsets must not become an asserted boot-sector write.
	offsetValue := event.Details["offset"]
	hasOffset := false
	switch value := offsetValue.(type) {
	case int:
		hasOffset = value >= 0
	case float64:
		hasOffset = value >= 0 && !math.IsInf(value, 0) && value == math.Trunc(value)
	default:
		hasOffset = false
	}
	rawDisk := rawDiskTarget.MatchString(target)
	if event.Type == "disk_write" && (!rawDisk || !hasOffset) {
		return
	}
	if event.Type == "mbr_write" || (event.Type == "disk_write" && rawDisk && hasOffset && writeOffset == 0) {
		i.raiseAlert(event, core.SeverityCritical,
			"MBR/GPT Overwrite Detected [T1561.002]",
			fmt.Sprintf("Boot-sector write reported. Process: %s, Target: %s, Bytes: %d, Offset: %d. MITRE ATT&CK T1561.002: possible Disk Structure Wipe. Verify authorized disk maintenance. Response depends on enforcement policy and mode.",
				processName, target, bytesWritten, writeOffset),
			"mbr_overwrite")
		return
	}

	// Explicit partition telemetry is routed through the ordinary response policy.
	if event.Type == "partition_write" {
		i.raiseAlert(event, core.SeverityCritical,
			"Partition Table Destruction [T1561.002]",
			fmt.Sprintf("Partition table modification reported. Process: %s, Target: %s, Bytes: %d. MITRE ATT&CK T1561.002: possible Disk Structure Wipe. Response depends on enforcement policy and mode.",
				processName, target, bytesWritten),
			"partition_destroy")
		return
	}

	// Check for zero-fill or random-fill wipe patterns
	pattern := getStringDetail(event, "write_pattern")
	if pattern == "" && (wiperType == "zero_fill" || wiperType == "random_fill") {
		pattern = wiperType
	}
	if event.Type == "disk_write" && pattern != "zero_fill" && pattern != "random_fill" {
		return
	}
	i.wiperTracker.RecordEvent(event.SourceIP, processName, wiperType)
	severity := core.SeverityCritical
	title := "Disk Wipe Activity Detected [T1561.001]"
	desc := fmt.Sprintf("Disk wipe activity detected. Type: %s, Process: %s, Target: %s, Bytes written: %d",
		wiperType, processName, target, bytesWritten)

	if pattern == "zero_fill" {
		desc += ". Write pattern: zero-fill (all 0x00 bytes). MITRE ATT&CK T1561.001: Disk Content Wipe."
	} else if pattern == "random_fill" {
		desc += ". Write pattern: random data overwrite. MITRE ATT&CK T1561.001: Disk Content Wipe."
	} else {
		desc += fmt.Sprintf(". MITRE ATT&CK T1561: Disk Wipe.")
	}

	// Track cumulative wipe activity — escalate to active response on rapid wiping
	stats := i.wiperTracker.GetStats(event.SourceIP)
	if stats.EventCount > 3 {
		desc += fmt.Sprintf(" ESCALATION: %d wipe events from this host in %s. Response depends on enforcement policy and mode.",
			stats.EventCount, stats.Duration.String())
		i.raiseAlert(event, severity, title, desc, "wiper_activity")
		return
	}

	i.raiseAlert(event, severity, title, desc, "wiper_activity")
}

// checkCompoundAttack detects when multiple pre-ransomware indicators fire together,
// which is a near-certain sign of imminent ransomware deployment.
func (i *Interceptor) checkCompoundAttack(event *core.SecurityEvent) {
	stats := i.backupTracker.GetStats(event.SourceIP)

	// If we see VSS deletion + backup destruction + service stops from the same host,
	// this is a compound ransomware preparation attack
	indicators := 0
	if stats.VSSDeletes > 0 {
		indicators++
	}
	if stats.BackupDestroys > 0 {
		indicators++
	}
	if stats.ServiceStops > 0 {
		indicators++
	}

	if indicators >= 2 {
		i.raiseAlert(event, core.SeverityCritical,
			"COMPOUND RANSOMWARE PREPARATION [T1490+T1489]",
			fmt.Sprintf("Multiple ransomware preparation indicators detected from %s: %d VSS deletions, %d backup destructions, %d service stops in %s. MITRE ATT&CK T1490+T1489. IMMEDIATE ACTION REQUIRED: Ransomware deployment is imminent. Isolate this host NOW.",
				event.SourceIP, stats.VSSDeletes, stats.BackupDestroys, stats.ServiceStops, stats.Duration.String()),
			"compound_ransomware_prep")
	}
}

// handleHypervisorAttack detects ESXi/hypervisor-targeted ransomware activity.
// 2025-2026 threat: Akira, ESXiArgs, and other groups targeting VMware ESXi directly.
// Hypervisor ransomware surged from 3% to 25% of encryption incidents in H2 2025.
// Attackers use SSH tunneling, native esxcli commands, and LotL techniques.
// References: Huntress 2025 report, Sygnia ESXi SSH tunneling research, CrowdStrike ESXi detection.
func (i *Interceptor) handleHypervisorAttack(event *core.SecurityEvent) {
	action := strings.ToLower(getStringDetail(event, "action"))
	vmName := getStringDetail(event, "vm_name")
	datastore := getStringDetail(event, "datastore")
	processName := getStringDetail(event, "process_name")
	commandLine := strings.ToLower(getStringDetail(event, "command_line"))
	vmCount := getIntDetail(event, "vm_count")

	// VM encryption event (direct VMDK/snapshot encryption)
	if event.Type == "vm_encryption" {
		desc := fmt.Sprintf("Virtual machine encryption detected. VM: %s, Datastore: %s, Process: %s.",
			vmName, datastore, processName)
		if vmCount > 1 {
			desc += fmt.Sprintf(" %d VMs affected — mass VM encryption in progress.", vmCount)
		}
		desc += " MITRE ATT&CK T1486. Hypervisor-level encryption can destroy entire virtualized infrastructure."
		i.raiseAlert(event, core.SeverityCritical,
			"VM Encryption Detected [T1486]",
			desc,
			"vm_encryption")
		return
	}

	// ESXi SSH tunneling (C2 via SSH SOCKS proxy)
	if strings.Contains(commandLine, "ssh") && (strings.Contains(commandLine, "-d") || strings.Contains(commandLine, "socks") || strings.Contains(commandLine, "-r")) {
		i.raiseAlert(event, core.SeverityCritical,
			"ESXi SSH Tunneling Detected [T1572]",
			fmt.Sprintf("SSH tunnel established on ESXi host: %s. Attackers use SSH SOCKS tunnels to proxy C2 traffic through ESXi, blending with legitimate admin traffic.",
				commandLine),
			"esxi_ssh_tunnel")
		return
	}

	// ESXi configuration tampering
	if strings.Contains(action, "config_change") || strings.Contains(action, "firewall_disable") ||
		strings.Contains(action, "syslog_disable") {
		i.raiseAlert(event, core.SeverityHigh,
			"ESXi Configuration Tampering",
			fmt.Sprintf("ESXi configuration modified: %s. Action: %s. Attackers tamper with ESXi configs to disable logging and security controls before encryption.",
				commandLine, action),
			"esxi_config_tamper")
		return
	}

	// VM power-off (pre-encryption step — VMs must be off to encrypt VMDK files)
	if strings.Contains(action, "power_off") || strings.Contains(action, "vm_kill") {
		desc := fmt.Sprintf("VM power-off detected: %s. Process: %s.", vmName, processName)
		if vmCount > 2 {
			desc += fmt.Sprintf(" %d VMs powered off — likely pre-encryption preparation.", vmCount)
		}
		i.raiseAlert(event, core.SeverityHigh,
			"Mass VM Power-Off Detected [T1529]",
			desc,
			"vm_power_off")
		return
	}

	// Snapshot deletion (removing recovery points)
	if strings.Contains(action, "snapshot_delete") || strings.Contains(action, "snapshot_remove") {
		i.raiseAlert(event, core.SeverityHigh,
			"VM Snapshot Deletion Detected [T1490]",
			fmt.Sprintf("VM snapshot deletion: VM=%s, Action=%s. Removing snapshots eliminates recovery options before encryption.",
				vmName, action),
			"vm_snapshot_delete")
	}
}

// handleCredentialHarvesting detects pre-ransomware credential harvesting.
// 2025-2026 threat: ransomware operators increasingly harvest credentials before
// deploying encryption to enable lateral movement and maximize blast radius.
// References: Splunk 2026 ransomware trends, Microsoft Storm-0501 analysis.
func (i *Interceptor) handleCredentialHarvesting(event *core.SecurityEvent) {
	technique := strings.ToLower(getStringDetail(event, "technique"))
	toolName := strings.ToLower(getStringDetail(event, "tool_name"))
	processName := strings.ToLower(getStringDetail(event, "process_name"))
	target := getStringDetail(event, "target")

	// Check specific techniques first (before generic tool matching)

	// LSASS memory access
	if technique == "lsass_dump" || technique == "lsass_access" || strings.Contains(target, "lsass") {
		i.raiseAlert(event, core.SeverityCritical,
			"LSASS Memory Access Detected [T1003.001]",
			fmt.Sprintf("LSASS process memory accessed by %s. Technique: %s. MITRE ATT&CK T1003.001: LSASS Memory. Credential theft enables lateral movement for ransomware deployment.",
				processName, technique),
			"lsass_access")
		return
	}

	// NTLM hash extraction
	if technique == "ntlm_dump" || technique == "sam_dump" || technique == "ntds_dump" {
		i.raiseAlert(event, core.SeverityCritical,
			"NTLM/SAM Hash Extraction [T1003.002]",
			fmt.Sprintf("Credential hash extraction detected. Technique: %s, Process: %s, Target: %s. MITRE ATT&CK T1003.002/003. Extracted hashes enable pass-the-hash attacks for ransomware propagation.",
				technique, processName, target),
			"ntlm_hash_extraction")
		return
	}

	// Kerberos ticket theft
	if technique == "kerberoasting" || technique == "ticket_dump" || technique == "golden_ticket" {
		i.raiseAlert(event, core.SeverityCritical,
			"Kerberos Credential Theft [T1558]",
			fmt.Sprintf("Kerberos credential theft detected. Technique: %s, Process: %s. MITRE ATT&CK T1558. Kerberos tickets enable domain-wide ransomware deployment.",
				technique, processName),
			"kerberos_theft")
		return
	}

	// Known credential dumping tools
	knownTools := []struct {
		name string
		desc string
	}{
		{"mimikatz", "Mimikatz credential dumper"},
		{"lazagne", "LaZagne credential recovery"},
		{"secretsdump", "Impacket secretsdump"},
		{"pypykatz", "Python Mimikatz implementation"},
		{"nanodump", "Nanodump LSASS dumper"},
		{"procdump", "ProcDump (potential LSASS dump)"},
		{"comsvcs.dll", "LSASS dump via comsvcs.dll"},
	}

	for _, kt := range knownTools {
		if strings.Contains(toolName, kt.name) || strings.Contains(processName, kt.name) {
			i.raiseAlert(event, core.SeverityCritical,
				"Credential Dumping Tool Detected [T1003]",
				fmt.Sprintf("Credential dumping tool detected: %s. Process: %s, Target: %s. MITRE ATT&CK T1003: OS Credential Dumping. This is a common pre-ransomware lateral movement technique.",
					kt.desc, processName, target),
				"credential_dump")
			return
		}
	}

	// Generic credential access
	if technique != "" || toolName != "" {
		i.raiseAlert(event, core.SeverityHigh,
			"Pre-Ransomware Credential Access [T1003]",
			fmt.Sprintf("Credential access detected. Technique: %s, Tool: %s, Process: %s, Target: %s. Credential harvesting often precedes ransomware deployment.",
				technique, toolName, processName, target),
			"credential_access")
	}
}

func (i *Interceptor) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if i.bus != nil {
		_ = i.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.EventIDs = append(alert.EventIDs, event.ID)
	alert.Metadata["original_event_id"] = event.ID
	processHost := getStringDetail(event, "hostname")
	if processHost == "" {
		processHost = event.SourceIP
	}
	if processHost == "" {
		processHost = getStringDetail(event, "host_id")
	}
	if processHost != "" {
		alert.Metadata["process_host"] = processHost
	}
	if alertType != "data_exfiltration" && alertType != "compound_ransomware_prep" {
		if name := getStringDetail(event, "process_name"); name != "" {
			alert.Metadata["process_name"] = name
		}
		if pid := processID(event); pid != "" {
			alert.Metadata["process_id"] = pid
		}
	}
	if path := getStringDetail(event, "path"); path != "" {
		// This may be victim data or a raw disk, not a malicious artifact.
		alert.Metadata["affected_path"] = path
	}
	alert.Mitigations = getRansomwareMitigations(alertType)
	if i.pipeline != nil {
		i.pipeline.Process(alert)
	}
}

// getRansomwareMitigations returns context-specific mitigations based on alert type.
func getRansomwareMitigations(alertType string) []string {
	base := []string{
		"Immediately isolate the affected system from the network",
		"Preserve forensic evidence for investigation",
	}

	switch alertType {
	case "shadow_copy_delete", "backup_destruction", "compound_ransomware_prep":
		return append(base,
			"Verify offline/air-gapped backup integrity immediately",
			"Block the responsible process and user account",
			"Check for lateral movement to other systems",
			"Ransomware deployment is likely imminent — escalate to incident response",
			"Do NOT restart the system — it may trigger encryption payload",
		)
	case "wiper_activity", "mbr_overwrite", "partition_destroy":
		return append(base,
			"This is a DESTRUCTIVE attack — data recovery may not be possible",
			"Power off affected systems to prevent further destruction",
			"Do NOT attempt to reboot — MBR/partition may be destroyed",
			"Engage disk forensics team for potential data recovery",
			"Check for wiper propagation to other networked systems",
		)
	case "service_stop":
		return append(base,
			"Restart critical services if safe to do so",
			"Monitor for subsequent encryption activity",
			"Verify backup service availability",
		)
	case "data_exfiltration":
		return append(base,
			"Block outbound connections from the affected host",
			"Identify what data was transferred and to where",
			"This may indicate double-extortion ransomware (encrypt + leak)",
		)
	// 2025-2026: intermittent/partial encryption
	case "intermittent_encryption":
		return append(base,
			"Intermittent encryption evades entropy-based detection — do not rely solely on entropy monitoring",
			"Terminate the encrypting process immediately",
			"Check file headers for corruption even if entropy appears normal",
			"Restore affected files from immutable backups",
		)
	// 2025-2026: ESXi/hypervisor ransomware
	case "esxi_ransomware", "vm_encryption", "esxi_ssh_tunnel", "esxi_config_tamper", "vm_power_off", "vm_snapshot_delete":
		return append(base,
			"Disable SSH on ESXi hosts when not in active maintenance",
			"Enable ESXi lockdown mode to restrict management access",
			"Stream ESXi logs to external SIEM — attackers tamper with local logs",
			"Maintain offline backups of VM configurations and VMDK files",
			"Restrict ESXi management to dedicated jump hosts with MFA",
		)
	// 2025-2026: Linux ransomware
	case "linux_ransomware":
		return append(base,
			"Audit /tmp and world-writable directories for suspicious binaries",
			"Implement application allowlisting on Linux servers",
			"Monitor for unusual file enumeration patterns (find commands targeting VM files)",
		)
	// 2025-2026: pre-ransomware credential harvesting
	case "credential_dump", "lsass_access", "ntlm_hash_extraction", "kerberos_theft", "credential_access":
		return append(base,
			"Enable Credential Guard and VBS key isolation on Windows endpoints",
			"Rotate all potentially compromised credentials immediately",
			"Check for lateral movement — credential theft precedes ransomware deployment",
			"Implement LSASS protection (RunAsPPL) on all Windows systems",
			"Monitor for pass-the-hash and pass-the-ticket activity",
		)
	default:
		return append(base,
			"Identify and terminate the malicious process",
			"Verify backup integrity before attempting restoration",
			"Do not pay the ransom — it does not guarantee data recovery",
		)
	}
}

// ---------------------------------------------------------------------------
// WiperTracker monitors disk wipe activity patterns.
// ---------------------------------------------------------------------------

type WiperTracker struct {
	mu      sync.RWMutex
	records map[string]*wiperRecord // sourceIP -> record
}

type wiperRecord struct {
	events    []wiperEvent
	firstSeen time.Time
	lastSeen  time.Time
}

type wiperEvent struct {
	timestamp   time.Time
	processName string
	wiperType   string
}

type WiperStats struct {
	EventCount int
	Duration   time.Duration
}

func NewWiperTracker() *WiperTracker {
	return &WiperTracker{
		records: make(map[string]*wiperRecord),
	}
}

func (wt *WiperTracker) RecordEvent(sourceIP, processName, wiperType string) {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	now := time.Now()
	rec, exists := wt.records[sourceIP]
	if !exists {
		rec = &wiperRecord{
			firstSeen: now,
		}
		wt.records[sourceIP] = rec
	}

	rec.events = append(rec.events, wiperEvent{
		timestamp:   now,
		processName: processName,
		wiperType:   wiperType,
	})
	rec.lastSeen = now
}

func (wt *WiperTracker) GetStats(sourceIP string) WiperStats {
	wt.mu.RLock()
	defer wt.mu.RUnlock()

	rec, exists := wt.records[sourceIP]
	if !exists {
		return WiperStats{}
	}
	return WiperStats{
		EventCount: len(rec.events),
		Duration:   rec.lastSeen.Sub(rec.firstSeen),
	}
}

func (wt *WiperTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wt.mu.Lock()
			cutoff := time.Now().Add(-1 * time.Hour)
			for ip, rec := range wt.records {
				if rec.lastSeen.Before(cutoff) {
					delete(wt.records, ip)
				}
			}
			wt.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// BackupDestructionTracker monitors backup/VSS/service-stop compound attacks.
// ---------------------------------------------------------------------------

type BackupDestructionTracker struct {
	mu      sync.RWMutex
	records map[string]*backupDestructionRecord // sourceIP -> record
}

type backupDestructionRecord struct {
	vssDeletes     int
	backupDestroys int
	serviceStops   int
	firstSeen      time.Time
	lastSeen       time.Time
}

type BackupDestructionStats struct {
	VSSDeletes     int
	BackupDestroys int
	ServiceStops   int
	Duration       time.Duration
}

func NewBackupDestructionTracker() *BackupDestructionTracker {
	return &BackupDestructionTracker{
		records: make(map[string]*backupDestructionRecord),
	}
}

func (bt *BackupDestructionTracker) RecordEvent(sourceIP, eventType string) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := time.Now()
	rec, exists := bt.records[sourceIP]
	if !exists || now.Sub(rec.lastSeen) > 30*time.Minute {
		rec = &backupDestructionRecord{
			firstSeen: now,
		}
		bt.records[sourceIP] = rec
	}

	switch eventType {
	case "vss_delete":
		rec.vssDeletes++
	case "backup_destroy":
		rec.backupDestroys++
	case "service_stop":
		rec.serviceStops++
	}
	rec.lastSeen = now
}

func (bt *BackupDestructionTracker) GetStats(sourceIP string) BackupDestructionStats {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	rec, exists := bt.records[sourceIP]
	if !exists {
		return BackupDestructionStats{}
	}
	return BackupDestructionStats{
		VSSDeletes:     rec.vssDeletes,
		BackupDestroys: rec.backupDestroys,
		ServiceStops:   rec.serviceStops,
		Duration:       rec.lastSeen.Sub(rec.firstSeen),
	}
}

func (bt *BackupDestructionTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bt.mu.Lock()
			cutoff := time.Now().Add(-1 * time.Hour)
			for ip, rec := range bt.records {
				if rec.lastSeen.Before(cutoff) {
					delete(bt.records, ip)
				}
			}
			bt.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// FileActivityTracker monitors file modification patterns for ransomware behavior.
// ---------------------------------------------------------------------------

type FileActivityTracker struct {
	mu                  sync.RWMutex
	processActivity     map[string]*processFileActivity
	encryptionThreshold int
}

type processFileActivity struct {
	modifiedFiles map[string]float64
	renamedFiles  map[string]bool
	transitions   map[string]bool
	totalEntropy  float64
	entropyCount  int
	firstSeen     time.Time
	lastSeen      time.Time
}

type ActivityResult struct {
	MassEncryption        bool
	HighEntropy           bool
	RapidRename           bool
	FileCount             int
	RenameCount           int
	AvgEntropy            float64
	Duration              time.Duration
	EncryptionTransitions int
}

func NewFileActivityTracker(threshold int) *FileActivityTracker {
	if threshold <= 0 {
		threshold = 5
	}
	return &FileActivityTracker{
		processActivity:     make(map[string]*processFileActivity),
		encryptionThreshold: threshold,
	}
}

func (ft *FileActivityTracker) RecordModification(process, path string, entropy float64) ActivityResult {
	return ft.recordActivity(process, path, entropy, isRansomwareExtension(path), false)
}

func (ft *FileActivityTracker) recordActivity(process, path string, entropy float64, renamed, transitioned bool) ActivityResult {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	result := ActivityResult{}
	if process == "" || path == "" {
		return result
	}
	now := time.Now()

	activity, exists := ft.processActivity[process]
	if !exists || now.Sub(activity.firstSeen) >= 5*time.Minute {
		activity = &processFileActivity{
			modifiedFiles: make(map[string]float64),
			renamedFiles:  make(map[string]bool),
			transitions:   make(map[string]bool),
			firstSeen:     now,
		}
		ft.processActivity[process] = activity
	}

	activity.lastSeen = now

	// Keep one current entropy sample per distinct file, not one vote per write.
	if previous, ok := activity.modifiedFiles[path]; ok && previous > 0 {
		activity.totalEntropy -= previous
		activity.entropyCount--
	}
	if math.IsNaN(entropy) || math.IsInf(entropy, 0) || entropy < 0 || entropy > 8 {
		entropy = 0
	}
	activity.modifiedFiles[path] = entropy
	if entropy > 7 && transitioned {
		activity.transitions[path] = true
	} else {
		delete(activity.transitions, path)
	}
	if entropy > 0 {
		activity.totalEntropy += entropy
		activity.entropyCount++
	}

	result.FileCount = len(activity.modifiedFiles)
	result.EncryptionTransitions = len(activity.transitions)
	result.Duration = now.Sub(activity.firstSeen)

	if activity.entropyCount > 0 {
		result.AvgEntropy = activity.totalEntropy / float64(activity.entropyCount)
	}

	// High entropy indicates encryption (random data has entropy ~8.0)
	if entropy > 7.5 {
		result.HighEntropy = true
	}

	// Mass encryption: many files modified with high average entropy
	if activity.entropyCount >= ft.encryptionThreshold && result.AvgEntropy > 7.0 {
		result.MassEncryption = true
	}

	// Rapid rename detection
	if renamed {
		activity.renamedFiles[path] = true
	}
	result.RenameCount = len(activity.renamedFiles)
	if result.RenameCount > 5 && result.Duration < 2*time.Minute {
		result.RapidRename = true
	}

	return result
}

func (ft *FileActivityTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ft.mu.Lock()
			cutoff := time.Now().Add(-30 * time.Minute)
			for proc, activity := range ft.processActivity {
				if activity.lastSeen.Before(cutoff) {
					delete(ft.processActivity, proc)
				}
			}
			ft.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// ExfilTracker monitors data egress for exfiltration detection.
// ---------------------------------------------------------------------------

type ExfilTracker struct {
	mu        sync.RWMutex
	records   *lru.Cache[string, *exfilRecord] // sourceIP -> record
	threshold int64
}

type exfilRecord struct {
	totalBytes            int64
	destinations          map[string]bool
	destinationsTruncated bool
	firstSeen             time.Time
	lastSeen              time.Time
}

type ExfilStats struct {
	TotalBytes            int64
	UniqueDestinations    int
	DestinationsTruncated bool
	CapacityEvicted       bool
}

func NewExfilTracker(thresholdBytes int64) *ExfilTracker {
	records, _ := lru.New[string, *exfilRecord](4096)
	return &ExfilTracker{
		records:   records,
		threshold: thresholdBytes,
	}
}

func (et *ExfilTracker) Record(sourceIP, destIP string, bytes int64) bool {
	exceeded, _ := et.record(sourceIP, destIP, bytes)
	return exceeded
}

func (et *ExfilTracker) record(sourceIP, destIP string, bytes int64) (bool, ExfilStats) {
	et.mu.Lock()
	defer et.mu.Unlock()
	if sourceIP == "" || bytes <= 0 {
		return false, ExfilStats{}
	}

	now := time.Now()
	rec, exists := et.records.Get(sourceIP)
	evicted := false
	if !exists || now.Sub(rec.firstSeen) > time.Hour {
		rec = &exfilRecord{
			destinations: make(map[string]bool),
			firstSeen:    now,
		}
		evicted = et.records.Add(sourceIP, rec)
	}

	if bytes > math.MaxInt64-rec.totalBytes {
		rec.totalBytes = math.MaxInt64
	} else {
		rec.totalBytes += bytes
	}
	rec.lastSeen = now
	if destIP != "" {
		if len(rec.destinations) < 256 || rec.destinations[destIP] {
			rec.destinations[destIP] = true
		} else {
			rec.destinationsTruncated = true
		}
	}

	return rec.totalBytes > et.threshold, ExfilStats{TotalBytes: rec.totalBytes, UniqueDestinations: len(rec.destinations), DestinationsTruncated: rec.destinationsTruncated, CapacityEvicted: evicted}
}

func (et *ExfilTracker) GetStats(sourceIP string) ExfilStats {
	et.mu.RLock()
	defer et.mu.RUnlock()

	rec, exists := et.records.Peek(sourceIP)
	if !exists {
		return ExfilStats{}
	}
	return ExfilStats{
		TotalBytes:            rec.totalBytes,
		UniqueDestinations:    len(rec.destinations),
		DestinationsTruncated: rec.destinationsTruncated,
	}
}

func (et *ExfilTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			et.mu.Lock()
			cutoff := time.Now().Add(-2 * time.Hour)
			for _, ip := range et.records.Keys() {
				rec, _ := et.records.Peek(ip)
				if rec.lastSeen.Before(cutoff) {
					et.records.Remove(ip)
				}
			}
			et.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func isRansomwareExtension(path string) bool {
	ransomExts := []string{
		".encrypted", ".locked", ".crypto", ".crypt",
		".locky", ".cerber", ".zepto", ".thor",
		".aesir", ".zzzzz", ".micro", ".enc",
		".crypted", ".crinf", ".r5a", ".xrtn",
		".xtbl", ".crypt1", ".da_vinci_code",
		".magic", ".SUPERCRYPT", ".CTBL", ".CTB2",
		".wncry", ".wcry", ".wncryt", ".WNCRYPT",
		".petya", ".notpetya", ".gandcrab",
		".ryuk", ".sodinokibi", ".revil",
		".conti", ".lockbit", ".blackcat",
		".alphv", ".hive", ".royal",
		".play", ".blackbasta", ".akira",
		".rhysida", ".medusa", ".bianlian",
	}
	pathLower := strings.ToLower(path)
	for _, ext := range ransomExts {
		if strings.HasSuffix(pathLower, strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

func isRansomNote(path string) bool {
	notePatterns := []string{
		"readme", "how_to_decrypt", "how_to_recover",
		"decrypt_instructions", "ransom", "restore_files",
		"your_files", "attention", "warning",
		"recovery_key", "decrypt_your_files",
		"!readme!", "help_decrypt", "read_me",
		"_readme_", "how_to_back", "restore_data",
		"recover_your_files", "files_encrypted",
		"important_read_me", "decrypt_info",
	}
	pathLower := strings.ToLower(path)
	for _, pattern := range notePatterns {
		if strings.Contains(pathLower, pattern) {
			ext := strings.ToLower(pathAfterLastDot(path))
			if ext == "txt" || ext == "html" || ext == "hta" || ext == "" {
				return true
			}
		}
	}
	return false
}

func pathAfterLastDot(s string) string {
	idx := strings.LastIndex(s, ".")
	if idx < 0 {
		return ""
	}
	return s[idx+1:]
}

// ShannonEntropy calculates the Shannon entropy of a byte slice.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}
	length := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
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

// processID preserves valid numeric or string collector PIDs for response executors.
func processID(event *core.SecurityEvent) string {
	value := event.Details["process_id"]
	if value == nil {
		value = event.Details["pid"]
	}
	var pid int64
	switch v := value.(type) {
	case string:
		parsed, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return ""
		}
		pid = parsed
	case int:
		pid = int64(v)
	case int64:
		pid = v
	case json.Number:
		parsed, ok := core.ParseProcessIDNumber(v)
		if !ok {
			return ""
		}
		return parsed
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) || v > math.MaxInt32 {
			return ""
		}
		pid = int64(v)
	}
	if pid <= 0 || pid > math.MaxInt32 {
		return ""
	}
	return strconv.FormatInt(pid, 10)
}

func getIntDetail(event *core.SecurityEvent, key string) int {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func getFloatDetail(event *core.SecurityEvent, key string) float64 {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
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
