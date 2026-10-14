package iot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "iot_shield"

// Shield is the IoT & OT Shield module providing device fingerprinting,
// protocol anomaly detection, firmware integrity verification, default credential
// scanning, rogue device detection, OT command validation, device behavior
// baseline monitoring, network segmentation enforcement, and firmware CVE tracking.
type Shield struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	cfg          *core.Config
	ctx          context.Context
	cancel       context.CancelFunc
	inventory    *DeviceInventory
	anomalyDet   *ProtocolAnomalyDetector
	behaviorMon  *DeviceBehaviorMonitor
	otValidator  *OTCommandValidator
	credScanner  *CredentialScanner
	fwIntegrity  *FirmwareIntegrityDB
	segEnforcer  *SegmentationEnforcer
	accessPolicy *core.ManagementAccessPolicy
}

func New() *Shield { return &Shield{} }

func (s *Shield) Name() string { return ModuleName }
func (s *Shield) Description() string {
	return "IoT/OT device fingerprinting, protocol anomaly detection, firmware integrity, default credential scanning, rogue device detection, OT command validation, device behavior baselining, network segmentation enforcement, and firmware vulnerability tracking"
}
func (s *Shield) EventTypes() []string {
	return []string{
		"device_connect", "device_activity", "iot_traffic",
		"protocol_message",
		"firmware_update", "firmware_check",
		"ot_command", "scada_command", "plc_command",
		"management_access", "management_exposure",
		"network_flow", "iot_network",
		// 2025-2026: persistent firmware implants, ICS wiper malware, coordinated OT attacks
		"firmware_boot", "firmware_flash",
		"ot_wiper", "ics_destructive",
		"ot_coordinated", "multi_protocol_attack",
	}
}

func (s *Shield) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	policy, err := core.NewManagementAccessPolicy(cfg.ManagementAccess)
	if err != nil {
		return err
	}
	s.accessPolicy = policy
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.bus = bus
	s.pipeline = pipeline
	s.cfg = cfg
	s.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)

	s.inventory = NewDeviceInventory()
	s.anomalyDet = NewProtocolAnomalyDetector()
	s.behaviorMon = NewDeviceBehaviorMonitor(settings)
	s.otValidator = NewOTCommandValidator()
	s.credScanner = NewCredentialScanner()
	s.fwIntegrity = NewFirmwareIntegrityDB()
	s.segEnforcer = NewSegmentationEnforcer(settings)

	go s.inventory.CleanupLoop(s.ctx)
	go s.behaviorMon.CleanupLoop(s.ctx)
	go s.anomalyDet.CleanupLoop(s.ctx)

	s.logger.Info().Msg("IoT & OT shield started")
	return nil
}

func (s *Shield) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Shield) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "device_connect", "device_activity", "iot_traffic":
		s.handleDeviceEvent(event)
	case "protocol_message":
		s.handleProtocolEvent(event)
	case "firmware_update", "firmware_check":
		s.handleFirmwareEvent(event)
	case "ot_command", "scada_command", "plc_command":
		s.handleOTCommand(event)
	case "management_access":
		s.handleManagementAccess(event)
	case "management_exposure":
		if exposed, _ := event.Details["publicly_reachable"].(bool); exposed {
			s.raiseAlert(event, core.SeverityCritical, "Management Interface Exposed to Internet",
				fmt.Sprintf("Management interface for %s is publicly reachable. Restrict access to a protected management network.", getStringDetail(event, "target")), "management_exposure")
		}
	case "network_flow", "iot_network":
		s.handleNetworkFlow(event)
	// 2025-2026: persistent firmware implants (HiatusRAT-X, bootloader rootkits)
	case "firmware_boot", "firmware_flash":
		s.handleFirmwareImplant(event)
	// 2025-2026: ICS-specific wiper/destructive malware (VoltRuptor-style)
	case "ot_wiper", "ics_destructive":
		s.handleICSWiper(event)
	// 2025-2026: coordinated multi-protocol OT attacks
	case "ot_coordinated", "multi_protocol_attack":
		s.handleCoordinatedOTAttack(event)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------

func (s *Shield) handleDeviceEvent(event *core.SecurityEvent) {
	deviceID := getStringDetail(event, "device_id")
	deviceType := getStringDetail(event, "device_type")
	mac := getStringDetail(event, "mac_address")
	firmware := getStringDetail(event, "firmware_version")
	vendor := getStringDetail(event, "vendor")
	protocol := getStringDetail(event, "protocol")

	if deviceID == "" && mac == "" {
		return
	}
	if deviceID == "" {
		deviceID = mac
	}

	// Register device and detect new/rogue devices
	regResult := s.inventory.Register(deviceID, deviceType, mac, firmware, vendor, event.SourceIP)

	if regResult.IsNew {
		s.raiseAlert(event, core.SeverityMedium,
			"New IoT Device Detected",
			fmt.Sprintf("New device on network: ID=%s type=%s vendor=%s IP=%s MAC=%s firmware=%s",
				deviceID, deviceType, vendor, event.SourceIP, mac, firmware),
			"new_device")
	}

	if regResult.IPChanged {
		s.raiseAlert(event, core.SeverityHigh,
			"IoT Device IP Address Changed",
			fmt.Sprintf("Device %s (%s) changed IP from %s to %s. Possible device spoofing or DHCP manipulation.",
				deviceID, deviceType, regResult.PreviousIP, event.SourceIP),
			"device_ip_change")
	}

	if regResult.FirmwareDowngrade {
		s.raiseAlert(event, core.SeverityCritical,
			"Firmware Downgrade Detected",
			fmt.Sprintf("Device %s firmware downgraded from %s to %s. Firmware downgrades can reintroduce patched vulnerabilities.",
				deviceID, regResult.PreviousFirmware, firmware),
			"firmware_downgrade")
	}

	// Credential scanning
	username := getStringDetail(event, "username")
	password := getStringDetail(event, "password")
	if username != "" {
		if finding := s.credScanner.Check(username, password, deviceType, vendor); finding != "" {
			s.raiseAlert(event, core.SeverityCritical,
				"Default/Weak Credentials Detected",
				fmt.Sprintf("Device %s (%s, vendor: %s) is using %s (user: %s)",
					deviceID, deviceType, vendor, finding, username),
				"default_credentials")
		}
	}

	// Behavior baseline analysis
	anomaly := s.behaviorMon.RecordActivity(deviceID, deviceType, protocol, event.SourceIP)
	if anomaly.UnusualProtocol {
		s.raiseAlert(event, core.SeverityHigh,
			"IoT Device Using Unusual Protocol",
			fmt.Sprintf("Device %s (%s) is using protocol %s for the first time. Known protocols: %s",
				deviceID, deviceType, protocol, strings.Join(anomaly.KnownProtocols, ", ")),
			"unusual_protocol")
	}
	if anomaly.ActivitySpike {
		s.raiseAlert(event, core.SeverityMedium,
			"IoT Device Activity Spike",
			fmt.Sprintf("Device %s (%s) activity rate is %.1fx above baseline (%d events/min vs normal %d).",
				deviceID, deviceType, anomaly.SpikeRatio, anomaly.CurrentRate, anomaly.BaselineRate),
			"activity_spike")
	}
	if anomaly.UnusualHour {
		s.raiseAlert(event, core.SeverityMedium,
			"IoT Device Active Outside Normal Hours",
			fmt.Sprintf("Device %s (%s) is active at hour %d, outside its normal operating window.",
				deviceID, deviceType, anomaly.CurrentHour),
			"unusual_hours")
	}
}

func (s *Shield) handleProtocolEvent(event *core.SecurityEvent) {
	protocol := strings.ToLower(getStringDetail(event, "protocol"))
	payload := getStringDetail(event, "payload")
	payloadSize := getIntDetail(event, "payload_size")
	functionCode := getIntDetail(event, "function_code")

	if protocol == "" {
		return
	}

	// Rate-based anomaly detection
	anomaly := s.anomalyDet.Check(protocol, payload, event.SourceIP, payloadSize, functionCode)
	for _, finding := range anomaly {
		s.raiseAlert(event, finding.Severity,
			finding.Title,
			fmt.Sprintf("Protocol anomaly on %s from %s: %s", protocol, event.SourceIP, finding.Description),
			finding.AlertType)
	}
}

func (s *Shield) handleFirmwareEvent(event *core.SecurityEvent) {
	deviceID := getStringDetail(event, "device_id")
	version := getStringDetail(event, "firmware_version")
	hash := getStringDetail(event, "firmware_hash")
	expectedHash := getStringDetail(event, "expected_hash")
	vendor := getStringDetail(event, "vendor")
	model := getStringDetail(event, "model")

	// Hash integrity check
	if hash != "" && expectedHash != "" && hash != expectedHash {
		s.raiseAlert(event, core.SeverityCritical,
			"Firmware Integrity Violation",
			fmt.Sprintf("Device %s firmware hash mismatch. Expected: %s, Got: %s (version: %s). Firmware may be tampered.",
				deviceID, truncate(expectedHash, 16), truncate(hash, 16), version),
			"firmware_integrity")
	}

	// Track firmware in integrity DB
	if hash != "" {
		result := s.fwIntegrity.RecordFirmware(deviceID, vendor, model, version, hash)
		if result.UnknownFirmware {
			s.raiseAlert(event, core.SeverityHigh,
				"Unknown Firmware Detected",
				fmt.Sprintf("Device %s running firmware %s (hash: %s) not in known-good database for vendor %s model %s.",
					deviceID, version, truncate(hash, 16), vendor, model),
				"unknown_firmware")
		}
		if result.KnownVulnerable {
			s.raiseAlert(event, core.SeverityCritical,
				"Vulnerable Firmware Detected",
				fmt.Sprintf("Device %s running firmware %s which has known vulnerabilities: %s. Update immediately.",
					deviceID, version, result.VulnDescription),
				"vulnerable_firmware")
		}
	}
}

func (s *Shield) handleOTCommand(event *core.SecurityEvent) {
	protocol := strings.ToLower(getStringDetail(event, "protocol"))
	command := getStringDetail(event, "command")
	functionCode := getIntDetail(event, "function_code")
	target := getStringDetail(event, "target")
	value := getStringDetail(event, "value")
	operator := getStringDetail(event, "operator")

	result := s.otValidator.Validate(protocol, command, functionCode, target, value, operator, event.SourceIP)
	if s.accessPolicy.Configured() {
		s.handleManagementAccess(event)
	}

	if result.Blocked {
		s.raiseAlert(event, core.SeverityCritical,
			"Dangerous OT Command Detected",
			fmt.Sprintf("Detected %s command on %s protocol from %s (operator: %s): %s. Target: %s, Value: %s. Traffic rejection requires an enforcing gateway or response integration.",
				command, protocol, event.SourceIP, operator, result.Reason, target, value),
			"ot_command_blocked")
	}

	if result.Suspicious {
		s.raiseAlert(event, core.SeverityHigh,
			"Suspicious OT Command Detected",
			fmt.Sprintf("Suspicious %s command on %s from %s (operator: %s): %s",
				command, protocol, event.SourceIP, operator, result.Reason),
			"ot_command_suspicious")
	}

	if result.OutOfRange {
		s.raiseAlert(event, core.SeverityHigh,
			"OT Setpoint Out of Safe Range",
			fmt.Sprintf("Command to set %s to %s is outside safe operating range. Protocol: %s, Operator: %s",
				target, value, protocol, operator),
			"ot_out_of_range")
	}

}

// CheckManagementAccess returns a decision; the calling gateway enforces it.
func (s *Shield) CheckManagementAccess(req core.ManagementAccessRequest) core.ManagementAccessDecision {
	return s.accessPolicy.Check(req)
}

func (s *Shield) handleManagementAccess(event *core.SecurityEvent) {
	verified, _ := event.Details["identity_verified"].(bool)
	action := getStringDetail(event, "action")
	if action == "" {
		action = getStringDetail(event, "command")
	}
	req := core.ManagementAccessRequest{SourceIP: event.SourceIP, Operator: getStringDetail(event, "operator"),
		IdentityVerified: verified, Target: getStringDetail(event, "target"), Action: action}
	decision := s.CheckManagementAccess(req)
	if !decision.Allowed {
		s.raiseAlert(event, core.SeverityCritical, "Management Access Denied by Policy",
			fmt.Sprintf("Access to %s by operator %s from %s fails management policy: %s. Telemetry is an alert; a gateway must enforce the decision before forwarding.",
				req.Target, req.Operator, req.SourceIP, decision.Reason), "management_access_denied")
	}
}

func (s *Shield) handleNetworkFlow(event *core.SecurityEvent) {
	deviceID := getStringDetail(event, "device_id")
	srcZone := getStringDetail(event, "src_zone")
	dstZone := getStringDetail(event, "dst_zone")
	destIP := event.DestIP
	destPort := getIntDetail(event, "dest_port")
	protocol := getStringDetail(event, "protocol")

	violation := s.segEnforcer.Check(srcZone, dstZone, event.SourceIP, destIP, destPort, protocol)
	if violation != nil {
		s.raiseAlert(event, violation.Severity,
			"Network Segmentation Violation",
			fmt.Sprintf("Device %s (zone: %s, IP: %s) attempted to reach zone %s (IP: %s, port: %d, proto: %s). %s",
				deviceID, srcZone, event.SourceIP, dstZone, destIP, destPort, protocol, violation.Reason),
			"segmentation_violation")
	}
}

// handleFirmwareImplant detects persistent firmware implants and bootloader rootkits.
// 2025-2026 threat: HiatusRAT-X style attacks that rewrite U-Boot environments,
// survive factory resets, and persist across firmware updates.
// References: CISA advisories on persistent flash implants, CVE-2025-3052 Secure Boot bypass.
func (s *Shield) handleFirmwareImplant(event *core.SecurityEvent) {
	deviceID := getStringDetail(event, "device_id")
	implantType := strings.ToLower(getStringDetail(event, "implant_type"))
	bootloader := getStringDetail(event, "bootloader")
	persistenceMethod := getStringDetail(event, "persistence_method")
	surviveReset := getStringDetail(event, "survives_factory_reset")
	hash := getStringDetail(event, "firmware_hash")
	expectedHash := getStringDetail(event, "expected_hash")

	// Secure Boot bypass detection (check specific implant types first)
	if implantType == "secure_boot_bypass" {
		s.raiseAlert(event, core.SeverityCritical,
			"Secure Boot Bypass Detected",
			fmt.Sprintf("Device %s: Secure Boot has been bypassed. Bootloader: %s. Attackers can execute unsigned code at the highest privilege level.",
				deviceID, bootloader),
			"secure_boot_bypass")
		return
	}

	// Flash write to boot partition outside maintenance window
	if implantType == "flash_write" || implantType == "boot_partition_write" {
		s.raiseAlert(event, core.SeverityCritical,
			"Suspicious Boot Partition Write",
			fmt.Sprintf("Device %s: unexpected write to boot partition (type: %s). This may indicate firmware implant installation.",
				deviceID, implantType),
			"boot_partition_write")
		return
	}

	// Persistent flash implant detection (survives factory reset)
	if strings.EqualFold(surviveReset, "true") || strings.EqualFold(surviveReset, "yes") {
		s.raiseAlert(event, core.SeverityCritical,
			"Persistent Firmware Implant Detected",
			fmt.Sprintf("Device %s has a firmware implant that survives factory reset. Type: %s, Persistence: %s. This indicates a deep-level compromise requiring hardware-level remediation.",
				deviceID, implantType, persistenceMethod),
			"persistent_firmware_implant")
		return
	}

	// Bootloader modification detection
	if bootloader != "" {
		bootloaderLower := strings.ToLower(bootloader)
		suspiciousBootloaders := []string{"modified", "custom", "unsigned", "tampered", "unknown"}
		for _, sb := range suspiciousBootloaders {
			if strings.Contains(bootloaderLower, sb) {
				s.raiseAlert(event, core.SeverityCritical,
					"Bootloader Rootkit Detected",
					fmt.Sprintf("Device %s has a %s bootloader (%s). Bootloader rootkits can survive factory resets and firmware updates. Persistence: %s",
						deviceID, sb, bootloader, persistenceMethod),
					"bootloader_rootkit")
				return
			}
		}
	}

	// Hash mismatch on boot-time firmware check
	if hash != "" && expectedHash != "" && hash != expectedHash {
		s.raiseAlert(event, core.SeverityCritical,
			"Boot-Time Firmware Integrity Violation",
			fmt.Sprintf("Device %s firmware hash mismatch at boot. Expected: %s, Got: %s. Firmware may contain a persistent implant.",
				deviceID, truncate(expectedHash, 16), truncate(hash, 16)),
			"firmware_integrity")
	}
}

// handleICSWiper detects ICS-specific destructive/wiper malware.
// 2025-2026 threat: VoltRuptor-style multi-protocol wiper malware targeting
// critical infrastructure with anti-forensics capabilities.
// References: ENISA 2025 Threat Landscape, Dragos 2026 OT report (PYROXENE wiper deployments).
func (s *Shield) handleICSWiper(event *core.SecurityEvent) {
	deviceID := getStringDetail(event, "device_id")
	wiperType := getStringDetail(event, "wiper_type")
	targetProtocol := strings.ToLower(getStringDetail(event, "target_protocol"))
	action := strings.ToLower(getStringDetail(event, "action"))
	target := getStringDetail(event, "target")
	processName := getStringDetail(event, "process_name")

	// PLC logic wipe / ladder logic destruction
	if strings.Contains(action, "logic_wipe") || strings.Contains(action, "ladder_delete") ||
		strings.Contains(action, "program_erase") {
		s.raiseAlert(event, core.SeverityCritical,
			"PLC Logic Wipe Detected [ICS-CERT]",
			fmt.Sprintf("Destructive action on device %s: PLC logic being wiped (action: %s, target: %s, protocol: %s). This can cause immediate physical process disruption.",
				deviceID, action, target, targetProtocol),
			"plc_logic_wipe")
		return
	}

	// Safety system tampering
	if strings.Contains(target, "safety") || strings.Contains(target, "sis") ||
		strings.Contains(target, "emergency_shutdown") {
		s.raiseAlert(event, core.SeverityCritical,
			"Safety System Tampering Detected",
			fmt.Sprintf("Destructive action targeting safety system on device %s: %s (target: %s). Disabling safety systems can lead to physical harm.",
				deviceID, action, target),
			"safety_system_tamper")
		return
	}

	// HMI defacement / operator display manipulation
	if strings.Contains(action, "hmi_overwrite") || strings.Contains(action, "display_tamper") {
		s.raiseAlert(event, core.SeverityCritical,
			"HMI Display Tampering Detected",
			fmt.Sprintf("HMI/operator display on device %s is being tampered with (action: %s). Operators may see false readings while physical process is compromised.",
				deviceID, action),
			"hmi_tamper")
		return
	}

	// Configuration wipe (historian, SCADA server configs)
	if strings.Contains(action, "config_wipe") || strings.Contains(action, "config_destroy") {
		s.raiseAlert(event, core.SeverityCritical,
			"OT Configuration Destruction Detected",
			fmt.Sprintf("Configuration destruction on device %s: %s (target: %s, process: %s). Recovery may require manual reconfiguration of industrial systems.",
				deviceID, action, target, processName),
			"ot_config_wipe")
		return
	}

	// Generic ICS wiper activity
	s.raiseAlert(event, core.SeverityCritical,
		"ICS Destructive Malware Detected",
		fmt.Sprintf("Destructive activity on OT device %s. Type: %s, Action: %s, Target: %s, Protocol: %s, Process: %s. Immediate isolation recommended.",
			deviceID, wiperType, action, target, targetProtocol, processName),
		"ics_wiper")
}

// handleCoordinatedOTAttack detects coordinated multi-protocol attacks on OT environments.
// 2025-2026 threat: Dragos identified threat groups (SYLVANITE, PYROXENE, AZURITE) using
// coordinated attacks spanning multiple industrial protocols simultaneously.
// References: Dragos 2026 Year in Review, ENISA 2025 Threat Landscape.
func (s *Shield) handleCoordinatedOTAttack(event *core.SecurityEvent) {
	protocols := getStringDetail(event, "protocols")
	attackPhase := strings.ToLower(getStringDetail(event, "attack_phase"))
	targetCount := getIntDetail(event, "target_count")
	deviceID := getStringDetail(event, "device_id")
	threatGroup := getStringDetail(event, "threat_group")

	// Multi-protocol simultaneous attack
	if protocols != "" {
		protoList := strings.Split(protocols, ",")
		if len(protoList) >= 2 {
			s.raiseAlert(event, core.SeverityCritical,
				"Coordinated Multi-Protocol OT Attack",
				fmt.Sprintf("Coordinated attack spanning %d protocols (%s) detected. Device: %s, Phase: %s. Multi-protocol attacks indicate sophisticated threat actor with OT expertise.",
					len(protoList), protocols, deviceID, attackPhase),
				"multi_protocol_attack")
		}
	}

	// Handoff pattern detection (one group gains access, another operates)
	if attackPhase == "handoff" || attackPhase == "ot_handoff" {
		desc := fmt.Sprintf("OT attack handoff detected on device %s. Initial access actor handing off to OT-specialized operator.", deviceID)
		if threatGroup != "" {
			desc += fmt.Sprintf(" Attributed to: %s.", threatGroup)
		}
		s.raiseAlert(event, core.SeverityCritical,
			"OT Attack Handoff Detected",
			desc,
			"ot_attack_handoff")
	}

	// Mass targeting (multiple devices simultaneously)
	if targetCount > 3 {
		s.raiseAlert(event, core.SeverityCritical,
			"Mass OT Device Targeting Detected",
			fmt.Sprintf("Coordinated attack targeting %d OT devices simultaneously. Phase: %s. This indicates a planned destructive campaign against industrial infrastructure.",
				targetCount, attackPhase),
			"mass_ot_targeting")
	}

	// Reconnaissance-to-attack transition
	if attackPhase == "active_exploitation" || attackPhase == "destructive" {
		s.raiseAlert(event, core.SeverityCritical,
			"OT Attack Entered Destructive Phase",
			fmt.Sprintf("OT attack on device %s has entered %s phase. Targets: %d. Immediate physical process isolation may be required.",
				deviceID, attackPhase, targetCount),
			"ot_destructive_phase")
	}
}

func (s *Shield) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if s.bus != nil {
		_ = s.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getIoTMitigations(alertType)
	if s.pipeline != nil {
		s.pipeline.Process(alert)
	}
}

func getIoTMitigations(alertType string) []string {
	base := []string{"Maintain an up-to-date inventory of all IoT/OT devices"}
	switch alertType {
	case "default_credentials":
		return append(base, "Change all default credentials immediately",
			"Implement a credential rotation policy for IoT devices",
			"Disable unused default accounts on devices")
	case "firmware_integrity", "firmware_downgrade", "unknown_firmware", "vulnerable_firmware":
		return append(base, "Verify firmware images against vendor-signed hashes",
			"Implement secure boot on all OT/IoT devices",
			"Subscribe to vendor security advisories for firmware updates")
	case "ot_command_blocked", "ot_command_suspicious", "ot_out_of_range", "ot_unauthorized_source":
		return append(base, "Restrict OT command sources to designated engineering workstations",
			"Implement allowlists for critical OT commands",
			"Enable OT protocol deep packet inspection",
			"Maintain safe operating range limits for all setpoints")
	case "segmentation_violation":
		return append(base, "Enforce strict network segmentation between IT and OT zones",
			"Deploy firewalls between IoT VLANs and corporate networks",
			"Monitor east-west traffic within IoT segments")
	case "management_access_denied", "management_exposure":
		return append(base, "Remove public exposure of management interfaces",
			"Require a protected VPN or management gateway with independently verified operator identity",
			"Forward requests only after an explicit allow decision from the access policy")
	case "protocol_anomaly", "unusual_protocol":
		return append(base, "Baseline normal protocol usage per device type",
			"Block unauthorized protocols at the network level")
	// 2025-2026: persistent firmware implant mitigations
	case "bootloader_rootkit", "persistent_firmware_implant", "boot_partition_write", "secure_boot_bypass":
		return append(base, "Enable and enforce Secure Boot on all devices",
			"Use signed firmware with hardware root of trust",
			"Monitor boot partition writes outside maintenance windows",
			"Maintain golden images for PLCs, drives, and controllers",
			"Consider hardware replacement for devices with persistent implants")
	// 2025-2026: ICS wiper/destructive malware mitigations
	case "plc_logic_wipe", "ics_wiper", "ot_config_wipe":
		return append(base, "Maintain offline backups of all PLC programs and configurations",
			"Implement PLC logic change detection and alerting",
			"Restrict programming access to designated engineering workstations",
			"Test restore procedures for industrial control systems regularly")
	case "safety_system_tamper":
		return append(base, "Isolate safety instrumented systems (SIS) on dedicated networks",
			"Implement hardware-enforced safety interlocks where possible",
			"Monitor all access to safety system controllers",
			"Maintain independent safety system backups")
	case "hmi_tamper":
		return append(base, "Implement independent process variable verification",
			"Cross-check HMI readings against field instrument data",
			"Restrict HMI configuration access to authorized operators")
	// 2025-2026: coordinated OT attack mitigations
	case "multi_protocol_attack", "ot_attack_handoff", "mass_ot_targeting", "ot_destructive_phase":
		return append(base, "Implement network segmentation between protocol zones",
			"Baseline Modbus/EtherNet-IP/OPC-UA traffic and alert on anomalies",
			"Use time-boxed vendor access with MFA and session recording",
			"Maintain SBOMs for all OT devices and monitor for supply chain compromise",
			"Prepare physical process isolation procedures for coordinated attacks")
	default:
		return append(base, "Isolate suspicious devices from the network",
			"Review device logs and network captures for forensic analysis")
	}
}

// ===========================================================================
// DeviceInventory — tracks known IoT/OT devices with change detection
// ===========================================================================

type DeviceInventory struct {
	mu      sync.RWMutex
	devices map[string]*DeviceRecord
}

type DeviceRecord struct {
	ID              string
	Type            string
	MAC             string
	Firmware        string
	Vendor          string
	IP              string
	PreviousIPs     []string
	FirstSeen       time.Time
	LastSeen        time.Time
	FirmwareHistory []string
}

type RegistrationResult struct {
	IsNew             bool
	IPChanged         bool
	FirmwareDowngrade bool
	PreviousIP        string
	PreviousFirmware  string
}

func NewDeviceInventory() *DeviceInventory {
	return &DeviceInventory{devices: make(map[string]*DeviceRecord)}
}

func (inv *DeviceInventory) Register(id, deviceType, mac, firmware, vendor, ip string) RegistrationResult {
	inv.mu.Lock()
	defer inv.mu.Unlock()

	now := time.Now()
	result := RegistrationResult{}

	rec, exists := inv.devices[id]
	if !exists {
		inv.devices[id] = &DeviceRecord{
			ID: id, Type: deviceType, MAC: mac,
			Firmware: firmware, Vendor: vendor, IP: ip,
			FirstSeen: now, LastSeen: now,
		}
		if firmware != "" {
			inv.devices[id].FirmwareHistory = []string{firmware}
		}
		result.IsNew = true
		return result
	}

	rec.LastSeen = now

	// IP change detection
	if ip != "" && rec.IP != "" && ip != rec.IP {
		result.IPChanged = true
		result.PreviousIP = rec.IP
		rec.PreviousIPs = append(rec.PreviousIPs, rec.IP)
		if len(rec.PreviousIPs) > 20 {
			rec.PreviousIPs = rec.PreviousIPs[len(rec.PreviousIPs)-20:]
		}
		rec.IP = ip
	} else if ip != "" {
		rec.IP = ip
	}

	// Firmware downgrade detection (simple version string comparison)
	if firmware != "" && rec.Firmware != "" && firmware != rec.Firmware {
		result.PreviousFirmware = rec.Firmware
		if isVersionDowngrade(rec.Firmware, firmware) {
			result.FirmwareDowngrade = true
		}
		rec.FirmwareHistory = append(rec.FirmwareHistory, firmware)
		if len(rec.FirmwareHistory) > 50 {
			rec.FirmwareHistory = rec.FirmwareHistory[len(rec.FirmwareHistory)-50:]
		}
		rec.Firmware = firmware
	}

	if vendor != "" {
		rec.Vendor = vendor
	}

	return result
}

func (inv *DeviceInventory) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			inv.mu.Lock()
			cutoff := time.Now().Add(-24 * time.Hour)
			for id, rec := range inv.devices {
				if rec.LastSeen.Before(cutoff) {
					delete(inv.devices, id)
				}
			}
			inv.mu.Unlock()
		}
	}
}

// isVersionDowngrade does a best-effort comparison of dotted version strings.
func isVersionDowngrade(oldVer, newVer string) bool {
	oldParts := strings.Split(oldVer, ".")
	newParts := strings.Split(newVer, ".")
	maxLen := len(oldParts)
	if len(newParts) > maxLen {
		maxLen = len(newParts)
	}
	for i := 0; i < maxLen; i++ {
		o, n := 0, 0
		if i < len(oldParts) {
			o = parseVersionPart(oldParts[i])
		}
		if i < len(newParts) {
			n = parseVersionPart(newParts[i])
		}
		if n < o {
			return true
		}
		if n > o {
			return false
		}
	}
	return false
}

func parseVersionPart(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}

// ===========================================================================
// ProtocolAnomalyDetector — deep IoT/OT protocol inspection
// ===========================================================================

type ProtocolAnomalyDetector struct {
	mu       sync.RWMutex
	counters map[string]*protoCounter
	// Per-protocol payload size baselines
	payloadBaselines map[string]*payloadBaseline
}

type protoCounter struct {
	count    int
	window   time.Time
	lastSeen time.Time
}

type payloadBaseline struct {
	totalSize int64
	count     int64
	maxSeen   int
}

type ProtoFinding struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
}

func NewProtocolAnomalyDetector() *ProtocolAnomalyDetector {
	return &ProtocolAnomalyDetector{
		counters:         make(map[string]*protoCounter),
		payloadBaselines: make(map[string]*payloadBaseline),
	}
}

func (d *ProtocolAnomalyDetector) Check(protocol, payload, sourceIP string, payloadSize, functionCode int) []ProtoFinding {
	d.mu.Lock()
	defer d.mu.Unlock()

	var findings []ProtoFinding
	key := sourceIP + ":" + protocol
	now := time.Now()

	// Rate anomaly
	counter, exists := d.counters[key]
	if !exists {
		d.counters[key] = &protoCounter{count: 1, window: now, lastSeen: now}
	} else {
		if now.Sub(counter.window) > time.Minute {
			counter.count = 0
			counter.window = now
		}
		counter.count++
		counter.lastSeen = now

		if counter.count > 500 {
			findings = append(findings, ProtoFinding{
				Title:       "IoT Protocol Flood",
				Description: fmt.Sprintf("abnormal message rate: %d msgs/min on %s", counter.count, protocol),
				Severity:    core.SeverityHigh,
				AlertType:   "protocol_flood",
			})
		}
	}

	// Payload size anomaly
	if payloadSize > 0 {
		bl, exists := d.payloadBaselines[protocol]
		if !exists {
			bl = &payloadBaseline{}
			d.payloadBaselines[protocol] = bl
		}
		bl.totalSize += int64(payloadSize)
		bl.count++
		if payloadSize > bl.maxSeen {
			bl.maxSeen = payloadSize
		}
		if bl.count > 100 {
			avg := float64(bl.totalSize) / float64(bl.count)
			if float64(payloadSize) > avg*5 && payloadSize > 1024 {
				findings = append(findings, ProtoFinding{
					Title:       "Abnormal IoT Payload Size",
					Description: fmt.Sprintf("payload size %d bytes is %.1fx above average (%.0f bytes) for %s", payloadSize, float64(payloadSize)/avg, avg, protocol),
					Severity:    core.SeverityMedium,
					AlertType:   "abnormal_payload_size",
				})
			}
		}
	}

	// Industrial protocol deep inspection
	findings = append(findings, d.inspectIndustrialProtocol(protocol, payload, functionCode, sourceIP)...)

	return findings
}

func (d *ProtocolAnomalyDetector) inspectIndustrialProtocol(protocol, payload string, functionCode int, sourceIP string) []ProtoFinding {
	var findings []ProtoFinding

	switch protocol {
	case "modbus":
		findings = append(findings, d.inspectModbus(payload, functionCode, sourceIP)...)
	case "dnp3":
		findings = append(findings, d.inspectDNP3(payload, functionCode, sourceIP)...)
	case "opcua":
		findings = append(findings, d.inspectOPCUA(payload, sourceIP)...)
	case "bacnet":
		findings = append(findings, d.inspectBACnet(payload, functionCode, sourceIP)...)
	case "mqtt":
		findings = append(findings, d.inspectMQTT(payload, sourceIP)...)
	case "coap":
		findings = append(findings, d.inspectCoAP(payload, sourceIP)...)
	}

	return findings
}

func (d *ProtocolAnomalyDetector) inspectModbus(payload string, functionCode int, sourceIP string) []ProtoFinding {
	var findings []ProtoFinding

	// Dangerous Modbus function codes
	dangerousFCs := map[int]string{
		5:  "Write Single Coil",
		6:  "Write Single Register",
		15: "Write Multiple Coils",
		16: "Write Multiple Registers",
		22: "Mask Write Register",
		23: "Read/Write Multiple Registers",
		8:  "Diagnostics (can restart device)",
		43: "Encapsulated Interface Transport (device identification)",
	}

	if desc, ok := dangerousFCs[functionCode]; ok {
		severity := core.SeverityMedium
		if functionCode == 8 || functionCode == 5 || functionCode == 15 {
			severity = core.SeverityHigh
		}
		findings = append(findings, ProtoFinding{
			Title:       "Modbus Write/Control Command",
			Description: fmt.Sprintf("Modbus FC %d (%s) from %s", functionCode, desc, sourceIP),
			Severity:    severity,
			AlertType:   "modbus_write_command",
		})
	}

	// Modbus broadcast (unit ID 0) — affects all devices
	if strings.Contains(payload, "unit_id=0") || strings.Contains(payload, "broadcast") {
		findings = append(findings, ProtoFinding{
			Title:       "Modbus Broadcast Command",
			Description: fmt.Sprintf("Modbus broadcast (unit_id=0) from %s — affects all devices on the bus", sourceIP),
			Severity:    core.SeverityCritical,
			AlertType:   "modbus_broadcast",
		})
	}

	return findings
}

func (d *ProtocolAnomalyDetector) inspectDNP3(payload string, functionCode int, sourceIP string) []ProtoFinding {
	var findings []ProtoFinding

	// DNP3 dangerous operations
	dangerousDNP3 := map[int]string{
		3:  "Direct Operate",
		4:  "Direct Operate No Ack",
		13: "Cold Restart",
		14: "Warm Restart",
		18: "Stop Application",
		20: "Enable Unsolicited",
		21: "Disable Unsolicited",
		31: "Activate Configuration",
	}

	if desc, ok := dangerousDNP3[functionCode]; ok {
		severity := core.SeverityHigh
		if functionCode == 13 || functionCode == 14 || functionCode == 18 {
			severity = core.SeverityCritical
		}
		findings = append(findings, ProtoFinding{
			Title:       "DNP3 Control Command",
			Description: fmt.Sprintf("DNP3 FC %d (%s) from %s", functionCode, desc, sourceIP),
			Severity:    severity,
			AlertType:   "dnp3_control_command",
		})
	}

	return findings
}

func (d *ProtocolAnomalyDetector) inspectOPCUA(payload, sourceIP string) []ProtoFinding {
	var findings []ProtoFinding
	payloadLower := strings.ToLower(payload)

	suspiciousOps := []struct {
		pattern string
		desc    string
		sev     core.Severity
	}{
		{"write_value", "OPC UA Write Value — modifying process data", core.SeverityHigh},
		{"call_method", "OPC UA Method Call — executing server-side logic", core.SeverityHigh},
		{"add_nodes", "OPC UA AddNodes — modifying server address space", core.SeverityCritical},
		{"delete_nodes", "OPC UA DeleteNodes — removing server objects", core.SeverityCritical},
		{"register_server", "OPC UA RegisterServer — registering new server", core.SeverityHigh},
		{"translate_browse", "OPC UA TranslateBrowsePathsToNodeIds — reconnaissance", core.SeverityMedium},
	}

	for _, op := range suspiciousOps {
		if strings.Contains(payloadLower, op.pattern) {
			findings = append(findings, ProtoFinding{
				Title:       "OPC UA Suspicious Operation",
				Description: fmt.Sprintf("%s from %s", op.desc, sourceIP),
				Severity:    op.sev,
				AlertType:   "opcua_suspicious_op",
			})
		}
	}

	return findings
}

func (d *ProtocolAnomalyDetector) inspectBACnet(payload string, functionCode int, sourceIP string) []ProtoFinding {
	var findings []ProtoFinding

	// BACnet dangerous services
	dangerousBACnet := map[int]string{
		6:  "WriteProperty",
		15: "WritePropertyMultiple",
		20: "DeviceCommunicationControl",
		21: "ReinitializeDevice",
	}

	if desc, ok := dangerousBACnet[functionCode]; ok {
		severity := core.SeverityHigh
		if functionCode == 20 || functionCode == 21 {
			severity = core.SeverityCritical
		}
		findings = append(findings, ProtoFinding{
			Title:       "BACnet Control Command",
			Description: fmt.Sprintf("BACnet service %d (%s) from %s", functionCode, desc, sourceIP),
			Severity:    severity,
			AlertType:   "bacnet_control_command",
		})
	}

	// BACnet file access services — CVE-2026-21878 vector
	// AtomicReadFile (6), AtomicWriteFile (7) can be abused for arbitrary file ops
	fileAccessServices := map[int]string{
		6: "AtomicReadFile",
		7: "AtomicWriteFile",
	}
	if desc, ok := fileAccessServices[functionCode]; ok {
		findings = append(findings, ProtoFinding{
			Title:       "BACnet File Access Operation",
			Description: fmt.Sprintf("BACnet file service %d (%s) from %s — potential arbitrary file read/write via BACnet stack (ref: CVE-2026-21878)", functionCode, desc, sourceIP),
			Severity:    core.SeverityCritical,
			AlertType:   "bacnet_file_access",
		})
	}

	// Detect oversized BACnet payloads (potential buffer overflow / heap overflow)
	if len(payload) > 1476 { // BACnet max APDU is typically 1476 bytes
		findings = append(findings, ProtoFinding{
			Title:       "BACnet Oversized Payload",
			Description: fmt.Sprintf("BACnet payload from %s exceeds max APDU size (%d bytes) — potential buffer overflow attempt", sourceIP, len(payload)),
			Severity:    core.SeverityHigh,
			AlertType:   "bacnet_oversized_payload",
		})
	}

	// Detect rapid BACnet Who-Is broadcasts (reconnaissance)
	if functionCode == 8 { // Who-Is
		d.mu.Lock()
		key := "bacnet_whois_" + sourceIP
		counter, exists := d.counters[key]
		if !exists || time.Since(counter.window) > 5*time.Minute {
			counter = &protoCounter{window: time.Now()}
			d.counters[key] = counter
		}
		counter.count++
		counter.lastSeen = time.Now()
		count := counter.count
		d.mu.Unlock()
		if count > 50 {
			findings = append(findings, ProtoFinding{
				Title:       "BACnet Reconnaissance Detected",
				Description: fmt.Sprintf("Excessive Who-Is broadcasts (%d) from %s — possible BACnet device enumeration", count, sourceIP),
				Severity:    core.SeverityMedium,
				AlertType:   "bacnet_recon",
			})
		}
	}

	return findings
}

func (d *ProtocolAnomalyDetector) inspectMQTT(payload, sourceIP string) []ProtoFinding {
	var findings []ProtoFinding
	payloadLower := strings.ToLower(payload)

	// MQTT wildcard subscriptions (# or +) can be used for reconnaissance
	if strings.Contains(payloadLower, "subscribe") && (strings.Contains(payload, "#") || strings.Contains(payload, "+")) {
		findings = append(findings, ProtoFinding{
			Title:       "MQTT Wildcard Subscription",
			Description: fmt.Sprintf("MQTT wildcard subscription from %s — can intercept all messages on the broker", sourceIP),
			Severity:    core.SeverityHigh,
			AlertType:   "mqtt_wildcard_sub",
		})
	}

	// MQTT $SYS topic access (broker internals)
	if strings.Contains(payload, "$SYS") {
		findings = append(findings, ProtoFinding{
			Title:       "MQTT System Topic Access",
			Description: fmt.Sprintf("Access to MQTT $SYS topic from %s — exposes broker internals", sourceIP),
			Severity:    core.SeverityMedium,
			AlertType:   "mqtt_sys_topic",
		})
	}

	return findings
}

func (d *ProtocolAnomalyDetector) inspectCoAP(payload, sourceIP string) []ProtoFinding {
	var findings []ProtoFinding
	payloadLower := strings.ToLower(payload)

	if strings.Contains(payloadLower, ".well-known/core") {
		findings = append(findings, ProtoFinding{
			Title:       "CoAP Resource Discovery",
			Description: fmt.Sprintf("CoAP resource discovery request from %s — enumerating device capabilities", sourceIP),
			Severity:    core.SeverityMedium,
			AlertType:   "coap_discovery",
		})
	}

	return findings
}

func (d *ProtocolAnomalyDetector) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for key, counter := range d.counters {
				if counter.lastSeen.Before(cutoff) {
					delete(d.counters, key)
				}
			}
			d.mu.Unlock()
		}
	}
}

// ===========================================================================
// DeviceBehaviorMonitor — baselines device behavior and detects anomalies
// ===========================================================================

type DeviceBehaviorMonitor struct {
	mu             sync.RWMutex
	profiles       map[string]*deviceBehaviorProfile
	spikeThreshold float64
}

type deviceBehaviorProfile struct {
	DeviceType     string
	KnownProtocols map[string]bool
	// Activity rate tracking
	activityCount   int
	activityWindow  time.Time
	baselineRate    int // events per minute (rolling average)
	baselineSamples int
	// Time-of-day tracking
	activeHours map[int]int // hour -> count
	totalEvents int
	LastSeen    time.Time
	CreatedAt   time.Time
}

type BehaviorAnomaly struct {
	UnusualProtocol bool
	ActivitySpike   bool
	UnusualHour     bool
	KnownProtocols  []string
	SpikeRatio      float64
	CurrentRate     int
	BaselineRate    int
	CurrentHour     int
}

func NewDeviceBehaviorMonitor(settings map[string]interface{}) *DeviceBehaviorMonitor {
	threshold := 3.0
	if val, ok := settings["behavior_spike_threshold"]; ok {
		if v, ok := val.(float64); ok && v > 0 {
			threshold = v
		}
	}
	return &DeviceBehaviorMonitor{
		profiles:       make(map[string]*deviceBehaviorProfile),
		spikeThreshold: threshold,
	}
}

func (bm *DeviceBehaviorMonitor) RecordActivity(deviceID, deviceType, protocol, ip string) BehaviorAnomaly {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	anomaly := BehaviorAnomaly{}
	now := time.Now()
	hour := now.Hour()
	anomaly.CurrentHour = hour

	profile, exists := bm.profiles[deviceID]
	if !exists {
		profile = &deviceBehaviorProfile{
			DeviceType:     deviceType,
			KnownProtocols: make(map[string]bool),
			activeHours:    make(map[int]int),
			activityWindow: now,
			CreatedAt:      now,
		}
		bm.profiles[deviceID] = profile
	}

	profile.LastSeen = now
	profile.totalEvents++
	profile.activeHours[hour]++

	// Protocol anomaly (only after baseline period)
	if protocol != "" {
		if now.Sub(profile.CreatedAt) > 2*time.Hour && !profile.KnownProtocols[protocol] {
			anomaly.UnusualProtocol = true
			for p := range profile.KnownProtocols {
				anomaly.KnownProtocols = append(anomaly.KnownProtocols, p)
			}
		}
		profile.KnownProtocols[protocol] = true
	}

	// Activity rate tracking
	if now.Sub(profile.activityWindow) > time.Minute {
		// Update baseline with previous window
		if profile.baselineSamples > 0 {
			profile.baselineRate = (profile.baselineRate*profile.baselineSamples + profile.activityCount) / (profile.baselineSamples + 1)
		} else {
			profile.baselineRate = profile.activityCount
		}
		profile.baselineSamples++
		profile.activityCount = 0
		profile.activityWindow = now
	}
	profile.activityCount++

	// Spike detection (only after sufficient baseline)
	if profile.baselineSamples > 10 && profile.baselineRate > 0 {
		ratio := float64(profile.activityCount) / float64(profile.baselineRate)
		if ratio > bm.spikeThreshold {
			anomaly.ActivitySpike = true
			anomaly.SpikeRatio = ratio
			anomaly.CurrentRate = profile.activityCount
			anomaly.BaselineRate = profile.baselineRate
		}
	}

	// Unusual hour detection (only after 24+ hours of data)
	if profile.totalEvents > 1000 && now.Sub(profile.CreatedAt) > 24*time.Hour {
		totalHourEvents := 0
		for _, c := range profile.activeHours {
			totalHourEvents += c
		}
		avgPerHour := float64(totalHourEvents) / 24.0
		thisHourCount := float64(profile.activeHours[hour])
		// If this hour normally has <10% of average activity, it's unusual
		if avgPerHour > 10 && thisHourCount < avgPerHour*0.1 {
			anomaly.UnusualHour = true
		}
	}

	return anomaly
}

func (bm *DeviceBehaviorMonitor) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bm.mu.Lock()
			cutoff := time.Now().Add(-48 * time.Hour)
			for id, profile := range bm.profiles {
				if profile.LastSeen.Before(cutoff) {
					delete(bm.profiles, id)
				}
			}
			bm.mu.Unlock()
		}
	}
}

// ===========================================================================
// OTCommandValidator — validates OT/SCADA commands against safety policies
// ===========================================================================

type OTCommandValidator struct {
	mu                sync.RWMutex
	dangerousCommands map[string]*regexp.Regexp
	safeRanges        map[string]*safeRange
}

type safeRange struct {
	Min float64
	Max float64
}

type OTValidationResult struct {
	Blocked    bool
	Suspicious bool
	OutOfRange bool
	Reason     string
}

func NewOTCommandValidator() *OTCommandValidator {
	return &OTCommandValidator{
		dangerousCommands: map[string]*regexp.Regexp{
			"modbus": regexp.MustCompile(`(?i)(restart|reset|factory.?default|flash|firmware.?update|format|clear.?all|emergency.?stop)`),
			"dnp3":   regexp.MustCompile(`(?i)(cold.?restart|warm.?restart|stop.?application|initialize|clear.?config)`),
			"opcua":  regexp.MustCompile(`(?i)(delete.?node|shutdown|reset|factory|format|clear.?address.?space)`),
			"bacnet": regexp.MustCompile(`(?i)(reinitialize|device.?communication.?control|cold.?start|warm.?start)`),
		},
		safeRanges: map[string]*safeRange{
			"temperature": {Min: -50, Max: 500},
			"pressure":    {Min: 0, Max: 10000},
			"flow_rate":   {Min: 0, Max: 100000},
			"voltage":     {Min: 0, Max: 480},
			"speed":       {Min: 0, Max: 10000},
			"level":       {Min: 0, Max: 100},
		},
	}
}

func (v *OTCommandValidator) Validate(protocol, command string, functionCode int, target, value, operator, sourceIP string) OTValidationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()

	result := OTValidationResult{}

	// Check dangerous commands
	if pattern, ok := v.dangerousCommands[protocol]; ok {
		if pattern.MatchString(command) {
			result.Blocked = true
			result.Reason = fmt.Sprintf("command %q matches dangerous pattern for %s", command, protocol)
			return result
		}
	}

	// Check safe ranges for setpoint commands
	if value != "" && target != "" {
		targetLower := strings.ToLower(target)
		for rangeKey, sr := range v.safeRanges {
			if strings.Contains(targetLower, rangeKey) {
				numVal := parseFloat(value)
				if numVal < sr.Min || numVal > sr.Max {
					result.OutOfRange = true
					result.Reason = fmt.Sprintf("value %s for %s is outside safe range [%.1f, %.1f]",
						value, target, sr.Min, sr.Max)
					return result
				}
			}
		}
	}

	// Protocol-specific suspicious patterns
	switch protocol {
	case "modbus":
		// Write to coil 0 (often the emergency stop)
		if (functionCode == 5 || functionCode == 15) && strings.Contains(target, "coil_0") {
			result.Suspicious = true
			result.Reason = "write to coil 0 (potential emergency stop manipulation)"
		}
	case "dnp3":
		// Direct operate without select (bypasses safety interlock)
		if functionCode == 4 {
			result.Suspicious = true
			result.Reason = "Direct Operate No Ack — bypasses select-before-operate safety interlock"
		}
	}

	return result
}

// ===========================================================================
// CredentialScanner — expanded default/weak credential detection
// ===========================================================================

type CredentialScanner struct {
	// vendor -> username -> passwords
	vendorDefaults  map[string]map[string][]string
	genericDefaults map[string][]string
	weakPasswords   *regexp.Regexp
}

func NewCredentialScanner() *CredentialScanner {
	return &CredentialScanner{
		vendorDefaults: map[string]map[string][]string{
			"hikvision":  {"admin": {"12345", "admin12345", ""}},
			"dahua":      {"admin": {"admin", ""}},
			"axis":       {"root": {"pass", "root", ""}},
			"cisco":      {"admin": {"admin", "cisco", ""}, "cisco": {"cisco", ""}},
			"honeywell":  {"admin": {"1234", "admin", ""}},
			"schneider":  {"USER": {"USER", ""}, "admin": {"admin", ""}},
			"siemens":    {"admin": {"admin", ""}, "SIMATIC": {"SIMATIC", ""}},
			"abb":        {"admin": {"admin", ""}, "default": {"default", ""}},
			"rockwell":   {"admin": {"1234", ""}, "1784": {"1784", ""}},
			"moxa":       {"admin": {"", "admin", "root"}},
			"dlink":      {"admin": {"admin", "", "password"}},
			"tplink":     {"admin": {"admin", ""}},
			"ubiquiti":   {"ubnt": {"ubnt", ""}},
			"mikrotik":   {"admin": {"", "admin"}},
			"netgear":    {"admin": {"password", "1234"}},
			"samsung":    {"admin": {"1111111", "4321"}},
			"bosch":      {"admin": {"admin", ""}},
			"ge":         {"admin": {"admin", ""}, "engineer": {"engineer", ""}},
			"emerson":    {"admin": {"admin", ""}, "Ovation": {"Ovation", ""}},
			"yokogawa":   {"admin": {"admin", ""}, "CENTUM": {"CENTUM", ""}},
			"dell":       {"admin": {"admin", ""}, "root": {"calvin", ""}, "recoverpoint": {"recoverpoint", "boxmgmt", ""}},
			"hpe":        {"admin": {"admin", ""}, "root": {"hpinvent", ""}},
			"lenovo":     {"admin": {"admin", ""}, "USERID": {"PASSW0RD", ""}},
			"supermicro": {"ADMIN": {"ADMIN", ""}},
		},
		genericDefaults: map[string][]string{
			"admin":     {"admin", "password", "1234", "12345", "123456", ""},
			"root":      {"root", "toor", "password", "admin", ""},
			"user":      {"user", "password", "1234", ""},
			"default":   {"default", "password", ""},
			"pi":        {"raspberry", ""},
			"ubnt":      {"ubnt", ""},
			"support":   {"support", ""},
			"guest":     {"guest", ""},
			"operator":  {"operator", ""},
			"manager":   {"manager", ""},
			"service":   {"service", ""},
			"test":      {"test", "test123", ""},
			"ftp":       {"ftp", ""},
			"anonymous": {"", "anonymous"},
		},
		weakPasswords: regexp.MustCompile(`^(password|123456|12345678|qwerty|abc123|monkey|master|dragon|login|admin|letmein|welcome|shadow|sunshine|trustno1|iloveyou|batman|access|hello|charlie|000000|passw0rd|1q2w3e4r)$`),
	}
}

func (cs *CredentialScanner) Check(username, password, deviceType, vendor string) string {
	userLower := strings.ToLower(username)
	vendorLower := strings.ToLower(vendor)

	// Check vendor-specific defaults first
	if vendorLower != "" {
		if vendorCreds, ok := cs.vendorDefaults[vendorLower]; ok {
			if passwords, ok := vendorCreds[username]; ok {
				for _, p := range passwords {
					if password == p {
						return fmt.Sprintf("vendor-default credentials for %s", vendor)
					}
				}
			}
		}
	}

	// Check generic defaults
	if passwords, ok := cs.genericDefaults[userLower]; ok {
		for _, p := range passwords {
			if password == p {
				return "default credentials"
			}
		}
	}

	// Check weak passwords
	if cs.weakPasswords.MatchString(strings.ToLower(password)) {
		return "weak password from common password list"
	}

	// Empty password
	if password == "" && username != "" {
		return "empty password"
	}

	return ""
}

// ===========================================================================
// FirmwareIntegrityDB — tracks firmware hashes and known vulnerabilities
// ===========================================================================

type FirmwareIntegrityDB struct {
	mu         sync.RWMutex
	knownGood  map[string]map[string]bool // "vendor:model" -> set of known-good hashes
	vulnerable map[string]string          // hash -> vulnerability description
	deviceFW   map[string]string          // deviceID -> current hash
}

type FirmwareResult struct {
	UnknownFirmware bool
	KnownVulnerable bool
	VulnDescription string
}

func NewFirmwareIntegrityDB() *FirmwareIntegrityDB {
	db := &FirmwareIntegrityDB{
		knownGood:  make(map[string]map[string]bool),
		vulnerable: make(map[string]string),
		deviceFW:   make(map[string]string),
	}
	// Seed with example vulnerable firmware hashes (in production, this would
	// be populated from a vulnerability feed or configuration)
	return db
}

func (db *FirmwareIntegrityDB) RecordFirmware(deviceID, vendor, model, version, hash string) FirmwareResult {
	db.mu.Lock()
	defer db.mu.Unlock()

	result := FirmwareResult{}
	db.deviceFW[deviceID] = hash

	// Check known vulnerabilities
	if desc, ok := db.vulnerable[hash]; ok {
		result.KnownVulnerable = true
		result.VulnDescription = desc
		return result
	}

	// Check against known-good database
	key := strings.ToLower(vendor + ":" + model)
	if goodHashes, ok := db.knownGood[key]; ok {
		if !goodHashes[hash] {
			result.UnknownFirmware = true
		}
	}
	// If no known-good baseline exists for this vendor:model, we can't flag it
	// as unknown — we just record it for future comparison.

	return result
}

// RegisterKnownGood adds a hash to the known-good list for a vendor:model.
func (db *FirmwareIntegrityDB) RegisterKnownGood(vendor, model, hash string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	key := strings.ToLower(vendor + ":" + model)
	if _, ok := db.knownGood[key]; !ok {
		db.knownGood[key] = make(map[string]bool)
	}
	db.knownGood[key][hash] = true
}

// RegisterVulnerable marks a firmware hash as having known vulnerabilities.
func (db *FirmwareIntegrityDB) RegisterVulnerable(hash, description string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.vulnerable[hash] = description
}

// ===========================================================================
// SegmentationEnforcer — enforces IoT/OT network segmentation policies
// ===========================================================================

type SegmentationEnforcer struct {
	mu            sync.RWMutex
	blockedFlows  map[string]bool  // "srcZone->dstZone" -> blocked
	allowedPorts  map[string][]int // "srcZone->dstZone" -> allowed ports
	criticalZones map[string]bool
}

type SegmentationViolation struct {
	Severity core.Severity
	Reason   string
}

func NewSegmentationEnforcer(settings map[string]interface{}) *SegmentationEnforcer {
	se := &SegmentationEnforcer{
		blockedFlows: map[string]bool{
			"internet->ot":         true,
			"internet->iot":        true,
			"internet->scada":      true,
			"internet->plc":        true,
			"internet->safety":     true,
			"internet->management": true,
			"iot->corporate":       true,
			"iot->management":      true,
			"ot->internet":         true,
			"ot->corporate":        true,
			"scada->internet":      true,
			"dmz->ot":              true,
			"guest->ot":            true,
			"guest->iot":           true,
			"guest->management":    true,
		},
		allowedPorts: map[string][]int{
			"corporate->iot": {443, 8443}, // HTTPS management only
			"iot->ot":        {},          // no direct access
		},
		criticalZones: map[string]bool{
			"ot": true, "scada": true, "safety": true, "plc": true, "management": true,
		},
	}
	return se
}

func (se *SegmentationEnforcer) Check(srcZone, dstZone, srcIP, dstIP string, dstPort int, protocol string) *SegmentationViolation {
	srcZone = strings.ToLower(strings.TrimSpace(srcZone))
	dstZone = strings.ToLower(strings.TrimSpace(dstZone))
	if srcZone == "" || dstZone == "" || srcZone == dstZone {
		return nil
	}

	se.mu.RLock()
	defer se.mu.RUnlock()

	flowKey := strings.ToLower(srcZone + "->" + dstZone)

	// Check blocked flows
	if se.blockedFlows[flowKey] {
		severity := core.SeverityHigh
		if se.criticalZones[strings.ToLower(dstZone)] {
			severity = core.SeverityCritical
		}
		return &SegmentationViolation{
			Severity: severity,
			Reason:   fmt.Sprintf("traffic from %s to %s is blocked by segmentation policy", srcZone, dstZone),
		}
	}

	// Check port restrictions
	if allowedPorts, ok := se.allowedPorts[flowKey]; ok && len(allowedPorts) > 0 {
		allowed := false
		for _, p := range allowedPorts {
			if dstPort == p {
				allowed = true
				break
			}
		}
		if !allowed {
			return &SegmentationViolation{
				Severity: core.SeverityHigh,
				Reason:   fmt.Sprintf("port %d is not in the allowed list for %s -> %s traffic", dstPort, srcZone, dstZone),
			}
		}
	}

	return nil
}

// ===========================================================================
// Helpers
// ===========================================================================

// HashBytes returns the SHA-256 hex digest of data.
func HashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
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

func parseFloat(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
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

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Suppress unused import warnings — these are used by HashBytes and ShannonEntropy.
var (
	_ = sha256.New
	_ = hex.EncodeToString
	_ = math.Log2
	_ = regexp.MustCompile
)
