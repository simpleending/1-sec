package cloudposture

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "cloud_posture"

// Manager is the Cloud Posture Manager module providing configuration drift detection,
// misconfiguration scanning, secrets sprawl detection, multi-cloud policy enforcement,
// Kubernetes security posture management (KSPM), and container security checks.
type Manager struct {
	logger        zerolog.Logger
	bus           *core.EventBus
	pipeline      *core.AlertPipeline
	cfg           *core.Config
	ctx           context.Context
	cancel        context.CancelFunc
	driftTracker  *DriftTracker
	secretScanner *SecretScanner
	policyEngine  *CloudPolicyEngine
	restoreMu     sync.Mutex
	restoreState  map[string]string
}

func New() *Manager { return &Manager{} }

func (m *Manager) Name() string { return ModuleName }
func (m *Manager) Description() string {
	return "Cloud configuration drift detection, misconfiguration scanning, secrets sprawl detection, multi-cloud policy enforcement, and Kubernetes security posture management (KSPM)"
}
func (m *Manager) EventTypes() []string {
	return []string{
		"config_change", "resource_update", "iac_deploy",
		"config_scan", "posture_check",
		"secret_detected", "credential_found",
		"log_entry", "audit_log",
		"policy_check", "compliance_scan",
		"k8s_rbac_change", "k8s_admission", "k8s_network_policy",
		"container_config", "pod_security",
	}
}

func (m *Manager) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.bus = bus
	m.pipeline = pipeline
	m.cfg = cfg
	m.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	m.driftTracker = NewDriftTracker()
	m.secretScanner = NewSecretScanner()
	m.policyEngine = NewCloudPolicyEngine()
	m.restoreState = make(map[string]string)

	m.logger.Info().Msg("cloud posture manager started")
	return nil
}

func (m *Manager) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

func (m *Manager) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "config_change", "resource_update", "iac_deploy":
		m.handleConfigChange(event)
	case "config_scan", "posture_check":
		m.handleConfigScan(event)
	case "secret_detected", "credential_found":
		m.handleSecretDetection(event)
	case "log_entry", "audit_log":
		m.handleLogForSecrets(event)
	case "policy_check", "compliance_scan":
		m.handlePolicyCheck(event)
	case "k8s_rbac_change", "k8s_admission", "k8s_network_policy":
		m.handleKubernetesEvent(event)
	case "container_config", "pod_security":
		m.handleContainerPosture(event)
	}
	return nil
}

func (m *Manager) handleConfigChange(event *core.SecurityEvent) {
	resource := getStringDetail(event, "resource")
	resourceType := getStringDetail(event, "resource_type")
	changeType := getStringDetail(event, "change_type")
	user := getStringDetail(event, "user")
	oldValue := getStringDetail(event, "old_value")
	newValue := getStringDetail(event, "new_value")

	if resource == "" {
		return
	}

	drift := m.driftTracker.RecordChange(resource, resourceType, changeType, user, oldValue, newValue)

	if drift.UnexpectedChange {
		m.raiseAlert(event, core.SeverityHigh,
			"Configuration Drift Detected",
			fmt.Sprintf("Resource %s (%s) changed unexpectedly by %s. Change: %s. This deviates from the expected baseline.",
				resource, resourceType, user, changeType),
			"config_drift")
	}

	if drift.SecurityDegradation {
		m.raiseAlert(event, core.SeverityCritical,
			"Security Configuration Degraded",
			fmt.Sprintf("Resource %s security posture degraded: %s. Changed by %s.",
				resource, drift.DegradationReason, user),
			"security_degradation")
	}

	if drift.RapidChanges {
		m.raiseAlert(event, core.SeverityMedium,
			"Rapid Configuration Changes",
			fmt.Sprintf("Resource %s has been modified %d times in the last hour by %s. Possible misconfiguration or attack.",
				resource, drift.ChangeCount, user),
			"rapid_config_changes")
	}
}

func (m *Manager) handleConfigScan(event *core.SecurityEvent) {
	findings := getStringDetail(event, "findings")
	criticalCount := getIntDetail(event, "critical_count")
	highCount := getIntDetail(event, "high_count")
	resourceType := getStringDetail(event, "resource_type")

	// Check for common misconfigurations
	misconfigs := m.policyEngine.CheckMisconfigurations(event)
	for _, mc := range misconfigs {
		m.raiseAlert(event, mc.Severity,
			mc.Title,
			mc.Description,
			mc.AlertType)
	}

	if criticalCount > 0 {
		m.raiseAlert(event, core.SeverityCritical,
			"Critical Cloud Misconfigurations Found",
			fmt.Sprintf("Posture scan found %d critical and %d high misconfigurations in %s resources. Findings: %s",
				criticalCount, highCount, resourceType, truncate(findings, 200)),
			"critical_misconfigs")
	}
}

func (m *Manager) handleSecretDetection(event *core.SecurityEvent) {
	secretType := getStringDetail(event, "secret_type")
	location := getStringDetail(event, "location")
	file := getStringDetail(event, "file")

	m.raiseAlert(event, core.SeverityCritical,
		"Secret Detected in Infrastructure",
		fmt.Sprintf("Secret of type %q found in %s (file: %s). Rotate immediately and remove from source.",
			secretType, location, file),
		"secret_detected")
}

func (m *Manager) handleLogForSecrets(event *core.SecurityEvent) {
	logContent := getStringDetail(event, "content")
	if logContent == "" {
		logContent = event.Summary
	}

	secrets := m.secretScanner.Scan(logContent)
	for _, secret := range secrets {
		m.raiseAlert(event, core.SeverityCritical,
			"Secret Leaked in Logs",
			fmt.Sprintf("Secret of type %q detected in log output. Pattern: %s. Secrets must never appear in logs.",
				secret.Type, secret.PatternName),
			"secret_in_logs")
	}
}

func (m *Manager) handlePolicyCheck(event *core.SecurityEvent) {
	framework := getStringDetail(event, "framework")
	passCount := getIntDetail(event, "pass_count")
	failCount := getIntDetail(event, "fail_count")
	totalChecks := getIntDetail(event, "total_checks")

	if failCount > 0 && totalChecks > 0 {
		complianceRate := float64(passCount) / float64(totalChecks) * 100
		severity := core.SeverityMedium
		if complianceRate < 70 {
			severity = core.SeverityHigh
		}
		if complianceRate < 50 {
			severity = core.SeverityCritical
		}
		m.raiseAlert(event, severity,
			fmt.Sprintf("Compliance Check: %s", framework),
			fmt.Sprintf("Framework %s: %d/%d checks passed (%.1f%% compliance). %d failures require remediation.",
				framework, passCount, totalChecks, complianceRate, failCount),
			"compliance_failure")
	}
}

// handleKubernetesEvent detects Kubernetes security posture issues (KSPM).
// Ref: ARMO, Aqua, Sysdig KSPM best practices 2025-2026
func (m *Manager) handleKubernetesEvent(event *core.SecurityEvent) {
	namespace := getStringDetail(event, "namespace")
	resource := getStringDetail(event, "resource")
	user := getStringDetail(event, "user")
	action := getStringDetail(event, "action")

	switch event.Type {
	case "k8s_rbac_change":
		role := getStringDetail(event, "role")
		verbs := getStringDetail(event, "verbs")
		resources := getStringDetail(event, "resources")

		// Detect wildcard RBAC permissions
		if strings.Contains(verbs, "*") || strings.Contains(resources, "*") {
			m.raiseAlert(event, core.SeverityCritical,
				"Kubernetes RBAC Wildcard Permissions",
				fmt.Sprintf("RBAC role %q in namespace %q grants wildcard permissions (verbs: %s, resources: %s). "+
					"Changed by %s. Apply least-privilege RBAC.",
					role, namespace, verbs, resources, user),
				"k8s_rbac_wildcard")
		}

		// Detect cluster-admin binding to non-system accounts
		if strings.Contains(strings.ToLower(role), "cluster-admin") &&
			!strings.HasPrefix(user, "system:") {
			m.raiseAlert(event, core.SeverityHigh,
				"Kubernetes Cluster-Admin Binding",
				fmt.Sprintf("User %q bound to cluster-admin role in namespace %q. "+
					"Cluster-admin grants unrestricted access to all resources.",
					user, namespace),
				"k8s_cluster_admin_binding")
		}

		// Detect secrets access grants
		if strings.Contains(strings.ToLower(resources), "secrets") &&
			(strings.Contains(verbs, "get") || strings.Contains(verbs, "list") || strings.Contains(verbs, "*")) {
			m.raiseAlert(event, core.SeverityHigh,
				"Kubernetes Secrets Access Granted",
				fmt.Sprintf("RBAC role %q grants access to secrets (verbs: %s) in namespace %q. "+
					"Secrets access should be tightly controlled.",
					role, verbs, namespace),
				"k8s_secrets_access")
		}

	case "k8s_admission":
		// Detect privileged container admission
		privileged := getStringDetail(event, "privileged")
		hostNetwork := getStringDetail(event, "host_network")
		hostPID := getStringDetail(event, "host_pid")

		if privileged == "true" {
			m.raiseAlert(event, core.SeverityCritical,
				"Privileged Container Admitted",
				fmt.Sprintf("Privileged container admitted in namespace %q (resource: %s) by %s. "+
					"Privileged containers can escape to the host.",
					namespace, resource, user),
				"k8s_privileged_container")
		}

		if hostNetwork == "true" || hostPID == "true" {
			m.raiseAlert(event, core.SeverityHigh,
				"Container with Host Namespace Access",
				fmt.Sprintf("Container in namespace %q admitted with host access (hostNetwork: %s, hostPID: %s). "+
					"Host namespace sharing breaks container isolation.",
					namespace, hostNetwork, hostPID),
				"k8s_host_namespace")
		}

		m.checkRestoreAdmission(event, namespace, resource, user)
		m.checkAdmissionProfiles(event, namespace, resource)

	case "k8s_network_policy":
		// Detect missing or overly permissive network policies
		policyAction := getStringDetail(event, "policy_action")
		if policyAction == "deleted" || action == "delete" {
			m.raiseAlert(event, core.SeverityHigh,
				"Kubernetes Network Policy Deleted",
				fmt.Sprintf("Network policy %q deleted from namespace %q by %s. "+
					"Without network policies, all pod-to-pod traffic is allowed.",
					resource, namespace, user),
				"k8s_netpol_deleted")
		}
	}
}

func (m *Manager) checkRestoreAdmission(event *core.SecurityEvent, namespace, resource, user string) {
	key := admissionBaselineKey(namespace, resource)
	if key == "" {
		return
	}

	current := fingerprintAdmission(event)
	if !isRestoreAdmission(event) {
		m.restoreMu.Lock()
		m.restoreState[key] = current
		m.restoreMu.Unlock()
		return
	}

	m.restoreMu.Lock()
	previous := m.restoreState[key]
	m.restoreMu.Unlock()

	privileged := getStringDetail(event, "privileged") == "true"
	hostNetwork := getStringDetail(event, "host_network") == "true"
	hostPID := getStringDetail(event, "host_pid") == "true"
	dangerousCaps := hasDangerousCapability(getStringDetail(event, "capabilities"))

	if previous != "" && previous != current && (privileged || hostNetwork || hostPID || dangerousCaps) {
		m.raiseAlert(event, core.SeverityCritical,
			"Kubernetes Restore Drift Introduced Host Escape Risk",
			fmt.Sprintf("Restore-style admission for %s/%s by %s changed the pod security baseline and introduced privileged or host-level access. Backup/restore hooks must preserve the original hardened security context.",
				namespace, resource, user),
			"k8s_restore_privilege_escalation")
		return
	}

	if previous == "" && (privileged || hostNetwork || hostPID || dangerousCaps) {
		m.raiseAlert(event, core.SeverityHigh,
			"Restore Admission Added Sensitive Container Permissions",
			fmt.Sprintf("Restore-style admission for %s/%s by %s requested privileged settings without a known baseline. Review backup/restore automation for security-context drift.",
				namespace, resource, user),
			"k8s_restore_privilege_escalation")
	}
}

func (m *Manager) checkAdmissionProfiles(event *core.SecurityEvent, namespace, resource string) {
	weaknesses := collectProfileWeaknesses(event)
	for _, weakness := range weaknesses {
		m.raiseAlert(event, weakness.Severity,
			weakness.Title,
			fmt.Sprintf("Workload %s/%s uses a container profile that remains bypassable: %s",
				namespace, resource, weakness.Description),
			weakness.AlertType)
	}
}

type profileWeakness struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
}

func collectProfileWeaknesses(event *core.SecurityEvent) []profileWeakness {
	apparmor := strings.ToLower(getStringDetail(event, "apparmor_profile") + "\n" + getStringDetail(event, "apparmor_policy"))
	seccomp := strings.ToLower(getStringDetail(event, "seccomp_profile") + "\n" + getStringDetail(event, "seccomp_policy"))

	var weaknesses []profileWeakness
	if strings.Contains(apparmor, "unconfined") {
		weaknesses = append(weaknesses, profileWeakness{
			Title:       "AppArmor Unconfined Workload",
			Description: "AppArmor is set to unconfined, which removes the LSM barrier entirely for this workload.",
			Severity:    core.SeverityCritical,
			AlertType:   "container_profile_bypass",
		})
	}
	if strings.Contains(apparmor, "mount,") && !strings.Contains(apparmor, "deny mount") {
		weaknesses = append(weaknesses, profileWeakness{
			Title:       "AppArmor Mount Evasion Gap",
			Description: "Profile allows mount operations without an explicit deny rule, enabling denylist-style AppArmor bypass and container breakout staging.",
			Severity:    core.SeverityHigh,
			AlertType:   "container_profile_bypass",
		})
	}
	if allowsBindRemount(apparmor) && !hasReadonlyRemountGuard(apparmor) {
		weaknesses = append(weaknesses, profileWeakness{
			Title:       "AppArmor Remount Bind Escape Gap",
			Description: "Profile allows bind/remount-style mount operations without enforcing read-only remount protections, enabling denylist evasion similar to recent container breakout research.",
			Severity:    core.SeverityCritical,
			AlertType:   "container_profile_bypass",
		})
	}
	if strings.Contains(apparmor, "ptrace") && !strings.Contains(apparmor, "deny ptrace") {
		weaknesses = append(weaknesses, profileWeakness{
			Title:       "AppArmor Ptrace Escape Gap",
			Description: "Profile references ptrace controls without an explicit deny, leaving room for denylist evasion through process introspection.",
			Severity:    core.SeverityHigh,
			AlertType:   "container_profile_bypass",
		})
	}
	if strings.Contains(seccomp, "scmp_act_allow") {
		sensitiveSyscalls := []string{"mount", "umount2", "move_mount", "open_tree", "fsopen", "fsmount", "mount_setattr", "pivot_root", "ptrace", "bpf", "clone3", "unshare", "setns", "perf_event_open", "keyctl", "init_module", "finit_module"}
		for _, syscall := range sensitiveSyscalls {
			if strings.Contains(seccomp, syscall) {
				weaknesses = append(weaknesses, profileWeakness{
					Title:       "Permissive Seccomp Sensitive Syscall",
					Description: fmt.Sprintf("Seccomp profile defaults to allow while still exposing %s, which weakens breakout prevention during restore or rollout workflows.", syscall),
					Severity:    core.SeverityHigh,
					AlertType:   "container_profile_bypass",
				})
				break
			}
		}
	}
	return dedupeProfileWeaknesses(weaknesses)
}

func dedupeProfileWeaknesses(in []profileWeakness) []profileWeakness {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]profileWeakness, 0, len(in))
	for _, weakness := range in {
		key := weakness.Title + ":" + weakness.AlertType
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, weakness)
	}
	return out
}

func admissionBaselineKey(namespace, resource string) string {
	if namespace == "" && resource == "" {
		return ""
	}
	return strings.ToLower(namespace + "/" + resource)
}

func fingerprintAdmission(event *core.SecurityEvent) string {
	payload := strings.Join([]string{
		getStringDetail(event, "privileged"),
		getStringDetail(event, "host_network"),
		getStringDetail(event, "host_pid"),
		getStringDetail(event, "capabilities"),
		getStringDetail(event, "service_account"),
		getStringDetail(event, "apparmor_profile"),
		getStringDetail(event, "apparmor_policy"),
		getStringDetail(event, "seccomp_profile"),
		getStringDetail(event, "seccomp_policy"),
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return fmt.Sprintf("%x", sum[:])
}

func isRestoreAdmission(event *core.SecurityEvent) bool {
	restoreSignals := []string{
		getStringDetail(event, "action"),
		getStringDetail(event, "operation"),
		getStringDetail(event, "restore_name"),
		getStringDetail(event, "backup_name"),
		getStringDetail(event, "annotations"),
		event.Summary,
	}
	for _, signal := range restoreSignals {
		lower := strings.ToLower(signal)
		if strings.Contains(lower, "restore") || strings.Contains(lower, "velero.io/restore") || strings.Contains(lower, "backup") {
			return true
		}
	}
	return false
}

func hasDangerousCapability(capabilities string) bool {
	lower := strings.ToLower(capabilities)
	for _, cap := range []string{"sys_admin", "sys_ptrace", "net_admin", "net_raw", "sys_module", "dac_override"} {
		if strings.Contains(lower, cap) {
			return true
		}
	}
	return false
}

func allowsBindRemount(apparmor string) bool {
	return (strings.Contains(apparmor, "mount options=") || strings.Contains(apparmor, "mount,")) &&
		(strings.Contains(apparmor, "bind") || strings.Contains(apparmor, "remount"))
}

func hasReadonlyRemountGuard(apparmor string) bool {
	guards := []string{
		"ro,remount",
		"remount,ro",
		"deny remount",
		"deny mount options=(rw,bind)",
		"deny mount options=(bind,rw)",
		"options in (ro,remount)",
	}
	for _, guard := range guards {
		if strings.Contains(apparmor, guard) {
			return true
		}
	}
	return false
}

// handleContainerPosture detects container security misconfigurations.
func (m *Manager) handleContainerPosture(event *core.SecurityEvent) {
	image := getStringDetail(event, "image")
	runAsRoot := getStringDetail(event, "run_as_root")
	readOnlyFS := getStringDetail(event, "read_only_root_fs")
	capabilities := getStringDetail(event, "capabilities")
	namespace := getStringDetail(event, "namespace")

	if runAsRoot == "true" {
		m.raiseAlert(event, core.SeverityHigh,
			"Container Running as Root",
			fmt.Sprintf("Container image %q in namespace %q is running as root. "+
				"Containers should run as non-root users.",
				image, namespace),
			"container_root_user")
	}

	if readOnlyFS == "false" || readOnlyFS == "" {
		m.raiseAlert(event, core.SeverityMedium,
			"Container Without Read-Only Root Filesystem",
			fmt.Sprintf("Container image %q in namespace %q does not have a read-only root filesystem. "+
				"Writable filesystems increase the attack surface.",
				image, namespace),
			"container_writable_fs")
	}

	// Detect dangerous capabilities
	capsLower := strings.ToLower(capabilities)
	dangerousCaps := []string{"sys_admin", "sys_ptrace", "net_admin", "net_raw", "sys_module", "dac_override"}
	for _, cap := range dangerousCaps {
		if strings.Contains(capsLower, cap) {
			m.raiseAlert(event, core.SeverityHigh,
				"Container with Dangerous Capability",
				fmt.Sprintf("Container image %q in namespace %q has dangerous capability %s. "+
					"Drop all capabilities and add only what is needed.",
					image, namespace, strings.ToUpper(cap)),
				"container_dangerous_cap")
			break
		}
	}

	// Detect images without tags or using :latest
	if strings.HasSuffix(image, ":latest") || (!strings.Contains(image, ":") && image != "") {
		m.raiseAlert(event, core.SeverityMedium,
			"Container Using Unpinned Image Tag",
			fmt.Sprintf("Container image %q uses :latest or no tag. "+
				"Pin images to specific digests or version tags for reproducibility.",
				image),
			"container_unpinned_image")
	}
}

func (m *Manager) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewDerivedEvent(event, ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if m.bus != nil {
		_ = m.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getCloudPostureMitigations(alertType)
	if m.pipeline != nil {
		m.pipeline.Process(alert)
	}
}

func getCloudPostureMitigations(alertType string) []string {
	switch alertType {
	case "config_drift", "rapid_config_changes":
		return []string{
			"Implement infrastructure-as-code with drift detection and auto-remediation",
			"Use GitOps workflows to ensure all changes go through version control",
			"Alert on out-of-band changes that bypass the IaC pipeline",
		}
	case "security_degradation":
		return []string{
			"Immediately revert the security-degrading change",
			"Implement preventive guardrails (SCPs, OPA policies) to block degradations",
			"Require approval workflows for security-sensitive configuration changes",
		}
	case "secret_detected", "secret_in_logs":
		return []string{
			"Rotate the exposed secret immediately",
			"Remove the secret from source code/logs and scrub from history",
			"Use a secrets manager (Vault, AWS Secrets Manager) instead of hardcoded values",
		}
	case "public_bucket", "public_database", "open_security_group":
		return []string{
			"Remove public access immediately",
			"Implement account-level public access blocks",
			"Deploy automated remediation for public resource detection",
		}
	case "permissive_iam":
		return []string{
			"Replace wildcard permissions with specific resource and action grants",
			"Use IAM Access Analyzer to identify unused permissions",
			"Implement permission boundaries to limit maximum possible permissions",
		}
	case "k8s_rbac_wildcard", "k8s_cluster_admin_binding", "k8s_secrets_access":
		return []string{
			"Apply least-privilege RBAC: grant only the specific verbs and resources needed",
			"Avoid cluster-admin bindings for non-system accounts",
			"Use namespace-scoped roles instead of cluster-scoped where possible",
			"Audit RBAC bindings regularly with tools like kubectl-who-can",
		}
	case "k8s_privileged_container", "k8s_host_namespace":
		return []string{
			"Enforce Pod Security Standards (Restricted profile) via admission controllers",
			"Block privileged containers and host namespace access by default",
			"Use OPA Gatekeeper or Kyverno to enforce container security policies",
		}
	case "k8s_netpol_deleted":
		return []string{
			"Implement default-deny network policies for all namespaces",
			"Protect network policies with RBAC to prevent unauthorized deletion",
			"Monitor for network policy changes and alert on deletions",
		}
	case "container_root_user", "container_writable_fs", "container_dangerous_cap":
		return []string{
			"Run containers as non-root with a specific UID",
			"Set readOnlyRootFilesystem: true and use emptyDir for writable paths",
			"Drop all capabilities and add only required ones explicitly",
		}
	case "container_unpinned_image":
		return []string{
			"Pin container images to specific SHA256 digests",
			"Use image scanning in CI/CD to catch vulnerabilities before deployment",
			"Implement image allowlists in admission controllers",
		}
	default:
		return []string{
			"Review cloud configuration against security benchmarks (CIS, NIST)",
			"Implement continuous posture monitoring and automated remediation",
			"Maintain baseline configurations and alert on deviations",
		}
	}
}

// DriftTracker monitors configuration changes for drift.
type DriftTracker struct {
	mu        sync.RWMutex
	baselines map[string]*resourceBaseline
	changes   map[string]*changeHistory
}

type resourceBaseline struct {
	ResourceType string
	ExpectedHash string
	LastKnown    string
	SetAt        time.Time
}

type changeHistory struct {
	Count    int
	Window   time.Time
	LastUser string
}

type DriftResult struct {
	UnexpectedChange    bool
	SecurityDegradation bool
	RapidChanges        bool
	DegradationReason   string
	ChangeCount         int
}

func NewDriftTracker() *DriftTracker {
	return &DriftTracker{
		baselines: make(map[string]*resourceBaseline),
		changes:   make(map[string]*changeHistory),
	}
}

func (dt *DriftTracker) RecordChange(resource, resourceType, changeType, user, oldValue, newValue string) DriftResult {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	result := DriftResult{}
	now := time.Now()

	// Track change frequency
	hist, exists := dt.changes[resource]
	if !exists || now.Sub(hist.Window) > time.Hour {
		hist = &changeHistory{Window: now}
		dt.changes[resource] = hist
	}
	hist.Count++
	hist.LastUser = user
	result.ChangeCount = hist.Count

	if hist.Count > 10 {
		result.RapidChanges = true
	}

	// Check for security degradation patterns
	degradation := checkSecurityDegradation(resourceType, changeType, oldValue, newValue)
	if degradation != "" {
		result.SecurityDegradation = true
		result.DegradationReason = degradation
	}

	// Check against baseline
	baseline, hasBaseline := dt.baselines[resource]
	if hasBaseline && baseline.ExpectedHash != "" && newValue != baseline.ExpectedHash {
		result.UnexpectedChange = true
	}

	return result
}

func checkSecurityDegradation(resourceType, changeType, oldValue, newValue string) string {
	newLower := strings.ToLower(newValue)
	changeLower := strings.ToLower(changeType)

	// Public access enabled
	if strings.Contains(newLower, "public") && !strings.Contains(strings.ToLower(oldValue), "public") {
		return "resource changed from private to public access"
	}

	// Encryption disabled
	if strings.Contains(changeLower, "encryption") && (newLower == "false" || newLower == "disabled" || newLower == "none") {
		return "encryption was disabled"
	}

	// Logging disabled
	if strings.Contains(changeLower, "logging") && (newLower == "false" || newLower == "disabled") {
		return "logging was disabled"
	}

	// Firewall rule opened
	if strings.Contains(changeLower, "firewall") && strings.Contains(newLower, "0.0.0.0/0") {
		return "firewall opened to all traffic (0.0.0.0/0)"
	}

	// MFA disabled
	if strings.Contains(changeLower, "mfa") && (newLower == "false" || newLower == "disabled") {
		return "multi-factor authentication was disabled"
	}

	return ""
}

// SecretScanner detects secrets in text content.
type SecretScanner struct {
	patterns []secretPattern
}

type secretPattern struct {
	Name  string
	Type  string
	Regex *regexp.Regexp
}

type SecretFinding struct {
	PatternName string
	Type        string
}

func NewSecretScanner() *SecretScanner {
	return &SecretScanner{
		patterns: []secretPattern{
			{Name: "aws_access_key", Type: "AWS Access Key", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
			{Name: "aws_secret_key", Type: "AWS Secret Key", Regex: regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`)},
			{Name: "github_token", Type: "GitHub Token", Regex: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
			{Name: "github_oauth", Type: "GitHub OAuth", Regex: regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`)},
			{Name: "github_fine_grained", Type: "GitHub Fine-Grained PAT", Regex: regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{22,}`)},
			{Name: "gitlab_token", Type: "GitLab Token", Regex: regexp.MustCompile(`glpat-[a-zA-Z0-9\-]{20,}`)},
			{Name: "slack_token", Type: "Slack Token", Regex: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}`)},
			{Name: "openai_key", Type: "OpenAI API Key", Regex: regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`)},
			{Name: "anthropic_key", Type: "Anthropic API Key", Regex: regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-]{20,}`)},
			{Name: "stripe_key", Type: "Stripe Key", Regex: regexp.MustCompile(`(?:sk|pk)_(test|live)_[a-zA-Z0-9]{24,}`)},
			{Name: "private_key", Type: "Private Key", Regex: regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----`)},
			{Name: "generic_secret", Type: "Generic Secret", Regex: regexp.MustCompile(`(?i)(password|secret|token|api_key|apikey)\s*[=:]\s*['"][^'"]{8,}['"]`)},
			{Name: "connection_string", Type: "Connection String", Regex: regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s]+:[^\s]+@`)},
			{Name: "jwt_token", Type: "JWT Token", Regex: regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)},
			// 2025-2026 additions
			{Name: "gcp_service_account", Type: "GCP Service Account Key", Regex: regexp.MustCompile(`(?i)"type"\s*:\s*"service_account"`)},
			{Name: "azure_client_secret", Type: "Azure Client Secret", Regex: regexp.MustCompile(`(?i)(client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*[A-Za-z0-9\-_.~]{30,}`)},
			{Name: "hashicorp_vault_token", Type: "Vault Token", Regex: regexp.MustCompile(`hvs\.[a-zA-Z0-9_-]{24,}`)},
			{Name: "npm_token", Type: "NPM Token", Regex: regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)},
			{Name: "pypi_token", Type: "PyPI Token", Regex: regexp.MustCompile(`pypi-[a-zA-Z0-9_-]{50,}`)},
			{Name: "docker_hub_token", Type: "Docker Hub Token", Regex: regexp.MustCompile(`dckr_pat_[a-zA-Z0-9_-]{20,}`)},
			{Name: "age_secret_key", Type: "Age Secret Key", Regex: regexp.MustCompile(`AGE-SECRET-KEY-[A-Z0-9]{59}`)},
		},
	}
}

func (ss *SecretScanner) Scan(content string) []SecretFinding {
	var findings []SecretFinding
	for _, p := range ss.patterns {
		if p.Regex.MatchString(content) {
			findings = append(findings, SecretFinding{PatternName: p.Name, Type: p.Type})
		}
	}
	return findings
}

// CloudPolicyEngine checks for common cloud misconfigurations.
type CloudPolicyEngine struct {
	rules []policyRule
}

type policyRule struct {
	ResourceType string
	Check        func(event *core.SecurityEvent) *Misconfiguration
}

type Misconfiguration struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
}

func NewCloudPolicyEngine() *CloudPolicyEngine {
	pe := &CloudPolicyEngine{}
	pe.rules = []policyRule{
		{ResourceType: "storage_bucket", Check: checkPublicBucket},
		{ResourceType: "security_group", Check: checkOpenSecurityGroup},
		{ResourceType: "database", Check: checkPublicDatabase},
		{ResourceType: "iam_policy", Check: checkOverlyPermissiveIAM},
		{ResourceType: "k8s_pod", Check: checkK8sPodSecurity},
		{ResourceType: "k8s_service", Check: checkK8sExposedService},
	}
	return pe
}

func (pe *CloudPolicyEngine) CheckMisconfigurations(event *core.SecurityEvent) []*Misconfiguration {
	var results []*Misconfiguration
	resourceType := getStringDetail(event, "resource_type")

	for _, rule := range pe.rules {
		if rule.ResourceType == resourceType || resourceType == "" {
			if mc := rule.Check(event); mc != nil {
				results = append(results, mc)
			}
		}
	}
	return results
}

func checkPublicBucket(event *core.SecurityEvent) *Misconfiguration {
	acl := strings.ToLower(getStringDetail(event, "acl"))
	publicAccess := strings.ToLower(getStringDetail(event, "public_access"))
	if acl == "public-read" || acl == "public-read-write" || publicAccess == "true" || publicAccess == "enabled" {
		return &Misconfiguration{
			Title:       "Public Storage Bucket",
			Description: fmt.Sprintf("Storage bucket %s has public access enabled. This exposes data to the internet.", getStringDetail(event, "resource")),
			Severity:    core.SeverityCritical,
			AlertType:   "public_bucket",
		}
	}
	return nil
}

func checkOpenSecurityGroup(event *core.SecurityEvent) *Misconfiguration {
	ingressRule := getStringDetail(event, "ingress_cidr")
	port := getStringDetail(event, "port")
	if ingressRule == "0.0.0.0/0" && (port == "22" || port == "3389" || port == "3306" || port == "5432" || port == "27017") {
		return &Misconfiguration{
			Title:       "Security Group Open to Internet",
			Description: fmt.Sprintf("Security group allows inbound traffic from 0.0.0.0/0 on sensitive port %s.", port),
			Severity:    core.SeverityCritical,
			AlertType:   "open_security_group",
		}
	}
	return nil
}

func checkPublicDatabase(event *core.SecurityEvent) *Misconfiguration {
	publiclyAccessible := strings.ToLower(getStringDetail(event, "publicly_accessible"))
	if publiclyAccessible == "true" || publiclyAccessible == "yes" {
		return &Misconfiguration{
			Title:       "Publicly Accessible Database",
			Description: fmt.Sprintf("Database %s is publicly accessible. Databases should not be exposed to the internet.", getStringDetail(event, "resource")),
			Severity:    core.SeverityCritical,
			AlertType:   "public_database",
		}
	}
	return nil
}

func checkOverlyPermissiveIAM(event *core.SecurityEvent) *Misconfiguration {
	policy := getStringDetail(event, "policy")
	if strings.Contains(policy, "\"Action\": \"*\"") || strings.Contains(policy, "\"Resource\": \"*\"") {
		return &Misconfiguration{
			Title:       "Overly Permissive IAM Policy",
			Description: fmt.Sprintf("IAM policy on %s uses wildcard permissions. Apply least-privilege principle.", getStringDetail(event, "resource")),
			Severity:    core.SeverityHigh,
			AlertType:   "permissive_iam",
		}
	}
	return nil
}

func checkK8sPodSecurity(event *core.SecurityEvent) *Misconfiguration {
	privileged := getStringDetail(event, "privileged")
	runAsRoot := getStringDetail(event, "run_as_root")
	if privileged == "true" {
		return &Misconfiguration{
			Title:       "Privileged Pod Detected",
			Description: fmt.Sprintf("Pod %s is running in privileged mode. This grants full host access.", getStringDetail(event, "resource")),
			Severity:    core.SeverityCritical,
			AlertType:   "k8s_privileged_pod",
		}
	}
	if runAsRoot == "true" {
		return &Misconfiguration{
			Title:       "Pod Running as Root",
			Description: fmt.Sprintf("Pod %s is running as root user. Use runAsNonRoot: true.", getStringDetail(event, "resource")),
			Severity:    core.SeverityHigh,
			AlertType:   "k8s_root_pod",
		}
	}
	return nil
}

func checkK8sExposedService(event *core.SecurityEvent) *Misconfiguration {
	serviceType := getStringDetail(event, "service_type")
	if serviceType == "LoadBalancer" || serviceType == "NodePort" {
		namespace := getStringDetail(event, "namespace")
		if namespace == "default" || namespace == "kube-system" {
			return &Misconfiguration{
				Title:       "Kubernetes Service Exposed in Sensitive Namespace",
				Description: fmt.Sprintf("Service %s of type %s in namespace %q is externally accessible. Sensitive namespaces should not expose services directly.", getStringDetail(event, "resource"), serviceType, namespace),
				Severity:    core.SeverityHigh,
				AlertType:   "k8s_exposed_service",
			}
		}
	}
	return nil
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
