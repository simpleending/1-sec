package core

import (
	"fmt"
	"strings"
)

// GetApprovalGate returns an isolated snapshot of the runtime configuration.
func (ec *EnforcementConfig) GetApprovalGate() ApprovalGateConfig {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	config := ec.ApprovalGate
	config.RequireApproval = append([]string{}, config.RequireApproval...)
	return config
}

// UpdateApprovalSettings validates the whole change before changing either the
// displayed configuration or the live gate's independently held configuration.
func UpdateApprovalSettings(ec *EnforcementConfig, gate *ApprovalGate, auto *string, required []string) error {
	if auto != nil {
		value := strings.ToUpper(*auto)
		if value != "" && value != "LOW" && value != "MEDIUM" && value != "HIGH" && value != "CRITICAL" {
			return fmt.Errorf("invalid auto_approve_above")
		}
	}
	valid := map[string]bool{"block_ip": true, "kill_process": true, "quarantine_file": true, "drop_connection": true, "disable_user": true, "webhook": true, "command": true, "log_only": true}
	for _, action := range required {
		if !valid[action] {
			return fmt.Errorf("unknown action in require_approval: %s", action)
		}
	}
	ec.mu.Lock()
	defer ec.mu.Unlock()
	if auto != nil {
		ec.ApprovalGate.AutoApproveAbove = strings.ToUpper(*auto)
	}
	if required != nil {
		ec.ApprovalGate.RequireApproval = append([]string{}, required...)
	}
	if gate != nil {
		gate.mu.Lock()
		defer gate.mu.Unlock()
		gate.cfg.AutoApproveAbove = ec.ApprovalGate.AutoApproveAbove
		gate.cfg.RequireApproval = append([]string{}, ec.ApprovalGate.RequireApproval...)
	}
	return nil
}

func (re *ResponseEngine) PolicyStates() map[string]bool {
	re.mu.RLock()
	defer re.mu.RUnlock()
	states := make(map[string]bool, len(re.policies))
	for name, policy := range re.policies {
		states[name] = policy.Enabled
	}
	return states
}
