package runtime

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"

	"github.com/1sec-project/1sec/internal/core"
)

// Preserve investigative context without treating observed files or injection
// victims as artifacts/processes that this host is authorized to contain.
func runtimeResponseEvidence(alert *core.Alert, event *core.SecurityEvent) {
	if event.ID != "" && !slices.Contains(alert.EventIDs, event.ID) {
		alert.EventIDs = append(alert.EventIDs, event.ID)
	}
	alert.Metadata["original_event_id"] = event.ID
	alert.Metadata["runtime_event_type"] = event.Type
	if path := firstStringDetail(event, "path", "executed_path", "executable_path", "driver_path"); path != "" {
		alert.Metadata["affected_path"] = path
	}

	host, validHost := "", true
	for _, key := range []string{"process_host", "hostname", "syslog_hostname", "host_id"} {
		if value, exists := event.Details[key]; exists {
			name, ok := value.(string)
			if !ok || name == "" || name == "-" {
				validHost = false
				continue
			}
			alert.Metadata[key] = name
			if host == "" {
				host = name
			}
		}
	}
	if host != "" {
		alert.Metadata["process_host"] = host
	}
	for _, key := range []string{"container_id", "pid_namespace"} {
		if value, exists := event.Details[key]; exists {
			name, ok := value.(string)
			if !ok || name != "" {
				validHost = false
			}
			if ok {
				alert.Metadata[key] = name
			}
		}
	}

	var pidKeys []string
	nameKey := "process_name"
	switch event.Type {
	case "process_start", "process_exec", "fileless_execution", "powershell_exec", "wmi_exec", "mshta_exec":
		pidKeys = []string{"process_id", "pid"}
	case "memory_injection", "process_hollowing", "dll_injection":
		// target_pid names the injected victim, not the actor.
		pidKeys, nameKey = []string{"source_pid"}, "source_process"
	default:
		return
	}
	if name, ok := event.Details[nameKey].(string); ok && name != "" {
		alert.Metadata["process_name"] = name
	}
	pid := ""
	for _, key := range pidKeys {
		if value, exists := event.Details[key]; exists {
			normalized, ok := runtimePID(value)
			if !ok || (pid != "" && normalized != pid) {
				return
			}
			pid = normalized
		}
	}
	if pid != "" && host != "" && validHost {
		alert.Metadata["process_id"] = pid
		// The shared action boundary additionally checks detector type and local
		// host identity. This marker is telemetry evidence, not authentication.
		alert.Metadata["runtime_process_evidence"] = true
	}
}

func runtimePID(value interface{}) (string, bool) {
	var text string
	switch v := value.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 2 || v > math.MaxInt32 || math.Trunc(v) != v {
			return "", false
		}
		return strconv.FormatInt(int64(v), 10), true
	case json.Number:
		n, ok := core.ParseProcessIDNumber(v)
		if !ok {
			return "", false
		}
		return runtimePID(n)
	case string:
		text = v
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		text = fmt.Sprint(v)
	default:
		return "", false
	}
	if text == "" {
		return "", false
	}
	for _, ch := range text {
		if ch < '0' || ch > '9' {
			return "", false
		}
	}
	n, err := strconv.ParseUint(text, 10, 31)
	if err != nil || n < 2 {
		return "", false
	}
	return strconv.FormatUint(n, 10), true
}
