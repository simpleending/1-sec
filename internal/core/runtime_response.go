package core

import "strconv"

// Runtime file/privilege/container observations do not identify an actor in this
// executor's PID namespace. Only explicitly attributed process detections qualify.
func runtimeProcessResponseAllowed(alert *Alert) bool {
	evidence, _ := alert.Metadata["runtime_process_evidence"].(bool)
	pid, _ := alert.Metadata["process_id"].(string)
	n, err := strconv.ParseUint(pid, 10, 31)
	if !evidence || err != nil || n < 2 || strconv.FormatUint(n, 10) != pid {
		return false
	}
	host, _ := alert.Metadata["process_host"].(string)
	if host == "" {
		return false
	}
	for _, key := range []string{"process_host", "hostname", "syslog_hostname", "host_id"} {
		if value, exists := alert.Metadata[key]; exists {
			name, ok := value.(string)
			if !ok || validateLocalProcessHost(name) != nil {
				return false
			}
		}
	}
	for _, key := range []string{"container_id", "pid_namespace"} {
		if value, exists := alert.Metadata[key]; exists && value != "" {
			return false
		}
	}
	origin, _ := alert.Metadata["runtime_event_type"].(string)
	switch alert.Type {
	case "lolbin_abuse", "symlink_privilege_escalation", "symlink_creation", "ytdlp_rce",
		"library_path_hijack", "suspicious_process", "reverse_shell", "exec_path_swap",
		"exec_integrity_mismatch", "exec_transient_path":
		return origin == "process_start" || origin == "process_exec"
	case "encoded_fileless_exec", "download_cradle", "amsi_bypass", "etw_bypass",
		"lua_shellcode_loader", "wmi_execution", "fileless_execution":
		return origin == "fileless_execution" || origin == "powershell_exec" || origin == "wmi_exec" || origin == "mshta_exec"
	case "memory_injection":
		return origin == "memory_injection" || origin == "process_hollowing" || origin == "dll_injection"
	}
	return false
}
