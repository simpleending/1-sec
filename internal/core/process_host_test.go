package core

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestLocalProcessHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if err := validateLocalProcessHost(host); err != nil {
			t.Fatal(err)
		}
	}
	if hostname, err := os.Hostname(); err == nil {
		if err := validateLocalProcessHost(hostname); err != nil {
			t.Fatal(err)
		}
	}
	for _, host := range []string{"192.0.2.44", "collector.example.invalid", "127.0.0.1.attacker.invalid", "0.0.0.0"} {
		if err := validateLocalProcessHost(host); err == nil {
			t.Fatalf("accepted remote process host %q", host)
		}
	}
}

func TestKillProcessRejectsRemoteTargetBeforeExecution(t *testing.T) {
	alert := NewAlert(NewSecurityEvent("ransomware", "mass_encryption", SeverityCritical, "test"), "test", "test")
	alert.Metadata["process_host"] = "192.0.2.44"
	alert.Metadata["process_id"] = "invalid-pid"
	_, _, err := (&KillProcessExecutor{}).Execute(context.Background(), alert, ResponseRule{}, zerolog.Nop())
	if err == nil || !strings.Contains(err.Error(), "not local") {
		t.Fatalf("remote host was not rejected before PID processing: %v", err)
	}
	alert.Metadata["file_path"] = "missing-file"
	_, _, err = (&QuarantineFileExecutor{}).Execute(context.Background(), alert, ResponseRule{}, zerolog.Nop())
	if err == nil || !strings.Contains(err.Error(), "not local") {
		t.Fatalf("remote host was not rejected before file processing: %v", err)
	}
}
