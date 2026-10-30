package core

import (
	"context"
	"reflect"
	"regexp"
	"testing"
)

func TestProcessNameCannotBroadenKillSelection(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, name := range []string{"...", "worker.py", "-evil", "worker"} {
			cmd := killProcessCommand(context.Background(), platform, "", name)
			want := []string{"pkill", "-9", "-x", "--", regexp.QuoteMeta(name)}
			if !reflect.DeepEqual(cmd.Args, want) {
				t.Errorf("%s %q: args %q, want literal exact selector %q", platform, name, cmd.Args, want)
				continue
			}
			selector := regexp.MustCompile("^(?:" + cmd.Args[len(cmd.Args)-1] + ")$")
			if !selector.MatchString(name) || selector.MatchString("prefix"+name) || selector.MatchString("sshd") {
				t.Errorf("selector for %q broadened process selection", name)
			}
		}
	}
}

func TestProcessKillPIDTakesPrecedence(t *testing.T) {
	cmd := killProcessCommand(context.Background(), "linux", "4242", "...")
	if !reflect.DeepEqual(cmd.Args, []string{"kill", "-9", "4242"}) {
		t.Fatalf("unexpected PID selection: %q", cmd.Args)
	}
	cmd = killProcessCommand(context.Background(), "windows", "", "worker.exe")
	if !reflect.DeepEqual(cmd.Args, []string{"taskkill", "/F", "/IM", "worker.exe"}) {
		t.Fatalf("unexpected Windows selection: %q", cmd.Args)
	}
}
