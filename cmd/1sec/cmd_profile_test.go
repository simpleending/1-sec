package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportedProfileRetainsContentInPrivateFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	source := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(source, []byte("server:\n  api_keys: [private-key]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmdProfileCreate([]string{"--from", source, "private-profile"})
	path, err := profilePath("private-profile")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "private-key") {
		t.Fatal("profile import lost", err)
	}
}
