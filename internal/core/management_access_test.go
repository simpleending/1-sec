package core

import (
	"strings"
	"testing"
)

func TestManagementAccessPolicy(t *testing.T) {
	policy, err := NewManagementAccessPolicy(ManagementAccessConfig{
		AllowedSources: []string{"10.20.0.0/24", "2001:db8:20::/64"}, AllowedOperators: []string{"engineer@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := ManagementAccessRequest{SourceIP: "10.20.0.7", Operator: "engineer@example.com", IdentityVerified: true, Target: "controller-17", Action: "configure"}
	for _, tc := range []struct {
		name   string
		change func(*ManagementAccessRequest)
		want   string
	}{
		{"authorized", func(r *ManagementAccessRequest) {}, "allowed"},
		{"external", func(r *ManagementAccessRequest) { r.SourceIP = "198.51.100.23" }, "source_not_allowed"},
		{"CIDR boundary", func(r *ManagementAccessRequest) { r.SourceIP = "10.20.1.0" }, "source_not_allowed"},
		{"IPv6", func(r *ManagementAccessRequest) { r.SourceIP = "2001:db8:20::1" }, "allowed"},
		{"mapped IPv4", func(r *ManagementAccessRequest) { r.SourceIP = "::ffff:10.20.0.7" }, "allowed"},
		{"spoofed host", func(r *ManagementAccessRequest) { r.SourceIP = "10.20.0.7.attacker.example" }, "source_not_allowed"},
		{"scoped IPv6", func(r *ManagementAccessRequest) { r.SourceIP = "2001:db8:20::1%eth0" }, "source_not_allowed"},
		{"forged identity", func(r *ManagementAccessRequest) { r.IdentityVerified = false }, "identity_not_verified"},
		{"unknown operator", func(r *ManagementAccessRequest) { r.Operator = "attacker@example.com" }, "operator_not_allowed"},
		{"case-sensitive identity", func(r *ManagementAccessRequest) { r.Operator = "ENGINEER@example.com" }, "operator_not_allowed"},
		{"missing target", func(r *ManagementAccessRequest) { r.Target = "" }, "invalid_request"},
		{"missing action", func(r *ManagementAccessRequest) { r.Action = "" }, "invalid_request"},
		{"ambiguous identity", func(r *ManagementAccessRequest) { r.Operator += " " }, "invalid_request"},
		{"oversized identity", func(r *ManagementAccessRequest) { r.Operator = strings.Repeat("x", 257) }, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.change(&req)
			got := policy.Check(req)
			if got.Reason != tc.want || got.Allowed != (tc.want == "allowed") {
				t.Fatalf("got %+v, want %s", got, tc.want)
			}
		})
	}
	for _, cfg := range []ManagementAccessConfig{{}, {AllowedSources: []string{}, AllowedOperators: []string{}}} {
		p, err := NewManagementAccessPolicy(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if p.Check(base).Allowed {
			t.Fatal("unconfigured policy must deny")
		}
	}
	var unavailable *ManagementAccessPolicy
	if unavailable.Check(base).Allowed {
		t.Fatal("uninitialized policy must deny")
	}
}

func TestManagementAccessConfigRejectsInvalidPolicy(t *testing.T) {
	for _, source := range []string{"0.0.0.0/0", "::/0", "localhost", "10.0.0.1:443", "10.0.0.0/99", "::ffff:10.0.0.0/104", "224.0.0.1", "0.0.0.0", "fe80::1%eth0"} {
		cfg := DefaultConfig()
		cfg.ManagementAccess = ManagementAccessConfig{AllowedSources: []string{source}, AllowedOperators: []string{"engineer"}}
		_, errs := cfg.Validate()
		if len(errs) == 0 {
			t.Errorf("invalid source %q passed config validation", source)
		}
	}
	for _, cfg := range []ManagementAccessConfig{
		{AllowedSources: []string{"10.20.0.0/24"}},
		{AllowedOperators: []string{"engineer"}},
		{AllowedSources: []string{"10.20.0.0/24"}, AllowedOperators: []string{" "}},
	} {
		if _, err := NewManagementAccessPolicy(cfg); err == nil {
			t.Errorf("invalid policy accepted: %+v", cfg)
		}
	}
}
