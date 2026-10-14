package core

import (
	"fmt"
	"net/netip"
	"strings"
)

// ManagementAccessConfig restricts operators admitted by a trusted access gateway.
type ManagementAccessConfig struct {
	AllowedSources   []string `yaml:"allowed_sources"`
	AllowedOperators []string `yaml:"allowed_operators"`
}

// ManagementAccessRequest must be built by a trusted gateway after verifying the
// operator's identity. IdentityVerified is never an end-user supplied claim.
type ManagementAccessRequest struct {
	SourceIP         string `json:"source_ip"`
	Operator         string `json:"operator"`
	IdentityVerified bool   `json:"identity_verified"`
	Target           string `json:"target"`
	Action           string `json:"action"`
}

type ManagementAccessDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// ManagementAccessPolicy is immutable after construction and shared by checks.
type ManagementAccessPolicy struct {
	sources   []netip.Prefix
	operators map[string]bool
}

func NewManagementAccessPolicy(cfg ManagementAccessConfig) (*ManagementAccessPolicy, error) {
	p := &ManagementAccessPolicy{operators: make(map[string]bool)}
	if (len(cfg.AllowedSources) == 0) != (len(cfg.AllowedOperators) == 0) {
		return nil, fmt.Errorf("management_access requires both allowed_sources and allowed_operators")
	}
	for _, source := range cfg.AllowedSources {
		prefix, err := netip.ParsePrefix(source)
		if err != nil {
			addr, addrErr := netip.ParseAddr(source)
			if addrErr != nil || addr.Zone() != "" {
				return nil, fmt.Errorf("management_access.allowed_sources: invalid IP or CIDR %q", source)
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return nil, fmt.Errorf("management_access.allowed_sources: unsafe or ambiguous source %q", source)
		}
		p.sources = append(p.sources, prefix.Masked())
	}
	for _, operator := range cfg.AllowedOperators {
		if operator == "" || operator != strings.TrimSpace(operator) || len(operator) > 256 {
			return nil, fmt.Errorf("management_access.allowed_operators: invalid operator")
		}
		p.operators[operator] = true
	}
	return p, nil
}

func (p *ManagementAccessPolicy) Configured() bool {
	return p != nil && len(p.sources) > 0 && len(p.operators) > 0
}

func (p *ManagementAccessPolicy) SourceAllowed(source string) bool {
	if !p.Configured() {
		return false
	}
	addr, err := netip.ParseAddr(source)
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range p.sources {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (p *ManagementAccessPolicy) Check(req ManagementAccessRequest) ManagementAccessDecision {
	deny := func(reason string) ManagementAccessDecision {
		return ManagementAccessDecision{Reason: reason}
	}
	if !p.Configured() {
		return deny("policy_not_configured")
	}
	for _, value := range []string{req.SourceIP, req.Operator, req.Target, req.Action} {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 256 {
			return deny("invalid_request")
		}
	}
	if !p.SourceAllowed(req.SourceIP) {
		return deny("source_not_allowed")
	}
	if !req.IdentityVerified {
		return deny("identity_not_verified")
	}
	if !p.operators[req.Operator] {
		return deny("operator_not_allowed")
	}
	return ManagementAccessDecision{Allowed: true, Reason: "allowed"}
}
