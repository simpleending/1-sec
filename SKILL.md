---
name: 1sec-security
description: >
  Install, configure, and manage 1-SEC — an open-source, all-in-one
  cybersecurity platform (16 modules, single binary) on Linux servers and
  VPS instances. Use when the user asks to secure a server, install security
  monitoring, set up intrusion detection, harden a VPS, protect an AI agent
  host, or deploy endpoint defense. Covers installation, setup, enforcement
  presets, module configuration, alert management, and ongoing security
  operations.
license: AGPL-3.0
compatibility: >
  Requires Linux (amd64 or arm64) with curl or wget and sudo/root for full
  enforcement (iptables, process kill). All 16 detection modules run without
  any API key. Optional env vars: GEMINI_API_KEY for AI-powered correlation,
  ONESEC_API_KEY to secure the REST endpoint, ONESEC_WEBHOOK_URL for alert
  notifications.
metadata:
  author: simpleending
  version: "0.4.11"
  source_repository: "https://github.com/simpleending/1-sec"
  security_policy: "https://github.com/simpleending/1-sec/blob/main/SECURITY.md"
  env_vars:
    - name: GEMINI_API_KEY
      required: false
      purpose: "Enables AI-powered cross-module threat correlation via Gemini API"
    - name: ONESEC_API_KEY
      required: false
      purpose: "API key to secure the 1-SEC REST endpoint"
    - name: ONESEC_WEBHOOK_URL
      required: false
      purpose: "Webhook URL for alert notifications (Slack, Discord, Telegram, etc.)"
  external_connections:
    - domain: "1-sec.dev"
      purpose: "Serves the install script (install.sh) and binary redirects to GitHub Releases"
      data_sent: "OS, architecture (detected locally by install script)"
      required: false
      enabled_by: "Only if user runs the quick-install; manual install path avoids this entirely"
    - domain: "github.com / objects.githubusercontent.com"
      purpose: "Download binary releases and checksums.txt for manual installation"
      data_sent: "Standard HTTPS request headers"
      required: false
      enabled_by: "Manual install path (recommended)"
    - domain: "api.1-sec.dev"
      purpose: "Cloud control plane for centralized multi-host management"
      data_sent: "Alert metadata, host identifier (only if cloud.enabled: true in config)"
      required: false
      enabled_by: "cloud.enabled: true in 1sec.yaml (opt-in, disabled by default)"
    - domain: "user-configured"
      purpose: "Webhook alert notifications (Slack, Discord, Telegram, PagerDuty, Teams)"
      data_sent: "Alert metadata as configured by user"
      required: false
      enabled_by: "webhook_urls set in 1sec.yaml or via CLI"
    - domain: "generativelanguage.googleapis.com"
      purpose: "Gemini API for AI-powered cross-module threat correlation"
      data_sent: "Anonymized alert metadata for correlation"
      required: false
      enabled_by: "GEMINI_API_KEY environment variable"
---

# 1-SEC Security Platform — Agent Skill

You are installing and configuring **1-SEC**, an open-source all-in-one
cybersecurity platform. One binary, 16 defense modules, zero config required.

> **Trust Statement:** Only install this skill if you trust the source.
> 1-SEC is open-source (AGPL-3.0) and available at
> https://github.com/simpleending/1-sec. Review the code, checksums, and
> SECURITY.md before deploying to production systems.

## Security & Privacy

**What leaves this machine:**
- Alert metadata — only if you configure webhooks or enable the cloud API (both opt-in)
- Anonymized alert context — only if `GEMINI_API_KEY` is set (opt-in)

**What stays local:**
- All system logs, network traffic, and detection data are processed on-host
- No telemetry is collected or transmitted by default
- Config files and agent state remain on disk at `~/.1sec/`

**Privileges used:**
- `iptables`/`nftables`: only when enforcement preset is active (opt-in)
- `kill_process`: only when enforcement preset is active (opt-in)
- `quarantine_file`: only when enforcement preset is active (opt-in)
- All enforcement is disabled by default (`dry_run: true`, `safe` preset)

**External Endpoints**

| Domain | Purpose | Data Sent | Required | Enabled By |
|--------|---------|-----------|----------|------------|
| `1-sec.dev` | Serves install.sh redirect to GitHub Releases | OS/arch from install script | No | Quick-install only |
| `github.com` | Binary release downloads + `checksums.txt` | Standard HTTP headers | No | Manual install |
| `api.1-sec.dev` | Cloud control plane (centralized management) | Alert metadata, host ID | No | `cloud.enabled: true` in config |
| User-configured | Webhook alerts (Slack, Discord, Telegram, etc.) | Alert payload | No | `webhook_urls` in config |
| `generativelanguage.googleapis.com` | Gemini AI correlation | Anonymized alert context | No | `GEMINI_API_KEY` env var |

## When to Use This Skill

- User asks to "secure this server" or "install security monitoring"
- User wants intrusion detection, WAF, LLM firewall, or ransomware protection
- User is deploying an AI agent (OpenClaw, Manus, etc.) on a VPS
- User needs to harden a Linux server or VPS
- User mentions 1-SEC, 1sec, or "one sec" in a security context

## Installation

### Recommended: Manual Install with Checksum Verification

For production use, always download from GitHub Releases and verify before
running as root:

```bash
# 1. Download the release binary and checksums
VERSION="0.4.11"
wget https://github.com/simpleending/1-sec/releases/download/v${VERSION}/1sec-linux-amd64
wget https://github.com/simpleending/1-sec/releases/download/v${VERSION}/checksums.txt

# 2. Verify SHA256 checksum
sha256sum -c checksums.txt 2>&1 | grep 1sec-linux-amd64

# 3. Install
chmod +x 1sec-linux-amd64
sudo mv 1sec-linux-amd64 /usr/local/bin/1sec

# 4. Confirm
1sec --version
```

For arm64, replace `1sec-linux-amd64` with `1sec-linux-arm64`.

### Alternative: Quick Install (Testing / Non-Critical Environments)

```bash
# Download and review the install script first
curl -fsSL https://1-sec.dev/get -o install.sh
cat install.sh          # Review before running
sh install.sh           # Run after review
```

> **Note:** Piping remote scripts directly to `sh` (`curl | sh`) is
> convenient but bypasses local review. The quick-install script is open-source
> at https://github.com/simpleending/1-sec/blob/main/install.sh — review it before
> use on production systems.

## Post-Install Setup

### Option A: Non-interactive (recommended for agents)

```bash
1sec setup --non-interactive
1sec up
```

### Option B: AI agent VPS deployment

The `vps-agent` preset is designed for unattended AI agent hosts. It enables
aggressive enforcement (process kills, file quarantine, IP blocks) to protect
against prompt injection, malicious skills, and credential theft.

**Always start in dry-run mode and validate before going live:**

```bash
1sec setup --non-interactive

# Start in dry-run — no live enforcement yet
1sec enforce preset vps-agent --dry-run
1sec up

# Monitor 24-48 hours to validate behavior before going live
1sec alerts
1sec enforce history

# Go live only after validating dry-run output
1sec enforce dry-run off
```

### Option C: Interactive setup

```bash
1sec setup
```

## Enforcement Presets

1-SEC ships with `dry_run: true` and the `safe` preset by default. No live
enforcement happens until you explicitly enable it.

| Preset | Behavior |
|--------|----------|
| `lax` | Log + webhook only. Never blocks or kills. |
| `safe` | Default. Blocks only brute force + port scans at CRITICAL. |
| `balanced` | Blocks IPs on HIGH, kills processes on CRITICAL. |
| `strict` | Aggressive enforcement on MEDIUM+. |
| `vps-agent` | Max security for unattended AI agent hosts. Aggressive on auth, LLM firewall, containment, runtime, supply chain. |

```bash
# Preview a preset without applying
1sec enforce preset strict --show

# Apply with dry-run protection
1sec enforce preset balanced --dry-run

# Apply live
1sec enforce preset balanced
```

## AI Analysis (Optional)

All 16 detection modules work with zero API keys. To add AI-powered correlation:

```bash
export GEMINI_API_KEY=your_key_here
1sec up
```

## Essential Commands

```bash
1sec up                        # Start engine (all 16 modules)
1sec status                    # Engine status
1sec alerts                    # Recent alerts
1sec alerts --severity HIGH    # Filter by severity
1sec modules                   # List all modules
1sec dashboard                 # Real-time TUI dashboard
1sec check                     # Pre-flight diagnostics
1sec doctor                    # Health check with fix suggestions
1sec stop                      # Graceful shutdown
```

## The 16 Modules

| # | Module | Covers |
|---|--------|--------|
| 1 | Network Guardian | DDoS, rate limiting, IP reputation, C2 beaconing, port scans |
| 2 | API Fortress | BOLA, schema validation, shadow API discovery |
| 3 | IoT & OT Shield | Device fingerprinting, protocol anomaly, firmware integrity |
| 4 | Injection Shield | SQLi, XSS, SSRF, command injection, template injection |
| 5 | Supply Chain Sentinel | SBOM, typosquatting, dependency confusion, CI/CD |
| 6 | Ransomware Interceptor | Encryption detection, canary files, wiper detection |
| 7 | Auth Fortress | Brute force, credential stuffing, MFA fatigue, AitM |
| 8 | Deepfake Shield | Audio forensics, AI phishing, BEC detection |
| 9 | Identity Fabric | Synthetic identity, privilege escalation |
| 10 | LLM Firewall | 65+ prompt injection patterns, jailbreak detection, multimodal scanning |
| 11 | AI Agent Containment | Action sandboxing, scope escalation, OWASP Agentic Top 10 |
| 12 | Data Poisoning Guard | Training data integrity, RAG pipeline validation |
| 13 | Quantum-Ready Crypto | Crypto inventory, PQC readiness, TLS auditing |
| 14 | Runtime Watcher | FIM, container escape, LOLBin, memory injection |
| 15 | Cloud Posture Manager | Config drift, misconfiguration, secrets sprawl |
| 16 | AI Analysis Engine | Two-tier Gemini pipeline for correlation |

## Additional References

- `1sec-security/references/operations-runbook.md` — Day-to-day operations
- `1sec-security/references/config-reference.md` — Full configuration reference
- `1sec-security/references/vps-agent-guide.md` — VPS agent deployment guide
- `1sec-security/scripts/install-and-configure.sh` — Automated install script
