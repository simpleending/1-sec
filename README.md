<div align="center">
  <img src="https://1-sec.dev/og-image.png" alt="1-SEC" width="100%">

  <h1>🛡️ 1-SEC</h1>
  <p><strong>One binary. Total defense.</strong></p>
  <p>16 security modules. Single binary. Zero config required.<br/>
  Covers AI attacks, prompt injection, ransomware, supply chain, deepfakes, quantum crypto, and more.</p>

  <p>
    <a href="https://github.com/simpleending/1-sec/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg?style=flat-square" alt="License"></a>
    <a href="https://golang.org/"><img src="https://img.shields.io/github/go-mod/go-version/simpleending/1-sec?style=flat-square&color=blue" alt="Go Version"></a>
    <a href="https://github.com/simpleending/1-sec/releases"><img src="https://img.shields.io/github/v/release/simpleending/1-sec?style=flat-square&color=orange" alt="Release"></a>
  </p>

  <p>
    <a href="https://1-sec.dev">Website</a> ·
    <a href="https://1-sec.dev/docs">Docs</a> ·
    <a href="https://1-sec.dev/pricing">Enterprise</a> ·
    <a href="https://1-sec.dev/dashboard">Dashboard</a>
  </p>
</div>

---

## What is 1-SEC?

1-SEC is an open-source (AGPLv3) all-in-one cybersecurity platform. Instead of running 10+ separate agents — WAF, IDS, log shipper, compliance scanner, LLM firewall — you run **one binary** that covers every attack surface through a shared NATS JetStream event bus.

- **Zero config by default** — secure out of the box, tune later
- **One default operational binary** — no required external runtime services for core operation
- **Privacy first** — your data stays on your server; cloud features are opt-in
- **AI is additive** — all 16 modules work standalone; the AI analysis layer adds cross-module correlation on top

---

## Quick Start

```bash
# Install
curl -fsSL https://1-sec.dev/get | sh
# Production installs should pin a release:
# curl -fsSL https://1-sec.dev/get | sh -s -- --version v1.2.3

# Guided setup (config + AI keys + API auth)
1sec setup

# Or run directly (all 16 modules, zero config)
1sec up
```

Build from source:

```bash
git clone https://github.com/simpleending/1-sec.git
cd 1-sec
go build -o 1sec ./cmd/1sec
./1sec up
```

Docker:

```bash
cd deploy/docker
docker compose up -d
docker compose logs -f
```

Kubernetes (Helm):

```bash
helm install 1sec ./deploy/helm \
  --set env.GEMINI_API_KEY=your_key_here
```

---

## 16 Defense Modules

| # | Module | What it covers | Tier |
|---|--------|---------------|------|
| 1 | **Network Guardian** | DDoS, rate limiting, IP reputation, geo-fencing, DNS tunneling, C2 beaconing, lateral movement (PtH, Kerberoasting, Golden Ticket, DCSync), port scan detection, dynamic IP threat scoring (auto-blocks repeat offenders across modules) | 1 |
| 2 | **API Fortress** | BOLA detection, schema validation, shadow API discovery, per-endpoint rate limiting, security misconfiguration detection, unsafe API consumption monitoring | 1 |
| 3 | **IoT & OT Shield** | Device fingerprinting, protocol anomaly (MQTT/CoAP/Modbus/DNP3/BACnet/OPC UA), firmware integrity, default credential detection (Dell, HPE, Lenovo, Supermicro), OT command validation, device behavior baselining, network segmentation enforcement, persistent firmware implant detection (HiatusRAT-X), ICS wiper malware detection (VoltRuptor), coordinated multi-protocol OT attack detection | 1 |
| 4 | **Injection Shield** | SQLi (including blind boolean/time/error-based), XSS, SSRF, command injection, template injection, NoSQL injection, path traversal, Zip Slip archive traversal, deserialization RCE (Java/PHP/.NET/Python pickle), canary token detection, 8-phase input normalization pipeline | 2 |
| 5 | **Supply Chain Sentinel** | SBOM generation, package integrity, typosquatting (Levenshtein), dependency confusion, CI/CD hardening | 2 |
| 6 | **Ransomware Interceptor** | Encryption detection (threshold: 5 files), canary files, exfiltration monitoring, wiper detection (MBR/GPT), shadow copy deletion, compound attack correlation, intermittent/partial encryption detection, ESXi/hypervisor ransomware targeting, SSH tunneling for lateral movement, pre-ransomware credential harvesting (Mimikatz, LSASS, NTLM, Kerberos), Linux ransomware patterns | 2 |
| 7 | **Auth Fortress** | Brute force, credential stuffing, session hijack, impossible travel, MFA fatigue, OAuth consent phishing, password spray, stolen token detection, AitM/adversary-in-the-middle detection, passkey/FIDO2/WebAuthn monitoring, auth downgrade detection | 3 |
| 8 | **Deepfake Shield** | Prosodic audio analysis (pitch/jitter/shimmer/HNR), MFCC trajectory smoothness, phase coherence, spectral flatness, ELA video forensics, AI phishing with writing style analysis, expanded Unicode homoglyph + Punycode domain spoofing, reply-chain verification, BEC detection | 3 |
| 9 | **Identity Fabric Monitor** | Synthetic identity detection, privilege escalation, service account anomaly, bulk creation detection | 3 |
| 10 | **LLM Firewall** | 65+ prompt injection patterns, jailbreak detection (DAN, FlipAttack, many-shot, time bandit, skeleton key, XPIA, LPCI, etc.), output filtering, multi-turn tracking, tool-chain abuse, excessive agency monitoring, system prompt leakage detection, RAG/embedding weakness analysis, misinformation detection, multimodal hidden injection scanning (image metadata, HTML/CSS, PDF hidden text). Zero LLM calls, zero external dependencies. | 4 |
| 11 | **AI Agent Containment** | Action sandboxing, tool-use monitoring, shadow AI detection, scope escalation, policy enforcement, OWASP Agentic AI Top 10 coverage, tool integrity monitoring, goal hijack detection, memory poisoning detection, cascade failure monitoring | 4 |
| 12 | **Data Poisoning Guard** | Training data integrity, RAG pipeline validation (30+ injection patterns incl. delimiter/exfiltration attacks), adversarial input detection, model drift monitoring with output distribution tracking (Jensen-Shannon divergence), model supply chain attack detection (slopsquatting, unsigned models) | 4 |
| 13 | **Quantum-Ready Crypto** | Crypto inventory, PQC migration readiness, TLS auditing, cert expiry, HNDL attack detection | 5 |
| 14 | **Runtime Watcher** | FIM, container escape, LOLBin detection (40+), memory injection (process hollowing, DLL injection), persistence mechanisms, UEFI/bootkit, fileless malware, symlink privilege escalation, ETW/logging evasion, Lua shellcode loader detection | 6 |
| 15 | **Cloud Posture Manager** | Config drift, misconfiguration (public buckets, open SGs, wildcard IAM), secrets sprawl, Kubernetes RBAC auditing, container posture checks, KSPM | 6 |
| 16 | **AI Analysis Engine** | Two-tier Gemini pipeline: Flash Lite for triage, Flash for deep classification and cross-module correlation | X |
| — | **Threat Correlator** | Cross-module attack chain detection — automatically correlates alerts from multiple modules targeting the same source IP into unified incident alerts. 9 pre-defined attack chains (kill chain, credential→lateral, injection→persistence, etc.) | Core |

---

## CLI Reference

```
1sec up                          Start all enabled modules
1sec up --modules X,Y,Z          Start only specific modules
1sec up --config /path/cfg.yaml  Use a custom config file
1sec up --dry-run                Validate config without starting
1sec up --log-level debug        Override log level

1sec status                      Show running engine status
1sec status --json               JSON output

1sec alerts                      Fetch recent alerts
1sec alerts --severity CRITICAL  Filter by severity
1sec alerts --module llm_firewall Filter by module
1sec alerts --json --output f.json Save to file

1sec archive                     Manage historical alert storage (list, delete, vacuum)
1sec collect                     Manage local log collectors (auth, nginx, etc.)
1sec scan                        Submit payload via stdin
1sec scan --input file.json      Submit payload from file
1sec scan --module injection_shield --type sqli

1sec modules                     List all 16 modules
1sec modules --tier 4            Filter by tier
1sec modules --json

1sec dashboard                   Open the real-time TUI dashboard
1sec config                      Show resolved config
1sec config --validate           Validate and exit
1sec config --json
1sec config set-key <key>        Set Gemini API key for AI analysis
1sec config set-key --show       Show current AI key status (masked)
1sec config set-key --env        Import keys from GEMINI_API_KEY env vars

1sec check                       Pre-flight diagnostics
1sec doctor                      Health check with fix suggestions
1sec stop                        Gracefully stop instance

1sec docker up                   Start via Docker Compose
1sec docker down                 Stop containers
1sec docker logs                 Follow container logs
1sec docker status               Show container status
1sec docker build                Build image from source

1sec setup                       Guided interactive setup wizard
1sec setup --ai-only             Only configure AI (Gemini) keys
1sec setup --non-interactive     Use env vars, skip prompts

1sec correlator                  Inspect threat correlator state
1sec correlator --json           JSON output with chain definitions

1sec threats                     Query dynamic IP threat scoring
1sec threats --blocked           Show only blocked IPs
1sec threats --format csv        CSV output

1sec rust                        Check Rust sidecar engine status
1sec rust --json                 JSON output with config details

1sec enforce status              Enforcement engine status and stats
1sec enforce policies            List all response policies
1sec enforce history             Response action execution history
1sec enforce enable <module>     Enable enforcement for a module
1sec enforce disable <module>    Disable enforcement for a module
1sec enforce dry-run [on|off]    Toggle global dry-run mode
1sec enforce test <module>       Simulate alert to preview actions
1sec enforce preset <name>       Apply preset (lax, safe, balanced, strict, vps-agent)
1sec enforce approvals pending   List pending approval gates
1sec enforce approvals approve <id>  Approve a pending action
1sec enforce approvals reject <id>   Reject a pending action
1sec enforce history             Approval decision history
1sec enforce batching            Alert batcher stats
1sec enforce escalations         Escalation timer stats
1sec enforce chains list         Action chain definitions
1sec enforce chains records      Chain execution records

1sec version                     Print version + build info
1sec help <command>              Detailed help for any command
1sec completions [bash|zsh|ps1]  Generate shell autocompletes
1sec export                      Export alerts or configuration
1sec profile                     Start performance profiling (cpu, mem, trace)
1sec init                        Bootstrap a new configuration file
1sec events                      Inspect or ingest raw security events
```

---

## Configuration

Zero-config works out of the box. All settings have sane defaults. Override via `configs/default.yaml` or `--config`:

```yaml
server:
  host: "127.0.0.1"
  port: 1780
  allow_unauthenticated_read: false

bus:
  embedded: true        # NATS JetStream runs inside the binary
  data_dir: "./data/nats"
  port: 4222

modules:
  injection_shield:
    enabled: true
  auth_fortress:
    enabled: true
    settings:
      max_failures_per_minute: 10
      lockout_duration_seconds: 300
  deepfake_shield:
    enabled: true
    settings:
      trusted_domains:            # Add your org's domains for spoof detection
        - "yourcompany.com"
        - "partner.org"
      max_levenshtein: 2          # Typosquatting detection distance (default: 2)
  ai_analysis_engine:
    enabled: true
    settings:
      triage_model: "gemini-flash-lite-latest"
      deep_model: "gemini-flash-latest"
      # Keys read from env: GEMINI_API_KEY, GEMINI_API_KEY_2, ...
```

AI keys are read from environment variables — no key required for the 15 rule-based modules:

```bash
# Quickest way — one command
1sec config set-key AIzaSy...

# Or via environment variable
export GEMINI_API_KEY=your_key_here
1sec up

# Multiple keys for load balancing / rate-limit rotation
1sec config set-key key1 key2 key3

# Import from env vars
export GEMINI_API_KEY=key1
export GEMINI_API_KEY_2=key2
1sec config set-key --env

# Check key status
1sec config set-key --show
```

---

## Enforcement Presets

1-SEC ships with `dry_run: true` and the `safe` preset by default. This means all 16 modules detect threats immediately, but no enforcement actions (block IP, kill process, etc.) are actually executed until you're ready.

| Preset | Behavior | When to use |
|--------|----------|-------------|
| `lax` | Log + webhook only. Never blocks, kills, or quarantines. | Initial rollout, auditing, learning what fires |
| `safe` ⭐ | Log + webhook for most modules. `block_ip` only for brute force + port scans at CRITICAL. `kill_process` only for confirmed ransomware at CRITICAL. | **Default.** First deploy, low-risk enforcement |
| `balanced` | Blocks IPs on HIGH, kills processes on CRITICAL. Quarantines files. Disables compromised accounts. | Production environments with tuned allow lists |
| `strict` | Aggressive enforcement on MEDIUM+. Short cooldowns, high rate limits. Blocks, drops, kills on MEDIUM. | High-security environments, active incidents |
| `vps-agent` | Purpose-built for VPS-hosted AI agents (OpenClaw, Moltbot, Manus). Aggressive on auth, LLM firewall, containment, runtime, supply chain. Relaxed on IoT, deepfake, quantum. | Self-hosted AI agent deployments |

Recommended progression: `lax` → `safe` → `balanced` → `strict`

`vps-agent` is a standalone profile, not part of the escalation ladder.

```bash
# See what you're currently running
1sec enforce status

# Preview a preset before applying
1sec enforce preset balanced --show

# Apply a preset (starts in dry-run by default)
1sec enforce preset balanced

# Go live when you're confident
1sec enforce dry-run off

# Test what would happen for a specific module
1sec enforce test ransomware --severity CRITICAL
```

Override individual module policies in `configs/default.yaml` under `enforcement.policies` — these merge on top of the active preset.

---

## Deployment

### Single Binary

```bash
curl -fsSL https://1-sec.dev/get | sh
# Or pin a production install:
# curl -fsSL https://1-sec.dev/get | sh -s -- --version v1.2.3
1sec up
```

### Docker Compose

```bash
# Clone and start
git clone https://github.com/simpleending/1-sec.git
cd 1-sec/deploy/docker

# Set your Gemini key (optional — AI engine only)
echo "GEMINI_API_KEY=your_key" > .env

docker compose up -d
docker compose logs -f

# Check status
docker compose exec 1sec 1sec status
```

Or use the CLI shortcut from anywhere in the repo:

```bash
1sec docker up
1sec docker logs
1sec docker status
1sec docker down
```

### Kubernetes (Helm)

```bash
# Install with defaults
helm install 1sec ./deploy/helm

# Install with Gemini AI key
helm install 1sec ./deploy/helm \
  --set env.GEMINI_API_KEY=your_key_here

# Install with custom config
helm install 1sec ./deploy/helm \
  --set env.GEMINI_API_KEY=your_key_here \
  --set-string config="$(cat my-config.yaml)"

# Upgrade
helm upgrade 1sec ./deploy/helm --reuse-values

# Check status
kubectl exec deploy/1sec -- 1sec status
kubectl exec deploy/1sec -- 1sec check
```

The Helm chart includes:
- Deployment with liveness/readiness probes on `/health`
- PersistentVolumeClaim for NATS JetStream data
- ConfigMap for config override
- Secret for API keys (or reference an existing secret via `existingSecret`)
- Optional Ingress for the REST API
- Non-root security context, read-only root filesystem

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                      1SEC CLI / API / TUI                         │
│                     REST :1780   |  TUI Dashboard                 │
└───────────────────────────────┬───────────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────────┐
│              NATS JetStream Event Bus (Embedded) :4222            │
│  sec.events.>  sec.alerts.>  sec.matches.>  sec.responses.>       │
└───────┬───────────────────────┬──────────────────────────┬────────┘
        │                       │                          │
┌───────▼────────┐      ┌───────▼────────┐         ┌───────▼────────┐
│  GO ENGINE     │      │  RUST SIDECAR  │         │  COLLECTORS    │
│  16 Detection  │◄────►│  High-Perf DX  │◄────────┤  (Syslog, Auth,│
│    Modules     │      │  (DPI / PCAP)  │         │   Nginx, etc.) │
└───────┬────────┘      └────────────────┘         └────────────────┘
        │
┌───────▼────────┐      ┌────────────────┐         ┌────────────────┐
│ Threat         │      │ AI Engine      │         │ Enforcement    │
│ Correlator     │◄────►│ (Gemini Flash) │◄───────►│ (SOAR Engine)  │
│ (Attack Chains)│      │                │         │                │
└────────────────┘      └────────────────┘         └───────┬────────┘
                                                           │
                                            ┌──────────────┴────────┐
                                            │ block_ip / kill_proc  │
                                            │ quarantine / webhook  │
                                            │ approval_gate / chain │
                                            └───────────────────────┘

### Tech Stack

- **Core Engine**: Go 1.22+ (High-concurrency detection, SOAR logic, REST API)
- **Performance Layer**: Rust 1.75+ (High-speed pattern matching, DPI, packet capture)
- **Messaging**: NATS JetStream (Embedded, zero-latency internal event bus)
- **AI Layer**: Google Gemini (Flash/Lite) for cross-module threat correlation
- **Frontend**: Next.js 14 / TailwindCSS (Cloud Dashboard & Landing Page)
- **Storage**: LevelDB / Local FS (Fully standalone, no external DB required)
```

Each module implements a single Go interface:

```go
type Module interface {
    Name() string
    Description() string
    Start(ctx context.Context, bus *EventBus, pipeline *AlertPipeline, cfg *Config) error
    Stop() error
    HandleEvent(event *SecurityEvent) error
    EventTypes() []string  // filtered routing — return nil for all events
}
```

Adding a module = adding one import. No registration boilerplate.

---

## REST API

The engine exposes a REST API on port 1780. All endpoints except `/health`
require an API key when `server.api_keys` or `server.read_only_keys` are
configured. Without keys, read-only endpoints are served only on loopback binds
unless `server.allow_unauthenticated_read` is set.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/status` | Engine status, module list, alert count |
| GET | `/api/v1/modules` | All registered modules |
| GET | `/api/v1/alerts` | Recent alerts (`?limit=N&min_severity=HIGH`) |
| GET | `/api/v1/alerts/{id}` | Single alert by ID |
| GET | `/api/v1/config` | Current resolved config |
| GET | `/api/v1/logs` | In-memory log buffer |
| GET | `/api/v1/correlator` | Threat correlator state, attack chains, active sources |
| GET | `/api/v1/threats` | Dynamic IP threat scores, block status |
| GET | `/api/v1/rust` | Rust sidecar engine status and config |
| GET | `/api/v1/metrics` | Engine metrics (events, alerts, uptime) |
| GET | `/api/v1/event-schemas` | Supported event type schemas |
| GET | `/api/v1/archive/status` | Alert archiver status |
| GET | `/api/v1/enforce/status` | Enforcement engine status and statistics |
| GET | `/api/v1/enforce/policies` | All configured response policies |
| GET | `/api/v1/enforce/history` | Response action execution history |
| GET | `/api/v1/enforce/approvals/pending` | List actions awaiting human approval |
| GET | `/api/v1/enforce/approvals/history` | Approval decision history |
| GET | `/api/v1/enforce/approvals/stats` | Approval gate statistics |
| GET | `/api/v1/enforce/webhooks/stats` | Webhook dispatcher statistics |
| GET | `/api/v1/enforce/webhooks/dead-letters` | Failed webhook deliveries |
| POST | `/api/v1/events` | Ingest an external SecurityEvent |
| POST | `/api/v1/shutdown` | Graceful shutdown |
| POST | `/api/v1/config/reload` | Hot-reload configuration |
| DELETE | `/api/v1/alerts/clear` | Clear all alerts |
| POST | `/api/v1/enforce/policies/{module}` | Enable/disable enforcement per module |
| POST | `/api/v1/enforce/dry-run/{on\|off}` | Toggle global dry-run mode |
| POST | `/api/v1/enforce/test/{module}` | Simulate alert to preview enforcement |
| POST | `/api/v1/enforce/approve/{id}` | Approve a pending enforcement action |
| POST | `/api/v1/enforce/reject/{id}` | Reject a pending enforcement action |
| POST | `/api/v1/enforce/rollback/{id}` | Rollback an executed enforcement action |
| POST | `/api/v1/enforce/webhooks/retry/{id}` | Retry a failed webhook delivery |

Secure the API by setting `ONESEC_API_KEY` or `server.api_keys` in config. Read-only keys are blocked from mutating endpoints (enforce approve/reject/rollback, shutdown, etc.).

---

## Cloud Dashboard & AI (Pro/Enterprise)

The open-source engine is complete and fully functional standalone. Pro and Enterprise add:

- **Cloud dashboard** — real-time threat visualization, analytics, module health
- **Managed AI** — no Gemini key to configure; quota included (50K/500K triage events, 5K/50K deep analysis per month)
- **Webhooks** — Slack, Discord, PagerDuty, or any HTTP endpoint
- **Key rotation** — rotate API keys from the dashboard with usage history preserved

Community users can bring their own Gemini key (`GEMINI_API_KEY`) for AI features at no charge from us.

See [1-sec.dev/pricing](https://1-sec.dev/pricing) for details.

---

## Project Structure

```
1sec/
├── cmd/1sec/
│   ├── main.go               # CLI entry point
│   ├── cmd_up.go             # 1sec up — start engine
│   ├── cmd_enforce.go        # 1sec enforce — SOAR response management
│   ├── cmd_alerts.go         # 1sec alerts — query alerts
│   ├── cmd_archive.go        # 1sec archive — alert storage management
│   ├── cmd_collect.go        # 1sec collect — manage log collectors
│   ├── cmd_dashboard.go      # 1sec dashboard — terminal UI dashboard
│   ├── cmd_scan.go           # 1sec scan — submit payloads
│   ├── cmd_docker.go         # 1sec docker — compose shortcuts
│   ├── cmd_correlator.go     # 1sec correlator — threat chain state
│   ├── cmd_threats.go        # 1sec threats — IP threat scoring
│   ├── cmd_rust.go           # 1sec rust — Rust sidecar status
│   ├── cmd_setup.go          # 1sec setup — guided interactive wizard
│   ├── cmd_doctor.go         # 1sec doctor — health check with fix suggestions
│   ├── cmd_export.go         # 1sec export — export data/config
│   ├── cmd_profile.go        # 1sec profile — pprof performance analysis
│   └── selfupdate.go         # In-place binary self-update
├── internal/
│   ├── core/
│   │   ├── engine.go         # Central engine — orchestration & lifecycle
│   │   ├── bus.go            # NATS JetStream event bus management
│   │   ├── correlator.go     # Multi-module attack chain correlation
│   │   ├── response.go       # SOAR enforcement & action execution
│   │   ├── rustsidecar.go    # Rust pattern-matching sidecar lifecycle
│   │   ├── archiver.go       # Local alert persistence & archival
│   │   └── approval_gate.go  # Human-in-the-loop decision logic
│   ├── modules/              # 16 defense modules (one package each)
│   ├── collect/              # Log collectors (Auth, Nginx, Syslog, etc.)
│   ├── ingest/               # Ingest protocols (Syslog RFC5424/3164)
│   └── api/
│       ├── server.go         # REST API server & middleware
│       └── handlers.go       # API endpoint implementations
├── rust/
│   └── 1sec-engine/          # High-performance Rust pattern engine
├── web/                      # Next.js dashboard + marketing site
├── configs/                  # Default and example configurations
├── deploy/                   # Docker, Helm, and systemd deployment
└── scripts/                  # Helper scripts and installation tools
```

---

## License

1-SEC is dual-licensed:

- **Open Source** — [AGPLv3](LICENSE) for community use. The core engine and all 16 modules are free to use, modify, and self-host under the terms of the GNU Affero General Public License v3.
- **Commercial License** — available for organizations that need to use 1-SEC without AGPLv3 obligations (e.g., embedding in proprietary products, reselling, or offering as a managed service without source disclosure). Contact [support@driftrail.com](mailto:support@driftrail.com) for details.

You may not rebrand, resell, or offer 1-SEC as a competing commercial product or managed service without a commercial license.

## Contributing

1-SEC does not accept external pull requests at this time. This is to maintain licensing clarity under our dual-license model. Bug reports and feature requests via [Issues](https://github.com/simpleending/1-sec/issues) are welcome and encouraged. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.
