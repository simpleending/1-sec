# Individual sensor identity and credential revocation

This source follow-up to `90f4cee` implements the HTTP producer portion of the enterprise identity roadmap. It is not a new downloadable release. Named operator roles, durable collectors, immutable audit retention and measured fleet capacity remain separate work.

## What the boundary now enforces

- An operator enrolls an explicit sensor ID, reporting host and 1–64 exact `(module, type)` scopes. Empty scopes, wildcards, duplicate IDs and a remote host requesting local response are rejected. A default grant lasts 90 days; explicit expiry must be within one year. A revoked ID cannot be reenrolled or reactivated.
- Each sensor receives a unique 256-bit random bearer secret once. The registry stores only its SHA-256 hash, credential ID, scope and lifecycle metadata. A separate private signing key authenticates event provenance; neither raw sensor secrets nor that key appear in list/config/log responses. Enrollment and rotation responses use `Cache-Control: no-store`.
- A sensor credential permits only `POST /api/v1/events`, with a 64 KiB limit and exactly one JSON event. It cannot read engine data, enroll sensors, change policy, approve actions, exchange tokens or shut down the engine. This restriction also applies when no operator keys are configured.
- The engine creates the ingress ID and source, binds host fields to the enrollment, rejects conflicting host claims/reserved identity fields and checks the exact event scope. Supplied event IDs and source strings do not establish identity. A host is an operator-assigned name, not an independently attested device identity.
- The complete canonical event and sensor grant are authenticated across broker delivery. Tampered or inactive signed events do not reach Go detectors. Detector-derived events retain provenance. Rust forwards the exact original JSON, preserving numeric PID representations; Go verifies it and derives response context from the signed event rather than result context strings.
- Rotation replaces the credential generation immediately; old tokens and old queued containment grants cease to qualify. Revocation is idempotent and persisted before success is returned. Other sensors continue working. Expiry, rotation, revocation and failed state storage are rechecked for normal responses, approval execution, each chain retry and built-in containment executors.
- Sensor grants default to observation only. `allow_local_response: true` is an additional operator grant accepted only for this engine's host; the existing actor-PID, host/namespace, policy, approval, allowlist and OS-permission checks still apply. Remote sensors do not authorize killing processes, changing files/accounts or running commands on the central engine. There is no remote executor protocol in this change.
- Statistical aggregate alerts are observational and preserve that status through subsequent detector events. They cannot promote a mixed collection of observations into one sensor's local containment grant. Investigative logging and webhook notifications remain available after revocation; revocation does not erase evidence.

## Enable and enroll

Configure an engine write key first. Start with a private listener, TLS, dry-run and grants that omit local response. Enable identity and choose a persistent directory owned by the engine service account:

```yaml
sensors:
  enabled: true
  state_dir: /var/lib/1sec/sensor-identity
  require_sensor_ingest: true
```

When `state_dir` is omitted, it is `bus.data_dir/sensor-identity`, within the existing persisted broker directory. A custom directory must be mounted persistently and writable by the engine. Restart to activate configuration changes.

With Bash variables pointing to your HTTPS engine and protected operator credential:

```bash
curl --fail-with-body -sS -X POST "$ENGINE_URL/api/v1/sensors" \
  -H "Authorization: Bearer $ONESEC_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"id":"payments-01","host_id":"payments-01.example.internal","scopes":[{"module":"endpoint","type":"auth_failure"},{"module":"endpoint","type":"http_request"}]}'
```

Save the returned `token` in that sensor's secret store; it is not retrievable later. Set its client to send `Authorization: Bearer <sensor token>` to the same engine's `/api/v1/events`. Use exactly an enrolled `module`/`type`, and either omit host fields or use the enrolled host string. Use `/api/v1/event-schemas` with a monitoring/operator key when preparing the adapter; sensors do not receive that key.

Sensor requests require TLS, except connections from loopback for local clients or a local TLS-terminating proxy. `X-Forwarded-Proto` does not bypass this check. Clients must verify TLS certificates. Bind the backend to loopback when terminating TLS in a proxy. The engine does not configure the proxy or authenticate a remote syslog sender.

The existing operator credential manages lifecycle:

| Method/path | Result |
| --- | --- |
| `GET /api/v1/sensors` | Detached inventory without token hashes/signing keys; existing monitoring/operator authentication applies. |
| `POST /api/v1/sensors` | Enroll a new identity; return its one-time token. |
| `POST /api/v1/sensors/{id}/rotate` | Return a new token for an active, unexpired sensor; invalidate its old generation, including queued containment. |
| `POST /api/v1/sensors/{id}/revoke` | Persist revocation; a repeated revoke succeeds without reactivation. |

Rotation retains the original grant and expiry. Expired or revoked identities need a deliberately new enrollment ID. This avoids accidentally reviving a compromised identity. Clients should treat 403 as a stopped/invalid grant and require operator remediation, rather than retry indefinitely.

## Persistence and operational limits

The private append-only `registry.jsonl` is synced before state changes become authoritative in memory. An OS file lock prevents two engine owners using the same journal. It includes the signing key and token hashes, so treat it as sensitive recovery state. A torn/corrupt journal refuses startup; failed writes or capacity checks fail closed and degrade `/health`. `/live` remains independent. A rejected mutation is not a successful durable revocation: resolve storage failure and retry it.

Limits are 10,000 identities, 64 scopes per identity and a journal smaller than 64 MiB. Mutation checks the byte limit before writing, so successful operations cannot create a journal startup refuses for size. Rotation grows the journal. Monitor its size and preserve complete current state during backup/recovery; automatic compaction and multi-engine replication are not implemented. Restoring an older backup can roll back revocations. No tamper-proof, hardware/power-loss or remote-filesystem durability guarantee is made.

`require_sensor_ingest` is opt-in for migration compatibility. When false, trusted operator keys retain legacy HTTP ingestion, but cannot label it as enrolled sensor provenance. Local built-in collectors and the internal broker remain privileged integrations: do not distribute their shared NATS token, filesystem access or operator keys to sensors. Sensor tokens fail broker authentication. Protect external NATS with separate authentication, authorization, TLS and network admission; this change does not provision NATS accounts or per-subject users.

The credential authenticates possession of an enrolled secret, not the truth of telemetry. A compromised sensor can fabricate observations within its granted host/types, and a local-response grant remains powerful. Named operators, hardware/mTLS device attestation, tenant isolation and remote host execution are not supplied here. Revocation does not undo completed actions, cancel an action already executing, clear accumulated detector history or provide permanent replay rejection. Existing event deduplication and retention bounds still apply.

## Verification and dispositions

Implemented: individual sensor admission, host/event scope, isolated management authority, default observational grants, expiry, rotation/revocation persistence, fail-closed journal ownership/capacity, signed broker/Go/Rust provenance and queued containment checks. Existing trusted operator/local-collector behavior remains supported when strict HTTP admission is disabled.

Regressions cover sensor A versus B host/module/type and forged identity claims; token separation from operator and broker access; TLS versus spoofed forwarding headers; tampered payloads; concurrency; restart and independent revocation; expiry/rotation; queued normal/approval/chain/direct actions; storage failure/capacity and torn journals; real detector attribution; Token Vault adapter propagation; and the real Rust child with string, exponent and trailing-zero PID representations. The Token Vault bypass and Rust numeric-PID regression were reproduced before correction and pass afterward. Tests use mocks/dry-run/test children, not customer containment operations.

Required validation includes the full Go race suite, build/vet/static analysis, package/symbol govulncheck, raw Go/Rust OSV, Rust formatting/all-feature Clippy/audit and portable tests. Windows still lacks Npcap `wpcap.lib`; Linux CI verifies full-feature linking/tests and the real sidecar recovery/provenance test. See the commit's CI outcome before deploying.

Primary API references consulted: installed Go 1.26.10 `crypto/rand`, `crypto/hmac`, `crypto/sha256`, `net/http` and `os` documentation; installed `golang.org/x/sys` locking APIs; [NATS authorization](https://docs.nats.io/learn/security/authorization). No dependency version upgrade was needed.
