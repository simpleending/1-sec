# Dashboard access and local operations

The dashboard audit led to coordinated engine and website changes. The CLI remains independent of cloud services. An optional local web dashboard uses the existing engine API, while cloud reporting and remote control have separate configuration and credentials.

## Audit dispositions

| Issue | Implementation and regression coverage |
| --- | --- |
| Billing portal accepted an email without authentication | Owner authentication binds the portal to the stored Stripe customer. Member and machine keys cannot manage billing. |
| Team responses disclosed full sibling keys and members could acknowledge commands | Rosters expose opaque member IDs and key prefixes. Command acknowledgements require an enrolled command-enabled machine credential. Team and webhook management remain owner operations. |
| Rotation discarded roles and detached account data | Conditional account and principal records preserve roles, team membership, shared quota and a fixed storage namespace. Only owner rotation updates subscription ownership. Existing invites resolve the current owner through the account. |
| Repeated fulfillment and subscription cancellation left usable credentials | Conditional provisioning selects one canonical owner per subscription. Operational key validation and quota paths enforce the account entitlement. An inactive subscription's owner can still authenticate specifically to recover billing. Webhooks reconcile current Stripe state and known prices; an older event cannot overwrite a newer entitlement decision. |
| Purchase return page and session endpoint disagreed about authentication | Checkout sets a session-specific, HttpOnly browser claim. The return endpoint checks its hash, payment state and the initially provisioned credential. It reports pending provisioning and cannot reveal a replacement key after rotation. |
| Connection instructions configured AI without monitoring | The dashboard generates a separate instance key and a complete cloud reporting configuration. AI analysis is an additional option. Owners can list and revoke enrolled instances. |
| Commands had no machine target or exclusive execution claim | Issuing commands requires an online enrolled target. Pending polling and acknowledgement bind to that instance. Conditional writes enforce pending to acknowledged to terminal transitions and a private claim proof. The UI sends the actual approval ID. |
| Cloud reporting implicitly enabled command polling | The engine defaults `remote_commands_enabled` to false. Polling additionally requires a configured instance ID. Wrong-instance, expired, unscoped and unsuccessfully claimed commands never execute. |
| Fixed history and instance caps silently discarded data | Cloud history uses separate retained records and bounded cursor pages. Existing arrays remain readable. Owners can configure 1–365 days of retention, defaulting to 30. Dashboard filters, statistics and exports explicitly describe loaded records. |

Additional verified behavior: approval-setting changes update the live gate, not just the configuration shown by dashboards. Validation rejects the entire invalid settings change before changing runtime state. Cloud heartbeat policy state describes enforcement policies separately from detection-module enablement.

## Local web dashboard

Start the engine normally, then run:

```sh
1sec dashboard --web
```

The command prints the engine's `/ui/` URL. It does not launch a browser or place a credential in the URL. Enter a local engine API key in the page; cloud subscription keys are separate. A read-only key supports inspection. A write key permits supported enforcement, approval and configuration-reload operations through the existing protected API.

The local interface includes status, alerts, modules, enforcement policies and history, approvals, correlations, collectors/metrics, Rust status, archive/escalation status, webhooks, token-vault status, redacted configuration and logs. It keeps the entered key in page memory and clears displayed data on disconnect. Static assets contain no engine data. A same-origin content policy restricts scripts and API requests; serving the shell does not bypass API authentication.

## Upgrade and compatibility

- Install v0.4.26 or newer for the local web dashboard and enrolled-instance command protocol. The coordinated website deployment requires this version for its generated configuration; older versions do not recognize the new cloud fields.
- Save the owner key securely. Use the dashboard to generate a separate credential and unique `instance_id` for each machine. Copy the generated cloud settings into the existing configuration and restart the engine.
- Remote commands require both the enrolled credential's permission and `cloud.remote_commands_enabled: true`. Existing owner credentials can continue reporting telemetry, but must enroll a device to poll or acknowledge commands. Older engines do not implement the new instance claim protocol.
- Owner rotation keeps enrolled machine credentials and team members attached to the same subscription. Revoking an individual instance is separate from rotating the owner key.
- Existing seeded administrative keys remain supported without a live Stripe request on each API call. Subscription owners and team members share the account quota.
- Initial purchase-key recovery is limited to the checkout browser and the one-hour claim window. There is no promise of email delivery. A revoked or rotated initial credential is never returned as a current key.

## Operational limits

The local GUI exposes current API snapshots; durable archive queries and complete configuration authoring remain CLI operations. Runtime enforcement and approval changes do not automatically persist to the configuration file. Cloud history is separate from the engine's local archive and does not establish lossless telemetry delivery. Existing producer buffering, upload intervals and deployment availability still matter.

Cloud retention is enforced during reads with lazy deletion of expired individual records and conditional pruning of expired legacy-array entries; it is not a scheduled storage-erasure guarantee. Raising retention cannot recover pruned records or data already removed by the previous fixed caps. Blob listing and legacy migration still incur account-size-dependent metadata work.

An acknowledged command without a terminal result has an uncertain execution outcome. It is not automatically reclaimed or retried, avoiding duplicate side effects after a lost response or process crash. Review local state before issuing a replacement.

## Verification

Focused regressions cover billing authorization, rotation and revocation, duplicate fulfillment, cancellation and recovery, checkout claims, one-use concurrent invites, instance isolation and exclusive command claims, shared quotas, legacy keys, retention and pagination past each previous cap. Engine regressions cover opt-in, instance and expiry checks, claim failure, pagination, local GUI authentication and live approval decisions.

Verified locally on Windows:

- `go test -p 1 -race -timeout 120s ./cmd/... ./internal/...`: all tracked engine packages pass, including local GUI state regressions. Low parallelism avoids host resource exhaustion; nested website dependency directories are excluded.
- `go build -p 1 -o bin/1sec-dashboard-check.exe ./cmd/1sec`, `go vet -p 1 ./cmd/... ./internal/...`, and `govulncheck ./cmd/... ./internal/...`: pass. The reachability scan finds no affected calls or imported packages; one previously known advisory exists only in a required, uncalled dependency.
- `cargo fmt -- --check`, `cargo clippy --locked --all-features --all-targets -- -D warnings`, and the portable Rust build pass. `cargo test --locked --no-default-features --features pqc` passes 197 unit tests plus the owned-TCP runtime compatibility regression. Packet-capture linking on this Windows host requires unavailable `wpcap.lib`; Linux CI runs the all-feature build and tests.
- `cargo audit` and the Go/Rust OSV lockfile scan pass with the same five documented optional-PQC/paste maintenance exceptions. No exception is added.
- Website TypeScript validation, 22 dashboard regressions and 11 SEO regressions pass. A clean lockfile install and `npm audit` report zero vulnerabilities. The deployment build and final production checks are recorded with the website update.

No production purchase, customer credential or live enforcement action is used by these tests. The dashboard tests exercise the actual route handlers with conditional-storage and payment-provider test doubles; live Stripe and Netlify lifecycle behavior still depends on correctly configured production services.

## Dependency maintenance

The dependency gate identified Tokio's AsyncFd constructor soundness advisory, RUSTSEC-2026-0386. The sidecar now pins the supported patched 1.51 LTS line with `~1.51.6`. No enabled source path using AsyncFd was found; this removes the vulnerable dependency version without claiming a demonstrated remotely exploitable engine path. The runtime regression checks owned TCP I/O and notification behavior after the update.

The website moves from Next.js 16.2.10 to security-patched 16.4.1, updates Sharp to 0.35.5, and refreshes vulnerable compatible transitive dependencies. React and Stripe remain on their existing versions. Netlify uses Node 24, replacing the end-of-life Node 20 build pin.

## Implementation references

- [Next.js 16.4.1 security release](https://github.com/vercel/next.js/releases/tag/v16.4.1)
- [Netlify Blobs consistency and conditional writes](https://docs.netlify.com/build/data-and-storage/netlify-blobs/)
- [Stripe Checkout fulfillment](https://docs.stripe.com/checkout/fulfillment)
- [Go HTTP API](https://pkg.go.dev/net/http)
- [Tokio soundness advisory](https://rustsec.org/advisories/RUSTSEC-2026-0386.html)
- [Netlify build dependencies](https://docs.netlify.com/build/configure-builds/manage-dependencies/)
