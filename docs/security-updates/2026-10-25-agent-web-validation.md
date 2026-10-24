# Agent web and payment telemetry validation

This change adds source fixtures for existing behavior used by the briefs 1201–1500 documentation review. It adds no new runtime protection, payment integration, browser collector or release binary. The installed v0.4.26 behavior remains the implementation under review.

## Tested dispositions

| Path | Disposition and evidence |
| --- | --- |
| Markdown ingestion | Existing checks validated through `HandleEvent`: ordinary documentation, instruction spoofing, hidden comments, zero-width characters and an inert image exfiltration link. `TestContainment_MarkdownSignalsAndBenignControl` links the source scanner to actual emitted alert types. It is not a sanitizer or browser/network integration. |
| Web destination signals | Existing checks validated with public, loopback and metadata URL strings. A metadata address appearing in an ordinary documentation query also matches, demonstrating string inspection rather than resolution. `TestContainment_WebFetchSensitiveDestinations` performs no network request. |
| Payment metadata | `TestContainment_PaymentMetadataSignals` validates reported over-limit, missing-principal and recipient-substring findings, plus an ordinary metadata control. No payment is made. |
| Payment policy limits | `TestAgentPaymentMonitor_WindowAndPolicyLimits` establishes per-event amount comparison, presence-only principal text, mixed-currency accumulation and window-reset recipient history. It does not establish wallet spending enforcement, verified approval, fraud attribution, retry classification or settlement verification. Those broader briefs remain deferred. |
| Web content hashes | `TestGuard_WebContentDomainBaselineAndMutation` checks first-seen, unchanged and changed supplied hashes through the real handler, including two URLs sharing one domain baseline and rapid changes. `TestWebContentTracker_WindowResetAndDomainIsolation` checks separate domains and an expired change window. No content is fetched or authenticated by these tests. |

## Important limits retained

- A new-domain baseline is not verified domain trust. The hash tracker keys state by domain, not URL, and accepts producer-supplied hashes and lengths.
- The web-fetch monitor does not resolve DNS or validate redirect chains. Its alert descriptions saying a fetch is blocked do not intercept a transport.
- Payment metadata is advisory. A nonempty `delegated_by` string in the payment handler is not a verified delegation, and a supplied per-event limit is not a protected wallet policy. Raw floating-point totals do not normalize currencies or prove settlement.
- Service-account anomaly helper fixtures seed old baseline state; they do not establish natural baseline maturation under sustained traffic with hourly count-window resets.
- Source policy, operator verification, provider consent, credential storage, tenant authorization, browser capture and document authenticity remain separate integration boundaries. The website must describe implemented subsets and explicitly defer unsupported claims.

## Verification

The selected containment, data-poisoning, identity, authentication, Token Vault, API and core suites pass. Engine build, vet and vulnerability reachability checks pass; no reachable or imported-package vulnerability is found. The Go/Rust lockfile inventory gate and Rust audit pass with the same five documented optional-PQC/paste maintenance exceptions. No dependency or exception changes are made.

The full tracked-engine race suite (`go test -p 1 -race -timeout 120s ./cmd/... ./internal/...`) also passes. Remote CI results are recorded after completion. No live provider login, wallet operation, browser automation, malicious payload execution or customer credential is used.

Primary integration references: [OAuth security best practice](https://www.rfc-editor.org/rfc/rfc9700.html), [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [x402 protocol project](https://x402.org/), and [llms.txt proposal](https://llmstxt.org/). These describe external boundaries; they do not expand the engine's implemented coverage.
