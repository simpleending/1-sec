# October 30, 2026: incident review and source fixes

Status: source fixes based on `9fdef70df64fee987c4ee347de3ee301422baab5`, submitted for commit and push on October 30. **Published v0.4.29 does not contain these fixes; no new binary release is claimed.** This was a prioritized source/dependency review, not a new weekly intelligence collection. The weekly script was not run and no collection window was expanded.

## Implemented

| Boundary | Change | Regression |
| --- | --- | --- |
| Configuration | Empty/missing YAML still applies environment overrides, including API authentication. | `TestConfigFallbackRetainsEnvironment`, `TestMissingConfigEnvironmentKeyProtectsReadAPI` through real middleware. |
| Process response | Escape process-name regexes, select exact matches and terminate option parsing; retain PID precedence. | `TestProcessNameCannotBroadenKillSelection`, `TestProcessKillPIDTakesPrecedence`; no signals sent. |
| Rust matching | Replace incomplete handwritten literal gating with `regex` 1.12.3 `RegexSet` over successfully compiled patterns; direct scan on set-build failure. Existing configuration switch remains accepted. | `accelerated_scan_preserves_regex_matches`, `candidate_indices_follow_compiled_patterns`. |
| Packet text | Preserve UTF-8 and inspectable text around binary bytes within the 2 KiB preview bound. | `mixed_utf8_request_remains_inspectable`, binary/text/size tests. |
| Router logs | Correct IPv6 protocol column and version-specific minimum lengths; retain UDP/non-port IPv6 records. | Three `TestPfSense*` regressions against the [Netgate format](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html). |
| Log following | Preserve partial records at EOF, detect replacement by identity, cap records at 1 MiB and recover at the next newline. Close the current file after rotation. | `TestTailPreservesPartialLine`, `TestTailRecoversAfterOversizedRecord`; POSIX `TestTailFollowsLargerReplacement`. |

Configuration, process selection, Rust filtering, UTF-8, IPv6 and partial-line regressions failed before correction. No destructive response command was executed.

## Dependencies

Go 1.26.10 reachability scanning reports zero reachable vulnerabilities and zero affected imported packages. Required `golang.org/x/crypto` 0.56.0 carries [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) for unimported `openpgp`, with no fixed release. Disposition: already covered by reachability evidence; keep the dependency for its actual consumers.

Cargo Audit reports zero vulnerabilities or maintenance warnings. OSV flags `GHSA-qwgh-2vcv-g2f7` against locked `block-buffer` 0.10.4. Disposition: rejected for this exact version. The [maintainer advisory](https://github.com/RustCrypto/utils/security/advisories/GHSA-qwgh-2vcv-g2f7) specifies `>=0.11.0,<0.12.1`; the aggregate database overstates it as `<0.12.1`. Installed 0.10.4 stores `pos: u8` separately from `buffer`, so filling data cannot overwrite an inline cursor; `ReadBuffer` is absent. The dependency enters through async-nats/nkeys/ed25519-dalek/sha2/digest. No new ignore was added: raw OSV remains nonzero for this false positive and the Go maintenance record. Do not describe the repository dependency gate as green.

The separate `web` lockfile has zero npm-audit findings. Several Go/Rust packages have newer releases; age alone is not evidence of exposure. No broad upgrade or lockfile churn was performed.

## Deferred and limited

- The initially deferred runtime target issue is addressed by the [runtime-containment follow-up](2026-10-30-runtime-containment.md): process-specific detections retain an exact actor PID and reporting-host context, and response paths enforce local evidence. File-only observations retain affected-path context and do not authorize quarantine. The follow-up remains outside downloadable v0.4.29 binaries.
- Optional capture remains passive, packet-local and cannot decrypt TLS. Binary previews now cause more packets to be published; load impact is unmeasured. Capture filters, privileges and retention require deployment tuning. No production attack replay or throughput guarantee is claimed.
- Tailing starts at EOF and loses oversized records. Fast copy-truncate/regrowth or multiple rotations between polls can still lose data. Windows prevents the POSIX rename test because the original file is open; that test is skipped locally.
- Exact name matching can select several processes with the same name and inherits OS process-name limits. Prefer verified local PID identity. Linux/macOS signal behavior was not exercised.
- Audit coverage is partial. Architecture mapping and search hits do not count as fully reviewed files. Docker API binding, placeholder `collect all`, and SECURITY.md's 1.x support table versus actual 0.4.x releases remain documented follow-ups.

## Verification and publication

Full product Go race suite, engine build, vet and govulncheck; Rust formatting, all-feature Clippy, 207 portable unit tests plus one integration test, portable release build and Cargo Audit. All-feature tests cannot link on this Windows host because `wpcap.lib` is missing. Clippy validates capture compilation, not live capture behavior. POSIX rotation awaits Linux/macOS execution. Website type/content/build checks and source/publication commit identifiers are recorded in the local manifest. No new binary release or mesh-router test is claimed.

The separate `web` checkout contains an incident article and an update to the existing October 26 article. Both distinguish source fixes from released protections. Source changes are committed and pushed before the blog; publication/deployment status is tracked separately in the local manifest. The original script analysis was rechecked before publication; Binance's technical cause remains unverified in this review.

## Incident and home-network assessment

Polymarket's [status service](https://status.polymarket.com/en-us), [AP reporting](https://apnews.com/article/cd33bc1f9bf623103e1aeef3897846b5) and [Hudson Rock's original script analysis](https://www.infostealers.com/article/polymarket-breach-alert-wallet-draining-code-found-in-a-third-party-script/) support discussion of third-party browser authority. Remove unnecessary scripts from authenticated trading/signing pages, isolate untrusted code from credentials/signers, and verify reviewed immutable assets with [SRI](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity) where feasible. [CSP host allowlisting](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src) alone cannot protect against malicious bytes from an allowed vendor. Transaction/signing policy must be enforced before the operation. Binance's cause remains unverified here; signing isolation, limits and independent approval are recommendations, not a diagnosis. No evidence establishes that installing 1SEC would have prevented either incident.

For a home mesh, 1SEC can be an extra sensor on a supported always-on host with actual gateway/endpoint logs or capture on a gateway/mirrored interface. Generic syslog forwarding does not automatically invoke the file-based pfSense CSV collector. Syslog requires trusted senders and network restrictions. Linux `block_ip` modifies local INPUT, not transit FORWARD/outbound traffic. Off-path sensors do not enforce router policy. Access-check verdicts need an enforcing trusted gateway. Router firmware/CPU compatibility remains unknown without the mesh model.
