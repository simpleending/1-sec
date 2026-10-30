# October 30: runtime process evidence reaches containment

This follow-up addresses the runtime-target finding deferred in the earlier [incident review](2026-10-30-incident-review.md). It changes source behavior; it is not included in the downloadable v0.4.29 binaries and does not announce a new binary release.

## Corrected boundary

Runtime process and fileless detections now retain the observed actor's normalized PID, descriptive name, reporting-host context and original event ID. Injection detections use an explicit `source_pid`; `target_pid` identifies the injection victim and never becomes a kill target. All file findings retain `affected_path` for investigation.

The shared response boundary authorizes runtime process termination only for a recognized process detection with an exact PID and local reporting-host context. Normal policies, approvals and action chains use the same check; built-in executors check it again before side effects. Missing/invalid/conflicting IDs, name-only observations, unknown or remote hosts and container/namespace identifiers do not authorize a local kill. The normal response audit records an explicit skipped disposition. Process responses resolve cooldown/audit targets by PID rather than a shared client/source IP.

Runtime file-integrity, sensitive-file, persistence, firmware and container observations do not establish a malicious artifact or a uniquely identified local actor. They remain observable; runtime quarantine is refused, including forged `file_path` metadata. Strict/balanced/VPS-agent presets preserve affected files and remove their former runtime quarantine rules. This is deliberate file safety, not a missing-target execution failure. Content-verified, identity-bound artifact quarantine would require a separate capability; filename/path heuristics cannot establish it.

## Telemetry contract

- Process execution/start and fileless events accept `process_id` or `pid`; supplied aliases must agree. PIDs must be positive integral values in the supported 31-bit range; runtime termination excludes PID 1. Native integer/integral float values and exact JSON forms such as `4242`, `4242.0` and `4.242e3` normalize to the same PID.
- Process identifier JSON tokens are retained exactly across HTTP/broker decoding. A value such as `4242.00000000000000001` cannot round into PID 4242. Exact decimal parsing bounds input length/exponent before arithmetic. Other numeric telemetry keeps its previous float64 representation. Ransomware's PID consumer accepts the retained exact-number representation too.
- Host context comes from `process_host`, `hostname`, `syslog_hostname` or `host_id`. Every supplied identity must identify the executor's local hostname or a local/loopback interface address. Opaque/unmapped host IDs fail closed. These are assertions from already trusted telemetry producers, not authentication. `SourceIP` can identify a client or relay and is not inferred as process-host identity.
- Nonempty `container_id` or `pid_namespace` requires a namespace-aware executor; no container PID translation is implemented. Route remote evidence to the appropriate local executor.
- The integration schema exposes these optional fields. Neither PID/host metadata nor a detector match overrides dry-run, severity, allowlists, rate limits, cooldowns or approval policy. Safe/lax presets retain their existing observation-only runtime behavior.

Approval notifications now use a snapshot of the submitted pending record. The new response-path regression exposed a race between notification reads and execution updating the target; the snapshot preserves the submitted target/status while execution proceeds.

## Regression and compatibility evidence

The original exact-PID response and file-context reproductions failed before the change. After correction:

- `TestRuntimeDetectionReachesExactProcessResponse` and `TestRuntimeJSONPIDEligibility` exercise the actual runtime detector, pipeline and strict-preset response; eligible process actions retain PID 4242 in dry-run. Fractional, malformed, conflicting, remote and missing evidence remains alertable and is skipped for termination.
- `TestRuntimeInjectionSelectsSourceNotVictim` keeps the injected victim separate from an explicit actor.
- `TestRuntimeFileFindingsRetainContextWithoutDestructiveAuthority` covers external file events and both native file-monitor branches.
- `TestRuntimeContainmentBoundaryAcrossResponsePaths` uses harmless executors across normal, approved and chained actions. Eligible actors execute; forged victim/configuration targets do not.
- `TestRuntimeExecutorsRejectUnsafeTargetsBeforeSideEffects` verifies direct-executor rejection; an eligible PID reaches a canceled command boundary without sending a signal. A descriptive process name cannot invalidate an otherwise valid PID.
- `TestRuntimeCooldownSeparatesProcessesOnSameSourceIP`, `TestProcessIdentifiersSurviveJSONWithoutRounding` and `TestJSONProcessIDKeepsExactRansomwareAttribution` retain process isolation and legitimate numeric representations.
- `TestApprovalNotificationKeepsSubmittedSnapshot` and the full race suite cover approval notification consistency.

An independent prepatch investigation and one independent candidate review were completed. The review found the initially rejected integral JSON forms; exact parsing and raw-JSON regressions corrected that issue before final verification.

## Checks and limits

Full Go product race tests, build, vet and govulncheck pass. No reachable Go advisory was found. Cargo Audit reports no findings; Rust source/dependencies are unchanged. Raw Go/Rust OSV continues to report the same required-only OpenPGP maintenance record and the previously documented block-buffer range false positive; no ignore or dependency update was added. The prior source commit's hosted Linux Go tests and full-feature Rust job passed; its Go job failed at that OSV gate. This follow-up's hosted status is tracked separately in the local report manifest.

No arbitrary process was killed and no victim file was moved during verification. Host/PID fields rely on trusted collectors and must use the executor's PID namespace. Existing OS executors do not bind PIDs to kernel process handles or start times, so PID reuse and delayed actions remain operational limits. This patch fixes evidence loss and unsafe target promotion; it does not provide synchronous execution admission, container translation, malicious-artifact verification or remote process control.
