# October 23, 2026: detection and response reliability

These source changes improve the existing modules without new runtime dependencies. They are not included in the published v0.4.24 binaries. Rebuild the Go engine to use them. This is a code-quality follow-up, not another vulnerability feed collection or an expanded reporting window.

## Media screening

- Audio events accept validated RIFF/WAVE containing mono, 16-bit little-endian PCM at 16 kHz, or raw PCM with `audio_format: pcm_s16le`, `sample_rate: 16000`, and `channels: 1`. WAVE lengths, sample alignment, format fields, and chunk counts are checked before analysis. Compressed audio and other sample rates need upstream decoding/resampling.
- Audio feature extraction is limited to the first 32,000 PCM bytes (one second). Results report analyzed bytes and truncation. Silence is not synthetic-speaker evidence; content beyond the prefix is not screened.
- Video events accept JPEG/PNG image frames in `raw_data` or `details.frames` (byte slices or JSON base64 strings). They decode at most eight frames, each at most 8 MiB and 1920x1080, and sample 64x64 grayscale pixels. MP4 and other video containers require upstream frame extraction. Static frame sequences are not treated as deepfake evidence.
- Unsupported audio/video inputs produce informational `audio_analysis_unavailable` or `video_analysis_unavailable` alerts. They are not clean authenticity results. Existing `deepfake_audio`/`deepfake_video` alert types remain, but statistical findings are MEDIUM and explicitly describe uncalibrated anomalies. Byte-block entropy is no longer described as JPEG error level analysis.

These are screening features, not a trained or validated deepfake classifier. Noise, tones, compression, editing, and ordinary media can resemble synthetic artifacts. No real-speaker or generated-media accuracy claim is established by the regression fixtures.

## Ransomware detection and response

- File activity is grouped by reporting host (`host_id`, then source IP, then collector source) and PID when supplied, otherwise process name. `process_start_time` separates reused PIDs when available. Missing process/path attribution does not accumulate into a shared anonymous process.
- Each distinct file has one current entropy sample. Duplicate writes cannot dominate the average or rename count. Invalid entropy values are ignored. A fixed five-minute window expires even under continuous activity; events crossing its boundary can be split across windows.
- Actual `file_renamed` events count regardless of extension. Single-file high entropy is MEDIUM. A batch with high average entropy is HIGH; it becomes CRITICAL only when at least the configured threshold of distinct files have reported `entropy_before` to `entropy` increases of at least one bit per byte. Authorized compression/encryption can still produce these patterns.
- Missing or malformed disk offsets no longer become an asserted MBR write. Generic disk writes require raw-device context and explicit boot-sector or zero/random-fill evidence. Explicit `mbr_write`, `partition_write`, and `wiper_activity` telemetry remains supported. Legitimate disk maintenance can resemble these events.
- Ransomware alerts preserve original event IDs, validated numeric/string `process_id` (or `pid`), process name, file path, and reporting host. The ordinary enforcement pipeline controls actions, dry-run mode, approvals, cooldowns, and allowlists. Removed standalone `response_action` publications had no response-engine consumer and did not establish successful intervention.
- Local process termination and quarantine reject an explicitly nonlocal reporting host. Supply `hostname` matching the executor's kernel hostname, or a reporting source IP assigned to the executor. Opaque `host_id` values need a matching `hostname` for local execution. Remote sensor PIDs must go to an executor on that host. This check is not authentication: collectors, ingestion credentials, and attribution must be trusted. Existing alerts without host metadata retain their prior behavior.

The regression suite exercises detection through the response policy against the exact PID in dry-run mode. It does not execute malware or claim to prevent every file write before damage. Built-in telemetry does not universally provide process attribution or before/after entropy; integrations must supply that evidence. Aggressive custom policies can still act on lower-severity heuristic alerts. Backups and tested recovery remain necessary.

## Post-quantum assessment

- Capture-risk correlation requires an explicit passive capture type (`mirror`, `tap`, `pcap`, or `span`) and more than 100 MiB of captured observations using recognized classical key establishment in the same 24-hour source window. Ordinary bulk transfer alone is insufficient. Negative/zero counters and anonymous sources do not accumulate.
- Negotiated hybrid groups are not overridden by a cipher-suite name containing RSA/ECDHE. When key-exchange telemetry is absent, legacy suites can supply classical evidence; a TLS 1.3 AEAD cipher alone cannot. Offered groups describe capabilities, not the negotiated exchange. Group recognition uses complete names rather than substrings.
- Crypto inventory distinguishes `recognized_pqc`, `symmetric`, `classical`, and `unknown`. Unrecognized names, historical candidate names, and unverified revisions are not labeled quantum safe. Recognized algorithm names do not certify implementation, parameters, or appropriate use. TLS AEAD suite names do not establish connection-level quantum resistance.
- AES-128 is no longer called broken solely because of a theoretical Grover speedup, consistent with NIST guidance. Capture alerts are investigation signals and cannot establish adversary intent, authorization, or future decryption.

This module does not retrofit PQ encryption into other applications. Optional Rust PQ primitives and Go's TLS implementation are separate from telemetry-based migration assessment. The existing five optional Rust PQC/paste maintenance exceptions remain; no new dependency exception was added.

## Verification

Initial regression cases reproduced failures against the previous behavior before implementation. Additional coverage includes malformed WAVE containers, decoded JSON frames, silence/static controls, isolated processes and hosts, distinct file evidence, expiring activity, valid response targets, remote-response rejection, classical versus hybrid capture, and unrecognized crypto names.

- Full Go race suite: pass (`go test -race -timeout 120s ./cmd/... ./internal/...`), followed by affected tests after the final raw-device filter. Go engine build and vet: pass.
- Repository-configured staticcheck and blog `npx tsc --noEmit`: pass. The existing October blog entry was updated after code verification, preserving unrelated website edits.
- WAVE parser fuzzing: pass, 166,297 executions in the five-second fuzz interval. This bounded run is not exhaustive parser verification.
- Go vulnerability reachability: zero reachable or imported-package vulnerabilities. One required-only finding remains in unused dependency code.
- Repository-wide OSV dependency gate: zero unexcepted findings. Cargo audit: no vulnerable dependencies reported, with the same five optional PQC/paste maintenance warnings. No exceptions were added or extended.
- Unchanged Rust sidecar: 197 tests pass with `--locked --no-default-features --features pqc`; portable build, formatting, and all-feature/all-target Clippy pass. Packet capture was not exercised; the existing Windows `wpcap.lib` limitation still applies.

## Primary references

- [Microsoft WAVEFORMATEX](https://learn.microsoft.com/en-us/windows/win32/api/mmeapi/ns-mmeapi-waveformatex) and [RIFF chunk layout](https://learn.microsoft.com/en-us/windows/win32/xaudio2/resource-interchange-file-format--riff-)
- [TLS 1.3 negotiation, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
- [NIST PQC FAQ, including symmetric cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs) and [HNDL explanation](https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography)
- [CISA StopRansomware guidance](https://www.cisa.gov/stopransomware/ransomware-guide)
