# November 27 local-response decision isolation

Auth and Network now keep independent histories for local-response-eligible inputs and observations. A source without a live local-response grant still generates monitoring signals, but cannot contribute to or reset the eligible lane's counters, session/token history, network reputation, rate baselines, or protocol detector state. An explicit observation-only marker takes precedence even when a producer otherwise has a local-response grant. A revocation affects newly classified inputs; it does not erase historical measurements made while a source held a valid grant.

Trusted no-sensor events still use the existing local-response lane. A signed sensor's existing scope, identity, and live grant are checked separately at ingress/response; the lane distinction is not a new authorization grant or a per-tenant isolation boundary.

Observation notifications have their own per-module action quota and cooldown; they do not consume the eligible lane's budget. The thresholds are unchanged within each lane. The network threat list exposes eligible-lane reputation; observe-only findings are visible as alerts and do not imply an executable IP block.

This covers Auth, Network, and response accounting. It does not claim an all-module audit or that other inputs, producer-side labels, notification webhooks, and custom policies are safe by default. Leave enforcement in dry-run on a mixed-trust deployment unless every relevant module and sensor configuration has been reviewed. Tests use local auth/network fixtures and mock responders; no live system is required for these checks.

The Rust sidecar replaces the direct, unmaintained chrono dependency with the already-locked time crate. Its event, match-result and packet timestamps remain UTC RFC3339 strings; nanosecond precision and non-UTC input normalization are tested. No security gate or advisory policy was changed.
