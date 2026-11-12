# November 12 standalone engine improvements

The 1-SEC executable can start its API, dashboard, embedded event bus, existing detection modules, and configured log collectors in one process. Set `collectors.enabled: true` and list the sources under `collectors.sources`. The [integration guide](../connect-your-systems.md#connect-existing-logs-or-write-a-collector) has an example. Local file collection uses the existing broker and requires readable log files.

The collector CLI now accepts the documented `auth` and `json` names as well as `authlog` and `jsonlog`. It reports invalid or unavailable sources as startup errors. If a configured source cannot start, workers started in the same batch are stopped. The engine waits for its file collectors to stop before closing the broker. Publication failures are logged. File tailers follow new records and have no persistent read cursor.

The existing GitHub Actions collector processes the returned run IDs in order and advances its in-memory cursor after publishing each run. This covers the newest-first response without skipping the older runs in the batch. It remains an optional integration with a 20-run poll window and requires `GITHUB_TOKEN` and network access.

Startup now reports a busy API port or unusable TLS key pair before announcing readiness. Configuring either TLS file requires the other. Authorized API shutdown uses the same cleanup path as Ctrl+C, including on Windows. The CLI uses process liveness to request shutdown even when the engine is not ready to receive security events.

Release lookups now run only when requested with `1sec check --updates`. The lookup retrieves bounded release metadata and respects `ONESEC_NO_UPDATE=1`. The signed installer remains the upgrade path.

The Windows standalone smoke test built with cgo disabled, tailed an nginx log into an Injection Shield alert, and shut down through the authenticated CLI. The test intercepted attempted outbound HTTP through a loopback proxy and observed zero requests. Separate cases checked occupied ports and unavailable collector files. Existing package and service integrations remain available when configured. The published v0.4.32 binaries predate these source changes.
