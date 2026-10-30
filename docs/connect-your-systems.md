# Connect your own systems to 1-SEC

1-SEC uses API keys. You do not need a separate username/password login to open the dashboard, send events, or write an integration. Your applications can connect through HTTP, existing log collectors, or custom collector/module code.

The local open-source engine runs without a purchase or cloud connection. After purchasing hosted services, save the API key shown on the confirmation page and enter it at [1-sec.dev/dashboard](https://1-sec.dev/dashboard). That key accesses your hosted account; it does not automatically configure authentication on your own engine.

## Choose the right credential

| Credential | Purpose | Where it belongs |
| --- | --- | --- |
| Hosted key issued after purchase | Open the hosted dashboard and access permitted hosted APIs; an owner can enroll instances | Dashboard API-key field, or `Authorization: Bearer <key>` on `https://1-sec.dev/api/v1/...` |
| Dedicated hosted instance key | Report one engine's telemetry to your hosted account | `ONESEC_CLOUD_API_KEY` or `cloud.api_key`, paired with the enrolled `cloud.instance_id` |
| Local engine write key | Submit events and use supported management/response endpoints on your engine | Configure `ONESEC_API_KEY` or `server.api_keys`; send it to your engine in an authorization header |
| Local engine read-only key | Read status, schemas and alerts | Configure `server.read_only_keys`; it cannot submit events or change the engine |
| Embedded event-bus credential | Allow trusted collectors to publish locally | Default collectors discover the private instance credential; it is separate from HTTP API keys |

`GEMINI_API_KEY` is an optional model-provider credential, not a dashboard or local-engine access key. Keep all keys in protected environment/configuration, never in public browser code, source control or query-string URLs. Use HTTPS for networked APIs and retain the engine's loopback bind unless deliberately configuring protected remote access.

## Start a local engine with API access

Use `1sec setup` for guided configuration, or supply a strong random local write key before starting the engine. The shell examples below use Bash; set the same environment variable in your service or operating system when deploying.

```bash
export ONESEC_API_KEY='replace-with-your-random-engine-write-key'
1sec up
```

The engine API defaults to `http://127.0.0.1:1780`. In another terminal, set the same key for your client. This local key is selected by the engine operator; a purchased hosted key is not automatically accepted here. A keyless local read-only view does not permit event submission or management writes.

```bash
curl --fail-with-body -sS \
  -H "Authorization: Bearer $ONESEC_API_KEY" \
  'http://127.0.0.1:1780/api/v1/event-schemas?category=http'
```

The local API also accepts an `X-API-Key` header. Hosted examples use `Authorization: Bearer`.

## Send events from your application

Any language with an HTTP client can send a canonical `SecurityEvent` to the local engine. Use an event type from `/api/v1/event-schemas` and supply its required detail fields; the `type` determines which detectors receive the event. No 1-SEC SDK or login session is needed.

```bash
curl --fail-with-body -sS \
  -X POST 'http://127.0.0.1:1780/api/v1/events' \
  -H "Authorization: Bearer $ONESEC_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{
    "source": "my_app",
    "module": "external",
    "type": "http_request",
    "severity": "INFO",
    "summary": "Application request observed",
    "details": {"path": "/health", "method": "GET", "body": "hello"}
  }'
```

HTTP **202** with `status: "accepted"` means the event was queued for analysis. It is not an allow/deny decision or a guarantee that an alert will be raised. This benign example may produce no alert. Poll `GET /api/v1/alerts` with an authorized key to retrieve findings.

Python example using only the standard library:

```python
import json
import os
import uuid
from datetime import datetime, timezone
from urllib.request import Request, urlopen

event = {
    "id": str(uuid.uuid4()),
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "source": "my_app",
    "module": "external",
    "type": "http_request",
    "severity": "INFO",
    "summary": "Application request observed",
    "details": {"path": "/health", "method": "GET", "body": "hello"},
}
request = Request(
    "http://127.0.0.1:1780/api/v1/events",
    data=json.dumps(event).encode("utf-8"),
    headers={
        "Authorization": "Bearer " + os.environ["ONESEC_API_KEY"],
        "Content-Type": "application/json",
    },
    method="POST",
)
with urlopen(request, timeout=10) as response:
    print(response.status, json.load(response))
```

Create a fresh ID/timestamp for each independent observation. If retrying a delivery, reuse that observation's complete event, including ID and timestamp, so replay filtering can recognize it. A read-only key cannot call `POST /api/v1/events`.

## Connect existing logs or write a collector

Start the engine first, then run a collector on the same machine with the same config/data directory and an account allowed to read its private bus credential:

```bash
1sec collect nginx --log-path /var/log/nginx/access.log
# Or: 1sec collect auth --log-path /var/log/auth.log
# Or: 1sec collect json --log-path /var/log/cloudtrail.json
```

These local collectors use the event bus, not the purchased dashboard key or the local HTTP key. An explicit external `--nats-url` needs that broker's own protected credential configuration. See [collector instructions](https://1-sec.dev/collectors).

For custom code, adapt records to the canonical event schema and submit them through HTTP. Developers extending this repository can implement `internal/collect.Collector` for a log adapter or `internal/core.Module` for detection logic. A collector supplies telemetry; a module analyzes supported event types.

## Optional: connect an engine to the hosted dashboard

1. Save the key issued after purchase and use it to open the hosted dashboard. There is no separate login account/password to create.
2. With an owner key, create a dedicated instance credential through the hosted API. The shell variable below is a client-side example name, not an engine configuration setting:

```bash
export ONESEC_CLOUD_OWNER_KEY='your-key-from-checkout'
curl --fail-with-body -sS \
  -X POST 'https://1-sec.dev/api/v1/keys' \
  -H "Authorization: Bearer $ONESEC_CLOUD_OWNER_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"action":"enroll","allowCommands":false}'
```

3. Save the returned `apiKey` and `instanceId`. Set `ONESEC_CLOUD_API_KEY` to that instance key in the engine's protected environment and configure the matching ID:

```yaml
cloud:
  enabled: true
  api_url: "https://1-sec.dev/api/v1"
  instance_id: "i-replace-with-the-returned-instanceId"
  remote_commands_enabled: false
```

4. Restart the engine with that configuration. Its cloud reporter sends heartbeats, enforcement records and correlations to the hosted dashboard. Remote commands require separate explicit permission and engine opt-in; sending telemetry alone does not enable them. A device credential cannot browse the whole dashboard; keep using your permitted human key there.

The hosted `/api/v1/ingest` endpoint accepts those reporting payloads. Raw application `SecurityEvent` objects belong at your engine's `/api/v1/events`; the two endpoints are not interchangeable.

## Connect responses to your own application

### Runtime process containment

For process/start/execution and fileless telemetry, supply the observed actor's `process_id` or `pid`, together with its reporting host (`process_host`, `hostname`, `syslog_hostname` or `host_id`). Supplied PID aliases must agree; supplied host identities must match the local executor's hostname or interface addresses. A client `source_ip` does not identify the process's host. PIDs may be integer strings or exact integral JSON numbers. Name-only, missing, fractional, conflicting, remote and container-namespace evidence remains alertable but does not authorize local termination.

For injection telemetry, `source_pid` identifies the actor; `target_pid` identifies the victim and is never used as a kill target. Run the executor in the same host/PID namespace as its trusted collector. Host labels are telemetry assertions, not authentication; protect collector and API credentials.

Dry-run, severity, approvals, allowlists and response policy still control whether an eligible action runs. Review skipped-action records when an alert lacks executable evidence. Runtime file-integrity events retain `affected_path` for investigation; changed configuration or victim files are not automatically quarantined. See the [source-update contract and tests](security-updates/2026-10-30-runtime-containment.md). These source fixes are not in downloadable v0.4.29 binaries.

Read alerts or configure supported webhooks/response policies to connect detection to your own workflow. For an existing management gateway, `POST /api/v1/access/check` can supply an explicit decision after the operator configures its policy. The gateway must enforce that decision before forwarding and deny on errors/timeouts; see the [access-check contract](security-updates/2026-10-14.md#gateway-integration).

Customers can implement these adapters in their own code. Sending telemetry does not automatically place 1-SEC inside their request or tool-execution path, and the event-ingestion acknowledgment is not authorization to proceed. These integration choices do not require adding a login system to 1-SEC.
