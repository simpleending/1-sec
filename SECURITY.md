# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability

If you discover a security vulnerability in 1SEC, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **support@driftrail.com** with:

- A description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Any potential impact assessment

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Security Design

1SEC is a security product. We hold ourselves to a high standard:

- All modules run in-process with no required external runtime services
- The API server supports key-based authentication (set `ONESEC_API_KEY` or `server.api_keys` in config)
- Docker images run as non-root (UID 1000); the shipped Compose deployment uses a read-only root filesystem
- Helm chart enforces `seccompProfile: RuntimeDefault`, drops all capabilities, and disallows privilege escalation
- No secrets are baked into images — all sensitive config is injected via environment variables or mounted secrets
- CORS is configurable via `server.cors_origins`; the shipped config allows the two 1-sec.dev origins and the programmatic default allows none. CORS does not replace API authentication.

- Embedded NATS requires a private per-instance credential. Its clients are trusted telemetry producers; keep its data directory and collector accounts private. External brokers require their own authentication/TLS policy.
- Configuration activation requires restart; optional AI requests contain only allowlisted structural metadata.

## Hardening Checklist

For production deployments:

1. Set `ONESEC_API_KEY` to secure the REST API
2. Configure `server.cors_origins` to restrict allowed origins
3. Use the Helm chart's `existingSecret` to reference a Kubernetes Secret for API keys
4. Enable TLS termination via your ingress controller or reverse proxy
5. Review and tune resource limits for your traffic volume
