# Kawal-Trace 1.8.0 — Universal Connector Modes

Kawal-Trace can keep multiple named server profiles, but no client can read a server's logs just from its IP/domain. A profile must use an API/feed the owner has authorized, or the owner must deploy/enable an approved telemetry agent/adapter. Do not connect to third-party company systems without explicit written authorization.

## Mode A — Kawal-Trace API (full contract)

Select `Kawal-Trace API · upload + feed` for a backend implementing the contract in `docs/SERVER_SYNC_CONTRACT.md` and `docs/SERVER_TELEMETRY_CONTRACT.md`.

Expected paths:

- `GET /healthz` — authenticated client health check.
- `POST /api/v1/audit/events:batch` — idempotent audit upload and checkpoint acknowledgement.
- `GET /api/v1/security-events?limit=100` — read-only normalized security feed.
- The Linux agent additionally sends `POST /api/v1/security-events:batch` with its own write-only token.

Upload and read-only feed credentials must be separate. Tokens are kept in native secure storage when available; the profile JSON does not store tokens. TLS certificate validation remains enabled.

## Mode B — Generic REST/JSON (read-only)

Select `Generic REST/JSON · feed read-only` if an existing authorized monitoring API exposes a JSON list of events. This mode performs only an authenticated `GET` to the configured feed endpoint. It does not upload audit records, crawl endpoints, scan ports, SSH into a host, or attempt authentication bypass.

Configuration fields:

- `Base URL`: HTTPS origin/base path for the authorized API.
- `Path API feed`: exact documented GET path that returns an event feed.
- `Autentikasi feed`: `Bearer` token or `X-API-Key`.
- `Path array event JSON`: dotted JSON path to an array, e.g. `events` or `data.items`; use `$` if the response body itself is a JSON array.
- `Mapping field (JSON)`: object mapping Kawal-Trace canonical fields to dotted paths in each source event.

Example: if the API returns `{"result":{"items":[{"eventNo":"id-17","created":"2026-10-21T00:10:00Z","severity":"login failed","host":{"name":"ubuntu-lab"},"username":"alice","client":{"ip":"203.0.113.9"},"message":"SSH authentication failed"}]}}`, configure:

```json
{
  "event_id": "eventNo",
  "timestamp_utc": "created",
  "event_type": "severity",
  "host_id": "host.name",
  "source": "host.name",
  "actor": "username",
  "source_ip": "client.ip",
  "details": "message"
}
```

Set JSON array path to `result.items`. The event time must be ISO-8601 with timezone. Event types such as `login failed`, `login success`, `sudo`, `file modified`, and service/config changes are normalized into the internal allow-list. Unknown types are represented as `CUSTOM_SECURITY_EVENT`, not treated as proof of attack. Invalid IP/time or malformed events are rejected instead of guessed.

Only the common `Bearer` and `X-API-Key` modes are built in. APIs requiring OAuth token exchange, mTLS, custom request signing, pagination, or proprietary response formats need an approved adapter written against that service's official documentation. Do not paste privileged/admin tokens into the dashboard.

## Connection preflight

`Uji koneksi` saves the visible profile first and makes one health-check/feed GET request. HTTP 401/403 indicates missing/incorrect credentials or insufficient permission; 404 often indicates an incorrect endpoint; non-JSON responses or an incorrect array path indicate a schema mismatch. A successful GET proves only that the configured feed can be read—not that uploads, host monitoring, or all security events work.

## Monitoring data sources

A feed only displays events already recorded by the source service. For OS-level monitoring on Linux, the server owner must enable appropriate journald/auditd collection and install/configure the Kawal-Trace Linux agent or an approved bridge. A normal website API (for example, routes for catalog/status/admin functions) is not automatically a security-event API and does not become one just because it is exposed through Cloudflare Tunnel.

## Legal and operational boundary

Examples such as NASA, Pertamina, or other organizations are not reachable for monitoring just because their public websites exist. Integration requires the organization's explicit authorization, an account/token with the intended minimum scope, documented endpoint/schema, and usually a deployment/connector approved by that organization. Use a lab/staging server for integration tests. Never treat a public URL as permission to query private telemetry or install an agent.
