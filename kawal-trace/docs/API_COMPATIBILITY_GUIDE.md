# Kawal Trace 2.2.0 — API compatibility and deployment guide

## What "universal API" means

Kawal Trace has read-only adapters for documented security-event feeds using REST/JSON, OAuth2 client-credentials + REST/JSON, GraphQL query-only, SOAP/XML read-only, and WebSocket JSON. REST can use page, offset, or cursor pagination and extra query parameters. Each adapter maps the provider's event schema into Kawal Trace's normalized event format.

This is broad protocol support, not automatic compatibility with every vendor. The provider must expose the relevant authentication/security events to a read-only API identity or an authorized host agent must collect them. Public data APIs (for example, an astronomy API) do not thereby expose infrastructure login records. A user must have permission to access the chosen endpoint; no private API discovery or unauthorized access is provided.

## Configure from the Integrasi Server panel

Choose **Universal API adapter · read-only**, then choose the protocol in **Protokol feed eksternal**. Keep the profile's base URL and telemetry path aligned with the provider's official documentation. Use the field mapping to translate provider keys to normalized field names. API token credentials should be scoped read-only.

### REST/JSON with pagination

`adapter_options_json` example:

```json
{
  "events_path": "data.events",
  "query_params": {"tenant": "audit-readonly", "region": "eu-central"},
  "pagination": {
    "mode": "cursor",
    "items_path": "data.events",
    "next_cursor_path": "page.nextCursor",
    "cursor_param": "cursor",
    "page_size": 100,
    "max_pages": 10
  }
}
```

Pagination `mode` supports `none`, `page`, `offset`, or `cursor`; page size is 1–100 and the adapter will read at most 10 pages per poll. `query_params` supports up to 32 scalar values and cannot override limit/pagination keys. Exact field names and cursor shape depend on the upstream API.

### OAuth2 client credentials + REST

```json
{
  "token_url": "https://identity.example.com/oauth2/token",
  "client_id": "kawal-trace-audit-reader",
  "scope": "audit.events.read",
  "client_auth": "post",
  "events_path": "data.events"
}
```

Set `client_auth` to `post` or `basic` according to the provider's official OAuth2 contract. Enter the **OAuth2 client secret** in the separate secret field; the source app stores it using OS Secure Storage and rejects secret-looking keys in persisted JSON options. The adapter obtains/caches a short-lived Bearer token in memory and automatically requests a replacement when close to expiry. Provider-specific scopes, audience parameters, consent grants, and non-standard OAuth flows may need an adapter adjustment.

### GraphQL query-only

```json
{
  "query": "query SecurityEvents { securityEvents { id timestamp type host actor sourceIp message } }",
  "variables": {"limit": 100},
  "events_path": "data.securityEvents"
}
```

GraphQL uses POST because that is common for GraphQL APIs, but `mutation` and `subscription` operations are rejected. Query length is capped at 16,000 characters and variables at 8 KiB. The event path and field mapping must match the provider's response schema.

### SOAP/XML read-only

```json
{
  "soap_action": "GetSecurityEvents",
  "envelope_xml": "<Envelope><Body><GetSecurityEvents><Limit>100</Limit></GetSecurityEvents></Body></Envelope>",
  "event_tag": "Event",
  "xml_mapping": {
    "event_id": "Id",
    "timestamp_utc": "Timestamp",
    "event_type": "Type",
    "host_id": "Host",
    "source": "Source",
    "actor": "Username",
    "source_ip": "SourceIP",
    "details": "Message"
  }
}
```

XML is parsed with `defusedxml`. DTD/external entities are blocked, the request envelope is capped at 64 KiB, responses are capped at 4 MiB, and operation names must begin with a recognized read-only prefix such as `Get`, `List`, `Read`, `Query`, or `Search`. Some vendor SOAP schemas use other read-only names; those require a reviewed adapter change rather than weakening this guard.

### WebSocket JSON feed

```json
{
  "url": "wss://logs.example.com/api/security-events",
  "events_path": "$",
  "idle_timeout_seconds": 1.0,
  "messages_per_poll": 20,
  "subprotocols": []
}
```

Public endpoints must use `wss://`; plain `ws://` is allowed only for loopback development tests. The adapter holds a read-only WebSocket connection across polls while the app remains connected, reads bounded JSON event messages, and reconnects after a connection error on a later poll. It does not send subscription/control commands. If a provider requires a subscription frame before emitting events, add and review a provider-specific safe read-only handshake.

## Security behavior and limits

- Public Internet APIs require HTTPS/WSS with certificate validation; redirects are not followed; environment proxy variables are not trusted by the protocol adapter; read responses are capped at 4 MiB.
- Per-request timeout is 1–30 seconds (default 8 seconds). API event data is treated as untrusted input and normalized/validated before display.
- Generic external API profiles are **read-only**. These adapters cannot block users or alter server state. Active response features apply only to the app's own authorized Kawal Trace agents/API and remain separately guarded.
- API request parameters/query, field names and payload sizes are bounded. GraphQL mutations/subscriptions, SOAP DTD/XXE, unsafe WebSocket schemes, invalid token/header inputs, and invalid schema mappings are rejected in preflight.
- REST, GraphQL, SOAP, and WebSocket authentication modes currently support the existing read-only token choices (Bearer, API key, custom header, or none where truly public). OAuth2 uses client credentials with Bearer access tokens. Provider-specific signing, mutual TLS/client certificates, SAML/SSO, cookies, AWS/GCP/Azure SDK event APIs, database queries, syslog, vendor binary protocols, and non-standard pagination are not automatically supported.
- Never put secrets in `adapter_options_json`, README files or support reports. Use a dedicated scoped credential in OS Secure Storage. If a provider's API doesn't expose login/security events, Kawal Trace cannot infer data that the provider does not return.

## Live monitoring, local storage, and alerts

- Feed refresh/polling occurs approximately every five seconds while Kawal Trace is open and connected, plus network latency. This is near-real-time polling, not zero latency.
- WebSocket mode keeps a connection open across polls, but events are displayed and evaluated on the next client polling tick. Connection state and OS scheduling still affect latency.
- Local audit database files remain on-device unless the operator enables a remote sync profile. SQLite log payloads are **not encrypted at rest by the app itself**; use BitLocker/device encryption, OS account controls, and a strong lock screen. The SHA-256 chain is tamper-evident, not confidentiality protection or immunity to an administrator/root attacker.
- The app has an audio plugin and a Windows `winsound` fallback, and it can request native OS notification permission. Real OS audio/system notification behavior requires a built EXE/APK, correct plugin packaging, notification permissions/channels, speaker volume, and device-side testing.
- Sound and local notifications run while the app process is active. Push notification delivery while the app is fully closed is not configured; that requires a background/push component and may require a backend. A central server/authorized agent must remain operating to collect 24/7 logs.

## Verification scope for v2.2.0

- The full Python suite covers authentication, audit hash chain, agents, synchronization, protocol adapters, platform storage selection and alert policy.
- `scripts/simulate_1000_api_protocols.py` runs 1,000 scenarios on loopback: 500 REST mapping/auth variations, 100 paginated REST feeds, 100 OAuth2 flows, 100 GraphQL feeds, 100 SOAP feeds, 50 WebSocket feeds and 50 expected preflight rejections.
- `scripts/simulate_1000_attack_scenarios.py` runs 1,000 local defensive input/preflight cases involving configuration poisoning, unsafe URL/path settings, GraphQL mutation/subscription/oversize input, SOAP XXE/DTD/malformed/oversized XML and mutating operation names, WebSocket endpoint/subprotocol settings, and credential/header abuse.
- These tests never contact NASA, Pertamina, public Internet APIs, or other third-party servers. They are client code tests, not 1,000 external API certifications or a penetration test of a built executable.
- The GUI was not executed in this container, and no Windows EXE or Android APK was built here. Actual OS audio/notification, background behavior, platform permissions, real provider authorization, multi-region WAN latency, and vendor-specific event schemas remain device/provider tests.
