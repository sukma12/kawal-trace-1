# Kawal Trace v2.0.1 — Feature and readiness matrix

Legend: **Source implementation** = code exists and unit-tested; **requires deployment** = needs agent/API/platform configuration; **not complete** = deliberately not claimed as finished.

| Feature requested | Current implementation | Readiness / limit |
|---|---|---|
| Cryptographic anti-tampering | SHA-256 hash chains for local audit records and Linux/Windows sensor outboxes; remote audit chain checks sequence/hash. | Source implemented/tested. Not immutable against privileged attacker who can rewrite DB and chain; use off-host checkpoints/signed evidence for stronger forensic assurance. |
| Local database confidentiality | SQLite remains on the local device; API tokens/private keys use OS Secure Storage when the native storage bridge is available. | The audit-chain `details` column and the server-event archive payload are encrypted at rest (AES-256-GCM, per-row binding); other columns, the account and scanner databases, quarantine contents and exports are not. On Windows the key is wrapped with DPAPI (not yet run on a real Windows machine); on Android/Linux it is a 0600 file beside the database, so it protects against a stray database copy, not against someone who can read the whole app folder. Keep BitLocker/device encryption and a strong OS lock. See `docs/LOCAL_STORAGE.md`. |
| Windows Event ID monitor | Allowlist Security IDs 4624/4625/4634/4647/4672/4688/4697/1102/4720/4726/4728/4732, System 7045, Defender 1116/1117/5007. Minimizes exported fields; no command-line collection. | Requires separate Windows agent installed/configured on target host. First run baselines newest record, then collects only new events. |
| Automatic Windows Firewall response | Fixed temporary inbound block action, public IPv4 only, 5/15/30 min TTL, generated named firewall rule, expiry worker on the host. | Source implemented and policy-tested. Disabled by default on API and host, needs admin rights and host-local 4625 evidence. New inbound flows may be blocked; existing sessions are not guaranteed to terminate. |
| RDP session isolation | `logoff.exe` on explicitly named active Session ID only after `quser` username match, current-session protection, nonprotected user check and recent local RDP auth evidence. | Requires response enabled on both API and host; false positives can interrupt a real user. Staging/manual approval recommended. |
| CMD/PowerShell process termination | `taskkill.exe /PID` only for allowlisted shell binaries, with live PID/image/owner checks and local process creation evidence. | Doesn't accept arbitrary commands or target arbitrary process; requires elevated host agent. PID/process can exit or change before action, then it fails closed. |
| Low overhead | Windows poll default 10s, max 250 matching event records per channel/cycle and batches up to 100; first-run baseline prevents historical flood. No full disk scan. Linux watches journal/audit logs. ClamAV disabled by default and limited to specified changed files/roots. | Defaults implemented; real resource use must be measured on each host. |
| High priority notifications | Native local notification extension for new HIGH/CRITICAL events while the app is open and permissions are granted. The first feed read checks recent (last five minutes) events for an active incident and baselines older history. | Requires Flet build and OS permission/channel settings; no push service configured for app fully closed. OS may suppress notifications. |
| Private Network Access | Detects OpenZiti/WireGuard tools; explicit OpenZiti Edge Tunnel service start/stop (systemd/Windows Service Control); WireGuard .conf validation and explicit wg-quick / WireGuard for Windows tunnel install/uninstall; TCP test to a private endpoint. | Requires pre-installed clients, pre-enrolled OpenZiti identity or valid WireGuard peer config, and OS Administrator/root permission. Does not create identity/keys, install clients, configure router/firewall, or prove ZTNA policy from a TCP probe. |
| Privileged activity alert | New HIGH alert for server-reported `PRIVILEGE_USE`; can trigger the existing foreground sound/native notification path when the event is new. | Sudo/privilege use can be legitimate. Alert requests operator review and is not proof of unauthorized access. |
| Two-factor response confirmation | Admin role + typed target confirmation + TOTP code + response-only token + API feature flag + endpoint revalidation and audit. | Implemented for queued responses. Response actions are OFF by default. Protect TOTP seed separately from response token. |
| IP geolocation/map | Local GeoIP enrichment fields; OpenStreetMap link only when database supplies valid coordinates; country/region/city/ASN optional. | Approximate; requires installed local GeoIP database and API support. MAC addresses do not traverse Internet. No exact actor/home location inference. |
| Multi-server fleet status | Multi-profile registry, per-profile tokens/checkpoints, connect/test/disconnect/delete profile; fleet summary based on recent event feed. | Implemented in source. Shows only hosts visible in fetched feed; does not automatically discover other servers. |
| Local login throttling | Five failed password attempts in a five-minute window trigger a 60-second per-username lockout persisted in SQLite. Successful login clears the counter. | Implemented and tested; app-level guardrail only. OS account controls and file permissions remain necessary against local privileged attackers. |
| Generic REST feed hardening | Bearer/API-key/custom-header/no-auth modes; configurable JSON path/field mapping; strict TLS for Internet endpoints, no redirects, 4 MiB streamed response cap; client timeout range is 1–30 seconds but the UI still uses the 8-second default. | 1,000 loopback compatibility/security scenarios pass. Vendor OAuth, pagination/cursors, GraphQL/SOAP/WebSocket and undocumented formats need dedicated adapters. |
| Forensic report export | JSON and CSV exports; CSV formula-injection guard; export actions included in local audit. | Implemented in source. Store report files securely; they can contain sensitive IP/user/path metadata. |
| E2EE AES-256 | X25519 ephemeral key agreement, HKDF-SHA256 and AES-256-GCM on audit and security event payload bodies. Private key in OS Secure Storage; password-protected encrypted key backup uses Scrypt + AES-256-GCM. | Implemented/tested for telemetry and audit payloads. Routing metadata remains visible to API. **Response-control requests and generic REST feeds are not E2EE**; they rely on HTTPS/TLS, authentication, TOTP where applicable, and agent-side policy. This is not yet full control-plane E2EE. |
| Notifications while app closed | — | **Not complete**: requires Firebase Cloud Messaging (or another push provider), device enrollment, APNs/FCM credentials where needed, and tests on release APK. Polling stops when app is closed. |
| Cloudflare web visitor blocking | — | UFW response cannot reliably block a web visitor proxied by Cloudflare. Needs a separate Cloudflare WAF adapter and origin/visitor IP trust model. |
| EXE/APK release | Source + build scripts. | **Not built here**. User must run platform build and test the artifact. |
| Real server integration | API contract + optional local API + agents. | **Not connected to the user's live Ubuntu/Cloudflare yet**. API route compatibility and E2EE key deployment require staged integration. |

## Event ID semantics

Event IDs are heuristics/signals. 4625 = failed logon, 4624 = successful logon, 1102 = Security audit log cleared, 4688 = process creation (only minimal image/PID fields are exported), Defender 1116/1117/5007 = threat detection/action/config changes. A single signal is not proof of an attacker or illegal intent.

## Security deployment gates

1. Keep API and endpoint responses disabled by default.
2. Maintain a protected admin IP allowlist and a separate recovery path before testing firewall blocks.
3. Do not apply UFW to Cloudflare-proxied website visitors.
4. Use HTTPS with certificate validation; never `verify=False`.
5. Rotate/revoke per-device tokens and protect TOTP seed. Do not include secrets in logs or repositories.
6. Test first on an authorized staging host and collect evidence before enabling response actions.


## v2.3.0 advanced defense helpers

| Feature | Current behavior | Important limit |
|---|---|---|
| Local device PIN | 8–12 digit PIN, PBKDF2 hash, persistent local lockout; password remains recovery path | Not server authentication; SQLite database is not app-encrypted at rest |
| Windows/Android biometric | Optional `flet-local-auth` platform dialog; native dependency and Android permission declared | Requires native build/device test; Linux/Web unsupported |
| OpenZiti/WireGuard | Explicit connect/disconnect controls for preconfigured clients; WireGuard config is validated in-memory and shell hooks are rejected | Does not enroll identity, provision keys, install clients, or configure firewall/router; administrator/root permission is required |
| Email review | Offline `.eml` heuristics for auth headers, From/Reply-To, URL and urgency | Not a verdict; no automatic deletion or mailbox integration |
| PhishTank lookup | Manual single-URL HTTPS check, optional API key; email body not uploaded | External provider sees selected URL and request metadata; not tested against live service in offline test run |
| SpamAssassin | Optional bounded local CLI with timeout | Only works where SpamAssassin is installed; no email deletion |
| Micro-segmentation | Validated private, non-overlapping CIDR policy preview | Preview only; no firewall rules executed |


## Build 10 verification additions

| Area | Added verification | What success proves | What it does not prove |
|---|---|---|---|
| Telemetry pipeline | Local synthetic event test: validation → detection → SQLite archive → read-back → duplicate protection | Local processing and archive path work in the current app runtime | Does not prove the remote server/agent is sending events; no network is used |
| ZTNA endpoint | Operator-supplied host/port TCP probe | The endpoint is reachable from this device at test time | Does not identify the route as ZTNA, authenticate an identity, or validate controller/policy; use a private-only service |
