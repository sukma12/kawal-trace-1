# Kawal Trace optional archive API v1.5.1 + controlled response queue

This is an optional standard-library API for the Kawal-Trace client and Linux agent. Install it only on a Linux server you administer when an existing API does not already provide a compatible security-event feed. It does not modify the existing Node website on port 9999. It binds to `127.0.0.1:8765`; publish it only using a dedicated HTTPS Cloudflare Tunnel hostname.

## Endpoints

- `GET /healthz` — authenticated health check (`Authorization: Bearer ...`, `X-KAWAL-Device-ID`); reports `features` (v1.5.0 adds `stream`).
- `GET /api/v1/stream` — **v1.5.0** Server-Sent Events "doorbell" for real-time use from any network. Monitor token required. It tells the app *which kind* of data changed (`security`, `encrypted`, `actions`, `windows`) and never carries the data; the app then pulls through the endpoints below. See `docs/REMOTE_REALTIME.md`.
- `POST /api/v1/audit/events:batch` — app audit ingestion with SHA-256 chain/checkpoint checks and idempotent retry.
- `POST /api/v1/security-events:batch` — authenticated Linux-agent event ingestion.
- `GET /api/v1/security-events?limit=100` — read-only security feed, monitor token.
- `POST /api/v1/windows/response-actions` — queues a tightly bounded Windows action only when `KAWAL_WINDOWS_RESPONSE_ENABLED=true`, separate response token and TOTP are valid, target host is enrolled, typed confirmation/reason are present; endpoint-side revalidation is mandatory.
- `GET /api/v1/windows/response-actions?limit=20` — monitor-token read-only status view; endpoint polling uses a host-scoped token and `X-KAWAL-Host-ID`.
- `POST /api/v1/response-actions` — queues `TEMP_BLOCK_IP` only when response actions are explicitly enabled, response token valid, target a public IPv4, exact human confirmation/reason provided, target is not allowlisted, and the same IP appears in recent direct SSH authentication failure telemetry from the Linux agent (24-hour window).
- `GET /api/v1/response-actions?limit=20` — read-only status of response requests.

## Abuse limits and response hardening (v1.5.1)

- **Failed-authentication throttle, per real client address.** More than 10 `401` answers in 60 s from one address → every request from that address gets `429` with `Retry-After` until the oldest failures age out. Only failures are counted: legitimate traffic is never limited, and a throttled request does not extend its own penalty. The throttle is on the *address*, never on the account, so an attacker cannot lock the owner out by guessing.
- **Real client address.** Behind Cloudflare Tunnel every TCP peer is the local `cloudflared`, so the address is read from `CF-Connecting-IP`, trusted **only** when the TCP peer is loopback (the server refuses any other bind address). Set `KAWAL_TRUST_CF_CONNECTING_IP=false` if you put anything else in front of the API. When the header is missing, all clients share the loopback address and that address gets a 20× higher limit, so one attacker cannot lock everybody out.
- **Second factor cannot be guessed at speed.** 5 wrong TOTP codes per device in 5 minutes → `429` even for the *correct* code until the window passes; a correct code clears earlier typos. Wrong codes also count against the client address.
- **Bounded memory.** Counters hold at most 4096 keys (least recently active dropped first) and drop expired keys, so a flood of distinct addresses cannot exhaust memory. State is in memory: a restart forgets it (accepted; the limits are about bursts).
- **Every response** (JSON, event stream, and errors raised by the HTTP parser itself) carries `X-Content-Type-Options`, `Content-Security-Policy: default-src 'none'`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Resource-Policy` and `Strict-Transport-Security`. Malformed requests get a bare JSON `4xx/5xx` instead of an empty reply or an HTML page, and the `Server:` banner names no version.
- Limits are constants near the top of `server.py` (`AUTH_FAIL_LIMIT`, `TOTP_FAIL_LIMIT`, …). They were exercised only over loopback with a fake clock; **not** through a real Cloudflare Tunnel.

## systemd hardening (v1.5.1)

`deploy/kawal-trace-api.service` now runs the API with no capabilities, an invisible `/proc`, no namespaces, a tight system-call allow-list, and network access **only to loopback** (`IPAddressDeny=any` + `IPAddressAllow=localhost`): even a fully compromised API process cannot send data out to the Internet. `systemd-analyze security --offline` scores it **1.1 (OK)**, down from 6.5 (MEDIUM). The tests guard the assumption this rests on (the API never makes an outbound connection).

* The syscall allow-list (`@system-service` minus `@privileged @resources`) is **measured**: the whole API test suite was run under `strace` and every call fits, except `fchown()`, which SQLite issues only when run as root and ignores if refused. A refused call returns `EPERM` (visible as `PermissionError` in `journalctl -u kawal-trace-api`) instead of killing the process. Your server may use a different Python/libc: repeat the measurement with `python3 deploy/check_syscalls.py <strace file>` (instructions inside the script).
* Rollback if the service does not start or logs `PermissionError` after the update: comment out the three `SystemCall*` lines (or `IPAddressDeny`/`IPAddressAllow`), `sudo systemctl daemon-reload && sudo systemctl restart kawal-trace-api`, and tell me which call or line was responsible.
* **Response worker (`kawal-trace-response-worker.service`).** It runs as root only to drive UFW, so it was changed conservatively: the `ProtectSystem=full` it already had makes `/etc` read-only, yet UFW writes `/etc/ufw/user.rules`, so it now has `ReadWritePaths=-/etc/ufw …`, and `AF_NETLINK` is allowed because iptables-nft (the default on current Ubuntu) uses it. Both are from my knowledge of UFW, **not verified on a real host** (UFW is not installable where this was written). Its exposure score is 5.2 (MEDIUM) on purpose: restricting root's capabilities or system calls without being able to test UFW could silently disable enforcement. After enabling response actions, run one real temporary block end to end and read `journalctl -u kawal-trace-response-worker`; a failure shows as `ufw_rule_add_failed`.
* Not done and why: `PrivateUsers` (changes file ownership semantics of the state directory), `MemoryMax`/`CPUQuota` (depend on your server's RAM), a stricter worker sandbox (see above).

## Install on Ubuntu

For a new standalone API installation, extract this folder to `/home/server/Kawal-Trace/optional-server-api` or a similar directory, then run:

```bash
sudo bash install.sh
sudo /usr/bin/python3 /opt/kawal-trace-api/setup_tokens.py
sudo systemctl restart kawal-trace-api
sudo systemctl status kawal-trace-api --no-pager
```

`setup_tokens.py` prompts for the Device ID from the app profile and a Host ID for the Linux agent. It generates separate random tokens for app upload, app monitor, agent ingest, and response requests. Tokens are shown once. It preserves unrelated existing token ID mappings. The upgraded script refuses to rotate an existing ID unless `--rotate-existing` is explicitly supplied. For normal multi-user enrollment, do not run this script; use the v1.3.0 membership flow below. The environment file is `/etc/kawal-trace/api.env`, mode 0600.

Test locally before Cloudflare:

```bash
sudo ss -lntp | grep ':8765'
curl -i http://127.0.0.1:8765/healthz
```

An unauthenticated health check should return HTTP 401; that is expected. Use the app's Test Connection button with valid Device ID and upload token. Do not publish port 8765 directly to the Internet.

## Configure Cloudflare

Create a dedicated hostname on a Named Tunnel for `http://127.0.0.1:8765`; keep the existing website hostname and its local service on port 9999 unchanged. A Quick Tunnel is temporary and produces a URL that may change when restarted.

## Optional Linux agent

The API receives events; it does not magically read host logs by itself. Install and configure `server_agent/` separately for journald SSH/sudo and optional auditd file rules. Application login telemetry from the website Node.js app requires a separate, reviewed adapter.

## Malware signal

The agent can optionally run `clamscan` against the specific changed file, only if `KAWAL_TRACE_CLAMSCAN_ENABLED=true` and the file is under a configured `KAWAL_TRACE_CLAMSCAN_ROOTS`. ClamAV and current signatures must already be installed. A `MALWARE_DETECTED` event is emitted only on ClamAV signature match. It does not clean, delete, or isolate files automatically. The agent service is sandboxed with `ProtectHome=true`; `/home/...` paths will not be visible by default. If you specifically need to inspect a home-directory webroot, configure a narrowly reviewed systemd drop-in and file permissions for only that directory, then test read access as the service user before enabling scans.

## Controlled UFW response — OFF by default

The API only queues a request. The privileged `kawal-trace-response-worker` independently validates it before attempting a UFW `deny` rule. It only accepts public IPv4, a nonempty administrator IP allowlist, TTL 300/900/1800 seconds, a reason, exact confirmation `BLOCK <IP>`, a separate response token, and recent direct `AUTH_FAILURE` SSH evidence. In `/etc/kawal-trace/api.env`, default is:

```ini
KAWAL_RESPONSE_ACTIONS_ENABLED=false
KAWAL_RESPONSE_ALLOWLIST=
```

Keep it disabled until staged and reviewed. If deciding to enable, record the fixed/trusted administrator public IPv4 in `KAWAL_RESPONSE_ALLOWLIST` first, verify SSH recovery access and UFW rules, then only set `KAWAL_RESPONSE_ACTIONS_ENABLED=true` after the owner approves. Restart API and worker after changing env:

```bash
sudo systemctl restart kawal-trace-api kawal-trace-response-worker
sudo systemctl status kawal-trace-response-worker --no-pager
```

The worker is root because UFW needs privileges; it accepts only its fixed action and parameter types, never arbitrary shell commands. It uses marker comments and will not blindly delete a numbered rule if its marker is missing. Status `EXPIRY_ERROR` means manual review is required. The rule prevents matching new inbound flows; it is **not** a guarantee that existing SSH/web sessions are disconnected. Keep an administrator recovery path and test only in a staging/lab.

### Cloudflare limitation

Do not use the UFW action to eject HTTP users who reach a website via Cloudflare Tunnel/proxy. The origin's network connection is to Cloudflare or the local tunnel, not directly to the visitor. This package has no Cloudflare WAF/API blocking adapter. Web visitor handling requires trusted application logging and a separate authorized Cloudflare API/WAF integration.

## Data and security

- API does not perform port scanning, exploit attempts, or automatic retaliation.
- GeoIP is approximate; MAC addresses cannot be learned across the Internet.
- API database is `/var/lib/kawal-trace-api/events.sqlite3`; back it up.
- This starter integration is not a full SIEM, EDR, forensic collector, or substitute for a security review.


## Membership management (v1.3.0)

- Existing installs: run `sudo bash upgrade_membership.sh` from this folder. This backs up `/opt/kawal-trace-api/server.py`, installs the compatible API, and leaves `/etc/kawal-trace/api.env` and the event database untouched.
- Create the separate owner-only key once: `sudo python3 /opt/kawal-trace-api/setup_admin_token.py`. It appends only `KAWAL_ADMIN_TOKEN`, backs up the env file, and does not rotate device/agent tokens. Restart the service as instructed and keep that key private. Re-running without `--rotate` will not change or reveal it.
- Device client: save the HTTPS Base URL and press **Minta Akses / Ambil Token Otomatis**. The client creates a persistent local claim secret in OS secure storage and sends an enrollment request. The owner app stores the admin key in its own secure storage, opens **Muat Anggota**, enters the pending Device ID and presses **Tambah / Setujui Anggota**. The member then presses **Hubungkan** (or requests credentials again) to receive three scoped tokens automatically.
- Removal: the owner selects an ACTIVE Device ID and presses **Keluarkan Anggota**. The API changes its membership status to REVOKED; token checks reject that ID immediately, including old environment-backed tokens. The SQLite member records and existing event database are retained.
- `setup_tokens.py` is legacy/manual only. Do not run it to add normal members.
- Quick Tunnel URL can change when restarted; configure a stable named tunnel/hostname for regular deployments.


## Daily archive API (v1.4.0) — disabled by default

These endpoints store a client's own audit chain or log archive on this server. **The Kawal Trace app no longer uploads any of it**
(all app databases stay on the user's device), so the API answers them with HTTP 403 `client_data_storage_disabled` unless the
operator sets `KAWAL_API_ACCEPT_CLIENT_DATA=true` in `api.env`. Enable it only to serve an older app version or to run the protocol
tests. Security events pushed by monitored hosts (`/api/v1/security-events`, `/api/v1/security-events:batch`) are not affected.

Gated paths: `/api/v1/archive/events`, `/api/v1/archive/events/summary`, `/api/v1/archive/events:batch`,
`/api/v1/audit/events:batch`, `/api/v1/encrypted-audit/events:batch`.

When enabled, all of them require an enrolled device with an audit token and the matching `X-KAWAL-Device-ID`. Only expose the API
through HTTPS and an authenticated tunnel/reverse proxy.
