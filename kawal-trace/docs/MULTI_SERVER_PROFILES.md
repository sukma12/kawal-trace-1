# Multi-server profiles — Kawal-Trace 1.6.0

Kawal-Trace 1.6 supports a saved list of named API server profiles. It can be installed wherever Python/Flet builds are supported and can connect to different Ubuntu/Linux servers **provided each target exposes the Kawal-Trace HTTPS API contract (directly or through an adapter)**. It does not connect to arbitrary Ubuntu servers over SSH, and it does not automatically install an agent remotely.

## In-app workflow

1. Sign in as a local administrator.
2. Open **Integrasi server pusat**.
3. Click **Tambah server**.
4. Set a descriptive profile name, an HTTPS base URL, and the API paths for audit upload, health check, and security-event feed. Each profile gets its own client device ID by default.
5. Paste the device upload token and, separately, the read-only monitor token issued by that server's administrator. Press **Simpan profile** or **Hubungkan** (which saves the profile first).
6. **Uji koneksi** checks the selected profile's authenticated health endpoint. **Hubungkan** then marks that profile as active in this app session and enables audit sync and feed polling if their respective tokens exist.
7. Select another saved profile to switch servers. Selecting a different profile disconnects the prior profile from this app session. Only one profile is actively connected at a time.
8. **Putuskan** stops this app's background audit upload and security-feed polling for the selected profile. It does not stop the remote Ubuntu host, uninstall the Linux agent, revoke credentials on the server, or delete remote logs.
9. **Hapus profile** removes the selected profile and its per-profile credentials from this device's secure storage. It does not delete the remote server, remote data, or remote agent; revoke the server-side token separately if that is required.

## Storage and isolation

- Non-secret endpoint settings and selected profile ID are saved in the local `server-registry.json` file with restrictive permissions where supported. This file does not contain tokens.
- Device-upload and monitor-read-only tokens use separate secure-storage keys per profile. Tokens are never shared across profiles by design. A compatibility fallback exists for the old single-server `legacy-default` profile only.
- Sync cursors use per-profile SQLite files so the acknowledgement for Server A cannot advance the cursor for Server B. Local audit records remain in the existing local audit database.
- Connection state is deliberately **not** persisted. After restarting the app, a saved server must be explicitly connected again.
- Disconnecting the app does not mean the Linux sensor has stopped sending telemetry. The agent has its own token and continues running until an administrator stops or disables it on the host.

## Server-side requirements

Every profile must point to a compatible API:

- `GET /healthz` for authenticated connectivity test.
- `POST /api/v1/audit/events:batch` for client audit upload (idempotent by event/batch ID; chain acknowledgements must be validated).
- `POST /api/v1/security-events:batch` for Linux agent telemetry, with a separate write-only host token.
- `GET /api/v1/security-events?limit=100` for dashboard feed, with a separate read-only monitoring token.

Paths can be changed per profile to adapt the client to an existing API. The payload/response contract must still match, unless an adapter is supplied. Public Internet endpoints must use HTTPS with certificate validation. Do not paste admin tokens into the app. Do not expose tokens in screenshots, support logs, repositories, or shared ZIP files.

## Removing vs disconnecting

- **Disconnect**: runtime-only, reversible, stops app-side sync and polling.
- **Remove profile**: removes this app's local profile and stored tokens; does not change the server.
- **Revoke token**: a separate action in the server/API identity system. Revoke the token server-side if a device is lost or a credential is exposed.
- **Stop Linux agent**: a separate administrator action on the Ubuntu host, normally via `systemctl stop kawal-trace-agent` after checking impact.

Use staging servers first. A successful health-check is not proof that the security-event endpoint accepts all telemetry fields; test upload and feed round trips separately.
