# Windows Event Log agent guide (v1.9.0)

The dashboard and Windows sensor are separate processes. Running the dashboard does not install the sensor on a Windows host. Use this only on computers you own/administer or for which you have explicit authorization.

## Event coverage and overhead

- Security: 4624 (logon success), 4625 (failure), 4634/4647 (logoff), 4672 (special privilege), 4688 (process created; only image basename/PID collected, no command line), 4697 (service installed), 1102 (Security log cleared), 4720/4726 (user account create/delete), 4728/4732 (group membership).
- System: 7045 (service installed).
- Microsoft-Windows-Windows Defender/Operational: 1116 threat detection, 1117 action taken, 5007 configuration changed.
- Poll defaults to 10 seconds, constrained to 5–60 seconds; one query returns at most 250 matching events per channel; upload batches max 100.
- On first install, agent baselines each channel at the current latest record ID to avoid replaying a large backlog of old events. Only new events are collected afterward. If you need backfill, use a separate approved forensic export rather than changing this default silently.
- Local outbox stores SHA-256 hash-chain metadata and checks integrity at startup. A locally privileged attacker with write access to the whole database could still forge the whole chain; export/checkpoint it off-host for stronger assurance.

## Install files

Copy the project source to a protected path, e.g. `C:\Program Files\Kawal-Trace`. The package contains:

- `windows_agent/eventlog_agent.py`
- `windows_agent/run-agent.ps1`
- `windows_agent/agent.env.example`
- `windows_agent/requirements.txt`
- `chainlog/e2ee.py`

Using an independent agent venv avoids installing the dashboard GUI packages:

```powershell
py -3.13 -m venv 'C:\Program Files\Kawal-Trace\agent-venv'
& 'C:\Program Files\Kawal-Trace\agent-venv\Scripts\python.exe' -m pip install -r 'C:\Program Files\Kawal-Trace\windows_agent\requirements.txt'
```

Copy `windows_agent/agent.env.example` to `%ProgramData%\Kawal-Trace\agent.env` and fill in:

- `KAWAL_WIN_HOST_ID`: Host ID enrolled in the API.
- `KAWAL_API_BASE_URL`: HTTPS base URL of the Kawal-Trace API.
- `KAWAL_WIN_INGEST_TOKEN`: separate host-scoped ingest/action-poll token from server enrollment.
- `KAWAL_TRACE_E2EE_PUBLIC_KEY_B64`: public key from dashboard E2EE panel (public key may be shared; never put dashboard private key here).
- `KAWAL_WIN_RESPONSE_ENABLED=false`: leave this false until response has been reviewed in a staging environment.

Protect config and outbox. In elevated PowerShell:

```powershell
New-Item -ItemType Directory -Force "$env:ProgramData\Kawal-Trace" | Out-Null
# Copy/edit agent.env into the folder first, then lock ACL to SYSTEM and Administrators:
icacls "$env:ProgramData\Kawal-Trace" /inheritance:r
icacls "$env:ProgramData\Kawal-Trace" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
icacls "$env:ProgramData\Kawal-Trace\agent.env" /inheritance:r
icacls "$env:ProgramData\Kawal-Trace\agent.env" /grant:r "SYSTEM:R" "Administrators:F"
```

The PowerShell wrapper loads only `KAWAL_*` variables from the protected file, then starts the Python sensor. Configure a Task Scheduler task to run at startup as `SYSTEM` with highest privileges, using `powershell.exe` as the program and these arguments:

```text
-NoProfile -ExecutionPolicy RemoteSigned -File "C:\Program Files\Kawal-Trace\windows_agent\run-agent.ps1"
```

Set **Start in** to `C:\Program Files\Kawal-Trace`. The host requires rights to read the Security/System/Defender event channels. Because this task runs with high privilege, keep the installation directory non-writable by ordinary users and verify the source before enabling it. For read-only monitoring, leave `KAWAL_WIN_RESPONSE_ENABLED=false`; do not grant response capability unless needed.

## Two-factor response action controls

A response command is merely queued by the API. The endpoint checks again: local response flag, exact action/parameter allowlist, recent local event evidence, active RDP Session ID + username or live PID + process name + owner, protected user/process list, expiry, and TLS/authentication. It uses fixed calls (`New-NetFirewallRule`, `logoff.exe`, `taskkill.exe`) with `shell=False`; arbitrary command strings are never accepted.

- Windows Firewall block requires public IPv4 from a recent 4625 event on that same host; TTL is 300/900/1800 sec and the rule has an expiry record.
- RDP logoff requires a matching live session, non-current session, non-protected user, and recent remote-interactive login evidence.
- Process termination is limited to cmd.exe/powershell.exe/pwsh.exe/Windows Terminal names, with PID/name/owner checked live and local process-create evidence. Some existing shell processes cannot be targeted until a matching process event has been collected.
- To enable response requires **both** API `KAWAL_WINDOWS_RESPONSE_ENABLED=true` and endpoint `KAWAL_WIN_RESPONSE_ENABLED=true`, enrolled host token, response token, TOTP and typed confirmation. Keep both disabled unless staged tests and an explicit approval are completed.
- False positives can interrupt legitimate work. Maintain out-of-band console access and an allowlist for administrators. Firewall rules affect new inbound flows; they may not kill established TCP/RDP sessions. Cloudflare-proxied HTTP users need a separate WAF action, not a Windows Firewall rule against Cloudflare edge IPs.

## Test after configuration

1. Run the sensor manually from an elevated PowerShell once; confirm it prints a `local event chain verified` startup line.
2. Trigger one controlled failed login in a staging host using an IP in your approved scope; do not flood production.
3. Check `Get-WinEvent` / Windows Event Viewer for event 4625 and confirm a matching event appears in the Kawal-Trace feed.
4. Restart sensor; it should not replay the entire historic log.
5. Keep actions disabled until event fields, user identity and allowlists have been validated. Never test logoff or taskkill against your own admin session.
