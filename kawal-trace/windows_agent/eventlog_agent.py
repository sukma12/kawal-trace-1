"""Low-overhead Windows Event Log sensor for authorized Kawal-Trace hosts.

Reads a fixed allowlist of event IDs from Security/System/Defender logs, normalizes
minimal fields (never uploads arbitrary command lines), spools locally, and sends
E2EE envelopes to the API. Runs only when explicitly installed/configured by an
administrator. Requires permission to read the configured event logs.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

try:
    import httpx
except ImportError:
    httpx = None

try:
    from chainlog.e2ee import encrypt_payload, E2EEError
except ImportError:
    encrypt_payload = None
    class E2EEError(Exception):
        pass

HOST_ID = os.environ.get("KAWAL_WIN_HOST_ID", "").strip()
API_BASE_URL = os.environ.get("KAWAL_API_BASE_URL", "").strip().rstrip("/")
INGEST_TOKEN = os.environ.get("KAWAL_WIN_INGEST_TOKEN", "").strip()
E2EE_PUBLIC_KEY = os.environ.get("KAWAL_TRACE_E2EE_PUBLIC_KEY_B64", "").strip()
E2EE_REQUIRED = os.environ.get("KAWAL_TRACE_E2EE_REQUIRED", "true").strip().lower() == "true"
ALLOW_LEGACY_TLS = os.environ.get("KAWAL_TRACE_ALLOW_LEGACY_TLS", "false").strip().lower() == "true"
OUTBOX_DB = Path(os.environ.get("KAWAL_WIN_OUTBOX_DB", str(Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Kawal-Trace" / "outbox.sqlite3")))
POLL_SECONDS = max(5, min(60, int(os.environ.get("KAWAL_WIN_POLL_SECONDS", "10"))))
MAX_BATCH = 100
MAX_EVENT_WINDOW = 250
POWERSHELL = os.environ.get("KAWAL_WIN_POWERSHELL", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
SECURITY_IDS = (4624, 4625, 4634, 4647, 4672, 4688, 4697, 1102, 4720, 4726, 4728, 4732)
SYSTEM_IDS = (7045,)
DEFENDER_IDS = (1116, 1117, 5007)
XML_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class AgentError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def safe_text(value: Any, limit: int = 200) -> str:
    if value is None:
        return ""
    return "".join(ch for ch in str(value) if ch >= " " and ch != "\x7f")[:limit]


def stable_event_id(host_id: str, channel: str, record_id: int) -> str:
    return hashlib.sha256(f"{host_id}\n{channel}\n{int(record_id)}".encode("utf-8")).hexdigest()


def _event_data(root: ET.Element) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in root.findall(".//e:EventData/e:Data", XML_NS):
        name = node.attrib.get("Name") or f"field_{len(result)}"
        result[name] = safe_text(node.text or "", 512)
    # Some providers use UserData rather than EventData. Keep only scalar text.
    if not result:
        for node in root.findall(".//e:UserData//*", XML_NS):
            if len(node) == 0 and node.text:
                name = node.tag.rsplit("}", 1)[-1]
                result[name] = safe_text(node.text, 512)
    return result


def parse_windows_event_xml(xml_text: str, host_id: str) -> dict[str, Any] | None:
    """Normalize supported Windows Event IDs. Command line/credentials are not exported."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    system = root.find("e:System", XML_NS)
    if system is None:
        return None
    def child_text(path: str) -> str:
        node = system.find(path, XML_NS)
        return safe_text(node.text if node is not None else "", 256)
    try:
        event_id = int(child_text("e:EventID"))
        record_id = int(child_text("e:EventRecordID"))
    except (ValueError, TypeError):
        return None
    channel = child_text("e:Channel") or "Unknown"
    provider_node = system.find("e:Provider", XML_NS)
    provider = safe_text(provider_node.attrib.get("Name", "") if provider_node is not None else "", 128)
    time_node = system.find("e:TimeCreated", XML_NS)
    timestamp = safe_text(time_node.attrib.get("SystemTime", "") if time_node is not None else "", 64)
    if timestamp.endswith("Z"):
        pass
    elif timestamp:
        # Windows XML timestamps are normally UTC ISO-8601 with Z; fail safe if no zone.
        try:
            parsed = datetime.fromisoformat(timestamp)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            timestamp = parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            timestamp = utc_now()
    else:
        timestamp = utc_now()
    data = _event_data(root)
    source_ip = data.get("IpAddress", "")
    if source_ip in {"-", "::1", "127.0.0.1", "::", "0.0.0.0"}:
        source_ip = ""
    elif source_ip:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            source_ip = ""
    actor = data.get("TargetUserName") or data.get("SubjectUserName") or data.get("AccountName") or ""
    domain = data.get("TargetDomainName") or data.get("SubjectDomainName") or ""
    if actor and domain and domain not in {"-", "NT AUTHORITY"}:
        actor = f"{domain}\\{actor}"[:128]
    logon_type = data.get("LogonType", "")
    details: dict[str, Any] = {"windows_event_id": str(event_id), "log_name": channel, "provider": provider}
    event_type = "CUSTOM_SECURITY_EVENT"
    reason = "windows_event_observed"
    if event_id == 4624:
        event_type, reason = "AUTH_SUCCESS", "windows_logon_success"
        if logon_type:
            details["logon_type"] = logon_type
        if data.get("TargetUserName"):
            actor = f"{data.get('TargetDomainName','')}\\{data.get('TargetUserName','')}".strip("\\")[:128]
    elif event_id == 4625:
        event_type, reason = "AUTH_FAILURE", "windows_logon_failure"
        if logon_type:
            details["logon_type"] = logon_type
        if data.get("Status"):
            details["reason_code"] = data["Status"][:64]
    elif event_id in {4634, 4647}:
        reason = "windows_logoff"
    elif event_id == 4672:
        event_type, reason = "PRIVILEGE_USE", "special_privileges_assigned"
    elif event_id == 4688:
        reason = "windows_process_created"
        image = data.get("NewProcessName", "")
        details["image"] = image.rsplit("\\", 1)[-1][:128]
        details["process_id"] = data.get("NewProcessId", "")[:32]
        # Never include CommandLine, ParentCommandLine, or arbitrary argv.
    elif event_id in {4697, 7045}:
        event_type, reason = "SERVICE_CHANGE", "windows_service_installed"
        details["service"] = data.get("ServiceName", data.get("ServiceFileName", ""))[:128]
    elif event_id == 1102:
        reason = "windows_security_audit_log_cleared"
    elif event_id == 4720:
        reason = "windows_user_account_created"
        actor = data.get("TargetUserName") or actor
    elif event_id == 4726:
        reason = "windows_user_account_deleted"
        actor = data.get("TargetUserName") or actor
    elif event_id in {4728, 4732}:
        reason = "windows_account_added_to_privileged_group"
        details["target_user"] = data.get("MemberName", data.get("MemberSid", ""))[:128]
        details["group_name"] = data.get("TargetUserName", "")[:128]
    elif event_id == 1116:
        event_type, reason = "MALWARE_DETECTED", "windows_defender_malware_detected"
        details["signature_name"] = data.get("Threat Name", data.get("ThreatName", "Windows Defender detection"))[:128]
        details["path"] = data.get("Path", data.get("Resources", ""))[:256]
    elif event_id == 1117:
        reason = "windows_defender_action_taken"
        details["result"] = data.get("Action Name", data.get("ActionName", "action taken"))[:128]
    elif event_id == 5007:
        reason = "windows_defender_configuration_changed"
    details["reason"] = reason
    if data.get("LogonType") == "10":
        details["reason"] = f"{reason}; remote_interactive_rdp"
    return {
        "event_id": stable_event_id(host_id, channel, record_id),
        "timestamp_utc": timestamp,
        "host_id": safe_text(host_id, 128),
        "source": "windows-eventlog",
        "event_type": event_type,
        "actor": safe_text(actor, 128),
        "source_ip": source_ip,
        "details": details,
        "windows_record_id": record_id,
    }


class WindowsOutbox:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "nt":
                # Inherits the ACL of ProgramData\Kawal-Trace; docs require admins/SYSTEM only.
                pass
            else:
                self.path.parent.chmod(0o700)
        except OSError:
            pass
        with self.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS outbox(event_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS cursors(channel TEXT PRIMARY KEY, record_id INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS recent_events(event_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, timestamp_utc TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_recent_event_time ON recent_events(timestamp_utc);
                CREATE TABLE IF NOT EXISTS chain_entries(seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, payload_hash TEXT NOT NULL, previous_hash TEXT NOT NULL, record_hash TEXT NOT NULL, created_at_utc TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS active_firewall_rules(action_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, source_ip TEXT NOT NULL, expires_at REAL NOT NULL, status TEXT NOT NULL);
            """)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def cursor(self, channel: str) -> int:
        with self.connect() as conn:
            row = conn.execute("SELECT record_id FROM cursors WHERE channel=?", (channel,)).fetchone()
            return int(row["record_id"]) if row else 0

    def advance_cursor(self, channel: str, record_id: int) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO cursors(channel,record_id) VALUES(?,?) ON CONFLICT(channel) DO UPDATE SET record_id=MAX(record_id, excluded.record_id)", (channel, int(record_id)))

    @staticmethod
    def _canonical(event: dict[str, Any]) -> str:
        return json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def enqueue(self, event: dict[str, Any]) -> None:
        encoded = self._canonical(event)
        event_id = str(event.get("event_id", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", event_id):
            raise AgentError("outbox_event_id_must_be_sha256")
        payload_hash = self._digest(encoded)
        with self.connect() as conn:
            existing = conn.execute("SELECT payload_hash FROM chain_entries WHERE event_id=?", (event_id,)).fetchone()
            if existing:
                if existing["payload_hash"] != payload_hash:
                    raise AgentError("OUTBOX_INTEGRITY_ERROR: event id reused with different payload")
                # Already acknowledged events remain in chain history and are not requeued.
                conn.execute("INSERT OR IGNORE INTO recent_events(event_id,payload_json,timestamp_utc) VALUES(?,?,?)", (event_id, encoded, event.get("timestamp_utc", utc_now())))
                return
            last = conn.execute("SELECT record_hash FROM chain_entries ORDER BY seq DESC LIMIT 1").fetchone()
            previous_hash = last["record_hash"] if last else "0" * 64
            record_hash = self._digest(f"{event_id}\n{payload_hash}\n{previous_hash}")
            now = utc_now()
            conn.execute("INSERT INTO chain_entries(event_id,payload_hash,previous_hash,record_hash,created_at_utc) VALUES(?,?,?,?,?)", (event_id,payload_hash,previous_hash,record_hash,now))
            conn.execute("INSERT INTO outbox(event_id,payload_json,created_at) VALUES(?,?,?)", (event_id, encoded, time.time()))
            conn.execute("INSERT OR IGNORE INTO recent_events(event_id,payload_json,timestamp_utc) VALUES(?,?,?)", (event_id, encoded, event.get("timestamp_utc", now)))
            conn.execute("DELETE FROM recent_events WHERE timestamp_utc < ?", ((datetime.now(timezone.utc).timestamp() - 48 * 3600),))

    def verify_chain(self) -> tuple[bool, str, int]:
        with self.connect() as conn:
            entries = conn.execute("SELECT seq,event_id,payload_hash,previous_hash,record_hash FROM chain_entries ORDER BY seq").fetchall()
            pending = {row["event_id"]: row["payload_json"] for row in conn.execute("SELECT event_id,payload_json FROM outbox").fetchall()}
        previous = "0" * 64
        chain_ids: set[str] = set()
        for expected_seq, row in enumerate(entries, start=1):
            if row["seq"] != expected_seq or row["previous_hash"] != previous:
                return False, f"chain link/sequence mismatch at {row['event_id']}", len(entries)
            expected_hash = self._digest(f"{row['event_id']}\n{row['payload_hash']}\n{row['previous_hash']}")
            if row["record_hash"] != expected_hash:
                return False, f"chain hash mismatch at {row['event_id']}", len(entries)
            if row["event_id"] in pending and self._digest(pending[row["event_id"]]) != row["payload_hash"]:
                return False, f"pending payload changed at {row['event_id']}", len(entries)
            chain_ids.add(row["event_id"])
            previous = row["record_hash"]
        if set(pending) - chain_ids:
            return False, "pending event missing from chain", len(entries)
        return True, previous, len(entries)

    def batch(self, limit: int = MAX_BATCH) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT payload_json FROM outbox ORDER BY created_at LIMIT ?", (min(max(limit, 1), MAX_BATCH),)).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def acknowledge(self, event_ids: Iterable[str]) -> None:
        items = list(dict.fromkeys(str(x) for x in event_ids if x))
        if not items:
            return
        with self.connect() as conn:
            conn.executemany("DELETE FROM outbox WHERE event_id=?", [(item,) for item in items])

    def has_recent_evidence(self, event_type: str, *, source_ip: str = "", actor: str = "", reason: str = "", hours: int = 24) -> bool:
        cutoff = datetime.fromtimestamp(time.time() - hours * 3600, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with self.connect() as conn:
            rows = conn.execute("SELECT payload_json FROM recent_events WHERE timestamp_utc>=? ORDER BY timestamp_utc DESC LIMIT 2000", (cutoff,)).fetchall()
        for row in rows:
            try:
                event = json.loads(row["payload_json"])
                details = event.get("details") or {}
                if event.get("event_type") != event_type:
                    continue
                if source_ip and event.get("source_ip") != source_ip:
                    continue
                if actor and str(event.get("actor", "")).casefold() != actor.casefold():
                    continue
                if reason and not str(details.get("reason", "")).startswith(reason):
                    continue
                return True
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
        return False


POWERSHELL_SCRIPT = r'''
$ErrorActionPreference = 'SilentlyContinue'
$logs = @(
  @{ Name='Security'; Ids=@(4624,4625,4634,4647,4672,4688,4697,1102,4720,4726,4728,4732); CursorName='SECURITY' },
  @{ Name='System'; Ids=@(7045); CursorName='SYSTEM' },
  @{ Name='Microsoft-Windows-Windows Defender/Operational'; Ids=@(1116,1117,5007); CursorName='DEFENDER' }
)
$out = @()
foreach ($item in $logs) {
  $last = 0
  $cursorEnvName = "KAWAL_LAST_" + $item.CursorName
  $cursorValue = [System.Environment]::GetEnvironmentVariable($cursorEnvName)
  [void][int64]::TryParse([string]$cursorValue, [ref]$last)
  # On first install, baseline at the newest record to avoid replaying a large
  # historical Security log and generating a burst of stale alerts. Only new
  # records are collected after this baseline is persisted in the local outbox.
  if ($last -le 0) {
    try {
      $latest = Get-WinEvent -LogName $item.Name -MaxEvents 1 -ErrorAction Stop
      if ($null -ne $latest) {
        $out += [pscustomobject]@{ Channel=$item.Name; RecordId=[int64]$latest.RecordId; Baseline=$true }
      }
    } catch { }
    continue
  }
  $ids = ($item.Ids | ForEach-Object { "EventID=$($_)" }) -join ' or '
  $xpath = "*[System[(EventRecordID > $last) and ($ids)]]"
  try {
    $records = Get-WinEvent -LogName $item.Name -FilterXPath $xpath -MaxEvents 250 -Oldest -ErrorAction Stop
    foreach ($record in $records) {
      $out += [pscustomobject]@{ Channel=$item.Name; RecordId=[int64]$record.RecordId; Xml=$record.ToXml(); Baseline=$false }
    }
  } catch { }
}
if ($out.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject @($out) -Compress -Depth 4 }
'''


def collect_windows_events(host_id: str, outbox: WindowsOutbox, *, run_command=None) -> int:
    if os.name != "nt" and run_command is None:
        raise AgentError("Windows Event Log agent can only run on Windows; parser/outbox are testable cross-platform")
    runner = run_command or subprocess.run
    env = os.environ.copy()
    env["KAWAL_LAST_SECURITY"] = str(outbox.cursor("Security"))
    env["KAWAL_LAST_SYSTEM"] = str(outbox.cursor("System"))
    env["KAWAL_LAST_DEFENDER"] = str(outbox.cursor("Microsoft-Windows-Windows Defender/Operational"))
    proc = runner([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", POWERSHELL_SCRIPT],
                  env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", timeout=25, check=False, shell=False)
    if proc.returncode != 0:
        raise AgentError(f"PowerShell Event Log query failed with exit {proc.returncode}: {safe_text(proc.stderr, 180)}")
    raw = json.loads(proc.stdout.strip() or "[]")
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise AgentError("PowerShell output is not an event array")
    count = 0
    max_cursor: dict[str, int] = {}
    channel_cursor_key = {"Security": "Security", "System": "System", "Microsoft-Windows-Windows Defender/Operational": "Microsoft-Windows-Windows Defender/Operational"}
    for item in raw:
        if not isinstance(item, dict):
            continue
        channel = safe_text(item.get("Channel"), 160)
        try:
            record_id = int(item.get("RecordId", 0))
        except (TypeError, ValueError):
            continue
        if channel not in channel_cursor_key or record_id <= 0:
            continue
        max_cursor[channel] = max(max_cursor.get(channel, 0), record_id)
        if item.get("Baseline") is True:
            continue
        event = parse_windows_event_xml(str(item.get("Xml", "")), host_id)
        if event:
            event.pop("windows_record_id", None)  # keep record id only as local dedupe cursor
            outbox.enqueue(event)
            count += 1
    for channel, record_id in max_cursor.items():
        outbox.advance_cursor(channel, record_id)
    return count


def post_batch(outbox: WindowsOutbox, batch: list[dict[str, Any]], *, client_factory=None) -> int:
    if not batch:
        return 0
    if httpx is None and client_factory is None:
        raise AgentError("httpx is required to upload Windows telemetry")
    parsed = urlsplit(API_BASE_URL)
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise AgentError("Telemetry over Internet requires HTTPS")
    if not HOST_ID or len(INGEST_TOKEN) < 24 or not API_BASE_URL:
        raise AgentError("KAWAL_WIN_HOST_ID, KAWAL_API_BASE_URL and KAWAL_WIN_INGEST_TOKEN must be configured")
    ids = [str(item.get("event_id", "")) for item in batch]
    if any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in ids) or len(set(ids)) != len(ids):
        raise AgentError("invalid_or_duplicate_event_ids")
    idempotency_key = hashlib.sha256("\n".join(ids).encode("ascii")).hexdigest()
    headers = {"Authorization": f"Bearer {INGEST_TOKEN}", "X-KAWAL-Host-ID": HOST_ID, "Idempotency-Key": idempotency_key, "Accept": "application/json", "User-Agent": "Kawal-Trace-Windows-Agent/1.9.0"}
    if E2EE_PUBLIC_KEY:
        if encrypt_payload is None:
            raise AgentError("E2EE crypto package is unavailable; plaintext fallback is prohibited")
        envelopes = []
        for event in batch:
            metadata = {"event_id": event["event_id"], "host_id": event["host_id"], "timestamp_utc": event["timestamp_utc"], "stream": "security",
                        "event_type": str(event.get("event_type", "CUSTOM_SECURITY_EVENT")),
                        "source": str(event.get("source", "windows-eventlog")), "source_ip": str(event.get("source_ip", ""))}
            envelopes.append(encrypt_payload(E2EE_PUBLIC_KEY, event, metadata))
        endpoint = API_BASE_URL + "/api/v1/encrypted-security-events:batch"
        payload = {"host_id": HOST_ID, "events": envelopes}
    elif E2EE_REQUIRED or not ALLOW_LEGACY_TLS:
        raise AgentError("E2EE public key missing. Set KAWAL_TRACE_E2EE_PUBLIC_KEY_B64; plaintext fallback is disabled by default.")
    else:
        endpoint = API_BASE_URL + "/api/v1/security-events:batch"
        payload = {"host_id": HOST_ID, "events": batch}
    factory = client_factory or httpx.Client
    with factory(timeout=12.0, verify=True, follow_redirects=False, headers=headers) as client:
        response = client.post(endpoint, json=payload)
        if not 200 <= response.status_code < 300:
            raise AgentError(f"API rejected telemetry batch with HTTP {response.status_code}")
        body = response.json()
    accepted = body.get("accepted_event_ids", [])
    if not isinstance(accepted, list) or any(item not in {event["event_id"] for event in batch} for item in accepted):
        raise AgentError("API acknowledgment contains unknown event IDs")
    outbox.acknowledge(accepted)
    return len(accepted)


def validate_windows_action(action: dict[str, Any], *, protected_users: set[str], protected_processes: set[str]) -> tuple[str, dict[str, Any]]:
    """Validate parameters on the endpoint before any privileged command is invoked."""
    action_type = str(action.get("action", ""))
    params = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    if action_type == "WINDOWS_BLOCK_IP":
        try:
            ip = ipaddress.ip_address(str(params.get("source_ip", "")))
        except ValueError as exc:
            raise ValueError("invalid_source_ip") from exc
        if ip.version != 4 or not ip.is_global:
            raise ValueError("public_ipv4_required")
        ttl = int(action.get("ttl_seconds", 0))
        if ttl not in {300, 900, 1800}:
            raise ValueError("ttl_must_be_300_900_or_1800")
        return action_type, {"source_ip": str(ip), "ttl_seconds": ttl}
    if action_type == "WINDOWS_LOGOFF_SESSION":
        user = safe_text(params.get("target_user"), 128).strip()
        sid = int(params.get("session_id", 0))
        if sid <= 0 or not user:
            raise ValueError("session_and_user_required")
        if user.casefold() in {item.casefold() for item in protected_users}:
            raise ValueError("target_user_is_protected")
        return action_type, {"session_id": sid, "target_user": user}
    if action_type == "WINDOWS_TERMINATE_PROCESS":
        pid = int(params.get("pid", 0))
        user = safe_text(params.get("target_user"), 128).strip()
        process_name = safe_text(params.get("process_name"), 128).strip().lower()
        if pid <= 4 or not user or not process_name:
            raise ValueError("pid_user_process_required")
        if user.casefold() in {item.casefold() for item in protected_users}:
            raise ValueError("target_user_is_protected")
        approved_shells = {"cmd.exe", "powershell.exe", "pwsh.exe", "wt.exe", "windowsterminal.exe"}
        if process_name not in approved_shells or process_name in {item.casefold() for item in protected_processes}:
            raise ValueError("process_name_not_in_safe_allowlist")
        return action_type, {"pid": pid, "target_user": user, "process_name": process_name}
    raise ValueError("unsupported_windows_action")


def _ps_json(command: str, extra_env: dict[str, str] | None = None, timeout: int = 8) -> Any:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
                          env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False, shell=False)
    if proc.returncode != 0:
        raise AgentError(f"PowerShell action inspection failed: {safe_text(proc.stderr, 160)}")
    try:
        return json.loads(proc.stdout.strip() or "null")
    except json.JSONDecodeError as exc:
        raise AgentError("PowerShell action inspection returned invalid JSON") from exc


def _list_rdp_sessions() -> list[dict[str, Any]]:
    # Parse the standard English quser layout via headers; if locale/layout differs, fail closed.
    proc = subprocess.run(["quser.exe"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", timeout=8, check=False, shell=False)
    if proc.returncode not in {0, 1}:
        raise AgentError("Unable to query interactive sessions")
    lines = proc.stdout.splitlines()
    if not lines:
        return []
    header = lines[0]
    id_start = header.upper().find("ID")
    state_start = header.upper().find("STATE")
    if id_start < 0 or state_start < id_start:
        raise AgentError("quser format is not recognized on this locale; refusing session logoff")
    sessions: list[dict[str, Any]] = []
    for line in lines[1:]:
        clean = line.lstrip("> ")
        prefix = line.lstrip().startswith(">")
        left = clean[:id_start].strip().split()
        rest = clean[id_start:]
        tokens = rest.split()
        if not left or len(tokens) < 2:
            continue
        try:
            session_id = int(tokens[0])
        except ValueError:
            continue
        username = left[0]
        state = tokens[1]
        sessions.append({"session_id": session_id, "username": username, "state": state, "current_marker": prefix})
    return sessions


def _get_process_identity(pid: int) -> dict[str, str]:
    command = r"$p=Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $env:KAWAL_PID); if ($null -eq $p) { '{}' ; exit 0 }; $o=Invoke-CimMethod -InputObject $p -MethodName GetOwner; [pscustomobject]@{ Name=[IO.Path]::GetFileName([string]$p.ExecutablePath); User=[string]$o.User; Domain=[string]$o.Domain; PID=[string]$p.ProcessId } | ConvertTo-Json -Compress"
    data = _ps_json(command, {"KAWAL_PID": str(int(pid))})
    return data if isinstance(data, dict) else {}


def _firewall_block(ip: str, action_id: str, ttl_seconds: int, outbox: WindowsOutbox) -> None:
    display_name = "Kawal-Trace-" + hashlib.sha256(action_id.encode()).hexdigest()[:16]
    env = os.environ.copy(); env.update({"KAWAL_RULE_NAME": display_name, "KAWAL_SOURCE_IP": ip})
    command = r"New-NetFirewallRule -DisplayName $env:KAWAL_RULE_NAME -Direction Inbound -Action Block -RemoteAddress $env:KAWAL_SOURCE_IP -Profile Any -Enabled True -ErrorAction Stop | Select-Object -ExpandProperty DisplayName"
    proc = subprocess.run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", timeout=10, check=False, shell=False)
    if proc.returncode != 0 or display_name not in proc.stdout:
        raise AgentError("Windows Firewall did not confirm the exact temporary rule")
    with outbox.connect() as conn:
        conn.execute("INSERT OR REPLACE INTO active_firewall_rules(action_id,display_name,source_ip,expires_at,status) VALUES(?,?,?,?,?)", (action_id, display_name, ip, time.time() + ttl_seconds, "ACTIVE_TEMP_BLOCK"))


def _expire_firewall_rules(outbox: WindowsOutbox) -> int:
    with outbox.connect() as conn:
        rows = conn.execute("SELECT action_id,display_name FROM active_firewall_rules WHERE expires_at<=? AND status='ACTIVE_TEMP_BLOCK'", (time.time(),)).fetchall()
    count = 0
    for row in rows:
        display_name = str(row["display_name"])
        if not display_name.startswith("Kawal-Trace-"):
            continue
        env = os.environ.copy(); env["KAWAL_RULE_NAME"] = display_name
        command = r"$r=Get-NetFirewallRule -DisplayName $env:KAWAL_RULE_NAME -ErrorAction SilentlyContinue; if ($null -ne $r) { $r | Remove-NetFirewallRule -ErrorAction Stop }; 'OK'"
        proc = subprocess.run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", timeout=10, check=False, shell=False)
        with outbox.connect() as conn:
            conn.execute("UPDATE active_firewall_rules SET status=? WHERE action_id=?", ("EXPIRED" if proc.returncode == 0 and "OK" in proc.stdout else "EXPIRY_ERROR", str(row["action_id"])))
        count += 1
    return count


def execute_action(action: dict[str, Any], outbox: WindowsOutbox, *, enabled: bool, admin_allowlist: set[str], protected_processes: set[str]) -> tuple[str, str]:
    """Endpoint-side revalidation before doing one fixed, allowlisted action."""
    if not enabled:
        return "REJECTED_LOCAL_POLICY", "Windows response is disabled on this host"
    action_id = safe_text(action.get("action_id"), 64)
    if not action_id or not action_id.replace("-", "").isalnum():
        return "FAILED", "invalid action id"
    try:
        kind, params = validate_windows_action(action, protected_users=admin_allowlist, protected_processes=protected_processes)
        if kind == "WINDOWS_BLOCK_IP":
            ip = params["source_ip"]
            if not outbox.has_recent_evidence("AUTH_FAILURE", source_ip=ip, hours=24):
                raise ValueError("no recent local Windows auth-failure evidence for this IP")
            _firewall_block(ip, action_id, params["ttl_seconds"], outbox)
            return "SUCCEEDED", f"temporary firewall rule confirmed; expires in {params['ttl_seconds']} seconds"
        if kind == "WINDOWS_LOGOFF_SESSION":
            sessions = _list_rdp_sessions()
            match = next((s for s in sessions if s["session_id"] == params["session_id"] and s["username"].casefold() == params["target_user"].casefold()), None)
            if match is None:
                raise ValueError("active session ID and username do not match")
            if match.get("current_marker"):
                raise ValueError("refusing to log off a marked current session")
            if not outbox.has_recent_evidence("AUTH_SUCCESS", actor=params["target_user"], reason="windows_logon_success; remote_interactive_rdp", hours=24):
                raise ValueError("no recent remote-interactive RDP authentication evidence for target user")
            proc = subprocess.run(["logoff.exe", str(params["session_id"])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", timeout=10, check=False, shell=False)
            if proc.returncode != 0:
                raise AgentError("logoff.exe rejected the session ID")
            return "SUCCEEDED", f"interactive session {params['session_id']} for {params['target_user']} was logged off"
        if kind == "WINDOWS_TERMINATE_PROCESS":
            pid = params["pid"]
            if not outbox.has_recent_evidence("CUSTOM_SECURITY_EVENT", actor=params["target_user"], reason="windows_process_created", hours=24):
                raise ValueError("no recent process-creation evidence for target user")
            info = _get_process_identity(pid)
            if str(info.get("Name", "")).lower() != params["process_name"]:
                raise ValueError("live process name does not match confirmed target")
            live_user = "\\".join(part for part in (info.get("Domain", ""), info.get("User", "")) if part)
            if live_user.casefold() != params["target_user"].casefold():
                raise ValueError("live process owner does not match confirmed target user")
            proc = subprocess.run(["taskkill.exe", "/PID", str(pid), "/F"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", timeout=10, check=False, shell=False)
            if proc.returncode != 0:
                raise AgentError("taskkill rejected the PID")
            return "SUCCEEDED", f"process {params['process_name']} PID {pid} for {params['target_user']} was terminated"
        raise ValueError("unsupported action")
    except (ValueError, AgentError, OSError, subprocess.TimeoutExpired) as exc:
        return "REJECTED_LOCAL_POLICY", safe_text(str(exc), 220)


def _http_client():
    if httpx is None:
        raise AgentError("Install httpx in the Windows agent environment")
    return httpx.Client(timeout=httpx.Timeout(8, connect=3), verify=True, follow_redirects=False)


def poll_response_actions(outbox: WindowsOutbox, *, enabled: bool, admin_allowlist: set[str], protected_processes: set[str]) -> int:
    if not enabled:
        return 0
    if not API_BASE_URL or not HOST_ID or len(INGEST_TOKEN) < 24 or httpx is None:
        return 0
    headers = {"Authorization": f"Bearer {INGEST_TOKEN}", "X-KAWAL-Host-ID": HOST_ID, "Accept": "application/json"}
    base = API_BASE_URL.rstrip("/")
    with _http_client() as client:
        response = client.get(base + "/api/v1/windows/response-actions", headers=headers, params={"limit": 20})
        if response.status_code != 200:
            return 0
        body = response.json()
        actions = body.get("actions", []) if isinstance(body, dict) else []
        count = 0
        for action in actions[:20]:
            if not isinstance(action, dict) or action.get("status") != "PENDING":
                continue
            if float(action.get("expires_at_epoch", 0)) <= time.time():
                result_status, message = "EXPIRED", "action expired before endpoint execution"
            else:
                result_status, message = execute_action(action, outbox, enabled=enabled, admin_allowlist=admin_allowlist, protected_processes=protected_processes)
            result_path = base + "/api/v1/windows/response-actions/" + str(action.get("action_id", "")) + "/result"
            report = client.post(result_path, headers=headers, json={"status": result_status, "message": message[:220]})
            if report.status_code in {200, 202}:
                count += 1
        return count


def run_forever() -> None:
    if os.name != "nt":
        raise SystemExit("This agent runs on Windows only")
    if not HOST_ID or len(INGEST_TOKEN) < 24 or not API_BASE_URL:
        raise SystemExit("Configure KAWAL_WIN_HOST_ID, KAWAL_API_BASE_URL and KAWAL_WIN_INGEST_TOKEN before starting")
    if httpx is None:
        raise SystemExit("Install httpx before starting the agent")
    if E2EE_REQUIRED and not E2EE_PUBLIC_KEY:
        raise SystemExit("E2EE is required: configure KAWAL_TRACE_E2EE_PUBLIC_KEY_B64; no plaintext fallback")
    outbox = WindowsOutbox(OUTBOX_DB)
    chain_ok, chain_head, chain_count = outbox.verify_chain()
    if not chain_ok:
        raise SystemExit(f"LOCAL OUTBOX INTEGRITY FAILURE: {chain_head}. Preserve database for investigation; do not delete it.")
    print(f"[{utc_now()}] local event chain verified entries={chain_count} head={chain_head[:16]}", flush=True)
    protected_users = {x.strip() for x in os.environ.get("KAWAL_WIN_PROTECTED_USERS", "Administrator,SYSTEM,LOCAL SERVICE,NETWORK SERVICE").split(",") if x.strip()}
    protected_processes = {x.strip().lower() for x in os.environ.get("KAWAL_WIN_PROTECTED_PROCESSES", "lsass.exe,csrss.exe,winlogon.exe,services.exe,smss.exe,svchost.exe,system,explorer.exe,dwm.exe").split(",") if x.strip()}
    response_enabled = os.environ.get("KAWAL_WIN_RESPONSE_ENABLED", "false").lower() == "true"
    while True:
        started = time.monotonic()
        try:
            collect_windows_events(HOST_ID, outbox)
            _expire_firewall_rules(outbox)
            batch = outbox.batch()
            if batch:
                post_batch(outbox, batch)
            poll_response_actions(outbox, enabled=response_enabled, admin_allowlist=protected_users, protected_processes=protected_processes)
            # Low-volume heartbeat makes fleet status meaningful even on a quiet server.
            if int(time.time()) % 300 < POLL_SECONDS:
                heartbeat = {"event_id": stable_event_id(HOST_ID, "agent-health", str(int(time.time()) // 300)), "timestamp_utc": utc_now(), "host_id": HOST_ID, "source": "windows-agent", "event_type": "AGENT_HEALTH", "actor": "Kawal-Trace-Windows-Agent", "source_ip": "", "details": {"reason": "heartbeat", "result": "ok"}}
                outbox.enqueue(heartbeat)
        except Exception as exc:
            print(f"[{utc_now()}] agent cycle warning: {safe_text(str(exc), 220)}", file=sys.stderr, flush=True)
        elapsed = time.monotonic() - started
        time.sleep(max(1.0, POLL_SECONDS - elapsed))


if __name__ == "__main__":
    run_forever()
