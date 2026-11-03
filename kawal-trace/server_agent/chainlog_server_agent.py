#!/usr/bin/env python3
"""Defensive Linux telemetry collector for Kawal-Trace.

Reads new systemd journal SSH/sudo messages and optional Linux auditd events for
explicitly configured sensitive-path watch rules. It never executes commands from
log messages, never disables TLS validation, and keeps an SQLite outbox while
network/API delivery is unavailable.

Run as `python -m server_agent.chainlog_server_agent`. Configure via environment;
see docs/LINUX_SERVER_AGENT.md. This agent reports events; it does not block users.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import signal
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

HOST_ID = os.environ.get("KAWAL_TRACE_HOST_ID", "").strip()
INGEST_URL = os.environ.get("KAWAL_TRACE_INGEST_URL", "").strip()
API_TOKEN = os.environ.get("KAWAL_TRACE_API_TOKEN", "").strip()
OUTBOX_DB = Path(os.environ.get("KAWAL_TRACE_OUTBOX_DB", "/var/lib/kawal-trace-agent/outbox.sqlite3"))
AUDIT_LOG = os.environ.get("KAWAL_TRACE_AUDIT_LOG", "/var/log/audit/audit.log").strip()
CA_BUNDLE = os.environ.get("KAWAL_TRACE_CA_BUNDLE", "").strip()
GEOIP_CITY_DB = os.environ.get("KAWAL_TRACE_GEOIP_CITY_DB", "").strip()
GEOIP_ASN_DB = os.environ.get("KAWAL_TRACE_GEOIP_ASN_DB", "").strip()
WATCH_ROOTS = tuple(x.strip() for x in os.environ.get("KAWAL_TRACE_WATCH_ROOTS", "").split(",") if x.strip())
SCAN_ROOTS = tuple(x.strip() for x in os.environ.get("KAWAL_TRACE_CLAMSCAN_ROOTS", "").split(",") if x.strip())
CLAMSCAN_ENABLED = os.environ.get("KAWAL_TRACE_CLAMSCAN_ENABLED", "false").strip().lower() == "true"
CLAMSCAN_MAX_BYTES = 100 * 1024 * 1024
USER_AGENT = "Kawal-Trace-Linux-Agent/1.9.0"
E2EE_PUBLIC_KEY = os.environ.get("KAWAL_TRACE_E2EE_PUBLIC_KEY_B64", "").strip()
E2EE_REQUIRED = os.environ.get("KAWAL_TRACE_E2EE_REQUIRED", "true").strip().lower() == "true"
ALLOW_LEGACY_TLS = os.environ.get("KAWAL_TRACE_ALLOW_LEGACY_TLS", "false").strip().lower() == "true"
try:
    from chainlog.e2ee import encrypt_payload, E2EEError
except ImportError:
    encrypt_payload = None
    class E2EEError(Exception):
        pass
GEOIP_CITY_READER: Any | None = None
GEOIP_ASN_READER: Any | None = None
MAX_BATCH = 100
MAX_BODY_BYTES = 1_000_000
STOP = threading.Event()

AUTH_FAIL_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port ")
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port |$)")
AUTH_OK_RE = re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port ")
SUDO_RE = re.compile(r"sudo:\s*(?P<user>[A-Za-z0-9_.-]{1,64})\s*:.*?COMMAND=(?P<command>[^;\r\n]+)")
SUDO_SESSION_RE = re.compile(r"pam_unix\(sudo:session\): session opened for user (?P<user>\S+) by (?P<actor>[^ (]+)")
AUDIT_ID_RE = re.compile(r"msg=audit\((?P<epoch>[0-9]+(?:\.[0-9]+)?):(?P<serial>[0-9]+)\):")
AUDIT_KEY_RE = re.compile(r'\bkey=(?:"(?P<quoted>[^"]+)"|(?P<plain>[^\s]+))')
AUDIT_NAME_RE = re.compile(r'\bname="(?P<name>(?:\\.|[^"])*)"')
AUDIT_NAMETYPE_RE = re.compile(r"\bnametype=(?P<kind>CREATE|DELETE|NORMAL|PARENT)\b")
AUDIT_AUID_RE = re.compile(r"\bauid=(\d+)")
AUDIT_EUID_RE = re.compile(r"\beuid=(\d+)")
AUDIT_ADDR_RE = re.compile(r'\baddr="?([0-9a-fA-F:.]+)"?')
SENSITIVE_PREFIXES = (
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/ssh/",
    "/etc/sudoers", "/etc/sudoers.d/", "/etc/pam.d/", "/etc/systemd/system/",
    "/etc/nginx/", "/etc/apache2/", "/etc/audit/",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def safe_text(value: Any, limit: int = 256) -> str:
    if value is None:
        return ""
    text = str(value)
    return "".join(ch for ch in text if ch >= " " and ch != "\x7f")[:limit]


def stable_event_id(host_id: str, source: str, cursor: str) -> str:
    return hashlib.sha256(f"{host_id}\n{source}\n{cursor}".encode("utf-8")).hexdigest()


def _timestamp_from_journal(entry: dict[str, Any]) -> str:
    raw = entry.get("__REALTIME_TIMESTAMP")
    try:
        epoch = int(raw) / 1_000_000
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OSError, OverflowError):
        return utc_now()


def parse_journal_entry(entry: dict[str, Any], host_id: str) -> dict[str, Any] | None:
    """Convert a single journald JSON object into a normalized security event."""
    message = safe_text(entry.get("MESSAGE"), 2000)
    if not message:
        return None
    unit = safe_text(entry.get("_SYSTEMD_UNIT") or entry.get("SYSLOG_IDENTIFIER") or "systemd-journal", 120)
    lowered_unit = unit.lower()
    if not any(word in lowered_unit for word in ("ssh", "sudo", "su", "polkit", "audit")) and not any(
        phrase in message.lower() for phrase in ("failed password", "accepted password", "accepted publickey", "sudo:", "session opened for user")
    ):
        return None

    event_type = ""
    actor = ""
    source_ip = ""
    details: dict[str, str] = {"service": unit}
    match = AUTH_FAIL_RE.search(message)
    if match:
        event_type = "AUTH_FAILURE"
        actor = safe_text(match.group("user"), 128)
        source_ip = safe_text(match.group("ip"), 64)
        details.update({"auth_method": "ssh", "reason": "failed_password"})
    else:
        match = AUTH_OK_RE.search(message)
        if match:
            event_type = "AUTH_SUCCESS"
            actor = safe_text(match.group("user"), 128)
            source_ip = safe_text(match.group("ip"), 64)
            details.update({"auth_method": safe_text(match.group("method"), 64), "result": "accepted"})
        else:
            match = INVALID_USER_RE.search(message)
            if match:
                # Kept as a visible signal but not counted as an auth failure, avoiding
                # double-counting when sshd writes both Invalid user and Failed password.
                event_type = "CUSTOM_SECURITY_EVENT"
                actor = safe_text(match.group("user"), 128)
                source_ip = safe_text(match.group("ip"), 64)
                details.update({"reason": "invalid_ssh_username_observed"})
            else:
                match = SUDO_RE.search(message)
                if match:
                    event_type = "PRIVILEGE_USE"
                    actor = safe_text(match.group("user"), 128)
                    command = safe_text(match.group("command").strip(), 512)
                    # Never send arbitrary argv: it may contain secrets. Record executable name only.
                    command = command.split()[0] if command else "unknown"
                    details.update({"reason": "sudo_command_observed", "command_basename": Path(command).name[:128]})
                else:
                    match = SUDO_SESSION_RE.search(message)
                    if match:
                        event_type = "PRIVILEGE_USE"
                        actor = safe_text(match.group("actor"), 128)
                        details.update({"reason": "sudo_session_opened", "uid": safe_text(match.group("user"), 32)})
    if not event_type:
        return None
    if source_ip:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            source_ip = ""

    cursor = safe_text(entry.get("__CURSOR"), 512)
    if not cursor:
        cursor = f"{entry.get('__REALTIME_TIMESTAMP','')}-{unit}-{message[:128]}"
    event = {
        "event_id": stable_event_id(host_id, "linux-journal", cursor),
        "timestamp_utc": _timestamp_from_journal(entry),
        "host_id": safe_text(host_id, 128),
        "source": "linux-journal",
        "event_type": event_type,
        "actor": actor,
        "source_ip": source_ip,
        "details": details,
    }
    return event


def _path_under_roots(candidate: str, roots: Iterable[str]) -> bool:
    """Check a canonical path against explicitly configured roots; reject path escape."""
    try:
        resolved = Path(candidate).resolve(strict=False)
        for root_text in roots:
            root = Path(root_text)
            if not root.is_absolute():
                continue
            resolved_root = root.resolve(strict=False)
            try:
                resolved.relative_to(resolved_root)
                return True
            except ValueError:
                continue
    except (OSError, RuntimeError):
        return False
    return False


def _audit_path_allowed(candidate: str, rule_key: str) -> bool:
    if not candidate.startswith("/") or "\x00" in candidate or ".." in candidate.split("/"):
        return False
    if rule_key == "kawal_trace_sensitive":
        return any(candidate == p.rstrip("/") or candidate.startswith(p) for p in SENSITIVE_PREFIXES)
    if rule_key == "kawal_trace_webroot":
        return _path_under_roots(candidate, WATCH_ROOTS)
    if rule_key == "kawal_trace_tempdir":
        return any(candidate == root.rstrip("/") or candidate.startswith(root.rstrip("/") + "/") for root in ("/tmp", "/var/tmp", "/dev/shm"))
    return False


def parse_audit_group(lines: Iterable[str], host_id: str) -> dict[str, Any] | None:
    """Recognize only configured auditd keys and paths; custom roots must be explicit."""
    material = list(lines)
    if not material:
        return None
    joined = "\n".join(material)
    ids = [AUDIT_ID_RE.search(line) for line in material]
    match_id = next((m for m in ids if m), None)
    if match_id is None:
        return None
    matched_keys: set[str] = set()
    candidate_paths: list[str] = []
    name_types: set[str] = set()
    allowed_keys = {"kawal_trace_sensitive", "kawal_trace_webroot", "kawal_trace_tempdir"}
    for line in material:
        for key_match in AUDIT_KEY_RE.finditer(line):
            key = key_match.group("quoted") or key_match.group("plain") or ""
            if key in allowed_keys:
                matched_keys.add(key)
        path_match = AUDIT_NAME_RE.search(line)
        if path_match:
            candidate = path_match.group("name").replace('\\"', '"')
            candidate_paths.append(candidate)
        name_type_match = AUDIT_NAMETYPE_RE.search(line)
        if name_type_match:
            name_types.add(name_type_match.group("kind"))
    selected: tuple[str, str] | None = None
    # Prefer sensitive paths, then explicitly configured web root, then configured temp dirs.
    key_priority = ("kawal_trace_sensitive", "kawal_trace_webroot", "kawal_trace_tempdir")
    for rule_key in key_priority:
        if rule_key not in matched_keys:
            continue
        for candidate in candidate_paths:
            if _audit_path_allowed(candidate, rule_key):
                selected = (candidate[:512], rule_key)
                break
        if selected:
            break
    if not selected or "success=yes" not in joined:
        return None
    path, rule_key = selected
    timestamp = utc_now()
    try:
        timestamp = datetime.fromtimestamp(float(match_id.group("epoch")), tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, OSError, OverflowError):
        pass
    auid = AUDIT_AUID_RE.search(joined)
    euid = AUDIT_EUID_RE.search(joined)
    address = AUDIT_ADDR_RE.search(joined)
    actor_id = auid.group(1) if auid else (euid.group(1) if euid else "unknown")
    source_ip = address.group(1) if address else ""
    if source_ip:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            source_ip = ""
    serial = match_id.group("serial")
    event_id = stable_event_id(host_id, "linux-auditd", f"{match_id.group('epoch')}:{serial}")
    # auditd PATH records distinguish a newly created destination, a removed
    # source, and an ordinary write. A pair of CREATE + DELETE entries is the
    # common shape of a rename/move. A copied file appears as CREATE at its target.
    if "CREATE" in name_types and "DELETE" in name_types:
        operation = "file_renamed"
    elif "DELETE" in name_types:
        operation = "file_deleted"
    elif "CREATE" in name_types:
        operation = "file_created"
    else:
        operation = "file_modified"
    return {
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "host_id": safe_text(host_id, 128),
        "source": "linux-auditd",
        "event_type": "FILE_CHANGE",
        "actor": f"uid:{actor_id}",
        "source_ip": source_ip,
        "details": {"path": path, "rule_key": rule_key, "reason": operation, "result": "success"},
    }


def build_filesystem_watch_health_event(
    host_id: str,
    *,
    roots: Iterable[str],
    audit_log_readable: bool,
    auditd_active: bool,
    active_rules_text: str | None,
    watch_roots_exist: bool = True,
    now_epoch: float | None = None,
) -> dict[str, Any]:
    """Build a bounded heartbeat describing the remote filesystem-watch readiness."""
    safe_roots = [
        safe_text(root, 240).strip() for root in roots
        if isinstance(root, str) and root.startswith("/") and root.rstrip("/") not in {"", "/"}
    ]
    if not safe_roots:
        reason = "WATCH_ROOTS_NOT_CONFIGURED"
    elif not watch_roots_exist:
        reason = "WATCH_ROOT_MISSING"
    elif not audit_log_readable:
        reason = "AUDIT_LOG_UNAVAILABLE"
    elif not auditd_active:
        reason = "AUDITD_INACTIVE"
    elif active_rules_text is None:
        reason = "AUDIT_RULE_STATUS_UNVERIFIED"
    else:
        rules = str(active_rules_text)
        matching_roots = [root for root in safe_roots if root in rules]
        if "kawal_trace_webroot" not in rules or len(matching_roots) != len(safe_roots):
            reason = "AUDIT_RULE_NOT_ACTIVE"
        else:
            reason = "READY"
    bucket = int((now_epoch if now_epoch is not None else time.time()) // 60)
    root_summary = "; ".join(safe_roots)[:240]
    return {
        "event_id": stable_event_id(host_id, "linux-agent-filesystem-watch", str(bucket)),
        "timestamp_utc": utc_now(),
        "host_id": safe_text(host_id, 128),
        "source": "linux-agent",
        "event_type": "AGENT_HEALTH",
        "actor": "system",
        "source_ip": "",
        "details": {
            "service": "filesystem-watch",
            "reason": reason,
            "result": "READY" if reason == "READY" else "WAITING",
            "path": root_summary,
        },
    }


def filesystem_watch_worker(outbox: "Outbox") -> None:
    """Publish a one-minute readiness heartbeat; never changes server audit settings."""
    while not STOP.is_set():
        roots = [root for root in WATCH_ROOTS if root.startswith("/") and root.rstrip("/") not in {"", "/"}]
        roots_exist = bool(roots) and all(Path(root).is_dir() for root in roots)
        audit_log_readable = bool(AUDIT_LOG and Path(AUDIT_LOG).is_file() and os.access(AUDIT_LOG, os.R_OK))
        auditd_active = False
        active_rules_text: str | None = None
        try:
            service = subprocess.run(
                ["systemctl", "is-active", "auditd"], capture_output=True, text=True,
                timeout=3, check=False,
            )
            auditd_active = service.returncode == 0 and service.stdout.strip() == "active"
        except (OSError, subprocess.SubprocessError):
            auditd_active = False
        try:
            rules = subprocess.run(
                ["auditctl", "-l"], capture_output=True, text=True,
                timeout=3, check=False,
            )
            if rules.returncode == 0:
                active_rules_text = rules.stdout
        except (OSError, subprocess.SubprocessError):
            active_rules_text = None
        try:
            outbox.enqueue(build_filesystem_watch_health_event(
                HOST_ID, roots=roots, audit_log_readable=audit_log_readable,
                auditd_active=auditd_active, active_rules_text=active_rules_text,
                watch_roots_exist=roots_exist,
            ))
        except Exception as exc:
            print(f"[chainlog-agent] filesystem-watch heartbeat failed: {safe_text(exc, 100)}", file=sys.stderr, flush=True)
        STOP.wait(60)


def scan_changed_file(event: dict[str, Any]) -> dict[str, Any] | None:
    """Optional ClamAV signature scan of a file-change event inside explicit scan roots."""
    if not CLAMSCAN_ENABLED or not SCAN_ROOTS or event.get("event_type") != "FILE_CHANGE":
        return None
    raw_path = str((event.get("details") or {}).get("path", ""))
    try:
        file_path = Path(raw_path)
        if not file_path.is_absolute() or file_path.is_symlink():
            return None
        resolved = file_path.resolve(strict=True)
        if not _path_under_roots(str(resolved), SCAN_ROOTS) or not resolved.is_file():
            return None
        if resolved.stat().st_size > CLAMSCAN_MAX_BYTES:
            return None
        proc = subprocess.run(
            ["clamscan", "--no-summary", "--infected", "--max-filesize=100M", "--max-scansize=150M", str(resolved)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
            timeout=25, check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError, RuntimeError):
        return None
    if proc.returncode != 1:
        return None
    signature = "signature_match"
    for line in proc.stdout.splitlines():
        match = re.search(r":\s*(.{1,128}?)\s+FOUND$", line)
        if match:
            signature = safe_text(match.group(1), 128)
            break
    base_event_id = str(event.get("event_id", ""))
    return {
        "event_id": stable_event_id(str(event.get("host_id", "unknown")), "clamav", base_event_id),
        "timestamp_utc": utc_now(),
        "host_id": safe_text(event.get("host_id"), 128),
        "source": "clamav-signature-scan",
        "event_type": "MALWARE_DETECTED",
        "actor": safe_text(event.get("actor"), 128),
        "source_ip": safe_text(event.get("source_ip"), 64),
        "details": {"path": str(resolved)[:256], "rule_key": "clamav_signature_match",
                    "reason": "clamav_signature_match", "result": signature, "signature_name": signature},
    }


def enqueue_audit_event(outbox: "Outbox", event: dict[str, Any]) -> None:
    outbox.enqueue(event)
    malware_event = scan_changed_file(event)
    if malware_event:
        outbox.enqueue(malware_event)


def configure_geoip_readers() -> str:
    """Load optional local MaxMind MMDB readers. No external IP lookup is performed."""
    global GEOIP_CITY_READER, GEOIP_ASN_READER
    if not GEOIP_CITY_DB and not GEOIP_ASN_DB:
        return "GeoIP disabled (local DB paths not configured)"
    try:
        import geoip2.database  # optional extra; only required when local GeoIP is configured
    except ImportError:
        return "GeoIP disabled (install server_agent/requirements-geoip.txt)"
    status: list[str] = []
    if GEOIP_CITY_DB:
        if Path(GEOIP_CITY_DB).is_file():
            try:
                GEOIP_CITY_READER = geoip2.database.Reader(GEOIP_CITY_DB)
                status.append("city DB loaded")
            except Exception:
                status.append("city DB invalid; disabled")
        else:
            status.append("city DB not found; disabled")
    if GEOIP_ASN_DB:
        if Path(GEOIP_ASN_DB).is_file():
            try:
                GEOIP_ASN_READER = geoip2.database.Reader(GEOIP_ASN_DB)
                status.append("ASN DB loaded")
            except Exception:
                status.append("ASN DB invalid; disabled")
        else:
            status.append("ASN DB not found; disabled")
    return "GeoIP " + "; ".join(status or ["disabled"])


def enrich_event_geoip(
    event: dict[str, Any], city_reader: Any | None = None, asn_reader: Any | None = None,
) -> dict[str, Any]:
    """Add approximate location for a globally routable source IP using local MMDB data."""
    ip_text = safe_text(event.get("source_ip"), 64)
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError:
        return event
    # Avoid misleading lookups for private, reserved, loopback, or documentation IPs.
    if not address.is_global:
        return event
    if city_reader is not None and not event.get("source_city") and not event.get("source_country"):
        try:
            city = city_reader.city(ip_text)
            country = getattr(getattr(city, "country", None), "name", None)
            region_obj = getattr(getattr(city, "subdivisions", None), "most_specific", None)
            region = getattr(region_obj, "name", None)
            city_name = getattr(getattr(city, "city", None), "name", None)
            location = getattr(city, "location", None)
            radius = getattr(location, "accuracy_radius", None)
            latitude = getattr(location, "latitude", None)
            longitude = getattr(location, "longitude", None)
            if isinstance(latitude, (int, float)) and isinstance(longitude, (int, float)) and -90 <= latitude <= 90 and -180 <= longitude <= 180:
                # Approximate IP centroid only. Never interpret as a person's exact location.
                event["source_latitude"] = round(float(latitude), 5)
                event["source_longitude"] = round(float(longitude), 5)
            if country:
                event["source_country"] = safe_text(country, 64)
            if region:
                event["source_region"] = safe_text(region, 100)
            if city_name:
                event["source_city"] = safe_text(city_name, 100)
            if country or region or city_name:
                event["source_geo_source"] = "GeoLite2 local MMDB"
                event["source_geo_accuracy"] = f"approximate; radius {int(radius)} km" if isinstance(radius, (int, float)) and radius >= 0 else "approximate"
        except Exception:
            # Missing entries are normal; don't cause event collection to stop.
            pass
    if asn_reader is not None and not event.get("source_asn"):
        try:
            asn = asn_reader.asn(ip_text)
            number = getattr(asn, "autonomous_system_number", None)
            org = getattr(asn, "autonomous_system_organization", None)
            if number is not None:
                event["source_asn"] = f"AS{int(number)}"[:100]
            if org:
                event["source_org"] = safe_text(org, 180)
        except Exception:
            pass
    return event


class Outbox:
    """Durable local queue with an append-only SHA-256 metadata chain.

    The chain detects accidental/tampering changes to the outbox and its own
    linked records. For stronger evidence, checkpoints must also be exported to
    a separate trusted system; a root attacker can rewrite a local database.
    """
    GENESIS = "0" * 64

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS outbox (
                event_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL,
                created_at_utc TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT ''
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS chain_entries (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                payload_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            )""")
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _canonical(event: dict[str, Any]) -> str:
        return json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)

    @staticmethod
    def _digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def enqueue(self, event: dict[str, Any]) -> None:
        event = dict(event)
        enrich_event_geoip(event, GEOIP_CITY_READER, GEOIP_ASN_READER)
        encoded = self._canonical(event)
        event_id = str(event.get("event_id", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", event_id):
            raise ValueError("outbox_event_id_must_be_sha256")
        payload_hash = self._digest(encoded)
        with self._lock, self._connect() as conn:
            existing = conn.execute("SELECT payload_hash FROM chain_entries WHERE event_id=?", (event_id,)).fetchone()
            if existing:
                if existing[0] != payload_hash:
                    raise RuntimeError("OUTBOX_INTEGRITY_ERROR: event id reused with different payload")
                # Do not queue an already acknowledged event a second time.
                return
            last = conn.execute("SELECT record_hash FROM chain_entries ORDER BY seq DESC LIMIT 1").fetchone()
            previous = last[0] if last else self.GENESIS
            record_hash = self._digest(f"{event_id}\n{payload_hash}\n{previous}")
            created = utc_now()
            conn.execute("INSERT INTO chain_entries(event_id,payload_hash,previous_hash,record_hash,created_at_utc) VALUES(?,?,?,?,?)",
                         (event_id, payload_hash, previous, record_hash, created))
            conn.execute("INSERT INTO outbox(event_id,payload_json,created_at_utc) VALUES(?,?,?)",
                         (event_id, encoded, created))

    def verify_chain(self) -> tuple[bool, str, int]:
        """Verify the persistent chain and any pending payloads; O(n), run on start/manual check."""
        with self._connect() as conn:
            entries = conn.execute("SELECT seq,event_id,payload_hash,previous_hash,record_hash FROM chain_entries ORDER BY seq").fetchall()
            pending = {row[0]: row[1] for row in conn.execute("SELECT event_id,payload_json FROM outbox").fetchall()}
        previous = self.GENESIS
        for expected_seq, row in enumerate(entries, start=1):
            seq, event_id, payload_hash, previous_hash, record_hash = row
            if seq != expected_seq or previous_hash != previous:
                return False, f"chain link/sequence mismatch at {event_id}", len(entries)
            expected_hash = self._digest(f"{event_id}\n{payload_hash}\n{previous_hash}")
            if record_hash != expected_hash:
                return False, f"chain hash mismatch at {event_id}", len(entries)
            if event_id in pending and self._digest(pending[event_id]) != payload_hash:
                return False, f"pending payload changed at {event_id}", len(entries)
            previous = record_hash
        if set(pending) - {row[1] for row in entries}:
            return False, "pending event missing from chain", len(entries)
        return True, previous, len(entries)

    def batch(self, limit: int = MAX_BATCH) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload_json FROM outbox ORDER BY created_at_utc LIMIT ?", (min(max(int(limit), 1), MAX_BATCH),)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def acknowledge(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        with self._lock, self._connect() as conn:
            conn.executemany("DELETE FROM outbox WHERE event_id=?", [(event_id,) for event_id in event_ids])

    def mark_failed(self, event_ids: list[str], error: str) -> None:
        safe_error = safe_text(error, 100)
        with self._lock, self._connect() as conn:
            conn.executemany("UPDATE outbox SET attempts=attempts+1,last_error=? WHERE event_id=?",
                             [(safe_error, event_id) for event_id in event_ids])

    def count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0])


def validate_agent_config() -> None:
    if not HOST_ID or len(HOST_ID) > 128 or any(ch.isspace() for ch in HOST_ID):
        raise SystemExit("KAWAL_TRACE_HOST_ID wajib diisi (maks 128 karakter tanpa spasi).")
    if len(API_TOKEN) < 24 or any(ch.isspace() for ch in API_TOKEN):
        raise SystemExit("KAWAL_TRACE_API_TOKEN wajib diisi dengan token perangkat unik (minimal 24 karakter).")
    parsed = urlsplit(INGEST_URL)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("KAWAL_TRACE_INGEST_URL harus berupa URL endpoint yang valid tanpa kredensial/query.")
    if parsed.scheme != "https" and parsed.hostname.lower() not in {"localhost", "127.0.0.1", "::1", "[::1]"}:
        raise SystemExit("HTTPS wajib untuk endpoint di internet. HTTP hanya diizinkan untuk loopback saat uji lokal.")
    if CA_BUNDLE and not Path(CA_BUNDLE).is_file():
        raise SystemExit("KAWAL_TRACE_CA_BUNDLE tidak ditemukan.")
    if E2EE_REQUIRED and parsed.scheme == "https" and not E2EE_PUBLIC_KEY:
        raise SystemExit("E2EE diwajibkan untuk internet: isi KAWAL_TRACE_E2EE_PUBLIC_KEY_B64; plaintext fallback tidak diizinkan.")


def post_batch(outbox: Outbox, batch: list[dict[str, Any]]) -> tuple[list[str], str]:
    if not batch:
        return [], "empty"
    if not HOST_ID or len(API_TOKEN) < 24 or not INGEST_URL:
        raise RuntimeError("agent_config_incomplete")
    parsed_url = urlsplit(INGEST_URL)
    if parsed_url.scheme != "https" and (parsed_url.hostname or "").lower() not in {"localhost", "127.0.0.1", "::1", "[::1]"}:
        raise RuntimeError("https_required_for_remote_ingest")
    ids = [str(e.get("event_id", "")) for e in batch]
    if any(not re.fullmatch(r"[0-9a-f]{64}", event_id) for event_id in ids) or len(set(ids)) != len(ids):
        raise RuntimeError("invalid_or_duplicate_event_ids")
    idem = hashlib.sha256("\n".join(ids).encode("ascii")).hexdigest()
    headers = {
        "Authorization": f"Bearer {API_TOKEN}", "X-KAWAL-Host-ID": HOST_ID,
        "Idempotency-Key": idem, "User-Agent": USER_AGENT,
        "Content-Type": "application/json", "Accept": "application/json",
    }
    if E2EE_PUBLIC_KEY:
        if encrypt_payload is None:
            raise RuntimeError("e2ee_crypto_unavailable_plaintext_fallback_prohibited")
        envelopes = []
        for event in batch:
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            metadata = {
                "event_id": event["event_id"], "host_id": HOST_ID,
                "timestamp_utc": str(event["timestamp_utc"]), "stream": "security",
                "event_type": str(event.get("event_type", "CUSTOM_SECURITY_EVENT")),
                "source": str(event.get("source", "linux-agent")),
                "source_ip": str(event.get("source_ip", "")),
                "auth_method": str(details.get("auth_method", "")),
                "log_name": str(details.get("service", "")),
            }
            envelopes.append(encrypt_payload(E2EE_PUBLIC_KEY, event, metadata))
        body_obj = {"schema_version": 1, "host_id": HOST_ID, "sent_at_utc": utc_now(), "events": envelopes}
        endpoint_path = "/api/v1/encrypted-security-events:batch"
    else:
        remote = (parsed_url.scheme == "https" and (parsed_url.hostname or "").lower() not in {"localhost", "127.0.0.1", "::1", "[::1]"})
        if remote and (E2EE_REQUIRED or not ALLOW_LEGACY_TLS):
            raise RuntimeError("e2ee_public_key_missing_plaintext_fallback_prohibited")
        body_obj = {"schema_version": 1, "host_id": HOST_ID, "sent_at_utc": utc_now(), "events": batch}
        endpoint_path = "/api/v1/security-events:batch"
    body = json.dumps(body_obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("batch_too_large")
    # Keep the host/path configuration but switch only the route to the API mode selected above.
    final_url = INGEST_URL
    if parsed_url.path.endswith("/api/v1/security-events:batch") or parsed_url.path.endswith("/api/v1/encrypted-security-events:batch"):
        final_url = parsed_url._replace(path=endpoint_path, query="", fragment="").geturl()
    elif parsed_url.path in {"", "/"}:
        final_url = parsed_url._replace(path=endpoint_path, query="", fragment="").geturl()
    else:
        raise RuntimeError("ingest_url_must_be_api_base_or_security_batch_endpoint")
    request = urllib.request.Request(final_url, data=body, method="POST", headers=headers)
    context = ssl.create_default_context(cafile=CA_BUNDLE or None)
    try:
        with urllib.request.urlopen(request, timeout=12, context=context) as response:
            status = response.status
            response_bytes = response.read(500_001)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"http_{exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"transport_{type(exc).__name__}") from None
    if not 200 <= status < 300:
        raise RuntimeError(f"http_{status}")
    if len(response_bytes) > 500_000:
        raise RuntimeError("response_too_large")
    try:
        parsed = json.loads(response_bytes)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("response_not_json") from None
    accepted = parsed.get("accepted_event_ids") if isinstance(parsed, dict) else None
    if not isinstance(accepted, list):
        raise RuntimeError("response_missing_accepted_event_ids")
    accepted_set = {x for x in accepted if isinstance(x, str)}
    acknowledged = [event_id for event_id in ids if event_id in accepted_set]
    outbox.acknowledge(acknowledged)
    missing = len(ids) - len(acknowledged)
    if missing:
        outbox.mark_failed([event_id for event_id in ids if event_id not in accepted_set], "partial_ack")
    if not acknowledged:
        raise RuntimeError("no_events_acknowledged")
    return acknowledged, f"ack={len(acknowledged)} pending={outbox.count()}"


def network_worker(outbox: Outbox) -> None:
    failures = 0
    while not STOP.is_set():
        batch = outbox.batch()
        if not batch:
            STOP.wait(1)
            continue
        ids = [e["event_id"] for e in batch]
        try:
            _acknowledged, message = post_batch(outbox, batch)
            failures = 0
            print(f"[chainlog-agent] batch {message}", flush=True)
            # If API returned a partial ack, short wait then retry remaining entries.
            STOP.wait(0.5 if outbox.count() else 1)
        except Exception as exc:  # keep collecting locally when remote API is unavailable
            failures += 1
            outbox.mark_failed(ids, str(exc))
            delay = min(60, 2 ** min(failures, 6))
            print(f"[chainlog-agent] delivery pending ({safe_text(exc, 100)}); outbox={outbox.count()}; retry in {delay}s", file=sys.stderr, flush=True)
            STOP.wait(delay)


def journal_worker(outbox: Outbox) -> None:
    while not STOP.is_set():
        try:
            process = subprocess.Popen(
                ["journalctl", "--follow", "--output=json", "--no-pager", "--lines=0"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
        except OSError as exc:
            print(f"[chainlog-agent] journalctl unavailable: {type(exc).__name__}; retrying", file=sys.stderr, flush=True)
            STOP.wait(10)
            continue
        assert process.stdout is not None
        try:
            for line in process.stdout:
                if STOP.is_set():
                    break
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(raw, dict):
                    continue
                event = parse_journal_entry(raw, HOST_ID)
                if event:
                    outbox.enqueue(event)
        finally:
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        STOP.wait(2)


def audit_worker(outbox: Outbox) -> None:
    """Follow optional auditd file with `tail -F`, grouping records by audit serial."""
    if not AUDIT_LOG:
        return
    if not Path(AUDIT_LOG).exists():
        print(f"[chainlog-agent] audit log unavailable; file-change watch disabled: {AUDIT_LOG}", file=sys.stderr, flush=True)
        return
    while not STOP.is_set():
        try:
            process = subprocess.Popen(
                ["tail", "-n", "0", "-F", "--", AUDIT_LOG], stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
        except OSError as exc:
            print(f"[chainlog-agent] audit tail unavailable: {type(exc).__name__}; file-change watch disabled", file=sys.stderr, flush=True)
            return
        assert process.stdout is not None
        current_serial: str | None = None
        group: list[str] = []
        try:
            for line in process.stdout:
                if STOP.is_set():
                    break
                match = AUDIT_ID_RE.search(line)
                serial = f"{match.group('epoch')}:{match.group('serial')}" if match else None
                if serial and current_serial and serial != current_serial:
                    event = parse_audit_group(group, HOST_ID)
                    if event:
                        enqueue_audit_event(outbox, event)
                    group = []
                if serial:
                    current_serial = serial
                if current_serial:
                    group.append(line.rstrip("\n"))
                    if "type=EOE" in line:
                        event = parse_audit_group(group, HOST_ID)
                        if event:
                            enqueue_audit_event(outbox, event)
                        group = []
                        current_serial = None
        finally:
            # Flush the last complete-ish event on orderly shutdown.
            event = parse_audit_group(group, HOST_ID)
            if event:
                enqueue_audit_event(outbox, event)
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        STOP.wait(2)


def _handle_stop(_signum, _frame) -> None:
    STOP.set()


def main() -> int:
    validate_agent_config()
    geoip_status = configure_geoip_readers()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _handle_stop)
    outbox = Outbox(OUTBOX_DB)
    chain_ok, chain_head, chain_count = outbox.verify_chain()
    if not chain_ok:
        raise SystemExit(f"LOCAL OUTBOX INTEGRITY FAILURE: {chain_head}. Preserve the database for investigation; do not delete it.")
    print(f"[chainlog-agent] local event chain verified entries={chain_count} head={chain_head[:16]}", flush=True)
    print(f"[chainlog-agent] started host={HOST_ID} pending={outbox.count()} audit_log={'enabled' if AUDIT_LOG and Path(AUDIT_LOG).exists() else 'disabled'}; watch_roots={len(WATCH_ROOTS)} clamscan={'enabled' if CLAMSCAN_ENABLED else 'disabled'}; {geoip_status}", flush=True)
    threads = [
        threading.Thread(target=network_worker, args=(outbox,), name="api-delivery", daemon=True),
        threading.Thread(target=journal_worker, args=(outbox,), name="systemd-journal", daemon=True),
        threading.Thread(target=filesystem_watch_worker, args=(outbox,), name="filesystem-watch-health", daemon=True),
    ]
    if AUDIT_LOG:
        threads.append(threading.Thread(target=audit_worker, args=(outbox,), name="auditd-follow", daemon=True))
    for thread in threads:
        thread.start()
    while not STOP.is_set():
        STOP.wait(1)
    print("[chainlog-agent] stopping", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
