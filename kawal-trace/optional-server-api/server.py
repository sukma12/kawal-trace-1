#!/usr/bin/env python3
"""Standalone Kawal-Trace API, isolated from any existing website service.

Standard-library only. Bind to loopback and publish through Cloudflare Tunnel.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import struct
import json
import os
import re
import secrets
import select
import socket
import sqlite3
import threading
import time
from collections import OrderedDict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

HOST = os.environ.get("KAWAL_API_HOST", "127.0.0.1")
PORT = int(os.environ.get("KAWAL_API_PORT", "8765"))
DB_PATH = Path(os.environ.get("KAWAL_API_DB_PATH", "/var/lib/kawal-trace-api/events.sqlite3"))
MAX_BODY = 1_000_000
MAX_BATCH = 100
HEX64 = re.compile(r"^[0-9a-f]{64}$")
GENESIS = "0" * 64
ALLOWED_SECURITY_TYPES = {
    "AUTH_FAILURE", "AUTH_SUCCESS", "PRIVILEGE_USE", "FILE_CHANGE", "SERVICE_CHANGE",
    "WEB_AUTH_FAILURE", "WEB_AUTH_SUCCESS", "AGENT_HEALTH", "API_AUTH_FAILURE",
    "API_AUTH_SUCCESS", "CUSTOM_SECURITY_EVENT", "MALWARE_DETECTED",
}
DETAIL_KEYS = {
    "path", "auth_method", "reason", "service", "command_basename", "uid",
    "rule_key", "message_excerpt", "result", "signature_name", "windows_event_id",
    "log_name", "provider", "logon_type", "reason_code", "image", "process_id",
    "target_user", "group_name",
}
OPTIONAL_METADATA_LIMITS = {
    "source_country": 64, "source_region": 100, "source_city": 100, "source_asn": 100,
    "source_org": 180, "source_hostname": 128, "source_os": 100,
    "source_device_type": 80, "source_vendor": 100, "source_model": 100,
    "source_user_agent": 240, "source_geo_source": 64, "source_geo_accuracy": 80,
    "source_device_source": 64, "source_latitude": 32, "source_longitude": 32,
}
DB_LOCK = threading.RLock()
MEMBER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
CLAIM_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
# --- Abuse limits -------------------------------------------------------------------------------------
# Failures are counted per real client address and per identity, in memory and bounded, so neither a flood of
# bad tokens nor a flood of distinct addresses can exhaust CPU, logs or memory. Behind Cloudflare Tunnel the TCP
# peer is always the local tunnel daemon, so the real address comes from CF-Connecting-IP. That header is trusted
# ONLY when the peer is loopback (main() refuses any other bind address) and KAWAL_TRUST_CF_CONNECTING_IP is not
# "false". If it is missing the client is treated as the shared loopback address, which gets a much higher
# limit: otherwise one attacker could lock every legitimate user out.
AUTH_FAIL_WINDOW_SECONDS = 60.0
AUTH_FAIL_LIMIT = 10
AUTH_FAIL_LOOPBACK_FACTOR = 20
TOTP_FAIL_WINDOW_SECONDS = 300.0
TOTP_FAIL_LIMIT = 5
ENROLLMENT_WINDOW_SECONDS = 3600.0
ENROLLMENT_LIMIT = 20
LIMITER_MAX_KEYS = 4096


class SlidingWindowCounter:
    """Per-key event counter over a sliding window with a hard cap on tracked keys (least recently used drops first)."""

    def __init__(self, window_seconds: float, max_keys: int = LIMITER_MAX_KEYS, clock=time.monotonic) -> None:
        self._window = window_seconds
        self._max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: "OrderedDict[str, deque[float]]" = OrderedDict()

    def _prune(self, key: str, now: float) -> "deque[float] | None":
        hits = self._hits.get(key)
        if hits is None:
            return None
        while hits and now - hits[0] >= self._window:
            hits.popleft()
        if not hits:
            del self._hits[key]
            return None
        return hits

    def count(self, key: str) -> int:
        with self._lock:
            hits = self._prune(key, self._clock())
            return len(hits) if hits else 0

    def retry_after(self, key: str, limit: int) -> float:
        """Seconds until `key` drops below `limit` events (0 when it already is)."""
        with self._lock:
            now = self._clock()
            hits = self._prune(key, now)
            if not hits or len(hits) < limit:
                return 0.0
            return max(0.0, self._window - (now - hits[len(hits) - limit]))

    def add(self, key: str) -> int:
        with self._lock:
            now = self._clock()
            hits = self._prune(key, now)
            if hits is None:
                hits = self._hits[key] = deque()
            hits.append(now)
            self._hits.move_to_end(key)
            while len(self._hits) > self._max_keys:
                self._hits.popitem(last=False)
            return len(hits)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def tracked_keys(self) -> int:
        with self._lock:
            return len(self._hits)


AUTH_FAILURES = SlidingWindowCounter(AUTH_FAIL_WINDOW_SECONDS)
TOTP_FAILURES = SlidingWindowCounter(TOTP_FAIL_WINDOW_SECONDS)
ENROLLMENT_ATTEMPTS = SlidingWindowCounter(ENROLLMENT_WINDOW_SECONDS)


def auth_fail_limit_for(client_ip: str) -> int:
    try:
        shared = ipaddress.ip_address(client_ip).is_loopback
    except ValueError:
        shared = False
    return AUTH_FAIL_LIMIT * (AUTH_FAIL_LOOPBACK_FACTOR if shared else 1)


MEMBER_TOKEN_COLUMNS = {
    "KAWAL_AUDIT_TOKENS": "audit_token",
    "KAWAL_MONITOR_TOKENS": "monitor_token",
    "KAWAL_RESPONSE_TOKENS": "response_token",
    "KAWAL_WINDOWS_HOST_TOKENS": "windows_token",
    "KAWAL_INGEST_TOKENS": "ingest_token",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def audit_record_hash(event: dict[str, Any]) -> str:
    covered = {
        "seq": int(event["seq"]),
        "timestamp_utc": str(event["timestamp_utc"]),
        "event_type": str(event["event_type"]),
        "actor": str(event["actor"]),
        "source": str(event["source"]),
        "details": event["details"],
        "previous_hash": str(event["previous_hash"]),
    }
    return sha256(canonical_json(covered))


# Endpoints that STORE the client's own data (its audit chain and its log archive) on this server. The
# Kawal Trace app no longer sends any of it -- every database stays on the user's device -- so these are
# switched off unless the operator deliberately sets KAWAL_API_ACCEPT_CLIENT_DATA=true (e.g. to serve an
# older app version or to run the protocol tests). Security events from monitored hosts are unaffected.
CLIENT_DATA_PATHS = frozenset({
    "/api/v1/archive/events", "/api/v1/archive/events/summary", "/api/v1/archive/events:batch",
    "/api/v1/audit/events:batch", "/api/v1/encrypted-audit/events:batch",
})


def client_data_storage_enabled() -> bool:
    return os.environ.get("KAWAL_API_ACCEPT_CLIENT_DATA", "false").strip().lower() == "true"


def env_map(name: str) -> dict[str, str]:
    """Parse KEY|TOKEN;KEY2|TOKEN2 from a root-readable systemd EnvironmentFile."""
    raw = os.environ.get(name, "").strip()
    result: dict[str, str] = {}
    if not raw:
        return result
    for item in raw.split(";"):
        item = item.strip()
        if not item:
            continue
        if "|" not in item:
            raise RuntimeError(f"Format {name} salah; gunakan ID|TOKEN dipisahkan titik koma.")
        key, token = item.split("|", 1)
        key, token = key.strip(), token.strip()
        if not key or len(token) < 48 or any(c.isspace() for c in token):
            raise RuntimeError(f"Entri {name} tidak valid; ID wajib ada dan token minimal 48 hex karakter.")
        if key in result:
            raise RuntimeError(f"ID duplikat pada {name}.")
        result[key] = token
    return result


def token_matches(mapping_name: str, identity: str, supplied: str) -> bool:
    """Check database-managed member grants first, then retain legacy env tokens.

    A revoked member row overrides environment tokens for that Device ID, so removing
    a legacy device revokes it immediately without rewriting the admin's token file.
    """
    column = MEMBER_TOKEN_COLUMNS.get(mapping_name)
    if column and identity:
        try:
            with DB_LOCK, db_session() as conn:
                row = conn.execute(
                    f"SELECT status, {column} AS token_value FROM member_accounts WHERE device_id=?",
                    (identity,),
                ).fetchone()
            if row is not None:
                if row["status"] == "REVOKED":
                    return False
                if row["status"] == "ACTIVE":
                    expected = str(row["token_value"] or "")
                    return bool(expected and supplied and hmac.compare_digest(expected, supplied))
                # A pending enrollment does not break a legacy connection before approval.
        except sqlite3.OperationalError:
            # During a migration the membership table may not exist yet; legacy auth remains.
            pass
    mapping = env_map(mapping_name)
    expected = mapping.get(identity)
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def totp_secret_map(name: str = "KAWAL_RESPONSE_TOTP_SECRETS") -> dict[str, str]:
    """Parse device_id|BASE32 secret entries; never log secret values."""
    raw = os.environ.get(name, "").strip()
    result: dict[str, str] = {}
    if not raw:
        return result
    for item in raw.split(";"):
        if "|" not in item:
            raise RuntimeError(f"Format {name} salah; gunakan ID|BASE32 dipisahkan titik koma.")
        identity, secret = (part.strip() for part in item.split("|", 1))
        secret = secret.replace(" ", "").upper()
        if not identity or not re.fullmatch(r"[A-Z2-7]{16,64}", secret):
            raise RuntimeError(f"Entri {name} tidak valid; gunakan secret Base32 16–64 karakter.")
        if identity in result:
            raise RuntimeError(f"ID duplikat pada {name}.")
        result[identity] = secret
    if name == "KAWAL_RESPONSE_TOTP_SECRETS":
        try:
            with DB_LOCK, db_session() as conn:
                rows = conn.execute("SELECT device_id, status, totp_secret FROM member_accounts").fetchall()
            for row in rows:
                if row["status"] == "ACTIVE" and row["totp_secret"]:
                    result[str(row["device_id"])] = str(row["totp_secret"])
                elif row["status"] == "REVOKED":
                    result.pop(str(row["device_id"]), None)
        except sqlite3.OperationalError:
            pass
    return result


def _totp(secret_b32: str, when: float | None = None) -> str:
    secret = base64.b32decode(secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8), casefold=True)
    counter = int((time.time() if when is None else when) // 30)
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1_000_000
    return f"{code:06d}"


def verify_totp(identity: str, supplied: Any) -> bool:
    code = str(supplied or "").strip()
    if not re.fullmatch(r"[0-9]{6}", code):
        return False
    try:
        secret = totp_secret_map().get(identity)
    except RuntimeError:
        return False
    if not secret:
        return False
    now = time.time()
    return any(hmac.compare_digest(_totp(secret, now + delta), code) for delta in (-30, 0, 30))


def validate_envelope(raw: Any, expected_host: str, expected_stream: str) -> dict[str, Any]:
    """Validate envelope bounds and its clear routing metadata; ciphertext stays opaque."""
    if not isinstance(raw, dict) or raw.get("v") != 1 or raw.get("alg") != "X25519-HKDF-SHA256-AES-256-GCM":
        raise ValueError("unsupported_envelope")
    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("invalid_metadata")
    event_id = safe_text(metadata.get("event_id"), 64)
    host_id = safe_text(metadata.get("host_id"), 128)
    timestamp = parse_timestamp(metadata.get("timestamp_utc"))
    if not HEX64.fullmatch(event_id) or host_id != expected_host or metadata.get("stream") != expected_stream:
        raise ValueError("event_identity_or_stream_invalid")
    def b64_length(key: str, expected: int | None = None, maximum: int = MAX_BODY) -> bytes:
        value = raw.get(key)
        if not isinstance(value, str) or len(value) > maximum * 2:
            raise ValueError("envelope_field_invalid")
        try:
            value_bytes = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except Exception as exc:
            raise ValueError("envelope_field_invalid") from exc
        if expected is not None and len(value_bytes) != expected:
            raise ValueError("envelope_field_invalid")
        if len(value_bytes) > maximum:
            raise ValueError("envelope_too_large")
        return value_bytes
    b64_length("ephemeral_public_key_b64", 32, 32)
    b64_length("salt_b64", 16, 16)
    b64_length("nonce_b64", 12, 12)
    ciphertext = b64_length("ciphertext_b64", None, MAX_BODY)
    if len(ciphertext) < 16:
        raise ValueError("ciphertext_too_short")
    event_type = safe_text(metadata.get("event_type", "CUSTOM_SECURITY_EVENT"), 48).upper()
    if expected_stream == "security" and event_type not in ALLOWED_SECURITY_TYPES:
        raise ValueError("unsupported_event_type")
    source_ip = safe_text(metadata.get("source_ip", ""), 64)
    if source_ip:
        source_ip = str(ipaddress.ip_address(source_ip))
    clean_meta = {"event_id": event_id, "host_id": host_id, "timestamp_utc": timestamp, "stream": expected_stream}
    for key in ("event_type", "source", "source_ip", "auth_method", "log_name", "device_id", "seq", "record_hash", "previous_hash", "batch_id"):
        if key not in metadata:
            continue
        value = metadata[key]
        if isinstance(value, int) and not isinstance(value, bool):
            clean_meta[key] = value
        elif isinstance(value, str) and len(value) <= 180:
            clean_meta[key] = source_ip if key == "source_ip" else value
        else:
            raise ValueError("invalid_metadata_value")
    clean = {"v": 1, "alg": raw["alg"], "metadata": clean_meta,
             "ephemeral_public_key_b64": raw["ephemeral_public_key_b64"], "salt_b64": raw["salt_b64"],
             "nonce_b64": raw["nonce_b64"], "ciphertext_b64": raw["ciphertext_b64"]}
    if len(canonical_json(clean).encode("utf-8")) > MAX_BODY:
        raise ValueError("envelope_too_large")
    return clean


def parse_timestamp(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("timestamp_utc tidak valid")
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        raise ValueError("timestamp harus memiliki timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def safe_text(value: Any, limit: int = 256) -> str:
    if value is None:
        return ""
    if not isinstance(value, (str, int, float, bool)):
        return ""
    return "".join(c for c in str(value) if c >= " " and c != "\x7f")[:limit]


def sanitize_security_event(raw: Any, host_id: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("event harus object")
    event_id = safe_text(raw.get("event_id"), 64)
    if not HEX64.fullmatch(event_id):
        raise ValueError("event_id harus 64 karakter SHA-256 hex lowercase")
    supplied_host = safe_text(raw.get("host_id"), 128)
    if supplied_host != host_id:
        raise PermissionError("host_id event tidak cocok")
    event_type = safe_text(raw.get("event_type"), 48).upper()
    if event_type not in ALLOWED_SECURITY_TYPES:
        raise ValueError("event_type tidak didukung")
    timestamp = parse_timestamp(raw.get("timestamp_utc"))
    ip = safe_text(raw.get("source_ip", ""), 64)
    if ip:
        ip = str(ipaddress.ip_address(ip))
    details_raw = raw.get("details", {})
    if details_raw is None:
        details_raw = {}
    if not isinstance(details_raw, dict):
        raise ValueError("details harus object")
    details = {k: safe_text(details_raw[k], 256) for k in DETAIL_KEYS if k in details_raw}
    path = details.get("path", "")
    if "\x00" in path or ".." in path.replace("\\", "/").split("/"):
        raise ValueError("details.path tidak aman")
    event: dict[str, Any] = {
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "host_id": host_id,
        "source": safe_text(raw.get("source"), 64),
        "event_type": event_type,
        "actor": safe_text(raw.get("actor"), 128),
        "source_ip": ip,
        "details": details,
    }
    for key, limit in OPTIONAL_METADATA_LIMITS.items():
        event[key] = safe_text(raw.get(key), limit)
    return event


def connect_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


@contextmanager
def db_session():
    conn = connect_db()
    try:
        yield conn
        if conn.in_transaction:
            conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with DB_LOCK, db_session() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS audit_events (
          device_id TEXT NOT NULL,
          seq INTEGER NOT NULL,
          event_id TEXT NOT NULL,
          batch_id TEXT NOT NULL,
          timestamp_utc TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          previous_hash TEXT NOT NULL,
          record_hash TEXT NOT NULL,
          received_at_utc TEXT NOT NULL,
          PRIMARY KEY(device_id, seq),
          UNIQUE(device_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS security_events (
          event_id TEXT PRIMARY KEY,
          host_id TEXT NOT NULL,
          timestamp_utc TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          received_at_utc TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_security_events_received ON security_events(received_at_utc DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_host ON security_events(host_id, received_at_utc DESC);
        CREATE TABLE IF NOT EXISTS server_archive_events (
          device_id TEXT NOT NULL, source_profile_id TEXT NOT NULL,
          source_profile_name TEXT NOT NULL DEFAULT '', event_id TEXT NOT NULL, source_event_id TEXT NOT NULL DEFAULT '',
          timestamp_utc TEXT NOT NULL, event_date_utc TEXT NOT NULL,
          payload_json TEXT NOT NULL, archived_at_utc TEXT NOT NULL,
          PRIMARY KEY(device_id, source_profile_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_server_archive_date
          ON server_archive_events(device_id, source_profile_id, event_date_utc, timestamp_utc DESC);
        CREATE TABLE IF NOT EXISTS encrypted_security_events (
          event_id TEXT PRIMARY KEY, host_id TEXT NOT NULL, timestamp_utc TEXT NOT NULL,
          event_type TEXT NOT NULL, source_ip TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
          metadata_json TEXT NOT NULL, envelope_json TEXT NOT NULL, received_at_utc TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_encrypted_security_received ON encrypted_security_events(received_at_utc DESC);
        CREATE INDEX IF NOT EXISTS idx_encrypted_security_host ON encrypted_security_events(host_id, received_at_utc DESC);
        CREATE TABLE IF NOT EXISTS encrypted_audit_events (
          device_id TEXT NOT NULL, seq INTEGER NOT NULL, event_id TEXT NOT NULL, batch_id TEXT NOT NULL,
          timestamp_utc TEXT NOT NULL, metadata_json TEXT NOT NULL, envelope_json TEXT NOT NULL,
          previous_hash TEXT NOT NULL, record_hash TEXT NOT NULL, received_at_utc TEXT NOT NULL,
          PRIMARY KEY(device_id, seq), UNIQUE(device_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS windows_response_actions (
          action_id TEXT PRIMARY KEY, target_host_id TEXT NOT NULL, action TEXT NOT NULL,
          parameters_json TEXT NOT NULL, ttl_seconds INTEGER NOT NULL, reason TEXT NOT NULL,
          requested_by_device_id TEXT NOT NULL, requested_at_utc TEXT NOT NULL,
          expires_at_epoch REAL NOT NULL, status TEXT NOT NULL, worker_message TEXT NOT NULL DEFAULT '',
          updated_at_utc TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_windows_actions_host_status ON windows_response_actions(target_host_id, status, requested_at_utc DESC);
        CREATE TABLE IF NOT EXISTS response_actions (
          action_id TEXT PRIMARY KEY,
          device_id TEXT NOT NULL,
          action TEXT NOT NULL,
          source_ip TEXT NOT NULL,
          ttl_seconds INTEGER NOT NULL,
          reason TEXT NOT NULL,
          requested_at_utc TEXT NOT NULL,
          expires_at_utc TEXT NOT NULL,
          expires_at_epoch REAL NOT NULL,
          status TEXT NOT NULL,
          worker_message TEXT NOT NULL DEFAULT '',
          updated_at_utc TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions(status, requested_at_utc DESC);
        CREATE INDEX IF NOT EXISTS idx_response_actions_ip ON response_actions(source_ip, status);
        CREATE INDEX IF NOT EXISTS idx_response_actions_updated ON response_actions(updated_at_utc);
        CREATE INDEX IF NOT EXISTS idx_windows_actions_updated ON windows_response_actions(updated_at_utc);
        CREATE TABLE IF NOT EXISTS member_accounts (
          device_id TEXT PRIMARY KEY,
          display_name TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL CHECK(status IN ('PENDING','ACTIVE','REVOKED')),
          claim_secret_sha256 TEXT NOT NULL DEFAULT '',
          audit_token TEXT NOT NULL DEFAULT '',
          monitor_token TEXT NOT NULL DEFAULT '',
          response_token TEXT NOT NULL DEFAULT '',
          totp_secret TEXT NOT NULL DEFAULT '',
          created_at_utc TEXT NOT NULL,
          approved_at_utc TEXT NOT NULL DEFAULT '',
          revoked_at_utc TEXT NOT NULL DEFAULT '',
          last_seen_at_utc TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_members_status_created ON member_accounts(status, created_at_utc DESC);
        """)


# --- Live change stream (Server-Sent Events) ----------------------------------------------------------
# The stream is a doorbell, not a data channel: it says WHICH kind of data changed, never WHAT. The app then
# pulls through the same authenticated, size-bounded, validated endpoints it already uses, so a lost or
# duplicated message can neither hide an event nor invent one, and no event content crosses this channel.
# Every stream needs the monitor (read-only) token; revocation closes a live stream within one heartbeat.
STREAM_PATH = "/api/v1/stream"
STREAM_KINDS = ("security", "encrypted", "actions", "windows")


def _env_number(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return float(default)
    return min(high, max(low, value))


STREAM_HEARTBEAT_SECONDS = _env_number("KAWAL_STREAM_HEARTBEAT_SECONDS", 15.0, 0.05, 30.0)
STREAM_WATCH_SECONDS = _env_number("KAWAL_STREAM_WATCH_SECONDS", 1.0, 0.02, 10.0)
STREAM_MAX_LIFETIME_SECONDS = _env_number("KAWAL_STREAM_MAX_LIFETIME_SECONDS", 3600.0, 0.5, 86400.0)
STREAM_MAX_TOTAL = int(_env_number("KAWAL_STREAM_MAX_TOTAL", 32, 1, 256))
STREAM_MAX_PER_IDENTITY = int(_env_number("KAWAL_STREAM_MAX_PER_IDENTITY", 2, 1, 16))
STREAM_WRITE_TIMEOUT_SECONDS = 10.0


def _read_stream_heads() -> dict[str, str]:
    """Cheap change markers (indexed MAX lookups) for each kind of data the app can pull."""
    conn = connect_db()
    try:
        security = conn.execute("SELECT COALESCE(MAX(rowid),0) FROM security_events").fetchone()[0]
        encrypted = conn.execute("SELECT COALESCE(MAX(rowid),0) FROM encrypted_security_events").fetchone()[0]
        actions = conn.execute("SELECT COALESCE(MAX(rowid),0), COALESCE(MAX(updated_at_utc),'') FROM response_actions").fetchone()
        windows = conn.execute("SELECT COALESCE(MAX(rowid),0), COALESCE(MAX(updated_at_utc),'') FROM windows_response_actions").fetchone()
    finally:
        conn.close()
    return {
        "security": str(security), "encrypted": str(encrypted),
        "actions": f"{actions[0]}:{actions[1]}", "windows": f"{windows[0]}:{windows[1]}",
    }


class ChangeHub:
    """One shared watcher thread polls the database and wakes every open stream.

    Database load stays constant no matter how many apps are connected, and the watcher is also what notices
    status changes made by the separate response-worker process. It runs only while someone is subscribed.
    """

    def __init__(self, reader=None) -> None:
        self._reader = reader or _read_stream_heads
        self._cond = threading.Condition()
        self._version = 0
        self._kind_version = {kind: 0 for kind in STREAM_KINDS}
        self._head: dict[str, str] | None = None
        self._subscribers = 0
        self._thread: threading.Thread | None = None
        self._last_error_log = 0.0

    def subscribe(self) -> int:
        # The baseline is read HERE, before the caller can send 'hello', and outside the condition lock (a database read
        # must never be made while holding it). If the watcher took its own baseline on its first poll instead, a write
        # landing between 'hello' and that poll would become part of the baseline and never be announced.
        with self._cond:
            starting = self._thread is None or not self._thread.is_alive()
        baseline: dict[str, str] | None = None
        if starting:
            try:
                baseline = self._reader()
            except Exception:  # noqa: BLE001 - the watcher then takes its baseline from its first successful read
                baseline = None
        with self._cond:
            self._subscribers += 1
            if self._thread is None or not self._thread.is_alive():
                # Changes made while nobody watched are not signalled; a new subscriber catches up on hello.
                self._head = baseline
                self._thread = threading.Thread(target=self._run, name="kawal-stream-watch", daemon=True)
                self._thread.start()
            return self._version

    def unsubscribe(self) -> None:
        with self._cond:
            self._subscribers = max(0, self._subscribers - 1)

    def poke(self) -> None:
        with self._cond:
            self._cond.notify_all()

    def _run(self) -> None:
        while True:
            try:
                head = self._reader()
            except Exception as exc:  # noqa: BLE001 - a transient DB error must not kill the watcher
                head = None
                now = time.monotonic()
                if now - self._last_error_log > 60:
                    self._last_error_log = now
                    print(f"[stream] watcher read failed: {type(exc).__name__}", flush=True)
            with self._cond:
                if self._subscribers <= 0:
                    self._thread = None
                    return
                if head is not None:
                    if self._head is not None:
                        changed = [kind for kind in STREAM_KINDS if head.get(kind) != self._head.get(kind)]
                        if changed:
                            self._version += 1
                            for kind in changed:
                                self._kind_version[kind] = self._version
                            self._cond.notify_all()
                    self._head = head
            time.sleep(STREAM_WATCH_SECONDS)

    def wait(self, seen: int, timeout: float, ticket: "StreamTicket") -> tuple[int, tuple[str, ...]]:
        deadline = time.monotonic() + timeout
        with self._cond:
            while self._version <= seen and not ticket.stop:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._cond.wait(remaining)
            changed = tuple(kind for kind in STREAM_KINDS if self._kind_version[kind] > seen)
            return self._version, changed


class StreamTicket:
    __slots__ = ("identity", "stop")

    def __init__(self, identity: str) -> None:
        self.identity = identity
        self.stop = False


class StreamRegistry:
    """Caps open streams. A newer stream from the same device replaces its oldest one.

    A phone that changes network leaves a half-open connection on the server; evicting the oldest keeps the
    reconnect from being refused. The global cap protects the server's threads from being exhausted.
    """

    def __init__(self, hub: ChangeHub) -> None:
        self._hub = hub
        self._lock = threading.Lock()
        self._tickets: list[StreamTicket] = []

    def admit(self, identity: str) -> StreamTicket | None:
        with self._lock:
            active = [t for t in self._tickets if not t.stop]
            others = [t for t in active if t.identity != identity]
            if len(others) >= STREAM_MAX_TOTAL:
                return None
            mine = [t for t in active if t.identity == identity]
            evicted = False
            while len(mine) >= STREAM_MAX_PER_IDENTITY:
                mine.pop(0).stop = True
                evicted = True
            ticket = StreamTicket(identity)
            self._tickets.append(ticket)
        if evicted:
            self._hub.poke()
        return ticket

    def release(self, ticket: StreamTicket) -> None:
        with self._lock:
            if ticket in self._tickets:
                self._tickets.remove(ticket)

    def open_count(self) -> int:
        with self._lock:
            return len(self._tickets)


STREAM_HUB = ChangeHub()
STREAMS = StreamRegistry(STREAM_HUB)


class APIHandler(BaseHTTPRequestHandler):
    # The banner is visible to anyone who can reach the port, so it names no version (GET /healthz, behind a token, does).
    server_version = "Kawal-Trace-API"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        # Avoid logging credentials or request bodies; log only method and route. The parser calls this for requests
        # it rejects before `path`/`command` exist, so both are read defensively; the raw line is never logged.
        path = urlsplit(getattr(self, "path", "") or "").path[:200]
        print(f"[{utc_now()}] {self._client_ip()} {getattr(self, 'command', None) or '-'} {path or '-'}", flush=True)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Errors raised by the HTTP parser itself (bad request line, unknown verb, oversized header) are answered
        like every other response: a bare JSON status with the security headers, never an HTML page that echoes
        attacker-controlled text."""
        try:
            status = int(code)
        except (TypeError, ValueError):
            status = 500
        self.log_error("code %d", status)
        encoded = json.dumps({"error": "http_error", "status": status}, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        if getattr(self, "command", None) != "HEAD" and status >= 200 and status not in (204, 304):
            self.wfile.write(encoded)
        self.close_connection = True

    def _security_headers(self) -> None:
        """Headers for every response. This is an API, so nothing it returns may be framed, sniffed, cached or scripted."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Strict-Transport-Security", "max-age=31536000")

    def _client_ip(self) -> str:
        """The real client address: CF-Connecting-IP when the peer is the local tunnel, else the TCP peer."""
        peer = str(self.client_address[0])
        if os.environ.get("KAWAL_TRUST_CF_CONNECTING_IP", "true").strip().lower() == "false":
            return peer
        try:
            if not ipaddress.ip_address(peer).is_loopback:
                return peer
            headers = getattr(self, "headers", None)   # absent while a malformed request line is being logged
            claimed = headers.get("CF-Connecting-IP", "").strip() if headers is not None else ""
            return str(ipaddress.ip_address(claimed)) if claimed else peer
        except ValueError:
            return peer

    def _rate_gate(self) -> bool:
        """False (and a 429 sent) while this client has too many recent authentication failures."""
        ip = self._client_ip()
        wait = AUTH_FAILURES.retry_after(ip, auth_fail_limit_for(ip))
        if wait > 0:
            self._json(429, {"error": "too_many_failed_attempts", "retry_after_seconds": int(wait) + 1},
                       headers={"Retry-After": str(int(wait) + 1)})
            return False
        return True

    def _check_totp(self, device_id: str, supplied: Any) -> bool:
        """Verify a second-factor code with a per-device attempt budget (a 6-digit code must not be guessable)."""
        wait = TOTP_FAILURES.retry_after(device_id, TOTP_FAIL_LIMIT)
        if wait > 0:
            self._json(429, {"error": "too_many_totp_attempts", "retry_after_seconds": int(wait) + 1},
                       headers={"Retry-After": str(int(wait) + 1)})
            return False
        if verify_totp(device_id, supplied):
            TOTP_FAILURES.reset(device_id)
            return True
        TOTP_FAILURES.add(device_id)
        AUTH_FAILURES.add(self._client_ip())
        self._json(403, {"error": "totp_required_or_invalid"})
        return False

    def _json(self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        if status == 401:
            AUTH_FAILURES.add(self._client_ip())
        encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self._security_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def _body(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Content-Length tidak valid") from exc
        if length <= 0 or length > MAX_BODY:
            raise OverflowError("ukuran body harus 1 sampai 1.000.000 byte")
        data = self.rfile.read(length)
        body = json.loads(data.decode("utf-8"))
        if not isinstance(body, dict):
            raise ValueError("body harus JSON object")
        return body

    def _bearer(self) -> str:
        value = self.headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            return ""
        return value[7:].strip()

    def _admin_authorized(self) -> bool:
        expected = os.environ.get("KAWAL_ADMIN_TOKEN", "").strip()
        supplied = self._bearer()
        return bool(len(expected) >= 48 and supplied and hmac.compare_digest(expected, supplied))

    def _require_admin(self) -> bool:
        if len(os.environ.get("KAWAL_ADMIN_TOKEN", "").strip()) < 48:
            self._json(503, {"error": "admin_management_not_configured", "message": "Pemilik server harus membuat token administrator satu kali."})
            return False
        if not self._admin_authorized():
            self._json(401, {"error": "admin_unauthorized"})
            return False
        return True

    def _enrollment_rate_ok(self) -> bool:
        ip = self._client_ip()
        if ENROLLMENT_ATTEMPTS.count(ip) >= ENROLLMENT_LIMIT:
            return False
        ENROLLMENT_ATTEMPTS.add(ip)
        return True

    def _member_public_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "device_id": row["device_id"], "display_name": row["display_name"],
            "status": row["status"], "created_at_utc": row["created_at_utc"],
            "approved_at_utc": row["approved_at_utc"], "revoked_at_utc": row["revoked_at_utc"],
            "last_seen_at_utc": row["last_seen_at_utc"],
        }

    def _authorized(self, map_name: str, identity_header: str) -> tuple[bool, str]:
        identity = self.headers.get(identity_header, "").strip()
        token = self._bearer()
        if not identity or not token:
            return False, identity
        try:
            return token_matches(map_name, identity, token), identity
        except RuntimeError:
            return False, identity

    def _client_data_gate(self, path: str) -> bool:
        """True when the request may continue. Refuses (403) client-data endpoints unless explicitly enabled."""
        if path in CLIENT_DATA_PATHS and not client_data_storage_enabled():
            self._json(403, {"error": "client_data_storage_disabled",
                             "detail": "This server does not store client audit logs or archives (KAWAL_API_ACCEPT_CLIENT_DATA is not true)."})
            return False
        return True

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if not self._rate_gate():
            return
        if not self._client_data_gate(parsed.path):
            return
        if parsed.path == "/api/v1/admin/members":
            if not self._require_admin(): return
            with DB_LOCK, db_session() as conn:
                rows = conn.execute("SELECT * FROM member_accounts ORDER BY created_at_utc DESC").fetchall()
            self._json(200, {"members": [self._member_public_row(r) for r in rows], "count": len(rows)})
            return
        if parsed.path == "/api/v1/archive/events/summary":
            ok, device_id = self._authorized("KAWAL_AUDIT_TOKENS", "X-KAWAL-Device-ID")
            if not ok:
                self._json(401, {"error": "unauthorized"})
                return
            query = parse_qs(parsed.query, keep_blank_values=False)
            source_profile_id = safe_text(query.get("source_profile_id", [""])[0], 128).strip()
            if not MEMBER_ID_RE.fullmatch(source_profile_id):
                self._json(400, {"error": "invalid_source_profile_id"})
                return
            with DB_LOCK, db_session() as conn:
                rows = conn.execute(
                    "SELECT event_date_utc AS date, COUNT(*) AS count FROM server_archive_events "
                    "WHERE device_id=? AND source_profile_id=? GROUP BY event_date_utc ORDER BY event_date_utc DESC",
                    (device_id, source_profile_id),
                ).fetchall()
            dates = [{"date": str(row["date"]), "count": int(row["count"])} for row in rows]
            self._json(200, {"source_profile_id": source_profile_id, "dates": dates,
                             "total": sum(item["count"] for item in dates), "time_utc": utc_now()})
            return
        if parsed.path == "/api/v1/archive/events":
            ok, device_id = self._authorized("KAWAL_AUDIT_TOKENS", "X-KAWAL-Device-ID")
            if not ok:
                self._json(401, {"error": "unauthorized"})
                return
            query = parse_qs(parsed.query, keep_blank_values=False)
            source_profile_id = safe_text(query.get("source_profile_id", [""])[0], 128).strip()
            raw_date = safe_text(query.get("date", [""])[0], 10).strip()
            try:
                limit = int(query.get("limit", ["500"])[0])
                offset = int(query.get("offset", ["0"])[0])
            except (ValueError, TypeError):
                self._json(400, {"error": "invalid_limit_or_offset"}); return
            if not MEMBER_ID_RE.fullmatch(source_profile_id) or not 1 <= limit <= 1000 or not 0 <= offset <= 1000000:
                self._json(400, {"error": "invalid_source_profile_limit_or_offset"}); return
            if raw_date and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw_date):
                self._json(400, {"error": "invalid_utc_date"}); return
            if raw_date:
                try:
                    datetime.strptime(raw_date, "%Y-%m-%d")
                except ValueError:
                    self._json(400, {"error": "invalid_utc_date"}); return
            sql = "SELECT event_id,source_event_id,timestamp_utc,event_date_utc,payload_json,source_profile_name,archived_at_utc FROM server_archive_events WHERE device_id=? AND source_profile_id=?"
            values: list[Any] = [device_id, source_profile_id]
            if raw_date:
                sql += " AND event_date_utc=?"; values.append(raw_date)
            sql += " ORDER BY timestamp_utc DESC,event_id DESC LIMIT ? OFFSET ?"; values.extend([limit, offset])
            with DB_LOCK, db_session() as conn:
                rows = conn.execute(sql, values).fetchall()
            events = []
            for row in rows:
                try:
                    event = json.loads(row["payload_json"])
                    event["event_id"] = str(row["source_event_id"] or event.get("event_id", ""))
                    event["profile_name"] = str(row["source_profile_name"] or "")
                    event["event_date_utc"] = str(row["event_date_utc"])
                    event["archived_at_utc"] = str(row["archived_at_utc"])
                    events.append(event)
                except (TypeError, ValueError, json.JSONDecodeError):
                    self._json(500, {"error": "stored_archive_invalid"}); return
            self._json(200, {"source_profile_id": source_profile_id, "date_filter_utc": raw_date or "all", "count": len(events), "events": events, "time_utc": utc_now()})
            return
        if parsed.path == STREAM_PATH:
            ok, identity = self._authorized("KAWAL_MONITOR_TOKENS", "X-KAWAL-Device-ID")
            if not ok:
                self._json(401, {"error": "unauthorized"})
                return
            self._serve_stream(identity)
            return
        if parsed.path == "/healthz":
            identity = self.headers.get("X-KAWAL-Device-ID", "").strip()
            token = self._bearer()
            ok = False
            try:
                ok = token_matches("KAWAL_AUDIT_TOKENS", identity, token) or token_matches("KAWAL_MONITOR_TOKENS", identity, token)
            except RuntimeError:
                ok = False
            if not ok:
                self._json(401, {"error": "unauthorized"})
                return
            self._json(200, {"status": "ok", "service": "kawal-trace-api", "api_version": "1.5.1", "features": ["stream"], "time_utc": utc_now()})
            return

        if parsed.path == "/api/v1/encrypted-security-events":
            ok, _identity = self._authorized("KAWAL_MONITOR_TOKENS", "X-KAWAL-Device-ID")
            if not ok:
                self._json(401, {"error": "unauthorized"})
                return
            query = parse_qs(parsed.query, keep_blank_values=False)
            try:
                limit = int(query.get("limit", ["100"])[0])
            except (ValueError, TypeError):
                self._json(400, {"error": "invalid_limit"}); return
            if not 1 <= limit <= 100:
                self._json(400, {"error": "limit_must_be_1_to_100"}); return
            with DB_LOCK, db_session() as conn:
                rows = conn.execute("SELECT envelope_json FROM encrypted_security_events ORDER BY received_at_utc DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
            self._json(200, {"events": [json.loads(row["envelope_json"]) for row in rows], "count": len(rows), "encryption": "opaque-e2ee-envelope", "time_utc": utc_now()})
            return

        if parsed.path == "/api/v1/windows/response-actions":
            host_id = self.headers.get("X-KAWAL-Host-ID", "").strip()
            if host_id and token_matches_safe("KAWAL_WINDOWS_HOST_TOKENS", host_id, self._bearer()):
                query = parse_qs(parsed.query, keep_blank_values=False)
                try: limit = max(1, min(50, int(query.get("limit", ["20"])[0])))
                except (ValueError, TypeError): self._json(400, {"error": "invalid_limit"}); return
                with DB_LOCK, db_session() as conn:
                    rows = conn.execute("SELECT * FROM windows_response_actions WHERE target_host_id=? AND status='PENDING' ORDER BY requested_at_utc LIMIT ?", (host_id, limit)).fetchall()
                actions=[]
                now=time.time()
                for row in rows:
                    actions.append({"action_id": row["action_id"], "target_host_id": row["target_host_id"], "action": row["action"], "parameters": json.loads(row["parameters_json"]), "ttl_seconds": int(row["ttl_seconds"]), "reason": row["reason"], "requested_at_utc": row["requested_at_utc"], "expires_at_epoch": float(row["expires_at_epoch"]), "status": row["status"]})
                self._json(200, {"actions": actions, "count": len(actions), "server_time_epoch": now}); return
            ok, _identity = self._authorized("KAWAL_MONITOR_TOKENS", "X-KAWAL-Device-ID")
            if not ok:
                self._json(401, {"error": "unauthorized"}); return
            query = parse_qs(parsed.query, keep_blank_values=False)
            target = safe_text(query.get("host_id", [""])[0], 128)
            try: limit = max(1, min(100, int(query.get("limit", ["20"])[0])))
            except (ValueError, TypeError): self._json(400, {"error": "invalid_limit"}); return
            with DB_LOCK, db_session() as conn:
                if target:
                    rows=conn.execute("SELECT action_id,target_host_id,action,parameters_json,ttl_seconds,reason,requested_at_utc,status,worker_message,updated_at_utc FROM windows_response_actions WHERE target_host_id=? ORDER BY requested_at_utc DESC LIMIT ?", (target, limit)).fetchall()
                else:
                    rows=conn.execute("SELECT action_id,target_host_id,action,parameters_json,ttl_seconds,reason,requested_at_utc,status,worker_message,updated_at_utc FROM windows_response_actions ORDER BY requested_at_utc DESC LIMIT ?", (limit,)).fetchall()
            result=[{**dict(row), "parameters": json.loads(row["parameters_json"])} for row in rows]
            self._json(200, {"actions": result, "count": len(result), "time_utc": utc_now()}); return

        if parsed.path == "/api/v1/response-actions":
            ok, _identity = self._authorized("KAWAL_MONITOR_TOKENS", "X-KAWAL-Device-ID")
            if not ok:
                self._json(401, {"error": "unauthorized"})
                return
            query = parse_qs(parsed.query, keep_blank_values=False)
            try:
                limit = int(query.get("limit", ["20"])[0])
            except (ValueError, TypeError):
                self._json(400, {"error": "invalid_limit"})
                return
            if not 1 <= limit <= 100:
                self._json(400, {"error": "limit_must_be_1_to_100"})
                return
            with DB_LOCK, db_session() as conn:
                rows = conn.execute(
                    "SELECT action_id,action,source_ip,ttl_seconds,reason,requested_at_utc,expires_at_utc,status,worker_message,updated_at_utc "
                    "FROM response_actions ORDER BY requested_at_utc DESC LIMIT ?", (limit,)
                ).fetchall()
            self._json(200, {"actions": [dict(row) for row in rows], "count": len(rows), "time_utc": utc_now()})
            return

        if parsed.path == "/api/v1/security-events":
            ok, _identity = self._authorized("KAWAL_MONITOR_TOKENS", "X-KAWAL-Device-ID")
            if not ok:
                self._json(401, {"error": "unauthorized"})
                return
            query = parse_qs(parsed.query, keep_blank_values=False)
            try:
                limit = int(query.get("limit", ["100"])[0])
            except (ValueError, TypeError):
                self._json(400, {"error": "invalid_limit"})
                return
            if not 1 <= limit <= 100:
                self._json(400, {"error": "limit_must_be_1_to_100"})
                return
            with DB_LOCK, db_session() as conn:
                rows = conn.execute(
                    "SELECT payload_json FROM security_events ORDER BY received_at_utc DESC, rowid DESC LIMIT ?", (limit,)
                ).fetchall()
            events = [json.loads(row["payload_json"]) for row in rows]
            self._json(200, {"events": events, "count": len(events), "time_utc": utc_now()})
            return
        self._json(404, {"error": "not_found"})

    def _peer_closed(self) -> bool:
        """True once the app has hung up. A GET has no body, so readable-with-EOF means it is gone."""
        try:
            readable, _, _ = select.select([self.connection], [], [], 0)
            if not readable:
                return False
            return self.connection.recv(1, socket.MSG_PEEK) == b""
        except (OSError, ValueError):
            return True

    def _sse_write(self, payload: bytes) -> None:
        self.wfile.write(payload)
        self.wfile.flush()

    def _sse(self, event: str, data: dict[str, Any], seq: int) -> None:
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        self._sse_write(f"id: {seq}\nevent: {event}\ndata: {body}\n\n".encode("utf-8"))

    def _serve_stream(self, identity: str) -> None:
        """Server-Sent Events doorbell. Carries change notices only; see the STREAM_* block for the contract."""
        supplied = self._bearer()
        ticket = STREAMS.admit(identity)
        if ticket is None:
            self._json(503, {"error": "stream_capacity_reached"})
            return
        subscribed = False
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-transform")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self._security_headers()
            self.end_headers()
            self.close_connection = True
            self.connection.settimeout(STREAM_WRITE_TIMEOUT_SECONDS)
            seen = STREAM_HUB.subscribe()
            subscribed = True
            started = last_auth = time.monotonic()
            self._sse_write(b"retry: 3000\n\n")
            self._sse("hello", {"v": 1, "seq": seen, "changed": [], "heartbeat_seconds": STREAM_HEARTBEAT_SECONDS,
                                "max_lifetime_seconds": STREAM_MAX_LIFETIME_SECONDS, "time_utc": utc_now()}, seen)
            while True:
                if ticket.stop:
                    self._sse("bye", {"v": 1, "reason": "replaced"}, seen)
                    return
                if time.monotonic() - started >= STREAM_MAX_LIFETIME_SECONDS:
                    self._sse("bye", {"v": 1, "reason": "lifetime"}, seen)
                    return
                version, changed = STREAM_HUB.wait(seen, STREAM_HEARTBEAT_SECONDS, ticket)
                if self._peer_closed():
                    return  # free the slot and let the watcher wind down instead of waiting for a failed write
                now = time.monotonic()
                if now - last_auth >= STREAM_HEARTBEAT_SECONDS:
                    last_auth = now
                    if not token_matches_safe("KAWAL_MONITOR_TOKENS", identity, supplied):
                        self._sse("revoked", {"v": 1}, seen)
                        return
                if ticket.stop:
                    continue
                if changed:
                    seen = version
                    self._sse("state", {"v": 1, "seq": version, "changed": list(changed), "time_utc": utc_now()}, version)
                else:
                    self._sse_write(b": ping\n\n")
        except (BrokenPipeError, ConnectionError, TimeoutError, OSError):
            return  # the app went away or stopped reading; nothing to clean up beyond the finally block
        finally:
            if subscribed:
                STREAM_HUB.unsubscribe()
            STREAMS.release(ticket)

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if not self._rate_gate():
            return
        try:
            body = self._body()
        except OverflowError:
            self._json(413, {"error": "request_too_large_or_empty"})
            return
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"error": "invalid_json"})
            return
        if not self._client_data_gate(parsed.path):
            return

        if parsed.path == "/api/v1/archive/events:batch":
            self._post_archive_events(body); return
        if parsed.path == "/api/v1/enrollment/request":
            self._post_enrollment_request(body); return
        if parsed.path == "/api/v1/enrollment/claim":
            self._post_enrollment_claim(body); return
        if parsed.path == "/api/v1/admin/members":
            self._post_admin_member(body); return
        if parsed.path == "/api/v1/encrypted-security-events:batch":
            self._post_encrypted_security(body); return
        if parsed.path == "/api/v1/encrypted-audit/events:batch":
            self._post_encrypted_audit(body); return
        if parsed.path == "/api/v1/windows/response-actions":
            self._post_windows_response_action(body); return
        win_result_match = re.fullmatch(r"/api/v1/windows/response-actions/([0-9a-f]{32})/result", parsed.path)
        if win_result_match:
            self._post_windows_response_result(win_result_match.group(1), body); return
        if parsed.path == "/api/v1/audit/events:batch":
            self._post_audit(body)
            return
        if parsed.path == "/api/v1/security-events:batch":
            self._post_security(body)
            return
        if parsed.path == "/api/v1/response-actions":
            self._post_response_action(body)
            return
        self._json(404, {"error": "not_found"})

    def _post_archive_events(self, body: dict[str, Any]) -> None:
        """Store read-only feed events archived by an authenticated enrolled client."""
        ok, device_id = self._authorized("KAWAL_AUDIT_TOKENS", "X-KAWAL-Device-ID")
        if not ok:
            self._json(401, {"error": "unauthorized"}); return
        source_profile_id = safe_text(body.get("source_profile_id"), 128).strip()
        source_profile_name = safe_text(body.get("source_profile_name", ""), 80).strip()
        events_raw = body.get("events")
        if body.get("schema_version") != 1 or not MEMBER_ID_RE.fullmatch(source_profile_id):
            self._json(400, {"error": "invalid_archive_schema_or_profile"}); return
        if not isinstance(events_raw, list) or not 1 <= len(events_raw) <= MAX_BATCH:
            self._json(400, {"error": "archive_batch_must_contain_1_to_100_events"}); return
        try:
            events: list[dict[str, Any]] = []
            for raw in events_raw:
                if not isinstance(raw, dict):
                    raise ValueError("event_must_be_object")
                # The access token is bound to the archiving client; host_id is source-event metadata.
                raw_host_id = safe_text(raw.get("host_id"), 128).strip() or "unknown-host"
                clean = sanitize_security_event(raw, raw_host_id)
                original_id = safe_text(raw.get("archive_source_event_id", raw.get("event_id", "")), 128).strip()
                if not original_id:
                    raise ValueError("source_event_id_required")
                clean["__archive_source_event_id"] = original_id
                events.append(clean)
            event_ids = [event["event_id"] for event in events]
            if len(set(event_ids)) != len(event_ids):
                raise ValueError("duplicate_event_ids")
        except PermissionError:
            self._json(403, {"error": "event_host_mismatch"}); return
        except (ValueError, TypeError, KeyError):
            self._json(400, {"error": "invalid_archive_event"}); return

        received = utc_now()
        accepted: list[str] = []
        with DB_LOCK, db_session() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                for event in events:
                    original_id = str(event.pop("__archive_source_event_id", event["event_id"]))
                    encoded = canonical_json(event)
                    event_id = event["event_id"]
                    existing = conn.execute(
                        "SELECT payload_json,source_event_id FROM server_archive_events WHERE device_id=? AND source_profile_id=? AND event_id=?",
                        (device_id, source_profile_id, event_id),
                    ).fetchone()
                    if existing:
                        if existing["payload_json"] != encoded or existing["source_event_id"] != original_id:
                            raise ValueError("archive_event_id_conflict")
                    else:
                        conn.execute(
                            "INSERT INTO server_archive_events(device_id,source_profile_id,source_profile_name,event_id,source_event_id,timestamp_utc,event_date_utc,payload_json,archived_at_utc) VALUES(?,?,?,?,?,?,?,?,?)",
                            (device_id, source_profile_id, source_profile_name, event_id, original_id, event["timestamp_utc"], event["timestamp_utc"][:10], encoded, received),
                        )
                    accepted.append(event_id)
                conn.commit()
            except ValueError:
                conn.rollback(); self._json(409, {"error": "archive_event_conflict"}); return
            except sqlite3.IntegrityError:
                conn.rollback(); self._json(409, {"error": "duplicate_archive_event"}); return
        self._json(200, {"accepted_event_ids": accepted, "accepted_count": len(accepted), "source_profile_id": source_profile_id})

    def _post_encrypted_security(self, body: dict[str, Any]) -> None:
        host_id = safe_text(body.get("host_id"), 128)
        if not host_id or host_id != self.headers.get("X-KAWAL-Host-ID", "").strip() or not token_matches_safe("KAWAL_INGEST_TOKENS", host_id, self._bearer()):
            self._json(401, {"error": "unauthorized"}); return
        events = body.get("events")
        if body.get("schema_version") != 1 or not isinstance(events, list) or not 1 <= len(events) <= MAX_BATCH:
            self._json(400, {"error": "invalid_batch_schema"}); return
        try:
            clean = [validate_envelope(item, host_id, "security") for item in events]
            ids = [item["metadata"]["event_id"] for item in clean]
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate_event_ids")
            expected = sha256("\n".join(ids))
            if self.headers.get("Idempotency-Key", "") != expected:
                raise ValueError("idempotency_key_mismatch")
        except (ValueError, TypeError, KeyError):
            self._json(400, {"error": "invalid_encrypted_envelope_batch"}); return
        received = utc_now(); accepted=[]
        with DB_LOCK, db_session() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                for envelope in clean:
                    meta=envelope["metadata"]; event_id=meta["event_id"]
                    encoded=canonical_json(envelope); meta_encoded=canonical_json(meta)
                    existing=conn.execute("SELECT envelope_json,host_id FROM encrypted_security_events WHERE event_id=?", (event_id,)).fetchone()
                    if existing:
                        if existing["host_id"] != host_id or existing["envelope_json"] != encoded:
                            raise Conflict("encrypted event id conflict")
                    else:
                        conn.execute("INSERT INTO encrypted_security_events(event_id,host_id,timestamp_utc,event_type,source_ip,source,metadata_json,envelope_json,received_at_utc) VALUES(?,?,?,?,?,?,?,?,?)",
                                     (event_id, host_id, meta["timestamp_utc"], safe_text(meta.get("event_type", "CUSTOM_SECURITY_EVENT"), 48).upper(), safe_text(meta.get("source_ip", ""), 64), safe_text(meta.get("source", ""), 64), meta_encoded, encoded, received))
                    accepted.append(event_id)
                conn.commit()
                self._json(200, {"accepted_event_ids": accepted, "accepted_count": len(accepted), "encryption": "opaque-e2ee-envelope"})
            except Conflict:
                conn.rollback(); self._json(409, {"error": "encrypted_event_conflict"})

    def _post_encrypted_audit(self, body: dict[str, Any]) -> None:
        device_id = safe_text(body.get("device_id"), 128)
        if not device_id or device_id != self.headers.get("X-KAWAL-Device-ID", "").strip() or not token_matches_safe("KAWAL_AUDIT_TOKENS", device_id, self._bearer()):
            self._json(401, {"error": "unauthorized"}); return
        raw_events=body.get("events")
        if body.get("schema_version") != 1 or not isinstance(raw_events, list) or not 1 <= len(raw_events) <= 500:
            self._json(400, {"error": "invalid_batch_schema"}); return
        try:
            envelopes=[validate_envelope(item, device_id, "audit") for item in raw_events]
            metas=[item["metadata"] for item in envelopes]
            seqs=[int(m["seq"]) for m in metas]
            if any(b != a+1 for a,b in zip(seqs,seqs[1:])): raise ValueError("noncontiguous_seq")
            first_seq,last_seq=int(body["first_seq"]),int(body["last_seq"])
            if first_seq != seqs[0] or last_seq != seqs[-1]: raise ValueError("invalid_seq_range")
            if any(m.get("device_id") != device_id or m.get("record_hash") is None or not HEX64.fullmatch(str(m.get("record_hash"))) or not HEX64.fullmatch(str(m.get("previous_hash", ""))) for m in metas):
                raise ValueError("invalid_chain_metadata")
            for m in metas:
                expected_id=sha256(f"{device_id}\n{int(m['seq'])}\n{m['record_hash']}")
                if m["event_id"] != expected_id or m.get("batch_id") != body.get("batch_id"):
                    raise ValueError("event_id_or_batch_id_mismatch")
            seed=f"{device_id}\n{first_seq}\n{last_seq}\n{metas[0]['record_hash']}\n{metas[-1]['record_hash']}"
            batch_id=sha256(seed)
            if body.get("batch_id") != batch_id or self.headers.get("Idempotency-Key", "") != batch_id:
                raise ValueError("batch_id_mismatch")
            prev_seq=int(body.get("previous_ack_seq", -1)); prev_hash=str(body.get("previous_ack_hash", ""))
            if prev_seq < 0 or not HEX64.fullmatch(prev_hash): raise ValueError("previous_checkpoint_invalid")
        except (ValueError, TypeError, KeyError):
            self._json(400, {"error": "invalid_encrypted_audit_batch"}); return
        inserted=0
        with DB_LOCK, db_session() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                if prev_seq == 0:
                    if prev_hash != GENESIS: raise Conflict("genesis checkpoint mismatch")
                else:
                    prev=conn.execute("SELECT record_hash FROM encrypted_audit_events WHERE device_id=? AND seq=?", (device_id,prev_seq)).fetchone()
                    if not prev or prev["record_hash"] != prev_hash: raise Conflict("previous checkpoint mismatch")
                latest=conn.execute("SELECT seq,record_hash FROM encrypted_audit_events WHERE device_id=? ORDER BY seq DESC LIMIT 1", (device_id,)).fetchone()
                cur_seq=int(latest["seq"]) if latest else 0; cur_hash=str(latest["record_hash"]) if latest else GENESIS
                for envelope,meta in zip(envelopes, metas):
                    seq=int(meta["seq"]); event_id=meta["event_id"]; encoded=canonical_json(envelope); meta_json=canonical_json(meta)
                    existing=conn.execute("SELECT event_id,envelope_json,record_hash FROM encrypted_audit_events WHERE device_id=? AND seq=?", (device_id,seq)).fetchone()
                    if existing:
                        if existing["event_id"] != event_id or existing["record_hash"] != meta["record_hash"] or existing["envelope_json"] != encoded: raise Conflict("sequence already exists with different encrypted content")
                        continue
                    if seq != cur_seq+1 or meta["previous_hash"] != cur_hash: raise Conflict("sequence gap or previous hash mismatch")
                    conn.execute("INSERT INTO encrypted_audit_events(device_id,seq,event_id,batch_id,timestamp_utc,metadata_json,envelope_json,previous_hash,record_hash,received_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                 (device_id,seq,event_id,batch_id,meta["timestamp_utc"],meta_json,encoded,meta["previous_hash"],meta["record_hash"],utc_now()))
                    cur_seq,cur_hash=seq,str(meta["record_hash"]); inserted += 1
                conn.commit()
                self._json(200,{"accepted_through_seq":last_seq,"head_hash":str(metas[-1]["record_hash"]),"accepted_count":inserted,"encryption":"opaque-e2ee-envelope"})
            except Conflict:
                conn.rollback(); self._json(409,{"error":"encrypted_audit_chain_conflict"})

    def _post_windows_response_action(self, body: dict[str, Any]) -> None:
        device_id=self.headers.get("X-KAWAL-Device-ID", "").strip()
        if not device_id or not token_matches_safe("KAWAL_RESPONSE_TOKENS", device_id, self._bearer()):
            self._json(401,{"error":"unauthorized"}); return
        if os.environ.get("KAWAL_WINDOWS_RESPONSE_ENABLED", "false").strip().lower() != "true":
            self._json(403,{"error":"windows_response_disabled"}); return
        if not self._check_totp(device_id, body.get("totp_code")):
            return
        target_host=safe_text(body.get("target_host_id"),128)
        if not target_host or target_host not in env_map_safe("KAWAL_WINDOWS_HOST_TOKENS"):
            self._json(403,{"error":"target_windows_host_not_enrolled"}); return
        action=safe_text(body.get("action"),40).upper(); reason=safe_text(body.get("reason"),180).strip()
        confirmation=safe_text(body.get("confirmation"),180).strip(); params=body.get("parameters") if isinstance(body.get("parameters"),dict) else {}
        if len(reason)<8:
            self._json(400,{"error":"reason_required"}); return
        try:
            ttl=int(body.get("ttl_seconds",300)); ttl=ttl if ttl in {300,900,1800} else 0
            if ttl == 0: raise ValueError("ttl_invalid")
            if action == "WINDOWS_BLOCK_IP":
                ip=ipaddress.ip_address(str(params.get("source_ip","")))
                allow={str(ipaddress.ip_address(x.strip())) for x in os.environ.get("KAWAL_RESPONSE_ALLOWLIST","").split(",") if x.strip()}
                if ip.version!=4 or not ip.is_global or str(ip) in allow: raise ValueError("public_ipv4_not_allowlisted_required")
                params={"source_ip":str(ip)}; expected=f"BLOCK {ip}"
                ttl=ttl
            elif action == "WINDOWS_LOGOFF_SESSION":
                sid=int(params.get("session_id",0)); user=safe_text(params.get("target_user"),128).strip()
                if sid<=0 or not user: raise ValueError("session_id_and_user_required")
                params={"session_id":sid,"target_user":user}; expected=f"LOGOFF {sid} {user}"; ttl=300
            elif action == "WINDOWS_TERMINATE_PROCESS":
                pid=int(params.get("pid",0)); user=safe_text(params.get("target_user"),128).strip(); name=safe_text(params.get("process_name"),128).strip().lower()
                if pid<=4 or not user or name not in {"cmd.exe","powershell.exe","pwsh.exe","wt.exe","windowsterminal.exe"}: raise ValueError("process_target_not_allowed")
                params={"pid":pid,"target_user":user,"process_name":name}; expected=f"TERMINATE {pid} {name}"; ttl=300
            else: raise ValueError("unsupported_windows_action")
            if confirmation != expected: raise ValueError("typed_confirmation_mismatch")
        except (ValueError, TypeError):
            self._json(400,{"error":"invalid_action_parameters_or_confirmation"}); return
        action_id=secrets.token_hex(16); now=datetime.now(timezone.utc); requested=now.isoformat(timespec="milliseconds").replace("+00:00","Z")
        expires_epoch=now.timestamp() + (min(ttl,300) if action != "WINDOWS_BLOCK_IP" else 300)
        with DB_LOCK, db_session() as conn:
            conn.execute("INSERT INTO windows_response_actions(action_id,target_host_id,action,parameters_json,ttl_seconds,reason,requested_by_device_id,requested_at_utc,expires_at_epoch,status,worker_message,updated_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                         (action_id,target_host,action,canonical_json(params),ttl,reason,device_id,requested,expires_epoch,"PENDING","queued; endpoint revalidates evidence/policy",requested))
        self._json(202,{"status":"PENDING","action_id":action_id,"target_host_id":target_host,"action":action,"expires_at_epoch":expires_epoch,"message":"Queued. No action is active until the enrolled endpoint revalidates and confirms success."})

    def _post_windows_response_result(self, action_id: str, body: dict[str, Any]) -> None:
        host_id=self.headers.get("X-KAWAL-Host-ID", "").strip()
        if not host_id or not token_matches_safe("KAWAL_WINDOWS_HOST_TOKENS",host_id,self._bearer()):
            self._json(401,{"error":"unauthorized"}); return
        status=safe_text(body.get("status"),40).upper(); message=safe_text(body.get("message"),220)
        if status not in {"SUCCEEDED","REJECTED_LOCAL_POLICY","FAILED","EXPIRED"}:
            self._json(400,{"error":"invalid_result_status"}); return
        with DB_LOCK, db_session() as conn:
            cur=conn.execute("UPDATE windows_response_actions SET status=?,worker_message=?,updated_at_utc=? WHERE action_id=? AND target_host_id=? AND status='PENDING'",
                             (status,message,utc_now(),action_id,host_id))
            if cur.rowcount != 1:
                self._json(404,{"error":"pending_action_not_found"}); return
        self._json(200,{"status":status,"action_id":action_id,"updated_at_utc":utc_now()})

    def _has_recent_direct_ssh_failure(self, source_ip: str) -> bool:
        """Require corroborating direct SSH failure telemetry before queueing a UFW block.

        UFW on an origin behind Cloudflare cannot block an HTTP visitor IP reliably;
        the host sees Cloudflare's connection. This check restricts this worker to
        IPs reported by the authorized Linux journal agent as recent SSH failures.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with DB_LOCK, db_session() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM security_events WHERE received_at_utc>=? ORDER BY received_at_utc DESC LIMIT 5000",
                (cutoff,),
            ).fetchall()
        for row in rows:
            try:
                event = json.loads(row["payload_json"])
                details = event.get("details") if isinstance(event.get("details"), dict) else {}
                if (event.get("source_ip") == source_ip
                        and event.get("event_type") == "AUTH_FAILURE"
                        and event.get("source") == "linux-journal"
                        and (details.get("auth_method") == "ssh" or "ssh" in str(details.get("service", "")).lower())):
                    return True
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
        with DB_LOCK, db_session() as conn:
            rows = conn.execute("SELECT metadata_json FROM encrypted_security_events WHERE received_at_utc>=? ORDER BY received_at_utc DESC LIMIT 5000", (cutoff,)).fetchall()
        for row in rows:
            try:
                meta=json.loads(row["metadata_json"])
                if (meta.get("source_ip")==source_ip and str(meta.get("event_type","")).upper()=="AUTH_FAILURE"
                        and str(meta.get("source","")).startswith("linux-journal")
                        and str(meta.get("auth_method","")).lower()=="ssh"):
                    return True
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
        return False

    def _post_response_action(self, body: dict[str, Any]) -> None:
        """Queue a bounded UFW request. A separate root worker re-validates and executes it."""
        device_id = self.headers.get("X-KAWAL-Device-ID", "").strip()
        if not device_id or not token_matches_safe("KAWAL_RESPONSE_TOKENS", device_id, self._bearer()):
            self._json(401, {"error": "unauthorized"})
            return
        if not self._check_totp(device_id, body.get("totp_code")):
            return
        if os.environ.get("KAWAL_RESPONSE_ACTIONS_ENABLED", "false").strip().lower() != "true":
            self._json(403, {"error": "response_actions_disabled"})
            return
        allowlist_raw = os.environ.get("KAWAL_RESPONSE_ALLOWLIST", "").strip()
        if not allowlist_raw:
            self._json(503, {"error": "response_allowlist_not_configured"})
            return
        try:
            allowlist = {str(ipaddress.ip_address(item.strip())) for item in allowlist_raw.split(",") if item.strip()}
        except ValueError:
            self._json(503, {"error": "response_allowlist_invalid"})
            return
        if not allowlist:
            self._json(503, {"error": "response_allowlist_not_configured"})
            return
        action = safe_text(body.get("action"), 32)
        raw_ip = safe_text(body.get("source_ip"), 64)
        reason = safe_text(body.get("reason"), 180).strip()
        confirmation = safe_text(body.get("confirmation"), 80).strip()
        try:
            ip = ipaddress.ip_address(raw_ip)
            ttl = int(body.get("ttl_seconds", 0))
        except (ValueError, TypeError):
            self._json(400, {"error": "invalid_ip_or_ttl"})
            return
        if action not in {"TEMP_BLOCK_IP", "FORCE_DISCONNECT_SSH"}:
            self._json(400, {"error": "unsupported_action", "supported": ["TEMP_BLOCK_IP", "FORCE_DISCONNECT_SSH"]})
            return
        # Safe starter worker implements public IPv4 UFW rules and carefully scoped SSH session disconnect.
        if ip.version != 4 or not ip.is_global:
            self._json(400, {"error": "public_ipv4_only"})
            return
        ip_text = str(ip)
        if ip_text in allowlist:
            self._json(403, {"error": "ip_is_in_admin_allowlist"})
            return
        if action == "TEMP_BLOCK_IP":
            if ttl not in {300, 900, 1800}:
                self._json(400, {"error": "ttl_must_be_300_900_or_1800"})
                return
            if len(reason) < 8 or confirmation != f"BLOCK {ip_text}":
                self._json(400, {"error": "reason_or_confirmation_invalid"})
                return
            if not self._has_recent_direct_ssh_failure(ip_text):
                self._json(409, {"error": "ip_requires_recent_direct_ssh_failure_from_agent"})
                return
        else:  # FORCE_DISCONNECT_SSH
            # TTL is informational for audit; disconnect is one-shot.
            if ttl not in {0, 60, 300}:
                ttl = 60
            account = safe_text(body.get("account"), 64).strip()
            if len(reason) < 8 or confirmation != f"DISCONNECT {ip_text}":
                self._json(400, {"error": "reason_or_confirmation_invalid", "need": f"DISCONNECT {ip_text}"})
                return
            # Never queue disconnect for empty account or protected admin names.
            protected = {"root", "admin", "ubuntu", "kawal", "administrator"}
            if not account or account.lower() in protected:
                self._json(403, {"error": "protected_or_empty_account", "message": "Force disconnect refuses empty or protected admin accounts."})
                return
            # Fold account into reason for audit trail (schema has no dedicated account column).
            reason = f"[account={account}] {reason}"
        action_id = secrets.token_hex(16)
        now = datetime.now(timezone.utc)
        expiry = now.timestamp() + ttl
        requested = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        expires = datetime.fromtimestamp(expiry, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with DB_LOCK, db_session() as conn:
            active = conn.execute(
                "SELECT action_id,status FROM response_actions WHERE source_ip=? AND status IN ('PENDING','ACTIVE_TEMP_BLOCK') LIMIT 1",
                (ip_text,),
            ).fetchone()
            if active:
                self._json(409, {"error": "ip_already_pending_or_blocked", "action_id": active["action_id"], "status": active["status"]})
                return
            conn.execute(
                "INSERT INTO response_actions(action_id,device_id,action,source_ip,ttl_seconds,reason,requested_at_utc,expires_at_utc,expires_at_epoch,status,worker_message,updated_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (action_id, device_id, action, ip_text, ttl, reason, requested, expires, expiry, "PENDING", "queued_for_privileged_worker", requested),
            )
        self._json(202, {"status": "PENDING", "action_id": action_id, "source_ip": ip_text,
                         "ttl_seconds": ttl, "expires_at_utc": expires,
                         "message": "Request queued. No block is active until the response worker confirms."})

    def _post_audit(self, body: dict[str, Any]) -> None:
        device_id = str(body.get("device_id", "")).strip()
        header_id = self.headers.get("X-KAWAL-Device-ID", "").strip()
        if not device_id or device_id != header_id or not token_matches_safe("KAWAL_AUDIT_TOKENS", device_id, self._bearer()):
            self._json(401, {"error": "unauthorized"})
            return
        events = body.get("events")
        if body.get("schema_version") != 1 or not isinstance(events, list) or not (1 <= len(events) <= 500):
            self._json(400, {"error": "invalid_batch_schema"})
            return
        try:
            seqs = [int(event["seq"]) for event in events if isinstance(event, dict)]
            if len(seqs) != len(events) or any(b != a + 1 for a, b in zip(seqs, seqs[1:])):
                raise ValueError("sequence harus kontigu")
            first_seq, last_seq = int(body["first_seq"]), int(body["last_seq"])
            if first_seq != seqs[0] or last_seq != seqs[-1]:
                raise ValueError("rentang sequence salah")
            if any(event.get("device_id") != device_id for event in events):
                raise ValueError("device id event tidak cocok")
            if any(not HEX64.fullmatch(str(event.get("record_hash", ""))) for event in events):
                raise ValueError("record_hash invalid")
            for event in events:
                parse_timestamp(event.get("timestamp_utc"))
                if not isinstance(event.get("details"), dict):
                    raise ValueError("details harus object")
                if audit_record_hash(event) != event["record_hash"]:
                    raise ValueError("record_hash mismatch")
                expected_event_id = sha256(f"{device_id}\n{int(event['seq'])}\n{event['record_hash']}")
                if event.get("event_id") != expected_event_id:
                    raise ValueError("event_id mismatch")
                if not HEX64.fullmatch(str(event.get("previous_hash", ""))):
                    raise ValueError("previous_hash invalid")
            seed = f"{device_id}\n{first_seq}\n{last_seq}\n{events[0]['record_hash']}\n{events[-1]['record_hash']}"
            computed_batch_id = sha256(seed)
            if body.get("batch_id") != computed_batch_id or self.headers.get("Idempotency-Key", "") != computed_batch_id:
                raise ValueError("batch id mismatch")
            previous_ack_seq = int(body.get("previous_ack_seq", -1))
            previous_ack_hash = str(body.get("previous_ack_hash", ""))
            if previous_ack_seq < 0 or not HEX64.fullmatch(previous_ack_hash):
                raise ValueError("previous ack invalid")
        except (KeyError, TypeError, ValueError, OverflowError):
            self._json(400, {"error": "invalid_audit_batch_or_hash"})
            return

        inserted = 0
        with DB_LOCK, db_session() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                if previous_ack_seq == 0:
                    if previous_ack_hash != GENESIS:
                        raise Conflict("genesis checkpoint mismatch")
                else:
                    ackrow = conn.execute("SELECT record_hash FROM audit_events WHERE device_id=? AND seq=?", (device_id, previous_ack_seq)).fetchone()
                    if not ackrow or not hmac.compare_digest(ackrow["record_hash"], previous_ack_hash):
                        raise Conflict("previous checkpoint mismatch")
                latest = conn.execute("SELECT seq,record_hash FROM audit_events WHERE device_id=? ORDER BY seq DESC LIMIT 1", (device_id,)).fetchone()
                current_seq = int(latest["seq"]) if latest else 0
                current_hash = str(latest["record_hash"]) if latest else GENESIS
                for event in events:
                    seq = int(event["seq"])
                    stored = conn.execute("SELECT event_id,payload_json,record_hash FROM audit_events WHERE device_id=? AND seq=?", (device_id, seq)).fetchone()
                    encoded = canonical_json(event)
                    if stored:
                        if stored["event_id"] != event["event_id"] or stored["record_hash"] != event["record_hash"] or stored["payload_json"] != encoded:
                            raise Conflict("sequence already exists with different content")
                        continue
                    if seq != current_seq + 1:
                        raise Conflict("sequence gap or missing historical record")
                    if event["previous_hash"] != current_hash:
                        raise Conflict("previous_hash mismatch")
                    conn.execute(
                        "INSERT INTO audit_events(device_id,seq,event_id,batch_id,timestamp_utc,payload_json,previous_hash,record_hash,received_at_utc) VALUES(?,?,?,?,?,?,?,?,?)",
                        (device_id, seq, event["event_id"], body["batch_id"], event["timestamp_utc"], encoded, event["previous_hash"], event["record_hash"], utc_now()),
                    )
                    current_seq, current_hash = seq, event["record_hash"]
                    inserted += 1
                last_event = events[-1]
                conn.commit()
                self._json(200, {"accepted_through_seq": int(last_event["seq"]), "head_hash": str(last_event["record_hash"]), "accepted_count": inserted})
            except Conflict:
                conn.rollback()
                self._json(409, {"error": "audit_chain_conflict"})
            except sqlite3.IntegrityError:
                conn.rollback()
                self._json(409, {"error": "duplicate_or_conflicting_audit_event"})

    def _post_security(self, body: dict[str, Any]) -> None:
        host_id = str(body.get("host_id", "")).strip()
        if not host_id or host_id != self.headers.get("X-KAWAL-Host-ID", "").strip() or not token_matches_safe("KAWAL_INGEST_TOKENS", host_id, self._bearer()):
            self._json(401, {"error": "unauthorized"})
            return
        events_raw = body.get("events")
        if body.get("schema_version") != 1 or not isinstance(events_raw, list) or not (1 <= len(events_raw) <= MAX_BATCH):
            self._json(400, {"error": "invalid_batch_schema"})
            return
        ids = [safe_text(event.get("event_id"), 64) for event in events_raw if isinstance(event, dict)]
        if len(ids) != len(events_raw) or len(set(ids)) != len(ids) or any(not HEX64.fullmatch(value) for value in ids):
            self._json(400, {"error": "invalid_or_duplicate_event_ids"})
            return
        expected_idem = sha256("\n".join(ids))
        if self.headers.get("Idempotency-Key", "") != expected_idem:
            self._json(400, {"error": "idempotency_key_mismatch"})
            return
        try:
            events = [sanitize_security_event(raw, host_id) for raw in events_raw]
        except PermissionError:
            self._json(403, {"error": "host_id_mismatch"})
            return
        except (ValueError, TypeError):
            self._json(400, {"error": "invalid_security_event"})
            return

        accepted: list[str] = []
        with DB_LOCK, db_session() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                for event in events:
                    encoded = canonical_json(event)
                    stored = conn.execute("SELECT host_id,payload_json FROM security_events WHERE event_id=?", (event["event_id"],)).fetchone()
                    if stored:
                        if stored["host_id"] != host_id or stored["payload_json"] != encoded:
                            raise Conflict("event id already stored with different content")
                    else:
                        conn.execute(
                            "INSERT INTO security_events(event_id,host_id,timestamp_utc,payload_json,received_at_utc) VALUES(?,?,?,?,?)",
                            (event["event_id"], host_id, event["timestamp_utc"], encoded, utc_now()),
                        )
                    accepted.append(event["event_id"])
                conn.commit()
                self._json(200, {"accepted_event_ids": accepted, "accepted_count": len(accepted)})
            except Conflict:
                conn.rollback()
                self._json(409, {"error": "security_event_conflict"})
            except sqlite3.IntegrityError:
                conn.rollback()
                self._json(409, {"error": "duplicate_security_event"})

    def _post_enrollment_request(self, body: dict[str, Any]) -> None:
        device_id = safe_text(body.get("device_id"), 128).strip()
        claim_secret = safe_text(body.get("claim_secret"), 128).strip()
        display_name = safe_text(body.get("display_name", "Kawal-Trace device"), 100).strip() or "Kawal-Trace device"
        if not MEMBER_ID_RE.fullmatch(device_id):
            self._json(400, {"error": "invalid_device_id"}); return
        if not CLAIM_SECRET_RE.fullmatch(claim_secret) or any(c.isspace() for c in claim_secret):
            self._json(400, {"error": "invalid_claim_secret"}); return
        claim_hash = sha256(claim_secret)
        now = utc_now()
        with DB_LOCK, db_session() as conn:
            row = conn.execute("SELECT * FROM member_accounts WHERE device_id=?", (device_id,)).fetchone()
            if row:
                if row["claim_secret_sha256"] and not hmac.compare_digest(str(row["claim_secret_sha256"]), claim_hash):
                    self._json(409, {"error": "device_id_claim_mismatch"}); return
                if row["status"] == "REVOKED":
                    # A legacy revoked row may not have a claim proof yet. Store the
                    # newly presented proof but keep it revoked until the owner explicitly re-approves.
                    if not row["claim_secret_sha256"]:
                        conn.execute("UPDATE member_accounts SET claim_secret_sha256=?,display_name=?,last_seen_at_utc=? WHERE device_id=?",
                                     (claim_hash, display_name, now, device_id))
                    self._json(403, {"error": "device_revoked", "status": "REVOKED", "message": "Akses dicabut; pemilik harus menyetujui ulang perangkat."}); return
                if row["status"] == "ACTIVE":
                    conn.execute("UPDATE member_accounts SET display_name=?,last_seen_at_utc=? WHERE device_id=?", (display_name, now, device_id))
                    self._json(200, {"device_id": device_id, "status": "ACTIVE", "message": "Perangkat sudah disetujui."}); return
                conn.execute("UPDATE member_accounts SET display_name=?,last_seen_at_utc=? WHERE device_id=?", (display_name, now, device_id))
                self._json(202, {"device_id": device_id, "status": "PENDING", "message": "Menunggu persetujuan pemilik server."}); return
            if not self._enrollment_rate_ok():
                self._json(429, {"error": "enrollment_rate_limited"}); return
            conn.execute(
                "INSERT INTO member_accounts(device_id,display_name,status,claim_secret_sha256,created_at_utc,last_seen_at_utc) VALUES(?,?,?,?,?,?)",
                (device_id, display_name, "PENDING", claim_hash, now, now),
            )
        self._json(202, {"device_id": device_id, "status": "PENDING", "message": "Permintaan akses terkirim; tunggu persetujuan pemilik server."})

    def _post_enrollment_claim(self, body: dict[str, Any]) -> None:
        device_id = safe_text(body.get("device_id"), 128).strip()
        claim_secret = safe_text(body.get("claim_secret"), 128).strip()
        if not MEMBER_ID_RE.fullmatch(device_id) or not CLAIM_SECRET_RE.fullmatch(claim_secret):
            self._json(400, {"error": "invalid_enrollment_credentials"}); return
        claim_hash = sha256(claim_secret)
        with DB_LOCK, db_session() as conn:
            row = conn.execute("SELECT * FROM member_accounts WHERE device_id=?", (device_id,)).fetchone()
            if not row or not row["claim_secret_sha256"] or not hmac.compare_digest(str(row["claim_secret_sha256"]), claim_hash):
                self._json(401, {"error": "enrollment_claim_invalid"}); return
            if row["status"] == "REVOKED":
                self._json(403, {"error": "device_revoked", "status": "REVOKED"}); return
            if row["status"] != "ACTIVE":
                self._json(202, {"error": "approval_pending", "status": row["status"]}); return
            if not row["audit_token"] or not row["monitor_token"] or not row["response_token"]:
                self._json(500, {"error": "membership_credentials_missing"}); return
            conn.execute("UPDATE member_accounts SET last_seen_at_utc=? WHERE device_id=?", (utc_now(), device_id))
            credentials = {"device_id": device_id, "device_token": row["audit_token"],
                           "monitor_token": row["monitor_token"], "response_token": row["response_token"],
                           "response_totp_secret": row["totp_secret"], "status": "ACTIVE"}
        self._json(200, credentials)

    def _post_admin_member(self, body: dict[str, Any]) -> None:
        if not self._require_admin(): return
        device_id = safe_text(body.get("device_id"), 128).strip()
        display_name = safe_text(body.get("display_name", "Member"), 100).strip() or "Member"
        if not MEMBER_ID_RE.fullmatch(device_id):
            self._json(400, {"error": "invalid_device_id"}); return
        now = utc_now()
        with DB_LOCK, db_session() as conn:
            row = conn.execute("SELECT * FROM member_accounts WHERE device_id=?", (device_id,)).fetchone()
            if not row:
                # Support revocation of a legacy env-mapped device even when it has not enrolled.
                self._json(404, {"error": "enrollment_request_not_found", "message": "Perangkat harus lebih dulu membuka aplikasi dan meminta akses ke server ini."}); return
            if not row["claim_secret_sha256"]:
                self._json(409, {"error": "claim_proof_missing", "message": "Perangkat perlu meminta akses dari aplikasi sebelum disetujui."}); return
            if row["status"] == "ACTIVE":
                self._json(200, {"device_id": device_id, "status": "ACTIVE", "message": "Anggota sudah aktif; token tidak dirotasi."}); return
            audit = secrets.token_hex(32)
            monitor = secrets.token_hex(32)
            response = secrets.token_hex(32)
            totp = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
            conn.execute("UPDATE member_accounts SET display_name=?,status='ACTIVE',audit_token=?,monitor_token=?,response_token=?,totp_secret=?,approved_at_utc=?,revoked_at_utc='',last_seen_at_utc=? WHERE device_id=?",
                         (display_name, audit, monitor, response, totp, now, now, device_id))
        self._json(200, {"device_id": device_id, "status": "ACTIVE", "message": "Anggota disetujui. Aplikasi anggota dapat mengambil kredensial secara otomatis."})

    def do_PUT(self) -> None:
        self._json(405, {"error": "method_not_allowed"})
    do_PATCH = do_PUT

    def do_DELETE(self) -> None:
        parsed = urlsplit(self.path)
        if not self._rate_gate():
            return
        match = re.fullmatch(r"/api/v1/admin/members/([A-Za-z0-9][A-Za-z0-9._:-]{7,127})", parsed.path)
        if not match:
            self._json(404, {"error": "not_found"}); return
        if not self._require_admin(): return
        device_id = match.group(1)
        now = utc_now()
        with DB_LOCK, db_session() as conn:
            row = conn.execute("SELECT device_id FROM member_accounts WHERE device_id=?", (device_id,)).fetchone()
            if not row:
                # The tombstone overrides any legacy token entries for this ID.
                conn.execute("INSERT INTO member_accounts(device_id,display_name,status,created_at_utc,revoked_at_utc) VALUES(?,?,?,?,?)",
                             (device_id, "Revoked legacy device", "REVOKED", now, now))
                self._json(200, {"device_id": device_id, "status": "REVOKED", "message": "Akses perangkat dicabut."}); return
            conn.execute("UPDATE member_accounts SET status='REVOKED',audit_token='',monitor_token='',response_token='',totp_secret='',revoked_at_utc=? WHERE device_id=?",
                         (now, device_id))
        self._json(200, {"device_id": device_id, "status": "REVOKED", "message": "Akses perangkat dicabut; token lama tidak lagi diterima."})


class Conflict(Exception):
    pass


def env_map_safe(name: str) -> dict[str, str]:
    try:
        return env_map(name)
    except RuntimeError:
        return {}


def token_matches_safe(mapping_name: str, identity: str, token: str) -> bool:
    try:
        return token_matches(mapping_name, identity, token)
    except RuntimeError:
        return False


def main() -> None:
    init_db()
    # Validate token maps at startup but never print their content.
    for name in ("KAWAL_AUDIT_TOKENS", "KAWAL_MONITOR_TOKENS", "KAWAL_INGEST_TOKENS", "KAWAL_RESPONSE_TOKENS", "KAWAL_WINDOWS_HOST_TOKENS"):
        env_map(name)
    admin_token = os.environ.get("KAWAL_ADMIN_TOKEN", "").strip()
    if admin_token and (len(admin_token) < 48 or any(c.isspace() for c in admin_token)):
        raise SystemExit("KAWAL_ADMIN_TOKEN tidak valid; harus minimal 48 karakter tanpa spasi.")
    if os.environ.get("KAWAL_RESPONSE_ACTIONS_ENABLED", "false").strip().lower() == "true":
        raw_allowlist = os.environ.get("KAWAL_RESPONSE_ALLOWLIST", "").strip()
        if not raw_allowlist:
            raise SystemExit("KAWAL_RESPONSE_ACTIONS_ENABLED=true memerlukan KAWAL_RESPONSE_ALLOWLIST nonkosong")
        try:
            for value in raw_allowlist.split(","):
                if value.strip():
                    ipaddress.ip_address(value.strip())
        except ValueError:
            raise SystemExit("KAWAL_RESPONSE_ALLOWLIST mengandung IP invalid") from None
    if HOST not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("Demi keamanan, API hanya boleh bind ke loopback di belakang reverse proxy/tunnel.")
    server = ThreadingHTTPServer((HOST, PORT), APIHandler)
    server.daemon_threads = True
    print(f"Kawal-Trace API listening on {HOST}:{PORT}; DB={DB_PATH}; public access must go through HTTPS tunnel", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
