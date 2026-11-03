"""Secure, retryable synchronization of local Kawal Trace records to an API.

The client keeps the audit chain local-first. It never clears local records after
upload. Remote delivery is at-least-once; the API MUST deduplicate event_id and
reject sequence gaps. TLS validation is always on.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx

from .core import AuditStore, GENESIS_HASH, canonical_json, verify_records
from .http_json import ResponseBodyTooLargeError, bounded_response_json
from .storage_policy import require_remote_storage

APP_VERSION = "1.0"
DEFAULT_EVENTS_PATH = "/api/v1/audit/events:batch"
DEFAULT_HEALTH_PATH = "/healthz"
DEFAULT_TELEMETRY_PATH = "/api/v1/security-events"
DEFAULT_CONNECTOR_TYPE = "kawal_trace_api"
DEFAULT_FEED_AUTH_MODE = "bearer"
DEFAULT_FEED_AUTH_HEADER_NAME = "X-API-Key"
DEFAULT_FEED_AUTH_HEADER_NAME = "X-API-Key"
DEFAULT_FEED_JSON_PATH = "events"
DEFAULT_FEED_FIELD_MAPPING = json.dumps({
    "event_id": "event_id",
    "timestamp_utc": "timestamp_utc",
    "host_id": "host_id",
    "source": "source",
    "event_type": "event_type",
    "actor": "actor",
    "source_ip": "source_ip",
    "details": "details",
    "source_country": "source_country",
    "source_region": "source_region",
    "source_city": "source_city",
    "source_asn": "source_asn",
    "source_org": "source_org",
    "source_hostname": "source_hostname",
    "source_os": "source_os",
    "source_device_type": "source_device_type",
    "source_vendor": "source_vendor",
    "source_model": "source_model",
    "source_user_agent": "source_user_agent",
    "source_geo_source": "source_geo_source",
    "source_geo_accuracy": "source_geo_accuracy",
    "source_device_source": "source_device_source",
}, separators=(",", ":"))
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class SyncError(Exception):
    """Base error for synchronization failures."""


class SyncConfigError(SyncError):
    """Invalid or incomplete server/device configuration."""


class SyncProtocolError(SyncError):
    """API response does not satisfy the Kawal Trace sync contract."""


class SyncTransportError(SyncError):
    """Network, TLS, timeout, or HTTP status error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _is_loopback(host: str | None) -> bool:
    return (host or "").lower() in {"localhost", "127.0.0.1", "::1", "[::1]"}


def _clean_json_path(path: str, field_name: str) -> str:
    value = str(path).strip()
    if not value or len(value) > 240:
        raise SyncConfigError(f"{field_name} wajib diisi dan maksimal 240 karakter.")
    if value == "$":
        return value
    parts = value.split(".")
    if any(not re.fullmatch(r"[A-Za-z0-9_-]+", part) for part in parts):
        raise SyncConfigError(f"{field_name} harus berupa jalur JSON bertitik sederhana, misalnya data.events.")
    return value


def _validate_field_mapping(raw: str) -> str:
    try:
        mapping = json.loads(str(raw))
    except (TypeError, ValueError) as exc:
        raise SyncConfigError("Mapping field harus berupa JSON object yang valid.") from exc
    allowed = {
        "event_id", "timestamp_utc", "host_id", "source", "event_type", "actor", "source_ip", "details",
        "source_country", "source_region", "source_city", "source_asn", "source_org", "source_hostname",
        "source_os", "source_device_type", "source_vendor", "source_model", "source_user_agent",
        "source_geo_source", "source_geo_accuracy", "source_device_source",
    }
    if not isinstance(mapping, dict) or len(mapping) > 24:
        raise SyncConfigError("Mapping field harus berupa JSON object dengan maksimal 24 field.")
    clean: dict[str, str] = {}
    for target, source_path in mapping.items():
        if target not in allowed or not isinstance(source_path, str):
            raise SyncConfigError(f"Field mapping tidak didukung: {target!r}.")
        clean[target] = _clean_json_path(source_path, f"Mapping {target}")
    if "timestamp_utc" not in clean and "timestamp_utc" not in mapping:
        raise SyncConfigError("Mapping wajib memuat timestamp_utc.")
    return json.dumps(clean, ensure_ascii=False, separators=(",", ":"))


def _clean_endpoint_path(path: str, field_name: str) -> str:
    value = str(path).strip()
    if not value.startswith("/") or value.startswith("//") or "?" in value or "#" in value:
        raise SyncConfigError(f"{field_name} harus berupa path API yang diawali '/', tanpa query atau fragment.")
    if ".." in value.split("/"):
        raise SyncConfigError(f"{field_name} tidak boleh memuat segmen '..'.")
    return value


@dataclass(frozen=True)
class SyncSettings:
    base_url: str
    device_id: str
    events_path: str = DEFAULT_EVENTS_PATH
    health_path: str = DEFAULT_HEALTH_PATH
    telemetry_path: str = DEFAULT_TELEMETRY_PATH
    ca_bundle: str = ""
    connector_type: str = DEFAULT_CONNECTOR_TYPE
    feed_auth_mode: str = DEFAULT_FEED_AUTH_MODE
    feed_json_path: str = DEFAULT_FEED_JSON_PATH
    feed_field_mapping: str = DEFAULT_FEED_FIELD_MAPPING
    feed_auth_header_name: str = DEFAULT_FEED_AUTH_HEADER_NAME
    adapter_protocol: str = "rest"
    adapter_options_json: str = "{}"

    def validated(self) -> "SyncSettings":
        raw_url = self.base_url.strip().rstrip("/")
        parsed = urlsplit(raw_url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise SyncConfigError("URL server harus berupa URL HTTPS yang valid.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise SyncConfigError("URL server tidak boleh berisi kredensial, query, atau fragment.")
        if parsed.scheme != "https" and not _is_loopback(parsed.hostname):
            raise SyncConfigError("HTTPS wajib untuk server internet. HTTP hanya diizinkan untuk localhost saat uji lokal.")
        device_id = self.device_id.strip()
        if not DEVICE_ID_RE.fullmatch(device_id):
            raise SyncConfigError("ID perangkat tidak valid (8–128 karakter alfanumerik, titik, _, :, atau -).")
        events_path = _clean_endpoint_path(self.events_path, "Events path")
        health_path = _clean_endpoint_path(self.health_path, "Health path")
        telemetry_path = _clean_endpoint_path(self.telemetry_path, "Telemetry path")
        ca_bundle = self.ca_bundle.strip()
        if ca_bundle and not Path(ca_bundle).expanduser().is_file():
            raise SyncConfigError("File CA bundle khusus tidak ditemukan.")
        connector_type = str(self.connector_type).strip().lower()
        if connector_type not in {"kawal_trace_api", "generic_rest_readonly"}:
            raise SyncConfigError("Jenis konektor harus kawal_trace_api atau generic_rest_readonly.")
        feed_auth_mode = str(self.feed_auth_mode).strip().lower()
        if feed_auth_mode not in {"bearer", "api_key", "custom_header", "none"}:
            raise SyncConfigError("Mode autentikasi feed tidak didukung.")
        feed_auth_header_name = str(self.feed_auth_header_name or DEFAULT_FEED_AUTH_HEADER_NAME).strip()
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}", feed_auth_header_name):
            raise SyncConfigError("Nama header autentikasi tidak valid.")
        feed_json_path = _clean_json_path(self.feed_json_path, "Path array event JSON")
        feed_field_mapping = _validate_field_mapping(self.feed_field_mapping)
        adapter_protocol = str(self.adapter_protocol or "rest").strip().lower()
        if adapter_protocol not in {"rest", "oauth2_rest", "graphql", "soap", "websocket"}:
            raise SyncConfigError("Protokol adapter harus rest, oauth2_rest, graphql, soap, atau websocket.")
        adapter_options_json = str(self.adapter_options_json or "{}")
        if len(adapter_options_json.encode("utf-8", errors="replace")) > 98304:
            raise SyncConfigError("Konfigurasi adapter maksimal 96 KiB.")
        try:
            adapter_options = json.loads(adapter_options_json)
        except ValueError as exc:
            raise SyncConfigError("Konfigurasi adapter harus JSON valid.") from exc
        if not isinstance(adapter_options, dict) or len(adapter_options) > 64:
            raise SyncConfigError("Konfigurasi adapter harus berupa object dengan maksimal 64 properti.")
        forbidden_secret_keys = {"client_secret", "password", "access_token", "refresh_token", "api_secret", "authorization", "bearer_token"}
        def contains_secret_key(value: Any) -> bool:
            if isinstance(value, dict):
                return any(str(key).strip().lower() in forbidden_secret_keys or contains_secret_key(child)
                           for key, child in value.items())
            if isinstance(value, list):
                return any(contains_secret_key(child) for child in value)
            return False
        if contains_secret_key(adapter_options):
            raise SyncConfigError("Rahasia tidak boleh disimpan di file konfigurasi (termasuk nested JSON); gunakan Secure Storage OS.")
        adapter_options_json = json.dumps(adapter_options, ensure_ascii=False, separators=(",", ":"))
        return SyncSettings(
            base_url=raw_url, device_id=device_id, events_path=events_path, health_path=health_path,
            telemetry_path=telemetry_path, ca_bundle=ca_bundle, connector_type=connector_type,
            feed_auth_mode=feed_auth_mode, feed_json_path=feed_json_path, feed_field_mapping=feed_field_mapping,
            feed_auth_header_name=feed_auth_header_name, adapter_protocol=adapter_protocol,
            adapter_options_json=adapter_options_json,
        )

    @classmethod
    def new_device(cls, base_url: str = "", **kwargs: Any) -> "SyncSettings":
        return cls(base_url=base_url, device_id="cl-" + uuid.uuid4().hex, **kwargs)


class SyncSettingsStore:
    """Persists only non-secret endpoint/device settings; never writes the token."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.settings = self._load_or_create()

    def _load_or_create(self) -> SyncSettings:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                return SyncSettings(
                    base_url=str(raw.get("base_url", "")),
                    device_id=str(raw.get("device_id", "")),
                    events_path=str(raw.get("events_path", DEFAULT_EVENTS_PATH)),
                    health_path=str(raw.get("health_path", DEFAULT_HEALTH_PATH)),
                    telemetry_path=str(raw.get("telemetry_path", DEFAULT_TELEMETRY_PATH)),
                    ca_bundle=str(raw.get("ca_bundle", "")),
                    connector_type=str(raw.get("connector_type", DEFAULT_CONNECTOR_TYPE)),
                    feed_auth_mode=str(raw.get("feed_auth_mode", DEFAULT_FEED_AUTH_MODE)),
                    feed_json_path=str(raw.get("feed_json_path", DEFAULT_FEED_JSON_PATH)),
                    feed_field_mapping=str(raw.get("feed_field_mapping", DEFAULT_FEED_FIELD_MAPPING)),
                    feed_auth_header_name=str(raw.get("feed_auth_header_name", DEFAULT_FEED_AUTH_HEADER_NAME)),
                    adapter_protocol=str(raw.get("adapter_protocol", "rest")),
                    adapter_options_json=str(raw.get("adapter_options_json", "{}")),
                )
            except (OSError, ValueError, TypeError) as exc:
                raise SyncConfigError("File konfigurasi sinkronisasi tidak dapat dibaca; buat cadangan lalu periksa JSON-nya.") from exc
        default = SyncSettings.new_device()
        self.save(default)
        return default

    def save(self, settings: SyncSettings) -> SyncSettings:
        checked = settings.validated() if settings.base_url.strip() else settings
        if not checked.device_id:
            raise SyncConfigError("ID perangkat tidak boleh kosong.")
        body = {
            "format": "Kawal Trace-sync-settings",
            "version": 1,
            "base_url": checked.base_url,
            "device_id": checked.device_id,
            "events_path": checked.events_path,
            "health_path": checked.health_path,
            "telemetry_path": checked.telemetry_path,
            "ca_bundle": checked.ca_bundle,
            "connector_type": checked.connector_type,
            "feed_auth_mode": checked.feed_auth_mode,
            "feed_json_path": checked.feed_json_path,
            "feed_field_mapping": checked.feed_field_mapping,
            "feed_auth_header_name": checked.feed_auth_header_name,
            "adapter_protocol": checked.adapter_protocol,
            "adapter_options_json": checked.adapter_options_json,
            "updated_at_utc": utc_now(),
            "secret_storage_note": "Token perangkat disimpan terpisah pada secure storage native, bukan di file ini.",
        }
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temp, self.path)
        if os.name != "nt":
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        self.settings = checked
        return checked


@dataclass(frozen=True)
class SyncCursor:
    device_id: str
    last_ack_seq: int
    last_ack_hash: str


class SyncCursorStore:
    """Durable non-secret delivery cursor. Re-send is safe because API dedupes event IDs."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_cursor (
                    device_id TEXT PRIMARY KEY,
                    last_ack_seq INTEGER NOT NULL CHECK(last_ack_seq >= 0),
                    last_ack_hash TEXT NOT NULL CHECK(length(last_ack_hash) = 64),
                    updated_at_utc TEXT NOT NULL
                )
            """)
        if os.name != "nt":
            try:
                self.path.chmod(0o600)
            except OSError:
                pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def get(self, device_id: str) -> SyncCursor:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM sync_cursor WHERE device_id=?", (device_id,)).fetchone()
            if row is None:
                return SyncCursor(device_id, 0, GENESIS_HASH)
            return SyncCursor(str(row["device_id"]), int(row["last_ack_seq"]), str(row["last_ack_hash"]))

    def advance(self, device_id: str, seq: int, head_hash: str) -> SyncCursor:
        if seq < 0 or len(head_hash) != 64:
            raise SyncProtocolError("Checkpoint server tidak valid.")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT last_ack_seq FROM sync_cursor WHERE device_id=?", (device_id,)).fetchone()
            previous = int(row["last_ack_seq"]) if row else 0
            if seq < previous:
                conn.rollback()
                raise SyncProtocolError("Checkpoint server mundur dibandingkan checkpoint lokal.")
            conn.execute("""
                INSERT INTO sync_cursor(device_id,last_ack_seq,last_ack_hash,updated_at_utc) VALUES(?,?,?,?)
                ON CONFLICT(device_id) DO UPDATE SET last_ack_seq=excluded.last_ack_seq,
                  last_ack_hash=excluded.last_ack_hash, updated_at_utc=excluded.updated_at_utc
            """, (device_id, seq, head_hash, utc_now()))
            conn.commit()
        return SyncCursor(device_id, seq, head_hash)


@dataclass(frozen=True)
class SyncResult:
    ok: bool
    device_id: str
    accepted_count: int
    last_ack_seq: int
    last_ack_hash: str
    message: str
    server_status: int | None = None


def _event_id(device_id: str, record: Mapping[str, Any]) -> str:
    raw = f"{device_id}\n{int(record['seq'])}\n{record['record_hash']}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _event_payload(device_id: str, record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "event_id": _event_id(device_id, record),
        "device_id": device_id,
        "seq": int(record["seq"]),
        "timestamp_utc": str(record["timestamp_utc"]),
        "event_type": str(record["event_type"]),
        "actor": str(record["actor"]),
        "source": str(record["source"]),
        "details": record["details"],
        "previous_hash": str(record["previous_hash"]),
        "record_hash": str(record["record_hash"]),
    }


class SyncClient:
    """HTTPS client that ships verified local records to a compatible API."""

    def __init__(
        self,
        settings: SyncSettings,
        device_token: str,
        cursor_store: SyncCursorStore,
        *,
        batch_size: int = 100,
        timeout_seconds: float = 12.0,
        recipient_public_key_b64: str = "",
        require_e2ee_for_remote: bool = True,
        allow_remote_storage: bool = False,
    ):
        # Default-deny: the application never uploads local records (see chainlog/storage_policy.py).
        self.allow_remote_storage = bool(allow_remote_storage)
        self.settings = settings.validated()
        self.token = str(device_token).strip()
        if len(self.token) < 24 or any(ch.isspace() for ch in self.token):
            raise SyncConfigError("Token perangkat kosong/terlalu pendek. Gunakan token unik yang diterbitkan server (minimal 24 karakter, disarankan 32+ acak).")
        if not 1 <= batch_size <= 500:
            raise SyncConfigError("Ukuran batch harus 1–500 record.")
        if timeout_seconds < 1 or timeout_seconds > 60:
            raise SyncConfigError("Timeout harus antara 1–60 detik.")
        self.cursor_store = cursor_store
        self.batch_size = batch_size
        self.timeout_seconds = timeout_seconds
        self.recipient_public_key_b64 = str(recipient_public_key_b64 or "").strip()
        self.require_e2ee_for_remote = bool(require_e2ee_for_remote)

    def _client(self) -> httpx.Client:
        verify: bool | str = self.settings.ca_bundle or True
        return httpx.Client(
            verify=verify,
            timeout=httpx.Timeout(self.timeout_seconds, connect=min(5.0, self.timeout_seconds)),
            follow_redirects=False,
            headers={
                "Authorization": f"Bearer {self.token}",
                "X-KAWAL-Device-ID": self.settings.device_id,
                "User-Agent": f"KawalTrace/{APP_VERSION}",
                "Accept": "application/json",
            },
        )

    def health_check(self) -> dict[str, Any]:
        url = self.settings.base_url + self.settings.health_path
        try:
            with self._client() as client:
                with client.stream("GET", url) as response:
                    if not 200 <= response.status_code < 300:
                        raise SyncTransportError(f"Health check ditolak server (HTTP {response.status_code}). Periksa token, ID perangkat, dan path health.")
                    try:
                        data = bounded_response_json(response)
                        return data if isinstance(data, dict) else {"response": "ok"}
                    except ResponseBodyTooLargeError as exc:
                        raise SyncProtocolError(f"Health check ditolak: {exc}") from exc
                    except ValueError:
                        # Some lightweight health endpoints return plain text or no JSON body.
                        return {"response": "ok"}
        except httpx.HTTPError as exc:
            raise SyncTransportError(f"Koneksi/TLS gagal ({type(exc).__name__}). Periksa DNS, firewall, dan sertifikat server.") from exc

    def sync_once(self, store: AuditStore) -> SyncResult:
        require_remote_storage(self.allow_remote_storage, "Pengiriman log audit ke server")
        # Fail closed: don't send a known-invalid local chain.
        verification = store.verify()
        if not verification.valid:
            raise SyncProtocolError(f"Sinkronisasi diblokir karena audit lokal tidak valid pada record {verification.failing_seq}: {verification.reason}")

        settings = self.settings
        cursor = self.cursor_store.get(settings.device_id)
        records = store.records()
        seq_hashes = {int(item["seq"]): str(item["record_hash"]) for item in records}
        if cursor.last_ack_seq > 0:
            local_hash = seq_hashes.get(cursor.last_ack_seq)
            if local_hash is None or local_hash != cursor.last_ack_hash:
                raise SyncProtocolError("Checkpoint lokal tidak cocok dengan database. Sinkronisasi dihentikan agar perubahan historis tidak terlewat.")
        pending = [item for item in records if int(item["seq"]) > cursor.last_ack_seq]
        if not pending:
            return SyncResult(True, settings.device_id, 0, cursor.last_ack_seq, cursor.last_ack_hash, "Tidak ada record tertunda; lokal sudah sinkron.")

        batch_records = pending[: self.batch_size]
        clear_events = [_event_payload(settings.device_id, item) for item in batch_records]
        first_seq, last_seq = int(batch_records[0]["seq"]), int(batch_records[-1]["seq"])
        batch_seed = f"{settings.device_id}\n{first_seq}\n{last_seq}\n{batch_records[0]['record_hash']}\n{batch_records[-1]['record_hash']}"
        batch_id = hashlib.sha256(batch_seed.encode("utf-8")).hexdigest()
        if self.recipient_public_key_b64:
            from .e2ee import encrypt_payload
            envelopes = []
            for event in clear_events:
                metadata = {
                    "event_id": event["event_id"], "host_id": settings.device_id,
                    "device_id": settings.device_id, "timestamp_utc": event["timestamp_utc"],
                    "stream": "audit", "seq": int(event["seq"]),
                    "record_hash": str(event["record_hash"]), "previous_hash": str(event["previous_hash"]),
                    "batch_id": batch_id,
                    "event_type": str(event["event_type"]),
                    "source": str(event["source"]),
                }
                envelopes.append(encrypt_payload(self.recipient_public_key_b64, event, metadata))
            payload = {
                "schema_version": 1, "app_version": APP_VERSION, "device_id": settings.device_id,
                "batch_id": batch_id, "sent_at_utc": utc_now(), "first_seq": first_seq,
                "last_seq": last_seq, "previous_ack_seq": cursor.last_ack_seq,
                "previous_ack_hash": cursor.last_ack_hash, "events": envelopes,
            }
            url = settings.base_url + "/api/v1/encrypted-audit/events:batch"
        else:
            parsed_url = urlsplit(settings.base_url)
            if self.require_e2ee_for_remote and parsed_url.scheme == "https":
                raise SyncConfigError("E2EE diwajibkan untuk upload internet. Buat/impor kunci E2EE di dashboard, simpan di Secure Storage, lalu distribusikan public key ke agent/server. Tidak ada fallback plaintext.")
            payload = {
                "schema_version": 1, "app_version": APP_VERSION, "device_id": settings.device_id,
                "batch_id": batch_id, "sent_at_utc": utc_now(), "first_seq": first_seq,
                "last_seq": last_seq, "previous_ack_seq": cursor.last_ack_seq,
                "previous_ack_hash": cursor.last_ack_hash, "events": clear_events,
            }
            url = settings.base_url + settings.events_path
        try:
            with self._client() as client:
                with client.stream("POST", url, json=payload, headers={"Idempotency-Key": batch_id}) as response:
                    if not 200 <= response.status_code < 300:
                        action = "Periksa enrollment/token" if response.status_code in (401, 403) else "Periksa kontrak API dan log server"
                        if response.status_code in (408, 425, 429, 500, 502, 503, 504):
                            action = "Server/jaringan sementara tidak tersedia; pengiriman akan dicoba ulang"
                        raise SyncTransportError(f"API menolak batch (HTTP {response.status_code}). {action}; log lokal tidak dihapus.")
                    try:
                        body = bounded_response_json(response)
                    except ResponseBodyTooLargeError as exc:
                        raise SyncProtocolError(f"API mengembalikan respons terlalu besar; checkpoint tidak dimajukan: {exc}") from exc
                    except ValueError as exc:
                        raise SyncProtocolError("API mengembalikan respons yang bukan JSON; checkpoint tidak dimajukan.") from exc
                    response_status_code = response.status_code
        except httpx.HTTPError as exc:
            raise SyncTransportError(f"Pengiriman gagal ({type(exc).__name__}). Log tetap tersimpan lokal dan akan dicoba ulang.") from exc
        if not isinstance(body, dict) or "accepted_through_seq" not in body or "head_hash" not in body:
            raise SyncProtocolError("Respons API harus berisi accepted_through_seq dan head_hash; checkpoint tidak dimajukan.")
        try:
            accepted_seq = int(body["accepted_through_seq"])
        except (ValueError, TypeError) as exc:
            raise SyncProtocolError("accepted_through_seq dari API bukan integer.") from exc
        known_batch_hashes = {int(item["seq"]): str(item["record_hash"]) for item in batch_records}
        expected_hash = GENESIS_HASH if accepted_seq == 0 else known_batch_hashes.get(accepted_seq)
        if accepted_seq < cursor.last_ack_seq or accepted_seq > last_seq or expected_hash is None:
            raise SyncProtocolError("Checkpoint server berada di luar batch yang dikirim; checkpoint lokal tidak dimajukan.")
        if str(body["head_hash"]) != expected_hash:
            raise SyncProtocolError("head_hash dari API tidak cocok dengan rantai lokal; checkpoint tidak dimajukan.")
        if accepted_seq < last_seq and accepted_seq == cursor.last_ack_seq:
            raise SyncProtocolError("Server belum mengonfirmasi satu pun record baru; periksa aturan penerimaan batch.")
        updated = self.cursor_store.advance(settings.device_id, accepted_seq, expected_hash)
        accepted_count = max(0, accepted_seq - cursor.last_ack_seq)
        return SyncResult(
            True, settings.device_id, accepted_count, updated.last_ack_seq, updated.last_ack_hash,
            f"Server mengonfirmasi record sampai #{updated.last_ack_seq}; {accepted_count} record baru diterima.",
            response_status_code,
        )
