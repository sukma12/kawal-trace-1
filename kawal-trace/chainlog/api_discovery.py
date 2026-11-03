"""Safe, user-triggered discovery for common REST/JSON security-event feeds.

This helper only sends bounded GET requests to a Base URL explicitly entered by
an authorized operator, using a short fixed list of common feed paths. It does
not crawl links, follow redirects, guess credentials, or perform write actions.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx

from .http_json import ResponseBodyTooLargeError, bounded_response_json
from .sync import SyncSettings

MAX_CANDIDATES = 9
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
COMMON_SECURITY_FEED_PATHS = (
    "/api/v1/security-events",
    "/api/security-events",
    "/api/v1/audit-logs",
    "/api/audit-logs",
    "/api/v1/logs",
    "/api/logs",
    "/security-events",
    "/logs",
)

# Try semantically likely containers before walking the rest of the JSON object.
_CONTAINER_PRIORITY = (
    "events", "security_events", "securityEvents", "audit_events", "auditEvents",
    "logs", "records", "items", "results", "entries", "data", "result",
)

_ALIASES: dict[str, tuple[str, ...]] = {
    "event_id": ("event_id", "eventId", "id", "uuid", "event_uuid", "eventNo", "record_id"),
    "timestamp_utc": ("timestamp_utc", "timestampUtc", "timestamp", "created_at", "createdAt", "occurred_at", "event_time", "eventTime", "time", "datetime", "ts"),
    "event_type": ("event_type", "eventType", "type", "action", "event", "kind", "event_name", "eventName", "category", "severity"),
    "host_id": ("host_id", "hostId", "hostname", "host_name", "hostName", "host.name", "server", "node", "instance"),
    "source": ("source", "program", "service", "process", "facility", "provider"),
    "actor": ("actor", "username", "user_name", "userName", "user", "account", "principal", "subject"),
    "source_ip": ("source_ip", "sourceIp", "ip_address", "ipAddress", "ip", "client_ip", "clientIp", "remote_addr", "remoteAddress", "client.ip", "source.ip", "remote.ip"),
    "details": ("details", "message", "description", "reason", "msg", "event_message", "eventMessage", "summary"),
}


def _key_norm(value: str) -> str:
    return "".join(ch.lower() for ch in str(value) if ch.isalnum())


def find_event_collection(body: Any, *, max_depth: int = 6) -> tuple[str, list[dict[str, Any]]] | None:
    """Find a list of event-like objects and return its dotted JSON path."""
    def walk(node: Any, path: str, depth: int) -> tuple[str, list[dict[str, Any]]] | None:
        if depth > max_depth:
            return None
        if isinstance(node, list):
            if not node and path.split(".")[-1:] and path.split(".")[-1] in _CONTAINER_PRIORITY:
                return path or "$", []
            if node and all(isinstance(item, Mapping) for item in node[: min(20, len(node))]):
                # Refuse mixed/scalar arrays; they are more likely ordinary API data than event records.
                if all(isinstance(item, Mapping) for item in node):
                    return path or "$", [dict(item) for item in node[:100]]
            return None
        if not isinstance(node, Mapping):
            return None
        keys = list(node.keys())
        rank = {_key_norm(key): i for i, key in enumerate(_CONTAINER_PRIORITY)}
        keys.sort(key=lambda key: (rank.get(_key_norm(key), 999), str(key)))
        for key in keys:
            value = node[key]
            child_path = f"{path}.{key}" if path else str(key)
            # An explicitly named event/log container has priority over nested metadata.
            if _key_norm(str(key)) in {_key_norm(k) for k in _CONTAINER_PRIORITY} and isinstance(value, list):
                found = walk(value, child_path, depth + 1)
                if found is not None:
                    return found
        for key in keys:
            value = node[key]
            if isinstance(value, (Mapping, list)):
                child_path = f"{path}.{key}" if path else str(key)
                found = walk(value, child_path, depth + 1)
                if found is not None:
                    return found
        return None

    return walk(body, "", 0)


def _flatten_paths(value: Mapping[str, Any], prefix: str = "", depth: int = 0) -> list[tuple[str, Any, str]]:
    result: list[tuple[str, Any, str]] = []
    if depth > 4:
        return result
    for key, item in value.items():
        key = str(key)
        path = f"{prefix}.{key}" if prefix else key
        result.append((path, item, _key_norm(key)))
        if isinstance(item, Mapping):
            result.extend(_flatten_paths(item, path, depth + 1))
    return result


def _valid_timestamp_sample(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, (int, float)):
        return True
    if not isinstance(value, str) or not value.strip():
        return False
    raw = value.strip()
    if raw.isdigit():
        return True
    candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        parsed = datetime.fromisoformat(candidate)
        return parsed.tzinfo is not None
    except ValueError:
        return False


def infer_event_mapping(sample: Mapping[str, Any]) -> dict[str, str]:
    """Infer common field names from a sample object without guessing secrets."""
    flattened = _flatten_paths(sample)
    by_norm: dict[str, tuple[str, Any]] = {}
    # Preserve the first top-level occurrence; nested path aliases remain supported.
    for path, value, normalized_key in flattened:
        by_norm.setdefault(normalized_key, (path, value))
        by_norm.setdefault(_key_norm(path), (path, value))

    mapping: dict[str, str] = {}
    for target, aliases in _ALIASES.items():
        for alias in aliases:
            found = by_norm.get(_key_norm(alias))
            if found is None:
                continue
            path, value = found
            if target == "timestamp_utc" and not _valid_timestamp_sample(value):
                continue
            if target == "source_ip" and value not in (None, ""):
                try:
                    ipaddress.ip_address(str(value).strip())
                except ValueError:
                    continue
            if isinstance(value, (Mapping, list)):
                continue
            mapping[target] = path
            break
    # Timestamp is required by the normalizer. A weak guess would create false success.
    if "timestamp_utc" not in mapping:
        return {}
    return mapping


def _auth_headers(settings: SyncSettings, token: str) -> dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": "KawalTrace-CompatibilityWizard/2.4.0"}
    mode = settings.feed_auth_mode
    if mode != "none" and (len(token) < 24 or any(ch.isspace() for ch in token)):
        raise ValueError("Token/API key read-only belum tersedia atau formatnya tidak valid.")
    if mode == "bearer" and token:
        headers["Authorization"] = f"Bearer {token}"
    elif mode == "api_key" and token:
        headers["X-API-Key"] = token
    elif mode == "custom_header" and token:
        headers[settings.feed_auth_header_name] = token
    elif mode != "none":
        raise ValueError("Mode autentikasi API tidak didukung.")
    return headers


def probe_readonly_json_event_feed(settings: SyncSettings, token: str = "", *, timeout_seconds: float = 3.5) -> dict[str, Any]:
    """Probe a short fixed list of read-only REST paths at a user-supplied host.

    Returns a diagnostic result; it never changes the remote service.
    """
    checked = settings.validated()
    if checked.connector_type != "generic_rest_readonly":
        raise ValueError("Pilih mode 'API log sudah tersedia' terlebih dahulu.")
    if checked.adapter_protocol != "rest":
        raise ValueError("Deteksi otomatis saat ini hanya untuk REST/JSON. Protokol lain memakai konfigurasi resminya.")
    headers = _auth_headers(checked, token)
    base = checked.base_url.rstrip("/")
    paths: list[str] = []
    for path in (checked.telemetry_path, *COMMON_SECURITY_FEED_PATHS):
        if path.startswith("/") and not path.startswith("//") and path not in paths:
            paths.append(path)
        if len(paths) >= MAX_CANDIDATES:
            break

    diagnostics: list[str] = []
    unsupported_sample: dict[str, Any] | None = None
    empty_candidate: dict[str, Any] | None = None
    try:
        timeout = httpx.Timeout(timeout_seconds, connect=min(2.5, timeout_seconds))
        with httpx.Client(
            verify=checked.ca_bundle or True,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            headers=headers,
        ) as client:
            for path in paths:
                url = base + path
                try:
                    with client.stream("GET", url, params={"limit": 10}, headers=headers) as response:
                        if response.status_code in (401, 403):
                            diagnostics.append(f"{path}: HTTP {response.status_code} (cek kredensial/izin baca)")
                            continue
                        if response.status_code in (301, 302, 303, 307, 308):
                            diagnostics.append(f"{path}: redirect ditolak demi keamanan")
                            continue
                        if not 200 <= response.status_code < 300:
                            diagnostics.append(f"{path}: HTTP {response.status_code}")
                            continue
                        try:
                            body = bounded_response_json(response, max_bytes=MAX_RESPONSE_BYTES)
                        except (ValueError, ResponseBodyTooLargeError):
                            diagnostics.append(f"{path}: respons bukan JSON valid atau melebihi 4 MiB")
                            continue
                        collection = find_event_collection(body)
                        if collection is None:
                            diagnostics.append(f"{path}: JSON ada, tetapi array event tidak ditemukan")
                            continue
                        event_path, events = collection
                        mapping = infer_event_mapping(events[0]) if events else {}
                        if events and not mapping:
                            diagnostics.append(f"{path}: array ditemukan, tetapi timestamp tidak dikenali/berzona waktu")
                            if unsupported_sample is None:
                                unsupported_sample = {
                                    "ok": False, "path": path, "events_path": event_path,
                                    "sample_count": len(events), "mapping": {},
                                    "message": "Endpoint mengembalikan array JSON, tetapi field waktu tidak bisa dipetakan otomatis. Periksa dokumentasi API; tidak ada perubahan profil yang disimpan.",
                                }
                            continue
                        if not events:
                            diagnostics.append(f"{path}: array event ditemukan tetapi kosong")
                            if empty_candidate is None:
                                empty_candidate = {
                                    "ok": True, "path": path, "events_path": event_path,
                                    "sample_count": 0, "mapping": {},
                                    "message": "Endpoint log merespons JSON, tetapi belum ada event contoh. Mapping saat ini dipertahankan; jalankan Uji Koneksi.",
                                }
                            continue
                        return {
                            "ok": True, "path": path, "events_path": event_path,
                            "sample_count": len(events), "mapping": mapping,
                            "message": "Endpoint dan sampel event berhasil dikenali.",
                            "diagnostics": diagnostics,
                        }
                except httpx.TimeoutException:
                    diagnostics.append(f"{path}: timeout")
                except httpx.RequestError as exc:
                    diagnostics.append(f"{path}: koneksi/TLS gagal ({type(exc).__name__})")
    except ValueError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Deteksi endpoint gagal ({type(exc).__name__}).") from exc

    if empty_candidate is not None:
        empty_candidate["diagnostics"] = diagnostics
        return empty_candidate
    if unsupported_sample is not None:
        unsupported_sample["diagnostics"] = diagnostics
        return unsupported_sample
    return {
        "ok": False,
        "path": "",
        "events_path": "",
        "sample_count": 0,
        "mapping": {},
        "message": "Tidak ditemukan endpoint REST/JSON yang cocok pada path umum yang diuji. Gunakan path resmi dari pemilik API atau pilih mode agen.",
        "diagnostics": diagnostics,
    }
