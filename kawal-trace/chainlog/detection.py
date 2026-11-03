"""Defensive rule engine for normalized Linux server telemetry.

Rules raise reviewable alerts; they do not claim to identify a human or prove intent.
All input from an external API is treated as untrusted and bounded before use.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import islice
from typing import Any, Iterable, Mapping

MAX_EVENTS = 500
MAX_TEXT = 512
DEFAULT_AUTH_FAILURE_THRESHOLD = 2
DEFAULT_AUTH_FAILURE_WINDOW_SECONDS = 300
_HEX_ID_RE = re.compile(r"^[A-Fa-f0-9]{16,128}$")
_SENSITIVE_PREFIXES = (
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/ssh/", "/etc/sudoers", "/etc/pam.d/", "/etc/systemd/system/",
    "/etc/nginx/", "/etc/apache2/", "/etc/audit/",
)


class TelemetryValidationError(ValueError):
    """A server telemetry event has an invalid or unsupported shape."""


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    if not isinstance(value, (str, int, float, bool)):
        return ""
    # Strip control characters to prevent terminal/log/UI injection.
    return "".join(ch for ch in str(value) if ch >= " " and ch != "\x7f")[:limit]


def _parse_time(value: Any) -> datetime:
    raw = _text(value, 64)
    if not raw:
        raise TelemetryValidationError("timestamp_utc kosong")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise TelemetryValidationError("timestamp_utc bukan ISO-8601") from exc
    if parsed.tzinfo is None:
        raise TelemetryValidationError("timestamp_utc harus memiliki timezone")
    return parsed.astimezone(timezone.utc)


def _safe_ip(value: Any) -> str:
    raw = _text(value, 64)
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise TelemetryValidationError("source_ip bukan alamat IP valid") from exc


def normalize_server_event(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a compact safe schema for an event from the server feed."""
    if not isinstance(raw, Mapping):
        raise TelemetryValidationError("event harus berupa object")
    event_id = _text(raw.get("event_id"), 128)
    if not _HEX_ID_RE.fullmatch(event_id):
        raise TelemetryValidationError("event_id tidak valid")
    event_type = _text(raw.get("event_type"), 48).upper()
    allowed_types = {
        "AUTH_FAILURE", "AUTH_SUCCESS", "PRIVILEGE_USE", "FILE_CHANGE",
        "SERVICE_CHANGE", "WEB_AUTH_FAILURE", "WEB_AUTH_SUCCESS", "AGENT_HEALTH",
        "API_AUTH_FAILURE", "API_AUTH_SUCCESS", "CUSTOM_SECURITY_EVENT", "MALWARE_DETECTED",
    }
    if event_type not in allowed_types:
        raise TelemetryValidationError("event_type tidak didukung")
    timestamp = _parse_time(raw.get("timestamp_utc"))
    details_raw = raw.get("details", {})
    if details_raw is None:
        details_raw = {}
    if not isinstance(details_raw, Mapping):
        raise TelemetryValidationError("details harus berupa object")
    # Only permit a small allow-list. Secrets and arbitrary payloads are discarded.
    details: dict[str, str] = {}
    for key in ("path", "auth_method", "reason", "service", "command_basename", "uid", "rule_key", "message_excerpt", "result",
                "windows_event_id", "log_name", "provider", "logon_type", "reason_code", "image", "process_id",
                "target_user", "group_name", "signature_name"):
        if key in details_raw:
            details[key] = _text(details_raw[key], 256)
    path = details.get("path", "")
    if path and ("\x00" in path or ".." in path.replace("\\", "/").split("/")):
        raise TelemetryValidationError("details.path tidak aman")
    # Optional enrichment supplied by the server/API. GeoIP should be done on the
    # operator's server (prefer a local DB); endpoint inventory must come from an
    # enrolled agent. These are metadata claims, not proof of a person's identity.
    optional_fields = {
        "source_country": 64,
        "source_region": 100,
        "source_city": 100,
        "source_asn": 100,
        "source_org": 180,
        "source_hostname": 128,
        "source_os": 100,
        "source_device_type": 80,
        "source_vendor": 100,
        "source_model": 100,
        "source_user_agent": 240,
        "source_geo_source": 64,
        "source_geo_accuracy": 80,
        "source_device_source": 64,
    }
    enriched = {key: _text(raw.get(key), limit) for key, limit in optional_fields.items()}
    # Coordinates are approximate GeoIP centroids only, not exact-person locations.
    for key, lower, upper in (("source_latitude", -90.0, 90.0), ("source_longitude", -180.0, 180.0)):
        value = raw.get(key)
        try:
            number = float(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            number = None
        if number is not None and lower <= number <= upper:
            enriched[key] = number

    return {
        "event_id": event_id,
        "timestamp_utc": timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "timestamp_epoch": timestamp.timestamp(),
        "host_id": _text(raw.get("host_id"), 128),
        "source": _text(raw.get("source"), 64),
        "event_type": event_type,
        "actor": _text(raw.get("actor"), 128),
        "source_ip": _safe_ip(raw.get("source_ip")),
        **enriched,
        "details": details,
    }


@dataclass(frozen=True)
class SecurityAlert:
    rule_id: str
    severity: str
    title: str
    description: str
    event_ids: tuple[str, ...]
    host_id: str
    source_ip: str = ""
    created_at_utc: str = ""


class DetectionEngine:
    """Small explainable rules for recent server telemetry, not a full SIEM."""

    def __init__(self, *, auth_failure_threshold: int = DEFAULT_AUTH_FAILURE_THRESHOLD, window_seconds: int = DEFAULT_AUTH_FAILURE_WINDOW_SECONDS):
        if not 2 <= auth_failure_threshold <= 100:
            raise ValueError("auth_failure_threshold harus 2–100")
        if not 30 <= window_seconds <= 3600:
            raise ValueError("window_seconds harus 30–3600")
        self.auth_failure_threshold = auth_failure_threshold
        self.window_seconds = window_seconds

    def evaluate(self, raw_events: Iterable[Mapping[str, Any]]) -> list[SecurityAlert]:
        normalized: list[dict[str, Any]] = []
        for raw in islice(iter(raw_events), MAX_EVENTS):
            normalized.append(normalize_server_event(raw))
        normalized.sort(key=lambda e: (e["timestamp_epoch"], e["event_id"]))

        failures: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(deque)
        emitted: set[tuple[str, str]] = set()
        alerts: list[SecurityAlert] = []

        def push(rule: str, severity: str, title: str, description: str, events: list[dict[str, Any]], ip: str = "") -> None:
            if not events:
                return
            newest = events[-1]
            alerts.append(SecurityAlert(
                rule_id=rule,
                severity=severity,
                title=title,
                description=description,
                event_ids=tuple(dict.fromkeys(e["event_id"] for e in events)),
                host_id=newest["host_id"],
                source_ip=ip,
                created_at_utc=newest["timestamp_utc"],
            ))

        for event in normalized:
            kind = event["event_type"]
            ip = event["source_ip"]
            epoch = event["timestamp_epoch"]
            host = event["host_id"] or "unknown-host"
            source = event["source"].lower()

            if kind in {"AUTH_FAILURE", "WEB_AUTH_FAILURE", "API_AUTH_FAILURE"} and ip:
                key = (host, ip)
                window = failures[key]
                window.append(event)
                while window and epoch - window[0]["timestamp_epoch"] > self.window_seconds:
                    window.popleft()
                if len(window) >= self.auth_failure_threshold:
                    bucket = int(epoch // self.window_seconds)
                    dedupe_key = (f"AUTH_FAILURE_BURST:{kind}", f"{host}:{ip}:{bucket}")
                    if dedupe_key not in emitted:
                        emitted.add(dedupe_key)
                        push(
                            "AUTH_FAILURE_BURST", "HIGH",
                            "Lonjakan autentikasi gagal",
                            f"{len(window)} kegagalan autentikasi dari sumber yang sama dalam {self.window_seconds} detik; perlu validasi terhadap jadwal uji dan kebijakan server.",
                            list(window), ip,
                        )

            if kind in {"AUTH_SUCCESS", "WEB_AUTH_SUCCESS", "API_AUTH_SUCCESS"}:
                service_name = event["details"].get("service", "").lower()
                auth_method = event["details"].get("auth_method", "").lower()
                if event["actor"].lower() == "root" and ("ssh" in source or "ssh" in service_name or auth_method == "ssh"):
                    push("ROOT_REMOTE_LOGIN", "HIGH", "Login remote akun root", "Sesi remote akun root teramati. Pastikan ini sesuai kebijakan administrasi.", [event], ip)
                if ip:
                    recent = [e for e in failures.get((host, ip), ()) if epoch - e["timestamp_epoch"] <= 600]
                    if len(recent) >= self.auth_failure_threshold:
                        key = ("AUTH_SUCCESS_AFTER_FAILURES", f"{host}:{ip}:{event['event_id']}")
                        if key not in emitted:
                            emitted.add(key)
                            push(
                                "AUTH_SUCCESS_AFTER_FAILURES", "CRITICAL",
                                "Login berhasil setelah banyak kegagalan",
                                f"Login berhasil dari sumber yang sebelumnya memiliki {len(recent)} kegagalan autentikasi dalam 10 menit.",
                                recent + [event], ip,
                            )

            if kind == "FILE_CHANGE":
                path = event["details"].get("path", "")
                if path and any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in _SENSITIVE_PREFIXES):
                    push(
                        "SENSITIVE_FILE_CHANGE", "HIGH", "Perubahan file sensitif server",
                        f"Audit sistem melaporkan perubahan pada jalur sensitif: {path}. Peristiwa ini perlu ditinjau; belum membuktikan niat pelaku.",
                        [event], ip,
                    )

            if kind == "PRIVILEGE_USE":
                push(
                    "PRIVILEGED_ACTIVITY", "HIGH", "Aktivitas hak istimewa terdeteksi",
                    "Log server melaporkan penggunaan sudo/hak istimewa. Periksa akun, perintah, waktu, dan tiket perubahan; event ini belum membuktikan akses tanpa izin.",
                    [event], ip,
                )

            if kind == "SERVICE_CHANGE":
                push("SERVICE_CONFIGURATION_CHANGE", "HIGH", "Perubahan konfigurasi layanan", "Sumber audit server melaporkan perubahan layanan/konfigurasi.", [event], ip)

            if kind == "MALWARE_DETECTED":
                scan_result = event["details"].get("result", "signature match")
                path = event["details"].get("path", "jalur tidak tersedia")
                push("MALWARE_SIGNATURE_MATCH", "CRITICAL", "Tanda tangan malware cocok",
                     f"Pemindai endpoint melaporkan signature match pada {path} ({scan_result}). Ini perlu isolasi dan validasi analis; tidak menjalankan atau menghapus file otomatis.", [event], ip)

        return alerts
