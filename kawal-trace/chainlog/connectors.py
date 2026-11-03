"""Authorized generic REST read-only connector for normalized security-event feeds.

This module deliberately performs only GET requests to the explicitly configured
HTTPS endpoint. It does not scan hosts, enumerate endpoints, or exploit services.
The upstream API owner must authorize the integration and provide the field mapping.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx

from .detection import TelemetryValidationError, normalize_server_event
from .http_json import ResponseBodyTooLargeError, bounded_response_json
from .sync import SyncSettings


class GenericRestFeedError(Exception):
    """Generic REST connector failed or returned data outside the configured schema."""


def _path_value(node: Any, dotted: str) -> Any:
    if dotted == "$":
        return node
    value = node
    for part in dotted.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def _stable_id(raw_id: Any, event: Mapping[str, Any]) -> str:
    value = str(raw_id or "").strip()
    if re.fullmatch(r"[A-Fa-f0-9]{16,128}", value):
        return value.lower()
    canonical = json.dumps({"upstream_id": value, "event": event}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


def _coerce_timestamp(value: Any) -> Any:
    """Normalize Unix seconds/milliseconds from common APIs to ISO-8601 UTC."""
    if isinstance(value, bool) or value is None or isinstance(value, str) and not value.strip():
        return value
    number = None
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str) and re.fullmatch(r"-?\d+(?:\.\d+)?", value.strip()):
        try:
            number = float(value.strip())
        except ValueError:
            number = None
    if number is None:
        return value
    # Values with magnitude typical of Unix milliseconds are converted to seconds.
    if abs(number) >= 100_000_000_000:
        number /= 1000.0
    try:
        return datetime.fromtimestamp(number, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return value


def _event_type(value: Any) -> str:
    key = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "LOGIN_FAILED": "AUTH_FAILURE", "LOGIN_FAILURE": "AUTH_FAILURE", "FAILED_LOGIN": "AUTH_FAILURE",
        "SSH_AUTH_FAILURE": "AUTH_FAILURE", "AUTHENTICATION_FAILURE": "AUTH_FAILURE", "AUTH_FAILED": "AUTH_FAILURE",
        "LOGIN_SUCCESS": "AUTH_SUCCESS", "SUCCESSFUL_LOGIN": "AUTH_SUCCESS", "SSH_AUTH_SUCCESS": "AUTH_SUCCESS",
        "PRIVILEGE_ESCALATION": "PRIVILEGE_USE", "SUDO": "PRIVILEGE_USE", "FILE_MODIFIED": "FILE_CHANGE",
        "FILE_CREATED": "FILE_CHANGE", "FILE_DELETED": "FILE_CHANGE", "CONFIG_CHANGE": "SERVICE_CHANGE",
        "SERVICE_CONFIGURATION_CHANGE": "SERVICE_CHANGE", "HTTP_AUTH_FAILURE": "WEB_AUTH_FAILURE",
        "HTTP_AUTH_SUCCESS": "WEB_AUTH_SUCCESS",
    }
    supported = {
        "AUTH_FAILURE", "AUTH_SUCCESS", "PRIVILEGE_USE", "FILE_CHANGE", "SERVICE_CHANGE",
        "WEB_AUTH_FAILURE", "WEB_AUTH_SUCCESS", "AGENT_HEALTH", "API_AUTH_FAILURE", "API_AUTH_SUCCESS",
        "CUSTOM_SECURITY_EVENT",
    }
    result = aliases.get(key, key)
    return result if result in supported else "CUSTOM_SECURITY_EVENT"


class GenericRestFeedClient:
    """Fetch a mapped, read-only JSON event feed from a server the user is authorized to access."""

    def __init__(self, settings: SyncSettings, token: str, *, timeout_seconds: float = 8.0):
        self.settings = settings.validated()
        if self.settings.connector_type != "generic_rest_readonly":
            raise GenericRestFeedError("Profile bukan bertipe Generic REST read-only.")
        self.token = str(token or "").strip()
        if self.settings.feed_auth_mode != "none" and (len(self.token) < 24 or any(ch.isspace() for ch in self.token)):
            raise GenericRestFeedError("Token/API key read-only belum valid (minimal 24 karakter tanpa spasi).")
        if self.settings.feed_auth_mode == "none" and self.token:
            # Ignore leftover token for no-auth mode; never send it to the API.
            self.token = ""
        if not 1 <= timeout_seconds <= 30:
            raise GenericRestFeedError("Timeout harus 1–30 detik.")
        self.timeout_seconds = float(timeout_seconds)
        try:
            self.mapping = json.loads(self.settings.feed_field_mapping)
        except ValueError as exc:
            raise GenericRestFeedError("Mapping field bukan JSON valid.") from exc

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "KawalTrace/2.4.0"}
        if self.settings.feed_auth_mode == "bearer":
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.settings.feed_auth_mode == "api_key":
            headers["X-API-Key"] = self.token
        elif self.settings.feed_auth_mode == "custom_header":
            headers[self.settings.feed_auth_header_name] = self.token
        elif self.settings.feed_auth_mode == "none":
            pass
        else:
            raise GenericRestFeedError("Mode autentikasi feed tidak didukung.")
        return headers

    def _mapped_event(self, source: Mapping[str, Any]) -> dict[str, Any]:
        mapped: dict[str, Any] = {}
        for target, source_path in self.mapping.items():
            mapped[target] = _path_value(source, source_path)
        mapped["event_id"] = _stable_id(mapped.get("event_id"), source)
        mapped["timestamp_utc"] = _coerce_timestamp(mapped.get("timestamp_utc"))
        mapped["event_type"] = _event_type(mapped.get("event_type"))
        mapped["source"] = str(mapped.get("source") or "generic-rest")[:64]
        mapped["host_id"] = str(mapped.get("host_id") or "upstream-server")[:128]
        mapped["actor"] = str(mapped.get("actor") or "unknown")[:128]
        details = mapped.get("details")
        if not isinstance(details, Mapping):
            mapped["details"] = {"message_excerpt": str(details)[:240]} if details else {}
        return mapped

    def fetch_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise GenericRestFeedError("Limit feed harus 1–100 event.")
        url = self.settings.base_url + self.settings.telemetry_path
        parsed = urlsplit(url)
        if parsed.scheme != "https" and (parsed.hostname or "").lower() not in {"localhost", "127.0.0.1", "::1", "[::1]"}:
            raise GenericRestFeedError("Feed server internet wajib menggunakan HTTPS.")
        try:
            with httpx.Client(
                verify=self.settings.ca_bundle or True,
                timeout=httpx.Timeout(self.timeout_seconds, connect=min(4.0, self.timeout_seconds)),
                follow_redirects=False,
                headers=self._headers(),
            ) as client:
                with client.stream("GET", url, params={"limit": limit}) as response:
                    if not 200 <= response.status_code < 300:
                        hint = "Periksa token dan izin read-only" if response.status_code in {401, 403} else "Periksa path feed, API, dan format auth"
                        raise GenericRestFeedError(f"REST feed menolak permintaan (HTTP {response.status_code}). {hint}.")
                    try:
                        body = bounded_response_json(response)
                    except ResponseBodyTooLargeError as exc:
                        raise GenericRestFeedError(f"REST feed ditolak: {exc}") from exc
                    except ValueError as exc:
                        raise GenericRestFeedError("REST feed tidak mengembalikan JSON UTF-8 yang valid.") from exc
        except httpx.HTTPError as exc:
            raise GenericRestFeedError(f"Koneksi/TLS REST feed gagal ({type(exc).__name__}).") from exc
        raw_events = _path_value(body, self.settings.feed_json_path)
        if not isinstance(raw_events, list):
            raise GenericRestFeedError(
                f"Path JSON '{self.settings.feed_json_path}' tidak menunjuk ke array event. Sesuaikan path/mapping atau buat adapter di server."
            )
        if len(raw_events) > 5000:
            raise GenericRestFeedError("REST feed mengembalikan lebih dari 5000 event; tambahkan pagination/limit pada API.")
        mapped_events: list[dict[str, Any]] = []
        for item in raw_events[:limit]:
            if not isinstance(item, Mapping):
                raise GenericRestFeedError("Setiap event REST harus berupa JSON object.")
            try:
                mapped_events.append(normalize_server_event(self._mapped_event(item)))
            except TelemetryValidationError as exc:
                raise GenericRestFeedError(f"Event REST tidak cocok dengan skema keamanan: {exc}") from exc
        mapped_events.sort(key=lambda item: item["timestamp_epoch"], reverse=True)
        return mapped_events

    def health_check(self) -> dict[str, Any]:
        events = self.fetch_recent(limit=1)
        return {"status": "ok", "connector": "generic_rest_readonly", "sample_events": len(events)}
