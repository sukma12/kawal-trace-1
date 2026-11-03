"""Read-only client for a server's normalized security-event feed.

The feed API is a separate read scope from client-to-server audit ingestion. The
server must expose GET /api/v1/security-events and enforce an authorization policy.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from .detection import TelemetryValidationError, normalize_server_event
from .http_json import ResponseBodyTooLargeError, bounded_response_json
from .sync import SyncSettings

DEFAULT_SERVER_FEED_PATH = "/api/v1/security-events"


class ServerFeedError(Exception):
    """A server security-feed request failed or returned invalid data."""


class ServerFeedClient:
    def __init__(self, settings: SyncSettings, monitor_token: str, *, timeout_seconds: float = 8.0):
        self.settings = settings.validated()
        self.token = str(monitor_token).strip()
        if len(self.token) < 24 or any(ch.isspace() for ch in self.token):
            raise ServerFeedError("Token monitor/read-only belum valid (minimal 24 karakter).")
        if not 1 <= timeout_seconds <= 30:
            raise ServerFeedError("Timeout feed harus 1–30 detik.")
        self.timeout_seconds = timeout_seconds

    def fetch_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ServerFeedError("Limit feed harus 1–100 event.")
        settings = self.settings
        parsed = urlsplit(settings.base_url + settings.telemetry_path)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ServerFeedError("Endpoint feed tidak valid.")
        verify: bool | str = settings.ca_bundle or True
        try:
            with httpx.Client(
                verify=verify,
                timeout=httpx.Timeout(self.timeout_seconds, connect=min(4.0, self.timeout_seconds)),
                follow_redirects=False,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "X-KAWAL-Device-ID": settings.device_id,
                    "User-Agent": "KawalTrace/2.0.1",
                    "Accept": "application/json",
                },
            ) as client:
                with client.stream("GET", parsed.geturl(), params={"limit": limit}) as response:
                    if not 200 <= response.status_code < 300:
                        hint = "Periksa token read-only dan izin feed" if response.status_code in (401, 403) else "Periksa endpoint/feed API server"
                        raise ServerFeedError(f"Feed server menolak permintaan (HTTP {response.status_code}). {hint}.")
                    try:
                        body = bounded_response_json(response)
                    except ResponseBodyTooLargeError as exc:
                        raise ServerFeedError(f"Feed server ditolak: {exc}") from exc
                    except ValueError as exc:
                        raise ServerFeedError("Feed server tidak mengembalikan JSON UTF-8 yang valid.") from exc
        except httpx.HTTPError as exc:
            raise ServerFeedError(f"Koneksi/TLS feed gagal ({type(exc).__name__}).") from exc
        if not isinstance(body, dict) or not isinstance(body.get("events"), list):
            raise ServerFeedError("Respons feed harus berupa object dengan array 'events'.")
        raw_events = body["events"]
        if len(raw_events) > limit:
            raise ServerFeedError("Feed mengembalikan lebih banyak event daripada limit; hasil ditolak.")
        events: list[dict[str, Any]] = []
        seen: set[str] = set()
        try:
            for raw in raw_events:
                event = normalize_server_event(raw)
                if event["event_id"] not in seen:
                    events.append(event)
                    seen.add(event["event_id"])
        except TelemetryValidationError as exc:
            raise ServerFeedError(f"Feed berisi event tidak valid; data tidak ditampilkan: {exc}.") from exc
        # API contract says newest first, but clients sort locally for stable behavior.
        events.sort(key=lambda item: item["timestamp_epoch"], reverse=True)
        return events


class E2EEServerFeedClient:
    """Read opaque encrypted event envelopes and decrypt locally on the dashboard.

    The API server needs only the public key and never receives the receiver private key.
    Metadata is limited and remains visible for routing/deduplication.
    """
    def __init__(self, settings: SyncSettings, monitor_token: str, receiver_private_key_b64: str, *, timeout_seconds: float = 8.0):
        from .e2ee import public_from_private
        self.settings = settings.validated()
        self.token = str(monitor_token).strip()
        if len(self.token) < 24 or any(ch.isspace() for ch in self.token):
            raise ServerFeedError("Token monitor/read-only belum valid.")
        if not receiver_private_key_b64:
            raise ServerFeedError("Kunci privat E2EE belum tersedia; feed tidak akan diturunkan ke plaintext.")
        try:
            # Validate key before any API call.
            self.public_key_b64 = public_from_private(receiver_private_key_b64)
        except Exception as exc:
            raise ServerFeedError("Kunci privat E2EE tidak valid.") from exc
        if not 1 <= timeout_seconds <= 30:
            raise ServerFeedError("Timeout feed E2EE harus 1–30 detik.")
        self.private_key_b64 = receiver_private_key_b64
        self.timeout_seconds = float(timeout_seconds)

    def fetch_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        from .e2ee import decrypt_payload, E2EEError
        from .detection import TelemetryValidationError
        if not 1 <= limit <= 100:
            raise ServerFeedError("Limit feed harus 1–100 event.")
        settings = self.settings
        url = settings.base_url.rstrip("/") + "/api/v1/encrypted-security-events"
        try:
            with httpx.Client(
                verify=settings.ca_bundle or True,
                timeout=httpx.Timeout(self.timeout_seconds, connect=min(4.0, self.timeout_seconds)),
                follow_redirects=False,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "X-KAWAL-Device-ID": settings.device_id,
                    "User-Agent": "KawalTrace/2.0.1",
                    "Accept": "application/json",
                },
            ) as client:
                with client.stream("GET", url, params={"limit": limit}) as response:
                    if not 200 <= response.status_code < 300:
                        raise ServerFeedError(f"Feed E2EE ditolak server (HTTP {response.status_code}); pastikan API v1.9+ dan token monitor benar.")
                    try:
                        body = bounded_response_json(response)
                    except ResponseBodyTooLargeError as exc:
                        raise ServerFeedError(f"Feed E2EE ditolak: {exc}") from exc
                    except ValueError as exc:
                        raise ServerFeedError("Feed E2EE tidak mengembalikan JSON UTF-8 yang valid.") from exc
        except httpx.HTTPError as exc:
            raise ServerFeedError(f"Koneksi/TLS feed E2EE gagal ({type(exc).__name__}).") from exc
        envelopes = body.get("events") if isinstance(body, dict) else None
        if not isinstance(envelopes, list) or len(envelopes) > limit:
            raise ServerFeedError("Feed E2EE harus mengembalikan array 'events' sesuai limit.")
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for envelope in envelopes:
            try:
                raw = decrypt_payload(self.private_key_b64, envelope)
                if raw.get("event_id") in seen:
                    continue
                normalized.append(normalize_server_event(raw))
                seen.add(str(raw.get("event_id", "")))
            except (E2EEError, TelemetryValidationError, TypeError, ValueError) as exc:
                raise ServerFeedError(f"Envelope E2EE tidak valid atau tidak dapat didekripsi; ditolak seluruh feed: {type(exc).__name__}.") from exc
        normalized.sort(key=lambda item: item["timestamp_epoch"], reverse=True)
        return normalized
