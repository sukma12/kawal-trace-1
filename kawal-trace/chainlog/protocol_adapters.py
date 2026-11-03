"""Read-only adapters for documented security-event APIs.

All adapters only read explicitly configured feeds. No endpoint discovery, write
operations, mutation queries, shell execution, or remote response actions are exposed.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx
from defusedxml import ElementTree as SafeET

from .connectors import GenericRestFeedClient, GenericRestFeedError, _event_type, _path_value, _stable_id
from .detection import TelemetryValidationError, normalize_server_event
from .http_json import ResponseBodyTooLargeError, bounded_response_json
from .sync import SyncSettings

MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 96 * 1024
MAX_EVENTS = 100
MAX_PAGES = 10


class ProtocolAdapterError(Exception):
    """Configured read-only API adapter failed safely."""


def _url_allowed(url: str, *, websocket: bool = False) -> str:
    parsed = urlsplit(str(url or ""))
    allowed_schemes = {"wss", "ws"} if websocket else {"https", "http"}
    if parsed.scheme not in allowed_schemes or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ProtocolAdapterError("URL endpoint tidak valid atau memuat kredensial/fragment.")
    loopback = (parsed.hostname or "").lower() in {"localhost", "127.0.0.1", "::1", "[::1]"}
    if parsed.scheme in {"http", "ws"} and not loopback:
        raise ProtocolAdapterError("Endpoint Internet wajib menggunakan HTTPS/WSS; HTTP/WS hanya untuk loopback lokal.")
    return url


def _bounded_config(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8", errors="replace")) > MAX_CONFIG_BYTES:
        raise ProtocolAdapterError("Konfigurasi adapter melebihi 32 KiB.")
    try:
        config = json.loads(raw or "{}")
    except (TypeError, ValueError) as exc:
        raise ProtocolAdapterError("Konfigurasi adapter harus berupa JSON valid.") from exc
    if not isinstance(config, dict) or len(config) > 64:
        raise ProtocolAdapterError("Konfigurasi adapter harus berupa object JSON dengan maksimal 64 properti.")
    return config


def _safe_path(node: Any, path: str) -> Any:
    if path in {"", "$"}:
        return node
    value = node
    for part in path.split("."):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", part):
            raise ProtocolAdapterError("Path JSON memuat karakter yang tidak didukung.")
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


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
    if abs(number) >= 100_000_000_000:
        number /= 1000.0
    try:
        return datetime.fromtimestamp(number, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return value


def _normalize_json_event(raw: Mapping[str, Any], mapping: dict[str, str], source_name: str) -> dict[str, Any]:
    mapped = {target: _safe_path(raw, path) for target, path in mapping.items()}
    mapped["event_id"] = _stable_id(mapped.get("event_id"), raw)
    mapped["timestamp_utc"] = _coerce_timestamp(mapped.get("timestamp_utc"))
    mapped["event_type"] = _event_type(mapped.get("event_type"))
    mapped["source"] = str(mapped.get("source") or source_name)[:64]
    mapped["host_id"] = str(mapped.get("host_id") or "upstream-server")[:128]
    mapped["actor"] = str(mapped.get("actor") or "unknown")[:128]
    if not isinstance(mapped.get("details"), Mapping):
        details = mapped.get("details")
        mapped["details"] = {"message_excerpt": str(details)[:240]} if details is not None else {}
    try:
        return normalize_server_event(mapped)
    except TelemetryValidationError as exc:
        raise ProtocolAdapterError(f"Event API tidak sesuai skema keamanan: {exc}") from exc


class ReadOnlyProtocolAdapter:
    """Supports REST pagination, OAuth2 client credentials, GraphQL, SOAP/XML, and WebSocket feeds."""

    def __init__(self, settings: SyncSettings, token: str = "", *, client_secret: str = "", timeout_seconds: float = 8.0):
        self.settings = settings.validated()
        if self.settings.connector_type != "generic_rest_readonly":
            raise ProtocolAdapterError("Profile harus menggunakan konektor read-only.")
        if not 1 <= float(timeout_seconds) <= 30:
            raise ProtocolAdapterError("Timeout harus 1–30 detik.")
        self.timeout_seconds = float(timeout_seconds)
        self.token = str(token or "").strip()
        self.client_secret = str(client_secret or "")
        self.config = _bounded_config(getattr(self.settings, "adapter_options_json", "{}"))
        self.protocol = str(getattr(self.settings, "adapter_protocol", "rest") or "rest").strip().lower()
        if self.protocol not in {"rest", "oauth2_rest", "graphql", "soap", "websocket"}:
            raise ProtocolAdapterError("Protokol adapter belum didukung.")
        if self.settings.feed_auth_mode != "none" and self.protocol != "oauth2_rest":
            if len(self.token) < 24 or any(ch.isspace() for ch in self.token):
                raise ProtocolAdapterError("Token read-only belum valid (minimal 24 karakter tanpa spasi).")
        try:
            mapping = json.loads(self.settings.feed_field_mapping)
        except (TypeError, ValueError) as exc:
            raise ProtocolAdapterError("Mapping event harus berupa JSON object.") from exc
        if not isinstance(mapping, dict) or not mapping:
            raise ProtocolAdapterError("Mapping event harus berupa JSON object tidak kosong.")
        self.mapping: dict[str, str] = mapping
        self._oauth_token = ""
        self._oauth_expiry = 0.0
        self._websocket_connection = None
        self._websocket_url = ""

    def close(self) -> None:
        """Release an open persistent WebSocket connection if one exists."""
        connection, self._websocket_connection = self._websocket_connection, None
        self._websocket_url = ""
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

    def _auth_headers(self, token: str | None = None) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "KawalTrace/2.4.0"}
        value = self.token if token is None else token
        mode = self.settings.feed_auth_mode
        if mode == "bearer":
            if value:
                headers["Authorization"] = f"Bearer {value}"
        elif mode == "api_key":
            if value:
                headers["X-API-Key"] = value
        elif mode == "custom_header":
            if value:
                headers[self.settings.feed_auth_header_name] = value
        elif mode != "none":
            raise ProtocolAdapterError("Mode autentikasi API tidak didukung.")
        return headers

    def _oauth_access_token(self) -> str:
        cfg = self.config
        token_url = _url_allowed(str(cfg.get("token_url", "")))
        client_id = str(cfg.get("client_id", "")).strip()
        scope = str(cfg.get("scope", "")).strip()
        client_auth = str(cfg.get("client_auth", "post")).lower()
        if not client_id or len(client_id) > 512 or not self.client_secret:
            raise ProtocolAdapterError("OAuth2 memerlukan client_id dan client_secret yang disimpan di secure storage OS.")
        if client_auth not in {"post", "basic"}:
            raise ProtocolAdapterError("OAuth client_auth harus 'post' atau 'basic'.")
        if self._oauth_token and time.time() < self._oauth_expiry - 30:
            return self._oauth_token
        data = {"grant_type": "client_credentials"}
        if scope:
            data["scope"] = scope[:2000]
        auth = (client_id, self.client_secret) if client_auth == "basic" else None
        if client_auth == "post":
            data["client_id"] = client_id
            data["client_secret"] = self.client_secret
        try:
            with httpx.Client(verify=self.settings.ca_bundle or True,
                              timeout=httpx.Timeout(self.timeout_seconds, connect=min(4.0, self.timeout_seconds)),
                              follow_redirects=False, trust_env=False) as client:
                with client.stream("POST", token_url, data=data, auth=auth, headers={"Accept": "application/json"}) as response:
                    response.raise_for_status()
                    body = bounded_response_json(response)
        except (httpx.HTTPError, ValueError, ResponseBodyTooLargeError) as exc:
            raise ProtocolAdapterError(f"OAuth2 token endpoint gagal ({type(exc).__name__}); rahasia tidak ditampilkan.") from exc
        access_token = body.get("access_token") if isinstance(body, dict) else None
        token_type = str(body.get("token_type", "Bearer")) if isinstance(body, dict) else ""
        try:
            expires_in = max(1, min(86400, int(body.get("expires_in", 300))))
        except (TypeError, ValueError, AttributeError):
            expires_in = 300
        if not isinstance(access_token, str) or not access_token or len(access_token) > 8192 or token_type.lower() != "bearer":
            raise ProtocolAdapterError("Respons OAuth2 tidak menyediakan Bearer access_token yang valid.")
        self._oauth_token = access_token
        self._oauth_expiry = time.time() + expires_in
        return access_token

    def _request(self, method: str, url: str, *, headers: dict[str, str], params: dict[str, Any] | None = None,
                 json_body: Any = None, content: bytes | None = None, content_type: str | None = None) -> tuple[Any, str]:
        _url_allowed(url)
        req_headers = dict(headers)
        if content_type:
            req_headers["Content-Type"] = content_type
        try:
            with httpx.Client(verify=self.settings.ca_bundle or True,
                              timeout=httpx.Timeout(self.timeout_seconds, connect=min(4.0, self.timeout_seconds)),
                              follow_redirects=False, trust_env=False, headers=req_headers) as client:
                with client.stream(method, url, params=params, json=json_body, content=content) as response:
                    if response.status_code < 200 or response.status_code >= 300:
                        raise ProtocolAdapterError(f"API menolak permintaan: HTTP {response.status_code}; periksa izin dan kontrak endpoint.")
                    if content_type and "xml" in content_type:
                        raw = bytearray()
                        for chunk in response.iter_bytes():
                            raw.extend(chunk)
                            if len(raw) > MAX_BODY_BYTES:
                                raise ProtocolAdapterError("Respons SOAP/XML melampaui batas 4 MiB.")
                        return bytes(raw), response.headers.get("content-type", "")
                    try:
                        return bounded_response_json(response), response.headers.get("content-type", "")
                    except (ValueError, ResponseBodyTooLargeError) as exc:
                        raise ProtocolAdapterError(f"Respons API bukan JSON valid atau terlalu besar ({type(exc).__name__}).") from exc
        except ProtocolAdapterError:
            raise
        except httpx.HTTPError as exc:
            raise ProtocolAdapterError(f"Koneksi API gagal ({type(exc).__name__}); periksa TLS, endpoint, dan timeout.") from exc

    def _normalize_records(self, raw_events: Any, limit: int, path_label: str = "events") -> list[dict[str, Any]]:
        if not isinstance(raw_events, list):
            raise ProtocolAdapterError(f"Path event '{path_label}' tidak menunjuk array JSON.")
        if len(raw_events) > 5000:
            raise ProtocolAdapterError("Feed mengirim lebih dari 5000 event; gunakan pagination API.")
        out = []
        for raw in raw_events[:limit]:
            if not isinstance(raw, Mapping):
                raise ProtocolAdapterError("Setiap event JSON wajib berupa object.")
            out.append(_normalize_json_event(raw, self.mapping, self.protocol))
        out.sort(key=lambda e: e["timestamp_epoch"], reverse=True)
        return list({e["event_id"]: e for e in out}.values())[:limit]

    def _json_events(self, body: Any, limit: int) -> list[dict[str, Any]]:
        path = str(self.config.get("events_path", self.settings.feed_json_path))
        return self._normalize_records(_safe_path(body, path), limit, path)

    def _fetch_rest(self, limit: int, oauth: bool = False) -> list[dict[str, Any]]:
        url = self.settings.base_url.rstrip("/") + self.settings.telemetry_path
        pagination = self.config.get("pagination", {})
        if not isinstance(pagination, dict):
            raise ProtocolAdapterError("Konfigurasi pagination harus berupa object.")
        mode = str(pagination.get("mode", "none")).lower()
        if mode not in {"none", "page", "offset", "cursor"}:
            raise ProtocolAdapterError("Pagination mode harus none, page, offset, atau cursor.")
        max_pages = int(pagination.get("max_pages", 1 if mode == "none" else MAX_PAGES))
        if not 1 <= max_pages <= MAX_PAGES:
            raise ProtocolAdapterError("max_pages harus antara 1 dan 10.")
        page_param = str(pagination.get("page_param", "page"))
        offset_param = str(pagination.get("offset_param", "offset"))
        cursor_param = str(pagination.get("cursor_param", "cursor"))
        page_size = int(pagination.get("page_size", min(limit, 100)))
        if not 1 <= page_size <= 100:
            raise ProtocolAdapterError("pagination.page_size harus antara 1 dan 100.")
        base_query_params = self.config.get("query_params", {})
        if not isinstance(base_query_params, dict) or len(base_query_params) > 32:
            raise ProtocolAdapterError("query_params harus berupa object dengan maksimal 32 parameter.")
        reserved_params = {"limit", page_param.lower(), offset_param.lower(), cursor_param.lower()}
        if set(str(k).lower() for k in base_query_params) & reserved_params:
            raise ProtocolAdapterError("query_params tidak boleh menimpa parameter pagination/limit.")
        for key, value in base_query_params.items():
            if not re.fullmatch(r"[A-Za-z0-9_.~-]{1,100}", str(key)) or not isinstance(value, (str, int, float, bool)) or len(str(value)) > 1000:
                raise ProtocolAdapterError("query_params berisi nama/nilai parameter yang tidak valid.")
        items_path = str(pagination.get("items_path", self.config.get("events_path", self.settings.feed_json_path)))
        next_cursor_path = str(pagination.get("next_cursor_path", "next_cursor"))
        if oauth:
            headers = {"Accept": "application/json", "User-Agent": "KawalTrace/2.4.0", "Authorization": f"Bearer {self._oauth_access_token()}"}
        else:
            headers = self._auth_headers()
        found: list[dict[str, Any]] = []
        cursor: Any = None
        seen_cursors: set[str] = set()
        for index in range(max_pages):
            params: dict[str, Any] = dict(base_query_params)
            params["limit"] = min(page_size, limit - len(found), 100)
            if mode == "page": params[page_param] = int(pagination.get("start_page", 1)) + index
            elif mode == "offset": params[offset_param] = int(pagination.get("start_offset", 0)) + (index * page_size)
            elif mode == "cursor" and cursor is not None: params[cursor_param] = cursor
            body, _ = self._request("GET", url, headers=headers, params=params)
            raw_events = _safe_path(body, items_path)
            if not isinstance(raw_events, list):
                raise ProtocolAdapterError(f"Path event '{items_path}' tidak menunjuk array JSON.")
            for raw in raw_events:
                if len(found) >= limit:
                    break
                if not isinstance(raw, Mapping):
                    raise ProtocolAdapterError("Setiap event JSON wajib berupa object.")
                found.append(_normalize_json_event(raw, self.mapping, self.protocol))
            if mode == "none" or len(found) >= limit or not raw_events:
                break
            if mode in {"page", "offset"} and len(raw_events) < params["limit"]:
                break
            if mode == "cursor":
                cursor = _safe_path(body, next_cursor_path)
                if cursor in (None, "", False): break
                marker = json.dumps(cursor, sort_keys=True, default=str)
                if marker in seen_cursors:
                    raise ProtocolAdapterError("API mengembalikan cursor berulang; pagination dihentikan untuk mencegah loop.")
                seen_cursors.add(marker)
        deduped = {e["event_id"]: e for e in found}
        return sorted(deduped.values(), key=lambda e: e["timestamp_epoch"], reverse=True)[:limit]

    def _fetch_graphql(self, limit: int) -> list[dict[str, Any]]:
        cfg = self.config
        raw_query = str(cfg.get("query", ""))
        if len(raw_query) > 16000:
            raise ProtocolAdapterError("GraphQL memerlukan query read-only maksimal 16.000 karakter.")
        query = raw_query.strip()
        if not query:
            raise ProtocolAdapterError("GraphQL memerlukan query read-only maksimal 16.000 karakter.")
        if re.search(r"\b(mutation|subscription)\b", query, re.IGNORECASE):
            raise ProtocolAdapterError("Kawal Trace hanya menerima GraphQL query read-only; mutation/subscription ditolak.")
        variables = cfg.get("variables", {})
        if not isinstance(variables, dict) or len(json.dumps(variables)) > 8000:
            raise ProtocolAdapterError("Variables GraphQL tidak valid atau terlalu besar.")
        headers = self._auth_headers()
        body, _ = self._request("POST", self.settings.base_url.rstrip("/") + self.settings.telemetry_path,
                                headers=headers, json_body={"query": query, "variables": variables})
        if not isinstance(body, dict):
            raise ProtocolAdapterError("Respons GraphQL harus berupa object JSON.")
        if body.get("errors"):
            raise ProtocolAdapterError("GraphQL mengembalikan errors; event tidak diproses sebagian.")
        event_path = str(cfg.get("events_path", "data.events"))
        return self._normalize_records(_safe_path(body, event_path), limit, event_path)

    def _xml_local_name(self, tag: str) -> str:
        return tag.rsplit("}", 1)[-1].split(":")[-1]

    def _xml_path_text(self, node: Any, path: str) -> str | None:
        parts = [part for part in path.strip("/").split("/") if part]
        cur = node
        for part in parts:
            matches = [child for child in list(cur) if self._xml_local_name(child.tag) == part]
            if not matches:
                return None
            cur = matches[0]
        return (cur.text or "").strip() if cur is not None else None

    def _fetch_soap(self, limit: int) -> list[dict[str, Any]]:
        cfg = self.config
        envelope = str(cfg.get("envelope_xml", ""))
        if not envelope or len(envelope.encode("utf-8")) > 64 * 1024:
            raise ProtocolAdapterError("SOAP envelope wajib diisi dan maksimal 64 KiB.")
        if re.search(r"<!\s*(DOCTYPE|ENTITY)", envelope, re.IGNORECASE):
            raise ProtocolAdapterError("DOCTYPE/ENTITY tidak diizinkan pada template SOAP.")
        # Template XML must be well formed. It is only sent to the configured read-only endpoint.
        try:
            envelope_root = SafeET.fromstring(envelope.encode("utf-8"))
        except Exception as exc:
            raise ProtocolAdapterError("Template SOAP XML tidak valid atau berisi konstruksi terlarang.") from exc
        body_node = next((node for node in envelope_root.iter() if self._xml_local_name(node.tag).lower() == "body"), None)
        body_children = list(body_node) if body_node is not None else []
        operation_node = body_children[0] if len(body_children) == 1 else None
        operation_name = self._xml_local_name(operation_node.tag) if operation_node is not None else ""
        if len(body_children) != 1 or not re.match(r"^(Get|List|Fetch|Read|Query|Search|Describe|Enumerate|Find|Retrieve|Lookup)[A-Za-z0-9_]*$", operation_name, re.IGNORECASE):
            raise ProtocolAdapterError("Operasi SOAP tidak dikenal sebagai read-only; gunakan operasi Get/List/Fetch/Read/Query/Search/Describe/Find/Retrieve.")
        action = str(cfg.get("soap_action", "")).strip()
        headers = self._auth_headers()
        if action:
            if len(action) > 500 or "\r" in action or "\n" in action:
                raise ProtocolAdapterError("SOAPAction tidak valid.")
            headers["SOAPAction"] = action
        raw, _ = self._request("POST", self.settings.base_url.rstrip("/") + self.settings.telemetry_path,
                               headers=headers, content=envelope.encode("utf-8"),
                               content_type='text/xml; charset=utf-8')
        try:
            root = SafeET.fromstring(raw)
        except Exception as exc:
            raise ProtocolAdapterError("Respons SOAP/XML tidak valid atau memuat entitas terlarang.") from exc
        event_tag = str(cfg.get("event_tag", "Event"))
        xml_mapping = cfg.get("xml_mapping", {})
        if not isinstance(xml_mapping, dict) or not xml_mapping:
            raise ProtocolAdapterError("SOAP memerlukan xml_mapping field aplikasi ke path XML.")
        if any(self._xml_local_name(node.tag).lower() == "fault" for node in root.iter()):
            raise ProtocolAdapterError("SOAP server mengembalikan Fault; detail provider tidak ditampilkan.")
        events = [node for node in root.iter() if self._xml_local_name(node.tag) == event_tag]
        normalized = []
        for node in events[:limit]:
            raw_item: dict[str, Any] = {}
            for target, path in xml_mapping.items():
                if target not in self.mapping or not isinstance(path, str):
                    raise ProtocolAdapterError(f"Target XML mapping tidak dikenal: {target}.")
                raw_item[target] = self._xml_path_text(node, path)
            # convert this XML-derived mapping into a synthetic JSON object with dotted paths.
            flat_mapping = {key: key for key in raw_item}
            normalized.append(_normalize_json_event(raw_item, flat_mapping, "soap"))
        normalized.sort(key=lambda e: e["timestamp_epoch"], reverse=True)
        return normalized

    def _fetch_websocket(self, limit: int) -> list[dict[str, Any]]:
        try:
            from websockets.sync.client import connect
            from websockets.exceptions import ConnectionClosed
        except ImportError as exc:
            raise ProtocolAdapterError("Untuk WebSocket, pasang dependensi websockets.") from exc
        cfg = self.config
        url = _url_allowed(str(cfg.get("url", "")), websocket=True)
        idle_timeout = float(cfg.get("idle_timeout_seconds", 1.0))
        if not 0.1 <= idle_timeout <= 3.0:
            raise ProtocolAdapterError("WebSocket idle_timeout_seconds harus 0.1–3.0 detik.")
        receive_limit = min(limit, max(1, int(cfg.get("messages_per_poll", 20))))
        headers = self._auth_headers()
        subprotocols = cfg.get("subprotocols", [])
        if not isinstance(subprotocols, list) or len(subprotocols) > 8 or any(not isinstance(p, str) or len(p) > 128 for p in subprotocols):
            raise ProtocolAdapterError("Daftar WebSocket subprotocol tidak valid.")
        events: list[dict[str, Any]] = []
        try:
            if self._websocket_connection is None or self._websocket_url != url:
                self.close()
                self._websocket_connection = connect(
                    url, additional_headers=headers, subprotocols=subprotocols or None,
                    open_timeout=self.timeout_seconds, close_timeout=1, ping_timeout=self.timeout_seconds,
                    max_size=MAX_BODY_BYTES, max_queue=20, proxy=None,
                )
                self._websocket_url = url
            websocket = self._websocket_connection
            for _ in range(receive_limit):
                try:
                    message = websocket.recv(timeout=idle_timeout)
                except TimeoutError:
                    break  # keep the same connection alive for the next five-second polling turn
                if isinstance(message, bytes):
                    message = message.decode("utf-8", errors="strict")
                if not isinstance(message, str) or len(message.encode("utf-8")) > MAX_BODY_BYTES:
                    raise ProtocolAdapterError("Pesan WebSocket melebihi batas atau bukan teks UTF-8.")
                try:
                    body = json.loads(message)
                except ValueError as exc:
                    raise ProtocolAdapterError("Pesan WebSocket bukan JSON valid.") from exc
                event_path = str(cfg.get("events_path", self.settings.feed_json_path))
                candidate = _safe_path(body, event_path)
                if isinstance(candidate, list):
                    records = candidate
                elif isinstance(candidate, Mapping):
                    records = [candidate]
                elif isinstance(body, Mapping):
                    records = [body]
                else:
                    raise ProtocolAdapterError("Pesan WebSocket tidak memuat event object/array.")
                for raw in records:
                    if len(events) >= limit:
                        break
                    if not isinstance(raw, Mapping):
                        raise ProtocolAdapterError("Event WebSocket harus berupa object JSON.")
                    events.append(_normalize_json_event(raw, self.mapping, "websocket"))
                if len(events) >= limit:
                    break
        except ProtocolAdapterError:
            raise
        except (TimeoutError, OSError, ValueError, ConnectionClosed) as exc:
            self.close()
            raise ProtocolAdapterError(f"WebSocket feed gagal ({type(exc).__name__}); koneksi akan dicoba kembali pada polling berikutnya.") from exc
        unique = {e["event_id"]: e for e in events}
        return sorted(unique.values(), key=lambda e: e["timestamp_epoch"], reverse=True)[:limit]

    def fetch_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= int(limit) <= MAX_EVENTS:
            raise ProtocolAdapterError("Limit event harus 1–100.")
        limit = int(limit)
        try:
            if self.protocol == "rest": return self._fetch_rest(limit, oauth=False)
            if self.protocol == "oauth2_rest": return self._fetch_rest(limit, oauth=True)
            if self.protocol == "graphql": return self._fetch_graphql(limit)
            if self.protocol == "soap": return self._fetch_soap(limit)
            if self.protocol == "websocket": return self._fetch_websocket(limit)
        except ProtocolAdapterError:
            raise
        except (ValueError, TypeError, KeyError) as exc:
            raise ProtocolAdapterError(f"Konfigurasi adapter tidak valid ({type(exc).__name__}).") from exc
        raise ProtocolAdapterError("Protokol adapter tidak didukung.")

    def health_check(self) -> dict[str, Any]:
        events = self.fetch_recent(limit=1)
        return {"status": "ok", "connector": "universal_readonly", "protocol": self.protocol, "sample_events": len(events)}


def adapter_secret_fingerprint(secret: str) -> str:
    """Non-reversible cache key; do not use it to store or recover credentials."""
    return hashlib.sha256(str(secret).encode("utf-8", errors="replace")).hexdigest()
