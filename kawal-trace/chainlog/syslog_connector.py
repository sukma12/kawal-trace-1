"""RFC 5424/3164 syslog ingestion over bounded TCP, with TLS required off-loopback.

The listener is an explicit source connector; it does not start on import. When
binding to a non-loopback interface, a TLS server context requiring client
certificates is mandatory. It never forwards event data to a third party by itself.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import socketserver
import ssl
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from .detection import normalize_server_event

MAX_SYSLOG_MESSAGE_BYTES = 65_536
MAX_SYSLOG_MESSAGES_PER_CONNECTION = 10_000
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2})\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>(?:\[[^\]]*\](?:\s*\[[^\]]*\])*|-))(?:\s+(?P<message>.*))?$"
)
RFC3164_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<tag>[^: ]+)(?:\[[0-9]+\])?:\s*(?P<message>.*)$")


class SyslogConnectorError(ValueError):
    """Invalid listener config or malformed/oversized syslog message."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_syslog_message(raw_message: bytes | str, *, received_at: str | None = None) -> dict[str, Any]:
    if isinstance(raw_message, bytes):
        if len(raw_message) > MAX_SYSLOG_MESSAGE_BYTES:
            raise SyslogConnectorError("Pesan syslog melampaui batas 64 KiB.")
        text = raw_message.decode("utf-8", errors="replace").strip("\r\n\x00")
    else:
        text = str(raw_message).strip("\r\n\x00")
        if len(text.encode("utf-8", errors="replace")) > MAX_SYSLOG_MESSAGE_BYTES:
            raise SyslogConnectorError("Pesan syslog melampaui batas 64 KiB.")
    if not text or any(ord(ch) == 0 for ch in text):
        raise SyslogConnectorError("Pesan syslog kosong atau mengandung null byte.")

    match = RFC5424_RE.match(text)
    if match:
        groups = match.groupdict()
        pri = int(groups["pri"])
        hostname = groups["host"]
        app_name = groups["app"]
        message = groups.get("message") or ""
        stamp = groups["timestamp"]
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            timestamp = parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            timestamp = received_at or _now()
        parse_format = "rfc5424"
    else:
        match = RFC3164_RE.match(text)
        if not match:
            raise SyslogConnectorError("Pesan tidak sesuai framing RFC 5424 atau RFC 3164 yang didukung.")
        groups = match.groupdict()
        pri = int(groups["pri"])
        hostname = groups["host"]
        app_name = re.sub(r"\[\d+\]$", "", groups["tag"])
        message = groups.get("message") or ""
        timestamp = received_at or _now()  # RFC 3164 timestamp has no year/zone; don't guess.
        parse_format = "rfc3164"
    if not 0 <= pri <= 191:
        raise SyslogConnectorError("PRI syslog harus berada pada rentang 0–191.")
    if not hostname or len(hostname) > 255 or len(app_name) > 48:
        raise SyslogConnectorError("Hostname atau app-name syslog tidak valid.")
    message = message[:MAX_SYSLOG_MESSAGE_BYTES]
    lower = message.lower()
    if any(m in lower for m in ("failed password", "authentication failure", "invalid user", "login failed", "failed login", "login failure")):
        event_type, reason = "AUTH_FAILURE", "authentication_failed"
    elif any(m in lower for m in ("accepted password", "accepted publickey", "login succeeded", "authentication succeeded", "logged in from")):
        event_type, reason = "AUTH_SUCCESS", "authentication_succeeded"
    elif "sudo" in lower and ("command=" in lower or "executed" in lower):
        event_type, reason = "PRIVILEGE_USE", "privileged_command"
    elif "audit" in app_name.lower() and any(m in lower for m in ("deleted", "modified", "created", "permission")):
        event_type, reason = "FILE_CHANGE", "audit_record"
    else:
        event_type, reason = "CUSTOM_SECURITY_EVENT", "syslog_message"

    source_ip = ""
    for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{3,})(?![\w.])", message):
        try:
            source_ip = str(ipaddress.ip_address(candidate.strip("[]")))
            break
        except ValueError:
            continue
    actor = "unknown"
    for pattern in (r"Failed password for (?:invalid user )?([^\s]+)", r"Accepted (?:password|publickey|keyboard-interactive) for ([^\s]+)", r"Invalid user ([^\s]+)", r"sudo:\s*([^\s:]+)\s*:",
                    # Message-text shape used by MikroTik RouterOS logs ("login failure for user X from IP via winbox")
                    r"login failure for user ([^\s]+)", r"user ([^\s]+) logged in from"):
        m = re.search(pattern, message, re.IGNORECASE)
        if m:
            actor = m.group(1)[:128]
            break
    via = re.search(r"\bvia (winbox|ssh|telnet|api-ssl|api|ftp|www-ssl|www|web)\b", message, re.IGNORECASE)
    event_id = hashlib.sha256((text + "\x00" + timestamp).encode("utf-8", errors="replace")).hexdigest()
    raw = {
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "event_type": event_type,
        "host_id": hostname[:128],
        "source": app_name[:64],
        "actor": actor,
        "source_ip": source_ip,
        "details": {"message_excerpt": message[:256], "service": app_name[:64], "reason": reason, "provider": parse_format},
    }
    if via:
        raw["details"]["auth_method"] = via.group(1).lower()
    try:
        return normalize_server_event(raw)
    except Exception as exc:
        raise SyslogConnectorError("Pesan syslog tidak dapat dinormalisasi ke skema event yang diizinkan.") from exc


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = True


class SyslogTCPReceiver:
    """Explicitly started RFC5424/3164 TCP listener for owned/authorized sources."""

    def __init__(self, host: str, port: int, event_handler: Callable[[dict[str, Any]], None], *,
                 tls_context: ssl.SSLContext | None = None, timeout_seconds: int = 5,
                 max_message_bytes: int = MAX_SYSLOG_MESSAGE_BYTES):
        try:
            host_value = str(host).strip()
            host_ip = ipaddress.ip_address(host_value)
            port_value = int(port)
            timeout = int(timeout_seconds)
            message_cap = int(max_message_bytes)
        except (TypeError, ValueError) as exc:
            raise SyslogConnectorError("Host listener wajib berupa IP literal dan port/timeout valid.") from exc
        if not 0 <= port_value <= 65535 or not 1 <= timeout <= 30 or not 512 <= message_cap <= MAX_SYSLOG_MESSAGE_BYTES:
            raise SyslogConnectorError("Port harus 0–65535, timeout 1–30 detik, ukuran pesan 512–65536 byte.")
        if not host_ip.is_loopback:
            if tls_context is None:
                raise SyslogConnectorError("Syslog non-loopback memerlukan TLS; plaintext listener jaringan dilarang.")
            if tls_context.verify_mode != ssl.CERT_REQUIRED:
                raise SyslogConnectorError("Syslog TLS non-loopback wajib memverifikasi sertifikat klien (mTLS).")
        if not callable(event_handler):
            raise SyslogConnectorError("Event handler harus berupa callable.")
        self.host = str(host_ip)
        self.port = port_value
        self.event_handler = event_handler
        self.tls_context = tls_context
        self.timeout_seconds = timeout
        self.max_message_bytes = message_cap
        self.received_count = 0
        self.rejected_count = 0
        self._server: _ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def address(self) -> tuple[str, int] | None:
        if self._server is None:
            return None
        return self._server.server_address[:2]

    def start(self) -> tuple[str, int]:
        if self._server is not None:
            return self._server.server_address[:2]
        parent = self

        class ConfiguredServer(_ThreadingTCPServer):
            def get_request(self):
                request, client_address = super().get_request()
                if parent.tls_context is not None:
                    # Bound the TLS handshake itself. Otherwise a client that opens
                    # TCP and never starts TLS could stall the accept loop forever.
                    request.settimeout(parent.timeout_seconds)
                    try:
                        request = parent.tls_context.wrap_socket(request, server_side=True)
                        request.settimeout(None)
                    except Exception:
                        request.close()
                        raise
                return request, client_address

        class Handler(socketserver.StreamRequestHandler):
            def setup(self):
                super().setup()
                self.request.settimeout(parent.timeout_seconds)
                self._messages = 0

            def _read_frame(self) -> bytes | None:
                first = self.rfile.read(1)
                if not first:
                    return None
                # RFC 6587 octet-counting framing: '<length> <payload>'.
                if first.isdigit():
                    digits = bytearray(first)
                    while len(digits) <= 10:
                        ch = self.rfile.read(1)
                        if not ch:
                            return None
                        if ch == b" ":
                            break
                        if not ch.isdigit():
                            # Not a valid length prefix; reject instead of guessing.
                            raise SyslogConnectorError("Framing RFC 6587 tidak valid.")
                        digits.extend(ch)
                    else:
                        raise SyslogConnectorError("Panjang framing RFC 6587 terlalu besar.")
                    length = int(digits.decode("ascii"))
                    if not 1 <= length <= parent.max_message_bytes:
                        raise SyslogConnectorError("Ukuran pesan framing syslog tidak valid.")
                    payload = self.rfile.read(length)
                    if len(payload) != length:
                        raise SyslogConnectorError("Pesan framing syslog terpotong.")
                    return payload
                # Common line-delimited syslog framing.
                rest = self.rfile.readline(parent.max_message_bytes + 2)
                payload = first + rest
                if len(payload) > parent.max_message_bytes:
                    raise SyslogConnectorError("Pesan syslog melampaui batas ukuran.")
                return payload.rstrip(b"\r\n")

            def handle(self):
                while self._messages < MAX_SYSLOG_MESSAGES_PER_CONNECTION:
                    try:
                        payload = self._read_frame()
                        if payload is None:
                            return
                        event = parse_syslog_message(payload)
                        parent.event_handler(event)
                        with parent._lock:
                            parent.received_count += 1
                        self._messages += 1
                    except (SyslogConnectorError, OSError, TimeoutError):
                        with parent._lock:
                            parent.rejected_count += 1
                        return
                    except Exception:
                        with parent._lock:
                            parent.rejected_count += 1
                        return

        server = ConfiguredServer((self.host, self.port), Handler)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True, name="KawalTraceSyslog")
        self._thread.start()
        return server.server_address[:2]

    def close(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def __enter__(self) -> "SyslogTCPReceiver":
        self.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()
