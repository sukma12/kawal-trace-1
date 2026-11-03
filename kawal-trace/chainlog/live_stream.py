"""Real-time "doorbell" client for the Kawal-Trace server stream (Server-Sent Events over HTTPS).

The stream tells the app WHICH kind of server data changed; it never carries the data. On every doorbell the
app pulls through the same authenticated, size-bounded, validated feed it already uses, so:

* a lost, duplicated or forged message cannot hide an event or invent one;
* nothing from this device is ever sent to the server (the request is a bodyless GET);
* the app works from any network, because the connection is outbound HTTPS from the app to the server.

The pieces are small and separately testable: `parse_sse` (bounded wire parser), `interpret` (strict message
validation), `LiveStreamClient` (one connection), `LiveStreamSupervisor` (reconnect with backoff and honest
status), `DoorbellCoalescer` (bursts become one refresh) and `poll_interval_seconds` (how often the safety-net
poll runs, which is rare while the stream is healthy).
"""
from __future__ import annotations

import json
import random
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, NamedTuple

import httpx

from .sync import SyncError, SyncSettings

STREAM_PATH = "/api/v1/stream"
ALL_KINDS: frozenset[str] = frozenset({"security", "encrypted", "actions", "windows"})
PROTOCOL_VERSION = 1
MAX_LINE_BYTES = 2048
MAX_MESSAGE_BYTES = 4096
KNOWN_BYE_REASONS = frozenset({"replaced", "lifetime"})

# Connection states reported to the UI. They are the only truth the UI may show about "real-time".
STATE_CONNECTING = "connecting"
STATE_LIVE = "live"
STATE_RETRYING = "retrying"
STATE_UNSUPPORTED = "unsupported"
STATE_UNAUTHORIZED = "unauthorized"
STATE_STOPPED = "stopped"


class LiveStreamError(Exception):
    """The stream could not be used; the supervisor decides whether to retry."""


class StreamProtocolError(LiveStreamError):
    """The peer sent something that is not the documented stream format."""


class StreamAuthError(LiveStreamError):
    """The server refused the monitor token (HTTP 401/403). Retrying cannot help."""


class StreamUnsupportedError(LiveStreamError):
    """This server has no stream endpoint (older API). The app keeps polling instead."""


class SSEMessage(NamedTuple):
    event: str
    data: str
    id: str


@dataclass(frozen=True)
class StreamSignal:
    kind: str                       # hello | state | bye | revoked
    changed: frozenset[str] = frozenset()
    reason: str = ""
    heartbeat_seconds: float | None = None


def iter_lines_bounded(chunks: Iterable[bytes], *, max_line_bytes: int = MAX_LINE_BYTES) -> Iterator[str]:
    """Split a byte stream into lines, refusing a line longer than `max_line_bytes` before buffering it."""
    buffer = bytearray()
    for chunk in chunks:
        if not chunk:
            continue
        buffer.extend(chunk)
        while True:
            newline = buffer.find(b"\n")
            if newline < 0:
                if len(buffer) > max_line_bytes:
                    raise StreamProtocolError("Baris stream melebihi batas aman; koneksi ditutup.")
                break
            if newline > max_line_bytes:
                raise StreamProtocolError("Baris stream melebihi batas aman; koneksi ditutup.")
            raw = bytes(buffer[:newline])
            del buffer[:newline + 1]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            try:
                yield raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise StreamProtocolError("Stream berisi byte non-UTF-8.") from exc


def parse_sse(lines: Iterable[str], *, max_message_bytes: int = MAX_MESSAGE_BYTES) -> Iterator[SSEMessage]:
    """Parse already-split lines per the SSE format. Comments (heartbeats) and unknown fields are ignored."""
    event, ident = "", ""
    data: list[str] = []
    size = 0
    for line in lines:
        if line == "":
            if data or event:
                yield SSEMessage(event or "message", "\n".join(data), ident)
            event, ident, data, size = "", "", [], 0
            continue
        if line.startswith(":"):
            continue
        name, _sep, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        size += len(line)
        if size > max_message_bytes:
            raise StreamProtocolError("Pesan stream melebihi batas aman; koneksi ditutup.")
        if name == "event":
            event = value[:32]
        elif name == "data":
            data.append(value)
        elif name == "id":
            ident = value[:64]
        # "retry" and unknown fields are deliberately ignored: reconnect timing is the supervisor's decision.


def interpret(message: SSEMessage) -> StreamSignal | None:
    """Turn a wire message into a signal, or None for anything unknown, malformed or from a newer protocol."""
    if message.event not in {"hello", "state", "bye", "revoked"}:
        return None
    try:
        body = json.loads(message.data) if message.data else {}
    except ValueError:
        return None
    if not isinstance(body, dict) or body.get("v") != PROTOCOL_VERSION:
        return None
    if message.event == "hello":
        heartbeat = body.get("heartbeat_seconds")
        if isinstance(heartbeat, bool) or not isinstance(heartbeat, (int, float)) or not 0.05 <= heartbeat <= 120:
            heartbeat = None
        # A (re)connection may have missed changes, so hello always means "catch up on everything".
        return StreamSignal("hello", ALL_KINDS, heartbeat_seconds=float(heartbeat) if heartbeat is not None else None)
    if message.event == "state":
        raw = body.get("changed")
        if not isinstance(raw, list):
            return None
        kinds = frozenset(item for item in raw if isinstance(item, str) and item in ALL_KINDS)
        return StreamSignal("state", kinds) if kinds else None
    if message.event == "bye":
        reason = body.get("reason")
        return StreamSignal("bye", reason=reason if reason in KNOWN_BYE_REASONS else "unknown")
    return StreamSignal("revoked")


class LiveStreamClient:
    """One HTTPS connection to the stream. Read-only: a bodyless GET with the monitor token."""

    def __init__(self, settings: SyncSettings, monitor_token: str, *, connect_timeout: float = 6.0,
                 read_timeout: float = 40.0, transport: httpx.BaseTransport | None = None):
        # Setup problems can never fix themselves by retrying, so they surface as the non-retryable auth error.
        try:
            self.settings = settings.validated()
        except SyncError as exc:
            raise StreamAuthError(f"Pengaturan server tidak valid: {exc}") from exc
        self.token = str(monitor_token).strip()
        if len(self.token) < 24 or any(ch.isspace() for ch in self.token):
            raise StreamAuthError("Token monitor/read-only belum valid (minimal 24 karakter).")
        if not 1 <= connect_timeout <= 30 or not 5 <= read_timeout <= 120:
            raise StreamAuthError("Timeout stream di luar batas aman.")
        self.connect_timeout = connect_timeout
        # The server heartbeats at most every 30 s (default 15 s); silence for longer means a dead link.
        self.read_timeout = read_timeout
        self._transport = transport
        self._lock = threading.Lock()
        self._response: httpx.Response | None = None

    @property
    def url(self) -> str:
        return self.settings.base_url.rstrip("/") + STREAM_PATH

    def close(self) -> None:
        """Best-effort close from another thread; the reader also checks its stop flag on every chunk."""
        with self._lock:
            response = self._response
        if response is not None:
            try:
                response.close()
            except Exception:  # noqa: BLE001 - closing a half-dead socket may raise anything
                pass

    def run_once(self, on_signal: Callable[[StreamSignal], None], stop: threading.Event) -> str:
        """Hold one connection open. Returns why it ended; raises for auth/unsupported/protocol failures."""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "X-KAWAL-Device-ID": self.settings.device_id,
            "User-Agent": "KawalTrace/2.0.1",
            "Accept": "text/event-stream",
            "Accept-Encoding": "identity",   # a compressing proxy would hold heartbeats back in its buffer
            "Cache-Control": "no-store",
        }
        timeout = httpx.Timeout(self.read_timeout, connect=self.connect_timeout)
        try:
            with httpx.Client(verify=self.settings.ca_bundle or True, timeout=timeout, follow_redirects=False,
                              transport=self._transport) as client:
                with client.stream("GET", self.url, headers=headers) as response:
                    with self._lock:
                        self._response = response
                    try:
                        return self._consume(response, on_signal, stop)
                    finally:
                        with self._lock:
                            self._response = None
        except httpx.HTTPError as exc:
            if stop.is_set():
                return "stopped"
            raise LiveStreamError(f"Koneksi stream terputus ({type(exc).__name__}).") from exc

    def _consume(self, response: httpx.Response, on_signal: Callable[[StreamSignal], None], stop: threading.Event) -> str:
        status = response.status_code
        if status in (401, 403):
            raise StreamAuthError("Server menolak token monitor untuk stream (HTTP %d)." % status)
        if status in (404, 405, 501):
            raise StreamUnsupportedError("Server ini belum mendukung stream real-time (API lebih lama).")
        if status != 200:
            raise LiveStreamError(f"Server menolak stream (HTTP {status}).")
        if not response.headers.get("content-type", "").lower().startswith("text/event-stream"):
            raise StreamProtocolError("Server tidak mengirim text/event-stream (mungkin portal login/proxy).")
        for message in parse_sse(iter_lines_bounded(response.iter_raw())):
            if stop.is_set():
                return "stopped"
            signal = interpret(message)
            if signal is None:
                continue
            if signal.kind == "revoked":
                raise StreamAuthError("Akses perangkat ini dicabut di server.")
            on_signal(signal)
            if signal.kind == "bye":
                return f"bye:{signal.reason}"
        return "stopped" if stop.is_set() else "closed"


def backoff_delay(attempt: int, *, base: float = 1.0, cap: float = 60.0, rng: Callable[[], float] = random.random) -> float:
    """Exponential backoff with equal jitter: half fixed, half random, so many apps never reconnect in lockstep."""
    ceiling = min(cap, base * (2 ** max(0, attempt)))
    return ceiling / 2 + (ceiling / 2) * rng()


class LiveStreamSupervisor:
    """Keeps one stream alive on a daemon thread, reconnecting politely, and reports an honest state."""

    STABLE_SECONDS = 20.0          # a connection must last this long before the backoff is forgiven
    REPLACED_PAUSE_SECONDS = 30.0  # another app instance took the slot; do not fight it

    def __init__(self, client_factory: Callable[[], LiveStreamClient], on_signal: Callable[[frozenset[str]], None],
                 on_status: Callable[[str, str], None], *, clock: Callable[[], float] = time.monotonic,
                 rng: Callable[[], float] = random.random, wait: Callable[[float], bool] | None = None):
        self._factory = client_factory
        self._on_signal = on_signal
        self._on_status = on_status
        self._clock = clock
        self._rng = rng
        self._stop = threading.Event()
        self._wait = wait or self._stop.wait   # returns True when stopped; injectable so tests need no real sleeping
        self._thread: threading.Thread | None = None
        self._client: LiveStreamClient | None = None
        self._state = STATE_STOPPED
        self._state_lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._state_lock:
            return self._state

    def _report(self, state: str, detail: str = "") -> None:
        with self._state_lock:
            self._state = state
        try:
            self._on_status(state, detail)
        except Exception:  # noqa: BLE001 - a UI callback must never kill the stream thread
            pass

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="kawal-live-stream", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        client = self._client
        if client is not None:
            client.close()
        self._report(STATE_STOPPED, "")

    def join(self, timeout: float = 5.0) -> None:
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def _deliver(self, signal: StreamSignal) -> None:
        if self._stop.is_set():
            return
        if signal.kind == "hello":
            self._report(STATE_LIVE, "")
        if signal.changed:
            try:
                self._on_signal(signal.changed)
            except Exception:  # noqa: BLE001
                pass

    def _run(self) -> None:
        attempt = 0
        while not self._stop.is_set():
            self._report(STATE_CONNECTING if attempt == 0 else STATE_RETRYING, "")
            started = self._clock()
            pause = 0.0
            try:
                client = self._factory()
                self._client = client
                reason = client.run_once(self._deliver, self._stop)
            except StreamAuthError as exc:
                self._report(STATE_UNAUTHORIZED, str(exc))
                return
            except StreamUnsupportedError as exc:
                self._report(STATE_UNSUPPORTED, str(exc))
                return
            except LiveStreamError as exc:
                reason = f"error:{exc}"
            except Exception as exc:  # noqa: BLE001 - never let the thread die silently while the UI says "live"
                reason = f"error:{type(exc).__name__}"
            finally:
                self._client = None
            if self._stop.is_set():
                return
            lasted = self._clock() - started
            if reason == "bye:replaced":
                pause = self.REPLACED_PAUSE_SECONDS   # another app instance took the slot; not a failure
            elif reason == "bye:lifetime":
                pause = 0.5 + self._rng()             # routine rotation, not a failure
                attempt = 0
            else:
                if lasted >= self.STABLE_SECONDS:
                    attempt = 0                       # it worked for a while: start the delays over
                pause = backoff_delay(attempt, rng=self._rng)
                attempt += 1
            detail = reason[6:] if reason.startswith("error:") else ""
            self._report(STATE_RETRYING, detail or reason)
            if self._wait(pause):
                return


class Take(NamedTuple):
    kinds: frozenset[str]
    retry_after: float | None


class DoorbellCoalescer:
    """Turns a burst of doorbells into at most one refresh per `min_interval`, never dropping a kind."""

    def __init__(self, min_interval: float = 1.0, clock: Callable[[], float] = time.monotonic):
        if not 0 <= min_interval <= 60:
            raise ValueError("min_interval must be 0..60 seconds")
        self._min = min_interval
        self._clock = clock
        self._lock = threading.Lock()
        self._pending: set[str] = set()
        self._last_take = float("-inf")

    def ring(self, kinds: Iterable[str]) -> None:
        valid = {k for k in kinds if k in ALL_KINDS}
        if valid:
            with self._lock:
                self._pending |= valid

    def take(self) -> Take:
        with self._lock:
            if not self._pending:
                return Take(frozenset(), None)
            wait = self._last_take + self._min - self._clock()
            if wait > 0:
                return Take(frozenset(), wait)
            kinds = frozenset(self._pending)
            self._pending.clear()
            self._last_take = self._clock()
            return Take(kinds, None)


def poll_interval_seconds(stream_state: str) -> float:
    """Safety-net poll cadence. A healthy stream makes frequent polling pointless (and costs battery/data)."""
    if stream_state == STATE_LIVE:
        return 30.0
    if stream_state in (STATE_CONNECTING, STATE_RETRYING):
        return 10.0
    return 5.0   # no stream (older server, revoked, stopped): behave exactly as before


def status_text(state: str, detail: str = "") -> str:
    """Indonesian one-liner for the UI. 'LIVE' is claimed only while the stream is actually connected."""
    if state == STATE_LIVE:
        return "REAL-TIME AKTIF · server memberi sinyal begitu ada perubahan"
    if state == STATE_CONNECTING:
        return "MENYAMBUNGKAN STREAM · sementara memakai polling"
    if state == STATE_RETRYING:
        suffix = f" ({detail[:80]})" if detail else ""
        return f"STREAM TERPUTUS{suffix} · mencoba lagi, sementara memakai polling"
    if state == STATE_UNSUPPORTED:
        return "SERVER BELUM MENDUKUNG STREAM · memakai polling tiap 5 detik (perbarui API server ke 1.5.0)"
    if state == STATE_UNAUTHORIZED:
        suffix = f" ({detail[:100]})" if detail else ""
        return f"STREAM DITOLAK{suffix} · token monitor tidak diterima atau akses dicabut; periksa token"
    return "STREAM MATI · memakai polling"
