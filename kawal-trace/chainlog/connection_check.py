"""Step-by-step diagnosis of the path from this device to a Kawal-Trace server (any distance, any network).

Each step names what it proved, or the most likely cause when it did not, in plain Indonesian. The check only
READS: GET /healthz, GET /api/v1/security-events?limit=1 and a short-lived GET /api/v1/stream. It never posts
an event, never queues a response action and never sends anything about this device except the Device ID header.
The monitor token is read from the environment by the caller; it is never printed.
"""
from __future__ import annotations

import socket
import ssl
import statistics
import threading
import time
from dataclasses import dataclass
from typing import Callable

import httpx

from .live_stream import LiveStreamClient, LiveStreamError, StreamAuthError, StreamProtocolError, StreamSignal, StreamUnsupportedError
from .sync import SyncError, SyncSettings

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"
SLOW_ROUND_TRIP_SECONDS = 0.8


@dataclass(frozen=True)
class CheckResult:
    name: str
    level: str           # ok | warn | fail | skip
    detail: str
    hint: str = ""


def _cause_chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        chain.append(current)
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return chain


def classify_connection_error(exc: BaseException, timeout: float) -> tuple[str, str]:
    """(what happened, what to check) from the real exception chain, not from translated message text."""
    chain = _cause_chain(exc)
    if any(isinstance(item, ssl.SSLCertVerificationError) for item in chain):
        return ("Sertifikat HTTPS server tidak dipercaya.",
                "Pastikan alamat memakai nama domain yang cocok dengan sertifikat (bukan alamat IP), sertifikat belum kedaluwarsa, "
                "dan jam perangkat ini benar. Jangan mematikan verifikasi TLS.")
    if any(isinstance(item, ssl.SSLError) for item in chain):
        return ("Jabat tangan TLS gagal.", "Server mungkin tidak melayani HTTPS pada port itu, atau ada perangkat jaringan yang mencegat koneksi.")
    if any(isinstance(item, socket.gaierror) for item in chain):
        return ("Nama server tidak dapat diterjemahkan (DNS).", "Periksa penulisan alamat dan koneksi internet perangkat ini; coba ganti DNS atau jaringan.")
    if any(isinstance(item, ConnectionRefusedError) for item in chain):
        return ("Koneksi ditolak server.", "Layanan di server mati atau port salah. Jika memakai Cloudflare Tunnel, pastikan cloudflared dan layanan API berjalan.")
    if isinstance(exc, (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout)) or any(isinstance(item, TimeoutError) for item in chain):
        return (f"Tidak ada jawaban dalam {timeout:.0f} detik.",
                "Server mati, diblokir firewall, atau jaringan perangkat ini memblokir akses keluar. Coba dari jaringan lain (mis. data seluler).")
    return (f"Koneksi gagal ({type(exc).__name__}).", "Periksa alamat, koneksi internet, dan apakah server sedang berjalan.")


def run_checks(base_url: str, device_id: str, monitor_token: str, *, ca_bundle: str = "", timeout: float = 8.0,
               stream_wait: float = 12.0, transport: httpx.BaseTransport | None = None,
               clock: Callable[[], float] = time.monotonic) -> list[CheckResult]:
    results: list[CheckResult] = []

    def add(name: str, level: str, detail: str, hint: str = "") -> CheckResult:
        result = CheckResult(name, level, detail, hint)
        results.append(result)
        return result

    def skip_rest(reason: str, names: list[str]) -> None:
        for name in names:
            add(name, SKIP, reason)

    later = ["Server menjawab", "Token & Device ID", "Feed telemetri", "Stream real-time", "Kecepatan"]
    try:
        settings = SyncSettings(base_url=base_url, device_id=device_id).validated()
    except SyncError as exc:
        add("Alamat server", FAIL, str(exc), "Gunakan alamat HTTPS lengkap, mis. https://monitor.contoh.id (tanpa path, kredensial, atau query).")
        skip_rest("dilewati karena alamat tidak valid", later)
        return results
    add("Alamat server", OK, settings.base_url)
    token = str(monitor_token or "").strip()
    if len(token) < 24 or any(ch.isspace() for ch in token):
        add("Token monitor", FAIL, "Token monitor (read-only) belum diisi atau bentuknya salah.",
            "Salin hanya nilainya (minimal 24 karakter, tanpa spasi) dari KAWAL_MONITOR_TOKENS di server.")
        skip_rest("dilewati karena token belum benar", later)
        return results
    headers = {"Authorization": f"Bearer {token}", "X-KAWAL-Device-ID": settings.device_id, "Accept": "application/json",
               "User-Agent": "KawalTrace-check/1"}
    base = settings.base_url

    def get(client: httpx.Client, path: str) -> tuple[httpx.Response, float]:
        started = clock()
        response = client.get(base + path, headers=headers)
        return response, clock() - started

    try:
        with httpx.Client(verify=ca_bundle or True, timeout=httpx.Timeout(timeout, connect=min(timeout, 6.0)),
                          follow_redirects=False, transport=transport) as client:
            try:
                health, first_rtt = get(client, "/healthz")
            except httpx.HTTPError as exc:
                what, hint = classify_connection_error(exc, timeout)
                add("Server menjawab", FAIL, what, hint)
                skip_rest("dilewati karena server tidak terjangkau", later[1:])
                return results
            add("Server menjawab", OK, f"HTTPS tersambung dan sertifikat tepercaya ({first_rtt * 1000:.0f} ms)")

            features: list[str] = []
            if health.status_code in (401, 403):
                add("Token & Device ID", FAIL, f"Server menolak token atau Device ID (HTTP {health.status_code}).",
                    "Token monitor harus pasangan dari Device ID yang sama di KAWAL_MONITOR_TOKENS. Jika akses dicabut, minta pemilik server mendaftarkan ulang.")
                skip_rest("dilewati karena token ditolak", later[2:])
                return results
            body = None
            if health.status_code == 200:
                try:
                    body = health.json()
                except ValueError:
                    body = None
            if not (isinstance(body, dict) and body.get("service") == "kawal-trace-api"):
                if health.status_code in (502, 503, 504, 520, 521, 522, 523, 524, 530):
                    add("Token & Device ID", FAIL, f"Gerbang di depan server menjawab HTTP {health.status_code}.",
                        "Cloudflare Tunnel/proxy hidup tetapi tidak bisa menjangkau layanan API: pastikan layanan kawal-trace-api berjalan dan tunnel menunjuk ke 127.0.0.1:8765.")
                else:
                    add("Token & Device ID", FAIL, f"Alamat itu menjawab HTTP {health.status_code} tetapi bukan Kawal-Trace API.",
                        "Periksa bahwa alamat/tunnel menunjuk ke layanan API Kawal-Trace, bukan situs lain.")
                skip_rest("dilewati karena API tidak dikenali", later[2:])
                return results
            raw_features = body.get("features", [])
            features = [str(item) for item in raw_features] if isinstance(raw_features, list) else []
            add("Token & Device ID", OK, f"diterima · API {body.get('api_version', '?')}")

            try:
                feed, _rtt = get(client, "/api/v1/security-events?limit=1")
                data = feed.json() if feed.status_code == 200 else None
            except (httpx.HTTPError, ValueError) as exc:
                add("Feed telemetri", FAIL, f"Gagal membaca feed ({type(exc).__name__}).", "Ulangi; jika terus gagal periksa log layanan API.")
            else:
                if feed.status_code != 200 or not isinstance(data, dict):
                    add("Feed telemetri", FAIL, f"Feed menjawab HTTP {feed.status_code}.", "Token monitor mungkin tidak punya izin baca feed.")
                elif data.get("count", 0) == 0:
                    add("Feed telemetri", WARN, "Terbaca, tetapi belum ada event di server.",
                        "Feed kosong tidak membuktikan server aman: pastikan agen (Linux/Windows) terpasang dan mengirim event.")
                else:
                    add("Feed telemetri", OK, "event terbaru terbaca")

            # Round trip: median of three light requests, so the person sees what their distance really costs.
            trips = [first_rtt]
            for _ in range(2):
                try:
                    trips.append(get(client, "/healthz")[1])
                except httpx.HTTPError:
                    break
            median = statistics.median(trips)
            level = WARN if median > SLOW_ROUND_TRIP_SECONDS else OK
            add("Kecepatan", level, f"waktu bolak-balik sekitar {median * 1000:.0f} ms",
                "Lambat: real-time tetap bekerja, tetapi tiap sinyal terasa tertunda sebesar itu. Coba jaringan lain." if level == WARN else "")
    except httpx.HTTPError as exc:   # a failure outside the guarded calls (client setup, TLS bundle)
        what, hint = classify_connection_error(exc, timeout)
        add("Server menjawab", FAIL, what, hint)
        return results

    # Stream: the arrival of `hello` is the proof that nothing between here and the server buffers the stream.
    if "stream" not in features:
        add("Stream real-time", WARN, "Server ini belum mendukung stream (API lebih lama dari 1.5.0).",
            "Aplikasi tetap bekerja dengan polling tiap 5 detik. Perbarui server (folder optional-server-api) untuk real-time.")
        return _ordered(results)
    outcome: dict[str, object] = {}
    arrived = threading.Event()
    stop = threading.Event()

    def on_signal(signal: StreamSignal) -> None:
        if signal.kind == "hello" and "at" not in outcome:
            outcome["at"] = clock() - started_stream
            arrived.set()
            stop.set()

    started_stream = clock()
    try:
        stream_client = LiveStreamClient(settings, token, transport=transport)
    except StreamAuthError as exc:
        add("Stream real-time", FAIL, str(exc), "")
        return _ordered(results)

    def worker() -> None:
        try:
            stream_client.run_once(on_signal, stop)
        except StreamAuthError as exc:
            outcome["error"] = ("auth", str(exc))
        except StreamUnsupportedError as exc:
            outcome["error"] = ("unsupported", str(exc))
        except (StreamProtocolError, LiveStreamError) as exc:
            outcome["error"] = ("other", str(exc))
        except Exception as exc:  # noqa: BLE001 - report instead of dying silently
            outcome["error"] = ("other", f"{type(exc).__name__}")
        finally:
            arrived.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    arrived.wait(stream_wait)
    stop.set()
    stream_client.close()
    if "at" in outcome:
        add("Stream real-time", OK, f"tersambung dan sinyal pertama tiba dalam {float(outcome['at']) * 1000:.0f} ms (tidak ada buffering di jalur)")
    elif "error" in outcome:
        kind, message = outcome["error"]  # type: ignore[misc]
        hints = {
            "auth": "Token monitor harus sama dengan yang dipakai untuk feed; periksa KAWAL_MONITOR_TOKENS dan status akses perangkat.",
            "unsupported": "Perbarui server (folder optional-server-api) ke API 1.5.0 atau lebih baru.",
        }
        add("Stream real-time", FAIL, message, hints.get(kind, "Ulangi; jika terus gagal, periksa apakah proxy/tunnel mengubah respons (docs/REMOTE_REALTIME.md)."))
    else:
        add("Stream real-time", FAIL, f"Tidak ada sinyal dalam {stream_wait:.0f} detik.",
            "Kemungkinan proxy/tunnel menahan (buffer) stream. Pastikan tidak ada kompresi/caching untuk /api/v1/stream; lihat docs/REMOTE_REALTIME.md.")
    return _ordered(results)


def _ordered(results: list[CheckResult]) -> list[CheckResult]:
    order = ["Alamat server", "Token monitor", "Server menjawab", "Token & Device ID", "Feed telemetri", "Stream real-time", "Kecepatan"]
    return sorted(results, key=lambda item: order.index(item.name) if item.name in order else len(order))


def format_report(results: list[CheckResult]) -> str:
    marks = {OK: "[OK]    ", WARN: "[CEK]   ", FAIL: "[GAGAL] ", SKIP: "[lewati]"}
    lines = []
    for item in results:
        lines.append(f"{marks[item.level]} {item.name}: {item.detail}")
        if item.hint and item.level in (WARN, FAIL):
            lines.append(f"           -> {item.hint}")
    failed = sum(1 for item in results if item.level == FAIL)
    warned = sum(1 for item in results if item.level == WARN)
    if failed:
        lines.append(f"\nHASIL: {failed} langkah gagal. Perbaiki yang pertama gagal dulu; langkah sesudahnya bergantung padanya.")
    elif warned:
        lines.append("\nHASIL: tersambung, dengan catatan yang perlu dibaca di atas.")
    else:
        lines.append("\nHASIL: semua langkah berhasil. Ini membuktikan jalur dari perangkat ini ke server, bukan bahwa server aman.")
    return "\n".join(lines)


def exit_code(results: list[CheckResult]) -> int:
    return 1 if any(item.level == FAIL for item in results) else 0
