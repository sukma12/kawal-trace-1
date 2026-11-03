"""Local-first, URL-only website availability monitoring.

This module checks only an explicitly saved HTTP(S) URL. It never requests API
credentials, probes additional paths, scans ports, or writes events to the security
log chain. Website checks live in their own local SQLite database.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import secrets
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_UA = "KawalTrace-WebsiteMonitor/1.0"
MAX_REDIRECTS = 5
MAX_TARGETS = 500
MIN_INTERVAL_SECONDS = 30
MAX_INTERVAL_SECONDS = 86_400
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 30


class WebsiteMonitorError(ValueError):
    """A target or monitoring configuration is not safe or valid."""


@dataclass(frozen=True)
class WebsiteTarget:
    target_id: int
    name: str
    url: str
    interval_seconds: int
    timeout_seconds: int
    failure_threshold: int
    consecutive_failures: int
    allow_internal: bool
    enabled: bool
    last_status: str
    last_checked_utc: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _normal_host(host: str) -> str:
    return str(host or "").rstrip(".").strip("[]").lower()


def redact_website_url(url: str) -> str:
    """Hide query parameter values when showing/exporting a configured target."""
    try:
        parsed = urlsplit(str(url or ""))
        safe_query = urlencode([(key, "[REDACTED]") for key, _value in parse_qsl(parsed.query, keep_blank_values=True)])
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, safe_query, ""))
    except (TypeError, ValueError):
        return "[URL tidak valid]"


def _is_metadata_host(host: str) -> bool:
    host = _normal_host(host)
    return host in {
        "metadata", "metadata.google.internal", "metadata.google", "instance-data",
        "instance-data.ec2.internal", "metadata.tencentyun.com", "metadata.azure.internal",
    }


def _validate_ip(ip_text: str, allow_internal: bool) -> None:
    try:
        ip = ipaddress.ip_address(ip_text.split("%", 1)[0])
    except ValueError as exc:
        raise WebsiteMonitorError("Alamat IP target tidak valid.") from exc
    # Link-local commonly includes cloud instance metadata endpoints; never allow it.
    metadata_ranges = (
        ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata endpoint
        ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 instance metadata endpoint
    )
    if (ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved
            or any(ip in network for network in metadata_ranges)):
        raise WebsiteMonitorError("Alamat link-local, metadata, multicast, atau reserved ditolak.")
    if not ip.is_global:
        if not allow_internal or not (ip.is_private or ip.is_loopback):
            raise WebsiteMonitorError("Target jaringan internal hanya boleh digunakan setelah opsi target internal diaktifkan.")


def _validate_url_shape(url: str, allow_internal: bool) -> str:
    raw = str(url or "").strip()
    if not raw or len(raw) > 2048:
        raise WebsiteMonitorError("URL wajib diisi dan maksimal 2048 karakter.")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise WebsiteMonitorError("Format URL atau port tidak valid.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise WebsiteMonitorError("URL harus menggunakan HTTP atau HTTPS dan memiliki hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise WebsiteMonitorError("URL tidak boleh menyimpan username atau password di dalam alamat.")
    if parsed.fragment:
        raise WebsiteMonitorError("URL tidak boleh memiliki fragment (#).")
    try:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
    except ValueError as exc:
        raise WebsiteMonitorError("URL memiliki terlalu banyak parameter query atau format query tidak valid.") from exc
    sensitive_keys = {
        "token", "access_token", "refresh_token", "id_token", "api_key", "apikey", "key",
        "client_secret", "secret", "password", "passwd", "pwd", "auth", "authorization",
        "cookie", "session", "sessionid", "signature", "sig", "credential", "credentials",
    }
    for query_key, _query_value in query_pairs:
        normalized_key = query_key.strip().casefold().replace("-", "_")
        if normalized_key in sensitive_keys or normalized_key.endswith(("_token", "_secret", "_password", "_signature", "_credential", "_credentials")):
            raise WebsiteMonitorError(
                "URL tidak boleh menyimpan token, password, signature, cookie, atau kredensial di parameter query."
            )
    if port is not None and not 1 <= port <= 65535:
        raise WebsiteMonitorError("Port harus berada pada rentang 1–65535.")
    host = _normal_host(parsed.hostname)
    if not host or any(ch.isspace() for ch in host) or "\\" in host:
        raise WebsiteMonitorError("Hostname tidak valid.")
    if _is_metadata_host(host) or host.endswith((".metadata.google.internal", ".instance-data.ec2.internal")):
        raise WebsiteMonitorError("Hostname metadata cloud tidak boleh dipantau melalui mode website.")
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal", ".lan")):
        if not allow_internal:
            raise WebsiteMonitorError("Hostname lokal/internal hanya boleh dipakai jika opsi target internal diaktifkan.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        _validate_ip(host, allow_internal)
    return raw


def _resolve_and_validate(host: str, port: int, allow_internal: bool) -> tuple[float, list[str]]:
    """Resolve once, validate every address, and return IP literals to pin connections to."""
    started = time.perf_counter()
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise _CheckFailure("DNS_ERROR", "DNS tidak dapat menemukan alamat target.") from exc
    except OSError as exc:
        raise _CheckFailure("DNS_ERROR", "Resolusi DNS gagal.") from exc
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    addresses = sorted({str(item[4][0]).split("%", 1)[0] for item in answers if item and item[4]})
    if not addresses:
        raise _CheckFailure("DNS_ERROR", "DNS tidak mengembalikan alamat IP.")
    try:
        for address in addresses:
            _validate_ip(address, allow_internal)
    except WebsiteMonitorError as exc:
        # Fail closed if DNS returns even one prohibited address. Never choose just
        # the public answer from a mixed public/private answer set.
        raise _CheckFailure("TARGET_BLOCKED", str(exc)) from exc
    return elapsed_ms, addresses


class _CheckFailure(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _read_pinned_http_response(url: str, address: str, timeout_seconds: int) -> tuple[int, dict[str, str]]:
    """Issue a minimal HTTP/1.1 GET to a previously validated IP literal.

    The TCP socket connects to the IP returned by _resolve_and_validate, never to
    the hostname. For HTTPS, certificate validation and SNI still use the original
    hostname. This closes the validate-then-re-resolve gap that permits classic DNS
    rebinding between policy validation and the HTTP library's connection.
    """
    parsed = urlsplit(url)
    host = _normal_host(parsed.hostname or "")
    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        connect_host = str(ipaddress.ip_address(address.split("%", 1)[0]))
    except ValueError as exc:
        raise _CheckFailure("TARGET_BLOCKED", "Alamat koneksi bukan IP literal yang tervalidasi.") from exc

    request_path = parsed.path or "/"
    if parsed.query:
        request_path += "?" + parsed.query
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in request_path):
        raise _CheckFailure("URL_ERROR", "URL berisi karakter kontrol yang ditolak.")

    try:
        host_ip = ipaddress.ip_address(host)
        host_header = f"[{host}]" if host_ip.version == 6 else host
    except ValueError:
        host_header = host.encode("idna").decode("ascii")
    if port != (443 if scheme == "https" else 80):
        host_header = f"{host_header}:{port}"
    request_path = quote(request_path, safe="/%:@!$&'()*+,;=-._~?")
    request_bytes = (
        f"GET {request_path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: {APP_UA}\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: identity\r\n"
        "Range: bytes=0-65535\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", errors="strict")

    raw_socket: socket.socket | None = None
    stream = None
    try:
        # `address` is a checked IP literal. create_connection does not look up the
        # original user-controlled hostname here; only this numeric address.
        raw_socket = socket.create_connection((connect_host, port), timeout=float(timeout_seconds))
        raw_socket.settimeout(float(timeout_seconds))
        if scheme == "https":
            context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            # wrap_socket validates the certificate against the DNS hostname and
            # sets SNI to that hostname; the TCP peer remains the pinned IP.
            raw_socket = context.wrap_socket(raw_socket, server_hostname=host.encode("idna").decode("ascii"))
            raw_socket.settimeout(float(timeout_seconds))
        raw_socket.sendall(request_bytes)
        stream = raw_socket.makefile("rb")

        def read_line(limit: int = 8192) -> bytes:
            line = stream.readline(limit + 1)
            if len(line) > limit:
                raise _CheckFailure("PROTOCOL_ERROR", "Baris respons HTTP melampaui batas ukuran.")
            if not line:
                raise _CheckFailure("CONNECTION_ERROR", "Target menutup koneksi sebelum respons HTTP diterima.")
            return line

        # Handle informational responses (100/103) without treating them as final.
        while True:
            status_line = read_line()
            match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?\r?\n", status_line)
            if not match:
                raise _CheckFailure("PROTOCOL_ERROR", "Target tidak mengirim status HTTP/1.0 atau HTTP/1.1 yang valid.")
            status_code = int(match.group(1))
            headers: dict[str, str] = {}
            total_header_bytes = len(status_line)
            header_count = 0
            while True:
                line = read_line()
                total_header_bytes += len(line)
                header_count += 1
                if total_header_bytes > 65536 or header_count > 100:
                    raise _CheckFailure("PROTOCOL_ERROR", "Header respons HTTP terlalu besar.")
                if line in {b"\r\n", b"\n"}:
                    break
                if line[:1] in {b" ", b"\t"} or b":" not in line:
                    raise _CheckFailure("PROTOCOL_ERROR", "Format header respons HTTP tidak valid.")
                key, value = line.split(b":", 1)
                try:
                    header_name = key.decode("ascii").strip().lower()
                    header_value = value.decode("latin-1").strip()
                except UnicodeError as exc:
                    raise _CheckFailure("PROTOCOL_ERROR", "Header respons HTTP tidak valid.") from exc
                if not header_name or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~" for ch in header_name):
                    raise _CheckFailure("PROTOCOL_ERROR", "Nama header respons HTTP tidak valid.")
                headers[header_name] = header_value
            if 100 <= status_code < 200 and status_code != 101:
                continue
            return status_code, headers
    except _CheckFailure:
        raise
    except ssl.SSLCertVerificationError as exc:
        raise _CheckFailure("TLS_ERROR", "Verifikasi TLS/sertifikat gagal. Periksa sertifikat dan jam perangkat.") from exc
    except ssl.SSLError as exc:
        raise _CheckFailure("TLS_ERROR", "Koneksi TLS gagal atau sertifikat tidak dapat diverifikasi.") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise _CheckFailure("TIMEOUT", "Pemeriksaan melewati batas waktu yang ditentukan.") from exc
    except (OSError, UnicodeError) as exc:
        raise _CheckFailure("CONNECTION_ERROR", f"Koneksi ke alamat tervalidasi gagal ({type(exc).__name__}).") from exc
    finally:
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
        if raw_socket is not None:
            try:
                raw_socket.close()
            except OSError:
                pass


def check_website(url: str, *, allow_internal: bool = False, timeout_seconds: int = 8) -> dict[str, Any]:
    """Check one explicit URL using DNS-pinned HTTP(S) and bounded redirects.

    Bodies are never read or stored. HTTPS verifies certificates. Proxies and
    hostname re-resolution during connect are avoided. Each redirect is resolved,
    validated, and pinned independently before any request is sent to it.
    """
    try:
        timeout = int(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise WebsiteMonitorError("Timeout harus berupa bilangan bulat 1–30 detik.") from exc
    if not MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS:
        raise WebsiteMonitorError("Timeout harus berada pada rentang 1–30 detik.")

    current_url = _validate_url_shape(url, allow_internal)
    initial_parts = urlsplit(current_url)
    initial_scheme = initial_parts.scheme.lower()
    initial_host = _normal_host(initial_parts.hostname or "")
    dns_ms_total = 0.0
    response_ms = 0.0
    started = time.perf_counter()
    redirects = 0
    current_status: int | None = None

    while True:
        parsed = urlsplit(current_url)
        host = _normal_host(parsed.hostname or "")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        # An internal-target approval applies only to the exact configured host,
        # not to a different private host reached through a redirect.
        permit_internal_host = allow_internal and host == initial_host
        dns_started = time.perf_counter()
        try:
            dns_ms, addresses = _resolve_and_validate(host, port, permit_internal_host)
        except _CheckFailure as exc:
            status, message = exc.status, exc.message
            break
        dns_ms_total += dns_ms
        current_error: _CheckFailure | None = None
        request_started = time.perf_counter()
        response_headers: dict[str, str] = {}
        for address in addresses:
            try:
                current_status, response_headers = _read_pinned_http_response(current_url, address, timeout)
                current_error = None
                break
            except _CheckFailure as exc:
                current_error = exc
                # Do not retry another address after a TLS, protocol, or timeout
                # error. A normal connection refusal may try another validated IP.
                if exc.status not in {"CONNECTION_ERROR"}:
                    break
        response_ms += (time.perf_counter() - request_started) * 1000
        if current_error is not None:
            status, message = current_error.status, current_error.message
            break
        if current_status is None:
            status, message = "CONNECTION_ERROR", "Target tidak memberikan respons HTTP."
            break

        location = response_headers.get("location", "").strip()
        if current_status in {301, 302, 303, 307, 308} and location:
            if redirects >= MAX_REDIRECTS:
                status, message = "REDIRECT_BLOCKED", "Redirect melebihi batas aman 5 kali."
                break
            next_url = urljoin(current_url, location)
            try:
                checked_next = _validate_url_shape(next_url, allow_internal)
            except WebsiteMonitorError as exc:
                status, message = "REDIRECT_BLOCKED", str(exc)
                break
            next_scheme = urlsplit(checked_next).scheme.lower()
            if initial_scheme == "https" and next_scheme != "https":
                status, message = "REDIRECT_BLOCKED", "Redirect dari HTTPS ke HTTP ditolak untuk mencegah downgrade."
                break
            current_url = checked_next
            redirects += 1
            continue
        status = "UP" if 200 <= current_status < 400 else "HTTP_ERROR"
        message = (f"Website merespons HTTP {current_status}." if status == "UP" else
                   f"Website merespons HTTP {current_status}; koneksi berhasil tetapi status HTTP perlu ditinjau.")
        break

    result_status = status
    return {
        "status": result_status,
        "http_status": current_status,
        "dns_ms": round(dns_ms_total, 2),
        "response_ms": round(response_ms, 2),
        "total_ms": round((time.perf_counter() - started) * 1000, 2),
        "redirect_count": redirects,
        "error_type": "" if result_status in {"UP", "HTTP_ERROR"} else result_status,
        "message": message,
        "checked_at_utc": utc_now(),
    }


class WebsiteMonitorStore:
    """AES-GCM encrypted SQLite image store, separate from security events.

    SQLite is opened only in memory. After a transaction, the complete serialized
    database image is encrypted with AES-256-GCM and atomically persisted. The key
    must come from platform secure storage; there is intentionally no plaintext-key
    or unencrypted SQLite fallback.
    """

    _MAGIC = b"KAWALTRACE-ENCDB\x01"
    _AAD = b"KawalTrace:WebsiteMonitorStore:1"

    def __init__(self, path: str | Path, encryption_key: bytes | str):
        self.path = Path(path).expanduser().resolve()
        if isinstance(encryption_key, str):
            try:
                encryption_key = bytes.fromhex(encryption_key)
            except ValueError as exc:
                raise WebsiteMonitorError("Kunci enkripsi database harus berupa 64 karakter heksadesimal.") from exc
        if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
            raise WebsiteMonitorError("Kunci enkripsi database wajib 32 byte dari Secure Storage OS.")
        self._key = bytes(encryption_key)
        self._thread_lock = threading.RLock()
        self._lock_path = Path(str(self.path) + ".lock")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                self.path.parent.chmod(0o700)
            except OSError:
                pass
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS website_targets (
                    target_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 30 AND 86400),
                    timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds BETWEEN 1 AND 30),
                    failure_threshold INTEGER NOT NULL DEFAULT 3 CHECK(failure_threshold BETWEEN 1 AND 10),
                    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK(consecutive_failures >= 0),
                    allow_internal INTEGER NOT NULL DEFAULT 0 CHECK(allow_internal IN (0,1)),
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
                    last_status TEXT NOT NULL DEFAULT '',
                    last_checked_utc TEXT NOT NULL DEFAULT '',
                    created_at_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_website_targets_enabled ON website_targets(enabled, last_checked_utc);
                CREATE TABLE IF NOT EXISTS website_checks (
                    check_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL REFERENCES website_targets(target_id) ON DELETE CASCADE,
                    checked_at_utc TEXT NOT NULL,
                    status TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    http_status INTEGER,
                    dns_ms REAL,
                    response_ms REAL,
                    total_ms REAL NOT NULL,
                    redirect_count INTEGER NOT NULL DEFAULT 0,
                    error_type TEXT NOT NULL DEFAULT '',
                    message TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_website_checks_target_time ON website_checks(target_id, checked_at_utc DESC);
                """
            )
            # Forward-compatible additive migration for an earlier in-development schema.
            target_columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(website_targets)").fetchall()}
            if "failure_threshold" not in target_columns:
                conn.execute("ALTER TABLE website_targets ADD COLUMN failure_threshold INTEGER NOT NULL DEFAULT 3")
            if "consecutive_failures" not in target_columns:
                conn.execute("ALTER TABLE website_targets ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0")
        self._restrict_file_permissions()

    def _restrict_file_permissions(self) -> None:
        if os.name != "nt":
            for p in (self.path, self._lock_path):
                try:
                    if p.exists():
                        p.chmod(0o600)
                except OSError:
                    pass

    @contextmanager
    def _process_lock(self):
        """Serialize database read/modify/write cycles across threads and processes."""
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock_path.open("a+b") as lock_file:
            if os.name != "nt":
                try:
                    os.chmod(self._lock_path, 0o600)
                except OSError:
                    pass
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            else:
                import msvcrt
                lock_file.seek(0, os.SEEK_END)
                if lock_file.tell() == 0:
                    lock_file.write(b"0")
                    lock_file.flush()
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)

    def _load_database_image(self, conn: sqlite3.Connection) -> None:
        if not self.path.exists():
            return
        try:
            data = self.path.read_bytes()
        except OSError as exc:
            raise WebsiteMonitorError("Database website terenkripsi tidak dapat dibaca.") from exc
        if not data:
            raise WebsiteMonitorError("Database website kosong/tidak lengkap; data tidak akan ditimpa otomatis.")
        if data.startswith(self._MAGIC):
            offset = len(self._MAGIC)
            if len(data) < offset + 12 + 16:
                raise WebsiteMonitorError("Database website terenkripsi tidak lengkap.")
            nonce = data[offset:offset + 12]
            ciphertext = data[offset + 12:]
            try:
                plaintext = AESGCM(self._key).decrypt(nonce, ciphertext, self._AAD)
            except InvalidTag as exc:
                raise WebsiteMonitorError("Kunci Secure Storage salah atau integritas database terenkripsi gagal; file tidak diubah.") from exc
            if not plaintext.startswith(b"SQLite format 3\x00"):
                raise WebsiteMonitorError("Konten database terenkripsi tidak memiliki header SQLite yang valid.")
            try:
                conn.deserialize(plaintext)
            except sqlite3.DatabaseError as exc:
                raise WebsiteMonitorError("Database website terenkripsi rusak; file tidak diubah.") from exc
            return
        if data.startswith(b"SQLite format 3\x00"):
            # One-time migration from the previous plaintext SQLite file. The
            # old DB is checkpointed and serialized, then atomically replaced by an
            # authenticated encrypted image on this context's first successful save.
            legacy = sqlite3.connect(str(self.path), timeout=10)
            try:
                try:
                    legacy.execute("PRAGMA wal_checkpoint(FULL)")
                    legacy.execute("PRAGMA journal_mode=DELETE")
                except sqlite3.DatabaseError:
                    pass
                plaintext = legacy.serialize()
            except sqlite3.DatabaseError as exc:
                raise WebsiteMonitorError("Database website lama tidak dapat dimigrasikan dengan aman.") from exc
            finally:
                legacy.close()
                for suffix in ("-wal", "-shm"):
                    try:
                        Path(str(self.path) + suffix).unlink(missing_ok=True)
                    except OSError:
                        pass
            try:
                conn.deserialize(plaintext)
            except sqlite3.DatabaseError as exc:
                raise WebsiteMonitorError("Database website lama tidak dapat dibaca untuk migrasi.") from exc
            return
        raise WebsiteMonitorError("Format database website tidak dikenal; file dipertahankan agar tidak kehilangan data.")

    def _persist_database_image(self, conn: sqlite3.Connection) -> None:
        plaintext = conn.serialize()
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, self._AAD)
        payload = self._MAGIC + nonce + ciphertext
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile("wb", dir=str(self.path.parent), prefix=".kawal-db-", suffix=".tmp", delete=False) as tmp:
                temp_path = Path(tmp.name)
                if os.name != "nt":
                    os.chmod(temp_path, 0o600)
                tmp.write(payload)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(temp_path, self.path)
            temp_path = None
            if os.name != "nt":
                try:
                    self.path.chmod(0o600)
                    dir_fd = os.open(str(self.path.parent), os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    pass
            # Remove sidecars from a migrated plaintext SQLite DB; new DB writes
            # happen only in memory, so no WAL/SHM files should be created.
            for suffix in ("-wal", "-shm", "-journal"):
                try:
                    Path(str(self.path) + suffix).unlink(missing_ok=True)
                except OSError:
                    pass
        except OSError as exc:
            raise WebsiteMonitorError("Database website terenkripsi tidak dapat disimpan secara atomik.") from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    @contextmanager
    def _connection(self):
        with self._thread_lock:
            with self._process_lock():
                conn = sqlite3.connect(":memory:", timeout=10)
                conn.row_factory = sqlite3.Row
                try:
                    self._load_database_image(conn)
                    conn.execute("PRAGMA foreign_keys=ON")
                    conn.execute("PRAGMA busy_timeout=5000")
                    conn.execute("PRAGMA synchronous=FULL")
                    try:
                        conn.execute("PRAGMA trusted_schema=OFF")
                    except sqlite3.DatabaseError:
                        pass
                    yield conn
                    if conn.in_transaction:
                        conn.commit()
                    self._persist_database_image(conn)
                except Exception:
                    if conn.in_transaction:
                        conn.rollback()
                    raise
                finally:
                    conn.close()

    def add_target(self, name: str, url: str, interval_seconds: int = 300,
                   timeout_seconds: int = 8, allow_internal: bool = False,
                   failure_threshold: int = 3) -> WebsiteTarget:
        clean_name = " ".join(str(name or "").split())
        if not clean_name or len(clean_name) > 100:
            raise WebsiteMonitorError("Nama target wajib diisi dan maksimal 100 karakter.")
        try:
            interval = int(interval_seconds)
            timeout = int(timeout_seconds)
            threshold = int(failure_threshold)
        except (TypeError, ValueError) as exc:
            raise WebsiteMonitorError("Interval, timeout, dan ambang kegagalan harus berupa bilangan bulat.") from exc
        if not MIN_INTERVAL_SECONDS <= interval <= MAX_INTERVAL_SECONDS:
            raise WebsiteMonitorError("Interval harus 30–86400 detik.")
        if not MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS:
            raise WebsiteMonitorError("Timeout harus 1–30 detik.")
        if not 1 <= threshold <= 10:
            raise WebsiteMonitorError("Ambang kegagalan berurutan harus 1–10.")
        clean_url = _validate_url_shape(url, bool(allow_internal))
        with self._connection() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM website_targets").fetchone()[0])
            if count >= MAX_TARGETS:
                raise WebsiteMonitorError(f"Maksimal {MAX_TARGETS} target website dapat disimpan.")
            try:
                cur = conn.execute(
                    "INSERT INTO website_targets(name,url,interval_seconds,timeout_seconds,failure_threshold,allow_internal,enabled,created_at_utc) VALUES(?,?,?,?,?,?,1,?)",
                    (clean_name, clean_url, interval, timeout, threshold, int(bool(allow_internal)), utc_now()),
                )
            except sqlite3.IntegrityError as exc:
                raise WebsiteMonitorError("Konfigurasi target tidak dapat disimpan.") from exc
            target_id = int(cur.lastrowid)
        target = self.get_target(target_id)
        if target is None:
            raise WebsiteMonitorError("Target tersimpan tetapi tidak dapat dibaca kembali.")
        return target

    @staticmethod
    def _target_from_row(row: sqlite3.Row) -> WebsiteTarget:
        return WebsiteTarget(
            target_id=int(row["target_id"]), name=str(row["name"]), url=str(row["url"]),
            interval_seconds=int(row["interval_seconds"]), timeout_seconds=int(row["timeout_seconds"]),
            failure_threshold=int(row["failure_threshold"]), consecutive_failures=int(row["consecutive_failures"]),
            allow_internal=bool(row["allow_internal"]), enabled=bool(row["enabled"]),
            last_status=str(row["last_status"]), last_checked_utc=str(row["last_checked_utc"]),
        )

    def get_target(self, target_id: int) -> WebsiteTarget | None:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM website_targets WHERE target_id=?", (int(target_id),)).fetchone()
        return self._target_from_row(row) if row else None

    def list_targets(self, *, enabled_only: bool = False) -> list[WebsiteTarget]:
        query = "SELECT * FROM website_targets"
        if enabled_only:
            query += " WHERE enabled=1"
        query += " ORDER BY target_id DESC"
        with self._connection() as conn:
            rows = conn.execute(query).fetchall()
        return [self._target_from_row(row) for row in rows]

    def set_enabled(self, target_id: int, enabled: bool) -> None:
        with self._connection() as conn:
            cur = conn.execute("UPDATE website_targets SET enabled=? WHERE target_id=?", (int(bool(enabled)), int(target_id)))
            if cur.rowcount != 1:
                raise WebsiteMonitorError("Target website tidak ditemukan.")

    def delete_target(self, target_id: int) -> None:
        with self._connection() as conn:
            # Delete children explicitly as well as relying on the FK cascade. This also
            # makes target deletion deterministic for encrypted database images that
            # were created by an older build with foreign-key enforcement disabled.
            conn.execute("DELETE FROM website_checks WHERE target_id=?", (int(target_id),))
            cur = conn.execute("DELETE FROM website_targets WHERE target_id=?", (int(target_id),))
            if cur.rowcount != 1:
                raise WebsiteMonitorError("Target website tidak ditemukan.")

    def list_checks(self, target_id: int, limit: int = 20) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 100))
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM website_checks WHERE target_id=? ORDER BY check_id DESC LIMIT ?",
                (int(target_id), bounded),
            ).fetchall()
        return [dict(row) for row in rows]

    def check_target(self, target_id: int) -> dict[str, Any]:
        target = self.get_target(target_id)
        if target is None:
            raise WebsiteMonitorError("Target website tidak ditemukan.")
        result = check_website(target.url, allow_internal=target.allow_internal, timeout_seconds=target.timeout_seconds)
        previous = target.last_status
        previous_failures = target.consecutive_failures
        status = str(result["status"])
        non_outage_blocks = {"TARGET_BLOCKED", "URL_ERROR", "REDIRECT_BLOCKED"}
        if status == "UP":
            current_failures = 0
        elif status in non_outage_blocks:
            current_failures = previous_failures
        else:
            current_failures = previous_failures + 1
        result["failure_streak"] = current_failures
        result["failure_threshold"] = target.failure_threshold
        result["alert_triggered"] = current_failures >= target.failure_threshold and previous_failures < target.failure_threshold
        if status == "UP":
            event_type = "WEBSITE_RECOVERED" if previous and previous not in {"UP"} else "WEBSITE_UP"
        elif status == "HTTP_ERROR":
            event_type = "WEBSITE_HTTP_ERROR"
        elif status == "DNS_ERROR":
            event_type = "WEBSITE_DNS_ERROR"
        elif status == "TLS_ERROR":
            event_type = "WEBSITE_TLS_ERROR"
        elif status == "TIMEOUT":
            event_type = "WEBSITE_TIMEOUT"
        elif status == "REDIRECT_BLOCKED":
            event_type = "WEBSITE_REDIRECT_BLOCKED"
        elif status in {"TARGET_BLOCKED", "URL_ERROR"}:
            event_type = "WEBSITE_TARGET_BLOCKED"
        elif status == "CONNECTION_ERROR":
            event_type = "WEBSITE_CONNECTION_ERROR"
        else:
            event_type = "WEBSITE_DOWN"
        result["event_type"] = event_type
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO website_checks(target_id,checked_at_utc,status,event_type,http_status,dns_ms,response_ms,total_ms,redirect_count,error_type,message) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (target.target_id, result["checked_at_utc"], result["status"], result["event_type"], result["http_status"], result["dns_ms"], result["response_ms"], result["total_ms"], result["redirect_count"], result["error_type"], result["message"]),
            )
            conn.execute("UPDATE website_targets SET last_status=?,last_checked_utc=?,consecutive_failures=? WHERE target_id=?",
                         (result["status"], result["checked_at_utc"], current_failures, target.target_id))
        return {"target_id": target.target_id, "target_name": target.name, **result}

    def export_checks_json(self, target_id: int, limit: int = 1000) -> str:
        bounded = max(1, min(int(limit), 5000))
        target = self.get_target(target_id)
        if target is None:
            raise WebsiteMonitorError("Target website tidak ditemukan.")
        checks = self.list_checks(target_id, bounded)
        parsed = urlsplit(target.url)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        return json.dumps({
            "format": "kawal-trace-website-checks-v1",
            "target": {"target_id": target.target_id, "name": target.name, "origin": origin},
            "checks": checks,
        }, ensure_ascii=False, indent=2, allow_nan=False)
