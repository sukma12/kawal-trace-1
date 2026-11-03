"""Persistent daily archive for normalized server security events.

Local storage is the default. Optional remote storage is supported only by a
self-managed Kawal Trace API implementing /api/v1/archive/events endpoints.
"""
from __future__ import annotations

import csv
from contextlib import contextmanager
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlencode, urlsplit

from .at_rest import AtRestError, DataCipher, resolve_cipher, scrub_plaintext_remnants
from .storage_policy import require_remote_storage

try:
    import httpx
except ImportError:  # Local archive/export still works without the HTTP dependency.
    httpx = None

PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{5,127}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
REMOTE_PATH = "/api/v1/archive/events"
REMOTE_BATCH_PATH = "/api/v1/archive/events:batch"

def remote_archive_event_id(source_profile_id: str, source_event_id: str) -> str:
    """Create the API's stable, profile-scoped 64-hex key for one source event."""
    source = _safe_profile_id(source_profile_id)
    return hashlib.sha256(f"{source}\n{str(source_event_id or '')}".encode("utf-8")).hexdigest()


_AUTO = object()


class ArchiveError(ValueError):
    """Invalid archive configuration or unsupported archive response."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        raise ArchiveError("Timestamp event kosong; event tidak diarsipkan.")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ArchiveError("Timestamp event tidak valid; gunakan ISO 8601 dengan zona waktu.") from exc
    if dt.tzinfo is None:
        raise ArchiveError("Timestamp event tidak memiliki zona waktu; event tidak diarsipkan agar tanggal tidak keliru.")
    return dt.astimezone(timezone.utc)


def _safe_profile_id(value: Any) -> str:
    result = str(value or "").strip()
    if not PROFILE_RE.fullmatch(result):
        raise ArchiveError("Profile server tidak valid untuk arsip.")
    return result


def _canonical_event(raw: Mapping[str, Any]) -> tuple[str, str, str]:
    if not isinstance(raw, Mapping):
        raise ArchiveError("Event arsip harus berupa object.")
    event = dict(raw)
    raw_id = str(event.get("event_id") or "").strip()
    if not raw_id:
        raw_id = hashlib.sha256(json.dumps(event, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    if not re.fullmatch(r"[A-Fa-f0-9]{16,128}", raw_id):
        raw_id = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()
    event["event_id"] = raw_id.lower()
    stamp = _parse_timestamp(event.get("timestamp_utc"))
    stamp_text = stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    event["timestamp_utc"] = stamp_text
    event.pop("timestamp_epoch", None)  # Derived value can be recreated; UTC is canonical.
    try:
        payload = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ArchiveError("Event tidak dapat diserialisasi sebagai JSON.") from exc
    if len(payload.encode("utf-8")) > 32_768:
        raise ArchiveError("Ukuran satu event melebihi batas arsip 32 KiB.")
    return event["event_id"], stamp_text, payload


class ServerEventArchive:
    """SQLite archive, partitioned logically by source profile and UTC event date."""

    def __init__(self, path: str | Path, *, cipher: DataCipher | None | object = _AUTO):
        self._cipher_arg = cipher
        self.scrub_warning = ""      # non-empty when converting an old archive left plaintext remnants in the file
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                self.path.parent.chmod(0o700)
            except OSError:
                pass
        with self._connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS server_events (
                    profile_id TEXT NOT NULL,
                    profile_name TEXT NOT NULL DEFAULT '',
                    event_id TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    event_date_utc TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    archived_at_utc TEXT NOT NULL,
                    PRIMARY KEY(profile_id, event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_server_events_profile_date
                    ON server_events(profile_id, event_date_utc, timestamp_utc DESC);
                CREATE TABLE IF NOT EXISTS archive_uploads (
                    source_profile_id TEXT NOT NULL,
                    destination_profile_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    uploaded_at_utc TEXT NOT NULL,
                    PRIMARY KEY(source_profile_id, destination_profile_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS archive_local_pins (
                    profile_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    pinned_at_utc TEXT NOT NULL,
                    PRIMARY KEY(profile_id, event_id)
                );
            """)
        if os.name != "nt":
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        self._encrypt_legacy_rows()

    # ------------------------------------------------------------------ encryption at rest (payload column)
    def _cipher(self) -> DataCipher | None:
        if self._cipher_arg is not _AUTO:
            return self._cipher_arg  # type: ignore[return-value]
        return resolve_cipher(self.path.parent, self._has_encrypted_rows)

    def _has_encrypted_rows(self) -> bool:
        try:
            with self._connection() as conn:
                return conn.execute("SELECT 1 FROM server_events WHERE payload_json LIKE 'kt1:%' LIMIT 1").fetchone() is not None
        except sqlite3.Error:
            return False

    @staticmethod
    def _context(profile_id: str, event_id: str) -> str:
        return f"archive|{profile_id}|{event_id}"

    def _seal(self, profile_id: str, event_id: str, payload: str) -> str:
        cipher = self._cipher()
        return payload if cipher is None else cipher.encrypt_text(payload, self._context(profile_id, event_id))

    def _open(self, profile_id: str, event_id: str, stored: str) -> str:
        if not DataCipher.is_encrypted(stored):
            return str(stored)            # written before encryption existed; converted on the next start
        cipher = self._cipher()
        if cipher is None:
            raise ArchiveError("Arsip terenkripsi, tetapi kunci tidak diberikan.")
        try:
            return cipher.decrypt_text(str(stored), self._context(profile_id, event_id))
        except AtRestError as exc:
            raise ArchiveError("Data arsip tidak bisa dibuka (kunci tidak cocok atau isi diubah); "
                               "buat cadangan database sebelum perbaikan.") from exc

    def _encrypt_legacy_rows(self) -> int:
        if self._cipher() is None:
            return 0
        with self._connection() as conn:
            rows = conn.execute("SELECT profile_id,event_id,payload_json FROM server_events WHERE payload_json NOT LIKE 'kt1:%'").fetchall()
            if not rows:
                return 0
            conn.execute("BEGIN IMMEDIATE")
            for row in rows:
                conn.execute("UPDATE server_events SET payload_json=? WHERE profile_id=? AND event_id=?",
                             (self._seal(row["profile_id"], row["event_id"], row["payload_json"]), row["profile_id"], row["event_id"]))
            conn.commit()
            try:
                scrub_plaintext_remnants(conn)
                self.scrub_warning = ""
            except sqlite3.Error as exc:
                self.scrub_warning = f"Arsip terenkripsi, tetapi sisa teks lama di berkas belum dibersihkan: {str(exc)[:200]}"
            return len(rows)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA secure_delete=ON")
        try:
            conn.execute("PRAGMA trusted_schema=OFF")
        except sqlite3.DatabaseError:
            pass
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            yield conn
            if conn.in_transaction:
                conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def add_events(self, profile_id: str, profile_name: str, events: Iterable[Mapping[str, Any]]) -> int:
        pid = _safe_profile_id(profile_id)
        name = " ".join(str(profile_name or "").split())[:80]
        rows = []
        for raw in events:
            event_id, stamp, payload = _canonical_event(raw)
            event_date = stamp[:10]
            rows.append((pid, name, event_id, stamp, event_date, payload, utc_now()))
        inserted = 0
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for row in rows:
                existing = conn.execute(
                    "SELECT payload_json FROM server_events WHERE profile_id=? AND event_id=?",
                    (row[0], row[2]),
                ).fetchone()
                if existing:
                    if self._open(row[0], row[2], str(existing["payload_json"])) != row[5]:
                        conn.rollback()
                        raise ArchiveError("Event ID yang sama datang dengan isi berbeda; arsip ditahan untuk pemeriksaan.")
                    continue
                conn.execute(
                    "INSERT INTO server_events(profile_id,profile_name,event_id,timestamp_utc,event_date_utc,payload_json,archived_at_utc) VALUES(?,?,?,?,?,?,?)",
                    (*row[:5], self._seal(row[0], row[2], row[5]), row[6]),
                )
                inserted += 1
            conn.commit()
        return inserted

    def date_counts(self, profile_id: str) -> list[dict[str, Any]]:
        pid = _safe_profile_id(profile_id)
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT event_date_utc AS event_date, COUNT(*) AS count FROM server_events WHERE profile_id=? GROUP BY event_date_utc ORDER BY event_date_utc DESC",
                (pid,),
            ).fetchall()
        return [{"date": str(row["event_date"]), "count": int(row["count"])} for row in rows]

    def list_events(self, profile_id: str, event_date: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        pid = _safe_profile_id(profile_id)
        query = "SELECT profile_name,event_id,timestamp_utc,event_date_utc,payload_json,archived_at_utc FROM server_events WHERE profile_id=?"
        params: list[Any] = [pid]
        if event_date and event_date != "all":
            if not DATE_RE.fullmatch(event_date):
                raise ArchiveError("Tanggal arsip harus berformat YYYY-MM-DD UTC.")
            try:
                datetime.strptime(event_date, "%Y-%m-%d")
            except ValueError as exc:
                raise ArchiveError("Tanggal arsip tidak valid.") from exc
            query += " AND event_date_utc=?"
            params.append(event_date)
        query += " ORDER BY timestamp_utc DESC,event_id DESC"
        if limit is not None:
            if not 1 <= int(limit) <= 100_000:
                raise ArchiveError("Batas baca arsip harus 1–100000 event.")
            query += " LIMIT ?"
            params.append(int(limit))
        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        results = []
        for row in rows:
            try:
                event = json.loads(self._open(pid, str(row["event_id"]), row["payload_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise ArchiveError("Data arsip tidak bisa dibaca; buat cadangan database sebelum perbaikan.") from exc
            results.append({
                "profile_id": pid,
                "profile_name": str(row["profile_name"]),
                "event_date_utc": str(row["event_date_utc"]),
                "archived_at_utc": str(row["archived_at_utc"]),
                **event,
            })
        return results

    def pending_upload(self, source_profile_id: str, destination_profile_id: str, limit: int = 100) -> list[dict[str, Any]]:
        source = _safe_profile_id(source_profile_id)
        dest = _safe_profile_id(destination_profile_id)
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT e.event_id,e.payload_json FROM server_events e LEFT JOIN archive_uploads u ON u.source_profile_id=e.profile_id AND u.destination_profile_id=? AND u.event_id=e.event_id WHERE e.profile_id=? AND u.event_id IS NULL ORDER BY e.timestamp_utc ASC LIMIT ?",
                (dest, source, max(1, min(int(limit), 100))),
            ).fetchall()
        output = []
        for row in rows:
            event = json.loads(self._open(source, str(row["event_id"]), row["payload_json"]))
            output.append(event)
        return output

    def mark_uploaded(self, source_profile_id: str, destination_profile_id: str, event_ids: Iterable[str]) -> None:
        source, dest = _safe_profile_id(source_profile_id), _safe_profile_id(destination_profile_id)
        timestamp = utc_now()
        with self._connection() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO archive_uploads(source_profile_id,destination_profile_id,event_id,uploaded_at_utc) VALUES(?,?,?,?)",
                [(source, dest, str(event_id), timestamp) for event_id in event_ids],
            )

    def pin_events(self, profile_id: str, event_ids: Iterable[str]) -> None:
        """Mark an explicitly downloaded event as a deliberate persistent local copy."""
        pid = _safe_profile_id(profile_id)
        values = [(pid, str(event_id), utc_now()) for event_id in event_ids if str(event_id)]
        if not values:
            return
        with self._connection() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO archive_local_pins(profile_id,event_id,pinned_at_utc) VALUES(?,?,?)",
                values,
            )

    def purge_uploaded_events(self, source_profile_id: str, destination_profile_id: str) -> int:
        """Delete acknowledged local payloads but keep explicitly downloaded/pinned copies.

        Upload receipts and pin IDs are metadata only. This method is used by
        server-only mode after successful remote acknowledgement; device/dual modes
        never call it automatically.
        """
        source, dest = _safe_profile_id(source_profile_id), _safe_profile_id(destination_profile_id)
        with self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM server_events WHERE profile_id=? AND EXISTS ("
                "SELECT 1 FROM archive_uploads u WHERE u.source_profile_id=server_events.profile_id "
                "AND u.destination_profile_id=? AND u.event_id=server_events.event_id) "
                "AND NOT EXISTS (SELECT 1 FROM archive_local_pins p WHERE p.profile_id=server_events.profile_id "
                "AND p.event_id=server_events.event_id)",
                (source, dest),
            )
            deleted = int(cursor.rowcount)
            conn.commit()
            # Best-effort WAL truncation so acknowledged payload pages are less likely
            # to remain in the transient journal. OS/SSD backups are outside app control.
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.DatabaseError:
                pass
            return deleted

    def upload_count(self, source_profile_id: str, destination_profile_id: str) -> int:
        source, dest = _safe_profile_id(source_profile_id), _safe_profile_id(destination_profile_id)
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM archive_uploads WHERE source_profile_id=? AND destination_profile_id=?", (source, dest)).fetchone()
        return int(row[0])


def export_archive_json(path: str | Path, profile_id: str, profile_name: str, event_date: str | None,
                        events: list[dict[str, Any]]) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "format": "KawalTrace-server-event-archive",
        "version": 1,
        "generated_at_utc": utc_now(),
        "profile_id": profile_id,
        "profile_name": profile_name,
        "date_filter_utc": event_date or "all",
        "event_count": len(events),
        "events": events,
        "note": "Event berasal dari feed yang dikonfigurasi. Log kosong bukan bukti bahwa server aman.",
    }
    _atomic_write(output, json.dumps(body, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    return output


def export_archive_csv(path: str | Path, events: list[dict[str, Any]]) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    columns = ["event_date_utc", "timestamp_utc", "event_id", "host_id", "event_type", "actor", "source_ip", "source", "profile_name", "details_json"]
    temp = output.with_suffix(output.suffix + ".tmp")
    with temp.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for event in events:
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            row = {key: event.get(key, "") for key in columns}
            row["details_json"] = json.dumps(details, ensure_ascii=False, sort_keys=True)
            for key, value in list(row.items()):
                text = str(value if value is not None else "")[:4000]
                if text.startswith(("=", "+", "-", "@")):
                    text = "'" + text
                row[key] = text
            writer.writerow(row)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, output)
    if os.name != "nt":
        try:
            output.chmod(0o600)
        except OSError:
            pass
    return output


def export_archive_pdf(path: str | Path, profile_name: str, event_date: str | None,
                       events: list[dict[str, Any]]) -> Path:
    """Create a small dependency-free PDF report using the PDF base Helvetica font."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "KAWAL TRACE - LAPORAN LOG SERVER",
        f"Server/profil: {profile_name[:90]}",
        f"Tanggal filter UTC: {event_date or 'Semua tanggal'}",
        f"Dibuat (UTC): {utc_now()}",
        f"Jumlah event: {len(events)}",
        "Catatan: hasil mengikuti data yang tersedia di feed; bukan bukti mutlak bahwa server aman.",
        "-" * 90,
    ]
    for event in events:
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        detail_text = "; ".join(f"{k}={v}" for k, v in list(details.items())[:6])[:160]
        lines.extend([
            f"[{event.get('timestamp_utc','')}] {event.get('event_type','UNKNOWN')} | HOST={event.get('host_id','unknown')} | USER={event.get('actor','unknown')}",
            f"IP={event.get('source_ip','')} | SOURCE={event.get('source','')} | ID={event.get('event_id','')}",
            f"DETAIL: {detail_text or '(tidak ada detail)'}",
            "",
        ])
    wrapped: list[str] = []
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        while len(line) > 105:
            split_at = line.rfind(" ", 0, 105)
            split_at = split_at if split_at > 0 else 105
            wrapped.append(line[:split_at])
            line = "  " + line[split_at:].lstrip()
        wrapped.append(line)
    lines_per_page = 52
    pages = [wrapped[i:i + lines_per_page] for i in range(0, len(wrapped), lines_per_page)] or [[]]

    def pdf_literal(text: str) -> bytes:
        # Helvetica/WinAnsi cannot represent all Unicode. Replace unsupported glyphs, keep file valid.
        data = text.encode("cp1252", errors="replace")
        data = data.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
        return b"(" + data + b")"

    objects: list[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")  # object 1
    page_obj_ids = [3 + i * 2 for i in range(len(pages))]
    font_id = 3 + len(pages) * 2
    kids = b" ".join(f"{obj_id} 0 R".encode("ascii") for obj_id in page_obj_ids)
    objects.append(b"<< /Type /Pages /Kids [" + kids + f"] /Count {len(pages)} >>".encode("ascii"))
    for index, page_lines in enumerate(pages):
        page_id = page_obj_ids[index]
        content_id = page_id + 1
        commands = [b"BT", b"/F1 8 Tf", b"40 800 Td", b"11 TL"]
        for line in page_lines:
            commands.append(pdf_literal(line) + b" Tj")
            commands.append(b"T*")
        commands.append(b"ET")
        stream = b"\n".join(commands)
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode("ascii")
        )
        objects.append(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    content = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(content))
        content.extend(f"{number} 0 obj\n".encode("ascii"))
        content.extend(obj)
        content.extend(b"\nendobj\n")
    xref_offset = len(content)
    content.extend(f"xref\n0 {len(objects)+1}\n".encode("ascii"))
    content.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        content.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    content.extend(
        f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    _atomic_write_bytes(output, bytes(content))
    return output


def _atomic_write(path: Path, content: str) -> None:
    _atomic_write_bytes(path, content.encode("utf-8"))


def _atomic_write_bytes(path: Path, content: bytes) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


class ServerArchiveRemoteClient:
    """Explicit opt-in archive API client for a user-controlled Kawal Trace server."""

    def __init__(self, base_url: str, device_id: str, device_token: str, *, timeout_seconds: float = 12.0,
                 allow_remote_storage: bool = False):
        # Reading history back (date_counts/fetch/fetch_all) is always allowed; writing (upload) is default-deny.
        self.allow_remote_storage = bool(allow_remote_storage)
        self.base_url = str(base_url or "").strip().rstrip("/")
        self.device_id = str(device_id or "").strip()
        self.token = str(device_token or "").strip()
        parsed = urlsplit(self.base_url)
        local = (parsed.hostname or "").lower() in {"localhost", "127.0.0.1", "::1", "[::1]"}
        if parsed.scheme != "https" and not local:
            raise ArchiveError("Arsip server wajib menggunakan HTTPS, kecuali pengujian loopback lokal.")
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ArchiveError("Base URL arsip server tidak valid.")
        if not self.device_id or len(self.device_id) > 128 or any(ch.isspace() for ch in self.device_id):
            raise ArchiveError("Device ID arsip server tidak valid.")
        if len(self.token) < 24 or any(ch.isspace() for ch in self.token):
            raise ArchiveError("Token audit untuk arsip server tidak valid.")
        if not 1 <= timeout_seconds <= 30:
            raise ArchiveError("Timeout arsip server harus 1–30 detik.")
        if httpx is None:
            raise ArchiveError("Dependensi HTTPX belum tersedia.")
        self.timeout_seconds = timeout_seconds

    def _client(self):
        return httpx.Client(
            timeout=httpx.Timeout(self.timeout_seconds, connect=min(4.0, self.timeout_seconds)),
            verify=True,
            follow_redirects=False,
            headers={
                "Authorization": f"Bearer {self.token}",
                "X-KAWAL-Device-ID": self.device_id,
                "Accept": "application/json",
                "User-Agent": "KawalTrace-Archive/2.2.0",
            },
        )

    def upload(self, source_profile_id: str, source_profile_name: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        require_remote_storage(self.allow_remote_storage, "Pengiriman arsip ke server")
        if not events:
            return {"accepted_count": 0, "accepted_event_ids": []}
        source = _safe_profile_id(source_profile_id)
        if len(events) > 100:
            raise ArchiveError("Batch arsip server maksimal 100 event.")
        safe_events = []
        seen = set()
        for raw in events:
            event = dict(raw)
            source_event_id = str(event.get("event_id") or "")
            event_id = remote_archive_event_id(source, source_event_id)
            event["archive_source_event_id"] = source_event_id[:128]
            event["event_id"] = event_id
            event.pop("timestamp_epoch", None)
            # Server uses a strict 64-hex ID and host_id/event schema.
            if not event.get("host_id"):
                event["host_id"] = "unknown-host"
            _id, stamp, payload = _canonical_event(event)
            normalized = json.loads(payload)
            normalized["event_id"] = event_id
            if event_id in seen:
                continue
            seen.add(event_id)
            safe_events.append(normalized)
        body = {
            "schema_version": 1,
            "source_profile_id": source,
            "source_profile_name": " ".join(str(source_profile_name or "").split())[:80],
            "events": safe_events,
        }
        try:
            with self._client() as client:
                response = client.post(self.base_url + REMOTE_BATCH_PATH, json=body)
        except httpx.HTTPError as exc:
            raise ArchiveError(f"Gagal mengirim arsip ke server ({type(exc).__name__}); salinan perangkat tetap tersimpan.") from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise ArchiveError(f"API arsip server mengembalikan respons non-JSON (HTTP {response.status_code}).") from exc
        if not 200 <= response.status_code < 300:
            raise ArchiveError(f"Server menolak arsip (HTTP {response.status_code}: {str(data.get('error','request_rejected'))[:100]}). Salinan perangkat tetap tersimpan.")
        if not isinstance(data, dict) or not isinstance(data.get("accepted_event_ids"), list):
            raise ArchiveError("Respons arsip server tidak sesuai kontrak Kawal Trace.")
        return data

    def date_counts(self, source_profile_id: str) -> list[dict[str, Any]]:
        """Return date partition counts without downloading event payloads."""
        source = _safe_profile_id(source_profile_id)
        try:
            with self._client() as client:
                response = client.get(self.base_url + REMOTE_PATH + "/summary", params={"source_profile_id": source})
        except httpx.HTTPError as exc:
            raise ArchiveError(f"Gagal membaca daftar tanggal arsip server ({type(exc).__name__}).") from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise ArchiveError(f"API arsip server mengembalikan respons non-JSON (HTTP {response.status_code}).") from exc
        if response.status_code == 404:
            raise ArchiveError("Endpoint ringkasan tanggal tidak ditemukan (HTTP 404). Perbarui API opsional Kawal Trace ke v1.4.0 menggunakan optional-server-api/upgrade_membership.sh.")
        if not 200 <= response.status_code < 300:
            raise ArchiveError(f"Daftar tanggal arsip ditolak server (HTTP {response.status_code}).")
        rows = data.get("dates") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise ArchiveError("Respons ringkasan arsip server tidak memiliki array dates.")
        clean: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                raise ArchiveError("Baris ringkasan tanggal arsip tidak valid.")
            date = str(row.get("date") or "")
            try:
                if not DATE_RE.fullmatch(date):
                    raise ValueError
                datetime.strptime(date, "%Y-%m-%d")
                count = int(row.get("count", 0))
            except (ValueError, TypeError):
                raise ArchiveError("Tanggal atau jumlah event pada ringkasan arsip tidak valid.")
            if count < 0:
                raise ArchiveError("Jumlah event pada ringkasan arsip tidak boleh negatif.")
            clean.append({"date": date, "count": count})
        clean.sort(key=lambda item: item["date"], reverse=True)
        return clean

    def fetch(self, source_profile_id: str, event_date: str | None = None, limit: int = 500, offset: int = 0) -> list[dict[str, Any]]:
        source = _safe_profile_id(source_profile_id)
        if not 1 <= limit <= 1000 or not 0 <= int(offset) <= 1_000_000:
            raise ArchiveError("Batas/offset pengambilan arsip server tidak valid.")
        params = {"source_profile_id": source, "limit": limit, "offset": int(offset)}
        if event_date and event_date != "all":
            if not DATE_RE.fullmatch(event_date):
                raise ArchiveError("Tanggal arsip harus YYYY-MM-DD UTC.")
            params["date"] = event_date
        try:
            with self._client() as client:
                response = client.get(self.base_url + REMOTE_PATH + "?" + urlencode(params))
        except httpx.HTTPError as exc:
            raise ArchiveError(f"Gagal mengambil arsip dari server ({type(exc).__name__}).") from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise ArchiveError(f"API arsip server mengembalikan respons non-JSON (HTTP {response.status_code}).") from exc
        if not 200 <= response.status_code < 300:
            raise ArchiveError(f"Pengambilan arsip ditolak server (HTTP {response.status_code}).")
        events = data.get("events") if isinstance(data, dict) else None
        if not isinstance(events, list):
            raise ArchiveError("Respons arsip server tidak memiliki array events.")
        return events


    def fetch_all(self, source_profile_id: str, event_date: str | None = None, page_size: int = 500, max_events: int = 100_000) -> list[dict[str, Any]]:
        """Fetch all available pages with a memory/offset guard."""
        if not 1 <= page_size <= 1000 or not 1 <= max_events <= 100_000:
            raise ArchiveError("Ukuran halaman atau batas arsip tidak valid.")
        collected: list[dict[str, Any]] = []
        offset = 0
        while len(collected) < max_events:
            page = self.fetch(source_profile_id, event_date, min(page_size, max_events - len(collected)), offset)
            collected.extend(page)
            if len(page) < page_size:
                return collected
            offset += len(page)
        # One extra fetch distinguishes complete results from a truncated maximum.
        extra = self.fetch(source_profile_id, event_date, 1, offset)
        if extra:
            raise ArchiveError(f"Arsip server melebihi batas aman {max_events:,} event; pilih tanggal tertentu untuk mengambilnya bertahap.")
        return collected
