"""Local append-only audit log with SHA-256 hash chaining.

The chain is tamper-evident, not tamper-proof. For adversaries with full device
control, periodically anchor exported head hashes in a separate trusted system.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Mapping

from .at_rest import AtRestError, DataCipher, resolve_cipher, scrub_plaintext_remnants

APP_NAME = "Kawal Trace"
SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
ALLOWED_EVENT_TYPES = {"SYSTEM", "AUTH", "ACCESS", "CONFIG", "ALERT", "NOTE", "VERIFY"}


class ChainLogError(Exception):
    """Base error for Kawal Trace."""


class ValidationError(ChainLogError):
    """User supplied data failed validation."""


class IntegrityError(ChainLogError):
    """An operation was blocked because the chain is invalid."""


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    count: int
    head_hash: str
    reason: str = ""
    failing_seq: int | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    """Stable JSON representation for reproducible cryptographic hashing."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def record_hash(record: Mapping[str, Any]) -> str:
    """Compute a record hash from the canonical, hash-covered fields only."""
    body = {
        "seq": int(record["seq"]),
        "timestamp_utc": str(record["timestamp_utc"]),
        "event_type": str(record["event_type"]),
        "actor": str(record["actor"]),
        "source": str(record["source"]),
        "details": record["details"],
        "previous_hash": str(record["previous_hash"]),
    }
    return sha256_text(canonical_json(body))


def _branded_data_path(parent: Path) -> Path:
    """Use the Kawal Trace path and migrate an existing legacy folder if possible."""
    target = parent / APP_NAME
    legacy = parent / "Kawal-Trace"
    if target.exists() or not legacy.is_dir():
        return target
    try:
        legacy.replace(target)
        return target
    except OSError:
        # Keep access to existing data if the OS prevents a safe folder rename.
        return legacy


def _application_data_dir() -> Path:
    """Choose a per-user/per-app writable directory on desktop and mobile."""
    override = os.environ.get("KAWAL_TRACE_DATA_DIR")
    if override:
        return Path(override).expanduser()

    # Flet sets this to its app-private storage directory on packaged clients.
    flet_data = os.environ.get("FLET_APP_STORAGE_DATA")
    if flet_data:
        return _branded_data_path(Path(flet_data))

    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        return _branded_data_path(Path(root) if root else Path.home())
    if sys.platform == "darwin":
        return _branded_data_path(Path.home() / "Library" / "Application Support")
    return _branded_data_path(Path.home() / ".local" / "share")


def _secure_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            path.chmod(0o700)
        except OSError:
            pass


def _decode_row(row: Mapping[str, Any]) -> dict[str, Any]:
    details = row.get("details")
    if details is None and "details_json" in row:
        details = json.loads(row["details_json"])
    return {
        "seq": row["seq"],
        "timestamp_utc": row["timestamp_utc"],
        "event_type": row["event_type"],
        "actor": row["actor"],
        "source": row["source"],
        "details": details,
        "previous_hash": row["previous_hash"],
        "record_hash": row["record_hash"],
    }


def verify_records(records: Iterable[Mapping[str, Any]]) -> VerificationResult:
    """Verify an ordered collection of records without changing persistent data."""
    raw_records = list(records)
    expected_prev = GENESIS_HASH
    last_hash = GENESIS_HASH

    for expected_seq, raw in enumerate(raw_records, start=1):
        seq_for_error: int | None = None
        try:
            if "seq" not in raw:
                raise ValueError("sequence number is missing")
            seq_for_error = int(raw["seq"])
            record = _decode_row(raw)
            if seq_for_error != expected_seq:
                return VerificationResult(
                    False, len(raw_records), last_hash,
                    f"Nomor urut tidak kontinu: seharusnya {expected_seq}, ditemukan {seq_for_error}.",
                    seq_for_error,
                )
            if record["previous_hash"] != expected_prev:
                return VerificationResult(
                    False, len(raw_records), last_hash,
                    "previous_hash tidak cocok dengan hash record sebelumnya.", seq_for_error,
                )
            calculated = record_hash(record)
            stored = str(record["record_hash"])
            if not hmac.compare_digest(calculated, stored):
                return VerificationResult(
                    False, len(raw_records), last_hash,
                    "Hash record tidak cocok; isi log mungkin telah diubah.", seq_for_error,
                )
            expected_prev = stored
            last_hash = stored
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return VerificationResult(
                False, len(raw_records), last_hash,
                f"Record {seq_for_error or expected_seq} tidak dapat dibaca: {exc}",
                seq_for_error or expected_seq,
            )

    return VerificationResult(True, len(raw_records), last_hash, "Seluruh rantai valid.", None)


_AUTO = object()


class AuditStore:
    """SQLite-backed append-only audit store.

    The `details` of every NEW record are encrypted at rest (see chainlog/at_rest.py). The hash chain is computed
    over the plaintext, so verification is unchanged. Rows written before encryption existed stay readable and are
    converted once by `initialize()`. Pass `cipher=None` to open a database strictly as plain text (used only to
    read old plaintext files, e.g. backups made before this feature).
    """

    def __init__(self, db_path: str | Path | None = None, *, cipher: DataCipher | None | object = _AUTO):
        self._cipher_arg = cipher
        if db_path is None:
            data_dir = _application_data_dir()
            _secure_mkdir(data_dir)
            db_path = data_dir / "chainlog.sqlite3"
            self.data_dir = data_dir
        else:
            self.data_dir = Path(db_path).expanduser().parent
            _secure_mkdir(self.data_dir)
        self.db_path = Path(db_path).expanduser().resolve()
        _secure_mkdir(self.db_path.parent)

    # ------------------------------------------------------------------ encryption at rest
    def _cipher(self) -> DataCipher | None:
        """The key is re-resolved on every use (cheap, cached by file signature) so a restore that swaps it is honoured."""
        if self._cipher_arg is not _AUTO:
            return self._cipher_arg  # type: ignore[return-value]
        return resolve_cipher(self.data_dir, self._has_encrypted_rows)

    def _has_encrypted_rows(self) -> bool:
        """True when this database already holds encrypted rows: then a MISSING key must never be replaced by a new one."""
        if not self.db_path.exists():
            return False
        try:
            conn = sqlite3.connect(f"{self.db_path.as_uri()}?mode=ro", uri=True, timeout=5)
            try:
                return conn.execute("SELECT 1 FROM log_entries WHERE details_json LIKE 'kt1:%' LIMIT 1").fetchone() is not None
            finally:
                conn.close()
        except sqlite3.Error:
            return False

    @staticmethod
    def _context(seq: int) -> str:
        return f"audit|{int(seq)}"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            conn.execute("PRAGMA trusted_schema = OFF")
        except sqlite3.DatabaseError:
            pass
        return conn

    @contextmanager
    def _connection(self):
        """Open a short-lived connection and always release its file handle."""
        conn = self._connect()
        try:
            yield conn
        finally:
            if conn.in_transaction:
                conn.rollback()
            conn.close()

    @staticmethod
    def _ensure_schema(conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS log_entries (
                seq INTEGER PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                source TEXT NOT NULL,
                details_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL CHECK(length(previous_hash) = 64),
                record_hash TEXT NOT NULL CHECK(length(record_hash) = 64)
            )
        """)
        conn.execute("CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute(
            "INSERT INTO app_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(SCHEMA_VERSION),)
        )
        # Application-level append-only guardrails. A privileged attacker can still
        # remove triggers or edit the file, so the chain verification remains vital.
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS deny_log_update
            BEFORE UPDATE ON log_entries
            BEGIN SELECT RAISE(ABORT, 'Audit log is append-only'); END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS deny_log_delete
            BEFORE DELETE ON log_entries
            BEGIN SELECT RAISE(ABORT, 'Audit log is append-only'); END
        """)

    def initialize(self) -> None:
        with self._connection() as conn:
            self._ensure_schema(conn)
            row = conn.execute("SELECT COUNT(*) AS n FROM log_entries").fetchone()
            if int(row["n"]) == 0:
                self._insert_record(
                    conn,
                    event_type="SYSTEM",
                    actor="Kawal Trace",
                    source="local-app",
                    details={"message": "Audit log lokal diinisialisasi", "schema_version": SCHEMA_VERSION},
                )
            converted = self._encrypt_legacy_rows(conn)
            if converted:
                try:
                    scrub_plaintext_remnants(conn)
                except sqlite3.Error as exc:
                    # The data IS encrypted; only the cleanup of old bytes in the file failed. Say so in the chain.
                    self._insert_record(conn, event_type="SYSTEM", actor="Kawal Trace", source="local-app", details={
                        "message": "Enkripsi data lama selesai, tetapi sisa teks lama di berkas database belum dibersihkan",
                        "error": str(exc)[:200]})

    def _encrypt_legacy_rows(self, conn: sqlite3.Connection) -> int:
        """Convert rows written before encryption existed, in ONE transaction, without changing any hash.

        The append-only trigger is lifted only inside that transaction (SQLite DDL is transactional, so a crash
        puts everything back). The chain must verify before AND after with an identical head hash, otherwise
        nothing is changed: a database that already fails verification is left exactly as found for investigation.
        """
        cipher = self._cipher()
        if cipher is None:
            return 0
        plain_seqs = [int(r[0]) for r in conn.execute("SELECT seq FROM log_entries WHERE details_json NOT LIKE 'kt1:%' ORDER BY seq")]
        if not plain_seqs:
            return 0
        conn.execute("BEGIN IMMEDIATE")
        try:
            before = verify_records(self._query_records(conn))
            if not before.valid:
                conn.rollback()
                return 0
            conn.execute("DROP TRIGGER IF EXISTS deny_log_update")
            for seq in plain_seqs:
                stored = conn.execute("SELECT details_json FROM log_entries WHERE seq=?", (seq,)).fetchone()[0]
                conn.execute("UPDATE log_entries SET details_json=? WHERE seq=?",
                             (cipher.encrypt_text(stored, self._context(seq)), seq))
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS deny_log_update
                BEFORE UPDATE ON log_entries
                BEGIN SELECT RAISE(ABORT, 'Audit log is append-only'); END
            """)
            after = verify_records(self._query_records(conn))
            if not after.valid or after.head_hash != before.head_hash or after.count != before.count:
                raise IntegrityError("Konversi enkripsi mengubah rantai audit; dibatalkan dan data lama dipertahankan.")
            conn.commit()
            return len(plain_seqs)
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

    def _insert_record(
        self,
        conn: sqlite3.Connection,
        *,
        event_type: str,
        actor: str,
        source: str,
        details: Mapping[str, Any],
    ) -> dict[str, Any]:
        last = conn.execute(
            "SELECT seq, record_hash FROM log_entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq = int(last["seq"]) + 1 if last else 1
        previous_hash = str(last["record_hash"]) if last else GENESIS_HASH
        item = {
            "seq": seq,
            "timestamp_utc": utc_now(),
            "event_type": event_type,
            "actor": actor,
            "source": source,
            "details": dict(details),
            "previous_hash": previous_hash,
        }
        item["record_hash"] = record_hash(item)
        stored_details = canonical_json(item["details"])
        cipher = self._cipher()
        if cipher is not None:
            stored_details = cipher.encrypt_text(stored_details, self._context(seq))
        conn.execute(
            "INSERT INTO log_entries(seq, timestamp_utc, event_type, actor, source, details_json, previous_hash, record_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                item["seq"], item["timestamp_utc"], item["event_type"], item["actor"],
                item["source"], stored_details, item["previous_hash"], item["record_hash"],
            ),
        )
        return item

    def add_event(
        self,
        event_type: str,
        actor: str,
        source: str,
        details: Mapping[str, Any] | str,
    ) -> dict[str, Any]:
        normalized_type = str(event_type).strip().upper()
        if normalized_type not in ALLOWED_EVENT_TYPES:
            raise ValidationError(f"Jenis event harus salah satu: {', '.join(sorted(ALLOWED_EVENT_TYPES))}.")
        normalized_actor = str(actor).strip()
        normalized_source = str(source).strip()
        if not normalized_actor or len(normalized_actor) > 80:
            raise ValidationError("Aktor wajib diisi dan maksimal 80 karakter.")
        if not normalized_source or len(normalized_source) > 120:
            raise ValidationError("Sumber wajib diisi dan maksimal 120 karakter.")
        if isinstance(details, str):
            details_obj: Mapping[str, Any] = {"message": details.strip()}
        else:
            details_obj = dict(details)
        if not details_obj:
            details_obj = {"message": "(tanpa detail)"}
        try:
            details_text = canonical_json(details_obj)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"Detail tidak dapat diserialisasi sebagai JSON: {exc}") from exc
        if len(details_text.encode("utf-8")) > 4096:
            raise ValidationError("Detail maksimal 4 KB.")

        with self._connection() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            rows = self._query_records(conn)
            check = verify_records(rows)
            if not check.valid:
                conn.rollback()
                raise IntegrityError(
                    f"Penambahan log diblokir karena rantai tidak valid pada record {check.failing_seq}: {check.reason}"
                )
            item = self._insert_record(
                conn, event_type=normalized_type, actor=normalized_actor,
                source=normalized_source, details=details_obj,
            )
            conn.commit()
            return item

    def _query_records(self, conn: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT seq, timestamp_utc, event_type, actor, source, details_json, previous_hash, record_hash "
            "FROM log_entries ORDER BY seq ASC"
        ).fetchall()
        output: list[dict[str, Any]] = []
        cipher: DataCipher | None = None
        cipher_loaded = False
        for row in rows:
            item = dict(row)
            stored = item.pop("details_json")
            encrypted = DataCipher.is_encrypted(stored)
            if encrypted and not cipher_loaded:
                cipher, cipher_loaded = self._cipher(), True
            if encrypted and cipher is None:
                raise AtRestError("Database audit terenkripsi, tetapi kunci tidak diberikan.")
            try:
                if encrypted:
                    stored = cipher.decrypt_text(stored, self._context(int(item["seq"])))  # type: ignore[union-attr]
                item["details"] = json.loads(stored)
            except (json.JSONDecodeError, AtRestError):
                # An unreadable or tampered row is preserved as such for the verifier to report; never silently fixed.
                item["details"] = None
                item["details_json"] = "<INVALID JSON>"
            output.append(item)
        return output

    def records(self, limit: int | None = None) -> list[dict[str, Any]]:
        with self._connection() as conn:
            self._ensure_schema(conn)
            records = self._query_records(conn)
        if limit is not None:
            return records[-max(0, limit):] if limit > 0 else []
        return records

    def verify(self) -> VerificationResult:
        try:
            with self._connection() as conn:
                self._ensure_schema(conn)
                integrity_row = conn.execute("PRAGMA integrity_check").fetchone()
                if not integrity_row or str(integrity_row[0]).lower() != "ok":
                    count = int(conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0])
                    return VerificationResult(False, count, GENESIS_HASH, f"SQLite integrity_check gagal: {integrity_row[0] if integrity_row else 'no result'}")
                records = self._query_records(conn)
                return verify_records(records)
        except sqlite3.DatabaseError as exc:
            return VerificationResult(False, 0, GENESIS_HASH, f"Database tidak dapat diverifikasi: {exc}")

    def simulate_tampering(self) -> VerificationResult:
        """Tamper with an in-memory copy only; the real database is never modified."""
        records = self.records()
        if not records:
            return VerificationResult(False, 0, GENESIS_HASH, "Tidak ada record untuk disimulasikan.")
        index = max(0, (len(records) - 1) // 2)
        target = records[index]
        details = target.get("details")
        if not isinstance(details, dict):
            details = {"original": str(details)}
        tampered = dict(target)
        tampered["details"] = dict(details)
        tampered["details"]["SIMULATED_ATTACK"] = "Konten diubah tanpa menghitung ulang hash"
        records[index] = tampered
        result = verify_records(records)
        if result.valid:
            # This should never happen; keep it explicit in case the algorithm changes.
            return VerificationResult(False, len(records), GENESIS_HASH, "Simulasi tidak terdeteksi; periksa implementasi verifikasi.", int(target["seq"]))
        reason = f"SIMULASI: record #{target['seq']} dimanipulasi di memori. {result.reason}"
        return VerificationResult(False, result.count, result.head_hash, reason, result.failing_seq)

    def export_json(self) -> Path:
        records = self.records()
        result = verify_records(records)
        body = {
            "format": "Kawal Trace-export",
            "format_version": 1,
            "exported_at_utc": utc_now(),
            "record_count": len(records),
            "verification": {
                "valid": result.valid,
                "reason": result.reason,
                "head_hash": result.head_hash,
                "failing_seq": result.failing_seq,
            },
            "records": records,
            "warning": "Hash chain bersifat tamper-evident; simpan head_hash/checkpoint di sistem tepercaya terpisah untuk pembuktian lintas perangkat.",
        }
        return self._write_export(f"chainlog-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json", json.dumps(body, ensure_ascii=False, indent=2) + "\n")

    def export_csv(self) -> Path:
        records = self.records()
        name = f"chainlog-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
        exports = self.data_dir / "exports"
        _secure_mkdir(exports)
        path = exports / name
        temp_path = path.with_suffix(path.suffix + ".tmp")
        fields = ["seq", "timestamp_utc", "event_type", "actor", "source", "details_json", "previous_hash", "record_hash"]
        with temp_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for record in records:
                row = dict(record)
                row["details_json"] = canonical_json(row.pop("details", {}))
                writer.writerow(row)
        os.replace(temp_path, path)
        if os.name != "nt":
            try:
                path.chmod(0o600)
            except OSError:
                pass
        return path

    def _write_export(self, name: str, content: str) -> Path:
        exports = self.data_dir / "exports"
        _secure_mkdir(exports)
        path = exports / name
        temp_path = path.with_suffix(path.suffix + ".tmp")
        with temp_path.open("w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        if os.name != "nt":
            try:
                path.chmod(0o600)
            except OSError:
                pass
        return path

    def database_stats(self) -> dict[str, Any]:
        records = self.records()
        result = verify_records(records)
        return {
            "count": len(records),
            "head_hash": result.head_hash,
            "last_timestamp": records[-1]["timestamp_utc"] if records else "—",
            "db_path": str(self.db_path),
            "data_dir": str(self.data_dir),
            "valid": result.valid,
        }
