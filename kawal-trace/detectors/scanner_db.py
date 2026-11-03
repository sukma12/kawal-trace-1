"""Local SQLite store for the scanner (malware_signatures, phishing_urls, scan history).

All SQL uses bound parameters; no value is ever interpolated into a statement. The
schema follows the project requirements (4 tables, indexes on hash/domain) plus a
schema_migrations table so later versions can migrate without deleting user data.
The database holds hashes, domains and scan results only: it never stores file or
e-mail contents.
"""
from __future__ import annotations

import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from . import ScannerError
from .urlnorm import host_candidates, normalize_indicator, parse_url

SCHEMA_VERSION = 2
SEVERITIES = ("Low", "Medium", "High")
THREAT_TYPES = ("Phishing", "Scam")
STATUSES = ("SAFE", "SUSPICIOUS", "MALWARE", "PHISHING")
FILE_TYPES = ("FILE", "EMAIL")
FINDING_TYPES = ("HASH_MATCH", "AI_DETECTION", "BAD_URL", "HEADER_AUTH", "HEADER_MISMATCH",
                 "URL_HEURISTIC", "ATTACHMENT_RISK", "STATIC", "INFO")
HISTORY_RETENTION_DAYS = 30
MAX_TEXT = 2000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS malware_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_sha256 TEXT NOT NULL CHECK (length(hash_sha256) = 64),
    malware_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Low','Medium','High'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_signatures_hash ON malware_signatures(hash_sha256);
CREATE TABLE IF NOT EXISTS phishing_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_or_url TEXT NOT NULL,
    threat_type TEXT NOT NULL CHECK (threat_type IN ('Phishing','Scam'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_phishing_domain_or_url ON phishing_urls(domain_or_url);
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT NOT NULL,
    file_type TEXT NOT NULL CHECK (file_type IN ('FILE','EMAIL')),
    scan_date TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('SAFE','SUSPICIOUS','MALWARE','PHISHING')),
    details TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scan_history_date ON scan_history(scan_date);
CREATE TABLE IF NOT EXISTS scan_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
    finding_type TEXT NOT NULL CHECK (finding_type IN
        ('HASH_MATCH','AI_DETECTION','BAD_URL','HEADER_AUTH','HEADER_MISMATCH','URL_HEURISTIC','ATTACHMENT_RISK','STATIC','INFO')),
    description TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_details_scan ON scan_details(scan_id);
"""


class ScannerDatabaseError(ScannerError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def clean_text(value: Any, limit: int = MAX_TEXT) -> str:
    """Strip control characters (log/UI injection) and bound the length."""
    return _CTRL_RE.sub("", str(value if value is not None else ""))[:limit]


class ScannerDatabase:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    # ---- connection helpers ------------------------------------------------------
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=10)  # one connection per call: thread-safe
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA trusted_schema = OFF")  # same hardening as the audit store
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists() and self.path.stat().st_size > 0
        if existed:
            self._migrate_v1_to_v2_if_needed()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, _iso(_utc_now())),
            )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _migrate_v1_to_v2_if_needed(self) -> None:
        """Rebuild scan_history/scan_details so their CHECK constraints accept SUSPICIOUS / STATIC.

        SQLite cannot ALTER a CHECK constraint, so the tables are recreated inside ONE transaction
        (all-or-nothing) with every existing row copied, ids included. If anything fails the
        transaction rolls back and the v1 database is left exactly as it was.
        """
        conn = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "scan_history" not in tables:
                return
            version = 0
            if "schema_migrations" in tables:
                version = int(conn.execute("SELECT COALESCE(MAX(version),0) FROM schema_migrations").fetchone()[0])
            if version >= 2:
                return
            conn.execute("PRAGMA foreign_keys = OFF")  # must be set outside a transaction
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("""CREATE TABLE scan_history_v2 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    file_type TEXT NOT NULL CHECK (file_type IN ('FILE','EMAIL')),
                    scan_date TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('SAFE','SUSPICIOUS','MALWARE','PHISHING')),
                    details TEXT NOT NULL DEFAULT '')""")
                conn.execute("INSERT INTO scan_history_v2(id,file_name,file_type,scan_date,status,details) "
                             "SELECT id,file_name,file_type,scan_date,status,details FROM scan_history")
                conn.execute("""CREATE TABLE scan_details_v2 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
                    finding_type TEXT NOT NULL CHECK (finding_type IN
                        ('HASH_MATCH','AI_DETECTION','BAD_URL','HEADER_AUTH','HEADER_MISMATCH','URL_HEURISTIC','ATTACHMENT_RISK','STATIC','INFO')),
                    description TEXT NOT NULL)""")
                conn.execute("INSERT INTO scan_details_v2(id,scan_id,finding_type,description) "
                             "SELECT id,scan_id,finding_type,description FROM scan_details")
                before = (conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0],
                          conn.execute("SELECT COUNT(*) FROM scan_details").fetchone()[0])
                after = (conn.execute("SELECT COUNT(*) FROM scan_history_v2").fetchone()[0],
                         conn.execute("SELECT COUNT(*) FROM scan_details_v2").fetchone()[0])
                if before != after:
                    raise ScannerDatabaseError("Migrasi dibatalkan: jumlah baris tidak sama setelah disalin.")
                conn.execute("DROP TABLE scan_details")
                conn.execute("DROP TABLE scan_history")
                conn.execute("ALTER TABLE scan_history_v2 RENAME TO scan_history")
                conn.execute("ALTER TABLE scan_details_v2 RENAME TO scan_details")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_date ON scan_history(scan_date)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_details_scan ON scan_details(scan_id)")
                conn.execute("INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (2, ?)", (_iso(_utc_now()),))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    def schema_version(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        return int(row["v"] or 0)

    # ---- signatures --------------------------------------------------------------
    def add_signatures(self, rows: Iterable[tuple[str, str, str]]) -> tuple[int, int]:
        """Insert (sha256, name, severity). Returns (inserted, rejected). Duplicates are updated."""
        inserted = rejected = 0
        with self._connect() as conn:
            for sha, name, severity in rows:
                digest = str(sha or "").strip().lower()
                label = clean_text(name, 200).strip()
                sev = str(severity or "").strip().capitalize()
                if not _SHA256_RE.match(digest) or not label or sev not in SEVERITIES:
                    rejected += 1
                    continue
                conn.execute(
                    "INSERT INTO malware_signatures(hash_sha256, malware_name, severity) VALUES (?, ?, ?) "
                    "ON CONFLICT(hash_sha256) DO UPDATE SET malware_name=excluded.malware_name, severity=excluded.severity",
                    (digest, label, sev),
                )
                inserted += 1
        return inserted, rejected

    def lookup_signature(self, sha256: str) -> dict[str, Any] | None:
        digest = str(sha256 or "").strip().lower()
        if not _SHA256_RE.match(digest):
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT hash_sha256, malware_name, severity FROM malware_signatures WHERE hash_sha256 = ?",
                (digest,),
            ).fetchone()
        return dict(row) if row else None

    def all_signature_hashes(self) -> list[str]:
        with self._connect() as conn:
            return [r["hash_sha256"] for r in conn.execute("SELECT hash_sha256 FROM malware_signatures")]

    def signature_count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM malware_signatures").fetchone()["n"])

    # ---- phishing indicators -----------------------------------------------------
    def add_phishing_indicators(self, rows: Iterable[tuple[str, str]]) -> tuple[int, int]:
        inserted = rejected = 0
        with self._connect() as conn:
            for value, threat in rows:
                normalized = normalize_indicator(str(value or ""))
                kind = str(threat or "").strip().capitalize()
                if normalized is None or kind not in THREAT_TYPES:
                    rejected += 1
                    continue
                conn.execute(
                    "INSERT INTO phishing_urls(domain_or_url, threat_type) VALUES (?, ?) "
                    "ON CONFLICT(domain_or_url) DO UPDATE SET threat_type=excluded.threat_type",
                    (normalized[1], kind),
                )
                inserted += 1
        return inserted, rejected

    def lookup_phishing(self, url_or_domain: str) -> dict[str, Any] | None:
        """Exact canonical URL match, or host / parent-domain match."""
        parsed = parse_url(url_or_domain)
        if parsed is None:
            return None
        _, host, canonical = parsed
        candidates = [canonical] + host_candidates(host)
        marks = ",".join("?" for _ in candidates)  # placeholders only; values stay bound
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT domain_or_url, threat_type FROM phishing_urls WHERE domain_or_url IN ({marks}) LIMIT 1",
                candidates,
            ).fetchone()
        return dict(row) if row else None

    def phishing_count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM phishing_urls").fetchone()["n"])

    # ---- history -----------------------------------------------------------------
    def record_scan(self, file_name: str, file_type: str, status: str, details: str,
                    findings: Iterable[tuple[str, str]], *, when: datetime | None = None) -> int:
        if file_type not in FILE_TYPES or status not in STATUSES:
            raise ScannerDatabaseError("Jenis atau status pemindaian tidak valid.")
        stamp = _iso(when or _utc_now())
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scan_history(file_name, file_type, scan_date, status, details) VALUES (?, ?, ?, ?, ?)",
                (clean_text(file_name, 255) or "(tanpa nama)", file_type, stamp, status, clean_text(details)),
            )
            scan_id = int(cursor.lastrowid)
            for kind, description in findings:
                if kind not in FINDING_TYPES:
                    raise ScannerDatabaseError(f"Jenis temuan tidak dikenal: {kind}")
                conn.execute(
                    "INSERT INTO scan_details(scan_id, finding_type, description) VALUES (?, ?, ?)",
                    (scan_id, kind, clean_text(description)),
                )
        return scan_id

    def history(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT id, file_name, file_type, scan_date, status, details FROM scan_history "
                "ORDER BY id DESC LIMIT ?", (limit,))]

    def details(self, scan_id: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT id, scan_id, finding_type, description FROM scan_details WHERE scan_id = ? ORDER BY id",
                (int(scan_id),))]

    def history_count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM scan_history").fetchone()["n"])

    def prune_history(self, days: int = HISTORY_RETENTION_DAYS, *, now: datetime | None = None) -> int:
        """Delete scans older than `days`; their scan_details rows cascade. Returns rows removed."""
        if not 1 <= int(days) <= 3650:
            raise ScannerDatabaseError("Retensi riwayat harus 1-3650 hari.")
        cutoff = _iso((now or _utc_now()) - timedelta(days=int(days)))
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM scan_history WHERE scan_date < ?", (cutoff,))
            return int(cursor.rowcount)

    def clear_history(self) -> int:
        """Delete every scan-history row and its child details, returning the deleted scan count."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM scan_history")
            return int(cursor.rowcount)
