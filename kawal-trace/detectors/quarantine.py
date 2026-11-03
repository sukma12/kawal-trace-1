"""Quarantine vault: a separate store for files the scanner flagged.

Data separation ("pintu terpisah"): the vault has its own directory and its own SQLite
file. It shares nothing with the audit chain, the account database, the server profiles
or the signature database, and it never opens a network connection.

Life cycle of a detected file:

  detected --(move)--> QUARANTINED --(user: Hapus)---------> DELETED
                                    --(deadline passes)----> AUTO_DELETED   (silent: no notification)
                                    --(user: Pulihkan)-----> RESTORED

Safety rules that make silent auto-deletion acceptable:

* only an exact SHA-256 signature match gets a deadline; heuristic findings are never auto-deleted;
* a file is re-hashed immediately before it is removed from its original location; if it no
  longer matches what was flagged, it is NOT deleted (status SKIPPED_CHANGED);
* the moved copy is hashed again inside the vault, so a file swapped between scan and move is put back;
* symlinks are never followed, directories are never touched, system locations and the
  application's own folders are refused;
* every outcome (including failures) is recorded in the vault history, which the UI shows.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from . import ScannerError

GRACE_SECONDS_DEFAULT = 15 * 60
HISTORY_RETENTION_DAYS = 30
ACTIVE_STATUSES = ("QUARANTINED", "PENDING_IN_PLACE", "REVIEW", "DELETE_FAILED")
CLOSED_STATUSES = ("DELETED", "AUTO_DELETED", "RESTORED", "SKIPPED_CHANGED")
_CHUNK = 1024 * 1024


class QuarantineError(ScannerError):
    pass


def _protected_prefixes(extra: tuple[Path, ...] = ()) -> list[str]:
    prefixes: list[str] = []
    if os.name == "nt":
        for var in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            value = os.environ.get(var)
            if value:
                prefixes.append(value)
        if not prefixes:
            prefixes.extend([r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)"])
    else:
        prefixes.extend(["/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/etc", "/boot", "/proc", "/sys",
                         "/dev", "/run", "/system", "/vendor", "/apex", "/product", "/odm"])
    prefixes.extend(str(p) for p in extra)
    return [os.path.normcase(os.path.realpath(p)) for p in prefixes if p]


def _inside(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("\\/") + os.sep)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    vault_name TEXT,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    size INTEGER NOT NULL,
    malware_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    detection TEXT NOT NULL CHECK (detection IN ('signature','heuristic')),
    detected_at REAL NOT NULL,
    deadline REAL,
    status TEXT NOT NULL,
    resolved_at REAL,
    resolved_by TEXT,
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status, deadline);
"""


class QuarantineVault:
    def __init__(self, base_dir: str | os.PathLike[str], *, clock: Callable[[], float] = time.time,
                 protected_extra: tuple[Path, ...] = ()) -> None:
        self.base_dir = Path(base_dir).expanduser().resolve()
        self.vault_dir = self.base_dir / "vault"
        self.restore_dir = self.base_dir / "restored"
        self.db_path = self.base_dir / "quarantine.sqlite3"
        self._clock = clock
        self._lock = threading.RLock()
        self._extra_protected = tuple(protected_extra)
        for directory in (self.base_dir, self.vault_dir):
            directory.mkdir(parents=True, exist_ok=True)
            self._chmod(directory, 0o700)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        self._chmod(self.db_path, 0o600)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _chmod(path: Path, mode: int) -> None:
        if os.name != "nt":
            try:
                path.chmod(mode)
            except OSError:
                pass

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA trusted_schema = OFF")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _is_protected(self, path: Path) -> str:
        """Return a reason when `path` must never be moved/deleted by the scanner."""
        resolved = os.path.normcase(os.path.realpath(path))
        for prefix in _protected_prefixes():
            if _inside(resolved, prefix):
                return "lokasi sistem yang dilindungi"
        for prefix in _protected_prefixes(self._extra_protected)[len(_protected_prefixes()):]:
            if _inside(resolved, prefix):
                return "folder data aplikasi sendiri"
        base = os.path.normcase(str(self.base_dir.parent))  # the app's own data directory
        vault = os.path.normcase(str(self.vault_dir))
        if _inside(resolved, base) and not _inside(resolved, vault):
            return "folder data aplikasi sendiri"
        project_root = os.path.normcase(os.path.realpath(Path(__file__).resolve().parent.parent))
        if _inside(resolved, project_root):
            return "folder program aplikasi"
        return ""

    def _row(self, conn: sqlite3.Connection, threat_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM threats WHERE id=?", (int(threat_id),)).fetchone()
        if row is None:
            raise QuarantineError("Ancaman tidak ditemukan.")
        return row

    def _set(self, threat_id: int, status: str, *, actor: str = "", note: str = "", clear_deadline: bool = True,
             vault_name: str | None | bool = False) -> None:
        sets = ["status=?", "resolved_at=?", "resolved_by=?", "note=?"]
        values: list[Any] = [status, self._clock() if status in CLOSED_STATUSES else None, actor[:64], note[:300]]
        if clear_deadline and status in CLOSED_STATUSES:
            sets.append("deadline=NULL")
        if vault_name is not False:
            sets.append("vault_name=?")
            values.append(vault_name)
        values.append(int(threat_id))
        with self._connect() as conn:
            conn.execute(f"UPDATE threats SET {', '.join(sets)} WHERE id=?", values)  # column list is fixed above

    # ------------------------------------------------------------------ registration
    def register(self, original_path: str | os.PathLike[str], sha256: str, size: int, malware_name: str,
                 severity: str, *, detection: str = "signature", quarantine: bool = True,
                 grace_seconds: int | None = GRACE_SECONDS_DEFAULT) -> dict[str, Any]:
        """Record a flagged file; optionally move it into the vault. Returns the stored row."""
        if detection not in {"signature", "heuristic"}:
            raise QuarantineError("Jenis deteksi tidak valid.")
        path = Path(os.path.abspath(os.fspath(original_path)))
        with self._lock:
            with self._connect() as conn:
                existing = conn.execute(
                    "SELECT id FROM threats WHERE original_path=? AND sha256=? AND status IN ('QUARANTINED','PENDING_IN_PLACE','REVIEW')",
                    (str(path), sha256)).fetchone()
                if existing is not None:
                    return self.get(int(existing["id"]))
                now = self._clock()
                # Heuristic findings never get a deadline: only an exact signature may be auto-deleted.
                deadline = now + grace_seconds if (detection == "signature" and grace_seconds) else None
                cursor = conn.execute(
                    "INSERT INTO threats(original_path,sha256,size,malware_name,severity,detection,detected_at,deadline,status,note) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (str(path), sha256, int(size), malware_name[:200], severity[:20], detection, now, deadline,
                     "PENDING_IN_PLACE" if deadline else "REVIEW", ""))
                threat_id = int(cursor.lastrowid)

            reason = self._is_protected(path)
            if reason:
                with self._connect() as conn:  # keep it visible, but never schedule deletion for it
                    conn.execute("UPDATE threats SET status='REVIEW', deadline=NULL, note=? WHERE id=?",
                                 (f"Tidak dihapus otomatis: {reason}. Hapus manual setelah memeriksa.", threat_id))
                return self.get(threat_id)
            if os.path.islink(path):
                with self._connect() as conn:
                    conn.execute("UPDATE threats SET status='REVIEW', deadline=NULL, note=? WHERE id=?",
                                 ("Berkas adalah symlink; tidak diikuti dan tidak dihapus otomatis.", threat_id))
                return self.get(threat_id)
            if quarantine:
                self._try_isolate(threat_id, path, sha256)
        return self.get(threat_id)

    def _try_isolate(self, threat_id: int, path: Path, sha256: str) -> None:
        name = f"{threat_id}-{sha256[:16]}.quarantined"  # fixed, non-executable name; never derived from user input
        target = self.vault_dir / name
        try:
            if not path.is_file():
                self._note(threat_id, "File asli sudah tidak ada saat akan dikarantina.")
                return
            shutil.move(str(path), str(target))
        except OSError as exc:
            self._note(threat_id, f"Tidak dapat dipindahkan ke karantina ({type(exc).__name__}); tetap di lokasi asal.")
            if target.exists() and path.exists():  # copy made but original could not be removed
                try:
                    target.unlink()
                except OSError:
                    pass
            return
        self._chmod(target, 0o600)
        try:
            actual = _sha256_file(target)
        except OSError:
            actual = ""
        if actual != sha256:
            # The file changed between scan and move: this is not what was flagged. Put it back.
            try:
                shutil.move(str(target), str(path))
            except OSError:
                pass
            self._set(threat_id, "SKIPPED_CHANGED", note="Berkas berubah setelah dipindai; dikembalikan dan tidak dianggap ancaman.")
            return
        with self._connect() as conn:
            conn.execute("UPDATE threats SET status='QUARANTINED', vault_name=? WHERE id=?", (name, threat_id))

    def _note(self, threat_id: int, note: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE threats SET note=? WHERE id=?", (note[:300], threat_id))

    # ------------------------------------------------------------------ queries
    def get(self, threat_id: int) -> dict[str, Any]:
        with self._connect() as conn:
            return dict(self._row(conn, threat_id))

    def list_threats(self, *, active_only: bool = True, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            if active_only:
                marks = ",".join("?" for _ in ACTIVE_STATUSES)
                rows = conn.execute(f"SELECT * FROM threats WHERE status IN ({marks}) ORDER BY detected_at DESC LIMIT ?",
                                    (*ACTIVE_STATUSES, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM threats ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def seconds_remaining(self, row: dict[str, Any]) -> int | None:
        if row.get("deadline") is None or row.get("status") not in ACTIVE_STATUSES:
            return None
        return max(0, int(row["deadline"] - self._clock()))

    # ------------------------------------------------------------------ actions
    def delete(self, threat_id: int, *, actor: str, auto: bool = False) -> dict[str, Any]:
        """Permanently remove the flagged file. Never raises for filesystem problems: it records them."""
        with self._lock:
            with self._connect() as conn:
                row = dict(self._row(conn, threat_id))
            if row["status"] not in ACTIVE_STATUSES:
                raise QuarantineError("Ancaman ini sudah ditangani.")
            final = "AUTO_DELETED" if auto else "DELETED"
            who = "otomatis-15-menit" if auto else actor

            if row["vault_name"]:
                target = (self.vault_dir / row["vault_name"])
                if target.parent != self.vault_dir:  # defence against a tampered database row
                    self._set(threat_id, "DELETE_FAILED", actor=who, note="Nama berkas karantina tidak valid; tidak dihapus.")
                    return self.get(threat_id)
                try:
                    target.unlink()
                except FileNotFoundError:
                    self._set(threat_id, final, actor=who, note="Berkas karantina sudah tidak ada.")
                except OSError as exc:
                    self._set(threat_id, "DELETE_FAILED", actor=who, note=f"Gagal menghapus berkas karantina ({type(exc).__name__}).")
                else:
                    self._set(threat_id, final, actor=who, note="Berkas karantina dihapus permanen.")
                return self.get(threat_id)

            path = Path(row["original_path"])
            reason = self._is_protected(path)
            if reason:
                self._set(threat_id, "REVIEW", actor=who, note=f"Tidak dihapus: {reason}.", clear_deadline=False)
                with self._connect() as conn:
                    conn.execute("UPDATE threats SET deadline=NULL WHERE id=?", (int(threat_id),))
                return self.get(threat_id)
            try:
                if os.path.islink(path):
                    self._set(threat_id, "DELETE_FAILED", actor=who, note="Symlink tidak dihapus.")
                    return self.get(threat_id)
                if not path.exists():
                    self._set(threat_id, final, actor=who, note="Berkas sudah tidak ada di lokasi asal.")
                    return self.get(threat_id)
                if not path.is_file():
                    self._set(threat_id, "DELETE_FAILED", actor=who, note="Target bukan berkas biasa; tidak dihapus.")
                    return self.get(threat_id)
                if _sha256_file(path) != row["sha256"]:
                    self._set(threat_id, "SKIPPED_CHANGED", actor=who,
                              note="Isi berkas sudah berbeda dari yang terdeteksi; tidak dihapus demi keamanan data.")
                    return self.get(threat_id)
                path.unlink()
            except PermissionError:
                self._set(threat_id, "DELETE_FAILED", actor=who, note="Izin menghapus ditolak atau berkas sedang dipakai.",
                          clear_deadline=False)
            except OSError as exc:
                self._set(threat_id, "DELETE_FAILED", actor=who, note=f"Gagal menghapus ({type(exc).__name__}).", clear_deadline=False)
            else:
                self._set(threat_id, final, actor=who, note="Berkas dihapus permanen dari lokasi asal.")
            return self.get(threat_id)

    def restore(self, threat_id: int, *, actor: str) -> dict[str, Any]:
        """Undo a quarantine (false positive). Never overwrites an existing file."""
        with self._lock:
            with self._connect() as conn:
                row = dict(self._row(conn, threat_id))
            if row["status"] != "QUARANTINED" or not row["vault_name"]:
                raise QuarantineError("Hanya berkas yang sedang dikarantina yang dapat dipulihkan.")
            source = self.vault_dir / row["vault_name"]
            if source.parent != self.vault_dir or not source.is_file():
                raise QuarantineError("Berkas karantina tidak ditemukan.")
            destination = Path(row["original_path"])
            note = "Dipulihkan ke lokasi asal."
            if destination.exists() or not destination.parent.is_dir():
                self.restore_dir.mkdir(parents=True, exist_ok=True)
                self._chmod(self.restore_dir, 0o700)
                destination = self.restore_dir / f"{threat_id}-{Path(row['original_path']).name[:80]}"
                note = f"Lokasi asal tidak tersedia; dipulihkan ke {destination.name} di folder 'restored'."
            try:
                shutil.move(str(source), str(destination))
            except OSError as exc:
                raise QuarantineError(f"Gagal memulihkan ({type(exc).__name__}).") from None
            self._set(threat_id, "RESTORED", actor=actor, note=note)
            return self.get(threat_id)

    def process_due(self) -> list[dict[str, Any]]:
        """Auto-delete everything whose deadline has passed. Silent: callers must not notify."""
        now = self._clock()
        with self._lock:
            with self._connect() as conn:
                due = [int(r["id"]) for r in conn.execute(
                    "SELECT id FROM threats WHERE deadline IS NOT NULL AND deadline<=? AND status IN ('QUARANTINED','PENDING_IN_PLACE')",
                    (now,)).fetchall()]
            results = []
            for threat_id in due:
                try:
                    results.append(self.delete(threat_id, actor="otomatis-15-menit", auto=True))
                except QuarantineError:
                    continue
            return results

    def purge_history(self, days: int = HISTORY_RETENTION_DAYS) -> int:
        cutoff = self._clock() - days * 86400
        marks = ",".join("?" for _ in CLOSED_STATUSES)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(f"DELETE FROM threats WHERE status IN ({marks}) AND resolved_at IS NOT NULL AND resolved_at<?",
                                  (*CLOSED_STATUSES, cutoff))
            return cursor.rowcount
