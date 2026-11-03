"""Transparent, user-initiated directory integrity monitor.

This module monitors only a directory explicitly selected by the logged-in user.
It does not install a service, hide itself, change files, or infer an OS-level
actor from filesystem changes. Events are classified as UNATTRIBUTED/review.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any


MAX_FILES_PER_SCAN = 2500
MAX_HASH_BYTES_PER_SCAN = 128 * 1024 * 1024
MAX_HASH_FILE_BYTES = 64 * 1024 * 1024
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "$recycle.bin"}
SKIP_FILES = {"chainlog.sqlite3", "chainlog.sqlite3-wal", "chainlog.sqlite3-shm", "identity.sqlite3", "identity.sqlite3-wal", "identity.sqlite3-shm", "monitor-root.txt"}


class MonitorError(Exception):
    """Invalid monitor setup or filesystem error."""


def _sha256_file(path: Path, limit: int) -> str | None:
    """Hash a stable regular file, respecting per-scan byte budgets outside this helper."""
    try:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        after = path.stat(follow_symlinks=False)
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            # File was actively being written; wait for the next scan.
            return None
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


class DirectoryMonitor:
    """Snapshot-and-hash monitor with explicit baseline and no automatic startup."""

    def __init__(self) -> None:
        self.root: Path | None = None
        self._snapshot: dict[str, dict[str, Any]] = {}
        self._started = False
        self._has_baseline = False
        self._scan_truncated = False
        self.last_warning = ""

    @property
    def active(self) -> bool:
        return self._started

    @property
    def has_baseline(self) -> bool:
        return self._has_baseline

    @property
    def baseline_count(self) -> int:
        return len(self._snapshot)

    @property
    def root_label(self) -> str:
        return str(self.root) if self.root else "Folder belum dipilih"

    def select_root(self, root: str | Path) -> Path:
        original = Path(root).expanduser()
        if original.is_symlink():
            raise MonitorError("Folder target tidak boleh berupa symbolic link.")
        candidate = original.resolve()
        if not candidate.exists() or not candidate.is_dir():
            raise MonitorError("Folder tidak ditemukan atau bukan direktori.")
        if candidate == Path(candidate.anchor).resolve():
            raise MonitorError("Demi keamanan dan performa, jangan pantau seluruh drive/root. Pilih folder data yang lebih spesifik.")
        if candidate.is_symlink():
            raise MonitorError("Folder target tidak boleh berupa symbolic link.")
        self.root = candidate
        self._snapshot = {}
        self._started = False
        self._has_baseline = False
        self.last_warning = ""
        return candidate

    def _scan(self) -> tuple[dict[str, dict[str, Any]], bool, str]:
        if self.root is None:
            raise MonitorError("Pilih folder terlebih dahulu.")
        if not self.root.is_dir():
            self._started = False
            raise MonitorError("Folder pantauan tidak lagi tersedia. Pemantauan dihentikan.")

        snapshot: dict[str, dict[str, Any]] = {}
        total_hashed_bytes = 0
        file_limit_hit = False
        hash_budget_hit = False
        skipped = 0

        for current, dirs, files in os.walk(self.root, topdown=True, followlinks=False):
            dirs[:] = sorted(
                d for d in dirs
                if d.lower() not in SKIP_DIRS
                and not (Path(current) / d).is_symlink()
            )
            for file_name in sorted(files):
                if file_name.lower() in SKIP_FILES or file_name.endswith((".tmp", ".temp")):
                    continue
                full_path = Path(current) / file_name
                try:
                    st = full_path.stat(follow_symlinks=False)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    relative = full_path.relative_to(self.root).as_posix()
                except (OSError, ValueError):
                    skipped += 1
                    continue

                if len(snapshot) >= MAX_FILES_PER_SCAN:
                    file_limit_hit = True
                    break

                digest: str | None = None
                if st.st_size <= MAX_HASH_FILE_BYTES and total_hashed_bytes + st.st_size <= MAX_HASH_BYTES_PER_SCAN:
                    digest = _sha256_file(full_path, MAX_HASH_FILE_BYTES)
                    if digest is not None:
                        total_hashed_bytes += st.st_size
                else:
                    hash_budget_hit = True

                snapshot[relative] = {
                    "size": int(st.st_size),
                    "mtime_ns": int(st.st_mtime_ns),
                    "sha256": digest,
                }
            if file_limit_hit:
                break

        warnings: list[str] = []
        if file_limit_hit:
            warnings.append(f"Batas {MAX_FILES_PER_SCAN} file tercapai; daftar parsial, penghapusan tidak disimpulkan dari scan ini.")
        if hash_budget_hit:
            warnings.append("Batas hashing 128 MiB/scan atau 64 MiB/file tercapai; file besar memakai metadata sebagai fallback.")
        if skipped:
            warnings.append(f"{skipped} file tidak dapat dibaca; hasil untuk file tersebut mungkin tertunda.")
        warning = " ".join(warnings)
        self._scan_truncated = file_limit_hit
        return snapshot, not file_limit_hit and skipped == 0, warning

    def start_baseline(self) -> dict[str, Any]:
        """Establish a new baseline. Starting is an explicit operator action."""
        if self.root is None:
            raise MonitorError("Pilih folder terlebih dahulu.")
        snapshot, complete, warning = self._scan()
        if not snapshot and warning:
            raise MonitorError("Tidak ada file yang berhasil dipindai. " + warning)
        self._snapshot = snapshot
        self._started = True
        self._has_baseline = True
        self.last_warning = warning
        return {"root": str(self.root), "files": len(snapshot), "complete": complete, "warning": warning}

    def resume(self) -> None:
        """Resume from the existing snapshot without silently replacing its baseline."""
        if self.root is None or not self._has_baseline:
            raise MonitorError("Baseline belum tersedia. Mulai pemantauan untuk membuat baseline awal.")
        if not self.root.is_dir():
            raise MonitorError("Folder pantauan tidak lagi tersedia.")
        self._started = True

    def stop(self) -> None:
        self._started = False

    def poll_once(self) -> dict[str, Any]:
        """Return detected changes. Does not claim to identify the OS-level actor."""
        if not self._started:
            return {"events": [], "warning": self.last_warning, "scanned": 0}
        current, complete, warning = self._scan()
        previous = self._snapshot
        events: list[dict[str, Any]] = []
        now_keys, old_keys = set(current), set(previous)

        for rel_path in sorted(now_keys - old_keys):
            state = current[rel_path]
            events.append({"operation": "CREATED", "path": rel_path, "old_sha256": None,
                           "new_sha256": state["sha256"], "size": state["size"], "severity": "HIGH"})

        for rel_path in sorted(old_keys & now_keys):
            before, after = previous[rel_path], current[rel_path]
            changed = (
                before["size"] != after["size"]
                or before["mtime_ns"] != after["mtime_ns"]
                or (before["sha256"] is not None and after["sha256"] is not None
                    and before["sha256"] != after["sha256"])
            )
            if changed:
                events.append({"operation": "MODIFIED", "path": rel_path,
                               "old_sha256": before["sha256"], "new_sha256": after["sha256"],
                               "old_size": before["size"], "size": after["size"], "severity": "HIGH"})

        # Do not generate deletion alarms from incomplete scans, to avoid false positives.
        if complete:
            for rel_path in sorted(old_keys - now_keys):
                before = previous[rel_path]
                events.append({"operation": "DELETED", "path": rel_path,
                               "old_sha256": before["sha256"], "new_sha256": None,
                               "old_size": before["size"], "size": 0, "severity": "CRITICAL"})

        # Keep old states for paths omitted from incomplete scans so they aren't falsely deleted.
        if complete:
            self._snapshot = current
        else:
            merged = dict(previous)
            merged.update(current)
            self._snapshot = merged

        self.last_warning = warning
        return {"events": events, "warning": warning, "scanned": len(current), "complete": complete}
