"""File Hashing Module: stream a file into SHA-256 (and optional legacy MD5).

SHA-256 is the only digest used for malware-signature decisions. MD5 is exposed
only as an informational value that analysts often quote; it is collision-prone
and must never be used to declare a file safe.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from . import ScanInputError

CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 512 * 1024 * 1024  # refuse absurd inputs on phones/laptops


def hash_bytes(data: bytes, *, include_md5: bool = False) -> dict[str, Any]:
    """Hash an in-memory payload (for e-mail attachments)."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ScanInputError("Data yang di-hash harus bytes.")
    raw = bytes(data)
    result: dict[str, Any] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    if include_md5:
        result["md5"] = hashlib.md5(raw, usedforsecurity=False).hexdigest()
    return result


def hash_file(path: str | os.PathLike[str], *, include_md5: bool = False,
              max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> dict[str, Any]:
    """Stream-hash a regular file. The file is opened read-only and never executed.

    Raises ScanInputError for missing/unreadable/non-regular/oversized files so the
    caller can report a precise reason instead of silently calling the file safe.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes harus positif")
    try:
        candidate = Path(path)
    except TypeError as exc:
        raise ScanInputError("Path file tidak valid.") from exc
    if "\x00" in str(candidate):
        raise ScanInputError("Path file mengandung karakter NUL.")
    try:
        info = candidate.stat()  # follows symlinks: we hash what the user selected
    except FileNotFoundError as exc:
        raise ScanInputError("File tidak ditemukan.") from exc
    except OSError as exc:
        raise ScanInputError(f"File tidak dapat diakses ({type(exc).__name__}).") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ScanInputError("Hanya file biasa yang dapat dipindai (bukan folder/perangkat/pipa).")
    if info.st_size > max_bytes:
        raise ScanInputError(f"File melebihi batas pemindaian {max_bytes // (1024 * 1024)} MiB.")
    sha = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False) if include_md5 else None
    total = 0
    try:
        with candidate.open("rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:  # file grew while reading
                    raise ScanInputError(f"File melebihi batas pemindaian {max_bytes // (1024 * 1024)} MiB.")
                sha.update(chunk)
                if md5 is not None:
                    md5.update(chunk)
    except PermissionError as exc:
        raise ScanInputError("Izin membaca file ditolak.") from exc
    except OSError as exc:
        raise ScanInputError(f"File tidak dapat dibaca ({type(exc).__name__}).") from exc
    result: dict[str, Any] = {"sha256": sha.hexdigest(), "size": total}
    if md5 is not None:
        result["md5"] = md5.hexdigest()
    return result
