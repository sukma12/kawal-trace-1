"""File scanner: hash a file and match it against the local signature set."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .hashing import DEFAULT_MAX_FILE_BYTES, hash_file
from .signature_matcher import SignatureMatcher


@dataclass
class FileScanResult:
    file_name: str
    sha256: str
    md5: str | None
    size: int
    status: str                 # SAFE | MALWARE
    signature: dict[str, Any] | None
    bloom: str


def scan_file(path: str | Path, matcher: SignatureMatcher, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> FileScanResult:
    info = hash_file(path, include_md5=True, max_bytes=max_bytes)
    verdict = matcher.check(info["sha256"])
    return FileScanResult(
        file_name=Path(path).name, sha256=info["sha256"], md5=info.get("md5"), size=info["size"],
        status="MALWARE" if verdict["match"] else "SAFE",
        signature=verdict if verdict["match"] else None, bloom=verdict["bloom"],
    )
