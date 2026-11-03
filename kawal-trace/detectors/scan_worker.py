"""Isolated scan worker: the only process that touches untrusted file bytes.

Protocol (one JSON object per line on stdin, one JSON line back on stdout):

  {"id": 1, "mode": "ping"}
  {"id": 2, "mode": "path",  "path": "/abs/file", "max_bytes": 536870912, "md5": true}
  {"id": 3, "mode": "bytes", "name": "invoice.pdf", "length": 12345}   # followed by exactly `length` raw bytes

The worker never executes, imports or renders scanned content; it only reads bytes, hashes
them and runs the fixed rules of static_heuristics. Defence in depth on top of that:

* network functions of `socket` are disabled after start-up;
* on POSIX, CPU time, address space and written-file size are capped (RLIMIT_FSIZE=0 means it
  cannot create files at all);
* the host process enforces a wall-clock timeout and kills the worker if it hangs;
* it holds no database handle: the host does the signature lookup with the returned SHA-256.

This is process-level isolation, not a sandbox or VM. A kernel-level bug or a Python-level
parser bug could still matter; see docs/MALWARE_ISOLATION.md.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys

MAX_HEADER_BYTES = 8192
CHUNK = 1024 * 1024
STATIC_SAMPLE_DEFAULT = 8 * 1024 * 1024
STATIC_SAMPLE_CONTAINER = 64 * 1024 * 1024   # zip central directory sits at the END of the file
MAX_BYTES_MODE = 64 * 1024 * 1024
MAX_FINDINGS = 40


def _apply_limits() -> None:
    try:
        import resource
    except ImportError:  # Windows
        return
    limits = (
        (getattr(resource, "RLIMIT_CPU", None), (600, 600)),
        (getattr(resource, "RLIMIT_AS", None), (1024 * 1024 * 1024, 1024 * 1024 * 1024)),
        (getattr(resource, "RLIMIT_FSIZE", None), (0, 0)),
        (getattr(resource, "RLIMIT_CORE", None), (0, 0)),
    )
    for which, value in limits:
        if which is None:
            continue
        try:
            resource.setrlimit(which, value)
        except (ValueError, OSError):
            pass  # Limit not supported here; the host timeout still applies.


def _block_network() -> None:
    import socket

    def _denied(*_args, **_kwargs):
        raise OSError("Akses jaringan dinonaktifkan di worker pemindai.")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "socketpair", "fromfd"):
        if hasattr(socket, name):
            setattr(socket, name, _denied)


def _finding_rows(report) -> list[list]:
    return [[f.description[:300], int(f.weight)] for f in report.findings[:MAX_FINDINGS]]


def _result(request_id, **fields) -> dict:
    out = {"id": request_id, "ok": True}
    out.update(fields)
    return out


def _error(request_id, message: str) -> dict:
    return {"id": request_id, "ok": False, "error": message[:300]}


def inspect_path(path: str, max_bytes: int, include_md5: bool) -> dict:
    """Hash a regular file in a stream and keep a bounded sample for static rules."""
    from .static_heuristics import analyse_bytes

    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("Path file tidak valid.")
    try:
        info = os.stat(path)
    except FileNotFoundError:
        raise ValueError("File tidak ditemukan.") from None
    except OSError as exc:
        raise ValueError(f"File tidak dapat diakses ({type(exc).__name__}).") from None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Hanya file biasa yang dapat dipindai (bukan folder/perangkat/pipa).")
    if info.st_size > max_bytes:
        raise ValueError(f"File melebihi batas pemindaian {max_bytes // (1024 * 1024)} MiB.")

    sha = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False) if include_md5 else None
    sample = bytearray()
    sample_limit = STATIC_SAMPLE_DEFAULT
    total = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(CHUNK)
                if not chunk:
                    break
                if total == 0 and chunk.startswith((b"PK", b"\xd0\xcf\x11\xe0", b"%PDF")):
                    sample_limit = STATIC_SAMPLE_CONTAINER
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"File melebihi batas pemindaian {max_bytes // (1024 * 1024)} MiB.")
                sha.update(chunk)
                if md5 is not None:
                    md5.update(chunk)
                if len(sample) < sample_limit:
                    sample.extend(chunk[: sample_limit - len(sample)])
    except PermissionError:
        raise ValueError("Izin membaca file ditolak.") from None
    except OSError as exc:
        raise ValueError(f"File tidak dapat dibaca ({type(exc).__name__}).") from None

    truncated = total > len(sample)
    report = analyse_bytes(bytes(sample), os.path.basename(path))
    findings = _finding_rows(report)
    if truncated and sample_limit == STATIC_SAMPLE_DEFAULT and report.file_kind in {"zip-container"}:
        findings.append(["Arsip besar: isi tidak dianalisis (hanya hash).", 0])
    out = {"sha256": sha.hexdigest(), "size": total, "file_kind": report.file_kind,
           "entropy": report.entropy, "findings": findings, "static_score": report.score}
    if md5 is not None:
        out["md5"] = md5.hexdigest()
    return out


def inspect_bytes(data: bytes, name: str) -> dict:
    from .static_heuristics import analyse_bytes

    report = analyse_bytes(data, name)
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "file_kind": report.file_kind,
            "entropy": report.entropy, "findings": _finding_rows(report), "static_score": report.score}


def handle(request: dict, stdin) -> dict:
    request_id = request.get("id")
    mode = request.get("mode")
    try:
        if mode == "ping":
            return _result(request_id, pong=True)
        if mode == "path":
            max_bytes = int(request.get("max_bytes") or 0)
            if not 1 <= max_bytes <= 2 * 1024 * 1024 * 1024:
                raise ValueError("Batas ukuran tidak valid.")
            return _result(request_id, **inspect_path(request.get("path"), max_bytes, bool(request.get("md5"))))
        if mode == "bytes":
            length = int(request.get("length", -1))
            if not 0 <= length <= MAX_BYTES_MODE:
                raise ValueError("Ukuran data tidak valid.")
            data = stdin.read(length)
            if len(data) != length:
                raise ValueError("Data terpotong.")
            return _result(request_id, **inspect_bytes(data, str(request.get("name", "upload"))[:200]))
        raise ValueError("Mode tidak dikenal.")
    except ValueError as exc:
        return _error(request_id, str(exc))
    except MemoryError:
        return _error(request_id, "Memori worker habis; berkas terlalu rumit untuk dianalisis.")


def serve(stdin, stdout) -> int:
    while True:
        line = stdin.readline(MAX_HEADER_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_HEADER_BYTES:
            return 2  # Protocol violation: refuse to continue rather than guess framing.
        try:
            request = json.loads(line.decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("bukan objek")
        except (ValueError, UnicodeDecodeError):
            stdout.write(json.dumps(_error(None, "Permintaan tidak valid.")).encode() + b"\n")
            stdout.flush()
            return 2
        response = handle(request, stdin)
        stdout.write(json.dumps(response, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
        stdout.flush()


def main() -> int:
    if os.environ.get("KAWAL_SCAN_WORKER") != "1":
        sys.stderr.write("scan_worker hanya boleh dijalankan oleh pemindai Kawal Trace.\n")
        return 64
    _apply_limits()
    # Import the rule module BEFORE blocking the network/setting limits is not needed (pure
    # stdlib), but importing first keeps lazy imports from failing under RLIMIT_FSIZE.
    from . import static_heuristics  # noqa: F401
    _block_network()
    return serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
