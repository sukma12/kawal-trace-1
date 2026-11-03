"""Host side of the isolated scan worker.

`IsolatedInspector` hands untrusted file bytes to `detectors.scan_worker` in a separate
OS process and validates everything that comes back. When a separate Python process
cannot be started safely (packaged Windows/Android builds where `sys.executable` is the
app itself, or a process-spawn failure) it falls back to running the very same functions
in-process and says so through `mode` / `fallback_reason` — it never pretends to be isolated.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from . import ScanInputError
from .hashing import DEFAULT_MAX_FILE_BYTES

MAX_RESPONSE_BYTES = 256 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PYTHON_NAME_RE = re.compile(r"^python[0-9.]*(w)?(\.exe)?$", re.IGNORECASE)


@dataclass(frozen=True)
class InspectionResult:
    sha256: str
    size: int
    md5: str | None
    file_kind: str
    entropy: float | None
    static_score: int
    findings: tuple[tuple[str, int], ...] = field(default_factory=tuple)


def _validate(response: Any) -> InspectionResult:
    """Treat the worker's answer as untrusted input as well."""
    if not isinstance(response, dict) or not response.get("ok"):
        message = response.get("error") if isinstance(response, dict) else None
        raise ScanInputError(str(message or "Worker pemindai mengembalikan jawaban tidak valid.")[:300])
    sha = response.get("sha256")
    size = response.get("size")
    if not isinstance(sha, str) or not _SHA256_RE.fullmatch(sha):
        raise ScanInputError("Worker pemindai mengembalikan hash tidak valid.")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ScanInputError("Worker pemindai mengembalikan ukuran tidak valid.")
    md5 = response.get("md5")
    if md5 is not None and not (isinstance(md5, str) and re.fullmatch(r"[0-9a-f]{32}", md5)):
        raise ScanInputError("Worker pemindai mengembalikan MD5 tidak valid.")
    rows = response.get("findings") or []
    if not isinstance(rows, list) or len(rows) > 60:
        raise ScanInputError("Worker pemindai mengembalikan temuan tidak valid.")
    findings: list[tuple[str, int]] = []
    for row in rows:
        if (not isinstance(row, list) or len(row) != 2 or not isinstance(row[0], str)
                or not isinstance(row[1], int) or isinstance(row[1], bool) or not 0 <= row[1] <= 100):
            raise ScanInputError("Worker pemindai mengembalikan temuan tidak valid.")
        findings.append((row[0][:300], row[1]))
    entropy = response.get("entropy")
    if entropy is not None and not isinstance(entropy, (int, float)):
        raise ScanInputError("Worker pemindai mengembalikan entropi tidak valid.")
    score = response.get("static_score", 0)
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
        raise ScanInputError("Worker pemindai mengembalikan skor tidak valid.")
    return InspectionResult(sha, size, md5, str(response.get("file_kind", "unknown"))[:40],
                            float(entropy) if entropy is not None else None, score, tuple(findings))


def _safe_to_spawn_python() -> tuple[bool, str]:
    exe = sys.executable or ""
    if getattr(sys, "frozen", False):
        return False, "aplikasi dibundel (frozen); interpreter terpisah tidak tersedia"
    if not exe or not _PYTHON_NAME_RE.match(os.path.basename(exe)):
        return False, f"sys.executable bukan interpreter Python ({os.path.basename(exe) or 'kosong'}); menjalankannya akan membuka ulang aplikasi"
    return True, ""


class IsolatedInspector:
    """Serialises requests to one long-lived worker process; recycles it periodically."""

    def __init__(self, *, project_root: str | Path | None = None, workdir: str | Path | None = None,
                 worker_argv: Sequence[str] | None = None, timeout: float = 120.0,
                 recycle_after: int = 200, use_subprocess: bool = True) -> None:
        self.project_root = Path(project_root) if project_root else Path(__file__).resolve().parent.parent
        self.workdir = Path(workdir) if workdir else None
        self.timeout = float(timeout)
        self.recycle_after = max(1, int(recycle_after))
        self._argv = list(worker_argv) if worker_argv else None
        self._proc: subprocess.Popen[bytes] | None = None
        self._served = 0
        self._next_id = 0
        self._lock = threading.Lock()
        self.mode = "in-process"
        self.fallback_reason = ""
        if not use_subprocess:
            self.fallback_reason = "dinonaktifkan oleh konfigurasi"
        elif self._argv is None:
            ok, reason = _safe_to_spawn_python()
            if ok:
                self._argv = [sys.executable, "-I", "-B", "-c",
                              "import sys; sys.path.insert(0, sys.argv[1]); "
                              "from detectors.scan_worker import main; raise SystemExit(main())",
                              str(self.project_root)]
            else:
                self.fallback_reason = reason
        if self._argv is not None:
            try:
                self._start()
                self.mode = "subprocess"
            except (OSError, ScanInputError) as exc:
                self._kill()
                self._argv = None
                self.fallback_reason = f"worker tidak dapat dimulai ({type(exc).__name__}: {str(exc)[:120]})"

    # ------------------------------------------------------------------ process management
    def _spawn_env(self) -> dict[str, str]:
        env = {"KAWAL_SCAN_WORKER": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"}
        for key in ("SYSTEMROOT", "SystemRoot", "TMP", "TEMP", "LANG", "LC_ALL"):  # Python start-up on Windows needs these
            if key in os.environ:
                env[key] = os.environ[key]
        return env

    def _start(self) -> None:
        assert self._argv is not None
        kwargs: dict[str, Any] = {}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        cwd = None
        if self.workdir is not None:
            self.workdir.mkdir(parents=True, exist_ok=True)
            cwd = str(self.workdir)
        self._proc = subprocess.Popen(
            self._argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=cwd, env=self._spawn_env(), close_fds=True, shell=False, **kwargs,
        )
        self._served = 0
        reply = self._roundtrip({"mode": "ping"}, b"", timeout=15.0)
        if not isinstance(reply, dict) or reply.get("pong") is not True:
            raise ScanInputError("Worker pemindai tidak menjawab ping.")

    def _kill(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.kill()
        except OSError:
            pass
        for stream in (proc.stdin, proc.stdout):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass

    def _roundtrip(self, request: dict[str, Any], payload: bytes, *, timeout: float) -> Any:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.stdout is None:
            raise ScanInputError("Worker pemindai tidak berjalan.")
        self._next_id += 1
        request = dict(request, id=self._next_id)
        timed_out = threading.Event()

        def _expire() -> None:
            timed_out.set()
            try:
                proc.kill()
            except OSError:
                pass

        timer = threading.Timer(timeout, _expire)
        timer.daemon = True
        timer.start()
        try:
            try:
                proc.stdin.write(json.dumps(request, ensure_ascii=True).encode("ascii") + b"\n" + payload)
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass  # The read below reports the failure with the right message.
            line = proc.stdout.readline(MAX_RESPONSE_BYTES + 1)
        finally:
            timer.cancel()
        if timed_out.is_set():
            self._kill()
            raise ScanInputError("Pemindaian melebihi batas waktu; worker dihentikan dan akan dimulai ulang.")
        if not line or len(line) > MAX_RESPONSE_BYTES or not line.endswith(b"\n"):
            self._kill()
            raise ScanInputError("Worker pemindai berhenti tiba-tiba; berkas dilewati.")
        try:
            reply = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._kill()
            raise ScanInputError("Worker pemindai mengirim jawaban rusak.") from None
        if not isinstance(reply, dict) or reply.get("id") != self._next_id:
            self._kill()
            raise ScanInputError("Worker pemindai mengirim jawaban yang tidak cocok.")
        return reply

    def _dispatch(self, request: dict[str, Any], payload: bytes, inproc: Callable[[], dict[str, Any]]) -> InspectionResult:
        with self._lock:
            if self.mode == "in-process":
                try:
                    return _validate({"ok": True, **inproc()})
                except ValueError as exc:
                    raise ScanInputError(str(exc)[:300]) from None
            if self._proc is None or self._proc.poll() is not None or self._served >= self.recycle_after:
                self._kill()
                try:
                    self._start()
                except (OSError, ScanInputError) as exc:
                    self._kill()
                    raise ScanInputError(f"Worker pemindai tidak dapat dimulai ulang: {exc}") from None
            self._served += 1
            return _validate(self._roundtrip(request, payload, timeout=self.timeout))

    # ------------------------------------------------------------------ public API
    def inspect_path(self, path: str | os.PathLike[str], *, max_bytes: int = DEFAULT_MAX_FILE_BYTES,
                     include_md5: bool = False) -> InspectionResult:
        text = os.fspath(path)
        if "\x00" in text:
            raise ScanInputError("Path file mengandung karakter NUL.")
        from . import scan_worker  # same code the subprocess runs

        return self._dispatch({"mode": "path", "path": text, "max_bytes": int(max_bytes), "md5": bool(include_md5)}, b"",
                              lambda: scan_worker.inspect_path(text, int(max_bytes), bool(include_md5)))

    def inspect_bytes(self, data: bytes, name: str = "upload") -> InspectionResult:
        from . import scan_worker

        raw = bytes(data)
        if len(raw) > scan_worker.MAX_BYTES_MODE:
            raise ScanInputError("Data melebihi batas analisis dalam memori (64 MiB).")
        return self._dispatch({"mode": "bytes", "name": str(name)[:200], "length": len(raw)}, raw,
                              lambda: scan_worker.inspect_bytes(raw, str(name)[:200]))

    def close(self) -> None:
        with self._lock:
            self._kill()
            self.mode = "in-process"

    def status(self) -> str:
        if self.mode == "subprocess":
            return "proses terpisah (tanpa jaringan, batas CPU/memori)"
        return f"dalam proses yang sama ({self.fallback_reason or 'tanpa isolasi proses'})"
