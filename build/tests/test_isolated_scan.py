import hashlib
import os
import sys
import textwrap

import pytest

from detectors import ScanInputError
from detectors.isolated_scan import IsolatedInspector, _safe_to_spawn_python, _validate


@pytest.fixture()
def sample(tmp_path):
    path = tmp_path / "doc.txt"
    path.write_bytes(b"hello kawal trace")
    return path


def test_subprocess_mode_hashes_a_file_in_a_separate_process(sample, tmp_path):
    inspector = IsolatedInspector(workdir=tmp_path / "w")
    try:
        assert inspector.mode == "subprocess", inspector.fallback_reason
        result = inspector.inspect_path(sample, include_md5=True)
        assert result.sha256 == hashlib.sha256(b"hello kawal trace").hexdigest()
        assert result.size == 17 and result.md5 == hashlib.md5(b"hello kawal trace").hexdigest()
        pid_before = inspector._proc.pid
        inspector.inspect_path(sample)
        assert inspector._proc.pid == pid_before  # one long-lived worker, not one per file
        assert pid_before != os.getpid()
    finally:
        inspector.close()


def test_worker_reports_errors_instead_of_crashing(tmp_path):
    inspector = IsolatedInspector(workdir=tmp_path / "w")
    try:
        with pytest.raises(ScanInputError, match="tidak ditemukan"):
            inspector.inspect_path(tmp_path / "missing.bin")
        with pytest.raises(ScanInputError, match="file biasa"):
            inspector.inspect_path(tmp_path)  # a directory
        # worker still alive and usable after errors
        (tmp_path / "ok.txt").write_text("ok")
        assert inspector.inspect_path(tmp_path / "ok.txt").size == 2
    finally:
        inspector.close()


def test_size_limit_is_enforced_in_worker(tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 2048)
    inspector = IsolatedInspector(workdir=tmp_path / "w")
    try:
        with pytest.raises(ScanInputError, match="melebihi batas"):
            inspector.inspect_path(big, max_bytes=1024)
    finally:
        inspector.close()


def test_bytes_mode_never_touches_disk(tmp_path):
    inspector = IsolatedInspector(workdir=tmp_path / "w")
    try:
        payload = b"MZ" + b"\x90" * 300
        result = inspector.inspect_bytes(payload, "invoice.pdf")
        assert result.sha256 == hashlib.sha256(payload).hexdigest()
        assert result.static_score >= 50
        assert not any(p.is_file() for p in (tmp_path / "w").rglob("*"))
    finally:
        inspector.close()


def test_hung_worker_is_killed_and_replaced(tmp_path):
    hang = tmp_path / "hang.py"
    hang.write_text(textwrap.dedent("""
        import json, sys, time
        first = True
        while True:
            line = sys.stdin.buffer.readline()
            if not line: break
            req = json.loads(line)
            if req["mode"] == "ping":
                sys.stdout.buffer.write(json.dumps({"id": req["id"], "ok": True, "pong": True}).encode() + b"\\n"); sys.stdout.buffer.flush()
            else:
                time.sleep(60)
    """))
    inspector = IsolatedInspector(workdir=tmp_path / "w", worker_argv=[sys.executable, "-I", str(hang)], timeout=1.0)
    try:
        assert inspector.mode == "subprocess"
        (tmp_path / "a.txt").write_text("a")
        with pytest.raises(ScanInputError, match="batas waktu"):
            inspector.inspect_path(tmp_path / "a.txt")
        assert inspector._proc is None  # killed, will be restarted on the next call
    finally:
        inspector.close()


def test_garbage_from_worker_is_rejected(tmp_path):
    liar = tmp_path / "liar.py"
    liar.write_text(textwrap.dedent("""
        import json, sys
        while True:
            line = sys.stdin.buffer.readline()
            if not line: break
            req = json.loads(line)
            if req["mode"] == "ping":
                out = {"id": req["id"], "ok": True, "pong": True}
            else:
                out = {"id": req["id"], "ok": True, "sha256": "not-a-hash", "size": 1}
            sys.stdout.buffer.write(json.dumps(out).encode() + b"\\n"); sys.stdout.buffer.flush()
    """))
    inspector = IsolatedInspector(workdir=tmp_path / "w", worker_argv=[sys.executable, "-I", str(liar)])
    try:
        (tmp_path / "a.txt").write_text("a")
        with pytest.raises(ScanInputError, match="hash tidak valid"):
            inspector.inspect_path(tmp_path / "a.txt")
    finally:
        inspector.close()


def test_falls_back_in_process_and_says_so(sample, tmp_path):
    inspector = IsolatedInspector(workdir=tmp_path / "w", use_subprocess=False)
    assert inspector.mode == "in-process" and "dinonaktifkan" in inspector.fallback_reason
    assert "dalam proses yang sama" in inspector.status()
    assert inspector.inspect_path(sample).size == 17


def test_wont_spawn_when_executable_is_not_python(monkeypatch):
    monkeypatch.setattr(sys, "executable", "/opt/app/Kawal-Trace.exe")
    ok, reason = _safe_to_spawn_python()
    assert not ok and "membuka ulang aplikasi" in reason


def test_worker_refuses_to_run_without_the_host_flag(tmp_path):
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {root!r}); "
                          "from detectors.scan_worker import main; raise SystemExit(main())"],
                          capture_output=True, timeout=20, env={})
    assert proc.returncode == 64


def test_worker_has_no_network(tmp_path):
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = (f"import sys; sys.path.insert(0, {root!r}); import detectors.scan_worker as w; w._block_network(); import socket\n"
            "try:\n    socket.socket()\nexcept OSError as e:\n    print('blocked')\n")
    proc = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, timeout=20, text=True)
    assert "blocked" in proc.stdout


@pytest.mark.skipif(os.name == "nt", reason="rlimits are POSIX only")
def test_worker_cannot_write_files(tmp_path):
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target = tmp_path / "x.bin"
    code = (f"import sys; sys.path.insert(0, {root!r}); import detectors.scan_worker as w; w._apply_limits()\n"
            f"try:\n    with open({str(target)!r}, 'wb') as fh:\n        fh.write(b'abc')\n        fh.flush()\n    print('wrote')\n"
            "except BaseException as e:\n    print('blocked', type(e).__name__)\n")
    proc = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, timeout=20, text=True)
    assert "blocked" in proc.stdout and "wrote" not in proc.stdout, proc.stdout + proc.stderr
    assert not target.exists() or target.stat().st_size == 0


def test_validate_rejects_malformed_answers():
    good = {"ok": True, "sha256": "a" * 64, "size": 1}
    assert _validate(good).sha256 == "a" * 64
    for bad in ({}, {"ok": False, "error": "x"}, {**good, "sha256": "A" * 64}, {**good, "size": -1}, {**good, "size": True},
                {**good, "findings": [["x", 500]]}, {**good, "findings": [["x"]]}, {**good, "static_score": 101}, None, []):
        with pytest.raises(ScanInputError):
            _validate(bad)
