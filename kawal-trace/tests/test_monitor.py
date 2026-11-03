from __future__ import annotations

import os
from pathlib import Path

from chainlog.monitor import DirectoryMonitor


def test_monitor_baseline_and_no_initial_alert(tmp_path: Path):
    (tmp_path / "brief.txt").write_text("baseline", encoding="utf-8")
    monitor = DirectoryMonitor()
    monitor.select_root(tmp_path)
    baseline = monitor.start_baseline()
    assert baseline["files"] == 1
    assert monitor.poll_once()["events"] == []


def test_monitor_detects_modify_even_if_size_and_mtime_preserved(tmp_path: Path):
    target = tmp_path / "brief.txt"
    target.write_text("alpha", encoding="utf-8")
    monitor = DirectoryMonitor()
    monitor.select_root(tmp_path)
    monitor.start_baseline()

    old_stat = target.stat()
    target.write_text("bravo", encoding="utf-8")  # same number of bytes
    os.utime(target, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))

    batch = monitor.poll_once()
    assert len(batch["events"]) == 1
    assert batch["events"][0]["operation"] == "MODIFIED"
    assert batch["events"][0]["old_sha256"] != batch["events"][0]["new_sha256"]


def test_monitor_detects_create_and_delete(tmp_path: Path):
    target = tmp_path / "new.txt"
    monitor = DirectoryMonitor()
    monitor.select_root(tmp_path)
    monitor.start_baseline()

    target.write_text("new", encoding="utf-8")
    created = monitor.poll_once()["events"]
    assert [event["operation"] for event in created] == ["CREATED"]

    target.unlink()
    deleted = monitor.poll_once()["events"]
    assert [event["operation"] for event in deleted] == ["DELETED"]


def test_monitor_does_not_follow_symlink_directories(tmp_path: Path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("not in watched root", encoding="utf-8")
    try:
        (root / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Pembuatan symbolic link tidak diizinkan pada lingkungan tes ini.")

    monitor = DirectoryMonitor()
    monitor.select_root(root)
    baseline = monitor.start_baseline()
    assert baseline["files"] == 0


def test_resume_does_not_replace_existing_baseline(tmp_path: Path):
    target = tmp_path / "brief.txt"
    target.write_text("baseline", encoding="utf-8")
    monitor = DirectoryMonitor()
    monitor.select_root(tmp_path)
    monitor.start_baseline()
    monitor.stop()
    target.write_text("changed!", encoding="utf-8")

    monitor.resume()
    batch = monitor.poll_once()
    assert len(batch["events"]) == 1
    assert batch["events"][0]["operation"] == "MODIFIED"
