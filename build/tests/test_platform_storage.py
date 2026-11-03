from __future__ import annotations

import sys
from pathlib import Path

from chainlog import core


def test_windows_storage_uses_user_local_appdata(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("KAWAL_TRACE_DATA_DIR", raising=False)
    monkeypatch.delenv("FLET_APP_STORAGE_DATA", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    assert core._application_data_dir() == tmp_path / "LocalAppData" / "Kawal Trace"


def test_android_packaged_storage_prefers_flet_private_storage(monkeypatch, tmp_path: Path):
    private_root = tmp_path / "android-app-private"
    monkeypatch.delenv("KAWAL_TRACE_DATA_DIR", raising=False)
    monkeypatch.setenv("FLET_APP_STORAGE_DATA", str(private_root))
    monkeypatch.setattr(sys, "platform", "linux")
    assert core._application_data_dir() == private_root / "Kawal Trace"


def test_local_audit_store_works_without_server_configuration(tmp_path: Path):
    store = core.AuditStore(tmp_path / "offline" / "chainlog.sqlite3")
    store.initialize()
    entry = store.add_event("NOTE", "offline-user", "local", {"mode": "offline"})
    verified = store.verify()
    assert entry["seq"] >= 1
    assert verified.valid is True
    assert verified.count == entry["seq"]
    assert store.db_path.exists()


def test_kawal_trace_data_dir_override_takes_precedence(monkeypatch, tmp_path: Path):
    configured = tmp_path / "custom-kawal-trace-data"
    monkeypatch.setenv("KAWAL_TRACE_DATA_DIR", str(configured))
    assert core._application_data_dir() == configured


def test_legacy_data_folder_is_migrated_without_losing_contents(monkeypatch, tmp_path: Path):
    parent = tmp_path / "LocalAppData"
    legacy = parent / "Kawal-Trace"
    legacy.mkdir(parents=True)
    (legacy / "sentinel.db").write_text("existing data", encoding="utf-8")
    monkeypatch.delenv("KAWAL_TRACE_DATA_DIR", raising=False)
    monkeypatch.delenv("FLET_APP_STORAGE_DATA", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(parent))
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    result = core._application_data_dir()
    assert result == parent / "Kawal Trace"
    assert (result / "sentinel.db").read_text(encoding="utf-8") == "existing data"
    assert not legacy.exists()
