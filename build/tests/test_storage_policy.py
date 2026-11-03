"""Every database stays on the device: nothing in the app uploads local data to a server."""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from chainlog.core import AuditStore
from chainlog.server_archive import ServerArchiveRemoteClient
from chainlog.storage_policy import REMOTE_STORAGE_DISABLED_MESSAGE, RemoteStorageDisabledError
from chainlog.sync import SyncClient, SyncCursorStore, SyncSettings

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "t" * 48
# Nothing listens here: if either client tried to open a connection the test would see a transport error,
# not the policy error, so a RemoteStorageDisabledError proves that no request was even attempted.
UNREACHABLE = "https://127.0.0.1:9"


def test_sync_client_refuses_to_upload_by_default(tmp_path):
    settings = SyncSettings(base_url=UNREACHABLE, device_id="cl-policy-device-001")
    client = SyncClient(settings, TOKEN, SyncCursorStore(tmp_path / "c.sqlite3"))
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    with pytest.raises(RemoteStorageDisabledError, match="hanya disimpan di perangkat ini"):
        client.sync_once(store)
    assert client.allow_remote_storage is False


def test_archive_client_refuses_to_upload_by_default(tmp_path):
    client = ServerArchiveRemoteClient(UNREACHABLE, "cl-policy-device-001", TOKEN)
    event = {"event_id": "a" * 64, "timestamp_utc": "2026-10-22T01:00:00Z", "host_id": "h", "source": "s",
             "event_type": "AUTH_FAILURE", "actor": "a", "source_ip": "192.0.2.1", "details": {}}
    with pytest.raises(RemoteStorageDisabledError):
        client.upload("srv-policy-profile-001", "Lab", [event])
    with pytest.raises(RemoteStorageDisabledError):
        client.upload("srv-policy-profile-001", "Lab", [])        # even an empty batch is not a loophole


def test_policy_error_is_a_permission_error_with_the_user_facing_message():
    assert issubclass(RemoteStorageDisabledError, PermissionError)
    assert "Penyimpanan jarak jauh dimatikan" in REMOTE_STORAGE_DISABLED_MESSAGE


def _python_sources():
    for path in ROOT.rglob("*.py"):
        parts = set(path.relative_to(ROOT).parts)
        if parts & {"tests", "optional-server-api", ".git", "build", "dist", "__pycache__"}:
            continue
        yield path


def test_application_code_never_opts_in_to_remote_storage():
    offenders = []
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "allow_remote_storage":
                if not (isinstance(node.value, ast.Constant) and node.value.value is False):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.value.lineno}")
    assert offenders == []


def test_the_app_has_no_upload_call_sites_and_no_server_archive_modes():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    assert ".sync_once(" not in source
    assert ".upload(" not in source
    assert "sync_archive_to_server" not in source and "background_sync_loop" not in source
    assert not re.search(r'["\']server_and_device["\']', source.split("legacy_remote_archive = ")[1].split("\n", 1)[1])
    assert "archive_destination_dropdown" not in source
    assert "Perangkat ini saja (tidak dikirim ke server)" in source


def test_older_remote_archive_preference_is_forced_back_to_the_device_but_remembered_for_migration():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    assert 'legacy_remote_archive = archive_preferences.get("mode") in {"server", "server_and_device"}' in source
    assert 'archive_preferences["mode"] = "device"' in source
