from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_alarm_asset_is_a_valid_wave_file():
    asset = (ROOT / "assets" / "security_alert.wav").read_bytes()
    assert asset[:4] == b"RIFF"
    assert asset[8:12] == b"WAVE"


def test_native_notification_dependencies_and_android_permission_are_declared():
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    main = (ROOT / "main.py").read_text(encoding="utf-8")
    assert '"flet-notifications==0.1.4"' in metadata
    assert '"flet-audio==1.0.4"' in metadata
    assert '"cryptography==48.0.0"' in metadata
    assert '"android.permission.POST_NOTIFICATIONS" = true' in metadata
    assert '"android.permission.USE_BIOMETRIC" = true' in metadata
    assert '"android.permission.INTERNET" = true' in metadata
    icon = (ROOT / "assets" / "icon.png").read_bytes()
    assert icon[:8] == b"\x89PNG\r\n\x1a\n"
    assert int.from_bytes(icon[16:20], "big") == 1024
    assert int.from_bytes(icon[20:24], "big") == 1024
    assert '"flet-local-auth>=1.0.4,<2"' in metadata
    assert "request_permissions()" in main
    assert "native_notifications.show(" in main
    assert "winsound.Beep" in main


def test_android_permissions_are_exactly_the_reviewed_set():
    """Every Android permission widens what a compromised app could do: adding one must be a conscious, documented change."""
    import re
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section = metadata.split("[tool.flet.android.permission]", 1)[1].split("\n[", 1)[0]
    declared = set(re.findall(r'^"(android\.permission\.[A-Z_]+)"\s*=\s*true', section, flags=re.MULTILINE))
    assert declared == {
        "android.permission.POST_NOTIFICATIONS",        # alarms
        "android.permission.INTERNET",                  # server connection (HTTPS)
        "android.permission.USE_BIOMETRIC",             # re-verification
        "android.permission.MANAGE_EXTERNAL_STORAGE",   # scanner: read/delete files in shared storage, opt-in by the user
    }
    assert "MANAGE_EXTERNAL_STORAGE" in (ROOT / "docs" / "MALWARE_ISOLATION.md").read_text(encoding="utf-8"), \
        "the broad storage permission must be explained to the user"


def test_build_scripts_target_windows_and_android_artifacts():
    windows = (ROOT / "build_windows.bat").read_text(encoding="utf-8")
    android = (ROOT / "scripts" / "build_android.sh").read_text(encoding="utf-8")
    assert "flet build windows" in windows
    assert "--build-number 13 --build-version 1.0.1" in windows
    assert "flet build apk" in android
    assert "Kawal-Trace" in windows and "Kawal-Trace" in android
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "kawaltrace"' in project
    assert "build_number = 13" in project
    assert 'org = "id.kawaltrace"' in project
    assert 'exclude = [' in project and '"optional-server-api"' in project
    assert "--bundle-id id.kawaltrace.app" in android


def test_universal_readonly_adapter_is_used_for_connect_and_test_actions():
    tree = ast.parse((ROOT / "main.py").read_text(encoding="utf-8"))
    wanted = {"test_server_connection", "connect_selected_server", "refresh_server_feed"}
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted:
            found[node.name] = node
    assert wanted <= found.keys()
    for name in wanted:
        calls = [n for n in ast.walk(found[name]) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        called = {c.func.id for c in calls}
        assert "_make_readonly_feed_client" in called, f"{name} bypasses universal read-only adapters"
