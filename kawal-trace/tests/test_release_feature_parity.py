from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_every_file_from_user_supplied_project_archive_is_preserved():
    manifest = (ROOT / "docs" / "LEGACY_FILE_MANIFEST.txt").read_text(encoding="utf-8").splitlines()
    missing = [relative for relative in manifest if not (ROOT / relative).is_file()]
    assert missing == [], f"Files from the original project were removed: {missing}"


def test_core_features_still_have_source_modules_and_regression_suites():
    required = {
        "chainlog/core.py": ["AuditStore", "verify"],
        "chainlog/auth.py": ["UserRegistry", "authenticate_device_pin", "set_device_pin"],
        "chainlog/detection.py": ["DetectionEngine"],
        "chainlog/monitor.py": ["DirectoryMonitor"],
        "chainlog/server_feed.py": ["ServerFeedClient"],
        "chainlog/server_archive.py": ["ServerEventArchive", "export_archive_json", "export_archive_csv", "export_archive_pdf"],
        "chainlog/e2ee.py": ["generate_keypair", "import_private_key_backup"],
        "chainlog/website_monitor.py": ["WebsiteMonitorStore"],
        "chainlog/ssh_connector.py": ["SSHReadOnlyConnector"],
        "chainlog/database_audit.py": ["DatabaseAuditConnector"],
        "chainlog/syslog_connector.py": ["SyslogTCPReceiver"],
        "windows_agent/eventlog_agent.py": ["parse_windows_event_xml", "collect_windows_events", "run_forever"],
        "server_agent/chainlog_server_agent.py": ["parse_journal_entry", "Outbox", "main"],
    }
    for relative, symbols in required.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        for symbol in symbols:
            assert symbol in text, f"{symbol} missing from {relative}"

    required_test_files = [
        "test_core.py", "test_auth.py", "test_detection.py", "test_monitor.py",
        "test_connectors.py", "test_server_archive.py", "test_e2ee.py",
        "test_website_monitor.py", "test_ssh_connector.py", "test_database_audit.py",
        "test_syslog_connector.py", "test_server_agent.py", "test_windows_agent.py",
        "test_security_pipeline_e2e.py",
    ]
    for name in required_test_files:
        assert (ROOT / "tests" / name).is_file(), f"Regression test missing: {name}"


def test_all_expected_dashboard_sections_remain_registered():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_build_dashboard")
    section = ast.get_source_segment(source, main_fn) or ""
    keys = {
        '"dashboard"', '"jejak"', '"catat"', '"pantau"', '"website"',
        '"integrasi"', '"telemetri"', '"konektor-audit"', '"lanjutan"', '"akun"',
    }
    missing = sorted(key for key in keys if key not in section)
    assert missing == [], f"Dashboard menu key(s) missing: {missing}"
    labels = [
        "Dashboard", "Jejak Aktivitas", "Catat Aktivitas", "Pantau Folder",
        "Pantau Website", "Integrasi Server", "Telemetri & Arsip",
        "Konektor Audit", "Perlindungan Lanjutan", "Akun Operator",
    ]
    for label in labels:
        assert label in section, f"Dashboard feature disappeared: {label}"


def test_login_has_no_banner_image_and_dashboard_has_no_invalid_database_icon():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    auth_source = source[source.index("def show_auth"):source.index("def _build_dashboard")]
    assert "ft.Image(" not in auth_source
    assert "height=195" not in auth_source
    assert "ft.Icons.DATABASE" not in source
    assert "ft.Icons.TABLE_CHART" in source


def test_dashboard_validates_all_used_flet_icons_before_constructing_controls():
    import re

    source = (ROOT / "main.py").read_text(encoding="utf-8")
    references = set(re.findall(r"ft\.Icons\.([A-Z0-9_]+)", source))
    block = source[source.index("REQUIRED_FLET_ICON_NAMES = ("):source.index("def main(")]
    declared = set(re.findall(r'^\s+"([A-Z0-9_]+)",$', block, flags=re.MULTILINE))
    assert references == declared
    dashboard = source[source.index("def _build_dashboard("):source.index('if __name__ == "__main__":')]
    assert 'mark_stage("validate Flet icon contract")' in dashboard
    assert 'if missing_icons:' in dashboard
    assert 'Flet runtime tidak menyediakan ikon yang digunakan dashboard:' in dashboard
