from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_readonly_connectors_are_wired_to_an_explicit_ui_page_and_hash_chain():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    assert '("konektor-audit", "Konektor Audit", ft.Icons.LAN, [connector_panel])' in source
    assert 'content="Uji SSH & impor event"' in source
    assert 'content="Uji database & impor 100 event"' in source
    assert 'content="Mulai listener syslog"' in source
    assert 'on_click=stop_syslog_listener' in source
    assert "connector_ingestor.ingest" in source
    assert "secure_storage.set(secret_key, private_key)" in source
    assert "secure_storage.set(secret_key, password_value)" in source


def test_syslog_ui_requires_mutual_tls_for_non_loopback_listener():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "def _build_syslog_tls_context(host: str)" in source
    assert "context.verify_mode = ssl.CERT_REQUIRED" in source
    assert "context.minimum_version = ssl.TLSVersion.TLSv1_2" in source
    assert '"listener non-loopback harus menggunakan mTLS."' in source or "listener non-loopback wajib" in source.lower()
