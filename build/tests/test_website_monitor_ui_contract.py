from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_website_monitor_is_a_separate_navigation_mode_without_api_token_fields():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    assert '("website", "Pantau Website", ft.Icons.LANGUAGE, [website_monitor_panel])' in source
    assert 'label="URL website (HTTP/HTTPS, tanpa kredensial)"' in source
    assert 'content="Simpan target"' in source
    assert 'content="Uji sekarang"' in source
    assert 'content="Mulai pemantauan"' in source
    assert "page.run_task(delete_website_target, tid)" in source
    assert "page.run_task(toggle_website_target, tid, not en)" in source
    assert "WebsiteMonitorStore(" in source
    assert "encryption_key=key_hex.lower()" in source
    assert "DATABASE TERENKRIPSI SIAP" in source
    assert "refresh_website_targets()" in source


def test_website_monitor_does_not_start_automatically_at_dashboard_launch():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    assert 'website_monitor_state: dict[str, bool] = {"active": False}' in source
    # Initial render only populates local controls; no target is probed until the operator asks.
    assert "refresh_website_targets()" in source
    assert "page.run_task(initialize_website_monitor_store)" in source
    assert "refresh_summary()" in source
    assert source.index("refresh_website_targets()", source.index('mark_stage("load initial archive and monitor data")')) < source.index("page.run_task(initialize_website_monitor_store)") < source.index("refresh_summary()", source.index('mark_stage("refresh audit summary")'))
    assert 'website_monitor_state["active"] = True' in source
    assert 'page.run_task(website_monitor_loop)' in source
    assert 'website_monitor_state["active"] = False' in source


def test_documentation_is_explicit_about_website_mode_security_limitations():
    guide = (ROOT / "docs" / "WEBSITE_MONITORING.md").read_text(encoding="utf-8").lower()
    assert "tidak meminta token api" in guide
    assert "terpisah" in guide
    assert "sqlcipher" in guide
    assert "dns rebinding" in guide
    assert "aes-256-gcm" in guide
    assert "secure storage os" in guide
