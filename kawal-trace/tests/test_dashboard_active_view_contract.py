"""Source-level guards for the dashboard navigation architecture.

Behaviour (clicking every menu, lint of the mounted tree, error containment) is covered by
tests/test_dashboard_render_contract.py, which executes the real dashboard code. These checks only pin the
structural decisions that code relies on, so a refactor cannot silently reintroduce the old patterns.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _source() -> str:
    return (ROOT / "main.py").read_text(encoding="utf-8")


def test_dashboard_mounts_only_the_active_page_in_one_persistent_body():
    source = _source()
    start = source.index("    page_controls: dict[str, list[ft.Control]]")
    end = source.index("    def is_compact() -> bool:", start)
    layout = source[start:end]
    assert 'visible=(key == "dashboard")' not in source
    assert "page_body = ft.Column(" in layout
    assert "expand=True, scroll=ft.ScrollMode.HIDDEN" in layout
    assert "view_host" not in source and "page_views" not in source


def test_go_to_swaps_controls_without_rebuilding_the_sidebar_and_contains_failures():
    source = _source()
    go_start = source.index("    def go_to(key: str) -> None:")
    go_end = source.index("    def on_page_resize", go_start)
    go_to = source[go_start:go_end]
    assert "page_body.controls = page_controls[key]" in go_to
    assert "render_sidebar()" not in go_to                  # rebuilding disposed the button being handled
    assert "style_nav(previous, False)" in go_to and "style_nav(key, True)" in go_to
    assert "page_error_card(key, exc, diag)" in go_to       # a failing page shows a card, never a blank surface
    assert "for view_key, view in" not in go_to


def test_topbar_never_puts_a_flexible_child_inside_a_wrapping_row():
    source = _source()
    start = source.index("    topbar = ft.Column(")
    end = source.index("    content_area = ft.Column(", start)
    topbar = source[start:end]
    assert "wrap=True" not in topbar                        # Flutter cannot flex inside Wrap
    assert "expand=True" in topbar
    content_start = end
    content_end = source.index('    mark_stage("attach dashboard layout")', content_start)
    content_area = source[content_start:content_end]
    assert "page_body," in content_area and "list(page_controls.values())" not in content_area
    root_start = content_end
    root_end = source.index('    mark_stage("load initial archive and monitor data")', root_start)
    root_layout = source[root_start:root_end]
    assert "ft.SafeArea(\n            expand=True," in root_layout
    assert "expand=True,\n                padding" not in root_layout   # no `expand` on non-flex Container/Row inside SafeArea


def test_brand_mark_uses_the_supplied_kawal_trace_key_asset():
    source = _source()
    assert 'ft.Image(src="kawal_trace_key.png"' in source
    sidebar_source = source[source.index('def render_sidebar()'):source.index('page_open_hooks:')]
    assert 'ft.Icons.SHIELD, size=22' not in sidebar_source


def test_dashboard_uses_actual_connector_state_for_the_animation_not_a_fake_timer():
    source = _source()
    assert 'edge_specs = [' in source
    assert 'connector_runtime_state["ssh_status"] = "good"' in source
    assert 'connector_runtime_state["ssh_status"] = "bad"' in source
    assert 'startConnectionProcess' not in source


def test_startup_goes_directly_to_session_or_login_without_video():
    source = _source()
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "flet-video" not in requirements and "flet-video" not in metadata
    assert "flet_video" not in source and "Animasi-HD.mp4" not in source
    assert "if not try_resume_session():\n        show_auth()" in source
    assert (ROOT / "assets" / "kawal_trace_key.png").is_file()


def test_dashboard_uses_server_connection_verification_topology():
    source = _source()
    assert "status_rows_column" not in source
    assert 'status_overview_panel = topology_visual' in source
    for feature in ("AUDIT CORE", "VERIFIKASI", "SSH", "SQL", "TCP", "SYSLOG", "SERVER API"):
        assert feature in source
    # Malware scanning remains a separate feature; it is deliberately not a node
    # in the server-connection diagram.
    assert 'Pemindai keamanan' in source and 'MALWARE SCAN' not in source
    assert "bezier_point" in source and "append_curve" in source
