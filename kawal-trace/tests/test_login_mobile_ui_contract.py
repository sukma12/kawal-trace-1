from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _main_source() -> str:
    return (ROOT / "main.py").read_text(encoding="utf-8")


def test_new_install_does_not_create_admin_before_setup_form():
    source = _main_source()
    tree = ast.parse(source)
    main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    call_names = {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(main_fn)
        if isinstance(node, ast.Call) and (isinstance(node.func, ast.Name) or isinstance(node.func, ast.Attribute))
    }
    assert "needs_setup" in call_names
    assert "ensure_default_admin_once" not in call_names
    assert '"Buat akun administrator" if initial_setup else' in source
    assert '"Amankan akun lokal lama" if legacy_migration else' in source
    assert '4–10 karakter: huruf, angka, titik, _ atau -' in source
    assert '"max_length": 32 if credential_rotation else 10' in source
    assert 'max_length=256 if credential_rotation else 128' in source
    assert 'label="Kata sandi baru (8–128 karakter)"' in source
    assert '6–12' not in source   # the old password policy must not survive anywhere in the UI text
    assert "DEFAULT_ADMIN_PASSWORD" not in source
    assert "DEFAULT_ADMIN_USERNAME" not in source
    assert 'on_click=submit' in source


def test_pin_panel_is_collapsed_and_only_offered_for_a_configured_pin():
    source = _main_source()
    assert "device_account = None if (initial_setup or credential_rotation) else registry.device_unlock_user()" in source
    assert re.search(r"visible=False,\s*content=ft\.Column\(controls=\[", source)
    assert 'content="Masuk dengan PIN perangkat"' in source
    assert '"Sembunyikan PIN perangkat" if pin_unlock_panel.visible' in source
    assert "controls.extend([pin_toggle_button, pin_unlock_panel])" in source


def test_biometrics_require_supported_platform_and_enrolled_method():
    source = _main_source()
    assert 'platform_name not in {"android", "ios", "windows", "macos"}' in source
    assert "await local_auth_service.is_device_supported()" in source
    assert "await local_auth_service.can_check_biometrics()" in source
    assert "await local_auth_service.get_available_biometrics()" in source
    assert "if supported and can_check and available and biometric_button is not None" in source


def test_login_and_dashboard_are_scrollable_and_mobile_navigation_expands_content():
    source = _main_source()
    assert "auth_column = ft.Column(" in source
    assert "scroll=ft.ScrollMode.HIDDEN" in source
    assert "page.scroll = None" in source
    assert "def responsive_card_width()" in source
    assert "auth_root = ft.Container(" in source
    assert "alignment=ft.Alignment(0, 0)" in source
    assert "page.on_resize = on_auth_resize" in source
    assert 'mobile_nav_dropdown.visible = compact' in source
    assert 'sidebar.visible = not compact' in source
    assert "ft.SafeArea(" in source


def test_dashboard_failure_log_contains_stage_and_traceback():
    source = _main_source()
    assert 'startup_stage = {"name": "dashboard preflight"}' in source
    assert 'stage=startup_stage["name"]' in source
    assert 'f"stage={_redact_diagnostic_text(stage)!r}' in source
    assert "traceback.format_exc()" in source
    assert "exception_summary = _redact_diagnostic_text(str(exc))[:240]" in source
    assert "Ringkasan: {exception_summary}" in source
    assert "safe_trace = _redact_diagnostic_text(trace)" in source
    assert "diagnostic_column = ft.Column(" in source
    assert "scroll=ft.ScrollMode.HIDDEN" in source
    assert '"load initial archive and monitor data"' in source
    assert '"verify local audit chain"' in source


def test_visible_app_version_is_1_0_1_and_package_version_is_semver_1_0_1():
    source = _main_source()
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    installer = (ROOT / "installer" / "kawal-trace.iss").read_text(encoding="utf-8")
    assert re.search(r'^APP_VERSION = "1\.0"$', source, flags=re.MULTILINE)
    assert re.search(r'^version = "1\.0\.1"$', metadata, flags=re.MULTILINE)
    assert '#define AppVersion "1.0.1"' in installer


def test_dashboard_diagnostic_view_is_responsive_and_sanitizes_secrets():
    source = _main_source()
    assert 'card_width = int(max(240, min(620, viewport_width - 24)))' in source or 'card.width = int(max(200, min(620, live_width - 32)))' in source
    assert 'page.on_resize = on_diagnostic_resize' in source
    redaction = (ROOT / "chainlog" / "redaction.py").read_text(encoding="utf-8")
    assert 'r"(?i)\\b(password|passwd|token|api[_-]?key|secret|authorization|cookie|private[_-]?key|passphrase)\\b' in redaction
    assert 'Bearer [REDACTED]' in redaction
    assert "return redact_secrets(value)" in source
    assert 'Coba buka lagi' in source
    assert 'Kembali ke login' in source


def test_app_version_is_passed_to_sync_client():
    sync_source = (ROOT / "chainlog" / "sync.py").read_text(encoding="utf-8")
    assert re.search(r'^APP_VERSION = "1\.0"$', sync_source, flags=re.MULTILINE)


def test_fixed_login_and_dashboard_controls_follow_viewport_width():
    source = _main_source()
    assert "def responsive_auth_button_width() -> int" in source
    assert "submit_button.width = responsive_width" in source
    assert "pin_toggle_button.width = responsive_width" in source
    assert "responsive_width_bindings: list[tuple[Any, float, float]] = []" in source
    assert "def responsive_dashboard_width(maximum: float, reserve: float = 64.0) -> float" in source
    assert "archive_storage_mode_container = responsive_width(" in source
    assert "archive_date_container = responsive_width(" in source
    assert "export_json_button = responsive_width(" in source
    assert "for control, maximum, reserve in responsive_width_bindings" in source


def test_dashboard_does_not_apply_desktop_minimums_to_mobile_or_web():
    source = _main_source()
    assert 'platform_name not in {"android", "ios"}' in source
    assert 'not bool(getattr(page, "web", False))' in source
    assert 'except (AttributeError, RuntimeError, TypeError, ValueError):' in source
    assert 'A window hint must never block dashboard setup.' in source


def test_no_shared_admin_password_or_bootstrap_call_in_application_source():
    source = _main_source()
    auth_source = (ROOT / "chainlog" / "auth.py").read_text(encoding="utf-8")
    assert "DEFAULT_ADMIN_PASSWORD" not in source
    assert "ensure_default_admin_once" not in source
    assert "ensure_default_admin_once" not in auth_source
    assert "create_initial_admin(username_value, password_value)" in source
    assert "change_admin_credentials(" in source
    login_source = source[source.index('def show_auth'):source.index('def _build_dashboard')]
    assert 'Buat akun pribadi / ganti kredensial' not in login_source
    assert 'Perbarui kredensial' in source
    assert 'admin_current_password' in source
    assert 'admin_new_username' in source


def test_secret_storage_guidance_distinguishes_local_login_from_deployment_secrets():
    guide = (ROOT / "docs" / "SECRETS_AND_LOCAL_ACCOUNTS.md").read_text(encoding="utf-8")
    assert "environment variable" in guide.lower()
    assert "not a substitute" in guide.lower()
    assert "Secure Storage" in guide
    assert "baked-in or build-time environment variable is not a safe per-user password source" in guide


def test_dashboard_diagnostic_prioritizes_real_exception_before_random_code():
    whole = _main_source()
    # Scoped to the dashboard failure view: the data-key failure page has its own "Kode diagnosa" line earlier in the file.
    source = whole[whole.index('def _show_dashboard_failure'):whole.index('live_dashboard: dict[str, Any]')]
    stage = source.index('ft.Text(f"Tahap gagal: {stage}"')
    summary = source.index('ft.Text(f"Ringkasan: {exception_summary}"')
    diagnostic = source.index('ft.Text(f"Kode diagnosa: {diagnostic_id}"')
    assert stage < summary < diagnostic
    assert 'bgcolor=C["bg"]' in whole[whole.index('def _show_dashboard_failure'):whole.index('def show_auth')]


def test_login_viewport_is_explicitly_centered_and_hides_scrollbar_chrome():
    source = _main_source()
    assert 'alignment=ft.Alignment(0, 0)' in source
    assert 'bgcolor=C["bg"]' in source
    assert 'height=max(180, int(responsive_viewport_height() - 48))' in source
    assert 'scroll=ft.ScrollMode.HIDDEN' in source
    assert 'auth_column.width = responsive_card_width()' in source
    assert 'auth_column.height = max(180, int(responsive_viewport_height() - 48))' in source


def test_dashboard_diagnostic_and_main_content_use_hidden_scrollbars_without_disabling_scroll():
    source = _main_source()
    assert 'diagnostic_column = ft.Column(' in source
    assert 'scroll=ft.ScrollMode.HIDDEN' in source
    assert 'diagnostic_column.width = card.width' in source
    assert 'nav_column = ft.Column(controls=[], spacing=4, scroll=ft.ScrollMode.HIDDEN, expand=True)' in source
    assert 'page_body = ft.Column(' in source
    assert 'controls=list(page_controls["dashboard"]), spacing=16, expand=True, scroll=ft.ScrollMode.HIDDEN' in source
    assert 'page_body.controls = page_controls[key]' in source
    assert 'view_host' not in source and 'page_views' not in source
    assert 'ft.Column(controls=list(page_controls.values())' not in source


def test_login_header_does_not_include_large_image_placeholder_or_grey_banner():
    source = _main_source()
    auth_source = source[source.index('def show_auth'):source.index('def _build_dashboard')]
    header_start = auth_source.index('# Keep the login header text-only')
    header_end = auth_source.index('if initial_setup:', header_start)
    header = auth_source[header_start:header_end]
    assert 'ft.Image(' not in header
    assert 'KAWAL TRACE' in header
    assert 'f"v{APP_VERSION} · build {APP_BUILD}"' in header
    assert 'height=195' not in header


def test_dashboard_does_not_reference_missing_database_icon_constant():
    source = _main_source()
    assert 'ft.Icons.DATABASE' not in source
    assert 'icon=ft.Icons.TABLE_CHART, on_click=test_database_audit_connector' in source


def test_pin_login_is_only_rendered_when_device_pin_exists():
    source = _main_source()
    assert 'device_account = None if (initial_setup or credential_rotation) else registry.device_unlock_user()' in source
    assert 'if device_account and not initial_setup:' in source
    assert 'registry.set_device_pin(session["username"], pin_value)' in source


def test_database_path_is_not_exposed_in_regular_dashboard_ui():
    source = _main_source()
    assert 'PENYIMPANAN DATA' in source
    assert 'Data disimpan lokal di direktori aplikasi perangkat ini.' in source
    assert 'db_value.value = str(stats.get("db_path", store.db_path))' not in source


def test_visible_internal_build_marker_matches_native_package_build_thirteen():
    source = _main_source()
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^APP_BUILD = "13"', source, flags=re.MULTILINE)
    assert "build_number = 13" in metadata
    assert 'f"v{APP_VERSION} · build {APP_BUILD}"' in source


def test_regular_login_inputs_match_current_local_account_policy_after_migration():
    source = _main_source()
    auth_source = source[source.index('def show_auth'):source.index('def _build_dashboard')]
    assert 'label=("Username akun lama" if credential_rotation else "Buat username administrator (4–10 karakter)" if initial_setup else "Username (4–10 karakter)")' in auth_source
    assert '"max_length": 32 if credential_rotation else 10' in auth_source
    assert 'max_length=256 if credential_rotation else 128' in auth_source
    assert 'label=("Kata sandi lama" if credential_rotation else "Buat kata sandi (8–128 karakter)" if initial_setup else "Kata sandi")' in auth_source


def test_old_v1_accounts_are_migrated_before_limited_login_fields_are_shown():
    auth_source = (ROOT / "chainlog" / "auth.py").read_text(encoding="utf-8")
    assert "local_credentials_setup_v2" in auth_source
    assert "policy_marker is None" in auth_source
    assert '"local_credentials_setup_v2"' in auth_source
