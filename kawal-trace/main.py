"""Kawal Trace — local audit console for Windows and Android.

UI uses Flet; audit logic remains isolated in chainlog.core.
The SHA-256 chain is tamper-evident, not tamper-proof.
"""
from __future__ import annotations

import asyncio
import csv
import functools
import hashlib
import ipaddress
import json
import math
import os
import secrets
import shutil
import sqlite3
import ssl
import threading
import time
import tempfile
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import flet as ft
except ImportError as exc:
    raise SystemExit(
        "Flet belum terpasang. Jalankan install_windows.bat terlebih dahulu."
    ) from exc

try:
    import flet.canvas as cv
except ImportError:  # Headless contract tests use a lightweight Flet stand-in.
    cv = None

from chainlog.at_rest import AtRestError
from chainlog.core import AuditStore, ChainLogError, VerificationResult
from chainlog.auth import AuthenticationError, UserRegistry
from chainlog.device_identity import (
    clear_session_token, device_fingerprint, read_session_token, write_session_token,
)
from chainlog.website_monitor import WebsiteMonitorError, WebsiteMonitorStore, redact_website_url
from chainlog.connector_ingest import ConnectorEventIngestor
from chainlog.ssh_connector import SSHConnectorError, SSHReadOnlyConnector
from chainlog.database_audit import DatabaseAuditConfig, DatabaseAuditConnector, DatabaseAuditError
from chainlog.syslog_connector import SyslogConnectorError, SyslogTCPReceiver
from chainlog.detection import DetectionEngine, DEFAULT_AUTH_FAILURE_THRESHOLD, DEFAULT_AUTH_FAILURE_WINDOW_SECONDS
from chainlog.notification_policy import find_new_event_ids
from chainlog.server_feed import ServerFeedClient, E2EEServerFeedClient, ServerFeedError
from chainlog.live_stream import (
    DoorbellCoalescer, LiveStreamClient, LiveStreamSupervisor, poll_interval_seconds,
    status_text as live_stream_message, STATE_CONNECTING, STATE_LIVE, STATE_RETRYING,
    STATE_STOPPED, STATE_UNAUTHORIZED, STATE_UNSUPPORTED,
)
from chainlog.connectors import GenericRestFeedClient, GenericRestFeedError
from chainlog.protocol_adapters import ReadOnlyProtocolAdapter, ProtocolAdapterError, adapter_secret_fingerprint
from chainlog.api_discovery import probe_readonly_json_event_feed
from chainlog.servers import ServerRegistryError, ServerRegistryStore
from chainlog.trusted_access import (
    TrustedAccessError, TrustedAccessStore, generate_device_keypair,
)
from chainlog.server_archive import (
    ArchiveError, ServerEventArchive, ServerArchiveRemoteClient,
    export_archive_json, export_archive_csv, export_archive_pdf,
)
from chainlog.e2ee import (E2EEError, generate_keypair, public_from_private, export_private_key_backup, import_private_key_backup)
from chainlog.sync import (
    DEFAULT_EVENTS_PATH,
    DEFAULT_HEALTH_PATH,
    DEFAULT_TELEMETRY_PATH,
    DEFAULT_FEED_FIELD_MAPPING,
    DEFAULT_FEED_JSON_PATH,
    DEFAULT_CONNECTOR_TYPE,
    DEFAULT_FEED_AUTH_MODE,
    SyncClient,
    SyncConfigError,
    SyncCursorStore,
    SyncError,
    SyncSettings,
    SyncSettingsStore,
)

try:
    from flet_notifications import LocalNotifications
except ImportError:
    LocalNotifications = None

try:
    import flet_audio as fta
except ImportError:
    fta = None

try:
    import httpx
except ImportError:
    httpx = None

try:
    import flet_secure_storage as fss
except ImportError:  # Keep local auditing usable if the optional bridge is unavailable.
    fss = None

try:
    import flet_local_auth as local_auth_plugin
except ImportError:  # Password and local PIN remain available if native auth isn't built.
    local_auth_plugin = None

from chainlog.advanced_security import (
    AdvancedSecurityError, analyze_email, build_microsegmentation_plan,
    check_phishtank_url, inspect_ztna_tools, manage_ztna_tunnel, probe_private_endpoint, run_spamassassin, validate_wireguard_config,
)
from chainlog.openziti_setup import OpenZitiSetupError, download_and_launch_windows_installer

from chainlog.telemetry_selftest import run_telemetry_self_test
from chainlog.redaction import redact_secrets
from chainlog.backup import BackupError, create_backup, restore_backup, verify_backup

try:  # The scanner is a bundled package; a packaging mistake must not block login.
    from detectors import ScannerError
    from detectors.pipeline import SecurityScanner
except ImportError:  # pragma: no cover - only when the package is missing from a build
    ScannerError = Exception  # type: ignore[assignment,misc]
    SecurityScanner = None  # type: ignore[assignment,misc]

APP_VERSION = "1.0"
APP_BUILD = "14"  # Internal build marker; visible version remains 1.0. Trusted Access & Response.
STEP_UP_SECONDS = 300  # how long a password/PIN re-check stays valid for sensitive actions

# Palet gelap hijau-teal mengikuti referensi "halaman aplikasi" (bukan biru default Flet).
C = {
    "bg": "#071A18",
    "panel": "#0C2522",
    "panel_alt": "#103029",
    "panel_lift": "#173D38",
    "line": "#1F4A43",
    "text": "#EAF7F4",
    "muted": "#9DBDB6",
    "quiet": "#6A918A",
    "lime": "#2EE6C5",
    "green": "#5BE3A0",
    "amber": "#F0B86B",
    "red": "#FF7E83",
    "blue": "#7CC4E8",
    "black": "#06130F",
}

# All material icon constants referenced by this UI. Validate against the installed
# Flet runtime before building the dashboard so a mismatched package yields an
# actionable diagnostic rather than an AttributeError halfway through page setup.
REQUIRED_FLET_ICON_NAMES = (
    "ADD",
    "ADD_LINK",
    "CABLE",
    "CHECK_CIRCLE",
    "CLOUD_DONE",
    "CLOUD_QUEUE",
    "CLOUD_SYNC",
    "DATA_OBJECT",
    "DELETE",
    "DELETE_OUTLINE",
    "DOWNLOAD",
    "FACT_CHECK",
    "FINGERPRINT",
    "FOLDER_OPEN",
    "HISTORY",
    "INFO_OUTLINE",
    "KEY",
    "LAN",
    "LANGUAGE",
    "LINK",
    "LINK_OFF",
    "LOCK",
    "LOCK_OPEN",
    "LOGIN",
    "LOGOUT",
    "MANAGE_SEARCH",
    "NOTIFICATIONS",
    "PAUSE",
    "PERSON_ADD",
    "PERSON_OUTLINE",
    "PERSON_REMOVE",
    "PICTURE_AS_PDF",
    "PLAY_ARROW",
    "POLICY",
    "RADAR",
    "REFRESH",
    "RULE",
    "SAVE",
    "SEARCH",
    "SECURITY",
    "SHIELD",
    "STOP",
    "TABLE_CHART",
    "TUNE",
    "VERIFIED_USER",
    "VOLUME_UP",
    "WARNING_AMBER",
)



def _log_ui_diagnostic(data_dir: Path, stage: str, exc: BaseException) -> str:
    """Append a redacted, bounded diagnostic entry and return its id (never raises)."""
    diagnostic_id = uuid.uuid4().hex[:10].upper()
    try:
        path = Path(data_dir) / "startup-errors.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        previous = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        entry = (
            f"\n[{datetime.now(timezone.utc).isoformat()}] id={diagnostic_id} stage={redact_secrets(stage)!r} "
            f"exception={type(exc).__name__}: {redact_secrets(str(exc))[:240]}\n{redact_secrets(traceback.format_exc())}\n"
        )
        path.write_text((previous + entry)[-180_000:], encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:  # diagnostics must never become a second failure
        pass
    return diagnostic_id


def _show_data_key_failure(page: ft.Page, data_dir: Path, exc: BaseException, retry: Any) -> str:
    """Explain that the local data cannot be opened with the key on this device, and offer only safe next steps.

    Nothing here deletes, resets or re-creates anything: a new key would make every encrypted row unreadable for
    good. Returns the diagnostic id written to startup-errors.log.
    """
    diagnostic_id = _log_ui_diagnostic(data_dir, "data encryption key", exc)
    summary = redact_secrets(str(exc))[:400] or "Kunci enkripsi data tidak dapat dipakai."
    page.title = "Kawal Trace | Data terkunci"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = C["bg"]
    try:
        viewport_width = float(getattr(page, "width", None) or getattr(getattr(page, "window", None), "width", None) or 320)
    except (TypeError, ValueError):
        viewport_width = 320.0
    card_width = int(max(200, min(620, viewport_width - 32)))
    card = ft.Container(
        width=card_width,
        padding=18 if card_width < 380 else 24,
        bgcolor=C["bg"],
        border=ft.Border.all(1, C["red"]),
        border_radius=16,
        content=ft.Column(
            controls=[
                ft.Text("DATA TIDAK BISA DIBUKA", size=21 if card_width < 380 else 23, weight=ft.FontWeight.BOLD, color=C["red"]),
                ft.Text(summary, color=C["amber"], selectable=True, size=13, weight=ft.FontWeight.BOLD),
                ft.Text("Tidak ada data yang dihapus atau diubah. Aplikasi sengaja TIDAK membuat kunci baru: kunci baru membuat "
                        "data lama tidak terbaca selamanya.", color=C["text"], size=13),
                ft.Text("Cara memulihkan", color=C["text"], size=13, weight=ft.FontWeight.BOLD),
                ft.Text("1. Kembalikan berkas kunci (data-key.bin atau data-key.dpapi) ke folder data bila Anda memindahkannya.",
                        color=C["text"], size=12),
                ft.Text("2. Atau pulihkan dari berkas backup (.ktbak) milik perangkat asal lewat Perlindungan Lanjutan > Backup & Restore "
                        "pada folder data yang bersih; kunci ikut tersimpan di dalam backup terenkripsi itu.",
                        color=C["text"], size=12),
                ft.Text("3. Di Windows, kunci hanya bisa dibuka oleh akun Windows yang membuatnya; data yang disalin ke komputer "
                        "atau akun lain harus dipulihkan lewat backup.", color=C["text"], size=12),
                ft.Text(f"Aplikasi v{APP_VERSION} · build {APP_BUILD}", color=C["muted"], selectable=True, size=10),
                ft.Text(f"Kode diagnosa: {diagnostic_id}", color=C["lime"], selectable=True, size=11),
                ft.Text(f"Folder data: {data_dir}", color=C["muted"], selectable=True, size=10),
                ft.Text("Jika perlu bantuan, kirim startup-errors.log saja. Jangan kirim database, PIN, kata sandi, token, atau kunci.",
                        color=C["muted"], size=10),
                ft.FilledButton(content="Coba lagi", icon=ft.Icons.REFRESH, on_click=lambda e: retry(),
                                bgcolor=C["lime"], color=C["black"]),
            ], spacing=12,
        ),
    )
    page.controls.clear()
    page.add(ft.SafeArea(
        expand=True,
        content=ft.Container(
            expand=True, alignment=ft.Alignment(0, 0), bgcolor=C["bg"],
            padding=ft.Padding(left=12, right=12, top=12, bottom=12),
            content=ft.Column(controls=[card], width=card_width, scroll=ft.ScrollMode.AUTO,
                              horizontal_alignment=ft.CrossAxisAlignment.CENTER, alignment=ft.MainAxisAlignment.CENTER),
        ),
    ))
    page.update()
    return diagnostic_id


_SCANNER_CACHE: dict[str, Any] = {}
_SCANNER_CACHE_LOCK = threading.Lock()


def _shared_scanner(data_dir: Path) -> Any:
    """One scanner (and one isolated worker process) per data folder for the whole app run.

    Signing out and back in rebuilds the dashboard; without sharing, every rebuild would start another
    worker process and another quarantine vault object over the same files. Failures are not cached.
    """
    if SecurityScanner is None:
        raise RuntimeError("Modul pemindai tidak terpasang pada build ini.")
    key = str(Path(data_dir).resolve())
    with _SCANNER_CACHE_LOCK:
        scanner = _SCANNER_CACHE.get(key)
        if scanner is None:
            scanner = SecurityScanner(Path(data_dir) / "scanner", protected_dirs=(Path(data_dir),))
            _SCANNER_CACHE[key] = scanner
        return scanner


def _quarantine_has_active_threats(data_dir: Path) -> bool:
    """Cheap read-only peek: is there any flagged file still waiting for its 15-minute deadline?

    Lets the headless guard avoid starting the scanner (and its worker process) when there is nothing to do.
    """
    db_path = Path(data_dir) / "scanner" / "quarantine" / "quarantine.sqlite3"
    if not db_path.is_file():
        return False
    conn = None
    try:
        conn = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
        row = conn.execute(
            "SELECT 1 FROM threats WHERE deadline IS NOT NULL AND status IN ('QUARANTINED','PENDING_IN_PLACE') LIMIT 1"
        ).fetchone()
        return row is not None
    except sqlite3.Error:
        return True  # cannot tell: let the guard look properly rather than skip a deadline
    finally:
        if conn is not None:
            conn.close()


def _resume_remembered_session(registry: UserRegistry, data_dir: Path) -> tuple[dict[str, Any] | None, str]:
    """Sign in from the remembered-device token, if this device has a valid one.

    Returns (user, warning). A missing, expired, revoked or foreign token simply yields (None, "") so the
    normal login screen appears (the stale token file is removed). The token is single-use: a fresh one is
    written back. If that write fails the session still opens, the unusable token is revoked, and a warning
    says the next start will need the password.
    """
    if not registry.device_bound:
        return None, ""
    token = read_session_token(data_dir)
    if not token:
        return None, ""
    result = registry.resume_trusted_session(token)
    if result is None:
        clear_session_token(data_dir)
        return None, ""
    user, fresh = result
    try:
        write_session_token(data_dir, fresh)
    except OSError as exc:
        try:
            registry.revoke_trusted_sessions(user["username"])
        except Exception:  # best effort: the unsaved token is unknowable to anyone else anyway
            pass
        return user, (f"Token perangkat tidak dapat diperbarui ({type(exc).__name__}); "
                      "login berikutnya memerlukan kata sandi.")
    return user, ""


def _remember_device(registry: UserRegistry, data_dir: Path, username: str, remember: bool) -> str:
    """Apply the \"remember this device\" choice after a successful sign-in. Returns a warning ('' if fine).

    A device keeps at most ONE remembered session: the previous one is always revoked first, so choosing
    \"don't remember\" also forgets the device. A failure never blocks the sign-in itself but is reported.
    """
    if not registry.device_bound:
        return ("Ingat-perangkat tidak tersedia karena ID perangkat tidak dapat dibuat; "
                "kata sandi diminta setiap kali aplikasi dibuka.") if remember else ""
    try:
        registry.revoke_trusted_sessions()
        clear_session_token(data_dir)
        if remember:
            write_session_token(data_dir, registry.create_trusted_session(username))
    except Exception as exc:
        try:
            registry.revoke_trusted_sessions()
        except Exception:
            pass
        return (f"Ingat-perangkat gagal ({type(exc).__name__}); "
                "login berikutnya memerlukan kata sandi.")
    return ""


def _forget_device(registry: UserRegistry, data_dir: Path) -> None:
    """Sign-out: the remembered session of this device is revoked in the database AND removed from disk."""
    errors: list[BaseException] = []
    try:
        registry.revoke_trusted_sessions()
    except Exception as exc:
        errors.append(exc)
    try:
        clear_session_token(data_dir)
    except Exception as exc:
        errors.append(exc)
    if errors:
        raise errors[0]


def main(page: ft.Page) -> None:
    """Show first-run account setup or the local sign-in screen."""
    bootstrap_store = AuditStore()
    try:
        bootstrap_store.initialize()
    except AtRestError as exc:
        # The key does not fit the data (missing, damaged, or from another device). Never continue with a new key.
        _show_data_key_failure(page, bootstrap_store.data_dir, exc, lambda: main(page))
        return
    app_data_dir = bootstrap_store.data_dir
    device_warning = ""
    device_fp: str | None = None
    try:
        device_fp = device_fingerprint(app_data_dir)
    except Exception as exc:  # never fall back silently: the login screen states what is not available
        device_warning = (
            f"ID perangkat tidak dapat dibuat ({type(exc).__name__}; ID diagnosa "
            f"{_log_ui_diagnostic(app_data_dir, 'device fingerprint', exc)}). Akun tidak terikat ke perangkat "
            "ini dan fitur ingat-perangkat dimatikan sampai masalah ini diperbaiki."
        )
    registry = UserRegistry(app_data_dir / "identity.sqlite3", device_fp)
    platform_value = getattr(getattr(page, "platform", None), "value", getattr(page, "platform", None))
    platform_name = str(platform_value).split(".")[-1].lower()
    if platform_name in {"none", "", "unknown"}:
        platform_name = sys.platform.lower()
    device_audit_context = {
        "device_id": device_fp or "unavailable",
        "platform": platform_name,
    }
    # Do not create an account before the setup screen is rendered. A clean install
    # must require an explicit click on "Buat administrator". Existing local accounts
    # are preserved and are never reset during startup.

    page.title = "Kawal Trace | Security Console"
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = ft.Theme(color_scheme_seed=C["lime"], use_material3=True, font_family="Segoe UI")
    page.bgcolor = C["bg"]
    page.padding = 0
    # The login form owns its scroll viewport. Avoid a second, competing page scroll.
    page.scroll = None
    try:
        platform_value = getattr(getattr(page, "platform", None), "value", getattr(page, "platform", None))
        platform_name = str(platform_value).split(".")[-1].lower()
        is_mobile_client = platform_name in {"android", "ios"}
        if not is_mobile_client:
            page.window.min_width = 360
            page.window.min_height = 560
    except (AttributeError, RuntimeError, TypeError):
        pass

    def input_style() -> dict[str, Any]:
        return {
            "filled": True, "bgcolor": C["bg"], "color": C["text"],
            "cursor_color": C["lime"], "text_size": 13,
            "border": {
                ft.ControlState.DEFAULT: ft.OutlineInputBorder(
                    border_radius=8, side=ft.BorderSide(width=1, color=C["line"]),
                ),
                ft.ControlState.FOCUSED: ft.OutlineInputBorder(
                    border_radius=8, side=ft.BorderSide(width=1.5, color=C["lime"]),
                ),
            },
        }

    def _redact_diagnostic_text(value: str) -> str:
        """Reduce risk of writing credentials that appear in exception text/URLs."""
        return redact_secrets(value)

    def _show_dashboard_failure(
        user: dict[str, str], action: str, exc: BaseException, trace: str,
        stage: str = "dashboard initialization",
    ) -> None:
        """Show a responsive, scrollable error view and keep a sanitized traceback."""
        error_path = bootstrap_store.data_dir / "startup-errors.log"
        diagnostic_id = uuid.uuid4().hex[:10].upper()
        exception_summary = _redact_diagnostic_text(str(exc))[:240] or "Tidak ada pesan error tambahan."
        safe_trace = _redact_diagnostic_text(trace)
        # Keep the diagnostic file bounded and private where the OS supports it.
        try:
            error_path.parent.mkdir(parents=True, exist_ok=True)
            previous = error_path.read_text(encoding="utf-8", errors="replace") if error_path.exists() else ""
            entry = (
                f"\n[{datetime.now(timezone.utc).isoformat()}] id={diagnostic_id} "
                f"stage={_redact_diagnostic_text(stage)!r} user={user.get('username', '<unknown>')!r} "
                f"action={_redact_diagnostic_text(action)!r} exception={type(exc).__name__}: {exception_summary}\n{safe_trace}\n"
            )
            error_path.write_text((previous + entry)[-180_000:], encoding="utf-8")
            try:
                os.chmod(error_path, 0o600)
            except OSError:
                pass
        except Exception:
            # The visible failure view is still preferable if disk diagnostics fail.
            pass

        try:
            try:
                viewport_width = float(getattr(page, "width", None) or getattr(getattr(page, "window", None), "width", None) or 320)
            except (TypeError, ValueError):
                viewport_width = 320.0
            card_width = int(max(200, min(620, viewport_width - 32)))
            card = ft.Container(
                width=card_width,
                padding=18 if card_width < 380 else 24,
                bgcolor=C["bg"],
                border=ft.Border.all(1, C["red"]),
                border_radius=16,
                content=ft.Column(
                    controls=[
                        ft.Text("GAGAL MEMBUKA DASHBOARD", size=21 if card_width < 380 else 23, weight=ft.FontWeight.BOLD, color=C["red"]),
                        ft.Text("Login berhasil, tetapi aplikasi mengalami error saat memuat dashboard. Ini bukan proses yang sedang menunggu. Periksa tahap dan ringkasan error di bawah.", color=C["text"], size=13),
                        ft.Text(f"Tahap gagal: {stage}", color=C["amber"], selectable=True, size=12),
                        ft.Text(f"Jenis kesalahan: {type(exc).__name__}", color=C["text"], selectable=True, size=12),
                        ft.Text(f"Ringkasan: {exception_summary}", color=C["amber"], selectable=True, size=12, weight=ft.FontWeight.BOLD),
                        ft.Text(f"Aplikasi v{APP_VERSION} · build {APP_BUILD}", color=C["muted"], selectable=True, size=10),
                        ft.Text(f"Kode diagnosa: {diagnostic_id}", color=C["lime"], selectable=True, size=11),
                        ft.Text(f"File log: {error_path}", color=C["muted"], selectable=True, size=10),
                        ft.Text("Jika perlu bantuan, kirim startup-errors.log saja. Jangan kirim database, PIN, kata sandi, token, atau kunci privat.", color=C["muted"], size=10),
                        ft.Row(
                            controls=[
                                ft.FilledButton(content="Coba buka lagi", icon=ft.Icons.REFRESH,
                                                on_click=lambda e: show_dashboard(user, action), bgcolor=C["lime"], color=C["black"]),
                                ft.OutlinedButton(content="Kembali ke login", icon=ft.Icons.LOGOUT,
                                                  on_click=lambda e: show_auth()),
                            ], wrap=True, spacing=10,
                        ),
                    ], spacing=12,
                ),
            )
            page.controls.clear()
            try:
                live_height = float(getattr(page, "height", None) or getattr(getattr(page, "window", None), "height", None) or 700)
            except (TypeError, ValueError):
                live_height = 700.0
            diagnostic_column = ft.Column(
                controls=[card],
                width=card_width,
                height=max(180, int(live_height - 48)),
                scroll=ft.ScrollMode.HIDDEN,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                alignment=ft.MainAxisAlignment.CENTER,
            )
            page.add(ft.SafeArea(
                expand=True,
                content=ft.Container(
                    expand=True,
                    alignment=ft.Alignment(0, 0),
                    bgcolor=C["bg"],
                    padding=ft.Padding(left=12, right=12, top=12, bottom=12),
                    content=diagnostic_column,
                ),
            ))

            def on_diagnostic_resize(_: Any = None) -> None:
                try:
                    live_width = float(getattr(page, "width", None) or getattr(getattr(page, "window", None), "width", None) or 320)
                    live_height = float(getattr(page, "height", None) or getattr(getattr(page, "window", None), "height", None) or 520)
                    card.width = int(max(200, min(620, live_width - 32)))
                    card.padding = 18 if card.width < 380 else 24
                    diagnostic_column.width = card.width
                    diagnostic_column.height = max(180, int(live_height - 48))
                    page.update()
                except Exception:
                    pass

            try:
                page.on_resize = on_diagnostic_resize
            except Exception:
                pass
            page.update()
        except Exception:
            # Last-resort console trace for developer-run builds. There is no claim
            # that this fallback can draw if the Flet client itself is broken.
            print(f"Kawal Trace dashboard error [{diagnostic_id}]: {type(exc).__name__}: {exception_summary}")

    live_dashboard: dict[str, Any] = {"lifecycle": None}

    def stop_live_dashboard() -> None:
        """Stop everything the previous dashboard started (loops, monitors, listeners) before another is built."""
        lifecycle, live_dashboard["lifecycle"] = live_dashboard["lifecycle"], None
        shutdown = (lifecycle or {}).get("shutdown")
        if shutdown is not None:
            try:
                shutdown()
            except Exception as exc:
                _log_ui_diagnostic(app_data_dir, "dashboard shutdown", exc)

    def logout() -> None:
        """Sign out: forget this device's remembered session, stop the dashboard and return to the login screen."""
        notice = "Anda sudah keluar. Perangkat ini tidak lagi diingat; masuk dengan kata sandi atau PIN."
        try:
            _forget_device(registry, app_data_dir)
        except Exception as exc:
            notice = (f"Anda keluar, tetapi sesi perangkat belum dapat dicabut sepenuhnya ({type(exc).__name__}; "
                      f"ID diagnosa {_log_ui_diagnostic(app_data_dir, 'logout revoke', exc)}).")
        try:
            bootstrap_store.add_event("AUTH", str(live_dashboard.get("username") or "unknown"), "local-auth",
                                      {"action": "logout", "result": "success", **device_audit_context})
        except Exception:
            pass
        stop_live_dashboard()
        live_dashboard["username"] = None
        show_auth(notice)

    def show_dashboard(user: dict[str, str], action: str, auth_via: str | None = None, notice: str = "") -> None:
        session = dict(user)
        session["auth_via"] = auth_via or str(user.get("auth_via") or "password")
        session.update(device_audit_context)
        try:
            bootstrap_store.add_event(
                "AUTH", session["username"], "local-auth",
                {"action": action, "result": "success", "role": session["role"], "via": session["auth_via"],
                 **device_audit_context},
            )
        except Exception:
            # A failed audit append must not cause a silent blank screen before the
            # dashboard error handler. The integrity panel reports a broken chain.
            pass
        stop_live_dashboard()
        startup_stage = {"name": "dashboard preflight"}
        lifecycle: dict[str, Any] = {}
        try:
            _build_dashboard(page, session, registry, startup_stage=startup_stage,
                             on_logout=logout, lifecycle=lifecycle, notice=notice)
            live_dashboard["lifecycle"] = lifecycle
            live_dashboard["username"] = session["username"]
        except Exception as exc:
            try:
                if lifecycle.get("shutdown") is not None:
                    lifecycle["shutdown"]()
            except Exception as stop_exc:
                _log_ui_diagnostic(app_data_dir, "dashboard shutdown after failed build", stop_exc)
            _show_dashboard_failure(
                session, action, exc, traceback.format_exc(), stage=startup_stage["name"]
            )

    def finish_login(user: dict[str, Any], action: str, remember: bool, via: str) -> None:
        """Common tail of every successful sign-in (password, PIN, biometric, first administrator).

        `via` is "password", "pin" or "biometric". Only a password or PIN typed in the app counts as a
        fresh verification for sensitive actions (see the step-up panel in the dashboard).
        """
        warning = _remember_device(registry, app_data_dir, user["username"], remember)
        show_dashboard(user, action, auth_via=via, notice=warning)

    def try_resume_session() -> bool:
        """Open the dashboard straight away when this device holds a valid remembered session."""
        try:
            user, warning = _resume_remembered_session(registry, app_data_dir)
        except Exception as exc:
            _log_ui_diagnostic(app_data_dir, "resume remembered session", exc)
            return False
        if user is None:
            return False
        show_dashboard(user, "remembered_device", auth_via="remembered", notice=warning)
        return True

    def show_auth(notice: str | None = None) -> None:
        page.controls.clear()
        initial_setup = registry.needs_setup()
        legacy_migration = registry.needs_legacy_credential_rotation()
        credential_rotation = legacy_migration

        def responsive_viewport_width() -> float:
            try:
                live_width = float(getattr(page, "width", None) or 0)
                if live_width <= 0:
                    live_width = float(getattr(getattr(page, "window", None), "width", None) or 320)
                return max(200.0, live_width)
            except (TypeError, ValueError):
                # A narrow first-frame fallback prevents horizontal overflow before on_resize.
                return 320.0

        def responsive_viewport_height() -> float:
            try:
                live_height = float(getattr(page, "height", None) or 0)
                if live_height <= 0:
                    live_height = float(getattr(getattr(page, "window", None), "height", None) or 520)
                return max(240.0, live_height)
            except (TypeError, ValueError):
                # Keep first frame usable on short phone screens until actual dimensions arrive.
                return 520.0

        def responsive_card_width() -> int:
            # Leave visible margins even on narrow phones; cap the form on laptops.
            return int(max(180, min(520, responsive_viewport_width() - 32)))

        def responsive_auth_button_width() -> int:
            width = responsive_card_width()
            horizontal_padding = 20 if width < 380 else 30
            return int(max(160, min(280, width - (2 * horizontal_padding) - 8)))

        user_name = ft.TextField(
            label=("Username akun lama" if credential_rotation else "Buat username administrator (4–10 karakter)" if initial_setup else "Username (4–10 karakter)"),
            value="",
            hint_text=("Pilih 4–10 karakter: huruf, angka, titik, _ atau -" if initial_setup else None if credential_rotation else "4–10 karakter"),
            autofocus=True, scroll_padding=24,
            **({"max_length": 32 if credential_rotation else 10}), **input_style(),
        )
        password = ft.TextField(
            label=("Kata sandi lama" if credential_rotation else "Buat kata sandi (8–128 karakter)" if initial_setup else "Kata sandi"),
            value="", password=True, can_reveal_password=True,
            hint_text=("Masukkan kata sandi lama" if credential_rotation else "Boleh berupa kalimat panjang" if initial_setup else None),
            max_length=256 if credential_rotation else 128,
            scroll_padding=24, **input_style(),
        )
        confirm = ft.TextField(
            label="Ulangi kata sandi (8–128 karakter)", value="",
            password=True, can_reveal_password=True, max_length=128,
            scroll_padding=24, **input_style(),
        )
        legacy_new_username = ft.TextField(
            label="Username baru (4–10 karakter)", value="",
            hint_text="Pilih username 4–10 karakter", max_length=10,
            scroll_padding=24, **input_style(),
        )
        legacy_new_password = ft.TextField(
            label="Kata sandi baru (8–128 karakter)", value="", password=True,
            can_reveal_password=True, max_length=128, scroll_padding=24, **input_style(),
        )
        legacy_confirm_password = ft.TextField(
            label="Ulangi kata sandi baru", value="", password=True,
            can_reveal_password=True, max_length=128, scroll_padding=24, **input_style(),
        )
        feedback = ft.Text(notice or "", size=11, color=C["amber"], selectable=True)
        foreign_accounts = bool(initial_setup and registry.has_foreign_accounts())
        can_remember = bool(registry.device_bound and not credential_rotation)
        remember_device = ft.Checkbox(
            label="Ingat perangkat ini (tanpa login ulang sampai 30 hari)", value=True,
            visible=can_remember,
        )
        remember_note = ft.Text(
            "Saat aktif, siapa pun yang membuka aplikasi ini di perangkat Anda yang tidak terkunci bisa masuk tanpa "
            "kata sandi. Aksi sensitif (akun, PIN, cadangan, kunci) tetap meminta kata sandi/PIN. "
            "Matikan di perangkat bersama; tombol Keluar mencabut ingatan ini.",
            size=10, color=C["muted"], visible=can_remember,
        )
        device_account = None if (initial_setup or credential_rotation) else registry.device_unlock_user()
        pin_user_field = ft.TextField(
            label="Akun perangkat", value=(device_account or {}).get("username", ""),
            max_length=32, scroll_padding=24, **input_style(),
        )
        device_pin_field = ft.TextField(
            label="PIN aplikasi (8–12 angka)", password=True, can_reveal_password=False,
            max_length=12, keyboard_type=ft.KeyboardType.NUMBER,
            scroll_padding=24, **input_style(),
        )
        pin_feedback = ft.Text("PIN hanya disimpan sebagai hash di perangkat ini.", size=10, color=C["muted"], selectable=True)

        def submit_pin(_: ft.ControlEvent | None = None) -> None:
            try:
                user = registry.authenticate_device_pin(pin_user_field.value or "", device_pin_field.value or "")
                if not user:
                    try:
                        bootstrap_store.add_event(
                            "AUTH", (pin_user_field.value or "unknown")[:80], "local-auth",
                            {"action": "login", "result": "failed", "via": "pin",
                             "reason": "invalid_pin", **device_audit_context},
                        )
                    except ChainLogError:
                        pass
                    pin_feedback.value = "PIN salah, akun tidak aktif, atau percobaan sementara dibatasi."
                    pin_feedback.color = C["red"]
                    device_pin_field.value = ""
                    page.update()
                    return
                finish_login(user, "device_pin_unlock", bool(remember_device.value), "pin")
            except Exception as exc:
                pin_feedback.value = f"PIN perangkat gagal: {exc}"
                pin_feedback.color = C["red"]
                page.update()

        local_auth_service: Any | None = None
        biometric_button: Any | None = None

        async def detect_biometric_support() -> None:
            """Show biometrics only when the platform supports them and a method is enrolled."""
            nonlocal local_auth_service
            if local_auth_plugin is None or not device_account or initial_setup or credential_rotation:
                return
            try:
                platform = getattr(page, "platform", None)
                platform_value = getattr(platform, "value", platform)
                platform_name = str(platform_value).split(".")[-1].lower()
                if bool(getattr(page, "web", False)) or platform_name not in {"android", "ios", "windows", "macos"}:
                    return
                if not registry.has_device_pin(device_account["username"]):
                    return
                local_auth_service = local_auth_plugin.LocalAuthentication()
                if local_auth_service not in page.services:
                    page.services.append(local_auth_service)
                supported = await local_auth_service.is_device_supported()
                can_check = await local_auth_service.can_check_biometrics()
                available = await local_auth_service.get_available_biometrics()
                if supported and can_check and available and biometric_button is not None:
                    biometric_button.visible = True
                    page.update()
            except Exception:
                # Unsupported builds stay on the password/PIN path without a dead button.
                if biometric_button is not None:
                    biometric_button.visible = False
                try:
                    page.update()
                except Exception:
                    pass

        async def submit_biometric(_: ft.ControlEvent | None = None) -> None:
            if local_auth_service is None or biometric_button is None or not biometric_button.visible:
                pin_feedback.value = "Biometrik tidak tersedia atau belum disiapkan pada perangkat ini. Gunakan PIN atau kata sandi."
                pin_feedback.color = C["amber"]
                page.update()
                return
            try:
                ok = await local_auth_service.authenticate(
                    "Buka Kawal Trace dengan biometrik perangkat",
                    biometric_only=True,
                    sensitive_transaction=True,
                )
                if not ok:
                    pin_feedback.value = "Verifikasi biometrik tidak berhasil. Gunakan PIN perangkat."
                    pin_feedback.color = C["red"]
                    page.update()
                    return
                user = registry.device_unlock_user()
                if user:
                    finish_login(user, "device_biometric_unlock", bool(remember_device.value), "biometric")
                else:
                    pin_feedback.value = "PIN perangkat sudah tidak aktif. Masuk dengan kata sandi akun lokal."
                    pin_feedback.color = C["red"]
                    page.update()
            except Exception as exc:
                # Do not expose platform details or secrets in the UI.
                pin_feedback.value = f"Biometrik gagal ({type(exc).__name__}). Gunakan PIN perangkat."
                pin_feedback.color = C["amber"]
                page.update()

        def submit(_: ft.ControlEvent | None = None) -> None:
            username_value = user_name.value or ""
            password_value = password.value or ""
            try:
                if initial_setup:
                    if password_value != (confirm.value or ""):
                        raise AuthenticationError("Kata sandi dan konfirmasi belum cocok.")
                    user = registry.create_initial_admin(username_value, password_value)
                    finish_login(user, "first_admin_created", bool(remember_device.value), "password")
                    return

                if credential_rotation:
                    new_password_value = legacy_new_password.value or ""
                    if new_password_value != (legacy_confirm_password.value or ""):
                        raise AuthenticationError("Kata sandi baru dan konfirmasi belum cocok.")
                    registry.change_admin_credentials(
                        username_value,
                        password_value,
                        legacy_new_username.value or "",
                        new_password_value,
                    )
                    show_auth("Kredensial lokal berhasil diperbarui. Masuk kembali dengan username dan kata sandi baru.")
                    return

                user = registry.authenticate(username_value, password_value)
                if not user:
                    try:
                        bootstrap_store.add_event(
                            "AUTH", username_value.strip()[:80] or "unknown", "local-auth",
                            {"action": "login", "result": "failed", "reason": "invalid_credentials",
                             **device_audit_context},
                        )
                    except ChainLogError:
                        pass
                    feedback.value = "Kredensial tidak valid, akun dinonaktifkan, atau login sementara dibatasi setelah percobaan berulang."
                    feedback.color = C["red"]
                    password.value = ""
                    page.update()
                    return
                finish_login(user, "login", bool(remember_device.value), "password")
            except AuthenticationError as exc:
                feedback.value = str(exc)
                feedback.color = C["amber"]
                page.update()
            except Exception as exc:
                feedback.value = f"Autentikasi gagal: {exc}"
                feedback.color = C["red"]
                page.update()

        title = (
            "Buat akun administrator" if initial_setup else
            ("Amankan akun lokal lama" if legacy_migration else "Perbarui kredensial lokal") if credential_rotation else
            "Selamat datang kembali"
        )
        subtitle = (
            "Buat username dan kata sandi pribadi untuk perangkat ini. Tidak ada akun bersama atau kata sandi bawaan."
            if initial_setup else
            ("Instalasi ini berasal dari versi lama yang menggunakan kredensial bootstrap. Verifikasi akun lama lalu ganti dengan kredensial pribadi; data audit tidak dihapus."
             if legacy_migration else
             "Masukkan kredensial saat ini lalu pilih username/kata sandi baru. Data audit tidak dihapus.")
            if credential_rotation else
            "Masuk untuk membuka ruang pemantauan, catatan audit, dan koneksi server yang sudah dikonfigurasi."
        )
        # Keep the login header text-only. The old image-bearing row rendered as a
        # large blank grey block in packaged Windows builds, wasting the first screen.
        controls: list[ft.Control] = [
            ft.Row(
                controls=[
                    ft.Column(
                        controls=[
                            ft.Text("KAWAL TRACE", size=20, weight=ft.FontWeight.BOLD, color=C["text"], font_family="Segoe UI"),
                            ft.Text("SECURITY MONITORING  /  AUDIT TRAIL", size=9, color=C["lime"], font_family="Segoe UI"),
                        ], spacing=4, expand=True,
                    ),
                    ft.Text(f"v{APP_VERSION} · build {APP_BUILD}", size=10, color=C["muted"]),
                ], spacing=12, alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            ft.Divider(color=C["line"]),
            ft.Text(title, size=27, weight=ft.FontWeight.BOLD, color=C["text"], font_family="Segoe UI"),
            ft.Text(subtitle, size=12, color=C["muted"]),
        ]
        if device_warning:
            controls.append(ft.Text(device_warning, size=11, color=C["red"], selectable=True))
        if initial_setup:
            controls.append(ft.Text(
                "PENYIAPAN PERANGKAT BARU · Kata sandi wajib kamu buat sendiri dan tidak dikirim ke layanan online.",
                size=11, color=C["lime"], selectable=True,
            ))
            if foreign_accounts:
                controls.append(ft.Text(
                    "ID perangkat ini berbeda dari perangkat tempat akun lama dibuat. Akun perangkat lain tidak berlaku di "
                    "sini: buat username dan kata sandi baru khusus untuk perangkat ini. Akun lama tidak dihapus.",
                    size=11, color=C["amber"], selectable=True,
                ))
        elif credential_rotation:
            controls.append(ft.Text(
                "Pembaruan ini tidak menghapus log, target, atau konfigurasi. Kata sandi lama hanya dipakai untuk membuktikan kepemilikan akun.",
                size=11, color=C["amber"], selectable=True,
            ))
        pin_unlock_panel: Any | None = None
        pin_toggle_button: Any | None = None
        if device_account and not initial_setup:
            biometric_button = ft.OutlinedButton(
                content="Sidik jari / wajah", icon=ft.Icons.FINGERPRINT,
                on_click=submit_biometric, visible=False,
            )
            pin_unlock_panel = ft.Container(
                visible=False,
                content=ft.Column(controls=[
                    ft.Text("BUKA KUNCI PERANGKAT", size=10, color=C["lime"], weight=ft.FontWeight.BOLD),
                    ft.Text("PIN hanya tersimpan sebagai hash lokal. Biometrik menggunakan autentikasi sistem, bila didukung dan sudah diaktifkan di perangkat.", size=10, color=C["muted"]),
                    device_pin_field,
                    ft.Row(controls=[
                        ft.FilledButton(content="Buka dengan PIN", icon=ft.Icons.LOCK_OPEN,
                                        on_click=submit_pin, bgcolor=C["panel_lift"], color=C["text"]),
                        biometric_button,
                    ], wrap=True, spacing=8),
                    pin_feedback,
                ], spacing=9),
                padding=13, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=10,
            )

            def toggle_device_pin_panel(_: ft.ControlEvent | None = None) -> None:
                if pin_unlock_panel is None:
                    return
                pin_unlock_panel.visible = not bool(pin_unlock_panel.visible)
                if pin_toggle_button is not None:
                    pin_toggle_button.content = (
                        "Sembunyikan PIN perangkat" if pin_unlock_panel.visible
                        else "Masuk dengan PIN perangkat"
                    )
                page.update()

            pin_toggle_button = ft.OutlinedButton(
                content="Masuk dengan PIN perangkat", icon=ft.Icons.LOCK_OPEN,
                on_click=toggle_device_pin_panel, width=responsive_auth_button_width(),
            )
            controls.extend([pin_toggle_button, pin_unlock_panel])
        if credential_rotation:
            user_name.label = "Username akun lama"
            password.label = "Kata sandi lama"
            controls.extend([user_name, password, legacy_new_username, legacy_new_password, legacy_confirm_password])
        else:
            controls.extend([user_name, password])
            if initial_setup:
                controls.append(confirm)
            controls.extend([remember_device, remember_note])
        submit_button = ft.FilledButton(
            content=("Buat akun administrator" if initial_setup else "Perbarui akun lokal" if credential_rotation else "Masuk dengan akun lokal"),
            icon=(ft.Icons.PERSON_ADD if (initial_setup or credential_rotation) else ft.Icons.LOGIN),
            on_click=submit, bgcolor=C["lime"], color=C["black"],
            width=responsive_auth_button_width(),
        )
        controls.extend([
            submit_button,
            feedback,
            ft.Divider(color=C["line"]),
            ft.Row(
                controls=[ft.Icon(ft.Icons.INFO_OUTLINE, size=15, color=C["amber"]),
                          ft.Text("Ini autentikasi aplikasi lokal, bukan autentikasi Windows/domain atau server terpusat.",
                                  size=10, color=C["quiet"], expand=True)],
                spacing=8, vertical_alignment=ft.CrossAxisAlignment.START,
            ),
        ])
        card = ft.Container(
            content=ft.Column(controls=controls, spacing=13),
            padding=20 if responsive_card_width() < 380 else 30,
            bgcolor=C["panel"], border=ft.Border.all(1, C["line"]), border_radius=22,
            width=responsive_card_width(),
        )
        auth_footer = ft.Text(
            "KAWAL TRACE  ·  PRIVATE BY DESIGN  ·  LOCAL-FIRST",
            size=9, color=C["quiet"], font_family="Consolas", text_align=ft.TextAlign.CENTER,
        )
        # A scrollable Column does not reliably center itself when it is a child
        # of Container without explicit constraints. Give it a viewport width/height,
        # then center that viewport in the full-screen SafeArea. HIDDEN only hides the
        # scrollbar chrome; finger/wheel scrolling remains enabled on small screens.
        auth_column = ft.Column(
            controls=[card, auth_footer],
            width=responsive_card_width(),
            height=max(180, int(responsive_viewport_height() - 48)),
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=15,
            scroll=ft.ScrollMode.HIDDEN,
        )
        auth_root = ft.Container(
            expand=True,
            alignment=ft.Alignment(0, 0),
            bgcolor=C["bg"],
            padding=ft.Padding(left=12, right=12, top=12, bottom=12),
            content=auth_column,
        )
        page.add(ft.SafeArea(expand=True, content=auth_root))

        def on_auth_resize(_: Any = None) -> None:
            card.width = responsive_card_width()
            card.padding = 20 if card.width < 380 else 30
            auth_column.width = responsive_card_width()
            auth_column.height = max(180, int(responsive_viewport_height() - 48))
            responsive_width = responsive_auth_button_width()
            submit_button.width = responsive_width
            if pin_toggle_button is not None:
                pin_toggle_button.width = responsive_width
            try:
                page.update()
            except Exception:
                pass

        try:
            page.on_resize = on_auth_resize
        except Exception:
            pass
        page.update()
        if device_account and not initial_setup and not credential_rotation:
            page.run_task(detect_biometric_support)

    async def quarantine_guard() -> None:
        """Honour the 15-minute deadline even while nobody is signed in (login screen).

        While a dashboard is open its own loop does this work; the guard only acts when none is. Silent by
        design, exactly like the dashboard loop: the outcome goes to the tamper-evident audit chain only.
        """
        reported = False
        while True:
            await asyncio.sleep(15)
            if live_dashboard["lifecycle"] is not None:
                continue
            try:
                if not await asyncio.to_thread(_quarantine_has_active_threats, app_data_dir):
                    continue
                scanner = await asyncio.to_thread(_shared_scanner, app_data_dir)
                done = await asyncio.to_thread(scanner.vault.process_due)
                for item in done:
                    try:
                        bootstrap_store.add_event(
                            "ALERT", "sistem", "pemindai-keamanan",
                            {"message": "Ancaman " + ("dihapus otomatis" if item["status"] == "AUTO_DELETED"
                                                      else "penghapusan otomatis gagal"),
                             "name": str(item.get("malware_name", ""))[:120],
                             "sha256": str(item.get("sha256", "")), "status": str(item.get("status", ""))})
                    except ChainLogError:
                        pass
            except Exception as exc:
                if not reported:  # one trace per run; the next attempt happens in 15 seconds
                    reported = True
                    _log_ui_diagnostic(app_data_dir, "headless quarantine guard", exc)

    if SecurityScanner is not None:
        page.run_task(quarantine_guard)
    # Startup langsung menuju sesi tersimpan atau layar login; tidak ada intro/video.
    if not try_resume_session():
        show_auth()


def _build_dashboard(
    page: ft.Page, session: dict[str, str], registry: UserRegistry,
    startup_stage: dict[str, str] | None = None,
    on_logout: Any = None, lifecycle: dict[str, Any] | None = None, notice: str = "",
) -> None:
    # `alive` lets every loop this dashboard starts end when the user signs out; `lifecycle["shutdown"]`
    # (set just before the loops start) stops monitors and listeners as well.
    alive = {"on": True}
    # Step-up verification (re-entering password/PIN before a sensitive action) is valid for 5 minutes.
    # A password or PIN typed to sign in counts as a fresh verification; a remembered device or biometric does not.
    step_up_state: dict[str, Any] = {
        "valid_until": time.monotonic() + STEP_UP_SECONDS if session.get("auth_via") in {"password", "pin"} else 0.0,
        "pending": None,
    }

    # Keep a precise stage in diagnostics so a UI startup failure is actionable.
    def mark_stage(name: str) -> None:
        if startup_stage is not None:
            startup_stage["name"] = name

    responsive_width_bindings: list[tuple[Any, float, float]] = []

    def responsive_dashboard_width(maximum: float, reserve: float = 64.0) -> float:
        try:
            viewport = float(getattr(page, "width", None) or getattr(getattr(page, "window", None), "width", None) or 390)
        except (TypeError, ValueError):
            viewport = 390.0
        return max(180.0, min(float(maximum), viewport - reserve))

    def responsive_width(control: Any, maximum: float, reserve: float = 64.0) -> Any:
        control.width = responsive_dashboard_width(maximum, reserve)
        responsive_width_bindings.append((control, maximum, reserve))
        return control

    mark_stage("validate Flet icon contract")
    missing_icons = [name for name in REQUIRED_FLET_ICON_NAMES if not hasattr(ft.Icons, name)]
    if missing_icons:
        raise RuntimeError(
            "Flet runtime tidak menyediakan ikon yang digunakan dashboard: "
            + ", ".join(missing_icons)
            + ". Bangun ulang aplikasi memakai versi dependency di requirements.txt."
        )

    mark_stage("initialize local audit database")
    page.controls.clear()
    store = AuditStore()
    store.initialize()
    server_event_archive = ServerEventArchive(store.data_dir / "server-event-archive.sqlite3")
    # Website availability records use an authenticated encrypted database image.
    # The database key is created/read only through the OS-backed Secure Storage.
    website_monitor_store: WebsiteMonitorStore | None = None
    website_monitor_state: dict[str, bool] = {"active": False}
    connector_ingestor = ConnectorEventIngestor(store)
    syslog_receiver: SyslogTCPReceiver | None = None
    connector_runtime_state: dict[str, Any] = {
        "syslog_active": False, "syslog_received": 0, "syslog_rejected": 0,
        "syslog_error": "", "syslog_label": "", "syslog_status": "idle",
        "ssh_status": "idle", "ssh_label": "",
        "database_status": "idle", "database_label": "",
        "folder_status": "idle", "server_status": "idle",
        "folder_headline": "MENUNGGU KONEKSI SERVER",
        "folder_path": "Belum ada laporan dari Linux Server Agent",
        "folder_detail": "Pemantauan berjalan di server melalui auditd setelah agen server terpasang dan terhubung.",
        "linux_agent_status": "idle", "windows_agent_status": "idle",
    }
    connector_ingest_lock = threading.RLock()
    folder_picker = ft.FilePicker()
    page.services.append(folder_picker)

    # Offline malware/phishing scanner (bundled detectors/ package, no network, no cloud).
    scanner: Any = None
    scanner_unavailable_reason = "Modul pemindai tidak terpasang pada build ini."
    if SecurityScanner is not None:
        try:
            scanner = _shared_scanner(store.data_dir)
            scanner_unavailable_reason = ""
        except Exception as exc:  # the dashboard must still open; the page explains what failed
            scanner = None
            scanner_unavailable_reason = (
                f"Pemindai gagal dimulai ({type(exc).__name__}). "
                f"ID diagnosa {_log_ui_diagnostic(store.data_dir, 'scanner init', exc)} di startup-errors.log."
            )

    def safe_icon(name: str, fallback: Any) -> Any:
        """New icons resolve defensively so an unknown name can never abort the dashboard."""
        return getattr(ft.Icons, name, fallback)

    sync_settings_store = SyncSettingsStore(store.data_dir / "sync-settings.json")
    server_registry_store = ServerRegistryStore(store.data_dir / "server-registry.json")
    trusted_access_store = TrustedAccessStore(store.data_dir / "trusted-access.sqlite3")
    archive_preferences_path = store.data_dir / "server-archive-preferences.json"
    try:
        raw_archive_preferences = json.loads(archive_preferences_path.read_text(encoding="utf-8"))
        archive_preferences = raw_archive_preferences if isinstance(raw_archive_preferences, dict) else {}
    except (OSError, ValueError):
        archive_preferences = {}
    archive_preferences.setdefault("version", 1)
    # Remote archive storage was removed: every database stays on this device. If an older preferences file
    # chose a server mode, keep the old destination ONLY so its history can be pulled home once (read-only).
    legacy_remote_archive = archive_preferences.get("mode") in {"server", "server_and_device"}
    archive_preferences["mode"] = "device"
    if not legacy_remote_archive:
        archive_preferences["destination_profile_id"] = ""
    archive_preferences.setdefault("destination_profile_id", "")
    archive_preferences.setdefault("export_dir", str(store.data_dir / "reports" / "server-logs"))
    # Migrate the former single-server configuration once without moving tokens
    # into JSON. The legacy token keys remain read-only fallback for this profile.
    if not server_registry_store.list() and sync_settings_store.settings.base_url.strip():
        server_registry_store.upsert(
            "Server utama (migrasi)", sync_settings_store.settings,
            profile_id="legacy-default", select=True,
        )
    active_server_id: str | None = server_registry_store.selected_id
    # Canonical install identity follows the selected existing profile during migration.
    # That preserves the Device ID already enrolled on the central server while ensuring
    # a newly created server profile doesn't mint a fresh ID on every click/restart.
    selected_identity_profile = server_registry_store.get(active_server_id)
    if selected_identity_profile and sync_settings_store.settings.device_id != selected_identity_profile.settings.device_id:
        old_global = sync_settings_store.settings
        sync_settings_store.save(SyncSettings(
            base_url=old_global.base_url,
            device_id=selected_identity_profile.settings.device_id,
            events_path=old_global.events_path,
            health_path=old_global.health_path,
            telemetry_path=old_global.telemetry_path,
            ca_bundle=old_global.ca_bundle,
            connector_type=old_global.connector_type,
            feed_auth_mode=old_global.feed_auth_mode,
            feed_json_path=old_global.feed_json_path,
            feed_field_mapping=old_global.feed_field_mapping,
            feed_auth_header_name=getattr(old_global, "feed_auth_header_name", "X-API-Key"),
            adapter_protocol=getattr(old_global, "adapter_protocol", "rest"),
            adapter_options_json=getattr(old_global, "adapter_options_json", "{}"),
        ))
    connected_server_id: str | None = None  # runtime state only; never persisted
    enrollment_poll_task: asyncio.Task | None = None
    legacy_sync_cursor_store = SyncCursorStore(store.data_dir / "sync-state.sqlite3")
    profile_cursor_stores: dict[str, SyncCursorStore] = {"legacy-default": legacy_sync_cursor_store}

    def current_cursor_store() -> SyncCursorStore:
        profile_key = active_server_id or "unselected"
        if profile_key not in profile_cursor_stores:
            safe_key = "".join(ch for ch in profile_key if ch.isalnum() or ch in "._-")
            profile_cursor_stores[profile_key] = SyncCursorStore(store.data_dir / f"sync-state-{safe_key}.sqlite3")
        return profile_cursor_stores[profile_key]

    secure_storage = None
    if fss is not None:
        try:
            secure_storage = fss.SecureStorage()
            page.services.append(secure_storage)
        except Exception:
            # Synchronization stays disabled until secure storage is available.
            secure_storage = None

    website_store_init_lock = asyncio.Lock()
    website_store_key_name = "kawal_trace_website_db_aesgcm_v1"

    async def ensure_website_monitor_store() -> WebsiteMonitorStore:
        """Unlock/create the encrypted website database through OS Secure Storage."""
        nonlocal website_monitor_store
        if website_monitor_store is not None:
            return website_monitor_store
        if secure_storage is None:
            raise WebsiteMonitorError(
                "Pemantauan website dikunci karena Secure Storage OS tidak tersedia; database tidak dibuka tanpa enkripsi."
            )
        async with website_store_init_lock:
            if website_monitor_store is not None:
                return website_monitor_store
            try:
                key_hex = str(await secure_storage.get(website_store_key_name) or "").strip()
            except Exception as exc:
                raise WebsiteMonitorError(
                    "Kunci database website tidak dapat dibaca dari Secure Storage OS."
                ) from exc
            if not key_hex:
                existing_db = store.data_dir / "website-monitor.sqlite3"
                try:
                    if existing_db.is_file():
                        with existing_db.open("rb") as existing_db_file:
                            existing_prefix = existing_db_file.read(32)
                    else:
                        existing_prefix = b""
                except OSError as exc:
                    raise WebsiteMonitorError("File database website tidak dapat diperiksa; file tetap dipertahankan.") from exc
                if existing_prefix.startswith(WebsiteMonitorStore._MAGIC):
                    raise WebsiteMonitorError(
                        "Kunci Secure Storage OS tidak ditemukan untuk database terenkripsi yang sudah ada; pulihkan kunci/backup. Kunci baru tidak dibuat agar data tidak terkunci lebih jauh."
                    )
                key_hex = secrets.token_hex(32)
                try:
                    await secure_storage.set(website_store_key_name, key_hex)
                    key_hex = str(await secure_storage.get(website_store_key_name) or "").strip()
                except Exception as exc:
                    raise WebsiteMonitorError(
                        "Kunci enkripsi website tidak dapat disimpan di Secure Storage OS."
                    ) from exc
            if len(key_hex) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in key_hex):
                raise WebsiteMonitorError(
                    "Kunci database website tidak valid di Secure Storage OS; file tidak dibuka."
                )
            candidate = WebsiteMonitorStore(
                store.data_dir / "website-monitor.sqlite3", encryption_key=key_hex.lower()
            )
            website_monitor_store = candidate
            return candidate

    async def initialize_website_monitor_store() -> None:
        try:
            await ensure_website_monitor_store()
            website_monitor_status_text.value = (
                "DATABASE TERENKRIPSI SIAP · kunci dikelola Secure Storage OS; pemeriksaan jaringan tetap nonaktif sampai diminta."
            )
            website_monitor_status_text.color = C["green"]
            refresh_website_targets()
            refresh_status_overview()
            page.update()
        except Exception as exc:
            website_monitor_status_text.value = (
                f"PENYIMPANAN WEBSITE TERKUNCI · {type(exc).__name__}; tidak ada fallback database plaintext."
            )
            website_monitor_status_text.color = C["red"]
            refresh_status_overview()
            page.update()

    mark_stage("prepare platform services")
    # Native notifications require a built Flet artifact; stock `flet run` does not
    # include the plugin's Flutter half. Polling alerts only run while this app runs.
    native_notifications = None
    native_notifications_enabled = False
    security_alarm_enabled = True  # audible alarms for new high/critical alerts while the app is open
    security_alarm_audio = None
    feed_seen_event_ids: dict[str, set[str]] = {}
    feed_profile_initialized: set[str] = set()
    notified_alert_keys: set[str] = set()
    universal_feed_client_cache: dict[str, tuple[str, ReadOnlyProtocolAdapter]] = {}
    if LocalNotifications is not None:
        try:
            native_notifications = LocalNotifications()
        except Exception:
            native_notifications = None
    if fta is not None:
        try:
            security_alarm_audio = fta.Audio(src="security_alert.wav", volume=1.0, autoplay=False)
            page.services.append(security_alarm_audio)
        except Exception:
            security_alarm_audio = None

    page.title = "Kawal Trace | Audit Console"
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = ft.Theme(color_scheme_seed=C["lime"], use_material3=True, font_family="Segoe UI")
    page.bgcolor = C["bg"]
    page.padding = 0
    page.spacing = 0
    page.scroll = None  # scroll ada di area konten; menu kiri tetap diam
    try:
        platform_value = getattr(getattr(page, "platform", None), "value", getattr(page, "platform", None))
        platform_name = str(platform_value).split(".")[-1].lower()
        if not bool(getattr(page, "web", False)) and platform_name not in {"android", "ios"}:
            page.window.min_width = 360
            page.window.min_height = 640
    except (AttributeError, RuntimeError, TypeError, ValueError):
        # Mobile clients determine their own viewport; some native clients disallow
        # desktop-only window minimums. A window hint must never block dashboard setup.
        pass

    mark_stage("construct dashboard controls")
    # Live values are kept as controls so refreshes do not rebuild the whole page.
    total_value = ft.Text("—", size=27, weight=ft.FontWeight.BOLD, color=C["text"])
    last_value = ft.Text("—", size=15, weight=ft.FontWeight.W_600, color=C["text"])
    head_value = ft.Text("—", size=11, color=C["lime"], font_family="Consolas", selectable=True)
    db_value = ft.Text("Data disimpan lokal di direktori aplikasi perangkat ini.", size=11, color=C["muted"])
    alert_value = ft.Text("0", size=27, weight=ft.FontWeight.BOLD, color=C["red"])
    monitor_path_text = ft.Text("Belum ada laporan dari Linux Server Agent", size=11, color=C["muted"], selectable=True)
    monitor_status_text = ft.Text("MENUNGGU KONEKSI SERVER", size=10, color=C["muted"], weight=ft.FontWeight.BOLD)
    monitor_detail_text = ft.Text(
        "Folder server akan dipantau otomatis setelah server terhubung dan Linux Server Agent melaporkan auditd siap.",
        size=11, color=C["muted"], selectable=True,
    )
    monitor_last_event_text = ft.Text("Belum ada perubahan file yang diterima.", size=10, color=C["quiet"], selectable=True)

    result_icon = ft.Icon(ft.Icons.VERIFIED_USER, color=C["lime"], size=25)
    result_flag = ft.Text("CHECK BELUM DIJALANKAN", size=10, color=C["lime"], weight=ft.FontWeight.BOLD)
    result_title = ft.Text("Menyiapkan pemeriksaan", size=23, weight=ft.FontWeight.BOLD, color=C["text"])
    result_desc = ft.Text(
        "Mesin akan memeriksa urutan record, previous_hash, hash record, dan integritas SQLite.",
        size=13, color=C["muted"], selectable=True,
    )
    result_count = ft.Text("RECORD DIPERIKSA  —", size=10, color=C["muted"], weight=ft.FontWeight.BOLD)
    result_head = ft.Text("HEAD HASH  —", size=10, color=C["muted"], font_family="Consolas", selectable=True)
    result_panel: ft.Container
    chain_runtime_state: dict[str, str] = {"status": "idle"}

    notice_dot = ft.Container(width=7, height=7, bgcolor=C["lime"], border_radius=9)
    notice_text = ft.Text("Konsol lokal siap.", size=11, color=C["muted"], selectable=True)

    def field_style() -> dict[str, Any]:
        return {
            "filled": True,
            "bgcolor": C["bg"],
            "color": C["text"],
            "cursor_color": C["lime"],
            "selection_color": C["panel_lift"],
            "hint_style": ft.TextStyle(color=C["quiet"]),
            "border": {
                ft.ControlState.DEFAULT: ft.OutlineInputBorder(
                    border_radius=8, side=ft.BorderSide(width=1, color=C["line"]),
                ),
                ft.ControlState.FOCUSED: ft.OutlineInputBorder(
                    border_radius=8, side=ft.BorderSide(width=1.5, color=C["lime"]),
                ),
            },
        }

    # --- Step-up verification: inline panel (the app has no modal dialogs) --------------------------------
    step_up_reason_text = ft.Text("", size=11, color=C["text"])
    step_up_field = ft.TextField(
        label="Kata sandi atau PIN Anda", password=True, can_reveal_password=True, max_length=128,
        text_size=12, **field_style(),
    )
    step_up_feedback = ft.Text("", size=10, color=C["amber"], selectable=True)
    step_up_panel = ft.Container(
        visible=False,
        content=ft.Column(controls=[
            ft.Text("VERIFIKASI ULANG DIPERLUKAN", size=10, color=C["lime"], weight=ft.FontWeight.BOLD),
            step_up_reason_text,
            ft.Text(f"Setelah benar, aksi sensitif tidak meminta lagi selama {STEP_UP_SECONDS // 60} menit.",
                    size=10, color=C["muted"]),
            step_up_field,
            ft.Row(controls=[
                ft.FilledButton(content="Verifikasi & lanjutkan", icon=ft.Icons.VERIFIED_USER,
                                on_click=lambda e: page.run_task(confirm_step_up), bgcolor=C["lime"], color=C["black"]),
                ft.OutlinedButton(content="Batal", on_click=lambda e: cancel_step_up()),
            ], wrap=True, spacing=8),
            step_up_feedback,
        ], spacing=9),
        padding=13, bgcolor=C["panel_alt"], border=ft.Border.all(1, C["amber"]), border_radius=10,
    )

    def step_up_is_fresh() -> bool:
        return time.monotonic() < float(step_up_state["valid_until"])

    def cancel_step_up() -> None:
        step_up_state["pending"] = None
        step_up_field.value = ""
        step_up_feedback.value = ""
        step_up_panel.visible = False
        page.update()

    def _audit_step_up(result: str, reason: str) -> None:
        try:
            store.add_event("AUTH", session["username"], "local-auth",
                            {"action": "step_up", "result": result, "reason": reason[:80],
                             "device_id": session.get("device_id", "unavailable"),
                             "platform": session.get("platform", "unknown")})
        except ChainLogError:
            pass  # the verification outcome still applies; the integrity panel reports a broken chain

    async def confirm_step_up(_: Any = None) -> None:
        pending = step_up_state["pending"]
        if pending is None:
            cancel_step_up()
            return
        fn, is_async, args, kwargs, reason = pending
        secret = step_up_field.value or ""
        step_up_field.value = ""
        ok = await asyncio.to_thread(registry.verify_step_up, session["username"], secret)
        if not ok:
            _audit_step_up("failed", reason)
            step_up_feedback.value = ("Verifikasi gagal, atau percobaan dibatasi sementara setelah terlalu banyak salah. "
                                      "Periksa kata sandi/PIN lalu coba lagi.")
            step_up_feedback.color = C["red"]
            page.update()
            return
        _audit_step_up("success", reason)
        step_up_state["valid_until"] = time.monotonic() + STEP_UP_SECONDS
        step_up_state["pending"] = None
        step_up_feedback.value = ""
        step_up_panel.visible = False
        page.update()
        if is_async:
            page.run_task(fn, *args, **kwargs)
        else:
            fn(*args, **kwargs)

    def requires_step_up(reason: str) -> Any:
        """Decorator: the handler runs at once while a recent verification is valid; otherwise the panel asks first.

        The wrapped function is remembered and executed, unchanged, right after a correct password/PIN.
        """
        def decorate(fn: Any) -> Any:
            is_async = asyncio.iscoroutinefunction(fn)

            def ask(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
                step_up_state["pending"] = (fn, is_async, args, kwargs, reason)
                step_up_reason_text.value = f"Anda akan: {reason}. Masukkan kata sandi (atau PIN) akun {session['username']}."
                step_up_feedback.value = ""
                step_up_panel.visible = True
                page.update()

            if is_async:
                @functools.wraps(fn)
                async def guarded_async(*args: Any, **kwargs: Any) -> Any:
                    if step_up_is_fresh():
                        return await fn(*args, **kwargs)
                    ask(args, kwargs)
                    return None
                return guarded_async

            @functools.wraps(fn)
            def guarded(*args: Any, **kwargs: Any) -> Any:
                if step_up_is_fresh():
                    return fn(*args, **kwargs)
                ask(args, kwargs)
                return None
            return guarded
        return decorate

    event_type = ft.TextField(
        label="Jenis peristiwa", value="ACCESS", hint_text="AUTH / ACCESS / CONFIG / ALERT",
        max_length=20, capitalization=ft.TextCapitalization.CHARACTERS,
        text_size=13, **field_style(),
    )
    actor_field = ft.TextField(
        label="Aktor (identitas sesi terautentikasi)", value=session["username"],
        max_length=80, read_only=True, text_size=13, **field_style(),
    )
    source_field = ft.TextField(
        label="Sumber / modul", value="dashboard", max_length=120,
        text_size=13, **field_style(),
    )
    details_field = ft.TextField(
        label="Catatan aktivitas", hint_text="Tuliskan tindakan, target, dan hasil yang tercatat…",
        multiline=True, min_lines=3, max_lines=5, max_length=3500,
        text_size=13, **field_style(),
    )
    review_seq_field = ft.TextField(label="Nomor record alarm", hint_text="mis. 0042", max_length=12,
                                    text_size=12, **field_style())
    review_decision_field = ft.TextField(label="Penilaian admin", value="suspicious",
                                         hint_text="authorized atau suspicious", max_length=24,
                                         text_size=12, **field_style())
    review_notes_field = ft.TextField(label="Catatan pemeriksaan", hint_text="Alasan dan bukti pendukung…",
                                      max_length=1200, text_size=12, **field_style())
    search_field = ft.TextField(
        hint_text="Cari aktor, jenis, sumber, atau isi log…", prefix_icon=ft.Icons.SEARCH,
        text_size=12, on_change=lambda _: refresh_logs(), **field_style(),
    )
    log_list = ft.Column(spacing=8)
    shown_count = ft.Text("0 RECORD", size=10, color=C["muted"], weight=ft.FontWeight.BOLD)

    website_name_field = ft.TextField(
        label="Nama target website", hint_text="Contoh: Website perusahaan", max_length=100,
        text_size=12, **field_style(),
    )
    website_url_field = ft.TextField(
        label="URL website (HTTP/HTTPS, tanpa kredensial)", hint_text="https://example.org/",
        max_length=2048, keyboard_type=ft.KeyboardType.URL, text_size=12, **field_style(),
    )
    website_interval_field = ft.TextField(
        label="Interval (detik, 30–86400)", value="300", max_length=5,
        keyboard_type=ft.KeyboardType.NUMBER, text_size=12, **field_style(),
    )
    website_timeout_field = ft.TextField(
        label="Timeout (detik, 1–30)", value="8", max_length=2,
        keyboard_type=ft.KeyboardType.NUMBER, text_size=12, **field_style(),
    )
    website_failure_threshold_field = ft.TextField(
        label="Ambang gagal berurutan (1–10)", value="3", max_length=2,
        keyboard_type=ft.KeyboardType.NUMBER, text_size=12, **field_style(),
    )
    website_allow_internal = ft.Checkbox(
        label="Target internal milik saya / diizinkan administrator", value=False,
    )
    website_monitor_status_text = ft.Text(
        "PEMANTAUAN NONAKTIF · URL tidak diperiksa sampai tombol Uji atau Mulai ditekan.",
        size=11, color=C["muted"], selectable=True,
    )
    website_target_list = ft.Column(controls=[], spacing=8)

    # Optional, explicitly configured, read-only audit connectors. Secret values are
    # sent to the OS Secure Storage bridge; they are never written into JSON profiles.
    connector_status_text = ft.Text(
        "KONEKTOR NONAKTIF · koneksi jaringan hanya berjalan setelah tombol Uji/Start ditekan.",
        size=11, color=C["muted"], selectable=True,
    )
    ssh_host_field = ft.TextField(label="SSH hostname/IP", value="", hint_text="linux.example.org", text_size=11, **field_style())
    ssh_port_field = ft.TextField(label="Port SSH", value="22", keyboard_type=ft.KeyboardType.NUMBER, text_size=11, **field_style())
    ssh_user_field = ft.TextField(label="Username read-only", value="audit_reader", text_size=11, **field_style())
    ssh_key_path_field = ft.TextField(label="Path private key (opsional; dimuat ke Secure Storage saat Uji)", value="", text_size=10, **field_style())
    ssh_known_hosts_field = ft.TextField(label="Path known_hosts terpercaya", value="", text_size=10, **field_style())
    ssh_profile_field = ft.Dropdown(
        label="Log SSH yang dibaca", value="ssh_auth_recent", text_size=11,
        options=[ft.DropdownOption(key="ssh_auth_recent", text="Autentikasi SSH terbaru"),
                 ft.DropdownOption(key="sudo_recent", text="Aktivitas sudo terbaru"),
                 ft.DropdownOption(key="auth_log_recent", text="/var/log/auth.log terbaru")],
        filled=True, bgcolor=C["bg"], color=C["text"],
    )
    db_engine_field = ft.Dropdown(
        label="Database", value="mysql", text_size=11,
        options=[ft.DropdownOption(key="mysql", text="MySQL"),
                 ft.DropdownOption(key="mariadb", text="MariaDB"),
                 ft.DropdownOption(key="sqlserver", text="SQL Server")],
        filled=True, bgcolor=C["bg"], color=C["text"],
    )
    db_host_field = ft.TextField(label="Hostname/IP database", value="", text_size=11, **field_style())
    db_port_field = ft.TextField(label="Port", value="3306", keyboard_type=ft.KeyboardType.NUMBER, text_size=11, **field_style())
    db_name_field = ft.TextField(label="Nama database", value="", text_size=11, **field_style())
    db_user_field = ft.TextField(label="User SELECT-only", value="audit_reader", text_size=11, **field_style())
    db_password_field = ft.TextField(label="Password (Secure Storage OS)", value="", password=True, can_reveal_password=True, text_size=11, **field_style())
    db_table_field = ft.TextField(label="Tabel/view audit", value="audit_events", text_size=11, **field_style())
    db_ca_path_field = ft.TextField(label="CA TLS file untuk MySQL/MariaDB", value="", text_size=10, **field_style())
    db_time_column_field = ft.TextField(label="Kolom waktu UTC", value="event_time", text_size=10, **field_style())
    db_type_column_field = ft.TextField(label="Kolom event_type", value="event_type", text_size=10, **field_style())
    db_host_column_field = ft.TextField(label="Kolom host_id", value="host_id", text_size=10, **field_style())
    db_source_column_field = ft.TextField(label="Kolom source", value="source", text_size=10, **field_style())
    db_actor_column_field = ft.TextField(label="Kolom actor", value="actor", text_size=10, **field_style())
    db_message_column_field = ft.TextField(label="Kolom message", value="message", text_size=10, **field_style())
    db_id_column_field = ft.TextField(label="Kolom event_id (opsional)", value="event_id", text_size=10, **field_style())

    syslog_bind_host_field = ft.TextField(label="IP listener syslog", value="127.0.0.1", text_size=11, **field_style())
    syslog_bind_port_field = ft.TextField(label="Port TCP", value="1514", keyboard_type=ft.KeyboardType.NUMBER, text_size=11, **field_style())
    syslog_ca_path_field = ft.TextField(label="CA sertifikat klien (wajib untuk listener non-loopback)", value="", text_size=10, **field_style())
    syslog_cert_path_field = ft.TextField(label="Sertifikat server TLS", value="", text_size=10, **field_style())
    syslog_key_path_field = ft.TextField(label="Private key TLS server", value="", text_size=10, **field_style())

    def current_server_settings() -> SyncSettings:
        profile = server_registry_store.get(active_server_id)
        return profile.settings if profile is not None else sync_settings_store.settings

    initial_sync_settings = current_server_settings()
    initial_profile = server_registry_store.get(active_server_id)
    server_name_field = ft.TextField(
        label="Nama profile server", value=initial_profile.name if initial_profile else "Server baru",
        hint_text="Contoh: Ubuntu production / Ubuntu lab", max_length=80, text_size=12,
        read_only=session["role"] != "admin", **field_style(),
    )
    server_profile_dropdown = ft.Dropdown(
        label="Server terdaftar", value=active_server_id,
        options=[ft.DropdownOption(key=p.profile_id, text=f"{p.name} · {p.settings.base_url}")
                 for p in server_registry_store.list()],
        hint_text="Pilih server yang akan dikelola", text_size=12,
        on_select=None, filled=True, bgcolor=C["bg"], color=C["text"],
    )
    server_connection_text = ft.Text(
        "TERPUTUS · pilih atau tambahkan server", size=11, color=C["muted"], selectable=True,
    )
    initial_wizard_mode = (
        "existing_api" if initial_sync_settings.connector_type == "generic_rest_readonly" else "kawal_api"
    )
    integration_mode_dropdown = ft.Dropdown(
        label="Cara server menyediakan log",
        value=initial_wizard_mode,
        options=[
            ft.DropdownOption(key="existing_api", text="Server sudah punya API log (paling mudah)"),
            ft.DropdownOption(key="kawal_api", text="API Kawal Trace (enrollment + feed)"),
            ft.DropdownOption(key="agent", text="Log hanya ada di server (perlu agen/collector)")
        ],
        text_size=12, filled=True, bgcolor=C["bg"], color=C["text"],
    )
    integration_mode_help = ft.Text(
        "Gunakan jika pemilik server telah menyediakan API yang membaca event keamanan. Kawal Trace mencoba beberapa path REST umum; bila API memakai path khusus, masukkan path resmi dari pemilik API.",
        size=10, color=C["muted"], selectable=True,
    )
    integration_wizard_result = ft.Text(
        "WIZARD SIAP · pilih jenis sumber log, lalu Terapkan pilihan.",
        size=10, color=C["muted"], selectable=True,
    )
    wizard_api_status_text = ft.Text("API · BELUM DIUJI", size=10, color=C["muted"], selectable=True)
    wizard_feed_status_text = ft.Text("FEED · BELUM DIUJI", size=10, color=C["muted"], selectable=True)
    wizard_agent_status_text = ft.Text("AGEN · BELUM DIVERIFIKASI", size=10, color=C["muted"], selectable=True)
    wizard_detection_status_text = ft.Text("DETEKSI · MENUNGGU EVENT", size=10, color=C["muted"], selectable=True)
    wizard_notification_status_text = ft.Text("NOTIFIKASI · BELUM DIUJI PADA PERANGKAT", size=10, color=C["muted"], selectable=True)

    def update_integration_wizard_help(e: ft.ControlEvent | None = None) -> None:
        mode = getattr(getattr(e, "control", None), "value", None) or integration_mode_dropdown.value
        descriptions = {
            "existing_api": "Paling mudah jika server sudah menyediakan API log keamanan. Masukkan Base URL dan token baca bila diperlukan, lalu gunakan Cari endpoint REST. Tidak perlu memasang API Kawal Trace pada server jika feed sudah kompatibel.",
            "kawal_api": "Untuk server yang memakai kontrak API Kawal Trace. Perangkat anggota meminta akses dan menunggu persetujuan administrator server satu kali.",
            "agent": "Untuk log yang hanya ada di OS. Agen/collector harus dipasang oleh pemilik atau administrator server sumber; Kawal Trace tidak bisa membaca log internal hanya dari URL website.",
        }
        integration_mode_help.value = descriptions.get(str(mode), descriptions["existing_api"])
        page.update()

    integration_mode_dropdown.on_select = update_integration_wizard_help
    sync_server_field = ft.TextField(
        label="Base URL server (HTTPS)", value=initial_sync_settings.base_url,
        hint_text="https://api.domain-milikmu.tld", text_size=12,
        read_only=session["role"] != "admin", **field_style(),
    )
    sync_events_path_field = ft.TextField(
        label="Path endpoint penerimaan batch", value=initial_sync_settings.events_path,
        hint_text=DEFAULT_EVENTS_PATH, text_size=12,
        read_only=session["role"] != "admin", **field_style(),
    )
    sync_health_path_field = ft.TextField(
        label="Path health-check", value=initial_sync_settings.health_path,
        hint_text=DEFAULT_HEALTH_PATH, text_size=12,
        read_only=session["role"] != "admin", **field_style(),
    )
    sync_telemetry_path_field = ft.TextField(
        label="Path API feed telemetri server (GET)", value=initial_sync_settings.telemetry_path,
        hint_text=DEFAULT_TELEMETRY_PATH, text_size=12,
        read_only=session["role"] != "admin", **field_style(),
    )
    def connector_mode_guidance(mode: str) -> str:
        if mode == "generic_rest_readonly":
            return (
                "API LOG EKSTERNAL · READ-ONLY. Pakai jika pemilik API sudah menyediakan event keamanan. "
                "Gunakan Cari endpoint REST untuk mencoba path umum dengan GET; jika tidak ditemukan, pakai path resmi penyedia. "
                "Koneksi ke website saja tidak berarti log host tersedia."
            )
        return (
            "API KAWAL TRACE · enrollment, feed, dan arsip sesuai kontrak API. Untuk event SSH/sudo/auditd, server sumber "
            "juga perlu memiliki agen/collector atau sumber log lain. Ini bukan syarat untuk pengguna yang sudah mempunyai API log kompatibel."
        )

    connector_mode_help_text = ft.Text(
        connector_mode_guidance(initial_sync_settings.connector_type),
        size=10, color=C["quiet"], selectable=True,
    )

    def update_connector_mode_guidance(e: ft.ControlEvent | None = None) -> None:
        selected_mode = getattr(getattr(e, "control", None), "value", None) or connector_type_dropdown.value
        selected_mode = str(selected_mode or DEFAULT_CONNECTOR_TYPE)
        connector_mode_help_text.value = connector_mode_guidance(selected_mode)
        # Keep the default Kawal Trace setup uncluttered. REST mapping controls
        # only appear when the operator explicitly selects Generic REST read-only.
        generic_rest_settings_panel.visible = selected_mode == "generic_rest_readonly"
        feed_auth_header_field.visible = feed_auth_mode_dropdown.value == "custom_header"
        adapter_protocol_dropdown.visible = selected_mode == "generic_rest_readonly"
        adapter_options_field.visible = selected_mode == "generic_rest_readonly"
        adapter_secret_field.visible = selected_mode == "generic_rest_readonly" and adapter_protocol_dropdown.value == "oauth2_rest"
        # In normal REST/API mode, show only the credential field relevant to reading the feed.
        monitor_token_field.visible = (selected_mode == "generic_rest_readonly" and feed_auth_mode_dropdown.value != "none") or manual_token_fields_visible
        page.update()

    connector_type_dropdown = ft.Dropdown(
        label="Jenis konektor",
        value=initial_sync_settings.connector_type,
        options=[
            ft.DropdownOption(key="kawal_trace_api", text="Kawal Trace API · upload + feed"),
            ft.DropdownOption(key="generic_rest_readonly", text="Universal API adapter · read-only"),
        ],
        text_size=12, filled=True, bgcolor=C["bg"], color=C["text"],
        disabled=session["role"] != "admin",
        on_select=update_connector_mode_guidance,
    )
    def update_feed_auth_header_visibility(e: ft.ControlEvent | None = None) -> None:
        selected_auth_mode = getattr(getattr(e, "control", None), "value", None) or feed_auth_mode_dropdown.value
        feed_auth_header_field.visible = selected_auth_mode == "custom_header"
        monitor_token_field.visible = (connector_type_dropdown.value == "generic_rest_readonly" and selected_auth_mode != "none") or manual_token_fields_visible
        page.update()

    feed_auth_mode_dropdown = ft.Dropdown(
        label="Autentikasi feed REST",
        value=initial_sync_settings.feed_auth_mode,
        options=[
            ft.DropdownOption(key="bearer", text="Authorization: Bearer token"),
            ft.DropdownOption(key="api_key", text="X-API-Key"),
            ft.DropdownOption(key="custom_header", text="Header khusus dari pemilik API"),
            ft.DropdownOption(key="none", text="Tanpa autentikasi (hanya jika API mengizinkan)"),
        ],
        text_size=12, filled=True, bgcolor=C["bg"], color=C["text"],
        disabled=session["role"] != "admin",
        on_select=update_feed_auth_header_visibility,
    )
    feed_auth_header_field = ft.TextField(
        label="Nama header autentikasi khusus",
        value=getattr(initial_sync_settings, "feed_auth_header_name", "X-API-Key"),
        hint_text="Misalnya X-Auth-Token", text_size=12,
        read_only=session["role"] != "admin",
    )
    feed_auth_header_field.visible = initial_sync_settings.feed_auth_mode == "custom_header"
    feed_json_path_field = ft.TextField(
        label="Generic REST · path array event JSON",
        value=initial_sync_settings.feed_json_path,
        hint_text="events atau data.items", text_size=12,
        read_only=session["role"] != "admin", **field_style(),
    )
    feed_field_mapping_field = ft.TextField(
        label="Generic REST · mapping field (JSON)",
        value=json.dumps(json.loads(initial_sync_settings.feed_field_mapping), ensure_ascii=False, indent=2),
        multiline=True, min_lines=5, max_lines=12, text_size=10,
        read_only=session["role"] != "admin", **field_style(),
    )
    adapter_protocol_dropdown = ft.Dropdown(
        label="Protokol feed eksternal",
        value=getattr(initial_sync_settings, "adapter_protocol", "rest"),
        options=[
            ft.DropdownOption(key="rest", text="REST/JSON + pagination"),
            ft.DropdownOption(key="oauth2_rest", text="REST/JSON + OAuth2 client credentials"),
            ft.DropdownOption(key="graphql", text="GraphQL query-only"),
            ft.DropdownOption(key="soap", text="SOAP/XML read-only"),
            ft.DropdownOption(key="websocket", text="WebSocket JSON feed"),
        ], text_size=12, filled=True, bgcolor=C["bg"], color=C["text"],
        disabled=session["role"] != "admin",
        on_select=lambda e: (setattr(adapter_secret_field, "visible", (getattr(getattr(e, "control", None), "value", None) or adapter_protocol_dropdown.value) == "oauth2_rest"), page.update()),
    )
    adapter_options_field = ft.TextField(
        label="Adapter options JSON (tanpa secret/token/password)",
        value=getattr(initial_sync_settings, "adapter_options_json", "{}"),
        hint_text='REST pagination: {"pagination":{"mode":"cursor","items_path":"data.events","next_cursor_path":"page.nextCursor","cursor_param":"cursor","max_pages":10}}',
        multiline=True, min_lines=4, max_lines=12, max_length=98304, text_size=10,
        read_only=session["role"] != "admin", **field_style(),
    )
    adapter_secret_field = ft.TextField(
        label="OAuth2 client secret (hanya disimpan Secure Storage OS)",
        hint_text="Diisi saat menyimpan profile; tidak dimasukkan ke JSON config",
        password=True, can_reveal_password=True, max_length=4096, text_size=12,
        read_only=session["role"] != "admin", visible=getattr(initial_sync_settings, "adapter_protocol", "rest") == "oauth2_rest", **field_style(),
    )
    advanced_api_settings_panel = ft.Container(
        visible=False,
        content=ft.Column(controls=[
            ft.Text("PENGATURAN LANJUTAN · HANYA JIKA FORMAT API BERBEDA", size=10, color=C["amber"], weight=ft.FontWeight.BOLD),
            feed_field_mapping_field,
            adapter_options_field,
            ft.Text("Mapping menerjemahkan nama field API ke field standar Kawal Trace. Adapter options dipakai untuk pagination/cursor atau konfigurasi protokol khusus. Jangan memasukkan token/password di JSON ini.", size=10, color=C["quiet"], selectable=True),
        ], spacing=8),
        padding=10, bgcolor=C["panel"], border=ft.Border.all(1, C["line"]), border_radius=8,
    )

    def toggle_api_advanced_settings(_: ft.ControlEvent | None = None) -> None:
        advanced_api_settings_panel.visible = not advanced_api_settings_panel.visible
        advanced_api_settings_toggle.content = (
            "Sembunyikan pengaturan lanjutan" if advanced_api_settings_panel.visible
            else "Pengaturan lanjutan · mapping / pagination"
        )
        page.update()

    advanced_api_settings_toggle = ft.OutlinedButton(
        content="Pengaturan lanjutan · mapping / pagination", icon=ft.Icons.TUNE,
        on_click=toggle_api_advanced_settings,
    )
    try:
        _initial_map = json.loads(feed_field_mapping_field.value or "{}")
        _default_map = json.loads(DEFAULT_FEED_FIELD_MAPPING)
        if _initial_map != _default_map or (adapter_options_field.value or "{}").strip() not in {"", "{}"}:
            advanced_api_settings_panel.visible = True
            advanced_api_settings_toggle.content = "Sembunyikan pengaturan lanjutan"
    except (TypeError, ValueError):
        advanced_api_settings_panel.visible = True
        advanced_api_settings_toggle.content = "Sembunyikan pengaturan lanjutan"

    generic_rest_settings_panel = ft.Container(
        visible=initial_sync_settings.connector_type == "generic_rest_readonly",
        content=ft.Column(controls=[
            ft.Text("API LOG EKSTERNAL · READ-ONLY", size=10,
                    weight=ft.FontWeight.BOLD, color=C["lime"]),
            ft.Text("Jika API sudah memberikan event keamanan, cukup isi protokol, autentikasi, dan path feed. Tombol Cari endpoint REST dapat mencoba beberapa path umum dengan GET saja. Path/mapping khusus tetap harus mengikuti dokumentasi pemilik API.", size=10, color=C["muted"], selectable=True),
            ft.ResponsiveRow(controls=[
                ft.Container(content=adapter_protocol_dropdown, col={"xs": 12, "md": 6}),
                ft.Container(content=feed_auth_mode_dropdown, col={"xs": 12, "md": 6}),
                ft.Container(content=feed_auth_header_field, col={"xs": 12, "md": 6}),
                ft.Container(content=sync_telemetry_path_field, col={"xs": 12, "md": 6}),
                ft.Container(content=feed_json_path_field, col={"xs": 12, "md": 6}),
                ft.Container(content=adapter_secret_field, col={"xs": 12, "md": 12}),
            ], spacing=10, run_spacing=8),
            advanced_api_settings_toggle,
            advanced_api_settings_panel,
            ft.Text("Token read-only disimpan di Secure Storage OS. Auto-detect hanya memakai GET ke Base URL yang kamu masukkan, tidak mengikuti redirect, dan tidak mengubah server remote.", size=10, color=C["quiet"], selectable=True),
        ], spacing=8),
        padding=10, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8,
    )
    kawal_api_advanced_paths_panel = ft.Container(
        visible=False,
        content=ft.Column(controls=[
            ft.Text("PATH API KAWAL TRACE · UBAH HANYA JIKA DOKUMENTASI SERVER MENYATAKAN BERBEDA", size=10, color=C["amber"], weight=ft.FontWeight.BOLD),
            connector_type_dropdown,
            ft.ResponsiveRow(controls=[
                ft.Container(content=sync_events_path_field, col={"xs": 12, "md": 7}),
                ft.Container(content=sync_health_path_field, col={"xs": 12, "md": 5}),
            ], spacing=10, run_spacing=8),
        ], spacing=8),
        padding=10, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8,
    )

    def toggle_kawal_api_advanced_paths(_: ft.ControlEvent | None = None) -> None:
        kawal_api_advanced_paths_panel.visible = not kawal_api_advanced_paths_panel.visible
        kawal_api_advanced_paths_toggle.content = (
            "Sembunyikan path API lanjutan" if kawal_api_advanced_paths_panel.visible
            else "Path API lanjutan · biasanya tidak perlu diubah"
        )
        page.update()

    kawal_api_advanced_paths_toggle = ft.OutlinedButton(
        content="Path API lanjutan · biasanya tidak perlu diubah", icon=ft.Icons.TUNE,
        on_click=toggle_kawal_api_advanced_paths,
    )

    sync_device_id_field = ft.TextField(
        label="ID perangkat (unik; cocokkan dengan enrollment server)",
        value=initial_sync_settings.device_id, read_only=True, text_size=11,
        **field_style(),
    )
    sync_token_field = ft.TextField(
        label="Token perangkat dari administrator server",
        hint_text="Dimasukkan satu kali, disimpan pada secure storage OS",
        password=True, can_reveal_password=True, text_size=12,
        read_only=session["role"] != "admin", visible=False, **field_style(),
    )
    monitor_token_field = ft.TextField(
        label="Token/API key untuk membaca feed (read-only)",
        hint_text="Token baca dari pemilik API; bukan token administrator",
        password=True, can_reveal_password=True, text_size=12,
        read_only=session["role"] != "admin",
        visible=(initial_sync_settings.connector_type == "generic_rest_readonly" and initial_sync_settings.feed_auth_mode != "none"),
        **field_style(),
    )
    response_token_field = ft.TextField(
        label="Token respons insiden (mode manual/legacy)",
        hint_text="Biasanya terisi otomatis setelah anggota disetujui server",
        password=True, can_reveal_password=True, text_size=12,
        read_only=session["role"] != "admin", visible=False, **field_style(),
    )
    admin_token_field = ft.TextField(
        label="Token administrator server (pemilik saja)",
        hint_text="Dibuat satu kali di Ubuntu; tidak sama dengan token perangkat",
        password=True, can_reveal_password=True, text_size=12,
        read_only=session["role"] != "admin", **field_style(),
    )
    member_device_id_field = ft.TextField(
        label="Device ID anggota", hint_text="Tempel ID perangkat anggota yang meminta akses",
        max_length=128, text_size=12, **field_style(),
    )
    membership_status_text = ft.Text(
        "PENDAFTARAN ANGGOTA BELUM DIPERIKSA", size=11, color=C["muted"], selectable=True,
    )
    membership_list = ft.Column(spacing=6)
    # Build 14 — Trusted Access local invitation + incident UI
    invite_name_field = ft.TextField(
        label="Nama anggota baru", hint_text="Contoh: Budi Santoso",
        max_length=100, text_size=12, **field_style(),
    )
    invite_email_field = ft.TextField(
        label="Email anggota", hint_text="Contoh: budi@example.com",
        max_length=120, text_size=12, **field_style(),
    )
    invite_role_dropdown = ft.Dropdown(
        label="Peran",
        options=[
            ft.dropdown.Option("member", "Member"),
            ft.dropdown.Option("operator", "Operator"),
            ft.dropdown.Option("viewer", "Viewer"),
        ],
        value="member",
        text_size=12,
        dense=True,
    )
    invite_code_display = ft.TextField(
        label="Kode undangan (berikan ke anggota secara aman)",
        value="", read_only=True, text_size=11, visible=False, **field_style(),
    )
    local_trusted_status = ft.Text(
        "Trusted Access lokal belum dimuat", size=11, color=C["muted"], selectable=True,
    )
    local_trusted_list = ft.Column(spacing=6)
    incident_status_text = ft.Text(
        "Riwayat insiden belum dimuat", size=11, color=C["muted"], selectable=True,
    )
    incident_list = ft.Column(spacing=6)
    member_totp_seed_field = ft.TextField(
        label="Seed TOTP perangkat ini (simpan di Authenticator; rahasia)",
        value="", read_only=True, text_size=11, visible=False, **field_style(),
    )
    manual_token_fields_visible = False
    manual_token_toggle_button = ft.OutlinedButton(
        content="Pengaturan token manual (legacy)", icon=ft.Icons.TUNE,
        on_click=lambda e: toggle_manual_token_fields(),
    )
    response_totp_field = ft.TextField(
        label="Kode TOTP 6 digit untuk persetujuan respons",
        hint_text="Kode authenticator yang berlaku saat ini", max_length=6,
        password=True, can_reveal_password=True, text_size=12,
        read_only=session["role"] != "admin", **field_style(),
    )
    e2ee_public_key_field = ft.TextField(
        label="E2EE public key untuk server/agen (boleh dibagikan)",
        value="Belum dibuat", read_only=True, multiline=True, min_lines=1, max_lines=3,
        text_size=10, **field_style(),
    )
    e2ee_backup_passphrase_field = ft.TextField(
        label="Frasa sandi backup kunci E2EE (min. 14 karakter)",
        password=True, can_reveal_password=True, max_length=200, text_size=12,
        read_only=session["role"] != "admin", **field_style(),
    )
    e2ee_backup_json_field = ft.TextField(
        label="Backup kunci privat terenkripsi (salin ke perangkat kedua)",
        hint_text="JSON backup akan muncul di sini; backup tetap perlu frasa sandi.",
        multiline=True, min_lines=3, max_lines=7, max_length=8000, text_size=10,
        read_only=session["role"] != "admin", **field_style(),
    )
    e2ee_status_text = ft.Text(
        "E2EE BELUM DIKONFIGURASI · buat keypair lalu salin public key ke agen/server",
        size=10, color=C["amber"], selectable=True,
    )
    response_ip_field = ft.TextField(
        label="IPv4 publik dari event feed yang akan dikarantina sementara",
        hint_text="Hanya IP yang terlihat pada feed profile aktif",
        text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    response_reason_field = ft.TextField(
        label="Alasan respons / nomor tiket", hint_text="Contoh: IR-2026-004 · lonjakan SSH gagal",
        max_length=180, text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    response_confirm_field = ft.TextField(
        label="Konfirmasi eksplisit", hint_text="Ketik tepat: BLOCK <alamat-IP>",
        max_length=64, text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    response_ttl_dropdown = ft.Dropdown(
        label="Durasi karantina sementara", value="300",
        options=[ft.DropdownOption(key="300", text="5 menit"),
                 ft.DropdownOption(key="900", text="15 menit"),
                 ft.DropdownOption(key="1800", text="30 menit")],
        text_size=12, filled=True, bgcolor=C["bg"], color=C["text"],
        disabled=session["role"] != "admin",
    )
    response_status_text = ft.Text(
        "RESPONS NONAKTIF · memerlukan API/worker, allowlist admin, dan token respons khusus",
        size=10, color=C["muted"], selectable=True,
    )
    response_actions_list = ft.Column(spacing=6)
    windows_target_host_field = ft.TextField(
        label="Windows Host ID terdaftar", hint_text="Host ID dari feed / enrollment server",
        text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    windows_action_dropdown = ft.Dropdown(
        label="Tindakan Windows (nonaktif secara default di host)", value="WINDOWS_BLOCK_IP",
        options=[
            ft.DropdownOption(key="WINDOWS_BLOCK_IP", text="Firewall: blokir IP sementara"),
            ft.DropdownOption(key="WINDOWS_LOGOFF_SESSION", text="Isolasi sesi RDP: logoff"),
            ft.DropdownOption(key="WINDOWS_TERMINATE_PROCESS", text="Hentikan CMD/PowerShell milik target"),
        ], text_size=12, filled=True, bgcolor=C["bg"], color=C["text"],
        disabled=session["role"] != "admin",
    )
    windows_target_value_field = ft.TextField(
        label="Target: IPv4 / Session ID / PID", hint_text="Isi sesuai tindakan yang dipilih",
        text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    windows_target_user_field = ft.TextField(
        label="Nama user target (untuk RDP/process)", hint_text="Nama akun tepat seperti hasil inventaris host",
        text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    windows_process_name_field = ft.TextField(
        label="Nama proses target (untuk tindakan terminate)", hint_text="cmd.exe / powershell.exe / pwsh.exe / wt.exe",
        text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    windows_response_reason_field = ft.TextField(
        label="Alasan / tiket insiden Windows", hint_text="Minimal 8 karakter; sertakan nomor insiden",
        max_length=180, text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    windows_response_confirm_field = ft.TextField(
        label="Konfirmasi dua langkah (ketik persis sesuai target)",
        hint_text="BLOCK 8.8.8.8 / LOGOFF 12 user / TERMINATE 1234 powershell.exe",
        max_length=180, text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    windows_response_totp_field = ft.TextField(
        label="Kode TOTP 6 digit untuk persetujuan Windows", max_length=6,
        password=True, can_reveal_password=True, text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    windows_response_status_text = ft.Text(
        "WINDOWS RESPONSE NONAKTIF secara default · target host harus terdaftar dan agen Windows harus mengonfirmasi kebijakan lokal",
        size=10, color=C["muted"], selectable=True,
    )
    windows_response_actions_list = ft.Column(spacing=6)
    notification_status_text = ft.Text(
        "NOTIFIKASI SISTEM BELUM DIAKTIFKAN · izin OS diperlukan; push saat aplikasi ditutup butuh FCM",
        size=10, color=C["muted"], selectable=True,
    )
    current_feed_ips: set[str] = set()
    current_feed_ufw_ips: set[str] = set()
    current_feed_windows_auth_ips: set[tuple[str, str]] = set()
    server_feed_status_text = ft.Text(
        "FEED SERVER BELUM DIUJI", size=11, color=C["muted"], selectable=True,
    )
    live_stream_status_text = ft.Text(
        live_stream_message(STATE_STOPPED), size=11, color=C["muted"], selectable=True,
    )
    server_feed_summary_text = ft.Text(
        "Belum ada telemetri server yang diambil. Feed kosong tidak membuktikan server aman.",
        size=11, color=C["muted"], selectable=True,
    )
    server_feed_fleet_text = ft.Text("FLEET BELUM DIPERIKSA · profile multi-server tersimpan lokal", size=10, color=C["blue"], selectable=True)
    latest_server_feed_events: list[dict[str, Any]] = []
    current_feed_hosts: set[str] = set()
    server_feed_list = ft.Column(spacing=7)
    archive_storage_mode_dropdown = ft.Dropdown(
        label="Penyimpanan arsip aktivitas",
        value="device",
        options=[ft.DropdownOption(key="device", text="Perangkat ini saja (tidak dikirim ke server)")],
        text_size=12, filled=True, bgcolor=C["bg"], color=C["text"],
        on_select=None, disabled=True,
    )
    archive_date_dropdown = ft.Dropdown(
        label="Tanggal arsip (UTC)", value="all",
        options=[ft.DropdownOption(key="all", text="Semua tanggal")],
        text_size=12, filled=True, bgcolor=C["bg"], color=C["text"], on_select=None,
    )
    archive_status_text = ft.Text(
        "Arsip lokal siap · event akan dipisahkan menurut tanggal UTC", size=10, color=C["muted"], selectable=True,
    )
    archive_summary_text = ft.Text("Belum ada log arsip untuk profile yang dipilih.", size=11, color=C["muted"], selectable=True)
    archive_export_directory_text = ft.Text(str(archive_preferences.get("export_dir", store.data_dir / "reports" / "server-logs")), size=9, color=C["quiet"], selectable=True)
    archive_preview_list = ft.Column(spacing=6)
    sync_status_text = ft.Text(
        "BELUM DIKONFIGURASI · log tetap tersimpan lokal", size=11,
        color=C["muted"], selectable=True,
    )

    def label(value: str, color: str | None = None) -> ft.Text:
        return ft.Text(value.upper(), size=10, color=color or C["muted"], weight=ft.FontWeight.BOLD)

    def tag(value: str, color: str = C["muted"], bg: str = C["panel_lift"]) -> ft.Container:
        return ft.Container(
            content=ft.Text(value, size=9, color=color, weight=ft.FontWeight.BOLD),
            padding=ft.Padding(left=9, right=9, top=6, bottom=6),
            bgcolor=bg, border=ft.Border.all(1, C["line"]), border_radius=5,
        )

    def section_heading(kicker: str, title: str, detail: str | None = None) -> ft.Column:
        controls: list[ft.Control] = [
            label(kicker, C["lime"]),
            ft.Text(title, size=18, weight=ft.FontWeight.BOLD, color=C["text"]),
        ]
        if detail:
            controls.append(ft.Text(detail, size=12, color=C["muted"]))
        return ft.Column(controls=controls, spacing=4)

    def panel(content: ft.Control, *, padding: int = 18, bgcolor: str | None = None) -> ft.Container:
        return ft.Container(
            content=content,
            padding=padding,
            bgcolor=bgcolor or C["panel"],
            border=ft.Border.all(1, C["line"]),
            border_radius=14,
        )

    def metric_card(kicker: str, value_control: ft.Control, symbol: str, hint: str) -> ft.Container:
        return ft.Container(
            content=ft.Column(
                controls=[
                    ft.Row(
                        controls=[label(kicker), ft.Text(symbol, size=12, color=C["lime"], weight=ft.FontWeight.BOLD)],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    value_control,
                    ft.Text(hint, size=10, color=C["quiet"]),
                ], spacing=8,
            ),
            padding=15, bgcolor=C["panel"], border=ft.Border.all(1, C["line"]), border_radius=11,
        )

    def set_notice(message: str, tone: str = "neutral") -> None:
        color = {
            "good": C["green"], "warning": C["amber"], "danger": C["red"], "neutral": C["lime"],
        }.get(tone, C["lime"])
        notice_dot.bgcolor = color
        notice_text.value = message
        notice_text.color = color if tone != "neutral" else C["muted"]
        page.update()

    def _website_status_color(status: str) -> str:
        return C["green"] if status == "UP" else C["amber"] if status == "HTTP_ERROR" else C["red"]

    def refresh_website_targets(_: Any = None) -> None:
        website_target_list.controls = []
        monitor_store = website_monitor_store
        if monitor_store is None:
            website_target_list.controls.append(ft.Container(
                content=ft.Text("Menunggu Secure Storage OS untuk membuka database website terenkripsi…", size=11, color=C["muted"]),
                padding=14, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=9,
            ))
            page.update()
            return
        targets = monitor_store.list_targets()
        if not targets:
            website_target_list.controls.append(ft.Container(
                content=ft.Text("Belum ada target website. Tambahkan URL secara manual di atas.", size=11, color=C["muted"]),
                padding=14, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=9,
            ))
        for target in targets:
            latest = monitor_store.list_checks(target.target_id, 1)
            last_check = latest[0] if latest else None
            status = target.last_status or "BELUM DIUJI"
            detail = (
                f"{last_check['event_type']} · HTTP {last_check['http_status'] or '—'} · "
                f"DNS {last_check['dns_ms'] if last_check['dns_ms'] is not None else '—'} ms · "
                f"respons {last_check['response_ms'] if last_check['response_ms'] is not None else '—'} ms · "
                f"total {last_check['total_ms']} ms · {format_time(str(last_check['checked_at_utc']))}"
                if last_check else "Belum ada hasil pemeriksaan."
            )
            website_target_list.controls.append(ft.Container(
                content=ft.Column(controls=[
                    ft.Row(controls=[
                        ft.Column(controls=[
                            ft.Text(target.name, size=13, weight=ft.FontWeight.BOLD, color=C["text"]),
                            ft.Text(redact_website_url(target.url), size=10, color=C["muted"], selectable=True),
                        ], spacing=3, expand=True),
                        ft.Container(content=ft.Text(status, size=9, color=_website_status_color(status), weight=ft.FontWeight.BOLD),
                                     padding=7, bgcolor=C["bg"], border=ft.Border.all(1, _website_status_color(status)), border_radius=6),
                    ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    ft.Text(f"Interval {target.interval_seconds} detik · timeout {target.timeout_seconds} detik · "
                            f"{'internal diizinkan' if target.allow_internal else 'target publik saja'} · "
                            f"{'AKTIF' if target.enabled else 'DINONAKTIFKAN'}", size=9, color=C["quiet"]),
                    ft.Text(detail, size=10, color=C["muted"], selectable=True),
                    ft.Row(controls=[
                        ft.OutlinedButton(content="Uji sekarang", icon=ft.Icons.LAN,
                                          on_click=lambda e, tid=target.target_id: page.run_task(test_website_target, tid),
                                          disabled=session["role"] == "viewer"),
                        ft.OutlinedButton(content="Nonaktifkan" if target.enabled else "Aktifkan", icon=ft.Icons.PAUSE if target.enabled else ft.Icons.PLAY_ARROW,
                                          on_click=lambda e, tid=target.target_id, en=target.enabled: page.run_task(toggle_website_target, tid, not en),
                                          disabled=session["role"] == "viewer"),
                        ft.OutlinedButton(content="Ekspor JSON", icon=ft.Icons.DOWNLOAD,
                                          on_click=lambda e, tid=target.target_id: page.run_task(export_website_history, tid)),
                        ft.OutlinedButton(content="Hapus", icon=ft.Icons.DELETE_OUTLINE,
                                          on_click=lambda e, tid=target.target_id: page.run_task(delete_website_target, tid),
                                          disabled=session["role"] == "viewer"),
                    ], spacing=7, wrap=True),
                ], spacing=6), padding=12, bgcolor=C["panel_alt"],
                border=ft.Border.all(1, C["line"]), border_radius=10,
            ))
        page.update()

    async def add_website_target(_: ft.ControlEvent | None = None) -> None:
        if session["role"] == "viewer":
            set_notice("Peran viewer hanya dapat membaca data; target website tidak ditambahkan.", "warning")
            return
        try:
            monitor_store = await ensure_website_monitor_store()
            target = monitor_store.add_target(
                website_name_field.value or "", website_url_field.value or "",
                int((website_interval_field.value or "300").strip()),
                int((website_timeout_field.value or "8").strip()),
                allow_internal=bool(website_allow_internal.value),
                failure_threshold=int((website_failure_threshold_field.value or "3").strip()),
            )
            website_monitor_status_text.value = (
                f"TARGET TERSIMPAN LOKAL · {target.name}. Belum ada koneksi jaringan dibuat; tekan Uji sekarang atau Mulai pemantauan."
            )
            website_monitor_status_text.color = C["green"]
            website_url_field.value = ""
            refresh_website_targets()
            set_notice("Target website disimpan lokal. Belum ada request jaringan yang dijalankan.", "good")
        except (WebsiteMonitorError, ValueError, sqlite3.Error) as exc:
            website_monitor_status_text.value = f"TARGET TIDAK DISIMPAN · {type(exc).__name__}: {str(exc)[:160]}"
            website_monitor_status_text.color = C["red"]
            page.update()
            set_notice("Validasi target website gagal; lihat pesan di panel pemantauan.", "warning")

    async def test_website_target(target_id: int, quiet: bool = False) -> None:
        try:
            monitor_store = await ensure_website_monitor_store()
            result = await asyncio.to_thread(monitor_store.check_target, target_id)
            website_monitor_status_text.value = (
                f"{result['event_type']} · {result['message']} · DNS {result['dns_ms']} ms · "
                f"respons {result['response_ms']} ms · total {result['total_ms']} ms. "
                "Hasil disimpan di riwayat website lokal, bukan security log."
            )
            website_monitor_status_text.color = _website_status_color(str(result["status"]))
            refresh_website_targets()
            refresh_status_overview()
            alert_msg = (f" Alarm: gagal {result['failure_streak']} kali berturut-turut (ambang {result['failure_threshold']})."
                         if result.get("alert_triggered") else "")
            if not quiet or result.get("alert_triggered"):
                set_notice(f"Pemeriksaan website selesai: {result['event_type']}.{alert_msg}",
                           "good" if result["status"] == "UP" else "warning" if result["status"] == "HTTP_ERROR" else "danger")
        except WebsiteMonitorError as exc:
            website_monitor_status_text.value = f"PEMERIKSAAN DITOLAK · {exc}"
            website_monitor_status_text.color = C["red"]
            refresh_status_overview()
            page.update()
            if not quiet:
                set_notice("Pemeriksaan website tidak dijalankan.", "warning")
        except Exception as exc:
            website_monitor_status_text.value = f"PEMERIKSAAN GAGAL · {type(exc).__name__}; detail sensitif tidak ditampilkan."
            website_monitor_status_text.color = C["red"]
            refresh_status_overview()
            page.update()
            if not quiet:
                set_notice("Pemeriksaan website gagal karena kesalahan lokal yang perlu ditinjau.", "danger")

    async def export_website_history(target_id: int) -> None:
        try:
            monitor_store = await ensure_website_monitor_store()
            payload = monitor_store.export_checks_json(target_id, 5000)
            target = monitor_store.get_target(target_id)
            if target is None:
                raise WebsiteMonitorError("Target website tidak ditemukan.")
            filename = ("kawal-trace-website-history-" + str(target.target_id) + "-"
                        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
            saved_path = await folder_picker.save_file(
                dialog_title="Ekspor riwayat website lokal", file_name=filename,
                file_type=ft.FilePickerFileType.CUSTOM, allowed_extensions=["json"],
                src_bytes=(payload + "\n").encode("utf-8"),
            )
            if saved_path:
                website_monitor_status_text.value = f"EKSPOR RIWAYAT SELESAI · file lokal: {saved_path}"
                website_monitor_status_text.color = C["green"]
                set_notice("Riwayat website diekspor ke lokasi yang dipilih; tidak ada upload cloud.", "good")
            else:
                website_monitor_status_text.value = "EKSPOR DIBATALKAN · tidak ada file yang dinyatakan tersimpan."
                website_monitor_status_text.color = C["amber"]
                set_notice("Dialog ekspor dibatalkan; tidak ada file yang dinyatakan tersimpan.", "warning")
            page.update()
        except Exception as exc:
            website_monitor_status_text.value = f"EKSPOR GAGAL · {type(exc).__name__}; tidak ada klaim file tersimpan."
            website_monitor_status_text.color = C["red"]
            page.update()
            set_notice("Ekspor riwayat website gagal.", "danger")

    async def toggle_website_target(target_id: int, enabled: bool) -> None:
        try:
            monitor_store = await ensure_website_monitor_store()
            monitor_store.set_enabled(target_id, enabled)
            refresh_website_targets()
            set_notice("Target website diaktifkan." if enabled else "Target website dinonaktifkan; tidak ikut pemantauan terjadwal.", "good")
        except WebsiteMonitorError as exc:
            set_notice(str(exc), "warning")

    async def delete_website_target(target_id: int) -> None:
        try:
            monitor_store = await ensure_website_monitor_store()
            monitor_store.delete_target(target_id)
            if monitor_store.get_target(target_id) is not None:
                raise WebsiteMonitorError("Target website masih ditemukan setelah penghapusan.")
            refresh_website_targets()
            set_notice("Target website dan riwayat lokalnya dihapus.", "good")
        except (WebsiteMonitorError, sqlite3.Error, OSError) as exc:
            set_notice(f"Target website belum terhapus: {exc}", "danger")

    async def website_monitor_loop() -> None:
        """Poll enabled targets only after the operator explicitly starts monitoring."""
        try:
            monitor_store = await ensure_website_monitor_store()
        except Exception as exc:
            website_monitor_state["active"] = False
            website_monitor_status_text.value = f"PEMANTAUAN TIDAK DIMULAI · penyimpanan terenkripsi terkunci ({type(exc).__name__})."
            website_monitor_status_text.color = C["red"]
            page.update()
            return
        while website_monitor_state["active"]:
            try:
                now = datetime.now(timezone.utc)
                for target in monitor_store.list_targets(enabled_only=True):
                    if not website_monitor_state["active"]:
                        break
                    due = not target.last_checked_utc
                    if target.last_checked_utc:
                        try:
                            last = datetime.fromisoformat(target.last_checked_utc.replace("Z", "+00:00"))
                            if last.tzinfo is None:
                                last = last.replace(tzinfo=timezone.utc)
                            due = (now - last.astimezone(timezone.utc)).total_seconds() >= target.interval_seconds
                        except ValueError:
                            due = True
                    if due:
                        await test_website_target(target.target_id, quiet=True)
                await asyncio.sleep(5)
            except asyncio.CancelledError:
                return
            except Exception as exc:
                website_monitor_status_text.value = f"PEMANTAUAN TERGANGGU · {type(exc).__name__}; data lama tetap lokal."
                website_monitor_status_text.color = C["amber"]
                page.update()
                await asyncio.sleep(5)

    async def start_website_monitor(_: ft.ControlEvent | None = None) -> None:
        if session["role"] == "viewer":
            set_notice("Peran viewer tidak dapat memulai koneksi website.", "warning")
            return
        if website_monitor_state["active"]:
            set_notice("Pemantauan website sudah aktif.", "neutral")
            return
        try:
            monitor_store = await ensure_website_monitor_store()
        except Exception as exc:
            website_monitor_status_text.value = f"PEMANTAUAN TIDAK DIMULAI · database terenkripsi terkunci ({type(exc).__name__})."
            website_monitor_status_text.color = C["red"]
            page.update()
            return
        if not monitor_store.list_targets(enabled_only=True):
            website_monitor_status_text.value = "BELUM ADA TARGET AKTIF · simpan dan aktifkan target terlebih dahulu."
            website_monitor_status_text.color = C["amber"]
            page.update()
            return
        website_monitor_state["active"] = True
        website_monitor_status_text.value = "PEMANTAUAN AKTIF · hanya target yang tersimpan dan diaktifkan yang diperiksa."
        website_monitor_status_text.color = C["green"]
        page.run_task(website_monitor_loop)
        page.update()
        set_notice("Pemantauan website aktif. Koneksi hanya ke target yang dipilih.", "good")

    def stop_website_monitor(_: ft.ControlEvent | None = None) -> None:
        website_monitor_state["active"] = False
        website_monitor_status_text.value = "PEMANTAUAN NONAKTIF · data dan riwayat lokal tetap tersedia."
        website_monitor_status_text.color = C["muted"]
        page.update()
        set_notice("Pemantauan website dihentikan.", "neutral")

    def _connector_secret_key(namespace: str, identity: str) -> str:
        digest = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()[:24]
        return f"kawal_trace_{namespace}_{digest}"

    async def test_ssh_connector(_: ft.ControlEvent | None = None) -> None:
        if session["role"] == "viewer":
            connector_status_text.value = "DITOLAK · akun viewer tidak dapat menjalankan konektor sumber."
            connector_status_text.color = C["red"]
            page.update()
            return
        connector_runtime_state["ssh_status"] = "connecting"
        connector_runtime_state["ssh_label"] = (ssh_host_field.value or "SSH").strip()
        refresh_status_overview()
        try:
            if secure_storage is None:
                raise SSHConnectorError("Secure Storage OS tidak tersedia; private key tidak dipakai.")
            host = (ssh_host_field.value or "").strip()
            username = (ssh_user_field.value or "").strip()
            port = int((ssh_port_field.value or "22").strip())
            identity = f"{host.casefold()}:{port}:{username}"
            secret_key = _connector_secret_key("ssh_private_key", identity)
            private_key = str(await secure_storage.get(secret_key) or "")
            key_path_text = (ssh_key_path_field.value or "").strip()
            if key_path_text:
                key_path = Path(key_path_text).expanduser()
                if not key_path.is_file() or key_path.stat().st_size > 128_000:
                    raise SSHConnectorError("File private key tidak ditemukan atau lebih dari 128 KB.")
                private_key = key_path.read_text(encoding="utf-8")
                if "PRIVATE KEY-----" not in private_key:
                    raise SSHConnectorError("File yang dipilih tidak tampak seperti private key PEM/OpenSSH.")
                await secure_storage.set(secret_key, private_key)
                ssh_key_path_field.value = ""
                page.update()
            if not private_key:
                raise SSHConnectorError("Private key belum tersimpan; masukkan path file agar disalin ke Secure Storage OS.")
            connector = SSHReadOnlyConnector(
                host=host, username=username, private_key_pem=private_key,
                known_hosts_file=(ssh_known_hosts_field.value or "").strip(), port=port,
                command_profile=ssh_profile_field.value or "ssh_auth_recent", timeout_seconds=8,
            )
            events = await asyncio.to_thread(connector.fetch_events, 100)
            label = f"ssh:{host}:{port}"
            with connector_ingest_lock:
                result = connector_ingestor.ingest(label, events)
            refresh_logs()
            connector_status_text.value = (
                f"SSH READ-ONLY SELESAI · {len(events)} event; {result['added']} baru, "
                f"{result['skipped_duplicate']} duplikat dilewati, {result['rejected']} ditolak."
            )
            connector_status_text.color = C["green"]
            connector_runtime_state["ssh_status"] = "good"
        except (SSHConnectorError, OSError, ValueError) as exc:
            connector_status_text.value = f"SSH GAGAL · {type(exc).__name__}: {str(exc)[:180]}"
            connector_status_text.color = C["red"]
            connector_runtime_state["ssh_status"] = "bad"
        except Exception as exc:
            connector_status_text.value = f"SSH GAGAL · {type(exc).__name__}; detail rahasia tidak ditampilkan."
            connector_status_text.color = C["red"]
            connector_runtime_state["ssh_status"] = "bad"
        refresh_status_overview()
        page.update()

    async def test_database_audit_connector(_: ft.ControlEvent | None = None) -> None:
        if session["role"] == "viewer":
            connector_status_text.value = "DITOLAK · akun viewer tidak dapat menjalankan konektor sumber."
            connector_status_text.color = C["red"]
            page.update()
            return
        connector_runtime_state["database_status"] = "connecting"
        connector_runtime_state["database_label"] = (db_host_field.value or "Database").strip()
        refresh_status_overview()
        try:
            if secure_storage is None:
                raise DatabaseAuditError("Secure Storage OS tidak tersedia; password tidak dipakai.")
            engine = (db_engine_field.value or "mysql").strip().lower()
            host = (db_host_field.value or "").strip()
            port = int((db_port_field.value or ("1433" if engine == "sqlserver" else "3306")).strip())
            database_name = (db_name_field.value or "").strip()
            username = (db_user_field.value or "").strip()
            identity = f"{engine}:{host.casefold()}:{port}:{database_name}:{username}"
            secret_key = _connector_secret_key("db_password", identity)
            password_value = str(db_password_field.value or "")
            if password_value.strip():
                await secure_storage.set(secret_key, password_value)
                db_password_field.value = ""
                page.update()
            else:
                password_value = str(await secure_storage.get(secret_key) or "")
            if not password_value:
                raise DatabaseAuditError("Password wajib diisi dan disimpan di Secure Storage OS.")
            config = DatabaseAuditConfig(
                engine=engine, host=host, port=port, database=database_name,
                username=username, source_table=(db_table_field.value or "").strip(),
                timestamp_column=(db_time_column_field.value or "event_time").strip(),
                event_type_column=(db_type_column_field.value or "event_type").strip(),
                host_column=(db_host_column_field.value or "host_id").strip(),
                source_column=(db_source_column_field.value or "source").strip(),
                actor_column=(db_actor_column_field.value or "actor").strip(),
                message_column=(db_message_column_field.value or "message").strip(),
                event_id_column=(db_id_column_field.value or "").strip(),
                tls_ca_file=(db_ca_path_field.value or "").strip(), timeout_seconds=8,
            )
            connector = DatabaseAuditConnector(config, password=password_value)
            events = await asyncio.to_thread(connector.fetch_events, limit=100)
            label = f"database:{engine}:{host}:{port}/{database_name}"
            with connector_ingest_lock:
                result = connector_ingestor.ingest(label, events)
            refresh_logs()
            connector_status_text.value = (
                f"AUDIT DATABASE SELESAI · {len(events)} event; {result['added']} baru, "
                f"{result['skipped_duplicate']} duplikat dilewati, {result['rejected']} ditolak. "
                "Akun sumber wajib dibatasi SELECT-only di database."
            )
            connector_status_text.color = C["green"]
            connector_runtime_state["database_status"] = "good"
        except (DatabaseAuditError, OSError, ValueError) as exc:
            connector_status_text.value = f"AUDIT DATABASE GAGAL · {type(exc).__name__}: {str(exc)[:180]}"
            connector_status_text.color = C["red"]
            connector_runtime_state["database_status"] = "bad"
        except Exception as exc:
            connector_status_text.value = f"AUDIT DATABASE GAGAL · {type(exc).__name__}; detail rahasia tidak ditampilkan."
            connector_status_text.color = C["red"]
            connector_runtime_state["database_status"] = "bad"
        refresh_status_overview()
        page.update()

    def _build_syslog_tls_context(host: str) -> ssl.SSLContext | None:
        cert_path = (syslog_cert_path_field.value or "").strip()
        key_path = (syslog_key_path_field.value or "").strip()
        ca_path = (syslog_ca_path_field.value or "").strip()
        ip = ipaddress.ip_address(host)
        if ip.is_loopback and not (cert_path or key_path or ca_path):
            return None
        if not (cert_path and key_path and ca_path):
            raise SyslogConnectorError("Listener non-loopback memerlukan CA klien, sertifikat server, dan private key TLS.")
        for path_value in (cert_path, key_path, ca_path):
            if not Path(path_value).expanduser().is_file():
                raise SyslogConnectorError("Salah satu file TLS syslog tidak ditemukan.")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(Path(cert_path).expanduser()), keyfile=str(Path(key_path).expanduser()))
        context.load_verify_locations(cafile=str(Path(ca_path).expanduser()))
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    async def syslog_status_loop(receiver: SyslogTCPReceiver) -> None:
        last_count = -1
        while connector_runtime_state["syslog_active"] and syslog_receiver is receiver:
            address = receiver.address
            if address:
                connector_status_text.value = (
                    f"SYSLOG LISTENING · {address[0]}:{address[1]} · {receiver.received_count} pesan diterima, "
                    f"{receiver.rejected_count} ditolak. Tekan Hentikan untuk menutup listener."
                )
                connector_status_text.color = C["green"]
            else:
                connector_status_text.value = "SYSLOG TIDAK AKTIF"
                connector_status_text.color = C["amber"]
            if receiver.received_count != last_count:
                last_count = receiver.received_count
                refresh_logs()
            page.update()
            await asyncio.sleep(1)

    async def start_syslog_listener(_: ft.ControlEvent | None = None) -> None:
        nonlocal syslog_receiver
        if session["role"] == "viewer":
            connector_status_text.value = "DITOLAK · akun viewer tidak dapat membuka listener."
            connector_status_text.color = C["red"]
            page.update()
            return
        if connector_runtime_state["syslog_active"]:
            connector_status_text.value = "SYSLOG SUDAH AKTIF · hentikan listener saat ini terlebih dahulu."
            connector_status_text.color = C["amber"]
            page.update()
            return
        connector_runtime_state["syslog_status"] = "connecting"
        refresh_status_overview()
        try:
            host = (syslog_bind_host_field.value or "127.0.0.1").strip()
            port = int((syslog_bind_port_field.value or "1514").strip())
            tls_context = _build_syslog_tls_context(host)
            label = f"syslog:{host}:{port}"

            def accept_event(event: dict[str, Any]) -> None:
                try:
                    with connector_ingest_lock:
                        result = connector_ingestor.ingest(label, [event])
                    if result["rejected"]:
                        connector_runtime_state["syslog_error"] = "Event ditolak oleh pipeline audit lokal."
                except Exception as exc:
                    connector_runtime_state["syslog_error"] = type(exc).__name__
                    connector_runtime_state["syslog_rejected"] += 1

            receiver = SyslogTCPReceiver(host, port, accept_event, tls_context=tls_context)
            address = await asyncio.to_thread(receiver.start)
            syslog_receiver = receiver
            connector_runtime_state["syslog_active"] = True
            connector_runtime_state["syslog_status"] = "good"
            connector_runtime_state["syslog_label"] = label
            connector_runtime_state["syslog_error"] = ""
            connector_status_text.value = (
                f"SYSLOG LISTENING · {address[0]}:{address[1]} · pastikan sumber resmi dan firewall sudah dikonfigurasi; "
                "listener non-loopback harus menggunakan mTLS."
            )
            connector_status_text.color = C["green"]
            refresh_status_overview()
            page.update()
            page.run_task(syslog_status_loop, receiver)
        except (SyslogConnectorError, OSError, ValueError) as exc:
            connector_runtime_state["syslog_status"] = "bad"
            connector_runtime_state["syslog_error"] = type(exc).__name__
            connector_status_text.value = f"SYSLOG GAGAL DIMULAI · {type(exc).__name__}: {str(exc)[:180]}"
            connector_status_text.color = C["red"]
            refresh_status_overview()
            page.update()
        except Exception as exc:
            connector_runtime_state["syslog_status"] = "bad"
            connector_runtime_state["syslog_error"] = type(exc).__name__
            connector_status_text.value = f"SYSLOG GAGAL DIMULAI · {type(exc).__name__}; detail rahasia tidak ditampilkan."
            connector_status_text.color = C["red"]
            refresh_status_overview()
            page.update()

    async def stop_syslog_listener(_: ft.ControlEvent | None = None) -> None:
        nonlocal syslog_receiver
        connector_runtime_state["syslog_active"] = False
        connector_runtime_state["syslog_status"] = "idle"
        receiver, syslog_receiver = syslog_receiver, None
        if receiver is not None:
            await asyncio.to_thread(receiver.close)
        connector_status_text.value = (
            f"SYSLOG NONAKTIF · {receiver.received_count if receiver else 0} pesan diterima, "
            f"{receiver.rejected_count if receiver else 0} ditolak."
        )
        connector_status_text.color = C["muted"]
        refresh_logs()
        refresh_status_overview()
        page.update()

    def database_engine_changed(_: Any = None) -> None:
        engine = (db_engine_field.value or "mysql").strip().lower()
        if (db_port_field.value or "").strip() in {"", "3306", "1433"}:
            db_port_field.value = "1433" if engine == "sqlserver" else "3306"
            page.update()

    db_engine_field.on_select = database_engine_changed

    def render_result(result: VerificationResult, simulated: bool = False) -> None:
        if result.valid:
            tone, title = C["green"], "Rantai terverifikasi"
            flag, icon_name = "INTEGRITAS / VALID", ft.Icons.VERIFIED_USER
            description = (
                f"{result.count} record diperiksa. Seluruh tautan hash cocok dan tidak ditemukan perubahan."
            )
            bg = C["panel_alt"]
        elif simulated:
            tone, title = C["red"], "Perubahan berhasil terdeteksi"
            flag, icon_name = "SIMULASI / ALARM AKTIF", ft.Icons.WARNING_AMBER
            description = result.reason + " Database asli tetap utuh; perubahan hanya dilakukan pada salinan memori."
            bg = "#241515"
        else:
            tone, title = C["red"], "Integritas rantai bermasalah"
            flag, icon_name = "INTEGRITAS / TIDAK VALID", ft.Icons.WARNING_AMBER
            description = result.reason or "Ditemukan ketidaksesuaian saat verifikasi."
            bg = "#241515"

        result_icon.name = icon_name
        result_icon.color = tone
        result_flag.value = flag
        result_flag.color = tone
        result_title.value = title
        result_title.color = C["text"]
        result_desc.value = description
        result_count.value = f"RECORD DIPERIKSA  {result.count:>04}"
        fail_text = f"  /  POSISI BERMASALAH #{result.failing_seq}" if result.failing_seq else ""
        result_head.value = f"HEAD HASH  {result.head_hash[:28]}…{fail_text}"
        result_panel.bgcolor = bg
        result_panel.border = ft.Border.all(1, tone)
        chain_runtime_state["status"] = "good" if result.valid and not simulated else "bad"
        try:
            render_topology()
        except NameError:
            # The first verification can run before the topology controls are constructed.
            pass
        page.update()

    def format_time(raw: str) -> str:
        # Stored UTC ISO timestamps are stable in exports; compact only for the UI.
        if not raw or raw == "—":
            return "—"
        try:
            return raw.replace("T", "  ").replace("Z", " UTC")[:25]
        except Exception:
            return raw

    def make_log_card(record: dict[str, Any]) -> ft.Control:
        details = record.get("details", {})
        try:
            detail_string = json.dumps(details, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            detail_string = str(details)
        if len(detail_string) > 210:
            detail_string = detail_string[:207] + "…"

        kind = str(record.get("event_type", "UNKNOWN")).upper()
        tone = {
            "AUTH": C["green"], "ACCESS": C["green"], "CONFIG": C["amber"],
            "ALERT": C["red"], "VERIFY": C["lime"], "SYSTEM": C["muted"], "NOTE": C["muted"],
        }.get(kind, C["muted"])
        short_hash = str(record.get("record_hash", ""))[:34]

        return ft.Container(
            content=ft.Row(
                controls=[
                    ft.Container(width=3, height=88, bgcolor=tone, border_radius=5),
                    ft.Column(
                        controls=[
                            ft.Row(
                                controls=[
                                    ft.Text(f"{int(record['seq']):04}", size=11, color=C["lime"], font_family="Consolas", weight=ft.FontWeight.BOLD),
                                    tag(kind, tone, C["panel_lift"]),
                                    ft.Container(expand=True),
                                    ft.Text(format_time(str(record.get("timestamp_utc", ""))), size=9, color=C["quiet"]),
                                ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            ft.Text(
                                f"{record.get('actor', '—')}  /  {record.get('source', '—')}",
                                size=12, color=C["text"], weight=ft.FontWeight.W_600,
                            ),
                            ft.Text(detail_string, size=11, color=C["muted"], selectable=True),
                            ft.Row(
                                controls=[
                                    ft.Icon(ft.Icons.FINGERPRINT, size=12, color=C["quiet"]),
                                    ft.Text(short_hash + "…", size=9, color=C["quiet"], font_family="Consolas", selectable=True),
                                ], spacing=5,
                            ),
                        ], spacing=7, expand=True,
                    ),
                ], spacing=11, vertical_alignment=ft.CrossAxisAlignment.START,
            ),
            padding=12, bgcolor=C["panel"], border=ft.Border.all(1, C["line"]), border_radius=10,
        )

    def refresh_logs() -> None:
        query = (search_field.value or "").strip().casefold()
        records = store.records(limit=80)
        records = list(reversed(records))
        if query:
            def searchable(record: dict[str, Any]) -> str:
                try:
                    details = json.dumps(record.get("details", {}), ensure_ascii=False, sort_keys=True)
                except (TypeError, ValueError):
                    details = str(record.get("details", ""))
                return " ".join((
                    str(record.get("seq", "")), str(record.get("event_type", "")),
                    str(record.get("actor", "")), str(record.get("source", "")), details,
                )).casefold()
            records = [record for record in records if query in searchable(record)]
        log_list.controls = [make_log_card(record) for record in records]
        if not records:
            message = "Belum ada aktivitas di database." if not query else "Tidak ada log yang cocok dengan pencarian."
            log_list.controls = [
                ft.Container(
                    content=ft.Column(
                        controls=[
                            ft.Icon(ft.Icons.SEARCH if query else ft.Icons.HISTORY, size=24, color=C["quiet"]),
                            ft.Text(message, size=12, color=C["muted"]),
                        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=8,
                    ), padding=24, alignment=ft.Alignment(0, 0),
                    border=ft.Border.all(1, C["line"]), border_radius=10,
                )
            ]
        shown_count.value = f"{len(records):02} RECORD" + (" / FILTER AKTIF" if query else " / TERBARU")
        page.update()

    def refresh_summary() -> None:
        stats = store.database_stats()
        total_value.value = f"{int(stats['count']):,}".replace(",", ".")
        raw_last = str(stats.get("last_timestamp", "—"))
        last_value.value = format_time(raw_last)
        raw_head = str(stats.get("head_hash", ""))
        head_value.value = raw_head[:48] + ("…" if len(raw_head) > 48 else "")
        # Keep the physical identity/audit database path out of the normal UI.
        # Diagnostic logs remain available to the owner when an actual error occurs.
        db_value.value = "Data disimpan lokal di direktori aplikasi perangkat ini."
        try:
            records_for_review = store.records()
            reviewed_sequences = {
                int(item.get("details", {}).get("alert_seq"))
                for item in records_for_review
                if item.get("event_type") == "CONFIG"
                and isinstance(item.get("details"), dict)
                and item["details"].get("action") == "alert_reviewed"
                and str(item["details"].get("alert_seq", "")).isdigit()
            }
            pending_count = sum(
                1 for item in records_for_review
                if item.get("event_type") == "ALERT"
                and isinstance(item.get("details"), dict)
                and item["details"].get("classification") == "UNATTRIBUTED_EXTERNAL_CHANGE"
                and int(item.get("seq", 0)) not in reviewed_sequences
            )
            alert_value.value = str(pending_count)
        except Exception:
            alert_value.value = "?"
        refresh_logs()
        try:
            refresh_status_overview()
        except Exception as exc:
            _log_ui_diagnostic(store.data_dir, "status overview", exc)

    def run_verification(_: ft.ControlEvent | None = None) -> None:
        result = store.verify()
        render_result(result)
        set_notice(
            "Rantai lolos pemeriksaan." if result.valid else "Perhatian: verifikasi menemukan masalah.",
            "good" if result.valid else "danger",
        )

    def run_simulation(_: ft.ControlEvent | None = None) -> None:
        result = store.simulate_tampering()
        render_result(result, simulated=True)
        set_notice("Skenario selesai. Database asli tidak diubah.", "danger" if not result.valid else "warning")

    def add_log(_: ft.ControlEvent | None = None) -> None:
        if session["role"] == "viewer":
            set_notice("Peran viewer hanya dapat membaca data; penambahan log ditolak.", "warning")
            return
        detail = (details_field.value or "").strip()
        if not detail:
            set_notice("Catatan aktivitas masih kosong — isi dulu sebelum menyimpan.", "warning")
            return
        try:
            store.add_event(
                event_type.value or "ACCESS",
                actor_field.value or "",
                source_field.value or "",
                {"message": detail},
            )
            details_field.value = ""
            refresh_summary()
            render_result(store.verify())
            set_notice("Record tersimpan. Hash baru terhubung dengan record sebelumnya.", "good")
        except ChainLogError as exc:
            set_notice(str(exc), "danger")
        except Exception as exc:  # Keep an unexpected local failure visible to the operator.
            set_notice(f"Gagal menyimpan log: {exc}", "danger")

    def add_demo(_: ft.ControlEvent | None = None) -> None:
        if session["role"] == "viewer":
            set_notice("Peran viewer tidak dapat menambahkan data demo.", "warning")
            return
        samples = [
            ("AUTH", session["username"], "identity.local", {"message": "Sesi operator lokal dibuka", "result": "success"}),
            ("ACCESS", session["username"], "asset-register", {"message": "Permintaan akses modul inventaris", "result": "allowed"}),
            ("CONFIG", session["username"], "policy.check", {"message": "Pemeriksaan konfigurasi demo", "result": "no-change"}),
        ]
        try:
            for kind, actor, source, details in samples:
                store.add_event(kind, actor, source, details)
            refresh_summary()
            render_result(store.verify())
            set_notice("Tiga record demo ditambahkan untuk pengujian presentasi.", "good")
        except ChainLogError as exc:
            set_notice(str(exc), "danger")

    def export_json(_: ft.ControlEvent | None = None) -> None:
        try:
            path = store.export_json()
            set_notice(f"Bukti JSON tersimpan: {path}", "good")
        except Exception as exc:
            set_notice(f"Ekspor JSON gagal: {exc}", "danger")

    def export_csv(_: ft.ControlEvent | None = None) -> None:
        try:
            path = store.export_csv()
            set_notice(f"CSV tersimpan: {path}", "good")
        except Exception as exc:
            set_notice(f"Ekspor CSV gagal: {exc}", "danger")

    async def export_server_feed_json(_: ft.ControlEvent | None = None) -> None:
        await export_server_archive("json")

    async def export_server_feed_csv(_: ft.ControlEvent | None = None) -> None:
        await export_server_archive("csv")

    async def export_server_feed_pdf(_: ft.ControlEvent | None = None) -> None:
        await export_server_archive("pdf")

    # --- Secure client-to-server synchronization --------------------------
    def _profile_secret_key(kind: str, profile_id: str | None = None) -> str:
        pid = profile_id or active_server_id or "unselected"
        safe_pid = "".join(ch for ch in pid if ch.isalnum() or ch in "._:-")
        return f"kawal_trace_{kind}:{safe_pid}"

    async def _load_device_token(profile_id: str | None = None) -> str:
        """Load a profile-scoped device/audit token from OS secure storage."""
        target_profile_id = profile_id if profile_id is not None else active_server_id
        if secure_storage is not None and target_profile_id:
            try:
                value = await secure_storage.get(_profile_secret_key("device_token", target_profile_id))
                if isinstance(value, str) and value.strip():
                    return value.strip()
                if target_profile_id == "legacy-default":
                    legacy_value = await secure_storage.get("kawal_trace_device_token")
                    if isinstance(legacy_value, str) and legacy_value.strip():
                        return legacy_value.strip()
            except Exception:
                pass
        # Environment-token fallback is retained only for a single-server shell deployment.
        if profile_id is None and active_server_id is None:
            return os.environ.get("KAWAL_TRACE_DEVICE_TOKEN", "").strip()
        return ""

    def _make_sync_client(token: str, recipient_public_key_b64: str = "") -> SyncClient:
        settings = current_server_settings()
        if not settings.base_url:
            raise SyncConfigError("Base URL server belum diatur.")
        return SyncClient(settings, token, current_cursor_store(), recipient_public_key_b64=recipient_public_key_b64,
                          require_e2ee_for_remote=True)

    async def _load_monitor_token() -> str:
        if secure_storage is None or not active_server_id:
            return ""
        try:
            value = await secure_storage.get(_profile_secret_key("monitor_token"))
            if isinstance(value, str) and value.strip():
                return value.strip()
            if active_server_id == "legacy-default":
                return str(await secure_storage.get("kawal_trace_monitor_token") or "").strip()
            return ""
        except Exception:
            return ""

    async def _load_oauth_client_secret() -> str:
        if secure_storage is None or not active_server_id:
            return ""
        try:
            value = await secure_storage.get(_profile_secret_key("oauth_client_secret"))
            return value if isinstance(value, str) else ""
        except Exception:
            return ""

    async def _make_readonly_feed_client(settings: SyncSettings):
        """Build/reuse the configured read-only connector for any supported protocol."""
        token = await _load_monitor_token()
        protocol = getattr(settings, "adapter_protocol", "rest") or "rest"
        is_oauth = settings.connector_type == "generic_rest_readonly" and protocol == "oauth2_rest"
        if settings.feed_auth_mode != "none" and not token and not is_oauth:
            raise GenericRestFeedError("Token/API key read-only belum tersedia. Gunakan kredensial dari administrator API.")
        if not settings.base_url:
            raise SyncConfigError("Base URL server belum diatur.")
        options = getattr(settings, "adapter_options_json", "{}") or "{}"
        if protocol == "rest" and not json.loads(options):
            return GenericRestFeedClient(settings, token)
        adapter_secret = await _load_oauth_client_secret() if is_oauth else ""
        if is_oauth and not adapter_secret:
            raise ProtocolAdapterError("OAuth2 client secret belum tersimpan di Secure Storage OS; simpan profile dengan secret dari administrator API.")
        secret_fingerprint = adapter_secret_fingerprint(adapter_secret)
        cache_key = str(active_server_id or "unselected")
        profile_signature = hashlib.sha256((
            settings.base_url + settings.telemetry_path + protocol + options +
            settings.feed_field_mapping + settings.feed_json_path + settings.feed_auth_mode +
            settings.feed_auth_header_name + settings.ca_bundle + settings.device_id +
            secret_fingerprint + hashlib.sha256(token.encode()).hexdigest()
        ).encode()).hexdigest()
        cached = universal_feed_client_cache.get(cache_key)
        if cached is None or cached[0] != profile_signature:
            if cached is not None:
                cached[1].close()
            client = ReadOnlyProtocolAdapter(settings, token, client_secret=adapter_secret)
            universal_feed_client_cache[cache_key] = (profile_signature, client)
            return client
        return cached[1]

    def _save_archive_preferences() -> None:
        archive_preferences["version"] = 1
        archive_preferences["mode"] = "device"
        archive_preferences["export_dir"] = str(archive_export_directory_text.value or (store.data_dir / "reports" / "server-logs"))
        archive_preferences_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = archive_preferences_path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(archive_preferences, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temp_path, archive_preferences_path)
        if os.name != "nt":
            try:
                archive_preferences_path.chmod(0o600)
            except OSError:
                pass

    def _selected_archive_date() -> str | None:
        selected = str(archive_date_dropdown.value or "all")
        return None if selected == "all" else selected

    def _render_archive_preview(events: list[dict[str, Any]], empty_message: str) -> None:
        preview_controls: list[ft.Control] = []
        for event in events[:20]:
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            try:
                parsed = datetime.fromisoformat(str(event.get("timestamp_utc", "")).replace("Z", "+00:00"))
                local_text = parsed.astimezone().strftime("%d-%m-%Y %H:%M:%S %Z")
            except (ValueError, TypeError):
                local_text = "waktu tidak valid"
            detail_text = "; ".join(f"{key}: {value}" for key, value in list(details.items())[:4])[:180] or "Tidak ada detail tambahan"
            event_type = str(event.get("event_type", "UNKNOWN"))
            color = C["red"] if "FAILURE" in event_type or event_type == "MALWARE_DETECTED" else C["amber"] if event_type in {"FILE_CHANGE", "SERVICE_CHANGE", "PRIVILEGE_USE"} else C["muted"]
            preview_controls.append(ft.Container(
                content=ft.Column(controls=[
                    ft.Row(controls=[tag(event_type, color), ft.Text(local_text, size=9, color=C["muted"])], wrap=True, alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Text(f"UTC {event.get('timestamp_utc', '')} · HOST {event.get('host_id', 'unknown')} · AKUN {event.get('actor', 'unknown')}", size=9, color=C["text"], selectable=True),
                    ft.Text(f"IP {event.get('source_ip') or 'tidak tersedia'} · {detail_text}", size=10, color=C["muted"], selectable=True),
                ], spacing=4), padding=9, bgcolor=C["panel_alt"], border=ft.Border.all(1, C["line"]), border_radius=7,
            ))
        if events:
            preview_controls.append(ft.Text("Pratinjau menampilkan maksimal 20 event terbaru; ekspor dapat memuat seluruh hasil sesuai tanggal filter.", size=9, color=C["quiet"]))
        else:
            preview_controls.append(ft.Text(empty_message, size=10, color=C["muted"]))
        archive_preview_list.controls = preview_controls

    def refresh_archive_view(_: ft.ControlEvent | None = None) -> None:
        if not active_server_id:
            archive_date_dropdown.options = [ft.DropdownOption(key="all", text="Semua tanggal")]
            archive_date_dropdown.value = "all"
            archive_summary_text.value = "Pilih atau simpan profile server terlebih dahulu."
            _render_archive_preview([], "Belum ada sumber log.")
            archive_status_text.value = "Arsip lokal siap; belum ada profile server aktif."
            page.update()
            return
        try:
            counts = server_event_archive.date_counts(active_server_id)
            total = sum(item["count"] for item in counts)
            available_dates = {item["date"] for item in counts}
            options = [ft.DropdownOption(key="all", text=f"Semua tanggal · {total} event")]
            options.extend(ft.DropdownOption(key=item["date"], text=f"{item['date']} UTC · {item['count']} event") for item in counts)
            selected = str(archive_date_dropdown.value or "all")
            if selected != "all" and selected not in available_dates:
                selected = "all"
            archive_date_dropdown.options = options
            archive_date_dropdown.value = selected
            selected_count = total if selected == "all" else next((item["count"] for item in counts if item["date"] == selected), 0)
            date_text = "semua tanggal" if selected == "all" else f"tanggal UTC {selected}"
            archive_summary_text.value = f"{selected_count} event · {date_text} · {len(counts)} hari tersedia. Timestamp sumber disimpan sebagai UTC; tampilan juga menunjukkan waktu lokal perangkat."
            events = server_event_archive.list_events(active_server_id, selected, limit=20)
            _render_archive_preview(events, "Belum ada event tersimpan pada tanggal ini. Hubungkan feed lalu tekan Ambil event server.")
            archive_status_text.value = "Arsip hanya di perangkat ini; tidak ada salinan yang dikirim ke server."
            archive_status_text.color = C["muted"]
        except (ArchiveError, OSError, ValueError, sqlite3.Error) as exc:
            archive_status_text.value = f"Arsip belum dapat dibaca: {exc}"
            archive_status_text.color = C["red"]
            _render_archive_preview([], "Periksa laporan error arsip dan buat cadangan database sebelum perbaikan.")
        page.update()

    async def choose_archive_export_folder(_: ft.ControlEvent | None = None) -> None:
        try:
            selected_dir = await folder_picker.get_directory_path(dialog_title="Pilih folder ekspor log Kawal Trace")
            if selected_dir:
                archive_export_directory_text.value = str(selected_dir)
                archive_preferences["export_dir"] = str(selected_dir)
                _save_archive_preferences()
                archive_status_text.value = f"Folder ekspor dipilih: {selected_dir}"
                archive_status_text.color = C["green"]
                page.update()
        except Exception as exc:
            set_notice(f"Pemilihan folder ekspor gagal: {exc}", "warning")

    async def export_server_archive(file_format: str) -> None:
        try:
            if not active_server_id:
                raise ArchiveError("Pilih server sumber terlebih dahulu.")
            profile = server_registry_store.get(active_server_id)
            if profile is None:
                raise ArchiveError("Profile server tidak ditemukan.")
            selected_date = _selected_archive_date()
            events = server_event_archive.list_events(active_server_id, selected_date)
            if not events:
                set_notice("Tidak ada event pada filter arsip yang dipilih; tidak ada file dibuat.", "warning")
                return
            output_dir = Path(str(archive_export_directory_text.value or archive_preferences.get("export_dir") or (store.data_dir / "reports" / "server-logs"))).expanduser()
            output_dir.mkdir(parents=True, exist_ok=True)
            safe_profile = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in profile.name).strip("-._")[:48] or "server"
            date_part = selected_date or "semua-tanggal-UTC"
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            path = output_dir / f"kawal-trace-{safe_profile}-{date_part}-{stamp}.{file_format}"
            if file_format == "json":
                export_archive_json(path, active_server_id, profile.name, selected_date, events)
            elif file_format == "csv":
                export_archive_csv(path, events)
            elif file_format == "pdf":
                export_archive_pdf(path, profile.name, selected_date, events)
            else:
                raise ArchiveError("Format ekspor tidak dikenal.")
            _save_archive_preferences()
            try:
                store.add_event("EXPORT", session["username"], "server-event-archive", {"format": file_format, "date_filter_utc": selected_date or "all", "event_count": len(events), "file_name": path.name, "storage_mode": "device"})
            except ChainLogError:
                pass
            set_notice(f"Ekspor {file_format.upper()} selesai · {len(events)} event · {path}", "good")
            archive_status_text.value = f"File tersimpan: {path}"
            archive_status_text.color = C["green"]
            page.update()
        except (ArchiveError, OSError, ValueError, sqlite3.Error) as exc:
            archive_status_text.value = f"Ekspor arsip gagal: {exc}"
            archive_status_text.color = C["red"]
            page.update()
            set_notice(f"Ekspor arsip gagal: {exc}", "danger")

    async def download_server_archive(_: ft.ControlEvent | None = None) -> None:
        """One-way migration: copy history that an older version stored on the user's own server back to this device."""
        try:
            if not active_server_id:
                raise ArchiveError("Pilih profile log sumber terlebih dahulu.")
            destination = server_registry_store.get(str(archive_preferences.get("destination_profile_id") or ""))
            if not destination or destination.settings.connector_type != "kawal_trace_api":
                raise ArchiveError("Profile server arsip lama tidak ditemukan. Pilih/buat ulang profile Kawal Trace API yang dulu dipakai.")
            token = await _load_device_token(destination.profile_id)
            if not token:
                raise ArchiveError("Token perangkat/audit untuk server arsip lama belum tersedia. Hubungkan dan setujui profile itu terlebih dahulu.")
            client = ServerArchiveRemoteClient(destination.settings.base_url, destination.settings.device_id, token)
            remote_events = await asyncio.to_thread(client.fetch_all, active_server_id, None)
            existing = {str(item.get("event_id", "")) for item in server_event_archive.list_events(active_server_id, "all")}
            additions = []
            for event in remote_events:
                clean = dict(event)
                clean.pop("event_date_utc", None)
                clean.pop("archived_at_utc", None)
                if str(clean.get("event_id", "")) not in existing:
                    additions.append(clean)
            source = server_registry_store.get(active_server_id)
            added = server_event_archive.add_events(active_server_id, source.name if source else active_server_id, additions) if additions else 0
            refresh_archive_view()
            archive_status_text.value = (f"Arsip lama diambil dari server: {len(remote_events)} dibaca, {added} event baru disalin ke perangkat. "
                                         "Mulai sekarang arsip hanya disimpan di perangkat ini.")
            archive_status_text.color = C["green"]
            page.update()
            set_notice(archive_status_text.value, "good")
        except (ArchiveError, SyncError, OSError, ValueError, sqlite3.Error) as exc:
            archive_status_text.value = f"Pengambilan arsip lama gagal: {exc}"
            archive_status_text.color = C["red"]
            page.update()
            set_notice(archive_status_text.value, "warning")

    async def _load_response_token() -> str:
        if secure_storage is None or not active_server_id:
            return ""
        try:
            value = await secure_storage.get(_profile_secret_key("response_token"))
            return value.strip() if isinstance(value, str) else ""
        except Exception:
            return ""

    def toggle_manual_token_fields() -> None:
        nonlocal manual_token_fields_visible
        manual_token_fields_visible = not manual_token_fields_visible
        sync_token_field.visible = manual_token_fields_visible
        monitor_token_field.visible = manual_token_fields_visible or (connector_type_dropdown.value == "generic_rest_readonly" and feed_auth_mode_dropdown.value != "none")
        response_token_field.visible = manual_token_fields_visible
        manual_token_toggle_button.content = (
            "Sembunyikan token manual" if manual_token_fields_visible else "Pengaturan token manual (legacy)"
        )
        page.update()

    async def _load_admin_token() -> str:
        if secure_storage is None or not active_server_id:
            return ""
        try:
            value = await secure_storage.get(_profile_secret_key("admin_token"))
            return value.strip() if isinstance(value, str) else ""
        except Exception:
            return ""

    async def _get_or_create_claim_secret() -> str:
        """Persist a claim proof per Device ID + server URL, independent of profile IDs.

        Removing/recreating a server profile must not invalidate the enrollment proof
        for the same installation, otherwise the API rejects it as a mismatched claim.
        """
        if secure_storage is None or not active_server_id:
            raise SyncConfigError("Secure Storage native tidak tersedia; pendaftaran anggota otomatis dinonaktifkan.")
        settings = current_server_settings()
        normalized_base = (settings.base_url or "").strip().rstrip("/").lower()
        device_id = (settings.device_id or "").strip()
        if not normalized_base or not device_id:
            raise SyncConfigError("Base URL dan Device ID wajib tersedia sebelum pendaftaran anggota.")
        fingerprint = hashlib.sha256(f"{normalized_base}\n{device_id}".encode("utf-8")).hexdigest()[:32]
        key = f"kawal_trace_claim_secret:{fingerprint}"
        try:
            existing = await secure_storage.get(key)
        except Exception:
            existing = None
        if isinstance(existing, str) and len(existing) >= 43 and not any(c.isspace() for c in existing):
            return existing.strip()
        fresh = secrets.token_urlsafe(48)
        await secure_storage.set(key, fresh)
        return fresh

    async def _membership_http(method: str, path: str, *, payload: dict[str, Any] | None = None,
                               admin: bool = False) -> tuple[int, dict[str, Any]]:
        if httpx is None:
            raise SyncConfigError("HTTP client belum tersedia. Pasang dependency httpx terlebih dahulu.")
        settings = current_server_settings()
        base = (settings.base_url or "").strip().rstrip("/")
        if not base:
            raise SyncConfigError("Isi Base URL HTTPS dan simpan profil terlebih dahulu.")
        headers = {"Accept": "application/json"}
        if admin:
            admin_token = (admin_token_field.value or "").strip() or await _load_admin_token()
            if len(admin_token) < 48 or any(c.isspace() for c in admin_token):
                raise SyncConfigError("Token administrator belum disimpan atau formatnya tidak valid.")
            headers["Authorization"] = f"Bearer {admin_token}"
        # Give the UI a readable connection error instead of allowing httpx
        # ConnectTimeout/RequestError to escape as an unhandled Flet traceback.
        try:
            timeout = httpx.Timeout(12.0, connect=5.0)
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=True) as client:
                response = await client.request(method, base + path, json=payload, headers=headers)
        except httpx.TimeoutException as exc:
            raise SyncConfigError(
                "Koneksi ke server timeout sebelum menerima respons. Periksa Base URL HTTPS "
                "Cloudflare yang terbaru dan pastikan terminal cloudflared tetap berjalan."
            ) from exc
        except httpx.RequestError as exc:
            raise SyncConfigError(
                "Tidak dapat menjangkau server. Periksa URL HTTPS, DNS/jaringan, dan status tunnel Cloudflare."
            ) from exc
        try:
            body = response.json()
        except Exception:
            body = {"error": f"server_returned_non_json_http_{response.status_code}"}
        if not isinstance(body, dict):
            body = {"error": "invalid_server_response"}
        return response.status_code, body

    async def _request_or_claim_current_device() -> bool:
        """Register this install, then fetch server-issued credentials only after approval."""
        settings = current_server_settings()
        device_id = settings.device_id
        claim_secret = await _get_or_create_claim_secret()
        status_code, request_body = await _membership_http(
            "POST", "/api/v1/enrollment/request",
            payload={"device_id": device_id, "claim_secret": claim_secret,
                     "display_name": (server_name_field.value or "Kawal Trace device")[:100]},
        )
        status = str(request_body.get("status", ""))
        if status_code not in {200, 202}:
            raise SyncConfigError(f"Permintaan akses gagal: {request_body.get('message') or request_body.get('error') or status_code}")
        if status != "ACTIVE":
            membership_status_text.value = f"MENUNGGU PERSETUJUAN · Device ID {device_id} · pemilik server harus menambahkan ID ini"
            membership_status_text.color = C["amber"]
            sync_status_text.value = membership_status_text.value
            sync_status_text.color = C["amber"]
            page.update()
            return False
        claim_code, credentials = await _membership_http(
            "POST", "/api/v1/enrollment/claim",
            payload={"device_id": device_id, "claim_secret": claim_secret},
        )
        if claim_code != 200:
            if claim_code == 202:
                membership_status_text.value = "MENUNGGU PERSETUJUAN PEMILIK SERVER"
                membership_status_text.color = C["amber"]
                page.update()
                return False
            raise SyncConfigError(f"Pengambilan akses gagal: {credentials.get('error') or claim_code}")
        if str(credentials.get("device_id", "")) != device_id:
            raise SyncConfigError("Server mengembalikan Device ID yang tidak cocok.")
        if secure_storage is None or not active_server_id:
            raise SyncConfigError("Secure Storage tidak tersedia; token tidak disimpan.")
        await secure_storage.set(_profile_secret_key("device_token"), str(credentials.get("device_token", "")))
        await secure_storage.set(_profile_secret_key("monitor_token"), str(credentials.get("monitor_token", "")))
        await secure_storage.set(_profile_secret_key("response_token"), str(credentials.get("response_token", "")))
        try:
            store.add_event("AUTH", session["username"], "server-enrollment",
                            {"action": "device_activated", "result": "success", "device_id": device_id,
                             "platform": session.get("platform", "unknown")})
        except ChainLogError:
            pass
        totp_seed = str(credentials.get("response_totp_secret", ""))
        if totp_seed:
            await secure_storage.set(_profile_secret_key("response_totp_seed"), totp_seed)
            member_totp_seed_field.value = totp_seed
            member_totp_seed_field.visible = True
        sync_token_field.value = ""
        monitor_token_field.value = ""
        response_token_field.value = ""
        membership_status_text.value = f"ANGGOTA AKTIF · kredensial diterima otomatis untuk {device_id}"
        membership_status_text.color = C["green"]
        sync_status_text.value = "KREDENSIAL ANGGOTA DITERIMA · klik Hubungkan untuk memulai feed/sinkronisasi"
        sync_status_text.color = C["green"]
        page.update()
        set_notice("Akses server disetujui; token disimpan di secure storage perangkat.", "good")
        return True

    async def _watch_for_membership_approval() -> None:
        """While the app is open, automatically claim credentials after the owner approves."""
        nonlocal enrollment_poll_task
        try:
            for _ in range(60):  # bounded: up to five minutes, one check every five seconds
                await asyncio.sleep(5)
                try:
                    ready = await _request_or_claim_current_device()
                except Exception:
                    # Transient network/server failures do not destroy the pending request.
                    continue
                if ready:
                    set_notice("Server menyetujui perangkat ini; menghubungkan otomatis…", "good")
                    await connect_selected_server()
                    return
            membership_status_text.value = "PERMINTAAN MASIH MENUNGGU · tekan Minta Akses lagi untuk mencoba kembali"
            membership_status_text.color = C["amber"]
            page.update()
        finally:
            enrollment_poll_task = None

    def _start_enrollment_poll() -> None:
        nonlocal enrollment_poll_task
        if enrollment_poll_task is None or enrollment_poll_task.done():
            enrollment_poll_task = asyncio.create_task(_watch_for_membership_approval())

    async def request_current_device_access(_: ft.ControlEvent | None = None) -> None:
        if not await save_sync_config():
            return
        try:
            ready = await _request_or_claim_current_device()
            if not ready:
                _start_enrollment_poll()
                set_notice("Permintaan akses terkirim. Aplikasi akan terhubung otomatis setelah pemilik menyetujui ID ini.", "warning")
        except Exception as exc:
            membership_status_text.value = f"PENDAFTARAN GAGAL · {exc}"
            membership_status_text.color = C["red"]
            page.update()
            set_notice("Pendaftaran anggota gagal.", "danger")

    @requires_step_up("menyimpan token administrator server")
    async def save_admin_token_click(_: ft.ControlEvent | None = None) -> None:
        token = (admin_token_field.value or "").strip()
        if secure_storage is None or not active_server_id:
            set_notice("Simpan profil server dan pastikan Secure Storage tersedia dahulu.", "danger")
            return
        if len(token) < 48 or any(c.isspace() for c in token):
            set_notice("Token administrator minimal 48 karakter tanpa spasi.", "danger")
            return
        try:
            await secure_storage.set(_profile_secret_key("admin_token"), token)
            admin_token_field.value = ""
            membership_status_text.value = "TOKEN ADMINISTRATOR TERSIMPAN AMAN DI PERANGKAT INI"
            membership_status_text.color = C["green"]
            page.update()
            set_notice("Token administrator disimpan di secure storage.", "good")
        except Exception as exc:
            set_notice(f"Token administrator gagal disimpan: {exc}", "danger")

    async def refresh_member_list_click(_: ft.ControlEvent | None = None) -> None:
        try:
            status_code, body = await _membership_http("GET", "/api/v1/admin/members", admin=True)
            if status_code != 200:
                raise SyncConfigError(f"Gagal mengambil daftar anggota: {body.get('error') or status_code}")
            rows = body.get("members", [])
            membership_list.controls.clear()
            for item in rows if isinstance(rows, list) else []:
                did = str(item.get("device_id", ""))
                state = str(item.get("status", "UNKNOWN"))
                color = C["green"] if state == "ACTIVE" else C["red"] if state == "REVOKED" else C["amber"]
                controls: list[Any] = [
                    ft.Column(controls=[
                        ft.Text(f"{did} · {state}", size=11, weight=ft.FontWeight.BOLD, color=color, selectable=True),
                        ft.Text(str(item.get("display_name", "")), size=10, color=C["muted"], selectable=True),
                    ], spacing=2, expand=True)
                ]
                if state in {"PENDING", "REVOKED"}:
                    controls.append(ft.OutlinedButton(
                        content="Setujui", on_click=lambda e, device_id=did: asyncio.create_task(approve_member_id(device_id)),
                        disabled=session["role"] != "admin",
                    ))
                if state == "ACTIVE":
                    controls.append(ft.OutlinedButton(
                        content="Keluarkan", on_click=lambda e, device_id=did: asyncio.create_task(revoke_member_id(device_id)),
                        disabled=session["role"] != "admin",
                    ))
                membership_list.controls.append(ft.Container(
                    content=ft.Row(controls=controls, spacing=8), padding=8,
                    border=ft.Border.all(1, C["line"]), border_radius=8,
                ))
            if not membership_list.controls:
                membership_list.controls.append(ft.Text("Belum ada anggota atau permintaan akses.", size=10, color=C["muted"]))
            membership_status_text.value = f"DAFTAR ANGGOTA SERVER · {len(rows)} perangkat"
            membership_status_text.color = C["green"]
            page.update()
        except Exception as exc:
            membership_status_text.value = f"GAGAL MEMUAT ANGGOTA · {exc}"
            membership_status_text.color = C["red"]
            page.update()

    async def approve_member_id(device_id: str) -> None:
        if session["role"] != "admin":
            set_notice("Hanya administrator aplikasi yang bisa mengelola anggota server.", "danger")
            return
        try:
            status_code, body = await _membership_http(
                "POST", "/api/v1/admin/members",
                payload={"device_id": device_id, "display_name": device_id}, admin=True,
            )
            if status_code not in {200, 201}:
                raise SyncConfigError(body.get("message") or body.get("error") or f"HTTP {status_code}")
            membership_status_text.value = f"ANGGOTA DISETUJUI · {device_id}"
            membership_status_text.color = C["green"]
            page.update()
            await refresh_member_list_click()
            set_notice("Anggota server disetujui. Perangkat anggota dapat mengambil token otomatis.", "good")
        except Exception as exc:
            membership_status_text.value = f"GAGAL MENAMBAHKAN ANGGOTA · {exc}"
            membership_status_text.color = C["red"]
            page.update()
            set_notice("Penambahan anggota gagal.", "danger")

    async def add_member_click(_: ft.ControlEvent | None = None) -> None:
        device_id = (member_device_id_field.value or "").strip()
        if not device_id:
            set_notice("Isi Device ID anggota yang sudah mengirim permintaan akses.", "warning")
            return
        await approve_member_id(device_id)

    async def revoke_member_id(device_id: str) -> None:
        if session["role"] != "admin":
            set_notice("Hanya administrator aplikasi yang bisa mencabut anggota server.", "danger")
            return
        try:
            status_code, body = await _membership_http(
                "DELETE", f"/api/v1/admin/members/{device_id}", admin=True,
            )
            if status_code != 200:
                raise SyncConfigError(body.get("error") or f"HTTP {status_code}")
            membership_status_text.value = f"AKSES DICABUT · {device_id} · token lama ditolak server"
            membership_status_text.color = C["amber"]
            page.update()
            await refresh_member_list_click()
            set_notice("Akses anggota dicabut di server.", "good")
        except Exception as exc:
            membership_status_text.value = f"GAGAL MENGELUARKAN ANGGOTA · {exc}"
            membership_status_text.color = C["red"]
            page.update()
            set_notice("Pencabutan anggota gagal.", "danger")

    # ------------------------------------------------------------------ Build 14 Trusted Access handlers
    async def create_local_invitation_click(_: ft.ControlEvent | None = None) -> None:
        if session["role"] != "admin":
            set_notice("Hanya administrator yang dapat membuat undangan anggota.", "danger")
            return
        name = (invite_name_field.value or "").strip()
        email = (invite_email_field.value or "").strip()
        role = (invite_role_dropdown.value or "member").strip()
        if not name:
            set_notice("Isi nama anggota terlebih dahulu.", "warning")
            return
        try:
            member, inv = await asyncio.to_thread(
                trusted_access_store.create_invitation, name, email, role, 72
            )
            invite_code_display.value = inv.invite_code
            invite_code_display.visible = True
            local_trusted_status.value = (
                f"UNDANGAN DIBUAT · {member.display_name} · status {member.status} · "
                f"kode berlaku sampai {inv.expires_at_utc}"
            )
            local_trusted_status.color = C["green"]
            invite_name_field.value = ""
            invite_email_field.value = ""
            page.update()
            await refresh_local_trusted_click()
            set_notice(
                f"Undangan dibuat. Berikan kode ke {name} melalui saluran aman. "
                "Anggota harus memverifikasi kode di perangkatnya.",
                "good",
            )
        except TrustedAccessError as exc:
            local_trusted_status.value = f"GAGAL MEMBUAT UNDANGAN · {exc}"
            local_trusted_status.color = C["red"]
            page.update()
            set_notice(str(exc), "danger")
        except Exception as exc:
            local_trusted_status.value = f"GAGAL MEMBUAT UNDANGAN · {exc}"
            local_trusted_status.color = C["red"]
            page.update()
            set_notice("Pembuatan undangan gagal.", "danger")

    async def refresh_local_trusted_click(_: ft.ControlEvent | None = None) -> None:
        try:
            members = await asyncio.to_thread(trusted_access_store.list_members)
            devices = await asyncio.to_thread(trusted_access_store.list_devices)
            local_trusted_list.controls.clear()
            if not members:
                local_trusted_list.controls.append(
                    ft.Text("Belum ada anggota lokal. Buat undangan terlebih dahulu.", size=10, color=C["muted"])
                )
            else:
                device_by_member: dict[str, list] = {}
                for d in devices:
                    device_by_member.setdefault(d.member_id, []).append(d)
                for m in members:
                    color = C["green"] if m.status == "ACTIVE" else C["red"] if m.status == "REVOKED" else C["amber"]
                    devs = device_by_member.get(m.member_id, [])
                    dev_txt = ", ".join(f"{d.device_id[:12]}… ({d.platform}/{d.status})" for d in devs) if devs else "belum ada perangkat"
                    row_controls: list = [
                        ft.Column(controls=[
                            ft.Text(f"{m.display_name} · {m.status}", size=11, weight=ft.FontWeight.BOLD, color=color, selectable=True),
                            ft.Text(f"{m.email or '—'} · peran {m.role}", size=10, color=C["muted"], selectable=True),
                            ft.Text(f"Perangkat: {dev_txt}", size=10, color=C["quiet"], selectable=True),
                        ], spacing=2, expand=True)
                    ]
                    if m.status != "REVOKED" and session["role"] == "admin":
                        row_controls.append(
                            ft.OutlinedButton(
                                content="Cabut",
                                on_click=lambda e, mid=m.member_id: asyncio.create_task(revoke_local_member_click(mid)),
                            )
                        )
                    local_trusted_list.controls.append(
                        ft.Container(
                            content=ft.Row(controls=row_controls, spacing=8),
                            padding=8, border=ft.Border.all(1, C["line"]), border_radius=8,
                        )
                    )
            summary = await asyncio.to_thread(trusted_access_store.summarize)
            local_trusted_status.value = (
                f"TRUSTED ACCESS LOKAL · anggota {summary.get('members', {})} · "
                f"perangkat {summary.get('devices', {})}"
            )
            local_trusted_status.color = C["green"]
            page.update()
        except Exception as exc:
            local_trusted_status.value = f"GAGAL MEMUAT TRUSTED ACCESS · {exc}"
            local_trusted_status.color = C["red"]
            page.update()

    async def revoke_local_member_click(member_id: str) -> None:
        if session["role"] != "admin":
            set_notice("Hanya administrator yang dapat mencabut anggota.", "danger")
            return
        try:
            member = await asyncio.to_thread(trusted_access_store.revoke_member, member_id)
            local_trusted_status.value = f"ANGGOTA DICABUT · {member.display_name}"
            local_trusted_status.color = C["amber"]
            page.update()
            await refresh_local_trusted_click()
            set_notice(f"Akses lokal {member.display_name} dicabut (termasuk perangkatnya).", "good")
        except Exception as exc:
            local_trusted_status.value = f"GAGAL MENCABUT · {exc}"
            local_trusted_status.color = C["red"]
            page.update()
            set_notice("Pencabutan lokal gagal.", "danger")

    async def refresh_incident_list_click(_: ft.ControlEvent | None = None) -> None:
        try:
            records = await asyncio.to_thread(trusted_access_store.list_incidents, 50)
            incident_list.controls.clear()
            if not records:
                incident_list.controls.append(
                    ft.Text("Belum ada insiden tercatat.", size=10, color=C["muted"])
                )
            else:
                for rec in records:
                    color = (
                        C["red"] if rec.classification in {"INTRUDER", "SUSPICIOUS"}
                        else C["amber"] if rec.classification == "UNKNOWN"
                        else C["green"]
                    )
                    actions = ", ".join(rec.actions_taken) if rec.actions_taken else "—"
                    incident_list.controls.append(
                        ft.Container(
                            content=ft.Column(controls=[
                                ft.Text(
                                    f"{rec.classification} · {rec.detected_at_utc}",
                                    size=11, weight=ft.FontWeight.BOLD, color=color, selectable=True,
                                ),
                                ft.Text(
                                    f"IP {rec.source_ip or '—'} · akun {rec.account or '—'} · "
                                    f"device {rec.device_id or '—'} · sesi {rec.session_id or '—'}",
                                    size=10, color=C["muted"], selectable=True,
                                ),
                                ft.Text(f"Alasan: {rec.reason}", size=10, color=C["quiet"], selectable=True),
                                ft.Text(f"Tindakan: {actions} · hasil: {rec.outcome or '—'}", size=10, color=C["quiet"], selectable=True),
                            ], spacing=2),
                            padding=8, border=ft.Border.all(1, C["line"]), border_radius=8,
                        )
                    )
            incident_status_text.value = f"RIWAYAT INSIDEN · {len(records)} catatan terakhir"
            incident_status_text.color = C["green"]
            page.update()
        except Exception as exc:
            incident_status_text.value = f"GAGAL MEMUAT INSIDEN · {exc}"
            incident_status_text.color = C["red"]
            page.update()

    async def record_test_incident_click(_: ft.ControlEvent | None = None) -> None:
        """Catat insiden uji (bukan aksi live) agar alur Incident History bisa diverifikasi."""
        if session["role"] != "admin":
            set_notice("Hanya administrator yang dapat mencatat insiden uji.", "danger")
            return
        try:
            rec = await asyncio.to_thread(
                trusted_access_store.record_incident,
                "203.0.113.50",
                "unknown",
                "",
                "test-session",
                "INTRUDER",
                "Uji pencatatan insiden dari dashboard (bukan force-disconnect live)",
                ["record_only"],
                "recorded",
                {"test": True, "source": "dashboard"},
            )
            incident_status_text.value = f"INSIDEN UJI TERCATAT · {rec.incident_id}"
            incident_status_text.color = C["green"]
            page.update()
            await refresh_incident_list_click()
            set_notice("Insiden uji dicatat. Force-disconnect live memerlukan response worker + allow-list.", "good")
        except Exception as exc:
            incident_status_text.value = f"GAGAL MENCATAT INSIDEN UJI · {exc}"
            incident_status_text.color = C["red"]
            page.update()
            set_notice("Pencatatan insiden uji gagal.", "danger")

    E2EE_PRIVATE_STORAGE_KEY = "kawal_trace_e2ee_private_key_v1"

    async def _load_e2ee_private_key() -> str:
        if secure_storage is None:
            return ""
        try:
            value = await secure_storage.get(E2EE_PRIVATE_STORAGE_KEY)
            return value.strip() if isinstance(value, str) else ""
        except Exception:
            return ""

    async def refresh_e2ee_public_key(_: ft.ControlEvent | None = None) -> str:
        private_key = await _load_e2ee_private_key()
        if not private_key:
            e2ee_public_key_field.value = "Belum dibuat"
            e2ee_status_text.value = "E2EE BELUM DIKONFIGURASI · buat keypair di dashboard ini"
            e2ee_status_text.color = C["amber"]
            page.update()
            return ""
        try:
            public_key = public_from_private(private_key)
            e2ee_public_key_field.value = public_key
            e2ee_status_text.value = "E2EE KEYPAIR TERSEDIA · kunci privat disimpan di Secure Storage OS"
            e2ee_status_text.color = C["green"]
            page.update()
            return public_key
        except E2EEError as exc:
            e2ee_status_text.value = f"KUNCI E2EE TIDAK VALID · {exc}"
            e2ee_status_text.color = C["red"]
            page.update()
            return ""

    @requires_step_up("membuat kunci enkripsi baru")
    async def generate_e2ee_keypair_click(_: ft.ControlEvent | None = None) -> None:
        if session["role"] != "admin":
            set_notice("Hanya admin lokal yang dapat mengganti kunci E2EE.", "danger")
            return
        if secure_storage is None:
            set_notice("Secure Storage native tidak tersedia; kunci privat tidak akan ditulis ke file plaintext.", "danger")
            return
        try:
            existing = await _load_e2ee_private_key()
            if existing:
                set_notice("Kunci E2EE sudah ada. Export backup terlebih dahulu; pembuatan kunci baru memutus akses ke feed lama.", "warning")
                return
            pair = generate_keypair()
            await secure_storage.set(E2EE_PRIVATE_STORAGE_KEY, pair["private_key_b64"])
            e2ee_public_key_field.value = pair["public_key_b64"]
            e2ee_status_text.value = "KEYPAIR DIBUAT · kirim public key ke server/agen; jangan bagikan private key"
            e2ee_status_text.color = C["green"]
            store.add_event("CONFIG", session["username"], "e2ee", {"action": "receiver_key_generated", "algorithm": "X25519-HKDF-SHA256-AES-256-GCM"})
            page.update()
            set_notice("Kunci E2EE dibuat dan private key disimpan melalui Secure Storage.", "good")
        except Exception as exc:
            e2ee_status_text.value = f"GAGAL MEMBUAT KEYPAIR · {type(exc).__name__}"
            e2ee_status_text.color = C["red"]
            page.update()

    @requires_step_up("mengekspor cadangan kunci pribadi")
    async def export_e2ee_key_backup(_: ft.ControlEvent | None = None) -> None:
        """Create an encrypted E2EE backup, show it, and offer an actual file save/download."""
        if session["role"] != "admin":
            set_notice("Hanya administrator lokal yang dapat mengekspor backup kunci E2EE.", "danger")
            return

        passphrase = e2ee_backup_passphrase_field.value or ""
        if len(passphrase) < 14:
            message = "Frasa sandi backup wajib minimal 14 karakter. JSON backup belum dibuat."
            e2ee_status_text.value = message
            e2ee_status_text.color = C["red"]
            page.update()
            set_notice(message, "danger")
            return

        try:
            private_key = await _load_e2ee_private_key()
            if not private_key:
                message = "Kunci privat E2EE tidak ditemukan di Secure Storage OS. Buat atau impor keypair dahulu."
                e2ee_status_text.value = message
                e2ee_status_text.color = C["red"]
                page.update()
                set_notice(message, "danger")
                return

            backup = export_private_key_backup(private_key, passphrase)
            backup_json = json.dumps(backup, ensure_ascii=False, indent=2) + "\n"
            # Show the encrypted JSON first so the user can copy it even if a file dialog
            # is unavailable or cancelled on the current platform.
            e2ee_backup_json_field.value = backup_json
            e2ee_status_text.value = (
                "BACKUP TERENKRIPSI DIBUAT · JSON ditampilkan di kolom backup; "
                "sedang membuka dialog simpan file. Simpan file dan frasa sandi secara terpisah."
            )
            e2ee_status_text.color = C["green"]
            page.update()
            set_notice("Backup terenkripsi berhasil dibuat. Pilih lokasi untuk menyimpan file JSON.", "good")

            filename = "kawal-trace-e2ee-key-backup-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"
            try:
                saved_path = await folder_picker.save_file(
                    dialog_title="Simpan backup kunci E2EE terenkripsi",
                    file_name=filename,
                    file_type=ft.FilePickerFileType.CUSTOM,
                    allowed_extensions=["json"],
                    src_bytes=backup_json.encode("utf-8"),
                )
                if saved_path:
                    e2ee_status_text.value = f"BACKUP FILE TERSIMPAN · {saved_path} · simpan frasa sandi secara terpisah"
                    e2ee_status_text.color = C["green"]
                    set_notice("Backup E2EE tersimpan sebagai file JSON. Simpan frasa sandi di tempat terpisah.", "good")
                else:
                    e2ee_status_text.value = (
                        "BACKUP TERENKRIPSI SUDAH DIBUAT · dialog simpan dibatalkan. "
                        "JSON masih ada di kolom backup; salin dan simpan secara aman."
                    )
                    e2ee_status_text.color = C["amber"]
                    set_notice("Dialog simpan dibatalkan; JSON backup tetap tersedia di kolom backup.", "warning")
                page.update()
            except Exception as save_exc:
                # Preserve the JSON in the visible field and state clearly that no file
                # was confirmed as saved; never claim a successful file export.
                e2ee_status_text.value = (
                    "BACKUP TERENKRIPSI DIBUAT, FILE BELUM TERSIMPAN · "
                    "JSON tetap ada di kolom backup. Salin secara manual atau coba lagi. "
                    f"Alasan dialog file: {type(save_exc).__name__}"
                )
                e2ee_status_text.color = C["amber"]
                page.update()
                set_notice("JSON backup dibuat, tetapi dialog penyimpanan gagal. Salin JSON dari kolom backup.", "warning")
        except E2EEError as exc:
            message = f"Ekspor backup E2EE gagal: {exc}"
            e2ee_status_text.value = message
            e2ee_status_text.color = C["red"]
            page.update()
            set_notice(message, "danger")
        except Exception as exc:
            message = f"Ekspor backup E2EE gagal ({type(exc).__name__}). Periksa Secure Storage dan log aplikasi."
            e2ee_status_text.value = message
            e2ee_status_text.color = C["red"]
            page.update()
            set_notice(message, "danger")

    @requires_step_up("mengimpor kunci pribadi")
    async def import_e2ee_key_backup(_: ft.ControlEvent | None = None) -> None:
        if secure_storage is None:
            set_notice("Secure Storage native tidak tersedia.", "danger")
            return
        try:
            backup = json.loads(e2ee_backup_json_field.value or "{}")
            private_key = import_private_key_backup(backup, e2ee_backup_passphrase_field.value or "")
            public_key = public_from_private(private_key)
            await secure_storage.set(E2EE_PRIVATE_STORAGE_KEY, private_key)
            e2ee_public_key_field.value = public_key
            e2ee_status_text.value = "KEY E2EE DIIMPOR · public key harus cocok dengan key yang digunakan server/agen"
            e2ee_status_text.color = C["green"]
            store.add_event("CONFIG", session["username"], "e2ee", {"action": "receiver_key_backup_imported", "algorithm": "X25519-HKDF-SHA256-AES-256-GCM"})
            page.update()
            set_notice("Backup E2EE berhasil diimpor ke Secure Storage.", "good")
        except (ValueError, TypeError, E2EEError) as exc:
            set_notice(f"Backup E2EE gagal diimpor: {exc}", "danger")


    async def _play_security_alarm() -> bool:
        """Play a local alarm for a new high/critical event while the app is open."""
        if not security_alarm_enabled:
            return False
        if security_alarm_audio is not None:
            try:
                await security_alarm_audio.play()
                return True
            except Exception:
                pass
        # Standard-library fallback for Windows desktop. It is non-blocking for the UI.
        try:
            import winsound
            def _beep_pattern() -> None:
                winsound.Beep(1450, 420)
                winsound.Beep(980, 420)
                winsound.Beep(1450, 420)
            await asyncio.to_thread(_beep_pattern)
            return True
        except Exception:
            # On platforms without the audio extension, OS notifications remain the fallback.
            return False

    async def test_security_alarm_sound(_: ft.ControlEvent | None = None) -> None:
        ok = await _play_security_alarm()
        if ok:
            notification_status_text.value = "ALARM SUARA BERHASIL DIUJI · suara lokal saat aplikasi berjalan"
            notification_status_text.color = C["green"]
            wizard_notification_status_text.value = "ALARM SUARA OK · notifikasi sistem diuji terpisah"
            wizard_notification_status_text.color = C["green"]
            set_notice("Alarm suara lokal diuji.", "good")
        else:
            notification_status_text.value = "ALARM SUARA BELUM TERSEDIA · periksa dependensi flet-audio/build dan volume perangkat"
            notification_status_text.color = C["amber"]
            wizard_notification_status_text.value = "ALARM BELUM TERSEDIA · perlu diuji pada build/perangkat native"
            wizard_notification_status_text.color = C["amber"]
            set_notice("Pemutaran suara tidak tersedia pada runtime ini.", "warning")
        page.update()

    async def enable_native_notifications(_: ft.ControlEvent | None = None) -> None:
        nonlocal native_notifications_enabled
        # Test local sound independently from native notification permission.
        await _play_security_alarm()
        if native_notifications is None:
            notification_status_text.value = "SUARA DIUJI · paket flet-notifications/native bridge tidak tersedia pada runtime ini"
            notification_status_text.color = C["amber"]
            wizard_notification_status_text.value = "NOTIFIKASI SISTEM BELUM TERSEDIA · native bridge tidak terpasang"
            wizard_notification_status_text.color = C["amber"]
            page.update()
            return
        try:
            granted = await native_notifications.request_permissions()
            if not granted:
                native_notifications_enabled = False
                notification_status_text.value = "IZIN NOTIFIKASI DITOLAK · alarm foreground tetap tersedia jika audio aktif"
                notification_status_text.color = C["amber"]
                wizard_notification_status_text.value = "NOTIFIKASI SISTEM DITOLAK OLEH OS"
                wizard_notification_status_text.color = C["amber"]
                page.update()
                return
            native_notifications_enabled = True
            await native_notifications.show(id=780001, title="Kawal Trace", body="Notifikasi keamanan berhasil diuji.")
            notification_status_text.value = "NOTIFIKASI SISTEM AKTIF · alarm lokal memicu pada event BARU HIGH/CRITICAL saat aplikasi berjalan"
            notification_status_text.color = C["green"]
            wizard_notification_status_text.value = "NOTIFIKASI SISTEM AKTIF · uji native berhasil"
            wizard_notification_status_text.color = C["green"]
            page.update()
            set_notice("Izin notifikasi diberikan; notifikasi dan alarm lokal diuji.", "good")
        except Exception as exc:
            notification_status_text.value = f"NOTIFIKASI BELUM TERSEDIA · {type(exc).__name__}: {str(exc)[:120]}"
            notification_status_text.color = C["amber"]
            wizard_notification_status_text.value = f"NOTIFIKASI GAGAL · {type(exc).__name__}"
            wizard_notification_status_text.color = C["amber"]
            page.update()

    async def _notify_new_security_alerts(events: list[dict[str, Any]]) -> None:
        """Baseline first read; sound and notify only for newly observed high/critical alerts."""
        if not active_server_id or not events:
            return
        profile_id = active_server_id
        new_ids = find_new_event_ids(
            profile_id, events, feed_seen_event_ids, feed_profile_initialized,
            now_epoch=datetime.now(timezone.utc).timestamp(),
        )
        if not new_ids:
            return
        try:
            alerts = DetectionEngine(
                auth_failure_threshold=DEFAULT_AUTH_FAILURE_THRESHOLD,
                window_seconds=DEFAULT_AUTH_FAILURE_WINDOW_SECONDS,
            ).evaluate(events)
        except (ValueError, TypeError):
            return
        epoch_by_id = {str(e.get("event_id", "")): float(e.get("timestamp_epoch", 0) or 0) for e in events}
        emitted = 0
        for alert in alerts:
            if alert.severity not in {"HIGH", "CRITICAL"} or not (set(alert.event_ids) & new_ids):
                continue
            if alert.rule_id == "AUTH_FAILURE_BURST":
                newest_epoch = max((epoch_by_id.get(eid, 0.0) for eid in alert.event_ids), default=0.0)
                dedupe_bucket = int(newest_epoch // DEFAULT_AUTH_FAILURE_WINDOW_SECONDS)
                key = f"{profile_id}:{alert.rule_id}:{alert.host_id}:{alert.source_ip}:{dedupe_bucket}"
            else:
                key = f"{profile_id}:{alert.rule_id}:{alert.host_id}:{alert.source_ip}:{alert.event_ids[-1] if alert.event_ids else alert.created_at_utc}"
            if key in notified_alert_keys:
                continue
            notified_alert_keys.add(key)
            await _play_security_alarm()
            note_id = int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:7], 16) or 1
            body = f"{alert.host_id} · IP {alert.source_ip or 'tidak tersedia'} · {alert.title}"
            if native_notifications_enabled and native_notifications is not None:
                try:
                    await native_notifications.show(id=note_id, title=f"Kawal Trace · {alert.severity}", body=body[:220], payload=key[:400])
                except Exception:
                    notification_status_text.value = "NOTIFIKASI SISTEM GAGAL · alarm lokal/feed tetap aktif saat aplikasi berjalan"
                    notification_status_text.color = C["amber"]
                    try:
                        page.update()
                    except Exception:
                        pass
            emitted += 1
            if emitted >= 3:
                break
        if len(notified_alert_keys) > 2000:
            notified_alert_keys.clear()

    def _valid_geo_coordinates(latitude: Any, longitude: Any) -> bool:
        try:
            lat, lon = float(latitude), float(longitude)
        except (TypeError, ValueError):
            return False
        return -90 <= lat <= 90 and -180 <= lon <= 180

    def _render_server_feed(events: list[dict[str, Any]]) -> None:
        nonlocal current_feed_ips, current_feed_ufw_ips, current_feed_windows_auth_ips, current_feed_hosts, latest_server_feed_events
        latest_server_feed_events = [dict(item) for item in events if isinstance(item, dict)]
        now_epoch = datetime.now(timezone.utc).timestamp()

        def _fresh_agent_event(item: dict[str, Any]) -> bool:
            try:
                epoch = float(item.get("timestamp_epoch") or 0)
                if not epoch:
                    stamp = str(item.get("timestamp_utc") or "").replace("Z", "+00:00")
                    epoch = datetime.fromisoformat(stamp).timestamp() if stamp else 0.0
                return 0 < epoch <= now_epoch + 60 and now_epoch - epoch <= 900
            except (TypeError, ValueError, OverflowError):
                return False

        recent_linux_event = any(
            str(item.get("source", "")).lower().startswith(("linux-journal", "linux-auditd", "systemd-journal", "clamav"))
            and _fresh_agent_event(item) for item in latest_server_feed_events
        )
        recent_windows_heartbeat = any(
            str(item.get("source", "")).lower() == "windows-agent"
            and str(item.get("event_type", "")).upper() == "AGENT_HEALTH"
            and _fresh_agent_event(item) for item in latest_server_feed_events
        )
        recent_windows_event = any(
            str(item.get("source", "")).lower() == "windows-eventlog"
            and _fresh_agent_event(item) for item in latest_server_feed_events
        )
        filesystem_health_events = [
            item for item in latest_server_feed_events
            if str(item.get("source", "")).lower() == "linux-agent"
            and str(item.get("event_type", "")).upper() == "AGENT_HEALTH"
            and isinstance(item.get("details"), dict)
            and str(item["details"].get("service", "")).lower() == "filesystem-watch"
            and _fresh_agent_event(item)
        ]
        latest_filesystem_health = max(
            filesystem_health_events,
            key=lambda item: float(item.get("timestamp_epoch") or 0), default=None,
        )
        filesystem_changes = [
            item for item in latest_server_feed_events
            if str(item.get("event_type", "")).upper() == "FILE_CHANGE"
            and str(item.get("source", "")).lower() == "linux-auditd"
            and _fresh_agent_event(item)
        ]
        latest_filesystem_change = max(
            filesystem_changes,
            key=lambda item: float(item.get("timestamp_epoch") or 0), default=None,
        )

        health_is_ready = bool(
            latest_filesystem_health
            and str((latest_filesystem_health.get("details") or {}).get("result", "")).upper() == "READY"
        )
        connector_runtime_state["linux_agent_status"] = "good" if recent_linux_event or health_is_ready else (
            "warn" if latest_filesystem_health else "idle"
        )
        connector_runtime_state["windows_agent_status"] = (
            "good" if recent_windows_heartbeat else ("warn" if recent_windows_event else "idle")
        )

        health_details = (latest_filesystem_health or {}).get("details") or {}
        health_result = str(health_details.get("result", "")).upper()
        health_reason = str(health_details.get("reason", "")).upper()
        reported_root = str(health_details.get("path", "")).strip()
        if reported_root:
            connector_runtime_state["folder_path"] = reported_root
        if latest_filesystem_change and (not latest_filesystem_health or health_result != "READY"):
            change_details = latest_filesystem_change.get("details") or {}
            connector_runtime_state["folder_status"] = "good"
            connector_runtime_state["folder_headline"] = "EVENT PERUBAHAN FILE DITERIMA"
            connector_runtime_state["folder_path"] = str(change_details.get("path") or reported_root or "Path tidak tersedia")
            connector_runtime_state["folder_detail"] = (
                "Event FILE_CHANGE dari auditd sudah diterima. Watch rule terbukti menghasilkan event; "
                "status pemeriksaan konfigurasi agen tetap perlu ditinjau."
            )
        elif latest_filesystem_health:
            connector_runtime_state["folder_path"] = reported_root or "Root belum dilaporkan agen"
            if health_result == "READY":
                connector_runtime_state["folder_status"] = "good"
                connector_runtime_state["folder_headline"] = "PEMANTAUAN SERVER AKTIF OTOMATIS"
                connector_runtime_state["folder_detail"] = (
                    "Linux Server Agent aktif; auditd dan watch rule dilaporkan siap. "
                    "Perubahan file akan masuk ke feed tanpa tombol mulai/hentikan."
                )
            else:
                reason_text = {
                    "WATCH_ROOTS_NOT_CONFIGURED": "Root server belum ditentukan pada konfigurasi agen.",
                    "WATCH_ROOT_MISSING": "Root server tidak ditemukan atau tidak dapat diakses oleh layanan agen.",
                    "AUDIT_LOG_UNAVAILABLE": "Log auditd tidak tersedia atau tidak dapat dibaca oleh agen.",
                    "AUDITD_INACTIVE": "Layanan auditd belum aktif pada server.",
                    "AUDIT_RULE_NOT_ACTIVE": "Watch rule Kawal Trace belum aktif di auditd.",
                    "AUDIT_RULE_STATUS_UNVERIFIED": "Agen belum dapat memverifikasi status watch rule auditd.",
                }.get(health_reason, "Agen belum menyatakan pemantauan file siap.")
                connector_runtime_state["folder_status"] = "warn"
                connector_runtime_state["folder_headline"] = "AGEN TERHUBUNG · PEMANTAUAN BELUM SIAP"
                connector_runtime_state["folder_detail"] = reason_text
        elif latest_filesystem_change:
            change_details = latest_filesystem_change.get("details") or {}
            connector_runtime_state["folder_status"] = "good"
            connector_runtime_state["folder_headline"] = "EVENT PERUBAHAN FILE DITERIMA"
            connector_runtime_state["folder_path"] = str(change_details.get("path") or "Path tidak tersedia")
            connector_runtime_state["folder_detail"] = (
                "Feed menerima event auditd terbaru. Status ini membuktikan event sampai ke aplikasi, "
                "tetapi heartbeat konfigurasi agen belum tersedia."
            )
        elif connected_server_id == active_server_id and active_server_id:
            connector_runtime_state["folder_status"] = "warn"
            connector_runtime_state["folder_headline"] = "MENUNGGU LINUX SERVER AGENT"
            connector_runtime_state["folder_path"] = "Belum ada root server yang dilaporkan"
            connector_runtime_state["folder_detail"] = (
                "Server API terhubung, tetapi belum menerima heartbeat filesystem-watch. "
                "Pastikan Linux Server Agent berjalan dan auditd watch rule telah diaktifkan."
            )
        else:
            connector_runtime_state["folder_status"] = "idle"
            connector_runtime_state["folder_headline"] = "MENUNGGU KONEKSI SERVER"
            connector_runtime_state["folder_path"] = "Belum ada laporan dari Linux Server Agent"
            connector_runtime_state["folder_detail"] = (
                "Hubungkan profil server. Pemantauan server otomatis aktif jika Linux Server Agent dan auditd sudah siap."
            )

        monitor_path_text.value = str(connector_runtime_state.get("folder_path", ""))
        monitor_status_text.value = str(connector_runtime_state.get("folder_headline", ""))
        monitor_status_text.color = {
            "good": C["green"], "warn": C["amber"], "bad": C["red"], "connecting": C["blue"],
        }.get(str(connector_runtime_state.get("folder_status", "idle")), C["muted"])
        monitor_detail_text.value = str(connector_runtime_state.get("folder_detail", ""))
        if latest_filesystem_change:
            change_details = latest_filesystem_change.get("details") or {}
            reason = str(change_details.get("reason") or "file_change").replace("file_", "").replace("_", " ").upper()
            path = str(change_details.get("path") or "path tidak tersedia")
            monitor_last_event_text.value = f"{reason} · {path} · {str(latest_filesystem_change.get('timestamp_utc', ''))[:19]} UTC"
        elif latest_filesystem_health:
            monitor_last_event_text.value = "Belum ada perubahan file; heartbeat konfigurasi agen diterima."
        else:
            monitor_last_event_text.value = "Belum ada event perubahan file dari auditd."
        current_feed_hosts = {str(item.get("host_id", "")).strip() for item in events if str(item.get("host_id", "")).strip()}
        current_feed_ips = set()
        current_feed_ufw_ips = set()
        current_feed_windows_auth_ips = set()
        for item in events:
            try:
                candidate_ip = str(item.get("source_ip") or "")
                parsed_ip = ipaddress.ip_address(candidate_ip) if candidate_ip else None
                if parsed_ip and parsed_ip.version == 4 and parsed_ip.is_global:
                    normalized_ip = str(parsed_ip)
                    current_feed_ips.add(normalized_ip)
                    # UFW response is limited to directly observed SSH auth events.
                    # HTTP visitor addresses behind Cloudflare need a WAF adapter.
                    event_type = str(item.get("event_type", "")).upper()
                    source = str(item.get("source", "")).lower()
                    details = item.get("details") if isinstance(item.get("details"), dict) else {}
                    service = str(details.get("service", "")).lower()
                    auth_method = str(details.get("auth_method", "")).lower()
                    if (event_type in {"AUTH_FAILURE", "AUTH_SUCCESS"}
                            and source in {"linux-journal", "linux-journald", "systemd-journal"}
                            and (auth_method == "ssh" or "ssh" in service)):
                        current_feed_ufw_ips.add(normalized_ip)
                    if event_type == "AUTH_FAILURE" and source == "windows-eventlog":
                        host_key = str(item.get("host_id", "")).strip()
                        if host_key:
                            current_feed_windows_auth_ips.add((host_key, normalized_ip))
            except ValueError:
                pass
        alerts = DetectionEngine(auth_failure_threshold=DEFAULT_AUTH_FAILURE_THRESHOLD, window_seconds=DEFAULT_AUTH_FAILURE_WINDOW_SECONDS).evaluate(events)
        alert_controls: list[ft.Control] = []
        severity_colors = {"CRITICAL": C["red"], "HIGH": C["amber"], "MEDIUM": C["blue"], "LOW": C["muted"]}
        for alert in alerts[:8]:
            alert_controls.append(ft.Container(
                content=ft.Column(controls=[
                    ft.Row(controls=[ft.Text(alert.severity, size=9, color=severity_colors.get(alert.severity, C["red"]), weight=ft.FontWeight.BOLD),
                                     ft.Text(alert.rule_id, size=9, color=C["lime"], font_family="Consolas")], spacing=8),
                    ft.Text(alert.title, size=12, weight=ft.FontWeight.BOLD, color=C["text"]),
                    ft.Text(alert.description, size=10, color=C["muted"], selectable=True),
                    ft.Text(f"HOST {alert.host_id}  ·  SOURCE {alert.source_ip or 'tidak tersedia'}  ·  {alert.created_at_utc}",
                            size=9, color=C["quiet"], font_family="Consolas", selectable=True),
                ], spacing=4), padding=11, bgcolor=C["bg"],
                border=ft.Border.all(1, severity_colors.get(alert.severity, C["line"])), border_radius=8,
            ))
        event_controls: list[ft.Control] = []
        for event in events[:50]:
            details = event.get("details", {})
            path = details.get("path", "")
            reason = details.get("reason", "")
            service = details.get("service", "")
            extra = " · ".join(str(part) for part in (reason, path, service) if part)

            # Show both local time for the operator and UTC for cross-host correlation.
            try:
                parsed_time = datetime.fromisoformat(event["timestamp_utc"].replace("Z", "+00:00"))
                local_time = parsed_time.astimezone().strftime("%d-%m-%Y %H:%M:%S %Z")
                utc_time = parsed_time.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, TypeError, KeyError):
                local_time = "Waktu lokal tidak tersedia"
                utc_time = str(event.get("timestamp_utc", "waktu tidak diketahui"))

            ip_value = event.get("source_ip") or "IP tidak tersedia dari log"
            city_region = ", ".join(part for part in (
                event.get("source_city", ""), event.get("source_region", "")
            ) if part)
            country = event.get("source_country", "")
            geo_parts = [part for part in (city_region, country) if part]
            location_value = ", ".join(geo_parts) if geo_parts else "Belum tersedia dari enrichment GeoIP server"
            geo_source = event.get("source_geo_source", "")
            geo_accuracy = event.get("source_geo_accuracy", "")
            if geo_source or geo_accuracy:
                suffix = " · ".join(part for part in (geo_source, geo_accuracy) if part)
                location_value += f" ({suffix})"

            asn_org = " · ".join(part for part in (
                event.get("source_asn", ""), event.get("source_org", "")
            ) if part)
            hostname = event.get("source_hostname", "")
            os_name = event.get("source_os", "")
            device_type = event.get("source_device_type", "")
            vendor_model = " ".join(part for part in (
                event.get("source_vendor", ""), event.get("source_model", "")
            ) if part)
            device_source = event.get("source_device_source", "")
            user_agent = event.get("source_user_agent", "")
            device_parts = [part for part in (hostname, os_name, device_type, vendor_model) if part]
            device_value = " · ".join(device_parts) if device_parts else "Merek/model tidak dapat ditentukan dari IP saja"
            if device_source:
                device_value += f" · sumber: {device_source}"
            if not vendor_model and user_agent:
                device_value += f" · User-Agent: {user_agent[:140]} (klaim header, bisa dipalsukan)"

            kind = event.get("event_type", "UNKNOWN")
            kind_color = C["red"] if "FAILURE" in kind or kind == "MALWARE_DETECTED" else (C["amber"] if kind in {"FILE_CHANGE", "SERVICE_CHANGE", "PRIVILEGE_USE"} else C["lime"])
            event_controls.append(ft.Container(
                content=ft.Column(controls=[
                    ft.Row(controls=[
                        tag(kind, kind_color, C["panel_lift"]),
                        ft.Text(f"{local_time}", size=10, color=C["text"], weight=ft.FontWeight.BOLD),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, wrap=True),
                    ft.Text(f"UTC {utc_time} · event {event.get('event_id', '')[:16]}…",
                            size=9, color=C["quiet"], font_family="Consolas", selectable=True),
                    ft.Text(f"IP SUMBER  {ip_value}", size=12, color=C["text"], weight=ft.FontWeight.BOLD, selectable=True),
                    ft.Text(f"LOKASI IP (PERKIRAAN)  {location_value}", size=10, color=C["blue"], selectable=True),
                    ft.Text(f"ASN / ORGANISASI  {asn_org or 'Tidak tersedia dari feed'}", size=10, color=C["muted"], selectable=True),
                    ft.Text(f"PERANGKAT  {device_value}", size=10, color=C["muted"], selectable=True),
                    *([ft.TextButton(content="Buka peta GeoIP (perkiraan)", url=f"https://www.openstreetmap.org/?mlat={float(event['source_latitude']):.5f}&mlon={float(event['source_longitude']):.5f}#map=8/{float(event['source_latitude']):.5f}/{float(event['source_longitude']):.5f}")]
                      if _valid_geo_coordinates(event.get("source_latitude"), event.get("source_longitude")) else []),
                    ft.Text(f"HOST SERVER  {event.get('host_id') or 'unknown'} · AKUN  {event.get('actor') or 'unknown'} · SUMBER LOG  {event.get('source') or 'unknown'}",
                            size=10, color=C["text"], selectable=True),
                    ft.Text(f"DETAIL  {extra[:256] if extra else 'Tidak ada detail tambahan'}",
                            size=10, color=C["muted"], selectable=True),
                ], spacing=5), padding=12, bgcolor=C["panel_alt"],
                border=ft.Border.all(1, kind_color if "FAILURE" in kind or kind in {"FILE_CHANGE", "SERVICE_CHANGE"} else C["line"]),
                border_radius=8,
            ))
        server_feed_list.controls = []
        if alerts:
            server_feed_list.controls.append(ft.Text(f"RULE HITS · {len(alerts)}", size=10, color=C["amber"], weight=ft.FontWeight.BOLD))
            server_feed_list.controls.extend(alert_controls)
        else:
            server_feed_list.controls.append(ft.Text("Tidak ada rule hit pada event yang diambil. Ini bukan bukti bahwa server bebas ancaman.", size=10, color=C["muted"]))
        server_feed_list.controls.append(ft.Divider(color=C["line"]))
        server_feed_list.controls.append(ft.Text(f"EVENT TERBARU · {len(events)} diterima · refresh otomatis 5 detik", size=10, color=C["muted"], weight=ft.FontWeight.BOLD))
        server_feed_list.controls.extend(event_controls)
        if not events:
            server_feed_list.controls.append(ft.Text("Feed mengembalikan nol event.", size=10, color=C["muted"]))
        profiles = server_registry_store.list()
        heartbeats = {str(e.get("host_id", "")) for e in events if str(e.get("event_type", "")).upper() == "AGENT_HEALTH" and e.get("host_id")}
        windows_hosts = {str(e.get("host_id", "")) for e in events if str(e.get("source", "")).lower() == "windows-eventlog" and e.get("host_id")}
        linux_hosts = {str(e.get("host_id", "")) for e in events if str(e.get("source", "")).lower().startswith(("linux-", "clamav")) and e.get("host_id")}
        server_feed_fleet_text.value = (f"FLEET · {len(profiles)} profile tersimpan · {len(current_feed_hosts)} host unik pada feed terbaru · "
                                        f"heartbeat {len(heartbeats)} · Windows {len(windows_hosts)} · Linux {len(linux_hosts)} · profile aktif {active_server_id or 'belum dipilih'}")
        server_feed_summary_text.value = f"{len(events)} event dari server · {len(alerts)} rule hit · ambang auth gagal 2 dalam 300 detik. Lokasi IP hanya perkiraan; peta hanya ditampilkan bila GeoIP memberikan koordinat. Merek/model hanya ditampilkan bila tersedia dari agen/inventory."
        try:
            refresh_status_overview()
        except (NameError, UnboundLocalError):
            # Initial feed rendering can occur before the dashboard status panel is mounted.
            pass

    async def refresh_server_feed(_: ft.ControlEvent | None = None, quiet: bool = False) -> None:
        try:
            if not active_server_id or connected_server_id != active_server_id:
                if not quiet:
                    server_feed_status_text.value = "SERVER TERPUTUS · hubungkan profile terlebih dahulu"
                    server_feed_status_text.color = C["amber"]
                    page.update()
                return
            settings = current_server_settings()
            token = await _load_monitor_token()
            is_oauth = settings.connector_type == "generic_rest_readonly" and getattr(settings, "adapter_protocol", "rest") == "oauth2_rest"
            if settings.feed_auth_mode != "none" and not token and not is_oauth:
                if not quiet:
                    server_feed_status_text.value = "TOKEN READ-ONLY BELUM DIATUR · gunakan token feed terpisah dari server"
                    server_feed_status_text.color = C["amber"]
                    page.update()
                return
            if not settings.base_url:
                if not quiet:
                    server_feed_status_text.value = "BASE URL BELUM DIATUR"
                    server_feed_status_text.color = C["amber"]
                    page.update()
                return
            if settings.connector_type == "generic_rest_readonly":
                client = await _make_readonly_feed_client(settings)
            else:
                private_key = await _load_e2ee_private_key()
                if not private_key:
                    raise ServerFeedError("E2EE key receiver belum disiapkan. Buat/import keypair sebelum membaca feed terenkripsi.")
                client = E2EEServerFeedClient(settings, token, private_key)
            events = await asyncio.to_thread(client.fetch_recent, 100)
            # Keep an idempotent daily archive on the device. Nothing is replicated to any server.
            try:
                source_profile = server_registry_store.get(active_server_id)
                server_event_archive.add_events(active_server_id, source_profile.name if source_profile else active_server_id, events)
                refresh_archive_view()
            except (ArchiveError, OSError, ValueError, sqlite3.Error) as archive_exc:
                archive_status_text.value = f"Feed diterima tetapi arsip lokal bermasalah: {archive_exc}"
                archive_status_text.color = C["red"]
                page.update()
            await _notify_new_security_alerts(events)
            _render_server_feed(events)
            server_feed_status_text.value = f"LIVE POLL · {len(events)} event · {getattr(settings, 'adapter_protocol', 'rest').upper()} · diperbarui {datetime.now().astimezone().strftime('%d-%m-%Y %H:%M:%S %Z')} · {settings.telemetry_path}"
            server_feed_status_text.color = C["green"] if events else C["amber"]
            wizard_api_status_text.value = "API TERJANGKAU · feed request berhasil"
            wizard_api_status_text.color = C["green"]
            if events:
                wizard_feed_status_text.value = f"FEED BERHASIL · {len(events)} event diterima pada poll ini"
                wizard_feed_status_text.color = C["green"]
                rules_now = DetectionEngine(auth_failure_threshold=DEFAULT_AUTH_FAILURE_THRESHOLD, window_seconds=DEFAULT_AUTH_FAILURE_WINDOW_SECONDS).evaluate(events)
                wizard_detection_status_text.value = f"DETEKSI DIJALANKAN · {len(events)} event diperiksa · {len(rules_now)} rule hit"
                wizard_detection_status_text.color = C["amber"] if rules_now else C["green"]
            else:
                wizard_feed_status_text.value = "FEED BERHASIL DIJANGKAU · 0 event diterima; sumber log belum terbukti"
                wizard_feed_status_text.color = C["amber"]
                wizard_detection_status_text.value = "DETEKSI MENUNGGU EVENT · tidak ada data untuk dievaluasi"
                wizard_detection_status_text.color = C["amber"]
            if settings.connector_type == "generic_rest_readonly":
                wizard_agent_status_text.value = "AGEN TIDAK DINILAI · konektor API baca-saja tidak mengonfirmasi agen host"
                wizard_agent_status_text.color = C["muted"]
            elif any(str(event.get("event_type", "")).upper() == "AGENT_HEALTH" for event in events):
                wizard_agent_status_text.value = "AGEN HEARTBEAT DITERIMA · setidaknya satu event AGENT_HEALTH terdeteksi"
                wizard_agent_status_text.color = C["green"]
            else:
                wizard_agent_status_text.value = "AGEN BELUM DIVERIFIKASI · belum ada event AGENT_HEALTH dalam poll ini"
                wizard_agent_status_text.color = C["amber"]
            page.update()
        except (ServerFeedError, GenericRestFeedError, ProtocolAdapterError, SyncError, OSError, ValueError) as exc:
            server_feed_status_text.value = f"FEED GAGAL · {exc}"
            server_feed_status_text.color = C["red"]
            wizard_feed_status_text.value = f"FEED GAGAL · {str(exc)[:180]}"
            wizard_feed_status_text.color = C["red"]
            wizard_detection_status_text.value = "DETEKSI TIDAK DAPAT MEMERIKSA · feed gagal"
            wizard_detection_status_text.color = C["amber"]
            if not quiet:
                set_notice("Tidak dapat membaca feed server; audit lokal tetap berjalan.", "warning")
            try:
                page.update()
            except Exception:
                return
        except Exception as exc:
            # A malformed/custom feed adapter must not bubble through the connect
            # handler and tear down a healthy SSE stream. Record the real failure,
            # keep local audit alive, and let the normal retry/poll path recover.
            _log_ui_diagnostic(store.data_dir, "server telemetry refresh", exc)
            server_feed_status_text.value = f"FEED GAGAL · {type(exc).__name__}: {str(exc)[:180]}"
            server_feed_status_text.color = C["red"]
            wizard_feed_status_text.value = f"FEED GAGAL · {type(exc).__name__}"
            wizard_feed_status_text.color = C["red"]
            wizard_detection_status_text.value = "DETEKSI MENUNGGU · feed gagal; koneksi stream dipertahankan"
            wizard_detection_status_text.color = C["amber"]
            try:
                page.update()
            except Exception:
                pass

    def refresh_server_profile_options() -> None:
        profiles = server_registry_store.list()
        server_profile_dropdown.options = [
            ft.DropdownOption(key=p.profile_id, text=f"{p.name} · {p.settings.base_url}")
            for p in profiles
        ]
        server_profile_dropdown.value = active_server_id if active_server_id in server_registry_store.profiles else None

    def _load_profile_into_fields(profile_id: str | None) -> None:
        profile = server_registry_store.get(profile_id)
        if profile is None:
            # One persistent install ID is created by SyncSettingsStore and reused
            # when adding server profiles; do not mint a new ID on every click.
            defaults = sync_settings_store.settings
            server_name_field.value = "Server baru"
            sync_server_field.value = ""
            sync_events_path_field.value = defaults.events_path
            sync_health_path_field.value = defaults.health_path
            sync_telemetry_path_field.value = defaults.telemetry_path
            connector_type_dropdown.value = defaults.connector_type
            feed_auth_mode_dropdown.value = defaults.feed_auth_mode
            feed_json_path_field.value = defaults.feed_json_path
            feed_field_mapping_field.value = json.dumps(json.loads(DEFAULT_FEED_FIELD_MAPPING), ensure_ascii=False, indent=2)
            feed_auth_header_field.value = getattr(defaults, "feed_auth_header_name", "X-API-Key")
            feed_auth_header_field.visible = defaults.feed_auth_mode == "custom_header"
            adapter_protocol_dropdown.value = getattr(defaults, "adapter_protocol", "rest")
            adapter_options_field.value = getattr(defaults, "adapter_options_json", "{}")
            adapter_secret_field.value = ""
            adapter_secret_field.visible = adapter_protocol_dropdown.value == "oauth2_rest"
            sync_device_id_field.value = defaults.device_id
        else:
            settings = profile.settings
            server_name_field.value = profile.name
            sync_server_field.value = settings.base_url
            sync_events_path_field.value = settings.events_path
            sync_health_path_field.value = settings.health_path
            sync_telemetry_path_field.value = settings.telemetry_path
            connector_type_dropdown.value = settings.connector_type
            feed_auth_mode_dropdown.value = settings.feed_auth_mode
            feed_json_path_field.value = settings.feed_json_path
            try:
                feed_field_mapping_field.value = json.dumps(json.loads(settings.feed_field_mapping), ensure_ascii=False, indent=2)
            except ValueError:
                feed_field_mapping_field.value = DEFAULT_FEED_FIELD_MAPPING
            feed_auth_header_field.value = getattr(settings, "feed_auth_header_name", "X-API-Key")
            feed_auth_header_field.visible = settings.feed_auth_mode == "custom_header"
            adapter_protocol_dropdown.value = getattr(settings, "adapter_protocol", "rest")
            adapter_options_field.value = getattr(settings, "adapter_options_json", "{}")
            adapter_secret_field.value = ""
            adapter_secret_field.visible = adapter_protocol_dropdown.value == "oauth2_rest"
            sync_device_id_field.value = settings.device_id
        connector_mode_help_text.value = connector_mode_guidance(str(connector_type_dropdown.value or DEFAULT_CONNECTOR_TYPE))
        integration_mode_dropdown.value = "existing_api" if connector_type_dropdown.value == "generic_rest_readonly" else "kawal_api"
        generic_rest_settings_panel.visible = connector_type_dropdown.value == "generic_rest_readonly"
        monitor_token_field.visible = (connector_type_dropdown.value == "generic_rest_readonly" and feed_auth_mode_dropdown.value != "none")
        integration_wizard_result.value = "Profile dimuat. Tekan Uji Koneksi untuk menguji API, lalu periksa status FEED dan AGEN secara terpisah."
        integration_wizard_result.color = C["muted"]
        sync_token_field.value = ""
        monitor_token_field.value = ""
        response_token_field.value = ""
        admin_token_field.value = ""
        adapter_secret_field.value = ""
        member_totp_seed_field.value = ""
        member_totp_seed_field.visible = False

    def select_server_profile(e: ft.ControlEvent) -> None:
        nonlocal active_server_id, connected_server_id
        chosen_id = getattr(e.control, "value", None)
        if not chosen_id or chosen_id not in server_registry_store.profiles:
            return
        try:
            old_feed = universal_feed_client_cache.get(str(active_server_id)) if active_server_id else None
            if old_feed:
                old_feed[1].close()
            server_registry_store.select(chosen_id)
            active_server_id = chosen_id
            selected_profile_for_identity = server_registry_store.get(chosen_id)
            if selected_profile_for_identity:
                current_global = sync_settings_store.settings
                if current_global.device_id != selected_profile_for_identity.settings.device_id:
                    sync_settings_store.save(SyncSettings(
                        base_url=current_global.base_url,
                        device_id=selected_profile_for_identity.settings.device_id,
                        events_path=current_global.events_path,
                        health_path=current_global.health_path,
                        telemetry_path=current_global.telemetry_path,
                        ca_bundle=current_global.ca_bundle,
                        connector_type=current_global.connector_type,
                        feed_auth_mode=current_global.feed_auth_mode,
                        feed_json_path=current_global.feed_json_path,
                        feed_field_mapping=current_global.feed_field_mapping,
                        feed_auth_header_name=getattr(current_global, "feed_auth_header_name", "X-API-Key"),
                        adapter_protocol=getattr(current_global, "adapter_protocol", "rest"),
                        adapter_options_json=getattr(current_global, "adapter_options_json", "{}"),
                    ))
            connected_server_id = None
            stop_live_stream()
            connector_runtime_state["server_status"] = "idle"
            _load_profile_into_fields(chosen_id)
            profile = server_registry_store.get(chosen_id)
            server_connection_text.value = f"TERPUTUS · profile dipilih: {profile.name if profile else chosen_id}"
            server_connection_text.color = C["amber"]
            sync_status_text.value = "SERVER BERGANTI · tekan Hubungkan untuk mengaktifkan koneksi"
            sync_status_text.color = C["amber"]
            server_feed_status_text.value = "FEED BELUM AKTIF · hubungkan server terpilih"
            server_feed_status_text.color = C["muted"]
            refresh_archive_view()
            refresh_status_overview()
            page.update()
        except ServerRegistryError as exc:
            set_notice(str(exc), "danger")

    def prepare_new_server(_: ft.ControlEvent | None = None) -> None:
        nonlocal active_server_id, connected_server_id
        if session["role"] != "admin":
            set_notice("Hanya admin yang dapat menambah server.", "danger")
            return
        connected_server_id = None
        stop_live_stream()
        connector_runtime_state["server_status"] = "idle"
        active_server_id = None
        server_profile_dropdown.value = None
        _load_profile_into_fields(None)
        integration_mode_dropdown.value = "kawal_api"
        integration_mode_help.value = "Untuk API Kawal Trace milikmu. Jika server hanya menyediakan API log lain, pilih 'Server sudah punya API log' lalu gunakan auto-detect."
        generic_rest_settings_panel.visible = False
        server_connection_text.value = "PROFILE BARU · isi nama dan URL HTTPS, lalu Terapkan pilihan"
        server_connection_text.color = C["amber"]
        sync_status_text.value = "SERVER BELUM DISIMPAN · log lokal tetap berjalan"
        sync_status_text.color = C["muted"]
        server_feed_status_text.value = "FEED NONAKTIF · belum ada server terpilih"
        server_feed_status_text.color = C["muted"]
        refresh_status_overview()
        page.update()

    async def save_sync_config(_: ft.ControlEvent | None = None) -> bool:
        nonlocal active_server_id, connected_server_id
        if session["role"] != "admin":
            set_notice("Hanya admin yang dapat mengubah konfigurasi server.", "danger")
            return False
        try:
            existing = server_registry_store.get(active_server_id)
            draft_device_id = (sync_device_id_field.value or "").strip()
            if not draft_device_id:
                draft_device_id = sync_settings_store.settings.device_id
            candidate = SyncSettings(
                base_url=sync_server_field.value or "",
                device_id=draft_device_id,
                events_path=sync_events_path_field.value or DEFAULT_EVENTS_PATH,
                health_path=sync_health_path_field.value or DEFAULT_HEALTH_PATH,
                telemetry_path=sync_telemetry_path_field.value or DEFAULT_TELEMETRY_PATH,
                ca_bundle=existing.settings.ca_bundle if existing else "",
                connector_type=connector_type_dropdown.value or DEFAULT_CONNECTOR_TYPE,
                feed_auth_mode=feed_auth_mode_dropdown.value or DEFAULT_FEED_AUTH_MODE,
                feed_json_path=feed_json_path_field.value or DEFAULT_FEED_JSON_PATH,
                feed_field_mapping=feed_field_mapping_field.value or DEFAULT_FEED_FIELD_MAPPING,
                feed_auth_header_name=feed_auth_header_field.value or "X-API-Key",
                adapter_protocol=adapter_protocol_dropdown.value or "rest",
                adapter_options_json=adapter_options_field.value or "{}",
            ).validated()
            profile_name = (server_name_field.value or "").strip()
            if not profile_name:
                raise ServerRegistryError("Isi nama profile server terlebih dahulu.")
            supplied_token = (sync_token_field.value or "").strip()
            supplied_monitor_token = (monitor_token_field.value or "").strip()
            supplied_response_token = (response_token_field.value or "").strip()
            supplied_admin_token = (admin_token_field.value or "").strip()
            supplied_adapter_secret = adapter_secret_field.value or ""
            if supplied_token or supplied_monitor_token or supplied_response_token or supplied_admin_token or supplied_adapter_secret:
                if secure_storage is None:
                    raise SyncConfigError("Secure Storage native belum tersedia. Token tidak akan ditulis ke file konfigurasi.")
            for token_value, token_label in ((supplied_token, "Token perangkat"), (supplied_monitor_token, "Token pemantauan"), (supplied_response_token, "Token respons")):
                if not token_value:
                    continue
                if any(ch.isspace() for ch in token_value):
                    raise SyncConfigError(
                        f"{token_label} mengandung spasi/baris baru. Salin hanya nilai tokennya, "
                        "tanpa label seperti 'Token perangkat:' atau teks penjelasan. Token 80+ karakter boleh."
                    )
                if len(token_value) < 24:
                    raise SyncConfigError(
                        f"{token_label} baru {len(token_value)} karakter; minimal 24. "
                        "Token 80+ karakter tetap valid jika disalin lengkap tanpa spasi."
                    )

            profile_id_for_save = active_server_id or ("srv-" + uuid.uuid4().hex)
            profile = server_registry_store.upsert(
                profile_name, candidate, profile_id=profile_id_for_save, select=True,
            )
            active_server_id = profile.profile_id
            connected_server_id = None  # changed config always requires explicit reconnect
            stop_live_stream()
            if active_server_id == "legacy-default":
                sync_settings_store.save(candidate)  # retain compatibility for a migrated v1.5 profile
            if supplied_token:
                await secure_storage.set(_profile_secret_key("device_token", active_server_id), supplied_token)
                sync_token_field.value = ""
            if supplied_monitor_token:
                await secure_storage.set(_profile_secret_key("monitor_token", active_server_id), supplied_monitor_token)
                monitor_token_field.value = ""
            if supplied_response_token:
                await secure_storage.set(_profile_secret_key("response_token", active_server_id), supplied_response_token)
                response_token_field.value = ""
            if supplied_admin_token:
                await secure_storage.set(_profile_secret_key("admin_token", active_server_id), supplied_admin_token)
                admin_token_field.value = ""
            if supplied_adapter_secret:
                await secure_storage.set(_profile_secret_key("oauth_client_secret", active_server_id), supplied_adapter_secret)
                adapter_secret_field.value = ""
            store.add_event(
                "CONFIG", session["username"], "server-sync",
                {"action": "server_profile_saved", "profile_id": profile.profile_id,
                 "profile_name": profile.name, "base_url": candidate.base_url,
                 "events_path": candidate.events_path, "health_path": candidate.health_path,
                 "connector_type": candidate.connector_type, "feed_auth_mode": candidate.feed_auth_mode,
                 "feed_json_path": candidate.feed_json_path, "device_id": candidate.device_id,
                 "device_token_updated": bool(supplied_token),
                 "monitor_token_updated": bool(supplied_monitor_token),
                 "response_token_updated": bool(supplied_response_token),
                 "oauth_client_secret_updated": bool(supplied_adapter_secret),
                 "adapter_protocol": candidate.adapter_protocol},
            )
            sync_device_id_field.value = candidate.device_id
            refresh_server_profile_options()
            server_connection_text.value = f"TERSIMPAN · {profile.name} · belum terhubung"
            server_connection_text.color = C["amber"]
            sync_status_text.value = "PROFILE DISIMPAN · token tidak disimpan dalam file konfigurasi; tekan Hubungkan"
            sync_status_text.color = C["green"]
            refresh_summary()
            page.update()
            set_notice(f"Profile server '{profile.name}' tersimpan. Tekan Hubungkan untuk mengaktifkan.", "good")
            return True
        except (SyncError, ServerRegistryError, ChainLogError, OSError, ValueError) as exc:
            sync_status_text.value = f"KONFIGURASI GAGAL · {exc}"
            sync_status_text.color = C["red"]
            page.update()
            set_notice("Konfigurasi server gagal disimpan.", "danger")
            return False

    async def test_server_connection(_: ft.ControlEvent | None = None) -> None:
        try:
            # Save visible settings first so the test always checks the selected profile.
            if not await save_sync_config():
                return
            settings = current_server_settings()
            if settings.connector_type == "generic_rest_readonly":
                client = await _make_readonly_feed_client(settings)
                result = await asyncio.to_thread(client.health_check)
                sample_events = int(result.get("sample_events", 0) or 0)
                wizard_api_status_text.value = "API TERJANGKAU · TLS tervalidasi"
                wizard_api_status_text.color = C["green"]
                if sample_events:
                    wizard_feed_status_text.value = f"FEED ADA · {sample_events} event sampel diterima"
                    wizard_feed_status_text.color = C["green"]
                    wizard_detection_status_text.value = "DETEKSI SIAP · menunggu polling event terbaru"
                    wizard_detection_status_text.color = C["muted"]
                else:
                    wizard_feed_status_text.value = "FEED RESPON · 0 event sampel; belum ada log untuk diproses"
                    wizard_feed_status_text.color = C["amber"]
                    wizard_detection_status_text.value = "DETEKSI MENUNGGU EVENT · nol event diterima"
                    wizard_detection_status_text.color = C["amber"]
                wizard_agent_status_text.value = "AGEN TIDAK DINILAI · konektor API umum tidak membuktikan status agen host"
                wizard_agent_status_text.color = C["muted"]
            else:
                token = await _load_device_token()
                if not token:
                    ready = await _request_or_claim_current_device()
                    if not ready:
                        _start_enrollment_poll()
                        wizard_api_status_text.value = "API TERJANGKAU? · menunggu persetujuan perangkat"
                        wizard_api_status_text.color = C["amber"]
                        page.update()
                        return
                    token = await _load_device_token()
                if not token:
                    raise SyncConfigError("Akses belum aktif. Minta pemilik server menyetujui Device ID ini, lalu coba lagi.")
                client = _make_sync_client(token)
                result = await asyncio.to_thread(client.health_check)
                wizard_api_status_text.value = "API KAWAL TRACE TERJANGKAU · autentikasi berhasil"
                wizard_api_status_text.color = C["green"]
                wizard_feed_status_text.value = "FEED BELUM DIVERIFIKASI · lakukan Hubungkan lalu ambil event"
                wizard_feed_status_text.color = C["amber"]
                wizard_agent_status_text.value = "AGEN BELUM DIVERIFIKASI · perlu heartbeat/event dari host"
                wizard_agent_status_text.color = C["amber"]
                wizard_detection_status_text.value = "DETEKSI MENUNGGU FEED · belum ada event yang dievaluasi"
                wizard_detection_status_text.color = C["muted"]
            sync_status_text.value = f"UJI KONEKSI BERHASIL · {settings.base_url} · TLS tervalidasi"
            sync_status_text.color = C["green"]
            integration_wizard_result.value = "UJI KONEKSI LULUS · API sudah merespons. Periksa status FEED, AGEN, dan DETEKSI secara terpisah; hijau di API tidak membuktikan seluruh log terkumpul."
            integration_wizard_result.color = C["green"]
            set_notice(str(result.get("status", "Health-check server berhasil.")), "good")
            page.update()
        except (GenericRestFeedError, ProtocolAdapterError, SyncError, OSError, ValueError, RuntimeError) as exc:
            sync_status_text.value = f"UJI KONEKSI GAGAL · {exc}"
            sync_status_text.color = C["red"]
            wizard_api_status_text.value = f"API GAGAL · {str(exc)[:180]}"
            wizard_api_status_text.color = C["red"]
            wizard_feed_status_text.value = "FEED BELUM DIVERIFIKASI"
            wizard_feed_status_text.color = C["amber"]
            wizard_agent_status_text.value = "AGEN BELUM DIVERIFIKASI"
            wizard_agent_status_text.color = C["muted"]
            wizard_detection_status_text.value = "DETEKSI MENUNGGU FEED"
            wizard_detection_status_text.color = C["muted"]
            integration_wizard_result.value = (
                f"UJI GAGAL · {str(exc)[:240]}\n"
                "Periksa Base URL, path, hak akses/token, serta dokumentasi resmi API. "
                "Log lokal tetap tersedia."
            )
            integration_wizard_result.color = C["red"]
            page.update()
            set_notice("Koneksi server gagal; database lokal tetap aktif.", "danger")

    def apply_integration_wizard_mode(_: ft.ControlEvent | None = None) -> None:
        """Apply a beginner-friendly source mode without silently changing saved credentials."""
        if session["role"] != "admin":
            set_notice("Hanya admin lokal yang dapat mengubah koneksi server.", "danger")
            return
        mode = str(integration_mode_dropdown.value or "existing_api")
        previous_connector = connector_type_dropdown.value
        if mode == "existing_api":
            connector_type_dropdown.value = "generic_rest_readonly"
            if previous_connector != "generic_rest_readonly":
                adapter_protocol_dropdown.value = "rest"
                adapter_options_field.value = "{}"
            generic_rest_settings_panel.visible = True
            adapter_protocol_dropdown.visible = True
            feed_auth_header_field.visible = feed_auth_mode_dropdown.value == "custom_header"
            adapter_secret_field.visible = adapter_protocol_dropdown.value == "oauth2_rest"
            monitor_token_field.visible = feed_auth_mode_dropdown.value != "none" or manual_token_fields_visible
            integration_wizard_result.value = (
                "MODE API YANG SUDAH ADA DIPILIH · masukkan Base URL dan kredensial baca, lalu tekan Cari endpoint REST. "
                "Jika feed punya path non-standar, gunakan path resmi yang diberikan pemilik API."
            )
            integration_wizard_result.color = C["muted"]
        elif mode == "kawal_api":
            connector_type_dropdown.value = "kawal_trace_api"
            generic_rest_settings_panel.visible = False
            monitor_token_field.visible = manual_token_fields_visible
            integration_wizard_result.value = (
                "MODE KAWAL TRACE API DIPILIH · gunakan URL API yang menerapkan kontrak Kawal Trace. "
                "Perangkat anggota perlu enrollment/approval satu kali."
            )
            integration_wizard_result.color = C["muted"]
        else:
            connector_type_dropdown.value = "kawal_trace_api"
            generic_rest_settings_panel.visible = False
            monitor_token_field.visible = manual_token_fields_visible
            integration_wizard_result.value = (
                "MODE AGEN DIPILIH · API penerima Kawal Trace akan dipakai. Pemilik server sumber harus mengizinkan agen membaca log; "
                "jangan pasang agen ke server pihak lain tanpa persetujuan."
            )
            integration_wizard_result.color = C["amber"]
        update_connector_mode_guidance()
        # Restore mode-specific visibility after generic helper updates the panel.
        generic_rest_settings_panel.visible = mode == "existing_api"
        monitor_token_field.visible = (mode == "existing_api" and feed_auth_mode_dropdown.value != "none") or manual_token_fields_visible
        page.update()

    async def detect_api_endpoint_click(_: ft.ControlEvent | None = None) -> None:
        """Try a small safe list of common GET-only REST log paths on the entered API host."""
        if str(integration_mode_dropdown.value or "") != "existing_api":
            integration_wizard_result.value = "PILIH MODE API LOG YANG SUDAH ADA, lalu tekan Terapkan pilihan sebelum deteksi."
            integration_wizard_result.color = C["amber"]
            page.update()
            return
        if connector_type_dropdown.value != "generic_rest_readonly":
            apply_integration_wizard_mode()
        if not await save_sync_config():
            integration_wizard_result.value = "DETEKSI DIBATALKAN · perbaiki konfigurasi yang ditandai gagal terlebih dahulu."
            integration_wizard_result.color = C["red"]
            page.update()
            return
        try:
            settings = current_server_settings()
            if settings.adapter_protocol != "rest":
                raise ProtocolAdapterError("Cari endpoint otomatis saat ini hanya untuk REST/JSON. Pilih protokol REST atau gunakan path resmi untuk GraphQL/SOAP/WebSocket.")
            token = await _load_monitor_token()
            integration_wizard_result.value = "SEDANG MEMERIKSA · GET read-only ke path umum pada host yang kamu masukkan; redirect tidak diikuti."
            integration_wizard_result.color = C["muted"]
            page.update()
            result = await asyncio.to_thread(probe_readonly_json_event_feed, settings, token)
            if not result.get("ok"):
                diagnostics = "; ".join(result.get("diagnostics", [])[:6])
                integration_wizard_result.value = result.get("message", "Endpoint tidak ditemukan.") + (f" Detail: {diagnostics}" if diagnostics else "")
                integration_wizard_result.color = C["amber"]
                wizard_api_status_text.value = "API BELUM COCOK · lihat detail deteksi"
                wizard_api_status_text.color = C["amber"]
                page.update()
                set_notice("Deteksi tidak mengubah profil karena tidak menemukan feed yang bisa dipetakan dengan aman.", "warning")
                return

            sync_telemetry_path_field.value = str(result.get("path") or settings.telemetry_path)
            feed_json_path_field.value = str(result.get("events_path") or settings.feed_json_path)
            detected_mapping = result.get("mapping") or {}
            if detected_mapping:
                try:
                    merged_mapping = json.loads(DEFAULT_FEED_FIELD_MAPPING)
                except ValueError:
                    merged_mapping = {}
                merged_mapping.update(detected_mapping)
                feed_field_mapping_field.value = json.dumps(merged_mapping, ensure_ascii=False, indent=2)
                advanced_api_settings_panel.visible = False
                advanced_api_settings_toggle.content = "Pengaturan lanjutan · mapping / pagination"
            if not await save_sync_config():
                raise SyncConfigError("Endpoint ditemukan, tetapi profil baru tidak tersimpan. Periksa Secure Storage dan kolom yang ditandai.")
            count = int(result.get("sample_count", 0) or 0)
            if count:
                integration_wizard_result.value = f"ENDPOINT DITEMUKAN · {result['path']} · array event: {result['events_path']} · {count} sampel · mapping umum diterapkan. Menjalankan uji koneksi…"
                integration_wizard_result.color = C["green"]
            else:
                integration_wizard_result.value = f"ENDPOINT MERESPONS TAPI KOSONG · {result['path']} · array: {result['events_path']}. Mapping tidak ditebak tanpa sampel; uji feed lalu periksa mapping jika perlu."
                integration_wizard_result.color = C["amber"]
            page.update()
            await test_server_connection(None)
        except (GenericRestFeedError, ProtocolAdapterError, SyncError, OSError, ValueError, RuntimeError) as exc:
            integration_wizard_result.value = f"DETEKSI GAGAL · {str(exc)[:240]}"
            integration_wizard_result.color = C["red"]
            wizard_api_status_text.value = "API / FEED BELUM COCOK"
            wizard_api_status_text.color = C["red"]
            page.update()
            set_notice("Deteksi berhenti dengan aman; profil sebelumnya tidak dihapus.", "danger")

    # --- Real-time doorbell ------------------------------------------------------------------------
    # The server stream only says WHICH kind of data changed. Every doorbell is answered by the same
    # authenticated, validated pull the five-second poll uses, so nothing new is trusted from the stream and
    # nothing from this device is sent over it. The poll stays as a safety net (rare while the stream is live).
    live_stream: dict[str, Any] = {"supervisor": None, "state": STATE_STOPPED, "owner": None}
    doorbell = DoorbellCoalescer(min_interval=1.0)
    doorbell_wake = asyncio.Event()

    def _apply_live_stream_status(state: str, detail: str) -> None:
        live_stream["state"] = state
        live_stream_status_text.value = live_stream_message(state, detail)
        live_stream_status_text.color = {
            STATE_LIVE: C["green"], STATE_UNAUTHORIZED: C["red"],
            STATE_CONNECTING: C["amber"], STATE_RETRYING: C["amber"], STATE_UNSUPPORTED: C["amber"],
        }.get(state, C["muted"])
        try:
            page.update()
        except Exception:
            pass

    def stop_live_stream() -> None:
        """Safe to call at any time and more than once; every path that drops the connection calls it."""
        supervisor = live_stream["supervisor"]
        live_stream["supervisor"] = None
        live_stream["owner"] = None
        if supervisor is not None:
            supervisor.stop()
        _apply_live_stream_status(STATE_STOPPED, "")

    def start_live_stream(settings: SyncSettings, monitor_token: str) -> None:
        stop_live_stream()
        loop = asyncio.get_running_loop()
        holder: dict[str, Any] = {}

        def on_status(state: str, detail: str) -> None:       # runs on the stream thread
            def apply() -> None:
                if live_stream["supervisor"] is holder.get("supervisor"):   # ignore a stream we already replaced
                    _apply_live_stream_status(state, detail)
            loop.call_soon_threadsafe(apply)

        def on_signal(kinds: frozenset[str]) -> None:           # runs on the stream thread
            doorbell.ring(kinds)
            loop.call_soon_threadsafe(doorbell_wake.set)

        supervisor = LiveStreamSupervisor(lambda: LiveStreamClient(settings, monitor_token), on_signal, on_status)
        holder["supervisor"] = supervisor
        live_stream["supervisor"] = supervisor
        live_stream["owner"] = active_server_id
        supervisor.start()

    async def doorbell_consumer() -> None:
        while alive["on"]:
            try:
                await asyncio.wait_for(doorbell_wake.wait(), timeout=60)
            except asyncio.TimeoutError:
                continue
            doorbell_wake.clear()
            while alive["on"]:
                taken = doorbell.take()
                if taken.kinds:
                    try:
                        if taken.kinds & {"security", "encrypted"}:
                            await refresh_server_feed(quiet=True)
                        if taken.kinds & {"actions", "windows"}:
                            await refresh_response_actions(quiet=True)
                    except Exception as exc:  # never let one failed refresh end real-time updates
                        _log_ui_diagnostic(store.data_dir, "doorbell refresh", exc)
                    continue
                if taken.retry_after:
                    await asyncio.sleep(taken.retry_after)
                    continue
                break

    async def connect_selected_server(_: ft.ControlEvent | None = None) -> None:
        nonlocal connected_server_id
        if not await save_sync_config():
            return
        connector_runtime_state["server_status"] = "connecting"
        connector_runtime_state["folder_status"] = "connecting"
        connector_runtime_state["folder_headline"] = "MENGHUBUNGKAN KE SERVER"
        connector_runtime_state["folder_detail"] = "Menunggu koneksi server dan laporan Linux Server Agent."
        connector_runtime_state["linux_agent_status"] = "idle"
        connector_runtime_state["windows_agent_status"] = "idle"
        refresh_status_overview()
        try:
            settings = current_server_settings()
            if settings.connector_type == "generic_rest_readonly":
                client = await _make_readonly_feed_client(settings)
                result = await asyncio.to_thread(client.health_check)
            else:
                token = await _load_device_token()
                if not token:
                    ready = await _request_or_claim_current_device()
                    if not ready:
                        connector_runtime_state["server_status"] = "warn"
                        refresh_status_overview()
                        _start_enrollment_poll()
                        return
                    token = await _load_device_token()
                if not token:
                    raise SyncConfigError("Akses belum aktif. Pemilik server perlu menyetujui Device ID ini.")
                client = _make_sync_client(token)
                result = await asyncio.to_thread(client.health_check)
            connected_server_id = active_server_id
            connector_runtime_state["server_status"] = "good"
            profile = server_registry_store.get(active_server_id)
            server_connection_text.value = f"TERHUBUNG · {profile.name if profile else settings.base_url} · TLS tervalidasi"
            server_connection_text.color = C["green"]
            mode_label = f"READ-ONLY {getattr(settings, 'adapter_protocol', 'rest').upper()}" if settings.connector_type == "generic_rest_readonly" else "Kawal Trace API"
            sync_status_text.value = f"KONEKSI AKTIF · {settings.base_url} · mode={mode_label} · status={result.get('status', 'ok')}"
            sync_status_text.color = C["green"]
            refresh_status_overview()
            page.update()
            set_notice("Server terhubung. Feed keamanan dan sinkronisasi aktif untuk profile terpilih.", "good")
            if settings.connector_type == "generic_rest_readonly":
                await refresh_server_feed(quiet=True)
            else:
                monitor_token = await _load_monitor_token()
                if monitor_token:
                    # Start the stream first: real-time must not depend on the very first pull succeeding, and a
                    # failing feed is exactly when its automatic retry matters. hello makes the app pull anyway.
                    start_live_stream(settings, monitor_token)
                    await refresh_server_feed(quiet=True)
                    await refresh_response_actions(quiet=True)
                else:
                    server_feed_status_text.value = "TERHUBUNG UNTUK UPLOAD · token monitor read-only belum diatur"
                    server_feed_status_text.color = C["amber"]
                    page.update()
        except (GenericRestFeedError, ProtocolAdapterError, SyncError, OSError, ValueError) as exc:
            connected_server_id = None
            stop_live_stream()
            connector_runtime_state["server_status"] = "bad"
            connector_runtime_state["folder_status"] = "idle"
            connector_runtime_state["folder_headline"] = "SERVER TIDAK TERHUBUNG"
            connector_runtime_state["folder_detail"] = "Pemantauan folder server tidak berjalan dari aplikasi karena koneksi gagal."
            server_connection_text.value = f"GAGAL TERHUBUNG · {exc}"
            server_connection_text.color = C["red"]
            sync_status_text.value = f"KONEKSI GAGAL · {exc}"
            sync_status_text.color = C["red"]
            refresh_status_overview()
            page.update()
            set_notice("Server belum terhubung. Log lokal tetap disimpan.", "warning")
        except Exception as exc:
            connected_server_id = None
            stop_live_stream()
            connector_runtime_state["server_status"] = "bad"
            connector_runtime_state["folder_status"] = "idle"
            connector_runtime_state["folder_headline"] = "SERVER TIDAK TERHUBUNG"
            connector_runtime_state["folder_detail"] = "Pemantauan folder server tidak berjalan dari aplikasi karena koneksi gagal."
            server_connection_text.value = f"GAGAL TERHUBUNG · {type(exc).__name__}"
            server_connection_text.color = C["red"]
            sync_status_text.value = f"KONEKSI GAGAL · {type(exc).__name__}"
            sync_status_text.color = C["red"]
            refresh_status_overview()
            page.update()
            set_notice("Server gagal terhubung karena kesalahan yang tidak terduga. Log lokal tetap disimpan.", "warning")

    def disconnect_selected_server(_: ft.ControlEvent | None = None) -> None:
        nonlocal connected_server_id, enrollment_poll_task
        connector_runtime_state["linux_agent_status"] = "idle"
        connector_runtime_state["windows_agent_status"] = "idle"
        if enrollment_poll_task is not None and not enrollment_poll_task.done():
            enrollment_poll_task.cancel()
            enrollment_poll_task = None
        if not active_server_id:
            set_notice("Tidak ada server terpilih.", "warning")
            return
        connected_server_id = None
        stop_live_stream()
        connector_runtime_state["server_status"] = "idle"
        connector_runtime_state["folder_status"] = "idle"
        connector_runtime_state["folder_headline"] = "SERVER TERPUTUS"
        connector_runtime_state["folder_detail"] = "Feed pemantauan server dihentikan di aplikasi; agen server tidak dihentikan dan tetap berjalan di server."
        cached_feed = universal_feed_client_cache.get(str(active_server_id))
        if cached_feed:
            cached_feed[1].close()
        profile = server_registry_store.get(active_server_id)
        server_connection_text.value = f"DIPUTUSKAN · {profile.name if profile else active_server_id} · konfigurasi dan log server tidak dihapus"
        server_connection_text.color = C["amber"]
        server_feed_status_text.value = "FEED TERPUTUS · tekan Hubungkan untuk melanjutkan polling"
        server_feed_status_text.color = C["muted"]
        sync_status_text.value = "KONEKSI CLIENT DIPUTUSKAN · agen Linux dan server tetap berjalan"
        sync_status_text.color = C["amber"]
        refresh_status_overview()
        page.update()
        set_notice("Koneksi dari aplikasi dihentikan. Server/agen remote tidak dimatikan dan data tidak dihapus.", "warning")

    async def remove_server_profile(_: ft.ControlEvent | None = None) -> None:
        nonlocal active_server_id, connected_server_id
        if session["role"] != "admin":
            set_notice("Hanya admin yang dapat menghapus profile lokal.", "danger")
            return
        if not active_server_id:
            set_notice("Pilih profile server yang akan dihapus.", "warning")
            return
        remove_id = active_server_id
        cached_feed = universal_feed_client_cache.pop(str(remove_id), None)
        if cached_feed:
            cached_feed[1].close()
        profile = server_registry_store.get(remove_id)
        connected_server_id = None
        stop_live_stream()
        connector_runtime_state["server_status"] = "idle"
        try:
            server_registry_store.remove(remove_id)
            if remove_id != "legacy-default":
                profile_cursor_stores.pop(remove_id, None)
                safe_cursor_id = "".join(ch for ch in remove_id if ch.isalnum() or ch in "._-")
                for suffix in ("", "-wal", "-shm"):
                    try:
                        (store.data_dir / f"sync-state-{safe_cursor_id}.sqlite3{suffix}").unlink(missing_ok=True)
                    except OSError:
                        pass
            # Preserve the installation identity even when the last profile is removed.
            # Blank base_url prevents the deleted profile being silently recreated on next launch.
            remaining_profile = server_registry_store.selected()
            kept_id = remaining_profile.settings.device_id if remaining_profile else sync_settings_store.settings.device_id
            old_global = sync_settings_store.settings
            sync_settings_store.save(SyncSettings(
                base_url="", device_id=kept_id,
                events_path=old_global.events_path, health_path=old_global.health_path,
                telemetry_path=old_global.telemetry_path, ca_bundle=old_global.ca_bundle,
                connector_type=old_global.connector_type, feed_auth_mode=old_global.feed_auth_mode,
                feed_json_path=old_global.feed_json_path, feed_field_mapping=old_global.feed_field_mapping,
                feed_auth_header_name=getattr(old_global, "feed_auth_header_name", "X-API-Key"),
                adapter_protocol=getattr(old_global, "adapter_protocol", "rest"),
                adapter_options_json=getattr(old_global, "adapter_options_json", "{}"),
            ))
            if secure_storage is not None:
                for kind in ("device_token", "monitor_token", "response_token", "admin_token", "claim_secret", "response_totp_seed", "oauth_client_secret"):
                    try:
                        await secure_storage.remove(_profile_secret_key(kind, remove_id))
                    except Exception:
                        pass
                if remove_id == "legacy-default":
                    for old_key in ("kawal_trace_device_token", "kawal_trace_monitor_token"):
                        try:
                            await secure_storage.remove(old_key)
                        except Exception:
                            pass
            active_server_id = server_registry_store.selected_id
            _load_profile_into_fields(active_server_id)
            refresh_server_profile_options()
            server_connection_text.value = f"PROFILE LOKAL DIHAPUS · {profile.name if profile else remove_id}; konfigurasi remote tidak diubah"
            server_connection_text.color = C["amber"]
            sync_status_text.value = "KONFIGURASI LOKAL DIHAPUS · server/agen remote tetap berjalan"
            sync_status_text.color = C["amber"]
            page.update()
            set_notice("Profile dan token lokal dihapus. Ini tidak menghapus log atau menonaktifkan agen di server.", "warning")
        except ServerRegistryError as exc:
            set_notice(str(exc), "danger")
    async def refresh_response_actions(_: ft.ControlEvent | None = None, quiet: bool = False) -> None:
        if not active_server_id or connected_server_id != active_server_id:
            if not quiet:
                response_status_text.value = "STATUS RESPONS BELUM DIAMBIL · hubungkan server terlebih dahulu"
                response_status_text.color = C["muted"]
                page.update()
            return
        settings = current_server_settings()
        if settings.connector_type != "kawal_trace_api" or httpx is None:
            if not quiet:
                response_status_text.value = "STATUS RESPONS HANYA TERSEDIA UNTUK KAWAL TRACE API"
                response_status_text.color = C["amber"]
                page.update()
            return
        token = await _load_monitor_token()
        if not token:
            if not quiet:
                response_status_text.value = "TOKEN MONITOR READ-ONLY BELUM DIATUR"
                response_status_text.color = C["amber"]
                page.update()
            return
        try:
            headers = {"Authorization": f"Bearer {token}", "X-KAWAL-Device-ID": settings.device_id, "Accept": "application/json"}
            def fetch_actions() -> tuple[int, dict[str, Any], list[dict[str, Any]]]:
                with httpx.Client(timeout=httpx.Timeout(8.0, connect=3.0), verify=True, follow_redirects=False) as client:
                    response = client.get(settings.base_url.rstrip("/") + "/api/v1/response-actions?limit=20", headers=headers)
                    try:
                        data = response.json()
                    except ValueError:
                        data = {"error": "response_not_json"}
                    windows_actions: list[dict[str, Any]] = []
                    # Older API deployments may not include Windows response endpoints; this is optional.
                    try:
                        windows_response = client.get(settings.base_url.rstrip("/") + "/api/v1/windows/response-actions?limit=20", headers=headers)
                        if windows_response.status_code == 200:
                            parsed_windows = windows_response.json()
                            candidate = parsed_windows.get("actions", []) if isinstance(parsed_windows, dict) else []
                            if isinstance(candidate, list):
                                windows_actions = [x for x in candidate if isinstance(x, dict)]
                    except Exception:
                        windows_actions = []
                    return response.status_code, data if isinstance(data, dict) else {"error": "invalid_response"}, windows_actions
            status_code, data, windows_actions = await asyncio.to_thread(fetch_actions)
            if status_code != 200:
                raise ValueError(f"HTTP {status_code} · {str(data.get('error', 'feed error'))[:100]}")
            actions = data.get("actions", [])
            if not isinstance(actions, list):
                raise ValueError("Format response actions tidak valid.")
            response_actions_list.controls = []
            windows_response_actions_list.controls = []
            status_color = {"PENDING": C["amber"], "ACTIVE_TEMP_BLOCK": C["red"], "EXPIRED": C["green"],
                            "FAILED": C["red"], "EXPIRY_ERROR": C["red"], "EXPIRED_BEFORE_APPLY": C["muted"]}
            for action in actions[:20]:
                if not isinstance(action, dict):
                    continue
                state = str(action.get("status", "UNKNOWN"))
                tone = status_color.get(state, C["muted"])
                message = str(action.get("worker_message", ""))[:160]
                response_actions_list.controls.append(ft.Container(
                    content=ft.Column(controls=[
                        ft.Row(controls=[ft.Text(f"LINUX · {state}", size=10, color=tone, weight=ft.FontWeight.BOLD),
                                         ft.Text(str(action.get("requested_at_utc", "")), size=9, color=C["quiet"])],
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN, wrap=True),
                        ft.Text(f"IP {action.get('source_ip', '—')} · TTL {action.get('ttl_seconds', '—')}s · expires {action.get('expires_at_utc', '—')}", size=10, color=C["text"], selectable=True),
                        ft.Text(f"Alasan: {str(action.get('reason', ''))[:150]} · Worker: {message or 'belum ada konfirmasi'}", size=9, color=C["muted"], selectable=True),
                    ], spacing=3), padding=9, bgcolor=C["bg"], border=ft.Border.all(1, tone), border_radius=7,
                ))
            windows_status_color = {"PENDING": C["amber"], "SUCCEEDED": C["green"], "REJECTED_LOCAL_POLICY": C["amber"], "FAILED": C["red"], "EXPIRED": C["muted"]}
            for action in windows_actions[:20]:
                state = str(action.get("status", "UNKNOWN")).upper()
                tone = windows_status_color.get(state, C["muted"])
                params = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
                target = str(action.get("target_host_id", "unknown-host"))
                action_name = str(action.get("action", "WINDOWS_ACTION"))
                target_description = params.get("source_ip") or (f"session={params.get('session_id')} user={params.get('target_user')}" if params.get("session_id") else f"pid={params.get('pid')} process={params.get('process_name')} user={params.get('target_user')}" )
                windows_response_actions_list.controls.append(ft.Container(
                    content=ft.Column(controls=[
                        ft.Row(controls=[ft.Text(f"WINDOWS · {state}", size=10, color=tone, weight=ft.FontWeight.BOLD),
                                         ft.Text(str(action.get("requested_at_utc", "")), size=9, color=C["quiet"])],
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN, wrap=True),
                        ft.Text(f"Host {target} · {action_name} · {target_description}", size=10, color=C["text"], selectable=True),
                        ft.Text(f"Alasan: {str(action.get('reason', ''))[:150]} · Endpoint: {str(action.get('worker_message', 'belum mengonfirmasi'))[:150]}", size=9, color=C["muted"], selectable=True),
                    ], spacing=3), padding=9, bgcolor=C["bg"], border=ft.Border.all(1, tone), border_radius=7,
                ))
            if not actions:
                response_actions_list.controls.append(ft.Text("Belum ada permintaan respons Linux pada server.", size=10, color=C["muted"]))
            if not windows_actions:
                windows_response_actions_list.controls.append(ft.Text("Belum ada permintaan respons Windows pada server.", size=10, color=C["muted"]))
            response_status_text.value = f"STATUS RESPONS DIPERBARUI · Linux {len(actions)} · status aktif hanya jika worker mengonfirmasi"
            response_status_text.color = C["green"]
            windows_response_status_text.value = f"WINDOWS RESPONSE STATUS · {len(windows_actions)} action · SUCCEEDED hanya jika endpoint Windows mengonfirmasi"
            windows_response_status_text.color = C["green"] if windows_actions else C["muted"]
            page.update()
        except Exception as exc:
            response_status_text.value = f"STATUS RESPONS TIDAK TERSEDIA · {str(exc)[:180]}"
            response_status_text.color = C["amber"]
            if not quiet:
                page.update()

    async def request_temporary_ip_quarantine(_: ft.ControlEvent | None = None) -> None:
        """Queue a bounded response action; the server worker validates again before UFW."""
        if session["role"] != "admin":
            set_notice("Hanya admin lokal yang boleh meminta respons insiden.", "danger")
            return
        try:
            if not active_server_id or connected_server_id != active_server_id:
                raise ValueError("Hubungkan profile server dahulu.")
            settings = current_server_settings()
            if settings.connector_type != "kawal_trace_api":
                raise ValueError("Respons hanya tersedia untuk Kawal Trace API milikmu/yang kamu administrasikan; Generic REST bersifat read-only.")
            if not current_feed_ips:
                raise ValueError("Belum ada IPv4 publik pada feed server aktif. Ambil event terlebih dahulu.")
            parsed_ip = ipaddress.ip_address((response_ip_field.value or "").strip())
            if parsed_ip.version != 4 or not parsed_ip.is_global:
                raise ValueError("Hanya IPv4 publik yang dapat diajukan pada prototipe ini.")
            source_ip = str(parsed_ip)
            if source_ip not in current_feed_ufw_ips:
                raise ValueError("Untuk UFW, IP harus berasal dari event autentikasi SSH langsung dari agen Linux. IP pengunjung website di balik Cloudflare tidak boleh diblokir lewat UFW; gunakan adapter WAF tersendiri.")
            reason = (response_reason_field.value or "").strip()
            if len(reason) < 8:
                raise ValueError("Isi alasan respons minimal 8 karakter atau nomor tiket insiden.")
            confirmation = (response_confirm_field.value or "").strip()
            if confirmation != f"BLOCK {source_ip}":
                raise ValueError(f"Ketik tepat: BLOCK {source_ip}")
            response_token = await _load_response_token()
            if not response_token:
                raise ValueError("Token respons khusus belum disimpan. Server harus menerbitkan KAWAL_RESPONSE_TOKENS.")
            if httpx is None:
                raise ValueError("httpx tidak tersedia. Instal dependensi proyek terlebih dahulu.")
            ttl_seconds = int(response_ttl_dropdown.value or "300")
            if ttl_seconds not in {300, 900, 1800}:
                raise ValueError("TTL harus 5, 15, atau 30 menit.")
            totp_code = (response_totp_field.value or "").strip()
            if len(totp_code) != 6 or not totp_code.isdigit():
                raise ValueError("Masukkan kode TOTP 6 digit dari authenticator untuk two-factor response.")
            payload = {"action": "TEMP_BLOCK_IP", "source_ip": source_ip, "ttl_seconds": ttl_seconds,
                       "reason": reason, "confirmation": confirmation, "totp_code": totp_code}
            base = settings.base_url.rstrip("/")
            headers = {"Authorization": f"Bearer {response_token}", "X-KAWAL-Device-ID": settings.device_id,
                       "Content-Type": "application/json", "Accept": "application/json"}
            def post_action() -> tuple[int, dict[str, Any]]:
                with httpx.Client(timeout=httpx.Timeout(10.0, connect=4.0), verify=True, follow_redirects=False) as client:
                    response = client.post(base + "/api/v1/response-actions", headers=headers, json=payload)
                    try:
                        data = response.json()
                    except ValueError:
                        data = {"error": "response_not_json"}
                    return response.status_code, data if isinstance(data, dict) else {"error": "invalid_response"}
            status_code, data = await asyncio.to_thread(post_action)
            if status_code != 202:
                raise ValueError(f"Server menolak permintaan (HTTP {status_code}; {str(data.get('error', 'no_detail'))[:100]}). Periksa API, allowlist admin dan worker.")
            store.add_event("RESPONSE", session["username"], "server-response-request", {
                "action": "temporary_ip_block_requested", "server_profile": active_server_id,
                "source_ip": source_ip, "ttl_seconds": ttl_seconds, "reason": reason,
                "server_action_id": str(data.get("action_id", ""))[:80], "status": "PENDING_WORKER",
            })
            response_status_text.value = f"DIANTREKAN · {source_ip} · {ttl_seconds}s · ID {str(data.get('action_id', ''))[:18]} · tunggu status worker; bukan bukti bahwa blok telah aktif"
            response_status_text.color = C["amber"]
            response_confirm_field.value = ""
            response_totp_field.value = ""
            page.update()
            set_notice("Permintaan masuk antrean server. Pemblokiran baru dianggap aktif setelah worker mengonfirmasi; sesi yang sudah aktif mungkin tetap hidup.", "warning")
        except Exception as exc:
            response_status_text.value = f"RESPONS DITOLAK / GAGAL · {str(exc)[:220]}"
            response_status_text.color = C["red"]
            page.update()
            set_notice("Tidak ada aksi firewall yang diklaim berhasil. Periksa koneksi, izin, alasan, dan allowlist.", "danger")

    async def request_windows_response_action(_: ft.ControlEvent | None = None) -> None:
        """Queue a two-confirmation Windows response; the enrolled host revalidates locally."""
        if session["role"] != "admin":
            set_notice("Hanya admin lokal yang dapat mengajukan respons Windows.", "danger")
            return
        try:
            if not active_server_id or connected_server_id != active_server_id:
                raise ValueError("Hubungkan profile server terlebih dahulu.")
            settings = current_server_settings()
            if settings.connector_type != "kawal_trace_api":
                raise ValueError("Respons Windows hanya didukung oleh Kawal Trace API yang kamu administrasikan; Generic REST tetap read-only.")
            host_id = (windows_target_host_field.value or "").strip()
            if not host_id or host_id not in current_feed_hosts:
                raise ValueError("Host ID harus muncul pada feed server yang baru diambil. Pastikan agen Windows terdaftar dan sudah mengirim heartbeat/event.")
            action = str(windows_action_dropdown.value or "").upper()
            target = (windows_target_value_field.value or "").strip()
            target_user = (windows_target_user_field.value or "").strip()
            process_name = (windows_process_name_field.value or "").strip().lower()
            if action == "WINDOWS_BLOCK_IP":
                parsed = ipaddress.ip_address(target)
                if parsed.version != 4 or not parsed.is_global:
                    raise ValueError("Target firewall harus IPv4 publik.")
                source_ip = str(parsed)
                if (host_id, source_ip) not in current_feed_windows_auth_ips:
                    raise ValueError("IP harus berasal dari event AUTH_FAILURE windows-eventlog pada host yang dipilih.")
                parameters = {"source_ip": source_ip}
                confirmation_expected = f"BLOCK {source_ip}"
                ttl_seconds = int(response_ttl_dropdown.value or "300")
                if ttl_seconds not in {300, 900, 1800}:
                    raise ValueError("TTL harus 5, 15, atau 30 menit.")
            elif action == "WINDOWS_LOGOFF_SESSION":
                try:
                    session_id = int(target)
                except ValueError as exc:
                    raise ValueError("Target harus Session ID numerik dari sesi RDP aktif.") from exc
                if session_id <= 0 or not target_user:
                    raise ValueError("Session ID dan username target wajib diisi.")
                parameters = {"session_id": session_id, "target_user": target_user}
                confirmation_expected = f"LOGOFF {session_id} {target_user}"
                ttl_seconds = 300
            elif action == "WINDOWS_TERMINATE_PROCESS":
                try:
                    pid = int(target)
                except ValueError as exc:
                    raise ValueError("Target harus PID numerik dari proses yang benar-benar diperiksa.") from exc
                if pid <= 4 or not target_user or process_name not in {"cmd.exe", "powershell.exe", "pwsh.exe", "wt.exe", "windowsterminal.exe"}:
                    raise ValueError("PID, username, dan nama shell allowlist wajib sesuai.")
                parameters = {"pid": pid, "target_user": target_user, "process_name": process_name}
                confirmation_expected = f"TERMINATE {pid} {process_name}"
                ttl_seconds = 300
            else:
                raise ValueError("Jenis tindakan Windows tidak didukung.")
            reason = (windows_response_reason_field.value or "").strip()
            if len(reason) < 8:
                raise ValueError("Alasan/tiket minimal 8 karakter.")
            confirmation = (windows_response_confirm_field.value or "").strip()
            if confirmation != confirmation_expected:
                raise ValueError(f"Konfirmasi tidak cocok. Ketik tepat: {confirmation_expected}")
            totp_code = (windows_response_totp_field.value or "").strip()
            if len(totp_code) != 6 or not totp_code.isdigit():
                raise ValueError("Masukkan TOTP 6 digit. Ini harus dipakai bersama konfirmasi target secara eksplisit.")
            response_token = await _load_response_token()
            if not response_token:
                raise ValueError("Token respons khusus belum disimpan. Jangan gunakan token monitor sebagai pengganti.")
            if httpx is None:
                raise ValueError("httpx tidak tersedia.")
            payload = {"target_host_id": host_id, "action": action, "parameters": parameters,
                       "ttl_seconds": ttl_seconds, "reason": reason, "confirmation": confirmation,
                       "totp_code": totp_code}
            headers = {"Authorization": f"Bearer {response_token}", "X-KAWAL-Device-ID": settings.device_id,
                       "Content-Type": "application/json", "Accept": "application/json"}
            def queue_action() -> tuple[int, dict[str, Any]]:
                with httpx.Client(timeout=httpx.Timeout(10.0, connect=4.0), verify=True, follow_redirects=False) as client:
                    response = client.post(settings.base_url.rstrip("/") + "/api/v1/windows/response-actions", headers=headers, json=payload)
                    try:
                        body = response.json()
                    except ValueError:
                        body = {"error": "response_not_json"}
                    return response.status_code, body if isinstance(body, dict) else {"error": "invalid_response"}
            status_code, data = await asyncio.to_thread(queue_action)
            if status_code != 202:
                raise ValueError(f"Server menolak aksi (HTTP {status_code} · {str(data.get('error','no_detail'))[:120]}). Respons Windows/Host harus diaktifkan secara eksplisit di server dan endpoint.")
            action_id = str(data.get("action_id", ""))[:80]
            store.add_event("RESPONSE", session["username"], "windows-response-request", {
                "server_profile": active_server_id, "target_host_id": host_id, "action": action,
                "parameters": parameters, "reason": reason, "action_id": action_id, "status": "PENDING_ENDPOINT_POLICY",
            })
            windows_response_status_text.value = f"DIANTREKAN · {action} · host={host_id} · action_id={action_id} · belum dieksekusi; endpoint wajib memvalidasi lagi"
            windows_response_status_text.color = C["amber"]
            windows_response_confirm_field.value = ""
            windows_response_totp_field.value = ""
            await refresh_response_actions(quiet=True)
            page.update()
            set_notice("Aksi Windows masuk antrean. Ini belum berarti sesi diputus atau firewall aktif; tunggu konfirmasi agen Windows.", "warning")
        except Exception as exc:
            windows_response_status_text.value = f"DITOLAK / GAGAL · {str(exc)[:220]}"
            windows_response_status_text.color = C["red"]
            page.update()
            set_notice("Tidak ada klaim bahwa penindakan berhasil. Periksa izin, target, TOTP, kebijakan dan status agen.", "danger")

    async def background_telemetry_loop() -> None:
        """Safety-net poll of the security feed while the app is open and configured.

        Every five seconds without a stream; much rarer while the real-time stream is genuinely connected."""
        while alive["on"]:
            await asyncio.sleep(poll_interval_seconds(live_stream["state"]))
            if not alive["on"]:
                return
            if not active_server_id or connected_server_id != active_server_id or not current_server_settings().base_url:
                continue
            settings = current_server_settings()
            token = await _load_monitor_token()
            # A read-only REST feed may intentionally use no token or OAuth managed
            # by its adapter. Do not silently disable its automatic polling merely
            # because the Kawal Trace API monitor token is absent.
            generic_public_or_oauth = (
                settings.connector_type == "generic_rest_readonly"
                and (settings.feed_auth_mode == "none" or getattr(settings, "adapter_protocol", "rest") == "oauth2_rest")
            )
            if not token and not generic_public_or_oauth:
                continue
            await refresh_server_feed(quiet=True)
            await refresh_response_actions(quiet=True)

    # Remote server filesystem monitoring is driven by the Linux Server Agent feed.
    # The dashboard does not scan a folder on the operator's device and exposes no
    # local choose/start/stop controls for a remote server path.

    # --- Local account administration -------------------------------------
    new_operator_name = ft.TextField(label="Username baru (4–10 karakter)", hint_text="4–10 karakter", max_length=10, text_size=12, **field_style())
    new_operator_password = ft.TextField(
        label="Kata sandi awal (8–128 karakter)", password=True, can_reveal_password=True,
        max_length=128, text_size=12, **field_style(),
    )
    admin_current_password = ft.TextField(
        label="Kata sandi administrator saat ini", password=True, can_reveal_password=True,
        text_size=12, **field_style(),
    )
    admin_new_username = ft.TextField(
        label="Username baru (4–10 karakter)", value=session["username"] if len(session["username"]) <= 10 else "",
        hint_text="4–10 karakter", max_length=10, text_size=12, **field_style(),
    )
    admin_new_password = ft.TextField(
        label="Kata sandi baru (8–128 karakter)", password=True, can_reveal_password=True,
        max_length=128, text_size=12, **field_style(),
    )
    admin_confirm_password = ft.TextField(
        label="Ulangi kata sandi baru", password=True, can_reveal_password=True,
        max_length=128, text_size=12, **field_style(),
    )
    admin_credential_status = ft.Text("", size=11, color=C["muted"], selectable=True)
    account_list = ft.Column(spacing=5)

    def refresh_accounts() -> None:
        try:
            users = registry.list_users()
            account_list.controls = [
                ft.Row(
                    controls=[
                        ft.Icon(ft.Icons.PERSON_OUTLINE, size=15, color=C["lime"] if user["active"] else C["red"]),
                        ft.Text(user["username"], size=11, color=C["text"], expand=True),
                        tag(str(user["role"]).upper(), C["lime"] if user["role"] == "admin" else C["muted"]),
                    ], spacing=8,
                ) for user in users
            ]
        except Exception as exc:
            account_list.controls = [ft.Text(f"Daftar akun tidak dapat dibaca: {exc}", color=C["red"], size=11)]

    def update_admin_credentials_click(_: ft.ControlEvent | None = None) -> None:
        if session["role"] != "admin":
            admin_credential_status.value = "Hanya administrator yang dapat mengubah kredensial administrator."
            admin_credential_status.color = C["red"]
            page.update()
            return
        if (admin_new_password.value or "") != (admin_confirm_password.value or ""):
            admin_credential_status.value = "Kata sandi baru dan konfirmasi tidak sama."
            admin_credential_status.color = C["red"]
            page.update()
            return
        old_username = session["username"]
        try:
            changed = registry.change_admin_credentials(
                old_username,
                admin_current_password.value or "",
                admin_new_username.value or "",
                admin_new_password.value or "",
            )
            try:
                store.add_event(
                    "AUTH", old_username, "account-registry",
                    {"action": "admin_credentials_changed", "new_username": changed["username"], "result": "success",
                     "device_id": session.get("device_id", "unavailable"), "platform": session.get("platform", "unknown")},
                )
            except Exception:
                # Credential updates must not be reported as failed only because audit append failed.
                pass
            session["username"] = changed["username"]
            admin_current_password.value = ""
            admin_new_password.value = ""
            admin_confirm_password.value = ""
            admin_new_username.value = changed["username"]
            admin_credential_status.value = "Kredensial berhasil diperbarui. Login berikutnya memakai username dan kata sandi baru."
            admin_credential_status.color = C["green"]
            refresh_accounts()
            set_notice("Kredensial administrator diperbarui.", "good")
        except AuthenticationError as exc:
            admin_credential_status.value = str(exc)
            admin_credential_status.color = C["red"]
        except Exception as exc:
            admin_credential_status.value = f"Kredensial tidak berubah: {type(exc).__name__}. Periksa log aplikasi."
            admin_credential_status.color = C["red"]
        page.update()

    @requires_step_up("membuat akun pengguna")
    def create_account(role: str) -> None:
        if session["role"] != "admin":
            set_notice("Hanya administrator yang boleh mendaftarkan akun.", "warning")
            return
        try:
            user = registry.add_user(new_operator_name.value or "", new_operator_password.value or "", role)
            store.add_event(
                "AUTH", session["username"], "account-registry",
                {"action": "account_created", "new_username": user["username"], "role": user["role"],
                 "device_id": session.get("device_id", "unavailable"), "platform": session.get("platform", "unknown")},
            )
            new_operator_name.value = ""
            new_operator_password.value = ""
            refresh_accounts()
            refresh_summary()
            set_notice(f"Akun {user['role']} {user['username']} berhasil dibuat.", "good")
        except (AuthenticationError, ChainLogError) as exc:
            set_notice(f"Tidak dapat membuat akun: {exc}", "danger")

    def create_operator(_: ft.ControlEvent | None = None) -> None:
        create_account("operator")

    def create_viewer(_: ft.ControlEvent | None = None) -> None:
        create_account("viewer")

    def review_alarm(_: ft.ControlEvent | None = None) -> None:
        if session["role"] != "admin":
            set_notice("Hanya administrator yang dapat menetapkan hasil tinjauan alarm.", "warning")
            return
        try:
            sequence = int((review_seq_field.value or "").strip())
            decision = (review_decision_field.value or "").strip().lower()
            note = (review_notes_field.value or "").strip()
            if decision not in {"authorized", "suspicious"}:
                raise ValueError("Penilaian harus 'authorized' atau 'suspicious'.")
            records_for_review = store.records()
            target = next((item for item in records_for_review if int(item.get("seq", -1)) == sequence), None)
            if not target:
                raise ValueError("Nomor record tidak ditemukan.")
            target_details = target.get("details", {})
            if not isinstance(target_details, dict):
                raise ValueError("Detail record tidak valid.")
            is_local_file_alarm = (
                target.get("event_type") == "ALERT"
                and target_details.get("classification") == "UNATTRIBUTED_EXTERNAL_CHANGE"
            )
            is_remote_file_event = (
                target.get("event_type") == "CONFIG"
                and str(target_details.get("source_event_type", "")).upper() == "FILE_CHANGE"
            )
            if not (is_local_file_alarm or is_remote_file_event):
                raise ValueError("Record tersebut bukan perubahan file dari sumber pemantauan.")
            already_reviewed = any(
                item.get("event_type") == "CONFIG"
                and isinstance(item.get("details"), dict)
                and item["details"].get("action") == "alert_reviewed"
                and str(item["details"].get("alert_seq")) == str(sequence)
                for item in records_for_review
            )
            if already_reviewed:
                raise ValueError("Alarm ini sudah memiliki catatan hasil tinjauan.")
            store.add_event(
                "CONFIG", session["username"], "manual-alert-review",
                {
                    "action": "alert_reviewed", "alert_seq": sequence,
                    "decision": decision, "reviewer": session["username"],
                    "review_notes": note or "Tidak ada catatan tambahan.",
                    "relative_path": target_details.get("relative_path") or target_details.get("path"),
                    "original_classification": "UNATTRIBUTED_EXTERNAL_CHANGE",
                    "warning": "Penilaian ini adalah keputusan admin, bukan atribusi otomatis dari sistem operasi.",
                },
            )
            refresh_summary()
            if decision == "authorized":
                set_notice(f"Alarm #{sequence} ditinjau sebagai perubahan sah oleh admin; event asli tetap disimpan.", "good")
            else:
                set_notice(f"Alarm #{sequence} ditinjau sebagai mencurigakan; event asli tetap disimpan.", "danger")
        except (ValueError, ChainLogError) as exc:
            set_notice(f"Tinjauan tidak disimpan: {exc}", "warning")

    metrics = ft.ResponsiveRow(
        controls=[
            ft.Container(content=metric_card("TOTAL RECORD", total_value, "01", "Jejak tersimpan"), col={"xs": 12, "sm": 6, "md": 2}),
            ft.Container(content=metric_card("ALGORITMA", ft.Text("SHA-256", size=21, weight=ft.FontWeight.BOLD, color=C["text"]), "02", "Hash kriptografis"), col={"xs": 12, "sm": 6, "md": 2}),
            ft.Container(content=metric_card("PENYIMPANAN", ft.Text("SQLite", size=21, weight=ft.FontWeight.BOLD, color=C["text"]), "03", "File lokal perangkat"), col={"xs": 12, "sm": 6, "md": 2}),
            ft.Container(content=metric_card("AKTIVITAS TERAKHIR", last_value, "04", "Waktu UTC tersimpan"), col={"xs": 12, "sm": 6, "md": 3}),
            ft.Container(content=metric_card("ALARM / REVIEW", alert_value, "05", "Perubahan butuh tinjauan"), col={"xs": 12, "sm": 6, "md": 3}),
        ], spacing=10, run_spacing=10,
    )

    monitor_panel = panel(
        ft.Column(
            controls=[
                ft.Row(
                    controls=[
                        section_heading(
                            "PEMANTAUAN FOLDER SERVER", "Pemantauan integritas server otomatis",
                            "Aplikasi menerima event perubahan dari Linux Server Agent. Tidak ada pemilihan folder lokal atau tombol mulai/hentikan di sini.",
                        ),
                        ft.Container(expand=True),
                        ft.Container(
                            content=ft.Icon(ft.Icons.RADAR, color=C["lime"], size=22),
                            width=42, height=42, bgcolor=C["panel_alt"], border_radius=10,
                            alignment=ft.Alignment(0, 0),
                        ),
                    ], vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Container(
                    content=ft.Row(
                        controls=[
                            ft.Icon(ft.Icons.FOLDER_OPEN, color=C["lime"], size=18),
                            ft.Column(controls=[label("ROOT SERVER YANG DIPANTAU OTOMATIS"), monitor_path_text], spacing=4, expand=True),
                        ], spacing=11, vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ), padding=12, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=9,
                ),
                ft.Row(
                    controls=[ft.Container(width=7, height=7, bgcolor=C["quiet"], border_radius=8), monitor_status_text],
                    spacing=8,
                ),
                monitor_detail_text,
                ft.Divider(color=C["line"], height=1),
                label("PERUBAHAN FILE TERAKHIR DARI SERVER"),
                monitor_last_event_text,
                ft.Divider(color=C["line"], height=1),
                ft.Row(
                    controls=[
                        ft.Icon(ft.Icons.WARNING_AMBER, color=C["amber"], size=17),
                        ft.Text(
                            "Auditd mencatat file baru (termasuk hasil salin ke root), perubahan, rename, dan penghapusan. Pembacaan/salin-keluar root tidak dipantau rule ini. Event tidak membuktikan pelaku hacker; akun/proses harus ditinjau dari log server.",
                            size=10, color=C["muted"], selectable=True, expand=True,
                        ),
                    ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.START,
                ),
                ft.Divider(color=C["line"], height=1),
                section_heading("TINJAUAN ADMIN", "Tinjau perubahan file", "Masukkan nomor record lokal yang mengacu pada event FILE_CHANGE dari server. Keputusan ditambahkan sebagai record baru, event asli tidak diubah."),
                review_seq_field,
                review_decision_field,
                review_notes_field,
                ft.OutlinedButton(
                    content="Simpan hasil tinjauan", icon=ft.Icons.FACT_CHECK,
                    on_click=review_alarm, style=ft.ButtonStyle(color=C["amber"]),
                    disabled=session["role"] != "admin",
                ),
            ], spacing=12,
        ), padding=17,
    )

    result_panel = ft.Container(
        content=ft.Column(
            controls=[
                ft.Row(controls=[label("CHAIN HEALTH"), tag("CHECKPOINT LOCAL")], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Row(
                    controls=[
                        ft.Container(content=result_icon, width=49, height=49, bgcolor=C["panel_lift"], border_radius=11, alignment=ft.Alignment(0, 0)),
                        ft.Column(controls=[result_flag, result_title], spacing=5, expand=True),
                    ], spacing=13, vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                result_desc,
                ft.Divider(color=C["line"], height=1),
                ft.Row(controls=[result_count], spacing=4),
                result_head,
                ft.Row(
                    controls=[
                        ft.FilledButton(content="Verifikasi rantai", icon=ft.Icons.VERIFIED_USER, on_click=run_verification,
                                        bgcolor=C["lime"], color=C["black"], icon_color=C["black"]),
                        ft.OutlinedButton(content="Simulasikan manipulasi", icon=ft.Icons.WARNING_AMBER, on_click=run_simulation,
                                          style=ft.ButtonStyle(color=C["amber"])),
                    ], spacing=9, wrap=True,
                ),
            ], spacing=13,
        ),
        padding=18, bgcolor=C["panel"], border=ft.Border.all(1, C["line"]), border_radius=14,
    )

    event_form = panel(
        ft.Column(
            controls=[
                section_heading("CATATAN AUDIT", "Catat aktivitas", "Record baru masuk ke rantai setelah validasi."),
                event_type,
                actor_field,
                source_field,
                details_field,
                ft.FilledButton(
                    content="Simpan record", icon=ft.Icons.ADD, on_click=add_log, width=220,
                    bgcolor=C["lime"], color=C["black"], icon_color=C["black"],
                    disabled=session["role"] == "viewer",
                ),
                ft.Text("Aktor diambil dari sesi login dan tidak bisa diedit manual.", size=10, color=C["quiet"]),
                ft.Text("Jenis event: SYSTEM, AUTH, ACCESS, CONFIG, ALERT, NOTE, VERIFY.", size=10, color=C["quiet"]),
            ], spacing=11,
        ), padding=17,
    )

    activity_header = ft.Row(
        controls=[section_heading("JEJAK AUDIT", "Jejak aktivitas", "Record terakhir, ditampilkan dari yang terbaru."),
                  ft.Container(expand=True), shown_count],
        vertical_alignment=ft.CrossAxisAlignment.END,
    )
    activity_panel = panel(
        ft.Column(controls=[activity_header, search_field, log_list], spacing=13), padding=16,
    )

    export_json_button = responsive_width(
        ft.FilledButton(content="Ekspor JSON + checkpoint", icon=ft.Icons.DATA_OBJECT, on_click=export_json,
                        bgcolor=C["panel_lift"], color=C["text"], icon_color=C["lime"], width=260), 260, 100,
    )
    export_csv_button = responsive_width(
        ft.OutlinedButton(content="Ekspor tabel CSV", icon=ft.Icons.TABLE_CHART, on_click=export_csv,
                          style=ft.ButtonStyle(color=C["text"]), width=260), 260, 100,
    )
    export_panel = panel(
        ft.Column(
            controls=[
                section_heading("BUKTI AUDIT", "Paket bukti", "Ekspor untuk diperiksa di luar aplikasi."),
                export_json_button,
                export_csv_button,
                ft.Divider(color=C["line"], height=1),
                label("HEAD HASH / TERAKHIR"),
                head_value,
                label("PENYIMPANAN DATA"),
                db_value,
                ft.Text("Hash chain memberi bukti perubahan, bukan jaminan anti-perusakan mutlak. Untuk audit produksi, simpan checkpoint di sistem tepercaya yang terpisah.", size=10, color=C["quiet"]),
            ], spacing=11,
        ), padding=17,
    )

    server_profile_dropdown.on_select = select_server_profile

    sync_panel = panel(
        ft.Column(
            controls=[
                ft.Row(
                    controls=[section_heading(
                        "SINKRONISASI SERVER", "Integrasi server pusat",
                        "Pilih konektor Kawal Trace API (upload + feed) atau Universal API read-only dengan mapping JSON. Hanya hubungkan server/API yang memang kamu miliki atau diberi izin oleh pemiliknya.",
                    ), ft.Container(expand=True), ft.Icon(ft.Icons.CLOUD_SYNC, size=23, color=C["lime"])],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Container(
                    content=ft.Column(controls=[
                        ft.Text("WIZARD INTEGRASI · PILIH JENIS SERVER", size=11, color=C["lime"], weight=ft.FontWeight.BOLD),
                        integration_mode_dropdown,
                        integration_mode_help,
                        ft.Row(controls=[
                            ft.FilledButton(content="Terapkan pilihan", icon=ft.Icons.CHECK_CIRCLE,
                                            on_click=apply_integration_wizard_mode, bgcolor=C["panel_lift"], color=C["text"],
                                            disabled=session["role"] != "admin"),
                            ft.OutlinedButton(content="Cari endpoint REST", icon=ft.Icons.SEARCH,
                                              on_click=detect_api_endpoint_click, disabled=session["role"] != "admin"),
                            ft.OutlinedButton(content="Uji koneksi", icon=ft.Icons.CLOUD_DONE,
                                              on_click=test_server_connection),
                        ], wrap=True, spacing=8),
                        integration_wizard_result,
                        ft.ResponsiveRow(controls=[
                            ft.Container(content=ft.Container(content=wizard_api_status_text, padding=8, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8), col={"xs":12,"md":6}),
                            ft.Container(content=ft.Container(content=wizard_feed_status_text, padding=8, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8), col={"xs":12,"md":6}),
                            ft.Container(content=ft.Container(content=wizard_agent_status_text, padding=8, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8), col={"xs":12,"md":6}),
                            ft.Container(content=ft.Container(content=wizard_detection_status_text, padding=8, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8), col={"xs":12,"md":6}),
                            ft.Container(content=ft.Container(content=wizard_notification_status_text, padding=8, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8), col={"xs":12,"md":12}),
                        ], spacing=8, run_spacing=8),
                    ], spacing=9),
                    padding=12, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=10,
                ),
                ft.ResponsiveRow(
                    controls=[
                        ft.Container(content=server_profile_dropdown, col={"xs": 12, "md": 8}),
                        ft.Container(content=ft.FilledButton(
                            content="Tambah server", icon=ft.Icons.ADD_LINK,
                            on_click=prepare_new_server, bgcolor=C["panel_lift"], color=C["text"],
                            disabled=session["role"] != "admin",
                        ), col={"xs": 12, "md": 4}),
                    ], spacing=10, run_spacing=8,
                ),
                server_name_field,
                sync_server_field,
                monitor_token_field,
                generic_rest_settings_panel,
                kawal_api_advanced_paths_toggle,
                kawal_api_advanced_paths_panel,
                connector_mode_help_text,
                ft.Text(
                    "Tidak ada konektor yang otomatis dapat membaca semua server hanya dari domain/IP. API harus menyediakan event yang memang boleh diakses. Untuk meninjau host Linux, log sumber harus dikumpulkan oleh agent/collector yang disetujui. HTTPS dan verifikasi sertifikat tetap aktif.",
                    size=10, color=C["quiet"], selectable=True,
                ),
                sync_device_id_field,
                ft.Container(
                    content=ft.Column(controls=[
                        ft.Text("AKSES ANGGOTA OTOMATIS", size=11, weight=ft.FontWeight.BOLD, color=C["lime"]),
                        ft.Text(
                            "Anggota tidak perlu menempel token audit/pemantauan/respons. Isi URL server lalu tekan Minta Akses; pemilik menyetujui Device ID dari konsol administrator. Setelah disetujui, tekan Hubungkan lagi untuk mengambil kredensial otomatis.",
                            size=10, color=C["quiet"], selectable=True,
                        ),
                        ft.Row(controls=[
                            ft.OutlinedButton(content="Minta Akses / Ambil Token Otomatis", icon=ft.Icons.PERSON_ADD,
                                              on_click=request_current_device_access),
                        ], wrap=True, spacing=8),
                        member_totp_seed_field,
                        ft.Divider(color=C["line"]),
                        ft.Text("KELOLA ANGGOTA SERVER · PEMILIK SERVER SAJA", size=11, weight=ft.FontWeight.BOLD, color=C["amber"]),
                        admin_token_field,
                        ft.Row(controls=[
                            ft.OutlinedButton(content="Simpan Token Admin", icon=ft.Icons.KEY,
                                              on_click=save_admin_token_click, disabled=session["role"] != "admin"),
                            ft.OutlinedButton(content="Muat Anggota", icon=ft.Icons.REFRESH,
                                              on_click=refresh_member_list_click, disabled=session["role"] != "admin"),
                        ], wrap=True, spacing=8),
                        member_device_id_field,
                        ft.Row(controls=[
                            ft.FilledButton(content="Tambah / Setujui Anggota", icon=ft.Icons.PERSON_ADD,
                                            on_click=add_member_click, bgcolor=C["panel_lift"], color=C["text"],
                                            disabled=session["role"] != "admin"),
                            ft.OutlinedButton(content="Keluarkan Anggota", icon=ft.Icons.PERSON_REMOVE,
                                              on_click=lambda e: asyncio.create_task(revoke_member_id((member_device_id_field.value or "").strip())),
                                              disabled=session["role"] != "admin"),
                        ], wrap=True, spacing=8),
                        membership_status_text,
                        membership_list,
                        ft.Divider(color=C["line"]),
                        ft.Text("TRUSTED ACCESS LOKAL · UNDANGAN AKTIVASI (Build 14)", size=11, weight=ft.FontWeight.BOLD, color=C["lime"]),
                        ft.Text(
                            "Admin memasukkan nama + email → sistem membuat undangan → anggota memasang aplikasi, "
                            "memverifikasi kode, dan mendaftarkan identitas perangkat + kunci kriptografi. "
                            "Bukan sekadar email terdaftar yang membuat seseorang dipercaya.",
                            size=10, color=C["quiet"], selectable=True,
                        ),
                        invite_name_field,
                        invite_email_field,
                        invite_role_dropdown,
                        ft.Row(controls=[
                            ft.FilledButton(
                                content="Buat Undangan Anggota", icon=ft.Icons.MAIL,
                                on_click=create_local_invitation_click,
                                bgcolor=C["lime"], color=C["black"],
                                disabled=session["role"] != "admin",
                            ),
                            ft.OutlinedButton(
                                content="Muat Trusted Access", icon=ft.Icons.REFRESH,
                                on_click=refresh_local_trusted_click,
                                disabled=session["role"] != "admin",
                            ),
                        ], wrap=True, spacing=8),
                        invite_code_display,
                        local_trusted_status,
                        local_trusted_list,
                        ft.Divider(color=C["line"]),
                        ft.Text("RIWAYAT INSIDEN · DETEKSI & PENINDAKAN", size=11, weight=ft.FontWeight.BOLD, color=C["amber"]),
                        ft.Text(
                            "Mencatat IP, akun, perangkat, sesi, klasifikasi, alasan, tindakan (force disconnect / IP block / revoke), "
                            "dan hasil. Force-disconnect live SSH membutuhkan response worker privileged + allow-list admin.",
                            size=10, color=C["quiet"], selectable=True,
                        ),
                        ft.Row(controls=[
                            ft.OutlinedButton(
                                content="Muat Riwayat Insiden", icon=ft.Icons.HISTORY,
                                on_click=refresh_incident_list_click,
                            ),
                            ft.OutlinedButton(
                                content="Catat Insiden Uji", icon=ft.Icons.BUG_REPORT,
                                on_click=record_test_incident_click,
                                disabled=session["role"] != "admin",
                            ),
                        ], wrap=True, spacing=8),
                        incident_status_text,
                        incident_list,
                    ], spacing=8),
                    padding=12, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=10,
                ),
                # Manual token entry is an optional compatibility path; normal members use server enrollment.
                manual_token_toggle_button,
                sync_token_field,
                response_token_field,
                ft.Container(
                    content=ft.Column(controls=[
                        ft.Text("AKSI PROFIL SERVER", size=11, weight=ft.FontWeight.BOLD, color=C["lime"]),
                        ft.Text(
                            "Simpan profil dulu, uji koneksi, lalu hubungkan. Kolom token yang tidak digunakan boleh kosong; "
                            "untuk mode Kawal Trace API, token perangkat adalah token upload/audit. Token pemantauan dan "
                            "respons adalah token terpisah dengan izin berbeda.",
                            size=10, color=C["quiet"], selectable=True,
                        ),
                        ft.Row(controls=[
                            ft.FilledButton(
                                content="Simpan Profil", icon=ft.Icons.SAVE,
                                on_click=save_sync_config, bgcolor=C["panel_lift"], color=C["text"],
                                disabled=session["role"] != "admin",
                            ),
                            ft.OutlinedButton(
                                content="Uji Koneksi", icon=ft.Icons.CLOUD_DONE,
                                on_click=test_server_connection,
                            ),
                            ft.FilledButton(
                                content="Hubungkan", icon=ft.Icons.LINK,
                                on_click=connect_selected_server, bgcolor=C["lime"], color=C["black"],
                            ),
                            ft.OutlinedButton(
                                content="Putuskan", icon=ft.Icons.LINK_OFF,
                                on_click=disconnect_selected_server,
                            ),
                        ], wrap=True, spacing=8),
                        ft.Row(controls=[
                            ft.OutlinedButton(
                                content="Hapus Profil", icon=ft.Icons.DELETE_OUTLINE,
                                on_click=remove_server_profile, disabled=session["role"] != "admin",
                            ),
                        ], wrap=True, spacing=8),
                        ft.Container(
                            content=ft.Row(controls=[ft.Icon(ft.Icons.CABLE, size=16, color=C["amber"]), server_connection_text], spacing=8),
                            padding=10, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8,
                        ),
                        ft.Container(
                            content=ft.Row(controls=[ft.Icon(ft.Icons.CLOUD_QUEUE, size=16, color=C["amber"]), sync_status_text], spacing=8),
                            padding=10, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8,
                        ),
                    ], spacing=8),
                    padding=12, bgcolor=C["panel_lift"], border=ft.Border.all(1, C["line"]), border_radius=10,
                ),
                ft.Divider(color=C["line"]),
                section_heading("ENKRIPSI E2EE", "Enkripsi end-to-end AES-256-GCM", "Private key tidak dikirim ke API. API hanya menyimpan ciphertext; metadata event minimum tetap terlihat untuk routing/deduplikasi."),
                e2ee_public_key_field,
                ft.Row(controls=[
                    ft.OutlinedButton(content="Buat receiver key", icon=ft.Icons.KEY,
                                      on_click=generate_e2ee_keypair_click, disabled=session["role"] != "admin"),
                    ft.OutlinedButton(content="Muat public key", icon=ft.Icons.REFRESH,
                                      on_click=refresh_e2ee_public_key),
                    ft.OutlinedButton(content="Ekspor backup terenkripsi", icon=ft.Icons.LOCK,
                                      on_click=export_e2ee_key_backup, disabled=session["role"] != "admin"),
                    ft.OutlinedButton(content="Impor backup", icon=ft.Icons.LOCK,
                                      on_click=import_e2ee_key_backup, disabled=session["role"] != "admin"),
                ], wrap=True, spacing=8),
                e2ee_backup_passphrase_field,
                e2ee_backup_json_field,
                e2ee_status_text,
                ft.Text("Salin hanya public key ke agen/API. Untuk Android, pindahkan backup private key terenkripsi + frasa sandi melalui kanal terpisah; jangan tempel private key plaintext di chat. Generic REST pihak ketiga hanya mendapat perlindungan TLS sesuai API mereka, bukan E2EE Kawal Trace.", size=10, color=C["amber"], selectable=True),
                ft.Text("RESPONS INSIDEN · tidak aktif secara default di server. Memerlukan token respons khusus, allowlist admin, alasan, konfirmasi eksplisit, dan worker firewall terpisah. Hanya mengantrekan blok IPv4 publik sementara (maksimal 30 menit) dari event SSH langsung; tidak cocok untuk visitor HTTP yang diproksi Cloudflare dan tidak memutus sesi lama.", size=10, color=C["amber"], selectable=True),
                ft.ResponsiveRow(controls=[
                    ft.Container(content=response_ip_field, col={"xs": 12, "md": 6}),
                    ft.Container(content=response_ttl_dropdown, col={"xs": 12, "md": 6}),
                    ft.Container(content=response_reason_field, col={"xs": 12, "md": 6}),
                    ft.Container(content=response_confirm_field, col={"xs": 12, "md": 6}),
                    ft.Container(content=response_totp_field, col={"xs": 12, "md": 6}),
                ], spacing=10, run_spacing=8),
                ft.Row(controls=[ft.FilledButton(content="Ajukan karantina IP sementara", icon=ft.Icons.SHIELD,
                    on_click=request_temporary_ip_quarantine, bgcolor=C["red"], color=C["text"], disabled=session["role"] != "admin")], wrap=True),
                response_status_text,
                ft.Row(controls=[ft.OutlinedButton(content="Periksa status karantina", icon=ft.Icons.REFRESH,
                    on_click=refresh_response_actions)], wrap=True),
                response_actions_list,
                ft.Divider(color=C["line"]),
                section_heading("RESPONS ENDPOINT WINDOWS", "Firewall & isolasi sesi Windows", "Memerlukan agen Windows Event Log yang sudah terdaftar, token host, TOTP, konfirmasi target yang diketik, bukti lokal di host, serta kebijakan pengguna/proses yang dilindungi. Nonaktif secara default di server dan endpoint."),
                ft.Text("Aksi tersedia hanya pada Windows host yang kamu administrasikan. Firewall block hanya untuk IP dari event 4625 pada host itu. Logoff RDP/terminate shell bisa mengganggu pengguna; jangan menargetkan akun/proses admin. Tindakan tidak berjalan sampai host mengonfirmasi status.", size=10, color=C["amber"], selectable=True),
                ft.ResponsiveRow(controls=[
                    ft.Container(content=windows_target_host_field, col={"xs": 12, "md": 6}),
                    ft.Container(content=windows_action_dropdown, col={"xs": 12, "md": 6}),
                    ft.Container(content=windows_target_value_field, col={"xs": 12, "md": 6}),
                    ft.Container(content=windows_target_user_field, col={"xs": 12, "md": 6}),
                    ft.Container(content=windows_process_name_field, col={"xs": 12, "md": 6}),
                    ft.Container(content=windows_response_reason_field, col={"xs": 12, "md": 6}),
                    ft.Container(content=windows_response_confirm_field, col={"xs": 12, "md": 6}),
                    ft.Container(content=windows_response_totp_field, col={"xs": 12, "md": 6}),
                ], spacing=10, run_spacing=8),
                ft.Row(controls=[ft.FilledButton(content="Ajukan respons Windows (TOTP + konfirmasi)", icon=ft.Icons.SHIELD,
                    on_click=request_windows_response_action, bgcolor=C["red"], color=C["text"], disabled=session["role"] != "admin"),
                    ft.OutlinedButton(content="Periksa status Windows", icon=ft.Icons.REFRESH, on_click=refresh_response_actions)], wrap=True),
                windows_response_status_text,
                windows_response_actions_list,
                ft.Text(
                    "Setiap server punya ID perangkat dan token tersendiri. Hubungkan mengaktifkan sinkronisasi/polling untuk profile terpilih; Putuskan hanya menghentikan koneksi client. "
                    "Hapus profile menghapus konfigurasi/token lokal saja—tidak menghapus server, log remote, atau service agen Linux. HTTPS dan validasi sertifikat selalu aktif.",
                    size=10, color=C["quiet"], selectable=True,
                ),
            ], spacing=12,
        ), padding=17,
    )

    archive_storage_mode_container = responsive_width(
        ft.Container(content=archive_storage_mode_dropdown, width=360), 360, 64,
    )
    archive_date_container = responsive_width(
        ft.Container(content=archive_date_dropdown, width=270), 270, 64,
    )
    archive_storage_mode_row = ft.Row(
        controls=[archive_storage_mode_container], spacing=9, wrap=True,
    )
    archive_remote_actions_row = ft.Row(controls=[
        ft.OutlinedButton(content="Ambil arsip lama dari server ke perangkat", icon=ft.Icons.DOWNLOAD, on_click=download_server_archive),
    ], spacing=8, wrap=True, visible=legacy_remote_archive)

    async def run_telemetry_pipeline_self_test(_: ft.ControlEvent | None = None) -> None:
        """Exercise production validation, detection and archive code with synthetic local events."""
        archive_status_text.value = "UJI PIPELINE BERJALAN · membuat event sintetis lokal…"
        archive_status_text.color = C["blue"]
        page.update()
        try:
            with tempfile.TemporaryDirectory(prefix="kawal-trace-selftest-") as temp_dir:
                result = await asyncio.to_thread(
                    run_telemetry_self_test, Path(temp_dir) / "telemetry-selftest.sqlite3"
                )
            stages = result["stages"]
            stage_text = " · ".join(f"{name}={state.upper()}" for name, state in stages.items())
            archive_status_text.value = (
                f"UJI PIPELINE {result['status'].upper()} · {stage_text} · "
                f"{result['synthetic_events']} event sintetis · {result['alerts']} alert "
                "· data uji sementara dihapus · tidak mengakses jaringan/server"
            )
            archive_status_text.color = C["green"]
            set_notice("Uji pipeline lokal berhasil: deteksi, arsip, baca ulang, dan deduplikasi.", "good")
        except Exception as exc:
            archive_status_text.value = f"UJI PIPELINE GAGAL · {type(exc).__name__}: {str(exc)[:180]}"
            archive_status_text.color = C["red"]
            set_notice("Uji pipeline lokal gagal; periksa pesan hasil uji.", "danger")
        page.update()

    server_feed_panel = panel(
        ft.Column(controls=[
            ft.Row(controls=[section_heading(
                "TELEMETRI SERVER", "Pemantauan aktivitas server",
                "Real-time lewat stream HTTPS dari server (Kawal Trace API 1.5.0+); bila server belum mendukung atau stream putus, aplikasi memakai polling dan status di bawah menyatakannya. Menampilkan waktu, IP sumber, GeoIP perkiraan, ASN/organisasi, dan metadata perangkat jika API mengirimkannya.",
            ), ft.Container(expand=True), ft.Icon(ft.Icons.SHIELD, size=22, color=C["lime"])]),
            ft.Row(controls=[
                ft.FilledButton(content="Ambil event server", icon=ft.Icons.REFRESH,
                                on_click=refresh_server_feed, bgcolor=C["panel_lift"], color=C["text"]),
                ft.OutlinedButton(content="Aktifkan / uji notifikasi", icon=ft.Icons.NOTIFICATIONS,
                                  on_click=enable_native_notifications),
                ft.OutlinedButton(content="Uji alarm suara", icon=ft.Icons.VOLUME_UP,
                                  on_click=test_security_alarm_sound),
                ft.OutlinedButton(content="Uji pipeline lokal", icon=ft.Icons.FACT_CHECK,
                                  on_click=run_telemetry_pipeline_self_test),
            ], spacing=8, wrap=True),
            notification_status_text,
            ft.Container(content=ft.Row(controls=[ft.Icon(ft.Icons.CLOUD_SYNC, size=16, color=C["amber"]), server_feed_status_text], spacing=8),
                         padding=11, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8),
            ft.Container(content=ft.Row(controls=[ft.Icon(ft.Icons.RADAR, size=16, color=C["amber"]), live_stream_status_text], spacing=8),
                         padding=11, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]), border_radius=8),
            server_feed_fleet_text,
            server_feed_summary_text,
            server_feed_list,
            ft.Divider(color=C["line"]),
            section_heading("ARSIP LOG", "Riwayat & ekspor log", "Log yang berhasil diterima disimpan lokal otomatis, dipisah menurut tanggal event UTC, dan tetap tersedia setelah aplikasi ditutup."),
            archive_storage_mode_row,
            ft.Text("Semua arsip disimpan di perangkat ini. Aplikasi tidak mengirim arsip, log audit, atau data pemindai ke server mana pun; server hanya dibaca untuk menerima event pemantauan.", size=10, color=C["muted"]),
            ft.Row(controls=[
                archive_date_container,
                ft.OutlinedButton(content="Perbarui arsip", icon=ft.Icons.REFRESH, on_click=refresh_archive_view),
            ], spacing=8, wrap=True),
            archive_remote_actions_row,
            archive_summary_text,
            ft.Text("Folder ekspor", size=10, color=C["muted"], weight=ft.FontWeight.BOLD),
            archive_export_directory_text,
            ft.Row(controls=[
                ft.OutlinedButton(content="Pilih folder", icon=ft.Icons.FOLDER_OPEN, on_click=choose_archive_export_folder),
                ft.OutlinedButton(content="Ekspor tanggal terpilih · JSON", icon=ft.Icons.DATA_OBJECT, on_click=export_server_feed_json),
                ft.OutlinedButton(content="Ekspor tanggal terpilih · CSV", icon=ft.Icons.TABLE_CHART, on_click=export_server_feed_csv),
                ft.OutlinedButton(content="Ekspor tanggal terpilih · PDF", icon=ft.Icons.PICTURE_AS_PDF, on_click=export_server_feed_pdf),
            ], spacing=8, wrap=True),
            archive_status_text,
            archive_preview_list,
            ft.Text("Panduan: pilih tanggal UTC atau Semua tanggal, lalu ekspor PDF untuk laporan, CSV untuk Excel, atau JSON untuk analisis. Mode Server saja mengambil pratinjau dan ekspor langsung dari API arsip; tombol Unduh arsip dari server ke perangkat membuat salinan lokal permanen. Aktifkan sinkronisasi waktu otomatis di OS.",
                    size=10, color=C["quiet"], selectable=True),
            ft.Text("Alarm suara dan notifikasi sistem berjalan untuk event BARU HIGH/CRITICAL saat aplikasi aktif dan feed tersambung. Pada HP, aplikasi Kawal Trace juga harus berjalan serta izin notifikasi diberikan. Push ke HP/laptop saat aplikasi benar-benar tertutup BELUM AKTIF karena backend push dan pendaftaran perangkat belum dikonfigurasi. MAC address penyerang dari internet tidak tersedia; lokasi IP hanya perkiraan. Feed kosong bukan bukti server aman.",
                    size=10, color=C["quiet"], selectable=True),
        ], spacing=11), padding=17,
    )

    account_panel = panel(
        ft.Column(
            controls=[
                section_heading("KREDENSIAL ADMINISTRATOR", "Ubah akun perangkat", "Masukkan kata sandi saat ini untuk mengganti username/kata sandi. Username baru 4–10 karakter; kata sandi baru 8–128 karakter."),
                admin_current_password,
                admin_new_username,
                admin_new_password,
                admin_confirm_password,
                ft.Row(controls=[ft.FilledButton(
                    content="Perbarui kredensial", icon=ft.Icons.KEY,
                    on_click=update_admin_credentials_click, bgcolor=C["panel_lift"], color=C["text"],
                    disabled=session["role"] != "admin",
                )], wrap=True),
                admin_credential_status,
                ft.Divider(color=C["line"]),
                section_heading("AKUN & AKSES", "Akun operator lokal", "Hanya administrator yang dapat mendaftarkan operator baru."),
                new_operator_name,
                new_operator_password,
                ft.Row(
                    controls=[
                        ft.FilledButton(
                            content="Daftarkan operator", icon=ft.Icons.PERSON_ADD,
                            on_click=create_operator, bgcolor=C["panel_lift"], color=C["text"],
                            disabled=session["role"] != "admin",
                        ),
                        ft.OutlinedButton(
                            content="Daftarkan viewer", icon=ft.Icons.PERSON_OUTLINE,
                            on_click=create_viewer, style=ft.ButtonStyle(color=C["muted"]),
                            disabled=session["role"] != "admin",
                        ),
                    ], wrap=True, spacing=8,
                ),
                ft.Divider(color=C["line"]),
                label("AKUN TERDAFTAR"),
                account_list,
                ft.Text("Akun ini hanya berlaku pada instalasi lokal ini; belum disinkronkan ke server pusat.", size=10, color=C["quiet"]),
            ], spacing=10,
        ), padding=17,
    )
    # Local device PIN is a quick-unlock factor for this installation only.
    device_pin_input = ft.TextField(
        label="PIN baru perangkat (8–12 angka)", password=True, can_reveal_password=False,
        max_length=12, **field_style(),
    )
    device_pin_confirm_input = ft.TextField(
        label="Ulangi PIN", password=True, can_reveal_password=False,
        max_length=12, **field_style(),
    )
    device_pin_status = ft.Text(
        "PIN perangkat belum diatur untuk akun ini." if not registry.has_device_pin(session["username"])
        else "PIN perangkat sudah aktif untuk akun ini.",
        size=10, color=C["muted"], selectable=True,
    )

    @requires_step_up("menyimpan PIN perangkat")
    def save_device_pin_click(_: ft.ControlEvent | None = None) -> None:
        pin_value = device_pin_input.value or ""
        if pin_value != (device_pin_confirm_input.value or ""):
            device_pin_status.value = "PIN dan konfirmasi tidak sama."
            device_pin_status.color = C["red"]
            page.update()
            return
        try:
            registry.set_device_pin(session["username"], pin_value)
            device_pin_input.value = ""
            device_pin_confirm_input.value = ""
            device_pin_status.value = "PIN perangkat tersimpan sebagai hash lokal. Pada login berikutnya, PIN atau biometrik perangkat bisa dipakai."
            device_pin_status.color = C["green"]
            set_notice("PIN perangkat diperbarui.", "good")
        except AuthenticationError as exc:
            device_pin_status.value = str(exc)
            device_pin_status.color = C["red"]
            page.update()

    @requires_step_up("menghapus PIN perangkat")
    def remove_device_pin_click(_: ft.ControlEvent | None = None) -> None:
        try:
            registry.remove_device_pin(session["username"])
            device_pin_status.value = "PIN perangkat dihapus. Login berikutnya memakai kata sandi akun lokal."
            device_pin_status.color = C["amber"]
            set_notice("PIN perangkat dihapus.", "warning")
        except AuthenticationError as exc:
            device_pin_status.value = str(exc)
            device_pin_status.color = C["red"]
            page.update()

    device_auth_panel = panel(ft.Column(controls=[
        section_heading("KEPERCAYAAN PERANGKAT", "PIN & biometrik perangkat", "PIN aplikasi disimpan sebagai hash PBKDF2 lokal. Biometrik memakai dialog autentikasi Windows/Android, bukan Google Login."),
        ft.Text("Masuk dengan kata sandi akun lokal dahulu, lalu atur PIN di sini. Jika perangkat mendukung flet-local-auth, layar login berikutnya dapat menampilkan sidik jari/wajah. Biometrik tidak dikirim ke server dan tidak menggantikan autentikasi API.", size=10, color=C["muted"], selectable=True),
        device_pin_input,
        device_pin_confirm_input,
        ft.Row(controls=[
            ft.FilledButton(content="Simpan PIN perangkat", icon=ft.Icons.LOCK, on_click=save_device_pin_click, bgcolor=C["panel_lift"], color=C["text"]),
            ft.OutlinedButton(content="Hapus PIN perangkat", icon=ft.Icons.LOCK_OPEN, on_click=remove_device_pin_click),
        ], wrap=True, spacing=8),
        device_pin_status,
    ], spacing=10), padding=16)

    # Private Network Access: explicit, operator-triggered tunnel controls.
    ztna_status_text = ft.Text("Status klien ZTNA belum diperiksa.", size=11, color=C["muted"], selectable=True)
    ztna_action_status = ft.Text("Belum ada tindakan koneksi tunnel.", size=10, color=C["muted"], selectable=True)
    ztna_setup_status = ft.Text("Runtime OpenZiti dapat disiapkan dari dashboard. Identity tetap harus diterbitkan oleh administrator jaringan.", size=10, color=C["muted"], selectable=True)
    ztna_target_host_field = ft.TextField(
        label="Host layanan privat", hint_text="contoh: 10.20.0.10 atau app.internal.ziti",
        text_size=11, width=300, **field_style(),
    )
    ztna_target_port_field = ft.TextField(
        label="Port TCP", value="443", keyboard_type=ft.KeyboardType.NUMBER,
        text_size=11, width=110, **field_style(),
    )
    ztna_probe_status_text = ft.Text("Uji jalur privat belum dijalankan.", size=10, color=C["muted"], selectable=True)
    wg_config_path: dict[str, str] = {"path": ""}
    wg_config_status = ft.Text("Belum ada konfigurasi WireGuard dipilih.", size=10, color=C["muted"], selectable=True)

    async def install_openziti_runtime_click(_: ft.ControlEvent | None = None) -> None:
        ztna_setup_status.value = "MENGAMBIL INSTALLER RESMI OPENZITI DAN MEMVERIFIKASI TANDA TANGAN…"
        ztna_setup_status.color = C["blue"]
        page.update()
        try:
            result = await asyncio.to_thread(download_and_launch_windows_installer)
            ztna_setup_status.value = (
                f"INSTALLER RESMI TERVERIFIKASI · versi {result['version']} · SHA-256 {result['sha256'][:16]}… · "
                "installer dibuka melalui UAC. Selesaikan instalasi, lalu periksa ulang runtime. "
                "Identity belum didaftarkan."
            )
            ztna_setup_status.color = C["green"]
        except OpenZitiSetupError as exc:
            ztna_setup_status.value = f"PENYIAPAN OPENZITI GAGAL · {str(exc)[:220]}"
            ztna_setup_status.color = C["red"]
        except Exception as exc:
            ztna_setup_status.value = f"PENYIAPAN OPENZITI GAGAL · {type(exc).__name__}: {str(exc)[:180]}"
            ztna_setup_status.color = C["red"]
        page.update()

    async def run_ztna_action(provider: str, action: str) -> None:
        label = "OpenZiti Edge Tunnel" if provider == "openziti" else "WireGuard"
        ztna_action_status.value = f"{label}: menjalankan {action.upper()}…"
        ztna_action_status.color = C["blue"]
        page.update()
        try:
            result = await asyncio.to_thread(
                manage_ztna_tunnel, provider, action,
                config_path=wg_config_path["path"] if provider == "wireguard" else None,
            )
            state = result["status"].upper()
            ztna_action_status.value = (
                f"{label} · PERINTAH {action.upper()} · {state} · {result['detail']}"
                + (" · Jalankan aplikasi sebagai Administrator/root jika ditolak OS."
                   if result.get("requires_admin") or result.get("status") == "error" else "")
            )
            ztna_action_status.color = C["green"] if result["status"] == "success" else C["amber"]
        except Exception as exc:
            ztna_action_status.value = f"{label} · {action.upper()} GAGAL · {type(exc).__name__}: {str(exc)[:180]}"
            ztna_action_status.color = C["red"]
        page.update()

    async def choose_wg_config(_: ft.ControlEvent | None = None) -> None:
        try:
            picked = await folder_picker.pick_files(
                dialog_title="Pilih konfigurasi WireGuard (.conf)", allow_multiple=False,
                file_type=ft.FilePickerFileType.CUSTOM, allowed_extensions=["conf"],
            )
            if not picked:
                return
            path = str(picked[0].path or "")
            if not path:
                wg_config_status.value = "File dipilih tetapi path lokal tidak tersedia pada platform ini."
                wg_config_status.color = C["amber"]
            else:
                from chainlog.advanced_security import validate_wireguard_config as _validate_wg
                config_text = await asyncio.to_thread(Path(path).read_text, encoding="utf-8")
                validation = _validate_wg(config_text)
                wg_config_path["path"] = path
                wg_config_status.value = (
                    f"KONFIGURASI VALID · {Path(path).name} · {validation['peer_count']} peer · "
                    f"{', '.join(validation['interface_addresses'])} · private key tidak ditampilkan"
                )
                wg_config_status.color = C["green"]
        except Exception as exc:
            wg_config_path["path"] = ""
            wg_config_status.value = f"KONFIGURASI DITOLAK · {type(exc).__name__}: {str(exc)[:180]}"
            wg_config_status.color = C["red"]
        page.update()

    async def probe_ztna_endpoint_click(_: ft.ControlEvent | None = None) -> None:
        host = str(ztna_target_host_field.value or "").strip()
        raw_port = str(ztna_target_port_field.value or "").strip()
        try:
            port = int(raw_port)
            ztna_probe_status_text.value = "MENGUJI KONEKSI TCP KE ENDPOINT…"
            ztna_probe_status_text.color = C["blue"]
            page.update()
            result = await asyncio.to_thread(probe_private_endpoint, host, port, timeout=3.0)
            if result["status"] == "reachable":
                ztna_probe_status_text.value = (
                    f"ENDPOINT TERJANGKAU · {result['host']}:{result['port']} · peer={result['peer']} · "
                    f"{result['elapsed_ms']} ms · {result['detail']}"
                )
                ztna_probe_status_text.color = C["green"]
            else:
                ztna_probe_status_text.value = (
                    f"ENDPOINT TIDAK TERJANGKAU · {result['host']}:{result['port']} · "
                    f"{result['elapsed_ms']} ms · {result['detail']}"
                )
                ztna_probe_status_text.color = C["amber"]
        except (AdvancedSecurityError, ValueError) as exc:
            ztna_probe_status_text.value = f"INPUT / UJI KONEKSI GAGAL · {str(exc)[:180]}"
            ztna_probe_status_text.color = C["red"]
        except Exception as exc:
            ztna_probe_status_text.value = f"UJI KONEKSI GAGAL · {type(exc).__name__}: {str(exc)[:160]}"
            ztna_probe_status_text.color = C["red"]
        page.update()

    async def check_ztna_click(_: ft.ControlEvent | None = None) -> None:
        ztna_status_text.value = "MEMERIKSA TOOL, VERSI, DAN STATUS RUNTIME…"
        ztna_status_text.color = C["blue"]
        page.update()
        try:
            status = await asyncio.to_thread(inspect_ztna_tools)
            lines: list[str] = []
            for label, path in status["available"].items():
                version = status["versions"].get(label, {})
                version_text = version.get("detail", "versi belum diperiksa")
                lines.append(f"{label}: {'TERPASANG' if path else 'BELUM TERPASANG'}"
                             + (f" · {path}" if path else "") + f" · versi: {version_text}")
            edge = status["edge_runtime"]
            wg = status["wireguard_runtime"]
            controller = status["controller_status"]
            lines.extend([
                f"OPENZITI EDGE RUNTIME: {edge['status'].upper()} · {edge['detail']}",
                f"  SERVICE: {status['edge_service']['status'].upper()} · {status['edge_service']['detail']}",
                f"  PROSES: {status['edge_process']['status'].upper()} · {status['edge_process']['detail']}",
                f"WIREGUARD INTERFACE: {wg['status'].upper()} · {wg['detail']}",
                f"CONTROLLER / IDENTITY: {controller['status'].upper()} · {controller['detail']}",
                status["recommendation"], status["dark_ip_note"],
            ])
            ztna_status_text.value = "\n".join(lines)
            ztna_status_text.color = C["green"] if status["installed_count"] else C["amber"]
        except Exception as exc:
            ztna_status_text.value = f"PEMERIKSAAN ZTNA GAGAL · {type(exc).__name__}: {str(exc)[:160]}"
            ztna_status_text.color = C["red"]
        page.update()

    ztna_panel = panel(ft.Column(controls=[
        section_heading("PRIVATE NETWORK ACCESS", "Private Network Access", "Satu tempat untuk mengelola koneksi OpenZiti dan WireGuard, lalu menguji layanan privat melalui tunnel yang aktif."),
        ft.Text("Kelola runtime OpenZiti dari dashboard. Di Windows, KAWAL TRACE mengambil installer resmi, memeriksa tanda tangan digital, lalu meminta UAC untuk memasang service tunneler. Setelah terpasang, pengguna tidak perlu membuka panel Desktop Edge setiap kali. Identity/JWT tetap harus diterbitkan oleh administrator Controller; KAWAL TRACE tidak membuat kredensial jaringan sendiri. Untuk VM Ubuntu, script scripts/setup_openziti_ubuntu.sh dan panduan docs/OPENZITI_KAWAL_TRACE_SETUP.md disertakan.", size=10, color=C["muted"], selectable=True),
        ft.Row(controls=[
            ft.FilledButton(content="Siapkan runtime OpenZiti Windows", icon=ft.Icons.DOWNLOAD, on_click=install_openziti_runtime_click, bgcolor=C["panel_lift"], color=C["text"]),
            ft.OutlinedButton(content="Periksa tools & status", icon=ft.Icons.SECURITY, on_click=check_ztna_click),
        ], wrap=True, spacing=8),
        ztna_setup_status, ztna_status_text,
        ft.Divider(color=C["line"]),
        ft.Text("OPENZITI EDGE TUNNEL", size=10, weight=ft.FontWeight.BOLD, color=C["lime"]),
        ft.Row(controls=[
            ft.FilledButton(content="Hubungkan OpenZiti", icon=ft.Icons.LINK, on_click=lambda e: run_ztna_action("openziti", "connect"), bgcolor=C["panel_lift"], color=C["text"]),
            ft.OutlinedButton(content="Putuskan OpenZiti", icon=ft.Icons.LINK_OFF, on_click=lambda e: run_ztna_action("openziti", "disconnect")),
        ], wrap=True, spacing=8),
        ft.Divider(color=C["line"]),
        ft.Text("WIREGUARD", size=10, weight=ft.FontWeight.BOLD, color=C["lime"]),
        ft.Row(controls=[
            ft.OutlinedButton(content="Pilih file konfigurasi .conf", icon=ft.Icons.FOLDER_OPEN, on_click=choose_wg_config),
            ft.FilledButton(content="Hubungkan WireGuard", icon=ft.Icons.LINK, on_click=lambda e: run_ztna_action("wireguard", "connect"), bgcolor=C["panel_lift"], color=C["text"]),
            ft.OutlinedButton(content="Putuskan WireGuard", icon=ft.Icons.LINK_OFF, on_click=lambda e: run_ztna_action("wireguard", "disconnect")),
        ], wrap=True, spacing=8),
        wg_config_status, ztna_action_status,
        ft.Divider(color=C["line"]),
        ft.Text("UJI AKSES LAYANAN PRIVAT", size=10, weight=ft.FontWeight.BOLD, color=C["lime"]),
        ft.Text("Jalankan koneksi OpenZiti atau WireGuard terlebih dahulu. Masukkan host dan port yang hanya tersedia melalui tunnel, lalu uji TCP. Endpoint yang terbuka lewat jalur lain tidak membuktikan ZTNA aktif.", size=10, color=C["muted"], selectable=True),
        ft.Row(controls=[ztna_target_host_field, ztna_target_port_field], spacing=8, wrap=True),
        ft.OutlinedButton(content="Uji koneksi endpoint privat", icon=ft.Icons.CABLE, on_click=probe_ztna_endpoint_click),
        ztna_probe_status_text,
    ], spacing=10), padding=16)

    # Offline email analysis: content never goes to the cloud unless the user explicitly
    # selects one URL for a PhishTank reputation lookup.
    email_message_field = ft.TextField(
        label="Tempel sumber email (.eml): header + isi", multiline=True, min_lines=5, max_lines=10,
        text_size=11, hint_text="From: ...\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail\nSubject: ...\n\nIsi email...",
        **field_style(),
    )
    phishing_status_text = ft.Text("Analisis email berjalan secara lokal; tautan tidak dibuka otomatis.", size=10, color=C["muted"], selectable=True)
    phishing_result_text = ft.Text("Belum ada hasil analisis.", size=11, color=C["muted"], selectable=True)
    phish_url_field = ft.TextField(label="URL yang dipilih untuk cek reputasi opsional", text_size=11, **field_style())
    phish_key_field = ft.TextField(label="API key PhishTank (opsional, tidak disimpan)", password=True, can_reveal_password=False, text_size=11, **field_style())

    def analyze_email_click(_: ft.ControlEvent | None = None) -> None:
        try:
            result = analyze_email(email_message_field.value or "")
            phish_url_field.value = (result["urls"][0] if result["urls"] else "")
            lines = [f"Penilaian: {result['verdict']} · skor indikator {result['score']}/100",
                     f"Pengirim: {result['from'] or '(tidak tercantum)'}",
                     f"Subjek: {result['subject'] or '(tidak tercantum)'}",
                     f"URL ditemukan: {result['url_count']}", "Temuan:"]
            lines.extend([f"• [{item['level'].upper()}] {item['message']}" for item in result["findings"][:12]])
            lines.append("Ini analisis heuristik, bukan keputusan pasti. Pesan tidak dihapus atau dikirim ke layanan eksternal.")
            phishing_result_text.value = "\n".join(lines)
            phishing_status_text.value = "Analisis lokal selesai. Periksa temuan sebelum mengambil tindakan."
            phishing_status_text.color = C["green"] if result["score"] < 20 else C["amber"] if result["score"] < 50 else C["red"]
            page.update()
        except AdvancedSecurityError as exc:
            phishing_status_text.value = str(exc)
            phishing_status_text.color = C["red"]
            page.update()

    async def phishtank_lookup_click(_: ft.ControlEvent | None = None) -> None:
        try:
            result = await asyncio.to_thread(
                check_phishtank_url, phish_url_field.value or "", phish_key_field.value or ""
            )
            phishing_status_text.value = (
                "URL terkonfirmasi phishing oleh PhishTank." if result["is_confirmed_phish"]
                else "PhishTank tidak mengonfirmasi URL ini pada hasil saat ini; itu bukan jaminan aman."
            )
            phishing_status_text.color = C["red"] if result["is_confirmed_phish"] else C["amber"]
            page.update()
        except AdvancedSecurityError as exc:
            phishing_status_text.value = str(exc)
            phishing_status_text.color = C["amber"]
            page.update()

    async def spamassassin_click(_: ft.ControlEvent | None = None) -> None:
        try:
            result = await asyncio.to_thread(run_spamassassin, email_message_field.value or "")
            phishing_result_text.value = json.dumps(result, ensure_ascii=False, indent=2)[:12000]
            phishing_status_text.value = "SpamAssassin tersedia dan selesai dijalankan." if result.get("available") else result.get("result", "SpamAssassin tidak tersedia.")
            phishing_status_text.color = C["green"] if result.get("available") else C["amber"]
            page.update()
        except AdvancedSecurityError as exc:
            phishing_status_text.value = str(exc)
            phishing_status_text.color = C["red"]
            page.update()

    phishing_panel = panel(ft.Column(controls=[
        section_heading("PERTAHANAN EMAIL", "Analisis email phishing", "Analisis header dan tautan secara lokal. Tidak terhubung ke mailbox dan tidak otomatis menghapus email."),
        ft.Text("Pemeriksaan membaca hasil SPF/DKIM/DMARC yang tercantum pada header penerima (bukan memverifikasi tanda tangan itu sendiri), perbedaan From/Reply-To, URL mencurigakan, dan bahasa mendesak. Untuk PhishTank, hanya URL yang kamu pilih yang dikirim ke layanan tersebut; email lengkap tidak diunggah.", size=10, color=C["muted"], selectable=True),
        email_message_field,
        ft.Row(controls=[
            ft.FilledButton(content="Analisis email lokal", icon=ft.Icons.MANAGE_SEARCH, on_click=analyze_email_click, bgcolor=C["panel_lift"], color=C["text"]),
            ft.OutlinedButton(content="Cek URL dengan PhishTank", icon=ft.Icons.LANGUAGE, on_click=phishtank_lookup_click),
            ft.OutlinedButton(content="Jalankan SpamAssassin lokal", icon=ft.Icons.RULE, on_click=spamassassin_click),
        ], wrap=True, spacing=8),
        phish_url_field,
        phish_key_field,
        phishing_status_text,
        phishing_result_text,
    ], spacing=10), padding=16)

    segmentation_management_field = ft.TextField(label="CIDR jaringan manajemen (contoh 10.10.10.0/24)", value="10.10.10.0/24", text_size=11, **field_style())
    segmentation_web_field = ft.TextField(label="CIDR zona web (contoh 10.10.20.0/24)", value="10.10.20.0/24", text_size=11, **field_style())
    segmentation_app_field = ft.TextField(label="CIDR zona aplikasi (contoh 10.10.30.0/24)", value="10.10.30.0/24", text_size=11, **field_style())
    segmentation_data_field = ft.TextField(label="CIDR zona data (contoh 10.10.40.0/24)", value="10.10.40.0/24", text_size=11, **field_style())
    segmentation_output_text = ft.Text("Belum ada rencana segmentasi.", size=10, color=C["muted"], selectable=True)

    def preview_segmentation_click(_: ft.ControlEvent | None = None) -> None:
        try:
            plan = build_microsegmentation_plan(
                segmentation_management_field.value or "", segmentation_web_field.value or "",
                segmentation_app_field.value or "", segmentation_data_field.value or "",
            )
            segmentation_output_text.value = json.dumps(plan, ensure_ascii=False, indent=2)[:16000]
            segmentation_output_text.color = C["amber"]
        except AdvancedSecurityError as exc:
            segmentation_output_text.value = f"Rencana ditolak: {exc}"
            segmentation_output_text.color = C["red"]
        page.update()

    segmentation_panel = panel(ft.Column(controls=[
        section_heading("SEGMENTASI JARINGAN", "Micro-segmentation", "Membuat rencana kebijakan firewall untuk ditinjau; tidak mengeksekusi nftables/iptables dan tidak mengubah jaringan otomatis."),
        ft.Text("Contoh default: manajemen → SSH, internet → HTTPS zona web, web → port aplikasi, aplikasi → port database; trafik antar-zona lain ditolak dalam rencana. Isi CIDR sesuai topologi nyata. Wajib ada uji staging dan rencana rollback agar tidak mengunci akses administrator.", size=10, color=C["muted"], selectable=True),
        segmentation_management_field, segmentation_web_field, segmentation_app_field, segmentation_data_field,
        ft.FilledButton(content="Buat pratinjau kebijakan", icon=ft.Icons.POLICY, on_click=preview_segmentation_click, bgcolor=C["panel_lift"], color=C["text"]),
        segmentation_output_text,
    ], spacing=9), padding=16)

    website_monitor_panel = panel(ft.Column(controls=[
        section_heading(
            "PANTAU WEBSITE PUBLIK", "Pemantauan website URL-only",
            "Masukkan URL HTTP/HTTPS saja. Tidak membutuhkan token API dan tidak membaca log internal server. Hasil disimpan di database website lokal yang terpisah dari security log.",
        ),
        ft.ResponsiveRow(controls=[
            ft.Container(content=website_name_field, col={"xs": 12, "md": 4}),
            ft.Container(content=website_url_field, col={"xs": 12, "md": 8}),
            ft.Container(content=website_interval_field, col={"xs": 12, "sm": 6, "md": 3}),
            ft.Container(content=website_timeout_field, col={"xs": 12, "sm": 6, "md": 3}),
            ft.Container(content=website_failure_threshold_field, col={"xs": 12, "sm": 6, "md": 3}),
            ft.Container(content=website_allow_internal, col={"xs": 12, "md": 3}),
        ], spacing=10, run_spacing=8),
        ft.Text(
            "Mode publik menolak alamat internal/reserved dan hostname metadata. Centang target internal hanya untuk host milik Anda atau yang secara eksplisit diizinkan. Jangan masukkan token/password pada URL. Pemeriksaan tidak memindai port atau mencoba kredensial.",
            size=10, color=C["muted"], selectable=True,
        ),
        ft.Row(controls=[
            ft.FilledButton(content="Simpan target", icon=ft.Icons.SAVE, on_click=add_website_target,
                            bgcolor=C["lime"], color=C["black"], disabled=session["role"] == "viewer"),
            ft.FilledButton(content="Mulai pemantauan", icon=ft.Icons.PLAY_ARROW, on_click=start_website_monitor,
                            bgcolor=C["panel_lift"], color=C["text"], disabled=session["role"] == "viewer"),
            ft.OutlinedButton(content="Hentikan", icon=ft.Icons.STOP, on_click=stop_website_monitor,
                              style=ft.ButtonStyle(color=C["amber"])),
            ft.OutlinedButton(content="Segarkan daftar", icon=ft.Icons.REFRESH, on_click=refresh_website_targets),
        ], spacing=8, wrap=True),
        ft.Container(content=website_monitor_status_text, padding=10, bgcolor=C["bg"],
                     border=ft.Border.all(1, C["line"]), border_radius=8),
        ft.Divider(color=C["line"], height=1),
        section_heading("TARGET LOKAL", "Target dan hasil terakhir", "Uji target satu per satu atau mulai pemantauan berkala. Interval minimal 30 detik untuk membatasi frekuensi request."),
        website_target_list,
    ], spacing=12), padding=17)

    connector_panel = panel(ft.Column(controls=[
        section_heading(
            "KONEKTOR AUDIT READ-ONLY", "SSH · Database Audit · Syslog TCP",
            "Konektor hanya berjalan atas target yang Anda isi dan setelah tombol ditekan. Event yang lolos validasi masuk ke audit chain lokal. Gunakan hanya server/database yang Anda kelola atau diizinkan untuk diaudit.",
        ),
        section_heading("SUMBER SSH", "Tarik log SSH read-only", "Host key wajib sudah dipercaya di known_hosts. Perintah bersifat tetap/allow-list; tidak mendukung command bebas atau eksekusi perubahan."),
        ft.ResponsiveRow(controls=[
            ft.Container(content=ssh_host_field, col={"xs": 12, "md": 5}),
            ft.Container(content=ssh_port_field, col={"xs": 4, "md": 2}),
            ft.Container(content=ssh_user_field, col={"xs": 8, "md": 5}),
            ft.Container(content=ssh_profile_field, col={"xs": 12, "md": 5}),
            ft.Container(content=ssh_known_hosts_field, col={"xs": 12, "md": 7}),
            ft.Container(content=ssh_key_path_field, col={"xs": 12, "md": 12}),
        ], spacing=8, run_spacing=6),
        ft.Row(controls=[ft.FilledButton(
            content="Uji SSH & impor event", icon=ft.Icons.VERIFIED_USER, on_click=test_ssh_connector,
            bgcolor=C["panel_lift"], color=C["text"], disabled=session["role"] == "viewer",
        )], wrap=True),
        ft.Divider(color=C["line"]),
        section_heading("SUMBER DATABASE", "Audit table/view read-only", "Pakai akun khusus SELECT-only. MySQL/MariaDB mensyaratkan CA TLS; SQL Server memverifikasi sertifikat sistem dan mengaktifkan ApplicationIntent=ReadOnly. Query dikunci ke SELECT berparameter."),
        ft.ResponsiveRow(controls=[
            ft.Container(content=db_engine_field, col={"xs": 12, "md": 4}),
            ft.Container(content=db_host_field, col={"xs": 12, "md": 6}),
            ft.Container(content=db_port_field, col={"xs": 4, "md": 2}),
            ft.Container(content=db_name_field, col={"xs": 12, "md": 4}),
            ft.Container(content=db_user_field, col={"xs": 12, "md": 4}),
            ft.Container(content=db_password_field, col={"xs": 12, "md": 4}),
            ft.Container(content=db_table_field, col={"xs": 12, "md": 6}),
            ft.Container(content=db_ca_path_field, col={"xs": 12, "md": 6}),
        ], spacing=8, run_spacing=6),
        ft.Text("Mapping kolom untuk view audit", size=11, weight=ft.FontWeight.BOLD, color=C["muted"]),
        ft.ResponsiveRow(controls=[
            ft.Container(content=db_time_column_field, col={"xs": 12, "sm": 6, "md": 3}),
            ft.Container(content=db_type_column_field, col={"xs": 12, "sm": 6, "md": 3}),
            ft.Container(content=db_host_column_field, col={"xs": 12, "sm": 6, "md": 3}),
            ft.Container(content=db_source_column_field, col={"xs": 12, "sm": 6, "md": 3}),
            ft.Container(content=db_actor_column_field, col={"xs": 12, "sm": 6, "md": 4}),
            ft.Container(content=db_message_column_field, col={"xs": 12, "sm": 6, "md": 4}),
            ft.Container(content=db_id_column_field, col={"xs": 12, "sm": 6, "md": 4}),
        ], spacing=8, run_spacing=6),
        ft.Row(controls=[ft.FilledButton(
            content="Uji database & impor 100 event", icon=ft.Icons.TABLE_CHART, on_click=test_database_audit_connector,
            bgcolor=C["panel_lift"], color=C["text"], disabled=session["role"] == "viewer",
        )], wrap=True),
        ft.Divider(color=C["line"]),
        section_heading("SUMBER SYSLOG", "Terima event syslog TCP", "Listener loopback plaintext tersedia untuk uji lokal. Listener pada alamat jaringan wajib memakai TLS 1.2+ dan mTLS; siapkan sertifikat yang dikeluarkan CA yang Anda percaya dan atur firewall sesuai kebutuhan."),
        ft.ResponsiveRow(controls=[
            ft.Container(content=syslog_bind_host_field, col={"xs": 12, "md": 6}),
            ft.Container(content=syslog_bind_port_field, col={"xs": 12, "md": 6}),
            ft.Container(content=syslog_ca_path_field, col={"xs": 12, "md": 4}),
            ft.Container(content=syslog_cert_path_field, col={"xs": 12, "md": 4}),
            ft.Container(content=syslog_key_path_field, col={"xs": 12, "md": 4}),
        ], spacing=8, run_spacing=6),
        ft.Row(controls=[
            ft.FilledButton(content="Mulai listener syslog", icon=ft.Icons.PLAY_ARROW,
                            on_click=start_syslog_listener, bgcolor=C["panel_lift"], color=C["text"],
                            disabled=session["role"] == "viewer"),
            ft.OutlinedButton(content="Hentikan listener", icon=ft.Icons.STOP, on_click=stop_syslog_listener),
        ], wrap=True, spacing=8),
        ft.Container(content=connector_status_text, padding=10, bgcolor=C["bg"],
                     border=ft.Border.all(1, C["line"]), border_radius=8),
        ft.Text(
            "Rahasia SSH/database disimpan melalui Secure Storage OS, bukan settings JSON. Private-key path hanya dibaca ketika Anda menekan Uji dan dikosongkan dari formulir setelah key disalin ke Secure Storage OS; file sumber tidak dihapus dan tetap harus Anda lindungi. Listener hanya aktif sampai dihentikan atau aplikasi berhenti; pengiriman syslog dari perangkat lain harus dikonfigurasi di sumbernya.",
            size=10, color=C["muted"], selectable=True,
        ),
    ], spacing=11), padding=16)

    # ------------------------------------------------------------------ Ringkasan status (dashboard)
    STATE_COLORS = {
        "good": C["green"], "warn": C["amber"], "bad": C["red"],
        "idle": C["quiet"], "connecting": C["blue"],
    }

    def overview_items() -> list[tuple[str, str, str, str]]:
        """Read actual connector status. These values feed the animation, not a duplicate status list."""
        items: list[tuple[str, str, str, str]] = []
        # Website: HTTP/DNS/TLS result, not a claim about internal server logs.
        try:
            if website_monitor_store is None:
                items.append(("Website", "idle", "Belum dibuka", "Penyimpanan target website belum dibuka."))
            else:
                targets = website_monitor_store.list_targets()
                up = sum(1 for t in targets if t.last_status == "UP")
                untested = sum(1 for t in targets if not t.last_status)
                bad = len(targets) - up - untested
                if not targets:
                    items.append(("Website", "idle", "Tanpa target", "Belum ada target website."))
                else:
                    state = "bad" if bad else ("good" if up == len(targets) else "warn")
                    items.append(("Website", state, f"{up}/{len(targets)} UP", "Pemeriksaan HTTP/DNS/TLS."))
        except Exception as exc:
            items.append(("Website", "warn", "Tidak terbaca", type(exc).__name__))

        # Optional server connection.
        try:
            profiles = server_registry_store.list()
            selected = server_registry_store.get(active_server_id)
            if not profiles:
                items.append(("Koneksi server", "idle", "Tidak dipakai", "Aplikasi berjalan lokal."))
            else:
                state = str(connector_runtime_state.get("server_status", "good" if connected_server_id else "idle"))
                headline = {"good": "Terhubung", "connecting": "Menghubungkan", "bad": "Gagal",
                            "warn": "Menunggu persetujuan", "idle": "Belum terhubung"}.get(state, "Belum terhubung")
                items.append(("Koneksi server", state, headline,
                              f"{len(profiles)} profil · aktif: {selected.name if selected else '—'}"))
        except Exception as exc:
            items.append(("Koneksi server", "warn", "Tidak terbaca", type(exc).__name__))

        # Remote server file monitoring is reported by the Linux agent feed; syslog is local.
        try:
            folder_state = str(connector_runtime_state.get("folder_status", "idle"))
            folder_active = folder_state == "good"
            syslog_active = bool(connector_runtime_state.get("syslog_active"))
            syslog_state = str(connector_runtime_state.get("syslog_status", "good" if syslog_active else "idle"))
            audit_state = "good" if (folder_active or syslog_active) else (
                "bad" if folder_state == "bad" or syslog_state == "bad" else
                "warn" if folder_state in {"warn", "connecting"} or syslog_state == "warn" else "idle"
            )
            items.append(("Sumber audit", audit_state,
                          "Pemantauan server aktif" if folder_active else ("Syslog aktif" if syslog_active else "Menunggu sumber audit"),
                          f"Folder server: {connector_runtime_state.get('folder_headline', 'menunggu')} · Syslog {'aktif' if syslog_active else 'nonaktif'}."))
        except Exception as exc:
            items.append(("Sumber audit", "warn", "Tidak terbaca", type(exc).__name__))

        # Agent health is known only from fresh, authenticated feed events.
        linux_state = str(connector_runtime_state.get("linux_agent_status", "idle"))
        windows_state = str(connector_runtime_state.get("windows_agent_status", "idle"))
        agent_state = "good" if "good" in {linux_state, windows_state} else (
            "warn" if "warn" in {linux_state, windows_state} else "idle"
        )
        items.append(("Kesehatan agen", agent_state,
                      f"Linux {linux_state.upper()} · Windows {windows_state.upper()}",
                      "Status hanya berasal dari heartbeat/event agen terbaru pada feed server."))

        # API feed state.
        try:
            selected = server_registry_store.get(active_server_id)
            if selected is None:
                items.append(("API feed", "idle", "Tidak dikonfigurasi", "Belum memilih profil server."))
            else:
                api_state = str(connector_runtime_state.get("server_status", "good" if connected_server_id else "idle"))
                items.append(("API feed", api_state, str(selected.settings.connector_type),
                              f"Profil {selected.name}."))
        except Exception as exc:
            items.append(("API feed", "warn", "Tidak terbaca", type(exc).__name__))

        # Pending security events.
        pending = str(alert_value.value or "0")
        items.append(("Event keamanan", "bad" if pending.isdigit() and int(pending) > 0 else "good",
                      f"{pending} perlu ditinjau" if pending != "0" else "Tidak ada antrean",
                      f"Total record audit: {total_value.value} · terakhir: {last_value.value}"))

        # SSH/database only change after an explicit read-only test.
        ssh_state = str(connector_runtime_state.get("ssh_status", "idle"))
        ssh_headline = {"good": "Uji berhasil", "connecting": "Sedang diuji", "bad": "Gagal diuji",
                        "warn": "Perlu dicek", "idle": "Belum diuji"}.get(ssh_state, "Belum diuji")
        items.append(("SSH", ssh_state, ssh_headline,
                      str(connector_runtime_state.get("ssh_label") or "Uji read-only belum dijalankan.")))
        db_state = str(connector_runtime_state.get("database_status", "idle"))
        db_headline = {"good": "Uji berhasil", "connecting": "Sedang diuji", "bad": "Gagal diuji",
                       "warn": "Perlu dicek", "idle": "Belum diuji"}.get(db_state, "Belum diuji")
        items.append(("Database audit", db_state, db_headline,
                      str(connector_runtime_state.get("database_label") or "Uji koneksi belum dijalankan.")))

        # Scanner readiness.
        if scanner is None:
            items.append(("Pemindai keamanan", "warn", "Tidak aktif", scanner_unavailable_reason))
        else:
            info = scanner.stats()
            items.append(("Pemindai keamanan", "good" if info["ai_available"] else "warn",
                          f"{info['signatures']} signature · {info['phishing_entries']} entri phishing",
                          ("Model AI lokal siap." if info["ai_available"] else "Model AI tidak tersedia; hanya hash dan blacklist.")
                          + f" Riwayat: {info['history']}."))
        return items

    # Nodes are arranged exactly like the reference: one trunk, three branches that
    # converge at verification, then two agent branches that reconverge at the API.
    topology_phase: dict[str, Any] = {"value": 0.0, "nodes": {}}
    topology_canvas = None

    def _topology_state_nodes() -> dict[str, tuple[str, str]]:
        return dict(topology_phase["nodes"])

    def render_topology() -> None:
        """Render the branching network map with cable endpoints outside every node."""
        if topology_canvas is None or cv is None:
            return

        width = float(topology_canvas.width or 1080)
        mobile = width < 700
        height = 870 if mobile else 610
        topology_canvas.height = height
        state_nodes = _topology_state_nodes()
        phase = float(topology_phase["value"])

        colors = {
            "good": "#43E6AD", "connecting": "#62C9F5", "bad": "#FF6877",
            "warn": "#E9B65E", "idle": "#53766D",
        }
        default_state = ("idle", "MENUNGGU")
        labels = {
            "AUDIT CORE": "SQLITE · LOG LOKAL",
            "VERIFIKASI": "TRACE · VALIDASI SERVER",
            "SSH": "SECURE SHELL",
            "SQL": "DATABASE CONNECTION",
            "TCP": "API TRANSPORT · TCP",
            "SYSLOG": "SYSLOG LISTENER · TCP",
            "SERVER API": "SERVER CONNECTION",
        }
        state_labels = {
            "VERIFIKASI": {"good": "VERIFIKASI LULUS", "connecting": "MEMERIKSA SERVER", "bad": "VERIFIKASI GAGAL", "warn": "PERLU REVIEW", "idle": "MENUNGGU PEMERIKSAAN"},
            "SSH": {"good": "KONEKSI BERHASIL", "connecting": "MENGHUBUNGKAN", "bad": "KONEKSI GAGAL", "warn": "PERLU DICEK", "idle": "BELUM DIUJI"},
            "SQL": {"good": "DATABASE TERHUBUNG", "connecting": "MENGUJI DATABASE", "bad": "KONEKSI GAGAL", "warn": "PERLU DICEK", "idle": "BELUM DIUJI"},
            "TCP": {"good": "TRANSPORT TERHUBUNG", "connecting": "MENGHUBUNGKAN", "bad": "KONEKSI GAGAL", "warn": "PERLU DICEK", "idle": "MENUNGGU SERVER"},
            "SYSLOG": {"good": "LISTENER AKTIF", "connecting": "MEMULAI LISTENER", "bad": "LISTENER GAGAL", "warn": "PERLU DICEK", "idle": "BELUM AKTIF"},
            "SERVER API": {"good": "SERVER TERHUBUNG", "connecting": "MENGHUBUNGKAN", "bad": "KONEKSI GAGAL", "warn": "PERLU DICEK", "idle": "BELUM TERHUBUNG"},
        }

        if mobile:
            points = {
                "APP": (width * 0.50, 45),
                "AUDIT CORE": (width * 0.50, 165),
                "VERIFIKASI": (width * 0.50, 300),
                "SSH": (width * 0.25, 535),
                "SQL": (width * 0.75, 535),
                "TCP": (width * 0.25, 665),
                "SYSLOG": (width * 0.75, 665),
                "SERVER API": (width * 0.50, 805),
            }
        else:
            points = {
                "APP": (width * 0.50, 48),
                "AUDIT CORE": (width * 0.50, 160),
                "VERIFIKASI": (width * 0.50, 285),
                "SSH": (width * 0.16, 435),
                "SQL": (width * 0.39, 435),
                "TCP": (width * 0.61, 435),
                "SYSLOG": (width * 0.84, 435),
                "SERVER API": (width * 0.50, 555),
            }

        shapes: list[Any] = []
        for i in range(32 if not mobile else 24):
            px = (i * 137.0 + phase * (18 + (i % 4) * 7)) % width
            py = (i * 71.0 + (i % 5) * 13.0) % height
            radius = 0.7 + (i % 3) * 0.25
            shapes.append(cv.Circle(x=px, y=py, radius=radius + 1.8,
                                    paint=ft.Paint(color="#0D3026", style=ft.PaintingStyle.FILL)))
            shapes.append(cv.Circle(x=px, y=py, radius=radius,
                                    paint=ft.Paint(color="#256B51", style=ft.PaintingStyle.FILL)))

        edge_specs = [
            ("APP", "AUDIT CORE", "good"),
            ("AUDIT CORE", "VERIFIKASI", "VERIFIKASI"),
            ("VERIFIKASI", "SSH", "SSH"),
            ("VERIFIKASI", "SQL", "SQL"),
            ("VERIFIKASI", "TCP", "TCP"),
            ("VERIFIKASI", "SYSLOG", "SYSLOG"),
            ("SSH", "SERVER API", "SSH"),
            ("SQL", "SERVER API", "SQL"),
            ("TCP", "SERVER API", "TCP"),
            ("SYSLOG", "SERVER API", "SYSLOG"),
        ]
        node_clearance = {
            "APP": 31.0, "AUDIT CORE": 29.0, "VERIFIKASI": 29.0,
            "SSH": 27.0, "SQL": 27.0, "TCP": 27.0,
            "SYSLOG": 27.0, "SERVER API": 32.0,
        }

        def bezier_point(a: tuple[float, float], b: tuple[float, float], t: float) -> tuple[float, float]:
            dx, dy = b[0] - a[0], b[1] - a[1]
            if abs(dx) >= abs(dy):
                c1 = (a[0] + dx * 0.50, a[1])
                c2 = (b[0] - dx * 0.50, b[1])
            else:
                c1 = (a[0], a[1] + dy * 0.50)
                c2 = (b[0], b[1] - dy * 0.50)
            u = 1.0 - t
            x = (u ** 3) * a[0] + 3 * (u ** 2) * t * c1[0] + 3 * u * (t ** 2) * c2[0] + (t ** 3) * b[0]
            y = (u ** 3) * a[1] + 3 * (u ** 2) * t * c1[1] + 3 * u * (t ** 2) * c2[1] + (t ** 3) * b[1]
            return x, y

        def append_curve(src: str, dst: str, state: str, idx: int) -> None:
            source, target = points[src], points[dst]
            dx, dy = target[0] - source[0], target[1] - source[1]
            distance = max(1.0, (dx * dx + dy * dy) ** 0.5)
            ux, uy = dx / distance, dy / distance
            # End each cable just outside the source and destination glyphs. No line
            # is allowed to pass through the center of an icon.
            start_pad = node_clearance[src] + 3.0
            end_pad = node_clearance[dst] + 3.0
            if distance <= start_pad + end_pad + 8:
                return
            a = (source[0] + ux * start_pad, source[1] + uy * start_pad)
            b = (target[0] - ux * end_pad, target[1] - uy * end_pad)
            color = colors.get(state, colors["idle"])
            active = state in {"good", "connecting"}
            segments = 18 if not mobile else 16
            previous = bezier_point(a, b, 0.0)
            for seg in range(1, segments + 1):
                current = bezier_point(a, b, seg / segments)
                glow = color if active or state in {"bad", "warn"} else "#21664D"
                core = ("#A4F6D4" if state == "good" else color) if active or state in {"bad", "warn"} else "#2A805F"
                shapes.append(cv.Line(x1=previous[0], y1=previous[1], x2=current[0], y2=current[1],
                                      paint=ft.Paint(color=glow, stroke_width=3.6 if active else 2.1)))
                shapes.append(cv.Line(x1=previous[0], y1=previous[1], x2=current[0], y2=current[1],
                                      paint=ft.Paint(color=core, stroke_width=1.1)))
                previous = current
            # Moving packets mean a verified/ongoing connection, not a decorative
            # claim that an idle or failed cable is carrying traffic.
            if active:
                packet_color = "#B9FFE0" if state == "good" else color
                for packet in range(3):
                    t = (phase * 0.29 + idx * 0.071 + packet * 0.34) % 1.0
                    px, py = bezier_point(a, b, t)
                    shapes.append(cv.Circle(x=px, y=py, radius=2.0 if not mobile else 1.7,
                                            paint=ft.Paint(color=packet_color, style=ft.PaintingStyle.FILL)))

        def draw_node(name: str, point: tuple[float, float], state: str, status: str,
                      radius: float, *, app: bool = False, server: bool = False) -> None:
            x, y = point
            color = colors.get(state, colors["idle"])
            fill_color = "#04130F"

            def glyph_line(x1: float, y1: float, x2: float, y2: float, stroke: float = 1.6) -> None:
                shapes.append(cv.Line(x1=x1, y1=y1, x2=x2, y2=y2,
                                      paint=ft.Paint(color=color, stroke_width=stroke)))

            def glyph_circle(cx: float, cy: float, r: float, stroke: float = 1.4) -> None:
                shapes.append(cv.Circle(x=cx, y=cy, radius=r,
                                        paint=ft.Paint(color=color, style=ft.PaintingStyle.STROKE,
                                                       stroke_width=stroke)))

            if app:
                phone_w, phone_h = (14, 27) if not mobile else (12, 22)
                x1, x2, y1, y2 = x - phone_w, x + phone_w, y - phone_h, y + phone_h
                for p1, p2 in [((x1 + 4, y1), (x2 - 4, y1)), ((x1, y1 + 4), (x1, y2 - 4)),
                               ((x2, y1 + 4), (x2, y2 - 4)), ((x1 + 4, y2), (x2 - 4, y2)),
                               ((x1, y1 + 4), (x1 + 4, y1)), ((x2 - 4, y1), (x2, y1 + 4)),
                               ((x1, y2 - 4), (x1 + 4, y2)), ((x2 - 4, y2), (x2, y2 - 4))]:
                    glyph_line(p1[0], p1[1], p2[0], p2[1], 2.2)
                glyph_line(x - 4, y1 + 5, x + 4, y1 + 5, 1.2)
                shield = [(x, y - 9), (x + 6, y - 6), (x + 5, y + 2),
                          (x, y + 8), (x - 5, y + 2), (x - 6, y - 6)]
                for first, second in zip(shield, shield[1:] + shield[:1]):
                    glyph_line(first[0], first[1], second[0], second[1], 1.8)
                node_title, node_sub = "KAWAL TRACE", "APLIKASI LOKAL"
                label_y = y + phone_h + 13
            else:
                pulse = (math.sin(phase * math.tau) + 1.0) / 2.0 if state in {"good", "connecting"} else 0.0
                for halo_radius, halo_color in ((radius + 10 + pulse * 3.0, "#0B3025"),
                                                (radius + 6 + pulse * 2.0, "#13513B")):
                    shapes.append(cv.Circle(x=x, y=y, radius=halo_radius,
                                            paint=ft.Paint(color=halo_color, style=ft.PaintingStyle.STROKE,
                                                           stroke_width=1.2 + pulse * 0.35)))
                if state in {"good", "connecting"}:
                    orbit_angle = phase * math.tau
                    orbit_x = x + math.cos(orbit_angle) * (radius + 12 + pulse * 2.0)
                    orbit_y = y + math.sin(orbit_angle) * (radius + 12 + pulse * 2.0)
                    shapes.append(cv.Circle(x=orbit_x, y=orbit_y, radius=2.0,
                                            paint=ft.Paint(color=color, style=ft.PaintingStyle.FILL)))
                shapes.append(cv.Circle(x=x, y=y, radius=radius + 8,
                                        paint=ft.Paint(color="#1C7454", style=ft.PaintingStyle.STROKE, stroke_width=1.0)))
                shapes.append(cv.Circle(x=x, y=y, radius=radius,
                                        paint=ft.Paint(color=fill_color, style=ft.PaintingStyle.FILL)))
                shapes.append(cv.Circle(x=x, y=y, radius=radius,
                                        paint=ft.Paint(color=color, style=ft.PaintingStyle.STROKE,
                                                       stroke_width=2.0 if server else 1.8)))
                if server:
                    for dy in (-6, 0, 6):
                        glyph_line(x - 8, y + dy, x + 8, y + dy, 2.0)
                elif name == "AUDIT CORE":
                    shield = [(x, y - 7), (x + 6, y - 4), (x + 5, y + 3),
                              (x, y + 8), (x - 5, y + 3), (x - 6, y - 4)]
                    for first, second in zip(shield, shield[1:] + shield[:1]):
                        glyph_line(first[0], first[1], second[0], second[1])
                elif name == "VERIFIKASI":
                    glyph_line(x - 7, y, x - 2, y + 5, 2.2)
                    glyph_line(x - 2, y + 5, x + 8, y - 6, 2.2)
                elif name == "SSH":
                    glyph_line(x - 7, y - 5, x - 2, y, 1.8)
                    glyph_line(x - 2, y, x - 7, y + 5, 1.8)
                    glyph_line(x + 1, y + 5, x + 7, y + 5, 1.5)
                elif name == "SQL":
                    glyph_circle(x, y - 5, 6.0, 1.4)
                    glyph_line(x - 6, y - 5, x - 6, y + 5, 1.4)
                    glyph_line(x + 6, y - 5, x + 6, y + 5, 1.4)
                    glyph_circle(x, y + 5, 6.0, 1.4)
                elif name == "TCP":
                    glyph_line(x - 7, y - 5, x + 7, y - 5, 1.5)
                    glyph_line(x - 7, y + 5, x + 7, y + 5, 1.5)
                    glyph_line(x - 7, y - 5, x - 7, y + 5, 1.5)
                    glyph_line(x + 7, y - 5, x + 7, y + 5, 1.5)
                    glyph_circle(x, y, 2.0, 1.2)
                elif name == "SYSLOG":
                    glyph_line(x - 6, y - 6, x + 6, y - 6, 1.5)
                    glyph_line(x - 6, y, x + 6, y, 1.5)
                    glyph_line(x - 6, y + 6, x + 6, y + 6, 1.5)

                node_title = name
                node_sub = status or state_labels.get(name, {}).get(state, labels.get(name, "MENUNGGU"))
                above = False
                label_y = y - radius - 36 if above else y + radius + 13

            title_width = min(124.0, max(88.0, width * (0.30 if mobile else 0.12)))
            title_font = 7.3 if not mobile else 6.8
            sub_font = 6.4 if not mobile else 5.9
            left = max(3.0, min(width - title_width - 3.0, x - title_width / 2))
            shapes.append(cv.Text(x=left, y=label_y, value=node_title,
                                  style=ft.TextStyle(color="#68E7B2" if state == "good" else color,
                                                     size=title_font, weight=ft.FontWeight.BOLD),
                                  text_align=ft.TextAlign.CENTER, max_width=title_width))
            shapes.append(cv.Text(x=left, y=label_y + (11 if not mobile else 10), value=node_sub,
                                  style=ft.TextStyle(color="#A4D9C5" if state == "good" else color,
                                                     size=sub_font),
                                  text_align=ft.TextAlign.CENTER, max_width=title_width))

        for idx, (src, dst, state_key) in enumerate(edge_specs):
            edge_state = "good" if state_key == "good" else state_nodes.get(state_key, default_state)[0]
            append_curve(src, dst, edge_state, idx)

        node_names = ["AUDIT CORE", "VERIFIKASI", "SSH", "SQL", "TCP", "SYSLOG", "SERVER API"]
        for name in node_names:
            state, dynamic_status = state_nodes.get(name, default_state)
            status = dynamic_status or state_labels.get(name, {}).get(state, labels.get(name, ""))
            if name == "AUDIT CORE":
                status = labels[name]
            draw_node(name, points[name], state, status,
                      21 if name == "SERVER API" else (19 if name == "AUDIT CORE" else 15.5),
                      server=(name == "SERVER API"))
        draw_node("KAWAL TRACE", points["APP"], "good", "APLIKASI LOKAL", 22, app=True)

        topology_canvas.shapes = shapes
        topology_canvas.update()

    if cv is not None:
        viewport_width = float(getattr(page, "width", None) or 1180)
        mobile_layout = viewport_width < 700
        topology_width = max(320.0 if mobile_layout else 1080.0,
                             min(1400.0, viewport_width - 48.0))
        topology_height = 870 if mobile_layout else 610
        topology_canvas = cv.Canvas(width=topology_width, height=topology_height, shapes=[])
        topology_row = ft.Row(
            controls=[topology_canvas], alignment=ft.MainAxisAlignment.CENTER,
            scroll=ft.ScrollMode.AUTO,
        )
        topology_visual = ft.Container(
            content=topology_row, width=max(300.0, viewport_width - 28.0),
            bgcolor="#010806", border=ft.Border.all(1, "#174D3C"), border_radius=10, padding=4,
        )
    else:
        topology_visual = ft.Container(
            content=ft.Text("Visualisasi koneksi aktif saat aplikasi berjalan pada Flet.", size=11, color=C["muted"]),
            bgcolor="#010806", border=ft.Border.all(1, "#174D3C"), border_radius=10, padding=16,
        )

    def refresh_status_overview() -> None:
        overview = overview_items()
        observed = {title: (state, headline, detail) for title, state, headline, detail in overview}

        folder_state = str(connector_runtime_state.get("folder_status", "idle"))
        scanner_state = observed.get("Pemindai keamanan", ("idle", "", ""))[0]
        website_state = observed.get("Website", ("idle", "", ""))[0]
        api_state = observed.get("API feed", ("idle", "", ""))[0]

        connector_states = [
            str(connector_runtime_state.get("ssh_status", "idle")),
            str(connector_runtime_state.get("database_status", "idle")),
            str(connector_runtime_state.get("syslog_status", "good" if connector_runtime_state.get("syslog_active") else "idle")),
        ]
        if "connecting" in connector_states:
            connector_state = "connecting"
        elif "bad" in connector_states and "good" in connector_states:
            connector_state = "warn"  # one connector is healthy, another has failed
        elif "bad" in connector_states:
            connector_state = "bad"
        elif "warn" in connector_states:
            connector_state = "warn"
        elif "good" in connector_states:
            connector_state = "good"
        else:
            connector_state = "idle"

        ssh_state = str(connector_runtime_state.get("ssh_status", "idle"))
        sql_state = str(connector_runtime_state.get("database_status", "idle"))
        tcp_state = str(connector_runtime_state.get("server_status", "idle"))
        syslog_state = str(connector_runtime_state.get("syslog_status", "good" if connector_runtime_state.get("syslog_active") else "idle"))
        # TRACE verification and the destination node reflect real successful server
        # checks (SSH, SQL, API/TCP, or received remote syslog), not the local hash chain.
        checked_states = (ssh_state, sql_state, tcp_state)
        remote_syslog_seen = int(connector_runtime_state.get("syslog_received", 0) or 0) > 0
        if "good" in checked_states or remote_syslog_seen:
            server_state = "good"
        elif "connecting" in checked_states:
            server_state = "connecting"
        elif "bad" in checked_states:
            server_state = "bad"
        else:
            server_state = "idle"
        topology_phase["nodes"] = {
            "AUDIT CORE": ("good", "SQLITE · LOG LOKAL"),
            "VERIFIKASI": (server_state, "TRACE · VALIDASI KONEKSI SERVER"),
            "SSH": (ssh_state, str(connector_runtime_state.get("ssh_label") or "Uji read-only belum dijalankan")),
            "SQL": (sql_state, str(connector_runtime_state.get("database_label") or "Uji koneksi belum dijalankan")),
            "TCP": (tcp_state, "STATUS TRANSPORT API SERVER"),
            "SYSLOG": (syslog_state, str(connector_runtime_state.get("syslog_label") or "Listener TCP belum aktif")),
            "SERVER API": (server_state, ""),
        }
        render_topology()

    # Only the animated network remains in this dashboard region; the duplicate status rows are removed.
    status_overview_panel = topology_visual

    # ------------------------------------------------------------------ Pemindai keamanan (hash, email, phishing)
    scan_path_field = ft.TextField(
        label="File atau email (.eml) yang akan dipindai",
        hint_text="Pilih lewat tombol, atau tempel path lengkap", text_size=12, **field_style(),
    )
    scan_text_field = ft.TextField(
        label="Atau tempel isi email / URL", multiline=True, min_lines=3, max_lines=8, text_size=11,
        hint_text="Teks tidak dikirim ke mana pun; URL tidak dibuka.", **field_style(),
    )
    scan_banner_title = ft.Text("BELUM ADA PEMINDAIAN", size=19, weight=ft.FontWeight.BOLD, color=C["muted"])
    scan_banner_detail = ft.Text("Pilih file/email atau tempel teks, lalu tekan Pindai.", size=11, color=C["muted"], selectable=True)
    scan_banner = ft.Container(
        content=ft.Column(controls=[scan_banner_title, scan_banner_detail], spacing=6),
        padding=16, bgcolor=C["panel_alt"], border=ft.Border.all(1, C["line"]), border_radius=12,
    )
    scan_findings_column = ft.Column(controls=[], spacing=5)
    scan_history_column = ft.Column(controls=[], spacing=6)
    scanner_stats_text = ft.Text("", size=10, color=C["muted"], selectable=True)
    scan_state: dict[str, bool] = {"busy": False}
    SCAN_STYLE = {
        "SAFE": ("TIDAK ADA KECOCOKAN", "#0F3A2B", C["green"]),
        "SUSPICIOUS": ("MENCURIGAKAN", "#3A2E10", C["amber"]),
        "MALWARE": ("MALWARE TERDETEKSI", "#3B1519", C["red"]),
        "PHISHING": ("PHISHING TERDETEKSI", "#3B1519", C["red"]),
    }
    FINDING_COLOR = {
        "HASH_MATCH": C["red"], "BAD_URL": C["red"], "AI_DETECTION": C["red"], "HEADER_AUTH": C["amber"],
        "HEADER_MISMATCH": C["amber"], "URL_HEURISTIC": C["amber"], "ATTACHMENT_RISK": C["amber"],
        "STATIC": C["amber"], "INFO": C["muted"],
    }
    threat_list_column = ft.Column(controls=[], spacing=8)
    threat_history_column = ft.Column(controls=[], spacing=4)
    THREAT_STATE_LABEL = {
        "QUARANTINED": ("DIKARANTINA", C["amber"]), "PENDING_IN_PLACE": ("MENUNGGU DIHAPUS", C["amber"]),
        "REVIEW": ("PERLU DITINJAU", C["amber"]), "DELETE_FAILED": ("GAGAL DIHAPUS", C["red"]),
    }
    CLOSED_LABEL = {"DELETED": "dihapus pengguna", "AUTO_DELETED": "dihapus otomatis", "RESTORED": "dipulihkan",
                    "SKIPPED_CHANGED": "dilewati (file berubah)"}

    def _clock_text(epoch: float | None) -> str:
        return datetime.fromtimestamp(epoch).strftime("%H:%M:%S") if epoch else "-"

    def refresh_threat_view() -> None:
        """Redraw pending/closed threats. Never raises into the UI and never shows a notification."""
        if scanner is None:
            threat_list_column.controls = []
            threat_history_column.controls = []
            return
        try:
            active = scanner.vault.list_threats(active_only=True, limit=50)
            closed = [t for t in scanner.vault.list_threats(active_only=False, limit=60)
                      if t["status"] in {"DELETED", "AUTO_DELETED", "RESTORED", "SKIPPED_CHANGED"}][:10]
        except Exception as exc:
            threat_list_column.controls = [ft.Text(f"Daftar ancaman tidak dapat dibaca ({type(exc).__name__}).", size=11, color=C["red"])]
            return
        is_viewer = session["role"] == "viewer"
        cards: list[ft.Control] = []
        for item in active:
            state_text, state_color = THREAT_STATE_LABEL.get(item["status"], (item["status"], C["muted"]))
            remaining = scanner.vault.seconds_remaining(item)
            if remaining is not None:
                timer_text = (f"Dihapus otomatis pukul {_clock_text(item['deadline'])} "
                              f"(±{max(1, (remaining + 59) // 60)} menit lagi) bila tidak ada tindakan.")
            else:
                timer_text = "Tidak dihapus otomatis; perlu keputusan Anda."
            buttons: list[ft.Control] = [
                ft.FilledButton(content="Coba hapus lagi" if item["status"] == "DELETE_FAILED" else "Hapus sekarang",
                                icon=safe_icon("DELETE_FOREVER", ft.Icons.DELETE), bgcolor=C["red"], color=C["text"],
                                disabled=is_viewer,
                                on_click=lambda e, tid=item["id"]: page.run_task(delete_threat_click, tid)),
            ]
            if item["status"] == "QUARANTINED":
                buttons.append(ft.OutlinedButton(content="Pulihkan (salah deteksi)", icon=safe_icon("RESTORE", ft.Icons.REFRESH),
                                                 disabled=session["role"] != "admin",
                                                 on_click=lambda e, tid=item["id"]: page.run_task(restore_threat_click, tid)))
            cards.append(ft.Container(
                content=ft.Column(controls=[
                    ft.Row(controls=[ft.Text(str(item["malware_name"])[:80], size=13, weight=ft.FontWeight.BOLD, color=C["red"], expand=True),
                                     tag(state_text, state_color), tag(f"Tingkat {item['severity']}", C["muted"])],
                           spacing=8, wrap=True),
                    ft.Text(f"Metode: {'cocok signature SHA-256' if item['detection'] == 'signature' else 'analisis statis (dugaan)'} · "
                            f"{item['size']} byte", size=10, color=C["muted"]),
                    ft.Text(f"Lokasi asal: {item['original_path']}", size=10, color=C["muted"], selectable=True),
                    ft.Text(f"SHA-256: {item['sha256']}", size=10, color=C["quiet"], selectable=True),
                    ft.Text(timer_text, size=11, color=C["amber"]),
                    ft.Text(str(item["note"]), size=10, color=C["muted"]) if item.get("note") else ft.Container(height=0),
                    ft.Row(controls=buttons, spacing=8, wrap=True),
                ], spacing=5),
                padding=12, bgcolor="#2A1215", border=ft.Border.all(1, C["red"]), border_radius=10,
            ))
        threat_list_column.controls = cards or [ft.Text("Tidak ada ancaman yang menunggu tindakan.", size=11, color=C["muted"])]
        threat_history_column.controls = [
            ft.Text(f"• {_clock_text(t['resolved_at'])} · {t['malware_name'][:50]} · {CLOSED_LABEL.get(t['status'], t['status'])}"
                    f"{' · ' + t['note'] if t.get('note') else ''}"[:200], size=10, color=C["quiet"])
            for t in closed
        ]

    def _audit_threat(action: str, item: dict[str, Any], actor: str) -> None:
        try:
            store.add_event("ALERT", actor, "pemindai-keamanan",
                            {"message": f"Ancaman {action}", "name": str(item.get("malware_name", ""))[:120],
                             "sha256": str(item.get("sha256", "")), "status": str(item.get("status", ""))})
        except ChainLogError:
            pass  # the vault history already records the outcome; do not turn this into a user-facing error

    async def delete_threat_click(threat_id: int) -> None:
        if scanner is None:
            return
        if session["role"] == "viewer":
            set_notice("Peran viewer tidak dapat menghapus ancaman.", "warning")
            return
        try:
            result = await asyncio.to_thread(scanner.vault.delete, int(threat_id), actor=session["username"])
        except ScannerError as exc:
            set_notice(redact_secrets(str(exc))[:200], "warning")
            refresh_threat_view()
            page.update()
            return
        ok = result["status"] in {"DELETED", "AUTO_DELETED"}
        set_notice(f"{'Dihapus' if ok else 'Belum terhapus'}: {result['note']}", "good" if ok else "warning")
        _audit_threat("dihapus pengguna" if ok else "gagal dihapus", result, session["username"])
        refresh_threat_view()
        page.update()

    @requires_step_up("memulihkan berkas yang dikarantina")
    async def restore_threat_click(threat_id: int) -> None:
        if scanner is None:
            return
        if session["role"] != "admin":
            set_notice("Hanya administrator yang dapat memulihkan berkas dari karantina.", "danger")
            return
        try:
            result = await asyncio.to_thread(scanner.vault.restore, int(threat_id), actor=session["username"])
        except ScannerError as exc:
            set_notice(redact_secrets(str(exc))[:200], "warning")
        else:
            set_notice(f"Dipulihkan: {result['note']}", "warning")
            _audit_threat("dipulihkan dari karantina", result, session["username"])
        refresh_threat_view()
        page.update()

    async def quarantine_due_loop() -> None:
        """Silently remove threats whose 15 minutes elapsed. No toast, no notification, no sound by design.

        While nobody is signed in, the headless guard in main() does the same job, so the deadline is
        honoured whether or not a dashboard is open.
        """
        while alive["on"]:
            if scanner is not None:
                try:
                    done = await asyncio.to_thread(scanner.vault.process_due)
                    for item in done:
                        _audit_threat("dihapus otomatis" if item["status"] == "AUTO_DELETED" else "penghapusan otomatis gagal",
                                      item, "sistem")
                    if not alive["on"]:
                        return
                    if done or scanner.vault.list_threats(active_only=True, limit=1):
                        refresh_threat_view()
                        page.update()
                except Exception as exc:
                    _log_ui_diagnostic(store.data_dir, "quarantine loop", exc)
            await asyncio.sleep(15)

    def scanner_ready() -> bool:
        if scanner is None:
            set_notice(scanner_unavailable_reason, "danger")
            return False
        return True

    def render_scan_report(report: Any) -> None:
        label_text, bg, edge = SCAN_STYLE.get(report.status, SCAN_STYLE["SAFE"])
        scan_banner.bgcolor, scan_banner.border = bg, ft.Border.all(1, edge)
        scan_banner_title.value, scan_banner_title.color = f"{label_text} · {report.file_name}"[:140], edge
        score = f" · skor AI {report.ai_score * 100:.1f}%" if report.ai_score is not None else ""
        scan_banner_detail.value = report.summary + score
        scan_banner_detail.color = C["text"]
        scan_findings_column.controls = [
            ft.Text(f"• [{kind}] {description}", size=11, color=FINDING_COLOR.get(kind, C["muted"]), selectable=True)
            for kind, description in report.findings[:60]
        ]

    def refresh_scan_history() -> None:
        if scanner is None:
            scan_history_column.controls = [ft.Text(scanner_unavailable_reason, size=11, color=C["amber"])]
            return
        rows: list[ft.Control] = []
        for row in scanner.db.history(12):
            _, _, edge = SCAN_STYLE.get(row["status"], SCAN_STYLE["SAFE"])
            rows.append(ft.Row(controls=[
                ft.Container(width=9, height=9, bgcolor=edge, border_radius=5),
                ft.Text(f"{row['status']} · {row['file_type']} · {row['file_name']}"[:90], size=11, color=C["text"], expand=True),
                ft.Text(str(row["scan_date"])[:19].replace("T", " "), size=10, color=C["quiet"]),
            ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER))
        scan_history_column.controls = rows or [ft.Text("Belum ada riwayat pemindaian.", size=11, color=C["muted"])]

    def refresh_scanner_view() -> None:
        refresh_scan_history()
        refresh_threat_view()
        if scanner is None:
            scanner_stats_text.value = scanner_unavailable_reason
            return
        info = scanner.stats()
        bloom = info["bloom"]
        scanner_stats_text.value = (
            f"Signature: {info['signatures']} (Bloom {bloom['state']}, ±{bloom['bloom_bytes']} B) · "
            f"Entri phishing: {info['phishing_entries']} · Riwayat: {info['history']} (otomatis dihapus >30 hari) · "
            f"AI lokal: {info['ai_status']} · Isolasi pemindaian: {info['isolation']}"
        )

    def record_scan_audit(report: Any) -> None:
        if session["role"] == "viewer":
            return  # viewers are read-only for the audit chain
        try:
            store.add_event(
                "ALERT" if report.is_threat else "NOTE", session["username"], "pemindai-keamanan",
                {"message": f"Pemindaian {report.file_type}: {report.status}", "status": report.status,
                 "name": report.file_name[:120], "sha256": report.sha256 or "", "scan_id": int(report.scan_id or 0)},
            )
            refresh_summary()
        except ChainLogError as exc:
            set_notice(f"Hasil pemindaian tersimpan, tetapi gagal dicatat ke rantai audit: {exc}", "warning")

    async def execute_scan(submit: Any) -> None:
        if not scanner_ready():
            return
        if scan_state["busy"]:
            set_notice("Pemindaian sebelumnya masih berjalan.", "warning")
            return
        scan_state["busy"] = True
        scan_banner_title.value, scan_banner_title.color = "MEMINDAI…", C["amber"]
        scan_banner_detail.value = "Pekerjaan berjalan di antrean latar; aplikasi tetap dapat dipakai."
        page.update()
        try:
            job_id = submit()
            job = await scanner.queue.wait_async(job_id, 900)
            if job.status == "done":
                render_scan_report(job.result)
                record_scan_audit(job.result)
            else:
                message = job.error.split(": ", 1)[-1] if job.error else f"Pekerjaan berstatus {job.status}."
                scan_banner_title.value, scan_banner_title.color = "PEMINDAIAN GAGAL", C["amber"]
                scan_banner_detail.value = redact_secrets(message)[:300]
                scan_findings_column.controls = []
        except ScannerError as exc:
            scan_banner_title.value, scan_banner_title.color = "PEMINDAIAN DITOLAK", C["amber"]
            scan_banner_detail.value = redact_secrets(str(exc))[:300]
        finally:
            scan_state["busy"] = False
            refresh_scanner_view()
            page.update()

    async def pick_scan_file(_: ft.ControlEvent | None = None) -> None:
        try:
            picked = await folder_picker.pick_files(dialog_title="Pilih file atau email (.eml) untuk dipindai", allow_multiple=False)
        except Exception as exc:
            set_notice(f"Pemilih file tidak tersedia ({type(exc).__name__}). Tempel path file secara manual.", "warning")
            return
        chosen = getattr(picked[0], "path", None) if picked else None
        if chosen:
            scan_path_field.value = str(chosen)
            page.update()
        elif picked:
            set_notice("Pemilih file tidak memberi path (umum di Android). Salin file ke folder yang dapat diakses lalu tempel path-nya.", "warning")

    async def pick_scan_folder(_: ft.ControlEvent | None = None) -> None:
        try:
            chosen = await folder_picker.get_directory_path(dialog_title="Pilih folder untuk dipindai")
        except Exception as exc:
            set_notice(f"Pemilih folder tidak tersedia ({type(exc).__name__}). Tempel path folder secara manual.", "warning")
            return
        if chosen:
            scan_path_field.value = str(chosen)
            page.update()

    async def scan_file_click(_: ft.ControlEvent | None = None) -> None:
        path = (scan_path_field.value or "").strip().strip('"')
        if not path:
            set_notice("Isi path file/email atau pilih lewat tombol Pilih file.", "warning")
            return
        if scanner_ready():
            if Path(path).is_dir():
                await execute_scan(lambda: scanner.submit_folder(path))
            else:
                await execute_scan(lambda: scanner.submit_path(path))

    async def scan_text_click(_: ft.ControlEvent | None = None) -> None:
        text = scan_text_field.value or ""
        if not text.strip():
            scan_banner_title.value = "INPUT BELUM LENGKAP"
            scan_banner_title.color = C["amber"]
            scan_banner_detail.value = "Tempel isi email atau URL pada kolom di atas sebelum memulai pemindaian."
            scan_banner_detail.color = C["amber"]
            page.update()
            return
        if scanner_ready():
            await execute_scan(lambda: scanner.queue.submit(scanner.scan_text, text))

    async def import_list_click(kind: str) -> None:
        if not scanner_ready():
            return
        if session["role"] != "admin":
            set_notice("Hanya administrator lokal yang dapat mengimpor daftar signature/blacklist.", "danger")
            return
        try:
            picked = await folder_picker.pick_files(dialog_title="Pilih file daftar (.txt / .csv)", allow_multiple=False,
                                                    file_type=ft.FilePickerFileType.CUSTOM, allowed_extensions=["txt", "csv"])
        except Exception as exc:
            set_notice(f"Pemilih file tidak tersedia ({type(exc).__name__}).", "warning")
            return
        chosen = getattr(picked[0], "path", None) if picked else None
        if not chosen:
            return
        try:
            if kind == "hash":
                inserted, rejected = await asyncio.to_thread(scanner.import_signature_file, chosen)
            else:
                inserted, rejected = await asyncio.to_thread(scanner.import_phishing_file, chosen)
            set_notice(f"Impor selesai: {inserted} entri masuk, {rejected} baris ditolak (format tidak valid).", "good" if inserted else "warning")
        except ScannerError as exc:
            set_notice(redact_secrets(str(exc))[:200], "danger")
        refresh_scanner_view()
        page.update()

    async def import_hash_click(_: ft.ControlEvent | None = None) -> None:
        await import_list_click("hash")

    async def import_url_click(_: ft.ControlEvent | None = None) -> None:
        await import_list_click("url")

    async def clear_scan_history_click(_: ft.ControlEvent | None = None) -> None:
        if not scanner_ready():
            return
        if session["role"] == "viewer":
            set_notice("Peran viewer tidak dapat membersihkan riwayat.", "warning")
            return
        try:
            removed = await asyncio.to_thread(scanner.clear_history)
            remaining = await asyncio.to_thread(scanner.db.history_count)
            if remaining != 0:
                raise ScannerError(f"Masih ada {remaining} riwayat tersimpan setelah pembersihan.")
            refresh_scanner_view()
            set_notice(f"Seluruh riwayat pemindaian dihapus dari database: {removed} record. Signature dan daftar phishing tetap tersimpan.", "good")
            page.update()
        except Exception as exc:
            set_notice(f"Riwayat tidak berhasil dibersihkan: {type(exc).__name__}: {str(exc)[:160]}", "danger")

    scanner_panel = panel(ft.Column(controls=[
        section_heading("PEMINDAI KEAMANAN", "Pemindai malware & phishing (offline)",
                        "Hash SHA-256 file dicocokkan lewat Bloom filter lalu SQLite; email dibedah (header, lampiran, tautan) dan teksnya dinilai model AI lokal."),
        ft.Text("Semua pemeriksaan berjalan di perangkat ini. File tidak dijalankan, tautan tidak dibuka, dan tidak ada data dikirim ke luar. "
                "Hasil AMAN berarti tidak ada kecocokan dengan daftar yang Anda impor dan model lokal; ini bukan jaminan bebas ancaman.",
                size=10, color=C["muted"], selectable=True),
        scan_banner,
        scan_findings_column,
        label("ANCAMAN MENUNGGU TINDAKAN"),
        ft.Text("File yang cocok dengan signature dipindahkan ke karantina terpisah (tidak bisa dijalankan). Anda bisa menghapusnya sekarang; "
                "jika tidak ada tindakan dalam 15 menit, file dihapus permanen secara otomatis tanpa pemberitahuan (hasilnya tercatat di riwayat di bawah). "
                "Dugaan dari analisis statis tidak pernah dihapus otomatis.", size=10, color=C["muted"], selectable=True),
        threat_list_column,
        threat_history_column,
        ft.Divider(color=C["line"], height=1),
        scan_path_field,
        ft.Row(controls=[
            ft.OutlinedButton(content="Pilih file", icon=safe_icon("UPLOAD_FILE", ft.Icons.ADD), on_click=pick_scan_file),
            ft.OutlinedButton(content="Pilih folder", icon=safe_icon("FOLDER_OPEN", ft.Icons.ADD), on_click=pick_scan_folder),
            ft.FilledButton(content="Pindai file / email", icon=safe_icon("BUG_REPORT", ft.Icons.SECURITY), on_click=scan_file_click,
                            bgcolor=C["lime"], color=C["black"], icon_color=C["black"]),
        ], spacing=9, wrap=True),
        scan_text_field,
        ft.Row(controls=[
            ft.FilledButton(content="Pindai teks / URL", icon=ft.Icons.MANAGE_SEARCH, on_click=scan_text_click,
                            bgcolor=C["panel_lift"], color=C["text"]),
        ], spacing=9, wrap=True),
        ft.Divider(color=C["line"], height=1),
        label("RIWAYAT PEMINDAIAN TERBARU"),
        scan_history_column,
        ft.Divider(color=C["line"], height=1),
        label("DATABASE LOKAL"),
        scanner_stats_text,
        ft.Text("Aplikasi tidak membawa database malware sungguhan: hanya satu signature uji EICAR dan satu domain uji. "
                "Impor daftar SHA-256 (satu per baris: hash,nama,Low|Medium|High) dan daftar domain phishing dari sumber tepercaya pilihan Anda.",
                size=10, color=C["muted"], selectable=True),
        ft.Row(controls=[
            ft.OutlinedButton(content="Impor daftar hash", icon=ft.Icons.ADD, on_click=import_hash_click, disabled=session["role"] != "admin"),
            ft.OutlinedButton(content="Impor daftar domain phishing", icon=ft.Icons.ADD, on_click=import_url_click, disabled=session["role"] != "admin"),
            ft.OutlinedButton(content="Bersihkan seluruh riwayat", icon=safe_icon("DELETE_SWEEP", ft.Icons.REFRESH), on_click=clear_scan_history_click,
                              disabled=session["role"] == "viewer"),
        ], spacing=9, wrap=True),
    ], spacing=11), padding=16)

    # ------------------------------------------------------------------ Backup & restore terenkripsi
    backup_pass_field = ft.TextField(
        label="Frasa sandi backup (min. 14 karakter)", password=True, can_reveal_password=True,
        max_length=128, text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    backup_confirm_field = ft.TextField(
        label="Ulangi frasa sandi (hanya untuk membuat backup)", password=True, can_reveal_password=True,
        max_length=128, text_size=12, read_only=session["role"] != "admin", **field_style(),
    )
    restore_confirm_check = ft.Checkbox(label="Saya mengerti pemulihan menimpa data lokal (salinan pengaman dibuat otomatis)", value=False)
    backup_status_text = ft.Text("Backup dibuat hanya saat Anda menekan tombol dan disimpan di lokasi pilihan Anda.", size=11, color=C["muted"], selectable=True)
    backup_state: dict[str, bool] = {"busy": False}

    def backup_gate() -> bool:
        if session["role"] != "admin":
            set_notice("Backup dan pemulihan hanya untuk administrator lokal.", "danger")
            return False
        if backup_state["busy"]:
            set_notice("Operasi backup lain masih berjalan.", "warning")
            return False
        return True

    def backup_say(message: str, tone: str) -> None:
        backup_status_text.value = message
        backup_status_text.color = {"good": C["green"], "warning": C["amber"], "danger": C["red"]}.get(tone, C["muted"])
        page.update()

    @requires_step_up("membuat cadangan data")
    async def create_backup_click(_: ft.ControlEvent | None = None) -> None:
        if not backup_gate():
            return
        passphrase = backup_pass_field.value or ""
        if passphrase != (backup_confirm_field.value or ""):
            backup_say("Kedua frasa sandi tidak sama. Backup belum dibuat.", "danger")
            return
        backup_state["busy"] = True
        try:
            filename = "kawal-trace-backup-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".ktbak"
            staged = store.data_dir / "backups" / filename
            backup_say("Membuat backup terenkripsi…", "warning")
            info = await asyncio.to_thread(create_backup, store.data_dir, staged, passphrase)
            payload = staged.read_bytes() if staged.stat().st_size <= 64 * 1024 * 1024 else None
            saved = await folder_picker.save_file(
                dialog_title="Simpan backup terenkripsi Kawal Trace", file_name=filename,
                file_type=ft.FilePickerFileType.CUSTOM, allowed_extensions=["ktbak"], src_bytes=payload,
            )
            if saved:
                destination = Path(str(saved))
                try:
                    if not destination.exists() or destination.stat().st_size != staged.stat().st_size:
                        shutil.copyfile(staged, destination)
                    staged.unlink(missing_ok=True)
                except OSError as exc:
                    backup_say(f"Backup dibuat tetapi tidak dapat disalin ke lokasi pilihan ({type(exc).__name__}); salinan ada di folder data aplikasi (backups).", "warning")
                    return
                backup_pass_field.value = backup_confirm_field.value = ""
                backup_say(f"BACKUP TERSIMPAN · {len(info.files)} file data · {saved}. Simpan frasa sandi terpisah; rahasia di Secure Storage OS tidak ikut dibackup.", "good")
                try:
                    store.add_event("CONFIG", session["username"], "backup", {"message": "Backup terenkripsi dibuat", "action": "backup_created", "files": len(info.files)})
                    refresh_summary()
                except ChainLogError:
                    pass
            else:
                backup_say("Dialog simpan dibatalkan. Backup terenkripsi tetap ada di folder data aplikasi (backups) hingga dihapus.", "warning")
        except BackupError as exc:
            backup_say(redact_secrets(str(exc))[:300], "danger")
        except Exception as exc:
            backup_say(f"Backup gagal ({type(exc).__name__}). ID diagnosa {_log_ui_diagnostic(store.data_dir, 'create backup', exc)}.", "danger")
        finally:
            backup_state["busy"] = False

    async def pick_backup_file() -> str | None:
        picked = await folder_picker.pick_files(
            dialog_title="Pilih file backup (.ktbak)", allow_multiple=False,
            file_type=ft.FilePickerFileType.CUSTOM, allowed_extensions=["ktbak"],
        )
        return str(getattr(picked[0], "path", "") or "") or None if picked else None

    async def verify_backup_click(_: ft.ControlEvent | None = None) -> None:
        if not backup_gate():
            return
        backup_state["busy"] = True
        try:
            chosen = await pick_backup_file()
            if not chosen:
                backup_say("Tidak ada file backup yang dipilih.", "warning")
                return
            backup_say("Memverifikasi backup (dekripsi, checksum, SQLite, rantai audit)…", "warning")
            report = await asyncio.to_thread(verify_backup, chosen, backup_pass_field.value or "")
            chain = ("valid" if report.audit_chain_valid else "TIDAK valid") if report.audit_chain_valid is not None else "tidak ada"
            if report.ok:
                backup_say(f"BACKUP VALID · dibuat {report.created_utc} · {len(report.files)} file · rantai audit {chain} ({report.audit_records} record). Data aktif tidak diubah.", "good")
            else:
                backup_say("BACKUP BERMASALAH · " + "; ".join(report.problems)[:300], "danger")
        except BackupError as exc:
            backup_say(redact_secrets(str(exc))[:300], "danger")
        except Exception as exc:
            backup_say(f"Verifikasi gagal ({type(exc).__name__}). ID diagnosa {_log_ui_diagnostic(store.data_dir, 'verify backup', exc)}.", "danger")
        finally:
            backup_state["busy"] = False

    @requires_step_up("memulihkan data dari cadangan")
    async def restore_backup_click(_: ft.ControlEvent | None = None) -> None:
        if not backup_gate():
            return
        if not restore_confirm_check.value:
            backup_say("Centang konfirmasi dahulu: pemulihan menimpa data lokal.", "warning")
            return
        backup_state["busy"] = True
        try:
            chosen = await pick_backup_file()
            if not chosen:
                backup_say("Tidak ada file backup yang dipilih.", "warning")
                return
            backup_say("Memulihkan data…", "warning")
            result = await asyncio.to_thread(restore_backup, chosen, backup_pass_field.value or "", store.data_dir, confirm=True)
            restore_confirm_check.value = False
            backup_pass_field.value = backup_confirm_field.value = ""
            safety = f" Salinan pengaman data lama: {result.safety_copy.name}." if result.safety_copy else ""
            backup_say(f"PEMULIHAN SELESAI · {len(result.restored)} file dipulihkan.{safety}"
                       f"{' Akun tidak ikut dipulihkan (akun terikat ke perangkat); gunakan akun perangkat ini.' if result.skipped else ''}"
                       " Tutup dan buka ulang aplikasi sebelum melanjutkan.", "good")
        except BackupError as exc:
            backup_say(redact_secrets(str(exc))[:300], "danger")
        except Exception as exc:
            backup_say(f"Pemulihan gagal ({type(exc).__name__}). Data lama tidak dihapus. ID diagnosa {_log_ui_diagnostic(store.data_dir, 'restore backup', exc)}.", "danger")
        finally:
            backup_state["busy"] = False

    backup_panel = panel(ft.Column(controls=[
        section_heading("BACKUP & RESTORE", "Backup terenkripsi lokal",
                        "AES-256-GCM dengan kunci dari frasa sandi (scrypt). Tidak ada unggahan otomatis; Anda memilih lokasi simpan."),
        ft.Text("Isi backup: database audit, identitas lokal, arsip, riwayat website/pemindai, dan pengaturan. "
                "TIDAK termasuk rahasia di Secure Storage OS (token API, kunci database website): kunci itu harus dipulihkan terpisah atau dimasukkan ulang. "
                "Gunakan 'Verifikasi backup' untuk uji pemulihan tanpa menyentuh data aktif.",
                size=10, color=C["muted"], selectable=True),
        backup_pass_field,
        backup_confirm_field,
        ft.Row(controls=[
            ft.FilledButton(content="Buat backup terenkripsi", icon=safe_icon("BACKUP", ft.Icons.ADD), on_click=create_backup_click,
                            bgcolor=C["lime"], color=C["black"], icon_color=C["black"], disabled=session["role"] != "admin"),
            ft.OutlinedButton(content="Verifikasi backup", icon=ft.Icons.VERIFIED_USER, on_click=verify_backup_click, disabled=session["role"] != "admin"),
        ], spacing=9, wrap=True),
        ft.Divider(color=C["line"], height=1),
        restore_confirm_check,
        ft.Row(controls=[
            ft.OutlinedButton(content="Pulihkan dari backup", icon=safe_icon("RESTORE", ft.Icons.REFRESH), on_click=restore_backup_click,
                              style=ft.ButtonStyle(color=C["amber"]), disabled=session["role"] != "admin"),
        ], spacing=9, wrap=True),
        backup_status_text,
    ], spacing=11), padding=16)

    advanced_security_panel = panel(ft.Column(controls=[
        section_heading("PERLINDUNGAN LANJUTAN", "Perlindungan lanjutan", "ZTNA, PIN/biometrik lokal, review phishing, dan rencana isolasi jaringan. Semua perubahan berisiko tetap memerlukan persetujuan operator."),
        device_auth_panel,
        ztna_panel,
        phishing_panel,
        segmentation_panel,
    ], spacing=13), padding=16)

    refresh_accounts()

    footer = ft.Container(
        content=ft.Row(controls=[notice_dot, notice_text], spacing=9),
        padding=ft.Padding(left=2, right=2, top=6, bottom=3),
    )

    # --- Tata letak: menu kiri + SATU badan halaman tetap ---------------------------------------
    # Semua panel/fitur lama dipertahankan utuh; hanya dipasang ke badan halaman saat menunya dipilih.
    page_defs: list[tuple[str, list[tuple[str, str, Any, list[ft.Control]]]]] = [
        ("RINGKASAN", [
            ("dashboard", "Dashboard", ft.Icons.VERIFIED_USER, [status_overview_panel, metrics]),
            ("jejak", "Jejak Aktivitas", ft.Icons.HISTORY, [
                ft.ResponsiveRow(
                    controls=[
                        ft.Container(content=activity_panel, col={"xs": 12, "lg": 8}),
                        ft.Container(content=export_panel, col={"xs": 12, "lg": 4}),
                    ], spacing=14, run_spacing=14,
                ),
            ]),
        ]),
        ("OPERASI", [
            ("catat", "Catat Aktivitas", ft.Icons.ADD, [event_form]),
            ("pantau", "Pantau Folder", ft.Icons.RADAR, [monitor_panel]),
            ("website", "Pantau Website", ft.Icons.LANGUAGE, [website_monitor_panel]),
        ]),
        ("SERVER", [
            ("integrasi", "Integrasi Server", ft.Icons.CLOUD_SYNC, [sync_panel]),
            ("telemetri", "Telemetri & Arsip", ft.Icons.SHIELD, [server_feed_panel]),
            ("konektor-audit", "Konektor Audit", ft.Icons.LAN, [connector_panel]),
        ]),
        ("KEAMANAN", [
            ("pemindai", "Pemindai Keamanan", safe_icon("BUG_REPORT", ft.Icons.SECURITY), [scanner_panel]),
            ("lanjutan", "Perlindungan Lanjutan", ft.Icons.SECURITY, [advanced_security_panel]),
        ]),
        ("DATA & AKUN", [
            ("backup", "Backup & Restore", safe_icon("BACKUP", ft.Icons.SHIELD), [backup_panel]),
        ] + ([("akun", "Akun Operator", ft.Icons.PERSON_ADD, [account_panel])] if session["role"] == "admin" else [])),
    ]
    page_titles: dict[str, str] = {key: title for _, items in page_defs for key, title, _, _ in items}
    page_controls: dict[str, list[ft.Control]] = {
        key: list(controls) for _, items in page_defs for key, _, _, controls in items
    }
    nav_state: dict[str, Any] = {"current": "dashboard", "compact": False}
    # One persistent scrollable body that is a direct flex child of the content column. Navigation only
    # replaces its `controls`; no Column/Container is swapped, and the sidebar is NOT rebuilt on click
    # (rebuilding disposed the very button being handled). Layout hazards are linted in
    # tests/test_dashboard_render_contract.py; a run on a real Windows/Android client is still required.
    page_body = ft.Column(
        controls=list(page_controls["dashboard"]), spacing=16, expand=True, scroll=ft.ScrollMode.HIDDEN,
    )

    def is_compact() -> bool:
        """Layar sempit (HP): menu kiri diciutkan menjadi pemilih menu di bagian atas."""
        try:
            width = page.width
            if width:
                return float(width) < 760
        except (AttributeError, TypeError, ValueError):
            pass
        try:
            platform = getattr(page, "platform", None)
            platform_value = getattr(platform, "value", platform)
            return str(platform_value).split(".")[-1].lower() in {"android", "ios"}
        except (AttributeError, TypeError):
            return False

    page_title_text = ft.Text(page_titles["dashboard"], size=21, weight=ft.FontWeight.BOLD, color=C["text"])
    brand_holder = ft.Container()
    nav_column = ft.Column(controls=[], spacing=4, scroll=ft.ScrollMode.HIDDEN, expand=True)
    session_holder = ft.Container()
    sidebar = ft.Container(
        width=236, padding=14, bgcolor=C["panel"],
        border=ft.Border.all(1, C["line"]), border_radius=16,
        content=ft.Column(controls=[brand_holder, nav_column, session_holder], spacing=12),
    )
    # A full-width selector replaces the sidebar on phone-sized screens.
    mobile_nav_dropdown = ft.Dropdown(
        label="Menu aplikasi",
        options=[ft.DropdownOption(key=key, text=title) for key, title in page_titles.items()],
        value="dashboard", visible=False,
        on_select=lambda e: go_to(str(mobile_nav_dropdown.value or "dashboard")),
    )
    responsive_width(mobile_nav_dropdown, 520, 56)
    refresh_button = ft.OutlinedButton(
        content="Segarkan data", icon=ft.Icons.REFRESH, on_click=lambda e: refresh_summary(),
        style=ft.ButtonStyle(color=C["lime"]),
    )
    nav_widgets: dict[str, tuple[ft.Container, ft.Icon, ft.Text | None]] = {}

    def style_nav(key: str, active: bool) -> None:
        """Recolour an existing nav button in place (no control is created or disposed)."""
        widgets = nav_widgets.get(key)
        if widgets is None:
            return
        container, icon_control, text_control = widgets
        container.bgcolor = C["panel_lift"] if active else C["panel"]
        container.border = ft.Border.all(1, C["lime"] if active else C["panel"])
        icon_control.color = C["lime"] if active else C["muted"]
        if text_control is not None:
            text_control.color = C["text"] if active else C["muted"]
            text_control.weight = ft.FontWeight.BOLD if active else ft.FontWeight.NORMAL

    def nav_button(key: str, title: str, icon: Any, compact: bool) -> ft.Container:
        active = key == nav_state["current"]
        icon_control = ft.Icon(icon, size=19, color=C["lime"] if active else C["muted"])
        text_control: ft.Text | None = None
        controls: list[ft.Control] = [icon_control]
        if not compact:
            text_control = ft.Text(title, size=13, expand=True, color=C["text"] if active else C["muted"],
                                   weight=ft.FontWeight.BOLD if active else ft.FontWeight.NORMAL)
            controls.append(text_control)
        container = ft.Container(
            content=ft.Row(
                controls=controls, spacing=11,
                alignment=ft.MainAxisAlignment.CENTER if compact else ft.MainAxisAlignment.START,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=ft.Padding(left=11, right=11, top=10, bottom=10),
            bgcolor=C["panel_lift"] if active else C["panel"],
            border=ft.Border.all(1, C["lime"] if active else C["panel"]),
            border_radius=10, ink=True, tooltip=title,
            on_click=lambda e, target=key: go_to(target),
        )
        nav_widgets[key] = (container, icon_control, text_control)
        return container

    def render_sidebar() -> None:
        """Build the sidebar. Only called at startup and when the window crosses the compact threshold."""
        compact = bool(nav_state["compact"])
        sidebar.visible = not compact
        mobile_nav_dropdown.visible = compact
        mobile_nav_dropdown.value = nav_state["current"]
        refresh_button.content = "Segarkan" if compact else "Segarkan data"
        page_title_text.size = 16 if compact else 21
        sidebar.width = 66 if compact else 236
        sidebar.padding = 8 if compact else 14
        # The supplied Kawal Trace key mark replaces only the old shield; the wordmark/layout stay unchanged.
        logo_mark = ft.Container(
            content=ft.Image(src="kawal_trace_key.png", width=32, height=32, fit=ft.BoxFit.CONTAIN),
            width=38, height=38, bgcolor=C["bg"], border=ft.Border.all(1, C["line"]),
            border_radius=10, alignment=ft.Alignment(0, 0),
        )
        if compact:
            brand_holder.content = ft.Row(controls=[logo_mark], alignment=ft.MainAxisAlignment.CENTER)
        else:
            brand_holder.content = ft.Row(
                controls=[
                    logo_mark,
                    ft.Column(
                        controls=[
                            ft.Text("KAWAL TRACE", size=15, weight=ft.FontWeight.BOLD, color=C["text"]),
                            ft.Text("Security Console", size=10, color=C["lime"]),
                        ], spacing=1, expand=True,
                    ),
                ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER,
            )
        nav_widgets.clear()
        items: list[ft.Control] = []
        for group, group_items in page_defs:
            if compact:
                items.append(ft.Divider(color=C["line"], height=10))
            else:
                items.append(ft.Container(content=label(group, C["quiet"]), padding=ft.Padding(left=6, right=0, top=10, bottom=4)))
            for key, title, icon, _ in group_items:
                items.append(nav_button(key, title, icon, compact))
        nav_column.controls = items
        role_label = str(session["role"]).upper()
        if compact:
            session_holder.content = ft.Row(
                controls=[ft.Icon(ft.Icons.PERSON_OUTLINE, size=20, color=C["green"])],
                alignment=ft.MainAxisAlignment.CENTER,
            )
            session_holder.tooltip = f"{session['username']} / {session['role']}"
            session_holder.padding = 8
        else:
            session_holder.content = ft.Column(
                controls=[
                    ft.Row(
                        controls=[
                            ft.Container(
                                content=ft.Icon(ft.Icons.PERSON_OUTLINE, size=18, color=C["green"]),
                                width=34, height=34, bgcolor=C["panel_lift"], border_radius=17,
                                alignment=ft.Alignment(0, 0),
                            ),
                            ft.Column(
                                controls=[
                                    ft.Text(str(session["username"]), size=12, weight=ft.FontWeight.BOLD, color=C["text"]),
                                    ft.Text(role_label, size=9, color=C["green"], weight=ft.FontWeight.BOLD),
                                ], spacing=1, expand=True,
                            ),
                        ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    ft.Text("Audit lokal · feed server terpisah", size=10, color=C["muted"]),
                    ft.Text(f"v{APP_VERSION} · build {APP_BUILD}", size=10, color=C["quiet"]),
                ], spacing=6,
            )
            session_holder.tooltip = None
            session_holder.padding = 12
        session_holder.bgcolor = C["panel_alt"]
        session_holder.border = ft.Border.all(1, C["line"])
        session_holder.border_radius = 12

    page_open_hooks: dict[str, Any] = {
        "dashboard": lambda: (refresh_summary(), refresh_status_overview()),
        "pemindai": refresh_scanner_view,
    }

    def page_error_card(key: str, exc: BaseException, diagnostic_id: str) -> ft.Control:
        return ft.Container(
            content=ft.Column(controls=[
                ft.Text(f"Halaman '{page_titles.get(key, key)}' tidak dapat dimuat", size=16, weight=ft.FontWeight.BOLD, color=C["red"]),
                ft.Text(f"{type(exc).__name__}: {redact_secrets(str(exc))[:240] or 'tanpa pesan'}", size=11, color=C["text"], selectable=True),
                ft.Text(f"ID diagnosa {diagnostic_id} · detail aman tercatat di startup-errors.log. Fitur lain tetap dapat dipakai.",
                        size=10, color=C["muted"], selectable=True),
                ft.OutlinedButton(content="Kembali ke Dashboard", icon=ft.Icons.VERIFIED_USER, on_click=lambda e: go_to("dashboard")),
            ], spacing=8),
            padding=16, bgcolor="#2A1215", border=ft.Border.all(1, C["red"]), border_radius=12,
        )

    def go_to(key: str) -> None:
        """Show one feature page. A failing page shows its own error card instead of a blank surface."""
        if key not in page_controls:
            return
        previous = str(nav_state["current"])
        hook = page_open_hooks.get(key)
        if hook is not None:
            try:
                hook()
            except Exception as exc:  # stale numbers are better than no page
                diag = _log_ui_diagnostic(store.data_dir, f"page open hook {key}", exc)
                set_notice(f"Data halaman {page_titles[key]} gagal disegarkan (ID {diag}).", "warning")
        try:
            page_body.controls = page_controls[key]
        except Exception as exc:
            diag = _log_ui_diagnostic(store.data_dir, f"mount page {key}", exc)
            try:
                page_body.controls = [page_error_card(key, exc, diag)]
            except Exception as card_exc:  # nothing more can be shown; keep the app alive and leave a trace
                _log_ui_diagnostic(store.data_dir, f"error card for {key}", card_exc)
        nav_state["current"] = key
        page_title_text.value = page_titles[key]
        mobile_nav_dropdown.value = key
        style_nav(previous, False)
        style_nav(key, True)
        page.update()

    def on_page_resize(_: Any = None) -> None:
        compact = is_compact()
        resized_control = False
        for control, maximum, reserve in responsive_width_bindings:
            new_width = responsive_dashboard_width(maximum, reserve)
            if getattr(control, "width", None) != new_width:
                control.width = new_width
                resized_control = True
        if compact != nav_state["compact"]:
            nav_state["compact"] = compact
            render_sidebar()
            resized_control = True
        if topology_canvas is not None:
            viewport_width = float(getattr(page, "width", None) or 1180)
            mobile_topology = viewport_width < 700
            topology_canvas.width = max(320.0 if mobile_topology else 1080.0,
                                       min(1400.0, viewport_width - 48.0))
            topology_canvas.height = 870 if mobile_topology else 610
            if topology_visual is not None:
                topology_visual.width = max(300.0, viewport_width - 28.0)
            render_topology()
            resized_control = True
        if resized_control:
            page.update()

    mark_stage("build responsive navigation")
    nav_state["compact"] = is_compact()
    render_sidebar()
    try:
        page.on_resize = on_page_resize
    except Exception:  # Beberapa klien tidak menyediakan event ubah ukuran.
        pass

    # The title column is the only flexible child of a NON-wrapping Row (Flutter cannot flex inside Wrap).
    topbar = ft.Column(
        controls=[
            ft.Row(
                controls=[
                    ft.Column(
                        controls=[
                            ft.Text("KAWAL TRACE  ›  KONSOL KEAMANAN", size=9, color=C["quiet"], weight=ft.FontWeight.BOLD),
                            page_title_text,
                        ], spacing=2, expand=True,
                    ),
                    refresh_button,
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=8,
            ),
            mobile_nav_dropdown,
        ],
        spacing=8,
    )
    if on_logout is not None:
        via_label = {
            "remembered": "perangkat diingat (tanpa kata sandi)", "password": "kata sandi",
            "pin": "PIN perangkat", "biometric": "biometrik perangkat",
        }.get(str(session.get("auth_via")), "sesi lokal")
        topbar.controls.insert(1, ft.Row(
            controls=[
                ft.Container(expand=True),
                ft.OutlinedButton(content="Keluar", icon=ft.Icons.LOGOUT, on_click=lambda e: on_logout(),
                                  style=ft.ButtonStyle(color=C["amber"])),
            ],
            vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=8,
        ))

    content_area = ft.Column(
        controls=[
            topbar,
            ft.Divider(color=C["line"], height=1),
            step_up_panel,
            page_body,
            footer,
        ],
        spacing=12,
        horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
    )

    mark_stage("attach dashboard layout")
    # SafeArea is the only expanded child of the page; everything below it receives tight constraints,
    # so only direct Row/Column children use `expand` (see the layout linter in the render-contract test).
    page.add(
        ft.SafeArea(
            expand=True,
            content=ft.Container(
                padding=ft.Padding(left=14, right=14, top=14, bottom=10),
                content=ft.Row(
                    controls=[
                        sidebar,
                        ft.Container(content=content_area, expand=True, bgcolor=C["bg"]),
                    ],
                    spacing=16, vertical_alignment=ft.CrossAxisAlignment.STRETCH,
                ),
            ),
        )
    )

    async def topology_animation_loop() -> None:
        while alive["on"]:
            await asyncio.sleep(0.08)
            if not alive["on"]:
                break
            if topology_canvas is not None and nav_state.get("current") == "dashboard":
                topology_phase["value"] = (topology_phase["value"] + 0.035) % 1.0
                render_topology()

    mark_stage("load initial archive and monitor data")
    archive_date_dropdown.on_select = refresh_archive_view
    refresh_archive_view()
    refresh_website_targets()
    page.run_task(initialize_website_monitor_store)
    mark_stage("refresh audit summary")
    refresh_summary()
    refresh_status_overview()
    if topology_canvas is not None:
        page.run_task(topology_animation_loop)
    # The first screen reports the current chain state immediately on launch.
    mark_stage("verify local audit chain")
    initial_result = store.verify()
    render_result(initial_result)
    set_notice("Pemeriksaan awal selesai." if initial_result.valid else "Peringatan: rantai tidak valid.",
               "good" if initial_result.valid else "danger")
    if notice:
        set_notice(notice, "warning")
    elif legacy_remote_archive:
        set_notice("Arsip server sudah dihentikan: semua arsip kini hanya di perangkat ini. Riwayat lama di server Anda "
                   "dapat diambil sekali lewat tombol di Riwayat & ekspor log.", "warning")

    def shutdown_dashboard() -> None:
        """Stop every loop, monitor and listener this dashboard started. Safe to call more than once.

        The shared scanner is NOT closed: it belongs to the whole app run, and overdue threats keep being
        removed by the headless guard in main() while nobody is signed in.
        """
        nonlocal syslog_receiver
        alive["on"] = False
        try:
            stop_live_stream()
        except Exception as exc:
            _log_ui_diagnostic(store.data_dir, "shutdown live stream", exc)
        website_monitor_state["active"] = False
        connector_runtime_state["syslog_active"] = False
        receiver, syslog_receiver = syslog_receiver, None
        if receiver is not None:
            try:
                receiver.close()
            except Exception as exc:
                _log_ui_diagnostic(store.data_dir, "shutdown syslog", exc)
        step_up_state["valid_until"] = 0.0
        step_up_state["pending"] = None

    if lifecycle is not None:
        lifecycle["shutdown"] = shutdown_dashboard
    mark_stage("start optional background tasks")
    page.run_task(background_telemetry_loop)
    page.run_task(doorbell_consumer)
    page.run_task(quarantine_due_loop)
    mark_stage("dashboard ready")



if __name__ == "__main__":
    ft.run(main)
