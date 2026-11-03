"""Dashboard render-contract tests.

They execute the REAL `_build_dashboard` code from main.py against a headless Flet stand-in
(tests/ui_harness.py): every sidebar entry is clicked, the mounted control tree is linted for layout
patterns that make the Flutter client paint a grey error surface, and the scanner/backup screens are driven
end to end. This is GUI-structure testing, not a rendering test: it cannot see pixels, so a run on a real
Windows/Android client is still required before the UI is called fixed.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import sys
import types
from pathlib import Path

import pytest

import ui_harness as h
from chainlog.auth import UserRegistry
from chainlog.backup import verify_backup
from chainlog.core import AuditStore

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
PHISH_TEXT = "Your account has been suspended. Verify your password immediately at http://secure-login.example.xyz/verify"
PASS = "a long enough passphrase"


class Built:
    def __init__(self, main, page, root, stage, data_dir):
        self.main, self.page, self.root, self.stage, self.data_dir = main, page, root, stage, data_dir

    def nav_buttons(self):
        return [c for c in self.root.walk() if c.kind == "Container" and c.ink and c.on_click and c.tooltip]

    def nav(self, title):
        return next(c for c in self.nav_buttons() if c.tooltip == title)

    def open(self, title):
        """Click a sidebar entry; only the active page is mounted, so look-ups need the right page open."""
        self.nav(title).on_click(None)
        return self

    def body(self):
        """The persistent scrollable page body (the expanding scroll Column that is NOT inside the sidebar)."""
        sidebar = next(c for c in self.root.walk() if c.kind == "Container" and c.width in (66, 236))
        inside_sidebar = {id(n) for n in sidebar.walk()}
        candidates = [c for c in self.root.walk() if c.kind == "Column" and c.scroll is not None and c.expand is True
                      and id(c) not in inside_sidebar]
        assert len(candidates) == 1, len(candidates)
        return candidates[0]

    def button(self, kind, content):
        return h.find(self.root, kind, content=content)[0]

    def field(self, label):
        return h.find(self.root, "TextField", label=label)[0]

    def texts(self):
        return [c.value for c in self.root.walk() if c.kind == "Text" and isinstance(c.value, str)]

    def picker(self):
        return next(c for c in self.page.services if getattr(c, "kind", "") == "FilePicker")

    def store(self):
        return AuditStore(self.data_dir / "chainlog.sqlite3")


@pytest.fixture
def build_ui(tmp_path, monkeypatch):
    saved = {name: sys.modules.get(name) for name in ("flet", "main")}
    monkeypatch.setenv("KAWAL_TRACE_DATA_DIR", str(tmp_path / "data"))
    ft = h.install_fake_flet()
    sys.modules.pop("main", None)
    main = importlib.import_module("main")

    def build(role: str = "admin", width: int = 1280, auth_via: str = "password", on_logout=None, notice: str = "",
              with_account: bool = False) -> Built:
        """`auth_via="password"` models a session that just typed its password (sensitive actions run at once);
        "remembered" models a reopened app on a remembered device (sensitive actions must re-verify)."""
        store = AuditStore()
        store.initialize()
        registry = UserRegistry(store.data_dir / "identity.sqlite3")
        if with_account and registry.needs_setup():
            registry.create_initial_admin("admin", PASS)
        page = ft.Page(width=width)
        stage = {"name": ""}
        lifecycle: dict = {}
        session = {"username": "admin" if role == "admin" else "viewer1", "role": role, "auth_via": auth_via}
        main._build_dashboard(page, session, registry, stage, on_logout=on_logout, lifecycle=lifecycle, notice=notice)
        root = page.controls[0]
        built = Built(main, page, root, stage, store.data_dir)
        built.lifecycle, built.registry = lifecycle, registry
        return built

    yield build
    for name, module in saved.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


def active_titles(ui: Built) -> list[str]:
    return [c.tooltip for c in ui.nav_buttons() if c.bgcolor == ui.main.C["panel_lift"]]


# ---------------------------------------------------------------------------- structure
def test_dashboard_reaches_ready_and_shows_content_not_just_a_sidebar(build_ui):
    ui = build_ui()
    assert ui.stage["name"] == "dashboard ready"
    text = " ".join(ui.texts())
    # The headless test adapter has no Canvas renderer; the real labels are asserted
    # in the topology source contract, while this adapter must still mount the dashboard.
    for needle in ("Visualisasi koneksi aktif saat aplikasi berjalan pada Flet.", "TOTAL RECORD"):
        assert needle in text
    assert "CHAIN HEALTH" not in text
    assert "Rantai terverifikasi" not in text
    assert not (ui.data_dir / "startup-errors.log").exists()      # nothing was silently swallowed


def test_every_menu_exists_and_clicking_each_swaps_content_without_rebuilding_the_sidebar(build_ui):
    ui = build_ui()
    titles = [c.tooltip for c in ui.nav_buttons()]
    assert titles == ["Dashboard", "Jejak Aktivitas", "Catat Aktivitas", "Pantau Folder", "Pantau Website",
                      "Integrasi Server", "Telemetri & Arsip", "Konektor Audit", "Pemindai Keamanan",
                      "Perlindungan Lanjutan", "Backup & Restore", "Akun Operator"]
    sidebar_ids = [id(c) for c in ui.nav_buttons()]
    seen_bodies = set()
    for title in titles:
        before = ui.page.update_count
        ui.nav(title).on_click(None)
        assert ui.page.update_count > before                             # the click repainted the page
        assert [id(c) for c in ui.nav_buttons()] == sidebar_ids          # same objects: nothing was disposed mid-click
        assert active_titles(ui) == [title]                              # exactly one highlighted entry
        page_title = [t for t in ui.texts() if t == title]
        assert page_title, f"page title not shown for {title}"
        content = [c for c in ui.root.walk() if c.kind == "Text" and c.value and c.value != title]
        assert len(content) > 8                                          # real content, not an empty surface
        seen_bodies.add(tuple(id(c) for c in ui.body().controls))
    assert len(seen_bodies) == len(titles)                               # each menu mounts its own controls
    assert not (ui.data_dir / "startup-errors.log").exists()


def test_layout_linter_finds_no_flutter_hazards_on_any_page(build_ui):
    ui = build_ui()
    assert h.lint_tree(ui.root) == []
    for button in ui.nav_buttons():
        button.on_click(None)
        assert h.lint_tree(ui.root) == [], button.tooltip


def test_linter_actually_detects_the_patterns_it_guards_against():
    ft = h.install_fake_flet()
    bad_wrap = ft.Row(controls=[ft.Column(controls=[], expand=True)], wrap=True)
    bad_scroll = ft.Column(controls=[ft.Container(expand=True)], scroll="auto")
    bad_field = ft.Row(controls=[ft.TextField(label="x")])
    bad_parent = ft.Container(content=ft.Column(controls=[], expand=True))
    for tree in (bad_wrap, bad_scroll, bad_field, bad_parent):
        assert h.lint_tree(tree), tree.kind
    assert h.lint_tree(ft.Row(controls=[ft.TextField(label="x", expand=True)])) == []


def test_viewer_does_not_get_the_account_menu_and_cannot_use_admin_tools(build_ui):
    ui = build_ui(role="viewer")
    assert "Akun Operator" not in [c.tooltip for c in ui.nav_buttons()]
    ui.open("Pemindai Keamanan")
    assert ui.button("OutlinedButton", "Impor daftar hash").disabled is True
    ui.open("Backup & Restore")
    assert ui.button("FilledButton", "Buat backup terenkripsi").disabled is True
    assert ui.button("OutlinedButton", "Pulihkan dari backup").disabled is True


def test_a_page_that_fails_to_mount_shows_an_error_card_and_the_rest_keeps_working(build_ui):
    ui = build_ui()
    body = ui.body()

    class Exploding(type(body)):
        armed = True

        @property
        def controls(self):
            return self.__dict__.get("_c", [])

        @controls.setter
        def controls(self, value):
            if Exploding.armed and value and value is not self.__dict__.get("_c") and len(value) == 1 and getattr(value[0], "kind", "") == "Container" \
                    and "Pemindai malware & phishing (offline)" in [getattr(n, "value", "") for n in value[0].walk()]:
                raise RuntimeError("simulated client failure token=abc123")
            self.__dict__["_c"] = value

    body.__class__ = Exploding
    body.__dict__["_c"] = list(body.__dict__.get("controls", []))
    ui.nav("Pemindai Keamanan").on_click(None)
    shown = " ".join(str(getattr(n, "value", "")) for n in body.controls[0].walk()) if body.controls else ""
    assert "tidak dapat dimuat" in shown and "abc123" not in shown        # visible error, secret redacted
    log = (ui.data_dir / "startup-errors.log").read_text(encoding="utf-8")
    assert "mount page pemindai" in log and "abc123" not in log
    Exploding.armed = False
    ui.nav("Catat Aktivitas").on_click(None)                              # other pages still open normally
    assert active_titles(ui) == ["Catat Aktivitas"]


def test_compact_phone_layout_swaps_sidebar_for_selector_and_back(build_ui):
    ui = build_ui(width=400)
    sidebar = next(c for c in ui.root.walk() if c.kind == "Container" and c.width in (66, 236))
    dropdown = h.find(ui.root, "Dropdown", label="Menu aplikasi")[0]
    assert sidebar.visible is False and dropdown.visible is True
    assert len(dropdown.options) == 12 and dropdown.width and dropdown.width <= 400
    dropdown.value = "backup"
    dropdown.on_select(None)
    assert any(t == "Backup & Restore" for t in ui.texts())
    assert h.lint_tree(ui.root) == []
    ui.page.width = 1280
    ui.page.on_resize(None)
    assert sidebar.visible is True and dropdown.visible is False and sidebar.width == 236
    assert h.lint_tree(ui.root) == []


def test_status_overview_does_not_render_duplicate_status_rows(build_ui):
    ui = build_ui()
    text = ui.texts()
    # The runtime status is represented by the animated topology, not a second list below it.
    for row in ("Website", "Koneksi server", "Sumber audit", "Kesehatan agen", "API feed",
                "Event keamanan", "Pemindai keamanan", "SSH", "Database audit"):
        assert row not in text, row
    assert not any(t.startswith("Diperbarui: ") for t in text)


def test_status_overview_does_not_echo_server_profile_or_endpoint_in_a_duplicate_list(build_ui, tmp_path):
    from chainlog.servers import ServerRegistryStore
    from chainlog.sync import SyncSettings
    data = tmp_path / "data"
    data.mkdir(mode=0o700, exist_ok=True)
    ServerRegistryStore(data / "server-registry.json").upsert(
        "Server uji", SyncSettings(base_url="https://api.example.test", device_id="cl-device-test-001"))
    ui = build_ui()
    text = ui.texts()
    # Server status remains consumed by the Canvas animation; it is no longer duplicated as text rows.
    assert not any("Server uji" in t for t in text)
    assert not any("Belum terhubung" in t for t in text)
    assert not any("api.example.test" in t for t in text)


def test_app_build_is_12_and_version_stays_1_0(build_ui):
    ui = build_ui()
    assert ui.main.APP_VERSION == "1.0" and ui.main.APP_BUILD == "13"
    assert any(t == "v1.0 · build 12" for t in ui.texts())


# ---------------------------------------------------------------------------- scanner screen
def run(coro):
    return asyncio.run(coro)


def test_scanning_a_known_bad_file_end_to_end_turns_the_banner_red_and_audits_it(build_ui, tmp_path):
    ui = build_ui()
    ui.nav("Pemindai Keamanan").on_click(None)
    bad = tmp_path / "eicar.com"
    bad.write_bytes(EICAR)
    ui.field("File atau email (.eml) yang akan dipindai").value = str(bad)
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))
    banner = next(c for c in ui.root.walk() if c.kind == "Text" and isinstance(c.value, str) and c.value.startswith("MALWARE TERDETEKSI"))
    assert banner.color == ui.main.C["red"] and "eicar.com" in banner.value
    assert any("[HASH_MATCH]" in t for t in ui.texts())
    assert any("MALWARE · FILE · eicar.com" in t for t in ui.texts())            # history row rendered
    events = [r for r in ui.store().records() if r["event_type"] == "ALERT" and r["source"] == "pemindai-keamanan"]
    assert len(events) == 1 and events[0]["details"]["status"] == "MALWARE"
    assert ui.store().verify().valid


def test_clean_file_is_green_and_bad_input_is_reported_not_swallowed(build_ui, tmp_path):
    ui = build_ui()
    ui.open("Pemindai Keamanan")
    ok = tmp_path / "notes.txt"
    ok.write_text("hello")
    path_field = ui.field("File atau email (.eml) yang akan dipindai")
    path_field.value = str(ok)
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))
    green = next(c for c in ui.root.walk() if c.kind == "Text" and isinstance(c.value, str) and c.value.startswith("TIDAK ADA KECOCOKAN"))
    assert green.color == ui.main.C["green"]
    path_field.value = str(tmp_path / "missing.bin")
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))
    assert any(t == "PEMINDAIAN GAGAL" for t in ui.texts()) and any("tidak ditemukan" in t for t in ui.texts())
    path_field.value = ""
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))          # empty input -> notice, no crash


def test_pasted_phishing_text_is_flagged_through_the_async_queue(build_ui):
    ui = build_ui()
    ui.open("Pemindai Keamanan")
    ui.field("Atau tempel isi email / URL").value = PHISH_TEXT
    run(ui.button("FilledButton", "Pindai teks / URL").on_click(None))
    assert any(t.startswith("PHISHING TERDETEKSI") for t in ui.texts())
    assert any("[AI_DETECTION]" in t for t in ui.texts())



def test_clear_history_button_removes_database_rows_and_details_through_ui(build_ui, tmp_path):
    ui = build_ui()
    ui.open("Pemindai Keamanan")
    sample = tmp_path / "history-clean.txt"
    sample.write_text("history entry")
    ui.field("File atau email (.eml) yang akan dipindai").value = str(sample)
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))

    from detectors.scanner_db import ScannerDatabase
    db = ScannerDatabase(ui.data_dir / "scanner" / "scanner.sqlite3")
    assert db.history_count() == 1
    assert db.details(db.history(1)[0]["id"])

    run(ui.button("OutlinedButton", "Bersihkan seluruh riwayat").on_click(None))
    assert db.history_count() == 0
    with db._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_details").fetchone()[0] == 0
    assert "Belum ada riwayat pemindaian." in ui.texts()
    assert any("Seluruh riwayat pemindaian dihapus dari database" in t for t in ui.texts())

def test_viewer_can_scan_but_nothing_is_written_to_the_audit_chain(build_ui, tmp_path):
    ui = build_ui(role="viewer")
    ui.open("Pemindai Keamanan")
    before = len(ui.store().records())
    bad = tmp_path / "eicar.com"
    bad.write_bytes(EICAR)
    ui.field("File atau email (.eml) yang akan dipindai").value = str(bad)
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))
    assert any(t.startswith("MALWARE TERDETEKSI") for t in ui.texts())
    assert len(ui.store().records()) == before


def test_signature_import_through_the_ui_changes_the_next_verdict(build_ui, tmp_path):
    import hashlib
    ui = build_ui()
    ui.open("Pemindai Keamanan")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"custom sample")
    lst = tmp_path / "hashes.txt"
    lst.write_text(f"{hashlib.sha256(b'custom sample').hexdigest()},Custom.Trojan,High\nbadline\n")

    async def pick_files(**kwargs):
        return [types.SimpleNamespace(path=str(lst))]
    ui.picker().pick_files = pick_files
    run(ui.button("OutlinedButton", "Impor daftar hash").on_click(None))
    ui.field("File atau email (.eml) yang akan dipindai").value = str(sample)
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))
    assert any("Custom.Trojan" in t for t in ui.texts())


# ---------------------------------------------------------------------------- backup screen
@pytest.mark.parametrize("picker_writes_bytes", [True, False])
def test_backup_verify_and_restore_roundtrip_through_the_ui(build_ui, tmp_path, picker_writes_bytes):
    ui = build_ui()
    ui.nav("Backup & Restore").on_click(None)
    destination = tmp_path / "chosen" / "saved.ktbak"

    async def save_file(**kwargs):
        destination.parent.mkdir(exist_ok=True)
        if picker_writes_bytes and kwargs.get("src_bytes"):
            destination.write_bytes(kwargs["src_bytes"])      # mobile/web behaviour
        return str(destination)                               # desktop behaviour: path only, app must write
    ui.picker().save_file = save_file
    ui.field("Frasa sandi backup (min. 14 karakter)").value = PASS
    ui.field("Ulangi frasa sandi (hanya untuk membuat backup)").value = PASS + "x"
    run(ui.button("FilledButton", "Buat backup terenkripsi").on_click(None))
    assert not destination.exists()                                               # mismatch -> refused
    ui.field("Ulangi frasa sandi (hanya untuk membuat backup)").value = PASS
    count_at_backup = len(ui.store().records())
    run(ui.button("FilledButton", "Buat backup terenkripsi").on_click(None))
    assert destination.exists() and destination.read_bytes().startswith(b"KTBAK1")
    assert not list((ui.data_dir / "backups").glob("*.ktbak"))                    # staging copy removed after saving
    assert verify_backup(destination, PASS).ok

    async def pick_files(**kwargs):
        return [types.SimpleNamespace(path=str(destination))]
    ui.picker().pick_files = pick_files
    ui.field("Frasa sandi backup (min. 14 karakter)").value = PASS
    run(ui.button("OutlinedButton", "Verifikasi backup").on_click(None))
    assert any(t.startswith("BACKUP VALID") for t in ui.texts())

    store = ui.store()
    store.add_event("NOTE", "admin", "unit", {"message": "written after the backup"})
    after = len(store.records())
    assert after > count_at_backup
    run(ui.button("OutlinedButton", "Pulihkan dari backup").on_click(None))       # checkbox not ticked -> refused
    assert len(ui.store().records()) == after
    h.find(ui.root, "Checkbox")[0].value = True
    run(ui.button("OutlinedButton", "Pulihkan dari backup").on_click(None))
    assert any(t.startswith("PEMULIHAN SELESAI") for t in ui.texts())
    assert len(ui.store().records()) == count_at_backup and ui.store().verify().valid
    assert list(ui.data_dir.glob("restore-safety-*"))                              # previous data kept aside


def test_wrong_passphrase_is_reported_and_live_data_is_untouched(build_ui, tmp_path):
    ui = build_ui()
    ui.open("Backup & Restore")
    destination = tmp_path / "b.ktbak"

    async def save_file(**kwargs):
        destination.write_bytes(kwargs["src_bytes"])
        return str(destination)
    ui.picker().save_file = save_file
    for label in ("Frasa sandi backup (min. 14 karakter)", "Ulangi frasa sandi (hanya untuk membuat backup)"):
        ui.field(label).value = PASS
    run(ui.button("FilledButton", "Buat backup terenkripsi").on_click(None))

    async def pick_files(**kwargs):
        return [types.SimpleNamespace(path=str(destination))]
    ui.picker().pick_files = pick_files
    ui.field("Frasa sandi backup (min. 14 karakter)").value = "wrong passphrase entirely"
    before = len(ui.store().records())
    h.find(ui.root, "Checkbox")[0].value = True
    run(ui.button("OutlinedButton", "Pulihkan dari backup").on_click(None))
    assert any("Frasa sandi salah" in t for t in ui.texts())
    assert len(ui.store().records()) == before


def test_viewer_cannot_create_or_restore_backups(build_ui, tmp_path):
    ui = build_ui(role="viewer")
    ui.open("Backup & Restore")
    ui.field("Frasa sandi backup (min. 14 karakter)").value = PASS
    run(ui.button("FilledButton", "Buat backup terenkripsi").on_click(None))
    assert not (ui.data_dir / "backups").exists()


def press_background_task(ui, kind, label):
    """Buttons that use page.run_task only record the task in the fake page; run the recorded coroutine."""
    ui.page.tasks.clear()
    ui.button(kind, label).on_click(None)
    handler, args, kwargs = ui.page.tasks[-1]
    return run(handler(*args, **kwargs))


def test_detected_file_shows_threat_card_then_user_can_delete_it_now(build_ui, tmp_path):
    ui = build_ui()
    ui.nav("Pemindai Keamanan").on_click(None)
    bad = tmp_path / "dropper.com"
    bad.write_bytes(EICAR)
    ui.field("File atau email (.eml) yang akan dipindai").value = str(bad)
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))
    texts = ui.texts()
    assert not bad.exists()                                                    # moved out of the user's folder
    assert any(t.startswith("Lokasi asal:") and "dropper.com" in t for t in texts)
    assert any(t.startswith("SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") for t in texts)
    assert any(t.startswith("Dihapus otomatis pukul") for t in texts)          # the 15-minute rule is visible
    press_background_task(ui, "FilledButton", "Hapus sekarang")
    texts = ui.texts()
    assert any("Tidak ada ancaman yang menunggu tindakan." == t for t in texts)
    assert any("dihapus pengguna" in t for t in texts)                          # recorded in the visible history
    events = [r["details"]["message"] for r in ui.store().records() if r["source"] == "pemindai-keamanan" and "Ancaman" in r["details"].get("message", "")]
    assert events == ["Ancaman dihapus pengguna"]
    assert ui.store().verify().valid


def test_viewer_cannot_delete_or_restore_threats(build_ui, tmp_path):
    ui = build_ui(role="viewer")
    ui.nav("Pemindai Keamanan").on_click(None)
    bad = tmp_path / "dropper.com"
    bad.write_bytes(EICAR)
    ui.field("File atau email (.eml) yang akan dipindai").value = str(bad)
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))
    assert ui.button("FilledButton", "Hapus sekarang").disabled
    assert ui.button("OutlinedButton", "Pulihkan (salah deteksi)").disabled


def test_scanning_a_folder_reports_one_summary(build_ui, tmp_path):
    ui = build_ui()
    ui.nav("Pemindai Keamanan").on_click(None)
    folder = tmp_path / "unduhan"
    folder.mkdir()
    (folder / "a.txt").write_text("aman")
    (folder / "tagihan.pdf").write_bytes(b"MZ" + b"\x90" * 400)
    ui.field("File atau email (.eml) yang akan dipindai").value = str(folder)
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))
    assert any(t.startswith("MENCURIGAKAN · folder: unduhan") for t in ui.texts())
    assert any("2 file dipindai, 1 ditandai" in t for t in ui.texts())


# ---------------------------------------------------------------------------- sessions, logout, step-up verification
def _step_up_panel(ui):
    """The inline re-verification panel (innermost container that holds its heading)."""
    holders = [c for c in ui.root.walk() if c.kind == "Container" and any(
        t.kind == "Text" and t.value == "VERIFIKASI ULANG DIPERLUKAN" for t in c.walk())]
    return min(holders, key=lambda c: len(list(c.walk())))


def _run_last_task(ui):
    handler, args, kwargs = ui.page.tasks[-1]
    return run(handler(*args, **kwargs))


def _fill_pin(ui, pin="73829164"):
    ui.field("PIN baru perangkat (8–12 angka)").value = pin
    ui.field("Ulangi PIN").value = pin


def _answer_step_up(ui, secret):
    ui.field("Kata sandi atau PIN Anda").value = secret
    press_background_task(ui, "FilledButton", "Verifikasi & lanjutkan")


def test_remembered_session_must_reverify_before_a_sensitive_action_and_then_it_runs(build_ui):
    ui = build_ui(auth_via="remembered", with_account=True)
    ui.open("Perlindungan Lanjutan")
    _fill_pin(ui)
    ui.button("FilledButton", "Simpan PIN perangkat").on_click(None)
    assert not ui.registry.has_device_pin("admin")                       # NOT executed yet
    assert _step_up_panel(ui).visible is True
    assert any("menyimpan PIN perangkat" in t for t in ui.texts())        # the user is told what they are authorising

    _answer_step_up(ui, "kata sandi yang salah")
    assert not ui.registry.has_device_pin("admin")
    assert _step_up_panel(ui).visible is True
    assert any(t.startswith("Verifikasi gagal") for t in ui.texts())

    _answer_step_up(ui, PASS)
    assert ui.registry.has_device_pin("admin")                            # the original action ran, once
    assert _step_up_panel(ui).visible is False

    ui.button("OutlinedButton", "Hapus PIN perangkat").on_click(None)    # inside the 5-minute window: no second prompt
    assert not ui.registry.has_device_pin("admin")
    assert _step_up_panel(ui).visible is False

    outcomes = [r["details"]["result"] for r in ui.store().records() if r["details"].get("action") == "step_up"]
    assert outcomes == ["failed", "success"]
    assert ui.store().verify().valid


def test_a_fresh_password_login_counts_as_verification(build_ui):
    ui = build_ui(auth_via="password", with_account=True)
    ui.open("Perlindungan Lanjutan")
    _fill_pin(ui)
    ui.button("FilledButton", "Simpan PIN perangkat").on_click(None)
    assert ui.registry.has_device_pin("admin")
    assert _step_up_panel(ui).visible is False


def test_biometric_login_is_not_a_fresh_verification(build_ui):
    ui = build_ui(auth_via="biometric", with_account=True)
    ui.open("Perlindungan Lanjutan")
    _fill_pin(ui)
    ui.button("FilledButton", "Simpan PIN perangkat").on_click(None)
    assert not ui.registry.has_device_pin("admin") and _step_up_panel(ui).visible is True


def test_session_without_a_known_login_method_fails_closed(build_ui):
    ui = build_ui(auth_via="", with_account=True)
    ui.open("Perlindungan Lanjutan")
    _fill_pin(ui)
    ui.button("FilledButton", "Simpan PIN perangkat").on_click(None)
    assert not ui.registry.has_device_pin("admin") and _step_up_panel(ui).visible is True


def test_verification_window_is_five_minutes_and_expires(build_ui, monkeypatch):
    assert sys.modules["main"].STEP_UP_SECONDS == 300
    monkeypatch.setattr(sys.modules["main"], "STEP_UP_SECONDS", 0)       # an already-expired window
    ui = build_ui(auth_via="password", with_account=True)
    ui.open("Perlindungan Lanjutan")
    _fill_pin(ui)
    ui.button("FilledButton", "Simpan PIN perangkat").on_click(None)
    assert not ui.registry.has_device_pin("admin") and _step_up_panel(ui).visible is True


def test_cancelling_the_prompt_discards_the_pending_action(build_ui):
    ui = build_ui(auth_via="remembered", with_account=True)
    ui.open("Perlindungan Lanjutan")
    _fill_pin(ui)
    ui.button("FilledButton", "Simpan PIN perangkat").on_click(None)
    ui.button("OutlinedButton", "Batal").on_click(None)
    assert _step_up_panel(ui).visible is False
    ui.page.tasks.clear()
    ui.button("FilledButton", "Verifikasi & lanjutkan").on_click(None)    # nothing pending any more
    run(ui.page.tasks[-1][0](*ui.page.tasks[-1][1]))
    assert not ui.registry.has_device_pin("admin")


def test_repeated_wrong_answers_lock_the_prompt_even_for_the_right_password(build_ui):
    ui = build_ui(auth_via="remembered", with_account=True)
    ui.open("Perlindungan Lanjutan")
    _fill_pin(ui)
    ui.button("FilledButton", "Simpan PIN perangkat").on_click(None)
    for _ in range(5):
        _answer_step_up(ui, "salah-salah-salah")
    _answer_step_up(ui, PASS)                                            # right password, but the account is locked out
    assert not ui.registry.has_device_pin("admin")
    assert any(t.startswith("Verifikasi gagal") for t in ui.texts())


def test_restoring_a_quarantined_file_needs_reverification_on_a_remembered_session(build_ui, tmp_path):
    ui = build_ui(auth_via="remembered", with_account=True)
    ui.nav("Pemindai Keamanan").on_click(None)
    bad = tmp_path / "dropper.com"
    bad.write_bytes(EICAR)
    ui.field("File atau email (.eml) yang akan dipindai").value = str(bad)
    run(ui.button("FilledButton", "Pindai file / email").on_click(None))
    assert not bad.exists()
    ui.page.tasks.clear()
    ui.button("OutlinedButton", "Pulihkan (salah deteksi)").on_click(None)
    run(ui.page.tasks[-1][0](*ui.page.tasks[-1][1]))                     # the guarded handler only opens the prompt
    assert not bad.exists() and _step_up_panel(ui).visible is True
    _answer_step_up(ui, PASS)
    _run_last_task(ui)                                                   # the verified restore is scheduled, then run
    assert bad.exists() and bad.read_bytes() == EICAR


def test_sign_out_button_exists_only_when_a_handler_is_given_and_calls_it(build_ui):
    assert not [b for b in h.find(build_ui().root, "OutlinedButton", content="Keluar")]
    calls = []
    ui = build_ui(auth_via="remembered", on_logout=lambda: calls.append("out"))
    button = ui.button("OutlinedButton", "Keluar")
    assert not any("perangkat diingat" in t for t in ui.texts())       # login-method caption is intentionally hidden
    button.on_click(None)
    assert calls == ["out"]


def test_sign_out_shutdown_ends_the_background_loops_and_is_repeatable(build_ui):
    ui = build_ui()
    names = {t[0].__name__ for t in ui.page.tasks}
    assert "background_sync_loop" not in names                         # nothing uploads local data any more
    loops = {h_[0].__name__: h_[0] for h_ in ui.page.tasks if h_[0].__name__ in
             {"background_telemetry_loop", "quarantine_due_loop"}}
    assert set(loops) == {"background_telemetry_loop", "quarantine_due_loop"}
    ui.lifecycle["shutdown"]()
    ui.lifecycle["shutdown"]()                                           # idempotent
    for name, loop in loops.items():
        asyncio.run(asyncio.wait_for(loop(), timeout=3))                 # returns instead of looping forever


def test_a_startup_notice_is_shown_on_the_dashboard(build_ui):
    ui = build_ui(notice="Ingat-perangkat gagal (OSError); login berikutnya memerlukan kata sandi.")
    assert any(t.startswith("Ingat-perangkat gagal") for t in ui.texts())


def test_remote_folder_monitor_has_no_local_picker_start_or_stop_controls(build_ui):
    ui = build_ui()
    ui.nav("Pantau Folder").on_click(None)
    visible_text = " ".join(ui.texts())
    assert "PEMANTAUAN FOLDER SERVER" in visible_text
    assert "ROOT SERVER YANG DIPANTAU OTOMATIS" in visible_text
    assert "Pilih folder" not in visible_text
    assert "Mulai pemantauan" not in visible_text
    assert "Hentikan" not in visible_text


def test_dashboard_exposes_local_telemetry_pipeline_self_test():
    import inspect
    import main

    source = inspect.getsource(main)
    assert 'content="Uji pipeline lokal"' in source
    assert "run_telemetry_self_test" in source
    assert "archive_readback" in source or "run_telemetry_self_test" in source
    assert 'content="Uji koneksi endpoint privat"' in source
    assert "probe_private_endpoint" in source
