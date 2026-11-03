"""Sign-in, remembered-device and per-device-account flows, driving the REAL `main.main` on the headless Flet
stand-in (tests/ui_harness.py).

Like the other UI tests this checks structure and behaviour, not pixels: it cannot prove how the screens look
or how `ft.Checkbox` behaves on a real Windows/Android client.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib
import sys
import types
from pathlib import Path

import pytest

import ui_harness as h
from chainlog.core import AuditStore
from chainlog.device_identity import SESSION_FILE, device_fingerprint

PASS = "a long enough passphrase"


class Screen:
    """Convenience view over whatever `main.main` has drawn on one fake page."""

    def __init__(self, page):
        self.page = page

    @property
    def root(self):
        return self.page.controls[0]

    def texts(self):
        return [c.value for c in self.root.walk() if c.kind == "Text" and isinstance(c.value, str)]

    def field(self, label):
        return h.find(self.root, "TextField", label=label)[0]

    def has_field(self, label):
        return bool(h.find(self.root, "TextField", label=label))

    def button(self, kind, content):
        return h.find(self.root, kind, content=content)[0]

    def checkbox(self):
        return h.find(self.root, "Checkbox")[0]

    def on_dashboard(self):
        return any(t == "KAWAL TRACE  ›  KONSOL KEAMANAN" for t in self.texts())

    def on_login(self):
        return self.has_field("Kata sandi") or self.has_field("Buat kata sandi (8–128 karakter)")


class Env:
    def __init__(self, main, ft, data_dir):
        self.main, self.ft, self.data_dir = main, ft, data_dir

    def start(self) -> Screen:
        page = self.ft.Page(width=420, platform="android")
        self.main.main(page)
        return Screen(page)

    @property
    def token_file(self) -> Path:
        return self.data_dir / SESSION_FILE

    def store(self):
        return AuditStore(self.data_dir / "chainlog.sqlite3")

    def other_device(self, monkeypatch, machine="another-computer"):
        real = device_fingerprint
        monkeypatch.setattr(self.main, "device_fingerprint", lambda d: real(d, machine_id=machine))


@pytest.fixture
def env(tmp_path, monkeypatch):
    saved = {name: sys.modules.get(name) for name in ("flet", "main")}
    data_dir = tmp_path / "data"
    monkeypatch.setenv("KAWAL_TRACE_DATA_DIR", str(data_dir))
    ft = h.install_fake_flet()
    sys.modules.pop("main", None)
    main = importlib.import_module("main")
    monkeypatch.setattr(main, "device_fingerprint", lambda d: device_fingerprint(d, machine_id="this-computer"))
    yield Env(main, ft, data_dir)
    for name, module in saved.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


def create_first_account(screen, username="owner01", password=PASS):
    screen.field("Buat username administrator (4–10 karakter)").value = username
    screen.field("Buat kata sandi (8–128 karakter)").value = password
    screen.field("Ulangi kata sandi (8–128 karakter)").value = password
    screen.button("FilledButton", "Buat akun administrator").on_click(None)


def sign_in(screen, username="owner01", password=PASS):
    screen.field("Username (4–10 karakter)").value = username
    screen.field("Kata sandi").value = password
    screen.button("FilledButton", "Masuk dengan akun lokal").on_click(None)


# ----------------------------------------------------------------------------------- first run / remembered device
def test_first_run_offers_account_creation_with_the_remember_choice_on_by_default(env):
    screen = env.start()
    assert screen.on_login() and not screen.on_dashboard()
    assert screen.checkbox().value is True and screen.checkbox().visible is True
    assert "tanpa login ulang sampai 30 hari" in str(screen.checkbox().label)
    assert any("siapa pun yang membuka aplikasi" in t for t in screen.texts())          # the trade-off is stated
    assert not any("berbeda dari perangkat" in t for t in screen.texts())               # no "other device" text on a clean install


def test_creating_the_account_signs_in_remembers_the_device_and_the_next_start_skips_login(env):
    first = env.start()
    create_first_account(first)
    assert first.on_dashboard()
    assert env.token_file.is_file() and oct(env.token_file.stat().st_mode & 0o777) == "0o600"
    before = env.token_file.read_text()

    second = env.start()                                          # the app is opened again on the same device
    assert second.on_dashboard() and not second.on_login()
    assert any("perangkat diingat" in t for t in second.texts())
    assert env.token_file.read_text() != before                    # single-use token was rotated

    audit = [r["details"] for r in env.store().records() if r["source"] == "local-auth"]
    assert [a["action"] for a in audit] == ["first_admin_created", "remembered_device"]
    assert [a["via"] for a in audit] == ["password", "remembered"]
    assert env.store().verify().valid


def test_auth_audit_records_are_tagged_with_this_install_device_and_platform(env):
    screen = env.start()
    create_first_account(screen)
    records = [r for r in env.store().records() if r["event_type"] == "AUTH" and r["source"] == "local-auth"]
    assert records
    details = records[-1]["details"]
    assert details["action"] == "first_admin_created"
    assert details["device_id"] == device_fingerprint(env.data_dir, machine_id="this-computer")
    assert details["platform"] == "android"


def test_signing_out_forgets_the_device_and_the_next_start_asks_for_the_password(env):
    first = env.start()
    create_first_account(first)
    first.button("OutlinedButton", "Keluar").on_click(None)
    assert first.on_login() and not first.on_dashboard()
    assert any(t.startswith("Anda sudah keluar") for t in first.texts())
    assert not env.token_file.exists()
    assert env.start().on_login()                                  # a fresh start does not log back in
    assert env.store().verify().valid


def test_sign_out_stops_the_dashboard_loops_so_signing_in_again_does_not_stack_them(env):
    first = env.start()
    create_first_account(first)
    loops = {t[0].__name__: t[0] for t in first.page.tasks}
    assert {"background_telemetry_loop", "quarantine_due_loop"} <= set(loops) and "background_sync_loop" not in loops
    first.button("OutlinedButton", "Keluar").on_click(None)
    for name in ("background_telemetry_loop", "quarantine_due_loop"):
        asyncio.run(asyncio.wait_for(loops[name](), timeout=3))   # each loop returns instead of running forever


def test_unticking_remember_signs_in_without_leaving_a_token(env):
    first = env.start()
    create_first_account(first)
    first.button("OutlinedButton", "Keluar").on_click(None)
    first.checkbox().value = False
    sign_in(first)
    assert first.on_dashboard() and not env.token_file.exists()
    assert env.start().on_login()


def test_wrong_password_stays_on_login_and_leaves_no_session(env):
    first = env.start()
    create_first_account(first)
    first.button("OutlinedButton", "Keluar").on_click(None)
    sign_in(first, password="not the right one")
    assert first.on_login() and not first.on_dashboard()
    assert any(t.startswith("Kredensial tidak valid") for t in first.texts())
    assert not env.token_file.exists()


# ----------------------------------------------------------------------------------- different device -> different account
def test_another_device_must_create_its_own_account_and_cannot_use_the_first_ones(env, monkeypatch):
    first = env.start()
    create_first_account(first)                                    # device A: account "owner01", token remembered
    assert env.token_file.is_file()

    env.other_device(monkeypatch)                                  # same data folder, different device ID (copied folder)
    other = env.start()
    assert other.on_login() and not other.on_dashboard()           # the token of device A does not open anything here
    assert other.has_field("Buat username administrator (4–10 karakter)")   # asked to CREATE an account
    assert any("berbeda dari perangkat" in t for t in other.texts())
    assert not env.token_file.exists()                             # the foreign token was discarded, not reused

    create_first_account(other, username="phone01", password="a different phrase")
    assert other.on_dashboard()
    from chainlog.auth import UserRegistry

    registry = UserRegistry(env.data_dir / "identity.sqlite3", device_fingerprint(env.data_dir, machine_id="another-computer"))
    assert [u["username"] for u in registry.list_users()] == ["phone01"]
    original = UserRegistry(env.data_dir / "identity.sqlite3", device_fingerprint(env.data_dir, machine_id="this-computer"))
    assert [u["username"] for u in original.list_users()] == ["owner01"]       # the first device's account was not touched
    assert original.authenticate("owner01", PASS) is not None


def test_same_device_keeps_using_the_same_account(env):
    first = env.start()
    create_first_account(first)
    first.button("OutlinedButton", "Keluar").on_click(None)
    again = env.start()
    assert again.has_field("Username (4–10 karakter)") and not again.has_field("Buat username administrator (4–10 karakter)")
    sign_in(again)
    assert again.on_dashboard()


# ----------------------------------------------------------------------------------- failures are shown, never swallowed
def test_when_the_device_id_cannot_be_created_the_screen_says_so_and_remember_is_off(env, monkeypatch):
    def broken(_dir):
        raise OSError("read-only file system")

    monkeypatch.setattr(env.main, "device_fingerprint", broken)
    screen = env.start()
    assert any(t.startswith("ID perangkat tidak dapat dibuat (OSError") for t in screen.texts())
    assert screen.checkbox().visible is False
    create_first_account(screen)                                   # the app still works, but is honest that it is unbound
    assert screen.on_dashboard() and not env.token_file.exists()
    assert (env.data_dir / "startup-errors.log").is_file()         # and the cause is in the diagnostics log


def test_a_failure_to_remember_is_reported_on_the_dashboard_and_leaves_no_usable_session(env, monkeypatch):
    def cannot_write(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(env.main, "write_session_token", cannot_write)
    first = env.start()
    create_first_account(first)
    assert first.on_dashboard()
    assert any(t.startswith("Ingat-perangkat gagal (OSError)") for t in first.texts())
    assert not env.token_file.exists()
    assert env.start().on_login()                                  # nothing half-remembered remains


def test_a_failure_to_rotate_the_token_still_opens_the_dashboard_but_warns_and_revokes(env, monkeypatch):
    first = env.start()
    create_first_account(first)
    real = env.main.write_session_token
    calls = {"n": 0}

    def fail_on_rotation(*args, **kwargs):
        calls["n"] += 1
        raise OSError("disk full")

    monkeypatch.setattr(env.main, "write_session_token", fail_on_rotation)
    second = env.start()
    assert second.on_dashboard() and calls["n"] == 1
    assert any(t.startswith("Token perangkat tidak dapat diperbarui") for t in second.texts())
    monkeypatch.setattr(env.main, "write_session_token", real)
    assert env.start().on_login()                                  # the consumed token cannot be replayed


def test_a_garbage_or_stale_token_file_is_ignored_and_removed(env):
    first = env.start()
    create_first_account(first)
    env.token_file.write_text("x" * 60)                            # well-formed but unknown token
    again = env.start()
    assert again.on_login() and not again.on_dashboard()
    assert not env.token_file.exists()


# ----------------------------------------------------------------------------------- the 15-minute rule keeps working while locked out
def _bad_file(scanner, directory: Path):
    data = b"harmless bytes registered as a test signature"
    scanner.import_signature_text(f"{hashlib.sha256(data).hexdigest()},Test.Trojan,High")
    path = directory / "invoice.bin"
    path.write_bytes(data)
    assert scanner.scan_file(path).status == "MALWARE"
    return path


def _one_guard_cycle(main, monkeypatch, guard):
    """Run exactly one 15-second cycle of the guard without waiting: the second sleep ends the coroutine."""
    shim = types.ModuleType("asyncio_shim")
    shim.__dict__.update(asyncio.__dict__)
    state = {"sleeps": 0}

    async def fast_sleep(_seconds, *args):
        state["sleeps"] += 1
        if state["sleeps"] > 1:
            raise asyncio.CancelledError()

    shim.sleep = fast_sleep
    monkeypatch.setattr(main, "asyncio", shim)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(guard())


def test_overdue_threats_are_removed_by_the_headless_guard_while_nobody_is_signed_in(env, monkeypatch, tmp_path):
    first = env.start()
    create_first_account(first)
    first.button("OutlinedButton", "Keluar").on_click(None)        # now on the login screen, no dashboard alive
    scanner = env.main._shared_scanner(env.data_dir)
    quarantined = _bad_file(scanner, tmp_path)
    threats = scanner.vault.list_threats(active_only=True, limit=5)
    assert len(threats) == 1 and threats[0]["deadline"] is not None
    scanner.vault._clock = lambda: threats[0]["deadline"] + 1     # the 15 minutes have passed

    guard = next(t[0] for t in first.page.tasks if t[0].__name__ == "quarantine_guard")
    _one_guard_cycle(env.main, monkeypatch, guard)

    assert scanner.vault.list_threats(active_only=True, limit=5) == []
    assert scanner.vault.get(threats[0]["id"])["status"] == "AUTO_DELETED"
    assert not quarantined.exists()
    events = [r["details"]["message"] for r in env.store().records() if r["source"] == "pemindai-keamanan"]
    assert "Ancaman dihapus otomatis" in events                    # silent for the user, recorded in the audit chain
    assert env.store().verify().valid


def test_the_guard_leaves_threats_to_the_dashboard_loop_while_a_dashboard_is_open(env, monkeypatch, tmp_path):
    first = env.start()
    create_first_account(first)                                    # dashboard alive
    scanner = env.main._shared_scanner(env.data_dir)
    _bad_file(scanner, tmp_path)
    threat = scanner.vault.list_threats(active_only=True, limit=5)[0]
    scanner.vault._clock = lambda: threat["deadline"] + 1
    guard = next(t[0] for t in first.page.tasks if t[0].__name__ == "quarantine_guard")
    _one_guard_cycle(env.main, monkeypatch, guard)
    assert scanner.vault.get(threat["id"])["status"] in {"QUARANTINED", "PENDING_IN_PLACE"}   # untouched by the guard


def test_the_guard_does_not_start_the_scanner_when_nothing_is_waiting(env, monkeypatch):
    first = env.start()
    create_first_account(first)
    first.button("OutlinedButton", "Keluar").on_click(None)
    env.main._SCANNER_CACHE.clear()
    guard = next(t[0] for t in first.page.tasks if t[0].__name__ == "quarantine_guard")
    _one_guard_cycle(env.main, monkeypatch, guard)
    assert env.main._SCANNER_CACHE == {}                           # no worker process was spawned for nothing


def test_one_scanner_is_shared_per_data_folder(env):
    a = env.main._shared_scanner(env.data_dir)
    assert env.main._shared_scanner(env.data_dir) is a
    assert env.main._shared_scanner(env.data_dir / ".." / "data") is a
