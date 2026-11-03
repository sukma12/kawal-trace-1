"""What the user sees when the data key does not fit the data, driving the REAL `main.main` on the headless Flet
stand-in (tests/ui_harness.py). Structure and behaviour only, not pixels; not run on a real Flet client."""
from __future__ import annotations

import importlib
import sys

import pytest

import ui_harness as h
from chainlog.at_rest import KEY_FILE_RAW
from chainlog.core import AuditStore
from chainlog.device_identity import device_fingerprint


class Env:
    def __init__(self, main, ft, data_dir):
        self.main, self.ft, self.data_dir = main, ft, data_dir

    def start(self):
        page = self.ft.Page(width=420, platform="android")
        self.main.main(page)
        return page

    @staticmethod
    def texts(page):
        return [c.value for c in page.controls[0].walk() if c.kind == "Text" and isinstance(c.value, str)]

    @staticmethod
    def buttons(page):
        return [c for c in page.controls[0].walk() if c.kind in ("FilledButton", "OutlinedButton", "TextButton", "IconButton")]


@pytest.fixture
def env(tmp_path, monkeypatch):
    saved = {name: sys.modules.get(name) for name in ("flet", "main")}
    data_dir = tmp_path / "data"
    monkeypatch.setenv("KAWAL_TRACE_DATA_DIR", str(data_dir))
    ft = h.install_fake_flet()
    sys.modules.pop("main", None)
    main = importlib.import_module("main")
    monkeypatch.setattr(main, "device_fingerprint", lambda d: device_fingerprint(d, machine_id="this-computer"))
    store = AuditStore(data_dir / "chainlog.sqlite3")
    store.initialize()
    store.add_event("NOTE", "tester", "unit", {"message": "ada data", "source_ip": "203.0.113.77"})
    yield Env(main, ft, data_dir)
    for name, module in saved.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


def test_missing_key_shows_a_clear_page_and_changes_nothing(env):
    key = env.data_dir / KEY_FILE_RAW
    key.unlink()
    database = (env.data_dir / "chainlog.sqlite3").read_bytes()

    page = env.start()
    texts = env.texts(page)
    assert "DATA TIDAK BISA DIBUKA" in texts
    assert any("TIDAK dibuat" in t for t in texts)                    # the real reason, from the key layer
    assert any("Tidak ada data yang dihapus atau diubah" in t for t in texts)
    assert any("startup-errors.log" in t for t in texts) and any(t.startswith("Kode diagnosa: ") for t in texts)
    assert not any("Masuk dengan akun lokal" in t or "Buat akun administrator" in t for t in texts)   # no way past it

    assert not key.exists()                                            # no replacement key was created
    assert (env.data_dir / "chainlog.sqlite3").read_bytes() == database
    log = (env.data_dir / "startup-errors.log").read_text(encoding="utf-8")
    code = next(t for t in texts if t.startswith("Kode diagnosa: ")).split(": ", 1)[1]
    assert code in log and "data encryption key" in log
    assert "203.0.113.77" not in "".join(texts) + log                 # no data content leaks into the page or the log


def test_the_only_action_offered_is_to_retry(env):
    (env.data_dir / KEY_FILE_RAW).unlink()
    page = env.start()
    assert [str(b.content) for b in env.buttons(page)] == ["Coba lagi"]


def test_retry_works_once_the_key_is_back(env):
    key = env.data_dir / KEY_FILE_RAW
    saved = key.read_bytes()
    key.unlink()
    page = env.start()
    retry = env.buttons(page)[0]
    retry.on_click(None)
    assert "DATA TIDAK BISA DIBUKA" in env.texts(page)                 # still missing: still refused, still no new key
    assert not key.exists()

    key.write_bytes(saved)                                             # the user restores the key file
    retry.on_click(None)
    texts = env.texts(page)
    assert "DATA TIDAK BISA DIBUKA" not in texts
    assert any("Buat akun administrator" in t for t in texts) or any("Masuk dengan akun lokal" in t for t in texts)


def test_a_damaged_key_file_is_left_exactly_as_found(env):
    key = env.data_dir / KEY_FILE_RAW
    damaged = key.read_bytes()[:7]
    key.write_bytes(damaged)
    page = env.start()
    assert "DATA TIDAK BISA DIBUKA" in env.texts(page)
    assert any("rusak atau terpotong" in t for t in env.texts(page))
    assert key.read_bytes() == damaged                                 # not "repaired", not replaced


def test_healthy_data_goes_straight_to_the_normal_login(env):
    page = env.start()
    assert "DATA TIDAK BISA DIBUKA" not in env.texts(page)
