import hashlib
import os
import sqlite3
import sys

import pytest

from detectors.quarantine import GRACE_SECONDS_DEFAULT, QuarantineError, QuarantineVault


class Clock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture()
def env(tmp_path):
    clock = Clock()
    app = tmp_path / "app"          # stands in for the application's own data directory
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    vault = QuarantineVault(app / "quarantine", clock=clock, protected_extra=(app,))
    return vault, clock, downloads


def make(downloads, name="evil.bin", data=b"bad bytes"):
    path = downloads / name
    path.write_bytes(data)
    return path, sha(data)


def test_detected_file_is_moved_into_vault_with_15_minute_deadline(env):
    vault, clock, downloads = env
    path, digest = make(downloads)
    row = vault.register(path, digest, 9, "Test.Malware", "High")
    assert row["status"] == "QUARANTINED" and row["detection"] == "signature"
    assert row["deadline"] == clock.now + 15 * 60 == clock.now + GRACE_SECONDS_DEFAULT
    assert not path.exists()                                   # gone from where the user could run it
    stored = vault.vault_dir / row["vault_name"]
    assert stored.read_bytes() == b"bad bytes" and row["vault_name"].endswith(".quarantined")
    if os.name != "nt":
        assert stored.stat().st_mode & 0o111 == 0              # not executable
    assert vault.seconds_remaining(row) == 900


def test_user_can_delete_immediately_and_it_is_recorded(env):
    vault, clock, downloads = env
    path, digest = make(downloads)
    row = vault.register(path, digest, 9, "Test.Malware", "High")
    result = vault.delete(row["id"], actor="admin")
    assert result["status"] == "DELETED" and result["resolved_by"] == "admin"
    assert not (vault.vault_dir / row["vault_name"]).exists()
    with pytest.raises(QuarantineError):
        vault.delete(row["id"], actor="admin")                 # cannot be handled twice


def test_nothing_happens_before_deadline_then_auto_delete_after_15_minutes(env):
    vault, clock, downloads = env
    path, digest = make(downloads)
    row = vault.register(path, digest, 9, "Test.Malware", "High")
    clock.now += 14 * 60 + 59
    assert vault.process_due() == []
    assert (vault.vault_dir / row["vault_name"]).exists()
    clock.now += 2
    done = vault.process_due()
    assert [d["status"] for d in done] == ["AUTO_DELETED"]
    assert done[0]["resolved_by"] == "otomatis-15-menit"
    assert not (vault.vault_dir / row["vault_name"]).exists()
    assert vault.process_due() == []                           # idempotent


def test_restore_cancels_the_auto_delete(env):
    vault, clock, downloads = env
    path, digest = make(downloads)
    row = vault.register(path, digest, 9, "False.Positive", "Low")
    restored = vault.restore(row["id"], actor="admin")
    assert restored["status"] == "RESTORED" and path.read_bytes() == b"bad bytes"
    clock.now += 3600
    assert vault.process_due() == []
    assert path.exists()                                        # the deadline no longer applies


def test_restore_never_overwrites_a_newer_file(env):
    vault, clock, downloads = env
    path, digest = make(downloads)
    row = vault.register(path, digest, 9, "X", "Low")
    path.write_bytes(b"user's new file")
    restored = vault.restore(row["id"], actor="admin")
    assert path.read_bytes() == b"user's new file"
    assert (vault.restore_dir / f"{row['id']}-evil.bin").read_bytes() == b"bad bytes"
    assert "folder 'restored'" in restored["note"]


def test_file_swapped_before_move_is_put_back_and_not_deleted(env, monkeypatch):
    vault, clock, downloads = env
    path, digest = make(downloads)                              # scanner saw these bytes...
    path.write_bytes(b"completely different user data")         # ...but the file changed before the move
    row = vault.register(path, digest, 9, "X", "High")
    assert row["status"] == "SKIPPED_CHANGED"
    assert path.read_bytes() == b"completely different user data"
    clock.now += 7200
    assert vault.process_due() == []


def test_in_place_delete_rechecks_hash_and_refuses_changed_file(env):
    vault, clock, downloads = env
    path, digest = make(downloads)
    row = vault.register(path, digest, 9, "X", "High", quarantine=False)
    assert row["status"] == "PENDING_IN_PLACE" and path.exists()
    path.write_bytes(b"the user replaced it with something valuable")
    clock.now += 901
    done = vault.process_due()
    assert done[0]["status"] == "SKIPPED_CHANGED"
    assert path.read_bytes() == b"the user replaced it with something valuable"


def test_in_place_delete_removes_unchanged_file(env):
    vault, clock, downloads = env
    path, digest = make(downloads)
    vault.register(path, digest, 9, "X", "High", quarantine=False)
    clock.now += 901
    assert vault.process_due()[0]["status"] == "AUTO_DELETED"
    assert not path.exists()


def test_heuristic_findings_never_get_a_deadline(env):
    vault, clock, downloads = env
    path, digest = make(downloads, "maybe.apk", b"suspicious but unproven")
    row = vault.register(path, digest, 23, "Mencurigakan", "Medium", detection="heuristic", quarantine=False)
    assert row["deadline"] is None and row["status"] == "REVIEW"
    clock.now += 10**6
    assert vault.process_due() == [] and path.exists()


def test_symlink_is_not_followed_or_deleted(env):
    vault, clock, downloads = env
    target = downloads / "real.txt"
    target.write_bytes(b"precious")
    link = downloads / "link.bin"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    row = vault.register(link, sha(b"precious"), 8, "X", "High")
    assert row["status"] == "REVIEW" and row["deadline"] is None
    clock.now += 7200
    assert vault.process_due() == []
    assert target.read_bytes() == b"precious" and link.is_symlink()


def test_app_own_data_and_system_locations_are_never_auto_deleted(env, tmp_path):
    vault, clock, downloads = env
    own = tmp_path / "app" / "chainlog.sqlite3"
    own.write_bytes(b"audit db")
    row = vault.register(own, sha(b"audit db"), 8, "X", "High")
    assert row["status"] == "REVIEW" and "folder data aplikasi" in row["note"]
    clock.now += 7200
    vault.process_due()
    assert own.read_bytes() == b"audit db"
    system_file = "C:\\Windows\\System32\\x.dll" if os.name == "nt" else "/etc/hostname"
    row = vault.register(system_file, "a" * 64, 1, "X", "High")
    assert row["status"] == "REVIEW" and "sistem" in row["note"]


def test_project_source_folder_is_protected(env):
    vault, clock, downloads = env
    here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py")
    row = vault.register(here, "b" * 64, 1, "X", "High")
    assert row["status"] == "REVIEW" and row["deadline"] is None


def test_tampered_vault_name_cannot_escape_the_vault(env, tmp_path):
    vault, clock, downloads = env
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"do not delete")
    path, digest = make(downloads)
    row = vault.register(path, digest, 9, "X", "High")
    with sqlite3.connect(vault.db_path) as conn:
        conn.execute("UPDATE threats SET vault_name=? WHERE id=?", ("../../victim.txt", row["id"]))
    result = vault.delete(row["id"], actor="admin")
    assert result["status"] == "DELETE_FAILED"
    assert victim.read_bytes() == b"do not delete"


def test_delete_failure_is_recorded_not_hidden(env, monkeypatch):
    vault, clock, downloads = env
    path, digest = make(downloads)
    row = vault.register(path, digest, 9, "X", "High")
    real_unlink = type(vault.vault_dir).unlink

    def deny(self, *a, **k):
        raise PermissionError("locked")

    monkeypatch.setattr(type(vault.vault_dir), "unlink", deny)
    result = vault.delete(row["id"], actor="admin")
    assert result["status"] == "DELETE_FAILED" and "Gagal menghapus" in result["note"]
    monkeypatch.setattr(type(vault.vault_dir), "unlink", real_unlink)
    assert vault.delete(row["id"], actor="admin")["status"] == "DELETED"   # retry works


def test_missing_file_at_deadline_is_closed_cleanly(env):
    vault, clock, downloads = env
    path, digest = make(downloads)
    row = vault.register(path, digest, 9, "X", "High")
    (vault.vault_dir / row["vault_name"]).unlink()
    clock.now += 901
    assert vault.process_due()[0]["status"] == "AUTO_DELETED"


def test_duplicate_registration_is_deduplicated(env):
    vault, clock, downloads = env
    path, digest = make(downloads)
    a = vault.register(path, digest, 9, "X", "High", quarantine=False)
    b = vault.register(path, digest, 9, "X", "High", quarantine=False)
    assert a["id"] == b["id"] and len(vault.list_threats()) == 1


def test_history_purge_keeps_active_and_recent(env):
    vault, clock, downloads = env
    p1, d1 = make(downloads, "a.bin", b"aaa")
    p2, d2 = make(downloads, "b.bin", b"bbb")
    old = vault.register(p1, d1, 3, "A", "High")
    vault.delete(old["id"], actor="admin")
    clock.now += 40 * 86400
    active = vault.register(p2, d2, 3, "B", "High")
    assert vault.purge_history(30) == 1
    assert [t["id"] for t in vault.list_threats(active_only=False)] == [active["id"]]


def test_vault_files_and_db_are_private_on_posix(env):
    vault, clock, downloads = env
    if os.name == "nt":
        pytest.skip("POSIX permissions")
    assert vault.vault_dir.stat().st_mode & 0o077 == 0
    assert vault.db_path.stat().st_mode & 0o077 == 0
