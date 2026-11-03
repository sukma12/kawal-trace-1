from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import zipfile
from pathlib import Path

import pytest

from chainlog.backup import (
    CHUNK, MAGIC, BackupError, create_backup, list_backup_files, restore_backup, verify_backup,
)
from chainlog.core import AuditStore

PASS = "correct horse battery staple"


def make_data_dir(root: Path) -> Path:
    data = root / "data"
    store = AuditStore(data / "chainlog.sqlite3")
    store.initialize()
    for i in range(5):
        store.add_event("NOTE", "tester", "unit", {"message": f"event {i}"})
    (data / "sync-settings.json").write_text(json.dumps({"base_url": "https://example.test"}), encoding="utf-8")
    other = sqlite3.connect(data / "scanner.sqlite3")
    other.execute("CREATE TABLE t(x TEXT)")
    other.execute("INSERT INTO t VALUES ('row-1')")
    other.commit()
    other.close()
    (data / "startup-errors.log").write_text("must not be backed up")
    (data / "reports").mkdir()
    (data / "reports" / "x.json").write_text("{}")
    return data


def test_file_selection_excludes_logs_reports_and_journals(tmp_path):
    data = make_data_dir(tmp_path)
    (data / "chainlog.sqlite3-wal").write_bytes(b"x")
    (data / "weird name.json").write_text("{}")
    assert {p.name for p in list_backup_files(data)} == {"chainlog.sqlite3", "sync-settings.json", "scanner.sqlite3"}


def test_backup_is_encrypted_and_restore_roundtrip_on_a_fresh_device(tmp_path):
    data = make_data_dir(tmp_path)
    backup = tmp_path / "out" / "b.ktbak"
    info = create_backup(data, backup, PASS)
    assert info.files == ["chainlog.sqlite3", "scanner.sqlite3", "sync-settings.json"]
    blob = backup.read_bytes()
    assert blob.startswith(MAGIC)
    for needle in (b"example.test", b"row-1", b"SQLite format 3", b"event 3"):
        assert needle not in blob                       # nothing readable without the passphrase
    # real restore into an empty "new device" directory, then use the data
    fresh = tmp_path / "new-device"
    report = restore_backup(backup, PASS, fresh, confirm=True)
    assert sorted(report.restored) == info.files and report.safety_copy is None
    restored_store = AuditStore(fresh / "chainlog.sqlite3")
    result = restored_store.verify()
    assert result.valid and result.count == 6   # genesis record + 5 events
    assert json.loads((fresh / "sync-settings.json").read_text())["base_url"] == "https://example.test"
    assert sqlite3.connect(fresh / "scanner.sqlite3").execute("SELECT x FROM t").fetchone()[0] == "row-1"
    assert not list(fresh.glob("*.restore-tmp")) and not list(fresh.glob("kt-restore-*"))


def test_verify_backup_reports_chain_and_does_not_touch_live_data(tmp_path):
    data = make_data_dir(tmp_path)
    backup = tmp_path / "b.ktbak"
    create_backup(data, backup, PASS)
    before = hashlib.sha256((data / "chainlog.sqlite3").read_bytes()).hexdigest()
    report = verify_backup(backup, PASS)
    assert report.ok and report.audit_chain_valid and report.audit_records == 6 and report.created_utc.endswith("Z")
    assert hashlib.sha256((data / "chainlog.sqlite3").read_bytes()).hexdigest() == before


def test_wrong_passphrase_short_passphrase_and_bad_files(tmp_path):
    data = make_data_dir(tmp_path)
    backup = tmp_path / "b.ktbak"
    create_backup(data, backup, PASS)
    with pytest.raises(BackupError, match="Frasa sandi salah"):
        verify_backup(backup, "another long wrong passphrase")
    with pytest.raises(BackupError, match="minimal"):
        create_backup(data, tmp_path / "x.ktbak", "short")
    junk = tmp_path / "junk.ktbak"
    junk.write_bytes(b"not a backup at all")
    with pytest.raises(BackupError, match="Bukan file backup"):
        verify_backup(junk, PASS)
    with pytest.raises(BackupError):
        verify_backup(tmp_path / "missing.ktbak", PASS)


def test_tampering_and_truncation_are_detected(tmp_path):
    data = make_data_dir(tmp_path)
    backup = tmp_path / "b.ktbak"
    create_backup(data, backup, PASS)
    original = backup.read_bytes()
    flipped = bytearray(original)
    flipped[len(original) // 2] ^= 0x01
    (tmp_path / "flip.ktbak").write_bytes(bytes(flipped))
    with pytest.raises(BackupError):
        verify_backup(tmp_path / "flip.ktbak", PASS)
    (tmp_path / "cut.ktbak").write_bytes(original[:-5])
    with pytest.raises(BackupError):
        verify_backup(tmp_path / "cut.ktbak", PASS)


def test_multi_chunk_backup_detects_truncated_final_chunk_and_reordering(tmp_path):
    data = make_data_dir(tmp_path)
    (data / "big.json").write_text(json.dumps({"blob": os.urandom(int(CHUNK * 1.6)).hex()}), encoding="utf-8")
    backup = tmp_path / "big.ktbak"
    create_backup(data, backup, PASS)
    assert verify_backup(backup, PASS).ok
    raw = backup.read_bytes()
    header_len = int.from_bytes(raw[8:12], "big")
    pos = 12 + header_len
    chunks = []
    while pos < len(raw):
        length = int.from_bytes(raw[pos:pos + 4], "big")
        chunks.append(raw[pos:pos + 4 + length])
        pos += 4 + length
    assert len(chunks) >= 2
    prefix = raw[:12 + header_len]
    (tmp_path / "dropped-last.ktbak").write_bytes(prefix + b"".join(chunks[:-1]))     # silent truncation at a boundary
    with pytest.raises(BackupError):
        verify_backup(tmp_path / "dropped-last.ktbak", PASS)
    # the cipher layer alone (before any ZIP parsing) must also refuse it, via the authenticated "last chunk" flag
    from chainlog.backup import _decrypt_to
    with pytest.raises(BackupError, match="rusak/diubah"):
        _decrypt_to(tmp_path / "dropped-last.ktbak", PASS, tmp_path / "scratch.out")
    (tmp_path / "swapped.ktbak").write_bytes(prefix + chunks[1] + chunks[0] + b"".join(chunks[2:]))
    with pytest.raises(BackupError):
        verify_backup(tmp_path / "swapped.ktbak", PASS)


def test_restore_requires_confirmation_and_keeps_a_safety_copy(tmp_path):
    data = make_data_dir(tmp_path)
    backup = tmp_path / "b.ktbak"
    create_backup(data, backup, PASS)
    store = AuditStore(data / "chainlog.sqlite3")
    store.add_event("NOTE", "tester", "unit", {"message": "added after backup"})
    with pytest.raises(BackupError, match="konfirmasi"):
        restore_backup(backup, PASS, data)
    assert store.verify().count == 7                                   # unchanged after the refused attempt
    report = restore_backup(backup, PASS, data, confirm=True)
    assert AuditStore(data / "chainlog.sqlite3").verify().count == 6   # rolled back to backup state
    assert report.safety_copy and (report.safety_copy / "chainlog.sqlite3").exists()
    assert AuditStore(report.safety_copy / "chainlog.sqlite3").verify().count == 7   # the newer data is still recoverable


def test_stale_wal_files_are_removed_so_they_cannot_corrupt_the_restored_db(tmp_path):
    data = make_data_dir(tmp_path)
    backup = tmp_path / "b.ktbak"
    create_backup(data, backup, PASS)
    (data / "chainlog.sqlite3-wal").write_bytes(b"stale wal bytes")
    (data / "chainlog.sqlite3-shm").write_bytes(b"stale shm bytes")
    restore_backup(backup, PASS, data, confirm=True)
    assert not (data / "chainlog.sqlite3-wal").exists() or (data / "chainlog.sqlite3-wal").read_bytes() != b"stale wal bytes"
    assert AuditStore(data / "chainlog.sqlite3").verify().valid


def _forge(tmp_path, entries, manifest=None):
    """Build a validly-encrypted backup around a hostile ZIP to test the restore-side defences."""
    import detectors  # noqa: F401  (keeps import order stable)
    from chainlog import backup as b
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as z:
        files = {}
        for name, data in entries.items():
            z.writestr(name, data)
            files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        z.writestr("manifest.json", json.dumps(manifest or {"files": files}))
    return payload.getvalue(), b


def _encrypt_payload(b, payload: bytes, dest: Path):
    import struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, prefix = os.urandom(16), os.urandom(4)
    header = json.dumps({"v": 1, "alg": "scrypt+AES-256-GCM-chunked", "n": b.SCRYPT_N, "r": 8, "p": 1,
                         "salt": b._b64(salt), "nonce_prefix": b._b64(prefix), "chunk": b.CHUNK,
                         "created_utc": "2026-01-01T00:00:00Z"}, sort_keys=True, separators=(",", ":")).encode()
    hh = hashlib.sha256(header).digest()
    ct = AESGCM(b._derive(PASS.encode(), salt, b.SCRYPT_N, 8, 1)).encrypt(b._nonce(prefix, 0), payload, b._chunk_aad(hh, 0, True))
    dest.write_bytes(b.MAGIC + struct.pack(">I", len(header)) + header + struct.pack(">I", len(ct)) + ct)


@pytest.mark.parametrize("evil_name", ["../escape.json", "sub/dir.json", "/abs.json", "..\\win.json", "run.exe", "a b.json", ".hidden.json"])
def test_zip_slip_and_disallowed_names_are_rejected(tmp_path, evil_name):
    payload, b = _forge(tmp_path, {evil_name: b"{}"})
    forged = tmp_path / "evil.ktbak"
    _encrypt_payload(b, payload, forged)
    target = tmp_path / "victim"
    with pytest.raises(BackupError, match="tidak diizinkan"):
        restore_backup(forged, PASS, target, confirm=True)
    assert not (tmp_path / "escape.json").exists() and not list(target.glob("*.json"))


def test_manifest_checksum_mismatch_and_extra_files_are_rejected(tmp_path):
    payload, b = _forge(tmp_path, {"settings.json": b'{"a":1}'}, manifest={"files": {"settings.json": {"sha256": "0" * 64, "size": 7}}})
    forged = tmp_path / "bad-sum.ktbak"
    _encrypt_payload(b, payload, forged)
    with pytest.raises(BackupError, match="Checksum"):
        verify_backup(forged, PASS)
    payload2, b = _forge(tmp_path, {"a.json": b"{}", "b.json": b"{}"}, manifest={"files": {"a.json": {"sha256": hashlib.sha256(b"{}").hexdigest(), "size": 2}}})
    forged2 = tmp_path / "extra.ktbak"
    _encrypt_payload(b, payload2, forged2)
    with pytest.raises(BackupError, match="tidak cocok dengan manifest"):
        verify_backup(forged2, PASS)


def test_backup_with_broken_audit_chain_is_refused_unless_explicitly_allowed(tmp_path):
    data = make_data_dir(tmp_path)
    conn = sqlite3.connect(data / "chainlog.sqlite3")
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    conn.close()
    # tamper with the audit table through a trigger-free raw edit of record contents
    conn = sqlite3.connect(data / "chainlog.sqlite3")
    try:
        conn.execute("DROP TRIGGER IF EXISTS audit_no_update")
    except sqlite3.Error:
        pass
    triggers = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")]
    for name in triggers:
        conn.execute(f'DROP TRIGGER IF EXISTS "{name}"')
    event_table = next(t for t in tables if "event" in t.lower() or "record" in t.lower() or "log" in t.lower())
    cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{event_table}")')]
    column = next((c for c in cols if c in {"details_json", "details", "actor"}), None)
    assert column, cols
    conn.execute(f'UPDATE "{event_table}" SET "{column}" = "{column}" || \'x\' WHERE rowid = 2')
    conn.commit()
    conn.close()
    assert not AuditStore(data / "chainlog.sqlite3").verify().valid
    backup = tmp_path / "tampered.ktbak"
    create_backup(data, backup, PASS)
    assert verify_backup(backup, PASS).audit_chain_valid is False
    with pytest.raises(BackupError, match="Rantai audit"):
        restore_backup(backup, PASS, tmp_path / "t2", confirm=True)
    forced = restore_backup(backup, PASS, tmp_path / "t3", confirm=True, allow_invalid_chain=True)
    assert "chainlog.sqlite3" in forced.restored


def test_hostile_kdf_parameters_in_header_are_rejected_before_deriving_a_key(tmp_path):
    data = make_data_dir(tmp_path)
    backup = tmp_path / "b.ktbak"
    create_backup(data, backup, PASS)
    raw = backup.read_bytes()
    hlen = int.from_bytes(raw[8:12], "big")
    header = json.loads(raw[12:12 + hlen])
    header["n"] = 2 ** 30                                              # would demand a huge amount of memory
    new_header = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    evil = raw[:8] + len(new_header).to_bytes(4, "big") + new_header + raw[12 + hlen:]
    (tmp_path / "evil.ktbak").write_bytes(evil)
    with pytest.raises(BackupError, match="di luar batas"):
        verify_backup(tmp_path / "evil.ktbak", PASS)


# ---------------------------------------------------------------- accounts are per device and never travel
def _add_identity(data: Path, marker: str) -> bytes:
    conn = sqlite3.connect(data / "identity.sqlite3")
    conn.execute("CREATE TABLE IF NOT EXISTS users(name TEXT)")
    conn.execute("INSERT INTO users VALUES (?)", (marker,))
    conn.commit()
    conn.close()
    return (data / "identity.sqlite3").read_bytes()


def test_backups_do_not_contain_the_device_bound_account_database(tmp_path):
    data = make_data_dir(tmp_path)
    _add_identity(data, "akun-perangkat-lama")
    assert "identity.sqlite3" not in {p.name for p in list_backup_files(data)}
    info = create_backup(data, tmp_path / "b.ktbak", PASS)
    assert "identity.sqlite3" not in info.files
    assert b"akun-perangkat-lama" not in (tmp_path / "b.ktbak").read_bytes()


def test_restore_keeps_this_devices_accounts_even_from_an_older_backup_that_contains_them(tmp_path, monkeypatch):
    import chainlog.backup as backup_module

    source = make_data_dir(tmp_path / "old-device")
    _add_identity(source, "akun-perangkat-lama")
    monkeypatch.setattr(backup_module, "DEVICE_BOUND_FILES", frozenset())      # how versions before this change made backups
    old_backup = tmp_path / "older.ktbak"
    assert "identity.sqlite3" in create_backup(source, old_backup, PASS).files
    monkeypatch.undo()

    target = tmp_path / "new-device"
    target.mkdir()
    mine = _add_identity(target, "akun-yang-baru-saya-buat")
    report = restore_backup(old_backup, PASS, target, confirm=True)
    assert report.skipped == ["identity.sqlite3"] and "identity.sqlite3" not in report.restored
    assert (target / "identity.sqlite3").read_bytes() == mine                  # the account I just signed in with survives
    assert "chainlog.sqlite3" in report.restored                               # everything else is restored as before
    assert report.safety_copy is None or not (report.safety_copy / "identity.sqlite3").exists()   # it was never touched
