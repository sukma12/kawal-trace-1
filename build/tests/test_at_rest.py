"""Encryption at rest: what is protected, what happens when the key is wrong, missing or damaged.

Everything here runs against the real code and real SQLite files. The ONE thing that cannot be exercised on this
platform is the Windows DPAPI call itself; `FakeDpapi` tests the surrounding logic (file naming, refusal on
other platforms, migration of an old key file) and is labelled as such. Whether CryptProtectData works on a real
Windows machine is NOT proven by this file.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from chainlog.at_rest import (
    KEY_FILE_DPAPI,
    KEY_FILE_RAW,
    AtRestError,
    DataCipher,
    KeyMissingError,
    install_raw_key,
    load_cipher,
    resolve_cipher,
)
from chainlog.backup import create_backup, restore_backup, verify_backup
from chainlog.core import AuditStore
from chainlog.server_archive import ArchiveError, ServerEventArchive

PASS = "correct horse battery staple 42"
SECRET_IP = "203.0.113.77"
SECRET_USER = "root-backdoor-account"
PROFILE = "srv-at-rest-profile-001"


def raw_bytes_of_folder(folder: Path) -> bytes:
    """Everything an attacker holding a copy of the database files (but not the key) could read."""
    blob = b""
    for path in sorted(folder.glob("*")):
        if path.is_file() and path.name not in (KEY_FILE_RAW, KEY_FILE_DPAPI):
            blob += path.read_bytes()
    return blob


def make_store(folder: Path, *, cipher=None, events: int = 4, secret: bool = True) -> AuditStore:
    kwargs = {} if cipher is None else {"cipher": cipher}
    store = AuditStore(folder / "chainlog.sqlite3", **kwargs)
    store.initialize()
    for i in range(events):
        details = {"message": f"percobaan {i}"}
        if secret:
            details.update(source_ip=SECRET_IP, account=SECRET_USER)
        store.add_event("NOTE", "tester", "unit", details)
    return store


def swap_ciphertexts(db: Path, seq_a: int, seq_b: int) -> None:
    """What a file-level attacker does: edit the database directly, bypassing the application."""
    conn = sqlite3.connect(db)
    try:
        a = conn.execute("SELECT details_json FROM log_entries WHERE seq=?", (seq_a,)).fetchone()[0]
        b = conn.execute("SELECT details_json FROM log_entries WHERE seq=?", (seq_b,)).fetchone()[0]
        conn.execute("DROP TRIGGER deny_log_update")          # the trigger is a guardrail, not a defence
        conn.execute("UPDATE log_entries SET details_json=? WHERE seq=?", (b, seq_a))
        conn.execute("UPDATE log_entries SET details_json=? WHERE seq=?", (a, seq_b))
        conn.commit()
    finally:
        conn.close()


# ----------------------------------------------------------------------------------------------- the cipher
def test_cipher_roundtrip_unicode_and_fresh_nonce_each_time():
    cipher = DataCipher(b"k" * 32)
    text = '{"pesan": "Kalimantan ← Jakarta ✓", "ip": "198.51.100.9"}'
    first, second = cipher.encrypt_text(text, "audit|1"), cipher.encrypt_text(text, "audit|1")
    assert first != second                                   # random nonce: equal plaintexts do not look equal
    assert cipher.decrypt_text(first, "audit|1") == cipher.decrypt_text(second, "audit|1") == text
    assert text not in first and "198.51.100.9" not in first and DataCipher.is_encrypted(first)


def test_cipher_binds_each_value_to_its_row():
    cipher = DataCipher(b"k" * 32)
    sealed = cipher.encrypt_text("rahasia", "audit|5")
    with pytest.raises(AtRestError):
        cipher.decrypt_text(sealed, "audit|6")               # moved to another row
    with pytest.raises(AtRestError):
        cipher.decrypt_text(sealed, "archive|x|y")           # moved to another table


def test_cipher_rejects_wrong_key_flipped_bits_and_garbage():
    sealed = DataCipher(b"a" * 32).encrypt_text("rahasia", "ctx")
    with pytest.raises(AtRestError, match="tidak cocok atau isi diubah"):
        DataCipher(b"b" * 32).decrypt_text(sealed, "ctx")
    flipped = sealed[:-3] + ("A" if sealed[-3] != "A" else "B") + sealed[-2:]
    with pytest.raises(AtRestError):
        DataCipher(b"a" * 32).decrypt_text(flipped, "ctx")
    for garbage in ("kt1:", "kt1:@@@@", "kt1:" + "A" * 10, "plain text"):
        with pytest.raises(AtRestError):
            DataCipher(b"a" * 32).decrypt_text(garbage, "ctx")
    with pytest.raises(AtRestError):
        DataCipher(b"short")


# ----------------------------------------------------------------------------------------------- audit store
def test_audit_details_are_unreadable_in_the_file_but_normal_through_the_app(tmp_path):
    store = make_store(tmp_path)
    blob = raw_bytes_of_folder(tmp_path)
    assert SECRET_IP.encode() not in blob and SECRET_USER.encode() not in blob and b"percobaan" not in blob
    records = store.records()
    assert len(records) == 5                                   # init record + 4 events
    assert records[-1]["details"]["source_ip"] == SECRET_IP    # the app still sees plain values
    assert store.verify().valid
    conn = sqlite3.connect(tmp_path / "chainlog.sqlite3")
    try:
        stored = [r[0] for r in conn.execute("SELECT details_json FROM log_entries")]
    finally:
        conn.close()
    assert stored and all(value.startswith("kt1:") for value in stored)
    assert (tmp_path / KEY_FILE_RAW).exists() or (tmp_path / KEY_FILE_DPAPI).exists()


def test_legacy_plaintext_database_is_converted_with_the_identical_chain_head(tmp_path):
    # An old install: strictly plaintext rows (cipher=None opens the database as plain text).
    store = AuditStore(tmp_path / "chainlog.sqlite3", cipher=None)
    store.initialize()
    for i in range(6):
        store.add_event("NOTE", "tester", "unit", {"message": f"lama {i}", "source_ip": SECRET_IP})
    before = store.verify()
    assert before.valid and SECRET_IP.encode() in raw_bytes_of_folder(tmp_path)

    upgraded = AuditStore(tmp_path / "chainlog.sqlite3")      # the new app opens the same file
    upgraded.initialize()
    after = upgraded.verify()
    assert after.valid and after.count == before.count and after.head_hash == before.head_hash
    assert SECRET_IP.encode() not in raw_bytes_of_folder(tmp_path)
    assert upgraded.records()[3]["details"]["message"] == "lama 2"
    upgraded.add_event("NOTE", "tester", "unit", {"message": "baru"})   # still appendable after conversion
    assert upgraded.verify().valid


def test_chain_that_was_already_broken_is_not_touched_by_the_conversion(tmp_path):
    store = AuditStore(tmp_path / "chainlog.sqlite3", cipher=None)
    store.initialize()
    for i in range(3):
        store.add_event("NOTE", "tester", "unit", {"message": f"x{i}"})
    conn = sqlite3.connect(tmp_path / "chainlog.sqlite3")
    conn.execute("DROP TRIGGER deny_log_update")
    conn.execute("UPDATE log_entries SET details_json='{\"message\":\"dipalsukan\"}' WHERE seq=2")
    conn.commit()
    conn.close()
    assert not store.verify().valid
    opened = AuditStore(tmp_path / "chainlog.sqlite3")
    opened.initialize()                                        # must not "repair" or encrypt the evidence
    conn = sqlite3.connect(tmp_path / "chainlog.sqlite3")
    try:
        rows = [r[0] for r in conn.execute("SELECT details_json FROM log_entries")]
    finally:
        conn.close()
    assert all(not value.startswith("kt1:") for value in rows)
    assert not opened.verify().valid                           # evidence kept; the verifier still reports the break


def test_rows_swapped_in_the_file_are_detected(tmp_path):
    store = make_store(tmp_path)
    assert store.verify().valid
    swap_ciphertexts(tmp_path / "chainlog.sqlite3", 2, 3)
    # Two independent layers: the AES-GCM row binding refuses to open a ciphertext moved to another row ...
    swapped = {r["seq"]: r for r in store.records()}
    assert swapped[2]["details"] is None and swapped[3]["details"] is None
    # ... and the hash chain would reject the record even if the cipher layer were bypassed.
    result = store.verify()
    assert not result.valid and result.failing_seq in (2, 3)


def test_edited_ciphertext_is_detected(tmp_path):
    store = make_store(tmp_path)
    conn = sqlite3.connect(tmp_path / "chainlog.sqlite3")
    conn.execute("DROP TRIGGER deny_log_update")
    conn.execute("UPDATE log_entries SET details_json=details_json || 'A' WHERE seq=3")
    conn.commit()
    conn.close()
    result = store.verify()
    assert not result.valid and result.failing_seq == 3


def test_missing_key_with_encrypted_data_never_creates_a_new_key(tmp_path):
    make_store(tmp_path)
    (tmp_path / KEY_FILE_RAW).unlink()
    database_before = (tmp_path / "chainlog.sqlite3").read_bytes()
    with pytest.raises(AtRestError, match="TIDAK dibuat"):
        AuditStore(tmp_path / "chainlog.sqlite3").records()
    assert not (tmp_path / KEY_FILE_RAW).exists()              # no silent replacement: data would be orphaned
    assert (tmp_path / "chainlog.sqlite3").read_bytes() == database_before


def test_damaged_key_file_is_an_error_not_a_reason_to_generate_another(tmp_path):
    make_store(tmp_path)
    key_path = tmp_path / KEY_FILE_RAW
    original = key_path.read_bytes()
    key_path.write_bytes(original[:10])                        # truncated
    with pytest.raises(AtRestError, match="rusak atau terpotong"):
        AuditStore(tmp_path / "chainlog.sqlite3").records()
    assert key_path.read_bytes() == original[:10]              # untouched, so the user can restore it


def test_wrong_key_reads_as_tampering_not_as_empty(tmp_path):
    make_store(tmp_path)
    other = AuditStore(tmp_path / "chainlog.sqlite3", cipher=DataCipher(b"z" * 32))
    result = other.verify()
    assert not result.valid                                    # unreadable rows are reported, never skipped


def test_a_new_database_in_an_empty_folder_gets_a_key_automatically(tmp_path):
    folder = tmp_path / "fresh"
    store = make_store(folder, events=1)
    assert store.verify().valid
    assert len((folder / KEY_FILE_RAW).read_bytes()) == 32
    if os.name != "nt":
        assert (folder / KEY_FILE_RAW).stat().st_mode & 0o777 == 0o600


# ----------------------------------------------------------------------------------------------- backups
def test_backup_carries_the_key_so_a_new_device_can_open_the_data(tmp_path):
    source = tmp_path / "old-phone"
    make_store(source)
    backup = tmp_path / "out" / "b.ktbak"
    create_backup(source, backup, PASS)
    blob = backup.read_bytes()
    assert (source / KEY_FILE_RAW).read_bytes() not in blob    # the raw key is only inside the encrypted archive
    assert SECRET_IP.encode() not in blob
    assert verify_backup(backup, PASS).ok

    fresh = tmp_path / "new-phone"                             # a different device: no key yet
    restore_backup(backup, PASS, fresh, confirm=True)
    restored = AuditStore(fresh / "chainlog.sqlite3")
    assert restored.verify().valid and restored.verify().count == 5
    assert restored.records()[-1]["details"]["source_ip"] == SECRET_IP
    assert SECRET_IP.encode() not in raw_bytes_of_folder(fresh)


def test_restore_over_a_device_with_another_key_keeps_the_old_key_and_data_in_a_safety_folder(tmp_path):
    source = tmp_path / "old"
    make_store(source)
    backup = tmp_path / "b.ktbak"
    create_backup(source, backup, PASS)

    target = tmp_path / "target"
    make_store(target, events=2, secret=False)                 # the target has its own data and its own key
    old_key = (target / KEY_FILE_RAW).read_bytes()
    assert old_key != (source / KEY_FILE_RAW).read_bytes()
    report = restore_backup(backup, PASS, target, confirm=True)
    assert report.safety_copy is not None
    assert (report.safety_copy / KEY_FILE_RAW).read_bytes() == old_key
    assert (target / KEY_FILE_RAW).read_bytes() == (source / KEY_FILE_RAW).read_bytes()
    # both generations stay readable: the restored one in place, the replaced one from the safety copy
    assert AuditStore(target / "chainlog.sqlite3").verify().count == 5
    assert AuditStore(report.safety_copy / "chainlog.sqlite3").verify().count == 3


def test_a_backup_made_before_encryption_existed_still_restores(tmp_path):
    source = tmp_path / "old-install"
    store = AuditStore(source / "chainlog.sqlite3", cipher=None)
    store.initialize()
    store.add_event("NOTE", "tester", "unit", {"message": "lama", "source_ip": SECRET_IP})
    backup = tmp_path / "legacy.ktbak"
    create_backup(source, backup, PASS)
    assert not (source / KEY_FILE_RAW).exists()                # an old install never had a key

    fresh = tmp_path / "fresh"
    restore_backup(backup, PASS, fresh, confirm=True)
    reopened = AuditStore(fresh / "chainlog.sqlite3")
    reopened.initialize()                                      # converts, like every start
    assert reopened.verify().valid and SECRET_IP.encode() not in raw_bytes_of_folder(fresh)


# ----------------------------------------------------------------------------------------------- archive
def archive_event(event_id: str, stamp: str = "2026-10-22T01:00:00Z", ip: str = SECRET_IP) -> dict:
    return {"event_id": event_id, "timestamp_utc": stamp, "host_id": "host-1", "source": "journald",
            "event_type": "AUTH_FAILURE", "actor": SECRET_USER, "source_ip": ip,
            "details": {"reason": "failed_password", "service": "sshd.service"}}


def test_archive_payload_is_encrypted_on_disk_and_normal_through_the_api(tmp_path):
    archive = ServerEventArchive(tmp_path / "server-archive.sqlite3")
    assert archive.add_events(PROFILE, "Lab", [archive_event("a" * 64), archive_event("b" * 64, "2026-10-22T02:00:00Z")]) == 2
    blob = raw_bytes_of_folder(tmp_path)
    assert SECRET_IP.encode() not in blob and SECRET_USER.encode() not in blob and b"failed_password" not in blob
    listed = archive.list_events(PROFILE, "all")
    assert {e["actor"] for e in listed} == {SECRET_USER} and {e["source_ip"] for e in listed} == {SECRET_IP}
    assert archive.add_events(PROFILE, "Lab", [archive_event("a" * 64)]) == 0          # dedup compares plaintext
    with pytest.raises(ArchiveError, match="isi berbeda"):
        archive.add_events(PROFILE, "Lab", [archive_event("a" * 64, ip="198.51.100.200")])


def test_legacy_plaintext_archive_is_converted_on_open(tmp_path):
    path = tmp_path / "server-archive.sqlite3"
    legacy = ServerEventArchive(path, cipher=None)             # an archive written by an older version
    legacy.add_events(PROFILE, "Lab", [archive_event("c" * 64)])
    assert SECRET_IP.encode() in raw_bytes_of_folder(tmp_path)

    upgraded = ServerEventArchive(path)
    assert SECRET_IP.encode() not in raw_bytes_of_folder(tmp_path)
    assert upgraded.list_events(PROFILE, "all")[0]["source_ip"] == SECRET_IP


def test_archive_rows_cannot_be_swapped_or_edited_without_notice(tmp_path):
    path = tmp_path / "server-archive.sqlite3"
    archive = ServerEventArchive(path)
    archive.add_events(PROFILE, "Lab", [archive_event("d" * 64), archive_event("e" * 64, "2026-10-22T03:00:00Z", ip="192.0.2.5")])
    conn = sqlite3.connect(path)
    a = conn.execute("SELECT payload_json FROM server_events WHERE event_id=?", ("d" * 64,)).fetchone()[0]
    b = conn.execute("SELECT payload_json FROM server_events WHERE event_id=?", ("e" * 64,)).fetchone()[0]
    conn.execute("UPDATE server_events SET payload_json=? WHERE event_id=?", (b, "d" * 64))
    conn.execute("UPDATE server_events SET payload_json=? WHERE event_id=?", (a, "e" * 64))
    conn.commit()
    conn.close()
    with pytest.raises(ArchiveError, match="tidak bisa dibuka"):
        archive.list_events(PROFILE, "all")


def test_archive_with_missing_key_refuses_instead_of_starting_a_new_one(tmp_path):
    path = tmp_path / "server-archive.sqlite3"
    ServerEventArchive(path).add_events(PROFILE, "Lab", [archive_event("f" * 64)])
    (tmp_path / KEY_FILE_RAW).unlink()
    with pytest.raises(AtRestError, match="TIDAK dibuat"):
        ServerEventArchive(path).list_events(PROFILE, "all")
    assert not (tmp_path / KEY_FILE_RAW).exists()


def test_audit_store_and_archive_in_one_folder_share_one_key(tmp_path):
    make_store(tmp_path, events=1)
    ServerEventArchive(tmp_path / "server-archive.sqlite3").add_events(PROFILE, "Lab", [archive_event("1" * 64)])
    keys = [p for p in tmp_path.iterdir() if p.name.startswith("data-key")]
    assert [p.name for p in keys] == [KEY_FILE_RAW]


# ----------------------------------------------------------------------------------------------- key handling
def test_resolve_cipher_creates_a_key_only_when_nothing_depends_on_one(tmp_path):
    assert resolve_cipher(tmp_path, lambda: False).raw_key == (tmp_path / KEY_FILE_RAW).read_bytes()
    empty = tmp_path / "other"
    with pytest.raises(AtRestError):
        resolve_cipher(empty, lambda: True)
    assert not (empty / KEY_FILE_RAW).exists()
    with pytest.raises(KeyMissingError):
        load_cipher(empty, create=False)


def test_a_restore_that_swaps_the_key_is_noticed_without_restarting(tmp_path):
    first = load_cipher(tmp_path)
    assert load_cipher(tmp_path) is first                      # cached while the key file is unchanged
    install_raw_key(tmp_path, b"n" * 32)
    second = load_cipher(tmp_path)
    assert second is not first and second.raw_key == b"n" * 32


class FakeDpapi:
    """Stands in for CryptProtectData. NOT a test of Windows itself: it only lets the surrounding logic run here."""

    name = "dpapi"

    def protect(self, key: bytes) -> bytes:
        return bytes(b ^ 0x5A for b in key)[::-1]

    def unprotect(self, blob: bytes) -> bytes:
        return bytes(b ^ 0x5A for b in blob[::-1])


def test_dpapi_path_logic_with_a_fake_protector(tmp_path):
    cipher = load_cipher(tmp_path, protector=FakeDpapi())
    assert cipher.protection == "dpapi"
    stored = (tmp_path / KEY_FILE_DPAPI).read_bytes()
    assert stored.startswith(b"KTDPAPI1") and cipher.raw_key not in stored        # wrapped, never the raw key
    assert not (tmp_path / KEY_FILE_RAW).exists()
    assert load_cipher(tmp_path, protector=FakeDpapi()).raw_key == cipher.raw_key  # survives a reload

    with pytest.raises(AtRestError, match="hanya dapat dibuka di Windows"):         # copied to another platform
        load_cipher(tmp_path, protector=None)


def test_dpapi_install_removes_a_stale_plain_key_file(tmp_path):
    load_cipher(tmp_path, protector=None)                      # an earlier, file-protected key
    assert (tmp_path / KEY_FILE_RAW).exists()
    install_raw_key(tmp_path, b"q" * 32, protector=FakeDpapi())
    assert (tmp_path / KEY_FILE_DPAPI).exists() and not (tmp_path / KEY_FILE_RAW).exists()
    assert load_cipher(tmp_path, protector=FakeDpapi()).raw_key == b"q" * 32


def test_install_rejects_a_key_of_the_wrong_size_and_changes_nothing(tmp_path):
    original = load_cipher(tmp_path, protector=None).raw_key
    with pytest.raises(AtRestError):
        install_raw_key(tmp_path, b"short", protector=None)
    assert (tmp_path / KEY_FILE_RAW).read_bytes() == original


# ----------------------------------------------------------------------------------------------- cleanup of old plaintext
def test_conversion_scrubs_remnants_of_the_old_plaintext_from_the_file(tmp_path, monkeypatch):
    """Measured on this code: without the scrub a converted audit file still contained the old IP address."""
    import chainlog.core as core

    calls = []
    real = core.scrub_plaintext_remnants
    monkeypatch.setattr(core, "scrub_plaintext_remnants", lambda conn: (calls.append(1), real(conn))[1])
    legacy = AuditStore(tmp_path / "chainlog.sqlite3", cipher=None)
    legacy.initialize()
    legacy.add_event("NOTE", "tester", "unit", {"message": "lama", "source_ip": SECRET_IP})
    AuditStore(tmp_path / "chainlog.sqlite3").initialize()
    assert calls == [1]
    assert SECRET_IP.encode() not in raw_bytes_of_folder(tmp_path)
    # an already-encrypted database is not vacuumed again on every start
    AuditStore(tmp_path / "chainlog.sqlite3").initialize()
    assert calls == [1]


def test_archive_conversion_calls_the_scrub_too(tmp_path, monkeypatch):
    """For small archives the plaintext happened not to survive even without it, so the data check alone cannot
    prove the scrub runs here; this asserts the call itself."""
    import chainlog.server_archive as archive_module

    calls = []
    real = archive_module.scrub_plaintext_remnants
    monkeypatch.setattr(archive_module, "scrub_plaintext_remnants", lambda conn: (calls.append(1), real(conn))[1])
    path = tmp_path / "server-archive.sqlite3"
    ServerEventArchive(path, cipher=None).add_events(PROFILE, "Lab", [archive_event("9" * 64)])
    upgraded = ServerEventArchive(path)
    assert calls == [1] and upgraded.scrub_warning == ""
    ServerEventArchive(path)
    assert calls == [1]


def test_a_failed_scrub_is_reported_in_the_chain_and_does_not_lose_data(tmp_path, monkeypatch):
    import chainlog.core as core

    def failing(conn):
        raise sqlite3.OperationalError("disk penuh")

    monkeypatch.setattr(core, "scrub_plaintext_remnants", failing)
    legacy = AuditStore(tmp_path / "chainlog.sqlite3", cipher=None)
    legacy.initialize()
    legacy.add_event("NOTE", "tester", "unit", {"message": "lama", "source_ip": SECRET_IP})
    store = AuditStore(tmp_path / "chainlog.sqlite3")
    store.initialize()                                          # must not raise: the data is safely encrypted
    records = store.records()
    assert store.verify().valid
    assert records[1]["details"]["source_ip"] == SECRET_IP
    warning = records[-1]
    assert warning["event_type"] == "SYSTEM" and "belum dibersihkan" in warning["details"]["message"]
    assert "disk penuh" in warning["details"]["error"]


def test_a_failed_archive_scrub_is_exposed_as_a_warning(tmp_path, monkeypatch):
    import chainlog.server_archive as archive_module

    def failing(conn):
        raise sqlite3.OperationalError("disk penuh")

    monkeypatch.setattr(archive_module, "scrub_plaintext_remnants", failing)
    path = tmp_path / "server-archive.sqlite3"
    ServerEventArchive(path, cipher=None).add_events(PROFILE, "Lab", [archive_event("8" * 64)])
    upgraded = ServerEventArchive(path)
    assert "belum dibersihkan" in upgraded.scrub_warning and "disk penuh" in upgraded.scrub_warning
    assert upgraded.list_events(PROFILE, "all")[0]["source_ip"] == SECRET_IP
