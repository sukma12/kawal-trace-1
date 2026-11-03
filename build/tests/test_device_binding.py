import os
import shutil
import sqlite3
import time

import pytest

from chainlog.auth import (AUTH_LOCKOUT_MAX_SECONDS, AUTH_LOCKOUT_SECONDS, SESSION_DAYS, SESSION_MAX_DAYS,
                           AuthenticationError, UserRegistry)
from chainlog.device_identity import (clear_session_token, device_fingerprint, install_secret, read_session_token,
                                      write_session_token)

PW = "CorrectHorse9"


def fp(data_dir, machine="machine-A"):
    return device_fingerprint(data_dir, machine_id=machine)


# ----------------------------------------------------------------------------- fingerprint
def test_fingerprint_is_stable_per_device_and_differs_across_devices(tmp_path):
    a1 = fp(tmp_path / "a")
    assert a1 == fp(tmp_path / "a") and len(a1) == 64
    assert a1 != fp(tmp_path / "b")                    # another install secret
    assert a1 != fp(tmp_path / "a", machine="machine-B")  # same data folder copied onto another computer
    assert "machine-A" not in a1


def test_install_secret_is_private_and_corruption_is_not_silently_reused(tmp_path):
    first = install_secret(tmp_path)
    if os.name != "nt":
        assert (tmp_path / "device-secret.bin").stat().st_mode & 0o077 == 0
    (tmp_path / "device-secret.bin").write_bytes(b"short")
    assert install_secret(tmp_path) != first            # replaced, so old accounts won't match


def test_session_token_file_roundtrip_and_clear(tmp_path):
    assert read_session_token(tmp_path) == ""
    write_session_token(tmp_path, "A" * 43)
    assert read_session_token(tmp_path) == "A" * 43
    if os.name != "nt":
        assert (tmp_path / "device-session.token").stat().st_mode & 0o077 == 0
    clear_session_token(tmp_path)
    assert read_session_token(tmp_path) == ""
    (tmp_path / "device-session.token").write_text("not a valid token!!")
    assert read_session_token(tmp_path) == ""


# ----------------------------------------------------------------------------- account binding
def test_new_device_must_create_its_own_account_and_cannot_use_foreign_ones(tmp_path):
    db = tmp_path / "identity.sqlite3"
    laptop = UserRegistry(db, fp(tmp_path / "laptop"))
    assert laptop.needs_setup()
    laptop.create_initial_admin("budi", PW)
    assert not laptop.needs_setup() and laptop.authenticate("budi", PW)

    # The same identity file now appears on a different device (copied folder / restored backup).
    phone = UserRegistry(db, fp(tmp_path / "phone"))
    assert phone.needs_setup()                          # => the UI shows "create account"
    assert phone.has_foreign_accounts()
    assert phone.authenticate("budi", PW) is None       # a copied account does not log in here
    assert phone.list_users() == []
    phone.create_initial_admin("sari", "AnotherPass8")
    assert phone.authenticate("sari", "AnotherPass8")
    assert laptop.authenticate("sari", "AnotherPass8") is None     # and vice versa
    assert [u["username"] for u in laptop.list_users()] == ["budi"]
    with pytest.raises(AuthenticationError, match="sudah terdaftar"):
        phone.add_user("budi", PW, "operator")


def test_same_device_reopens_with_same_account(tmp_path):
    db = tmp_path / "identity.sqlite3"
    device = fp(tmp_path / "d")
    UserRegistry(db, device).create_initial_admin("budi", PW)
    again = UserRegistry(db, device)
    assert not again.needs_setup() and again.authenticate("budi", PW)
    assert not again.has_foreign_accounts()


def test_accounts_from_before_device_binding_are_adopted_by_first_device(tmp_path):
    db = tmp_path / "identity.sqlite3"
    legacy = UserRegistry(db)                           # no device binding: how every older install ran
    legacy.create_initial_admin("budi", PW)
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT device_fp FROM users").fetchone()[0] is None
    bound = UserRegistry(db, fp(tmp_path / "d"))
    assert not bound.needs_setup() and bound.authenticate("budi", PW)


def test_pin_is_scoped_to_the_device_too(tmp_path):
    db = tmp_path / "identity.sqlite3"
    laptop = UserRegistry(db, fp(tmp_path / "laptop"))
    laptop.create_initial_admin("budi", PW)
    laptop.set_device_pin("budi", "73910482")
    assert laptop.has_device_pin("budi") and laptop.authenticate_device_pin("budi", "73910482")
    phone = UserRegistry(db, fp(tmp_path / "phone"))
    assert not phone.has_device_pin("budi") and phone.authenticate_device_pin("budi", "73910482") is None
    assert phone.device_unlock_user() is None and phone.list_device_pin_users() == []


def test_invalid_fingerprint_is_rejected(tmp_path):
    with pytest.raises(AuthenticationError):
        UserRegistry(tmp_path / "i.sqlite3", "not-a-fingerprint")


# ----------------------------------------------------------------------------- remembered-device sessions
@pytest.fixture()
def reg(tmp_path):
    registry = UserRegistry(tmp_path / "identity.sqlite3", fp(tmp_path / "d"))
    registry.create_initial_admin("budi", PW)
    return registry


def test_remembered_session_resumes_and_rotates_the_token(reg):
    t0 = 1_000_000.0
    token = reg.create_trusted_session("budi", now=t0)
    user, fresh = reg.resume_trusted_session(token, now=t0 + 60)
    assert user == {"username": "budi", "role": "admin"} and fresh != token
    assert reg.resume_trusted_session(token, now=t0 + 61) is None      # the old token is dead after one use
    assert reg.resume_trusted_session(fresh, now=t0 + 120)[0]["username"] == "budi"


def test_session_stored_only_as_hash(reg):
    token = reg.create_trusted_session("budi")
    with sqlite3.connect(reg.db_path) as conn:
        stored = [r[0] for r in conn.execute("SELECT token_hash FROM trusted_sessions")]
    assert token not in stored and len(stored[0]) == 64


def test_session_expires_after_30_days_idle_and_90_days_absolute(reg):
    t0 = 1_000_000.0
    token = reg.create_trusted_session("budi", now=t0)
    assert reg.resume_trusted_session(token, now=t0 + (SESSION_DAYS + 1) * 86400) is None
    # Sliding window: used every 29 days it stays valid, but never past the 90-day absolute cap.
    token = reg.create_trusted_session("budi", now=t0)
    now = t0
    alive = True
    for _ in range(5):
        now += 29 * 86400
        result = reg.resume_trusted_session(token, now=now)
        if result is None:
            alive = False
            break
        token = result[1]
    assert not alive and now >= t0 + SESSION_MAX_DAYS * 86400 - 29 * 86400


def test_session_stolen_to_another_device_is_useless(tmp_path):
    db = tmp_path / "identity.sqlite3"
    laptop = UserRegistry(db, fp(tmp_path / "laptop"))
    laptop.create_initial_admin("budi", PW)
    token = laptop.create_trusted_session("budi")
    thief = UserRegistry(db, fp(tmp_path / "other"))
    assert thief.resume_trusted_session(token) is None
    assert laptop.resume_trusted_session(token) is None       # and a probe by a thief burned the token: re-login needed


def test_logout_and_credential_change_revoke_sessions(reg):
    token = reg.create_trusted_session("budi")
    assert reg.revoke_trusted_sessions("budi") == 1
    assert reg.resume_trusted_session(token) is None
    token = reg.create_trusted_session("budi")
    reg.change_admin_credentials("budi", PW, "budi2", "BrandNewPass1")
    assert reg.resume_trusted_session(token) is None


def test_deactivated_account_session_is_rejected(reg):
    token = reg.create_trusted_session("budi")
    with sqlite3.connect(reg.db_path) as conn:
        conn.execute("UPDATE users SET active=0")
    assert reg.resume_trusted_session(token) is None


def test_garbage_tokens_are_rejected(reg):
    for bad in ("", "x", "a" * 200, None, 123, "A" * 43):
        assert reg.resume_trusted_session(bad) is None


def test_sessions_need_a_bound_device(tmp_path):
    unbound = UserRegistry(tmp_path / "i.sqlite3")
    unbound.create_initial_admin("budi", PW)
    with pytest.raises(AuthenticationError):
        unbound.create_trusted_session("budi")
    assert unbound.resume_trusted_session("A" * 43) is None


# ----------------------------------------------------------------------------- step-up + lockout
def test_step_up_accepts_password_or_pin_and_rejects_others(reg):
    assert reg.verify_step_up("budi", PW)
    assert not reg.verify_step_up("budi", "wrong-password")
    assert not reg.verify_step_up("budi", "") and not reg.verify_step_up("", PW)
    reg.set_device_pin("budi", "73910482")
    assert reg.verify_step_up("budi", "73910482")
    assert not reg.verify_step_up("budi", "11223344")


def test_step_up_failures_count_toward_the_same_lockout(reg):
    for _ in range(5):
        assert not reg.verify_step_up("budi", "nope-nope-nope")
    assert not reg.verify_step_up("budi", PW)          # locked: even the right password waits


def test_lockout_doubles_on_repeat_and_is_capped(reg):
    now = 2_000_000.0
    waits = []
    key = "budi"
    for _ in range(9):
        for _ in range(5):
            reg._record_failure(key, now)
        with sqlite3.connect(reg.db_path) as conn:
            locked_until = conn.execute("SELECT locked_until FROM auth_attempts WHERE username_key=?", (key,)).fetchone()[0]
        waits.append(round(locked_until - now))
        now = locked_until + 1                         # wait it out, then fail again
    assert waits[:4] == [60, 120, 240, 480]
    assert max(waits) == AUTH_LOCKOUT_MAX_SECONDS == 3600 and waits[0] == AUTH_LOCKOUT_SECONDS


def test_quiet_day_forgets_earlier_lockouts(reg):
    now = 3_000_000.0
    for _ in range(5):
        reg._record_failure("budi", now)
    for _ in range(5):
        reg._record_failure("budi", now + 100_000)     # > 24h later
    with sqlite3.connect(reg.db_path) as conn:
        locked_until = conn.execute("SELECT locked_until FROM auth_attempts WHERE username_key='budi'").fetchone()[0]
    assert round(locked_until - (now + 100_000)) == 60


def test_successful_login_clears_strikes(reg):
    for _ in range(5):
        reg.authenticate("budi", "bad-bad-bad")
    with sqlite3.connect(reg.db_path) as conn:
        conn.execute("UPDATE auth_attempts SET locked_until=0")      # lockout elapsed
    assert reg.authenticate("budi", PW)
    with sqlite3.connect(reg.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM auth_attempts").fetchone()[0] == 0
