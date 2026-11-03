from pathlib import Path

import pytest

from chainlog.auth import AuthenticationError, UserRegistry


def test_first_admin_setup_and_authentication(tmp_path: Path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    assert registry.needs_setup() is True
    admin = registry.create_initial_admin("auditadm", "Ganti12!")
    assert admin == {"username": "auditadm", "role": "admin"}
    assert registry.needs_setup() is False
    assert registry.authenticate("auditadm", "Ganti12!") == admin
    assert registry.authenticate("auditadm", "salah-sekali") is None


def test_password_minimum_and_username_validation(tmp_path: Path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    with pytest.raises(AuthenticationError):
        registry.create_initial_admin("root", "short")
    with pytest.raises(AuthenticationError):
        registry.create_initial_admin("bad name", "Good12!")


def test_admin_can_create_operator_and_duplicate_is_rejected(tmp_path: Path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    registry.create_initial_admin("auditadm", "Ganti12!")
    operator = registry.add_user("operator.1", "Opera12!", "operator")
    assert operator == {"username": "operator.1", "role": "operator"}
    assert registry.authenticate("operator.1", "Opera12!") == operator
    with pytest.raises(AuthenticationError):
        registry.add_user("operator.1", "Opera12!", "operator")


def test_repeated_failed_logins_lock_account_through_app_restarts(tmp_path: Path):
    from chainlog.auth import MAX_FAILED_AUTH_ATTEMPTS

    db_path = tmp_path / "identity.sqlite3"
    registry = UserRegistry(db_path)
    registry.create_initial_admin("auditadm", "Ganti12!")
    for _ in range(MAX_FAILED_AUTH_ATTEMPTS):
        assert registry.authenticate("auditadm", "incorrect-password") is None

    # A fresh registry instance sees the persistent lockout and denies even correct credentials.
    reopened_registry = UserRegistry(db_path)
    assert reopened_registry.authenticate("auditadm", "Ganti12!") is None


def test_successful_login_clears_failed_attempt_counter(tmp_path: Path):
    import sqlite3
    from chainlog.auth import MAX_FAILED_AUTH_ATTEMPTS

    db_path = tmp_path / "identity.sqlite3"
    registry = UserRegistry(db_path)
    registry.create_initial_admin("auditadm", "Ganti12!")
    for _ in range(MAX_FAILED_AUTH_ATTEMPTS - 1):
        assert registry.authenticate("auditadm", "incorrect-password") is None
    assert registry.authenticate("auditadm", "Ganti12!") == {"username": "auditadm", "role": "admin"}
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM auth_attempts").fetchone()[0] == 0


def test_new_account_username_and_password_boundaries(tmp_path: Path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    # Lower and upper boundaries are inclusive for newly-created credentials (password 8-128 characters).
    account = registry.create_initial_admin("abcd", "Abc12345")
    assert account == {"username": "abcd", "role": "admin"}

    registry2 = UserRegistry(tmp_path / "second.sqlite3")
    long_passphrase = "Ab1" + "x" * 125                       # exactly 128 characters: a passphrase must be accepted
    assert len(long_passphrase) == 128
    account2 = registry2.create_initial_admin("abcdefghij", long_passphrase)
    assert registry2.authenticate("abcdefghij", long_passphrase) == account2
    assert account2 == {"username": "abcdefghij", "role": "admin"}

    for bad_username in ("abc", "abcdefghijk", "bad name"):
        with pytest.raises(AuthenticationError):
            UserRegistry(tmp_path / f"bad-{len(bad_username)}-{bad_username.replace(' ', '_')}.sqlite3").create_initial_admin(
                bad_username, "Abc12345"
            )

    for bad_password in ("Ab12345", "Ab1" + "x" * 126, "123456", "password", "aaaaaaaa"):   # 7 chars, 129 chars, common, repeated
        registry_bad = UserRegistry(tmp_path / f"pw-{len(bad_password)}-{bad_password.replace(' ', '_')}.sqlite3")
        with pytest.raises(AuthenticationError):
            registry_bad.create_initial_admin("gooduser", bad_password)


def test_existing_long_credentials_remain_usable_and_can_be_rotated(tmp_path: Path):
    import secrets
    from chainlog.auth import PBKDF2_ITERATIONS, _derive
    from chainlog.core import utc_now

    registry = UserRegistry(tmp_path / "identity.sqlite3")
    old_username = "legacy-admin-name"
    old_password = "ThisIsAnOldLegacyPassword!"
    salt = secrets.token_bytes(16)
    with registry._connect() as conn:
        conn.execute(
            "INSERT INTO users(username,salt,password_hash,iterations,role,active,created_at_utc) "
            "VALUES(?,?,?,?,?,1,?)",
            (old_username, salt, _derive(old_password, salt), PBKDF2_ITERATIONS, "admin", utc_now()),
        )
        # Mark this as a legacy install so credential rotation uses the old login.
        conn.execute(
            "INSERT INTO app_meta(meta_key,meta_value,updated_at_utc) VALUES(?,?,?)",
            ("default_admin_bootstrap_v1", "complete", utc_now()),
        )
    assert registry.authenticate(old_username, old_password) == {"username": old_username, "role": "admin"}
    changed = registry.rotate_legacy_credentials(old_username, old_password, "newadmin", "NewPass12!")
    assert changed == {"username": "newadmin", "role": "admin"}
    assert registry.authenticate("newadmin", "NewPass12!") == changed
    assert registry.authenticate(old_username, old_password) is None


def test_new_username_and_password_limits_are_enforced_by_auth_layer(tmp_path: Path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    with pytest.raises(AuthenticationError, match="4–10"):
        registry.create_initial_admin("abc", "Valid12!")
    with pytest.raises(AuthenticationError, match="4–10"):
        registry.create_initial_admin("username111", "Valid12!")
    with pytest.raises(AuthenticationError, match="minimal 8"):
        registry.create_initial_admin("validuser", "Ab12345")
    with pytest.raises(AuthenticationError, match="maksimal 128"):
        registry.create_initial_admin("validuser", "Ab1" + "x" * 126)
    # The old 12-character ceiling is gone: a normal passphrase is fine.
    assert registry.create_initial_admin("validuser", "correct horse battery staple")["username"] == "validuser"
