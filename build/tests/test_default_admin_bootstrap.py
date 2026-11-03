from __future__ import annotations

import sqlite3
import secrets
from concurrent.futures import ThreadPoolExecutor
import pytest

from chainlog.auth import AuthenticationError, PBKDF2_ITERATIONS, UserRegistry, _derive
from chainlog.core import utc_now


def _mark_legacy_bootstrap(registry: UserRegistry) -> None:
    with registry._connect() as conn:
        conn.execute(
            "INSERT INTO app_meta(meta_key,meta_value,updated_at_utc) VALUES(?,?,?)",
            ("default_admin_bootstrap_v1", "complete", "2026-01-01T00:00:00Z"),
        )


def test_fresh_install_requires_explicit_account_creation(tmp_path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    assert registry.needs_setup() is True
    assert registry.needs_legacy_credential_rotation() is False
    account = registry.create_initial_admin("my-admin", "MyPass12!")
    assert account == {"username": "my-admin", "role": "admin"}
    assert registry.needs_setup() is False
    assert registry.needs_legacy_credential_rotation() is False
    assert registry.authenticate("my-admin", "MyPass12!") == account


def test_legacy_shared_bootstrap_is_rotated_only_after_old_password_is_verified(tmp_path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    old = registry.create_initial_admin("admin", "OldPass12!")
    registry.set_device_pin("admin", "58310497")
    _mark_legacy_bootstrap(registry)

    assert registry.needs_legacy_credential_rotation() is True
    with pytest.raises(AuthenticationError):
        registry.rotate_legacy_credentials(
            "admin", "wrong old password", "private1", "NewPass12!"
        )
    assert registry.needs_legacy_credential_rotation() is True
    assert registry.authenticate("admin", "OldPass12!") == old

    changed = registry.rotate_legacy_credentials(
        "admin", "OldPass12!", "private1", "NewPass12!"
    )
    assert changed == {"username": "private1", "role": "admin"}
    assert registry.authenticate("private1", "NewPass12!") == changed
    assert registry.authenticate("admin", "OldPass12!") is None
    assert registry.authenticate_device_pin("private1", "58310497") == changed
    assert registry.needs_legacy_credential_rotation() is False

    # Credential migration does not delete unrelated local accounts/data.
    with sqlite3.connect(tmp_path / "identity.sqlite3") as conn:
        user_names = {row[0] for row in conn.execute("SELECT username FROM users")}
    assert user_names == {"private1"}


def test_legacy_rotation_rejects_username_collision_without_destroying_accounts(tmp_path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    registry.create_initial_admin("old-admin", "OldAdm12!")
    registry.add_user("other-user", "Other12!", "operator")
    _mark_legacy_bootstrap(registry)

    with pytest.raises(AuthenticationError, match="sudah digunakan"):
        registry.rotate_legacy_credentials(
            "old-admin", "OldAdm12!", "other-user", "NewAdm12!"
        )
    assert registry.authenticate("old-admin", "OldAdm12!") is not None
    assert registry.authenticate("other-user", "Other12!") is not None
    assert registry.needs_legacy_credential_rotation() is True


def test_unmarked_existing_install_requires_verified_rotation_instead_of_skipping_setup(tmp_path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    registry.create_initial_admin("admin", "OldAcc12!")
    # Simulate a database created by an older release that had no setup-version marker.
    with registry._connect() as conn:
        conn.execute("DELETE FROM app_meta WHERE meta_key IN ('local_credentials_setup_v1','local_credentials_setup_v2')")
    assert registry.needs_setup() is False
    assert registry.needs_legacy_credential_rotation() is True
    with pytest.raises(AuthenticationError):
        registry.rotate_legacy_credentials(
            "admin", "incorrect password", "my-admin", "NewPass12!"
        )
    assert registry.authenticate("admin", "OldAcc12!") is not None
    changed = registry.rotate_legacy_credentials(
        "admin", "OldAcc12!", "my-admin", "NewPass12!"
    )
    assert changed == {"username": "my-admin", "role": "admin"}
    assert registry.needs_legacy_credential_rotation() is False


def test_only_one_concurrent_first_run_admin_can_be_created(tmp_path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")

    def attempt(username: str):
        try:
            return registry.create_initial_admin(username, "Pass1234!")["username"]
        except AuthenticationError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, ["firsta", "seconda"]))
    assert sorted(results) in (["firsta", "rejected"], ["rejected", "seconda"])
    with registry._connect() as conn:
        rows = conn.execute("SELECT username, role FROM users").fetchall()
    assert len(rows) == 1
    assert rows[0]["role"] == "admin"


def test_v1_personal_account_is_migrated_once_to_current_username_and_password_policy(tmp_path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    # Seed the old v1 account schema directly because the current create method
    # correctly refuses to create a new password longer than 12 characters.
    old_password = "OldPassword13$"
    salt = secrets.token_bytes(16)
    with registry._connect() as conn:
        conn.execute(
            "INSERT INTO users(username,salt,password_hash,iterations,role,active,created_at_utc) VALUES(?,?,?,?,?,1,?)",
            ("admin", salt, _derive(old_password, salt), PBKDF2_ITERATIONS, "admin", utc_now()),
        )
        conn.execute(
            "INSERT INTO app_meta(meta_key,meta_value,updated_at_utc) VALUES(?,?,?)",
            ("local_credentials_setup_v1", "complete", utc_now()),
        )
    assert registry.needs_setup() is False
    assert registry.needs_legacy_credential_rotation() is True
    with pytest.raises(AuthenticationError):
        registry.rotate_legacy_credentials(
            "admin", "wrong-old-password", "sukmaadmin", "NewPass7!"
        )
    assert registry.authenticate("admin", old_password) is not None
    updated = registry.rotate_legacy_credentials(
        "admin", old_password, "sukmaadmin", "NewPass7!"
    )
    assert updated == {"username": "sukmaadmin", "role": "admin"}
    assert registry.needs_legacy_credential_rotation() is False
    assert registry.authenticate("sukmaadmin", "NewPass7!") == updated


def test_new_policy_enforces_username_and_password_lengths_at_auth_layer(tmp_path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    with pytest.raises(AuthenticationError, match="4–10"):
        registry.create_initial_admin("abc", "GoodPass7!")
    assert registry.needs_setup() is True
    with pytest.raises(AuthenticationError, match="maksimal 128"):
        registry.create_initial_admin("gooduser", "Ab1" + "x" * 126)
    assert registry.needs_setup() is True
    account = registry.create_initial_admin("gooduser", "GoodPass7!")
    assert account == {"username": "gooduser", "role": "admin"}
    assert registry.needs_legacy_credential_rotation() is False
