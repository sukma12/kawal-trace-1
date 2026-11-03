from __future__ import annotations

import pytest

from chainlog.auth import AuthenticationError, UserRegistry


def test_device_pin_setup_and_login(tmp_path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    admin = registry.create_initial_admin("admlocal", "Device9!")
    registry.set_device_pin(admin["username"], "48295173")
    assert registry.has_device_pin("admlocal")
    assert registry.device_unlock_user()["username"] == "admlocal"
    assert registry.authenticate_device_pin("admlocal", "48295173")["role"] == "admin"
    assert registry.authenticate_device_pin("admlocal", "123456") is None
    # Extra digits must not be silently truncated into a valid configured PIN.
    assert registry.authenticate_device_pin("admlocal", "482951731") is None


def test_pin_rules_and_disable(tmp_path):
    registry = UserRegistry(tmp_path / "identity.sqlite3")
    registry.create_initial_admin("admlocal", "Device9!")
    for bad in ("12345678", "00000000", "23456789", "87654321", "abc12345", "1234567", "1234567890123"):
        with pytest.raises(AuthenticationError):
            registry.set_device_pin("admlocal", bad)
    registry.set_device_pin("admlocal", "48295173")
    registry.remove_device_pin("admlocal")
    assert not registry.has_device_pin("admlocal")
    assert registry.device_unlock_user() is None


def test_pin_lockout_survives_registry_reopen(tmp_path):
    path = tmp_path / "identity.sqlite3"
    registry = UserRegistry(path)
    registry.create_initial_admin("admlocal", "Device9!")
    registry.set_device_pin("admlocal", "48295173")
    for _ in range(5):
        assert registry.authenticate_device_pin("admlocal", "99999999") is None
    registry = UserRegistry(path)
    # Correct PIN is temporarily blocked after repeated attempts.
    assert registry.authenticate_device_pin("admlocal", "48295173") is None
