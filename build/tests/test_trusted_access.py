"""Tests for Build 14 Trusted Access & Response module."""
from __future__ import annotations

from pathlib import Path

import pytest

from chainlog.trusted_access import (
    TrustedAccessError,
    TrustedAccessStore,
    generate_device_keypair,
    sign_challenge,
)


def test_create_invitation_and_consume(tmp_path: Path):
    store = TrustedAccessStore(tmp_path / "trusted.sqlite3")
    member, inv = store.create_invitation(
        display_name="Budi Santoso",
        email="budi@example.com",
        role="operator",
        ttl_hours=48,
    )
    assert member.status == "PENDING"
    assert inv.status == "OPEN"
    assert inv.email == "budi@example.com"

    priv, pub = generate_device_keypair()
    device_id = "dev_" + "a" * 16
    activated_member, device = store.consume_invitation(
        inv.invite_code,
        device_id=device_id,
        platform="Android",
        public_key_pem=pub,
        label="HP Budi",
    )
    assert activated_member.status == "ACTIVE"
    assert device.status == "TRUSTED"
    assert device.device_id == device_id
    assert device.fingerprint

    # invite cannot be reused
    with pytest.raises(TrustedAccessError):
        store.consume_invitation(
            inv.invite_code,
            device_id="another",
            platform="Windows",
            public_key_pem=pub,
        )


def test_revoke_member_revokes_devices(tmp_path: Path):
    store = TrustedAccessStore(tmp_path / "trusted.sqlite3")
    member, inv = store.create_invitation("Ayu", "ayu@example.com")
    priv, pub = generate_device_keypair()
    store.consume_invitation(inv.invite_code, "dev_ayu1", "Windows", pub)
    revoked = store.revoke_member(member.member_id)
    assert revoked.status == "REVOKED"
    devices = store.list_devices(member.member_id)
    assert all(d.status == "REVOKED" for d in devices)


def test_device_key_verification(tmp_path: Path):
    store = TrustedAccessStore(tmp_path / "trusted.sqlite3")
    member, inv = store.create_invitation("Key User", "key@example.com")
    priv, pub = generate_device_keypair()
    device_id = "dev_keytest"
    store.consume_invitation(inv.invite_code, device_id, "Linux", pub)

    challenge = b"kawal-trace-challenge-v1|" + b"nonce123"
    signature = sign_challenge(priv, challenge)
    assert store.verify_device_key(device_id, challenge, signature) is True
    assert store.verify_device_key(device_id, challenge, b"bad-sig") is False
    assert store.verify_device_key("unknown", challenge, signature) is False


def test_incident_recording(tmp_path: Path):
    store = TrustedAccessStore(tmp_path / "trusted.sqlite3")
    rec = store.record_incident(
        source_ip="203.0.113.50",
        account="unknown",
        device_id="",
        session_id="ssh-sess-1",
        classification="INTRUDER",
        reason="SSH login without trusted device key",
        actions_taken=["force_disconnect", "ip_block"],
        outcome="session_terminated",
        evidence={"port": 22, "method": "password"},
    )
    assert rec.incident_id.startswith("inc_")
    listed = store.list_incidents()
    assert len(listed) == 1
    assert listed[0].classification == "INTRUDER"
    assert "force_disconnect" in listed[0].actions_taken

    summary = store.summarize()
    assert summary["incidents_total"] == 1
