import copy
import pytest

from chainlog.e2ee import (
    E2EEError, decrypt_payload, encrypt_payload, export_private_key_backup,
    generate_keypair, import_private_key_backup, public_from_private,
)


def test_aes256_gcm_e2ee_round_trip_and_api_cannot_decrypt():
    keys = generate_keypair()
    assert public_from_private(keys["private_key_b64"]) == keys["public_key_b64"]
    payload = {"event_id": "e" * 64, "timestamp_utc": "2026-10-21T00:00:00Z", "host_id": "win-test", "details": {"secret": "must not be visible"}}
    metadata = {"event_id": payload["event_id"], "timestamp_utc": payload["timestamp_utc"], "host_id": payload["host_id"]}
    envelope = encrypt_payload(keys["public_key_b64"], payload, metadata)
    assert "must not be visible" not in str(envelope)
    assert decrypt_payload(keys["private_key_b64"], envelope) == payload


def test_e2ee_rejects_modified_ciphertext_and_wrong_key():
    key_a = generate_keypair(); key_b = generate_keypair()
    payload = {"event_id": "a" * 64, "timestamp_utc": "now", "host_id": "h1"}
    env = encrypt_payload(key_a["public_key_b64"], payload, payload)
    altered = copy.deepcopy(env)
    altered["ciphertext_b64"] = altered["ciphertext_b64"][:-2] + "AA"
    with pytest.raises(E2EEError):
        decrypt_payload(key_a["private_key_b64"], altered)
    with pytest.raises(E2EEError):
        decrypt_payload(key_b["private_key_b64"], env)


def test_e2ee_private_key_backup_is_passphrase_protected():
    keys = generate_keypair()
    with pytest.raises(E2EEError):
        export_private_key_backup(keys["private_key_b64"], "short")
    backup = export_private_key_backup(keys["private_key_b64"], "long secure test passphrase")
    assert keys["private_key_b64"] not in str(backup)
    assert import_private_key_backup(backup, "long secure test passphrase") == keys["private_key_b64"]
    with pytest.raises(E2EEError):
        import_private_key_backup(backup, "wrong passphrase")
