import json

from chainlog.e2ee import (
    export_private_key_backup,
    generate_keypair,
    import_private_key_backup,
)


def test_export_payload_is_valid_json_and_contains_encrypted_backup_only():
    keys = generate_keypair()
    passphrase = "a-secure-test-passphrase-2026"
    backup = export_private_key_backup(keys["private_key_b64"], passphrase)
    backup_json = json.dumps(backup, ensure_ascii=False, indent=2) + "\n"
    restored = json.loads(backup_json)
    assert restored["v"] == 1
    assert restored["alg"] == "Scrypt-SHA256+AES-256-GCM"
    assert keys["private_key_b64"] not in backup_json
    assert import_private_key_backup(restored, passphrase) == keys["private_key_b64"]


def test_export_payload_rejects_short_passphrase():
    keys = generate_keypair()
    try:
        export_private_key_backup(keys["private_key_b64"], "too-short")
    except Exception as exc:
        assert "14 characters" in str(exc)
    else:
        raise AssertionError("Short passphrase must be rejected")
