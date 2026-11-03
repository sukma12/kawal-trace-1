"""End-to-end encrypted event envelopes for Kawal Trace.

Events are encrypted to a dashboard receiver's X25519 public key. The API only
stores/relays opaque envelopes; it does not hold the receiver private key. The
payload uses an ephemeral X25519 key, HKDF-SHA256 and AES-256-GCM. Clear envelope
metadata is deliberately limited to routing/deduplication fields and is AAD-bound.

This module requires `cryptography`. Do not silently fall back to plaintext if it
is unavailable or a key is invalid.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any, Mapping

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:  # fail closed; don't downgrade to plaintext
    raise RuntimeError("E2EE requires the 'cryptography' package; no plaintext fallback is allowed.") from exc

VERSION = 1
ALGORITHM = "X25519-HKDF-SHA256-AES-256-GCM"
INFO = b"Kawal-Trace-E2EE-v1"
KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 16
MAX_ENVELOPE_BYTES = 1_000_000


class E2EEError(ValueError):
    """Invalid key, envelope, or authentication tag."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(value: str, *, expected: int | None = None, max_len: int = MAX_ENVELOPE_BYTES) -> bytes:
    if not isinstance(value, str) or not value or len(value) > max_len * 2:
        raise E2EEError("Base64 field is invalid or too large")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise E2EEError("Base64 field could not be decoded") from exc
    if expected is not None and len(decoded) != expected:
        raise E2EEError("Base64 field has an invalid length")
    if len(decoded) > max_len:
        raise E2EEError("Decoded field is too large")
    return decoded


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise E2EEError("Payload must be JSON-serializable") from exc


def generate_keypair() -> dict[str, str]:
    """Generate a receiver keypair. Private key should be put in OS secure storage."""
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"private_key_b64": _b64e(private_raw), "public_key_b64": _b64e(public_raw)}


def public_from_private(private_key_b64: str) -> str:
    private_raw = _b64d(private_key_b64, expected=32, max_len=32)
    private = X25519PrivateKey.from_private_bytes(private_raw)
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _b64e(public_raw)


def validate_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(metadata, Mapping):
        raise E2EEError("metadata must be an object")
    result: dict[str, Any] = {}
    for key in ("event_id", "host_id", "timestamp_utc"):
        value = metadata.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 180:
            raise E2EEError(f"metadata.{key} is required")
        result[key] = value.strip()
    # Extra routing metadata is allowed, bounded and authenticated as AAD.
    for key in ("stream", "device_id", "seq", "record_hash", "previous_hash", "batch_id", "event_type", "source", "source_ip", "auth_method", "log_name"):
        if key in metadata:
            value = metadata[key]
            if isinstance(value, int) and not isinstance(value, bool):
                result[key] = value
            elif isinstance(value, str) and len(value) <= 180:
                result[key] = value
            else:
                raise E2EEError(f"metadata.{key} has an invalid type/length")
    return result


def _aad(metadata: Mapping[str, Any]) -> bytes:
    return canonical_json({"v": VERSION, "alg": ALGORITHM, "metadata": dict(metadata)})


def encrypt_payload(recipient_public_key_b64: str, payload: Mapping[str, Any], metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Encrypt JSON to a dashboard public key; API has no private key to decrypt."""
    clean_meta = validate_metadata(metadata)
    recipient_raw = _b64d(recipient_public_key_b64, expected=32, max_len=32)
    try:
        recipient = X25519PublicKey.from_public_bytes(recipient_raw)
    except ValueError as exc:
        raise E2EEError("Recipient public key is invalid") from exc
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = ephemeral.exchange(recipient)
    salt = os.urandom(SALT_LEN)
    key = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=INFO).derive(shared)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, canonical_json(dict(payload)), _aad(clean_meta))
    envelope = {
        "v": VERSION,
        "alg": ALGORITHM,
        "metadata": clean_meta,
        "ephemeral_public_key_b64": _b64e(ephemeral_public),
        "salt_b64": _b64e(salt),
        "nonce_b64": _b64e(nonce),
        "ciphertext_b64": _b64e(ciphertext),
    }
    validate_envelope(envelope)
    return envelope


def validate_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Validate envelope shape/size without decrypting the payload."""
    if not isinstance(envelope, Mapping) or envelope.get("v") != VERSION or envelope.get("alg") != ALGORITHM:
        raise E2EEError("Unsupported E2EE envelope version/algorithm")
    metadata = validate_metadata(envelope.get("metadata", {}))
    _b64d(str(envelope.get("ephemeral_public_key_b64", "")), expected=32, max_len=32)
    _b64d(str(envelope.get("salt_b64", "")), expected=SALT_LEN, max_len=SALT_LEN)
    _b64d(str(envelope.get("nonce_b64", "")), expected=NONCE_LEN, max_len=NONCE_LEN)
    ciphertext = _b64d(str(envelope.get("ciphertext_b64", "")), max_len=MAX_ENVELOPE_BYTES)
    if len(ciphertext) < 16:
        raise E2EEError("Ciphertext is too short")
    encoded_len = len(canonical_json(dict(envelope)))
    if encoded_len > MAX_ENVELOPE_BYTES:
        raise E2EEError("Envelope is too large")
    return {"v": VERSION, "alg": ALGORITHM, "metadata": metadata,
            "ephemeral_public_key_b64": str(envelope["ephemeral_public_key_b64"]),
            "salt_b64": str(envelope["salt_b64"]), "nonce_b64": str(envelope["nonce_b64"]),
            "ciphertext_b64": str(envelope["ciphertext_b64"])}


def decrypt_payload(receiver_private_key_b64: str, envelope: Mapping[str, Any]) -> dict[str, Any]:
    clean = validate_envelope(envelope)
    private_raw = _b64d(receiver_private_key_b64, expected=32, max_len=32)
    try:
        private = X25519PrivateKey.from_private_bytes(private_raw)
        ephemeral = X25519PublicKey.from_public_bytes(_b64d(clean["ephemeral_public_key_b64"], expected=32, max_len=32))
        shared = private.exchange(ephemeral)
    except ValueError as exc:
        raise E2EEError("Invalid X25519 key material") from exc
    salt = _b64d(clean["salt_b64"], expected=SALT_LEN, max_len=SALT_LEN)
    nonce = _b64d(clean["nonce_b64"], expected=NONCE_LEN, max_len=NONCE_LEN)
    key = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=INFO).derive(shared)
    try:
        raw = AESGCM(key).decrypt(nonce, _b64d(clean["ciphertext_b64"]), _aad(clean["metadata"]))
    except InvalidTag as exc:
        raise E2EEError("E2EE authentication failed; envelope or key was changed") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise E2EEError("Decrypted payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise E2EEError("Decrypted payload must be a JSON object")
    # Bind routing metadata to the encrypted contents, not just the AEAD tag.
    for key_name in ("event_id", "timestamp_utc", "event_type", "source", "source_ip", "auth_method", "log_name", "device_id", "seq", "record_hash", "previous_hash"):
        if payload.get(key_name) is not None and key_name in clean["metadata"] and str(payload[key_name]) != str(clean["metadata"][key_name]):
            raise E2EEError(f"Envelope metadata mismatch: {key_name}")
    if payload.get("host_id") is not None and str(payload["host_id"]) != clean["metadata"]["host_id"]:
        raise E2EEError("Envelope metadata mismatch: host_id")
    return payload


def export_private_key_backup(private_key_b64: str, passphrase: str) -> dict[str, str]:
    """Password-protect a key transfer backup. Never use a short/reused passphrase."""
    if not isinstance(passphrase, str) or len(passphrase) < 14:
        raise E2EEError("Backup passphrase must contain at least 14 characters")
    private_raw = _b64d(private_key_b64, expected=32, max_len=32)
    salt, nonce = os.urandom(16), os.urandom(NONCE_LEN)
    key = Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(nonce, private_raw, b"Kawal-Trace-private-key-backup-v1")
    return {"v": 1, "alg": "Scrypt-SHA256+AES-256-GCM", "salt_b64": _b64e(salt), "nonce_b64": _b64e(nonce), "ciphertext_b64": _b64e(ciphertext)}


def import_private_key_backup(backup: Mapping[str, Any], passphrase: str) -> str:
    if not isinstance(backup, Mapping) or backup.get("v") != 1 or backup.get("alg") != "Scrypt-SHA256+AES-256-GCM":
        raise E2EEError("Unsupported key backup format")
    salt = _b64d(str(backup.get("salt_b64", "")), expected=16, max_len=16)
    nonce = _b64d(str(backup.get("nonce_b64", "")), expected=NONCE_LEN, max_len=NONCE_LEN)
    ciphertext = _b64d(str(backup.get("ciphertext_b64", "")), max_len=1024)
    key = Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1).derive(str(passphrase).encode("utf-8"))
    try:
        private_raw = AESGCM(key).decrypt(nonce, ciphertext, b"Kawal-Trace-private-key-backup-v1")
    except InvalidTag as exc:
        raise E2EEError("Wrong passphrase or damaged private-key backup") from exc
    if len(private_raw) != 32:
        raise E2EEError("Private-key backup has an invalid key length")
    return _b64e(private_raw)
