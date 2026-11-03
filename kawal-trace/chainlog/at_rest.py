"""Encryption at rest for the sensitive columns of the local databases.

What is protected: the free-form event details of the audit chain and the payload of the server-event archive
(IP addresses, account names, commands, file paths). They are stored as `kt1:` + base64(nonce || AES-256-GCM
ciphertext). The hash chain is computed over the PLAINTEXT, so tamper evidence is unchanged; the AES-GCM tag
additionally makes a row that was edited in the file fail to decrypt. Each value is bound to its row
(associated data = context string such as "audit|17"), so ciphertexts cannot be swapped between rows.

Where the key lives -- stated plainly, because it decides what this protects against:

* Windows: the 32-byte data key is wrapped with DPAPI (CryptProtectData, current-user scope) and stored in
  `data-key.dpapi`. Copying the data folder to another computer or Windows account yields files that cannot be
  opened there. Moving data to a new machine goes through Backup & Restore, which carries the key inside the
  passphrase-encrypted backup.
* Linux / macOS / Android: no OS key store is reachable synchronously from this layer, so the key is a
  random file `data-key.bin` (mode 0600) next to the databases. That protects against a database file leaking
  on its own (a stray copy, a partial backup, a sync folder that skipped the key) but NOT against someone
  who can read the whole app folder; there the app sandbox and OS disk encryption are what protect you.
* A key file that exists but cannot be opened, or has the wrong size, is an error. A new key is never
  generated in its place, because that would silently orphan every encrypted row.

Not encrypted here: the account database (it only holds salted PBKDF2 hashes), the scanner's signature
and history database, and exported reports (exports are plaintext by design: the user asked for a readable file).
"""
from __future__ import annotations

import base64
import os
import secrets
import sqlite3
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "kt1:"
KEY_FILE_RAW = "data-key.bin"
KEY_FILE_DPAPI = "data-key.dpapi"
KEY_MEMBER_NAME = "data-key.raw"          # name of the key inside a (passphrase-encrypted) backup
_DPAPI_MAGIC = b"KTDPAPI1"
_KEY_LEN = 32
_NONCE_LEN = 12


class AtRestError(Exception):
    """The data key is missing, unreadable, or does not match the data. The message is safe to show."""


class KeyMissingError(AtRestError):
    """No key file exists yet (as opposed to one that exists but cannot be used)."""


class KeyProtector(Protocol):
    name: str

    def protect(self, key: bytes) -> bytes: ...
    def unprotect(self, blob: bytes) -> bytes: ...


class DPAPIProtector:
    """Windows Data Protection API, current-user scope. Needs a real Windows session to run."""

    name = "dpapi"

    @staticmethod
    def _call(data: bytes, protect: bool) -> bytes:
        import ctypes
        from ctypes import wintypes

        class _Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32  # type: ignore[attr-defined]
        buffer = ctypes.create_string_buffer(data, len(data))
        blob_in = _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
        blob_out = _Blob()
        function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
        # dwFlags 0x1 = CRYPTPROTECT_UI_FORBIDDEN: never pop a prompt from a background thread.
        if not function(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)):
            raise AtRestError(f"Windows DPAPI menolak operasi (kode {ctypes.GetLastError()}).")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32.LocalFree(blob_out.pbData)

    def protect(self, key: bytes) -> bytes:
        return self._call(key, True)

    def unprotect(self, blob: bytes) -> bytes:
        return self._call(blob, False)


def default_protector() -> KeyProtector | None:
    return DPAPIProtector() if sys.platform == "win32" else None


# ------------------------------------------------------------------------------------------ the cipher
class DataCipher:
    def __init__(self, key: bytes, protection: str = "memory") -> None:
        if not isinstance(key, bytes) or len(key) != _KEY_LEN:
            raise AtRestError("Kunci enkripsi data harus 32 byte.")
        self._aead = AESGCM(key)
        self._key = key
        self.protection = protection

    @property
    def raw_key(self) -> bytes:
        """Only for building a backup (which is itself passphrase-encrypted)."""
        return self._key

    @staticmethod
    def is_encrypted(value: object) -> bool:
        return isinstance(value, str) and value.startswith(PREFIX)

    @staticmethod
    def _aad(context: str) -> bytes:
        return b"kawal-trace-at-rest-v1|" + context.encode("utf-8")

    def encrypt_text(self, plaintext: str, context: str) -> str:
        nonce = secrets.token_bytes(_NONCE_LEN)
        sealed = self._aead.encrypt(nonce, plaintext.encode("utf-8"), self._aad(context))
        return PREFIX + base64.urlsafe_b64encode(nonce + sealed).decode("ascii")

    def decrypt_text(self, value: str, context: str) -> str:
        if not self.is_encrypted(value):
            raise AtRestError("Nilai tidak terenkripsi.")
        try:
            raw = base64.urlsafe_b64decode(value[len(PREFIX):].encode("ascii"))
            if len(raw) < _NONCE_LEN + 16:
                raise ValueError("terlalu pendek")
            return self._aead.decrypt(raw[:_NONCE_LEN], raw[_NONCE_LEN:], self._aad(context)).decode("utf-8")
        except (InvalidTag, ValueError, UnicodeError) as exc:
            raise AtRestError("Data terenkripsi tidak dapat dibuka: kunci tidak cocok atau isi diubah.") from exc


# ------------------------------------------------------------------------------------------ key files
def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


def key_files(data_dir: str | os.PathLike[str]) -> list[Path]:
    base = Path(data_dir)
    return [p for p in (base / KEY_FILE_DPAPI, base / KEY_FILE_RAW) if p.exists()]


def _read_key(data_dir: Path, protector: KeyProtector | None) -> tuple[bytes, str] | None:
    dpapi_path, raw_path = data_dir / KEY_FILE_DPAPI, data_dir / KEY_FILE_RAW
    if dpapi_path.exists():
        blob = dpapi_path.read_bytes()
        if not blob.startswith(_DPAPI_MAGIC):
            raise AtRestError("Berkas kunci data (DPAPI) rusak.")
        if protector is None or protector.name != "dpapi":
            raise AtRestError("Kunci data dilindungi Windows DPAPI dan hanya dapat dibuka di Windows oleh akun yang membuatnya.")
        try:
            key = protector.unprotect(blob[len(_DPAPI_MAGIC):])
        except AtRestError as exc:
            raise AtRestError("Kunci enkripsi data tidak dapat dibuka oleh akun/komputer ini (data mungkin disalin dari "
                              "perangkat lain). Pulihkan lewat Backup & Restore dari perangkat asal. "
                              f"Detail: {exc}") from exc
        if len(key) != _KEY_LEN:
            raise AtRestError("Kunci data (DPAPI) memiliki ukuran yang salah.")
        return key, "dpapi"
    if raw_path.exists():
        key = raw_path.read_bytes()
        if len(key) != _KEY_LEN:
            raise AtRestError("Berkas kunci data rusak atau terpotong; kunci baru TIDAK dibuat agar data lama tidak yatim.")
        return key, "file"
    return None


def _store_key(data_dir: Path, key: bytes, protector: KeyProtector | None) -> str:
    if protector is not None and protector.name == "dpapi":
        _write_private(data_dir / KEY_FILE_DPAPI, _DPAPI_MAGIC + protector.protect(key))
        return "dpapi"
    _write_private(data_dir / KEY_FILE_RAW, key)
    return "file"


_CACHE: dict[str, tuple[tuple[int, int], DataCipher]] = {}
_CACHE_LOCK = threading.Lock()


def _signature(data_dir: Path) -> tuple[int, int]:
    """Cheap fingerprint of the key file, so a restore that swaps the key is noticed immediately."""
    for name in (KEY_FILE_DPAPI, KEY_FILE_RAW):
        try:
            info = (data_dir / name).stat()
            return info.st_mtime_ns, info.st_size
        except OSError:
            continue
    return (0, 0)


def load_cipher(data_dir: str | os.PathLike[str], *, create: bool = True, protector: KeyProtector | None | str = "auto") -> DataCipher:
    """Open (or, when `create` is true and nothing exists yet, create) the data key of `data_dir`."""
    base = Path(data_dir).expanduser().resolve()
    chosen = default_protector() if protector == "auto" else protector
    cache_key = f"{base}|{getattr(chosen, 'name', 'file')}"
    with _CACHE_LOCK:
        signature = _signature(base)
        cached = _CACHE.get(cache_key)
        if cached is not None and cached[0] == signature and signature != (0, 0):
            return cached[1]
        found = _read_key(base, chosen)
        if found is None:
            if not create:
                raise KeyMissingError("Kunci enkripsi data tidak ditemukan.")
            key = secrets.token_bytes(_KEY_LEN)
            protection = _store_key(base, key, chosen)
        else:
            key, protection = found
        cipher = DataCipher(key, protection)
        _CACHE[cache_key] = (_signature(base), cipher)
        return cipher


def resolve_cipher(data_dir: str | os.PathLike[str], has_encrypted_rows: Callable[[], bool]) -> DataCipher:
    """Open the key of `data_dir`; create one only when nothing already depends on a missing key."""
    try:
        return load_cipher(data_dir, create=False)
    except KeyMissingError:
        if has_encrypted_rows():
            raise AtRestError("Kunci enkripsi data hilang padahal database berisi data terenkripsi. Kunci baru TIDAK dibuat "
                              "agar data tidak yatim; pulihkan berkas kunci atau gunakan Backup & Restore.") from None
        return load_cipher(data_dir, create=True)


def scrub_plaintext_remnants(conn: sqlite3.Connection) -> None:
    """Remove the old plaintext that survives an in-place conversion to ciphertext.

    Rewriting a row as ciphertext does not erase the previous bytes: SQLite leaves them in the free space of the
    page (measured, not assumed: a freshly converted file still contained the IP address). VACUUM rewrites every
    page and a TRUNCATE checkpoint empties the write-ahead log. Must run outside a transaction. Raises
    sqlite3.Error when it cannot finish; the caller must report that, never swallow it.

    Limit: this cleans the database FILE. Copies the filesystem made earlier (old blocks on flash storage,
    snapshots, backups taken before conversion) are outside what an application can erase.
    """
    conn.execute("VACUUM")
    row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if row is not None and int(row[0]) != 0:
        raise sqlite3.OperationalError("checkpoint WAL tidak selesai (database sedang dipakai proses lain)")


def cipher_from_raw_file(path: str | os.PathLike[str]) -> DataCipher:
    key = Path(path).read_bytes()
    return DataCipher(key, "backup")


def install_raw_key(data_dir: str | os.PathLike[str], key: bytes, *, protector: KeyProtector | None | str = "auto") -> str:
    """Replace the data key of `data_dir` (used by restore). Returns the protection used."""
    base = Path(data_dir).expanduser().resolve()
    chosen = default_protector() if protector == "auto" else protector
    if len(key) != _KEY_LEN:
        raise AtRestError("Kunci dalam backup memiliki ukuran yang salah.")
    with _CACHE_LOCK:
        protection = _store_key(base, key, chosen)       # write the new key FIRST: a failure leaves the old one intact
        keep = KEY_FILE_DPAPI if protection == "dpapi" else KEY_FILE_RAW
        for stale in key_files(base):
            if stale.name != keep:
                stale.unlink()                           # a key stored the other way must not linger and shadow the new one
        _CACHE.clear()
    return protection


def describe(cipher: Any) -> str:
    if cipher is None:
        return "tidak terenkripsi"
    return {"dpapi": "terenkripsi · kunci dilindungi Windows DPAPI",
            "file": "terenkripsi · kunci di berkas lokal (lindungi dengan enkripsi disk/OS)"}.get(getattr(cipher, "protection", ""),
                                                                                                     "terenkripsi")
