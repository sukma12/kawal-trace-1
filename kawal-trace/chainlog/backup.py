"""Encrypted local backup and verified restore (manual only; nothing is ever uploaded).

Format ``.ktbak``: MAGIC + JSON header + AES-256-GCM chunks. The key comes from a passphrase via
scrypt (same cost as the E2EE key backup). Every chunk is authenticated together with its index and a
"last chunk" flag, so truncation, reordering and tampering are all detected. The decrypted payload is
a ZIP of flat, allow-listed files plus a manifest with SHA-256 per file.

Restore is deliberately cautious: the archive is decrypted to a private temp directory, the manifest and
every SQLite file are verified, the audit hash chain is re-verified, a safety copy of the current data is
made, and files are swapped in atomically. Secrets kept in the OS Secure Storage (API tokens, the
website-database key) are NOT part of a backup and must be restored separately.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import struct
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:  # fail closed, never write an unencrypted backup
    raise RuntimeError("Backup memerlukan paket 'cryptography'; tidak ada fallback tanpa enkripsi.") from exc

from .at_rest import (KEY_MEMBER_NAME, AtRestError, cipher_from_raw_file, install_raw_key, key_files,
                      load_cipher)
from .core import AuditStore, ChainLogError

MAGIC = b"KTBAK1\n\x00"
FORMAT_VERSION = 1
CHUNK = 1024 * 1024
MIN_PASSPHRASE = 14
MAX_HEADER = 4096
MAX_FILES = 200
MAX_TOTAL_BYTES = 4 * 1024 ** 3
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
ALLOWED_SUFFIXES = (".sqlite3", ".json", ".bloom")
EXCLUDED_SUFFIXES = ("-wal", "-shm", ".tmp", ".restore-tmp")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
# Accounts belong to ONE device (see device_identity.py), so they never travel in a backup: restoring them onto a
# new device would replace the account the user just signed in with by accounts that are invisible there.
# Older backups that still contain this file are accepted; the file is skipped on restore and reported.
DEVICE_BOUND_FILES = frozenset({"identity.sqlite3"})
_SQLITE_MAGIC = b"SQLite format 3\x00"
MANIFEST_NAME = "manifest.json"


class BackupError(ChainLogError):
    """Backup/restore failed; the message is safe to show to the operator."""


@dataclass
class BackupInfo:
    path: Path
    files: list[str]
    plaintext_bytes: int
    created_utc: str


@dataclass
class VerifyReport:
    ok: bool
    files: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    audit_chain_valid: bool | None = None
    audit_records: int | None = None
    created_utc: str = ""


@dataclass
class RestoreReport:
    restored: list[str]
    safety_copy: Path | None
    verify: VerifyReport
    skipped: list[str] = field(default_factory=list)   # present in the backup but deliberately not restored


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(value: str, length: int | None = None) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise BackupError("Header backup rusak.") from exc
    if length is not None and len(raw) != length:
        raise BackupError("Header backup rusak.")
    return raw


def _check_passphrase(passphrase: str) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
        raise BackupError(f"Frasa sandi backup minimal {MIN_PASSPHRASE} karakter.")
    return passphrase.encode("utf-8")


def _derive(passphrase: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase)


def _chunk_aad(header_hash: bytes, index: int, last: bool) -> bytes:
    return header_hash + struct.pack(">QB", index, 1 if last else 0)


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + struct.pack(">Q", index)


# ---------------------------------------------------------------- selection of data
def is_backup_candidate(path: Path) -> bool:
    name = path.name
    return (path.is_file() and not path.is_symlink() and bool(_NAME_RE.match(name))
            and name.endswith(ALLOWED_SUFFIXES) and not name.endswith(EXCLUDED_SUFFIXES)
            and name not in DEVICE_BOUND_FILES)


def list_backup_files(data_dir: Path) -> list[Path]:
    return sorted(p for p in Path(data_dir).iterdir() if is_backup_candidate(p))


def _snapshot(src: Path, dst: Path) -> None:
    """Consistent copy: SQLite databases through the online backup API, other files verbatim."""
    with src.open("rb") as handle:
        is_sqlite = handle.read(16) == _SQLITE_MAGIC
    if not is_sqlite:
        shutil.copyfile(src, dst)
        return
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=10)
    try:
        target = sqlite3.connect(str(dst))
        try:
            source.backup(target)
        finally:
            target.close()
    finally:
        source.close()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------- create
def create_backup(data_dir: str | Path, dest: str | Path, passphrase: str) -> BackupInfo:
    secret = _check_passphrase(passphrase)
    data = Path(data_dir)
    destination = Path(dest)
    if not data.is_dir():
        raise BackupError("Folder data aplikasi tidak ditemukan.")
    sources = [p for p in list_backup_files(data) if p.resolve() != destination.resolve()]
    if not sources:
        raise BackupError("Tidak ada data lokal yang dapat dibackup.")
    if len(sources) > MAX_FILES:
        raise BackupError("Terlalu banyak file data untuk satu backup.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # The databases are encrypted at rest, so a backup is useless on another device without their key. The key goes
    # INSIDE the passphrase-encrypted archive only. An unreadable key aborts the backup: a backup that cannot be
    # restored is worse than none.
    data_key: bytes | None = None
    if key_files(data):
        try:
            data_key = load_cipher(data, create=False).raw_key
        except AtRestError as exc:
            raise BackupError(f"Backup dibatalkan: kunci enkripsi data tidak dapat dibaca ({exc}).") from exc
    created = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    with tempfile.TemporaryDirectory(prefix="kt-backup-", dir=str(destination.parent)) as scratch_name:
        scratch = Path(scratch_name)
        manifest: dict[str, Any] = {"format": FORMAT_VERSION, "created_utc": created, "files": {}}
        zip_path = scratch / "payload.zip"
        total = 0
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for source in sources:
                copy = scratch / f"snap-{len(manifest['files'])}"
                try:
                    _snapshot(source, copy)
                except (OSError, sqlite3.Error) as exc:
                    raise BackupError(f"Gagal menyalin {source.name} ({type(exc).__name__}).") from exc
                size = copy.stat().st_size
                total += size
                if total > MAX_TOTAL_BYTES:
                    raise BackupError("Ukuran data melebihi batas backup 4 GiB.")
                manifest["files"][source.name] = {"sha256": _sha256_file(copy), "size": size}
                archive.write(copy, arcname=source.name)
                copy.unlink()
            if data_key is not None:
                archive.writestr(KEY_MEMBER_NAME, data_key)
                manifest["files"][KEY_MEMBER_NAME] = {"sha256": hashlib.sha256(data_key).hexdigest(), "size": len(data_key)}
            archive.writestr(MANIFEST_NAME, json.dumps(manifest, sort_keys=True))
        salt, prefix = os.urandom(16), os.urandom(4)
        header = json.dumps({
            "v": FORMAT_VERSION, "alg": "scrypt+AES-256-GCM-chunked", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "salt": _b64(salt), "nonce_prefix": _b64(prefix), "chunk": CHUNK, "created_utc": created,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        header_hash = hashlib.sha256(header).digest()
        cipher = AESGCM(_derive(secret, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P))
        tmp_out = scratch / "out.ktbak"
        with zip_path.open("rb") as plain, tmp_out.open("wb") as out:
            out.write(MAGIC + struct.pack(">I", len(header)) + header)
            index = 0
            block = plain.read(CHUNK)
            while True:
                following = plain.read(CHUNK)
                last = not following
                encrypted = cipher.encrypt(_nonce(prefix, index), block, _chunk_aad(header_hash, index, last))
                out.write(struct.pack(">I", len(encrypted)) + encrypted)
                if last:
                    break
                block, index = following, index + 1
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp_out, destination)
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass
    return BackupInfo(destination, [p.name for p in sources], total, created)


# ---------------------------------------------------------------- decrypt
def _decrypt_to(src: Path, passphrase: str, out_path: Path) -> str:
    secret = _check_passphrase(passphrase)
    try:
        handle = src.open("rb")
    except OSError as exc:
        raise BackupError(f"File backup tidak dapat dibuka ({type(exc).__name__}).") from exc
    with handle:
        if handle.read(len(MAGIC)) != MAGIC:
            raise BackupError("Bukan file backup Kawal Trace (.ktbak) atau file rusak.")
        raw_len = handle.read(4)
        if len(raw_len) != 4:
            raise BackupError("File backup terpotong.")
        (header_len,) = struct.unpack(">I", raw_len)
        if not 2 <= header_len <= MAX_HEADER:
            raise BackupError("Header backup tidak valid.")
        header = handle.read(header_len)
        if len(header) != header_len:
            raise BackupError("File backup terpotong.")
        try:
            meta = json.loads(header)
            if meta["v"] != FORMAT_VERSION or meta["alg"] != "scrypt+AES-256-GCM-chunked":
                raise BackupError("Versi/format backup tidak didukung.")
            n, r, p = int(meta["n"]), int(meta["r"]), int(meta["p"])
            chunk = int(meta["chunk"])
            salt, prefix = _unb64(meta["salt"], 16), _unb64(meta["nonce_prefix"], 4)
        except (KeyError, TypeError, ValueError) as exc:
            raise BackupError("Header backup tidak valid.") from exc
        if not (2 ** 14 <= n <= 2 ** 20 and 1 <= r <= 16 and 1 <= p <= 4 and 4096 <= chunk <= 16 * CHUNK):
            raise BackupError("Parameter KDF backup di luar batas aman.")  # blocks hostile "make it use 100 GB" headers
        header_hash = hashlib.sha256(header).digest()
        cipher = AESGCM(_derive(secret, salt, n, r, p))
        index, total = 0, 0
        with out_path.open("wb") as out:
            while True:
                raw = handle.read(4)
                if len(raw) != 4:
                    raise BackupError("File backup terpotong (tidak ada penanda akhir).")
                (length,) = struct.unpack(">I", raw)
                if not 16 <= length <= chunk + 16:
                    raise BackupError("Blok backup tidak valid.")
                encrypted = handle.read(length)
                if len(encrypted) != length:
                    raise BackupError("File backup terpotong.")
                last = handle.read(1) == b""
                if not last:
                    handle.seek(-1, os.SEEK_CUR)
                try:
                    plain = cipher.decrypt(_nonce(prefix, index), encrypted, _chunk_aad(header_hash, index, last))
                except InvalidTag as exc:
                    raise BackupError("Frasa sandi salah atau file backup rusak/diubah.") from exc
                total += len(plain)
                if total > MAX_TOTAL_BYTES + 64 * 1024 * 1024:
                    raise BackupError("Isi backup terlalu besar.")
                out.write(plain)
                if last:
                    break
                index += 1
    return str(meta.get("created_utc", ""))


def _validated_members(archive: zipfile.ZipFile) -> dict[str, Any]:
    infos = archive.infolist()
    if len(infos) > MAX_FILES + 1:
        raise BackupError("Backup berisi terlalu banyak file.")
    try:
        manifest = json.loads(archive.read(MANIFEST_NAME))
        declared = dict(manifest["files"])
    except (KeyError, ValueError, TypeError) as exc:
        raise BackupError("Manifest backup hilang atau rusak.") from exc
    total = 0
    names = set()
    for info in infos:
        if info.filename == MANIFEST_NAME:
            continue
        name = info.filename
        is_key = name == KEY_MEMBER_NAME
        if (not _NAME_RE.match(name) or not (is_key or name.endswith(ALLOWED_SUFFIXES)) or name.endswith(EXCLUDED_SUFFIXES)
                or info.is_dir() or name in names or (is_key and info.file_size != 32)):
            raise BackupError(f"Nama file tidak diizinkan dalam backup: {name[:60]!r}")
        names.add(name)
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise BackupError("Isi backup melebihi batas ukuran (kemungkinan zip bomb).")
    if names != set(declared):
        raise BackupError("Daftar file backup tidak cocok dengan manifest.")
    return declared


def _extract(archive: zipfile.ZipFile, declared: dict[str, Any], dest: Path) -> None:
    for name, meta in declared.items():
        target = dest / name
        written = 0
        digest = hashlib.sha256()
        if name == KEY_MEMBER_NAME:
            target.touch(mode=0o600)
        with archive.open(name) as src, target.open("wb") as out:
            for block in iter(lambda: src.read(CHUNK), b""):
                written += len(block)
                if written > int(meta["size"]):
                    raise BackupError(f"Ukuran {name} melebihi manifest.")
                digest.update(block)
                out.write(block)
        if written != int(meta["size"]) or digest.hexdigest() != str(meta["sha256"]).lower():
            raise BackupError(f"Checksum {name} tidak cocok dengan manifest (backup rusak/diubah).")


def _verify_extracted(folder: Path, files: list[str]) -> VerifyReport:
    report = VerifyReport(ok=True, files=sorted(n for n in files if n != KEY_MEMBER_NAME))
    for name in files:
        if name == KEY_MEMBER_NAME:
            continue
        path = folder / name
        with path.open("rb") as handle:
            is_sqlite = handle.read(16) == _SQLITE_MAGIC
        if is_sqlite:
            try:
                conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
                try:
                    result = conn.execute("PRAGMA integrity_check").fetchone()[0]
                finally:
                    conn.close()
                if result != "ok":
                    report.problems.append(f"{name}: integrity_check SQLite gagal ({str(result)[:80]}).")
            except sqlite3.Error as exc:
                report.problems.append(f"{name}: database tidak dapat dibuka ({type(exc).__name__}).")
        elif name.endswith(".json"):
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                report.problems.append(f"{name}: JSON tidak valid.")
    chain = folder / "chainlog.sqlite3"
    if chain.exists():
        try:
            shipped_key = folder / KEY_MEMBER_NAME
            result = AuditStore(chain, cipher=cipher_from_raw_file(shipped_key) if shipped_key.exists() else None).verify()
            report.audit_chain_valid, report.audit_records = bool(result.valid), int(result.count)
            if not result.valid:
                report.problems.append(f"Rantai audit tidak valid pada backup: {result.reason[:120]}")
        except Exception as exc:  # noqa: BLE001 - report instead of crashing the verify screen
            report.audit_chain_valid = False
            report.problems.append(f"Rantai audit tidak dapat diverifikasi ({type(exc).__name__}).")
    report.ok = not report.problems
    return report


def _open_verified(src: Path, passphrase: str, scratch: Path) -> tuple[VerifyReport, dict[str, Any], Path]:
    payload = scratch / "payload.zip"
    created = _decrypt_to(src, passphrase, payload)
    try:
        with zipfile.ZipFile(payload) as archive:
            declared = _validated_members(archive)
            folder = scratch / "extracted"
            folder.mkdir()
            _extract(archive, declared, folder)
    except zipfile.BadZipFile as exc:
        raise BackupError("Isi backup bukan arsip yang valid.") from exc
    report = _verify_extracted(folder, list(declared))
    report.created_utc = created
    return report, declared, folder


def verify_backup(src: str | Path, passphrase: str) -> VerifyReport:
    """Real restore test without touching live data: decrypt, check manifest, SQLite and audit chain."""
    source = Path(src)
    with tempfile.TemporaryDirectory(prefix="kt-verify-") as scratch:
        report, _declared, _folder = _open_verified(source, passphrase, Path(scratch))
        return report


# ---------------------------------------------------------------- restore
def restore_backup(src: str | Path, passphrase: str, data_dir: str | Path, *, confirm: bool = False,
                   allow_invalid_chain: bool = False) -> RestoreReport:
    if confirm is not True:
        raise BackupError("Pemulihan menimpa data lokal; konfirmasi eksplisit diperlukan.")
    target = Path(data_dir)
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kt-restore-", dir=str(target)) as scratch_name:
        scratch = Path(scratch_name)
        report, declared, folder = _open_verified(Path(src), passphrase, scratch)
        if report.audit_chain_valid is False and not allow_invalid_chain:
            raise BackupError("Rantai audit di backup tidak valid; pemulihan dibatalkan. " + "; ".join(report.problems)[:300])
        other = [p for p in report.problems if not p.startswith("Rantai audit")]
        if other:
            raise BackupError("Backup gagal verifikasi: " + "; ".join(other)[:300])
        safety: Path | None = None
        existing = [p for p in list_backup_files(target) if p.name in declared]
        shipped_key = folder / KEY_MEMBER_NAME if KEY_MEMBER_NAME in declared else None
        old_keys = key_files(target) if shipped_key is not None else []
        if existing or old_keys:
            safety = target / ("restore-safety-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
            safety.mkdir(mode=0o700)
            for path in existing:
                _snapshot(path, safety / path.name)
            for old_key in old_keys:                    # the replaced key stays recoverable next to the replaced databases
                shutil.copyfile(old_key, safety / old_key.name)
                os.chmod(safety / old_key.name, 0o600)
        restored: list[str] = []
        skipped = sorted(n for n in declared if n in DEVICE_BOUND_FILES)
        for name in sorted(n for n in declared if n != KEY_MEMBER_NAME and n not in DEVICE_BOUND_FILES):
            staged = target / (name + ".restore-tmp")
            shutil.copyfile(folder / name, staged)
            for suffix in ("-wal", "-shm"):   # stale journal files must never be replayed onto the restored DB
                stale = target / (name + suffix)
                if stale.exists():
                    stale.unlink()
            os.replace(staged, target / name)
            restored.append(name)
        if shipped_key is not None:
            # Last, so a failure above leaves the old key beside the old databases. Re-protected for THIS device.
            install_raw_key(target, shipped_key.read_bytes())
    return RestoreReport(restored, safety, report, skipped)
