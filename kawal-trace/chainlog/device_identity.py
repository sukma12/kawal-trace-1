"""Per-device identity used to bind local accounts and "remembered device" sessions to ONE device.

The fingerprint is HMAC-SHA256(install_secret, machine_id):

* install_secret: 32 random bytes created on first run and kept in the app's private data
  directory (mode 0600 where the OS supports it);
* machine_id: an OS-provided identifier when one can be read (Windows MachineGuid, Linux
  /etc/machine-id); empty when the platform exposes none (typical for Android sandboxes).

Consequences, stated honestly:

* The raw machine id never leaves this module and is never stored; only the keyed hash is used.
* Copying the whole data folder to another computer changes machine_id, so the fingerprint no
  longer matches and the copied accounts/sessions stop working there (a new account is required).
* On platforms without a machine id (Android) the binding rests on the install secret alone: it
  survives app restarts, but is lost if the app data is cleared or the app is reinstalled.
* This is not hardware attestation. Someone who already controls the unlocked device and its app
  data can act as that device; OS account protection and disk encryption remain necessary.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sys
from pathlib import Path

SECRET_FILE = "device-secret.bin"
SESSION_FILE = "device-session.token"
_SECRET_LEN = 32
_DOMAIN = b"kawal-trace-device-v1|"


def read_machine_id() -> str:
    """Best-effort OS machine identifier; empty string when unavailable."""
    try:
        if sys.platform == "win32":
            import winreg  # type: ignore[import-not-found]

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                                0, winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)) as key:
                return str(winreg.QueryValueEx(key, "MachineGuid")[0]).strip()
        for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            path = Path(candidate)
            if path.is_file():
                value = path.read_text(encoding="ascii", errors="ignore").strip()
                if value:
                    return value
    except (OSError, ImportError, ValueError):
        pass
    return ""


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
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


def install_secret(data_dir: str | os.PathLike[str]) -> bytes:
    path = Path(data_dir) / SECRET_FILE
    try:
        secret = path.read_bytes()
        if len(secret) == _SECRET_LEN:
            return secret
    except FileNotFoundError:
        pass
    # A wrong-sized file is treated as corrupt: replace it. That changes the fingerprint, so the
    # accounts bound to the old value will require a new account on this device (never silently reused).
    secret = secrets.token_bytes(_SECRET_LEN)
    _write_private(path, secret)
    return secret


def device_fingerprint(data_dir: str | os.PathLike[str], *, machine_id: str | None = None) -> str:
    mid = read_machine_id() if machine_id is None else machine_id
    return hmac.new(install_secret(data_dir), _DOMAIN + mid.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- remembered-device session token (client side)
def read_session_token(data_dir: str | os.PathLike[str]) -> str:
    try:
        value = (Path(data_dir) / SESSION_FILE).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return value if 32 <= len(value) <= 128 and value.replace("-", "").replace("_", "").isalnum() else ""


def write_session_token(data_dir: str | os.PathLike[str], token: str) -> None:
    _write_private(Path(data_dir) / SESSION_FILE, token.encode("ascii"))


def clear_session_token(data_dir: str | os.PathLike[str]) -> None:
    try:
        (Path(data_dir) / SESSION_FILE).unlink()
    except FileNotFoundError:
        pass
    except OSError:
        # Could not delete: overwrite so the stale token is useless even if the file stays.
        try:
            _write_private(Path(data_dir) / SESSION_FILE, b"revoked")
        except OSError:
            pass
