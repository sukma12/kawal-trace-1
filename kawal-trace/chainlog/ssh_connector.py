"""Explicitly authorized, read-only SSH log connector.

Only fixed, allow-listed journal queries are supported. Host keys must already be
trusted through a known_hosts file; unknown keys are rejected. The caller is
responsible for storing the private key in OS Secure Storage and passing it only in
memory to this connector.
"""
from __future__ import annotations

import hashlib
import io
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .detection import normalize_server_event

MAX_OUTPUT_BYTES = 1_048_576
MAX_EVENTS = 500
COMMAND_PROFILES = {
    "ssh_auth_recent": "journalctl --no-pager --output=short-iso -n 200 -u sshd.service -u ssh.service",
    "sudo_recent": "journalctl --no-pager --output=short-iso -n 200 SYSLOG_IDENTIFIER=sudo",
    "auth_log_recent": "tail -n 200 /var/log/auth.log",
}


class SSHConnectorError(ValueError):
    """SSH configuration, host verification, command, or output validation failed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validate_host(host: str) -> str:
    value = str(host or "").strip().rstrip(".")
    if not value or len(value) > 253 or any(ord(ch) < 33 or ord(ch) > 126 for ch in value):
        raise SSHConnectorError("Hostname SSH tidak valid.")
    if any(ch in value for ch in "/\\@?#;$`|&<>\r\n\t"):
        raise SSHConnectorError("Hostname SSH mengandung karakter yang ditolak.")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not re.fullmatch(r"(?i)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value):
            raise SSHConnectorError("Hostname SSH tidak valid.")
        if ".." in value:
            raise SSHConnectorError("Hostname SSH tidak valid.")
        return value.encode("idna").decode("ascii").lower()


def _private_key_object(paramiko: Any, private_key_pem: str) -> Any:
    value = str(private_key_pem or "")
    if not value or len(value) > 128_000 or "PRIVATE KEY-----" not in value:
        raise SSHConnectorError("Private key SSH harus dimuat dari Secure Storage OS dan tidak boleh kosong.")
    key_errors: list[str] = []
    for key_class_name in ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey"):
        key_class = getattr(paramiko, key_class_name, None)
        if key_class is None:
            continue
        try:
            return key_class.from_private_key(io.StringIO(value))
        except Exception as exc:
            key_errors.append(type(exc).__name__)
    raise SSHConnectorError("Private key SSH tidak didukung atau tidak valid (" + ", ".join(key_errors[:4]) + ").")


def _event_from_line(host: str, profile: str, line: str) -> dict[str, Any] | None:
    clean = " ".join(str(line or "").split())[:4000]
    if not clean:
        return None
    lower = clean.lower()
    if any(marker in lower for marker in ("failed password", "authentication failure", "invalid user", "failed publickey", "login failed")):
        event_type, source, reason = "AUTH_FAILURE", "sshd", "authentication_failed"
    elif any(marker in lower for marker in ("accepted password", "accepted publickey", "accepted keyboard-interactive", "login succeeded")):
        event_type, source, reason = "AUTH_SUCCESS", "sshd", "authentication_succeeded"
    elif "sudo" in lower and ("command=" in lower or "executed" in lower):
        event_type, source, reason = "PRIVILEGE_USE", "sudo", "privileged_command"
    else:
        return None

    timestamp = _utc_now()
    # journalctl --output=short-iso normally begins with a timezone-aware ISO token.
    stamp = re.match(r"^(\d{4}-\d{2}-\d{2}[T ][^\s]+)\s+", clean)
    if stamp:
        candidate = stamp.group(1).replace(" ", "T", 1)
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                timestamp = parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            pass

    actor = "unknown"
    patterns = (
        r"Failed password for (?:invalid user )?([^\s]+) from ",
        r"Accepted (?:password|publickey|keyboard-interactive) for ([^\s]+) from ",
        r"Invalid user ([^\s]+) from ",
        r"sudo:\s*([^\s:]+)\s*:",
    )
    for pattern in patterns:
        match = re.search(pattern, clean, re.IGNORECASE)
        if match:
            actor = match.group(1)[:128]
            break
    source_ip = ""
    for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{3,})(?![\w.])", clean):
        try:
            source_ip = str(ipaddress.ip_address(candidate.strip("[]")))
            break
        except ValueError:
            continue
    event_id = hashlib.sha256((host + "\x00" + profile + "\x00" + clean).encode("utf-8", errors="replace")).hexdigest()
    raw_event = {
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "event_type": event_type,
        "host_id": host[:128],
        "source": source,
        "actor": actor,
        "source_ip": source_ip,
        "details": {"message_excerpt": clean[:256], "reason": reason, "service": source},
    }
    try:
        return normalize_server_event(raw_event)
    except Exception as exc:
        raise SSHConnectorError("Baris log SSH tidak sesuai skema event yang diizinkan.") from exc


class SSHReadOnlyConnector:
    """Pull recent, selected security lines over SSH with strict host-key checks."""

    def __init__(self, *, host: str, username: str, private_key_pem: str, known_hosts_file: str | Path,
                 port: int = 22, command_profile: str = "ssh_auth_recent", timeout_seconds: int = 8,
                 _paramiko_module: Any = None):
        self.host = _validate_host(host)
        self.username = str(username or "").strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", self.username):
            raise SSHConnectorError("Username SSH tidak valid.")
        try:
            self.port = int(port)
            self.timeout_seconds = int(timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise SSHConnectorError("Port dan timeout SSH harus berupa bilangan bulat.") from exc
        if not 1 <= self.port <= 65535 or not 1 <= self.timeout_seconds <= 30:
            raise SSHConnectorError("Port harus 1–65535 dan timeout 1–30 detik.")
        if command_profile not in COMMAND_PROFILES:
            raise SSHConnectorError("Profil perintah SSH tidak diizinkan; perintah bebas tidak didukung.")
        self.command_profile = command_profile
        self.known_hosts_file = Path(known_hosts_file).expanduser().resolve()
        if not self.known_hosts_file.is_file() or self.known_hosts_file.stat().st_size > 1_000_000:
            raise SSHConnectorError("File known_hosts wajib ada dan berukuran maksimal 1 MiB.")
        self._private_key_pem = str(private_key_pem or "")
        self._paramiko_module = _paramiko_module

    def fetch_events(self, limit: int = 100) -> list[dict[str, Any]]:
        try:
            cap = max(1, min(int(limit), MAX_EVENTS))
        except (TypeError, ValueError) as exc:
            raise SSHConnectorError("Limit event SSH harus berupa bilangan bulat 1–500.") from exc
        if cap < 1:
            raise SSHConnectorError("Limit event SSH harus berupa bilangan bulat 1–500.")
        try:
            paramiko = self._paramiko_module
            if paramiko is None:
                import paramiko as paramiko_package
                paramiko = paramiko_package
            pkey = _private_key_object(paramiko, self._private_key_pem)
            client = paramiko.SSHClient()
            # Host keys are loaded from an administrator-trusted file. Unknown keys
            # must fail; never use AutoAddPolicy or disable key checking.
            client.load_host_keys(str(self.known_hosts_file))
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                hostname=self.host, port=self.port, username=self.username, pkey=pkey,
                timeout=self.timeout_seconds, banner_timeout=self.timeout_seconds,
                auth_timeout=self.timeout_seconds, allow_agent=False, look_for_keys=False,
                compress=False, sock=None,
            )
            try:
                _stdin, stdout, stderr = client.exec_command(
                    COMMAND_PROFILES[self.command_profile], timeout=self.timeout_seconds,
                    get_pty=False,
                )
                raw_output = stdout.read(MAX_OUTPUT_BYTES + 1)
                if isinstance(raw_output, str):
                    raw_output = raw_output.encode("utf-8", errors="replace")
                if len(raw_output) > MAX_OUTPUT_BYTES:
                    raise SSHConnectorError("Output log SSH melampaui batas 1 MiB; turunkan rentang log di sisi server.")
                err_output = stderr.read(8192)
                if isinstance(err_output, bytes) and len(err_output) > 0 and not raw_output:
                    # Do not expose raw stderr; it can contain environment details.
                    raise SSHConnectorError("Perintah baca SSH gagal; periksa izin akun read-only dan profil log.")
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    raise SSHConnectorError(f"Perintah baca SSH selesai dengan kode {exit_status}; periksa izin sumber log.")
            finally:
                client.close()
        except SSHConnectorError:
            raise
        except ImportError as exc:
            raise SSHConnectorError("Dependensi Paramiko belum terpasang; pasang optional extra [ssh].") from exc
        except Exception as exc:
            raise SSHConnectorError(f"Koneksi SSH gagal atau host key tidak dipercaya ({type(exc).__name__}); detail rahasia tidak ditampilkan.") from exc

        lines = raw_output.decode("utf-8", errors="replace").splitlines()[-cap:]
        events = []
        for line in lines:
            event = _event_from_line(self.host, self.command_profile, line)
            if event is not None:
                events.append(event)
        events.sort(key=lambda item: item["timestamp_epoch"], reverse=True)
        return events[:cap]

    def close(self) -> None:
        """No persistent SSH session is kept between fetch_events calls."""
        return None
