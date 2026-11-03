#!/usr/bin/env python3
"""Legacy manual token setup. Refuses to rotate existing IDs unless explicitly asked."""
from __future__ import annotations
import base64
import os
import re
import secrets
import shutil
import sys
from datetime import datetime
from pathlib import Path

ENV_PATH = Path(os.environ.get("KAWAL_API_ENV_PATH", "/etc/kawal-trace/api.env"))
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")

def ask(prompt: str, pattern: re.Pattern[str]) -> str:
    while True:
        value = input(prompt).strip()
        if pattern.fullmatch(value) and "|" not in value and ";" not in value:
            return value
        print("ID tidak valid. Gunakan huruf/angka dan . _ : -; tanpa spasi, |, atau ;.")

def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _upsert_token_map(raw: str, identity: str, token: str) -> str:
    entries: dict[str, str] = {}
    for item in raw.split(";"):
        if "|" in item:
            key, value = item.split("|", 1)
            if key.strip() and value.strip():
                entries[key.strip()] = value.strip()
    entries[identity] = token
    return ";".join(f"{key}|{value}" for key, value in entries.items())


def main() -> None:
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("Jalankan dengan sudo agar file env terlindungi, misalnya sudo python3 /opt/kawal-trace-api/setup_tokens.py")
    rotate_existing = "--rotate-existing" in sys.argv[1:]
    print("Kawal-Trace API — penerbit token perangkat/host. Token baru ditampilkan sekali.\n")
    print("Untuk anggota biasa, gunakan pendaftaran otomatis via aplikasi; skrip ini untuk pemasangan manual/legacy.\n")
    device_id = ask("Masukkan Device ID dari profile aplikasi Kawal-Trace: ", ID_RE)
    host_id = ask("Masukkan Host ID untuk agen Linux (contoh ubuntu-main): ", HOST_RE)
    windows_host_id = input("Masukkan Host ID untuk agen Windows (atau tekan Enter untuk melewati): ").strip()
    if windows_host_id and (not HOST_RE.fullmatch(windows_host_id) or "|" in windows_host_id or ";" in windows_host_id):
        raise SystemExit("Windows Host ID tidak valid.")
    ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    values = _read_env(ENV_PATH)
    existing_device_ids = set()
    for key in ("KAWAL_AUDIT_TOKENS", "KAWAL_MONITOR_TOKENS", "KAWAL_RESPONSE_TOKENS", "KAWAL_RESPONSE_TOTP_SECRETS"):
        for item in values.get(key, "").split(";"):
            if "|" in item:
                existing_device_ids.add(item.split("|", 1)[0].strip())
    existing_host_ids = set()
    for key in ("KAWAL_INGEST_TOKENS", "KAWAL_WINDOWS_HOST_TOKENS"):
        for item in values.get(key, "").split(";"):
            if "|" in item:
                existing_host_ids.add(item.split("|", 1)[0].strip())
    conflicts = []
    if device_id in existing_device_ids:
        conflicts.append(f"Device ID {device_id}")
    if host_id in existing_host_ids:
        conflicts.append(f"Host ID {host_id}")
    if windows_host_id and windows_host_id in existing_host_ids:
        conflicts.append(f"Windows Host ID {windows_host_id}")
    if conflicts and not rotate_existing:
        raise SystemExit(
            "STOP: " + ", ".join(conflicts) + " sudah memiliki token. Tidak ada konfigurasi yang diubah. "
            "Tambahkan anggota melalui endpoint membership/aplikasi. Jika benar-benar ingin merotasi token legacy, "
            "jalankan skrip dengan --rotate-existing dan perbarui semua client terkait."
        )
    audit = secrets.token_hex(32)
    monitor = secrets.token_hex(32)
    ingest = secrets.token_hex(32)
    response = secrets.token_hex(32)
    totp_secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    windows_ingest = secrets.token_hex(32) if windows_host_id else ""
    if ENV_PATH.exists():
        backup = ENV_PATH.with_name(ENV_PATH.name + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(ENV_PATH, backup)
        backup.chmod(0o600)
        print(f"Backup konfigurasi lama: {backup}")
    values["KAWAL_AUDIT_TOKENS"] = _upsert_token_map(values.get("KAWAL_AUDIT_TOKENS", ""), device_id, audit)
    values["KAWAL_MONITOR_TOKENS"] = _upsert_token_map(values.get("KAWAL_MONITOR_TOKENS", ""), device_id, monitor)
    values["KAWAL_INGEST_TOKENS"] = _upsert_token_map(values.get("KAWAL_INGEST_TOKENS", ""), host_id, ingest)
    values["KAWAL_RESPONSE_TOKENS"] = _upsert_token_map(values.get("KAWAL_RESPONSE_TOKENS", ""), device_id, response)
    values["KAWAL_RESPONSE_TOTP_SECRETS"] = _upsert_token_map(values.get("KAWAL_RESPONSE_TOTP_SECRETS", ""), device_id, totp_secret)
    if windows_host_id:
        # The enrolled Windows host uses the same host-scoped token for encrypted
        # telemetry ingestion and for fetching/reporting approved response actions.
        # Each API mapping remains separate, so the token has no dashboard/admin rights.
        values["KAWAL_INGEST_TOKENS"] = _upsert_token_map(values.get("KAWAL_INGEST_TOKENS", ""), windows_host_id, windows_ingest)
        values["KAWAL_WINDOWS_HOST_TOKENS"] = _upsert_token_map(values.get("KAWAL_WINDOWS_HOST_TOKENS", ""), windows_host_id, windows_ingest)
    values.setdefault("KAWAL_RESPONSE_ACTIONS_ENABLED", "false")
    values.setdefault("KAWAL_WINDOWS_RESPONSE_ENABLED", "false")
    values.setdefault("KAWAL_RESPONSE_ALLOWLIST", "")
    values.setdefault("KAWAL_API_HOST", "127.0.0.1")
    values.setdefault("KAWAL_API_PORT", "8765")
    values.setdefault("KAWAL_API_DB_PATH", "/var/lib/kawal-trace-api/events.sqlite3")
    # Known keys first in stable order; preserve additional administrator settings afterward.
    known = ["KAWAL_AUDIT_TOKENS", "KAWAL_MONITOR_TOKENS", "KAWAL_INGEST_TOKENS", "KAWAL_RESPONSE_TOKENS",
             "KAWAL_RESPONSE_TOTP_SECRETS", "KAWAL_WINDOWS_HOST_TOKENS", "KAWAL_RESPONSE_ACTIONS_ENABLED", "KAWAL_WINDOWS_RESPONSE_ENABLED",
             "KAWAL_RESPONSE_ALLOWLIST", "KAWAL_API_HOST", "KAWAL_API_PORT", "KAWAL_API_DB_PATH"]
    lines = ["# Secrets generated by setup_tokens.py; root-only; do not share."]
    for key in known:
        lines.append(f"{key}={values.pop(key, '')}")
    for key, value in values.items():
        lines.append(f"{key}={value}")
    lines.append("")
    ENV_PATH.write_text("\n".join(lines), encoding="utf-8")
    ENV_PATH.chmod(0o600)
    print("\nTOKEN BARU DITAMPILKAN SEKALI — simpan dengan aman, jangan tempel ke chat/screenshot:\n")
    print(f"Aplikasi — token upload/audit untuk Device ID {device_id}:\n{audit}\n")
    print(f"Aplikasi — token read-only feed untuk Device ID {device_id}:\n{monitor}\n")
    print(f"Agen Linux — token ingest untuk Host ID {host_id}:\n{ingest}\n")
    print(f"Aplikasi — token respons terbatas untuk Device ID {device_id}:\n{response}\n")
    print(f"TOTP seed untuk authenticator (Device ID {device_id}; simpan sekali, jangan kirim lewat chat):\n{totp_secret}\n")
    if windows_host_id:
        print(f"Agen Windows — Host ID {windows_host_id}:\n{windows_ingest}\n")
    print("Token untuk ID lain dan KAWAL_ADMIN_TOKEN tetap dipertahankan. ID yang sudah ada hanya dapat dirotasi dengan --rotate-existing.")
    print("Respons firewall tetap NONAKTIF kecuali admin sebelumnya sudah mengaktifkannya. Windows response juga NONAKTIF secara default; tinjau allowlist, protected users, bukti event lokal dan prosedur rollback terlebih dahulu.")
    print(f"File env tersimpan sebagai {ENV_PATH} dengan izin 600.")
    print("Sesudah mencatat token, restart service: sudo systemctl restart kawal-trace-api")

if __name__ == "__main__":
    main()
