#!/usr/bin/env python3
"""Create the initial Kawal-Trace administrator key without touching member tokens.

By default this is one-time/idempotent: if KAWAL_ADMIN_TOKEN already exists, it is
not changed or printed. Use --rotate only when intentionally replacing the admin key.
"""
from __future__ import annotations
import os
import re
import secrets
import shutil
import sys
from datetime import datetime
from pathlib import Path

ENV_PATH = Path(os.environ.get("KAWAL_API_ENV_PATH", "/etc/kawal-trace/api.env"))
KEY = "KAWAL_ADMIN_TOKEN"

def main() -> int:
    rotate = "--rotate" in sys.argv[1:]
    if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("ERROR: jalankan sebagai root: sudo python3 setup_admin_token.py", file=sys.stderr)
        return 2
    if not ENV_PATH.is_file():
        print(f"ERROR: file {ENV_PATH} tidak ditemukan. Instal API dahulu; tidak ada file yang diubah.", file=sys.stderr)
        return 2
    original = ENV_PATH.read_text(encoding="utf-8")
    lines = original.splitlines()
    indices = [i for i, line in enumerate(lines)
               if line.strip() and not line.lstrip().startswith("#")
               and line.partition("=")[0].strip() == KEY]
    if len(indices) > 1:
        print(f"ERROR: {KEY} muncul lebih dari sekali; perbaiki duplikasi manual. Tidak ada perubahan.", file=sys.stderr)
        return 2
    existing = ""
    if indices:
        existing = lines[indices[0]].partition("=")[2].strip().strip('"').strip("'")
    if existing and not rotate:
        print(f"{KEY} sudah dikonfigurasi; tidak diubah dan tidak ditampilkan lagi.")
        print("Jika token hilang, rotasi hanya token administrator dengan --rotate; token anggota tidak disentuh.")
        return 0
    if rotate and not existing:
        print(f"{KEY} belum ada; membuat token awal tanpa memutar token anggota.")
    token = secrets.token_hex(32)
    backup = ENV_PATH.with_name(ENV_PATH.name + ".bak-admin-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    shutil.copy2(ENV_PATH, backup)
    backup.chmod(0o600)
    if indices:
        lines[indices[0]] = f"{KEY}={token}"
    else:
        lines.append(f"{KEY}={token}")
    temp = ENV_PATH.with_name(ENV_PATH.name + ".tmp")
    temp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temp.chmod(0o600)
    os.replace(temp, ENV_PATH)
    ENV_PATH.chmod(0o600)
    print(f"Cadangan dibuat: {backup}")
    print("TOKEN ADMINISTRATOR BARU (simpan di password manager; tampil sekali):")
    print(token)
    print("Token audit/pemantauan/ingest/respons dan database tidak diubah.")
    print("Setelah selesai mencatat token, jalankan: systemctl restart kawal-trace-api")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
