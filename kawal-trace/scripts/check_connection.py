#!/usr/bin/env python3
"""Cek jalur dari perangkat ini ke server Kawal-Trace, langkah demi langkah (hanya membaca).

Pemakaian:
    set KAWAL_MONITOR_TOKEN=...            (Windows)   /   export KAWAL_MONITOR_TOKEN=...   (Linux/macOS)
    python scripts/check_connection.py --url https://monitor.contoh.id --device-id ID-PERANGKAT-ANDA

Token dibaca dari variabel lingkungan atau diminta tanpa tampil di layar; sengaja tidak ada opsi --token supaya
token tidak tersimpan di riwayat perintah. Skrip tidak mengirim event, tidak mengantre aksi respons, dan tidak
mengirim apa pun tentang perangkat ini selain Device ID.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chainlog.connection_check import exit_code, format_report, run_checks  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cek koneksi ke server Kawal-Trace (hanya membaca).")
    parser.add_argument("--url", required=True, help="Alamat HTTPS server, mis. https://monitor.contoh.id")
    parser.add_argument("--device-id", required=True, help="Device ID yang didaftarkan di server")
    parser.add_argument("--ca-bundle", default="", help="File CA khusus (opsional; jangan dipakai untuk melewati verifikasi)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Batas waktu tiap langkah, detik (1-30)")
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 30:
        parser.error("--timeout harus 1-30 detik")
    token = os.environ.get("KAWAL_MONITOR_TOKEN", "").strip()
    if not token and sys.stdin.isatty():
        token = getpass.getpass("Token monitor (tidak ditampilkan): ").strip()
    results = run_checks(args.url, args.device_id, token, ca_bundle=args.ca_bundle, timeout=args.timeout)
    print(format_report(results))
    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
