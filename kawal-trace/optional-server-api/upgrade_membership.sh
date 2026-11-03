#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Jalankan: sudo bash upgrade_membership.sh" >&2
  exit 2
fi
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="/opt/kawal-trace-api"
SERVICE="kawal-trace-api"

if [[ ! -f "$DEST/server.py" ]]; then
  echo "ERROR: $DEST/server.py tidak ditemukan. Skrip ini hanya untuk upgrade API yang sudah terpasang." >&2
  exit 2
fi
if [[ ! -f /etc/kawal-trace/api.env ]]; then
  echo "ERROR: /etc/kawal-trace/api.env tidak ditemukan. Tidak ada perubahan dilakukan." >&2
  exit 2
fi
if ! systemctl cat "$SERVICE" >/dev/null 2>&1; then
  echo "ERROR: unit $SERVICE tidak ditemukan. Tidak ada perubahan dilakukan." >&2
  exit 2
fi
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="$DEST/backups/membership-$STAMP"
install -d -o root -g root -m 0700 "$BACKUP_DIR"
cp -a "$DEST/server.py" "$BACKUP_DIR/server.py"
if [[ -f "$DEST/setup_admin_token.py" ]]; then cp -a "$DEST/setup_admin_token.py" "$BACKUP_DIR/setup_admin_token.py"; fi
if [[ -f "$DEST/setup_tokens.py" ]]; then cp -a "$DEST/setup_tokens.py" "$BACKUP_DIR/setup_tokens.py"; fi

install -o root -g root -m 0644 "$SRC_DIR/server.py" "$DEST/server.py.new.py"
install -o root -g root -m 0750 "$SRC_DIR/setup_admin_token.py" "$DEST/setup_admin_token.py.new.py"
install -o root -g root -m 0750 "$SRC_DIR/setup_tokens.py" "$DEST/setup_tokens.py.new.py"
python3 -m py_compile "$DEST/server.py.new.py" "$DEST/setup_admin_token.py.new.py" "$DEST/setup_tokens.py.new.py"
mv -f "$DEST/server.py.new.py" "$DEST/server.py"
mv -f "$DEST/setup_admin_token.py.new.py" "$DEST/setup_admin_token.py"
mv -f "$DEST/setup_tokens.py.new.py" "$DEST/setup_tokens.py"

if systemctl restart "$SERVICE" && systemctl is-active --quiet "$SERVICE"; then
  echo "OK: API diperbarui. Database dan api.env tidak ditimpa."
  echo "Backup API lama: $BACKUP_DIR"
  echo "Berikutnya, buat token admin satu kali dengan: python3 $DEST/setup_admin_token.py"
  echo "Jangan jalankan setup_tokens.py untuk mengelola anggota."
else
  echo "ERROR: service gagal aktif. Memulihkan server.py lama dari backup..." >&2
  cp -a "$BACKUP_DIR/server.py" "$DEST/server.py"
  if [[ -f "$BACKUP_DIR/setup_admin_token.py" ]]; then cp -a "$BACKUP_DIR/setup_admin_token.py" "$DEST/setup_admin_token.py"; fi
  if [[ -f "$BACKUP_DIR/setup_tokens.py" ]]; then cp -a "$BACKUP_DIR/setup_tokens.py" "$DEST/setup_tokens.py"; fi
  systemctl restart "$SERVICE" || true
  echo "Versi server.py lama dipulihkan. Periksa: journalctl -u $SERVICE -n 80 --no-pager" >&2
  exit 1
fi
