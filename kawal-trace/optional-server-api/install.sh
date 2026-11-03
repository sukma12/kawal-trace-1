#!/usr/bin/env bash
set -euo pipefail
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/kawal-trace-api"
STATE_DIR="/var/lib/kawal-trace-api"
ENV_DIR="/etc/kawal-trace"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Jalankan: sudo bash install.sh" >&2
  exit 1
fi

if ! id kawal-trace-api >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/kawal-trace-api --create-home --shell /usr/sbin/nologin kawal-trace-api
fi
install -d -o root -g root -m 0755 "$INSTALL_DIR"
install -m 0644 "$SOURCE_DIR/server.py" "$INSTALL_DIR/server.py"
install -m 0750 "$SOURCE_DIR/response_worker.py" "$INSTALL_DIR/response_worker.py"
install -m 0644 "$SOURCE_DIR/setup_tokens.py" "$INSTALL_DIR/setup_tokens.py"
install -d -o root -g root -m 0750 "$ENV_DIR"
install -d -o kawal-trace-api -g kawal-trace-api -m 0750 "$STATE_DIR"
if [[ ! -f "$ENV_DIR/api.env" ]]; then
  install -o root -g root -m 0600 "$SOURCE_DIR/deploy/api.env.example" "$ENV_DIR/api.env"
  echo "Dibuat $ENV_DIR/api.env dengan token kosong. Jalankan setup_tokens.py sebelum mengaktifkan koneksi client."
fi
install -o root -g root -m 0644 "$SOURCE_DIR/deploy/kawal-trace-api.service" /etc/systemd/system/kawal-trace-api.service
install -o root -g root -m 0644 "$SOURCE_DIR/deploy/kawal-trace-response-worker.service" /etc/systemd/system/kawal-trace-response-worker.service
systemctl daemon-reload
systemctl enable kawal-trace-api.service
systemctl enable kawal-trace-response-worker.service
systemctl restart kawal-trace-api.service
systemctl restart kawal-trace-response-worker.service
sleep 1
systemctl --no-pager --full status kawal-trace-api.service || true
cat <<'EOF'

Langkah berikutnya:
  sudo /usr/bin/python3 /opt/kawal-trace-api/setup_tokens.py
  sudo systemctl restart kawal-trace-api
  sudo systemctl status kawal-trace-api --no-pager
  sudo systemctl status kawal-trace-response-worker --no-pager

API hanya bind ke 127.0.0.1:8765. Belum ada port publik yang dibuka.
Respons firewall default tetap NONAKTIF di api.env. Jangan aktifkan sebelum mengatur allowlist admin, memastikan UFW sudah aktif, menguji di staging, dan memahami risiko.
Jangan ubah /home/server/Anime_Projeck/server.js atau port 9999.
EOF
