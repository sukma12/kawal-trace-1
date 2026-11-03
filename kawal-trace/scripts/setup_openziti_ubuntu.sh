#!/usr/bin/env bash
# Install the official OpenZiti Edge Tunnel service on Ubuntu Server.
# Optional: pass a one-time enrollment JWT file and an identity name.
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Jalankan dengan sudo: sudo bash $0 [identity.jwt] [identity-name]" >&2
  exit 2
fi
if [[ ! -r /etc/os-release ]]; then
  echo "Tidak dapat mendeteksi distribusi Linux." >&2
  exit 3
fi
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "Script ini khusus Ubuntu; terdeteksi: ${PRETTY_NAME:-unknown}" >&2
  exit 4
fi
CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
if [[ -z "$CODENAME" || ! "$CODENAME" =~ ^[a-z0-9]+$ ]]; then
  echo "Codename Ubuntu tidak valid." >&2
  exit 5
fi
JWT_FILE="${1:-}"
IDENTITY_NAME="${2:-kawal-trace-server}"
if [[ -n "$JWT_FILE" ]]; then
  [[ -f "$JWT_FILE" && -r "$JWT_FILE" ]] || { echo "File JWT tidak ditemukan/tidak dapat dibaca." >&2; exit 6; }
  [[ "$IDENTITY_NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "Nama identity tidak valid." >&2; exit 7; }
  [[ -s "$JWT_FILE" && $(wc -c < "$JWT_FILE") -le 65536 ]] || { echo "Ukuran JWT tidak valid." >&2; exit 8; }
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg
install -d -m 0755 /usr/share/keyrings
curl --proto '=https' --tlsv1.2 -fsSL https://get.openziti.io/tun/package-repos.gpg \
  | gpg --dearmor --yes -o /usr/share/keyrings/openziti.gpg
chmod 0644 /usr/share/keyrings/openziti.gpg
printf 'deb [signed-by=/usr/share/keyrings/openziti.gpg] https://packages.openziti.org/zitipax-openziti-deb-stable %s main\n' "$CODENAME" \
  > /etc/apt/sources.list.d/openziti.list
apt-get update
apt-get install -y ziti-edge-tunnel

if [[ -n "$JWT_FILE" ]]; then
  install -d -o root -g ziti -m 0750 /opt/openziti/etc/identities
  install -o root -g ziti -m 0640 "$JWT_FILE" "/opt/openziti/etc/identities/${IDENTITY_NAME}.jwt"
fi
systemctl enable --now ziti-edge-tunnel.service
if [[ -n "$JWT_FILE" ]]; then
  systemctl restart ziti-edge-tunnel.service
fi
systemctl --no-pager --full status ziti-edge-tunnel.service || true
echo "OpenZiti Edge Tunnel service terpasang. Status Controller/policy dan akses layanan harus diverifikasi terpisah."
