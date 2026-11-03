# Build 14 — Trusted Access & Response

## Ringkasan

Build 14 menambahkan lapisan **Trusted Access & Response** di atas Build 13.

### Alur Tambah Anggota (sesuai spesifikasi)

1. Administrator memasukkan **nama** dan **email** anggota.
2. `TrustedAccessStore.create_invitation(...)` membuat anggota PENDING + kode undangan aktivasi (berbatas waktu).
3. Anggota memasang aplikasi KAWAL TRACE di perangkatnya.
4. Anggota memverifikasi undangan dengan kode.
5. Aplikasi menghasilkan **keypair kriptografi Ed25519** untuk perangkat (`generate_device_keypair`).
6. Server / store lokal mendaftarkan identitas perangkat + public key sebagai **TRUSTED**.
7. Setiap koneksi berikutnya harus membuktikan kepemilikan kunci privat (challenge–response via `verify_device_key` / `sign_challenge`).

Bukan sekadar “email terdaftar = dipercaya”.

### Fitur yang tersedia di modul

| Fitur               | Fungsi                              |
| ------------------- | ----------------------------------- |
| Trusted Members     | Daftar anggota resmi                |
| Trusted Devices     | Daftar perangkat resmi              |
| Access Verification | Memverifikasi setiap koneksi        |
| Unauthorized Access | Daftar percobaan akses tanpa izin   |
| Force Disconnect    | (dirancang; eksekusi via response worker / agent) |
| IP Blocking         | (sudah ada di response_worker UFW)  |
| Revoke Access       | Mencabut akses anggota & perangkat  |
| Incident History    | Riwayat deteksi dan penindakan      |

### Modul baru

- `chainlog/trusted_access.py`
- `tests/test_trusted_access.py` (4 tes lulus)

### Integrasi dengan yang sudah ada

- `optional-server-api` member_accounts + enrollment/claim tetap dipakai untuk otoritas server.
- `response_worker.py` tetap menangani temporary UFW deny.
- Device fingerprint lokal (Build 13) tetap mengikat akun lokal ke instalasi.
- Build number native = 14, versi paket 1.0.2.

### Batas

- UI dashboard untuk form undangan & daftar insiden belum dipasang penuh di layar (modul siap dipanggil).
- Force-disconnect SSH sesi nyata memerlukan privileged worker di host dan allow-list admin; jangan aktifkan di produksi tanpa staging.
- Email undangan (SMTP) belum diimplementasikan; kode undangan diberikan manual/secure channel.


## Update implementasi UI + Force Disconnect

### Dashboard (main.py)
Panel **Keanggotaan server** sekarang berisi:
- Form undangan: Nama, Email, Peran → tombol **Buat Undangan Anggota**
- Kode undangan ditampilkan setelah dibuat (berikan lewat channel aman)
- **Muat Trusted Access** — daftar anggota lokal + perangkat
- **Cabut** per anggota (mencabut perangkat juga)
- **Muat Riwayat Insiden** + **Catat Insiden Uji**

### Force Disconnect & IP Blocking
- `TEMP_BLOCK_IP` — sudah ada (UFW temporary deny via response_worker)
- `FORCE_DISCONNECT_SSH` — antrian baru di API:
  - Butuh konfirmasi `DISCONNECT <ip>`
  - Menolak akun kosong / protected (`root`, `admin`, `ubuntu`, `kawal`, `administrator`)
  - Menolak IP yang ada di admin allowlist
- Worker: **fail-closed**. Tidak mengeksekusi kill SSH otomatis. Hanya menandai `ACKNOWLEDGED_NO_AUTO_KILL` kecuali policy host diperluas secara terpisah dengan `KAWAL_FORCE_DISCONNECT_ENABLED=true`.

### Pengujian yang sudah dijalankan
- `python -m py_compile main.py chainlog/trusted_access.py optional-server-api/server.py response_worker.py` → lulus
- `pytest tests/test_trusted_access.py tests/test_auth.py tests/test_core.py` → 19 passed
- Skrip end-to-end logic (undangan → keypair → verify → incident → revoke) → ALL GREEN

### Batas jujur
Live force-disconnect SSH pada host Ubuntu produksi **tidak** dijalankan dari sandbox ini (tidak ada server SSH root milik lingkungan audit). Kode antrian + proteksi + fail-closed worker sudah diuji secara sintaks dan logika.
