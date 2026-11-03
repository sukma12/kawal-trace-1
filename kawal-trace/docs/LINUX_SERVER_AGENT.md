# Memasang agen telemetri Linux untuk Kawal-Trace

Agen ini membaca event baru dari systemd journal untuk SSH/sudo dan (opsional) event auditd yang cocok dengan rule jalur sensitif. Agen tidak melakukan eksploitasi, tidak menjalankan perintah dari log, dan tidak memblokir akses. Ia menyimpan antrean lokal SQLite sampai API mengonfirmasi ID event yang diterima.

## Prasyarat

- Linux dengan systemd/journalctl dan Python 3.10+.
- `auditd` hanya diperlukan jika ingin mendeteksi perubahan file sensitif.
- API server sudah menyediakan kontrak `POST /api/v1/security-events:batch` pada `docs/SERVER_TELEMETRY_CONTRACT.md`.
- Token ingest write-only khusus host. Dashboard juga membutuhkan token read-only terpisah.
- Uji pertama di staging/lab, jangan langsung pada server produksi atau sistem rahasia.

## Instalasi contoh pada Debian/Ubuntu

1. Salin folder `server_agent/` dan file module `chainlog/detection.py` tidak diperlukan untuk agent; agen memakai pustaka standar Python saja. Tempatkan proyek di `/opt/kawal-trace` dengan direktori `server_agent/` berisi `__init__.py` dan `chainlog_server_agent.py`.
2. Buat akun layanan khusus tanpa shell interaktif:

   ```bash
   sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin kawal-trace
   sudo groupadd --system kawal-trace-audit 2>/dev/null || true
   sudo usermod -aG systemd-journal,kawal-trace-audit kawal-trace
   sudo install -d -o root -g root -m 0700 /etc/kawal-trace-agent
   sudo install -d -o kawal-trace -g kawal-trace -m 0700 /var/lib/kawal-trace-agent
   ```

3. Salin `server_agent/agent.env.example` ke `/etc/kawal-trace-agent/agent.env`. Ganti host ID, endpoint HTTPS dan token unik. Jangan gunakan token admin API.

   ```bash
   sudo chown root:root /etc/kawal-trace-agent/agent.env
   sudo chmod 0600 /etc/kawal-trace-agent/agent.env
   ```

   systemd manager membaca `EnvironmentFile` sebelum menurunkan privilege service; token tidak perlu ditulis ke command line.

4. Untuk pemantauan folder otomatis, `agent.env.example` dan `auditd-chainlog.rules` sudah disetel ke `/home/server/Anime_Projeck`. Pastikan direktori tersebut memang folder aplikasi server. Jika lokasinya berbeda, ganti `KAWAL_TRACE_WATCH_ROOTS` dan kedua rule `dir=` dengan path yang sama. Salin rule ke `/etc/audit/rules.d/chainlog.rules`, jalankan `sudo augenrules --load`, lalu verifikasi `sudo auditctl -l`. Langkah ini perlu hak administrator karena mengubah kebijakan auditd; aplikasi desktop tidak menjalankan perintah tersebut dari jarak jauh.
5. Jika `audit.log` tidak dapat dibaca oleh akun layanan, konfigurasikan akses read-only yang spesifik pada `/var/log/audit/audit.log` melalui grup/ACL menurut kebijakan host. Jangan menjalankan agen sebagai root hanya untuk melewati permission.
6. Salin `server_agent/kawal-trace-agent.service` ke `/etc/systemd/system/kawal-trace-agent.service`, lalu:

   Unit contoh memberi agen akses baca hanya ke `/home/server/Anime_Projeck` melalui `BindReadOnlyPaths`; sesuaikan baris itu jika root proyek berbeda. Akun `kawal-trace` tetap non-root dan tidak dapat mengubah file server melalui agen.

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now kawal-trace-agent
   sudo systemctl status kawal-trace-agent
   sudo journalctl -u kawal-trace-agent -f
   ```

7. Buat perubahan uji yang disetujui di lab dan pastikan API menerima event; verifikasi event muncul pada `GET /api/v1/security-events?limit=100` dan dashboard Flet dapat membacanya dengan token read-only.

## Privilege dan cakupan

- Agen menggunakan `journalctl` tanpa shell command dari payload. Jalankan sebagai user layanan, bukan root.
- Setelah instalasi satu kali di server (agen, auditd rule, izin baca log), pemantauan pada aplikasi desktop otomatis mengikuti koneksi profil server. Tidak ada tombol pilih/mulai/hentikan folder pada desktop. Tanpa Linux Server Agent dan rule auditd yang aktif, aplikasi tidak dapat memantau isi folder server hanya dari koneksi API.
- Rule memantau operasi tulis/atribut (`perm=wa`): file baru hasil salin/upload ke dalam root akan tampil sebagai pembuatan, perubahan isi sebagai modifikasi, rename/move sebagai pasangan hapus-buat, dan penghapusan sebagai delete. Aktivitas baca atau penyalinan keluar dari root tidak dipantau oleh rule ini karena audit baca dapat menghasilkan volume log sangat besar. Event membuktikan operasi file, bukan identitas penyerang; auditd tidak selalu menyediakan proses/pelaku yang dapat dipastikan.
- `tail -F` digunakan hanya untuk membaca `audit.log`; command-line path berasal dari environment administrasi, bukan dari data jaringan.
- Log command sudo dicatat pada nama executable saja; argumen sengaja tidak dikirim karena dapat mengandung secret.
- Antrean lokal bisa bertambah ketika API mati. Pantau disk dan alarm `pending`; tetapkan retensi serta kebijakan pembersihan setelah event berhasil diterima dan diverifikasi.

## Uji aman tanpa menyerang server

Buat fixture event dengan timestamp dan IP dokumentasi, atau lakukan satu login gagal yang memang diizinkan pada host staging dari IP penguji yang tercantum dalam scope. Jangan membanjiri autentikasi/endpoint produksi. Rule `AUTH_FAILURE_BURST` sengaja memiliki ambang agar satu salah ketik tidak selalu menjadi alarm tingkat tinggi.


## Malware alert opsional (ClamAV)

Agen tidak menyatakan file sebagai malware hanya karena file berubah. Untuk event `MALWARE_DETECTED`, instal ClamAV dan perbarui signature dengan prosedur distro (`clamav`/`clamav-freshclam`), tentukan `KAWAL_TRACE_CLAMSCAN_ROOTS` dengan cakupan sesempit mungkin, lalu set `KAWAL_TRACE_CLAMSCAN_ENABLED=true`. Agen menjalankan `clamscan` pada file yang berubah di root yang diizinkan, berukuran maksimal 100 MiB; ia hanya mengirim event jika signature match dikembalikan oleh ClamAV. Agen tidak membersihkan/menghapus file. Uji pertama memakai test fixture/EICAR di lingkungan terisolasi, bukan malware nyata.

**Perhatian untuk `/home/server/Anime_Projeck`:** unit service mempertahankan `ProtectHome=true` dan hanya mengekspos root proyek itu secara read-only melalui `BindReadOnlyPaths`. Jika project root berbeda, sesuaikan path bind tersebut, environment, dan rule auditd bersama-sama. Pemantauan file tetap bergantung pada auditd; heartbeat akan melaporkan root tidak ditemukan, log tidak dapat dibaca, auditd tidak aktif, atau rule tidak terverifikasi alih-alih mengklaim aktif.

## Respons firewall bukan bagian dari agen

Agen hanya mengumpulkan/mengirim event. Respons IP menggunakan response worker terpisah pada add-on API Ubuntu. UFW hanya untuk IP koneksi langsung (mis. SSH) dan defaultnya disabled. Di belakang Cloudflare, jangan mencoba memblokir visitor HTTP lewat UFW; butuh integrasi WAF yang terpisah.
