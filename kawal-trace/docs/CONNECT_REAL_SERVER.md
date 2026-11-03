# Menyambungkan aplikasi ke server nyata (SSH? Winbox? agen? API?)

Jawaban singkat: **aplikasi tidak "masuk" ke server lewat Winbox atau RDP.** Aplikasi membaca *telemetri* yang
dihasilkan server (log login, perubahan, status), lewat salah satu jalur di bawah. Jalur mana yang cocok
bergantung pada apa yang sebenarnya kamu punya.

## 0. Syarat yang tidak bisa ditawar: izin

Hanya pantau server **milikmu** atau yang pemiliknya memberi izin tertulis dan akun/token resmi. Kalau yang kamu
maksud "server Telkomsel" adalah sistem milik Telkomsel sendiri, kamu butuh izin resmi mereka; aplikasi ini tidak
membuka jalan masuk apa pun ke sistem orang lain, dan memang tidak boleh. Kalau yang dimaksud adalah **VPS/server
yang kamu sewa** dari penyedia mana pun, server itu milikmu untuk dikelola dan semua panduan di bawah berlaku.

## 1. Pilih jalur dari apa yang kamu punya

| Yang kamu punya | Jalur yang cocok | Real-time? | Catatan |
|---|---|---|---|
| Server **Linux**, akses SSH dengan hak sudo | **Agen + API Kawal-Trace** (jalur utama) | Ya (stream) | `docs/LINUX_SERVER_AGENT.md` + `optional-server-api/README.md`. Data tetap di perangkatmu. |
| Server Linux, hanya SSH akun terbatas, tidak boleh memasang apa pun | **Konektor SSH read-only** (menu Konektor Audit) | Tidak (ambil manual) | Hanya perintah log yang sudah ditetapkan; kunci host harus terverifikasi lewat `known_hosts`. |
| Server **Windows** (RDP) | **Agen Windows** + API | Ya (stream) | `docs/WINDOWS_AGENT.md`. Winbox/RDP hanya untuk kamu mengelola server, bukan untuk aplikasi. |
| **Router MikroTik** (Winbox) | **Syslog jarak jauh** dari router ke penerima syslog | Mendekati (log dikirim router) | Winbox hanyalah aplikasi admin MikroTik: aplikasi ini **tidak** memakainya. Lihat bagian 4. |
| Hosting bersama/panel tanpa shell | Hanya jika penyedia memberi **API/feed log** | Tergantung | Mode "Server sudah punya API log" (Generic REST, baca-saja). Tanpa feed log, tidak ada yang bisa dipantau. |
| Server milik pihak lain tanpa izin | **Tidak ada** | — | Lihat bagian 0. |

SSH sendiri adalah *cara kamu masuk untuk memasang dan mengamankan*, bukan saluran yang dipakai aplikasi sehari-hari:
sehari-hari aplikasi hanya bicara HTTPS ke API di server.

## 2. Jalur utama untuk server Linux (langkah demi langkah)

Urutannya penting: **amankan dulu, baru pasang pemantau.**

1. **Amankan SSH (pencegahan).** Masuk dengan SSH dari terminal/PuTTY, lalu:
   * Buat kunci SSH di perangkatmu dan pasang kunci publiknya (`ssh-copy-id` atau salin ke `~/.ssh/authorized_keys`).
   * **Buka sesi SSH kedua dan pastikan login dengan kunci berhasil sebelum mengubah apa pun**, supaya tidak terkunci.
   * Di `/etc/ssh/sshd_config`: `PasswordAuthentication no`, `PermitRootLogin no`; muat ulang `sshd`.
   * Firewall: `sudo ufw allow OpenSSH`, `sudo ufw limit OpenSSH` (membatasi laju percobaan), lalu `sudo ufw enable`.
     Jangan menutup SSH di firewall sebelum yakin bisa masuk.
2. **Pasang API Kawal-Trace** (add-on `optional-server-api/`), sesuai README-nya: `sudo bash install.sh`, lalu
   `sudo /usr/bin/python3 /opt/kawal-trace-api/setup_tokens.py`, restart, dan uji lokal
   `curl -i http://127.0.0.1:8765/healthz` (401 tanpa token itu normal). Jangan membuka port 8765 ke internet.
3. **Cloudflare Tunnel** bernama (bukan Quick Tunnel; URL-nya berubah) ke `http://127.0.0.1:8765`, dengan nama
   domain khusus. Untuk stream, ikuti catatan di `docs/REMOTE_REALTIME.md`.
4. **Pasang agen log** (`server_agent/`) sesuai `docs/LINUX_SERVER_AGENT.md` dengan token ingest khusus agen.
5. **Di aplikasi:** menu *Integrasi Server* → profil baru (nama, alamat HTTPS, Device ID) → simpan token monitor →
   **Hubungkan**. Status "REAL-TIME AKTIF" muncul hanya bila stream benar-benar tersambung.
6. **Periksa jalurnya dari tempat kamu berada** (mis. dari Kalimantan):
   `python scripts/check_connection.py --url https://alamat-kamu --device-id ID-PERANGKAT`. Ia menyebut langkah
   pertama yang gagal dan penyebab paling mungkin.
7. **Uji aman**, tanpa menyerang server sendiri: satu login SSH gagal yang disengaja dari IP penguji, lalu pastikan
   event muncul di aplikasi (`docs/LINUX_SERVER_AGENT.md`, bagian "Uji aman").
8. **Aktifkan respons hanya setelah semua di atas stabil:** isi `KAWAL_RESPONSE_ALLOWLIST` dengan IPv4 publik admin
   *sebelum* `KAWAL_RESPONSE_ACTIONS_ENABLED=true`, dan pastikan kamu punya jalur masuk cadangan (konsol penyedia).

## 3. Jalur SSH read-only (tanpa memasang apa pun di server)

Menu **Konektor Audit → SSH** menjalankan hanya perintah log yang sudah ditetapkan (SSH/sudo dari journal, atau
`auth.log`), dengan akun khusus baca. Butuh `pip install -e '.[ssh]'`, file `known_hosts` yang dibuat dari kunci host
yang kamu verifikasi lewat saluran tepercaya (kunci tak dikenal ditolak), dan kunci privat yang disimpan di
penyimpanan aman OS. Ini ambil-sekali-per-tekan, bukan real-time, dan tidak memantau perubahan file.

## 4. MikroTik/RouterOS dan "Winbox"

* **Winbox** adalah aplikasi administrasi MikroTik. Ia berguna bagi *kamu* untuk mengatur router, tapi tidak
  memberi aplikasi ini jalur baca log.
* Yang bisa dipakai: konfigurasikan router untuk **mengirim log ke penerima syslog** (menu *Konektor Audit → Syslog TCP*
  atau pemancar syslog yang meneruskan ke sana). Untuk alamat non-loopback penerima mewajibkan **TLS + sertifikat
  klien (mTLS)**; sebagian besar router mengirim syslog biasa (UDP/TCP tanpa TLS), jadi pasang penerima/relai di
  jaringan tepercaya, jangan membuka port syslog polos ke internet.
* Parser mengenali pola pesan bergaya RouterOS: `login failure for user X from IP via winbox` → kegagalan login,
  `user X logged in from IP via ssh` → login berhasil, dan mencatat metodenya (winbox/ssh/api/…).
* **Belum terbukti:** pola itu ditulis dari bentuk pesan yang didokumentasikan, **bukan** dari perangkat MikroTik nyata,
  dan bentuk *framing* syslog yang dikirim versi RouterOS tertentu belum diverifikasi. Jika baris dari routermu
  ditolak, penghitung "ditolak" di menu Konektor Audit bertambah dan event tidak masuk; kirim contoh barisnya
  (tanpa data sensitif) agar parser dapat disesuaikan dengan keluaran sebenarnya.
* Tidak ada konektor RouterOS API/SSH baca-saja dan tidak ada tindakan terhadap router dari aplikasi ini.

## 5. Yang tidak bisa saya buktikan dari lingkungan pengembangan

* Sambungan ke server, Cloudflare, jaringan seluler, atau router **nyata**: semua diuji hanya lewat loopback dan tiruan.
  Karena itu `scripts/check_connection.py` ada: hasilnya dari perangkatmu adalah bukti yang sebenarnya.
* Pemasangan `install.sh`, systemd, UFW, dan worker pada distro tertentu.
* Bentuk log MikroTik nyata (bagian 4).
