# Real-time dari jarak jauh (server di Jakarta, pemilik di Kalimantan)

Tujuan: pemilik bisa melihat serangan dan menindaknya dari mana saja, tanpa harus berada di jaringan yang sama,
tanpa membuka port server ke internet, dan tanpa mengunggah data perangkat pemilik ke server.

## Bentuknya

```
Server (Jakarta)                                          Perangkat pemilik (Kalimantan)
  agen log ──► API Kawal-Trace (127.0.0.1:8765)             aplikasi Kawal-Trace
                    ▲                                              │
                    └── cloudflared (koneksi KELUAR dari server) ◄─ HTTPS ─┘
```

* Server **tidak membuka port masuk**. `cloudflared` (Cloudflare Tunnel) yang menghubungi Cloudflare dari dalam;
  aplikasi menghubungi nama domain HTTPS. Jadi tidak perlu satu jaringan, VPN, atau IP publik tetap di sisi pemilik.
* Aplikasi memegang **satu koneksi HTTPS keluar** ke `GET /api/v1/stream` (Server-Sent Events).
* Stream hanya **bel pintu**: pesannya berisi *jenis* data yang berubah (`security`, `encrypted`, `actions`,
  `windows`), tidak pernah isi event, IP, atau nama host. Begitu bel berbunyi, aplikasi mengambil data lewat jalur
  yang sama dengan polling lama: terautentikasi, dibatasi ukuran, dan divalidasi ketat.

Akibatnya:

| Pertanyaan | Jawaban |
|---|---|
| Pesan stream hilang / ganda / dipalsukan? | Tidak bisa menyembunyikan atau menciptakan event: isi event selalu berasal dari pengambilan terautentikasi. Bel palsu paling banyak memicu satu pengambilan ekstra. |
| Apakah ada data perangkat pemilik yang dikirim? | Tidak. Permintaan stream adalah GET tanpa isi (hanya token monitor dan Device ID di header). Semua database tetap di perangkat. |
| Server lama (tanpa stream)? | Aplikasi mendapat HTTP 404, menampilkan "SERVER BELUM MENDUKUNG STREAM", dan kembali ke polling 5 detik. |
| Stream putus? | Aplikasi menyambung ulang (jeda 0,5–60 dtk dengan acak) dan selama itu polling 10 detik. Setiap sambung ulang memicu pengambilan penuh agar tidak ada perubahan yang terlewat. |

## Kapan sinyal terkirim

1. Agen mengirim event ke API (`POST /api/v1/security-events:batch`) atau response worker memperbarui status aksi.
2. **Satu** thread pengamat di server melihat penanda perubahan database tiap 1 detik (`MAX(rowid)` terindeks, beban
   tetap berapa pun jumlah aplikasi yang tersambung) dan membangunkan semua stream.
3. Aplikasi menerima sinyal, menggabungkan lonjakan (paling cepat satu pengambilan per detik), lalu mengambil data.

Pengamat juga menangkap perubahan yang dibuat **proses lain** (response worker adalah proses terpisah yang hanya
meng-UPDATE baris), dan berhenti sendiri saat tidak ada yang tersambung.

Yang terukur di lingkungan uji (loopback, tanpa jaringan nyata): dengan interval pengamat 0,04 detik (pengaturan uji)
sinyal tiba hampir seketika, dan aplikasi mengambil ulang dalam < 3 detik. Dengan interval bawaan 1 detik, sinyal
paling lambat sekitar 1 detik setelah baris ditulis. **Latensi lewat internet/Cloudflare/agen nyata belum diukur**;
tambahkan waktu bolak-balik jaringan dan jeda agen mengirim batch. Ukur dari perangkatmu dengan
`scripts/check_connection.py` (lihat bawah).

## Batas dan perlindungan di server

| Pengaturan | Bawaan | Arti |
|---|---|---|
| `KAWAL_STREAM_HEARTBEAT_SECONDS` | 15 | Kirim `: ping` dan **periksa ulang token** tiap interval ini. Harus jauh di bawah 100 dtk (batas diam Cloudflare). |
| `KAWAL_STREAM_MAX_PER_IDENTITY` | 2 | Stream baru dari perangkat yang sama menggantikan yang terlama (koneksi setengah-mati setelah ganti jaringan tidak memblokir sambung ulang). |
| `KAWAL_STREAM_MAX_TOTAL` | 32 | Batas stream terbuka dari semua perangkat; melebihi ini → HTTP 503 `stream_capacity_reached`. |
| `KAWAL_STREAM_MAX_LIFETIME_SECONDS` | 3600 | Stream ditutup dengan `bye`; aplikasi menyambung lagi sendiri. |

* Token monitor wajib. Token upload/audit milik perangkat yang sama **tidak** bisa membuka stream.
* Akses dicabut (`DELETE /api/v1/admin/members/<id>`) → stream terputus paling lama satu heartbeat dan aplikasi
  berhenti mencoba (status "STREAM DITOLAK").
* Aplikasi tidak mengikuti redirect (token tidak pernah diteruskan ke alamat lain), menolak jawaban yang bukan
  `text/event-stream` (mis. halaman login portal), dan membatasi panjang baris/pesan.

## Cloudflare Tunnel — yang perlu diperhatikan

Konfigurasi ingress ke `http://127.0.0.1:8765` (lihat `optional-server-api/README.md`). Untuk stream:

* Jangan menaruh aturan **kompresi, caching, atau "Rocket Loader/minify"** untuk path `/api/v1/stream`. Aplikasi
  meminta `Accept-Encoding: identity`, dan server mengirim `Cache-Control: no-store, no-transform` serta
  `X-Accel-Buffering: no`.
* Menurut dokumentasi Cloudflare yang saya ketahui, koneksi yang diam sekitar 100 detik bisa diputus (tidak saya
  verifikasi dari sini); heartbeat 15 detik dipilih jauh di bawah itu.
* **Saya tidak dapat menguji lewat Cloudflare dari lingkungan pengembangan.** Karena itu ada `check_connection.py`:
  bila proxy menahan (buffer) stream, sinyal `hello` tidak pernah tiba dan langkah "Stream real-time" gagal dengan
  petunjuk, bukan diam-diam terlihat "aktif".

## Memeriksa jalur dari perangkatmu

```bash
export KAWAL_MONITOR_TOKEN=...        # Windows: set KAWAL_MONITOR_TOKEN=...
python scripts/check_connection.py --url https://monitor.contoh.id --device-id ID-PERANGKAT-ANDA
```

Skrip hanya membaca: alamat → DNS/TLS → server menjawab → token & Device ID → feed → stream → waktu bolak-balik.
Ia berhenti di langkah pertama yang gagal dan menyebut penyebab paling mungkin (DNS, sertifikat, tunnel mati,
token salah, alamat bukan API Kawal-Trace, proxy menahan stream). Tidak ada opsi `--token` agar token tidak masuk
riwayat perintah, dan token tidak pernah dicetak.

## Penindakan, pencegahan, penanganan

Yang **sudah ada** dan kini terlihat hampir seketika karena status aksi ikut membunyikan bel (`actions`, `windows`):

* **Blokir sementara IP** (`TEMP_BLOCK_IP`, Linux/UFW): token respons khusus + kode TOTP + ketik konfirmasi persis
  (`BLOCK <ip>`) + alasan; hanya IPv4 publik, bukan IP di allowlist admin, hanya IP yang baru saja gagal login SSH
  langsung (dicatat agen), TTL 5/15/30 menit. API hanya mengantre; **worker root terpisah** memvalidasi ulang dan
  menjalankan UFW, lalu mencabut aturan saat kedaluwarsa. Status `PENDING → ACTIVE_TEMP_BLOCK` baru dianggap aktif
  setelah worker mengonfirmasi.
* **Aksi Windows** terbatas: token respons + TOTP + konfirmasi di aplikasi, lalu dijalankan oleh agen Windows pada host
  terdaftar yang mengambil antreannya dengan token host sendiri (lihat `docs/WINDOWS_AGENT.md`).
* Pemberitahuan dan alarm di aplikasi saat event baru masuk.

Yang **sengaja tidak ada**: pemblokiran otomatis tanpa persetujuan. Pemblokiran otomatis mudah mengunci pemilik
sendiri (IP berubah, salah ketik sandi) dan bisa dimanfaatkan penyerang untuk memblokir pihak yang sah (IP
dipalsukan di belakang proxy). Jalur yang dipilih: **deteksi otomatis → bel real-time → pemilik menyetujui dengan
TOTP**. Pencegahan di sisi server (kunci SSH, tanpa login root/sandi, pembatasan laju) ada di
`docs/CONNECT_REAL_SERVER.md`.

Batas yang jujur:

* UFW tidak dapat memblokir pengunjung HTTP yang masuk lewat Cloudflare (server melihat IP Cloudflare/tunnel).
* Memutus sesi yang **sudah** terbuka tidak dilakukan oleh aturan UFW baru.
* Aksi respons membutuhkan worker aktif (`KAWAL_RESPONSE_ACTIONS_ENABLED=true`, allowlist IP admin terisi); bawaannya mati.

## Android dan aplikasi di latar belakang

Stream hidup **selama aplikasi berjalan**. Android dapat menangguhkan aplikasi yang ditutup atau di latar belakang,
dan saat itu bel dan alarm di aplikasi tidak berbunyi. Notifikasi *push* (mis. FCM) atau layanan foreground
**belum diimplementasikan** dan tidak dapat diuji dari lingkungan ini. Sampai itu ada, untuk serangan yang tidak boleh
terlewat, biarkan aplikasi terbuka (atau di Windows, berjalan) dan matikan penghemat baterai untuk aplikasi ini.
Polling berjarak 30 detik saat stream hidup, bukan sebagai pengganti, melainkan jaring pengaman.

## Memperbarui server ke 1.5.1

Salin `optional-server-api/server.py` baru ke `/opt/kawal-trace-api/server.py` (cadangkan yang lama), lalu:

```bash
sudo systemctl restart kawal-trace-api
sudo systemctl status kawal-trace-api --no-pager
```

Unit systemd juga diperketat di 1.5.1 (lihat bagian *systemd hardening* di `optional-server-api/README.md`). Salin `deploy/kawal-trace-api.service` dan `deploy/kawal-trace-response-worker.service` ke `/etc/systemd/system/`, lalu `sudo systemctl daemon-reload` sebelum `restart`. Bila layanan gagal start atau mencatat `PermissionError`, ikuti langkah *rollback* di bagian itu.

Tidak ada perubahan token atau format database; dua indeks baru dibuat otomatis saat mulai (`IF NOT EXISTS`). Versi 1.5.1 menambah pembatas kegagalan login/TOTP per alamat klien (lihat bagian *Abuse limits* di `optional-server-api/README.md`). Bila ada yang memakai tebakan token berulang dari satu alamat, ia mendapat HTTP 429; klien sah tidak terpengaruh.
Pemeriksaan: `GET /healthz` (dengan token) kini memuat `"features":["stream"]`.

## Yang belum terbukti

* Perilaku nyata melalui Cloudflare Tunnel dan jaringan seluler (hanya diuji lewat loopback).
* Tampilan GUI di Windows/Android (uji memakai pengganti Flet tanpa render piksel).
* Notifikasi saat aplikasi di latar belakang Android.
