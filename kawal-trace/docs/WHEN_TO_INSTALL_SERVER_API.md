# Kawal Trace 2.4.0 — Kapan perlu API/agen server?

## Jawaban singkat

**Tidak semua server harus memasang API Kawal-Trace.** API tambahan hanya diperlukan jika server yang ingin kamu pantau belum menyediakan endpoint feed telemetri keamanan dengan format yang kompatibel.

| Kondisi server | Perlu memasang Kawal-Trace Server API? | Yang dibutuhkan |
|---|---|---|
| API resmi sudah menyediakan feed event keamanan JSON dan memberi token read-only | Tidak | Mode **Generic REST/JSON**, URL endpoint resmi, auth yang didukung, dan mapping JSON |
| Backend sudah memakai kontrak Kawal-Trace untuk audit upload dan security feed | Tidak | Mode **Kawal-Trace API**, token terpisah sesuai peran |
| Ubuntu milik sendiri hanya menjalankan website umum (seperti aplikasi Node pada port 9999) dan tidak menyediakan feed security event | Ya, jika ingin menggunakan kontrak siap pakai Kawal-Trace | Pasang add-on API opsional di folder `optional-server-api/`; untuk event SSH/sudo/file tambahkan agen Linux |
| Hanya punya domain publik/website tanpa akses API/log | Tidak bisa langsung | Dapatkan API resmi atau akses log/agent yang disetujui pemilik server |
| Server pihak ketiga/organisasi lain | Bukan otomatis | Harus ada izin eksplisit, akun/token yang diberikan, API terdokumentasi, dan/atau agent yang disetujui pemiliknya |

## Untuk Ubuntu milikmu saat ini

Dari pemeriksaan yang kamu berikan, `Anime_Projeck/server.js` berjalan pada `127.0.0.1:9999`. Rute yang terlihat (`/api/services/status`, `/api/anime`, `/api/admin/...`) adalah API aplikasi AnimePass/NontonBareng. Rute itu bukan feed keamanan OS dan tidak otomatis mengungkap login SSH, event `sudo`, perubahan file, atau aktivitas pengguna aplikasi secara lengkap.

Jadi ada dua jalur yang tidak saling menggantikan:

1. **Punya API log yang kompatibel**: tidak perlu memasang API atau agen Kawal Trace. Gunakan mode `Server sudah punya API log` di Wizard Integrasi Server.
2. **Ingin melihat event host Ubuntu** (SSH, sudo, perubahan file sensitif): pemilik/admin host harus mengaktifkan sumber log dan memasang agen/collector yang disetujui. Untuk servermu yang menggabungkan route API ke Node.js, endpoint publik bisa berada pada port website yang sama (9999).
3. Add-on `optional-server-api/` pada folder ini adalah alternatif backend lama yang memakai service loopback terpisah; itu opsional dan bukan persyaratan untuk semua pengguna.
Catatan: apabila yang ingin dipantau adalah login aplikasi website, aplikasi web perlu mencatat event login/logout/admin dan mengekspornya ke feed. Agen OS tidak otomatis melihat setiap aktivitas login aplikasi. Lakukan perubahan website produksi hanya setelah backup dan pengujian staging.

## Cara memasang add-on API opsional dari paket terpadu

Paket versi lama menyertakan folder `optional-server-api/` yang berisi kode API server, installer systemd, penerbit token, contoh konfigurasi, dan tes. Folder ini **tidak diinstal pada Windows client**. Transfer folder itu ke Ubuntu, kemudian jalankan `sudo bash install.sh` dari dalam folder yang sudah diekstrak. Ikuti `optional-server-api/README.md` untuk langkah token dan Cloudflare. API bind ke `127.0.0.1:8765`, tidak mengedit Node.js port 9999, tidak membuka firewall, dan tidak mengubah konfigurasi Cloudflare otomatis.

## Mode Generic REST/JSON

Gunakan jika provider server/API yang kamu miliki atau diberi izin sudah menyediakan GET endpoint yang menghasilkan event JSON. Konfigurasi URL HTTPS, path dokumentasi, token read-only Bearer atau `X-API-Key`, path array dan mapping field. Konektor ini hanya melakukan GET ke satu endpoint yang ditentukan; ia tidak mengunggah audit log lokal dan tidak melakukan scan, enumerasi endpoint, login SSH, atau bypass autentikasi. Fitur pagination, OAuth, mTLS, request signing, atau skema proprietari perlu adapter yang sesuai dokumentasi resmi.

## Batasan live feed

Dashboard hanya dapat menampilkan event yang benar-benar direkam sumber log/API dan diteruskan oleh server. IP saja tidak membuktikan identitas manusia atau merek komputer. Lokasi GeoIP hanya perkiraan. Jangan menghubungkan sistem organisasi lain tanpa izin tertulis yang sesuai.
