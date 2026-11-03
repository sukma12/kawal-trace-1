# Wizard Integrasi Server — Kawal Trace 2.4.0

## Tujuan
Wizard menyederhanakan konfigurasi koneksi dan memisahkan status agar `API terhubung` tidak disalahartikan sebagai `semua log sudah tersedia`.

## Jalur koneksi
1. **Server sudah punya API log** — pilih mode ini, isi nama dan Base URL HTTPS, pilih metode autentikasi sesuai dokumentasi API, lalu tekan **Cari endpoint REST**. Token/API key wajib memiliki izin baca yang sesuai. Auto-detect memakai GET saja, mencoba maksimal sembilan path umum pada host yang diberikan, tidak mengikuti redirect, dan membatasi respons menjadi 4 MiB.
2. **API Kawal Trace** — pilih mode ini untuk API yang mengikuti kontrak enrollment/feed Kawal Trace. Perangkat harus disetujui pemilik server saat pertama kali mendaftar.
3. **Log hanya ada di server** — pilih mode ini jika event masih berada di sistem operasi. Pemilik/administrator host harus mengizinkan agen/collector membaca sumber log dan mengirim event. Wizard tidak memasang software diam-diam atau mengubah firewall remote.

## Auto-detect REST
Path yang dicoba ialah path telemetri profil saat ini dan sejumlah path umum seperti `/api/v1/security-events`, `/api/security-events`, `/api/v1/audit-logs`, `/api/audit-logs`, `/api/v1/logs`, `/api/logs`, `/security-events`, dan `/logs`. Deteksi hanya dianggap kompatibel bila respons JSON memuat array event dan sampel berisi timestamp yang dapat dipetakan. Mapping umum bisa disarankan otomatis. API yang memakai path tidak standar, pagination khusus, payload bertanda tangan, atau skema lain tetap perlu dokumentasi resmi/konfigurasi lanjutan.

Jika endpoint mengembalikan array kosong, wizard dapat mengenali path tetapi tidak mengarang mapping tanpa sampel. Hasil kosong bukan bukti bahwa host aman. Jika tidak ada endpoint yang cocok, gunakan path resmi dari pemilik API atau jalur agen.

## Status terpisah
- **API**: permintaan/ autentikasi API berhasil.
- **Feed**: endpoint mengembalikan event. Nol event ditampilkan sebagai feed kosong, bukan dianggap data sehat.
- **Agen**: hanya dianggap mengirim heartbeat bila ada event `AGENT_HEALTH`; konektor API eksternal umum tidak membuktikan kondisi agen host.
- **Deteksi**: aturan dievaluasi pada event yang diterima; tidak ada event berarti deteksi belum mempunyai data untuk diperiksa.
- **Notifikasi**: statusnya baru hijau setelah jalur audio/notifikasi berhasil diuji di runtime perangkat yang mendukungnya.

## Batas dan privasi
Kawal Trace tidak dapat membaca log internal hanya dari domain/website. Untuk server yang tidak membuka feed keamanan, seseorang yang berwenang mengelola host harus memasang agen/collector atau mengaktifkan feed log. Auto-detect tidak mencari host lain dan tidak melakukan penulisan/serangan. API umum bersifat read-only. Jangan memberi token administrator kepada konektor eksternal; gunakan token baca khusus.
