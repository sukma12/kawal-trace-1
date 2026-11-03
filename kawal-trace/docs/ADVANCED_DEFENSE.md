# Kawal Trace 2.3.0 — Panduan pertahanan lanjutan

Semua fitur di halaman **Perlindungan lanjutan** adalah alat defensif untuk perangkat/server yang dimiliki atau telah diizinkan. Kawal Trace tidak memasang tunnel, mengubah firewall, menghapus email, atau menjalankan perintah respons secara otomatis.

## 1. Akses jarak jauh Zero Trust (ZTNA)

Dokumentasi vendor: [OpenZiti](https://openziti.io/docs/) dan [WireGuard](https://www.wireguard.com/quickstart/).

- **OpenZiti** disarankan untuk membuka aplikasi/service tertentu melalui jaringan overlay berbasis identitas dan kebijakan.
- **WireGuard** sesuai untuk overlay VPN antarperangkat atau jaringan; siapkan peer, kunci, routing, dan firewall terlebih dahulu.
- Tombol `Periksa tool ZTNA` hanya memeriksa apakah tool klien tersedia pada perangkat. Itu bukan tes bahwa tunnel sudah online dan tidak mengubah konfigurasi.
- `Dark IP` bukan jaminan bahwa host tidak bisa dipindai dari semua jalur. Paparan berkurang jika service tidak mendengarkan alamat publik dan firewall/routing benar. Jangan menutup akses SSH sebelum jalur manajemen melalui overlay sudah diuji dari sesi kedua/console.
- Jangan tempel PrivateKey WireGuard ke tiket, chat, atau laporan. Pemeriksa config di modul ini hanya validasi sintaks dan tidak mengembalikan nilai PrivateKey; lebih aman mengelola config dengan tool OS resmi.

## 2. PIN lokal dan biometrik perangkat

1. Masuk pertama kali dengan username dan kata sandi lokal yang kuat.
2. Buka `Perlindungan lanjutan → PIN & biometrik perangkat`.
3. Set PIN 8–12 angka dan konfirmasi.
4. Tutup dan buka aplikasi lagi. Jika PIN sudah aktif, layar login menawarkan PIN perangkat dan—pada build yang memuat `flet-local-auth` dan platform yang didukung—biometrik lokal Windows/Android.
5. Jika biometrik tidak tersedia atau dibatalkan, gunakan PIN atau kata sandi lokal.

PIN disimpan sebagai hash PBKDF2 pada database lokal dan percobaan PIN dibatasi secara lokal. PIN bukan autentikasi ke server dan bukan pengganti perlindungan akun OS. Biometrik diproses lewat dialog keamanan sistem, bukan dikirim ke Google atau Kawal Trace. Pengujian dialog biometrik membutuhkan build native dan tes pada perangkat nyata.

## 3. Analisis email phishing

Referensi API: [PhishTank API](https://phishtank.org/api_info.php). Versi ini hanya melakukan lookup manual pada URL yang dipilih dan mensyaratkan HTTPS; tidak turun ke HTTP biasa untuk menghindari mengirim API key tanpa enkripsi. Jika endpoint HTTPS tidak tersedia dari jaringan/provider, lookup gagal dengan aman dan analisis lokal tetap tersedia.

1. Salin sumber email `.eml` (header dan body) ke kotak analisis.
2. Tekan `Analisis email lokal`. Pemeriksa menganalisis hasil SPF/DKIM/DMARC yang tertulis dalam header, perbedaan From/Reply-To, URL yang mencurigakan, dan bahasa mendesak.
3. Periksa temuan satu per satu. Skor adalah heuristik, bukan vonis dan bukan bukti email aman.
4. Untuk reputasi eksternal, pilih URL tertentu, masukkan API key PhishTank, lalu tekan `Cek URL dengan PhishTank`. Hanya URL terpilih yang dikirim ke penyedia; seluruh email tidak diunggah. API key yang dimasukkan pada kolom tidak disimpan oleh aplikasi.
5. `Jalankan SpamAssassin lokal` hanya berfungsi jika `spamassassin` terpasang pada perangkat yang menjalankan aplikasi; tidak semua build Windows/Android menyediakannya.

Kawal Trace tidak terhubung otomatis ke mailbox/MTA dan tidak menghapus email. Dokumentasi [SpamAssassin](https://spamassassin.apache.org/full/4.0.x/doc/spamassassin-run.html) menjelaskan mode test yang dipakai pemeriksa lokal. Untuk pemeriksaan email otomatis saat diterima, operator harus mengintegrasikan SpamAssassin atau filter setara pada mail server/MTA. Mulai dengan tag/quarantine manual. Jangan auto-delete dari skor heuristik karena false positive dapat menghapus email yang sah.

## 4. Micro-segmentation

Form CIDR adalah **contoh kebijakan**, bukan konfigurasi jaringan sebenarnya. Masukkan network privat yang benar-benar ada di server untuk manajemen, web, aplikasi, dan database. Tekan `Buat pratinjau kebijakan`; Kawal Trace memvalidasi format, menolak CIDR publik/tumpang tindih, lalu menghasilkan daftar izin/larangan.

Status hasil selalu `PREVIEW_ONLY`. Kawal Trace tidak mengeksekusi nftables/iptables. Sebelum operator menerapkan aturan pada firewall secara manual, pastikan:

- akses manajemen dari CIDR yang benar tetap diizinkan;
- DNS, monitoring, backup, update, dan jalur respons insiden diperhitungkan;
- ada akses console/out-of-band dan rencana rollback;
- aturan diuji pada staging dan tidak memutus sesi admin/layanan produksi.

Jangan memakai contoh CIDR bawaan sebagai pengganti peta jaringan nyata.

## 5. Batasan dan privasi

- Analisis email offline tidak membuka URL. URL yang dipilih untuk PhishTank dikirim ke penyedia, jadi tinjau privasi sebelum melakukan lookup.
- Belum ada integrasi otomatis dengan layanan email, OpenZiti controller, atau WireGuard service. Fitur saat ini membantu pemeriksaan dan konfigurasi, tetapi operator tetap memasang/mengelola software jaringan melalui cara resmi.
- Tidak ada pemblokiran firewall otomatis dari halaman micro-segmentation.
- SQLite lokal belum terenkripsi oleh aplikasi; gunakan enkripsi disk/perangkat dan backup aman.
