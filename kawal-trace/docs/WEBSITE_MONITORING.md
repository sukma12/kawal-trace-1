# Pemantauan Website URL-only — Kawal Trace 2.5.0

## Tujuan dan batasan

Mode ini memeriksa ketersediaan satu URL HTTP/HTTPS yang dimasukkan operator. Mode ini tidak meminta token API, tidak mencoba login, tidak melakukan pemindaian port, tidak menebak path, dan tidak membaca file atau log internal server. HTTP 200 bukan bukti bahwa server aman.

Target dan hasil pemeriksaan disimpan di `website-monitor.sqlite3`, terpisah dari database audit/hash-chain dan arsip security-event. SQLite hanya dibuka sebagai database in-memory ketika aplikasi berjalan; seluruh image database yang disimpan di disk dienkripsi dan diautentikasi menggunakan **AES-256-GCM**. Kunci 256-bit dibuat/dibaca melalui Secure Storage OS, bukan dari konfigurasi JSON atau file samping. Jika Secure Storage tidak tersedia, kunci salah, tag autentikasi gagal, atau image rusak, aplikasi menolak membuka database dan tidak melakukan fallback ke database plaintext. Ini adalah enkripsi database pada tingkat aplikasi yang ekuivalen untuk data-at-rest; bukan SQLCipher. Perubahan basis data diterapkan ke file terenkripsi secara atomik.

File SQLite plaintext dari versi sebelum migrasi dienkripsi saat pertama kali database dibuka dan berhasil disimpan. Cadangkan folder aplikasi sebelum memperbarui versi lama. Jika kunci Secure Storage hilang, data terenkripsi tidak dapat dipulihkan; simpan backup sebelum mengganti perangkat atau menghapus data aplikasi.

## Validasi dan mitigasi DNS rebinding

- URL harus memakai HTTP atau HTTPS, tidak boleh menaruh username/password, dan tidak boleh memiliki parameter query yang namanya mengindikasikan token/API key/password/signature/cookie/session/kredensial.
- Hostname di-resolve satu kali per hop. **Semua** hasil DNS diperiksa; jika set hasil mencampur IP publik dan internal/terlarang, hop ditolak.
- Socket TCP dihubungkan ke IP literal yang sudah lolos validasi, bukan menghubungkan ulang hostname melalui HTTP client. Pada HTTPS, sertifikat tetap diverifikasi dan SNI/nama sertifikat menggunakan hostname URL. Ini menutup gap validate-then-re-resolve pada implementasi koneksi ini.
- Setiap redirect divalidasi dan di-resolve lagi, maksimal lima hop. Redirect dari HTTPS ke HTTP ditolak. Persetujuan target internal hanya berlaku untuk hostname yang sama persis dengan target awal, bukan hostname privat lain pada redirect.
- Proxy lingkungan tidak digunakan; target internal memerlukan persetujuan eksplisit. Link-local dan hostname/IP metadata cloud tetap ditolak.
- Request hanya memakai metode GET pada URL yang diberikan, timeout 1–30 detik, interval polling 30–86400 detik. Body respons tidak disimpan maupun dianalisis.

DNS pinning menghilangkan celah re-resolve pada socket aplikasi, tetapi tidak menggantikan firewall, kontrol egress, perlindungan jaringan, atau tinjauan keamanan untuk lingkungan sensitif. Aplikasi tidak boleh dipublikasikan sebagai proxy terbuka.

## Status dan riwayat

Status yang dibedakan meliputi `UP`, `HTTP_ERROR`, `DNS_ERROR`, `TLS_ERROR`, `TIMEOUT`, `CONNECTION_ERROR`, `TARGET_BLOCKED`, dan `REDIRECT_BLOCKED`. Riwayat menyimpan timestamp UTC, status HTTP jika ada, durasi resolusi DNS, durasi respons, total durasi, jumlah redirect, kategori error, dan pesan diagnostik. Hasil website tidak dimasukkan sebagai security log dan bukan bukti bahwa server aman.

## Pengujian dan batas platform

Tes unit menguji penyimpanan autentik terenkripsi, penolakan kunci salah, migrasi database plaintext versi lama, pemblokiran URL sensitif, redirect, TLS, DNS, dan DNS rebinding melalui resolusi yang berubah. Build Windows/Android, integrasi OS Secure Storage pada perangkat nyata, serta perilaku setelah proses crash/power loss tetap harus diuji pada mesin build dan perangkat dukungan sebelum rilis produksi.
