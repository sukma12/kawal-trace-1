# Kawal Trace 2.0.1 — Privasi, konektor eksternal, dan rilis publik

## Model local-first
- Audit lokal disimpan pada database aplikasi di perangkat. Kolom detail rantai audit dan payload arsip server **dienkripsi at-rest** (AES-256-GCM); kolom lain, database akun/pemindai, isi karantina, dan ekspor **tidak**. Pada Android/Linux kunci berada di berkas di samping database, jadi enkripsi disk OS dan kunci layar tetap diperlukan. Rincian: `LOCAL_STORAGE.md`.
- Menutup server remote tidak menghapus kemampuan pencatatan dan verifikasi audit lokal.
- Profil server menyimpan URL/path/mapping saja; token/API key harus berada di OS Secure Storage.
- Kode aplikasi tidak menambahkan endpoint telemetry/analytics pembuat aplikasi. Jaringan hanya digunakan oleh konektor/profil yang dipilih pengguna, notifikasi native, dan layanan yang secara eksplisit diaktifkan. Review build dependencies dan traffic tetap diperlukan sebelum mengklaim zero telemetry secara mutlak.
- Aplikasi tidak mengunggah audit, arsip, atau hasil pemindaian ke server mana pun; profil Kawal-Trace API hanya dipakai untuk membaca event dari server yang dipantau.

## Konektor API eksternal
Generic REST adalah read-only. Pengguna harus memiliki izin, HTTPS, endpoint feed JSON yang terdokumentasi, mapping field, dan metode auth yang didukung: Bearer, X-API-Key, custom header, atau none hanya jika API memang publik. Tidak semua API kompatibel otomatis. Upload/respons insiden tidak diaktifkan pada Generic REST karena kontraknya berbeda.

## Alarm
Secara default, dua kegagalan autentikasi dari host/IP yang sama dalam 300 detik memicu rule `AUTH_FAILURE_BURST`. Pada koneksi awal, event dalam lima menit terakhir juga dinilai agar insiden yang masih berlangsung tidak hilang di proses baseline. Setelahnya, suara/notifikasi dipicu atas ID event baru yang diterima ketika aplikasi sedang berjalan. Alarm ini tidak memantau semua login lokal sendiri dan tidak berfungsi di latar belakang setelah aplikasi ditutup tanpa agen/backend notifikasi. Tambahkan server/agen yang diberi izin untuk mengirim event keamanan.

## Privasi dan metadata
- Password tidak boleh dikirim sebagai detail event. Normalizer menggunakan allow-list field.
- IP, ASN, negara/kota GeoIP adalah metadata perkiraan bila feed menyediakan; tidak mengidentifikasi seseorang.
- MAC address perangkat di jaringan lokal bukan informasi yang bisa diperoleh begitu saja dari koneksi internet. Metadata perangkat perlu dikirim oleh agen enrollment yang sah.
- Export JSON/CSV tetap merupakan data sensitif. Pengguna bertanggung jawab menyimpannya dengan aman.

## Respons insiden
Pengeluaran anggota hanya berlaku bila API tujuan mendukung pencabutan. Firewall/IP block, logoff RDP, dan penghentian proses hanya tersedia untuk host yang diadministrasikan, dengan token/cakupan, bukti event, allowlist/policy, konfirmasi eksplisit dan pengujian staging. Generic REST eksternal tetap read-only. Jangan mengaktifkan respons otomatis tanpa persetujuan pengelola server.

## Batas operasional
- Feed near-real-time pada dashboard v2.0.1 masih polling setiap 5 detik saat aplikasi terbuka, bukan push global.
- Notifikasi/alarm ketika app ditutup membutuhkan mekanisme OS/background atau push yang diaktifkan dan dikonfigurasi terpisah; tidak termasuk dalam patch ini.
- Paket ini adalah source code; APK/EXE final dan kebijakan toko harus dibangun/ditinjau sesuai target platform. Jangan menyatakan sudah tersedia di Play Store atau Steam sebelum diterbitkan dan disetujui.
