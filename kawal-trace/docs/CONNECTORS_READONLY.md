# Konektor Audit Read-only — Kawal Trace 2.5.0

Semua konektor di menu **Konektor Audit** berjalan hanya setelah operator menekan tombol. Gunakan target yang dimiliki atau yang akses auditnya sudah disetujui.

## SSH

Pasang optional dependency `pip install -e '.[ssh]'`. Masukkan host, username khusus read-only, port, `known_hosts` yang dibuat dari host key yang diverifikasi melalui saluran tepercaya, profil log, dan path private key jika belum pernah disimpan. Saat tombol uji dipilih, key file dibaca maksimal 128 KiB dan isi private key disimpan di OS Secure Storage; field path kemudian dikosongkan; berkas sumber pada disk tidak dihapus otomatis. Jangan mempercayai host key dari koneksi pertama tanpa verifikasi independen. Konektor menolak host key yang tidak dipercaya, tidak memakai SSH agent atau pencarian key otomatis, dan hanya menjalankan perintah allow-list untuk membaca log SSH/sudo/auth. Tidak ada kolom command bebas.

## MySQL / MariaDB / SQL Server audit

Pasang `pip install -e '.[mysql]'` untuk MySQL/MariaDB, atau `pip install -e '.[sqlserver]'` untuk SQL Server beserta ODBC driver Microsoft yang kompatibel di OS Anda. Siapkan tabel/view audit dengan kolom waktu, `event_type`, `host_id`, `source`, `actor`, `message`, dan opsional `event_id`, lalu petakan nama kolom di UI. Buat akun database khusus dengan hak **SELECT-only** pada view yang dibutuhkan; aplikasi tidak dapat menggantikan kontrol izin di server.

MySQL/MariaDB memerlukan file CA tepercaya dan verifikasi identitas TLS. SQL Server memakai `Encrypt=yes`, `TrustServerCertificate=no`, dan `ApplicationIntent=ReadOnly`, tetapi tetap memerlukan driver ODBC dan akun dengan hak SELECT saja. Konektor hanya menjalankan SELECT dengan parameter, membatasi jumlah baris dan timeout. Password disimpan melalui Secure Storage OS, tidak di settings JSON dan tidak ditulis ke status error.

## Syslog TCP

Listener dimulai eksplisit. `127.0.0.1` atau IP loopback boleh dipakai tanpa TLS untuk uji lokal. Untuk IP non-loopback, server memerlukan TLS 1.2+ dan mTLS: sertifikat server, private key, dan CA yang memvalidasi sertifikat klien. Jangan membuka port di firewall sebelum sumber pengirim dan aturan jaringan disiapkan. Parser membatasi ukuran/panjang pesan serta mendukung RFC 5424, RFC 3164, framing octet-counted, dan line-delimited.

## Jalur ingestion

Event yang tervalidasi dinormalisasi dan dimasukkan ke audit chain hash lokal dengan kategori yang dibatasi (`AUTH`, `ACCESS`, `CONFIG`, `ALERT`, `SYSTEM`, `NOTE`). ID event sumber disimpan pada detail hash-covered untuk menghindari duplikasi lintas restart. Rantai hash mendeteksi modifikasi tetapi bukan perlindungan mutlak terhadap penyerang dengan kendali penuh atas perangkat; verifikasi/anchor hash di media tepercaya terpisah tetap diperlukan.

## Apa yang diuji

Tes otomasi memeriksa SSH memakai fake Paramiko transport, query DB dengan driver palsu, dan uji TCP syslog end-to-end terhadap listener loopback sungguhan. Itu membuktikan kontrak/protokol di batas aplikasi, bukan akses ke server produksi. Koneksi SSH, MySQL/MariaDB, SQL Server, mTLS syslog antarmesin, sertifikat organisasi, izin firewall, dan build GUI/native harus diverifikasi pada lingkungan yang Anda kelola sebelum digunakan di produksi.
