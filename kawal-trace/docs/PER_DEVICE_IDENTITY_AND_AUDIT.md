# Identitas dan riwayat per perangkat

KAWAL TRACE menyimpan akun lokal di `identity.sqlite3` dan mengikat akun, PIN, serta remembered-session ke fingerprint instalasi. Fingerprint adalah HMAC-SHA256 dari secret instalasi dan identifier OS yang tersedia. Identifier hardware mentah tidak ditulis ke record audit.

Setiap event autentikasi mencatat `device_id` (fingerprint pseudonim) dan `platform` (mis. `windows` atau `android`). Event yang dicatat meliputi pembuatan akun administrator pertama, login sukses, login password/PIN gagal, logout, perubahan kredensial administrator, pembuatan akun operator/viewer, dan aktivasi server yang berhasil.

Data aplikasi disimpan dalam direktori privat aplikasi pada masing-masing perangkat. Akun, PIN, dan token remembered-session tidak dibagikan lintas perangkat. Instalasi baru dengan fingerprint berbeda harus membuat akun lokalnya sendiri. Token dari perangkat lain tidak dapat dipakai.

## Batasan yang harus diketahui

- Fingerprint ini bukan hardware attestation. Pada Android, saat OS tidak menyediakan machine ID yang dapat dibaca aplikasi, identitas bergantung pada secret di app-private storage; menghapus data aplikasi atau memasang ulang dapat menghasilkan identitas baru.
- Riwayat autentikasi lokal tetap berada pada perangkat asal. Record aktivasi server menggunakan Device ID yang didaftarkan pada server. Jangan menyalin database aplikasi secara manual antarperangkat untuk menggabungkan riwayat.
- Build 13 menambahkan penandaan perangkat ke record audit; ini tidak mengklaim bahwa runtime OpenZiti sudah dibundel/diintegrasikan penuh pada Windows maupun Android. Runtime OpenZiti dan pengujian koneksi fisik tetap merupakan pekerjaan terpisah.
