# Membangun dan memverifikasi APK Kawal Trace 1.0

## Penting sebelum mulai

ZIP source bukan APK dan tidak mengubah aplikasi yang sudah terpasang di ponsel. Untuk mendapatkan perbaikan terbaru, APK harus dibangun ulang dan dipasang. Versi yang terlihat di aplikasi tetap `1.0`; nomor build internal dikonfigurasi `6`.

## Di Windows

1. Ekstrak ZIP ke folder baru, misalnya `C:\KawalTrace-1.0`. Jangan mengekstrak di atas folder data aplikasi yang sedang dipakai.
2. Pastikan Python 3.13 tersedia, internet aktif, dan ruang disk mencukupi. Proses Flet mungkin perlu menyiapkan Flutter/JDK/Android SDK.
3. Jalankan `BUILD_ANDROID_APK.cmd` dan tunggu sampai ada pesan `[SELESAI]`. Jika berhenti dengan `[GAGAL]`, simpan pesan lengkap di terminal dari baris pertama error.
4. Temukan APK di lokasi output yang dicetak oleh Flet, lalu pasang sebagai pembaruan hanya jika Android menerima tanda tangan dan nomor versi build yang cocok. Jangan hapus aplikasi lama untuk memaksa pemasangan sebelum data lokal dicadangkan; penghapusan aplikasi dapat menghapus database akun dan konfigurasi.
5. Pada database yang benar-benar baru, layar pertama harus `Buat akun administrator`, dengan semua kolom kosong. Pada database lama tanpa penanda setup kredensial, layar `Amankan akun lokal lama` akan meminta username/kata sandi lama serta kredensial pribadi baru. Ini sengaja mempertahankan data yang lama.
6. Setelah login, pastikan dashboard tampil. Jika masih gagal, ambil `startup-errors.log` dari folder data aplikasi yang dipakai APK baru. Kirim log saja setelah memeriksa agar tidak ada data pribadi; jangan kirim `identity.sqlite3`, database audit, PIN, password, token, atau private key.

## Bukti pengujian

Tes source build 7 berada di `reports/Kawal_Trace_1.0_Build7_Source_Verification.txt`; log build 6 lama bersifat historis dan bukan bukti build 7. Smoke test menggunakan Flet stub dan bukan bukti bahwa widget sudah dirender secara visual di Android. Rilis tidak boleh dinyatakan lulus perangkat sampai APK selesai dibangun, dipasang, dan alur setup/login/dashboard diuji pada perangkat nyata.


Setelah build dibuka, pastikan footer/header menampilkan `v1.0 · build 7`. Jika masih menampilkan banner login abu-abu besar, batas username 3–32, kata sandi 256, atau error `AttributeError: DATABASE`, cek apakah benar build 7. Jika versi build sudah 7 tetapi panel konten tetap abu-abu, itu adalah kegagalan render yang harus dilaporkan—jangan dianggap lulus.
