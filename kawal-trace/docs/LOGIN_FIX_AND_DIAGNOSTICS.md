# Login, diagnosis, dan layout perangkat — Kawal Trace 1.0

## Alur instalasi baru

- Pada instalasi yang belum memiliki akun lokal, aplikasi menampilkan **Buat akun administrator** terlebih dahulu.
- Username dan password tidak diisi otomatis. Akun baru hanya dibuat setelah pengguna mengisi form setup dan menekan tombol pembuatan akun. Tidak ada kredensial admin bersama di source.
- Setiap instalasi menyimpan database identitas lokalnya sendiri. Salt/hash PBKDF2 bersifat unik per akun/per instalasi dan Device ID tidak dipakai untuk menurunkan password/PIN.
- Instalasi lama dengan marker bootstrap bersama, tanpa penanda setup pribadi, atau tanpa marker kebijakan `local_credentials_setup_v2` diarahkan ke alur rotasi kredensial: password lama harus diverifikasi, username/password baru ditetapkan, dan data lokal tidak dihapus. Untuk database akun yang sudah ada, menu ini adalah migrasi aman; akun baru penuh hanya ditampilkan bila database identitas belum mempunyai pengguna. Detail environment variable untuk server/agen ada di `SECRETS_AND_LOCAL_ACCOUNTS.md`.

## PIN dan biometrik

- Form PIN tidak ditampilkan langsung; tekan **Masuk dengan PIN perangkat** untuk membuka form PIN.
- Tombol biometrik hanya muncul pada Windows/Android/iOS/macOS yang didukung ketika `flet-local-auth` tersedia, sistem mengonfirmasi dukungan, dan sedikitnya satu metode biometrik terdaftar. Jika pengujian tidak tersedia/gagal, login kata sandi tetap tersedia.
- PIN disimpan sebagai hash lokal; PIN tidak dibentuk dari Device ID.

## Responsif dan diagnosa dashboard

- Form login berada pada `SafeArea` dengan kolom scroll yang eksplisit, padding dan tombol yang menyesuaikan lebar, header yang dapat wrap, serta handler resize. Minimum ukuran window desktop tidak diterapkan pada perangkat mobile.
- Pada layar dashboard sempit, sidebar disembunyikan dan diganti pemilih menu agar panel utama tidak dipersempit oleh rail ikon. Kontrol arsip/ekspor berlebar adaptif dan diperbarui saat viewport berubah.
- Jika pembangunan dashboard gagal, `startup-errors.log` menulis ID diagnosa, tahap saat exception, jenis/pesan exception yang dibatasi, serta traceback yang disamarkan. Layar diagnostik juga bisa digulir dan menampilkan ringkasan exception. Kode ID acak sendiri bukan penjelasan penyebab error; gunakan log untuk menautkan ID dan traceback.

## Status verifikasi

Tes source dan smoke test dengan Flet stub hanya memeriksa alur logika Python/kontrak UI; itu bukan uji GUI nyata. Pada lingkungan penyusunan ini, Flet dan toolchain Flutter/Android tidak tersedia serta jaringan paket tidak dapat dijangkau. Oleh karena itu APK/EXE dan tampilan native harus diuji di perangkat target sebelum dinyatakan lulus. Jangan bagikan `identity.sqlite3`, file Secure Storage, PIN, token API, atau backup private key ketika mengirim log.


## Layout adaptif terbaru
- Kartu login dan tampilan diagnostik berada di root `SafeArea` dengan `Container(alignment=ft.Alignment(0, 0))` dan viewport yang lebarnya/tingginya mengikuti dimensi halaman; handler `on_resize` menghitung ulang ukuran kartu, viewport, dan tombol.
- Scrollbar sengaja disembunyikan dengan `ft.ScrollMode.HIDDEN`; scroll tetap dapat digunakan melalui sentuhan, wheel, atau trackpad. Ini menghilangkan thumb/track scrollbar yang terlihat seperti batang abu-abu panjang, bukan menghapus form maupun menonaktifkan gulir.
- Pada layar sempit, kartu dibatasi ke lebar viewport dikurangi margin; pada laptop kartu maksimum 520 px dan dipusatkan. Dashboard menggunakan selector menu pada HP dan sidebar pada jendela lebar.
- Judul error sekarang `GAGAL MEMBUKA DASHBOARD`; ini menandai exception yang benar-benar terjadi, bukan status loading. Akar exception harus diperiksa pada `startup-errors.log` dari runtime yang gagal.


## Build 7: credential policy and stale build identification

- New installs write `local_credentials_setup_v1` and `local_credentials_setup_v2` only after explicit account creation. No account is bootstrapped automatically.
- Existing accounts from build 5 or earlier that lack the v2 marker must verify the previous password once and choose a new username/password under the current length policy. The old-password field deliberately allows longer legacy input so a user can prove ownership.
- Normal login after migration limits username input to 10 characters and password input to 12. The server-side/local-auth validator remains authoritative for newly created credentials.
- Login, sidebar and dashboard diagnostics show `v1.0 · build 7`. If the app still shows the old banner, 32/256 counters, or the old `DATABASE` error, that is not build 7.
- The dashboard performs a preflight over all Flet icon constants referenced by the UI. If a build contains an incompatible Flet runtime, diagnostics identify the missing constant before the dashboard partially renders.
