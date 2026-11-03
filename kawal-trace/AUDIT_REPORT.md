# Addendum build 8 (29 Oktober 2026)

Baca `reports/Kawal_Trace_1.0_Build8_Verification.txt` untuk hasil tes yang dipisah per jenis (unit, integrasi, struktur GUI headless, perangkat nyata) dan
`reports/Kawal_Trace_1.0_Build8_Before_After.txt` untuk perbandingan isi source sebelum/sesudah. Ringkas:

* Navigasi dashboard ditulis ulang dan diperiksa dengan linter tata letak pada kode dashboard asli; **render nyata belum teruji** (tidak ada Flet/EXE/APK di lingkungan audit).
* Ditambahkan: pemindai offline, backup/restore terenkripsi, ringkasan status. Kesenjangan terhadap ketentuan dicatat di `docs/FEATURE_READINESS_MATRIX.md`.
* Angka "277 passed" pada audit build 7 tidak dapat direproduksi persis: pada salinan bersih ZIP asli saya mengukur 243 tes utama (241 lulus, 2 dilewati karena `websockets` tidak terpasang di sandbox) ditambah 35 tes API opsional.

---

# Kawal Trace 1.0 — Audit final build 7

Tanggal: 28 Oktober 2026
Paket source: `Kawal-Trace_1.0_Blank_Main_Fix_Build7_Source.zip`
Versi tampilan: `1.0` · nomor build native: `7`

## Akar masalah dan perbaikan

Screenshot sebelumnya menunjukkan tahap `construct dashboard controls`, exception `AttributeError`, ringkasan `DATABASE`. Source lama memakai `ft.Icons.DATABASE`, yang tidak tersedia pada runtime Flet yang menjalankan build tersebut. Tombol audit database sekarang menggunakan `ft.Icons.TABLE_CHART`. Sebelum dashboard membuat kontrol, build 7 memeriksa semua konstanta ikon Flet yang dirujuk. Jika dependency tidak cocok, halaman diagnosis menyebutkan konstanta yang hilang alih-alih berhenti di tengah penyusunan dashboard.

Header form login tidak menggunakan gambar besar; hanya teks nama aplikasi, versi dan build. Ini mencegah placeholder gambar abu-abu yang terlihat di screenshot versi sebelumnya. Form login dan setup menggunakan `SafeArea`, lebar responsif, dan scroll dengan scrollbar tersembunyi tetapi tetap dapat digunakan.

## Akun lokal

- Instalasi baru tanpa akun membuka `Buat akun administrator`; tidak ada akun/password otomatis dan tidak ada kolom terisi.
- Username baru dibatasi 4–10 karakter; password baru 6–12 karakter. Validasi ada pada `chainlog/auth.py` selain pembatasan field UI.
- Akun dari build lama tanpa `local_credentials_setup_v2` menjalani satu kali verifikasi kredensial lama sebelum dapat menetapkan kredensial baru. Input password lama mengizinkan panjang historis agar pemilik tidak terkunci dari akun sendiri. Perubahan ini tidak menghapus database audit, PIN, target, profil konektor, atau konfigurasi lokal.
- Login normal setelah migrasi dibatasi 10/12 karakter. Tombol PIN hanya dibuat jika ada PIN terdaftar; biometrik hanya ditawarkan ketika plugin, platform, dukungan sistem, dan metode biometrik yang tersedia lolos pemeriksaan.
- Login, sidebar, dan diagnosis menampilkan `v1.0 · build 7` agar executable lama mudah dikenali.

## Fitur lama dipertahankan

File manifest membandingkan paket release terhadap seluruh 101 path file pada direktori proyek dalam ZIP yang diberikan pada awal percakapan; semua path lama tetap ada. `Panduan.txt` di root juga dibandingkan dan tetap identik dengan file yang dikirim. Tidak ada modul lama yang sengaja dihapus. Menu dashboard masih mendaftarkan Dashboard, Jejak Aktivitas, Catat Aktivitas, Pantau Folder, Pantau Website, Integrasi Server, Telemetri & Arsip, Konektor Audit, Perlindungan Lanjutan, dan Akun Operator (untuk role admin).

Tambahan yang ada di source meliputi pemantauan website dengan penyimpanan riwayat terpisah, konektor SSH read-only, audit MySQL/MariaDB/SQL Server, penerima syslog, ingestion ke audit chain, Linux/Windows agent, Universal API Adapter, arsip, ekspor, backup/E2EE dan panel perlindungan. Akses ke server/database nyata tetap memerlukan target, izin, driver, kredensial dan konfigurasi pengguna.

## Tes yang dijalankan

| Pemeriksaan | Hasil |
|---|---:|
| Suite proyek utama (`python -m pytest -q`) | **277 passed** |
| Suite API opsional (`python -m pytest -q optional-server-api/tests`) | **35 passed** |
| `compileall` pada source, connector, tests dan agents | **PASS** |
| Manifest file proyek awal | **Semua path dipertahankan** |
| `Panduan.txt` terhadap file yang dikirim pengguna | **Identik** |
| Pemeriksaan referensi `ft.Icons.DATABASE` lama | **Tidak ada** |
| Artefak `.exe`/`.apk` di lingkungan audit | **Tidak dibuat** |

Jumlah tes di atas adalah hasil unit/integration tests yang dapat dijalankan secara lokal dari source; bukan jumlah percobaan GUI dan bukan bukti server remote sungguhan berhasil dikoneksikan.

## Verifikasi paket bersih

ZIP source build 7 diekstrak ulang ke direktori bersih, lalu tes dijalankan dari ekstraksi tersebut: **277 tes utama lulus**, **35 tes API opsional lulus**, `compileall` lulus, **102 entri manifest tersedia tanpa file hilang**, dan `Panduan.txt` cocok byte-per-byte dengan file pengguna. Log build 7 ada di `reports/Kawal_Trace_1.0_Build7_Source_Verification.txt`. File laporan build 6 yang lama dipertahankan sebagai catatan historis.

## Batasan yang belum dapat diklaim selesai

- Flet tidak tersedia di lingkungan audit dan pip tidak dapat mengakses index paket saat diperiksa. Karena itu GUI Flet asli belum dapat dibuka atau difoto setelah perubahan.
- Tidak ada EXE/installer Windows atau APK Android yang dibangun di sini. Windows `flet build windows` memerlukan Windows; Android build memerlukan Flet CLI, Flutter/JDK/Android SDK dan dependensi yang dapat diunduh. Skrip dan CI sekarang meminta build number 7 dan membersihkan output lama, tetapi keberhasilan artefak harus dibuktikan pada mesin build/CI.
- Biometrik/native notifications perlu pengujian build pada perangkat yang kompatibel.
- SSH, database audit dan SIEM/syslog telah diuji di tingkat unit/integration fixtures yang disediakan tes; server/database organisasi pengguna belum diuji secara live. Tidak ada klaim bahwa semua format SIEM atau semua vendor otomatis kompatibel.
- Database audit utama/arsip lokal masih memerlukan proteksi sistem operasi/perangkat pada data-at-rest; enkripsi database website tidak berarti seluruh SQLite lain otomatis terenkripsi.

## Cara memastikan executable yang benar dibuka

1. Cadangkan data lokal terlebih dahulu. Jangan menghapus data aplikasi untuk memaksa halaman setup.
2. Bangun APK atau EXE dari source ZIP ini, bukan menjalankan executable lama. Skrip menghapus folder `build` lama dan memastikan artefak hasil ditemukan sebelum melaporkan sukses.
3. Pada startup, lihat label `v1.0 · build 7`. Jika label tidak tampak atau masih ada banner abu-abu, tutup aplikasi karena yang berjalan bukan build 7.
4. Pada instalasi benar-benar baru, pastikan `Buat akun administrator` muncul. Pada database lama yang belum memiliki marker v2, verifikasi akun lama dan pilih kredensial baru.
5. Login dan periksa dashboard; semua menu yang sesuai role harus tampil. Jika gagal, kirim hanya `startup-errors.log` yang sudah diperiksa agar tidak berisi rahasia.


## Build 7 — user screenshot: blank grey main panel

The screenshot for build 7 showed a fully blank grey content pane while the sidebar rendered. This is a functional failure; the previous source test counts did not verify native visual rendering. The current source changes the dashboard layout from a single scrollable column containing every visible/hidden feature page to one active `view_host`. Navigation swaps `view_host.content` to the selected page, so inactive connector UI is not mounted during initial dashboard rendering. The content host also has an explicit app background.

Build 7 includes a source contract test for this architecture. This environment has no installed Flet runtime and cannot download it, so **native rendering has not been verified here**. If build 7 still renders a blank pane, that is a failure; capture the Windows/Flet console traceback or `startup-errors.log`. Do not treat the source-contract test as proof that the UI rendered.
