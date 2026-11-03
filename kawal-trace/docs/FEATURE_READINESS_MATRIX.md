# Kawal Trace 1.0 — Feature readiness matrix (build 8)

Tanggal pemeriksaan: 29 Oktober 2026 (build 8; baris build 7 yang tidak berubah dipertahankan). Acuan fitur: `Panduan.txt` asli yang disertakan pengguna. Status berikut sengaja membedakan keberadaan source, tes otomatis, koneksi live, dan native UI.

## Status utama

- **Ada source + automated tests**: source dan tes yang relevan berada di paket, dan suite tersedia berhasil dijalankan pada lingkungan audit.
- **Fixture/loopback only**: jalur diuji dengan test double atau layanan lokal, bukan infrastruktur milik pengguna.
- **Butuh setup target**: fungsi memerlukan izin, target, driver, sertifikat, atau kredensial yang disediakan pemilik sistem.
- **Belum diverifikasi di perangkat**: aplikasi native/GUI belum dibangun dan dijalankan pada Windows/Android dalam lingkungan audit.
- **Struktur GUI diuji headless (build 8)**: kode dashboard asli dijalankan terhadap tiruan Flet (`tests/ui_harness.py`), setiap menu diklik, dan pohon kontrol diperiksa linter tata letak. Ini bukan uji render: tidak ada piksel yang dilihat.

| Fitur | Source/UI | Tes lokal yang tersedia | Hal yang belum diklaim |
|---|---|---|---|
| Buat akun lokal, login, rotasi kredensial lama | Ada | `test_auth.py`, `test_default_admin_bootstrap.py`, UI contracts | GUI native pada perangkat belum dijalankan |
| PIN perangkat | Ada | `test_device_unlock.py` dan auth tests | PIN yang disimpan di HP/laptop nyata belum diuji pada build baru |
| Biometrik | Conditional pada dukungan platform/plugin | UI/source contract | Belum diverifikasi dengan sensor biometrik nyata |
| Dashboard dan navigasi fitur | Ada; build 8 menulis ulang navigasi (satu badan halaman tetap, sidebar tidak dibangun ulang saat klik, kartu error per halaman) | `test_dashboard_render_contract.py` (18 tes, kode dashboard asli + tiruan Flet), `test_dashboard_active_view_contract.py`, UI contracts | **Belum dilihat pada GUI nyata.** Keluhan area utama abu-abu setelah klik menu belum dapat dinyatakan teratasi sampai EXE/APK dijalankan |
| Ringkasan status dashboard (website / koneksi / sumber audit / agen / API feed / event / pemindai dipisah) | Ada (build 8) | Render-contract tests | Status agen hanya bisa diketahui lewat feed server; ditulis apa adanya |
| Pemindai keamanan offline (hash SHA-256, Bloom, SQLite, email, tautan, AI lokal) | Ada (build 8) | `test_detectors_core.py`, `test_detectors_email_ai.py`, `test_detectors_pipeline.py`, alur UI di render-contract tests; uji mutasi | Tidak ada database malware sungguhan yang dibawa (hanya EICAR uji); model AI (ensemble, `test_phishing_ensemble.py`) dilatih pada korpus tulisan tangan 212 pesan dan diukur dengan leave-one-group-out + 85 pesan skenario baru, **bukan email nyata**; angka di `AI_MODEL.md` optimistis dan penipuan BEC tanpa tautan hampir tak terdeteksi; SPF/DKIM/DMARC hanya dibaca dari header |
| Backup & Restore terenkripsi | Ada (build 8) | `test_backup.py` (18 tes, termasuk pemulihan nyata, zip-slip, pemotongan, header berbahaya), alur UI | Rahasia Secure Storage OS tidak ikut dibackup; belum diuji di perangkat/EXE/APK; restore ke versi aplikasi berbeda belum diuji |
| Audit lokal/hash-chain | Ada | `test_core.py`, `test_security_pipeline_e2e.py` | Tidak mengklaim tahan jika penyerang menguasai dan dapat menulis ulang seluruh database/checkpoint |
| Jejak/catat aktivitas dan deteksi | Ada | core/detection/pipeline tests | Deteksi bergantung pada event yang benar-benar diterima dari sumber |
| Pantau folder | Ada | `test_monitor.py` | Monitoring direktori pada mesin target nyata belum diuji melalui EXE/APK |
| Pantau website (URL-only) | Ada; database history terpisah terenkripsi | `test_website_monitor.py`, UI contract | Belum dipantau terhadap target eksternal selama tes ini; URL publik tidak memberi akses ke log internal |
| Telemetri & arsip, ekspor PDF/CSV/JSON | Ada | `test_server_archive.py`, `test_server_feed.py`, E2E tests | Arsip remote butuh backend dan akun/izin yang dikelola pengguna |
| Linux agent | Ada | `test_server_agent.py` | Instalasi systemd dan pengambilan log langsung pada host Linux belum live-tested |
| Windows Event Log agent | Ada | `test_windows_agent.py` | Windows Event Log dan service/installer belum dijalankan di Windows nyata |
| SSH read-only | Ada | `test_ssh_connector.py` | Menggunakan fixture/mocked transport; belum terhubung ke server SSH pengguna |
| Database audit MySQL/MariaDB/SQL Server | Ada | `test_database_audit.py` | Driver/credential/permissions milik pengguna dan sumber audit aktif belum diuji live |
| Syslog TCP receiver | Ada | `test_syslog_connector.py`, termasuk loopback test | Tidak menyatakan semua SIEM kompatibel; mTLS dan integrasi collector organisasi perlu tes sendiri |
| Universal API adapters | Ada | connector/protocol/API tests | Skema dan autentikasi vendor tertentu harus dikonfigurasi dan diuji per target |
| Backend API opsional | Ada | 35 tes `optional-server-api/tests` lulus | Deployment pada server produksi/akses jaringan pengguna belum diuji |
| E2EE, key backup, arsip | Ada | `test_e2ee.py`, backup/export contract tests | E2EE hanya untuk payload yang terdokumentasi; metadata routing tetap dapat terlihat sesuai desain |
| Perlindungan lanjutan | Ada | `test_advanced_security.py` dan related tests | Operasi native seperti firewall/RDP harus diuji terpisah pada host staging; respons tetap opt-in |
| EXE Windows | Build scripts dan CI workflow ada | source/test jobs lulus | File EXE/installer belum dibangun dalam lingkungan audit |
| APK Android | Build scripts dan CI workflow ada | source/test jobs lulus | File APK belum dibangun/dipasang dalam lingkungan audit |

## Persyaratan UI dan akun yang diperiksa

- Instalasi bersih tanpa akun harus diarahkan ke `Buat akun administrator`; tidak ada password administrator hardcoded.
- Username baru 4–10 karakter, password baru 8–128 karakter. Validasi dilakukan pada auth layer dan UI. Kredensial historis dimasukkan melalui alur verifikasi/migrasi satu kali agar data lama tidak dihapus.
- Tombol PIN baru ditampilkan saat PIN sudah didaftarkan. Biometrics hanya ditawarkan bila plugin/platform/registrasi terkait didukung.
- Login tidak memakai gambar besar di header; kontainer responsif dan scroll dapat dilakukan tanpa menampilkan scrollbar sebagai batang abu-abu.
- Versi visual tetap `1.0`, build internal saat ini `6` untuk membedakan executable lama.
- Manifest di `docs/LEGACY_FILE_MANIFEST.txt` berisi seluruh path file inner-project dari ZIP asli; tes parity memastikan semua path tersebut tetap ada. `Panduan.txt` dipertahankan identik.

## Hasil yang benar-benar dijalankan pada paket source

- Suite proyek utama: 276 tes lulus.
- Suite API opsional: 35 tes lulus.
- Kompilasi Python: lulus.
- Pemeriksaan GUI Flet asli/native build: belum dapat dilakukan karena Flet dan native toolchain tidak tersedia di container audit.

**Kesimpulan:** matriks ini tidak menandai semua fitur sebagai live-tested. Implementasi lokal/unit yang memiliki tes dibedakan dari konektor yang perlu target nyata dan build yang masih harus dibuat. Rilis native baru boleh dinyatakan siap setelah EXE/APK dibuat, dipasang, dan diuji lewat alur setup → login → dashboard → menu utama pada perangkat yang didukung.


## Kesenjangan terhadap dokumen ketentuan (jujur, build 8)

| Butir ketentuan | Status |
|---|---|
| 4. Skema 14 tabel (`local_settings`, `local_profiles`, `targets`, ...) | **Belum.** Data tersebar di beberapa SQLite/JSON yang sudah ada (audit, identitas, registri server, riwayat website, arsip). Hanya database pemindai memiliki `schema_migrations`. Memigrasi semuanya ke satu skema berisiko merusak data pengguna dan tidak dikerjakan tanpa rencana migrasi yang diuji. |
| 5. Enkripsi database lokal setara SQLCipher | **Sebagian.** Kolom `details` rantai audit dan payload arsip server dienkripsi AES-256-GCM (`test_at_rest.py`, termasuk pertukaran/penyuntingan baris, kunci hilang/rusak, konversi data lama, backup/restore pada perangkat baru). Riwayat website terenkripsi terpisah (kunci di Secure Storage). **Tidak** terenkripsi: kolom jenis/aktor/sumber/waktu, database akun dan pemindai, isi karantina, ekspor. Kunci: DPAPI di Windows (**belum diuji di Windows sungguhan**) atau berkas 0600 di Android/Linux, jadi di sana yang menahan pembaca folder aplikasi tetaplah sandbox dan enkripsi disk OS. Backup `.ktbak` terenkripsi. Lihat `LOCAL_STORAGE.md`. |
| 2.10 Riwayat notifikasi lokal | **Belum.** Notifikasi ditampilkan, tetapi tidak ada tabel/layar riwayat notifikasi. |
| 2.14 Pengaturan lokal terpusat | **Sebagian.** Pengaturan tersebar pada panel masing-masing (sinkronisasi, arsip, folder, website, akun); belum ada layar pengaturan tunggal. |
| 7.7 / 6 EXE dan APK sungguhan | **Belum dibangun/diuji** di lingkungan ini. |
| 9. Struktur `my_antivirus_app/`, `requests`, FastAPI/Flask sebagai backend utama, PyInstaller | **Disesuaikan**, bukan ditiru: pemindai dipanggil langsung oleh UI Flet; Flask hanya sebagai API loopback opsional; `httpx` dipakai; build memakai `flet build`. Lihat `docs/SCANNER_AND_BACKUP.md`. |
