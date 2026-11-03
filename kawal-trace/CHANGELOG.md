## Build 14 — Trusted Access & Response (Kawal Trace v10 target)

- Added `chainlog/trusted_access.py`: local store and helpers for Trusted Members, Trusted Devices, activation invitations, cryptographic device identity (Ed25519 keypairs), access verification (challenge–response), Unauthorized Access / Incident History, and response audit trail.
- Invitation flow (admin side):
  1. Admin enters member name + email.
  2. System creates a PENDING member and a time-limited activation invitation code.
  3. Member installs the app, verifies the invitation, generates a device keypair, and registers the device identity + public key.
  4. Server/local store marks the device TRUSTED; subsequent connections must prove possession of the private key.
- Membership is no longer “email registered = trusted”. Trust requires the verified device identity and key material.
- Incident recording captures source IP, account, device, session, classification (OFFICIAL / UNKNOWN / SUSPICIOUS / INTRUDER), reason, actions taken (force disconnect, IP block, revoke, isolate), and outcome.
- Official members are still monitored; compromised accounts or devices can be classified and responded to. Administrator protection remains a design constraint for automatic force-disconnect.
- Feature matrix covered by the new module (local companion to existing optional-server-api member_accounts + response_worker):
  | Fitur               | Fungsi                              |
  | ------------------- | ----------------------------------- |
  | Trusted Members     | Daftar anggota resmi                |
  | Trusted Devices     | Daftar perangkat resmi              |
  | Access Verification | Memverifikasi setiap koneksi        |
  | Unauthorized Access | Daftar percobaan akses tanpa izin   |
  | Force Disconnect    | Memutus sesi penyusup terverifikasi |
  | IP Blocking         | Memblokir sumber serangan           |
  | Revoke Access       | Mencabut akses anggota              |
  | Incident History    | Riwayat deteksi dan penindakan      |
- Existing Build 13 authentication records, device fingerprint binding, enrollment/claim API, and response_worker UFW temporary deny remain intact; this build extends them.
- Unit tests: `tests/test_trusted_access.py` (invitation lifecycle, device key verification, revoke cascade, incident recording).
- Native build number raised to 14; package version 1.0.2. Display version remains 1.0 style for continuity.
- Verification performed with automated unit tests on the new module + end-to-end logic test (invitation → key proof → incident → revoke).
- Form undangan + daftar Trusted Members/Devices + Riwayat Insiden dipasang di panel Keanggotaan server pada dashboard (admin saja).
- Tombol: Buat Undangan Anggota, Muat Trusted Access, Muat Riwayat Insiden, Catat Insiden Uji.
- API response mendukung antrian `FORCE_DISCONNECT_SSH` (selain `TEMP_BLOCK_IP`) dengan proteksi akun admin/root/ubuntu dan konfirmasi eksplisit.
- Response worker memproses FORCE_DISCONNECT secara **fail-closed**: menolak auto-kill kecuali `KAWAL_FORCE_DISCONNECT_ENABLED=true`, dan bahkan saat itu hanya menandai ACKNOWLEDGED_NO_AUTO_KILL (tidak mengeksekusi pkill/ss otomatis) agar administrator terlindungi.
- Full live SSH force-disconnect on a production host still requires the privileged response worker, UFW, allow-list, and explicit KAWAL_FORCE_DISCONNECT_ENABLED on that host.

## Build 12 — OpenZiti Setup Integration
- Added an in-dashboard Windows OpenZiti setup action that downloads the official latest Desktop Edge installer from the official GitHub release, enforces HTTPS host allowlisting, size checks, optional release SHA-256 digest validation, and Authenticode signature/publisher validation before launch. Installation still requires the vendor installer and Windows UAC.
- Added an Ubuntu Server setup script for the VirtualBox VM using the official signed OpenZiti Debian package repository; supports restricted-permission JWT staging for a server-specific identity.
- Added an OpenZiti deployment guide clarifying separate identities, Controller/Edge Router prerequisites, and what the app does not provision.

## Build 11 — Private Network Access
- Added explicit connect/disconnect controls for an already-installed OpenZiti Edge Tunnel service (Linux systemd / Windows Service Control).
- Added WireGuard configuration selection, in-memory config validation, and explicit wg-quick / WireGuard for Windows tunnel service connect/disconnect.
- Unified both providers with private endpoint TCP reachability testing; actions require OS administrator/root permissions where applicable.
- No router, firewall, enrollment, identity, or peer configuration is created automatically.

# Kawal Trace — Changelog

## Build 13 — Record autentikasi dan aktivasi per perangkat

- Setiap record autentikasi penting sekarang menyertakan ID perangkat pseudonim yang stabil dan label platform (Windows/Android), tanpa menyimpan MachineGuid atau ID perangkat mentah.
- Riwayat mencatat pembuatan administrator pertama, login sukses (password/PIN/biometrik/perangkat diingat), login password/PIN yang gagal, logout, perubahan kredensial administrator, pembuatan akun operator/viewer, dan aktivasi server yang berhasil.
- Identitas lokal, akun, PIN, dan sesi tetap terikat pada fingerprint instalasi. Perangkat lain tidak dapat memakai akun atau token perangkat pertama; perangkat tersebut harus membuat akun lokalnya sendiri.
- Event aktivasi server mencatat Device ID server yang sedang digunakan, sehingga riwayat aktivasi dapat ditelusuri ke perangkat asalnya.
- Tidak ada penggabungan akun atau sesi antarperangkat. Log lokal tetap berada di penyimpanan privat instalasi; sinkronisasi/arsip pusat tidak digunakan untuk menyatukan log autentikasi lokal.
- Build Windows dan Android dinaikkan ke 1.0.1 / build 13.
- Batas verifikasi: perubahan ini diuji dengan harness otomatis dan bukan bukti build native atau uji koneksi OpenZiti nyata di perangkat fisik.


## Build 10 — Uji pipeline telemetri dan probe endpoint ZTNA

- Menambahkan tombol **Uji pipeline lokal** yang menjalankan event sintetis melalui validasi, deteksi lonjakan autentikasi, penulisan arsip SQLite, baca ulang, dan deduplikasi. Data uji disimpan sementara lalu dihapus; tidak menghubungi server atau membuat insiden nyata.
- Menambahkan **Uji koneksi endpoint privat** untuk menguji host/port TCP layanan privat dari perangkat. Uji hanya membuka koneksi singkat dan tidak mengubah tunnel, route, firewall, atau service. Keberhasilan hanya membuktikan endpoint terjangkau; endpoint harus private-only agar hasilnya relevan untuk ZTNA.
- Build internal dinaikkan ke 10.

## 1.0 build 9 — ZTNA diagnostics, telemetry alerts, and dashboard motion

- ZTNA diagnostics now check OpenZiti Edge Tunnel/CLI and WireGuard tool installation, bounded version output, local Edge Tunnel service/process state, and WireGuard interface presence. All checks are read-only; Controller identity/policy are explicitly marked unverified without authorized credentials.
- Server telemetry now raises a HIGH review alert for server-reported privileged activity (`PRIVILEGE_USE`), using the existing new-event sound/native notification path. This is a review signal, not proof of unauthorized access.
- Automatic REST-feed polling now also runs for explicitly configured no-auth/OAuth read-only adapters, without requiring a separate Kawal Trace monitor token. Unexpected feed adapter exceptions are logged and no longer tear down a healthy real-time stream.
- Dashboard topology animation now pulses connected/connecting nodes and only animates traffic packets on active/connecting links; idle and failed links no longer look like they carry traffic.
- Notifications remain local while the app is running. Push delivery while the app is fully closed is not configured; no FCM credentials or device-registration backend are fabricated.

## Perubahan tampilan Kawal Trace — animasi, logo, dan status koneksi

- Sidebar memakai simbol kunci dari logo Kawal Trace yang diberikan; nama dan tata letak merek tetap dipertahankan.
- Tidak ada intro video saat aplikasi dibuka; aplikasi langsung memulihkan sesi tersimpan atau menampilkan login.
- Video asli 630×360 diproses menjadi salinan 1920×1080 dengan resampling Lanczos dan penajaman ringan. Detail yang tidak ada pada sumber resolusi rendah tidak dapat dipulihkan; file asli tetap disimpan sebagai `docs/reference/Animasi-original.mp4`.
- Area hero dan kartu alur integritas statis pada dashboard dihapus; area ringkasan menjadi visualisasi topologi jaringan beranimasi dengan susunan cabang melengkung mengikuti referensi: aplikasi → audit core → file monitor/pemindai/website → verifikasi SHA-256 → konektor audit → agen Linux/Windows → Server API. Kabel optik, titik paket bergerak, ikon fitur, dan partikel latar digambar langsung pada Canvas.
- Daftar status teks ganda (Website, koneksi server, sumber audit, agen, API feed, event, SSH, database, dan pemindai) dihapus dari bawah animasi. Status masing-masing fitur kini terlihat pada node animasinya sendiri. Status hijau/biru/merah/amber/abu-abu tetap berasal dari runtime aktual, bukan timer simulasi.
- Baris metode login di topbar dan catatan footer yang ditandai dihapus; tombol Keluar dan sistem notifikasi tetap ada. Validasi teks email/URL yang kosong ditampilkan pada panel pemindai, bukan di footer global.
- Dependensi pemutar video dihapus karena alur pembuka tidak lagi memakai video. Animasi topologi digambar langsung pada Canvas dan mengikuti status fitur aktual.

## Belum dirilis — pemindai terisolasi, akun per perangkat

- **Bug stream real-time diperbaiki (API 1.5.1).** Penjaga perubahan mengambil titik acuan pada polling pertamanya sendiri, sehingga perubahan yang masuk setelah `hello` tetapi sebelum polling itu bisa tidak pernah diberitahukan (hanya terkejar polling cadangan). Titik acuan kini diambil sebelum `subscribe()` kembali. Ditemukan lewat satu tes yang gagal hanya saat mesin sibuk; sekarang ada tes deterministik untuk celah itu.

- **Audit dependensi di CI** (`.github/workflows/audit.yml`): `pip-audit` (versi dipin) berjalan tiap Senin dan saat berkas dependensi berubah, terpisah dari build agar kerentanan baru terlihat tanpa memblokir perbaikan lain. **Audit ini belum pernah dijalankan** (indeks paket tidak terjangkau dari lingkungan penyusunan): hasil run pertamanya adalah jawaban nyata pertama tentang kerentanan dependensi. Aksi GitHub (`actions/*@v4/v5`) masih dirujuk lewat tag, bukan SHA commit, karena saya tidak dapat mencari SHA yang benar dari sini dan tidak mau mengarangnya; sematkan ke SHA bila ingin perlindungan tambahan terhadap tag yang dibajak. `tests/test_workflows.py` menjaga agar berkas workflow tetap YAML valid (kesalahan ini sempat saya buat sendiri dan tertangkap).

- **Pindai-folder tidak lagi memberi kepastian palsu.** Folder yang tidak dapat dibaca (mis. Android tanpa "Akses semua file", atau izin ditolak) dulu berakhir sebagai "0 file dipindai · AMAN"; kini menjadi galat yang menyebut penyebab dan langkah perbaikan, subfolder yang tidak terbaca dilaporkan, dan hasil bersih diberi label "pada file yang dapat dibaca". Izin Android `MANAGE_EXTERNAL_STORAGE` dideklarasikan (opt-in pengguna di Pengaturan) agar hapus-malware di penyimpanan bersama dapat bekerja; tes mengunci daftar izin. `docs/MALWARE_ISOLATION.md` menjelaskan tiga pintu, karantina, hapus otomatis 15 menit, batas Android, dan yang belum terbukti.

- **Unit systemd diperketat (API 1.5.1).** Layanan API: tanpa capability, `/proc` tersembunyi, tanpa namespace, daftar-izin syscall (`@system-service` tanpa `@privileged @resources`, **diukur** dengan menjalankan seluruh tes API di bawah `strace`), jaringan hanya ke loopback (proses API yang diambil alih tidak bisa mengirim data keluar), batas thread; skor `systemd-analyze security --offline` 6.5 → 1.1. Tes menjaga bahwa API tidak pernah membuat koneksi keluar. `deploy/check_syscalls.py` mengulang pengukuran di servermu. Unit worker UFW dilonggarkan seperlunya agar bisa menulis `/etc/ufw` (sebelumnya `/etc` read-only di bawah `ProtectSystem=full`, jadi aturan baru kemungkinan besar gagal) dan `AF_NETLINK` untuk iptables-nft, ditambah pembatasan yang pasti aman; **belum terverifikasi di host nyata**.
- **Server API 1.5.1: pembatasan penyalahgunaan dan pengerasan respons.** Batas kegagalan autentikasi per alamat klien nyata (10 kegagalan/60 dtk → HTTP 429 + `Retry-After`; hanya kegagalan yang dihitung, jadi lalu lintas sah tidak pernah dibatasi dan penyerang tidak bisa mengunci pemilik), alamat klien dari `CF-Connecting-IP` hanya bila peer TCP adalah loopback, jatah tebakan TOTP (5 salah/5 menit per perangkat; kode benar pun ditolak sampai jendela lewat), pencacah dibatasi memori (4096 kunci), header keamanan di semua jawaban (termasuk stream dan kesalahan parser), banner tanpa versi. **Bug lama diperbaiki:** permintaan HTTP cacat (baris permintaan rusak, URI terlalu panjang, versi HTTP salah) membuat handler crash — klien menerima jawaban kosong dan traceback masuk ke log; kini dijawab JSON bersih. Hanya diuji lewat loopback dengan jam tiruan, bukan lewat Cloudflare nyata.

- **Real-time dari jarak jauh (API server 1.5.0).** Endpoint `GET /api/v1/stream` (SSE lewat HTTPS) hanya memberi sinyal "ada perubahan" (jenis: security/encrypted/actions/windows) tanpa membawa data; aplikasi lalu mengambil data lewat jalur terautentikasi yang sudah ada. Token monitor wajib, pencabutan akses memutus stream paling lama satu heartbeat (15 dtk), ada batas stream per perangkat/global, dan pengamat database bersama berhenti saat tidak ada pendengar. Aplikasi: stream dimulai saat Hubungkan, dihentikan di semua jalur pemutusan, polling jadi 30 dtk hanya selama stream benar-benar tersambung (10 dtk saat mencoba menyambung, 5 dtk bila server lama), dan teks status hanya menyatakan "REAL-TIME AKTIF" saat tersambung. Belum diuji lewat Cloudflare/server nyata; jalankan `scripts/check_connection.py` dari perangkatmu.
- **Cek koneksi langkah demi langkah** (`scripts/check_connection.py`, `chainlog/connection_check.py`): alamat, DNS/TLS, token, feed, stream (mendeteksi proxy yang menahan stream), dan waktu bolak-balik; hanya membaca dan tidak mencetak token.
- Konektor syslog mengenali pola pesan gaya MikroTik RouterOS (`login failure for user X from IP via winbox`, `user X logged in from IP via ssh`) dan mencatat metode (winbox/ssh/api/...). Pola ini ditulis dari bentuk pesan yang didokumentasikan, bukan dari perangkat nyata.

- **Pemindai tiga "pintu".** Pintu 1: berkas tak tepercaya hanya dibaca proses pekerja terpisah (tanpa jaringan, batas CPU/memori, tidak menulis berkas). Pintu 2: karantina dengan database dan folder sendiri. Pintu 3: koneksi server tetap di modul lain. Bila build terbungkus tidak dapat memulai proses terpisah, pemindai berjalan dalam proses yang sama dan **menyatakannya** di layar.
- **Hapus malware dari perangkat.** Ancaman ditampilkan lebih dulu (nama, lokasi asal, SHA-256, batas waktu); pengguna dapat langsung menghapus atau memulihkan (salah deteksi). Tanpa tindakan 15 menit, berkas dihapus otomatis dan **tanpa notifikasi** (hanya tercatat di rantai audit). Hanya kecocokan tanda tangan SHA-256 persis yang boleh dihapus otomatis; temuan heuristik berstatus MENCURIGAKAN dan tidak pernah dihapus otomatis. Hash dicek ulang sebelum hapus; lokasi sistem/folder aplikasi dilindungi; symlink tidak diikuti.
- **Akun terikat perangkat.** ID perangkat berbeda → harus membuat akun baru; perangkat sama → akun yang sama. Opsi "Ingat perangkat ini" (token sekali pakai yang berputar, disimpan sebagai hash, maks 30 hari, batas mutlak 90 hari) agar aplikasi tidak meminta login terus. Tombol **Keluar** mencabutnya.
- **Verifikasi ulang** (kata sandi/PIN, berlaku 5 menit) untuk aksi sensitif: membuat akun, PIN, token admin, kunci E2EE, backup/restore, memulihkan berkas karantina.
- Kata sandi baru 8–128 karakter (sebelumnya 6–12); penguncian login bertahap hingga 1 jam.
- Pemantau dan pendengar dashboard kini dihentikan saat keluar; pemindai dipakai bersama sehingga login ulang tidak menambah proses pekerja.
- **AI phishing diperbaiki.** Model lama (Naive Bayes pada 800 contoh templat, "akurasi 100%") diganti ensemble: Naive Bayes + sinyal teks/tautan (permintaan kata sandi/OTP, domain peniru merek, `.apk`, teks tautan menipu, hosting disalahgunakan, dan sinyal pesan sah) + regresi logistik, dengan pita AMAN / MENCURIGAKAN / PHISHING dan **alasan** pada setiap temuan. Dilatih pada korpus tulisan tangan 212 pesan/29 keluarga; diukur dengan leave-one-group-out dan set skenario baru, dibandingkan dengan model lama (salah-tandai pesan sah pada set tantangan 24% → 0%, recall 70% → 95%, **dengan peringatan bahwa angka itu membengkak**; lihat `docs/AI_MODEL.md`). `.pkl` tidak lagi dikirim. Kelemahan yang diketahui: penipuan BEC tanpa tautan hampir tak terdeteksi; kinerja pada email nyata belum pernah diukur.
- Workflow CI `.github/workflows/build.yml` ditulis ulang (berkas asli tidak ada di ZIP yang diterima).
- **Semua database di perangkat.** Aplikasi tidak lagi mengunggah rantai audit atau arsip ke server: klien sinkronisasi dan arsip menolak mengunggah secara bawaan, UI unggah dan loop sinkron latar dihapus, dan API server menolak endpoint penyimpanan data klien (HTTP 403 `client_data_storage_disabled`) kecuali `KAWAL_API_ACCEPT_CLIENT_DATA=true`. Arsip lama di server dapat ditarik satu arah ke perangkat. Lihat `docs/LOCAL_STORAGE.md`.
- **Enkripsi at-rest** (AES-256-GCM) untuk kolom detail rantai audit dan payload arsip server; terikat per baris, hash berantai tetap dihitung atas teks asli. Kunci: Windows DPAPI (belum diuji di Windows sungguhan) atau berkas 0600 di platform lain. Kunci yang hilang/rusak tidak pernah diganti diam-diam; aplikasi menampilkan halaman "DATA TIDAK BISA DIBUKA" tanpa mengubah data. Data lama dikonversi sekali dengan hash kepala identik, lalu `VACUUM` karena sisa teks lama terbukti tertinggal di berkas setelah konversi. **Tidak** terenkripsi: kolom jenis/aktor/sumber/waktu, database akun dan pemindai, isi karantina, ekspor.
- Backup membawa kunci data di dalam arsip terenkripsi; saat dipulihkan kunci dilindungi ulang untuk perangkat tujuan. `identity.sqlite3` (akun terikat perangkat) kini dikecualikan dari backup dan dilewati saat restore.
- Perbaikan dokumen: `SCANNER_AND_BACKUP.md` keliru menyebut database pemindai ikut di backup (ia ada di subfolder `scanner/` yang tidak dibackup).

## 1.0 build 8 — Navigasi dashboard, pemindai offline, backup terenkripsi

- **Navigasi dashboard ditulis ulang.** Satu badan halaman tetap; klik menu hanya mengganti isinya dan mewarnai ulang tombol (sidebar tidak lagi dibangun ulang di tengah klik). Halaman yang gagal dipasang menampilkan kartu error ber-ID diagnosa. Pola tata letak yang ditolak Flutter dihapus: `expand` pada `Container`/`Row` di dalam induk non-fleksibel dan `Column(expand=True)` di dalam `Row(wrap=True)` pada topbar. Logo berbasis aset diganti ikon agar tidak bergantung path aset. Linter tata letak (`tests/ui_harness.py`) mencegah pola itu kembali. **Belum diverifikasi pada GUI nyata.**
- **Ringkasan status** di dashboard: Website, Koneksi server, Sumber audit, Kesehatan agen, API feed, Event keamanan, Pemindai dipisah dan tidak saling menyimpulkan.
- **Pemindai Keamanan** (paket `detectors/`): hashing SHA-256, Bloom filter, SQLite 4 tabel + indeks, pembedah header email (SPF/DKIM/DMARC dari header), pengekstrak tautan, blacklist offline, praproses teks, klasifier phishing (TF-IDF + Naive Bayes, JSON portabel), antrean tugas latar, pruning riwayat > 30 hari, API loopback opsional.
- **Backup & Restore terenkripsi** (`chainlog/backup.py`): AES-256-GCM berblok, scrypt, verifikasi (uji pemulihan nyata), konfirmasi, salinan pengaman, perlindungan zip-slip/zip-bomb/parameter KDF berbahaya.
- `chainlog/redaction.py`: redaksi rahasia dipusatkan (kini juga menyamarkan `passphrase`).
- Nomor build internal 8 (versi tampil tetap 1.0) di `main.py`, `pyproject.toml`, skrip build, CI, dan installer.
- Tes: dari 243 menjadi 340+ (lihat `reports/Kawal_Trace_1.0_Build8_Verification.txt`); tes kontrak lama yang memeriksa teks implementasi `view_host/page_views` diganti dengan tes perilaku.

## 1.0 build 7 — Fix blank main dashboard

- Fixes the blank grey main panel by mounting only the selected feature page instead of attaching all hidden feature panels at once.
- Gives the active view host and desktop content surface an explicit dark background.
- Keeps the sidebar and all existing feature definitions; navigation swaps the active view instead of hiding/showing every panel.
- Increments native build number to 7 while keeping displayed application version 1.0.
- Verification remains source/contract-level in this environment; native EXE/APK visual rendering is not claimed as tested.

## 1.0 — Build 7 (local-first release hardening)

- Fixes the dashboard construction crash caused by the unavailable `ft.Icons.DATABASE` constant by using the supported `ft.Icons.TABLE_CHART` constant.
- Keeps the login header text-only so packaged builds cannot render a large empty image placeholder.
- Makes older v1 local accounts complete a verified one-time credential rotation to enforce username length 4–10 and password length 6–12 without deleting existing audit/configuration data.
- Shows a visible internal build marker in login/sidebar/diagnostics so stale binaries can be identified.
- Increases native build number to 7 and makes CI Windows/Android build jobs depend on the passing test job.
- Cleans prior native build output before local Windows/APK builds to reduce confusion from stale artifacts.

# Riwayat perubahan Kawal Trace

## Kawal Trace v1.0 — Perbaikan layout adaptif Android/Windows
- Root login dan layar diagnostik diberi viewport dengan ukuran eksplisit, alignment tengah, warna latar aplikasi, dan perhitungan ulang saat ukuran layar/jendela berubah; ini mengatasi kartu login yang terdorong ke kiri karena kolom scroll tidak punya constraint/alignment layar penuh.
- Scrollbar abu-abu persisten disembunyikan pada form login, layar diagnostik, navigasi dashboard, dan area konten utama menggunakan `ScrollMode.HIDDEN`; kemampuan scroll tetap aktif (geser jari di Android, wheel/trackpad di desktop).
- Lebar fallback dibuat aman untuk first frame layar HP sempit; kartu setup/login tetap maksimum 520 px di laptop, sementara pada HP mengikuti viewport dengan margin.
- Halaman diagnostik juga mengikuti viewport dan judulnya diganti menjadi `GAGAL MEMBUKA DASHBOARD`; teks menjelaskan bahwa ini error, bukan proses loading.
- Nomor build internal Android/Windows/CI dinaikkan ke 5, sementara versi yang terlihat tetap `1.0` dan versi paket tetap `1.0.0`.
- Memperbaiki error dashboard yang terlihat di screenshot: `ft.Icons.DATABASE` tidak tersedia dan menyebabkan `AttributeError`; tombol audit database sekarang memakai `ft.Icons.TABLE_CHART`. Tes kontrak memastikan referensi yang salah tidak kembali.
- Menghapus kontrol gambar dari header login yang dirender sebagai blok abu-abu besar pada build lama; login/setup menjadi text-only dan kartu tetap dipusatkan secara responsif.
- Tes source/logic sudah dijalankan. GUI Flet native serta hasil build EXE/APK tidak bisa dikonfirmasi di mesin audit ini karena Flet/Flutter/Android SDK/MSBuild tidak tersedia dan akses jaringan paket mati.

## Kawal Trace v1.0 — Perbaikan alur awal, login, dan tampilan ponsel
- Instalasi baru menampilkan formulir buat akun sebelum autentikasi; proses startup tidak lagi membuat akun tersembunyi sebelum `needs_setup()` dicek.
- Menambah rotasi kredensial lokal aman untuk instalasi lama dengan validasi password saat ini; akun, PIN, dan data lokal dipertahankan.
- Menaikkan nomor build internal Android ke 5 supaya build perbaikan dapat dipasang sebagai update, sambil mempertahankan versi yang terlihat `1.0`.
- Menghapus kredensial admin bersama dan nilai password bawaan. Form pertama kosong dan menyimpan hash PBKDF2 bersalt setelah pengguna membuat akun.
- Database identitas lama tanpa penanda setup versi pribadi sekarang meminta rotasi kredensial dengan verifikasi kata sandi lama; data lokal tidak dihapus. Setup baru menulis penanda versi kredensial.
- Perubahan kredensial tidak ditampilkan pada layar login normal; administrator mengubahnya dari panel akun setelah berhasil masuk. Instalasi lawas tanpa marker setup tetap menjalani rotasi yang diverifikasi.
- Panel error dashboard menempatkan tahap, tipe exception, dan ringkasan error di atas ID acak agar penyebab lebih mudah terlihat; gaya panel dibuat lebih ringkas.
- Pembuatan admin pertama kini memakai transaksi SQLite `BEGIN IMMEDIATE` untuk mencegah dua proses setup bersamaan membuat dua admin pertama.
- Login menggunakan area scroll yang eksplisit, lebar kartu adaptif, padding ponsel, dan penanganan ukuran ulang; minimum window desktop tidak diterapkan pada Android/iOS.
- Lebar tombol login, pilihan arsip, pilihan tanggal, dan tombol ekspor menyesuaikan viewport dan dihitung ulang pada perubahan ukuran/orientasi; halaman diagnosa error juga dapat digulir dan mengikuti lebar HP.
- Ringkasan exception ditampilkan dengan penyamaran pola kredensial; traceback yang dicatat juga disaring dari pola password/token umum.
- PIN perangkat diringkas di balik tombol `Masuk dengan PIN perangkat`; biometrik baru muncul bila platform mendukung, hardware dapat memeriksa biometrik, dan metode biometrik telah terdaftar.
- Navigasi dashboard pada ponsel menggunakan pemilih menu lebar penuh, bukan sidebar ikon yang menyempitkan area konten.
- Diagnostik dashboard kini mencatat tahap startup beserta traceback sehingga ID diagnosa bisa dipasangkan dengan penyebab sebenarnya.
- Dashboard tidak lagi memaksakan minimum ukuran jendela desktop pada Android/iOS/Web; jalur ini sebelumnya berpotensi mengganggu startup native tertentu. Lebar dropdown arsip dan tombol ekspor mengikuti viewport saat resize.
- GUI Flet, APK Android, dan EXE Windows belum dapat diuji langsung di lingkungan penyusunan ini; hanya tes source/logic dan smoke test memakai Flet stub yang tersedia di paket verifikasi.

## Kawal Trace v2.5.1 (historis — tidak dipakai sebagai rilis sekarang)
- Rilis historis ini memiliki bootstrap kredensial bersama. Implementasi tersebut telah digantikan oleh v1.0 dan tidak boleh dijadikan paket rilis baru.
- Source v1.0 menghapus password bawaan, mengharuskan setup kredensial pribadi pada instalasi bersih, dan meminta rotasi kredensial yang diverifikasi untuk database identitas lama yang belum memiliki penanda setup.
- Halaman diagnostik v1.0 menampilkan jenis/tahap/ringkasan exception serta menyimpan traceback yang disamarkan; uji GUI native masih harus dilakukan pada perangkat target.

## Kawal Trace v2.5.0 — Enkripsi website, DNS pinning, dan konektor audit
- Database pemantauan website sekarang disimpan sebagai image SQLite terenkripsi AES-256-GCM; kunci diambil dari Secure Storage OS dan tidak ada fallback plaintext. File lama dimigrasikan saat dibuka/disimpan.
- Perbaikan anti-DNS-rebinding: resolusi DNS divalidasi semua IP, koneksi socket dipin ke IP yang diperiksa, TLS tetap memvalidasi hostname, dan setiap redirect divalidasi ulang.
- Menambahkan panel konektor read-only SSH, MySQL/MariaDB/SQL Server audit table/view, serta penerima syslog TCP dengan mTLS wajib pada listener non-loopback.
- Isi private key SSH dan password database disimpan melalui Secure Storage OS (file key sumber tidak dihapus otomatis); query database dibatasi ke SELECT berparameter; host key SSH yang belum dipercaya ditolak.
- Menambahkan pipeline ingestion idempoten ke audit hash-chain untuk event konektor, beserta tes unit/integrasi lokal.
- Verifikasi otomasi tidak dianggap sebagai pengganti pengujian terhadap server/DB produksi, mTLS antarmesin, Secure Storage pada perangkat, atau build Windows/Android.

## Kawal Trace v2.4.2 — Website URL-only monitor (superseded by v2.5.0)
- Menambahkan halaman **Pantau Website** untuk menyimpan target HTTP/HTTPS dan melakukan pemeriksaan tanpa token API.
- Memisahkan target serta riwayat pemeriksaan website ke SQLite lokal tersendiri; tidak mencampur status HTTP dengan security-event log.
- Menambahkan validasi URL, gate eksplisit untuk target internal, blokir alamat metadata/link-local, validasi redirect, batas redirect dan timeout, verifikasi sertifikat, serta interval polling minimum.
- Pemeriksaan jaringan hanya berjalan setelah operator menguji target atau menekan Mulai pemantauan; startup hanya membaca database lokal.
- Menambahkan tes untuk keberhasilan HTTP lokal, redirect, HTTP 404, DNS failure, URL berbahaya, metadata destination, dan persistensi lokal.
- Batas terbuka: database belum dienkripsi dengan SQLCipher, DNS belum di-pin ke koneksi, timing TCP/TLS belum dipisah, dan build GUI native belum diuji di Windows/Android.

## Antarmuka baru (v2.4.1)
- Tampilan diganti: menu kiri + area konten; semua fitur lama dipertahankan.
- Logo dan ikon baru; palet hijau-teal gelap.
- Judul panel dirapikan; installer Windows (Setup.exe) dan APK dibangun otomatis lewat GitHub Actions.

---

# Kawal Trace v2.4.1 — Android packaging preparation

- Branding aplikasi dan direktori penyimpanan baru menggunakan Kawal Trace.
- Identitas paket Android disiapkan sebagai `id.kawaltrace.app`.
- Konfigurasi build APK mengecualikan dokumentasi, laporan pengujian, tes, agen desktop/server, dan installer desktop yang tidak dibutuhkan pada runtime Android. Sumber fitur tetap dipertahankan dalam arsip proyek.
- Variabel lingkungan folder data: `KAWAL_TRACE_DATA_DIR`.
- Nama header, payload kriptografi, variabel lingkungan, dan kunci penyimpanan memakai merek Kawal Trace.
- APK belum dapat dibangun pada lingkungan audit ini karena Flet CLI/Flutter/Android SDK tidak tersedia dan akses jaringan untuk mengunduh dependensi tidak tersedia. Gunakan `BUILD_ANDROID_APK.cmd` pada mesin Windows setelah toolchain siap.

---

# Kawal Trace v2.4.0 — Integration Wizard

- Added a beginner-friendly Integration Wizard with three paths: existing security-log API, Kawal Trace API, or host agent/collector needed.
- Added explicit **Find REST endpoint** workflow: bounded GET-only probes on a small common-path list, no redirects, TLS verification, 4 MiB response cap, and inferred JSON event path/field mapping when a usable sample exists.
- Auto-detection refuses to claim compatibility when it cannot find a log array or a usable timestamp; empty-feed results are reported separately from working feed results.
- Simplified the default REST API form by collapsing mapping/pagination options into advanced settings.
- Separated API, feed, agent-heartbeat, detection, and notification status in the UI so a green API connection cannot imply all features work.
- Added normalization for Unix timestamp seconds/milliseconds for the generic REST/protocol JSON adapters.
- Added unit/integration tests for field inference, bounded endpoint detection, redirects, missing auth, and timestamp conversion.
- Full UI/native runtime still needs device verification; Flet is not installed in the code-audit container.

---

# Kawal Trace v2.3.1 — E2EE Backup Export Fix

## Perbaikan
- Tombol `Ekspor backup terenkripsi` kini memvalidasi frasa sandi minimal 14 karakter dan memberi status yang terlihat.
- Backup terenkripsi ditampilkan di kolom JSON sebelum dialog simpan dibuka.
- Aplikasi menawarkan simpan/unduh file `.json` melalui FilePicker, menggunakan bytes yang terenkripsi.
- Jika dialog dibatalkan atau gagal, UI menyatakan dengan jelas bahwa file belum tersimpan dan JSON masih tersedia untuk disalin manual.
- Penanganan error umum ditambahkan agar kegagalan Secure Storage atau FilePicker tidak terlihat seperti tombol tidak melakukan apa-apa.
- Format backup dan algoritme kriptografi tidak diubah; private key tetap berada di Secure Storage dan hanya backup berpelindung frasa sandi yang diekspor.

## Batas pengujian
- Pengujian unit enkripsi/backup dapat dijalankan otomatis.
- Dialog FilePicker dan hasil unduhan perlu diuji pada build Windows/Android yang terpasang; uji otomatis pada container tidak membuktikan perilaku native.

---

# Kawal Trace v2.3.0

## Added
- Optional local device PIN unlock (8–12 digits), PBKDF2 hash, and persistent lockout in local SQLite. Password login remains recovery path.
- Native local biometric button via `flet-local-auth` for supported Windows/Android native builds; not a Google sign-in. Falls back to PIN/password if unsupported.
- Read-only OpenZiti/WireGuard tool presence helper and setup guidance; no privileged tunnel commands are executed.
- Offline .eml email phishing review: SPF/DKIM/DMARC result headers, From/Reply-To mismatch, suspicious URLs, urgency language and bounded input handling.
- Optional manual PhishTank URL check. Only the selected URL is sent; the complete email is never uploaded. API key is not persisted by this UI.
- Optional local SpamAssassin CLI invocation with subprocess timeout, size bounds and no shell. Does not delete/quarantine email.
- Micro-segmentation policy preview for management/web/application/data zones, including CIDR overlap/private-range checks and service-specific allow rules. Preview only; firewall is not changed.
- Indonesian advanced-defense guide and 2,000-case local defensive simulation matrix.

## Security notes
- Biometric support requires a native build with `flet-local-auth`; the GUI was not launched in this artifact environment, so test on Windows and Android devices before production use.
- OpenZiti/WireGuard are not installed/configured automatically. "Dark IP" is not a guarantee of invisibility.
- Phishing scoring is heuristic, not a conclusive verdict. No email is automatically deleted.
- Firewall policy is never automatically applied by the new UI.
- PhishTank is an external lookup; only an explicitly selected URL is submitted over HTTPS. The user's API key is not saved.
- This release is a defensive prototype, not independently security-certified.

---

# Kawal Trace v2.2.0

## Perubahan utama

- Merapikan pengaturan server dan telemetri di bawah kelompok **Integrasi & pemantauan server** dengan panduan ringkas Bahasa Indonesia.
- Menambahkan arsip event keamanan persisten di SQLite lokal, deduplikasi event, dan pengelompokan berdasarkan tanggal UTC.
- Menambahkan tiga mode penyimpanan: perangkat saja, server milik sendiri saja, dan server + salinan perangkat. Mode server-only menggunakan buffer sampai server mengakui upload; setelah ack event payload lokal dihapus, sedangkan tanda terima upload untuk deduplikasi dipertahankan. Kegagalan koneksi tidak menghapus buffer.
- Mode server-only menampilkan tanggal/pratinjau dari API pemilik dan mengekspor event langsung dari API. Unduh arsip dari server ke perangkat adalah tindakan eksplisit untuk membuat salinan lokal.
- Menambahkan endpoint `GET /api/v1/archive/events/summary` dan memperbarui API optional ke v1.4.0. Upgrade server tetap mempertahankan `api.env` dan database lewat skrip upgrade yang tersedia.
- Menambahkan ekspor laporan PDF tanpa dependensi tambahan, CSV yang dapat dibuka dengan spreadsheet, dan JSON untuk arsip/analisis; pengguna dapat memilih tanggal atau semua tanggal.
- Timestamp log distandardisasi ke UTC dan dashboard menampilkan waktu lokal perangkat untuk pembacaan operator. Aplikasi mengandalkan sinkronisasi waktu OS; tidak mengubah jam sistem.
- Memperluas tes untuk arsip harian, ringkasan tanggal server, remote round-trip, dan pembersihan payload lokal setelah upload diakui.

## Catatan

- Arsip ke server hanya tersedia untuk API Kawal Trace yang dikelola sendiri; konektor REST pihak ketiga tetap read-only.
- Bila API sedang tak tersedia dalam mode server-only, event yang belum mendapat pengakuan tetap berada di buffer lokal agar tidak hilang.
- UI native Windows/Android dan notifikasi suara masih harus diuji di build perangkat sesungguhnya.

---

# Kawal Trace v2.1.0 — protocol adapters and defensive validation

- Added a protocol adapter layer for REST/JSON with page/offset/cursor pagination and bounded extra query parameters.
- Added OAuth2 client-credentials token acquisition/caching and renewal; client secret remains in OS Secure Storage rather than the JSON profile.
- Added GraphQL query-only support; mutation/subscription requests and oversized query/variables are rejected before network access.
- Added SOAP/XML read-only adapter with `defusedxml`, DTD/entity rejection, request/response limits, and allowlisted read-operation name prefixes.
- Added a persistent WebSocket JSON reader for WSS feeds; it keeps the connection across polls and reconnects after disconnects.
- Added 1,000-scenario loopback API protocol matrix and 1,000-scenario defensive input/attack matrix. These do not contact public/third-party APIs.
- Fixed the UI connection/test actions to invoke the selected read-only protocol adapter instead of always calling the legacy REST connector; OAuth2 secrets are loaded from OS Secure Storage.
- Added regression checks for server profile persistence, native-build metadata, alert assets and adapter use from connect/test/poll actions.
- Expanded tests for OAuth, pagination, GraphQL, SOAP, WebSocket persistence, unsafe schemes and secret-in-configuration rejection.
- Native sound/notification code paths are retained, including Windows sound fallback. Real EXE/APK notification behavior remains unverified until built and tested on devices.
- Local SQLite data is still not encrypted at rest by the app itself. Use OS/device encryption and access controls.

### Hotfix kompatibilitas Flet 1.0.4
- Mengganti `ft.ImageFit.CONTAIN` menjadi `ft.BoxFit.CONTAIN` pada logo login dan header dashboard agar sesuai dengan API `Image.fit` pada Flet 1.0.4.
- Pemeriksaan sintaks berhasil dan suite tes otomatis: 139 passed.

---

# Kawal Trace v2.0.1 — hardening update

## Fixes
- Generic REST now uses its configured 1–30 second timeout instead of a hard-coded 8-second timeout.
- Security feed clients stream JSON responses and reject content exceeding 4 MiB before JSON decoding.
- E2EE feed request timeout values are validated.
- On a profile's first read, recent events (within five minutes) can trigger alert evaluation; older history is baselined to avoid a storm of old notifications.
- Local password authentication now persists failed-attempt counts: five failures in a five-minute window trigger a 60-second lockout, including across app restarts. Successful authentication clears the counter.
- App/build product metadata and network user-agent branding use Kawal Trace while retaining the existing Android application ID and internal data directory for compatibility.
- Documented that SQLite log payloads are not encrypted at rest in this version; device encryption/OS protections are required.

## Verification
- 120 unit/integration tests passed, including `optional-server-api/tests`.
- 1,000/1,000 local API simulation scenarios passed in about 15 seconds; the simulator bound only to `127.0.0.1` and contacted no outside service.
- Native Flet GUI, Windows EXE, Android APK, operating-system sound/notification delivery, and any real production endpoint were not tested in this environment.

---

# Kawal-Trace v2.0.0 — Public local-first client update

## Perubahan terarah dari v1.9.4
- Mempertahankan source/dashboard/modul sebelumnya dan menerapkan update pada blok yang dituju, bukan menulis ulang seluruh aplikasi.
- Menghapus duplikasi UI: response-actions list Linux yang kedua dan tombol export feed yang terulang di subsection Windows.
- Ambang default deteksi `AUTH_FAILURE_BURST` diubah dari 5 menjadi 2 kegagalan autentikasi dalam 300 detik untuk host/IP yang sama.
- Menambahkan alarm suara lokal untuk event baru HIGH/CRITICAL saat aplikasi terbuka, dengan tombol uji suara. Menggunakan `flet-audio`; Windows memiliki fallback `winsound`.
- Memperluas Generic REST read-only untuk Bearer, X-API-Key, custom header, dan tanpa auth jika endpoint publik. Header name divalidasi untuk mencegah CR/LF injection.
- Tetap local-first: tidak menambahkan server pusat pembuat aplikasi atau telemetry analytics; data hanya dikirim ke profil server yang dipilih saat koneksi/sinkronisasi, sementara log lokal dipertahankan jika upload gagal.
- Dokumentasi privasi dan batas fitur publik ditambahkan.

## Hal yang belum diklaim selesai
- Generic REST tetap read-only; tidak bisa melakukan upload atau respons terhadap API yang belum menyediakan kontrak/izin itu.
- Alert berbunyi saat aplikasi terbuka menerima event baru. Push/background ketika app ditutup belum dikonfigurasi.
- Device MAC dan lokasi individu tidak dapat diinferensi dari koneksi internet; data perangkat/GeoIP bergantung pada agent dan sumber yang sah.
- EXE/APK belum dibangun dan dites pada perangkat pengguna dari paket ini.

---

# Kawal-Trace v1.9.2 — member enrollment and persistent identity

- Added separate one-time owner admin token setup that does not rotate member/agent tokens.
- Added pending enrollment, owner approval, automatic scoped-token delivery over HTTPS, and server-side revocation.
- Device IDs stay stable across app restarts and newly added server profiles; legacy profile IDs are preserved.
- Manual token fields are hidden by default; automatic enrollment is the normal workflow.
- API v1.3.0 adds SQLite member accounts and admin-only member management routes.

---

# Kawal-Trace v1.9.1 — perubahan antarmuka

- Tombol **Simpan Profil**, **Uji Koneksi**, **Hubungkan**, **Putuskan**, dan status koneksi dipindahkan tepat di bawah kolom Device ID dan token.
- Pengaturan Generic REST/JSON hanya terlihat jika jenis konektor **Generic REST/JSON · feed read-only** dipilih, sehingga setup Kawal-Trace API lebih ringkas.
- Petunjuk token menjelaskan bahwa salin nilai token saja, tanpa label atau titik dua. Token minimal 24 karakter; token 80 karakter atau lebih tetap valid jika tidak berisi spasi.
- Pesan validasi membedakan token terlalu pendek dari token yang mengandung spasi/baris baru, tanpa menampilkan nilai token.

## Validasi

- `python3 -m py_compile main.py`: lulus.
- `python3 -m pytest -q`: 95 tes lulus.
- UI Flet interaktif dan pembuatan EXE/APK belum dijalankan dalam lingkungan pembuat paket.


## 1.0 — Login and dashboard regression fix

- Removed the image-backed login header that appeared as an oversized grey block in packaged Windows screenshots; retained the app name and version in a compact header.
- Replaced nonexistent `ft.Icons.DATABASE` with the already-used, supported `ft.Icons.TABLE_CHART`. The former caused `AttributeError: DATABASE` during dashboard construction after a successful login.
- New usernames are validated as 4–10 characters and new passwords as 6–12 characters in both UI and authentication registry. Legacy credentials remain accepted for login/migration so existing users are not locked out by the new input limits.
- Moved admin credential changes to the signed-in account settings; fresh installs continue to show account setup first. PIN login remains hidden until a device PIN is enrolled.


- Follow-up from the supplied screenshots: removed the image-backed login header (source of the oversized blank block), moved administrator credential changes into the signed-in account panel, and stopped exposing the local database path in the normal UI.
- Fixed the confirmed `AttributeError: DATABASE` at dashboard construction by using `ft.Icons.TABLE_CHART`, which is already used by the project for CSV/table actions.
- Enforced username 4–10 and new password 6–12 character boundaries at both UI and authentication layer; legacy login remains compatible until credentials are rotated.
- Increased internal native build number to 5 while keeping the visible app version 1.0.
