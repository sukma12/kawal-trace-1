# Pemindai keamanan offline dan Backup & Restore (build 8)

Dokumen ini menjelaskan apa yang **benar-benar dikerjakan kode**, bagaimana cara memakainya, dan batasnya. Status pengujian ada di
`reports/Kawal_Trace_1.0_Build8_Verification.txt`.

## 1. Pemindai keamanan (`detectors/`, menu **Pemindai Keamanan**)

Seluruh pemeriksaan berjalan di perangkat. Tidak ada file/teks yang dikirim ke luar, tautan tidak pernah dibuka, file yang dipindai
tidak pernah dijalankan.

| Modul | Fungsi |
|---|---|
| `hashing.py` | SHA-256 (MD5 hanya informasi) dengan streaming 1 MiB; menolak path hilang, folder, perangkat/pipa, dan file > 512 MiB. |
| `bloom_filter.py` | Bloom filter (default galat 0,1%) dengan checksum dan penulisan atomik; tidak pernah false negative. |
| `signature_matcher.py` | SHA-256 → Bloom → konfirmasi SQLite. Filter yang hilang/rusak/kedaluwarsa dibangun ulang dari SQLite; selama belum ada, pencarian langsung ke SQLite. |
| `scanner_db.py` | SQLite 4 tabel sesuai ketentuan (`malware_signatures`, `phishing_urls`, `scan_history`, `scan_details`) + `schema_migrations`. Semua query berparameter; ada indeks pada `hash_sha256` dan `domain_or_url`; `ON DELETE CASCADE`; pruning > 30 hari. |
| `email_parser.py` | Membedah `.eml` dengan `email` bawaan: header, MIME, lampiran (di-hash di memori), hasil SPF/DKIM/DMARC dari header penerima, ketidaksejajaran From/Reply-To/Return-Path/DKIM, pemalsuan nama tampilan, lampiran berisiko (ekstensi ganda, makro, karakter pembalik arah). |
| `link_extractor.py` | Mengambil URL dari teks dan HTML (a/area/form/iframe), mendeteksi teks tautan yang menampilkan situs berbeda dari tujuan sebenarnya. Memakai BeautifulSoup bila terpasang, selain itu parser bawaan. |
| `url_checker.py` | Pencocokan offline ke `phishing_urls` (domain, subdomain, atau URL persis) + indikator heuristik (informasional). |
| `text_preprocess.py` | Menghapus HTML/skrip, huruf kecil, menjaga kata dari URL, membuang tanda baca. |
| `phishing_classifier.py`, `phishing_ensemble.py` | Ensemble TF-IDF + Naive Bayes + sinyal teks/tautan + regresi logistik. Runtime memakai `ml_models/phishing_model.json` (tanpa scikit-learn, tanpa eksekusi kode, hash dicek ke `MODEL_MANIFEST.json`). `.pkl` tidak lagi dikirim; bila dibuat developer (`--with-pickle`) hanya dimuat bila diminta eksplisit **dan** hash-nya cocok. |
| `task_queue.py` | Antrean kerja berlatar (terbatas, dapat dibatalkan, galat dicatat pada job) agar UI tidak macet. |
| `pipeline.py` | Alur diagram ketentuan; menyimpan riwayat dan detail temuan. |
| `local_api.py` | **Opsional**, Flask khusus loopback + token bearer acak, tanpa path server (hanya isi dikirim lewat body). Tidak dijalankan aplikasi dan tidak ikut APK. |

### Aturan status

`MALWARE` (hash lampiran/file cocok signature) > `PHISHING` (URL ada di blacklist **atau** skor ensemble AI di pita PHISHING; pita `MENCURIGAKAN` hanya memberi tanda "periksa manual") > `SAFE`.
Temuan lain (header SPF/DKIM/DMARC, tautan mencurigakan, lampiran berisiko) ditampilkan sebagai temuan kuning tetapi **tidak mengubah status sendirian**.
Bila model AI tidak tersedia atau teks tidak mengandung istilah yang dikenal model, hal itu ditulis sebagai catatan; hasil tidak berpura-pura lolos uji AI.

### Data yang harus Anda sediakan

Aplikasi **tidak membawa database malware sungguhan**. Isi awal hanya satu signature uji EICAR (file uji standar industri, bukan malware) dan satu
domain uji `phishing-test.invalid` agar alur dapat dicoba. Untuk perlindungan nyata, impor daftar dari sumber tepercaya pilihan Anda lewat tombol di halaman:

* Daftar hash: satu baris per signature, `sha256[,nama[,Low|Medium|High]]`, baris berawalan `#` diabaikan.
* Daftar domain/URL: satu baris per entri, `domain_atau_url[,Phishing|Scam]`.

Baris yang tidak valid ditolak dan dihitung. Hanya administrator lokal yang dapat mengimpor.

### Cara mencoba tanpa malware sungguhan

1. **Tanpa EICAR** (disarankan jika antivirus PC Anda agresif; Windows Defender akan menghapus file EICAR): buat file teks biasa `contoh.txt`, hitung SHA-256-nya
   (`certutil -hashfile contoh.txt SHA256` di Windows), simpan satu baris `HASH,Contoh.Uji,Low` ke `daftar.txt`, impor lewat **Impor daftar hash**, lalu pindai `contoh.txt` → status **MALWARE** (karena Anda sendiri yang mendaftarkannya).
2. **Dengan EICAR**: string uji standar 68 karakter dari eicar.org disimpan sebagai file; signature-nya sudah ada di database awal.
3. **Phishing**: tempel `http://phishing-test.invalid/login` pada kotak teks → **PHISHING** (domain uji bawaan). Tempel kalimat seperti "Akun Anda ditangguhkan, segera verifikasi kata sandi" untuk melihat skor AI.

### Model AI: apa adanya

Model berupa **ensemble** (Naive Bayes + sinyal teks/tautan + regresi logistik) dengan tiga pita: AMAN, MENCURIGAKAN, PHISHING. Ia dilatih pada korpus **tulisan tangan** (bukan email nyata) dan
diukur dengan *leave-one-group-out* serta set skenario baru; hasilnya jauh dari 100% dan angka yang bagus pada set tantangan hampir pasti membengkak. Penjelasan lengkap, tabel per keluarga penipuan,
kelemahan (mis. penipuan BEC tanpa tautan), dan cara melatih ulang ada di [`AI_MODEL.md`](AI_MODEL.md). Model lama (templat sintetis, "100%") sudah diganti.

## 2. Backup & Restore (`chainlog/backup.py`, menu **Backup & Restore**)

* **Hanya administrator lokal.** Dibuat hanya saat Anda menekan tombol; lokasi simpan dipilih Anda; tidak ada unggahan otomatis.
* Format `.ktbak`: AES-256-GCM per blok 1 MiB, kunci dari frasa sandi (min. 14 karakter) lewat scrypt (N=2^15). Setiap blok mengikat nomor urut dan penanda "blok terakhir" sehingga pemotongan, penukaran urutan, dan pengubahan terdeteksi.
* Isi: `*.sqlite3`, `*.json`, `*.bloom` **yang berada langsung di folder data** (database audit, arsip, riwayat website, pengaturan) ditambah kunci enkripsi data di dalam arsip terenkripsi. SQLite disalin lewat API backup SQLite (konsisten walau aplikasi terbuka). Log, laporan, dan file `-wal/-shm` tidak ikut.
* **Tidak ikut:** `identity.sqlite3` (akun terikat ke perangkat, jadi tidak berpindah; backup lama yang memuatnya tetap bisa dipulihkan, berkas akunnya dilewati dan dilaporkan) serta isi subfolder `scanner/` (tanda tangan, riwayat, dan karantina berisi berkas berbahaya). Tanda tangan yang Anda tambahkan sendiri di pemindai tidak dibackup oleh fitur ini.
* **Tidak termasuk**: rahasia di Secure Storage OS (token API, kunci database website, kunci E2EE). Pada perangkat baru, rahasia itu harus dimasukkan ulang/dipulihkan terpisah; database website terenkripsi tidak terbaca tanpa kuncinya.
* **Verifikasi backup** = uji pemulihan sungguhan tanpa menyentuh data aktif: dekripsi, checksum manifest per file, `PRAGMA integrity_check`, dan verifikasi ulang rantai hash audit.
* **Pulihkan**: wajib mencentang konfirmasi; backup dengan rantai audit rusak ditolak; salinan pengaman data lama dibuat di `restore-safety-<waktu>/`; nama file di arsip dibatasi (anti zip-slip, anti zip-bomb); file jurnal `-wal/-shm` lama dihapus; file diganti atomik. Tutup dan buka ulang aplikasi setelah pemulihan.

## 3. Navigasi dashboard dan ringkasan status

* Satu badan halaman tetap (`page_body`) berisi halaman aktif; klik menu hanya mengganti isinya dan mewarnai ulang tombol (sidebar tidak dibangun ulang saat diklik).
* Halaman yang gagal dipasang menampilkan kartu error dengan ID diagnosa (tercatat, rahasia disamarkan di `startup-errors.log`) alih-alih permukaan kosong.
* Struktur tata letak tidak lagi memakai pola yang ditolak Flutter: `expand` pada induk non-fleksibel dan anak fleksibel di dalam `Row(wrap=True)`. Pola itu diperiksa otomatis oleh linter di `tests/ui_harness.py`.
* Dashboard menampilkan **Status sistem** dengan baris terpisah: Website, Koneksi server, Sumber audit, Kesehatan agen, API feed, Event keamanan, Pemindai keamanan.

**Penting:** semua verifikasi di atas dilakukan pada tiruan Flet tanpa piksel. Hanya menjalankan EXE/APK sungguhan yang dapat membuktikan area utama tidak lagi abu-abu.
