# Penyimpanan data: semua di perangkat Anda

Dokumen ini menjelaskan apa yang sebenarnya dilakukan kode (`chainlog/at_rest.py`, `chainlog/core.py`,
`chainlog/server_archive.py`, `chainlog/backup.py`, `chainlog/storage_policy.py`) dan batasnya. Tidak ada klaim "tidak bisa dibobol".

## 1. Aturan: tidak ada data klien yang diunggah

Kawal Trace tidak mengirim rantai audit, arsip log, hasil pemindaian, atau akun Anda ke server mana pun.

* Klien sinkronisasi audit (`SyncClient`) dan klien arsip (`ServerArchiveRemoteClient`) **menolak mengunggah secara bawaan**
  (`allow_remote_storage=False`; galat `RemoteStorageDisabledError` sebelum ada koneksi dibuka). Dashboard tidak lagi memiliki tombol atau
  loop latar yang mengunggah.
* API server opsional menolak endpoint penyimpanan data klien dengan HTTP 403 `client_data_storage_disabled`, kecuali operator server
  sengaja menyetel `KAWAL_API_ACCEPT_CLIENT_DATA=true` (untuk melayani aplikasi versi lama atau menjalankan tes protokol).
  Event keamanan dari server yang dipantau (agen Linux/Windows) tidak terpengaruh.
* Arsip lama yang pernah dikirim ke server oleh versi sebelumnya dapat ditarik **satu arah** ke perangkat lewat tombol
  "Ambil arsip lama dari server ke perangkat" (hanya tampil bila arsip lama terdeteksi).

Yang tetap memakai jaringan: Anda **membaca** event dari server yang Anda pantau, dan koneksi yang Anda pilih sendiri (profil server,
konektor, pemeriksaan website). Itu pengambilan data masuk, bukan pengunggahan data Anda.

## 2. Peta data di perangkat

| Berkas | Isi | Terenkripsi? |
|---|---|---|
| `chainlog.sqlite3` | Rantai audit | **Hanya kolom `details`** (AES-256-GCM). Jenis event, aktor, sumber, waktu, dan hash tetap terbaca. |
| `server-event-archive.sqlite3` | Arsip event server | **Hanya kolom payload**. ID profil, ID event, dan tanggal tetap terbaca. |
| `identity.sqlite3` | Akun, hash PBKDF2, hash token sesi | Tidak (hanya hash berasin; tanpa kata sandi asli). |
| `scanner/…` | Tanda tangan dan riwayat pemindai | Tidak (hash, domain, hasil; tidak pernah isi file). |
| `…/vault/` karantina | Berkas berbahaya yang dipindah | **Tidak.** Dipindah apa adanya, mode 0600, tanpa hak eksekusi. |
| `data-key.bin` / `data-key.dpapi` | Kunci data 32 byte | Lihat bagian 3. |
| Laporan ekspor (PDF/CSV/JSON) | Salinan yang Anda minta | Tidak, sengaja: Anda meminta berkas yang bisa dibaca. |
| Backup `.ktbak` | Salinan database + kunci | Ya, dengan kata sandi backup (scrypt + AES-256-GCM). |

Setiap nilai terenkripsi terikat ke barisnya (data tambahan AES-GCM: `audit|{seq}` atau `archive|{profil}|{event}`), jadi
ciphertext tidak bisa dipindah ke baris lain. Hash berantai dihitung atas teks asli, sehingga verifikasi rantai tidak berubah, dan
baris yang diedit langsung di berkas gagal dibuka.

## 3. Di mana kunci berada, dan apa artinya

* **Windows:** kunci dibungkus Windows DPAPI (lingkup akun pengguna) dan disimpan di `data-key.dpapi`. Folder data yang disalin ke
  komputer atau akun lain tidak bisa dibuka di sana. *Kode DPAPI belum pernah dijalankan pada Windows sungguhan*: tes memakai
  pelindung tiruan untuk logika di sekitarnya, bukan untuk panggilan `CryptProtectData` itu sendiri.
* **Android / Linux / macOS:** tidak ada penyimpanan kunci OS yang dapat dijangkau dari lapisan ini, sehingga kunci berupa berkas acak
  `data-key.bin` (mode 0600) di samping database. Ini melindungi dari **salinan database yang bocor sendirian** (salinan sebagian,
  folder sinkronisasi yang melewatkan kunci), **bukan** dari orang yang dapat membaca seluruh folder aplikasi. Untuk itu yang
  melindungi adalah sandbox aplikasi, kunci layar, dan enkripsi disk OS.
* Berkas kunci yang ada tetapi rusak atau terpotong adalah **galat**. Kunci baru tidak pernah dibuat diam-diam, karena itu membuat seluruh
  data lama yatim.

## 4. Bila kunci tidak cocok dengan data

Aplikasi menampilkan halaman **"DATA TIDAK BISA DIBUKA"** dengan alasan dan kode diagnosa, tanpa mengubah atau menghapus apa pun
dan tanpa jalan masuk ke akun. Pemulihan:

1. Kembalikan `data-key.bin` / `data-key.dpapi` ke folder data bila Anda memindahkannya.
2. Atau pulihkan dari backup `.ktbak` perangkat asal (kunci ikut di dalamnya) ke folder data yang bersih.
3. Di Windows, data yang disalin ke komputer/akun lain hanya dapat dipulihkan lewat backup.

Jika kunci hilang tanpa backup, data terenkripsi tidak dapat dipulihkan oleh siapa pun, termasuk pengembang. Itulah harga enkripsi:
buat backup dan simpan kata sandinya.

## 5. Data dari versi lama

Saat dibuka pertama kali, baris lama (teks biasa) dikonversi dalam satu transaksi. Rantai harus valid sebelum dan sesudah dengan
**hash kepala identik**, kalau tidak, konversi dibatalkan dan data dibiarkan apa adanya. Rantai yang sudah rusak tidak disentuh.

Menulis ulang baris tidak menghapus byte lama: SQLite meninggalkannya di ruang kosong halaman (terukur pada kode ini; sisa IP lama masih
ada di berkas setelah konversi). Karena itu konversi diikuti `VACUUM` dan pengosongan WAL. Bila pembersihan gagal (mis. disk penuh), data
tetap terenkripsi dan kegagalan **dicatat** di rantai audit (arsip: `scrub_warning`), bukan disembunyikan.

Batas: pembersihan hanya berlaku untuk berkas database. Salinan yang dibuat sebelum konversi (backup lama, folder `restore-safety-*`,
snapshot, blok lama di penyimpanan flash) berada di luar jangkauan aplikasi.

## 6. Pindah perangkat

Gunakan Backup & Restore. Backup membawa kunci di dalam arsip yang dienkripsi kata sandi; saat dipulihkan kunci dilindungi ulang untuk
perangkat tujuan (di Windows dibungkus DPAPI milik akun tujuan). Kunci lama dan database yang diganti disimpan di folder
`restore-safety-*`. **Akun tidak ikut berpindah**: akun terikat ke ID perangkat (lihat `DEVICE_ACCOUNTS.md`), jadi `identity.sqlite3`
dikecualikan dari backup dan dilewati saat memulihkan, agar akun yang baru Anda buat di perangkat tujuan tidak tertimpa. Subfolder `scanner/`
(tanda tangan, riwayat, karantina) juga tidak dibackup.

## 7. Belum diverifikasi

* DPAPI pada Windows sungguhan; penyimpanan berkas kunci pada sandbox Android; perilaku GUI. Semua tes berjalan di Linux dengan Flet palsu.
* Enkripsi isi karantina, database pemindai, dan database akun tidak dilakukan.
