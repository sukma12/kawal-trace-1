# Akun per perangkat, "ingat perangkat", dan verifikasi ulang

Dokumen ini menjelaskan apa yang sebenarnya dilakukan kode (`chainlog/device_identity.py`, `chainlog/auth.py`,
`main.py`) dan batasnya. Tidak ada klaim "tidak bisa dibobol".

## 1. ID perangkat

ID perangkat = `HMAC-SHA256(rahasia_instalasi, machine_id)`.

* `rahasia_instalasi`: 32 byte acak, dibuat saat pertama dijalankan, disimpan di folder data aplikasi (mode 0600 bila OS mendukung).
* `machine_id`: pengenal dari OS bila bisa dibaca (Windows `MachineGuid`, Linux `/etc/machine-id`); kosong di platform yang tidak memberikannya (umumnya sandbox Android).
* `machine_id` mentah tidak pernah disimpan atau dikirim; hanya hasil HMAC yang dipakai.

Akibatnya:

| Situasi | Hasil |
|---|---|
| Perangkat yang sama, aplikasi dibuka lagi | ID sama → akun yang sama. |
| Folder data disalin ke komputer lain | `machine_id` berbeda → ID berbeda → akun lama tidak berlaku; pengguna membuat akun baru. Akun lama tidak dihapus. |
| Android, data aplikasi dihapus / aplikasi dipasang ulang | Rahasia instalasi hilang → ID baru → harus membuat akun baru (Android tidak memberi `machine_id`, jadi ikatan hanya bertumpu pada rahasia instalasi). |
| Orang yang sudah menguasai perangkat dalam keadaan terbuka dan data aplikasinya | Dapat bertindak sebagai perangkat itu. Ini bukan attestasi perangkat keras; kunci layar OS dan enkripsi disk tetap diperlukan. |

Bila ID perangkat gagal dibuat (mis. folder data tidak dapat ditulis), layar login **menampilkan peringatan merah**, akun tidak diikat, dan
"ingat perangkat" dimatikan. Tidak ada fallback diam-diam.

## 2. Akun

* Setiap akun menyimpan `device_fp`. Perangkat hanya melihat akun miliknya. Akun lama (sebelum fitur ini) diadopsi oleh perangkat pertama yang menjalankan versi baru.
* Username harus unik di dalam satu berkas identitas; perangkat baru memilih username lain.
* Kata sandi baru 8–128 karakter. Login tetap menerima kata sandi lama 6–12 karakter.
* Penguncian: 5 kegagalan dalam 5 menit → kunci 60 detik, lalu dua kali lipat setiap kali kambuh, maksimum 1 jam; hari tenang melupakan catatan.

## 3. Ingat perangkat (agar tidak login terus)

* Kotak centang **Ingat perangkat ini** (default aktif) membuat token acak 256-bit. Hanya hash SHA-256-nya yang disimpan di database; token asli ada di berkas `device-session.token` (0600).
* Token **sekali pakai dan berputar**: setiap pembukaan aplikasi menukar token lama dengan yang baru. Token yang dicuri dan dipakai lebih dulu akan membuat token pemilik asli mati (terlihat sebagai harus login ulang).
* Masa berlaku 30 hari sejak pemakaian terakhir, batas mutlak 90 hari sejak login dengan kata sandi.
* Token terikat ke ID perangkat; disalin ke perangkat lain tidak berguna.
* Satu perangkat hanya menyimpan **satu** sesi diingat. Mematikan kotak centang saat login, atau menekan **Keluar**, mencabutnya di database dan menghapus berkas token.
* Risiko yang harus dipahami: selama sesi diingat, siapa pun yang membuka aplikasi di perangkat yang tidak terkunci bisa masuk tanpa kata sandi. Matikan di perangkat bersama.

## 4. Verifikasi ulang untuk aksi sensitif

Panel inline (aplikasi tidak memakai dialog modal) meminta kata sandi atau PIN akun sebelum: membuat akun, mengatur/menghapus PIN, menyimpan token admin, membuat/mengekspor/mengimpor kunci E2EE, membuat/memulihkan backup, dan memulihkan berkas dari karantina.

* Berlaku 5 menit setelah benar. Login dengan kata sandi/PIN dihitung sebagai verifikasi baru; sesi "diingat" dan biometrik **tidak**.
* Memakai penghitung penguncian yang sama dengan login, sehingga tidak bisa dipakai menebak kata sandi tanpa batas.
* Berhasil/gagal tercatat di rantai audit.
* Mengganti kredensial admin sudah mewajibkan kata sandi saat ini, jadi tidak digandakan.

## 5. Backup dan akun

Akun tidak ikut Backup & Restore. `identity.sqlite3` dikecualikan dari backup baru dan dilewati saat memulihkan backup lama yang masih memuatnya
(hasil pemulihan melaporkannya). Alasannya: memulihkan akun perangkat lain ke perangkat ini hanya akan menimpa akun yang baru Anda buat dan
menggantinya dengan akun yang tidak terlihat di sini. Data lainnya (audit, arsip, pengaturan) tetap berpindah; lihat `LOCAL_STORAGE.md`.

## 6. Yang belum diverifikasi

Semua perilaku di atas diuji lewat tes otomatis terhadap kode (termasuk simulasi alur login pada harness UI palsu). Belum diuji pada
Flet/Windows/Android sungguhan: tampilan, perilaku `ft.Checkbox`, dan penyimpanan berkas token pada sandbox Android.
