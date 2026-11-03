# Arsip dan ekspor log Kawal Trace v2.2.0

## Penyimpanan: hanya di perangkat

Arsip permanen berada di SQLite pada perangkat ini. Kawal Trace **tidak mengunggah** arsip atau log Anda ke server mana pun
(lihat [`LOCAL_STORAGE.md`](LOCAL_STORAGE.md)). Pilihan "Server milik saya saja" dan "Server + salinan perangkat" yang ada di
versi sebelumnya sudah dihapus; menu penyimpanan kini hanya menampilkan **Perangkat saja** dan tidak dapat diubah.

Payload event di arsip dienkripsi AES-256-GCM dengan kunci perangkat; ID profil, ID event, dan tanggal tetap terbaca agar
pengelompokan harian bisa dibuat.

**Arsip lama di server:** bila versi sebelumnya pernah mengunggah arsip, tombol **Ambil arsip lama dari server ke perangkat**
tampil di **Riwayat & ekspor log**. Ia hanya mengunduh (satu arah) ke SQLite lokal; tidak ada yang diunggah atau dihapus di server.

## Lihat dan unduh

1. Pilih profile server sumber.
2. Pilih **Tanggal arsip (UTC)** atau **Semua tanggal**. Pratinjau membaca SQLite perangkat.
3. Pilih format **PDF** untuk laporan, **CSV** untuk Excel/analisis tabel, atau **JSON** untuk integrasi dan analisis teknis.
4. Tentukan folder ekspor, lalu tekan tombol ekspor. File diberi nama dengan nama profile, tanggal filter, dan waktu pembuatan UTC.

**Berkas ekspor tidak terenkripsi**: Anda memintanya sebagai berkas yang bisa dibaca. Simpan dan bagikan dengan hati-hati.

## Waktu

Event dinormalisasi dan dikelompokkan berdasarkan timestamp sumber dalam UTC. Pratinjau juga menunjukkan waktu lokal perangkat. Aktifkan pengaturan **Atur waktu secara otomatis** dan **Zona waktu otomatis** pada Windows/Android. Kawal Trace tidak mengubah jam sistem, dan jam OS yang salah dapat membuat label waktu lokal kurang akurat.

## Server API

Endpoint arsip pada API opsional (`/api/v1/archive/...`) kini **nonaktif secara bawaan** dan membalas HTTP 403
`client_data_storage_disabled`. Operator server dapat mengaktifkannya dengan `KAWAL_API_ACCEPT_CLIENT_DATA=true` hanya untuk
melayani aplikasi versi lama atau uji protokol. Jangan membuka port API langsung ke internet; gunakan HTTPS/tunnel yang dilindungi
autentikasi.

## Batas penting

Enkripsi hanya melindungi kolom payload di berkas database; pada Android/Linux kunci berada di berkas di samping database, sehingga
perlindungan dari orang yang dapat membaca seluruh folder aplikasi bergantung pada sandbox aplikasi dan enkripsi disk OS. Rincian
lengkap ada di `LOCAL_STORAGE.md`.
