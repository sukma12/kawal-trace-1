# OpenZiti terintegrasi dengan Kawal Trace

## Tujuan

Kawal Trace menjadi panel pengelola koneksi dan status. OpenZiti tetap berjalan sebagai service/daemon sistem operasi karena ia membutuhkan hak untuk membuat tunnel, mengatur DNS/rute, dan menyimpan sertifikat identity. Pengguna tidak perlu membuka panel Desktop Edge setiap kali setelah service tersedia.

## Windows (komputer operator)

1. Buka **Private Network Access** di Kawal Trace.
2. Pilih **Siapkan runtime OpenZiti Windows**. Kawal Trace mengambil installer dari rilis resmi `openziti/desktop-edge-win`, membatasi sumber HTTPS, memeriksa ukuran, dan mewajibkan tanda tangan Authenticode valid.
3. Selesaikan installer resmi dan persetujuan UAC/driver jika diminta.
4. Kembali ke Kawal Trace, pilih **Periksa tools & status**.
5. Identity perangkat harus diterbitkan oleh administrator OpenZiti Controller. Jangan memakai satu identity/JWT untuk beberapa perangkat. Simpan JWT secara privat dan jangan mengirimkannya ke chat atau log.

Catatan: rilis resmi Windows saat ini memasang komponen service tunneler dan komponen pendampingnya. Kawal Trace tidak mengemas ulang atau memodifikasi binari vendor. Enrollment identity pada Windows masih mengikuti mekanisme resmi OpenZiti Desktop Edge; tombol connect tidak boleh dianggap berhasil sebelum service dan identity benar-benar aktif.

## Ubuntu Server di VirtualBox

Paket `ziti-edge-tunnel` dipasang di dalam Ubuntu VM, bukan di Windows host. Script `scripts/setup_openziti_ubuntu.sh` disertakan untuk menambahkan repository paket OpenZiti yang ditandatangani, memasang paket resmi, dan mengaktifkan `ziti-edge-tunnel.service`.

Instalasi tanpa identity:

```bash
sudo bash scripts/setup_openziti_ubuntu.sh
```

Instalasi sekaligus menyiapkan token enrollment satu kali:

```bash
sudo bash scripts/setup_openziti_ubuntu.sh /path/aman/server.jwt kawal-trace-server
```

JWT akan ditempatkan dengan izin terbatas pada `/opt/openziti/etc/identities/`. Gunakan JWT yang dibuat khusus untuk server Ubuntu ini. Setelah enrollment, hapus salinan JWT sumber dengan aman sesuai kebijakan administrator.

Periksa hasilnya:

```bash
sudo systemctl status ziti-edge-tunnel.service --no-pager
sudo journalctl -u ziti-edge-tunnel.service -n 80 --no-pager
```

## Yang tetap diperlukan

- OpenZiti Controller dan setidaknya satu Edge Router yang dapat dijangkau dari Windows dan Ubuntu VM.
- Satu identity terpisah untuk komputer operator dan satu identity untuk Ubuntu server.
- Service/policy OpenZiti yang mengizinkan akses ke layanan yang memang dibutuhkan.
- Akses jaringan keluar dari kedua perangkat. Tidak perlu port forwarding router untuk pola koneksi keluar, tetapi Controller/Router tetap harus tersedia.

Kawal Trace tidak membuat Controller, identity, JWT, sertifikat, service, atau policy secara otomatis. Hasil TCP probe saja bukan bukti autentikasi atau policy ZTNA.
