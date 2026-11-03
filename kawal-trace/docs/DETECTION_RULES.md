# Rule engine telemetri Kawal-Trace

Rule engine saat ini transparan dan berbasis aturan, bukan machine learning dan bukan SIEM penuh. Rule menghitung event yang diterima dari server feed. Event feed yang tidak valid ditolak supaya UI tidak memberi kesan bahwa data invalid sudah diperiksa.

| Rule ID | Kondisi | Severity awal | Catatan |
|---|---|---|---|
| `AUTH_FAILURE_BURST` | 2+ event autentikasi gagal dari IP yang sama dalam 300 detik | HIGH | Sesuaikan ambang melalui kode berdasarkan baseline; uji penetrasi resmi juga bisa memicunya. |
| `AUTH_SUCCESS_AFTER_FAILURES` | Sukses dari IP yang memiliki 2+ kegagalan dalam 10 menit | CRITICAL | Prioritas triase tinggi, bukan kepastian kompromi. |
| `ROOT_REMOTE_LOGIN` | Event login remote sukses dengan actor `root` | HIGH | Bisa sah bila kebijakan mengizinkan; sebaiknya nonaktifkan remote root bila tidak dibutuhkan. |
| `SENSITIVE_FILE_CHANGE` | Auditd melaporkan perubahan di path sensitif allow-list | HIGH | Hanya bekerja untuk path yang benar-benar diaudit oleh Linux auditd. |
| `SERVICE_CONFIGURATION_CHANGE` | Feed menyampaikan event `SERVICE_CHANGE` | HIGH | Butuh integrasi log/config dari server/API yang nyata. |

### Batasan dan pengurangan false positive

- Event dari scanner/uji penetrasi yang disetujui bisa memicu rule. Catat jendela waktu, IP sumber, akun pengujian, serta host yang masuk scope.
- Feed terakhir hanya berisi event yang diminta; “0 alert” tidak berarti “server aman”.
- Tidak ada rule yang otomatis memblokir IP, menghentikan service, atau mengubah firewall. Respons otomatis memerlukan desain anti-abuse dan kontrol operator terpisah.
- Pastikan API menyimpan `received_at_utc`, sumber event, status kelengkapan log, dan identitas sensor yang menerbitkan event.


## Malware signature event

`MALWARE_DETECTED` hanya dibuat oleh agen jika pemindaian opsional ClamAV untuk file yang berubah pada root yang diizinkan mengembalikan signature match. Perubahan file sendiri tidak berarti malware, dan tidak ada auto-delete/remediation. Alert tidak identifikasi pelaku/manufacturer.

## Notifikasi dan respons

Notifikasi native HIGH/CRITICAL memerlukan build aplikasi dengan extension, izin OS, koneksi feed, serta aplikasi yang berjalan. Push saat aplikasi ditutup belum disiapkan. Respons IP tidak otomatis dan hanya tersedia untuk event gagal SSH langsung yang direkam agen, dengan token khusus, allowlist admin, konfirmasi, dan worker terpisah. Lihat optional-server-api README.
