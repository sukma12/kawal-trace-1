# Kawal-Trace 1.4 — Kontrak API sinkronisasi audit client-server

Dokumen ini mendefinisikan kontrak yang diharapkan oleh client Kawal-Trace 1.3. Karena detail API server existing belum diberikan, client mendukung path yang bisa dikonfigurasi, tetapi format request/response tetap mengikuti kontrak ini. Jika API yang ada berbeda, buat adapter tipis di API/server; jangan menonaktifkan validasi TLS atau verifikasi hash.

> **Status: dinonaktifkan bawaan.** Aplikasi Kawal Trace tidak lagi mengunggah rantai audit ke server (semua database disimpan di
> perangkat; lihat `LOCAL_STORAGE.md`). `SyncClient.sync_once` menolak berjalan kecuali dibuat dengan `allow_remote_storage=True`, dan
> API server menolak endpoint ini (HTTP 403 `client_data_storage_disabled`) kecuali `KAWAL_API_ACCEPT_CLIENT_DATA=true`. Kontrak di bawah
> dipertahankan untuk kompatibilitas dan pengujian protokol, bukan sebagai alur normal aplikasi.

## Alur

1. Administrator mendaftarkan satu perangkat dengan `device_id` yang terlihat pada aplikasi.
2. Server menerbitkan **token unik per perangkat**, idealnya minimal 32 byte acak dari CSPRNG. Token hanya berizin menerima log dari perangkat tersebut, bukan admin API. Token dapat dicabut/dirotasi.
3. Operator mengisi base URL HTTPS, path health, path event batch, dan token di aplikasi. Token disimpan di native Secure Storage Flet (Windows Credential Manager/Android Keystore); token tidak ditulis ke `sync-settings.json`, SQLite audit, query URL, atau log aplikasi. Environment `KAWAL_TRACE_DEVICE_TOKEN` tersedia sebagai opsi administrasi untuk testing.
4. Client memverifikasi seluruh local hash chain sebelum mengirim. Record lokal tidak pernah dihapus sesudah upload.
5. Client mengirim batch berurutan. Jika jaringan putus, cursor tidak maju; client mengirim ulang batch yang sama. API harus idempotent.
6. Server commit data lebih dahulu, kemudian membalas `accepted_through_seq` dan `head_hash`. Client memajukan cursor lokal hanya bila nomor urut tersebut berada dalam batch dan hash sama persis dengan hash lokal.

## Transport dan autentikasi

Semua host Internet wajib memakai HTTPS dengan validasi sertifikat tetap aktif. HTTP hanya diperbolehkan untuk `localhost`/loopback saat uji pengembangan. Jangan memakai `verify=False`.

Setiap request berisi:

- `Authorization: Bearer <device-token>`
- `X-KAWAL-Device-ID: <device_id>`
- `User-Agent: Kawal-Trace/1.5.0`

POST batch juga berisi `Idempotency-Key`, nilainya sama dengan `batch_id`. Server wajib mengikat token ke device ID yang sama, membatasi rate dan ukuran body, memvalidasi tipe data/ukuran field, dan menolak device yang dicabut.

## GET health

Default: `GET /healthz`, harus dilindungi dengan autentikasi perangkat atau aturan health-check yang sesuai kebijakan deployment. Response sukses boleh seperti:

```json
{"status":"ok","service":"audit-api"}
```

Client menerima HTTP 2xx untuk health-check dan tidak menganggap endpoint terbuka tanpa autentikasi sebagai bukti enrollment.

## POST batch events

Default: `POST /api/v1/audit/events:batch`

Header `Content-Type: application/json`. Contoh payload:

```json
{
  "schema_version": 1,
  "app_version": "1.5.0",
  "device_id": "cl-0123456789abcdef0123456789abcdef",
  "batch_id": "sha256-hex-value",
  "sent_at_utc": "2026-10-20T02:00:00.000Z",
  "first_seq": 1,
  "last_seq": 2,
  "previous_ack_seq": 0,
  "previous_ack_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "events": [
    {
      "event_id": "sha256-hex-value",
      "device_id": "cl-0123456789abcdef0123456789abcdef",
      "seq": 1,
      "timestamp_utc": "2026-10-20T02:00:00.000Z",
      "event_type": "SYSTEM",
      "actor": "Kawal-Trace",
      "source": "local-app",
      "details": {"message": "local audit initialized"},
      "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "record_hash": "sha256-hex-value"
    }
  ]
}
```

Nilai hash di atas hanya placeholder untuk dokumentasi. Jangan mengirim string placeholder.

### Cara menghitung nilai yang diikat oleh record hash

Server menghitung ulang SHA-256 atas UTF-8 canonical JSON dengan key diurutkan, `ensure_ascii=False`, pemisah `,` dan `:` tanpa spasi, dan `allow_nan=False`. Field yang masuk ke record hash persis:

```json
{
  "seq": 1,
  "timestamp_utc": "...",
  "event_type": "SYSTEM",
  "actor": "...",
  "source": "...",
  "details": {},
  "previous_hash": "..."
}
```

`record_hash` yang dikirim tidak termasuk ke dalam JSON yang di-hash. `event_id`, `device_id` envelope, `batch_id`, dan metadata pengiriman juga tidak ikut ke record hash lokal.

- `previous_hash` pada seq 1 harus 64 karakter hex nol (`GENESIS_HASH`).
- Nomor urut harus kontinu per perangkat, tidak boleh ada gap. Untuk seq berikutnya, `previous_hash` harus sama dengan `record_hash` record sebelumnya.
- `event_id = SHA256(UTF8(device_id + "\\n" + seq + "\\n" + record_hash))`.
- `batch_id = SHA256(UTF8(device_id + "\\n" + first_seq + "\\n" + last_seq + "\\n" + first_record_hash + "\\n" + last_record_hash))`.

### Response sukses wajib

Server commit batch terlebih dahulu lalu membalas JSON seperti:

```json
{"accepted_through_seq": 42, "head_hash": "64-hex-record-hash", "accepted_count": 42}
```

`accepted_through_seq` harus merupakan seq yang benar-benar sudah tersimpan dan termasuk dalam batch yang dikirim (atau checkpoint lama untuk kasus duplicate yang dikenali). `head_hash` harus merupakan `record_hash` untuk seq tersebut. Client tidak memajukan cursor kalau field hilang, hash salah, seq melompat, atau response bukan JSON. Partial ack boleh dipakai untuk prefix kontinu yang valid.

### Idempotensi dan penyimpanan server

Server sebaiknya menerapkan constraint database:

- `UNIQUE(device_id, seq)`
- `UNIQUE(device_id, event_id)`
- `UNIQUE(device_id, batch_id)` pada tabel penerimaan batch/idempotency

Untuk retry, jika event dengan `(device_id, seq)` sudah ada, server hanya boleh menganggapnya duplikat apabila `event_id` dan `record_hash` sama. Bila beda, balas `409 Conflict` dan catat insiden. Jangan pernah menimpa record lama. Untuk event baru, terapkan pemeriksaan seq, previous hash, dan canonical record hash secara transaksional sebelum commit.

Status umum:

- `200/201`: batch diterima/duplicate idempotent, dengan response checkpoint wajib.
- `400`: payload/schema/hash invalid.
- `401/403`: token tidak sah, perangkat berbeda, atau perangkat dicabut.
- `409`: urutan/hash konflik.
- `413`: payload terlalu besar.
- `429`: rate limit.
- `5xx`: gangguan sementara; client mempertahankan cursor dan mencoba ulang.

## Batas kepercayaan

- `device_id` bukan identitas yang dipercaya tanpa token; token yang di-enroll server adalah kontrol aksesnya.
- Hash chain membuktikan konsistensi konten yang dikirim, bukan membuktikan bahwa file yang terdeteksi pasti diubah oleh orang tertentu.
- Client bisa dikuasai admin lokal. Server sebaiknya menyimpan penerimaan append-only, mencatat token/device auth events, dan membuat checkpoint terpisah dari database client.
- Untuk sistem operasional, pertimbangkan mTLS, sertifikat perangkat yang dapat dicabut, MFA untuk admin server, rate-limiting/WAF, backup immutable, monitoring server, retensi, dan review keamanan independen.

## Langkah adaptasi API existing

1. Pastikan endpoint dapat menerima header `Authorization` dan `X-KAWAL-Device-ID`.
2. Petakan route existing ke `health_path` dan `events_path` di panel integrasi.
3. Jika skema request/respons berbeda, implementasikan adapter di server yang mengubah format menjadi kontrak di atas; jangan mengakali klien dengan mematikan TLS atau menerima checkpoint tanpa hash.
4. Buat enrollment perangkat dan token unik; jangan masukkan token server admin ke client.
5. Uji dulu di staging / perangkat uji. Jangan sambungkan ke sistem produksi/rahasia sebelum pemilik server menyetujui dan audit keamanan dilakukan.


> Catatan versi 1.4: endpoint ini hanya untuk mengirim audit chain aplikasi. Untuk log sistem Linux yang teramati agen server dan feed read-only ke dashboard, lihat [`SERVER_TELEMETRY_CONTRACT.md`](SERVER_TELEMETRY_CONTRACT.md).
