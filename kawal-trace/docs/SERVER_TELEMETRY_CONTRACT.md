# Kawal-Trace 1.5 — Kontrak Feed Telemetri Server

## Koreksi arsitektur

Endpoint sinkronisasi audit yang lama (`POST /api/v1/audit/events:batch`) hanya mengirim rantai audit aplikasi ke server. Endpoint itu sendiri tidak membuat aplikasi dapat membaca log SSH, sudo, auditd, atau log web server Linux.

Untuk mengawasi aktivitas pada host Linux, host tersebut harus mengirimkan event melalui agen/sumber log yang terpasang dan diizinkan. API perlu menampung event keamanan host, lalu menyediakan feed read-only untuk dashboard Windows/Android. Rute di bawah adalah kontrak integrasi baru; bukan klaim bahwa server existing sudah memilikinya.

## Endpoint yang dibutuhkan

### POST `/api/v1/security-events:batch`

Dipanggil agen Linux. Harus memakai token **write-only khusus host**; jangan memakai token admin atau token monitor dashboard.

Headers:

- `Authorization: Bearer <sensor-token>`
- `X-KAWAL-Host-ID: <host-id-yang-di-enroll>`
- `Idempotency-Key: <sha256-batch-id>`
- `Content-Type: application/json`

`Idempotency-Key` dihitung oleh agen sebagai SHA-256 dari daftar `event_id` dalam batch yang digabungkan dengan karakter newline (`\n`), berurutan sesuai payload. Server harus menganggap key ini sebagai petunjuk deduplikasi batch, bukan bukti autentikasi: autentikasi tetap berasal dari token sensor, dan setiap `event_id` tetap harus unik serta idempoten. Jika respons hilang, pengiriman ulang payload yang sama harus mengembalikan hasil penerimaan sebelumnya tanpa menggandakan event.

Request:

```json
{
  "schema_version": 1,
  "host_id": "srv-lab-01",
  "sent_at_utc": "2026-10-20T03:00:00.000Z",
  "events": [
    {
      "event_id": "64-karakter-hex-unik",
      "timestamp_utc": "2026-10-20T02:59:00.000Z",
      "host_id": "srv-lab-01",
      "source": "linux-journal",
      "event_type": "AUTH_FAILURE",
      "actor": "test-user",
      "source_ip": "192.0.2.10",
      "source_country": "Example Country",
      "source_region": "Example Region",
      "source_city": "Example City",
      "source_asn": "AS64500",
      "source_org": "Example Network",
      "source_geo_source": "local-geoip-db",
      "source_geo_accuracy": "approximate",
      "source_hostname": "managed-endpoint-07",
      "source_os": "Windows 11",
      "source_device_type": "desktop",
      "source_vendor": "Example Vendor",
      "source_model": "Example Model",
      "source_device_source": "enrolled-endpoint-agent",
      "source_user_agent": "optional HTTP user-agent; untrusted hint",
      "details": {"service": "sshd.service", "auth_method": "ssh", "reason": "failed_password"}
    }
  ]
}
```

Response `200`:

```json
{"accepted_event_ids": ["64-karakter-hex-unik"]}
```

API harus memvalidasi token terkait `host_id`, field dan ukuran payload, deduplikasi `event_id`, batas laju, serta persistensi sebelum mengakui event. Bila ID yang sama datang lagi dengan konten berbeda, tolak dan catat konflik; jangan menimpa event lama. Respons partial-ack boleh berisi subset ID yang benar-benar disimpan. Jangan memasukkan token, password, cookie, session ID, atau private key ke log payload.

### GET `/api/v1/security-events?limit=100`

Dipanggil dashboard Flet memakai token **read-only terpisah**. Batasi `limit` ke rentang 1–100. Response harus mengembalikan event terbaru terlebih dahulu:

```json
{"events": [ /* normalized server security events */ ]}
```

Feed ini tidak boleh mengembalikan token, raw request body, password, session cookie, secret, atau detail file sensitif yang tidak diperlukan. Token monitor tidak boleh punya hak tulis atau admin.

## Event type yang didukung

- `AUTH_FAILURE`, `AUTH_SUCCESS` — kegagalan/keberhasilan autentikasi dari journal.
- `PRIVILEGE_USE` — penggunaan sudo/sesi privilege; bukan otomatis dianggap serangan.
- `FILE_CHANGE` — perubahan jalur sensitif yang teramati oleh auditd dan rule yang disetel administrator.
- `SERVICE_CHANGE` — event perubahan service/config yang dikirim oleh integrasi server.
- `WEB_AUTH_FAILURE`, `WEB_AUTH_SUCCESS`, `API_AUTH_FAILURE`, `API_AUTH_SUCCESS` — bila API/web app dapat mengeluarkan event terstruktur.
- `CUSTOM_SECURITY_EVENT`, `AGENT_HEALTH` — event lain yang sudah dinormalisasi.

Setiap event wajib mempunyai `event_id` heksadesimal 16–128 karakter, `timestamp_utc` ISO-8601 dengan zona waktu, `host_id`, `source`, `event_type`, `actor`, `source_ip` (kosong atau IP valid), dan `details` object. `details` yang ditampilkan client dibatasi ke allow-list (`path`, `auth_method`, `reason`, `service`, `command_basename`, `uid`, `rule_key`, `message_excerpt`, `result`).


## Metadata konteks sumber (opsional, versi dashboard 1.5)

API dapat menambahkan metadata berikut ke setiap event feed. Client membatasi panjang teks dan menampilkannya sebagai metadata tak tepercaya; pengirim API bertanggung jawab memastikan provenance.

- `source_country`, `source_region`, `source_city`: hasil GeoIP perkiraan dari `source_ip` (jangan tampilkan seolah koordinat/alamat tepat).
- `source_asn`, `source_org`: ASN atau organisasi jaringan.
- `source_geo_source`, `source_geo_accuracy`: nama database/metode dan label tingkat ketelitian seperti `approximate`.
- `source_hostname`, `source_os`, `source_device_type`, `source_vendor`, `source_model`, `source_device_source`: hanya bila tersedia dari endpoint terdaftar/agent inventory atau sistem manajemen perangkat.
- `source_user_agent`: hanya petunjuk dari HTTP header; dapat dipalsukan dan tidak dapat membuktikan merek/model.

Prefer GeoIP lokal di server API, bukan mengirim setiap IP ke situs pihak ketiga. Jangan menghasilkan lokasi bagi IP privat/loopback/reserved. IP sumber dan geolokasi tidak mengidentifikasi individu secara pasti; VPN, proxy, NAT, dan database yang tidak presisi dapat mengubah hasil. Field perangkat SSH biasanya tidak tersedia tanpa agent endpoint terdaftar.

## Transport dan kontrol akses

- Gunakan HTTPS dengan verifikasi sertifikat aktif untuk akses internet. Jangan menggunakan `verify=False` atau menonaktifkan pemeriksaan TLS.
- Enroll token berbeda per host dan per hak: ingest sensor (write-only) serta dashboard (read-only).
- Token memiliki masa berlaku/rotasi dan dapat dicabut.
- Letakkan API di belakang kontrol akses, batas ukuran request, rate limiting, log audit, backup serta checkpoint terpisah.
- Sinkronkan jam host (NTP); timestamp event dan timestamp penerimaan server sebaiknya disimpan terpisah.
- Raw logs adalah data tidak tepercaya. Terapkan sanitasi output, limit ukuran, pembatasan akses, dan redaksi secret/PII.
- Telemetri bukan bukti identitas manusia secara definitif; IP, username, dan UID perlu dikorelasikan dengan sumber autentikasi tambahan.


## v1.8 response/alert additions

Event type `MALWARE_DETECTED` is accepted only from an authorized host ID; for the bundled agent, it is emitted after optional ClamAV signature match on a file that changed under an explicit scan root. This is not a full-disk scan and does not automatically delete/quarantine files.

The optional API adds `GET /api/v1/response-actions?limit=20` (monitor token) and `POST /api/v1/response-actions` (dedicated response token). The POST is disabled unless an administrator sets `KAWAL_RESPONSE_ACTIONS_ENABLED=true` and a valid `KAWAL_RESPONSE_ALLOWLIST`. It accepts only a public IPv4 not in the allowlist, TTL 300/900/1800 seconds, a reason of at least 8 characters, exact confirmation `BLOCK <IP>`, and a matching direct SSH `AUTH_FAILURE` event from `linux-journal` received in the last 24 hours. The API queues the request; only the separate root UFW worker can activate it and report `ACTIVE_TEMP_BLOCK`. This action does not disconnect established sessions and must not be used to block web visitors via Cloudflare proxy/tunnel.

## Notification behavior

The client uses local native notifications for new HIGH/CRITICAL events only while it is running, connected and permitted by the OS. `flet-notifications==0.1.4` is a native Flet extension; test it on a built application rather than `flet run`. Push events after the app process is closed are out of scope until a push service such as FCM has been provisioned and securely integrated.
