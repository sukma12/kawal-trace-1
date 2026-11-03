# Kawal Trace 1.0 — Local-first security client

Kawal Trace is a local-first audit and defensive monitoring prototype for Windows endpoints, Ubuntu/Linux hosts, and a Flet dashboard that can be built for Windows and Android. Its URL-only website mode checks availability from outside; reading internal security logs still requires an explicitly authorized API, agent, or collector. It is not a full SIEM/EDR and does not magically monitor arbitrary public servers.

## Quick connection guide

- Website URL-only monitoring (no API token): see [`docs/WEBSITE_MONITORING.md`](docs/WEBSITE_MONITORING.md). Targets and check history are local and separate from the security-event log.

See [`docs/INTEGRATION_WIZARD.md`](docs/INTEGRATION_WIZARD.md) for the Wizard Integrasi Server workflow and its compatibility limits.

## What is included in this source release

- **Advanced defensive helpers (v2.3.0):** device-local 8–12 digit PIN unlock with persistent throttling; optional Windows/Android system biometrics through `flet-local-auth`; read-only OpenZiti/WireGuard tool checks; offline `.eml` phishing indicators with an optional selected-URL PhishTank lookup and optional local SpamAssassin CLI; and a micro-segmentation firewall-policy preview. These helpers do not install VPN clients, change firewall rules, delete emails, or apply server actions automatically. See `docs/ADVANCED_DEFENSE.md`.

- SHA-256 hash-chained SQLite audit records on the dashboard client and local sensor outboxes. Tampering is detectable if records/links are modified; an attacker who can rewrite the entire database and chain may still forge it unless an independently protected checkpoint exists. SQLite log payloads are not encrypted at rest in this source release; enable OS/device encryption and access controls.
- E2EE audit and security-event payloads: X25519 ephemeral key agreement, HKDF-SHA256, AES-256-GCM authenticated encryption. The API stores ciphertext and does not hold the dashboard private key. Routing metadata (including selected identifiers, timestamp, event type, source IP, sequence/checkpoint fields where needed) remains visible to the API. The action-control/response queue is HTTPS-authenticated with TOTP and local checks, but its request parameters are **not yet E2EE**; do not claim that every field/command is end-to-end encrypted.
- Windows Event Log agent with an allowlist of Security/System/Defender event IDs; fields are minimized and arbitrary command-line arguments are not uploaded. Event IDs include 4624, 4625, 4634, 4647, 4672, 4688, 4697, 1102, 4720, 4726, 4728, 4732, System 7045, and Defender 1116/1117/5007.
- Linux agent for journald SSH/sudo and optional auditd file-change events, optional local GeoIP DB, and optional ClamAV scan for explicitly watched changed files. Malware events only reflect scanner/signature results; no auto-delete is performed.
- Low overhead defaults: Windows Event Log polling defaults to 10 seconds, queries a fixed event-ID allowlist, caps a collection window at 250 results per channel and batches up to 100 events. First install baselines each channel at its current newest EventRecordID to avoid replaying huge historical logs. Linux collection is event-driven by journal/audit input. ClamAV is disabled by default and only scans explicitly configured roots/files.
- Live dashboard feed polling about every 5 seconds while the app remains open, per-server fleet summary, GeoIP/IP/ASN metadata when the server supplies it, map links only when coordinates exist, JSON/CSV report export, and local notifications for new HIGH/CRITICAL alerts while the built app is running and permissions are granted.
- Windows response request UI supports temporary Windows Firewall block for a public IPv4 with recent local Windows Event ID 4625 evidence, RDP session logoff after local evidence/identity revalidation, and termination only of a small allowlist of shell process names after live PID/name/owner checks. Actions require explicit typed confirmation, a TOTP, response token, and target host enrollment. The server and agent response switches are OFF by default. This is for approved endpoints only; false-positive response can disrupt legitimate users.
- Linux UFW response queue is separate, requires explicit opt-in, TOTP, admin allowlist, reason/confirmation, and recent direct SSH auth failure evidence. It does not block visitors arriving through Cloudflare proxy/tunnel.
- **Website URL-only monitoring (v2.5.0):** explicitly saved HTTP/HTTPS targets, public/internal target gate, DNS validation with pinned destination IPs, redirect revalidation, TLS hostname verification, credential-shaped query rejection, bounded timeouts and polling intervals, AES-256-GCM encrypted local history with a key held in OS Secure Storage, history separate from security events, and no API token required. See `docs/WEBSITE_MONITORING.md` for details.
- **Read-only audit connectors (v2.5.0):** SSH using a trusted `known_hosts` file and fixed log-command allowlist; MySQL/MariaDB/SQL Server audit views with read-only SELECT queries and TLS validation; and a syslog TCP receiver with mutual TLS required on non-loopback interfaces. Events are normalized, bounded, deduplicated and added to the local hash-chain audit store. Install optional driver extras and test against authorized infrastructure before production use.
- Multi-server profiles, connect/test/disconnect controls, and read-only adapters for REST/JSON + pagination, OAuth2 client-credentials, GraphQL query-only, SOAP/XML read-only and WebSocket JSON; a self-managed Kawal Trace API connector is also available.
- Persistent server-event archive partitioned by UTC date, stored **only on the device** (payloads encrypted at rest with AES-256-GCM; nothing is uploaded). Archives uploaded by older versions can be pulled back to the device one way. See `docs/LOCAL_STORAGE.md`.
- Export server logs by chosen UTC date or all dates as PDF, CSV, or JSON. Exports are plain files by design.
- A beginner-friendly Integration Wizard in the dashboard separates ready-made security APIs from Kawal Trace API enrollment and host agent/collector setup. It can probe a short list of common REST/JSON log paths using bounded GET requests and infer common field names when a usable sample exists.

## Limits that matter

- Website monitor timing reports DNS resolution, response-header time, and total time; TCP-connect and TLS-handshake durations are not separate metrics yet. Its database image is encrypted with AES-256-GCM using a key in OS Secure Storage, and validated DNS addresses are pinned for connection. Losing the OS secure-storage key means the encrypted history cannot be decrypted unless a separately supported recovery/backup exists; protect the device and its recovery path.

- Native notifications require a built artifact; plain `flet run` can lack the native Dart extension. Push notifications while the app is fully closed are **not configured**; that needs a push backend such as Firebase Cloud Messaging and appropriate device registration. Local notification delivery is subject to OS permission/channel settings and battery policies.
- IP location is an estimate from a local GeoIP database. An IP does not reveal a specific person's home or hardware make/model. MAC addresses do not cross the Internet and cannot be learned from a remote public IP.
- Windows Firewall response can affect new inbound flows but does not guarantee already-established connections are terminated. RDP logoff/process termination require live host-side evidence and may interrupt a legitimate session. The agent's host-side response feature is disabled by default and must be reviewed/tested in staging.
- E2EE applies to the audit/security telemetry payload bodies and encrypted private-key backups. Clear routing metadata is visible, and current response-control command parameters are protected by HTTPS/TOTP but are not yet E2EE. Generic REST connectors use HTTPS/TLS only because their remote schema/keying is external. This source has not had an independent security audit.
- E2EE requires generating the dashboard keypair once, protecting its private key in OS Secure Storage, backing it up with a strong passphrase (min. 14 chars), and copying the public key to each telemetry agent. If key material is lost, encrypted past feed events cannot be decrypted.
- A third-party organization’s public domain is not sufficient authorization. Integrate only API endpoints, logs, or agents for which you have explicit permission.

## Layout Windows dan Android

- Form buat akun/login dipusatkan pada layar penuh dan menggunakan lebar adaptif (maksimum 520 px di laptop; layar kecil memakai viewport dikurangi margin). Ukuran dihitung ulang saat jendela/orientasi berubah.
- Scrollbar visual disembunyikan agar tidak tampak sebagai batang abu-abu panjang; form dan dashboard tetap bisa digulir dengan sentuhan, mouse wheel, atau trackpad.
- Windows memakai sidebar ketika ruang cukup; Android dan jendela sempit memakai pemilih menu yang mengambil lebar konten.
- Build number internal saat ini `6`, sedangkan versi yang terlihat tetap `1.0`. Source ZIP bukan APK/EXE; jalankan skrip build pada mesin yang sudah memiliki toolchain.

## Setup on Windows

1. Use Python 3.13.x. Keep the existing `.venv` if you already installed the project.
2. Extract/update source to `D:\projeck\Kawal-Trace` after making a backup. Do not copy `.venv`, `__pycache__`, SQLite DB, token files, or reports from a source archive over existing data.
3. From CMD:
   ```cmd
   cd /d D:\projeck\Kawal-Trace
   install_windows.bat
   run_windows.bat
   ```
4. Pada instalasi baru, layar pertama adalah **Buat akun administrator**. Username dan kata sandi kosong; buat kredensial pribadi dan konfirmasi kata sandi sebelum akun disimpan. Tidak ada password admin bawaan di source. Jika instalasi lama memiliki penanda akun bootstrap bersama, layar akan meminta verifikasi kredensial lama lalu menggantinya tanpa menghapus riwayat audit atau konfigurasi. Lihat [panduan secrets dan akun lokal](docs/SECRETS_AND_LOCAL_ACCOUNTS.md). Untuk E2EE, buat keypair di menu terkait, ekspor backup dengan frasa sandi kuat, dan simpan private key hanya di perangkat tepercaya; jangan kirim private key ke API atau chat.
5. Configure a server profile with its HTTPS base URL and separate upload/read-only tokens, then test the connection and feed. For daily archive, choose storage under **Integrasi & pemantauan server → Riwayat & ekspor log**. See `docs/ARCHIVE_AND_EXPORT.md` for storage modes, UTC date filters, and exporting PDF/CSV/JSON.
6. To package an EXE, install Visual Studio 2022/2026 with `Desktop development with C++`, enable Windows Developer Mode for symlink support, then run `build_windows.bat`. To build APK, install Android SDK/JDK, accept SDK licenses, then run `flet build apk --python-version 3.13`. This repository release does not include a prebuilt EXE or APK; target-device UI/notification tests must be performed after building.

## Windows Event Log agent (endpoint sensor)

See [docs/WINDOWS_AGENT.md](docs/WINDOWS_AGENT.md). It is a separate sensor and is not installed just by running the dashboard. It needs host enrollment, a write-only host token, the dashboard E2EE public key, a protected `agent.env`, and a scheduled task/service with required Event Log rights. Enable remote response only after a staging test and explicit approval on both the API and Windows host.

## Ubuntu/Linux agent and optional API

- Linux agent: [docs/LINUX_SERVER_AGENT.md](docs/LINUX_SERVER_AGENT.md)
- Optional API: [optional-server-api/README.md](optional-server-api/README.md)
- Decide whether optional API is needed: [docs/WHEN_TO_INSTALL_SERVER_API.md](docs/WHEN_TO_INSTALL_SERVER_API.md)

Your existing AnimePass/NontonBareng website on port 9999 is a separate Node.js app, not automatically a security feed. If it does not expose authorized security event endpoints, the optional Kawal Trace API binds to `127.0.0.1:8765`; for one public hostname, route only API paths through a carefully configured reverse proxy/tunnel and keep the website routes unchanged. Do not expose port 8765 directly to the Internet. For server-only archive date summaries, update the API to v1.4.0 using `optional-server-api/upgrade_membership.sh`; the upgrade backs up `server.py` and preserves `api.env` and the database.

## API and testing

- API spec: `docs/openapi-sync-contract.yaml`
- Security telemetry contract: `docs/SERVER_TELEMETRY_CONTRACT.md`
- **Full feature/status matrix:** `docs/FEATURE_READINESS_MATRIX.md` (source/test/live/native distinctions); security details: `docs/SECURITY_FEATURE_MATRIX.md`
- Windows agent guide: `docs/WINDOWS_AGENT.md`

Run the automated tests with a development Python environment:

```cmd
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

v2.3.0 automated source-tree tests include device-PIN, phishing-input, WireGuard validation, ZTNA helper and micro-segmentation preview tests. See the audit report and `reports/2000_advanced_security_matrix.json` for this release’s measured test results. The 1,000-scenario API protocol matrix and 1,000-scenario defensive input matrix were re-run against local loopback simulators; these do not certify external vendor APIs. Python syntax/tests pass, but the Flet GUI was not run in the artifact-building environment, EXE/APK were not produced here, and the user’s real Ubuntu/Cloudflare/API integration has not been tested end-to-end. Treat this as a source prototype requiring staged validation, independent review, backups, and explicit authorizations before operational use.


## Membership workflow

The API v1.3.0 membership flow supports server-owner approvals; v1.4.0 adds date summaries (disabled by default, see `KAWAL_API_ACCEPT_CLIENT_DATA`). Install/upgrade the API only on the owner's central Ubuntu server; member laptops only need Kawal Trace and an HTTPS Base URL. For deployment, see `optional-server-api/README.md`. The admin token is initialized once with `setup_admin_token.py`; member tokens are provisioned automatically after owner approval.


## 2.0.1 hardening update
- The first server-feed read checks recent events from the last five minutes for active HIGH/CRITICAL incidents rather than silently baselining them. Older history is baselined to avoid notification floods.
- Security feed JSON responses are streamed with a 4 MiB limit; oversized responses are rejected before JSON decoding.
- Generic REST connector now honours its configured request timeout (1–30 seconds).
- Local login throttles after five failed attempts in a five-minute window for a 60-second lockout; the counter persists across app restarts. This remains an app-level control, not OS account protection.
- Branding metadata set to Kawal Trace. The Android application ID and internal storage folder remain unchanged to avoid breaking existing app upgrades/data.
- A loopback-only 1,000-scenario API compatibility/security simulator is included at `scripts/simulate_1000_api_protocols.py`.

## 2.0.0 Public client additions
See `CHANGELOG_v2.0.0.md` and `docs/PUBLIC_CLIENT_PRIVACY.md`. Generic REST supports common read-only auth patterns; local logs continue to work offline; auth-failure alert threshold is two events in five minutes. Audio alerts require the app to be running and the audio extension to be built into the app.


## 2.1.0 protocol and defensive validation update
See `CHANGELOG_v2.1.0.md` and `docs/API_COMPATIBILITY_GUIDE.md` for adapter configuration examples, size/time bounds and test scope. Native EXE/APK builds, device sound/system notification tests, provider permissions and vendor-specific API schemas still need target-side verification.


## v2.2.0 archive storage and daily exports

See [`docs/ARCHIVE_AND_EXPORT.md`](docs/ARCHIVE_AND_EXPORT.md). The optional archive API endpoints are off by default because the app keeps its archive on the device (`docs/LOCAL_STORAGE.md`). API server upgrade uses `optional-server-api/upgrade_membership.sh`, which makes a backup and retains `api.env` and the SQLite DB. Full native EXE/APK builds and real-device UI/sound notifications still require target-device verification.


## Kawal Trace 1.0 — Setup awal, login, dan tampilan ponsel

- Instalasi baru menampilkan formulir **Buat akun administrator** sebelum masuk. Akun tidak lagi dibuat diam-diam ketika aplikasi mulai.
- Form setup versi 1.0 tidak mengisi username atau kata sandi bawaan. Pengguna memilih kredensial lokal sendiri; hanya hash PBKDF2 bersalt yang disimpan. Kredensial server/agen dapat dikonfigurasi melalui environment variable pada proses deployment dan tidak boleh dimasukkan ke paket rilis.
- Nomor build internal Android/Windows untuk perbaikan ini adalah `6`; versi yang tampil di aplikasi tetap `1.0`. Naikkan `build_number` untuk setiap rilis berikutnya agar Android menerima pembaruan.
- Login memakai kartu responsif yang dipusatkan eksplisit di layar penuh; lebar/tinggi menyesuaikan viewport dan dihitung ulang saat resize. Scrollbar visual disembunyikan tetapi scrolling tetap aktif. PIN ada di balik tombol **Masuk dengan PIN perangkat**.
- Biometrik hanya muncul bila platform didukung, pemeriksaan biometrik tersedia, dan setidaknya satu biometrik telah terdaftar. Di layar sempit, dashboard memakai pemilih menu daripada sidebar yang menyempitkan konten.
- Jika startup dashboard gagal, tampilan menyebut `GAGAL MEMBUKA DASHBOARD`, menunjukkan tahap serta ringkasan exception, dan mencatat traceback ke `startup-errors.log`. GUI native, APK, dan EXE belum dapat dinyatakan lulus tanpa pengujian langsung pada perangkat target.

## Kawal Trace 2.5.0 — Enkripsi dan konektor audit

Versi 2.5.0 menambahkan penyimpanan pemantauan website terenkripsi AES-256-GCM, koneksi website DNS-pinned untuk menekan risiko DNS rebinding, serta panel konektor SSH/database audit/syslog. Rincian setup, extra dependency, keamanan, dan batas pengujian ada di [`docs/CONNECTORS_READONLY.md`](docs/CONNECTORS_READONLY.md) dan [`docs/WEBSITE_MONITORING.md`](docs/WEBSITE_MONITORING.md). Konektor produksi membutuhkan host/izin/sertifikat dan driver yang disediakan operator; tes lokal tidak berarti semua koneksi jaringan nyata telah diverifikasi.


### Catatan migrasi Kawal Trace 1.0

Jika database identitas lama sudah berisi akun tetapi belum memiliki penanda setup kredensial pribadi, aplikasi akan meminta verifikasi kredensial lama lalu membuat username/kata sandi pribadi baru. Ini sengaja tidak menghapus data pada update. Pada instalasi bersih tanpa akun, layar pertama adalah “Buat akun administrator” dengan semua kolom kosong. Versi tampilan tetap 1.0; nomor build internal saat ini 6.


## Local account setup (v1.0)

- A clean installation shows **Buat akun administrator** before any login screen.
- New usernames must be 4–10 characters; new passwords must be 8–128 characters (passphrases welcome; earlier builds allowed 6–12, and those accounts still sign in). The same checks run in `chainlog.auth`, not only in the form.
- **Accounts belong to one device.** Each device derives an ID (`chainlog/device_identity.py`); accounts are tied to it. A different device sees no accounts and must create its own; accounts from other devices are never deleted or reused. See `docs/DEVICE_ACCOUNTS.md`.
- Accounts created by build 5 and earlier without the `local_credentials_setup_v2` marker enter a one-time verified credential-rotation screen before dashboard access. Enter the old credentials, then select a username of 4–10 characters and a password of 8–128 characters. The application does not delete existing audit history, PINs, target profiles or connector settings. Fresh installs show account creation immediately.
- The PIN-login control is only shown when a PIN has actually been enrolled on that installation. PIN creation/removal remains in the device-trust panel.
- The login header is text-only to avoid the oversized blank image area in packaged builds. The database-audit button uses an icon constant that exists in the pinned Flet dependency.


## Latest screenshot-driven correction

- Login header is text-only; no login banner image is loaded.
- The dashboard builder's invalid `ft.Icons.DATABASE` reference is replaced with `ft.Icons.TABLE_CHART`, fixing the reported `AttributeError: DATABASE` path.
- New account usernames: 4–10 characters. New passwords: 8–128 characters. Legacy current credentials can still be entered at sign-in; they are only constrained when creating new credentials.
- The physical local DB path is no longer displayed in the ordinary audit panel. App-local data remains stored under the per-user/app data directory.
- Native build number is 8 (was 7); visible version remains 1.0. The login, sidebar and diagnostics show `build 8` to make it obvious when an older installed binary is still running.


## Release verification (carried over from build 7; see build 8 below)

- Visible application version remains `1.0`; login/sidebar/diagnostics additionally show the internal build (now `build 8`) so a stale installed executable can be identified.
- Existing accounts from build 5 and earlier without the `local_credentials_setup_v2` marker are sent through a one-time verified credential rotation. This preserves local audit and target data while enforcing the current username/password bounds.
- Fresh installs still show account creation directly. Login PIN appears only when a PIN has actually been enrolled.
- The Windows and Android build scripts remove stale generated `build` output before packaging and check that the requested native artifact exists.
- Source release only. The current environment could not build native Windows/Android artifacts; do not treat source/unit tests as device acceptance.


## Blank main panel — build 7 (superseded by build 8 below)

Build 7 changes the dashboard to mount only the active page inside a dedicated `view_host`, rather than attaching every inactive feature panel to the main scroll column. The right-hand content surface has an explicit dark background. Source tests pass, but Flet native rendering is **not verified in this environment** because the Flet runtime could not be installed.


## Build 8 — navigasi, pemindai offline, backup terenkripsi

* **Navigasi dashboard**: satu badan halaman tetap; sidebar tidak dibangun ulang saat diklik; halaman yang gagal menampilkan kartu error, bukan permukaan kosong. Pola tata letak yang tidak sah di Flutter (`expand` di induk non-fleksibel, `expand` di dalam `Row(wrap=True)`) dihapus dan dijaga linter. **Perbaikan ini belum dilihat pada GUI nyata**; jika area utama masih abu-abu setelah klik menu, kirim `startup-errors.log` (sudah disamarkan) dan jangan menganggap tes headless sebagai bukti render.
* **Pemindai Keamanan** (menu baru): pindai file/`.eml`, tempel teks/URL, lihat riwayat, impor daftar signature/blacklist. Semuanya offline; lihat `docs/SCANNER_AND_BACKUP.md` untuk batas (tidak ada database malware bawaan; model AI dilatih pada data sintetis).
* **Backup & Restore** (menu baru, administrator): backup `.ktbak` terenkripsi, verifikasi (uji pemulihan tanpa menyentuh data aktif), dan pemulihan dengan salinan pengaman. Rahasia di Secure Storage OS tidak ikut dibackup.
* **Ringkasan status** di Dashboard: status website, koneksi, sumber audit, dan agen dipisahkan.
* Model AI phishing: ensemble tulisan-tangan, dievaluasi jujur (bukan 100%); lihat [`docs/AI_MODEL.md`](docs/AI_MODEL.md). Latih ulang: `python -m ml_models.train_model`.
* Menjalankan tes: `pip install -r requirements-dev.txt && python -m pytest -q` (tambahan ekstra `scanner-dev` membuat tes paritas scikit-learn dan API loopback ikut berjalan, bukan dilewati).
* Latih ulang model: `python -m ml_models.train_model --data data_anda.csv`.
