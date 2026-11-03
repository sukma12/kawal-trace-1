# Model AI phishing: apa yang dilakukan, seberapa baik, dan batasnya

Dokumen ini menjelaskan `detectors/phishing_classifier.py`, `detectors/phishing_ensemble.py`, dan `ml_models/`. Semua angka berasal dari
`ml_models/EVALUATION.json` (dihasilkan `python -m ml_models.train_model`); tes `test_phishing_ensemble.py` memastikan berkas itu milik model yang
dikirim. **Baca bagian "Yang tidak boleh disimpulkan" sebelum memakai angka mana pun.**

## 1. Cara kerja

Pesan (teks atau HTML email) dinilai oleh **ensemble** yang berjalan offline di perangkat, tanpa scikit-learn dan tanpa kode yang bisa dieksekusi dari berkas model:

1. **Naive Bayes** atas TF-IDF kata/bigram menghasilkan log-odds "mirip phishing".
2. **Sinyal** (23 fitur 0/1) dari teks dan tautan: permintaan kata sandi/PIN/OTP, tekanan waktu, ancaman blokir, iming-iming hadiah, biaya pencairan,
   permintaan memasang `.apk`, ajakan pindah ke WhatsApp/Telegram, domain yang meniru merek, TLD berisiko, tautan ke hosting gratis, teks tautan yang menipu, dan
   sinyal *pesan sah* (peringatan "jangan bagikan kode", "tidak perlu tindakan").
3. **Regresi logistik** kecil menimbang keduanya. Bobotnya tersimpan di `phishing_model.json` (bagian `stack`) dan bisa dibaca; pesan hasil analisis memuat **alasan** teratas.
4. Skor akhir dipetakan ke **tiga pita**: `SAFE` (< 0.46), `SUSPICIOUS`/MENCURIGAKAN (0.46 sampai < 0.72), `PHISHING` (≥ 0.72).
   Ambang dipilih dari skor *out-of-fold* korpus seed agar pesan sah yang salah ditandai PHISHING ≤ ~2% dan ≥ MENCURIGAKAN ≤ ~10% (target, bukan jaminan).

Status `PHISHING` tetap **perkiraan statistik**, bukan bukti. Pemeriksaan yang pasti (blacklist URL lokal, hash malware) tidak berubah dan tidak digantikan oleh model ini.
Model format 1 lama (hanya Naive Bayes, ambang 70%) masih dapat dimuat.

## 2. Data: apa adanya

* **Korpus seed** (`corpus_seed.py`): 212 pesan **tulisan tangan** (Indonesia + Inggris) dalam 29 "keluarga" (jenis penipuan atau jenis surat sah).
  Berisi kasus sulit: OTP/reset kata sandi sah, peringatan server yang mendesak, newsletter bertautan, serta penipuan tanpa tautan (BEC) dan penipuan di hosting resmi (Google Sites/Forms).
* **Set tantangan** (`corpus_challenge.py`): 85 pesan dari skenario yang **tidak ada** di korpus seed. Tidak pernah dipakai untuk melatih, memilih ambang, atau menyetel apa pun.
* Semuanya **ditulis oleh pengembang aplikasi ini (asisten AI)** karena dataset publik tidak dapat diunduh di lingkungan pembangunan. Ini **bukan** sampel email nyata: email nyata lebih panjang, lebih berantakan, dan lebih beragam.
* Korpus templat lama (800 contoh sintetis, `training_corpus.py`) hanya dipakai sebagai pembanding dan sebagai varian ablasi.

## 3. Cara mengukur

* **Leave-one-group-out (LOGO):** setiap keluarga di-hold-out bergantian dan dinilai oleh model yang belum pernah melihatnya, lewat kode yang sama dengan aplikasi. Skor tumpukan untuk data latihnya sendiri berasal dari Naive Bayes *out-of-fold*, bukan dari model yang sudah menghafalnya.
* **Set tantangan:** model akhir (dilatih pada seluruh seed) dinilai pada skenario baru.
* **Pembanding:** model lama (Naive Bayes pada korpus templat, ambang 0,70) dinilai pada data yang sama.
* Interval kepercayaan 95% memakai metode Wilson. Dengan 40-100 pesan per kelas, intervalnya lebar.

## 4. Hasil

**Model yang dipakai (ensemble)**

* LOGO: AUC 0.974; pita PHISHING: recall 77% (CI95 68%-84%), salah-tandai 3% (CI95 1%-8%); minimal MENCURIGAKAN: recall 89%, salah-tandai 9% (CI95 5%-16%).
* Set tantangan: AUC 0.999; pita PHISHING: recall 95% (CI95 84%-99%), salah-tandai 0% (CI95 0%-8%); minimal MENCURIGAKAN: recall 100%, salah-tandai 9% (CI95 4%-21%).

**Model lama pada data yang sama (ambang 0,70):** pada set tantangan recall 70% dengan salah-tandai **24%** (CI95 14%-39%); pada korpus seed AUC 0.898.
Model lama dilaporkan "akurasi 100%" pada korpus templatnya sendiri; angka itu tidak mengukur apa pun.

**Ablasi: apa yang menyumbang**

| Varian | AUC LOGO | Recall PHISHING | Salah-tandai PHISHING | AUC tantangan |
|---|---|---|---|---|
| Hanya Naive Bayes (dikalibrasi) | 0.926 | 56% | 3% | 0.987 |
| Hanya sinyal teks/tautan | 0.923 | 67% | 3% | 0.997 |
| Ensemble (dipakai) | 0.974 | 77% | 3% | 0.999 |
| Ensemble + data templat berbobot 0,25 | 0.969 | 74% | 3% | 0.989 |

**Per keluarga (LOGO), penipuan**

| Keluarga | n | Ditandai PHISHING | Ditandai ≥ MENCURIGAKAN |
|---|---|---|---|
| `account_alert` | 7 | 86% | 100% |
| `apk_whatsapp` | 7 | 57% | 100% |
| `bank_credential` | 7 | 86% | 100% |
| `compromised_hosting` | 7 | 86% | 100% |
| `crypto_tech_support` | 7 | 100% | 100% |
| `delivery_fee` | 7 | 86% | 100% |
| `document_share` | 7 | 86% | 100% |
| `government_tax` | 7 | 100% | 100% |
| `html_deceptive_links` | 5 | 100% | 100% |
| `impersonation_request` | 7 | 0% | 14% |
| `job_scam` | 7 | 57% | 57% |
| `loan_gambling_spam` | 7 | 86% | 100% |
| `payment_invoice` | 7 | 71% | 100% |
| `prize_lottery` | 7 | 100% | 100% |
| `romance_investment` | 7 | 57% | 71% |

**Per keluarga (LOGO), pesan sah**

| Keluarga | n | Ditandai PHISHING | Ditandai ≥ MENCURIGAKAN |
|---|---|---|---|
| `academic_school` | 8 | 0% | 0% |
| `billing_receipts` | 8 | 0% | 0% |
| `community_org` | 8 | 0% | 0% |
| `dev_tools` | 8 | 0% | 0% |
| `hr_admin` | 8 | 0% | 0% |
| `html_mail_legit` | 5 | 0% | 0% |
| `links_varied_tld` | 8 | 12% | 25% |
| `newsletter_marketing` | 8 | 0% | 0% |
| `ops_alerts` | 8 | 12% | 12% |
| `order_shipping` | 8 | 0% | 12% |
| `personal_chat` | 8 | 0% | 25% |
| `security_notice_legit` | 8 | 12% | 50% |
| `travel_booking` | 8 | 0% | 0% |
| `work_coordination` | 8 | 0% | 0% |

## 5. Kelemahan yang diketahui

* **Penipuan tanpa tautan atau kata kunci (BEC)**, mis. "Pak Direktur, tolong belikan voucher": nyaris tidak terdeteksi (`impersonation_request` di tabel). Teks saja tidak cukup; kebijakan pembayaran (verifikasi lewat telepon) lebih ampuh daripada model apa pun.
* **Pesan sah yang mirip penipuan** tetap salah ditandai: pemberitahuan sertifikat kedaluwarsa, tagihan kartu kredit, notifikasi OTP. Pita MENCURIGAKAN sengaja longgar (target salah-tandai ≈ 10%), jadi ia berarti "periksa manual", bukan "berbahaya".
* **Pengetahuan ahli yang ditanam tangan:** batas bawah bobot untuk `apk_install`, `display_mismatch`, `url_hi`, `url_shortener` (tercatat di `stack.weight_source`). Alasannya: sinyal itu jarang di korpus kecil tetapi kuat di dunia nyata (memasang `.apk` dari pesan adalah jalur malware utama di Indonesia). Ini bukan hasil belajar.
* **Daftar merek, TLD berisiko, dan hosting yang disalahgunakan** ditulis tangan dan akan basi; penjahat berpindah domain.
* **Bahasa:** hanya Indonesia dan Inggris. Pesan bahasa lain umumnya "tidak meyakinkan".
* Model tidak membuka tautan, tidak memeriksa reputasi domain di internet, dan tidak membaca lampiran (lampiran ditangani pemindai berkas).

## 6. Yang tidak boleh disimpulkan

* **AUC set tantangan 0.999 dan salah-tandai 0% hampir pasti membengkak.** Penulisnya sama dengan korpus seed, dan korpus itu punya jalan pintas: tautan phishing buatan saya hampir selalu memakai TLD berisiko (`.top/.xyz/.click`) sementara pesan sah jarang memuat tautan. Saya menambahkan kelompok yang memutus jalan pintas itu, tetapi itu tidak menghapusnya.
* Angka LOGO lebih konservatif, tetapi saya **melihat galat LOGO lalu memperbaiki aturan** (pengecualian domain resmi, batas bawah `.apk`, sinyal hosting). Jadi LOGO sedikit optimistis. Set tantangan tidak dipakai untuk menyetel apa pun, namun saya sempat melihat angka agregatnya sebelum perbaikan itu.
* **Performa pada email nyata belum pernah diukur.** Perkirakan lebih buruk daripada semua angka di atas, terutama pada penipuan baru, bahasa campuran, dan email HTML panjang.
* Satu catatan koreksi: saya sempat menduga skor tinggi pada pesan reset kata sandi sah disebabkan kata kunci di nama host. Dugaan itu salah (kata `signin` ada di path, bukan host). Pengecualian domain resmi tetap dipertahankan karena benar untuk host seperti `support.google.com`, dan kini punya tes yang sungguh mengujinya.

## 7. Melatih ulang dengan data Anda

```
pip install scikit-learn joblib numpy
python -m ml_models.train_model --data data_anda.csv     # kolom: text,label[,group]
```

Isi kolom `group` dengan jenis penipuan/jenis surat supaya evaluasi menahan satu keluarga penuh. Tanpa `group`, baris dibagi ke 10 kelompok semu sehingga hasilnya optimistis bila data
mengandung banyak duplikat mirip. Skrip menulis `phishing_model.json`, `MODEL_MANIFEST.json` (SHA-256; aplikasi menolak model yang hash-nya berbeda), dan `EVALUATION.json`.
`--with-pickle` menulis `.pkl` khusus developer; aplikasi hanya memuatnya bila diminta eksplisit **dan** hash-nya cocok, karena pickle dapat mengeksekusi kode.
Model sengaja ringan: berkas JSON ±354 KB, inferensi Python murni.
