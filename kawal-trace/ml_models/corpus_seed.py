"""Hand-written seed corpus (Indonesian + English), grouped by scam / mail "family".

HONESTY NOTES
* Written by the project author (an AI assistant) because no real mail dataset could be downloaded in the build
  environment. It is NOT a sample of real-world traffic; real phishing is messier, longer and more varied.
* Every message belongs to a `group`. The evaluation holds out a whole group at a time, so a score on a family
  means "the model had never seen this kind of message", which is the question that matters for a new scam.
* Domains are invented look-alikes; none are meant to resolve and they are never fetched.
* Hard negatives are included on purpose: genuine OTP / password-reset / security notices, server alerts with
  urgent wording, newsletters with links. A model that only learns "urgent + password = phishing" fails these.

Format of each block: one message per line as `group::text`.
"""
from __future__ import annotations

PHISHING_BLOCK = """
bank_credential::Yth. Nasabah, akun m-banking Anda terindikasi aktivitas tidak wajar dan akan dibekukan. Lakukan verifikasi data (nomor kartu, PIN, kode OTP) melalui http://bri-verifikasi-nasabah.top/m dalam 1x24 jam.
bank_credential::INFO BCA: perubahan tarif transfer mulai berlaku. Untuk tetap menikmati layanan, konfirmasi ulang KlikBCA Anda di https://klikbca-update.xyz/login. Diabaikan = akun diblokir.
bank_credential::Dear customer, we noticed a sign-in to your online banking from a new device. To keep your account active, please confirm your card number, CVV and one-time passcode here: http://secure-bankverify.click/auth
bank_credential::Your debit card has been temporarily restricted. Restore access by completing identity verification at https://card-restore.support/verify today.
bank_credential::Bank Mandiri: kartu ATM Anda akan kedaluwarsa. Perbarui data dan PIN sekarang agar tidak ditutup https://livin-mandiri.online/update
bank_credential::Hello, this is the fraud department. We blocked a suspicious payment of $842.15. If it wasn't you, reply with your online banking username and the SMS code we just sent.
bank_credential::Pak/Bu, ada transaksi mencurigakan Rp 4.750.000 dari rekening Anda. Jika bukan Anda, balas pesan ini dengan nomor rekening, PIN, dan kode OTP untuk pembatalan.
delivery_fee::Paket JNE Anda dengan resi 0023987412 tertahan di gudang karena alamat kurang lengkap. Lengkapi data dan bayar ongkir Rp 3.500 di http://jne-lacak.top/resi
delivery_fee::USPS: your parcel could not be delivered due to an incomplete address. Update delivery details and pay the $1.99 redelivery fee: http://usps-redeliver.icu/pay
delivery_fee::DHL Express notice: a customs clearance fee of 2.40 EUR is outstanding for shipment 7721 4410. Pay within 48 hours to avoid return to sender https://dhl-customs-fee.work/track
delivery_fee::J&T: paket COD atas nama Anda gagal diantar 2x. Konfirmasi ulang dan transfer biaya administrasi agar dikirim ulang https://bit.ly/3Qk9ZaL
delivery_fee::Kurir kami sudah di depan rumah tapi nomor Anda tidak aktif. Klik untuk atur ulang jadwal dan bayar biaya penanganan: http://sicepat-jadwal.click/atur
delivery_fee::Your package is on hold. A small handling fee is required before we can deliver it. Pay now at tinyurl.com/pkg-release-88
delivery_fee::Notifikasi pengiriman: pesanan internasional Anda ditahan Bea Cukai. Bayar pajak impor Rp 85.000 melalui link berikut agar barang dilepas http://beacukai-bayar.site/p
prize_lottery::SELAMAT! Nomor Anda terpilih sebagai pemenang undian Tokopedia periode ini berhadiah Honda Vario. Hubungi panitia di WhatsApp 0812-9988-7766 untuk klaim, siapkan KTP dan nomor rekening.
prize_lottery::You are today's lucky winner of a $500 Amazon gift card! Only 3 left. Claim it before midnight: http://amzn-rewards.top/claim
prize_lottery::Anda mendapat bonus saldo DANA Rp 750.000 dari program loyalitas. Klaim dalam 10 menit lewat http://dana-kaget-promo.xyz sebelum hangus.
prize_lottery::Congratulations, your email was randomly selected in the Microsoft International Lottery. Reply with your full name, address and phone number to receive 850,000 GBP.
prize_lottery::Survei kepuasan pelanggan Shopee berhadiah iPhone 15! Isi 3 pertanyaan lalu masukkan data kartu untuk biaya pengiriman hadiah: https://shopee-hadiah.click/survey
prize_lottery::Your Netflix customer survey reward: a free 12-month subscription. Complete the survey and confirm your payment details to activate http://nflx-reward.online/s
prize_lottery::Kamu beruntung! Cashback 100% untuk 50 orang pertama, cukup login dengan akun Instagram kamu di https://ig-cashback.top/login
payment_invoice::Please find the attached invoice INV-20418 that is now overdue. Open the secure document and sign in with your Microsoft 365 email to view it: https://onedrive-docs.support/view
payment_invoice::Terlampir tagihan jatuh tempo bulan ini. Mohon segera dibayar, detail pembayaran dapat dilihat di http://tagihan-online-pay.site/invoice/8841 (login dengan email Anda).
payment_invoice::Subscription renewal: your antivirus plan was automatically renewed for $349.99. If you did not authorize this, call our billing support immediately at +1-888-555-0143 to cancel and get a refund.
payment_invoice::Payment declined. We were unable to process your Netflix membership. Update your payment method within 24 hours or your account will be cancelled: http://netflix-billing-help.click/update
payment_invoice::Tagihan listrik PLN Anda bulan ini Rp 1.856.400 belum terbayar, ancaman pemutusan 2 hari lagi. Bayar via http://pln-bayar-cepat.top/tagihan
payment_invoice::Hello, kindly confirm receipt of the payment advice attached and update the beneficiary bank details as requested in the document.
payment_invoice::Faktur pajak belum lengkap. Unduh dan isi formulir terlampir (.htm), lalu masukkan akun email kantor Anda untuk validasi.
account_alert::Security alert: someone just used your password to try to sign in to your Google Account. Secure your account now: https://accounts-google-security.xyz/recover
account_alert::Your Apple ID was locked for security reasons. Unlock it by verifying your identity at https://appleid-unlock.click/ within 24 hours or it will be permanently disabled.
account_alert::Akun Instagram Anda dilaporkan melanggar hak cipta dan akan dihapus. Ajukan banding dalam 24 jam melalui https://ig-appeal-center.top/form
account_alert::PERINGATAN: akun Facebook Anda login dari Rusia. Jika ini bukan Anda, amankan akun dengan memasukkan kata sandi di https://fb-secure-login.online
account_alert::Your mailbox storage is 98% full. Incoming mail will be rejected. Click to upgrade storage and re-enter your email password: http://webmail-quota.support/upgrade
account_alert::We detected a new login to your Microsoft account from Lagos, Nigeria. If this wasn't you, review the activity: http://192.46.210.75/ms/review
account_alert::Verifikasi 2 langkah Anda dinonaktifkan. Aktifkan kembali dengan kode yang dikirim ke nomor Anda, lalu kirimkan kode itu ke admin di sini.
apk_whatsapp::Kepada Yth. Bapak/Ibu, berikut kami sampaikan Undangan Pernikahan Digital (Undangan.apk). Mohon dibuka dan install aplikasinya untuk melihat detail acara.
apk_whatsapp::Halo, ini foto dokumentasi kemarin ya, silakan unduh file FOTO_KEGIATAN.apk lalu install.
apk_whatsapp::SURAT TILANG ELEKTRONIK (ETLE) atas kendaraan Anda. Unduh aplikasi cek tilang resmi: http://etle-polri-cek.top/etle.apk
apk_whatsapp::Lihat resi pengiriman paket Anda di sini, pasang aplikasi pelacak Resi_Paket.apk agar update tampil otomatis. Izinkan semua akses ya.
apk_whatsapp::Tagihan BPJS Anda menunggak. Buka file Tagihan_BPJS_2026.apk untuk melihat rincian.
apk_whatsapp::Hey, I'm sharing the photos from the trip. Install the viewer app (photos_viewer.apk) first and allow all permissions to open them.
apk_whatsapp::Bapak/Ibu mendapat bantuan bansos tahap baru. Install aplikasi pencairan resmi (bansos-cair.apk) lalu verifikasi dengan KTP dan wajah.
job_scam::Lowongan kerja part time dari rumah, cukup like dan subscribe video. Gaji Rp 300rb - 1,5jt per hari dibayar langsung. Minat? Chat WhatsApp 0838-1100-2244 atau grup Telegram t.me/loker_online_88
job_scam::We are hiring remote assistants. $400/day for 2 hours of work, no experience needed. Message our HR on Telegram @hr_global_jobs to get started.
job_scam::Dibutuhkan admin online shop. Modal 0. Tugas: transfer deposit awal Rp 200.000 sebagai jaminan, dikembalikan dengan bonus 30% dalam 1 jam.
job_scam::Congratulations! After reviewing your resume you have been shortlisted. To process your onboarding, purchase the company equipment starter kit from our approved vendor and send the receipt.
job_scam::Kerja santai tinggal klik iklan, komisi cair tiap hari. Gabung sekarang, kuota terbatas! Daftar di http://klik-cuan-harian.xyz
job_scam::Mystery shopper wanted. We will send you a check for $2,450. Deposit it, keep $300 as your pay and wire the rest to our evaluator.
job_scam::Anda lolos seleksi tahap awal PT Global Sukses. Kirim biaya administrasi training Rp 500.000 ke rekening berikut untuk konfirmasi kehadiran.
impersonation_request::Are you at your desk? I need you to handle something confidential and time-sensitive. Reply as soon as you get this. Michael (CEO)
impersonation_request::Please process an urgent wire transfer of $18,400 to the new vendor account below today. I'm in meetings and can't take calls. I'll approve it later.
impersonation_request::Pagi, ini Pak Direktur. Tolong belikan voucher Google Play 5 x Rp 1.000.000 sekarang, kodenya kirim ke saya via chat. Nanti saya ganti. Jangan beri tahu yang lain dulu.
impersonation_request::Hi, it's your manager. I'm travelling and my phone is broken. Can you buy 4 Apple gift cards of $200 each and email me the codes? I'll reimburse you.
impersonation_request::Mohon ubah rekening pembayaran vendor kita ke nomor rekening baru berikut mulai pembayaran hari ini. Surat pemberitahuan terlampir. Segera ya, jangan telepon.
impersonation_request::Following our conversation, please update payroll direct deposit details for the attached employee as the previous account was closed.
impersonation_request::Halo bunda, ini nomor baru mama ya, HP lama rusak. Mama lagi butuh bantuan transfer dulu Rp 2.500.000, nanti diganti, tolong ya jangan dikasih tahu papa.
crypto_tech_support::Important: your wallet must be re-validated after the network upgrade. Enter your 12-word recovery phrase at https://metamask-validate.top to avoid losing your funds.
crypto_tech_support::Free airdrop of 5,000 tokens for early holders. Connect your wallet to claim: https://airdrop-claim-eth.xyz
crypto_tech_support::Microsoft Support alert: your computer is infected with 3 viruses. Do not shut down. Call +1-855-555-0188 immediately; a certified technician will remove them via remote access.
crypto_tech_support::Binance: penarikan Rp 25 juta dari akun Anda sedang diproses. Jika bukan Anda, batalkan di https://binance-cancel-withdraw.click dengan login dan kode 2FA.
crypto_tech_support::Your Coinbase account has been limited. Verify your seed phrase and ID to restore trading: http://coinbase-restore.support
crypto_tech_support::Ikuti sinyal trading kripto kami, profit 20% per hari dijamin. Deposit minimal 1 juta, tarik kapan saja. Daftar https://cuan-kripto-pro.site
crypto_tech_support::We have recorded you visiting adult websites. Pay $1,200 in Bitcoin to this wallet within 48 hours or we send the video to your contacts.
government_tax::DJP Online: terdapat selisih pajak SPT Anda. Segera lakukan koreksi melalui http://djp-koreksi-spt.top/login paling lambat 3 hari untuk menghindari denda.
government_tax::HMRC: you are eligible for a tax refund of 384.50 GBP. Submit your bank details to receive the payment: https://hmrc-refund-gov.click/claim
government_tax::Polda Metro Jaya: Anda tercatat melakukan pelanggaran lalu lintas. Lihat bukti foto dan bayar denda melalui https://etilang-bayar.site/denda
government_tax::IRS Notice CP-2000: unpaid balance detected. Failure to respond will result in legal action and wage garnishment. Call the number below within 24 hours.
government_tax::BPJS Kesehatan: kartu Anda akan dinonaktifkan karena data tidak valid. Perbarui NIK dan foto KTP di https://bpjs-update-data.online
government_tax::Pemberitahuan resmi Dukcapil: e-KTP Anda perlu aktivasi ulang. Kirim foto KTP dan swafoto ke nomor admin 0821-3344-9900.
government_tax::Government grant approved: you qualify for $9,000 in federal relief. Pay a $150 processing fee to release the funds.
romance_investment::Hi dear, I saw your profile and feel a real connection. I'm an engineer on an oil rig and I'd love to get to know you. Can we chat on WhatsApp? +44 7700 900123
romance_investment::Halo kak, aku Lisa dari Singapura. Aku punya tips investasi emas digital yang bikin untung 5x lipat dalam seminggu. Mau aku ajarin? Bergabung di grup VIP kami.
romance_investment::My late father left me 4.5 million USD in a trust account and I need a trustworthy partner abroad to help transfer it. You will receive 30% for your help.
romance_investment::Kak, platform investasi ini sudah terbukti. Deposit 5 juta jadi 15 juta dalam 3 hari. Aku sudah withdraw, ini buktinya. Daftar lewat link aku ya https://invest-mega-profit.top/ref=2291
romance_investment::I've been making $1,500 a week with this AI trading bot. Send me a message and I'll show you how. Limited spots left.
romance_investment::Saya Dokter Andrew dari Amerika, ingin mengirim paket hadiah untuk Anda. Tolong transfer biaya pajak pengiriman dulu ya.
romance_investment::Dear beneficiary, funds of 2.3M USD have been approved for release to you. Kindly provide your bank account, passport copy and the clearance fee.
loan_gambling_spam::PINJAMAN CEPAT cair 10 menit tanpa jaminan! Limit sampai 20 juta, tanpa BI checking. Download aplikasi di http://pinjam-kilat88.top lalu izinkan akses kontak dan galeri.
loan_gambling_spam::SLOT GACOR hari ini maxwin! Deposit 10rb langsung bonus 100%. Daftar di https://gacor-win777.xyz link alternatif terbaru.
loan_gambling_spam::Anda terdaftar di data pinjol, tagihan jatuh tempo. Jika tidak dibayar hari ini, data dan foto Anda akan kami sebar ke semua kontak.
loan_gambling_spam::Online casino bonus! Get 300% on your first deposit and 100 free spins. Register at http://royal-spin-bonus.click today only.
loan_gambling_spam::Toto togel prediksi jitu malam ini, bocoran angka main hanya di https://bocoran-togel-akurat.site
loan_gambling_spam::Butuh dana mendesak? Kami bantu cairkan pinjaman Rp 5-50 juta, syarat KTP saja. Admin: 0877-4400-1122. Biaya asuransi dibayar di muka.
loan_gambling_spam::Get an instant loan with no credit check. Pay the processing fee upfront and the money is in your account within the hour.
document_share::Mike shared a document with you: 'Q3 Salary Revision.xlsx'. Sign in with your work email to open it https://sharepoint-docs-view.click/doc
document_share::You have 3 pending voicemail messages. Listen to them here: http://voicemail-playback.top/v?id=551 (login required)
document_share::Dokumen penting dari HRD: 'Perubahan Gaji 2026.pdf' dikirim melalui drive. Klik Buka Dokumen lalu masuk dengan akun email kantor https://drive-docs-hrd.xyz
document_share::Your account requires re-authentication. Scan the attached QR code with your phone and sign in to continue.
document_share::Anda dikirimi pesan terenkripsi. Untuk membacanya, verifikasi akun email Anda terlebih dahulu di tautan ini http://secure-msg-read.top/v
document_share::Your Zoom meeting recording is ready. Sign in to view it or it will be deleted in 24 hours http://zoom-recordings-share.support/r
document_share::Docusign: please review and sign the contract. Access the document using your email password: http://docusign-view.work/sign
compromised_hosting::Pembaruan data nasabah wajib dilakukan hari ini. Isi formulir verifikasi di https://sites.google.com/view/bca-verifikasi-nasabah agar rekening tidak diblokir.
compromised_hosting::Your parcel is waiting. Confirm your address and card details on https://forms.gle/Qx7vN2aKp9LmT4b to schedule delivery.
compromised_hosting::Klaim bantuan sosial Anda di https://linktr.ee/bansos.cair.2026 dan isi NIK serta nomor rekening.
compromised_hosting::Sign in to review the shared file: http://www.kopikita-cafe.com/wp-content/uploads/office365/login.php
compromised_hosting::Akun Anda perlu diverifikasi. Buka https://docs.google.com/forms/d/e/1FAIpQLSd9xKq/viewform lalu isi kata sandi email Anda.
compromised_hosting::Security notice: confirm your identity at https://storage.googleapis.com/secure-check-9912/verify.html within 24 hours or access will be removed.
compromised_hosting::Tagihan pajak kendaraan Anda: bayar sekarang di http://tokobunga-mawar.co.id/img/pajak/bayar.php sebelum denda berlaku.
html_deceptive_links::<p>Dear user, your PayPal account needs attention. <a href="http://paypal-resolution-center.top/login">https://www.paypal.com/myaccount</a> Please log in to restore access.</p>
html_deceptive_links::<html><body>Akun BRI Anda perlu verifikasi. Klik <a href="http://bri-token-update.xyz/m">www.bri.co.id</a> dan masukkan PIN serta OTP.</body></html>
html_deceptive_links::<div>Invoice ready: <a href="http://doc-share-view.click/inv">view at microsoft.com/invoices</a>. Sign in with your Microsoft password to open.</div>
html_deceptive_links::<p>Netflix: pembayaran gagal. <a href="https://netflix-help-center.online/pay">netflix.com/pembayaran</a> perbarui kartu Anda dalam 24 jam.</p>
html_deceptive_links::<p>Your Amazon gift card is waiting: <a href="http://bit.ly/3KpQw9x">amazon.com/giftcard</a> claim it now before it expires.</p>
"""

LEGITIMATE_BLOCK = """
work_coordination::Hi team, the weekly sync is moved to Thursday 10:00. The agenda is in the shared drive; please add your items before Wednesday noon.
work_coordination::Terlampir notulen rapat koordinasi kemarin. Mohon dicek, jika ada koreksi kabari saya paling lambat Jumat.
work_coordination::Reminder: sprint review tomorrow at 2 pm in room 4B. The remote link is in the calendar invite.
work_coordination::Pak, draf proposal sudah saya revisi sesuai masukan. Tolong dilihat lagi ya, besok pagi saya presentasikan.
work_coordination::Can you send me the latest numbers for the Q3 forecast when you have a moment? No rush, end of the week is fine.
work_coordination::Rekan-rekan, mohon isi daftar hadir pelatihan di formulir yang dibagikan di grup. Terima kasih.
work_coordination::Quick update: the vendor confirmed delivery for next Tuesday. I'll forward the confirmation once I get it.
work_coordination::Selamat pagi, jadwal piket minggu ini sudah saya tempel di papan pengumuman dan di grup divisi.
order_shipping::Thanks for your order #48213. Your items will ship tomorrow and we'll email the tracking number. You can view your order any time in your account on our website.
order_shipping::Pesanan Anda di Tokopedia telah dikirim. Nomor resi JNE 0034871120. Lacak melalui aplikasi atau https://www.tokopedia.com/order/status
order_shipping::Your Amazon order has shipped and will arrive Thursday. Track the package at https://www.amazon.com/progress-tracker
order_shipping::Paket Anda sudah sampai di titik pengambilan. Tunjukkan kode pengambilan di aplikasi Anda kepada petugas. Tidak ada biaya tambahan.
order_shipping::Your food delivery is on its way! Driver Budi will arrive in about 12 minutes.
order_shipping::Pesanan #SHP-77120 berhasil dibayar. Terima kasih sudah berbelanja, estimasi tiba 3-4 hari kerja.
order_shipping::Your return has been received and your refund of $24.50 will appear on your original payment method within 5-7 business days.
order_shipping::Receipt for your purchase at Warung Kopi Senja. Total Rp 48.000 dibayar dengan QRIS.
security_notice_legit::Your password was changed successfully. If this was you, no further action is needed.
security_notice_legit::Kode OTP Anda adalah 482913. Berlaku 5 menit. JANGAN BERIKAN kode ini kepada siapa pun termasuk pihak yang mengaku dari kami.
security_notice_legit::We noticed a new sign-in to your GitHub account from Chrome on Windows. If this was you, you can ignore this email. If not, reset your password at https://github.com/settings/security
security_notice_legit::Verifikasi email berhasil. Selamat datang di Kawal App, akun Anda sudah aktif.
security_notice_legit::Use code 619274 to verify your sign-in. Never share this code with anyone. We will never ask you for it.
security_notice_legit::Anda meminta reset kata sandi. Klik tombol di bawah dalam 60 menit: https://accounts.google.com/signin/recovery. Jika bukan Anda, abaikan email ini.
security_notice_legit::Pemberitahuan: login baru ke akun Anda dari perangkat Samsung A54 di Pontianak pada 14:32. Jika ini Anda, tidak perlu melakukan apa pun.
security_notice_legit::Your two-step verification was turned on. You'll now be asked for a code when signing in on a new device.
newsletter_marketing::Newsletter: this month we released three product updates. Read the release notes on our official blog https://blog.example.org/releases and let us know what you think.
newsletter_marketing::Promo Gajian! Diskon hingga 40% untuk semua produk fashion hanya tanggal 25-27. Syarat dan ketentuan berlaku. Belanja di aplikasi resmi kami.
newsletter_marketing::New arrivals are here: spring collection, free shipping over $50. You can unsubscribe any time from your account settings.
newsletter_marketing::Webinar gratis: dasar-dasar keamanan siber untuk UMKM, Sabtu 10.00 WIB. Daftar di https://events.example.org/cyber-umkm
newsletter_marketing::Your weekly digest: 5 articles picked for you, plus a recipe for nasi goreng kampung.
newsletter_marketing::Hai Kak, voucher ulang tahun Rp 25.000 sudah masuk ke akun kamu dan berlaku sampai akhir bulan. Cek di aplikasi.
newsletter_marketing::Thanks for subscribing! You'll get one email a week with new tutorials. No spam, unsubscribe anytime.
newsletter_marketing::Festival kuliner akhir pekan ini di Alun-Alun Kapuas, gratis masuk. Ajak keluarga ya!
billing_receipts::Your invoice for last month is attached for your records. No action is required; payment was collected automatically.
billing_receipts::Transaksi berhasil: transfer Rp 1.250.000 ke Budi Santoso pada 12/10 09:14. Simpan bukti ini. Info lebih lanjut hubungi 14000 atau aplikasi resmi.
billing_receipts::Your subscription renews on November 3 for $9.99. Manage or cancel any time in Settings > Subscriptions in the app.
billing_receipts::Tagihan listrik bulan Oktober Rp 312.450 sudah dibayar lunas via m-banking. Terima kasih.
billing_receipts::Payment received: thank you. Receipt #5521 for your annual domain renewal is available in your dashboard.
billing_receipts::Rekening koran Anda periode September tersedia dan dikirim sebagai lampiran terenkripsi; kata sandinya adalah tanggal lahir Anda (DDMMYYYY).
billing_receipts::Reminder: your gym membership payment of Rp 350.000 will be debited on the 5th. No action needed unless you want to change your plan.
billing_receipts::Pembayaran SPP semester ganjil telah kami terima. Kuitansi terlampir. Terima kasih.
personal_chat::Bro, jadi nonton nanti malam? Aku jemput jam 7 ya, parkirnya di basement.
personal_chat::Mom, I got the job! Starting next Monday. I'll call you after dinner.
personal_chat::Kak, makasih ya buat oleh-olehnya kemarin, enak banget lempernya. Salam buat ibu.
personal_chat::Hey, are we still on for lunch Friday? That new Thai place near the office looks good.
personal_chat::Besok kita kumpul di rumah nenek jam 10, bawa makanan masing-masing ya. Jangan telat.
personal_chat::Sorry I missed your call, I was on the train. Call me back when you're free.
personal_chat::Sudah sampai rumah? Hati-hati di jalan ya, hujan deras banget di sini.
personal_chat::Ini foto-foto liburan kemarin, aku taruh di album bersama di Google Photos, kamu sudah dapat undangannya?
dev_tools::Pull request #87 was merged into main after two approvals. Release is planned for next sprint https://github.com/org/repo/pull/87
dev_tools::Build #1204 failed on branch feature/login. 2 tests failed in test_session.py. See logs: https://ci.example.org/builds/1204
dev_tools::Dependabot opened a pull request to bump httpx from 0.27.0 to 0.28.1.
dev_tools::Issue #312: crash when opening settings on Android 12. Could you share the logcat output?
dev_tools::Your deployment to production completed successfully at 14:05 UTC. No errors reported.
dev_tools::Reminder: your API key 'ci-readonly' will expire in 7 days. Create a new key in the dashboard under Settings > API.
dev_tools::Review requested: add rate limiting to the login endpoint (#451). Please take a look when you can.
dev_tools::Server alert: disk usage on db-01 reached 91%. Please clean old logs or extend the volume before it fills.
academic_school::Jadwal kuliah semester ini sudah tersedia di portal akademik resmi https://siakad.example.ac.id. Mohon cek bentrok mata kuliah sebelum 20 Agustus.
academic_school::Dear students, the midterm exam will be held on Oct 21 in Hall B. Bring your student ID and a pencil.
academic_school::Pengumuman: kegiatan belajar mengajar libur pada tanggal merah, kembali normal keesokan harinya.
academic_school::Tugas akhir bab 2 dikumpulkan paling lambat Jumat pukul 23.59 lewat LMS. Format dan template sudah ada di materi minggu ini.
academic_school::Parent-teacher meeting is scheduled for Saturday at 9 am. Please confirm attendance by replying to this email.
academic_school::Selamat, proposal skripsi Anda disetujui. Silakan hubungi pembimbing untuk jadwal bimbingan.
academic_school::Library notice: the book you reserved is ready for pickup until Friday.
academic_school::Beasiswa tahun ini dibuka sampai 30 November. Persyaratan lengkap tersedia di bagian kemahasiswaan dan papan pengumuman fakultas.
hr_admin::Your payslip for October is now available in the HR portal. You can access it from the intranet at https://intranet.example.org/hr as usual.
hr_admin::Pengajuan cuti Anda tanggal 5-7 November telah disetujui oleh atasan. Selamat berlibur!
hr_admin::Welcome aboard! Your first day is Monday at 9 am. Please bring your ID and bank details for payroll; HR will meet you at reception.
hr_admin::Mohon lengkapi data BPJS Ketenagakerjaan di bagian HRD paling lambat akhir bulan. Cukup bawa fotokopi KK dan KTP ke ruang HRD.
hr_admin::Reminder: annual performance reviews start next week. Please complete your self-assessment in the HR system.
hr_admin::Undangan townhall bulanan, Jumat 15.00 di aula lantai 3. Tautan online dikirim lewat kalender.
hr_admin::Company policy update: remote work days are now up to 3 per week. The full policy is attached.
hr_admin::Pemberitahuan: kantor tutup lebih awal pukul 15.00 pada hari Jumat karena acara internal.
travel_booking::Your e-ticket for flight GA 421 Jakarta - Pontianak on Nov 12 is attached. Check-in opens 24 hours before departure in the airline's official app.
travel_booking::Booking confirmed: Hotel Orchid, 2 nights from 5 Dec. Free cancellation until 3 Dec. Confirmation code HB-88231.
travel_booking::Tiket kereta Anda Bandung - Gambir berangkat 07.20, kursi 5C. Tunjukkan KTP saat boarding.
travel_booking::Your ride receipt: Rp 32.000, pickup Jl. Gajah Mada, drop-off Bandara Supadio.
travel_booking::Reminder: your check-out time is 12:00. Late check-out can be requested at the front desk.
travel_booking::Itinerary update: your tour starts at 08:30 sharp from the hotel lobby. Bring water and a hat.
travel_booking::Visa application received. We'll notify you by email once the embassy completes processing. Processing typically takes 5 business days.
travel_booking::Your rental car is ready for pickup at counter 3. Please bring your driving licence and the card used for booking.
community_org::Bapak/Ibu warga RT 05, kerja bakti membersihkan parit diadakan Minggu pagi jam 7. Mohon membawa peralatan masing-masing.
community_org::Jadwal pengajian rutin malam Jumat dimulai ba'da Isya di masjid. Konsumsi disediakan bergiliran.
community_org::Church choir rehearsal is moved to Wednesday 6:30 pm. Please bring your scores.
community_org::Info donor darah PMI: Sabtu ini di balai desa pukul 08.00-12.00. Terbuka untuk umum.
community_org::The neighbourhood watch meeting is next Tuesday at the community hall. Topics: street lighting and parking.
community_org::Arisan bulan ini di rumah Bu Ratna hari Minggu jam 3 sore. Jangan lupa iuran ya.
community_org::Pengumuman iuran kebersihan bulan November: Rp 25.000 per KK, bisa diserahkan langsung ke bendahara RT.
community_org::Volunteers needed for the food bank this Saturday. The sign-up sheet is at the community centre.
ops_alerts::[ALERT] CPU usage on web-02 above 90% for 10 minutes. Auto-scaling triggered. No action required unless it persists.
ops_alerts::Peringatan: sertifikat SSL untuk api.example.org akan kedaluwarsa dalam 14 hari. Segera perbarui melalui panel hosting.
ops_alerts::Backup harian selesai pukul 02:10. Ukuran 3,2 GB, status: sukses.
ops_alerts::SSH login failed 5 times for user deploy from 203.0.113.9. IP blocked for 15 minutes by fail2ban.
ops_alerts::Urgent: payment gateway latency is elevated. Engineers are investigating; the status page will be updated every 30 minutes.
ops_alerts::Pemeliharaan terjadwal Minggu 02.00-04.00 WIB, layanan mungkin tidak tersedia sementara.
ops_alerts::Your domain example.org will expire on Dec 1. Enable auto-renew in your registrar account to avoid interruption.
ops_alerts::Monitoring: website uptime 99.98% in the last 30 days. Report attached.
links_varied_tld::Dokumentasi proyek dan changelog bisa dilihat di https://docs.kawalproject.id/changelog. Silakan beri masukan lewat issue tracker.
links_varied_tld::Our new site is live at https://studio-kopi.xyz - come visit our roastery this weekend and try the new single origin.
links_varied_tld::Pendaftaran lomba desain terbuka di https://lombadesain.online sampai 30 November, gratis untuk pelajar.
links_varied_tld::Hasil pengumuman seleksi bisa dicek di https://pengumuman.univ-contoh.ac.id/seleksi dengan nomor peserta Anda.
links_varied_tld::The recording of today's talk is available at https://youtu.be/dQw4w9WgXcQ for the next 30 days.
links_varied_tld::Berikut tautan Zoom untuk rapat besok: https://zoom.us/j/9876543210. Kode rapat dikirim terpisah oleh panitia.
links_varied_tld::Invoice dan laporan bulanan tersedia di portal https://billing.example.co.id/laporan setelah login seperti biasa.
links_varied_tld::You can download the installer from the official page https://www.videolan.org/vlc/ and verify the checksum listed there.
html_mail_legit::<p>Halo, berikut <a href="https://www.tokopedia.com/order/status">status pesanan Anda</a>. Terima kasih sudah berbelanja!</p>
html_mail_legit::<html><body>Read our <a href="https://blog.example.org/releases">release notes</a> for this month. Unsubscribe from <a href="https://example.org/unsub">settings</a>.</body></html>
html_mail_legit::<div>Your GitHub notification: <a href="https://github.com/org/repo/issues/312">issue 312</a> was updated.</div>
html_mail_legit::<p>Reset your password using <a href="https://accounts.google.com/signin/recovery">this secure link</a>. If you did not request it, ignore this email.</p>
html_mail_legit::<p>Jadwal lengkap ada di <a href="https://www.pajak.go.id/jadwal">pajak.go.id/jadwal</a>; pelaporan dilakukan sendiri tanpa perantara.</p>
"""


def _parse(block: str, label: int) -> list[tuple[str, int, str]]:
    rows: list[tuple[str, int, str]] = []
    for line in block.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        group, _, text = line.partition("::")
        if not group or not text:
            raise ValueError(f"baris korpus tidak valid: {line[:60]!r}")
        rows.append((group.strip(), label, text.strip()))
    return rows


def seed_rows() -> list[tuple[str, int, str]]:
    """[(group, label, text)] — label 1 = phishing/scam, 0 = legitimate."""
    return _parse(PHISHING_BLOCK, 1) + _parse(LEGITIMATE_BLOCK, 0)
