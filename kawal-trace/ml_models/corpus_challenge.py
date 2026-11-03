"""Challenge set: scenarios that do NOT appear in `corpus_seed.py`.

Never used for training, threshold selection or any tuning; it is only read by the evaluation. It is still
written by the same author as the seed corpus, so it shares that author's habits and is NOT independent
ground truth. With 40 + 40 messages the numbers carry wide uncertainty (the evaluation prints intervals).
Same line format as the seed corpus: `group::text`.
"""
from __future__ import annotations

from .corpus_seed import _parse

PHISHING_BLOCK = """
telco_sim::Telkomsel: nomor Anda belum registrasi ulang dan akan diblokir 24 jam lagi. Registrasi dengan NIK dan KK di https://telkomsel-registrasi.click/sim
telco_sim::Kartu SIM Anda akan dinonaktifkan karena data tidak sesuai aturan. Segera kirim foto KTP ke nomor CS berikut 0813-5566-7788.
telco_sim::Your mobile carrier: your account has been flagged for an unpaid balance. Pay now to avoid SIM deactivation: http://carrier-pay.support/bal
telco_sim::Selamat Anda dapat kuota gratis 100GB dari XL! Klik dan masukkan nomor dan kode OTP yang masuk: https://xl-kuota-gratis.top
marketplace_refund::Shopee: pengembalian dana Rp 389.000 untuk pesanan dibatalkan siap dicairkan. Masukkan data rekening dan kode verifikasi di https://shopee-refund-id.click
marketplace_refund::Penjual meminta pindah transaksi ke WhatsApp supaya lebih murah, transfer langsung ke rekening pribadi ini. Pembayaran lewat aplikasi ditutup.
marketplace_refund::eBay: your item was sold! Release the funds by confirming your PayPal login at http://ebay-seller-confirm.xyz
marketplace_refund::Pembeli ingin COD tetapi kurir perlu deposit. Mohon transfer jaminan Rp 150.000 dulu, nanti dikembalikan bersama uang barang.
insurance_loan::Polis asuransi Anda gagal diperpanjang. Untuk menghindari hangus, lakukan pembayaran premi via http://asuransi-bayar-polis.top/p
insurance_loan::Pencairan klaim asuransi Rp 12.500.000 menunggu. Konfirmasi dengan nomor rekening, PIN ATM dan kode OTP.
insurance_loan::Your loan has been pre-approved for $15,000. Pay the $250 insurance fee first to release the funds.
insurance_loan::Kredit tanpa agunan disetujui! Transfer biaya provisi Rp 750.000 terlebih dahulu untuk pencairan hari ini.
utility_scam::PLN: meteran Anda akan diganti, jadwalkan teknisi dan bayar biaya penggantian di https://pln-meter-baru.xyz
utility_scam::Token listrik gratis dari pemerintah! Masukkan nomor ID pelanggan dan nomor HP lalu verifikasi OTP: http://token-gratis-pln.click
utility_scam::Water utility notice: your account is overdue. Pay immediately by card to avoid service disconnection http://aqua-bill-pay.top
utility_scam::Subsidi listrik Anda dicabut. Ajukan keberatan dengan mengisi data KTP dan kartu keluarga di link ini.
social_engineering::Hi, I found your phone while out. Click here to see where I left it https://found-phone-info.icu/id
social_engineering::Kak tolong vote anakku di lomba menggambar ya, klik link ini dan login dengan Facebook https://vote-lomba-anak.top/vote
social_engineering::Is this you in this video?? http://bit.ly/3zTqXk2
social_engineering::Mas, ini aku teman SMA kamu. Lagi ada kesulitan, boleh pinjam uang 1 juta dulu? Kirim ke rekening teman aku ya.
government_id::Kemendikbud: dana PIP siswa Anda cair. Verifikasi NISN dan rekening di https://pip-kemdikbud-cair.site
government_id::Bantuan Langsung Tunai Rp 600.000 tahap 3. Cek penerima dengan memasukkan NIK dan nomor ATM di http://blt-cek-penerima.top
government_id::Passport office: your renewal application has a problem. Pay the $85 correction fee here http://passport-renew-help.click
government_id::Pemberitahuan Imigrasi: paspor Anda ditahan. Hubungi petugas di nomor ini dan siapkan biaya pembebasan.
gaming_streaming::Free Robux generator! Enter your username and password to receive 10,000 Robux instantly https://robux-free-gen.top
gaming_streaming::Akun Mobile Legends Anda terkena banned. Banding di https://ml-banding.click/appeal dengan memasukkan email dan password.
gaming_streaming::Spotify: your payment didn't go through, your Premium ends today. Update billing http://spotify-premium-bill.xyz/u
gaming_streaming::Top up diamond 50% off hari ini, login dengan akun Free Fire di http://ff-topup-murah.site
charity_donation::Mohon bantu korban banjir, transfer donasi ke rekening pribadi berikut atas nama Siti, hanya hari ini.
charity_donation::Please donate to children in need, 100% goes to them. Send gift card codes to this email.
charity_donation::Penggalangan dana operasi anak sakit: donasi lewat link https://donasi-anak-kita.click/pay (isi data kartu kredit).
charity_donation::Charity lottery winner: you won 50,000 GBP, send us your bank details to receive the donation prize.
travel_booking_scam::Booking.com: guest message about your reservation. Verify your card to avoid cancellation: https://booking-card-verify.click
travel_booking_scam::Hotel desk: your reservation will be cancelled unless you confirm your credit card via this link within 2 hours.
travel_booking_scam::Anda memenangkan paket liburan gratis ke Bali. Bayar pajak hadiah 1,5 juta untuk mengaktifkan voucher.
travel_booking_scam::Airline refund: your flight was cancelled. To receive your refund enter your card details and passport number: http://air-refund-claim.top
fake_security_vendor::Windows Defender: ancaman terdeteksi di perangkat Anda. Unduh pembersih resmi dari https://defender-cleaner-pro.click dan jalankan sebagai administrator.
fake_security_vendor::Your security-monitor license expired. Re-enter your admin token and password at http://monitor-license-renew.top to continue protection.
fake_security_vendor::Chrome update required: install the attached ChromeUpdate.exe to continue browsing securely.
fake_security_vendor::Admin server Anda: log mencurigakan terdeteksi. Login ke panel di http://cpanel-security-check.xyz dan masukkan kata sandi root untuk verifikasi.
"""

LEGITIMATE_BLOCK = """
telco_legit::Pulsa Anda tersisa Rp 12.400. Isi ulang melalui aplikasi resmi, minimarket, atau mobile banking.
telco_legit::Your monthly bill for November is Rp 189.000, due Nov 20. View the details in the MyTelco app.
telco_legit::Paket data 30GB Anda akan berakhir 3 hari lagi. Perpanjang di aplikasi atau lewat *123#.
telco_legit::Promo: dapat bonus kuota 5GB setiap isi ulang Rp 50.000 minggu ini. S&K berlaku.
telco_legit::Your roaming pass is active in Singapore until Nov 6.
marketplace_legit::Pesanan Anda sudah diterima pembeli. Dana akan diteruskan ke saldo penjual dalam 1x24 jam.
marketplace_legit::A buyer left you a 5-star review: 'Barang sesuai, pengiriman cepat'.
marketplace_legit::Your listing 'Used guitar' has 3 new messages from interested buyers. Reply in the app.
marketplace_legit::Flash sale mulai jam 12.00, siapkan keranjang belanja Anda!
marketplace_legit::Your payout of $142.30 has been sent to your bank account and should arrive in 1-3 days.
utility_legit::Tagihan PDAM bulan ini Rp 87.500, jatuh tempo tanggal 20. Pembayaran dapat dilakukan di loket, minimarket, atau aplikasi bank.
utility_legit::Pemadaman listrik terencana Sabtu 09.00-13.00 di wilayah Kotabaru untuk perawatan jaringan.
utility_legit::Your electricity meter reading was recorded: 4,512 kWh. Your next bill will be issued on the 1st.
utility_legit::Info: pembayaran listrik otomatis berhasil didebet dari rekening Anda.
utility_legit::Gas supply maintenance in your area on Tuesday from 10 am to 2 pm, no action needed.
bank_legit::Saldo rekening Anda Rp 5.230.000 per 30 Okt. Informasi ini dikirim otomatis, jangan berikan PIN/OTP kepada siapa pun.
bank_legit::Your monthly statement is ready. Sign in to the official banking app to view it.
bank_legit::Kartu kredit Anda: tagihan Rp 2.450.000 jatuh tempo 25 Nov, pembayaran minimum Rp 245.000.
bank_legit::We have updated our terms of service effective January 1. You can read the changes in the app under Legal; no action is required.
bank_legit::Cabang kami tutup pada hari libur nasional. Layanan ATM dan mobile banking tetap beroperasi.
friends_family::Selamat ulang tahun, Kak! Semoga sehat selalu dan sukses terus ya.
friends_family::The potluck is on Saturday, I'll bring rice and you bring dessert?
friends_family::Rapat orang tua murid diundur jadi Minggu pukul 10.00 di sekolah.
friends_family::Thanks for dinner last night, it was wonderful. Let's do it again soon.
friends_family::Mohon doa untuk keluarga kami, ayah sedang dirawat di rumah sakit. Terima kasih atas perhatiannya.
tech_legit::Your Kawal-Trace backup completed. 5 files, 3.2 MB, verified successfully.
tech_legit::Windows update will restart your computer tonight at 2 am. Save your work.
tech_legit::Chrome has been updated to the latest version automatically.
tech_legit::Pemindaian selesai: 1.240 berkas diperiksa, tidak ada ancaman ditemukan.
tech_legit::Your two-factor authentication app was set up successfully. Keep your recovery codes in a safe place.
government_legit::Pengumuman resmi: pendaftaran PPDB dibuka 1-15 Juni di situs dinas pendidikan, tanpa biaya.
government_legit::Reminder from the city council: waste collection moves to Wednesday this week due to the holiday.
government_legit::Batas akhir pelaporan SPT Tahunan 31 Maret. Pelaporan dilakukan sendiri melalui DJP Online, tanpa perantara.
government_legit::Your passport appointment is confirmed for Nov 14 at 10:30. Bring the original documents listed on the official site.
government_legit::Info BMKG: potensi hujan lebat di wilayah Kalimantan Barat pada sore hingga malam hari.
security_awareness::Kami tidak pernah meminta kata sandi, PIN, atau kode OTP Anda melalui email, telepon, atau WhatsApp. Waspadai penipuan yang mengatasnamakan kami.
security_awareness::Security tip: never share your verification codes. Our staff will never ask for them.
security_awareness::Akun Anda berhasil dihubungkan dengan aplikasi baru. Jika bukan Anda, cabut aksesnya di Pengaturan > Keamanan.
security_awareness::We've received your request to delete your account. It will be removed in 30 days; sign in before then to cancel.
security_awareness::Update kebijakan privasi mulai 1 Desember. Tidak ada tindakan yang diperlukan dari Anda.
work_misc::Hi Pak Andi, saya sudah transfer DP sesuai kesepakatan tadi pagi, mohon dicek ya. Bukti transfer saya lampirkan.
work_misc::Please find attached the signed contract for your records. Thank you for the smooth process.
work_misc::Reminder: submit your timesheet by Friday 5 pm in the HR portal.
work_misc::Undangan makan malam perpisahan Pak Hendra, Jumat 19.00 di Resto Khatulistiwa. Konfirmasi ke Bu Rina.
work_misc::Bu, kuitansi pembayaran vendor bulan ini sudah saya scan dan simpan di folder keuangan bersama.
"""


def challenge_rows() -> list[tuple[str, int, str]]:
    return _parse(PHISHING_BLOCK, 1) + _parse(LEGITIMATE_BLOCK, 0)
