"""Deterministic, template-based demo corpus (English + Bahasa Indonesia).

IMPORTANT: this is SYNTHETIC data written for the project, used so the model files can be rebuilt
offline without downloading anything. Scores measured on a hold-out split of this corpus are
optimistic because templates repeat. For real-world use, retrain with your own labelled mailbox
or a public phishing dataset: `python -m ml_models.train_model --data your.csv` (columns: text,label).
"""
from __future__ import annotations

import random

BRANDS = ["PayPal", "Bank Central", "Netflix", "Microsoft", "Google", "Instagram", "BRI", "BCA", "Mandiri",
          "Shopee", "Tokopedia", "Apple", "Amazon", "DHL", "Facebook", "WhatsApp"]
TLDS = ["xyz", "top", "click", "info", "site", "online", "support", "work"]
PRIZES = ["iPhone 15", "uang tunai 50 juta", "a $1000 gift card", "voucher belanja 5 juta", "a free laptop"]

PHISH_EN = [
    "Your {b} account has been suspended. Verify your account immediately at {u} to avoid permanent closure.",
    "Unusual activity detected on your {b} account. Confirm your password now: {u}",
    "Payment failed for your {b} subscription. Update your billing information within 24 hours {u}",
    "Congratulations! You have won {p}. Claim your reward now by entering your card details {u}",
    "Security alert: someone tried to sign in to your {b} account. Click here to secure your account {u}",
    "Your package could not be delivered. Pay the customs fee to release it {u}",
    "Urgent: your mailbox is full. Login to {b} webmail to keep receiving emails {u}",
    "Invoice overdue. Open the document and enter your {b} credentials to view it {u}",
    "Final notice: your {b} password expires today. Reset your password immediately {u}",
    "We locked your {b} account. Provide your card number and OTP to unlock {u}",
]
PHISH_ID = [
    "Akun {b} Anda ditangguhkan. Segera verifikasi akun di {u} sebelum diblokir permanen.",
    "Aktivitas mencurigakan pada rekening {b} Anda. Konfirmasi kata sandi dan kode OTP Anda sekarang {u}",
    "Selamat! Anda terpilih memenangkan hadiah {p}. Klik tautan untuk klaim dan isi data kartu {u}",
    "Paket Anda tertahan. Bayar biaya pengiriman agar paket dikirim {u}",
    "Kartu kredit {b} Anda akan diblokir. Perbarui data dan PIN Anda hari ini {u}",
    "Tagihan {b} gagal dibayar. Segera login dan perbarui pembayaran {u}",
    "Peringatan keamanan: akun {b} Anda diakses dari perangkat tidak dikenal. Verifikasi sekarang {u}",
    "Kata sandi {b} Anda segera kedaluwarsa. Segera masuk dan ubah kata sandi {u}",
]
LEGIT_EN = [
    "Hi team, the weekly sync is moved to Thursday at 10 am. Agenda and notes are in the shared folder.",
    "Attached are the meeting minutes from yesterday. Please review and send comments by Friday.",
    "Thanks for your order. Your items will ship tomorrow and the tracking number will follow in a separate message.",
    "Reminder: the quarterly report draft is due next Monday. Let me know if you need more time.",
    "Your password was changed successfully. If this was you, no further action is needed.",
    "Newsletter: this month we released three product updates, read the release notes on our official blog {u}",
    "Pull request {n} was merged into main after two approvals. Release is planned for next sprint {u}",
    "Lunch on Friday? The new place near the office has a good vegetarian menu.",
    "Your invoice for last month is attached for your records. No action is required.",
    "Calendar invite: project kickoff on Tuesday at 2 pm in room 4B, remote link in the invite {u}",
    "Here are the slides from today's presentation, feel free to share them with your colleagues.",
    "Conference registration is confirmed. Your badge will be available at the front desk on arrival.",
]
LEGIT_ID = [
    "Halo tim, rapat mingguan dipindah ke hari Kamis pukul 10.00. Agenda ada di folder bersama.",
    "Terlampir notulen rapat kemarin. Mohon dicek dan kirim masukan sebelum hari Jumat.",
    "Terima kasih telah berbelanja. Pesanan Anda dikirim besok dan nomor resi menyusul di pesan terpisah.",
    "Pengingat: draf laporan triwulan dikumpulkan Senin depan. Kabari saya jika butuh waktu tambahan.",
    "Kata sandi Anda berhasil diubah. Jika ini memang Anda, tidak ada tindakan lebih lanjut.",
    "Pengumuman: kantor libur pada tanggal merah, layanan kembali normal keesokan harinya.",
    "Jadwal kuliah semester ini sudah tersedia di portal kampus resmi {u}",
    "Makan siang bareng hari Jumat? Ada tempat baru dekat kantor dengan menu enak.",
    "Tagihan bulan lalu terlampir untuk arsip Anda. Tidak diperlukan tindakan apa pun.",
    "Undangan rapat: pembahasan proyek hari Selasa pukul 14.00 di ruang 4B, tautan daring ada di undangan {u}",
    "Berikut slide presentasi hari ini, silakan dibagikan kepada rekan kerja.",
]
LEGIT_URLS = ["https://docs.example.org/report", "https://github.com/org/repo/pull/12", "https://intranet.example.org/news",
              "https://www.wikipedia.org/wiki/Email", "https://calendar.example.org/event/42"]


def _phish_url(rng: random.Random, brand: str) -> str:
    slug = brand.lower().replace(" ", "")
    shapes = [f"http://{slug}-secure-login.{rng.choice(TLDS)}/verify", f"http://{slug}{rng.randint(1, 9)}.account-verify.{rng.choice(TLDS)}/login",
              f"http://{rng.randint(11, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}/{slug}/confirm",
              f"https://bit.ly/{rng.randint(100000, 999999)}"]
    return rng.choice(shapes)


def build_corpus(per_class: int = 400, seed: int = 1337) -> list[tuple[str, int]]:
    """Return [(text, label)] with label 1 = phishing, 0 = legitimate."""
    rng = random.Random(seed)
    rows: list[tuple[str, int]] = []
    for _ in range(per_class):
        brand = rng.choice(BRANDS)
        template = rng.choice(PHISH_EN + PHISH_ID)
        rows.append((template.format(b=brand, u=_phish_url(rng, brand), p=rng.choice(PRIZES)), 1))
        legit = rng.choice(LEGIT_EN + LEGIT_ID)
        rows.append((legit.format(u=rng.choice(LEGIT_URLS), n=rng.randint(10, 999)), 0))
    rng.shuffle(rows)
    return rows
