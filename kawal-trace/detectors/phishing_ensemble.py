"""Features for the phishing ensemble: text signals + link signals, shared by training, evaluation and the app.

The Naive Bayes model only sees which words occur. Real phishing is recognised by more than that: it asks for a
credential, creates urgency, points at a link whose host imitates a brand, or asks to move to a chat app. These
are computed here as plain 0/1 features (pure Python, no network, no third-party packages). A small logistic
"stack" trained in `ml_models/train_model.py` learns how much each one is worth; the weights ship inside the model
JSON, so the shipped numbers and the shipped code cannot drift apart without a test noticing.

Everything here is a heuristic with false positives and false negatives. It never fetches a link.
"""
from __future__ import annotations

import re
from typing import Iterable, Sequence

from chainlog.advanced_security import url_indicators

from .text_preprocess import _SCRIPT_RE, _TAG_RE, _URL_RE
from .urlnorm import parse_url

# (name, Indonesian label shown to the user). The order is the order of the weights in the model file.
TEXT_FEATURES: tuple[tuple[str, str], ...] = (
    ("cred_request", "meminta Anda memasukkan/mengirim kata sandi, PIN, OTP, data kartu, atau data identitas"),
    ("urgency", "menekan agar bertindak segera / dengan batas waktu"),
    ("threat", "mengancam akun diblokir, dibekukan, ditutup, atau denda"),
    ("lure", "iming-iming hadiah, undian, bonus, atau pengembalian dana"),
    ("fee_release", "meminta bayar biaya/pajak/deposit agar sesuatu dicairkan atau dikirim"),
    ("apk_install", "meminta memasang berkas .apk/.exe atau mengizinkan semua akses"),
    ("money_request", "meminta tolong transfer/membelikan sesuatu secara mendesak"),
    ("secrecy", "meminta dirahasiakan dari orang lain"),
    ("contact_channel", "mengajak pindah ke WhatsApp/Telegram/telepon ke nomor tertentu"),
    ("otp_warning", "berisi peringatan resmi agar tidak membagikan kode/kata sandi (tanda pesan sah)"),
    ("no_action", "menyatakan tidak ada tindakan yang diperlukan / boleh diabaikan (tanda pesan sah)"),
)
LINK_FEATURES: tuple[tuple[str, str], ...] = (
    ("has_url", "memuat tautan"),
    ("url_count", "memuat banyak tautan"),
    ("url_hi", "tautan memakai alamat IP, punycode, userinfo, atau skema tidak lazim"),
    ("url_shortener", "tautan memakai pemendek URL yang menyembunyikan tujuan"),
    ("url_http", "tautan tanpa HTTPS"),
    ("risky_tld", "domain tautan berakhiran yang sering dipakai penipuan"),
    ("kw_host", "nama domain tautan berisi kata seperti login/secure/verify/update"),
    ("host_hyphens", "nama domain tautan memuat banyak tanda hubung"),
    ("hosting_abuse", "tautan menuju layanan hosting/formulir gratis yang sering disalahgunakan untuk mengumpulkan data"),
    ("display_mismatch", "teks tautan menampilkan situs yang berbeda dari tujuan sebenarnya"),
    ("brand_lookalike", "nama domain meniru merek yang disebut tetapi bukan domain resminya"),
    ("brand_mismatch", "menyebut sebuah merek, tetapi tautannya tidak menuju domain resmi merek itu"),
)
FEATURE_LABELS: dict[str, str] = dict(TEXT_FEATURES + LINK_FEATURES)
FEATURE_ORDER: tuple[str, ...] = tuple(name for name, _ in TEXT_FEATURES + LINK_FEATURES)

_VERBS = (r"(?:masukkan|memasukkan|isi|mengisi|kirim|kirimkan|balas|berikan|konfirmasi|mengkonfirmasi|verifikasi|memverifikasi|"
          r"perbarui|update|validasi|enter|provide|send|reply with|confirm|verify|re-?enter|submit|share|sign in|log ?in|login)")
_NOUNS = (r"(?:kata sandi|katasandi|password|passcode|passphrase|pin|otp|kode otp|kode verifikasi|kode sms|verification code|"
          r"security code|cvv|cvc|nomor kartu|card number|card details|data kartu|detail kartu|kredensial|credentials|"
          r"recovery phrase|seed phrase|username|nomor rekening|nomor atm|bank details|bank account|2fa|ktp|nik|"
          r"email password|login)")

_RULES: dict[str, re.Pattern[str]] = {
    "cred_request": re.compile(rf"\b{_VERBS}\b(?:\s+\w+){{0,7}}?\s+{_NOUNS}\b"),
    "urgency": re.compile(
        r"\b(?:segera|sekarang juga|secepatnya|hari ini juga|dalam \d+ ?(?:jam|menit|hari)|\d+x24 jam|batas waktu|immediately|"
        r"urgent|right away|within \d+ ?(?:hours?|minutes?|days?)|final notice|last warning|expires? today|act now|"
        r"before midnight|limited time|only today|hanya hari ini|kuota terbatas|limited spots|sebelum hangus|hangus|mendesak|"
        r"time-sensitive|as soon as you get this)\b"),
    "threat": re.compile(
        r"\b(?:diblokir|dibekukan|ditangguhkan|dinonaktifkan|ditutup|dicabut|ditahan|suspended|locked|disabled|deactivated|"
        r"terminated|cancelled|canceled|permanently|legal action|garnishment|denda|ancaman|pemutusan|disconnection|"
        r"disebar|sebar|banned|restricted|dibatasi|expired|kedaluwarsa)\b"),
    "lure": re.compile(
        r"\b(?:selamat|congratulations?|hadiah|pemenang|menang|undian|lottery|winner|won|claim|klaim|gift cards?|gratis|free|"
        r"bonus|cashback|beruntung|lucky|giveaway|airdrop|refund|pengembalian dana|reward|dicairkan|cair|maxwin|jackpot)\b"),
    "fee_release": re.compile(
        r"(?:\b(?:bayar|membayar|pay|transfer|wire|kirim|dibayar)\b(?:\s+\w+){0,5}?\s+(?:biaya|fee|ongkir|pajak|tax|deposit|"
        r"jaminan|administrasi|provisi|asuransi|premi|denda)\b)|"
        r"(?:\b(?:biaya|fee|pajak|tax|deposit|jaminan|administrasi|provisi|premi)\b(?:\s+\w+){0,6}?\s+(?:agar|untuk|to|before|"
        r"sebelum)\b(?:\s+\w+){0,4}?\s+(?:dilepas|dikirim|dicairkan|cair|release|released|deliver|delivered|unlock|aktif|activate|"
        r"diantar|pencairan)\b)|"
        r"\b(?:handling|redelivery|customs|clearance|processing) fee\b|\bbiaya (?:penanganan|pengiriman|administrasi|provisi)\b|"
        r"\bdeposit (?:awal|minimal)\b"),
    "apk_install": re.compile(r"\.apk\b|\.exe\b|\.scr\b|\bizinkan semua akses\b|\ballow all permissions\b|\bunduh file\b.*\binstall\b"),
    "money_request": re.compile(
        r"\b(?:tolong|mohon|please|kindly|can you|could you|bisa)\b(?:\s+\w+){0,6}?\s+"
        r"(?:transfer|wire|buy|belikan|beli|send|kirim|process|proses|pinjamkan|pinjam|ubah rekening|update payroll|update)\b"
        r"(?:\s+\w+){0,8}?\s+(?:\$|rp|usd|eur|gbp|voucher|gift|rekening|account|payroll|transfer|codes?|kode|\d)"
        r"|\bpinjam uang\b|\bwire transfer\b|\bgift cards?\b.*\b(?:codes?|kode)\b"),
    "secrecy": re.compile(
        r"\b(?:jangan|do not|don t|dont)\b(?:\s+\w+){0,3}?\s+(?:beri tahu|kasih tahu|dikasih tahu|kasih tau|tell|mention)\b|"
        r"\bconfidential\b|\brahasia\b|\bjangan telepon\b|\bcan t take calls\b"),
    "contact_channel": re.compile(
        r"\b(?:chat|hubungi|telepon|call|message|whatsapp|wa|telegram|admin|hr)\b(?:\s+\w+){0,5}?\s+"
        r"(?:\+?\d[\d\s]{7,}|@\w+|t\.me/\w+)|\bt\.me/\w+|\b(?:bergabung|gabung|join)\b.*\b(?:grup|group|telegram|whatsapp)\b"),
    "otp_warning": re.compile(
        r"\b(?:jangan|do not|don t|dont|never|tidak pernah|tak pernah|will never)\b(?:\s+\w+){0,4}?\s+"
        r"(?:bagikan|berikan|memberikan|beri tahu|share|give|tell|disclose|meminta|minta|ask)\b(?:\s+\w+){0,8}?\s+"
        r"(?:kode|otp|pin|code|codes|password|kata sandi|verification|anyone|siapa pun)\b|"
        r"\bwill never ask\b|\btidak akan pernah meminta\b"),
    "no_action": re.compile(
        r"\bno (?:further )?action (?:is )?(?:needed|required|necessary)\b|\btidak (?:ada )?(?:perlu|diperlukan) (?:tindakan|melakukan)\b|"
        r"\byou can ignore this\b|\babaikan (?:email|pesan) ini\b|\bif this was you\b|\bjika ini (?:memang )?anda\b|"
        r"\btidak ada tindakan\b|\bno action needed\b"),
}

_RISKY_TLDS = frozenset({"xyz", "top", "click", "icu", "buzz", "rest", "cfd", "sbs", "cyou", "gq", "tk", "ml", "ga", "cf",
                         "monster", "support", "work", "zip", "mov", "site", "online", "live", "link", "fit"})
_HOST_KEYWORDS = frozenset({"login", "signin", "secure", "security", "verify", "verifikasi", "verification", "update", "account",
                            "auth", "support", "helpdesk", "confirm", "bayar", "klaim", "hadiah", "promo", "refund", "recover",
                            "restore", "unlock", "appeal", "banding", "validate", "cek", "resi", "tagihan", "docs", "view",
                            "payment", "billing", "kuota", "gratis", "bonus", "invoice"})
# Free hosting / form services that host anyone's page. A link here is not proof of anything, but credential-harvesting
# pages are commonly parked on them precisely because the domain looks trustworthy.
_ABUSED_HOSTS = ("sites.google.com", "forms.gle", "docs.google.com", "storage.googleapis.com", "drive.google.com", "linktr.ee",
                 "notion.site", "github.io", "weebly.com", "wixsite.com", "blogspot.com", "firebaseapp.com", "web.app", "pages.dev",
                 "netlify.app", "glitch.me", "herokuapp.com", "000webhostapp.com", "dropboxusercontent.com", "typeform.com")
_SHORTENER_RE = re.compile(r"\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|s\.id|is\.gd|rb\.gy|shorturl\.at|ow\.ly)/\S+")

# brand word(s) -> registrable domains that are genuinely theirs. Used both ways: a host that CONTAINS the brand
# but is not one of these is a look-alike; a message that names the brand but links elsewhere is a mismatch.
_BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com",), "bca": ("bca.co.id", "klikbca.com"), "klikbca": ("klikbca.com", "bca.co.id"),
    "bri": ("bri.co.id",), "brimo": ("bri.co.id",), "mandiri": ("bankmandiri.co.id", "mandiri.co.id"),
    "livin": ("bankmandiri.co.id", "mandiri.co.id"), "bni": ("bni.co.id",), "cimb": ("cimbniaga.co.id",),
    "netflix": ("netflix.com",), "google": ("google.com", "gmail.com", "goo.gl"), "gmail": ("google.com", "gmail.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com", "sharepoint.com", "onedrive.com", "microsoftonline.com"),
    "outlook": ("microsoft.com", "outlook.com", "live.com"), "onedrive": ("microsoft.com", "onedrive.com", "live.com"),
    "sharepoint": ("sharepoint.com", "microsoft.com"), "office": ("office.com", "microsoft.com"),
    "apple": ("apple.com", "icloud.com"), "icloud": ("icloud.com", "apple.com"), "amazon": ("amazon.com", "amazon.co.uk", "amzn.to"),
    "facebook": ("facebook.com", "fb.com", "meta.com"), "instagram": ("instagram.com", "meta.com"),
    "whatsapp": ("whatsapp.com", "meta.com"), "shopee": ("shopee.co.id", "shopee.com"), "tokopedia": ("tokopedia.com",),
    "dana": ("dana.id",), "ovo": ("ovo.id",), "gopay": ("gojek.com", "gopay.co.id", "go-jek.com"), "gojek": ("gojek.com", "go-jek.com"),
    "jne": ("jne.co.id",), "sicepat": ("sicepat.com",), "dhl": ("dhl.com", "dhl.de"), "usps": ("usps.com",), "fedex": ("fedex.com",),
    "pln": ("pln.co.id",), "telkomsel": ("telkomsel.com",), "indosat": ("indosatooredoo.com", "im3.id"), "xl": ("xl.co.id",),
    "bpjs": ("bpjs-kesehatan.go.id", "bpjsketenagakerjaan.go.id"), "github": ("github.com", "githubusercontent.com"),
    "spotify": ("spotify.com",), "zoom": ("zoom.us",), "docusign": ("docusign.com", "docusign.net"), "binance": ("binance.com",),
    "coinbase": ("coinbase.com",), "metamask": ("metamask.io",), "ebay": ("ebay.com",), "booking": ("booking.com",),
    "linkedin": ("linkedin.com",), "tiktok": ("tiktok.com",), "djp": ("pajak.go.id",), "hmrc": ("gov.uk",), "irs": ("irs.gov",),
    "binance ": ("binance.com",),
}
_BRAND_WORD_RE = {b: re.compile(rf"\b{re.escape(b.strip())}\b") for b in _BRANDS}
# Domains that really belong to well-known services. Keyword / TLD / hyphen / plain-HTTP rules say nothing about them
# ("accounts.google.com/signin" is Google's own), so those rules are skipped for these hosts.
_KNOWN_OFFICIAL = frozenset(d for domains in _BRANDS.values() for d in domains) | {
    "youtube.com", "youtu.be", "wikipedia.org", "zoom.us", "gov.uk", "go.id", "ac.id", "mozilla.org", "videolan.org"}


def _clean(text: str) -> str:
    """Case-folded text with markup and URLs removed (their words must not trigger the text rules)."""
    value = _SCRIPT_RE.sub(" ", str(text)[:40_000])
    value = _TAG_RE.sub(" ", value)
    value = value.casefold()
    value = _URL_RE.sub(" ", value)
    value = _SHORTENER_RE.sub(" ", value)
    value = re.sub(r"[^\w\s.@/+]", " ", value)
    value = re.sub(r"(?<![\w])[./]+|[./]+(?![\w])", " ", value)       # keep dots inside words (".apk", "t.me/x")
    return re.sub(r"\s+", " ", value).strip()


def _host_in(host: str, domains: Iterable[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _link_hosts(links: Sequence[tuple[str, bool]]) -> list[tuple[str, str, bool]]:
    out: list[tuple[str, str, bool]] = []
    for url, mismatch in links:
        parsed = parse_url(url)
        if parsed is not None:
            out.append((parsed[2], parsed[1], bool(mismatch)))
    return out


def extract_features(text: str, links: Sequence[tuple[str, bool]] = ()) -> dict[str, float]:
    """0/1 (and one 0..1) features for `text` and its links `[(url, display_mismatch)]`. Deterministic and bounded."""
    clean = _clean(text)
    raw = str(text)[:40_000]
    feats: dict[str, float] = {name: 0.0 for name in FEATURE_ORDER}
    for name, pattern in _RULES.items():
        if pattern.search(clean):
            feats[name] = 1.0

    # bare shorteners ("bit.ly/abc") are not picked up by the link extractor but matter just as much
    all_links = list(links) + [("http://" + m.group(0).rstrip(".,;:!?)"), False) for m in _SHORTENER_RE.finditer(raw.casefold())]
    parsed = _link_hosts(all_links)
    if parsed:
        feats["has_url"] = 1.0
        feats["url_count"] = min(len(parsed), 3) / 3.0
    brands_in_text = [b for b, pattern in _BRAND_WORD_RE.items() if pattern.search(clean)]
    mismatch_hit = False
    for canonical, host, display_mismatch in parsed:
        points = [p for p, _ in url_indicators(canonical)]
        if any(p >= 20 for p in points):
            feats["url_hi"] = 1.0
        if any(p == 12 for p in points) or _SHORTENER_RE.search(host + "/x"):
            feats["url_shortener"] = 1.0
        if _host_in(host, _ABUSED_HOSTS):
            feats["hosting_abuse"] = 1.0
        if not _host_in(host, _KNOWN_OFFICIAL):
            if canonical.startswith("http://"):
                feats["url_http"] = 1.0
            if host.split(".")[-1] in _RISKY_TLDS:
                feats["risky_tld"] = 1.0
            host_tokens_here = set(re.split(r"[.\-_0-9]+", host)) - {""}
            if host_tokens_here & _HOST_KEYWORDS:
                feats["kw_host"] = 1.0
            if host.count("-") >= 2:
                feats["host_hyphens"] = 1.0
        host_tokens = set(re.split(r"[.\-_0-9]+", host)) - {""}
        if display_mismatch:
            feats["display_mismatch"] = 1.0
        for brand, domains in _BRANDS.items():
            token = brand.strip()
            if token in host_tokens and not _host_in(host, domains):
                feats["brand_lookalike"] = 1.0
        if brands_in_text:
            if not any(_host_in(host, _BRANDS[b]) for b in brands_in_text):
                mismatch_hit = True
    if parsed and brands_in_text and mismatch_hit:
        # only when NO link goes to a mentioned brand's own domain
        official = any(_host_in(h, _BRANDS[b]) for _, h, _ in parsed for b in brands_in_text)
        if not official:
            feats["brand_mismatch"] = 1.0
    return feats
