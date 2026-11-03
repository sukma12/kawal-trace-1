"""Email Header Parser: dissect an .eml message (MIME structure, sender data, SPF/DKIM/DMARC).

Offline only. SPF/DKIM/DMARC are READ from the Authentication-Results / Received-SPF headers that
the receiving mail server recorded; this module cannot re-verify signatures or DNS records without
a network, and it says so. Only the top-most Authentication-Results header is trusted because a
sender can forge extra copies lower in the message. Attachments are hashed in memory and never
written to disk or executed.
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import re
from dataclasses import dataclass, field
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from . import ScanInputError
from .link_extractor import _same_site
from .urlnorm import normalize_host

MAX_EMAIL_BYTES = 25 * 1024 * 1024
MAX_PARTS = 200
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
_AUTH_RE = re.compile(r"(?i)\b(spf|dkim|dmarc)\s*=\s*([a-z]+)")
_DKIM_D_RE = re.compile(r"(?i)\bd\s*=\s*([^;\s]+)")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
_EXEC_EXT = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
             ".ps1", ".msi", ".jar", ".lnk", ".hta", ".dll", ".cpl", ".apk", ".iso", ".img"}
_MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
_DOUBLE_EXT_RE = re.compile(r"(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt)\s*\.(exe|scr|bat|cmd|js|vbs|lnk|com|pif|hta)$")
_ADDR_IN_NAME_RE = re.compile(r"(?i)[a-z0-9._%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)|\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str | None
    risk_notes: list[str] = field(default_factory=list)
    # Held in memory only until the pipeline has handed it to the isolated worker; never written to disk.
    payload: bytes | None = field(default=None, repr=False, compare=False)


@dataclass
class ParsedEmail:
    sender: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received_hops: int = 0
    auth: dict[str, str | None] = field(default_factory=lambda: {"spf": None, "dkim": None, "dmarc": None})
    attachments: list[Attachment] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    findings: list[tuple[str, str]] = field(default_factory=list)   # (finding_type, description)
    part_count: int = 0


def _domain(value: str) -> str:
    _, address = email.utils.parseaddr(value or "")
    return normalize_host(address.rsplit("@", 1)[1]) or "" if "@" in address else ""


def _header(msg: Message, name: str, limit: int = 500) -> str:
    try:
        return _CTRL_RE.sub(" ", str(msg.get(name, "") or ""))[:limit]
    except Exception:  # malformed header objects must not abort parsing
        return ""


def _text_of(part: Message) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:
        pass
    try:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    except Exception:
        return ""


def _clean_filename(name: str) -> str:
    base = re.split(r"[\\/]", _CTRL_RE.sub("", name or ""))[-1]
    return base[:255] or "(tanpa nama)"


def _attachment_risks(filename: str) -> list[str]:
    notes: list[str] = []
    lower = filename.lower()
    suffix = Path(lower).suffix
    if _BIDI_RE.search(filename):
        notes.append("Nama file memakai karakter pembalik arah teks (penyamaran ekstensi).")
    if _DOUBLE_EXT_RE.search(lower):
        notes.append("Ekstensi ganda menyamarkan file yang dapat dijalankan.")
    elif suffix in _EXEC_EXT:
        notes.append(f"Lampiran bertipe dapat dijalankan/berisiko ({suffix}).")
    elif suffix in _MACRO_EXT:
        notes.append(f"Dokumen Office dengan makro ({suffix}).")
    return notes


def parse_email(raw: bytes | str) -> ParsedEmail:
    if isinstance(raw, str):
        data = raw.encode("utf-8", errors="replace")
    elif isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
    else:
        raise ScanInputError("Isi email harus berupa bytes atau teks.")
    if not data.strip():
        raise ScanInputError("Email kosong.")
    if len(data) > MAX_EMAIL_BYTES:
        raise ScanInputError(f"Email melebihi batas {MAX_EMAIL_BYTES // (1024 * 1024)} MiB.")
    try:
        msg = BytesParser(policy=email.policy.default).parsebytes(data)
    except Exception as exc:  # the stdlib parser is lenient, but never trust that
        raise ScanInputError(f"Struktur email tidak dapat dibaca ({type(exc).__name__}).") from exc

    parsed = ParsedEmail(
        sender=_header(msg, "From"), reply_to=_header(msg, "Reply-To"), return_path=_header(msg, "Return-Path"),
        to=_header(msg, "To"), subject=_header(msg, "Subject"), date=_header(msg, "Date"),
        message_id=_header(msg, "Message-ID"), received_hops=len(msg.get_all("Received", []) or []),
    )
    if not parsed.sender:
        parsed.findings.append(("HEADER_MISMATCH", "Header From tidak ada; pengirim tidak dapat diverifikasi."))

    _read_authentication(msg, parsed)
    _check_alignment(msg, parsed)

    texts: list[str] = []
    htmls: list[str] = []
    for index, part in enumerate(msg.walk(), start=1):
        parsed.part_count = index
        if index > MAX_PARTS:
            parsed.findings.append(("INFO", f"Email memiliki lebih dari {MAX_PARTS} bagian MIME; sisanya tidak dipindai."))
            break
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or filename:
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            name = _clean_filename(filename or "")
            size = len(payload)
            digest = hashlib.sha256(payload).hexdigest() if size <= MAX_ATTACHMENT_BYTES else None
            notes = _attachment_risks(name)
            if digest is None:
                notes.append("Lampiran terlalu besar untuk di-hash; tidak dipindai.")
            parsed.attachments.append(Attachment(name, part.get_content_type(), size, digest, notes,
                                                 payload=payload if digest is not None else None))
            for note in notes:
                parsed.findings.append(("ATTACHMENT_RISK", f"{name}: {note}"))
            continue
        if part.get_content_maintype() == "text":
            sub = part.get_content_subtype()
            if sub == "plain":
                texts.append(_text_of(part))
            elif sub == "html":
                htmls.append(_text_of(part))
    parsed.body_text = "\n".join(texts)[:2_000_000]
    parsed.body_html = "\n".join(htmls)[:2_000_000]
    return parsed


def parse_email_file(path: str | Path) -> ParsedEmail:
    target = Path(path)
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise ScanInputError("File email tidak dapat diakses.") from exc
    if not target.is_file():
        raise ScanInputError("Pilih file .eml, bukan folder.")
    if size > MAX_EMAIL_BYTES:
        raise ScanInputError(f"Email melebihi batas {MAX_EMAIL_BYTES // (1024 * 1024)} MiB.")
    try:
        return parse_email(target.read_bytes())
    except OSError as exc:
        raise ScanInputError(f"File email tidak dapat dibaca ({type(exc).__name__}).") from exc


def _read_authentication(msg: Message, parsed: ParsedEmail) -> None:
    headers = msg.get_all("Authentication-Results", []) or []
    if headers:
        for mech, result in _AUTH_RE.findall(str(headers[0])):   # top-most header only
            parsed.auth.setdefault(mech.lower(), None)
            if parsed.auth[mech.lower()] is None:
                parsed.auth[mech.lower()] = result.lower()
    if parsed.auth["spf"] is None:
        spf = str(msg.get("Received-SPF", "") or "").strip().split(" ", 1)[0].lower()
        if spf:
            parsed.auth["spf"] = spf
    for mech in ("spf", "dkim", "dmarc"):
        result = parsed.auth[mech]
        if result is None:
            parsed.findings.append(("HEADER_AUTH", f"{mech.upper()}: tidak ada hasil pada header (tidak dapat diverifikasi offline)."))
        elif result != "pass":
            parsed.findings.append(("HEADER_AUTH", f"{mech.upper()} bukan pass ({result})."))


def _check_alignment(msg: Message, parsed: ParsedEmail) -> None:
    from_domain = _domain(parsed.sender)
    reply_domain = _domain(parsed.reply_to)
    path_domain = _domain(parsed.return_path)
    if from_domain and reply_domain and not _same_site(from_domain, reply_domain):
        parsed.findings.append(("HEADER_MISMATCH", f"Reply-To ({reply_domain}) berbeda dari From ({from_domain})."))
    if from_domain and path_domain and not _same_site(from_domain, path_domain):
        parsed.findings.append(("HEADER_MISMATCH", f"Return-Path ({path_domain}) berbeda dari From ({from_domain})."))
    display_name, _address = email.utils.parseaddr(parsed.sender)
    for match in _ADDR_IN_NAME_RE.finditer(display_name or ""):
        shown = normalize_host(match.group(1) or match.group(2) or "")
        if shown and from_domain and not _same_site(shown, from_domain):
            parsed.findings.append(("HEADER_MISMATCH", f"Nama pengirim menampilkan {shown} tetapi alamat sebenarnya {from_domain}."))
            break
    signature = msg.get("DKIM-Signature")
    if signature and from_domain:
        found = _DKIM_D_RE.search(str(signature))
        signer = normalize_host(found.group(1)) if found else None
        if signer and not _same_site(signer, from_domain):
            parsed.findings.append(("HEADER_MISMATCH", f"Domain penanda tangan DKIM ({signer}) tidak sejajar dengan From ({from_domain})."))
