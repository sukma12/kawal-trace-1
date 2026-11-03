"""Static (never-executing) file analysis used by the isolated scan worker.

Everything here reads bytes and applies fixed rules. Nothing is executed, imported,
rendered or extracted to disk. ZIP-based formats (Office, APK, JAR) are only *listed*
(central directory names), never decompressed, so a zip bomb cannot expand in memory.

These are heuristics, not a verdict: a score >= SUSPICIOUS_THRESHOLD only means
"look at this before opening it". Only a signature (hash) match is treated as
malware, and only that can lead to automatic deletion.
"""
from __future__ import annotations

import io
import math
import re
import zipfile
from dataclasses import dataclass, field

SUSPICIOUS_THRESHOLD = 50
MAX_ZIP_ENTRIES = 5000
MAX_TEXT_SCAN = 1024 * 1024

# Extensions that Windows/Android/Linux will run or that commonly carry active content.
EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "lnk", "msi", "jar", "apk", "dll", "sys", "cpl", "reg", "sh", "run", "bin",
}
# Extensions a user expects to be harmless documents/media.
BENIGN_LOOKING_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "rtf", "mp3", "mp4", "mkv", "avi", "csv", "zip", "heic",
}
_SCRIPT_EXTENSIONS = {"ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "sh", "php", "py", "pl", "phtml", "php5", "phar"}

# (regex, description, weight). Matching is case-insensitive over decoded text.
_SCRIPT_PATTERNS: tuple[tuple[re.Pattern[str], str, int], ...] = tuple(
    (re.compile(p, re.IGNORECASE), d, w) for p, d, w in (
        (r"powershell[^\n]{0,80}\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", "PowerShell dengan perintah ter-encode (-enc)", 50),
        (r"frombase64string\s*\(", "Memuat data base64 saat dijalankan (FromBase64String)", 20),
        (r"\b(iex|invoke-expression)\b", "Menjalankan teks sebagai perintah (Invoke-Expression)", 25),
        (r"downloadstring\s*\(|downloadfile\s*\(|invoke-webrequest|net\.webclient", "Mengunduh konten dari internet saat dijalankan", 25),
        (r"certutil[^\n]{0,40}-urlcache|bitsadmin[^\n]{0,40}/transfer", "Alat Windows dipakai untuk mengunduh file (LOLBin)", 40),
        (r"mshta(\.exe)?\s+(https?:|vbscript:|javascript:)", "mshta menjalankan skrip dari URL", 45),
        (r"wscript\.shell|createobject\(\s*[\"']wscript\.shell", "Skrip membuat shell Windows (WScript.Shell)", 25),
        (r"(hkcu|hklm)[^\n]{0,60}\\run\b|reg\s+add[^\n]{0,80}\\run\b", "Menambah autostart lewat registry Run", 30),
        (r"/dev/tcp/\d|bash\s+-i\s*>&|\bnc(\.exe)?\s+(-e|-c)\s", "Pola reverse shell", 55),
        (r"(curl|wget)[^\n|]{0,120}\|\s*(ba)?sh\b", "Mengunduh lalu langsung menjalankan (curl | sh)", 45),
        (r"base64\s+(-d|--decode)[^\n]{0,40}\|\s*(ba)?sh\b", "Dekode base64 langsung dijalankan", 45),
        (r"eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(", "PHP: eval pada data ter-encode (pola webshell)", 55),
        (r"\b(eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(get|post|request|cookie)", "PHP: menjalankan input HTTP langsung (webshell)", 60),
        (r"eval\s*\(\s*atob\s*\(|eval\s*\(\s*unescape\s*\(|document\.write\s*\(\s*unescape", "JavaScript tersamar (eval/atob/unescape)", 30),
        (r"chmod\s+\+x\s+/(tmp|dev/shm|var/tmp)", "Menjadikan file di /tmp dapat dieksekusi", 25),
    )
)

# Android permissions that banking trojans/spyware rely on.
_APK_RISKY_PERMISSIONS = (
    "SEND_SMS", "READ_SMS", "RECEIVE_SMS", "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW", "READ_CALL_LOG", "RECORD_AUDIO",
    "MANAGE_EXTERNAL_STORAGE", "READ_CONTACTS", "BIND_NOTIFICATION_LISTENER_SERVICE",
)


@dataclass(frozen=True)
class StaticFinding:
    kind: str          # always "STATIC" at this layer; the pipeline maps it to a stored finding type
    description: str
    weight: int


@dataclass
class StaticReport:
    file_kind: str = "unknown"
    entropy: float | None = None
    findings: list[StaticFinding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(f.weight for f in self.findings))

    @property
    def suspicious(self) -> bool:
        return self.score >= SUSPICIOUS_THRESHOLD


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def sniff_kind(head: bytes) -> str:
    if head.startswith(b"MZ"):
        return "windows-executable"
    if head.startswith(b"\x7fELF"):
        return "linux-executable"
    if head[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}:
        # 0xCAFEBABE is shared by Java classes and Mach-O fat binaries; both are executable content.
        return "macho-or-java-class"
    if head.startswith(b"dex\n"):
        return "android-dex"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole-document"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip-container"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head[:4] == b"L\x00\x00\x00" and head[4:8] == b"\x01\x14\x02\x00":
        return "windows-shortcut"
    if head.startswith(b"#!"):
        return "script-shebang"
    if head.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")):
        return "image"
    return "unknown"


def _extension_parts(name: str) -> tuple[str, list[str]]:
    base = name.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    parts = base.split(".")
    exts = [p for p in parts[1:] if p]
    return (exts[-1] if exts else ""), exts


def _decode_text(data: bytes) -> str:
    return data[:MAX_TEXT_SCAN].decode("utf-8", errors="ignore")


def _scan_script_text(text: str, report: StaticReport) -> None:
    seen: set[str] = set()
    for pattern, description, weight in _SCRIPT_PATTERNS:
        if description not in seen and pattern.search(text):
            seen.add(description)
            report.findings.append(StaticFinding("STATIC", description, weight))


def _zip_names(data: bytes) -> list[str] | None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                return [i.filename for i in infos[:MAX_ZIP_ENTRIES]]
            return [i.filename for i in infos]
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError, RuntimeError):
        return None


def _analyse_apk(names: list[str], data: bytes, report: StaticReport) -> None:
    report.file_kind = "android-apk"
    manifest_bytes = b""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            info = archive.getinfo("AndroidManifest.xml")
            if info.file_size <= 2 * 1024 * 1024:  # bounded read of a single known entry
                manifest_bytes = archive.read(info)
    except (KeyError, zipfile.BadZipFile, ValueError, OSError, RuntimeError, NotImplementedError):
        manifest_bytes = b""
    found: list[str] = []
    for permission in _APK_RISKY_PERMISSIONS:
        needle_utf8 = permission.encode("ascii")
        needle_utf16 = permission.encode("utf-16-le")
        if needle_utf8 in manifest_bytes or needle_utf16 in manifest_bytes:
            found.append(permission)
    if found:
        weight = 15 if len(found) < 3 else 55 if len(found) >= 4 else 40
        report.findings.append(StaticFinding(
            "STATIC", f"APK meminta izin berisiko: {', '.join(found[:8])}"
            f"{' dan lainnya' if len(found) > 8 else ''}. Pola umum trojan perbankan/spyware.", weight))
    else:
        report.findings.append(StaticFinding("STATIC", "Berkas APK (aplikasi Android). Pasang hanya dari toko resmi.", 5))


def analyse_bytes(data: bytes, name: str) -> StaticReport:
    """Analyse an in-memory payload. Safe for hostile input; bounded work."""
    report = StaticReport()
    head = data[:64]
    kind = sniff_kind(head)
    report.file_kind = kind
    ext, all_exts = _extension_parts(name)

    # Executable content disguised with a harmless-looking extension (invoice.pdf that is really an EXE).
    executable_magic = kind in {"windows-executable", "linux-executable", "macho-or-java-class", "android-dex", "windows-shortcut"}
    if executable_magic and ext in BENIGN_LOOKING_EXTENSIONS:
        report.findings.append(StaticFinding(
            "STATIC", f"Isi berkas adalah program ({kind}) tetapi ekstensinya .{ext}. Penyamaran umum pada malware.", 65))
    elif executable_magic:
        report.findings.append(StaticFinding("STATIC", f"Berkas program ({kind}). Jangan dijalankan jika asalnya tidak jelas.", 5))

    # invoice.pdf.exe: a benign-looking extension followed by an executable one.
    if len(all_exts) >= 2 and all_exts[-1] in EXECUTABLE_EXTENSIONS and all_exts[-2] in BENIGN_LOOKING_EXTENSIONS:
        report.findings.append(StaticFinding("STATIC", f"Ekstensi ganda menyesatkan (.{all_exts[-2]}.{all_exts[-1]}).", 50))

    if kind in {"windows-executable", "linux-executable", "zip-container", "unknown"} and len(data) >= 65536:
        sample = data[:1024 * 1024]
        entropy = shannon_entropy(sample)
        report.entropy = round(entropy, 3)
        if kind in {"windows-executable", "linux-executable"} and entropy > 7.4:
            report.findings.append(StaticFinding("STATIC", f"Entropi sangat tinggi ({entropy:.2f}/8): kemungkinan program dipacking/dienkripsi.", 20))

    if kind == "zip-container":
        names = _zip_names(data)
        if names is not None:
            lowered = [n.lower() for n in names]
            if "androidmanifest.xml" in lowered and any(n.endswith(".dex") for n in lowered):
                _analyse_apk(names, data, report)
            elif any(n.endswith("vbaproject.bin") for n in lowered):
                report.file_kind = "office-with-macros"
                report.findings.append(StaticFinding("STATIC", "Dokumen Office berisi makro VBA (vbaProject.bin).", 35))
            elif any(n.startswith("meta-inf/") for n in lowered) and ext == "jar":
                report.file_kind = "java-archive"
            hidden_exec = [n for n in names if n.lower().rsplit(".", 1)[-1] in {"exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "lnk", "hta"}
                           and not n.endswith("/")]
            if hidden_exec and ext in {"zip", "rar", "7z"} and report.file_kind == "zip-container":
                report.findings.append(StaticFinding("STATIC", f"Arsip berisi file yang dapat dijalankan: {', '.join(hidden_exec[:3])}.", 20))
            if len(names) >= MAX_ZIP_ENTRIES:
                report.findings.append(StaticFinding("STATIC", "Arsip berisi sangat banyak entri (kemungkinan zip bomb).", 25))
    elif kind == "ole-document":
        blob = data[:4 * 1024 * 1024]
        if b"_VBA_PROJECT" in blob or b"VBA" in blob[:4096] or b"Macros" in blob:
            report.file_kind = "office-with-macros"
            report.findings.append(StaticFinding("STATIC", "Dokumen Office lama berisi makro VBA.", 35))
        if re.search(rb"(AutoOpen|Auto_Open|Document_Open|Workbook_Open)", blob):
            report.findings.append(StaticFinding("STATIC", "Makro berjalan otomatis saat dokumen dibuka.", 30))
    elif kind == "pdf":
        blob = data[:4 * 1024 * 1024]
        active = [tok.decode() for tok in (b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/EmbeddedFile", b"/AA") if tok in blob]
        if "/Launch" in active:
            # A Launch action asks the viewer to start another program; legitimate PDFs essentially never do.
            report.findings.append(StaticFinding("STATIC", f"PDF berisi aksi /Launch yang menjalankan program lain ({', '.join(active)}).", 60))
        elif ("/JavaScript" in active or "/JS" in active) and ("/OpenAction" in active or "/AA" in active):
            report.findings.append(StaticFinding("STATIC", f"PDF menjalankan JavaScript otomatis saat dibuka ({', '.join(active)}).", 45))
        elif active:
            report.findings.append(StaticFinding("STATIC", f"PDF berisi elemen aktif ({', '.join(active)}); sering sah, periksa asalnya.", 10))
    elif kind == "rtf":
        if b"\\objdata" in data[:4 * 1024 * 1024].lower():
            report.findings.append(StaticFinding("STATIC", "RTF menyematkan objek OLE (\\objdata), vektor eksploit umum.", 40))

    is_text_like = kind in {"script-shebang", "unknown"} or ext in _SCRIPT_EXTENSIONS
    if is_text_like:
        text = _decode_text(data)
        if text:
            _scan_script_text(text, report)
    return report


def analyse_text_for_webshell(text: str) -> StaticReport:
    """Convenience for scanning a pasted snippet of script/PHP source."""
    report = StaticReport(file_kind="text")
    _scan_script_text(text[:MAX_TEXT_SCAN], report)
    return report
