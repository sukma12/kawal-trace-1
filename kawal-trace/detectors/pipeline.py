"""Scan pipeline following the project flowchart.

FILE  : SHA-256 -> Bloom filter -> SQLite exact match      -> SAFE | MALWARE
EMAIL : parse -> attachments (FILE flow) + links (phishing_urls) + text/links (local AI ensemble)
        -> MALWARE > PHISHING > SAFE, then save history and show details.

Informational findings (header results, link look-alikes, risky attachment types) are saved and
shown but never change the status by themselves; only a signature hit, a blacklist hit or an AI
score >= 70 % do. A scan that could not run a stage says so in the details instead of implying a
clean result.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import ScanInputError, ScannerError
from .email_parser import ParsedEmail, parse_email, parse_email_file
from .isolated_scan import InspectionResult, IsolatedInspector
from .quarantine import GRACE_SECONDS_DEFAULT, QuarantineVault
from .static_heuristics import SUSPICIOUS_THRESHOLD
from .link_extractor import ExtractedLink, extract_links
from .phishing_classifier import PhishingClassifier
from .scanner_db import HISTORY_RETENTION_DAYS, ScannerDatabase, clean_text
from .signature_matcher import SignatureMatcher
from .task_queue import AsyncTaskQueue
from .text_preprocess import preprocess_text
from .url_checker import LinkReputationChecker
from .urlnorm import parse_url

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
MAX_IMPORT_BYTES = 64 * 1024 * 1024
MAX_HEURISTIC_FINDINGS = 20
_SEVERITY_RANK = {"SAFE": 0, "SUSPICIOUS": 1, "PHISHING": 2, "MALWARE": 3}


@dataclass
class ScanReport:
    status: str
    file_type: str                      # FILE | EMAIL
    file_name: str
    scan_id: int | None = None
    sha256: str | None = None
    summary: str = ""
    findings: list[tuple[str, str]] = field(default_factory=list)
    ai_score: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_threat(self) -> bool:
        return self.status != "SAFE"


def _escalate(current: str, new: str) -> str:
    return new if _SEVERITY_RANK[new] > _SEVERITY_RANK[current] else current


class SecurityScanner:
    def __init__(self, data_dir: str | os.PathLike[str], model_dir: str | os.PathLike[str] | None = None, *,
                 allow_pickle: bool = False, workers: int = 1, seed_test_entries: bool = True,
                 isolate: bool = True, quarantine_dir: str | os.PathLike[str] | None = None,
                 protected_dirs: tuple[Path, ...] = (), quarantine_on_detect: bool = True,
                 grace_seconds: int = GRACE_SECONDS_DEFAULT) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db = ScannerDatabase(self.data_dir / "scanner.sqlite3")
        self.db.initialize()
        # Door 1: untrusted bytes are only ever read inside this (separate-process) inspector.
        self.inspector = IsolatedInspector(workdir=self.data_dir / "worker-tmp", use_subprocess=isolate)
        # Door 2: flagged files live in their own vault + database, apart from signatures/history/audit.
        self.vault = QuarantineVault(quarantine_dir if quarantine_dir is not None else self.data_dir / "quarantine",
                                     protected_extra=tuple(protected_dirs))
        self.quarantine_on_detect = bool(quarantine_on_detect)
        self.grace_seconds = int(grace_seconds)
        if seed_test_entries:
            self._seed_test_entries()
        self.matcher = SignatureMatcher(self.db, self.data_dir / "malware_signatures.bloom")
        self.matcher.load()
        self.urls = LinkReputationChecker(self.db)
        model_path = Path(model_dir) if model_dir else Path(__file__).resolve().parent.parent / "ml_models"
        self.classifier = PhishingClassifier.load(model_path, allow_pickle=allow_pickle)
        self.queue = AsyncTaskQueue(workers=workers)
        self.pruned_on_start = self.prune()

    # ---- maintenance -------------------------------------------------------------
    def _seed_test_entries(self) -> None:
        if self.db.signature_count() == 0:
            self.db.add_signatures([(EICAR_SHA256, "EICAR-Test-File (file uji standar, bukan malware)", "Low")])
        if self.db.phishing_count() == 0:
            self.db.add_phishing_indicators([("phishing-test.invalid", "Phishing")])  # .invalid never resolves

    def prune(self, days: int = HISTORY_RETENTION_DAYS) -> int:
        return self.db.prune_history(days)

    def clear_history(self) -> int:
        """Remove all saved scan results (including cascading detail rows)."""
        return self.db.clear_history()

    def close(self) -> None:
        self.queue.shutdown(wait=True)
        self.inspector.close()

    def stats(self) -> dict[str, Any]:
        return {
            "signatures": self.db.signature_count(), "phishing_entries": self.db.phishing_count(),
            "history": self.db.history_count(), "bloom": self.matcher.stats(),
            "ai_available": self.classifier.available, "ai_status": self.classifier.status,
            "schema_version": self.db.schema_version(),
            "isolation": self.inspector.status(),
            "threats_pending": len(self.vault.list_threats()),
        }

    # ---- offline list import -----------------------------------------------------
    @staticmethod
    def _read_import_file(path: str | Path) -> str:
        target = Path(path)
        try:
            if not target.is_file() or target.stat().st_size > MAX_IMPORT_BYTES:
                raise ScanInputError("File daftar tidak ditemukan atau lebih besar dari 64 MiB.")
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ScanInputError(f"File daftar tidak dapat dibaca ({type(exc).__name__}).") from exc

    @staticmethod
    def _lines(text: str) -> Iterable[list[str]]:
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                yield [p.strip() for p in line.replace("\t", ",").split(",")]

    def import_signature_text(self, text: str) -> tuple[int, int]:
        """Lines: sha256[,nama[,Low|Medium|High]]. Missing name/severity get safe defaults."""
        rows = []
        for parts in self._lines(text):
            rows.append((parts[0], parts[1] if len(parts) > 1 and parts[1] else "Daftar impor",
                         parts[2] if len(parts) > 2 and parts[2] else "Medium"))
        return self.matcher.import_signatures(rows)

    def import_phishing_text(self, text: str, threat_type: str = "Phishing") -> tuple[int, int]:
        rows = [(parts[0], parts[1] if len(parts) > 1 and parts[1] else threat_type) for parts in self._lines(text)]
        return self.db.add_phishing_indicators(rows)

    def import_signature_file(self, path: str | Path) -> tuple[int, int]:
        return self.import_signature_text(self._read_import_file(path))

    def import_phishing_file(self, path: str | Path, threat_type: str = "Phishing") -> tuple[int, int]:
        return self.import_phishing_text(self._read_import_file(path), threat_type)

    # ---- scans -------------------------------------------------------------------
    def _save(self, report: ScanReport) -> ScanReport:
        report.scan_id = self.db.record_scan(report.file_name, report.file_type, report.status,
                                             report.summary, report.findings)
        return report

    def _static_findings(self, info: InspectionResult, findings: list[tuple[str, str]], status: str) -> str:
        """Add static-analysis findings; SUSPICIOUS is only ever a "look before you open" flag."""
        for description, weight in info.findings:
            if weight > 0:
                findings.append(("STATIC", f"{description} (bobot {weight})"))
            elif description:
                findings.append(("INFO", description))
        if info.static_score >= SUSPICIOUS_THRESHOLD:
            findings.append(("STATIC", f"Skor analisis statis {info.static_score}/100 (ambang {SUSPICIOUS_THRESHOLD}): berkas mencurigakan, "
                                       "tetapi tidak ada signature yang cocok. Jangan dibuka sebelum diperiksa."))
            status = _escalate(status, "SUSPICIOUS")
        return status

    def _quarantine(self, path: str | Path, info: InspectionResult, verdict: dict[str, Any],
                    findings: list[tuple[str, str]]) -> dict[str, Any] | None:
        if not self.quarantine_on_detect:
            return None
        try:
            row = self.vault.register(path, info.sha256, info.size, verdict["malware_name"], verdict["severity"],
                                      detection="signature", quarantine=True, grace_seconds=self.grace_seconds)
        except ScannerError as exc:  # a vault problem must never hide the detection itself
            findings.append(("INFO", f"Karantina gagal dicatat: {exc}"))
            return None
        if row["status"] == "QUARANTINED":
            findings.append(("INFO", "Berkas dipindahkan ke karantina dan akan dihapus permanen dalam "
                                     f"{self.grace_seconds // 60} menit kecuali Anda memulihkannya."))
        elif row["status"] == "PENDING_IN_PLACE":
            findings.append(("INFO", f"Berkas tidak dapat dipindahkan ({row['note']}). Hapus manual, atau akan dihapus otomatis dalam "
                                     f"{self.grace_seconds // 60} menit."))
        else:
            findings.append(("INFO", row["note"] or "Berkas ditandai untuk ditinjau; tidak ada penghapusan otomatis."))
        return row

    def scan_file(self, path: str | Path) -> ScanReport:
        info = self.inspector.inspect_path(path, include_md5=True)
        verdict = self.matcher.check(info.sha256)
        findings: list[tuple[str, str]] = []
        status = "SAFE"
        threat: dict[str, Any] | None = None
        if verdict["match"]:
            status = "MALWARE"
            findings.append(("HASH_MATCH", f"SHA-256 cocok dengan signature {verdict['malware_name']} (tingkat {verdict['severity']})."))
            summary = f"MALWARE: {verdict['malware_name']}"
            threat = self._quarantine(path, info, verdict, findings)
        else:
            findings.append(("INFO", "Tidak ada kecocokan dengan database signature lokal. "
                                     "Ini bukan jaminan bebas malware: database hanya berisi signature yang Anda impor."))
            summary = "Tidak ada signature yang cocok."
        status = self._static_findings(info, findings, status)
        if status == "SUSPICIOUS":
            summary = "MENCURIGAKAN menurut analisis statis (tanpa signature)."
        findings.append(("INFO", f"SHA-256 {info.sha256} · ukuran {info.size} byte · jalur Bloom: {verdict['bloom']} · jenis {info.file_kind}."))
        report = ScanReport(status, "FILE", Path(path).name, sha256=info.sha256,
                            summary=f"{summary} SHA-256 {info.sha256}", findings=findings,
                            extra={"size": info.size, "md5": info.md5, "static_score": info.static_score,
                                   "threat_id": threat["id"] if threat else None,
                                   "original_path": str(Path(path).absolute())})
        return self._save(report)

    def scan_bytes(self, data: bytes, name: str = "upload") -> ScanReport:
        """Inspect an in-memory payload (used by the optional loopback API; no path is ever opened)."""
        info = self.inspector.inspect_bytes(data, name)
        verdict = self.matcher.check(info.sha256)
        findings: list[tuple[str, str]] = []
        if verdict["match"]:
            status = "MALWARE"
            findings.append(("HASH_MATCH", f"SHA-256 cocok dengan signature {verdict['malware_name']} (tingkat {verdict['severity']})."))
            summary = f"MALWARE: {verdict['malware_name']}"
        else:
            status = "SAFE"
            findings.append(("INFO", "Tidak ada kecocokan dengan database signature lokal. Ini bukan jaminan bebas malware."))
            summary = "Tidak ada signature yang cocok."
        status = self._static_findings(info, findings, status)
        if status == "SUSPICIOUS":
            summary = "MENCURIGAKAN menurut analisis statis (tanpa signature)."
        findings.append(("INFO", f"SHA-256 {info.sha256} · ukuran {info.size} byte · jalur Bloom: {verdict['bloom']}."))
        return self._save(ScanReport(status, "FILE", clean_text(name, 200), sha256=info.sha256,
                                     summary=f"{summary} SHA-256 {info.sha256}", findings=findings,
                                     extra={"size": info.size, "static_score": info.static_score}))

    def scan_folder(self, folder: str | Path, *, recursive: bool = True, max_files: int = 2000) -> dict[str, Any]:
        """Scan regular files in a folder. Symlinks and special files are skipped; work is bounded."""
        root = Path(folder)
        if not root.is_dir():
            raise ScanInputError("Folder tidak ditemukan.")
        scanned = skipped = unreadable = 0
        truncated = False
        reports: list[ScanReport] = []
        stack = [root]
        while stack:
            if scanned >= max_files:
                truncated = True  # unvisited sub-folders remain
                break
            current = stack.pop()
            try:
                entries = list(os.scandir(current))
            except OSError as exc:
                if current == root:
                    # Never answer "nothing found" for a folder that could not even be listed (on Android this is what
                    # happens without the 'All files access' permission).
                    raise ScanInputError(
                        "Folder tidak dapat dibaca (izin ditolak atau tidak tersedia). Di Android: Pengaturan > Aplikasi > "
                        "Kawal Trace > Izin > 'Akses semua file' (izin khusus), lalu coba lagi. Atau pindai satu file lewat "
                        "Pilih file.") from exc
                skipped += 1
                unreadable += 1
                continue
            for entry in entries:
                if scanned >= max_files:
                    truncated = True  # more entries were left unvisited in this folder
                    break
                try:
                    if entry.is_symlink():
                        skipped += 1
                    elif entry.is_dir(follow_symlinks=False):
                        if recursive:
                            stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        try:
                            report = self.scan_file(entry.path)
                        except ScannerError:
                            skipped += 1
                            continue
                        scanned += 1
                        if report.status != "SAFE":
                            reports.append(report)
                except OSError:
                    skipped += 1
        return {"scanned": scanned, "skipped": skipped, "unreadable": unreadable, "flagged": reports, "truncated": truncated}

    def scan_folder_report(self, folder: str | Path, *, recursive: bool = True, max_files: int = 2000) -> ScanReport:
        """Folder scan summarised as ONE history entry (the per-file results are stored as usual)."""
        result = self.scan_folder(folder, recursive=recursive, max_files=max_files)
        flagged: list[ScanReport] = result["flagged"]
        status = "SAFE"
        for item in flagged:
            status = _escalate(status, item.status)
        findings: list[tuple[str, str]] = []
        for item in flagged[:50]:
            kind = "HASH_MATCH" if item.status == "MALWARE" else "BAD_URL" if item.status == "PHISHING" else "STATIC"
            findings.append((kind, f"{item.file_name}: {item.status} - {item.summary[:160]}"))
        if len(flagged) > 50:
            findings.append(("INFO", f"{len(flagged) - 50} temuan lain tidak ditampilkan (lihat riwayat)."))
        note = f"{result['scanned']} file dipindai, {len(flagged)} ditandai, {result['skipped']} dilewati."
        incomplete = int(result.get("unreadable", 0))
        if incomplete:
            note += f" {incomplete} folder tidak dapat dibaca."
            findings.append(("INFO", f"{incomplete} folder tidak dapat dibaca (izin ditolak?): isinya BELUM dipindai, jadi hasil ini "
                                     "tidak berlaku untuk isi folder tersebut."))
        if result["truncated"]:
            findings.append(("INFO", f"Batas {max_files} file tercapai: sebagian isi folder BELUM dipindai."))
        findings.append(("INFO", note))
        label = {"SAFE": "Tidak ada kecocokan di folder" if not incomplete else "Tidak ada kecocokan pada file yang dapat dibaca",
                 "SUSPICIOUS": "Ada berkas mencurigakan di folder",
                 "PHISHING": "Ada temuan phishing di folder", "MALWARE": "MALWARE ditemukan di folder"}[status]
        return self._save(ScanReport(status, "FILE", clean_text(f"folder: {Path(folder).name or folder}", 200),
                                     summary=f"{label}. {note}", findings=findings,
                                     extra={"scanned": result["scanned"], "flagged": len(flagged),
                                            "truncated": result["truncated"]}))

    def submit_folder(self, folder: str | Path) -> str:
        return self.queue.submit(self.scan_folder_report, folder)

    def scan_email(self, raw: bytes | str | None = None, *, path: str | Path | None = None) -> ScanReport:
        parsed = parse_email_file(path) if path is not None else parse_email(raw if raw is not None else b"")
        name = Path(path).name if path is not None else (parsed.subject or "(email tanpa subjek)")
        return self._save(self._analyse_email(parsed, name))

    def scan_text(self, text: str, label: str = "teks yang ditempel") -> ScanReport:
        """Pasted message body or bare URL/domain: links + local AI, no header/attachment stages."""
        if not isinstance(text, str) or not text.strip():
            raise ScanInputError("Tempelkan teks email atau URL yang akan diperiksa.")
        if len(text) > 2_000_000:
            raise ScanInputError("Teks melebihi batas 2 juta karakter.")
        findings: list[tuple[str, str]] = []
        status = "SAFE"
        links = extract_links(text=text, html=text if "<" in text else "")
        if not links:
            bare = parse_url(text.strip()) if " " not in text.strip() else None
            if bare is not None:  # user pasted just "evil.example/login"
                links = [ExtractedLink(bare[2], "text")]
        status = self._check_links(links, findings, status)
        holder: dict[str, Any] = {}
        status = self._check_ai(text, findings, status, holder, links)
        report = ScanReport(status, "EMAIL", clean_text(label, 120), findings=findings,
                            ai_score=holder.get("score"),
                            summary=self._summary(status, findings, link_count=len(links)))
        return self._save(report)

    def scan_path(self, path: str | Path) -> ScanReport:
        """Flowchart entry point: .eml -> EMAIL flow, everything else -> FILE flow."""
        if str(path).lower().endswith(".eml"):
            return self.scan_email(path=path)
        return self.scan_file(path)

    def submit_path(self, path: str | Path) -> str:
        """Queue a scan on the worker thread; poll/await the returned job id."""
        return self.queue.submit(self.scan_path, path)

    # ---- internals ---------------------------------------------------------------
    def _analyse_email(self, parsed: ParsedEmail, display_name: str) -> ScanReport:
        findings: list[tuple[str, str]] = list(parsed.findings)
        status = "SAFE"

        for attachment in parsed.attachments:
            if attachment.sha256 is None:
                continue
            verdict = self.matcher.check(attachment.sha256)
            if verdict["match"]:
                status = _escalate(status, "MALWARE")
                findings.append(("HASH_MATCH", f"Lampiran {attachment.filename} cocok dengan signature "
                                               f"{verdict['malware_name']} ({verdict['severity']})."))
            if attachment.payload is not None:
                try:
                    info = self.inspector.inspect_bytes(attachment.payload, attachment.filename)
                except ScanInputError as exc:
                    findings.append(("INFO", f"Lampiran {attachment.filename}: analisis statis dilewati ({exc})."))
                else:
                    labelled: list[tuple[str, str]] = []
                    status = self._static_findings(info, labelled, status)
                    findings.extend((kind, f"Lampiran {attachment.filename}: {text}") for kind, text in labelled)
                finally:
                    attachment.payload = None  # release attachment bytes as soon as they were inspected
        if parsed.attachments:
            findings.append(("INFO", f"{len(parsed.attachments)} lampiran di-hash SHA-256 dan dicocokkan dengan database lokal."))

        links = extract_links(text=parsed.body_text, html=parsed.body_html)
        status = self._check_links(links, findings, status)

        body = parsed.body_text or parsed.body_html
        ai_text = f"{parsed.subject}\n{body}"
        holder: dict[str, Any] = {}
        status = self._check_ai(ai_text, findings, status, holder, links)

        report = ScanReport(status, "EMAIL", clean_text(display_name, 200), findings=findings,
                            ai_score=holder.get("score"),
                            summary=self._summary(status, findings, link_count=len(links),
                                                  attachments=len(parsed.attachments)),
                            extra={"from": parsed.sender, "auth": dict(parsed.auth), "links": len(links),
                                   "attachments": len(parsed.attachments)})
        return report

    def _check_links(self, links, findings: list[tuple[str, str]], status: str) -> str:
        heuristic_count = 0
        for verdict in self.urls.check_links(links):
            if verdict.blacklisted:
                status = _escalate(status, "PHISHING")
                findings.append(("BAD_URL", f"{verdict.url} terdaftar di blacklist lokal ({verdict.threat_type}; entri {verdict.matched_entry})."))
            if verdict.display_mismatch and heuristic_count < MAX_HEURISTIC_FINDINGS:
                heuristic_count += 1
                findings.append(("URL_HEURISTIC", f"Teks tautan menampilkan situs berbeda dari tujuan sebenarnya: {verdict.url}"))
            for message in verdict.heuristics:
                if heuristic_count >= MAX_HEURISTIC_FINDINGS:
                    break
                heuristic_count += 1
                findings.append(("URL_HEURISTIC", f"{verdict.host or verdict.url}: {message}"))
        if links:
            findings.append(("INFO", f"{len(links)} tautan dicocokkan dengan blacklist offline (tidak ada yang dibuka)."))
        return status

    def _check_ai(self, text: str, findings: list[tuple[str, str]], status: str, holder: dict[str, Any], links=()) -> str:
        """Ensemble verdict: text model + text/link signals. PHISHING and SUSPICIOUS are reported with their reasons;
        both use the AI_DETECTION finding type (the status carries the severity), because the history table only
        accepts the existing finding types."""
        if not self.classifier.available:
            findings.append(("INFO", f"Analisis AI tidak dijalankan: {self.classifier.status}"))
            return status
        verdict = self.classifier.assess(text, [(link.url, link.display_mismatch) for link in links])
        if verdict is None or verdict.band == "INCONCLUSIVE":
            findings.append(("INFO", "Analisis AI tidak meyakinkan: tidak ada istilah teks atau sinyal yang dikenal model."))
            return status
        holder["score"] = verdict.score
        percent = round(verdict.score * 100, 1)
        low, high = round(verdict.thresholds[0] * 100), round(verdict.thresholds[1] * 100)
        why = ("; ".join(label for label, _ in verdict.reasons[:3]) or "pola kata dalam pesan") + "."
        if verdict.band == "PHISHING":
            findings.append(("AI_DETECTION", f"Model AI lokal menilai pesan ini sangat mirip phishing: skor {percent}% (ambang {high}%). "
                                             f"Alasan: {why} Ini perkiraan statistik, bukan bukti."))
            return _escalate(status, "PHISHING")
        if verdict.band == "SUSPICIOUS":
            findings.append(("AI_DETECTION", f"Model AI lokal menilai pesan ini mencurigakan: skor {percent}% (mencurigakan mulai {low}%, "
                                             f"phishing mulai {high}%). Alasan: {why} Periksa manual sebelum membuka tautan atau membalas."))
            return _escalate(status, "SUSPICIOUS")
        if verdict.ensemble:
            findings.append(("INFO", f"Model AI lokal: skor phishing {percent}% (di bawah ambang mencurigakan {low}%)."))
        else:
            findings.append(("INFO", f"Model AI lokal: skor phishing {percent}% (di bawah ambang {high}%)."))
        return status

    @staticmethod
    def _summary(status: str, findings: list[tuple[str, str]], **counts: int) -> str:
        label = {"SAFE": "TIDAK ADA KECOCOKAN pada pemeriksaan lokal (bukan jaminan aman)",
                 "SUSPICIOUS": "MENCURIGAKAN, perlu diperiksa manual", "MALWARE": "MALWARE terdeteksi",
                 "PHISHING": "PHISHING terdeteksi"}[status]
        threats = [d for t, d in findings if t in {"HASH_MATCH", "BAD_URL", "AI_DETECTION", "STATIC"}]
        tail = " ".join(f"{k}={v}" for k, v in counts.items())
        return f"{label}. {threats[0] if threats else ''} {tail}".strip()
