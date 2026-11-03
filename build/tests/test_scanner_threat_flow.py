import hashlib
import sqlite3
from email.message import EmailMessage

import pytest

from detectors.pipeline import SecurityScanner
from detectors.scanner_db import ScannerDatabase


@pytest.fixture()
def env(tmp_path):
    app = tmp_path / "app"
    scanner = SecurityScanner(app / "scanner", seed_test_entries=True, protected_dirs=(app,))
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    yield scanner, downloads
    scanner.close()


def register_bad(scanner, data: bytes, name="Test.Trojan", severity="High"):
    digest = hashlib.sha256(data).hexdigest()
    scanner.import_signature_text(f"{digest},{name},{severity}")
    return digest


def test_signature_match_is_quarantined_and_scheduled(env):
    scanner, downloads = env
    data = b"sample-malware-bytes-for-test"
    digest = register_bad(scanner, data)
    path = downloads / "setup.bin"
    path.write_bytes(data)
    report = scanner.scan_file(path)
    assert report.status == "MALWARE" and report.sha256 == digest
    assert not path.exists()
    threats = scanner.vault.list_threats()
    assert len(threats) == 1 and threats[0]["id"] == report.extra["threat_id"]
    assert threats[0]["malware_name"] == "Test.Trojan" and threats[0]["status"] == "QUARANTINED"
    assert any("15 menit" in text for _, text in report.findings)
    assert scanner.stats()["threats_pending"] == 1


def test_quarantine_can_be_disabled_and_then_file_stays_put(env, tmp_path):
    scanner, downloads = env
    scanner.quarantine_on_detect = False
    data = b"another-sample"
    register_bad(scanner, data)
    path = downloads / "x.bin"
    path.write_bytes(data)
    assert scanner.scan_file(path).status == "MALWARE"
    assert path.exists() and scanner.vault.list_threats() == []


def test_clean_file_is_not_touched(env):
    scanner, downloads = env
    path = downloads / "notes.txt"
    path.write_text("my shopping list")
    report = scanner.scan_file(path)
    assert report.status == "SAFE" and path.exists() and scanner.vault.list_threats() == []
    assert "TIDAK ADA KECOCOKAN" in report.summary or "Tidak ada signature" in report.summary


def test_disguised_executable_is_suspicious_not_malware_and_never_auto_deleted(env):
    scanner, downloads = env
    path = downloads / "tagihan.pdf"
    path.write_bytes(b"MZ" + b"\x90" * 400)
    report = scanner.scan_file(path)
    assert report.status == "SUSPICIOUS" and any(kind == "STATIC" for kind, _ in report.findings)
    assert path.exists() and scanner.vault.list_threats() == []     # nothing moved, nothing scheduled


def test_scan_history_accepts_the_new_status(env):
    scanner, downloads = env
    path = downloads / "tagihan.pdf"
    path.write_bytes(b"MZ" + b"\x90" * 400)
    scanner.scan_file(path)
    assert scanner.db.history(1)[0]["status"] == "SUSPICIOUS"



def test_clear_history_deletes_all_scan_rows_and_details_but_keeps_signatures_and_phishing_list(env):
    scanner, downloads = env
    bad = b"registered-malware-for-history-clear"
    register_bad(scanner, bad, name="History.Clear.Test")
    scanner.import_phishing_text("history-clear-phishing.example")
    clean_path = downloads / "safe.txt"
    clean_path.write_text("safe file")
    bad_path = downloads / "bad.bin"
    bad_path.write_bytes(bad)
    scanner.scan_file(clean_path)
    scanner.scan_file(bad_path)
    scanner.scan_text("http://history-clear-phishing.example/login")

    before = scanner.db.history_count()
    assert before == 3
    assert any(scanner.db.details(row["id"]) for row in scanner.db.history(10))
    signatures_before = scanner.db.signature_count()
    phishing_before = scanner.db.phishing_count()

    removed = scanner.clear_history()
    assert removed == before
    assert scanner.db.history_count() == 0
    assert scanner.db.history(10) == []
    with scanner.db._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_details").fetchone()[0] == 0
    assert scanner.db.signature_count() == signatures_before
    assert scanner.db.phishing_count() == phishing_before

def test_email_attachment_is_inspected_in_memory(env):
    scanner, downloads = env
    msg = EmailMessage()
    msg["From"] = "a@example.org"; msg["To"] = "b@example.org"; msg["Subject"] = "Tagihan"
    msg.set_content("Terlampir tagihan.")
    msg.add_attachment(b"MZ" + b"\x90" * 400, maintype="application", subtype="octet-stream", filename="tagihan.pdf")
    report = scanner.scan_email(msg.as_bytes())
    assert report.status == "SUSPICIOUS"
    assert any("tagihan.pdf" in text and kind == "STATIC" for kind, text in report.findings)
    assert not list(downloads.iterdir())                             # nothing was written to disk


def test_email_attachment_signature_match_is_malware(env):
    scanner, downloads = env
    data = b"attachment-malware"
    register_bad(scanner, data)
    msg = EmailMessage()
    msg["From"] = "a@example.org"; msg["To"] = "b@example.org"; msg["Subject"] = "x"
    msg.set_content("hi")
    msg.add_attachment(data, maintype="application", subtype="zip", filename="a.zip")
    assert scanner.scan_email(msg.as_bytes()).status == "MALWARE"


def test_scan_folder_flags_only_bad_files_and_skips_symlinks(env, tmp_path):
    scanner, downloads = env
    bad = b"folder-malware"
    register_bad(scanner, bad)
    (downloads / "sub").mkdir()
    (downloads / "sub" / "bad.bin").write_bytes(bad)
    (downloads / "ok.txt").write_text("fine")
    (downloads / "disguised.jpg").write_bytes(b"MZ" + b"\x00" * 300)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    try:
        (downloads / "link").symlink_to(outside)
    except (OSError, NotImplementedError):
        pass
    result = scanner.scan_folder(downloads)
    flagged = {r.file_name: r.status for r in result["flagged"]}
    assert flagged == {"bad.bin": "MALWARE", "disguised.jpg": "SUSPICIOUS"}
    assert result["scanned"] == 3 and outside.exists()


def test_scan_folder_respects_the_file_limit(env):
    scanner, downloads = env
    for i in range(6):
        (downloads / f"f{i}.txt").write_text(str(i))
    result = scanner.scan_folder(downloads, max_files=3)
    assert result["scanned"] == 3 and result["truncated"] is True


def test_v1_database_is_migrated_without_losing_history(tmp_path):
    path = tmp_path / "scanner.sqlite3"
    with sqlite3.connect(path) as conn:      # the exact v1 schema shipped before this change
        conn.executescript("""
        CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE malware_signatures (id INTEGER PRIMARY KEY AUTOINCREMENT, hash_sha256 TEXT NOT NULL CHECK (length(hash_sha256) = 64),
            malware_name TEXT NOT NULL, severity TEXT NOT NULL CHECK (severity IN ('Low','Medium','High')));
        CREATE UNIQUE INDEX idx_signatures_hash ON malware_signatures(hash_sha256);
        CREATE TABLE phishing_urls (id INTEGER PRIMARY KEY AUTOINCREMENT, domain_or_url TEXT NOT NULL,
            threat_type TEXT NOT NULL CHECK (threat_type IN ('Phishing','Scam')));
        CREATE UNIQUE INDEX idx_phishing_domain_or_url ON phishing_urls(domain_or_url);
        CREATE TABLE scan_history (id INTEGER PRIMARY KEY AUTOINCREMENT, file_name TEXT NOT NULL,
            file_type TEXT NOT NULL CHECK (file_type IN ('FILE','EMAIL')), scan_date TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('SAFE','MALWARE','PHISHING')), details TEXT NOT NULL DEFAULT '');
        CREATE TABLE scan_details (id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
            finding_type TEXT NOT NULL CHECK (finding_type IN
                ('HASH_MATCH','AI_DETECTION','BAD_URL','HEADER_AUTH','HEADER_MISMATCH','URL_HEURISTIC','ATTACHMENT_RISK','INFO')),
            description TEXT NOT NULL);
        INSERT INTO schema_migrations VALUES (1, '2026-01-01T00:00:00Z');
        INSERT INTO malware_signatures(hash_sha256, malware_name, severity) VALUES ('%s','Old.Sig','High');
        INSERT INTO scan_history(id,file_name,file_type,scan_date,status,details) VALUES (7,'old.exe','FILE','2026-01-02T00:00:00Z','MALWARE','old');
        INSERT INTO scan_history(id,file_name,file_type,scan_date,status,details) VALUES (9,'mail.eml','EMAIL','2026-01-03T00:00:00Z','PHISHING','old2');
        INSERT INTO scan_details(scan_id,finding_type,description) VALUES (7,'HASH_MATCH','cocok');
        INSERT INTO scan_details(scan_id,finding_type,description) VALUES (9,'BAD_URL','url jahat');
        """ % ("ab" * 32))
    db = ScannerDatabase(path)
    db.initialize()
    assert db.schema_version() == 2
    assert [(r["id"], r["status"]) for r in db.history(10)] == [(9, "PHISHING"), (7, "MALWARE")]
    assert [d["description"] for d in db.details(7)] == ["cocok"]
    assert db.signature_count() == 1
    new_id = db.record_scan("x.pdf", "FILE", "SUSPICIOUS", "static", [("STATIC", "hidden exe")])
    assert new_id == 10 and db.details(new_id)[0]["finding_type"] == "STATIC"
    with sqlite3.connect(path) as conn:      # cascade still works after the rebuild
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("DELETE FROM scan_history WHERE id=7")
        assert conn.execute("SELECT COUNT(*) FROM scan_details WHERE scan_id=7").fetchone()[0] == 0
    db.initialize()                          # idempotent
    assert db.schema_version() == 2 and db.history_count() == 2


# --- unreadable folders must never be reported as clean --------------------------------------------------------------

def _deny_scandir(monkeypatch, denied):
    import os
    real = os.scandir

    def guarded(path="."):
        if os.fspath(path) in {os.fspath(p) for p in denied}:
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", guarded)


def test_a_folder_that_cannot_be_read_is_an_error_not_a_clean_result(env, monkeypatch):
    from detectors import ScanInputError
    scanner, downloads = env
    (downloads / "ok.txt").write_text("fine")
    _deny_scandir(monkeypatch, [downloads])
    with pytest.raises(ScanInputError) as caught:
        scanner.scan_folder(downloads)
    assert "tidak dapat dibaca" in str(caught.value) and "Akses semua file" in str(caught.value)
    with pytest.raises(ScanInputError):
        scanner.scan_folder_report(downloads)


def test_unreadable_subfolders_are_reported_and_not_called_clean(env, monkeypatch):
    scanner, downloads = env
    (downloads / "ok.txt").write_text("fine")
    (downloads / "locked").mkdir()
    (downloads / "locked" / "hidden.bin").write_bytes(b"never read")
    _deny_scandir(monkeypatch, [downloads / "locked"])
    result = scanner.scan_folder(downloads)
    assert result["scanned"] == 1 and result["skipped"] == 1 and result["unreadable"] == 1
    report = scanner.scan_folder_report(downloads)
    assert report.status == "SAFE"
    assert "Tidak ada kecocokan di folder" not in report.summary
    assert "tidak dapat dibaca" in report.summary and "1 folder" in report.summary
    assert any("tidak dapat dibaca" in text and "BELUM dipindai" in text for _, text in report.findings)


def test_a_fully_readable_folder_keeps_the_plain_clean_label(env):
    scanner, downloads = env
    (downloads / "ok.txt").write_text("fine")
    report = scanner.scan_folder_report(downloads)
    assert report.status == "SAFE" and "Tidak ada kecocokan di folder" in report.summary
    assert not any("tidak dapat dibaca" in text for _, text in report.findings)
