from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

import pytest

from detectors import ScanInputError
from detectors.pipeline import EICAR_SHA256, SecurityScanner

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
PHISH_TEXT = "Your account has been suspended. Verify your password immediately at http://secure-login.example.xyz/verify"


@pytest.fixture
def scanner(tmp_path):
    instance = SecurityScanner(tmp_path / "data")
    yield instance
    instance.close()


def email_bytes(subject="Hi", body="Meeting notes attached.", attachments=(), html=None):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "alice@example.org", "bob@example.net", subject
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    for name, data in attachments:
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return msg.as_bytes()


def test_eicar_constant_is_the_real_sha256():
    assert hashlib.sha256(EICAR).hexdigest() == EICAR_SHA256


def test_clean_file_is_safe_and_eicar_file_is_malware_end_to_end(scanner, tmp_path):
    clean = tmp_path / "clean.txt"
    clean.write_bytes(b"just a note")
    eicar = tmp_path / "eicar.com"
    eicar.write_bytes(EICAR)
    safe = scanner.scan_file(clean)
    assert safe.status == "SAFE" and safe.sha256 == hashlib.sha256(b"just a note").hexdigest()
    assert any("bukan jaminan" in d for _, d in safe.findings)      # SAFE never claims certainty
    bad = scanner.scan_file(eicar)
    assert bad.status == "MALWARE" and any(t == "HASH_MATCH" for t, _ in bad.findings)
    # history + details are persisted (flowchart: SIMPAN RIWAYAT KE SQLITE)
    rows = scanner.db.history()
    assert [r["status"] for r in rows] == ["MALWARE", "SAFE"] and rows[0]["file_type"] == "FILE"
    assert scanner.db.details(bad.scan_id)[0]["finding_type"] == "HASH_MATCH"


def test_file_errors_do_not_create_a_clean_history_row(scanner, tmp_path):
    with pytest.raises(ScanInputError):
        scanner.scan_file(tmp_path / "missing.bin")
    assert scanner.db.history_count() == 0


def test_imported_signature_list_takes_effect_immediately(scanner, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"pretend malware body")
    digest = hashlib.sha256(b"pretend malware body").hexdigest()
    assert scanner.scan_file(sample).status == "SAFE"
    inserted, rejected = scanner.import_signature_text(
        f"# comment\n{digest},Test.Trojan,High\nnot-a-hash,Bad,High\n\n")
    assert (inserted, rejected) == (1, 1)
    assert scanner.scan_file(sample).status == "MALWARE"


def test_email_with_malware_attachment_is_malware(scanner):
    report = scanner.scan_email(email_bytes(attachments=[("invoice.pdf", EICAR)]))
    assert report.status == "MALWARE" and report.file_type == "EMAIL"
    assert any(t == "HASH_MATCH" and "invoice.pdf" in d for t, d in report.findings)


def test_email_with_blacklisted_link_is_phishing_even_with_friendly_text(scanner):
    scanner.import_phishing_text("evil-bank.example\n")
    raw = email_bytes(body="See the statement", html='<a href="http://login.evil-bank.example/s">my bank</a>')
    report = scanner.scan_email(raw)
    assert report.status == "PHISHING" and any(t == "BAD_URL" for t, _ in report.findings)


def test_seeded_test_domain_triggers_phishing_for_pipeline_demo(scanner):
    assert scanner.scan_text("click http://phishing-test.invalid/now").status == "PHISHING"


def test_ai_threshold_70_percent_decides_phishing_for_text_without_known_bad_links(scanner):
    report = scanner.scan_email(email_bytes(subject="Urgent", body=PHISH_TEXT))
    assert report.status == "PHISHING" and report.ai_score >= 0.70
    assert any(t == "AI_DETECTION" for t, _ in report.findings)
    benign = scanner.scan_email(email_bytes(subject="Notes", body="Hi, minutes of the meeting are attached. Thanks."))
    assert benign.status == "SAFE" and benign.ai_score < 0.70
    assert not any(t == "AI_DETECTION" for t, _ in benign.findings)


def test_status_priority_malware_over_phishing_over_safe(scanner):
    raw = email_bytes(subject="Urgent", body=PHISH_TEXT, attachments=[("a.bin", EICAR)])
    assert scanner.scan_email(raw).status == "MALWARE"


def test_informational_heuristics_alone_never_flip_status(scanner):
    raw = email_bytes(body="Docs here: http://203.0.113.7:8080/report and notes for tomorrow's meeting.")
    report = scanner.scan_email(raw)
    assert any(t == "URL_HEURISTIC" for t, _ in report.findings)
    assert report.status == "SAFE"


def test_missing_model_is_reported_and_never_counts_as_a_clean_ai_pass(tmp_path):
    empty_models = tmp_path / "no-models"
    empty_models.mkdir()
    s = SecurityScanner(tmp_path / "d", model_dir=empty_models)
    try:
        report = s.scan_text(PHISH_TEXT)
        assert report.status == "SAFE" and report.ai_score is None   # no blacklist hit, no model
        assert any("AI tidak dijalankan" in d for _, d in report.findings)
        assert s.stats()["ai_available"] is False
    finally:
        s.close()


def test_unknown_terms_are_inconclusive_not_safe_with_a_score(scanner):
    report = scanner.scan_text("zzzz qqqq xxxx")
    assert report.ai_score is None and any("tidak meyakinkan" in d for _, d in report.findings)


def test_scan_path_routes_eml_to_email_flow(scanner, tmp_path):
    eml = tmp_path / "msg.eml"
    eml.write_bytes(email_bytes(attachments=[("x.bin", EICAR)]))
    assert scanner.scan_path(eml).status == "MALWARE" and scanner.scan_path(eml).file_type == "EMAIL"
    plain = tmp_path / "doc.txt"
    plain.write_text("hello")
    assert scanner.scan_path(plain).file_type == "FILE"


def test_text_input_validation(scanner):
    with pytest.raises(ScanInputError):
        scanner.scan_text("   ")
    with pytest.raises(ScanInputError):
        scanner.scan_text("x" * 2_000_001)
    assert scanner.scan_text("evil.example/login").file_type == "EMAIL"   # bare domain accepted as a link


def test_heavy_scans_run_through_the_async_queue_without_blocking(scanner, tmp_path):
    files = []
    for i in range(12):
        f = tmp_path / f"f{i}.bin"
        f.write_bytes(EICAR if i % 4 == 0 else f"data-{i}".encode())
        files.append(f)
    ids = [scanner.submit_path(f) for f in files]
    results = [scanner.queue.wait(j, timeout=20) for j in ids]
    assert all(r.status == "done" for r in results)
    assert sorted(r.result.status for r in results).count("MALWARE") == 3
    assert scanner.db.history_count() == 12          # concurrent writers did not lose rows


def test_prune_runs_on_start_and_removes_old_history(tmp_path):
    first = SecurityScanner(tmp_path / "d")
    first.db.record_scan("ancient.bin", "FILE", "SAFE", "", [("INFO", "old")],
                         when=datetime.now(timezone.utc) - timedelta(days=45))
    first.db.record_scan("recent.bin", "FILE", "SAFE", "", [("INFO", "new")])
    first.close()
    second = SecurityScanner(tmp_path / "d")
    try:
        assert second.pruned_on_start == 1
        assert [r["file_name"] for r in second.db.history()] == ["recent.bin"]
    finally:
        second.close()


def test_data_persists_across_restart(tmp_path):
    a = SecurityScanner(tmp_path / "d")
    a.import_phishing_text("evil.example")
    a.scan_text("http://evil.example/x")
    a.close()
    b = SecurityScanner(tmp_path / "d")
    try:
        assert b.scan_text("http://evil.example/y").status == "PHISHING" and b.db.history_count() == 2
        assert b.matcher.bloom_state == "loaded"
    finally:
        b.close()


def test_stats_reflect_state(scanner):
    stats = scanner.stats()
    assert stats["signatures"] == 1 and stats["phishing_entries"] == 1 and stats["ai_available"]
    assert stats["bloom"]["state"] in {"loaded", "missing-or-corrupt-rebuilt"} and stats["schema_version"] == 2


# ---------------------------------------------------------------- optional loopback API
def test_local_api_requires_token_and_scans_by_value(scanner):
    pytest.importorskip("flask")
    from detectors.local_api import create_app
    token = "t" * 40
    client = create_app(scanner, token).test_client()
    assert client.get("/api/v1/health").status_code == 401
    assert client.get("/api/v1/health", headers={"Authorization": "Bearer wrong"}).status_code == 401
    auth = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/health", headers=auth).get_json()["status"] == "ok"
    body = client.post("/api/v1/scan/file", data=EICAR, headers={**auth, "X-File-Name": "eicar.com"}).get_json()
    assert body["status"] == "MALWARE" and body["sha256"] == EICAR_SHA256
    text = client.post("/api/v1/scan/text", data=json.dumps({"text": PHISH_TEXT}),
                       headers={**auth, "Content-Type": "application/json"}).get_json()
    assert text["status"] == "PHISHING"
    assert client.post("/api/v1/scan/email", data=b"  ", headers=auth).status_code == 400
    assert client.get("/api/v1/history?limit=5", headers=auth).get_json()["items"]
    with pytest.raises(ValueError):
        create_app(scanner, "short")


def test_local_api_refuses_non_loopback_bind(scanner):
    pytest.importorskip("flask")
    from detectors.local_api import serve_in_thread
    with pytest.raises(ValueError, match="loopback"):
        serve_in_thread(scanner, host="0.0.0.0")


def test_local_api_real_socket_roundtrip(scanner):
    pytest.importorskip("flask")
    import http.client
    from detectors.local_api import serve_in_thread
    server, token, port = serve_in_thread(scanner)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/api/v1/scan/file", body=EICAR, headers={"Authorization": f"Bearer {token}"})
        reply = conn.getresponse()
        assert reply.status == 200 and json.loads(reply.read())["status"] == "MALWARE"
        conn.request("GET", "/api/v1/health")
        assert conn.getresponse().status == 401
    finally:
        server.shutdown()
