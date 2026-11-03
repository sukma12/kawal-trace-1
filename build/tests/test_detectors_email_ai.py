from __future__ import annotations

import hashlib
import json
import shutil
import threading
import time
from email.message import EmailMessage
from pathlib import Path

import pytest

import detectors.link_extractor as link_extractor
from detectors import ScanInputError
from detectors.email_parser import MAX_EMAIL_BYTES, parse_email, parse_email_file
from detectors.link_extractor import extract_links
from detectors.phishing_classifier import (
    MANIFEST_NAME, MODEL_JSON_NAME, MODEL_PKL_NAME, PhishingClassifier,
)
from detectors.scanner_db import ScannerDatabase
from detectors.task_queue import AsyncTaskQueue, QueueFullError
from detectors.text_preprocess import preprocess_text
from detectors.url_checker import LinkReputationChecker

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "ml_models"


def make_message(*, sender="Alice <alice@example.org>", subject="Hello", body="Hi there", html=None,
                 extra_headers=None, attachments=()):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, "bob@example.net", subject
    for key, value in (extra_headers or {}).items():
        msg[key] = value
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    for name, data in attachments:
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return msg.as_bytes()


# ---------------------------------------------------------------- link extractor
def test_links_from_text_and_html_with_hidden_target_and_dedupe():
    html = ('<p>Visit <a href="http://evil.example/login">https://www.mybank.example</a> now</p>'
            '<a href="HTTP://EVIL.example/login">dup</a><a href="mailto:a@b.example">mail</a>'
            '<a href="javascript:alert(1)">js</a><form action="http://collector.example/post"></form>')
    links = extract_links(text="see www.plain.example/path, and https://t.example/x).", html=html)
    urls = [l.url for l in links]
    assert "http://evil.example/login" in urls and urls.count("http://evil.example/login") == 1
    assert "http://collector.example/post" in urls and "http://www.plain.example/path" in urls
    assert "https://t.example/x" in urls                      # trailing ")." stripped
    assert not any(u.startswith(("mailto", "javascript")) for u in urls)
    hidden = next(l for l in links if l.url == "http://evil.example/login")
    assert hidden.display_mismatch                           # text shows mybank, target is evil


def test_link_extractor_stdlib_fallback_matches_bs4(monkeypatch):
    html = '<a href="http://evil.example/a">https://safe.example</a><iframe src="http://frame.example/"></iframe>'
    with_bs4 = [(l.url, l.display_mismatch) for l in extract_links(html=html)]
    monkeypatch.setattr(link_extractor, "BeautifulSoup", None)
    stdlib = [(l.url, l.display_mismatch) for l in extract_links(html=html)]
    assert sorted(stdlib) == sorted(with_bs4) and len(stdlib) == 2


def test_link_extractor_is_bounded_and_survives_malformed_html():
    many = " ".join(f"http://h{i}.example/" for i in range(500))
    assert len(extract_links(text=many)) == 100
    assert extract_links(html="<a href='http://x.example/'<<<>>> <div><a") is not None
    assert extract_links(text=None, html=None) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------- reputation checker
def test_reputation_checker_blacklist_and_heuristics(tmp_path):
    db = ScannerDatabase(tmp_path / "s.sqlite3")
    db.initialize()
    db.add_phishing_indicators([("evil.example", "Phishing")])
    checker = LinkReputationChecker(db)
    bad = checker.check("http://pay.evil.example/login")
    assert bad.blacklisted and bad.threat_type == "Phishing" and bad.matched_entry == "evil.example"
    ip = checker.check("http://203.0.113.9/x")
    assert not ip.blacklisted and any("alamat IP" in h for h in ip.heuristics)   # informational only
    assert not checker.check("https://fine.example/").blacklisted
    junk = checker.check("ftp://x")
    assert junk.host == "" and not junk.blacklisted


# ---------------------------------------------------------------- preprocessing
def test_preprocess_lowercases_strips_html_punctuation_and_keeps_url_words():
    out = preprocess_text("<style>x{}</style><b>URGENT!!</b> Verify: http://Pay-Pal.evil.example/login?id=1 &amp; go")
    assert out == out.lower() and "<" not in out and "!" not in out and "&amp" not in out
    assert "urltoken" in out and "pay" in out and "evil" in out and "x{}" not in out
    assert preprocess_text(None) == ""  # type: ignore[arg-type]
    assert len(preprocess_text("a " * 100_000)) <= 20_000


# ---------------------------------------------------------------- e-mail parser
def test_parser_reads_headers_attachments_and_auth_results():
    raw = make_message(
        sender="PayPal Support <noreply@paypa1-secure.example>",
        extra_headers={"Reply-To": "help@other.example", "Return-Path": "<bounce@third.example>",
                       "Authentication-Results": "mx.local; spf=fail smtp.mailfrom=x; dkim=none; dmarc=fail",
                       "DKIM-Signature": "v=1; a=rsa-sha256; d=unrelated.example; s=k; b=abc"},
        attachments=[("report.pdf.exe", b"MZ-fake"), ("notes.txt", b"hello")])
    parsed = parse_email(raw)
    assert parsed.auth == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    kinds = [t for t, _ in parsed.findings]
    assert kinds.count("HEADER_AUTH") == 3 and "HEADER_MISMATCH" in kinds and "ATTACHMENT_RISK" in kinds
    text = " ".join(d for _, d in parsed.findings)
    assert "Reply-To" in text and "Return-Path" in text and "DKIM" in text and "Ekstensi ganda" in text
    names = {a.filename: a for a in parsed.attachments}
    assert names["notes.txt"].sha256 == hashlib.sha256(b"hello").hexdigest()
    assert names["report.pdf.exe"].risk_notes


def test_parser_trusts_only_the_topmost_authentication_results_header():
    # The receiving server records only spf; a forged lower header claims dkim/dmarc passed.
    forged = "Authentication-Results: attacker.example; spf=pass; dkim=pass; dmarc=pass\r\n"
    raw = (b"Authentication-Results: mx.local; spf=fail\r\n" + forged.encode() +
           b"From: a@example.org\r\nSubject: s\r\n\r\nbody")
    parsed = parse_email(raw)
    assert parsed.auth == {"spf": "fail", "dkim": None, "dmarc": None}   # forged claims were not adopted
    assert sum(1 for t, d in parsed.findings if t == "HEADER_AUTH" and "tidak ada hasil" in d) == 2


def test_parser_detects_display_name_spoofing_and_missing_auth():
    parsed = parse_email(make_message(sender='"service@mybank.example" <crook@evil.example>'))
    descriptions = [d for _, d in parsed.findings]
    assert any("mybank.example" in d and "evil.example" in d for d in descriptions)
    assert sum(1 for t, _ in parsed.findings if t == "HEADER_AUTH") == 3   # no results -> reported, not assumed pass


def test_parser_sanitises_attachment_names_and_rejects_bad_input(tmp_path):
    raw = make_message(attachments=[("../../etc/passwd\u202egpj.exe", b"x")])
    attachment = parse_email(raw).attachments[0]
    assert "/" not in attachment.filename and ".." not in attachment.filename.split("passwd")[0]
    assert any("pembalik arah" in n for n in attachment.risk_notes)
    with pytest.raises(ScanInputError):
        parse_email(b"   ")
    with pytest.raises(ScanInputError):
        parse_email(b"x" * (MAX_EMAIL_BYTES + 1))
    with pytest.raises(ScanInputError):
        parse_email(12345)  # type: ignore[arg-type]
    with pytest.raises(ScanInputError):
        parse_email_file(tmp_path)
    eml = tmp_path / "m.eml"
    eml.write_bytes(make_message())
    assert parse_email_file(eml).subject == "Hello"


def test_parser_survives_malformed_mime():
    nasty = (b"From: =?utf-8?q?bad\r\nContent-Type: multipart/mixed; boundary=\r\n\r\n--\r\n"
             b"Content-Type: text/plain; charset=nonexistent-charset\r\n\r\n\xff\xfe broken")
    assert parse_email(nasty) is not None


# ---------------------------------------------------------------- classifier
def test_shipped_model_flags_obvious_phishing_and_passes_ordinary_mail():
    clf = PhishingClassifier.load(MODEL_DIR)
    assert clf.available, clf.status
    phish = clf.assess("Your account is suspended. Verify your password immediately http://secure-login.example.xyz/verify",
                       [("http://secure-login.example.xyz/verify", False)])
    assert phish.band == "PHISHING" and phish.ensemble and phish.reasons
    bank = clf.assess("Akun BCA Anda diblokir, segera konfirmasi PIN dan OTP di http://bca-secure.xyz", [("http://bca-secure.xyz/", False)])
    assert bank.band == "PHISHING"
    assert any("meniru merek" in label or "kata sandi" in label for label, _ in bank.reasons)
    ordinary = clf.assess("Hi team, attached are the minutes of today's meeting. Thanks!")
    assert ordinary.band == "SAFE" and ordinary.score < ordinary.thresholds[0]
    unseen = clf.assess("zzzz qqqq xxxx")
    assert unseen.band == "INCONCLUSIVE" and unseen.known_terms == 0


def _fresh_sklearn_nb():
    """The Naive Bayes half of the shipped training recipe, rebuilt here with scikit-learn."""
    pytest.importorskip("sklearn")
    import sys
    sys.path.insert(0, str(ROOT))
    from ml_models.corpus_seed import seed_rows
    from ml_models.train_model import build_spec, fit_nb
    rows = seed_rows()
    vec, nb = fit_nb([t for _, _, t in rows], [l for _, l, _ in rows])
    return vec, nb, build_spec(vec, nb, None, {})


def test_portable_inference_matches_scikit_learn_exactly():
    vec, nb, spec = _fresh_sklearn_nb()
    from detectors.phishing_classifier import PortableNaiveBayes
    portable = PortableNaiveBayes(spec)
    for text in ["Verify your PayPal password now http://paypa1.evil.xyz", "Rapat besok pukul 9, notulen terlampir",
                 "Final notice: pay the customs fee to release your package", "lunch on friday?", "Segera konfirmasi PIN dan OTP Anda"]:
        reference = float(nb.predict_proba(vec.transform([preprocess_text(text)]))[0][1])
        assert portable.predict(text).score == pytest.approx(reference, abs=1e-9)


def test_shipped_model_text_part_is_what_the_training_recipe_produces():
    """Guards against the JSON and the corpus/recipe drifting apart (someone edits one without retraining)."""
    _, _, fresh = _fresh_sklearn_nb()
    shipped = json.loads((MODEL_DIR / MODEL_JSON_NAME).read_text(encoding="utf-8"))
    assert set(shipped["terms"]) == set(fresh["terms"])
    for term in list(fresh["terms"])[:200]:
        assert shipped["terms"][term] == pytest.approx(fresh["terms"][term], abs=1e-9)
    assert shipped["class_log_prior"] == pytest.approx(fresh["class_log_prior"], abs=1e-9)


def test_model_checksum_mismatch_is_refused_and_pickle_is_opt_in(tmp_path):
    joblib = pytest.importorskip("joblib")
    from sklearn.pipeline import Pipeline
    vec, nb, _ = _fresh_sklearn_nb()
    shutil.copy(MODEL_DIR / MODEL_JSON_NAME, tmp_path / MODEL_JSON_NAME)
    joblib.dump(Pipeline([("tfidf", vec), ("nb", nb)]), tmp_path / MODEL_PKL_NAME)      # a developer-built pickle
    manifest = {"sha256": {MODEL_JSON_NAME: hashlib.sha256((tmp_path / MODEL_JSON_NAME).read_bytes()).hexdigest(),
                           MODEL_PKL_NAME: hashlib.sha256((tmp_path / MODEL_PKL_NAME).read_bytes()).hexdigest()}}
    (tmp_path / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    assert PhishingClassifier.load(tmp_path).available
    # tampering with the portable model is detected through MODEL_MANIFEST.json
    spec = json.loads((tmp_path / MODEL_JSON_NAME).read_text(encoding="utf-8"))
    spec["class_log_prior"] = [-5.0, -0.0001]
    (tmp_path / MODEL_JSON_NAME).write_text(json.dumps(spec), encoding="utf-8")
    refused = PhishingClassifier.load(tmp_path)
    assert not refused.available and "checksum" in refused.status
    # with the JSON gone, the pickle is ignored unless explicitly allowed, then still hash-checked
    (tmp_path / MODEL_JSON_NAME).unlink()
    assert not PhishingClassifier.load(tmp_path).available
    assert PhishingClassifier.load(tmp_path, allow_pickle=True).available
    (tmp_path / MODEL_PKL_NAME).write_bytes((tmp_path / MODEL_PKL_NAME).read_bytes() + b"x")
    tampered = PhishingClassifier.load(tmp_path, allow_pickle=True)
    assert not tampered.available and "checksum" in tampered.status


def test_missing_or_malformed_model_reports_unavailable(tmp_path):
    assert not PhishingClassifier.load(tmp_path / "nothing").available
    (tmp_path / MODEL_JSON_NAME).write_text("{not json", encoding="utf-8")
    assert not PhishingClassifier.load(tmp_path).available
    (tmp_path / MODEL_JSON_NAME).write_text(json.dumps({"format": "kawaltrace-portable-nb", "version": 1}), encoding="utf-8")
    assert not PhishingClassifier.load(tmp_path).available


# ---------------------------------------------------------------- task queue
def test_queue_runs_jobs_off_thread_and_records_errors():
    q = AsyncTaskQueue(workers=2)
    main_thread = threading.current_thread().name
    ok = q.submit(lambda x: (x * 2, threading.current_thread().name), 21)
    bad = q.submit(lambda: 1 / 0)
    done = q.wait(ok, timeout=5)
    assert done.status == "done" and done.result[0] == 42 and done.result[1] != main_thread
    failed = q.wait(bad, timeout=5)
    assert failed.status == "error" and "ZeroDivisionError" in failed.error
    q.shutdown()


def test_queue_is_bounded_cancels_queued_jobs_and_rejects_after_shutdown():
    gate = threading.Event()
    q = AsyncTaskQueue(workers=1, max_queue=2)
    q.submit(gate.wait, 5)                          # occupies the only worker
    time.sleep(0.1)
    queued = q.submit(lambda: "later")
    q.submit(lambda: "x")
    with pytest.raises(QueueFullError):
        q.submit(lambda: "overflow")
    assert q.cancel(queued) is True and q.get(queued).status == "cancelled"
    gate.set()
    q.shutdown()
    with pytest.raises(Exception):
        q.submit(lambda: 1)


def test_queue_wait_async():
    import asyncio
    q = AsyncTaskQueue()
    job_id = q.submit(lambda: "async-ok")
    job = asyncio.run(q.wait_async(job_id, 5))
    assert job.result == "async-ok"
    q.shutdown()
