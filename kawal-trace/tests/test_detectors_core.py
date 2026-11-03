from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from detectors import ScanInputError
from detectors.bloom_filter import BloomFilter, BloomFilterError
from detectors.hashing import hash_bytes, hash_file
from detectors.scanner_db import ScannerDatabase, ScannerDatabaseError
from detectors.signature_matcher import SignatureMatcher
from detectors.urlnorm import host_candidates, normalize_host, normalize_indicator, parse_url

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA = hashlib.sha256(EICAR).hexdigest()


# ---------------------------------------------------------------- hashing
def test_hash_file_matches_hashlib_and_streams_large_files(tmp_path):
    big = tmp_path / "big.bin"
    payload = b"abc123" * 700_000  # > 4 MiB: spans several 1 MiB chunks
    big.write_bytes(payload)
    result = hash_file(big, include_md5=True)
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["md5"] == hashlib.md5(payload, usedforsecurity=False).hexdigest()
    assert result["size"] == len(payload)
    assert "md5" not in hash_file(big)


def test_hash_file_rejects_missing_directory_oversize_and_nul(tmp_path):
    with pytest.raises(ScanInputError, match="tidak ditemukan"):
        hash_file(tmp_path / "nope.bin")
    with pytest.raises(ScanInputError, match="file biasa"):
        hash_file(tmp_path)
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x" * 2048)
    with pytest.raises(ScanInputError, match="melebihi batas"):
        hash_file(sample, max_bytes=1024)
    with pytest.raises(ScanInputError):
        hash_file("bad\x00name")


def test_hash_bytes_known_vector():
    assert hash_bytes(b"")["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert hash_bytes(EICAR)["sha256"] == EICAR_SHA
    with pytest.raises(ScanInputError):
        hash_bytes("not bytes")  # type: ignore[arg-type]


# ---------------------------------------------------------------- bloom filter
def test_bloom_has_no_false_negatives_and_low_false_positive_rate():
    bloom = BloomFilter(capacity=5000, error_rate=0.001)
    members = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(5000)]
    for item in members:
        bloom.add(item)
    assert all(item in bloom for item in members)  # a Bloom filter must never miss a member
    outsiders = [hashlib.sha256(f"x{i}".encode()).hexdigest() for i in range(20_000)]
    false_positives = sum(1 for item in outsiders if item in bloom)
    assert false_positives / len(outsiders) < 0.01
    assert bloom.estimated_false_positive_rate() < 0.01


def test_bloom_is_far_smaller_than_the_raw_hash_list():
    bloom = BloomFilter(capacity=100_000, error_rate=0.001)
    raw_hash_list_bytes = 100_000 * 64
    assert bloom.size_bytes < raw_hash_list_bytes / 3


def test_bloom_roundtrip_and_tamper_detection(tmp_path):
    bloom = BloomFilter(capacity=100)
    bloom.add(EICAR_SHA)
    path = tmp_path / "b.bin"
    bloom.save(path)
    assert not list(tmp_path.glob(".bloom-*"))  # atomic write leaves no temp file
    loaded = BloomFilter.load(path)
    assert EICAR_SHA in loaded and loaded.count == 1
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0xFF
    path.write_bytes(bytes(blob))
    with pytest.raises(BloomFilterError, match="Checksum"):
        BloomFilter.load(path)
    path.write_bytes(b"short")
    with pytest.raises(BloomFilterError):
        BloomFilter.load(path)
    with pytest.raises(BloomFilterError):
        BloomFilter.load(tmp_path / "missing.bin")


# ---------------------------------------------------------------- url normalisation
def test_normalize_host_idna_case_and_dots():
    assert normalize_host("Example.COM.") == "example.com"
    assert normalize_host("bücher.example") == "xn--bcher-kva.example"
    assert normalize_host("bad host.com") is None
    assert normalize_host("-bad.com") is None
    assert normalize_host("a" * 300 + ".com") is None


def test_parse_url_defeats_common_parser_tricks():
    assert parse_url("http://good.example\\@evil.example/")[1] == "good.example"   # backslash == slash in browsers
    assert parse_url("http://good.example@evil.example/login")[1] == "evil.example"  # userinfo is not the host
    assert parse_url("HTTP://EVIL.Example:80/a?b=1#frag")[2] == "http://evil.example/a?b=1"
    assert parse_url("evil.example/login")[2] == "http://evil.example/login"
    assert parse_url("javascript:alert(1)") is None
    assert parse_url("mailto:a@b.example") is None
    assert parse_url("file:///etc/passwd") is None
    assert parse_url("http://") is None
    assert parse_url("x" * 5000) is None


def test_host_candidates_and_indicators():
    assert host_candidates("a.b.evil.example") == ["a.b.evil.example", "b.evil.example", "evil.example"]
    assert normalize_indicator("Evil.Example") == ("domain", "evil.example")
    assert normalize_indicator("http://evil.example/") == ("domain", "evil.example")
    assert normalize_indicator("http://evil.example/login?id=1") == ("url", "http://evil.example/login?id=1")
    assert normalize_indicator("not a domain") is None
    assert normalize_indicator("localhost") is None


# ---------------------------------------------------------------- database
@pytest.fixture
def db(tmp_path):
    database = ScannerDatabase(tmp_path / "scanner.sqlite3")
    database.initialize()
    return database


def test_schema_has_required_tables_columns_and_indexes(db):
    with sqlite3.connect(db.path) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        cols = {t: [r[1] for r in conn.execute(f"PRAGMA table_info({t})")] for t in
                ("malware_signatures", "phishing_urls", "scan_history", "scan_details")}
    assert {"malware_signatures", "phishing_urls", "scan_history", "scan_details", "schema_migrations"} <= tables
    assert cols["malware_signatures"] == ["id", "hash_sha256", "malware_name", "severity"]
    assert cols["phishing_urls"] == ["id", "domain_or_url", "threat_type"]
    assert cols["scan_history"] == ["id", "file_name", "file_type", "scan_date", "status", "details"]
    assert cols["scan_details"] == ["id", "scan_id", "finding_type", "description"]
    assert {"idx_signatures_hash", "idx_phishing_domain_or_url"} <= indexes
    assert db.schema_version() == 2
    db.initialize()  # idempotent: re-running must not duplicate or fail
    assert db.schema_version() == 2


def test_signature_lookup_uses_the_index(db):
    db.add_signatures([(EICAR_SHA, "EICAR", "Low")])
    with sqlite3.connect(db.path) as conn:
        plan = " ".join(str(r) for r in conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM malware_signatures WHERE hash_sha256 = ?", (EICAR_SHA,)))
    assert "idx_signatures_hash" in plan


def test_signature_import_validates_and_updates(db):
    inserted, rejected = db.add_signatures([
        (EICAR_SHA.upper(), "EICAR", "low"),          # case-insensitive input, canonicalised
        ("zz" * 32, "Bad hash", "High"),                # not hex
        (EICAR_SHA[:60], "Short", "High"),              # wrong length
        ("a" * 64, "", "High"),                          # empty name
        ("b" * 64, "Sev", "Critical"),                   # unsupported severity
    ])
    assert (inserted, rejected) == (1, 4)
    assert db.lookup_signature(EICAR_SHA)["severity"] == "Low"
    db.add_signatures([(EICAR_SHA, "EICAR renamed", "High")])
    assert db.signature_count() == 1 and db.lookup_signature(EICAR_SHA)["malware_name"] == "EICAR renamed"
    assert db.lookup_signature("not-a-hash") is None


def test_sql_injection_strings_are_stored_as_data_not_executed(db):
    nasty = "evil.example'; DROP TABLE malware_signatures; --"
    assert db.add_phishing_indicators([(nasty, "Phishing")]) == (0, 1)   # not a valid domain -> rejected
    assert db.lookup_phishing("http://x.example/?q=' OR 1=1 --") is None
    db.add_signatures([(EICAR_SHA, "x'); DROP TABLE scan_history;--", "High")])
    assert db.lookup_signature(EICAR_SHA)["malware_name"].startswith("x')")
    assert db.signature_count() == 1 and db.history_count() == 0  # tables still exist


def test_phishing_lookup_domain_parent_and_exact_url(db):
    db.add_phishing_indicators([("evil.example", "Phishing"), ("http://good.example/steal?id=7", "Scam")])
    assert db.lookup_phishing("https://evil.example/anything")["threat_type"] == "Phishing"
    assert db.lookup_phishing("http://login.secure.evil.example/")["domain_or_url"] == "evil.example"
    assert db.lookup_phishing("http://good.example/steal?id=7")["threat_type"] == "Scam"
    assert db.lookup_phishing("http://good.example/other") is None       # URL entry does not blacklist the whole site
    assert db.lookup_phishing("http://notevil.example/") is None          # suffix match must respect label boundaries
    assert db.lookup_phishing("garbage") is None and db.lookup_phishing("") is None   # junk input never raises


def test_history_roundtrip_with_details_and_sanitisation(db):
    scan_id = db.record_scan("inv\x00oice\n.eml", "EMAIL", "PHISHING", "ringkasan",
                             [("BAD_URL", "http://evil.example"), ("INFO", "ok")])
    row = db.history()[0]
    assert row["id"] == scan_id and row["status"] == "PHISHING" and "\x00" not in row["file_name"]
    assert [d["finding_type"] for d in db.details(scan_id)] == ["BAD_URL", "INFO"]
    with pytest.raises(ScannerDatabaseError):
        db.record_scan("x", "FILE", "UNKNOWN", "", [])
    with pytest.raises(ScannerDatabaseError):
        db.record_scan("x", "FILE", "SAFE", "", [("MADE_UP", "d")])
    assert db.history_count() == 1  # the failed insert rolled back, no orphan row


def test_prune_removes_only_rows_older_than_30_days_and_cascades(db):
    now = datetime(2026, 10, 28, tzinfo=timezone.utc)
    old = db.record_scan("old.bin", "FILE", "SAFE", "", [("INFO", "old")], when=now - timedelta(days=31))
    edge = db.record_scan("edge.bin", "FILE", "SAFE", "", [("INFO", "edge")], when=now - timedelta(days=29, hours=23))
    new = db.record_scan("new.bin", "FILE", "MALWARE", "", [("HASH_MATCH", "new")], when=now)
    assert db.prune_history(30, now=now) == 1
    remaining = {r["id"] for r in db.history()}
    assert remaining == {edge, new} and old not in remaining
    assert db.details(old) == []                 # cascade removed the findings of the pruned scan
    assert len(db.details(new)) == 1
    with pytest.raises(ScannerDatabaseError):
        db.prune_history(0)


# ---------------------------------------------------------------- signature matcher
def test_matcher_bloom_miss_hit_and_false_positive_confirmation(db, tmp_path):
    matcher = SignatureMatcher(db, tmp_path / "sig.bloom")
    matcher.load()
    assert matcher.check(EICAR_SHA)["match"] is False
    assert matcher.import_signatures([(EICAR_SHA, "EICAR", "Low")]) == (1, 0)
    hit = matcher.check(EICAR_SHA)
    assert hit["match"] and hit["bloom"] == "hit" and hit["malware_name"] == "EICAR"
    clean = matcher.check(hashlib.sha256(b"clean").hexdigest())
    assert clean["match"] is False and clean["bloom"] == "miss"
    # force a Bloom false positive: filter says "maybe" but SQLite has no such hash -> must be SAFE
    other = hashlib.sha256(b"other").hexdigest()
    matcher._bloom.add(other)
    fp = matcher.check(other)
    assert fp["bloom"] == "hit" and fp["match"] is False


def test_stale_or_corrupt_bloom_is_rebuilt_never_trusted(db, tmp_path):
    path = tmp_path / "sig.bloom"
    first = SignatureMatcher(db, path)
    first.load()
    first.import_signatures([(EICAR_SHA, "EICAR", "Low")])
    # a signature added straight to the DB makes the saved filter stale (would be a false negative)
    late = hashlib.sha256(b"late").hexdigest()
    db.add_signatures([(late, "Late", "High")])
    second = SignatureMatcher(db, path)
    second.load()
    assert second.bloom_state == "stale-rebuilt" and second.check(late)["match"]
    path.write_bytes(b"garbage garbage garbage garbage garbage")
    third = SignatureMatcher(db, path)
    third.load()
    assert third.bloom_state == "missing-or-corrupt-rebuilt" and third.check(EICAR_SHA)["match"]


def test_matcher_without_filter_fails_safe_to_database(db, tmp_path):
    db.add_signatures([(EICAR_SHA, "EICAR", "Low")])
    matcher = SignatureMatcher(db, tmp_path / "never-loaded.bloom")   # load() not called
    verdict = matcher.check(EICAR_SHA)
    assert verdict["match"] and verdict["bloom"] == "unavailable"
