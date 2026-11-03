"""Signature Matcher: SHA-256 -> Bloom filter -> SQLite exact match.

Flow (per project spec): a Bloom miss is a definite "not in set" (SAFE for this check);
a Bloom hit is only "maybe" and is confirmed in SQLite. The Bloom file is checked
against the DB on load; when it is missing, corrupt or out of date it is rebuilt from
SQLite, and until then every lookup goes straight to SQLite so a stale filter can never
hide a known signature.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .bloom_filter import BloomFilter, BloomFilterError
from .scanner_db import ScannerDatabase


class SignatureMatcher:
    def __init__(self, db: ScannerDatabase, bloom_path: str | Path) -> None:
        self.db = db
        self.bloom_path = Path(bloom_path)
        self._bloom: BloomFilter | None = None
        self.bloom_state = "not-loaded"

    def load(self) -> None:
        expected = self.db.signature_count()
        try:
            candidate = BloomFilter.load(self.bloom_path)
            if candidate.count == expected:
                self._bloom, self.bloom_state = candidate, "loaded"
                return
            self.bloom_state = "stale-rebuilt"
        except BloomFilterError:
            self.bloom_state = "missing-or-corrupt-rebuilt"
        self.rebuild()

    def rebuild(self) -> None:
        hashes = self.db.all_signature_hashes()
        bloom = BloomFilter(capacity=max(1024, len(hashes) * 2), error_rate=0.001)
        for digest in hashes:
            bloom.add(digest)
        bloom.save(self.bloom_path)
        self._bloom = bloom

    def import_signatures(self, rows) -> tuple[int, int]:
        inserted, rejected = self.db.add_signatures(rows)
        self.rebuild()  # DB first, then filter: never the other way round
        return inserted, rejected

    def check(self, sha256: str) -> dict[str, Any]:
        digest = str(sha256 or "").strip().lower()
        if self._bloom is None:
            # Fail safe: no filter available -> trust only the database.
            record = self.db.lookup_signature(digest)
            return self._result(digest, record, bloom="unavailable")
        if digest not in self._bloom:
            return {"match": False, "sha256": digest, "bloom": "miss", "malware_name": None, "severity": None}
        record = self.db.lookup_signature(digest)
        return self._result(digest, record, bloom="hit")

    @staticmethod
    def _result(digest: str, record: dict[str, Any] | None, *, bloom: str) -> dict[str, Any]:
        return {
            "match": record is not None, "sha256": digest, "bloom": bloom,
            "malware_name": record["malware_name"] if record else None,
            "severity": record["severity"] if record else None,
        }

    def stats(self) -> dict[str, Any]:
        bloom = self._bloom
        return {
            "state": self.bloom_state,
            "signatures": self.db.signature_count(),
            "bloom_bytes": bloom.size_bytes if bloom else 0,
            "bloom_est_fp_rate": round(bloom.estimated_false_positive_rate(), 8) if bloom else None,
        }
