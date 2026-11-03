"""Link Reputation Checker: offline blacklist lookup (phishing_urls table).

Only the blacklist decides PHISHING. Look-alike/heuristic indicators are reported as
informational findings: a heuristic hit on its own is not proof, and treating it as
one would flood users with false positives.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from chainlog.advanced_security import url_indicators
from .link_extractor import ExtractedLink
from .scanner_db import ScannerDatabase
from .urlnorm import parse_url


@dataclass
class UrlVerdict:
    url: str
    host: str
    blacklisted: bool
    threat_type: str | None = None
    matched_entry: str | None = None
    heuristics: list[str] = field(default_factory=list)
    display_mismatch: bool = False


class LinkReputationChecker:
    def __init__(self, db: ScannerDatabase) -> None:
        self.db = db

    def check(self, url: str, *, display_mismatch: bool = False) -> UrlVerdict:
        parsed = parse_url(url)
        if parsed is None:
            return UrlVerdict(url=str(url)[:200], host="", blacklisted=False,
                              heuristics=["URL tidak valid atau bukan HTTP/HTTPS; tidak diperiksa."])
        _, host, canonical = parsed
        record = self.db.lookup_phishing(canonical)
        heuristics = [message for _points, message in url_indicators(canonical)]
        return UrlVerdict(
            url=canonical, host=host, blacklisted=record is not None,
            threat_type=record["threat_type"] if record else None,
            matched_entry=record["domain_or_url"] if record else None,
            heuristics=heuristics, display_mismatch=display_mismatch,
        )

    def check_links(self, links: list[ExtractedLink]) -> list[UrlVerdict]:
        return [self.check(link.url, display_mismatch=link.display_mismatch) for link in links]
