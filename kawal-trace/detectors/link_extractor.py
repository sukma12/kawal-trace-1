"""Link Extractor: find every URL in e-mail text/HTML, including links hidden behind anchor text.

HTML is only parsed, never rendered or fetched. BeautifulSoup (bs4) is used when it is
installed; otherwise the standard-library HTMLParser gives the same result, so the
packaged app does not depend on bs4.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser

from .urlnorm import MAX_URL_LENGTH, host_candidates, parse_url

try:  # optional dependency
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover - exercised through the stdlib fallback test
    BeautifulSoup = None

MAX_LINKS = 100
MAX_HTML_CHARS = 2 * 1024 * 1024
_TEXT_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
_LOOKS_LIKE_HOST_RE = re.compile(r"(?i)(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)")
_LINK_ATTRS = {"a": "href", "area": "href", "form": "action", "iframe": "src"}


@dataclass(frozen=True)
class ExtractedLink:
    url: str
    source: str                      # "text" | "html:a" | "html:form" ...
    display_text: str = ""
    display_mismatch: bool = False   # visible text names a different site than the real target


class _StdlibLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items: list[tuple[str, str, str]] = []   # (tag, url, text)
        self._open: list[list[str]] = []              # stack of [tag, url, text...]

    def handle_starttag(self, tag, attrs):
        attr = _LINK_ATTRS.get(tag)
        if not attr:
            return
        value = dict(attrs).get(attr)
        if value:
            self._open.append([tag, value.strip(), ""])
            if tag != "a":  # no visible text for form/iframe/area
                self.items.append((tag, value.strip(), ""))
                self._open.pop()

    def handle_data(self, data):
        if self._open:
            self._open[-1][2] += data

    def handle_endtag(self, tag):
        if tag == "a" and self._open and self._open[-1][0] == "a":
            _, url, text = self._open.pop()
            self.items.append(("a", url, " ".join(text.split())))


def _html_items(html: str) -> list[tuple[str, str, str]]:
    html = html[:MAX_HTML_CHARS]
    if BeautifulSoup is not None:
        soup = BeautifulSoup(html, "html.parser")
        items: list[tuple[str, str, str]] = []
        for tag_name, attr in _LINK_ATTRS.items():
            for node in soup.find_all(tag_name):
                value = node.get(attr)
                if isinstance(value, str) and value.strip():
                    text = " ".join(node.get_text(" ").split()) if tag_name == "a" else ""
                    items.append((tag_name, value.strip(), text))
        return items
    parser = _StdlibLinkParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass  # malformed HTML must not abort the scan; keep what was parsed
    return parser.items


def _same_site(host_a: str, host_b: str) -> bool:
    a, b = set(host_candidates(host_a)), set(host_candidates(host_b))
    return bool(a & b)


def _mismatch(display_text: str, target_host: str) -> bool:
    match = _LOOKS_LIKE_HOST_RE.search(display_text or "")
    if not match:
        return False
    shown = parse_url(match.group(0))
    return bool(shown and not _same_site(shown[1], target_host))


def extract_links(text: str = "", html: str = "", *, limit: int = MAX_LINKS) -> list[ExtractedLink]:
    """Return unique, normalised http(s) links from plain text and HTML (bounded)."""
    found: list[ExtractedLink] = []
    seen: set[str] = set()

    def add(raw: str, source: str, display: str = "") -> None:
        if len(found) >= limit or not raw or len(raw) > MAX_URL_LENGTH:
            return
        parsed = parse_url(raw.rstrip(".,;:!?)]}>'\""))
        if parsed is None:
            return
        _, host, canonical = parsed
        key = canonical.casefold()
        if key in seen:
            return
        seen.add(key)
        found.append(ExtractedLink(canonical, source, display[:200], _mismatch(display, host)))

    for tag, url, shown in _html_items(html or ""):
        add(url, f"html:{tag}", shown)
    for match in _TEXT_URL_RE.finditer((text or "")[:MAX_HTML_CHARS]):
        add(match.group(0), "text")
    return found
