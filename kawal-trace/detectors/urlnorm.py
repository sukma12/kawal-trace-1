"""URL / domain normalisation shared by the link extractor, reputation checker and DB.

Attackers abuse parser differences (backslashes, userinfo "@", mixed case, trailing
dots, IDN look-alikes). Everything is normalised once here so the blacklist lookup
and the stored indicators agree on the same canonical form.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_CTRL_RE = re.compile(r"[\x00-\x20\x7f]+")
MAX_URL_LENGTH = 4096


def normalize_host(host: str) -> str | None:
    """Return the lowercase ASCII (IDNA/punycode) host or None when it is not a valid host."""
    if not isinstance(host, str):
        return None
    value = host.strip().strip(".").lower()
    if not value or len(value) > 253:
        return None
    # IPv4/IPv6 literals pass through unchanged (validated by caller if needed).
    if value.startswith("[") and value.endswith("]"):
        return value
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = ascii_host.split(".")
    if any(not _LABEL_RE.match(label) for label in labels):
        return None
    return ascii_host


def parse_url(url: str) -> tuple[str, str, str] | None:
    """Parse to (scheme, host, canonical_url). Returns None for non-http(s)/invalid input.

    Bare "evil.example/login" is assumed to be http because that is how a user or a
    mail client would treat it; no request is ever made.
    """
    if not isinstance(url, str):
        return None
    raw = _CTRL_RE.sub("", url.strip())
    if not raw or len(raw) > MAX_URL_LENGTH:
        return None
    raw = raw.replace("\\", "/")  # browsers treat backslash as slash
    if "://" not in raw:
        if raw.lower().startswith(("mailto:", "tel:", "javascript:", "data:", "file:", "ftp:")):
            return None
        raw = "http://" + raw.lstrip("/")
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            return None
        hostname = parts.hostname  # urlsplit already strips userinfo before "@"
        port = parts.port
    except ValueError:
        return None
    host = normalize_host(hostname or "")
    if host is None:
        return None
    netloc = host if port is None or (scheme, port) in {("http", 80), ("https", 443)} else f"{host}:{port}"
    path = parts.path or "/"
    canonical = f"{scheme}://{netloc}{path}" + (f"?{parts.query}" if parts.query else "")
    return scheme, host, canonical


def host_candidates(host: str) -> list[str]:
    """host and its parent domains down to two labels: a.b.evil.com -> [a.b.evil.com, b.evil.com, evil.com]."""
    if host.startswith("["):
        return [host]
    labels = host.split(".")
    if len(labels) < 2:
        return [host]
    return [".".join(labels[i:]) for i in range(0, len(labels) - 1)]


def normalize_indicator(value: str) -> tuple[str, str] | None:
    """Normalise a blacklist entry to ("domain", host) or ("url", canonical_url)."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_URL_LENGTH:
        return None
    looks_like_url = "://" in text or "/" in text or "?" in text or "\\" in text
    if looks_like_url:
        parsed = parse_url(text)
        if parsed is None:
            return None
        _, host, canonical = parsed
        path_part = canonical.split("://", 1)[1]
        # A bare "host/" is equivalent to the domain.
        if path_part.rstrip("/") == path_part.split("/", 1)[0]:
            return "domain", host
        return "url", canonical
    host = normalize_host(text)
    if host is None or "." not in host:
        return None
    return "domain", host
