"""Text Preprocessing: clean e-mail text before it reaches the phishing classifier.

HTML tags/scripts are dropped, text is case-folded, URLs are kept as words (their
words are strong phishing evidence) behind a marker token, and punctuation is removed.
"""
from __future__ import annotations

import html
import re

MAX_CHARS = 20_000
URL_TOKEN = "urltoken"
_SCRIPT_RE = re.compile(r"(?is)<(script|style)\b.*?</\1\s*>")
_TAG_RE = re.compile(r"(?s)<[^>]{1,2000}>")
_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
_PUNCT_RE = re.compile(r"[^\w\s]|_", re.UNICODE)
_SPACE_RE = re.compile(r"\s+")


def preprocess_text(text: str, *, max_chars: int = MAX_CHARS) -> str:
    if not isinstance(text, str):
        return ""
    value = text[: max_chars * 2]
    value = _SCRIPT_RE.sub(" ", value)
    value = _TAG_RE.sub(" ", value)
    value = html.unescape(value)
    value = value.casefold()
    value = _URL_RE.sub(lambda m: f" {URL_TOKEN} {m.group(0)} ", value)
    value = _PUNCT_RE.sub(" ", value)
    value = _SPACE_RE.sub(" ", value).strip()
    return value[:max_chars]
