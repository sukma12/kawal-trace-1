"""Secret redaction for diagnostics, logs and error text shown in the UI."""
from __future__ import annotations

import re

_KEY_VALUE = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|authorization|cookie|private[_-]?key|passphrase)\b(\s*[:=]\s*)([^\s,;]+)")
_QUERY = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|token|api_key|apikey|password|secret|signature)=)[^&\s]+")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")


def redact_secrets(value: object) -> str:
    """Reduce the risk of writing credentials that appear in exception text or URLs."""
    text = str(value or "")
    text = _KEY_VALUE.sub(r"\1\2[REDACTED]", text)
    text = _QUERY.sub(r"\1[REDACTED]", text)
    return _BEARER.sub("Bearer [REDACTED]", text)
