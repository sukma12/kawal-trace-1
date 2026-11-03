"""Bounded JSON decoding for remote security APIs.

Treat every API response as untrusted input. Call this with an httpx streaming
response after checking the HTTP status so an oversized body is rejected before
JSON decoding and before buffering the entire response in memory.
"""
from __future__ import annotations

import json
from typing import Any

MAX_SECURITY_FEED_RESPONSE_BYTES = 4 * 1024 * 1024  # 4 MiB for up to 100 normalized events


class ResponseBodyTooLargeError(ValueError):
    """Remote API response exceeded the configured decoded-body limit."""


def bounded_response_json(response: Any, *, max_bytes: int = MAX_SECURITY_FEED_RESPONSE_BYTES) -> Any:
    """Read and JSON-decode a streaming HTTP response with a strict byte cap."""
    if not 1 <= max_bytes <= 32 * 1024 * 1024:
        raise ValueError("max_bytes must be between 1 byte and 32 MiB")
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            declared_bytes = int(declared)
        except (TypeError, ValueError):
            declared_bytes = -1
        if declared_bytes > max_bytes:
            raise ResponseBodyTooLargeError(
                f"Respons API melebihi batas {max_bytes} byte (Content-Length)."
            )
    body = bytearray()
    for chunk in response.iter_bytes():
        if not chunk:
            continue
        if len(body) + len(chunk) > max_bytes:
            raise ResponseBodyTooLargeError(
                f"Respons API melebihi batas aman {max_bytes} byte."
            )
        body.extend(chunk)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Respons API tidak berisi JSON UTF-8 yang valid.") from exc
