"""Kawal Trace local malware / phishing detectors (offline, no cloud, no code execution).

Nothing in this package opens network connections, executes scanned content or
uploads files. Scanned files are only read (streamed) and hashed; e-mail messages
are parsed with the standard library and never rendered.
"""
from __future__ import annotations

__all__ = [
    "ScanInputError", "ScannerError",
]


class ScannerError(Exception):
    """Base class for scanner failures that should be shown to the operator."""


class ScanInputError(ScannerError, ValueError):
    """The file/e-mail/text given to the scanner is missing, unreadable or too large."""
