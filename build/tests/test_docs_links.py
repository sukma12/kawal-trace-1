"""Guides that tell a person to run a script or read another file must point at files that exist."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUIDES = ["docs/REMOTE_REALTIME.md", "docs/CONNECT_REAL_SERVER.md"]
PATH_RE = re.compile(r"`((?:docs|scripts|optional-server-api|server_agent|windows_agent|chainlog|tests)/[A-Za-z0-9_./-]+)`")


@pytest.mark.parametrize("guide", GUIDES)
def test_every_repository_path_a_guide_mentions_exists(guide):
    text = (ROOT / guide).read_text(encoding="utf-8")
    mentioned = sorted(set(PATH_RE.findall(text)))
    assert mentioned, "guide should reference real files"
    missing = [path for path in mentioned if not (ROOT / path.rstrip("/")).exists() and "<" not in path]
    assert missing == [], f"{guide} points at files that do not exist: {missing}"


def test_guides_state_what_was_not_verified():
    for guide in GUIDES:
        text = (ROOT / guide).read_text(encoding="utf-8").lower()
        assert "belum" in text and "terbukti" in text or "tidak bisa saya buktikan" in text or "tidak dapat menguji" in text, guide


def test_the_connection_guide_never_suggests_turning_off_tls_verification():
    for guide in GUIDES:
        text = (ROOT / guide).read_text(encoding="utf-8").lower()
        for bad in ("verify=false", "--insecure", "curl -k", "matikan verifikasi tls"):
            assert bad not in text, (guide, bad)
