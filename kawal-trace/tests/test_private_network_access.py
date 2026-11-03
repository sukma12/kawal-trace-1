from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

import pytest

from chainlog.advanced_security import AdvancedSecurityError, manage_ztna_tunnel

WG_CONFIG = """[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 10.77.0.2/32

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
AllowedIPs = 10.77.0.0/24
Endpoint = 192.0.2.10:51820
"""


def test_openziti_connect_uses_fixed_systemd_service_command(monkeypatch):
    calls = []
    monkeypatch.setattr("chainlog.advanced_security.platform.system", lambda: "Linux")
    monkeypatch.setattr("chainlog.advanced_security.shutil.which", lambda name: "/usr/bin/systemctl" if name == "systemctl" else None)
    monkeypatch.setattr("chainlog.advanced_security.subprocess.run", lambda cmd, **kw: (calls.append((cmd, kw)) or SimpleNamespace(returncode=0, stdout="", stderr="")))
    result = manage_ztna_tunnel("openziti", "connect")
    assert result["status"] == "success"
    assert calls[0][0] == ["/usr/bin/systemctl", "start", "ziti-edge-tunnel.service"] or calls[0][0] == ["/usr/bin/systemctl", "start", "ziti-edge-tunnel.service"]
    assert calls[0][1]["shell"] is False


def test_wireguard_connect_validates_config_and_uses_wg_quick(monkeypatch, tmp_path):
    config = tmp_path / "kawal.conf"
    config.write_text(WG_CONFIG, encoding="utf-8")
    calls = []
    monkeypatch.setattr("chainlog.advanced_security.platform.system", lambda: "Linux")
    monkeypatch.setattr("chainlog.advanced_security.shutil.which", lambda name: "/usr/bin/wg-quick" if name == "wg-quick" else None)
    monkeypatch.setattr("chainlog.advanced_security.subprocess.run", lambda cmd, **kw: (calls.append((cmd, kw)) or SimpleNamespace(returncode=0, stdout="interface up", stderr="")))
    result = manage_ztna_tunnel("wireguard", "connect", config_path=str(config))
    assert result["status"] == "success"
    assert calls[0][0] == ["/usr/bin/wg-quick", "up", str(config.resolve())] or calls[0][0] == ["/usr/bin/wg-quick", "up", str(config.resolve())]
    assert calls[0][1]["shell"] is False
    assert "PrivateKey" not in repr(result)


def test_wireguard_rejects_shell_hooks_before_running_command(monkeypatch, tmp_path):
    config = tmp_path / "bad.conf"
    config.write_text(WG_CONFIG + "\nPostUp = touch /tmp/pwned\n", encoding="utf-8")
    monkeypatch.setattr("chainlog.advanced_security.platform.system", lambda: "Linux")
    monkeypatch.setattr("chainlog.advanced_security.shutil.which", lambda name: "/usr/bin/wg-quick")
    monkeypatch.setattr("chainlog.advanced_security.subprocess.run", lambda *a, **k: pytest.fail("must not execute"))
    with pytest.raises(AdvancedSecurityError, match="hook shell"):
        manage_ztna_tunnel("wireguard", "connect", config_path=str(config))


def test_wireguard_requires_config_and_rejects_unknown_provider():
    with pytest.raises(AdvancedSecurityError, match="Pilih file"):
        manage_ztna_tunnel("wireguard", "connect")
    with pytest.raises(AdvancedSecurityError, match="Provider"):
        manage_ztna_tunnel("other", "connect")


def test_openziti_reports_missing_service_manager(monkeypatch):
    monkeypatch.setattr("chainlog.advanced_security.platform.system", lambda: "Linux")
    monkeypatch.setattr("chainlog.advanced_security.shutil.which", lambda name: None)
    result = manage_ztna_tunnel("openziti", "disconnect")
    assert result["status"] == "not_installed"


def test_private_network_access_ui_exposes_both_tunnel_controls_and_probe():
    source = Path(__file__).resolve().parents[1] / "main.py"
    text = source.read_text(encoding="utf-8")
    assert '"Private Network Access"' in text
    assert 'run_ztna_action("openziti", "connect")' in text
    assert 'run_ztna_action("openziti", "disconnect")' in text
    assert 'run_ztna_action("wireguard", "connect")' in text
    assert 'run_ztna_action("wireguard", "disconnect")' in text
    assert 'on_click=probe_ztna_endpoint_click' in text
