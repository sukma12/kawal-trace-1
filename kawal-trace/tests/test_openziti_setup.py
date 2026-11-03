from __future__ import annotations

import platform

import pytest

from chainlog.openziti_setup import OpenZitiSetupError, _https_request, download_and_launch_windows_installer


def test_openziti_setup_rejects_non_windows(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    with pytest.raises(OpenZitiSetupError, match="hanya dapat dijalankan"):
        download_and_launch_windows_installer(launch=False)


@pytest.mark.parametrize("url", [
    "http://github.com/openziti/desktop-edge-win/releases/latest",
    "https://evil.example/openziti.exe",
    "https://github.com.evil.example/openziti.exe",
])
def test_openziti_download_rejects_untrusted_urls(url):
    with pytest.raises(OpenZitiSetupError):
        _https_request(url)
