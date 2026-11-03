"""OpenZiti runtime bootstrap helpers for Kawal Trace.

Only obtains the official signed Windows installer from the OpenZiti GitHub
release and verifies its Authenticode signature before starting it. The
installer itself performs the privileged OS changes through the normal UAC
flow; this module never installs a tunnel silently.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

API_URL = "https://api.github.com/repos/openziti/desktop-edge-win/releases/latest"
_ALLOWED_HOSTS = {"api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
MAX_INSTALLER_BYTES = 300 * 1024 * 1024


class OpenZitiSetupError(RuntimeError):
    pass


def _https_request(url: str, *, timeout: float = 20.0):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in _ALLOWED_HOSTS:
        raise OpenZitiSetupError("Sumber unduhan bukan host HTTPS resmi yang diizinkan.")
    request = urllib.request.Request(url, headers={"User-Agent": "Kawal-Trace-OpenZiti-Setup", "Accept": "application/vnd.github+json"})
    return urllib.request.urlopen(request, timeout=timeout)


def download_and_launch_windows_installer(*, launch: bool = True) -> dict[str, Any]:
    """Download latest official Ziti Desktop Edge installer, verify signature, optionally launch.

    This installs the OpenZiti Windows background tunneler/service component.
    It does not enroll an identity or create a controller/network.
    """
    if platform.system() != "Windows":
        raise OpenZitiSetupError("Pemasang Windows hanya dapat dijalankan dari KAWAL TRACE di Windows.")

    try:
        with _https_request(API_URL) as response:
            from urllib.parse import urlsplit
            final = urlsplit(response.geturl())
            if final.scheme != "https" or (final.hostname or "").lower() not in _ALLOWED_HOSTS:
                raise OpenZitiSetupError("Redirect metadata menuju host yang tidak diizinkan.")
            metadata = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise OpenZitiSetupError(f"Tidak dapat mengambil metadata rilis OpenZiti: {type(exc).__name__}") from exc

    if metadata.get("draft") or not metadata.get("html_url", "").startswith("https://github.com/openziti/desktop-edge-win/releases/"):
        raise OpenZitiSetupError("Metadata rilis tidak cocok dengan repositori resmi OpenZiti.")
    assets = metadata.get("assets") or []
    candidates = [a for a in assets if str(a.get("name", "")).lower().startswith("ziti.desktop.edge.client-")
                  and str(a.get("name", "")).lower().endswith(".exe")
                  and str(a.get("browser_download_url", "")).startswith("https://github.com/openziti/desktop-edge-win/releases/download/")]
    if len(candidates) != 1:
        raise OpenZitiSetupError("Installer Windows resmi tidak ditemukan secara unik pada rilis terbaru.")
    asset = candidates[0]
    size = int(asset.get("size") or 0)
    if size <= 0 or size > MAX_INSTALLER_BYTES:
        raise OpenZitiSetupError("Ukuran installer di luar batas aman.")

    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "KawalTrace" / "runtime" / "openziti"
    root.mkdir(parents=True, exist_ok=True)
    destination = root / Path(str(asset["name"])).name
    digest = hashlib.sha256()
    total = 0
    try:
        with _https_request(str(asset["browser_download_url"]), timeout=45.0) as response, destination.open("wb") as out:
            from urllib.parse import urlsplit
            final = urlsplit(response.geturl())
            if final.scheme != "https" or (final.hostname or "").lower() not in _ALLOWED_HOSTS:
                raise OpenZitiSetupError("Redirect installer menuju host yang tidak diizinkan.")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_INSTALLER_BYTES:
                    raise OpenZitiSetupError("Unduhan melewati batas ukuran aman.")
                digest.update(chunk)
                out.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    if total != size:
        destination.unlink(missing_ok=True)
        raise OpenZitiSetupError("Ukuran hasil unduhan tidak cocok dengan metadata GitHub.")

    # GitHub asset digest is available on newer releases. Authenticode remains mandatory.
    expected = str(asset.get("digest") or "")
    if expected.startswith("sha256:") and digest.hexdigest().lower() != expected.split(":", 1)[1].lower():
        destination.unlink(missing_ok=True)
        raise OpenZitiSetupError("SHA-256 installer tidak cocok dengan digest rilis.")
    ps = ("$s=Get-AuthenticodeSignature -LiteralPath $args[0]; "
          "if ($s.Status -ne 'Valid') { exit 31 }; "
          "if (-not $s.SignerCertificate) { exit 32 }; "
          "$n=$s.SignerCertificate.Subject; "
          "if ($n -notmatch '(?i)OpenZiti|NetFoundry') { exit 33 }; exit 0")
    verified = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps, str(destination)],
                              capture_output=True, text=True, timeout=20, shell=False)
    if verified.returncode != 0:
        destination.unlink(missing_ok=True)
        raise OpenZitiSetupError("Tanda tangan digital installer tidak valid; file ditolak.")
    if launch:
        try:
            subprocess.Popen([str(destination)], close_fds=True, shell=False)
        except OSError as exc:
            raise OpenZitiSetupError(f"Installer terverifikasi tetapi gagal dijalankan: {type(exc).__name__}") from exc
    return {"status": "downloaded_and_launched" if launch else "downloaded", "version": str(metadata.get("tag_name") or "unknown"),
            "path": str(destination), "sha256": digest.hexdigest(), "signature": "valid", "requires_uac": True,
            "identity_enrolled": False}
