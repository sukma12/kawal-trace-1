"""Local-first advanced defensive helpers for Kawal Trace.

This module intentionally does not apply firewall rules, open tunnels, delete email,
or execute arbitrary content from an analyzed message. It provides bounded analysis,
read-only tool checks and policy previews for administrator review.
"""
from __future__ import annotations

import configparser
import email
import email.policy
import email.utils
import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from email.parser import BytesParser
from typing import Any
from urllib.parse import urlsplit

MAX_EMAIL_BYTES = 512 * 1024
MAX_URLS = 100
MAX_PHISHTANK_BODY = 1024 * 1024

_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"'`]+")
_AUTH_FAILURE_RE = {
    "SPF": re.compile(r"\bspf\s*=\s*(fail|softfail|neutral|none|temperror|permerror)\b", re.I),
    "DKIM": re.compile(r"\bdkim\s*=\s*(fail|none|temperror|permerror)\b", re.I),
    "DMARC": re.compile(r"\bdmarc\s*=\s*(fail|none|temperror|permerror)\b", re.I),
}
_URGENCY_TERMS = (
    "verify your account", "verify immediately", "urgent action", "password expires",
    "account suspended", "unusual activity", "confirm your password", "payment failed",
    "reset your password", "act now", "immediately", "akun ditangguhkan",
    "verifikasi akun", "kata sandi", "segera verifikasi", "akun diblokir",
)
_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy",
}


class AdvancedSecurityError(ValueError):
    """An advanced-security input is invalid or exceeds safety bounds."""


def _decode_part(part: email.message.Message) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except (LookupError, UnicodeError, AttributeError):
        try:
            payload = part.get_payload(decode=True) or b""
            return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            return ""


def _extract_body(msg: email.message.Message) -> str:
    parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() != "text":
                continue
            if part.get_content_subtype() not in {"plain", "html"}:
                continue
            parts.append(_decode_part(part))
            if sum(len(p) for p in parts) > MAX_EMAIL_BYTES:
                break
    else:
        parts.append(_decode_part(msg))
    # For HTML, retain href targets and visible-ish text; never render or execute HTML.
    body = "\n".join(parts)
    hrefs = re.findall(r"(?is)href\s*=\s*[\"']([^\"']+)[\"']", body)
    if hrefs:
        body += "\n" + "\n".join(hrefs[:MAX_URLS])
    body = re.sub(r"(?is)<(script|style)\b.*?</\1\s*>", " ", body)
    body = re.sub(r"(?s)<[^>]{1,2000}>", " ", body)
    return body[:MAX_EMAIL_BYTES]


def extract_urls(text: str, *, limit: int = MAX_URLS) -> list[str]:
    if not isinstance(text, str):
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text[:MAX_EMAIL_BYTES]):
        value = match.group(0).rstrip(".,;:!?)]}")
        if len(value) > 4096:
            continue
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            urls.append(value)
            if len(urls) >= max(0, min(limit, MAX_URLS)):
                break
    return urls


def _domain_from_mailbox(header_value: str) -> str:
    _, address = email.utils.parseaddr(header_value or "")
    if "@" not in address:
        return ""
    domain = address.rsplit("@", 1)[1].strip().strip(".").lower()
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


def _url_indicators(url: str) -> list[tuple[int, str]]:
    results: list[tuple[int, str]] = []
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            return [(25, "Tautan tidak memiliki skema HTTP/HTTPS atau host yang valid.")]
        if parsed.username is not None or parsed.password is not None:
            results.append((25, "URL berisi userinfo sebelum nama host; pola ini sering dipakai untuk menyamarkan tujuan."))
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_global:
                results.append((20, "Tautan memakai alamat IP langsung, bukan nama domain."))
            else:
                results.append((10, "Tautan memakai alamat IP nonpublik/reserved; jangan dibuka tanpa konteks."))
        except ValueError:
            if "xn--" in host:
                results.append((20, "Nama domain memakai punycode; periksa kemungkinan penyamaran karakter."))
            if host in _SHORTENERS:
                results.append((12, "Tautan memakai layanan pemendek URL yang menyembunyikan tujuan akhir."))
            if host.count(".") >= 4:
                results.append((8, "Nama host memiliki banyak subdomain; verifikasi domain induknya."))
        if parsed.scheme.lower() == "http":
            results.append((8, "Tautan menggunakan HTTP tanpa enkripsi transport."))
        if parsed.port not in (None, 80, 443):
            results.append((8, "Tautan memakai port yang tidak umum untuk web."))
        if len(url) > 240:
            results.append((5, "URL sangat panjang; periksa parameter dan tujuan sebenarnya."))
    except (ValueError, UnicodeError):
        results.append((25, "Format URL tidak valid atau sulit diparse."))
    return results


def url_indicators(url: str) -> list[tuple[int, str]]:
    """Public wrapper used by the offline scanner (same heuristics as analyze_email)."""
    return _url_indicators(url)


def analyze_email(raw_message: str | bytes) -> dict[str, Any]:
    """Analyze a pasted .eml/message locally. Never fetches links or deletes messages."""
    if isinstance(raw_message, bytes):
        raw = raw_message
        try:
            decoded = raw.decode("utf-8", errors="replace")
        except Exception:
            decoded = raw.decode(errors="replace")
    elif isinstance(raw_message, str):
        decoded = raw_message
        raw = decoded.encode("utf-8", errors="replace")
    else:
        raise AdvancedSecurityError("Isi email harus berupa teks atau bytes.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise AdvancedSecurityError("Email melebihi batas analisis 512 KiB.")
    if not decoded.strip():
        raise AdvancedSecurityError("Tempelkan header dan isi email .eml terlebih dahulu.")

    msg = BytesParser(policy=email.policy.default).parsebytes(raw)
    body = _extract_body(msg)
    header_text = "\n".join(str(msg.get_all(name, [])) for name in (
        "Authentication-Results", "Received-SPF", "From", "Reply-To", "Return-Path"
    ))
    content_for_urls = f"{header_text}\n{body}\n{decoded[:65536]}"
    urls = extract_urls(content_for_urls)
    findings: list[dict[str, str]] = []
    score = 0

    auth_text = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    auth_text += " " + " ".join(str(v) for v in msg.get_all("Received-SPF", []))
    for mechanism, pattern in _AUTH_FAILURE_RE.items():
        found = pattern.search(auth_text)
        if found:
            score += 22 if found.group(1).lower() == "fail" else 12
            findings.append({"level": "high" if found.group(1).lower() == "fail" else "medium",
                             "code": f"AUTH_{mechanism}_NOT_PASS",
                             "message": f"Hasil autentikasi {mechanism} pada header bukan pass ({found.group(1).lower()})."})

    sender_domain = _domain_from_mailbox(str(msg.get("From", "")))
    reply_domain = _domain_from_mailbox(str(msg.get("Reply-To", "")))
    if sender_domain and reply_domain and sender_domain != reply_domain:
        score += 20
        findings.append({"level": "medium", "code": "REPLY_TO_DOMAIN_MISMATCH",
                         "message": "Domain Reply-To berbeda dari From; verifikasi apakah ini memang diharapkan."})

    for url in urls:
        for points, message in _url_indicators(url):
            score += points
            findings.append({"level": "medium" if points < 20 else "high", "code": "SUSPICIOUS_URL", "message": message})
            # Keep the list bounded and avoid repeating the same URL warning endlessly.
            if len(findings) >= 50:
                break
        if len(findings) >= 50:
            break

    combined_body = (body + "\n" + str(msg.get("Subject", ""))).lower()
    urgency_hits = [term for term in _URGENCY_TERMS if term in combined_body]
    if urgency_hits:
        score += min(15, 5 * len(urgency_hits))
        findings.append({"level": "medium", "code": "URGENT_CREDENTIAL_LANGUAGE",
                         "message": "Ada bahasa mendesak atau meminta verifikasi akun/kredensial; periksa konteks pengirim."})

    score = min(100, score)
    verdict = "TINGGI" if score >= 50 else "PERLU DITINJAU" if score >= 20 else "INDIKATOR RENDAH"
    if not findings:
        findings.append({"level": "info", "code": "NO_STRONG_LOCAL_INDICATOR",
                         "message": "Tidak ada indikator kuat dari pemeriksaan lokal ini. Ini bukan jaminan email aman."})
    return {
        "score": score,
        "verdict": verdict,
        "from": str(msg.get("From", ""))[:500],
        "subject": str(msg.get("Subject", ""))[:500],
        "url_count": len(urls),
        "urls": urls,
        "findings": findings[:50],
        "analysis_mode": "offline_heuristic",
        "automatic_delete": False,
    }


def run_spamassassin(raw_message: str | bytes, *, timeout_seconds: float = 8.0) -> dict[str, Any]:
    """Optionally run local SpamAssassin CLI; never uses a shell and never auto-deletes."""
    raw = raw_message.encode("utf-8", errors="replace") if isinstance(raw_message, str) else raw_message
    if not isinstance(raw, bytes) or len(raw) > MAX_EMAIL_BYTES:
        raise AdvancedSecurityError("Email untuk SpamAssassin harus berupa bytes/teks maksimal 512 KiB.")
    if not 1 <= timeout_seconds <= 15:
        raise AdvancedSecurityError("Timeout SpamAssassin harus 1–15 detik.")
    executable = shutil.which("spamassassin")
    if not executable:
        return {"available": False, "result": "SpamAssassin tidak terpasang pada perangkat ini.", "automatic_delete": False}
    try:
        proc = subprocess.run(
            [executable, "--test-mode"], input=raw, capture_output=True, timeout=timeout_seconds,
            check=False, shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"available": True, "result": "Analisis SpamAssassin melewati batas waktu.", "automatic_delete": False}
    except OSError as exc:
        return {"available": True, "result": f"SpamAssassin tidak dapat dijalankan ({type(exc).__name__}).", "automatic_delete": False}
    output = (proc.stdout + b"\n" + proc.stderr).decode("utf-8", errors="replace")[:12000]
    return {"available": True, "return_code": proc.returncode, "result": output.strip(), "automatic_delete": False}


def _global_http_url(url: str) -> str:
    parsed = urlsplit(str(url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise AdvancedSecurityError("URL wajib HTTP/HTTPS valid tanpa kredensial atau fragment.")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise AdvancedSecurityError("Port URL tidak valid.") from exc
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        raise AdvancedSecurityError("Port URL harus antara 1 dan 65535.")
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if not ip.is_global:
            raise AdvancedSecurityError("URL IP nonpublik/reserved tidak dikirim ke layanan reputasi eksternal.")
    except AdvancedSecurityError:
        raise
    except ValueError:
        try:
            host_ascii = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise AdvancedSecurityError("Nama domain tidak valid.") from exc
        if not host_ascii or "." not in host_ascii:
            raise AdvancedSecurityError("URL harus menunjuk ke domain publik yang valid.")
        if host_ascii.endswith((".local", ".test", ".example", ".invalid", ".internal", ".localhost")) or host_ascii in {"localhost", "local", "internal"}:
            raise AdvancedSecurityError("Domain lokal/test tidak dikirim ke layanan reputasi eksternal.")
    return url


def check_phishtank_url(url: str, api_key: str, *, timeout_seconds: float = 8.0) -> dict[str, Any]:
    """Explicitly look up one user-selected URL. The whole email is never uploaded."""
    url = _global_http_url(url)
    api_key = str(api_key or "").strip()
    if not api_key or len(api_key) > 512:
        raise AdvancedSecurityError("API key PhishTank diperlukan untuk pemeriksaan reputasi.")
    if not 1 <= timeout_seconds <= 15:
        raise AdvancedSecurityError("Timeout PhishTank harus 1–15 detik.")
    try:
        import httpx
    except ImportError as exc:
        raise AdvancedSecurityError("Dependensi httpx tidak tersedia.") from exc
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    try:
        with httpx.Client(verify=True, follow_redirects=False,
                          timeout=httpx.Timeout(timeout_seconds, connect=min(4.0, timeout_seconds)),
                          trust_env=False) as client:
            with client.stream(
                "POST", endpoint,
                data={"url": url, "format": "json", "app_key": api_key},
                headers={"Accept": "application/json", "User-Agent": "KawalTrace/2.3 phishing-review"},
            ) as response:
                if response.status_code != 200:
                    raise AdvancedSecurityError(f"Layanan reputasi menolak permintaan (HTTP {response.status_code}).")
                chunks = bytearray()
                for chunk in response.iter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > MAX_PHISHTANK_BODY:
                        raise AdvancedSecurityError("Respons PhishTank terlalu besar.")
        import json
        payload = json.loads(chunks.decode("utf-8", errors="strict"))
    except AdvancedSecurityError:
        raise
    except Exception as exc:
        raise AdvancedSecurityError(f"Pemeriksaan reputasi gagal ({type(exc).__name__}); URL belum dapat dinilai.") from exc
    result: Any = payload.get("results", {}) if isinstance(payload, dict) else {}
    if isinstance(result, list):
        result = result[0] if result else {}
    if isinstance(result, dict) and "url" not in result and result:
        # Some responses nest an entry keyed by URL.
        values = [v for v in result.values() if isinstance(v, dict)]
        result = values[0] if values else result
    in_db = str(result.get("in_database", "false")).lower() in {"true", "1", "yes", "y"} if isinstance(result, dict) else False
    verified = str(result.get("verified", "false")).lower() in {"true", "1", "yes", "y"} if isinstance(result, dict) else False
    valid = str(result.get("valid", "false")).lower() in {"true", "1", "yes", "y"} if isinstance(result, dict) else False
    return {
        "checked_url": url,
        "in_database": in_db,
        "verified": verified,
        "valid": valid,
        "is_confirmed_phish": bool(in_db and verified and valid),
        "source": "PhishTank",
        "note": "Hanya URL yang dipilih dikirim ke layanan reputasi; email lengkap tidak dikirim.",
    }


def _read_only_command(binary: str | None, args: tuple[str, ...], *, timeout: float = 3.0) -> dict[str, Any]:
    """Run a fixed, bounded diagnostic command; never invokes a shell or changes state."""
    if not binary:
        return {"status": "not_installed", "detail": "Executable tidak ditemukan"}
    try:
        result = subprocess.run(
            [binary, *args], capture_output=True, text=True, timeout=timeout,
            check=False, shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "detail": "Pemeriksaan melewati batas waktu"}
    except OSError as exc:
        return {"status": "error", "detail": type(exc).__name__}
    output = (result.stdout or result.stderr or "").strip().splitlines()
    detail = " ".join(output[0].split())[:140] if output else f"exit code {result.returncode}"
    return {"status": "ok" if result.returncode == 0 else "error", "detail": detail}


def inspect_ztna_tools() -> dict[str, Any]:
    """Read-only ZTNA diagnostics: installation, versions and observable local tunnel state."""
    names = {
        "OpenZiti Edge Tunnel": "ziti-edge-tunnel",
        "OpenZiti CLI": "ziti",
        "WireGuard Tools": "wg",
        "WireGuard Userspace": "wireguard-go",
    }
    available = {label: shutil.which(binary) for label, binary in names.items()}
    versions = {
        "OpenZiti Edge Tunnel": _read_only_command(available["OpenZiti Edge Tunnel"], ("version",)),
        "OpenZiti CLI": _read_only_command(available["OpenZiti CLI"], ("version",)),
        "WireGuard Tools": _read_only_command(available["WireGuard Tools"], ("--version",)),
        "WireGuard Userspace": _read_only_command(available["WireGuard Userspace"], ("--version",)),
    }
    wg_interfaces = _read_only_command(available["WireGuard Tools"], ("show", "interfaces"))
    # Do not request identity lists or controller data: those require authenticated
    # management credentials and can expose inventory. Local service/process checks
    # are observational only and never start/stop a tunnel.
    edge_service = {"status": "unknown", "detail": "Pemeriksaan service OS tidak tersedia"}
    edge_process = {"status": "unknown", "detail": "Pemeriksaan proses OS tidak tersedia"}
    if available["OpenZiti Edge Tunnel"]:
        systemctl = shutil.which("systemctl")
        if systemctl:
            edge_service = _read_only_command(systemctl, ("is-active", "ziti-edge-tunnel.service"))
            if edge_service["status"] == "error" and edge_service["detail"] in {"inactive", "failed", "activating", "deactivating"}:
                edge_service["status"] = edge_service["detail"]
        pgrep = shutil.which("pgrep")
        tasklist = shutil.which("tasklist.exe") or shutil.which("tasklist")
        if pgrep:
            edge_process = _read_only_command(pgrep, ("-x", "ziti-edge-tunnel"))
            if edge_process["status"] == "error":
                edge_process["status"] = "inactive"
        elif tasklist:
            edge_process = _read_only_command(tasklist, ("/FI", "IMAGENAME eq ziti-edge-tunnel.exe", "/FO", "CSV", "/NH"))
            if edge_process["status"] == "ok" and "ziti-edge-tunnel.exe" not in edge_process["detail"].lower():
                edge_process["status"] = "inactive"
        edge_runtime = edge_service if edge_service["status"] == "ok" else edge_process
    else:
        edge_runtime = {"status": "not_installed", "detail": "OpenZiti Edge Tunnel belum terpasang"}
    wg_state = "active" if wg_interfaces["status"] == "ok" and wg_interfaces["detail"] not in {"", "exit code 0"} else (
        "inactive" if wg_interfaces["status"] == "ok" else wg_interfaces["status"]
    )
    return {
        "available": available,
        "versions": versions,
        "edge_runtime": edge_runtime,
        "edge_service": edge_service,
        "edge_process": edge_process,
        "wireguard_interfaces": wg_interfaces,
        "wireguard_runtime": {"status": wg_state, "detail": wg_interfaces["detail"]},
        "controller_status": {"status": "not_checked", "detail": "Memerlukan enrollment identity dan kredensial/controller yang sah"},
        "installed_count": sum(1 for path in available.values() if path),
        "recommendation": (
            "OpenZiti Edge Tunnel terpasang. Verifikasi service, enrollment identity, controller dan policy sebelum mengandalkan akses privat."
            if available["OpenZiti Edge Tunnel"] else
            "Belum ditemukan OpenZiti Edge Tunnel. Instalasi dan enrollment harus dilakukan oleh administrator; pemeriksaan ini tidak memasang apa pun."
        ),
        "no_auto_apply": True,
        "dark_ip_note": "Pemeriksaan ini tidak mengubah tunnel, firewall, routing, atau service. Status controller/policy tidak dapat dipastikan tanpa autentikasi resmi.",
    }



def manage_ztna_tunnel(provider: str, action: str, *, config_path: str | None = None, timeout: float = 25.0) -> dict[str, Any]:
    """Explicitly start/stop a preconfigured OpenZiti or WireGuard client.

    Commands are fixed, shell-free and bounded. The caller must obtain explicit
    operator consent; OS administrator/root privileges may be required.
    """
    from pathlib import Path

    provider_key = str(provider or "").strip().lower()
    action_key = str(action or "").strip().lower()
    if provider_key not in {"openziti", "wireguard"}:
        raise AdvancedSecurityError("Provider harus openziti atau wireguard.")
    if action_key not in {"connect", "disconnect"}:
        raise AdvancedSecurityError("Aksi harus connect atau disconnect.")
    if not 1 <= float(timeout) <= 45:
        raise AdvancedSecurityError("Timeout kontrol tunnel harus 1–45 detik.")

    system = platform.system()
    if provider_key == "openziti":
        if system == "Linux":
            executable = shutil.which("systemctl")
            command = [executable, "start" if action_key == "connect" else "stop", "ziti-edge-tunnel.service"] if executable else None
        elif system == "Windows":
            executable = shutil.which("sc.exe") or shutil.which("sc")
            command = [executable, "start" if action_key == "connect" else "stop", "ziti-edge-tunnel"] if executable else None
        else:
            raise AdvancedSecurityError("Kontrol service OpenZiti otomatis saat ini didukung di Linux dan Windows.")
        if not command:
            return {"status": "not_installed", "provider": provider_key, "action": action_key,
                    "detail": "Pengelola service OS (systemctl/sc.exe) tidak ditemukan."}
    else:
        if not config_path:
            raise AdvancedSecurityError("Pilih file konfigurasi WireGuard .conf terlebih dahulu.")
        config = Path(config_path).expanduser()
        try:
            resolved = config.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise AdvancedSecurityError("File konfigurasi WireGuard tidak ditemukan atau tidak dapat diakses.") from exc
        if not resolved.is_file() or resolved.suffix.lower() != ".conf":
            raise AdvancedSecurityError("Pilih file konfigurasi WireGuard berakhiran .conf.")
        try:
            config_text = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise AdvancedSecurityError("File konfigurasi WireGuard tidak dapat dibaca sebagai UTF-8.") from exc
        validation = validate_wireguard_config(config_text)
        if not validation.get("valid"):
            raise AdvancedSecurityError("Konfigurasi WireGuard belum valid.")
        if system == "Linux":
            executable = shutil.which("wg-quick")
            command = [executable, "up" if action_key == "connect" else "down", str(resolved)] if executable else None
        elif system == "Windows":
            executable = shutil.which("wireguard.exe") or shutil.which("wireguard")
            if not executable:
                return {"status": "not_installed", "provider": provider_key, "action": action_key,
                        "detail": "wireguard.exe tidak ditemukan."}
            command = [executable, "/installtunnelservice", str(resolved)] if action_key == "connect" else [
                executable, "/uninstalltunnelservice", resolved.stem
            ]
        else:
            raise AdvancedSecurityError("Kontrol WireGuard otomatis saat ini didukung di Linux dan Windows.")
        if not command:
            return {"status": "not_installed", "provider": provider_key, "action": action_key,
                    "detail": "wg-quick tidak ditemukan."}

    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=float(timeout),
                                   check=False, shell=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "provider": provider_key, "action": action_key,
                "detail": "Perintah melewati batas waktu; periksa status tunnel sebelum mencoba lagi."}
    except OSError as exc:
        return {"status": "error", "provider": provider_key, "action": action_key,
                "detail": f"Perintah tidak dapat dijalankan ({type(exc).__name__})."}
    output = (completed.stdout or completed.stderr or "").strip().splitlines()
    detail = " ".join(output[0].split())[:220] if output else f"exit code {completed.returncode}"
    return {"status": "success" if completed.returncode == 0 else "error",
            "provider": provider_key, "action": action_key, "return_code": completed.returncode,
            "detail": detail, "command": [Path(str(part)).name if index == 0 else str(part)
                                               for index, part in enumerate(command)],
            "requires_admin": True, "shell_used": False}

def probe_private_endpoint(host: str, port: int, *, timeout: float = 3.0) -> dict[str, Any]:
    """Test TCP reachability to an operator-supplied private service without changing routes.

    A successful probe proves only that the endpoint is reachable from this device.
    The operator must ensure the target is private-only if the result is to validate
    a ZTNA path rather than an ordinary public/LAN route.
    """
    raw_host = str(host or "").strip()
    if (not raw_host or len(raw_host) > 253 or any(ch.isspace() for ch in raw_host)
            or any(ch in raw_host for ch in "/\\@?#")):
        raise AdvancedSecurityError("Host target harus berupa hostname atau alamat IP saja, tanpa URL/path.")
    try:
        normalized_ip = str(ipaddress.ip_address(raw_host.strip("[]")))
        target_host = normalized_ip
    except ValueError:
        if not re.fullmatch(r"(?i)(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", raw_host):
            raise AdvancedSecurityError("Format hostname target tidak valid.")
        if ".." in raw_host:
            raise AdvancedSecurityError("Hostname target tidak valid.")
        target_host = raw_host.rstrip(".")
    if isinstance(port, bool):
        raise AdvancedSecurityError("Port harus berupa angka 1–65535.")
    try:
        target_port = int(port)
    except (TypeError, ValueError) as exc:
        raise AdvancedSecurityError("Port harus berupa angka 1–65535.") from exc
    if not 1 <= target_port <= 65535:
        raise AdvancedSecurityError("Port harus berupa angka 1–65535.")
    if not 0.5 <= float(timeout) <= 5.0:
        raise AdvancedSecurityError("Timeout probe harus 0,5–5 detik.")
    started = time.monotonic()
    try:
        with socket.create_connection((target_host, target_port), timeout=float(timeout)) as connection:
            peer = connection.getpeername()
        elapsed_ms = round((time.monotonic() - started) * 1000)
        return {
            "status": "reachable", "host": target_host, "port": target_port,
            "peer": str(peer[0]), "elapsed_ms": elapsed_ms,
            "detail": "TCP berhasil tersambung; ini membuktikan endpoint terjangkau, bukan identitas/policy ZTNA.",
        }
    except (OSError, TimeoutError) as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        return {
            "status": "unreachable", "host": target_host, "port": target_port,
            "peer": "", "elapsed_ms": elapsed_ms,
            "detail": f"{type(exc).__name__}: {str(exc)[:160]}",
        }


def validate_wireguard_config(config_text: str) -> dict[str, Any]:
    """Validate WireGuard config blocks in-memory without returning secret values.

    Repeated [Peer] blocks are supported. Hooks which could execute shell commands
    when applied with wg-quick are rejected; this function never applies config.
    """
    import base64

    if not isinstance(config_text, str) or len(config_text.encode("utf-8", errors="replace")) > 64 * 1024:
        raise AdvancedSecurityError("Konfigurasi WireGuard harus berupa teks maksimal 64 KiB.")
    if "\x00" in config_text:
        raise AdvancedSecurityError("Konfigurasi WireGuard memuat byte NUL yang tidak valid.")
    sections: list[tuple[str, dict[str, str]]] = []
    current_name = ""
    current_values: dict[str, str] | None = None
    blocked_hooks = {"preup", "postup", "predown", "postdown", "preexit"}
    for number, original in enumerate(config_text.splitlines(), start=1):
        line = original.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            if name not in {"Interface", "Peer"}:
                raise AdvancedSecurityError(f"Bagian '{name}' di baris {number} tidak dikenal.")
            if name == "Interface" and any(existing_name == "Interface" for existing_name, _ in sections):
                raise AdvancedSecurityError("Konfigurasi hanya boleh memiliki satu bagian [Interface].")
            current_name = name
            current_values = {}
            sections.append((current_name, current_values))
            continue
        if current_values is None or "=" not in line:
            raise AdvancedSecurityError(f"Baris konfigurasi {number} tidak valid.")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key):
            raise AdvancedSecurityError(f"Nama opsi di baris {number} tidak valid.")
        key_lower = key.lower()
        if key_lower in blocked_hooks:
            raise AdvancedSecurityError("Konfigurasi memuat hook shell PreUp/PostUp/PreDown/PostDown; hapus hook dan tinjau manual sebelum digunakan.")
        if key_lower in current_values:
            raise AdvancedSecurityError(f"Opsi '{key}' diduplikasi dalam blok yang sama.")
        current_values[key_lower] = value
    interfaces = [values for name, values in sections if name == "Interface"]
    peers = [values for name, values in sections if name == "Peer"]
    if not interfaces or not peers:
        raise AdvancedSecurityError("Konfigurasi membutuhkan bagian [Interface] dan minimal satu [Peer].")
    interface = interfaces[0]
    private_key = interface.get("privatekey", "").strip()
    if not private_key or len(private_key) > 128:
        raise AdvancedSecurityError("PrivateKey tidak ditemukan atau formatnya terlalu panjang.")
    try:
        decoded_private = base64.b64decode(private_key, validate=True)
        if len(decoded_private) != 32:
            raise ValueError("wrong key size")
    except (ValueError, base64.binascii.Error) as exc:
        raise AdvancedSecurityError("PrivateKey harus berupa kunci WireGuard Base64 32-byte yang valid.") from exc
    address = interface.get("address", "").strip()
    if not address:
        raise AdvancedSecurityError("Address pada [Interface] wajib diisi.")
    addresses = []
    try:
        for value in address.split(","):
            addresses.append(str(ipaddress.ip_interface(value.strip())))
    except ValueError as exc:
        raise AdvancedSecurityError("Address berisi alamat interface/CIDR yang tidak valid.") from exc
    if interface.get("listenport"):
        try:
            listen_port = int(interface["listenport"])
            if not 1 <= listen_port <= 65535:
                raise ValueError
        except ValueError as exc:
            raise AdvancedSecurityError("ListenPort harus antara 1 dan 65535.") from exc
    for peer_index, peer in enumerate(peers, start=1):
        public_key = peer.get("publickey", "").strip()
        try:
            decoded_public = base64.b64decode(public_key, validate=True)
            if len(decoded_public) != 32:
                raise ValueError("wrong key size")
        except (ValueError, base64.binascii.Error) as exc:
            raise AdvancedSecurityError(f"PublicKey pada peer ke-{peer_index} harus berupa kunci Base64 32-byte.") from exc
        if not peer.get("allowedips", "").strip():
            raise AdvancedSecurityError(f"Peer ke-{peer_index} harus memiliki AllowedIPs.")
        try:
            for value in peer["allowedips"].split(","):
                ipaddress.ip_network(value.strip(), strict=False)
        except ValueError as exc:
            raise AdvancedSecurityError(f"AllowedIPs pada peer ke-{peer_index} berisi network tidak valid.") from exc
        endpoint = peer.get("endpoint", "").strip()
        if endpoint and (len(endpoint) > 300 or not re.fullmatch(r"(?:[A-Za-z0-9.\-]+|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}", endpoint)):
            raise AdvancedSecurityError(f"Endpoint peer ke-{peer_index} tidak valid.")
        if endpoint:
            port_text = endpoint.rsplit(":", 1)[1]
            if not 1 <= int(port_text) <= 65535:
                raise AdvancedSecurityError(f"Port endpoint peer ke-{peer_index} tidak valid.")
        if peer.get("presharedkey"):
            try:
                if len(base64.b64decode(peer["presharedkey"], validate=True)) != 32:
                    raise ValueError("wrong key size")
            except (ValueError, base64.binascii.Error) as exc:
                raise AdvancedSecurityError(f"PresharedKey pada peer ke-{peer_index} tidak valid.") from exc
    return {
        "valid": True,
        "interface_addresses": addresses,
        "peer_count": len(peers),
        "private_key_present": True,
        "private_key_value_returned": False,
        "warnings": [
            "Kunci pribadi tidak ditampilkan atau disimpan oleh pemeriksa ini.",
            "Periksa AllowedIPs dan routing agar konfigurasi tidak mengalihkan seluruh trafik tanpa sengaja.",
            "Pemeriksaan sintaks tidak membuktikan peer online atau aturan firewall benar.",
            "Konfigurasi tidak diterapkan oleh Kawal Trace.",
        ],
    }


def build_microsegmentation_plan(
    management_cidr: str,
    web_cidr: str,
    app_cidr: str,
    data_cidr: str,
    *,
    ssh_port: int = 22,
    web_port: int = 443,
    app_port: int = 8080,
    database_port: int = 5432,
) -> dict[str, Any]:
    """Produce a non-executable-by-default policy preview; never alters a firewall."""
    inputs = {
        "management": management_cidr,
        "web": web_cidr,
        "application": app_cidr,
        "database": data_cidr,
    }
    networks: dict[str, ipaddress._BaseNetwork] = {}
    for name, cidr in inputs.items():
        try:
            network = ipaddress.ip_network(str(cidr).strip(), strict=True)
        except ValueError as exc:
            raise AdvancedSecurityError(f"CIDR zona '{name}' tidak valid atau memiliki host bits; gunakan network CIDR yang tepat.") from exc
        if not network.is_private or network.is_loopback or network.is_link_local or network.is_unspecified:
            raise AdvancedSecurityError(f"Zona '{name}' harus menggunakan network privat yang dirancang khusus.")
        networks[name] = network
    values = list(networks.items())
    for i, (name_a, net_a) in enumerate(values):
        for name_b, net_b in values[i + 1:]:
            if net_a.version != net_b.version:
                continue
            if net_a.overlaps(net_b):
                raise AdvancedSecurityError(f"Zona '{name_a}' dan '{name_b}' tumpang tindih; buat subnet berbeda.")
    try:
        port_values = {"ssh": int(ssh_port), "web": int(web_port), "app": int(app_port), "database": int(database_port)}
    except (TypeError, ValueError) as exc:
        raise AdvancedSecurityError("Port harus berupa bilangan bulat.") from exc
    if any(port < 1 or port > 65535 for port in port_values.values()):
        raise AdvancedSecurityError("Port harus antara 1 dan 65535.")
    if len(set(port_values.values())) < 3:
        # Identical service ports can be valid in rare deployments, but are suspicious enough to review.
        warning_duplicate_ports = True
    else:
        warning_duplicate_ports = False
    rules = [
        {"action": "allow", "source": "any", "destination": "any", "protocol": "established,related", "reason": "Pertahankan trafik koneksi yang sudah sah."},
        {"action": "allow", "source": str(networks["management"]), "destination": "all managed zones", "protocol": f"tcp/{port_values['ssh']}", "reason": "Akses administrasi dari jaringan manajemen yang ditentukan."},
        {"action": "allow", "source": "any", "destination": str(networks["web"]), "protocol": f"tcp/{port_values['web']}", "reason": "Titik masuk HTTPS ke zona web."},
        {"action": "allow", "source": str(networks["web"]), "destination": str(networks["application"]), "protocol": f"tcp/{port_values['app']}", "reason": "Web hanya menuju port aplikasi yang diperlukan."},
        {"action": "allow", "source": str(networks["application"]), "destination": str(networks["database"]), "protocol": f"tcp/{port_values['database']}", "reason": "Aplikasi hanya menuju port database yang ditentukan."},
        {"action": "deny", "source": "all other cross-zone traffic", "destination": "all managed zones", "protocol": "any", "reason": "Default-deny antar-zona; tinjau kebutuhan monitoring, backup, DNS, dan update sebelum penerapan."},
    ]
    return {
        "mode": "PREVIEW_ONLY",
        "zones": {name: str(network) for name, network in networks.items()},
        "rules": rules,
        "warnings": [
            "Tidak ada aturan firewall yang diterapkan oleh Kawal Trace.",
            "Ganti contoh CIDR/port sesuai topologi sebenarnya dan siapkan rollback/akses console sebelum menerapkan.",
            "Uji di staging; default-deny yang salah dapat memutus SSH, database, monitoring, atau update.",
            *(["Ada port layanan yang sama; tinjau kemungkinan konflik konfigurasi."] if warning_duplicate_ports else []),
        ],
        "requires_operator_review": True,
    }
