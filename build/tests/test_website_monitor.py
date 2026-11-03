from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3

import pytest

from chainlog import website_monitor as wm

TEST_ENCRYPTION_KEY = bytes(range(32))


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib handler signature
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        if self.path == "/external-redirect":
            self.send_response(302)
            self.send_header("Location", "https://metadata.google.internal/computeMetadata/v1/")
            self.end_headers()
            return
        if self.path == "/private-redirect":
            self.send_response(302)
            self.send_header("Location", "http://192.168.1.10/")
            self.end_headers()
            return
        if self.path == "/not-found":
            self.send_response(404)
            self.end_headers()
            return
        if self.path == "/forbidden":
            self.send_response(403)
            self.end_headers()
            return
        if self.path == "/server-error":
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        return


@pytest.fixture()
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_url_requires_http_or_https_and_blocks_embedded_credentials():
    for value in ("ftp://example.com", "https://user:pass@example.com", "https://example.com/#fragment", "file:///etc/passwd"):
        with pytest.raises(wm.WebsiteMonitorError):
            wm._validate_url_shape(value, allow_internal=False)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/path?token=secret",
        "https://example.com/path?API_KEY=secret",
        "https://example.com/path?X-Amz-Signature=secret",
        "https://example.com/path?password=secret",
        "https://example.com/path?%61ccess_token=secret",
    ],
)
def test_secret_like_query_parameters_are_rejected_before_persistence(url):
    with pytest.raises(wm.WebsiteMonitorError, match="parameter query"):
        wm._validate_url_shape(url, allow_internal=False)


def test_private_ip_and_localhost_require_explicit_internal_choice():
    with pytest.raises(wm.WebsiteMonitorError, match="internal"):
        wm._validate_url_shape("http://127.0.0.1:8080/", allow_internal=False)
    with pytest.raises(wm.WebsiteMonitorError, match="internal"):
        wm._validate_url_shape("http://192.168.1.5/", allow_internal=False)
    assert wm._validate_url_shape("http://127.0.0.1:8080/", allow_internal=True)


def test_cloud_metadata_destinations_are_always_rejected():
    with pytest.raises(wm.WebsiteMonitorError, match="metadata"):
        wm._validate_url_shape("http://169.254.169.254/latest/meta-data/", allow_internal=True)
    with pytest.raises(wm.WebsiteMonitorError, match="metadata"):
        wm._validate_url_shape("https://metadata.google.internal/", allow_internal=True)


@pytest.mark.parametrize("url", ["http://100.100.100.200/", "http://[fd00:ec2::254]/"])
def test_additional_cloud_metadata_ip_addresses_are_rejected(url):
    with pytest.raises(wm.WebsiteMonitorError):
        wm._validate_url_shape(url, allow_internal=True)


def test_local_website_success_and_redirect(local_server):
    result = wm.check_website(local_server + "/ok", allow_internal=True)
    assert result["status"] == "UP"
    assert result["http_status"] == 200
    assert result["dns_ms"] >= 0
    assert result["total_ms"] >= 0
    assert "url" not in result

    redirected = wm.check_website(local_server + "/redirect", allow_internal=True)
    assert redirected["status"] == "UP"
    assert redirected["http_status"] == 200
    assert redirected["redirect_count"] == 1


@pytest.mark.parametrize(("path", "status_code"), [("/forbidden", 403), ("/not-found", 404), ("/server-error", 500)])
def test_http_errors_are_distinguished_from_connection_failure(local_server, path, status_code):
    result = wm.check_website(local_server + path, allow_internal=True)
    assert result["status"] == "HTTP_ERROR"
    assert result["http_status"] == status_code
    assert f"HTTP {status_code}" in result["message"]


def test_external_monitor_mode_blocks_metadata_redirect_before_following(monkeypatch):
    calls = []
    monkeypatch.setattr(wm, "_resolve_and_validate", lambda host, port, internal: (0.0, ["93.184.216.34"]))
    def fake_request(url, address, timeout):
        calls.append((url, address, timeout))
        return 302, {"location": "https://metadata.google.internal/computeMetadata/v1/"}
    monkeypatch.setattr(wm, "_read_pinned_http_response", fake_request)
    result = wm.check_website("https://example.invalid/start", allow_internal=False)
    assert result["status"] == "REDIRECT_BLOCKED"
    assert len(calls) == 1
    assert calls[0][0] == "https://example.invalid/start"
    assert calls[0][1] == "93.184.216.34"


def test_https_to_http_downgrade_redirect_is_blocked(monkeypatch):
    monkeypatch.setattr(wm, "_resolve_and_validate", lambda host, port, internal: (0.0, ["93.184.216.34"]))
    monkeypatch.setattr(wm, "_read_pinned_http_response", lambda *_args: (302, {"location": "http://example.invalid/insecure"}))
    result = wm.check_website("https://example.invalid/start", allow_internal=False)
    assert result["status"] == "REDIRECT_BLOCKED"


def test_redirect_loop_is_stopped_at_the_configured_limit(monkeypatch):
    calls = []
    monkeypatch.setattr(wm, "_resolve_and_validate", lambda host, port, internal: (0.0, ["93.184.216.34"]))
    def fake_request(url, address, timeout):
        calls.append((url, address))
        return 302, {"location": "/loop"}
    monkeypatch.setattr(wm, "_read_pinned_http_response", fake_request)
    result = wm.check_website("https://example.invalid/loop", allow_internal=False)
    assert result["status"] == "REDIRECT_BLOCKED"
    assert len(calls) == wm.MAX_REDIRECTS + 1


def test_invalid_tls_certificate_is_reported(monkeypatch):
    monkeypatch.setattr(wm, "_resolve_and_validate", lambda host, port, internal: (0.0, ["93.184.216.34"]))
    def fail(*_args):
        raise wm._CheckFailure("TLS_ERROR", "certificate verify failed")
    monkeypatch.setattr(wm, "_read_pinned_http_response", fail)
    result = wm.check_website("https://example.invalid/", allow_internal=False)
    assert result["status"] == "TLS_ERROR"
    assert result["error_type"] == "TLS_ERROR"


def test_network_timeout_is_reported(monkeypatch):
    monkeypatch.setattr(wm, "_resolve_and_validate", lambda host, port, internal: (0.0, ["93.184.216.34"]))
    def fail(*_args):
        raise wm._CheckFailure("TIMEOUT", "simulated timeout")
    monkeypatch.setattr(wm, "_read_pinned_http_response", fail)
    result = wm.check_website("https://example.invalid/", allow_internal=False)
    assert result["status"] == "TIMEOUT"
    assert result["error_type"] == "TIMEOUT"


def test_dns_rebinding_does_not_re_resolve_hostname_for_tcp_connection(local_server, monkeypatch):
    parsed = wm.urlsplit(local_server)
    port = parsed.port
    real_getaddrinfo = wm.socket.getaddrinfo
    queried_hosts = []
    def controlled_getaddrinfo(host, requested_port, *args, **kwargs):
        queried_hosts.append(str(host))
        if host == "rebind.test":
            return [(wm.socket.AF_INET, wm.socket.SOCK_STREAM, 6, "", ("127.0.0.1", requested_port))]
        return real_getaddrinfo(host, requested_port, *args, **kwargs)
    monkeypatch.setattr(wm.socket, "getaddrinfo", controlled_getaddrinfo)
    result = wm.check_website(f"http://rebind.test:{port}/ok", allow_internal=True)
    assert result["status"] == "UP"
    assert queried_hosts.count("rebind.test") == 1
    assert "127.0.0.1" in queried_hosts


def test_dns_failure_is_reported_not_hidden(monkeypatch):
    def fail_dns(*_args, **_kwargs):
        raise wm._CheckFailure("DNS_ERROR", "DNS tidak dapat menemukan alamat target.")
    monkeypatch.setattr(wm, "_resolve_and_validate", fail_dns)
    result = wm.check_website("https://example.invalid/", allow_internal=False)
    assert result["status"] == "DNS_ERROR"
    assert result["error_type"] == "DNS_ERROR"


def test_store_keeps_website_checks_separate_and_persists_events(tmp_path, local_server):
    path = tmp_path / "website.sqlite3"
    store = wm.WebsiteMonitorStore(path, encryption_key=TEST_ENCRYPTION_KEY)
    target = store.add_target("Website lokal", local_server + "/ok", 30, 3, allow_internal=True)
    checked = store.check_target(target.target_id)
    assert checked["status"] == "UP"
    assert checked["event_type"] == "WEBSITE_UP"
    assert store.get_target(target.target_id).last_status == "UP"
    assert store.list_checks(target.target_id)[0]["event_type"] == "WEBSITE_UP"
    assert store.list_targets(enabled_only=True)[0].target_id == target.target_id
    exported = json.loads(store.export_checks_json(target.target_id))
    assert exported["format"] == "kawal-trace-website-checks-v1"
    assert "url" not in exported["target"]
    store.set_enabled(target.target_id, False)
    assert store.list_targets(enabled_only=True) == []
    store.delete_target(target.target_id)
    assert store.get_target(target.target_id) is None
    assert store.list_checks(target.target_id) == []
    # Deletion is persisted into the encrypted database image, not merely hidden in UI.
    reopened = wm.WebsiteMonitorStore(path, encryption_key=TEST_ENCRYPTION_KEY)
    assert reopened.get_target(target.target_id) is None
    assert reopened.list_checks(target.target_id) == []


def test_export_does_not_include_target_path_or_query_secrets(tmp_path):
    store = wm.WebsiteMonitorStore(tmp_path / "website.sqlite3", encryption_key=TEST_ENCRYPTION_KEY)
    target = store.add_target(
        "URL with query", "http://127.0.0.1:12345/private/path?lang=id&sort=asc", allow_internal=True
    )
    exported = store.export_checks_json(target.target_id)
    assert "lang=id" not in exported and "sort=asc" not in exported
    assert "/private/path" not in exported
    assert '"origin": "http://127.0.0.1:12345"' in exported


def test_store_validates_interval_timeout_name_and_target_count(tmp_path):
    store = wm.WebsiteMonitorStore(tmp_path / "website.sqlite3", encryption_key=TEST_ENCRYPTION_KEY)
    with pytest.raises(wm.WebsiteMonitorError):
        store.add_target("", "https://example.com")
    with pytest.raises(wm.WebsiteMonitorError, match="Interval"):
        store.add_target("Bad interval", "https://example.com", 1)
    with pytest.raises(wm.WebsiteMonitorError, match="Timeout"):
        store.add_target("Bad timeout", "https://example.com", 30, 90)
    with pytest.raises(wm.WebsiteMonitorError):
        store.add_target("Bad URL", "javascript:alert(1)")


def test_url_query_values_are_redacted_in_displays_and_exports():
    assert wm.redact_website_url("https://example.com/path?token=secret&lang=id") == (
        "https://example.com/path?token=%5BREDACTED%5D&lang=%5BREDACTED%5D"
    )


def test_internal_approval_does_not_allow_redirect_to_another_private_host(local_server):
    result = wm.check_website(local_server + "/private-redirect", allow_internal=True)
    assert result["status"] == "TARGET_BLOCKED"


def test_failure_threshold_triggers_once_and_resets_after_recovery(tmp_path, local_server):
    store = wm.WebsiteMonitorStore(tmp_path / "website.sqlite3", encryption_key=TEST_ENCRYPTION_KEY)
    target = store.add_target("Threshold", local_server + "/not-found", 30, 3, allow_internal=True, failure_threshold=2)
    first = store.check_target(target.target_id)
    second = store.check_target(target.target_id)
    third = store.check_target(target.target_id)
    assert first["failure_streak"] == 1 and not first["alert_triggered"]
    assert second["failure_streak"] == 2 and second["alert_triggered"]
    assert third["failure_streak"] == 3 and not third["alert_triggered"]
    # Emulate a recovery by changing the configured URL to the healthy local path.
    with store._connection() as conn:
        conn.execute("UPDATE website_targets SET url=? WHERE target_id=?", (local_server + "/ok", target.target_id))
    recovered = store.check_target(target.target_id)
    assert recovered["status"] == "UP" and recovered["failure_streak"] == 0
    with store._connection() as conn:
        conn.execute("UPDATE website_targets SET url=? WHERE target_id=?", (local_server + "/not-found", target.target_id))
    after_recovery = store.check_target(target.target_id)
    assert after_recovery["failure_streak"] == 1 and not after_recovery["alert_triggered"]


def test_website_store_is_authenticated_encrypted_at_rest_and_wrong_key_fails_closed(tmp_path):
    path = tmp_path / "website.sqlite3"
    store = wm.WebsiteMonitorStore(path, encryption_key=TEST_ENCRYPTION_KEY)
    store.add_target("Secret host", "https://secret-example.invalid/", 300, 8)
    raw = path.read_bytes()
    assert raw.startswith(wm.WebsiteMonitorStore._MAGIC)
    assert b"SQLite format 3" not in raw
    assert b"secret-example.invalid" not in raw
    assert b"https://secret-example.invalid/" not in raw
    with pytest.raises(wm.WebsiteMonitorError, match="Kunci Secure Storage"):
        wm.WebsiteMonitorStore(path, encryption_key=b"x" * 32)
    # Correct key can still read all records.
    assert wm.WebsiteMonitorStore(path, encryption_key=TEST_ENCRYPTION_KEY).list_targets()[0].name == "Secret host"


def test_legacy_plain_sqlite_website_database_is_migrated_to_encrypted_image(tmp_path):
    path = tmp_path / "website.sqlite3"
    legacy = sqlite3.connect(path)
    legacy.executescript("""
        CREATE TABLE website_targets (
            target_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL,
            interval_seconds INTEGER NOT NULL, timeout_seconds INTEGER NOT NULL,
            allow_internal INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
            last_status TEXT NOT NULL DEFAULT '', last_checked_utc TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL
        );
        CREATE TABLE website_checks (
            check_id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL, checked_at_utc TEXT NOT NULL,
            status TEXT NOT NULL, event_type TEXT NOT NULL, http_status INTEGER, dns_ms REAL,
            response_ms REAL, total_ms REAL NOT NULL, redirect_count INTEGER NOT NULL DEFAULT 0,
            error_type TEXT NOT NULL DEFAULT '', message TEXT NOT NULL
        );
        INSERT INTO website_targets(name,url,interval_seconds,timeout_seconds,created_at_utc)
        VALUES('legacy','https://legacy-secret.invalid/',300,8,'2026-01-01T00:00:00Z');
    """)
    legacy.commit()
    legacy.close()
    assert path.read_bytes().startswith(b"SQLite format 3\x00")
    migrated = wm.WebsiteMonitorStore(path, encryption_key=TEST_ENCRYPTION_KEY)
    assert migrated.list_targets()[0].url == "https://legacy-secret.invalid/"
    assert path.read_bytes().startswith(wm.WebsiteMonitorStore._MAGIC)
    assert b"legacy-secret.invalid" not in path.read_bytes()
