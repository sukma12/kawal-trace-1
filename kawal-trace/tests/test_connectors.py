from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from chainlog.connectors import GenericRestFeedClient, GenericRestFeedError
from chainlog.sync import SyncConfigError, SyncSettings

TOKEN = "read-only-api-key-0123456789-abcdef"


@pytest.fixture
def rest_feed():
    state = {"authorized": True, "events": [
        {
            "eventNo": "upstream-event-17",
            "created": "2026-10-21T00:10:00Z",
            "severity": "login failed",
            "host": {"name": "ubuntu-lab"},
            "username": "tester",
            "client": {"ip": "203.0.113.23"},
            "message": "SSH authentication failed",
        }
    ]}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_GET(self):
            if not self.path.startswith("/v2/security/events"):
                self.send_response(404); self.end_headers(); return
            if not state["authorized"] or self.headers.get("X-API-Key") != TOKEN:
                self.send_response(401); self.end_headers(); return
            body = json.dumps({"result": {"items": state["events"]}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_generic_readonly_rest_normalizes_mapped_events(rest_feed):
    _, base_url = rest_feed
    mapping = {
        "event_id": "eventNo", "timestamp_utc": "created", "event_type": "severity",
        "host_id": "host.name", "source": "host.name", "actor": "username",
        "source_ip": "client.ip", "details": "message",
    }
    settings = SyncSettings(
        base_url=base_url, device_id="cl-generic-rest-test-001", connector_type="generic_rest_readonly",
        feed_auth_mode="api_key", telemetry_path="/v2/security/events", feed_json_path="result.items",
        feed_field_mapping=json.dumps(mapping),
    )
    events = GenericRestFeedClient(settings, TOKEN).fetch_recent()
    assert len(events) == 1
    assert events[0]["event_type"] == "AUTH_FAILURE"
    assert events[0]["host_id"] == "ubuntu-lab"
    assert events[0]["source_ip"] == "203.0.113.23"
    assert len(events[0]["event_id"]) == 64


def test_generic_feed_rejects_bad_key(rest_feed):
    _, base_url = rest_feed
    settings = SyncSettings(
        base_url=base_url, device_id="cl-generic-rest-test-001", connector_type="generic_rest_readonly",
        feed_auth_mode="api_key", telemetry_path="/v2/security/events", feed_json_path="result.items",
    )
    with pytest.raises(GenericRestFeedError, match="401"):
        GenericRestFeedClient(settings, "wrong-token-01234567890123456789").fetch_recent()


def test_generic_feed_rejects_unknown_json_path(rest_feed):
    _, base_url = rest_feed
    settings = SyncSettings(
        base_url=base_url, device_id="cl-generic-rest-test-001", connector_type="generic_rest_readonly",
        feed_auth_mode="api_key", telemetry_path="/v2/security/events", feed_json_path="not.events",
    )
    with pytest.raises(GenericRestFeedError, match="Path JSON"):
        GenericRestFeedClient(settings, TOKEN).fetch_recent()


def test_generic_mode_and_mapping_validation():
    with pytest.raises(SyncConfigError, match="Mapping field"):
        SyncSettings(
            base_url="https://api.example.test", device_id="cl-generic-rest-test-001",
            connector_type="generic_rest_readonly", feed_field_mapping="not-json",
        ).validated()
    with pytest.raises(SyncConfigError, match="Jenis konektor"):
        SyncSettings(
            base_url="https://api.example.test", device_id="cl-generic-rest-test-001",
            connector_type="magic-scan",
        ).validated()


def test_generic_rest_custom_auth_header():
    from chainlog.sync import DEFAULT_FEED_FIELD_MAPPING
    settings = SyncSettings(
        base_url="https://api.example.test", device_id="cl-custom-header-test-001",
        connector_type="generic_rest_readonly", feed_auth_mode="custom_header",
        feed_auth_header_name="X-Org-Access",
    ).validated()
    client = GenericRestFeedClient(settings, TOKEN)
    headers = client._headers()
    assert headers["X-Org-Access"] == TOKEN
    assert "Authorization" not in headers


def test_generic_rest_no_auth_does_not_send_stale_token():
    settings = SyncSettings(
        base_url="https://api.example.test", device_id="cl-no-auth-test-001",
        connector_type="generic_rest_readonly", feed_auth_mode="none",
    ).validated()
    client = GenericRestFeedClient(settings, TOKEN)
    headers = client._headers()
    assert "Authorization" not in headers
    assert "X-API-Key" not in headers


def test_custom_header_name_rejects_newlines():
    with pytest.raises(SyncConfigError, match="Nama header"):
        SyncSettings(
            base_url="https://api.example.test", device_id="cl-bad-header-test-001",
            connector_type="generic_rest_readonly", feed_auth_mode="custom_header",
            feed_auth_header_name="X-Ok\r\nAuthorization",
        ).validated()
