from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from chainlog.api_discovery import find_event_collection, infer_event_mapping, probe_readonly_json_event_feed
from chainlog.sync import SyncSettings


EVENT = {
    "id": "source-event-0001",
    "timestamp": "2026-10-23T01:02:03Z",
    "type": "login failed",
    "host": {"name": "ubuntu-lab"},
    "user": {"name": "operator"},
    "client": {"ip": "203.0.113.25"},
    "message": "authentication failed",
}


def test_find_events_nested_in_common_wrappers():
    found = find_event_collection({"status": "ok", "data": {"results": {"events": [EVENT]}}})
    assert found is not None
    path, events = found
    assert path == "data.results.events"
    assert events[0]["id"] == EVENT["id"]


def test_find_event_array_at_root():
    found = find_event_collection([EVENT])
    assert found is not None
    assert found[0] == "$"


def test_infer_common_nested_mapping():
    mapping = infer_event_mapping(EVENT)
    assert mapping["timestamp_utc"] == "timestamp"
    assert mapping["event_type"] == "type"
    assert mapping["host_id"] == "host.name"
    assert mapping["actor"] == "user.name"
    assert mapping["source_ip"] == "client.ip"
    assert mapping["details"] == "message"


def test_infer_epoch_timestamp_field():
    mapping = infer_event_mapping({"created_at": 1792717323, "action": "login failed"})
    assert mapping["timestamp_utc"] == "created_at"


def test_no_timestamp_does_not_claim_compatibility():
    assert infer_event_mapping({"event": "login failed", "ip": "203.0.113.25"}) == {}


def test_probe_finds_authenticated_readonly_feed():
    state = {"hits": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_GET(self):
            state["hits"].append(self.path)
            if self.headers.get("Authorization") != "Bearer integration-test-token-1234567890":
                self.send_response(401); self.end_headers(); return
            if self.path.split("?", 1)[0] == "/api/security-events":
                body = json.dumps({"data": {"events": [EVENT]}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body); return
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        settings = SyncSettings(
            base_url=base,
            device_id="kt-discovery-test-0001",
            connector_type="generic_rest_readonly",
            telemetry_path="/not-a-feed",
            feed_auth_mode="bearer",
            feed_json_path="events",
        ).validated()
        result = probe_readonly_json_event_feed(settings, "integration-test-token-1234567890", timeout_seconds=1.0)
        assert result["ok"] is True
        assert result["path"] == "/api/security-events"
        assert result["events_path"] == "data.events"
        assert result["mapping"]["timestamp_utc"] == "timestamp"
        assert "Authorization" not in json.dumps(result)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_auto_discovery_never_follows_redirects():
    state = {"paths": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_GET(self):
            state["paths"].append(self.path.split("?", 1)[0])
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/redirect-target")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        settings = SyncSettings(
            base_url=f"http://127.0.0.1:{server.server_address[1]}",
            device_id="kt-discovery-test-0002",
            connector_type="generic_rest_readonly",
            telemetry_path="/custom-feed",
            feed_auth_mode="none",
        ).validated()
        result = probe_readonly_json_event_feed(settings, "", timeout_seconds=1.0)
        assert result["ok"] is False
        assert state["paths"]
        assert all(path != "/redirect-target" for path in state["paths"])
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_probe_rejects_missing_auth_before_network():
    settings = SyncSettings(
        base_url="https://api.example.test",
        device_id="kt-discovery-test-0003",
        connector_type="generic_rest_readonly",
        telemetry_path="/api/v1/security-events",
        feed_auth_mode="bearer",
    ).validated()
    try:
        probe_readonly_json_event_feed(settings, "", timeout_seconds=0.5)
    except ValueError as exc:
        assert "Token/API key" in str(exc)
    else:
        raise AssertionError("Missing auth should be rejected before attempting the network")


def test_numeric_timestamp_conversion_supports_seconds_and_milliseconds():
    from chainlog.connectors import _coerce_timestamp as rest_timestamp
    from chainlog.protocol_adapters import _coerce_timestamp as adapter_timestamp

    seconds = 1792717323
    milliseconds = seconds * 1000
    expected = datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    assert rest_timestamp(seconds) == expected
    assert rest_timestamp(str(milliseconds)) == expected
    assert adapter_timestamp(seconds) == expected
    assert adapter_timestamp(milliseconds) == expected
