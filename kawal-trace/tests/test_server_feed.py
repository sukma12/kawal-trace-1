from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from chainlog.server_feed import ServerFeedClient, ServerFeedError
from chainlog.sync import SyncSettings, SyncSettingsStore, DEFAULT_TELEMETRY_PATH

MONITOR_TOKEN = "monitor-read-only-token-test-0123456789"


@pytest.fixture
def feed_api():
    state = {"authorized": True, "events": []}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return
        def do_GET(self):
            if self.path != f"{DEFAULT_TELEMETRY_PATH}?limit=100":
                self.send_response(404); self.end_headers(); return
            if self.headers.get("Authorization") != f"Bearer {MONITOR_TOKEN}" or not state["authorized"]:
                self.send_response(401); self.end_headers(); return
            body = json.dumps({"events": state["events"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield state, url
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_fetch_readonly_server_feed_and_normalize(tmp_path: Path, feed_api):
    state, base_url = feed_api
    state["events"] = [{
        "event_id": "a" * 64,
        "timestamp_utc": "2026-10-20T02:30:00Z",
        "host_id": "srv-test",
        "source": "linux-journal",
        "event_type": "AUTH_FAILURE",
        "actor": "tester",
        "source_ip": "203.0.113.9",
        "details": {"reason": "failed_password", "password": "must-not-show"},
    }]
    settings = SyncSettings(base_url=base_url, device_id="cl-test-device-001", telemetry_path=DEFAULT_TELEMETRY_PATH)
    events = ServerFeedClient(settings, MONITOR_TOKEN).fetch_recent()
    assert len(events) == 1
    assert events[0]["event_type"] == "AUTH_FAILURE"
    assert "must-not-show" not in json.dumps(events[0])


def test_feed_rejects_bad_token(feed_api):
    _, base_url = feed_api
    settings = SyncSettings(base_url=base_url, device_id="cl-test-device-001")
    with pytest.raises(ServerFeedError, match="401"):
        ServerFeedClient(settings, "wrong-monitor-token-long-enough-123").fetch_recent()


def test_sync_settings_persists_feed_path_without_tokens(tmp_path):
    store = SyncSettingsStore(tmp_path / "sync-settings.json")
    settings = SyncSettings(base_url="https://api.example.test", device_id="cl-test-device-001", telemetry_path="/custom/feed")
    store.save(settings)
    parsed = json.loads((tmp_path / "sync-settings.json").read_text())
    assert parsed["telemetry_path"] == "/custom/feed"
    assert "monitor_token" not in json.dumps(parsed)


def test_sensor_ingest_roundtrip_to_dashboard_feed(tmp_path: Path, monkeypatch):
    """Loopback E2E: Linux agent payload is stored by API and appears in dashboard feed."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from server_agent import chainlog_server_agent as agent
    from server_agent.chainlog_server_agent import Outbox, stable_event_id

    sensor_token = "sensor-write-only-token-test-0123456789"
    state = {"events": {}, "host_id": "srv-lab-e2e"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return
        def do_POST(self):
            if self.path != "/api/v1/security-events:batch":
                self.send_response(404); self.end_headers(); return
            if self.headers.get("Authorization") != f"Bearer {sensor_token}" or self.headers.get("X-KAWAL-Host-ID") != state["host_id"]:
                self.send_response(401); self.end_headers(); return
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            accepted = []
            for event in payload.get("events", []):
                existing = state["events"].get(event["event_id"])
                if existing is not None and existing != event:
                    self.send_response(409); self.end_headers(); return
                state["events"][event["event_id"]] = event
                accepted.append(event["event_id"])
            body = json.dumps({"accepted_event_ids": accepted}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            if self.path != f"{DEFAULT_TELEMETRY_PATH}?limit=100":
                self.send_response(404); self.end_headers(); return
            if self.headers.get("Authorization") != f"Bearer {MONITOR_TOKEN}":
                self.send_response(401); self.end_headers(); return
            body = json.dumps({"events": list(state["events"].values())[-100:][::-1]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    monkeypatch.setattr(agent, "HOST_ID", state["host_id"])
    monkeypatch.setattr(agent, "API_TOKEN", sensor_token)
    monkeypatch.setattr(agent, "INGEST_URL", base_url + "/api/v1/security-events:batch")
    monkeypatch.setattr(agent, "CA_BUNDLE", "")
    try:
        outbox = Outbox(tmp_path / "e2e-outbox.sqlite3")
        event = {
            "event_id": stable_event_id(state["host_id"], "linux-journal", "sample-cursor-1"),
            "timestamp_utc": "2026-10-20T02:30:00Z",
            "host_id": state["host_id"],
            "source": "linux-journal",
            "event_type": "AUTH_FAILURE",
            "actor": "lab-user",
            "source_ip": "203.0.113.8",
            "details": {"service": "sshd.service", "auth_method": "ssh", "reason": "failed_password"},
        }
        outbox.enqueue(event)
        acked, _ = agent.post_batch(outbox, outbox.batch())
        assert acked == [event["event_id"]]
        assert outbox.count() == 0

        settings = SyncSettings(base_url=base_url, device_id="cl-dashboard-e2e")
        feed = ServerFeedClient(settings, MONITOR_TOKEN).fetch_recent()
        assert len(feed) == 1
        assert feed[0]["host_id"] == state["host_id"]
        assert feed[0]["event_type"] == "AUTH_FAILURE"
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
