"""Integrated defensive pipeline test: Linux SSH event -> E2EE API -> dashboard -> alert.

The API simulator binds only to 127.0.0.1. No real SSH login, public IP, account,
firewall rule, or external API is touched.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from chainlog.detection import DetectionEngine
from chainlog.e2ee import generate_keypair
from chainlog.server_feed import E2EEServerFeedClient
from chainlog.sync import SyncSettings
from server_agent import chainlog_server_agent as agent
from server_agent.chainlog_server_agent import Outbox, parse_journal_entry


SENSOR_TOKEN = "e2e-sensor-write-token-only-0123456789"
MONITOR_TOKEN = "e2e-monitor-read-only-token-0123456789"


def _journal_failure(cursor: str, epoch_us: int, username: str, ip: str) -> dict:
    return {
        "__CURSOR": cursor,
        "__REALTIME_TIMESTAMP": str(epoch_us),
        "_SYSTEMD_UNIT": "sshd.service",
        "MESSAGE": f"Failed password for {username} from {ip} port 43122 ssh2",
    }


def test_ssh_failure_burst_survives_encrypted_ingest_and_reaches_detection(tmp_path, monkeypatch):
    keypair = generate_keypair()
    state = {"envelopes": [], "host_id": "srv-lab-e2e"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def _json(self, status: int, body: dict):
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self):
            if self.path != "/api/v1/encrypted-security-events:batch":
                self._json(404, {"error": "not_found"})
                return
            if (self.headers.get("Authorization") != f"Bearer {SENSOR_TOKEN}"
                    or self.headers.get("X-KAWAL-Host-ID") != state["host_id"]):
                self._json(401, {"error": "unauthorized"})
                return
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                envelopes = body.get("events")
                if body.get("schema_version") != 1 or not isinstance(envelopes, list) or not envelopes:
                    raise ValueError("invalid_batch")
                ids = [item["metadata"]["event_id"] for item in envelopes]
                expected_idem = hashlib.sha256("\n".join(ids).encode("ascii")).hexdigest()
                if self.headers.get("Idempotency-Key") != expected_idem:
                    raise ValueError("idempotency_mismatch")
                # Store opaque envelopes only; this simulated API never decrypts event bodies.
                state["envelopes"].extend(envelopes)
                self._json(200, {"accepted_event_ids": ids})
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                self._json(400, {"error": "invalid_batch"})

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path != "/api/v1/encrypted-security-events":
                self._json(404, {"error": "not_found"})
                return
            if self.headers.get("Authorization") != f"Bearer {MONITOR_TOKEN}":
                self._json(401, {"error": "unauthorized"})
                return
            try:
                limit = int(parse_qs(parsed.query).get("limit", ["100"])[0])
            except ValueError:
                self._json(400, {"error": "invalid_limit"})
                return
            self._json(200, {"events": list(reversed(state["envelopes"][-limit:])), "count": len(state["envelopes"])})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"

    monkeypatch.setattr(agent, "HOST_ID", state["host_id"])
    monkeypatch.setattr(agent, "API_TOKEN", SENSOR_TOKEN)
    monkeypatch.setattr(agent, "INGEST_URL", base_url)
    monkeypatch.setattr(agent, "CA_BUNDLE", "")
    monkeypatch.setattr(agent, "E2EE_PUBLIC_KEY", keypair["public_key_b64"])
    monkeypatch.setattr(agent, "E2EE_REQUIRED", True)
    monkeypatch.setattr(agent, "ALLOW_LEGACY_TLS", False)

    try:
        now_us = int(time.time() * 1_000_000)
        event_1 = parse_journal_entry(_journal_failure("cursor-e2e-1", now_us, "lab-unknown", "203.0.113.8"), state["host_id"])
        event_2 = parse_journal_entry(_journal_failure("cursor-e2e-2", now_us + 2_000_000, "lab-unknown", "203.0.113.8"), state["host_id"])
        assert event_1 is not None and event_2 is not None
        assert event_1["event_type"] == event_2["event_type"] == "AUTH_FAILURE"
        assert event_1["source_ip"] == event_2["source_ip"] == "203.0.113.8"

        outbox = Outbox(tmp_path / "agent-outbox.sqlite3")
        outbox.enqueue(event_1)
        outbox.enqueue(event_2)
        accepted, summary = agent.post_batch(outbox, outbox.batch())
        assert set(accepted) == {event_1["event_id"], event_2["event_id"]}
        assert outbox.count() == 0
        assert "pending=0" in summary
        assert len(state["envelopes"]) == 2
        opaque_text = json.dumps(state["envelopes"])
        assert "failed_password" not in opaque_text
        assert '"actor":"lab-unknown"' not in opaque_text

        settings = SyncSettings(base_url=base_url, device_id="dashboard-e2e-device")
        feed = E2EEServerFeedClient(settings, MONITOR_TOKEN, keypair["private_key_b64"]).fetch_recent()
        assert len(feed) == 2
        alerts = DetectionEngine(auth_failure_threshold=2, window_seconds=300).evaluate(feed)
        burst = [item for item in alerts if item.rule_id == "AUTH_FAILURE_BURST"]
        assert burst, "two SSH failures from one source should generate a HIGH burst alert"
        assert burst[0].severity == "HIGH"
        assert burst[0].source_ip == "203.0.113.8"
        assert set(burst[0].event_ids) == {event_1["event_id"], event_2["event_id"]}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
