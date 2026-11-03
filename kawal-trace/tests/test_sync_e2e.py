"""Network-level integration tests against a local in-process test API.

Only localhost HTTP is used here; production Internet endpoints must use HTTPS.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from chainlog.core import AuditStore, GENESIS_HASH, record_hash
from chainlog.sync import (
    DEFAULT_EVENTS_PATH,
    DEFAULT_HEALTH_PATH,
    SyncClient,
    SyncConfigError,
    SyncCursorStore,
    SyncProtocolError,
    SyncSettings,
    SyncSettingsStore,
    SyncTransportError,
)

TOKEN = "test-device-token-1a2b3c4d5e6f7g8h9i0j"


class _APIState:
    def __init__(self) -> None:
        self.device_id = "cl-test-device-0001"
        self.token = TOKEN
        self.events: dict[str, dict[int, dict[str, Any]]] = {}
        self.fail_next_post = False
        self.wrong_ack_hash = False
        self.lock = threading.Lock()


@pytest.fixture

def test_api():
    state = _APIState()

    class Handler(BaseHTTPRequestHandler):
        server_version = "Kawal-Trace-TestAPI/1.0"

        def log_message(self, *_args):
            return

        def _json(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            return (
                self.headers.get("Authorization") == f"Bearer {state.token}"
                and self.headers.get("X-KAWAL-Device-ID") == state.device_id
            )

        def do_GET(self):
            if self.path != DEFAULT_HEALTH_PATH:
                return self._json(404, {"error": "not_found"})
            if not self._authorized():
                return self._json(401, {"error": "unauthorized"})
            return self._json(200, {"status": "ok", "service": "kawal-trace-test"})

        def do_POST(self):
            if self.path != DEFAULT_EVENTS_PATH:
                return self._json(404, {"error": "not_found"})
            if not self._authorized():
                return self._json(401, {"error": "unauthorized"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 2_000_000:
                    return self._json(413, {"error": "bad_size"})
                body = json.loads(self.rfile.read(length))
            except (ValueError, json.JSONDecodeError):
                return self._json(400, {"error": "bad_json"})
            if body.get("device_id") != state.device_id:
                return self._json(403, {"error": "device_mismatch"})
            if self.headers.get("Idempotency-Key") != body.get("batch_id"):
                return self._json(400, {"error": "idempotency_key_mismatch"})
            events = body.get("events")
            if not isinstance(events, list) or not events:
                return self._json(400, {"error": "empty_batch"})

            with state.lock:
                if state.fail_next_post:
                    state.fail_next_post = False
                    return self._json(503, {"error": "planned_test_outage"})
                current = state.events.setdefault(state.device_id, {})
                for event in events:
                    try:
                        seq = int(event["seq"])
                        event_hash = str(event["record_hash"])
                        eid = str(event["event_id"])
                        if record_hash(event) != event_hash:
                            return self._json(400, {"error": "record_hash_invalid"})
                    except (KeyError, TypeError, ValueError):
                        return self._json(400, {"error": "record_invalid"})
                    prior = current.get(seq)
                    if prior:
                        if prior["event_id"] != eid or prior["record_hash"] != event_hash:
                            return self._json(409, {"error": "duplicate_conflict"})
                        continue
                    expected_seq = max(current, default=0) + 1
                    expected_previous = current[max(current)]["record_hash"] if current else GENESIS_HASH
                    if seq != expected_seq:
                        return self._json(409, {"error": "sequence_gap", "expected_seq": expected_seq})
                    if event["previous_hash"] != expected_previous:
                        return self._json(409, {"error": "chain_link_invalid"})
                    # Store a copy to model server persistence and idempotency.
                    current[seq] = dict(event)
                accepted_seq = int(events[-1]["seq"])
                accepted_hash = current[accepted_seq]["record_hash"]
                if state.wrong_ack_hash:
                    state.wrong_ack_hash = False
                    accepted_hash = "f" * 64
                return self._json(200, {
                    "accepted_through_seq": accepted_seq,
                    "head_hash": accepted_hash,
                    "accepted_count": len(events),
                })

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield state, base_url
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def _make_client(tmp_path: Path, base_url: str, state: _APIState, token: str = TOKEN) -> SyncClient:
    settings_store = SyncSettingsStore(tmp_path / "settings.json")
    settings = SyncSettings(
        base_url=base_url,
        device_id=state.device_id,
        events_path=DEFAULT_EVENTS_PATH,
        health_path=DEFAULT_HEALTH_PATH,
    )
    settings_store.save(settings)
    # These tests exercise the server-side protocol, so they opt in explicitly; the application never does.
    return SyncClient(settings, token, SyncCursorStore(tmp_path / "sync-state.sqlite3"), allow_remote_storage=True)


def _store(tmp_path: Path) -> AuditStore:
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    store.add_event("ACCESS", "tester", "test-suite", {"message": "uji integrasi"})
    store.add_event("ALERT", "tester", "test-suite", {"message": "perubahan sampel", "severity": "HIGH"})
    return store


def test_end_to_end_sync_and_dedupe(tmp_path, test_api):
    state, base_url = test_api
    store = _store(tmp_path)
    client = _make_client(tmp_path, base_url, state)

    health = client.health_check()
    assert health["status"] == "ok"

    result = client.sync_once(store)
    assert result.ok
    assert result.last_ack_seq == len(store.records())
    assert result.accepted_count == len(store.records())
    assert len(state.events[state.device_id]) == len(store.records())

    second = client.sync_once(store)
    assert second.accepted_count == 0
    assert len(state.events[state.device_id]) == len(store.records())


def test_offline_or_server_outage_keeps_local_records_and_retries(tmp_path, test_api):
    state, base_url = test_api
    store = _store(tmp_path)
    state.fail_next_post = True
    client = _make_client(tmp_path, base_url, state)

    with pytest.raises(SyncTransportError):
        client.sync_once(store)
    cursor = client.cursor_store.get(state.device_id)
    assert cursor.last_ack_seq == 0
    local_count = len(store.records())
    assert local_count >= 3

    result = client.sync_once(store)
    assert result.ok
    assert result.last_ack_seq == local_count
    assert len(store.records()) == local_count
    assert len(state.events[state.device_id]) == local_count


def test_wrong_server_checkpoint_never_advances_local_cursor(tmp_path, test_api):
    state, base_url = test_api
    store = _store(tmp_path)
    state.wrong_ack_hash = True
    client = _make_client(tmp_path, base_url, state)

    with pytest.raises(SyncProtocolError):
        client.sync_once(store)
    assert client.cursor_store.get(state.device_id).last_ack_seq == 0


def test_bad_token_is_rejected_and_not_logged_into_config(tmp_path, test_api):
    state, base_url = test_api
    settings_store = SyncSettingsStore(tmp_path / "settings.json")
    settings_store.save(SyncSettings(base_url=base_url, device_id=state.device_id))
    client = SyncClient(settings_store.settings, "bad-token-value-that-is-long-enough", SyncCursorStore(tmp_path / "cursor.sqlite3"), allow_remote_storage=True)
    with pytest.raises(SyncTransportError, match="401"):
        client.health_check()
    file_contents = (tmp_path / "settings.json").read_text(encoding="utf-8")
    assert TOKEN not in file_contents
    assert "bad-token-value-that-is-long-enough" not in file_contents


def test_invalid_local_chain_blocks_upload(tmp_path, test_api):
    state, base_url = test_api
    store = _store(tmp_path)
    with store._connection() as conn:
        conn.execute("DROP TRIGGER IF EXISTS deny_log_update")
        conn.execute("UPDATE log_entries SET details_json='{}' WHERE seq=2")
    client = _make_client(tmp_path, base_url, state)
    with pytest.raises(SyncProtocolError, match="audit lokal tidak valid"):
        client.sync_once(store)
    assert not state.events.get(state.device_id)


def test_internet_http_is_refused_and_custom_path_is_checked():
    with pytest.raises(SyncConfigError, match="HTTPS wajib"):
        SyncSettings("http://example.invalid", "cl-test-device-0001").validated()
    with pytest.raises(SyncConfigError):
        SyncSettings("https://api.example.invalid", "cl-test-device-0001", events_path="//evil.invalid/hook").validated()


def test_settings_never_persist_device_token(tmp_path):
    settings = SyncSettings.new_device("https://api.example.invalid")
    saved = SyncSettingsStore(tmp_path / "sync-settings.json")
    saved.save(settings)
    parsed = json.loads((tmp_path / "sync-settings.json").read_text(encoding="utf-8"))
    assert "device_token" not in parsed
    assert "authorization" not in parsed
    assert parsed["device_id"] == settings.device_id
    assert "issued-secret-value" not in json.dumps(parsed)


def test_health_check_rejects_oversized_remote_response(tmp_path: Path):
    class HugeHeaderHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_GET(self):
            body = b'{}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            # Test that the client rejects an oversized Content-Length before consuming body bytes.
            self.send_header("Content-Length", str(4 * 1024 * 1024 + 1))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), HugeHeaderHandler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        settings = SyncSettings(
            base_url=f"http://127.0.0.1:{httpd.server_address[1]}",
            device_id="cl-size-check-0001",
        )
        client = SyncClient(settings, TOKEN, SyncCursorStore(tmp_path / "cursor.sqlite3"), allow_remote_storage=True)
        with pytest.raises(SyncProtocolError, match="Health check ditolak"):
            client.health_check()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)
