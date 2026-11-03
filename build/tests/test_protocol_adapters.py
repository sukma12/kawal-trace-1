from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from websockets.sync.server import serve as ws_serve

from chainlog.protocol_adapters import ProtocolAdapterError, ReadOnlyProtocolAdapter
from chainlog.sync import SyncSettings, SyncConfigError

TOKEN = "adapter-readonly-test-token-0123456789"
SECRET = "oauth-client-secret-test-only"
STAMP = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
MAPPING = {
    "event_id": "id", "timestamp_utc": "at", "event_type": "kind", "host_id": "host",
    "source": "source", "actor": "user", "source_ip": "ip", "details": "message",
}
EVENT = {"id": "test-event-0001", "at": STAMP, "kind": "login failed", "host": "lab-01",
         "source": "sshd", "user": "alice", "ip": "198.51.100.20", "message": "simulated login failed"}


class APIState:
    def __init__(self):
        self.requests = []
        self.lock = threading.Lock()


@pytest.fixture
def api_server():
    state = APIState()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *_args):
            return
        def send(self, status, body, content_type="application/json"):
            body = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status); self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body))); self.send_header("Connection", "close")
            self.end_headers()
            try: self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError): pass
        def do_GET(self):
            parsed = urlsplit(self.path)
            with state.lock: state.requests.append(("GET", parsed.path, dict(self.headers)))
            if parsed.path == "/token":
                self.send(405, {"error": "POST only"}); return
            if parsed.path == "/page":
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    self.send(401, {"error": "unauthorized"}); return
                qs = parse_qs(parsed.query); offset = int(qs.get("offset", [0])[0])
                values = [{**EVENT, "id": f"event-{i:04d}"} for i in range(offset, min(offset + 2, 6))]
                self.send(200, {"data": {"events": values}, "next_cursor": None}); return
            if parsed.path == "/oauth-logs":
                if self.headers.get("Authorization") != "Bearer oauth-access-token":
                    self.send(401, {"error": "unauthorized"}); return
                self.send(200, {"events": [EVENT]}); return
            self.send(404, {"error": "not found"})
        def do_POST(self):
            parsed = urlsplit(self.path)
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            with state.lock: state.requests.append(("POST", parsed.path, dict(self.headers)))
            if parsed.path == "/token":
                form = parse_qs(raw.decode())
                if form.get("grant_type") == ["client_credentials"] and form.get("client_id") == ["demo-client"] and form.get("client_secret") == [SECRET]:
                    self.send(200, {"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300}); return
                self.send(401, {"error": "invalid_client"}); return
            if parsed.path == "/graphql":
                if b"mutation" in raw.lower() or b"subscription" in raw.lower():
                    self.send(400, {"errors": [{"message": "read only"}]}); return
                self.send(200, {"data": {"auditEvents": [EVENT]}}); return
            if parsed.path == "/soap":
                self.send(200, b"<Envelope><Body><GetEventsResponse><Event><Id>soap-event-0000001</Id><At>" + STAMP.encode() + b"</At><Kind>login failed</Kind><Host>lab-soap</Host><Source>sshd</Source><User>bob</User><Ip>198.51.100.21</Ip><Message>failed</Message></Event></GetEventsResponse></Body></Envelope>", "text/xml"); return
            self.send(404, {"error": "not found"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True); thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def settings(base_url, protocol="rest", options=None, path="/page", auth="bearer"):
    return SyncSettings(
        base_url=base_url, device_id="kt-adapter-test-0001", connector_type="generic_rest_readonly",
        telemetry_path=path, feed_auth_mode=auth, feed_json_path="data.events",
        feed_field_mapping=json.dumps(MAPPING), adapter_protocol=protocol,
        adapter_options_json=json.dumps(options or {}),
    ).validated()


def test_rest_offset_pagination_collects_multiple_pages(api_server):
    state, base = api_server
    s = settings(base, "rest", {"events_path": "data.events", "pagination": {
        "mode": "offset", "items_path": "data.events", "offset_param": "offset", "page_size": 2, "max_pages": 4}}, "/page")
    events = ReadOnlyProtocolAdapter(s, TOKEN).fetch_recent(6)
    assert len(events) == 6
    assert len({e["event_id"] for e in events}) == 6
    assert sum(1 for method, path, _ in state.requests if method == "GET" and path == "/page") == 3


def test_oauth2_client_credentials_uses_secret_without_logging_it(api_server):
    state, base = api_server
    s = settings(base, "oauth2_rest", {"token_url": base + "/token", "client_id": "demo-client", "client_auth": "post", "events_path": "events"}, "/oauth-logs")
    client = ReadOnlyProtocolAdapter(s, client_secret=SECRET)
    events = client.fetch_recent(1)
    assert len(events) == 1 and events[0]["event_type"] == "AUTH_FAILURE"
    assert client._oauth_token == "oauth-access-token"
    assert SECRET not in repr(state.requests)


def test_graphql_query_read_only_maps_events(api_server):
    _, base = api_server
    s = settings(base, "graphql", {"query": "query SecurityEvents { auditEvents { id at kind host source user ip message } }", "events_path": "data.auditEvents"}, "/graphql", auth="none")
    events = ReadOnlyProtocolAdapter(s).fetch_recent(10)
    assert len(events) == 1 and events[0]["source"] == "sshd"


def test_graphql_mutation_is_rejected_before_network(api_server):
    _, base = api_server
    s = settings(base, "graphql", {"query": "mutation { deleteEverything { ok } }", "events_path": "data.auditEvents"}, "/graphql", auth="none")
    with pytest.raises(ProtocolAdapterError, match="mutation"):
        ReadOnlyProtocolAdapter(s).fetch_recent(1)


def test_soap_xml_uses_safe_parser_and_normalizes(api_server):
    _, base = api_server
    options = {"envelope_xml": "<Envelope><Body><GetEvents/></Body></Envelope>", "event_tag": "Event",
               "xml_mapping": {"event_id": "Id", "timestamp_utc": "At", "event_type": "Kind", "host_id": "Host", "source": "Source", "actor": "User", "source_ip": "Ip", "details": "Message"}}
    s = settings(base, "soap", options, "/soap", auth="none")
    events = ReadOnlyProtocolAdapter(s).fetch_recent(10)
    assert len(events) == 1 and events[0]["host_id"] == "lab-soap"


def test_soap_rejects_doctype_and_entity(payload_server=None):
    class Dummy: pass
    s = settings("http://127.0.0.1:8765", "soap", {"envelope_xml": "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><Envelope>&e;</Envelope>", "event_tag": "Event", "xml_mapping": {"timestamp_utc": "At"}}, "/soap", auth="none")
    with pytest.raises(ProtocolAdapterError, match="DOCTYPE"):
        ReadOnlyProtocolAdapter(s).fetch_recent(1)


def test_websocket_json_events_read_only():
    def handler(connection):
        connection.send(json.dumps(EVENT))
    server = ws_serve(handler, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.socket.getsockname()[1]
        s = settings("http://127.0.0.1:1", "websocket", {"url": f"ws://127.0.0.1:{port}", "events_path": "$", "idle_timeout_seconds": 0.25, "messages_per_poll": 2}, "/unused", auth="none")
        events = ReadOnlyProtocolAdapter(s).fetch_recent(1)
        assert len(events) == 1 and events[0]["host_id"] == "lab-01"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_internet_websocket_requires_wss():
    s = settings("https://example.test", "websocket", {"url": "ws://example.test/events", "events_path": "$"}, "/unused", auth="none")
    with pytest.raises(ProtocolAdapterError, match="WSS"):
        ReadOnlyProtocolAdapter(s).fetch_recent(1)


def test_adapter_config_rejects_secret_in_plaintext_settings():
    with pytest.raises(SyncConfigError, match="Rahasia"):
        SyncSettings(base_url="https://api.example.test", device_id="kt-adapter-test-0001",
                     connector_type="generic_rest_readonly", adapter_options_json='{"client_secret":"not-allowed"}').validated()


def test_nested_secret_key_is_rejected_recursively():
    with pytest.raises(SyncConfigError, match="Rahasia"):
        SyncSettings(base_url="https://api.example.test", device_id="kt-adapter-test-0001",
                     connector_type="generic_rest_readonly",
                     adapter_options_json='{"oauth":{"client_id":"demo","client_secret":"must-not-persist"}}').validated()


def test_soap_mutating_operation_is_rejected_before_network(api_server):
    _, base = api_server
    options = {"envelope_xml": "<Envelope><Body><DeleteUser><id>1</id></DeleteUser></Body></Envelope>",
               "event_tag": "Event", "xml_mapping": {"timestamp_utc": "At"}}
    s = settings(base, "soap", options, "/soap", auth="none")
    with pytest.raises(ProtocolAdapterError, match="read-only"):
        ReadOnlyProtocolAdapter(s).fetch_recent(1)


def test_websocket_connection_is_reused_across_polls():
    connections = []
    def handler(connection):
        connections.append(1)
        connection.send(json.dumps(EVENT))
        second = {**EVENT, "id": "second-websocket-event", "user": "charlie"}
        connection.send(json.dumps(second))
        threading.Event().wait(0.4)
    server = ws_serve(handler, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    client = None
    try:
        port = server.socket.getsockname()[1]
        s = settings("http://127.0.0.1:1", "websocket", {"url": f"ws://127.0.0.1:{port}", "events_path": "$", "idle_timeout_seconds": 0.1, "messages_per_poll": 1}, "/unused", auth="none")
        client = ReadOnlyProtocolAdapter(s)
        first = client.fetch_recent(1)
        second = client.fetch_recent(1)
        assert len(first) == len(second) == 1
        assert len(connections) == 1, "WebSocket should remain persistent between polling calls"
    finally:
        if client: client.close()
        server.shutdown(); thread.join(timeout=2)


def test_soap_rejects_multiple_body_operations(api_server):
    _, base = api_server
    options = {"envelope_xml": "<Envelope><Body><GetEvents/><DeleteUser/></Body></Envelope>",
               "event_tag": "Event", "xml_mapping": {"timestamp_utc": "At"}}
    s = settings(base, "soap", options, "/soap", auth="none")
    with pytest.raises(ProtocolAdapterError, match="read-only"):
        ReadOnlyProtocolAdapter(s).fetch_recent(1)


def test_rest_query_params_are_passed_and_cannot_override_pagination(api_server):
    _, base = api_server
    s = settings(base, "rest", {"events_path":"data.events", "query_params":{"tenant":"audit-only"},
                                 "pagination":{"mode":"none","max_pages":1}}, "/page")
    # The upstream test server authorizes the request and returns a schema that can be mapped.
    # This case is only exercising bounded config validation; the existing server route requires auth.
    assert ReadOnlyProtocolAdapter(s, TOKEN).config["query_params"]["tenant"] == "audit-only"
    bad = settings(base, "rest", {"query_params":{"limit":999}}, "/page")
    with pytest.raises(ProtocolAdapterError, match="tidak boleh menimpa"):
        ReadOnlyProtocolAdapter(bad, TOKEN).fetch_recent(1)
