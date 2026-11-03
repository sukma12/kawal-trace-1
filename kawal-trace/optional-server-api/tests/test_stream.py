"""Live change stream (Server-Sent Events doorbell) on the optional server API.

The server module is loaded as a private copy so these tests own their database and tuning constants
instead of depending on whichever test module imported `server` first.
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import os
import queue
import socket
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

SERVER_PATH = Path(__file__).resolve().parents[1] / "server.py"
MONITOR_A = ("dev-stream-0001", "m" * 64)
MONITOR_B = ("dev-stream-0002", "n" * 64)
AUDIT_TOKEN = "q" * 64


def load_server():
    spec = importlib.util.spec_from_file_location("kawal_stream_server_under_test", SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StreamClient:
    """Minimal SSE reader that records every raw byte it received."""

    def __init__(self, port: int, identity: str, token: str, *, timeout: float = 6.0) -> None:
        self.raw = bytearray()
        self.messages: "queue.Queue[tuple[str, dict | None]]" = queue.Queue()
        self.closed = threading.Event()
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        headers = {"Authorization": f"Bearer {token}", "X-KAWAL-Device-ID": identity}
        self.conn.request("GET", "/api/v1/stream", headers=headers)
        self.response = self.conn.getresponse()
        self.status = self.response.status
        self.content_type = self.response.getheader("Content-Type", "")
        self.error_body = b""
        if self.status == 200:
            self.thread = threading.Thread(target=self._read, daemon=True)
            self.thread.start()
        else:
            self.error_body = self.response.read()
            self.closed.set()

    def _read(self) -> None:
        event, data = "", ""
        try:
            while True:
                line = self.response.fp.readline()
                if not line:
                    break
                self.raw.extend(line)
                text = line.decode("utf-8").rstrip("\r\n")
                if text == "":
                    if event:
                        self.messages.put((event, json.loads(data) if data else None))
                    event, data = "", ""
                elif text.startswith(":"):
                    self.messages.put(("ping", None))
                elif text.startswith("event:"):
                    event = text[6:].strip()
                elif text.startswith("data:"):
                    data = text[5:].strip()
        except (OSError, ValueError):
            pass
        finally:
            self.closed.set()

    def next(self, *, timeout: float = 4.0, skip_ping: bool = True) -> tuple[str, dict | None]:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("no stream message before the deadline")
            item = self.messages.get(timeout=remaining)
            if skip_ping and item[0] == "ping":
                continue
            return item

    def drain(self, *, quiet: float = 0.4) -> list[tuple[str, dict | None]]:
        """Collect messages until the stream has been silent (apart from pings) for `quiet` seconds."""
        collected: list[tuple[str, dict | None]] = []
        last_real = time.monotonic()
        while time.monotonic() - last_real < quiet:
            try:
                item = self.messages.get(timeout=0.05)
            except queue.Empty:
                continue
            if item[0] != "ping":  # heartbeats do not count as activity (they would keep us here forever)
                collected.append(item)
                last_real = time.monotonic()
        return collected

    def close(self) -> None:
        """Hang up the way a real app does: send FIN. For a close-delimited response http.client hands the
        socket to the response (conn.sock is None) and the reader thread keeps its file open, so conn.close()
        alone never closes the TCP connection and the server would never see the hang-up."""
        try:
            self.response.fp.raw._sock.shutdown(socket.SHUT_RDWR)
        except (AttributeError, OSError, ValueError):
            pass
        self.closed.wait(2)
        try:
            self.conn.close()
        except OSError:
            pass


class StreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {
            "KAWAL_API_DB_PATH": str(Path(cls.temp.name) / "stream.sqlite3"),
            "KAWAL_MONITOR_TOKENS": f"{MONITOR_A[0]}|{MONITOR_A[1]};{MONITOR_B[0]}|{MONITOR_B[1]}",
            "KAWAL_AUDIT_TOKENS": f"{MONITOR_A[0]}|{AUDIT_TOKEN}",
            # test_api.py switches this on process-wide when it is imported; this module asserts the default.
            "KAWAL_API_ACCEPT_CLIENT_DATA": "false",
        })
        cls.env.start()
        cls.server = load_server()
        cls.server.init_db()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), cls.server.APIHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)
        cls.env.stop()
        cls.temp.cleanup()

    def setUp(self):
        s = self.server
        s.STREAM_HEARTBEAT_SECONDS = 0.25
        s.STREAM_WATCH_SECONDS = 0.04
        s.STREAM_MAX_LIFETIME_SECONDS = 600.0
        s.STREAM_MAX_TOTAL = 8
        s.STREAM_MAX_PER_IDENTITY = 2
        self.clients: list[StreamClient] = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        # Streams must release their slot and the watcher must wind down once everyone is gone.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and (self.server.STREAMS.open_count() or self.server.STREAM_HUB._thread):
            time.sleep(0.05)

    def open(self, identity_token=MONITOR_A) -> StreamClient:
        client = StreamClient(self.port, *identity_token)
        self.clients.append(client)
        return client

    def sql(self, statement: str, params: tuple = ()) -> None:
        with self.server.DB_LOCK, self.server.db_session() as conn:
            conn.execute(statement, params)

    # -- authentication ---------------------------------------------------------------------------------

    def test_rejects_missing_wrong_and_other_scope_tokens(self):
        for identity, token in (("", ""), (MONITOR_A[0], ""), (MONITOR_A[0], "x" * 64),
                                ("someone-else-01", MONITOR_A[1]),
                                (MONITOR_A[0], AUDIT_TOKEN)):  # an audit-upload token must not open a stream
            client = StreamClient(self.port, identity, token)
            self.clients.append(client)
            self.assertEqual(client.status, 401, (identity, token[:3]))
        self.assertEqual(self.server.STREAMS.open_count(), 0)

    def test_stream_path_is_not_a_client_data_endpoint(self):
        # The stream carries no client data, so it must stay available when client-data storage is off.
        self.assertNotIn(self.server.STREAM_PATH, self.server.CLIENT_DATA_PATHS)
        self.assertFalse(self.server.client_data_storage_enabled())
        client = self.open()
        self.assertEqual(client.status, 200)

    def test_event_stream_headers_and_hello(self):
        client = self.open()
        self.assertEqual(client.status, 200)
        self.assertTrue(client.content_type.startswith("text/event-stream"))
        event, data = client.next()
        self.assertEqual(event, "hello")
        self.assertEqual(data["v"], 1)
        self.assertEqual(data["changed"], [])
        self.assertEqual(data["heartbeat_seconds"], self.server.STREAM_HEARTBEAT_SECONDS)
        self.assertIn(b"retry: 3000", bytes(client.raw))

    def test_health_advertises_stream_feature(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        conn.request("GET", "/healthz", headers={"Authorization": f"Bearer {MONITOR_A[1]}", "X-KAWAL-Device-ID": MONITOR_A[0]})
        body = json.loads(conn.getresponse().read())
        conn.close()
        self.assertIn("stream", body["features"])

    # -- change notices ---------------------------------------------------------------------------------

    def test_each_kind_of_change_rings_the_right_bell(self):
        client = self.open()
        self.assertEqual(client.next()[0], "hello")
        now = "2026-11-01T00:00:00.000Z"
        cases = [
            ("security", "INSERT INTO security_events(event_id,host_id,timestamp_utc,payload_json,received_at_utc) VALUES('ev1','h','%s','{}','%s')" % (now, now)),
            ("encrypted", "INSERT INTO encrypted_security_events(event_id,host_id,timestamp_utc,event_type,metadata_json,envelope_json,received_at_utc) VALUES('en1','h','%s','AUTH_FAILURE','{}','{}','%s')" % (now, now)),
            ("actions", "INSERT INTO response_actions(action_id,device_id,action,source_ip,ttl_seconds,reason,requested_at_utc,expires_at_utc,expires_at_epoch,status,updated_at_utc) VALUES('a1','d','TEMP_BLOCK_IP','203.0.113.9',300,'reason text','%s','%s',1,'PENDING','%s')" % (now, now, now)),
            ("windows", "INSERT INTO windows_response_actions(action_id,target_host_id,action,parameters_json,ttl_seconds,reason,requested_by_device_id,requested_at_utc,expires_at_epoch,status,updated_at_utc) VALUES('w1','win','DISABLE_USER','{}',300,'reason text','d','%s',1,'PENDING','%s')" % (now, now)),
        ]
        for kind, statement in cases:
            self.sql(statement)
            event, data = client.next()
            self.assertEqual((event, data["changed"]), ("state", [kind]), kind)
            self.assertEqual(client.drain(), [], f"{kind}: exactly one notice per change")

    def test_status_change_from_another_process_rings_actions(self):
        """The response worker is a separate process that only UPDATEs the row; the stream must notice."""
        now = "2026-11-01T00:00:00.000Z"
        self.sql("INSERT INTO response_actions(action_id,device_id,action,source_ip,ttl_seconds,reason,requested_at_utc,expires_at_utc,expires_at_epoch,status,updated_at_utc) VALUES('a2','d','TEMP_BLOCK_IP','203.0.113.10',300,'reason text',?,?,1,'PENDING',?)", (now, now, now))
        client = self.open()
        self.assertEqual(client.next()[0], "hello")
        self.sql("UPDATE response_actions SET status='ACTIVE_TEMP_BLOCK', updated_at_utc='2026-11-01T00:00:05.000Z' WHERE action_id='a2'")
        event, data = client.next()
        self.assertEqual((event, data["changed"]), ("state", ["actions"]))

    def test_notice_carries_no_event_content(self):
        client = self.open()
        self.assertEqual(client.next()[0], "hello")
        payload = json.dumps({"source_ip": "198.51.100.77", "actor": "secret-actor-name", "event_id": "f" * 64})
        self.sql("INSERT INTO security_events(event_id,host_id,timestamp_utc,payload_json,received_at_utc) VALUES(?,?,?,?,?)",
                 ("f" * 64, "prod-host-xyz", "2026-11-01T00:00:00.000Z", payload, "2026-11-01T00:00:00.000Z"))
        self.assertEqual(client.next()[0], "state")
        raw = bytes(client.raw)
        for secret in (b"198.51.100.77", b"secret-actor-name", b"prod-host-xyz", b"f" * 64):
            self.assertNotIn(secret, raw)

    def test_idle_stream_sends_heartbeat_pings(self):
        client = self.open()
        self.assertEqual(client.next()[0], "hello")
        self.assertEqual(client.next(skip_ping=False, timeout=2)[0], "ping")
        self.assertEqual(client.next(skip_ping=False, timeout=2)[0], "ping")

    def test_burst_of_changes_is_never_missed(self):
        client = self.open()
        self.assertEqual(client.next()[0], "hello")
        for index in range(30):
            self.sql("INSERT INTO security_events(event_id,host_id,timestamp_utc,payload_json,received_at_utc) VALUES(?,?,?,?,?)",
                     (f"burst{index}", "h", "2026-11-01T00:00:00.000Z", "{}", "2026-11-01T00:00:00.000Z"))
        notices = client.drain(quiet=0.6)
        self.assertGreaterEqual(len(notices), 1)
        self.assertTrue(all(d["changed"] == ["security"] for _e, d in notices))
        # It is fine to coalesce, but the last notice must come after the last write; ringing again proves
        # the stream is still live and level-triggered after the burst.
        self.sql("INSERT INTO security_events(event_id,host_id,timestamp_utc,payload_json,received_at_utc) VALUES('burst-last','h','2026-11-01T00:00:00.000Z','{}','2026-11-01T00:00:00.000Z')")
        self.assertEqual(client.next()[1]["changed"], ["security"])

    # -- lifecycle and limits ---------------------------------------------------------------------------

    def test_revoked_device_is_cut_off_within_one_heartbeat(self):
        identity, token = "dev-revoke-0003", "r" * 64
        self.sql("INSERT INTO member_accounts(device_id,display_name,status,created_at_utc,monitor_token) VALUES(?,?,?,?,?)",
                 (identity, "t", "ACTIVE", "2026-11-01T00:00:00.000Z", token))
        client = self.open((identity, token))
        self.assertEqual(client.status, 200)
        self.assertEqual(client.next()[0], "hello")
        self.sql("UPDATE member_accounts SET status='REVOKED', monitor_token='' WHERE device_id=?", (identity,))
        event, _data = client.next(timeout=2)
        self.assertEqual(event, "revoked")
        self.assertTrue(client.closed.wait(2), "the connection must be closed after revocation")
        # and the token no longer opens a new stream
        again = StreamClient(self.port, identity, token)
        self.clients.append(again)
        self.assertEqual(again.status, 401)

    def test_newest_stream_from_same_device_replaces_the_oldest(self):
        first, second = self.open(), self.open()
        self.assertEqual(first.next()[0], "hello")
        self.assertEqual(second.next()[0], "hello")
        third = self.open()
        self.assertEqual(third.status, 200)
        event, data = first.next(timeout=2)
        self.assertEqual((event, data["reason"]), ("bye", "replaced"))
        self.assertTrue(first.closed.wait(2))
        self.assertFalse(second.closed.is_set())
        self.assertEqual(third.next()[0], "hello")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and self.server.STREAMS.open_count() != 2:
            time.sleep(0.02)
        self.assertEqual(self.server.STREAMS.open_count(), 2)

    def test_global_cap_refuses_other_devices_and_frees_up_on_close(self):
        self.server.STREAM_MAX_TOTAL = 1
        holder = self.open(MONITOR_A)
        self.assertEqual(holder.next()[0], "hello")
        refused = StreamClient(self.port, *MONITOR_B)
        self.clients.append(refused)
        self.assertEqual(refused.status, 503)
        self.assertEqual(json.loads(refused.error_body)["error"], "stream_capacity_reached")
        # the holder is untouched by the refusal
        self.assertFalse(holder.closed.is_set())
        holder.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and self.server.STREAMS.open_count():
            time.sleep(0.05)
        accepted = self.open(MONITOR_B)
        self.assertEqual(accepted.status, 200)

    def test_stream_ends_after_maximum_lifetime(self):
        self.server.STREAM_MAX_LIFETIME_SECONDS = 0.6
        client = self.open()
        self.assertEqual(client.next()[0], "hello")
        event, data = client.next(timeout=3)
        self.assertEqual((event, data["reason"]), ("bye", "lifetime"))
        self.assertTrue(client.closed.wait(2))

    def test_hang_up_is_noticed_at_the_next_wakeup_not_after_a_failed_write(self):
        """After the app hangs up, the first write still succeeds (the kernel only learns on the RST), so
        relying on write errors takes two heartbeats. Checking the peer at each wakeup takes one."""
        self.server.STREAM_HEARTBEAT_SECONDS = 0.8
        client = self.open()
        self.assertEqual(client.next()[0], "hello")
        started = time.monotonic()
        client.close()
        while self.server.STREAMS.open_count() and time.monotonic() - started < 3:
            time.sleep(0.02)
        elapsed = time.monotonic() - started
        self.assertEqual(self.server.STREAMS.open_count(), 0)
        self.assertLess(elapsed, 1.3, f"released after {elapsed:.2f}s; should be ~one heartbeat (0.8s), not two")

    def test_watcher_stops_when_nobody_listens_and_restarts_for_the_next_stream(self):
        hub = self.server.STREAM_HUB
        first = self.open()
        self.assertEqual(first.next()[0], "hello")
        self.assertIsNotNone(hub._thread)
        first.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and hub._thread is not None:
            time.sleep(0.05)
        self.assertIsNone(hub._thread, "no idle database polling when nobody is connected")
        second = self.open()
        self.assertEqual(second.next()[0], "hello")
        self.sql("INSERT INTO security_events(event_id,host_id,timestamp_utc,payload_json,received_at_utc) VALUES('after-restart','h','2026-11-01T00:00:00.000Z','{}','2026-11-01T00:00:00.000Z')")
        self.assertEqual(second.next()[1]["changed"], ["security"])


class ChangeHubUnitTests(unittest.TestCase):
    """Deterministic hub behaviour with an injected reader (no sockets)."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {"KAWAL_API_DB_PATH": str(Path(cls.temp.name) / "hub.sqlite3")})
        cls.env.start()
        cls.server = load_server()

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.temp.cleanup()

    def setUp(self):
        self.server.STREAM_WATCH_SECONDS = 0.02

    def test_reader_failure_does_not_kill_the_watcher(self):
        state = {"heads": {k: "0" for k in self.server.STREAM_KINDS}, "fail": 3}

        def reader():
            if state["fail"] > 0:
                state["fail"] -= 1
                raise RuntimeError("database is locked")
            return dict(state["heads"])

        hub = self.server.ChangeHub(reader)
        ticket = self.server.StreamTicket("x")
        seen = hub.subscribe()
        try:
            time.sleep(0.2)  # the failures happen first
            self.assertTrue(hub._thread.is_alive())
            state["heads"]["encrypted"] = "5"
            version, changed = hub.wait(seen, 2.0, ticket)
            self.assertEqual(changed, ("encrypted",))
            self.assertGreater(version, seen)
        finally:
            hub.unsubscribe()

    def test_a_change_between_subscribing_and_the_first_poll_is_still_signalled(self):
        """Regression: the watcher used to take its baseline on its OWN first poll. A write landing after the app got
        'hello' but before that first poll became part of the baseline and was never announced (found as a test that
        failed only when the machine was busy). The baseline must be taken before subscribe() returns."""
        heads = {k: "0" for k in self.server.STREAM_KINDS}
        release = threading.Event()
        main = threading.main_thread()

        def reader():
            if threading.current_thread() is not main:
                release.wait(5)          # hold the watcher thread back, as a busy machine would
            return dict(heads)

        hub = self.server.ChangeHub(reader)
        ticket = self.server.StreamTicket("x")
        seen = hub.subscribe()           # == the moment 'hello' is sent
        try:
            heads["actions"] = "9:x"     # the write that must not be lost
            release.set()                # now let the watcher do its first poll
            version, changed = hub.wait(seen, 3.0, ticket)
            self.assertEqual(changed, ("actions",))
            self.assertGreater(version, seen)
        finally:
            release.set()
            hub.unsubscribe()

    def test_a_failing_first_read_still_ends_in_a_working_watcher(self):
        heads = {k: "0" for k in self.server.STREAM_KINDS}
        calls = {"n": 0}

        def reader():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("database is locked")      # the baseline read made by subscribe()
            return dict(heads)

        hub = self.server.ChangeHub(reader)
        ticket = self.server.StreamTicket("x")
        seen = hub.subscribe()
        try:
            time.sleep(0.15)             # watcher takes its baseline from the next successful read
            heads["security"] = "4"
            self.assertEqual(hub.wait(seen, 3.0, ticket)[1], ("security",))
        finally:
            hub.unsubscribe()

    def test_wait_times_out_quietly_and_unchanged_kinds_stay_quiet(self):
        heads = {k: "0" for k in self.server.STREAM_KINDS}
        hub = self.server.ChangeHub(lambda: dict(heads))
        ticket = self.server.StreamTicket("x")
        seen = hub.subscribe()
        try:
            started = time.monotonic()
            version, changed = hub.wait(seen, 0.15, ticket)
            self.assertEqual((version, changed), (seen, ()))
            self.assertGreaterEqual(time.monotonic() - started, 0.12)
            heads["actions"] = "1:x"
            version, changed = hub.wait(seen, 2.0, ticket)
            self.assertEqual(changed, ("actions",))
            # a subscriber that already saw that version is not told again
            self.assertEqual(hub.wait(version, 0.1, ticket)[1], ())
        finally:
            hub.unsubscribe()

    def test_eviction_wakes_a_waiting_stream_immediately(self):
        hub = self.server.ChangeHub(lambda: {k: "0" for k in self.server.STREAM_KINDS})
        registry = self.server.StreamRegistry(hub)
        self.server.STREAM_MAX_PER_IDENTITY = 1
        old = registry.admit("dev")
        seen = hub.subscribe()
        woke = []

        def waiter():
            started = time.monotonic()
            hub.wait(seen, 5.0, old)
            woke.append(time.monotonic() - started)

        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.1)
        new = registry.admit("dev")
        thread.join(2)
        hub.unsubscribe()
        self.assertTrue(old.stop)
        self.assertFalse(new.stop)
        self.assertTrue(woke and woke[0] < 1.5, woke)

    def test_registry_caps_other_devices_without_evicting_anyone(self):
        hub = self.server.ChangeHub(lambda: {k: "0" for k in self.server.STREAM_KINDS})
        registry = self.server.StreamRegistry(hub)
        self.server.STREAM_MAX_TOTAL = 2
        self.server.STREAM_MAX_PER_IDENTITY = 2
        a = registry.admit("a")
        b = registry.admit("b")
        self.assertIsNone(registry.admit("c"))
        self.assertFalse(a.stop or b.stop)
        registry.release(a)
        self.assertIsNotNone(registry.admit("c"))


if __name__ == "__main__":
    unittest.main()
