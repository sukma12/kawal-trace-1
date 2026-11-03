"""Client side of the real-time doorbell: parser, strict interpretation, one connection, reconnect policy,
burst coalescing, and an end-to-end run against the real optional server API."""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from chainlog import live_stream as ls
from chainlog.sync import SyncConfigError, SyncSettings

TOKEN = "t" * 48
DEVICE = "dev-stream-0001"
ROOT = Path(__file__).resolve().parents[1]


def msg(event: str, data: dict | None = None) -> bytes:
    body = json.dumps({"v": 1, **(data or {})}, separators=(",", ":"))
    return f"id: 1\nevent: {event}\ndata: {body}\n\n".encode()


class ScriptedServer:
    """Loopback HTTP server whose response to GET /api/v1/stream is a per-test script."""

    def __init__(self, script):
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                       "method": "GET"})
                try:
                    script(self)
                except (BrokenPipeError, ConnectionError, OSError):
                    pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

    @property
    def settings(self) -> SyncSettings:
        return SyncSettings(base_url=f"http://127.0.0.1:{self.port}", device_id=DEVICE)

    def client(self, **kw) -> ls.LiveStreamClient:
        return ls.LiveStreamClient(self.settings, TOKEN, **kw)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def stream_headers(handler, status=200, content_type="text/event-stream; charset=utf-8", extra=()):
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    for key, value in extra:
        handler.send_header(key, value)
    handler.end_headers()


class ParserTests(unittest.TestCase):
    WIRE = (b": ping\n\nretry: 3000\n\n"
            b"id: 7\nevent: state\ndata: {\"v\":1,\"changed\":[\"security\"]}\n\n"
            b"event: hello\r\ndata: {\"v\":1}\r\n\r\n")

    def parse(self, wire: bytes, chunk: int):
        chunks = [wire[i:i + chunk] for i in range(0, len(wire), chunk)]
        return list(ls.parse_sse(ls.iter_lines_bounded(chunks)))

    def test_result_does_not_depend_on_how_the_bytes_are_chunked(self):
        expected = self.parse(self.WIRE, len(self.WIRE))
        self.assertEqual([m.event for m in expected], ["state", "hello"])
        self.assertEqual(expected[0].id, "7")
        for size in (1, 2, 3, 5, 7, 13, 64):
            self.assertEqual(self.parse(self.WIRE, size), expected, size)

    def test_multiline_data_comments_and_unknown_fields(self):
        wire = b": comment\nfoo: bar\nevent: x\ndata: a\ndata: b\n\n\n\ndata: only\n\n"
        messages = list(ls.parse_sse(ls.iter_lines_bounded([wire])))
        self.assertEqual([(m.event, m.data) for m in messages], [("x", "a\nb"), ("message", "only")])

    def test_overlong_line_is_refused_before_it_is_buffered(self):
        with self.assertRaises(ls.StreamProtocolError):
            list(ls.iter_lines_bounded([b"data: " + b"a" * (ls.MAX_LINE_BYTES + 10)]))   # no newline at all
        with self.assertRaises(ls.StreamProtocolError):
            list(ls.iter_lines_bounded([b"data: " + b"a" * (ls.MAX_LINE_BYTES + 10) + b"\n"]))

    def test_overlong_message_is_refused(self):
        line = "data: " + "a" * 1000
        with self.assertRaises(ls.StreamProtocolError):
            list(ls.parse_sse([line] * 6))

    def test_invalid_utf8_is_refused(self):
        with self.assertRaises(ls.StreamProtocolError):
            list(ls.iter_lines_bounded([b"data: \xff\xfe\n"]))


class InterpretTests(unittest.TestCase):
    def sig(self, event, body):
        return ls.interpret(ls.SSEMessage(event, body if isinstance(body, str) else json.dumps(body), ""))

    def test_hello_means_catch_up_on_everything(self):
        signal = self.sig("hello", {"v": 1, "heartbeat_seconds": 15})
        self.assertEqual((signal.kind, signal.changed, signal.heartbeat_seconds), ("hello", ls.ALL_KINDS, 15.0))

    def test_hello_heartbeat_is_validated(self):
        for bad in (True, -1, 0, 9999, "15", None):
            self.assertIsNone(self.sig("hello", {"v": 1, "heartbeat_seconds": bad}).heartbeat_seconds, bad)

    def test_state_keeps_only_known_kinds(self):
        signal = self.sig("state", {"v": 1, "changed": ["security", "bogus", 5, None, "actions"]})
        self.assertEqual(signal.changed, frozenset({"security", "actions"}))

    def test_state_with_nothing_usable_is_ignored(self):
        for body in ({"v": 1, "changed": []}, {"v": 1, "changed": ["bogus"]}, {"v": 1, "changed": "security"}, {"v": 1}):
            self.assertIsNone(self.sig("state", body), body)

    def test_unknown_version_event_json_and_shapes_are_ignored(self):
        self.assertIsNone(self.sig("state", {"v": 2, "changed": ["security"]}))
        self.assertIsNone(self.sig("state", {"changed": ["security"]}))
        self.assertIsNone(self.sig("state", "not json"))
        self.assertIsNone(self.sig("state", "[1,2]"))
        self.assertIsNone(self.sig("message", {"v": 1, "changed": ["security"]}))
        self.assertIsNone(self.sig("execute", {"v": 1}))

    def test_bye_and_revoked(self):
        self.assertEqual(self.sig("bye", {"v": 1, "reason": "lifetime"}).reason, "lifetime")
        self.assertEqual(self.sig("bye", {"v": 1, "reason": "<script>"}).reason, "unknown")
        self.assertEqual(self.sig("revoked", {"v": 1}).kind, "revoked")


class ClientConnectionTests(unittest.TestCase):
    def setUp(self):
        self.servers: list[ScriptedServer] = []

    def tearDown(self):
        for server in self.servers:
            server.close()

    def serve(self, script) -> ScriptedServer:
        server = ScriptedServer(script)
        self.servers.append(server)
        return server

    def run_client(self, server, **kw):
        signals: list[ls.StreamSignal] = []
        reason = server.client(**kw).run_once(signals.append, threading.Event())
        return reason, signals

    def test_happy_path_is_a_bodyless_authenticated_get(self):
        def script(h):
            stream_headers(h)
            h.wfile.write(msg("hello", {"heartbeat_seconds": 15}) + msg("state", {"changed": ["security", "actions"]})
                          + msg("bye", {"reason": "lifetime"}))
        server = self.serve(script)
        reason, signals = self.run_client(server)
        self.assertEqual(reason, "bye:lifetime")
        self.assertEqual([s.kind for s in signals], ["hello", "state", "bye"])
        self.assertEqual(signals[1].changed, frozenset({"security", "actions"}))
        request = server.requests[0]
        self.assertEqual(request["path"], "/api/v1/stream")
        headers = request["headers"]
        self.assertEqual(headers["authorization"], f"Bearer {TOKEN}")
        self.assertEqual(headers["x-kawal-device-id"], DEVICE)
        self.assertEqual(headers["accept"], "text/event-stream")
        self.assertEqual(headers["accept-encoding"], "identity")
        self.assertNotIn("content-length", headers)      # nothing from this device is uploaded
        self.assertNotIn("content-type", headers)

    def test_one_byte_at_a_time_still_parses(self):
        def script(h):
            stream_headers(h)
            for byte in msg("hello") + msg("state", {"changed": ["windows"]}):
                h.wfile.write(bytes([byte]))
                h.wfile.flush()
        reason, signals = self.run_client(self.serve(script))
        self.assertEqual([s.kind for s in signals], ["hello", "state"])
        self.assertEqual(reason, "closed")

    def test_unknown_and_malformed_messages_are_skipped_not_fatal(self):
        def script(h):
            stream_headers(h)
            h.wfile.write(b"event: state\ndata: {oops\n\n" + msg("state", {"changed": ["bogus"]})
                          + b"event: execute\ndata: {\"v\":1}\n\n" + msg("state", {"changed": ["encrypted"]}))
        _reason, signals = self.run_client(self.serve(script))
        self.assertEqual([s.changed for s in signals], [frozenset({"encrypted"})])

    def test_auth_refusals_are_not_retryable(self):
        for status in (401, 403):
            server = self.serve(lambda h, status=status: (stream_headers(h, status, "application/json"), h.wfile.write(b"{}")))
            with self.assertRaises(ls.StreamAuthError):
                self.run_client(server)

    def test_old_servers_without_the_endpoint_are_reported_as_unsupported(self):
        for status in (404, 405, 501):
            server = self.serve(lambda h, status=status: (stream_headers(h, status, "application/json"), h.wfile.write(b"{}")))
            with self.assertRaises(ls.StreamUnsupportedError):
                self.run_client(server)

    def test_capacity_and_server_errors_are_retryable_not_fatal(self):
        for status in (429, 500, 502, 503, 530):
            server = self.serve(lambda h, status=status: (stream_headers(h, status, "application/json"), h.wfile.write(b"{}")))
            with self.assertRaises(ls.LiveStreamError) as raised:
                self.run_client(server)
            self.assertNotIsInstance(raised.exception, (ls.StreamAuthError, ls.StreamUnsupportedError), status)

    def test_redirects_are_not_followed(self):
        target = self.serve(lambda h: (stream_headers(h), h.wfile.write(msg("hello"))))
        redirecting = self.serve(lambda h: (stream_headers(h, 302, "text/plain", [("Location", f"http://127.0.0.1:{target.port}/x")]),))
        with self.assertRaises(ls.LiveStreamError):
            self.run_client(redirecting)
        self.assertEqual(target.requests, [], "the token must never be replayed to a redirect target")

    def test_a_captive_portal_page_is_not_mistaken_for_a_stream(self):
        server = self.serve(lambda h: (stream_headers(h, 200, "text/html"), h.wfile.write(b"<html>login</html>")))
        with self.assertRaises(ls.StreamProtocolError):
            self.run_client(server)

    def test_oversized_line_closes_the_connection_with_a_protocol_error(self):
        def script(h):
            stream_headers(h)
            h.wfile.write(msg("hello") + b"data: " + b"x" * 50_000)
        with self.assertRaises(ls.StreamProtocolError):
            self.run_client(self.serve(script))

    def test_revoked_message_is_a_fatal_auth_error(self):
        server = self.serve(lambda h: (stream_headers(h), h.wfile.write(msg("hello") + msg("revoked"))))
        with self.assertRaises(ls.StreamAuthError):
            self.run_client(server)

    def test_silent_server_is_detected_by_the_read_timeout(self):
        release = threading.Event()

        def script(h):
            stream_headers(h)
            h.wfile.write(msg("hello"))
            h.wfile.flush()
            release.wait(10)
        server = self.serve(script)
        client = server.client()
        client.read_timeout = 0.4          # the constructor floors it at 5 s; shorten only for the test
        started = time.monotonic()
        try:
            with self.assertRaises(ls.LiveStreamError):
                client.run_once(lambda _s: None, threading.Event())
        finally:
            release.set()
        self.assertLess(time.monotonic() - started, 3)

    def test_stop_flag_ends_the_connection_at_the_next_message(self):
        stop = threading.Event()

        def script(h):
            stream_headers(h)
            h.wfile.write(msg("hello"))
            h.wfile.flush()
            time.sleep(0.2)
            h.wfile.write(msg("state", {"changed": ["security"]}))

        server = self.serve(script)
        seen: list[str] = []

        def on_signal(signal):
            seen.append(signal.kind)
            stop.set()
        reason = server.client().run_once(on_signal, stop)
        self.assertEqual(reason, "stopped")
        self.assertEqual(seen, ["hello"], "no signal may be delivered after stop")

    def test_plaintext_to_a_real_hostname_is_refused_at_setup(self):
        with self.assertRaises(ls.StreamAuthError) as raised:
            ls.LiveStreamClient(SyncSettings(base_url="http://example.org", device_id=DEVICE), TOKEN)
        self.assertIsInstance(raised.exception.__cause__, SyncConfigError)

    def test_bad_tokens_are_refused_before_any_request(self):
        settings = SyncSettings(base_url="https://example.org", device_id=DEVICE)
        for token in ("", "short", "has space " + "x" * 30):
            with self.assertRaises(ls.StreamAuthError):
                ls.LiveStreamClient(settings, token)

    def test_url_is_the_stream_endpoint_on_the_configured_server(self):
        client = ls.LiveStreamClient(SyncSettings(base_url="https://monitor.example.org/", device_id=DEVICE), TOKEN)
        self.assertEqual(client.url, "https://monitor.example.org/api/v1/stream")


class FakeClient:
    """Scripted stand-in for LiveStreamClient: each run_once pops one outcome."""

    def __init__(self, outcomes, clock=None, advance=0.0):
        self.outcomes = outcomes
        self.clock = clock
        self.advance = advance
        self.closed = False

    def run_once(self, on_signal, stop):
        outcome = self.outcomes.pop(0)
        if self.clock is not None:
            self.clock.now += self.advance
        if callable(outcome):
            return outcome(on_signal, stop)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def close(self):
        self.closed = True


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class SupervisorTests(unittest.TestCase):
    def build(self, outcomes, *, advance=0.0, stop_after=None):
        self.clock = Clock()
        self.pauses: list[float] = []
        self.states: list[tuple[str, str]] = []
        self.signals: list[frozenset[str]] = []
        self.factory_calls = 0
        done = threading.Event()
        self.done = done
        holder = {}

        def wait(pause):
            self.pauses.append(round(pause, 3))
            if stop_after is not None and len(self.pauses) >= stop_after:
                holder["sup"]._stop.set()
                done.set()
            return holder["sup"]._stop.is_set()

        def factory():
            self.factory_calls += 1
            return FakeClient(outcomes, self.clock, advance)

        sup = ls.LiveStreamSupervisor(factory, self.signals.append, lambda s, d: self.states.append((s, d)),
                                      clock=self.clock, rng=lambda: 0.0, wait=wait)
        holder["sup"] = sup
        return sup

    def drive(self, sup):
        sup._run()   # synchronous: the loop is the unit under test, threading is covered separately

    def test_failures_back_off_exponentially_and_stop_when_told(self):
        sup = self.build([ls.LiveStreamError("boom")] * 6, stop_after=6)
        self.drive(sup)
        # rng=0 -> half of the ceiling (1, 2, 4, 8, 16, 32 s); the 60 s cap itself is covered by BackoffTests
        self.assertEqual(self.pauses, [0.5, 1.0, 2.0, 4.0, 8.0, 16.0])
        self.assertEqual(self.states[0][0], ls.STATE_CONNECTING)
        self.assertTrue(all(s == ls.STATE_RETRYING for s, _d in self.states[1:] if s != ls.STATE_CONNECTING))

    def test_a_connection_that_lasted_resets_the_backoff(self):
        sup = self.build([ls.LiveStreamError("x"), ls.LiveStreamError("x"), "closed", ls.LiveStreamError("x")], stop_after=4)
        # advance the fake clock only during the third run (the one that "lasted")
        original = FakeClient.run_once

        def run_once(client, on_signal, stop):
            if not client.outcomes[0:1] or client.outcomes[0] == "closed":
                self.clock.now += 25.0
            return original(client, on_signal, stop)
        with mock.patch.object(FakeClient, "run_once", run_once):
            self.drive(sup)
        self.assertEqual(self.pauses[0:2], [0.5, 1.0])
        self.assertEqual(self.pauses[2], 0.5, "after a stable connection the delay starts over")

    def test_flapping_connections_do_not_reset_the_backoff(self):
        sup = self.build(["closed"] * 4, advance=1.0, stop_after=4)   # each connection lasts only 1 s
        self.drive(sup)
        self.assertEqual(self.pauses, [0.5, 1.0, 2.0, 4.0])

    def test_auth_refusal_stops_for_good(self):
        sup = self.build([ls.StreamAuthError("ditolak")])
        self.drive(sup)
        self.assertEqual(self.factory_calls, 1)
        self.assertEqual(self.states[-1], (ls.STATE_UNAUTHORIZED, "ditolak"))
        self.assertEqual(self.pauses, [])

    def test_unsupported_server_stops_and_reports_it(self):
        sup = self.build([ls.StreamUnsupportedError("lama")])
        self.drive(sup)
        self.assertEqual(self.factory_calls, 1)
        self.assertEqual(self.states[-1][0], ls.STATE_UNSUPPORTED)

    def test_configuration_errors_from_the_factory_are_fatal_not_retried_forever(self):
        calls = []

        def factory():
            calls.append(1)
            raise ls.StreamAuthError("token kosong")
        states = []
        sup = ls.LiveStreamSupervisor(factory, lambda k: None, lambda s, d: states.append(s), wait=lambda p: False)
        sup._run()
        self.assertEqual((len(calls), states[-1]), (1, ls.STATE_UNAUTHORIZED))

    def test_replaced_by_another_instance_waits_long_and_lifetime_rotation_reconnects_fast(self):
        sup = self.build(["bye:replaced", "bye:lifetime"], stop_after=2)
        self.drive(sup)
        self.assertEqual(self.pauses[0], 30.0)
        self.assertLess(self.pauses[1], 2.0)

    def test_unexpected_exceptions_never_kill_the_loop(self):
        sup = self.build([ValueError("surprise"), RuntimeError("again"), "closed"], stop_after=3)
        self.drive(sup)
        self.assertEqual(self.factory_calls, 3)
        self.assertIn(ls.STATE_RETRYING, [s for s, _d in self.states])

    def test_hello_marks_live_and_requests_a_full_catch_up_then_state_passes_kinds_through(self):
        def outcome(on_signal, stop):
            on_signal(ls.StreamSignal("hello", ls.ALL_KINDS))
            on_signal(ls.StreamSignal("state", frozenset({"actions"})))
            return "closed"
        sup = self.build([outcome], stop_after=1)
        self.drive(sup)
        self.assertIn(ls.STATE_LIVE, [s for s, _d in self.states])
        self.assertEqual(self.signals, [ls.ALL_KINDS, frozenset({"actions"})])

    def test_callback_exceptions_do_not_break_the_stream(self):
        def outcome(on_signal, stop):
            on_signal(ls.StreamSignal("state", frozenset({"security"})))
            on_signal(ls.StreamSignal("state", frozenset({"actions"})))
            return "closed"
        sup = self.build([outcome], stop_after=1)
        seen = []

        def boom(kinds):
            seen.append(kinds)
            raise RuntimeError("UI exploded")
        sup._on_signal = boom
        sup._on_status = lambda s, d: (_ for _ in ()).throw(RuntimeError("status exploded"))
        self.drive(sup)
        self.assertEqual(len(seen), 2)

    def test_nothing_is_delivered_after_stop(self):
        sup = self.build([lambda on_signal, stop: (sup._stop.set(), on_signal(ls.StreamSignal("state", frozenset({"security"}))), "closed")[-1]])
        self.drive(sup)
        self.assertEqual(self.signals, [])

    def test_real_thread_start_stop_and_restart(self):
        started = threading.Event()
        release = threading.Event()

        class Blocking:
            def run_once(self, on_signal, stop):
                on_signal(ls.StreamSignal("hello", ls.ALL_KINDS))
                started.set()
                release.wait(5)
                return "stopped"

            def close(self):
                release.set()
        states = []
        sup = ls.LiveStreamSupervisor(Blocking, lambda k: None, lambda s, d: states.append(s))
        sup.start()
        self.assertTrue(started.wait(2))
        self.assertEqual(sup.state, ls.STATE_LIVE)
        sup.stop()
        sup.join(2)
        self.assertFalse(sup._thread.is_alive())
        self.assertEqual(sup.state, ls.STATE_STOPPED)
        self.assertTrue(sup._thread.daemon, "must not delay application exit")


class BackoffTests(unittest.TestCase):
    def test_bounds_and_jitter(self):
        for attempt in range(0, 12):
            low = ls.backoff_delay(attempt, rng=lambda: 0.0)
            high = ls.backoff_delay(attempt, rng=lambda: 1.0)
            ceiling = min(60.0, 2 ** attempt)
            self.assertEqual((low, high), (ceiling / 2, ceiling), attempt)
        self.assertEqual(ls.backoff_delay(500, rng=lambda: 1.0), 60.0)


class CoalescerTests(unittest.TestCase):
    def test_burst_becomes_one_take_with_every_kind(self):
        clock = Clock()
        c = ls.DoorbellCoalescer(1.0, clock)
        for _ in range(100):
            c.ring({"security"})
        c.ring(["actions", "bogus"])
        taken = c.take()
        self.assertEqual(taken, ls.Take(frozenset({"security", "actions"}), None))
        self.assertEqual(c.take(), ls.Take(frozenset(), None))

    def test_rings_inside_the_interval_wait_and_then_accumulate(self):
        clock = Clock()
        c = ls.DoorbellCoalescer(1.0, clock)
        c.ring({"security"})
        self.assertEqual(c.take().kinds, frozenset({"security"}))
        clock.now += 0.3
        c.ring({"windows"})
        early = c.take()
        self.assertEqual(early.kinds, frozenset())
        self.assertAlmostEqual(early.retry_after, 0.7, places=6)
        c.ring({"encrypted"})
        clock.now += 0.7
        self.assertEqual(c.take().kinds, frozenset({"windows", "encrypted"}))

    def test_nothing_pending_means_nothing_to_wait_for(self):
        self.assertEqual(ls.DoorbellCoalescer(1.0, Clock()).take(), ls.Take(frozenset(), None))

    def test_concurrent_rings_lose_nothing(self):
        c = ls.DoorbellCoalescer(0.0)
        kinds = sorted(ls.ALL_KINDS)

        def worker(kind):
            for _ in range(500):
                c.ring({kind})
        threads = [threading.Thread(target=worker, args=(k,)) for k in kinds]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(c.take().kinds, ls.ALL_KINDS)

    def test_interval_is_bounded(self):
        with self.assertRaises(ValueError):
            ls.DoorbellCoalescer(-1)
        with self.assertRaises(ValueError):
            ls.DoorbellCoalescer(61)


class PolicyAndHonestyTests(unittest.TestCase):
    def test_polling_is_rare_only_while_the_stream_is_actually_live(self):
        self.assertEqual(ls.poll_interval_seconds(ls.STATE_LIVE), 30.0)
        for state in (ls.STATE_CONNECTING, ls.STATE_RETRYING):
            self.assertEqual(ls.poll_interval_seconds(state), 10.0)
        for state in (ls.STATE_UNSUPPORTED, ls.STATE_UNAUTHORIZED, ls.STATE_STOPPED, "anything-else"):
            self.assertEqual(ls.poll_interval_seconds(state), 5.0)

    def test_real_time_is_claimed_only_when_connected(self):
        for state in (ls.STATE_CONNECTING, ls.STATE_RETRYING, ls.STATE_UNSUPPORTED, ls.STATE_UNAUTHORIZED, ls.STATE_STOPPED):
            text = ls.status_text(state, "detail")
            self.assertNotIn("REAL-TIME AKTIF", text, state)
            self.assertIn("polling" if state != ls.STATE_UNAUTHORIZED else "token", text, state)
        self.assertIn("REAL-TIME AKTIF", ls.status_text(ls.STATE_LIVE))

    def test_status_text_truncates_untrusted_detail(self):
        self.assertLess(len(ls.status_text(ls.STATE_RETRYING, "x" * 5000)), 200)


def load_real_server(db_path: str):
    spec = importlib.util.spec_from_file_location("kawal_real_server_for_client_e2e", ROOT / "optional-server-api" / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EndToEndAgainstRealServerTests(unittest.TestCase):
    """The client and the real server module must agree on the wire format."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {
            "KAWAL_API_DB_PATH": str(Path(cls.temp.name) / "e2e.sqlite3"),
            "KAWAL_MONITOR_TOKENS": f"{DEVICE}|{TOKEN}",
        })
        cls.env.start()
        cls.server = load_real_server(cls.temp.name)
        cls.server.init_db()
        cls.server.STREAM_HEARTBEAT_SECONDS = 0.3
        cls.server.STREAM_WATCH_SECONDS = 0.04
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), cls.server.APIHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.settings = SyncSettings(base_url=f"http://127.0.0.1:{cls.httpd.server_address[1]}", device_id=DEVICE)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.env.stop()
        cls.temp.cleanup()

    def wait_for(self, predicate, timeout=4.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.03)
        return False

    def test_live_signal_arrives_within_a_second_and_revocation_ends_it(self):
        rung: list[frozenset[str]] = []
        states: list[str] = []
        sup = ls.LiveStreamSupervisor(lambda: ls.LiveStreamClient(self.settings, TOKEN), rung.append,
                                      lambda s, d: states.append(s))
        sup.start()
        try:
            self.assertTrue(self.wait_for(lambda: ls.STATE_LIVE in states), states)
            self.assertEqual(rung[0], ls.ALL_KINDS, "hello triggers a full catch-up")
            before = len(rung)
            started = time.monotonic()
            with self.server.DB_LOCK, self.server.db_session() as conn:
                conn.execute("INSERT INTO security_events(event_id,host_id,timestamp_utc,payload_json,received_at_utc) VALUES('e2e1','h','2026-11-01T00:00:00.000Z','{}','2026-11-01T00:00:00.000Z')")
            self.assertTrue(self.wait_for(lambda: len(rung) > before))
            self.assertEqual(rung[before], frozenset({"security"}))
            self.assertLess(time.monotonic() - started, 1.5)
            # Revoke: the same device id gets a REVOKED tombstone, exactly as the admin DELETE does.
            with self.server.DB_LOCK, self.server.db_session() as conn:
                conn.execute("INSERT INTO member_accounts(device_id,display_name,status,created_at_utc,revoked_at_utc) VALUES(?,?,?,?,?)",
                             (DEVICE, "revoked", "REVOKED", "2026-11-01T00:00:00.000Z", "2026-11-01T00:00:00.000Z"))
            self.assertTrue(self.wait_for(lambda: sup.state == ls.STATE_UNAUTHORIZED), sup.state)
        finally:
            sup.stop()
            sup.join(3)
            with self.server.DB_LOCK, self.server.db_session() as conn:
                conn.execute("DELETE FROM member_accounts WHERE device_id=?", (DEVICE,))


if __name__ == "__main__":
    unittest.main()
