"""Abuse limits and response hardening of the optional server API (private module copy, real HTTP on loopback)."""
from __future__ import annotations

import http.client
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

SERVER_PATH = Path(__file__).resolve().parents[1] / "server.py"
DEVICE, MONITOR = "dev-harden-0001", "m" * 64
OTHER, OTHER_RESPONSE = "dev-harden-0002", "q" * 64
RESPONSE = "r" * 64
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
OTHER_SECRET = "KRSXG5CTMVRXEZLU"
ATTACKER_IP, BYSTANDER_IP = "198.51.100.7", "203.0.113.9"


def load_server():
    spec = importlib.util.spec_from_file_location("kawal_hardening_server_under_test", SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecordingServer(ThreadingHTTPServer):
    """Remembers handler crashes: socketserver otherwise only prints them, and the client just sees an empty reply."""

    def __init__(self, *args, **kwargs):
        self.crashes = []
        super().__init__(*args, **kwargs)

    def handle_error(self, request, client_address):
        import traceback
        self.crashes.append(traceback.format_exc())


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class HardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {
            "KAWAL_API_DB_PATH": str(Path(cls.temp.name) / "harden.sqlite3"),
            "KAWAL_MONITOR_TOKENS": f"{DEVICE}|{MONITOR}",
            "KAWAL_RESPONSE_TOKENS": f"{DEVICE}|{RESPONSE};{OTHER}|{OTHER_RESPONSE}",
            "KAWAL_RESPONSE_TOTP_SECRETS": f"{DEVICE}|{TOTP_SECRET};{OTHER}|{OTHER_SECRET}",
            "KAWAL_RESPONSE_ACTIONS_ENABLED": "false",
            "KAWAL_TRUST_CF_CONNECTING_IP": "true",
        })
        cls.env.start()
        cls.server = load_server()
        cls.server.init_db()
        cls.httpd = RecordingServer(("127.0.0.1", 0), cls.server.APIHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.env.stop()
        cls.temp.cleanup()

    def setUp(self):
        s = self.server
        s.AUTH_FAIL_LIMIT, s.AUTH_FAIL_LOOPBACK_FACTOR, s.TOTP_FAIL_LIMIT = 10, 20, 5
        s.AUTH_FAILURES = s.SlidingWindowCounter(60.0)
        s.TOTP_FAILURES = s.SlidingWindowCounter(300.0)
        s.ENROLLMENT_ATTEMPTS = s.SlidingWindowCounter(3600.0)

    def call(self, method, path, *, token=None, identity=DEVICE, client_ip=None, body=None, extra=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if identity:
            headers["X-KAWAL-Device-ID"] = identity
        if client_ip:
            headers["CF-Connecting-IP"] = client_ip
        headers.update(extra or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        result = (response.status, {k.lower(): v for k, v in response.getheaders()}, json.loads(raw) if raw else {})
        conn.close()
        return result

    # -- response headers -------------------------------------------------------------------------------

    def assert_hardened(self, headers):
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertIn("default-src 'none'", headers["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertEqual(headers["referrer-policy"], "no-referrer")
        self.assertEqual(headers["cross-origin-resource-policy"], "same-origin")
        self.assertIn("max-age=", headers["strict-transport-security"])

    def test_every_kind_of_json_response_carries_the_security_headers(self):
        for status, headers, _body in (self.call("GET", "/healthz"),                              # 401
                                       self.call("GET", "/healthz", token=MONITOR),               # 200
                                       self.call("GET", "/no/such/route", token=MONITOR),         # 404
                                       self.call("PUT", "/healthz")):                             # 405
            self.assert_hardened(headers)
            self.assertEqual(headers["cache-control"], "no-store")

    def raw(self, data: bytes) -> bytes:
        import socket
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            out = b""
            try:
                sock.sendall(data)
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        return out
                    out += chunk
            except ConnectionResetError:
                # the server may close while we are still sending an oversized request; keep what already arrived
                return out

    def parse_raw(self, data: bytes):
        head, _, payload = self.raw(data).partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        self.assertTrue(lines[0].startswith("HTTP/1."), f"no HTTP answer at all: {lines[0]!r}")
        headers = {k.lower(): v for k, _, v in (line.partition(": ") for line in lines[1:])}
        return int(lines[0].split()[1]), headers, payload

    def test_requests_the_parser_rejects_get_the_same_bare_json_and_headers(self):
        cases = {
            "garbage request line": (b"GARBAGE\r\n\r\n", 400),
            "unsupported version": (b"GET / HTTP/9.9\r\nHost: x\r\n\r\n", 505),
            "oversized request line": (b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\nHost: x\r\n\r\n", 414),
            "verb the server does not implement": (b"OPTIONS / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 501),
        }
        for label, (data, expected) in cases.items():
            status, headers, payload = self.parse_raw(data)
            self.assertEqual(status, expected, label)
            self.assertEqual(headers["content-type"], "application/json; charset=utf-8", label)
            self.assert_hardened(headers)
            self.assertEqual(json.loads(payload), {"error": "http_error", "status": expected}, label)
            self.assertNotIn(b"<html", payload.lower(), label)
        self.assertEqual(self.httpd.crashes, [], "a rejected request must never crash the handler")

    def test_a_rejected_head_request_carries_no_body(self):
        status, headers, payload = self.parse_raw(b"HEAD /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertEqual((status, payload), (501, b""))
        self.assert_hardened(headers)

    def test_the_banner_names_no_version(self):
        status, headers, _ = self.parse_raw(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        self.assertEqual(status, 401)
        self.assertTrue(headers["server"].startswith("Kawal-Trace-API"))
        self.assertNotRegex(headers["server"], r"\d")
        self.assertNotIn("Python", headers["server"])

    def test_the_event_stream_carries_them_too(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/api/v1/stream", headers={"Authorization": f"Bearer {MONITOR}", "X-KAWAL-Device-ID": DEVICE})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assert_hardened({k.lower(): v for k, v in response.getheaders()})
        conn.close()

    # -- per-client failure limit -----------------------------------------------------------------------

    def test_a_client_that_keeps_failing_is_throttled_but_other_clients_are_not(self):
        for attempt in range(10):
            status, _h, _b = self.call("GET", "/healthz", token="x" * 64, client_ip=ATTACKER_IP)
            self.assertEqual(status, 401, attempt)
        status, headers, body = self.call("GET", "/healthz", token="x" * 64, client_ip=ATTACKER_IP)
        self.assertEqual(status, 429)
        self.assertEqual(body["error"], "too_many_failed_attempts")
        self.assertGreaterEqual(int(headers["retry-after"]), 1)
        self.assertLessEqual(int(headers["retry-after"]), 61)
        self.assertEqual(body["retry_after_seconds"], int(headers["retry-after"]))
        self.assert_hardened(headers)
        # the throttle is on the address, not the account: the right token from that address waits too...
        self.assertEqual(self.call("GET", "/healthz", token=MONITOR, client_ip=ATTACKER_IP)[0], 429)
        # ...and an attacker can never lock out a different, legitimate client.
        self.assertEqual(self.call("GET", "/healthz", token=MONITOR, client_ip=BYSTANDER_IP)[0], 200)

    def test_every_http_verb_honours_the_throttle(self):
        for _ in range(10):
            self.call("GET", "/healthz", token="x" * 64, client_ip=ATTACKER_IP)
        for method, path, body in (("GET", "/healthz", None),
                                   ("POST", "/api/v1/security-events:batch", {"events": []}),
                                   ("POST", "/api/v1/response-actions", {"action": "TEMP_BLOCK_IP"}),
                                   ("DELETE", "/api/v1/admin/members/dev-someone-0001", None)):
            status, _h, payload = self.call(method, path, token=MONITOR, client_ip=ATTACKER_IP, body=body)
            self.assertEqual((status, payload.get("error")), (429, "too_many_failed_attempts"), f"{method} {path}")

    def test_throttled_requests_do_not_extend_their_own_penalty(self):
        for _ in range(10):
            self.call("GET", "/healthz", token="x" * 64, client_ip=ATTACKER_IP)
        before = self.server.AUTH_FAILURES.count(ATTACKER_IP)
        for _ in range(5):
            self.assertEqual(self.call("GET", "/healthz", token="x" * 64, client_ip=ATTACKER_IP)[0], 429)
        self.assertEqual(self.server.AUTH_FAILURES.count(ATTACKER_IP), before)

    def test_successful_traffic_is_never_counted_or_blocked(self):
        for _ in range(60):
            self.assertEqual(self.call("GET", "/healthz", token=MONITOR, client_ip=BYSTANDER_IP)[0], 200)
        self.assertEqual(self.server.AUTH_FAILURES.count(BYSTANDER_IP), 0)

    def test_without_a_real_client_address_the_shared_limit_is_much_higher(self):
        """Behind a tunnel that omits the header every client looks like 127.0.0.1: a low limit would let one
        attacker lock everybody out, so the shared address gets a multiple of the normal budget."""
        self.server.AUTH_FAIL_LIMIT, self.server.AUTH_FAIL_LOOPBACK_FACTOR = 2, 3
        for attempt in range(6):
            self.assertEqual(self.call("GET", "/healthz", token="x" * 64)[0], 401, attempt)
        self.assertEqual(self.call("GET", "/healthz", token="x" * 64)[0], 429)

    def test_a_malformed_client_address_header_falls_back_instead_of_crashing(self):
        status, _h, _b = self.call("GET", "/healthz", token=MONITOR, extra={"CF-Connecting-IP": "not-an-ip; DROP TABLE"})
        self.assertEqual(status, 200)

    def _handler(self, peer, header=None):
        handler = object.__new__(self.server.APIHandler)
        handler.client_address = (peer, 5555)
        handler.headers = {"CF-Connecting-IP": header} if header is not None else {}
        return handler

    def test_the_forwarded_address_is_trusted_only_from_the_local_tunnel(self):
        s = self.server
        self.assertEqual(self._handler("127.0.0.1", ATTACKER_IP)._client_ip(), ATTACKER_IP)
        self.assertEqual(self._handler("::1", ATTACKER_IP)._client_ip(), ATTACKER_IP)
        # a non-loopback peer must not be able to pick its own identity by sending the header
        self.assertEqual(self._handler("192.0.2.55", ATTACKER_IP)._client_ip(), "192.0.2.55")
        self.assertEqual(self._handler("127.0.0.1")._client_ip(), "127.0.0.1")
        self.assertEqual(self._handler("127.0.0.1", "garbage")._client_ip(), "127.0.0.1")
        with mock.patch.dict(os.environ, {"KAWAL_TRUST_CF_CONNECTING_IP": "false"}):
            self.assertEqual(self._handler("127.0.0.1", ATTACKER_IP)._client_ip(), "127.0.0.1")

    # -- second-factor guessing -------------------------------------------------------------------------

    def _wrong_code(self, secret):
        valid = {self.server._totp(secret, __import__("time").time() + delta) for delta in (-30, 0, 30)}
        return next(f"{n:06d}" for n in range(1_000_000) if f"{n:06d}" not in valid)

    def _response_call(self, identity, token, secret, code, ip=BYSTANDER_IP):
        body = {"action": "TEMP_BLOCK_IP", "source_ip": "203.0.113.50", "ttl_seconds": 300,
                "reason": "test reason", "confirmation": "BLOCK 203.0.113.50", "totp_code": code}
        return self.call("POST", "/api/v1/response-actions", token=token, identity=identity, client_ip=ip, body=body)

    def test_second_factor_codes_cannot_be_guessed_at_speed(self):
        wrong = self._wrong_code(TOTP_SECRET)
        for attempt in range(5):
            status, _h, body = self._response_call(DEVICE, RESPONSE, TOTP_SECRET, wrong)
            self.assertEqual((status, body["error"]), (403, "totp_required_or_invalid"), attempt)
        # even the CORRECT code is refused once the budget is spent: guessing must not be able to "land"
        status, headers, body = self._response_call(DEVICE, RESPONSE, TOTP_SECRET, self.server._totp(TOTP_SECRET))
        self.assertEqual((status, body["error"]), (429, "too_many_totp_attempts"))
        self.assertGreaterEqual(int(headers["retry-after"]), 1)

    def test_the_second_factor_budget_is_per_device(self):
        wrong = self._wrong_code(TOTP_SECRET)
        for _ in range(5):
            self._response_call(DEVICE, RESPONSE, TOTP_SECRET, wrong, ip="198.51.100.21")
        self.assertEqual(self._response_call(DEVICE, RESPONSE, TOTP_SECRET, self.server._totp(TOTP_SECRET), ip="198.51.100.21")[0], 429)
        # another device is not affected by it: its correct code passes the second factor (and then stops at the
        # disabled-by-default switch, which is what proves the code itself was accepted)
        status, _h, body = self._response_call(OTHER, OTHER_RESPONSE, OTHER_SECRET, self.server._totp(OTHER_SECRET), ip="198.51.100.22")
        self.assertEqual((status, body["error"]), (403, "response_actions_disabled"))

    def test_a_correct_code_clears_earlier_typos(self):
        wrong = self._wrong_code(TOTP_SECRET)
        for _ in range(3):
            self.assertEqual(self._response_call(DEVICE, RESPONSE, TOTP_SECRET, wrong)[2]["error"], "totp_required_or_invalid")
        ok = self._response_call(DEVICE, RESPONSE, TOTP_SECRET, self.server._totp(TOTP_SECRET))
        self.assertEqual(ok[2]["error"], "response_actions_disabled")      # past the second factor
        for _ in range(4):                                                  # 3+4 would exceed 5 had the typos not been cleared
            self.assertEqual(self._response_call(DEVICE, RESPONSE, TOTP_SECRET, wrong)[2]["error"], "totp_required_or_invalid")

    def test_the_second_factor_budget_comes_back_after_its_window(self):
        clock = Clock()
        self.server.TOTP_FAILURES = self.server.SlidingWindowCounter(300.0, clock=clock)
        wrong = self._wrong_code(TOTP_SECRET)
        for _ in range(5):
            self._response_call(DEVICE, RESPONSE, TOTP_SECRET, wrong)
        self.assertEqual(self._response_call(DEVICE, RESPONSE, TOTP_SECRET, self.server._totp(TOTP_SECRET))[0], 429)
        clock.now += 301
        self.assertEqual(self._response_call(DEVICE, RESPONSE, TOTP_SECRET, self.server._totp(TOTP_SECRET))[2]["error"], "response_actions_disabled")

    def test_wrong_codes_also_count_against_the_address(self):
        wrong = self._wrong_code(TOTP_SECRET)
        for _ in range(4):
            self._response_call(DEVICE, RESPONSE, TOTP_SECRET, wrong, ip="198.51.100.30")
        self.assertEqual(self.server.AUTH_FAILURES.count("198.51.100.30"), 4)

    # -- enrollment (unauthenticated) -------------------------------------------------------------------

    def test_enrollment_budget_is_per_real_client_not_per_tunnel(self):
        a = self._handler("127.0.0.1", ATTACKER_IP)
        b = self._handler("127.0.0.1", BYSTANDER_IP)
        self.assertTrue(all(a._enrollment_rate_ok() for _ in range(20)))
        self.assertFalse(a._enrollment_rate_ok())
        self.assertTrue(b._enrollment_rate_ok(), "one noisy client must not stop a different client from enrolling")


class SlidingWindowCounterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {"KAWAL_API_DB_PATH": str(Path(cls.temp.name) / "unit.sqlite3")})
        cls.env.start()
        cls.server = load_server()

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.temp.cleanup()

    def counter(self, window=60.0, max_keys=4096):
        self.clock = Clock()
        return self.server.SlidingWindowCounter(window, max_keys, clock=self.clock)

    def test_events_expire_after_the_window(self):
        c = self.counter()
        for _ in range(3):
            c.add("k")
        self.assertEqual(c.count("k"), 3)
        self.clock.now += 59.9
        self.assertEqual(c.count("k"), 3)
        self.clock.now += 0.2
        self.assertEqual(c.count("k"), 0)
        self.assertEqual(c.tracked_keys(), 0, "expired keys must not linger in memory")

    def test_retry_after_is_exactly_when_the_oldest_blocking_event_expires(self):
        c = self.counter()
        for _ in range(3):
            c.add("k")
            self.clock.now += 10          # events at t=0,10,20 ; now = 30
        self.assertEqual(c.retry_after("k", 3), 30.0)        # the t=0 event leaves at t=60
        self.assertEqual(c.retry_after("k", 4), 0.0)         # below the limit
        self.assertEqual(c.retry_after("missing", 1), 0.0)
        self.clock.now += 31
        self.assertEqual(c.retry_after("k", 3), 0.0)

    def test_retry_after_waits_until_the_count_is_back_under_the_limit_not_just_until_one_event_expires(self):
        c = self.counter()
        for _ in range(5):
            c.add("k")
            self.clock.now += 10          # events at t=0,10,20,30,40 ; now = 50
        start = 1000.0                    # Clock() starts here: events at start+0..40, now = start+50
        # limit 3 means three events must leave the window: the third-newest-but-one (start+20) expires at start+80
        self.assertEqual(c.retry_after("k", 3), 30.0)
        self.clock.now = start + 80.0
        self.assertEqual(c.retry_after("k", 3), 0.0)

    def test_memory_stays_bounded_under_a_flood_of_distinct_clients(self):
        c = self.counter(max_keys=100)
        for index in range(10_000):
            c.add(f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}")
        self.assertLessEqual(c.tracked_keys(), 100)

    def test_the_least_recently_active_key_is_dropped_first(self):
        c = self.counter(max_keys=3)
        for key in ("a", "b", "c"):
            c.add(key)
        c.add("a")                      # a is active again
        c.add("d")                      # evicts b, the least recently touched
        self.assertEqual((c.count("a"), c.count("b"), c.count("c"), c.count("d")), (2, 0, 1, 1))

    def test_reset_forgets_one_key_only(self):
        c = self.counter()
        c.add("a")
        c.add("b")
        c.reset("a")
        self.assertEqual((c.count("a"), c.count("b")), (0, 1))

    def test_every_operation_runs_under_the_counter_lock(self):
        """A lost-update race on a plain dict is almost impossible to provoke under the GIL (measured: ~1 in 1000
        rounds even when forced), so a stress test cannot prove the lock. This checks it directly instead."""
        class RecordingLock:
            def __init__(self):
                self.entries = 0
                self._real = threading.Lock()

            def __enter__(self):
                self.entries += 1
                self._real.acquire()
                return self

            def __exit__(self, *exc):
                self._real.release()

        c = self.counter()
        c._lock = RecordingLock()
        operations = {
            "add": lambda: c.add("k"),
            "count": lambda: c.count("k"),
            "retry_after": lambda: c.retry_after("k", 1),
            "reset": lambda: c.reset("k"),
            "tracked_keys": lambda: c.tracked_keys(),
        }
        for name, operation in operations.items():
            before = c._lock.entries
            operation()
            self.assertGreater(c._lock.entries, before, f"{name} does not take the lock")

    def test_concurrent_use_smoke(self):
        """Not a proof of thread safety (see above): it only shows that heavy concurrent use neither raises nor
        miscounts in the common case."""
        c = self.counter()
        barrier = threading.Barrier(8)

        def hit():
            barrier.wait()
            for _ in range(100):
                c.add("shared")
                c.count("shared")
                c.retry_after("shared", 5)

        threads = [threading.Thread(target=hit) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(c.count("shared"), 800)

    def test_limit_scales_only_for_the_shared_loopback_address(self):
        s = self.server
        self.assertEqual(s.auth_fail_limit_for("198.51.100.7"), s.AUTH_FAIL_LIMIT)
        self.assertEqual(s.auth_fail_limit_for("2001:db8::1"), s.AUTH_FAIL_LIMIT)
        self.assertEqual(s.auth_fail_limit_for("127.0.0.1"), s.AUTH_FAIL_LIMIT * s.AUTH_FAIL_LOOPBACK_FACTOR)
        self.assertEqual(s.auth_fail_limit_for("::1"), s.AUTH_FAIL_LIMIT * s.AUTH_FAIL_LOOPBACK_FACTOR)
        self.assertEqual(s.auth_fail_limit_for("not an ip"), s.AUTH_FAIL_LIMIT)


if __name__ == "__main__":
    unittest.main()
