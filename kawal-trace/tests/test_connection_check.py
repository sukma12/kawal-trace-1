"""The connection check must tell a person far from the server WHICH step broke and what to look at."""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import httpx

from chainlog import connection_check as cc

ROOT = Path(__file__).resolve().parents[1]
DEVICE = "dev-check-0001"
TOKEN = "k" * 48


def by_name(results, name):
    return next(item for item in results if item.name == name)


def levels(results):
    return {item.name: item.level for item in results}


class FailingTransport(httpx.BaseTransport):
    def __init__(self, error: Exception):
        self.error = error

    def handle_request(self, request):
        raise self.error


def chained(outer: Exception, cause: BaseException) -> Exception:
    outer.__cause__ = cause
    return outer


class FailureClassificationTests(unittest.TestCase):
    def check(self, error):
        return cc.run_checks("https://monitor.example.org", DEVICE, TOKEN, transport=FailingTransport(error), timeout=5)

    def test_dns_failure(self):
        results = self.check(chained(httpx.ConnectError("x"), socket.gaierror(-2, "Name or service not known")))
        server = by_name(results, "Server menjawab")
        self.assertEqual(server.level, cc.FAIL)
        self.assertIn("DNS", server.detail)
        self.assertEqual(levels(results)["Token & Device ID"], cc.SKIP)

    def test_untrusted_certificate_never_suggests_disabling_verification(self):
        results = self.check(chained(httpx.ConnectError("x"), ssl.SSLCertVerificationError("bad cert")))
        server = by_name(results, "Server menjawab")
        self.assertIn("Sertifikat", server.detail)
        self.assertIn("Jangan mematikan verifikasi TLS", server.hint)

    def test_connection_refused_points_at_the_tunnel_and_service(self):
        results = self.check(chained(httpx.ConnectError("x"), ConnectionRefusedError()))
        self.assertIn("ditolak", by_name(results, "Server menjawab").detail)
        self.assertIn("cloudflared", by_name(results, "Server menjawab").hint)

    def test_timeout(self):
        results = self.check(httpx.ConnectTimeout("t"))
        self.assertIn("Tidak ada jawaban", by_name(results, "Server menjawab").detail)

    def test_other_tls_errors(self):
        results = self.check(chained(httpx.ConnectError("x"), ssl.SSLError("handshake")))
        self.assertIn("TLS", by_name(results, "Server menjawab").detail)

    def test_unknown_errors_are_named_not_hidden(self):
        results = self.check(httpx.ConnectError("weird"))
        self.assertIn("ConnectError", by_name(results, "Server menjawab").detail)


class InputValidationTests(unittest.TestCase):
    def test_plain_http_to_a_real_hostname_is_refused_and_nothing_else_runs(self):
        results = cc.run_checks("http://example.org", DEVICE, TOKEN)
        self.assertEqual(by_name(results, "Alamat server").level, cc.FAIL)
        self.assertTrue(all(item.level == cc.SKIP for item in results[1:]))

    def test_bad_or_missing_token_stops_before_any_request(self):
        class Boom(httpx.BaseTransport):
            def handle_request(self, request):
                raise AssertionError("no request may be made without a usable token")
        for token in ("", "short", "has space " + "x" * 30):
            results = cc.run_checks("https://monitor.example.org", DEVICE, token, transport=Boom())
            self.assertEqual(by_name(results, "Token monitor").level, cc.FAIL)

    def test_exit_code_reflects_failures_only(self):
        self.assertEqual(cc.exit_code([cc.CheckResult("a", cc.OK, ""), cc.CheckResult("b", cc.WARN, "")]), 0)
        self.assertEqual(cc.exit_code([cc.CheckResult("a", cc.OK, ""), cc.CheckResult("b", cc.FAIL, "")]), 1)


class ScriptedServer:
    def __init__(self, routes):
        outer = self
        self.paths: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.paths.append(self.path)
                routes(self)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def reply(handler, status, body, content_type="application/json"):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class WhatTheAddressActuallyIsTests(unittest.TestCase):
    def setUp(self):
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.close()

    def serve(self, routes):
        server = ScriptedServer(routes)
        self.servers.append(server)
        return server

    def run_against(self, server, **kw):
        return cc.run_checks(server.url, DEVICE, TOKEN, timeout=3, **kw)

    def test_a_different_service_is_not_mistaken_for_the_api(self):
        server = self.serve(lambda h: reply(h, 200, b"<html>hello</html>", "text/html"))
        results = self.run_against(server)
        self.assertEqual(by_name(results, "Token & Device ID").level, cc.FAIL)
        self.assertIn("bukan Kawal-Trace API", by_name(results, "Token & Device ID").detail)
        self.assertEqual(by_name(results, "Stream real-time").level, cc.SKIP)

    def test_gateway_errors_blame_the_tunnel_not_the_token(self):
        for status in (502, 530):
            server = self.serve(lambda h, status=status: reply(h, status, b"bad gateway", "text/plain"))
            detail = by_name(self.run_against(server), "Token & Device ID")
            self.assertEqual(detail.level, cc.FAIL)
            self.assertIn(str(status), detail.detail)
            self.assertIn("127.0.0.1:8765", detail.hint)

    def test_rejected_token_is_reported_as_such_and_never_echoed(self):
        server = self.serve(lambda h: reply(h, 401, {"error": "unauthorized"}))
        results = self.run_against(server)
        rejected = by_name(results, "Token & Device ID")
        self.assertEqual(rejected.level, cc.FAIL)
        self.assertIn("menolak token", rejected.detail)       # a refusal, not "this is some other service"
        self.assertNotIn("bukan Kawal-Trace API", rejected.detail)
        report = cc.format_report(results)
        self.assertNotIn(TOKEN, report)
        self.assertIn("HASIL: 1 langkah gagal", report)

    def test_older_api_without_stream_is_a_warning_not_a_failure(self):
        def routes(h):
            if h.path == "/healthz":
                reply(h, 200, {"status": "ok", "service": "kawal-trace-api", "api_version": "1.4.0"})
            else:
                reply(h, 200, {"events": [], "count": 0})
        server = self.serve(routes)
        results = self.run_against(server)
        self.assertEqual(by_name(results, "Stream real-time").level, cc.WARN)
        self.assertIn("polling", by_name(results, "Stream real-time").hint)
        self.assertEqual(cc.exit_code(results), 0)

    def test_a_proxy_that_buffers_the_stream_is_detected_by_the_missing_hello(self):
        release = threading.Event()

        def routes(h):
            if h.path == "/healthz":
                reply(h, 200, {"status": "ok", "service": "kawal-trace-api", "api_version": "1.5.0", "features": ["stream"]})
            elif h.path.startswith("/api/v1/security-events"):
                reply(h, 200, {"events": [{"event_id": "e"}], "count": 1})
            else:
                h.send_response(200)
                h.send_header("Content-Type", "text/event-stream")
                h.end_headers()
                h.wfile.flush()
                release.wait(8)    # headers out, body held back: what a buffering proxy looks like
        server = self.serve(routes)
        try:
            started = time.monotonic()
            results = self.run_against(server, stream_wait=0.8)
            self.assertLess(time.monotonic() - started, 4)
        finally:
            release.set()
        stream = by_name(results, "Stream real-time")
        self.assertEqual(stream.level, cc.FAIL)
        self.assertIn("buffer", stream.hint)
        self.assertEqual(by_name(results, "Feed telemetri").level, cc.OK, "earlier steps still report their own result")

    def test_slow_links_are_flagged_with_the_measured_round_trip(self):
        ticks = iter(range(0, 10_000))
        server = self.serve(lambda h: reply(h, 200, {"status": "ok", "service": "kawal-trace-api", "api_version": "1.4.0"}))
        results = self.run_against(server, clock=lambda: float(next(ticks)))   # every clock read "takes" a second
        speed = by_name(results, "Kecepatan")
        self.assertEqual(speed.level, cc.WARN)
        self.assertIn("1000 ms", speed.detail)


def load_real_server():
    spec = importlib.util.spec_from_file_location("kawal_real_server_for_check", ROOT / "optional-server-api" / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AgainstTheRealServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {
            "KAWAL_API_DB_PATH": str(Path(cls.temp.name) / "check.sqlite3"),
            "KAWAL_MONITOR_TOKENS": f"{DEVICE}|{TOKEN}",
        })
        cls.env.start()
        cls.server = load_real_server()
        cls.server.init_db()
        cls.server.STREAM_HEARTBEAT_SECONDS = 0.3
        cls.server.STREAM_WATCH_SECONDS = 0.04
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), cls.server.APIHandler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.env.stop()
        cls.temp.cleanup()

    def seed_event(self):
        with self.server.DB_LOCK, self.server.db_session() as conn:
            conn.execute("INSERT OR REPLACE INTO security_events(event_id,host_id,timestamp_utc,payload_json,received_at_utc) VALUES('chk1','h','2026-11-01T00:00:00.000Z','{}','2026-11-01T00:00:00.000Z')")

    def test_empty_feed_is_a_warning_and_everything_else_passes(self):
        with self.server.DB_LOCK, self.server.db_session() as conn:
            conn.execute("DELETE FROM security_events")
        results = cc.run_checks(self.url, DEVICE, TOKEN, stream_wait=4)
        self.assertEqual(levels(results), {
            "Alamat server": cc.OK, "Server menjawab": cc.OK, "Token & Device ID": cc.OK, "Feed telemetri": cc.WARN,
            "Stream real-time": cc.OK, "Kecepatan": cc.OK,
        })
        self.assertIn("tidak membuktikan server aman", by_name(results, "Feed telemetri").hint)
        self.assertEqual(cc.exit_code(results), 0)

    def test_fully_healthy_path(self):
        self.seed_event()
        results = cc.run_checks(self.url, DEVICE, TOKEN, stream_wait=4)
        self.assertTrue(all(item.level == cc.OK for item in results), cc.format_report(results))
        report = cc.format_report(results)
        self.assertIn("semua langkah berhasil", report)
        self.assertIn("bukan bahwa server aman", report)
        self.assertNotIn(TOKEN, report)
        self.assertEqual(list(levels(results)), ["Alamat server", "Server menjawab", "Token & Device ID", "Feed telemetri", "Stream real-time", "Kecepatan"])

    def _wait_closed(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and self.server.STREAMS.open_count():
            time.sleep(0.05)
        return self.server.STREAMS.open_count() == 0

    def test_the_check_leaves_no_stream_behind(self):
        self.seed_event()
        cc.run_checks(self.url, DEVICE, TOKEN, stream_wait=4)
        self.assertTrue(self._wait_closed(), "the diagnostic must not hold a server stream slot")

    def test_wrong_token_against_the_real_server(self):
        results = cc.run_checks(self.url, DEVICE, "z" * 48)
        self.assertEqual(by_name(results, "Token & Device ID").level, cc.FAIL)
        self.assertEqual(by_name(results, "Stream real-time").level, cc.SKIP)

    def test_command_line_wrapper(self):
        spec = importlib.util.spec_from_file_location("check_connection_script", ROOT / "scripts" / "check_connection.py")
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        self.seed_event()
        import contextlib
        import io
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"KAWAL_MONITOR_TOKEN": TOKEN}), contextlib.redirect_stdout(out):
            self.assertEqual(script.main(["--url", self.url, "--device-id", DEVICE, "--timeout", "4"]), 0)
        self.assertIn("HASIL: semua langkah berhasil", out.getvalue())
        self.assertNotIn(TOKEN, out.getvalue())
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"KAWAL_MONITOR_TOKEN": "y" * 48}), contextlib.redirect_stdout(out):
            self.assertEqual(script.main(["--url", self.url, "--device-id", DEVICE]), 1)
        with self.assertRaises(SystemExit):
            script.main(["--url", self.url, "--device-id", DEVICE, "--timeout", "0"])

    def test_the_script_has_no_option_that_puts_the_token_in_shell_history(self):
        source = (ROOT / "scripts" / "check_connection.py").read_text(encoding="utf-8")
        self.assertNotIn('"--token"', source)
        self.assertIn("KAWAL_MONITOR_TOKEN", source)


if __name__ == "__main__":
    unittest.main()
