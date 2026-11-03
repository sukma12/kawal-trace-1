"""The REAL dashboard code (main.py) driven against the REAL optional server API over loopback HTTP.

Covers the wiring the unit tests cannot: pressing "Hubungkan" starts the stream, a server-side change makes the
app pull again within about a second, the status text only claims real-time while connected, and every way of
dropping the connection stops the stream. The Flet UI is the headless stand-in from ui_harness (structure, not
pixels), and secure storage is an in-memory fake; the network path is the real one.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import inspect
import json
import os
import re
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import pytest

import ui_harness as h
from chainlog.auth import UserRegistry
from chainlog.core import AuditStore
from chainlog.e2ee import generate_keypair

ROOT = Path(__file__).resolve().parents[1]
PROFILE_ID = "srv-uitest01"
DEVICE = "dev-ui-stream-01"
AUDIT_TOKEN = "a" * 64
MONITOR_TOKEN = "m" * 64


class FakeSecureStorage:
    """Stands in for the OS keystore bridge; same async get/set/remove surface."""

    def __init__(self):
        self.values: dict[str, str] = {}

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value):
        self.values[key] = value

    async def remove(self, key):
        self.values.pop(key, None)

    async def contains_key(self, key):
        return key in self.values


def load_real_server():
    spec = importlib.util.spec_from_file_location("kawal_real_server_for_ui_e2e", ROOT / "optional-server-api" / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def world(tmp_path, monkeypatch):
    env = {
        "KAWAL_API_DB_PATH": str(tmp_path / "server.sqlite3"),
        "KAWAL_MONITOR_TOKENS": f"{DEVICE}|{MONITOR_TOKEN}",
        "KAWAL_AUDIT_TOKENS": f"{DEVICE}|{AUDIT_TOKEN}",
        "KAWAL_API_ACCEPT_CLIENT_DATA": "false",
    }
    with mock.patch.dict(os.environ, env):
        server = load_real_server()
        server.init_db()
        server.STREAM_HEARTBEAT_SECONDS = 0.3
        server.STREAM_WATCH_SECONDS = 0.04
        hits: list[str] = []

        class Recording(server.APIHandler):
            def do_GET(self):
                hits.append(self.path)
                super().do_GET()

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Recording)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base_url = f"http://127.0.0.1:{httpd.server_address[1]}"

        data_dir = tmp_path / "data"
        monkeypatch.setenv("KAWAL_TRACE_DATA_DIR", str(data_dir))
        data_dir.mkdir()
        (data_dir / "server-registry.json").write_text(json.dumps({
            "format": "Kawal Trace-server-registry", "version": 1, "selected_id": PROFILE_ID,
            "profiles": [{"profile_id": PROFILE_ID, "name": "Server uji", "base_url": base_url, "device_id": DEVICE,
                          "connector_type": "kawal_trace_api"}],
        }), encoding="utf-8")

        saved = {name: sys.modules.get(name) for name in ("flet", "main")}
        ft = h.install_fake_flet()
        sys.modules.pop("main", None)
        main = importlib.import_module("main")
        storage = FakeSecureStorage()
        private_key, _public = generate_keypair()
        storage.values.update({
            f"kawal_trace_device_token:{PROFILE_ID}": AUDIT_TOKEN,
            f"kawal_trace_monitor_token:{PROFILE_ID}": MONITOR_TOKEN,
            "kawal_trace_e2ee_private_key_v1": private_key,
        })
        monkeypatch.setattr(main, "fss", type("FakeFss", (), {"SecureStorage": staticmethod(lambda: storage)}))

        def build():
            store = AuditStore()
            store.initialize()
            registry = UserRegistry(store.data_dir / "identity.sqlite3")
            page = ft.Page(width=1280)
            stage = {"name": ""}
            lifecycle: dict = {}
            session = {"username": "admin", "role": "admin", "auth_via": "password"}
            main._build_dashboard(page, session, registry, stage, on_logout=None, lifecycle=lifecycle, notice="")
            return page, page.controls[0], lifecycle

        try:
            yield types_ns(server=server, hits=hits, main=main, build=build, storage=storage, base_url=base_url)
        finally:
            httpd.shutdown()
            httpd.server_close()
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module


def types_ns(**kw):
    import types
    return types.SimpleNamespace(**kw)


def text_with(root, prefix):
    return next((c for c in root.walk() if c.kind == "Text" and isinstance(c.value, str) and c.value.startswith(prefix)), None)


def button(root, label):
    return h.find(root, None, content=label)[0]


async def until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.03)
    return False


async def call(handler):
    result = handler(None)
    if inspect.isawaitable(result):
        await result


LIVE_PREFIXES = ("REAL-TIME AKTIF", "MENYAMBUNGKAN STREAM", "STREAM TERPUTUS", "STREAM MATI",
                 "SERVER BELUM MENDUKUNG STREAM", "STREAM DITOLAK")


def nav(root, title):
    """Only the active page is mounted, so open a sidebar entry before looking for controls on it."""
    next(c for c in root.walk() if c.kind == "Container" and c.ink and c.on_click and c.tooltip == title).on_click(None)


def stream_status_control(root):
    """The status Text object persists as a closure variable, so grab it once while its page is mounted."""
    nav(root, "Telemetri & Arsip")
    return next(c for c in root.walk() if c.kind == "Text" and isinstance(c.value, str) and c.value.startswith(LIVE_PREFIXES))


def add_response_action(server, action_id, updated="2026-11-01T00:00:00.000Z"):
    with server.DB_LOCK, server.db_session() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO response_actions(action_id,device_id,action,source_ip,ttl_seconds,reason,requested_at_utc,expires_at_utc,expires_at_epoch,status,updated_at_utc) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (action_id, "d", "TEMP_BLOCK_IP", "203.0.113.9", 300, "reason text", updated, updated, 1, "PENDING", updated))


def test_connect_goes_live_a_server_change_pulls_again_and_disconnect_stops_everything(world):
    page, root, lifecycle = world.build()
    tasks = {getattr(handler, "__name__", ""): handler for handler, _a, _k in page.tasks}
    assert "doorbell_consumer" in tasks and "background_telemetry_loop" in tasks
    status = stream_status_control(root)
    assert status.value.startswith("STREAM MATI"), "no real-time claim before connecting"
    nav(root, "Integrasi Server")
    connect, disconnect = button(root, "Hubungkan"), button(root, "Putuskan")
    pulls = lambda: world.hits.count("/api/v1/response-actions?limit=20")

    async def scenario():
        consumer = asyncio.create_task(tasks["doorbell_consumer"]())
        try:
            await call(connect.on_click)
            assert await until(lambda: status.value.startswith("REAL-TIME AKTIF")), status.value
            assert world.server.STREAMS.open_count() == 1

            await asyncio.sleep(0.6)   # let the hello catch-up refresh finish
            baseline = pulls()
            started = time.monotonic()
            add_response_action(world.server, "ui-a1")
            assert await until(lambda: pulls() > baseline), "no pull after the doorbell"
            assert time.monotonic() - started < 3.0

            await call(disconnect.on_click)
            assert status.value.startswith("STREAM MATI")
            assert await until(lambda: world.server.STREAMS.open_count() == 0), "server still holds the stream"
            quiet_baseline = pulls()
            add_response_action(world.server, "ui-a2", updated="2026-11-01T00:00:09.000Z")
            await asyncio.sleep(1.2)
            assert pulls() == quiet_baseline, "disconnected app must not keep pulling"
        finally:
            consumer.cancel()
            lifecycle["shutdown"]()

    asyncio.run(scenario())
    assert not (Path(os.environ["KAWAL_TRACE_DATA_DIR"]) / "startup-errors.log").exists()


def test_dashboard_shutdown_stops_the_stream(world):
    page, root, lifecycle = world.build()
    status = stream_status_control(root)
    nav(root, "Integrasi Server")
    connect = button(root, "Hubungkan")

    async def scenario():
        await call(connect.on_click)
        assert await until(lambda: status.value.startswith("REAL-TIME AKTIF"))
        lifecycle["shutdown"]()
        assert await until(lambda: world.server.STREAMS.open_count() == 0), "sign-out must close the stream"

    asyncio.run(scenario())


def test_older_server_without_stream_falls_back_and_says_so(world):
    world.server.STREAM_PATH = "/api/v1/stream-disabled-for-this-test"   # the server now answers 404 for /api/v1/stream
    page, root, lifecycle = world.build()
    status = stream_status_control(root)
    nav(root, "Integrasi Server")
    connect = button(root, "Hubungkan")

    async def scenario():
        try:
            await call(connect.on_click)
            assert await until(lambda: status.value.startswith("SERVER BELUM MENDUKUNG STREAM")), status.value
            assert world.server.STREAMS.open_count() == 0
        finally:
            lifecycle["shutdown"]()

    asyncio.run(scenario())


def test_wrong_monitor_token_is_reported_not_retried_forever(world):
    world.storage.values[f"kawal_trace_monitor_token:{PROFILE_ID}"] = "x" * 64
    page, root, lifecycle = world.build()
    status = stream_status_control(root)
    nav(root, "Integrasi Server")
    connect = button(root, "Hubungkan")

    async def scenario():
        try:
            await call(connect.on_click)
            # Either the connect itself or the stream refuses the token; the app must never show real-time.
            await asyncio.sleep(1.0)
            assert not status.value.startswith("REAL-TIME AKTIF")
            assert world.server.STREAMS.open_count() == 0
        finally:
            lifecycle["shutdown"]()

    asyncio.run(scenario())


def test_a_replaced_stream_cannot_overwrite_the_new_streams_status(world, monkeypatch):
    """Connecting again replaces the stream. A late report from the old one must not change the label or the
    polling cadence (the label would lie, and a wrong state would make the safety-net poll too slow)."""
    created = []

    class FakeSupervisor:
        def __init__(self, factory, on_signal, on_status):
            self.on_status, self.stopped = on_status, False
            created.append(self)

        def start(self):
            pass

        def stop(self):
            self.stopped = True

    monkeypatch.setattr(world.main, "LiveStreamSupervisor", FakeSupervisor)
    page, root, lifecycle = world.build()
    status = stream_status_control(root)
    nav(root, "Integrasi Server")
    connect = button(root, "Hubungkan")

    async def scenario():
        await call(connect.on_click)
        await call(connect.on_click)
        assert len(created) == 2 and created[0].stopped and not created[1].stopped
        created[1].on_status("live", "")
        await asyncio.sleep(0.05)
        assert status.value.startswith("REAL-TIME AKTIF")
        created[0].on_status("retrying", "late report from the replaced stream")
        created[0].on_status("unauthorized", "late")
        await asyncio.sleep(0.05)
        assert status.value.startswith("REAL-TIME AKTIF"), status.value
        lifecycle["shutdown"]()

    asyncio.run(scenario())


def test_a_failing_refresh_is_logged_and_does_not_end_real_time_updates(world, monkeypatch):
    class ExplodingFeed:
        def __init__(self, *args, **kwargs):
            pass

        def fetch_recent(self, limit):
            raise RuntimeError("feed exploded for the test")

    monkeypatch.setattr(world.main, "E2EEServerFeedClient", ExplodingFeed)
    page, root, lifecycle = world.build()
    tasks = {getattr(handler, "__name__", ""): handler for handler, _a, _k in page.tasks}
    status = stream_status_control(root)
    nav(root, "Integrasi Server")
    connect = button(root, "Hubungkan")
    pulls = lambda: world.hits.count("/api/v1/response-actions?limit=20")
    log = Path(os.environ["KAWAL_TRACE_DATA_DIR"]) / "startup-errors.log"

    async def scenario():
        consumer = asyncio.create_task(tasks["doorbell_consumer"]())
        try:
            try:
                await call(connect.on_click)
            except RuntimeError:
                pass   # the explicit connect-time refresh is not under the consumer's protection; only the stream matters here
            assert await until(lambda: status.value.startswith("REAL-TIME AKTIF")), status.value
            assert await until(lambda: log.exists() and "feed exploded for the test" in log.read_text()), "failure must be recorded, not swallowed"
            await asyncio.sleep(0.6)
            baseline = pulls()
            add_response_action(world.server, "ui-b1")
            assert await until(lambda: pulls() > baseline), "consumer died after a failed refresh"
            assert not consumer.done()
        finally:
            consumer.cancel()
            lifecycle["shutdown"]()

    asyncio.run(scenario())


# ----------------------------------------------------------------------------- static wiring guarantees
MAIN_SOURCE = (ROOT / "main.py").read_text(encoding="utf-8")


def test_every_path_that_drops_the_connection_also_stops_the_stream():
    lines = MAIN_SOURCE.splitlines()
    sites = [i for i, line in enumerate(lines) if re.match(r"\s*connected_server_id = None\b", line)]
    assert len(sites) >= 6, "expected the known connection-reset sites"
    for i in sites:
        following = next(l.strip() for l in lines[i + 1:i + 4] if l.strip())
        assert following == "stop_live_stream()", f"line {i + 1}: connection dropped without stopping the stream"


def test_stream_threads_never_touch_ui_controls_directly():
    import ast
    tree = ast.parse(MAIN_SOURCE)
    start = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "start_live_stream")
    inner = {n.name: n for n in start.body if isinstance(n, ast.FunctionDef)}
    assert set(inner) == {"on_status", "on_signal"}
    for name, fn in inner.items():
        for node in ast.walk(fn):
            if isinstance(node, ast.Attribute) and node.attr in {"update", "value", "color", "controls"}:
                # `apply` (nested in on_status) is scheduled onto the UI loop and is the only place allowed to touch the UI
                inside_apply = any(isinstance(p, ast.FunctionDef) and p.name == "apply" and node in ast.walk(p) for p in ast.walk(fn))
                assert inside_apply, f"{name} touches `.{node.attr}` from the stream thread"
        assert "call_soon_threadsafe" in ast.unparse(fn)


def test_real_time_is_never_hardcoded_in_the_ui():
    assert "REAL-TIME AKTIF" not in MAIN_SOURCE, "only live_stream.status_text may claim it, and only for the live state"


def test_polling_cadence_comes_from_the_stream_state_not_a_constant():
    block = MAIN_SOURCE.split("async def background_telemetry_loop", 1)[1].split("# --- Transparent", 1)[0]
    assert 'poll_interval_seconds(live_stream["state"])' in block
    assert "asyncio.sleep(5)" not in block


def test_stream_only_starts_for_the_kawal_api_with_a_monitor_token():
    block = MAIN_SOURCE.split("async def connect_selected_server", 1)[1].split("def disconnect_selected_server", 1)[0]
    assert block.count("start_live_stream(") == 1
    before_token_lookup, after_token_lookup = block.split("monitor_token = await _load_monitor_token()", 1)
    assert "start_live_stream(" not in before_token_lookup, "the read-only Generic REST connector must never open our stream"
    with_token = after_token_lookup.split("if monitor_token:", 1)[1].split("else:", 1)[0]
    assert "start_live_stream(settings, monitor_token)" in with_token, "no monitor token means no stream"
