from __future__ import annotations

import json

import pytest

from server_agent.chainlog_server_agent import (
    Outbox, build_filesystem_watch_health_event, parse_audit_group,
    parse_journal_entry, stable_event_id,
)


def test_parse_journal_ssh_failed_password():
    entry = {
        "__CURSOR": "s=unique-cursor-123",
        "__REALTIME_TIMESTAMP": "1760000000123456",
        "_SYSTEMD_UNIT": "sshd.service",
        "MESSAGE": "Failed password for test-user from 203.0.113.8 port 43122 ssh2",
    }
    event = parse_journal_entry(entry, "srv-test")
    assert event is not None
    assert event["event_type"] == "AUTH_FAILURE"
    assert event["actor"] == "test-user"
    assert event["source_ip"] == "203.0.113.8"
    assert len(event["event_id"]) == 64


def test_parse_journal_accepted_root_login():
    entry = {
        "__CURSOR": "s=cursor-root-123",
        "__REALTIME_TIMESTAMP": "1760000000123456",
        "_SYSTEMD_UNIT": "ssh.service",
        "MESSAGE": "Accepted publickey for root from 203.0.113.9 port 22 ssh2",
    }
    event = parse_journal_entry(entry, "srv-test")
    assert event["event_type"] == "AUTH_SUCCESS"
    assert event["actor"] == "root"
    assert event["details"]["auth_method"] == "publickey"


def test_parse_sudo_does_not_include_arbitrary_command_arguments():
    entry = {
        "__CURSOR": "s=cursor-sudo-123",
        "_SYSTEMD_UNIT": "sudo.service",
        "MESSAGE": "sudo: operator : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /tmp/credentials.txt",
    }
    event = parse_journal_entry(entry, "srv-test")
    assert event is not None
    assert event["event_type"] == "PRIVILEGE_USE"
    assert event["details"]["command_basename"] == "cat"
    assert "credentials.txt" not in json.dumps(event)


def test_parse_sensitive_auditd_group():
    lines = [
        'type=SYSCALL msg=audit(1760000000.123:777): arch=c000003e syscall=257 success=yes exit=3 auid=1001 uid=0 euid=0 key="kawal_trace_sensitive"',
        'type=CWD msg=audit(1760000000.123:777): cwd="/root"',
        'type=PATH msg=audit(1760000000.123:777): item=0 name="/etc/ssh/sshd_config" inode=1234 nametype=NORMAL',
        'type=EOE msg=audit(1760000000.123:777):',
    ]
    event = parse_audit_group(lines, "srv-test")
    assert event is not None
    assert event["event_type"] == "FILE_CHANGE"
    assert event["details"]["path"] == "/etc/ssh/sshd_config"
    assert event["actor"] == "uid:1001"


def test_outbox_deduplicates_stable_event_id_and_acknowledges_only_requested_ids(tmp_path):
    outbox = Outbox(tmp_path / "outbox.sqlite3")
    event = {"event_id": stable_event_id("host", "journal", "cursor-1"), "event_type": "AUTH_FAILURE"}
    outbox.enqueue(event)
    outbox.enqueue(event)
    assert outbox.count() == 1
    valid, _head, entries = outbox.verify_chain()
    assert valid and entries == 1
    outbox.acknowledge(["not-a-real-id"])
    assert outbox.count() == 1
    outbox.acknowledge([event["event_id"]])
    assert outbox.count() == 0
    # The event ID remains in the audit chain after upload/acknowledgment.
    valid, _head, entries = outbox.verify_chain()
    assert valid and entries == 1


def test_outbox_detects_pending_payload_tampering(tmp_path):
    outbox = Outbox(tmp_path / "outbox.sqlite3")
    event = {"event_id": stable_event_id("host", "journal", "cursor-tamper"), "event_type": "AUTH_FAILURE", "details": {"reason": "test"}}
    outbox.enqueue(event)
    with outbox._connect() as conn:
        conn.execute("UPDATE outbox SET payload_json='{}' WHERE event_id=?", (event["event_id"],))
    valid, message, _count = outbox.verify_chain()
    assert not valid and "pending payload changed" in message


def test_agent_posts_events_and_only_removes_acknowledged_ids(tmp_path, monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from server_agent import chainlog_server_agent as agent

    received = {"events": []}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return
        def do_POST(self):
            assert self.headers.get("Authorization") == f"Bearer {agent.API_TOKEN}"
            assert self.headers.get("X-KAWAL-Host-ID") == agent.HOST_ID
            size = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(size))
            received["events"].extend(payload["events"])
            # Acknowledge only the first event to exercise partial-ack durability.
            ids = [payload["events"][0]["event_id"]]
            body = json.dumps({"accepted_event_ids": ids}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    monkeypatch.setattr(agent, "HOST_ID", "srv-test-agent")
    monkeypatch.setattr(agent, "API_TOKEN", "agent-write-token-long-enough-012345")
    monkeypatch.setattr(agent, "INGEST_URL", f"http://127.0.0.1:{server.server_address[1]}/api/v1/security-events:batch")
    monkeypatch.setattr(agent, "CA_BUNDLE", "")
    try:
        outbox = Outbox(tmp_path / "outbox.sqlite3")
        e1 = {"event_id": stable_event_id("srv", "journal", "1"), "event_type": "AUTH_FAILURE"}
        e2 = {"event_id": stable_event_id("srv", "journal", "2"), "event_type": "AUTH_SUCCESS"}
        outbox.enqueue(e1); outbox.enqueue(e2)
        acked, summary = agent.post_batch(outbox, outbox.batch())
        assert acked == [e1["event_id"]]
        assert outbox.count() == 1
        assert outbox.batch()[0]["event_id"] == e2["event_id"]
        assert "pending=1" in summary
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_geoip_enrichment_uses_local_readers_and_only_global_ip():
    from types import SimpleNamespace
    from server_agent.chainlog_server_agent import enrich_event_geoip

    city_reader = SimpleNamespace(city=lambda _ip: SimpleNamespace(
        country=SimpleNamespace(name="Example Country"),
        subdivisions=SimpleNamespace(most_specific=SimpleNamespace(name="Example Region")),
        city=SimpleNamespace(name="Example City"),
        location=SimpleNamespace(accuracy_radius=25, latitude=40.7128, longitude=-74.0060),
    ))
    asn_reader = SimpleNamespace(asn=lambda _ip: SimpleNamespace(
        autonomous_system_number=64500,
        autonomous_system_organization="Example Network",
    ))
    event = {"source_ip": "8.8.8.8"}
    enriched = enrich_event_geoip(event, city_reader, asn_reader)
    assert enriched["source_city"] == "Example City"
    assert enriched["source_country"] == "Example Country"
    assert enriched["source_asn"] == "AS64500"
    assert enriched["source_geo_accuracy"] == "approximate; radius 25 km"
    assert enriched["source_latitude"] == 40.7128
    assert enriched["source_longitude"] == -74.006

    private_event = {"source_ip": "192.168.1.20"}
    enrich_event_geoip(private_event, city_reader, asn_reader)
    assert "source_city" not in private_event
    assert "source_asn" not in private_event


def test_parse_configured_webroot_auditd_group(tmp_path, monkeypatch):
    from server_agent import chainlog_server_agent as agent
    root = tmp_path / "webroot"
    root.mkdir()
    monkeypatch.setattr(agent, "WATCH_ROOTS", (str(root),))
    lines = [
        'type=SYSCALL msg=audit(1760000000.123:778): arch=c000003e syscall=257 success=yes exit=3 auid=1001 uid=1000 euid=1000 key="kawal_trace_webroot"',
        f'type=PATH msg=audit(1760000000.123:778): item=0 name="{root}/index.html" inode=1234 nametype=NORMAL',
        'type=EOE msg=audit(1760000000.123:778):',
    ]
    event = agent.parse_audit_group(lines, "srv-test")
    assert event is not None
    assert event["event_type"] == "FILE_CHANGE"
    assert event["details"]["rule_key"] == "kawal_trace_webroot"


def test_parse_webroot_rejects_path_outside_explicit_root(tmp_path, monkeypatch):
    from server_agent import chainlog_server_agent as agent
    root = tmp_path / "webroot"
    root.mkdir()
    monkeypatch.setattr(agent, "WATCH_ROOTS", (str(root),))
    lines = [
        'type=SYSCALL msg=audit(1760000000.123:779): arch=c000003e syscall=257 success=yes exit=3 auid=1001 uid=1000 euid=1000 key="kawal_trace_webroot"',
        'type=PATH msg=audit(1760000000.123:779): item=0 name="/etc/passwd" inode=1234 nametype=NORMAL',
        'type=EOE msg=audit(1760000000.123:779):',
    ]
    assert agent.parse_audit_group(lines, "srv-test") is None


def test_clamav_detection_requires_explicit_scan_root_and_signature_match(tmp_path, monkeypatch):
    import subprocess
    from server_agent import chainlog_server_agent as agent
    root = tmp_path / "scanroot"
    root.mkdir()
    target = root / "suspicious.bin"
    target.write_bytes(b"test fixture only; not real malware")
    monkeypatch.setattr(agent, "CLAMSCAN_ENABLED", True)
    monkeypatch.setattr(agent, "SCAN_ROOTS", (str(root),))
    monkeypatch.setattr(agent.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, stdout=f"{target}: Example.Test.Signature FOUND\n", stderr=""))
    file_event = {
        "event_id": stable_event_id("srv-test", "linux-auditd", "fixture"),
        "timestamp_utc": "2026-10-21T00:00:00Z", "host_id": "srv-test",
        "source": "linux-auditd", "event_type": "FILE_CHANGE", "actor": "uid:1000",
        "source_ip": "", "details": {"path": str(target), "rule_key": "kawal_trace_webroot"},
    }
    malware = agent.scan_changed_file(file_event)
    assert malware is not None
    assert malware["event_type"] == "MALWARE_DETECTED"
    assert malware["details"]["signature_name"] == "Example.Test.Signature"
    assert malware["event_id"] != file_event["event_id"]


@pytest.mark.parametrize(
    ("nametype", "expected"),
    [("CREATE", "file_created"), ("DELETE", "file_deleted"), ("NORMAL", "file_modified")],
)
def test_auditd_file_change_operation_is_classified(nametype, expected, monkeypatch):
    from server_agent import chainlog_server_agent as agent
    monkeypatch.setattr(agent, "WATCH_ROOTS", ("/home/server/Anime_Projeck",))
    lines = [
        'type=SYSCALL msg=audit(1760000000.123:778): arch=c000003e syscall=257 success=yes exit=3 auid=1001 uid=0 euid=0 key="kawal_trace_webroot"',
        'type=PATH msg=audit(1760000000.123:778): item=0 name="/home/server/Anime_Projeck/a.txt" inode=1235 nametype=' + nametype,
        'type=EOE msg=audit(1760000000.123:778):',
    ]
    event = parse_audit_group(lines, "srv-test")
    assert event is not None
    assert event["event_type"] == "FILE_CHANGE"
    assert event["details"]["reason"] == expected


def test_auditd_rename_is_detected_from_create_and_delete_path_records(monkeypatch):
    from server_agent import chainlog_server_agent as agent
    monkeypatch.setattr(agent, "WATCH_ROOTS", ("/home/server/Anime_Projeck",))
    lines = [
        'type=SYSCALL msg=audit(1760000000.124:779): arch=c000003e syscall=82 success=yes exit=0 auid=1001 uid=0 euid=0 key="kawal_trace_webroot"',
        'type=PATH msg=audit(1760000000.124:779): item=0 name="/home/server/Anime_Projeck/old.txt" inode=1235 nametype=DELETE',
        'type=PATH msg=audit(1760000000.124:779): item=1 name="/home/server/Anime_Projeck/new.txt" inode=1236 nametype=CREATE',
        'type=EOE msg=audit(1760000000.124:779):',
    ]
    event = parse_audit_group(lines, "srv-test")
    assert event is not None and event["details"]["reason"] == "file_renamed"


def test_filesystem_watch_health_reports_ready_only_when_root_audit_and_rule_are_ready():
    event = build_filesystem_watch_health_event(
        "srv-test", roots=["/home/server/Anime_Projeck"], audit_log_readable=True,
        auditd_active=True,
        active_rules_text="-a always,exit -F dir=/home/server/Anime_Projeck -F perm=wa -k kawal_trace_webroot",
        watch_roots_exist=True, now_epoch=1760000040,
    )
    assert event["event_type"] == "AGENT_HEALTH"
    assert event["source"] == "linux-agent"
    assert event["details"]["service"] == "filesystem-watch"
    assert event["details"]["result"] == "READY"
    assert event["details"]["path"] == "/home/server/Anime_Projeck"


def test_filesystem_watch_health_never_reports_ready_when_root_is_missing_or_rule_is_unverified():
    missing = build_filesystem_watch_health_event(
        "srv-test", roots=["/home/server/Anime_Projeck"], audit_log_readable=True,
        auditd_active=True, active_rules_text="", watch_roots_exist=False, now_epoch=1760000040,
    )
    unverified = build_filesystem_watch_health_event(
        "srv-test", roots=["/home/server/Anime_Projeck"], audit_log_readable=True,
        auditd_active=True, active_rules_text=None, watch_roots_exist=True, now_epoch=1760000100,
    )
    assert missing["details"]["reason"] == "WATCH_ROOT_MISSING"
    assert missing["details"]["result"] == "WAITING"
    assert unverified["details"]["reason"] == "AUDIT_RULE_STATUS_UNVERIFIED"
    assert unverified["details"]["result"] == "WAITING"
