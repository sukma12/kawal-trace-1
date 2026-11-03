from __future__ import annotations

import socket
import ssl
import time

import pytest

from chainlog.syslog_connector import SyslogConnectorError, SyslogTCPReceiver, parse_syslog_message
from chainlog.core import AuditStore
from chainlog.connector_ingest import ConnectorEventIngestor


RFC5424_FAILED = b"<34>1 2026-10-28T01:20:00Z linux-lab sshd 123 ID47 - Failed password for alice from 198.51.100.20 port 22 ssh2"


def test_rfc5424_parser_maps_security_event_and_source_ip():
    event = parse_syslog_message(RFC5424_FAILED)
    assert event["event_type"] == "AUTH_FAILURE"
    assert event["host_id"] == "linux-lab"
    assert event["source"] == "sshd"
    assert event["actor"] == "alice"
    assert event["source_ip"] == "198.51.100.20"
    assert event["details"]["reason"] == "authentication_failed"


def test_rfc3164_parser_does_not_guess_missing_timezone():
    event = parse_syslog_message("<34>Oct 28 01:20:00 linux-lab sshd[123]: Failed password for alice from 198.51.100.20 port 22")
    assert event["event_type"] == "AUTH_FAILURE"
    assert event["source"] == "sshd"
    assert event["timestamp_utc"].endswith("Z")


def test_syslog_rejects_malformed_and_oversized_messages():
    with pytest.raises(SyslogConnectorError, match="RFC 5424"):
        parse_syslog_message("garbage message")
    with pytest.raises(SyslogConnectorError, match="64 KiB"):
        parse_syslog_message(b"x" * 65_537)


def test_syslog_receiver_ingests_tcp_framed_message_end_to_end_on_loopback():
    events = []
    receiver = SyslogTCPReceiver("127.0.0.1", 0, events.append)
    host, port = receiver.start()
    try:
        with socket.create_connection((host, port), timeout=2) as sock:
            sock.sendall(RFC5424_FAILED + b"\n")
        deadline = time.monotonic() + 2
        while not events and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(events) == 1
        assert events[0]["event_type"] == "AUTH_FAILURE"
        assert receiver.received_count == 1
    finally:
        receiver.close()


def test_syslog_receiver_supports_octet_counted_framing():
    events = []
    receiver = SyslogTCPReceiver("127.0.0.1", 0, events.append)
    host, port = receiver.start()
    try:
        with socket.create_connection((host, port), timeout=2) as sock:
            sock.sendall(str(len(RFC5424_FAILED)).encode() + b" " + RFC5424_FAILED)
        deadline = time.monotonic() + 2
        while not events and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(events) == 1
        assert events[0]["event_type"] == "AUTH_FAILURE"
    finally:
        receiver.close()


def test_non_loopback_plaintext_syslog_listener_is_rejected():
    with pytest.raises(SyslogConnectorError, match="TLS"):
        SyslogTCPReceiver("0.0.0.0", 514, lambda _event: None)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with pytest.raises(SyslogConnectorError, match="mTLS"):
        SyslogTCPReceiver("0.0.0.0", 514, lambda _event: None, tls_context=context)


def test_syslog_receiver_to_audit_chain_end_to_end(tmp_path):
    store = AuditStore(tmp_path / "syslog-audit.sqlite3")
    store.initialize()
    ingestor = ConnectorEventIngestor(store)
    connector_label = "syslog:127.0.0.1:1514"
    handler_results = []

    def accept(event):
        handler_results.append(ingestor.ingest(connector_label, [event]))

    receiver = SyslogTCPReceiver("127.0.0.1", 0, accept)
    host, port = receiver.start()
    try:
        with socket.create_connection((host, port), timeout=2) as sock:
            sock.sendall(RFC5424_FAILED + b"\n")
        deadline = time.monotonic() + 2
        while not handler_results and time.monotonic() < deadline:
            time.sleep(0.01)
        assert handler_results == [{"added": 1, "skipped_duplicate": 0, "rejected": 0}]
        assert receiver.received_count == 1
        assert store.verify().valid
        last = store.records()[-1]
        assert last["event_type"] == "AUTH"
        assert last["source"] == "connector:" + connector_label
        assert last["details"]["source_event_type"] == "AUTH_FAILURE"
    finally:
        receiver.close()


# Message-text patterns used by MikroTik RouterOS ("Winbox" is its admin GUI, not a log protocol). These samples are
# written from the documented message shapes and are carried in standard RFC 5424 framing; they were NOT captured from
# real hardware, and the framing a given RouterOS version emits has not been verified.
ROUTEROS_FAILURE = b"<34>1 2026-11-02T01:20:00Z edge-router system,error,critical - - - login failure for user admin from 203.0.113.50 via winbox"
ROUTEROS_SUCCESS = b"<38>1 2026-11-02T01:21:00Z edge-router system,info,account - - - user admin logged in from 203.0.113.50 via ssh"


def test_routeros_style_login_failure_is_an_auth_failure_with_actor_ip_and_method():
    event = parse_syslog_message(ROUTEROS_FAILURE)
    assert (event["event_type"], event["actor"], event["source_ip"]) == ("AUTH_FAILURE", "admin", "203.0.113.50")
    assert event["details"]["auth_method"] == "winbox"


def test_routeros_style_login_success_is_an_auth_success():
    event = parse_syslog_message(ROUTEROS_SUCCESS)
    assert (event["event_type"], event["actor"], event["source_ip"]) == ("AUTH_SUCCESS", "admin", "203.0.113.50")
    assert event["details"]["auth_method"] == "ssh"


def test_unrelated_messages_get_no_auth_method_and_stay_custom_events():
    event = parse_syslog_message(b"<34>1 2026-11-02T01:20:00Z edge-router system - - - interface ether1 link up")
    assert event["event_type"] == "CUSTOM_SECURITY_EVENT"
    assert "auth_method" not in event["details"]


def test_sshd_messages_are_unchanged_by_the_routeros_patterns():
    event = parse_syslog_message(RFC5424_FAILED)
    assert (event["event_type"], event["actor"]) == ("AUTH_FAILURE", "alice")
    assert "auth_method" not in event["details"]
