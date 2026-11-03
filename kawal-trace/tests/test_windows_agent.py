from __future__ import annotations

import json
from pathlib import Path

import pytest

from windows_agent.eventlog_agent import (
    WindowsOutbox,
    parse_windows_event_xml,
    stable_event_id,
    validate_windows_action,
)

NS = 'http://schemas.microsoft.com/win/2004/08/events/event'

def event_xml(event_id: int, record_id: int, data: dict[str, str], *, logon_time: str = '2026-10-21T00:00:00.000Z') -> str:
    items = ''.join(f'<Data Name="{name}">{value}</Data>' for name, value in data.items())
    return f'''<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{event_id}</EventID><TimeCreated SystemTime="{logon_time}"/><EventRecordID>{record_id}</EventRecordID><Channel>Security</Channel></System><EventData>{items}</EventData></Event>'''


def test_windows_4625_parses_auth_failure_without_secrets():
    event = parse_windows_event_xml(event_xml(4625, 801, {
        'TargetUserName': 'test-user', 'TargetDomainName': 'LAB', 'IpAddress': '8.8.8.8',
        'LogonType': '10', 'Status': '0xC000006D', 'CommandLine': 'secret=do-not-upload',
    }), 'win-lab-01')
    assert event is not None
    assert event['event_type'] == 'AUTH_FAILURE'
    assert event['source_ip'] == '8.8.8.8'
    assert event['actor'] == 'LAB\\test-user'
    assert event['details']['windows_event_id'] == '4625'
    assert 'secret=do-not-upload' not in json.dumps(event)
    assert 'remote_interactive_rdp' in event['details']['reason']


def test_windows_1102_audit_log_clear_is_preserved_as_security_event():
    event = parse_windows_event_xml(event_xml(1102, 802, {'SubjectUserName': 'operator'}), 'win-lab-01')
    assert event is not None
    assert event['details']['reason'] == 'windows_security_audit_log_cleared'
    assert event['details']['windows_event_id'] == '1102'


def test_windows_parser_rejects_malformed_xml_and_unknown_ids_without_throwing():
    assert parse_windows_event_xml('<broken', 'win-lab-01') is None
    unknown = parse_windows_event_xml(event_xml(99999, 803, {'TargetUserName': 'somebody'}), 'win-lab-01')
    assert unknown is not None
    assert unknown['event_type'] == 'CUSTOM_SECURITY_EVENT'


def test_windows_action_policy_requires_public_ipv4_and_bounded_ttl():
    action = {'action': 'WINDOWS_BLOCK_IP', 'parameters': {'source_ip': '8.8.8.8'}, 'ttl_seconds': 300}
    assert validate_windows_action(action, protected_users={'Administrator'}, protected_processes=set())[1] == {'source_ip': '8.8.8.8', 'ttl_seconds': 300}
    for ip, ttl in [('127.0.0.1', 300), ('10.0.0.8', 300), ('8.8.8.8', 120)] :
        with pytest.raises(ValueError):
            validate_windows_action({'action':'WINDOWS_BLOCK_IP','parameters':{'source_ip':ip},'ttl_seconds':ttl}, protected_users=set(), protected_processes=set())


def test_windows_action_policy_protects_admin_and_limits_session_or_process():
    with pytest.raises(ValueError, match='target_user_is_protected'):
        validate_windows_action({'action':'WINDOWS_LOGOFF_SESSION','parameters':{'session_id':4,'target_user':'Administrator'}}, protected_users={'Administrator'}, protected_processes=set())
    with pytest.raises(ValueError, match='process_name_not_in_safe_allowlist'):
        validate_windows_action({'action':'WINDOWS_TERMINATE_PROCESS','parameters':{'pid':455,'target_user':'tester','process_name':'lsass.exe'}}, protected_users={'Administrator'}, protected_processes={'lsass.exe'})
    with pytest.raises(ValueError, match='process_name_not_in_safe_allowlist'):
        validate_windows_action({'action':'WINDOWS_TERMINATE_PROCESS','parameters':{'pid':455,'target_user':'tester','process_name':'chrome.exe'}}, protected_users={'Administrator'}, protected_processes=set())


def test_windows_outbox_chain_detects_pending_payload_tamper(tmp_path):
    outbox = WindowsOutbox(tmp_path / 'win-outbox.sqlite3')
    event = {'event_id': stable_event_id('win-host','Security',10), 'timestamp_utc':'2026-10-21T00:00:00Z','host_id':'win-host','source':'windows-eventlog','event_type':'AUTH_FAILURE','actor':'tester','source_ip':'8.8.8.8','details':{'reason':'test'}}
    outbox.enqueue(event)
    ok, head, count = outbox.verify_chain()
    assert ok and count == 1 and len(head) == 64
    with outbox.connect() as conn:
        conn.execute("UPDATE outbox SET payload_json='{}' WHERE event_id=?", (event['event_id'],))
    ok, message, count = outbox.verify_chain()
    assert not ok and 'pending payload changed' in message


def test_windows_outbox_detects_chain_link_tamper(tmp_path):
    outbox = WindowsOutbox(tmp_path / 'win-outbox.sqlite3')
    for n in range(2):
        event = {'event_id': stable_event_id('win-host','Security',n+1), 'timestamp_utc':'2026-10-21T00:00:00Z','host_id':'win-host','source':'windows-eventlog','event_type':'CUSTOM_SECURITY_EVENT','details':{'n':n}}
        outbox.enqueue(event)
    with outbox.connect() as conn:
        conn.execute("UPDATE chain_entries SET previous_hash=? WHERE seq=2", ('f'*64,))
    ok, message, _ = outbox.verify_chain()
    assert not ok and 'chain link/sequence mismatch' in message


def test_windows_first_run_baselines_at_latest_event_without_replaying_history(tmp_path):
    from types import SimpleNamespace
    from windows_agent.eventlog_agent import collect_windows_events

    outbox = WindowsOutbox(tmp_path / "first-run.sqlite3")
    def fake_runner(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps([
            {"Channel": "Security", "RecordId": 9000, "Baseline": True},
            {"Channel": "System", "RecordId": 700, "Baseline": True},
        ]), stderr="")
    count = collect_windows_events("win-first-install", outbox, run_command=fake_runner)
    assert count == 0
    assert outbox.cursor("Security") == 9000
    assert outbox.cursor("System") == 700
    assert outbox.batch() == []


def test_windows_event_collection_uses_defender_cursor_and_powershell_env_lookup(tmp_path):
    from types import SimpleNamespace
    from windows_agent.eventlog_agent import collect_windows_events, POWERSHELL_SCRIPT

    outbox = WindowsOutbox(tmp_path / "cursor-map.sqlite3")
    outbox.advance_cursor("Security", 101)
    outbox.advance_cursor("System", 202)
    outbox.advance_cursor("Microsoft-Windows-Windows Defender/Operational", 303)
    seen = {}
    def fake_runner(args, **kwargs):
        seen.update(kwargs.get("env", {}))
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")
    collect_windows_events("win-cursors", outbox, run_command=fake_runner)
    assert seen["KAWAL_LAST_SECURITY"] == "101"
    assert seen["KAWAL_LAST_SYSTEM"] == "202"
    assert seen["KAWAL_LAST_DEFENDER"] == "303"
    assert '[System.Environment]::GetEnvironmentVariable($cursorEnvName)' in POWERSHELL_SCRIPT


def test_rdp_logoff_requires_remote_interactive_rdp_evidence(tmp_path):
    from datetime import datetime, timezone

    outbox = WindowsOutbox(tmp_path / "rdp-evidence.sqlite3")
    base = {
        "event_id": stable_event_id("win-host", "Security", 9901),
        "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "host_id": "win-host",
        "source": "windows-eventlog",
        "event_type": "AUTH_SUCCESS",
        "actor": "LAB\\tester",
        "source_ip": "8.8.8.8",
        "details": {"reason": "windows_logon_success"},
    }
    outbox.enqueue(base)
    assert outbox.has_recent_evidence("AUTH_SUCCESS", actor="LAB\\tester", reason="windows_logon_success", hours=24)
    assert not outbox.has_recent_evidence("AUTH_SUCCESS", actor="LAB\\tester", reason="windows_logon_success; remote_interactive_rdp", hours=24)

    rdp = dict(base)
    rdp["event_id"] = stable_event_id("win-host", "Security", 9902)
    rdp["details"] = {"reason": "windows_logon_success; remote_interactive_rdp"}
    outbox.enqueue(rdp)
    assert outbox.has_recent_evidence("AUTH_SUCCESS", actor="LAB\\tester", reason="windows_logon_success; remote_interactive_rdp", hours=24)
