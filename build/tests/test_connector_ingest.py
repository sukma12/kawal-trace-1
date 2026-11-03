from __future__ import annotations

from chainlog.core import AuditStore
from chainlog.connector_ingest import ConnectorEventIngestor


def _event(event_id="a" * 64, event_type="AUTH_FAILURE"):
    return {
        "event_id": event_id,
        "timestamp_utc": "2026-10-28T01:20:00.000Z",
        "event_type": event_type,
        "host_id": "lab-server",
        "source": "sshd",
        "actor": "alice",
        "source_ip": "198.51.100.20",
        "details": {"reason": "authentication_failed", "message_excerpt": "Failed password",
                    "path": "/home/server/Anime_Projeck/index.js", "rule_key": "kawal_trace_webroot"},
    }


def test_connector_events_are_appended_to_verified_hash_chain_and_deduplicated_across_restart(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    ingestor = ConnectorEventIngestor(store)
    assert ingestor.ingest("ssh:lab-server", [_event()]) == {"added": 1, "skipped_duplicate": 0, "rejected": 0}
    assert store.verify().valid
    record = store.records()[-1]
    assert record["event_type"] == "AUTH"
    assert record["source"] == "connector:ssh:lab-server"
    assert record["details"]["source_event_id"] == "a" * 64
    assert record["details"]["path"] == "/home/server/Anime_Projeck/index.js"
    assert record["details"]["rule_key"] == "kawal_trace_webroot"

    # A fresh ingestor sees the prior event ID in the persisted chain.
    restarted = ConnectorEventIngestor(AuditStore(tmp_path / "audit.sqlite3"))
    assert restarted.ingest("ssh:lab-server", [_event()]) == {"added": 0, "skipped_duplicate": 1, "rejected": 0}
    assert len(store.records()) == 2  # initialized record + one source event
    assert store.verify().valid


def test_connector_event_types_map_to_restricted_audit_categories(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.initialize()
    ingestor = ConnectorEventIngestor(store)
    events = [
        _event("1" * 64, "PRIVILEGE_USE"),
        _event("2" * 64, "FILE_CHANGE"),
        _event("3" * 64, "MALWARE_DETECTED"),
        _event("4" * 64, "CUSTOM_SECURITY_EVENT"),
    ]
    assert ingestor.ingest("syslog:loopback", events)["added"] == 4
    assert [r["event_type"] for r in store.records()[-4:]] == ["ACCESS", "CONFIG", "ALERT", "NOTE"]
    assert store.verify().valid
