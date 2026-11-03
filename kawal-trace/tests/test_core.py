from __future__ import annotations

import json
import sqlite3

import pytest

from chainlog.core import AuditStore, IntegrityError, ValidationError, verify_records


@pytest.fixture
def store(tmp_path):
    item = AuditStore(tmp_path / "chainlog.sqlite3")
    item.initialize()
    return item


def test_initialize_and_append_verify(store):
    assert store.verify().valid
    start = store.records()
    assert len(start) == 1
    assert start[0]["previous_hash"] == "0" * 64

    store.add_event("AUTH", "tester", "unit-test", {"result": "ok"})
    result = store.verify()
    assert result.valid
    assert result.count == 2
    assert store.records()[-1]["previous_hash"] == store.records()[-2]["record_hash"]


def test_virtual_simulation_does_not_modify_database(store):
    store.add_event("ACCESS", "tester", "unit-test", {"message": "original"})
    before = store.records()
    result = store.simulate_tampering()
    after = store.records()

    assert not result.valid
    assert "SIMULASI" in result.reason
    assert before == after
    assert store.verify().valid


def test_real_tamper_is_detected_and_append_is_blocked(store):
    store.add_event("ACCESS", "tester", "unit-test", {"message": "original"})
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("DROP TRIGGER deny_log_update")
        conn.execute("UPDATE log_entries SET details_json = ? WHERE seq = 2", (json.dumps({"message": "changed"}),))

    result = store.verify()
    assert not result.valid
    assert result.failing_seq == 2
    with pytest.raises(IntegrityError):
        store.add_event("NOTE", "tester", "unit-test", "must be blocked")


def test_sqlite_guardrails_reject_update_and_delete(store):
    with sqlite3.connect(store.db_path) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE log_entries SET actor = 'attacker' WHERE seq = 1")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM log_entries WHERE seq = 1")


def test_invalid_type_is_rejected(store):
    with pytest.raises(ValidationError):
        store.add_event("UNKNOWN", "tester", "test", "x")


def test_exports_created(store):
    store.add_event("NOTE", "tester", "unit-test", {"text": "ekspor"})
    json_path = store.export_json()
    csv_path = store.export_csv()
    assert json_path.exists() and csv_path.exists()
    bundle = json.loads(json_path.read_text(encoding="utf-8"))
    assert bundle["record_count"] == 2
    assert bundle["verification"]["valid"] is True
    assert "record_hash" in csv_path.read_text(encoding="utf-8-sig")


def test_sequence_tamper_detected(store):
    records = store.records()
    altered = [dict(r) for r in records]
    altered[0]["seq"] = 4
    assert not verify_records(altered).valid
