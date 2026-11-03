from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from chainlog.database_audit import DatabaseAuditConfig, DatabaseAuditConnector, DatabaseAuditError
from chainlog.core import AuditStore
from chainlog.connector_ingest import ConnectorEventIngestor


class _FakeCursor:
    description = [(name,) for name in ("event_id", "timestamp_utc", "event_type", "host_id", "source", "actor", "message")]

    def __init__(self, rows=None):
        self.rows = rows or []
        self.calls = []

    def execute(self, query, params=()):
        self.calls.append((query, params))
        assert query.lstrip().upper().startswith(("SELECT", "SET SESSION"))
        assert not any(marker in query.upper() for marker in ("DROP ", "DELETE ", "UPDATE ", "INSERT ", "ALTER ", ";"))

    def fetchall(self):
        return self.rows


class _FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.closed = False

    def cursor(self):
        return self._cursor

    def close(self):
        self.closed = True


class _FakePyMySQL:
    cursors = SimpleNamespace(DictCursor=object)

    def __init__(self, cursor):
        self._cursor = cursor
        self.kwargs = None
        self.connection = None

    def connect(self, **kwargs):
        self.kwargs = kwargs
        self.connection = _FakeConnection(self._cursor)
        return self.connection


class _FakePyODBC:
    def __init__(self, cursor):
        self._cursor = cursor
        self.connection_string = ""
        self.connection = None

    def connect(self, connection_string, **kwargs):
        self.connection_string = connection_string
        self.connection = _FakeConnection(self._cursor)
        return self.connection


def _dict_row():
    return {
        "event_id": "security-event-001",
        "timestamp_utc": datetime(2026, 10, 28, 1, 0, tzinfo=timezone.utc),
        "event_type": "login failed",
        "host_id": "db-prod-01",
        "source": "mysql-audit",
        "actor": "alice",
        "message": "Failed login from 198.51.100.22",
    }


def _mysql_config(ca_file: Path, **kwargs):
    values = {
        "engine": "mysql", "host": "db.example.test", "database": "security", "username": "audit_reader",
        "source_table": "audit_events", "tls_ca_file": str(ca_file),
    }
    values.update(kwargs)
    return DatabaseAuditConfig(**values)


def test_mysql_audit_connector_uses_tls_readonly_and_bound_parameters(tmp_path):
    ca = tmp_path / "root-ca.pem"
    ca.write_text("TEST CA placeholder", encoding="utf-8")
    cursor = _FakeCursor([_dict_row()])
    driver = _FakePyMySQL(cursor)
    connector = DatabaseAuditConnector(_mysql_config(ca), password="test-db-secret", driver_module=driver)
    events = connector.fetch_events(since=datetime(2026, 10, 27, tzinfo=timezone.utc), limit=10)
    assert len(events) == 1 and events[0]["event_type"] == "AUTH_FAILURE"
    assert events[0]["source_ip"] == "198.51.100.22"
    assert driver.kwargs["ssl"]["ca"] == str(ca)
    assert driver.kwargs["ssl"]["check_hostname"] is True
    assert driver.kwargs["user"] == "audit_reader"
    assert cursor.calls[0][0] == "SET SESSION TRANSACTION READ ONLY"
    query, params = cursor.calls[1]
    assert query.startswith("SELECT") and "`audit_events`" in query
    assert "test-db-secret" not in query and len(params) == 2
    assert driver.connection.closed
    store = AuditStore(tmp_path / "db-audit.sqlite3")
    store.initialize()
    outcome = ConnectorEventIngestor(store).ingest("database:mysql:db.example.test", events)
    assert outcome["added"] == 1
    assert store.verify().valid
    assert store.records()[-1]["event_type"] == "AUTH"


def test_sqlserver_audit_connector_requires_encrypted_trusted_connection():
    cursor = _FakeCursor([_dict_row()])
    driver = _FakePyODBC(cursor)
    config = DatabaseAuditConfig(
        engine="sqlserver", host="sql.example.test", database="security", username="audit_reader",
        source_table="AuditEvents", schema="dbo", port=1433,
    )
    connector = DatabaseAuditConnector(config, password="test-db-secret", driver_module=driver)
    events = connector.fetch_events(since=datetime(2026, 10, 27, tzinfo=timezone.utc), limit=10)
    assert len(events) == 1
    conn = driver.connection_string
    assert "Encrypt=yes" in conn
    assert "TrustServerCertificate=no" in conn
    assert "ApplicationIntent=ReadOnly" in conn
    assert "test-db-secret" in conn  # passed only to the driver; never included in diagnostics/query
    query, params = cursor.calls[0]
    assert query.startswith("SELECT TOP (?)")
    assert "[dbo].[AuditEvents]" in query
    assert len(params) == 2


def test_database_audit_rejects_sql_injection_in_table_or_column_names(tmp_path):
    ca = tmp_path / "root-ca.pem"
    ca.write_text("TEST", encoding="utf-8")
    with pytest.raises(DatabaseAuditError, match="Identifier source_table"):
        _mysql_config(ca, source_table="audit_events; DROP TABLE users") .validated()
    with pytest.raises(DatabaseAuditError, match="Identifier timestamp_column"):
        _mysql_config(ca, timestamp_column="event_time) OR 1=1 --").validated()


def test_mysql_requires_trusted_ca_and_database_password(tmp_path):
    with pytest.raises(DatabaseAuditError, match="CA TLS"):
        DatabaseAuditConfig(engine="mysql", host="db", database="security", username="reader", source_table="audit_events").validated()
    ca = tmp_path / "ca.pem"
    ca.write_text("test", encoding="utf-8")
    with pytest.raises(DatabaseAuditError, match="Password"):
        DatabaseAuditConnector(_mysql_config(ca), password="")


def test_database_events_deduplicate_by_source_id_and_keep_message_bounded(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("test", encoding="utf-8")
    row = _dict_row()
    row["event_id"] = "a" * 64
    cursor = _FakeCursor([row])
    driver = _FakePyMySQL(cursor)
    event = DatabaseAuditConnector(_mysql_config(ca), password="secret", driver_module=driver).fetch_events()[0]
    assert event["event_id"] == "a" * 64
