from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from chainlog.server_archive import (
    ArchiveError,
    ServerArchiveRemoteClient,
    ServerEventArchive,
    export_archive_csv,
    export_archive_json,
    export_archive_pdf,
)


def event(event_id: str, stamp: str, actor: str = "tester"):
    return {
        "event_id": event_id,
        "timestamp_utc": stamp,
        "event_type": "AUTH_FAILURE",
        "host_id": "lab-host",
        "source": "linux-journal",
        "actor": actor,
        "source_ip": "192.0.2.50",
        "details": {"reason": "failed_password", "service": "sshd.service"},
    }


def test_archive_persists_deduplicates_and_partitions_by_utc_date(tmp_path):
    path = tmp_path / "server-archive.sqlite3"
    archive = ServerEventArchive(path)
    assert archive.add_events("srv-test-profile-001", "Lab", [
        event("a" * 64, "2026-10-21T23:59:59Z"),
        event("b" * 64, "2026-10-22T00:00:01Z"),
    ]) == 2
    assert archive.add_events("srv-test-profile-001", "Lab", [event("a" * 64, "2026-10-21T23:59:59Z")]) == 0
    assert archive.date_counts("srv-test-profile-001") == [
        {"date": "2026-10-22", "count": 1}, {"date": "2026-10-21", "count": 1}
    ]
    assert len(archive.list_events("srv-test-profile-001", "2026-10-21")) == 1
    reopened = ServerEventArchive(path)
    assert len(reopened.list_events("srv-test-profile-001", "all")) == 2


def test_archive_rejects_same_event_id_with_changed_contents(tmp_path):
    archive = ServerEventArchive(tmp_path / "a.sqlite3")
    archive.add_events("srv-test-profile-001", "Lab", [event("c" * 64, "2026-10-22T01:00:00Z")])
    with pytest.raises(ArchiveError, match="isi berbeda"):
        archive.add_events("srv-test-profile-001", "Lab", [event("c" * 64, "2026-10-22T01:00:00Z", actor="changed")])


def test_archive_rejects_timezone_naive_and_bad_dates(tmp_path):
    archive = ServerEventArchive(tmp_path / "a.sqlite3")
    with pytest.raises(ArchiveError, match="zona waktu"):
        archive.add_events("srv-test-profile-001", "Lab", [event("d" * 64, "2026-10-22T01:00:00")])
    with pytest.raises(ArchiveError, match="Tanggal arsip"):
        archive.list_events("srv-test-profile-001", "2026-99-99")


def test_archive_remote_queue_is_idempotent(tmp_path):
    archive = ServerEventArchive(tmp_path / "a.sqlite3")
    archive.add_events("srv-test-profile-001", "Lab", [event("e" * 64, "2026-10-22T01:00:00Z")])
    assert len(archive.pending_upload("srv-test-profile-001", "srv-dest-profile-001")) == 1
    archive.mark_uploaded("srv-test-profile-001", "srv-dest-profile-001", ["e" * 64])
    assert archive.pending_upload("srv-test-profile-001", "srv-dest-profile-001") == []
    assert archive.upload_count("srv-test-profile-001", "srv-dest-profile-001") == 1


def test_export_json_csv_pdf(tmp_path):
    archive = ServerEventArchive(tmp_path / "a.sqlite3")
    archive.add_events("srv-test-profile-001", "Lab", [event("f" * 64, "2026-10-22T01:00:00Z")])
    events = archive.list_events("srv-test-profile-001", "2026-10-22")
    json_path = export_archive_json(tmp_path / "one.json", "srv-test-profile-001", "Lab", "2026-10-22", events)
    csv_path = export_archive_csv(tmp_path / "one.csv", events)
    pdf_path = export_archive_pdf(tmp_path / "one.pdf", "Lab", "2026-10-22", events)
    body = json.loads(json_path.read_text(encoding="utf-8"))
    assert body["event_count"] == 1
    assert "timestamp_utc" in csv_path.read_text(encoding="utf-8-sig")
    assert pdf_path.read_bytes().startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_path.read_bytes()


def test_remote_client_rejects_plain_http_public_url():
    with pytest.raises(ArchiveError, match="HTTPS"):
        ServerArchiveRemoteClient("http://archive.example.com", "device-123456", "x" * 48)


def test_server_only_purge_removes_payload_but_keeps_upload_receipts(tmp_path):
    archive = ServerEventArchive(tmp_path / "a.sqlite3")
    events = [event("1" * 64, "2026-10-22T01:00:00Z"), event("2" * 64, "2026-10-22T02:00:00Z")]
    archive.add_events("srv-test-profile-001", "Lab", events)
    archive.mark_uploaded("srv-test-profile-001", "srv-dest-profile-001", ["1" * 64])
    assert archive.purge_uploaded_events("srv-test-profile-001", "srv-dest-profile-001") == 1
    assert [item["event_id"] for item in archive.list_events("srv-test-profile-001", "all")] == ["2" * 64]
    pending = archive.pending_upload("srv-test-profile-001", "srv-dest-profile-001")
    assert [item["event_id"] for item in pending] == ["2" * 64]
    assert archive.upload_count("srv-test-profile-001", "srv-dest-profile-001") == 1


def test_explicitly_downloaded_pinned_copy_survives_server_only_purge(tmp_path):
    archive = ServerEventArchive(tmp_path / "a.sqlite3")
    archive.add_events("srv-test-profile-001", "Lab", [event("a" * 64, "2026-10-22T01:00:00Z")])
    archive.mark_uploaded("srv-test-profile-001", "srv-dest-profile-001", ["a" * 64])
    archive.pin_events("srv-test-profile-001", ["a" * 64])
    assert archive.purge_uploaded_events("srv-test-profile-001", "srv-dest-profile-001") == 0
    assert len(archive.list_events("srv-test-profile-001", "all")) == 1
