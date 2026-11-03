"""Safe local self-test for the telemetry -> detection -> archive pipeline.

Only synthetic documentation-range IPs and clearly labelled test events are used.
No network request, server change, real login, or notification is generated.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .detection import DetectionEngine
from .server_archive import ServerEventArchive


def run_telemetry_self_test(archive_path: str | Path) -> dict[str, Any]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    profile_id = "SELFTEST-LOCAL-0001"
    events: list[dict[str, Any]] = []
    for index, seconds_ago in enumerate((40, 15), start=1):
        stamp = now - timedelta(seconds=seconds_ago)
        event_id = hashlib.sha256(f"kawal-trace-self-test:{now.isoformat()}:{index}".encode()).hexdigest()
        events.append({
            "event_id": event_id,
            "timestamp_utc": stamp.isoformat().replace("+00:00", "Z"),
            "timestamp_epoch": stamp.timestamp(),
            "host_id": "SELF-TEST-LOCAL",
            "source": "kawal-trace-self-test",
            "event_type": "AUTH_FAILURE",
            "actor": "synthetic-test-user",
            "source_ip": "192.0.2.44",  # TEST-NET-1; not a real client address
            "details": {"reason": "synthetic self-test only"},
        })

    alerts = DetectionEngine(auth_failure_threshold=2, window_seconds=300).evaluate(events)
    matching = [alert for alert in alerts if alert.rule_id == "AUTH_FAILURE_BURST"]
    if not matching:
        raise RuntimeError("Deteksi gagal: dua event sintetis tidak menghasilkan AUTH_FAILURE_BURST.")

    archive = ServerEventArchive(Path(archive_path), cipher=None)
    inserted = archive.add_events(profile_id, "Kawal Trace local self-test", events)
    read_back = archive.list_events(profile_id, "all")
    if inserted != 2 or len(read_back) != 2:
        raise RuntimeError(f"Arsip gagal diverifikasi: inserted={inserted}, read_back={len(read_back)}.")
    duplicate_inserted = archive.add_events(profile_id, "Kawal Trace local self-test", events)
    if duplicate_inserted != 0:
        raise RuntimeError("Idempotensi arsip gagal: event duplikat tersimpan kembali.")

    return {
        "status": "passed",
        "stages": {
            "event_validation": "passed",
            "detection": "passed",
            "archive_write": "passed",
            "archive_readback": "passed",
            "duplicate_protection": "passed",
        },
        "synthetic_events": len(events),
        "archive_readback": len(read_back),
        "alerts": len(matching),
        "alert_rule": matching[0].rule_id,
        "test_only": True,
        "network_used": False,
    }
