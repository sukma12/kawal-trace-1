from __future__ import annotations

from chainlog.notification_policy import find_new_event_ids


def test_initial_feed_baselines_old_history_but_keeps_recent_incident_alertable():
    now = 2_000_000_000.0
    seen: dict[str, set[str]] = {}
    initialized: set[str] = set()
    events = [
        {"event_id": "old-event", "timestamp_epoch": now - 3600},
        {"event_id": "recent-failure-1", "timestamp_epoch": now - 60},
        {"event_id": "recent-failure-2", "timestamp_epoch": now - 30},
        {"event_id": "future-bad-clock", "timestamp_epoch": now + 3600},
    ]
    new_ids = find_new_event_ids("profile-a", events, seen, initialized, now_epoch=now)
    assert new_ids == {"recent-failure-1", "recent-failure-2"}
    assert seen["profile-a"] == {"old-event", "recent-failure-1", "recent-failure-2", "future-bad-clock"}
    assert "profile-a" in initialized


def test_subsequent_poll_returns_only_new_ids():
    now = 2_000_000_000.0
    seen: dict[str, set[str]] = {"profile-a": {"already-seen"}}
    initialized = {"profile-a"}
    events = [
        {"event_id": "already-seen", "timestamp_epoch": now},
        {"event_id": "new-event", "timestamp_epoch": now},
    ]
    assert find_new_event_ids("profile-a", events, seen, initialized, now_epoch=now) == {"new-event"}


def test_missing_ids_or_invalid_timestamps_do_not_create_initial_alert_candidates():
    seen: dict[str, set[str]] = {}
    initialized: set[str] = set()
    events = [
        {"event_id": "invalid-time", "timestamp_epoch": "not-a-time"},
        {"timestamp_epoch": 2_000_000_000.0},
    ]
    assert find_new_event_ids("profile-a", events, seen, initialized, now_epoch=2_000_000_000.0) == set()


def test_recent_failed_login_burst_on_first_connect_is_alertable():
    from datetime import datetime, timedelta, timezone
    from chainlog.detection import DetectionEngine

    now = 2_000_000_000.0
    now_dt = datetime.fromtimestamp(now, timezone.utc)
    events = []
    for index, seconds_ago in ((1, 60), (2, 30)):
        stamp = now_dt - timedelta(seconds=seconds_ago)
        events.append({
            "event_id": f"{index:064x}",
            "timestamp_utc": stamp.isoformat().replace("+00:00", "Z"),
            "timestamp_epoch": stamp.timestamp(),
            "host_id": "lab-ssh-01",
            "source": "sshd.service",
            "event_type": "AUTH_FAILURE",
            "actor": "unknown",
            "source_ip": "198.51.100.77",
            "details": {"reason": "bad password"},
        })
    seen: dict[str, set[str]] = {}
    initialized: set[str] = set()
    new_ids = find_new_event_ids("profile-a", events, seen, initialized, now_epoch=now)
    alerts = DetectionEngine().evaluate(events)
    burst_alerts = [alert for alert in alerts if alert.rule_id == "AUTH_FAILURE_BURST"]
    assert burst_alerts
    assert any(set(alert.event_ids) & new_ids for alert in burst_alerts)
