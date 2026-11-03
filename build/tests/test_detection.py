from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from chainlog.detection import DetectionEngine, TelemetryValidationError, normalize_server_event


def _event(event_id: int, event_type: str, ts: datetime, ip: str = "203.0.113.10", actor: str = "tester", **details):
    return {
        "event_id": f"{event_id:064x}",
        "timestamp_utc": ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "host_id": "srv-lab-01",
        "source": "sshd.service",
        "event_type": event_type,
        "actor": actor,
        "source_ip": ip,
        "details": details,
    }


def test_auth_failure_burst_and_success_after_failures_alert():
    now = datetime.now(timezone.utc)
    events = [_event(i + 1, "AUTH_FAILURE", now + timedelta(seconds=i * 15)) for i in range(5)]
    events.append(_event(6, "AUTH_SUCCESS", now + timedelta(seconds=90)))
    alerts = DetectionEngine().evaluate(events)
    rule_ids = {alert.rule_id for alert in alerts}
    assert "AUTH_FAILURE_BURST" in rule_ids
    assert "AUTH_SUCCESS_AFTER_FAILURES" in rule_ids
    assert any(alert.severity == "CRITICAL" for alert in alerts)


def test_remote_root_login_alerts_for_review():
    event = _event(10, "AUTH_SUCCESS", datetime.now(timezone.utc), actor="root", auth_method="ssh")
    alerts = DetectionEngine().evaluate([event])
    assert any(alert.rule_id == "ROOT_REMOTE_LOGIN" for alert in alerts)
    agent_style_event = _event(11, "AUTH_SUCCESS", datetime.now(timezone.utc), actor="root", service="sshd.service", auth_method="publickey")
    assert any(alert.rule_id == "ROOT_REMOTE_LOGIN" for alert in DetectionEngine().evaluate([agent_style_event]))


def test_sensitive_file_change_alerts_but_does_not_claim_intent():
    event = _event(20, "FILE_CHANGE", datetime.now(timezone.utc), ip="", path="/etc/ssh/sshd_config", rule_key="kawal_trace_sensitive")
    alerts = DetectionEngine().evaluate([event])
    assert alerts[0].rule_id == "SENSITIVE_FILE_CHANGE"
    assert "belum membuktikan niat" in alerts[0].description


def test_normalizer_discards_non_allowlisted_secret_fields():
    raw = _event(30, "AUTH_FAILURE", datetime.now(timezone.utc), password="dont-log-this", details_token="secret")
    normalized = normalize_server_event(raw)
    assert "password" not in normalized
    assert "details_token" not in normalized
    assert "password" not in normalized["details"]


def test_normalizer_rejects_bad_ip_and_timestamp():
    event = _event(40, "AUTH_FAILURE", datetime.now(timezone.utc), ip="not-an-ip")
    with pytest.raises(TelemetryValidationError):
        normalize_server_event(event)
    event = _event(41, "AUTH_FAILURE", datetime.now(timezone.utc))
    event["timestamp_utc"] = "2026-01-01T00:00:00"
    with pytest.raises(TelemetryValidationError):
        normalize_server_event(event)


def test_detector_caps_huge_event_batches():
    now = datetime.now(timezone.utc)
    events = [_event(i + 1, "AUTH_FAILURE", now + timedelta(seconds=i)) for i in range(600)]
    # The first 500 include enough repeated failures; engine remains bounded.
    assert len(DetectionEngine().evaluate(events)) < 20


def test_normalizer_keeps_bounded_ip_geo_and_device_enrichment():
    now = datetime.now(timezone.utc)
    event = _event(80, "AUTH_FAILURE", now)
    event.update({
        "source_country": "Indonesia",
        "source_region": "West Java",
        "source_city": "Bandung",
        "source_asn": "AS64500",
        "source_org": "Example ISP",
        "source_geo_source": "local-geoip-db",
        "source_geo_accuracy": "approximate",
        "source_hostname": "managed-client-01",
        "source_os": "Windows 11",
        "source_device_type": "desktop",
        "source_vendor": "ExampleVendor",
        "source_model": "ExampleModel",
        "source_device_source": "enrolled-endpoint-agent",
        "source_user_agent": "ExampleBrowser/1.0",
        "source_password": "never keep this",
    })
    normalized = normalize_server_event(event)
    assert normalized["source_city"] == "Bandung"
    assert normalized["source_vendor"] == "ExampleVendor"
    assert normalized["source_geo_accuracy"] == "approximate"
    assert "source_password" not in normalized


def test_normalizer_caps_untrusted_context_metadata():
    now = datetime.now(timezone.utc)
    event = _event(81, "AUTH_FAILURE", now)
    event["source_user_agent"] = "x" * 1000
    normalized = normalize_server_event(event)
    assert len(normalized["source_user_agent"]) == 240


def test_malware_signature_match_alert_is_critical():
    event = _event(91, "MALWARE_DETECTED", datetime.now(timezone.utc), ip="", path="/opt/lab/upload.bin", result="Example.Test.Signature")
    alerts = DetectionEngine().evaluate([event])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "MALWARE_SIGNATURE_MATCH"
    assert alerts[0].severity == "CRITICAL"


def test_default_threshold_is_two_failed_auth_attempts():
    now = datetime.now(timezone.utc)
    events = [
        _event(701, "AUTH_FAILURE", now, ip="203.0.113.77"),
        _event(702, "AUTH_FAILURE", now + timedelta(seconds=2), ip="203.0.113.77"),
    ]
    alerts = DetectionEngine().evaluate(events)
    assert any(alert.rule_id == "AUTH_FAILURE_BURST" for alert in alerts)


def test_single_auth_failure_does_not_trigger_burst_by_default():
    event = _event(703, "AUTH_FAILURE", datetime.now(timezone.utc), ip="203.0.113.78")
    alerts = DetectionEngine().evaluate([event])
    assert not any(alert.rule_id == "AUTH_FAILURE_BURST" for alert in alerts)


def test_privileged_activity_is_flagged_for_operator_review():
    event = _event(920, "PRIVILEGE_USE", datetime.now(timezone.utc), actor="operator", ip="203.0.113.22", command_basename="systemctl")
    alerts = DetectionEngine().evaluate([event])
    assert any(alert.rule_id == "PRIVILEGED_ACTIVITY" and alert.severity == "HIGH" for alert in alerts)
    assert "belum membuktikan akses tanpa izin" in alerts[0].description
