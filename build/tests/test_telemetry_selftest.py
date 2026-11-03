from chainlog.telemetry_selftest import run_telemetry_self_test


def test_local_telemetry_selftest_exercises_detection_archive_and_deduplication(tmp_path):
    result = run_telemetry_self_test(tmp_path / "selftest.sqlite3")
    assert result["status"] == "passed"
    assert result["stages"] == {
        "event_validation": "passed",
        "detection": "passed",
        "archive_write": "passed",
        "archive_readback": "passed",
        "duplicate_protection": "passed",
    }
    assert result["synthetic_events"] == 2
    assert result["archive_readback"] == 2
    assert result["alerts"] == 1
    assert result["test_only"] is True
    assert result["network_used"] is False
