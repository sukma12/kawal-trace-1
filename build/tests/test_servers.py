from __future__ import annotations

import json
from pathlib import Path

import pytest

from chainlog.servers import ServerRegistryError, ServerRegistryStore
from chainlog.sync import SyncConfigError, SyncSettings


def _settings(host: str, device_id: str) -> SyncSettings:
    return SyncSettings(base_url=f"https://{host}", device_id=device_id)


def test_registry_add_select_update_and_reload(tmp_path: Path):
    path = tmp_path / "server-registry.json"
    store = ServerRegistryStore(path)
    first = store.upsert("Ubuntu Lab", _settings("lab.example.test", "cl-device-lab-001"))
    second = store.upsert("Ubuntu Production", _settings("prod.example.test", "cl-device-prod-001"))
    assert store.selected_id == second.profile_id

    store.select(first.profile_id)
    updated = store.upsert("Ubuntu Lab - Revised", _settings("lab2.example.test", "cl-device-lab-001"), profile_id=first.profile_id)
    assert updated.settings.base_url == "https://lab2.example.test"

    reopened = ServerRegistryStore(path)
    assert reopened.selected_id == first.profile_id
    assert reopened.get(first.profile_id).name == "Ubuntu Lab - Revised"
    assert reopened.get(second.profile_id).settings.base_url == "https://prod.example.test"


def test_registry_never_persists_tokens_or_passwords(tmp_path: Path):
    path = tmp_path / "server-registry.json"
    store = ServerRegistryStore(path)
    store.upsert("Lab", _settings("lab.example.test", "cl-device-lab-001"))
    raw = path.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert parsed["format"] == "Kawal Trace-server-registry"
    lower = raw.lower()
    assert '"device_token"' not in lower and '"monitor_token"' not in lower
    assert '"password"' not in lower
    assert '"authorization"' not in lower


def test_registry_rejects_duplicate_names_case_insensitively(tmp_path: Path):
    store = ServerRegistryStore(tmp_path / "server-registry.json")
    store.upsert("Ubuntu Lab", _settings("lab.example.test", "cl-device-lab-001"))
    with pytest.raises(ServerRegistryError, match="Nama server sudah dipakai"):
        store.upsert("ubuntu lab", _settings("other.example.test", "cl-device-other-001"))


def test_registry_remove_profile_selects_remaining_and_then_none(tmp_path: Path):
    store = ServerRegistryStore(tmp_path / "server-registry.json")
    first = store.upsert("Alpha", _settings("alpha.example.test", "cl-device-alpha-01"))
    second = store.upsert("Beta", _settings("beta.example.test", "cl-device-beta-001"))
    store.remove(second.profile_id)
    assert store.selected_id == first.profile_id
    store.remove(first.profile_id)
    assert store.selected_id is None
    assert store.list() == []
    assert ServerRegistryStore(tmp_path / "server-registry.json").selected_id is None


def test_registry_rejects_insecure_remote_http(tmp_path: Path):
    store = ServerRegistryStore(tmp_path / "server-registry.json")
    with pytest.raises(SyncConfigError, match="HTTPS wajib"):
        store.upsert("Remote bad", SyncSettings("http://ubuntu.example.test", "cl-device-test-001"))


def test_registry_roundtrips_custom_auth_header(tmp_path: Path):
    path = tmp_path / "server-registry.json"
    store = ServerRegistryStore(path)
    profile = store.upsert("External API", SyncSettings(
        base_url="https://api.example.test", device_id="cl-external-header-test-001",
        connector_type="generic_rest_readonly", feed_auth_mode="custom_header",
        feed_auth_header_name="X-Org-Token",
    ))
    reopened = ServerRegistryStore(path)
    assert reopened.get(profile.profile_id).settings.feed_auth_mode == "custom_header"
    assert reopened.get(profile.profile_id).settings.feed_auth_header_name == "X-Org-Token"


def test_registry_roundtrips_protocol_adapter_without_secrets(tmp_path: Path):
    path = tmp_path / "server-registry.json"
    store = ServerRegistryStore(path)
    profile = store.upsert("GraphQL telemetry", SyncSettings(
        base_url="https://api.example.test", device_id="cl-graphql-test-001",
        connector_type="generic_rest_readonly", adapter_protocol="graphql",
        adapter_options_json=json.dumps({"query": "query Events { events { id } }", "variables": {"limit": 10}}),
    ))
    persisted = json.loads(path.read_text(encoding="utf-8"))
    reopened = ServerRegistryStore(path)
    loaded = reopened.get(profile.profile_id).settings
    assert loaded.adapter_protocol == "graphql"
    assert json.loads(loaded.adapter_options_json)["variables"]["limit"] == 10
    serialized = json.dumps(persisted).lower()
    assert "client_secret" not in serialized and "access_token" not in serialized


def test_legacy_registry_format_is_still_readable(tmp_path: Path):
    path = tmp_path / "server-registry.json"
    settings = _settings("legacy.example.test", "cl-legacy-test-001")
    path.write_text(json.dumps({
        "format": "Kawal-Trace-server-registry",
        "version": 1,
        "selected_id": None,
        "profiles": [{
            "profile_id": "legacy-profile-001",
            "name": "Legacy server",
            "base_url": settings.base_url,
            "device_id": settings.device_id,
            "events_path": settings.events_path,
            "health_path": settings.health_path,
            "telemetry_path": settings.telemetry_path,
            "ca_bundle": "",
            "connector_type": settings.connector_type,
            "feed_auth_mode": settings.feed_auth_mode,
            "feed_json_path": settings.feed_json_path,
            "feed_field_mapping": settings.feed_field_mapping,
            "feed_auth_header_name": settings.feed_auth_header_name,
            "adapter_protocol": "rest",
            "adapter_options_json": "{}"
        }]
    }), encoding="utf-8")
    reopened = ServerRegistryStore(path)
    assert reopened.get("legacy-profile-001") is not None
    assert reopened.get("legacy-profile-001").settings.base_url == "https://legacy.example.test"
