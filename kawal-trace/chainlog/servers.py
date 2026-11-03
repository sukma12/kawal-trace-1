"""Multi-server profile registry for Kawal Trace.

The registry stores non-secret connection configuration only. Tokens must live
in the platform secure-storage service and are namespaced by profile ID.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .sync import (DEFAULT_CONNECTOR_TYPE, DEFAULT_FEED_AUTH_MODE, DEFAULT_FEED_AUTH_HEADER_NAME, DEFAULT_FEED_FIELD_MAPPING, DEFAULT_FEED_JSON_PATH, SyncConfigError, SyncSettings, utc_now)

PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{5,127}$")


class ServerRegistryError(ValueError):
    """Invalid, missing, or inconsistent local server profile."""


@dataclass(frozen=True)
class ServerProfile:
    profile_id: str
    name: str
    settings: SyncSettings

    def public_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "name": self.name,
            "base_url": self.settings.base_url,
            "device_id": self.settings.device_id,
            "events_path": self.settings.events_path,
            "health_path": self.settings.health_path,
            "telemetry_path": self.settings.telemetry_path,
            "ca_bundle": self.settings.ca_bundle,
            "connector_type": self.settings.connector_type,
            "feed_auth_mode": self.settings.feed_auth_mode,
            "feed_auth_header_name": self.settings.feed_auth_header_name,
            "feed_json_path": self.settings.feed_json_path,
            "feed_field_mapping": self.settings.feed_field_mapping,
            "adapter_protocol": getattr(self.settings, "adapter_protocol", "rest"),
            "adapter_options_json": getattr(self.settings, "adapter_options_json", "{}"),
        }


class ServerRegistryStore:
    """Persist named server profiles with atomic writes and private permissions."""

    FORMAT = "Kawal Trace-server-registry"
    VERSION = 1

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.profiles: dict[str, ServerProfile] = {}
        self.selected_id: str | None = None
        self._load()

    def _secure_mode(self) -> None:
        if os.name != "nt":
            try:
                self.path.chmod(0o600)
            except OSError:
                pass

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            body = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(body, dict) or body.get("format") not in {self.FORMAT, "Kawal-Trace-server-registry"}:
                raise ServerRegistryError("Format registry server tidak dikenal.")
            if int(body.get("version", 0)) != self.VERSION:
                raise ServerRegistryError("Versi registry server tidak didukung.")
            raw_profiles = body.get("profiles", [])
            if not isinstance(raw_profiles, list):
                raise ServerRegistryError("Daftar profile server tidak valid.")
            loaded: dict[str, ServerProfile] = {}
            for item in raw_profiles:
                if not isinstance(item, dict):
                    raise ServerRegistryError("Entri profile server tidak valid.")
                profile_id = str(item.get("profile_id", ""))
                name = self._validate_name(str(item.get("name", "")))
                settings = SyncSettings(
                    base_url=str(item.get("base_url", "")),
                    device_id=str(item.get("device_id", "")),
                    events_path=str(item.get("events_path", "/api/v1/audit/events:batch")),
                    health_path=str(item.get("health_path", "/healthz")),
                    telemetry_path=str(item.get("telemetry_path", "/api/v1/security-events")),
                    ca_bundle=str(item.get("ca_bundle", "")),
                    connector_type=str(item.get("connector_type", DEFAULT_CONNECTOR_TYPE)),
                    feed_auth_mode=str(item.get("feed_auth_mode", DEFAULT_FEED_AUTH_MODE)),
                    feed_json_path=str(item.get("feed_json_path", DEFAULT_FEED_JSON_PATH)),
                    feed_field_mapping=str(item.get("feed_field_mapping", DEFAULT_FEED_FIELD_MAPPING)),
                    feed_auth_header_name=str(item.get("feed_auth_header_name", DEFAULT_FEED_AUTH_HEADER_NAME)),
                    adapter_protocol=str(item.get("adapter_protocol", "rest")),
                    adapter_options_json=str(item.get("adapter_options_json", "{}")),
                ).validated()
                self._validate_profile_id(profile_id)
                if profile_id in loaded:
                    raise ServerRegistryError("ID profile server duplikat.")
                loaded[profile_id] = ServerProfile(profile_id, name, settings)
            selected_id = body.get("selected_id")
            if selected_id is not None and selected_id not in loaded:
                selected_id = None
            self.profiles = loaded
            self.selected_id = str(selected_id) if selected_id else None
        except ServerRegistryError:
            raise
        except (OSError, ValueError, TypeError, SyncConfigError) as exc:
            raise ServerRegistryError("Registry server rusak/tidak bisa dibaca; backup file lalu periksa JSON-nya.") from exc

    @staticmethod
    def _validate_profile_id(value: str) -> str:
        value = str(value).strip()
        if not PROFILE_ID_RE.fullmatch(value):
            raise ServerRegistryError("ID profile server tidak valid.")
        return value

    @staticmethod
    def _validate_name(value: str) -> str:
        name = " ".join(str(value).strip().split())
        if not name or len(name) > 80 or any(ord(char) < 32 for char in name):
            raise ServerRegistryError("Nama server wajib diisi dan maksimal 80 karakter.")
        return name

    def list(self) -> list[ServerProfile]:
        return sorted(self.profiles.values(), key=lambda profile: profile.name.casefold())

    def get(self, profile_id: str | None) -> ServerProfile | None:
        return self.profiles.get(str(profile_id)) if profile_id else None

    def selected(self) -> ServerProfile | None:
        return self.get(self.selected_id)

    def _save(self) -> None:
        body = {
            "format": self.FORMAT,
            "version": self.VERSION,
            "selected_id": self.selected_id,
            "updated_at_utc": utc_now(),
            "secret_storage_note": "Credentials are stored separately in platform secure storage.",
            "profiles": [profile.public_dict() for profile in self.list()],
        }
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)
        self._secure_mode()

    def upsert(self, name: str, settings: SyncSettings, *, profile_id: str | None = None,
               select: bool = True) -> ServerProfile:
        clean_name = self._validate_name(name)
        try:
            clean_settings = settings.validated()
        except SyncConfigError:
            raise
        clean_id = self._validate_profile_id(profile_id) if profile_id else "srv-" + uuid.uuid4().hex
        for existing_id, existing in self.profiles.items():
            if existing_id != clean_id and existing.name.casefold() == clean_name.casefold():
                raise ServerRegistryError("Nama server sudah dipakai; gunakan nama yang berbeda.")
        profile = ServerProfile(clean_id, clean_name, clean_settings)
        self.profiles[clean_id] = profile
        if select:
            self.selected_id = clean_id
        self._save()
        return profile

    def select(self, profile_id: str) -> ServerProfile:
        if profile_id not in self.profiles:
            raise ServerRegistryError("Profile server tidak ditemukan.")
        self.selected_id = profile_id
        self._save()
        return self.profiles[profile_id]

    def remove(self, profile_id: str) -> ServerProfile:
        profile = self.profiles.get(profile_id)
        if profile is None:
            raise ServerRegistryError("Profile server tidak ditemukan.")
        del self.profiles[profile_id]
        if self.selected_id == profile_id:
            remaining = self.list()
            self.selected_id = remaining[0].profile_id if remaining else None
        self._save()
        return profile
