"""Bridge normalized connector events into the local tamper-evident audit chain.

Connector events are treated as untrusted input and only a bounded, normalized
subset is recorded. Duplicate source event IDs are skipped across app restarts by
checking the event IDs already covered by the local hash chain.
"""
from __future__ import annotations

import threading
from typing import Any, Iterable, Mapping

from .core import AuditStore, ValidationError

MAX_INGEST_BATCH = 500


def _audit_type(event_type: str) -> str:
    value = str(event_type or "CUSTOM_SECURITY_EVENT").upper()
    if "AUTH" in value or "LOGIN" in value:
        return "AUTH"
    if value in {"PRIVILEGE_USE"}:
        return "ACCESS"
    if value in {"FILE_CHANGE", "SERVICE_CHANGE"}:
        return "CONFIG"
    if value == "MALWARE_DETECTED":
        return "ALERT"
    if value == "AGENT_HEALTH":
        return "SYSTEM"
    return "NOTE"


class ConnectorEventIngestor:
    """Idempotent bridge from a connector to the local AuditStore."""

    def __init__(self, store: AuditStore):
        if not isinstance(store, AuditStore):
            raise TypeError("store must be an AuditStore")
        self.store = store
        self._lock = threading.RLock()

    def ingest(self, connector_name: str, events: Iterable[Mapping[str, Any]]) -> dict[str, int]:
        label = " ".join(str(connector_name or "").split())
        if not label or len(label) > 64:
            raise ValueError("Nama konektor wajib diisi dan maksimal 64 karakter.")
        batch = list(events)
        if len(batch) > MAX_INGEST_BATCH:
            raise ValueError(f"Maksimal {MAX_INGEST_BATCH} event per batch.")

        added = skipped = rejected = 0
        # AuditStore serializes writes transactionally. Keep duplicate inspection
        # and inserts serialized for callers using this ingestor from TCP workers.
        with self._lock:
            existing: set[tuple[str, str]] = set()
            for record in self.store.records():
                details = record.get("details")
                if not isinstance(details, dict):
                    continue
                prior_connector = str(details.get("connector") or "")
                prior_event_id = str(details.get("source_event_id") or "")
                if prior_connector and prior_event_id:
                    existing.add((prior_connector, prior_event_id))

            for raw in batch:
                if not isinstance(raw, Mapping):
                    rejected += 1
                    continue
                event_id = str(raw.get("event_id") or "").strip()
                event_type = str(raw.get("event_type") or "CUSTOM_SECURITY_EVENT").upper()
                if not event_id or len(event_id) > 128:
                    rejected += 1
                    continue
                dedup_key = (label, event_id)
                if dedup_key in existing:
                    skipped += 1
                    continue
                details_source = raw.get("details") if isinstance(raw.get("details"), Mapping) else {}
                safe_details = {
                    "connector": label,
                    "source_event_id": event_id,
                    "source_event_type": event_type[:48],
                    "timestamp_utc": str(raw.get("timestamp_utc") or "")[:40],
                    "host_id": str(raw.get("host_id") or "")[:128],
                    "source": str(raw.get("source") or "")[:64],
                    "source_ip": str(raw.get("source_ip") or "")[:64],
                    "reason": str(details_source.get("reason") or "")[:256],
                    "path": str(details_source.get("path") or "")[:512],
                    "rule_key": str(details_source.get("rule_key") or "")[:80],
                    "message_excerpt": str(details_source.get("message_excerpt") or "")[:256],
                }
                actor = " ".join(str(raw.get("actor") or "unknown").split())[:80] or "unknown"
                source = f"connector:{label}"[:120]
                try:
                    self.store.add_event(_audit_type(event_type), actor, source, safe_details)
                except (ValidationError, TypeError, ValueError):
                    rejected += 1
                    continue
                existing.add(dedup_key)
                added += 1
        return {"added": added, "skipped_duplicate": skipped, "rejected": rejected}
