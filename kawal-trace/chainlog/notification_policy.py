"""Pure event-baselining policy for client-side security alerts."""
from __future__ import annotations

import time
from typing import Any, MutableMapping, MutableSet, Sequence

INITIAL_ALERT_LOOKBACK_SECONDS = 300
MAX_FUTURE_CLOCK_SKEW_SECONDS = 60
MAX_TRACKED_EVENT_IDS_PER_PROFILE = 2000


def find_new_event_ids(
    profile_id: str,
    events: Sequence[dict[str, Any]],
    seen_by_profile: MutableMapping[str, set[str]],
    initialized_profiles: MutableSet[str],
    *,
    now_epoch: float | None = None,
) -> set[str]:
    """Return unseen IDs, but on first connect only alert on the recent lookback window.

    Existing historical events are baselined to avoid flooding alerts after initial
    setup. Recent events remain eligible so connecting during an ongoing incident
    does not silently suppress it. Later polls report any newly received event ID.
    """
    now = time.time() if now_epoch is None else float(now_epoch)
    current = {
        str(event.get("event_id", ""))
        for event in events
        if str(event.get("event_id", ""))
    }
    seen = seen_by_profile.setdefault(profile_id, set())

    if profile_id not in initialized_profiles:
        recent: set[str] = set()
        for event in events:
            event_id = str(event.get("event_id", ""))
            if not event_id:
                continue
            try:
                stamp = float(event.get("timestamp_epoch", 0) or 0)
            except (TypeError, ValueError):
                continue
            if now - INITIAL_ALERT_LOOKBACK_SECONDS <= stamp <= now + MAX_FUTURE_CLOCK_SKEW_SECONDS:
                recent.add(event_id)
        seen.update(current)
        initialized_profiles.add(profile_id)
        fresh = recent
    else:
        fresh = current - seen
        seen.update(current)

    if len(seen) > MAX_TRACKED_EVENT_IDS_PER_PROFILE:
        # Retain IDs from the current feed window only, matching the polling feed's
        # bounded nature and avoiding unbounded growth over long running sessions.
        seen.clear()
        seen.update(current)
    return fresh
