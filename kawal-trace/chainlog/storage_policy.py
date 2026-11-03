"""The "every database stays on this device" rule, in one place.

Kawal Trace reads events FROM monitored servers and keeps what it receives on the device. It does not
send the device's own data (audit chain, archives, scan history, accounts) to any server. The two
client classes that can write to a server -- `SyncClient.sync_once` and `ServerArchiveRemoteClient.upload`
-- refuse to run unless a caller passes `allow_remote_storage=True`. The application never does; the flag
exists so the server-side protocol can still be tested and so a future, explicit, opt-in feature has one
obvious place to hook in. Reading history back from a server (migration to the device) stays allowed.
"""
from __future__ import annotations

REMOTE_STORAGE_DISABLED_MESSAGE = (
    "Penyimpanan jarak jauh dimatikan: database, arsip, dan log audit hanya disimpan di perangkat ini."
)


class RemoteStorageDisabledError(PermissionError):
    """Raised instead of sending local data to a server."""


def require_remote_storage(allowed: bool, what: str) -> None:
    if not allowed:
        raise RemoteStorageDisabledError(f"{what}: {REMOTE_STORAGE_DISABLED_MESSAGE}")
