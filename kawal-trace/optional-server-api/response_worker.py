#!/usr/bin/env python3
"""Narrow privileged worker for queued temporary UFW IPv4 deny rules.

The API process never executes firewall commands. This worker fails closed unless
response actions are explicitly enabled, the administrator allowlist is populated,
UFW is active, and the exact temporary rule comment can be verified.
"""
from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(os.environ.get("KAWAL_API_DB_PATH", "/var/lib/kawal-trace-api/events.sqlite3"))
ENABLED = os.environ.get("KAWAL_RESPONSE_ACTIONS_ENABLED", "false").strip().lower() == "true"
ALLOWLIST_RAW = os.environ.get("KAWAL_RESPONSE_ALLOWLIST", "").strip()
POLL_SECONDS = 2.0
RULE_RE = re.compile(r"^\[\s*(\d+)\]\s+.*#\s*(Kawal-Trace-[A-Fa-f0-9]{12})\s*$")


class RuleMarkerNotVerifiable(RuntimeError):
    """Rule might exist, but the worker cannot safely identify it for expiry."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def allowlist() -> set[str]:
    if not ALLOWLIST_RAW:
        return set()
    parsed: set[str] = set()
    for item in ALLOWLIST_RAW.split(","):
        item = item.strip()
        if item:
            parsed.add(str(ipaddress.ip_address(item)))
    return parsed


def validate_target(source_ip: str, ttl_seconds: int, trusted: set[str]) -> str:
    ip = ipaddress.ip_address(source_ip)
    if ip.version != 4 or not ip.is_global:
        raise ValueError("public IPv4 only")
    if str(ip) in trusted:
        raise ValueError("target is in response allowlist")
    if ttl_seconds not in {300, 900, 1800}:
        raise ValueError("ttl must be 300, 900, or 1800")
    if not trusted:
        raise ValueError("response allowlist is empty")
    return str(ip)


def run_ufw(args: list[str], *, timeout: int = 8) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["/usr/sbin/ufw", *args], text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout, check=False, shell=False)


def ufw_active() -> bool:
    proc = run_ufw(["status"])
    return proc.returncode == 0 and any(line.strip().lower() == "status: active" for line in proc.stdout.splitlines())


def marker_for(action_id: str) -> str:
    if not re.fullmatch(r"[A-Fa-f0-9]{32}", action_id):
        raise ValueError("invalid action id")
    return f"Kawal-Trace-{action_id[:12]}"


def find_rule_numbers(marker: str) -> list[int]:
    proc = run_ufw(["status", "numbered"])
    if proc.returncode != 0:
        raise RuntimeError("ufw_status_numbered_failed")
    result: list[int] = []
    for line in proc.stdout.splitlines():
        if marker in line:
            match = re.match(r"^\[\s*(\d+)\]", line.strip())
            if match:
                result.append(int(match.group(1)))
    return sorted(result, reverse=True)


def remove_rule(marker: str) -> bool:
    # Re-read the numbered rule each time because deletion renumbers later entries.
    numbers = find_rule_numbers(marker)
    for number in numbers:
        proc = run_ufw(["--force", "delete", str(number)])
        if proc.returncode != 0:
            raise RuntimeError("ufw_rule_delete_failed")
    return bool(numbers)


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _mark(action_id: str, status: str, message: str) -> None:
    with db_connect() as conn:
        conn.execute("UPDATE response_actions SET status=?,worker_message=?,updated_at_utc=? WHERE action_id=?",
                     (status, message[:220], utc_now(), action_id))


def process_pending_once() -> int:
    if not ENABLED:
        return 0
    trusted = allowlist()
    # Force-disconnect is disabled by default. Even when response actions are enabled,
    # SSH session kill requires an explicit second switch and never targets allowlisted IPs
    # or protected account names (enforced at queue time in the API).
    force_disconnect_enabled = os.environ.get("KAWAL_FORCE_DISCONNECT_ENABLED", "false").strip().lower() == "true"
    with db_connect() as conn:
        pending = conn.execute("SELECT * FROM response_actions WHERE status='PENDING' ORDER BY requested_at_utc LIMIT 10").fetchall()
    processed = 0
    for row in pending:
        action_id = str(row["action_id"])
        action = str(row["action"] or "")
        try:
            ip = validate_target(str(row["source_ip"]), int(row["ttl_seconds"]), trusted)
            if float(row["expires_at_epoch"]) <= time.time() and action == "TEMP_BLOCK_IP":
                _mark(action_id, "EXPIRED_BEFORE_APPLY", "ttl elapsed before worker action")
                processed += 1
                continue
            if action == "FORCE_DISCONNECT_SSH":
                if not force_disconnect_enabled:
                    _mark(
                        action_id,
                        "FAILED",
                        "FORCE_DISCONNECT_SSH requires KAWAL_FORCE_DISCONNECT_ENABLED=true; refused fail-closed",
                    )
                    processed += 1
                    continue
                # Even when enabled, this worker only records intent. Live session kill
                # (e.g. via ss/pkill scoped to the source IP) must be reviewed on the host
                # and is intentionally not auto-executed here to protect administrators.
                _mark(
                    action_id,
                    "ACKNOWLEDGED_NO_AUTO_KILL",
                    "Queued force-disconnect acknowledged; automatic SSH kill is not performed by this worker. Review host sessions manually or extend with a host-specific, allow-listed killer under separate control.",
                )
                processed += 1
                continue
            if action != "TEMP_BLOCK_IP":
                _mark(action_id, "FAILED", f"unsupported_action:{action}")
                processed += 1
                continue
            if not ufw_active():
                raise RuntimeError("ufw_not_active_fail_closed")
            with db_connect() as conn:
                active = conn.execute("SELECT action_id FROM response_actions WHERE source_ip=? AND status='ACTIVE_TEMP_BLOCK' LIMIT 1", (ip,)).fetchone()
            if active:
                raise RuntimeError("ip_already_active")
            marker = marker_for(action_id)
            args = ["insert", "1", "deny", "from", ip, "to", "any", "comment", marker]
            dry_run = run_ufw(["--dry-run", *args])
            if dry_run.returncode != 0:
                raise RuntimeError("ufw_comment_rule_not_supported_or_dry_run_failed")
            apply = run_ufw(args)
            if apply.returncode != 0:
                raise RuntimeError("ufw_rule_add_failed")
            if marker not in "\n".join([apply.stdout, *(line for line in run_ufw(["status", "numbered"]).stdout.splitlines())]):
                # Do not claim the action succeeded without a uniquely identifiable expiry marker.
                raise RuleMarkerNotVerifiable("UFW rule may have been added but its expiry marker is not verifiable; manual review required")
            _mark(action_id, "ACTIVE_TEMP_BLOCK", "UFW deny rule active; expiry worker scheduled")
        except RuleMarkerNotVerifiable as exc:
            _mark(action_id, "EXPIRY_ERROR", f"{type(exc).__name__}:{exc}")
        except Exception as exc:
            _mark(action_id, "FAILED", f"{type(exc).__name__}:{exc}")
        processed += 1
    return processed


def expire_due_once() -> int:
    with db_connect() as conn:
        due = conn.execute("SELECT action_id,expires_at_epoch FROM response_actions WHERE status='ACTIVE_TEMP_BLOCK' AND expires_at_epoch<=?",
                            (time.time(),)).fetchall()
    processed = 0
    for row in due:
        action_id = str(row["action_id"])
        try:
            if not ufw_active():
                raise RuntimeError("ufw_not_active; block retained for manual review")
            marker = marker_for(action_id)
            found = remove_rule(marker)
            if not found:
                raise RuntimeError("temporary_rule_marker_not_found; no blind rule deletion performed")
            _mark(action_id, "EXPIRED", "temporary UFW rule removed after TTL")
        except Exception as exc:
            _mark(action_id, "EXPIRY_ERROR", f"{type(exc).__name__}:{exc}")
        processed += 1
    return processed


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("response worker must run as root; it processes only queued, allowlisted TEMP_BLOCK_IP actions")
    if not Path("/usr/sbin/ufw").is_file():
        raise SystemExit("UFW executable missing; response worker will not run")
    if ENABLED and not allowlist():
        raise SystemExit("KAWAL_RESPONSE_ACTIONS_ENABLED=true requires a populated KAWAL_RESPONSE_ALLOWLIST")
    print(f"[kawal-trace-response-worker] started enabled={ENABLED} allowlist_entries={len(allowlist())}", flush=True)
    while True:
        if ENABLED:
            process_pending_once()
            expire_due_once()
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
