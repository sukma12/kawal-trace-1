#!/usr/bin/env python3
"""Check an strace log against the system-call allow-list used by kawal-trace-api.service.

Why: the unit allows only '@system-service' minus '@privileged @resources'. That set was measured on one machine
(Python 3.13, glibc of a development container). Your server may run a different Python or libc, so repeat the
measurement there before trusting the filter, and again after OS or Python upgrades.

    # 1. run the API for a few minutes under strace as its own user, using systemd so the env file is read the
    #    way the real service reads it (it is NOT shell syntax), and send real traffic meanwhile (app, agent, stream)
    sudo systemctl stop kawal-trace-api
    sudo systemd-run --wait --collect -p User=kawal-trace-api -p StateDirectory=kawal-trace-api \\
        -p EnvironmentFile=/etc/kawal-trace/api.env -p RuntimeMaxSec=300 \\
        /usr/bin/strace -f -qq -o /tmp/api.strace /usr/bin/python3 /opt/kawal-trace-api/server.py
    # 2. start the real service again, then:
    sudo systemctl start kawal-trace-api
    python3 check_syscalls.py /tmp/api.strace

(Those commands were written without a systemd host to run them on: adapt them if your distribution differs.)

Exit status 0 = every observed call is allowed; 1 = at least one call would be refused with EPERM.
Note: a run as root also shows fchown(), which SQLite issues only for root and ignores if it fails; run the
service as its own user (as above) for a representative measurement.
Needs `systemd-analyze` (part of systemd) to expand the call groups. It never changes anything.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ALLOW = "@system-service"
DENY = ("@privileged", "@resources")
LINE = re.compile(r"^(?:\d+\s+)?(?:\d+:\d+:\d+(?:\.\d+)?\s+)?([a-z_][a-z_0-9]*)\(")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def direct_members(group: str, cache: dict[str, list[str]]) -> list[str]:
    if group not in cache:
        result = subprocess.run(["systemd-analyze", "syscall-filter", group], capture_output=True, text=True, check=True)
        lines = ANSI.sub("", result.stdout).splitlines()[1:]
        cache[group] = [line.split()[0] for line in lines if line.strip() and not line.strip().startswith("#")]
    return cache[group]


def expand(group: str, cache: dict[str, list[str]], seen: set[str] | None = None) -> set[str]:
    seen = seen if seen is not None else set()
    if group in seen:
        return set()
    seen.add(group)
    names: set[str] = set()
    for member in direct_members(group, cache):
        names |= expand(member, cache, seen) if member.startswith("@") else {member}
    return names


def observed_calls(path: Path) -> set[str]:
    calls: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = LINE.match(line)
        if match:
            calls.add(match.group(1))
    return calls


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"Berkas strace tidak ditemukan: {path}")
        return 2
    cache: dict[str, list[str]] = {}
    allowed = expand(ALLOW, cache)
    for group in DENY:
        allowed -= expand(group, cache)
    used = observed_calls(path)
    if not used:
        print("Tidak ada panggilan sistem yang terbaca; pakai `strace -f -qq -o <berkas>` (tanpa -c).")
        return 2
    refused = sorted(used - allowed)
    print(f"{len(used)} panggilan sistem teramati; {len(refused)} akan ditolak oleh filter unit.")
    for name in refused:
        print(f"  DITOLAK: {name}")
    if refused:
        print("Komentari tiga baris SystemCall* di kawal-trace-api.service sampai ini dibahas.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
