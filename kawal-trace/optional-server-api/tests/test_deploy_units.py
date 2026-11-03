"""The systemd units keep their hardening, the worker unit can really write UFW's files, and the API stays offline.

What this cannot show: that the services start and behave on a real host. It checks the unit files as text, scores them
with `systemd-analyze security --offline` when that tool exists, and guards the assumptions the hardening rests on.
"""
from __future__ import annotations

import ast
import importlib.util
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
API_UNIT = DEPLOY / "kawal-trace-api.service"
WORKER_UNIT = DEPLOY / "kawal-trace-response-worker.service"


def parse_unit(path: Path) -> dict[str, list[str]]:
    """Directives of the [Service] section; repeated keys keep every value, like systemd does."""
    values: dict[str, list[str]] = {}
    section = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line
            continue
        if section == "[Service]" and "=" in line:
            key, _, value = line.partition("=")
            values.setdefault(key.strip(), []).append(value.strip())
    return values


def load_checker():
    spec = importlib.util.spec_from_file_location("kawal_check_syscalls", DEPLOY / "check_syscalls.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def offline_score(unit: Path):
    """(score, stderr) from systemd-analyze, or None when this systemd cannot score offline."""
    tool = shutil.which("systemd-analyze")
    if not tool:
        return None
    result = subprocess.run([tool, "security", "--offline=true", str(unit)], capture_output=True, text=True, timeout=60)
    match = re.search(r"Overall exposure level for [^:]+: ([0-9.]+) ", result.stdout)
    if result.returncode != 0 or not match:
        return None
    return float(match.group(1)), result.stderr


class ApiUnitTests(unittest.TestCase):
    def setUp(self):
        self.unit = parse_unit(API_UNIT)

    def test_runs_unprivileged_with_no_capabilities_and_no_new_privileges(self):
        self.assertEqual(self.unit["User"], ["kawal-trace-api"])
        self.assertEqual(self.unit["NoNewPrivileges"], ["true"])
        self.assertEqual(self.unit["CapabilityBoundingSet"], [""], "an empty list means no capability at all")
        self.assertEqual(self.unit["AmbientCapabilities"], [""])

    def test_filesystem_is_read_only_apart_from_its_own_state(self):
        self.assertEqual(self.unit["ProtectSystem"], ["strict"])
        self.assertEqual(self.unit["ProtectHome"], ["true"])
        self.assertEqual(self.unit["StateDirectory"], ["kawal-trace-api"])
        self.assertNotIn("ReadWritePaths", self.unit, "the API may write only its own state directory")

    def test_it_can_only_talk_to_loopback_and_to_nobody_else(self):
        self.assertEqual(self.unit["IPAddressDeny"], ["any"])
        self.assertEqual(self.unit["IPAddressAllow"], ["localhost"])
        # PrivateNetwork would also hide loopback from cloudflared, which would silently take the API offline
        self.assertNotEqual(self.unit.get("PrivateNetwork"), ["true"])

    def test_socket_families_exclude_raw_and_netlink(self):
        families = self.unit["RestrictAddressFamilies"][0].split()
        self.assertEqual(sorted(families), ["AF_INET", "AF_INET6", "AF_UNIX"])

    def test_the_syscall_filter_is_an_allow_list_that_excludes_privileged_calls(self):
        filters = self.unit["SystemCallFilter"]
        self.assertIn("@system-service", filters)
        self.assertIn("~@privileged @resources", filters)
        self.assertEqual(self.unit["SystemCallErrorNumber"], ["EPERM"], "a miss must be visible, not a silent SIGSYS kill")

    def test_remaining_restrictions_are_present(self):
        for key in ("ProtectProc", "ProcSubset", "ProtectClock", "ProtectHostname", "ProtectKernelLogs", "RestrictNamespaces",
                    "RestrictRealtime", "RestrictSUIDSGID", "SystemCallArchitectures", "RemoveIPC", "TasksMax",
                    "MemoryDenyWriteExecute", "LockPersonality", "PrivateDevices", "PrivateTmp", "UMask"):
            self.assertIn(key, self.unit, key)
        self.assertEqual(self.unit["UMask"], ["0077"])
        self.assertLessEqual(int(self.unit["TasksMax"][0]), 1024)

    def test_the_api_never_makes_an_outbound_connection(self):
        """IPAddressDeny=any is only safe because of this: if the API ever needs to call out, this fails first."""
        tree = ast.parse((ROOT / "server.py").read_text(encoding="utf-8"))
        forbidden_modules = {"urllib.request", "http.client", "smtplib", "ftplib", "telnetlib", "imaplib", "poplib",
                             "xmlrpc.client", "requests", "httpx", "aiohttp", "websocket", "websockets", "ssl", "asyncio"}
        forbidden_calls = {"urlopen", "create_connection", "getaddrinfo", "gethostbyname", "open_connection"}
        problems = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                problems += [alias.name for alias in node.names if alias.name in forbidden_modules]
            elif isinstance(node, ast.ImportFrom) and node.module:
                problems += [node.module] if node.module in forbidden_modules else []
                problems += [f"{node.module}.{alias.name}" for alias in node.names if f"{node.module}.{alias.name}" in forbidden_modules]
            elif isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name in forbidden_calls:
                    problems.append(f"call {name}() at line {node.lineno}")
        self.assertEqual(problems, [], "server.py reaches out to the network; update IPAddressDeny/Allow before allowing that")

    def test_offline_exposure_score_stays_low(self):
        scored = offline_score(API_UNIT)
        if scored is None:
            self.skipTest("this systemd cannot score units offline")
        score, stderr = scored
        self.assertLessEqual(score, 2.0, f"exposure level rose to {score}")
        self.assertNotRegex(stderr, r"Unknown (key|section)", "systemd does not understand a directive in the unit")


class WorkerUnitTests(unittest.TestCase):
    def setUp(self):
        self.unit = parse_unit(WORKER_UNIT)

    def test_it_can_write_the_files_ufw_changes_even_with_a_read_only_etc(self):
        """ProtectSystem=full makes /etc read-only, and `ufw` writes /etc/ufw/user.rules: without this every block fails."""
        self.assertEqual(self.unit["ProtectSystem"], ["full"])
        paths = " ".join(self.unit["ReadWritePaths"]).split()
        self.assertIn("-/etc/ufw", paths)
        self.assertTrue(all(path.startswith("-") for path in paths), "a missing path must not stop the unit from starting")
        for path in paths:
            self.assertFalse(path.lstrip("-").startswith(("/etc/kawal-trace", "/opt")), f"{path} is not UFW's")

    def test_netlink_is_allowed_because_iptables_nft_needs_it(self):
        families = self.unit["RestrictAddressFamilies"][0].split()
        self.assertIn("AF_NETLINK", families)
        self.assertNotIn("AF_PACKET", families)

    def test_the_worker_keeps_only_restrictions_that_cannot_stop_ufw(self):
        self.assertEqual(self.unit["NoNewPrivileges"], ["true"])
        self.assertNotIn("CapabilityBoundingSet", self.unit, "restricting root's capabilities untested could silently disable blocking")
        self.assertNotIn("SystemCallFilter", self.unit)
        for key in ("ProtectClock", "ProtectHostname", "ProtectKernelLogs", "RestrictNamespaces", "RestrictRealtime",
                    "RestrictSUIDSGID", "SystemCallArchitectures", "TasksMax"):
            self.assertIn(key, self.unit, key)

    def test_offline_exposure_score_does_not_regress(self):
        scored = offline_score(WORKER_UNIT)
        if scored is None:
            self.skipTest("this systemd cannot score units offline")
        score, stderr = scored
        self.assertLessEqual(score, 5.5, f"exposure level rose to {score} (it was 6.9 before hardening)")
        self.assertNotRegex(stderr, r"Unknown (key|section)")


class SyscallCheckerTests(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()

    def test_it_reads_the_common_strace_line_shapes(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "t.strace"
            log.write_text(
                "1182  openat(AT_FDCWD, \"/x\", O_RDONLY) = 3\n"
                "12:00:01.123456 read(3, \"\", 10) = 0\n"
                "1183  <... futex resumed>)          = 0\n"
                "1182  --- SIGCHLD {si_signo=SIGCHLD} ---\n"
                "1182  +++ exited with 0 +++\n"
                "write(1, \"x\", 1) = 1\n"
                "1184  clone3({flags=CLONE_VM}, 88) = 1185\n", encoding="utf-8")
            self.assertEqual(self.checker.observed_calls(log), {"openat", "read", "write", "clone3"})

    @unittest.skipUnless(shutil.which("systemd-analyze"), "needs systemd-analyze to expand call groups")
    def test_it_accepts_ordinary_calls_and_refuses_privileged_ones(self):
        with tempfile.TemporaryDirectory() as folder:
            fine = Path(folder) / "fine.strace"
            fine.write_text("1  openat(AT_FDCWD, \"/x\", O_RDONLY) = 3\n1  read(3, \"\", 1) = 0\n1  accept4(3, NULL, NULL, 0) = 4\n", encoding="utf-8")
            bad = Path(folder) / "bad.strace"
            bad.write_text("1  read(3, \"\", 1) = 0\n1  mount(\"a\", \"b\", \"c\", 0, NULL) = -1 EPERM\n1  setrlimit(RLIMIT_NOFILE, {}) = 0\n", encoding="utf-8")
            empty = Path(folder) / "empty.strace"
            empty.write_text("", encoding="utf-8")
            # calls that @system-service contains but the unit removes again: one from '@privileged', one from '@resources'
            for name, call in (("privileged", "setuid(0) = 0"), ("resources", "setrlimit(RLIMIT_NOFILE, {}) = 0")):
                only = Path(folder) / f"only-{name}.strace"
                only.write_text(f"1  read(3, \"\", 1) = 0\n1  {call}\n", encoding="utf-8")
                self.assertEqual(self.checker.main(["x", str(only)]), 1, name)
            self.assertEqual(self.checker.main(["x", str(fine)]), 0)
            self.assertEqual(self.checker.main(["x", str(bad)]), 1)
            self.assertEqual(self.checker.main(["x", str(empty)]), 2)
            self.assertEqual(self.checker.main(["x", str(Path(folder) / "missing")]), 2)
            self.assertEqual(self.checker.main(["x"]), 2)


if __name__ == "__main__":
    unittest.main()
