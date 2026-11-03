from __future__ import annotations

from pathlib import Path

import pytest

from chainlog.ssh_connector import COMMAND_PROFILES, SSHConnectorError, SSHReadOnlyConnector
from chainlog.core import AuditStore
from chainlog.connector_ingest import ConnectorEventIngestor


class _FakeKey:
    @classmethod
    def from_private_key(cls, handle):
        contents = handle.read()
        assert "PRIVATE KEY-----" in contents
        return "TEST-KEY-OBJECT"


class _FakeStdout:
    def __init__(self, payload: bytes, code: int = 0):
        self.payload = payload
        self.channel = self
        self.code = code

    def read(self, _limit):
        return self.payload

    def recv_exit_status(self):
        return self.code


class _FakeStderr:
    def read(self, _limit):
        return b""


class _FakeClient:
    instances = []

    def __init__(self):
        self.loaded_hosts = ""
        self.policy = None
        self.connect_args = None
        self.command = None
        self.closed = False
        self.__class__.instances.append(self)

    def load_host_keys(self, path):
        self.loaded_hosts = path

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.connect_args = kwargs

    def exec_command(self, command, **kwargs):
        self.command = command
        return object(), _FakeStdout(
            b"2026-10-28T01:20:00+00:00 lab sshd[11]: Failed password for alice from 198.51.100.20 port 22 ssh2\n"
            b"2026-10-28T01:21:00+00:00 lab sshd[12]: Accepted publickey for bob from 198.51.100.22 port 22 ssh2\n",
        ), _FakeStderr()

    def close(self):
        self.closed = True


class _FakeParamiko:
    Ed25519Key = _FakeKey
    ECDSAKey = None
    RSAKey = None
    DSSKey = None
    SSHClient = _FakeClient

    class RejectPolicy:
        pass


def _connector(tmp_path: Path, **kwargs) -> SSHReadOnlyConnector:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("lab ssh-ed25519 AAAATESTKEY\n", encoding="utf-8")
    return SSHReadOnlyConnector(
        host="lab.example.test", username="audit_reader", private_key_pem="-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----",
        known_hosts_file=known_hosts, _paramiko_module=_FakeParamiko, **kwargs,
    )


def test_ssh_read_only_fetch_uses_trusted_host_key_and_allowlisted_command(tmp_path):
    _FakeClient.instances.clear()
    connector = _connector(tmp_path, command_profile="ssh_auth_recent")
    events = connector.fetch_events(20)
    client = _FakeClient.instances[-1]
    assert client.loaded_hosts.endswith("known_hosts")
    assert isinstance(client.policy, _FakeParamiko.RejectPolicy)
    assert client.connect_args["allow_agent"] is False
    assert client.connect_args["look_for_keys"] is False
    assert client.connect_args["pkey"] == "TEST-KEY-OBJECT"
    assert client.command == COMMAND_PROFILES["ssh_auth_recent"]
    assert "Failed password" not in client.command
    assert [event["event_type"] for event in events] == ["AUTH_SUCCESS", "AUTH_FAILURE"]
    assert events[0]["source_ip"] == "198.51.100.22"
    store = AuditStore(tmp_path / "ssh-audit.sqlite3")
    store.initialize()
    outcome = ConnectorEventIngestor(store).ingest("ssh:lab-server", events)
    assert outcome["added"] == 2
    assert store.verify().valid
    assert [item["event_type"] for item in store.records()[-2:]] == ["AUTH", "AUTH"]
    assert client.closed


def test_ssh_rejects_arbitrary_command_profiles_and_injected_hosts(tmp_path):
    with pytest.raises(SSHConnectorError, match="perintah SSH tidak diizinkan"):
        _connector(tmp_path, command_profile="journalctl; rm -rf /")
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("lab ssh-ed25519 AAAATESTKEY\n", encoding="utf-8")
    with pytest.raises(SSHConnectorError, match="karakter yang ditolak"):
        SSHReadOnlyConnector(host="lab;touch-bad", username="reader", private_key_pem="-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----", known_hosts_file=known_hosts, _paramiko_module=_FakeParamiko)


def test_ssh_requires_existing_known_hosts_and_valid_key(tmp_path):
    with pytest.raises(SSHConnectorError, match="known_hosts"):
        SSHReadOnlyConnector(host="lab.example.test", username="reader", private_key_pem="key", known_hosts_file=tmp_path / "missing")
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("lab ssh-ed25519 AAAATESTKEY\n", encoding="utf-8")
    connector = SSHReadOnlyConnector(host="lab.example.test", username="reader", private_key_pem="not a key", known_hosts_file=known_hosts, _paramiko_module=_FakeParamiko)
    with pytest.raises(SSHConnectorError, match="Private key SSH"):
        connector.fetch_events(1)


def test_ssh_rejects_overlong_log_output(tmp_path):
    class OversizeClient(_FakeClient):
        def exec_command(self, command, **kwargs):
            self.command = command
            return object(), _FakeStdout(b"x" * (1_048_577)), _FakeStderr()

    class OversizeParamiko(_FakeParamiko):
        SSHClient = OversizeClient

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("lab ssh-ed25519 AAAATESTKEY\n", encoding="utf-8")
    connector = SSHReadOnlyConnector(host="lab.example.test", username="reader", private_key_pem="-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----", known_hosts_file=known_hosts, _paramiko_module=OversizeParamiko)
    with pytest.raises(SSHConnectorError, match="1 MiB"):
        connector.fetch_events(1)
