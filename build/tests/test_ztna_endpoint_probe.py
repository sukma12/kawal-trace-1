import socket
import threading

import pytest

from chainlog.advanced_security import AdvancedSecurityError, probe_private_endpoint


def test_private_endpoint_probe_reaches_local_test_service():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    thread = threading.Thread(target=lambda: listener.accept()[0].close(), daemon=True)
    thread.start()
    try:
        result = probe_private_endpoint("127.0.0.1", port)
        assert result["status"] == "reachable"
        assert result["host"] == "127.0.0.1"
        assert result["port"] == port
        assert result["peer"] == "127.0.0.1"
        assert result["elapsed_ms"] >= 0
    finally:
        listener.close()
        thread.join(timeout=1)


@pytest.mark.parametrize("host", ["", "https://example.com", "host/path", "bad host", "a..b"])
def test_private_endpoint_probe_rejects_non_host_input(host):
    with pytest.raises(AdvancedSecurityError):
        probe_private_endpoint(host, 443)


@pytest.mark.parametrize("port", [0, 65536, "abc", True])
def test_private_endpoint_probe_rejects_invalid_port(port):
    with pytest.raises(AdvancedSecurityError):
        probe_private_endpoint("127.0.0.1", port)


def test_private_endpoint_probe_reports_unreachable_port():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    result = probe_private_endpoint("127.0.0.1", port, timeout=0.5)
    assert result["status"] == "unreachable"
    assert result["host"] == "127.0.0.1"
    assert result["port"] == port
    assert result["detail"]
