import asyncio

import httpx
import pytest

from recon.safeweb import (
    BlockedRequestError,
    _guard,
    _is_public_ip,
    async_client,
)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_ips_allowed(ip):
    assert _is_public_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "127.0.0.1",        # loopback
    "10.0.0.5",         # private
    "192.168.1.1",      # private
    "172.16.0.1",       # private
    "169.254.169.254",  # link-local / cloud metadata
    "0.0.0.0",          # unspecified
    "::1",              # IPv6 loopback
    "fc00::1",          # IPv6 unique-local
    "not-an-ip",
])
def test_non_public_ips_rejected(ip):
    assert _is_public_ip(ip) is False


def _run_guard(url):
    return asyncio.run(_guard(httpx.Request("GET", url)))


def test_guard_blocks_metadata_endpoint():
    with pytest.raises(BlockedRequestError):
        _run_guard("http://169.254.169.254/latest/meta-data/")


def test_guard_blocks_loopback_literal():
    with pytest.raises(BlockedRequestError):
        _run_guard("http://127.0.0.1:8420/api/sites")


def test_guard_blocks_non_http_scheme():
    with pytest.raises(BlockedRequestError):
        _run_guard("file:///etc/passwd")


def test_guard_allows_public_ip_literal():
    # Must not raise (no network call is made — the guard only validates).
    _run_guard("http://8.8.8.8/")


def test_async_client_installs_request_guard():
    client = async_client()
    try:
        assert _guard in client.event_hooks["request"]
        assert "User-Agent" in client.headers
    finally:
        asyncio.run(client.aclose())
