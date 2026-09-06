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


# --- access policy enforced on the client itself (review of increment C, S2) -------

def test_guard_refuses_denied_hosts_before_dns():
    """No DNS lookup is needed to refuse a denied host, so this runs offline."""
    req = httpx.Request("GET", "https://www.instagram.com/someone/")
    with pytest.raises(BlockedRequestError, match="access policy"):
        asyncio.run(_guard(req))


def test_redirect_to_a_denied_host_is_refused_on_the_hop():
    """A permitted host that 302s to reddit.com used to be followed by every
    fetcher built on async_client; plan-time filtering cannot see a redirect."""
    def handler(request):
        if request.url.host == "93.184.216.34":
            return httpx.Response(302, headers={"location": "https://www.reddit.com/user/x"})
        return httpx.Response(200, text="should never be reached")

    async def go():
        async with async_client(transport=httpx.MockTransport(handler)) as client:
            return await client.get("http://93.184.216.34/profile")

    with pytest.raises(BlockedRequestError, match="reddit.com"):
        asyncio.run(go())


def test_policy_table_matches_the_observed_robots_for_x_image_cdn():
    """pbs.twimg.com serves 'User-agent: * / Disallow:' (allows all; observed
    2026-09-06), so it must not be denied; the platform hosts still are."""
    from recon import policy
    assert policy.denied_reason("https://pbs.twimg.com/profile_images/1/x.jpg") is None
    assert policy.denied_reason("https://x.com/someone")
    for host in ("scontent.cdninstagram.com", "scontent.xx.fbcdn.net", "i.pinimg.com",
                 "styles.redditmedia.com"):
        assert policy.denied_reason(f"https://{host}/a.jpg"), host


@pytest.mark.parametrize("ip", ["100.64.0.1", "2002:7f00:1::1", "::ffff:10.0.0.5",
                                "2001:0:4136:e378:8000:63bf:3fff:fdd2"])
def test_shared_address_space_and_6to4_are_not_public(ip):
    """RFC 6598 shared space and 6to4 (which can encode 127.0.0.1) passed the
    explicit checks; is_global rejects them (security audit F-9)."""
    assert _is_public_ip(ip) is False
