"""The avatar proxy (Increment H2, V11 / F-6).

Remote avatars are relayed by ``GET /api/avatar?u=`` so the analyst's browser
never contacts the subject's host. ``httpx.MockTransport`` stands in for the
network; the real SSRF guard hooks stay on the client (DNS is stubbed to a
public address so the guard runs offline), and the request-protection
middleware runs as in production.
"""

import time

import httpx
import pytest
from fastapi.testclient import TestClient

import app as appmod
from recon import safeweb

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4
IMG = "https://cdn.example/u/alice.png"
MIB = 1024 * 1024


def _u(url):
    from urllib.parse import quote
    return "/api/avatar?u=" + quote(url, safe="")


class _Chunks(httpx.AsyncByteStream):
    """A body with no Content-Length, streamed in chunks."""

    def __init__(self, total, chunk=64 * 1024):
        self.total, self.chunk = total, chunk

    async def __aiter__(self):
        sent = 0
        while sent < self.total:
            n = min(self.chunk, self.total - sent)
            yield b"x" * n
            sent += n


@pytest.fixture
def proxy(monkeypatch):
    """TestClient whose avatar fetches hit a swappable handler; ``calls`` logs
    every request that reached the (mock) network."""
    calls = []
    state = {"handler": lambda r: httpx.Response(200, content=PNG,
                                                 headers={"content-type": "image/png"})}

    def handler(request):
        calls.append(request)
        return state["handler"](request)

    def factory():
        from recon.adapters import USER_AGENT
        return safeweb.async_client(timeout=1.0,
                                    headers={"User-Agent": USER_AGENT, "Accept": "image/*"},
                                    transport=httpx.MockTransport(handler))

    async def resolve(host, port):
        return ["93.184.216.34"]

    monkeypatch.setattr(appmod, "_avatar_client", factory)
    monkeypatch.setattr(safeweb, "_resolve", resolve)
    appmod._avatar_cache.clear()
    with TestClient(appmod.app) as c:
        c.calls = calls
        c.respond = lambda h: state.__setitem__("handler", h)
        yield c
    appmod._avatar_cache.clear()


# --- the happy path ---------------------------------------------------------

def test_relays_the_image_with_its_type_and_private_cache_headers(proxy):
    proxy.respond(lambda r: httpx.Response(
        200, content=PNG, headers={"content-type": "image/png; charset=binary"}))
    r = proxy.get(_u(IMG))
    assert r.status_code == 200
    assert r.content == PNG
    assert r.headers["content-type"] == "image/png"          # parameters stripped
    assert r.headers["cache-control"] == "private, max-age=86400"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in r.headers["content-security-policy"]
    # The subject's host sees the project's honest UA, not the analyst's browser.
    sent = proxy.calls[0]
    assert sent.headers["user-agent"].startswith("sherlock-web/")
    assert sent.headers["accept"] == "image/*"
    assert str(sent.url) == IMG


def test_cache_hit_performs_no_second_fetch(proxy):
    assert proxy.get(_u(IMG)).status_code == 200
    assert proxy.get(_u(IMG)).status_code == 200
    assert len(proxy.calls) == 1
    assert proxy.get(_u("https://cdn.example/u/bob.png")).status_code == 200
    assert len(proxy.calls) == 2


# --- refusals ----------------------------------------------------------------

def test_non_image_content_is_415(proxy):
    proxy.respond(lambda r: httpx.Response(
        200, text="<html>login</html>", headers={"content-type": "text/html"}))
    r = proxy.get(_u(IMG))
    assert r.status_code == 415 and "image" in r.json()["error"]


def test_svg_is_refused_even_though_it_is_an_image_type(proxy):
    """An SVG relayed from this origin could carry script if navigated to."""
    proxy.respond(lambda r: httpx.Response(
        200, content=b"<svg onload='alert(1)'/>", headers={"content-type": "image/svg+xml"}))
    assert proxy.get(_u(IMG)).status_code == 415


def test_declared_oversize_is_413_without_reading_the_body(proxy):
    proxy.respond(lambda r: httpx.Response(
        200, content=b"x" * (2 * MIB + 1), headers={"content-type": "image/png"}))
    r = proxy.get(_u(IMG))
    assert r.status_code == 413 and "2 MiB" in r.json()["error"]


def test_streamed_oversize_is_cut_at_2_mib(proxy):
    proxy.respond(lambda r: httpx.Response(
        200, stream=_Chunks(3 * MIB), headers={"content-type": "image/png"}))
    r = proxy.get(_u(IMG))
    assert r.status_code == 413
    assert len(proxy.calls) == 1
    # Exactly 2 MiB without a Content-Length is fine.
    appmod._avatar_cache.clear()
    proxy.respond(lambda r: httpx.Response(
        200, stream=_Chunks(2 * MIB), headers={"content-type": "image/png"}))
    r = proxy.get(_u("https://cdn.example/u/big.png"))
    assert r.status_code == 200 and len(r.content) == 2 * MIB


def test_denied_host_is_403_and_never_fetched(proxy):
    r = proxy.get(_u("https://www.instagram.com/alice/pic.jpg"))
    assert r.status_code == 403
    assert "access policy" in r.json()["error"]
    assert proxy.calls == []


def test_redirect_to_a_denied_host_is_refused_on_the_hop(proxy):
    def handler(request):
        if request.url.host == "cdn.example":
            return httpx.Response(302, headers={"location": "https://www.reddit.com/u/x.png"})
        return httpx.Response(200, content=PNG, headers={"content-type": "image/png"})
    proxy.respond(handler)
    r = proxy.get(_u(IMG))
    assert r.status_code == 403 and "reddit.com" in r.json()["error"]
    assert [c.url.host for c in proxy.calls] == ["cdn.example"]


def test_redirect_to_a_non_http_scheme_is_never_followed(proxy):
    proxy.respond(lambda r: httpx.Response(302, headers={"location": "ftp://cdn.example/x.png"}))
    r = proxy.get(_u(IMG))
    assert r.status_code in (403, 502)
    assert len(proxy.calls) == 1


def test_non_public_address_is_403(proxy, monkeypatch):
    async def resolve(host, port):
        return ["127.0.0.1"]
    monkeypatch.setattr(safeweb, "_resolve", resolve)
    r = proxy.get(_u("https://intranet.example/a.png"))
    assert r.status_code == 403 and "non-public" in r.json()["error"]
    assert proxy.calls == []


@pytest.mark.parametrize("bad", [
    "javascript:alert(1)", "ftp://cdn.example/a.png", "data:image/png;base64,AAAA",
    "file:///etc/passwd", "//cdn.example/a.png", "cdn.example/a.png", "", "https://",
])
def test_non_http_urls_are_400(proxy, bad):
    r = proxy.get(_u(bad))
    assert r.status_code == 400, bad
    assert proxy.calls == []


def test_overlong_url_is_400(proxy):
    r = proxy.get(_u("https://cdn.example/" + "a" * 3000))
    assert r.status_code == 400 and proxy.calls == []


def test_missing_parameter_is_a_client_error(proxy):
    assert proxy.get("/api/avatar").status_code in (400, 422)


# --- upstream failure --------------------------------------------------------

def test_upstream_error_status_is_502(proxy):
    proxy.respond(lambda r: httpx.Response(404))
    r = proxy.get(_u(IMG))
    assert r.status_code == 502 and "404" in r.json()["error"]


def test_upstream_transport_error_is_502_and_not_cached(proxy):
    def boom(request):
        raise httpx.ConnectError("refused", request=request)
    proxy.respond(boom)
    assert proxy.get(_u(IMG)).status_code == 502
    proxy.respond(lambda r: httpx.Response(200, content=PNG, headers={"content-type": "image/png"}))
    assert proxy.get(_u(IMG)).status_code == 200      # failures are never cached
    assert len(proxy.calls) == 2


# --- cross-site guard --------------------------------------------------------

def test_cross_site_load_is_403_but_our_own_page_may_load_it(proxy):
    """Another site embedding <img src=http://127.0.0.1:8420/api/avatar?…> is
    refused; the console's own <img> is a same-origin subresource (no Origin
    header is sent for images) and passes."""
    r = proxy.get(_u(IMG), headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403 and proxy.calls == []
    r = proxy.get(_u(IMG), headers={"Sec-Fetch-Site": "same-origin",
                                    "Sec-Fetch-Dest": "image", "Sec-Fetch-Mode": "no-cors"})
    assert r.status_code == 200 and len(proxy.calls) == 1


def test_avatar_is_not_a_pure_read():
    """It starts network activity, so it must not be on the guard's allow-list."""
    assert not appmod._is_pure_read("GET", "/api/avatar")


# --- the cache itself --------------------------------------------------------

def test_cache_is_bounded_by_entries_bytes_and_age(monkeypatch):
    c = appmod._AvatarCache(max_entries=3, max_bytes=100, ttl_s=10)
    for i in range(4):
        c.put(f"u{i}", "image/png", b"x" * 10)
    assert len(c) == 3 and c.get("u0") is None and c.get("u3") is not None
    c.get("u1")                              # touch → most recently used
    c.put("u4", "image/png", b"x" * 10)      # evicts u2, the least recently used
    assert c.get("u2") is None and c.get("u1") is not None
    c.put("big", "image/png", b"x" * 95)     # bytes bound evicts the rest
    assert c.get("big") is not None and len(c) == 1
    c.put("huge", "image/png", b"x" * 101)   # larger than the whole cache: skipped
    assert c.get("huge") is None
    now = time.monotonic()
    monkeypatch.setattr(time, "monotonic", lambda: now + 11)
    assert c.get("big") is None              # expired
    assert len(c) == 0
