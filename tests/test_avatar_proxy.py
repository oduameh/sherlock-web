"""The avatar proxy (Increment H2, V11 / F-6).

Remote avatars are relayed by ``GET /api/avatar?u=`` so the analyst's browser
never contacts the subject's host. ``httpx.MockTransport`` stands in for the
network; the real SSRF guard hooks stay on the client (DNS is stubbed to a
public address so the guard runs offline), and the request-protection
middleware runs as in production.
"""

import time

import httpx
import re

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
        kw = appmod._avatar_client_kwargs()
        kw["timeout"] = 1.0
        return safeweb.async_client(transport=httpx.MockTransport(handler), **kw)

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


# --- review of H2: bombs, deadlines, redirect loops, ports, userinfo, trailing dot -------

SAME = {"Sec-Fetch-Site": "same-origin"}


def test_compressed_upstream_bodies_are_refused(proxy):
    """httpx inflates a gzip bomb chunk by chunk before a byte cap sees it."""
    # A streamed body (not pre-read by the mock) so the encoding check runs
    # before any byte is decoded.
    proxy.respond(lambda r: httpx.Response(200, stream=_Chunks(100),
                                           headers={"content-type": "image/png",
                                                    "content-encoding": "gzip"}))
    assert proxy.get(_u(IMG), headers=SAME).status_code == 415


def test_request_advertises_identity_encoding(proxy):
    assert proxy.get(_u(IMG), headers=SAME).status_code == 200
    assert proxy.calls[-1].headers.get("accept-encoding") == "identity"


def test_total_deadline_caps_a_dripping_upstream(proxy, monkeypatch):
    import asyncio as _a
    monkeypatch.setattr(appmod, "AVATAR_TOTAL_DEADLINE_S", 0.3)

    async def slow(r):
        await _a.sleep(1.5)
        return httpx.Response(200, content=PNG, headers={"content-type": "image/png"})
    proxy.respond(slow)
    r = proxy.get(_u("https://cdn.example/slow.png"), headers=SAME)
    assert r.status_code == 502 and "exceeded" in r.json()["error"]


def test_redirect_loops_are_capped(proxy):
    proxy.respond(lambda r: httpx.Response(302, headers={"location": "https://cdn.example/loop"}))
    r = proxy.get(_u("https://cdn.example/loop"), headers=SAME)
    assert r.status_code == 502
    assert len(proxy.calls) <= appmod.AVATAR_MAX_REDIRECTS + 1


@pytest.mark.parametrize("url", ["https://cdn.example:22/a.png", "https://user:pw@cdn.example/a.png",
                                 "https://cdn.example:8443/a.png"])
def test_ports_and_userinfo_are_refused(proxy, url):
    assert proxy.get(_u(url), headers=SAME).status_code == 400
    assert proxy.calls == []


def test_trailing_dot_does_not_bypass_the_policy(proxy):
    from recon import policy
    assert policy.denied_reason("https://www.instagram.com./x.jpg")
    assert proxy.get(_u("https://www.instagram.com./x.jpg"), headers=SAME).status_code == 403
    assert proxy.calls == []


def test_iframe_sandbox_allows_modals_and_downloads():
    html = (appmod.STATIC_DIR / "index.html").read_text()
    tag = re.search(r"<iframe id=\"gevFrame\"[^>]*>", html).group(0)
    sandbox = re.search(r'sandbox="([^"]*)"', tag).group(1).split()
    allow = re.search(r'allow="([^"]*)"', tag).group(1)
    assert {"allow-scripts", "allow-same-origin", "allow-modals", "allow-downloads"} <= set(sandbox)
    assert "microphone" not in allow and "camera" not in allow


# --- saved reports embed server-made thumbnails (V11 for the file on disk) ----

def _real_png(size=(120, 90)):
    import io
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", size, (30, 144, 255)).save(buf, format="PNG")
    return buf.getvalue()


def _seed_recon_run(avatar_url, gravatar_url=None):
    import json
    from dbconn import connect, insert_returning_id
    results = {
        "params": {"usernames": ["alice"]},
        "accounts": [{"site": "GitHub", "username": "alice", "url": "https://github.com/alice",
                      "engines": ["sherlock"], "enrichment": {"og_image": avatar_url}}],
        "variants": [], "correlation": [],
        "email": {"gravatar": {"avatar_url": gravatar_url, "profile_url": "https://gravatar.com/alice",
                               "display_name": "Alice"}} if gravatar_url else {},
    }
    with connect(appmod.DB_PATH) as conn:
        return insert_returning_id(
            conn, "INSERT INTO runs (ts, username, found, total, results, kind, investigation_id)"
                  " VALUES (?,?,?,?,?,?,?)",
            ("2026-09-06 00:00:00", "alice", 1, 1, json.dumps(results), "recon", None))


SRC_ATTR = re.compile(r"""src=(['"])(.*?)\1""", re.I | re.S)


def test_report_embeds_proxied_thumbnails_and_never_the_remote_url(proxy):
    proxy.respond(lambda r: httpx.Response(200, content=_real_png(),
                                           headers={"content-type": "image/png"}))
    run_id = _seed_recon_run(IMG, "https://0.gravatar.com/avatar/abc")
    r = proxy.get(f"/api/recon/report/{run_id}")
    assert r.status_code == 200
    srcs = [u for _, u in SRC_ATTR.findall(r.text)]
    assert len(srcs) == 2 and all(u.startswith("data:image/png;base64,") for u in srcs)
    assert "cdn.example" not in r.text and "0.gravatar.com/avatar" not in r.text
    assert sorted(str(c.url) for c in proxy.calls) == sorted([IMG, "https://0.gravatar.com/avatar/abc"])
    # Rendering again serves from the avatar cache: no second fetch.
    proxy.get(f"/api/recon/report/{run_id}")
    assert len(proxy.calls) == 2


def test_report_renders_without_a_picture_when_the_avatar_cannot_be_fetched(proxy):
    proxy.respond(lambda r: httpx.Response(503))
    run_id = _seed_recon_run(IMG)
    r = proxy.get(f"/api/recon/report/{run_id}")
    assert r.status_code == 200 and "<img" not in r.text and "cdn.example" not in r.text
    assert "alice" in r.text
    # An undecodable body is a missing picture too, not an error.
    proxy.respond(lambda r: httpx.Response(200, content=PNG, headers={"content-type": "image/png"}))
    appmod._avatar_cache.clear()
    r = proxy.get(f"/api/recon/report/{run_id}")
    assert r.status_code == 200 and "<img" not in r.text


def test_report_applies_the_proxys_refusals_without_touching_the_network(proxy):
    run_id = _seed_recon_run("https://www.instagram.com/x.jpg", "https://user:pw@cdn.example/a.png")
    r = proxy.get(f"/api/recon/report/{run_id}")
    assert r.status_code == 200 and "<img" not in r.text
    assert proxy.calls == []


def test_report_thumbnails_stop_at_the_budget(proxy, monkeypatch):
    import asyncio

    async def slow(request):
        await asyncio.sleep(2)
        return httpx.Response(200, content=_real_png(), headers={"content-type": "image/png"})

    proxy.respond(slow)
    monkeypatch.setattr(appmod, "AVATAR_REPORT_BUDGET_S", 0.2)
    run_id = _seed_recon_run(IMG)
    t0 = time.monotonic()
    r = proxy.get(f"/api/recon/report/{run_id}")
    assert time.monotonic() - t0 < 1.5
    assert r.status_code == 200 and "<img" not in r.text
