"""Profile-enrichment coverage: extraction (Scrapling + regex fallback) and the
retrieval rules of ``enrich_profiles`` — budget, control probe, template
stripping, rate-limit backoff, fetch-error surfacing. No network: every fetch
is a stub or an ``httpx.MockTransport``.
"""

import asyncio
import time

import httpx

from recon import adapters, enrich, stealthweb
from recon.enrich import FetchResult, _extract, _extract_regex, _extract_scrapling

_HTML = """
<html><head>
<title>Jane &amp; John Doe (@jdoe) &#8226; Profile</title>
<meta property="og:title" content="Jane &amp; John">
<meta name="description" content="Bio with &quot;quotes&quot; &amp; entities">
<meta name="twitter:image" content="https://cdn.example.com/a.png?w=1&amp;h=2">
<script type="application/ld+json">
{"@type":"Person","name":"Jane Doe","image":{"url":"https://x.test/av.jpg"}}
</script>
</head><body></body></html>
"""

# Long enough not to read as a JS shell (< 80 visible chars would escalate).
REAL_PAGE = ("<html><head><title>Real Page</title></head>"
             "<body>hello world, a real page with enough words on it that nobody "
             "could mistake it for an empty application shell or an interstitial."
             "</body></html>")


def test_html_entities_are_decoded():
    # The old extractor kept &amp; / &#8226; verbatim, which polluted name
    # attribution downstream. Both paths must decode now.
    for data in (_extract(_HTML), _extract_regex(_HTML)):
        assert data["title"] == "Jane & John Doe (@jdoe) • Profile"


def test_scrapling_captures_meta_description_and_twitter_image():
    # These are the fields the regex path never reached.
    data = _extract_scrapling(_HTML, "https://x.test/jdoe")
    assert data is not None
    assert data["og_description"] == 'Bio with "quotes" & entities'
    assert data["og_image"] == "https://cdn.example.com/a.png?w=1&h=2"


def test_regex_path_misses_those_fields():
    # Documents the gap the Scrapling path closes (guards against regressing
    # the fallback into silently "passing" without the new coverage).
    rx = _extract_regex(_HTML)
    assert "og_description" not in rx      # no og:description meta present
    assert "og_image" not in rx            # only a twitter:image is present


def test_jsonld_person_is_extracted_by_both_paths():
    for data in (_extract(_HTML), _extract_regex(_HTML)):
        assert data["jsonld_name"] == "Jane Doe"
        assert data["jsonld_image"] == "https://x.test/av.jpg"


def test_extract_prefers_scrapling_but_backfills_from_regex():
    # og:title comes from og meta (both paths); the combined extractor returns
    # a superset that includes the Scrapling-only fields.
    data = _extract(_HTML, "https://x.test/jdoe")
    assert data["og_title"] == "Jane & John"
    assert data["og_description"] == 'Bio with "quotes" & entities'
    assert data["og_image"].endswith("h=2")


def test_regex_path_handles_single_quoted_and_mixed_quote_attributes():
    html = ("<meta property='og:title' content='Jane\"s page'>"
            '<meta name="og:image" content="https://x.test/i.png">'
            "<meta property='og:description' content=\"it's fine\">")
    rx = _extract_regex(html)
    assert rx["og_title"] == 'Jane"s page'
    assert rx["og_image"] == "https://x.test/i.png"
    assert rx["og_description"] == "it's fine"


def test_extract_never_raises_on_garbage():
    for junk in ("", "<not html", "<title>", "\x00\xff", "<script type='application/ld+json'>{bad"):
        assert isinstance(_extract(junk), dict)
        assert isinstance(_extract_regex(junk), dict)


def test_extract_regex_is_linear_on_hostile_markup():
    """F-3: each of these took > 9 s (title/heading > 20 s) with the old regexes
    and ran inside the event loop."""
    for label, hostile in (
            ("title", "<title>" * 40000),
            ("jsonld", '<script type="application/ld+json">' + "{" * 280000),
            ("meta", "<meta a" * 50000),
            ("meta-unterminated-content", '<meta property="og:title" content="' + "a" * 300000),
    ):
        t0 = time.perf_counter()
        _extract_regex(hostile)
        assert time.perf_counter() - t0 < 0.5, label


# --- verification budget --------------------------------------------------

def _no_stealth(monkeypatch):
    monkeypatch.setattr(adapters, "adapter_for", lambda site: None)
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)


def test_policy_denied_rows_do_not_consume_the_verification_budget(monkeypatch):
    """Denied hosts are answered from policy without a fetch. They must not eat
    budget slots that fetchable rows need — in one real run 28 Instagram/
    Pinterest/Twitter rows did exactly that and 105 fetchable rows went
    unexamined."""
    fetched = []

    async def fake_fetch(client, url):
        fetched.append(url)
        return FetchResult(200, REAL_PAGE)

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    monkeypatch.setattr(enrich, "_control_url", lambda url, u: None)
    _no_stealth(monkeypatch)

    denied = [{"username": f"u{i}", "site": "Instagram",
               "url": f"https://www.instagram.com/u{i}/", "engines": ["sherlock"]}
              for i in range(3)]
    fetchable = [{"username": f"u{i}", "site": "Steam",
                  "url": f"https://steamcommunity.com/id/u{i}", "engines": ["sherlock"]}
                 for i in range(3)]
    # Denied rows sort first (same source, more of them is irrelevant): with a
    # budget of 3 the old code spent every slot on them.
    rows = denied + fetchable
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=3))

    assert len(fetched) == 3, "every budget slot must go to a fetchable row"
    for r in denied:
        assert r["verification"]["reason"] == "access_policy"
    for r in fetchable:
        assert r["verification"]["status"] != "not_examined"


# --- control-probe template stripping ----------------------------------------

def test_strip_template_fields_drops_only_site_wide_values():
    from recon.enrich import strip_template_fields
    profile = {"og_image": "https://images-cdn.9gag.com/img/9gag-og.png",
               "og_title": "torvalds on 9GAG", "og_description": "Memes",
               "jsonld_name": "Linus"}
    control = {"og_image": "https://images-cdn.9gag.com/img/9gag-og.png",
               "og_title": "9GAG", "og_description": "Memes"}
    out = strip_template_fields(profile, control)
    assert "og_image" not in out and "og_description" not in out
    assert out["og_title"] == "torvalds on 9GAG" and out["jsonld_name"] == "Linus"
    assert out["template_fields"] == ["og_image", "og_description"]
    assert profile["og_image"]                     # pure: input untouched
    assert "template_fields" not in strip_template_fields({"og_title": "x"}, {})


def test_enrich_profiles_strips_site_logo_shared_with_control_page(monkeypatch):
    """A site that serves its logo as og:image on every page (including the
    page of a nonexistent handle) must not hand that logo to correlation as
    the user's avatar — six unrelated sites once bonded on exactly this."""
    logo = "https://images-cdn.9gag.com/img/9gag-og.png"

    async def fake_fetch(client, url):
        who = "nobody" if "sw_ctl_" in url or "control" in url else "torvalds"
        return FetchResult(200, (
            f"<html><head><title>{who} - 9GAG</title>"
            f'<meta property="og:image" content="{logo}">'
            f'<meta property="og:title" content="{who} on 9GAG">'
            f"</head><body><h1>{who}</h1>"
            f"<p>Profile page of {who} with posts and comments {'x ' * 40}</p>"
            "</body></html>"))

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    monkeypatch.setattr(enrich, "_control_url",
                        lambda url, u: "https://9gag.com/u/sw_ctl_nobody")
    _no_stealth(monkeypatch)

    row = {"username": "torvalds", "site": "9GAG",
           "url": "https://9gag.com/u/torvalds", "engines": ["maigret"]}
    asyncio.run(enrich.enrich_profiles([row], lambda r, d: None, limit=5))
    enr = row["enrichment"]
    assert "og_image" not in enr, "site logo must not survive as an avatar"
    assert enr["og_title"] == "torvalds on 9GAG"     # person-specific: kept
    assert enr["template_fields"] == ["og_image"]


# --- V7: rate limits back off, never escalate --------------------------------

def _rows(host, n, site="Site"):
    return [{"username": f"u{i}", "site": site, "url": f"https://{host}/u{i}",
             "engines": ["sherlock"]} for i in range(n)]


def test_rate_limited_host_is_fetched_once_and_never_escalated(monkeypatch):
    """Trace (a) of the retrieval audit: one 429 used to be answered with a
    TLS-impersonated retry, a browser fetch and a control fetch — four requests
    — and every other row on the host repeated it. Now: one request, a
    per-host backoff, and the remaining rows are marked without fetching."""
    fetched = []
    tls_calls = {"n": 0}

    async def fake_fetch(client, url):
        fetched.append(url)
        await asyncio.sleep(0)      # real latency: other rows are already waiting
        if "ratelimited.example" in url:
            return FetchResult(429, "<html><body>Too many requests</body></html>")
        if enrich.CONTROL_HANDLE in url:
            return FetchResult(404, None)   # other.example 404s unknown handles
        return FetchResult(200, REAL_PAGE)

    async def fake_tls(url):
        tls_calls["n"] += 1
        return None, None

    async def never_browser(url):
        raise AssertionError("browser tier must not run for a rate limit")

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    monkeypatch.setattr(adapters, "adapter_for", lambda site: None)
    monkeypatch.setattr(stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(stealthweb, "fetch_tls", fake_tls)
    monkeypatch.setattr(stealthweb, "fetch_browser", never_browser)

    limited = _rows("ratelimited.example", 4)
    other = _rows("other.example", 1)
    stats = {}
    asyncio.run(enrich.enrich_profiles(limited + other, lambda r, d: None,
                                       limit=10, stats=stats))

    hits = [u for u in fetched if "ratelimited.example" in u]
    assert len(hits) == 1, hits
    assert enrich.CONTROL_HANDLE not in hits[0], "the control probe must not run"
    assert tls_calls["n"] == 0, "no stealth ladder on a 429"
    for r in limited:
        v = r["verification"]
        assert v["status"] == "indeterminate" and v["score"] == 30
        assert v["reason"] == "rate_limited"
        assert v["signals"][0] == "rate limited (HTTP 429) — not retried this run"
    not_fetched = [r for r in limited if len(r["verification"]["signals"]) > 1]
    assert len(not_fetched) == 3
    assert other[0]["verification"]["status"] != "indeterminate"
    assert stats["rate_limited_hosts"] == 1
    assert stats["rate_limited_rows"] == 4
    assert stats["backoff_s"]["ratelimited.example"] == enrich.DEFAULT_BACKOFF_S


def test_retry_after_header_sets_the_backoff_and_503_counts_too(monkeypatch):
    async def fake_fetch(client, url):
        if "a.example" in url:
            return FetchResult(429, None, None, 120.0)
        return FetchResult(503, "<html>maintenance</html>", None, None)

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    _no_stealth(monkeypatch)
    rows = _rows("a.example", 2) + _rows("b.example", 2)
    stats = {}
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=10, stats=stats))
    assert stats["backoff_s"] == {"a.example": 120.0, "b.example": enrich.DEFAULT_BACKOFF_S}
    assert stats["rate_limited_hosts"] == 2 and stats["rate_limited_rows"] == 4
    assert rows[2]["verification"]["reason"] == "rate_limited"
    assert "HTTP 503" in rows[2]["verification"]["signals"][0]


def test_rate_limited_control_probe_backs_off_the_host(monkeypatch):
    """A 429 on the control fetch used to be cached as "no control" for the
    run and every later row still hammered the host. Now it is a failed probe
    and the host backs off."""
    fetched = []

    async def fake_fetch(client, url):
        fetched.append(url)
        if enrich.CONTROL_HANDLE in url:
            return FetchResult(429, None)
        return FetchResult(200, REAL_PAGE)

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    _no_stealth(monkeypatch)
    rows = _rows("c.example", 3)
    stats = {}
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=10, stats=stats))
    profile_fetches = [u for u in fetched if enrich.CONTROL_HANDLE not in u]
    control_fetches = [u for u in fetched if enrich.CONTROL_HANDLE in u]
    assert len(profile_fetches) == 1 and len(control_fetches) == 1
    first = next(r for r in rows if r["verification"].get("reason") != "rate_limited")
    assert first["verification"]["control_probe"] == "failed"
    assert sum(1 for r in rows if r["verification"].get("reason") == "rate_limited") == 2
    assert stats["control_failed_hosts"] == ["c.example"]


# --- control-probe honesty ---------------------------------------------------

def test_failed_control_probe_is_retried_once_then_reported_failed(monkeypatch):
    fetched = []

    async def fake_fetch(client, url):
        fetched.append(url)
        if enrich.CONTROL_HANDLE in url:
            return FetchResult(500, None)
        return FetchResult(200, REAL_PAGE)

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    _no_stealth(monkeypatch)
    rows = _rows("d.example", 3)
    stats = {}
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=10, stats=stats))
    assert sum(1 for u in fetched if enrich.CONTROL_HANDLE in u) == enrich.CONTROL_MAX_ATTEMPTS
    assert [r["verification"]["control_probe"] for r in rows] == ["failed"] * 3
    assert stats["control_failed_hosts"] == ["d.example"]


def test_transport_failure_on_the_control_is_failed_not_not_applicable(monkeypatch):
    async def fake_fetch(client, url):
        if enrich.CONTROL_HANDLE in url:
            return FetchResult(None, None, "ReadTimeout")
        return FetchResult(200, REAL_PAGE)

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    _no_stealth(monkeypatch)
    rows = _rows("e.example", 1)
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=10))
    assert rows[0]["verification"]["control_probe"] == "failed"


def test_control_probe_success_on_retry_is_cached(monkeypatch):
    calls = {"control": 0}

    async def fake_fetch(client, url):
        if enrich.CONTROL_HANDLE in url:
            calls["control"] += 1
            if calls["control"] == 1:
                return FetchResult(None, None, "ConnectError")
            return FetchResult(200, "<html><head><title>Not here</title></head>"
                                    "<body>no such member on this site</body></html>")
        return FetchResult(200, REAL_PAGE)

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    _no_stealth(monkeypatch)
    rows = _rows("f.example", 3)
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=10))
    assert calls["control"] == 2
    assert sorted(r["verification"]["control_probe"] for r in rows) == ["failed", "ran", "ran"]


def test_404_control_is_decisive_and_cached_not_failed(monkeypatch):
    """A site that 404s the control handle answered the probe decisively; there
    is simply no page to compare. That is not a failure and is never retried."""
    calls = {"control": 0}

    async def fake_fetch(client, url):
        if enrich.CONTROL_HANDLE in url:
            calls["control"] += 1
            return FetchResult(404, None)
        return FetchResult(200, REAL_PAGE)

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    _no_stealth(monkeypatch)
    rows = _rows("g.example", 3)
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=10))
    assert calls["control"] == 1
    assert {r["verification"]["control_probe"] for r in rows} == {"not_applicable"}


# --- fetch-error class and ladder behaviour ----------------------------------

def test_fetch_error_class_reaches_the_verdict(monkeypatch):
    async def fake_fetch(client, url):
        return FetchResult(None, None, "ConnectTimeout")

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    _no_stealth(monkeypatch)
    rows = _rows("h.example", 1)
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=10))
    v = rows[0]["verification"]
    assert v["status"] == "indeterminate"
    assert "ConnectTimeout" in v["signals"][0]


def test_escalation_never_asks_the_browser_to_solve_challenges(monkeypatch):
    """The browser fake accepts only ``url`` — any solver kwarg would raise and
    the row would never get its rescued verdict."""
    challenge = ("<html><head><title>Just a moment...</title></head>"
                 "<body>Checking your browser before accessing.</body></html>")
    browser_calls = []

    async def fake_fetch(client, url):
        if enrich.CONTROL_HANDLE in url:
            return FetchResult(404, None)
        return FetchResult(200, challenge)

    async def fake_tls(url):
        return 200, challenge

    async def fake_browser(url):
        browser_calls.append(url)
        return 200, ("<html><head><title>realperson77 (Real Person) · Site</title></head>"
                     "<body>" + "rendered profile content " * 10 + "</body></html>")

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    monkeypatch.setattr(adapters, "adapter_for", lambda site: None)
    monkeypatch.setattr(stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(stealthweb, "fetch_tls", fake_tls)
    monkeypatch.setattr(stealthweb, "fetch_browser", fake_browser)
    rows = [{"username": "realperson77", "site": "Site",
             "url": "https://i.example/realperson77", "engines": ["sherlock"]}]
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=10))
    assert browser_calls == ["https://i.example/realperson77"]
    assert rows[0].get("fetch_via") == "scrapling_browser"
    assert rows[0]["verification"]["status"] == "confirmed"


def test_challenge_page_that_survives_rendering_stays_blocked(monkeypatch):
    challenge = ("<html><head><title>Just a moment...</title></head>"
                 "<body>Checking your browser before accessing.</body></html>")

    async def fake_fetch(client, url):
        if enrich.CONTROL_HANDLE in url:
            return FetchResult(200, challenge)
        return FetchResult(200, challenge)

    async def fake_tls(url):
        return 200, challenge

    async def fake_browser(url):
        return 200, challenge

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    monkeypatch.setattr(adapters, "adapter_for", lambda site: None)
    monkeypatch.setattr(stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(stealthweb, "fetch_tls", fake_tls)
    monkeypatch.setattr(stealthweb, "fetch_browser", fake_browser)
    rows = _rows("j.example", 1)
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=10))
    v = rows[0]["verification"]
    assert v["status"] == "indeterminate"
    assert "anti-bot challenge page" in v["signals"][0]
    assert "fetch_via" not in rows[0]


def test_browser_seen_404_upgrades_a_blocked_plain_status(monkeypatch):
    """The "a tier answered decisively" branch was unreachable whenever the
    plain status was ≥ 400 — i.e. exactly when status-driven escalation runs."""
    async def fake_fetch(client, url):
        if enrich.CONTROL_HANDLE in url:
            return FetchResult(403, None)
        return FetchResult(403, None)

    async def fake_tls(url):
        return 403, None

    async def fake_browser(url):
        return 404, None

    monkeypatch.setattr(enrich, "_fetch_page_ex", fake_fetch)
    monkeypatch.setattr(adapters, "adapter_for", lambda site: None)
    monkeypatch.setattr(stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(stealthweb, "fetch_tls", fake_tls)
    monkeypatch.setattr(stealthweb, "fetch_browser", fake_browser)
    rows = _rows("k.example", 1)
    asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, limit=10))
    assert rows[0]["verification"]["status"] == "likely_false_positive"


def test_rate_limited_verdict_shape():
    v = enrich.rate_limited_verdict(429)
    assert v == {"status": "indeterminate", "score": 30,
                 "signals": ["rate limited (HTTP 429) — not retried this run"],
                 "reason": "rate_limited"}
    skipped = enrich.rate_limited_verdict(429, fetched=False)
    assert skipped["signals"][0] == v["signals"][0]
    assert "not fetched" in skipped["signals"][1]


# --- _fetch_page_ex over a mock transport ------------------------------------

def test_fetch_page_ex_reports_status_retry_after_and_error_class():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/limited":
            return httpx.Response(429, headers={"Retry-After": "120",
                                                "content-type": "text/html"},
                                  text="<html>slow down</html>")
        if path == "/json":
            return httpx.Response(200, json={"a": 1})
        if path == "/boom":
            raise httpx.ConnectTimeout("timed out")
        return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"},
                              text="<html><title>ok</title></html>")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            limited = await enrich._fetch_page_ex(client, "https://h.example/limited")
            as_json = await enrich._fetch_page_ex(client, "https://h.example/json")
            boom = await enrich._fetch_page_ex(client, "https://h.example/boom")
            ok = await enrich._fetch_page_ex(client, "https://h.example/ok")
            two = await enrich._fetch_page(client, "https://h.example/ok")
            return limited, as_json, boom, ok, two

    limited, as_json, boom, ok, two = asyncio.run(run())
    assert limited == FetchResult(429, "<html>slow down</html>", None, 120.0)
    assert as_json.status == 200 and as_json.html is None and as_json.error is None
    assert boom.status is None and boom.error == "ConnectTimeout"
    assert ok.status == 200 and "ok" in ok.html
    assert two == (200, ok.html) and len(two) == 2


def test_parse_retry_after():
    from email.utils import format_datetime
    from datetime import datetime, timedelta, timezone
    assert enrich._parse_retry_after(None) is None
    assert enrich._parse_retry_after("garbage") is None
    assert enrich._parse_retry_after("90") == 90.0
    assert enrich._parse_retry_after("999999") == enrich.MAX_BACKOFF_S
    soon = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30), usegmt=True)
    assert 25.0 <= enrich._parse_retry_after(soon) <= 31.0
    past = format_datetime(datetime.now(timezone.utc) - timedelta(seconds=30), usegmt=True)
    assert enrich._parse_retry_after(past) == 0.0
