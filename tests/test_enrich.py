"""Profile-enrichment coverage: extraction (Scrapling + regex fallback) and the
retrieval rules of ``enrich_profiles`` — budget, control probe, template
stripping, rate-limit backoff, the stealth ladder, blocked/transport reasons.
No network: every page comes from an ``httpx.MockTransport`` behind the real
SSRF-guarded client (G2: the fetch itself is ``recon.retrieval.fetch``; there
is no enrichment-private fetcher left to stub).
"""

import asyncio
import time

import httpx
import pytest
from conftest import mock_client

from recon import adapters, enrich, retrieval, stealthweb
from recon.enrich import _extract, _extract_regex, _extract_scrapling
from recon.ladder import StealthLadder

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
CHALLENGE = ("<html><head><title>Just a moment...</title></head>"
             "<body>Checking your browser before accessing.</body></html>")


@pytest.fixture(autouse=True)
def _dns(public_dns):
    """Every fetch here is offline: the guard resolves to a public address."""


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


# --- helpers ------------------------------------------------------------------

def _html(body, status=200, headers=None):
    h = {"content-type": "text/html; charset=utf-8"}
    if headers:
        h.update(headers)
    return httpx.Response(status, headers=h, text=body)


def _install(monkeypatch, handler, calls=None):
    """Route every enrichment fetch to ``handler`` (a MockTransport handler)."""
    monkeypatch.setattr(enrich.safeweb, "async_client", mock_client(handler, calls))


def _urls(calls):
    return [str(r.url) for r in calls]


def _no_stealth(monkeypatch):
    monkeypatch.setattr(adapters, "adapter_for", lambda site: None)
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)


def _stealth(monkeypatch, tls, browser):
    monkeypatch.setattr(adapters, "adapter_for", lambda site: None)
    monkeypatch.setattr(stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(stealthweb, "fetch_tls", tls)
    monkeypatch.setattr(stealthweb, "fetch_browser", browser)


def _rows(host, n, site="Site"):
    return [{"username": f"u{i}", "site": site, "url": f"https://{host}/u{i}",
             "engines": ["sherlock"]} for i in range(n)]


def _run(rows, **kw):
    kw.setdefault("limit", 10)
    return asyncio.run(enrich.enrich_profiles(rows, lambda r, d: None, **kw))


# --- verification budget --------------------------------------------------

def test_policy_denied_rows_do_not_consume_the_verification_budget(monkeypatch):
    """Denied hosts are answered from policy without a fetch. They must not eat
    budget slots that fetchable rows need — in one real run 28 Instagram/
    Pinterest/Twitter rows did exactly that and 105 fetchable rows went
    unexamined."""
    calls = []
    _install(monkeypatch, lambda req: _html(REAL_PAGE), calls)
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
    _run(rows, limit=3)

    assert len(calls) == 3, "every budget slot must go to a fetchable row"
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

    def handler(req):
        who = "nobody" if "sw_ctl_" in req.url.path else "torvalds"
        return _html(
            f"<html><head><title>{who} - 9GAG</title>"
            f'<meta property="og:image" content="{logo}">'
            f'<meta property="og:title" content="{who} on 9GAG">'
            f"</head><body><h1>{who}</h1>"
            f"<p>Profile page of {who} with posts and comments {'x ' * 40}</p>"
            "</body></html>")

    _install(monkeypatch, handler)
    monkeypatch.setattr(enrich, "_control_url",
                        lambda url, u: "https://9gag.com/u/sw_ctl_nobody")
    _no_stealth(monkeypatch)

    row = {"username": "torvalds", "site": "9GAG",
           "url": "https://9gag.com/u/torvalds", "engines": ["maigret"]}
    _run([row], limit=5)
    enr = row["enrichment"]
    assert "og_image" not in enr, "site logo must not survive as an avatar"
    assert enr["og_title"] == "torvalds on 9GAG"     # person-specific: kept
    assert enr["template_fields"] == ["og_image"]


# --- V7: rate limits back off, never escalate --------------------------------

def test_rate_limited_host_is_fetched_once_and_never_escalated(monkeypatch):
    """Trace (a) of the retrieval audit: one 429 used to be answered with a
    TLS-impersonated retry, a browser fetch and a control fetch — four requests
    — and every other row on the host repeated it. Now: one request, a
    per-host backoff in the shared HostState, and the remaining rows are
    marked without fetching."""
    calls = []
    tls_calls = {"n": 0}

    def handler(req):
        if req.url.host == "ratelimited.example":
            return _html("<html><body>Too many requests</body></html>", 429)
        if enrich.CONTROL_HANDLE in req.url.path:
            return httpx.Response(404)   # other.example 404s unknown handles
        return _html(REAL_PAGE)

    async def fake_tls(url):
        tls_calls["n"] += 1
        return None, None

    async def never_browser(url):
        raise AssertionError("browser tier must not run for a rate limit")

    _install(monkeypatch, handler, calls)
    _stealth(monkeypatch, fake_tls, never_browser)

    limited = _rows("ratelimited.example", 4)
    other = _rows("other.example", 1)
    stats = {}
    hs = retrieval.HostState()
    _run(limited + other, stats=stats, host_state=hs)

    hits = [u for u in _urls(calls) if "ratelimited.example" in u]
    assert len(hits) == 1, hits
    assert enrich.CONTROL_HANDLE not in hits[0], "the control probe must not run"
    assert tls_calls["n"] == 0, "no stealth ladder on a 429"
    for r in limited:
        v = r["verification"]
        assert v["status"] == "indeterminate" and v["score"] == 30
        assert v["reason"] == "rate_limited"
        assert v["signals"][0] == "rate limited / unavailable (HTTP 429) — not retried this run"
    not_fetched = [r for r in limited if len(r["verification"]["signals"]) > 1]
    assert len(not_fetched) == 3
    assert other[0]["verification"]["status"] != "indeterminate"
    assert stats["rate_limited_hosts"] == 1
    assert stats["rate_limited_rows"] == 4
    assert stats["backoff_s"]["ratelimited.example"] == retrieval.DEFAULT_BACKOFF_S
    # The backoff lives in the shared per-host state, not in enrichment.
    assert hs.active_backoff("ratelimited.example") is not None
    assert hs.last_status("ratelimited.example") == 429


def test_retry_after_header_sets_the_backoff_and_503_counts_too(monkeypatch):
    def handler(req):
        if req.url.host == "a.example":
            return httpx.Response(429, headers={"Retry-After": "120"})
        return _html("<html>maintenance</html>", 503)

    _install(monkeypatch, handler)
    _no_stealth(monkeypatch)
    rows = _rows("a.example", 2) + _rows("b.example", 2)
    stats = {}
    _run(rows, stats=stats)
    assert stats["backoff_s"] == {"a.example": 120.0,
                                  "b.example": retrieval.DEFAULT_BACKOFF_S}
    assert stats["rate_limited_hosts"] == 2 and stats["rate_limited_rows"] == 4
    assert rows[2]["verification"]["reason"] == "rate_limited"
    assert "HTTP 503" in rows[2]["verification"]["signals"][0]


def test_a_host_backed_off_earlier_in_the_run_is_never_requested(monkeypatch):
    """The HostState is shared across the run: a 429 seen by discovery keeps
    enrichment away from the host without a single request."""
    calls = []
    _install(monkeypatch, lambda req: _html(REAL_PAGE), calls)
    _no_stealth(monkeypatch)
    hs = retrieval.HostState()
    hs.backoff("busy.example", 60, status=429)
    hs.record("busy.example", retrieval.BLOCKED, 429)
    rows = _rows("busy.example", 2)
    _run(rows, host_state=hs)
    assert calls == []
    for r in rows:
        assert r["verification"]["reason"] == "rate_limited"
        assert "not fetched" in r["verification"]["signals"][1]


def test_rate_limited_control_probe_backs_off_the_host(monkeypatch):
    """A 429 on the control fetch used to be cached as "no control" for the
    run and every later row still hammered the host. Now it is a failed probe
    and the host backs off."""
    calls = []

    def handler(req):
        if enrich.CONTROL_HANDLE in req.url.path:
            return httpx.Response(429)
        return _html(REAL_PAGE)

    _install(monkeypatch, handler, calls)
    _no_stealth(monkeypatch)
    rows = _rows("c.example", 3)
    stats = {}
    _run(rows, stats=stats)
    profile_fetches = [u for u in _urls(calls) if enrich.CONTROL_HANDLE not in u]
    control_fetches = [u for u in _urls(calls) if enrich.CONTROL_HANDLE in u]
    assert len(profile_fetches) == 1 and len(control_fetches) == 1
    first = next(r for r in rows if r["verification"].get("reason") != "rate_limited")
    assert first["verification"]["control_probe"] == "failed"
    assert sum(1 for r in rows if r["verification"].get("reason") == "rate_limited") == 2
    assert stats["control_failed_hosts"] == ["c.example"]


# --- control-probe honesty ---------------------------------------------------

def test_failed_control_probe_is_retried_once_then_reported_failed(monkeypatch):
    calls = []

    def handler(req):
        if enrich.CONTROL_HANDLE in req.url.path:
            return httpx.Response(500)
        return _html(REAL_PAGE)

    _install(monkeypatch, handler, calls)
    _no_stealth(monkeypatch)
    rows = _rows("d.example", 3)
    stats = {}
    _run(rows, stats=stats)
    assert sum(1 for u in _urls(calls) if enrich.CONTROL_HANDLE in u) == enrich.CONTROL_MAX_ATTEMPTS
    assert [r["verification"]["control_probe"] for r in rows] == ["failed"] * 3
    assert stats["control_failed_hosts"] == ["d.example"]


def test_transport_failure_on_the_control_is_failed_not_not_applicable(monkeypatch):
    def handler(req):
        if enrich.CONTROL_HANDLE in req.url.path:
            raise httpx.ReadTimeout("slow")
        return _html(REAL_PAGE)

    _install(monkeypatch, handler)
    _no_stealth(monkeypatch)
    rows = _rows("e.example", 1)
    _run(rows)
    assert rows[0]["verification"]["control_probe"] == "failed"


def test_control_probe_success_on_retry_is_cached(monkeypatch):
    calls = {"control": 0}

    def handler(req):
        if enrich.CONTROL_HANDLE in req.url.path:
            calls["control"] += 1
            if calls["control"] == 1:
                raise httpx.ConnectError("refused")
            return _html("<html><head><title>Not here</title></head>"
                         "<body>no such member on this site</body></html>")
        return _html(REAL_PAGE)

    _install(monkeypatch, handler)
    _no_stealth(monkeypatch)
    rows = _rows("f.example", 3)
    _run(rows)
    assert calls["control"] == 2
    assert sorted(r["verification"]["control_probe"] for r in rows) == ["failed", "ran", "ran"]


def test_404_control_is_decisive_and_cached_not_failed(monkeypatch):
    """A site that 404s the control handle answered the probe decisively; there
    is simply no page to compare. That is not a failure and is never retried."""
    calls = {"control": 0}

    def handler(req):
        if enrich.CONTROL_HANDLE in req.url.path:
            calls["control"] += 1
            return httpx.Response(404)
        return _html(REAL_PAGE)

    _install(monkeypatch, handler)
    _no_stealth(monkeypatch)
    rows = _rows("g.example", 3)
    _run(rows)
    assert calls["control"] == 1
    assert {r["verification"]["control_probe"] for r in rows} == {"not_applicable"}


def test_a_wall_on_the_control_is_a_failed_probe_not_a_control(monkeypatch):
    """A challenge page for the control handle is not a page to compare
    against; it used to be cached as the site's control."""
    def handler(req):
        if enrich.CONTROL_HANDLE in req.url.path:
            return _html(CHALLENGE)
        return _html(REAL_PAGE)

    _install(monkeypatch, handler)
    _no_stealth(monkeypatch)
    rows = _rows("w.example", 1)
    stats = {}
    _run(rows, stats=stats)
    assert rows[0]["verification"]["control_probe"] == "failed"
    assert stats["control_failed_hosts"] == ["w.example"]


# --- blocked / transport rows carry retrieval's reason verbatim -----------------

def test_fetch_error_class_reaches_the_verdict(monkeypatch):
    def handler(req):
        raise httpx.ConnectTimeout("timed out")

    _install(monkeypatch, handler)
    _no_stealth(monkeypatch)
    rows = _rows("h.example", 1)
    _run(rows)
    v = rows[0]["verification"]
    assert v["status"] == "indeterminate"
    assert v["signals"][0] == "no response (ConnectTimeout) — cannot determine existence"
    assert v["reason"] == "transport"


def test_login_redirect_is_blocked_with_the_reason(monkeypatch):
    """A 2xx that landed on a login page is not the profile; the body alone
    cannot show it (it is a normal-looking page), so the verdict comes from
    retrieval's final-URL rule."""
    def handler(req):
        if req.url.path.startswith("/login"):
            return _html("<html><head><title>Sign in</title></head><body>"
                         + "<p>Please sign in to continue to your account.</p>" * 6
                         + "</body></html>")
        if enrich.CONTROL_HANDLE in req.url.path:
            return httpx.Response(404)
        return httpx.Response(302, headers={"location": "https://l.example/login?next=/u0"})

    _install(monkeypatch, handler)
    _no_stealth(monkeypatch)
    rows = _rows("l.example", 1)
    _run(rows)
    v = rows[0]["verification"]
    assert v["status"] == "indeterminate" and v["reason"] == "blocked"
    assert v["signals"][0] == "blocked: login redirect (/login) — cannot determine existence"
    assert "control_probe" not in v          # a decisive 404 control: nothing to compare
    assert "enrichment" not in rows[0], "a login page's metadata is not the person's"


def test_blocked_status_keeps_the_cf_mitigated_detail(monkeypatch):
    def handler(req):
        return httpx.Response(403, headers={"cf-mitigated": "challenge"})

    _install(monkeypatch, handler)
    _no_stealth(monkeypatch)
    rows = _rows("m.example", 1)
    _run(rows)
    v = rows[0]["verification"]
    assert v["status"] == "indeterminate"
    assert v["signals"][0].startswith("blocked: HTTP 403 (cf-mitigated: challenge)")


def test_ssrf_url_is_not_examined(monkeypatch):
    calls = []
    _install(monkeypatch, lambda req: _html(REAL_PAGE), calls)
    _no_stealth(monkeypatch)
    row = {"username": "x", "site": "Site", "url": "http://127.0.0.1:8080/x",
           "engines": ["sherlock"]}
    _run([row])
    assert calls == []
    assert row["verification"]["status"] == "not_examined"
    assert row["verification"]["reason"] == "ssrf"


def test_blocked_verdict_shape():
    res = retrieval.FetchResult(retrieval.BLOCKED, "HTTP 403", 403, None)
    v = enrich.blocked_verdict(res, control_probe="failed")
    assert v == {"status": "indeterminate", "score": 30,
                 "signals": ["blocked: HTTP 403 — cannot determine existence"],
                 "reason": "blocked", "control_probe": "failed"}
    t = enrich.blocked_verdict(retrieval.FetchResult(
        retrieval.TRANSPORT, "no response (ReadError)", None, None, "ReadError"))
    assert t["signals"] == ["no response (ReadError) — cannot determine existence"]
    assert "control_probe" not in t


# --- the stealth ladder ---------------------------------------------------------

def test_escalation_never_asks_the_browser_to_solve_challenges(monkeypatch):
    """The browser fake accepts only ``url`` — any solver kwarg would raise and
    the row would never get its rescued verdict."""
    browser_calls = []

    def handler(req):
        if enrich.CONTROL_HANDLE in req.url.path:
            return httpx.Response(404)
        return _html(CHALLENGE)

    async def fake_tls(url):
        return 200, CHALLENGE

    async def fake_browser(url):
        browser_calls.append(url)
        return 200, ("<html><head><title>realperson77 (Real Person) · Site</title></head>"
                     "<body>" + "rendered profile content " * 10 + "</body></html>")

    _install(monkeypatch, handler)
    _stealth(monkeypatch, fake_tls, fake_browser)
    rows = [{"username": "realperson77", "site": "Site",
             "url": "https://i.example/realperson77", "engines": ["sherlock"]}]
    ladder = StealthLadder(enrich.STEALTH_BROWSER_BUDGET)
    stats = {}
    _run(rows, ladder=ladder, stats=stats)
    assert browser_calls == ["https://i.example/realperson77"]
    assert rows[0].get("fetch_via") == "scrapling_browser"
    assert rows[0]["verification"]["status"] == "confirmed"
    assert stats["stealth_browser"] == 1 and stats["stealth_tls"] == 0
    assert stats["stealth"] == {"tls_attempts": 1, "tls_ok": 0, "browser_attempts": 1,
                                "browser_ok": 1,
                                "browser_budget": enrich.STEALTH_BROWSER_BUDGET,
                                "browser_budget_left": enrich.STEALTH_BROWSER_BUDGET - 1,
                                "rate_limited": 0}


def test_challenge_page_that_survives_rendering_stays_blocked(monkeypatch):
    _install(monkeypatch, lambda req: _html(CHALLENGE))

    async def fake_tls(url):
        return 200, CHALLENGE

    async def fake_browser(url):
        return 200, CHALLENGE

    _stealth(monkeypatch, fake_tls, fake_browser)
    rows = _rows("j.example", 1)
    _run(rows)
    v = rows[0]["verification"]
    assert v["status"] == "indeterminate"
    assert "anti-bot challenge page" in v["signals"][0]
    assert "fetch_via" not in rows[0]


def test_browser_seen_404_upgrades_a_blocked_plain_status(monkeypatch):
    """The "a tier answered decisively" branch was unreachable whenever the
    plain status was ≥ 400 — i.e. exactly when status-driven escalation runs."""
    _install(monkeypatch, lambda req: httpx.Response(403))

    async def fake_tls(url):
        return 403, None

    async def fake_browser(url):
        return 404, None

    _stealth(monkeypatch, fake_tls, fake_browser)
    rows = _rows("k.example", 1)
    _run(rows)
    assert rows[0]["verification"]["status"] == "likely_false_positive"


def test_shell_page_is_rendered_and_a_tier_rate_limit_backs_off(monkeypatch):
    """A 2xx JS shell is ``ok`` to retrieval; enrichment decides to render it.
    A 429 from the tier is a rate limit like any other: backoff, no retry."""
    shell = "<html><head><title>App</title></head><body><div id=root></div></body></html>"
    _install(monkeypatch, lambda req: _html(shell))

    async def fake_tls(url):
        return 429, None

    async def never_browser(url):
        raise AssertionError("no browser after a rate limit")

    _stealth(monkeypatch, fake_tls, never_browser)
    rows = _rows("s.example", 2)
    stats = {}
    hs = retrieval.HostState()
    _run(rows, stats=stats, host_state=hs)
    assert rows[0]["verification"]["reason"] == "rate_limited"
    assert rows[1]["verification"]["reason"] == "rate_limited"
    assert "not fetched" in rows[1]["verification"]["signals"][1]
    assert hs.active_backoff("s.example") is not None
    assert stats["stealth"]["rate_limited"] == 1


def test_rate_limited_verdict_shape():
    v = enrich.rate_limited_verdict(429)
    assert v == {"status": "indeterminate", "score": 30,
                 "signals": ["rate limited / unavailable (HTTP 429) — not retried this run"],
                 "reason": "rate_limited"}
    skipped = enrich.rate_limited_verdict(429, fetched=False)
    assert skipped["signals"][0] == v["signals"][0]
    assert "not fetched" in skipped["signals"][1]


# --- the adapter cache ------------------------------------------------------------

def test_enrichment_recheck_is_served_from_the_adapter_cache(monkeypatch):
    """Discovery already asked GitHub this run; enrichment must not ask again
    (defect 10: the 60/h budget was spent twice per handle)."""
    adapters.clear_cache()
    calls = []

    def handler(req):
        if req.url.host == "api.github.com":
            return httpx.Response(200, json={"id": 1, "login": "alice", "name": "Alice A",
                                             "created_at": "2011-01-25T18:44:36Z"})
        return _html(REAL_PAGE)

    # One patch serves every fetcher (one shared safeweb module).
    _install(monkeypatch, handler, calls)
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)
    asyncio.run(adapters.adapter_for("GitHub").check("alice"))      # discovery
    assert [r.url.host for r in calls] == ["api.github.com"]

    row = {"username": "alice", "site": "GitHub", "url": "https://github.com/alice",
           "engines": ["sherlock"]}
    _run([row])
    assert [r.url.host for r in calls] == ["api.github.com"], "no second GitHub call"
    assert row["verification"]["status"] == "confirmed"
    assert row["platform_identity"]["display_name"] == "Alice A"
    assert row["temporal"]["created_at"].startswith("2011")
    adapters.clear_cache()


# --- budget accounting -------------------------------------------------------------

def test_stats_report_the_verification_budget(monkeypatch):
    _install(monkeypatch, lambda req: _html(REAL_PAGE))
    _no_stealth(monkeypatch)
    rows = _rows("b.example", 5)
    stats = {}
    _run(rows, limit=2, stats=stats)
    assert stats["verify_budget"] == 2
    assert stats["verify_budget_used"] == 2
    assert stats["verify_budget_skipped"] == 3
    assert sum(1 for r in rows if r["verification"].get("reason") == "budget_exhausted") == 3
