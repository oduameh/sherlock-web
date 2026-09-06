"""HTML report + dossier: remote URLs must not become javascript: links (F-6).

Both renderers interpolate subject-controlled URLs (Gravatar ``profile_url``
and ``accounts[].url``, account/correlation/broker URLs) into ``href='…'``.
``html.escape`` neutralises quotes, not schemes, so ``_href`` allow-lists
http(s) and emits an empty ``href`` for everything else. The hostile string
may still appear as escaped link *text*; it must never be an ``href`` value.
"""

import re

from recon.dossier import _href as dossier_href
from recon.dossier import render_dossier
from recon.report import _href as report_href
from recon.report import render_report

EVIL = "javascript:alert(1)"
EVIL_NAME = "<script>alert('x')</script>"
EVIL_NAME_ESCAPED = "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"
GOOD_PROFILE = "https://gravatar.com/alice"
GOOD_ACCOUNT = "https://mastodon.example/@alice"
GOOD_SITE = "https://github.com/alice"

# any href whose value starts (after optional whitespace) with a script-capable scheme
BAD_HREF = re.compile(r"""href=(['"])\s*(javascript|vbscript|data):""", re.IGNORECASE)


def _gravatar():
    return {
        "display_name": EVIL_NAME,
        "profile_url": EVIL,
        "avatar_url": "https://0.gravatar.com/avatar/abc",
        "about": "bio",
        "accounts": [
            {"name": "Mastodon", "domain": "mastodon.example", "url": GOOD_ACCOUNT},
            {"name": "Evil", "domain": "evil.example", "url": "JavaScript:alert(2)"},
            {"name": "Data", "domain": "data.example", "url": "data:text/html,hi"},
        ],
    }


def _account(url=GOOD_SITE):
    return {
        "site": "GitHub", "username": "alice", "url": url,
        "engines": ["sherlock"],
        "verification": {"status": "confirmed", "confidence": 80},
    }


def _report_run():
    return {
        "subject": "alice", "ts": "2026-09-06 00:00:00",
        "params": {"usernames": ["alice"], "email": "alice@example.com"},
        "results": {
            "accounts": [_account(), _account(url=EVIL)],
            "variants": [{**_account(url="vbscript:msgbox(1)"), "username": "alice1",
                          "variant_of": "alice", "source": "variant"}],
            "email": {"gravatar": _gravatar(), "holehe": []},
            "correlation": [{
                "confidence": 55,
                "members": [{"site": "GitHub", "url": GOOD_SITE},
                            {"site": "Evil", "url": EVIL}],
                "links": [{"rationale": "shared handle"}],
            }],
        },
    }


def _dossier_summary():
    return {
        "params": {"name": EVIL_NAME, "usernames": ["alice"],
                   "email": "alice@example.com", "phone": "+15555550100"},
        "accounts": [_account(), _account(url=EVIL)],
        "variants": [],
        "name_accounts": [],
        "email": {"gravatar": _gravatar(), "holehe": []},
        "phone": {
            "valid": True, "e164": "+15555550100",
            "reverse_lookup": [{"name": "Broker", "search_url": EVIL,
                                "optout_url": "https://broker.example/optout"}],
            "footprint": [{"label": "dork", "kind": "search", "url": EVIL},
                          {"label": "ok", "kind": "search", "url": GOOD_SITE}],
        },
        "domain": {},
        "candidates": [],
    }


# --- helper contract ------------------------------------------------------------

def test_href_allow_lists_http_schemes_only():
    for fn in (report_href, dossier_href):
        assert fn("https://a.example/x?y=1&z=2") == "https://a.example/x?y=1&amp;z=2"
        assert fn("HTTP://A.EXAMPLE/") == "HTTP://A.EXAMPLE/"
        assert fn("  https://a.example/ ") == "https://a.example/"
        assert fn(EVIL) == ""
        assert fn("JavaScript:alert(1)") == ""
        assert fn(" javascript:alert(1)") == ""
        assert fn("data:text/html,hi") == ""
        assert fn("vbscript:msgbox(1)") == ""
        assert fn("//a.example/protocol-relative") == ""
        assert fn("ftp://a.example/") == ""
        assert fn(None) == ""
        assert fn("") == ""
        assert fn("https://a.example/'\"><img src=x onerror=1>") == \
            "https://a.example/&#x27;&quot;&gt;&lt;img src=x onerror=1&gt;"


# --- report ---------------------------------------------------------------------

def test_report_has_no_script_scheme_hrefs():
    out = render_report(_report_run())
    assert not BAD_HREF.search(out)
    assert f"href='{EVIL}'" not in out
    assert 'href="javascript:' not in out.lower()
    assert "href='javascript:" not in out.lower()


def test_report_keeps_https_links():
    out = render_report(_report_run())
    assert f"href='{GOOD_SITE}'" in out
    assert f"href='{GOOD_ACCOUNT}'" in out


THUMB = "data:image/png;base64,iVBORw0KGgo="


def test_report_never_links_an_avatar_to_the_subjects_host():
    """V11: a saved report opened later must not fetch from the subject's
    host, so the remote avatar URL never becomes an ``<img src>`` — only a
    thumbnail the server made from proxied bytes does."""
    run = _report_run()
    run["results"]["accounts"][0]["enrichment"] = {"og_image": "https://cdn.example/alice.png"}
    out = render_report(run)
    assert "<img" not in out                     # nothing was proxied: no picture
    assert "0.gravatar.com/avatar/abc" not in out and "cdn.example" not in out
    out = render_report(run, avatars={"https://cdn.example/alice.png": THUMB,
                                      "https://0.gravatar.com/avatar/abc": THUMB})
    assert out.count(f'<img class="avatar" src="{THUMB}"') == 2
    assert "cdn.example" not in out and "0.gravatar.com/avatar" not in out


def test_report_only_embeds_server_made_thumbnails():
    run = _report_run()
    run["results"]["accounts"][0]["enrichment"] = {"og_image": "https://cdn.example/alice.png"}
    for bad in ("https://cdn.example/alice.png", "data:image/svg+xml,<svg onload=alert(1)>",
                "javascript:alert(1)", "data:image/png;base64,\u00e9", ""):
        out = render_report(run, avatars={"https://cdn.example/alice.png": bad})
        assert "<img" not in out, bad


def test_report_escapes_script_in_display_name():
    out = render_report(_report_run())
    assert "<script>alert" not in out
    assert EVIL_NAME_ESCAPED in out


# --- dossier --------------------------------------------------------------------

def test_dossier_has_no_script_scheme_hrefs():
    inv = {"id": 7, "created_at": "2026-09-06 00:00:00"}
    out = render_dossier(inv, _dossier_summary())
    assert not BAD_HREF.search(out)
    assert f"href='{EVIL}'" not in out
    assert 'href="javascript:' not in out.lower()
    assert "href='javascript:" not in out.lower()


def test_dossier_keeps_https_links_and_escapes_name():
    inv = {"id": 7, "created_at": "2026-09-06 00:00:00"}
    out = render_dossier(inv, _dossier_summary())
    assert f"href='{GOOD_SITE}'" in out
    assert f"href='{GOOD_ACCOUNT}'" in out
    assert "href='https://broker.example/optout'" in out
    assert "<script>alert" not in out
    assert EVIL_NAME_ESCAPED in out


# --- brokers section, <img src>, and an allow-list over EVERY URL attribute ---------
# (review of increment F: the report's two <img src> interpolations were not
# scheme-gated, and the dossier fixture never rendered its brokers section.)

ATTR_URL = re.compile(r"""(?:href|src)=(['"])(.*?)\1""", re.I | re.S)


def _brokers_block():
    return {
        "name": "Alice Example", "city": "Austin", "state": "TX",
        "drop_portal": EVIL,
        "brokers": [
            {"name": "Spokeo", "category": "people-search", "owner": "x",
             "optout_url": "data:text/html,evil", "search_url": EVIL, "status": "listed"},
            {"name": "Whitepages", "category": "people-search", "owner": "y",
             "optout_url": "https://www.whitepages.com/suppression",
             "search_url": GOOD_SITE, "status": "not_found"},
        ],
        "summary": {"total": 2, "auto_checked": 2, "listed": 1, "blocked": 0, "manual": 0},
    }


def _assert_only_http_urls(html, *, thumbs=False):
    ok = ("http://", "https://") + (("data:image/png;base64,",) if thumbs else ())
    bad = [u for _, u in ATTR_URL.findall(html) if u and not u.lower().startswith(ok)]
    assert bad == [], f"non-http(s) URL attributes rendered: {bad}"


def test_report_gates_img_src_and_every_url_attribute():
    run = _report_run()
    run["results"]["accounts"].append({**_account(), "site": "Evil",
        "enrichment": {"og_image": "javascript:alert(2)", "og_title": "Evil"}})
    run["results"]["email"]["gravatar"]["avatar_url"] = "data:image/svg+xml,evil"
    out = render_report(run, avatars={"javascript:alert(2)": THUMB,
                                      "data:image/svg+xml,evil": THUMB})
    _assert_only_http_urls(out, thumbs=True)
    assert "alert(2)" not in out                    # a hostile src is dropped, not escaped
    assert "svg" not in out
    assert f"href='{GOOD_SITE}'" in out


def test_dossier_every_url_attribute_is_http_including_brokers():
    inv = {"id": 7, "created_at": "2026-09-06 00:00:00"}
    summary = _dossier_summary()
    summary["brokers"] = _brokers_block()
    out = render_dossier(inv, summary)
    _assert_only_http_urls(out)
    assert "whitepages.com/suppression" in out       # the brokers section did render
    assert "Spokeo" in out


# --- the raw page <title> is never rendered as a person's name (D7 / V10) --------------

RAW_TITLE_PLAIN = "carmen_pop - Streamer Overview & Stats · TwitchTracker"


def _title_only_account():
    return {"site": "TwitchTracker", "username": "carmen_pop",
            "url": "https://twitchtracker.com/carmen_pop", "engines": ["sherlock"],
            "verification": {"status": "confirmed"},
            "enrichment": {"title": RAW_TITLE_PLAIN}}


def test_report_never_renders_the_raw_title_as_a_name():
    run = _report_run()
    run["results"]["accounts"] = [_title_only_account(),
                                  {**_account(), "enrichment": {"jsonld_name": "Alice Example",
                                                                "title": RAW_TITLE_PLAIN}}]
    out = render_report(run)
    assert "Streamer Overview" not in out
    assert "<b>Alice Example</b>" in out


def test_dossier_never_renders_the_raw_title_as_a_name():
    inv = {"id": 7, "created_at": "2026-09-06 00:00:00"}
    summary = _dossier_summary()
    summary["accounts"] = [_title_only_account(),
                           {**_account(), "enrichment": {"og_title": "Alice Example",
                                                         "title": RAW_TITLE_PLAIN}}]
    out = render_dossier(inv, summary)
    assert "Streamer Overview" not in out
    assert "<td>Alice Example</td>" in out
    assert "<td>—</td>" in out            # the title-only row shows no identity


# --- G2: the dossier does not claim "no exposure" when holehe did not answer ---------

def test_dossier_says_could_not_be_determined_when_holehe_was_rate_limited():
    s = _dossier_summary()
    s["email"]["holehe"] = [{"site": f"s{i}", "exists": False, "rate_limit": True}
                            for i in range(100)]
    out = render_dossier({"id": 1, "created_at": "2026-09-06"}, s)
    assert "Email checks were rate-limited/failed on 100 of 100 services" in out
    assert "exposure could not be determined" in out
    assert "No registered-account exposure was found" not in out
    assert "100 rate-limited or failed" in out


def test_dossier_still_says_no_exposure_when_the_checks_answered():
    s = _dossier_summary()
    s["email"]["holehe"] = [{"site": "a", "exists": False}, {"site": "b", "exists": False}]
    out = render_dossier({"id": 1, "created_at": "2026-09-06"}, s)
    assert "No registered-account exposure was found" in out
    assert "exposure could not be determined" not in out
    assert "rate-limited or failed" not in out


def test_dossier_reports_a_gravatar_that_could_not_be_checked():
    s = _dossier_summary()
    s["email"]["gravatar"] = None
    s["email"]["gravatar_error"] = "could not check: rate limited (HTTP 429)"
    out = render_dossier({"id": 1, "created_at": "2026-09-06"}, s)
    assert "Gravatar could not be checked (could not check: rate limited (HTTP 429))" in out
    assert "No public Gravatar profile" not in out
