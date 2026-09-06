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
    assert "src='https://0.gravatar.com/avatar/abc'" in out  # avatar is an <img>, not a link


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
