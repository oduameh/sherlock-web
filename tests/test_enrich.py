"""Profile-enrichment extraction coverage.

Verifies the Scrapling-backed extractor and its regex fallback: HTML-entity
decoding, the meta/Twitter-card fallbacks the old regex path missed, and
JSON-LD Person parsing. No network — pure parsing over inline HTML.
"""

from recon.enrich import _extract, _extract_regex, _extract_scrapling

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


def test_extract_never_raises_on_garbage():
    for junk in ("", "<not html", "<title>", "\x00\xff", "<script type='application/ld+json'>{bad"):
        assert isinstance(_extract(junk), dict)
        assert isinstance(_extract_regex(junk), dict)


# --- verification budget --------------------------------------------------

def test_policy_denied_rows_do_not_consume_the_verification_budget(monkeypatch):
    """Denied hosts are answered from policy without a fetch. They must not eat
    budget slots that fetchable rows need — in one real run 28 Instagram/
    Pinterest/Twitter rows did exactly that and 105 fetchable rows went
    unexamined."""
    import asyncio
    from recon import enrich, adapters, stealthweb

    fetched = []

    async def fake_fetch(client, url):
        fetched.append(url)
        return 200, "<html><head><title>Real Page</title></head><body>hello world</body></html>"

    monkeypatch.setattr(enrich, "_fetch_page", fake_fetch)
    monkeypatch.setattr(enrich, "_control_url", lambda url, u: None)
    monkeypatch.setattr(adapters, "adapter_for", lambda site: None)
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)

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
    import asyncio
    from recon import enrich, adapters, stealthweb

    logo = "https://images-cdn.9gag.com/img/9gag-og.png"

    async def fake_fetch(client, url):
        who = "nobody" if "sw_ctl_" in url or "control" in url else "torvalds"
        return 200, (f"<html><head><title>{who} - 9GAG</title>"
                     f'<meta property="og:image" content="{logo}">'
                     f'<meta property="og:title" content="{who} on 9GAG">'
                     f"</head><body><h1>{who}</h1>"
                     f"<p>Profile page of {who} with posts and comments {'x ' * 40}</p>"
                     "</body></html>")

    monkeypatch.setattr(enrich, "_fetch_page", fake_fetch)
    monkeypatch.setattr(enrich, "_control_url",
                        lambda url, u: "https://9gag.com/u/sw_ctl_nobody")
    monkeypatch.setattr(adapters, "adapter_for", lambda site: None)
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)

    row = {"username": "torvalds", "site": "9GAG",
           "url": "https://9gag.com/u/torvalds", "engines": ["maigret"]}
    asyncio.run(enrich.enrich_profiles([row], lambda r, d: None, limit=5))
    enr = row["enrichment"]
    assert "og_image" not in enr, "site logo must not survive as an avatar"
    assert enr["og_title"] == "torvalds on 9GAG"     # person-specific: kept
    assert enr["template_fields"] == ["og_image"]
