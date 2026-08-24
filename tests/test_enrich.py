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
