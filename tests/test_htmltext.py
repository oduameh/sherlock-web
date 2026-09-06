"""recon.htmltext — the shared HTML→text helpers and marker lists. Pure, no network.

Includes the F-3 regressions: each hostile input below took > 20 s (JSON-LD
~10 s) with the previous regexes and ran inside the event loop; every one must
now finish in well under half a second.
"""

import time

import pytest

from recon import htmltext as h

AKAMAI_PAGE = (
    "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1>"
    "<p>You don't have permission to access \"http://www.example.com/johnsmith77\" "
    "on this server.</p><p>Reference #18.4f1d2c17.1725600000.1a2b3c4d</p></body></html>"
)
IMPERVA_PAGE = (
    "<html><head><title>Pardon Our Interruption</title></head><body>"
    "<h1>Pardon Our Interruption...</h1><p>As you were browsing something about your "
    "browser made us think you were a bot. There are a few reasons this might happen.</p>"
    "<p>Incapsula incident ID: 123-456</p></body></html>"
)
# A legitimate profile fronted by DataDome: their tag is on every page.
LEGIT_DATADOME_PAGE = (
    "<html><head><script src='https://js.datadome.co/tags.js'></script>"
    "<title>Jane Doe (@janedoe) · Example</title></head><body>"
    + "Jane posts about gardening and cats. " * 10
    + "</body></html>"
)


# --- HTML → text ------------------------------------------------------------

def test_visible_text_strips_scripts_styles_and_tags():
    html = ("<html><head><style>.a{color:red}</style>"
            "<script>var x = '<b>bold</b>';</script></head>"
            "<body><h1>Hello</h1> <p>World</p></body></html>")
    assert h.visible_text(html) == "hello world"


def test_unterminated_script_swallows_the_rest_like_a_browser():
    assert h.visible_text("<p>intro</p><script>var a=1; <p>never shown</p>") == "intro"


def test_strip_script_style_ignores_lookalike_tag_names():
    assert h.visible_text("<scripts>keep</scripts><stylesheet>also</stylesheet>") == "keep also"


def test_visible_text_is_bounded():
    assert len(h.visible_text("word " * 10000, limit=100)) == 100
    assert h.visible_text(None) == "" and h.visible_text("") == ""


def test_page_headline_reads_nested_heading_markup():
    # ``<h1><span>…</span></h1>`` is how many sites mark up the not-found line;
    # a ``[^<]`` capture would return "" here and lose the phrase.
    html = ("<html><head><title>Example</title></head>"
            "<body><h1><span>User not found</span></h1></body></html>")
    assert "user not found" in h.page_headline(html, {})


def test_page_headline_includes_extracted_title_and_og_title():
    assert h.page_headline(None, {"title": "A", "og_title": "B"}) == "a b"
    assert h.page_headline("", None) == ""


def test_page_headline_scans_only_the_head_of_the_document():
    html = ("<html><body>" + "x" * h.HEADLINE_SCAN_LIMIT
            + "<h1>late heading</h1></body></html>")
    assert "late heading" not in h.page_headline(html, {})


def test_heading_texts_limit_and_cap():
    html = "".join(f"<h2>h{i}</h2>" for i in range(10))
    assert h.heading_texts(html, limit=3) == ["h0", "h1", "h2"]
    long = "<h1>" + "a" * 5000 + "</h1>"
    assert len(h.heading_texts(long)[0]) == h.HEADING_TEXT_CAP


def test_iter_tags_yields_only_the_named_tag():
    html = ('<meta property="og:title" content="T"><metadata>x</metadata>'
            "<META name='og:image' content='i'/>")
    assert list(h.iter_tags(html, "meta")) == [
        '<meta property="og:title" content="T">', "<META name='og:image' content='i'/>"]


def test_iter_tags_skips_a_tag_with_no_closing_bracket_within_cap():
    html = "<meta " + "a" * (h.TAG_TEXT_CAP + 10) + '><meta name="x" content="y">'
    assert list(h.iter_tags(html, "meta")) == ['<meta name="x" content="y">']


def test_iter_jsonld_blocks_finds_only_ld_json_and_caps_count():
    html = ('<script type="application/ld+json">{"a":1}</script><script>var b=2</script>'
            "<script  type='application/ld+json' async>{\"c\":3}</script>")
    assert list(h.iter_jsonld_blocks(html)) == ['{"a":1}', '{"c":3}']
    many = '<script type="application/ld+json">{}</script>' * 30
    assert len(list(h.iter_jsonld_blocks(many))) == h.JSONLD_MAX_BLOCKS


def test_iter_jsonld_unterminated_block_is_dropped():
    assert list(h.iter_jsonld_blocks('<script type="application/ld+json">{"a":')) == []


# --- challenge / consent markers --------------------------------------------

def test_akamai_and_imperva_block_pages_carry_challenge_markers():
    # V2: both used to slip through every list and end up "refuted" or "lead".
    assert h.challenge_marker(AKAMAI_PAGE) == "access denied"
    assert h.challenge_marker(IMPERVA_PAGE) == "pardon our interruption"
    assert h.has_challenge_markers(AKAMAI_PAGE) is True
    assert h.has_challenge_markers(IMPERVA_PAGE) is True


def test_reference_number_at_the_top_of_the_body_is_a_marker():
    html = "<html><head><title>Error</title></head><body><p>Reference #18.abc</p></body></html>"
    assert h.challenge_marker(html) == "reference #"


@pytest.mark.parametrize("phrase", ["access denied", "request blocked",
                                    "verify you are a human", "reference #",
                                    "pardon our interruption"])
def test_generic_phrase_deep_in_a_bio_does_not_trigger(phrase):
    html = ("<html><head><title>someone · Example</title></head><body>"
            + "lorem ipsum " * 80 + f" my story: {phrase} lol " + "lorem ipsum " * 80
            + "</body></html>")
    assert h.challenge_marker(html) is None
    assert h.has_challenge_markers(html) is False


def test_vendor_token_in_raw_html_escalates_but_never_decides_a_verdict():
    # Escalation may spend a stealth fetch on it; verification must not call
    # a real profile a block page because of a script tag.
    assert h.has_challenge_markers(LEGIT_DATADOME_PAGE) is True
    assert h.challenge_marker(LEGIT_DATADOME_PAGE, raw_tokens=False) is None


def test_vendor_token_beyond_the_raw_window_is_ignored():
    html = ("<html><head><title>t</title></head><body>" + "a" * h.MARKER_RAW_LIMIT
            + " datadome</body></html>")
    assert h.has_challenge_markers(html) is False


def test_shared_list_is_a_superset_of_both_former_copies():
    former = {
        "just a moment", "attention required", "checking your browser",
        "verifying you are human", "verify you are a human", "one more step",
        "enable javascript and cookies", "ddos protection by", "ddos-guard",
        "cf-challenge", "challenge-platform", "datadome", "perimeterx",
        "px-captcha", "captcha-delivery",
    }
    assert former <= set(h.CHALLENGE_MARKERS)
    for added in ("access denied", "reference #", "pardon our interruption",
                  "incapsula incident", "request unsuccessful", "awswaf", "kasada",
                  "client challenge", "request blocked"):
        assert added in h.CHALLENGE_MARKERS, added


def test_consent_wall_detection():
    html = ("<html><head><title>Before you continue to YouTube</title></head>"
            "<body><h1>Before you continue to YouTube</h1></body></html>")
    assert h.consent_wall_marker(html) == "before you continue to"
    assert h.has_consent_wall(html) is True
    assert h.has_consent_wall("<html><body>" + "profile text " * 30 + "</body></html>") is False
    assert h.has_consent_wall(None) is False


def test_looks_like_shell():
    assert h.looks_like_shell('<html><body><div id="root"></div></body></html>') is True
    assert h.looks_like_shell("<html><body>" + "real words here " * 10 + "</body></html>") is False
    assert h.looks_like_shell(None) is False


# --- soft-404 regex (V1) ----------------------------------------------------

@pytest.mark.parametrize("headline", [
    "profile johnsmith77 not found | examplesite",
    "the user @jsmith does not exist",
    "this page couldn't be found",
    "account j.smith could not be found",
    "member jsmith no longer exists",
    "user doesn’t exist",
])
def test_soft_404_regex_matches_handle_echo_forms(headline):
    assert h.SOFT_404_RE.search(headline), headline


@pytest.mark.parametrize("headline", [
    "alicejones (alice) · example",
    "not found",
    "user " + "x" * 41 + " not found",          # gap over 40 chars
    "found my profile page at last",
    "profile — lost and found",
    "notfound user",
])
def test_soft_404_regex_rejects_other_wording(headline):
    assert not h.SOFT_404_RE.search(headline), headline


# --- F-3: hostile markup must be linear -------------------------------------

@pytest.mark.parametrize("label,fn", [
    ("title*40000", lambda: h.TITLE_RE.search("<title>" * 40000)),
    ("headline h1*50000", lambda: h.page_headline("<h1>" * 50000, {})),
    ("headline unterminated titles", lambda: h.page_headline("<titleaaaa" * 5000, {})),
    ("visible_text <*100000", lambda: h.visible_text("<" * 100000)),
    ("visible_text script*40000", lambda: h.visible_text("<script>" * 40000)),
    ("jsonld unterminated 280KB",
     lambda: list(h.iter_jsonld_blocks('<script type="application/ld+json">' + "{" * 280000))),
    ("meta*50000", lambda: sum(1 for _ in h.iter_tags("<meta a" * 50000, "meta"))),
    ("challenge_marker h1*50000", lambda: h.challenge_marker("<h1>" * 50000)),
])
def test_hostile_markup_is_processed_in_linear_time(label, fn):
    t0 = time.perf_counter()
    fn()
    assert time.perf_counter() - t0 < 0.5, label


# --- review of increment B: the M×N stripper shape and the handle-anchored pattern ---

import time as _time  # noqa: E402

from recon.htmltext import soft_404_pattern, strip_script_style, visible_text  # noqa: E402
from recon.verify import verify_username as _verify  # noqa: E402


@pytest.mark.parametrize("html", [
    "<style>x</style>" * 750 + "<scriptx" * 1500,
    "<script></script><stylex" * 1000,
    "<script src=a>" * 3000 + "</script>",
], ids=["style-then-scriptx", "alternating", "nested-opens"])
def test_stripper_is_linear_on_lookalike_heavy_markup(html):
    t0 = _time.perf_counter()
    visible_text(html)
    _verify("someone", "https://x/someone", html, {}, status=200, control_html=html)
    assert _time.perf_counter() - t0 < 0.5


def test_stripper_output_is_unchanged_on_ordinary_markup():
    cases = [
        "<p>a</p><script>var x = '<p>';</script><b>b</b>",
        "<style>p{}</style>text<STYLE>x</STYLE>more",
        "<scripts>not a script</scripts><script>gone</script>tail",
        "<script>unterminated",
        "",
    ]
    expected = ["<p>a</p> <b>b</b>", " text more", "<scripts>not a script</scripts> tail", " ", ""]
    assert [strip_script_style(c) for c in cases] == expected


def test_soft_404_pattern_is_anchored_on_the_handle():
    pat = soft_404_pattern("torvalds")
    assert pat.search("Torvalds does not use Launchpad")
    assert pat.search("torvalds is not on Mastodon")
    assert pat.search("torvalds hasn't joined Keybase yet")
    assert pat.search("Profile johnsmith77 not found")
    assert not pat.search("torvalds (Hemant)")
    assert not pat.search("ken (Torvalds) - Gitee.com")
    assert not soft_404_pattern("ab").search("ab does not use it")   # too short to anchor
