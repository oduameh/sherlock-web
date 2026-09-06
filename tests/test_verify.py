from recon.verify import CONTROL_HANDLE, verify_username


def test_confirmed_via_structured_metadata():
    v = verify_username("octocat", "https://github.com/octocat",
                        "<html>x</html>",
                        {"og_title": "octocat (The Octocat)"})
    assert v["status"] == "confirmed"


def test_body_echo_alone_does_not_confirm():
    # The handle appears only in the raw body/URL, never in extracted metadata.
    # It must NOT confirm — the handle is in the canonical URL of error pages
    # too. This was the single biggest false-confirm bug.
    html = "<html><body>Welcome to the profile of octocat here</body></html>"
    v = verify_username("octocat", "https://x/octocat", html, {})
    assert v["status"] != "confirmed"


def test_soft_404_phrase_flagged():
    html = "<html><title>Not Found</title><body>User not found</body></html>"
    v = verify_username("ghostuser", "https://x/ghostuser", html, {})
    assert v["status"] == "likely_false_positive"


def test_control_probe_flags_serve_all_sites():
    # A site that returns the same page for a real and a nonexistent handle is
    # a soft-404 factory — the "hit" is a false positive. Such sites stamp
    # their site-wide Open Graph tags on every page; that metadata is what
    # distinguishes a soft-404 factory from a metadata-free WAF block page
    # (see test_identical_metadata_free_page_is_a_block_page_not_a_refutation).
    page = ("<html><head><title>Acme</title>"
            '<meta property="og:title" content="Acme — join today"></head>'
            "<body>Join Acme today. Sign up now.</body></html>")
    meta = {"title": "Acme", "og_title": "Acme — join today"}
    v = verify_username("whoever", "https://acme.com/whoever", page,
                        meta, status=200, control_html=page, control_extracted=meta)
    assert v["status"] == "likely_false_positive"


def test_hard_404_flagged():
    v = verify_username("nobody", "https://x/nobody", None, {}, status=404)
    assert v["status"] == "likely_false_positive"


def test_identity_mismatch_downgrades_but_does_not_flag():
    # A different structured name is weak NEGATIVE evidence, not proof of a
    # different person (nicknames/handles-as-names are common), so it must
    # downgrade to a lead rather than hard-flag a possibly-real account.
    v = verify_username("jsmith", "https://x/jsmith",
                        "<html><title>Jane Doe</title></html>",
                        {"jsonld_name": "Jane Doe"}, status=200,
                        subject_name="John Smith")
    assert v["status"] == "unconfirmed"
    assert v.get("identity_match") is False


def test_identity_match_confirms():
    v = verify_username("jsmith", "https://x/jsmith",
                        "<html><title>John Smith</title></html>",
                        {"jsonld_name": "John Smith"}, status=200,
                        subject_name="John Smith")
    assert v["status"] == "confirmed"
    assert v.get("identity_match") is True


def test_unconfirmed_generic_page():
    html = "<html><body>A generic landing page about widgets</body></html>"
    v = verify_username("alice", "https://x/alice", html, {})
    assert v["status"] == "unconfirmed"


def test_no_html_is_indeterminate_not_a_finding():
    # Nothing retrieved means we could not check — not "absent", not a lead.
    v = verify_username("alice", "https://x/alice", None, {})
    assert v["status"] == "indeterminate"


def test_handle_matching_ignores_separators():
    v = verify_username("john.smith", "https://x/john.smith",
                        "<title>johnsmith on Example</title>",
                        {"title": "johnsmith on Example"})
    assert v["status"] == "confirmed"


# --- regression tests: real failures reproduced by the audit swarm ----------

def test_mention_of_subject_name_does_not_confirm():
    """A fan page / article merely MENTIONING the subject is not their account.
    Previously confirmed at 95% off og_description."""
    v = verify_username(
        "fanaccount", "https://x.com/fanaccount",
        "<html><body>fan page</body></html>",
        {"og_description": "A tribute page dedicated to John Smith and his work"},
        status=200, subject_name="John Smith")
    assert v["status"] != "confirmed"


def test_free_text_title_is_not_identity_evidence():
    v = verify_username(
        "someblog", "https://x.com/someblog", "<html><body>x</body></html>",
        {"title": "News: John Smith wins award"},
        status=200, subject_name="John Smith")
    assert v["status"] != "confirmed"


def test_different_display_name_is_a_lead_not_a_rejection():
    """A real account whose display name is the handle (or a nickname) must not
    be hard-flagged as a false positive."""
    v = verify_username(
        "jsmith", "https://x.com/jsmith", "<html><body>profile</body></html>",
        {"jsonld_name": "jsmith"}, status=200, subject_name="John Smith")
    assert v["status"] != "likely_false_positive"


def test_blocked_is_not_absent():
    """401/403/429/5xx mean we could not check — never 'the account is absent'."""
    for code in (401, 403, 429, 500, 503):
        v = verify_username("someone", "https://x.com/someone", None, {},
                            status=code)
        assert v["status"] == "indeterminate", code


def test_absent_statuses_still_flag():
    for code in (404, 410):
        v = verify_username("nobody", "https://x.com/nobody", None, {},
                            status=code)
        assert v["status"] == "likely_false_positive", code


def test_soft_404_only_matches_page_headline():
    """A profile bio containing an unlucky phrase must not condemn the account."""
    html = ("<html><head><title>alicejones (Alice) · Example</title></head>"
            "<body><p>my old blog is no longer exists sorry</p></body></html>")
    v = verify_username("alicejones", "https://x/alicejones", html,
                        {"title": "alicejones (Alice) · Example"}, status=200)
    assert v["status"] == "confirmed"


def test_suspended_account_is_kept_as_a_lead():
    html = "<html><head><title>Account suspended</title></head><body>x</body></html>"
    v = verify_username("acct", "https://x/acct", html,
                        {"title": "Account suspended"}, status=200)
    assert v["status"] == "unconfirmed"
    assert "removed/suspended" in v["signals"][0]


def test_short_handle_does_not_confirm_from_title():
    """3-letter handles collide with ordinary words; require a real handle."""
    v = verify_username("bob", "https://x/bob", "<html><body>x</body></html>",
                        {"title": "Bobby's Blog about bob the builder"},
                        status=200)
    assert v["status"] != "confirmed"


def test_control_probe_recorded_in_verdict():
    v = verify_username("someone", "https://x/someone",
                        "<html><body>a real and distinct profile page</body></html>",
                        {"title": "someone"}, status=200,
                        control_html="<html><body>totally different not found</body></html>",
                        control_extracted={"title": "not found"})
    assert v.get("control_probe") == "ran"


def test_cloudflare_challenge_is_indeterminate_not_unconfirmed():
    # A challenge page is *blockage*: it must not read as a real profile
    # ("unconfirmed" lead) and never as absence.
    html = ("<html><head><title>Just a moment...</title></head>"
            "<body>Checking your browser before accessing.</body></html>")
    v = verify_username("someone", "https://x/someone", html,
                        {"title": "Just a moment..."}, status=200)
    assert v["status"] == "indeterminate"
    assert "anti-bot challenge page" in v["signals"][0]


def test_challenge_phrase_in_bio_alone_does_not_trigger():
    # Scope check: the phrase must be in title/heading/top-of-content, not
    # buried mid-body.
    html = ("<html><head><title>someone · Example</title></head><body>"
            + "lorem ipsum " * 80
            + " ...and my friend dared me to verify you are a human, ha. "
            + "lorem ipsum " * 80
            + "</body></html>")
    v = verify_username("someone", "https://x/someone", html,
                        {"title": "someone · Example"}, status=200)
    assert v["status"] != "indeterminate"


def test_challenge_page_does_not_veto_identity_confirmation():
    # A structured name match is still the strongest evidence — but a
    # challenge page carries no structured name anyway; this pins the order.
    html = ("<html><head><title>Just a moment...</title></head>"
            "<body>enable javascript and cookies to continue</body></html>")
    v = verify_username("jsmith", "https://x/jsmith", html, {}, status=200,
                        subject_name="John Smith")
    assert v["status"] == "indeterminate"


def test_transport_blocked_status_stays_indeterminate():
    v = verify_username("someone", "https://x/someone", None, {}, status=403)
    assert v["status"] == "indeterminate"


def test_consent_wall_is_indeterminate_not_a_lead():
    """YouTube's GDPR interstitial ("Before you continue to YouTube") is served
    for every logged-out datacenter request. It is blockage — never absence,
    and never an "unconfirmed" lead that reads as a real profile."""
    html = ("<html><head><title>Before you continue to YouTube</title></head>"
            "<body><h1>Before you continue to YouTube</h1>"
            "<p>We use cookies and data to deliver and maintain Google "
            "services...</p></body></html>")
    v = verify_username("carmenpop", "https://www.youtube.com/@carmenpop", html,
                        {"title": "Before you continue to YouTube"}, status=200)
    assert v["status"] == "indeterminate"
    assert "consent/cookie wall" in v["signals"][0]


def test_vendor_script_tag_on_a_real_profile_is_not_a_block_page():
    """DataDome/PerimeterX put their script tag on every page of a protected
    site. That raw token may cost a stealth fetch, but it must never turn a real
    profile into "blocked"."""
    html = ("<html><head><script src='https://js.datadome.co/tags.js'></script>"
            "<title>janedoe (Jane Doe) · Example</title></head><body>"
            + "Jane posts about gardening and cats. " * 10 + "</body></html>")
    v = verify_username("janedoe", "https://x/janedoe", html,
                        {"title": "janedoe (Jane Doe) · Example"}, status=200)
    assert v["status"] == "confirmed"


# --- V1: a not-found page that echoes the handle (retrieval audit §3c) -------

ECHO_PAGE = (
    "<html><head><title>Profile johnsmith77 not found | ExampleSite</title>"
    '<meta property="og:title" content="Profile johnsmith77 not found | ExampleSite">'
    "</head><body><h1>Profile johnsmith77 not found</h1>"
    "<p>We could not find a member with that name. Try searching instead.</p>"
    "</body></html>"
)
ECHO_META = {"title": "Profile johnsmith77 not found | ExampleSite",
             "og_title": "Profile johnsmith77 not found | ExampleSite"}
ECHO_CONTROL = ECHO_PAGE.replace("johnsmith77", CONTROL_HANDLE)
ECHO_CONTROL_META = {k: v.replace("johnsmith77", CONTROL_HANDLE) for k, v in ECHO_META.items()}


def test_handle_echo_soft_404_with_control_is_flagged():
    """Reproduced pair: used to verify as ``confirmed 72`` because the fixed
    phrases need adjacency, the titles differ by the handle and the 4-gram
    overlap of two short pages that differ by one token is < 0.90."""
    v = verify_username("johnsmith77", "https://examplesite.com/johnsmith77",
                        ECHO_PAGE, ECHO_META, status=200,
                        control_html=ECHO_CONTROL, control_extracted=ECHO_CONTROL_META)
    assert v["status"] == "likely_false_positive"
    assert v["control_probe"] == "ran"


def test_handle_echo_soft_404_without_control_is_flagged():
    v = verify_username("johnsmith77", "https://examplesite.com/johnsmith77",
                        ECHO_PAGE, ECHO_META, status=200)
    assert v["status"] == "likely_false_positive"
    assert "not-found" in v["signals"][0]


def test_handle_echo_soft_404_with_failed_control_is_flagged_and_labelled():
    v = verify_username("johnsmith77", "https://examplesite.com/johnsmith77",
                        ECHO_PAGE, ECHO_META, status=200, control_failed=True)
    assert v["status"] == "likely_false_positive"
    assert v["control_probe"] == "failed"


def test_control_comparison_masks_both_handles():
    """A template page with no not-found wording that differs from the control
    only by the echoed handle must still read as the same template."""
    page = ("<html><head><title>jdoe77 | Acme members</title>"
            "<meta property='og:title' content='jdoe77 on Acme'></head>"
            "<body><h1>jdoe77</h1><p>Welcome to Acme. Sign up to see jdoe77's "
            "activity, friends and photos. Join today.</p></body></html>")
    meta = {"title": "jdoe77 | Acme members", "og_title": "jdoe77 on Acme"}
    ctrl = page.replace("jdoe77", CONTROL_HANDLE)
    ctrl_meta = {k: v.replace("jdoe77", CONTROL_HANDLE) for k, v in meta.items()}
    v = verify_username("jdoe77", "https://acme.com/jdoe77", page, meta, status=200,
                        control_html=ctrl, control_extracted=ctrl_meta)
    assert v["status"] == "likely_false_positive"
    assert "indistinguishable" in v["signals"][0]


def test_real_profile_that_differs_from_the_control_is_still_confirmed():
    page = ("<html><head><title>torvalds (Linus Torvalds) · GitHub</title></head>"
            "<body><h1>Linus Torvalds</h1><p>Followers 200k · repositories 7 · "
            "Portland, OR · linux kernel maintainer</p></body></html>")
    ctrl = ("<html><head><title>Page not found · GitHub</title></head>"
            "<body><h1>404</h1><p>This is not the web page you are looking for.</p>"
            "</body></html>")
    v = verify_username("torvalds", "https://github.com/torvalds", page,
                        {"title": "torvalds (Linus Torvalds) · GitHub"}, status=200,
                        control_html=ctrl, control_extracted={"title": "Page not found · GitHub"})
    assert v["status"] == "confirmed"


# --- V2: unlisted WAF pages are blocked, not refuted and not leads -----------

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


def test_akamai_access_denied_is_blocked_not_refuted():
    """Served identically for the real and the control handle, so the control
    rule used to call it ``likely_false_positive`` (tier "refuted")."""
    for ctrl in (AKAMAI_PAGE, None):
        v = verify_username("johnsmith77", "https://x/johnsmith77", AKAMAI_PAGE,
                            {"title": "Access Denied"}, status=200,
                            control_html=ctrl,
                            control_extracted={"title": "Access Denied"} if ctrl else None)
        assert v["status"] == "indeterminate", ctrl is not None
        assert "anti-bot challenge page" in v["signals"][0]


def test_imperva_pardon_our_interruption_is_blocked_not_a_lead():
    """Used to be ``unconfirmed 45`` — a lead adding footprint points."""
    for ctrl in (IMPERVA_PAGE, None):
        v = verify_username("johnsmith77", "https://x/johnsmith77", IMPERVA_PAGE,
                            {"title": "Pardon Our Interruption"}, status=200,
                            control_html=ctrl,
                            control_extracted={"title": "Pardon Our Interruption"} if ctrl else None)
        assert v["status"] == "indeterminate", ctrl is not None


def test_identical_metadata_free_page_is_a_block_page_not_a_refutation():
    """A WAF whose wording is not in any list: identical to the control and
    carrying no profile metadata → blocked ("likely a block page"), never
    "likely false positive"."""
    page = ("<html><head><title>Error</title></head><body><h1>Error</h1>"
            "<p>Your request could not be processed at this time. Please contact "
            "the site administrator if the problem persists.</p></body></html>")
    v = verify_username("someone", "https://x/someone", page, {"title": "Error"},
                        status=200, control_html=page, control_extracted={"title": "Error"})
    assert v["status"] == "indeterminate"
    assert "block page" in v["signals"][0]


# --- control-probe honesty and fetch-error class -----------------------------

def test_failed_control_probe_is_labelled_failed_and_noted():
    """A rate-limited/timeout control used to be recorded as "not_applicable"
    and the resulting ``confirmed`` verdict said nothing about it."""
    v = verify_username("someone", "https://x/someone",
                        "<html><body>a real and distinct profile page</body></html>",
                        {"title": "someone"}, status=200, control_failed=True)
    assert v["control_probe"] == "failed"
    assert v["status"] == "confirmed"
    assert any("control probe failed" in s for s in v["signals"])


def test_control_probe_not_applicable_only_when_none_was_wanted():
    v = verify_username("someone", "https://x/someone",
                        "<html><body>a real and distinct profile page</body></html>",
                        {"title": "someone"}, status=200)
    assert v["control_probe"] == "not_applicable"
    assert not any("control probe failed" in s for s in v["signals"])


def test_failed_control_is_labelled_even_on_blocked_status():
    v = verify_username("someone", "https://x/someone", None, {}, status=403,
                        control_failed=True)
    assert v["status"] == "indeterminate"
    assert v["control_probe"] == "failed"


def test_fetch_error_class_is_in_the_signal():
    v = verify_username("alice", "https://x/alice", None, {}, fetch_error="ConnectTimeout")
    assert v["status"] == "indeterminate"
    assert "ConnectTimeout" in v["signals"][0]


def test_non_html_response_is_named_in_the_signal():
    v = verify_username("alice", "https://x/alice", None, {}, status=200)
    assert v["status"] == "indeterminate"
    assert "non-HTML" in v["signals"][0]
