from recon.verify import verify_username


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
    # a soft-404 factory — the "hit" is a false positive.
    page = ("<html><head><title>Acme</title></head>"
            "<body>Join Acme today. Sign up now.</body></html>")
    v = verify_username("whoever", "https://acme.com/whoever", page,
                        {"title": "Acme"}, status=200,
                        control_html=page, control_extracted={"title": "Acme"})
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
