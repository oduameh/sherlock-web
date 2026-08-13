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


def test_identity_mismatch_flagged():
    v = verify_username("jsmith", "https://x/jsmith",
                        "<html><title>Jane Doe</title></html>",
                        {"jsonld_name": "Jane Doe"}, status=200,
                        subject_name="John Smith")
    assert v["status"] == "likely_false_positive"
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


def test_unconfirmed_when_no_html():
    v = verify_username("alice", "https://x/alice", None, {})
    assert v["status"] == "unconfirmed"


def test_handle_matching_ignores_separators():
    v = verify_username("john.smith", "https://x/john.smith",
                        "<title>johnsmith on Example</title>",
                        {"title": "johnsmith on Example"})
    assert v["status"] == "confirmed"
