from recon.verify import verify_username


def test_confirmed_via_structured_metadata():
    v = verify_username("octocat", "https://github.com/octocat",
                        "<html>...</html>",
                        {"og_title": "octocat (The Octocat)"})
    assert v["status"] == "confirmed"
    assert v["score"] >= 80


def test_confirmed_via_body_echo():
    html = "<html><body>Welcome to the profile of octocat here</body></html>"
    v = verify_username("octocat", "https://x/octocat", html, {})
    assert v["status"] == "confirmed"


def test_soft_404_flagged_as_false_positive():
    html = "<html><title>Not Found</title><body>User not found</body></html>"
    v = verify_username("ghostuser", "https://x/ghostuser", html, {})
    assert v["status"] == "likely_false_positive"


def test_soft_404_that_echoes_handle_is_not_confirmed():
    # A "user ghostuser not found" page echoes the handle — must NOT confirm.
    html = "<html><body>Sorry, user ghostuser not found on this site</body></html>"
    v = verify_username("ghostuser", "https://x/ghostuser", html, {})
    assert v["status"] == "likely_false_positive"


def test_unconfirmed_when_handle_absent():
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
