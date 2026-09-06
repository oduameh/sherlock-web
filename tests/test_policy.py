"""Access-policy helpers for engine site templates and third-party check
modules (recon.policy). Pure functions, no network.

Background: ``policy.py`` promised that robots-denied hosts are never fetched,
but until 2026-09-06 only our own fetchers honoured it — Sherlock/Maigret/
WhatsMyName scanned Instagram, Reddit, X, Flickr and Threads on every run and
holehe/ignorant called their Instagram/Twitter/Pinterest modules on every
pivot (audit defect 8, security F-2). These tests pin the helpers that make
the promise true at plan time.
"""

from types import SimpleNamespace

from recon import policy


# --- template filling ------------------------------------------------------

def test_fill_template_substitutes_every_engine_placeholder():
    assert policy.fill_template("https://a.example/{}") == "https://a.example/probe"
    assert policy.fill_template("https://a.example/{username}/") == "https://a.example/probe/"
    assert policy.fill_template("https://a.example/u?n={account}") == "https://a.example/u?n=probe"
    # Maigret resolves {urlMain}/{urlSubpath} from the site object.
    assert policy.fill_template("{urlMain}{urlSubpath}/users/{username}",
                                url_main="https://forum.example",
                                url_subpath="/f") == "https://forum.example/f/users/probe"
    # Unknown placeholders are treated as handle positions too.
    assert policy.fill_template("https://a.example/{weird}") == "https://a.example/probe"


def test_fill_template_gives_scheme_less_templates_a_scheme():
    # A few Maigret entries have no scheme; the host must still be readable.
    assert policy.fill_template("discourse.mozilla.org/u/{username}") == \
        "https://discourse.mozilla.org/u/probe"
    assert policy.fill_template("") == ""


def test_is_denied_template_reads_the_request_host():
    assert policy.is_denied_template("https://instagram.com/{}")
    assert policy.is_denied_template("https://www.reddit.com/user/{username}/about.json")
    assert policy.is_denied_template("https://api.x.com/i/users/username_available.json?username={account}")
    assert policy.is_denied_template("https://hacker-news.firebaseio.com/v0/user/{account}.json")
    assert policy.is_denied_template("{urlMain}/user/{username}",
                                     url_main="https://www.reddit.com")
    assert not policy.is_denied_template("https://github.com/{}")
    assert not policy.is_denied_template("https://news.ycombinator.com/user?id={}")
    # Handle in the host position of a permitted platform stays permitted.
    assert not policy.is_denied_template("https://{}.tumblr.com/")
    # ... and of a denied one is still denied (suffix match).
    assert policy.is_denied_template("https://{}.instagram.com/")
    assert not policy.is_denied_template("")


def test_is_denied_template_ignores_denied_hosts_in_query_params():
    t = "https://archive.org/wayback/available?url=https://instagram.com/{}"
    assert not policy.is_denied_template(t)


def test_denied_template_reason_matches_denied_reason():
    assert policy.denied_template_reason("https://x.com/{account}") == \
        policy.denied_reason("https://x.com/probe")
    assert policy.denied_template_reason("https://github.com/{}") is None


# --- filter_site_mapping / denied_site_reason -------------------------------

def test_filter_site_mapping_with_single_template():
    mapping = {
        "GitHub": {"url": "https://github.com/{}"},
        "Instagram": {"url": "https://instagram.com/{}"},
        "Reddit": {"url": "https://www.reddit.com/user/{}"},
        "Keybase": {"url": "https://keybase.io/{}"},
    }
    kept, denied = policy.filter_site_mapping(mapping, lambda v: v["url"])
    assert list(kept) == ["GitHub", "Keybase"]        # order preserved
    assert denied == ["Instagram", "Reddit"]
    assert kept["GitHub"] is mapping["GitHub"]        # values untouched


def test_filter_site_mapping_denies_when_any_fetched_url_is_denied():
    # Maigret's HackerNews: permitted profile URL, denied probe URL. The probe
    # is what gets requested, so the site must go.
    hn = SimpleNamespace(url="https://news.ycombinator.com/user?id={username}",
                         url_probe="https://hacker-news.firebaseio.com/v0/user/{username}.json")
    gh = SimpleNamespace(url="https://github.com/{username}", url_probe=None)
    kept, denied = policy.filter_site_mapping(
        {"HackerNews": hn, "GitHub": gh},
        lambda s: [t for t in (s.url, s.url_probe) if t])
    assert list(kept) == ["GitHub"]
    assert denied == ["HackerNews"]


def test_filter_site_mapping_empty_and_none_templates():
    kept, denied = policy.filter_site_mapping({}, lambda v: v)
    assert kept == {} and denied == []
    kept, denied = policy.filter_site_mapping({"A": None, "B": ""},
                                              lambda v: v)
    assert list(kept) == ["A", "B"] and denied == []


def test_denied_site_reason_accepts_str_or_iterable():
    assert policy.denied_site_reason("https://flickr.com/{}")
    assert policy.denied_site_reason(["https://github.com/{}",
                                      "https://www.pinterest.com/{}/"])
    assert policy.denied_site_reason(["https://github.com/{}"]) is None
    assert policy.denied_site_reason(None) is None
    assert policy.denied_site_reason([None, ""]) is None


# --- platform names and check modules ---------------------------------------

def test_denied_labels_are_derived_from_denied_hosts(monkeypatch):
    labels = policy.denied_labels()
    # Every denied host contributes its registrable label.
    for host in policy.DENIED_HOSTS:
        assert policy._norm(host.split(".")[-2]) in labels, host
    # Not hand-typed: adding a host denies its label immediately.
    patched = dict(policy.DENIED_HOSTS, **{"example-platform.net": "test rule"})
    monkeypatch.setattr(policy, "DENIED_HOSTS", patched)
    assert policy.denied_name_reason("ExamplePlatform") == "test rule"


def test_denied_name_reason_for_platform_names():
    for name in ("Instagram", "instagram", "Twitter", "X", "Reddit",
                 "Pinterest", "Facebook", "Flickr", "Threads"):
        assert policy.denied_name_reason(name), name
    for name in ("GitHub", "Snapchat", "Telegram", "Keybase", "", None):
        assert policy.denied_name_reason(name) is None, name
    # Sherlock's HackerNews entry checks news.ycombinator.com (permitted); only
    # the Firebase API host is denied, and that is caught by URL, not by name.
    assert policy.denied_name_reason("HackerNews") is None


def test_denied_module_reason_by_name_or_constants():
    assert policy.denied_module_reason("instagram")
    assert policy.denied_module_reason("twitter", ())
    # Neutral name, but the module's domain constant / endpoint is denied.
    assert policy.denied_module_reason("neutral", ["register", "pinterest.com"])
    assert policy.denied_module_reason(
        "neutral", ["https://www.instagram.com/accounts/emailsignup/"])
    # Permitted module: neither name nor constants match.
    assert policy.denied_module_reason(
        "amazon", ["amazon.com", "https://www.amazon.com/ap/signin", "login"]) is None
    # Non-hostname strings are never treated as hosts.
    assert policy.denied_module_reason("neutral", ["x", "reddit", "not a host"]) is None


def _make_functions():
    async def instagram(email, client, out):          # denied by name
        out.append({"name": "instagram", "domain": "instagram.com"})

    async def helper_with_denied_domain(email, client, out):   # denied by constant
        domain = "pinterest.com"
        out.append({"name": "helper", "domain": domain})

    async def github(email, client, out):             # permitted
        domain = "github.com"
        out.append({"name": "github", "domain": domain,
                    "url": "https://github.com/settings/emails"})

    return instagram, helper_with_denied_domain, github


def test_function_denied_reason_reads_name_and_code_constants():
    instagram, helper, github = _make_functions()
    assert policy.function_denied_reason(instagram)
    assert policy.function_denied_reason(helper)
    assert policy.function_denied_reason(github) is None
    # Objects without code (mocks, partials) are simply permitted.
    assert policy.function_denied_reason(object()) is None


def test_partition_check_functions():
    instagram, helper, github = _make_functions()
    kept, skipped = policy.partition_check_functions([instagram, helper, github])
    assert kept == [github]
    assert skipped == ["instagram", "helper_with_denied_domain"]
    assert policy.partition_check_functions([]) == ([], [])
