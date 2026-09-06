"""Plan-time site-set filtering (recon.plan).

Acceptance criterion (architecture §10 row C): no denied host in any planned
set, and each denied (site, engine) reported once. Exercised on fake data and
on the real, offline engine datasets (Sherlock's bundled data.json, Maigret's
bundled DB when installed, the vendored WhatsMyName data).
"""

import json
from types import SimpleNamespace

import pytest

from recon import engines, policy, whatsmyname
from recon.plan import plan_site_sets


def _msite(name, url, url_probe=None, url_main=""):
    return SimpleNamespace(name=name, url=url, url_probe=url_probe,
                           url_main=url_main, url_subpath="")


_SHER = {
    "GitHub": {"url": "https://github.com/{}", "urlMain": "https://github.com/"},
    "Instagram": {"url": "https://instagram.com/{}", "urlMain": "https://instagram.com/"},
    "GitLab": {"url": "https://gitlab.com/{}", "urlMain": "https://gitlab.com/"},
    "threads": {"url": "https://www.threads.net/@{}", "urlMain": "https://www.threads.net/"},
}
_MAI = {
    "GitHub": _msite("GitHub", "https://github.com/{username}"),
    "Twitter": _msite("Twitter", "https://twitter.com/{username}"),
    "HackerNews": _msite("HackerNews", "https://news.ycombinator.com/user?id={username}",
                         url_probe="https://hacker-news.firebaseio.com/v0/user/{username}.json"),
    "Forum": _msite("Forum", "{urlMain}/u/{username}", url_main="https://www.reddit.com"),
}
_WMN = [
    {"name": "GitHub", "uri_check": "https://github.com/{account}"},
    {"name": "Reddit", "uri_check": "https://www.reddit.com/user/{account}/about.json"},
    {"name": "X", "uri_check": "https://api.x.com/i/users/username_available.json?username={account}"},
]


def test_plan_removes_denied_sites_from_every_set():
    plan = plan_site_sets(sherlock=_SHER, maigret=_MAI, maigret_reduced={"Twitter": _MAI["Twitter"], "GitHub": _MAI["GitHub"]},
                          whatsmyname=_WMN, whatsmyname_reduced=_WMN[:2])
    assert list(plan.sherlock) == ["GitHub", "GitLab"]
    assert list(plan.maigret) == ["GitHub"]                 # Twitter, HackerNews(probe), Forum({urlMain}) gone
    assert list(plan.maigret_reduced) == ["GitHub"]
    assert [s["name"] for s in plan.whatsmyname] == ["GitHub"]
    assert [s["name"] for s in plan.whatsmyname_reduced] == ["GitHub"]
    # The Sherlock reduced set is a curated subset of the filtered full set.
    assert set(plan.sherlock_reduced) <= set(plan.sherlock)


def test_plan_reports_each_denied_site_once_with_engine_and_reason():
    plan = plan_site_sets(sherlock=_SHER, maigret=_MAI,
                          maigret_reduced={"Twitter": _MAI["Twitter"]},   # also in the full set
                          whatsmyname=_WMN, whatsmyname_reduced=_WMN)
    rows = {(r["site"], r["engine"]): r["reason"] for r in plan.skipped_policy}
    assert len(rows) == len(plan.skipped_policy)            # deduped by (site, engine)
    assert set(rows) == {
        ("Instagram", "sherlock"), ("threads", "sherlock"),
        ("Twitter", "maigret"), ("HackerNews", "maigret"), ("Forum", "maigret"),
        ("Reddit", "whatsmyname"), ("X", "whatsmyname"),
    }
    assert rows[("HackerNews", "maigret")] == policy.DENIED_HOSTS["hacker-news.firebaseio.com"]
    assert rows[("Forum", "maigret")] == policy.DENIED_HOSTS["reddit.com"]
    ev = plan.skipped_event()
    assert ev["count"] == 7 and ev["sites"] == plan.skipped_policy
    for r in ev["sites"]:
        assert set(r) == {"site", "engine", "reason"} and r["reason"]


def test_circuit_filter_runs_after_policy_and_never_sees_denied_sites():
    seen: list[tuple[str, tuple]] = []

    def circuit_filter(mapping, engine):
        seen.append((engine, tuple(mapping)))
        return {n: v for n, v in mapping.items() if n != "GitLab"}   # one open circuit

    plan = plan_site_sets(sherlock=_SHER, maigret=_MAI, maigret_reduced={},
                          whatsmyname=_WMN, whatsmyname_reduced=[],
                          circuit_filter=circuit_filter)
    assert list(plan.sherlock) == ["GitHub"]                # GitLab dropped by the circuit
    for engine, names in seen:
        for n in names:
            assert (n, engine) not in {(r["site"], r["engine"]) for r in plan.skipped_policy}
    # A degraded site is never also reported as a policy skip.
    assert "GitLab" not in {r["site"] for r in plan.skipped_policy}


def test_plan_handles_empty_inputs():
    plan = plan_site_sets(sherlock={}, maigret={}, maigret_reduced={},
                          whatsmyname=[], whatsmyname_reduced=[])
    assert plan.sherlock == {} and plan.maigret == {} and plan.whatsmyname == []
    assert plan.skipped_policy == [] and plan.skipped_event() == {"count": 0, "sites": []}


# --- real datasets (offline) ------------------------------------------------

def _sherlock_bundled() -> dict:
    import sherlock_project
    path = sherlock_project.__path__[0] + "/resources/data.json"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data.pop("$schema", None)
    return data


def _assert_no_denied(mapping_or_list, url_of, label):
    items = mapping_or_list.values() if isinstance(mapping_or_list, dict) else mapping_or_list
    bad = [url_of(v) for v in items if policy.denied_site_reason(url_of(v))]
    assert not bad, f"{label}: denied templates survived: {bad[:5]}"


def test_no_denied_host_survives_in_any_planned_set_real_data():
    sher = _sherlock_bundled()
    if engines.maigret_available():
        mai_all = engines.maigret_all_sites(None)                      # whole DB
        mai_red = engines.maigret_variant_sites(policy_filtered=False)
    else:
        mai_all, mai_red = {}, {}
    plan = plan_site_sets(
        sherlock=sher, maigret=mai_all, maigret_reduced=mai_red,
        whatsmyname=whatsmyname.all_sites(),
        whatsmyname_reduced=whatsmyname.variant_sites(policy_filtered=False),
    )
    _assert_no_denied(plan.sherlock, engines.sherlock_url_templates, "sherlock")
    _assert_no_denied(plan.sherlock_reduced, engines.sherlock_url_templates, "sherlock_reduced")
    _assert_no_denied(plan.maigret, engines.maigret_url_templates, "maigret")
    _assert_no_denied(plan.maigret_reduced, engines.maigret_url_templates, "maigret_reduced")
    _assert_no_denied(plan.whatsmyname, whatsmyname.url_templates, "whatsmyname")
    _assert_no_denied(plan.whatsmyname_reduced, whatsmyname.url_templates, "whatsmyname_reduced")

    skipped = {(r["site"], r["engine"]) for r in plan.skipped_policy}
    # The known offenders from the 2026-09-06 audit are gone and reported.
    for site in ("Instagram", "Reddit", "Flickr", "threads"):
        assert (site, "sherlock") in skipped, site
        assert site not in plan.sherlock
    for site in ("Facebook", "Instagram", "Reddit", "Pinterest", "Threads", "X"):
        assert (site, "whatsmyname") in skipped, site
    # Counts the ``meta`` event reports are the filtered sizes.
    sher_denied = [r for r in plan.skipped_policy if r["engine"] == "sherlock"]
    assert len(plan.sherlock) == len(sher) - len(sher_denied)
    assert len(plan.whatsmyname) == len(whatsmyname.all_sites()) - len(
        [r for r in plan.skipped_policy if r["engine"] == "whatsmyname"])
    # Twitter is scanned by Sherlock on x.com — denied by host, not by name.
    assert ("Twitter", "sherlock") in skipped


def test_maigret_denied_sites_are_planned_out_real_data():
    if not engines.maigret_available():
        pytest.skip("maigret not installed")
    plan = plan_site_sets(sherlock={}, maigret=engines.maigret_all_sites(None),
                          maigret_reduced=engines.maigret_variant_sites(policy_filtered=False),
                          whatsmyname=[], whatsmyname_reduced=[])
    skipped = {r["site"] for r in plan.skipped_policy if r["engine"] == "maigret"}
    for site in ("Facebook", "Instagram", "Twitter", "Pinterest", "Reddit",
                 "Flickr", "Threads", "HackerNews"):
        assert site in skipped, site
        assert site not in plan.maigret and site not in plan.maigret_reduced
