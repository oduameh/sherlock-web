"""Plan-time site-set filtering: access policy first, open circuits second.

``recon.policy`` promises that robots-denied hosts are never fetched. Until
2026-09-06 that was true only of our own fetchers: the pipeline handed
Sherlock, Maigret and WhatsMyName their raw site lists, so Instagram, Reddit,
X/Twitter, Flickr, Threads, Facebook and Pinterest were scanned on every run
(audit ``retrieval-reliability.md`` §6 defect 8, ``security.md`` F-2;
architecture §8 decision 3). :func:`plan_site_sets` is the single place where
every engine's site set is filtered before any engine runs, and the single
place that *reports* what was skipped, so the analyst sees "not examined —
access policy" once per denied site instead of silence or fake errors.

Pure: takes site dicts in, returns a :class:`SitePlan`; the optional
``circuit_filter`` (the router's ``filter_sites``) is applied *after* policy so
a denied site is never reported as degraded as well.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from recon import engines, policy
from recon import whatsmyname as wmn_module

logger = logging.getLogger("recon.plan")

CircuitFilter = Callable[[dict, str], dict]


@dataclass
class SitePlan:
    """The filtered site sets an investigation may scan, plus what it skipped."""

    sherlock: dict[str, dict]
    sherlock_reduced: dict[str, dict]
    maigret: dict[str, Any]
    maigret_reduced: dict[str, Any]
    whatsmyname: list[dict]
    whatsmyname_reduced: list[dict]
    # [{site, engine, reason}], one row per (site, engine) — the payload of
    # the additive ``skipped_policy`` SSE event.
    skipped_policy: list[dict] = field(default_factory=list)

    def skipped_event(self) -> dict:
        return {"count": len(self.skipped_policy),
                "sites": self.skipped_policy[:10]}


def _policy_filter(mapping: dict, engine: str, url_of: Callable[[Any], Any],
                   skipped: list[dict], seen: set[tuple[str, str]]) -> dict:
    kept, denied = policy.filter_site_mapping(mapping, url_of)
    for name in denied:
        key = (name, engine)
        if key in seen:
            continue
        seen.add(key)
        skipped.append({"site": name, "engine": engine,
                        "reason": skip_reason(url_of(mapping[name]))})
    return kept


def skip_reason(templates) -> str:
    """The analyst-facing reason a site was skipped — true to what the engine
    would actually have fetched. Templates are ordered profile URL first.

    * profile denied, probe permitted (Sherlock Instagram → imginn, Twitter →
      nitter): say so — the platform is denied and the mirror is not used as a
      proxy for it (policy module docstring);
    * profile permitted, probe denied (HackerNews → Firebase): the probe is
      what gets fetched — say that instead of blaming the profile host.
    """
    tpls = [templates] if isinstance(templates, str) else list(templates or [])
    if not tpls:
        return ""
    reasons = [policy.denied_site_reason(t) for t in tpls]
    if reasons[0]:
        if len(tpls) > 1 and any(r is None for r in reasons[1:]):
            return (f"{reasons[0]} — the engine would probe a third-party mirror,"
                    " which is not used as a proxy for a denied platform")
        return reasons[0]
    probe = next((r for r in reasons[1:] if r), "")
    return f"{probe} — the engine's check request goes there behind a permitted profile URL"


def plan_site_sets(
    *,
    sherlock: dict[str, dict],
    maigret: dict[str, Any],
    maigret_reduced: dict[str, Any],
    whatsmyname: list[dict],
    whatsmyname_reduced: list[dict],
    circuit_filter: Optional[CircuitFilter] = None,
) -> SitePlan:
    """Filter every engine site set by access policy, then by open circuits.

    * ``sherlock``: Sherlock's site dict (``name -> information``); the reduced
      (variant) subset is derived from the filtered result.
    * ``maigret`` / ``maigret_reduced``: Maigret site objects by name.
    * ``whatsmyname`` / ``whatsmyname_reduced``: WhatsMyName site dicts.
    * ``circuit_filter(site_dict, engine)``: the router's open-circuit filter.

    Guarantees: no returned set contains a site whose fetched URL template is
    on a denied host; ``skipped_policy`` lists each denied (site, engine) once
    with its reason; the reduced sets are subsets of the filtered full sets'
    rules (a denied site can never re-enter through a curated list).
    """
    skipped: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def circuits(mapping: dict, engine: str) -> dict:
        if circuit_filter is None or not mapping:
            return mapping
        return circuit_filter(mapping, engine)

    sher = circuits(_policy_filter(sherlock or {}, "sherlock",
                                   engines.sherlock_url_templates,
                                   skipped, seen), "sherlock")
    # The curated subset comes from the already-filtered full set; the helper
    # filters again itself (defence in depth) — nothing new to report.
    sher_reduced = engines.sherlock_variant_site_data(sher)

    mai = circuits(_policy_filter(maigret or {}, "maigret",
                                  engines.maigret_url_templates,
                                  skipped, seen), "maigret")
    mai_reduced = circuits(_policy_filter(maigret_reduced or {}, "maigret",
                                          engines.maigret_url_templates,
                                          skipped, seen), "maigret")

    wmn_url = wmn_module.url_templates
    wmn = list(circuits(_policy_filter(_by_name(whatsmyname), "whatsmyname",
                                       wmn_url, skipped, seen),
                        "whatsmyname").values())
    wmn_reduced = list(circuits(_policy_filter(_by_name(whatsmyname_reduced),
                                               "whatsmyname", wmn_url,
                                               skipped, seen),
                                "whatsmyname").values())

    if skipped:
        logger.info("access policy: %d engine site(s) not examined: %s",
                    len(skipped),
                    ", ".join(f"{s['engine']}:{s['site']}" for s in skipped))
    return SitePlan(
        sherlock=sher, sherlock_reduced=sher_reduced,
        maigret=mai, maigret_reduced=mai_reduced,
        whatsmyname=wmn, whatsmyname_reduced=wmn_reduced,
        skipped_policy=skipped,
    )


def _by_name(sites: Optional[list[dict]]) -> dict[str, dict]:
    """Key WhatsMyName site defs by name (the router's filter wants a dict)."""
    return {s["name"]: s for s in (sites or []) if s.get("name")}
