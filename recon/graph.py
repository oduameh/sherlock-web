"""Build the interactive identity-graph JSON from an investigation summary.

Nodes: one central person node, **handle pivot nodes** (one per reused handle —
the same handle on N sites pivots through a single node, so "one handle
everywhere" is visible at a glance), account nodes (sized by confidence,
coloured by verification client-side), one email node, one phone node,
registration nodes from account-existence hits, and domain / IP / nameserver
infrastructure.

Accounts carry two investigative signals the UI renders directly:

* ``category``   platform category (social / coding / gaming …) from the
                 pipeline merge, with the vendored WhatsMyName dataset as a
                 fallback lookup by site name.
* ``created_at`` account creation date when an adapter reported one (GitHub,
                 Bluesky, …). The client's timeline scrubber grows the graph
                 from these dates; nodes without dates are baseline.

Edges carry a confidence score and a human-readable rationale.

Confidence heuristic (advisory):
  account node    45 base, +25 two-engine confirmation, +20 enrichment with
                  a display name or avatar, -15 for name-derived candidates
  account edge    same as its account node
  correlation     the correlator's own score (avatar/name/bio signals)
  holehe edge     70 (registered-account check is a strong but single signal)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from recon.confidence import account_confidence, account_tier
from recon.engines import normalize_site

_WMN_DATA = Path(__file__).resolve().parent / "data" / "wmn-data.json"
_category_cache: Optional[dict[str, str]] = None


def _site_categories() -> dict[str, str]:
    """``{lowercased site name: category}`` from the vendored WMN dataset."""
    global _category_cache
    if _category_cache is None:
        try:
            data = json.loads(_WMN_DATA.read_text(encoding="utf-8"))
            _category_cache = {
                (s.get("name") or "").strip().lower(): s.get("cat")
                for s in (data.get("sites") or [])
                if s.get("cat")
            }
        except Exception:
            _category_cache = {}
    return _category_cache


def category_for(site: Optional[str]) -> Optional[str]:
    """Best-effort platform category for a site name."""
    if not site:
        return None
    return _site_categories().get(str(site).strip().lower())


def _avatar(row: dict) -> Optional[str]:
    enr = row.get("enrichment") or {}
    return enr.get("jsonld_image") or enr.get("og_image")


def _display_name(row: dict) -> Optional[str]:
    enr = row.get("enrichment") or {}
    return enr.get("jsonld_name") or enr.get("og_title") or enr.get("title")


def _created_at(row: dict) -> Optional[str]:
    """ISO creation date when an adapter reported one."""
    return (row.get("temporal") or {}).get("created_at") or None


def _all_account_rows(summary: dict) -> list[dict]:
    return ((summary.get("accounts") or [])
            + (summary.get("variants") or [])
            + (summary.get("name_accounts") or []))


def build_graph(summary: dict, baseline: Optional[dict] = None) -> dict:
    """summary: the stored investigation summary. Returns {nodes, edges}.

    ``baseline`` — a previous summary for the same subject inputs. When
    given, accounts absent from the baseline are flagged ``is_new`` and
    baseline-only accounts are emitted as ghost "gone" nodes, so a re-scan
    reads as case intelligence rather than a flat snapshot."""
    params = summary.get("params") or {}
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()

    def add_node(node: dict) -> None:
        if node["id"] not in node_ids:
            node_ids.add(node["id"])
            nodes.append(node)

    def add_edge(source: str, target: str, confidence: int,
                 rationale: str, kind: str = "link",
                 evidence: Optional[dict] = None) -> None:
        edge = {
            "id": f"e{len(edges)}",
            "source": source, "target": target,
            "confidence": max(0, min(100, int(confidence))),
            "rationale": rationale,
            "kind": kind,
        }
        if evidence:
            edge["evidence"] = evidence
        edges.append(edge)

    # --- central person node ------------------------------------------------
    label = (params.get("name") or (params.get("usernames") or [""])[0]
             or params.get("email") or params.get("phone") or "subject")
    add_node({
        "id": "person", "type": "person", "label": label,
        "confidence": 100,
        "data": {k: v for k, v in params.items() if v},
    })

    # --- account nodes ------------------------------------------------------
    # Pass 1 creates every account node; pass 2 wires edges so that reused
    # handles can pivot through one shared node instead of star-ing off the
    # person individually.
    url_to_id: dict[str, str] = {}
    acct_by_site: dict[str, str] = {}   # normalized site -> account node id
    all_rows = _all_account_rows(summary)
    baseline_urls: Optional[set] = None
    if baseline is not None:
        baseline_urls = {
            r.get("url") for r in _all_account_rows(baseline) if r.get("url")
        }
    for row in all_rows:
        nid = f"acct:{row.get('site')}:{row.get('username')}"
        conf = account_confidence(row)
        verification = (row.get("verification") or {}).get("status")
        enr = row.get("enrichment") or {}
        created = _created_at(row)
        category = row.get("category") or category_for(row.get("site"))
        add_node({
            "id": nid, "type": "account",
            "label": row.get("username"), "sublabel": row.get("site"),
            "url": row.get("url"), "avatar": _avatar(row),
            "confidence": conf, "engines": row.get("engines") or [],
            "verification": verification,
            "tier": account_tier(row),
            "created_at": created,
            "data": {
                "site": row.get("site"), "url": row.get("url"),
                "source": row.get("source"),
                "variant_of": row.get("variant_of"),
                "from_name": row.get("from_name"),
                "candidate": row.get("candidate"),
                "display_name": _display_name(row),
                "verification": verification,
                "category": category,
                "bio": enr.get("jsonld_description")
                       or enr.get("og_description"),
            },
        })
        if row.get("url"):
            url_to_id[row["url"]] = nid
        if row.get("site"):
            acct_by_site.setdefault(normalize_site(row["site"]), nid)

    def _norm_handle(u: Optional[str]) -> str:
        return (u or "").strip().lstrip("@").lower()

    # Pass 2: group by normalized handle. Handles used on two or more sites
    # become pivot nodes; single-site handles stay directly wired to the
    # person (a pivot for one node is pure noise).
    by_handle: dict[str, list[dict]] = {}
    for row in all_rows:
        h = _norm_handle(row.get("username"))
        if h:
            by_handle.setdefault(h, []).append(row)
    for h, rows in by_handle.items():
        ids = [f"acct:{r.get('site')}:{r.get('username')}" for r in rows]
        if len(ids) < 2:
            r0 = rows[0]
            add_edge("person", ids[0], account_confidence(r0),
                     f"username match on {r0.get('site')}", kind="account")
            continue
        hid = f"handle:{h}"
        top_conf = max(account_confidence(r) for r in rows)
        add_node({
            "id": hid, "type": "handle",
            "label": h, "sublabel": f"{len(ids)} sites",
            "confidence": top_conf,
            "data": {"handle": h, "sites": [r.get("site") for r in rows]},
        })
        add_edge("person", hid, top_conf,
                 f"handle '{h}' reused across platforms", kind="handle")
        for r in rows:
            add_edge(hid, f"acct:{r.get('site')}:{r.get('username')}",
                     account_confidence(r),
                     f"'{h}' on {r.get('site')}", kind="handle")

    # --- run diff vs a baseline scan ----------------------------------------
    if baseline_urls is not None:
        current_urls = set(url_to_id)
        by_id = {n["id"]: n for n in nodes}
        for row in all_rows:
            u = row.get("url")
            if u is None or u in baseline_urls:
                continue
            n = by_id.get(f"acct:{row.get('site')}:{row.get('username')}")
            if n is not None:
                n["data"]["is_new"] = True
        for r in _all_account_rows(baseline):
            u = r.get("url")
            if not u or u in current_urls:
                continue
            nid = f"gone:{r.get('site')}:{r.get('username')}"
            add_node({
                "id": nid, "type": "account",
                "label": r.get("username"), "sublabel": r.get("site"),
                "url": u, "avatar": _avatar(r),
                "confidence": account_confidence(r),
                "engines": r.get("engines") or [],
                "verification": (r.get("verification") or {}).get("status"),
                "tier": account_tier(r),
                "created_at": _created_at(r),
                "data": {
                    "site": r.get("site"), "url": u, "gone": True,
                    "category": r.get("category") or category_for(r.get("site")),
                    "display_name": _display_name(r),
                },
            })
            add_edge("person", nid,
                     max(20, min(account_confidence(r), 50)),
                     "present in an earlier scan of this subject; now absent",
                     kind="account")

    # --- email node + holehe registration nodes ------------------------------
    email_addr = params.get("email") or ""
    email_state = summary.get("email") or {}
    grav = email_state.get("gravatar")
    if email_addr:
        add_node({
            "id": "email", "type": "email", "label": email_addr,
            "confidence": 100,
            "avatar": (grav or {}).get("avatar_url"),
            "data": {
                "gravatar": grav,
                "holehe_hits": sum(
                    1 for h in (email_state.get("holehe") or [])
                    if h.get("exists")),
            },
        })
        add_edge("person", "email", 100, "input email", kind="input")
        for h in email_state.get("holehe") or []:
            if not h.get("exists"):
                continue
            nid = f"reg:{h.get('site')}"
            add_node({
                "id": nid, "type": "registration",
                "label": h.get("site"), "sublabel": h.get("domain"),
                "confidence": 70,
                "data": {"domain": h.get("domain"),
                         "category": category_for(h.get("site")),
                         "email_recovery": h.get("email_recovery"),
                         "phone_number": h.get("phone_number"),
                         "corroborates_phone": h.get("corroborates_phone")},
            })
            add_edge("email", nid, 70,
                     "registered-account check positive (holehe)",
                     kind="registration")

    # --- phone node + phone-registration nodes -------------------------------
    phone = summary.get("phone")
    if phone:
        add_node({
            "id": "phone", "type": "phone",
            "label": phone.get("international") or params.get("phone"),
            "confidence": 100,
            "data": phone,
        })
        add_edge("person", "phone", 100, "input phone", kind="input")
        # Trail stitching: an email-derived account whose masked recovery phone
        # matches this number links straight to the phone (phone↔email↔account).
        for h in (summary.get("email") or {}).get("holehe") or []:
            if h.get("exists") and h.get("corroborates_phone"):
                reg_id = f"reg:{h.get('site')}"
                if reg_id in node_ids:
                    add_edge(reg_id, "phone", 80,
                             "account's recovery phone matches the subject number",
                             kind="trail")
        # Account-existence hits (ignorant): each positive platform becomes a
        # registration node hanging off the phone — the same pattern as holehe
        # email registrations. Where the platform matches a username-discovered
        # account, also link the phone straight to that account (correlation).
        for a in phone.get("accounts") or []:
            if not a.get("exists"):
                continue
            site = a.get("site")
            nid = f"reg:phone:{site}"
            add_node({
                "id": nid, "type": "registration",
                "label": site, "sublabel": a.get("domain"),
                "confidence": 70,
                "data": {"domain": a.get("domain"), "via": "phone",
                         "method": a.get("method"),
                         "category": category_for(site)},
            })
            add_edge("phone", nid, 70, "registered by phone (ignorant)",
                     kind="registration")
            acct_id = acct_by_site.get(normalize_site(site or ""))
            if acct_id:
                add_edge("phone", acct_id, 60,
                         "number registered on a discovered account's platform",
                         kind="trail")

    # --- domain / infrastructure nodes ---------------------------------------
    domain_state = summary.get("domain")
    if domain_state and domain_state.get("domain") and not domain_state.get("error"):
        dom = domain_state["domain"]
        dom_id = f"domain:{dom}"
        rdap = domain_state.get("rdap") or {}
        dns = domain_state.get("dns") or {}
        add_node({
            "id": dom_id, "type": "domain", "label": dom,
            "sublabel": rdap.get("registrar"), "confidence": 100,
            "data": {
                "registrar": rdap.get("registrar"),
                "registered": rdap.get("registered"),
                "expires": rdap.get("expires"),
                "subdomains": domain_state.get("subdomain_count"),
                "mx": ", ".join(dns.get("MX") or []) or None,
            },
        })
        # Attach the domain to the email node when it was derived from one,
        # otherwise to the person.
        if "email" in node_ids:
            add_edge("email", dom_id, 90, "email domain", kind="infra")
        else:
            add_edge("person", dom_id, 90, "subject domain", kind="infra")
        # A-record IPs and nameservers as their own infrastructure nodes.
        for ip in (dns.get("A") or [])[:3]:
            ip_id = f"ip:{ip}"
            add_node({"id": ip_id, "type": "ip", "label": ip,
                      "confidence": 80, "data": {"ip": ip}})
            add_edge(dom_id, ip_id, 80, "A record", kind="infra")
        for ns in (rdap.get("nameservers") or dns.get("NS") or [])[:4]:
            ns_id = f"ns:{ns}"
            add_node({"id": ns_id, "type": "nameserver", "label": ns,
                      "confidence": 70, "data": {"nameserver": ns}})
            add_edge(dom_id, ns_id, 70, "nameserver", kind="infra")

    # --- correlation edges between accounts ----------------------------------
    # These avatar/name/bio matches are the "same person" evidence, so they get
    # their own kind (elevated in the UI), a structured evidence breakdown, and
    # a shared ``cluster`` id on their member nodes so the UI can hull them.
    node_by_id = {n["id"]: n for n in nodes}
    for ci, cluster in enumerate(summary.get("correlation") or []):
        members = cluster.get("members") or []
        member_ids = [url_to_id.get(m.get("url")) for m in members]
        member_ids = [m for m in member_ids if m]
        for link in cluster.get("links") or []:
            # Link endpoints are "site (url)" labels — resolve via the url.
            ids = []
            for endpoint in (link.get("a"), link.get("b")):
                url = endpoint[endpoint.find("(") + 1:endpoint.rfind(")")] \
                    if endpoint and "(" in endpoint else None
                nid = url_to_id.get(url)
                if nid:
                    ids.append(nid)
            if len(ids) == 2 and ids[0] != ids[1]:
                add_edge(ids[0], ids[1], link.get("score", 50),
                         link.get("rationale") or "correlated profiles",
                         kind="correlation", evidence=link.get("signals"))
        # Fallback: if no links resolved, connect members in a chain.
        if len(member_ids) >= 2 and not any(
            e["source"] in member_ids and e["target"] in member_ids
            for e in edges
        ):
            for a, b in zip(member_ids, member_ids[1:]):
                add_edge(a, b, cluster.get("confidence", 50),
                         "same correlation cluster", kind="correlation")
        # Stamp a shared cluster id on every resolved member (>= 2 = a person).
        if len(member_ids) >= 2:
            cid = f"cluster:{ci}"
            for mid in member_ids:
                n = node_by_id.get(mid)
                if n is not None:
                    n["cluster"] = cid

    return {"nodes": nodes, "edges": edges}
