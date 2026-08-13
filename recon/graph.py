"""Build the interactive identity-graph JSON from an investigation summary.

Nodes: one central person node, account nodes (sized by confidence, colored
by engine count client-side), one email node, one phone node, and registration
nodes from account-existence hits — holehe on the email, ignorant on the phone.
Edges carry a confidence score and a human-readable rationale, mostly derived
from the correlator.

Confidence heuristic (advisory):
  account node    45 base, +25 two-engine confirmation, +20 enrichment with
                  a display name or avatar, -15 for name-derived candidates
  account edge    same as its account node
  correlation     the correlator's own score (avatar/name/bio signals)
  holehe edge     70 (registered-account check is a strong but single signal)
"""

from __future__ import annotations

from typing import Optional

from recon.confidence import account_confidence
from recon.engines import normalize_site


def _avatar(row: dict) -> Optional[str]:
    enr = row.get("enrichment") or {}
    return enr.get("jsonld_image") or enr.get("og_image")


def _display_name(row: dict) -> Optional[str]:
    enr = row.get("enrichment") or {}
    return enr.get("jsonld_name") or enr.get("og_title") or enr.get("title")


def build_graph(summary: dict) -> dict:
    """summary: the stored investigation summary. Returns {nodes, edges}."""
    params = summary.get("params") or {}
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()

    def add_node(node: dict) -> None:
        if node["id"] not in node_ids:
            node_ids.add(node["id"])
            nodes.append(node)

    def add_edge(source: str, target: str, confidence: int,
                 rationale: str) -> None:
        edges.append({
            "id": f"e{len(edges)}",
            "source": source, "target": target,
            "confidence": max(0, min(100, int(confidence))),
            "rationale": rationale,
        })

    # --- central person node ------------------------------------------------
    label = (params.get("name") or (params.get("usernames") or [""])[0]
             or params.get("email") or params.get("phone") or "subject")
    add_node({
        "id": "person", "type": "person", "label": label,
        "confidence": 100,
        "data": {k: v for k, v in params.items() if v},
    })

    # --- account nodes ------------------------------------------------------
    url_to_id: dict[str, str] = {}
    acct_by_site: dict[str, str] = {}   # normalized site -> account node id
    all_rows = ((summary.get("accounts") or [])
                + (summary.get("variants") or [])
                + (summary.get("name_accounts") or []))
    for row in all_rows:
        nid = f"acct:{row.get('site')}:{row.get('username')}"
        conf = account_confidence(row)
        verification = (row.get("verification") or {}).get("status")
        enr = row.get("enrichment") or {}
        if row.get("source") == "name":
            rationale = (f"name-derived candidate '{row.get('candidate')}' "
                         f"from '{row.get('from_name')}'")
        elif row.get("source") == "variant":
            rationale = f"username variant of '{row.get('variant_of')}'"
        else:
            rationale = "username match"
        add_node({
            "id": nid, "type": "account",
            "label": row.get("username"), "sublabel": row.get("site"),
            "url": row.get("url"), "avatar": _avatar(row),
            "confidence": conf, "engines": row.get("engines") or [],
            "verification": verification,
            "data": {
                "site": row.get("site"), "url": row.get("url"),
                "source": row.get("source"),
                "variant_of": row.get("variant_of"),
                "from_name": row.get("from_name"),
                "candidate": row.get("candidate"),
                "display_name": _display_name(row),
                "verification": verification,
                "bio": enr.get("jsonld_description")
                       or enr.get("og_description"),
            },
        })
        if row.get("url"):
            url_to_id[row["url"]] = nid
        if row.get("site"):
            acct_by_site.setdefault(normalize_site(row["site"]), nid)
        add_edge("person", nid, conf, rationale)

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
        add_edge("person", "email", 100, "input email")
        for h in email_state.get("holehe") or []:
            if not h.get("exists"):
                continue
            nid = f"reg:{h.get('site')}"
            add_node({
                "id": nid, "type": "registration",
                "label": h.get("site"), "sublabel": h.get("domain"),
                "confidence": 70,
                "data": {"domain": h.get("domain"),
                         "email_recovery": h.get("email_recovery"),
                         "phone_number": h.get("phone_number"),
                         "corroborates_phone": h.get("corroborates_phone")},
            })
            add_edge("email", nid, 70,
                     "registered-account check positive (holehe)")

    # --- phone node + phone-registration nodes -------------------------------
    phone = summary.get("phone")
    if phone:
        add_node({
            "id": "phone", "type": "phone",
            "label": phone.get("international") or params.get("phone"),
            "confidence": 100,
            "data": phone,
        })
        add_edge("person", "phone", 100, "input phone")
        # Trail stitching: an email-derived account whose masked recovery phone
        # matches this number links straight to the phone (phone↔email↔account).
        for h in (summary.get("email") or {}).get("holehe") or []:
            if h.get("exists") and h.get("corroborates_phone"):
                reg_id = f"reg:{h.get('site')}"
                if reg_id in node_ids:
                    add_edge(reg_id, "phone", 80,
                             "account's recovery phone matches the subject number")
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
                         "method": a.get("method")},
            })
            add_edge("phone", nid, 70, "registered by phone (ignorant)")
            acct_id = acct_by_site.get(normalize_site(site or ""))
            if acct_id:
                add_edge("phone", acct_id, 60,
                         "number registered on a discovered account's platform")

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
            add_edge("email", dom_id, 90, "email domain")
        else:
            add_edge("person", dom_id, 90, "subject domain")
        # A-record IPs and nameservers as their own infrastructure nodes.
        for ip in (dns.get("A") or [])[:3]:
            ip_id = f"ip:{ip}"
            add_node({"id": ip_id, "type": "ip", "label": ip,
                      "confidence": 80, "data": {"ip": ip}})
            add_edge(dom_id, ip_id, 80, "A record")
        for ns in (rdap.get("nameservers") or dns.get("NS") or [])[:4]:
            ns_id = f"ns:{ns}"
            add_node({"id": ns_id, "type": "nameserver", "label": ns,
                      "confidence": 70, "data": {"nameserver": ns}})
            add_edge(dom_id, ns_id, 70, "nameserver")

    # --- correlation edges between accounts ----------------------------------
    for cluster in summary.get("correlation") or []:
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
                         link.get("rationale") or "correlated profiles")
        # Fallback: if no links resolved, connect members in a chain.
        if len(member_ids) >= 2 and not any(
            e["source"] in member_ids and e["target"] in member_ids
            for e in edges
        ):
            for a, b in zip(member_ids, member_ids[1:]):
                add_edge(a, b, cluster.get("confidence", 50),
                         "same correlation cluster")

    return {"nodes": nodes, "edges": edges}
