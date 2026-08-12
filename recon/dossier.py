"""Professional dossier report for investigations.

Self-contained HTML (no external assets), print-to-PDF friendly. Cover block,
auto-generated executive summary, digital-footprint score, then evidence
sections, methodology, limitations, and a responsible-use footer.
"""

from __future__ import annotations

import html
import time
from typing import Any

from recon.confidence import account_confidence
from recon.exposure import exposure_summary, footprint_score


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


_ACCT_HEADER = ("<tr><th>Platform</th><th>Profile</th><th>Engines</th>"
                "<th>Conf.</th><th>Identity</th></tr>")

_VERIFY_CHIP = {
    "confirmed": "<span class='tag' style='color:var(--green);"
                 "border-color:var(--green)'>verified</span>",
    "likely_false_positive": "<span class='tag' style='color:var(--red);"
                             "border-color:var(--red)'>likely false</span>",
}


_CSS = """
:root{--ink:#1a1d21;--dim:#5a6472;--border:#d8dee6;--accent:#1f6feb;
--green:#1a7f37;--red:#cf222e;--amber:#9a6700}
*{box-sizing:border-box;margin:0;padding:0}
body{background:#fff;color:var(--ink);font-family:Georgia,'Times New Roman',serif;
max-width:860px;margin:0 auto;padding:40px 28px;font-size:14px;line-height:1.55}
.cover{border:2px solid var(--ink);padding:28px 32px;margin-bottom:32px}
.cover .conf{font-family:-apple-system,'Segoe UI',sans-serif;font-size:11px;
letter-spacing:2px;color:var(--red);border:1px solid var(--red);display:inline-block;
padding:3px 10px;margin-bottom:16px;font-weight:700}
.cover h1{font-size:26px;margin-bottom:6px}
.cover .subj{font-size:17px;color:var(--accent);margin-bottom:14px}
.cover table{font-size:13px}
.cover td{padding:2px 16px 2px 0;color:var(--dim)}
.cover td:first-child{font-family:-apple-system,'Segoe UI',sans-serif;
text-transform:uppercase;font-size:10.5px;letter-spacing:1px}
h2{font-family:-apple-system,'Segoe UI',sans-serif;font-size:14px;
text-transform:uppercase;letter-spacing:1.2px;margin:30px 0 10px;
padding-bottom:5px;border-bottom:2px solid var(--ink)}
.score-band{display:flex;align-items:center;gap:20px;border:1px solid var(--border);
padding:16px 20px;margin:10px 0}
.score-num{font-size:44px;font-weight:700;font-family:-apple-system,'Segoe UI',sans-serif}
.score-num small{font-size:16px;color:var(--dim)}
.score-detail{font-size:12.5px;color:var(--dim)}
table.data{width:100%;border-collapse:collapse;font-size:12.5px;
font-family:-apple-system,'Segoe UI',sans-serif}
table.data th{text-align:left;text-transform:uppercase;font-size:10px;
letter-spacing:.8px;color:var(--dim);padding:5px 8px;border-bottom:1.5px solid var(--ink)}
table.data td{padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
a{color:var(--accent);text-decoration:none;word-break:break-all}
.tag{display:inline-block;font-size:10px;border:1px solid var(--dim);border-radius:3px;
padding:0 5px;margin-right:4px;color:var(--dim);font-family:-apple-system,'Segoe UI',sans-serif}
.dim{color:var(--dim)}
ul.tight{margin:6px 0 6px 20px}
ul.tight li{margin-bottom:3px}
.notebox{border-left:3px solid var(--amber);background:#fff8e6;padding:10px 14px;
font-size:12.5px;margin:10px 0}
footer{margin-top:44px;padding-top:14px;border-top:1px solid var(--border);
font-size:11.5px;color:var(--dim)}
@media print{
  body{padding:0;font-size:12px}
  .cover{page-break-after:avoid}
  h2{page-break-after:avoid}
  table.data tr{page-break-inside:avoid}
  a{color:var(--ink)}
}
"""


def _exec_summary(inv: dict, summary: dict, score: dict) -> str:
    params = summary.get("params") or {}
    accounts = summary.get("accounts") or []
    variants = summary.get("variants") or []
    name_rows = summary.get("name_accounts") or []
    email = summary.get("email") or {}
    phone = summary.get("phone") or {}
    clusters = summary.get("correlation") or []

    n = len(accounts) + len(variants) + len(name_rows)
    platforms = {r.get("site") for r in accounts + variants + name_rows}
    holehe_hits = sum(1 for h in (email.get("holehe") or []) if h.get("exists"))
    strong_links = sum(
        1 for c in clusters if (c.get("confidence") or 0) >= 60
    )

    inputs = []
    if params.get("name"):
        inputs.append(f"the name \u201c{params['name']}\u201d")
    if params.get("usernames"):
        inputs.append("username(s) " + ", ".join(params["usernames"]))
    if params.get("email"):
        inputs.append(f"the email {params['email']}")
    if params.get("phone"):
        inputs.append(f"the phone number {params['phone']}")
    subject = ", ".join(inputs) or "the supplied inputs"

    s = (
        f"Investigation #{inv.get('id')} began from {subject}. "
        f"The automated pipeline identified {n} account(s) across "
        f"{len(platforms)} platform(s)"
    )
    if variants:
        s += f", including {len(variants)} via username variants"
    if name_rows:
        s += f" and {len(name_rows)} via name-derived candidate handles"
    s += ". "
    if strong_links:
        s += (f"Cross-account correlation produced {strong_links} "
              f"high-confidence identity link(s) (\u226560% confidence). ")
    elif clusters:
        s += (f"{len(clusters)} tentative correlation cluster(s) were found, "
              f"none above the high-confidence threshold. ")
    if params.get("email"):
        if holehe_hits:
            s += (f"The email address is registered on {holehe_hits} checked "
                  f"service(s)"
                  + (" and has a public Gravatar profile. "
                     if email.get("gravatar") else ". "))
        else:
            s += "No registered-account exposure was found for the email. "
    if phone:
        if phone.get("valid"):
            s += (f"The phone number is valid ({phone.get('country') or phone.get('region') or 'unknown region'}"
                  + (f", carrier {phone['carrier']}" if phone.get("carrier") else "")
                  + "). ")
        else:
            s += "The phone number could not be validated as assigned. "
    s += (f"Overall digital-footprint score: {score['score']}/100. "
          f"All findings derive from public data and heuristic correlation; "
          f"manual verification is required before any operational use.")
    return s


def _account_rows(rows: list[dict]) -> str:
    out = []
    for r in rows:
        enr = r.get("enrichment") or {}
        name = enr.get("jsonld_name") or enr.get("og_title") or enr.get("title")
        engines = ", ".join(r.get("engines") or [])
        conf = account_confidence(r)
        vchip = _VERIFY_CHIP.get((r.get("verification") or {}).get("status"), "")
        tags = ""
        if r.get("source") == "variant":
            tags = f"<span class='tag'>variant of {_e(r.get('variant_of'))}</span>"
        elif r.get("source") == "name":
            tags = (f"<span class='tag'>candidate {_e(r.get('candidate'))}"
                    f" from {_e(r.get('from_name'))}</span>")
        out.append(
            f"<tr><td><b>{_e(r.get('site'))}</b></td>"
            f"<td><a href='{_e(r.get('url'))}'>{_e(r.get('url'))}</a>"
            f"<div class='dim'>{_e(r.get('username'))} {vchip}{tags}</div></td>"
            f"<td>{_e(engines)}</td><td><b>{conf}%</b></td>"
            f"<td>{_e(name) or '—'}</td></tr>"
        )
    return "".join(out)


_TIMELINE_KIND = {
    "opened": "Investigation opened",
    "scan": "Scan run",
    "account_created": "Account created",
    "alert": "Watchlist alert",
}


def _exposure_section(summary: dict) -> str:
    """Category breakdown, identity signals, and top accounts."""
    exp = exposure_summary(summary)
    out = [f"<h2>Exposure profile — {_e(exp['band'])}</h2>"]
    if exp["factors"]:
        out.append("<ul class='tight'>")
        out.extend(f"<li>{_e(f)}</li>" for f in exp["factors"])
        out.append("</ul>")
    if exp["categories"]:
        out.append("<table class='data'><tr><th>Category</th>"
                   "<th>Accounts</th></tr>")
        for cat, n in exp["categories"].items():
            out.append(f"<tr><td>{_e(cat.capitalize())}</td><td>{n}</td></tr>")
        out.append("</table>")
    if exp["top_accounts"]:
        out.append("<h2 style='border:none;text-transform:none;font-size:12px;"
                   "margin:12px 0 4px'>Highest-confidence accounts</h2>")
        out.append("<table class='data'><tr><th>Platform</th><th>Handle</th>"
                   "<th>Category</th><th>Conf.</th></tr>")
        for a in exp["top_accounts"]:
            out.append(
                f"<tr><td><b>{_e(a['site'])}</b></td>"
                f"<td>{_e(a['username'])}</td>"
                f"<td>{_e((a['category'] or '').capitalize())}</td>"
                f"<td><b>{a['confidence']}%</b></td></tr>"
            )
        out.append("</table>")
    return "".join(out)


def _timeline_section(timeline: list[dict]) -> str:
    """Chronological milestone table."""
    out = [f"<h2>Subject timeline ({len(timeline)} events)</h2>"]
    out.append("<table class='data'><tr><th>When</th><th>Event</th>"
               "<th>Detail</th></tr>")
    for ev in timeline:
        when = ev.get("date") if ev.get("dated") else "—"
        kind = _TIMELINE_KIND.get(ev.get("kind"), ev.get("kind") or "")
        title = ev.get("title") or kind
        out.append(
            f"<tr><td>{_e(when)}</td>"
            f"<td><b>{_e(title)}</b><div class='dim'>{_e(kind)}</div></td>"
            f"<td class='dim'>{_e(ev.get('detail'))}</td></tr>"
        )
    out.append("</table>")
    out.append("<p class='dim'>Undated events (—) had no public timestamp and "
               "sort last. Account-creation dates come from public platform "
               "APIs (e.g. GitHub) where available.</p>")
    return "".join(out)


def _connections_section(connections: list[dict]) -> str:
    """Links to other investigations sharing identifiers with this one."""
    out = [f"<h2>Cross-case connections ({len(connections)})</h2>"]
    out.append(
        "<p class='dim'>Other stored investigations that share an identifier "
        "with this subject. Shared handles alone are weak (username reuse); "
        "shared emails, phones, and domains are strong.</p>"
    )
    out.append("<table class='data'><tr><th>Case</th><th>Strength</th>"
               "<th>Shared</th></tr>")
    for c in connections:
        out.append(
            f"<tr><td>#{_e(c.get('investigation_id'))} "
            f"{_e(c.get('label'))}</td>"
            f"<td><b>{c.get('strength')}%</b></td>"
            f"<td>{_e(c.get('summary'))}</td></tr>"
        )
    out.append("</table>")
    return "".join(out)


_BROKER_STATUS_LABEL = {
    "listed": "Profile listed",
    "blocked": "Blocked (check manually)",
    "not_found": "Not found",
    "manual": "Opt-out available",
}


def _broker_section(brokers: dict) -> str:
    """Data-broker exposure + opt-out map (the Incogni-style remediation view)."""
    rows = brokers.get("brokers") or []
    s = brokers.get("summary") or {}
    out = [f"<h2>Data-broker exposure ({len(rows)} brokers)</h2>"]
    out.append(
        "<p class='dim'>People-search sites and data brokers that may expose "
        "this subject. Each row links directly to that broker's opt-out page — "
        "the removal path. Most brokers block automated presence checks (shown "
        "as &lsquo;blocked&rsquo;, never a false &lsquo;not found&rsquo;); those "
        "must be checked by hand via the search link.</p>"
    )
    order = {"listed": 0, "blocked": 1, "manual": 2, "not_found": 3}
    rows = sorted(rows, key=lambda b: order.get(b.get("status"), 9))
    out.append("<table class='data'><tr><th>Broker</th><th>Category</th>"
               "<th>Status</th><th>Opt-out</th></tr>")
    for b in rows:
        status = _BROKER_STATUS_LABEL.get(b.get("status"), b.get("status") or "")
        search = b.get("search_url")
        search_link = (f" · <a href='{_e(search)}'>search</a>" if search else "")
        out.append(
            f"<tr><td><b>{_e(b.get('name'))}</b></td>"
            f"<td>{_e((b.get('category') or '').capitalize())}</td>"
            f"<td>{_e(status)}</td>"
            f"<td><a href='{_e(b.get('optout_url'))}'>opt out</a>{search_link}</td>"
            f"</tr>"
        )
    out.append("</table>")
    if s.get("listed"):
        out.append(f"<p><b>{s['listed']}</b> confirmed listing(s) found. ")
    else:
        out.append("<p class='dim'>")
    out.append(
        f"California residents can remove data from 500+ registered brokers with "
        f"one free request via the state DROP portal: "
        f"<a href='{_e(brokers.get('drop_portal'))}'>"
        f"{_e(brokers.get('drop_portal'))}</a>.</p>"
    )
    return "".join(out)


def render_dossier(inv: dict, summary: dict, *,
                   timeline: list | None = None,
                   connections: list | None = None) -> str:
    """inv: investigations row dict {id, created_at}; summary: stored JSON.

    ``timeline`` and ``connections`` are optional pre-computed analysis blocks
    (from :mod:`recon.timeline` and :mod:`recon.connections`); when supplied
    they render as extra sections. Omitting them keeps the classic report.
    """
    from recon.graph import build_graph

    params = summary.get("params") or {}
    accounts = summary.get("accounts") or []
    variants = summary.get("variants") or []
    name_rows = summary.get("name_accounts") or []
    email_state = summary.get("email") or {}
    phone = summary.get("phone") or {}
    domain = summary.get("domain") or {}
    candidates = summary.get("candidates") or []

    score = footprint_score(summary)
    graph = build_graph(summary)
    generated = time.strftime("%Y-%m-%d %H:%M:%S")

    subject_bits = [params.get("name") or ""] + (params.get("usernames") or []) \
        + [params.get("email") or "", params.get("phone") or ""]
    subject = " · ".join(b for b in subject_bits if b)

    p: list[str] = []
    p.append(
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>Dossier #{_e(inv.get('id'))} — {_e(subject)}</title>"
        f"<style>{_CSS}</style></head><body>"
    )

    # -- cover ---------------------------------------------------------------
    p.append("<div class='cover'>")
    p.append("<div class='conf'>CONFIDENTIAL — OSINT ASSESSMENT</div>")
    p.append("<h1>Identity Investigation Dossier</h1>")
    p.append(f"<div class='subj'>{_e(subject)}</div>")
    p.append("<table>")
    p.append(f"<tr><td>Investigation</td><td>#{_e(inv.get('id'))}</td></tr>")
    p.append(f"<tr><td>Opened</td><td>{_e(inv.get('created_at'))}</td></tr>")
    p.append(f"<tr><td>Report generated</td><td>{_e(generated)}</td></tr>")
    inputs_desc = []
    for k in ("name", "usernames", "email", "phone"):
        v = params.get(k)
        if v:
            inputs_desc.append(
                f"<tr><td>{_e(k.capitalize())}</td>"
                f"<td>{_e(', '.join(v) if isinstance(v, list) else v)}</td></tr>"
            )
    p.append("".join(inputs_desc))
    p.append("</table></div>")

    # -- executive summary -----------------------------------------------------
    p.append("<h2>Executive summary</h2>")
    p.append(f"<p>{_e(_exec_summary(inv, summary, score))}</p>")

    # -- footprint score -------------------------------------------------------
    p.append("<h2>Digital-footprint score</h2>")
    p.append(
        f"<div class='score-band'><div class='score-num'>{score['score']}"
        f"<small>/100</small></div><div class='score-detail'>"
        + "<br>".join(f"{_e(k)}: <b>{v}</b>" for k, v in score["parts"].items())
        + "</div></div>"
    )
    p.append(
        "<p class='dim'>Heuristic: 4 pts per account (cap 40), 5 pts per email "
        "registration (cap 25), 10 for a Gravatar profile, 2 per enriched "
        "profile (cap 15), 10 for a valid phone number. Higher = larger public "
        "footprint.</p>"
    )

    # -- exposure profile ------------------------------------------------------
    p.append(_exposure_section(summary))

    # -- timeline (optional) ---------------------------------------------------
    if timeline:
        p.append(_timeline_section(timeline))

    # -- cross-case connections (optional) -------------------------------------
    if connections:
        p.append(_connections_section(connections))

    # -- identity graph data -----------------------------------------------------
    p.append(f"<h2>Identity graph ({len(graph['nodes'])} nodes, "
             f"{len(graph['edges'])} edges)</h2>")
    p.append(
        "<table class='data'><tr><th>From</th><th>To</th><th>Conf.</th>"
        "<th>Rationale</th></tr>"
    )
    node_label = {n["id"]: n.get("label") for n in graph["nodes"]}
    for e in graph["edges"]:
        p.append(
            f"<tr><td>{_e(node_label.get(e['source'], e['source']))}</td>"
            f"<td>{_e(node_label.get(e['target'], e['target']))}</td>"
            f"<td>{e['confidence']}%</td><td>{_e(e['rationale'])}</td></tr>"
        )
    p.append("</table>")

    # -- confirmed accounts ------------------------------------------------------
    p.append(f"<h2>Confirmed accounts ({len(accounts)})</h2>")
    if accounts:
        p.append("<table class='data'>" + _ACCT_HEADER)
        p.append(_account_rows(accounts))
        p.append("</table>")
    else:
        p.append("<p class='dim'>No accounts found for the supplied usernames.</p>")

    if variants:
        p.append(f"<h2>Username-variant matches ({len(variants)})</h2>")
        p.append("<table class='data'>" + _ACCT_HEADER)
        p.append(_account_rows(variants))
        p.append("</table>")

    # -- name-candidate matches ----------------------------------------------------
    if params.get("name"):
        p.append(f"<h2>Name-candidate matches ({len(name_rows)})</h2>")
        p.append(
            f"<p class='dim'>{len(candidates)} candidate handles generated from "
            f"\u201c{_e(params['name'])}\u201d: "
            + _e(", ".join(candidates)) + "</p>"
        )
        if name_rows:
            p.append("<table class='data'>" + _ACCT_HEADER)
            p.append(_account_rows(name_rows))
            p.append("</table>")
        else:
            p.append("<p class='dim'>No candidate handles were claimed on the "
                     "high-value sites checked.</p>")

    # -- email pivot ---------------------------------------------------------------
    if params.get("email"):
        p.append("<h2>Email pivot</h2>")
        grav = email_state.get("gravatar")
        if grav:
            p.append("<ul class='tight'>")
            p.append(f"<li>Gravatar: <b>{_e(grav.get('display_name') or grav.get('full_name') or 'profile found')}</b>"
                     f" — <a href='{_e(grav.get('profile_url'))}'>{_e(grav.get('profile_url'))}</a></li>")
            if grav.get("about"):
                p.append(f"<li class='dim'>{_e(grav['about'][:300])}</li>")
            for a in grav.get("accounts") or []:
                if a.get("url"):
                    p.append(f"<li>linked: <a href='{_e(a['url'])}'>{_e(a.get('name') or a.get('domain'))}</a></li>")
            p.append("</ul>")
        else:
            p.append("<p class='dim'>No public Gravatar profile.</p>")
        holehe = email_state.get("holehe") or []
        hits = [h for h in holehe if h.get("exists")]
        p.append(f"<p>Registered-account checks: <b>{len(hits)} positive</b> "
                 f"/ {len(holehe)} sites checked.</p>")
        if hits:
            p.append("<table class='data'><tr><th>Service</th><th>Domain</th></tr>")
            for h in hits:
                p.append(f"<tr><td><b>{_e(h.get('site'))}</b></td>"
                         f"<td>{_e(h.get('domain'))}</td></tr>")
            p.append("</table>")

    # -- phone intel -----------------------------------------------------------------
    if phone:
        p.append("<h2>Phone intelligence</h2>")
        p.append("<table class='data'>")
        for label, key in [("Input", "input"), ("E.164", "e164"),
                           ("Valid", "valid"), ("Country", "country"),
                           ("Region", "region"), ("Location", "location"),
                           ("Carrier", "carrier"), ("Line type", "line_type")]:
            p.append(f"<tr><td>{label}</td><td>{_e(phone.get(key))}</td></tr>")
        p.append(f"<tr><td>Timezones</td><td>{_e(', '.join(phone.get('timezones') or []))}</td></tr>")
        p.append("</table>")
        if phone.get("note"):
            p.append(f"<div class='notebox'>{_e(phone['note'])}</div>")

    # -- domain / infrastructure ------------------------------------------------------
    if domain and domain.get("domain") and not domain.get("error"):
        rdap = domain.get("rdap") or {}
        dns = domain.get("dns") or {}
        subs = domain.get("subdomains") or []
        p.append(f"<h2>Domain intelligence — {_e(domain['domain'])}</h2>")
        p.append("<table class='data'>")
        for label, val in [
            ("Registrar", rdap.get("registrar")),
            ("Registered", rdap.get("registered")),
            ("Expires", rdap.get("expires")),
            ("Nameservers", ", ".join(rdap.get("nameservers")
                                      or dns.get("NS") or [])),
            ("A records", ", ".join(dns.get("A") or [])),
            ("AAAA records", ", ".join(dns.get("AAAA") or [])),
            ("MX", ", ".join(dns.get("MX") or [])),
        ]:
            if val:
                p.append(f"<tr><td>{label}</td><td>{_e(val)}</td></tr>")
        p.append("</table>")
        if dns.get("TXT"):
            p.append("<p class='dim' style='margin-top:6px'>TXT: "
                     + "; ".join(_e(t) for t in dns["TXT"][:10]) + "</p>")
        if subs:
            p.append(f"<h2 style='border:none;text-transform:none;font-size:12px;"
                     f"margin:12px 0 4px'>Subdomains ({len(subs)}, via CT logs)</h2>")
            p.append("<p class='dim'>" + _e(", ".join(subs[:60]))
                     + ("…" if len(subs) > 60 else "") + "</p>")

    # -- data-broker exposure --------------------------------------------------------
    brokers = summary.get("brokers") or {}
    if brokers and brokers.get("brokers"):
        p.append(_broker_section(brokers))

    # -- methodology / limitations -----------------------------------------------------
    p.append("<h2>Methodology</h2>")
    p.append(
        "<ul class='tight'>"
        "<li>Username discovery: Sherlock and Maigret engines against public "
        "profile URLs; results merged and de-duplicated by site.</li>"
        "<li>Name expansion: up to 24 ranked candidate handles (including "
        "nickname forms, e.g. Robert &rarr; bob/rob) generated from the "
        "supplied name and checked against a curated high-value site list.</li>"
        "<li>Email pivot: public Gravatar profile API and registration checks "
        "against public sign-up/password-reset endpoints (holehe).</li>"
        "<li>Phone intelligence: offline parsing (phonenumbers) — validity, "
        "region, carrier, line type, timezones. No messaging-app presence "
        "checks are performed.</li>"
        "<li>Domain intelligence: DNS records over DNS-over-HTTPS, registration "
        "data via RDAP, and subdomains from public Certificate Transparency "
        "logs (crt.sh). Public data, no API keys.</li>"
        "<li>Enrichment: public profile pages only (title, Open Graph, "
        "JSON-LD Person fields).</li>"
        "<li>Data-broker exposure: a curated map of people-search sites and "
        "data brokers with direct opt-out links; best-effort presence checks on "
        "the minority with predictable search URLs (WAF/CAPTCHA responses are "
        "reported as &lsquo;blocked&rsquo;, never a false &lsquo;not found&rsquo;).</li>"
        "<li>Verification: each fetched profile is cross-checked for the "
        "scanned handle; a &lsquo;verified&rsquo; chip means the handle appears "
        "on the page, &lsquo;likely false&rsquo; means the page reads like a "
        "soft-404 served with a 200.</li>"
        "<li>Account confidence (per-account %): engine agreement, enrichment, "
        "verification, and how the handle was derived, combined into 0-100.</li>"
        "<li>Correlation: heuristic avatar-hash, display-name and bio-overlap "
        "signals combined into a 0-100 confidence score.</li>"
        "</ul>"
    )
    p.append("<h2>Limitations</h2>")
    p.append(
        "<ul class='tight'>"
        "<li>Username reuse across platforms does not prove common ownership; "
        "correlation confidence is advisory.</li>"
        "<li>Checks observe public data at scan time only; private or "
        "rate-limited platforms may be missed or misreported.</li>"
        "<li>Registration checks indicate an account exists for the email; "
        "they do not prove the subject controls it.</li>"
        "</ul>"
    )
    p.append(
        "<footer>Generated by sherlock-web v3 · public data only · "
        "Responsible use: this report must comply with applicable law and "
        "platform terms. Do not use for stalking, harassment, or decisions "
        "about employment, credit, housing or insurance.</footer></body></html>"
    )
    return "".join(p)
