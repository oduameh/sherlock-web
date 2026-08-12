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


def footprint_score(summary: dict) -> dict:
    """Digital-footprint score 0-100. Documented heuristic:

      accounts found        4 pts each, capped at 40
      email registrations   5 pts each, capped at 25  (holehe positives)
      gravatar profile      10 pts flat
      enriched profiles     2 pts each, capped at 15  (name/avatar extracted)
      valid phone number    10 pts flat
    """
    accounts = summary.get("accounts") or []
    variants = summary.get("variants") or []
    name_rows = summary.get("name_accounts") or []
    email = summary.get("email") or {}
    phone = summary.get("phone") or {}

    n_accts = len(accounts) + len(variants) + len(name_rows)
    holehe_hits = sum(1 for h in (email.get("holehe") or []) if h.get("exists"))
    enriched = sum(
        1 for r in accounts + variants + name_rows
        if (r.get("enrichment") or {}).get("jsonld_name")
        or (r.get("enrichment") or {}).get("og_image")
    )
    parts = {
        f"accounts found ({n_accts} × 4, cap 40)": min(40, n_accts * 4),
        f"email registrations ({holehe_hits} × 5, cap 25)": min(25, holehe_hits * 5),
        "gravatar profile present": 10 if email.get("gravatar") else 0,
        f"enriched profiles ({enriched} × 2, cap 15)": min(15, enriched * 2),
        "valid phone number": 10 if phone.get("valid") else 0,
    }
    return {"score": min(100, sum(parts.values())), "parts": parts}


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


def render_dossier(inv: dict, summary: dict) -> str:
    """inv: investigations row dict {id, created_at}; summary: stored JSON."""
    from recon.graph import build_graph

    params = summary.get("params") or {}
    accounts = summary.get("accounts") or []
    variants = summary.get("variants") or []
    name_rows = summary.get("name_accounts") or []
    email_state = summary.get("email") or {}
    phone = summary.get("phone") or {}
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
        "<li>Enrichment: public profile pages only (title, Open Graph, "
        "JSON-LD Person fields).</li>"
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
