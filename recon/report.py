"""Self-contained HTML report rendering for recon runs.

Dark theme matching the app. No external assets: avatars are embedded as
small ``data:`` thumbnails the server produced from bytes fetched through the
avatar proxy path (V11), never as a link to the subject's host — a saved file
opened later must not contact it. All dynamic values are HTML-escaped.
"""

from __future__ import annotations

import html
import re
from typing import Any

from recon.rows import avatar, bio, display_name
from recon.thumbnail import is_thumbnail_uri


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


_HTTP_SCHEME = re.compile(r"^https?://", re.IGNORECASE)


def _href(v: Any) -> str:
    """Escaped URL for an ``href``; ``""`` unless the scheme is http(s).

    ``html.escape`` neutralises quotes, not ``javascript:`` — a profile field a
    subject controls (Gravatar, adapter metadata) must never become a
    navigable link in the analyst's browser.
    """
    s = "" if v is None else str(v).strip()
    return html.escape(s) if _HTTP_SCHEME.match(s) else ""


_CSS = """
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#1c2330;--border:#2d333b;--text:#e6edf3;
--dim:#8b949e;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--amber:#d29922}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,
"Segoe UI",Roboto,Helvetica,Arial,sans-serif;padding:32px 20px;max-width:1000px;margin:0 auto}
h1{font-size:22px;margin-bottom:4px}
h1 .m{color:var(--accent)}
.sub{color:var(--dim);font-size:13px;margin-bottom:28px}
h2{font-size:16px;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--dim);text-transform:uppercase;font-size:11px;letter-spacing:.5px;
text-align:left;padding:6px 10px;border-bottom:1px solid var(--border)}
td{padding:8px 10px;border-bottom:1px solid rgba(45,51,59,.5);vertical-align:top}
a{color:var(--accent);text-decoration:none;word-break:break-all}
a:hover{text-decoration:underline}
.badge{display:inline-block;font-size:10.5px;font-weight:600;border-radius:10px;
padding:1px 7px;margin-right:4px;border:1px solid}
.badge.sherlock{color:var(--accent);border-color:rgba(88,166,255,.4)}
.badge.maigret{color:#bc8cff;border-color:rgba(188,140,255,.4)}
.badge.variant{color:var(--amber);border-color:rgba(210,153,34,.4)}
.badge.vok{color:var(--green);border-color:rgba(63,185,80,.5)}
.badge.vno{color:var(--red);border-color:rgba(248,81,73,.5)}
.conf-track{background:var(--bg3);border-radius:5px;height:8px;width:140px;overflow:hidden;display:inline-block;vertical-align:middle}
.conf-fill{background:linear-gradient(90deg,var(--green),#79c0ff);height:100%}
.dim{color:var(--dim);font-size:12px}
.avatar{width:28px;height:28px;border-radius:50%;object-fit:cover;vertical-align:middle;margin-right:6px;background:var(--bg3)}
footer{margin-top:40px;color:var(--dim);font-size:12px;text-align:center}
"""


def _engine_badges(engines: list[str]) -> str:
    return "".join(
        f'<span class="badge {_e(e)}">{_e(e)}</span>' for e in engines
    )


def _verify_badge(row: dict) -> str:
    status = (row.get("verification") or {}).get("status")
    if status == "confirmed":
        return '<span class="badge vok">verified</span>'
    if status == "likely_false_positive":
        return '<span class="badge vno">likely false</span>'
    return ""


def _avatar_img(url: Any, avatars: dict[str, str] | None) -> str:
    """An ``<img>`` for the server-made thumbnail of ``url`` (a subject-
    controlled avatar URL), or ``""``. Only a data URI produced by
    :mod:`recon.thumbnail` is ever placed in ``src``: the remote URL itself
    would make the saved report fetch from the subject's host (V11), and a
    hostile scheme is dropped, not escaped (F-6)."""
    uri = (avatars or {}).get(url) if isinstance(url, str) else None
    if not is_thumbnail_uri(uri):
        return ""
    return f'<img class="avatar" src="{uri}" alt="">'


def _enrichment_cell(row: dict, avatars: dict[str, str] | None = None) -> str:
    """Avatar, name and bio through :mod:`recon.rows` — the raw page
    ``<title>`` is never shown as the person's name (D7)."""
    bits = []
    img = _avatar_img(avatar(row), avatars)
    if img:
        bits.append(img)
    name = display_name(row)
    if name:
        bits.append(f"<b>{_e(name)}</b>")
    desc = bio(row)
    if desc:
        snippet = desc if len(desc) <= 160 else desc[:157] + "..."
        bits.append(f'<div class="dim">{_e(snippet)}</div>')
    return " ".join(bits) if bits else '<span class="dim">—</span>'


def render_report(run: dict, *, avatars: dict[str, str] | None = None) -> str:
    """run: the stored recon run dict (subject, ts, params, results...)."""
    subject = _e(run.get("subject", ""))
    ts = _e(run.get("ts", ""))
    params = run.get("params") or {}
    results = run.get("results") or {}
    accounts = results.get("accounts") or []
    variants = results.get("variants") or []
    email = results.get("email") or {}
    clusters = results.get("correlation") or []

    parts: list[str] = []
    parts.append(
        f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>Recon report — {subject}</title><style>{_CSS}</style></head><body>"
    )
    parts.append(f"<h1><span class='m'>&#9906;</span> Recon report: {subject}</h1>")
    p_desc = []
    if params.get("usernames"):
        p_desc.append("usernames: " + _e(", ".join(params["usernames"])))
    if params.get("email"):
        p_desc.append("email: " + _e(params["email"]))
    if params.get("variants"):
        p_desc.append("variant scanning enabled")
    parts.append(
        f"<div class='sub'>Generated {_e(run.get('generated_at', ts))} · run at {ts} · "
        + " · ".join(p_desc)
        + "</div>"
    )

    # -- accounts -------------------------------------------------------
    parts.append(f"<h2>Accounts found ({len(accounts)})</h2>")
    if accounts:
        parts.append(
            "<div class='card'><table><tr><th>Site</th><th>Profile</th>"
            "<th>Engines</th><th>Enrichment</th></tr>"
        )
        for r in accounts:
            parts.append(
                f"<tr><td><b>{_e(r.get('site'))}</b></td>"
                f"<td><a href='{_href(r.get('url'))}'>{_e(r.get('url'))}</a>"
                f"<div class='dim'>username: {_e(r.get('username'))} "
                f"{_verify_badge(r)}</div></td>"
                f"<td>{_engine_badges(r.get('engines') or [])}</td>"
                f"<td>{_enrichment_cell(r, avatars)}</td></tr>"
            )
        parts.append("</table></div>")
    else:
        parts.append("<div class='card dim'>No accounts found.</div>")

    # -- variants -------------------------------------------------------
    if variants:
        parts.append(f"<h2>Username variant matches ({len(variants)})</h2>")
        parts.append(
            "<div class='card'><table><tr><th>Variant</th><th>Site</th>"
            "<th>Profile</th><th>Engines</th></tr>"
        )
        for r in variants:
            parts.append(
                f"<tr><td><span class='badge variant'>variant</span> {_e(r.get('username'))}"
                f"<div class='dim'>of {_e(r.get('variant_of'))}</div></td>"
                f"<td><b>{_e(r.get('site'))}</b></td>"
                f"<td><a href='{_href(r.get('url'))}'>{_e(r.get('url'))}</a></td>"
                f"<td>{_engine_badges(r.get('engines') or [])}</td></tr>"
            )
        parts.append("</table></div>")

    # -- email pivot ----------------------------------------------------
    if email:
        parts.append("<h2>Email pivot</h2>")
        grav = email.get("gravatar")
        parts.append("<div class='card'>")
        if grav:
            av = _avatar_img(grav.get("avatar_url"), avatars)
            if av:
                parts.append(av)
            parts.append(
                f"<b>{_e(grav.get('display_name') or grav.get('full_name') or 'Gravatar profile')}</b> "
                f"<a href='{_href(grav.get('profile_url'))}'>{_e(grav.get('profile_url'))}</a>"
            )
            if grav.get("about"):
                parts.append(f"<div class='dim'>{_e(grav['about'][:300])}</div>")
            accts = grav.get("accounts") or []
            if accts:
                parts.append("<div class='dim' style='margin-top:6px'>Linked accounts: "
                             + ", ".join(
                                 f"<a href='{_href(a.get('url'))}'>{_e(a.get('name') or a.get('domain'))}</a>"
                                 for a in accts
                             ) + "</div>")
        else:
            parts.append("<span class='dim'>No public Gravatar profile for this email.</span>")
        parts.append("</div>")

        holehe = email.get("holehe") or []
        hits = [h for h in holehe if h.get("exists")]
        parts.append(
            f"<div class='card'><b>Registered-account checks:</b> "
            f"{len(hits)} positive / {len(holehe)} sites checked</div>"
        )
        if hits:
            parts.append("<div class='card'><table><tr><th>Site</th><th>Domain</th></tr>")
            for h in hits:
                parts.append(f"<tr><td><b>{_e(h.get('site'))}</b></td><td>{_e(h.get('domain'))}</td></tr>")
            parts.append("</table></div>")

    # -- correlation ----------------------------------------------------
    parts.append(f"<h2>Correlation clusters ({len(clusters)})</h2>")
    if clusters:
        for c in clusters:
            conf = int(c.get("confidence", 0))
            parts.append("<div class='card'>")
            parts.append(
                f"<div><span class='conf-track'><span class='conf-fill' "
                f"style='width:{conf}%'></span></span> <b>{conf}%</b> confidence</div>"
            )
            parts.append("<ul style='margin:8px 0 8px 18px'>")
            for m in c.get("members", []):
                parts.append(
                    f"<li><b>{_e(m.get('site'))}</b> — "
                    f"<a href='{_href(m.get('url'))}'>{_e(m.get('url'))}</a></li>"
                )
            parts.append("</ul>")
            for l in c.get("links", []):
                parts.append(f"<div class='dim'>&#8596; {_e(l.get('rationale'))}</div>")
            parts.append("</div>")
    else:
        parts.append("<div class='card dim'>No cross-account correlations found.</div>")

    parts.append(
        "<footer>sherlock-web recon · public data only · heuristic correlation — "
        "verify manually before drawing conclusions</footer></body></html>"
    )
    return "".join(parts)
