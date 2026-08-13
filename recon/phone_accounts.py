"""Phone account-existence pivot: which platforms is a number registered on.

The phone analogue of the holehe email pivot (:mod:`recon.email_pivot`). It
drives `ignorant <https://github.com/megadose/ignorant>`_ (same author as
holehe) against public register / password-reset endpoints to infer whether a
phone number is used on sites like Instagram, Amazon, and Snapchat — without
notifying the number's owner.

Same posture as holehe: probabilistic, rate-sensitive, and gray-area, so checks
run **sequentially** with a delay and a per-module timeout, all through the
SSRF-guarded :mod:`recon.safeweb` client. ``ignorant`` is imported lazily and is
entirely optional; if it is missing (or upstream changes shape), the scan
degrades to an "unavailable" result and never raises. phonenumbers is used to
split an E.164 number into the national number + country code the ignorant
modules expect (``await module(phone, country_code, client, out)``).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Optional

from recon import safeweb

logger = logging.getLogger("recon.phone_accounts")

# Rate-sensitivity knobs — mirror the holehe pivot.
IGNORANT_DELAY_S = 0.5
IGNORANT_MODULE_TIMEOUT_S = 15


def ignorant_available() -> bool:
    try:
        import ignorant  # noqa: F401
        return True
    except Exception:
        return False


def _ignorant_functions() -> list:
    """All ignorant check functions (lazy import; raises if unavailable).

    Primary path mirrors holehe's dynamic module discovery. If ignorant's
    internals differ, fall back to importing the documented modules explicitly.
    """
    try:
        from ignorant.core import get_functions, import_submodules
        modules = import_submodules("ignorant.modules")
        funcs = get_functions(modules)
        if funcs:
            return funcs
    except Exception:
        logger.debug("ignorant dynamic discovery failed; trying explicit import")
    # Explicit fallback for the documented sites.
    funcs = []
    for path, attr in (
        ("ignorant.modules.shopping.amazon", "amazon"),
        ("ignorant.modules.social_media.instagram", "instagram"),
        ("ignorant.modules.social_media.snapchat", "snapchat"),
    ):
        try:
            mod = __import__(path, fromlist=[attr])
            funcs.append(getattr(mod, attr))
        except Exception:
            continue
    return funcs


def _split_e164(phone_e164: str) -> Optional[tuple[str, str]]:
    """(national_significant_number, country_code_str) from an E.164 string, or
    None if it can't be parsed. ignorant modules want these two pieces."""
    try:
        import phonenumbers
    except Exception:
        return None
    try:
        num = phonenumbers.parse(phone_e164, None)
    except Exception:
        return None
    nsn = phonenumbers.national_significant_number(num)
    return nsn, str(num.country_code)


async def ignorant_scan(phone_e164: str, on_result: Callable[[dict], None],
                        only: Optional[set[str]] = None,
                        delay: float = IGNORANT_DELAY_S) -> list[dict]:
    """Run ignorant modules sequentially (rate-friendly), streaming results.

    Each result dict: ``{site, domain, exists, rate_limit, method?, error?}``.
    Calls ``on_result`` per completed module. Never raises. ``only`` (a set of
    normalized site names) restricts the run to a subset. Mirrors
    :func:`recon.email_pivot.holehe_scan`.
    """
    results: list[dict] = []
    split = _split_e164(phone_e164)
    if split is None:
        on_result({"site": "ignorant", "error": "unparseable phone number"})
        return results
    national, country_code = split

    try:
        functions = _ignorant_functions()
    except Exception:
        logger.exception("ignorant import failed")
        functions = []
    if not functions:
        on_result({"site": "ignorant", "error": "ignorant unavailable"})
        return results
    if only is not None:
        functions = [fn for fn in functions if fn.__name__.lower() in only]

    async with safeweb.async_client(timeout=IGNORANT_MODULE_TIMEOUT_S) as client:
        for fn in functions:
            site = fn.__name__
            out: list = []
            entry: dict
            try:
                # ignorant modules: await fn(phone, country_code, client, out)
                await asyncio.wait_for(
                    fn(national, country_code, client, out),
                    timeout=IGNORANT_MODULE_TIMEOUT_S,
                )
                if out:
                    r = out[0]
                    entry = {
                        "site": r.get("name", site),
                        "domain": r.get("domain"),
                        "exists": bool(r.get("exists")),
                        "rate_limit": bool(r.get("rateLimit")),
                        "method": r.get("method"),
                    }
                else:
                    entry = {"site": site, "exists": False, "rate_limit": False}
            except Exception as exc:
                entry = {
                    "site": site,
                    "exists": None,
                    "error": f"{type(exc).__name__}",
                }
            results.append(entry)
            try:
                on_result(entry)
            except Exception:
                logger.exception("ignorant on_result callback failed")
            await asyncio.sleep(delay)
    return results
