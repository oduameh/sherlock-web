"""Username permutation generation.

Given a base username, produce a bounded set of plausible variants people
commonly use across platforms. Pure functions, no dependencies.
"""

import re

MAX_VARIANTS = 24

# Word-part separators people swap between platforms.
_SEPARATORS = [".", "_", "-"]

# Common affixes seen on secondary/brand accounts.
_PREFIXES = ["the", "real", "its", "im"]
_SUFFIXES = ["1", "01", "123", "_official", "tv", "hq"]


def _alpha_parts(username: str) -> list[str]:
    """Split a username into its alphabetic word parts (len >= 2 each)."""
    return [p for p in re.split(r"[^a-zA-Z]+", username) if len(p) >= 2]


def _vowel_strip(name: str) -> str:
    stripped = re.sub(r"[aeiouAEIOU]", "", name)
    # Only keep it if something actually remains and it's meaningfully shorter.
    return stripped if len(stripped) >= 3 and stripped != name else ""


def generate_variants(base: str, limit: int = MAX_VARIANTS) -> list[str]:
    """Return up to ``limit`` deduped variants of ``base`` (never the original).

    Order is roughly most-plausible first: separator swaps, reversed order,
    vowel-stripped, then affixes.
    """
    base = base.strip()
    if not base:
        return []

    variants: list[str] = []
    seen = {base.lower()}

    def add(v: str) -> None:
        v = v.strip()
        if v and v.lower() not in seen:
            seen.add(v.lower())
            variants.append(v)

    parts = _alpha_parts(base)

    # Separator variants: join word parts with each common separator.
    if len(parts) >= 2:
        for sep in _SEPARATORS:
            joined = sep.join(parts)
            if joined != base:
                add(joined)
        # Reversed word order for two-part names (smith.john style).
        if len(parts) == 2:
            rev = list(reversed(parts))
            for sep in _SEPARATORS:
                add(sep.join(rev))

    # Vowel-stripped variant of the concatenated alpha parts.
    if parts:
        vs = _vowel_strip("".join(parts))
        if vs:
            add(vs)

    # Affixes on the base username.
    for p in _PREFIXES:
        add(p + base)
    for s in _SUFFIXES:
        add(base + s)

    return variants[:limit]
