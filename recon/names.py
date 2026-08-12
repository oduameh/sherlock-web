"""Full-name -> username candidate generation.

Given a person's full name (2-4 words), produce a bounded, ranked list of
plausible handle candidates people commonly register. Pure functions, no
dependencies, ASCII-only lowercase output (transliteration-safe: accents are
stripped via NFKD, anything non [a-z] becomes a separator or is dropped).

Ranking is by commonness: plain ``firstlast`` first, separated forms next,
initial-based forms after, then nickname-based forms (Robert -> bob/rob, ...)
and finally digit-suffixed forms (only the common 1/01/123). Birth-year style
digits are deliberately NOT generated — too speculative.
"""

from __future__ import annotations

import re
import unicodedata

MAX_CANDIDATES = 24

_DIGIT_SUFFIXES = ["1", "01", "123"]

# Common English given-name -> nickname expansions. People very often register
# handles under a diminutive rather than their formal first name, so expanding
# these materially raises the hit rate on name-based investigations. Kept to
# high-confidence, widely-used forms only (noise here costs scan time).
_NICKNAMES: dict[str, list[str]] = {
    "abigail": ["abby"], "alexander": ["alex", "xander"],
    "alexandra": ["alex", "lexi", "sasha"], "andrew": ["andy", "drew"],
    "anthony": ["tony"], "benjamin": ["ben", "benny"],
    "catherine": ["cathy", "kate", "cat"], "charles": ["charlie", "chuck"],
    "christina": ["tina"], "christine": ["chris", "chrissy"],
    "christopher": ["chris", "topher"], "cynthia": ["cindy"],
    "daniel": ["dan", "danny"], "david": ["dave", "davey"],
    "deborah": ["deb", "debbie"], "edward": ["ed", "eddie", "ted"],
    "elizabeth": ["liz", "beth", "eliza", "lizzie", "betty"],
    "frederick": ["fred", "freddie"], "gregory": ["greg"],
    "isabella": ["bella", "izzy"], "jacob": ["jake"],
    "james": ["jim", "jamie", "jimmy"], "jennifer": ["jen", "jenny"],
    "jessica": ["jess", "jessie"], "john": ["jon", "johnny", "jack"],
    "jonathan": ["jon", "jonny"], "joseph": ["joe", "joey"],
    "joshua": ["josh"], "katherine": ["kate", "katie", "kathy", "kat"],
    "kenneth": ["ken", "kenny"], "kimberly": ["kim"],
    "lawrence": ["larry"], "margaret": ["maggie", "meg", "peggy"],
    "matthew": ["matt"], "michael": ["mike", "mikey"],
    "nicholas": ["nick", "nico"], "pamela": ["pam"],
    "patricia": ["pat", "patty", "trish"], "patrick": ["pat", "paddy"],
    "peter": ["pete"], "rebecca": ["becca", "becky"],
    "richard": ["rick", "rich", "richie"], "robert": ["rob", "bob", "bobby"],
    "ronald": ["ron", "ronnie"], "samantha": ["sam", "sammy"],
    "samuel": ["sam", "sammy"], "stephanie": ["steph"],
    "stephen": ["steve"], "steven": ["steve"], "susan": ["sue", "suzie"],
    "theodore": ["theo", "ted", "teddy"], "thomas": ["tom", "tommy"],
    "timothy": ["tim", "timmy"], "victoria": ["vicky", "tori"],
    "vincent": ["vince"], "william": ["will", "bill", "billy", "liam"],
    "zachary": ["zach", "zack"],
}

# Cap how many nicknames we expand per name so a name like "Elizabeth" doesn't
# crowd out every other pattern within the candidate budget.
_MAX_NICKNAMES = 4


def _ascii_words(name: str) -> list[str]:
    """Normalize a full name to lowercase ASCII word parts."""
    name = unicodedata.normalize("NFKD", name)
    name = name.encode("ascii", "ignore").decode("ascii")
    return [w for w in re.split(r"[^a-zA-Z]+", name.lower()) if w]


def generate_name_candidates(full_name: str,
                             limit: int = MAX_CANDIDATES) -> list[str]:
    """Return up to ``limit`` ranked handle candidates for a full name.

    Accepts 2-4 word names; returns [] for anything else. Candidates are
    lowercase ASCII, >= 3 chars, deduped, most-common patterns first.
    """
    words = _ascii_words(full_name or "")
    if not 2 <= len(words) <= 4:
        return []

    first, last = words[0], words[-1]
    middles = words[1:-1]
    fi = first[0]
    li = last[0]

    candidates: list[str] = []
    seen: set[str] = set()

    def add(v: str) -> None:
        v = re.sub(r"[^a-z0-9._-]", "", v).strip("._-")
        if len(v) >= 3 and v not in seen:
            seen.add(v)
            candidates.append(v)

    # Most common patterns first.
    add(first + last)                     # johnsmith
    add(first + "." + last)               # john.smith
    add(first + "_" + last)               # john_smith
    add(fi + last)                        # jsmith
    add(first + li)                       # johns
    add(fi + "." + last)                  # j.smith
    add(last + first)                     # smithjohn
    add(last + fi)                        # smithj
    add(first + "-" + last)               # john-smith

    # Middle-name-aware variants (3-4 word names).
    if middles:
        mi = "".join(m[0] for m in middles)
        add(first + middles[0] + last)    # johnqsmith
        add(fi + mi + last)               # jqsmith
        add(first + mi + last)            # johnqsmith (initial form)

    # Nickname-based forms (robert smith -> bobsmith, bob.smith, ...). Ranked
    # above digit suffixes because a diminutive handle is far more likely than
    # "firstlast123".
    for nick in _NICKNAMES.get(first, [])[:_MAX_NICKNAMES]:
        add(nick + last)                  # bobsmith
        add(nick + "." + last)            # bob.smith
        add(nick + "_" + last)            # bob_smith

    # Common digit suffixes on the two most common bases (no birth years).
    for suffix in _DIGIT_SUFFIXES:
        add(first + last + suffix)
    for suffix in _DIGIT_SUFFIXES:
        add(fi + last + suffix)

    return candidates[:limit]
