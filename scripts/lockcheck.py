#!/usr/bin/env python3
"""Refuse to drift: every requirement the repository declares must appear in
the hash-pinned locks, and every exact pin (``==``) must match.

    python scripts/lockcheck.py            # exit 1 with a list of problems

``pip-compile`` has no offline "is the lock current?" mode and a networked
``--dry-run`` would chase the newest release of every ``>=`` requirement, so
this checks the two things that can silently go wrong: a package added to a
``requirements*.txt`` that no lock knows (CI would then install it unpinned
and unhashed — pip refuses under ``--require-hashes``, but only at CI time),
and a bumped exact pin the lock still holds at the old version.

Pure functions; tested in ``tests/test_lockcheck.py``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (requirements files) -> lock that must cover them
LOCKS = {
    "requirements.lock": ("requirements.txt",),
    "requirements-ci.lock": ("requirements.txt", "requirements-dev.txt",
                             "requirements-stealth.txt"),
}

_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(==\s*([^\s;#]+))?")
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)")


def canonical(name: str) -> str:
    """PEP 503 normalisation: case-insensitive, ``-``/``_``/``.`` are one."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> dict[str, str | None]:
    """``{canonical name: exact version or None}`` for each requirement line.
    ``-r``/``-c`` includes, comments, blank lines and options are ignored."""
    out: dict[str, str | None] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ.match(line)
        if not m:
            continue
        out[canonical(m.group(1))] = m.group(4)
    return out


def parse_lock(text: str) -> dict[str, str]:
    """``{canonical name: version}`` for each ``name==version`` line."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        m = _PIN.match(raw.strip())
        if m:
            out[canonical(m.group(1))] = m.group(2)
    return out


def drift(requirements: dict[str, str | None], lock: dict[str, str],
          *, lock_name: str = "lock") -> list[str]:
    """Human-readable problems, empty when the lock covers the requirements."""
    problems = []
    for name, pin in sorted(requirements.items()):
        if name not in lock:
            problems.append(f"{lock_name}: {name} is required but not locked")
        elif pin is not None and lock[name] != pin:
            problems.append(f"{lock_name}: {name} is pinned to {pin} but locked at {lock[name]}")
    return problems


def check(root: Path = ROOT) -> list[str]:
    problems = []
    for lock_name, req_names in LOCKS.items():
        lock_path = root / lock_name
        if not lock_path.is_file():
            problems.append(f"{lock_name}: missing")
            continue
        lock = parse_lock(lock_path.read_text())
        for req_name in req_names:
            req_path = root / req_name
            if not req_path.is_file():
                problems.append(f"{req_name}: missing")
                continue
            problems += drift(parse_requirements(req_path.read_text()), lock,
                              lock_name=lock_name)
    return problems


def main() -> int:
    problems = check()
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        print("lockcheck: regenerate the locks (see README → Development & tests)",
              file=sys.stderr)
        return 1
    print("lockcheck: locks cover requirements*.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
