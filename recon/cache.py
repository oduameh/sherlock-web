"""A small TTL + LRU cache for source answers — positives and *definitive*
negatives only.

Retrieval audit defect 10: the geo and breach pivots kept process-lifetime
dicts that stored ``None`` for every kind of non-answer — a Nominatim 429, a
Cavalier 5xx, a timeout — so one bad minute made "could not geocode" /
"not compromised" permanent until restart, and the timeline re-fetched GitHub
on every report open because nothing remembered the answer at all.

The rule this module enforces by *shape*: **a failure is never cached**. There
is no API for it. A caller has exactly two things to say about a key —
:meth:`TTLCache.set` (a real answer) and :meth:`TTLCache.set_absent` (the
source answered and the thing does not exist) — and both expire. A request
that failed says nothing, so the next caller asks again.

Pure and in-process. The clock is injectable so tests can expire entries
without sleeping.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any, Callable, Hashable

__all__ = ["ABSENT", "TTLCache"]


class _Absent:
    """Sentinel for a definitive negative ("the source says: no such thing")."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - repr only
        return "ABSENT"


ABSENT = _Absent()


class TTLCache:
    """LRU cache whose entries expire ``ttl_s`` seconds after they were set.

    ``get(key)`` returns ``(hit, value)``: ``(False, None)`` for a miss or an
    expired entry; ``(True, value)`` for a cached answer; ``(True, None)`` for
    a cached *definitive absence* (:meth:`set_absent`). Use :meth:`is_absent`
    when the distinction between "absent" and "a value that happens to be
    None" matters — :meth:`set` refuses ``None`` values for exactly that
    reason.

    Eviction is least-recently-used once ``maxsize`` is exceeded; a hit
    refreshes recency, expiry does not.
    """

    def __init__(self, maxsize: int = 1024, ttl_s: float = 6 * 3600.0, *,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if maxsize < 1:
            raise ValueError("maxsize must be >= 1")
        if ttl_s <= 0:
            raise ValueError("ttl_s must be > 0")
        self.maxsize = int(maxsize)
        self.ttl_s = float(ttl_s)
        self._clock = clock
        self._data: "OrderedDict[Hashable, tuple[float, Any]]" = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._sets = 0
        self._absents = 0
        self._evictions = 0
        self._expired = 0

    # -- reads ---------------------------------------------------------------

    def _lookup(self, key: Hashable) -> tuple[bool, Any]:
        entry = self._data.get(key)
        if entry is None:
            self._misses += 1
            return False, None
        expires_at, value = entry
        if self._clock() >= expires_at:
            del self._data[key]
            self._expired += 1
            self._misses += 1
            return False, None
        self._data.move_to_end(key)
        self._hits += 1
        return True, value

    def get(self, key: Hashable) -> tuple[bool, Any]:
        """``(hit, value)``; a definitive absence is ``(True, None)``."""
        hit, value = self._lookup(key)
        if hit and value is ABSENT:
            return True, None
        return hit, value

    def is_absent(self, key: Hashable) -> bool:
        """True only when ``key`` is cached as a definitive negative."""
        hit, value = self._lookup(key)
        return hit and value is ABSENT

    def __contains__(self, key: Hashable) -> bool:
        return self._lookup(key)[0]

    def __len__(self) -> int:
        return len(self._data)

    # -- writes --------------------------------------------------------------

    def _store(self, key: Hashable, value: Any) -> None:
        self._data[key] = (self._clock() + self.ttl_s, value)
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)
            self._evictions += 1

    def set(self, key: Hashable, value: Any) -> None:
        """Cache a real answer. ``None`` is refused: say :meth:`set_absent`
        for "does not exist", and say nothing at all for "the request
        failed" — there is deliberately no way to cache a failure."""
        if value is None:
            raise ValueError("None is not an answer: use set_absent() for a "
                             "definitive negative; failures are never cached")
        self._sets += 1
        self._store(key, value)

    def set_absent(self, key: Hashable) -> None:
        """Cache a definitive negative — the source answered and there is
        nothing there (a 404, an empty result set). Never for a 429, a 5xx,
        a timeout or any other non-answer."""
        self._absents += 1
        self._store(key, ABSENT)

    def invalidate(self, key: Hashable) -> bool:
        """Drop one entry. True when something was removed."""
        return self._data.pop(key, None) is not None

    def clear(self) -> None:
        self._data.clear()

    # -- introspection ---------------------------------------------------------

    def stats(self) -> dict:
        return {
            "size": len(self._data),
            "maxsize": self.maxsize,
            "ttl_s": self.ttl_s,
            "hits": self._hits,
            "misses": self._misses,
            "sets": self._sets,
            "absents": self._absents,
            "evictions": self._evictions,
            "expired": self._expired,
        }
