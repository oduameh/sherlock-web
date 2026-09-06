"""recon.cache.TTLCache — positives and definitive negatives only, with TTL
and LRU eviction. No way to cache a failure exists, by design (defect 10)."""

import pytest

from recon.cache import ABSENT, TTLCache


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_miss_then_hit():
    c = TTLCache(maxsize=4, ttl_s=60)
    assert c.get("k") == (False, None)
    c.set("k", {"v": 1})
    assert c.get("k") == (True, {"v": 1})
    assert "k" in c and len(c) == 1


def test_definitive_absence_is_a_hit_with_none():
    c = TTLCache(maxsize=4, ttl_s=60)
    c.set_absent("nobody")
    assert c.get("nobody") == (True, None)
    assert c.is_absent("nobody") is True
    assert c.is_absent("unknown") is False
    c.set("someone", "x")
    assert c.is_absent("someone") is False


def test_none_is_not_an_answer():
    """``set(key, None)`` would be the failure-caching API in disguise."""
    c = TTLCache(maxsize=4, ttl_s=60)
    with pytest.raises(ValueError):
        c.set("k", None)
    assert c.get("k") == (False, None)
    assert not hasattr(c, "set_failure") and not hasattr(c, "set_error")


def test_entries_expire_with_the_injected_clock():
    clock = Clock()
    c = TTLCache(maxsize=4, ttl_s=10, clock=clock)
    c.set("k", 1)
    c.set_absent("gone")
    clock.t += 9.9
    assert c.get("k") == (True, 1) and c.get("gone") == (True, None)
    clock.t += 0.2
    assert c.get("k") == (False, None)
    assert c.get("gone") == (False, None)      # an absence expires too
    assert c.stats()["expired"] == 2


def test_lru_eviction_and_hit_refreshes_recency():
    c = TTLCache(maxsize=2, ttl_s=60)
    c.set("a", 1)
    c.set("b", 2)
    assert c.get("a") == (True, 1)        # a is now most recent
    c.set("c", 3)                         # evicts b, the least recent
    assert c.get("b") == (False, None)
    assert c.get("a") == (True, 1) and c.get("c") == (True, 3)
    assert c.stats()["evictions"] == 1 and len(c) == 2


def test_invalidate_and_clear():
    c = TTLCache(maxsize=4, ttl_s=60)
    c.set("a", 1)
    assert c.invalidate("a") is True and c.invalidate("a") is False
    c.set("b", 2)
    c.clear()
    assert len(c) == 0 and c.get("b") == (False, None)


def test_stats_shape():
    c = TTLCache(maxsize=8, ttl_s=30)
    c.set("a", 1)
    c.set_absent("b")
    c.get("a")
    c.get("zzz")
    s = c.stats()
    assert s == {"size": 2, "maxsize": 8, "ttl_s": 30.0, "hits": 1, "misses": 1,
                 "sets": 1, "absents": 1, "evictions": 0, "expired": 0}


def test_constructor_rejects_nonsense():
    with pytest.raises(ValueError):
        TTLCache(maxsize=0, ttl_s=1)
    with pytest.raises(ValueError):
        TTLCache(maxsize=1, ttl_s=0)


def test_absent_sentinel_is_never_returned_raw():
    c = TTLCache()
    c.set_absent("k")
    hit, value = c.get("k")
    assert hit and value is None and value is not ABSENT
