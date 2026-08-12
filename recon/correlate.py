"""Cross-account correlation: avatar hashes, name similarity, bio overlap.

Clusters enriched profiles that look like the same person and assigns a
confidence score (avatar 50 / name 30 / bio 20). Heuristic only — correlation
false positives are expected and confidence is advisory.
"""

from __future__ import annotations

import asyncio
import difflib
import io
import logging
import re
from typing import Any, Optional

from recon import safeweb
from recon.confidence import (
    AVATAR_WEIGHT,
    BIO_WEIGHT,
    CORRELATION_LINK_MIN,
    NAME_WEIGHT,
)

logger = logging.getLogger("recon.correlate")

AVATAR_HAMMING_MAX = 5       # <= this on an 8x8 average hash = "same avatar"
NAME_SIM_MIN = 0.75          # difflib ratio threshold
BIO_JACCARD_MIN = 0.30       # token-overlap threshold (bios >= 5 words)
MAX_AVATARS = 30
AVATAR_TIMEOUT_S = 8
AVATAR_MAX_BYTES = 5 * 1024 * 1024

_WORD_RE = re.compile(r"[a-z0-9]+")


def average_hash(image_bytes: bytes) -> Optional[int]:
    """8x8 average hash as a 64-bit int. None if the image can't be read."""
    try:
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes)).convert("L").resize((8, 8))
        pixels = list(img.tobytes())  # 64 grayscale bytes, one per pixel
        avg = sum(pixels) / len(pixels)
        bits = 0
        for p in pixels:
            bits = (bits << 1) | (1 if p >= avg else 0)
        return bits
    except Exception:
        return None


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def _norm_name(s: Optional[str]) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def name_similarity(a: str, b: str) -> float:
    a, b = _norm_name(a), _norm_name(b)
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def bio_similarity(a: Optional[str], b: Optional[str]) -> float:
    def tokens(s: Optional[str]) -> set[str]:
        return set(_WORD_RE.findall((s or "").lower()))

    ta, tb = tokens(a), tokens(b)
    if len(ta) < 5 or len(tb) < 5:
        return 0.0
    union = ta | tb
    return len(ta & tb) / len(union) if union else 0.0


def _display_name(row: dict) -> str:
    enr = row.get("enrichment") or {}
    return enr.get("jsonld_name") or enr.get("og_title") or enr.get("title") or ""


def _bio(row: dict) -> str:
    enr = row.get("enrichment") or {}
    return enr.get("jsonld_description") or enr.get("og_description") or ""


def _avatar_url(row: dict) -> Optional[str]:
    enr = row.get("enrichment") or {}
    return enr.get("jsonld_image") or enr.get("og_image")


async def _download_avatars(rows: list[dict]) -> None:
    """Attach ``avatar_hash`` to rows that have an avatar URL (in place)."""
    sem = asyncio.Semaphore(5)
    targets = [r for r in rows if _avatar_url(r)][:MAX_AVATARS]
    async with safeweb.async_client(timeout=AVATAR_TIMEOUT_S) as client:

        async def one(row: dict) -> None:
            url = _avatar_url(row)
            try:
                async with sem:
                    content = await safeweb.fetch_capped(
                        client, url, AVATAR_MAX_BYTES)
                if content:
                    h = average_hash(content)
                    if h is not None:
                        row["avatar_hash"] = h
            except Exception:
                pass

        await asyncio.gather(*(one(r) for r in targets), return_exceptions=True)


async def correlate(rows: list[dict]) -> list[dict]:
    """Cluster found-profile rows. Returns clusters with confidence 0-100.

    Only rows with enrichment data participate. Each cluster:
      {members: [{username, site, url}], confidence, links: [{a, b, score,
      rationale}]}
    """
    candidates = [r for r in rows if r.get("enrichment") or r.get("avatar_hash")]
    if len(candidates) < 2:
        return []

    await _download_avatars(candidates)
    candidates = [r for r in rows if r.get("enrichment")]
    if len(candidates) < 2:
        return []

    # Union-find over pairwise links.
    parent = list(range(len(candidates)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        parent[find(i)] = find(j)

    def label(r: dict) -> str:
        return f'{r.get("site")} ({r.get("url")})'

    links: list[dict] = []
    for i in range(len(candidates)):
        for j in range(i + 1, len(candidates)):
            a, b = candidates[i], candidates[j]
            score = 0
            reasons = []
            ha, hb = a.get("avatar_hash"), b.get("avatar_hash")
            if ha is not None and hb is not None:
                d = hamming(ha, hb)
                if d <= AVATAR_HAMMING_MAX:
                    score += AVATAR_WEIGHT
                    reasons.append(f"avatars match (hash distance {d})")
            nsim = name_similarity(_display_name(a), _display_name(b))
            if nsim >= NAME_SIM_MIN:
                score += round(NAME_WEIGHT * nsim)
                reasons.append(f"display names {nsim:.0%} similar")
            bsim = bio_similarity(_bio(a), _bio(b))
            if bsim >= BIO_JACCARD_MIN:
                score += round(BIO_WEIGHT * min(1.0, bsim / BIO_JACCARD_MIN))
                reasons.append(f"bios share {bsim:.0%} of words")
            if score >= CORRELATION_LINK_MIN:  # below this, too speculative
                links.append({
                    "a": label(a), "b": label(b),
                    "score": min(100, score),
                    "rationale": "; ".join(reasons),
                })
                union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(len(candidates)):
        groups.setdefault(find(i), []).append(i)

    clusters = []
    for idxs in groups.values():
        if len(idxs) < 2:
            continue
        members = [
            {
                "username": candidates[i].get("username"),
                "site": candidates[i].get("site"),
                "url": candidates[i].get("url"),
            }
            for i in idxs
        ]
        member_links = [
            l for l in links
            if any(l["a"].startswith(m["site"] + " (") for m in members)
            and any(l["b"].startswith(m["site"] + " (") for m in members)
        ]
        confidence = max((l["score"] for l in member_links), default=0)
        clusters.append({
            "members": members,
            "confidence": confidence,
            "links": member_links,
        })
    clusters.sort(key=lambda c: c["confidence"], reverse=True)
    return clusters
