import asyncio
import io

from recon.correlate import (
    average_hash,
    bio_similarity,
    correlate,
    hamming,
    name_similarity,
)


def _png_bytes(color: int) -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("L", (16, 16), color).save(buf, format="PNG")
    return buf.getvalue()


def test_average_hash_identical_images_match():
    a = average_hash(_png_bytes(120))
    b = average_hash(_png_bytes(120))
    assert a is not None and b is not None
    assert hamming(a, b) == 0


def test_average_hash_bad_bytes_returns_none():
    assert average_hash(b"not an image") is None


def test_name_similarity():
    assert name_similarity("John Smith", "john smith") == 1.0
    assert name_similarity("John Smith", "Jane Doe") < 0.5
    assert name_similarity("", "John") == 0.0


def test_bio_similarity_thresholds():
    a = "photographer and traveler based in berlin loves coffee"
    b = "photographer and traveler based in berlin loves coffee and cats"
    assert bio_similarity(a, b) >= 0.30
    # Short bios (< 5 words) do not contribute.
    assert bio_similarity("hi there", "hello world") == 0.0


def test_correlate_clusters_matching_names_and_bios():
    bio = "software engineer in london building open source developer tools"
    rows = [
        {"username": "alice", "site": "GitHub", "url": "https://gh/alice",
         "enrichment": {"jsonld_name": "Alice Example",
                        "jsonld_description": bio}},
        {"username": "alice", "site": "GitLab", "url": "https://gl/alice",
         "enrichment": {"jsonld_name": "Alice Example",
                        "jsonld_description": bio}},
    ]
    clusters = asyncio.run(correlate(rows))
    assert len(clusters) == 1
    assert clusters[0]["confidence"] >= 40
    assert {m["site"] for m in clusters[0]["members"]} == {"GitHub", "GitLab"}


def test_correlate_ignores_unrelated_profiles():
    rows = [
        {"username": "alice", "site": "GitHub", "url": "https://gh/alice",
         "enrichment": {"jsonld_name": "Alice Example",
                        "jsonld_description": "loves hiking and mountains a lot"}},
        {"username": "bob", "site": "Twitter", "url": "https://tw/bob",
         "enrichment": {"jsonld_name": "Robert Different",
                        "jsonld_description": "enjoys deep sea fishing daily now"}},
    ]
    assert asyncio.run(correlate(rows)) == []


def test_correlate_needs_two_enriched_rows():
    assert asyncio.run(correlate([])) == []
    assert asyncio.run(correlate([{"url": "x", "enrichment": {}}])) == []
