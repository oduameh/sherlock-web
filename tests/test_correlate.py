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


# --- honesty rules (each one was a live false bond in a real run) ------------

import pytest  # noqa: E402

from recon.correlate import (  # noqa: E402
    clean_bio_tokens,
    clean_display_name,
    is_generic_hash,
    is_placeholder_avatar,
    names_conflict,
    same_account,
    participates,
    placeholder_hashes,
    score_pair,
    site_template_tokens,
)


# Realistic avatar hashes: a face photo sets roughly half of the 64 bits. Tiny
# values like 0x5555 have low bit counts and are (correctly) generic images.
PHOTO_A = 0x0F0F0F0F0F0F0F0F          # popcount 32
PHOTO_A_NEAR = PHOTO_A ^ 0b111        # distance 3 from PHOTO_A
PHOTO_B = 0xF0F0F0F0F0F0F0F0          # popcount 32, distance 64 from A
PHOTO_C = 0x00FF00FF00FF00FF          # popcount 32


def _row(site, user, url=None, name=None, bio=None, img=None, h=None,
         verification=None, h16=None):
    enr = {}
    if name is not None:
        enr["og_title"] = name
    if bio is not None:
        enr["og_description"] = bio
    if img is not None:
        enr["og_image"] = img
    r = {"username": user, "site": site,
         "url": url or f"https://{site.lower()}.com/{user}",
         "enrichment": enr}
    if h is not None:
        r["avatar_hash"] = h
    if h16 is not None:
        r["avatar_hash16"] = h16
    if verification is not None:
        r["verification"] = verification
    return r


@pytest.mark.parametrize("url", [
    "https://static-cdn.jtvnw.net/user-default-pictures-uv/de130ab0-profile_image-300x300.png",
    "https://telegram.org/img/t_logo_2x.png",
    "https://assets.tumblr.com/images/default_avatar/cone_closed_200.png",
    "https://abs.twimg.com/sticky/default_profile_images/default_profile_400x400.png",
    "https://cdn.discordapp.com/embed/avatars/0.png",
])
def test_known_placeholder_avatar_urls(url):
    assert is_placeholder_avatar(url)


def test_real_avatar_urls_are_not_placeholders():
    assert not is_placeholder_avatar(
        "https://avatars.githubusercontent.com/u/53238518?v=4")
    assert not is_placeholder_avatar(
        "https://i1.sndcdn.com/avatars-000007412498-6d5wwd-t500x500.jpg")
    assert not is_placeholder_avatar(None)


def test_placeholder_hash_by_frequency_same_site():
    """One image on two different handles of one site is the site default,
    whatever its URL — this is the Twitch 97% false bond."""
    rows = [_row("Twitch", "carmen_pop", h=PHOTO_A, img="https://x/a.png"),
            _row("Twitch", "popcarmen", h=PHOTO_A, img="https://x/b.png"),
            _row("GitHub", "someone", h=PHOTO_B)]
    assert placeholder_hashes(rows) == {PHOTO_A}


def test_placeholder_hash_by_frequency_anywhere_and_degenerate():
    rows = [_row("A", "u1", h=PHOTO_A), _row("B", "u2", h=PHOTO_A),
            _row("C", "u3", h=PHOTO_A), _row("D", "u4", h=0),
            _row("E", "u5", h=(1 << 64) - 1), _row("F", "u6", h=PHOTO_B)]
    assert placeholder_hashes(rows) == {PHOTO_A, 0, (1 << 64) - 1}


def test_shared_placeholder_avatar_does_not_bond():
    ph = "https://static-cdn.jtvnw.net/user-default-pictures-uv/x-300x300.png"
    a = _row("Twitch", "carmen_pop", img=ph, h=PHOTO_A)
    b = _row("Telegram", "popcarmen", img=ph, h=PHOTO_A)
    res = score_pair(a, b, placeholders=placeholder_hashes([a, b]))
    assert res["score"] == 0
    assert "avatar_distance" not in res["signals"]
    assert any("placeholder" in why for why in res["signals"]["ignored"])


def test_same_site_text_similarity_is_not_evidence():
    """Two Patreon pages both titled 'Patreon' with the site's own description
    used to score name 1.0 + bio 1.0 = 50. Same-site text never bonds."""
    bio = ("Patreon is empowering a new generation of creators. Support and "
           "engage with artists and creators as they live out their passions")
    a = _row("Patreon", "carmenp", name="Carmen Q", bio=bio + " extra words here")
    b = _row("Patreon", "cpop", name="Carmen Q", bio=bio + " extra words here")
    res = score_pair(a, b)
    assert res["score"] == 0
    assert res["signals"].get("ignored")


def test_same_site_bond_needs_a_real_avatar_and_agreeing_names():
    a = _row("Snapchat", "carmenp", name="Carmen Pariamo", h=PHOTO_A, img="https://s/1.jpg")
    b = _row("Snapchat", "cpop", name="Casey Poplaski", h=PHOTO_A, img="https://s/2.jpg")
    # Same-site same-hash on two handles is itself a placeholder signal…
    assert PHOTO_A in placeholder_hashes([a, b])
    # …and even with a unique real avatar, conflicting display names veto it.
    res = score_pair(a, b, placeholders=set())
    assert res["score"] == 0
    assert "name_conflict" in res["signals"]
    assert any("display names differ" in why for why in res["signals"]["ignored"])


def test_cross_site_conflicting_names_deflate_but_do_not_veto():
    a = _row("GitHub", "alice", name="Alice Example", h=PHOTO_A, img="https://g/1.png")
    b = _row("GitLab", "alice", name="Zed Other", h=PHOTO_A, img="https://l/2.png")
    res = score_pair(a, b, placeholders=set())
    assert res["score"] == 50 - 20
    assert res["signals"]["avatar_distance"] == 0
    assert "name_conflict" in res["signals"]


def test_page_title_is_never_a_display_name():
    r = {"username": "carmen_pop", "site": "Twitch",
         "url": "https://twitchtracker.com/carmen_pop",
         "enrichment": {"title": "carmen_pop - Streamer Overview & Stats · TwitchTracker"}}
    assert clean_display_name(r) == ""


@pytest.mark.parametrize("site,user,raw,expected", [
    ("Snapchat", "carmen_pop", "on Snapchat", ""),                 # empty slot
    ("Snapchat", "carmenpop", "Carmen Pop on Snapchat", ""),       # = handle
    ("tumblr", "carmenpop", "Untitled (@carmenpop) on Tumblr", ""),
    ("Twitch", "cpop", "cpop - Streamer Overview & Stats", ""),
    ("Patreon", "carmenp", "Patreon", ""),
    ("SoundCloud", "carmen-pop", "Carmen Pop", ""),               # = handle
    ("Linktree", "carmenp", "@Carmenp", ""),
    ("GitLab", "carmenp", "Carmen Pacheco · GitLab", "carmen pacheco"),
    ("about.me", "carmenp", "Carmen Pérez", "carmen pérez"),
    ("CodePen", "cpop", "Ehab on CodePen", "ehab"),
    ("Telegram", "cpop123", "Connie Popov", "connie popov"),
    ("Linktree", "popc", "@POPCaféWazemmes", "popcaféwazemmes"),
])
def test_clean_display_name_strips_template_site_and_handle(site, user, raw, expected):
    r = _row(site, user, name=raw)
    assert clean_display_name(r) == expected


def test_bio_template_is_learned_per_site_and_stripped():
    tmpl = "Listen to {u} | SoundCloud is an audio platform that lets you listen to what you love"
    rows = [_row("SoundCloud", u, bio=tmpl.format(u=u)) for u in ("cpop", "popc", "cipop")]
    learned = site_template_tokens(rows)
    assert {"audio", "platform", "listen", "love"} <= learned
    # After stripping, nothing person-specific remains → no bio signal.
    assert len(clean_bio_tokens(rows[0], learned)) < 5
    # Too few rows: nothing is learned (seed phrases still apply).
    assert site_template_tokens(rows[:2]) == set()


def test_seed_phrases_strip_without_learning():
    r = _row("Snapchat", "carmenpop", bio="Carmen Pop is on Snapchat!")
    assert clean_bio_tokens(r) <= {"carmen", "pop", "is"}


def test_non_profile_rows_do_not_participate():
    """A challenge page's 'Just a moment...' title must never become a name."""
    assert not participates(_row("CodePen", "popc", name="Just a moment...",
                                 verification={"status": "indeterminate"}))
    assert not participates(_row("X", "u", name="n",
                                 verification={"status": "likely_false_positive"}))
    assert not participates(_row("X", "u", name="n",
                                 verification={"status": "not_examined"}))
    assert participates(_row("X", "u", name="n", verification={"status": "confirmed"}))
    assert participates(_row("X", "u", name="n", verification={"status": "unconfirmed"}))
    assert participates(_row("X", "u", name="n"))          # no verdict: allowed
    assert not participates({"username": "u", "site": "X", "url": "https://x/u"})


def test_cross_site_same_person_still_bonds_with_ignored_trail():
    """The positive path: a real avatar + real name across two sites."""
    a = _row("Telegram", "carmenpop", name="Carmen I. Pop",
             img="https://cdn4.telesco.pe/file/real.jpg", h=PHOTO_A)
    b = _row("GitHub", "cipop", name="Carmen I. Pop",
             img="https://avatars.githubusercontent.com/u/1?v=4", h=PHOTO_A)
    clusters = asyncio.run(correlate([a, b]))
    assert len(clusters) == 1
    assert clusters[0]["confidence"] >= 50 + 20
    link = clusters[0]["links"][0]
    assert link["signals"]["avatar_distance"] == 0
    assert link["signals"]["name_sim"] >= 0.75


def test_cluster_links_are_attributed_exactly_not_by_site_prefix():
    """Two separate Snapchat clusters used to show each other's links because
    membership was matched on the site-name prefix of the label."""
    a1 = _row("Snapchat", "a1", name="Ann Able", h=PHOTO_A, img="https://s/a1.jpg")
    a2 = _row("GitHub", "a2", name="Ann Able", h=PHOTO_A, img="https://g/a2.png")
    b1 = _row("Snapchat", "b1", name="Bob Baker", h=PHOTO_B, img="https://s/b1.jpg")
    b2 = _row("GitLab", "b2", name="Bob Baker", h=PHOTO_B, img="https://l/b2.png")
    clusters = asyncio.run(correlate([a1, a2, b1, b2]))
    assert len(clusters) == 2
    for c in clusters:
        urls = {m["url"] for m in c["members"]}
        for link in c["links"]:
            for end in (link["a"], link["b"]):
                assert end[end.find("(") + 1:end.rfind(")")] in urls


def test_names_conflict_is_token_based_not_letter_based():
    assert names_conflict("carmen pariamo", "casey poplaski")   # difflib says 0.50
    assert names_conflict("alice example", "zed other")
    assert not names_conflict("carmen pop", "carmen pop official")
    assert not names_conflict("rob smith", "robert smith")       # nickname prefix
    assert not names_conflict("", "anyone")


def test_real_name_containing_the_handle_keeps_its_name():
    r = _row("GitHub", "alice", name="Alice Example")
    assert clean_display_name(r) == "alice example"
    r = _row("Vimeo", "cpop", name="Cpop - ionlyU")
    assert clean_display_name(r) == "ionlyu"


# --- rule 5/6: site logos as og:image; one profile is not two -------------

@pytest.mark.parametrize("url", [
    "https://images-cdn.9gag.com/img/9gag-og.png",
    "https://web-assets.ifttt.com/builds/assets/ifttt-banner-BdwHPmXv.png",
    "https://s.tradingview.com/static/images/logo-preview.png",
    "https://avatars.discourse-cdn.com/v4/letter/t/45deac/45.png",
    "https://example.com/assets/opengraph.jpg",
])
def test_site_asset_og_images_are_placeholders(url):
    """Six unrelated sites bonded at hash distance 4 on these 'avatars'."""
    assert is_placeholder_avatar(url)


def test_generic_hash_by_bit_population():
    assert is_generic_hash(66229406269440)        # 9GAG logo: 16 bits
    assert is_generic_hash(66074181107712)        # letter avatar: 10 bits
    assert is_generic_hash(0) and is_generic_hash((1 << 64) - 1)
    assert not is_generic_hash(17166668570040376)  # real photo: 30 bits
    assert not is_generic_hash(PHOTO_A)
    assert not is_generic_hash(None)


def test_low_resolution_match_needs_16x16_corroboration():
    """Two different generic images can agree at 8x8; a reused photo also
    agrees at 16x16. Without both, no bond — and the analyst sees why."""
    far16 = (1 << 256) - 1
    a = _row("NPM", "torvalds", h=PHOTO_A, h16=0, img="https://n/a.png")
    b = _row("Figma", "torvalds", h=PHOTO_A_NEAR, h16=far16, img="https://f/b.png")
    res = score_pair(a, b, placeholders=set())
    assert res["score"] == 0
    assert any("low resolution" in why for why in res["signals"]["ignored"])
    # Corroborated: same photo → bond, with both distances in the trail.
    b["avatar_hash16"] = 0b1010
    res = score_pair(a, b, placeholders=set())
    assert res["score"] == 50
    assert res["signals"]["avatar_distance"] == 3
    assert res["signals"]["avatar_distance16"] == 2
    # Legacy rows without a 16x16 hash fall back to the 8x8 decision.
    del a["avatar_hash16"]
    assert score_pair(a, b, placeholders=set())["score"] == 50


def test_same_profile_under_two_site_labels_is_one_account():
    a = _row("Drive2", "torvalds", url="https://www.drive2.ru/users/torvalds",
             h=PHOTO_A, img="https://a1.drive-data.ru/5318698s-60.jpg")
    b = _row("DRIVE2.RU", "torvalds", url="https://drive2.ru/users/torvalds/",
             h=PHOTO_A, img="https://a1.drive-data.ru/5318698s-60.jpg")
    assert same_account(a, b)
    assert score_pair(a, b)["score"] == 0
    assert asyncio.run(correlate([a, b])) == []
    # Same host, same handle, different path shape: still one account.
    c = _row("X", "bob", url="https://site.com/u/bob")
    d = _row("Y", "bob", url="https://www.site.com/users/bob")
    assert same_account(c, d)
    assert not same_account(c, _row("X", "alice", url="https://site.com/u/alice"))
