from recon.permutations import MAX_VARIANTS, generate_variants


def test_never_returns_the_original():
    base = "johnsmith"
    assert base not in generate_variants(base)


def test_separator_and_reversed_forms():
    variants = generate_variants("john.smith")
    assert "john_smith" in variants
    assert "john-smith" in variants
    # Reversed word order for two-part names.
    assert any(v in variants for v in ("smith.john", "smith_john", "smithjohn"))


def test_affixes():
    variants = generate_variants("acme")
    assert "theacme" in variants
    assert "acme1" in variants
    assert "acme_official" in variants


def test_vowel_stripped_form():
    variants = generate_variants("john.smith")
    assert "jhnsmth" in variants


def test_bounded_and_deduped():
    variants = generate_variants("john.smith")
    assert len(variants) <= MAX_VARIANTS
    assert len(variants) == len(set(v.lower() for v in variants))


def test_empty_input():
    assert generate_variants("") == []
    assert generate_variants("   ") == []
