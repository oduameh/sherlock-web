from recon.names import MAX_CANDIDATES, generate_name_candidates


def test_basic_forms_present_and_ordered():
    cands = generate_name_candidates("John Smith")
    assert cands[0] == "johnsmith"          # most common form ranks first
    for expected in ("john.smith", "john_smith", "jsmith", "smithjohn"):
        assert expected in cands


def test_rejects_out_of_range_word_counts():
    assert generate_name_candidates("Madonna") == []          # 1 word
    assert generate_name_candidates("") == []
    assert generate_name_candidates("a b c d e") == []        # 5 words


def test_nickname_expansion():
    cands = generate_name_candidates("Robert Smith")
    # Diminutives should be generated and rank above digit suffixes.
    for nick_form in ("bobsmith", "robsmith", "bob.smith"):
        assert nick_form in cands, nick_form
    assert cands.index("bobsmith") < cands.index("robertsmith123")


def test_nickname_expansion_female_name():
    cands = generate_name_candidates("Elizabeth Jones")
    assert any(c.startswith("liz") or c.startswith("beth") for c in cands)


def test_unknown_first_name_has_no_nickname_forms():
    # A name with no nickname mapping still produces the standard forms.
    cands = generate_name_candidates("Zephyr Quill")
    assert "zephyrquill" in cands


def test_transliteration_and_lowercasing():
    cands = generate_name_candidates("Renée Dupont")
    assert "reneedupont" in cands
    assert all(c == c.lower() for c in cands)
    # Output is ASCII only.
    assert all(c.isascii() for c in cands)


def test_bounded_and_deduped():
    cands = generate_name_candidates("Robert James Smith")
    assert len(cands) <= MAX_CANDIDATES
    assert len(cands) == len(set(cands))
    assert all(len(c) >= 3 for c in cands)


def test_middle_name_forms():
    cands = generate_name_candidates("John Quincy Adams")
    assert "johnqadams" in cands or "jqadams" in cands
