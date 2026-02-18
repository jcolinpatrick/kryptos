"""Tests for alphabet model and keyword mixing."""
import pytest

from kryptos.kernel.alphabet import (
    Alphabet, AZ, KA,
    keyword_mixed_alphabet, make_alphabet, build_alphabet_pairs,
)
from kryptos.kernel.constants import ALPH, KRYPTOS_ALPHABET


class TestAlphabet:
    def test_az_encode_decode(self):
        text = "HELLOWORLD"
        indices = AZ.encode(text)
        decoded = AZ.decode(indices)
        assert decoded == text

    def test_ka_encode_decode(self):
        text = "KRYPTOS"
        indices = KA.encode(text)
        decoded = KA.decode(indices)
        assert decoded == text

    def test_index_table_bijection(self):
        tbl = AZ.index_table
        assert len(tbl) == 26
        assert sorted(tbl) == list(range(26))

    def test_ka_index_table(self):
        tbl = KA.index_table
        assert tbl[ord("K") - 65] == 0  # K is first in KA
        assert tbl[ord("R") - 65] == 1

    def test_invalid_alphabet_raises(self):
        with pytest.raises(ValueError):
            Alphabet("bad", "ABCDE")  # Too short

    def test_duplicate_letters_raises(self):
        with pytest.raises(ValueError):
            Alphabet("bad", "A" * 26)  # Not unique


class TestKeywordMixing:
    def test_kryptos(self):
        result = keyword_mixed_alphabet("KRYPTOS")
        assert result == KRYPTOS_ALPHABET

    def test_preserves_all_letters(self):
        result = keyword_mixed_alphabet("SANBORN")
        assert len(result) == 26
        assert set(result) == set(ALPH)

    def test_keyword_first(self):
        result = keyword_mixed_alphabet("BERLIN")
        assert result.startswith("BERLIN")

    def test_no_duplicates_in_keyword(self):
        result = keyword_mixed_alphabet("AARDVARK")
        assert result.startswith("ARDVK")

    def test_make_alphabet(self):
        a = make_alphabet("TEST")
        assert isinstance(a, Alphabet)
        assert len(a.sequence) == 26


class TestAlphabetPairs:
    def test_pairs_not_empty(self):
        pairs = build_alphabet_pairs()
        assert len(pairs) > 0

    def test_pairs_unique(self):
        pairs = build_alphabet_pairs()
        keys = set()
        for pa, ca in pairs:
            key = (pa.sequence, ca.sequence)
            assert key not in keys, f"Duplicate pair: {pa.label}/{ca.label}"
            keys.add(key)

    def test_pairs_include_identity(self):
        pairs = build_alphabet_pairs()
        has_az_az = any(
            pa.sequence == ALPH and ca.sequence == ALPH
            for pa, ca in pairs
        )
        assert has_az_az
