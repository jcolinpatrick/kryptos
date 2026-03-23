"""Regression tests for stego layer solve pipeline."""
import pytest
from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, BEAUFORT_KEYSTREAM_AT_CRIBS, ALPH,
)

# The 17 consensus null characters in position order
CONSENSUS_NULL_CHARS = tuple(CT[p] for p in sorted(CONSENSUS_NULL_POSITIONS))
CONSENSUS_NULL_NUMS = tuple(ALPH.index(c) for c in CONSENSUS_NULL_CHARS)


class TestNullDataIntegrity:
    """Lock in the exact null characters for all downstream experiments."""

    def test_17_consensus_nulls(self):
        assert len(CONSENSUS_NULL_POSITIONS) == 17

    def test_all_null_chars_in_palette(self):
        for p in CONSENSUS_NULL_POSITIONS:
            assert CT[p] in NULL_PALETTE, f"CT[{p}]={CT[p]} not in palette"

    def test_exact_null_characters(self):
        """The exact character at each null position — regression anchor."""
        expected = {
            0: 'O', 1: 'B', 2: 'K', 5: 'O', 8: 'G', 12: 'B', 14: 'O',
            20: 'W', 36: 'W', 52: 'K', 58: 'W', 59: 'I', 74: 'W',
            75: 'G', 78: 'Z', 84: 'I', 85: 'G',
        }
        for pos, char in expected.items():
            assert CT[pos] == char, f"CT[{pos}] expected {char}, got {CT[pos]}"

    def test_null_letter_frequencies(self):
        """W=4, O=3, G=3, B=2, I=2, K=2, Z=1."""
        from collections import Counter
        freqs = Counter(CT[p] for p in CONSENSUS_NULL_POSITIONS)
        assert freqs == {'W': 4, 'O': 3, 'G': 3, 'B': 2, 'I': 2, 'K': 2, 'Z': 1}

    def test_no_nulls_in_crib_ranges(self):
        assert not CONSENSUS_NULL_POSITIONS & CRIB_POSITIONS

    def test_keystream_length_matches_cribs(self):
        assert len(BEAUFORT_KEYSTREAM_AT_CRIBS) == 24


class TestPalettePositions:
    """Verify palette position structure used by Phase 2."""

    def test_35_palette_positions_in_ct97(self):
        palette_positions = [p for p in range(CT_LEN) if CT[p] in NULL_PALETTE]
        assert len(palette_positions) == 35

    def test_17_nulls_plus_18_reals_equals_35(self):
        palette_positions = {p for p in range(CT_LEN) if CT[p] in NULL_PALETTE}
        null_palette_positions = palette_positions & CONSENSUS_NULL_POSITIONS
        real_palette_positions = palette_positions - CONSENSUS_NULL_POSITIONS
        assert len(null_palette_positions) == 17
        assert len(real_palette_positions) == 18
