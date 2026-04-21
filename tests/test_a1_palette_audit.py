"""Tests validating that A1 palette diversity claim is not reproducible.

These tests document the finding from the 2026-04-01 score-conditioned null
experiment that the hardcoded CONSENSUS_NULL_POSITIONS cannot be reproduced
by the SA discovery process, and that the 7-letter diversity is an artifact
of post-hoc position selection.
"""

import pytest
from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS
# Retired imports (moved from constants to retired/ in Phase 2, 2026-04-20).
# This test IS the palette-provenance regression guard — it documents that
# the hardcoded CONSENSUS_NULL_POSITIONS cannot be reproduced. Legitimate
# historical-reproducibility use; on allow-list in tests/test_retired_usage.py.
from kryptos.kernel.retired import CONSENSUS_NULL_POSITIONS, NULL_PALETTE


class TestA1PaletteProvenance:
    """Document that the hardcoded consensus positions are all palette-letter positions."""

    def test_all_consensus_positions_have_palette_letters(self):
        """The hardcoded positions were selected FROM palette-letter positions.
        This makes the '7 distinct letters' observation tautological."""
        for pos in CONSENSUS_NULL_POSITIONS:
            assert CT[pos] in NULL_PALETTE, (
                f"Position {pos} has CT[{pos}]={CT[pos]} not in palette"
            )

    def test_palette_letter_positions_are_abundant(self):
        """31 of 73 non-crib positions have palette letters.
        Choosing 17 from 31 is trivial — not evidence of structure."""
        non_crib = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]
        palette_positions = [i for i in non_crib if CT[i] in NULL_PALETTE]
        assert len(palette_positions) == 31
        assert len(palette_positions) >= 17, "Must have enough palette positions"

    def test_consensus_is_subset_of_palette_positions(self):
        """The consensus IS a subset of palette positions — circular."""
        non_crib_palette = frozenset(
            i for i in range(CT_LEN) if i not in CRIB_POSITIONS and CT[i] in NULL_PALETTE
        )
        assert CONSENSUS_NULL_POSITIONS <= non_crib_palette

    def test_many_seven_letter_sets_cover_17_positions(self):
        """98.9% of all 7-letter subsets of non-crib letters cover ≥17 positions.
        The existence of SUCH a set is not rare."""
        from itertools import combinations
        from collections import Counter
        non_crib = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]
        freq = Counter(CT[i] for i in non_crib)
        letters = list(freq.keys())
        total = 0
        covering = 0
        for combo in combinations(letters, 7):
            total += 1
            coverage = sum(freq[l] for l in combo)
            if coverage >= 17:
                covering += 1
        fraction = covering / total
        assert fraction > 0.95, (
            f"Only {fraction:.1%} of 7-letter sets cover ≥17 positions "
            f"(expected >95%)"
        )
