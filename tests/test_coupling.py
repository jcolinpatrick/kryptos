"""Tests for stego-cipher coupling constraints (CxS-1 through CxS-4).

Verifies that the DerivedConstraint framework correctly captures the
statistical couplings between the stego layer (null palette) and the
cipher layer (Beaufort keystream at crib positions).
"""
from __future__ import annotations

import pytest

from kryptos.kernel.constants import ALPH, KRYPTOS_ALPHABET
# Retired imports (moved from constants to retired/ in Phase 2, 2026-04-20).
# Used as test fixtures for the historical CxS-1..CxS-4 coupling math, which
# is itself retired. On allow-list in tests/test_retired_usage.py.
from kryptos.kernel.retired import BEAUFORT_KEYSTREAM_AT_CRIBS, NULL_PALETTE
from kryptos.kernel.constraints.coupling import (
    DerivedConstraint,
    ap_palette_containment,
    dual_alphabet_structure,
    keystream_palette_enrichment,
    mod5_ka_structure,
    propagate_all,
)

# Real K4 Beaufort keystream at 24 crib positions, as integer values (A=0)
KS_NUMS = [ALPH.index(c) for c in BEAUFORT_KEYSTREAM_AT_CRIBS]


class TestKeystreamPaletteEnrichment:
    """CxS-1: Keystream values disproportionately map to null-palette letters."""

    def test_id(self):
        result = keystream_palette_enrichment(KS_NUMS, NULL_PALETTE)
        assert result.id == "CxS-1"

    def test_observed_count(self):
        result = keystream_palette_enrichment(KS_NUMS, NULL_PALETTE)
        assert result.observed == 13

    def test_p_value_significant(self):
        result = keystream_palette_enrichment(KS_NUMS, NULL_PALETTE)
        assert result.p_value < 0.01

    def test_expected_value(self):
        result = keystream_palette_enrichment(KS_NUMS, NULL_PALETTE)
        # Expected = 24 * 7/26 ≈ 6.46
        assert abs(result.expected - 24 * 7 / 26) < 0.01

    def test_returns_derived_constraint(self):
        result = keystream_palette_enrichment(KS_NUMS, NULL_PALETTE)
        assert isinstance(result, DerivedConstraint)
        assert result.constraint_type == "statistical"


class TestMod5KAStructure:
    """CxS-2: Keystream values cluster at KA positions with index % 5 in {0, 3}."""

    def test_id(self):
        result = mod5_ka_structure(KS_NUMS)
        assert result.id == "CxS-2"

    def test_observed_count(self):
        result = mod5_ka_structure(KS_NUMS)
        assert result.observed == 14

    def test_all_palette_letters_satisfy_mod5(self):
        """Every null-palette letter should have KA index % 5 in {0, 3}."""
        for letter in NULL_PALETTE:
            ka_idx = KRYPTOS_ALPHABET.index(letter)
            assert ka_idx % 5 in {0, 3}, (
                f"Palette letter {letter} at KA index {ka_idx} "
                f"has mod5={ka_idx % 5}, expected {{0, 3}}"
            )

    def test_cxs1_implies_cxs2(self):
        """CxS-1 enrichment (13) should be ≤ CxS-2 enrichment (14)."""
        cxs1 = keystream_palette_enrichment(KS_NUMS, NULL_PALETTE)
        cxs2 = mod5_ka_structure(KS_NUMS)
        assert cxs1.observed <= cxs2.observed


class TestAPPaletteContainment:
    """CxS-3: Arithmetic progression {G=6, K=10, O=14} dominates keystream."""

    def test_id(self):
        result = ap_palette_containment(KS_NUMS, NULL_PALETTE)
        assert result.id == "CxS-3"

    def test_observed_at_least_12(self):
        result = ap_palette_containment(KS_NUMS, NULL_PALETTE)
        assert result.observed >= 12

    def test_step4_in_az(self):
        """AP {G=6, K=10, O=14} has constant step 4 in standard alphabet."""
        ap = [ALPH.index("G"), ALPH.index("K"), ALPH.index("O")]
        assert ap == [6, 10, 14]
        steps = [ap[i + 1] - ap[i] for i in range(len(ap) - 1)]
        assert all(s == 4 for s in steps)

    def test_ap_members_in_palette(self):
        """All AP members {G, K, O} must be palette letters."""
        for letter in "GKO":
            assert letter in NULL_PALETTE


class TestDualAlphabet:
    """CxS-4: AP is regular in AZ but irregular in KA — both alphabets involved."""

    def test_id(self):
        result = dual_alphabet_structure(KS_NUMS)
        assert result.id == "CxS-4"

    def test_observed_both_alphabets(self):
        result = dual_alphabet_structure(KS_NUMS)
        assert result.observed is True

    def test_ka_positions_irregular(self):
        """In KA, positions of G, K, O are NOT equally spaced."""
        ka_g = KRYPTOS_ALPHABET.index("G")
        ka_k = KRYPTOS_ALPHABET.index("K")
        ka_o = KRYPTOS_ALPHABET.index("O")
        gaps = [ka_k - ka_g, ka_o - ka_k]
        # K=0, O=5, G=13 in KA → sorted: K=0, O=5, G=13
        # But we look up G, K, O individually:
        # G is at position 13, K at 0, O at 5
        assert gaps[0] != gaps[1], (
            f"KA gaps {gaps} should NOT be equal (not arithmetic)"
        )

    def test_az_positions_regular(self):
        """In AZ, positions of G, K, O ARE equally spaced (step 4)."""
        az_g = ALPH.index("G")
        az_k = ALPH.index("K")
        az_o = ALPH.index("O")
        gaps = [az_k - az_g, az_o - az_k]
        assert gaps[0] == gaps[1] == 4


class TestPropagateAll:
    """propagate_all() returns all 4 coupling constraints."""

    def test_returns_list(self):
        results = propagate_all(KS_NUMS, NULL_PALETTE)
        assert isinstance(results, list)
        assert len(results) >= 4

    def test_all_ids_present(self):
        results = propagate_all(KS_NUMS, NULL_PALETTE)
        ids = {r.id for r in results}
        assert {"CxS-1", "CxS-2", "CxS-3", "CxS-4"} <= ids

    def test_all_are_derived_constraints(self):
        results = propagate_all(KS_NUMS, NULL_PALETTE)
        for r in results:
            assert isinstance(r, DerivedConstraint)
