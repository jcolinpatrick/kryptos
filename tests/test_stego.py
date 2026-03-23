"""Tests for stego layer proof module — S2, S4, S5, S6."""
import pytest

from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE, CRIB_POSITIONS,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.constraints.stego import (
    StegoProperty,
    palette_restriction,
    null_position_classification,
    polybius_generation,
    crib_null_avoidance,
    full_stego_proof,
)


class TestPaletteRestriction:
    """S2: Letters at null positions use surprisingly few distinct values."""

    def test_returns_stego_property(self):
        result = palette_restriction(CT, CONSENSUS_NULL_POSITIONS)
        assert isinstance(result, StegoProperty)

    def test_id_is_s2(self):
        result = palette_restriction(CT, CONSENSUS_NULL_POSITIONS)
        assert result.id == "S2"

    def test_observed_is_7(self):
        result = palette_restriction(CT, CONSENSUS_NULL_POSITIONS)
        assert result.observed == 7

    def test_p_value_significant(self):
        result = palette_restriction(CT, CONSENSUS_NULL_POSITIONS)
        assert result.p_value < 0.001

    def test_all_null_letters_in_palette(self):
        """Every letter at a consensus null position must be in NULL_PALETTE."""
        for pos in CONSENSUS_NULL_POSITIONS:
            assert CT[pos] in NULL_PALETTE, (
                f"CT[{pos}]={CT[pos]} not in NULL_PALETTE"
            )

    def test_status_is_confirmed(self):
        result = palette_restriction(CT, CONSENSUS_NULL_POSITIONS)
        assert result.status == "confirmed"


class TestNullPositionClassification:
    """S4: (pos%7, pos%5) classification predicts null vs real."""

    def test_returns_stego_property(self):
        result = null_position_classification(CT, CONSENSUS_NULL_POSITIONS)
        assert isinstance(result, StegoProperty)

    def test_id_is_s4(self):
        result = null_position_classification(CT, CONSENSUS_NULL_POSITIONS)
        assert result.id == "S4"

    def test_observed_35_palette_positions(self):
        """There should be 35 positions in CT whose letter is in NULL_PALETTE."""
        result = null_position_classification(CT, CONSENSUS_NULL_POSITIONS)
        assert result.observed == 35

    def test_expected_35_correct(self):
        """The classification rule should correctly classify all 35."""
        result = null_position_classification(CT, CONSENSUS_NULL_POSITIONS)
        assert result.expected == 35

    def test_status_is_confirmed(self):
        result = null_position_classification(CT, CONSENSUS_NULL_POSITIONS)
        assert result.status == "confirmed"

    def test_p_value_is_sentinel(self):
        """S4 p_value is a sentinel (-1.0), not a real p-value (no MC null model)."""
        result = null_position_classification(CT, CONSENSUS_NULL_POSITIONS)
        assert result.p_value == -1.0, (
            "S4 p_value should be -1.0 sentinel (accuracy-based, no MC null model)"
        )


class TestPolybiusGeneration:
    """S5: KRYPTOS x SEVEN keywords generate palette via Polybius grid."""

    def test_returns_stego_property(self):
        result = polybius_generation(NULL_PALETTE, "KRYPTOS", "SEVEN")
        assert isinstance(result, StegoProperty)

    def test_id_is_s5(self):
        result = polybius_generation(NULL_PALETTE, "KRYPTOS", "SEVEN")
        assert result.id == "S5"

    def test_kryptos_seven_matches(self):
        result = polybius_generation(NULL_PALETTE, "KRYPTOS", "SEVEN")
        assert result.observed is True

    def test_p_value_significant(self):
        result = polybius_generation(NULL_PALETTE, "KRYPTOS", "SEVEN")
        assert result.p_value < 0.01

    def test_status_is_confirmed(self):
        result = polybius_generation(NULL_PALETTE, "KRYPTOS", "SEVEN")
        assert result.status == "confirmed"


class TestCribNullAvoidance:
    """S6: No null positions overlap with crib ranges."""

    def test_returns_stego_property(self):
        result = crib_null_avoidance(
            CONSENSUS_NULL_POSITIONS,
            [(21, 34), (63, 74)],
        )
        assert isinstance(result, StegoProperty)

    def test_id_is_s6(self):
        result = crib_null_avoidance(
            CONSENSUS_NULL_POSITIONS,
            [(21, 34), (63, 74)],
        )
        assert result.id == "S6"

    def test_observed_zero_overlap(self):
        result = crib_null_avoidance(
            CONSENSUS_NULL_POSITIONS,
            [(21, 34), (63, 74)],
        )
        assert result.observed == 0

    def test_p_value_exists(self):
        result = crib_null_avoidance(
            CONSENSUS_NULL_POSITIONS,
            [(21, 34), (63, 74)],
        )
        assert result.p_value < 1.0
        assert result.p_value > 0.0

    def test_status_is_confirmed(self):
        result = crib_null_avoidance(
            CONSENSUS_NULL_POSITIONS,
            [(21, 34), (63, 74)],
        )
        assert result.status == "confirmed"


class TestFullStegoProof:
    """full_stego_proof should run all 4 tests."""

    def test_returns_list(self):
        results = full_stego_proof(CT)
        assert isinstance(results, list)

    def test_at_least_4_items(self):
        results = full_stego_proof(CT)
        assert len(results) >= 4

    def test_all_expected_ids_present(self):
        results = full_stego_proof(CT)
        ids = {r.id for r in results}
        assert {"S2", "S4", "S5", "S6"} <= ids

    def test_all_are_stego_property(self):
        results = full_stego_proof(CT)
        for r in results:
            assert isinstance(r, StegoProperty)

    def test_all_confirmed(self):
        results = full_stego_proof(CT)
        for r in results:
            assert r.status == "confirmed"
