"""Tests for position-free crib scoring.

Validates that the free scorer correctly finds cribs at arbitrary positions,
handles partial matches, and produces correct gap/pairing analysis.
"""
import pytest

from kryptos.kernel.scoring.free_crib import (
    CRIB_BC, CRIB_ENE,
    FreeCribResult, find_all_occurrences, find_fragments,
    score_free, score_free_fast,
)
from kryptos.kernel.scoring.aggregate import (
    FreeScoreBreakdown, score_candidate_free,
)


class TestFindAllOccurrences:
    def test_no_match(self):
        assert find_all_occurrences("ABCDEF", "XYZ") == []

    def test_single_match(self):
        assert find_all_occurrences("ABCDEF", "BCD") == [1]

    def test_multiple_matches(self):
        assert find_all_occurrences("ABCABCABC", "ABC") == [0, 3, 6]

    def test_overlapping(self):
        assert find_all_occurrences("AAAA", "AA") == [0, 1, 2]

    def test_full_string(self):
        assert find_all_occurrences("ABC", "ABC") == [0]

    def test_empty_text(self):
        assert find_all_occurrences("", "ABC") == []


class TestScoreFree:
    def test_both_cribs_at_canonical(self):
        """Cribs at the standard positions 21 and 63."""
        text = "X" * 21 + CRIB_ENE + "X" * (63 - 34) + CRIB_BC + "X" * 13
        result = score_free(text)
        assert result.ene_found
        assert result.bc_found
        assert result.both_found
        assert result.canonical_positions
        assert 21 in result.ene_offsets
        assert 63 in result.bc_offsets
        assert result.score == 24

    def test_both_cribs_at_noncanonical(self):
        """Cribs present but at non-standard positions."""
        text = CRIB_ENE + "XXXXXXX" + CRIB_BC
        result = score_free(text)
        assert result.ene_found
        assert result.bc_found
        assert result.both_found
        assert not result.canonical_positions
        assert 0 in result.ene_offsets
        assert result.score == 24

    def test_ene_only(self):
        text = "XXXXX" + CRIB_ENE + "XXXXX"
        result = score_free(text)
        assert result.ene_found
        assert not result.bc_found
        assert not result.both_found
        assert result.score == 13

    def test_bc_only(self):
        text = "XXXXX" + CRIB_BC + "XXXXX"
        result = score_free(text)
        assert not result.ene_found
        assert result.bc_found
        assert not result.both_found
        assert result.score == 11

    def test_neither_crib(self):
        text = "X" * 97
        result = score_free(text)
        assert not result.ene_found
        assert not result.bc_found
        assert result.score == 0

    def test_gap_calculation(self):
        """Gap = distance from end of ENE to start of BC."""
        text = CRIB_ENE + "ABC" + CRIB_BC
        result = score_free(text)
        assert result.gap == 3
        assert result.best_ene_offset == 0
        assert result.best_bc_offset == len(CRIB_ENE) + 3

    def test_adjacent_cribs(self):
        """No gap between cribs."""
        text = CRIB_ENE + CRIB_BC
        result = score_free(text)
        assert result.gap == 0

    def test_reversed_order(self):
        """BC before ENE — should still find both."""
        text = CRIB_BC + "XXXXXX" + CRIB_ENE
        result = score_free(text)
        assert result.both_found
        assert result.score == 24
        # Gap should be negative (BC before ENE) or found via non-overlapping logic
        assert result.gap is not None

    def test_fragments_when_no_full_match(self):
        """When full crib is absent, fragments should be reported."""
        # Contains NORTHEAST (9 chars) but not full EASTNORTHEAST
        text = "XXXXNORTHEASTXXXX"
        result = score_free(text)
        assert not result.ene_found
        assert result.ene_fragments is not None
        assert len(result.ene_fragments) > 0
        # Should find NORTHEAST or similar
        frag_strings = [f[0] for f in result.ene_fragments]
        assert any("NORTHEAST" in f for f in frag_strings)

    def test_no_fragments_when_full_match(self):
        """When full crib is present, fragments list should be empty."""
        text = "XXX" + CRIB_ENE + "XXX"
        result = score_free(text)
        assert result.ene_found
        assert result.ene_fragments == []


class TestScoreFreeFast:
    def test_both(self):
        text = CRIB_ENE + CRIB_BC
        assert score_free_fast(text) == 24

    def test_ene_only(self):
        assert score_free_fast(CRIB_ENE) == 13

    def test_bc_only(self):
        assert score_free_fast(CRIB_BC) == 11

    def test_none(self):
        assert score_free_fast("ABCDEFG") == 0

    def test_case_insensitive(self):
        assert score_free_fast("eastnortheast") == 13


class TestScoreCandidateFree:
    def test_both_cribs(self):
        text = "A" * 10 + CRIB_ENE + "B" * 20 + CRIB_BC + "C" * 10
        result = score_candidate_free(text)
        assert isinstance(result, FreeScoreBreakdown)
        assert result.both_found
        assert result.crib_score == 24
        assert result.crib_classification == "breakthrough"
        assert result.is_breakthrough
        assert result.ic_value > 0

    def test_one_crib(self):
        text = "A" * 10 + CRIB_ENE + "B" * 50
        result = score_candidate_free(text)
        assert result.ene_found
        assert not result.bc_found
        assert result.crib_score == 13
        assert result.crib_classification == "signal"

    def test_no_cribs(self):
        text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3
        result = score_candidate_free(text)
        assert result.crib_score == 0
        assert result.crib_classification == "noise"

    def test_to_dict(self):
        text = CRIB_ENE + CRIB_BC
        result = score_candidate_free(text)
        d = result.to_dict()
        assert d["crib_score"] == 24
        assert d["both_found"] is True
        assert "ene_offsets" in d
        assert "bc_offsets" in d

    def test_summary_string(self):
        text = CRIB_ENE + "XXXX" + CRIB_BC
        result = score_candidate_free(text)
        s = result.summary
        assert "free_cribs=24/24" in s
        assert "ENE=YES" in s
        assert "BC=YES" in s
        assert "gap=" in s


class TestFreeScorerVsAnchored:
    """Compare free vs anchored scoring on the same text to demonstrate
    the difference when positions shift."""

    def test_canonical_agrees(self):
        """At canonical positions, both scorers should agree on crib presence."""
        from kryptos.kernel.scoring.aggregate import score_candidate
        text = "X" * 21 + CRIB_ENE + "X" * (63 - 34) + CRIB_BC + "X" * 13
        anchored = score_candidate(text)
        free = score_candidate_free(text)
        assert anchored.crib_score == 24
        assert free.crib_score == 24

    def test_shifted_disagrees(self):
        """When cribs are shifted, anchored misses but free finds them."""
        from kryptos.kernel.scoring.aggregate import score_candidate
        # Cribs shifted by 5 positions
        text = "X" * 26 + CRIB_ENE + "X" * (68 - 39) + CRIB_BC + "X" * 8
        anchored = score_candidate(text)
        free = score_candidate_free(text)
        # Anchored scorer should find very few matches at the wrong positions
        assert anchored.crib_score < 10
        # Free scorer should find both
        assert free.crib_score == 24
        assert free.both_found
