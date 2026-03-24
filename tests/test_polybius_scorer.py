"""Tests for kryptosbot/polybius_scorer.py."""
import sys
from pathlib import Path

# Ensure imports work
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kryptosbot.polybius_scorer import (
    ROW_KEY_AT_CRIBS, COL_KEY_AT_CRIBS, CRIB_POSITIONS_ORDERED,
    KA_WIDTH, KA_NROWS, KA_LETTER_TO_COORD, KA_COORD_TO_LETTER,
    PolybiusScore, check_row_key_consistency, row_key_from_plaintext,
    col_key_from_plaintext, count_crib_matches, score_polybius_candidate,
    check_bean_eq, check_bean_eq_row, check_bean_ineq,
)
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, KRYPTOS_ALPHABET,
    BEAUFORT_KEYSTREAM_AT_CRIBS, BEAN_EQ, BEAN_INEQ,
)


class TestConstants:
    """Verify scorer constants match authoritative sources."""

    def test_row_key_matches_memory(self):
        """Row key must match the value in MEMORY.md."""
        expected = (4, 4, 1, 4, 1, 5, 0, 0, 5, 4, 1, 2, 1,
                    4, 2, 0, 1, 3, 3, 4, 2, 3, 1, 0)
        assert ROW_KEY_AT_CRIBS == expected

    def test_crib_positions_count(self):
        assert len(CRIB_POSITIONS_ORDERED) == N_CRIBS == 24

    def test_crib_positions_sorted(self):
        assert list(CRIB_POSITIONS_ORDERED) == sorted(CRIB_POSITIONS_ORDERED)

    def test_grid_dimensions(self):
        assert KA_WIDTH == 5
        assert KA_NROWS == 6

    def test_all_26_letters_mapped(self):
        assert len(KA_LETTER_TO_COORD) == 26
        assert set(KA_LETTER_TO_COORD.keys()) == set(KRYPTOS_ALPHABET)

    def test_coord_roundtrip(self):
        for ch in KRYPTOS_ALPHABET:
            r, c = KA_LETTER_TO_COORD[ch]
            assert KA_COORD_TO_LETTER[(r, c)] == ch

    def test_row_key_derivation(self):
        """Row key should be (CT_r + PT_r) % 6 at each crib position."""
        for i, pos in enumerate(CRIB_POSITIONS_ORDERED):
            ct_r = KA_LETTER_TO_COORD[CT[pos]][0]
            pt_r = KA_LETTER_TO_COORD[CRIB_DICT[pos]][0]
            assert (ct_r + pt_r) % KA_NROWS == ROW_KEY_AT_CRIBS[i], \
                f"Mismatch at crib index {i}, pos {pos}"


class TestRowKeyConsistency:
    """Test check_row_key_consistency()."""

    def test_perfect_match(self):
        """A row key that matches exactly should score 24/24."""
        # Build a 97-element key that has the right values at crib positions
        key = [0] * CT_LEN
        for i, pos in enumerate(CRIB_POSITIONS_ORDERED):
            key[pos] = ROW_KEY_AT_CRIBS[i]
        matches, mismatches = check_row_key_consistency(key)
        assert matches == 24
        assert mismatches == []

    def test_zero_match(self):
        """An all-zeros key should match only where ROW_KEY_AT_CRIBS[i] == 0."""
        key = [0] * CT_LEN
        matches, _ = check_row_key_consistency(key)
        expected = sum(1 for v in ROW_KEY_AT_CRIBS if v == 0)
        assert matches == expected

    def test_wrong_length(self):
        """Short key should still score what it can."""
        key = [ROW_KEY_AT_CRIBS[0]] * 30  # Only covers first crib region
        matches, mismatches = check_row_key_consistency(key)
        # Should match some of ENE (pos 21-29) and miss all BC (pos 63-73)
        assert matches >= 0
        assert len(mismatches) > 0


class TestRowKeyFromPlaintext:
    """Test row_key_from_plaintext()."""

    def test_with_known_cribs(self):
        """Inserting known PT at crib positions should reproduce ROW_KEY_AT_CRIBS."""
        pt = list("A" * CT_LEN)
        for pos, ch in CRIB_DICT.items():
            pt[pos] = ch
        rk = row_key_from_plaintext("".join(pt))
        for i, pos in enumerate(CRIB_POSITIONS_ORDERED):
            assert rk[pos] == ROW_KEY_AT_CRIBS[i], \
                f"Row key mismatch at pos {pos}: got {rk[pos]}, expected {ROW_KEY_AT_CRIBS[i]}"

    def test_length(self):
        rk = row_key_from_plaintext("A" * CT_LEN)
        assert len(rk) == CT_LEN


class TestCribMatches:
    """Test count_crib_matches()."""

    def test_all_cribs(self):
        pt = list("X" * CT_LEN)
        for pos, ch in CRIB_DICT.items():
            pt[pos] = ch
        assert count_crib_matches("".join(pt)) == 24

    def test_no_cribs(self):
        assert count_crib_matches("X" * CT_LEN) == 0

    def test_partial_cribs(self):
        # Just EASTNORTHEAST
        pt = list("X" * CT_LEN)
        for pos in range(21, 34):
            pt[pos] = CRIB_DICT[pos]
        assert count_crib_matches("".join(pt)) == 13


class TestBeanConstraints:
    """Test Bean equality and inequality checks."""

    def test_bean_eq_with_known_cribs(self):
        """PT with correct cribs should pass Bean equality."""
        pt = list("A" * CT_LEN)
        for pos, ch in CRIB_DICT.items():
            pt[pos] = ch
        # Bean EQ requires k[27]==k[65]. With correct cribs at 27 and 65,
        # this should pass.
        assert check_bean_eq("".join(pt))

    def test_bean_eq_row_with_correct_key(self):
        key = [0] * CT_LEN
        for i, pos in enumerate(CRIB_POSITIONS_ORDERED):
            key[pos] = ROW_KEY_AT_CRIBS[i]
        # Bean EQ position 27 is crib index 6, position 65 is crib index 15
        # ROW_KEY_AT_CRIBS[6] = 0, ROW_KEY_AT_CRIBS[15] = 0 — both 0, should pass
        assert check_bean_eq_row(key)


class TestPolybiusScore:
    """Test the full scoring pipeline."""

    def test_score_with_correct_cribs(self):
        pt = list(CT)
        for pos, ch in CRIB_DICT.items():
            pt[pos] = ch
        score = score_polybius_candidate("".join(pt))
        assert score.crib_score == 24
        assert score.row_key_matches == 24
        assert score.bean_eq_passed
        assert score.is_signal

    def test_score_random(self):
        import random
        random.seed(42)
        pt = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(CT_LEN))
        score = score_polybius_candidate(pt)
        assert not score.is_signal
        # Random should get ~1 crib hit and ~4 row key matches
        assert score.crib_score < 10
        assert score.row_key_matches < 15

    def test_score_empty(self):
        score = score_polybius_candidate("")
        assert score.crib_score == 0
        assert score.row_key_matches == 0

    def test_score_lowercase(self):
        score = score_polybius_candidate("abc")
        assert score.crib_score == 0

    def test_summary_format(self):
        score = PolybiusScore(crib_score=5, row_key_matches=8)
        s = score.summary()
        assert "cribs=5/24" in s
        assert "row_key=8/24" in s
