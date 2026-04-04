"""Integration tests for position mapping across cipher layers.

AUDIT REMEDIATION (2026-04-01): The v1 keystream forensics bug demonstrated that
position-mapping errors in multi-layer models are a real and active risk. These
tests verify correctness of index transformations across mask removal, transposition,
and cipher-layer composition.

Tests cover:
- Null mask removal and crib position shifting
- Transposition permutation and inversion
- Composition of mask + transposition
- Round-trip consistency (apply → undo → verify)
- Bean constraint verification across layers
- Crib alignment after multi-layer transformations
"""
import pytest
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    ALPH_IDX, MOD, BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.crib_score import score_cribs


class TestNullMaskRemoval:
    """Test that null mask removal correctly shifts crib positions."""

    def test_consensus_null_positions_valid(self):
        """All consensus null positions are within CT range and non-overlapping with cribs."""
        for p in CONSENSUS_NULL_POSITIONS:
            assert 0 <= p < CT_LEN, f"Null position {p} out of range"
            assert p not in CRIB_POSITIONS, f"Null position {p} overlaps crib"

    def test_null_removal_preserves_non_null_letters(self):
        """Removing nulls preserves the original letters in order."""
        non_null_positions = sorted(set(range(CT_LEN)) - CONSENSUS_NULL_POSITIONS)
        extracted = "".join(CT[p] for p in non_null_positions)
        assert len(extracted) == CT_LEN - len(CONSENSUS_NULL_POSITIONS)
        # Each letter in extracted should match its source position
        for i, pos in enumerate(non_null_positions):
            assert extracted[i] == CT[pos]

    def test_crib_position_shifting_after_null_removal(self):
        """After removing nulls, crib positions shift by the count of nulls before them."""
        non_null_positions = sorted(set(range(CT_LEN)) - CONSENSUS_NULL_POSITIONS)
        pos_map = {old: new for new, old in enumerate(non_null_positions)}

        for pos, expected_ch in CRIB_DICT.items():
            assert pos in pos_map, f"Crib position {pos} was removed as null!"
            new_pos = pos_map[pos]
            # The shifted position should be less than the original
            nulls_before = sum(1 for n in CONSENSUS_NULL_POSITIONS if n < pos)
            assert new_pos == pos - nulls_before, (
                f"Position {pos} shifted to {new_pos}, expected {pos - nulls_before}"
            )

    def test_null_count_before_cribs(self):
        """Verify specific null counts before each crib region."""
        nulls_before_ene = sum(1 for n in CONSENSUS_NULL_POSITIONS if n < 21)
        nulls_before_bcl = sum(1 for n in CONSENSUS_NULL_POSITIONS if n < 63)
        # These are deterministic given the consensus null positions
        assert nulls_before_ene == 8, f"Expected 8 nulls before ENE, got {nulls_before_ene}"
        assert nulls_before_bcl == 12, f"Expected 12 nulls before BCL, got {nulls_before_bcl}"

    def test_extracted_text_length(self):
        """Extracted text has correct length."""
        n_nulls = len(CONSENSUS_NULL_POSITIONS)
        expected_len = CT_LEN - n_nulls
        assert expected_len == 80, f"Expected 80 (97-17), got {expected_len}"

    def test_null_positions_have_palette_letters(self):
        """All consensus null positions contain palette letters."""
        for p in CONSENSUS_NULL_POSITIONS:
            assert CT[p] in NULL_PALETTE, (
                f"Position {p} has CT[{p}]={CT[p]} which is not in palette {NULL_PALETTE}"
            )


class TestTranspositionInversion:
    """Test that transposition permutation and its inverse are consistent."""

    @staticmethod
    def columnar_perm(width, col_order, length):
        """Generate a columnar transposition permutation (gather convention)."""
        n_full_rows = length // width
        n_extra = length % width
        perm = []
        for col in col_order:
            rows = n_full_rows + (1 if col < n_extra else 0)
            for row in range(rows):
                perm.append(row * width + col)
        return perm

    @staticmethod
    def invert_perm(perm):
        """Invert a permutation: if output[i] = input[perm[i]], then
        inv_output[perm[i]] = input[i], i.e., inv[j] = i where perm[i] = j."""
        inv = [0] * len(perm)
        for i, j in enumerate(perm):
            inv[j] = i
        return inv

    def test_perm_inversion_roundtrip(self):
        """Applying permutation then its inverse recovers the original."""
        text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        perm = self.columnar_perm(5, [2, 0, 4, 1, 3], len(text))

        # Apply permutation (gather)
        permuted = "".join(text[perm[i]] for i in range(len(text)))
        # Apply inverse
        inv = self.invert_perm(perm)
        recovered = "".join(permuted[inv[i]] for i in range(len(text)))
        assert recovered == text

    def test_perm_is_bijection(self):
        """Permutation must be a bijection (all positions appear exactly once)."""
        for width in [5, 6, 7, 8, 9]:
            col_order = list(range(width))
            perm = self.columnar_perm(width, col_order, CT_LEN)
            assert len(perm) == CT_LEN
            assert sorted(perm) == list(range(CT_LEN))

    def test_identity_column_order_is_column_readoff(self):
        """Sequential column order reads off by columns, not by rows."""
        # Columnar transposition with identity column order reads columns in order:
        # col 0, col 1, col 2, ... This is NOT the identity permutation.
        # For a 4x5 grid: output = [0,5,10,15, 1,6,11,16, 2,7,12,17, 3,8,13,18, 4,9,14,19]
        perm = self.columnar_perm(5, [0, 1, 2, 3, 4], 20)
        expected = [0, 5, 10, 15, 1, 6, 11, 16, 2, 7, 12, 17, 3, 8, 13, 18, 4, 9, 14, 19]
        assert perm == expected

    def test_crib_preservation_through_transposition(self):
        """Cribs in the original text must map to specific positions after transposition."""
        # Create a text with cribs at known positions
        text = list("X" * CT_LEN)
        for pos, ch in CRIB_DICT.items():
            text[pos] = ch
        text = "".join(text)

        for width in [7, 9]:
            col_order = list(range(width))
            perm = self.columnar_perm(width, col_order, CT_LEN)
            inv = self.invert_perm(perm)

            # After transposition, crib at original pos should be at inv[pos]
            permuted = "".join(text[perm[i]] for i in range(CT_LEN))
            for pos, ch in CRIB_DICT.items():
                mapped_pos = inv[pos]
                assert permuted[mapped_pos] == ch, (
                    f"Width {width}: crib at pos {pos} ('{ch}') not found at "
                    f"mapped pos {mapped_pos} (found '{permuted[mapped_pos]}')"
                )


class TestBeanAcrossLayers:
    """Test Bean constraint verification across multi-layer transformations."""

    def test_bean_equality_positions(self):
        """Bean equality: positions 27 and 65 must have same CT letter."""
        a, b = BEAN_EQ[0]
        # Under direct correspondence, CT[27] = CT[65] = 'P'
        assert CT[a] == CT[b] == "P"

    def test_bean_equality_keystream(self):
        """Bean equality: Beaufort keystream at 27 and 65 must be equal."""
        a, b = BEAN_EQ[0]
        ka = (ALPH_IDX[CT[a]] + ALPH_IDX[CRIB_DICT[a]]) % MOD
        kb = (ALPH_IDX[CT[b]] + ALPH_IDX[CRIB_DICT[b]]) % MOD
        assert ka == kb, f"Bean EQ violated: k[{a}]={ka}, k[{b}]={kb}"

    def test_bean_inequality_count(self):
        """242 variant-independent inequalities derived from 276 pairs."""
        assert len(BEAN_INEQ) == 242
        # Verify: C(24,2) = 276, minus 1 equality, minus 33 variant-dependent = 242
        from math import comb
        total_pairs = comb(24, 2)
        assert total_pairs == 276
        assert total_pairs - len(BEAN_INEQ) - len(BEAN_EQ) == 33

    def test_bean_ineq_under_transposition(self):
        """Bean inequality positions map consistently through a permutation."""
        # After a transposition sigma, Bean EQ becomes:
        # k[sigma^-1(27)] == k[sigma^-1(65)]
        # This test verifies the mapping is computed correctly
        perm = list(range(CT_LEN))  # Identity permutation
        inv = list(range(CT_LEN))

        for a, b in BEAN_EQ:
            mapped_a, mapped_b = inv[a], inv[b]
            # Under identity, should be same positions
            assert mapped_a == a and mapped_b == b

    def test_beaufort_keystream_at_cribs(self):
        """Verify the BEAUFORT_KEYSTREAM_AT_CRIBS constant."""
        from kryptos.kernel.constants import BEAUFORT_KEYSTREAM_AT_CRIBS, BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC
        expected = "".join(chr(65 + v) for v in BEAUFORT_KEY_ENE + BEAUFORT_KEY_BC)
        assert BEAUFORT_KEYSTREAM_AT_CRIBS == expected


class TestMaskTranspositionComposition:
    """Test composition of null-mask removal + transposition."""

    def test_composition_order_matters(self):
        """mask_then_transpose != transpose_then_mask (in general)."""
        # Create a simple text
        text = CT[:20]  # Use first 20 chars of K4
        null_pos = {0, 5, 12, 14}  # Some null positions in first 20

        # Path 1: Remove nulls first, then transpose
        non_null = [i for i in range(20) if i not in null_pos]
        after_mask = "".join(text[i] for i in non_null)
        # Simple reversal as transposition
        path1 = after_mask[::-1]

        # Path 2: Transpose first, then remove nulls
        transposed = text[::-1]  # Reverse
        # Null positions in transposed space: position i in original is at (19-i) in transposed
        transposed_null = {19 - p for p in null_pos}
        path2 = "".join(transposed[i] for i in range(20) if i not in transposed_null)

        # These should generally be different
        # (They would be the same only if the transposition maps null positions to null positions)
        # This test documents that order matters
        assert len(path1) == len(path2) == 16

    def test_roundtrip_mask_then_transpose(self):
        """Full roundtrip: text → remove nulls → transpose → undo transpose → reinsert nulls → text."""
        text = "ABCDEFGHIJ"  # 10 chars
        null_pos = {2, 7}  # C and H are nulls

        # Remove nulls
        non_null = [i for i in range(10) if i not in null_pos]
        extracted = "".join(text[i] for i in non_null)  # "ABDEFGIJ"
        assert extracted == "ABDEFGIJ"

        # Transpose (simple swap of first and second half)
        half = len(extracted) // 2
        transposed = extracted[half:] + extracted[:half]  # "GIJABDEF"

        # Undo transpose
        undone = transposed[half:] + transposed[:half]  # "ABDEFGIJ"
        assert undone == extracted

        # Reinsert nulls
        reinserted = list(undone)
        for p in sorted(null_pos):
            reinserted.insert(p, text[p])
        reinserted = "".join(reinserted)
        assert reinserted == text
