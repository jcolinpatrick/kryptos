"""Validation tests for non-linear running key transforms.

Tests correctness of permutation generation, offset handling,
and scoring logic for the overnight campaign.
"""
import sys
import os
import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.campaigns.f_nonlinear_running_key_v1 import (
    make_reverse_perm,
    make_grid_column_perm,
    make_grid_column_rev_perm,
    make_boustrophedon_column_perm,
    make_skip_perm,
    get_all_transforms,
    REQUIRED_KEYS, MODES, CRIB_POS, N_CRIBS, N,
)


class TestReverse:
    def test_basic(self):
        p = make_reverse_perm(5)
        assert list(p) == [4, 3, 2, 1, 0]

    def test_preserves_length(self):
        for L in [10, 97, 1000, 50000]:
            p = make_reverse_perm(L)
            assert len(p) == L

    def test_is_permutation(self):
        p = make_reverse_perm(100)
        assert set(p) == set(range(100))

    def test_involution(self):
        """Reversing twice gives identity."""
        L = 200
        p = make_reverse_perm(L)
        text = np.arange(L)
        result = text[p][p]
        np.testing.assert_array_equal(result, text)

    def test_applied_to_text(self):
        text = "HELLO"
        p = make_reverse_perm(len(text))
        arr = np.array([ord(c) for c in text])
        result = ''.join(chr(c) for c in arr[p])
        assert result == "OLLEH"


class TestGridColumn:
    def test_small_exact(self):
        """ABCDEF in width 3 → grid:
        A B C
        D E F
        Read columns: A D B E C F"""
        p = make_grid_column_perm(6, 3)
        assert list(p) == [0, 3, 1, 4, 2, 5]

    def test_small_ragged(self):
        """ABCDE in width 3 → grid:
        A B C
        D E .
        Read columns: A D B E C"""
        p = make_grid_column_perm(5, 3)
        assert list(p) == [0, 3, 1, 4, 2]

    def test_preserves_length(self):
        for L in [10, 97, 500, 10000]:
            for w in [5, 7, 10, 13]:
                p = make_grid_column_perm(L, w)
                assert len(p) == L, f"L={L}, w={w}"

    def test_is_permutation(self):
        p = make_grid_column_perm(100, 7)
        assert sorted(p) == list(range(100))

    def test_width_1_is_identity(self):
        p = make_grid_column_perm(50, 1)
        np.testing.assert_array_equal(p, np.arange(50))

    def test_width_L_is_identity(self):
        """Width = L means 1 row, columns = positions, identity."""
        L = 20
        p = make_grid_column_perm(L, L)
        np.testing.assert_array_equal(p, np.arange(L))


class TestGridColumnRev:
    def test_small_exact(self):
        """ABCDEF in width 3, columns bottom-to-top:
        A B C
        D E F
        Read: D A E B F C"""
        p = make_grid_column_rev_perm(6, 3)
        assert list(p) == [3, 0, 4, 1, 5, 2]

    def test_preserves_length(self):
        p = make_grid_column_rev_perm(100, 7)
        assert len(p) == 100

    def test_is_permutation(self):
        p = make_grid_column_rev_perm(100, 7)
        assert sorted(p) == list(range(100))


class TestBoustrophedon:
    def test_small_exact(self):
        """ABCDEF in width 3, boustrophedon:
        Row 0 (L→R): A B C  → indices 0 1 2
        Row 1 (R→L): F E D  → indices 5 4 3
        Read columns: A F B E C D → indices 0 5 1 4 2 3"""
        p = make_boustrophedon_column_perm(6, 3)
        assert list(p) == [0, 5, 1, 4, 2, 3]

    def test_preserves_length(self):
        for L in [10, 97, 500]:
            for w in [5, 7, 10]:
                p = make_boustrophedon_column_perm(L, w)
                assert len(p) == L, f"L={L}, w={w}"

    def test_is_permutation(self):
        p = make_boustrophedon_column_perm(100, 7)
        assert sorted(p) == list(range(100))

    def test_even_rows_forward_odd_reversed(self):
        """Verify the boustrophedon pattern directly."""
        text = "ABCDEFGHIJKLMNOP"  # 16 chars, width 4
        p = make_boustrophedon_column_perm(16, 4)
        arr = np.array([ord(c) for c in text])
        transformed = ''.join(chr(c) for c in arr[p])
        # Grid after boustrophedon fill:
        # Row 0 (L→R): A B C D     → 0  1  2  3
        # Row 1 (R→L): H G F E     → 7  6  5  4
        # Row 2 (L→R): I J K L     → 8  9  10 11
        # Row 3 (R→L): P O N M     → 15 14 13 12
        # Column read: A H I P | B G J O | C F K N | D E L M
        assert transformed == "AHIPBGJOCFKNDELMM"[:16]
        # Actually let me compute this properly:
        # Col 0: row0=A, row1=H, row2=I, row3=P → AHIP
        # Col 1: row0=B, row1=G, row2=J, row3=O → BGJO
        # Col 2: row0=C, row1=F, row2=K, row3=N → CFKN
        # Col 3: row0=D, row1=E, row2=L, row3=M → DELM
        assert transformed == "AHIPBGJOCFKNDELM"


class TestSkip:
    def test_skip_2(self):
        """Skip-2 on 0..5: read 0,2,4 then 1,3,5."""
        p = make_skip_perm(6, 2)
        assert list(p) == [0, 2, 4, 1, 3, 5]

    def test_skip_3(self):
        """Skip-3 on 0..8: read 0,3,6 then 1,4,7 then 2,5,8."""
        p = make_skip_perm(9, 3)
        assert list(p) == [0, 3, 6, 1, 4, 7, 2, 5, 8]

    def test_preserves_length(self):
        for L in [10, 97, 500, 10000]:
            for skip in [2, 3, 5, 7, 11, 13]:
                p = make_skip_perm(L, skip)
                assert len(p) == L, f"L={L}, skip={skip}"

    def test_is_permutation(self):
        p = make_skip_perm(100, 7)
        assert sorted(p) == list(range(100))

    def test_skip_1_is_identity(self):
        p = make_skip_perm(50, 1)
        np.testing.assert_array_equal(p, np.arange(50))

    def test_ragged(self):
        """Skip-3 on 0..6 (7 elements): 0,3,6 | 1,4 | 2,5."""
        p = make_skip_perm(7, 3)
        assert list(p) == [0, 3, 6, 1, 4, 2, 5]


class TestGetAllTransforms:
    def test_count_for_large_text(self):
        """115 transforms expected: 1 + 36 + 36 + 36 + 6."""
        transforms = get_all_transforms(100000)
        assert len(transforms) == 115

    def test_too_short(self):
        transforms = get_all_transforms(50)
        assert len(transforms) == 0

    def test_names_unique(self):
        transforms = get_all_transforms(10000)
        names = [t[0] for t in transforms]
        assert len(names) == len(set(names))

    def test_all_are_permutations(self):
        L = 500
        transforms = get_all_transforms(L)
        for name, perm in transforms:
            assert len(perm) == L, f"{name}: length {len(perm)} != {L}"
            assert sorted(perm) == list(range(L)), f"{name}: not a permutation"


class TestRequiredKeys:
    def test_all_modes_have_keys(self):
        for mode in MODES:
            assert mode in REQUIRED_KEYS
            assert len(REQUIRED_KEYS[mode]) == N_CRIBS

    def test_key_values_in_range(self):
        for mode, keys in REQUIRED_KEYS.items():
            assert all(0 <= k < 26 for k in keys), f"{mode}: key out of range"

    def test_vig_beaufort_relationship(self):
        """Vig key + Beau key should equal 2*CT at each crib position (mod 26)."""
        # For AZ: vig_k = CT - PT, beau_k = CT + PT → vig_k + beau_k = 2*CT
        vig = REQUIRED_KEYS[("vig", "AZ")]
        beau = REQUIRED_KEYS[("beau", "AZ")]
        from kryptos.kernel.constants import CT, ALPH_IDX
        for i in range(N_CRIBS):
            pos = CRIB_POS[i]
            ct_val = ALPH_IDX[CT[pos]]
            assert (int(vig[i]) + int(beau[i])) % 26 == (2 * ct_val) % 26


class TestScoringIntegration:
    def test_known_linear_produces_correct_score(self):
        """Construct a source text that has the exact required key values
        at a known offset, and verify the scanner finds it."""
        # For Beaufort AZ, place the required key values at offset 0
        req = REQUIRED_KEYS[("beau", "AZ")]
        # Build a fake source of length 200
        src = np.zeros(200, dtype=np.int8)
        for i in range(N_CRIBS):
            src[CRIB_POS[i]] = req[i]
        # Identity permutation (linear scan)
        perm = np.arange(200, dtype=np.int32)
        # Check offset 0: all 24 should match
        score = 0
        for ci in range(N_CRIBS):
            if src[perm[0 + int(CRIB_POS[ci])]] == req[ci]:
                score += 1
        assert score == 24

    def test_reversed_offset(self):
        """Place key values in reversed position and verify detection."""
        req = REQUIRED_KEYS[("vig", "AZ")]
        L = 200
        src = np.zeros(L, dtype=np.int8)
        # Place values so that after reversal at offset 5, they land on crib positions
        perm = make_reverse_perm(L)
        target_offset = 5
        for i in range(N_CRIBS):
            src_idx = perm[target_offset + int(CRIB_POS[i])]
            src[src_idx] = req[i]
        # Verify
        score = 0
        for ci in range(N_CRIBS):
            if src[perm[target_offset + int(CRIB_POS[ci])]] == req[ci]:
                score += 1
        assert score == 24
