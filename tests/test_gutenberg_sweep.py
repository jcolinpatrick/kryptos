"""Tests for e_gutenberg_sweep_01 computational kernel."""
import sys
import os
import re
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, BEAN_EQ, BEAN_INEQ

# ── Constants for mask testing ───────────────────────────────────────
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
CORE_5 = {38, 39, 45, 87, 93}
REMAINING_11 = [40, 41, 42, 43, 44, 55, 56, 88, 94, 95, 96]


def _all_masks():
    from itertools import combinations
    masks = []
    for extra in combinations(REMAINING_11, 2):
        masks.append(sorted(CONSENSUS_NULLS | CORE_5 | set(extra)))
    return masks


class TestMaskGeneration:
    def test_mask_count(self):
        assert len(_all_masks()) == 55

    def test_each_mask_has_24_positions(self):
        for mask in _all_masks():
            assert len(mask) == 24
            assert len(set(mask)) == 24  # all unique

    def test_all_masks_unique(self):
        masks = [tuple(m) for m in _all_masks()]
        assert len(set(masks)) == 55

    def test_no_crib_in_any_mask(self):
        crib_positions = set(CRIB_DICT.keys())
        for mask in _all_masks():
            assert set(mask).isdisjoint(crib_positions), (
                f"Mask {mask} overlaps crib positions {set(mask) & crib_positions}"
            )

    def test_bean_positions_survive(self):
        """Bean EQ positions (27, 65) must never be null."""
        for mask in _all_masks():
            assert 27 not in mask
            assert 65 not in mask


class TestLayoutCollapse:
    """Verify that 55 masks collapse to 3 crib-scoring layouts."""

    def test_group1_invariant(self):
        """Group 1 CT73 positions must be identical across all 55 masks."""
        g1_positions_seen = set()
        for mask in _all_masks():
            mask_set = set(mask)
            ct73_pos = tuple(
                p - sum(1 for n in mask_set if n < p)
                for p in range(21, 34)
            )
            g1_positions_seen.add(ct73_pos)
        assert len(g1_positions_seen) == 1

    def test_group1_positions_are_13_to_25(self):
        """Group 1 should map to CT73 positions 13-25 (8 nulls before pos 21)."""
        mask = _all_masks()[0]
        mask_set = set(mask)
        ct73_pos = [p - sum(1 for n in mask_set if n < p) for p in range(21, 34)]
        assert ct73_pos == list(range(13, 26))

    def test_group2_has_3_layouts(self):
        g2_layouts = set()
        for mask in _all_masks():
            mask_set = set(mask)
            ct73_pos = tuple(
                p - sum(1 for n in mask_set if n < p)
                for p in range(63, 74)
            )
            g2_layouts.add(ct73_pos)
        assert len(g2_layouts) == 3

    def test_layout_counts_6_28_21(self):
        from collections import Counter
        counter = Counter()
        for mask in _all_masks():
            nb63 = sum(1 for n in mask if n < 63)
            counter[nb63] += 1
        assert sorted(counter.values()) == [6, 21, 28]

    def test_group2_layouts_are_consecutive(self):
        """Each Group 2 layout should be 11 consecutive CT73 positions."""
        for mask in _all_masks():
            mask_set = set(mask)
            ct73_pos = [
                p - sum(1 for n in mask_set if n < p)
                for p in range(63, 74)
            ]
            # Check consecutive
            for i in range(1, len(ct73_pos)):
                assert ct73_pos[i] == ct73_pos[i-1] + 1


class TestExpectedKeyValues:
    def test_beaufort_keystream_matches_known(self):
        """Beaufort keystream at cribs must match JLJODEGKUKKKLOCGGBGOKTRU."""
        known = "JLJODEGKUKKKLOCGGBGOKTRU"
        ct_num = [ALPH_IDX[c] for c in CT]
        for idx, pos in enumerate(sorted(CRIB_DICT.keys())):
            pt_num = ALPH_IDX[CRIB_DICT[pos]]
            beau_key = (ct_num[pos] + pt_num) % 26
            assert beau_key == ALPH_IDX[known[idx]], (
                f"pos {pos}: expected {known[idx]}={ALPH_IDX[known[idx]]}, got {beau_key}"
            )

    def test_vigenere_key_at_pos21(self):
        ct_num = ALPH_IDX[CT[21]]  # F=5
        pt_num = ALPH_IDX['E']      # E=4
        assert (ct_num - pt_num) % 26 == 1  # B

    def test_beaufort_key_at_pos21(self):
        ct_num = ALPH_IDX[CT[21]]  # F=5
        pt_num = ALPH_IDX['E']      # E=4
        assert (ct_num + pt_num) % 26 == 9  # J

    def test_var_beaufort_key_at_pos21(self):
        ct_num = ALPH_IDX[CT[21]]  # F=5
        pt_num = ALPH_IDX['E']      # E=4
        assert (pt_num - ct_num) % 26 == 25  # Z


class TestScoring:
    def test_perfect_score_crafted_text(self):
        """A text crafted to match all 24 Beaufort crib keys should score 24."""
        ct_num = [ALPH_IDX[c] for c in CT]
        text_chars = [0] * 97
        for pos, ch in CRIB_DICT.items():
            pt_num = ALPH_IDX[ch]
            text_chars[pos] = (ct_num[pos] + pt_num) % 26  # Beaufort
        score = 0
        for pos in sorted(CRIB_DICT.keys()):
            expected = (ct_num[pos] + ALPH_IDX[CRIB_DICT[pos]]) % 26
            if text_chars[pos] == expected:
                score += 1
        assert score == 24

    def test_random_text_low_score(self):
        import random
        random.seed(42)
        text_num = [random.randint(0, 25) for _ in range(500)]
        ct_num = [ALPH_IDX[c] for c in CT]
        scores = []
        for offset in range(500 - 97 + 1):
            score = 0
            for pos in sorted(CRIB_DICT.keys()):
                expected = (ct_num[pos] + ALPH_IDX[CRIB_DICT[pos]]) % 26
                if text_num[offset + pos] == expected:
                    score += 1
            scores.append(score)
        avg = sum(scores) / len(scores)
        assert avg < 3, f"Average score {avg} too high for random"


class TestModelBCorrectness:
    """Verify split-crib optimization produces correct results.

    The G1>=7 pre-filter prunes 99.7% of offsets for speed.
    This means best_score is exact for scores >= SIGNAL_THRESHOLD (18)
    and a lower bound for scores below it. The guarantee:
    - If naive best >= 18, optimized MUST find it exactly
    - Optimized best <= naive best (never overestimates)
    """

    def _get_imports(self):
        sweep_dir = str(Path(__file__).parent.parent / "scripts" / "running_key")
        if sweep_dir not in sys.path:
            sys.path.insert(0, sweep_dir)
        from e_gutenberg_sweep_01 import (
            scan_model_b, LAYOUTS, G1_CT73, VARIANTS, SIGNAL_THRESHOLD,
        )
        return scan_model_b, LAYOUTS, G1_CT73, VARIANTS, SIGNAL_THRESHOLD

    def test_optimized_never_overestimates(self):
        """Optimized best_score must be <= naive best_score."""
        import random
        random.seed(123)
        scan_model_b, LAYOUTS, G1_CT73, VARIANTS, _ = self._get_imports()

        text_alpha = ''.join(chr(random.randint(0, 25) + 65) for _ in range(500))
        result = scan_model_b(("test", "test", text_alpha))
        opt_best = result["best_score"]

        text_num = bytearray(ALPH_IDX[c] for c in text_alpha)
        naive_best = 0
        for _vname, g1_exp, g2_exp in VARIANTS:
            for layout in LAYOUTS:
                checks = list(zip(G1_CT73, g1_exp)) + \
                         list(zip(layout["g2_ct73"], g2_exp))
                for offset in range(500 - 73 + 1):
                    score = sum(
                        1 for pos, exp in checks
                        if offset + pos < 500 and text_num[offset + pos] == exp
                    )
                    if score > naive_best:
                        naive_best = score

        assert opt_best <= naive_best, f"Overestimate: opt {opt_best} > naive {naive_best}"

    def test_exact_above_signal_threshold(self):
        """If naive finds score >= 18, optimized must find it too.

        We test with a crafted text that scores exactly 18 at offset 0
        under Beaufort: 7 G1 matches + 11 G2 matches = 18.
        """
        scan_model_b, LAYOUTS, G1_CT73, VARIANTS, SIGNAL_THRESHOLD = self._get_imports()

        # Build a 200-char text. At offset 0, make:
        # - exactly 7 of 13 Group 1 positions match (Beaufort)
        # - all 11 Group 2 positions match (Beaufort, layout 0)
        text_num = bytearray(99 for _ in range(200))  # fill with non-matching

        # Beaufort expected values
        _, g1_beau, g2_beau = VARIANTS[1]  # beaufort
        g2_ct73 = LAYOUTS[0]["g2_ct73"]

        # Set 7 of 13 Group 1 positions to match
        for i in range(7):
            text_num[G1_CT73[i]] = g1_beau[i]

        # Set all 11 Group 2 positions to match (layout 0)
        for i in range(11):
            text_num[g2_ct73[i]] = g2_beau[i]

        text_alpha = ''.join(chr(b + 65) if b < 26 else 'X' for b in text_num)

        result = scan_model_b(("test", "crafted", text_alpha))
        assert result["best_score"] >= 18, (
            f"Failed to find crafted score 18: got {result['best_score']}"
        )


class TestModelAIntegration:
    """Integration test using cached Gutenberg text."""

    @pytest.mark.skipif(
        not Path("/data/tmp/gutenberg_cache/pg10.txt").exists(),
        reason="King James Bible not cached"
    )
    def test_kjb_best_score(self):
        """Prior scan showed KJB best = 8/24. Verify consistency."""
        raw = Path("/data/tmp/gutenberg_cache/pg10.txt").read_text(errors="replace")
        alpha = re.sub(r'[^A-Za-z]', '', raw).upper()
        assert len(alpha) > CT_LEN

        sweep_dir = str(Path(__file__).parent.parent / "scripts" / "running_key")
        if sweep_dir not in sys.path:
            sys.path.insert(0, sweep_dir)
        from e_gutenberg_sweep_01 import scan_model_a
        result = scan_model_a(("PG10", "King James Bible", alpha))
        assert result["best_score"] >= 7, f"Score {result['best_score']} below expected"
        assert result["best_score"] <= 12, f"Score {result['best_score']} unexpectedly high"
