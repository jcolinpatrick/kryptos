"""Tests for crib-paste detection in contracts._verify_against_kernel."""
from __future__ import annotations

import pytest

from kryptosbot.contracts import (
    _is_crib_paste_artifact,
    _non_crib_ngram_per_char,
)


# Spec §F: crib positions are 21-33 inclusive (EASTNORTHEAST, 13 chars)
# and 63-73 inclusive (BERLINCLOCK, 11 chars). 0-indexed.
CRIB_EAST_RANGE = (21, 34)   # half-open
CRIB_BERLIN_RANGE = (63, 74)


def _paste_pt(filler: str = "X") -> str:
    """Build a 97-char PT that pastes the canonical cribs and fills the
    remaining 73 positions with `filler` chars."""
    pt = [filler] * 97
    for i, ch in enumerate("EASTNORTHEAST"):
        pt[CRIB_EAST_RANGE[0] + i] = ch
    for i, ch in enumerate("BERLINCLOCK"):
        pt[CRIB_BERLIN_RANGE[0] + i] = ch
    return "".join(pt)


class TestNonCribNgramPerChar:
    def test_masks_crib_positions(self):
        pt = _paste_pt(filler="X")
        # 73 non-crib chars, all X — very low ngram score.
        score = _non_crib_ngram_per_char(pt)
        assert score < -5.0, f"all-X non-crib should be low, got {score}"

    def test_legitimate_english_non_crib_scores_higher(self):
        # Construct a PT with cribs at the canonical positions but
        # plausible-looking English everywhere else. The exact value depends
        # on the kernel ngram scorer's training corpus — we only assert
        # that English-looking text scores meaningfully higher than X-filler.
        pt = list("THEQUICKBROWNFOXJUMPSOVERLAZYDOGS" * 3)
        pt = pt[:97]
        for i, ch in enumerate("EASTNORTHEAST"):
            pt[CRIB_EAST_RANGE[0] + i] = ch
        for i, ch in enumerate("BERLINCLOCK"):
            pt[CRIB_BERLIN_RANGE[0] + i] = ch
        pt_str = "".join(pt)
        english_score = _non_crib_ngram_per_char(pt_str)
        paste_score = _non_crib_ngram_per_char(_paste_pt(filler="X"))
        assert english_score > paste_score

    def test_handles_empty_or_short_pt(self):
        # Helper must not crash on degenerate input.
        # _non_crib_ngram_per_char returns a sentinel value (very negative)
        # for inputs that don't conform to the 97-char shape.
        v_empty = _non_crib_ngram_per_char("")
        v_short = _non_crib_ngram_per_char("ABC")
        # Either returns a low sentinel value, or NaN.
        import math
        for v in (v_empty, v_short):
            assert math.isnan(v) or v <= -6.0


class TestIsCribPasteArtifact:
    def test_fires_at_threshold(self):
        # crib=24, non-crib ngram per-char at -6.2 (exact boundary).
        assert _is_crib_paste_artifact(
            "A" * 97,
            verified_crib=24,
            non_crib_ngram_per_char=-6.2,
        ) is True

    def test_does_not_fire_above_threshold(self):
        assert _is_crib_paste_artifact(
            "A" * 97,
            verified_crib=24,
            non_crib_ngram_per_char=-6.0,
        ) is False

    def test_does_not_fire_below_crib_24(self):
        assert _is_crib_paste_artifact(
            "A" * 97,
            verified_crib=23,
            non_crib_ngram_per_char=-10.0,
        ) is False

    def test_fires_for_paste_pt(self):
        # The 8 ledger 24/24 events all match this shape — X-filler around
        # canonical cribs.
        pt = _paste_pt(filler="X")
        ngram_pc = _non_crib_ngram_per_char(pt)
        assert ngram_pc <= -6.2
        assert _is_crib_paste_artifact(
            pt, verified_crib=24, non_crib_ngram_per_char=ngram_pc,
        ) is True
