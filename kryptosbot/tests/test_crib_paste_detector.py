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


from kryptosbot.contracts import _verify_against_kernel
from kryptosbot.models import WorkerContract, WorkerStatus


def _new_contract(pt: str, claimed_crib: int = 24) -> WorkerContract:
    return WorkerContract(
        hypothesis_id="test",
        best_plaintext=pt,
        crib_score=claimed_crib,
        bean_passed=True,
        score=float(claimed_crib),
        status=WorkerStatus.SUCCESS,
    )


class TestVerifyAgainstKernelIntegration:
    def test_paste_pt_is_classified_as_artifact(self):
        c = _new_contract(_paste_pt(filler="X"))
        _verify_against_kernel(c)
        # Zeroed signal fields.
        assert c.crib_score == 0
        assert c.bean_passed is False
        assert c.score == 0.0
        # Status forced to INCONCLUSIVE — NOT DISPROVED (which maps to
        # TheoryStatus.ELIMINATED in the controller).
        assert c.status == WorkerStatus.INCONCLUSIVE
        # Audit trail.
        assert c.fields_overwritten is True
        assert "crib_paste_artifact:v1" in (c.verification_error or "")
        assert c.raw_artifacts.get("artifact_class") == "crib_paste"
        snapshot = c.raw_artifacts.get("kernel_verified_before_artifact_filter")
        assert isinstance(snapshot, dict)
        assert snapshot.get("crib_score") == 24

    def test_paste_with_random_filler_is_classified_as_artifact(self):
        # Random-looking garbage around cribs (per the actual ledger events).
        import random
        rng = random.Random(0)
        chars = [chr(ord("A") + rng.randint(0, 25)) for _ in range(97)]
        for i, ch in enumerate("EASTNORTHEAST"):
            chars[CRIB_EAST_RANGE[0] + i] = ch
        for i, ch in enumerate("BERLINCLOCK"):
            chars[CRIB_BERLIN_RANGE[0] + i] = ch
        pt = "".join(chars)
        c = _new_contract(pt)
        _verify_against_kernel(c)
        # Random ASCII garbage scores below the ngram floor too — this is
        # the actual 8-event ledger signature.
        assert c.raw_artifacts.get("artifact_class") == "crib_paste"
        assert c.status == WorkerStatus.INCONCLUSIVE

    def test_non_paste_24_24_is_preserved(self):
        # English-looking PT with cribs at canonical positions: the
        # non-crib ngram floor should be ABOVE -6.2, so the detector
        # does NOT fire even if verified_crib == 24. We don't have a
        # known 24/24 legitimate plaintext (K4 is unsolved), so we
        # construct one with plausible English filler.
        pt = list("THEQUICKBROWNFOXJUMPSOVERLAZYDOG" * 4)
        pt = pt[:97]
        for i, ch in enumerate("EASTNORTHEAST"):
            pt[CRIB_EAST_RANGE[0] + i] = ch
        for i, ch in enumerate("BERLINCLOCK"):
            pt[CRIB_BERLIN_RANGE[0] + i] = ch
        c = _new_contract("".join(pt))
        _verify_against_kernel(c)
        # The Bean check may or may not pass for this random plaintext,
        # but the crib-paste detector must NOT fire.
        assert c.raw_artifacts.get("artifact_class") != "crib_paste"
        # Verification_error must NOT mention crib_paste.
        assert "crib_paste_artifact" not in (c.verification_error or "")

    def test_below_24_crib_score_untouched_by_detector(self):
        # 18/24 result: cribs not all matched; detector must not fire.
        pt = "A" * 97  # crib_score will be 0 from the kernel
        c = _new_contract(pt, claimed_crib=18)
        _verify_against_kernel(c)
        # Detector does not fire (verified_crib != 24).
        assert c.raw_artifacts.get("artifact_class") != "crib_paste"

    def test_detector_exception_fails_closed(self, monkeypatch):
        """If the detector raises, the contract must NOT be promoted as
        24/24. Spec §F: fail-closed."""
        import kryptosbot.contracts as ctr

        def _boom(*a, **kw):
            raise RuntimeError("synthetic detector failure")

        monkeypatch.setattr(ctr, "_is_crib_paste_artifact", _boom)
        c = _new_contract(_paste_pt(filler="X"))
        _verify_against_kernel(c)
        # Score must NOT show a promoted 24.
        assert c.crib_score == 0
        assert c.status == WorkerStatus.INCONCLUSIVE
