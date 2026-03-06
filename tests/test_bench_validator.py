"""Tests for bench.validator — plausibility scoring and confidence gating."""
from __future__ import annotations

import pytest

from bench.validator import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_NONE,
    MARGIN_SMALL,
    MIN_SCORABLE_LEN,
    QUADGRAM_FLOOR,
    QUADGRAM_HIGH,
    QUADGRAM_LOW,
    WORDLIST_HIGH,
    WORDLIST_LOW,
    PlausibilityResult,
    _compute_plausibility,
    _derive_confidence,
    quadgram_score,
    validate_candidate,
    validate_result,
    wordlist_hit_rate,
)


# ══════════════════════════════════════════════════════════════════════════
# Quadgram scoring
# ══════════════════════════════════════════════════════════════════════════


class TestQuadgramScore:
    """Quadgram per-char scores for known texts."""

    def test_strong_english(self):
        """The Sinkov textbook plaintext must score well above QUADGRAM_HIGH."""
        qg = quadgram_score("WEAREDISCOVEREDSAVEYOURSELF")
        assert qg is not None
        assert qg > QUADGRAM_HIGH, f"Expected > {QUADGRAM_HIGH}, got {qg}"

    def test_moderate_english(self):
        qg = quadgram_score("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")
        assert qg is not None
        assert qg > QUADGRAM_LOW

    def test_gibberish_scores_low(self):
        qg = quadgram_score("XQZJKVBWMFPGYLDTNHRSCIEUOA")
        assert qg is not None
        assert qg < QUADGRAM_LOW

    def test_short_text_returns_none(self):
        assert quadgram_score("AB") is None
        assert quadgram_score("ABC") is None

    def test_empty_returns_none(self):
        assert quadgram_score("") is None

    def test_non_alpha_stripped(self):
        qg1 = quadgram_score("HELLO WORLD")
        qg2 = quadgram_score("HELLOWORLD")
        assert qg1 == qg2


# ══════════════════════════════════════════════════════════════════════════
# Wordlist hit rate
# ══════════════════════════════════════════════════════════════════════════


class TestWordlistHitRate:
    def test_english_sentence(self):
        rate = wordlist_hit_rate("WEAREDISCOVEREDSAVEYOURSELF")
        # "WE ARE DISCOVERED SAVE YOUR SELF" — most words should match
        assert rate > 0.5

    def test_gibberish_low(self):
        rate = wordlist_hit_rate("XQZJKVBWMFPGYLDTNHRSCIEUOA")
        assert rate < WORDLIST_HIGH

    def test_empty_returns_zero(self):
        assert wordlist_hit_rate("") == 0.0

    def test_single_word(self):
        rate = wordlist_hit_rate("HELLO")
        assert rate > 0.0


# ══════════════════════════════════════════════════════════════════════════
# Plausibility computation
# ══════════════════════════════════════════════════════════════════════════


class TestComputePlausibility:
    def test_perfect_signals(self):
        # Both at ceiling
        p = _compute_plausibility(QUADGRAM_HIGH, WORDLIST_HIGH)
        assert p >= 0.99

    def test_floor_signals(self):
        p = _compute_plausibility(QUADGRAM_FLOOR, 0.0)
        assert p == 0.0

    def test_no_quadgram(self):
        # Falls back to wordlist only
        p = _compute_plausibility(None, WORDLIST_HIGH)
        assert p >= 0.99

    def test_no_quadgram_zero_wordlist(self):
        p = _compute_plausibility(None, 0.0)
        assert p == 0.0

    def test_mid_range(self):
        mid_qg = (QUADGRAM_HIGH + QUADGRAM_FLOOR) / 2
        mid_wl = WORDLIST_HIGH / 2
        p = _compute_plausibility(mid_qg, mid_wl)
        assert 0.2 < p < 0.8


# ══════════════════════════════════════════════════════════════════════════
# Confidence derivation
# ══════════════════════════════════════════════════════════════════════════


class TestDeriveConfidence:
    def test_high_plausibility_high_confidence(self):
        conf, val = _derive_confidence(0.8, -4.0, 0.7, 50, margin=5.0)
        assert conf == CONFIDENCE_HIGH
        assert val is True

    def test_medium_plausibility(self):
        conf, val = _derive_confidence(0.5, -5.0, 0.4, 50, margin=5.0)
        assert conf == CONFIDENCE_MEDIUM
        assert val is True

    def test_low_plausibility(self):
        conf, val = _derive_confidence(0.15, -6.0, 0.1, 50, margin=5.0)
        assert conf == CONFIDENCE_LOW
        assert val is False

    def test_very_low_plausibility(self):
        conf, val = _derive_confidence(0.05, -7.0, 0.05, 50, margin=5.0)
        assert conf == CONFIDENCE_NONE
        assert val is False

    def test_small_margin_reduces_confidence(self):
        # High plausibility but tiny margin → medium
        conf, val = _derive_confidence(0.8, -4.0, 0.7, 50, margin=0.5)
        assert conf == CONFIDENCE_MEDIUM

    def test_small_margin_low_plausibility(self):
        conf, val = _derive_confidence(0.3, -5.5, 0.3, 50, margin=0.5)
        assert conf == CONFIDENCE_LOW
        assert val is False

    def test_short_text_caps_at_medium(self):
        # Even with great scores, short text → medium max
        conf, val = _derive_confidence(0.9, -3.5, 0.9, 5, margin=10.0)
        assert conf == CONFIDENCE_MEDIUM

    def test_short_text_low_plausibility(self):
        conf, val = _derive_confidence(0.3, -5.5, 0.2, 5, margin=10.0)
        assert conf == CONFIDENCE_LOW
        assert val is False

    def test_hard_fail_below_floor(self):
        conf, val = _derive_confidence(0.5, -7.0, 0.4, 50, margin=5.0)
        assert conf == CONFIDENCE_NONE
        assert val is False

    def test_hard_fail_both_low(self):
        conf, val = _derive_confidence(0.3, -5.8, 0.2, 50, margin=5.0)
        assert conf == CONFIDENCE_LOW
        assert val is False

    def test_no_margin(self):
        # margin=None should not reduce confidence
        conf, val = _derive_confidence(0.8, -4.0, 0.7, 50, margin=None)
        assert conf == CONFIDENCE_HIGH
        assert val is True


# ══════════════════════════════════════════════════════════════════════════
# validate_candidate integration
# ══════════════════════════════════════════════════════════════════════════


class TestValidateCandidate:
    def test_classic_vigenere_deceptive_validates_high(self):
        """The textbook Vigenère DECEPTIVE plaintext must validate high."""
        vr = validate_candidate(
            "WEAREDISCOVEREDSAVEYOURSELF",
            best_score=100.0,
            runner_up_score=50.0,
        )
        assert vr.confidence == CONFIDENCE_HIGH
        assert vr.validated is True
        assert vr.plausibility > 0.6
        assert vr.quadgram_per_char is not None
        assert vr.quadgram_per_char > QUADGRAM_HIGH

    def test_gibberish_not_validated(self):
        """Random letter soup must NOT validate."""
        vr = validate_candidate("XQZJKVBWMFPGYLDTNHRSCIEUOA")
        assert vr.validated is False
        assert vr.confidence in (CONFIDENCE_LOW, CONFIDENCE_NONE)

    def test_bait_case_not_high_confidence(self):
        """A substitution-garbled text with a bait crib planted should
        not produce high-confidence validation.

        This simulates tier-3 adversarial: the ciphertext contains
        EASTNORTHEAST embedded in otherwise random-looking substitution
        output.  The overall plaintext quality is still garbage.
        """
        # 40 chars of substitution garbage with EASTNORTHEAST in the middle
        garbage = "QXVZBJWMFPGYL" + "EASTNORTHEAST" + "DNHRSCIEUOAXQ"
        vr = validate_candidate(garbage)
        assert vr.confidence != CONFIDENCE_HIGH
        # The bait crib alone shouldn't push plausibility above 0.7
        assert vr.plausibility < 0.7

    def test_margin_present_when_scores_given(self):
        vr = validate_candidate(
            "THISISATEST",
            best_score=10.0,
            runner_up_score=9.5,
        )
        assert vr.margin is not None
        assert vr.margin == pytest.approx(0.5)

    def test_margin_absent_when_no_scores(self):
        vr = validate_candidate("THISISATEST")
        assert vr.margin is None

    def test_empty_text(self):
        vr = validate_candidate("")
        assert vr.validated is False
        assert vr.confidence in (CONFIDENCE_LOW, CONFIDENCE_NONE)


# ══════════════════════════════════════════════════════════════════════════
# validate_result (dict-level integration)
# ══════════════════════════════════════════════════════════════════════════


class TestValidateResult:
    def test_success_result_gets_validation(self):
        result = {
            "case_id": "test1",
            "status": "success",
            "predicted_plaintext": "WEAREDISCOVEREDSAVEYOURSELF",
            "top_candidates": [
                {"score": 100.0, "plaintext": "WEAREDISCOVEREDSAVEYOURSELF", "method": "m1"},
                {"score": 50.0, "plaintext": "XXXYYY", "method": "m2"},
            ],
        }
        validate_result(result)
        v = result["validation"]
        assert v["validated"] is True
        assert v["confidence"] == CONFIDENCE_HIGH
        assert "plausibility" in v
        assert "quadgram_per_char" in v
        assert "margin" in v
        assert v["margin"] == pytest.approx(50.0)

    def test_error_result_not_validated(self):
        result = {
            "case_id": "err",
            "status": "error",
            "error": "something broke",
            "predicted_plaintext": "",
        }
        validate_result(result)
        v = result["validation"]
        assert v["validated"] is False
        assert v["confidence"] == CONFIDENCE_NONE

    def test_no_results_not_validated(self):
        result = {
            "case_id": "empty",
            "status": "no_results",
            "predicted_plaintext": "",
        }
        validate_result(result)
        v = result["validation"]
        assert v["validated"] is False

    def test_single_candidate_no_margin(self):
        result = {
            "case_id": "solo",
            "status": "success",
            "predicted_plaintext": "WEAREDISCOVEREDSAVEYOURSELF",
            "top_candidates": [
                {"score": 100.0, "plaintext": "WEAREDISCOVEREDSAVEYOURSELF", "method": "m1"},
            ],
        }
        validate_result(result)
        v = result["validation"]
        assert v.get("margin") is None
        assert v["validated"] is True


# ══════════════════════════════════════════════════════════════════════════
# PlausibilityResult serialization
# ══════════════════════════════════════════════════════════════════════════


class TestPlausibilityResult:
    def test_to_dict_complete(self):
        pr = PlausibilityResult(
            quadgram_per_char=-4.5,
            wordlist_coverage=0.7,
            plausibility=0.8,
            confidence=CONFIDENCE_HIGH,
            validated=True,
            margin=5.0,
        )
        d = pr.to_dict()
        assert d["plausibility"] == 0.8
        assert d["confidence"] == "high"
        assert d["validated"] is True
        assert d["wordlist_coverage"] == 0.7
        assert d["quadgram_per_char"] == -4.5
        assert d["margin"] == 5.0

    def test_to_dict_minimal(self):
        pr = PlausibilityResult()
        d = pr.to_dict()
        assert d["validated"] is False
        assert "quadgram_per_char" not in d
        assert "margin" not in d


# ══════════════════════════════════════════════════════════════════════════
# Schema round-trip (validation field persists through JSONL)
# ══════════════════════════════════════════════════════════════════════════


class TestSchemaRoundTrip:
    def test_validation_survives_serialization(self):
        from bench.schema import BenchmarkResult

        r = BenchmarkResult(
            case_id="rt",
            status="success",
            validation={"plausibility": 0.85, "confidence": "high", "validated": True,
                        "wordlist_coverage": 0.7},
        )
        d = r.to_dict()
        assert "validation" in d
        assert d["validation"]["confidence"] == "high"

        r2 = BenchmarkResult.from_dict(d)
        assert r2.validation == d["validation"]

    def test_no_validation_field_omitted(self):
        from bench.schema import BenchmarkResult

        r = BenchmarkResult(case_id="x", status="error")
        d = r.to_dict()
        assert "validation" not in d
