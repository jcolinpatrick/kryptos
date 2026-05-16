"""Tests for kryptosbot/family_yield.py: pure policy module."""
from __future__ import annotations

import pytest

from kryptosbot.family_yield import (
    DEFAULT_POLICY,
    FamilyYieldPolicy,
    FamilyYieldStats,
    FamilyYieldVerdict,
    check_bypass_eligibility,
    classify_family_yield,
)


class TestDataclasses:
    def test_policy_defaults(self):
        p = FamilyYieldPolicy()
        assert p.min_trials == 50
        assert p.mean_score_below == 2.0
        assert p.require_zero_promotions is True
        assert p.require_best_below_store_threshold is True
        assert p.low_yield_trials == 50
        assert p.low_yield_mean_below == 2.0
        assert p.shadow_mode is False

    def test_policy_is_frozen(self):
        p = FamilyYieldPolicy()
        with pytest.raises((AttributeError, Exception)):
            p.min_trials = 999

    def test_default_policy_singleton(self):
        assert DEFAULT_POLICY == FamilyYieldPolicy()

    def test_stats_shape(self):
        s = FamilyYieldStats(
            family="encoding",
            trials=826,
            mean_score=0.78,
            best_score=7.0,
            promotions=0,
            eliminated=750,
        )
        assert s.family == "encoding"
        assert s.trials == 826

    def test_verdict_shape(self):
        s = FamilyYieldStats("x", 1, 0.0, 0.0, 0, 0)
        v = FamilyYieldVerdict(
            family="x",
            status="healthy",
            reasons=("ok",),
            stats=s,
        )
        assert v.status == "healthy"
        assert v.stats is s


def _stats(family="x", trials=100, mean=0.5, best=0.0, promotions=0, eliminated=0):
    return FamilyYieldStats(family, trials, mean, best, promotions, eliminated)


class TestClassifyFamilyYield:
    def test_insufficient_data_when_below_min_trials(self):
        s = _stats(trials=49, mean=0.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "insufficient_data"

    def test_boundary_min_trials_49_not_dead(self):
        # n=49 with same metrics that WOULD be dead at n=50 must stay healthy.
        s = _stats(trials=49, mean=0.5, best=5.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "insufficient_data"

    def test_boundary_min_trials_50_can_be_dead(self):
        s = _stats(trials=50, mean=0.5, best=5.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "empirically_dead"

    def test_empirically_dead_full_match(self):
        # The 4 audit families.
        s = _stats(family="encoding", trials=826, mean=0.78, best=7.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "empirically_dead"
        assert "n=826" in " ".join(v.reasons)

    def test_low_yield_when_mean_low_but_best_at_or_above_store(self):
        # best_score >= STORE_THRESHOLD (10) blocks empirically_dead; falls
        # back to low_yield because mean is still under the low_yield threshold.
        s = _stats(trials=200, mean=1.0, best=12.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "low_yield"

    def test_healthy_when_promotions_present(self):
        s = _stats(trials=200, mean=0.5, best=5.0, promotions=1)
        v = classify_family_yield(s)
        assert v.status == "healthy"

    def test_healthy_when_mean_above_low_yield_threshold(self):
        s = _stats(trials=200, mean=3.0, best=5.0, promotions=0)
        v = classify_family_yield(s)
        assert v.status == "healthy"

    def test_classifier_is_deterministic_for_same_inputs(self):
        s = _stats(trials=100, mean=0.5, best=5.0, promotions=0)
        a = classify_family_yield(s)
        b = classify_family_yield(s)
        assert a == b


class TestCheckBypassEligibility:
    def test_eligible_when_both_subfamily_and_signature_are_new(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="new_subfamily_v1",
            mechanism_signature="sig_abc",
            prior_subfamilies_in_family=frozenset({"old1", "old2"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is True
        assert reasons == ()

    def test_ineligible_when_subfamily_already_tried(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="old1",
            mechanism_signature="sig_abc",
            prior_subfamilies_in_family=frozenset({"old1"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is False
        assert any("subfamily" in r.lower() for r in reasons)

    def test_ineligible_when_signature_already_tried(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="new_subfamily_v1",
            mechanism_signature="sig_old",
            prior_subfamilies_in_family=frozenset({"old1"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is False
        assert any("signature" in r.lower() for r in reasons)

    def test_ineligible_when_both_already_tried(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="old1",
            mechanism_signature="sig_old",
            prior_subfamilies_in_family=frozenset({"old1"}),
            prior_mechanism_signatures_in_family=frozenset({"sig_old"}),
        )
        assert eligible is False
        assert len(reasons) == 2

    def test_subfamily_empty_string_is_ineligible(self):
        # Empty subfamily cannot prove structural novelty.
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="",
            mechanism_signature="sig_new",
            prior_subfamilies_in_family=frozenset(),
            prior_mechanism_signatures_in_family=frozenset(),
        )
        assert eligible is False
        assert any("empty subfamily" in r.lower() for r in reasons)

    def test_signature_empty_string_is_ineligible(self):
        eligible, reasons = check_bypass_eligibility(
            family="encoding",
            subfamily="new_subfam",
            mechanism_signature="",
            prior_subfamilies_in_family=frozenset(),
            prior_mechanism_signatures_in_family=frozenset(),
        )
        assert eligible is False
        assert any("empty mechanism signature" in r.lower() for r in reasons)
