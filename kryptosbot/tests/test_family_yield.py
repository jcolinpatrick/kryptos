"""Tests for kryptosbot/family_yield.py: pure policy module."""
from __future__ import annotations

import pytest

from kryptosbot.family_yield import (
    DEFAULT_POLICY,
    FamilyYieldPolicy,
    FamilyYieldStats,
    FamilyYieldVerdict,
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
