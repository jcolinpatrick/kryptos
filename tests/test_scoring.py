"""Tests for scoring modules."""
import pytest

from kryptos.kernel.scoring.ic import ic, ic_by_position, ic_score
from kryptos.kernel.scoring.crib_score import (
    score_cribs, score_cribs_detailed,
    is_above_noise, is_storable, is_signal, is_breakthrough,
)
from kryptos.kernel.scoring.aggregate import score_candidate, ScoreBreakdown
from kryptos.kernel.constants import CT, IC_ENGLISH, IC_RANDOM


class TestIC:
    def test_ct_ic_range(self):
        ct_ic = ic(CT)
        assert 0.030 < ct_ic < 0.045

    def test_uniform_text(self):
        # Single letter repeated should have IC near 1.0
        text_ic = ic("A" * 100)
        assert text_ic > 0.99

    def test_random_like(self):
        # Use CT which has near-random IC
        ct_ic = ic(CT)
        assert abs(ct_ic - IC_RANDOM) < 0.01

    def test_ic_score_normalized(self):
        assert ic_score("A" * 100) == 1.0


class TestCribScore:
    def test_detailed_returns_all_fields(self):
        result = score_cribs_detailed("A" * 97)
        assert "score" in result
        assert "total" in result
        assert "ene_score" in result
        assert "bc_score" in result
        assert "classification" in result

    def test_classification_noise(self):
        result = score_cribs_detailed("A" * 97)
        assert result["classification"] == "noise"

    def test_thresholds(self):
        assert not is_above_noise(5)
        assert is_above_noise(7)
        assert not is_storable(9)
        assert is_storable(10)
        assert not is_signal(17)
        assert is_signal(18)
        assert not is_breakthrough(24, bean_pass=False)
        assert is_breakthrough(24, bean_pass=True)


class TestAggregateScoring:
    def test_score_candidate_returns_breakdown(self):
        result = score_candidate("A" * 97)
        assert isinstance(result, ScoreBreakdown)
        assert result.crib_total == 24

    def test_summary_string(self):
        result = score_candidate("A" * 97)
        summary = result.summary
        assert "cribs=" in summary
        assert "IC=" in summary
        assert "bean=" in summary

    def test_to_dict(self):
        result = score_candidate("A" * 97)
        d = result.to_dict()
        assert "crib_score" in d
        assert "ic_value" in d
        assert "is_breakthrough" in d
