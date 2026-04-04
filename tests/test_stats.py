"""Tests for statistical testing utilities."""
import numpy as np
import pytest

from kryptos.kernel.scoring.stats import (
    null_score_distribution,
    empirical_pvalue,
    fdr_correct,
    score_significance,
)


def test_null_distribution_shape():
    """Null distribution should have correct size and range."""
    null = null_score_distribution(n_trials=1000, seed=42)
    assert len(null) == 1000
    assert null.min() >= 0
    assert null.max() <= 24


def test_null_distribution_mean():
    """Mean of null distribution should be ~24/26 ≈ 0.923 per position."""
    null = null_score_distribution(n_trials=50000, seed=42)
    # Expected: 24 * (1/26) ≈ 0.923
    assert 0.5 < np.mean(null) < 1.5


def test_null_distribution_reproducible():
    """Same seed should give same distribution."""
    d1 = null_score_distribution(n_trials=100, seed=123)
    d2 = null_score_distribution(n_trials=100, seed=123)
    np.testing.assert_array_equal(d1, d2)


def test_empirical_pvalue_all_below():
    """If observed > all null values, p-value should be very small."""
    null = np.array([0, 0, 1, 1, 2, 2, 3, 3, 4, 4])
    p = empirical_pvalue(10, null)
    assert p < 0.15  # (0 + 1) / (10 + 1) = 0.091


def test_empirical_pvalue_all_above():
    """If observed < all null values, p-value should be ~1."""
    null = np.array([5, 6, 7, 8, 9, 10])
    p = empirical_pvalue(0, null)
    assert p > 0.8


def test_empirical_pvalue_exact():
    """Test exact computation."""
    null = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    p = empirical_pvalue(5, null)
    # 5 values >= 5 (5,6,7,8,9) -> (5+1)/(10+1) = 6/11
    assert abs(p - 6/11) < 1e-10


def test_fdr_correct_all_significant():
    """All very small p-values should survive correction."""
    pvals = [0.0001, 0.0002, 0.0003]
    reject, corrected = fdr_correct(pvals)
    assert all(reject)


def test_fdr_correct_none_significant():
    """All large p-values should not survive correction."""
    pvals = [0.5, 0.6, 0.7, 0.8]
    reject, corrected = fdr_correct(pvals)
    assert not any(reject)


def test_fdr_correct_mixed():
    """Mixed p-values should partially survive."""
    pvals = [0.001, 0.01, 0.5, 0.9]
    reject, corrected = fdr_correct(pvals)
    assert reject[0]  # smallest should survive
    assert not reject[-1]  # largest should not


def test_score_significance_low_score():
    """A score of 1 with 100 configs should not be significant."""
    result = score_significance(1, 100, n_null_trials=10000, seed=42)
    assert not result["is_significant_bonferroni"]
    assert result["verdict"].startswith(("NOT SIGNIFICANT", "EXPECTED"))


def test_score_significance_high_score():
    """A score of 20 with 10 configs should be highly significant."""
    result = score_significance(20, 10, n_null_trials=10000, seed=42)
    assert result["is_significant_bonferroni"]
    assert "SIGNIFICANT" in result["verdict"]


def test_score_significance_returns_expected_keys():
    """Result dict should have all expected keys."""
    result = score_significance(5, 1000, n_null_trials=1000, seed=42)
    expected_keys = {
        "observed", "n_configs", "raw_pvalue", "bonferroni_pvalue",
        "is_significant_bonferroni", "is_significant_fdr",
        "null_mean", "null_std", "null_max", "expected_max_score", "verdict",
    }
    assert set(result.keys()) == expected_keys
