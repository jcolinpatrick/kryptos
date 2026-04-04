"""Statistical testing utilities for K4 cryptanalysis.

Provides rigorous tools for answering "is this score significant?" —
the single most common question when evaluating sweep results.

Key functions:
  - permutation_test(): Empirical p-value for a score against a null distribution
  - fdr_correct(): Multiple testing correction (BH-FDR) for sweep results
  - null_score_distribution(): Generate null distribution by scoring random texts
  - score_significance(): Combined test: is this score significant given N configs?

These replace ad-hoc significance estimation scattered across scripts.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

import numpy as np

try:
    from statsmodels.stats.multitest import multipletests
    HAS_STATSMODELS = True
except ImportError:
    HAS_STATSMODELS = False

try:
    from resample.permutation import test as perm_test
    HAS_RESAMPLE = True
except ImportError:
    HAS_RESAMPLE = False


def null_score_distribution(
    n_trials: int = 10000,
    text_length: int = 97,
    seed: Optional[int] = None,
) -> np.ndarray:
    """Generate null crib-score distribution from random 26-letter texts.

    Returns array of crib scores (0-24) for random candidate texts.
    This is the empirical null for "how often does a random text
    match N crib positions by chance?"
    """
    from kryptos.kernel.constants import CRIB_DICT

    rng = np.random.default_rng(seed)
    positions = sorted(CRIB_DICT.keys())
    expected = np.array([ord(CRIB_DICT[p]) - 65 for p in positions], dtype=np.int8)
    pos_arr = np.array(positions, dtype=np.int32)

    scores = np.empty(n_trials, dtype=np.int32)
    for trial in range(n_trials):
        text = rng.integers(0, 26, size=text_length, dtype=np.int8)
        score = 0
        for i in range(len(pos_arr)):
            if pos_arr[i] < text_length and text[pos_arr[i]] == expected[i]:
                score += 1
        scores[trial] = score

    return scores


def empirical_pvalue(observed: int, null_distribution: np.ndarray) -> float:
    """Compute empirical p-value: fraction of null >= observed.

    Uses (count + 1) / (N + 1) to avoid p=0 and provide conservative
    estimate (Phipson & Smyth, 2010).
    """
    n = len(null_distribution)
    count = np.sum(null_distribution >= observed)
    return (count + 1) / (n + 1)


def permutation_test_scores(
    real_scores: np.ndarray,
    null_scores: np.ndarray,
    alternative: str = "greater",
) -> float:
    """Two-sample permutation test comparing real scores to null.

    Returns p-value for the hypothesis that real_scores are drawn
    from a distribution with higher mean than null_scores.

    If resample is available, uses its implementation (which handles
    edge cases and provides exact small-sample p-values). Otherwise
    falls back to a simple permutation test.
    """
    if HAS_RESAMPLE:
        # resample expects the test to be on a statistic
        # We test whether mean(real) > mean(null)
        def stat(x, y):
            return np.mean(x) - np.mean(y)

        # Use the permutation module properly
        from resample.permutation import test as rtest
        result = rtest(
            real_scores, null_scores,
            statistic=lambda x, y: np.mean(x) - np.mean(y),
            alternative=alternative,
        )
        return float(result)

    # Fallback: simple permutation test
    observed_diff = np.mean(real_scores) - np.mean(null_scores)
    combined = np.concatenate([real_scores, null_scores])
    n_real = len(real_scores)
    rng = np.random.default_rng(42)

    n_perm = 10000
    count = 0
    for _ in range(n_perm):
        rng.shuffle(combined)
        perm_diff = np.mean(combined[:n_real]) - np.mean(combined[n_real:])
        if perm_diff >= observed_diff:
            count += 1

    return (count + 1) / (n_perm + 1)


def fdr_correct(
    pvalues: List[float],
    alpha: float = 0.05,
    method: str = "fdr_bh",
) -> Tuple[np.ndarray, np.ndarray]:
    """Apply multiple testing correction.

    Returns:
        (reject_array, corrected_pvalues)
        reject_array[i] is True if hypothesis i should be rejected (significant)
        corrected_pvalues[i] is the adjusted p-value

    method: 'bonferroni', 'holm', 'fdr_bh' (Benjamini-Hochberg),
            'fdr_by' (Benjamini-Yekutieli)
    """
    pv = np.array(pvalues, dtype=np.float64)

    if HAS_STATSMODELS:
        reject, corrected, _, _ = multipletests(pv, alpha=alpha, method=method)
        return reject, corrected

    # Fallback: Bonferroni only (simple and conservative)
    n = len(pv)
    corrected = np.minimum(pv * n, 1.0)
    reject = corrected < alpha
    return reject, corrected


def score_significance(
    observed_score: int,
    n_configs_tested: int,
    null_distribution: Optional[np.ndarray] = None,
    n_null_trials: int = 100000,
    seed: int = 42,
) -> dict:
    """Comprehensive significance assessment for a single score.

    Answers: "I tested N configs and the best scored X/24.
    Is X significant, or expected by chance?"

    Returns dict with:
        - raw_pvalue: P(random >= observed)
        - bonferroni_pvalue: raw * n_configs_tested
        - fdr_threshold: effective significance threshold under BH-FDR
        - is_significant_bonferroni: bool
        - is_significant_fdr: bool
        - null_mean, null_std, null_max
        - expected_max_score: E[max(X_1, ..., X_n)] for n=n_configs_tested
    """
    if null_distribution is None:
        null_distribution = null_score_distribution(n_null_trials, seed=seed)

    raw_p = empirical_pvalue(observed_score, null_distribution)
    bonf_p = min(raw_p * n_configs_tested, 1.0)

    null_mean = float(np.mean(null_distribution))
    null_std = float(np.std(null_distribution))
    null_max = int(np.max(null_distribution))

    # Expected maximum of n iid draws from the null
    # For discrete distributions, compute E[max] exactly from CDF
    max_score = int(np.max(null_distribution))
    counts = np.bincount(null_distribution, minlength=max_score + 1)
    cdf = np.cumsum(counts) / len(null_distribution)
    # E[max of n draws] = sum_{k=0}^{max} (1 - CDF(k-1)^n)
    # simplified: E[max] = sum_{k=0}^{24} [1 - P(all < k)^n]
    expected_max = 0.0
    for k in range(max_score + 1):
        p_all_below = cdf[k] ** n_configs_tested if k < len(cdf) else 1.0
        expected_max += (1 - p_all_below)

    return {
        "observed": observed_score,
        "n_configs": n_configs_tested,
        "raw_pvalue": raw_p,
        "bonferroni_pvalue": bonf_p,
        "is_significant_bonferroni": bonf_p < 0.05,
        "is_significant_fdr": raw_p < (0.05 / np.log(max(n_configs_tested, 2))),
        "null_mean": null_mean,
        "null_std": null_std,
        "null_max": null_max,
        "expected_max_score": expected_max,
        "verdict": _verdict(observed_score, bonf_p, expected_max),
    }


def _verdict(score: int, bonf_p: float, expected_max: float) -> str:
    """Human-readable significance verdict."""
    if bonf_p < 0.001:
        return f"SIGNIFICANT (Bonferroni p={bonf_p:.2e})"
    if score <= expected_max + 0.5:
        return f"EXPECTED (score {score} <= expected max {expected_max:.1f})"
    if bonf_p < 0.05:
        return f"MARGINAL (Bonferroni p={bonf_p:.3f})"
    return f"NOT SIGNIFICANT (Bonferroni p={bonf_p:.3f})"
