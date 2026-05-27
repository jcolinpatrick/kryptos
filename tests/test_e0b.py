"""GAP-03: E0b extended-position distance statistic + calibrated nulls.

Validates the operationalized E0b side-effect against Bean's published anchor
(10 KRYPTOS-set crib positions, sum dist 21, mean 2.1, MC p ~ 1/5520).
"""
from __future__ import annotations

from kryptos.kernel.constants import CT, CRIB_DICT
from kryptos.kernel.scoring.e0b import (
    KRYPTOS_SET,
    e0b_statistic,
    e0b_bean_pvalue,
    e0b_candidate_pvalue,
)


def test_e0b_statistic_reproduces_bean_anchor():
    """The statistic on the disclosed cribs must reproduce Bean's numbers."""
    stat = e0b_statistic(CRIB_DICT, CT)
    assert stat.count == 10
    assert stat.sum_dist == 21
    assert abs(stat.mean_dist - 2.1) < 1e-9
    assert all(CRIB_DICT[p] in KRYPTOS_SET for p in stat.positions)


def test_e0b_bean_pvalue_reproduces_1_over_5520():
    """CT-permutation null on the crib K-set positions must reproduce Bean's
    p ~ 1/5520 (1.81e-4); bracket it generously to absorb MC noise."""
    res = e0b_bean_pvalue(CT, CRIB_DICT, n_mc=200_000, seed=42)
    assert res.count == 10
    assert res.obs_sum == 21
    assert 5e-5 < res.p_value < 5e-4


def test_candidate_pvalue_positive_control_is_significant():
    """A candidate whose K-set positions sit AT the CT (distance 0) must score
    far in the left tail of the crib-pinned null."""
    pt = CT  # PT == CT => every K-set position has distance 0
    stat, p = e0b_candidate_pvalue(pt, CT, CRIB_DICT, n_mc=20_000, seed=1)
    assert stat == 0.0
    assert p < 0.01


def test_candidate_pvalue_random_is_not_significant():
    """A random crib-pinned candidate must NOT be significant (guards against a
    null that fires on anything)."""
    import random
    rng = random.Random(7)
    chars = [
        CRIB_DICT[i] if i in CRIB_DICT else chr(65 + rng.randrange(26))
        for i in range(len(CT))
    ]
    pt = "".join(chars)
    stat, p = e0b_candidate_pvalue(pt, CT, CRIB_DICT, n_mc=20_000, seed=2)
    assert p > 0.01
