"""Tests for the GAP-09 T2 co-location closure test (exact hypergeometric).

T2 asks: do a score-free null mask's positions co-locate with an INDEPENDENT
K4-indexed observable more than chance? Because the co-location count is
|M intersect T| for a random m-subset M of the free (non-crib) pool and a fixed
target set T (the observable expanded by +/-delta), the exact null is
Hypergeometric(population=|free pool|, successes=|T|, draws=m). No Monte Carlo.

Pins: deterministic co-location count, exact hypergeometric tail, the
crib-cannot-be-null guard, and the conservative no-overlap case.
"""
import pytest

from kryptos.admissibility.gap09_colocation import (
    colocation_count,
    gap09_t2_colocation_p,
    gap09_t2_colocation_p_matched,
    periodic_rule_masks,
)
from kryptos.kernel.constants import CRIB_POSITIONS


def test_colocation_count_exact_delta0():
    assert colocation_count({1, 2, 3}, {2, 5}, delta=0, n=10) == 1  # only 2


def test_colocation_count_with_tolerance():
    # observable {2,5} expanded by +/-1 -> {1,2,3,4,5,6}; mask {1,2,3} all inside
    assert colocation_count({1, 2, 3}, {2, 5}, delta=1, n=10) == 3


def test_hypergeometric_exact_value():
    # population F=4, target t=2, draws m=2, observed c=2:
    # P(X>=2) = C(2,2)C(2,0)/C(4,2) = 1/6
    p = gap09_t2_colocation_p({0, 1}, {0, 1}, n=4, crib_positions=frozenset(), delta=0)
    assert p == pytest.approx(1 / 6)


def test_no_overlap_gives_p_one():
    p = gap09_t2_colocation_p({0, 1}, {2, 3}, n=8, crib_positions=frozenset(), delta=0)
    assert p == 1.0  # c=0; P(X>=0)=1


def test_strong_overlap_is_significant():
    # mask exactly equals a small target inside a large free pool -> small p
    mask = {0, 1, 2, 3, 4}
    obs = {0, 1, 2, 3, 4}
    p = gap09_t2_colocation_p(mask, obs, n=97, crib_positions=frozenset(), delta=0)
    assert p < 1e-4


def test_crib_positions_excluded_from_pool_and_mask_guard():
    # a mask overlapping crib positions is malformed (cribs cannot be nulls)
    with pytest.raises(ValueError):
        gap09_t2_colocation_p({21, 22}, {21}, n=97,
                              crib_positions=frozenset({21, 22, 23}), delta=0)


def test_p_is_monotone_in_observed_count():
    # more co-location => smaller (more significant) p, same pool/target sizes
    obs = set(range(10))
    crib = frozenset()
    p_low = gap09_t2_colocation_p({0, 50, 60, 70}, obs, n=97, crib_positions=crib)   # c=1
    p_high = gap09_t2_colocation_p({0, 1, 2, 3}, obs, n=97, crib_positions=crib)      # c=4
    assert p_high < p_low


# ---------------------------------------------------------------------------
# Periodicity-matched null (fix for the uniform-null misspecification).
#
# The uniform-random hypergeometric null in gap09_t2_colocation_p assumes the
# mask is a uniform random subset of the free pool. When the mask comes from a
# STRUCTURED generative family (e.g. "every Nth position") and the observable is
# ALSO structured (carved line-breaks are quasi-periodic), shared structure
# inflates co-location with ZERO stego content -- the uniform null then reports
# spurious significance. The matched null asks the correct question: within the
# mask's OWN generative family, is this co-location special, or generic to the
# family?
# ---------------------------------------------------------------------------

def test_matched_null_not_significant_for_periodic_mask_vs_periodic_observable():
    # Documented defect: an "every-14, phase 0" mask vs a period-14 observable
    # fires below the 1e-6 closure gate under the uniform null, despite carrying
    # no stego content -- it is pure shared period+phase alignment.
    cribs = set(CRIB_POSITIONS)
    observable = [0, 14, 28, 42, 56, 70, 84]            # period-14 line-breaks
    observed_mask = [p for p in range(0, 97, 14) if p not in cribs]   # phase 0

    p_uniform = gap09_t2_colocation_p(
        observed_mask, observable, n=97, crib_positions=cribs, delta=0)
    assert p_uniform <= 1e-6, "precondition: uniform null exhibits the misspecification"

    # The fix: matched null over all phases of the SAME period must be unimpressed
    # (only the aligning phase co-locates -> a ~1/period coincidence, not signal).
    family = periodic_rule_masks(14, n=97, crib_positions=cribs)
    p_matched = gap09_t2_colocation_p_matched(
        observed_mask, observable, null_masks=family,
        n=97, crib_positions=cribs, delta=0)
    assert p_matched >= 0.05, (
        f"matched null must not call shared-periodicity significant; got {p_matched}")


def test_matched_null_fires_when_colocation_exceeds_family():
    # Positive control: the fix must RETAIN sensitivity. A mask whose co-location
    # genuinely exceeds every family member's must still produce a small p.
    cribs = set(CRIB_POSITIONS)
    free = [p for p in range(97) if p not in cribs]
    observable = [3, 7, 11, 40, 45, 50]                 # arbitrary (non-periodic)
    observed_mask = list(observable)                    # mask == observable: maximal
    non_obs = [p for p in free if p not in set(observable)]
    # 60 null masks, none intersecting the observable -> all co-locate 0 < observed
    family = [set(non_obs[i:i + 6]) for i in range(60)]
    p = gap09_t2_colocation_p_matched(
        observed_mask, observable, null_masks=family,
        n=97, crib_positions=cribs, delta=0)
    assert p <= 1.0 / (1 + len(family)) + 1e-12          # = 1/61, the minimum
    assert p < 0.05


def test_matched_null_p_is_one_when_no_colocation():
    cribs = set(CRIB_POSITIONS)
    observable = [3, 7, 11]
    observed_mask = [40, 45, 50]                         # disjoint from observable
    family = [{1, 2}, {80, 81}, {90, 91}]
    p = gap09_t2_colocation_p_matched(
        observed_mask, observable, null_masks=family,
        n=97, crib_positions=cribs, delta=0)
    assert p == 1.0


def test_matched_null_crib_guard():
    cribs = frozenset({21, 22, 23})
    with pytest.raises(ValueError):
        gap09_t2_colocation_p_matched(
            {21, 22}, {21}, null_masks=[{0, 1}],
            n=97, crib_positions=cribs, delta=0)


def test_periodic_rule_masks_structure():
    cribs = set(CRIB_POSITIONS)
    fam = periodic_rule_masks(14, n=97, crib_positions=cribs)
    assert len(fam) == 14                                # one mask per phase
    seen = set()
    for phase, mask in enumerate(fam):
        for pos in mask:
            assert pos % 14 == phase                     # phase-consistent
            assert pos not in cribs                       # crib-free (valid nulls)
            assert 0 <= pos < 97
            seen.add(pos)
    # the family partitions the free pool exactly
    assert seen == (set(range(97)) - cribs)
