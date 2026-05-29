"""Tests for the family-matched reordering null (order-statistic-trap fix).

Background: `project_non_direct_alignment_null_orderstat_trap_2026_05_28`
established that a uniform-random-permutation null for crib-forcing ALIGNMENT
campaigns is methodologically broken (the naive
``p = P(rand-perm best >= real best)`` is inflated by order-statistic depth
mismatch + denominator dilution by cipher-incompatible perms). The fix is a
reordering-FAMILY-matched null: resample reorderings from the SAME grid-route
generator at HELD-OUT widths, and report ``null_beats_real`` (max-of-universe
vs max-of-universe) as the one honest number.

This module pins:
  * grid-route permutation generation (gather convention I[j] = CT[perm[j]]),
  * the family-matched null generator (held-out widths, same grammar),
  * the order-stat-trap-safe honest summary.
"""

import pytest

from kryptos.kernel.masking.route_null import (
    DEFAULT_ROUTES,
    grid_route_perms,
    family_matched_null_perms,
    honest_null_summary,
    mean_equality_permutation_p,
)

N = 97


# ── grid-route permutation generator ────────────────────────────────────────

def test_grid_route_perms_are_valid_permutations():
    out = list(grid_route_perms(6, n=N))
    assert out, "expected at least one route for width 6"
    for name, perm in out:
        assert sorted(perm) == list(range(N)), f"{name} is not a permutation of range({N})"


def test_grid_route_perms_cover_the_five_route_types():
    names = {name.split("_", 1)[1] for name, _ in grid_route_perms(6, n=N)}
    assert names == set(DEFAULT_ROUTES)


def test_grid_route_distinct_routes_differ():
    perms = {name: tuple(perm) for name, perm in grid_route_perms(6, n=N)}
    assert perms["grid6_colLR"] != perms["grid6_colRL"]
    assert perms["grid6_serpRow"] != perms["grid6_colLR"]


# ── family-matched null generator ───────────────────────────────────────────

def test_family_matched_null_excludes_real_widths():
    real_widths = {6}
    out = list(family_matched_null_perms(
        real_widths=real_widths, held_out_widths={5, 7}, n=N))
    assert out, "expected held-out route perms"
    for name, perm in out:
        width = int(name[len("grid"):].split("_", 1)[0])
        assert width not in real_widths, f"{name} leaks a real-universe width"
        assert sorted(perm) == list(range(N))


def test_family_matched_null_has_expected_cardinality():
    held = {5, 7, 9}
    out = list(family_matched_null_perms(
        real_widths={6}, held_out_widths=held, n=N))
    # one perm per (held-out width x route type); no identity/reverse pollution
    assert len(out) == len(held) * len(DEFAULT_ROUTES)
    assert all(name.startswith("grid") for name, _ in out)


def test_family_matched_null_refuses_overlap_with_real_widths():
    # held-out widths must be DISJOINT from real widths or it is not a null
    with pytest.raises(ValueError):
        list(family_matched_null_perms(
            real_widths={6, 7}, held_out_widths={7, 9}, n=N))


# ── honest summary (order-stat-trap-safe) ───────────────────────────────────

def test_honest_summary_positive_control_real_beats_null():
    s = honest_null_summary(real_best_total=100.0, null_best_totals=[10.0, 20.0, 30.0])
    assert s.null_beats_real is False          # real (100) is ABOVE null max (30)
    assert s.null_max_total == 30.0
    assert s.n_consistent_null == 3
    assert s.p_conditioned_on_consistent_null == 0.0


def test_honest_summary_negative_control_null_beats_real():
    s = honest_null_summary(real_best_total=15.0, null_best_totals=[10.0, 20.0, 30.0])
    assert s.null_beats_real is True           # null max (30) >= real (15)
    assert s.p_conditioned_on_consistent_null == pytest.approx(2 / 3)


def test_honest_summary_drops_incompatible_null_perms():
    # None entries = cipher-incompatible perms (no residue-consistent key);
    # they must be DROPPED, not counted as evidence for the real value.
    s = honest_null_summary(
        real_best_total=25.0,
        null_best_totals=[None, 30.0, None, 10.0, None])
    assert s.n_consistent_null == 2            # only the two non-None draws count
    assert s.null_max_total == 30.0
    assert s.null_beats_real is True


def test_honest_summary_no_consistent_null_is_conservative():
    s = honest_null_summary(real_best_total=50.0, null_best_totals=[None, None])
    assert s.n_consistent_null == 0
    assert s.null_beats_real is False          # nothing in the null can beat it...
    assert s.p_conditioned_on_consistent_null is None  # ...but we cannot infer
    assert "non-inferential" in s.note.lower() or "no consistent" in s.note.lower()


def test_honest_summary_no_real_cell():
    s = honest_null_summary(real_best_total=None, null_best_totals=[10.0, 20.0])
    assert s.null_beats_real is False          # no real value to beat
    assert s.p_conditioned_on_consistent_null is None


# ── mean-equality permutation test (real-vs-null distribution identity) ──────

def test_mean_equality_identical_samples_gives_p_one():
    # identical distributions => observed |mean diff| = 0 => every shuffle ties
    p = mean_equality_permutation_p([1.0, 2.0, 3.0, 4.0], [1.0, 2.0, 3.0, 4.0],
                                    trials=500, seed=1)
    assert p == 1.0


def test_mean_equality_separated_samples_gives_small_p():
    # fully separated means => only the original split reaches the observed gap
    p = mean_equality_permutation_p([10.0, 11.0, 12.0], [0.0, 1.0, 2.0],
                                    trials=4000, seed=1)
    assert p <= 0.2


def test_mean_equality_handles_empty_sample():
    assert mean_equality_permutation_p([], [1.0, 2.0], trials=100, seed=1) is None
    assert mean_equality_permutation_p([1.0], [], trials=100, seed=1) is None
