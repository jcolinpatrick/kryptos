"""Family-matched reordering null for crib-forcing ALIGNMENT campaigns.

The ``non_direct_alignment`` model posits an outer layer that REORDERS the
carved CT before an inner decrypt. Campaigns that crib-force an inner key over
a universe of reorderings need a null to answer "is the best real reordering
better than chance?". The naive null -- uniform-random 97-permutations -- is
methodologically broken (``project_non_direct_alignment_null_orderstat_trap_2026_05_28``):

  1. Order-statistic depth mismatch: the real "best" is a max over the k
     residue-consistent reorderings, while each uniform draw contributes one
     perm's best (max over 1).
  2. Denominator dilution: uniform perms are overwhelmingly cipher-INCOMPATIBLE
     (no residue-consistent key); counting them as non-exceeding draws inflates
     the real value's apparent rank.

The fix is a reordering-FAMILY-matched null: resample reorderings from the SAME
grid-route generator the real universe is drawn from, but at HELD-OUT grid
widths (disjoint from the real widths). Same generative grammar => same block
structure => comparable residue-consistency rate, so the decisive comparison is
a fair max-of-universe vs max-of-universe: ``null_beats_real``.

Pure stdlib, kernel-side. Gather convention throughout: a permutation ``perm``
defines the reordered intermediate ``I`` by ``I[j] = CT[perm[j]]`` (matches
``scripts/campaigns/f_non_direct_alignment_cribforce_2026_05_28.py``).
"""

from __future__ import annotations

import random
from dataclasses import dataclass

# The five grid-route families used by the 2026-05-25/28 alignment universe.
DEFAULT_ROUTES: tuple[str, ...] = ("colLR", "colRL", "serpRow", "antidiag", "spiralCW")

DEFAULT_N = 97


def grid_route_perms(width, n=DEFAULT_N, routes=DEFAULT_ROUTES):
    """Yield ``(name, perm)`` for each grid route over an ``n``-cell, ``width``-wide grid.

    ``perm`` is a permutation of ``range(n)`` in gather convention
    (``I[j] = CT[perm[j]]``). Grid cells beyond ``n`` ("ghosts") are dropped, so
    the result is always a valid permutation of exactly ``n`` indices. Route
    names are ``grid{width}_{route}`` to keep width recoverable downstream.
    """
    rows = -(-n // width)  # ceil
    grid = [[None] * width for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(width):
            if idx < n:
                grid[r][c] = idx
                idx += 1

    def drop_ghosts(seq):
        return [x for x in seq if x is not None]

    builders = {
        "colLR": lambda: [grid[r][c] for c in range(width) for r in range(rows)],
        "colRL": lambda: [grid[r][c] for c in range(width - 1, -1, -1) for r in range(rows)],
        "serpRow": _serp_row(grid, rows, width),
        "antidiag": _antidiag(grid, rows, width),
        "spiralCW": _spiral_cw(grid, rows, width),
    }
    for route in routes:
        if route not in builders:
            raise ValueError(f"unknown route {route!r}; known: {sorted(builders)}")
        perm = drop_ghosts(builders[route]())
        yield (f"grid{width}_{route}", perm)


def _serp_row(grid, rows, width):
    def build():
        out = []
        for r in range(rows):
            rng = range(width) if r % 2 == 0 else range(width - 1, -1, -1)
            for c in rng:
                out.append(grid[r][c])
        return out
    return build


def _antidiag(grid, rows, width):
    def build():
        out = []
        for s in range(rows + width - 1):
            for r in range(rows):
                c = s - r
                if 0 <= c < width:
                    out.append(grid[r][c])
        return out
    return build


def _spiral_cw(grid, rows, width):
    def build():
        top, bot, left, right = 0, rows - 1, 0, width - 1
        out = []
        while top <= bot and left <= right:
            for c in range(left, right + 1):
                out.append(grid[top][c])
            top += 1
            for r in range(top, bot + 1):
                out.append(grid[r][right])
            right -= 1
            if top <= bot:
                for c in range(right, left - 1, -1):
                    out.append(grid[bot][c])
                bot -= 1
            if left <= right:
                for r in range(bot, top - 1, -1):
                    out.append(grid[r][left])
                left += 1
        return out
    return build


def family_matched_null_perms(*, real_widths, held_out_widths, n=DEFAULT_N,
                              routes=DEFAULT_ROUTES):
    """Yield ``(name, perm)`` grid-route perms at HELD-OUT widths only.

    The family-matched null: same generative grammar (grid routes) as the real
    reordering universe, but drawn from ``held_out_widths`` which MUST be
    disjoint from ``real_widths``. Refuses overlap loudly -- a null that reuses
    a real width is not a null.
    """
    real = set(real_widths)
    held = set(held_out_widths)
    overlap = real & held
    if overlap:
        raise ValueError(
            f"held_out_widths overlaps real_widths at {sorted(overlap)}; "
            "a family-matched null must use widths disjoint from the real universe")
    for width in sorted(held):
        yield from grid_route_perms(width, n=n, routes=routes)


@dataclass(frozen=True)
class NullSummary:
    """Order-stat-trap-safe summary of a real-vs-null alignment comparison."""

    null_beats_real: bool
    real_best_total: float | None
    null_max_total: float | None
    n_consistent_null: int
    p_conditioned_on_consistent_null: float | None
    note: str


_NONINFERENTIAL_NOTE = (
    "null_beats_real (max-of-universe vs max-of-universe) is the decisive "
    "number. p_conditioned_on_consistent_null is over residue-consistent null "
    "perms only and is NON-INFERENTIAL (it does not correct the order-statistic "
    "depth or the family-match). See order-stat-trap memo 2026-05-28."
)


def honest_null_summary(real_best_total, null_best_totals):
    """Summarize a family-matched null comparison without the order-stat trap.

    Args:
        real_best_total: best (largest) n-gram total over residue-consistent
            real reorderings, or ``None`` if the real universe had no consistent
            cell.
        null_best_totals: per-null-perm best totals. ``None`` entries denote
            cipher-INCOMPATIBLE perms (no residue-consistent key) and are
            DROPPED, never counted as evidence for the real value.

    Returns:
        ``NullSummary``. ``null_beats_real`` is ``True`` iff there is at least
        one consistent null perm whose total is >= the real best -- a fair
        max-of-universe vs max-of-universe test. Conservative defaults: with no
        consistent null perm or no real cell, ``null_beats_real`` is ``False``
        (nothing demonstrably beats the real value) and the conditioned p is
        ``None`` (we cannot infer).
    """
    consistent = [x for x in null_best_totals if x is not None]
    n_consistent = len(consistent)
    null_max = max(consistent) if consistent else None

    if real_best_total is None:
        return NullSummary(
            null_beats_real=False, real_best_total=None, null_max_total=null_max,
            n_consistent_null=n_consistent, p_conditioned_on_consistent_null=None,
            note="no residue-consistent real cell; nothing to beat. " + _NONINFERENTIAL_NOTE,
        )

    if not consistent:
        return NullSummary(
            null_beats_real=False, real_best_total=real_best_total, null_max_total=None,
            n_consistent_null=0, p_conditioned_on_consistent_null=None,
            note="no consistent null perms; cannot infer enrichment. " + _NONINFERENTIAL_NOTE,
        )

    null_beats_real = null_max >= real_best_total
    ge = sum(1 for x in consistent if x >= real_best_total)
    p_conditioned = ge / n_consistent
    return NullSummary(
        null_beats_real=null_beats_real,
        real_best_total=real_best_total,
        null_max_total=null_max,
        n_consistent_null=n_consistent,
        p_conditioned_on_consistent_null=p_conditioned,
        note=_NONINFERENTIAL_NOTE,
    )


def mean_equality_permutation_p(real_totals, null_totals, *, trials=10000, seed=20260529):
    """Two-sample permutation p-value for H0: real and null have equal means.

    This is the INFERENTIAL companion to ``honest_null_summary``: where
    ``null_beats_real`` answers "is the single best real reordering beaten by the
    null max?", this answers "are the real and null per-reordering distributions
    statistically the same?". A large p (near 1) means the real family is
    indistinguishable from the family-matched null -- the decisive evidence that
    a marginal max-of-universe edge is order-statistic noise, not signal.

    Statistic: ``|mean(real) - mean(null)|``. Pool, shuffle, re-split at the
    original sizes, count shuffles whose statistic >= observed. Deterministic
    given ``seed``. Returns ``None`` if either sample is empty.
    """
    a = [x for x in real_totals if x is not None]
    b = [x for x in null_totals if x is not None]
    if not a or not b:
        return None
    na = len(a)
    observed = abs(sum(a) / na - sum(b) / len(b))
    pooled = a + b
    rng = random.Random(seed)
    ge = 0
    for _ in range(trials):
        rng.shuffle(pooled)
        sa = pooled[:na]
        sb = pooled[na:]
        stat = abs(sum(sa) / na - sum(sb) / len(sb))
        if stat >= observed - 1e-12:
            ge += 1
    return ge / trials
