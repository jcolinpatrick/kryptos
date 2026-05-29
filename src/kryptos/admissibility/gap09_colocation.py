"""GAP-09 T2 closure test: exact co-location significance of a null mask vs an
INDEPENDENT K4-indexed observable.

See `docs/REAL_K4_GAP09_ACQUISITION_SPEC_2026_05_29.md`. GAP-09 (null-mask / stego
evidence) closes only via an independent-observable alignment at p<=1e-6. This
module makes that test executable the moment an observable is acquired.

Key fact (why no Monte Carlo): the co-location count is the intersection of a
random m-subset of the free (non-crib) position pool with a FIXED target set T
(the observable, expanded by +/-delta, intersected with the free pool). That count
is exactly Hypergeometric(population=|free pool|, successes=|T|, draws=m), so the
tail probability P(X >= c) is an exact hypergeometric survival value computed with
`math.comb`. This resolves p<=1e-6 exactly, with no sampling floor.

Pure stdlib. Positions are 0-indexed K4 character indices in [0, n).

NULL-MODEL CAVEAT (important). ``gap09_t2_colocation_p`` assumes the mask is a
UNIFORM RANDOM subset of the free pool. That null is MISSPECIFIED when the mask
is drawn from a STRUCTURED generative family (e.g. a periodic "every Nth
position" rule) AND the observable is itself structured: carved line-breaks are
quasi-periodic, so a periodic mask co-locates with them by shared period+phase
ALONE, with zero stego content, yet the uniform null reports that overlap as
highly significant (a period-14 mask vs period-14 line-breaks fires below the
1e-6 gate). For any structured mask family, use ``gap09_t2_colocation_p_matched``
with a null family from the SAME grammar (``periodic_rule_masks`` builds the
periodic family) -- it asks whether the co-location is special WITHIN the family
rather than against a uniform draw the mask was never sampled from.
"""

from __future__ import annotations

from math import comb
from typing import Iterable


def _expand(observable: Iterable[int], delta: int, n: int) -> set[int]:
    """Observable expanded by +/-delta, clipped to [0, n)."""
    out: set[int] = set()
    for j in observable:
        for d in range(-delta, delta + 1):
            p = j + d
            if 0 <= p < n:
                out.add(p)
    return out


def colocation_count(mask: Iterable[int], observable: Iterable[int],
                     *, delta: int = 0, n: int = 97) -> int:
    """Number of mask positions within +/-delta of some observable position."""
    if delta < 0:
        raise ValueError("delta must be >= 0")
    target = _expand(observable, delta, n)
    return sum(1 for i in mask if i in target)


def _hypergeom_sf(c: int, population: int, successes: int, draws: int) -> float:
    """P(X >= c) for X ~ Hypergeometric(population, successes, draws), exact.

    X = number of 'successes' (target positions) in a uniform draw of `draws`
    items from `population` (the free pool). Uses exact integer binomials.
    """
    if c <= 0:
        return 1.0
    lo = max(0, draws - (population - successes))
    hi = min(draws, successes)
    if c > hi:
        return 0.0
    denom = comb(population, draws)
    num = 0
    for x in range(max(c, lo), hi + 1):
        num += comb(successes, x) * comb(population - successes, draws - x)
    return num / denom


def gap09_t2_colocation_p(mask: Iterable[int], observable: Iterable[int], *,
                          n: int = 97, crib_positions: Iterable[int],
                          delta: int = 0) -> float:
    """Exact one-sided p-value that the mask co-locates with the observable.

    Null: a random mask of size |mask| drawn uniformly from the free pool
    (`{0..n-1} \\ crib_positions`). Returns P(co-location count >= observed).

    Raises ValueError if the mask intersects a crib position (cribs cannot be
    nulls -- a malformed mask, per GAP-09 doctrine).
    """
    if delta < 0:
        raise ValueError("delta must be >= 0")
    crib = set(crib_positions)
    mask_set = set(mask)
    bad = mask_set & crib
    if bad:
        raise ValueError(
            f"mask intersects crib positions {sorted(bad)}; cribs cannot be nulls")

    free = set(range(n)) - crib
    population = len(free)
    m = len(mask_set & free)            # draws (mask positions in the free pool)
    target_free = _expand(observable, delta, n) & free
    successes = len(target_free)
    c = len(mask_set & target_free)     # observed co-location among free positions
    return _hypergeom_sf(c, population, successes, m)


def periodic_rule_masks(period: int, *, n: int = 97,
                        crib_positions: Iterable[int],
                        phases: Iterable[int] | None = None) -> list[set[int]]:
    """The crib-filtered 'every-`period`-th position' mask for each phase.

    For phase ``p`` the mask is ``{i in [0, n) : i % period == p and i not in
    crib_positions}``. This is the matched-null FAMILY for a periodic ("every
    Nth") generative mask: members differ only by phase, so a co-location with a
    periodic observable that exceeds the family reflects structure, not the
    shared period. Defaults to all phases ``range(period)`` (which partition the
    free pool exactly).
    """
    if period <= 0:
        raise ValueError("period must be >= 1")
    crib = set(crib_positions)
    phase_list = list(range(period)) if phases is None else list(phases)
    return [
        {i for i in range(n) if i % period == p and i not in crib}
        for p in phase_list
    ]


def gap09_t2_colocation_p_matched(mask: Iterable[int], observable: Iterable[int],
                                  *, null_masks: Iterable[Iterable[int]],
                                  n: int = 97, crib_positions: Iterable[int],
                                  delta: int = 0) -> float:
    """Empirical co-location p-value under a CALLER-DECLARED matched null family.

    Unlike ``gap09_t2_colocation_p`` (uniform-random null), this asks: among masks
    drawn from the SAME generative family as ``mask`` (supplied as ``null_masks``),
    what fraction co-locate with the observable at least as strongly as ``mask``?
    Use this whenever the mask comes from a structured family (e.g. periodic), so
    shared structure with a structured observable is not mistaken for signal.

    Returns the conservative Phipson-Smyth estimate
    ``(1 + #{M' : coloc(M', O) >= coloc(mask, O)}) / (1 + N)`` over the N null
    masks -- in (0, 1], never zero. ``mask`` need not appear in ``null_masks``;
    the add-one accounts for the observed mask itself.

    Raises ValueError if ``mask`` intersects a crib position (cribs cannot be
    nulls, per GAP-09 doctrine).
    """
    if delta < 0:
        raise ValueError("delta must be >= 0")
    crib = set(crib_positions)
    mask_set = set(mask)
    bad = mask_set & crib
    if bad:
        raise ValueError(
            f"mask intersects crib positions {sorted(bad)}; cribs cannot be nulls")

    observed = colocation_count(mask_set, observable, delta=delta, n=n)
    nulls = [set(mn) for mn in null_masks]
    at_least = sum(
        1 for mn in nulls
        if colocation_count(mn, observable, delta=delta, n=n) >= observed
    )
    return (1 + at_least) / (1 + len(nulls))
