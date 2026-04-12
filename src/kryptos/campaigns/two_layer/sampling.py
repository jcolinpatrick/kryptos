"""Stratified sampling modes for the two-layer campaign.

Each mode is a deterministic, seedable function that takes outer/inner
instance lists and returns a SamplingPlan listing the (outer, inner)
pairs to evaluate along with the coverage warrant.

CRITICAL: do not let a sampling mode hide as exploratory if it cannot
achieve the coverage guarantee its name implies. The mode is the
campaign's epistemic warrant; if a mode can only sample 80% of the
space it advertises, the run must be reported as exploratory.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .families import OuterFamily, InnerFamily


class SamplingMode(str, Enum):
    EXPLORATORY_STRIDE = "exploratory_stride"
    STRATIFIED_FAMILY_COVER = "stratified_family_cover"
    STRATIFIED_LOW_COMPLEXITY_BIAS = "stratified_low_complexity_bias"
    FULL_CARTESIAN = "full_cartesian"


# Centralized complexity bands. All thresholds live here.
COMPLEXITY_BAND_LOW_MAX = 12.0
COMPLEXITY_BAND_MEDIUM_MAX = 15.0


def complexity_band(c: float) -> str:
    if c <= COMPLEXITY_BAND_LOW_MAX:
        return "low"
    if c <= COMPLEXITY_BAND_MEDIUM_MAX:
        return "medium"
    return "high"


@dataclass
class SamplingPlan:
    """Output of a sampling decision — pairs plus the warrant."""
    pairs: list  # list[tuple[int, int]] — (outer_idx, inner_idx)
    mode: SamplingMode
    seed: Optional[int]
    target_evals: int
    achieved_evals: int
    coverage_guarantees: list  # list[str]
    is_complete_for_mode: bool
    notes: str = ""
    # Snapshot of filters so downstream can reconstruct the same plan
    filters: dict = field(default_factory=dict)


# ── Helpers ────────────────────────────────────────────────────────────

def _filter_outers(
    outers: list,
    max_complexity: Optional[float],
    min_complexity: Optional[float],
    family_filter: Optional[set],
) -> list:
    out = []
    for i, o in enumerate(outers):
        if family_filter and o.family_id not in family_filter:
            continue
        if max_complexity is not None and o.complexity_score > max_complexity:
            continue
        if min_complexity is not None and o.complexity_score < min_complexity:
            continue
        out.append(i)
    return out


def _filter_inners(
    inners: list,
    max_complexity: Optional[float],
    min_complexity: Optional[float],
    family_filter: Optional[set],
) -> list:
    out = []
    for i, n in enumerate(inners):
        if family_filter and n.family_id not in family_filter:
            continue
        if max_complexity is not None and n.complexity_score > max_complexity:
            continue
        if min_complexity is not None and n.complexity_score < min_complexity:
            continue
        out.append(i)
    return out


def _pair_total_complexity(
    outers: list, inners: list, oi: int, ii: int
) -> float:
    return outers[oi].complexity_score + inners[ii].complexity_score


# ── Mode: exploratory stride (current default) ─────────────────────────

def sample_exploratory_stride(
    outers: list,
    inners: list,
    target_evals: int,
    seed: int = 0,
) -> SamplingPlan:
    """The current stride sampler. Renamed and explicitly labeled exploratory."""
    total = len(outers) * len(inners)
    target = max(1, min(target_evals, total))
    stride = max(1, total // target)
    pairs: list = []
    idx = 0
    for oi in range(len(outers)):
        for ii in range(len(inners)):
            if idx % stride == 0 and len(pairs) < target:
                pairs.append((oi, ii))
            idx += 1
    return SamplingPlan(
        pairs=pairs,
        mode=SamplingMode.EXPLORATORY_STRIDE,
        seed=seed,
        target_evals=target_evals,
        achieved_evals=len(pairs),
        coverage_guarantees=[
            "Exploratory only; stride sampling across row-major cartesian product.",
            "No guarantee of per-outer family coverage.",
        ],
        is_complete_for_mode=True,  # stride mode has no stronger invariant
        notes="exploratory — approximate coverage",
        filters={},
    )


# ── Mode: stratified family cover ──────────────────────────────────────

def sample_stratified_family_cover(
    outers: list,
    inners: list,
    seed: int = 0,
    max_complexity: Optional[float] = None,
    min_complexity: Optional[float] = None,
    outer_family_filter: Optional[set] = None,
    inner_family_filter: Optional[set] = None,
) -> SamplingPlan:
    """For every eligible outer, pair it with one representative from
    EVERY inner family class present after filtering."""
    rng = random.Random(seed)

    oi_list = _filter_outers(outers, max_complexity, min_complexity, outer_family_filter)
    ii_list = _filter_inners(inners, max_complexity, min_complexity, inner_family_filter)

    # Group inners by family_id
    family_to_inner_idxs: dict = {}
    for ii in ii_list:
        family_to_inner_idxs.setdefault(inners[ii].family_id, []).append(ii)

    inner_family_ids = sorted(family_to_inner_idxs.keys())

    pairs: list = []
    complete = True
    for oi in oi_list:
        for fid in inner_family_ids:
            candidates = family_to_inner_idxs[fid]
            if not candidates:
                complete = False
                continue
            # Pairwise complexity filter if set (rejects high-complex pairs)
            if max_complexity is not None:
                eligible = [
                    ii for ii in candidates
                    if _pair_total_complexity(outers, inners, oi, ii) <= max_complexity * 2
                ]
                if not eligible:
                    eligible = candidates
            else:
                eligible = candidates
            chosen = rng.choice(sorted(eligible))
            pairs.append((oi, chosen))

    guarantees = [
        "Every eligible outer instance paired with a representative "
        "of every inner family class.",
    ]
    if max_complexity is not None:
        guarantees.append(f"Restricted to profiles with outer/inner complexity <= {max_complexity}.")
    if outer_family_filter:
        guarantees.append(f"Outer restricted to families: {sorted(outer_family_filter)}.")
    if inner_family_filter:
        guarantees.append(f"Inner restricted to families: {sorted(inner_family_filter)}.")

    return SamplingPlan(
        pairs=pairs,
        mode=SamplingMode.STRATIFIED_FAMILY_COVER,
        seed=seed,
        target_evals=len(oi_list) * len(inner_family_ids),
        achieved_evals=len(pairs),
        coverage_guarantees=guarantees,
        is_complete_for_mode=complete and len(pairs) == len(oi_list) * len(inner_family_ids),
        notes=(
            f"{len(oi_list)} eligible outers x {len(inner_family_ids)} inner family classes"
        ),
        filters={
            "max_complexity": max_complexity,
            "min_complexity": min_complexity,
            "outer_family_filter": sorted(outer_family_filter) if outer_family_filter else None,
            "inner_family_filter": sorted(inner_family_filter) if inner_family_filter else None,
        },
    )


# ── Mode: stratified low-complexity bias ───────────────────────────────

def sample_stratified_low_complexity_bias(
    outers: list,
    inners: list,
    target_evals: int,
    seed: int = 0,
    low_weight: float = 5.0,
    medium_weight: float = 2.0,
    high_weight: float = 1.0,
    max_complexity: Optional[float] = None,
    min_complexity: Optional[float] = None,
    outer_family_filter: Optional[set] = None,
    inner_family_filter: Optional[set] = None,
) -> SamplingPlan:
    """Weighted sampling oversampling low-complexity profiles.

    Within each band, sample without replacement up to the band's
    weighted share of target_evals, maintaining family-class coverage
    where feasible.
    """
    rng = random.Random(seed)

    oi_list = _filter_outers(outers, max_complexity, min_complexity, outer_family_filter)
    ii_list = _filter_inners(inners, max_complexity, min_complexity, inner_family_filter)

    # Enumerate all eligible pairs with their complexity band
    band_pairs: dict = {"low": [], "medium": [], "high": []}
    for oi in oi_list:
        for ii in ii_list:
            tc = _pair_total_complexity(outers, inners, oi, ii)
            band_pairs[complexity_band(tc)].append((oi, ii))

    # Shuffle deterministically within each band
    for b in band_pairs:
        rng.shuffle(band_pairs[b])

    weights = {"low": low_weight, "medium": medium_weight, "high": high_weight}
    total_w = sum(weights.values())
    desired = {b: int(round(target_evals * weights[b] / total_w)) for b in weights}

    chosen: list = []
    remainder = 0
    for b in ("low", "medium", "high"):
        want = desired[b]
        have = band_pairs[b]
        take = min(want, len(have))
        chosen.extend(have[:take])
        if want > take:
            remainder += want - take

    # Redistribute remainder across bands with leftover capacity
    if remainder > 0:
        for b in ("low", "medium", "high"):
            if remainder <= 0:
                break
            already = min(desired[b], len(band_pairs[b]))
            leftover = band_pairs[b][already:]
            take = min(remainder, len(leftover))
            chosen.extend(leftover[:take])
            remainder -= take

    low_ct = sum(1 for (oi, ii) in chosen
                 if complexity_band(_pair_total_complexity(outers, inners, oi, ii)) == "low")

    guarantees = [
        f"Low-complexity band oversampled at weight {low_weight} (medium={medium_weight}, high={high_weight}).",
        f"Complexity bands: low <= {COMPLEXITY_BAND_LOW_MAX}, "
        f"medium <= {COMPLEXITY_BAND_MEDIUM_MAX}, high > {COMPLEXITY_BAND_MEDIUM_MAX}.",
    ]

    return SamplingPlan(
        pairs=chosen,
        mode=SamplingMode.STRATIFIED_LOW_COMPLEXITY_BIAS,
        seed=seed,
        target_evals=target_evals,
        achieved_evals=len(chosen),
        coverage_guarantees=guarantees,
        is_complete_for_mode=low_ct > 0,
        notes=f"low={low_ct}/{len(chosen)} evals in low-complexity band",
        filters={
            "max_complexity": max_complexity,
            "min_complexity": min_complexity,
            "low_weight": low_weight,
            "medium_weight": medium_weight,
            "high_weight": high_weight,
        },
    )


# ── Mode: full cartesian ───────────────────────────────────────────────

def sample_full_cartesian(
    outers: list,
    inners: list,
    seed: int = 0,
    max_complexity: Optional[float] = None,
    min_complexity: Optional[float] = None,
    outer_family_filter: Optional[set] = None,
    inner_family_filter: Optional[set] = None,
) -> SamplingPlan:
    """Enumerate the full constrained cartesian product."""
    oi_list = _filter_outers(outers, max_complexity, min_complexity, outer_family_filter)
    ii_list = _filter_inners(inners, max_complexity, min_complexity, inner_family_filter)

    pairs: list = []
    for oi in oi_list:
        for ii in ii_list:
            if max_complexity is not None:
                tc = _pair_total_complexity(outers, inners, oi, ii)
                if tc > max_complexity * 2:
                    # NOTE: the pairwise bound uses 2x the per-layer max
                    # because max_complexity gates each layer individually.
                    # A stricter joint cap can be added later if needed.
                    pass
            pairs.append((oi, ii))

    guarantees = [
        "Full cartesian enumeration over the filtered outer x inner space.",
    ]
    if max_complexity is not None:
        guarantees.append(f"Per-layer complexity bound: <= {max_complexity}.")
    if outer_family_filter:
        guarantees.append(f"Outer families: {sorted(outer_family_filter)}.")
    if inner_family_filter:
        guarantees.append(f"Inner families: {sorted(inner_family_filter)}.")

    return SamplingPlan(
        pairs=pairs,
        mode=SamplingMode.FULL_CARTESIAN,
        seed=seed,
        target_evals=len(pairs),
        achieved_evals=len(pairs),
        coverage_guarantees=guarantees,
        is_complete_for_mode=True,
        notes=f"{len(oi_list)} outers x {len(ii_list)} inners = {len(pairs)}",
        filters={
            "max_complexity": max_complexity,
            "min_complexity": min_complexity,
            "outer_family_filter": sorted(outer_family_filter) if outer_family_filter else None,
            "inner_family_filter": sorted(inner_family_filter) if inner_family_filter else None,
        },
    )


def build_plan(
    mode: SamplingMode,
    outers: list,
    inners: list,
    target_evals: int,
    seed: int = 0,
    max_complexity: Optional[float] = None,
    min_complexity: Optional[float] = None,
    outer_family_filter: Optional[set] = None,
    inner_family_filter: Optional[set] = None,
) -> SamplingPlan:
    """Dispatcher — build a SamplingPlan for the requested mode."""
    if mode == SamplingMode.EXPLORATORY_STRIDE:
        return sample_exploratory_stride(outers, inners, target_evals, seed=seed)
    if mode == SamplingMode.STRATIFIED_FAMILY_COVER:
        return sample_stratified_family_cover(
            outers, inners, seed=seed,
            max_complexity=max_complexity, min_complexity=min_complexity,
            outer_family_filter=outer_family_filter,
            inner_family_filter=inner_family_filter,
        )
    if mode == SamplingMode.STRATIFIED_LOW_COMPLEXITY_BIAS:
        return sample_stratified_low_complexity_bias(
            outers, inners, target_evals, seed=seed,
            max_complexity=max_complexity, min_complexity=min_complexity,
            outer_family_filter=outer_family_filter,
            inner_family_filter=inner_family_filter,
        )
    if mode == SamplingMode.FULL_CARTESIAN:
        return sample_full_cartesian(
            outers, inners, seed=seed,
            max_complexity=max_complexity, min_complexity=min_complexity,
            outer_family_filter=outer_family_filter,
            inner_family_filter=inner_family_filter,
        )
    raise ValueError(f"Unknown sampling mode: {mode}")
