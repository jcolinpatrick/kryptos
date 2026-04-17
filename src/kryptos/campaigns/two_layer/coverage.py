"""Coverage accounting for the two-layer campaign.

Takes a SamplingPlan + the outer/inner instance lists and produces a
CoverageReport that quantifies what claims the run's coverage shape
actually warrants.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List

from .families import OuterFamily, InnerFamily
from .sampling import (
    COMPLEXITY_BAND_LOW_MAX,
    COMPLEXITY_BAND_MEDIUM_MAX,
    SamplingMode,
    SamplingPlan,
    complexity_band,
)


@dataclass
class CoverageReport:
    """Machine-readable coverage analysis for a campaign run."""
    total_pairs_evaluated: int
    distinct_outer_instances: int
    total_outer_instances: int
    distinct_inner_instances: int
    total_inner_instances: int
    outer_family_class_coverage: Dict[str, int]
    inner_family_class_coverage: Dict[str, int]
    cross_pair_coverage_count: int
    cross_pair_coverage_total: int
    per_outer_inner_family_classes_seen: Dict[str, List[int]]
    median_inner_families_per_outer: float
    outers_seeing_all_inner_families: int
    outers_seeing_one_inner_family: int
    complexity_histogram: Dict[str, int]
    low_complexity_eval_count: int
    medium_complexity_eval_count: int
    high_complexity_eval_count: int
    qualifies_as_family_cover_complete: bool
    qualifies_as_low_complexity_emphasized: bool
    qualifies_as_full_cartesian_complete: bool
    sampling_mode: str
    sampling_seed: int
    coverage_guarantees: List[str]

    def to_dict(self) -> dict:
        return asdict(self)


def compute_coverage_report(
    plan: SamplingPlan,
    outers: List[OuterFamily],
    inners: List[InnerFamily],
) -> CoverageReport:
    distinct_outer_idx = set()
    distinct_inner_idx = set()
    outer_fam_classes: Dict[str, set] = {}
    inner_fam_classes: Dict[str, set] = {}
    per_outer_inner_fams: Dict[int, set] = {}
    cross_pairs: set = set()
    complexity_hist = {"low": 0, "medium": 0, "high": 0}

    for (oi, ii) in plan.pairs:
        distinct_outer_idx.add(oi)
        distinct_inner_idx.add(ii)
        ofid = outers[oi].family_id
        ifid = inners[ii].family_id
        outer_fam_classes.setdefault(ofid, set()).add(oi)
        inner_fam_classes.setdefault(ifid, set()).add(ii)
        per_outer_inner_fams.setdefault(oi, set()).add(ifid)
        cross_pairs.add((ofid, ifid))
        tc = outers[oi].complexity_score + inners[ii].complexity_score
        complexity_hist[complexity_band(tc)] += 1

    all_outer_fams = {o.family_id for o in outers}
    all_inner_fams = {i.family_id for i in inners}

    n_inner_fams_touched = len(inner_fam_classes)
    n_inner_fams_expected = len(all_inner_fams)
    expected_outers_for_family_cover = (
        plan.target_evals // n_inner_fams_expected
        if n_inner_fams_expected and plan.target_evals % n_inner_fams_expected == 0
        else 0
    )
    per_outer_counts = [len(s) for s in per_outer_inner_fams.values()]
    per_outer_counts_sorted = sorted(per_outer_counts)
    if per_outer_counts_sorted:
        mid = len(per_outer_counts_sorted) // 2
        if len(per_outer_counts_sorted) % 2 == 1:
            median = float(per_outer_counts_sorted[mid])
        else:
            median = (per_outer_counts_sorted[mid - 1] + per_outer_counts_sorted[mid]) / 2.0
    else:
        median = 0.0

    outers_all = sum(1 for c in per_outer_counts if c == n_inner_fams_touched and n_inner_fams_touched > 0)
    outers_one = sum(1 for c in per_outer_counts if c == 1)

    cross_total = len(all_outer_fams) * len(all_inner_fams)
    full_instance_total = len(outers) * len(inners)

    # Per-outer family class count map (index -> fam-class count)
    per_outer_map: Dict[str, List[int]] = {}
    for oi, fams in per_outer_inner_fams.items():
        per_outer_map[outers[oi].name] = [len(fams)]

    # Qualification flags — strict invariants.
    # family_cover_complete: every outer in the touched set pairs with every
    # inner family class present in the touched set.
    touched_outer_count = len(distinct_outer_idx)
    qualifies_family_cover = (
        plan.mode == SamplingMode.STRATIFIED_FAMILY_COVER
        and plan.is_complete_for_mode
        and n_inner_fams_expected > 0
        and n_inner_fams_touched == n_inner_fams_expected
        and len(plan.pairs) == plan.target_evals == plan.achieved_evals
        and touched_outer_count == expected_outers_for_family_cover
        and outers_all == expected_outers_for_family_cover
    )

    qualifies_low_complex = (
        plan.mode == SamplingMode.STRATIFIED_LOW_COMPLEXITY_BIAS
        and complexity_hist["low"] > 0
        and complexity_hist["low"] >= complexity_hist["high"]
    )

    qualifies_full_cart = (
        plan.mode == SamplingMode.FULL_CARTESIAN
        and plan.is_complete_for_mode
        and len(plan.pairs) == full_instance_total
        and len(distinct_outer_idx) == len(outers)
        and len(distinct_inner_idx) == len(inners)
    )

    return CoverageReport(
        total_pairs_evaluated=len(plan.pairs),
        distinct_outer_instances=len(distinct_outer_idx),
        total_outer_instances=len(outers),
        distinct_inner_instances=len(distinct_inner_idx),
        total_inner_instances=len(inners),
        outer_family_class_coverage={k: len(v) for k, v in outer_fam_classes.items()},
        inner_family_class_coverage={k: len(v) for k, v in inner_fam_classes.items()},
        cross_pair_coverage_count=len(cross_pairs),
        cross_pair_coverage_total=cross_total,
        per_outer_inner_family_classes_seen=per_outer_map,
        median_inner_families_per_outer=median,
        outers_seeing_all_inner_families=outers_all,
        outers_seeing_one_inner_family=outers_one,
        complexity_histogram=complexity_hist,
        low_complexity_eval_count=complexity_hist["low"],
        medium_complexity_eval_count=complexity_hist["medium"],
        high_complexity_eval_count=complexity_hist["high"],
        qualifies_as_family_cover_complete=qualifies_family_cover,
        qualifies_as_low_complexity_emphasized=qualifies_low_complex,
        qualifies_as_full_cartesian_complete=qualifies_full_cart,
        sampling_mode=plan.mode.value,
        sampling_seed=plan.seed if plan.seed is not None else 0,
        coverage_guarantees=list(plan.coverage_guarantees),
    )
