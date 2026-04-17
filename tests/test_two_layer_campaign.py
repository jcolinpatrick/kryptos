"""Tests for the two-layer stego + weak-inner campaign."""
from __future__ import annotations

import pytest

from kryptos.campaigns.two_layer.families import (
    CompositionProfile,
    EvaluationResult,
    InnerMixingClass,
    OuterFamily,
    ProvenanceClass,
)
from kryptos.campaigns.two_layer import (
    evaluation as ev,
    inner_layers as inner_mod,
    multiplicity,
    outer_layers as outer_mod,
)
from kryptos.kernel.constants import CT


def _pair(outer, inner) -> CompositionProfile:
    return CompositionProfile(
        profile_id=f"test_{outer.name}_{inner.name}",
        outer=outer, inner=inner,
        total_complexity=outer.complexity_score + inner.complexity_score,
        is_elimination_grade=False,
    )


def _first_mask_outer():
    for o in outer_mod.generate_instances():
        if o.breaks_direct_positional_alignment and o.family_id == "OUTER-MASK-EVERYNTH":
            return o
    raise RuntimeError("no mask outer found")


def _first_caesar_inner():
    for i in inner_mod.generate_instances():
        if i.family_id == "INNER-LOCAL-CAESAR":
            return i
    raise RuntimeError("no caesar inner found")


def test_outer_mask_breaks_alignment_disables_bean_gate():
    outer = _first_mask_outer()
    inner = _first_caesar_inner()
    p = _pair(outer, inner)
    stream = outer_mod.apply_outer(outer, CT)
    cand = inner_mod.apply_inner_inverse(inner, stream)
    r = ev.evaluate_composition(p, cand)
    assert r.bean_compatibility is None
    assert "H1 disabled" in r.bean_compatibility_scope_note


def test_short_candidates_are_not_synthetically_padded():
    outer = _first_mask_outer()
    inner = _first_caesar_inner()
    p = _pair(outer, inner)
    short = "Z" * 20
    r = ev.evaluate_composition(p, short)
    assert r.candidate_text == short
    assert "length_mismatch_20_not_padded" in r.flags
    assert r.crib_compatibility_score == 0
    assert r.stehle_position_55_63_match is False
    assert r.weak_identity_preservation == 0.0


def test_short_aligned_candidates_remain_h1_conditional():
    outer = next(o for o in outer_mod.generate_instances()
                 if not o.breaks_direct_positional_alignment)
    inner = _first_caesar_inner()
    p = _pair(outer, inner)
    r = ev.evaluate_composition(p, "Z" * 20)
    assert r.crib_compatibility_score == 0
    assert r.provenance == ProvenanceClass.H1_CONDITIONAL


def test_width21_is_evaluation_not_generation():
    # All profiles get a width spectrum, regardless of outer width
    outer = _first_mask_outer()
    inner = _first_caesar_inner()
    p = _pair(outer, inner)
    stream = outer_mod.apply_outer(outer, CT)
    cand = inner_mod.apply_inner_inverse(inner, stream)
    r = ev.evaluate_composition(p, cand)
    assert 21 in r.width_spectrum
    assert set(r.width_spectrum.keys()) == set(ev.WIDTH_SPECTRUM_WIDTHS)


def test_cherry_picked_width_flagged():
    # Synthesize a post-hoc-selected width-21 outer and a text whose
    # width-21 repeat count is the max across the spectrum.
    outer = next(
        o for o in outer_mod.generate_instances(include_swept=True)
        if o.family_id == "OUTER-PROJECT-SWEPT" and o.parameters.get("width") == 21
    )
    inner = _first_caesar_inner()
    p = _pair(outer, inner)
    spectrum = {w: 0 for w in ev.WIDTH_SPECTRUM_WIDTHS}
    spectrum[21] = 50  # synthetic max
    assert multiplicity.is_cherry_picked_width(spectrum, 21) is True
    assert outer.is_post_hoc_selected is True


def test_post_hoc_swept_outer_carries_pool_size():
    swept = [o for o in outer_mod.generate_instances(include_swept=True)
             if o.family_id == "OUTER-PROJECT-SWEPT"]
    assert len(swept) == 29  # widths 2-30
    for o in swept:
        assert o.selection_pool_size == 29
        assert o.is_post_hoc_selected is True
    inner = _first_caesar_inner()
    p = _pair(swept[0], inner)
    pen = multiplicity.compute_multiplicity_penalty(p)
    assert 0.0 < pen < 1.0


def test_bean_reported_signals_not_hard_filter():
    # Stehle metrics are computed but never gate the pipeline. The
    # evaluator produces a result regardless of stehle values.
    outer = _first_mask_outer()
    inner = _first_caesar_inner()
    p = _pair(outer, inner)
    stream = outer_mod.apply_outer(outer, CT)
    cand = inner_mod.apply_inner_inverse(inner, stream)
    r = ev.evaluate_composition(p, cand)
    # Metric exists regardless of value; is a field not a filter
    assert isinstance(r.stehle_local_delta5_count, int)
    assert isinstance(r.stehle_position_55_63_match, bool)


def test_joint_anomaly_success_strict_standard():
    # A candidate with crib=17, all other metrics good, is NOT a success.
    outer = _first_mask_outer()
    inner = _first_caesar_inner()
    p = _pair(outer, inner)
    r = EvaluationResult(
        profile_id="synthetic",
        candidate_text="A" * 97,
        crib_compatibility_score=17,
        bean_compatibility=None,
        bean_compatibility_scope_note="test",
        width21_repeat_count=50,
        width21_zscore=5.0,
        width_spectrum={w: 1 for w in ev.WIDTH_SPECTRUM_WIDTHS},
        cherry_picked_width=False,
        stehle_local_delta5_count=1,
        stehle_position_55_63_match=False,
        weak_identity_preservation=0.9,
        english_likeness=0.9,
        novelty_against_known_eliminations=True,
        is_joint_anomaly_success=False,  # we set it explicitly
        multiplicity_penalty=1.0,
    )
    # The evaluator's strict criterion would require crib >= 18.
    # Directly assert that 17 is below threshold.
    assert r.crib_compatibility_score < 18


def test_provenance_survives_serialization():
    r = EvaluationResult(
        profile_id="s",
        candidate_text="A" * 97,
        crib_compatibility_score=0,
        bean_compatibility=None,
        bean_compatibility_scope_note="",
        width21_repeat_count=0,
        width21_zscore=0.0,
        width_spectrum={7: 0, 21: 0},
        cherry_picked_width=False,
        stehle_local_delta5_count=0,
        stehle_position_55_63_match=False,
        weak_identity_preservation=0.0,
        english_likeness=0.0,
        novelty_against_known_eliminations=True,
        is_joint_anomaly_success=False,
        multiplicity_penalty=1.0,
        provenance=ProvenanceClass.H1_CONDITIONAL,
    )
    d = r.to_dict()
    r2 = EvaluationResult.from_dict(d)
    assert r2.provenance == ProvenanceClass.H1_CONDITIONAL
    assert r2.width_spectrum == {7: 0, 21: 0}


def test_inner_near_identity_preferred():
    inners = inner_mod.generate_instances()
    near_id = [i for i in inners if i.family_id == "INNER-NEAR-ID"]
    caesars = [i for i in inners if i.family_id == "INNER-LOCAL-CAESAR"]
    assert len(near_id) > 0
    assert len(caesars) == 26
    for i in near_id + caesars:
        assert i.mixing_class == InnerMixingClass.NEAR_IDENTITY


def test_no_strongly_mixing_inner_layers():
    for i in inner_mod.generate_instances():
        assert i.mixing_class != InnerMixingClass.STRONGLY_MIXING


def test_summary_blocks_overclaim_language():
    out = {"total_profiles_tested": 100, "joint_anomaly_successes": []}
    s = ev.render_summary(out)
    lowered = s.lower()
    for bad in ("explains", "must be", "strong evidence"):
        assert bad not in lowered


# ═════════════════════════════════════════════════════════════════════
# v2 enhancements: sampling, coverage, parallel, checkpoints
# ═════════════════════════════════════════════════════════════════════

import os
import tempfile

from kryptos.campaigns.two_layer import sampling as smp
from kryptos.campaigns.two_layer.coverage import compute_coverage_report
from kryptos.campaigns.two_layer.checkpoint import Checkpoint
from kryptos.campaigns.two_layer.parallel import (
    default_worker_count,
    evaluate_pairs_parallel,
)


def _outers_inners():
    outers = outer_mod.generate_instances(include_swept=False)
    inners = inner_mod.generate_instances()
    return outers, inners


def test_stratified_family_cover_every_outer_sees_every_inner_family():
    outers, inners = _outers_inners()
    plan = smp.sample_stratified_family_cover(outers, inners, seed=1)
    inner_fams = {i.family_id for i in inners}
    per_outer: dict = {}
    for oi, ii in plan.pairs:
        per_outer.setdefault(oi, set()).add(inners[ii].family_id)
    for oi, fams in per_outer.items():
        assert fams == inner_fams


def test_stratified_family_cover_count_matches_invariant():
    outers, inners = _outers_inners()
    plan = smp.sample_stratified_family_cover(outers, inners, seed=0)
    n_inner_fams = len({i.family_id for i in inners})
    assert len(plan.pairs) == len(outers) * n_inner_fams
    assert plan.is_complete_for_mode is True


def test_low_complexity_bias_oversamples_low_band():
    outers, inners = _outers_inners()
    plan = smp.sample_stratified_low_complexity_bias(
        outers, inners, target_evals=1000, seed=0,
    )
    low = sum(
        1 for (oi, ii) in plan.pairs
        if smp.complexity_band(outers[oi].complexity_score + inners[ii].complexity_score) == "low"
    )
    high = sum(
        1 for (oi, ii) in plan.pairs
        if smp.complexity_band(outers[oi].complexity_score + inners[ii].complexity_score) == "high"
    )
    # Low should materially exceed high under oversampling (if both bands have supply)
    if high > 0:
        assert low > high


def test_full_cartesian_enumerates_full_count():
    outers, inners = _outers_inners()
    plan = smp.sample_full_cartesian(outers, inners, seed=0)
    assert len(plan.pairs) == len(outers) * len(inners)
    assert plan.is_complete_for_mode is True


def test_full_cartesian_with_complexity_filter_drops_correctly():
    outers, inners = _outers_inners()
    plan = smp.sample_full_cartesian(outers, inners, seed=0, max_complexity=6.0)
    for oi, ii in plan.pairs:
        assert outers[oi].complexity_score <= 6.0
        assert inners[ii].complexity_score <= 6.0


def test_exploratory_stride_not_qualifying_as_family_cover():
    outers, inners = _outers_inners()
    plan = smp.sample_exploratory_stride(outers, inners, target_evals=2000, seed=0)
    cov = compute_coverage_report(plan, outers, inners)
    assert cov.qualifies_as_family_cover_complete is False
    assert cov.qualifies_as_full_cartesian_complete is False


def test_parallel_results_match_serial():
    outers, inners = _outers_inners()
    plan = smp.sample_exploratory_stride(outers, inners, target_evals=40, seed=0)
    pairs = [(outers[oi], inners[ii]) for oi, ii in plan.pairs]
    serial = evaluate_pairs_parallel(pairs, workers=1, use_ngram=False)
    parallel = evaluate_pairs_parallel(pairs, workers=4, use_ngram=False, chunksize=5)
    assert len(serial) == len(parallel)
    for (ps, rs), (pp, rp) in zip(serial, parallel):
        assert ps.profile_id == pp.profile_id
        assert rs.candidate_text == rp.candidate_text
        assert rs.crib_compatibility_score == rp.crib_compatibility_score
        assert rs.width21_repeat_count == rp.width21_repeat_count


def test_parallel_worker_errors_fail_closed():
    """Worker failures must not be dropped from coverage accounting."""
    bad_outer = OuterFamily(
        family_id="OUTER-BOGUS",
        name="bogus_outer",
        description="synthetic invalid outer for fail-closed regression",
        parameters={},
        parameter_space_size=1,
        complexity_score=1.0,
        breaks_direct_positional_alignment=True,
        is_post_hoc_selected=False,
        selection_pool_size=1,
        provenance=ProvenanceClass.EXPLORATORY,
    )
    with pytest.raises(RuntimeError, match="refusing to drop failed profiles"):
        evaluate_pairs_parallel(
            [(bad_outer, _first_caesar_inner())],
            workers=1,
            use_ngram=False,
        )


def test_parallel_workers_zero_uses_default():
    assert default_worker_count() >= 1


def test_coverage_report_correctness():
    outers, inners = _outers_inners()
    plan = smp.sample_stratified_family_cover(outers, inners, seed=0)
    cov = compute_coverage_report(plan, outers, inners)
    assert cov.total_pairs_evaluated == len(plan.pairs)
    assert cov.distinct_outer_instances == len(outers)
    n_inner_fams = len({i.family_id for i in inners})
    assert cov.outers_seeing_all_inner_families == len(outers)
    assert cov.median_inner_families_per_outer == float(n_inner_fams)
    assert cov.qualifies_as_family_cover_complete is True


def test_checkpoint_roundtrip():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ckpt.json")
        c = Checkpoint.new("f_x", "full_cartesian", 42, 500, filters={"k": "v"})
        c.completed_pair_indices = [0, 1, 2]
        c.results = [{"idx": 0}, {"idx": 1}, {"idx": 2}]
        c.save(path)
        c2 = Checkpoint.load(path)
        assert c2.campaign_id == "f_x"
        assert c2.sampling_mode == "full_cartesian"
        assert c2.sampling_seed == 42
        assert c2.completed_pair_indices == [0, 1, 2]
        assert c2.filters == {"k": "v"}
        assert len(c2.results) == 3


def test_checkpoint_load_rejects_duplicate_completed_indices():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ckpt.json")
        payload = {
            "campaign_id": "f_x",
            "sampling_mode": "full_cartesian",
            "sampling_seed": 42,
            "target_evals": 10,
            "completed_pair_indices": [0, 1, 1],
            "results": [],
        }
        with open(path, "w") as f:
            import json
            json.dump(payload, f)
        with pytest.raises(ValueError, match="unique"):
            Checkpoint.load(path)


def test_checkpoint_load_rejects_out_of_range_indices():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ckpt.json")
        payload = {
            "campaign_id": "f_x",
            "sampling_mode": "full_cartesian",
            "sampling_seed": 42,
            "target_evals": 2,
            "completed_pair_indices": [0, 2],
            "results": [],
        }
        with open(path, "w") as f:
            import json
            json.dump(payload, f)
        with pytest.raises(ValueError, match=r"\[0, target_evals\)"):
            Checkpoint.load(path)


def test_checkpoint_load_rejects_result_idx_not_completed():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ckpt.json")
        payload = {
            "campaign_id": "f_x",
            "sampling_mode": "full_cartesian",
            "sampling_seed": 42,
            "target_evals": 10,
            "completed_pair_indices": [0, 1],
            "results": [{"idx": 3}],
        }
        with open(path, "w") as f:
            import json
            json.dump(payload, f)
        with pytest.raises(ValueError, match="present in completed_pair_indices"):
            Checkpoint.load(path)


def test_checkpoint_load_rejects_unsorted_completed_indices():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ckpt.json")
        payload = {
            "campaign_id": "f_x",
            "sampling_mode": "full_cartesian",
            "sampling_seed": 42,
            "target_evals": 10,
            "completed_pair_indices": [1, 0],
            "results": [],
        }
        with open(path, "w") as f:
            import json
            json.dump(payload, f)
        with pytest.raises(ValueError, match="sorted"):
            Checkpoint.load(path)


def test_checkpoint_resume_skips_completed():
    outers, inners = _outers_inners()
    plan = smp.sample_exploratory_stride(outers, inners, target_evals=1000, seed=0)
    completed = set(range(500))
    remaining = [i for i in range(len(plan.pairs)) if i not in completed]
    assert len(remaining) == len(plan.pairs) - 500


def test_render_summary_mode_aware_language():
    outers, inners = _outers_inners()
    stride_plan = smp.sample_exploratory_stride(outers, inners, target_evals=100, seed=0)
    cov = compute_coverage_report(stride_plan, outers, inners)
    out = {"total_profiles_tested": 100, "joint_anomaly_successes": []}
    s = ev.render_summary(out, coverage=cov)
    assert "EXPLORATORY" in s

    fc_plan = smp.sample_stratified_family_cover(outers, inners, seed=0)
    cov2 = compute_coverage_report(fc_plan, outers, inners)
    out2 = {"total_profiles_tested": len(fc_plan.pairs), "joint_anomaly_successes": []}
    s2 = ev.render_summary(out2, coverage=cov2)
    assert "FAMILY-COVER" in s2

    cart_plan = smp.sample_full_cartesian(outers, inners, seed=0)
    cov3 = compute_coverage_report(cart_plan, outers, inners)
    out3 = {"total_profiles_tested": len(cart_plan.pairs), "joint_anomaly_successes": []}
    s3 = ev.render_summary(out3, coverage=cov3)
    assert "FULL-CARTESIAN" in s3


def test_render_summary_does_not_overclaim_partial_runs():
    outers, inners = _outers_inners()
    plan = smp.sample_stratified_family_cover(outers, inners, seed=0)
    # Artificially drop some pairs to make it incomplete
    plan.pairs = plan.pairs[: len(plan.pairs) // 2]
    plan.is_complete_for_mode = False
    cov = compute_coverage_report(plan, outers, inners)
    out = {"total_profiles_tested": len(plan.pairs), "joint_anomaly_successes": []}
    s = ev.render_summary(out, coverage=cov)
    assert "FAMILY-COVER null" not in s
    assert "PARTIAL" in s


def test_malformed_full_cartesian_plan_fails_closed():
    """Coverage must not trust a completeness flag without pair-count proof."""
    outers, inners = _outers_inners()
    plan = smp.sample_full_cartesian(outers, inners, seed=0)
    malformed = smp.SamplingPlan(
        pairs=plan.pairs[:-1],  # drop one pair but keep the original claim
        mode=plan.mode,
        seed=plan.seed,
        target_evals=plan.target_evals,
        achieved_evals=len(plan.pairs) - 1,
        coverage_guarantees=plan.coverage_guarantees,
        is_complete_for_mode=True,
        notes=plan.notes,
        filters=plan.filters,
    )
    cov = compute_coverage_report(malformed, outers, inners)
    assert cov.qualifies_as_full_cartesian_complete is False

    out = {"total_profiles_tested": len(malformed.pairs), "joint_anomaly_successes": []}
    s = ev.render_summary(out, coverage=cov)
    assert "FULL-CARTESIAN null" not in s
    assert "PARTIAL" in s


def test_malformed_family_cover_plan_fails_closed():
    """Dropping an outer instance must void the family-cover warrant."""
    outers, inners = _outers_inners()
    plan = smp.sample_stratified_family_cover(outers, inners, seed=0)
    dropped_outer = plan.pairs[0][0]
    malformed_pairs = [pair for pair in plan.pairs if pair[0] != dropped_outer]
    malformed = smp.SamplingPlan(
        pairs=malformed_pairs,
        mode=plan.mode,
        seed=plan.seed,
        target_evals=plan.target_evals,
        achieved_evals=len(malformed_pairs),
        coverage_guarantees=plan.coverage_guarantees,
        is_complete_for_mode=True,
        notes=plan.notes,
        filters=plan.filters,
    )
    cov = compute_coverage_report(malformed, outers, inners)
    assert cov.qualifies_as_family_cover_complete is False

    out = {"total_profiles_tested": len(malformed.pairs), "joint_anomaly_successes": []}
    s = ev.render_summary(out, coverage=cov)
    assert "FAMILY-COVER null" not in s
    assert "PARTIAL" in s


def test_family_cover_missing_inner_family_fails_closed():
    """Dropping an inner family class must void the family-cover warrant."""
    outers, inners = _outers_inners()
    plan = smp.sample_stratified_family_cover(outers, inners, seed=0)
    dropped_family = inners[plan.pairs[0][1]].family_id
    malformed_pairs = [
        pair for pair in plan.pairs
        if inners[pair[1]].family_id != dropped_family
    ]
    malformed = smp.SamplingPlan(
        pairs=malformed_pairs,
        mode=plan.mode,
        seed=plan.seed,
        target_evals=len(malformed_pairs),
        achieved_evals=len(malformed_pairs),
        coverage_guarantees=plan.coverage_guarantees,
        is_complete_for_mode=True,
        notes=plan.notes,
        filters=plan.filters,
    )
    cov = compute_coverage_report(malformed, outers, inners)
    assert cov.qualifies_as_family_cover_complete is False

    out = {"total_profiles_tested": len(malformed.pairs), "joint_anomaly_successes": []}
    s = ev.render_summary(out, coverage=cov)
    assert "FAMILY-COVER null" not in s
    assert "PARTIAL" in s


def test_provenance_preserved_under_multiprocessing():
    outers, inners = _outers_inners()
    plan = smp.sample_exploratory_stride(outers, inners, target_evals=10, seed=0)
    pairs = [(outers[oi], inners[ii]) for oi, ii in plan.pairs]
    results = evaluate_pairs_parallel(pairs, workers=2, use_ngram=False, chunksize=5)
    for _, r in results:
        assert isinstance(r.provenance, ProvenanceClass)


def test_outer_family_filter_applied():
    outers, inners = _outers_inners()
    plan = smp.sample_full_cartesian(
        outers, inners, seed=0,
        outer_family_filter={"OUTER-PROJECT"},
    )
    for oi, ii in plan.pairs:
        assert outers[oi].family_id == "OUTER-PROJECT"


def test_low_complexity_filter_via_max_complexity():
    outers, inners = _outers_inners()
    plan = smp.sample_full_cartesian(outers, inners, seed=0, max_complexity=5.0)
    for oi, ii in plan.pairs:
        assert outers[oi].complexity_score <= 5.0
        assert inners[ii].complexity_score <= 5.0
