#!/usr/bin/env python3
"""
Cipher: two-layer stego + weak inner encipherment
Family: composition / two-layer
Status: active
Keyspace: bounded enumeration of low-complexity outer x inner family pairs
Last run:
Best score:
"""
# Disciplined two-layer architectural campaign. Tests ONE hypothesis:
#   K4 = outer stego/masking/selection/projection layer
#      + inner weak (near-identity-preserving) encipherment layer
#
# Anti-overfitting principle: generation and evaluation metrics are
# disjoint sets. Outer width is drawn from a justified small set;
# post-hoc sweeps carry a multiplicity penalty.
#
# v2 enhancements:
#   - Stratified sampling modes (exploratory_stride, stratified_family_cover,
#     stratified_low_complexity_bias, full_cartesian)
#   - Multiprocessing evaluation (--workers)
#   - Coverage accounting
#   - Checkpoint/resume (--resume)
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT  # noqa: E402
from kryptos.campaigns.two_layer.families import CompositionProfile  # noqa: E402
from kryptos.campaigns.two_layer.outer_layers import (  # noqa: E402
    generate_instances as outer_generate,
)
from kryptos.campaigns.two_layer.inner_layers import (  # noqa: E402
    generate_instances as inner_generate,
)
from kryptos.campaigns.two_layer.evaluation import render_summary  # noqa: E402
from kryptos.campaigns.two_layer.sampling import (  # noqa: E402
    SamplingMode,
    build_plan,
)
from kryptos.campaigns.two_layer.coverage import compute_coverage_report  # noqa: E402
from kryptos.campaigns.two_layer.parallel import (  # noqa: E402
    default_worker_count,
    evaluate_pairs_parallel,
)
from kryptos.campaigns.two_layer.checkpoint import Checkpoint  # noqa: E402


RESULTS_JSON = os.path.join(_ROOT, "results", "f_two_layer_stego_cipher_v1.json")
RESULTS_MD = os.path.join(_ROOT, "results", "f_two_layer_stego_cipher_v1.md")
CHECKPOINT_PATH = os.path.join(_ROOT, "results", "f_two_layer_stego_cipher_v1.checkpoint.json")


def _serialize_profile(profile: CompositionProfile) -> dict:
    return {
        "profile_id": profile.profile_id,
        "outer": {
            "family_id": profile.outer.family_id,
            "name": profile.outer.name,
            "parameters": profile.outer.parameters,
            "is_post_hoc_selected": profile.outer.is_post_hoc_selected,
            "selection_pool_size": profile.outer.selection_pool_size,
            "breaks_alignment": profile.outer.breaks_direct_positional_alignment,
        },
        "inner": {
            "family_id": profile.inner.family_id,
            "name": profile.inner.name,
            "parameters": profile.inner.parameters,
            "mixing_class": profile.inner.mixing_class.value,
        },
        "total_complexity": profile.total_complexity,
    }


def run_campaign(
    sampling_mode: str = "exploratory_stride",
    seed: int = 0,
    workers: int = 0,
    target_evals: int = 2000,
    max_complexity=None,
    min_complexity=None,
    outer_family_filter=None,
    inner_family_filter=None,
    resume: bool = False,
    checkpoint_every: int = 500,
    output: str = RESULTS_JSON,
    report: str = RESULTS_MD,
    verbose: bool = True,
):
    started = datetime.now(timezone.utc).isoformat()
    mode = SamplingMode(sampling_mode)

    outers = outer_generate(include_swept=False)
    inners = inner_generate()
    if verbose:
        print(f"[campaign] {len(outers)} outer, {len(inners)} inner instances")
        print(f"[campaign] Cartesian space = {len(outers) * len(inners)} profiles")

    plan = build_plan(
        mode=mode,
        outers=outers,
        inners=inners,
        target_evals=target_evals,
        seed=seed,
        max_complexity=max_complexity,
        min_complexity=min_complexity,
        outer_family_filter=outer_family_filter,
        inner_family_filter=inner_family_filter,
    )

    if verbose:
        print(f"[campaign] sampling mode: {plan.mode.value} (seed={seed})")
        print(f"[campaign] plan pairs: {len(plan.pairs)} (complete_for_mode={plan.is_complete_for_mode})")
        for g in plan.coverage_guarantees:
            print(f"  - {g}")
        if plan.notes:
            print(f"  [notes] {plan.notes}")

    # Resume support
    ckpt = None
    completed = set()
    prior_results: list = []
    if resume and os.path.exists(CHECKPOINT_PATH):
        ckpt = Checkpoint.load(CHECKPOINT_PATH)
        if ckpt.sampling_mode != plan.mode.value or ckpt.sampling_seed != seed:
            print(f"[campaign] checkpoint mode/seed mismatch — ignoring old checkpoint")
            ckpt = None
        else:
            completed = set(ckpt.completed_pair_indices)
            prior_results = list(ckpt.results)
            if verbose:
                print(f"[campaign] resuming: {len(completed)} pairs already completed")
    if ckpt is None:
        ckpt = Checkpoint.new(
            campaign_id="f_two_layer_stego_cipher_v1",
            sampling_mode=plan.mode.value,
            sampling_seed=seed,
            target_evals=target_evals,
            filters=plan.filters,
        )

    # Build the work list of (outer, inner) pairs to evaluate
    to_eval_indices = [i for i in range(len(plan.pairs)) if i not in completed]
    pending_pairs = [
        (outers[plan.pairs[i][0]], inners[plan.pairs[i][1]])
        for i in to_eval_indices
    ]

    if verbose:
        eff_workers = workers if workers > 0 else default_worker_count()
        print(f"[campaign] evaluating {len(pending_pairs)} pairs (workers={eff_workers})")

    t0 = time.time()

    # Chunked parallel evaluation for checkpointing granularity
    results: list = []
    CHUNK = max(checkpoint_every, 50) if checkpoint_every > 0 else len(pending_pairs)
    for start in range(0, len(pending_pairs), CHUNK):
        chunk = pending_pairs[start:start + CHUNK]
        chunk_indices = to_eval_indices[start:start + CHUNK]
        chunk_results = evaluate_pairs_parallel(
            chunk, workers=workers, ct=CT, use_ngram=True,
        )
        # chunk_results aligns to chunk order (sorted by stable idx)
        for (plan_idx, (profile, res)) in zip(chunk_indices, chunk_results):
            results.append((profile, res))
            ckpt.completed_pair_indices.append(plan_idx)
            ckpt.results.append({
                "plan_idx": plan_idx,
                "profile": _serialize_profile(profile),
                "result": res.to_dict(),
            })
        if checkpoint_every > 0:
            ckpt.save(CHECKPOINT_PATH)
        if verbose:
            dt = time.time() - t0
            done = start + len(chunk)
            print(f"  evaluated {done}/{len(pending_pairs)} ({dt:.1f}s)")

    dt = time.time() - t0
    if verbose:
        print(f"[campaign] done in {dt:.1f}s")

    # Merge prior results from checkpoint (on resume)
    # Note: prior_results are serialized dicts; we use them only for counts + outputs
    # Successes / top ranking rebuilt from live results only (restart-safe semantics).
    all_live_pairs = results  # new evals this run

    # Aggregate
    successes = [(p, r) for p, r in all_live_pairs if r.is_joint_anomaly_success]

    def soft_score(pair):
        p, r = pair
        return (
            r.crib_compatibility_score
            + max(0.0, r.width21_zscore) * 2.0
            + (10 if r.stehle_position_55_63_match else 0)
            + r.weak_identity_preservation * 5.0
            - (3.0 if r.cherry_picked_width else 0.0)
        ) * r.multiplicity_penalty

    top = sorted(all_live_pairs, key=soft_score, reverse=True)[:20]

    # Family baselines
    baselines: dict = {}
    for p, r in all_live_pairs:
        key = p.outer.family_id
        b = baselines.setdefault(key, {"n": 0, "sum_z": 0.0, "sum_crib": 0, "max_crib": 0})
        b["n"] += 1
        b["sum_z"] += r.width21_zscore
        b["sum_crib"] += r.crib_compatibility_score
        b["max_crib"] = max(b["max_crib"], r.crib_compatibility_score)
    for k, b in baselines.items():
        b["mean_z"] = b["sum_z"] / max(1, b["n"])
        b["mean_crib"] = b["sum_crib"] / max(1, b["n"])
        del b["sum_z"]
        del b["sum_crib"]

    coverage = compute_coverage_report(plan, outers, inners)

    completed_at = datetime.now(timezone.utc).isoformat()
    total_tested = len(all_live_pairs) + len(prior_results)
    out = {
        "campaign": "f_two_layer_stego_cipher_v1",
        "started_at": started,
        "completed_at": completed_at,
        "total_profiles_tested": total_tested,
        "sampling_mode": plan.mode.value,
        "sampling_seed": seed,
        "target_evals": target_evals,
        "workers": workers if workers > 0 else default_worker_count(),
        "outer_families_count": len(outers),
        "inner_families_count": len(inners),
        "plan_pair_count": len(plan.pairs),
        "plan_is_complete_for_mode": plan.is_complete_for_mode,
        "coverage_guarantees": plan.coverage_guarantees,
        "coverage_report": coverage.to_dict(),
        "joint_anomaly_successes": [
            {"profile": _serialize_profile(p), "result": r.to_dict()}
            for p, r in successes
        ],
        "top_candidates_by_metric": [
            {"profile": _serialize_profile(p), "result": r.to_dict(),
             "soft_score": soft_score((p, r))}
            for p, r in top
        ],
        "family_baselines": baselines,
        "scope_warnings": [
            "Bean compatibility is None for all mask/projection outers (H1 disabled).",
            "Stehle metrics are advisory; never used as hard elimination gate.",
            "crib_compatibility at anchored positions is H1_CONDITIONAL.",
        ],
        "elimination_grade_findings": [],
        "exploratory_findings": [],
    }

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w") as f:
        json.dump(out, f, indent=2, default=str)

    with open(report, "w") as f:
        f.write(_render_markdown(out, coverage))

    summary = render_summary(out, coverage=coverage)
    print("\n" + "=" * 60)
    print(summary)
    print("=" * 60)
    print(f"[campaign] JSON: {output}")
    print(f"[campaign] MD:   {report}")

    # Clean up checkpoint on successful completion
    if os.path.exists(CHECKPOINT_PATH):
        try:
            os.remove(CHECKPOINT_PATH)
        except OSError:
            pass

    return out


def _render_markdown(out: dict, coverage) -> str:
    lines = []
    lines.append("# f_two_layer_stego_cipher_v1 — Results")
    lines.append("")
    lines.append(f"- Started: {out['started_at']}")
    lines.append(f"- Completed: {out['completed_at']}")
    lines.append(f"- Sampling mode: {out['sampling_mode']} (seed={out['sampling_seed']})")
    lines.append(f"- Total profiles tested: {out['total_profiles_tested']}")
    lines.append(f"- Workers: {out['workers']}")
    lines.append(f"- Outer families: {out['outer_families_count']}")
    lines.append(f"- Inner families: {out['inner_families_count']}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(render_summary(out, coverage=coverage))
    lines.append("")
    lines.append("## Coverage report")
    lines.append(f"- Distinct outer instances: {coverage.distinct_outer_instances}/{coverage.total_outer_instances}")
    lines.append(f"- Distinct inner instances: {coverage.distinct_inner_instances}/{coverage.total_inner_instances}")
    lines.append(f"- Cross (outer_fam, inner_fam) pairs: {coverage.cross_pair_coverage_count}/{coverage.cross_pair_coverage_total}")
    lines.append(f"- Outers seeing ALL inner family classes: {coverage.outers_seeing_all_inner_families}")
    lines.append(f"- Median inner families per outer: {coverage.median_inner_families_per_outer}")
    lines.append(f"- Complexity histogram: low={coverage.low_complexity_eval_count} "
                 f"medium={coverage.medium_complexity_eval_count} "
                 f"high={coverage.high_complexity_eval_count}")
    lines.append(f"- Qualifies family-cover complete: {coverage.qualifies_as_family_cover_complete}")
    lines.append(f"- Qualifies low-complexity emphasized: {coverage.qualifies_as_low_complexity_emphasized}")
    lines.append(f"- Qualifies full-cartesian complete: {coverage.qualifies_as_full_cartesian_complete}")
    lines.append("")
    lines.append("## Coverage guarantees")
    for g in coverage.coverage_guarantees:
        lines.append(f"- {g}")
    lines.append("")
    lines.append("## Scope warnings")
    for w in out["scope_warnings"]:
        lines.append(f"- {w}")
    lines.append("")
    lines.append("## Joint anomaly successes")
    if not out["joint_anomaly_successes"]:
        lines.append("None.")
    else:
        for s in out["joint_anomaly_successes"]:
            lines.append(f"- {s['profile']['profile_id']}: "
                         f"crib={s['result']['crib_compatibility_score']} "
                         f"z21={s['result']['width21_zscore']:.2f}")
    lines.append("")
    lines.append("## Top candidates (soft ranking — NOT selection)")
    for t in out["top_candidates_by_metric"][:10]:
        r = t["result"]
        p = t["profile"]
        lines.append(
            f"- `{p['profile_id']}` {p['outer']['name']} + {p['inner']['name']}: "
            f"crib={r['crib_compatibility_score']} z21={r['width21_zscore']:.2f} "
            f"stehle={r['stehle_local_delta5_count']} flags={r['flags']}"
        )
    lines.append("")
    lines.append("## Family baselines")
    for fid, b in out["family_baselines"].items():
        lines.append(
            f"- {fid}: n={b['n']} mean_crib={b['mean_crib']:.2f} "
            f"mean_z21={b['mean_z']:.2f} max_crib={b['max_crib']}"
        )
    lines.append("")
    return "\n".join(lines)


def _parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--sampling-mode",
                   choices=["exploratory_stride", "stratified_family_cover",
                            "stratified_low_complexity_bias", "full_cartesian"],
                   default="exploratory_stride")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--workers", type=int, default=0,
                   help="0 = cpu_count - 2; 1 = serial")
    p.add_argument("--target-evals", type=int, default=2000)
    p.add_argument("--max-complexity", type=float, default=None)
    p.add_argument("--min-complexity", type=float, default=None)
    p.add_argument("--outer-family", action="append", default=None)
    p.add_argument("--inner-family", action="append", default=None)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--checkpoint-every", type=int, default=500)
    p.add_argument("--output", type=str, default=RESULTS_JSON)
    p.add_argument("--report", type=str, default=RESULTS_MD)
    # Back-compat — `--budget` aliases to --target-evals
    p.add_argument("--budget", type=int, default=None)
    return p.parse_args()


def main():
    args = _parse_args()
    target = args.target_evals
    if args.budget is not None:
        target = args.budget
    run_campaign(
        sampling_mode=args.sampling_mode,
        seed=args.seed,
        workers=args.workers,
        target_evals=target,
        max_complexity=args.max_complexity,
        min_complexity=args.min_complexity,
        outer_family_filter=set(args.outer_family) if args.outer_family else None,
        inner_family_filter=set(args.inner_family) if args.inner_family else None,
        resume=args.resume,
        checkpoint_every=args.checkpoint_every,
        output=args.output,
        report=args.report,
        verbose=True,
    )


if __name__ == "__main__":
    main()
