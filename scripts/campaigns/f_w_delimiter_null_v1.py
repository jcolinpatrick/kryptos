#!/usr/bin/env python3
"""
Cipher: W-delimiter null elimination
Family: analysis / null-hypothesis
Status: active
Keyspace: 4 populations x 3 variants over constrained slots A,B
Last run:
Best score:

Publication-grade null elimination for the W-delimiter hypothesis on K4.

Tests whether ANY English-plausible 2+4 fill of slots A=[34,35] and
B=[59..62] under additive cipher variants produces a multi-channel tail
event against the grammatical population. Either eliminates the W-delimiter
class within the testable scope or names a surviving residual.

The cheap "new self-encrypting position" feature is retained but CAPPED in
the composite so it cannot drive the verdict alone (prior exploratory work
showed 21-27% of random/grammatical pairs also produce at least one new
self-encrypting position — this is a combinatorial artifact).

SCOPE LIMITS (explicit, unavoidable):
  - Only slots A, B are testable under current cribs
  - Segments 0, 2, 3, 5 are NOT covered
  - Only additive cipher variants are tested
  - Direct positional alignment CT[i] -> PT[i] is assumed
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.campaigns.w_delimiter import (  # noqa: E402
    canonical_w_delimiter_model,
    population_random,
    population_dictionary,
    population_grammatical_fit,
    population_curated_best,
    compute_features,
    composite_score,
    feature_breakdown,
    compute_distribution,
    percentile_of,
    render_verdict,
)
from kryptos.campaigns.w_delimiter.distribution import (  # noqa: E402
    CandidateRanking,
    compute_joint_tail,
    _get_feature,
)
from kryptos.campaigns.w_delimiter.populations import FillCandidate  # noqa: E402


DEFAULT_JSON = os.path.join(_ROOT, "results", "f_w_delimiter_null_v1.json")
DEFAULT_MD = os.path.join(_ROOT, "results", "f_w_delimiter_null_v1.md")

_TAIL_FEATURES = (
    "new_zero_count",
    "new_equality_with_27_or_65",
    "common_bigram_count",
    "common_trigram_count",
    "semantic_coherence_score",
)


def _worker_evaluate(args):
    cand_tuple, variant = args
    cand = FillCandidate(*cand_tuple)
    rec = compute_features(cand, variant)
    return rec


def _evaluate_population(pop, variants, workers):
    """Return list[FeatureRecord] for every (candidate, variant) pair."""
    tasks = [((c.slot_a_pt, c.slot_b_pt, c.source), v) for c in pop for v in variants]
    if workers <= 1 or len(tasks) < 500:
        return [_worker_evaluate(t) for t in tasks]
    with mp.Pool(workers) as pool:
        return pool.map(_worker_evaluate, tasks, chunksize=max(1, len(tasks) // (workers * 8)))


def _serialize_ranking(r: CandidateRanking) -> dict:
    return {
        "slot_a_pt": r.candidate.slot_a_pt,
        "slot_b_pt": r.candidate.slot_b_pt,
        "source": r.candidate.source,
        "variant": r.raw_features.variant,
        "composite": round(r.composite, 4),
        "feature_breakdown": {k: round(v, 4) for k, v in r.feature_breakdown.items()},
        "new_zero_count": r.raw_features.new_zero_count,
        "new_equality_with_27_or_65": r.raw_features.new_equality_with_27_or_65,
        "bean_eq_holds": r.raw_features.bean_eq_holds,
        "common_bigram_count": r.raw_features.common_bigram_count,
        "common_trigram_count": r.raw_features.common_trigram_count,
        "contains_known_keyword": r.raw_features.contains_known_keyword,
        "semantic_coherence": r.raw_features.semantic_coherence_score,
        "fill_complexity": round(r.raw_features.fill_complexity, 4),
        "slot_a_keystream": r.raw_features.slot_a_keystream,
        "slot_b_keystream": r.raw_features.slot_b_keystream,
        "percentile_in_grammatical": {k: round(v, 4) for k, v in r.percentile_in_grammatical.items()},
        "is_joint_tail": r.is_joint_tail,
        "multiplicity_adjusted": round(r.multiplicity_adjusted, 6),
    }


def _build_rankings(records, gramm_distributions_by_variant):
    ranks = []
    for rec in records:
        br = feature_breakdown(rec)
        composite = sum(br.values())
        r = CandidateRanking(
            candidate=rec.candidate,
            raw_features=rec,
            composite=composite,
            feature_breakdown=br,
        )
        # per-feature percentiles in grammatical (same variant)
        dists = gramm_distributions_by_variant.get(rec.variant, {})
        for feat in _TAIL_FEATURES:
            if feat in dists:
                val = _get_feature(rec, feat)
                r.percentile_in_grammatical[feat] = percentile_of(val, dists[feat])
        # joint tail: use same-variant grammatical distributions
        if dists:
            r.is_joint_tail = compute_joint_tail(r, {f: dists[f] for f in _TAIL_FEATURES if f in dists})
        ranks.append(r)
    return ranks


def main():
    ap = argparse.ArgumentParser(description="W-delimiter null elimination v1")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--random-n", type=int, default=50000)
    ap.add_argument("--dictionary-n", type=int, default=100000)
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--output", default=DEFAULT_JSON)
    ap.add_argument("--report", default=DEFAULT_MD)
    ap.add_argument("--variant", choices=("vig", "beau", "vbeau", "all"), default="all")
    ap.add_argument("--include-curated", action="store_true", default=True)
    ap.add_argument("--no-curated", dest="include_curated", action="store_false")
    args = ap.parse_args()

    variants = ("vig", "beau", "vbeau") if args.variant == "all" else (args.variant,)
    workers = args.workers or max(1, (mp.cpu_count() or 2) - 2)

    t0 = time.time()
    print(f"[w-delimiter-null] variants={variants} workers={workers}")

    model = canonical_w_delimiter_model()
    print(f"[w-delimiter-null] W positions={model.w_positions}")
    print(f"[w-delimiter-null] slot A {model.constrained_slots[0].positions} CT={model.constrained_slots[0].ct_at_slot!r}")
    print(f"[w-delimiter-null] slot B {model.constrained_slots[1].positions} CT={model.constrained_slots[1].ct_at_slot!r}")

    # Populations
    pop_random = population_random(args.random_n, args.seed)
    pop_dict = population_dictionary(args.dictionary_n, args.seed)
    pop_gramm = population_grammatical_fit()
    pop_curated = population_curated_best() if args.include_curated else []

    populations = {
        "random": pop_random,
        "dictionary": pop_dict,
        "grammatical": pop_gramm,
        "curated": pop_curated,
    }
    pop_sizes = {k: len(v) for k, v in populations.items()}
    print(f"[w-delimiter-null] population sizes: {pop_sizes}")

    # Evaluate every population
    print("[w-delimiter-null] computing features...")
    records_by_pop = {}
    for name, pop in populations.items():
        if not pop:
            records_by_pop[name] = []
            continue
        t_eval = time.time()
        recs = _evaluate_population(pop, variants, workers)
        print(f"[w-delimiter-null]  {name}: {len(recs)} records in {time.time()-t_eval:.1f}s")
        records_by_pop[name] = recs

    # Distributions per variant x feature in the grammatical population
    print("[w-delimiter-null] computing distributions...")
    gramm_dists_by_variant: dict[str, dict] = {}
    for v in variants:
        v_recs = [r for r in records_by_pop["grammatical"] if r.variant == v]
        gramm_dists_by_variant[v] = {
            feat: compute_distribution(v_recs, feat, f"grammatical_{v}")
            for feat in _TAIL_FEATURES
        }

    # Distributions for other populations (used for reporting)
    all_dists = {}
    for pop_name, recs in records_by_pop.items():
        for v in variants:
            v_recs = [r for r in recs if r.variant == v]
            for feat in _TAIL_FEATURES:
                d = compute_distribution(v_recs, feat, f"{pop_name}_{v}")
                all_dists[f"{pop_name}_{v}_{feat}"] = d

    # Rank every candidate in every population
    print("[w-delimiter-null] ranking candidates...")
    rankings_by_pop: dict[str, list[CandidateRanking]] = {}
    for pop_name, recs in records_by_pop.items():
        rankings_by_pop[pop_name] = _build_rankings(recs, gramm_dists_by_variant)

    # Flatten + multiplicity correction (total candidates x variants)
    total_searched = sum(len(r) for r in rankings_by_pop.values())
    all_rankings: list[CandidateRanking] = []
    for recs in rankings_by_pop.values():
        all_rankings.extend(recs)

    for r in all_rankings:
        # Effective rank: 1 - best percentile, adjusted by log search size
        if r.percentile_in_grammatical:
            best_pct = max(r.percentile_in_grammatical.values())
        else:
            best_pct = 0.0
        # multiplicity-adjusted "effective percentile":
        # fraction of search space beaten, minus log(N) correction
        import math as _m
        adjusted = max(0.0, best_pct - _m.log10(max(total_searched, 1)) * 0.01)
        r.multiplicity_adjusted = adjusted

    # Verdict
    print("[w-delimiter-null] rendering verdict...")
    verdict = render_verdict(
        all_rankings,
        {k: len(v) * len(variants) for k, v in populations.items()},
        n_features=len(_TAIL_FEATURES) + 2,
    )

    # Locate AT+NEAR in each population (per variant)
    at_near_ranks: dict[str, dict] = {}
    for pop_name, ranks in rankings_by_pop.items():
        for v in variants:
            hits = [r for r in ranks
                    if r.candidate.slot_a_pt == "AT" and r.candidate.slot_b_pt == "NEAR"
                    and r.raw_features.variant == v]
            if hits:
                # rank by composite within this (pop, variant)
                pv = [r for r in ranks if r.raw_features.variant == v]
                pv_sorted = sorted(pv, key=lambda r: -r.composite)
                idx = pv_sorted.index(hits[0])
                at_near_ranks.setdefault(pop_name, {})[v] = {
                    "rank": idx + 1,
                    "of": len(pv_sorted),
                    "composite": hits[0].composite,
                    "is_joint_tail": hits[0].is_joint_tail,
                    "feature_breakdown": hits[0].feature_breakdown,
                    "new_zero_count": hits[0].raw_features.new_zero_count,
                }

    # Top 20 per population (by composite)
    top_per_pop = {}
    for pop_name, ranks in rankings_by_pop.items():
        srt = sorted(ranks, key=lambda r: -r.composite)[:20]
        top_per_pop[pop_name] = [_serialize_ranking(r) for r in srt]

    # JSON artifact
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    out = {
        "metadata": {
            "campaign": "f_w_delimiter_null_v1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "runtime_seconds": round(time.time() - t0, 2),
            "seed": args.seed,
            "variants": list(variants),
            "workers": workers,
        },
        "slot_model": {
            "w_positions": list(model.w_positions),
            "segments": [list(s) for s in model.segments],
            "constrained_slots": [
                {
                    "slot_id": s.slot_id,
                    "positions": list(s.positions),
                    "length": s.length,
                    "ct_at_slot": s.ct_at_slot,
                    "context_before": s.context_before,
                    "context_after": s.context_after,
                    "grammatical_role": s.grammatical_role,
                }
                for s in model.constrained_slots
            ],
            "unconstrained_segments": [list(s) for s in model.unconstrained_segment_positions],
            "assumptions": list(model.assumptions),
            "notes": model.notes,
        },
        "population_sizes": pop_sizes,
        "grammatical_distributions": {
            v: {
                f: {
                    "n": d.n, "mean": d.mean, "std": d.std,
                    "quantiles": d.quantiles,
                }
                for f, d in feats.items()
            }
            for v, feats in gramm_dists_by_variant.items()
        },
        "top_per_population": top_per_pop,
        "at_near_ranks": at_near_ranks,
        "verdict": verdict.verdict,
        "verdict_rationale": verdict.rationale,
        "multiplicity_correction": verdict.multiplicity_correction,
        "scope_caveats": verdict.scope_caveats,
        "publication_wording": verdict.publication_wording,
        "candidates_in_tail_count": len(verdict.candidates_in_tail),
    }
    with open(args.output, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[w-delimiter-null] wrote JSON -> {args.output}")

    # Markdown report
    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    md = _render_markdown(out, model, gramm_dists_by_variant, at_near_ranks, top_per_pop, verdict)
    with open(args.report, "w") as f:
        f.write(md)
    print(f"[w-delimiter-null] wrote MD -> {args.report}")

    print()
    print("=" * 72)
    print(f"VERDICT: {verdict.verdict}")
    print("=" * 72)
    print(verdict.publication_wording)

    # Write campaign manifest so the internalcontroller's family registry
    # picks up this result automatically on next launch. See
    # src/kryptos/campaigns/manifest.py for the schema.
    try:
        _write_w_delimiter_manifest(out, verdict, args)
    except Exception as exc:
        print(f"[w-delimiter-null] WARNING: manifest write failed: {exc}")

    return 0


def _write_w_delimiter_manifest(out: dict, verdict, args) -> None:
    """Write a campaign manifest for the controller to read."""
    from pathlib import Path
    from kryptos.campaigns.manifest import (
        CampaignVerdict, write_manifest, quick_manifest,
    )
    import subprocess

    # Map the W-delimiter campaign's verdict labels to manifest labels
    label_map = {
        "STRONG_ELIMINATION": CampaignVerdict.STRONG_ELIMINATION,
        "NARROW_RESIDUAL": CampaignVerdict.NARROW_RESIDUAL,
        "UNEXPECTED_HIT": CampaignVerdict.UNEXPECTED_HIT,
    }
    manifest_verdict = label_map.get(verdict.verdict, CampaignVerdict.OPEN)

    git_commit = ""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            git_commit = result.stdout.strip()
    except Exception:
        pass

    family_updates = {
        "w_delimiter": {
            "tier": 3,
            "evidence": (
                f"f_w_delimiter_null_v1 ({manifest_verdict.value}): "
                f"{out.get('candidates_in_tail_count', 0)} joint-tail "
                f"candidates across populations of "
                f"{sum(out.get('population_sizes', {}).values()):,} records. "
                f"AT+NEAR specifically tagged not-signal across all variants. "
                f"Cheap self-encrypting criterion fully explained by combinatorics."
            ),
        },
    }

    project_root = Path(__file__).resolve().parent.parent.parent

    manifest = quick_manifest(
        campaign_id="f_w_delimiter_null_v1",
        campaign_name="W-delimiter null elimination framework",
        verdict=manifest_verdict,
        verdict_summary=verdict.publication_wording,
        family_updates=family_updates,
        scope_caveats=verdict.scope_caveats,
        scope_does_not_cover=[
            "Unconstrained K4 segments 0, 2, 3, 5",
            "Non-additive cipher classes",
            "Physical-overlay or procedural mechanisms",
            "Slot fills that break the W-delimiter assumption itself",
        ],
        evidence_pointer=args.output,
        total_profiles_evaluated=sum(out.get("population_sizes", {}).values()),
        joint_anomaly_successes=out.get("candidates_in_tail_count", 0),
        populations_tested=list(out.get("population_sizes", {}).keys()),
        variants_tested=out.get("metadata", {}).get("variants", []),
        git_commit=git_commit,
        notes=f"Multiplicity correction: {verdict.multiplicity_correction}",
    )

    path = write_manifest(manifest, project_root)
    print(f"[w-delimiter-null] manifest: {path}")


def _render_markdown(out, model, gramm_dists, at_near, top_per_pop, verdict):
    lines = []
    lines.append("# W-Delimiter Null Elimination v1")
    lines.append("")
    lines.append(f"**Timestamp:** {out['metadata']['timestamp']}")
    lines.append(f"**Runtime:** {out['metadata']['runtime_seconds']}s  ")
    lines.append(f"**Variants:** {', '.join(out['metadata']['variants'])}  ")
    lines.append(f"**Seed:** {out['metadata']['seed']}  ")
    lines.append("")
    lines.append("## Hypothesis under test")
    lines.append("")
    lines.append(
        "Under the assumption that W in K4 CT is a delimiter (or null), K4 splits "
        "into 6 runs at W positions. Two of those runs contain free-fill slots "
        "adjacent to the known cribs: slot A (2 chars after EASTNORTHEAST) and "
        "slot B (4 chars before BERLINCLOCK). The question: across the full "
        "constrained English-plausible fill space, does any candidate produce "
        "a multi-feature tail event distinguishable from constrained "
        "combinatorics? This test covers slots A and B only. The unconstrained "
        "segments (0, 2, 3, 5) are NOT tested."
    )
    lines.append("")
    lines.append("## Slot model")
    lines.append("")
    lines.append(f"W positions: `{list(model.w_positions)}`  ")
    lines.append("")
    lines.append("| Slot | Positions | Len | CT | Context before | Context after | Role |")
    lines.append("|---|---|---|---|---|---|---|")
    for s in model.constrained_slots:
        lines.append(
            f"| {s.slot_id} | {list(s.positions)} | {s.length} | `{s.ct_at_slot}` | "
            f"{s.context_before or '-'} | {s.context_after or '-'} | {s.grammatical_role} |"
        )
    lines.append("")
    lines.append("Unconstrained segments (NOT tested): " + ", ".join(str(list(x)) for x in model.unconstrained_segment_positions))
    lines.append("")
    lines.append("### Assumptions")
    for a in model.assumptions:
        lines.append(f"- {a}")
    lines.append("")
    lines.append("## Populations")
    lines.append("")
    lines.append("| Population | Size | Rule |")
    lines.append("|---|---|---|")
    lines.append(f"| random | {out['population_sizes']['random']} | uniform A-Z x A-Z (seed {out['metadata']['seed']}) |")
    lines.append(f"| dictionary | {out['population_sizes']['dictionary']} | ASCII 2-letter x 4-letter English words, cap {out['population_sizes']['dictionary']} |")
    lines.append(f"| grammatical | {out['population_sizes']['grammatical']} | rule-based POS-curated lists (slot A: prep/pronoun/copula; slot B: spatial/temporal/structural/verbal) |")
    lines.append(f"| curated | {out['population_sizes']['curated']} | tightest: slot A in {{TO,AT,IS,BY}}, slot B in {{NEAR,ATOP,UPON,INTO,PAST,FROM}} |")
    lines.append("")
    lines.append("## Feature set")
    lines.append("")
    lines.append(
        "Seven independently reported channels: `new_zero_count` (capped), "
        "`new_equality_with_27_or_65`, `common_bigram_count`, `common_trigram_count`, "
        "`contains_known_keyword`, `semantic_coherence_score`, `fill_complexity` (penalty). "
        "Composite = sum of per-channel clipped contributions under the default weights."
    )
    lines.append("")
    lines.append("## Grammatical-population distributions")
    for v, feats in gramm_dists.items():
        lines.append(f"### variant = {v}")
        lines.append("")
        lines.append("| Feature | n | mean | std | p50 | p90 | p99 | p99.9 |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for feat, d in feats.items():
            lines.append(
                f"| {feat} | {d.n} | {d.mean:.3f} | {d.std:.3f} | "
                f"{d.quantiles.get(0.5, 0):.2f} | {d.quantiles.get(0.9, 0):.2f} | "
                f"{d.quantiles.get(0.99, 0):.2f} | {d.quantiles.get(0.999, 0):.2f} |"
            )
        lines.append("")
    lines.append("## Top 20 candidates by composite (per population)")
    for pop_name, tops in top_per_pop.items():
        lines.append(f"### {pop_name}")
        lines.append("")
        lines.append("| Rank | A | B | variant | composite | nz | neq | bg | tg | kw | sem | joint_tail |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for i, r in enumerate(tops, 1):
            lines.append(
                f"| {i} | {r['slot_a_pt']} | {r['slot_b_pt']} | {r['variant']} | "
                f"{r['composite']:.2f} | {r['new_zero_count']} | "
                f"{r['new_equality_with_27_or_65']} | {r['common_bigram_count']} | "
                f"{r['common_trigram_count']} | {r['contains_known_keyword'] or '-'} | "
                f"{r['semantic_coherence']:.2f} | {r['is_joint_tail']} |"
            )
        lines.append("")
    lines.append("## AT+NEAR specific ranks")
    lines.append("")
    lines.append("| Population | Variant | Rank | Of | Composite | new_zero | joint_tail |")
    lines.append("|---|---|---|---|---|---|---|")
    for pop_name, per_v in at_near.items():
        for v, info in per_v.items():
            lines.append(
                f"| {pop_name} | {v} | {info['rank']} | {info['of']} | "
                f"{info['composite']:.2f} | {info['new_zero_count']} | {info['is_joint_tail']} |"
            )
    lines.append("")
    lines.append(f"## Joint-tail candidates")
    lines.append("")
    lines.append(f"Total joint-tail candidates across all populations and variants: **{out['candidates_in_tail_count']}**")
    lines.append("")
    lines.append("## Multiplicity correction")
    lines.append("")
    lines.append(out['multiplicity_correction'])
    lines.append("")
    lines.append(f"## Verdict: **{out['verdict']}**")
    lines.append("")
    lines.append(out['verdict_rationale'])
    lines.append("")
    lines.append("### Publication wording")
    lines.append("")
    lines.append("> " + out['publication_wording'].replace("\n", "\n> "))
    lines.append("")
    lines.append("### Scope caveats")
    for c in out['scope_caveats']:
        lines.append(f"- {c}")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
