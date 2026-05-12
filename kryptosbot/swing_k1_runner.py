"""Swing K-1 serial and parallel orchestration."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable, Optional

from kryptosbot.swing_k1_artifacts import append_config_row, write_manifest, write_verdict_md
from kryptosbot.swing_k1_corpus import load_tier_a, load_tier_b
from kryptosbot.swing_k1_recovery import (
    bean_filter,
    derive_keystream_ct73,
    derive_keystream_ct97,
)
from kryptosbot.swing_k1_structure import (
    StructureVerdict,
    evaluate_structure_promotion,
    match_generator,
    match_keyword_expansion,
    ngram_score,
    scan_source_text,
)
from kryptosbot.swing_k1_universe import Config, compute_universe_hash, enumerate_universe


def _git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "UNKNOWN"


def _evaluate_config(config: Config, tier_a_entries, tier_b_entries) -> dict:
    """Single-config evaluation. Returns a row dict ready for configs.jsonl."""
    # M3 uses CT73 derivation; others use CT97
    if config.model_variant == "M3":
        implied = derive_keystream_ct73(
            variant=config.variant,
            alphabet=config.alphabet,
            null_positions=config.null_positions,
        )
    else:
        implied = derive_keystream_ct97(
            variant=config.variant,
            alphabet=config.alphabet,
            null_positions=config.null_positions,
        )
    bean = bean_filter(implied)
    row = {
        "spec_hash": config.spec_hash,
        "model_variant": config.model_variant,
        "variant": config.variant,
        "alphabet": config.alphabet,
        "mask_id": config.mask_id,
        "null_consumption_mode": config.null_consumption_mode,
        "tape_length": config.tape_length,
        "segment_boundaries": list(config.segment_boundaries) if config.segment_boundaries else None,
        "control_arm": config.control_arm,
        "crib_positions_used": sorted(implied.keys()),
        "implied_keystream": [implied[p] for p in sorted(implied.keys())],
        "bean_passed": bean.passed,
        "bean_eq_checked": bean.eq_checked,
        "bean_ineq_checked": bean.ineq_checked,
        "bean_linear_checked": bean.linear_checked,
    }
    if not bean.passed:
        return row
    # Bean admitted: run the structure suite.
    seq = [implied[p] for p in sorted(implied.keys())]
    if len(seq) < 24:
        # Sparse mask: skip structure suite (would not meet length thresholds).
        row["structure_skipped_short"] = True
        return row
    s1 = scan_source_text(seq[:24], tier_a_entries)
    s1_tier_b = scan_source_text(seq[:24], tier_b_entries) if tier_b_entries else None
    s2 = match_keyword_expansion(seq[:24])
    s3 = match_generator(seq[:24])
    s4 = ngram_score(seq[:24])
    verdict = StructureVerdict(s1=s1, s2=s2, s3=s3, s4_score=s4)
    promote, reason = evaluate_structure_promotion(verdict)
    row.update({
        "s1_match": None if s1 is None else {"source": s1.source_id, "offset": s1.offset, "len": s1.match_len},
        "s1_tier_b_match": None if s1_tier_b is None else {"source": s1_tier_b.source_id, "offset": s1_tier_b.offset, "len": s1_tier_b.match_len},
        "s2_match": None if s2 is None else {"keyword": s2.keyword, "len": s2.match_len},
        "s3_match": None if s3 is None else {"generator": s3.generator, "seed": list(s3.seed), "strength": s3.match_strength},
        "s4_ngram_score": s4,
        "promote_eligible": promote,
        "promotion_reason": reason,
    })
    return row


def run_serial(
    out_dir: Path,
    max_configs: Optional[int] = None,
    only_m1: bool = False,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    configs_path = out_dir / "configs.jsonl"
    tier_a = load_tier_a()
    tier_b = load_tier_b()
    universe_hash = compute_universe_hash()
    write_manifest(
        out_path=out_dir / "manifest.json",
        universe_hash=universe_hash,
        kernel_commit=_git_head(),
        prereg_thresholds={
            "promotion_p_max": 1e-6,
            "s1_min_match_len": 24,
            "s2_min_match_len": 8,
            "s3_min_match_strength": 0.95,
            "baseline_n_trials": 10_000,
        },
        mask_catalog_path="(in-memory)",
        corpus_manifest_path="data/swing_k1/tier_a_manifest.json",
        total_config_count=-1,  # filled in below
    )
    total = 0
    for config in enumerate_universe():
        if only_m1 and config.model_variant != "M1":
            continue
        if max_configs is not None and total >= max_configs:
            break
        row = _evaluate_config(config, tier_a.entries, tier_b.entries)
        append_config_row(configs_path, row)
        total += 1
    # Spec section 8.1: emit split artifacts derived from configs.jsonl.
    from kryptosbot.swing_k1_artifacts import split_artifacts, write_null_calibration
    counts = split_artifacts(out_dir)
    # Calibration is only meaningful when there are promotion-eligible
    # candidates. Spec section 7.1 stage 1 (10K shuffled CTs) and stage 2 (1M MC or
    # analytical Binomial) are gated on `counts["promotions"] > 0`. With zero
    # candidates the null_calibration.json records that fact honestly rather
    # than emitting placeholder shuffles that were never executed.
    write_null_calibration(
        out_path=out_dir / "null_calibration.json",
        method="not_run_no_promotion_candidates" if counts["promotions"] == 0 else "deferred_manual_escalation",
        n_trials=0,
        sampled_config_count=0,
        baseline_max_joint_event_count=0,
        candidate_p_values={},
    )
    write_verdict_md(
        out_path=out_dir / "verdict.md",
        classification="NULL_LEVEL" if counts["promotions"] == 0 else "PROMOTION_CANDIDATE",
        universe_hash=universe_hash,
        total_configs=total,
        admitted_count=counts["admitted"],
        promotions_count=counts["promotions"],
        tier_b_hits_count=counts["tier_b_hits"],
    )
    return {
        "total_evaluated": total,
        "bean_admitted": counts["admitted"],
        "promotions": counts["promotions"],
        "tier_b_hits": counts["tier_b_hits"],
        "out_dir": str(out_dir),
    }
