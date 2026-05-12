"""Swing K-1 serial and parallel orchestration."""
from __future__ import annotations

import multiprocessing as mp
import subprocess
from itertools import islice
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
    prepare_corpus,
    scan_source_text_prepared,
)
from kryptosbot.swing_k1_universe import Config, compute_universe_hash, enumerate_universe


def _git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "UNKNOWN"


def _evaluate_config(config: Config, prepared_tier_a, prepared_tier_b) -> dict:
    """Single-config evaluation. Returns a row dict ready for configs.jsonl.

    `prepared_tier_a` / `prepared_tier_b` are tuples produced by
    `swing_k1_structure.prepare_corpus()` — precomputed bytes buffers that
    let the S1 scan use C-level `bytes.find` (~300x faster than the legacy
    `scan_source_text` path).
    """
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
    s1 = scan_source_text_prepared(seq[:24], prepared_tier_a)
    s1_tier_b = scan_source_text_prepared(seq[:24], prepared_tier_b) if prepared_tier_b else None
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
    # Prepare corpora ONCE — bytes.find against precomputed idx_bytes is the
    # critical S1 perf fix (legacy scan_source_text was ~300x slower).
    prepared_tier_a = prepare_corpus(tier_a.entries)
    prepared_tier_b = prepare_corpus(tier_b.entries)
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
        row = _evaluate_config(config, prepared_tier_a, prepared_tier_b)
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


def _worker(payload: dict) -> dict:
    """Pool worker. Re-imports and re-derives to keep the inter-process payload small."""
    from kryptosbot.swing_k1_corpus import load_tier_a, load_tier_b
    from kryptosbot.swing_k1_structure import prepare_corpus
    from kryptosbot.swing_k1_universe import Config as _Config
    # Reconstruct Config from the payload dict.
    config = _Config(
        spec_hash=payload["spec_hash"],
        model_variant=payload["model_variant"],
        variant=payload["variant"],
        alphabet=payload["alphabet"],
        mask_id=payload["mask_id"],
        null_positions=frozenset(payload["null_positions"]),
        null_consumption_mode=payload["null_consumption_mode"],
        tape_length=payload["tape_length"],
        segment_boundaries=tuple(payload["segment_boundaries"]) if payload["segment_boundaries"] else None,
        control_arm=payload["control_arm"],
    )
    prepared_tier_a = prepare_corpus(load_tier_a().entries)
    prepared_tier_b = prepare_corpus(load_tier_b().entries)
    return _evaluate_config(config, prepared_tier_a, prepared_tier_b)


def _config_to_payload(c: Config) -> dict:
    return {
        "spec_hash": c.spec_hash,
        "model_variant": c.model_variant,
        "variant": c.variant,
        "alphabet": c.alphabet,
        "mask_id": c.mask_id,
        "null_positions": sorted(c.null_positions),
        "null_consumption_mode": c.null_consumption_mode,
        "tape_length": c.tape_length,
        "segment_boundaries": list(c.segment_boundaries) if c.segment_boundaries else None,
        "control_arm": c.control_arm,
    }


def run_parallel(
    out_dir: Path,
    max_configs: Optional[int] = None,
    only_m1: bool = False,
    n_workers: int = 24,
    per_task_timeout_sec: float = 60.0,
) -> dict:
    """Parallel-pool variant of run_serial.

    Uses `multiprocessing.Pool.apply_async` + per-future `.get(timeout=...)` so
    a single hung worker cannot block the entire pool — see
    `feedback_pool_worker_no_per_task_timeout.md` for the cycle-245 deadlock
    that motivates the per-future timeout pattern.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    configs_path = out_dir / "configs.jsonl"
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
            "per_task_timeout_sec": per_task_timeout_sec,
        },
        mask_catalog_path="(in-memory)",
        corpus_manifest_path="data/swing_k1/tier_a_manifest.json",
        total_config_count=-1,
    )
    total = 0
    iter_configs: Iterable[Config] = enumerate_universe()
    if only_m1:
        iter_configs = (c for c in iter_configs if c.model_variant == "M1")
    if max_configs is not None:
        iter_configs = islice(iter_configs, max_configs)
    ctx = mp.get_context("spawn")
    with ctx.Pool(processes=n_workers) as pool:
        async_results = []
        for config in iter_configs:
            payload = _config_to_payload(config)
            ar = pool.apply_async(_worker, (payload,))
            async_results.append((config, ar))
        for config, ar in async_results:
            try:
                row = ar.get(timeout=per_task_timeout_sec)
            except mp.TimeoutError:
                row = {
                    "spec_hash": config.spec_hash,
                    "model_variant": config.model_variant,
                    "error": "per_task_timeout",
                }
            append_config_row(configs_path, row)
            total += 1
    # Spec section 8.1: emit split artifacts.
    from kryptosbot.swing_k1_artifacts import split_artifacts, write_null_calibration
    counts = split_artifacts(out_dir)
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
