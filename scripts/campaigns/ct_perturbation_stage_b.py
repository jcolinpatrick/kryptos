#!/usr/bin/env python3
"""CT-Perturbation Stage B campaign runner + synthetic-recovery test.

What this module does:
    - Validates the ``--ambiguous-positions PATH`` JSON manifest using
      the framework's ``load_ambiguous_positions`` schema validator.
    - Computes the Stage B universe size for the supplied ``A``.
    - Runs the prereg §7 synthetic-recovery test:
        §7.1 Selective — plant H2 corruption at two crib positions,
              verify the H2-constrained sweep over ``A* = {p1, p2}``
              recovers the original encryption (alert fires for the
              planted (p1, old, new), (p2, old, new) tuple).
        §7.2 Structural — plant H2 corruption at non-crib positions,
              verify no false alert fires AND Bean state is unchanged
              from canonical (Bean is invariant under non-crib edits).
      Each case runs against BOTH cipher fixtures the prereg requires:
      Vigenère + AZ + ``PALIMPSEST`` and Beaufort + KA + ``KRYPTOS``.
    - Enumerates the full Stage B universe and runs the sweep under
      ``--execute-full``. The v1 loop inherits Stage A's worker pool
      and JSONL artifact schema; the H2 row schema extends Stage A's
      with ``pos_pair``, ``chars_pair``, and ``crib_overlapping``.

Exit codes:
    0  manifest validated; recovery test passed (if requested);
       dry-run summary printed; or ``--execute-full`` sweep completed.
    2  configuration error (missing arg, schema invalid, k>20 without
       override, etc.).
    4  ``--synthetic-recovery-test`` requested and one or both probes
       failed.

Usage:
    PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \\
        --ambiguous-positions PATH/TO/A.json \\
        [--allow-large-ambiguous-set] \\
        [--synthetic-recovery-test [--recovery-artifact-dir DIR]] \\
        [--dry-run | --execute-full]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import logging
import multiprocessing as mp
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

# Standalone bootstrap (script lives 2 levels deep under repo root).
_HERE = Path(__file__).resolve()
_ROOT = _HERE.parent.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


from kryptos.kernel.alphabet import AZ as _AZ, KA as _KA  # noqa: E402
from kryptos.kernel.constants import CRIB_DICT, CT  # noqa: E402
from kryptos.kernel.scoring.ngram import get_default_scorer  # noqa: E402
from kryptos.kernel.transforms.vigenere import (  # noqa: E402
    CipherVariant,
    encrypt_text,
)
from kryptosbot.ct_perturbation import (  # noqa: E402
    ARTIFACT_SCHEMA_VERSION,
    AlertPolicy,
    AmbiguousPositionsManifest,
    CAMPAIGN_ID_STAGE_B,
    CANONICAL_CRIB_DICT,
    CandidateScore,
    CTVariantH2,
    ScorerContext,
    SUPPORTED_ALPHABET_KINDS,
    SUPPORTED_FAMILIES,
    TopNHeap,
    _ct_sha256,
    derive_bean_constraints,
    enumerate_hamming2_variants_constrained,
    load_ambiguous_positions,
    score_candidate_ct_parametric,
    stage_b_universe_size,
)
from scripts.campaigns.ct_perturbation_stage_a import (  # noqa: E402
    KeywordSource,
    atomic_write_json,
    load_keywords,
    _git_commit,
    _module_sha,
    _rejection_reason_bucket,
)


logger = logging.getLogger("ct_perturbation_stage_b")

_K_MAX_DEFAULT = 20  # prereg §3.3
_PREREG_PATH = "docs/campaigns/ct_perturbation_stage_b_prereg.md"
_RECOVERY_ARTIFACT_DEFAULT = (
    _ROOT / "results" / "ct_perturbation_stage_b" / "_synthetic_recovery"
)

# Fixed cipher fixtures the prereg §7 requires. Both must be tested in
# the selective probe.
_RECOVERY_FIXTURES: tuple[dict[str, Any], ...] = (
    {
        "label": "vigenere_AZ_PALIMPSEST",
        "family": CipherVariant.VIGENERE,
        "alphabet_kind": "AZ",
        "alphabet": _AZ,
        "keyword": "PALIMPSEST",
    },
    {
        "label": "beaufort_KA_KRYPTOS",
        "family": CipherVariant.BEAUFORT,
        "alphabet_kind": "KA",
        "alphabet": _KA,
        "keyword": "KRYPTOS",
    },
)

# Crib positions used to plant the §7.1 selective probe. Both must be
# in the canonical crib set; we use the EAST/BERLIN boundary positions
# so the planted correction overlaps both crib regions.
_SELECTIVE_PROBE_POSITIONS: tuple[int, int] = (21, 63)

# Non-crib positions used for the §7.2 structural probe. Chosen from
# regions outside the cribs (positions 0-20, 34-62, 74-96).
_STRUCTURAL_PROBE_POSITIONS: tuple[int, int] = (10, 80)


# ─── sweep config ────────────────────────────────────────────────────────


@dataclass
class SweepConfig:
    """Internal config bundle for the Stage B H2 sweep driver.

    Mirrors Stage A's SweepConfig but typed against ``AmbiguousPositionsManifest``
    and uses ``max_h2_variants`` rather than the H1 ``max_ct_variants`` cap.
    """
    ct: str
    keywords: list[str]
    manifest: AmbiguousPositionsManifest | None
    families: tuple[CipherVariant, ...] = SUPPORTED_FAMILIES
    alphabet_kinds: tuple[str, ...] = SUPPORTED_ALPHABET_KINDS
    universe_size: int = 1
    policy: AlertPolicy = field(default_factory=AlertPolicy)
    include_h0: bool = False
    max_h2_variants: int | None = None
    max_configs: int | None = None
    keyword_limit: int | None = None
    crib_dict: dict[int, str] = field(default_factory=lambda: dict(CANONICAL_CRIB_DICT))
    run_id_for_logging: str = ""


# ─── sweep state accumulators ────────────────────────────────────────────


@dataclass
class SweepResults:
    """Accumulator for H2 sweep state."""
    candidates_evaluated: int = 0
    alerts: list[dict[str, Any]] = field(default_factory=list)
    watchlist: list[dict[str, Any]] = field(default_factory=list)
    top_n: TopNHeap = field(default_factory=lambda: TopNHeap(capacity=100))
    bean_pass_count: int = 0
    by_family_alert_count: dict[str, int] = field(default_factory=dict)
    by_alphabet_alert_count: dict[str, int] = field(default_factory=dict)
    rejection_reason_counts: dict[str, int] = field(default_factory=dict)
    variants_completed: int = 0
    last_completed_variant_id: str | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class VariantEvalResult:
    """Per-H2-variant result emitted by evaluate_one_h2_variant."""
    variant_id: str
    n_evaluated: int
    alerts: list[dict[str, Any]]
    watchlist: list[dict[str, Any]]
    top_candidates: list[tuple[float, dict[str, Any]]]
    bean_pass_count: int
    rejection_reason_counts: dict[str, int]
    trace_rows: list[dict[str, Any]]


# ─── H2 candidate row + helpers ──────────────────────────────────────────


_CRIB_POSITIONS_SET: frozenset[int] = frozenset(CANONICAL_CRIB_DICT.keys())


def _h2_candidate_row(
    run_id: str,
    variant: CTVariantH2,
    family: CipherVariant,
    alphabet_kind: str,
    keyword: str,
    score: CandidateScore,
    pt: str,
) -> dict[str, Any]:
    crib_overlapping = sum(
        1 for p in (variant.pos1, variant.pos2) if p in _CRIB_POSITIONS_SET
    )
    return {
        "run_id": run_id,
        "campaign_id": CAMPAIGN_ID_STAGE_B,
        "variant_id": variant.variant_id,
        "distance": variant.distance,
        "pos_pair": [variant.pos1, variant.pos2],
        "chars_pair": [variant.old1, variant.new1, variant.old2, variant.new2],
        "crib_overlapping": crib_overlapping,
        "ct_sha256": variant.ct_sha256,
        "family": family.value,
        "alphabet": alphabet_kind,
        "keyword": keyword,
        "effective_keyword_period": len(keyword),
        "pt": pt,
        "score": {
            "crib_score": score.crib_score,
            "crib_total": score.crib_total,
            "bean_passed": score.bean_passed,
            "bean_variant": score.bean_variant,
            "ngram_score": score.ngram_score,
            "crib_p_raw": score.crib_p_raw,
            "ngram_p_raw": score.ngram_p_raw,
            "ngram_null_available": score.ngram_null_available,
            "p_combined_raw": score.p_combined_raw,
            "p_adjusted": score.p_adjusted,
            "alert_class": score.alert_class,
            "rejection_reason": score.rejection_reason,
        },
    }


def _h2_summary_only(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "variant_id": row["variant_id"],
        "pos_pair": row["pos_pair"],
        "chars_pair": row["chars_pair"],
        "crib_overlapping": row["crib_overlapping"],
        "family": row["family"],
        "alphabet": row["alphabet"],
        "keyword": row["keyword"],
        "crib_score": row["score"]["crib_score"],
        "bean_passed": row["score"]["bean_passed"],
        "ngram_score": row["score"]["ngram_score"],
        "p_adjusted": row["score"]["p_adjusted"],
        "alert_class": row["score"]["alert_class"],
    }


# ─── per-variant evaluator ───────────────────────────────────────────────


def evaluate_one_h2_variant(
    variant: CTVariantH2,
    cfg: SweepConfig,
    *,
    ngram_scorer: Any,
    ngram_dist_az: Any,
    ngram_dist_ka: Any,
    trace_first_configs: int = 0,
) -> VariantEvalResult:
    """Score every (family x alphabet x keyword) cell for one H2 variant.

    ScorerContext.build is duck-type compatible: CTVariantH2 exposes
    .ct, .ct_sha256, .distance, .variant_id, same fields ScorerContext
    reads from a CTVariant.
    """
    keywords = (
        cfg.keywords if cfg.keyword_limit is None
        else cfg.keywords[: cfg.keyword_limit]
    )
    alerts: list[dict[str, Any]] = []
    watch: list[dict[str, Any]] = []
    heap_items: list[tuple[float, dict[str, Any]]] = []
    bean_pass = 0
    n_eval = 0
    rejection_counts: dict[str, int] = {}
    trace_rows: list[dict[str, Any]] = []

    ctx_by_kind = {
        "AZ": ScorerContext.build(
            variant, cfg.crib_dict, ngram_dist=ngram_dist_az, alphabet_kind="AZ",  # type: ignore[arg-type]
        ),
        "KA": ScorerContext.build(
            variant, cfg.crib_dict, ngram_dist=ngram_dist_ka, alphabet_kind="KA",  # type: ignore[arg-type]
        ),
    }

    for family in cfg.families:
        for kind in cfg.alphabet_kinds:
            ctx = ctx_by_kind[kind]
            for keyword in keywords:
                if cfg.max_configs is not None and n_eval >= cfg.max_configs:
                    return VariantEvalResult(
                        variant_id=variant.variant_id, n_evaluated=n_eval,
                        alerts=alerts, watchlist=watch,
                        top_candidates=heap_items, bean_pass_count=bean_pass,
                        rejection_reason_counts=rejection_counts,
                        trace_rows=trace_rows,
                    )
                score, pt = score_candidate_ct_parametric(
                    ctx, keyword=keyword, family=family,
                    alphabet_kind=kind, universe_size=cfg.universe_size,
                    policy=cfg.policy, ngram_scorer=ngram_scorer,
                )
                n_eval += 1
                reason = _rejection_reason_bucket(score.rejection_reason)
                rejection_counts[reason] = rejection_counts.get(reason, 0) + 1
                if score.bean_passed:
                    bean_pass += 1
                if len(trace_rows) < trace_first_configs:
                    trace_rows.append({
                        "variant_id": variant.variant_id,
                        "variant_distance": variant.distance,
                        "pos_pair": [variant.pos1, variant.pos2],
                        "family": family.value,
                        "alphabet": kind,
                        "keyword": keyword,
                        "effective_keyword_period": len(keyword),
                        "rejection_reason": score.rejection_reason,
                        "alert_class": score.alert_class,
                    })
                if score.alert_class in ("alert", "watchlist", "watchlist_null_unavailable"):
                    payload = _h2_candidate_row(
                        cfg.run_id_for_logging, variant, family, kind,
                        keyword, score, pt,
                    )
                    if score.alert_class == "alert":
                        alerts.append(payload)
                    else:
                        watch.append(payload)
                key = float(score.crib_score) * 1000.0 + float(
                    score.ngram_score if score.ngram_score is not None else -10.0
                )
                if score.crib_score >= 10:
                    payload = _h2_candidate_row(
                        cfg.run_id_for_logging, variant, family, kind,
                        keyword, score, pt,
                    )
                    heap_items.append((key, payload))

    return VariantEvalResult(
        variant_id=variant.variant_id, n_evaluated=n_eval,
        alerts=alerts, watchlist=watch, top_candidates=heap_items,
        bean_pass_count=bean_pass, rejection_reason_counts=rejection_counts,
        trace_rows=trace_rows,
    )


# ─── multiprocessing worker entry ────────────────────────────────────────


def _worker_evaluate_h2(args: tuple[CTVariantH2, SweepConfig]) -> VariantEvalResult:
    """Multiprocessing worker entry. Reconstructs scorer + null dist lazily
    in each subprocess so the parent doesn't have to serialize them.

    Per ``feedback_pool_worker_no_per_task_timeout.md`` the caller is
    responsible for per-future timeout. This worker function itself is
    best-effort and has no internal timeout."""
    variant, cfg = args
    try:
        ngram_scorer = get_default_scorer()
    except FileNotFoundError:
        ngram_scorer = None
    try:
        from kryptosbot.null_baselines import get_cached as _get_cached
        ngram_dist_az = _get_cached("ngram_score", "random_text", 97, "AZ")
        ngram_dist_ka = _get_cached("ngram_score", "random_text", 97, "KA")
    except Exception:
        ngram_dist_az = None
        ngram_dist_ka = None
    return evaluate_one_h2_variant(
        variant, cfg,
        ngram_scorer=ngram_scorer,
        ngram_dist_az=ngram_dist_az,
        ngram_dist_ka=ngram_dist_ka,
    )


# ─── checkpoint and summary writers ──────────────────────────────────────


def _h2_checkpoint(
    path: Path,
    results: SweepResults,
    started_at: float,
    started_at_iso: str,
    *,
    variants_total: int,
    expected_total: int,
    workers: int,
    status: str,
) -> None:
    updated_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "campaign_id": CAMPAIGN_ID_STAGE_B,
        "started_at": started_at_iso,
        "updated_at": updated_at,
        "status": status,
        "variants_completed": results.variants_completed,
        "variants_processed": results.variants_completed,
        "variants_total": variants_total,
        "candidates_evaluated": results.candidates_evaluated,
        "expected_total_config_cardinality": expected_total,
        "bean_pass_count": results.bean_pass_count,
        "alerts_count": len(results.alerts),
        "watchlist_count": len(results.watchlist),
        "elapsed_seconds": time.time() - started_at,
        "workers": workers,
        "last_completed_variant_id": results.last_completed_variant_id,
        "errors": results.errors,
    }
    atomic_write_json(path, payload)


def _build_h2_summary(
    *,
    run_id: str,
    results: SweepResults,
    started_at: float,
    status: str,
    workers: int,
    expected_total: int,
    run_metadata: dict[str, Any],
) -> dict[str, Any]:
    wall_time = time.time() - started_at
    configs_per_sec = (
        results.candidates_evaluated / wall_time if wall_time > 0 else 0.0
    )
    summary: dict[str, Any] = {
        "run_id": run_id,
        "campaign_id": CAMPAIGN_ID_STAGE_B,
        "status": status,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "canonical_ct_sha256": run_metadata.get("canonical_ct_sha256"),
        "ambiguous_positions_sha256": run_metadata.get("ambiguous_positions_sha256"),
        "k": run_metadata.get("k", 0),
        "h2_variants_executed": run_metadata.get(
            "h2_variants_executed", results.variants_completed,
        ),
        "families": [f.value for f in SUPPORTED_FAMILIES],
        "alphabets": list(SUPPORTED_ALPHABET_KINDS),
        "keyword_count": run_metadata.get("keyword_count", 0),
        "keyword_hash": run_metadata.get("keyword_hash", "empty"),
        "period_policy": "keyword_length",
        "expected_total_config_cardinality": expected_total,
        "candidates_evaluated": results.candidates_evaluated,
        "bean_pass_total": results.bean_pass_count,
        "bean_pass_count": results.bean_pass_count,
        "watchlist_total": len(results.watchlist),
        "alerts_total": len(results.alerts),
        "watchlist_count": len(results.watchlist),
        "alerts_count": len(results.alerts),
        "by_family_alert_count": dict(results.by_family_alert_count),
        "by_alphabet_alert_count": dict(results.by_alphabet_alert_count),
        "rejection_reason_counts": dict(results.rejection_reason_counts),
        "wall_time_seconds": wall_time,
        "configs_per_sec": configs_per_sec,
        "workers": workers,
        "errors": results.errors,
        "alerts": [_h2_summary_only(row) for row in results.alerts],
        "watchlist_preview": [
            _h2_summary_only(row) for row in results.watchlist[:25]
        ],
        "top_candidates_preview": [
            _h2_summary_only(payload)
            for payload in results.top_n.sorted_payloads()[:25]
        ],
    }
    summary.update({
        k: v for k, v in run_metadata.items() if k not in summary
    })
    return summary


def _iter_h2_variants(cfg: SweepConfig) -> Iterator[CTVariantH2]:
    """Yield CTVariantH2 instances from the manifest, respecting the
    optional max_h2_variants cap."""
    if cfg.manifest is None:
        return
    seen = 0
    for v in enumerate_hamming2_variants_constrained(cfg.ct, cfg.manifest):
        yield v
        seen += 1
        if cfg.max_h2_variants is not None and seen >= cfg.max_h2_variants:
            return


# ─── orchestrator ────────────────────────────────────────────────────────


def run_h2_sweep(
    cfg: SweepConfig,
    *,
    artifact_dir: Path,
    run_id: str,
    workers: int,
    progress_every_n_variants: int = 25,
    run_metadata: dict[str, Any] | None = None,
    trace_first_configs: int = 0,
    per_task_timeout_sec: float | None = None,
) -> SweepResults:
    """Drive the Stage B H2 sweep over CT variants enumerated from the
    ambiguous-position manifest. Writes JSONL artifacts and a progress
    checkpoint after each batch of variants. Single-process when
    ``workers <= 1`` or ``trace_first_configs > 0``; otherwise engages
    a ``spawn`` multiprocessing pool with per-future timeout enforcement.

    Per ``feedback_pool_worker_no_per_task_timeout.md`` the MP branch
    uses ``apply_async`` + ``.get(timeout=per_task_timeout_sec)`` rather
    than ``imap_unordered`` so a single hung worker cannot deadlock the
    entire sweep. ``multiprocessing.TimeoutError`` is recorded into
    ``results.errors`` as ``per_task_timeout`` and the sweep continues.
    """
    cfg.run_id_for_logging = run_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    run_metadata = dict(run_metadata or {})

    alerts_path = artifact_dir / "alerts.jsonl"
    watch_path = artifact_dir / "watchlist.jsonl"
    top_path = artifact_dir / "top_candidates.jsonl"
    trace_path = artifact_dir / "trace_first_configs.jsonl"
    progress_path = artifact_dir / "progress.json"
    summary_path = artifact_dir / "summary.json"
    chk_dir = artifact_dir / "checkpoints"
    chk_dir.mkdir(parents=True, exist_ok=True)
    for jsonl_path in (alerts_path, watch_path, top_path):
        jsonl_path.touch(exist_ok=True)
    if trace_first_configs:
        trace_path.write_text("")

    # Prereg §3.2 / §8: copy the operator-supplied manifest verbatim into
    # the run directory, and emit a derived universe_manifest so the run
    # is fully reproducible from its artifacts alone.
    if cfg.manifest is not None:
        atomic_write_json(
            artifact_dir / "ambiguous_positions_manifest.json",
            cfg.manifest.to_dict(),
        )
        universe = stage_b_universe_size(cfg.manifest, n_keywords=len(cfg.keywords))
        universe_payload: dict[str, Any] = {
            "schema_version": "ct_perturbation_stage_b.universe_manifest.v1",
            "campaign_id": CAMPAIGN_ID_STAGE_B,
            "run_id": run_id,
            "k": universe["k"],
            "position_pairs": universe["position_pairs"],
            "substitution_pairs": universe["substitution_pairs"],
            "h2_variants": universe["h2_variants"],
            "configs_per_variant": universe["configs_per_variant"],
            "total_configs": universe["total_configs"],
            "position_pair_list": [
                list(pair) for pair in cfg.manifest.position_pairs()
            ],
            "families": [f.value for f in cfg.families],
            "alphabet_kinds": list(cfg.alphabet_kinds),
            "n_keywords": len(cfg.keywords),
            "keyword_limit": cfg.keyword_limit,
            "max_h2_variants": cfg.max_h2_variants,
        }
        atomic_write_json(
            artifact_dir / "universe_manifest.json", universe_payload,
        )

    # Pre-build scorer + null distribution lookups once.
    try:
        ngram_scorer = get_default_scorer()
    except FileNotFoundError:
        logger.warning("ngram quadgram file missing; ngram scoring disabled")
        ngram_scorer = None

    try:
        from kryptosbot.null_baselines import get_cached as _get_cached
        ngram_dist_az = _get_cached("ngram_score", "random_text", 97, "AZ")
        ngram_dist_ka = _get_cached("ngram_score", "random_text", 97, "KA")
    except Exception:  # pragma: no cover — defensive
        ngram_dist_az = None
        ngram_dist_ka = None

    logger.info(
        "null cache: ngram_AZ=%s ngram_KA=%s",
        "present" if ngram_dist_az is not None else "missing",
        "present" if ngram_dist_ka is not None else "missing",
    )

    results = SweepResults()

    started_at = time.time()
    started_at_iso = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    variants_total = int(run_metadata.get("h2_variants_executed", 0))
    expected_total = int(run_metadata.get("expected_total_config_cardinality", cfg.universe_size))
    trace_remaining = max(0, trace_first_configs)

    def _write_trace(rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        with trace_path.open("a", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    def _merge_variant_result(result: VariantEvalResult) -> None:
        results.candidates_evaluated += result.n_evaluated
        results.bean_pass_count += result.bean_pass_count
        results.variants_completed += 1
        results.last_completed_variant_id = result.variant_id
        for reason, count in result.rejection_reason_counts.items():
            results.rejection_reason_counts[reason] = (
                results.rejection_reason_counts.get(reason, 0) + count
            )
        for row in result.alerts:
            with alerts_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
            results.alerts.append(_h2_summary_only(row))
            fam = row["family"]; alpha = row["alphabet"]
            results.by_family_alert_count[fam] = results.by_family_alert_count.get(fam, 0) + 1
            results.by_alphabet_alert_count[alpha] = results.by_alphabet_alert_count.get(alpha, 0) + 1
        for row in result.watchlist:
            with watch_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
            results.watchlist.append(_h2_summary_only(row))
        for key, payload in result.top_candidates:
            results.top_n.push(key, payload)
        _write_trace(result.trace_rows)

    def _process_one(variant: CTVariantH2, trace_limit: int = 0) -> VariantEvalResult:
        return evaluate_one_h2_variant(
            variant, cfg,
            ngram_scorer=ngram_scorer,
            ngram_dist_az=ngram_dist_az,
            ngram_dist_ka=ngram_dist_ka,
            trace_first_configs=trace_limit,
        )

    _h2_checkpoint(
        progress_path, results, started_at, started_at_iso,
        variants_total=variants_total, expected_total=expected_total,
        workers=workers, status="running",
    )

    try:
        if workers <= 1 or trace_first_configs:
            for variant in _iter_h2_variants(cfg):
                trace_limit = trace_remaining
                result = _process_one(variant, trace_limit=trace_limit)
                if trace_remaining:
                    trace_remaining = max(0, trace_remaining - len(result.trace_rows))
                _merge_variant_result(result)
                if results.variants_completed % progress_every_n_variants == 0:
                    _h2_checkpoint(
                        progress_path, results, started_at, started_at_iso,
                        variants_total=variants_total, expected_total=expected_total,
                        workers=workers, status="running",
                    )
        else:
            # Multiprocessing path: apply_async + per-future .get(timeout=...)
            # so a single hung worker cannot deadlock the parent. See
            # feedback_pool_worker_no_per_task_timeout.md (cycle 245 hang).
            with mp.get_context("spawn").Pool(workers) as pool:
                async_results = [
                    pool.apply_async(_worker_evaluate_h2, ((v, cfg),))
                    for v in _iter_h2_variants(cfg)
                ]
                for ar in async_results:
                    try:
                        result = ar.get(timeout=per_task_timeout_sec)
                    except mp.TimeoutError:
                        results.errors.append(
                            "per_task_timeout: H2 variant exceeded budget"
                        )
                        continue
                    _merge_variant_result(result)
                    if results.variants_completed % progress_every_n_variants == 0:
                        _h2_checkpoint(
                            progress_path, results, started_at, started_at_iso,
                            variants_total=variants_total, expected_total=expected_total,
                            workers=workers, status="running",
                        )
    except Exception as exc:
        results.errors.append(f"{type(exc).__name__}: {exc}")
        _h2_checkpoint(
            progress_path, results, started_at, started_at_iso,
            variants_total=variants_total, expected_total=expected_total,
            workers=workers, status="failed",
        )
        summary = _build_h2_summary(
            run_id=run_id,
            results=results,
            started_at=started_at,
            status="failed",
            workers=workers,
            expected_total=expected_total,
            run_metadata=run_metadata,
        )
        atomic_write_json(summary_path, summary)
        raise

    # Finalize artifacts.
    with top_path.open("w", encoding="utf-8") as fh:
        for payload in results.top_n.sorted_payloads():
            fh.write(json.dumps(payload, sort_keys=True) + "\n")

    status = "completed" if results.candidates_evaluated == expected_total else "incomplete"
    summary = _build_h2_summary(
        run_id=run_id,
        results=results,
        started_at=started_at,
        status=status,
        workers=workers,
        expected_total=expected_total,
        run_metadata=run_metadata,
    )
    atomic_write_json(summary_path, summary)
    _h2_checkpoint(
        progress_path, results, started_at, started_at_iso,
        variants_total=variants_total, expected_total=expected_total,
        workers=workers, status=status,
    )
    return results


# ─── synthetic recovery test ─────────────────────────────────────────────


def _build_synthetic_pt() -> str:
    """Build a 97-char synthetic plaintext that places the canonical 24
    cribs at canonical positions and fills non-crib slots with neutral
    filler. The filler matters only insofar as it determines the
    encrypted-CT bytes outside cribs; the recovery test does not score
    on filler content.
    """
    pt_chars = ["X"] * len(CT)
    for pos, ch in CRIB_DICT.items():
        pt_chars[pos] = ch
    return "".join(pt_chars)


def _swap_to_non_canonical(ct_char: str) -> str:
    """Return a letter that is alphabetic, uppercase, and != ct_char."""
    return "A" if ct_char != "A" else "B"


def _build_h2_corrupt_ct(
    true_ct: str, pos1: int, pos2: int
) -> tuple[str, dict[int, tuple[str, str]]]:
    """Apply Hamming-2 corruption at positions pos1 < pos2.

    Returns (corrupt_ct, {pos: (true_char, corrupt_char)}). The
    corruption is deterministic: each affected position receives 'A'
    unless that equals the true character, in which case 'B'.
    """
    if pos1 >= pos2:
        raise ValueError(f"pos1 must be less than pos2, got {pos1} >= {pos2}")
    new1 = _swap_to_non_canonical(true_ct[pos1])
    new2 = _swap_to_non_canonical(true_ct[pos2])
    corrupt = (
        true_ct[:pos1]
        + new1
        + true_ct[pos1 + 1 : pos2]
        + new2
        + true_ct[pos2 + 1 :]
    )
    return corrupt, {pos1: (true_ct[pos1], new1), pos2: (true_ct[pos2], new2)}


def _ambiguous_manifest_from_positions(
    positions: Iterable[int], rationale_per_position: dict[str, str],
) -> AmbiguousPositionsManifest:
    """Build an AmbiguousPositionsManifest in-memory for the recovery test.

    The recovery test does not load from disk; it constructs a manifest
    matching the operator-supplied schema directly. The schema's
    `archive_provenance` requirement is satisfied with a synthetic-test
    sentinel that disqualifies this manifest from real-K4 use.
    """
    sorted_positions = sorted(set(int(p) for p in positions))
    return AmbiguousPositionsManifest(
        schema_version="ct_perturbation_stage_b.ambiguous_positions.v1",
        archive_provenance={
            "primary_source": "SYNTHETIC_RECOVERY_TEST_NOT_FOR_REAL_K4",
            "image_hashes": [],
            "evaluator": "synthetic_recovery_test",
            "evaluation_date": time.strftime("%Y-%m-%d"),
            "method": "in-memory test fixture, not archive evidence",
        },
        positions=tuple(sorted_positions),
        rationale_per_position=dict(rationale_per_position),
        checksum_sha256=hashlib.sha256(
            ",".join(str(p) for p in sorted_positions).encode("utf-8")
        ).hexdigest(),
    )


def _selective_probe_for_fixture(
    fixture: dict[str, Any],
    pos_pair: tuple[int, int] = _SELECTIVE_PROBE_POSITIONS,
) -> dict[str, Any]:
    """Run the §7.1 selective recovery probe for one cipher fixture."""
    pos1, pos2 = sorted(pos_pair)
    family: CipherVariant = fixture["family"]
    alphabet = fixture["alphabet"]
    alphabet_kind: str = fixture["alphabet_kind"]
    keyword: str = fixture["keyword"]

    synthetic_pt = _build_synthetic_pt()
    key = alphabet.encode(keyword)
    true_ct = encrypt_text(synthetic_pt, key, variant=family, alphabet=alphabet)

    # The "carved" CT is true_ct corrupted at pos1, pos2.
    corrupt_ct, corruption_map = _build_h2_corrupt_ct(true_ct, pos1, pos2)

    # Ambiguous-position set planted to match the corruption.
    manifest = _ambiguous_manifest_from_positions(
        positions=[pos1, pos2],
        rationale_per_position={
            str(pos1): f"selective probe, pos1={pos1} (in EAST crib region)",
            str(pos2): f"selective probe, pos2={pos2} (in BERLIN crib region)",
        },
    )

    # Universe size for Bonferroni in the recovery test. With a 1-element
    # keyword pool and one (family, alphabet) combination, the universe
    # is exactly the H2 variant count over A.
    h2_variants = list(enumerate_hamming2_variants_constrained(corrupt_ct, manifest))
    universe_size = len(h2_variants) * 1 * 1 * 1

    policy = AlertPolicy(
        h1_require_full_cribs=True,
        h1_require_bean_pass=True,
        h1_require_ngram_floor=False,  # no ngram null in recovery test
        h1_p_adjusted_threshold=1.0,   # bypass null-cache requirement
        require_null_for_alert=False,
    )

    candidates_evaluated = 0
    matching_alert: dict[str, Any] | None = None
    alerts_total = 0

    for variant in h2_variants:
        ctx = ScorerContext.build(
            variant=variant,
            crib_dict=dict(CRIB_DICT),
            ngram_dist=None,
            alphabet_kind=alphabet_kind,
        )
        score, _pt = score_candidate_ct_parametric(
            ctx,
            keyword=keyword,
            family=family,
            alphabet_kind=alphabet_kind,
            universe_size=universe_size,
            policy=policy,
            ngram_scorer=None,
        )
        candidates_evaluated += 1
        if score.alert_class == "alert":
            alerts_total += 1
            # Match against the planted correction signature.
            matches_planted = (
                variant.pos1 == pos1
                and variant.pos2 == pos2
                and variant.new1 == true_ct[pos1]
                and variant.new2 == true_ct[pos2]
            )
            if matches_planted and matching_alert is None:
                matching_alert = {
                    "variant_id": variant.variant_id,
                    "pos1": variant.pos1,
                    "old1": variant.old1,
                    "new1": variant.new1,
                    "pos2": variant.pos2,
                    "old2": variant.old2,
                    "new2": variant.new2,
                    "crib_score": score.crib_score,
                    "crib_total": score.crib_total,
                    "bean_passed": score.bean_passed,
                }

    return {
        "fixture": fixture["label"],
        "pos1": pos1,
        "pos2": pos2,
        "expected_correction_pos1": (true_ct[pos1], corruption_map[pos1][1]),
        "expected_correction_pos2": (true_ct[pos2], corruption_map[pos2][1]),
        "h2_variants_enumerated": len(h2_variants),
        "candidates_evaluated": candidates_evaluated,
        "alerts_total": alerts_total,
        "matching_alert": matching_alert,
        "passed": matching_alert is not None,
        "true_ct_sha256": hashlib.sha256(true_ct.encode("utf-8")).hexdigest(),
        "corrupt_ct_sha256": hashlib.sha256(corrupt_ct.encode("utf-8")).hexdigest(),
    }


def _structural_probe_for_fixture(
    fixture: dict[str, Any],
    pos_pair: tuple[int, int] = _STRUCTURAL_PROBE_POSITIONS,
) -> dict[str, Any]:
    """Run the §7.2 structural recovery probe for one cipher fixture.

    The structural probe operates on the REAL K4 ciphertext (not a
    synthetic encryption) because the prereg's structural argument is
    about ensuring the Stage B sweep does not false-flag random
    non-crib perturbations of the real CT. With the synthetic
    encryption used by the selective probe, decrypting any H2 variant
    at non-crib positions trivially yields canonical cribs at canonical
    positions (Vigenère/Beaufort is position-local), which is a
    structural artifact of the synthetic fixture rather than a
    cryptographic property worth testing.

    Verifies:
      (a) no alert fires for the H2-constrained sweep over A* = {q1, q2}
          when the underlying CT is real K4 (random keyword decryption
          rarely produces full crib match);
      (b) Bean constraint set is unchanged when only non-crib positions
          are edited (a structural property of Bean we spot-check by
          comparing canonical-CT and corrupt-CT derivations).
    """
    pos1, pos2 = sorted(pos_pair)
    crib_positions = set(CRIB_DICT.keys())
    if pos1 in crib_positions or pos2 in crib_positions:
        raise ValueError(
            f"structural probe positions ({pos1}, {pos2}) must be non-crib"
        )

    family: CipherVariant = fixture["family"]
    alphabet = fixture["alphabet"]
    alphabet_kind: str = fixture["alphabet_kind"]
    keyword: str = fixture["keyword"]

    # Use REAL K4 CT for the structural probe.
    true_ct = CT
    corrupt_ct, _ = _build_h2_corrupt_ct(true_ct, pos1, pos2)

    manifest = _ambiguous_manifest_from_positions(
        positions=[pos1, pos2],
        rationale_per_position={
            str(pos1): f"structural probe, pos1={pos1} (non-crib)",
            str(pos2): f"structural probe, pos2={pos2} (non-crib)",
        },
    )

    h2_variants = list(enumerate_hamming2_variants_constrained(corrupt_ct, manifest))
    universe_size = max(1, len(h2_variants))

    policy = AlertPolicy(
        h1_require_full_cribs=True,
        h1_require_bean_pass=True,
        h1_require_ngram_floor=False,
        h1_p_adjusted_threshold=1.0,
        require_null_for_alert=False,
    )

    bean_pass_count = 0
    alert_count = 0
    candidates_evaluated = 0

    for variant in h2_variants:
        ctx = ScorerContext.build(
            variant=variant,
            crib_dict=dict(CRIB_DICT),
            ngram_dist=None,
            alphabet_kind=alphabet_kind,
        )
        score, _pt = score_candidate_ct_parametric(
            ctx,
            keyword=keyword,
            family=family,
            alphabet_kind=alphabet_kind,
            universe_size=universe_size,
            policy=policy,
            ngram_scorer=None,
        )
        candidates_evaluated += 1
        if score.bean_passed:
            bean_pass_count += 1
        if score.alert_class == "alert":
            alert_count += 1

    # Bean invariance spot-check: derive Bean constraints over canonical
    # CT and over the corrupt CT (both H2 outside cribs); compare. The
    # design memo's argument is that non-crib edits do not change Bean
    # state at the crib positions.
    canonical_eq, canonical_ineq, canonical_linear = derive_bean_constraints(
        CT, dict(CRIB_DICT), alphabet=alphabet,
    )
    corrupt_eq, corrupt_ineq, corrupt_linear = derive_bean_constraints(
        corrupt_ct, dict(CRIB_DICT), alphabet=alphabet,
    )
    bean_invariance_holds = (
        canonical_eq == corrupt_eq
        and canonical_ineq == corrupt_ineq
        and canonical_linear == corrupt_linear
    )

    return {
        "fixture": fixture["label"],
        "pos1": pos1,
        "pos2": pos2,
        "h2_variants_enumerated": len(h2_variants),
        "candidates_evaluated": candidates_evaluated,
        "bean_pass_count": bean_pass_count,
        "alerts_total": alert_count,
        "bean_invariance_holds": bean_invariance_holds,
        "passed": (alert_count == 0) and bean_invariance_holds,
        "true_ct_sha256": hashlib.sha256(true_ct.encode("utf-8")).hexdigest(),
        "corrupt_ct_sha256": hashlib.sha256(corrupt_ct.encode("utf-8")).hexdigest(),
    }


def synthetic_recovery_test(
    *,
    artifact_dir: Path | None = None,
) -> dict[str, Any]:
    """Run the prereg §7 synthetic-recovery test.

    Both probes run against both cipher fixtures (Vigenère + AZ +
    PALIMPSEST and Beaufort + KA + KRYPTOS). Writes
    ``recovery_test_report.json`` to ``artifact_dir`` (default
    ``results/ct_perturbation_stage_b/_synthetic_recovery/``).

    Returns a report dict. ``passed`` is True iff both probes pass for
    both fixtures.
    """
    if artifact_dir is None:
        artifact_dir = _RECOVERY_ARTIFACT_DEFAULT
    artifact_dir.mkdir(parents=True, exist_ok=True)

    selective_results = [
        _selective_probe_for_fixture(fixture)
        for fixture in _RECOVERY_FIXTURES
    ]
    structural_results = [
        _structural_probe_for_fixture(fixture)
        for fixture in _RECOVERY_FIXTURES
    ]

    selective_passed = all(r["passed"] for r in selective_results)
    structural_passed = all(r["passed"] for r in structural_results)
    overall_passed = selective_passed and structural_passed

    report = {
        "schema_version": "ct_perturbation_stage_b.recovery_test_report.v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "campaign_id": "ct_perturbation_stage_b",
        "prereg_section": "§7",
        "passed": overall_passed,
        "selective_passed": selective_passed,
        "structural_passed": structural_passed,
        "selective_probes": selective_results,
        "structural_probes": structural_results,
        "explanation": (
            "§7.1 selective: plant H2 corruption at two crib positions, "
            "verify the H2-constrained sweep over A* = {p1, p2} recovers "
            "the original encryption. §7.2 structural: plant H2 outside "
            "cribs, verify no false alert AND Bean state invariant."
        ),
    }

    out_path = artifact_dir / "recovery_test_report.json"
    out_path.write_text(json.dumps(report, indent=2))
    return report


# ─── Null-baseline cache freshness gate (prereg §5/§9) ───────────────────

_DEFAULT_NULL_BASELINES_MANIFEST = _ROOT / "null_baselines" / "manifest.json"


def _resolve_null_manifest_path() -> Path:
    """Path to the null-baseline cache summary manifest.

    Honors the ``KRYPTOS_NULL_BASELINES_MANIFEST`` env override so test
    runners can point the freshness gate at a fixture without mutating
    the live cache directory.
    """
    override = os.environ.get("KRYPTOS_NULL_BASELINES_MANIFEST")
    if override:
        return Path(override)
    return _DEFAULT_NULL_BASELINES_MANIFEST


def _current_kernel_commit() -> str:
    """Return the current kernel git HEAD, mirroring the helper used by
    the null-baseline writer (kryptosbot.null_baselines).

    Honors ``KRYPTOSBOT_KERNEL_COMMIT`` env override (same convention as
    the writer), so the freshness check resolves the SAME sha both sides
    of the comparison would see in the same process environment.
    """
    try:
        from kryptosbot.null_baselines import _compute_kernel_commit
        return _compute_kernel_commit()
    except Exception:
        # Fallback: best-effort local computation. Treated as 'unknown'
        # if git is unavailable, which the staleness check downgrades to
        # 'cannot determine drift' (permissive — mirrors writer behavior).
        return "unknown"


def _check_null_cache_freshness(
    *,
    allow_stale: bool,
    allow_missing: bool,
) -> tuple[bool, str]:
    """Decide whether the null-baseline cache is fresh enough to launch.

    Returns ``(ok, reason)``. ``reason`` is a one-line diagnostic safe to
    print at launch refusal. When ``ok`` is True, ``reason`` may still be
    a non-empty advisory (e.g. operator used an override flag).

    Prereg §5/§9: the cache MUST agree with the current kernel commit
    before launch. Drift means the cache describes a different scoring
    semantic than what the runner will compute, so any p-value gating on
    it is uncalibrated. Whole-cache absence is a separate failure mode:
    no calibration at all means the gate is structurally unreachable.
    Each refusal has an explicit operator override so a deliberate
    calibration rebuild can proceed.
    """
    manifest_path = _resolve_null_manifest_path()
    current = _current_kernel_commit()

    if not manifest_path.exists():
        msg = (
            f"null_cache_missing: null-baseline manifest not found at "
            f"{manifest_path}. The Stage B p-value gate requires a "
            f"calibrated null cache. Rebuild with "
            f"`PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py` "
            f"or pass --allow-null-unavailable to launch without it."
        )
        if allow_missing:
            return (True, f"OVERRIDE: {msg}")
        return (False, msg)

    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        msg = (
            f"null_cache_missing: failed to read null-baseline manifest "
            f"at {manifest_path}: {e!s}"
        )
        if allow_missing:
            return (True, f"OVERRIDE: {msg}")
        return (False, msg)

    cache_commit = str(manifest.get("kernel_commit_at_latest_write", "unknown"))

    # Permissive case: either side reports 'unknown' (git unavailable).
    # Mirror kryptosbot.null_baselines.calibration_stale: don't treat
    # 'unknown' as drift because it is not the operator's fault.
    if cache_commit == "unknown" or current == "unknown":
        return (
            True,
            f"null_cache_unknown_commit: cache_commit={cache_commit!r} "
            f"current={current!r}; cannot determine drift, proceeding.",
        )

    if cache_commit != current:
        msg = (
            f"stale_null_cache: null-baseline manifest at {manifest_path} "
            f"was built against kernel_commit={cache_commit!r} but the "
            f"current kernel commit is {current!r}. The p-value gate "
            f"would be uncalibrated. Rebuild with "
            f"`PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py` "
            f"or pass --allow-stale-null-cache to launch with the drift."
        )
        if allow_stale:
            return (True, f"OVERRIDE: {msg}")
        return (False, msg)

    return (
        True,
        f"null_cache_fresh: cache_commit={cache_commit} matches current.",
    )


# ─── stub CLI ────────────────────────────────────────────────────────────


def _build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=(
            "CT-Perturbation Stage B. Manifest validation, synthetic-"
            "recovery test, and full H2 sweep runner. See "
            f"{_PREREG_PATH}."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--ambiguous-positions",
        type=Path,
        required=False,
        help=(
            "Path to operator-predeclared ambiguous-position JSON. "
            "Required for manifest validation; not required for "
            "--synthetic-recovery-test (which constructs its own A "
            "in-memory). Schema: ct_perturbation_stage_b.ambiguous_positions.v1. "
            "See prereg §3.2."
        ),
    )
    ap.add_argument(
        "--allow-large-ambiguous-set",
        action="store_true",
        help=f"Permit |A| > {_K_MAX_DEFAULT} (default refuses).",
    )
    ap.add_argument(
        "--keyword-count",
        type=int,
        default=719,
        help="Keyword pool size for universe-size estimation (default 719).",
    )
    ap.add_argument(
        "--synthetic-recovery-test",
        action="store_true",
        help=(
            "Run the prereg §7 synthetic-recovery test (selective + "
            "structural probes against both cipher fixtures). Writes "
            "recovery_test_report.json to --recovery-artifact-dir."
        ),
    )
    ap.add_argument(
        "--recovery-artifact-dir",
        type=Path,
        default=None,
        help=(
            "Output directory for the recovery test report (default: "
            "results/ct_perturbation_stage_b/_synthetic_recovery/)."
        ),
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate manifest and print summary; do not attempt execution.",
    )
    ap.add_argument(
        "--execute-full",
        action="store_true",
        help=(
            "Run the full Stage B H2 sweep over the manifest. Requires "
            "--ambiguous-positions."
        ),
    )
    ap.add_argument(
        "--keyword-limit",
        type=int,
        default=None,
        help="Cap effective keyword count after loading (smoke).",
    )
    ap.add_argument(
        "--max-h2-variants",
        type=int,
        default=None,
        help="Cap H2 variant enumeration (smoke). Default: full universe.",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Multiprocessing pool size for H2 variant evaluation.",
    )
    ap.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Run identifier (default: UTC timestamp).",
    )
    ap.add_argument(
        "--artifact-root",
        type=Path,
        default=Path("results/ct_perturbation_stage_b"),
        help="Root directory for per-run artifact directories.",
    )
    ap.add_argument(
        "--keywords",
        type=Path,
        default=None,
        help="Path to keyword list (one per line, uppercase A-Z).",
    )
    ap.add_argument(
        "--per-task-timeout-sec",
        type=float,
        default=60.0,
        help=(
            "Per-H2-variant timeout (seconds) in MP mode. Default 60.0 per "
            "feedback_pool_worker_no_per_task_timeout.md."
        ),
    )
    ap.add_argument(
        "--allow-stale-null-cache",
        action="store_true",
        help=(
            "Override the prereg §5/§9 freshness gate: launch even when "
            "the null-baseline cache's kernel_commit differs from the "
            "current kernel. Use only when a calibration rebuild is "
            "intentionally deferred; the p-value gate will be uncalibrated."
        ),
    )
    ap.add_argument(
        "--allow-null-unavailable",
        action="store_true",
        help=(
            "Launch even when the null-baseline cache manifest is "
            "entirely absent. Use only when running explicitly without "
            "p-value gating; the alert path will fall back to legacy "
            "crib-only classification."
        ),
    )
    return ap


def _print_summary(manifest: AmbiguousPositionsManifest, n_keywords: int) -> None:
    universe = stage_b_universe_size(manifest, n_keywords=n_keywords)
    k = len(manifest.positions)
    print()
    print("=" * 72)
    print("  CT-Perturbation Stage B — manifest validated")
    print("=" * 72)
    print(f"  schema_version:      {manifest.schema_version}")
    print(
        f"  primary_source:      "
        f"{manifest.archive_provenance.get('primary_source', '(unset)')}"
    )
    print(
        f"  evaluator:           "
        f"{manifest.archive_provenance.get('evaluator', '(unset)')}"
    )
    print(
        f"  evaluation_date:     "
        f"{manifest.archive_provenance.get('evaluation_date', '(unset)')}"
    )
    print(f"  k = |A|:             {k}")
    print(f"  positions:           {sorted(manifest.positions)}")
    print()
    print("  Universe sizing (per prereg §3.3):")
    for key, value in universe.items():
        if isinstance(value, int):
            print(f"    {key:30s} {value:>15,}")
        else:
            print(f"    {key:30s} {value}")
    print()
    print("=" * 72)
    print(f"  See {_PREREG_PATH} for full campaign spec.")
    print("=" * 72)
    print()


def _print_recovery_report(report: dict[str, Any]) -> None:
    print()
    print("=" * 72)
    print("  Synthetic recovery test (prereg §7)")
    print("=" * 72)
    print(f"  overall passed:         {report['passed']}")
    print(f"  selective probes pass:  {report['selective_passed']}")
    print(f"  structural probes pass: {report['structural_passed']}")
    print()
    print("  Selective (§7.1):")
    for probe in report["selective_probes"]:
        ok = "PASS" if probe["passed"] else "FAIL"
        print(
            f"    [{ok}] {probe['fixture']:32s} "
            f"variants={probe['h2_variants_enumerated']:5d}  "
            f"alerts={probe['alerts_total']}  "
            f"matched_planted={probe['matching_alert'] is not None}"
        )
    print()
    print("  Structural (§7.2):")
    for probe in report["structural_probes"]:
        ok = "PASS" if probe["passed"] else "FAIL"
        print(
            f"    [{ok}] {probe['fixture']:32s} "
            f"variants={probe['h2_variants_enumerated']:5d}  "
            f"alerts={probe['alerts_total']}  "
            f"bean_invariant={probe['bean_invariance_holds']}"
        )
    print()


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)

    # If --synthetic-recovery-test is requested, run it FIRST. The recovery
    # test does not require an operator-supplied --ambiguous-positions
    # because it constructs its own ambiguous-position set in-memory.
    if args.synthetic_recovery_test:
        report = synthetic_recovery_test(
            artifact_dir=args.recovery_artifact_dir,
        )
        _print_recovery_report(report)
        if not report["passed"]:
            print(
                "\nERROR: synthetic-recovery test failed. The Stage B "
                "harness must pass §7 before --execute-full is "
                "authorized.",
                file=sys.stderr,
            )
            return 4
        # If only --synthetic-recovery-test was requested (no manifest
        # validation), exit successfully here.
        if args.ambiguous_positions is None:
            return 0

    # Manifest validation path (requires --ambiguous-positions).
    if args.ambiguous_positions is None:
        if not args.synthetic_recovery_test:
            print(
                "ERROR: --ambiguous-positions is required unless "
                "running --synthetic-recovery-test alone.",
                file=sys.stderr,
            )
            print(f"\nSee {_PREREG_PATH} §3 for the schema.", file=sys.stderr)
            return 2
        return 0  # recovery-test-only path already handled

    if not args.ambiguous_positions.exists():
        print(
            f"ERROR: --ambiguous-positions path does not exist: "
            f"{args.ambiguous_positions}",
            file=sys.stderr,
        )
        print(
            f"\nStage B requires an operator-predeclared ambiguous-position "
            f"set per prereg §3.\nSee {_PREREG_PATH} for the schema.",
            file=sys.stderr,
        )
        return 2

    try:
        manifest = load_ambiguous_positions(
            args.ambiguous_positions,
            allow_large=args.allow_large_ambiguous_set,
        )
    except (ValueError, json.JSONDecodeError) as e:
        print(
            f"ERROR: --ambiguous-positions failed schema validation: {e}",
            file=sys.stderr,
        )
        print(
            f"\nSee {_PREREG_PATH} §3.2 for the v1 schema and §3.1 for the "
            f"operator-decision contract.",
            file=sys.stderr,
        )
        return 2

    k = len(manifest.positions)
    if k > _K_MAX_DEFAULT and not args.allow_large_ambiguous_set:
        print(
            f"ERROR: |A| = {k} exceeds k_max_default = {_K_MAX_DEFAULT}; "
            f"pass --allow-large-ambiguous-set to override.",
            file=sys.stderr,
        )
        print(
            f"\nLarger archive evidence sets monotonically increase the "
            f"search universe; see prereg §3.3 cardinality table.",
            file=sys.stderr,
        )
        return 2

    _print_summary(manifest, n_keywords=args.keyword_count)

    if args.execute_full:
        if manifest is None:
            logger.error(
                "--execute-full requires --ambiguous-positions <manifest>"
            )
            return 2

        # Prereg §5/§9: refuse to launch if the null-baseline cache is
        # stale relative to the current kernel commit, or is entirely
        # absent. Each refusal has an explicit operator override.
        ok, reason = _check_null_cache_freshness(
            allow_stale=args.allow_stale_null_cache,
            allow_missing=args.allow_null_unavailable,
        )
        if not ok:
            print(f"ERROR: {reason}", file=sys.stderr)
            print(
                f"\nSee {_PREREG_PATH} §5 and §9 for the freshness contract.",
                file=sys.stderr,
            )
            return 2
        logger.info("null_cache_freshness_check: %s", reason)

        keywords_src = load_keywords(
            args.keywords if args.keywords is not None
            else Path("data/keywords_curated_v1.txt"),
            cap=args.keyword_count,
        )
        run_id = args.run_id or _dt.datetime.now(_dt.timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ_full"
        )
        artifact_dir = args.artifact_root / run_id
        universe = stage_b_universe_size(
            manifest, n_keywords=len(keywords_src.normalized)
        )
        effective_keywords = (
            args.keyword_limit if args.keyword_limit is not None
            else len(keywords_src.normalized)
        )
        effective_variants = (
            args.max_h2_variants if args.max_h2_variants is not None
            else universe["h2_variants"]
        )
        expected_total = (
            effective_variants
            * len(SUPPORTED_FAMILIES)
            * len(SUPPORTED_ALPHABET_KINDS)
            * effective_keywords
        )
        cfg = SweepConfig(
            ct=CT, keywords=list(keywords_src.normalized), manifest=manifest,
            universe_size=universe["total_configs"],
            max_h2_variants=args.max_h2_variants,
            keyword_limit=args.keyword_limit,
        )
        run_metadata = {
            "canonical_ct_sha256": _ct_sha256(CT),
            "ambiguous_positions_sha256": manifest.checksum_sha256,
            "k": manifest.k,
            "h2_variants_executed": effective_variants,
            "expected_total_config_cardinality": expected_total,
            "keyword_count": effective_keywords,
            "keyword_hash": keywords_src.normalized_sha256,
        }
        run_h2_sweep(
            cfg, artifact_dir=artifact_dir, run_id=run_id,
            workers=args.workers, run_metadata=run_metadata,
            per_task_timeout_sec=args.per_task_timeout_sec,
        )
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
