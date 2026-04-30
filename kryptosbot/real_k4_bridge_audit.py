"""Real-K4 LLM↔HCC bridge audit runner.

Orchestration:
  1. Load pseudo-clue packs (LLM-generated or fixture-loaded).
  2. Compile each pack into ``GeneratedSpec`` lists via the
     deterministic compiler.
  3. Dispatch the merged spec list through the kernel using the
     same audit-overridden DSL path as ``real_k4_audit``.
  4. Score every dispatched candidate against the public K4 cribs.
  5. Compute a null baseline from ``real_k4_audit.compute_null_baseline``.
  6. Emit an audit artifact with full provenance, per-pack
     summaries, top candidates, null-baseline classification, and
     explicit non-claim language.

This module does NOT call the LLM directly — that boundary lives
in ``run_controller.py`` (which already owns the Agent SDK
integration). The bridge supports two pack-load paths:

  * ``--bridge-packs-dir <DIR>``: load every ``*.json`` file as a
    pre-built fixture pack. Used for LLM-disabled pipeline tests
    and reproducible runs.
  * ``--bridge-packs-llm`` (future hook): when invoked from
    run_controller, the controller calls the LLM with the bridge
    prompt, parses the response via ``real_k4_bridge_prompt``, and
    passes the resulting ``PseudoCluePack`` list into this module.

This module reuses the audit infrastructure already built in
``real_k4_audit.py`` (dispatch, candidate construction, null
baseline) so the bridge produces an artifact in the same shape and
the same calibration semantics as the existing audit. Real-K4
normal mode (the default) is untouched: this module is invoked
ONLY when ``run_controller.py`` receives the explicit
``--real-k4-hcc-bridge-audit`` flag.

Hard contract:
  * No K4Bench challenge data is read.
  * No sealed-answer files are read.
  * Every candidate carries pack_id + evidence_tier provenance in
    its coverage extras.
  * Default ``classification`` for the run is
    ``"interpretive_pipeline_test"`` — promotion to ``"breakthrough"``
    requires the null baseline gate to fire (p ≤ 0.001).
  * The artifact carries an explicit non-claim banner.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from kryptosbot.hand_cipher_core import GeneratedSpec
from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
from kryptosbot.job_dispatcher import (
    execute as dispatcher_execute,
    JobResult,
)
from kryptosbot.problem_context import ProblemContext
from kryptosbot.real_k4_audit import (
    NullBaseline,
    DEFAULT_CLASSIFICATION_THRESHOLDS,
    compute_null_baseline,
    candidate_tier_signature,
    lessons_used_by_coverage,
    public_crib_match_map,
    _attach_audit_override,
    _candidate_from_result,
    RealK4AuditCandidate,
)
from kryptosbot.real_k4_pseudo_clue_pack import (
    PseudoCluePack,
    load_pack_directory,
    utc_run_id,
)
from kryptosbot.real_k4_pseudo_clue_compiler import (
    CompileError,
    compile_packs,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


_BRIDGE_OVERRIDE_JUSTIFICATION = (
    "real-K4 interpretive HCC bridge audit; explicit operator flag; "
    "every spec carries pack_id provenance; no sealed-answer access; "
    "no real-K4 progress claim unless null baseline gate fires."
)


@dataclass
class RealK4BridgeAuditConfig:
    """Bridge audit knobs.

    ``packs_dir`` (optional): directory of fixture pack JSON files
    for LLM-disabled mode. ``llm_packs`` (optional): pre-parsed
    PseudoCluePack list when the caller has already obtained the
    LLM response and parsed it. Exactly one of the two must be set.
    """
    output_path: Path
    packs_dir: Optional[Path] = None
    llm_packs: Optional[Sequence[PseudoCluePack]] = None
    global_max_specs: int = 2000
    workers: int = max(1, (os.cpu_count() or 4) - 2)
    timeout_per_spec_sec: int = 30
    classification_thresholds: Optional[Mapping[str, float]] = None
    skip_null_calibration: bool = False
    skip_null_calibration_reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.output_path, Path):
            self.output_path = Path(self.output_path)
        if self.packs_dir is not None and not isinstance(self.packs_dir, Path):
            self.packs_dir = Path(self.packs_dir)
        if self.global_max_specs <= 0:
            raise ValueError("global_max_specs must be positive")
        if self.global_max_specs > 20000:
            raise ValueError(
                f"global_max_specs {self.global_max_specs} exceeds bridge "
                "audit hard ceiling of 20000; tighten bounds or split run"
            )
        if self.workers <= 0:
            raise ValueError("workers must be positive")
        if self.timeout_per_spec_sec <= 0:
            raise ValueError("timeout_per_spec_sec must be positive")
        if self.packs_dir is None and self.llm_packs is None:
            raise ValueError(
                "RealK4BridgeAuditConfig requires either packs_dir or "
                "llm_packs"
            )
        if self.skip_null_calibration and not self.skip_null_calibration_reason:
            raise ValueError(
                "skip_null_calibration=True requires a non-empty "
                "skip_null_calibration_reason"
            )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _load_packs(config: RealK4BridgeAuditConfig) -> list[PseudoCluePack]:
    if config.llm_packs is not None:
        return list(config.llm_packs)
    if config.packs_dir is None:
        raise RuntimeError("unreachable: __post_init__ requires one source")
    packs = load_pack_directory(config.packs_dir)
    return packs


def _public_crib_dict() -> dict[int, str]:
    from kryptos.kernel.constants import CRIB_DICT
    return dict(CRIB_DICT)


def _public_ct() -> str:
    from kryptos.kernel.constants import CT
    return CT


def _dispatch_specs(
    specs: Sequence[GeneratedSpec],
    workers: int,
) -> list[tuple[GeneratedSpec, JobResult]]:
    """Mirror of real_k4_audit._dispatch_with_optional_workers but
    stamped with the bridge override justification."""
    out: list[tuple[GeneratedSpec, JobResult]] = []
    for i, spec in enumerate(specs, 1):
        if i % 50 == 0:
            logger.info(
                "real_k4_bridge_audit: dispatching spec %d/%d (%s)",
                i, len(specs), spec.coverage.layer_family,
            )
        try:
            parsed = validate_hypothesis_spec(spec.raw_spec)
            if not parsed.is_valid:
                out.append((spec, JobResult(
                    hypothesis_id=spec.hypothesis_id,
                    spec_hash="",
                    universe_hash="",
                    admissibility_verdict=(
                        f"validation_failed: {parsed.errors[:2]}"
                    ),
                )))
                continue
            audit_spec = parsed.value
            audit_spec.override_exhaustion = True
            audit_spec.override_justification = _BRIDGE_OVERRIDE_JUSTIFICATION
            result = dispatcher_execute(
                audit_spec, workers=workers, bench_mode=False,
            )
            out.append((spec, result))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "real_k4_bridge_audit: spec %s raised %s: %s",
                spec.hypothesis_id[:32], type(exc).__name__, exc,
            )
            out.append((spec, JobResult(
                hypothesis_id=spec.hypothesis_id,
                spec_hash="",
                universe_hash="",
                admissibility_verdict=(
                    f"dispatch_error: {type(exc).__name__}: {exc}"
                ),
            )))
    return out


def _summarize_candidate(
    cand: RealK4AuditCandidate,
) -> dict[str, Any]:
    cv = cand.coverage_vector or {}
    extras = cv.get("extras") or {}
    pack_id = _read_extra(extras, "pack_id", default="")
    evidence_tier = _read_extra(extras, "evidence_tier", default="")
    return {
        "hypothesis_id": cand.hypothesis_id,
        "layer_family": cand.layer_family,
        "layer_order": cv.get("layer_order"),
        "crib_score": cand.crib_score,
        "ngram_score": cand.ngram_score,
        "bean_passed": cand.bean_passed,
        "substitution_keyword": cv.get("substitution_keyword", ""),
        "transposition_keyword": cv.get("transposition_keyword", ""),
        "rail_fence_depth": _read_extra(extras, "rail_fence_depth"),
        "shift_value": cv.get("shift_value"),
        "role_assignment_mode": cv.get("role_assignment_mode", ""),
        "operation_source": cv.get("operation_source", ""),
        "pack_id": pack_id,
        "evidence_tier": evidence_tier,
        "lessons_used": cand.lessons_used,
        "plaintext_prefix": cand.plaintext[:32] if cand.plaintext else "",
    }


def _read_extra(
    extras: Any, key: str, *, default: Any = None,
) -> Any:
    """Read a single extras key. Tolerant of both shapes:
      * dict (CoverageVector.to_dict() form)
      * list/tuple of (k, v) pairs (raw CoverageVector.extras tuple)
    """
    if isinstance(extras, dict):
        return extras.get(key, default)
    if isinstance(extras, (list, tuple)):
        for kv in extras:
            if isinstance(kv, (list, tuple)) and len(kv) == 2 and kv[0] == key:
                return kv[1]
    return default


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_real_k4_bridge_audit(
    config: RealK4BridgeAuditConfig,
) -> dict[str, Any]:
    """Run the bridge audit and write the artifact. Returns the
    artifact dict (also available on disk at ``config.output_path``)."""
    t_start = time.monotonic()
    run_id = utc_run_id()

    # 1. Real-K4 ProblemContext sanity check.
    ctx = ProblemContext.real_k4()
    if not ctx.is_real_k4:
        raise RuntimeError(
            "real_k4_bridge_audit invoked with non-real-K4 "
            "ProblemContext; this should be impossible."
        )

    crib_dict = _public_crib_dict()
    ct = _public_ct()

    # 2. Load packs.
    packs = _load_packs(config)
    logger.info(
        "real_k4_bridge_audit: loaded %d packs from %s",
        len(packs),
        "llm" if config.llm_packs is not None else str(config.packs_dir),
    )

    # 3. Compile.
    specs, pack_summaries = compile_packs(
        packs, global_max_specs=config.global_max_specs,
    )
    n_specs = len(specs)
    logger.info(
        "real_k4_bridge_audit: compiled %d specs across %d packs",
        n_specs, len(packs),
    )

    # 4. Dispatch.
    dispatch_results: list[tuple[GeneratedSpec, JobResult]] = []
    if specs:
        dispatch_results = _dispatch_specs(specs, workers=config.workers)

    # 5. Build candidate list.
    candidates: list[RealK4AuditCandidate] = []
    n_admissibility_rejected = 0
    n_dispatch_error = 0
    n_no_candidate = 0
    for spec, result in dispatch_results:
        verdict = result.admissibility_verdict or "ok"
        if verdict != "ok":
            if verdict.startswith("dispatch_error"):
                n_dispatch_error += 1
            else:
                n_admissibility_rejected += 1
            continue
        cand = _candidate_from_result(spec, result, crib_dict)
        if cand is None:
            n_no_candidate += 1
            continue
        candidates.append(cand)

    candidates.sort(
        key=lambda c: (c.crib_score, c.ngram_score), reverse=True,
    )
    max_crib = candidates[0].crib_score if candidates else 0

    # 6. Null baseline.
    null_payload: Optional[dict[str, Any]] = None
    if config.skip_null_calibration:
        null_payload = {
            "skipped": True,
            "reason": config.skip_null_calibration_reason,
        }
    elif candidates:
        try:
            null_baseline: NullBaseline = compute_null_baseline(
                n_candidates=len(candidates),
                observed_max_crib=max_crib,
                classification_thresholds=(
                    config.classification_thresholds
                    or DEFAULT_CLASSIFICATION_THRESHOLDS
                ),
            )
            null_payload = null_baseline.to_dict()
        except Exception as exc:  # noqa: BLE001
            null_payload = {
                "skipped": True,
                "reason": f"null_baseline_failed: {type(exc).__name__}: {exc}",
            }
    else:
        null_payload = {
            "skipped": True,
            "reason": "no candidates produced a 97-char plaintext",
        }

    # 7. Score histogram + per-pack rollup.
    histogram: dict[int, int] = {}
    per_pack_max: dict[str, int] = {}
    per_pack_count: dict[str, int] = {}
    for c in candidates:
        histogram[c.crib_score] = histogram.get(c.crib_score, 0) + 1
        cv = c.coverage_vector or {}
        pid = str(_read_extra(cv.get("extras") or {}, "pack_id", default=""))
        per_pack_count[pid] = per_pack_count.get(pid, 0) + 1
        if c.crib_score > per_pack_max.get(pid, -1):
            per_pack_max[pid] = c.crib_score

    # 8. Top-N artifact slice.
    top_n = 20
    top_candidates = [
        _summarize_candidate(c) for c in candidates[:top_n]
    ]

    # 9. Run-level classification (NEVER calls a real-K4 solve).
    classification = "interpretive_pipeline_test"
    if isinstance(null_payload, dict) and not null_payload.get("skipped"):
        if null_payload.get("classification") == "breakthrough":
            classification = "candidate_pending_external_evaluator"
        elif null_payload.get("classification") == "interesting":
            classification = "interesting_pending_review"

    artifact: dict[str, Any] = {
        "schema_version": "real_k4_bridge_audit.v1",
        "run_id": run_id,
        "wall_time_sec": round(time.monotonic() - t_start, 3),
        "ct_length": len(ct),
        "n_crib_positions": len(crib_dict),
        "n_packs_loaded": len(packs),
        "n_specs_compiled": n_specs,
        "n_specs_dispatched": len(dispatch_results),
        "n_admissibility_rejected": n_admissibility_rejected,
        "n_dispatch_error": n_dispatch_error,
        "n_no_candidate_plaintext": n_no_candidate,
        "n_candidates_scored": len(candidates),
        "max_crib_score": max_crib,
        "score_histogram": {
            str(k): histogram[k] for k in sorted(histogram)
        },
        "pack_summaries": pack_summaries,
        "per_pack_max_crib": per_pack_max,
        "per_pack_candidate_count": per_pack_count,
        "top_candidates": top_candidates,
        "null_baseline": null_payload,
        "classification": classification,
        "non_claim_banner": (
            "This artifact reports an interpretive pipeline test of "
            "LLM-generated structured pseudo-clue packs against real "
            "Kryptos K4. NO real-K4 solve is claimed. Promotion to "
            "candidate-pending requires the null baseline gate "
            "(p <= 0.001). Sealed K4Bench answers were NOT accessed "
            "and CAN NOT influence this artifact."
        ),
        "config": {
            "global_max_specs": config.global_max_specs,
            "workers": config.workers,
            "timeout_per_spec_sec": config.timeout_per_spec_sec,
            "skip_null_calibration": config.skip_null_calibration,
            "skip_null_calibration_reason": config.skip_null_calibration_reason,
            "packs_source": (
                "llm" if config.llm_packs is not None
                else f"dir:{config.packs_dir}"
            ),
        },
    }

    config.output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config.output_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
    logger.info(
        "real_k4_bridge_audit: artifact written to %s "
        "(specs=%d candidates=%d max_crib=%d cls=%s)",
        config.output_path, n_specs, len(candidates), max_crib,
        classification,
    )
    return artifact


__all__ = [
    "RealK4BridgeAuditConfig",
    "run_real_k4_bridge_audit",
]
