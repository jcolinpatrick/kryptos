"""Real-K4 HCC capability audit (v2: tier filtering + null baseline).

Purpose
-------
A dedicated audit mode that exercises the HandCipherCore (HCC)
deterministic coverage catalogue against the REAL Kryptos K4 cipher,
using only PUBLIC, PROJECT-SAFE clue material — no K4Bench challenge
data, no synthetic clue packs, no benchmark plaintexts.

The audit does NOT call the LLM. It dispatches every HCC seed through
the normal kernel DSL pipeline, scores each candidate against the
public K4 cribs, classifies which lessons each candidate exercised
(LESSON-001..LESSON-015 + LESSON-015-identity), and emits a
structured artifact.

v2 additions (2026-04-28)
-------------------------
1. **Tier filtering.** The clue registry is provenance-tiered; the
   audit accepts a tier selector (preset name or comma-separated tier
   list) and restricts the keyword pool accordingly.
2. **Per-candidate tier signature.** Each candidate records which
   registry tiers its keywords come from (substitution_keyword,
   alphabet_keyword, transposition_keyword cross-referenced against
   the registry). Coverage rollups break down by tier and by
   provenance.
3. **Null-baseline calibration.** The artifact carries an analytical
   null distribution for max_crib_score under random A-Z plaintext
   (Binomial(24, 1/26) per candidate, max over n_candidates
   independent draws). Reports expected_max_crib, p-value for the
   observed maximum, and a classification (null_level / interesting /
   breakthrough) so an auditor can tell whether the observed max is
   explainable by chance.

Strict isolation contract
-------------------------
This module imports nothing from:

  * ``kryptosbot.bench_loader``
  * ``kryptosbot.bench_fallback``
  * ``kryptosbot.bench_attempts``
  * ``bench/k4bench/`` data files

Clue material comes exclusively from
``kryptosbot.real_k4_clue_registry``. A firewall test in
``tests/test_real_k4_hcc_audit.py`` greps the emitted artifact for
K4Bench challenge IDs and bench-only tokens (excluding tokens
authorized by the v2 registry).

Normal real-K4 mode is unchanged — this module is invoked ONLY when
``run_controller.py`` receives the explicit ``--real-k4-hcc-audit``
flag. ``ResearchController._collect_hcc_seeds()`` continues to return
``[]`` in real-K4 mode (the audit bypasses the controller path
entirely; it dispatches through ``job_dispatcher.execute`` directly).
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from math import comb
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from .hand_cipher_core import (
    GeneratedSpec,
    generate_layered_specs,
)
from .hypothesis_dsl import HypothesisSpec, validate_hypothesis_spec
from .job_dispatcher import (
    JobResult,
    execute as dispatcher_execute,
)
from .problem_context import ProblemContext
from .real_k4_clue_registry import (
    CLUE_TIERS_IN_ORDER,
    TIER_PRESETS,
    ClueWordEntry,
    real_k4_audit_clue_text,
    real_k4_clue_keywords,
    real_k4_clue_words_with_provenance,
    resolve_tier_selector,
    tier_for_token,
    provenance_for_token,
)


logger = logging.getLogger("kryptosbot.real_k4_audit")


_AUDIT_SCHEMA_VERSION: str = "real_k4_hcc_audit.v2"
_DEFAULT_TOP_N: int = 200

_AUDIT_OVERRIDE_JUSTIFICATION: str = (
    "real-K4 HCC capability audit (--real-k4-hcc-audit): every "
    "deterministic HCC seed is dispatched for capability inspection "
    "regardless of prior real-K4 exhaustion-log overlap. The audit "
    "does NOT claim novelty for any individual spec; it dispatches "
    "the full catalogue so the operator can see what the post-"
    "LESSON-001..-015 HCC catalogue actually exercises against the "
    "public K4 ciphertext + cribs. Audit dispatches are tagged in "
    "the artifact and ledger so they are never confused with fresh-"
    "attack attempts."
)


# ===========================================================================
# Lesson detection
# ===========================================================================


_LESSON_IDS: tuple[str, ...] = (
    "LESSON-001", "LESSON-002", "LESSON-003", "LESSON-004",
    "LESSON-005", "LESSON-006", "LESSON-007", "LESSON-008",
    "LESSON-009", "LESSON-010", "LESSON-011", "LESSON-012",
    "LESSON-013", "LESSON-014", "LESSON-015",
    "LESSON-015-identity",
)


def lessons_used_by_coverage(cv: Mapping[str, Any]) -> list[str]:
    """Map a coverage_vector dict to the LESSON-NNN IDs it exercises.

    Detection is purely structural — reads coverage_vector fields
    populated by the HCC family generators.
    """
    if not isinstance(cv, Mapping):
        return []
    used: set[str] = set()

    n_layers = int(cv.get("n_layers") or 0)
    if n_layers >= 2:
        used.add("LESSON-001")
        used.add("LESSON-002")

    if (cv.get("layer_family") or "").startswith("quagmire"):
        role = cv.get("role_assignment") or {}
        if isinstance(role, Mapping):
            keys = set(role.keys())
            if {
                "pt_alphabet_keyword", "ct_alphabet_keyword",
            }.issubset(keys):
                used.add("LESSON-003")

    co_source = (cv.get("col_order_source") or "").strip()
    if co_source == "keyword_stable_rank":
        used.add("LESSON-004")
        used.add("LESSON-005")

    alphabet_mode = (
        cv.get("alphabet_mode") or cv.get("alphabet") or "AZ"
    ).strip()
    if alphabet_mode and alphabet_mode != "AZ":
        used.add("LESSON-007")

    if cv.get("block_size") is not None:
        used.add("LESSON-008")

    if cv.get("shift_value") is not None:
        used.add("LESSON-009")

    role_mode = (cv.get("role_assignment_mode") or "").strip()
    if role_mode == "independent_three_role":
        used.add("LESSON-010")

    if (cv.get("route_mode") or "") == "skip_route":
        used.add("LESSON-011")

    op_source = (cv.get("operation_source") or "").strip()
    if op_source.startswith("phrase_bound") or op_source == "phrase_bound":
        used.add("LESSON-012")
    rw_source = (cv.get("row_reverse_source") or "").strip()
    if rw_source == "phrase_bound_row_reverse_width":
        used.add("LESSON-012")
    rt_source = (cv.get("route_width_source") or "").strip()
    if rt_source == "phrase_bound_route_width":
        used.add("LESSON-012")
    width_source = (cv.get("width_source") or "").strip()
    if width_source.startswith("phrase_bound"):
        used.add("LESSON-012")

    if co_source == "enumerated_permutation":
        used.add("LESSON-013")

    if (cv.get("route_mode") or "") == "route_boustrophedon":
        used.add("LESSON-014")

    if cv.get("row_reverse_width") is not None:
        if cv.get("row_reverse_identity") is True:
            used.add("LESSON-015-identity")
        else:
            used.add("LESSON-015")

    return sorted(used)


# ===========================================================================
# Public-crib match map
# ===========================================================================


def public_crib_match_map(
    plaintext: str,
    crib_dict: Mapping[int, str],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for pos in sorted(crib_dict.keys()):
        expected = crib_dict[pos]
        got = plaintext[pos] if 0 <= pos < len(plaintext) else ""
        out.append({
            "position": int(pos),
            "expected": expected,
            "got": got,
            "match": got == expected,
        })
    return out


# ===========================================================================
# Tier signature for a candidate
# ===========================================================================


def candidate_tier_signature(cv: Mapping[str, Any]) -> dict[str, Any]:
    """Cross-reference the candidate's keywords against the v2
    registry and return the set of tiers it touches plus per-role
    tier+provenance.

    Returns a dict::

        {
          "tiers": ["core_public_cribs", "kryptos_plaintext_legacy"],
          "substitution_keyword_tier": "core_public_cribs",
          "substitution_keyword_provenance": "public_crib_split",
          "alphabet_keyword_tier": "kryptos_plaintext_legacy",
          ...
        }

    Empty / unrecognized keyword fields produce ``None`` per role.
    """
    if not isinstance(cv, Mapping):
        return {"tiers": [], "lookups": {}}
    lookups: dict[str, dict[str, Optional[str]]] = {}
    tiers: set[str] = set()
    for role_field in (
        "substitution_keyword",
        "alphabet_keyword",
        "transposition_keyword",
    ):
        raw = cv.get(role_field) or ""
        if not raw:
            lookups[role_field] = {"keyword": "", "tier": None, "provenance": None}
            continue
        tier = tier_for_token(raw)
        prov = provenance_for_token(raw)
        lookups[role_field] = {
            "keyword": raw,
            "tier": tier,
            "provenance": prov,
        }
        if tier:
            tiers.add(tier)
    return {
        "tiers": sorted(tiers),
        "lookups": lookups,
    }


# ===========================================================================
# Null-baseline calibration
# ===========================================================================


@dataclass(frozen=True)
class NullBaseline:
    """Analytical null distribution for max_crib_score over a fixed
    number of independent random A-Z plaintext draws.

    Model:
      X_i ~ Binomial(n_crib_positions, 1/alphabet_size) i.i.d.
      M_n = max(X_1, ..., X_n)
    where n = ``n_candidates``.

    Caveat: candidates are NOT independent — they're decryptions of
    the SAME ciphertext under different cipher parameters. The
    independent-Binomial assumption gives an UPPER BOUND on the
    null-tail probability; if observed max is consistent with this
    null, the audit is definitively null-level. If observed max
    exceeds this null's tail, the result merits further inspection
    (the correlation structure could in principle produce a higher
    max, but only if the parameter space carries genuine signal).
    """
    n_candidates: int
    n_crib_positions: int
    alphabet_size: int
    expected_max_crib: float
    observed_max_crib: int
    p_value_for_observed_max: float
    classification: str
    p_max_geq: dict[int, float]
    thresholds: dict[str, float]

    def to_dict(self) -> dict:
        return {
            "n_candidates": self.n_candidates,
            "n_crib_positions": self.n_crib_positions,
            "alphabet_size": self.alphabet_size,
            "expected_max_crib": self.expected_max_crib,
            "observed_max_crib": self.observed_max_crib,
            "p_value_for_observed_max": self.p_value_for_observed_max,
            "classification": self.classification,
            "p_max_geq": {str(k): v for k, v in self.p_max_geq.items()},
            "thresholds": dict(self.thresholds),
            "model": (
                "Independent Binomial(n_crib_positions, 1/alphabet_size) "
                "per candidate; max over n_candidates draws. "
                "Caveat: real candidates are correlated decrypts of one "
                "ciphertext, so this is an upper bound on the null tail."
            ),
        }


# Classification thresholds. Operators MAY override via the
# ``classification_thresholds`` argument to ``compute_null_baseline``;
# the defaults below are conservative for one-audit reporting.
DEFAULT_CLASSIFICATION_THRESHOLDS: dict[str, float] = {
    # observed p > null_level_p_min → "null_level" (consistent with chance)
    "null_level_p_min": 0.05,
    # 0.001 < p <= 0.05 → "interesting"
    "interesting_p_max": 0.05,
    # p <= breakthrough_p_max → "breakthrough"
    "breakthrough_p_max": 0.001,
}


def _classify_pvalue(
    p: float, thresholds: Mapping[str, float],
) -> str:
    """Map a p-value to a label using thresholds."""
    if p <= thresholds["breakthrough_p_max"]:
        return "breakthrough"
    if p <= thresholds["interesting_p_max"]:
        return "interesting"
    return "null_level"


def compute_null_baseline(
    n_candidates: int,
    observed_max_crib: int,
    *,
    n_crib_positions: int = 24,
    alphabet_size: int = 26,
    classification_thresholds: Optional[Mapping[str, float]] = None,
) -> NullBaseline:
    """Compute the analytical null distribution for max_crib_score.

    Args:
      n_candidates: number of candidate plaintexts (independent draws
        under the null).
      observed_max_crib: the empirically observed max crib_score.
      n_crib_positions: total crib positions (24 for K4).
      alphabet_size: alphabet cardinality (26 for A-Z).
      classification_thresholds: override the default null/
        interesting/breakthrough p-value boundaries.

    Returns a NullBaseline carrying the expected max, the p-value
    P(M_n >= observed_max), the classification, and per-k tail
    probabilities for k in 0..n_crib_positions.
    """
    if n_candidates < 1:
        raise ValueError("n_candidates must be >= 1")
    if not 0 <= observed_max_crib <= n_crib_positions:
        raise ValueError(
            f"observed_max_crib={observed_max_crib} must be in "
            f"[0, {n_crib_positions}]"
        )
    thresholds = dict(
        classification_thresholds or DEFAULT_CLASSIFICATION_THRESHOLDS
    )
    p_match = 1.0 / alphabet_size
    # Single-candidate Binomial PMF + CDF.
    pmf = [
        comb(n_crib_positions, k)
        * (p_match ** k)
        * ((1.0 - p_match) ** (n_crib_positions - k))
        for k in range(n_crib_positions + 1)
    ]
    cdf: list[float] = []
    cum = 0.0
    for x in pmf:
        cum += x
        cdf.append(min(1.0, cum))
    # Max distribution: P(M_n <= k) = F_X(k)^n.
    cdf_max = [c ** n_candidates for c in cdf]
    # Expected max via E[M_n] = sum_k k * (P(M_n<=k) - P(M_n<=k-1)).
    expected_max = 0.0
    for k in range(n_crib_positions + 1):
        prev = cdf_max[k - 1] if k > 0 else 0.0
        p_eq_k = cdf_max[k] - prev
        if p_eq_k < 0.0:
            # Numerical floor: floating-point can produce tiny
            # negative differences when both are essentially 1.0.
            p_eq_k = 0.0
        expected_max += k * p_eq_k
    # Per-k tail probabilities. P(M_n >= k) = 1 - P(M_n <= k-1).
    p_max_geq: dict[int, float] = {}
    for k in range(n_crib_positions + 1):
        prev = cdf_max[k - 1] if k > 0 else 0.0
        tail = 1.0 - prev
        # Floor at 0 to suppress floating-point underflow artifacts
        # at the upper tail (where prev is essentially 1.0).
        if tail < 0.0:
            tail = 0.0
        p_max_geq[k] = tail
    p_value = p_max_geq[observed_max_crib]
    classification = _classify_pvalue(p_value, thresholds)
    return NullBaseline(
        n_candidates=n_candidates,
        n_crib_positions=n_crib_positions,
        alphabet_size=alphabet_size,
        expected_max_crib=expected_max,
        observed_max_crib=observed_max_crib,
        p_value_for_observed_max=p_value,
        classification=classification,
        p_max_geq=p_max_geq,
        thresholds=thresholds,
    )


# ===========================================================================
# Audit candidate
# ===========================================================================


@dataclass
class RealK4AuditCandidate:
    hypothesis_id: str
    layer_family: str
    layers: list[dict[str, Any]]
    coverage_vector: dict[str, Any]
    plaintext: str
    crib_score: int
    bean_passed: bool
    ngram_score: float
    public_crib_match_map: list[dict[str, Any]]
    lessons_used: list[str]
    tier_signature: dict[str, Any]
    notes: str
    wall_time_sec: float
    job_artifact_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "layer_family": self.layer_family,
            "layers": list(self.layers),
            "coverage_vector": dict(self.coverage_vector),
            "plaintext": self.plaintext,
            "crib_score": int(self.crib_score),
            "bean_passed": bool(self.bean_passed),
            "ngram_score": float(self.ngram_score),
            "public_crib_match_map": list(self.public_crib_match_map),
            "lessons_used": list(self.lessons_used),
            "tier_signature": dict(self.tier_signature),
            "notes": self.notes,
            "wall_time_sec": float(self.wall_time_sec),
            "job_artifact_path": self.job_artifact_path,
        }


# ===========================================================================
# Audit configuration
# ===========================================================================


@dataclass
class RealK4AuditConfig:
    output_path: Path
    max_specs: int = 10000
    workers: int = max(1, (os.cpu_count() or 4) - 2)
    timeout_per_spec_sec: int = 30
    top_n_in_artifact: int = _DEFAULT_TOP_N
    tier_selector: Optional[str | Sequence[str]] = None
    max_keywords: int = 30  # cap on the keyword pool fed into HCC
    classification_thresholds: Optional[Mapping[str, float]] = None

    def __post_init__(self) -> None:
        if not isinstance(self.output_path, Path):
            self.output_path = Path(self.output_path)
        if self.max_specs <= 0:
            raise ValueError("max_specs must be positive")
        if self.workers <= 0:
            raise ValueError("workers must be positive")
        if self.timeout_per_spec_sec <= 0:
            raise ValueError("timeout_per_spec_sec must be positive")
        if self.max_keywords <= 0:
            raise ValueError("max_keywords must be positive")


# ===========================================================================
# Audit runner internals
# ===========================================================================


def _build_real_k4_problem_context() -> ProblemContext:
    return ProblemContext.real_k4()


def _public_crib_dict() -> dict[int, str]:
    from kryptos.kernel.constants import CRIB_DICT
    return dict(CRIB_DICT)


def _public_ct() -> str:
    from kryptos.kernel.constants import CT
    return CT


def _generate_audit_specs(
    *,
    max_specs: int,
    tier_selector: Optional[str | Sequence[str]],
    max_keywords: int,
) -> tuple[list[GeneratedSpec], list[str], tuple[str, ...]]:
    """Generate the deterministic HCC spec catalogue using the v2
    tier-filtered keyword pool. Returns (specs, keywords_used,
    active_tiers).
    """
    keywords = real_k4_clue_keywords(
        tiers=tier_selector, max_keywords=max_keywords,
    )
    clue_text = real_k4_audit_clue_text()
    bench_slug = "real-k4-audit"
    active_tiers = resolve_tier_selector(tier_selector)
    specs = generate_layered_specs(
        keywords,
        bench_slug=bench_slug,
        clue_text=clue_text,
        max_specs=max_specs,
    )
    return specs, keywords, active_tiers


def _attach_audit_override(spec: HypothesisSpec) -> HypothesisSpec:
    spec.override_exhaustion = True
    spec.override_justification = _AUDIT_OVERRIDE_JUSTIFICATION
    return spec


def _candidate_from_result(
    spec: GeneratedSpec,
    result: JobResult,
    crib_dict: Mapping[int, str],
) -> Optional[RealK4AuditCandidate]:
    best = result.best_candidate or {}
    pt = best.get("plaintext") or best.get("candidate_pt") or ""
    if not pt or len(pt) != 97:
        return None
    cv_dict = spec.coverage.to_dict()
    return RealK4AuditCandidate(
        hypothesis_id=spec.hypothesis_id,
        layer_family=spec.coverage.layer_family,
        layers=list(result.dispatched_dsl_spec.get("pipeline") or []),
        coverage_vector=cv_dict,
        plaintext=pt,
        crib_score=int(best.get("crib_score") or 0),
        bean_passed=bool(best.get("bean_passed") or False),
        ngram_score=float(best.get("ngram_score") or 0.0),
        public_crib_match_map=public_crib_match_map(pt, crib_dict),
        lessons_used=lessons_used_by_coverage(cv_dict),
        tier_signature=candidate_tier_signature(cv_dict),
        notes=spec.notes,
        wall_time_sec=float(result.wall_time_sec),
        job_artifact_path=str(result.artifact_path or ""),
    )


def _coverage_summary(
    candidates: Sequence[RealK4AuditCandidate],
) -> dict[str, Any]:
    by_lesson: dict[str, dict[str, Any]] = {}
    by_family: dict[str, dict[str, Any]] = {}
    by_tier: dict[str, dict[str, Any]] = {}
    by_provenance: dict[str, dict[str, Any]] = {}
    unattributed_lessons = 0
    untiered = 0
    for c in candidates:
        if not c.lessons_used:
            unattributed_lessons += 1
        for lesson in c.lessons_used:
            entry = by_lesson.setdefault(
                lesson,
                {
                    "n_candidates": 0,
                    "max_crib_score": 0,
                    "distinct_families": set(),
                },
            )
            entry["n_candidates"] += 1
            entry["max_crib_score"] = max(
                entry["max_crib_score"], c.crib_score,
            )
            entry["distinct_families"].add(c.layer_family)
        fam_entry = by_family.setdefault(
            c.layer_family,
            {"n_candidates": 0, "max_crib_score": 0},
        )
        fam_entry["n_candidates"] += 1
        fam_entry["max_crib_score"] = max(
            fam_entry["max_crib_score"], c.crib_score,
        )
        sig_tiers = c.tier_signature.get("tiers") or []
        if not sig_tiers:
            untiered += 1
        for tier in sig_tiers:
            tier_entry = by_tier.setdefault(
                tier,
                {
                    "n_candidates": 0,
                    "max_crib_score": 0,
                    "distinct_families": set(),
                },
            )
            tier_entry["n_candidates"] += 1
            tier_entry["max_crib_score"] = max(
                tier_entry["max_crib_score"], c.crib_score,
            )
            tier_entry["distinct_families"].add(c.layer_family)
        # By-provenance: walk the role lookups so the same candidate
        # contributes to multiple provenances if it crosses tiers.
        lookups = c.tier_signature.get("lookups") or {}
        for _, info in lookups.items():
            prov = info.get("provenance") if isinstance(info, dict) else None
            if not prov:
                continue
            prov_entry = by_provenance.setdefault(
                prov,
                {"n_candidates": 0, "max_crib_score": 0},
            )
            prov_entry["n_candidates"] += 1
            prov_entry["max_crib_score"] = max(
                prov_entry["max_crib_score"], c.crib_score,
            )
    # Set → count for JSON serialization.
    for entry in by_lesson.values():
        entry["distinct_families"] = len(entry["distinct_families"])
    for entry in by_tier.values():
        entry["distinct_families"] = len(entry["distinct_families"])
    return {
        "by_lesson": by_lesson,
        "by_family": by_family,
        "by_tier": by_tier,
        "by_provenance": by_provenance,
        "unattributed_lessons": unattributed_lessons,
        "untiered": untiered,
    }


def _dispatch_with_optional_workers(
    specs: Sequence[GeneratedSpec],
    workers: int,
) -> list[tuple[GeneratedSpec, JobResult]]:
    out: list[tuple[GeneratedSpec, JobResult]] = []
    for i, spec in enumerate(specs, 1):
        if i % 50 == 0:
            logger.info(
                "real_k4_audit: dispatching spec %d/%d (%s)",
                i, len(specs), spec.coverage.layer_family,
            )
        try:
            parsed = validate_hypothesis_spec(spec.raw_spec)
            if not parsed.is_valid:
                empty = JobResult(
                    hypothesis_id=spec.hypothesis_id,
                    spec_hash="",
                    universe_hash="",
                    admissibility_verdict=(
                        f"validation_failed: {parsed.errors[:2]}"
                    ),
                )
                out.append((spec, empty))
                continue
            audit_spec = _attach_audit_override(parsed.value)
            result = dispatcher_execute(
                audit_spec,
                workers=workers,
                bench_mode=False,
            )
            out.append((spec, result))
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            logger.warning(
                "real_k4_audit: spec %s raised %s: %s",
                spec.hypothesis_id[:32], type(exc).__name__, exc,
            )
            failed = JobResult(
                hypothesis_id=spec.hypothesis_id,
                spec_hash="",
                universe_hash="",
                admissibility_verdict=(
                    f"dispatch_error: {type(exc).__name__}: {exc}"
                ),
            )
            out.append((spec, failed))
    return out


def run_real_k4_hcc_audit(
    config: RealK4AuditConfig,
) -> dict[str, Any]:
    """Run the audit and return a summary dict."""
    t_start = time.monotonic()

    ctx = _build_real_k4_problem_context()
    if not ctx.is_real_k4:
        raise RuntimeError(
            "real_k4_audit invoked with non-real-K4 ProblemContext; "
            "this should be impossible."
        )

    crib_dict = _public_crib_dict()
    ct = _public_ct()

    specs, keywords_used, active_tiers = _generate_audit_specs(
        max_specs=config.max_specs,
        tier_selector=config.tier_selector,
        max_keywords=config.max_keywords,
    )
    logger.info(
        "real_k4_audit: generated %d HCC specs (max_specs=%d, "
        "tiers=%s, max_keywords=%d, n_keywords=%d)",
        len(specs), config.max_specs,
        list(active_tiers), config.max_keywords, len(keywords_used),
    )

    dispatch_results = _dispatch_with_optional_workers(
        specs, workers=config.workers,
    )

    candidates: list[RealK4AuditCandidate] = []
    n_admissibility_rejected = 0
    n_dispatch_error = 0
    n_no_candidate = 0
    for spec, result in dispatch_results:
        if (result.admissibility_verdict or "ok") != "ok":
            verdict = result.admissibility_verdict or ""
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
        key=lambda c: (c.crib_score, c.ngram_score),
        reverse=True,
    )

    coverage = _coverage_summary(candidates)
    observed_max_crib = max(
        (c.crib_score for c in candidates), default=0,
    )

    null_baseline = compute_null_baseline(
        max(1, len(candidates)),
        observed_max_crib,
        classification_thresholds=config.classification_thresholds,
    )

    # Build the artifact.
    keyword_entries = real_k4_clue_words_with_provenance(
        tiers=config.tier_selector,
    )
    artifact: dict[str, Any] = {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "run_metadata": {
            "started_at_monotonic_sec": t_start,
            "wall_time_sec": time.monotonic() - t_start,
            "max_specs": config.max_specs,
            "top_n_in_artifact": config.top_n_in_artifact,
            "workers": config.workers,
            "mode": "real_k4",
            "tier_selector_input": (
                config.tier_selector if isinstance(config.tier_selector, str)
                else (list(config.tier_selector) if config.tier_selector else None)
            ),
            "active_tiers": list(active_tiers),
            "max_keywords": config.max_keywords,
        },
        "public_facts": {
            "ciphertext": ct,
            "ct_length": len(ct),
            "crib_dict": {
                str(pos): letter for pos, letter in sorted(crib_dict.items())
            },
            "n_cribs": len(crib_dict),
        },
        "clue_pack": {
            "source_module": "kryptosbot.real_k4_clue_registry",
            "registry_schema": "v2",
            "active_tiers": list(active_tiers),
            "keywords_used": list(keywords_used),
            "keyword_entries": [e.to_dict() for e in keyword_entries],
            "clue_text": real_k4_audit_clue_text(),
        },
        "dispatch_summary": {
            "n_specs_generated": len(specs),
            "n_candidates_with_plaintext": len(candidates),
            "n_admissibility_rejected": n_admissibility_rejected,
            "n_dispatch_error": n_dispatch_error,
            "n_no_candidate": n_no_candidate,
        },
        "coverage_summary": coverage,
        "null_baseline": null_baseline.to_dict(),
        "candidates": [
            c.to_dict() for c in candidates[: config.top_n_in_artifact]
        ],
    }

    config.output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config.output_path, "w") as f:
        json.dump(artifact, f, sort_keys=True, indent=2)

    summary = {
        "artifact_path": str(config.output_path),
        "active_tiers": list(active_tiers),
        "n_keywords": len(keywords_used),
        "n_specs_generated": len(specs),
        "n_candidates": len(candidates),
        "n_admissibility_rejected": n_admissibility_rejected,
        "n_dispatch_error": n_dispatch_error,
        "n_no_candidate": n_no_candidate,
        "max_crib_score": observed_max_crib,
        "null_baseline": {
            "expected_max_crib": null_baseline.expected_max_crib,
            "observed_max_crib": null_baseline.observed_max_crib,
            "p_value_for_observed_max": (
                null_baseline.p_value_for_observed_max
            ),
            "classification": null_baseline.classification,
        },
        "top_5_candidates": [
            {
                "hypothesis_id": c.hypothesis_id,
                "layer_family": c.layer_family,
                "crib_score": c.crib_score,
                "lessons_used": c.lessons_used,
                "tiers": c.tier_signature.get("tiers", []),
                "substitution_keyword": (
                    c.coverage_vector.get("substitution_keyword") or ""
                ),
                "alphabet_mode": (
                    c.coverage_vector.get("alphabet_mode") or ""
                ),
            }
            for c in candidates[:5]
        ],
        "coverage_by_lesson": {
            lesson: {
                "n_candidates": entry["n_candidates"],
                "max_crib_score": entry["max_crib_score"],
                "distinct_families": entry["distinct_families"],
            }
            for lesson, entry in coverage["by_lesson"].items()
        },
        "coverage_by_tier": {
            tier: {
                "n_candidates": entry["n_candidates"],
                "max_crib_score": entry["max_crib_score"],
                "distinct_families": entry["distinct_families"],
            }
            for tier, entry in coverage["by_tier"].items()
        },
        "coverage_by_provenance": dict(coverage["by_provenance"]),
        "wall_time_sec": time.monotonic() - t_start,
    }
    return summary


__all__ = [
    "RealK4AuditConfig",
    "RealK4AuditCandidate",
    "NullBaseline",
    "DEFAULT_CLASSIFICATION_THRESHOLDS",
    "compute_null_baseline",
    "lessons_used_by_coverage",
    "public_crib_match_map",
    "candidate_tier_signature",
    "run_real_k4_hcc_audit",
]
