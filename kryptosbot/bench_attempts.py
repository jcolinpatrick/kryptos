"""K4Bench attempt-artifact emitter.

After a controller run completes against a K4Bench challenge, this
module packages the controller's best candidates into the
``k4bench.attempts.v1`` schema so an offline evaluator can score the
run against the sealed answer file.

The artifact contains nothing the ledger does not already hold; it is
a focused projection of the ledger over one bench_id, with the
synthetic-mode taint surfaced explicitly.

The emitter is a boundary that must never crash a run: the controller
finished its real work before we get here. Callers wrap this in a
``try``/``except`` and log on failure rather than aborting.

Layer-source priority (2026-04-27 fix to the layers=[] bug):
  1. result.raw_artifacts.dispatched_dsl_spec.pipeline
  2. experiment.config.dsl_spec.pipeline
  3. theory.minimal_test_spec.dsl_spec.pipeline

The first layer source is the post-procedural-expansion HypothesisSpec
the dispatcher actually ran; the second is the repaired pre-dispatch
form; the third is whatever was last persisted on the theory row. The
old code only looked at theory.minimal_test_spec and used the wrong
key (``layers`` / ``steps``) instead of ``pipeline``, which is why
historical attempt artifacts had ``layers=[]`` for every entry even
when the dispatcher had run a fully-resolved spec.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # pragma: no cover — typing only
    from kryptosbot.bench_loader import K4BenchChallenge


_SCHEMA_VERSION = "k4bench.attempts.v1"


@dataclass
class AttemptCandidate:
    """One reportable attempt for the bench challenge.

    A controller run typically produces many tested theories; this
    structure carries the one(s) the evaluator should score. The
    fields mirror the K4Bench solver_output_contract so an evaluator
    can read both attempt and contract from the same vocabulary.

    ``layers`` carries the post-expansion HypothesisSpec.pipeline
    (CipherLayer dicts, with ``params`` as ParamRange dicts). When
    ``best_config_bindings`` is non-empty, the evaluator can collapse
    multi-value params to the single value the dispatcher actually
    picked for the best candidate.

    ``coverage_vector`` (lesson 006: failed_method_coverage) is the
    normalized record of which symmetry-class point this attempt
    tested. Downstream telemetry uses it to answer "have we tested
    all role inversions for this clue pair and family?". An empty
    dict means the theory was not hand_cipher_core-derived (legacy
    SDK theorist or other origin); the gap analyzer ignores empty
    vectors.
    """

    bench_id: str
    plaintext: str
    confidence: float
    method_summary: str
    layers: list[dict[str, Any]]
    crib_score: int
    evidence: dict[str, Any]
    reproducibility_notes: str
    # K4Bench replay support: when the dispatcher swept multiple
    # configs (e.g. a route with 8 rows×cols variants), this records
    # the binding tuple for the one that produced the best candidate.
    # Empty list when the spec had no params or no successful config.
    best_config_bindings: list[list[Any]]
    coverage_vector: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "bench_id": self.bench_id,
            "plaintext": self.plaintext,
            "confidence": self.confidence,
            "method_summary": self.method_summary,
            "layers": list(self.layers),
            "crib_score": self.crib_score,
            "evidence": dict(self.evidence),
            "reproducibility_notes": self.reproducibility_notes,
            "best_config_bindings": [list(p) for p in self.best_config_bindings],
            "coverage_vector": dict(self.coverage_vector),
        }


# --- Layer-source resolution --------------------------------------------------


def _coerce_pipeline(raw: Any) -> list[dict[str, Any]]:
    """Accept whatever a layer-source contains and return a list of
    layer dicts, or [] if the source was empty / wrong-shaped.

    The canonical key is ``pipeline`` (HypothesisSpec.to_dict). For
    backward compatibility we also accept ``layers`` and ``steps`` —
    pre-2026-04-27 artifacts used those names interchangeably and a
    handful of test fixtures still do.
    """
    if not isinstance(raw, dict):
        return []
    for key in ("pipeline", "layers", "steps"):
        candidate = raw.get(key)
        if isinstance(candidate, list):
            return [layer for layer in candidate if isinstance(layer, dict)]
    return []


def _safe_dsl_layers(
    theory,
    *,
    contract: Any = None,
    experiment: Any = None,
) -> list[dict[str, Any]]:
    """Resolve layers for one theory in priority order.

    Sources, in order:
      1. ``contract.raw_artifacts['dispatched_dsl_spec']['pipeline']``
      2. ``experiment.config['dsl_spec']['pipeline']``
      3. ``theory.minimal_test_spec['dsl_spec']['pipeline']``

    The function is tolerant: any source that is missing, has the
    wrong type, or lacks the expected nested keys is skipped silently
    and the next source is tried. Returns [] only when every source
    is empty.

    The first non-empty source wins; we do not merge across sources
    because the dispatcher's post-expansion form supersedes the
    pre-dispatch repaired form, which itself supersedes whatever the
    theorist originally authored.
    """
    # Source 1: contract.raw_artifacts.dispatched_dsl_spec.pipeline
    if contract is not None:
        raw_artifacts = getattr(contract, "raw_artifacts", None)
        if isinstance(raw_artifacts, dict):
            dispatched = raw_artifacts.get("dispatched_dsl_spec")
            layers = _coerce_pipeline(dispatched)
            if layers:
                return layers

    # Source 2: experiment.config.dsl_spec.pipeline
    if experiment is not None:
        config = getattr(experiment, "config", None)
        if isinstance(config, dict):
            dsl_spec = config.get("dsl_spec")
            layers = _coerce_pipeline(dsl_spec)
            if layers:
                return layers

    # Source 3: theory.minimal_test_spec.dsl_spec.pipeline (legacy)
    spec = getattr(theory, "minimal_test_spec", None)
    if isinstance(spec, dict):
        dsl_spec = spec.get("dsl_spec")
        layers = _coerce_pipeline(dsl_spec)
        if layers:
            return layers

    return []


def _safe_best_bindings(
    theory,
    *,
    contract: Any = None,
) -> list[list[Any]]:
    """Resolve the best-config bindings list, preferring the contract."""
    if contract is not None:
        raw_artifacts = getattr(contract, "raw_artifacts", None)
        if isinstance(raw_artifacts, dict):
            bindings = raw_artifacts.get("best_config_bindings")
            if isinstance(bindings, list):
                return [list(p) for p in bindings if isinstance(p, (list, tuple))]
    spec = getattr(theory, "minimal_test_spec", None)
    if isinstance(spec, dict):
        bindings = spec.get("best_config_bindings")
        if isinstance(bindings, list):
            return [list(p) for p in bindings if isinstance(p, (list, tuple))]
    return []


def _safe_coverage_vector(theory) -> dict[str, Any]:
    """Resolve the coverage vector from theory.minimal_test_spec.

    The hand_cipher_core fallback writes the vector at
    ``minimal_test_spec.coverage_vector``. Theories from other origins
    (legacy SDK theorists, real-K4 family registry) do not carry it
    and return {}; downstream telemetry treats an empty dict as
    "no coverage info available" and skips gap analysis for that row.
    """
    spec = getattr(theory, "minimal_test_spec", None)
    if not isinstance(spec, dict):
        return {}
    cv = spec.get("coverage_vector")
    if isinstance(cv, dict):
        return dict(cv)
    return {}


def _latest_experiment_for_theory(ledger, hypothesis_id: str):
    """Return the most-recently-completed experiment for the theory,
    or None if none exists. The ledger sorts experiments DESC by
    started_at so the head of the list is the latest run.
    """
    try:
        experiments = ledger.get_experiments_for_theory(hypothesis_id)
    except Exception:  # noqa: BLE001 — defensive boundary
        return None
    return experiments[0] if experiments else None


# --- Candidate selection ------------------------------------------------------


def _theory_is_hcc_seed(theory) -> bool:
    """Identify HandCipherCore-derived theories.

    A theory is an HCC seed iff EITHER:
      * its ``origin`` field is ``"programmatic_fallback"`` (the
        controller marker for HCC theories), OR
      * its ``minimal_test_spec`` carries a non-empty
        ``coverage_vector`` (the structural marker — set by
        hand_cipher_core_fallback for every emitted theory).

    Either condition alone is sufficient. Both should be true for
    real HCC seeds, but the OR-fallback covers the case where one
    of the two markers gets dropped by a future refactor — better
    to over-include than to silently lose a coverage-critical
    seed from the artifact.
    """
    origin = getattr(theory, "origin", "")
    if origin == "programmatic_fallback":
        return True
    spec = getattr(theory, "minimal_test_spec", None)
    if isinstance(spec, dict):
        cv = spec.get("coverage_vector")
        if isinstance(cv, dict) and cv:
            return True
    return False


def _build_attempt_candidate(
    theory,
    challenge: "K4BenchChallenge",
    ledger,
) -> Optional[AttemptCandidate]:
    """Build one AttemptCandidate from a TheoryRecord. Returns None
    if the theory has no scorable plaintext (no 97-char A-Z best_pt).
    """
    pt = (theory.best_plaintext or "").strip()
    if len(pt) != 97 or not pt.isalpha() or not pt.isupper():
        return None
    experiment = _latest_experiment_for_theory(ledger, theory.hypothesis_id)
    contract = getattr(experiment, "result", None) if experiment is not None else None
    layers = _safe_dsl_layers(theory, contract=contract, experiment=experiment)
    bindings = _safe_best_bindings(theory, contract=contract)
    coverage = _safe_coverage_vector(theory)
    method_summary = (theory.mechanism or theory.title or "").strip()
    crib_score = sum(
        1 for pos, ch in challenge.crib_dict.items() if pt[pos] == ch
    )
    return AttemptCandidate(
        bench_id=challenge.bench_id,
        plaintext=pt,
        confidence=float(min(max(theory.best_score / 24.0, 0.0), 1.0)),
        method_summary=method_summary[:500],
        layers=layers,
        crib_score=crib_score,
        evidence={
            "hypothesis_id": theory.hypothesis_id,
            "title": theory.title,
            "family": theory.family,
            "status": getattr(theory.status, "value", str(theory.status)),
            "outcome_summary": (theory.outcome_summary or "")[:1000],
            "origin": getattr(theory, "origin", ""),
            "is_hcc_seed": _theory_is_hcc_seed(theory),
            "why_this_is_not_crib_fitting": (
                "Plaintext outside crib spans should be evaluated for "
                "linguistic plausibility by the offline evaluator; the "
                "controller does not certify non-crib regions itself."
            ),
            "alternative_candidates_rejected": [],
        },
        reproducibility_notes=(
            f"Theory {theory.hypothesis_id[:8]} from K4Bench run "
            f"({challenge.bench_id}). Layers (if present) replay "
            f"deterministically through the kernel DSL."
        ),
        best_config_bindings=bindings,
        coverage_vector=coverage,
    )


def _select_candidates(
    ledger,
    challenge: "K4BenchChallenge",
    *,
    top_n: int = 5,
) -> list[AttemptCandidate]:
    """Pick candidates for the bench attempt artifact.

    2026-04-27 selection policy (changed from "top-N by crib_score"):

    1. INCLUDE EVERY HCC SEED with a 97-char plaintext. HCC seeds
       carry the deterministic-coverage contract — every one MUST
       appear in the artifact regardless of crib_score. The offline
       evaluator can then answer "did the missing-inverse-role spec
       get dispatched?" without depending on chance ranking.
    2. ADD top-N non-HCC theories ranked by crib_score then
       confidence. ``top_n`` controls only the non-HCC slice.

    The ordering inside the artifact: HCC seeds first (sorted by
    crib_score desc so the strongest seed shows up first within the
    HCC block), then the top-N non-HCC theories. The previous
    implementation flat-capped at ``top_n`` and lost coverage seeds
    whose crib_score didn't make the top-5 cut — that's the bug
    this patch closes.

    Theories with no 97-char plaintext are skipped (they can't be
    scored end-to-end). For HCC seeds this should never happen in
    practice — every dispatched HCC spec runs through the kernel
    pipeline and produces a 97-char output by construction — but
    the filter is kept as a defensive boundary.
    """
    theories = ledger.search_theories(min_score=0.0, limit=500)

    hcc_candidates: list[AttemptCandidate] = []
    other_candidates: list[AttemptCandidate] = []
    for theory in theories:
        cand = _build_attempt_candidate(theory, challenge, ledger)
        if cand is None:
            continue
        if _theory_is_hcc_seed(theory):
            hcc_candidates.append(cand)
        else:
            other_candidates.append(cand)

    # Sort each list by (crib_score desc, confidence desc).
    sort_key = lambda c: (c.crib_score, c.confidence)
    hcc_candidates.sort(key=sort_key, reverse=True)
    other_candidates.sort(key=sort_key, reverse=True)

    # HCC seeds are unconditional; non-HCC slice is top_n.
    return hcc_candidates + other_candidates[:top_n]


def emit_attempt_artifact(
    *,
    challenge: "K4BenchChallenge",
    ledger_db_path: Path,
    project_root: Path,
    output_path: Path | None = None,
    top_n: int = 5,
) -> Path:
    """Write the K4Bench attempt artifact JSON and return its path.

    Defaults to ``<project_root>/bench/k4bench/attempts/<bench_id>.json``.
    The output directory is created if missing. Existing files are
    overwritten — the artifact captures the ledger state at end-of-run
    and is not append-only.
    """
    # Lazy import to avoid pulling kryptosbot.theory_ledger when nobody
    # uses bench mode (the controller imports this module on demand).
    from kryptosbot.theory_ledger import TheoryLedger

    if output_path is None:
        out_dir = project_root / "bench" / "k4bench" / "attempts"
        out_dir.mkdir(parents=True, exist_ok=True)
        output_path = out_dir / f"{challenge.bench_id}.json"
    else:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

    ledger = TheoryLedger(ledger_db_path)
    candidates = _select_candidates(ledger, challenge, top_n=top_n)

    summary = ledger.summary()

    artifact = {
        "schema_version": _SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "challenge": challenge.to_summary_dict(),
        "ledger_summary": {
            # Field names mirror TheoryLedger.summary() output. A prior
            # version of this code looked up "theory_count"/"by_status",
            # which silently produced empty defaults because the ledger
            # uses "total_theories"/"theories_by_status".
            "total_theories": summary.get("total_theories", 0),
            "total_experiments": summary.get("total_experiments", 0),
            "theories_by_status": summary.get("theories_by_status", {}),
        },
        "attempts": [c.to_dict() for c in candidates],
        "notes": (
            "Generated by kryptosbot.bench_attempts.emit_attempt_artifact. "
            "Top-N candidates with non-empty 97-char plaintexts are listed. "
            "An empty attempts list means no theory in this run produced a "
            "scorable plaintext; the run is recorded as method_only / "
            "near_miss / unsupported_transform per the failure taxonomy. "
            "The offline evaluator should score the strict_pass_rule from "
            "the sealed answer file against these layers and plaintext."
        ),
    }
    output_path.write_text(json.dumps(artifact, indent=2, sort_keys=True))
    return output_path
