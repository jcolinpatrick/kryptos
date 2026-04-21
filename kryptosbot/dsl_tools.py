"""DSL-oriented MCP tools for K4 analysis via Claude Agent SDK.

Framework maturation Phase 5 (2026-04-21). These tools route worker
calls through the ``kryptosbot.hypothesis_dsl`` / ``kryptosbot.job_dispatcher``
infrastructure from Phase 4 and the kernel's canonical scoring path.
They replace the noise tools in ``kryptosbot.k4_tools``
(``hill_climb``, ``try_keyword_sweep``, ``swap_and_test``) which are
now deprecated.

All tools return the standard envelope:

    {
        "status": "ok" | "error" | "not_yet_available",
        "data":   <tool-specific payload>,
        "provenance": {
            "kernel_commit": "<git rev-parse HEAD at module load, or 'unknown'>",
            "phase":         5,
            "assumption_bundle": [...],
            ... (tool-specific extras)
        }
    }

and wrap the envelope in the SDK's content-blocks format at return time.

See ``docs/maturation/phase_05_report.md`` for the before/after tool
inventory and the design rationale.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from claude_agent_sdk import tool, create_sdk_mcp_server

from .hypothesis_dsl import (
    HypothesisSpec,
    _VALID_ALPHABET_KINDS,
    validate_hypothesis_spec,
)
from .job_dispatcher import (
    _SUPPORTED_KINDS,
    JobResult,
    check_admissibility,
    execute,
)

logger = logging.getLogger("kryptosbot.dsl_tools")


# ─── Provenance helpers ──────────────────────────────────────────────────────

def _compute_kernel_commit() -> str:
    """Return the git commit hash at module load time, or 'unknown'.

    Cached at module load; tool calls never subprocess. Falls back to
    the KRYPTOSBOT_KERNEL_COMMIT env var if git is unavailable.
    """
    import os
    env_override = os.environ.get("KRYPTOSBOT_KERNEL_COMMIT")
    if env_override:
        return env_override
    here = Path(__file__).resolve().parent.parent
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=here, capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


_KERNEL_COMMIT: str = _compute_kernel_commit()


def _envelope(
    status: str,
    data: Any,
    assumption_bundle: Optional[list[str]] = None,
    extra_provenance: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build the standard tool-return envelope."""
    prov: dict[str, Any] = {
        "kernel_commit": _KERNEL_COMMIT,
        "phase": 5,
        "assumption_bundle": list(assumption_bundle or []),
    }
    if extra_provenance:
        prov.update(extra_provenance)
    return {"status": status, "data": data, "provenance": prov}


def _text_response(envelope: dict[str, Any]) -> dict[str, Any]:
    """SDK content-blocks wrapper."""
    return {
        "content": [
            {"type": "text", "text": json.dumps(envelope, indent=2, default=str)}
        ]
    }


# ─── Background job registry ─────────────────────────────────────────────────
#
# submit_hypothesis_spec dispatches execute() on a worker thread so the
# MCP tool call returns immediately with a job_id; poll_job retrieves
# the current state. In-process, thread-safe, module-local — no external
# queue system. Adequate for per-controller-cycle scale; replace with
# a proper queue if the concurrency story ever needs to outlive the
# controller process.

_JOBS_LOCK = threading.Lock()
_JOBS: dict[str, dict[str, Any]] = {}


def _register_job(job_id: str, spec: HypothesisSpec) -> None:
    with _JOBS_LOCK:
        _JOBS[job_id] = {
            "job_id": job_id,
            "hypothesis_id": spec.hypothesis_id,
            "spec_hash": spec.spec_hash,
            "spec": spec.to_dict(),
            "state": "queued",           # "queued" | "running" | "completed" | "failed"
            "result": None,              # JobResult dict when completed
            "error": None,                # str when failed
            "started_at": None,           # float
            "finished_at": None,          # float
            "expected_cardinality": spec.expected_cardinality(),
        }


def _get_job(job_id: str) -> Optional[dict[str, Any]]:
    with _JOBS_LOCK:
        return dict(_JOBS.get(job_id)) if job_id in _JOBS else None


def _run_job_threaded(job_id: str, spec: HypothesisSpec) -> None:
    """Worker-thread body: execute the spec and record the result.

    All writes to ``_JOBS[job_id]`` are guarded by the lock AND tolerate
    the entry being missing — ``_reset_jobs_for_testing`` can clear the
    registry mid-flight, and the controller process may similarly cull
    stale jobs. A vanished entry is not an error; it just means no one
    is listening for this job's result anymore.
    """
    with _JOBS_LOCK:
        if job_id not in _JOBS:
            return
        _JOBS[job_id]["state"] = "running"
        _JOBS[job_id]["started_at"] = time.time()
    try:
        # parallel=False inside the background thread keeps pickle overhead
        # reasonable for the interactive MCP context; spec-level workers that
        # need more throughput can drop into execute() directly from the
        # controller outside the tool path.
        result = execute(spec, parallel=False)
        with _JOBS_LOCK:
            if job_id in _JOBS:
                _JOBS[job_id]["result"] = result.to_dict()
                _JOBS[job_id]["state"] = "completed"
                _JOBS[job_id]["finished_at"] = time.time()
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Background job %s raised", job_id)
        with _JOBS_LOCK:
            if job_id in _JOBS:
                _JOBS[job_id]["error"] = f"{type(exc).__name__}: {exc}"
                _JOBS[job_id]["state"] = "failed"
                _JOBS[job_id]["finished_at"] = time.time()


def _reset_jobs_for_testing() -> None:
    """Test hook — drop all registered jobs."""
    with _JOBS_LOCK:
        _JOBS.clear()


# ─── 1. submit_hypothesis_spec ───────────────────────────────────────────────

@tool(
    "submit_hypothesis_spec",
    "Submit a kryptosbot.hypothesis_dsl.HypothesisSpec for execution. "
    "Validates the spec (failing closed with explicit errors on malformed "
    "input), admissibility-checks against compute budget and "
    "exhaustion-log overlap, then dispatches execute() on a background "
    "thread and returns a job_id. Poll with poll_job(job_id).",
    {"spec": dict},
)
async def submit_hypothesis_spec_tool(args: dict[str, Any]) -> dict[str, Any]:
    spec_dict = args.get("spec")
    if not isinstance(spec_dict, dict):
        return _text_response(_envelope(
            "error",
            {"reason": "submit_hypothesis_spec requires 'spec': dict"},
        ))

    parsed = validate_hypothesis_spec(spec_dict)
    if not parsed.is_valid:
        return _text_response(_envelope(
            "error",
            {"reason": "spec validation failed", "errors": parsed.errors},
        ))
    assert parsed.value is not None
    spec = parsed.value

    admissible, reasons = check_admissibility(spec)
    if not admissible:
        return _text_response(_envelope(
            "error",
            {"reason": "admissibility rejected", "admissibility_reasons": reasons},
            assumption_bundle=spec.assumption_bundle,
            extra_provenance={"spec_hash": spec.spec_hash},
        ))

    job_id = f"job_{uuid.uuid4().hex[:12]}"
    _register_job(job_id, spec)
    thread = threading.Thread(
        target=_run_job_threaded, args=(job_id, spec), daemon=True,
    )
    thread.start()

    return _text_response(_envelope(
        "ok",
        {
            "job_id": job_id,
            "hypothesis_id": spec.hypothesis_id,
            "spec_hash": spec.spec_hash,
            "expected_cardinality": spec.expected_cardinality(),
        },
        assumption_bundle=spec.assumption_bundle,
        extra_provenance={"spec_hash": spec.spec_hash},
    ))


# ─── 2. poll_job ─────────────────────────────────────────────────────────────

@tool(
    "poll_job",
    "Poll a job previously submitted via submit_hypothesis_spec. Returns "
    "the current state (queued / running / completed / failed) plus the "
    "JobResult when completed. A progress percentage is returned when "
    "running (coarse: 0 while queued, 50 while running, 100 when done).",
    {"job_id": str},
)
async def poll_job_tool(args: dict[str, Any]) -> dict[str, Any]:
    job_id = args.get("job_id")
    if not isinstance(job_id, str) or not job_id:
        return _text_response(_envelope(
            "error", {"reason": "poll_job requires 'job_id': str"},
        ))

    entry = _get_job(job_id)
    if entry is None:
        return _text_response(_envelope(
            "error", {"reason": f"job_id {job_id!r} not found"},
        ))

    state = entry["state"]
    progress_pct: int = {"queued": 0, "running": 50,
                         "completed": 100, "failed": 100}.get(state, 0)
    data: dict[str, Any] = {
        "job_id": job_id,
        "state": state,
        "progress_pct": progress_pct,
        "hypothesis_id": entry["hypothesis_id"],
        "spec_hash": entry["spec_hash"],
        "expected_cardinality": entry["expected_cardinality"],
        "started_at": entry["started_at"],
        "finished_at": entry["finished_at"],
        "result": entry["result"],
        "error": entry["error"],
    }
    return _text_response(_envelope(
        "ok", data,
        extra_provenance={"spec_hash": entry["spec_hash"]},
    ))


# ─── 3. query_exhaustion ─────────────────────────────────────────────────────

@tool(
    "query_exhaustion",
    "Given a partial DSL spec (cipher kinds + assumption bundle), return "
    "overlapping entries from exhaustion_log.json. Agents call this "
    "BEFORE submitting a hypothesis to avoid re-testing an eliminated "
    "family. The overlap heuristic is a family-substring match; false "
    "positives are advisory.",
    {"kinds": list, "assumption_bundle": list},
)
async def query_exhaustion_tool(args: dict[str, Any]) -> dict[str, Any]:
    kinds = args.get("kinds") or []
    assumption_bundle = args.get("assumption_bundle") or []
    if not isinstance(kinds, list):
        return _text_response(_envelope(
            "error", {"reason": "'kinds' must be a list"},
        ))
    if not isinstance(assumption_bundle, list):
        return _text_response(_envelope(
            "error", {"reason": "'assumption_bundle' must be a list"},
        ))

    # Reuse the dispatcher's internals for consistency.
    from .job_dispatcher import _exhaustion_overlap, _load_exhaustion_log
    from .hypothesis_dsl import CipherLayer, HypothesisSpec

    # Build a minimal spec just for the overlap function.
    pipeline: list[CipherLayer] = []
    unknown_kinds = []
    for k in kinds:
        if not isinstance(k, str):
            unknown_kinds.append(repr(k))
            continue
        pipeline.append(CipherLayer(kind=k))
    probe = HypothesisSpec(
        hypothesis_id="probe",
        pipeline=pipeline,
        assumption_bundle=assumption_bundle,
    )
    log = _load_exhaustion_log()
    overlaps = _exhaustion_overlap(probe, log)

    return _text_response(_envelope(
        "ok",
        {
            "total_log_entries": len(log),
            "overlapping_scripts": overlaps,
            "overlap_count": len(overlaps),
            "unknown_kinds": unknown_kinds,
        },
        assumption_bundle=list(assumption_bundle),
    ))


# ─── 4. compute_null_baseline (Phase-6 stub + minimal Phase-5 baseline) ──────
#
# Phase 4 note: full null-baseline infrastructure is Phase 6 work. The
# Phase-5 implementation here handles exactly one scorer × method
# combination (crib_score × random_text at CT length 97) by running
# a deterministic Monte Carlo on demand and caching the result. Other
# combos return "not_yet_available" with a pointer at Phase 6. Callers
# who need other combos should wait for the Phase 6 calibration module.

_PHASE5_NULL_CACHE_PATH = (
    Path(__file__).resolve().parent.parent
    / "results" / "null_baselines_phase5_stub.json"
)


def _build_phase5_null_baseline_for_crib_score(
    n_samples: int = 10_000,
    seed: int = 20260421,
) -> dict[str, Any]:
    """Minimal demonstrator. Phase 6 replaces this with a proper module."""
    import random as _random
    from kryptos.kernel.scoring.crib_score import score_cribs

    rng = _random.Random(seed)
    scores = []
    for _ in range(n_samples):
        pt = "".join(
            rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(97)
        )
        scores.append(score_cribs(pt))
    scores.sort()
    n = len(scores)
    mean = sum(scores) / n
    var = sum((s - mean) ** 2 for s in scores) / n
    def pct(p: float) -> float:
        return scores[min(n - 1, int(p * n))]
    return {
        "scorer": "crib_score",
        "method": "random_text",
        "n_chars": 97,
        "alphabet": "AZ",
        "n_samples": n,
        "seed": seed,
        "mean": mean,
        "stdev": var ** 0.5,
        "min": scores[0],
        "max": scores[-1],
        "p50": pct(0.50),
        "p90": pct(0.90),
        "p95": pct(0.95),
        "p99": pct(0.99),
        "kernel_commit": _KERNEL_COMMIT,
    }


@tool(
    "compute_null_baseline",
    "Return the cached null distribution summary (mean, stdev, "
    "percentiles) for a given (scorer, method, n_chars, alphabet) "
    "combination. Phase 5 supports ONLY (scorer='crib_score', "
    "method='random_text', n_chars=97, alphabet='AZ') as a demonstrator; "
    "other combinations return 'not_yet_available' with a Phase 6 "
    "pointer. The Phase-5 baseline is deterministic (fixed seed) and "
    "cached to results/null_baselines_phase5_stub.json.",
    {"scorer": str, "method": str, "n_chars": int, "alphabet": str},
)
async def compute_null_baseline_tool(args: dict[str, Any]) -> dict[str, Any]:
    scorer = args.get("scorer", "crib_score")
    method = args.get("method", "random_text")
    n_chars = int(args.get("n_chars", 97))
    alphabet = args.get("alphabet", "AZ")

    supported = (scorer == "crib_score"
                 and method == "random_text"
                 and n_chars == 97
                 and alphabet == "AZ")
    if not supported:
        return _text_response(_envelope(
            "not_yet_available",
            {
                "reason": (
                    "Phase 5 supports only (scorer='crib_score', "
                    "method='random_text', n_chars=97, alphabet='AZ'). "
                    "Phase 6 null-baseline calibration module will extend "
                    "to other scorers and methods."
                ),
                "requested": {
                    "scorer": scorer, "method": method,
                    "n_chars": n_chars, "alphabet": alphabet,
                },
            },
            extra_provenance={"pending_phase": 6},
        ))

    # Cache hit or miss.
    if _PHASE5_NULL_CACHE_PATH.exists():
        try:
            cached = json.loads(_PHASE5_NULL_CACHE_PATH.read_text())
            return _text_response(_envelope(
                "ok", cached,
                extra_provenance={"cache": "hit"},
            ))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Null cache unreadable; rebuilding: %s", exc)

    summary = _build_phase5_null_baseline_for_crib_score()
    _PHASE5_NULL_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _PHASE5_NULL_CACHE_PATH.write_text(json.dumps(summary, indent=2))
    return _text_response(_envelope(
        "ok", summary,
        extra_provenance={"cache": "miss_built"},
    ))


# ─── 5. score_candidate_canonical ────────────────────────────────────────────

@tool(
    "score_candidate_canonical",
    "Score a 97-character plaintext candidate via the canonical kernel "
    "scoring path (kryptos.kernel.scoring.aggregate.score_candidate). "
    "Returns the full ScoreBreakdown with crib_score, bean_passed, "
    "ngram_score, classification, and (when available) a p-value vs "
    "the Phase-5 random_text baseline.",
    {"plaintext": str, "include_p_value": bool},
)
async def score_candidate_canonical_tool(args: dict[str, Any]) -> dict[str, Any]:
    pt = args.get("plaintext", "")
    include_p_value = bool(args.get("include_p_value", False))

    if not isinstance(pt, str):
        return _text_response(_envelope(
            "error", {"reason": "'plaintext' must be a string"},
        ))
    pt_norm = pt.strip().upper()

    try:
        from kryptos.kernel.scoring.aggregate import score_candidate
        breakdown = score_candidate(pt_norm)
    except Exception as exc:  # pragma: no cover - defensive
        return _text_response(_envelope(
            "error",
            {"reason": f"kernel scoring raised: {type(exc).__name__}: {exc}"},
        ))

    data: dict[str, Any] = {
        "plaintext_normalized": pt_norm,
        "length": len(pt_norm),
        "crib_score": int(getattr(breakdown, "crib_score", 0)),
        "bean_passed": bool(getattr(breakdown, "bean_passed", False)),
        "ngram_score": float(getattr(breakdown, "ngram_score", 0.0) or 0.0),
        "ic_value": float(getattr(breakdown, "ic_value", 0.0) or 0.0),
        "classification": str(getattr(breakdown, "crib_classification", "unknown")),
    }

    if include_p_value and _PHASE5_NULL_CACHE_PATH.exists():
        try:
            null = json.loads(_PHASE5_NULL_CACHE_PATH.read_text())
            # Fraction of null samples with crib_score >= observed.
            # For Phase 5 demonstrator this is a coarse estimate since
            # we only cached summary percentiles; use ordering against
            # the p95/p99 cutoffs to report an interval.
            observed = data["crib_score"]
            if observed >= null.get("p99", 0):
                p_bound = "p<=0.01"
            elif observed >= null.get("p95", 0):
                p_bound = "0.01<p<=0.05"
            elif observed >= null.get("p90", 0):
                p_bound = "0.05<p<=0.10"
            else:
                p_bound = "p>0.10"
            data["p_value_vs_null"] = p_bound
            data["null_mean"] = null.get("mean")
            data["null_stdev"] = null.get("stdev")
        except (OSError, json.JSONDecodeError):
            data["p_value_vs_null"] = "null_cache_unavailable"

    return _text_response(_envelope("ok", data))


# ─── 6. get_procedural_recipe ────────────────────────────────────────────────

_PROCEDURAL_MD_PATH = (
    Path(__file__).resolve().parent.parent
    / "docs" / "procedural_anomaly_recipes.md"
)


def _parse_procedural_recipes(md_text: str) -> dict[str, dict[str, Any]]:
    """Return {recipe_id: {section_id, section_title, procedure, tested, script}}.

    Parses markdown table rows of the form
    ``| <recipe_id> | <procedure> | <tested> | <script> |`` that sit under
    ``### <section_id>. <section_title>`` headings. Simple regex-based
    parser; good enough for the Phase 5 tool shape. A future phase can
    replace with a structured YAML/JSON index (the brief's Phase 8 §10.1
    mentions exactly this).
    """
    recipes: dict[str, dict[str, Any]] = {}
    current_section: Optional[tuple[str, str]] = None
    section_re = re.compile(r"^###\s+(\S+?)\.\s+(.*?)$")
    # Row: | <id> | <proc> | <tested> | <script> |
    # id starts with a letter + digits hyphens (e.g. P-A1-1, CP-1)
    row_re = re.compile(
        r"^\|\s*([A-Z]{1,3}-[A-Z0-9\-]+)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*$"
    )
    for line in md_text.splitlines():
        h = section_re.match(line)
        if h:
            current_section = (h.group(1).strip(), h.group(2).strip())
            continue
        row = row_re.match(line)
        if row and current_section is not None:
            recipe_id = row.group(1).strip()
            recipes[recipe_id] = {
                "recipe_id": recipe_id,
                "section_id": current_section[0],
                "section_title": current_section[1],
                "procedure": row.group(2).strip(),
                "tested": row.group(3).strip(),
                "script": row.group(4).strip(),
            }
    return recipes


_PROCEDURAL_CACHE_LOCK = threading.Lock()
_PROCEDURAL_CACHE: Optional[dict[str, dict[str, Any]]] = None


def _load_procedural_recipes() -> dict[str, dict[str, Any]]:
    global _PROCEDURAL_CACHE
    with _PROCEDURAL_CACHE_LOCK:
        if _PROCEDURAL_CACHE is None:
            if _PROCEDURAL_MD_PATH.exists():
                _PROCEDURAL_CACHE = _parse_procedural_recipes(
                    _PROCEDURAL_MD_PATH.read_text(encoding="utf-8")
                )
            else:
                _PROCEDURAL_CACHE = {}
        return dict(_PROCEDURAL_CACHE)


def _reset_procedural_cache_for_testing() -> None:
    global _PROCEDURAL_CACHE
    with _PROCEDURAL_CACHE_LOCK:
        _PROCEDURAL_CACHE = None


@tool(
    "get_procedural_recipe",
    "Look up a procedural recipe by ID (e.g. 'P-A1-1', 'CP-1') from "
    "docs/procedural_anomaly_recipes.md. Returns the structured recipe "
    "(section_id, section_title, procedure, tested, script). Pass "
    "recipe_id='*' to list all known recipe IDs.",
    {"recipe_id": str},
)
async def get_procedural_recipe_tool(args: dict[str, Any]) -> dict[str, Any]:
    recipe_id = args.get("recipe_id", "")
    if not isinstance(recipe_id, str):
        return _text_response(_envelope(
            "error", {"reason": "'recipe_id' must be a string"},
        ))

    recipes = _load_procedural_recipes()
    if not recipes:
        return _text_response(_envelope(
            "error",
            {"reason": "procedural recipe file not found or empty",
             "path": str(_PROCEDURAL_MD_PATH)},
        ))

    if recipe_id == "*":
        return _text_response(_envelope(
            "ok",
            {
                "total": len(recipes),
                "recipe_ids": sorted(recipes.keys()),
            },
        ))

    recipe = recipes.get(recipe_id)
    if recipe is None:
        # Case-insensitive fallback.
        for k, v in recipes.items():
            if k.upper() == recipe_id.upper():
                recipe = v
                break
    if recipe is None:
        return _text_response(_envelope(
            "error",
            {"reason": f"recipe_id {recipe_id!r} not found",
             "available_prefixes": sorted({k[:3] for k in recipes.keys()})},
        ))

    return _text_response(_envelope("ok", recipe))


# ─── 7. enumerate_admissible_transforms ──────────────────────────────────────

@tool(
    "enumerate_admissible_transforms",
    "Return all cipher kinds + alphabets that the dispatcher can currently "
    "translate. Agents call this before specifying a DSL so they bound their "
    "search to kinds that have a kernel translation path. Phase 5 does not "
    "filter by assumption_bundle (Phase 8 extends); the bundle is echoed in "
    "the response for the caller's provenance record.",
    {"assumption_bundle": list},
)
async def enumerate_admissible_transforms_tool(
    args: dict[str, Any],
) -> dict[str, Any]:
    assumption_bundle = args.get("assumption_bundle") or []
    if not isinstance(assumption_bundle, list):
        return _text_response(_envelope(
            "error", {"reason": "'assumption_bundle' must be a list"},
        ))

    # Supported alphabets are a subset of the DSL-valid alphabet set.
    # Phase 4 dispatcher currently only supports AZ for additive ciphers;
    # KA / keyword_mixed fail translation.
    supported_alphabets = ["AZ"]  # Phase 5 limit
    return _text_response(_envelope(
        "ok",
        {
            "supported_kinds": sorted(_SUPPORTED_KINDS),
            "supported_alphabets": supported_alphabets,
            "all_valid_alphabets": sorted(_VALID_ALPHABET_KINDS),
            "unsupported_alphabets": sorted(
                set(_VALID_ALPHABET_KINDS) - set(supported_alphabets)
            ),
        },
        assumption_bundle=assumption_bundle,
        extra_provenance={"filter_by_bundle": False,
                          "note": "bundle filtering is Phase-8 work"},
    ))


# ─── 8. request_compute_budget_estimate ──────────────────────────────────────

# Rough empirical cost per config, measured on the Phase 4 dispatcher
# with AZ Vigenere + score_candidate on 97-char CT.  Real wall-clock
# varies with pipeline complexity but this gives the theorist a signal
# worth iterating on.  Fold in a 2x safety factor.
_EMPIRICAL_SEC_PER_CONFIG_SERIAL = 0.0015
_EMPIRICAL_SAFETY_FACTOR = 2.0


@tool(
    "request_compute_budget_estimate",
    "Given a draft HypothesisSpec, return an estimated wall-clock time on "
    "the 28-core VM. Agents use this to iterate on spec size BEFORE "
    "submission — specs that exceed their declared "
    "compute_budget_cpu_minutes are admissibility-rejected by the "
    "dispatcher, so rightsizing here saves a round trip.",
    {"spec": dict},
)
async def request_compute_budget_estimate_tool(
    args: dict[str, Any],
) -> dict[str, Any]:
    spec_dict = args.get("spec")
    if not isinstance(spec_dict, dict):
        return _text_response(_envelope(
            "error", {"reason": "'spec' must be an object"},
        ))

    parsed = validate_hypothesis_spec(spec_dict)
    if not parsed.is_valid:
        return _text_response(_envelope(
            "error",
            {"reason": "spec validation failed", "errors": parsed.errors},
        ))
    assert parsed.value is not None
    spec = parsed.value

    cardinality = spec.expected_cardinality()
    # Serial estimate × safety factor, then divide by the workers pool.
    serial_sec = cardinality * _EMPIRICAL_SEC_PER_CONFIG_SERIAL * _EMPIRICAL_SAFETY_FACTOR
    workers_default = 26  # cpu_count() - 2 on the 28-core VM
    parallel_sec = serial_sec / workers_default if cardinality > 1 else serial_sec

    return _text_response(_envelope(
        "ok",
        {
            "hypothesis_id": spec.hypothesis_id,
            "spec_hash": spec.spec_hash,
            "expected_cardinality": cardinality,
            "declared_budget_cpu_minutes": spec.compute_budget_cpu_minutes,
            "estimated_serial_sec": round(serial_sec, 3),
            "estimated_parallel_sec_at_26_workers": round(parallel_sec, 3),
            "estimated_parallel_minutes_at_26_workers": round(parallel_sec / 60, 3),
            "under_budget": (
                parallel_sec / 60 <= spec.compute_budget_cpu_minutes
            ),
            "note": (
                "Empirical constant ~0.0015 sec/config + 2x safety factor; "
                "real wall-clock depends on pipeline complexity and kernel "
                "scoring path. Revise manually for non-additive layers."
            ),
        },
        assumption_bundle=spec.assumption_bundle,
        extra_provenance={"spec_hash": spec.spec_hash},
    ))


# ─── MCP server wiring ───────────────────────────────────────────────────────

ALL_TOOLS = [
    submit_hypothesis_spec_tool,
    poll_job_tool,
    query_exhaustion_tool,
    compute_null_baseline_tool,
    score_candidate_canonical_tool,
    get_procedural_recipe_tool,
    enumerate_admissible_transforms_tool,
    request_compute_budget_estimate_tool,
]


def create_dsl_mcp_server() -> dict:
    """Create the MCP server config exposing the 8 DSL tools."""
    return create_sdk_mcp_server(
        name="dsl_tools",
        version="1.0.0",
        tools=ALL_TOOLS,
    )


__all__ = [
    "ALL_TOOLS",
    "create_dsl_mcp_server",
    "submit_hypothesis_spec_tool",
    "poll_job_tool",
    "query_exhaustion_tool",
    "compute_null_baseline_tool",
    "score_candidate_canonical_tool",
    "get_procedural_recipe_tool",
    "enumerate_admissible_transforms_tool",
    "request_compute_budget_estimate_tool",
    # Test hooks:
    "_reset_jobs_for_testing",
    "_reset_procedural_cache_for_testing",
    "_PROCEDURAL_MD_PATH",
    "_PHASE5_NULL_CACHE_PATH",
]
