# Preregistration — First clue-bounded solver run against real K4

- **Campaign id:** `f_solver_clue_bounded_real_k4_2026_06_11`
- **Date:** 2026-06-11
- **Git HEAD:** 03d1139 (null caches pinned to HEAD; working tree carries only the
  expected post-rebuild `null_baselines/manifest.json` re-pin + a bench attempt
  file touched by tests — neither affects this run)
- **Runner:** `kryptosbot/solver.py::solve_real_k4(max_rounds=2, max_keywords=12)`
- **Classification:** [INTERNAL RESULT] producer; COMPUTE (small, CPU-only, zero tokens)

## Motivation

`project_controller_solver_gap_2026_05_31` documented that the controller acts as
a disprover (single-point theorist specs) rather than a clue-bounded solver: on
synthetic K4B-001 the in-controller path scored 1/24 while a <400-config
deterministic sweep solved 24/24 blind. The remediation (`solver.py`, bounded
ParamRange sweep authoring, no LLM in the loop) landed but has **never been
pointed at real K4**. This run closes the question: *did the solver-vs-disprover
gap ever cost us a real solve inside the bounded direct-aligned composition
space?*

## Universe (bounded, deterministic)

- Round 0: two-layer transposition+substitution, both orders — **96 specs,
  est. 13,132 configs** (enumerated by dry-run before dispatch).
- Round 1: three-layer (two transpositions + one substitution) — **388 specs,
  est. 237,216 configs**.
- Ingredients: 12 curated keywords (KRYPTOS, PALIMPSEST, ABSCISSA, BERLIN,
  CLOCK, LANGLEY, NORTHEAST, SHADOW, FORCES, LUCID, MEMORY, IQLUSION — all
  attested-content terms per `feedback_k4_keywords_must_fit_public_art_context`),
  6 transposition families × 5 substitution families, alphabets AZ + KA,
  per-spec cardinality cap 2,000.
- **Alignment model: `direct_positional` only** (hardcoded in `_spec()`).
  Assumption bundle: `ct97_direct_positional`, `az_a0`, `no_null_mask`.
  This is the H1 frame; results are H1-conditional, not global K4 facts.

## Pre-registered thresholds and interpretation

- Scoring: canonical kernel `score_candidate` via `job_dispatcher.execute`
  (`crib_plus_bean`); worker self-reports are not trusted (kernel overrule).
- Tiers: standard kernel thresholds (noise ≤9, interesting 10–17, signal ≥18,
  breakthrough 24). Per-spec null baseline: `shuffled_ct`, n=64 (solver gates on
  crib_score, not p-precision).
- **Escalation rule:** any kernel-verified `crib_score ≥ 18` → STOP, fresh-
  interpreter re-verification, matched-variant-family null recalibration, and
  red-team-disprover review before any claim. `BREAKTHROUGH` label is an input
  to validation, not an output (AUDIT-3 doctrine).
- **Expected outcome:** CLEAN_NULL-equivalent (best ≤ 9/24). The direct-aligned
  composition space is heavily eliminated; prior expectation of a hit is
  near-zero. A clean result is itself the deliverable: it certifies the
  solver-gap cost nothing in the direct space.
- Dispatcher admissibility rejections (exhaustion overlap with
  `exhaustion_log.json`) are recorded as informative output, not failures.
- **Kill rule:** no escalation → close as
  `SOLVER_GAP_CONFIRMED_COSTLESS_DIRECT`; the follow-up decision (extend solver
  to `post_transposition`/`free` alignment as separate engineering) is made
  after, not folded into this run.

## Artifacts

- Output dir: `results/solver_real_k4_2026_06_11/`
- Repro: `PYTHONPATH=src venv/bin/python3 results/solver_real_k4_2026_06_11/run_solver.py`
