# FINAL — Solver multi-layer free-alignment sweep

- **Campaign:** `f_solver_free_alignment_2026_06_11`
- **Prereg:** `docs/campaigns/solver_free_alignment_2026_06_11.md` (frozen before dispatch)
- **Verdict:** `CLEAN_NULL` (pre-registered rule: zero configs ≥ 11)
- **Date:** 2026-06-11 · Git HEAD at run: f98ce14

## Result [INTERNAL RESULT]

484 specs / **250,348 configs** (exact expected cardinality — complete
coverage), real-K4 dispatcher path, kernel-verified `score_candidate_free`
(`scoring_mode="free"`), 81 s wall:

- **Best free crib score: 0 / 24 everywhere.** Neither EASTNORTHEAST nor
  BERLINCLOCK appears as a contiguous substring in ANY two- or three-layer
  solver-universe decrypt of the carved CT (6 transposition × 5 substitution
  families, 12 attested keywords, AZ/KA, both/all decrypt orders).
- Zero hits ≥ 11; expected hits under H0 ≈ 6.0e-9 — observed 0, consistent.
- Zero admissibility rejections (B-3 alignment-scoped gate, no override used).
- Controls all passed pre-arm: C0 known-answer gate 3/3 (20k cycles),
  C1 kernel displaced-crib free 24/24, C2 worker-path synthetic free 24/24
  (`scoring_mode="free"`, non-canonical), C3 zoo F9 standing (suites green).
- Universe SHA-256 `468923810eab9775…`; summary: `summary.json`; per-spec
  artifacts: `jobs/` (484 JSONs, gitignored).

## Scope

CLOSES (exactly): the "right multi-layer composition, displaced cribs" escape
hatch over the solver's 484-spec universe — two-layer
{columnar, rail_fence, reverse_blocks, route_boustrophedon, route_diagonal,
skip_route} × {vigenere, beaufort, variant_beaufort, atbash, caesar} (both
orders) and three-layer (two distinct transpositions + substitution,
sub-outer/sub-mid) over the 12 listed keywords, default parameter ranges.
This extends the 2026-06-10 free-alignment closure (single-layer + two-layer
columnar×additive) into the multi-layer cell its §6 named as NOT closed —
within this bounded universe.

DOES NOT CLOSE: PT length ≠ 97; keywords outside the 12; parameters outside
solver default ranges; ≥4 layers; sub-innermost three-layer order; key_tape /
running-key / quagmire inners under free; non-contiguous crib dispersal;
fragment-level presence (<11). H1-independent: Bean N/A by construction
(free); no Bean elimination cited or extended.

## Toolchain delta (durable)

`kryptosbot/solver.py` now threads `crib_alignment` ∈ {direct_positional,
free} through spec construction (`build_sweep_specs(..., crib_alignment=)`,
`solve_real_k4(crib_alignment=)`); free specs dispatch via the real-K4 path
(the challenge branch has no free matcher — guarded, fails loudly on
non-kernel CT). post_transposition deliberately excluded (identical anchored
crib_score to direct after pipeline undo; only the Bean frame would differ).
TDD: `kryptosbot/tests/test_solver_alignment.py` (10 tests).

Repro: `PYTHONPATH=src venv/bin/python3 -u scripts/campaigns/f_solver_free_alignment_2026_06_11.py`
