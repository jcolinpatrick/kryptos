# FINAL — First clue-bounded solver run against real K4

- **Campaign:** `f_solver_clue_bounded_real_k4_2026_06_11`
- **Prereg:** `docs/campaigns/solver_clue_bounded_real_k4_2026_06_11.md` (written before dispatch)
- **Verdict:** `SOLVER_GAP_CONFIRMED_COSTLESS_DIRECT` (pre-registered kill rule; no escalation)
- **Date:** 2026-06-11 · Git HEAD at run: 03d1139

## Result [INTERNAL RESULT]

`solve_real_k4(max_rounds=2, max_keywords=12)` — deterministic bounded sweep,
no LLM in the loop, kernel-verified scoring via `job_dispatcher.execute`:

| round | specs | configs | best crib |
|-------|-------|---------|-----------|
| 0 (two-layer) | 96 | 13,132 | 7/24 |
| 1 (three-layer) | 388 | 237,216 | 7/24 |

- **Best: 7/24** (`solver-route_diagonal-beaufort-az-transfirst`,
  diagonal route w=10 + Beaufort keyword KRYPTOS, AZ), `bean_passed=false`,
  ngram −6.34/char (random floor), classification `challenge_crib_mismatch`.
- 7/24 equals the random ceiling observed in the 50-cycle controller run
  (`project_final_k4_goal_session_2026_06_06`). Escalation threshold (≥18)
  not approached. Wall time 1.96 s (kernel fast path, 250,348 configs).

## Interpretation (scope-explicit)

- The 2026-05-31 solver-vs-disprover gap (K4B-001: 1/24 in-controller vs 24/24
  by a <400-config dev sweep) **did not cost a real-K4 solve in the
  direct-aligned bounded composition space**. The capability gap was real on
  synthetic challenges; on real K4 the direct space simply contains no solve
  at this depth — consistent with all prior Bean-based eliminations.
- **H1-conditional.** This certifies nothing about `post_transposition`,
  `free`, `arbitrary_null_mask`, or `joint_mask_mechanism` alignment models,
  which remain the open frontier.
- Repro: `PYTHONPATH=src venv/bin/python3 results/solver_real_k4_2026_06_11/run_solver.py`

## Follow-up decision (made after close, per prereg)

Extending the solver to `post_transposition`/`free` alignment is a separate
engineering item; the open free-alignment cells are named in
`docs/campaigns/free_alignment_classical_2026_06_10.md` §"Scope NOT closed"
(key_tape inners under free alignment, quagmire_iv / KA-layer quagmire,
≥3-layer pipelines, sub-then-trans crib-scattering).
