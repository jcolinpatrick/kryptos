# K4 Agent Team — Progress Tracker
Last updated: 2026-02-19T02:00:00Z by agent_frac

## ALERTS
<!-- Scores ≥18/24 go here. If this section is non-empty, ALL agents should read it. -->
(none)

## Active Tasks
| Agent | Task | Started | Status |
|-------|------|---------|--------|

## Completed (reverse chronological)

### [2026-02-19T01:50Z] agent_frac — E-FRAC-06: Width-11 and Width-13 Structural Analysis
- **Hypothesis:** H6 — Width-11 (97=11×8+9) and width-13 (97=13×7+6) as alternative transposition widths
- **Configs tested:** 50K samples per width × 6 periods × 3 variants × 2 models = ~1.8M per width + 50K random baseline
- **Best score (w11):** 14/24 (period 7, Beaufort, model B)
- **Best score (w13):** 14/24 (period 7, Vigenère, model A)
- **Random baseline:** 14/24 — identical to both widths
- **Strict passes:** 0 for all three (w11, w13, random)
- **Structural:** Both w11 and w13 reduce lag-7 in 100% of orderings (same as random — not width-specific)
- **Verdict:** NOISE — width-11 and width-13 produce identical results to random permutations. Score distributions match within sampling error.
- **Runtime:** 175 seconds
- **Artifacts:** results/frac/e_frac_06_w11w13.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_06_w11w13_structural.py`

### [2026-02-19T01:25Z] agent_frac — E-FRAC-05: Width-9 + Column-Dependent Mixed Alphabets
- **Hypothesis:** H6 — Width-9 columnar transposition with arbitrary column-dependent substitution alphabets (mixed alphabets, not just shifted)
- **Configs tested:** 362,880 orderings, tested under PT-column and CT-column grouping models, + 50,000 random permutation baseline
- **Key findings:**
  - PT-column model: **0/362,880 orderings pass** (minimum 3 bijection conflicts). This is a hard mathematical elimination.
  - CT-column model: 75,071/362,880 (20.7%) pass bijection check. Random baseline: 12.0%. Ratio: 1.73x (not compelling).
  - CT-col + Bean: only 3,293 orderings pass both constraints
  - All passing orderings have DOF=215 (only 19/234 alphabet entries determined = 8.1%) — massively underdetermined
- **Verdict:** PT-column model ELIMINATED (hard math). CT-column model is NOISE (underdetermined, barely above random baseline).
- **Runtime:** 14 seconds + 1 second (baseline)
- **Artifacts:** results/frac/e_frac_05_mixed_alphabets.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_05_mixed_alphabets.py`

### [2026-02-19T00:55Z] agent_frac — E-FRAC-04: Width-9 × Width-7 Compound Transposition
- **Hypothesis:** H12 — Compound transposition (width-9 columnar followed by width-7 columnar, both directions) + periodic substitution
- **Configs tested:** 50,500,800 (5,010 width-9 samples × 5,040 width-7 × 2 compositions)
- **Best score:** 0/24 above threshold (strict periodic check at periods 2-7)
- **Noise floor:** N/A — zero results above strict-pass threshold 12/24
- **Verdict:** ELIMINATED — compound w9×w7 transposition with periodic substitution shows zero signal at discriminating periods (2-7)
- **Runtime:** 384 seconds
- **Artifacts:** results/frac/e_frac_04_compound_w9w7.json
- **Repro:** `PYTHONPATH=src python3 -u jobs/pending/e_frac_04_compound_w9w7.py --workers 3 --n-w9-samples 5000`

### [2026-02-19T00:40Z] agent_frac — E-FRAC-03: Width-9 Non-Columnar Reading Orders
- **Hypothesis:** H7 — Non-standard reading orders on 9-wide grid (serpentine, diagonal, spiral, column-major, knight-move) as transposition mechanism + periodic substitution
- **Configs tested:** 26 reading orders × 6 periods × 3 variants × 2 models = ~936
- **Best score:** 16/24 (row_major, period 13, Beaufort, model A)
- **Noise floor:** Identity permutation scores 16/24 at period 13 — ALL best scores are at period 13-14
- **Verdict:** ELIMINATED — all high scores are underdetermination artifacts at high periods. No signal at discriminating periods (≤7).
- **Runtime:** 0.1 seconds
- **Artifacts:** results/frac/e_frac_03_w9_reading_orders.json
- **Repro:** `PYTHONPATH=src python3 -u jobs/pending/e_frac_03_w9_reading_orders.py`

### [2026-02-19T00:25Z] agent_frac — E-FRAC-02: Width-9 Columnar + Non-Periodic Substitution
- **Hypothesis:** H6 — Width-9 columnar transposition + non-periodic substitution models (progressive key, CT-autokey, PT-autokey, column-progressive)
- **Configs tested:** 13,464 Bean-passing (from 362,880 orderings × 3 variants)
- **Best score:** Progressive: 8/24, CT-autokey: 6/24, PT-autokey: 7/24, Column-progressive: 20/24
- **Noise floor:** Column-progressive noise floor = 17.7/24 (Monte Carlo, N=10,000 random permutations, max observed 21/24). Progressive noise floor ≈ 5-6/24. All observed results within noise.
- **Verdict:** ELIMINATED — column-progressive 20/24 is a confirmed underdetermination artifact (random permutations score 17-21/24). Progressive, CT-autokey, and PT-autokey all within noise.
- **Runtime:** 31 seconds + 29 seconds (baseline)
- **Artifacts:** results/frac/e_frac_02_w9_nonperiodic.json
- **Repro:** `PYTHONPATH=src python3 -u jobs/pending/e_frac_02_w9_nonperiodic.py --workers 3`
- **Baseline repro:** `PYTHONPATH=src python3 -u scripts/e_frac_02b_colprog_baseline.py`

### [2026-02-19T00:00Z] agent_frac — E-FRAC-01: Width-9 Grid Structural Analysis
- **Hypothesis:** H6/H7 — Width-9 grid structural properties as diagnostic for the transposition hypothesis
- **Configs tested:** 362,880 orderings (IC, lag analysis, Bean constraints)
- **Key findings:**
  - 99.2% of width-9 orderings REDUCE lag-7 in un-transposed text → width-9 transposition naturally CREATES lag-7 correlations (consistent with hypothesis)
  - Bean equality passes: 15,120/362,880 (4.17%, above 3.85% random expectation)
  - Bean full passes (eq + all 21 ineq): 4,860/362,880 (1.34%) for Vigenère
  - CT IC = 0.0361 (below random 0.0385), invariant under permutation
  - Lag-7 raw: 9 matches, z=3.04 (significant)
- **Verdict:** STRUCTURAL ANALYSIS — width-9 explains the lag-7 signal, but no scoring-based signal found
- **Runtime:** 67 seconds
- **Artifacts:** results/frac/e_frac_01_w9_structural.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_01_w9_structural.py`
