# K4 Agent Team — Progress Tracker
Last updated: 2026-02-19T06:00:00Z by agent_frac

## ALERTS
<!-- Scores ≥18/24 go here. If this section is non-empty, ALL agents should read it. -->

### [2026-02-19T03:20Z] agent_frac — BIMODAL FINGERPRINT IS LIKELY AN ARTIFACT (E-FRAC-11)
**ALL AGENTS READ THIS.** The bimodal fingerprint pre-filter (MANDATORY in AGENT_PROMPT.md) is likely based on a statistical artifact, NOT evidence of transposition structure.

**Evidence:**
1. Per-position crib match rates decline MONOTONICALLY from position 21 (100%) to position 73 (11%) under random permutations. There is no "bimodal" pattern — just a smooth gradient caused by crib ordering.
2. ENE (positions 21-33) matches 3.5x better than BC (positions 63-73) under RANDOM permutations with NO transposition. This is because ENE positions come first and are more likely to be "first assignments" in periodic scoring.
3. 0/500,000 random permutations pass the bimodal check — the constraint is too restrictive.
4. ALL high-scoring random permutations show ENE >> BC regardless of transposition structure.

**Implication:** The bimodal pre-filter eliminates valid candidates based on an unfounded assumption. Agents should consider dropping or relaxing this filter.
**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_11_bimodal_validity.py`
**Artifacts:** results/frac/e_frac_11_bimodal_validity.json

### [2026-02-19T05:00Z] agent_frac — STATISTICAL SIGNALS ARE WEAKER THAN CLAIMED (E-FRAC-13/14)
**ALL AGENTS READ THIS.** Three pillars of the width-9 / structural hypotheses are statistically weak:

1. **K4's IC = 0.036 is NOT unusual.** It's at the 21.5th percentile of random 97-char text (z=-0.84, p=0.21). The "below-random IC" claim is not meaningful at n=97. IC does NOT constrain the cipher family.

2. **Lag-7 autocorrelation does NOT survive Bonferroni correction.** p=0.0077 uncorrected, but with 48 lags tested, the corrected threshold is p<0.001. After correction, ZERO lags are significant. The lag-7 signal is expected to appear at SOME lag by chance.

3. **DFT peak at k=9 is NOT significant.** Magnitude = 162, but the 95th percentile of the maximum random peak is 192. The k=9 peak doesn't even reach the 95th percentile, let alone 99th. Zero DFT peaks are significant.

**Implication:** There is NO strong statistical evidence for any specific transposition width, periodicity, or structural pattern in K4. The CT is statistically consistent with random text of length 97. Previous claims about DFT peaks and lag-7 as evidence for width-9 should be RETRACTED.

**Additional finding:** Bifid 6×6 on English plaintext produces IC ≈ 0.059-0.069 at ALL periods, far above K4's 0.036. K4 is at the 0th percentile. **Bifid is IC-incompatible with K4**, with or without transposition.

**Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_13_ic_analysis.py && PYTHONPATH=src python3 -u scripts/e_frac_14_autocorrelation.py`

## Active Tasks
| Agent | Task | Started | Status |
|-------|------|---------|--------|

## Completed (reverse chronological)

### [2026-02-19T05:55Z] agent_frac — E-FRAC-16: Key Value Distribution Analysis
- **Hypothesis:** Does the Beaufort or Vigenere key distribution show significant structure at crib positions?
- **Key findings:**
  - Beaufort key entropy at **0.3rd percentile** of random (p=0.003, p_adj≈0.018 after correction). **HIGHLY CONCENTRATED.**
  - Beaufort key value K(=10) at 5/24 positions (p=0.05): positions 28, 30, 31, 32, 70
  - Three consecutive K's at positions 30-31-32 (p=0.03)
  - Self-encrypting position 32 (S) has Beaufort key = K (first letter of KRYPTOS)
  - Vigenere key entropy at 16.1th percentile — unremarkable
- **Verdict:** The Beaufort key is significantly more concentrated than random. Weak evidence for Beaufort as the cipher variant.
- **Caveat:** Assumes direct correspondence. If transposition exists, this finding may not hold.
- **Runtime:** 15 seconds
- **Artifacts:** results/frac/e_frac_16_key_distribution.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_16_key_distribution.py`
- **Full meta-analysis:** `reports/frac_statistical_meta_analysis.md`

### [2026-02-19T05:25Z] agent_frac — E-FRAC-15: Functional Key Models (Linear, Quadratic, Exponential, Recurrence)
- **Hypothesis:** Is K4's key a simple mathematical function of position?
- **Models tested:** 676 linear (k=ai+b), 17,576 quadratic (k=ai²+bi+c), 600 exponential (k=a·b^i), 676 Fibonacci, 43,264 generalized recurrence — all × Vig/Beau/VB
- **Best scores:** Linear 7/24 (k=4i+20 Vig, ~3σ above best-of-676 random baseline 4.9±0.7), Quadratic 8/24, Exponential <6, Fibonacci <6, Gen. recurrence <8
- **None produce readable plaintext.** Random 3-letter words ("WAY", "ALL") appear by chance.
- **Verdict:** NOISE — the key is NOT a polynomial, exponential, or recurrence function of position
- **Runtime:** 6 seconds
- **Artifacts:** results/frac/e_frac_15_linear_key.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_15_linear_key.py`

### [2026-02-19T04:50Z] agent_frac — E-FRAC-14: Autocorrelation Deep Dive & Statistical Fingerprint (CRITICAL META-RESULT)
- **Hypothesis:** Is K4's lag-7 autocorrelation significant? What other statistical signals exist?
- **Key findings:**
  - Lag-7 has 9 matches (p=0.0077 uncorrected) but does NOT survive Bonferroni correction (48 lags tested, threshold p<0.001)
  - ZERO lags significant after Bonferroni
  - DFT: ZERO peaks exceed 95th percentile of random max (k=9 magnitude=162, threshold=192)
  - Lag-7 positions: [0, 7, 12, 15, 32, 45, 65, 76, 86]; 3 involve cribs
  - 10 repeated bigrams (z=+1.73 vs random, not significant); 0 repeated trigrams
  - First-order differences are UNIFORM (chi2=25.3, p>0.05)
  - Best linear key fit: k=4i+20 matches 7/24 (~3σ above best-of-676 baseline)
  - Best quadratic fit: 8/24 (same as linear + noise floor effect)
  - Beaufort key: positions 29-31 all have value 10 (K) — noteworthy but not conclusive
  - Almost any columnar width (5-10) reduces lag-7; not specific to width-9
- **Verdict:** K4 is statistically consistent with RANDOM TEXT. No significant autocorrelation, DFT, or ngram signals after proper multiple-testing correction.
- **Runtime:** 506 seconds
- **Artifacts:** results/frac/e_frac_14_autocorrelation.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_14_autocorrelation.py`

### [2026-02-19T04:30Z] agent_frac — E-FRAC-13: IC Statistical Analysis (CRITICAL META-RESULT)
- **Hypothesis:** Is K4's below-random IC (0.036) statistically significant? Does it constrain the cipher family?
- **Key findings:**
  - K4 IC = 0.036 is at 21.5th percentile of random text (z=-0.84). NOT significant.
  - Pre-ENE segment (pos 0-20) IC = 0.067 at 97.6th percentile — marginally interesting but not significant after multiple testing (5 segments tested, Bonferroni p≈0.12)
  - Periodic Vigenere at period 5-7: K4 at 2-4th percentile (marginally consistent)
  - Running key / long-period polyalphabetic: K4 at 22nd percentile (perfectly consistent)
  - **Bifid 6×6 is IC-INCOMPATIBLE**: mean IC 0.059-0.069 at ALL periods on English text, K4 at 0th percentile
  - Bifid 5×5: mean IC 0.045, K4 at ~1st percentile (also structurally impossible — 26 letters)
  - K4 letter frequencies NOT different from uniform (chi2=19.1, p>0.05)
  - Transposition preserves IC exactly (verified 10K samples)
- **Verdict:** IC is NOT diagnostic — does not constrain cipher family. Bifid 6×6 is IC-eliminated.
- **Runtime:** 77 seconds
- **Artifacts:** results/frac/e_frac_13_ic_analysis.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_13_ic_analysis.py`

### [2026-02-19T03:40Z] agent_frac — E-FRAC-12: Width-9 Strict Re-evaluation (No Bimodal, Periods 2-7)
- **Hypothesis:** Does width-9 columnar show signal at discriminating periods when bimodal filter is dropped?
- **Configs tested:** 362,880 orderings × 3 variants × 2 models × periods 2-7 (exhaustive)
- **Best score:** 14/24 (20 orderings, all at period 7, ALL fail Bean)
- **Best Bean-passing:** 13/24 (one ordering: [2,0,6,4,1,3,7,5,8], p7 Beaufort model B)
- **Random baseline (N=100K):** max=15/24, mean=9.38, 99.9th=12
- **Distribution comparison:** Width-9 score distribution matches random at ALL levels (ratios 0.97x-1.38x). No structural enhancement.
- **Verdict:** NOISE — width-9 columnar is indistinguishable from random at discriminating periods, even without the bimodal filter.
- **Runtime:** 934 seconds
- **Artifacts:** results/frac/e_frac_12_w9_strict_reeval.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_12_w9_strict_reeval.py`

### [2026-02-19T03:15Z] agent_frac — E-FRAC-11: Bimodal Fingerprint Validity Analysis (CRITICAL)
- **Hypothesis:** Is the bimodal fingerprint a real cryptanalytic constraint or a statistical artifact?
- **Result:** **ARTIFACT.** The "bimodal" pattern (ENE matches better than BC) is caused by crib position ordering in the scoring algorithm. Position 21 matches 100% of the time (first assignment), declining monotonically to position 73 (11%). No bimodal structure — just a smooth gradient.
- **Key finding:** ENE/BC ratio = 3.5x under RANDOM permutations with no transposition. The bimodal pre-filter is filtering out valid candidates based on an unfounded assumption.
- **Additional:** Shifted BC cribs (±1, ±2) show slightly different scores but nothing conclusive about crib indexing errors.
- **Runtime:** 188 seconds
- **Artifacts:** results/frac/e_frac_11_bimodal_validity.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_11_bimodal_validity.py`

### [2026-02-19T03:00Z] agent_frac — E-FRAC-10: Strip Manipulation + Periodic Substitution
- **Hypothesis:** Strip manipulation (bimodal-compatible) + periodic substitution at discriminating periods (2-7)
- **Configs tested:** ~1.8M strip configs across widths 5-20, filtered by bimodal + Bean
- **Best score:** 10/24 (strip width 11, period 7, Beaufort model A)
- **Noise floor:** Random bimodal+Bean baseline: max 12/24, mean 8.3/24
- **Verdict:** NOISE — best strip score within random baseline
- **Runtime:** 60 seconds
- **Artifacts:** results/frac/e_frac_10_strip_bimodal.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_10_strip_bimodal.py`

### [2026-02-19T02:50Z] agent_frac — E-FRAC-09: Structural Characterization of Bimodal-Compatible Permutations
- **Hypothesis:** What kinds of permutations satisfy the bimodal fingerprint? (Guides TRANS/BESPOKE search)
- **Key findings:**
  - 0/1M random permutations pass bimodal — extremely restrictive
  - Strip manipulation passes at 2.0% rate (strip width 11 best at 5.5%)
  - Block swaps pass at 10.5% (swapping blocks in BC region)
  - Local swaps (50 swaps, dist≤5) pass at 4.8%
  - Rail fence, route ciphers, columnar: ALL fail bimodal
- **Verdict:** If bimodal is valid (now questionable per E-FRAC-11), only "patch-based" transpositions are compatible
- **Runtime:** 151 seconds
- **Artifacts:** results/frac/e_frac_09_bimodal_structure.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_09_bimodal_structure.py`

### [2026-02-19T02:45Z] agent_frac — E-FRAC-08: Bimodal Fingerprint Across ALL Widths (CRITICAL)
- **Hypothesis:** H6/H7 — Is ANY columnar transposition width (2-20) compatible with the bimodal fingerprint?
- **Result:** **ZERO widths have ANY compatible columnar orderings.** Exhaustive for w≤10, 100K samples for w>10.
- **Widths tested exhaustively (0 pass):** w=2 (2), w=3 (6), w=4 (24), w=5 (120), w=6 (720), w=7 (5,040), w=8 (40,320), w=9 (362,880), w=10 (3,628,800)
- **Widths sampled (0/100K pass):** w=11 through w=20
- **Implication:** **Columnar transposition at ANY width is structurally incompatible with the bimodal fingerprint.** This is a fundamental result: either (1) the bimodal fingerprint assumption is wrong, or (2) the transposition is not columnar at any width, or (3) the transposition doesn't preserve position-displacement relationships in the expected way.
- **Key distinction:** This eliminates standard columnar transposition. Non-columnar transpositions (route ciphers, grilles, strip methods) remain open.
- **Runtime:** 44 seconds
- **Artifacts:** results/frac/e_frac_08_bimodal_multiwidth.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_08_bimodal_multiwidth.py`

### [2026-02-19T02:15Z] agent_frac — E-FRAC-07: Width-9 Bimodal Fingerprint (CRITICAL)
- **Hypothesis:** H6 — Is width-9 columnar transposition compatible with the bimodal fingerprint constraint?
- **Result:** **ZERO orderings pass at ANY tolerance level** (tested up to ENE≤10, BC≤6)
- **Root cause:** Positions 22-30 span all 9 columns of the width-9 grid. After columnar transposition, CT position 22 always maps to row 0 of some column (PT position 0-8), giving minimum displacement |perm[22]-22| = 14, far exceeding the ±5 tolerance.
- **Implication:** **Width-9 columnar transposition is structurally incompatible with the bimodal fingerprint.** If the bimodal fingerprint is correct (a separate question), width-9 columnar is eliminated as a candidate.
- **Note:** This does NOT eliminate non-columnar width-9 transpositions (e.g., strip manipulation on a 9-wide grid). It specifically eliminates the columnar reading order model.
- **Runtime:** 35 seconds
- **Artifacts:** results/frac/e_frac_07_bimodal.json
- **Repro:** `PYTHONPATH=src python3 -u scripts/e_frac_07_bimodal_w9.py`

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
