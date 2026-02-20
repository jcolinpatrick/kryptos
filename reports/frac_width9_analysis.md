# Width-9 Grid Hypothesis — Comprehensive Analysis

**Agent:** frac (FRAC role)
**Date:** 2026-02-19
**Status:** All priority tasks completed + bimodal analysis series (E-FRAC-07 through E-FRAC-11)

## Executive Summary

The width-9 grid hypothesis — that K4's transposition layer uses a 9-column grid (97/9 ≈ 10.78 rows, matching Sanborn's "10.8 rows" annotation) — has been tested exhaustively across multiple substitution models.

**CRITICAL UPDATE (E-FRAC-07/08/09/10/11):** The bimodal fingerprint is likely a **statistical artifact**, not evidence of transposition structure (E-FRAC-11). The "bimodal" pattern (ENE matches better than BC) is caused by crib position ordering: ENE positions come first in the sequence and match 3.5x better than BC under RANDOM permutations with no transposition. Per-position match rates decline MONOTONICALLY from position 21 (100%) to position 73 (11%) — no bimodal structure, just a smooth gradient.

Earlier findings (E-FRAC-07/08) showed NO columnar transposition at ANY width is bimodal-compatible. E-FRAC-09 showed only "patch-based" transpositions (strip manipulation, block swaps) satisfy bimodal. E-FRAC-10 showed strip manipulation with periodic substitution scores within noise. **Given that the bimodal assumption itself is questionable, these compatibility results may be moot.** Columnar transposition should be re-evaluated WITHOUT the bimodal pre-filter.

## Evidence For Width-9

1. **[PUBLIC FACT]** Sanborn's yellow pad annotation appears to read "10.8 rows" → 97/9 = 10.78 ≈ 10.8
2. **[INTERNAL RESULT]** DFT peak at k=9 (period ~10.8, z≈2.83) from E-S-25
3. **[INTERNAL RESULT]** Width-9 naturally creates lag-7 correlations: 99.2% of width-9 orderings reduce lag-7 in the un-transposed text, meaning the observed lag-7 (z=3.04) is consistent with a width-9 transposition artifact (E-FRAC-01)
4. **[DERIVED FACT]** Width-9 grid: columns 0-6 have 11 rows, columns 7-8 have 10 rows

## Experiments Completed

### E-FRAC-01: Structural Analysis
- **Finding:** Width-9 transposition creates lag-7 correlations. 99.2% of orderings reduce the raw lag-7 signal.
- **Finding:** 4,860 orderings pass full Bean constraints under Vigenère (1.34% vs 3.85% random for equality alone)
- **Finding:** CT IC = 0.0361, invariant under permutation
- **Significance:** Strongest structural argument FOR width-9 as the transposition family

### E-FRAC-02: Non-Periodic Substitution Models
- **Models tested:** Progressive key (key[i] = a+bi mod 26), CT-autokey, PT-autokey, column-progressive
- **Configs:** 13,464 Bean-passing orderings (from 362,880 × 3 variants)
- **Best genuine scores:** Progressive 8/24, CT-autokey 6/24, PT-autokey 7/24
- **Column-progressive 20/24:** CONFIRMED as underdetermination artifact (random baseline: mean 17.7, max 21)
- **Verdict:** ELIMINATED — all models within noise

### E-FRAC-03: Non-Columnar Reading Orders
- **Orders tested:** 26 (serpentine, diagonal, spiral, column-major, knight-move + inverses)
- **Best score:** 16/24 (period 13, underdetermination artifact)
- **Noise floor:** Identity permutation scores 16/24 at period 13
- **Verdict:** ELIMINATED — no signal at discriminating periods (≤7)

### E-FRAC-04: Compound w9×w7 Transposition
- **Configs:** 50,500,800 (5,010 w9 × 5,040 w7 × 2 compositions)
- **Best score:** 0/24 above strict-pass threshold at periods 2-7
- **Verdict:** ELIMINATED — zero signal from compound transposition + periodic substitution

### E-FRAC-05: Column-Dependent Mixed Alphabets
- **Finding:** PT-column model — **0/362,880 orderings pass** (hard mathematical elimination)
- **Finding:** CT-column model — 20.7% pass, but random baseline is 12.0% (ratio 1.73x, not compelling)
- **Finding:** All passing orderings have 215/234 degrees of freedom (8.1% determined) — massively underdetermined
- **Verdict:** PT-column ELIMINATED (hard math). CT-column model is noise.

## What Has Been Eliminated

Under width-9 columnar transposition, the following substitution models are **ELIMINATED** for producing cribs:

| Substitution Model | Best Score | Noise Floor | Status |
|---|---|---|---|
| Periodic Vigenère/Beaufort/VB (p=2-14) | 14/24 (p=7) | ~8/24 (p≤7), ~14/24 (p=13) | NOISE (via E-S-133/133b) |
| Progressive key (linear) | 8/24 | ~5-6/24 | NOISE |
| CT-autokey | 6/24 | ~2-3/24 | NOISE |
| PT-autokey | 7/24 | ~2-3/24 | NOISE |
| Column-progressive (linear per column) | 20/24 | 17.7/24 (random mean) | UNDERDETERMINED |
| PT-column mixed alphabets | 0 passes | N/A | HARD ELIMINATION |
| CT-column mixed alphabets | 20.7% pass | 12.0% random | UNDERDETERMINED |
| Non-columnar reading orders + periodic | 16/24 (p=13) | 16/24 (identity at p=13) | ARTIFACT |
| Compound w9×w7 + periodic | 0/24 (p≤7) | N/A | ELIMINATED |

### E-FRAC-07: Bimodal Fingerprint (CRITICAL)
- **Result:** ZERO width-9 columnar orderings satisfy the bimodal fingerprint at ANY tolerance
- **Root cause:** Positions 22-30 span all 9 columns. CT position 22 maps to row 0 of some column (PT 0-8), giving minimum displacement of 14.
- **Implication:** Width-9 columnar is structurally incompatible with the bimodal fingerprint

### E-FRAC-08: Bimodal Fingerprint — ALL Widths (CRITICAL)
- **Result:** ZERO columnar orderings at ANY width (2-20) satisfy the bimodal fingerprint
- **Method:** Exhaustive for w≤10 (up to 3.6M orderings), 100K samples for w>10
- **Implication:** Columnar transposition as a family is structurally incompatible with the bimodal fingerprint. This is not a width-9-specific result — it's a fundamental incompatibility.
- **Significance:** Either the bimodal assumption must be relaxed, or the transposition is not columnar.

### E-FRAC-06: Width-11 and Width-13
- **Result:** Both produce scores identical to random baseline (14/24 max at period 7)
- **Verdict:** NOISE — no evidence for width-11 or width-13

## What Remains Open

1. **Width-9 columnar with non-periodic substitution:** All periodic substitution tests showed noise, but arbitrary (non-periodic, non-autokey) substitution is technically untested. However, the parameter space is too large for direct search.

2. **The bimodal fingerprint is likely an artifact** (E-FRAC-11). The "bimodal" pre-filter should NOT be used to eliminate transposition candidates. This reopens columnar transposition at ALL widths.

3. **Strip manipulation (Sanborn's stated method):** Bimodal-compatible but scores within noise under periodic substitution. Worth testing with non-periodic models.

4. **Width-9 grid with arbitrary key:** No scoring signal found, but 97/9 ≈ 10.78 ≈ Sanborn's "10.8 rows" still has structural appeal.

## Structural Insights

1. **Width-9 creates lag-7:** 99.2% of width-9 orderings reduce lag-7 in un-transposed text. BUT: this is a general property — random permutations and other widths (11, 13) also reduce lag-7 at similar rates. The lag-7 reduction is NOT width-9-specific.

2. **Bimodal incompatibility is the key result:** Width-9 columnar structurally cannot preserve positions 22-30 because they span all 9 columns. This is a hard mathematical elimination.

3. **PT-column mixed alphabets are impossible:** Under any width-9 columnar ordering, crib positions sharing a column produce bijection conflicts. Eliminates "different alphabets per column" hypotheses.

4. **Bean constraint as pruner:** Bean reduces the width-9 ordering space from 362,880 to ~4,860 (Vigenère) or ~3,744 (Beaufort). Combined with CT-column bijection, only 3,293 orderings remain.

## Recommendations

1. **For TRANS agent:** The bimodal pre-filter is likely an artifact (E-FRAC-11) and should NOT be used to eliminate candidates. Columnar transpositions at ALL widths should be re-evaluated without this filter. The bimodal incompatibility (E-FRAC-07/08) is real but irrelevant if bimodal is wrong.

2. **For JTS agent:** The 3,293 orderings passing both Bean and CT-column bijection are the most constrained starting points. Each has 19 known alphabet entries and 215 unknown — still highly underdetermined, but a starting point for SA/hill-climbing.

3. **For FRAC (self):** All priority tasks complete. Consider:
   - Deeper analysis of orderings with highest key IC (possible English running key signal)
   - Width-11 and width-13 grid structural analysis (97 = 11×8+9, 97 = 13×7+6)
   - Testing whether other structural signatures (DFT peaks, digram patterns) differentiate width-9 from random

---
*Generated by agent_frac on 2026-02-19*
