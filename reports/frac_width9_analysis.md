# Width-9 Grid Hypothesis — Comprehensive Analysis

**Agent:** frac (FRAC role)
**Date:** 2026-02-19
**Status:** Priority tasks 1-4 completed

## Executive Summary

The width-9 grid hypothesis — that K4's transposition layer uses a 9-column grid (97/9 ≈ 10.78 rows, matching Sanborn's "10.8 rows" annotation) — has been tested exhaustively across multiple substitution models. **No discriminating signal was found.** However, the structural analysis shows that width-9 transposition naturally explains the observed lag-7 autocorrelation in the ciphertext, which keeps the hypothesis alive for non-standard substitution models not yet tested.

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

## What Remains Open

1. **Width-9 columnar + running key from UNKNOWN text:** The key IC (mean 0.038) is close to random, meaning the key looks random. An English running key should have IC ≈ 0.067. This argues against English running key, but a non-English or deliberately constructed key is possible.

2. **Width-9 columnar + completely arbitrary key:** By definition, any permutation is "consistent" with an arbitrary key (since any 97 key values can be assigned). The only discriminator is whether the resulting plaintext is meaningful English. This requires attempting to solve the substitution directly, which is the JTS agent's domain.

3. **Width-9 with non-columnar transposition + non-periodic substitution:** Only columnar reading was tested exhaustively. Non-standard transpositions on a 9-wide grid (e.g., physical manipulations of paper strips) combined with non-periodic keys remain untested.

## Structural Insights

1. **Width-9 creates lag-7:** This is the strongest evidence for width-9 as the transposition width. The mechanism: in a width-9 grid, positions separated by 7 in the original text can end up adjacent or periodic after columnar rearrangement, creating apparent lag-7 correlations.

2. **PT-column mixed alphabets are impossible:** Under any width-9 columnar ordering, the crib positions that share a column in the plaintext grid ALWAYS produce bijection conflicts when interpreted as column-dependent substitutions. This rules out a large class of "Sanborn used different alphabets for each column" hypotheses.

3. **Bean constraint as pruner:** Bean reduces the width-9 ordering space from 362,880 to ~4,860 (Vigenère) or ~3,744 (Beaufort). Combined with CT-column bijection, only 3,293 orderings remain. These could be useful starting points for the JTS agent's optimization.

## Recommendations

1. **For TRANS agent:** Width-9 results are available. The lag-7 explanation supports width-9 as a serious candidate. Consider testing width-9 orderings with bimodal pre-filter (positions 22-30 near-identity, 64-74 scattered).

2. **For JTS agent:** The 3,293 orderings passing both Bean and CT-column bijection are the most constrained starting points. Each has 19 known alphabet entries and 215 unknown — still highly underdetermined, but a starting point for SA/hill-climbing.

3. **For FRAC (self):** All priority tasks complete. Consider:
   - Deeper analysis of orderings with highest key IC (possible English running key signal)
   - Width-11 and width-13 grid structural analysis (97 = 11×8+9, 97 = 13×7+6)
   - Testing whether other structural signatures (DFT peaks, digram patterns) differentiate width-9 from random

---
*Generated by agent_frac on 2026-02-19*
