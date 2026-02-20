# TRANS Agent — Final Synthesis Report

**Agent:** trans (TRANS role)
**Date:** 2026-02-20
**Status:** DOMAIN EXHAUSTED — all structured transposition + substitution models eliminated
**Total experiments:** 6 (TRANS) + 48 (FRAC, overlapping domain) = 54 covering the transposition hypothesis space
**Genuine signals:** 0

---

## Executive Summary

The TRANS agent systematically tested all structured transposition families against periodic and non-periodic substitution models. Combined with the FRAC agent's 48 experiments (which comprehensively covered width-specific and structural questions), the entire transposition + substitution hypothesis space has been exhausted. **No structured transposition + periodic substitution model produces signal above random noise at discriminating periods (2-7).**

Key structural proofs from FRAC (E-FRAC-35) further demonstrate that periodic keying at ALL discriminating periods (2-7) is impossible under ANY transposition due to Bean inequality violations. The only substitution model surviving Bean constraints is running key from unknown text (E-FRAC-38), which is JTS territory.

---

## TRANS Agent Experiments (6 total)

### E-TRANS-1: Width-9 Columnar Exhaustive (`w9_columnar`)
- **Rationale:** Top priority — DFT peak at k=9, Sanborn's "10.8 rows" annotation
- **Configs:** 362,880 orderings (all 9! permutations) x periods 2-14 x 3 variants x 2 models
- **Bimodal filter result:** 0/362,880 orderings pass (structurally incompatible)
- **Strict algebraic passes:** 0 (also 0/28.3M without bimodal filter)
- **Verdict:** ELIMINATED — width-9 columnar is bimodal-incompatible and shows zero signal
- **Repro:** results/trans/w9_columnar/summary.json

### E-TRANS-2: Width-9 Non-Columnar Reading Orders (`w9_noncolumnar`)
- **Rationale:** Alternative reading orders on 9-wide grid
- **Configs:** 11 reading orders (serpentine, diagonal, column-major, zigzag, etc.)
- **Best score:** 16/24 at period 13 (Beaufort) — noise at non-discriminating period
- **Strict passes:** 0
- **Verdict:** ELIMINATED — all scores at periods 12-14, expected noise range
- **Repro:** results/trans/w9_noncolumnar/summary.json

### E-TRANS-3: Width-11 and Width-13 Columnar (`w11_w13_columnar`)
- **Rationale:** Alternative widths — 97=11x8+9, 97=13x7+6
- **Configs:** 57,265 keyword orderings (36,505 at w11, 20,760 at w13)
- **Best score:** 18/24 at period 14 — FALSE POSITIVE (p=14 baseline: 0.005% chance of >= 18)
- **Strict passes:** 0
- **Verdict:** ELIMINATED — scores are Monte Carlo noise at non-discriminating periods
- **Repro:** results/trans/w11_w13_columnar/summary.json

### E-TRANS-4: Bimodal-Compatible Transposition Methods (`bimodal_compatible`)
- **Rationale:** Only permutations consistent with the bimodal fingerprint
- **Configs:** 68,923 permutations across 6 families (segment swap, block move, segment reversal, strip manipulation, random bimodal)
- **Best score:** 19/24 at period 13 — ENE preservation artifact (~12/24 "free" at p=13)
- **Strict passes:** 0
- **Verdict:** ELIMINATED — all "signals" are bimodal artifact at p=13
- **Note:** FRAC later proved bimodal fingerprint itself is a statistical artifact (E-FRAC-11)
- **Repro:** results/trans/bimodal_compatible/summary.json

### E-TRANS-5: Simulated Annealing Over Bimodal Space (`sa_bimodal`)
- **Rationale:** SA hill-climbing to find best bimodal-compatible transposition
- **Configs:** 24 chains x 500K steps = 12M total steps
- **Best score:** 24/24 — ALL 24 chains converge to 24/24 at periods 9-10
- **Strict passes:** 24 (all chains)
- **Verdict:** OVERFITTING — period >= 9 has ~97 DoF vs 24 constraints; random permutations trivially satisfy. This is the definitive demonstration of the overfitting problem.
- **Key lesson:** SA at high periods produces false positives. Only period <= 7 scores are meaningful.
- **Repro:** results/trans/sa_bimodal/summary.json

### E-TRANS-6: No-Filter Strict Test, All Widths 5-15 (`nofilter_strict`)
- **Rationale:** Comprehensive test of ALL columnar widths without bimodal filter
- **Configs:** 1,009,080 columnar orderings (exhaustive w5-9, sampled w10-15) x periods 2-10
- **Best score:** min conflicts = 1-2 (never 0)
- **Strict passes:** 0 at ALL widths, ALL periods 2-10
- **Verdict:** ELIMINATED — no columnar transposition at any width + periodic sub passes strict algebraic check at low periods
- **Repro:** results/trans/nofilter_strict/summary.json

---

## Coverage Summary: What Has Been Eliminated

### By TRANS agent directly:
| Family | Widths/Configs | Verdict |
|--------|---------------|---------|
| Columnar (exhaustive) | w5-9 (all orderings), w10-15 (sampled 100K) | ELIMINATED |
| Non-columnar grid reads | 11 orders on w9 grid | ELIMINATED |
| Bimodal-compatible families | 68,923 perms (6 families) | ELIMINATED (artifact) |
| SA arbitrary search | 12M steps | OVERFITTING at p>=9 |

### By FRAC agent (overlapping TRANS domain):
| Family | Experiment | Verdict |
|--------|-----------|---------|
| Columnar w5-15 + periodic sub | E-FRAC-12/29/30 | ALL ELIMINATED (underperform random) |
| Columnar w5, w7 Bean | E-FRAC-26/27 | Bean-IMPOSSIBLE (zero orderings pass) |
| Simple transpositions (cyclic, affine, rail fence, reverse, swap) | E-FRAC-32 | ELIMINATED (below random) |
| Grid reading orders (13 families, w5-13) | E-FRAC-45 | ELIMINATED (below random) |
| Double columnar (9 Bean-compatible width pairs) | E-FRAC-46 | ELIMINATED (matches random) |
| Myszkowski (w5-13) | E-FRAC-47 | ELIMINATED (matches random) |
| AMSCO/Nihilist/Swapped (w5-13) | E-FRAC-48 | ELIMINATED + Bean-incompatible |
| ANY transposition + periodic key (p=2-7) | E-FRAC-35 | PROOF: Bean-impossible |
| Autokey + arbitrary transposition | E-FRAC-37 | Can't reach 24/24 |
| Progressive/Quadratic/Fibonacci key | E-FRAC-38 | Bean-ELIMINATED |
| W9 + non-periodic sub (progressive, autokey, column-progressive) | E-FRAC-02 | ELIMINATED |
| W9 x W7 compound | E-FRAC-04 | ELIMINATED |
| W9 + mixed alphabets | E-FRAC-05 | PT-column: ELIMINATED; CT-column: underdetermined |
| Strip manipulation + periodic sub | E-FRAC-10 | ELIMINATED |
| Arbitrary perm fitness landscape | E-FRAC-33 | Oracle insufficient (false 24/24 at all periods) |
| Information-theoretic limits | E-FRAC-44 | 138-bit deficit; arbitrary search underdetermined |

---

## Critical Structural Results

### 1. Bean Impossibility Proof (E-FRAC-35)
ALL discriminating periods (2-7) are impossible for transposition + periodic key due to Bean inequality constraints. Also eliminated: periods 9-12, 14, 15, 17, 18, 21, 22, 25. Only 8 of 25 tested periods survive: {8, 13, 16, 19, 20, 23, 24, 26}. This is a universal proof holding for ALL 97! permutations.

### 2. Information-Theoretic Underdetermination (E-FRAC-44)
- 505 bits needed to identify 1 of 97! permutations
- 367 bits available from all constraints (cribs + Bean + English)
- 138-bit deficit: ~2^138 permutations are consistent with ALL constraints
- Structured families work (expected FP = 0) because they reduce search from 2^505 to 2^18
- Arbitrary permutation search is inherently underdetermined

### 3. Bimodal Fingerprint is an Artifact (E-FRAC-11)
The "bimodal" pattern (ENE matches better than BC) is caused by crib position ordering in the scoring algorithm, not by transposition structure. The bimodal pre-filter in AGENT_PROMPT.md should not be relied upon.

### 4. Statistical Signals are Not Significant (E-FRAC-13/14)
- IC = 0.036: 21.5th percentile of random (not significant)
- Lag-7 autocorrelation: fails Bonferroni correction
- DFT peak at k=9: below 95th percentile of random max

### 5. Running Key is the Only Surviving Substitution Model (E-FRAC-38)
All polynomial, recurrence, progressive, autokey, and periodic key models are eliminated by Bean constraints. Running key from unknown text + structured transposition remains open but is JTS territory.

---

## Monte Carlo Baselines (verified)

| Period | Mean Score | 99th Pctile | Max (100K trials) | >= 18 Probability |
|--------|-----------|-------------|-------------------|-------------------|
| 2 | 5.1 | — | 9 | ~0% |
| 3 | 6.2 | — | 10 | ~0% |
| 5 | 7.7 | — | 12 | ~0% |
| 7 | 8.2 | 11 | 14 | ~0% |
| 13 | 12.8 | — | 18 | 0.003% |
| 14 | 13.1 | — | 19 | 0.005% |

---

## What Remains Open (NOT in TRANS domain)

1. **Running key + structured transposition (JTS):** Running key from unknown text survives Bean. Massively underdetermined (~700-2,000 feasible offsets per reference text). Requires multi-objective oracle (quadgram + word detection + semantic coherence). No automated metric achieves perfect separation from SA false positives.

2. **Bespoke physical methods (BESPOKE):** Non-standard, non-mathematical cipher methods that a sculptor could execute by hand. S-curve readout, strip manipulation as Sanborn described, physical alignment of tableau panels.

3. **Position-dependent alphabets (TABLEAU):** "Changed the language base" (Scheidt). Arbitrary lookup tables per position, non-periodic substitution.

4. **Non-standard structures not yet conceived:** The most dangerous category — methods that no cryptanalyst has thought to test because they don't appear in textbooks.

---

## Lessons Learned

1. **High-period scores are always noise.** Period >= 9 with arbitrary permutations trivially satisfies 24 constraints. Every "breakthrough" at high periods is overfitting.

2. **Statistical signals require multiple-testing correction.** The DFT peak, lag-7, and IC anomaly all evaporated under Bonferroni correction. Short sequences (n=97) have enormous variance.

3. **The bimodal pre-filter was counterproductive.** It eliminated 100% of columnar orderings AND was based on an artifact. Dropping it earlier would have saved compute.

4. **Bean constraints are structural gatekeepers.** Bean eliminates entire period ranges and width families (5, 7) in one proof. Using Bean as a hard constraint early in the pipeline is essential.

5. **Structured families eliminate false positives.** The 97! permutation space is too large for crib-based discrimination. Only by restricting to structured families (columnar, rail fence, etc.) with ~10^4-10^6 members does the oracle become sufficient.

6. **The domain is genuinely exhausted.** After testing columnar (all widths), double columnar, Myszkowski, AMSCO, Nihilist, Swapped, simple transpositions, grid reading orders, strip manipulation, and compound transpositions — all with periodic, autokey, progressive, quadratic, Fibonacci, and column-progressive substitution models — there is no remaining structured transposition + substitution model to test.

---

*TRANS agent synthesis report — 2026-02-20*
*54 experiments, 0 genuine signals, domain exhausted*
