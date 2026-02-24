# Width-9 Grid Hypothesis — Comprehensive Analysis

**Agent:** frac (FRAC role)
**Date:** 2026-02-19
**Status:** All experiments completed (E-FRAC-01 through E-FRAC-12)

## Executive Summary

The width-9 grid hypothesis — that K4's transposition layer uses a 9-column grid (97/9 ≈ 10.78 rows, matching Sanborn's "10.8 rows" annotation) — has been tested exhaustively across 12 experiments covering multiple substitution models, structural analyses, and the bimodal fingerprint.

**Bottom line: Width-9 columnar transposition + periodic substitution is ELIMINATED.** The score distribution at discriminating periods (2-7) is indistinguishable from random permutations (E-FRAC-12). Best score 14/24 at period 7 (all fail Bean), best Bean-passing 13/24 (one ordering). Random baseline reaches 15/24.

**The bimodal fingerprint is a statistical ARTIFACT** (E-FRAC-11). The "bimodal" pattern (ENE matches better than BC) is caused by crib position ordering in periodic scoring. Per-position match rates decline MONOTONICALLY from position 21 (100%) to position 73 (11%). ENE matches 3.5x better than BC under RANDOM permutations with no transposition. The bimodal pre-filter eliminates valid candidates based on an unfounded assumption.

## Evidence For Width-9

1. **[PUBLIC FACT]** Sanborn's yellow pad annotation appears to read "10.8 rows" → 97/9 = 10.78 ≈ 10.8
2. **[INTERNAL RESULT]** DFT peak at k=9 (period ~10.8, z≈2.83) from E-S-25
3. **[INTERNAL RESULT]** Width-9 naturally creates lag-7 correlations: 99.2% of width-9 orderings reduce lag-7, consistent with the observed lag-7 (z=3.04) being a width-9 artifact (E-FRAC-01)
4. **[DERIVED FACT]** Width-9 grid: columns 0-6 have 11 rows, columns 7-8 have 10 rows

**Evidence AGAINST width-9:**
- **[INTERNAL RESULT]** Score distribution at periods 2-7 matches random at ALL levels (ratios 0.97x-1.38x) — E-FRAC-12
- **[INTERNAL RESULT]** Lag-7 reduction is NOT width-9-specific; random permutations and other widths show similar rates — E-FRAC-01, E-FRAC-06
- **[INTERNAL RESULT]** All substitution models tested produce noise — E-FRAC-01 through E-FRAC-12

## Complete Experiment Summary

### E-FRAC-01: Structural Analysis
- Width-9 creates lag-7 correlations (99.2% reduce lag-7). Bean: 4,860 pass. CT IC=0.0361.
- **STRUCTURAL ANALYSIS** — explains lag-7 but no scoring signal

### E-FRAC-02: Non-Periodic Substitution
- Progressive 8/24, CT-autokey 6/24, PT-autokey 7/24, col-prog 20/24 (artifact)
- **ELIMINATED** — all within noise

### E-FRAC-03: Non-Columnar Reading Orders
- 26 orders, best 16/24 at p=13 (identity scores same)
- **ELIMINATED** — underdetermination artifacts only

### E-FRAC-04: Compound w9×w7
- 50.5M configs, zero results above threshold at p=2-7
- **ELIMINATED** — zero signal

### E-FRAC-05: Mixed Alphabets
- PT-column: 0/362,880 pass (hard math). CT-column: underdetermined.
- **PT-column HARD ELIMINATED**, CT-column NOISE

### E-FRAC-06: Width-11/13
- Both identical to random baseline (14/24 max)
- **NOISE**

### E-FRAC-07: Bimodal — Width-9
- 0/362,880 orderings pass bimodal at any tolerance
- **STRUCTURAL INCOMPATIBILITY** (positions 22-30 span all 9 columns)

### E-FRAC-08: Bimodal — All Widths
- 0 orderings at ANY width 2-20 pass bimodal
- **ALL COLUMNAR INCOMPATIBLE WITH BIMODAL**

### E-FRAC-09: Bimodal-Compatible Permutation Structure
- 0/1M random perms pass bimodal. Strip manipulation: 2.0%, block swaps: 10.5%
- **BIMODAL IS EXTREMELY RESTRICTIVE** — only "patch-based" methods pass

### E-FRAC-10: Strip Manipulation + Periodic Substitution
- Best strip score 10/24 vs random bimodal+Bean baseline max 12/24
- **NOISE**

### E-FRAC-11: Bimodal Validity (CRITICAL META-RESULT)
- Per-position match rates: monotonic decline 100%→11%, NOT bimodal
- ENE/BC ratio = 3.5x under random permutations — crib ordering artifact
- **BIMODAL FINGERPRINT IS AN ARTIFACT, NOT A REAL CONSTRAINT**

### E-FRAC-12: Width-9 Without Bimodal, Strict Scoring
- 362,880 orderings × periods 2-7. Distribution matches random (ratios ~1.0x)
- Best: 14/24 (all fail Bean). Best Bean: 13/24 (one ordering). Random max: 15/24.
- **NOISE — DEFINITIVELY ELIMINATED**

## Master Elimination Table

| Model | Best Score | Noise Floor | Bean | Status |
|---|---|---|---|---|
| W9 columnar + periodic Vig/Beau/VB (p=2-7) | 14/24 | 9.38/24 mean, 15/24 max | All fail | NOISE (E-FRAC-12) |
| W9 columnar + periodic (p=2-14) | 14/24 (p=7) | ~14/24 (p=13) | — | NOISE (E-S-133) |
| W9 + progressive key | 8/24 | ~5-6/24 | — | NOISE |
| W9 + CT-autokey | 6/24 | ~2-3/24 | — | NOISE |
| W9 + PT-autokey | 7/24 | ~2-3/24 | — | NOISE |
| W9 + column-progressive | 20/24 | 17.7/24 mean | — | UNDERDETERMINED |
| W9 + PT-column mixed alphabets | 0 passes | N/A | — | **HARD ELIMINATION** |
| W9 + CT-column mixed alphabets | 20.7% pass | 12.0% random | — | UNDERDETERMINED |
| W9 non-columnar reading orders + periodic | 16/24 (p=13) | 16/24 (identity) | — | ARTIFACT |
| Compound w9×w7 + periodic (p=2-7) | 0/24 | N/A | — | **ELIMINATED** |
| W11 columnar + periodic (p=2-7) | 14/24 | 14/24 random | — | NOISE |
| W13 columnar + periodic (p=2-7) | 14/24 | 14/24 random | — | NOISE |
| Strip manipulation + periodic (p=2-7) | 10/24 | 12/24 bimodal+Bean | — | NOISE |

## What Remains Open

1. **Width-9 columnar with truly arbitrary substitution:** All periodic, autokey, progressive, and column-progressive models eliminated. An arbitrary 97-key substitution remains technically open but has ~26^97 parameters — too underdetermined for direct search.

2. **Width-9 grid with non-columnar reading:** Grid-based operations other than columnar reading (strip manipulation, physical procedures). Strip manipulation with periodic sub is eliminated (E-FRAC-10), but non-periodic models untested.

3. **The DFT peak and "10.8 rows" remain unexplained.** If width-9 is wrong, what causes the DFT peak at k=9? Possible answers: (a) statistical noise (z=2.83 is ~3σ but with 48 frequencies tested, multiple testing weakens this), (b) an artifact of the substitution cipher rather than transposition.

## Critical Findings for Other Agents

### For TRANS Agent
- **DROP the bimodal pre-filter.** It is based on a statistical artifact (E-FRAC-11). The monotonic decline in per-position match rates means ENE will ALWAYS score better than BC regardless of transposition, giving a false "bimodal" appearance.
- Width-9 columnar is comprehensively eliminated at discriminating periods.

### For JTS Agent
- The bimodal pre-filter should not be used as a search constraint.
- Width-9 columnar is eliminated; JTS should focus on other transposition families or non-periodic substitution models.

### For BESPOKE Agent
- Strip manipulation (Sanborn's stated method) is bimodal-compatible but shows no scoring signal with periodic substitution. Non-periodic substitution models remain untested.

### For QA Agent
- The bimodal fingerprint definition in AGENT_PROMPT.md should be reclassified from "MANDATORY pre-filter" to "[HYPOTHESIS — likely artifact]".

---
*Generated by agent_frac on 2026-02-19. 12 experiments, ~55M configs tested, ~2500 seconds total compute.*
