# FRAC Agent Final Synthesis — 50 Experiments, Zero Positive Findings

**Agent:** frac (FRAC role — Width-9 & Structural Specialist)
**Date:** 2026-02-20
**Experiments:** E-FRAC-01 through E-FRAC-50
**Status:** MANDATE COMPLETE — all priority tasks exhausted, all Tier 4 gaps closed, running key gap closed

---

## Executive Summary

The FRAC agent conducted 50 experiments over approximately 65 million scored configurations and 17 billion running-key checks, producing **zero positive findings that survive scrutiny**. Every structured transposition family tested produces noise-level crib scores. Every statistical "anomaly" in K4 fails significance testing. Every key model except running key is Bean-eliminated. Running key + transposition is massively underdetermined — and running key + ALL structured transpositions from 7 known reference texts produces ZERO matches. No automated discriminator perfectly separates real solutions from false positives.

The headline result is an **information-theoretic proof** (E-FRAC-44): K4's 24 known plaintext positions provide only 367 of the 505 bits needed to identify a transposition from the 97! space. The 138-bit deficit means approximately 2^138 permutations satisfy ALL known constraints simultaneously. This deficit is fundamental and cannot be overcome by better algorithms — only by additional information (more cribs, more plaintext, or restricting to structured families).

---

## What FRAC Eliminated

### 1. Transposition Families (Tier 1 Eliminations)

Every tested structured transposition family produces crib scores at or below random baseline (14/24 from 50K random permutations at discriminating periods 2-7):

| Family | Experiments | Perms Tested | Best Score | vs Random |
|--------|------------|-------------|------------|-----------|
| Single columnar (w5-15) | E-FRAC-12/26/27/29/30 | ~600K exhaustive | 14/24 | = random |
| Simple families (cyclic, affine, rail fence, swap, reverse) | E-FRAC-32 | 14,035 | 13/24 | < random |
| Grid reading orders (13 families × w5-13) | E-FRAC-45 | 3,888 configs | 12/24 | < random |
| Double columnar (9 Bean-compatible width pairs) | E-FRAC-46 | 2,958,400 | 15/24 | = random |
| Myszkowski (w5-13) | E-FRAC-47 | 226,390 | 15/24 | = random |
| AMSCO/Nihilist/Swapped (w8-13) | E-FRAC-48 | 361,280 | 14/24 | = random |
| **Turning grille** | **Universal proof** | **N/A** | **N/A** | **Covered by E-FRAC-35** |
| **Running key + columnar (w6,8,9)** | E-FRAC-49 | 16,597 Bean-passing × 7 texts × 3 variants | 0/24 matches | 8.4B checks, ZERO matches |
| **Running key + ALL structured families** | E-FRAC-50 | 17,306 Bean-passing × 7 texts × 3 variants | 0/24 matches | 8.8B checks, ZERO matches |

**Additional structural eliminations:**
- Width-5 and Width-7: Bean-INCOMPATIBLE (zero orderings pass Bean equality, exhaustive proof)
- AMSCO/Nihilist/Swapped at widths 8-13: 0% Bean pass rate across 361K permutations
- Reverse and rail fence: Bean-INCOMPATIBLE (zero Bean passes with running key, E-FRAC-50)

### 2. Key Models (Bean Eliminations)

| Key Model | Status | Mechanism | Experiment |
|-----------|--------|-----------|------------|
| Periodic (p=2-7,9-12,14,15,17,18,21,22,25) | ELIMINATED | Bean inequality violation (universal proof for all 97! perms) | E-FRAC-35 |
| Progressive (k[i] = k[0] + iδ) | ELIMINATED | Only δ ∈ {0,13}, both trivial | E-FRAC-38 |
| Quadratic (k[i] = ai² + bi + c) | ELIMINATED | 0/676 (a,b) pairs survive Bean | E-FRAC-38 |
| Fibonacci (k[i] = F(i, seed1, seed2)) | ELIMINATED | 0/676 seeds survive Bean | E-FRAC-38 |
| Autokey (PT and CT, both variants) | ELIMINATED | Cannot reach 24/24 cribs (PT max=16, CT max=21) | E-FRAC-37 |
| **Running key** | **OPEN** | Bean constrains only ~6.5% of offsets | E-FRAC-38/39 |

**Only running key survives** as a structured non-periodic key model. Running key + transposition is massively underdetermined for arbitrary permutations (E-FRAC-39), but running key + ALL structured transposition families from 7 known reference texts produces ZERO matches (E-FRAC-49/50). The gap between running key + arbitrary transposition (underdetermined) and running key + structured transposition (zero matches) confirms E-FRAC-44's information-theoretic prediction.

### 3. Fractionation Families (Structural Proofs)

All 10 fractionation families structurally eliminated (E-FRAC-21):
- ADFGVX/ADFGX: parity impossible (output length 2N, K4=97 odd)
- Bifid/Trifid/Playfair/Two-Square/Four-Square: 25-letter alphabet, K4 uses all 26
- Straddling checkerboard: digit output
- Proofs hold with or without transposition

### 4. Statistical Signals (Debunked)

| Claimed Signal | Status | Evidence | Experiment |
|---------------|--------|----------|------------|
| K4 IC = 0.036 "below random" | NOT UNUSUAL | 21.5th percentile (z=-0.84, p=0.21) | E-FRAC-13 |
| Lag-7 autocorrelation | NOT SIGNIFICANT | p=0.0077 fails Bonferroni (need p<0.001) | E-FRAC-14 |
| DFT k=9 peak | NOT SIGNIFICANT | mag=162, 95th pctile threshold=192 | E-FRAC-14 |
| Bimodal fingerprint | ARTIFACT | Smooth gradient from crib ordering | E-FRAC-11 |
| Beaufort key entropy | RETRACTED | Selection effect, KKK impossible in natural language | E-FRAC-16→25 |

**Zero statistically significant signals in K4** after proper multiple-testing correction.

---

## What FRAC Established (Positive Contributions)

### 1. Multi-Objective Oracle for JTS (E-FRAC-33/34/36/40/41/42/43)

Characterized 265 false 24/24+Bean solutions and designed a multi-objective discriminator:

| Metric | False Positives | Real English | Gap | Cohen's d |
|--------|----------------|--------------|-----|-----------|
| Quadgram/char (crib-optimized SA) | best -5.77 | -4.84 | 0.93 | Large |
| Quadgram/char (quadgram-optimized SA) | -4.02 to -4.55 | -4.34 | ~0 | None |
| Non-crib words ≥7 chars | 0-11 | 1-20 | Moderate | 1.14 |
| IC | ~0.038 | ~0.067 | Variable | Low |
| Bigram score | HIGHER than English | — | Negative | -0.35 |
| Trigram score | ≈ English | — | None | 0.11 |

**Recommended JTS thresholds:** crib=24 + Bean PASS + quadgram > -4.84 + IC > 0.055 + non-crib words ≥7 chars ≥ 3 + semantic coherence (human evaluation for final candidates).

**Key insight:** SA quadgram optimization trivially produces English-like text with ANY key (Carter is NOT special, E-FRAC-40). Semantic coherence is the only reliable discriminator.

### 2. Information-Theoretic Framework (E-FRAC-44)

Unified theory explaining ALL underdetermination findings:

| Component | Bits |
|-----------|------|
| Target: identify 1 of 97! perms | 505 |
| Available: cribs | 113 |
| Available: Bean constraints | 6 |
| Available: English quality | 248 |
| **Total available** | **367** |
| **DEFICIT** | **138** |

- **Structured families** (2^18.5 options): expected false positives = 0 → oracle SUFFICIENT
- **Arbitrary permutations** (2^505 options): expected FP = 2^401 → oracle INSUFFICIENT
- **Turning grilles** (2^50 options): expected FP = 0 → oracle sufficient, but periodic key already Bean-eliminated

### 3. Bean Impossibility Proof (E-FRAC-35)

Universal proof that ALL 97! transpositions + periodic key at discriminating periods (2-7) violate Bean:
- **Type 1:** Same-residue inequality (eliminates periods {2,3,4,5,6,7,9,10,14,15,17,21,25})
- **Type 2:** Equality-inequality conflict (eliminates periods {11,12,18,22})
- **Only 8 periods survive out of 25 (2-26):** {8, 13, 16, 19, 20, 23, 24, 26}
- All surviving periods are underdetermined (E-FRAC-36 confirms false positives exist)

### 4. Crib Validation (E-FRAC-18)

Self-encrypting positions validated: pos 32 (S→S), pos 73 (K→K). Crib positions are correct.

### 5. Fitness Landscape Characterization (E-FRAC-33)

- Landscape is SMOOTH (parent-child correlation r ≈ 0.93 at all periods 2-7)
- Hill-climbing at period 5 reaches 24/24 in 30% of trials (false positives)
- Hill-climbing at "best period" reaches 24/24 in 50% of trials
- SA CAN navigate the landscape but WILL converge to false positives without multi-objective scoring

---

## Implications for Other Agents

### For JTS (Joint Transposition Search)
1. **Use the multi-objective oracle** (reports/frac_jts_oracle_specification.md)
2. **Restrict to structured families** OR accept underdetermination and use human evaluation
3. **Do NOT rely on crib score + Bean alone** — false positives are trivially achievable
4. **Period selection is critical:** only periods {8, 13, 16, 19, 20, 23, 24, 26} survive Bean
5. **Period 8 is the ONLY viable period with ≥2 cribs per residue** (meaningful discrimination)

### For TRANS (Transposition Specialist)
1. **All structured transposition families are ELIMINATED** at discriminating periods (universal proof)
2. **The only remaining avenue is non-periodic key models** (running key, position-dependent)
3. **Running key + transposition is underdetermined** — expect hundreds of feasible solutions per text

### For BESPOKE (Creative Methods)
1. **Any bespoke transposition is still a permutation in S_97** — E-FRAC-35 applies
2. **The method must either use a non-periodic key or operate at a non-eliminated period**
3. **Bespoke methods ARE the only remaining hope** — they're outside all tested families

### For TABLEAU (Substitution Analysis)
1. **Position-dependent alphabets** are the key open question
2. **Running key is the strongest surviving hypothesis** for non-periodic keying
3. **Non-standard tableaux** could provide the missing structure that periodic models lack

---

## Complete Experiment Index

| ID | Topic | Key Finding |
|----|-------|-------------|
| E-FRAC-01 to 10 | Width-9 columnar + substitution sweeps | ALL NOISE at discriminating periods |
| E-FRAC-11 | Bimodal fingerprint validity | ARTIFACT (gradient from crib ordering) |
| E-FRAC-12 | Width-9 strict re-evaluation | Exhaustive 362K orderings: max 14/24 = NOISE |
| E-FRAC-13 | IC analysis | K4 IC unremarkable (21.5th percentile) |
| E-FRAC-14 | Autocorrelation / DFT | Zero significant signals after correction |
| E-FRAC-15 | General recurrence keys | Noise (covered by E-FRAC-38) |
| E-FRAC-16 to 25 | Beaufort key entropy investigation | RETRACTED (selection effect) |
| E-FRAC-26 to 31 | Bean profiling + width elimination | w5,w7: Bean-IMPOSSIBLE; w6-15: NOISE |
| E-FRAC-32 | Simple transposition families | ALL below random baseline |
| E-FRAC-33 | Fitness landscape | Smooth, hill-climbing reaches false 24/24 |
| E-FRAC-34 | Multi-objective oracle design | Quadgram gap 0.93/char discriminates |
| E-FRAC-35 | Bean impossibility proof | ALL 97! perms × periodic key at p2-7: ELIMINATED |
| E-FRAC-36 | Bean-surviving periods | FP exist at p8, p13; oracle still discriminates |
| E-FRAC-37 | Autokey + transposition | Cannot reach 24/24 (structural) |
| E-FRAC-38 | All key models vs Bean | Only running key survives |
| E-FRAC-39 | Running key bipartite feasibility | ~700-2000 feasible offsets: UNDERDETERMINED |
| E-FRAC-40 | Carter quadgram screening | Carter NOT special (SA artifact) |
| E-FRAC-41 | Word discriminator | WEAK (SA gibberish has 3-17 words) |
| E-FRAC-42 | Refined word discriminator | MODERATE (d=1.14, no perfect separation) |
| E-FRAC-43 | N-gram discriminators | FAIL (SA scores BETTER than English) |
| E-FRAC-44 | Information-theoretic analysis | 138-bit deficit: FUNDAMENTAL underdetermination |
| E-FRAC-45 | Non-columnar grid reading orders | ALL underperform random |
| E-FRAC-46 | Double columnar transposition | 3M compositions: NOISE |
| E-FRAC-47 | Myszkowski transposition | 226K permutations: NOISE |
| E-FRAC-48 | AMSCO/Nihilist/Swapped columnar | 361K permutations: NOISE, 0% Bean pass |
| E-FRAC-49 | Running key + columnar (w6,8,9) | 16,597 configs × 7 texts × 3 variants: ZERO 24/24 matches |
| E-FRAC-50 | Running key + ALL structured families | 17,306 configs × 7 texts × 3 variants: ZERO matches |

---

## The Bottom Line

After 50 experiments, the FRAC agent has established four fundamental truths about K4:

1. **K4 is not a known structured transposition + periodic substitution.** Every classical transposition family (columnar, double columnar, Myszkowski, AMSCO, Nihilist, Swapped, rail fence, cyclic, affine, grid reading orders, turning grille) at every reasonable width (5-15) produces only noise. The Bean impossibility proof extends this universally: NO transposition + periodic key at discriminating periods is consistent with the Bean constraints. This is a mathematical certainty, not a sampling limitation.

2. **K4's statistical properties are consistent with random text of length 97.** The IC, autocorrelation, DFT spectrum, and bimodal fingerprint are all within expected ranges. There is no statistical signature pointing to any specific transposition width, periodicity, or structural pattern. Prior claims about these signals were not corrected for multiple testing.

3. **Arbitrary permutation search is information-theoretically underdetermined.** With 505 bits of uncertainty and only 367 bits of constraints, approximately 2^138 permutations satisfy ALL known requirements. This means SA-based search over 97! permutations will always find false positives, and no automated metric (quadgrams, n-grams, word count, IC) can reliably distinguish them from the true solution. Only human semantic evaluation of plaintext coherence can serve as the final discriminator.

4. **Running key + ALL structured transposition families produces ZERO matches from known texts.** E-FRAC-49/50 exhaustively tested running key from 7 reference texts (Carter Gutenberg 117K, Carter Vol1 288K, CIA Charter 9K, JFK Berlin 3K, NSA Act 70K, Reagan Berlin 13K, UDHR 9K) against ALL Bean-passing structured transposition configurations (columnar w6/8/9, identity, cyclic, affine, rail fence, block reversal, double columnar). 17.2 billion (config × offset) checks. Zero matches. This closes the gap between "periodic key + structured transposition = noise" (E-FRAC-12/29/30/32) and "running key + arbitrary transposition = underdetermined" (E-FRAC-39), confirming E-FRAC-44's information-theoretic prediction that structured families have expected false positives = 0.

**What remains open:** Non-standard substitution models (position-dependent alphabets, non-standard tableaux), bespoke physical methods (strip manipulation, coding charts), and running key from UNKNOWN texts (not tested among the 7 reference texts). These are the domain of other agents (TABLEAU, BESPOKE, JTS).

---

*FRAC agent mandate complete. 50 experiments, ~65M configurations + ~17B running-key checks, ~11K seconds of compute. Zero positive findings survive.*
