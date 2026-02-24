# Post-FRAC Synthesis: What Remains Viable for K4

**Author:** agent_tableau (TABLEAU role)
**Date:** 2026-02-20
**Context:** FRAC completed 48 experiments, TABLEAU completed 20 experiments. This report synthesizes all findings into a unified picture of what has been eliminated and what remains viable.

---

## 1. The Elimination Landscape (2026-02-20)

### What is DEFINITIVELY eliminated (Tier 1 proofs + exhaustive search):

| Hypothesis | Why Dead | Evidence |
|-----------|----------|----------|
| Pure transposition (no substitution) | CT has 2 E's, PT needs 3 | Mathematical proof |
| Periodic polyalphabetic (any variant, any period, direct correspondence) | Algebraic impossibility | Tier 1 proof |
| Periodic key + ANY transposition at periods 2-7, 9-12, 14, 15, 17, 18, 21, 22, 25 | Bean inequality structural violation | E-FRAC-35 (universal proof for all 97! permutations) |
| Columnar transposition widths 5-15 + periodic sub | Exhaustive search: all NOISE or ANTI-correlated | E-FRAC-12/29/30 |
| Width-5 and width-7 columnar | Bean-IMPOSSIBLE (zero orderings pass) | E-FRAC-26/27 |
| Hill 2×2/3×3/4×4 | Algebraic proof + 97 is prime (no divisor > 1) | Tier 1 + structural |
| ALL fractionation (Bifid, Trifid, ADFGVX, Playfair, etc.) | Structural proofs (parity, alphabet, IC) | E-FRAC-21 |
| Autokey (PT/CT × Vig/Beau) + arbitrary transposition | Cannot reach 24/24 (PT max=16, CT max=21) | E-FRAC-37 |
| Progressive key + any transposition | Bean-eliminated (only δ∈{0,13}, both trivial) | E-FRAC-38 |
| Quadratic key + any transposition | Bean-eliminated (0/676 survive) | E-FRAC-38 |
| Fibonacci key + any transposition | Bean-eliminated (0/676 survive) | E-FRAC-38 |
| Non-standard tableau usage (column reads, rotations, paths, physical keys) | All produce noise at crib positions | E-TABLEAU-01 to 08 |
| Kryptos tableau as key generator | No path explains observed keystream | E-TABLEAU-03/04/06 |
| Misspelling-derived keywords (QUAY, EQUAL) | All at noise | E-TABLEAU-08 |
| Affine substitution (a≠1) | Zero power beyond Vigenère | E-TABLEAU-18 |
| Cross-alphabet Quagmire (KA×STD, STD×KA) | Noise | E-TABLEAU-19 |
| K3-method with thematic keywords at Bean-surviving periods | All 25 keywords produce 4-8/24 (below noise 14/24) | E-TABLEAU-20 |
| Double columnar (Bean-compatible width pairs) | 2.96M compositions, noise | E-FRAC-46 |
| Myszkowski transposition (widths 5-13) | 226K patterns, noise | E-FRAC-47 |
| AMSCO/Nihilist/Swapped columnar (widths 5-13) | Bean-incompatible at w8-13, noise at w5-8 | E-FRAC-48 |
| Simple transpositions (cyclic, affine, rail fence, reversal, single swaps) | All BELOW random baseline | E-FRAC-32 |

### What is statistically discredited:

| Claimed Signal | Actual Status | Evidence |
|---------------|---------------|----------|
| K4's IC = 0.036 is "unusual" | 21.5th percentile of random (NOT significant) | E-FRAC-13 |
| Lag-7 autocorrelation | Fails Bonferroni correction (p=0.0077, needs p<0.001) | E-FRAC-14 |
| DFT peak at k=9 | Below 95th percentile of random maximum | E-FRAC-14 |
| "English-like" pre-ENE IC | Bonferroni p=1.0 | E-FRAC-19 |
| Beaufort key low entropy | Selection effect (Vigenère key unremarkable) | E-FRAC-25 |
| Bimodal fingerprint | Statistical artifact from crib ordering | E-FRAC-11 |

**Conclusion: K4's ciphertext is statistically consistent with random text of length 97. There is NO statistical evidence for any specific transposition width, periodicity, or cipher variant.**

---

## 2. What Survives

### 2.1 Viable key models (after Bean filtering):

| Model | Status | Notes |
|-------|--------|-------|
| Running key from unknown text | **OPEN** | Only structured model surviving Bean (E-FRAC-38). But running key + transposition is MASSIVELY underdetermined (E-FRAC-39). |
| Periodic key at periods {8, 13, 16, 19, 20, 23, 24, 26} | **OPEN but underdetermined** | Period 8 has 3 cribs/variable (barely constraining). Hill-climbing trivially reaches false 24/24+Bean at all surviving periods (E-FRAC-36). |
| Non-periodic, non-structured key (bespoke) | **OPEN** | No algebraic structure — cannot be tested systematically without a model. |
| Position-dependent alphabets | **OPEN** | Essentially equivalent to running key or bespoke key. |

### 2.2 Viable transposition models:

| Model | Status | Notes |
|-------|--------|-------|
| Structured families at Bean-surviving periods | **OPEN but unpromising** | All tested structured families (columnar w5-15, Myszkowski, AMSCO, double columnar, simple families) produce NOISE. |
| Bespoke physical transposition (S-curve, strip manipulation) | **OPEN** | Cannot be enumerated without creative hypothesis. BESPOKE agent territory. |
| No transposition (identity) | **OPEN** | If key is non-periodic, direct correspondence is viable. But all tested key models under direct correspondence are eliminated. |

### 2.3 Viable overall models:

1. **Running key from unknown text + structured transposition** — The key text is unknown, and the transposition must be from a structured family (arbitrary permutations are underdetermined per E-FRAC-44). JTS territory.

2. **Running key from unknown text + NO transposition** — Possible if the key text is specifically chosen to produce the observed keystream. Requires identifying the key text.

3. **Bespoke physical/procedural cipher** — "Not a math solution" (Sanborn). A method that doesn't fit standard cryptographic categories. BESPOKE territory.

4. **Something not yet conceived** — The possibility that K4 uses a cipher structure outside our current hypothesis taxonomy.

---

## 3. Key Structural Insights

### 3.1 Information-theoretic underdetermination (E-FRAC-44)

- **505 bits** needed to identify 1 of 97! permutations
- **367 bits** available from cribs (113) + Bean (6) + English (248)
- **138-bit deficit** → ~2^138 permutations satisfy ALL known constraints
- Structured families (columnar: 2^18.5 options) make the oracle sufficient
- Arbitrary permutations (2^505 options) guarantee false positives

### 3.2 The K3→K4 transition

- K3: Columnar(KRYPTOS, w7) → Vigenère(PALIMPSEST, p10)
- K3 was "solved the wrong way" (Scheidt) — frequency analysis instead of intended method
- K4 has an "intentional change in methodology" (Scheidt: difficulty 9/10)
- KRYPTOS (p7) and PALIMPSEST (p10) are both Bean-eliminated periods
- ABSCISSA (p8) is Bean-surviving but produces noise at all widths (E-TABLEAU-20)
- The "change" is likely fundamental: different cipher TYPE, not just different parameters

### 3.3 Scheidt's "instructions in earlier text"

- **LAYER TWO** (K2 ending): confirmed instruction for compound encipherment
- **Coordinates (38°57'6.5"N, 77°8'44"W)**: Numeric values from K2; could encode parameters but all obvious derivations produce Bean-eliminated periods
- **"T IS YOUR POSITION"** (Morse code): Possible cipher start position or tableau column indicator
- **K3 final "Q"**: Standalone letter, possibly a cipher indicator (Q=16, or "question")
- **No other clear operational instructions found** beyond LAYER TWO

### 3.4 Hill cipher structural elimination (new finding)

K4 has length 97, which is prime. Hill n×n cipher requires text length divisible by n. Since 97 is prime, only n=1 (monoalphabetic, trivially eliminated) and n=97 (absurdly complex) divide evenly. Hill cipher at any practical block size is **structurally incompatible** with K4's prime length.

---

## 4. Recommendations for Other Agents

### For JTS:
1. **Running key from Carter/reference texts + structured transposition** at Bean-surviving periods (8, 13). Use multi-objective oracle: crib=24 + Bean + quadgram > -5.0 + non-crib words ≥7 chars ≥ 3.
2. **Keyword search for 8-letter keywords** (period 8 is the ONLY Bean-surviving discriminating-ish period with 3 cribs/var). Exhaustive search over common English 8-letter words at width-8 columnar.
3. **Accept underdetermination**: Any 24/24+Bean solution requires human semantic evaluation. No automated metric provides perfect discrimination (E-FRAC-41-43).

### For BESPOKE:
1. **Focus on physical/procedural methods** that Sanborn (a sculptor, not a cryptographer) could execute by hand.
2. **Encoding charts** — Sanborn released K1/K2/K3 encoding charts with visual clues (arrows, rotations). These may specify the method.
3. **"Not a math solution"** — Consider non-cryptographic approaches: steganography, visual alignment, physical overlay.
4. **Strip manipulation** on the physical sculpture.

### For TRANS:
1. **All standard columnar/structured transpositions are DEAD.** Do not re-test.
2. **If continuing, focus on non-standard transpositions** not yet tested (geometric, physically-derived).
3. **Consider that there may be NO transposition** — the cipher might be pure substitution with a very long, non-periodic key.

### For QA:
1. **Validate E-TABLEAU-20** — quick repro: `PYTHONPATH=src python3 -u scripts/e_tableau_20_k3method_keywords.py`
2. **Update elimination tiers** to reflect TABLEAU E-TABLEAU-20 (thematic keywords eliminated).

---

## 5. TABLEAU Agent Status

**E-TABLEAU-01 through E-TABLEAU-20: COMPLETE.**

All investigation threads in the TABLEAU mandate have been exhaustively explored:
- Non-standard tableau access: ELIMINATED
- K1-K3 as instructions: LAYER TWO confirmed, no other instructions found
- Position-dependent alphabets: Equivalent to running key; tested and found noise
- Misspelling chain: ELIMINATED
- K3-method variants at Bean-surviving periods: ELIMINATED (E-TABLEAU-20)

**Agent YIELDED.** No further experiments within TABLEAU's hypothesis space appear viable unless new external information becomes available (e.g., decoded encoding charts, new Sanborn statements, or findings from other agents that reopen TABLEAU hypotheses).

---

*Repro commands for all TABLEAU experiments: results stored in `results/tableau/e_tableau_*.json`*
*Prior experiments (E-TABLEAU-01 to 19) were run in earlier sessions; results preserved in gitignored results/ directory.*
