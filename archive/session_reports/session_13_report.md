# Session 13 Report: Manifold SA, AMSCO, Lag-7 Constraints

**Date**: 2026-02-18 (continued from Session 12)
**Focus**: SA on valid manifold, AMSCO/disrupted transpositions, lag-7 constrained SA, thematic keys

---

## Completed Experiments

### E-S-19: Double Columnar Transposition — COMPLETE
- **Result**: Best 16/24 at (7,7) B_beau period 7
- **Detail**: ALL 16/24 hits share the same o1=[5,2,3,1,4,0,6] — this is an algebraic pocket, not signal
- **Total**: 34.6M permutation pairs × periods 3-8 × 4 variants
- **Verdict**: **NOISE** (16/24 < 18/24 signal threshold, concentrated on single o1)
- **Artifact**: `results/e_s_19_double_columnar.json`

### E-S-08: SA Perm + Quadgram — COMPLETE
- **Result**: 15/24 at period 7, key=[2,3,3,2,1,2,2]
- **PT**: "BYTHEARITWINESSPERAGMEASYWORTHESS..." — English fragments from SA optimization
- **Verdict**: **NOISE** (consistent with extreme-value for 100 SA restarts)
- **Artifact**: `results/e_s_08_sa_quadgram.json`

### E-S-22: AMSCO + Disrupted Columnar — COMPLETE
- **Families**: AMSCO (1-2 cell alternating), Nihilist, Swapped columnar
- **Widths**: 5-8 (9+ skipped — too many permutations for exhaustive)
- **Result**: Best 15/24 (Swapped w=8, B_beau, p=8); Period 7 best < 14
- **Verdict**: **NOISE** — no AMSCO/Nihilist/Swapped config produces signal at period 7
- **Artifact**: `results/e_s_22_amsco_disrupted.json`

### E-S-24: Thematic Key Derivation — COMPLETE
- **Keys**: 153 candidates from 2025 clues (dates, places, people, phrases, coordinates, combinations)
- **Result**: 0/24 across 29K configs at identity transposition
- **Verdict**: **NOISE** — confirms multi-layer structure required (no thematic key works alone)
- **Artifact**: `results/e_s_24_thematic_keys.json`

---

## Running Experiments

### E-S-21: SA on 24/24 Crib-Consistent Manifold
- **Status**: Period 7 vig/beau done, period 5 vig/beau done, period 6 vig running (15/50)
- **Key finding**: qg/c ≈ -3.77 to -3.83 (BETTER than English -4.285) with 24/24 cribs
- **Confirms**: E-S-20 underdetermination — 73 free positions trivially achieve English-like quadgram scores
- **PT examples**: "OCRATICATERTHERIANSPREASTNORTHEASTENESSA..." — artificial English fragments, not coherent text
- **Bean pass rate**: 0% across all restarts
- **Implication**: Quadgram fitness alone CANNOT discriminate real solutions from noise

### E-S-23: Lag-7 Constrained SA
- **Status**: Weight=0 vig done, weight=5 vig running (6/30)
- **Key finding**: At weight=5, SA achieves **lag7=8-9/9** while maintaining qg/c ≈ -3.8 to -3.9
- **Interpretation**: Lag-7 preservation is COMPATIBLE with English-like quadgrams
- **This means**: The lag-7 signal does NOT conflict with period-7 Vigenère + transposition
- **Open question**: Does coherent English emerge at high lag-7 weights? (test ongoing)
- **Configs**: weight ∈ {0, 5, 20, 50} × {vig, beau} × period 7

### E-S-11: Running Key + Columnar Transposition
- **Status**: Width 7 complete (11/24), width 8 running
- **9 texts**: K1-K3 PT, CIA charter, JFK/Reagan speeches, UDHR, NSA Act
- **Verdict so far**: NOISE (11/24 best, at width 7)

---

## Strategic Analysis

### The Underdetermination Wall (from Session 12)
E-S-20 proved that 24 cribs are fundamentally insufficient to determine the cipher period under arbitrary transposition. E-S-21 confirms this experimentally — SA trivially achieves 24/24 + English-like quadgrams.

### Lag-7 Signal Status
- **REAL**: z=3.036 (9 matches vs 3.46 expected)
- **UNEXPLAINED**: Not from columnar transposition, AMSCO, grille, or any tested family
- **COMPATIBLE**: E-S-23 shows lag-7 preservation doesn't conflict with quadgram quality
- **POSSIBLE SOURCES**: Period-7 component in key/transposition, or statistical coincidence (p≈0.2%)

### What's Been Eliminated This Session
| Experiment | Family | Result | Verdict |
|-----------|--------|--------|---------|
| E-S-19 | Double columnar (widths 5-7) | 16/24 (single o1 pocket) | NOISE |
| E-S-22 | AMSCO + Nihilist + Swapped | 15/24 at p=8, <14 at p=7 | NOISE |
| E-S-24 | Thematic keys (identity trans) | 0/24 | NOISE |
| E-S-08 | SA perm + quadgram | 15/24 at p=7 | NOISE |

### What Remains Viable
1. **Transposition + Vigenère (any period 3-13)** — underdetermined, not eliminable by cribs
2. **Running key from unknown text** — untestable without the text
3. **Non-standard cipher** — "change in methodology", "not even a math solution"
4. **Keyword-structured transposition with the RIGHT keyword** — infinite possibilities
5. **Position-dependent alphabets** — completely untested
6. **Physical/procedural cipher** — per Sanborn's hints

---

## Fractionation Status (from codebase analysis)
- **ADFGVX**: Structurally eliminated — output uses only 6 symbols, K4 has 26
- **Bifid 5×5**: Algebraically impossible — K4 CT has 26 unique letters
- **Bifid 6×6**: Eliminated for periods 2-11, surviving at 9 and 12+
- **Trifid**: Eliminated for periods 2-8, surviving at 9, 11
- **Straddling checkerboard**: 0% tested, but produces numeric output (needs conversion layer)

---

## Session 13 Continued: Bean Constraint Analysis (E-S-25 through E-S-28)

### E-S-25: CT Structural Analysis — COMPLETE
- **Key findings**:
  - Lag-7 is LOCAL (DFT at k=14 BELOW expected), not global periodic
  - DFT peak at k=9 (period ~10.8): z≈2.83 — borderline after multiple testing
  - Negative half-correlation (-0.347)
  - Zero repeated trigrams
- **Artifact**: `results/e_s_25_ct_structural.json`

### E-S-23: Lag-7 Constrained SA — COMPLETE
- Lag-7 preservation COMPATIBLE with English quadgrams
- Sweet spot at weight≈5: qg/c=-3.77, lag7=8-9/9 (BETTER than weight=0)
- Higher weights (20+) degrade quadgrams
- **Artifact**: `results/e_s_23_lag7_constrained.json`

### E-S-26: Bean-Constrained Manifold SA — ARTIFACT
- 0/1000 Bean+crib generation rate at p=7 — but this is an artifact (see E-S-28)
- The check_bean function tested key[a%p] vs key[b%p], which is WRONG for Model A + transposition

### E-S-27: Bean Algebraic Impossibility — RETRACTED
- Claimed to prove period 7 Model A is algebraically impossible
- Actually proved trivial tautology: key[r] ≠ key[r] is impossible
- This is irrelevant because Bean constrains k_obs (effective keystream), not the periodic key
- Under Model A with transposition, k_obs[i] = (CT[i] - CT[σ(i)] + key[i%p]) mod 26 ≠ key[i%p]

### E-S-28: Bean Redundancy Proof — CRITICAL CORRECTION
- **ALL 24 Bean positions** (1 EQ + 21 INEQ) are within crib ranges (21-33, 63-73)
- Bean constraints are TAUTOLOGICALLY SATISFIED by the known CT+PT data
- Bean provides ZERO additional constraint beyond the 24 cribs
- **Period 7 Model A IS viable** — not algebraically impossible
- All "0% Bean pass" results in E-S-21 and E-S-26 are ARTIFACTS
- **Implication**: Bean is only useful for pure Vigenère (no transposition), which is already eliminated
- **Artifact**: `results/e_s_28_bean_redundancy.json`

---

## Updated Strategic Analysis

### Key Corrections
1. **Bean is NOT a discriminator** — it's redundant with cribs for all models with transposition
2. **Period 7 Model A is NOT eliminated** — the "algebraic proof" was wrong
3. **E-S-21 underdetermination** confirmed: 24 cribs + quadgrams cannot identify the solution

### Current Search Space
The cipher is multi-layered (substitution + transposition). Two model orderings:
- **Model A**: CT = σ(Vig(PT, key)) — key at PT positions, then transpose
- **Model B**: CT = Vig(σ(PT), key) — transpose PT, then key at CT positions

Both remain viable at all periods. Neither Bean nor cribs alone can discriminate.

### Priority Experiments
1. **COHERENT plaintext search** — SA produces English fragments but not coherent text; need stronger language model
2. **Structured transposition** — constrain σ to specific families (keyword, Myszkowski, etc.) with thematic keys
3. **Physical/procedural cipher** — Sanborn's hints suggest non-mathematical element
4. **Running key from unknown source text** — thematic texts related to 1986 Egypt / 1989 Berlin

---

*Updated 2026-02-18. All results in artifacts/results/ directories.*
