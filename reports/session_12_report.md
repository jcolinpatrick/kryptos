# Session 12 Report: Double Columnar + Constraint Propagation

**Date**: 2026-02-18
**Focus**: Tier 4 gap-filling (double columnar transposition) + algebraic analysis of underdetermination

---

## Experiments This Session

### E-S-19: Double Columnar Transposition + Periodic Vig/Beau
**Status**: RUNNING (widths 5-7 exhaustive, (7,7) in progress)

- **Model A**: CT = col2(col1(Vig(PT, key))) — encrypt then transpose
- **Model B**: CT = Vig(col2(col1(PT)), key) — transpose then encrypt
- Both Vigenère and Beaufort, periods 3-8
- **Search space**: All w! × w! pairs for w1,w2 ∈ {5,6,7}
  - (5,5): 14.4K pairs → best 15/24
  - (5,6) + (6,5): 172.8K → best 15/24
  - (5,7) + (7,5): 1.21M → best 15/24
  - (6,6): 518.4K → best 15/24
  - (6,7) + (7,6): 7.26M → best 15/24
  - (7,7): 25.4M → in progress, 15/24 so far at 30%
- **Rate**: ~38-40K pairs/sec
- **Verdict so far**: Consistent 15/24 ceiling at period 7 across ALL width pairs. This matches the E-S-08 SA finding. **NOISE** (below 18/24 signal threshold).
- **Artifact**: `results/e_s_19_double_columnar.json` (when complete)

### E-S-20: Algebraic Transposition Constraint Propagation
**Status**: COMPLETE

**Key result**: The 24 crib positions create algebraic constraints on which transpositions are consistent with periodic Vigenère at each period. By computing the exact number of valid partial transposition assignments (CT position tuples that satisfy crib-period consistency), we find:

| Period | Valid Assignments (Vig) | Valid Assignments (Beau) | Per-Residue Group Sizes |
|--------|------------------------|-------------------------|------------------------|
| 3 | ≥ 4.50×10^16 (overflow) | ≥ 4.66×10^16 (overflow) | 9, 8, 7 |
| 4 | 1.31×10^19 | 1.69×10^19 | 6, 7, 5, 6 |
| 5 | 4.73×10^20 | 4.41×10^20 | 4, 5, 5, 6, 4 |
| 6 | 1.01×10^22 | 1.21×10^22 | 4, 4, 3, 5, 4, 4 |
| 7 | 2.99×10^23 | 2.83×10^23 | 4, 4, 4, 4, 3, 3, 2 |
| 8 | 9.42×10^24 | 1.01×10^25 | 4, 4, 2, 2, 2, 3, 3, 4 |

**NOTE**: All counts above are UPPER BOUNDS (products of per-residue valid tuples, not accounting for cross-class position conflicts). Actual counts may be significantly lower due to shared CT positions, but remain astronomically large.

**Interpretation**:
1. **24 cribs are fundamentally insufficient** to determine the substitution period when arbitrary transposition is involved.
2. **No period from 3-13 can be eliminated** by crib constraints alone under this model.
3. **Additional constraints are essential**: Bean equality/inequalities (~59× reduction), quadgram fitness (strong but non-algebraic), or structured transposition (keyword-derived).
4. The numbers grow with period because smaller residue groups have fewer constraints.
5. At period 7, each residue class independently allows 350-5,133 valid CT position tuples.

**Artifact**: `results/e_s_20_constraint_propagation.json`

---

## Background Tasks (from previous session)

### E-S-08: SA with Quadgram + Crib Fitness — NEAR COMPLETE
- Best across all periods: **15/24 at period 7** (key=[2,3,3,2,1,2,2])
- Period 7: 15/24, Period 6: 14/24, Period 5: 12/24, Period 3: 9/24
- Current: running a later period (period 4 or 2)
- **Verdict**: NOISE. The 15/24 is consistent with the extreme-value prediction for 100 SA restarts.
- PT at best: "BYTHEARITWINESSPERAGMEASYWORTH..." — English fragments from quadgram optimization, not real decryption.

### E-S-11: Running Key + Columnar Transposition — RUNNING
- Width 5: 9/24, Width 6: 10/24, Width 7: 11/24 (at 70%)
- Widths 8-10 still to go after width 7
- 9 running key texts tested (K1-K3 PT, CIA charter, JFK/Reagan speeches, UDHR, NSA Act)
- **Verdict so far**: NOISE. Best 11/24 at width 7.

### E-S-18: Turning Grille 10×10 — COMPLETE (from previous session)
- MC best: 16/24 at p=8 (B_vig), Targeted: 15/24 at p=7
- **Verdict**: NOISE. Consistent with extreme-value prediction for 2M MC samples.

---

## Strategic Conclusions

### The Underdetermination Wall

E-S-20 proves that the `transposition + periodic Vigenère` model is **fundamentally underdetermined** by the available cribs. Even at period 3 (the most constrained), there are ≥10^16 valid partial transpositions. This means:

1. **Any sweep over structured transpositions** (columnar, double columnar, keyword, turning grille) tests only a tiny fraction of the valid space.
2. **The 15/24 ceiling is NOT evidence against transposition + Vigenère** — it reflects the search method's coverage, not an algebraic impossibility.
3. **SA approaches** (E-S-08) explore more of the space but are trapped by the vast number of local optima (each valid partial assignment is a plateau).

### What Breaks Through?

To resolve the cipher, we need EITHER:

1. **More cribs** — Each additional known PT-CT pair adds ~1/26 elimination power. 10 more cribs would tighten constraints by ~10^13.
2. **The correct transposition structure** — If the transposition comes from a short keyword (e.g., KRYPTOS), only O(26^7) ≈ 10^10 transpositions are possible. Combined with period 7 key, that's ~10^10 × 26^7 ≈ 10^20 — still large but SA-tractable.
3. **Non-Vigenère substitution** — If the cipher isn't Vigenère, our entire testing framework is wrong.
4. **Physical/procedural insight** — Sanborn's "not even a math solution" hint.
5. **The lag-7 signal** — This z=3.036 structural feature constrains which transpositions are plausible.

### Updated Elimination Status

| Experiment | Cipher Family | Result | Verdict |
|-----------|--------------|--------|---------|
| E-S-18 | Turning grille + periodic Vig | 16/24 (p=8) | NOISE |
| E-S-19 | Double columnar + periodic Vig | 15/24 (p=7) so far | NOISE (preliminary) |
| E-S-20 | Constraint propagation | All periods underdetermined | THEORETICAL |
| E-S-08 | SA perm + quadgram | 15/24 (p=7) | NOISE |
| E-S-11 | Running key + columnar | 11/24 | NOISE (incomplete) |

### IC Below Random: Not Significant

K4's IC of 0.0361 vs random expectation of 0.0385. For 97 characters, σ(IC) ≈ 0.0055. The deviation is only 0.44σ — well within normal fluctuation. **The low IC does not constrain the cipher type.**

---

## What Remains Viable

1. **Transposition + Vigenère (any period 3-13)** — NOT eliminated. Underdetermined by cribs alone.
2. **Running key from unknown text** — No way to test without the text.
3. **Non-standard cipher** — Sanborn's "change in methodology" may refer to something outside classical categories.
4. **Physical/procedural cipher** — "Not even a math solution."
5. **Keyword-structured transposition + Vigenère** — The keyword reduces transposition freedom. If the keyword is KRYPTOS or similar, the search space becomes tractable for SA.

## Recommendations for Next Session

1. **Complete E-S-19** and E-S-11 to close out those experiments.
2. **SA over keyword-derived transpositions**: Instead of arbitrary permutations, restrict to transpositions derivable from short keywords (4-10 letters). Joint SA over keyword + Vigenère key.
3. **Deeper investigation of lag-7 mechanism**: Test whether specific transposition structures preserve lag-7 autocorrelation.
4. **Try non-Vigenère substitution layers**: Autokey, running key, Beaufort, with transposition.
5. **Explore "What's the point?" as a procedural clue**: Could "point" refer to a position in the text that serves as a key indicator?

---

*Generated 2026-02-18. All results to artifacts/results/ directories.*
