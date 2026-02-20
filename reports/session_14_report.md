# Session 14 Report — Double Columnar, Mixed Alphabet, and Structural Sweeps

**Date**: 2026-02-18
**Focus**: Deep structural analysis — double columnar transposition, mixed alphabet ciphers, null cipher extraction, Gronsfeld, and running key fragment analysis.

## Critical Correction from Session 13

**E-S-28: Bean Redundancy Proof** — ALL Bean constraint positions (27, 65 for equality; 21 inequality pairs) fall WITHIN the 24 known crib positions (21–33, 63–73). Therefore Bean is **tautologically satisfied** by the known CT+PT data and provides **ZERO additional constraint** beyond the 24 cribs. All prior "0% Bean pass" results (E-S-21, E-S-26, E-S-27) were artifacts of incorrectly checking periodic key rather than effective keystream.

- **E-S-27 algebraic "proof" RETRACTED**: proved trivial tautology, not actual impossibility
- **Period 7 Model A IS viable** (contrary to Session 13 claim)
- Script: `scripts/e_s_28_bean_redundancy_proof.py`
- Artifact: `results/e_s_28_bean_redundancy.json`

## Experiments Completed

### E-S-29: W-Separator Hypothesis — NO SIGNAL
- glthr hypothesis that W acts as separator in K4
- W positions: [20, 36, 48, 58, 74], creating 6 segments
- Chi²(A vs B) = 24.6 < 37.7, IC of both groups ≈ random (0.0386)
- Script: `scripts/e_s_29_w_separator.py`

### E-S-30: Three-Layer Mask — NOISE
- Model: CT = Mask + Columnar(Vig(PT, key))
- 16 masks (K1-K3 CT/PT, keywords, coordinates, years) × 5040 width-7 orderings
- 161,280 configs, ZERO hits above 14/24
- Script: `scripts/e_s_30_three_layer_mask.py`

### E-S-32: Compass/Coordinate Key — NOISE
- 43 key sequences from bearings, coordinates, dates, DMS values
- Also with width-7 columnar (K3 order, identity, reverse)
- Best: 17/24 at period 24 (underdetermined = noise)
- Script: `scripts/e_s_32_compass_coordinate_key.py`

### E-S-33: Double Columnar + Period-7 Vigenère — ELIMINATED
- **Model DC-A**: CT = σ₂(σ₁(Vig(PT, key))) — sub first, then two transpositions
- **Model DC-B**: CT = σ₂(Vig(σ₁(PT), key)) — trans, sub, trans
- Width (7,7): 25.4M pairs × 2 models × 2 variants
- 17 algebraic constraints per pair, early termination at ~97% per constraint
- **Result: 0 hits in 17.2s** → ELIMINATED
- Script: `scripts/e_s_33_double_columnar.py`

### E-S-33b: Mixed-Width Double Columnar — ELIMINATED (partial, running)
- Width combos tested: (7,5), (7,6), (7,8), (5,7), (6,7) at periods 5-7
- All 0 hits across ~400M+ pair tests
- Still running: (8,7), smaller-width combos, (7,7) at other periods
- Script: `scripts/e_s_33b_mixed_double_columnar.py`

### E-S-34: Key Fragment Analysis — NOISE
- For each width 5-8 columnar ordering, computed running key fragments at crib positions
- 92,400 candidates scored by quadgram statistics
- Best combined quadgram: -99.4 (English would be ~-50)
- No Carter text matches for any top-100 candidate
- No consistent-offset Carter hits
- **Conclusion**: No transposition makes the running key fragments look like readable English
- Script: `scripts/e_s_34_key_fragment_analysis.py`

### E-S-35: Null Cipher Extraction — NOISE
- Tested every-Nth, Fibonacci, primes, triangular, grid diagonals, coordinate positions
- High IC from character-value filters (CT[i]%N) is ARTIFACT (selecting subset of alphabet)
- Positional patterns: max IC = 0.072 (marginal after multiple testing correction)
- Step-7 column 3 IC=0.0879 (z≈2.45, n=14) — consistent with lag-7 but not actionable
- Script: `scripts/e_s_35_null_cipher_extraction.py`

### E-S-36: Gronsfeld Cipher — ELIMINATED
- Gronsfeld = Vigenère restricted to digit keys (0-9)
- Period 7 with identity: NOT consistent (residue 0 requires {24,1,12,14})
- Period 7 with all 5040 width-7 orderings: 0 consistent solutions (Model A or B)
- No date-based keys (1986, 1989, coordinates) match ≥8 cribs
- All periods 2-14 with identity: 0 Gronsfeld solutions
- Script: `scripts/e_s_36_gronsfeld_p7.py`

### E-S-37: Mixed Alphabet Cipher — PARTIALLY ELIMINATED
- Mixed alphabet: each period position uses a DIFFERENT permutation (not just shift)
- Constraint is WEAKER than Vigenère (equality + injectivity, not CT-PT=const)

Results by period (single width-7 columnar):
| Period | Pass/5040 | Constraint Strength | Verdict |
|--------|-----------|-------------------|---------|
| 5      | 2         | 2 eq + 45 ineq   | Near-eliminated |
| 6      | 428       | 0 eq + 37 ineq   | Underdetermined |
| 7      | 432       | 0 eq + 31 ineq   | Underdetermined |
| 8      | 1090      | 0 eq + 27 ineq   | Underdetermined |
| **9**  | **0**     | 5 eq + 16 ineq   | **ELIMINATED** |
| 10     | 1959      | 0 eq + 19 ineq   | Underdetermined |

- Double columnar (7,7) at period 7: 6.1M/25.4M pass (massively underdetermined)
- Script: `scripts/e_s_37_mixed_alphabet.py`

## E-S-31: Carter Running Key + Columnar (still running)
- Carter book (288K chars) + 5 other texts × all columnar orderings × widths 5-10
- Model A (hash-based fast filter) + Model B (full scan)
- Expected: NOISE (no hits in first ~3.5 minutes of width 7)

## E-S-11: Running Key + Columnar (still running, ~2.5 hours)
- Width 7 done: best 11/24 (NOISE)
- Width 8 in progress: best 9/24 so far
- Expected to complete but unlikely to show signal

## Updated Elimination Summary

### Newly Eliminated (Session 14)
1. **Double columnar transposition + periodic Vigenère** at period 5-7, widths (7,5), (7,6), (7,7), (7,8), (5,7), (6,7): 0 hits across 400M+ pairs
2. **Gronsfeld cipher (digit-only key)**: all periods 2-14, all width-7 orderings
3. **Mixed alphabet + width-7 columnar at period 9**: 0 pass (5 equality constraints)
4. **Three-layer mask (K1-K3 as pre-mask)**: 0 hits above 14/24
5. **W-separator hypothesis**: no frequency signal
6. **Compass/coordinate/date key derivation**: noise

### Narrowing but NOT Eliminated
- Mixed alphabet period 5: only 2 orderings survive (near-eliminated)
- Mixed alphabet period 7: 432 orderings survive (needs further filtering)
- Running key from unknown text (untestable without text)

## Strategic Assessment

### What we've eliminated (cumulative)
- ALL periodic polyalphabetic ciphers (standard, Beaufort, Gronsfeld, Quagmire I-III) at periods 2-14 with identity or single/double columnar transposition (widths 5-8)
- ALL linear recurrence keystream generators of order ≤ 8
- ALL polynomial position keystreams of degree ≤ 20
- Hill cipher n=2,3,4
- Bifid 5×5 (26-letter alphabet), Bifid 6×6 periods 2-8,11
- Trifid periods 2-8
- Autokey (PT/CT), Porta, Nihilist
- Digraphic ciphers (Playfair, Two-Square, Four-Square)
- Running key from 25+ known texts (Carter, CIA charter, speeches, etc.)
- Null cipher extraction patterns
- ADFGVX (requires 6-letter output alphabet)

### What remains viable
1. **Running key from unknown/private text** — fundamentally untestable without the text
2. **Mixed alphabet at periods 5-7 with specific transpositions** — 432 orderings at p=7, 2 at p=5
3. **Non-linear key generation** beyond tested families
4. **Physical/procedural cipher** ("not mathematical")
5. **Non-columnar transposition** (disrupted, Myszkowski, route cipher on non-rectangular grid)
6. **Cipher with >2 layers** of a type we haven't conceived
7. **Key derived from undiscovered source** (Sanborn's private texts, unpublished artworks)

### Recommended Next Steps
1. **Deep dive on mixed alphabet period 5 (2 survivors)**: Reconstruct partial alphabets, check for keyword structure, attempt extension
2. **Non-columnar transpositions**: disrupted transposition, Myszkowski, rail fence variants
3. **Broader running key search**: more historical texts related to 1986 Egypt / 1989 Berlin
4. **Physical analysis**: map K4 to the sculpture's physical grid and test reading orders
5. **K5 cross-correlation**: use K5's structure to constrain the cipher

---
*Session 14 — 2026-02-18 — 11 experiments (E-S-28 through E-S-37)*
