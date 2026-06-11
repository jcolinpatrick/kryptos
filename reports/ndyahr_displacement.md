# NDYAHR Directional Displacement Analysis

**Date**: 2026-03-14
**Author**: Claude (computational analysis) for Colin Patrick
**Status**: ANALYSIS COMPLETE -- no cipher signal found, but significant structural observations
**Script**: `scripts/geometry/e_ndyahr_displacement_08.py`
**Results**: `results/ndyahr_displacement.json`

---

## 1. The Observation

Six letters at the K3/K4 boundary in the sequence ENDYAHROHN are physically displaced from their grid positions in **specific, distinct directions**:

| Letter | Grid Position | Direction | Vector (dx,dy) | Compass |
|--------|--------------|-----------|----------------|---------|
| E      | Row 14, Col 0 | NONE (baseline) | (0,0) | -- |
| N      | Row 14, Col 1 | LEFT      | (-1, 0) | West |
| D      | Row 14, Col 2 | RIGHT     | (+1, 0) | East |
| Y      | Row 14, Col 3 | UP        | (0, -1) | North |
| A      | Row 14, Col 4 | UP        | (0, -1) | North |
| H      | Row 14, Col 5 | RIGHT     | (+1, 0) | East |
| R      | Row 14, Col 6 | UP-LEFT   | (-1, -1) | Northwest |

These are NOT random jitter. Sanborn: "You could not make any mistake with 1,800 letters."

---

## 2. Structural Observations (Non-Cipher)

### 2.1 NDYAHR Maps Exactly to RYPTOS (KRYPTOS Without K)

[DERIVED FACT] In the 31-wide master grid, ENDYAHR occupies Row 14, Cols 0-6 -- the same columns as the KRYPTOS keyword in the tableau header. The 1:1 column mapping is:

```
Col:  0   1   2   3   4   5   6
END:  E   N   D   Y   A   H   R
KRY:  K   R   Y   P   T   O   S
```

The six DISPLACED letters (NDYAHR, cols 1-6) map to RYPTOS -- **exactly KRYPTOS with the K removed**. The single UNDISPLACED letter (E, col 0) maps to K. This partition is structurally clean: K is the keyword initial and anchor; the remaining six letters get directional annotations.

### 2.2 Sum = 64 = 2^6

[DERIVED FACT] The A=0 letter values of NDYAHR:
- N=13, D=3, Y=24, A=0, H=7, R=17
- **Sum = 64 = 2^6**

Six letters whose values sum to exactly the sixth power of 2. Additionally:
- 64 + 1 = **65**, which is the Bean equality position (k[27] = k[65])
- 64 mod 26 = 12 = M
- 64 = 8 x 8 (8 lines of K4, from the legal pad)
- **6 x 4 = 24** (number of null positions in the 73-char hypothesis)

### 2.3 Displacement Vector Properties

[DERIVED FACT] The displacement vectors have these aggregate properties:
- **Horizontal sum = 0** (perfectly balanced: -1 + 1 + 0 + 0 + 1 - 1 = 0)
- **Vertical sum = -3** (net 3 steps upward: 0 + 0 - 1 - 1 + 0 - 1 = -3)
- The displacements are **horizontally symmetric** but **vertically biased upward by 3**

### 2.4 ENDYAHR Mod-30 Yields Exactly 24 Nulls

[DERIVED FACT] Using all 7 ENDYAHR letter values {4, 13, 3, 24, 0, 7, 17} as residues mod 30, and marking positions i where (i mod 30) matches any value: **exactly 24 null positions, 73 real**. However, this mask puts 7 crib positions into the null set (3 ENE + 4 BC), making it incompatible with the standard crib interpretation. Only 2/17 overlap with the consensus nulls from the 15/24 best lead.

### 2.5 Semaphore Partial Decoding

[HYPOTHESIS] Pairing consecutive directions as semaphore flag positions yields:
- (W, E) = positions (3, 7) = **P**
- (N, N) = positions (5, 5) = **invalid** (same position)
- (E, NW) = positions (7, 4) = **T**

P and T are both KRYPTOS keyword letters, and both correspond to the columns with direction N (up) in the displacement pattern. The middle pair (N,N) being invalid may be intentional -- it forces attention to P and T.

### 2.6 Column Reading Interpretation

If the directions encode how to read each column in a col-7 transposition:
- **Col 0 (K)**: E undisplaced = read normally
- **Col 1 (R)**: W (left) = backward?
- **Col 2 (Y)**: E (right) = forward
- **Col 3 (P)**: N (up) = bottom-to-top
- **Col 4 (T)**: N (up) = bottom-to-top
- **Col 5 (O)**: E (right) = forward
- **Col 6 (S)**: NW (up-left) = diagonal read?

This is structurally interesting but did not produce cipher signal when tested (all scores <= 2/24).

---

## 3. Cipher Testing Results

### 3.1 Hypotheses Tested

| Hypothesis | Configs | Best Score | Verdict |
|------------|---------|------------|---------|
| H1: Cardinal direction encoding (key from compass letters) | ~36 | 3/24 | NOISE |
| H2: Grid navigation (follow directions on 31-wide grid) | ~200+ | 0/24 | NOISE |
| H3: Displacement vectors as transposition offsets | ~50 | 2/24 | NOISE |
| H4: Binary/ternary encoding (directions as bits) | ~30 | 1/24 | NOISE |
| H5: Semaphore flag signaling | interpretive | -- | See 2.5 |
| H6: Letter numerology (NDYAHR values as key) | ~30 | 4/24 | NOISE |
| H7: Period-6 directional shift key | ~100 | 3/24 | NOISE |
| H8: Null mask from direction pattern | ~40 | 0/24 | NOISE |
| H9: Integration with DEFECTOR:AZ_beau+col7 | 5,040+ | 4/24 | NOISE |
| H10: Structural analysis (direction-serpentine col7) | ~10 | 2/24 | NOISE |

**Overall best: 4/24** (H6, H9) -- firmly in the noise range.

### 3.2 Key Negative Results

1. **Exhaustive col7 x DEFECTOR:AZ_beau**: All 5,040 column orderings tested. Best was 4/24 with order (0,3,2,1,5,4,6). This confirms that DEFECTOR:AZ_beau without a null mask produces only noise from pure col-7 transposition. The 15/24 best lead requires a null mask.

2. **Direction-derived column orderings** do not match or approach the column orderings that score well in the DEFECTOR:AZ_beau+col7+null-mask model.

3. **ENDYAHR mod-30 null mask** produces exactly 73 real / 24 null, but the mask is incompatible with the standard crib positions (7 crib positions land in nulls) and has near-zero overlap (2/17) with the consensus nulls from the 15/24 best lead.

4. **NDYAHR letter values as direct null positions** {0, 3, 7, 13, 17, 24} only designate 6 positions, not 24. Extending via modular arithmetic does not produce useful masks.

---

## 4. Assessment

### 4.1 What NDYAHR Probably IS

The NDYAHR displacement is almost certainly **deliberate** and **meaningful**, but it does not appear to function as a direct cipher key, transposition rule, or null mask generator. The strongest evidence for its significance:

1. **Exact KRYPTOS column correspondence**: NDYAHR = RYPTOS columns. This is not coincidence -- it is a structural announcement that the KRYPTOS keyword and the col-7 grid width are relevant to K4.

2. **Sum = 64 = 2^6**: Too clean to be random for 6 hand-selected letters.

3. **Horizontal symmetry**: The zero-sum horizontal displacement is a designed property.

### 4.2 What NDYAHR Probably IS NOT

- A direct cipher key (all periods/variants produce noise)
- A transposition rule (no reading order derived from it scores above noise)
- A null mask generator (mod-30 gives right count but wrong positions)
- A binary encoding of a useful number

### 4.3 Most Likely Interpretation

[HYPOTHESIS] NDYAHR is a **structural signpost** -- an instruction set that tells the solver:

1. **The KRYPTOS keyword matters for K4** (via the ENDYAHR-to-KRYPTOS column mapping)
2. **Width 7 is significant** (6 displaced letters + 1 undisplaced = 7 columns)
3. **The directions may encode column-reading modifications** for a transposition, but the key to exploiting them requires understanding a mechanism we have not yet conceived

The directions create a **vocabulary** (W, E, N, N, E, NW) that could only be operationally decoded once the correct transposition structure is identified. They may represent:
- Column read directions in a non-standard transposition (not yet tested with the correct null mask)
- A modifier applied AFTER identifying the correct model
- Part of a verification mechanism ("if you found the right answer, the directions should make sense")

### 4.4 Connection to Current Best Lead

The DEFECTOR:AZ_beau+col7+null-mask model at 15/24 uses col-7 transposition. NDYAHR occupies exactly 6 of the 7 KRYPTOS columns. This structural resonance is notable but does not improve the 15/24 score. The 15/24 model's null mask consensus positions (17/24 fixed across all 6 distinct solutions) do not correlate with any pattern derivable from NDYAHR directions.

---

## 5. Open Questions

1. Could the directions encode modifications that apply to a model we have not yet conceived?
2. Does the vertical bias (-3 = net 3 upward) encode a specific parameter (row offset? Key shift?)?
3. The semaphore partial decode (P, ?, T) -- are P and T operationally significant beyond being KRYPTOS letters?
4. Is there a mechanism connecting 64 = 2^6 to the K4 encryption method?
5. Do ALL 1,800 letters on the sculpture have directional displacements, or only these 6? If more exist, the pattern could encode a complete instruction set.

---

## 6. Recommendations

1. **Do NOT invest further compute** on direct cipher testing from NDYAHR -- the hypothesis space is thoroughly searched and all results are noise.
2. **Investigate whether other letters on the sculpture are displaced** -- if the directional encoding extends beyond NDYAHR, a fuller dataset might reveal the mechanism.
3. **Keep the KRYPTOS column correspondence** as a confirmed structural fact -- it reinforces the col-7 grid width and KRYPTOS keyword relevance.
4. **File NDYAHR sum=64 and Bean position 65** as a numerological observation pending mechanism discovery.
5. The **ENDYAHR-to-KRYPTOS mapping** should be cross-referenced with any future model that uses both keyword substitution and col-7 transposition.

---

*Truth classification: All cipher test results are [INTERNAL RESULT] with repro via `PYTHONPATH=src python3 -u scripts/geometry/e_ndyahr_displacement_08.py`. Structural observations (2.1-2.4) are [DERIVED FACT]. Interpretations (4.3) are [HYPOTHESIS].*
