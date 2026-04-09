---
status: HISTORICAL research plan — not authoritative
authored: 2026-03-23 (pre-dates palette retirement)
palette_dependency: yes — this plan materially depends on the retired {B,G,I,K,O,W,Z} palette construct and/or its derived null-mask rules
retired_on: 2026-04-01 (palette retirement); banner added 2026-04-09 (AUDIT-2 closure)
superseded_by: docs/a1_score_conditioned_null_report.md, memory/retired/README.md, MEMORY.md
---

> # HISTORICAL / PALETTE-DEPENDENT — NOT LIVE DOCTRINE
>
> This research plan was authored 2026-03-23 on top of the palette
> `{B,G,I,K,O,W,Z}` construct. That construct was **retired on 2026-04-01**
> as a post-hoc selection artifact (score-conditioned null; SA produces 11
> distinct letters on K4, indistinguishable from shuffled controls p=0.30).
> Any conclusion, predicted signal, or test plan in this file that depends
> on the palette, the mod-35 rule, BCL enrichment, or the Polybius
> row-selection model is **historical only** and must not be used to drive
> live research. See `memory/retired/README.md`, `docs/superpowers/README.md`,
> and `docs/a1_score_conditioned_null_report.md`.

# Multi-Phase Research Plan: Solving the K4 Steganographic Layer

**Date:** 2026-03-23
**Author:** Claude Opus 4.6 (steganalysis agent) for Colin Patrick
**Status:** Design Spec
**Scope:** Full characterization of K4's steganographic mechanism and its constraints on the cipher layer

---

## 0. Executive Summary

The stego layer is the only component of K4 with confirmed statistical signal (joint p=1.4e-7). After 950+ experiments and 884B+ cipher configurations yielding ZERO breakthroughs, the stego layer offers the highest marginal information gain per unit work. This plan attacks five open questions (OQ-1 through OQ-5) across four phases, ordered by information gain per compute cost.

**Key strategic insight:** The stego layer is partially solved but incompletely characterized. Completing it gives us the exact 24-position null mask, which reduces the cipher problem from 97 unknowns to 73 and tightly constrains the key generation mechanism. The stego layer is not the destination; it is the most promising path to the cipher.

**What "fully solved" means for the stego layer:**
1. All 24 null positions identified (17 known, 7 unknown)
2. The generative rule for null POSITIONS articulated as a falsifiable mechanism
3. The generative rule for null CHARACTER VALUES at each position articulated
4. The coupling between stego and cipher explained (WHY keystream is palette-biased)
5. The physical process Sanborn used identified (transparency, chart, grille)

We currently have (1) at 71%, (2) descriptively at 100% but mechanistically at ~40%, (3) at ~15%, (4) at ~60%, and (5) at ~10%.

---

## 1. Convention Freeze

```
CONVENTIONS:
  Positions:      0-indexed (repo standard)
  Alphabet map:   A=0, B=1, ..., Z=25
  Cipher variant: Beaufort C=(K-P)%26 (confirmed primary)
  Grid alphabet:  KA = KRYPTOSABCDEFGHIJLMNQUVWXZ (all 26 letters)
  Grid width:     5 (Polybius standard, confirmed by palette column structure)
  Null criterion: position p is consensus null if p in {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}
  Scope:          CT97 (full carved text)
  Null palette:   {B,G,I,K,O,W,Z} (7 letters)
  Keystream:      JLJODEGKUKKKLOCGGBGOKTRU (Beaufort A=0 at 24 crib positions)
```

All phases use these conventions unless explicitly stated otherwise.

---

## 2. Known Evidence Inventory

### Tier A: Statistically Robust (independently validated, convention-robust)

| Finding | Value | p-value | Holdout | Source |
|---------|-------|---------|---------|--------|
| Palette restriction (S2) | 7/26 letters at 17 positions | 6.3e-5 | N/A (single sample) | MC 100K |
| BCL keystream 7/8 palette (C*S-1 partial) | 7/8 at positions 63-70 | 6.27e-4 | Cross-validated (disjoint from palette source) | Binomial |
| Combined palette + BCL (C*S-1 full) | 13/24 keystream in palette | 0.0043 | Cross-validated | Binomial |
| AP {G,K,O} at 12/24 (C*S-3) | 12/24 keystream positions | 3.9e-6 | Alphabet-independent | Binomial |
| Joint null probability | Combined evidence | 1.4e-7 | MC 50M, proper joint | Fisher combined |
| Crib avoidance (S6) | 0/17 nulls in crib ranges | 0.0047 | Structural | Hypergeometric |

### Tier B: Descriptive (fits data perfectly but not independently validated)

| Finding | Value | Status | Concern |
|---------|-------|--------|---------|
| (pos%7, pos%5) table | 35/35 classification | 0 DOF, post-hoc | LOO = 51.4%, 162/342 mod pairs also perfect |
| KRYPTOS x SEVEN generation | 6/6 row-selection | Overfit risk (p~0.016-0.029 MC) | ~1.6% of English words match |
| Mixed cell tiebreaker (first=null) | 3/3 | N/A (tiny sample) | Could be any order rule |

### Tier C: Structural Properties (not probabilistic)

| Property | Value | Implication |
|----------|-------|-------------|
| 97 - 73 = 24 | Sanborn legal pad "3 Lines 93 [note: was misread as 8 lines 73]" | 24 nulls total |
| 35 palette positions = 5 * 7 | Grid structure echo | Width-5 x period-7 |
| Width-21 bigram anomaly is stego artifact | Destroyed by null extraction | Null insertion creates CT97 structure |
| Lag-7 autocorrelation is stego artifact | Destroyed by null extraction | Same |
| Width-10, width-17 bigram anomalies are cipher | Appear only in CT73 | Cipher layer has internal structure |

---

## 3. Open Questions — Priority Ordering

| Priority | Question | Information Gain | Compute Cost | Dependencies |
|----------|----------|-----------------|--------------|--------------|
| 1 | OQ-3: Null character assignment function | HIGH: reveals stego algorithm | LOW-MED | None |
| 2 | OQ-2: The 7 varying null positions | HIGH: completes 24-mask | MED | Partial: benefits from OQ-3 |
| 3 | OQ-1: 7x5 table cell assignment mechanism | MED: mechanistic understanding | LOW | None |
| 4 | OQ-5: Cipher families surviving stego constraints | MED-HIGH: constrains cipher | MED | Benefits from OQ-2 |
| 5 | OQ-4: Physical mechanism (RED transparency) | HIGH but non-computational | ZERO compute | External information |

**Rationale for ordering:**
- OQ-3 first because understanding HOW null characters are assigned could reveal the algorithm that also determines WHERE they go (solving OQ-2 as a side effect). It is the cheapest to test because we have 17 known examples with full context (CT neighbors, position, keystream at nearby cribs).
- OQ-2 before OQ-1 because completing the mask is operationally more valuable than understanding why the 7x5 table looks the way it does.
- OQ-5 last among computational questions because it requires the stego layer to be more complete before the constraints are maximally tight.
- OQ-4 is non-computational and should be pursued in parallel through archival research.

---

## 4. Phase 1: Null Character Assignment Function (OQ-3)

### 4.1 Question

**"Given that position P is a null, what determines which palette letter {B,G,I,K,O,W,Z} fills it?"**

This is the least-investigated aspect of the stego layer. We know the palette (WHAT letters) and the positions (WHERE they go, partially), but not the assignment function (WHICH letter at WHICH position).

### 4.2 Known Data

The 17 consensus null positions and their assigned characters:

```
Pos:  0  1  2  5  8 12 14 20 36 52 58 59 74 75 78 84 85
Char: O  B  K  O  G  B  O  W  W  K  W  I  W  G  Z  I  G
Num:  14  1 10 14  6  1 14 22 22 10 22  8 22  6 25  8  6
```

**Letter frequencies in nulls:** W=4, O=3, G=3, B=2, I=2, K=2, Z=1
**Expected (uniform over 7):** 2.43 each. W is 1.65x expected, Z is 0.41x.

### 4.3 Models to Test

| Model | Description | Prediction | Test |
|-------|-------------|------------|------|
| NC-1: Random draw from palette | Each null independently draws from {B,G,I,K,O,W,Z} | Uniform distribution, no neighbor correlation | Chi-square on frequencies |
| NC-2: Neighbor-determined | null_char = f(CT[p-1], CT[p+1]) | Each null uniquely determined by neighbors | Check if 17 functions f exist |
| NC-3: Position-determined | null_char = palette[g(pos)] for some g | Position alone determines char | Check all simple g(pos) formulas |
| NC-4: Keystream echo | null_char = keystream_value at nearest crib | Correlation with nearby keystream | Compare nearest crib keystream |
| NC-5: Grid lookup | null_char = grid[pos%7][pos%5] applied to palette somehow | Deterministic from grid position | Compute grid cell -> letter mapping |
| NC-6: Cipher-determined | null_char = Beaufort(real_PT_at_some_pos, key) | Null chars ARE cipher output under a specific key | Test with known keystream values |
| NC-7: Delta4=5 constraint | Null chars chosen to maintain constant lag-4 difference locally | At least pos 58,59 satisfy this | Extend to all 17 |

### 4.4 Test Methodology

**Cost Level 1 — Closed form (minutes):**

1. **NC-1 frequency test:** Chi-square goodness-of-fit for uniform distribution over 7 letters on 17 draws.
   - Pass: p > 0.05 (cannot reject uniform)
   - Fail: p < 0.05 (non-uniform, rules are present)
   - Note: With only 17 data points and 7 categories, power is very low. This is a cheap exclusion test, not a confirmation.

2. **NC-3 position formulas:** Test null_char_num = (a*pos + b) mod 7 mapped to palette for all (a,b) in Z_7 x Z_7 = 49 formulas. Also test mod 5, mod 26.
   - Pass: any formula matches 17/17
   - Fail: all < 14/17 (chance is ~2.4)

3. **NC-5 grid cell mapping:** The (pos%7, pos%5) cell is known for each of the 17 nulls. Check: do all nulls in the same cell get the same letter?
   - There are 10 pure-null cells containing 14 positions. If the same cell always maps to the same letter, the mechanism is a 10-entry lookup table.
   - Pass: perfect consistency (same cell = same letter for all 14)
   - Fail: any cell has two different null letters

**Cost Level 2 — Counting (seconds):**

4. **NC-2 neighbor analysis:** For each of the 17 nulls, record (CT[p-1], CT[p+1]). Check if null_char = any simple function of neighbors: sum mod 7, diff mod 7, XOR mod 7, min, max, KA-mean.
   - Also check: does the NULL letter fill a "gap" in some sequence (like the Delta4=5 finding at pos 58,59)?
   - Boundary cases: pos 0 has no CT[-1]. Use wrap-around (CT[96]) or omit.
   - Pass: any function matches 16/17 or better
   - Fail: all < 12/17

5. **NC-4 keystream echo:** For each null position p, find the nearest crib position c (by |p-c|). Record keystream[c]. Check correlation between null_char and keystream at nearest crib.
   - Also test: null_char = (keystream_at_nearest_crib + offset) mod 26 for offset 0-25.
   - Pass: any offset matches 14/17+
   - Fail: all < 8/17

**Cost Level 3 — MC validation (minutes):**

6. **NC-7 Delta constraint extension:** The Delta4=5 finding shows pos 58,59 are uniquely determined by positions 56,57,60,61. Generalize: for each null position, check if it is uniquely determined by a constant-delta constraint at some lag within a local window.
   - Window size: 3-9 characters centered on null position
   - Lags: 1-4
   - Pass: >10/17 nulls are delta-constrained
   - Fail: only 2/17 (the known pair at 58,59)

7. **NC-6 cipher determination:** Under Beaufort A=0, if position p is null, is CT[p] = Beaufort(X, K) for X from some regular source and K from the nearest known keystream? Specifically test: X = position in some known sequence, K = interpolated/extrapolated keystream.
   - This requires assumptions about keystream at non-crib positions
   - Pass: consistent model with 14/17+
   - Fail: model-dependent, inconclusive

### 4.5 Pass/Fail Criteria

- **Positive result:** A model achieves 17/17 (or 16/17 with one explainable exception). This would identify the null character assignment function.
- **Partial positive:** A model achieves 14-15/17, suggesting the mechanism plus a secondary rule.
- **Negative result (still valuable):** ALL models < 12/17. This means the null characters are NOT determined by simple position, neighbor, or keystream relationships. They may be read directly from the encoding chart (consistent with the "lookup table" hypothesis from OQ-1).
- **What a positive unlocks:** If we know the assignment function, we can predict what letter SHOULD appear at the 7 varying null positions, giving us a way to independently verify candidates for OQ-2.

### 4.6 Data/Infrastructure

- Existing: `CT`, `CONSENSUS_NULL_POSITIONS`, `NULL_PALETTE` from `kryptos.kernel.constants`
- New script needed: `scripts/analysis/e_null_char_assignment.py`
- Estimated compute: < 5 minutes total

---

## 5. Phase 2: Resolving the 7 Varying Null Positions (OQ-2)

### 5.1 Question

**"Which 7 of the 18 remaining palette-letter positions (plus any non-palette positions) complete the 24-null mask?"**

### 5.2 Known Data

17 consensus nulls are fixed. 7 more needed. Key constraints:
- The exhaustive C(56,7) = 231.9M mask search found 396 masks scoring 15/24 with DEFECTOR:AZ_beau+col7
- These 396 masks cluster in two paths: 88-path (378 masks) and 87-path (18 masks)
- Varying positions cluster in ranges: {38-45}, {54-56}, {87-88}, {93-96}
- The 7 varying positions use NON-palette letters: {Q,S,J,D,H,C,R}
- The varying positions have ZERO effect on crib matches (65/73 PT chars identical across all 396 masks)

### 5.3 Critical New Observation

The varying nulls use NON-palette letters. This means the (pos%7, pos%5) palette classification table does NOT apply to them. They have a DIFFERENT insertion mechanism. Two sub-questions:

**OQ-2a:** Are the 7 varying positions drawn from a SECOND palette?
**OQ-2b:** Is there a position rule for the varying nulls, independent of the palette rule?

### 5.4 Models to Test

| Model | Description | Test |
|-------|-------------|------|
| VM-1: Second palette | Varying nulls use a restricted second letter set | Count distinct letters across all 396 masks' varying positions |
| VM-2: Crib-derived | Varying positions are determined by crib positions | Check arithmetic relationships between varying ranges and crib ranges |
| VM-3: Complement of palette rule | Varying positions are where the 7x5 table says "null" but the letter is NOT in the palette | Count how many non-palette letters at "null" cells are varying nulls |
| VM-4: Keystream-dependent | Position p is a varying null iff keystream[p] meets some criterion | Requires keystream at non-crib positions (unknown) |
| VM-5: Physical spacing | Varying positions maintain some geometric regularity with consensus nulls | Gap analysis of combined 24-position set |

### 5.5 Test Methodology

**Cost Level 1 — Closed form:**

1. **VM-1 second palette:** The 396 masks use positions from a known range. List all letters at those positions and check diversity.
   - Positions in {38-45}: CT letters at 38=T, 39=J, 40=K, 41=L, 42=U, 43=D, 44=I, 45=A
   - Positions in {54-56}: CT letters at 54=N, 55=F, 56=B (palette!)
   - Position 87: CT[87]=D, Position 88: CT[88]=H
   - Positions in {93-96}: CT letters at 93=K(palette!), 94=C, 95=A, 96=R
   - Wait: some of these ARE palette letters (pos 44=I, 56=B, 93=K). But the finding says varying positions use NON-palette letters. This needs verification against the actual mask data.
   - Pass: < 10 distinct letters across all varying positions
   - Fail: > 15 distinct letters (approaching random)

2. **VM-3 complement check:** From the palette_mod35_rule.md, 16 non-palette positions fall in "N" (null-predicted) cells. Are these the candidates for varying nulls?
   - The 16 false-positive positions: {4,15,17,24,37,39,40,43,49,50,55,71,72,87,90,94}
   - Compare with varying null ranges: {38-45} contains {39,40,43}; {54-56} contains {55}; {87-88} contains {87}; {93-96} contains {94}. That is 6 of the 7 varying positions, if the 396-mask search selected from these.
   - This is a STRONG lead: the (pos%7, pos%5) table's false positives on non-palette letters may actually be the varying nulls.
   - Pass: >= 6/7 varying positions are in the set of 16 false-positive positions
   - Fail: < 4/7

**Cost Level 2 — Counting (seconds):**

3. **VM-2 crib arithmetic:** Check if varying position ranges relate to crib ranges by simple transforms.
   - {38-45} starts at 38 = 63-25 = BCL_start - 25. Or 38 = 33+5 = ENE_end + 5.
   - {54-56} immediately precedes cribs? No, BCL starts at 63.
   - {87-88} = 84+3 and 84+4 (near consensus null cluster at 84,85).
   - {93-96} = near end of CT.
   - Check all simple relationships: varying_pos = crib_pos + k for small k, varying_pos = 97 - crib_pos, etc.

**Cost Level 3 — Re-analysis of existing data (minutes):**

4. **Cross-reference 396-mask details:** Load the actual C(56,7) search results and tabulate: for each of the 7 varying slots, which positions appear and with what frequency.
   - Data source: `results/palette_exhaustive_null_mask.json` or `memory/bruteforce_7remaining.md`

### 5.6 Pass/Fail Criteria

- **Positive:** A model identifies all 7 varying positions uniquely (one specific 24-mask). This would complete the stego mask.
- **Partial positive:** Model narrows candidates to < 50 masks (from current 396).
- **Negative:** No model discriminates below 396. The varying positions require information we do not have (e.g., the encoding chart keyword).
- **What a positive unlocks:** The exact 73-character real ciphertext, enabling focused cipher attacks with known null positions removed.

### 5.7 Data/Infrastructure

- Existing: `memory/bruteforce_7remaining.md`, `results/palette_exhaustive_null_mask.json`
- Existing: (pos%7, pos%5) table false positives from `memory/palette_mod35_rule.md`
- New script needed: `scripts/analysis/e_varying_null_resolution.py`
- Estimated compute: < 15 minutes

---

## 6. Phase 3: The 7x5 Table Generation Mechanism (OQ-1)

### 6.1 Question

**"What generative mechanism produces the (pos%7, pos%5) classification table's N/R assignments?"**

### 6.2 Known Data

The table has 10 pure-null cells, 13 pure-real cells, 3 mixed cells, 9 empty cells. Exhaustive search found 8 cipher-word matches (TOWER, CHART, LAYER, etc.) and NO arithmetic/binary/geometric rules. The cipher-word matches have p~0.5% individually (weak).

### 6.3 The Cipher-Word Matches — Do They Deserve Deeper Investigation?

**Assessment: YES for CHART, conditionally for TOWER and LAYER.**

Reasons:

1. **CHART is thematically strongest.** Sanborn used "coding charts" to encrypt K4. If the 7x5 table is derived from Cipher(KRYPTOS[pos%7], CHART[pos%5]) on AZ Beaufort, the mechanism is: "use the encoding CHART keyword to determine which positions are nulls." This is operationally coherent with Sanborn's process.

2. **TOWER is architecturally relevant.** The Kryptos sculpture is sometimes described by its tower-like form. Weaker thematic link but structurally possible.

3. **LAYER connects to the two-layer paradigm.** "Pull up one layer, come to the next" (Sanborn). If LAYER is the second keyword (along with KRYPTOS for the first), this is self-referential.

4. **Statistical weakness is not dismissive at this stage.** Yes, ~0.5% of random 5-letter strings work. But we are not testing random strings; we are testing whether a SPECIFIC thematically motivated word matches. The prior probability of "CHART" being relevant to K4 is much higher than 1/11.8M (the random word space).

**However:** The null letter sets produced by these words have no simple structure (not threshold, not Polybius-column, not contiguous). This makes the cipher-word mechanism feel arbitrary rather than principled. A true mechanism should be SIMPLER than the lookup table it generates.

### 6.4 Models to Test

| Model | Description | Test |
|-------|-------------|------|
| TG-1: Cipher word from chart | Table = Cipher(KRYPTOS, WORD) output partition | Already found 8 matches; test thematic candidates |
| TG-2: Binary encoding of chart fold lines | Table encodes accordion fold positions | Map fold lines to 7x5 grid; compare |
| TG-3: RED transparency overlay | Table derived from which grid cells are visible through a red mask | Requires physical modeling |
| TG-4: Table is the chart itself | Sanborn's coding chart IS the 7x5 table (or contains it) | Compare with known chart features |
| TG-5: Table is derived from keystream | The 24 keystream values somehow generate the table | Check if keystream at nulls determines table |

### 6.5 Test Methodology

**Cost Level 1 — Arithmetic (minutes):**

1. **TG-1 extended thematic test:** Test the 8 matching words (TOWER, CHART, LAYER, plus 5 more) as operational components. For each matching word W:
   - Does W connect to any other K4 parameter? (word length, letter values, position in K4 CT)
   - Does the null letter set produced by Cipher(KRYPTOS, W) overlap with the palette {B,G,I,K,O,W,Z}?
   - Does the word appear in K1-K3 plaintext?

2. **TG-2 fold line mapping:** Sanborn's chart has accordion fold lines. The chart is 31 columns wide. Fold lines at regular intervals create panels. Map panel boundaries to the 7x5 grid and check alignment.
   - Known: chart is 14 rows x 31 columns. 31/5 = 6.2 (not clean). 14/7 = 2 (clean!).
   - The 7-row dimension of the table maps naturally to the 14-row chart (2 rows per table row).
   - The 5-column dimension maps to the chart via the Polybius width.
   - Check: do fold lines fall at column boundaries that correspond to the 5-wide Polybius grid?

3. **TG-5 keystream derivation:** Using the 24 known keystream values, compute: for each (r,c) cell in the 7x5 table, is there a crib position p where p%7=r and p%5=c? If so, does the keystream value at p predict whether the cell is N or R?
   - This is a small enumeration: 24 crib positions map to at most 24 of the 35 cells.
   - Pass: perfect prediction where data exists
   - Fail: no correlation

**Cost Level 2 — Deeper analysis (minutes-hours):**

4. **CHART hypothesis deep dive:** If CHART matches AZ_Beaufort, compute:
   - Beaufort(KRYPTOS[i], CHART[j]) for all (i,j) in 7x5
   - The output letters that fall in the "null set" define the N cells
   - Check: does this null set have any relationship to the palette?
   - Check: does this make the combined system "two uses of one grid" (palette from KRYPTOS x SEVEN, table from KRYPTOS x CHART)?
   - This would mean KRYPTOS, SEVEN, and CHART are the three keywords of K4.

### 6.6 Pass/Fail Criteria

- **Positive:** One thematic word produces the table AND connects to other known K4 parameters (palette, keystream, physical chart features).
- **Negative but informative:** No word connects beyond the table itself. The table remains a lookup table, likely part of the physical encoding chart and not derivable without it.
- **What a positive unlocks:** If the table is generated by KRYPTOS x CHART (or similar), we have identified a third keyword. This would drastically constrain the cipher layer (three keywords total: KRYPTOS for alphabet, SEVEN for palette row selection, CHART/TOWER/LAYER for null placement).

### 6.7 Data/Infrastructure

- Existing: `memory/palette_mod35_rule.md`, `results/mod35_table_derivation.json`
- New script needed: `scripts/analysis/e_table_generation_deep.py`
- Estimated compute: < 30 minutes

---

## 7. Phase 4: Backward Propagation — Cipher Constraint Tightening (OQ-5)

### 7.1 Question

**"What cipher mechanism families survive ALL stego constraints simultaneously?"**

### 7.2 Rationale

The existing `compliance.py` module scores individual mechanisms against a 14-point checklist. But it has not been used to ELIMINATE mechanism families. This phase uses the stego constraints as a filter: any mechanism that cannot produce palette-biased keystream values is structurally incompatible with the stego layer.

### 7.3 Constraints to Propagate

From the confirmed stego-cipher coupling:

1. **C*S-1:** At least 13/24 keystream values must be in {B,G,I,K,O,W,Z}. Any mechanism that produces uniformly distributed keystream at crib positions is eliminated.
2. **C*S-3:** At least 12/24 keystream values must be in {G,K,O}. Any mechanism without this concentration is eliminated.
3. **HC-4:** Non-periodic. All periodic mechanisms are eliminated.
4. **HC-2 + HC-3:** Bean equality k[27]=k[65] and 242 inequalities.

### 7.4 Mechanism Families to Evaluate

| Family | Can it produce palette-biased keystream? | Status |
|--------|------------------------------------------|--------|
| Periodic polyalphabetic | No (and independently eliminated by HC-4) | ELIMINATED |
| PT-autokey (any offset) | Depends on PT; offset=8 requires DEFECTOR but is structurally impossible | ELIMINATED (proof in MEMORY.md) |
| CT-autokey | All zero across all configs | ELIMINATED |
| Combined PT+CT autokey | Max 8/24 | ELIMINATED |
| Running key (English text) | Anti-correlation: key+PT cannot both be English | ELIMINATED (for English sources) |
| Running key (non-English) | Open but untestable without source identification | OPEN |
| Polybius-grid lookup | YES: if key reads from 5-wide grid, output is naturally mod-5 constrained | OPEN |
| OTP/manual key | YES: if key was hand-selected from grid | OPEN |
| Bespoke grid-based | YES: any grid-reading process on 5-wide KA grid could produce palette bias | OPEN |

### 7.5 New Test: Polybius Grid as Key Source

**Hypothesis:** The keystream is generated by reading from the same 5-wide KA Polybius grid that generates the palette. If the key is a running key read from the grid (column-by-column, row-by-row, diagonal, spiral, etc.), the keystream would naturally be biased toward columns 0 and 3 (the palette columns).

**Test:**
1. Enumerate all simple reading orders of the 5x6 KA grid (26 letters): left-to-right, top-to-bottom, column-major, diagonal, spiral, reverse.
2. For each reading order, use the resulting sequence as a running key under Beaufort.
3. Check: does the resulting plaintext at crib positions match the cribs?
4. Also: does the keystream match the known keystream JLJODEGKUKKKLOCGGBGOKTRU?

**Cost:** ~50 reading orders x 26 offsets = 1,300 tests. Seconds.

**This has likely been tested indirectly** through the 60K English Gutenberg running key search and the corpus keystream search, but NOT specifically as a grid-reading-order test on the KA Polybius grid itself.

### 7.6 New Test: Modular Arithmetic on Grid Coordinates

**Hypothesis:** keystream[i] = f(row_of_CT[i], col_of_CT[i]) where row/col are in the 5-wide KA Polybius grid.

For the 24 known keystream values, we know CT at those positions. Map each CT letter to its (row, col) in the 5x6 KA grid. Then test:
- key = (a*row + b*col + c) mod 26 for all (a,b,c)
- key = row*5 + col (Polybius coordinate value)
- key = other polynomial combinations

**Cost:** 26^3 = 17,576 (a,b,c) triples x 24 positions = seconds.

### 7.7 Pass/Fail Criteria

- **Positive:** A grid-based key generation mechanism matches 24/24 keystream values AND explains the palette bias structurally. This would solve K4's cipher layer.
- **Partial positive:** A grid-based model matches 20+/24 keystream values. This narrows the mechanism to a specific family.
- **Negative:** No grid-based model exceeds 13/24 (the palette enrichment baseline). The key source is NOT the grid itself, but something that shares structure with it (e.g., the encoding chart, which was derived from the grid).
- **What a positive unlocks:** Full decryption of K4.

### 7.8 Data/Infrastructure

- Existing: `kryptos.kernel.constraints.coupling`, `kryptos.kernel.scoring.compliance`
- Existing: `scripts/analysis/stego_proof_pipeline.py`
- New script needed: `scripts/analysis/e_grid_key_generation.py`
- Estimated compute: < 10 minutes for grid reading orders; < 1 hour for full backward propagation

---

## 8. Phase 5: Physical Mechanism and External Evidence (OQ-4)

### 8.1 The RED Transparency Hypothesis

**Evidence:** Smithsonian Box 6/18 contains a Kinko's receipt for "15% Red / TRANS" in the same folder as a stego sketch. This is a transparency (acetate sheet) printed at 15% reduction with red-colored content.

### 8.2 Testable Predictions

The red transparency could function in several ways. Each makes distinct predictions:

| Model | Physical Process | Prediction | How to Test |
|-------|-----------------|------------|-------------|
| PT-1: Darkroom safe light | Red transparency viewed under red safelight reveals hidden content | Content on chart visible only under red light | Requires physical chart |
| PT-2: Cardan grille carrier | Red transparency is a Cardan grille overlay; red squares mark key positions | 24 or 73 positions marked on a grid overlay | Test whether grille-as-key-CARRIER (not mask) produces viable keys |
| PT-3: Reduction overlay | 15% reduction means chart was scaled to 85% and overlaid on another document | Two documents at different scales align to reveal key | Requires physical documents |
| PT-4: Photographic contact print | Ed Shaw (photographer) made contact prints; red filter selects specific elements | Photographic process selects key characters | Non-computational |

### 8.3 Computationally Testable: Grille-as-Key-CARRIER

**Critical distinction:** Grille-as-MASK has been exhaustively tested (232M masks). But grille-as-key-CARRIER has NOT been tested. The difference:

- **Grille-as-mask:** The grille determines which CT positions are "real." This is the standard Cardan grille model. ELIMINATED.
- **Grille-as-key-carrier:** The grille is laid over the encoding chart. Characters visible through the grille openings spell out the cipher key. The grille does NOT touch the ciphertext directly.

**Test:**
1. Generate candidate grilles on the known 14x31 chart layout.
2. For each grille, read the visible characters as a key.
3. Apply Beaufort decryption with that key to CT97.
4. Score against cribs.

**Challenge:** We do not have the encoding chart content. We know its dimensions (14 rows x 31 columns) and that it contains PT/KEY/CT triplets. Without the chart content, we cannot read through any grille.

**However:** We CAN test the STRUCTURAL hypothesis: if the grille produces a key of length L that is applied as a running key, what values of L are consistent with the known keystream? The known 24 keystream values constrain the key at 24 positions. If L < 97, the key repeats, and we can check for periodicity violations. If L >= 97, no constraint beyond the 24 known values.

**Verdict on this test:** Low probability of success without the chart content. But the structural test (what key lengths are consistent) is essentially free and should be recorded.

### 8.4 Ed Shaw Investigation

Ed Shaw was Sanborn's photographer collaborator. Sanborn said Shaw was "the genesis of a lot of the mystery." Nobody has investigated Shaw's specific photographic techniques in 35 years. Photographic techniques (contact printing, double exposure, multiple plates) are natural stego carriers.

**Testable predictions from photographic stego:**
- Contact printing from two different negatives could produce a composite where some characters come from one plate and others from another. This maps to the two-palette model (17 consensus nulls from palette, 7 varying nulls from a different source).
- Double exposure would produce artifacts at specific positions. These might correspond to null positions.

**These are not computationally testable.** They require either physical access to Sanborn's materials or detailed knowledge of Shaw's photographic processes.

### 8.5 Pass/Fail Criteria

This phase is information-gathering, not hypothesis testing. Success means identifying a specific physical process that maps to the computational stego structure (palette, 7x5 table, crib avoidance).

---

## 9. Integration: The Stego Solve Endgame

### 9.1 What "Fully Solved" Looks Like

The stego layer is "fully solved" when we can answer all of the following:

1. **MASK (24 positions):** We know all 24 null positions with certainty and can state why each one is null. Currently: 17/24 known.

2. **PALETTE (7 letters):** We know why these 7 letters and not others. Currently: confirmed (columns 0,3 of 5-wide KA grid), but the generation rule (KRYPTOS x SEVEN) is overfit-suspect.

3. **PLACEMENT RULE (algorithm):** We can state the algorithm that determines null positions as a reproducible procedure, not a lookup table. Currently: (pos%7, pos%5) table exists descriptively, but the TABLE ITSELF has no known generative mechanism.

4. **CHARACTER ASSIGNMENT (algorithm):** We can state the algorithm that determines which palette letter fills each null position. Currently: unknown.

5. **COUPLING EXPLANATION (mechanism):** We can explain WHY the keystream is palette-biased structurally, not just statistically. Currently: "two systems, one grid" is the best model, but it is an explanation, not a mechanism.

### 9.2 Incremental Value Thresholds

| Milestone | Value | Requires |
|-----------|-------|----------|
| 24-mask determined | Very high: reduces cipher to 73-char problem | OQ-2 solved |
| Character assignment function found | High: reveals stego algorithm | OQ-3 solved |
| Table generation mechanism found | Medium: deepens understanding | OQ-1 solved |
| Coupling mechanism identified | High: constrains cipher family | OQ-5 solved |
| Physical process identified | Very high: may directly yield key | OQ-4 solved (external) |
| All 5 solved | Complete stego layer characterization | All OQs solved |

### 9.3 What the Stego Layer CANNOT Do

Even a fully solved stego layer does not decrypt K4. It gives us:
- The exact 73-character real ciphertext
- Tight constraints on the cipher mechanism (must produce palette-biased keystream)
- Possibly the keyword(s) used for key generation
- A formal constraint spec that any proposed solution must satisfy

The actual decryption requires identifying the key source (encoding chart, running text, bespoke procedure). The stego constraints narrow this search dramatically but do not complete it.

---

## 10. Experiment Schedule

| Phase | Question | Priority Tests | Est. Time | Dependencies |
|-------|----------|---------------|-----------|--------------|
| **1a** | OQ-3: NC-1 frequency | Chi-square on 17 null chars | 2 min | None |
| **1b** | OQ-3: NC-3 position formulas | 49 linear formulas mod 7 | 5 min | None |
| **1c** | OQ-3: NC-5 grid cell consistency | Cell-to-letter mapping | 5 min | None |
| **1d** | OQ-3: NC-2 neighbor analysis | f(CT[p-1], CT[p+1]) | 10 min | None |
| **1e** | OQ-3: NC-4 keystream echo | Nearest crib keystream | 10 min | None |
| **1f** | OQ-3: NC-7 Delta constraint | Generalized Delta4=5 | 15 min | None |
| **2a** | OQ-2: VM-3 complement check | False-positive positions vs varying nulls | 5 min | None |
| **2b** | OQ-2: VM-1 second palette | Letter diversity in varying positions | 10 min | 2a |
| **2c** | OQ-2: Cross-reference 396 masks | Tabulate varying position patterns | 15 min | None |
| **3a** | OQ-1: TG-1 CHART deep dive | Beaufort(KRYPTOS, CHART) analysis | 15 min | None |
| **3b** | OQ-1: TG-5 keystream derivation | Crib positions in 7x5 grid | 10 min | None |
| **3c** | OQ-1: TG-2 fold line mapping | Chart geometry vs table | 20 min | None |
| **4a** | OQ-5: Polybius grid as key source | Grid reading orders | 10 min | None |
| **4b** | OQ-5: Grid coordinate key function | f(row, col) mod 26 | 15 min | None |
| **4c** | OQ-5: Full backward propagation | Compliance scoring of surviving families | 30 min | 4a, 4b |

**Total estimated compute: ~3 hours**
**All phases are independent except where noted; parallelism possible.**

---

## 11. Risk Assessment

### 11.1 Risk: All Computational Tests Yield Negative Results

**Probability:** Medium-high (40-60%). The stego layer may be fully determined by the physical encoding chart, which we do not possess.

**Mitigation:** Negative results are still valuable. They formally establish that the stego mechanism is NOT derivable from the ciphertext, cribs, or known keywords alone. This is itself a publication-worthy finding and would strengthen the case that the $962.5K encoding chart is the key artifact.

### 11.2 Risk: Overfitting to 17 Data Points

**Probability:** High for any model with more than 3-4 free parameters.

**Mitigation:** Every model with > 2 parameters must be validated against perturbation (flip 1-3 null positions) and convention robustness (AZ vs KA, A=0 vs A=1). Report LOO accuracy for all classification models.

### 11.3 Risk: Varying Null Positions Are Not Computationally Resolvable

**Probability:** Medium. The 396-mask finding shows the 7 varying positions have ZERO effect on crib matches, meaning the cipher layer cannot distinguish between them.

**Mitigation:** If the cipher cannot discriminate, the stego layer must. Phase 1 (character assignment) may provide the discriminator. If Phase 1 also fails, the varying positions require external information.

### 11.4 Risk: CHART/TOWER/LAYER Words Are False Leads

**Probability:** Medium-high. 0.5% of random 5-letter words produce perfect table separation. CHART/TOWER/LAYER are thematic but not statistically significant.

**Mitigation:** Pursue CHART as a hypothesis only if it connects to other K4 parameters (palette, keystream, chart geometry). Do not invest compute in exploring it if the first-order checks fail.

---

## 12. Artifacts and Deliverables

### Scripts to Create
1. `scripts/analysis/e_null_char_assignment.py` — Phase 1 (OQ-3)
2. `scripts/analysis/e_varying_null_resolution.py` — Phase 2 (OQ-2)
3. `scripts/analysis/e_table_generation_deep.py` — Phase 3 (OQ-1)
4. `scripts/analysis/e_grid_key_generation.py` — Phase 4 (OQ-5)

### Results to Produce
1. `results/null_char_assignment.json` — Phase 1 results
2. `results/varying_null_resolution.json` — Phase 2 results
3. `results/table_generation_deep.json` — Phase 3 results
4. `results/grid_key_generation.json` — Phase 4 results

### Memory Updates
- `MEMORY.md` — After each phase
- `memory/elimination_ledger.md` — For any new eliminations (if that file is created)
- `memory/confirmed_findings.md` — For any new confirmations (if that file is created)
- `docs/constraint_spec.md` — If constraints are tightened

---

## 13. Success Criteria for the Overall Plan

| Outcome | Assessment |
|---------|------------|
| 1+ mechanism model achieves 17/17 null char prediction | **BREAKTHROUGH** — stego algorithm identified |
| Varying nulls narrowed to < 10 candidates | **SIGNIFICANT** — mask nearly complete |
| CHART (or other word) connects table to palette and keystream | **SIGNIFICANT** — third keyword identified |
| Grid-based key generation matches 24/24 keystream | **SOLUTION** — K4 decrypted |
| All tests negative | **VALUABLE** — stego layer formally proven chart-dependent |

---

## 14. Appendix: The Varying Nulls and the False-Positive Connection

This is the single most promising cheap test in the entire plan. Let me state the hypothesis precisely.

**Hypothesis VP-1:** The 7 varying null positions are drawn from the 16 non-palette positions that the (pos%7, pos%5) table misclassifies as "null."

**Evidence for VP-1:**
- The table classifies 26 cells as N (null) or R (real). When applied to ALL 97 positions (not just palette positions), 16 non-palette positions fall in N cells: {4,15,17,24,37,39,40,43,49,50,55,71,72,87,90,94}.
- Known varying null ranges overlap with this set: {39,40,43} in {38-45}, {55} in {54-56}, {87} in {87-88}, {94} in {93-96}. That is 6 positions.
- Position 4 and 15 are close to consensus nulls {2,5} and {14}. Position 17 is in the gap between consensus nulls 14 and 20. Positions 49,50 are between consensus nulls 36 and 52. Position 71 is in the BCL crib range (EXCLUDED by S6). Position 72 is at the BCL crib boundary. Position 90 is in the gap between consensus nulls 85 and end.

**If VP-1 is correct:**
- Remove positions in crib ranges (71, 72, and 24 — pos 24 is in ENE crib range [21-33]): leaves 13 candidates.
- We need 7 from 13 = C(13,7) = 1,716 masks to test.
- With the additional constraint that varying nulls must avoid cribs, this is a VERY tractable search.

**Test:** Enumerate C(13,7) = 1,716 masks. For each, apply the best cipher model and score against cribs. Check which (if any) exceed the 15/24 ceiling.

**Why this might break the ceiling:** The 15/24 ceiling was established with the DEFECTOR:AZ_beau+col7 model, which is now structurally eliminated (autokey impossible). A different cipher model on a CORRECT mask might exceed 15/24.

**Cost:** 1,716 masks x ~10 cipher models = ~17,000 evaluations. Seconds.

---

*End of design spec. Total estimated compute for all phases: ~3 hours. All phases produce falsifiable predictions with clear pass/fail criteria. Negative results are formally valuable as eliminations.*

*Generated: 2026-03-23 by Claude Opus 4.6 (steganalysis agent)*
