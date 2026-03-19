---
name: k-section-parallel
description: This skill should be used when reasoning about K4 through the lens of K1, K2, and K3. Formalizes the progressive solve pattern where solved sections predict unsolved section properties. Trigger when the user mentions "K1 and K2 use the same", "like K3", "same method", "parallel between sections", "what does K3 tell us about K4", "encoding chart format", "progressive solve", "same grid", "same transformation", or draws any analogy between solved and unsolved Kryptos sections. Also use when proposing a new K4 hypothesis to check whether it's consistent with the K1-K2-K3 progression.
---

# K-Section Parallel Analyzer

Reason about K4 by extracting patterns from K1, K2, and K3.
The Kryptos sculpture has a deliberate progressive structure — each
section builds on the previous. Properties that are consistent across
K1-K3 are strong predictors for K4.

## The Progressive Structure

### Tier 1: Properties shared by ALL three solved sections

These are the strongest predictors. K4 almost certainly shares them.

| Property | K1 | K2 | K3 | K4 Prediction |
|----------|----|----|----|----|
| **Alphabet** | KA (KRYPTOS-mixed) | KA | KA (implicit in dims) | KA |
| **Encoding chart format** | 31-col grid, PT/KEY/CT rows | Same | Same (14×24 worksheet) | Same format — 14×7 grid (?+K4=98=14×7) |
| **Keyword cycling** | Continuous across rows | Continuous | N/A (transposition) | Continuous |
| **All 26 letters present** | Yes | Yes | Yes | Yes (confirmed) |
| **Source text in English** | — | — | Howard Carter journal | English source |
| **Deliberate misspellings** | IQLUSION (→K in KA) | UNDERGRUUND | DESPARATLY (→A, grid shaping) | Possible — watch for anomalies |

### Tier 2: Properties shared by K1 and K2 (the substitution pair)

K1 and K2 share the same method (KA Vigenère) with different keywords.
If K3 and K4 are the analogous pair, they share the same transformation
with different parameters.

| Property | K1 | K2 | Parallel for K3→K4 |
|----------|----|----|-----|
| **Same cipher type** | Vigenère | Vigenère | K4 uses same transformation type as K3 |
| **Different keyword** | PALIMPSEST | ABSCISSA | K4 uses different keyword than KRYPTOS |
| **Same grid width** | 31 cols | 31 cols | K4 chart has same 14-col width as K3 chart |
| **K2 encodes K3 dims** | — | 38→24, 77→14, 8→8 | K4 dims may be encoded somewhere |

### Tier 3: Properties unique to K3 (the transposition section)

K3 introduces transposition. K4 may extend this with stego.

| K3 Property | Value | K4 Implication |
|-------------|-------|----------------|
| **Pure transposition** | No substitution | K4 adds "a bit of stego" (Scheidt) |
| **Double rotation** | 24×14 → 8×42 | K4 may use double rotation with different dims |
| **Self-inverting** | Same operation encrypts and decrypts | K4 mechanism may also be self-inverting |
| **All dims multiples of 7** | 14=2×7, 42=6×7, 24=? | K4 dims likely involve 7 (KRYPTOS length) |
| **Code chart = 14×24** | Read columns bottom-to-top | K4 chart = 14×7 (same width, 7 rows) |
| **ENDYAHR at starting corner** | Bottom-left of grid | K4 may have similar structural annotation |
| **336 chars fills grid exactly** | 14×24 = 336 | 14×7 = 98 = ?+K4 fills grid exactly |

## The K3/K4 Parallel (the core hypothesis)

This is the user's central analytical framework:

```
K1/K2 relationship:
  Same method (KA Vigenère)
  Different keywords (PALIMPSEST, ABSCISSA)
  Same grid (31 columns)

K3/K4 relationship (predicted):
  Same transformation (double rotation? encoding chart lookup?)
  Different keyword (KRYPTOS → ???)
  Same grid (14 columns, 24 rows)
  K4 ADDS stego (null insertion)
```

### What "same transformation + stego" means operationally

For K3: PT → transposition → CT (336 chars)
For K4: PT → transposition → intermediate → null insertion → CT (97 chars)

Or equivalently:
For K4: CT (97) → null removal (73) → inverse transposition → PT

The stego layer is the "extra" that K4 has over K3.

## Key Arithmetic

These relationships constrain K4's grid dimensions:

```
K3 chart:  14 × 24 = 336
K4 chart:  14 × 7  = 98  (with ? prefix)
           14 = 2 × 7 = 2 × len(KRYPTOS)
           24 + 7 = 31 = panel width
           336 + 1 + 97 = 434 = 14 × 31

K3 encryption grids: 24×14 → 8×42
  All multiples of 7: 14=2×7, 42=6×7
  Products: 24×14 = 8×42 = 336

K4 candidate grids (factors of 73, if 73 real chars):
  73 is PRIME → no rectangular grid
  But 72 = 8×9 = 6×12 = 4×18 = 3×24 = 2×36
  And 98 = 2×49 = 7×14
```

## Using This Skill

### When evaluating a K4 hypothesis:

Check it against all three tiers:

1. **Tier 1 (mandatory):** Does it use KA? Does it fit the encoding
   chart format? Is the source English?
2. **Tier 2 (strong):** Is the transformation type consistent with K3?
   Does it use a different keyword? Does the grid share dimensions?
3. **Tier 3 (suggestive):** Are dimensions multiples of 7? Is the
   mechanism self-inverting? Does it add exactly one layer (stego)
   beyond K3?

### When generating new hypotheses:

Start from the parallel and ask:
- "What transformation uses a 14×7 grid?"
- "What cipher is self-inverting with these dimensions?"
- "What mechanism can Sanborn do with graph paper and no computer?"
- "What adds 24 nulls to 73 chars using KRYPTOS×SEVEN?"

### When stuck:

Return to the encoding chart. The chart is the Rosetta Stone.
K1-K2 chart shows: PT row, KEY row, CT row. Same format for K4.
The KEY row identifies the keyword. The procedure visible in the
chart IS the cipher method. Studying the K1-K2 chart "in a forensic
manner" (Sanborn) means understanding the PROCESS, not finding
hidden data.

## What We Know About the K4 Chart

From the K1-K2 chart analysis:
- 31-column grid on graph paper
- PT/KEY/CT in triplet rows
- X delimiters ARE encrypted (keyword advances through them)
- ? marks are NOT encrypted (keyword does NOT advance)
- Column 0 has margin overflow characters
- Keyword cycles continuously, no restart at row boundaries
- PALIMPCEST misspelled in header, correct in KEY rows
- KA Vigenère confirmed (62/63 match on K1)

The K4 chart (owned by the auction buyer, $962.5K) would show:
- The KEYWORD written at the top
- The specific cipher operation (Beaufort? Vigenère? Something else?)
- Whether the 14×7 grid is used
- How null insertion positions are determined
- Any intermediate transposition steps

## Unsolved Parallels

Questions where the K1-K2-K3 pattern doesn't give a clear answer:

1. **Is K4 substitution or transposition?** K1-K2 = substitution,
   K3 = transposition. K4 could be either, or a combination.
2. **Does the keyword come from an earlier section?** K1's keyword
   PALIMPSEST appears in K1's own PT. K2's keyword ABSCISSA doesn't.
   K3's keyword KRYPTOS is the sculpture name. K4's keyword = ?
3. **Is ID BY ROWS / LAYER TWO operationally significant?** The last
   phrase of K2 on the sculpture. Could be instructions for K3/K4.
4. **Does DESPARATLY-style grid shaping apply to K4?** K3 shortened
   a word to make 336 = 14×24 exact. K4 is already 97 (prime).
   Adding ? gives 98 = 14×7. Was the ? added for this purpose?
