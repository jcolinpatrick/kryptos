# Berlin Clock Route/Permutation Hypothesis — Design Spec

**Date:** 2026-03-23
**Authors:** Colin Patrick + Claude (KryptosBot)
**Status:** Design approved, ready for implementation

---

## Problem Statement

The split-coordinate Polybius model reduces K4's cipher layer to 24 row-key values (mod 6) at the 24 crib positions. These values show no periodic structure and no simple mathematical relationship to NDYAHR or K2 coordinates.

**Core observation:** There are exactly 24 values and Berlin provides two public 24-position structures explicitly on-theme:
1. **Urania Weltzeituhr (World Clock)** — 24-sided column with timezone facets + wind rose
2. **Mengenlehreuhr (Set Theory Clock)** — 24 lamps arranged 1+4+4+11+4

**Hypothesis:** The row-key values are not in their natural order. A Berlin clock structure defines a ROUTING PERMUTATION that maps key positions to crib positions. Undoing the routing should reveal a simpler underlying key.

---

## The 24 Row-Key Values

Derived from CT and known PT at crib positions, under Beaufort convention on the 5×6 KA Polybius grid:

```
Crib positions: [21,22,23,24,25,26,27,28,29,30,31,32,33, 63,64,65,66,67,68,69,70,71,72,73]
Beaufort rows:  [ 4, 4, 1, 4, 1, 5, 0, 0, 5, 4, 1, 2, 1,  4, 2, 0, 1, 3, 3, 4, 2, 3, 1, 0]
Vigenere rows:  [ 0, 2, 5, 4, 1, 3, 0, 0, 1, 0, 5, 0, 1,  2, 4, 0, 1, 3, 3, 2, 2, 1, 5, 0]
```

Also test the full 26-value Beaufort keystream letters: `JLJODEGKUKKKLOCGGBGOKTRU`

---

## Phase 1: World Clock (Circular 24-Node)

**Priority: FIRST.** The row stream is a flat 24-term sequence. The World Clock is a circular 24-position object. Test whether the sequence lives on a circle.

### World Clock Structure
- 24 timezone facets arranged clockwise, labeled with city names
- Wind rose on the pavement below (directional — connects to EASTNORTHEAST)
- Historical: focal point of Oct 7, 1989 protest shortly before the Wall fell
- 24-sided column is a regular polygon — all rotations are natural

### Walks to Generate (circular permutations)
1. **24 rotations** — start reading from facet 0, 1, ..., 23 (clockwise)
2. **24 rotations reversed** — same but counterclockwise
3. **Step-k walks** — visit every k-th facet (k=1..23), both directions. Generates cyclic subgroups.
4. **Boustrophedon** — CW for first half, CCW for second (and vice versa)
5. **Reflection** — reverse the entire sequence
6. **ENE-anchored** — if the wind rose has a NNE/ENE direction, align that facet to crib position 0

**Total circular walks:** ~120-150

### For Each Walk (permutation π)
Apply π to the 24 row values. On the permuted sequence, check:

1. **Periodicity** — does it repeat with period ≤ 12?
2. **Keyword match** — do the permuted row values match any known keyword's KA row projection? Test: KRYPTOS, PALIMPSEST, ABSCISSA, BERLINCLOCK, SEVEN, CHART, DEFECTOR, SHADOW, ENIGMA, ORDINATE, EASTNORTHEAST + 50 thematic words.
3. **Low IC** — is IC significantly above random 0.167?
4. **Mathematical sequence** — linear, quadratic, Fibonacci mod 6?
5. **Palindrome / symmetry** — is the permuted sequence palindromic or has reflection symmetry?
6. **Full-alphabet recovery** — permute the full keystream letters JLJODEGKUKKKLOCGGBGOKTRU. Does any permutation produce a recognizable word/fragment?

### Success Criteria
- Permuted sequence has period ≤ 7 → **SIGNAL** (keyword-length periodicity)
- Permuted keystream spells a word → **BREAKTHROUGH**
- IC jumps above 0.25 under any permutation → **INVESTIGATE**

---

## Phase 2: Mengenlehreuhr (Banded 1+4+4+11+4)

**Priority: SECOND.** Test whether the banded structure adds explanatory power beyond the circular model.

### Mengenlehreuhr Structure
```
    [S]                          ← Band 0: 1 lamp (seconds blinker)
  [H5 H5 H5 H5]                 ← Band 1: 4 lamps (5-hour blocks)
  [H1 H1 H1 H1]                 ← Band 2: 4 lamps (1-hour blocks)
[M5 M5 M5 M5 M5 M5 M5 M5 M5 M5 M5]  ← Band 3: 11 lamps (5-minute)
  [M1 M1 M1 M1]                 ← Band 4: 4 lamps (1-minute blocks)
```

### Current Segmentation (Beaufort)
```
Band 0: [4]                              ← single value
Band 1: [4, 1, 4, 1]                     ← alternating pattern
Band 2: [5, 0, 0, 5]                     ← PALINDROME
Band 3: [4, 1, 2, 1, 4, 2, 0, 1, 3, 3, 4]  ← longest band
Band 4: [2, 3, 1, 0]                     ← descending-ish
```

### Walks to Generate (banded permutations)
1. **Band-order permutations** — 5! = 120 orderings of the 5 bands
2. **Within-band direction** — 2^5 = 32 (L→R or R→L per band)
3. **Serpentine** — alternating direction across bands
4. **Circular 11-band** — 11 starting positions for Band 3
5. **Combined** — top band-order × direction combos: 120 × 32 = 3,840 (capped to ~1,000 by pruning identical-result combos)

### For Each Walk
Same checks as Phase 1: periodicity, keyword match, IC, mathematical sequence, palindrome, full-alphabet recovery.

### Additional Band-Specific Checks
- Do any band orderings make ALL bands individually simple (constant, palindrome, or arithmetic)?
- Does reversing Band 2 ([5,0,0,5] → still palindrome) while reversing Band 3 produce structure?
- Does any band ordering align with K2 coordinate numbers (38, 57, 6.5, 77, 8, 44)?

---

## Phase 3: Cross-Validation

If either Phase 1 or Phase 2 finds a permutation that simplifies the row key:

1. **Full ciphertext test** — apply the same routing to ALL 97 (or 73) positions, not just cribs. Decrypt and score.
2. **Bean constraint check** — does the un-routed key still satisfy k[27]=k[65] and all 242 inequalities?
3. **Stego consistency** — does the routing interact with the null mask? (It shouldn't if the systems are truly orthogonal.)
4. **Hand-executability** — can Sanborn physically perform this routing with a picture of the clock and a grid?

---

## Implementation Notes

- Script: `scripts/fractionation/e_berlin_clock_route.py`
- Results: `results/e_berlin_clock_route.json`
- All 24 row values computed from `kryptos.kernel.constants` (CT, CRIB_DICT, KRYPTOS_ALPHABET)
- No external dependencies (stdlib only)
- Score each permutation, store all results above threshold, report best

---

## What This Tests

| If World Clock rotation k simplifies the row key... | Then... |
|------------------------------------------------------|---------|
| Permuted sequence is periodic with period 7 | The key is KRYPTOS (or another 7-letter word) applied in clock order |
| Permuted keystream spells a word | The keystream itself IS a message routed through the clock |
| Band 3 (11 values) becomes BERLINCLOCK-minus-1 row values | The cribs are self-referential — they describe the method |
| No permutation helps | The clock is thematic but not operational |

---

*Spec version 1.0 — 2026-03-23*
