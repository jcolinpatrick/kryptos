# K4 Composition Campaign Report — v3 (Stateful / Architecture-Specific)

**Date:** 2026-04-06
**Framework:** `src/kryptos/composition/` v3 (added 6 nonstandard stateful layer families)
**Ledger:** `db/composition_ledger.sqlite`
**Campaign script:** `scripts/campaigns/f_composition_k4_v3_stateful.py`

## Executive Summary

Tested **5,245 stateful/architecture-specific compositions** across 9 campaigns in 3.1 seconds.
**Maximum score: 5/24** (3 branches, no Bean pass). Expected score >=5 by chance: ~10.2.
Observed: 3. **Below random expectation. No signal detected.**

Six new layer families were added to the composition framework:
1. Band-scheduled additive offsets (Berlin clock 1-4-4-11-4 structure)
2. Polarity switching (Vig/Beau/VarBeau per position class)
3. Progressive key (Fibonacci-like recurrence from seed)
4. State-selected alphabet (state schedule modifies effective key)
5. Band polarity (Berlin clock band selects cipher variant)
6. Compass-bearing offsets

All families tested as outer layers with identity inner, and selected families
tested as two-layer compositions with transposition inner layers.

---

## New Layer Families

### Band offset (`band_offset`)
Position-preserving. Each of the 5 Berlin clock bands (1-4-4-11-4) applies a
distinct additive shift. Parameterized by 5 offset values. 2,401 configurations
tested (7 prime-based offset values per band, band A fixed at 0).

### Polarity switch (`polarity_switch`)
Position-preserving. A periodic schedule selects Vigenere (0), Beaufort (1),
or Variant Beaufort (2) at each position. The key is still periodic. 18 distinct
schedules tested (periods 2-24, including Berlin-clock-derived patterns) x 8 keywords
= 144 configurations.

### Progressive key (`progressive_key`)
Position-preserving. Keyword seed generates a non-repeating key stream via
(k[i-1] + k[i-2]) mod 26 Fibonacci-like recurrence. Same generation rule as
Gromark family. 15 thematic keywords tested.

### State alphabet (`state_alphabet`)
Position-preserving. A state schedule cycles through N states; each state adds
a fixed offset to the base keyword key value at that position. 24 state configurations
(2-state, 3-state, 5-state, 24-state Berlin-clock-derived) x 8 keywords = 192.

### Band polarity (`band_polarity`)
Position-preserving. Each Berlin clock band selects one of 3 cipher variants
(Vig/Beau/VarBeau). All 240 non-trivial band-variant combinations (3^5 - 3 all-same)
x 8 keywords = 1,920 configurations.

### Compass offset (`compass_offset`)
Position-preserving. Keyword positions map to 8 compass bearings (letter value mod 8);
each bearing applies a distinct additive offset. 5 keywords x 9 offset sets = 45.

---

## Campaign Results

| Campaign | Family | Inner | Tested | Best | Expected>=4 |
|----------|--------|-------|--------|------|-------------|
| A: Progressive key | progressive_key | identity | 15 | 2 | 0.2 |
| B: Polarity switch | polarity_switch | identity | 144 | 4 | 1.8 |
| C: Band polarity | band_polarity | identity | 1,920 | 4 | 24.1 |
| D: State alphabet | state_alphabet | identity | 192 | 4 | 2.4 |
| E: Band offset | band_offset | identity | 2,401 | 4 | 30.1 |
| F: Compass offset | compass_offset | identity | 45 | 3 | 0.6 |
| G: Progressive+rail | progressive_key | rail_fence | 176 | 5 | 2.2 |
| G: Progressive+col | progressive_key | columnar | 96 | 3 | 1.2 |
| H: Polarity+rail | polarity_switch | rail_fence | 256 | 5 | 3.2 |
| **Total** | | | **5,245** | **5** | **65.8** |

Observed score>=4: 38. Expected: 65.8. **Below chance.**
Observed score>=5: 3. Expected: 10.2. **Below chance.**

---

## Score Distribution

| Score | Observed | Expected (binomial) | Ratio |
|-------|----------|-------------------|-------|
| 0 | 1,872 | 2,048 | 0.91 |
| 1 | 2,137 | 1,965 | 1.09 |
| 2 | 909 | 903 | 1.01 |
| 3 | 289 | 265 | 1.09 |
| 4 | 35 | 56 | 0.63 |
| 5 | 3 | 9 | 0.33 |
| >=6 | 0 | 1.3 | 0.00 |

The deficit at score>=4 (38 observed vs 65.8 expected) likely reflects the
constrained parameter space: many configurations produce similar outputs when
the seed keyword is the same, reducing effective independence.

---

## Top Results (Score = 5)

| Outer | Inner | Peel | IC | Keyword |
|-------|-------|------|-----|---------|
| progressive_key | rail_fence(d=?) | outer_first | 0.0363 | EASTNORTHEAST |
| polarity_switch(sched=[0,0,1,1]) | rail_fence(d=?) | inner_first | 0.0378 | ABSCISSA |
| polarity_switch(sched=[0,0,1,1]) | rail_fence(d=?) | outer_first | 0.0378 | ABSCISSA |

All score-5 results are two-layer compositions with rail fence inner. No
single-layer stateful family exceeded score 4. No Bean pass on any result.

---

## What Changed Project Belief

**No stateful/architecture-specific family produces signal above random baseline.**

### Newly weakened hypothesis classes

1. **Band-scheduled offsets** — Berlin clock 1-4-4-11-4 band structure selecting
   additive shifts does not produce crib matches. 2,401 offset combinations tested.

2. **Polarity switching** — Cycling between Vig/Beau/VarBeau by any of 18 schedules
   (including band-derived, period-7, period-24) with thematic keywords produces no signal.

3. **Progressive key (Fibonacci recurrence)** — Non-repeating Gromark-style key
   generation from thematic seeds does not produce crib matches as a single layer.

4. **State-scheduled key modification** — Multi-state systems (2-state through
   24-state Berlin-clock) modifying effective key values produce no signal.

5. **Band polarity** — All 240 non-trivial band→variant assignments with 8 keywords
   produce no signal.

6. **Compass-bearing offsets** — Bearing-class-scheduled shifts with 5 keywords
   and 9 offset patterns produce no signal.

7. **Progressive + transposition and polarity + transposition** — Two-layer
   combinations of these stateful families with rail fence/columnar inner layers
   produce no signal beyond random.

### What remains open

- **Larger keyword spaces** for progressive key (the seed space is essentially
  unbounded; we only tested 15 thematic keywords)
- **Non-Fibonacci recurrence rules** (e.g., additive-with-carry, Lagged Fibonacci,
  digit-based recurrence from K2 numbers)
- **Alphabet mutation** (progressive alphabet rotation, not just key offset)
- **Multi-state transposition** (state-driven local permutation, not global)
- **Running-key + stateful combinations** (running key from external source
  combined with stateful mask)
- **Longer state schedules** with non-trivial transition rules
- **Keyed alphabet variants** (Quagmire tableau with stateful row/column selection)

---

## Framework Status

### Tests
- 26 new tests for stateful transforms: all pass
- 72 existing composition tests: all pass
- **Total: 98 tests passing**

### Ledger consistency
- All 9 v3 campaigns: **consistent**
- All prior v1+v2 campaigns: **consistent**
- Grand total across all versions: 37+ campaigns, 105K+ branches

---

## Artifacts

- **Transforms:** `src/kryptos/kernel/transforms/stateful.py`
- **Tests:** `tests/test_stateful_transforms.py` (26 tests)
- **Registry:** 6 new families in `src/kryptos/composition/registry.py`
- **Campaign script:** `scripts/campaigns/f_composition_k4_v3_stateful.py`
- **Summary:** `reports/composition_v3_summary.json`
- **Ledger:** `db/composition_ledger.sqlite`
