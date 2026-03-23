# Stego Mechanism Formalization — Design Spec

**Date:** 2026-03-23
**Author:** Colin Patrick + Claude (Opus 4.6)
**Status:** Approved
**Goal:** Formalize the K4 stego layer as a generative specification (B), propagate constraints to the cipher layer (C), resolve the 7 varying null positions as a downstream consequence (A).

---

## Prior Findings: Two Scoring Methodologies

Two separate analyses found CHART under different conditions:

| Finding | Variant | Scoring | Cells | Null-value set | Source |
|---------|---------|---------|-------|----------------|--------|
| `e_mod35_table_derivation.py` | Beaufort AZ | All 26 occupied cells (incl. mixed) | 26/26 | {D,I,M,N,O,P,Q,T,U,Y} (10 letters) | `results/mod35_table_derivation.json` |
| `e_table_generation_deep.py` | Vigenère AZ | 23 pure cells only (excl. 3 mixed) | 23/23 | {D,I,M,P,Q,T,U,Y} (8 letters) | `results/table_generation_deep.json` |

The Beaufort result classifies more cells (26 vs 23) but uses a larger null set (10 vs 8 letters), which makes the partition less constrained. The Vigenère result is more parsimonious (8-letter null set on 23 pure cells). TOWER:beaufort_az and LAYER:beaufort_ka also achieve 23/23 on pure cells.

**This spec uses the pure-cell scoring (23/23) as the primary methodology.** Pure cells are unambiguous ground truth; mixed cells require a tiebreaker rule that is itself under investigation (B4). Both variants (Beaufort and Vigenère) are tested throughout. The Beaufort 26/26 result is tracked as a secondary finding.

Prior exhaustive sweep (`e_mod35_table_derivation.py`) found ~58,682 of 11.88M AZ strings achieve perfect separation under the all-occupied scoring. Phase B2 re-runs under the pure-cell scoring to get the correct count.

---

## Problem Statement

We have a descriptive fit: `CHART:vigenere_az` classifies 23/23 occupied pure cells of the 7×5 `(pos%7, pos%5)` lookup table. But a descriptive fit is not a generative specification. To be operationally useful, we need:

1. **The partition rule must have algebraic structure** — the null output set {D,I,M,P,Q,T,U,Y} must be derivable from the system's keywords/grid, not fit from data.
2. **CHART must be thematically unique** — or the word doesn't matter and only the partition does.
3. **The mechanism must predict the 7 varying nulls** — or at least narrow them beyond crib-degenerate C(15,7)=6,435.
4. **At least one new cipher constraint must emerge** — stego formalization must tighten the cipher search space.

## Success Criteria

| Level | Criterion | Threshold |
|-------|-----------|-----------|
| **S1** | Partition rule has algebraic structure | Derivable from Polybius grid, keyword, threshold, or modular rule — not arbitrary |
| **S2** | CHART is thematically unique among perfect words | Among English dictionary words achieving 23/23, CHART is the most thematically coherent for Kryptos (coding charts, Sanborn's process). Prior sweep found ~0.5% of all 5-letter strings work, so hundreds of English words likely qualify — thematic coherence, not count, is the discriminator |
| **S3** | Mechanism predicts varying nulls | Predictions match ≥5/7 (baseline: ~2.7/7 random) |
| **S4** | New cipher constraint emerges | At least one cipher property is newly constrained by the stego spec |

## Failure Criteria

| Condition | Implication |
|-----------|-------------|
| Among English 23/23 words, multiple are equally or more thematically relevant than CHART | The word choice is not uniquely determined — partition is the real finding |
| CHART's partition {D,I,M,P,Q,T,U,Y} has no structural interpretation under any framework | Classification is descriptive, not generative — Phase B fails |
| Varying null predictions match ≤3/7 | Mechanism is incomplete — explains consensus only |
| No new cipher constraint beyond existing CxS-1..4 | Stego formalization is correct but cryptanalytically inert |

---

## Phase B1: Simplicity Tests

**Purpose:** Prove that a 3-keyword system is NECESSARY by showing simpler alternatives fail.

### B1.1: SEVEN Direct

For each of 4 cipher variants (beaufort_az, vigenere_az, beaufort_ka, vigenere_ka):
- Compute `Cipher(KRYPTOS[r], SEVEN[c])` for all 35 cells
- Find the optimal partition of 26 output values into null/real (maximize classification of 23 occupied pure cells)
- Test threshold rules: null iff output < T (for T = 0..25)
- Test modular rules: null iff output mod M ∈ S (for M = 2..6)

**Kill condition:** If any variant achieves 23/23 with a STRUCTURED partition (threshold, modular rule, or Polybius region — not merely a data-fit optimal partition) → CHART unnecessary. Achieving 23/23 with an arbitrary induced partition does NOT kill CHART, since ~0.5% of all 5-letter strings achieve this.

### B1.2: Single-Shift Parameter

For each shift s = 0..25, each of 4 variants:
- Compute `Cipher(KRYPTOS[r], s)` for all 35 cells (constant column key)
- Find optimal partition, score against 23 cells

**Kill condition:** If any shift achieves 23/23 → no column keyword needed at all.

### B1.3: Short Keys (2-letter cycling)

For each of 676 2-letter keys, each of 4 variants:
- Compute `Cipher(KRYPTOS[r], KEY[c % 2])` for all 35 cells
- Score as above

**Kill condition:** If any 2-letter key achieves 23/23 with structured partition → simpler than CHART.

**Compute estimate:** <1 minute total for all B1 tests.

---

## Phase B2: Exhaustive Word Sweep

**Purpose:** Characterize the full landscape of 5-letter strings that achieve 23/23.

### B2.1: Full 26^5 Sweep

For each of 11,881,376 five-letter strings × 4 cipher variants:
- Compute `Cipher(KRYPTOS[r], WORD[c])` for all occupied cells
- Induce null-value set from pure-null cells
- Score against all 23 occupied pure cells
- Record all words scoring ≥21/23

### B2.2: Statistical Characterization

From sweep results:
- Count of 23/23 words per variant
- Score distribution (histogram)
- Among 23/23 words: how many are in `wordlists/english.txt`?
- Among English 23/23 words: rank by thematic relevance to Kryptos (manual review of short list)

### B2.3: Partition Equivalence Classes (PRIMARY OBJECTIVE of B2)

**This is the most important question in Phase B2.** If all 23/23 words for a given variant produce the SAME partition, then the partition is uniquely determined by the table structure + variant, and the word is irrelevant. This would mean we need to understand the PARTITION, not the WORD.

Group all 23/23 words by the null-value set they produce:
- How many distinct partitions achieve 23/23?
- Which partition is most common?
- Is CHART's partition {D,I,M,P,Q,T,U,Y} = {3,8,12,15,16,19,20,24} common or rare?
- Do all 23/23 words for a given variant produce the SAME partition?
- If multiple partitions work: what distinguishes them? (partition size, structure, relationship to palette)

**Compute estimate:** ~20 minutes on 28 cores (4 variants × ~12M evaluations, embarrassingly parallel).

---

## Phase B3: Partition Rule Analysis

**Purpose:** Determine whether {D,I,M,P,Q,T,U,Y} (or whatever partition emerges as canonical) has algebraic structure.

### B3.1: Polybius Grid Mapping

Map null-output letters to positions in both grids:

**KA 5-wide grid:**
```
     c0  c1  c2  c3  c4
r0:  K   R   Y   P   T
r1:  O   S   A   B   C
r2:  D   E   F   G   H
r3:  I   J   L   M   N
r4:  Q   U   V   W   X
r5:  Z
```

**AZ 5-wide grid:**
```
     c0  c1  c2  c3  c4
r0:  A   B   C   D   E
r1:  F   G   H   I   J
r2:  K   L   M   N   O
r3:  P   Q   R   S   T
r4:  U   V   W   X   Y
r5:  Z
```

For {D,I,M,P,Q,T,U,Y}:
- AZ positions: D=(0,3), I=(1,3), M=(2,2), P=(3,0), Q=(3,1), T=(3,4), U=(4,0), Y=(4,4)
- KA positions: D=(2,0), I=(3,0), M=(3,3), P=(0,3), Q=(4,0), T=(0,4), U=(4,1), Y=(0,2)

Test: Do these form a contiguous region? A row set? Column set? Diagonal? Specific residue class in row×col space? Convex hull? Complement of a simpler region?

### B3.2: Set-Theoretic Relationships

- Complement of {D,I,M,P,Q,T,U,Y} = {A,B,C,E,F,G,H,J,K,L,N,O,R,S,V,W,X,Z} (18 letters)
- Intersection with palette {B,G,I,K,O,W,Z} = {I} (single letter). **Note:** null-output set and null palette are nearly disjoint — the cipher's "null-marking outputs" are almost entirely distinct from the "letters used as null characters." This asymmetry may be structurally significant.
- Intersection with KRYPTOS = {T,Y,P} (3/7)
- Intersection with SEVEN = {} (verify)
- Intersection with CHART = {T} (verify)
- Is the complement a keyword or contains a recognizable word?
- Is the set itself a keyword anagram?

### B3.3: Numerical Structure

Under AZ indexing: {3,8,12,15,16,19,20,24}
- Consecutive differences: 5,4,3,1,3,1,4
- Mod-5 residues: {3,3,2,0,1,4,0,4} — all 5 present
- Mod-6 residues: {3,2,0,3,4,1,2,0} — all 6 present
- Mod-7 residues: {3,1,5,1,2,5,6,3} — missing 0,4
- Mod-13 residues: {3,8,12,2,3,6,7,11}
- Sum: 3+8+12+15+16+19+20+24 = 117 = 9×13
- Is 117 significant? 26×(26-1)/2 = 325; 117/325 = 0.36
- Bit patterns (5-bit): check for mask or XOR relationship

Repeat under KA indexing.

### B3.4: Generative Tests

- Is {D,I,M,P,Q,T,U,Y} = Cipher(keyword, alphabet_subset) for some short keyword?
- Is it = {letters whose AZ index has bit B set} for some bit position B?
- Is it = {letters at distance ≤ D from some seed letter in some metric}?
- Is it = output of a simple substitution applied to another recognizable set?

### B3.5: Cross-Layer Test

Compare null-output values {3,8,12,15,16,19,20,24} to Model B Beaufort keystream values at crib positions. Compute:
- Set intersection
- Additive inverses mod 26
- Differences
- Any pairwise relationship

**Compute estimate:** <1 minute (all analytical, no search).

---

## Phase B4: Mixed Cells and Varying Nulls

### B4.1: Tiebreaker Formalization

The 3 mixed cells (each with 1 null + 1 real palette position):
- (0,0): null at pos 0, real at pos 70
- (2,3): null at pos 58, real at pos 93
- (5,2): null at pos 12, real at pos 47

In all 3 cases: null position < real position → "first occurrence wins."

Test whether this is:
(a) A consequence of the Vigenère output value (it's not — both positions produce the same cell output)
(b) A positional rule (first in reading order = null)
(c) A character-dependent rule (the specific CT letter at each position determines tiebreak)
(d) An artifact of the 24-null budget (17 consensus nulls + 7 varying; if we assigned BOTH positions as null in mixed cells, we'd have 20 consensus nulls, requiring only 4 varying — is that consistent?)

### B4.2: False-Positive Model for Varying Nulls

Count non-palette positions in "null" cells of the 7×5 table:
- Identify all positions p where table cell (p%7, p%5) is classified as null but CT[p] ∉ palette
- Compare this set to the 15 candidate varying null positions from prior VP-1 analysis
- If the count is exactly 7 (or close), test whether these positions ARE the 7 varying nulls

### B4.3: Position-Only Rule and Secondary Filter

The position-only rule "null iff (p%7, p%5) cell is null, regardless of CT character" produces ~39 null positions (verified from prior work) — 15 more than the target 24. So the palette restriction IS necessary as a primary filter, and the question is what secondary filter resolves the remaining positions.

Test secondary filter candidates:
- **CT character in palette** → produces exactly 17 consensus nulls (already known). The 22 non-palette positions in null cells include the 7 varying nulls + 15 extras. Need a THIRD criterion.
- **Positional budget**: if the system targets exactly 24 nulls, and 17 are palette-in-null-cell, then exactly 7 non-palette positions in null cells must also be null. Which 7 of the ~22? Test whether any simple rule (first N per cell, per-row budget, per-column budget) selects exactly 7.
- **Character-dependent tiebreak**: among non-palette characters in null cells, does some character property (frequency, AZ index, KA index) predict null vs real?

### B4.4: Varying Null Prediction Validation

Whatever prediction B4.2/B4.3 produce, validate against:
- Bean constraints (does the predicted full mask produce Bean EQ pass?)
- n-gram quality of the resulting 73-char text
- Keystream consistency at non-crib positions (if any varying nulls are adjacent to cribs)

**Compute estimate:** <5 minutes.

---

## Phase B5: Full Generative Specification

Synthesize B1–B4 into a complete, testable specification. **Note:** Palette generation (KRYPTOS × SEVEN dual-keyword rule) is assumed validated from prior work (`memory/kryptos_seven_palette_generation.md`, p≈1/1672). This spec does not re-test it.

```
STEGO SPECIFICATION v1.0 (candidate)

INPUTS:
  CT: 97-character K4 carved ciphertext
  Keywords: KRYPTOS (7), SEVEN (5), [CHART (5) if B1 fails]
  Grid: KA alphabet, 5-wide Polybius
  Cipher: Vigenère on AZ (or per B1/B2 results)

PALETTE GENERATION:
  On KA 5-wide grid:
    For each row r (0-5):
      If any KRYPTOS letter occupies cols 0-2 of row r → select col 0
      If any SEVEN letter occupies cols 0-2 of row r → select col 3
      If both → select both
      If neither → select col 0 (default)
    Palette = union of selected letters
    → {B,G,I,K,O,W,Z}

POSITION CLASSIFICATION:
  For position p in [0,96]:
    output = Vigenère_AZ(KRYPTOS[p%7], CHART[p%5])
    null_cell = (output ∈ NULL_SET)  [NULL_SET from B3]

  Classification:
    If CT[p] ∈ palette AND null_cell → CONSENSUS NULL
    If CT[p] ∉ palette AND null_cell → VARYING NULL (tiebreaker from B4)
    If NOT null_cell → REAL

NULL CHARACTER ASSIGNMENT:
  → Requires encoding chart (not publicly derivable — NC-1 through NC-7)

PREDICTIONS:
  Consensus nulls: [list 17 positions]
  Varying nulls: [list 7 predicted positions]
  Total: 24
```

**Test:** Give the spec to an independent implementation (clean Python script with no access to the data files). Does it reconstruct the consensus null positions?

---

## Phase C: Constraint Propagation to Cipher

### C1: Palette-Enriched Keystream

If the stego mechanism is confirmed generative (not just descriptive), the coupling CxS-1 (13/24 keystream values in palette) becomes a HARD constraint on the cipher mechanism. Any proposed cipher must naturally produce this enrichment level.

**Propagation:** For each candidate cipher mechanism, compute expected palette membership of keystream values. Reject if expected < 10/24 (2σ below observed 13/24).

### C2: AP {G,K,O} Structural Requirement

G=6, K=10, O=14 form an arithmetic progression with step 4 in AZ. Under KA, these are at rows 2, 0, 1 respectively. If the cipher operates on Polybius rows (split-coordinate model), the AP becomes a row-clustering constraint.

**Propagation:** The cipher key at 12/24 crib positions must produce a Polybius row that maps to G, K, or O. This is a strong filter for any row-based key hypothesis.

### C3: Row-Key Sequence

The 24 mod-6 row values are: `[4,4,1,4,1,5,0,0,5,4,1,2,1,4,2,0,1,3,3,4,2,3,1,0]`

With the stego mechanism confirmed, we know these are real (not artifacts of an incorrect mask). This sequence is the PRIMARY target for cipher-layer attacks:
- Non-periodic (proven)
- Not autokey (proven)
- Not NDYAHR/K2-derived (tested)
- Not Berlin Clock-routed (tested)
- IC = 0.1558 (below random 0.1667 for 6 values — slightly flatter than expected, consistent with high-entropy key; not significant for n=24)

**New tests enabled by confirmed stego:**
- Test whether the row-key sequence is a running key through a mod-6 operation on a known text
- Test whether it's a substitution cipher output at the mod-6 level (only 6! = 720 permutations). Test substitution of: (a) sequential position index mod 6, (b) CT letter at crib position mod 6, (c) plaintext letter at crib position mod 6, (d) column key at crib position mod 5 (with 0-padding for the 6th value)
- Test whether it's generated by a state machine on the Polybius grid

### C4: Partition-Cipher Interaction

If the null-output set has Polybius structure (B3), test whether the cipher avoids or targets the same Polybius region. Specifically: do the 24 keystream values (as AZ letters) avoid the null-output set? Or preferentially fall in it? Either would be a constraint.

### C5: Mask-Conditioned Cipher Re-test

With the mechanism-predicted mask (from B4), extract the 73-char real text. Re-run:
- Periodic substitution (sanity check — should still fail)
- Split-coordinate analysis (row keys may change slightly if mask differs from consensus)
- n-gram quality comparison between mechanism-predicted mask vs consensus mask

**Compute estimate:** C1-C4 are analytical (<1 min). C5 is a targeted re-run (~10 min).

---

## Implementation Plan

### Scripts (in `scripts/stego_mechanism/`)

| # | Script | Phase | Depends On | Compute |
|---|--------|-------|------------|---------|
| 1 | `e_simplicity_tests.py` | B1 | — | <1 min |
| 2 | `e_exhaustive_word_sweep.py` | B2 | B1 (only run if B1 fails) | ~20 min |
| 3 | `e_partition_analysis.py` | B3 | B2 results | <1 min |
| 4 | `e_mixed_cell_varying.py` | B4 | B3 results | <5 min |
| 5 | `e_full_spec_test.py` | B5 | B4 results | <1 min |
| 6 | `e_constraint_propagation.py` | C | B5 results | ~10 min |

### Dependency Graph

```
B1 (simplicity)
  │
  ├── if kills CHART → redefine B3 target partition, continue
  │
  └── if CHART survives → B2 (exhaustive sweep)
                             │
                             └── B3 (partition analysis) ← CRITICAL GATE
                                   │
                                   ├── if structured → B4 (mixed/varying)
                                   │                     │
                                   │                     └── B5 (full spec)
                                   │                           │
                                   │                           └── C (constraint propagation)
                                   │
                                   └── if arbitrary → STOP. Report descriptive finding.
                                                      C still runs on weaker constraints.
```

### Artifacts

All results to `results/stego_mechanism/`.
Spec updates to this document.
Memory updates to `memory/stego_mechanism_formalization.md`.
Elimination ledger updates if any hypothesis is killed.

---

## Conventions (k4-stego-cracker Step 0)

```
CONVENTIONS:
  Positions:      0-indexed (repo standard)
  Alphabet map:   A=0, B=1, ..., Z=25
  Cipher variant: Default Beaufort C=(K-P)%26 for keystream; Vigenère C=(P+K)%26 for table generation
  Grid alphabet:  KA (KRYPTOSABCDEFGHIJLMNQUVWXZ) for palette; AZ for table Vigenère
  Grid width:     5
  Null definition: Position is consensus null if CT[p] ∈ {B,G,I,K,O,W,Z} AND (p%7,p%5) cell = null
  Scope:          CT97 (full carved text)
```

**Why two cipher variants in one mechanism:** Beaufort is used for keystream derivation (it's the confirmed cipher-layer default, A=0). Vigenère is used for table generation because `CHART:vigenere_az` is the finding under test. If B1/B2 show Beaufort generates the table instead, the convention updates accordingly.

Convention changes between phases MUST be flagged.
