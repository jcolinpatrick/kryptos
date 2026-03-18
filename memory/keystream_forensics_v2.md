# Keystream Forensics V2 — Corrected Analysis (2026-03-15)

## Critical Bug Fix

The v1 keystream forensics script (`scripts/analysis/e_keystream_forensics.py`)
had a **crib position mapping bug**: it mapped CT97 crib positions through the
null mask AND col7 transposition, producing scrambled intermediate positions that
do NOT correspond to where cribs appear in the plaintext.

**Correct mapping**: After null removal, cribs shift to CT73 positions:
- ENE at CT73 positions 13..25 (n1=8 nulls before CT97 pos 21)
- BCL at CT73 positions 47..57 (n2=16 nulls before CT97 pos 63)

Since the model is `CT73 -> col7 transpose -> intermediate -> Beaufort decrypt -> PT`,
the PT positions = intermediate positions. Cribs at PT positions 13..25 and 47..57.

## Corrected Beaufort Keystream (24 crib positions in intermediate space)

```
Position: 13 14 15 16 17 18 19 20 21 22 23 24 25 | 47 48 49 50 51 52 53 54 55 56 57
Key:       H  X  X  L  M  T  W  D  V  P  S  O  U |  L  Y  J  B  Y  Y  X  I  S  N  Z
Value:     7 23 23 11 12 19 22  3 21 15 18 14 20 | 11 24  9  1 24 24 23  8 18 13 25
```

Letters: `HXXLMTWDVPSOULYJBYYXISNZ`

## Properties

- **IC = 0.0290** (0.75x random, BELOW random). Suggests high-entropy key source.
- **18 distinct values** out of 24 positions.
- **Palette {B,G,I,K,O,W,Z}**: only 5/24 = 20.8% (BELOW expected 26.9%). NOT enriched.
- **X(23) and Y(24)**: each appear 3x (most frequent). Adjacent values.
- **No period with 0 conflicts** at any period 1-26 for either Beaufort or Vigenere.
- **Nearest to consistent**: periods 22,23 with 2 conflicts each (due to sparse coverage).

## DEFECTOR Autokey: 15/24 Matches Identified

Matching positions: {13, 15, 16, 20, 22, 23, 25, 49, 50, 51, 52, 53, 54, 55, 56}
- ENE: 7/13 match (positions 13, 15, 16, 20, 22, 23, 25)
- BCL: 8/11 match (positions 49-56 = contiguous block of 8)

Miss positions: {14, 17, 18, 19, 21, 24, 47, 48, 57}
- ENE: 6 misses (positions 14, 17, 18, 19, 21, 24)
- BCL: 3 misses (positions 47, 48, 57)

## STRUCTURAL IMPOSSIBILITY PROOF: PT-Autokey

### The 3 "impossible" misses (feedback from correct crib)

For PT-autokey with offset=8: key[pos] = PT[pos-8]

At 3 miss positions, the feedback source IS a crib position with CORRECT PT:
- **miss@21**: key=PT[13]=E(4). Need key=V(21). CONTRADICTION (PT[13]=ENE[0]=E is FIXED).
- **miss@24**: key=PT[16]=T(19). Need key=O(14). CONTRADICTION (PT[16]=ENE[3]=T is FIXED).
- **miss@57**: key=PT[49]=R(17). Need key=Z(25). CONTRADICTION (PT[49]=BCL[2]=R is FIXED).

### Full crib-to-crib connection analysis (offset=8)

8 total crib-to-crib connections (both pos and pos-8 are crib positions):
- **7 are CONTRADICTIONS** (the autokey mechanism requires a different PT than the crib)
- **1 is consistent** (pos 23: key=PT[15]=S, needed key=S. Lucky coincidence.)

### All offsets tested (1-44)

| Offset | Connections | Contradictions | OK | Best% |
|--------|------------|----------------|-----|-------|
| 1 | 22 | 22 | 0 | 0.0% |
| 2 | 20 | 19 | 1 | 5.0% |
| 3 | 18 | 16 | 2 | 11.1% |
| 8 | 8 | 7 | 1 | 12.5% |
| 40 | 5 | 4 | 1 | 20.0% |

**NO offset achieves even 50% consistency.** Random expectation: 1/26 = 3.85%.
The best (offset=3 with 2/18) is only marginally above random.

### All 4 autokey variants tested

| Variant | Best offset | Best OK/total |
|---------|-----------|---------------|
| Beaufort PT-autokey | 3 | 2/18 (11.1%) |
| Beaufort CT-autokey | 39 | 2/11 (18.2%) |
| Vigenere PT-autokey | 1 | 3/22 (13.6%) |
| Vigenere CT-autokey | 4 | 3/24 (12.5%) |

**ALL 4 autokey variants are STRUCTURALLY IMPOSSIBLE** under this mask + col7.

## Error Propagation Analysis

The 15/24 score arises because:
- 8 crib positions have feedback from the primer (pos 13-20, with 8-char DEFECTOR primer)
  - 6 of these 8 produce correct PT (they're within the primer's direct reach)
  - 2 miss (pos 14 and 17-19 — 4 misses from non-crib feedback at pos 6,9,10,11)
- 16 crib positions have feedback from non-crib positions (pos 21-25, 47-57)
  - Non-crib PT values are FREE PARAMETERS (the model can produce any value there)
  - The 9/16 matches at these positions are coincidental alignment

The 3 crib-to-crib contradictions prove the mechanism is wrong, not just incomplete.

## Correction Vector (key deltas at 9 miss positions)

```
Positions: [14, 17, 18, 19, 21, 24, 47, 48, 57]
Values:    [11, 19, 19, 15, 17, 21,  9, 17,  8]
Letters:    L   T   T   P   R   V   J   R   I
```

- 7 distinct values (no constant correction)
- No periodicity found (tested periods 2-19)
- No keyword match (tested KRYPTOS, DEFECTOR, SEVEN, etc.)
- No simple function of position
- Spells "LTTPRVJRI" (no recognizable word)

## Bean Constraint

CT97[27] maps to intermediate position 57 (BCL[10]=K). Beaufort key = Z(25).
CT97[65] maps to intermediate position 46 (NOT a crib position).
Cannot verify Bean equality k[27]=k[65] because position 46 is non-crib.

DEFECTOR autokey: key[57]=R(17), key[46]=X(23). Bean VIOLATED in DEFECTOR model.

## Invalidated Prior Findings (from v1 bug)

The following findings from `memory/bcl_palette_keystream.md` and the statistical
validation need context correction:

1. **"BCL Beaufort keystream 7/8 palette (p=0.000627)"** -- This is VALID but it's
   a property of the RAW CT97 (no mask, no transposition). It does NOT apply to the
   transposed intermediate text where DEFECTOR:AZ_beau actually operates.

2. **"Keystream IC = 0.0797"** (from v1) -- WRONG. Correct IC = 0.0290.

3. **"Palette enrichment in keystream 13/24"** (from v1) -- WRONG in transposed space.
   Correct: 5/24 in transposed space. The 13/24 was at wrong positions.

4. **Fisher combined p = 1.4e-8** -- This combined (A) palette diversity (raw CT97 nulls)
   and (B) BCL keystream palette (raw CT97). BOTH are valid on raw CT97. The combined
   significance remains valid AS A PROPERTY OF THE CARVED TEXT, not of any cipher model.

## Implications

1. **DEFECTOR:AZ_beau PT-autokey is NOT the K4 cipher** (structural proof).
2. **The 15/24 score is a FALSE SIGNAL** from non-crib degrees of freedom.
3. **The correct keystream IC (0.029) is BELOW random** -- the key source has
   MORE entropy than a uniform random key. This rules out most keyword-based mechanisms.
4. **No periodicity at any period** -- consistent with running-key or position-dependent key.
5. The raw-CT97 palette enrichment remains valid and constrains the cipher design.

## Files

- Script: `/home/cpatrick/kryptos/scripts/analysis/e_keystream_forensics_v2.py`
- Result: `/home/cpatrick/kryptos/results/e_keystream_forensics_v2.json`
- Prior (buggy): `/home/cpatrick/kryptos/scripts/analysis/e_keystream_forensics.py`
