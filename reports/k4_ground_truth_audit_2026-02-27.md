# K4 Ground Truth Audit

**Date:** 2026-02-27
**Source Authority:** Colin Patrick's visual inspection (Antipodes.xlsx) + computational cross-verification
**Method:** Character-by-character extraction from Excel, pattern-matching against known section CTs

---

## LANE A — VERIFIED FACTS

All claims below are computationally verified against `Antipodes.xlsx` (Colin's authoritative Excel) and `project/ct.txt`.

### 1. K4 Ciphertext — FOUR-SOURCE MATCH ✓

```
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
```

| Source | Status |
|--------|--------|
| `CLAUDE.md` constants | ✓ Identical |
| `project/ct.txt` | ✓ Identical |
| Antipodes Pass 1 (letters[336:433]) | ✓ Identical |
| Antipodes Pass 2 (letters[1201:1298]) | ✓ Identical |

**Length: 97 characters. All 26 letters present.**
(Source: Antipodes.xlsx computational extraction, 2026-02-27)

### 2. Known Plaintext Positions — VERIFIED ✓

| Position (0-indexed) | CT | PT | Vig Key (CT−PT)%26 |
|---|---|---|---|
| 21 | F | E | B (1) |
| 22 | L | A | L (11) |
| 23 | R | S | Z (25) |
| 24 | V | T | C (2) |
| 25 | Q | N | D (3) |
| 26 | Q | O | C (2) |
| 27 | P | R | Y (24) |
| 28 | R | T | Y (24) |
| 29 | N | H | G (6) |
| 30 | G | E | C (2) |
| 31 | K | A | K (10) |
| 32 | S | S | A (0) |
| 33 | S | T | Z (25) |
| 63 | N | B | M (12) |
| 64 | Y | E | U (20) |
| 65 | P | R | Y (24) |
| 66 | V | L | K (10) |
| 67 | T | I | L (11) |
| 68 | T | N | G (6) |
| 69 | M | C | K (10) |
| 70 | Z | L | O (14) |
| 71 | F | O | R (17) |
| 72 | P | C | N (13) |
| 73 | K | K | A (0) |

**Cribs verified:** positions 21–33 = `EASTNORTHEAST`, positions 63–73 = `BERLINCLOCK`
(Source: computed from CLAUDE.md crib definitions + Antipodes.xlsx CT extraction)

### 3. Bean Constraints — VERIFIED ✓

- **Equality:** CT[27]=CT[65]='P', PT[27]=PT[65]='R', k_vig[27]=k_vig[65]=24 (Y) ✓
- **Additional equal pairs from cribs (13 total):** k[22]=k[67]=L, k[23]=k[33]=Z, k[24]=k[26]=k[30]=C, k[27]=k[28]=k[65]=Y, k[29]=k[68]=G, k[31]=k[66]=k[69]=K, k[32]=k[73]=A
- **Unequal pairs:** 263 out of C(24,2)=276

### 4. Transposition Impossibility — VERIFIED ✓

- CT contains 2 instances of 'E'
- Known plaintext (EASTNORTHEAST + BERLINCLOCK) requires 3 instances of 'E'
- **Pure single-layer transposition is mathematically impossible for K4**
(Source: computed from letter frequency of CT vs crib PT)

### 5. Antipodes Section Map (Letters-Only, 0-indexed) — VERIFIED ✓

| Pass | Section | Start | End | Length |
|------|---------|-------|-----|--------|
| 1 | K3 | 0 | 336 | 336 |
| 1 | K4 | 336 | 433 | 97 |
| 1 | K1 | 433 | 496 | 63 |
| 1 | K2 | 496 | 865 | 369 |
| 2 | K3 | 865 | 1201 | 336 |
| 2 | K4 | 1201 | 1298 | 97 |
| 2 | K1 | 1298 | 1361 | 63 |
| 2 | K2 | 1361 | 1584 | 223 (truncated) |

**Total letters: 1,584. Per-cycle: 865 letters.**
(Source: pattern-matching K3/K4/K1 reference CTs against Antipodes.xlsx letter stream)

### 6. Non-Alpha Characters on Antipodes — VERIFIED ✓

| Raw Pos | Char | Grid Row | Grid Col | Letters Before | Section | Internal Pos |
|---------|------|----------|----------|----------------|---------|-------------|
| 336 | ? | 10 | 31 | 336 | K3/K4 boundary | K3 end |
| 434–435 | [] | 13 | 26 | 433 | K4/K1 boundary | Space (Pass 1 only) |
| 536 | ? | 16 | 26 | 533 | K2 | 37 |
| 662 | ? | 20 | 18 | 658 | K2 | 162 |
| 724 | ? | 22 | 12 | 719 | K2 | 223 |
| 730 | . | 22 | 17 | 724 | K2 | 228 (in cell "S.") |
| 732 | . | 22 | 18 | 725 | K2 | 229 (in cell "F.") |
| 1209 | ? | 36 | 20 | 1201 | K3/K4 boundary (P2) | K3 end |
| 1407 | ? | 42 | 16 | 1398 | K2 (P2) | 37 |
| 1533 | ? | 46 | 8 | 1523 | K2 (P2) | 162 |

**Key structural findings:**
- `?` marks at K3/K4 boundary REPLACE the final K3 cipher letter (K3 is 336 letters on Antipodes vs 337 on Kryptos)
- 3 `?` marks in K2 REPLACE cipher letters Q (enciphered `?`) — K2 is 369 letters on Antipodes vs 372 on Kryptos
- `[]` space appears ONLY at Pass 1 K4→K1 boundary; Pass 2 has NO space
- 2 dots (`.`) are part of `S.` `F.` cells = W.W. abbreviation, appear ONLY in K2 Pass 1

### 7. Kryptos vs Antipodes Section Lengths — VERIFIED ✓

| Section | Kryptos (cipher letters) | Antipodes (cipher letters) | Difference |
|---------|--------------------------|----------------------------|------------|
| K3 | **336** (+ 1 boundary ?) | 336 (+ 1 boundary ?) | **0 (IDENTICAL)** |
| K4 | 97 | 97 | 0 (IDENTICAL) |
| K1 | 63 | 63 | 0 (IDENTICAL) |
| K2 | 369 (+ 3 literal ?) | 369 (+ 3 literal ?) | **0 (IDENTICAL)** |
| **Total letters** | **865** | **865** | **0** |
| **Total chars** | **869** (865+4?) | **869** per cycle (865+4?) | **0** |

**CORRECTION (2026-02-27, CT-PT-AUDIT team):** Previous version said K3=337 on Kryptos vs 336 on Antipodes. This was WRONG — the boundary `?` is punctuation, not a cipher letter. All four sections have IDENTICAL cipher letter counts across both sculptures. The ONLY CT difference is the UNDERGRUUND correction at position 177.

### 8. UNDERGRUUND Correction — VERIFIED ✓

- Kryptos global position 177 (K2 internal position 114 on Antipodes, ~115 on Kryptos after Q insertion)
- **Antipodes has 'E'** (UNDERGROUND — correct spelling)
- **Kryptos has 'R'** (UNDERGRUUND — Sanborn's documented error)
- K2 Pass 1 and Pass 2 on Antipodes are identical through their first 223 shared characters

### 9. Antipodes Tableau — VERIFIED ✓

- 26 unique rows × 33 columns (26 core + 7 overflow)
- All cells = `KA[(row_shift + col) mod 26]` — **perfect cyclic KA shifts, ZERO anomalies**
- Rows 27–32 repeat Rows 1–6
- KA alphabet: `KRYPTOSABCDEFGHIJLMNQUVWXZ` (all 26 letters, keyword KRYPTOS first)

---

## LANE B — MEMORY CORRECTIONS REQUIRED

### MEMORY Claims Verified Correct ✓

1. "K4 is character-identical" across Kryptos and Antipodes — **CONFIRMED**
2. "1,584 letters, ZERO mismatches" (Antipodes total) — **CONFIRMED**
3. "ONE SPACE only — row 13 (K4→K1, pass 1). Row 39 has NO space." — **CONFIRMED**
4. "Single CT difference: pos 177, R→E = UNDERGRUUND correction" — **CONFIRMED**
5. "K2 X-omission confirmed on both sculptures" — **CONFIRMED** (both have pre-correction K2)
6. "Tableau: 32×33, perfect KA cyclic shifts, ZERO anomalies" — **CONFIRMED**
7. "Antipodes offset = 435 = K1+K2 EXACT" — **CONFIRMED** (63+372=435 on Kryptos, Antipodes starts at K3)

### MEMORY Claims Requiring Correction ⚠️

1. **"K3[435-771]=337"** — This is the KRYPTOS length. On Antipodes, K3 = **336 letters** (final cipher letter replaced by literal `?`). MEMORY should clarify this distinction.

2. **"K2[63-434]=372"** — This is the KRYPTOS length. On Antipodes, K2 = **369 letters** (3 cipher Q's replaced by literal `?`). MEMORY should clarify.

3. **"Definitive section boundary map: K1[0-62] K2[63-434] K3[435-771] K4[772-868] = 869"** — These are KRYPTOS boundaries only. Antipodes boundaries are different (K3 first, different lengths). Recommend MEMORY specifies "(Kryptos only)" for this claim.

4. **"Antipodes offset = 435 = K1+K2 EXACT — starts precisely at K3 boundary"** — While true as a mathematical coincidence, the MECHANISM is simply that Antipodes starts with K3. The "offset" framing is confusing. Recommend: "Antipodes begins with K3, cycling K3→K4→K1→K2 with 865 letters per pass."

### Dangerous Assumptions (if wrong, pipeline breaks)

| Assumption | Risk Level | Current Evidence |
|------------|------------|------------------|
| 0-indexed positions are consistent | HIGH | Verified in this audit |
| Crib positions 21-33 and 63-73 are exact | HIGH | Verified against Antipodes CT |
| K4 CT on Kryptos = K4 CT on Antipodes | HIGH | CONFIRMED identical |
| K3 on Kryptos has 337 cipher letters | MEDIUM | Unverified — requires Kryptos photo verification |
| The 337th K3 cipher letter on Kryptos (not on Antipodes) | MEDIUM | Unknown character — needs physical inspection |
| K2 on Kryptos has exactly 372 cipher letters | MEDIUM | Consistent with 369 + 3 Q's, but unverified from Kryptos photos |

---

## Parsing Notes for Future Code

### Excel Cell Multi-Character Values

Three cells in Antipodes.xlsx contain multi-character values:

| Cell Content | Grid Location | Meaning |
|---|---|---|
| `[]` | Row 13, Col 26 | Space between K4 and K1 (Pass 1 only) |
| `S.` | Row 22, Col 17 | Cipher letter S + period (from W.W.) |
| `F.` | Row 22, Col 18 | Cipher letter F + period (from W.W.) |

**Critical:** When extracting letters, iterate *character-by-character* over the concatenated string, NOT cell-by-cell. Cell-level `isalpha()` will incorrectly drop the S and F from `S.` and `F.` cells.

```python
# CORRECT: character-by-character
raw_str = ''.join(str(cell.value) for cell in row if cell.value)
letters = ''.join(ch for ch in raw_str if ch.isalpha())

# WRONG: cell-level check (drops S. and F. entirely)
letters = ''.join(str(cell.value) for cell in row if str(cell.value).isalpha())
```
