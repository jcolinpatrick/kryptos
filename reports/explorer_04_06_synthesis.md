# E-EXPLORER-04/05/06: Non-Standard Cipher Structures — Synthesis

**Date:** 2026-02-20
**Agent:** Explorer
**Experiments:** E-EXPLORER-04, E-EXPLORER-05, E-EXPLORER-06
**Status:** ALL hypotheses NOISE. No signals found.

---

## Summary

Three experiment scripts tested 9 non-standard cipher hypotheses beyond classical textbook methods. Every hypothesis scored at or below the noise floor (<=6/24). One apparent 24/24 result (H3 interleave) was proven to be an underdetermination artifact.

---

## Hypotheses Tested

### E-EXPLORER-04: Non-Standard Structures

| Hypothesis | Description | Best Score | Verdict |
|-----------|-------------|-----------|---------|
| H1: Polybius-variant charts | CT as coordinate pairs in 5x5/5x6/6x5/6x6 grids, KRYPTOS/standard alphabets | 4/24 | NOISE |
| H2: Position-dependent alphabets | N alphabets (N=2..7) rotated by step, keyword-driven shifts, Quagmire-style with KRYPTOS/PALIMPSEST/ABSCISSA/BERLINCLOCK keywords | 4/24 | NOISE |
| H3: Dual-system interleave | CT split into N interleaved streams (N=2..5), each with periodic key (period 1-7), all Vig/Beau/VB combos | 24/24 at n=4,p=7 | **FALSE POSITIVE** |
| H4: K1-K3 as running key | K1, K2, K3 plaintext (forward/reversed) as running key at all offsets, Vig/Beau/VB | 5/24 | NOISE |

### E-EXPLORER-05: Interleave Follow-up

The 24/24 result from H3 was investigated in detail:
- **Root cause:** With 4-way interleave at period 7, NO residue class in ANY stream has more than 1 crib constraint. This means the key is ALWAYS solvable — 24/24 is guaranteed for ANY variant choice.
- **Monte Carlo confirmation:** 50.0% of random 4-stream/p7 configs score 24/24, confirming pure underdetermination.
- **Language quality:** All 16 unique decrypts have IC ~ 0.037 (random) and gibberish plaintext.
- **2-way interleave + periodic p<=7: ZERO configs at 24/24** — genuinely eliminated.
- **3-way interleave + periodic p<=7: ZERO configs at 24/24** — genuinely eliminated.

**Elimination:** N-way interleave (N=2,3) with periodic keys of period <= 7 is ELIMINATED. N=4+ is underdetermined and not discriminable.

### E-EXPLORER-06: Physical/Procedural Methods

| Hypothesis | Description | Best Score | Verdict |
|-----------|-------------|-----------|---------|
| H1: Berlin Clock reading | Grid layout [4,16,16,45,16] inspired by Mengenlehreuhr, 5 reading orders + Caesar shifts | 4/24 | NOISE |
| H2: Coordinate-derived keys | K2 coordinates (38,57,6,5,77,8,44), dates (1989,1986), as periodic Vigenere/Beaufort keys | 3/24 | NOISE |
| H3: Stencil cipher | Position selection via KRYPTOS-derived indices, CQUAE misspelling positions with various strides | 24/24 trivially | ARTIFACT (24/24 only when using crib positions directly) |
| H4: Layered unmasking | 29 first-layer transforms (Caesar 0-25 + KRYPTOS remap + atbash + reverse) x 14 keywords x 2 variants = 840 configs | 4/24 | NOISE |
| H5: Misspelling-derived | Wrong letters CQUAE as key [2,16,20,0,4], correct letters [18,11,14,4,8], word positions [7,2,10,5,4], EQUAL keyword, all via standard + KRYPTOS alphabet | 4/24 | NOISE |

### Bonus: Key Extension Analysis

Attempted polynomial fits k = f(pos) mod 26 to the 24 known Vigenere keystream values:
- **Best polynomial:** k = (4*pos + 20) mod 26 — matches 7/24 (just above random expectation of ~1/24 per position)
- **No clean algebraic function** generates the keystream. This confirms the key is non-periodic and non-polynomial.

---

## What This Eliminates

1. **Polybius/checkerboard encoding** of CT (coordinate-pair interpretation) — NOISE
2. **Position-modular alphabet switching** (N=2..7 alphabets, rotation steps 1-13) — NOISE
3. **2-way and 3-way interleave** with periodic sub-keys (period <= 7) — ELIMINATED (0/24)
4. **K1-K3 plaintext as running key** (all offsets, all variants) — NOISE (max 5/24)
5. **Berlin Clock grid reading orders** (5 schemes + Caesar) — NOISE
6. **K2 coordinate-derived periodic keys** — NOISE
7. **Layered unmasking** (simple L1 transform + keyword L2) — NOISE at standard keyword set
8. **Misspelling-derived keys** (CQUAE positions, EQUAL keyword) — NOISE
9. **Polynomial keystream** (degree 1-2) — max 7/24, no fit

---

## What Remains Open

All results are consistent with the prior finding that the cipher is NOT a standard classical method. The surviving hypothesis space:

1. **Running key from an UNKNOWN source text** — still viable, but K1-K3 are specifically eliminated as sources
2. **Bespoke lookup tables** (Sanborn's "coding charts") — untestable without the charts themselves
3. **Non-standard composition** where the substitution layer is genuinely novel (not Vigenere/Beaufort/VB)
4. **Physical procedural method** more complex than anything tested here

---

## Artifacts

- `/home/cpatrick/kryptos/artifacts/explorer_04_results.json`
- `/home/cpatrick/kryptos/artifacts/explorer_05_interleave_followup.json`
- `/home/cpatrick/kryptos/artifacts/explorer_06_results.json`

## Repro Commands

```bash
PYTHONPATH=src python3 -u scripts/e_explorer_04_nonstandard_structures.py
PYTHONPATH=src python3 -u scripts/e_explorer_05_interleave_followup.py
PYTHONPATH=src python3 -u scripts/e_explorer_06_physical_procedural.py
```
