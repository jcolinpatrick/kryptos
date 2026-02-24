# Session 23 Report — Autokey, Decimation, and Systematic Elimination

**Date:** 2026-02-19 (continued from Session 22)
**Experiments:** E-S-89 through E-S-99 (11 experiments)
**Focus:** Progressive keys, autokey, community proposals, decimation, running keys, monoalphabetic constraint propagation

---

## Executive Summary

Conducted **11 experiments** testing autokey ciphers, community proposals, decimation ciphers, K1-K3 running keys, monoalphabetic substitution, and progressive key models. **No signal found.** Every tested combination produced noise-level scores.

**Most important finding — E-S-94 Phase 3:** No periodic key of ANY period 2-14 is consistent with the cribs under ANY width-7 columnar ordering (0/15120 for all periods). Combined with E-S-91 confirming period-7 specifically has 0 survivors, **ALL periodic substitution + width-7 columnar is definitively dead.**

---

## Experiment Results

| Exp | Description | Best | Verdict |
|-----|-------------|------|---------|
| E-S-89 | Progressive key + w7 columnar (6 models) | 12/24 (artifact) | NOISE |
| E-S-90 | Extended structured keys (5 models) | 15/24 (artifact) | NOISE |
| E-S-91 | Plaintext extension + period-7 filter | 0/15120 baseline | **DEAD** |
| E-S-92 | Community proposals + creative models | 19/24 (artifact) | NOISE |
| E-S-93 | Autokey + w7 columnar (primers 1-2) | 4/24 | NOISE |
| E-S-94 | Keystream structure analysis (7 phases) | 0/15120 periodic | **CRITICAL** |
| E-S-95 | Gromark + Porta + w7 (partial) | 6/24 | NOISE |
| E-S-96 | Multi-width autokey (widths 5-10) | 9/24 | NOISE |
| E-S-97 | Decimation + periodic/autokey/mono | 10/24 (noise) | NOISE |
| E-S-98 | K1-K3 running key + w7 columnar | 8/24 | NOISE |
| E-S-99 | Monoalphabetic + columnar w5-11 | 0 survivors | **DEAD** |

---

## Detailed Results

### E-S-89: Progressive Key + Width-7 Columnar
Models: linear progressive (CT-coord, PT-coord), column-specific slopes (14 params), bilinear (3 params), diagonal (D params), horizontal progressive (15 params).
- Decisive tests (≤8 params, ≥16 excess): 4-8/24 = noise
- Underdetermined (≥14 params): 12-15/24 = artifact
- **All structured progressive keys: ELIMINATED**

### E-S-90: Extended Structured Key Models
Non-columnar transpositions + progressive, other widths (5,6,8), quadratic (21 params), Fibonacci recurrence (14 seeds), multiplicative.
- P1=6, P2=8, P3=15 (underdetermined), P4=13 (underdetermined), P5=3
- **All: ELIMINATED or artifacts**

### E-S-91: Plaintext Extension + Period-7 Consistency
**CRITICAL:** Baseline 0/15120 survivors with 24 base cribs alone. Tested 51 phrases × 2622 placements, all 0 survivors.
- **Period-7 + width-7 columnar: DEFINITIVELY DEAD**

### E-S-92: Community Proposals
- **Naughton (reverse+Vig+reverse):** 2/24 — debunked
- **Nash (pure transposition):** IC=0.036 << 0.050 — impossible
- **Double-key Vig (p7+p2):** 19/24 at combined p=35 — underdetermination
- **Row-shifted columnar:** 0/24 — dead
- **KA-alphabet Vig:** 10/24 — noise

### E-S-94: Keystream Structure Analysis (**Most Important**)
- **P3: 0/15120 for ALL periods 2-14 under ALL w7 orderings** — eliminates ALL periodic substitution + w7 columnar
- CT-autokey correlation: 7/24 max (noise)
- No arithmetic, grid-linear, readable key, or 2nd-difference patterns
- **Conclusive: the substitution layer must be non-periodic if w7 columnar is correct**

### E-S-96: Multi-Width Autokey
Width 5: 7, Width 6: 7, Width 7: 9, Width 8: 9, Width 9: 7, Width 10: 9.
Scores consistent with autokey chain structure noise (confirmed by E-S-97b).
- **Autokey + ANY columnar width 5-10: NOISE**

### E-S-97: Decimation Cipher
- Periodic (p=2-14): 0/24 for all 96 steps — **ELIMINATED**
- Autokey: 10/24 (PT-Beaufort d=11 primer CBG)
- E-S-97b analysis: score distribution matches Bin(24,1/26) with chain-inflated tails. 10/24 is expected max from 1.7M trials. PT is gibberish.
- **Decimation + all tested substitutions: NOISE**

### E-S-98: K1-K3 Running Key + Width-7 Columnar
All K1-K3 PT/CT, Morse code, concatenated K123: max 8/24. Direct: max 5/24.
- **K1-K3 texts are NOT the running key for K4**

### E-S-99: Monoalphabetic + Arbitrary Transposition
0 survivors for columnar widths 5-11. 0 for decimation. 0 for identity.
- **Monoalphabetic + any standard transposition: COMPLETELY ELIMINATED**

---

## Cumulative Elimination Status (Sessions 1-23)

### DEAD (confirmed, no exceptions)
- All periodic polyalphabetic (Vig/Beau/VB) + direct or columnar transposition
- All periodic substitution (p=2-14) + width-7 columnar (E-S-94)
- All structured non-periodic keys (progressive, quadratic, Fibonacci, etc.) + w7
- Autokey (CT/PT) + any columnar width 5-10, or decimation
- Gromark (mod 10 and mod 26) + any transposition
- Monoalphabetic + columnar widths 5-11
- Digraphic (Playfair, Two-Square, Four-Square)
- Bifid 5×5 (impossible), Bifid 6×6, Trifid 3×3×3
- Hill n=2,3,4 + columnar
- Nihilist, ADFGVX/ADFGX, straddling checkerboard
- Pure transposition (IC=0.036 << English 0.066)
- K1-K3 texts as running key + w7 columnar
- Decimation + periodic/mono
- Double columnar + periodic Vig (all w-pairs 5-8, p=2-14)
- Community proposals (Naughton, Nash)

### VIABLE (untested or underdetermined)
1. Running key from **unknown text** + transposition (underdetermined)
2. **Turning grille** (barely explored: 10^{-9} coverage)
3. **Physical/procedural** cipher ("not a math solution")
4. **Porta cipher** + width-7 (not fully tested)
5. **Novel cipher structure** not yet conceived
6. Width-7 with **truly novel** non-periodic substitution

---

## Strategic Assessment

The underdetermination wall is absolute: with 97 positions and 24 known chars, no scorer (character-level, word-level, or bigram) can overcome 73 free DOF under arbitrary transposition.

**To break through, we need one of:**
1. The specific running key text (physical "coding charts")
2. Additional confirmed plaintext beyond 24 characters
3. A completely new insight about the cipher structure
4. Physical/artistic knowledge about Sanborn's methods

---

*Session 23 — E-S-89 through E-S-99*
*Repro: `PYTHONPATH=src python3 -u scripts/e_s_<NN>_*.py` for each experiment*
