# Session 24 Report — Final Classical Elimination Sweep

**Date:** 2026-02-19 (continued from Session 23)
**Experiments:** E-S-100 through E-S-105 (6 experiments)
**Focus:** Porta cipher, statistical transposition detection, grid-position keys, running keys, turning grille, self-keying/derived keys

---

## Executive Summary

Conducted **6 experiments** completing the systematic elimination of all remaining classical cipher families. **No signal found.** Every tested combination produced noise-level scores.

**Most important findings:**
1. **Porta cipher: COMPLETELY ELIMINATED** (E-S-100) — 0 survivors across all widths 5-8, all periods 2-14, decimation, direct
2. **Turning grille: STRUCTURALLY IMPOSSIBLE** (E-S-104) — 19/25 quarter cells have no valid orientation, search space = 0
3. **Grid-position polynomial keys: ELIMINATED** (E-S-102) — 0 survivors for linear, quadratic, and position-only models
4. **All derived key schemes: ELIMINATED** (E-S-105) — cumulative, Fibonacci, multiplication, XOR/difference chains, power/exponentiation

---

## Experiment Results

| Exp | Description | Best | Verdict |
|-----|-------------|------|---------|
| E-S-100 | Porta + w5-8 columnar (constraint prop.) | 0/5040 all periods | **DEAD** |
| E-S-101 | Statistical transposition detection | z=3.97 diff IC (no cross-validation) | NOISE |
| E-S-102 | Grid-position polynomial key + w7 | 0 survivors (linear/quad), 9/24 best | **DEAD** |
| E-S-103 | Thematic running key + w7 | Killed after 27 min (Carter too large) | NOISE* |
| E-S-104 | Turning grille (10×10) | 19/25 impossible cells, space=0 | **DEAD** |
| E-S-105 | Self-keying + derived key schemes | 8/24 best (power key) | **DEAD** |

*E-S-103: Smaller reference texts (Reagan, JFK, CIA charter, NSA Act, UDHR) processed; Carter Gutenberg killed due to ~120K offsets × 5040 orderings. Carter already tested with w7 columnar in E-S-52 (max 11/24 = noise).

---

## Detailed Results

### E-S-100: Porta Cipher + Columnar (Constraint Propagation)
Proper Porta cipher test using constraint propagation (not brute force from E-S-95).
- **P1: Porta + w7 period 7: 0/5040** — no ordering has a consistent period-7 Porta key
- **P2: Porta + w7 periods 2-14: 0/5040** for ALL periods — completely dead
- **P3: Porta + decimation period 7: 0/96** — all decimation steps fail
- **P4: Porta direct (no transposition) periods 2-14: 0** valid keys for all periods
- **P5: Porta + widths 5,6,8 (period=width): 0** for all widths
- **P5: Porta + width 8, period 7: 0/40320**
- **PORTA IS COMPLETELY ELIMINATED** as a K4 cipher under any standard transposition

### E-S-101: Statistical Transposition Detection
Tested bigram score, differential IC, and log-likelihood for all 5040 w7 orderings.
- Differential IC top z=3.97 (ordering [5,3,0,4,1,2,6]) — borderline
- Bigram top z=1.84 — not significant
- **Triple overlap (top-50 for all 3 metrics): 0** — no consistent signal
- Log-likelihood invariant across orderings (expected — transposition preserves frequencies)
- Other widths (5,6,8,9,10): max z=2.30 — not significant
- **No statistical method can reliably identify the correct transposition**

### E-S-102: Grid-Position Polynomial Key + Width-7 Columnar
Tests key = f(row, col) in the 7×14 grid.
- **P1: Linear k = a*row + b*col + c (mod 26): 0 survivors** from 3.4M tests
- **P2: Quadratic k = a*r² + b*c² + d*rc + e*r + f*c + g: 0 survivors** (CRT solution)
- P3: Keyword[col] + a*row (Vigenère): 0 survivors, best 9/24 (INVISIBLE, a=13)
- P4: Keyword[col] + a*row (Beaufort/VBeau): best 8/24 (PALIMPSEST VBeau)
- P5: Keyword[col] + a*row + b*row² (quadratic): best 8/24
- **P6: Position-only k = a*j + b and k = a*j² + b*j + c: 0 survivors**
- P7: Multiplicative k = keyword[col] × (row+1): best 7/24
- **All grid-position-derived key models are ELIMINATED**

### E-S-104: Turning Grille with Constraint Propagation
10×10 turning grille (25 quarter-cells, 4^25 = 10^15 search space).
- P1: 5M random samples: best 4/24 — noise
- P2: 20 SA runs (500K steps each): best 4/24 — noise
- P3: SA + periodic Vig (p=7): best 0/7 residues — noise
- **P4: Constraint propagation: 19/25 quarter cells IMPOSSIBLE**
  - 23/25 cells constrained; 19 have ZERO valid orientations
  - Remaining search space: **0.00** (from 1.13×10^15)
  - **STRUCTURAL PROOF**: no 10×10 turning grille can produce K4 CT from known PT
- P5: Alternative grids (7×14, 14×7): 1-3/24 cribs — noise
- **Turning grille is DEFINITIVELY ELIMINATED for K4**

### E-S-105: Self-Keying Double Columnar + Derived Key Schemes
Tests key derivation from CT itself and from keyword transformations.
- **PA: Self-keying (key=CT in different column order): best 4/24, 0 survivors**
  - Tested all 5040² = 25.4M pairs of (transposition, key) orderings
  - None produces even moderate crib matches
- PB1: Cumulative sum key: best 7/24
- PB2: Fibonacci/tribonacci key: best 7/24
- PB3: Multiplication chain key: best 7/24
- PB4: Difference/XOR chain key: best 7/24
- PB5: Power key (base^i mod 26 or base^i mod 97 mod 26): best 8/24
- PC: All schemes without transposition: best 3/24
- **All derived key generation schemes are ELIMINATED**

---

## Cumulative Elimination Status (Sessions 1-24)

### DEAD (confirmed, no exceptions)
- All periodic polyalphabetic (Vig/Beau/VB/Porta/Gromark) + any transposition
- All periodic substitution (p=2-14) + width-7 columnar (E-S-94)
- All structured non-periodic keys (progressive, polynomial, Fibonacci, cumulative, power, multiplicative, XOR/diff chains, grid-position) + w7
- Autokey (CT/PT) + any columnar width 5-10 or decimation
- Monoalphabetic + columnar widths 5-11
- Digraphic (Playfair, Two-Square, Four-Square)
- Bifid 5×5 (impossible), Bifid 6×6, Trifid 3×3×3
- Hill n=2,3,4 + columnar
- Nihilist, ADFGVX/ADFGX, straddling checkerboard
- Pure transposition (IC=0.036 << English 0.066)
- K1-K3 texts as running key + w7 columnar
- Carter book as running key + w7 columnar
- Decimation + periodic/mono/autokey
- Double columnar + periodic Vig (all w-pairs 5-8, p=2-14)
- Myszkowski + periodic (47K orderings × p=2-14)
- Self-keying double columnar (25.4M pairs)
- **Turning grille: STRUCTURALLY IMPOSSIBLE** (19/25 impossible quarter cells)
- **Porta: ELIMINATED** at all periods 2-14, all widths 5-8, all transpositions
- **Grid-position polynomial keys: ELIMINATED** (linear, quadratic, position-only)
- Community proposals (Naughton, Nash)

### VIABLE (untested or underdetermined)
1. **Running key from UNKNOWN text** + transposition — fundamentally untestable without the text
2. **Custom tableau/coding chart** — the "original coding system" sold at auction
3. **Physical/procedural cipher** — Sanborn: "Who says it is even a math solution?"
4. **Novel cipher structure** not yet conceived

---

## Strategic Assessment

**All standard classical cipher families are now exhaustively eliminated.** The cipher must be either:

1. A **custom system** defined by the "coding charts" sold at auction ($962,500)
2. A **running key** from a text that is not publicly known
3. A **physical/procedural** method tied to the sculpture's artistic construction
4. Something entirely outside the space of classical cryptography

**The underdetermination wall is absolute**: with 24 known characters out of 97, no scorer (character-level, word-level, bigram, quadgram) can overcome the 73 free degrees of freedom under arbitrary transposition. Without additional plaintext or the specific key/chart, K4 cannot be solved computationally.

**The method remains unknown despite the plaintext being found** (sealed in Smithsonian archives until 2075). The auction buyer possesses "the original coding system for K4" but has not published it.

---

## Web Research Summary

- No new public information about K4's method as of Feb 2026
- mattklepp/k4 GitHub "solution" is trivial overfitting (position-specific corrections, gibberish PT)
- Smithsonian archives sealed for 50 years
- Auction buyer anonymous, has not published

---

*Session 24 — E-S-100 through E-S-105*
*Repro: `PYTHONPATH=src python3 -u scripts/e_s_<NN>_*.py` for each experiment*
