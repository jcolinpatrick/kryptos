# Exhaustive Sculpture Reading Path Search — Design Spec

**Date:** 2026-03-18
**Goal:** Find any reading path through Kryptos sculpture surfaces that, when used as a Beaufort/Vigenere key, produces correct plaintext at >=12 of 24 crib positions.

## Motivation

All standard cipher families, transposition combinations, key generation functions, and SA approaches are exhaustively eliminated. Bean compares K4 to Chaocipher — the mechanism may be novel. The remaining computational space is "simple physical procedures" — ways to read characters from the sculpture that produce the known keystream. This is the first exhaustive enumeration of reading paths as key generators.

## Surfaces

| Surface | Dimensions | Source |
|---|---|---|
| Quagmire II tableau | 26x26 (676 chars) | Reconstructed from KA alphabet |
| Master grid (CT) | 28x31 (868 chars) | K1-K4 ciphertext as carved |
| Master grid (PT) | 28x31 (868 chars) | K1-K3 solved plaintext + K4 CT |
| Morse decoded | ~150 chars | K0 decoded text |

## Path Families

### Family 1: Linear on 26x26 tableau (~50K paths)
- Row/column reading, 4 directions + boustrophedon
- Diagonal, 4 directions, all 51 start positions per direction
- Spiral CW/CCW from 4 corners
- Skip-N (N=2..13), all directions, all start positions

### Family 2: Linear on 28x31 master grid (~200K paths)
- Same patterns as Family 1 on larger grid
- K4-only rows (24-27), K1-K3 rows (0-13), cross-section
- Column reads at widths 5, 7, 31

### Family 3: Keyword-parameterized (~100K paths)
- Keywords: KRYPTOS, SEVEN, PALIMPSEST, ABSCISSA, DEFECTOR, KOMPASS
- Keyword letter selects tableau row, position selects column (and variants)
- Keyword-driven zigzag and direction changes

### Family 4: Coordinate-parameterized (~10K paths)
- K2 numbers (38,57,6,77,8,44) as start/skip/row/col selectors
- Tomb numbers (25,44,25,32,36,5) similarly
- Combined K2+Tomb arithmetic as parameters

### Family 5: Compound paths (~50K paths)
- **5A** Surface indexes surface: one surface character selects row/col on another
- **5B** Dual-path Polybius: two reading paths provide (row,col) coordinates
- **5C** Chained: read surface, transform through tableau with keyword
- **5D** Position-mapped: key[i] = surface[f(i)] for simple f

### Family 6: Morse/other (~5K paths)
- Morse decoded text as key at all offsets
- YAR/NDYAHR positions as skip selectors

## Scoring

Each path produces a character sequence used as key under 4 variants:
- AZ Beaufort: PT = (KEY - CT) mod 26
- AZ Vigenere: PT = (CT - KEY) mod 26
- KA Beaufort: PT = (KEY_ka - CT_ka) mod 26
- KA Vigenere: PT = (CT_ka - KEY_ka) mod 26

Score = number of crib positions (out of 24) where derived PT matches known crib character.

## Thresholds

- 12+/24: Report, log full details, decrypt and score plaintext
- 18+/24: Print SIGNAL banner to stdout immediately
- 24/24: Halt and report solution

## Architecture

Single script: `scripts/campaigns/f_sculpture_path_search_v1.py`

```
Path generators (per family)
  → yield (key_chars: str, description: str)
    → Universal scorer (test 4 variants x 24 cribs)
      → Hit collector (score >= threshold)
        → Detail analysis (decrypt, quadgram, Bean check)
          → Results JSON + stdout
```

Multiprocessing: 28 cores. Generators run in main process, scoring distributed to workers in batches.

## Output

File: `results/f_sculpture_path_search_v1.json`

Each hit includes: score, variant, family, description, key preview, matching positions, path parameters, full decrypted plaintext (if score >= 12), quadgram/intel scores.

## Not in scope

- SA or hill-climbing (proven ineffective)
- Random sampling (this is exhaustive enumeration)
- Quadgram optimization (scoring against cribs only)
