# Exhaustive Sculpture Reading Path Search — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Enumerate every simple reading path through the Kryptos sculpture surfaces and test each as a cipher key against the 24 known crib positions, reporting any path scoring 12+/24.

**Architecture:** Single script with generator functions per path family yielding (key_chars, description) tuples. A universal scorer tests each key against 4 cipher variants x 24 cribs. Multiprocessing on 28 cores. Results to JSON.

**Tech Stack:** Python 3.12, stdlib only (multiprocessing, itertools, json). Imports from kryptos.kernel.constants.

**Spec:** docs/superpowers/specs/2026-03-18-sculpture-path-search-design.md

---

## Task 1: Scaffold and Surface Data

**Files:** Create scripts/campaigns/f_sculpture_path_search_v1.py

Build the script skeleton with all surface data loaded and the universal scoring function.

- [ ] Step 1: Create script with imports, surfaces, and scorer

Surfaces to build:
- TABLEAU: 26x26 grid where TABLEAU[r][c] = KA[(r+c)%26]
- MASTER_CT: 28x31 grid of K1-K4 ciphertext as carved on the sculpture
- MASTER_PT: same grid but K1-K3 replaced with solved plaintext
- MORSE_TEXT: decoded Morse from K0

Scorer: score_key(key_chars) tests the key under AZ Beaufort, AZ Vigenere, KA Beaufort, KA Vigenere against 24 crib positions. Returns list of (score, variant) for scores >= threshold.

Refs: src/kryptos/kernel/constants.py, src/kryptos/novelty/generators.py (K1-K3 PT), memory/k3_method.md

- [ ] Step 2: Verify surfaces load correctly
- [ ] Step 3: Commit

---

## Task 2: Family 1 — Linear Paths on 26x26 Tableau (~50K paths)

**Files:** Modify scripts/campaigns/f_sculpture_path_search_v1.py

- [ ] Step 1: Implement path generators

Path types:
- Row reads: L-to-R, R-to-L, boustrophedon. 26 start rows x 3 modes = 78
- Column reads: T-to-B, B-to-T, boustrophedon. 26 start cols x 3 = 78
- Diagonals: 4 directions (NE/NW/SE/SW), all start positions along edges (~51 per direction), wrapping. ~204
- Spirals: CW/CCW from 4 corners = 8
- Skip-N: base direction (row-major, col-major) x skip N=2..13 x start offset 0..N-1. ~2x12x13 = 312
- All paths with variable start offset within the generated sequence

Each generator yields (key_chars, description). Key_chars must be >= 97 chars; cycle shorter sequences.

- [ ] Step 2: Test Family 1 standalone
- [ ] Step 3: Commit

---

## Task 3: Family 2 — Linear Paths on 28x31 Master Grid (~200K paths)

**Files:** Modify scripts/campaigns/f_sculpture_path_search_v1.py

- [ ] Step 1: Implement generators

Same pattern types as Family 1 but on both MASTER_CT and MASTER_PT.

Additional grid-specific patterns:
- K4-only rows (24-27): various directions
- K1K2-only rows (0-13): key from the solved section
- Single-column reads: column N for N=0..30 across all 28 rows (28-char keys, cycled)
- Width-7 strided column reads (every 7th column starting at each offset 0-6)
- Width-5 strided column reads

- [ ] Step 2: Test Family 2
- [ ] Step 3: Commit

---

## Task 4: Family 3 — Keyword-Parameterized Paths (~100K paths)

**Files:** Modify scripts/campaigns/f_sculpture_path_search_v1.py

- [ ] Step 1: Implement generators

Keywords: KRYPTOS, SEVEN, PALIMPSEST, ABSCISSA, DEFECTOR, KOMPASS, HOROLOGE, BERLIN, CARTER

Path types:
- Row-select: keyword[i%L] selects tableau row via KA index, i selects column
- Col-select: keyword selects column, i selects row
- Zigzag: read row-by-row, reverse direction at keyword letter positions
- Skip: KA index of keyword letters defines skip distances between reads
- Offset: keyword KA index added to base reading position

Each keyword x path type x surface = ~9 keywords x 5 types x 4 surfaces = 180 base generators, each yielding multiple paths from start offsets.

- [ ] Step 2: Test Family 3
- [ ] Step 3: Commit

---

## Task 5: Family 4 — Coordinate-Parameterized Paths (~10K paths)

**Files:** Modify scripts/campaigns/f_sculpture_path_search_v1.py

- [ ] Step 1: Implement generators

Number sets: K2 (38,57,6,77,8,44), Tomb (25,44,25,32,36,5), K2+Tomb sums (63,101,32,109,44,49), digit sums (7,8,17,5,9,11)

Path types:
- Start-skip: begin at position start, read every skip-th char from each surface
- Row-col: use number pairs as (row,col) start, read in each direction
- Modular: pos % M selects from surface, using coordinate numbers as M
- Digits-as-key: raw digit sequences mod 26 converted to letter keys

- [ ] Step 2: Test Family 4
- [ ] Step 3: Commit

---

## Task 6: Family 5 — Compound Paths (~50K paths)

**Files:** Modify scripts/campaigns/f_sculpture_path_search_v1.py

The most important family. Four sub-types.

- [ ] Step 1: Type 5A — Surface indexes surface (64 paths)

key[i] = tableau[idx(master_char[i])][i % col_mod]

Variations: 2 surfaces x 2 index functions (AZ,KA) x 2 row/col swaps x 4 col mods (26,7,5,31)

Also: key[i] = master[tableau_flat[i] % 868]

- [ ] Step 2: Type 5B — Dual-path Polybius (~1,352 paths)

Two tableau columns provide (row,col) coordinates:
key[i] = tableau[col_A[i%26]][col_B[i%26]]

All C(26,2)=325 column pairs. Plus cross-surface pairs.

- [ ] Step 3: Type 5C — Chained transformation (~36K paths)

Read surface path, transform result through tableau with keyword:
key[i] = tableau[KA_IDX[keyword[i%L]]][KA_IDX[intermediate[i]]]

~1K sampled base paths x 9 keywords x 4 operations

- [ ] Step 4: Type 5D — Position-mapped reads (~15K paths)

key[i] = surface[f(i) % surface_len]

Functions: linear (a*i+b), quadratic (sampled), fibonacci, coordinate sequences, keyword cumulative sums. All x 3 surfaces.

- [ ] Step 5: Test Family 5
- [ ] Step 6: Commit

---

## Task 7: Family 6 — Morse and Other (~5K paths)

**Files:** Modify scripts/campaigns/f_sculpture_path_search_v1.py

- [ ] Step 1: Implement generators

- Morse decoded text at all offsets as key
- Morse dots/dashes as binary position selectors
- YAR raised character positions as skip selectors
- NDYAHR (N,D,Y,A,H,R) KA indices as selection parameters

- [ ] Step 2: Test Family 6
- [ ] Step 3: Commit

---

## Task 8: Multiprocessing, CLI, and Full Run

**Files:** Modify scripts/campaigns/f_sculpture_path_search_v1.py

- [ ] Step 1: Add CLI flags

--family N (single family), --all (default), --threshold N (default 12)

- [ ] Step 2: Add multiprocessing wrapper

Worker pool distributes path batches to 28 cores. Progress every 10K paths.

- [ ] Step 3: Add hit analysis

For hits >= 12/24: full decrypt, quadgram, intel jargon, word coverage, Bean check. For hits >= 18/24: SIGNAL banner to stdout.

- [ ] Step 4: Add JSON results output

Write to results/f_sculpture_path_search_v1.json

- [ ] Step 5: Launch overnight run

PYTHONPATH=src python3 -u scripts/campaigns/f_sculpture_path_search_v1.py --all

Launch in background for overnight execution.

- [ ] Step 6: Commit
