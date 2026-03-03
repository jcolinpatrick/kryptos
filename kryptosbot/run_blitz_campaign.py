#!/usr/bin/env python3
"""
KryptosBot Blitz Campaign — ALL-OUT UNSCRAMBLING ASSAULT.

Launches 6 parallel Claude agents, each attacking the unscrambling problem
from a different angle. Every agent writes and executes Python scripts on
the VM, leveraging all CPU cores for brute-force search.

PARADIGM:
    The 97 carved characters are SCRAMBLED ciphertext.
    PT → simple substitution → REAL CT → SCRAMBLE → carved text.
    Crib positions on carved text are MEANINGLESS.
    English IC on carved text is MEANINGLESS.
    Find the unscrambling permutation. The Cardan grille is the primary lead.

AGENTS:
    1. grille_geometry   — Physical mask pattern, rotations, hole coordinates
    2. numeric_permuter  — Convert grille extract → numeric permutations
    3. t_position        — Exploit T-avoidance as positional encoding
    4. strip_route       — Strip cipher, route cipher, S-curve reading orders
    5. constraint_solver — SAT/constraint propagation from crib letter frequencies
    6. wildcard          — Lateral thinking: fold, XOR, cascaded ops, Scheidt tricks

Usage:
    cd ~/kryptos
    source venv/bin/activate
    PYTHONPATH=src python3 -u kryptosbot/run_blitz_campaign.py

    # Options:
    PYTHONPATH=src python3 -u kryptosbot/run_blitz_campaign.py --agents 4
    PYTHONPATH=src python3 -u kryptosbot/run_blitz_campaign.py --max-turns 30
    PYTHONPATH=src python3 -u kryptosbot/run_blitz_campaign.py --single grille_geometry
    PYTHONPATH=src python3 -u kryptosbot/run_blitz_campaign.py --preflight

Token budget: ~$15-60 depending on max-turns and agent count.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("kryptosbot.blitz")

# ── Shared constants (inline so agents don't waste turns reading files) ──────

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

GRILLE_MASK = """\
Row 01: 000000001010100000000010000000001~~
Row 02: 100000000010000001000100110000011~~
Row 03: 000000000000001000000000000000011~~
Row 04: 00000000000000000000100000010011~~
Row 05: 00000001000000001000010000000011~~
Row 06: 000000001000000000000000000000011~
Row 07: 100000000000000000000000000000011
Row 08: 00000000000000000000000100000100~~
Row 09: 0000000000000000000100000001000~~
Row 10: 0000000000000000000000000000100~~
Row 11: 000000001000000000000000000000~~
Row 12: 00000110000000000000000000000100~~
Row 13: 00000000000000100010000000000001~~
Row 14: 00000000000100000000000000001000~~
Row 15: 000110100001000000000000001000010~~
Row 16: 00001010000000000000000001000001~~
Row 17: 001001000010010000000000000100010~~
Row 18: 00000000000100000000010000010001~~
Row 19: 000000000000010001001000000010001~~
Row 20: 00000000000000001001000000000100~~
Row 21: 000000001100000010100100010001001~~
Row 22: 000000000000000100001010100100011~
Row 23: 00000000100000000000100001100001~~~
Row 24: 100000000000000000001000001000010~
Row 25: 10000001000001000000100000000001~~
Row 26: 000010000000000000010000100000011
Row 27: 0000000000000000000100001000000011
Row 28: 00000000000000100000001010000001~~"""

# Known keywords from the Kryptos installation
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "EAST", "NORTH",
    "LIGHT", "ANTIPODES", "MEDUSA", "ENIGMA",
]

# K4 letter frequency (for constraint solving)
K4_FREQ = {}
for c in K4_CARVED:
    K4_FREQ[c] = K4_FREQ.get(c, 0) + 1

# ── Core shared preamble for every agent ─────────────────────────────────────

SHARED_PREAMBLE = f"""\
## MISSION: Find the unscrambling permutation for K4

The 97 characters carved on Kryptos are SCRAMBLED ciphertext:
```
PT → Cipher(key) → real_CT → SCRAMBLE(σ) → carved text
```

**MODEL 2 — CONFIRMED (2026-03-03, three independent evidence lines):**
1. Algebraic: Under Model 2, scrambling destroys periodicity in carved text. Exhaustive period
   analysis found NO periodicity in K4 carved text → consistent with Model 2.
2. Statistical: Chi-squared tests show K4 is 7% outlier under Model 1 but 87% typical under
   Model 2 at period 7.
3. Scheidt quotes: "solve the technique first then the puzzle" = undo scramble first = cipher
   applied first (inner layer).

**CRITICAL IMPLICATIONS:**
1. **PERIODIC KEYS ARE VIABLE AGAIN.** All prior period eliminations (E-FRAC-35, E-AUDIT-01)
   were on carved text — meaningless under Model 2. K4 could use Vigenère with KRYPTOS (period 7).
2. **Crib positions (21-33, 63-73) are PLAINTEXT positions** (equivalently, real_CT positions).
   PT[21..33] = EASTNORTHEAST, PT[63..73] = BERLINCLOCK. These are NOT positions in the carved text.
3. **Given a key assumption**, we can compute the expected real_CT at 24 crib positions.
   Then the constraint is: carved[σ(j)] = expected_CT[j] for each crib position j.
4. **Fast verification**: For any candidate σ, derive keystream at 24 crib positions, check
   for periodicity. ~12 equality checks per candidate. No exhaustive decryption needed.

## K4 Carved Text (97 chars, SCRAMBLED)
```
{K4_CARVED}
```

## Cardan Grille Extract (106 chars from KA tableau — NO letter T)
```
{GRILLE_EXTRACT}
```
- 106 chars (9 more than K4's 97)
- Missing: T (only letter absent). P(chance) ≈ 1/69. DELIBERATE.
- IC = 0.0418
- Extracted from 28×33 KA Vigenère Tableau through physical Cardan mask

## Grille Binary Mask (28 rows × 33 cols, 0=hole, 1=masked, ~=off-grid)
```
{GRILLE_MASK}
```
- 107 visible cells (zeros), 106 with letters underneath
- Reading order: left-to-right, top-to-bottom

## Tableau Anomalies (period-8 pattern)
- KA tableau body is PERFECT cyclic shift — zero deviations EXCEPT:
  - Extra **L** at row **N** (row 14), extra **T** at row **V** (row 22)
  - N-L = V-T = 2 (constant difference), V-N = T-L = **8** (constant spacing)
  - L+T = **30** (= body columns per row!)
- Period-8 rows: F(6), N(14), V(22). Converges with "8 Lines 73" from Sanborn's yellow pad.
- 97 mod 8 = 1.

## Alphabets
- AZ: {AZ}
- KA: {KA} (keyword KRYPTOS first, then remaining letters in order)

## Keywords to try (KRYPTOS is primary candidate — same key as K1/K2)
{', '.join(KEYWORDS)}

## How to test a candidate permutation
σ maps real_CT positions → carved positions: real_CT[j] = carved[σ(j)]
```python
import json, sys, math, random
from multiprocessing import Pool, cpu_count
sys.path.insert(0, 'src')

K4 = "{K4_CARVED}"
AZ = "{AZ}"
KA = "{KA}"
KEYWORDS = {KEYWORDS}

def vig_enc(pt, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(pt[i]) + alpha.index(key[i % len(key)])) % 26] for i in range(len(pt)))

def vig_dec(ct, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(ct[i]) - alpha.index(key[i % len(key)])) % 26] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(key[i % len(key)]) - alpha.index(ct[i])) % 26] for i in range(len(ct)))

# Load quadgrams
qg = json.load(open('data/english_quadgrams.json'))
def score(text):
    return sum(qg.get(text[i:i+4].upper(), -10.0) for i in range(len(text)-3))

# Test a permutation: σ maps real_CT positions → carved positions
def test_perm(sigma):
    # Unscramble: real_CT[j] = K4[sigma[j]]
    real_ct = ''.join(K4[sigma[j]] for j in range(97))
    best = None
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(real_ct, kw, alpha)
                sc = score(pt)
                # Search for cribs at their PLAINTEXT positions
                ene_ok = pt[21:34] == "EASTNORTHEAST"
                bc_ok = pt[63:74] == "BERLINCLOCK"
                # Also search anywhere
                ene_any = pt.find("EASTNORTHEAST")
                bc_any = pt.find("BERLINCLOCK")
                if ene_ok or bc_ok or ene_any >= 0 or bc_any >= 0:
                    print(f"*** CRIB HIT: key={{kw}} cipher={{name}}/{{alpha_name}}")
                    print(f"    ENE@21={{ene_ok}} BC@63={{bc_ok}} ENE_any@{{ene_any}} BC_any@{{bc_any}}")
                    print(f"    PT: {{pt}}")
                    print(f"    Score: {{sc:.1f}}")
                    return {{"pt": pt, "score": sc, "key": kw, "cipher": name, "alpha": alpha_name}}
                if best is None or sc > best["score"]:
                    best = {{"pt": pt, "score": sc, "key": kw, "cipher": name, "alpha": alpha_name}}
    return best

# FAST CHECK: compute expected CT at crib positions, verify in carved text
def compute_expected_ct(keyword, cipher_type, alpha=AZ):
    expected = {{}}
    for crib_pos, crib_text in [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]:
        for j, pt_char in enumerate(crib_text):
            pos = crib_pos + j
            ki = alpha.index(keyword[pos % len(keyword)])
            pi = alpha.index(pt_char)
            if cipher_type == "vig":
                expected[pos] = alpha[(pi + ki) % 26]
            else:
                expected[pos] = alpha[(ki - pi) % 26]
    return expected

# SA for transposition cipher: swap positions in σ, score decrypted text
def sa_search(keyword, cipher_type, alpha, n_steps=500000, seed=42):
    rng = random.Random(seed)
    n = 97
    sigma = list(range(n))
    rng.shuffle(sigma)

    # Decrypt helper
    klen = len(keyword)
    a2i = {{c: i for i, c in enumerate(alpha)}}
    key_idx = [a2i[keyword[j % klen]] for j in range(n)]
    carved_idx = [a2i[c] for c in K4]

    # Build initial PT
    pt = [''] * n
    for j in range(n):
        ci = carved_idx[sigma[j]]
        if cipher_type == "vig":
            pt[j] = alpha[(ci - key_idx[j]) % 26]
        else:
            pt[j] = alpha[(key_idx[j] - ci) % 26]

    sc = score(''.join(pt))
    best_sc, best_pt = sc, ''.join(pt)

    T = 25.0
    cooling = math.exp(math.log(0.005/25.0) / n_steps)

    for step in range(n_steps):
        a, b = rng.sample(range(n), 2)
        # Compute new PT at positions a, b after swap
        ci_a = carved_idx[sigma[b]]
        ci_b = carved_idx[sigma[a]]
        if cipher_type == "vig":
            npt_a = alpha[(ci_a - key_idx[a]) % 26]
            npt_b = alpha[(ci_b - key_idx[b]) % 26]
        else:
            npt_a = alpha[(key_idx[a] - ci_a) % 26]
            npt_b = alpha[(key_idx[b] - ci_b) % 26]

        old_a, old_b = pt[a], pt[b]
        pt[a], pt[b] = npt_a, npt_b

        # Incremental score (affected quadgrams)
        affected = set()
        for p in (a, b):
            for s in range(max(0, p-3), min(n-4, p)+1):
                affected.add(s)
        old_c = sum(qg.get(old_a if i==a else (old_b if i==b else pt[i]) for ... ) ... )
        # Simplified: just rescore
        new_sc = score(''.join(pt))
        delta = new_sc - sc

        if delta > 0 or rng.random() < math.exp(delta / T):
            sigma[a], sigma[b] = sigma[b], sigma[a]
            sc = new_sc
            if sc > best_sc:
                best_sc = sc
                best_pt = ''.join(pt)
        else:
            pt[a], pt[b] = old_a, old_b
        T *= cooling

    return best_sc, best_pt, sigma
```

## What has ALREADY been tried (DO NOT repeat):
- Identity, reverse, boustrophedon, column-major, spiral, S-curve reading orders (widths 29-33): ALL NOISE
- Grille extract first-97 mod 97 as permutation: NOT a valid permutation
- Grille extract rank-order / inverse-rank as permutation: NOISE
- Columnar unscramble widths 2-10 (all column orderings): NOISE
- Width-8 columnar (all 40320 perms): ALL NOISE (E-GRILLE-20). Widths 7, 9, 12, 13: NOISE.
- Direct running key (grille as Vig/Beau key for K4): NOISE
- SA with pinned cribs (cribs at CARVED text positions): converges but not breakthrough
- Hill climbing for English coherence: loses cribs
- 200+ grille-derived permutations from e_unscramble_01/02: ALL NOISE
- T-position marking (7 variants): ALL NOISE (E-GRILLE-17)
- EQUAL anagram values as grille params (155 configs): NOISE (E-GRILLE-18)
- **SA with Model 2 on all configs is running locally (e_grille_22_model2_sa.py)**
  — if you have creative PERMUTATION IDEAS, focus on those instead of SA

## Rules
1. Write Python scripts in the `scripts/` directory
2. ALWAYS run scripts with: `cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/YOUR_SCRIPT.py`
3. Use `python3 -u` for unbuffered output
4. Save results to `blitz_results/YOUR_AGENT_NAME/` directory
5. If you find ANY crib hit (EASTNORTHEAST or BERLINCLOCK anywhere in plaintext), IMMEDIATELY report it
6. Print progress regularly so we can monitor
7. Be COMPUTATIONAL — write code, run it, analyze results, iterate
8. Use all available CPU cores (multiprocessing) for brute-force searches
9. **FOCUS ON PERMUTATION DERIVATION**: SA is running locally. Your value-add is figuring out
   HOW the grille/sculpture/clues define the specific permutation.
"""

# ── Agent-specific prompts ──────────────────────────────────────────────────

AGENT_PROMPTS = {
    "grille_geometry": {
        "title": "Grille Mask Geometry — Model 2: Physical hole pattern → permutation",
        "prompt": SHARED_PREAMBLE + """
## YOUR SPECIFIC MISSION: Grille Mask Geometry (Model 2 update)

The binary mask has 107 holes in a 28×33 grid. K4 has 97 characters.
CONFIRMED: Scramble is the OUTER layer. The grille defines HOW to unscramble.
The grille is STATIC Cardan (not Fleissner rotating) — 28×33 is not square.
Closest military analog: RS44 (WWII) — rectangular stencil, irregular holes.
RS44 two-step: stencil defines WHICH cells, column numbering defines reading SEQUENCE.

### Approaches to try (write code for EACH):

**A. RS44-style two-step**
- Step 1: The 107 holes define WHICH 97 positions matter (select 97 from 107)
- Step 2: A numbering rule (column-based, keyword-based) defines the SEQUENCE
- Try: number holes by column index, read in that order → permutation
- Try: number by KA-alphabet ordering of extracted letters → permutation
- Try: number by distance from top-left, center, or T-diagonal

**B. Hole-to-K4 overlay**
- K4 spans ~3 rows on the sculpture (rows 26-28, ~31 chars/row)
- Map the 28×33 mask to a 3×33 region → ~99 cells, 97 chars
- Which holes fall on K4 positions? Reading order of those holes = σ
- Try various row offsets and alignments

**C. "8 Lines 73" as grid dimensions**
- 8 rows × 12-13 columns ≈ 97 chars
- Lay K4 in this grid. The mask's hole pattern at rows/cols matching this grid
  defines the reading order.
- 73 = number of unknown positions (97 - 24 known crib chars)

**D. Column-of-holes as transposition key**
- Count holes per column (33 columns) → 33 numbers → columnar key for K4
- Alternatively: column indices of holes as a sequence → derive permutation

**E. Hole coordinates → permutation via modular arithmetic**
- For each hole at (row r, col c): compute (r*33 + c) mod 97 → position in permutation
- Also try: (r*31 + c) mod 97, (r*29 + c) mod 97, etc.
- Check if any produces a valid permutation (all unique mod 97)

**F. Diagonal and spiral readings**
- Read holes along diagonals (NW→SE, NE→SW) → reading order for K4
- Spiral from center outward, or from corners inward

For EVERY candidate permutation, run test_perm() and report results.
Write your main script as `scripts/blitz_grille_geometry_v5.py`.
""",
    },

    "numeric_permuter": {
        "title": "Numeric Permutation Derivation — Convert extract to numbers",
        "prompt": SHARED_PREAMBLE + """
## YOUR SPECIFIC MISSION: Numeric Permutation Derivation

The 106-char grille extract contains information. Convert it to a valid permutation of 97 characters.

### Approaches to try (write code for EACH):

**A. KA-index arithmetic**
- Each char → KA position (K=0, R=1, Y=2, P=3, T=4, ...)
- First 97 values: try cumulative sum mod 97, running difference mod 97
- Pair consecutive values: (a*26 + b) mod 97 for pairs → 53 values (need 97)
- Triple encoding: (a*676 + b*26 + c) mod 97
- Try EVERY arithmetic combination that produces a valid permutation of 0-96

**B. Rank-order with tie-breaking variations**
- Rank the first 97 chars by KA value — BUT vary the tie-breaking rule:
  - Break ties by position (already tried → NOISE)
  - Break ties by REVERSE position
  - Break ties by next character value
  - Break ties by previous character value
  - Break ties randomly (sample 10000 random tie-breakings)

**C. Extract as base-26 number → permutation**
- Treat entire 106-char extract as a base-26 number
- Convert to factorial number system → Lehmer code → permutation
- Use different subsets (first 97, last 97, every other, etc.)

**D. Character frequency ranking**
- Sort K4 characters by their frequency in the grille extract
- Characters appearing more often in extract get lower positions
- This is a frequency-based reordering

**E. Pattern matching between extract and K4**
- For each char in K4, find its occurrence position in the extract
- If char appears multiple times, assign occurrences in order
- Yields a mapping: K4_pos → extract_pos (or vice versa)

**F. Modular chains**
- Start at position 0. Next position = (current + extract_KA_value) mod 97
- Iterate until all 97 positions visited (if cycle covers all)
- Try different starting positions and different step functions

**G. Extract as a KEY for standard transposition**
- Use extract chars as columnar key (sort order = column reading order)
- Width = len(extract) / num_rows for various row counts

For EVERY candidate, run test_perm() and report results.
Write your main script as `scripts/blitz_numeric_permuter.py`.
""",
    },

    "t_position": {
        "title": "T-Position Exploitation — T-avoidance as positional encoding",
        "prompt": SHARED_PREAMBLE + """
## YOUR SPECIFIC MISSION: T-Position Exploitation

T is the ONLY letter missing from the 106-char grille extract. This is deliberate (P ≈ 1/69).
"T is your position" could mean T-positions in the tableau encode the permutation.

### The T-diagonal in the KA tableau
In the KA alphabet (KRYPTOSABCDEFGHIJLMNQUVWXZ), T is at index 4.
In each row of the 28-row tableau, the T moves one position left (cyclic shift).
Row 1: T is at column 4 (0-indexed)
Row 2: T is at column 3
Row 3: T is at column 2
...and so on cyclically.

### Approaches to try (write code for EACH):

**A. T-column positions as permutation indices**
- For each of 28 rows, compute T's column position
- These 28 numbers could be KEY values for a transposition of K4
- Try as columnar key, as strip reordering key, as route key

**B. Distance from each hole to nearest T**
- For each of the 107 holes, compute Manhattan/Euclidean distance to the T-diagonal
- These 107 distance values → select 97 → permutation
- Try: closest-T-first ordering, farthest-T-first ordering

**C. T-position relative encoding**
- For each hole at (row, col), compute (col - T_col_in_that_row) mod 33
- This offset encodes position RELATIVE to T
- 107 offset values → select/map to 97 K4 positions

**D. T as boundary marker**
- T-diagonal divides the tableau into two regions (left of T, right of T)
- Holes in left region → first part of K4, holes in right → second part
- Or: T-diagonal defines the FOLD LINE for the permutation

**E. T-insertion reconstruction**
- The grille extract has 106 chars, K4 has 97. The 106 chars PLUS T-insertions would give ~112+ chars
- What if: insert T at specific positions in the extract to get 97 values that map to K4?
- Where T appears in the full tableau at hole positions = where to insert T
- After insertion, take first/last 97 chars

**F. T-avoidance as bit encoding**
- Each hole is either "close to T" (0) or "far from T" (1) — binary encoding
- 107 bits → interpret as permutation instruction
- Or: holes ON the T-diagonal would give a specific message; their ABSENCE is the signal

**G. "T is your position" literally**
- For each of 97 K4 characters, find where T would be if that character were encrypted
- Under Vig with KRYPTOS: for CT[i], what key value makes PT = T? That key value = position encoding
- Under Beau: similar

For EVERY candidate, run test_perm() and report results.
Write your main script as `scripts/blitz_t_position.py`.
""",
    },

    "strip_route": {
        "title": "Strip & Route Ciphers — Physical reading order permutations",
        "prompt": SHARED_PREAMBLE + """
## YOUR SPECIFIC MISSION: Strip & Route Cipher Unscrambling

The carved text is arranged physically on the S-curved copper plate.
The scrambling could be a physical rearrangement: strip shuffling, route reading, or geometric transformation.

### Physical context
- K4 spans ~3 rows on the copper plate (rows 26-28 of the full text)
- The plate is S-curved (serpentine) — text alternates direction per row
- Sanborn's yellow pad: "8 Lines 73" for K4 area
- Row widths on sculpture: ~29-33 chars per row

### Approaches to try (write code for EACH):

**A. Extended columnar widths (11-20)**
- Prior work tested widths 2-10. Test 11-20 with ALL column orderings
- For width 11: 11! = 39.9M permutations (feasible with multiprocessing)
- For width 12: 12! = 479M (need smart pruning or constraint filtering)
- For widths 13+: use keyword-order only (KRYPTOS=7 cols, ABSCISSA=7, etc.)
- Use ALL CPU cores with multiprocessing.Pool

**B. "8 Lines 73" interpretation**
- 8 rows × ~12-13 chars = 97 (8×12=96, 8×13=104 → irregular)
- Try: 8 rows of lengths [13,12,12,12,12,12,12,12] = 97
- Or: 8 rows of [12,12,12,12,13,12,12,12] (extra char in different positions)
- Read columns in various orders = unscrambling permutation
- Try all column orderings for width 12 and 13

**C. Double transposition**
- Apply TWO columnar transpositions in sequence
- Width1 × Width2 where Width1,Width2 ∈ {{7,8,9,10,11,12,13}}
- For each combo: key1 from KRYPTOS (width 7), key2 from ABSCISSA (width 7)
- Also try: key1 from keyword, key2 from reverse keyword
- This is "two systems" → two transpositions

**D. Rail fence / zigzag at various depths**
- Depths 2-15 (some not yet tested)
- Combined with columnar: rail fence then columnar, or vice versa

**E. Myszkowski transposition with keywords**
- Uses repeating letters in keyword to group columns
- KRYPTOS has no repeats, but PALIMPSEST has repeated letters
- ABSCISSA has repeated letters: A(×3), S(×2)

**F. Disrupted/incomplete columnar**
- Standard columnar with some cells left BLANK
- If K4 has 97 chars and grid is 8×13=104, then 7 cells are blank
- Where blanks are placed changes the permutation
- Try: blanks in last row, blanks in diagonal, blanks at T-positions

**G. AMSCO cipher**
- Alternating 1-2 character groups placed in columnar grid
- Keyword-ordered column read-off
- Try with KRYPTOS, ABSCISSA, PALIMPSEST as keywords

For EVERY candidate, run test_perm() and report results.
Write your main script as `scripts/blitz_strip_route.py`.
""",
    },

    "constraint_solver": {
        "title": "Model 2 Constraint Solver — Expected CT at cribs → CSP + SA",
        "prompt": SHARED_PREAMBLE + """
## YOUR SPECIFIC MISSION: Model 2 Constraint-Based Search

THIS IS THE MOST POWERFUL APPROACH UNDER MODEL 2.

### The key insight (Model 2 specific)
Under Model 2: PT → Cipher(key) → real_CT → Scramble(σ) → carved text.
Crib positions are in the PLAINTEXT: PT[21..33] = EASTNORTHEAST, PT[63..73] = BERLINCLOCK.
Given a key assumption (e.g., Vigenère with KRYPTOS), we can COMPUTE the expected real_CT
at all 24 crib positions: real_CT[j] = Encrypt(PT[j], key[j]).
The scramble constraint: real_CT[j] = carved[σ(j)].
So carved[σ(j)] = expected_CT[j] for each crib position j.
σ(j) must point to a carved position containing the right letter.

### Pre-computed expected CT for Vigenère/KRYPTOS/AZ:
Crib 1 (pos 21-33): O R Q I G C J D Y C P L H
Crib 2 (pos 63-73): L V P A B B U V F A Z

FORCED: Y appears ONCE in carved text (pos 64). So σ(29) = 64.
V appears twice (pos 24, 66) and needed twice → both used.
C appears twice (pos 82, 94) and needed twice → both used.

### Approaches to try (write code for EACH):

**A. CSP with backtracking**
- 24 variables: σ(crib_pos) for each crib position
- Domain = carved positions with the required letter
- Constraint: all-different
- Use arc consistency + backtracking to enumerate valid partial assignments
- Propagate forced assignments (Y→64) immediately
- Count and sample solutions

**B. Constrained SA**
- Start from constraint-valid partial (24 positions correct)
- SA-optimize remaining 73 positions for quadgram score
- Keep crib positions FIXED, only swap free positions
- Many restarts with different initial partials

**C. Extended constraints from self-encrypting positions**
- CT[32]=PT[32]=S, CT[73]=PT[73]=K under Model 2:
  real_CT[32] = Enc(S, key[32]) where key[32]=KRYPTOS[32%7]=T(19)
  Vig: real_CT[32] = (18+19)%26 = 11 = L. Beau: (19-18)%26 = 1 = B.
  real_CT[73] = Enc(K, key[73]) where key[73]=KRYPTOS[73%7]=P(15)
  Vig: real_CT[73] = (10+15)%26 = 25 = Z. Beau: (15-10)%26 = 5 = F.
  These give 2 MORE constraints → 26 total.

**D. Alternative key assumptions**
- Beaufort/KRYPTOS, Vig/PALIMPSEST, Beau/PALIMPSEST, Vig/ABSCISSA
- For each: compute expected CT at cribs, check feasibility, run CSP+SA

**E. Keystream periodicity scan (model-free)**
- DON'T assume a keyword. For candidate σ:
  k[j] = (carved[σ(j)] - PT[j]) mod 26  (Vig) or (carved[σ(j)] + PT[j]) mod 26 (Beau)
  Check if k values at crib positions show ANY period 2-26
- Sample 10M+ random permutations, check each (12 equality checks = instant)
- Or: systematically enumerate permutations satisfying some constraints

**F. Genetic algorithm on constrained space**
- Population of constraint-valid permutations (24 fixed, 73 free)
- Order crossover on free positions, quadgram fitness
- 10K population, 100K generations with elitism

Write your main script as `scripts/blitz_constraint_solver_v2.py`.
""",
    },

    "wildcard": {
        "title": "Lateral & Creative — Model 2: bespoke unscrambling under confirmed paradigm",
        "prompt": SHARED_PREAMBLE + """
## YOUR SPECIFIC MISSION: Lateral & Creative Approaches (Model 2)

Think outside the box. The unscrambling method may be something nobody has considered.
CONFIRMED: Model 2 — cipher first, scramble second. Periodic keys are viable.

### Context from Scheidt/Sanborn
- "Solve the technique first then the puzzle" — technique = unscramble method
- "Two separate systems" — cipher + scramble are separate layers
- "I masked the English language" — the scramble is the masking
- Sanborn on misspellings: "It's not what they are... as their ORIENTATION OR POSITIONING"
- Gillogly: method "never appeared in cryptographic literature"
- BESPOKE — the SCRAMBLING method is non-standard (cipher may be standard Vigenère)

### Approaches to try (write code for EACH):

**A. K4 as interleaved streams**
- Split K4 into 2 streams (even/odd positions) → unscramble each → recombine
- Split into 3, 4, 5, 7 streams → unscramble with different permutations per stream
- "Two systems" = two interleaved messages that must be separated first

**B. Grille extract XOR with K4**
- Treat both as numeric streams (KA index)
- XOR (or mod-26 difference) between extract[0:97] and K4
- The RESULT might be the unscrambling key or the permutation itself
- Try: extract_KA_pos[i] XOR K4_KA_pos[i] for each i

**C. Self-referential permutation**
- K4 defines its OWN unscrambling:
  - Character values AS positions: K4[0]='O'=14 in AZ, so position 0 → position 14
  - This creates a permutation of K4 by K4
  - Apply repeatedly (iterate the permutation) and check each iteration

**D. K1-K3 ciphertext as the scrambling key**
- K4 was scrambled using text from elsewhere on the sculpture
- K1 CT or K2 CT or K3 CT as the transposition key
- K3 is 336 chars → take first 97 as columnar key (or rank-order to permutation)

**E. Copper plate fold**
- The sculpture can be physically folded (established 2026-03-01)
- Folding brings positions into new correspondence
- Under fold: position i maps to position (fold_offset - i) for direct overlay
- Various fold points: middle of K4, end of K3, etc.
- Apply fold permutation then decrypt

**F. Alphabetic substitution → position**
- The grille extract could be a SUBSTITUTION ALPHABET
- Where 'H' in the extract means "first character", 'J' means "second", etc.
- But the extract has repeats, so: 1st H = pos 0, 1st J = pos 1, ...
- Assign by first occurrence in extract

**G. Path through KA tableau**
- The grille holes define a PATH through the tableau
- Follow this path: each hole's (row,col) → tableau[row][col]
- The ORDER of the path through the tableau = reading order for K4
- Path traced by a knight's move, or diagonal, or shortest-path between holes

**H. Clock cipher (Weltzeituhr connection)**
- BERLINCLOCK = Weltzeituhr (24-hour clock with colored segments)
- 24 hours → 24 crib positions → clock arithmetic
- Permute K4 in groups of 24 (4 groups × 24 + 1 extra)
- Rotate each group by different amounts

**I. Morse code timing**
- K0 (Morse code on walkway) has specific timing/spacing
- Timing values as permutation key for K4

**J. IDBYROWS — "Read by rows"**
- Scheidt: "IDBYROWS may not be a mistake"
- Lay out K4 in a specific grid, ID (identify) BY ROWS
- Width could be the KEY: try widths 7-15, read by rows in keyword order

For EVERY approach, implement it, run it, and report results.
Write your main script as `scripts/blitz_wildcard.py`.
""",
    },
}


# ── Agent runner ─────────────────────────────────────────────────────────────

async def run_agent(
    name: str,
    config: dict,
    project_root: Path,
    max_turns: int,
    results_dir: Path,
) -> dict:
    """Run a single agent session and return structured results."""
    from claude_agent_sdk import ClaudeAgentOptions
    from kryptosbot.sdk_wrapper import safe_query

    agent_results_dir = results_dir / name
    agent_results_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("LAUNCHING: %s", config["title"])
    logger.info("Max turns: %d | Output: %s", max_turns, agent_results_dir)
    logger.info("=" * 60)

    options = ClaudeAgentOptions(
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        cwd=str(project_root),
        max_turns=max_turns,
        env={"CLAUDECODE": "", "PYTHONPATH": "src"},
    )

    output_chunks: list[str] = []
    start = datetime.now(timezone.utc)
    crib_found = False

    try:
        async for message in safe_query(prompt=config["prompt"], options=options):
            if hasattr(message, "result") and message.result:
                chunk = str(message.result)
                output_chunks.append(chunk)
                # Check for crib discoveries in real-time
                if "CRIB HIT" in chunk or "EASTNORTHEAST" in chunk or "BERLINCLOCK" in chunk:
                    crib_found = True
                    logger.warning("*** %s: POSSIBLE CRIB HIT ***", name)
                preview = chunk[:120].replace("\n", " ").strip()
                if preview:
                    logger.info("[%s] %s", name, preview[:80])

            if hasattr(message, "content") and isinstance(message.content, list):
                for block in message.content:
                    if hasattr(block, "text") and block.text:
                        chunk = block.text
                        output_chunks.append(chunk)
                        if "CRIB HIT" in chunk or "EASTNORTHEAST" in chunk:
                            crib_found = True
                            logger.warning("*** %s: POSSIBLE CRIB HIT ***", name)
                    elif hasattr(block, "name"):
                        tool_line = f"  [tool: {getattr(block, 'name', '?')}]"
                        output_chunks.append(tool_line)

    except Exception as e:
        logger.error("Agent %s FAILED: %s", name, e)
        output_chunks.append(f"\n\nERROR: {e}")

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    raw_output = "\n".join(output_chunks)

    # Save raw output
    raw_path = agent_results_dir / f"{name}_raw.txt"
    raw_path.write_text(raw_output)

    # Extract any verdict blocks
    verdict = None
    verdict_match = re.search(r"```(?:json|verdict)?\s*\n(\{[^}]+\"verdict_status\"[^}]+\})\s*\n```",
                               raw_output, re.DOTALL)
    if verdict_match:
        try:
            verdict = json.loads(verdict_match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    # Extract best scores mentioned in output
    score_matches = re.findall(r"[Ss]core[:\s]+(-?\d+\.?\d*)", raw_output)
    best_score = max((float(s) for s in score_matches), default=None)

    result = {
        "agent": name,
        "title": config["title"],
        "elapsed_seconds": round(elapsed, 1),
        "output_length": len(raw_output),
        "crib_found": crib_found,
        "best_score": best_score,
        "verdict": verdict,
        "raw_output_file": str(raw_path),
    }

    # Save structured result
    result_path = agent_results_dir / f"{name}_result.json"
    result_path.write_text(json.dumps(result, indent=2))

    logger.info("=" * 60)
    logger.info("COMPLETED: %s (%.0fs, %d chars, crib=%s, best_score=%s)",
                name, elapsed, len(raw_output), crib_found, best_score)
    logger.info("=" * 60)

    return result


# ── Campaign orchestration ──────────────────────────────────────────────────

async def run_campaign(args: argparse.Namespace) -> None:
    """Launch all agents concurrently and aggregate results."""
    project_root = Path(args.project_root).resolve()
    results_dir = project_root / "blitz_results"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Filter agents
    if args.single:
        agents = {args.single: AGENT_PROMPTS[args.single]}
    else:
        agents = dict(list(AGENT_PROMPTS.items())[:args.agents])

    logger.info("=" * 70)
    logger.info("KRYPTOSBOT BLITZ CAMPAIGN — ALL-OUT UNSCRAMBLING ASSAULT")
    logger.info("=" * 70)
    logger.info("Project root: %s", project_root)
    logger.info("Agents: %d | Max turns: %d | Results: %s",
                len(agents), args.max_turns, results_dir)
    logger.info("Agents: %s", ", ".join(agents.keys()))
    logger.info("=" * 70)

    # Launch all agents concurrently
    tasks = [
        run_agent(name, config, project_root, args.max_turns, results_dir)
        for name, config in agents.items()
    ]

    start = time.time()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    total_elapsed = time.time() - start

    # Process results
    successful = []
    failed = []
    any_crib = False

    for r in results:
        if isinstance(r, Exception):
            failed.append(str(r))
        else:
            successful.append(r)
            if r.get("crib_found"):
                any_crib = True

    # Print summary
    logger.info("")
    logger.info("=" * 70)
    logger.info("BLITZ CAMPAIGN COMPLETE — %.0fs total", total_elapsed)
    logger.info("=" * 70)
    logger.info("Successful: %d | Failed: %d | Crib found: %s",
                len(successful), len(failed), any_crib)
    logger.info("")

    for r in successful:
        crib_flag = " *** CRIB ***" if r.get("crib_found") else ""
        logger.info("  %-20s | %6.0fs | score=%s%s",
                    r["agent"], r["elapsed_seconds"],
                    r.get("best_score", "N/A"), crib_flag)

    for f in failed:
        logger.error("  FAILED: %s", f[:100])

    if any_crib:
        logger.warning("")
        logger.warning("=" * 70)
        logger.warning("*** CRIB HIT DETECTED — CHECK AGENT OUTPUTS ***")
        logger.warning("=" * 70)

    # Save campaign summary
    summary = {
        "campaign": "blitz_unscramble",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_elapsed_seconds": round(total_elapsed, 1),
        "agents_launched": len(agents),
        "successful": len(successful),
        "failed": len(failed),
        "any_crib_found": any_crib,
        "results": successful,
        "errors": failed,
    }

    summary_path = results_dir / "blitz_campaign_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    logger.info("\nCampaign summary: %s", summary_path)
    logger.info("Agent outputs: %s/*/", results_dir)


async def run_preflight() -> bool:
    """Test that SDK is working before committing to a full campaign."""
    from kryptosbot.sdk_wrapper import preflight_check
    logger.info("Running preflight check...")
    ok, msg = await preflight_check()
    if ok:
        logger.info("Preflight PASSED: %s", msg)
    else:
        logger.error("Preflight FAILED: %s", msg)
    return ok


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="KryptosBot Blitz Campaign — ALL-OUT UNSCRAMBLING ASSAULT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--agents", type=int, default=6,
        help="Number of agents to launch (1-6, default: 6)",
    )
    parser.add_argument(
        "--max-turns", type=int, default=25,
        help="Max agentic turns per agent (default: 25)",
    )
    parser.add_argument(
        "--single", type=str, default=None,
        choices=list(AGENT_PROMPTS.keys()),
        help="Run a single specific agent only",
    )
    parser.add_argument(
        "--project-root", type=str, default=".",
        help="Project root directory (default: current dir)",
    )
    parser.add_argument(
        "--preflight", action="store_true",
        help="Run preflight check only (test SDK/auth)",
    )
    parser.add_argument(
        "--list", action="store_true", dest="list_agents",
        help="List all available agents and exit",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list_agents:
        print("\nAvailable agents:")
        print("-" * 70)
        for name, config in AGENT_PROMPTS.items():
            print(f"  {name:22s} — {config['title']}")
        print()
        return

    if args.preflight:
        ok = asyncio.run(run_preflight())
        sys.exit(0 if ok else 1)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY required.", file=sys.stderr)
        print("Set it with: export ANTHROPIC_API_KEY=sk-ant-...", file=sys.stderr)
        print("Or add it to kryptosbot/.env", file=sys.stderr)
        sys.exit(1)

    asyncio.run(run_campaign(args))


if __name__ == "__main__":
    main()
