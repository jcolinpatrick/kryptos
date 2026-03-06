#!/usr/bin/env python3
"""
Cipher: Fleissner turning grille
Family: grille
Status: active
Keyspace: 4^25 = 1.13e15 (10x10 Fleissner)
Last run:
Best score:
"""
"""
Fleissner Grille Exploration for K4

KEY INSIGHT (user theory, 2026-03-05):
- K4 = 97 chars + 3 question marks on sculpture = 100 = 10x10
- The grille extract from the Cardan mask is EXACTLY 100 characters
- A Fleissner (turning) grille on a 10x10 grid has 25 orbits x 4 rotations = 100 cells
- The 3 ?'s are the 3 "null" cells that complete the 10x10

This script explores:
1. Mapping ? positions in the 28x31 master grid
2. Various 10x10 arrangements of K4 + 3 ?'s
3. Fleissner grille search with crib constraints
4. Whether the 100-char grille extract encodes orbit assignments
5. Fleissner + Vigenere/Beaufort substitution layer
"""

import sys
import os
import time
import random
import json
import math
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# ── Full sculpture text (28x31 grid) ────────────────────────────────────
# From full_ciphertext.md - all 868 positional characters including 3 ?'s
FULL_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",   # ? at col 6
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",   # ? at col 8
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",
    "FLGGTEZFKZBSFDQVGOGIPUFXHHDRKF",     # squeezed ? removed (non-positional)
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",
    # --- Bottom half (K3 + ? + K4) ---
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",   # ? at col 26, K4 starts col 27
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",
]

print("=" * 70)
print("FLEISSNER GRILLE EXPLORATION FOR K4")
print("=" * 70)

# ── Step 1: Locate all ? positions in the 28x31 grid ────────────────────
print("\n--- Step 1: Question mark positions in 28x31 grid ---")

qmark_positions = []  # (row, col) in 28x31 grid
k4_positions = []     # (row, col) for all 97 K4 characters
all_positions = []    # (row, col, char) for all 868 characters

# Handle rows with different lengths - normalize to 31
for row_idx, row_text in enumerate(FULL_ROWS):
    if len(row_text) == 32:
        # Row has 32 chars - this is the header-style row, trim to 31
        # Actually some rows naturally have 31-32 chars due to the sculpture layout
        row_text = row_text[:31]
    elif len(row_text) < 31:
        # Pad to 31 (shouldn't happen with correct data)
        row_text = row_text.ljust(31)

    for col_idx, ch in enumerate(row_text[:31]):
        all_positions.append((row_idx, col_idx, ch))
        if ch == '?':
            qmark_positions.append((row_idx, col_idx))

# Identify K4 positions (starts at row 24, col 27)
k4_start_found = False
k4_chars_collected = []
for row_idx in range(24, 28):
    start_col = 27 if row_idx == 24 else 0
    row_text = FULL_ROWS[row_idx][:31]
    for col_idx in range(start_col, min(len(row_text), 31)):
        ch = row_text[col_idx]
        if ch != '?':
            k4_positions.append((row_idx, col_idx))
            k4_chars_collected.append(ch)

# Verify K4 extraction
k4_from_grid = ''.join(k4_chars_collected)
print(f"K4 from grid: {k4_from_grid[:30]}... (len={len(k4_from_grid)})")
print(f"K4 expected:  {CT[:30]}... (len={CT_LEN})")
print(f"Match: {k4_from_grid == CT}")

print(f"\nQuestion mark positions (row, col):")
for r, c in qmark_positions:
    row_text = FULL_ROWS[r][:31]
    context = row_text[max(0,c-3):c+4]
    print(f"  Row {r:2d}, Col {c:2d} — context: ...{context}...")

print(f"\nTotal ?'s found: {len(qmark_positions)}")
print(f"K4 chars found: {len(k4_chars_collected)}")
print(f"K4 + ?'s = {len(k4_chars_collected) + len(qmark_positions)}")

# ── Step 2: Arrange 100 chars (K4 + 3 ?'s) in 10x10 ────────────────────
print("\n--- Step 2: 10x10 arrangements ---")

# Collect the 100 positions: 97 K4 + 3 ?'s
# The ?'s are at different places in the 28x31 grid.
# For a 10x10 Fleissner, we need to decide HOW to arrange them.

# Arrangement A: Simple sequential (K4 chars row-by-row, ?'s at end)
arrangement_A = list(CT) + ['?', '?', '?']
print(f"\nArrangement A: K4 then ?'s at end")
for row in range(10):
    print(f"  Row {row}: {''.join(arrangement_A[row*10:(row+1)*10])}")

# Arrangement B: ?'s interspersed at their relative positions
# The ?'s are at positions relative to K4 in the sculpture's reading order.
# ? at (3,6), (7,8), (24,26) in the 28x31 grid.
# K4 is at rows 24-27. The ?'s at rows 3 and 7 are FAR from K4.
# Only the ? at (24,26) is adjacent to K4.
print(f"\nArrangement B: ?'s at their positions relative to K4")
print(f"  ?1 at grid (3,6) — in K2 territory, far from K4")
print(f"  ?2 at grid (7,8) — in K2 territory, far from K4")
print(f"  ?3 at grid (24,26) — immediately before K4")
print(f"  Only ?3 is physically adjacent to K4.")

# Arrangement C: K4 in the physical 4-row layout (row 24-27 of the 31-wide grid)
# K4 occupies: row 24 cols 27-30 (4 chars), rows 25-27 full (31 chars each) = 97
# If we include ?3 at (24,26): we get cols 26-30 of row 24 = 5 chars, then 31+31+31 = 98
# Total = 98. Still need 2 more for 100.
# Row 24, cols 0-25 = K3 territory (26 chars)
# We could extend to row 24 cols 24-30 (adding 2 more K3 chars) to get 100... ugly.
print(f"\nArrangement C: Physical K4 subgrid in 31-wide layout")
print(f"  Row 24: ...TVDOHW?OBKR (cols 20-30)")
print(f"  Row 25: {FULL_ROWS[25][:31]}")
print(f"  Row 26: {FULL_ROWS[26][:31]}")
print(f"  Row 27: {FULL_ROWS[27][:31]}")

# ── Step 3: Fleissner grille mechanics on 10x10 ─────────────────────────
print("\n--- Step 3: Fleissner grille on 10x10 ---")

def rotate_90(r, c, size=10):
    """Rotate (r,c) 90 degrees clockwise in a size x size grid."""
    return (c, size - 1 - r)

def build_orbits(size=10):
    """Build rotation orbits for a size x size Fleissner grille.
    Returns list of 25 orbits, each = [(r0,c0), (r1,c1), (r2,c2), (r3,c3)]
    where position k is the location after k rotations.
    """
    orbits = []
    visited = set()
    for r in range(size):
        for c in range(size):
            if (r, c) not in visited:
                orbit = [(r, c)]
                cr, cc = r, c
                for _ in range(3):
                    cr, cc = rotate_90(cr, cc, size)
                    orbit.append((cr, cc))
                unique = list(dict.fromkeys(orbit))  # preserve order, remove dupes
                if len(unique) == 4:
                    orbits.append(unique)
                    visited.update(unique)
    return orbits

ORBITS = build_orbits(10)
print(f"10x10 orbits: {len(ORBITS)} (need 25)")
assert len(ORBITS) == 25, f"Expected 25 orbits, got {len(ORBITS)}"

# Show orbit structure
print(f"\nOrbit structure (first 5):")
for i, orb in enumerate(ORBITS[:5]):
    labels = [f"({r},{c})" for r, c in orb]
    print(f"  Orbit {i:2d}: {' -> '.join(labels)}")

# ── Step 4: Fleissner permutation generation ─────────────────────────────
print("\n--- Step 4: Fleissner permutation analysis ---")

def fleissner_perm(hole_choices, grid_text):
    """
    Generate the reading order for a Fleissner grille.

    hole_choices: list of 25 values (0-3). For orbit i, the hole is cut at
                  position hole_choices[i] (one of the 4 orbit positions).

    Encryption:
      Rotation 0: place grille, write PT through holes (row-major order)
      Rotation 1: rotate 90 CW, write more PT
      Rotation 2: rotate 180, write more PT
      Rotation 3: rotate 270, write more PT
      Read filled grid row-by-row -> CT

    Decryption:
      Arrange CT in 10x10 grid (row-major)
      Rotation 0: read through holes -> first 25 PT chars
      Rotation 1: rotate, read -> next 25
      ... etc -> 100 PT chars total (97 real + 3 nulls)

    Returns: reading_order[0..99] where reading_order[i] = grid linear index
             The first 97 entries give the PT order.
    """
    reading_order = []
    for rotation in range(4):
        # In rotation k, the hole for orbit i is at position (hole_choices[i] + k) % 4
        holes = []
        for i in range(25):
            pos_idx = (hole_choices[i] + rotation) % 4
            r, c = ORBITS[i][pos_idx]
            linear = r * 10 + c
            holes.append(linear)
        holes.sort()  # Read in row-major order within this rotation
        reading_order.extend(holes)
    return reading_order


def apply_fleissner_decrypt(grid_text, reading_order):
    """Read grid_text through the Fleissner grille to get plaintext."""
    return ''.join(grid_text[reading_order[i]] for i in range(min(len(reading_order), len(grid_text))))


# Test: identity grille (holes at position 0 for all orbits)
test_holes = [0] * 25
test_perm = fleissner_perm(test_holes, arrangement_A)
test_pt = apply_fleissner_decrypt(arrangement_A, test_perm)
print(f"Identity grille decrypt: {test_pt[:40]}...")
print(f"  (This is K4 read in Fleissner order with all holes at position 0)")

# ── Step 5: Crib-constrained search ──────────────────────────────────────
print("\n--- Step 5: Crib-constrained Fleissner search ---")

# For PURE transposition Fleissner:
# CT is arranged in 10x10 grid. Fleissner reading order gives PT.
# PT[i] = grid[reading_order[i]]
# At crib positions: PT[p] = known letter
# So grid[reading_order[p]] must equal the crib letter.
# grid = K4 + 3 nulls (arrangement A: nulls at positions 97,98,99 in the grid)

# For Arrangement A: grid positions 0-96 have CT[0]-CT[96], positions 97-99 have '?'
grid_A = list(CT) + ['?', '?', '?']

# For each crib position p, we need grid_A[reading_order[p]] == CRIB_DICT[p]
# reading_order[p] depends on which orbit contains position p and the hole choice.

# Build lookup: which CT positions have each letter?
ct_letter_positions = {}
for i, ch in enumerate(CT):
    if ch not in ct_letter_positions:
        ct_letter_positions[ch] = []
    ct_letter_positions[ch].append(i)

print(f"CT letter counts for crib letters:")
for p in sorted(CRIB_DICT.keys()):
    letter = CRIB_DICT[p]
    count = len(ct_letter_positions.get(letter, []))
    print(f"  PT[{p:2d}] = {letter}: {count} occurrences in CT")

# Expected random crib matches per grille
expected_random = sum(len(ct_letter_positions.get(CRIB_DICT[p], [])) / 100
                      for p in CRIB_DICT)
print(f"\nExpected random crib matches: {expected_random:.2f}/24")

# ── Phase A: Pure transposition Monte Carlo ──────────────────────────────
print("\n--- Phase A: Pure transposition MC (5M random Fleissner grilles) ---")

random.seed(42)
N_SAMPLES = 5_000_000
best_pure = 0
best_pure_holes = None
hist_pure = Counter()
t0 = time.time()

for trial in range(N_SAMPLES):
    holes = [random.randint(0, 3) for _ in range(25)]
    reading = fleissner_perm(holes, grid_A)

    # Count crib matches
    matches = 0
    for p, expected in CRIB_DICT.items():
        if p < 100:
            grid_pos = reading[p]
            if grid_pos < len(grid_A) and grid_A[grid_pos] == expected:
                matches += 1

    hist_pure[matches] += 1
    if matches > best_pure:
        best_pure = matches
        best_pure_holes = holes[:]
        pt = apply_fleissner_decrypt(grid_A, reading)
        print(f"  Trial {trial:,}: {matches}/24 cribs — PT: {pt[:50]}...")

    if trial % 1_000_000 == 0 and trial > 0:
        print(f"  {trial/1e6:.0f}M trials, best={best_pure}/24, {time.time()-t0:.1f}s")

print(f"\nPhase A results: best={best_pure}/24 from {N_SAMPLES:,} random grilles")
print(f"Distribution: {dict(sorted(hist_pure.items()))}")
print(f"Time: {time.time()-t0:.1f}s")

# ── Phase B: SA on Fleissner orientations (pure transposition) ───────────
print("\n--- Phase B: SA search (pure transposition, 20 restarts) ---")

best_sa_pure = 0
best_sa_holes = None
t1 = time.time()

for restart in range(20):
    holes = [random.randint(0, 3) for _ in range(25)]
    reading = fleissner_perm(holes, grid_A)

    current_score = 0
    for p, expected in CRIB_DICT.items():
        if p < 100 and reading[p] < len(grid_A) and grid_A[reading[p]] == expected:
            current_score += 1

    best_this = current_score
    T = 3.0

    for step in range(500_000):
        idx = random.randint(0, 24)
        old = holes[idx]
        holes[idx] = (old + random.randint(1, 3)) % 4

        reading = fleissner_perm(holes, grid_A)
        new_score = 0
        for p, expected in CRIB_DICT.items():
            if p < 100 and reading[p] < len(grid_A) and grid_A[reading[p]] == expected:
                new_score += 1

        delta = new_score - current_score
        if delta > 0 or random.random() < math.exp(delta / max(T, 0.01)):
            current_score = new_score
            if current_score > best_this:
                best_this = current_score
        else:
            holes[idx] = old

        T *= 0.999993

    if best_this > best_sa_pure:
        best_sa_pure = best_this
        best_sa_holes = holes[:]

    if restart % 5 == 0:
        print(f"  Restart {restart}: best_this={best_this}/24, overall={best_sa_pure}/24")

print(f"\nPhase B results: SA best={best_sa_pure}/24")
print(f"Time: {time.time()-t1:.1f}s")

# ── Phase C: Fleissner + Vigenere (period 7/8) ───────────────────────────
print("\n--- Phase C: Fleissner + Vigenere/Beaufort ---")
print("Testing: grille transposition THEN periodic substitution")

# Model: PT -> Vigenere(key) -> real_CT -> Fleissner(grille) -> grid -> read row-major -> carved CT
# Decryption: carved CT -> arrange in 10x10 -> Fleissner read -> real_CT -> Vigenere_decrypt -> PT
# At crib positions: key[p % period] = (real_CT[p] - PT[p]) mod 26  [Vigenere]
#                  or key[p % period] = (real_CT[p] + PT[p]) mod 26  [Beaufort]
# real_CT[p] = grid_A[reading[p]]

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_NUM = {p: ALPH_IDX[c] for p, c in CRIB_DICT.items()}

def check_periodic_consistency(reading, period, variant='vig'):
    """Check if a Fleissner grille is consistent with a periodic key."""
    residue_keys = {}  # residue -> required key value
    for p, pt_val in CRIB_NUM.items():
        if p >= 100:
            continue
        grid_pos = reading[p]
        if grid_pos >= CT_LEN:
            # Position maps to a ? cell — can't determine key
            continue
        ct_val = CT_NUM[grid_pos]

        if variant == 'vig':
            k = (ct_val - pt_val) % 26
        elif variant == 'beau':
            k = (ct_val + pt_val) % 26
        else:  # variant beau
            k = (pt_val - ct_val) % 26

        r = p % period
        if r in residue_keys:
            if residue_keys[r] != k:
                return 0  # Inconsistent
        else:
            residue_keys[r] = k

    return len(residue_keys)  # Number of consistent residues

best_vig = {7: 0, 8: 0}
best_beau = {7: 0, 8: 0}

random.seed(99)
N_PHASE_C = 5_000_000
t2 = time.time()

for trial in range(N_PHASE_C):
    holes = [random.randint(0, 3) for _ in range(25)]
    reading = fleissner_perm(holes, grid_A)

    for period in (7, 8):
        score_v = check_periodic_consistency(reading, period, 'vig')
        score_b = check_periodic_consistency(reading, period, 'beau')

        if score_v > best_vig[period]:
            best_vig[period] = score_v
            # Derive the key
            key_vals = {}
            for p, pt_val in CRIB_NUM.items():
                if p < 100 and reading[p] < CT_LEN:
                    k = (CT_NUM[reading[p]] - pt_val) % 26
                    key_vals[p % period] = k
            key_str = ''.join(ALPH[key_vals.get(r, 0)] for r in range(period))
            print(f"  Trial {trial}: Vig p={period} score={score_v}/{period} key={key_str}")

        if score_b > best_beau[period]:
            best_beau[period] = score_b
            key_vals = {}
            for p, pt_val in CRIB_NUM.items():
                if p < 100 and reading[p] < CT_LEN:
                    k = (CT_NUM[reading[p]] + pt_val) % 26
                    key_vals[p % period] = k
            key_str = ''.join(ALPH[key_vals.get(r, 0)] for r in range(period))
            print(f"  Trial {trial}: Beau p={period} score={score_b}/{period} key={key_str}")

    if trial % 1_000_000 == 0 and trial > 0:
        print(f"  {trial/1e6:.0f}M trials, {time.time()-t2:.1f}s")

print(f"\nPhase C results:")
for period in (7, 8):
    print(f"  Vig  period {period}: best={best_vig[period]}/{period}")
    print(f"  Beau period {period}: best={best_beau[period]}/{period}")
print(f"Time: {time.time()-t2:.1f}s")

# ── Phase D: SA with Fleissner + Vig consistency ─────────────────────────
print("\n--- Phase D: SA search with Fleissner + Vig(7)/Beau(7) ---")

best_sa_vig = 0
best_sa_beau = 0
t3 = time.time()

for variant in ('vig', 'beau'):
    for period in (7, 8):
        for restart in range(10):
            holes = [random.randint(0, 3) for _ in range(25)]
            reading = fleissner_perm(holes, grid_A)
            current_score = check_periodic_consistency(reading, period, variant)
            best_this = current_score
            T = 3.0

            for step in range(300_000):
                idx = random.randint(0, 24)
                old = holes[idx]
                holes[idx] = (old + random.randint(1, 3)) % 4

                reading = fleissner_perm(holes, grid_A)
                new_score = check_periodic_consistency(reading, period, variant)

                delta = new_score - current_score
                if delta > 0 or random.random() < math.exp(delta / max(T, 0.01)):
                    current_score = new_score
                    if current_score > best_this:
                        best_this = current_score
                else:
                    holes[idx] = old

                T *= 0.999993

            if best_this == period:
                # Full consistency! Derive key and decrypt
                reading = fleissner_perm(holes, grid_A)
                key_vals = {}
                for p, pt_val in CRIB_NUM.items():
                    if p < 100 and reading[p] < CT_LEN:
                        if variant == 'vig':
                            k = (CT_NUM[reading[p]] - pt_val) % 26
                        else:
                            k = (CT_NUM[reading[p]] + pt_val) % 26
                        key_vals[p % period] = k

                key = [key_vals.get(r, 0) for r in range(period)]
                key_str = ''.join(ALPH[k] for k in key)

                # Decrypt full text
                real_ct = [grid_A[reading[i]] for i in range(97)]
                pt_chars = []
                for i in range(97):
                    if real_ct[i] == '?':
                        pt_chars.append('?')
                    else:
                        ct_v = ALPH_IDX[real_ct[i]]
                        if variant == 'vig':
                            pt_v = (ct_v - key[i % period]) % 26
                        else:
                            pt_v = (key[i % period] - ct_v) % 26
                        pt_chars.append(ALPH[pt_v])
                pt_text = ''.join(pt_chars)
                print(f"  *** {variant.upper()} p={period} FULL CONSISTENCY! key={key_str}")
                print(f"      PT: {pt_text}")
                print(f"      Holes: {holes}")

        print(f"  {variant.upper()} p={period}: 10 SA restarts done")

print(f"Time: {time.time()-t3:.1f}s")

# ── Phase E: Grille extract analysis ─────────────────────────────────────
print("\n--- Phase E: Grille extract analysis ---")

GRILLE_EXTRACT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"
print(f"Grille extract: {GRILLE_EXTRACT}")
print(f"Length: {len(GRILLE_EXTRACT)}")

# IC of grille extract
from collections import Counter
ge_freq = Counter(GRILLE_EXTRACT)
ge_ic = sum(f*(f-1) for f in ge_freq.values()) / (len(GRILLE_EXTRACT) * (len(GRILLE_EXTRACT)-1))
print(f"IC: {ge_ic:.4f} (random=0.0385, English=0.067)")

# Letter frequency
print(f"Letter frequency:")
for ch in sorted(ge_freq.keys()):
    print(f"  {ch}: {ge_freq[ch]:2d} ({ge_freq[ch]/len(GRILLE_EXTRACT)*100:.1f}%)")

# Check if any letters are missing
missing = set(ALPH) - set(GRILLE_EXTRACT)
print(f"Missing letters: {missing if missing else 'NONE (all 26 present)'}")

# Could the 100-char extract encode orbit assignments?
# 100 chars = 25 orbits x 4 rotations
# If we group by orbits, do we see patterns?
print(f"\nGrouped by potential orbit structure (4 chars per orbit):")
for i in range(25):
    chunk = GRILLE_EXTRACT[i*4:(i+1)*4]
    print(f"  Orbit {i:2d}: {chunk}")

# Alternative: 25 chars per rotation (Fleissner reads 25 per rotation)
print(f"\nGrouped by rotation (25 chars per rotation):")
for rot in range(4):
    chunk = GRILLE_EXTRACT[rot*25:(rot+1)*25]
    print(f"  Rotation {rot}: {chunk}")

# Try: use grille extract positions as Vigenere key for K4
print(f"\nUsing grille extract as running key for K4:")
for variant in ('vig', 'beau'):
    pt = []
    for i in range(97):
        ct_v = ALPH_IDX[CT[i]]
        ke_v = ALPH_IDX[GRILLE_EXTRACT[i]]
        if variant == 'vig':
            pt_v = (ct_v - ke_v) % 26
        else:
            pt_v = (ke_v - ct_v) % 26
        pt.append(ALPH[pt_v])
    pt_text = ''.join(pt)
    # Quick IC check
    pt_freq = Counter(pt_text)
    pt_ic = sum(f*(f-1) for f in pt_freq.values()) / (len(pt_text)*(len(pt_text)-1))
    print(f"  {variant}: {pt_text[:50]}... IC={pt_ic:.4f}")

# Try with KA alphabet
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
print(f"\nUsing grille extract as running key (KA alphabet):")
for variant in ('vig', 'beau'):
    pt = []
    for i in range(97):
        ct_v = KA_IDX[CT[i]]
        ke_v = KA_IDX[GRILLE_EXTRACT[i]]
        if variant == 'vig':
            pt_v = (ct_v - ke_v) % 26
        else:
            pt_v = (ke_v - ct_v) % 26
        pt.append(KRYPTOS_ALPHABET[pt_v])
    pt_text = ''.join(pt)
    pt_freq = Counter(pt_text)
    pt_ic = sum(f*(f-1) for f in pt_freq.values()) / (len(pt_text)*(len(pt_text)-1))
    print(f"  {variant}: {pt_text[:50]}... IC={pt_ic:.4f}")


# ── Phase F: Non-square approaches ───────────────────────────────────────
print("\n--- Phase F: Non-square Fleissner variants ---")

# K4 occupies a 4x31 subgrid (sort of). Can we do 180-degree rotation?
# 180° on a 4x31 grid: position (r,c) -> (3-r, 30-c)
# This maps 124 cells, but K4 only has 97 (plus partial first row).

# More interesting: the full 28x31 grid has 868 cells.
# 868/2 = 434 exactly. And top/bottom halves are exactly 434 each!
# A 180° Fleissner on 28x31: 434 holes, read top half, flip, read bottom.

print(f"28x31 grid: {28*31} cells")
print(f"Half: {28*31//2} = 434")
print(f"Top 14 rows (K1+K2+2?): 14*31 = {14*31}")
print(f"Bottom 14 rows (K3+?+K4): 14*31 = {14*31}")
print(f"")
print(f"180-degree rotation on 28x31:")
print(f"  (r,c) -> (27-r, 30-c)")
print(f"  Each position pairs with its 180-rotated partner.")
print(f"  434 pairs, no fixed point (even dimensions).")
print(f"")
print(f"This means: a grille with 434 holes placed on the 28x31 grid")
print(f"would read one half of the sculpture in normal orientation,")
print(f"then flip 180 to read the other half.")
print(f"Top half = K1+K2 (the solved sections)")
print(f"Bottom half = K3+K4 (K3 solved, K4 not)")

# Check: what pairs up under 180-degree rotation in the K4 region?
print(f"\nK4 positions under 180° rotation of full 28x31 grid:")
print(f"K4 start: row 24, col 27")
print(f"  (24, 27) -> ({27-24}, {30-27}) = (3, 3)")
print(f"  (24, 28) -> (3, 2)")
print(f"  (24, 29) -> (3, 1)")
print(f"  (24, 30) -> (3, 0)")
print(f"  (25, 0)  -> (2, 30)")
print(f"  (27, 30) -> (0, 0)")
print(f"")
print(f"So K4 positions (rows 24-27) map to rows 0-3 under 180° rotation.")
print(f"Rows 0-3 contain K1 ciphertext!")
print(f"The 180° Fleissner would pair K4 positions with K1 positions.")

# ── Summary ──────────────────────────────────────────────────────────────
total_time = time.time() - t0
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Question marks: {len(qmark_positions)} at positions {qmark_positions}")
print(f"  K4 (97) + 3 ?'s = 100 = 10x10 Fleissner")
print(f"  Grille extract = 100 chars (matching!)")
print(f"")
print(f"  Phase A (pure transposition MC, 5M):  best={best_pure}/24")
print(f"  Phase B (pure transposition SA, 20):  best={best_sa_pure}/24")
print(f"  Phase C (Fleissner + Vig/Beau MC):    Vig7={best_vig[7]}/7 Vig8={best_vig[8]}/8")
print(f"                                        Beau7={best_beau[7]}/7 Beau8={best_beau[8]}/8")
print(f"  Phase E (grille extract as key):      see above")
print(f"  Phase F (180° on 28x31):              structural analysis")
print(f"")
print(f"  Total time: {total_time:.1f}s")

# Save results
os.makedirs("results", exist_ok=True)
output = {
    'experiment': 'Fleissner Exploration',
    'qmark_positions': qmark_positions,
    'arrangement': 'A (K4 then ?s at end)',
    'best_pure_mc': best_pure,
    'best_pure_sa': best_sa_pure,
    'best_vig': {str(k): v for k, v in best_vig.items()},
    'best_beau': {str(k): v for k, v in best_beau.items()},
    'elapsed': total_time,
}
with open("results/e_fleissner_exploration.json", "w") as f:
    json.dump(output, f, indent=2, default=str)
print(f"\n  Artifact: results/e_fleissner_exploration.json")
