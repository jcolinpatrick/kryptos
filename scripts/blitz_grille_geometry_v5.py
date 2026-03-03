#!/usr/bin/env python3
"""
Grille Geometry v5 — NEW APPROACHES under Model 2 paradigm:

1. KNOWN-PT CONSTRAINT BACKTRACKING
   For each keyword+cipher, compute expected real_CT at 24 crib positions.
   Use backtracking to find ALL consistent partial permutations (σ over 24
   crib positions). For each, score full decrypt. Mathematically forced
   assignments are identified and printed.

2. RS44-STYLE TWO-STEP
   107 holes define WHICH cells, column numbering defines SEQUENCE.
   Try selecting 97 of 106 (drop first/last/boundary), then apply
   column-based read order.

3. K4 PHYSICAL OVERLAY
   K4 is on sculpture rows 26-28 (~31-32 chars/row). Map 28×33 mask to
   that region; holes falling on K4 chars define reading order.

4. COLUMN-OF-HOLES TRANSPOSITION
   Holes per column → transposition key → unscramble K4.

5. HOLE COORDINATES → PERMUTATION (new modular formulas)
   (r*C+c) mod 97 for C in {28,29,30,31,32,33} and other formulas.

6. FORCED ASSIGNMENT ANALYSIS
   For KRYPTOS+Vig+AZ: Y is forced (σ(29)=64), V is forced (2 options),
   C is forced (2 options), H is forced (2 options). Print full analysis.

7. PERIOD-7 STRUCTURE IN σ
   Under KRYPTOS (period 7), test if σ could be a columnar transposition
   with width 7 (or multiples). Enumerate all w=7 columnar permutations.

8. INTERLEAVED COLUMN READING
   Different ways to read columns of the grille extract.
"""

import json, sys, os, math, itertools
from collections import defaultdict, Counter
from multiprocessing import Pool, cpu_count
import random

sys.path.insert(0, 'src')

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

GE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GE) == 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
            'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA']

# Cribs: (start_pos, text) — these are PT positions
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
CRIB_POSITIONS = {}
for start, text in CRIBS:
    for j, c in enumerate(text):
        CRIB_POSITIONS[start + j] = c

QG = json.load(open('data/english_quadgrams.json'))

def score_str(text):
    n = len(text) - 3
    return sum(QG.get(text[i:i+4], -10.) for i in range(n)) if n > 0 else -1000.

def score_per_char(text):
    n = len(text) - 3
    return score_str(text) / n if n > 0 else -10.

def vig_enc(pt, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(pt[i]) + alpha.index(key[i % len(key)])) % 26]
                   for i in range(len(pt)))

def vig_dec(ct, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(ct[i]) - alpha.index(key[i % len(key)])) % 26]
                   for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(key[i % len(key)]) - alpha.index(ct[i])) % 26]
                   for i in range(len(ct)))

RESULTS_DIR = "blitz_results/grille_geometry"
os.makedirs(RESULTS_DIR, exist_ok=True)

hits = []
all_results = []

def report_hit(label, pt, sigma=None, extra=""):
    ene = pt.find("EASTNORTHEAST")
    bc  = pt.find("BERLINCLOCK")
    sc  = score_per_char(pt)
    print(f"\n{'!'*70}")
    print(f"*** CRIB HIT: {label}")
    print(f"    ENE@{ene}  BC@{bc}  score={sc:.4f}")
    print(f"    PT: {pt}")
    if sigma: print(f"    sigma[:24]={sigma[:24]}")
    if extra: print(f"    {extra}")
    print('!'*70)
    hits.append({"label": label, "pt": pt, "ene": ene, "bc": bc, "score": sc})

def test_perm(sigma, label_base=""):
    """Test a permutation under all keyword/cipher combos. σ: real_CT[j] = K4[σ[j]]"""
    assert len(sigma) == 97
    real_ct = ''.join(K4[sigma[j]] for j in range(97))
    best_sc = -1e9
    best_r = {}
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(real_ct, kw, alpha)
                sc = score_per_char(pt)
                ene = pt.find("EASTNORTHEAST")
                bc  = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    report_hit(f"{label_base}_{cname}_{alpha_name}_{kw}", pt, list(sigma))
                if sc > best_sc:
                    best_sc = sc
                    best_r = {"label": f"{label_base}_{cname}_{alpha_name}_{kw}",
                              "pt": pt, "score": sc}
    if best_r:
        all_results.append(best_r)
    return best_sc

# ── Build K4 letter position index ──────────────────────────────────────────
K4_POS = defaultdict(list)
for i, c in enumerate(K4):
    K4_POS[c].append(i)

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 1: KNOWN-PT CONSTRAINT BACKTRACKING
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 1: KNOWN-PT CONSTRAINT BACKTRACKING")
print("="*70)
print("For each keyword+cipher, compute expected real_CT at 24 crib positions.")
print("Backtrack to find all consistent partial permutations of those 24 positions.")
print()

def compute_expected_ct(keyword, cipher, alpha):
    """Return {pt_pos: expected_real_ct_char} for all 24 crib positions."""
    expected = {}
    ai = {c: i for i, c in enumerate(alpha)}
    for start, text in CRIBS:
        for j, pt_char in enumerate(text):
            pos = start + j
            ki = ai[keyword[pos % len(keyword)]]
            pi = ai[pt_char]
            if cipher == "vig":
                expected[pos] = alpha[(pi + ki) % 26]
            else:  # beaufort
                expected[pos] = alpha[(ki - pi) % 26]
    return expected

def check_freq_feasible(expected):
    """Check if K4 has enough of each expected letter."""
    need = Counter(expected.values())
    for letter, count in need.items():
        if len(K4_POS[letter]) < count:
            return False, f"K4 has {len(K4_POS[letter])} {letter}s, need {count}"
    return True, "OK"

def backtrack_partial_perm(expected, max_solutions=10000):
    """
    Find all consistent injections: σ(crib_pos) → K4_position
    where K4[σ(crib_pos)] == expected[crib_pos] and all σ values distinct.
    Returns list of {crib_pos: k4_pos} dicts.
    """
    crib_pos_sorted = sorted(expected.keys(), key=lambda p: len(K4_POS[expected[p]]))

    solutions = []
    used_k4 = set()
    partial = {}

    def bt(idx):
        if len(solutions) >= max_solutions:
            return
        if idx == len(crib_pos_sorted):
            solutions.append(dict(partial))
            return
        cp = crib_pos_sorted[idx]
        letter = expected[cp]
        for k4p in K4_POS[letter]:
            if k4p not in used_k4:
                partial[cp] = k4p
                used_k4.add(k4p)
                bt(idx + 1)
                used_k4.remove(k4p)
                del partial[cp]

    bt(0)
    return solutions

def complete_perm_random(partial_sigma, seed=0):
    """Complete a partial permutation with remaining positions shuffled."""
    rng = random.Random(seed)
    partial_set = set(partial_sigma.values())
    remaining_k4 = [i for i in range(97) if i not in partial_set]
    remaining_pt  = [i for i in range(97) if i not in partial_sigma]
    rng.shuffle(remaining_k4)
    sigma = list(range(97))
    for pt_pos, k4_pos in partial_sigma.items():
        sigma[pt_pos] = k4_pos
    for i, pt_pos in enumerate(remaining_pt):
        sigma[pt_pos] = remaining_k4[i]
    return sigma

def complete_perm_grille_order(partial_sigma, holes_rc):
    """Complete using grille hole reading order for remaining positions."""
    partial_set = set(partial_sigma.values())
    remaining_k4 = [i for i in range(97) if i not in partial_set]
    remaining_pt  = sorted([i for i in range(97) if i not in partial_sigma])

    # Map holes (up to 97) to K4 positions in reading order
    # Try: hole[k] → K4 position k (grille defines identity-like scramble)
    # Holes reading order already defines a permutation of 0..96
    # For remaining positions, use that order
    hole_order = list(range(len(holes_rc)))
    hole_to_k4 = list(range(97))  # placeholder

    sigma = list(range(97))
    for pt_pos, k4_pos in partial_sigma.items():
        sigma[pt_pos] = k4_pos
    for i, pt_pos in enumerate(remaining_pt):
        sigma[pt_pos] = remaining_k4[i % len(remaining_k4)]
    return sigma

def score_partial(partial_sigma, keyword, cipher, alpha):
    """Score only the 24 crib positions of a partial sigma using PT coherence."""
    ai = {c: i for i, c in enumerate(alpha)}
    score = 0.
    for pt_pos, k4_pos in partial_sigma.items():
        k4_char = K4[k4_pos]
        ki = ai[keyword[pt_pos % len(keyword)]]
        ci = ai[k4_char]
        if cipher == "vig":
            pt_char = alpha[(ci - ki) % 26]
        else:
            pt_char = alpha[(ki - ci) % 26]
        expected_pt = CRIB_POSITIONS[pt_pos]
        if pt_char != expected_pt:
            return -1e9  # Contradiction (shouldn't happen if expected_ct is right)
        score += 1
    return score

best_configs = []

for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    for kw in KEYWORDS:
        for cname in ["vig", "beau"]:
            expected = compute_expected_ct(kw, cname, alpha)
            ok, reason = check_freq_feasible(expected)

            # Analyze forced / highly constrained positions
            forced = {p: K4_POS[c][0] for p, c in expected.items() if len(K4_POS[c]) == 1}
            tight = {p: K4_POS[c] for p, c in expected.items() if len(K4_POS[c]) <= 2}

            if not ok:
                # Print only notable infeasibilities
                continue

            label = f"{cname}_{alpha_name}_{kw}"

            # Count total combinations
            total_combos = 1
            for p, c in sorted(expected.items(), key=lambda x: len(K4_POS[x[1]])):
                total_combos *= len(K4_POS[c])

            if forced:
                print(f"\n[{label}] FORCED ASSIGNMENTS ({len(forced)}/24):")
                for p, k4p in sorted(forced.items()):
                    c = expected[p]
                    print(f"  σ({p})={k4p} (K4[{k4p}]={K4[k4p]}={c})")

            # Only run backtracking for configs with forced assignments or very tight
            n_forced = len(forced)
            if n_forced >= 1 or total_combos < 1e8:
                print(f"[{label}] Running backtrack (forced={n_forced}, combos≈{total_combos:.2e})...")
                solutions = backtrack_partial_perm(expected, max_solutions=5000)
                print(f"  → Found {len(solutions)} partial perms")

                best_configs.append((label, len(solutions), kw, cname, alpha, expected, solutions))

                if len(solutions) <= 100:
                    # Test each solution by completing with random fill and scoring
                    print(f"  Testing {len(solutions)} solutions with random completions...")
                    best_sc = -1e9
                    for sol_idx, sol in enumerate(solutions[:100]):
                        for seed in range(3):
                            sigma = complete_perm_random(sol, seed=seed * 97 + sol_idx)
                            real_ct = ''.join(K4[sigma[j]] for j in range(97))
                            pt = (vig_dec if cname == "vig" else beau_dec)(real_ct, kw, alpha)
                            sc = score_per_char(pt)
                            ene = pt.find("EASTNORTHEAST")
                            bc  = pt.find("BERLINCLOCK")
                            if ene >= 0 or bc >= 0:
                                report_hit(f"BT_{label}_sol{sol_idx}_seed{seed}", pt, sigma)
                            if sc > best_sc:
                                best_sc = sc
                    print(f"  Best score from random completions: {best_sc:.4f}")

print("\n--- Backtracking summary ---")
if best_configs:
    best_configs.sort(key=lambda x: x[1])  # fewest solutions = most constrained
    for label, nsol, *_ in best_configs[:10]:
        print(f"  [{label}]: {nsol} solutions")
else:
    print("  No feasible configs found (frequency constraints too tight).")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 2: RS44-STYLE TWO-STEP
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 2: RS44-STYLE TWO-STEP")
print("="*70)

# Parse grille mask
MASK_ROWS_RAW = [
    "000000001010100000000010000000001",
    "100000000010000001000100110000011",
    "000000000000001000000000000000011",
    "00000000000000000000100000010011",
    "00000001000000001000010000000011",
    "000000001000000000000000000000011",
    "100000000000000000000000000000011",
    "00000000000000000000000100000100",
    "0000000000000000000100000001000",
    "0000000000000000000000000000100",
    "000000001000000000000000000000",
    "00000110000000000000000000000100",
    "00000000000000100010000000000001",
    "00000000000100000000000000001000",
    "000110100001000000000000001000010",
    "00001010000000000000000001000001",
    "001001000010010000000000000100010",
    "00000000000100000000010000010001",
    "000000000000010001001000000010001",
    "00000000000000001001000000000100",
    "000000001100000010100100010001001",
    "000000000000000100001010100100011",
    "00000000100000000000100001100001",
    "100000000000000000001000001000010",
    "10000001000001000000100000000001",
    "000010000000000000010000100000011",
    "000000000000000000010000100000011",
    "00000000000000100000001010000001",
]

# Build hole list (row, col) for holes (0=hole)
holes_rc_all = []
for r, row in enumerate(MASK_ROWS_RAW):
    for c, ch in enumerate(row):
        if ch == '0':
            holes_rc_all.append((r, c))

print(f"Total holes (0s) in mask: {len(holes_rc_all)}")

# The first 106 holes (in reading order) correspond to the GE extract
# (one hole has no letter = is off-grid)
# The extract has 106 chars, K4 needs 97.

def perm_from_hole_order(hole_order_97):
    """
    Given 97 hole indices (in some reading order), return permutation σ where:
    σ[j] = j means "unscrambled position j maps to K4 position j"
    More precisely: hole reading order[j] says 'the j-th real_CT char is at K4 position j'
    But we need σ[j] = k4_position_for_real_ct_j
    Hole i (in extraction order) → GE[i] was taken from KA tableau position k
    We need to figure out: the hole's extraction ORDER defines the permutation.

    Interpretation: The grille, when laid over K4, defines a reading order.
    hole_order_97[j] = which K4 position is read j-th = σ(j)
    So: real_CT[j] = K4[sigma[j]]
    """
    # hole_order_97: list of 97 linear positions (row*33+col) or indices into holes_rc
    # Need to convert to K4 positions
    # Assumption: the grille is laid over K4 (97 chars) starting at position 0
    # So hole linear_pos maps to K4 position (if valid)
    sigma = list(range(97))
    for j, hp in enumerate(hole_order_97):
        if 0 <= hp < 97:
            sigma[j] = hp
        else:
            sigma[j] = hp % 97  # fallback
    return sigma

# Get linear positions of holes
holes_linear = [r * 33 + c for (r, c) in holes_rc_all]
print(f"Linear positions of holes: {holes_linear[:20]}...")

# Strategy A: Take first 97 holes in reading order (skip last 9)
# Strategy B: Take last 97 holes in reading order (skip first 9)
# Strategy C: Skip holes at row boundaries (rows with ~'s)

# For each strategy, try two column orderings:
# 1. Default reading order (left-to-right, top-to-bottom)
# 2. Column-major order: read all holes in column 0 first, then col 1, etc.
# 3. Hole rank by col: number holes by column position, use rank as permutation

def holes_to_perm_identity(selected_holes):
    """Holes in reading order → σ[j] = hole_linear[j] mod 97"""
    sigma = []
    for lp in selected_holes:
        sigma.append(lp % 97)
    if len(set(sigma)) != 97:
        return None  # Not a valid permutation
    return sigma

def holes_to_perm_colmajor(selected_holes_rc):
    """Sort holes by (col, row) → gives column-major reading order"""
    sorted_holes = sorted(selected_holes_rc, key=lambda x: (x[1], x[0]))
    return [r * 33 + c for r, c in sorted_holes]

def holes_to_perm_colkey(selected_holes_rc, keyword):
    """Number columns by keyword alphabetical rank → reorder holes."""
    # Get distinct columns used
    cols_used = sorted(set(c for r, c in selected_holes_rc))
    if len(cols_used) < len(keyword):
        return None
    # Assign keyword chars to columns in order
    col_to_rank = {}
    kw_chars = list(keyword[:len(cols_used)])
    # Sort columns by corresponding keyword char
    cols_sorted = sorted(cols_used[:len(kw_chars)],
                        key=lambda c: kw_chars[cols_used.index(c)])
    col_order = {c: i for i, c in enumerate(cols_sorted)}
    # Sort holes by (col_rank, row)
    sorted_holes = sorted(selected_holes_rc[:97],
                         key=lambda x: (col_order.get(x[1], 99), x[0]))
    return [r * 33 + c for r, c in sorted_holes]

approach2_count = 0
approach2_hits = 0

for strategy_name, selected_holes_rc in [
    ("first97", holes_rc_all[:97]),
    ("last97",  holes_rc_all[9:]),
    ("mid97_skip5each", holes_rc_all[5:102]),
]:
    if len(selected_holes_rc) != 97:
        selected_holes_rc = selected_holes_rc[:97]

    selected_linear = [r * 33 + c for r, c in selected_holes_rc]

    # Test A: linear mod 97 as sigma
    sigma_mod = [lp % 97 for lp in selected_linear]
    if len(set(sigma_mod)) == 97:
        sc = test_perm(sigma_mod, f"RS44_mod97_{strategy_name}")
        approach2_count += 1

    # Test B: column-major order
    colmaj = holes_to_perm_colmajor(selected_holes_rc)
    sigma_colmaj = [lp % 97 for lp in colmaj]
    if len(set(sigma_colmaj)) == 97:
        sc = test_perm(sigma_colmaj, f"RS44_colmaj_{strategy_name}")
        approach2_count += 1

    # Test C: keyword-ordered columns for each keyword
    for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
        result = holes_to_perm_colkey(selected_holes_rc, kw)
        if result:
            sigma_kw = [lp % 97 for lp in result]
            if len(set(sigma_kw)) == 97:
                sc = test_perm(sigma_kw, f"RS44_colkey_{kw}_{strategy_name}")
                approach2_count += 1

    # Test D: Sort holes by (distance from center, angle)
    center_r, center_c = 13.5, 16.0  # center of 28×33 grid
    dist_sorted = sorted(selected_holes_rc,
                        key=lambda x: (x[0]-center_r)**2 + (x[1]-center_c)**2)
    sigma_dist = [r*33+c for r,c in dist_sorted]
    if len(set(s % 97 for s in sigma_dist)) == 97:
        sigma_dist97 = [s % 97 for s in sigma_dist]
        sc = test_perm(sigma_dist97, f"RS44_dist_{strategy_name}")
        approach2_count += 1

print(f"RS44-style: tested {approach2_count} permutations")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 3: K4 PHYSICAL OVERLAY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 3: K4 PHYSICAL OVERLAY")
print("="*70)

# The Kryptos sculpture text (K1+K2+K3+K4 = 865 chars) is laid out
# on a copper scroll ~1.8m tall. The standard layout info:
# - Full text: 865 chars
# - Approximate chars per row: 28-32 (varies)
# - K4 starts at char 769 (0-indexed: 768), ends at 865
# - K4 = 97 chars

# Let's try multiple row widths and see which rows K4 occupies,
# then check which holes fall on those K4 rows.

FULL_K4_START = 768  # 0-indexed

for row_width in [28, 29, 30, 31, 32, 33]:
    k4_start_row = FULL_K4_START // row_width
    k4_rows_covered = list(range(k4_start_row,
                                  (FULL_K4_START + 97 + row_width - 1) // row_width))

    # Within K4 context: position in K4 (0..96) → (row, col) in K4 grid
    # K4[j] is at global row (768 + j) // row_width and col (768 + j) % row_width
    # But relative to the K4 start row, K4[j] is at local_row and local_col

    k4_global_start_col = FULL_K4_START % row_width

    # Now check which grille holes fall on K4 positions
    # The grille's row 0 corresponds to some row of the sculpture
    # Try: grille row r corresponds to sculpture row (r + k4_start_row)

    for grille_row_offset in range(max(0, k4_start_row - 5), k4_start_row + 5):
        # holes at (r, c) in grille → sculpture row r + grille_row_offset, col c
        # K4 char at sculpture (row, col) → K4_idx = row * row_width + col - FULL_K4_START

        sigma = []
        k4_hole_idx = 0

        for (r, c) in holes_rc_all:
            sculpt_row = r + grille_row_offset
            sculpt_col = c
            k4_idx = sculpt_row * row_width + sculpt_col - FULL_K4_START
            if 0 <= k4_idx < 97:
                sigma.append(k4_idx)

        if len(sigma) == 97 and len(set(sigma)) == 97:
            sc = test_perm(sigma, f"overlay_w{row_width}_off{grille_row_offset}")
        elif len(sigma) > 0:
            # Partial overlay — try extending
            pass

print("Physical overlay search complete")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 4: COLUMN-OF-HOLES TRANSPOSITION KEY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 4: COLUMN-OF-HOLES TRANSPOSITION KEY")
print("="*70)

# Count holes per column
col_holes = defaultdict(int)
for r, c in holes_rc_all:
    col_holes[c] += 1

print("Holes per column (33 cols):")
for c in range(33):
    print(f"  col{c:2d}: {col_holes[c]} holes")

# The 33 column counts give a sequence.
# Use it as a columnar transposition key for K4 (width 33):
# K4 has 97 chars. Width 33: row1=K4[0:33], row2=K4[33:66], row3=K4[66:97] (31 chars)
# Column order determined by hole counts (lower count = higher rank = read first, or vice versa)

def columnar_perm(text, col_key, width):
    """
    Columnar transposition permutation.
    col_key: list of 'width' values; columns are read in rank order.
    Returns the permutation (sigma) such that output[j] = text[sigma[j]].
    Equivalently, this is the unscramble permutation.
    """
    n = len(text)
    n_rows = (n + width - 1) // width

    # Rank the columns by col_key
    col_order = sorted(range(width), key=lambda c: col_key[c])

    # Build sigma: for each output position j, find which input position it came from
    # If we read by column: output = read col col_order[0] top-to-bottom, then col_order[1], ...
    sigma = [0] * n
    out_idx = 0
    for col in col_order:
        for row in range(n_rows):
            in_idx = row * width + col
            if in_idx < n:
                sigma[out_idx] = in_idx
                out_idx += 1

    # This sigma transforms: unscrambled[j] = scrambled[sigma[j]]
    # i.e., if carved = scrambled, then real_ct[j] = carved[sigma[j]] = K4[sigma[j]]
    return sigma

# Use hole counts as transposition key
col_key_counts = [col_holes[c] for c in range(33)]
print(f"\nColumn key (hole counts): {col_key_counts}")

# Test with width 33
sigma_col33 = columnar_perm(K4, col_key_counts, 33)
if len(set(sigma_col33)) == 97:
    test_perm(sigma_col33, "colkey_w33_holecount")
    # Also reverse: use inverse rank
    col_key_inv = [-x for x in col_key_counts]
    sigma_col33_inv = columnar_perm(K4, col_key_inv, 33)
    test_perm(sigma_col33_inv, "colkey_w33_holecount_inv")

# Try other widths
for width in [7, 8, 9, 10, 12, 13, 14, 28, 29, 30, 31, 32]:
    if width > 33:
        continue
    key = col_key_counts[:width]
    sigma = columnar_perm(K4, key, width)
    if len(set(sigma)) == 97:
        test_perm(sigma, f"colkey_w{width}_holecount")

# Also: use RANK of holes per column (not count) as key
# i.e., read holes row by row within each column (column-major), use row indices as key
col_first_hole_row = {}
for r, c in holes_rc_all:
    if c not in col_first_hole_row:
        col_first_hole_row[c] = r

col_key_firstrow = [col_first_hole_row.get(c, 99) for c in range(33)]
print(f"\nColumn key (first hole row): {col_key_firstrow}")

sigma_fr33 = columnar_perm(K4, col_key_firstrow, 33)
if len(set(sigma_fr33)) == 97:
    test_perm(sigma_fr33, "colkey_w33_firstrow")

for width in [7, 8, 9, 10, 12, 13, 28, 29, 30, 31, 32]:
    key = col_key_firstrow[:width]
    sigma = columnar_perm(K4, key, width)
    if len(set(sigma)) == 97:
        test_perm(sigma, f"colkey_w{width}_firstrow")

print("Column transposition search complete")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 5: HOLE COORDINATES → PERMUTATION VIA MODULAR ARITHMETIC
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 5: HOLE COORDINATES → PERMUTATION VIA MODULAR ARITHMETIC")
print("="*70)

def check_valid_perm(lst, n=97):
    return len(lst) == n and len(set(lst)) == n and all(0 <= x < n for x in lst)

approach5_count = 0

# F1: (r*C + c) mod 97 for various C
for C in range(26, 40):
    vals = [(r*C + c) % 97 for r, c in holes_rc_all[:97]]
    if check_valid_perm(vals):
        print(f"  VALID PERM: (r*{C}+c) mod 97 using first 97 holes")
        test_perm(vals, f"mod97_r{C}c_first97")
        approach5_count += 1

# F2: (r*C + c) mod 97 for all 107 holes (check last 97, first 97, etc.)
for C in range(26, 40):
    for subset_name, subset in [("all107", holes_rc_all[:107]),
                                  ("skip5each", holes_rc_all[5:102])]:
        vals = [(r*C + c) % 97 for r, c in subset]
        if check_valid_perm(vals, len(vals)) and len(vals) == 97:
            print(f"  VALID PERM: (r*{C}+c) mod 97 {subset_name}")
            test_perm(vals, f"mod97_r{C}c_{subset_name}")
            approach5_count += 1

# F3: rank order of (r*C + c) values (always gives valid perm)
for C in [28, 29, 30, 31, 32, 33, 97, 26, 34]:
    raw = [r*C + c for r, c in holes_rc_all[:97]]
    ranked = sorted(range(97), key=lambda i: raw[i])
    # sigma[j] = ranked[j] means: j-th real_CT char comes from K4[ranked[j]]
    if check_valid_perm(ranked):
        test_perm(ranked, f"rank_r{C}c_first97")
        approach5_count += 1
        # Also test inverse permutation
        inv = [0] * 97
        for j, v in enumerate(ranked): inv[v] = j
        test_perm(inv, f"rank_r{C}c_first97_inv")
        approach5_count += 1

# F4: Sort holes by (c*R + r) (column-then-row priority)
for R in [28, 29, 30, 33]:
    raw = [c*R + r for r, c in holes_rc_all[:97]]
    ranked = sorted(range(97), key=lambda i: raw[i])
    if check_valid_perm(ranked):
        test_perm(ranked, f"rank_c{R}r_first97")
        approach5_count += 1

# F5: Use Manhattan distance from corner (0,0) as sort key
for origin in [(0,0), (27,0), (0,32), (27,32), (0,16), (14,0), (14,16)]:
    raw = [abs(r - origin[0]) + abs(c - origin[1]) for r, c in holes_rc_all[:97]]
    ranked = sorted(range(97), key=lambda i: raw[i])
    if check_valid_perm(ranked):
        test_perm(ranked, f"manhattan_{origin[0]}_{origin[1]}")
        approach5_count += 1

# F6: Euclidean distance sort
for origin in [(0,0), (27,32), (13.5, 16.0)]:
    raw = [(r - origin[0])**2 + (c - origin[1])**2 for r, c in holes_rc_all[:97]]
    ranked = sorted(range(97), key=lambda i: raw[i])
    if check_valid_perm(ranked):
        test_perm(ranked, f"eucl_{origin[0]}_{origin[1]}")
        approach5_count += 1

# F7: Diagonal sort: r+c, r-c, etc.
for key_fn_name, key_fn in [
    ("diag_sum",  lambda r,c: r+c),
    ("diag_diff", lambda r,c: r-c),
    ("antidiag",  lambda r,c: -(r-c)),
    ("row_then_col_rev", lambda r,c: (r, -c)),
    ("col_then_row_rev", lambda r,c: (c, -r)),
    ("zigzag",    lambda r,c: (r, c if r%2==0 else -c)),
]:
    raw = [key_fn(r, c) for r, c in holes_rc_all[:97]]
    ranked = sorted(range(97), key=lambda i: raw[i])
    if check_valid_perm(ranked):
        test_perm(ranked, f"sort_{key_fn_name}")
        approach5_count += 1

print(f"Modular/distance permutations tested: {approach5_count}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 6: FORCED ASSIGNMENT ANALYSIS (KRYPTOS+Vig+AZ)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 6: FORCED ASSIGNMENT ANALYSIS — KRYPTOS+Vig+AZ")
print("="*70)

# Already computed above. Print the full analysis.
exp_kv_az = compute_expected_ct("KRYPTOS", "vig", AZ)
print("\nExpected real_CT under KRYPTOS+Vig+AZ at 24 crib positions:")
for j in sorted(exp_kv_az.keys()):
    letter = exp_kv_az[j]
    candidates = K4_POS[letter]
    crib_char = CRIB_POSITIONS[j]
    forced_str = " *** FORCED ***" if len(candidates) == 1 else ""
    print(f"  σ({j:2d}) ∈ {candidates}  [PT={crib_char}, real_CT={letter}, n={len(candidates)}]{forced_str}")

# Check frequency feasibility
need = Counter(exp_kv_az.values())
print(f"\nLetter frequency check (need vs available in K4):")
all_ok = True
for letter, count in sorted(need.items()):
    avail = len(K4_POS[letter])
    ok = avail >= count
    if not ok: all_ok = False
    print(f"  {letter}: need {count}, have {avail} {'OK' if ok else 'INFEASIBLE!'}")

if all_ok:
    print("FREQUENCY CHECK: OK — KRYPTOS+Vig+AZ is feasible")
    # Run targeted backtracking with verbose output
    solutions = backtrack_partial_perm(exp_kv_az, max_solutions=1000000)
    print(f"\nTotal partial permutations (24-position mappings): {len(solutions)}")

    # For each solution, score the partial plaintext and check non-crib positions
    if solutions:
        # The partial solution at crib positions already fixes the PT there correctly.
        # Score by completing randomly many times.
        best_completions = []
        n_test = min(len(solutions), 200)
        print(f"Testing {n_test} solutions with 10 random completions each...")
        for sol_idx, sol in enumerate(solutions[:n_test]):
            for seed in range(10):
                sigma = complete_perm_random(sol, seed=seed * 1000 + sol_idx)
                real_ct = ''.join(K4[sigma[j]] for j in range(97))
                pt = vig_dec(real_ct, "KRYPTOS", AZ)
                sc = score_per_char(pt)
                ene = pt.find("EASTNORTHEAST")
                bc  = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    report_hit(f"forced_KRYPTOS_vig_AZ_sol{sol_idx}_seed{seed}", pt, sigma)
                best_completions.append(sc)

        best_completions.sort(reverse=True)
        print(f"  Top 5 scores: {best_completions[:5]}")

# Also check KRYPTOS + Beaufort
print("\n--- KRYPTOS+Beau+AZ analysis ---")
exp_kb_az = compute_expected_ct("KRYPTOS", "beau", AZ)
print("Expected real_CT under KRYPTOS+Beau+AZ:")
for j in sorted(exp_kb_az.keys()):
    letter = exp_kb_az[j]
    candidates = K4_POS[letter]
    forced_str = " *** FORCED ***" if len(candidates) == 1 else ""
    print(f"  σ({j:2d}) ∈ {candidates}  [real_CT={letter}, n={len(candidates)}]{forced_str}")

need_b = Counter(exp_kb_az.values())
all_ok_b = all(len(K4_POS[l]) >= c for l, c in need_b.items())
print(f"Frequency check: {'OK' if all_ok_b else 'INFEASIBLE'}")

# Also KRYPTOS+Vig+KA
print("\n--- KRYPTOS+Vig+KA analysis ---")
exp_kv_ka = compute_expected_ct("KRYPTOS", "vig", KA)
for j in sorted(exp_kv_ka.keys()):
    letter = exp_kv_ka[j]
    candidates = K4_POS[letter]
    forced_str = " *** FORCED ***" if len(candidates) == 1 else ""
    print(f"  σ({j:2d}) ∈ {candidates}  [real_CT={letter}, n={len(candidates)}]{forced_str}")
need_kv = Counter(exp_kv_ka.values())
all_ok_kv = all(len(K4_POS[l]) >= c for l, c in need_kv.items())
print(f"Frequency check: {'OK' if all_ok_kv else 'INFEASIBLE'}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 7: PERIOD-7 COLUMNAR TRANSPOSITIONS
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 7: PERIOD-7 COLUMNAR TRANSPOSITIONS (Vigenère-compatible)")
print("="*70)

# Under Model 2, the cipher has period 7 (KRYPTOS). The scramble σ is
# INDEPENDENT of the cipher. But the sculpture designer might have used
# a transposition that's related to the period.
# Try columnar transposition with width 7 (all 7! = 5040 orderings)

def columnar_trans_perm(n, width, col_order):
    """
    col_order: list of column indices in read order (length = width)
    Returns σ such that: σ[j] = original position of j-th char in column-order reading.
    (Reading the columns in order col_order[0], col_order[1], ...)
    """
    n_rows = (n + width - 1) // width
    sigma = []
    for col in col_order:
        for row in range(n_rows):
            pos = row * width + col
            if pos < n:
                sigma.append(pos)
    assert len(sigma) == n
    return sigma

print("Testing all 7! = 5040 width-7 columnar transpositions...")
count7 = 0
best7 = -1e9
best7_perm = None
for col_order in itertools.permutations(range(7)):
    sigma = columnar_trans_perm(97, 7, list(col_order))
    if not check_valid_perm(sigma):
        continue
    # Quick test with KRYPTOS+vig+AZ only
    real_ct = ''.join(K4[sigma[j]] for j in range(97))
    pt = vig_dec(real_ct, "KRYPTOS", AZ)
    sc = score_per_char(pt)
    count7 += 1
    if sc > best7:
        best7 = sc
        best7_perm = list(col_order)
        best7_sigma = sigma[:]
    ene = pt.find("EASTNORTHEAST")
    bc  = pt.find("BERLINCLOCK")
    if ene >= 0 or bc >= 0:
        report_hit(f"colperm7_{col_order}", pt, sigma)

print(f"Tested {count7} width-7 columnar perms")
print(f"Best score (KRYPTOS+vig+AZ): {best7:.4f}")
if best7_perm:
    print(f"Best column order: {best7_perm}")
    real_ct = ''.join(K4[best7_sigma[j]] for j in range(97))
    print(f"Best PT: {vig_dec(real_ct, 'KRYPTOS', AZ)}")
    # Test the best with all keywords
    test_perm(best7_sigma, f"colperm7_best_{best7_perm}")

# Also try width 14 (2×7) — sample 1000 random ones
print("\nSampling 5000 width-14 columnar transpositions...")
rng = random.Random(42)
best14 = -1e9
for _ in range(5000):
    col_order = list(range(14))
    rng.shuffle(col_order)
    sigma = columnar_trans_perm(97, 14, col_order)
    real_ct = ''.join(K4[sigma[j]] for j in range(97))
    pt = vig_dec(real_ct, "KRYPTOS", AZ)
    sc = score_per_char(pt)
    if sc > best14: best14 = sc
    ene = pt.find("EASTNORTHEAST")
    bc  = pt.find("BERLINCLOCK")
    if ene >= 0 or bc >= 0:
        report_hit(f"colperm14_random", pt, sigma)

print(f"Width-14 best: {best14:.4f}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 8: GRILLE EXTRACT LETTER RANKS AS PERMUTATION
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 8: GRILLE EXTRACT LETTER RANKS AS PERMUTATION")
print("="*70)

# The 106-char grille extract may itself encode the permutation.
# Idea: within each letter group in GE, use the occurrence count as a rank.
# This gives a permutation-like mapping from [0..105] to relative ranks.

# Method A: rank GE[0..96] by position of their letter in AZ/KA
ge97 = GE[:97]
rank_az = sorted(range(97), key=lambda i: (AZ.index(ge97[i]), i))
rank_ka = sorted(range(97), key=lambda i: (KA.index(ge97[i]), i))

# rank_az[j] = which position in ge97 has the j-th smallest AZ index
# as sigma: σ[j] = rank_az[j] means "j-th real_CT char came from K4[rank_az[j]]"
if check_valid_perm(rank_az):
    test_perm(rank_az, "ge97_rank_az")
if check_valid_perm(rank_ka):
    test_perm(rank_ka, "ge97_rank_ka")

# Inverse ranks
inv_az = [0]*97
for j, v in enumerate(rank_az): inv_az[v] = j
if check_valid_perm(inv_az):
    test_perm(inv_az, "ge97_invrank_az")

inv_ka = [0]*97
for j, v in enumerate(rank_ka): inv_ka[v] = j
if check_valid_perm(inv_ka):
    test_perm(inv_ka, "ge97_invrank_ka")

# Method B: treat GE as a Vigenère key for K4 directly (running key)
# Already tried in v1-v4 — skip

# Method C: GE positions sorted by KA value, take first 97
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    # Sort all 106 positions by their letter's value in alpha
    sorted_pos = sorted(range(106), key=lambda i: (alpha.index(GE[i]), i))
    # Take first 97
    sigma_97 = sorted_pos[:97]
    if check_valid_perm(sigma_97):
        test_perm(sigma_97, f"ge106_rank_{alpha_name}_first97")
    # Take last 97
    sigma_97_last = sorted_pos[9:]
    if check_valid_perm(sigma_97_last):
        test_perm(sigma_97_last, f"ge106_rank_{alpha_name}_last97")

# Method D: GE as transposition key for K4
# If GE[0..96] defines the column key of a columnar transposition...
# Map each GE char to its AZ rank; use those 97 ranks as a columnar key
ge_ranks_az = [AZ.index(c) for c in ge97]
ge_ranks_ka = [KA.index(c) for c in ge97]

# Width = 7 columnar with GE-derived key
for width in [7, 8, 9, 10, 12, 13, 14, 97]:
    key_az = ge_ranks_az[:width]
    sigma = columnar_perm(K4, key_az, width)
    if check_valid_perm(sigma):
        test_perm(sigma, f"ge_colkey_az_w{width}")
    key_ka = ge_ranks_ka[:width]
    sigma = columnar_perm(K4, key_ka, width)
    if check_valid_perm(sigma):
        test_perm(sigma, f"ge_colkey_ka_w{width}")

print("Grille extract rank approaches done")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 9: PERIOD-8 / "8 LINES 73" STRUCTURED TRANSPOSITION
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print('APPROACH 9: "8 LINES 73" STRUCTURED TRANSPOSITION')
print("="*70)

# "8 Lines 73" from Sanborn's yellow pad — K4 has 8 lines of text,
# with 73 "unknown" (non-crib) chars. The grille period-8 rows are F(6), N(14), V(22).
# Hypothesis: the permutation is structured around 8-line groupings.
# 97 chars in 8 lines: 97 = 8*12 + 1. Try 12+12+12+12+12+12+12+13 line lengths.
# Or: rows of 13,13,12,12,12,12,12,11 etc.

# Key insight: the 97 chars might be arranged as 8 rows × ~12-13 cols.
# Common layouts:
layouts = [
    (8, 13),   # 8 rows of 13 = 104 > 97, last row partial
    (8, 12),   # 8 rows of 12 = 96 < 97
    (7, 14),   # 7×14 = 98 ≈ 97
    (13, 8),   # 13×8 = 104 ≈ 97 (transposed)
    (12, 8),   # 12×8 = 96
]

for n_rows, n_cols in layouts:
    # All columnar transpositions with this layout
    # Too many to enumerate if n_cols > 10, so sample
    if n_cols <= 8:
        perms_to_try = list(itertools.permutations(range(n_cols)))
    else:
        rng2 = random.Random(42)
        perms_to_try = []
        for _ in range(2000):
            p = list(range(n_cols))
            rng2.shuffle(p)
            perms_to_try.append(tuple(p))

    best_layout_sc = -1e9
    best_layout_order = None
    for col_order in perms_to_try:
        sigma = columnar_trans_perm(97, n_cols, list(col_order))
        if not check_valid_perm(sigma): continue
        real_ct = ''.join(K4[sigma[j]] for j in range(97))
        pt = vig_dec(real_ct, "KRYPTOS", AZ)
        sc = score_per_char(pt)
        if sc > best_layout_sc:
            best_layout_sc = sc
            best_layout_order = col_order
            best_layout_sigma = sigma[:]
        ene = pt.find("EASTNORTHEAST")
        bc  = pt.find("BERLINCLOCK")
        if ene >= 0 or bc >= 0:
            report_hit(f"8lines73_{n_rows}x{n_cols}_{col_order}", pt, sigma)

    print(f"Layout {n_rows}×{n_cols}: best={best_layout_sc:.4f} order={best_layout_order}")
    if best_layout_sigma:
        test_perm(best_layout_sigma, f"8lines73_best_{n_rows}x{n_cols}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 10: CONSTRAINT-GUIDED SA (starting from best partial sigma)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH 10: CONSTRAINT-GUIDED SA FROM PARTIAL PERMUTATION")
print("="*70)

# Use the KRYPTOS+Vig+AZ forced assignments as starting point for SA.
# The 24 crib positions are PINNED (they are correct by construction).
# SA only swaps among the 73 non-crib positions to maximize text quality.

def sa_crib_pinned(keyword, cipher_name, alpha, n_steps=1000000, n_restarts=3, seed=42):
    """SA where crib positions are LOCKED to correct K4 chars, non-crib positions are free."""
    rng = random.Random(seed)

    # Compute expected real_CT at crib positions
    expected = compute_expected_ct(keyword, cipher_name, alpha)
    ok, _ = check_freq_feasible(expected)
    if not ok:
        return None, None, None

    # Get all solutions for the 24 crib positions
    solutions = backtrack_partial_perm(expected, max_solutions=1000)
    if not solutions:
        return None, None, None

    print(f"  [{keyword}/{cipher_name}/{alpha}] {len(solutions)} partial perms, running SA...")

    ai = {c: i for i, c in enumerate(alpha)}
    klen = len(keyword)
    key_idx = [ai[keyword[j % klen]] for j in range(97)]
    carved_idx = [ai[c] for c in K4]

    best_global = -1e9
    best_pt = None
    best_sigma = None

    for sol in solutions[:min(len(solutions), 10)]:  # Try first 10 partial perms
        # Build initial sigma: pin crib positions, fill rest with remaining K4 positions
        pinned_k4 = set(sol.values())
        free_k4 = [i for i in range(97) if i not in pinned_k4]
        free_pt  = [i for i in range(97) if i not in sol]

        rng.shuffle(free_k4)
        sigma = [0] * 97
        for pt_pos, k4_pos in sol.items():
            sigma[pt_pos] = k4_pos
        for i, pt_pos in enumerate(free_pt):
            sigma[pt_pos] = free_k4[i]

        # Build PT array
        pt_arr = [None] * 97
        for j in range(97):
            ci = carved_idx[sigma[j]]
            if cipher_name == "vig":
                pt_arr[j] = alpha[(ci - key_idx[j]) % 26]
            else:
                pt_arr[j] = alpha[(key_idx[j] - ci) % 26]

        sc = score_str(''.join(pt_arr))
        T = 25.0
        cooling = math.exp(math.log(0.005/25.0) / n_steps)

        best_sc = sc
        best_local_pt = ''.join(pt_arr)

        for step in range(n_steps):
            # Only swap FREE positions
            if len(free_pt) < 2: break
            a_idx = rng.randrange(len(free_pt))
            b_idx = rng.randrange(len(free_pt))
            while b_idx == a_idx:
                b_idx = rng.randrange(len(free_pt))

            a = free_pt[a_idx]
            b = free_pt[b_idx]

            # Swap sigma[a] and sigma[b]
            ci_new_a = carved_idx[sigma[b]]
            ci_new_b = carved_idx[sigma[a]]
            if cipher_name == "vig":
                npt_a = alpha[(ci_new_a - key_idx[a]) % 26]
                npt_b = alpha[(ci_new_b - key_idx[b]) % 26]
            else:
                npt_a = alpha[(key_idx[a] - ci_new_a) % 26]
                npt_b = alpha[(key_idx[b] - ci_new_b) % 26]

            old_a, old_b = pt_arr[a], pt_arr[b]
            pt_arr[a], pt_arr[b] = npt_a, npt_b
            new_sc = score_str(''.join(pt_arr))
            delta = new_sc - sc

            if delta > 0 or rng.random() < math.exp(max(delta, -500) / max(T, 0.001)):
                sigma[a], sigma[b] = sigma[b], sigma[a]
                sc = new_sc
                if sc > best_sc:
                    best_sc = sc
                    best_local_pt = ''.join(pt_arr)
            else:
                pt_arr[a], pt_arr[b] = old_a, old_b

            T *= cooling

            if step % 200000 == 0:
                print(f"    step={step}, T={T:.3f}, sc={sc/93:.4f}")

        ene = best_local_pt.find("EASTNORTHEAST")
        bc  = best_local_pt.find("BERLINCLOCK")
        spc = best_sc / 93
        print(f"  SA result: {spc:.4f}  ENE@{ene}  BC@{bc}")
        if ene >= 0 or bc >= 0:
            report_hit(f"csa_{keyword}_{cipher_name}", best_local_pt, sigma)

        if best_sc > best_global:
            best_global = best_sc
            best_pt = best_local_pt
            best_sigma = sigma[:]

    return best_global / 93, best_pt, best_sigma

# Run for KRYPTOS+Vig+AZ (most likely key based on K1/K2)
result = sa_crib_pinned("KRYPTOS", "vig", AZ, n_steps=500000, n_restarts=1, seed=42)
if result[0]:
    print(f"CSA KRYPTOS/vig/AZ: best_sc={result[0]:.4f}")
    if result[1]:
        print(f"  PT: {result[1]}")

# Also try PALIMPSEST
result2 = sa_crib_pinned("PALIMPSEST", "vig", AZ, n_steps=300000, n_restarts=1, seed=43)
if result2[0]:
    print(f"CSA PALIMPSEST/vig/AZ: best_sc={result2[0]:.4f}")

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("FINAL SUMMARY")
print("="*70)

if hits:
    print(f"\n{'!'*60}")
    print(f"CRIB HITS FOUND: {len(hits)}")
    for h in hits:
        print(f"  [{h['label']}]  ENE@{h['ene']}  BC@{h['bc']}  score={h['score']:.4f}")
        print(f"  PT: {h['pt']}")
else:
    print("\nNo crib hits found.")

all_results.sort(key=lambda r: r['score'], reverse=True)
print(f"\nTop 10 overall by quadgram score:")
for r in all_results[:10]:
    print(f"  [{r['label'][:60]:60s}] sc={r['score']:.4f}")
    if 'pt' in r:
        print(f"    PT: {r['pt'][:70]}")

with open(f"{RESULTS_DIR}/results_v5.json", 'w') as f:
    json.dump({
        "hits": hits,
        "top_results": all_results[:30],
    }, f, indent=2, default=str)
print(f"\nResults saved to {RESULTS_DIR}/results_v5.json")
print("Done.")
