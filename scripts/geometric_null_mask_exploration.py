#!/usr/bin/env python3
"""
Geometric Null-Mask Exploration for Kryptos K4
===============================================
Explores how geometric properties of the 28×31 grid and the 24° angle
from the installation triangle could define which 24 of 97 positions are nulls.

Hypotheses tested:
1. Diagonal reading at 24° through K4's grid positions
2. Grid-based modular selection (row+col ≡ 0 mod N)
3. tan(24°) ≈ 0.4452 as grid slope (≈ 4/9 or 9/20)
4. Rotational Cardan grille at 24°
5. Distance/angle from grid center or corners
6. Critical constraint: all 24 crib positions must survive (not be nulls)
7. For valid masks: test Vigenère/Beaufort with KRYPTOS and KOMPASS
"""

import sys, math, os
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_POSITIONS, CRIB_DICT, ALPH_IDX, ALPH, MOD,
    KRYPTOS_ALPHABET, SELF_ENCRYPTING
)

# ── Grid Parameters ─────────────────────────────────────────────────────
GRID_ROWS = 28
GRID_COLS = 31
GRID_SIZE = GRID_ROWS * GRID_COLS  # 868

# K4 starts at row 24, col 27 (0-indexed) and occupies 97 positions
# in reading order (left-to-right, top-to-bottom)
K4_START_ROW = 24
K4_START_COL = 27
K4_START_POS = K4_START_ROW * GRID_COLS + K4_START_COL  # = 771

# Map each K4 index (0-96) to (row, col) in the 28×31 grid
def k4_grid_positions():
    """Return list of (row, col) for each of the 97 K4 characters."""
    positions = []
    grid_pos = K4_START_POS
    for i in range(CT_LEN):
        row = grid_pos // GRID_COLS
        col = grid_pos % GRID_COLS
        positions.append((row, col))
        grid_pos += 1
    return positions

K4_GRID = k4_grid_positions()

W_POSITIONS = [20, 36, 48, 58, 74]  # 5 W's in K4

print("=" * 80)
print("GEOMETRIC NULL-MASK EXPLORATION FOR K4")
print("=" * 80)

# ── Show K4 in Grid ─────────────────────────────────────────────────────
print("\n## K4 Grid Layout (28×31)")
print(f"K4 starts at grid position {K4_START_POS} = row {K4_START_ROW}, col {K4_START_COL}")
print(f"K4 ends at grid position {K4_START_POS + 96} = row {(K4_START_POS+96)//GRID_COLS}, col {(K4_START_POS+96)%GRID_COLS}")

# Show which rows K4 spans
rows_used = sorted(set(r for r, c in K4_GRID))
print(f"K4 spans rows: {rows_used}")
for row in rows_used:
    chars_in_row = [(i, c, col) for i, ((r, col), c) in enumerate(zip(K4_GRID, CT)) if r == row]
    cols = [col for _, _, col in chars_in_row]
    print(f"  Row {row}: cols {min(cols)}-{max(cols)} ({len(chars_in_row)} chars) "
          f"= K4[{chars_in_row[0][0]}..{chars_in_row[-1][0]}]")
    row_text = ''.join(c for _, c, _ in chars_in_row)
    print(f"          {row_text}")

# ── Helper Functions ─────────────────────────────────────────────────────
def check_mask(null_positions, label):
    """Check if a null mask preserves all crib positions. Returns (valid, details)."""
    null_set = set(null_positions)
    if len(null_set) != 24:
        return False, f"Wrong count: {len(null_set)} nulls (need 24)"
    if any(p < 0 or p >= CT_LEN for p in null_set):
        return False, "Positions out of range"
    crib_conflict = null_set & CRIB_POSITIONS
    if crib_conflict:
        return False, f"Crib conflict at positions: {sorted(crib_conflict)}"
    return True, "Valid"


def extract_73(null_positions):
    """Given 24 null positions, extract the 73 non-null chars."""
    null_set = set(null_positions)
    return ''.join(CT[i] for i in range(CT_LEN) if i not in null_set)


def vigenere_decrypt(ct_text, key, alphabet=ALPH):
    """Decrypt using Vigenère: PT[i] = (CT[i] - KEY[i]) mod 26"""
    idx = {c: i for i, c in enumerate(alphabet)}
    key_len = len(key)
    result = []
    for i, c in enumerate(ct_text):
        ci = idx[c]
        ki = idx[key[i % key_len]]
        pi = (ci - ki) % 26
        result.append(alphabet[pi])
    return ''.join(result)


def beaufort_decrypt(ct_text, key, alphabet=ALPH):
    """Decrypt using Beaufort: PT[i] = (KEY[i] - CT[i]) mod 26"""
    idx = {c: i for i, c in enumerate(alphabet)}
    key_len = len(key)
    result = []
    for i, c in enumerate(ct_text):
        ci = idx[c]
        ki = idx[key[i % key_len]]
        pi = (ki - ci) % 26
        result.append(alphabet[pi])
    return ''.join(result)


def variant_beaufort_decrypt(ct_text, key, alphabet=ALPH):
    """Decrypt Variant Beaufort: PT[i] = (CT[i] + KEY[i]) mod 26"""
    idx = {c: i for i, c in enumerate(alphabet)}
    key_len = len(key)
    result = []
    for i, c in enumerate(ct_text):
        ci = idx[c]
        ki = idx[key[i % key_len]]
        pi = (ci + ki) % 26
        result.append(alphabet[pi])
    return ''.join(result)


def test_decryptions(text_73, label):
    """Test a 73-char extract with various keywords and ciphers."""
    keywords = ["KRYPTOS", "KOMPASS", "PALIMPSEST", "ABSCISSA", "DEFECTOR"]
    ciphers = [
        ("Vigenere", vigenere_decrypt),
        ("Beaufort", beaufort_decrypt),
        ("VarBeau", variant_beaufort_decrypt),
    ]
    alphabets = [
        ("AZ", ALPH),
        ("KA", KRYPTOS_ALPHABET),
    ]

    results = []
    for kw in keywords:
        for cipher_name, cipher_fn in ciphers:
            for alph_name, alph in alphabets:
                pt = cipher_fn(text_73, kw, alph)
                # Check for crib fragments in the plaintext
                score = 0
                for crib_word in ["EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST", "BERLIN", "CLOCK", "EAST"]:
                    if crib_word in pt:
                        score += len(crib_word)
                # Check IC
                freqs = [0] * 26
                for c in pt:
                    freqs[ALPH_IDX[c]] += 1
                n = len(pt)
                ic = sum(f * (f - 1) for f in freqs) / (n * (n - 1)) if n > 1 else 0

                results.append((score, ic, kw, cipher_name, alph_name, pt))

    results.sort(key=lambda x: (-x[0], -x[1]))
    return results


def report_mask(null_positions, label, show_decryptions=True):
    """Report on a null mask."""
    valid, detail = check_mask(null_positions, label)
    null_list = sorted(null_positions)
    print(f"\n### {label}")
    print(f"  Null positions ({len(null_list)}): {null_list}")
    print(f"  Valid: {valid} — {detail}")

    if not valid:
        return None

    text_73 = extract_73(null_positions)
    print(f"  73-char extract: {text_73}")

    # Show which W's are nulls
    w_nulls = [p for p in W_POSITIONS if p in null_positions]
    print(f"  W positions as nulls: {w_nulls} of {W_POSITIONS}")

    # Map crib positions to new positions in 73-char string
    null_set = set(null_positions)
    pos_map = {}
    new_idx = 0
    for i in range(CT_LEN):
        if i not in null_set:
            pos_map[i] = new_idx
            new_idx += 1

    print(f"  Crib positions in 73-char string:")
    for start, word in [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]:
        new_start = pos_map[start]
        new_end = pos_map[start + len(word) - 1]
        # Check if contiguous
        new_positions = [pos_map[start + i] for i in range(len(word))]
        contiguous = all(new_positions[i+1] == new_positions[i] + 1 for i in range(len(new_positions)-1))
        print(f"    {word}: orig {start}-{start+len(word)-1} → new {new_start}-{new_end} "
              f"({'contiguous' if contiguous else 'BROKEN: ' + str(new_positions)})")

    if show_decryptions:
        results = test_decryptions(text_73, label)
        top5 = results[:5]
        print(f"  Top 5 decryptions (by crib-fragment score, then IC):")
        for score, ic, kw, cipher, alph, pt in top5:
            print(f"    [{score}] IC={ic:.4f} {cipher}/{alph}/{kw}: {pt[:50]}...")

    return text_73


# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 1: K4 row/column structure — which positions fall where?
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 1: K4 Row Structure in the Grid")
print("=" * 80)

# K4 occupies parts of 4 rows
# Row 24: cols 27-30 → K4[0..3] = 4 chars
# Row 25: cols 0-30  → K4[4..34] = 31 chars
# Row 26: cols 0-30  → K4[35..65] = 31 chars
# Row 27: cols 0-30  → K4[66..96] = 31 chars
# Total: 4 + 31 + 31 + 31 = 97 ✓

for i, (r, c) in enumerate(K4_GRID):
    if i < 5 or (30 <= i <= 36) or (62 <= i <= 68) or i > 93:
        print(f"  K4[{i:2d}] = '{CT[i]}' at row {r}, col {c:2d}")
    elif i == 5 or i == 36 or i == 68:
        print(f"  ...")

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 2: Modular selection — row+col ≡ 0 mod N
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 2: Modular Grid Selection (row+col mod N)")
print("=" * 80)

for n in range(2, 15):
    # Select positions where (row + col) % n == 0
    for target in range(n):
        selected = [i for i, (r, c) in enumerate(K4_GRID) if (r + c) % n == target]
        nulls = [i for i in range(CT_LEN) if i not in selected]
        if len(nulls) == 24:
            valid, detail = check_mask(nulls, f"(r+c)%{n}=={target}")
            print(f"  (r+c) % {n} == {target}: {len(selected)} selected, {len(nulls)} nulls → {detail}")
            if valid:
                report_mask(nulls, f"(r+c)%{n}=={target} → 24 nulls")

    # Also try row % n, col % n
    for target in range(n):
        selected_r = [i for i, (r, c) in enumerate(K4_GRID) if r % n != target]
        selected_c = [i for i, (r, c) in enumerate(K4_GRID) if c % n != target]
        for label, nulls_list in [
            (f"row%{n}=={target}", [i for i in range(CT_LEN) if i not in selected_r]),
            (f"col%{n}=={target}", [i for i in range(CT_LEN) if i not in selected_c]),
        ]:
            if len(nulls_list) == 24:
                valid, detail = check_mask(nulls_list, label)
                if valid:
                    print(f"  {label}: 24 nulls → VALID")
                    report_mask(nulls_list, label)
                elif "Crib conflict" not in detail:
                    print(f"  {label}: 24 nulls → {detail}")


# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 3: 24° slope = tan(24°) ≈ 0.4452 ≈ 4/9
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 3: Reading at 24° Angle (slope ≈ tan(24°) ≈ 0.4452)")
print("=" * 80)

angle_24 = 24 * math.pi / 180
slope_24 = math.tan(angle_24)
print(f"  tan(24°) = {slope_24:.6f}")
print(f"  Rational approximations: 4/9 = {4/9:.6f}, 9/20 = {9/20:.6f}")

# For each starting position, trace a line at 24° through the K4 grid region
# and see which K4 positions the line passes through (within 0.5 cell)
print(f"\n  --- Diagonal line at 24° from horizontal across K4 grid region ---")

# K4 occupies rows 24-27, cols 0-30 (plus partial row 24)
# A line at 24° from horizontal: for every 1 unit right, go tan(24°) ≈ 0.4452 units up
# In grid terms: for every step in col, row changes by -0.4452 (going up) or +0.4452 (going down)

for start_col_offset in range(GRID_COLS):
    for direction in [1, -1]:  # +1 = going down-right, -1 = going up-right
        # Start from row 24 (or other rows)
        for start_row in rows_used:
            hit_indices = set()
            # Trace from the start point
            for step in range(-50, 50):
                col = start_col_offset + step
                row_exact = start_row + direction * slope_24 * step
                row = round(row_exact)
                if 0 <= col < GRID_COLS and row in rows_used:
                    # Find the K4 index at this (row, col)
                    for ki, (kr, kc) in enumerate(K4_GRID):
                        if kr == row and kc == col:
                            hit_indices.add(ki)

            if len(hit_indices) == 73:
                nulls = [i for i in range(CT_LEN) if i not in hit_indices]
                valid, detail = check_mask(nulls, f"24° line from ({start_row},{start_col_offset})")
                if valid:
                    print(f"  VALID: 24° line from row {start_row}, col {start_col_offset}, dir={direction}")
                    report_mask(nulls, f"24°-line-r{start_row}-c{start_col_offset}-d{direction}")
            elif len(hit_indices) == 24:
                nulls = list(hit_indices)
                valid, detail = check_mask(nulls, f"24° line selects 24 (nulls)")
                if valid:
                    print(f"  VALID (inverted): 24° line selects 24 positions as nulls")
                    report_mask(nulls, f"24°-nulls-r{start_row}-c{start_col_offset}-d{direction}")

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 3b: Every-Nth-position with N related to 24° geometry
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 3b: Every-Nth Selection Patterns")
print("=" * 80)

# If we select every N-th position as a null, which N gives exactly 24?
# 97/24 ≈ 4.04 → every 4th position gives ~24 nulls
# More precisely: skip patterns
for step in range(2, 50):
    for offset in range(step):
        nulls = [i for i in range(offset, CT_LEN, step)]
        if len(nulls) == 24:
            valid, detail = check_mask(nulls, f"every-{step}-from-{offset}")
            if valid:
                print(f"  VALID: Every {step}th position starting at {offset} → 24 nulls")
                report_mask(nulls, f"every-{step}-from-{offset}")
            elif "Crib" in detail:
                # Count how many crib positions are hit
                crib_hits = len(set(nulls) & CRIB_POSITIONS)
                if crib_hits <= 2:
                    print(f"  NEAR MISS: every-{step}-from-{offset}, {crib_hits} crib conflicts")

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 4: Grid column-based null selection
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 4: Column-Based Selection (Specific Columns are Nulls)")
print("=" * 80)

# K4 has 4 chars in row 24 (cols 27-30) and 31 chars each in rows 25-27
# Total columns used: cols 0-30 in rows 25-27, cols 27-30 in row 24
# If certain columns are "null columns" in the full rows...

# For rows 25-27 (31 chars each = 93 chars), selecting N columns as nulls removes 3*N chars
# Plus row 24 has 4 chars in cols 27-30; some of those may also be nulls
# 3*N + adjustment from row 24 = 24
# 3*8 = 24 → 8 columns as nulls (if no row-24 adjustments)

print("  K4 row structure:")
print("  Row 24: 4 chars (cols 27-30)")
print("  Rows 25-27: 31 chars each (cols 0-30)")
print("  If 8 columns are null-columns in full rows (25-27): 3×8 = 24 nulls")

# Which sets of 8 columns, when marked as nulls for rows 25-27 only, give valid masks?
# With row 24's 4 chars (cols 27-30) always kept
# Constraint: crib positions must survive

# First, map crib positions to columns
print("\n  Crib positions → grid columns:")
crib_cols = set()
for pos in CRIB_POSITIONS:
    r, c = K4_GRID[pos]
    print(f"    K4[{pos}] = '{CT[pos]}' at col {c} (row {r})")
    crib_cols.add(c)
print(f"  Crib columns: {sorted(crib_cols)}")
print(f"  Number of distinct crib columns: {len(crib_cols)}")
print(f"  Available null columns (31 - {len(crib_cols)} = {31 - len(crib_cols)}): ", end="")
available_cols = sorted(set(range(31)) - crib_cols)
print(available_cols)

# Try all combinations of 8 columns from available (non-crib) columns
# But only for rows 25-27 (not row 24)
valid_8col_masks = []
if len(available_cols) >= 8:
    count = 0
    for combo in combinations(available_cols, 8):
        null_cols = set(combo)
        nulls = []
        for i, (r, c) in enumerate(K4_GRID):
            if r >= 25 and c in null_cols:
                nulls.append(i)
        if len(nulls) == 24:
            valid, detail = check_mask(nulls, f"8-col {combo}")
            if valid:
                valid_8col_masks.append((combo, nulls))
                count += 1
    print(f"\n  Valid 8-column masks (rows 25-27 only): {count}")
    if count > 0 and count <= 20:
        for combo, nulls in valid_8col_masks[:5]:
            report_mask(nulls, f"Null cols {combo}", show_decryptions=True)
    elif count > 20:
        print(f"  (Too many to show all — showing first 3)")
        for combo, nulls in valid_8col_masks[:3]:
            report_mask(nulls, f"Null cols {combo}", show_decryptions=True)

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 5: Distance / angle from grid center
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 5: Distance/Angle from Grid Center or K4 Center")
print("=" * 80)

# Center of K4 region
k4_rows = [r for r, c in K4_GRID]
k4_cols = [c for r, c in K4_GRID]
center_r = sum(k4_rows) / len(k4_rows)
center_c = sum(k4_cols) / len(k4_cols)
print(f"  K4 center: ({center_r:.2f}, {center_c:.2f})")

# Compute angle from center for each K4 position
angles = []
for i, (r, c) in enumerate(K4_GRID):
    ang = math.atan2(r - center_r, c - center_c) * 180 / math.pi
    dist = math.sqrt((r - center_r)**2 + (c - center_c)**2)
    angles.append((i, r, c, ang, dist))

# Sort by angle and try selecting every 4th (97/4 ≈ 24)
angles_sorted = sorted(angles, key=lambda x: x[3])
print(f"\n  Positions sorted by angle from center:")
for offset in range(4):
    nulls = [angles_sorted[i][0] for i in range(offset, len(angles_sorted), 4)]
    if len(nulls) >= 24:
        nulls = nulls[:24]
    valid, detail = check_mask(nulls, f"angle-sort-every4-offset{offset}")
    print(f"    Offset {offset}: nulls at K4 positions {sorted(nulls)[:10]}... → {detail}")

# Sort by distance from center
angles_dist = sorted(angles, key=lambda x: x[4])
# Farthest 24 as nulls
nulls_far = [a[0] for a in angles_dist[-24:]]
valid, detail = check_mask(nulls_far, "farthest-24")
print(f"\n  Farthest 24 from center: {detail}")
if valid:
    report_mask(nulls_far, "farthest-24-from-center")

# Closest 24 as nulls
nulls_near = [a[0] for a in angles_dist[:24]]
valid, detail = check_mask(nulls_near, "nearest-24")
print(f"  Nearest 24 to center: {detail}")
if valid:
    report_mask(nulls_near, "nearest-24-to-center")

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 6: Column mod patterns related to 24° / tan(24°)
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 6: Diagonal Stripes at 24° (col - row*tan(24°) mod period)")
print("=" * 80)

# A diagonal stripe at angle θ from horizontal groups positions by:
#   (col - row * tan(θ)) mod period
# For 24°: col - row * 0.4452

for period in range(2, 16):
    for target in range(period):
        nulls = []
        for i, (r, c) in enumerate(K4_GRID):
            stripe = (c - r * slope_24) % period
            # Quantize to nearest integer stripe
            stripe_int = round(stripe) % period
            if stripe_int == target:
                nulls.append(i)
        if len(nulls) == 24:
            valid, detail = check_mask(nulls, f"stripe-24deg-p{period}-t{target}")
            if valid:
                print(f"  VALID: 24° stripe, period {period}, target {target}")
                report_mask(nulls, f"24deg-stripe-p{period}-t{target}")
            else:
                print(f"  24° stripe p={period} t={target}: 24 nulls but {detail}")

# Also try exact rational slope 4/9
for period in range(2, 16):
    for target in range(period):
        nulls = []
        for i, (r, c) in enumerate(K4_GRID):
            # stripe = 9*c - 4*r (integer arithmetic, no rounding)
            stripe_val = (9 * c - 4 * r) % period
            if stripe_val == target:
                nulls.append(i)
        if len(nulls) == 24:
            valid, detail = check_mask(nulls, f"stripe-4/9-p{period}-t{target}")
            if valid:
                print(f"  VALID: 4/9 slope stripe, period {period}, target {target}")
                report_mask(nulls, f"4-9-stripe-p{period}-t{target}")

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 7: Specific geometric patterns — checkerboard, spiral, etc.
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 7: Specific Geometric Patterns")
print("=" * 80)

# 7a: Row 24 (4 chars) as nulls + 20 from specific columns
print("\n--- 7a: Row 24 all nulls + column-based nulls in rows 25-27 ---")
row24_indices = [i for i, (r, c) in enumerate(K4_GRID) if r == 24]
print(f"  Row 24 indices: {row24_indices} (chars: {''.join(CT[i] for i in row24_indices)})")
# Need 20 more nulls from rows 25-27

# Are any of row 24's positions crib positions?
row24_crib = set(row24_indices) & CRIB_POSITIONS
print(f"  Row 24 crib positions: {row24_crib}")

if not row24_crib:
    # Try selecting 20 more nulls from specific column patterns
    # 20 nulls from 3 full rows = need columns that contribute ~6.67 each
    # Options: 7 cols give 21 (too many), 6 cols give 18 (too few with row24's 4 = 22)
    # Actually: 4 (row 24) + 3*N (from N columns in rows 25-27) = 24 → N = 6.67 (not integer)
    # Try: 4 row24 + 7 cols × 3 rows = 4+21 = 25 (one too many)
    # Try: 4 row24 + 7 cols in 2 rows + 6 cols in 1 row... complex
    # Simpler: 4 row24 + mixed approach

    # What if NOT all of row 24 is null?
    pass

# 7b: W positions as nulls (5 of 24) — need 19 more
print("\n--- 7b: W positions as nulls + geometric selection of 19 more ---")
w_null_count = len(W_POSITIONS)
print(f"  W positions: {W_POSITIONS} ({w_null_count} positions)")
w_crib = set(W_POSITIONS) & CRIB_POSITIONS
print(f"  W positions in cribs: {w_crib}")

if not w_crib:
    # Need 19 more nulls from non-crib, non-W positions
    available = sorted(set(range(CT_LEN)) - CRIB_POSITIONS - set(W_POSITIONS))
    print(f"  Available positions for remaining 19 nulls: {len(available)} positions")

    # Try: W's + every 4th from available
    for offset in range(4):
        extra = [available[i] for i in range(offset, len(available), len(available)//19 or 1)][:19]
        if len(extra) == 19:
            nulls = sorted(W_POSITIONS + extra)
            valid, detail = check_mask(nulls, f"W+every-nth-{offset}")
            if valid:
                print(f"  VALID: W + pattern offset {offset}")
                report_mask(nulls, f"W-plus-pattern-{offset}")

# 7c: Modular position patterns
print("\n--- 7c: Simple position mod patterns ---")
for m in [4, 5, 7, 8, 9, 12, 13, 24, 31]:
    for target in range(m):
        nulls = [i for i in range(CT_LEN) if i % m == target]
        if abs(len(nulls) - 24) <= 1:
            if len(nulls) == 24:
                valid, detail = check_mask(nulls, f"pos%{m}=={target}")
                if valid:
                    print(f"  VALID: position % {m} == {target}")
                    report_mask(nulls, f"pos-mod-{m}-eq-{target}")
                else:
                    print(f"  pos%{m}=={target}: 24 nulls but {detail}")

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 8: Grid column at 24° offset per row
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 8: Column Offset at 24° Per Row")
print("=" * 80)

# In K4's grid, for each row, mark positions that fall on a diagonal
# at 24° from some anchor. The diagonal shifts ~0.445 columns per row.

# Since K4 spans 4 rows, the total horizontal shift over 4 rows = 4 * 0.445 ≈ 1.78 cols
# This means a 24° line through K4 covers very few distinct "diagonal" positions
# Let's think differently: multiple parallel diagonals at 24°

# Generate all possible diagonal lines at slope 4/9 through the grid
# and see which ones cover exactly K4 positions

print("  Multiple parallel diagonals at 24° through K4 region:")
print("  Slope = 4/9 → for every 9 columns right, go 4 rows down")

# For K4's rows (24-27), with 31 cols:
# A diagonal defined by: row = floor(start_row + (col - start_col) * 4/9)
# Or equivalently: 9*row - 4*col = constant (integer diagonal index)

diag_indices = {}  # diag_id → list of K4 positions
for i, (r, c) in enumerate(K4_GRID):
    d = 9 * r - 4 * c
    diag_indices.setdefault(d, []).append(i)

print(f"  Distinct diagonal indices (9r - 4c): {len(diag_indices)}")
for d in sorted(diag_indices):
    positions = diag_indices[d]
    chars = ''.join(CT[p] for p in positions)
    print(f"    d={d:4d}: {len(positions):2d} positions → K4{positions} = {chars}")

# Can we select 24 nulls by choosing specific diagonals?
# This is a subset-sum problem: find diagonals whose sizes sum to 24
diag_sizes = [(d, len(pos)) for d, pos in sorted(diag_indices.items())]
print(f"\n  Diagonal sizes: {[(d, s) for d, s in diag_sizes]}")

# Small enough for brute force: try all subsets of diagonals that sum to 24
from itertools import combinations as combs

print(f"\n  Searching for diagonal combinations summing to 24 nulls...")
valid_diag_combos = []
diag_keys = sorted(diag_indices.keys())
for r in range(1, len(diag_keys) + 1):
    for combo in combs(range(len(diag_keys)), r):
        total = sum(len(diag_indices[diag_keys[c]]) for c in combo)
        if total == 24:
            nulls = []
            for c in combo:
                nulls.extend(diag_indices[diag_keys[c]])
            valid, detail = check_mask(nulls, "diag-combo")
            if valid:
                ds = [diag_keys[c] for c in combo]
                valid_diag_combos.append((ds, nulls))

print(f"  Found {len(valid_diag_combos)} valid diagonal combinations")
for ds, nulls in valid_diag_combos[:5]:
    report_mask(nulls, f"24°-diag {ds}", show_decryptions=True)

if len(valid_diag_combos) > 5:
    print(f"  ... and {len(valid_diag_combos) - 5} more")

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 9: Grid coordinates related to 24 (the Weltzeituhr number)
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 9: Positions Related to 24 (Weltzeituhr Facets)")
print("=" * 80)

# 24 = number of Weltzeituhr facets, hours in a day
# Positions whose grid coordinates relate to 24 in some way

# 9a: col mod 24
for target in range(24):
    nulls = [i for i, (r, c) in enumerate(K4_GRID) if c % 24 == target]
    if len(nulls) == 24:
        valid, detail = check_mask(nulls, f"col%24=={target}")
        if valid:
            print(f"  VALID: col % 24 == {target}")
            report_mask(nulls, f"col24-{target}")

# 9b: (row * col) % 24
for target in range(24):
    nulls = [i for i, (r, c) in enumerate(K4_GRID) if (r * c) % 24 == target]
    if len(nulls) == 24:
        valid, detail = check_mask(nulls, f"(r*c)%24=={target}")
        if valid:
            print(f"  VALID: (row*col) % 24 == {target}")
            report_mask(nulls, f"rc24-{target}")

# 9c: Distance from specific corners
corners = [
    (0, 0, "top-left"),
    (0, 30, "top-right"),
    (27, 0, "bottom-left"),
    (27, 30, "bottom-right"),
    (K4_START_ROW, K4_START_COL, "K4-start"),
]
for cr, cc, name in corners:
    dists = [(i, math.sqrt((r-cr)**2 + (c-cc)**2)) for i, (r, c) in enumerate(K4_GRID)]
    dists.sort(key=lambda x: x[1])
    # Farthest 24
    nulls = [d[0] for d in dists[-24:]]
    valid, detail = check_mask(nulls, f"far-from-{name}")
    if valid:
        print(f"  VALID: 24 farthest from {name}")
        report_mask(nulls, f"far-from-{name}")
    # Nearest 24
    nulls = [d[0] for d in dists[:24]]
    valid, detail = check_mask(nulls, f"near-{name}")
    if valid:
        print(f"  VALID: 24 nearest to {name}")
        report_mask(nulls, f"near-{name}")

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 10: W + Row-24 + Column Selection
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 10: Composite Masks (W-positions + Row-24 + Column Patterns)")
print("=" * 80)

# 10a: W positions (5) + Row 24 positions (4) = 9 nulls
# Need 15 more from non-crib positions
# Try selecting columns that are NOT crib columns

composite_base = set(W_POSITIONS) | set(row24_indices)
composite_crib_conflict = composite_base & CRIB_POSITIONS
print(f"  W + Row24 base: {sorted(composite_base)} ({len(composite_base)} positions)")
print(f"  Crib conflict: {composite_crib_conflict}")

if not composite_crib_conflict:
    needed = 24 - len(composite_base)
    print(f"  Need {needed} more nulls")

    # Try 5 columns (giving 3*5=15 more nulls from rows 25-27) minus any already in base
    for combo in combs(available_cols, 5):
        extra = []
        for i, (r, c) in enumerate(K4_GRID):
            if r >= 25 and c in combo and i not in composite_base:
                extra.append(i)
        if len(extra) == needed:
            nulls = sorted(composite_base | set(extra))
            valid, detail = check_mask(nulls, f"W+R24+cols{combo}")
            if valid:
                report_mask(nulls, f"W+R24+cols{combo}", show_decryptions=True)
                break  # Show first valid one

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 11: Angle 24° from K4-start to each position
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 11: Angle from K4 Start Position")
print("=" * 80)

k4_start_r, k4_start_c = K4_GRID[0]
angles_from_start = []
for i, (r, c) in enumerate(K4_GRID):
    if i == 0:
        angles_from_start.append((i, 0.0))
        continue
    ang = math.atan2(r - k4_start_r, c - k4_start_c) * 180 / math.pi
    angles_from_start.append((i, ang))

# Find positions closest to 24° angle from start
angles_from_start.sort(key=lambda x: abs(x[1] - 24))
print(f"  K4 positions closest to 24° from K4 start:")
for idx, ang in angles_from_start[:10]:
    r, c = K4_GRID[idx]
    print(f"    K4[{idx}] = '{CT[idx]}' at ({r},{c}), angle={ang:.1f}°")

# Find positions within ±12° of multiples of 24°
for mult in range(1, 16):
    target_angle = 24 * mult
    if target_angle > 360:
        break
    near = [i for i, ang in angles_from_start if abs(ang - target_angle) < 12 or abs(ang - target_angle + 360) < 12]
    if len(near) == 24:
        valid, detail = check_mask(near, f"angle-near-{target_angle}deg")
        if valid:
            print(f"  VALID: 24 positions near {target_angle}° from K4 start")

# ══════════════════════════════════════════════════════════════════════════
# HYPOTHESIS 12: Reading along diagonals at various angles
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HYPOTHESIS 12: Multiple Parallel Lines at 24°")
print("=" * 80)

# Use the formula: line_id = round(9*row - 4*col) for slope 4/9
# We already computed this in H8. Now try: positions where line_id mod k == target
for k in range(2, 12):
    for target in range(k):
        nulls = [i for i, (r, c) in enumerate(K4_GRID)
                 if (9*r - 4*c) % k == target]
        if len(nulls) == 24:
            valid, detail = check_mask(nulls, f"diag49-mod{k}-{target}")
            if valid:
                print(f"  VALID: (9r-4c) mod {k} == {target}")
                report_mask(nulls, f"diag49-mod{k}-{target}", show_decryptions=True)
            else:
                crib_hits = len(set(nulls) & CRIB_POSITIONS)
                if crib_hits <= 3:
                    print(f"  NEAR: (9r-4c)%{k}=={target}: 24 nulls, {crib_hits} crib conflicts")

# Also try other rational slopes
for num, den in [(1,2), (2,5), (3,7), (1,3), (2,3), (5,11), (7,15), (3,8)]:
    for k in range(2, 12):
        for target in range(k):
            nulls = [i for i, (r, c) in enumerate(K4_GRID)
                     if (den*r - num*c) % k == target]
            if len(nulls) == 24:
                valid, detail = check_mask(nulls, f"diag{num}/{den}-mod{k}-{target}")
                if valid:
                    print(f"  VALID: slope {num}/{den}, ({den}r-{num}c) mod {k} == {target}")
                    report_mask(nulls, f"diag-{num}-{den}-mod{k}-{target}", show_decryptions=True)

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SUMMARY OF ALL VALID MASKS FOUND")
print("=" * 80)
print("(See detailed results above for each hypothesis)")
print("\nDone.")
