#!/usr/bin/env python3
"""Focused Geometric Analysis — Deep Dives on Promising Findings.

Family:    geometry
Cipher:    geometric operations on grid/circle/polar
Status:    active
Keyspace:  ~20K (targeted geometric tests)
Last run:  never
Best score: n/a

Follow-up to e_comprehensive_geometry_01.py. Deep dives into:
1. The 24° angle at LOOMIS — exactly matches 24 null positions
2. The 89° right-angle coincidence (24 cribs span exactly 89° of 97-circle)
3. Grid-column modular patterns in consensus nulls
4. 31-wide grid diagonal selection at installation bearings
5. The LODESTONE→LOOMIS bearing (74.5°) ≈ position 74 (end of BC crib)
6. Bearing-derived selection with DEFECTOR keyword
7. Circular position mapping with lodestone deflection
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

import math
import sys
import os
from itertools import combinations, permutations
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, ALPH, ALPH_IDX, MOD,
    N_CRIBS, KRYPTOS_ALPHABET, BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast

# ── Installation geometry (same as script 01) ──
def dms_to_dd(d, m, s):
    return d + m/60.0 + s/3600.0

POINTS = {
    'KRYPTOS':   (dms_to_dd(38,57,8.16),  -dms_to_dd(77,8,44.68)),
    'LODESTONE': (dms_to_dd(38,57,6.06),  -dms_to_dd(77,8,48.11)),
    'LOOMIS':    (dms_to_dd(38,57,5.82),  -dms_to_dd(77,8,49.22)),
    'K2_TARGET': (dms_to_dd(38,57,6.50),  -dms_to_dd(77,8,44.00)),
}

def to_local_meters(lat1, lon1, lat2, lon2):
    avg_lat = math.radians((lat1 + lat2) / 2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    dy = dlat * 6371000
    dx = dlon * 6371000 * math.cos(avg_lat)
    return dx, dy

def bearing_deg(p1, p2):
    dx, dy = to_local_meters(p1[0], p1[1], p2[0], p2[1])
    return math.degrees(math.atan2(dx, dy)) % 360

def distance_m(p1, p2):
    dx, dy = to_local_meters(p1[0], p1[1], p2[0], p2[1])
    return math.sqrt(dx*dx + dy*dy)

def angle_at_vertex(a, vertex, b):
    b1 = bearing_deg(vertex, a)
    b2 = bearing_deg(vertex, b)
    diff = abs(b1 - b2)
    if diff > 180:
        diff = 360 - diff
    return diff

GRID_COLS = 31
K4_START_ROW = 24
K4_START_COL = 27

def k4_grid_pos(i):
    abs_pos = (K4_START_ROW * GRID_COLS + K4_START_COL) + i
    return abs_pos // GRID_COLS, abs_pos % GRID_COLS

K4_GRID = [k4_grid_pos(i) for i in range(CT_LEN)]
W_POSITIONS = [20, 36, 48, 58, 74]
CONSENSUS_NULLS = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}

def check_mask(null_positions):
    null_set = set(null_positions)
    if len(null_set) != 24:
        return False, f"Count={len(null_set)}"
    if any(p < 0 or p >= CT_LEN for p in null_set):
        return False, "Out of range"
    crib_conflict = null_set & CRIB_POSITIONS
    if crib_conflict:
        return False, f"Crib conflict: {sorted(crib_conflict)}"
    return True, "Valid"

def extract_73(null_positions):
    null_set = set(null_positions)
    return ''.join(CT[i] for i in range(CT_LEN) if i not in null_set)

def vigenere_dec(ct, key):
    pt = []
    kl = len(key)
    for i, c in enumerate(ct):
        pt.append(ALPH[(ALPH_IDX[c] - ALPH_IDX[key[i % kl]]) % 26])
    return ''.join(pt)

def beaufort_dec(ct, key):
    pt = []
    kl = len(key)
    for i, c in enumerate(ct):
        pt.append(ALPH[(ALPH_IDX[key[i % kl]] - ALPH_IDX[c]) % 26])
    return ''.join(pt)

def score_with_mapped_cribs(pt, null_positions):
    """Score plaintext against cribs mapped from 97-space to 73-space."""
    null_set = set(null_positions)
    pos_map = {}
    new_idx = 0
    for i in range(CT_LEN):
        if i not in null_set:
            pos_map[i] = new_idx
            new_idx += 1
    hits = 0
    ene_hits = 0
    bc_hits = 0
    for orig_pos, ch in CRIB_DICT.items():
        if orig_pos in pos_map:
            new_pos = pos_map[orig_pos]
            if new_pos < len(pt) and pt[new_pos] == ch:
                hits += 1
                if 21 <= orig_pos <= 33:
                    ene_hits += 1
                else:
                    bc_hits += 1
    return hits, ene_hits, bc_hits


def test_mask_with_keywords(null_positions, label, keywords=None):
    """Test a null mask with keyword substitution, return best results."""
    if keywords is None:
        keywords = ["KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
                    "PALIMPSEST", "BERLIN", "COMPASS", "LOOMIS"]
    text_73 = extract_73(null_positions)
    results = []

    for kw in keywords:
        for name, fn in [("vig", vigenere_dec), ("beau", beaufort_dec)]:
            pt = fn(text_73, kw)
            hits, ene, bc = score_with_mapped_cribs(pt, null_positions)
            if hits >= 5:
                results.append((hits, ene, bc, f"{name}({kw})", pt[:50]))
            # Also check free crib
            sc = score_free_fast(pt)
            if sc > 0:
                results.append((sc, 0, 0, f"free-{name}({kw})", pt[:50]))

    # Single-letter keys
    for k in range(26):
        kw = ALPH[k]
        for name, fn in [("vig", vigenere_dec), ("beau", beaufort_dec)]:
            pt = fn(text_73, kw)
            hits, ene, bc = score_with_mapped_cribs(pt, null_positions)
            if hits >= 5:
                results.append((hits, ene, bc, f"{name}({kw})", pt[:50]))

    results.sort(key=lambda x: -x[0])
    return results


# ══════════════════════════════════════════════════════════════════════════════
# DEEP DIVE 1: THE 24° ANGLE AT LOOMIS
# ══════════════════════════════════════════════════════════════════════════════

def deep_dive_1():
    print("\n" + "=" * 80)
    print("DEEP DIVE 1: THE 24° ANGLE AT LOOMIS")
    print("=" * 80)

    # At LOOMIS, the angle between KRYPTOS and K2_TARGET is 24.03°
    angle_at_loomis = angle_at_vertex(POINTS['KRYPTOS'], POINTS['LOOMIS'], POINTS['K2_TARGET'])
    print(f"  Angle at LOOMIS (KRYPTOS-K2): {angle_at_loomis:.4f}°")
    print(f"  This encodes: 24 = number of null positions = number of crib positions")

    # What if this angle defines which positions are nulls?
    # Idea: on the 97-position circle, positions within a 24° arc are nulls
    # 24° of 360° = 24/360 of the circle = 6.67% = 6.5 positions
    # That's NOT 24 positions. 24 positions = 24/97 * 360 = 89.07°.

    # But what if it's 24° of a different reference?
    # 24° × 97/360 = 6.47 positions (not useful)
    # 24 × (360/97) = 89.07° → the 24 crib positions span 89° of the circle

    # Alternative: the 24° divides the bearing range into sectors
    # LOOMIS→KRYPTOS = 56.46°, LOOMIS→K2 = 80.49°, difference = 24.03°
    # On the 31-wide grid: 24/360 * 31 = 2.07 columns

    # Map the 24° angular sector to grid columns
    b_kryptos = bearing_deg(POINTS['LOOMIS'], POINTS['KRYPTOS'])
    b_k2 = bearing_deg(POINTS['LOOMIS'], POINTS['K2_TARGET'])
    b_lodestone = bearing_deg(POINTS['LOOMIS'], POINTS['LODESTONE'])
    print(f"\n  Bearings from LOOMIS:")
    print(f"    → KRYPTOS:   {b_kryptos:.2f}°")
    print(f"    → LODESTONE: {b_lodestone:.2f}°")
    print(f"    → K2_TARGET: {b_k2:.2f}°")
    print(f"    KRYPTOS-K2 gap: {b_k2 - b_kryptos:.2f}° = {angle_at_loomis:.2f}° (= 24!)")

    # What if we use the FOUR bearings to divide the 97 positions into groups?
    # Sort bearings and assign positions to sectors between them
    all_bearings = sorted([
        ('KRYPTOS', b_kryptos),
        ('LODESTONE', b_lodestone),
        ('K2_TARGET', b_k2),
    ], key=lambda x: x[1])

    print(f"\n  Sorted bearings: {[(n, f'{b:.2f}°') for n, b in all_bearings]}")
    print(f"  Sectors between bearings:")
    for i in range(len(all_bearings)):
        j = (i + 1) % len(all_bearings)
        b_start = all_bearings[i][1]
        b_end = all_bearings[j][1]
        arc = (b_end - b_start) % 360
        n_positions = round(arc / 360 * CT_LEN)
        print(f"    {all_bearings[i][0]} → {all_bearings[j][0]}: {arc:.2f}° → ~{n_positions} positions")

    # Key observation: 24° maps to 24/360 * 97 ≈ 6.47 positions
    # But the bearing range 56.46° to 80.49° maps to positions:
    # pos = bearing * 97 / 360
    pos_kryptos = b_kryptos * CT_LEN / 360
    pos_k2 = b_k2 * CT_LEN / 360
    pos_lodestone = b_lodestone * CT_LEN / 360
    print(f"\n  Bearing-to-position mapping (bearing * 97 / 360):")
    print(f"    KRYPTOS:   position {pos_kryptos:.2f}")
    print(f"    LODESTONE: position {pos_lodestone:.2f}")
    print(f"    K2_TARGET: position {pos_k2:.2f}")

    # The LOOMIS angle of 24° between KRYPTOS and K2 could select
    # positions where (pos * 360 / 97) falls within [56.46°, 80.49°]
    nulls_in_sector = []
    for i in range(CT_LEN):
        pos_bearing = i * 360.0 / CT_LEN
        if b_kryptos <= pos_bearing <= b_k2:
            nulls_in_sector.append(i)
    print(f"\n  Positions in KRYPTOS-K2 sector ({b_kryptos:.1f}°-{b_k2:.1f}°): {nulls_in_sector}")
    print(f"  Count: {len(nulls_in_sector)}")

    # 7 positions in this sector. Not 24.
    # But what if we use MULTIPLE angular sectors?
    # The triangle has 3 vertex angles: 24° (LOOMIS), ~69° (KRYPTOS), ~80° (K2)
    # 24 + 69 + 80 ≈ 173° (should be ~180° for a triangle, close)

    # What if 24° is the KEY and we select every position whose
    # distance from a reference is a multiple of 24 (mod 97)?
    for start in range(CT_LEN):
        nulls_24_step = [(start + i * 24) % CT_LEN for i in range(CT_LEN)]
        # Remove duplicates (since gcd(24, 97) = 1, this visits all 97 positions)
        # 24 and 97 are coprime → full cycle of 97
        # Take the first 24 positions visited
        unique = []
        seen = set()
        for p in nulls_24_step:
            if p not in seen:
                unique.append(p)
                seen.add(p)
            if len(unique) == 24:
                break
        valid, detail = check_mask(unique)
        if valid:
            overlap = len(set(unique) & CONSENSUS_NULLS)
            if overlap >= 8:  # At least half of consensus
                print(f"\n  Step-24 from pos {start}: VALID mask, consensus overlap={overlap}/17")
                results = test_mask_with_keywords(unique, f"step24-{start}")
                if results:
                    print(f"    Best: {results[0]}")


# ══════════════════════════════════════════════════════════════════════════════
# DEEP DIVE 2: THE 89° RIGHT ANGLE COINCIDENCE
# ══════════════════════════════════════════════════════════════════════════════

def deep_dive_2():
    print("\n" + "=" * 80)
    print("DEEP DIVE 2: THE 89° RIGHT-ANGLE COINCIDENCE")
    print("=" * 80)

    # 24 crib positions span 89.07° of the 97-circle ≈ right angle
    # 73 non-crib positions span 270.93° ≈ 3/4 circle
    # This is EXACTLY 24/97 * 360 = 89.07°

    crib_arc = 24.0 / 97 * 360
    non_crib_arc = 73.0 / 97 * 360
    print(f"  24 crib positions → {crib_arc:.4f}° (≈ 89° ≈ right angle)")
    print(f"  73 non-crib positions → {non_crib_arc:.4f}° (≈ 271° ≈ 3/4 circle)")

    # What angle at the installation is closest to 89°?
    # We already know the K2 angle is ~80°
    k2_angle = angle_at_vertex(POINTS['KRYPTOS'], POINTS['K2_TARGET'], POINTS['LODESTONE'])
    k2_angle2 = angle_at_vertex(POINTS['KRYPTOS'], POINTS['K2_TARGET'], POINTS['LOOMIS'])
    print(f"\n  Angle at K2 (KRYPTOS-LODESTONE): {k2_angle:.2f}°")
    print(f"  Angle at K2 (KRYPTOS-LOOMIS):    {k2_angle2:.2f}°")

    # The "right angle" connection: if we place the 97 positions on a circle
    # and draw two radii to the start of each crib block, the angle between
    # the NON-crib arc is very close to 270° = 3 * 90°

    # What if the cipher uses quadrant-based operations?
    # Divide the 97 positions into 4 quadrants (approximately 24-25 each)
    print(f"\n  Quadrant analysis (positions on 97-circle):")
    quadrants = [[], [], [], []]
    for i in range(CT_LEN):
        angle = i * 360.0 / CT_LEN
        q = int(angle / 90) % 4
        quadrants[q].append(i)

    for q in range(4):
        positions = quadrants[q]
        chars = ''.join(CT[p] for p in positions)
        crib_in = [p for p in positions if p in CRIB_POSITIONS]
        print(f"    Q{q} ({q*90}°-{(q+1)*90}°): {len(positions)} positions, "
              f"{len(crib_in)} crib positions")
        print(f"      Chars: {chars}")
        print(f"      Crib: {''.join(CRIB_DICT[p] for p in sorted(crib_in))}")

    # Q0 (0-89°) has positions 0-23 → includes ENE start
    # Q1 (90-179°) has positions 24-47 → includes ENE end
    # Q2 (180-269°) has positions 48-72 → includes BC
    # Q3 (270-359°) has positions 73-96

    # The cribs are in Q0+Q1 (ENE) and Q2+Q3 (BC)
    # Quadrant symmetry: ENE in first half, BC in third quarter

    # What if Q3 (positions 73-96) = the 24 nulls?
    q3_positions = quadrants[3]
    print(f"\n  Q3 as nulls: {q3_positions}")
    valid, detail = check_mask(q3_positions)
    print(f"  Valid: {detail}")
    if valid:
        results = test_mask_with_keywords(q3_positions, "Q3-nulls")
        if results:
            for r in results[:3]:
                print(f"    {r}")

    # What if we rotate the quadrant boundaries by some angle?
    for rotation in range(CT_LEN):
        q3_rotated = [(rotation + i) % CT_LEN for i in range(24)]  # 24 consecutive
        valid, detail = check_mask(q3_rotated)
        if valid:
            overlap = len(set(q3_rotated) & CONSENSUS_NULLS)
            if overlap >= 10:
                print(f"\n  Consecutive 24 starting at {rotation}: VALID, "
                      f"consensus overlap={overlap}/17")


# ══════════════════════════════════════════════════════════════════════════════
# DEEP DIVE 3: CONSENSUS NULLS — GRID COLUMN ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def deep_dive_3():
    print("\n" + "=" * 80)
    print("DEEP DIVE 3: CONSENSUS NULLS — COLUMN PATTERNS")
    print("=" * 80)

    # The consensus null columns are:
    # Row 24: cols 27, 28, 29 (3 of 4 chars in row 24)
    # Row 25: cols 1, 4, 8, 10, 16 (5 of 31)
    # Row 26: cols 1, 17, 23, 24 (4 of 31)
    # Row 27: cols 8, 9, 12, 18, 19 (5 of 31)

    # STRIKING: Column 1 has nulls in BOTH rows 25 and 26
    # Column 8 has nulls in BOTH rows 25 and 27

    # Show the full K4 grid with nulls marked
    print(f"\n  K4 grid with consensus nulls (X = null, . = kept):")
    for row in range(24, 28):
        line = ""
        for col in range(31):
            # Find K4 position at (row, col)
            found = False
            for i, (r, c) in enumerate(K4_GRID):
                if r == row and c == col:
                    if i in CONSENSUS_NULLS:
                        line += "X"
                    else:
                        line += CT[i]
                    found = True
                    break
            if not found:
                line += " "
        print(f"    Row {row}: {line}")

    # Check if null columns follow a mathematical pattern
    null_cols_25 = sorted([1, 4, 8, 10, 16])
    null_cols_26 = sorted([1, 17, 23, 24])
    null_cols_27 = sorted([8, 9, 12, 18, 19])

    print(f"\n  Column patterns:")
    print(f"    Row 25 null cols: {null_cols_25}")
    print(f"      Diffs: {[null_cols_25[i+1]-null_cols_25[i] for i in range(len(null_cols_25)-1)]}")
    print(f"    Row 26 null cols: {null_cols_26}")
    print(f"      Diffs: {[null_cols_26[i+1]-null_cols_26[i] for i in range(len(null_cols_26)-1)]}")
    print(f"    Row 27 null cols: {null_cols_27}")
    print(f"      Diffs: {[null_cols_27[i+1]-null_cols_27[i] for i in range(len(null_cols_27)-1)]}")

    # Check: do null columns align with grid diagonals?
    # A diagonal at slope m through starting column c0:
    # row 25 → c0, row 26 → c0+m, row 27 → c0+2m
    print(f"\n  Diagonal alignment check:")
    for m in range(-15, 16):
        # For each starting column in row 25's nulls
        for c0 in null_cols_25:
            c26 = (c0 + m) % 31
            c27 = (c0 + 2*m) % 31
            if c26 in null_cols_26 and c27 in null_cols_27:
                print(f"    Slope {m}: col {c0} (r25) → col {c26} (r26) → col {c27} (r27)")

    # What if the null columns are defined by a BEARING through the grid?
    # The grid columns map to compass directions
    # Column 0 = west edge, column 30 = east edge
    # A bearing of B° through 31 columns = tan(B) * rows_crossed columns
    print(f"\n  Bearing-guided column selection:")

    # Key bearings
    for bname, bval in [
        ("LOOMIS→KRYPTOS", bearing_deg(POINTS['LOOMIS'], POINTS['KRYPTOS'])),
        ("LOOMIS→K2", bearing_deg(POINTS['LOOMIS'], POINTS['K2_TARGET'])),
        ("LOOMIS→LODESTONE", bearing_deg(POINTS['LOOMIS'], POINTS['LODESTONE'])),
        ("KRYPTOS→K2", bearing_deg(POINTS['KRYPTOS'], POINTS['K2_TARGET'])),
        ("KRYPTOS→LODESTONE", bearing_deg(POINTS['KRYPTOS'], POINTS['LODESTONE'])),
    ]:
        # Column shift per row = tan(bearing) projected onto grid
        # But we need to think about how the grid maps to geography
        # Grid rows go downward (south), columns go right (east)
        # A bearing from north, clockwise:
        # 0° = up = -row direction
        # 90° = right = +col direction
        # So column_shift_per_row = tan(bearing) for bearing < 90°
        # For general bearing: dcol/drow = sin(b)/(-cos(b)) = -tan(b) ... careful

        rad = math.radians(bval)
        dcol_per_row = math.sin(rad) / abs(math.cos(rad)) if abs(math.cos(rad)) > 0.01 else float('inf')

        if abs(dcol_per_row) < 50:
            # Trace through the 4 K4 rows
            cols_hit = []
            for row_offset in range(4):
                c = int(round(dcol_per_row * row_offset)) % 31
                cols_hit.append(c)
            print(f"    {bname} ({bval:.1f}°): col shift = {dcol_per_row:.2f}/row → cols {cols_hit}")

    # Check: the consensus null columns have a pattern related to the
    # installation distances
    dists = {
        'LOOMIS→KRYPTOS': distance_m(POINTS['LOOMIS'], POINTS['KRYPTOS']),
        'LOOMIS→LODESTONE': distance_m(POINTS['LOOMIS'], POINTS['LODESTONE']),
        'LOOMIS→K2': distance_m(POINTS['LOOMIS'], POINTS['K2_TARGET']),
        'KRYPTOS→K2': distance_m(POINTS['KRYPTOS'], POINTS['K2_TARGET']),
    }
    print(f"\n  Installation distances:")
    for name, d in dists.items():
        print(f"    {name}: {d:.1f}m → mod 31 = {round(d) % 31}")


# ══════════════════════════════════════════════════════════════════════════════
# DEEP DIVE 4: LODESTONE→LOOMIS BEARING ≈ 74.5°
# ══════════════════════════════════════════════════════════════════════════════

def deep_dive_4():
    print("\n" + "=" * 80)
    print("DEEP DIVE 4: LODESTONE BEARING COINCIDENCES")
    print("=" * 80)

    # Key bearing coincidences from the installation
    b_loomis_to_lodestone = bearing_deg(POINTS['LOOMIS'], POINTS['LODESTONE'])
    b_lodestone_to_loomis = bearing_deg(POINTS['LODESTONE'], POINTS['LOOMIS'])
    b_kryptos_to_lodestone = bearing_deg(POINTS['KRYPTOS'], POINTS['LODESTONE'])

    print(f"  LOOMIS → LODESTONE: {b_loomis_to_lodestone:.2f}°")
    print(f"  LODESTONE → LOOMIS: {b_lodestone_to_loomis:.2f}°")
    print(f"  KRYPTOS → LODESTONE: {b_kryptos_to_lodestone:.2f}°")

    # LOOMIS→LODESTONE = 74.46° ≈ position 74 (W, first position AFTER BERLINCLOCK)
    print(f"\n  LOOMIS→LODESTONE bearing {b_loomis_to_lodestone:.1f}° ≈ position 74")
    print(f"    Position 74 = '{CT[74]}' = W (first char after BERLINCLOCK crib)")
    print(f"    This W is in the consensus null set: {74 in CONSENSUS_NULLS}")
    print(f"    All 5 W positions: {W_POSITIONS}")
    print(f"    Position 74 marks the END of the crib zone")

    # The LODESTONE bearing essentially points to the boundary between
    # the BC crib and the post-crib zone. This is geometrically meaningful.

    # What if the lodestone bearing DEFINES where to split the text?
    split_pos = round(b_loomis_to_lodestone)  # ≈ 74
    print(f"\n  Splitting CT at position {split_pos} (lodestone bearing):")
    part1 = CT[:split_pos]
    part2 = CT[split_pos:]
    print(f"    Part 1 ({len(part1)} chars): {part1}")
    print(f"    Part 2 ({len(part2)} chars): {part2}")

    # What if Part 2 is the "null zone"?
    # Part 2 has 23 chars (74..96), we need 24 nulls. Add position 73?
    # Position 73 = K = self-encrypting = crib position (last of BERLINCLOCK)
    # Can't null it. What about position 20? (W before ENE crib)
    additional = [20]  # W at position 20
    nulls_test = list(range(split_pos, CT_LEN)) + additional
    valid, detail = check_mask(nulls_test)
    print(f"\n  Nulls = [{split_pos}..96] + [20]: {detail}")

    # Try: positions at angles > 74° on the circle as nulls
    for threshold_angle in range(70, 100):
        nulls = [i for i in range(CT_LEN) if i * 360.0 / CT_LEN >= threshold_angle * 360.0 / CT_LEN]
        # This just gives positions >= threshold, same as above. Need circular.
        pass

    # Distance coincidences
    d_loomis_lodestone = distance_m(POINTS['LOOMIS'], POINTS['LODESTONE'])
    d_kryptos_k2 = distance_m(POINTS['KRYPTOS'], POINTS['K2_TARGET'])
    d_loomis_k2 = distance_m(POINTS['LOOMIS'], POINTS['K2_TARGET'])

    print(f"\n  Distance coincidences:")
    print(f"    LOOMIS→LODESTONE: {d_loomis_lodestone:.2f}m → mod 26 = {round(d_loomis_lodestone)%26}")
    print(f"    KRYPTOS→K2:       {d_kryptos_k2:.2f}m → mod 26 = {round(d_kryptos_k2)%26}")
    print(f"    LOOMIS→K2:        {d_loomis_k2:.2f}m → mod 26 = {round(d_loomis_k2)%26}")

    # d_loomis_lodestone ≈ 27.7m → mod 26 = 2 (C)
    # d_kryptos_k2 ≈ 53.8m → mod 26 = 2 (C)
    # d_loomis_k2 ≈ 127.1m → mod 26 = 23 (X)

    # KRYPTOS→K2 distance ≈ 53.8 ≈ 54 → position 54 = 'U' (LUDI)
    # 54 mod 26 = 2 → letter C


# ══════════════════════════════════════════════════════════════════════════════
# DEEP DIVE 5: 31-WIDE GRID + INSTALLATION BEARINGS AS READ PATTERN
# ══════════════════════════════════════════════════════════════════════════════

def deep_dive_5():
    print("\n" + "=" * 80)
    print("DEEP DIVE 5: GRID BEARING READ PATTERNS (DETAILED)")
    print("=" * 80)

    # The 31-wide grid with 4 K4 rows can be traversed in many ways.
    # Installation bearings define SPECIFIC traversal patterns.

    # Build the K4 grid as a 2D array for easy access
    grid = {}
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        grid[(r, c)] = i

    # Key idea: use bearing as a SKIP PATTERN
    # Bearing N° → every N-th column (wrapping around)

    key_values = {
        'b_LOOMIS_KRYPTOS': round(bearing_deg(POINTS['LOOMIS'], POINTS['KRYPTOS'])),  # 56
        'b_LOOMIS_K2': round(bearing_deg(POINTS['LOOMIS'], POINTS['K2_TARGET'])),      # 80
        'b_LOOMIS_LODESTONE': round(bearing_deg(POINTS['LOOMIS'], POINTS['LODESTONE'])), # 74
        'd_LOOMIS_LODESTONE': round(distance_m(POINTS['LOOMIS'], POINTS['LODESTONE'])),  # 28
        'd_KRYPTOS_K2': round(distance_m(POINTS['KRYPTOS'], POINTS['K2_TARGET'])),       # 54
        'angle_at_LOOMIS': round(angle_at_vertex(POINTS['KRYPTOS'], POINTS['LOOMIS'], POINTS['K2_TARGET'])), # 24
    }

    print(f"  Key geometric values:")
    for name, val in key_values.items():
        print(f"    {name}: {val} → mod 31 = {val % 31}, mod 97 = {val % 97}, mod 26 = {val % 26}")

    # Try: use geometric values as column reading orders
    # Read columns in order defined by: column = (start + i * step) mod 31
    print(f"\n  Column reading orders defined by geometric step sizes:")
    for step_name, step in [
        ("angle_24", 24),
        ("bearing_56", 56 % 31),  # = 25
        ("bearing_80", 80 % 31),  # = 18
        ("bearing_74", 74 % 31),  # = 12
        ("distance_28", 28 % 31),  # = 28
        ("distance_54", 54 % 31),  # = 23
        ("step_7", 7),
        ("step_13", 13),
        ("step_11", 11),
    ]:
        if math.gcd(step, 31) != 1 and step != 0:
            print(f"    Step {step_name} ({step}): gcd({step},31)={math.gcd(step,31)} → won't visit all columns")
            continue

        for start_col in range(31):
            col_order = [(start_col + i * step) % 31 for i in range(31)]
            if len(set(col_order)) != 31:
                continue

            # Read the grid in this column order
            text = []
            for c in col_order:
                for r in range(24, 28):
                    if (r, c) in grid:
                        text.append(CT[grid[(r, c)]])
            read_text = ''.join(text)
            if len(read_text) != CT_LEN:
                continue

            sc = score_cribs(read_text)
            sc_free = score_free_fast(read_text)
            if sc >= 5 or sc_free > 0:
                print(f"    Step {step_name} ({step}), start {start_col}: "
                      f"anchored={sc}, free={sc_free}")
                print(f"      Text: {read_text[:60]}...")

    # Try: read ROWS in geometric order (not just columns)
    # K4 has 4 rows (24-27), 4! = 24 permutations
    print(f"\n  Row permutation reading orders:")
    for perm in permutations([24, 25, 26, 27]):
        text = []
        for r in perm:
            for c in range(31):
                if (r, c) in grid:
                    text.append(CT[grid[(r, c)]])
        read_text = ''.join(text)
        sc = score_cribs(read_text)
        if sc >= 4:
            print(f"    Rows {perm}: anchored={sc}, text={read_text[:50]}...")

    # Try: alternating column+row orders
    print(f"\n  Geometric column step + S-curve row alternation:")
    for step in [7, 11, 12, 13, 23, 24, 25, 28]:
        for start_col in range(31):
            col_order = [(start_col + i * step) % 31 for i in range(31)]
            if len(set(col_order)) != 31:
                continue

            # Read with S-curve (alternate row direction per column)
            text = []
            for ci, c in enumerate(col_order):
                if ci % 2 == 0:
                    row_order = range(24, 28)
                else:
                    row_order = range(27, 23, -1)
                for r in row_order:
                    if (r, c) in grid:
                        text.append(CT[grid[(r, c)]])
            read_text = ''.join(text)
            sc = score_cribs(read_text)
            sc_free = score_free_fast(read_text)
            if sc >= 5 or sc_free > 0:
                print(f"    Step {step}, start {start_col}, S-curve: "
                      f"anchored={sc}, free={sc_free}")


# ══════════════════════════════════════════════════════════════════════════════
# DEEP DIVE 6: CIRCULAR POSITION MAPPING WITH LODESTONE DEFLECTION
# ══════════════════════════════════════════════════════════════════════════════

def deep_dive_6():
    print("\n" + "=" * 80)
    print("DEEP DIVE 6: CIRCULAR MAPPING WITH LODESTONE DEFLECTION")
    print("=" * 80)

    # The lodestone deflects compass readings. If positions on the 97-circle
    # are "deflected" by the lodestone bearing, we get a REMAPPING.
    lodestone_bearing = bearing_deg(POINTS['KRYPTOS'], POINTS['LODESTONE'])
    deflection_positions = lodestone_bearing * CT_LEN / 360  # ≈ 62.5

    print(f"  Lodestone bearing from KRYPTOS: {lodestone_bearing:.2f}°")
    print(f"  Deflection in positions: {deflection_positions:.2f}")
    print(f"  Round deflection: {round(deflection_positions)}")

    # Apply deflection as a circular shift
    shift = round(deflection_positions)  # ≈ 63
    print(f"\n  Circular shift by {shift} (lodestone deflection):")
    shifted = ''.join(CT[(i + shift) % CT_LEN] for i in range(CT_LEN))
    sc = score_cribs(shifted)
    print(f"    Anchored score: {sc}")
    print(f"    Shifted text: {shifted[:60]}...")

    # REMARKABLE: shift ≈ 63 and position 63 = start of BERLINCLOCK!
    print(f"\n  *** LODESTONE DEFLECTION ≈ 63 = START OF BERLINCLOCK CRIB ***")

    # What if the lodestone shift moves BERLINCLOCK to position 0?
    # Then EASTNORTHEAST would be at position 21 - 63 = -42 mod 97 = 55
    for exact_shift in range(60, 67):
        shifted = ''.join(CT[(i + exact_shift) % CT_LEN] for i in range(CT_LEN))
        sc = score_cribs(shifted)
        # Check where cribs would fall
        # After shifting by S, original position P becomes position (P - S) mod 97
        ene_new_start = (21 - exact_shift) % CT_LEN
        bc_new_start = (63 - exact_shift) % CT_LEN
        print(f"    Shift {exact_shift}: ENE→pos{ene_new_start}, BC→pos{bc_new_start}, score={sc}")

    # The shift of 63 makes BC start at position 0 and ENE at position 55
    # This is interesting because it "centers" the text around BERLINCLOCK

    # What if we apply shift + substitution?
    for exact_shift in [62, 63, 64]:
        shifted = ''.join(CT[(i + exact_shift) % CT_LEN] for i in range(CT_LEN))
        for kw in ["KRYPTOS", "DEFECTOR", "KOMPASS", "PALIMPSEST", "BERLIN", "COMPASS"]:
            for name, fn in [("vig", vigenere_dec), ("beau", beaufort_dec)]:
                pt = fn(shifted, kw)
                sc = score_free_fast(pt)
                if sc > 0:
                    print(f"    Shift {exact_shift} + {name}({kw}): free={sc}")
                    print(f"      PT: {pt[:60]}...")


# ══════════════════════════════════════════════════════════════════════════════
# DEEP DIVE 7: K2 COORDINATES AS GEOMETRIC CONSTRUCTOR
# ══════════════════════════════════════════════════════════════════════════════

def deep_dive_7():
    print("\n" + "=" * 80)
    print("DEEP DIVE 7: K2 COORDINATES AS GEOMETRIC CONSTRUCTOR")
    print("=" * 80)

    # K2 decoded: "38 degrees 57 minutes 6.5 seconds"
    # 38: 3²+8² = 73, 3×8 = 24, 3+8 = 11
    # 6.5: ×2 = 13, 6+5 = 11

    # These numbers define a CONSTRUCTION RECIPE, not a direct key.
    # What geometric construction uses 73, 24, 13, 11?

    print(f"  K2-derived constants: 73, 24, 13, 11")
    print(f"  97 = 73 + 24")
    print(f"  24 = 13 + 11")
    print(f"  73 = 97 - 24")

    # Construction: Draw a circle of circumference 97
    # Mark off 13 consecutive positions (ENE) starting at position 21
    # Mark off 11 consecutive positions (BC) starting at position 63
    # The 24 marked positions define the cribs
    # The 73 unmarked positions are the message

    # Now: 38 and 57 might define the STARTING POSITIONS
    # 38 mod 97 = 38, 57 mod 97 = 57
    # 38 + 21 = 59, 57 + 21 = 78 → not obvious
    # 38 - 21 = 17, 57 - 21 = 36 → 36 is a W position!

    print(f"\n  K2 position arithmetic:")
    for n in [38, 57, 65, 6, 5]:
        print(f"    {n}: mod 97 = {n % 97}, mod 26 = {n % 26} = {ALPH[n % 26]}, "
              f"mod 31 = {n % 31}")

    # 57 - 21 = 36 = W position (consensus null)
    # 38 - 21 = 17 (not a W or null)
    # 57 + 6 = 63 = BC start!
    print(f"    57 + 6 = 63 = BERLINCLOCK start!")
    print(f"    38 - 17 = 21 = EASTNORTHEAST start!")  # 38 - 17? No, that's arbitrary
    # Actually: 57 + 6 = 63 is remarkable
    # And: 38 + 57 = 95, 95 mod 97 = 95, 95 mod 26 = 17

    # What if 38 and 57 define a STEP SIZE on the grid?
    # Grid has 31 columns. 38 mod 31 = 7 → column width 7!
    print(f"\n  38 mod 31 = {38 % 31} → column width 7 (the winning transposition!)")
    print(f"  57 mod 31 = {57 % 31} → column width 26 = alphabet size")
    print(f"  65 mod 31 = {65 % 31} → column width 3")

    # KEY FINDING: 38 mod 31 = 7 → THIS IS THE COL7 TRANSPOSITION!
    # The K2 coordinate's degree value (38) mod the grid width (31) = 7
    # And col7 transposition is what makes DEFECTOR:AZ_beau achieve 15/24!

    print(f"\n  *** 38 mod 31 = 7 → K2 DEGREE VALUE ENCODES COL7 TRANSPOSITION ***")
    print(f"  This may be the operational mechanism for K2 coordinates → K4 method")

    # Further: 57 mod 31 = 26 → the ALPHABET SIZE
    # 6 mod 31 = 6 (not obviously significant)
    # 5 mod 31 = 5 (number of W's!)
    print(f"  57 mod 31 = {57 % 31} = 26 (alphabet size)")
    print(f"  6.5: 6 mod 31 = 6, 5 mod 31 = 5 = number of W's")

    # What about the other direction?
    # 77 degrees 8 minutes 44 seconds (longitude)
    print(f"\n  K2 longitude: 77°8'44\"")
    print(f"    77 mod 31 = {77 % 31} → 15 (position in grid)")
    print(f"    8 mod 31 = {8 % 31}")
    print(f"    44 mod 31 = {44 % 31} → 13 (ENE length!)")
    print(f"    77 mod 97 = {77 % 97} → position 77")
    print(f"    77 mod 26 = {77 % 26} → {ALPH[77 % 26]} = position 25 in alphabet")

    # 44 mod 31 = 13 = ENE length. Another encoding!
    print(f"\n  *** LONGITUDE SECONDS (44) mod 31 = 13 = ENE CRIB LENGTH ***")


# ══════════════════════════════════════════════════════════════════════════════
# DEEP DIVE 8: GEOMETRIC NULL MASK CANDIDATES WITH HIGHEST CONSENSUS OVERLAP
# ══════════════════════════════════════════════════════════════════════════════

def deep_dive_8():
    print("\n" + "=" * 80)
    print("DEEP DIVE 8: GEOMETRIC MASKS WITH HIGH CONSENSUS OVERLAP")
    print("=" * 80)

    # The consensus has 17 positions. We need 24 total.
    # The remaining 7 come from clusters: {38-45}, {55-56}, {87-88}, {93-96}
    # Test ALL combinations of 7 positions from non-consensus, non-crib positions
    # that geometrically make sense

    non_crib_non_consensus = sorted(
        set(range(CT_LEN)) - CRIB_POSITIONS - CONSENSUS_NULLS
    )
    print(f"  Available positions for remaining 7: {len(non_crib_non_consensus)} positions")
    print(f"  Positions: {non_crib_non_consensus}")

    # Instead of brute force C(56,7) ≈ 231M, use geometric constraints
    # The remaining 7 must come from the variable clusters
    cluster_options = [
        [38, 39, 40, 41, 42, 43, 44, 45],  # cluster 1
        [55, 56],                            # cluster 2
        [87, 88],                            # cluster 3
        [93, 94, 95, 96],                    # cluster 4
    ]

    # Filter to non-crib positions
    for i, cluster in enumerate(cluster_options):
        cluster_options[i] = [p for p in cluster if p not in CRIB_POSITIONS]
        print(f"  Cluster {i+1}: {cluster_options[i]}")

    # Generate all combinations that sum to 7 from these clusters
    from itertools import product as iprod

    valid_completions = []
    for n1 in range(len(cluster_options[0]) + 1):
        for n2 in range(len(cluster_options[1]) + 1):
            for n3 in range(len(cluster_options[2]) + 1):
                for n4 in range(len(cluster_options[3]) + 1):
                    if n1 + n2 + n3 + n4 == 7:
                        for c1 in combinations(cluster_options[0], n1):
                            for c2 in combinations(cluster_options[1], n2):
                                for c3 in combinations(cluster_options[2], n3):
                                    for c4 in combinations(cluster_options[3], n4):
                                        extra = list(c1) + list(c2) + list(c3) + list(c4)
                                        nulls = sorted(CONSENSUS_NULLS | set(extra))
                                        valid, detail = check_mask(nulls)
                                        if valid:
                                            valid_completions.append(nulls)

    print(f"\n  Valid 24-position masks extending consensus: {len(valid_completions)}")

    # Test each with DEFECTOR:AZ_beau (the known best keyword)
    best_results = []
    for nulls in valid_completions:
        text_73 = extract_73(nulls)
        # Test DEFECTOR:AZ_beau
        pt = beaufort_dec(text_73, "DEFECTOR")
        hits, ene, bc = score_with_mapped_cribs(pt, nulls)
        if hits >= 10:
            best_results.append((hits, ene, bc, sorted(set(nulls) - CONSENSUS_NULLS), pt[:50]))

    best_results.sort(key=lambda x: -x[0])
    print(f"\n  Results with DEFECTOR:AZ_beau (score >= 10):")
    for hits, ene, bc, extra, pt in best_results[:20]:
        print(f"    Score {hits}/24 (ene={ene}, bc={bc}), extra nulls: {extra}")
        print(f"      PT: {pt}")

    if not best_results:
        print(f"    No results scored >= 10")
        # Show best regardless
        all_results = []
        for nulls in valid_completions[:100]:  # Sample
            text_73 = extract_73(nulls)
            pt = beaufort_dec(text_73, "DEFECTOR")
            hits, ene, bc = score_with_mapped_cribs(pt, nulls)
            all_results.append((hits, ene, bc, sorted(set(nulls) - CONSENSUS_NULLS)))
        all_results.sort(key=lambda x: -x[0])
        print(f"\n  Top 5 from sample of {len(all_results)}:")
        for hits, ene, bc, extra in all_results[:5]:
            print(f"    Score {hits}/24 (ene={ene}, bc={bc}), extra: {extra}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 80)
    print("FOCUSED GEOMETRIC ANALYSIS — DEEP DIVES")
    print("=" * 80)
    print(f"CT ({CT_LEN} chars): {CT}")

    deep_dive_1()
    deep_dive_2()
    deep_dive_3()
    deep_dive_4()
    deep_dive_5()
    deep_dive_6()
    deep_dive_7()
    deep_dive_8()

    print("\n" + "=" * 80)
    print("FOCUSED ANALYSIS COMPLETE")
    print("=" * 80)


if __name__ == '__main__':
    main()
