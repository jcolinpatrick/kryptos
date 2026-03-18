#!/usr/bin/env python3
"""Cylindrical Projection Null-Mask Models for K4.

# Cipher: null_mask
# Family: geometry
# Status: active
# Keyspace: ~10K projection configurations
# Last run: never
# Best score: n/a

Explores how CYLINDRICAL PROJECTION could define the 24-null mask:

1. CYLINDER WRAP — K4 on a circumference-31 cylinder. Antipodal positions
   (col vs col+15/16) define front/back. Shadow = nulls.

2. LIGHT PROJECTION — For each light angle (0-360°), determine which
   front-side positions cast light onto back-side positions. Find angles
   that produce exactly 24 shadowed positions avoiding cribs.

3. K3K4 CYLINDER — K3 cutouts on the FRONT project light through to K4
   on the BACK. Which K3 letters illuminate which K4 positions?

4. S-CURVE OCCLUSION — Two half-cylinders. Parts of text block light
   from reaching other parts. Test with ENE direction (67.5°) and others.

5. ANTIPODES CONNECTION — "Antipodes" = diametrically opposite.
   Antipodal K4 positions as null pattern.

For each candidate mask: test DEFECTOR:AZ_beau + col7 transposition.
"""

import sys
import os
import math
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS, CRIB_DICT

# ── Constants ──────────────────────────────────────────────────────────────

CT97 = CT
N = 97
N_NULLS = 24
N_PT = 73
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63

GRID_COLS = 31
GRID_ROWS = 28

# K4 starts at row 24, col 27 (0-indexed in the 28×31 grid)
K4_START_ROW = 24
K4_START_COL = 27

# Full bottom-14 grid (K3 + K4), rows 14-27
# K3 occupies rows 14-23 (+ part of row 24 cols 0-26)
# K4 occupies row 24 cols 27-30, rows 25-27 full, for 97 chars total
BOTTOM_14_ROWS = [
    'ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI',   # row 14  K3 starts
    'ACHTNREYULDSLLSLLNOHSNOSMRWXMNE',   # row 15
    'TPRNGATIHNRARPESLNNELEBLPIIACAE',    # row 16  (30 chars)
    'WMTWNDITEENRAHCTENEUDRETNHAEOET',    # row 17
    'FOLSEDTIWENHAEIOYTEYQHEENCTAYCR',    # row 18
    'EIFTBRSPAMHHEWENATAMATEGYEERLBT',    # row 19
    'EEFOASFIOTUETUAEOTOARMAEERTNRTI',    # row 20
    'BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB',    # row 21
    'AECTDDHILCEIHSITEGOEAOSDDRYDLOR',    # row 22
    'ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE',    # row 23
    'ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR',    # row 24  K4@col27
    'UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO',    # row 25
    'TWTQSJQSSEKZZWATJKLUDIAWINFBNYP',    # row 26
    'VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR',    # row 27
]

# K4 grid positions: (row, col) for each of the 97 K4 characters
def k4_grid_positions():
    positions = []
    grid_pos = K4_START_ROW * GRID_COLS + K4_START_COL
    for i in range(CT_LEN):
        row = grid_pos // GRID_COLS
        col = grid_pos % GRID_COLS
        positions.append((row, col))
        grid_pos += 1
    return positions

K4_GRID = k4_grid_positions()

# Map K4 index → (row_in_bottom14, col)
# Bottom-14 starts at row 14
def k4_bottom14_positions():
    return [(r - 14, c) for r, c in K4_GRID]

K4_B14 = k4_bottom14_positions()

# K3 text and positions (everything in bottom-14 BEFORE K4)
def get_k3_positions_and_text():
    """Returns list of (bottom14_row, col, char) for K3 characters."""
    k3_chars = []
    for row_idx, row_text in enumerate(BOTTOM_14_ROWS):
        for col_idx, ch in enumerate(row_text):
            # K4 starts at row 24 (= bottom14 row 10), col 27
            if row_idx < 10 or (row_idx == 10 and col_idx < 27):
                if ch != '?':  # Skip the ? placeholder
                    k3_chars.append((row_idx, col_idx, ch))
    return k3_chars

K3_CHARS = get_k3_positions_and_text()

# ── Cipher Functions ──────────────────────────────────────────────────────

def columnar_perm(n, width):
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = reverse_perm(columnar_perm(N_PT, 7))
IDENTITY_PERM = list(range(N_PT))

def autokey_decrypt_az_beau(ct_list, kw):
    """Autokey Beaufort decrypt with AZ alphabet."""
    pt = []
    kw_n = [ord(c) - 65 for c in kw.upper()]
    L = len(kw_n)
    for i, ci in enumerate(ct_list):
        ki = kw_n[i] if i < L else ord(pt[i - L]) - 65
        pt.append(chr((ki - ci) % 26 + 65))
    return ''.join(pt)

def count_crib_hits(pt, ene_s, bcl_s):
    e = sum(1 for j, c in enumerate(ENE_WORD) if ene_s + j < len(pt) and pt[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD) if bcl_s + j < len(pt) and pt[bcl_s + j] == c)
    return e + b, e, b

def eval_mask(null_set, kw='DEFECTOR', perm=None):
    """Evaluate a null mask with DEFECTOR:AZ_beau + optional transposition."""
    if perm is None:
        perm = PERM_COL7
    null_set = frozenset(null_set)
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c) - 65 for c in ct73_raw]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2
    ct73_t = [ct73_az[perm[i]] for i in range(N_PT)]
    pt = autokey_decrypt_az_beau(ct73_t, kw)
    total, e, b = count_crib_hits(pt, ene_s, bcl_s)
    return total, e, b, pt

# ── Mask Validity Check ──────────────────────────────────────────────────

def is_valid_mask(null_set):
    """Check: exactly 24 nulls, none at crib positions."""
    if len(null_set) != N_NULLS:
        return False
    return null_set.isdisjoint(CRIB_POSITIONS)

# ── Reporting ─────────────────────────────────────────────────────────────

best_score = 0
best_results = []

def report(label, null_set, score, e, b, pt=""):
    global best_score, best_results
    if score >= 7:
        print(f"  ** ABOVE NOISE: {label}: {score}/24 (ene={e}/13, bcl={b}/11)")
        print(f"     nulls={sorted(null_set)}")
        if pt:
            print(f"     PT={pt[:60]}...")
    if score > best_score:
        best_score = score
        best_results = [(label, score, e, b, sorted(null_set), pt)]
    elif score == best_score and score >= 7:
        best_results.append((label, score, e, b, sorted(null_set), pt))

# ══════════════════════════════════════════════════════════════════════════
# MODEL 1: CYLINDER WRAP — ANTIPODAL POSITIONS
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 1: CYLINDER WRAP — ANTIPODAL POSITIONS")
print("=" * 80)
print()
print("K4 occupies 4 rows in a circumference-31 cylinder.")
print("Diametrically opposite: col → (col + 15) mod 31 or (col + 16) mod 31")
print()

# Show K4 layout
print("K4 grid layout:")
for i, (r, c) in enumerate(K4_GRID):
    if i == 0 or K4_GRID[i-1][0] != r:
        if i > 0:
            print()
        print(f"  Row {r}: ", end="")
    print(f"{CT97[i]}({c:2d})", end=" ")
print()
print()

# For each K4 position, compute its antipodal column
print("Antipodal pairs (col, col+15 mod 31):")
for offset in [15, 16]:
    antipodal_pairs = []
    for i, (r, c) in enumerate(K4_GRID):
        anti_col = (c + offset) % 31
        # Find K4 positions on same row with this column
        for j, (r2, c2) in enumerate(K4_GRID):
            if r2 == r and c2 == anti_col and i != j:
                antipodal_pairs.append((i, j))
    print(f"  Offset {offset}: {len(antipodal_pairs)} antipodal pairs within K4")
    if antipodal_pairs:
        for a, b in antipodal_pairs[:10]:
            print(f"    K4[{a}] (col {K4_GRID[a][1]}) <-> K4[{b}] (col {K4_GRID[b][1]})")

print()

# Model 1a: Front half vs back half of cylinder
# If the cylinder is viewed from the front, columns 0-15 are front, 16-30 are back (or vice versa)
print("Model 1a: Front/back split by column ranges")
for front_start in range(31):
    front_cols = set((front_start + i) % 31 for i in range(16))  # 16 front columns
    back_cols = set(range(31)) - front_cols  # 15 back columns

    null_set = set()
    for i, (r, c) in enumerate(K4_GRID):
        if c in back_cols:
            null_set.add(i)

    if len(null_set) == N_NULLS and is_valid_mask(null_set):
        sc, e, b, pt = eval_mask(null_set)
        report(f"front_start={front_start}", null_set, sc, e, b, pt)
        if sc >= 5:
            print(f"  front_start={front_start}: {sc}/24 (e={e}, b={b})")

# Also try narrower "visible" bands
print("\nModel 1b: Variable visibility arc (θ degrees visible)")
for arc_deg in range(60, 300, 10):
    arc_cols = int(round(arc_deg / 360.0 * 31))
    for center_col in range(31):
        visible = set((center_col + i - arc_cols // 2) % 31 for i in range(arc_cols))
        null_set = set()
        for i, (r, c) in enumerate(K4_GRID):
            if c not in visible:
                null_set.add(i)
        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            report(f"arc={arc_deg}°,center={center_col}", null_set, sc, e, b, pt)

print(f"\nModel 1 best: {best_score}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 2: LIGHT PROJECTION THROUGH CYLINDER
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 2: LIGHT PROJECTION THROUGH CYLINDER")
print("=" * 80)
print()
print("Light from angle θ passes through cutouts on the front and")
print("illuminates positions on the back. Shadow positions = nulls.")
print()

# Model the cylinder: circumference = 31 columns
# Each column occupies an angular position: θ_col = col * (360/31) degrees
# A parallel light beam from direction θ_light illuminates the front hemisphere
# Front = columns whose angular position is within ±90° of light direction
# Back = the rest
# Light through a front cutout at angular position α hits the back at the
# position that is the mirror of α through the cylinder center.
# On a cylinder: if front position has angle α, the projected position on
# the back side has angle (2*θ_light - α) mod 360

def angular_pos(col):
    """Angular position of column on cylinder (degrees)."""
    return col * 360.0 / 31.0

def col_from_angle(angle):
    """Nearest column to an angular position."""
    angle = angle % 360.0
    return round(angle * 31.0 / 360.0) % 31

def is_front(col, light_angle):
    """Is this column on the front (illuminated) side?"""
    col_angle = angular_pos(col)
    diff = (col_angle - light_angle + 180) % 360 - 180
    return abs(diff) < 90

def projected_col(front_col, light_angle):
    """Where does light through front_col project onto the back?"""
    # Light direction = light_angle. Front cutout at angle α.
    # The projected position on the back = mirror through the light axis
    # = 2*light_angle - α (mod 360)
    α = angular_pos(front_col)
    proj_angle = (2 * light_angle - α) % 360.0
    return col_from_angle(proj_angle)

# For each light angle, compute which K4 positions are illuminated
# (either directly on front, or by projection through front cutouts)
print("Scanning light angles 0-360° in 1° steps...")
model2_count = 0
for light_deg_10 in range(3600):  # 0.1° steps
    light_angle = light_deg_10 / 10.0

    # Classify each K4 position
    # "Front" positions are directly visible (not null)
    # "Back" positions that are illuminated by projection through front = not null
    # "Back" positions in shadow = null candidates

    illuminated = set()  # K4 indices that are illuminated (not null)

    for i, (r, c) in enumerate(K4_GRID):
        if is_front(c, light_angle):
            illuminated.add(i)

    # Now check which back positions are hit by light through front cutouts
    # On the real sculpture, letters are CUTOUTS. Light passes through them.
    # Each row is independent (parallel light, no vertical deviation)
    for i, (r, c) in enumerate(K4_GRID):
        if is_front(c, light_angle):
            # This is a cutout on the front. Light projects to back.
            back_col = projected_col(c, light_angle)
            # Find K4 positions on the same row with this back column
            for j, (r2, c2) in enumerate(K4_GRID):
                if r2 == r and c2 == back_col:
                    illuminated.add(j)

    null_set = set(range(N)) - illuminated
    if len(null_set) == N_NULLS and is_valid_mask(null_set):
        sc, e, b, pt = eval_mask(null_set)
        model2_count += 1
        report(f"light={light_angle:.1f}°", null_set, sc, e, b, pt)

print(f"\nModel 2: {model2_count} valid masks found")
print(f"Model 2 best: {best_score}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 2B: LIGHT WITH VARYING ILLUMINATION THRESHOLD
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 2B: LIGHT WITH ILLUMINATION THRESHOLD")
print("=" * 80)
print()
print("Not all front positions get equal light. Positions near the edge")
print("get grazing light (cos(angle) → 0). Only positions with sufficient")
print("illumination intensity count as 'lit'. Threshold controls null count.")
print()

for light_deg in range(0, 360, 5):
    light_angle = float(light_deg)
    # For each threshold, compute which positions are "sufficiently lit"
    for threshold_pct in range(10, 90, 5):
        threshold = math.cos(math.radians(threshold_pct))

        illuminated = set()
        for i, (r, c) in enumerate(K4_GRID):
            col_angle = angular_pos(c)
            diff = (col_angle - light_angle + 180) % 360 - 180
            intensity = math.cos(math.radians(diff)) if abs(diff) < 90 else 0
            if intensity >= threshold:
                illuminated.add(i)

        null_set = set(range(N)) - illuminated
        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            report(f"light={light_deg}°,thresh={threshold_pct}%", null_set, sc, e, b, pt)

print(f"\nModel 2B best: {best_score}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 3: K3K4 CYLINDER — K3 CUTOUTS PROJECT ONTO K4
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 3: K3K4 CYLINDER — K3 CUTOUTS PROJECT ONTO K4")
print("=" * 80)
print()
print("K3 and K4 share the bottom-14 cylinder. K3 text on the front,")
print("K4 on the back. K3 letter cutouts let light through to K4.")
print("K4 positions illuminated by K3 cutout projections = real text.")
print("K4 positions NOT illuminated = nulls.")
print()

# Build the bottom-14 cylinder (14 rows × 31 cols)
# K3 occupies rows 0-9 + row 10 cols 0-26 (in bottom-14 coords)
# K4 occupies row 10 cols 27-30 + rows 11-13 (in bottom-14 coords)

# K3 positions on the cylinder
k3_positions = [(r, c) for r, c, ch in K3_CHARS]

# K4 positions on the cylinder (bottom-14 coords)
k4_cyl = K4_B14

print(f"K3 has {len(K3_CHARS)} characters on the cylinder")
print(f"K4 has {len(k4_cyl)} characters on the cylinder")
print()

# For each light angle, determine which K4 positions are illuminated
# by light passing through K3 cutouts
print("Scanning light angles for K3→K4 projection...")
model3_count = 0
model3_masks = []

for light_deg_10 in range(3600):
    light_angle = light_deg_10 / 10.0

    # K3 cutouts on the front
    k3_front_cutouts = [(r, c) for r, c in k3_positions if is_front(c, light_angle)]

    # For each K3 front cutout, project to the back
    illuminated_k4 = set()
    for r3, c3 in k3_front_cutouts:
        back_col = projected_col(c3, light_angle)
        # Find K4 positions on ANY row with this back column
        # (light from K3 can hit K4 on different rows depending on geometry)
        # Model A: same-row only (horizontal light)
        for k4_idx, (r4, c4) in enumerate(k4_cyl):
            if c4 == back_col:
                # Check if this position is actually on the back
                if not is_front(c4, light_angle):
                    illuminated_k4.add(k4_idx)

    null_set = set(range(N)) - illuminated_k4
    if len(null_set) == N_NULLS and is_valid_mask(null_set):
        sc, e, b, pt = eval_mask(null_set)
        model3_count += 1
        model3_masks.append((light_angle, null_set, sc))
        report(f"K3proj_light={light_angle:.1f}°", null_set, sc, e, b, pt)

print(f"\nModel 3: {model3_count} valid masks found")
print()

# Also try: K3 cutouts project ONTO same-row K4 positions only
print("Model 3b: same-row K3→K4 projection only...")
for light_deg in range(0, 360, 1):
    light_angle = float(light_deg)

    illuminated_k4 = set()
    for r3, c3 in k3_positions:
        if is_front(c3, light_angle):
            back_col = projected_col(c3, light_angle)
            for k4_idx, (r4, c4) in enumerate(k4_cyl):
                if r4 == r3 and c4 == back_col and not is_front(c4, light_angle):
                    illuminated_k4.add(k4_idx)

    null_set = set(range(N)) - illuminated_k4
    if len(null_set) == N_NULLS and is_valid_mask(null_set):
        sc, e, b, pt = eval_mask(null_set)
        report(f"K3proj_samerow_light={light_deg}°", null_set, sc, e, b, pt)

print(f"\nModel 3b best: {best_score}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 4: S-CURVE SELF-OCCLUSION
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 4: S-CURVE SELF-OCCLUSION")
print("=" * 80)
print()
print("The Kryptos sculpture is S-shaped (two reverse curves).")
print("Model as two half-cylinders: top half curves one way, bottom the other.")
print("The inflection point is between K2 and K3 (row 13-14 boundary).")
print("K4 is in the bottom half-cylinder. The top half can block light to K4.")
print()

# S-curve model:
# Top half (rows 0-13): curves to the RIGHT (concave face → left)
# Bottom half (rows 14-27): curves to the LEFT (concave face → right)
# From any direction, the S-shape means some columns on the bottom half
# are occluded by the top half's curve.

# Simplified: model as a flat screen that is BENT at the middle.
# Each half subtends an arc. The bend angle determines occlusion.

# For K4 (bottom half), the relevant geometry:
# K4 occupies rows 24-27 in the bottom half (rows 14-27).
# Within the bottom half, K4 is near the bottom edge.

# Key insight: the S-curve is most significant for positions near the
# inflection point. K4 is FAR from the inflection (rows 24-27 vs inflection
# at row 13-14). So S-curve occlusion affects K4 minimally compared to
# pure cylinder geometry. But let's model it.

# Model: Two half-cylinders joined at the middle.
# Each half-cylinder has circumference 31 (same column structure).
# The bottom half-cylinder's axis is ROTATED by angle φ relative to
# the top half's axis. This rotation creates differential occlusion.

# For simplicity: model the bend as an angular offset.
# At the junction, the front of the top half may block the front of
# the bottom half for certain light directions.

# For K4 specifically: the S-curve means the "front" of K4's cylinder
# segment faces a different direction than the "front" of K1K2's segment.

# Model: front of K4's segment faces direction φ_bottom.
# For each light angle θ:
#   - K4 positions on the front (within 90° of θ - φ_bottom) are visible
#   - K4 positions on the back are shadowed
#   - EXCEPT: some front positions may be occluded by the top half

# Scan different S-curve bend angles
print("Scanning S-curve bend angles and light directions...")
for bend_angle in range(0, 180, 5):
    # The bottom half faces direction = bend_angle (relative to absolute)
    # Top half faces direction = -bend_angle (opposite curve)

    for light_deg in range(0, 360, 5):
        # Effective light angle on the bottom half
        eff_light = (light_deg - bend_angle) % 360

        illuminated = set()
        for i, (r, c) in enumerate(K4_GRID):
            if is_front(c, eff_light):
                illuminated.add(i)

        # Occlusion: top half blocks some positions
        # The top half's front face (facing -bend_angle) occludes
        # bottom positions that are behind it from the light's perspective
        # This is a simplified model: if bend > 90°, the entire back of
        # the bottom half is doubly shadowed (no change to null set)
        # If bend < 90°, some front positions of bottom half are blocked

        if bend_angle > 0 and bend_angle < 180:
            # Compute which front columns of bottom half are blocked
            # by the top half. The top half extends from angle -bend_angle ± 90°.
            top_front_start = (-bend_angle - 90) % 360
            top_front_end = (-bend_angle + 90) % 360

            # A bottom front position at angle α is blocked if:
            # 1. It's on the same side as the top half's back
            # 2. The light direction is such that the top half casts shadow on it
            # Simplified: the occlusion zone is where the two cylinders overlap
            # in angular space

            # For the S-curve, the occlusion strip is centered at the
            # junction and affects columns near the bend direction
            occluded_angle_center = (light_deg + 180) % 360  # directly behind light
            occluded_width = bend_angle * 0.5  # wider bend = wider occlusion

            for i, (r, c) in enumerate(K4_GRID):
                col_angle = angular_pos(c)
                diff = (col_angle - occluded_angle_center + 180) % 360 - 180
                if abs(diff) < occluded_width and i in illuminated:
                    # Proportional to row distance from junction
                    # K4 rows 24-27, junction at row 14 → distance 10-13
                    row_dist = r - 14
                    if row_dist < bend_angle / 15:  # closer rows more affected
                        illuminated.discard(i)

        null_set = set(range(N)) - illuminated
        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            report(f"S-curve_bend={bend_angle}°,light={light_deg}°", null_set, sc, e, b, pt)

print(f"\nModel 4 best: {best_score}/24")
print()

# Special case: light from ENE (67.5°), which is the lodestone bearing
print("Special case: ENE light direction (67.5°)")
for bend in range(0, 180, 5):
    eff_light = (67.5 - bend) % 360
    illuminated = set()
    for i, (r, c) in enumerate(K4_GRID):
        if is_front(c, eff_light):
            illuminated.add(i)
    null_set = set(range(N)) - illuminated
    if len(null_set) == N_NULLS and is_valid_mask(null_set):
        sc, e, b, pt = eval_mask(null_set)
        report(f"ENE_bend={bend}°", null_set, sc, e, b, pt)
    # Also with wider/narrower front
    for arc_fraction in [0.6, 0.7, 0.8]:
        arc_cols = int(round(arc_fraction * 31))
        vis = set()
        for i, (r, c) in enumerate(K4_GRID):
            col_angle = angular_pos(c)
            diff = (col_angle - eff_light + 180) % 360 - 180
            if abs(diff) < 180 * arc_fraction:
                vis.add(i)
        ns = set(range(N)) - vis
        if len(ns) == N_NULLS and is_valid_mask(ns):
            sc, e, b, pt = eval_mask(ns)
            report(f"ENE_bend={bend}°_arc={arc_fraction}", ns, sc, e, b, pt)

print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 5: ANTIPODES — DIAMETRICALLY OPPOSITE POSITIONS
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 5: ANTIPODES — DIAMETRICALLY OPPOSITE POSITIONS")
print("=" * 80)
print()
print('"Antipodes" literally means diametrically opposite points.')
print("On a circumference-31 cylinder, the antipode of column c is")
print("column (c + 15) mod 31 or (c + 16) mod 31.")
print()

# Model 5a: For each K4 position, check if its antipodal position
# is also a K4 position. If so, one of the pair is a null.
print("Model 5a: Antipodal pairs within K4")
for offset in [15, 16]:
    print(f"\n  Offset = {offset}:")
    pairs = []
    for i, (r, c) in enumerate(K4_GRID):
        anti_col = (c + offset) % 31
        for j, (r2, c2) in enumerate(K4_GRID):
            if r2 == r and c2 == anti_col and i < j:
                pairs.append((i, j))
    print(f"  {len(pairs)} antipodal pairs found")
    for a, b in pairs:
        print(f"    K4[{a}] '{CT97[a]}' (col {K4_GRID[a][1]}) <-> K4[{b}] '{CT97[b]}' (col {K4_GRID[b][1]})")

    if len(pairs) > 0:
        # Try making one of each pair a null (2^n_pairs possibilities)
        # But with n_pairs potentially large, we need constraints
        n_pairs = len(pairs)
        paired_positions = set()
        for a, b in pairs:
            paired_positions.add(a)
            paired_positions.add(b)
        unpaired = set(range(N)) - paired_positions

        print(f"  {len(paired_positions)} positions in pairs, {len(unpaired)} unpaired")

        if n_pairs <= 20:
            count = 0
            for bits in range(1 << n_pairs):
                null_from_pairs = set()
                for pi, (a, b) in enumerate(pairs):
                    if bits & (1 << pi):
                        null_from_pairs.add(b)
                    else:
                        null_from_pairs.add(a)

                # Need exactly 24 nulls total
                remaining_needed = N_NULLS - len(null_from_pairs)
                if remaining_needed < 0:
                    continue
                if remaining_needed == 0:
                    null_set = null_from_pairs
                    if is_valid_mask(null_set):
                        sc, e, b_sc, pt = eval_mask(null_set)
                        count += 1
                        report(f"antipodal_off={offset}_bits={bits}", null_set, sc, e, b_sc, pt)
                # If remaining_needed > 0, we'd need to add more nulls from unpaired
                # Too many combinations; skip unless pairs get us close
            print(f"  Tested {count} valid masks from antipodal pairs")

# Model 5b: Antipodal column selection — keep only ONE of each
# antipodal column pair, across the full 31-column set.
# On a 31-col cylinder, antipodal pairs: (0,15), (0,16), (1,16), (1,17), etc.
# Since 31 is odd, there's no exact half-column offset.
print("\nModel 5b: Column-based antipodal selection")
for half_start in range(31):
    # "Front" = columns closest to half_start
    # Select 24 columns as "visible", rest as null
    for n_visible_cols in range(10, 25):
        visible_cols = set((half_start + i - n_visible_cols // 2) % 31 for i in range(n_visible_cols))
        null_set = set()
        for i, (r, c) in enumerate(K4_GRID):
            if c not in visible_cols:
                null_set.add(i)
        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            report(f"col_anti_start={half_start}_vis={n_visible_cols}", null_set, sc, e, b, pt)

print(f"\nModel 5 best: {best_score}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 6: ROW-DEPENDENT PROJECTION (HELICAL/SPIRAL)
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 6: HELICAL/SPIRAL PROJECTION")
print("=" * 80)
print()
print("Light source at an angle creates a HELICAL shadow pattern on the cylinder.")
print("Each row has a different shadow boundary due to vertical light angle.")
print()

# Model: light from direction (θ_h, θ_v) where:
# θ_h = horizontal angle (around cylinder)
# θ_v = vertical angle (elevation)
# The shadow boundary on each row shifts by an amount proportional to
# the row's vertical position.

# K4 rows (in 28-row grid): 24, 25, 26, 27
# Vertical position of each row (from bottom): 27-row_idx

for theta_h in range(0, 360, 5):
    for twist_rate in range(-20, 21):  # columns of shift per row
        # Twist rate: how many columns the shadow boundary shifts per row
        illuminated = set()
        for i, (r, c) in enumerate(K4_GRID):
            # Shadow boundary for this row
            boundary_shift = twist_rate * (r - K4_START_ROW) / 10.0
            eff_angle = (theta_h + boundary_shift * 360.0 / 31.0) % 360
            if is_front(c, eff_angle):
                illuminated.add(i)

        null_set = set(range(N)) - illuminated
        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            report(f"helix_θ={theta_h}°_twist={twist_rate}", null_set, sc, e, b, pt)

print(f"\nModel 6 best: {best_score}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 7: CONSENSUS NULL COMPARISON
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 7: CONSENSUS NULL COMPARISON")
print("=" * 80)
print()
print("Known consensus nulls from 15/24 masks:")
CONSENSUS_NULLS = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}
print(f"  17 consensus positions: {sorted(CONSENSUS_NULLS)}")
print()

# Map consensus nulls to grid positions
print("Consensus null grid positions:")
for pos in sorted(CONSENSUS_NULLS):
    r, c = K4_GRID[pos]
    print(f"  K4[{pos:2d}] = '{CT97[pos]}' at row {r}, col {c:2d}, "
          f"angular pos = {angular_pos(c):.1f}°")

print()

# Check if consensus nulls cluster on one side of the cylinder
cols_of_consensus = [K4_GRID[p][1] for p in CONSENSUS_NULLS]
print(f"Consensus null columns: {sorted(set(cols_of_consensus))}")
print(f"Number of distinct columns: {len(set(cols_of_consensus))}")
print(f"Column range: {min(cols_of_consensus)}-{max(cols_of_consensus)}")

# Angular analysis
angles = [angular_pos(c) for c in cols_of_consensus]
mean_angle = math.atan2(sum(math.sin(math.radians(a)) for a in angles),
                        sum(math.cos(math.radians(a)) for a in angles))
mean_angle_deg = math.degrees(mean_angle) % 360
print(f"Mean angular direction of consensus nulls: {mean_angle_deg:.1f}°")
print()

# Check angular spread
print("Angular histogram (30° bins):")
for bin_start in range(0, 360, 30):
    count = sum(1 for a in angles if bin_start <= a < bin_start + 30)
    bar = '█' * count
    print(f"  {bin_start:3d}°-{bin_start+29:3d}°: {count:2d} {bar}")

print()

# Do consensus nulls correspond to any light projection model?
print("Testing if consensus nulls match any simple projection model:")
# The non-consensus positions that need 7 more nulls from {38-45, 55-56, 87-88, 93-96}
VARIABLE_CLUSTERS = [{38,39,40,41,42,43,44,45}, {55,56}, {87,88}, {93,94,95,96}]
print(f"Variable clusters: {[sorted(c) for c in VARIABLE_CLUSTERS]}")

# Need exactly 7 more from these clusters. Enumerate.
from itertools import combinations

variable_pool = set()
for cl in VARIABLE_CLUSTERS:
    variable_pool |= cl

print(f"Variable pool: {sorted(variable_pool)} ({len(variable_pool)} positions)")
print(f"Need 7 more nulls from these {len(variable_pool)} positions")
n_combos = math.comb(len(variable_pool), 7)
print(f"Testing all {n_combos} combinations with col7 transposition...")
print()

model7_count = 0
model7_best = 0
for extra_nulls in combinations(sorted(variable_pool), 7):
    null_set = CONSENSUS_NULLS | set(extra_nulls)
    if is_valid_mask(null_set):
        sc, e, b, pt = eval_mask(null_set)
        if sc > model7_best:
            model7_best = sc
        if sc >= 7:
            model7_count += 1
            # Check if this mask has a geometric interpretation
            null_cols = [K4_GRID[p][1] for p in null_set]
            report(f"consensus+{extra_nulls}", null_set, sc, e, b, pt)

print(f"\nModel 7: {model7_count} masks scored >=7/24")
print(f"Model 7 best: {model7_best}/24")
print()

# Also test without transposition (identity perm)
print("Testing consensus+extras without transposition (identity perm)...")
model7b_best = 0
for extra_nulls in combinations(sorted(variable_pool), 7):
    null_set = CONSENSUS_NULLS | set(extra_nulls)
    if is_valid_mask(null_set):
        sc, e, b, pt = eval_mask(null_set, perm=IDENTITY_PERM)
        if sc > model7b_best:
            model7b_best = sc
        if sc >= 7:
            report(f"consensus+{extra_nulls}_noperm", null_set, sc, e, b, pt)

print(f"Model 7 (no perm) best: {model7b_best}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 8: COLUMN-PARITY ON CYLINDER
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 8: COLUMN-MODULAR PATTERNS ON CYLINDER")
print("=" * 80)
print()
print("Test modular patterns: null if col mod M == r, for various M and r.")
print("On a cylinder, this selects evenly-spaced 'stripes'.")
print()

for mod in range(2, 16):
    for remainder in range(mod):
        null_set = set()
        for i, (r, c) in enumerate(K4_GRID):
            if c % mod == remainder:
                null_set.add(i)
        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            report(f"col%{mod}=={remainder}", null_set, sc, e, b, pt)

# Also: combined row+col modular
for mod in range(2, 16):
    for remainder in range(mod):
        null_set = set()
        for i, (r, c) in enumerate(K4_GRID):
            if (r + c) % mod == remainder:
                null_set.add(i)
        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            report(f"(r+c)%{mod}=={remainder}", null_set, sc, e, b, pt)

# Diagonal stripes on cylinder
for mod in range(2, 16):
    for remainder in range(mod):
        for slope in range(1, mod):
            null_set = set()
            for i, (r, c) in enumerate(K4_GRID):
                if (r * slope + c) % mod == remainder:
                    null_set.add(i)
            if len(null_set) == N_NULLS and is_valid_mask(null_set):
                sc, e, b, pt = eval_mask(null_set)
                report(f"({slope}r+c)%{mod}=={remainder}", null_set, sc, e, b, pt)

print(f"\nModel 8 best: {best_score}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 9: POINT LIGHT SOURCE AT SPECIFIC POSITIONS
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 9: POINT LIGHT SOURCE (NON-PARALLEL)")
print("=" * 80)
print()
print("A point light source (not parallel beam) creates non-uniform shadows.")
print("The light could be at the compass rose, the pool, or other installation")
print("features. The shadow width varies by row on the cylinder.")
print()

# Model a point light at various positions around the cylinder.
# The distance from the light determines the shadow cone width.
# Closer = wider shadow, farther = narrower.

# Cylinder radius R = circumference / (2*pi) = 31 / (2*pi) ≈ 4.93 units
R = 31.0 / (2 * math.pi)

# Light positions: distance from cylinder center, angle
for dist_ratio in [1.5, 2.0, 3.0, 5.0, 10.0]:
    light_dist = R * dist_ratio
    for light_angle_deg in range(0, 360, 5):
        light_angle = math.radians(light_angle_deg)
        light_x = light_dist * math.cos(light_angle)
        light_y = light_dist * math.sin(light_angle)

        illuminated = set()
        for i, (r, c) in enumerate(K4_GRID):
            # Position on cylinder surface
            col_angle = math.radians(angular_pos(c))
            pt_x = R * math.cos(col_angle)
            pt_y = R * math.sin(col_angle)

            # Surface normal at this point
            nx = math.cos(col_angle)
            ny = math.sin(col_angle)

            # Direction from surface point to light
            dx = light_x - pt_x
            dy = light_y - pt_y
            d_len = math.sqrt(dx*dx + dy*dy)
            if d_len > 0:
                dx /= d_len
                dy /= d_len

            # Dot product of normal and light direction
            dot = nx * dx + ny * dy
            if dot > 0:  # Light hits the front of this point
                illuminated.add(i)

        null_set = set(range(N)) - illuminated
        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            report(f"point_d={dist_ratio}R_θ={light_angle_deg}°", null_set, sc, e, b, pt)

print(f"\nModel 9 best: {best_score}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 10: TIME-BASED SHADOW (SUNLIGHT)
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 10: TIME-BASED SUNLIGHT SHADOW")
print("=" * 80)
print()
print("Kryptos at CIA HQ, Langley VA. Latitude ~38.95°N.")
print("The sculpture is oriented with specific compass directions.")
print("Sun path varies by time and season. 'Between subtle shading")
print("and the absence of light' — could refer to a specific time.")
print()

# K2 mentions coordinates 38°57'6.5"N 77°8'44"W (near CIA HQ)
# The sculpture is oriented roughly NW-SE along its S-curve.
# Model the sun's position at different times.

# Solar angle at 38.95°N latitude
LAT = 38.95

# For simplicity, test several key times:
# - 20:00 (8 PM) — referenced in timer: "pump OFF + light ON = 20:00-24:00"
# - Solar noon (sun due south)
# - Sunrise/sunset

# Solar azimuth at different declinations (seasons)
# Summer solstice: declination = 23.44°
# Equinox: declination = 0°
# Winter solstice: declination = -23.44°

# Simplified solar position model
def solar_azimuth(hour_angle_deg, lat_deg, dec_deg):
    """Simplified solar azimuth calculation."""
    lat = math.radians(lat_deg)
    dec = math.radians(dec_deg)
    ha = math.radians(hour_angle_deg)

    alt = math.asin(math.sin(lat) * math.sin(dec) +
                    math.cos(lat) * math.cos(dec) * math.cos(ha))

    if math.cos(alt) == 0:
        return 180.0

    cos_az = (math.sin(dec) - math.sin(alt) * math.sin(lat)) / (math.cos(alt) * math.cos(lat))
    cos_az = max(-1, min(1, cos_az))
    az = math.degrees(math.acos(cos_az))

    if math.sin(ha) > 0:
        az = 360 - az

    return az

# The sculpture orientation: assume the cipher face points roughly ENE (67.5°)
# Sun angles relative to the cipher face determine shadows

SCULPTURE_FACING = 67.5  # ENE, matching lodestone direction

print("Testing solar shadow patterns at different times/seasons...")
for dec in [-23.44, 0, 23.44]:  # Winter, equinox, summer
    season = "winter" if dec < 0 else ("equinox" if dec == 0 else "summer")
    for hour_offset in range(-6, 7):  # -6h to +6h from noon
        hour_angle = hour_offset * 15  # 15° per hour
        try:
            az = solar_azimuth(hour_angle, LAT, dec)
        except:
            continue

        # Relative angle to sculpture face
        rel_angle = (az - SCULPTURE_FACING) % 360

        illuminated = set()
        for i, (r, c) in enumerate(K4_GRID):
            if is_front(c, rel_angle):
                illuminated.add(i)

        null_set = set(range(N)) - illuminated
        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            report(f"sun_{season}_h={hour_offset}_az={az:.0f}°", null_set, sc, e, b, pt)

print(f"\nModel 10 best: {best_score}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL 11: COMBINED — BEST GEOMETRIC MASKS WITH MULTIPLE KEYWORDS
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("MODEL 11: TESTING BEST GEOMETRIC MASKS WITH MULTIPLE KEYWORDS")
print("=" * 80)
print()

# Collect all masks that scored 5+ and re-test with different keywords
# But since we tracked best_results, let's test the consensus masks
# with additional keywords

KEYWORDS_TO_TEST = [
    ('DEFECTOR', True),   # AZ_beau (the 15/24 keyword)
    ('KRYPTOS', False),   # AZ_vig
    ('KOMPASS', True),    # AZ_beau
    ('COLOPHON', True),   # AZ_beau
    ('ABSCISSA', True),   # AZ_beau
    ('PALIMPSEST', True), # AZ_beau
]

def autokey_decrypt_az(ct_list, kw, beau=False):
    pt = []
    kw_n = [ord(c) - 65 for c in kw.upper()]
    L = len(kw_n)
    for i, ci in enumerate(ct_list):
        ki = kw_n[i] if i < L else ord(pt[i - L]) - 65
        if beau:
            pt.append(chr((ki - ci) % 26 + 65))
        else:
            pt.append(chr((ci - ki) % 26 + 65))
    return ''.join(pt)

def eval_mask_kw(null_set, kw, beau, perm):
    null_set = frozenset(null_set)
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c) - 65 for c in ct73_raw]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2
    ct73_t = [ct73_az[perm[i]] for i in range(N_PT)]
    pt = autokey_decrypt_az(ct73_t, kw, beau)
    total, e, b = count_crib_hits(pt, ene_s, bcl_s)
    return total, e, b, pt

# Test the known 15/24 mask to verify our setup
KNOWN_15_MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
verify_sc, verify_e, verify_b, verify_pt = eval_mask(KNOWN_15_MASK)
print(f"Verification of known 15/24 mask: {verify_sc}/24 (e={verify_e}/13, b={verify_b}/11)")
assert verify_sc == 15, f"VERIFICATION FAILED: got {verify_sc}"
print("VERIFIED.")
print()

# Now test geometric masks with all keywords
print("Testing consensus + variable combinations with all keywords...")
for extra_nulls in combinations(sorted(variable_pool), 7):
    null_set = CONSENSUS_NULLS | set(extra_nulls)
    if is_valid_mask(null_set):
        for kw, beau in KEYWORDS_TO_TEST:
            sc, e, b, pt = eval_mask_kw(null_set, kw, beau, PERM_COL7)
            if sc >= 7:
                report(f"{kw}:{'beau' if beau else 'vig'}+col7 cons+{extra_nulls}",
                       null_set, sc, e, b, pt)
            # Also without transposition
            sc2, e2, b2, pt2 = eval_mask_kw(null_set, kw, beau, IDENTITY_PERM)
            if sc2 >= 7:
                report(f"{kw}:{'beau' if beau else 'vig'} (no trans) cons+{extra_nulls}",
                       null_set, sc2, e2, b2, pt2)

print()

# ══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("FINAL SUMMARY")
print("=" * 80)
print(f"\nOverall best score: {best_score}/24")
print(f"Number of results at best score: {len(best_results)}")
print()
if best_results:
    for label, sc, e, b, nulls, pt in best_results[:10]:
        print(f"  {label}: {sc}/24 (e={e}/13, b={b}/11)")
        print(f"    nulls={nulls}")
        if pt:
            print(f"    PT={pt[:70]}")
        print()

# Geometric analysis of best masks
if best_results and best_score >= 7:
    print("Geometric analysis of best masks:")
    for label, sc, e, b, nulls, pt in best_results[:5]:
        cols = [K4_GRID[p][1] for p in nulls]
        print(f"\n  {label}:")
        print(f"    Null columns: {cols}")
        print(f"    Distinct columns: {sorted(set(cols))}")
        # Check angular clustering
        angles = [angular_pos(c) for c in cols]
        mean_a = math.atan2(sum(math.sin(math.radians(a)) for a in angles),
                           sum(math.cos(math.radians(a)) for a in angles))
        mean_a_deg = math.degrees(mean_a) % 360
        print(f"    Mean angle of nulls: {mean_a_deg:.1f}°")
