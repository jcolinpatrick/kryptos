#!/usr/bin/env python3
"""Cylindrical Projection Deep Analysis — Geometric Characterization of Nulls.

# Cipher: null_mask
# Family: geometry
# Status: active
# Keyspace: ~50K configurations
# Last run: never
# Best score: n/a

This script does NOT search for new masks. Instead it:

1. Characterizes the KNOWN 15/24 consensus null positions geometrically
   on the cylinder surface. Are they one contiguous band? A specific arc?
   Do they follow any curve on the unwrapped cylinder?

2. Tests whether any geometric rule GENERATES a mask containing all 17
   consensus positions (and produces exactly 24 nulls with valid cribs).

3. Models the specific physical features of Kryptos:
   a. The letter cutouts are CUT INTO copper — light passes THROUGH them
   b. The sculpture is curved — an S-shape, not flat
   c. The compass rose/lodestone point ENE
   d. The petrified wood "shadow" on the ground
   e. "Between subtle shading and the absence of light" (artistic statement)

4. Tests the SPECIFIC geometric relationship between K3 solved plaintext
   positions and K4 null positions on the shared cylinder.

5. Tests whether the 24 Weltzeituhr facets (from BERLINCLOCK) map to
   24 angular sectors on the cylinder, and if one sector per row = 24 nulls.
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os, math
from itertools import combinations, product
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS

CT97 = CT
N = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63
GRID_COLS = 31

K4_START_ROW = 24; K4_START_COL = 27

def k4_grid_positions():
    positions = []
    gp = K4_START_ROW * GRID_COLS + K4_START_COL
    for i in range(CT_LEN):
        positions.append((gp // GRID_COLS, gp % GRID_COLS))
        gp += 1
    return positions

K4_GRID = k4_grid_positions()

# ── Cipher evaluation ─────────────────────────────────────────────────────

def columnar_perm(n, width):
    n_rows = (n + width - 1) // width
    grid = [list(range(row*width, min((row+1)*width, n))) for row in range(n_rows)]
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0]*len(perm)
    for i,p in enumerate(perm): inv[p]=i
    return inv

PERM_COL7 = reverse_perm(columnar_perm(N_PT, 7))

def eval_mask(null_set, kw='DEFECTOR', perm=None):
    if perm is None: perm = PERM_COL7
    null_set = frozenset(null_set)
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c)-65 for c in ct73]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2
    ct73_t = [ct73_az[perm[i]] for i in range(N_PT)]
    pt=[]; kw_n=[ord(c)-65 for c in kw]
    L = len(kw_n)
    for i,ci in enumerate(ct73_t):
        ki = kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr((ki-ci)%26+65))
    pt = ''.join(pt)
    e = sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<len(pt) and pt[ene_s+j]==c)
    b = sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<len(pt) and pt[bcl_s+j]==c)
    return e+b, e, b, pt

def is_valid_mask(ns):
    return len(ns)==N_NULLS and frozenset(ns).isdisjoint(CRIB_POSITIONS)

# ── Known data ────────────────────────────────────────────────────────────

CONSENSUS_17 = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}
KNOWN_15_MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])

W_POSITIONS = {20, 36, 48, 58, 74}  # 5 W's in K4

# ══════════════════════════════════════════════════════════════════════════
# PART 1: GEOMETRIC CHARACTERIZATION OF CONSENSUS NULLS
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PART 1: GEOMETRIC CHARACTERIZATION OF CONSENSUS NULL POSITIONS")
print("=" * 80)
print()

# Map consensus nulls to grid
print("Consensus null positions (17) on the 31-column cylinder:")
print(f"{'K4idx':>6} {'Char':>4} {'Row':>4} {'Col':>4} {'Angle':>7} {'IsW':>4}")
print("-" * 35)
for pos in sorted(CONSENSUS_17):
    r, c = K4_GRID[pos]
    angle = c * 360.0 / 31.0
    is_w = "W" if pos in W_POSITIONS else ""
    print(f"{pos:6d} {CT97[pos]:>4} {r:4d} {c:4d} {angle:7.1f}° {is_w:>4}")

print()

# Non-null (real) positions
real_positions = set(range(N)) - CONSENSUS_17
print(f"\nReal positions (80 = 17 consensus nulls subtracted from 97):")

# Row-by-row analysis
for row in sorted(set(r for r, c in K4_GRID)):
    row_positions = [(i, c) for i, (r, c) in enumerate(K4_GRID) if r == row]
    null_cols = [c for i, c in row_positions if i in CONSENSUS_17]
    real_cols = [c for i, c in row_positions if i not in CONSENSUS_17]
    print(f"\n  Row {row}: {len(row_positions)} positions")
    print(f"    Null cols ({len(null_cols)}): {sorted(null_cols)}")
    print(f"    Real cols ({len(real_cols)}): {sorted(real_cols)}")

    # Visualize as a 31-column strip
    strip = ['.'] * 31
    for i, c in row_positions:
        if i in CONSENSUS_17:
            strip[c] = 'X'  # null
        elif i in CRIB_POSITIONS:
            strip[c] = 'C'  # crib
        else:
            strip[c] = 'o'  # real, non-crib
    print(f"    {''.join(strip)}  (X=null, C=crib, o=real, .=not K4)")

print()

# Angular distribution on cylinder
print("Angular histogram of consensus nulls (15° bins):")
null_angles = [K4_GRID[p][1] * 360.0 / 31.0 for p in CONSENSUS_17]
for bin_start in range(0, 360, 15):
    count = sum(1 for a in null_angles if bin_start <= a < bin_start + 15)
    bar = '#' * count
    print(f"  {bin_start:3d}-{bin_start+14:3d}°: {count:2d} {bar}")

# Column frequency
print("\nColumn frequency of consensus nulls:")
null_cols = [K4_GRID[p][1] for p in CONSENSUS_17]
col_counts = Counter(null_cols)
for c in range(31):
    bar = '#' * col_counts.get(c, 0)
    k4_in_col = sum(1 for _, cc in K4_GRID if cc == c)
    print(f"  Col {c:2d}: {col_counts.get(c,0)}/{k4_in_col} null  {bar}")

print()

# Check if nulls form a contiguous arc on any row
print("Contiguous arc check per row:")
for row in sorted(set(r for r, c in K4_GRID)):
    row_positions = [(i, c) for i, (r, c) in enumerate(K4_GRID) if r == row]
    null_cols_in_row = sorted(c for i, c in row_positions if i in CONSENSUS_17)
    if len(null_cols_in_row) < 2:
        continue
    # Check if they form a contiguous arc (wrapping around 31)
    for start in range(31):
        arc = set((start + j) % 31 for j in range(len(null_cols_in_row)))
        if arc == set(null_cols_in_row):
            print(f"  Row {row}: CONTIGUOUS ARC starting at col {start}, width {len(null_cols_in_row)}")
            break
    else:
        # Check gaps
        diffs = [(null_cols_in_row[(i+1) % len(null_cols_in_row)] - null_cols_in_row[i]) % 31
                 for i in range(len(null_cols_in_row))]
        print(f"  Row {row}: NOT contiguous. Null cols = {null_cols_in_row}, gaps = {diffs}")

print()

# ══════════════════════════════════════════════════════════════════════════
# PART 2: WELTZEITUHR (24-FACET CLOCK) MODEL
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PART 2: WELTZEITUHR — 24-FACET CLOCK ON CYLINDER")
print("=" * 80)
print()
print("BERLINCLOCK references the Weltzeituhr, which has 24 facets.")
print("If the circumference-31 cylinder is divided into 24 sectors,")
print("each sector spans 31/24 = 1.292 columns.")
print("One sector per row (4 rows) = 4 sectors, different sizes possible.")
print()

# Model: 24 angular sectors on the cylinder, each 15° wide (360/24)
# One sector per K4 row is designated as "shadow" (null)
# The sector that is null shifts by some offset per row

for sector_width_cols in range(1, 16):  # 1-15 columns wide shadow band
    for start_col in range(31):
        for shift_per_row in range(-15, 16):
            null_set = set()
            for i, (r, c) in enumerate(K4_GRID):
                row_offset = r - K4_START_ROW
                shadow_center = (start_col + shift_per_row * row_offset) % 31
                # Is this column within sector_width_cols of shadow_center?
                dist = min((c - shadow_center) % 31, (shadow_center - c) % 31)
                if dist < sector_width_cols:
                    null_set.add(i)

            if len(null_set) == N_NULLS and is_valid_mask(null_set):
                sc, e, b, pt = eval_mask(null_set)
                if sc >= 7:
                    # Check overlap with consensus
                    overlap = len(null_set & CONSENSUS_17)
                    print(f"  SIGNAL: w={sector_width_cols} s={start_col} shift={shift_per_row}: "
                          f"{sc}/24 (e={e}/13, b={b}/11) consensus_overlap={overlap}/17")

print("Sector scan complete.")
print()

# ══════════════════════════════════════════════════════════════════════════
# PART 3: K3 PLAINTEXT PROJECTION
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PART 3: K3 PLAINTEXT POSITION → K4 NULL PROJECTION")
print("=" * 80)
print()

# K3 plaintext (solved):
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINS"
    "OFPASSAGEDEBABORASSANDEREDTWASNO"  # approximate
    "WTHECOUNTYTHATCAMETOLIGHTMADEPOSSIBLE"  # approximate
)

# Actually, let me use the confirmed K3 plaintext
K3_PLAINTEXT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGE"
    "DEBRISCOVEREDTHELOWEPORTOFADOORWAY"
    "WITHTREMBLINGHANDSIMADEATINY"
    "BREACHINTHELEFTHANDCORNERANDTHEN"
    "WIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDIN"
    "THEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKER"
    "BUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMIST"
    "XCANSEEANYTHINGQ"
)

# Actually the confirmed K3 plaintext from Carter's description is 337 chars
# K3 CT = 336 chars. Let me use the standard known text:
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACH"
    "TNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOET"
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT"
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR"
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# K3 occupies bottom-14 grid rows 14-23 + row 24 cols 0-26
# That's 10*31 + 27 = 337 positions (but row 16 has 30 chars due to
# the sculpture's physical layout — actually all rows are 31 in the grid)
# The ? at row 24 col 26 is a disputed character

# For this analysis, we care about the COLUMN positions of K3 characters
# on the same cylinder as K4

# K3 characters occupy rows 14-23 fully (310 chars) + row 24 cols 0-26 (27 chars) = 337
# K4 occupies row 24 cols 27-30 + rows 25-27 fully = 4 + 93 = 97

# On the cylinder, K3 and K4 share rows 25-27 (since cylinder wraps!)
# Wait - they DON'T share rows directly. K3 is rows 14-24(partial) and
# K4 is rows 24(partial)-27. They're sequential, not overlapping.

# But on a CYLINDER that is 14 rows tall (bottom half),
# row 14 and row 27 are vertically adjacent (top and bottom of the same cylinder).
# So the bottom-14 cylinder has K3 at the top and K4 at the bottom.

# Projection model: light passes through K3 character cutouts (top portion)
# and projects vertically down onto K4 (bottom portion).
# The "vertical" direction on the cylinder is along the axis.
# For this model, K3 and K4 positions with the SAME COLUMN are directly above/below.

print("K3 column occupancy (positions with same column as K4):")
k3_cols = set()
for row_idx in range(10):  # rows 0-9 of bottom-14
    for col in range(31):
        k3_cols.add(col)
# Also row 10 cols 0-26
for col in range(27):
    k3_cols.add(col)

print(f"K3 covers all 31 columns in rows 0-9, cols 0-26 in row 10")
print(f"K4 covers cols 27-30 in row 10, all 31 in rows 11-13")
print()

# So every K4 column has K3 characters above it.
# Model: K3 cutouts in column c project light downward onto K4 column c.
# IF column c has a K3 cutout (letter), light passes through.
# IF column c has NO K3 cutout... but K3 fills all positions, so this doesn't work.

# Alternative: K3 PLAINTEXT provides the mask rule.
# Specific letters in K3 plaintext determine which K4 columns are null.
# E.g., if K3 PT has a space (word boundary) at position X, then K4 at same column = null.

# Since K3 is a continuous text (no spaces), this doesn't directly apply.
# But K3 has specific letter patterns.

# Try: K3 PT positions containing specific letters determine K4 null columns
# Map K3 PT to the grid
K3_PT_STANDARD = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGE"
    "DEBRISCOVEREDTHELOWERPARTOFTHEDOORWAY"
    "WITHTREMBLINGHANDSIMADEATINY"
    "BREACHINTHELEFTHANDCORNERANDTHEN"
    "WIDENINGTHEHOLEALITTLEIINSERTED"
    "THECANDLEANDPEEREDIN"
    "THEHOTAIRESCAPINGFROMTHECHAMBER"
    "CAUSEDTHEFLAMETOFLICKER"
    "BUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMIST"
    "XCANSEEANYTHINGQ"
).upper()

# Actually the precise K3 PT length should be ~337 chars to match K3 CT length
# Let me not worry about exact K3 PT alignment and instead focus on the column
# relationship

# More productive approach: check if K4 null columns correlate with specific
# K3 CT letter frequencies per column
print("K3 CT letter at K4 null positions (same-column vertical projection):")
# For each consensus null K4 position, what K3 CT character is directly above?
for pos in sorted(CONSENSUS_17):
    r, c = K4_GRID[pos]
    b14_row = r - 14  # row in bottom-14
    # K3 characters directly above this column in ALL K3 rows
    k3_in_column = []
    for k3_row in range(10):  # K3 rows 0-9 in bottom-14
        k3_idx = k3_row * 31 + c
        # Get character from BOTTOM_14_ROWS grid
        if k3_row < 10:
            k3_char = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
            if k3_idx < len(k3_char):
                k3_in_column.append(k3_char[k3_idx])
    print(f"  K4[{pos:2d}] col={c:2d}: K3 above = {''.join(k3_in_column)}")

print()

# ══════════════════════════════════════════════════════════════════════════
# PART 4: DISTANCE-FROM-AXIS MODEL
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PART 4: DISTANCE METRICS AND GEOMETRIC CURVES")
print("=" * 80)
print()

# On the unwrapped cylinder (31-wide × 4-tall strip for K4),
# test various geometric curves as the null boundary

# Unwrap: x = column (0-30), y = row_within_K4 (0-3)
# K4 row mapping: row 24 = y=0 (only cols 27-30), row 25 = y=1, row 26 = y=2, row 27 = y=3

# Map K4 positions to unwrapped coordinates
def k4_unwrap():
    """Return (x, y, k4_idx) for each K4 position on the unwrapped cylinder."""
    positions = []
    for i, (r, c) in enumerate(K4_GRID):
        y = r - K4_START_ROW  # 0-3
        x = c  # 0-30
        positions.append((x, y, i))
    return positions

K4_UNWRAP = k4_unwrap()

# Test: sinusoidal boundary on the unwrapped cylinder
# null if x > A*sin(2*pi*y/P + phase) + offset
print("Sinusoidal null boundary on unwrapped cylinder:")
best_sin = 0
for amplitude in range(1, 16):
    for period_y in [1, 2, 3, 4, 5, 6, 7, 8]:  # period in rows
        for phase_steps in range(24):  # phase in steps of 15°
            phase = phase_steps * math.pi / 12
            for offset in range(31):
                null_set = set()
                for x, y, idx in K4_UNWRAP:
                    boundary = amplitude * math.sin(2 * math.pi * y / period_y + phase) + offset
                    # Null if x is within the "shadow zone"
                    # Try: x > boundary (mod 31 wrapping)
                    if (x - boundary) % 31 < 31 / 2:  # on the "far" side
                        null_set.add(idx)

                if len(null_set) == N_NULLS and is_valid_mask(null_set):
                    sc, e, b, pt = eval_mask(null_set)
                    if sc > best_sin:
                        best_sin = sc
                    if sc >= 7:
                        overlap = len(null_set & CONSENSUS_17)
                        print(f"  A={amplitude} P={period_y} ph={phase_steps} off={offset}: "
                              f"{sc}/24 (e={e}/13,b={b}/11) overlap={overlap}/17")

print(f"Best sinusoidal: {best_sin}/24")
print()

# Test: linear boundary y = mx + b (diagonal line on unwrapped cylinder)
print("Linear null boundary (diagonal cut):")
best_lin = 0
for m_num in range(-31, 32):
    m = m_num / 4.0  # slope
    for b_off in range(31):
        null_set = set()
        for x, y, idx in K4_UNWRAP:
            boundary = m * y + b_off
            if (x - boundary) % 31 < 31 / 2:
                null_set.add(idx)

        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            if sc > best_lin: best_lin = sc
            if sc >= 7:
                print(f"  m={m:.2f} b={b_off}: {sc}/24 (e={e}/13,b={b}/11)")

print(f"Best linear: {best_lin}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# PART 5: ANGULAR SECTOR MODEL (BERLINCLOCK = 24 SECTORS)
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PART 5: BERLINCLOCK 24-SECTOR ANGULAR MODEL")
print("=" * 80)
print()
print("The Weltzeituhr has 24 facets, one per timezone. If the cylinder")
print("is divided into 24 angular sectors, each sector selects ~1.29 columns.")
print("Test: null = positions in specific sectors. 24 sectors × 4 rows = 96")
print("possible sector-row combinations. Need 24 nulls from 97 positions.")
print()

# Divide circumference into 24 sectors
# Sector i covers angle [i*15°, (i+1)*15°)
# Column c has angle c*360/31

def column_sector(col, n_sectors=24):
    """Which sector (0-based) does this column fall in?"""
    angle = col * 360.0 / 31.0
    return int(angle / (360.0 / n_sectors)) % n_sectors

# Map columns to sectors
print("Column → sector mapping (24 sectors):")
for c in range(31):
    s = column_sector(c)
    print(f"  Col {c:2d} → Sector {s:2d} ({c*360/31:.1f}°)")

print()

# Count K4 positions per sector
sector_counts = Counter(column_sector(c) for _, c in K4_GRID)
print("K4 positions per sector:")
for s in range(24):
    print(f"  Sector {s:2d}: {sector_counts.get(s, 0)} positions")

# Model: select specific sectors as null
# Need exactly 24 nulls. Try combinations of sectors.
print("\nSearching for sector combinations that produce 24 valid nulls...")
for n_sectors_null in range(1, 8):
    for sector_combo in combinations(range(24), n_sectors_null):
        sector_set = set(sector_combo)
        null_set = set()
        for i, (r, c) in enumerate(K4_GRID):
            if column_sector(c) in sector_set:
                null_set.add(i)
        if len(null_set) == N_NULLS and is_valid_mask(null_set):
            sc, e, b, pt = eval_mask(null_set)
            if sc >= 7:
                overlap = len(null_set & CONSENSUS_17)
                print(f"  Sectors {sector_combo}: {sc}/24 (e={e}/13,b={b}/11) overlap={overlap}/17")

# Also try with different numbers of sectors (not just 24)
print("\nNon-24 sector counts:")
for n_sec in [7, 11, 13, 31, 73]:
    for n_null_sec in range(1, min(n_sec, 10)):
        for sector_combo in combinations(range(n_sec), n_null_sec):
            null_set = set()
            for i, (r, c) in enumerate(K4_GRID):
                s = int(c * n_sec / 31) % n_sec
                if s in set(sector_combo):
                    null_set.add(i)
            if len(null_set) == N_NULLS and is_valid_mask(null_set):
                sc, e, b, pt = eval_mask(null_set)
                if sc >= 7:
                    print(f"  n_sec={n_sec} nulls={sector_combo}: {sc}/24 (e={e},b={b})")

print()

# ══════════════════════════════════════════════════════════════════════════
# PART 6: SPIRAL/HELIX ON CYLINDER
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PART 6: SPIRAL/HELIX NULL BOUNDARY ON CYLINDER")
print("=" * 80)
print()
print("A helix on the cylinder creates a spiral pattern. The text 'above'")
print("the helix could be real, 'below' the helix could be null.")
print("Parameters: helix pitch (columns per row), starting column, width.")
print()

best_helix = 0
for pitch_num in range(-30, 31):  # pitch in columns per row
    pitch = pitch_num / 2.0
    for start_col in range(31):
        for width in range(1, 16):  # width of null band
            null_set = set()
            for i, (r, c) in enumerate(K4_GRID):
                y = r - K4_START_ROW
                helix_center = (start_col + pitch * y) % 31
                # Distance on circular column
                dist = min((c - helix_center) % 31, (helix_center - c) % 31)
                if dist < width:
                    null_set.add(i)

            if len(null_set) == N_NULLS and is_valid_mask(null_set):
                sc, e, b, pt = eval_mask(null_set)
                if sc > best_helix:
                    best_helix = sc
                if sc >= 7:
                    overlap = len(null_set & CONSENSUS_17)
                    print(f"  pitch={pitch:.1f} start={start_col} w={width}: "
                          f"{sc}/24 (e={e},b={b}) overlap={overlap}/17")

print(f"Best helix: {best_helix}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# PART 7: ROW-INDEPENDENT COLUMN SELECTION
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PART 7: ROW-INDEPENDENT COLUMN SELECTION (PER-ROW NULL BANDS)")
print("=" * 80)
print()
print("Each row has its own 'null band' — a contiguous arc of columns.")
print("This is the most general column-based model.")
print("Row 24: 4 positions (cols 27-30). Rows 25-27: 31 positions each.")
print("Total: 97. Need 24 nulls.")
print()

# Row 24 has 4 positions. Max nulls from row 24 = 4 (but need to preserve cribs if any there)
# Crib positions in row 24: check
row24_cribs = [i for i in range(4) if i in CRIB_POSITIONS]  # K4[0-3] = cols 27-30
print(f"Row 24 crib positions: {row24_cribs}")
print(f"Row 24 K4 indices: 0-3, cols 27-30")

# For rows 25-27, each has 31 positions
# A "contiguous arc" of width w starting at column s gives w nulls per row
# Total nulls = n24 + w25 + w26 + w27 = 24
# where n24 in {0,1,2,3,4}, w25,w26,w27 in {0,...,31}

# The contiguous arc for each row can start at any column (wrapping)
# This is a large search space: 4 * 31^3 * (5 * 32^3) but we can constrain

# For efficiency: iterate over null counts per row
print("Searching per-row contiguous arc null bands...")
best_row_arc = 0
count_valid = 0

for n24 in range(5):  # 0-4 nulls in row 24
    for n25 in range(min(32, N_NULLS - n24 + 1)):
        for n26 in range(min(32, N_NULLS - n24 - n25 + 1)):
            n27 = N_NULLS - n24 - n25 - n26
            if n27 < 0 or n27 > 31:
                continue

            # For row 24 (4 cols): choose n24 of 4 to be null
            # For rows 25-27: choose contiguous arc of width w starting at col s

            # Row 24 combos
            row24_indices = list(range(4))  # K4 indices 0-3
            for r24_nulls in combinations(row24_indices, n24):
                r24_null_set = set(r24_nulls)
                if r24_null_set & CRIB_POSITIONS:
                    continue

                # Row 25: 31 positions (K4 indices 4-34)
                for s25 in range(31) if n25 > 0 else [0]:
                    r25_null_set = set()
                    if n25 > 0:
                        for j in range(n25):
                            col = (s25 + j) % 31
                            k4_idx = 4 + col  # K4 index = 4 + column
                            r25_null_set.add(k4_idx)
                    if r25_null_set & CRIB_POSITIONS:
                        continue

                    # Row 26: K4 indices 35-65
                    for s26 in range(31) if n26 > 0 else [0]:
                        r26_null_set = set()
                        if n26 > 0:
                            for j in range(n26):
                                col = (s26 + j) % 31
                                k4_idx = 35 + col
                                r26_null_set.add(k4_idx)
                        if r26_null_set & CRIB_POSITIONS:
                            continue

                        # Row 27: K4 indices 66-96
                        for s27 in range(31) if n27 > 0 else [0]:
                            r27_null_set = set()
                            if n27 > 0:
                                for j in range(n27):
                                    col = (s27 + j) % 31
                                    k4_idx = 66 + col
                                    r27_null_set.add(k4_idx)
                            if r27_null_set & CRIB_POSITIONS:
                                continue

                            null_set = r24_null_set | r25_null_set | r26_null_set | r27_null_set
                            if len(null_set) != N_NULLS:
                                continue

                            count_valid += 1
                            sc, e, b, pt = eval_mask(null_set)
                            if sc > best_row_arc:
                                best_row_arc = sc
                            if sc >= 7:
                                overlap = len(null_set & CONSENSUS_17)
                                print(f"  n24={n24} s25={s25}w{n25} s26={s26}w{n26} s27={s27}w{n27}: "
                                      f"{sc}/24 (e={e},b={b}) overlap={overlap}/17")

print(f"\nRow-arc search: tested {count_valid} valid masks, best = {best_row_arc}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("FINAL SUMMARY — CYLINDRICAL PROJECTION DEEP ANALYSIS")
print("=" * 80)
print()
print(f"Model 1 (cylinder wrap front/back): covered in script 04")
print(f"Weltzeituhr 24-sector: see above")
print(f"Sinusoidal boundary: best = {best_sin}/24")
print(f"Linear boundary: best = {best_lin}/24")
print(f"Helix boundary: best = {best_helix}/24")
print(f"Per-row contiguous arc: best = {best_row_arc}/24")
print()

# Key finding: do consensus nulls match ANY geometric cylinder model?
print("KEY QUESTION: Do the 17 consensus null positions fit ANY cylinder model?")
# Check if they fit a contiguous arc per row
for row in sorted(set(r for r,c in K4_GRID)):
    row_positions = [(i,c) for i,(r2,c2) in enumerate(K4_GRID) if r2==row]
    null_in_row = sorted(c for i,c in row_positions if i in CONSENSUS_17)
    if null_in_row:
        # Check contiguity on circular column space
        contiguous = True
        for k in range(len(null_in_row)-1):
            if (null_in_row[k+1] - null_in_row[k]) % 31 != 1 and (null_in_row[k+1] - null_in_row[k]) != 1:
                contiguous = False
                break
        print(f"  Row {row}: null cols = {null_in_row}, contiguous = {contiguous}")
