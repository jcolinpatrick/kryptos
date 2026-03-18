#!/usr/bin/env python3
"""Cylindrical Projection — Physical Letter Cutout Model.

# Cipher: null_mask
# Family: geometry
# Status: active
# Keyspace: ~5K configurations
# Last run: never
# Best score: n/a

Models the ACTUAL physical behavior of light through letter-shaped cutouts:

1. Letters are CUT OUT of copper. Light passes through the HOLES.
2. On a curved surface, light through a cutout on one side illuminates
   a specific area on the OPPOSITE side (not just the diametrically
   opposite point — the projection spreads/contracts due to curvature).
3. Sanborn is a LIGHT PROJECTION artist. His other works project text
   through objects. The sculpture's key insight may be that light through
   K4's own letters projects a SUBSET of letters onto a nearby surface.
4. The Morse code copper plate BEHIND the S-screen is another layer
   through which light must pass.

KEY PHYSICAL INSIGHT: On an S-shaped screen, only certain letters have
"line of sight" through both curves of the S. The letters that CAN be
seen straight through the S-curve are the "real" ones; the others
(blocked by one of the S-curves) are the "nulls."

Also: the letter cutouts on the FRONT of the copper sheet project onto
the GROUND as shadows. "The petrified wood creates a shadow." The
shadow pattern on a specific date/time could select 73 of 97 letters.
"""

import sys, os, math
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS

CT97 = CT; N = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63; GRID_COLS = 31
K4_START_ROW = 24; K4_START_COL = 27
CONSENSUS_17 = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}

def k4_grid_positions():
    positions = []
    gp = K4_START_ROW * GRID_COLS + K4_START_COL
    for i in range(CT_LEN):
        positions.append((gp // GRID_COLS, gp % GRID_COLS))
        gp += 1
    return positions

K4_GRID = k4_grid_positions()

def columnar_perm(n, width):
    nr = (n+width-1)//width
    grid = [list(range(r*width,min((r+1)*width,n))) for r in range(nr)]
    perm = []
    for c in range(width):
        for r in range(nr):
            if c<len(grid[r]):
                perm.append(grid[r][c])
    return perm

def reverse_perm(p):
    inv=[0]*len(p)
    for i,v in enumerate(p): inv[v]=i
    return inv

PERM_COL7 = reverse_perm(columnar_perm(N_PT,7))
IDENTITY = list(range(N_PT))

def eval_mask(null_set, kw='DEFECTOR', perm=None):
    if perm is None: perm=PERM_COL7
    ns = frozenset(null_set)
    ct73 = ''.join(CT97[i] for i in range(N) if i not in ns)
    ct73_az = [ord(c)-65 for c in ct73]
    n1 = sum(1 for p in ns if p<ENE_START)
    n2 = sum(1 for p in ns if p<BCL_START)
    es = ENE_START-n1; bs = BCL_START-n2
    ct73_t = [ct73_az[perm[i]] for i in range(N_PT)]
    pt=[]; kn=[ord(c)-65 for c in kw]; L=len(kn)
    for i,ci in enumerate(ct73_t):
        ki=kn[i] if i<L else ord(pt[i-L])-65
        pt.append(chr((ki-ci)%26+65))
    pt=''.join(pt)
    e=sum(1 for j,c in enumerate(ENE_WORD) if es+j<len(pt) and pt[es+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bs+j<len(pt) and pt[bs+j]==c)
    return e+b,e,b,pt

def valid(ns): return len(ns)==N_NULLS and frozenset(ns).isdisjoint(CRIB_POSITIONS)

# ══════════════════════════════════════════════════════════════════════════
# MODEL A: S-CURVE LINE-OF-SIGHT
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("MODEL A: S-CURVE LINE-OF-SIGHT THROUGH BOTH CURVES")
print("="*80)
print()
print("The S-shaped screen has an inflection point in the middle.")
print("Model: two semicircles joined at the inflection, curving opposite ways.")
print("For a viewer at angle theta, each position on the screen either has")
print("'line of sight' through both curves, or is blocked by one curve.")
print()

# Physical model of the S-curve:
# Think of the S as seen from above (bird's eye). It's a curve in the
# horizontal plane. The "screen" is vertical.
#
# Approximate the S-curve profile as a sinusoidal displacement:
# The screen's x-position (depth from viewer) varies with column position:
#   depth(col) = A * sin(2*pi*col/31 + phase)
# where A is the amplitude of the S-curve and phase determines orientation.
#
# For S-shape with two bends: use a single full sinusoidal cycle
# (one forward bump, one backward bump across the 31 columns).

# A position is "visible" from direction theta if:
# 1. Its surface normal has a component toward the viewer
# 2. No other part of the S-curve blocks the line of sight

# Model the S-curve as a parametric curve
# t goes from 0 to 1 (left to right)
# x(t) = amplitude * sin(2*pi*t + phase)  [depth]
# y(t) = t * width  [horizontal position]
# Each "column" c corresponds to t = c/31

def s_curve_profile(n_cols, amplitude, phase=0):
    """Return (x, y) for each column position on the S-curve."""
    positions = []
    for c in range(n_cols):
        t = c / n_cols
        x = amplitude * math.sin(2 * math.pi * t + phase)
        y = t
        positions.append((x, y))
    return positions

def s_curve_normals(profile):
    """Surface normals for each position on the S-curve."""
    normals = []
    n = len(profile)
    for i in range(n):
        # Tangent = derivative of profile
        ip = (i + 1) % n
        im = (i - 1) % n
        dx = profile[ip][0] - profile[im][0]
        dy = profile[ip][1] - profile[im][1]
        # Normal is perpendicular to tangent, pointing "outward"
        # (right-hand rule: rotate 90° clockwise)
        length = math.sqrt(dx*dx + dy*dy)
        if length > 0:
            nx = dy / length
            ny = -dx / length
        else:
            nx, ny = 1, 0
        normals.append((nx, ny))
    return normals

def is_visible_on_scurve(col, profile, normals, viewer_dir):
    """Is position 'col' visible from direction 'viewer_dir'?
    viewer_dir = (vx, vy) unit vector pointing FROM viewer TO screen.
    Position is visible if:
    1. Normal faces toward viewer (dot product with -viewer_dir > 0)
    2. No intervening part of the curve blocks the line of sight.
    """
    vx, vy = viewer_dir
    nx, ny = normals[col]

    # Face check: normal must face toward viewer
    if nx * (-vx) + ny * (-vy) <= 0:
        return False

    # Line-of-sight check: cast a ray from the viewer through this position
    # and check if any other part of the curve is closer to the viewer
    # along this ray direction.
    px, py = profile[col]

    # Ray: point + t * viewer_dir (from viewer, t decreases toward viewer)
    # Check all other columns to see if they block the view
    for other_col in range(len(profile)):
        if other_col == col:
            continue
        ox, oy = profile[other_col]

        # Vector from this point to other point
        dx = ox - px
        dy = oy - py

        # Project onto viewer direction to get "depth" difference
        # Negative means the other point is closer to the viewer
        depth = dx * vx + dy * vy

        # Project onto perpendicular to get "lateral" distance
        lateral = abs(dx * (-vy) + dy * vx)

        # The other point blocks if it's closer to the viewer AND
        # laterally close enough (within approximately one column width)
        col_width = 1.0 / len(profile)
        if depth < 0 and lateral < col_width * 0.5:
            return False

    return True

# Test different S-curve amplitudes and light directions
print("Scanning S-curve amplitudes and viewer directions...")
best_s = 0

for amp_10 in range(1, 50):  # amplitude from 0.1 to 5.0
    amplitude = amp_10 / 10.0
    for phase_steps in range(12):  # phase from 0 to 330 in 30° steps
        phase = phase_steps * math.pi / 6

        profile = s_curve_profile(31, amplitude, phase)
        normals = s_curve_normals(profile)

        for angle_deg in range(0, 360, 5):
            angle_rad = math.radians(angle_deg)
            viewer_dir = (math.cos(angle_rad), math.sin(angle_rad))

            # Check visibility of each K4 position
            illuminated = set()
            for i, (r, c) in enumerate(K4_GRID):
                if is_visible_on_scurve(c, profile, normals, viewer_dir):
                    illuminated.add(i)

            null_set = set(range(N)) - illuminated
            if len(null_set) == N_NULLS and valid(null_set):
                sc, e, b, pt = eval_mask(null_set)
                if sc > best_s: best_s = sc
                if sc >= 7:
                    overlap = len(null_set & CONSENSUS_17)
                    print(f"  amp={amplitude:.1f} phase={phase_steps*30}° angle={angle_deg}°: "
                          f"{sc}/24 (e={e},b={b}) overlap={overlap}/17")

print(f"Best S-curve model: {best_s}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL B: SHADOW PROJECTION ONTO GROUND
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("MODEL B: SHADOW/LIGHT PROJECTION ONTO GROUND PLANE")
print("="*80)
print()
print("Letter cutouts project light onto the ground. Due to the S-curve,")
print("some cutouts project onto the ground directly below the sculpture")
print("while others project farther away or are blocked. The 'readable'")
print("letters are those whose projections land within a specific ground area.")
print()

# Model: ground plane below the cylinder.
# Each letter cutout at angle theta on the cylinder projects downward
# at an angle determined by the light source.
# If the light comes from elevation 'elev' and azimuth 'az':
# The shadow of position (theta, height) lands at:
#   x_shadow = R*cos(theta) + height * tan(elev) * cos(az)
#   y_shadow = R*sin(theta) + height * tan(elev) * sin(az)
# where R is the cylinder radius and height is the vertical position.

R = 31.0 / (2 * math.pi)  # cylinder radius

# "Readable area" on the ground: a rectangle or circle where a petrified
# wood slab might be placed

best_ground = 0

for elev_deg in range(10, 80, 5):  # sun elevation 10-75°
    tan_elev = math.tan(math.radians(elev_deg))
    for az_deg in range(0, 360, 10):  # sun azimuth
        az_rad = math.radians(az_deg)

        # Project each K4 position onto ground
        shadows = []
        for i, (r, c) in enumerate(K4_GRID):
            theta = c * 2 * math.pi / 31
            # Height: assume K4 is at the bottom of the sculpture
            # Row 24 is at height ~3 units, row 27 at height ~0
            height = (27 - r) * 1.0  # height from bottom

            sx = R * math.cos(theta) + height / tan_elev * math.cos(az_rad)
            sy = R * math.sin(theta) + height / tan_elev * math.sin(az_rad)
            shadows.append((sx, sy, i))

        # Try different "readable areas" — circles centered at various points
        # The petrified wood is near the base of the sculpture
        sx_all = [s[0] for s in shadows]
        sy_all = [s[1] for s in shadows]
        cx_range = (min(sx_all), max(sx_all))
        cy_range = (min(sy_all), max(sy_all))

        # Center of all shadows
        cx = sum(sx_all) / len(sx_all)
        cy = sum(sy_all) / len(sy_all)

        # Try different radii for the readable area
        dists = [math.sqrt((s[0]-cx)**2 + (s[1]-cy)**2) for s in shadows]
        dists_sorted = sorted(dists)

        # Radius that includes exactly 73 positions
        if len(dists_sorted) >= N_PT:
            r_73 = (dists_sorted[N_PT-1] + dists_sorted[N_PT]) / 2 if N_PT < N else dists_sorted[-1]
            readable = set()
            for sx, sy, idx in shadows:
                if math.sqrt((sx-cx)**2 + (sy-cy)**2) <= r_73:
                    readable.add(idx)
            if len(readable) == N_PT:
                null_set = set(range(N)) - readable
                if valid(null_set):
                    sc, e, b, pt = eval_mask(null_set)
                    if sc > best_ground: best_ground = sc
                    if sc >= 7:
                        print(f"  elev={elev_deg}° az={az_deg}°: {sc}/24 (e={e},b={b})")

print(f"Best ground projection: {best_ground}/24")
print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL C: LETTER FREQUENCY ON CYLINDER — UNIQUE LETTERS
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("MODEL C: CYLINDER COLUMN LETTER COINCIDENCE")
print("="*80)
print()
print("On the full 28-row cylinder, each column has 28 letters.")
print("K4 positions where the K4 letter MATCHES any letter in the same")
print("column of the K1K2K3 text could be 'reinforced' (real). Others = null.")
print("This models CONSTRUCTIVE INTERFERENCE of light through aligned cutouts.")
print()

# Full 28×31 grid (from existing data)
FULL_GRID = [
    'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV',   # row 0  K1
    'JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF',   # row 1
    'DVFPJUDEEHZWETZYVGWHKKQETGFQJNC',   # row 2
    'EGGWHKKXDQMCPFQZDQMMIAGPFXHQRLG',   # row 3  (? → X)
    'TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA',   # row 4
    'QZGZLECGYUXUEENJTBJLBQCETBJDFHR',   # row 5
    'RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT',   # row 6
    'IHHDDDUVHXDWKBFUFPWNTDFIYCUQZER',   # row 7  (? → X)
    'EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI',   # row 8
    'DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK',   # row 9
    'FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ',   # row 10
    'ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE',   # row 11
    'DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP',   # row 12
    'DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG',   # row 13  K2 ends
    'ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI',   # row 14  K3 starts
    'ACHTNREYULDSLLSLLNOHSNOSMRWXMNE',   # row 15
    'TPRNGATIHNRARPESLNNELEBLPIIACAEX',   # row 16  (30→31 padded)
    'WMTWNDITEENRAHCTENEUDRETNHAEOET',    # row 17 (30 chars)
    'FOLSEDTIWENHAEIOYTEYQHEENCTAYCR',   # row 18
    'EIFTBRSPAMHHEWENATAMATEGYEERLBT',   # row 19
    'EEFOASFIOTUETUAEOTOARMAEERTNRTI',   # row 20
    'BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB',   # row 21
    'AECTDDHILCEIHSITEGOEAOSDDRYDLOR',   # row 22
    'ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE',   # row 23
    'ECDMRIPFEIMEHNLSSTTRTVDOHWXOBKR',   # row 24  K4@col27 (? → X)
    'UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO',   # row 25
    'TWTQSJQSSEKZZWATJKLUDIAWINFBNYP',   # row 26
    'VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR',   # row 27
]

# Normalize row lengths (some rows are 30 or 31; pad if needed)
# Actually let's just use rows where we can get column data
print("K4 positions vs same-column letters in rest of grid:")
for pos in sorted(CONSENSUS_17):
    r, c = K4_GRID[pos]
    k4_char = CT97[pos]
    same_col_chars = []
    for row_idx, row_text in enumerate(FULL_GRID):
        if row_idx == r:
            continue  # skip K4's own row
        if c < len(row_text):
            same_col_chars.append(row_text[c])
    matches = same_col_chars.count(k4_char)
    is_consensus = "NULL" if pos in CONSENSUS_17 else "real"
    print(f"  K4[{pos:2d}]='{k4_char}' col={c:2d} [{is_consensus}]: "
          f"same-col matches={matches}/{len(same_col_chars)}, "
          f"col letters={''.join(same_col_chars)}")

print()

# Test: positions with 0 same-column matches are nulls?
null_by_zero_match = set()
for i in range(N):
    r, c = K4_GRID[i]
    k4_char = CT97[i]
    for row_idx, row_text in enumerate(FULL_GRID):
        if row_idx == r:
            continue
        if c < len(row_text) and row_text[c] == k4_char:
            break
    else:
        null_by_zero_match.add(i)

print(f"Positions with ZERO same-column matches: {len(null_by_zero_match)}")
print(f"  Indices: {sorted(null_by_zero_match)}")
print(f"  Overlap with consensus: {len(null_by_zero_match & CONSENSUS_17)}/17")
if len(null_by_zero_match) == N_NULLS and valid(null_by_zero_match):
    sc, e, b, pt = eval_mask(null_by_zero_match)
    print(f"  Score: {sc}/24 (e={e}, b={b})")
print()

# Test: positions with ≤k matches are nulls
for threshold in range(10):
    null_by_threshold = set()
    for i in range(N):
        r, c = K4_GRID[i]
        k4_char = CT97[i]
        matches = 0
        for row_idx, row_text in enumerate(FULL_GRID):
            if row_idx == r:
                continue
            if c < len(row_text) and row_text[c] == k4_char:
                matches += 1
        if matches <= threshold:
            null_by_threshold.add(i)
    print(f"  Threshold ≤{threshold}: {len(null_by_threshold)} positions, "
          f"consensus overlap = {len(null_by_threshold & CONSENSUS_17)}/17")
    if len(null_by_threshold) == N_NULLS and valid(null_by_threshold):
        sc, e, b, pt = eval_mask(null_by_threshold)
        print(f"    Score: {sc}/24 (e={e}, b={b})")

print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL D: ANTIPODES — LETTER ALIGNMENT ON OPPOSITE SIDE
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("MODEL D: ANTIPODAL LETTER ALIGNMENT (ANTIPODES SCULPTURE)")
print("="*80)
print()
print("'Antipodes' = diametrically opposite. On the cylinder, the")
print("antipodal column of c is (c+15) or (c+16) mod 31. If the letter")
print("at a K4 position MATCHES its antipodal partner (same row, col+15/16),")
print("it could be 'real' (constructive). Mismatches = nulls.")
print()

for offset in [15, 16]:
    print(f"Offset = {offset}:")
    match_set = set()
    mismatch_set = set()
    no_partner = set()

    for i, (r, c) in enumerate(K4_GRID):
        anti_col = (c + offset) % 31
        # Find character at (r, anti_col) in the full grid
        if r < len(FULL_GRID) and anti_col < len(FULL_GRID[r]):
            anti_char = FULL_GRID[r][anti_col]
            if CT97[i] == anti_char:
                match_set.add(i)
            else:
                mismatch_set.add(i)
        else:
            no_partner.add(i)

    print(f"  Matches: {len(match_set)} positions")
    print(f"  Mismatches: {len(mismatch_set)} positions")
    print(f"  No partner: {len(no_partner)} positions")
    print(f"  Match indices: {sorted(match_set)}")
    print(f"  Consensus overlap (matches vs consensus): {len(match_set & CONSENSUS_17)}")

    # Try: nulls = mismatches (if count is right)
    if len(mismatch_set) == N_NULLS and valid(mismatch_set):
        sc, e, b, pt = eval_mask(mismatch_set)
        print(f"  Mismatch-as-null score: {sc}/24 (e={e}, b={b})")

    # Try: nulls = matches
    if len(match_set) == N_NULLS and valid(match_set):
        sc, e, b, pt = eval_mask(match_set)
        print(f"  Match-as-null score: {sc}/24 (e={e}, b={b})")

print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL E: THROUGH-THE-LETTER PROJECTION
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("MODEL E: LIGHT THROUGH SPECIFIC LETTER SHAPES")
print("="*80)
print()
print("Different letter cutouts have different 'openness' (how much")
print("light passes through). O is wide open, I and L are narrow.")
print("Model: letters with area above a threshold project enough light")
print("to count as 'illuminated'. Below threshold = null.")
print()

# Rough relative openness of each letter (0-1 scale)
LETTER_OPENNESS = {
    'A': 0.3, 'B': 0.4, 'C': 0.5, 'D': 0.5, 'E': 0.3, 'F': 0.2,
    'G': 0.5, 'H': 0.3, 'I': 0.1, 'J': 0.2, 'K': 0.2, 'L': 0.2,
    'M': 0.3, 'N': 0.3, 'O': 0.7, 'P': 0.4, 'Q': 0.6, 'R': 0.4,
    'S': 0.4, 'T': 0.2, 'U': 0.4, 'V': 0.3, 'W': 0.3, 'X': 0.2,
    'Y': 0.2, 'Z': 0.2
}

# Sort K4 characters by openness
k4_openness = [(i, CT97[i], LETTER_OPENNESS.get(CT97[i], 0.3)) for i in range(N)]
k4_openness.sort(key=lambda x: x[2])

print("K4 characters sorted by letter openness:")
for i, ch, op in k4_openness[:30]:
    is_null = "NULL" if i in CONSENSUS_17 else "real"
    print(f"  K4[{i:2d}]='{ch}' openness={op:.1f} [{is_null}]")

# Test: least-open 24 letters are nulls
least_open_24 = set(i for i, ch, op in k4_openness[:24])
print(f"\nLeast-open 24: {sorted(least_open_24)}")
print(f"  Consensus overlap: {len(least_open_24 & CONSENSUS_17)}/17")
if valid(least_open_24):
    sc, e, b, pt = eval_mask(least_open_24)
    print(f"  Score: {sc}/24 (e={e}, b={b})")

# Most-open 24
most_open_24 = set(i for i, ch, op in k4_openness[-24:])
print(f"\nMost-open 24: {sorted(most_open_24)}")
print(f"  Consensus overlap: {len(most_open_24 & CONSENSUS_17)}/17")
if valid(most_open_24):
    sc, e, b, pt = eval_mask(most_open_24)
    print(f"  Score: {sc}/24 (e={e}, b={b})")

# Try various thresholds
for thresh_10 in range(1, 10):
    threshold = thresh_10 / 10.0
    null_set = set(i for i in range(N) if LETTER_OPENNESS.get(CT97[i], 0.3) < threshold)
    if len(null_set) == N_NULLS and valid(null_set):
        sc, e, b, pt = eval_mask(null_set)
        print(f"  Openness threshold < {threshold:.1f}: {sc}/24 (e={e}, b={b})")

print()

# ══════════════════════════════════════════════════════════════════════════
# MODEL F: COMPASS DIRECTION PROJECTION (ENE = 67.5°)
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("MODEL F: ENE COMPASS BEARING PROJECTION")
print("="*80)
print()
print("The lodestone points ENE (67.5°). If the cylinder is oriented")
print("so that column 0 faces North, then ENE = 67.5° maps to")
print("column 67.5 * 31 / 360 = 5.8 ≈ col 6.")
print()

# Column mapping: assume North = column 0
# Then angle_deg maps to column = round(angle_deg * 31 / 360)

# The lodestone direction
ENE_COL = round(67.5 * 31 / 360)  # ≈ 6
print(f"ENE (67.5°) → column {ENE_COL}")

# Different orientation assumptions:
# Maybe North = some other column
for north_col in range(31):
    ene_col = (north_col + round(67.5 * 31 / 360)) % 31
    # ENE is the direction TOWARD the viewer
    # Front face = centered at ene_col
    # Back face (shadow) = centered at (ene_col + 15) % 31

    # The 24 nulls are the positions on the "back" side
    # (far from the ENE direction, which is the viewer/light direction)
    for arc_cols in range(1, 31):
        # Shadow = positions MORE than arc_cols/2 from ene_col
        null_set = set()
        for i, (r, c) in enumerate(K4_GRID):
            dist = min((c - ene_col) % 31, (ene_col - c) % 31)
            if dist > arc_cols // 2:
                null_set.add(i)

        if len(null_set) == N_NULLS and valid(null_set):
            sc, e, b, pt = eval_mask(null_set)
            if sc >= 7:
                overlap = len(null_set & CONSENSUS_17)
                print(f"  north={north_col} ene={ene_col} arc={arc_cols}: "
                      f"{sc}/24 (e={e},b={b}) overlap={overlap}/17")

print()

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("SUMMARY — PHYSICAL LETTER CUTOUT MODELS")
print("="*80)
print()
print(f"Model A (S-curve line-of-sight): best = {best_s}/24")
print(f"Model B (ground shadow projection): best = {best_ground}/24")
print("Model C (column letter coincidence): see above")
print("Model D (antipodal letter alignment): see above")
print("Model E (letter openness): see above")
print("Model F (ENE compass projection): see above")
