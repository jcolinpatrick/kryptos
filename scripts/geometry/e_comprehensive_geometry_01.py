#!/usr/bin/env python3
"""Comprehensive Geometric Analysis of Kryptos K4.

Family:    geometry
Cipher:    geometric operations on grid/circle/polar
Status:    active
Keyspace:  ~50K (geometric transformations × scoring)
Last run:  never
Best score: n/a

Explores whether K4's cipher method is fundamentally GEOMETRIC rather than
algebraic. Tests circle mappings, grid read paths along bearings, polar
coordinate position generation, symmetry operations, triangulation masks,
angular spacing, and compass-rose selection patterns.

Key installation points:
- KRYPTOS sculpture (pool): 38°57'08.16"N 77°08'44.68"W
- LODESTONE:                38°57'06.06"N 77°08'48.11"W
- LOOMIS (destroyed 1984):  38°57'05.82"N 77°08'49.22"W
- K2 TARGET:                38°57'06.50"N 77°08'44.00"W
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

import math
import sys
import os
from itertools import combinations
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, ALPH, ALPH_IDX, MOD,
    N_CRIBS, KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast

# ══════════════════════════════════════════════════════════════════════════════
# INSTALLATION GEOMETRY
# ══════════════════════════════════════════════════════════════════════════════

def dms_to_dd(d, m, s):
    """Degrees, minutes, seconds to decimal degrees."""
    return d + m / 60.0 + s / 3600.0

# Four key points
POINTS = {
    'KRYPTOS':  (dms_to_dd(38, 57, 8.16),  -dms_to_dd(77, 8, 44.68)),
    'LODESTONE': (dms_to_dd(38, 57, 6.06), -dms_to_dd(77, 8, 48.11)),
    'LOOMIS':   (dms_to_dd(38, 57, 5.82),  -dms_to_dd(77, 8, 49.22)),
    'K2_TARGET': (dms_to_dd(38, 57, 6.50), -dms_to_dd(77, 8, 44.00)),
}

def to_local_meters(lat1, lon1, lat2, lon2):
    """Convert lat/lon to local ENU meters."""
    avg_lat = math.radians((lat1 + lat2) / 2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    dy = dlat * 6371000  # north
    dx = dlon * 6371000 * math.cos(avg_lat)  # east
    return dx, dy

def bearing_deg(p1, p2):
    """Compass bearing from p1 to p2 in degrees."""
    dx, dy = to_local_meters(p1[0], p1[1], p2[0], p2[1])
    return math.degrees(math.atan2(dx, dy)) % 360

def distance_m(p1, p2):
    """Distance in meters between two points."""
    dx, dy = to_local_meters(p1[0], p1[1], p2[0], p2[1])
    return math.sqrt(dx * dx + dy * dy)

def angle_at_vertex(a, vertex, b):
    """Angle at vertex between rays to a and b."""
    b1 = bearing_deg(vertex, a)
    b2 = bearing_deg(vertex, b)
    diff = abs(b1 - b2)
    if diff > 180:
        diff = 360 - diff
    return diff

# ── Grid parameters ──
GRID_COLS = 31
GRID_ROWS = 28
K4_START_ROW = 24
K4_START_COL = 27

def k4_grid_pos(i):
    """Return (row, col) for K4 position i in the 28x31 grid."""
    abs_pos = (K4_START_ROW * GRID_COLS + K4_START_COL) + i
    return abs_pos // GRID_COLS, abs_pos % GRID_COLS

K4_GRID = [k4_grid_pos(i) for i in range(CT_LEN)]
W_POSITIONS = [20, 36, 48, 58, 74]

# Consensus null positions from DEFECTOR:AZ_beau+col7 (17/24 fixed)
CONSENSUS_NULLS = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}

# ── Scoring helpers ──
def check_mask(null_positions):
    """Check if null mask is valid (24 nulls, no crib conflicts)."""
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
    """Extract 73 non-null chars."""
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

def test_substitutions(text, label=""):
    """Test text with common keywords, return best (score, method, pt)."""
    best = (0, "", "")
    keywords = ["KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
                "PALIMPSEST", "LOOMIS", "COMPASS", "AZIMUTH", "BERLIN"]
    for kw in keywords:
        for name, fn in [("vig", vigenere_dec), ("beau", beaufort_dec)]:
            pt = fn(text, kw)
            sc = score_free_fast(pt)
            if sc > best[0]:
                best = (sc, f"{name}({kw})", pt)
            # Also check anchored cribs if length == 97
            if len(pt) == CT_LEN:
                asc = score_cribs(pt)
                if asc > best[0]:
                    best = (asc, f"anchored-{name}({kw})", pt)
    # Single-letter keys
    for k in range(26):
        for name, fn in [("vig", vigenere_dec), ("beau", beaufort_dec)]:
            kw = ALPH[k]
            pt = fn(text, kw)
            sc = score_free_fast(pt)
            if sc > best[0]:
                best = (sc, f"{name}({kw})", pt)
            if len(pt) == CT_LEN:
                asc = score_cribs(pt)
                if asc > best[0]:
                    best = (asc, f"anchored-{name}({kw})", pt)
    return best

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: CIRCLE GEOMETRY — 24-SECTOR WELTZEITUHR MAPPING
# ══════════════════════════════════════════════════════════════════════════════

def section_1_circle_geometry():
    print("\n" + "=" * 80)
    print("SECTION 1: CIRCLE GEOMETRY — 24-SECTOR WELTZEITUHR MAPPING")
    print("=" * 80)

    # 24 facets = 15° per facet
    n_sectors = 24
    sector_angle = 360.0 / n_sectors  # 15°

    # Map 97 positions onto 24 sectors
    # Each position i maps to angle i * 360/97 degrees
    print(f"\n  97 positions on circle, 24 sectors of {sector_angle}° each")
    print(f"  Angular spacing per position: {360.0/97:.4f}° = {360.0/97:.4f}°")

    sectors = defaultdict(list)
    for i in range(CT_LEN):
        angle = i * 360.0 / CT_LEN
        sector = int(angle / sector_angle)  # sector 0-23
        sectors[sector].append(i)

    print(f"\n  Sector occupancy:")
    for s in range(n_sectors):
        positions = sectors[s]
        chars = ''.join(CT[p] for p in positions)
        crib_in_sector = [p for p in positions if p in CRIB_POSITIONS]
        marker = " *CRIB*" if crib_in_sector else ""
        print(f"    Sector {s:2d} ({s*15:3d}°-{(s+1)*15:3d}°): "
              f"{len(positions)} pos {positions} = {chars}{marker}")

    # Sector occupancy: 97/24 = 4.04, so most sectors have 4, some have 5
    sizes = [len(sectors[s]) for s in range(n_sectors)]
    print(f"\n  Sector sizes: {sizes}")
    print(f"  Sectors with 5 positions: {[s for s in range(n_sectors) if len(sectors[s]) == 5]}")
    print(f"  Sectors with 4 positions: {[s for s in range(n_sectors) if len(sectors[s]) == 4]}")

    # Which sectors contain crib positions?
    crib_sectors = defaultdict(list)
    for pos in sorted(CRIB_POSITIONS):
        angle = pos * 360.0 / CT_LEN
        sector = int(angle / sector_angle)
        crib_sectors[sector].append(pos)

    print(f"\n  Crib position distribution across sectors:")
    for s in sorted(crib_sectors.keys()):
        poses = crib_sectors[s]
        cribs = ''.join(CRIB_DICT[p] for p in poses)
        print(f"    Sector {s:2d}: positions {poses} = '{cribs}'")

    # Angular distance between crib blocks on the circle
    ene_center = (21 + 33) / 2  # = 27
    bc_center = (63 + 73) / 2  # = 68
    ene_angle = ene_center * 360.0 / CT_LEN
    bc_angle = bc_center * 360.0 / CT_LEN
    gap_angle = bc_angle - ene_angle
    print(f"\n  ENE center at position {ene_center} → angle {ene_angle:.2f}°")
    print(f"  BC center at position {bc_center} → angle {bc_angle:.2f}°")
    print(f"  Angular gap between cribs: {gap_angle:.2f}°")
    print(f"  Supplementary: {360 - gap_angle:.2f}°")

    # Does the gap match any installation bearing?
    bearings = {
        'KRYPTOS→LODESTONE': bearing_deg(POINTS['KRYPTOS'], POINTS['LODESTONE']),
        'KRYPTOS→LOOMIS': bearing_deg(POINTS['KRYPTOS'], POINTS['LOOMIS']),
        'KRYPTOS→K2': bearing_deg(POINTS['KRYPTOS'], POINTS['K2_TARGET']),
        'LODESTONE→LOOMIS': bearing_deg(POINTS['LODESTONE'], POINTS['LOOMIS']),
        'LODESTONE→K2': bearing_deg(POINTS['LODESTONE'], POINTS['K2_TARGET']),
        'LOOMIS→K2': bearing_deg(POINTS['LOOMIS'], POINTS['K2_TARGET']),
    }
    print(f"\n  Comparing angular gap ({gap_angle:.2f}°) to installation bearings:")
    for name, b in sorted(bearings.items(), key=lambda x: x[1]):
        diff = abs(gap_angle - b)
        if diff > 180:
            diff = 360 - diff
        match_note = " *** CLOSE MATCH" if diff < 5 else ""
        print(f"    {name:25s}: {b:7.2f}°  diff={diff:.2f}°{match_note}")

    # Null mask from sector membership
    # Hypothesis: specific sectors are "null sectors"
    # 97 positions / 24 sectors → 4-5 per sector
    # Need exactly 24 nulls. 6 sectors of size 4 = 24 nulls (if all size-4 sectors are null)
    size4_sectors = [s for s in range(n_sectors) if len(sectors[s]) == 4]
    size5_sectors = [s for s in range(n_sectors) if len(sectors[s]) == 5]
    print(f"\n  Null mask from full sectors:")
    print(f"    Size-4 sectors: {size4_sectors} (count={len(size4_sectors)})")
    print(f"    Size-5 sectors: {size5_sectors} (count={len(size5_sectors)})")

    # Try combinations of sectors summing to 24
    valid_sector_masks = []
    for n_from_4 in range(len(size4_sectors) + 1):
        needed_from_5 = 24 - 4 * n_from_4
        if needed_from_5 < 0:
            break
        if needed_from_5 % 5 != 0:
            continue
        n_from_5 = needed_from_5 // 5
        if n_from_5 > len(size5_sectors):
            continue
        # Try all combinations
        for combo4 in combinations(size4_sectors, n_from_4):
            for combo5 in combinations(size5_sectors, n_from_5):
                null_secs = set(combo4) | set(combo5)
                nulls = []
                for s in null_secs:
                    nulls.extend(sectors[s])
                valid, detail = check_mask(nulls)
                if valid:
                    valid_sector_masks.append((sorted(null_secs), sorted(nulls)))

    print(f"  Valid sector-based masks (sectors as nulls): {len(valid_sector_masks)}")
    for secs, nulls in valid_sector_masks[:5]:
        print(f"    Null sectors {secs}: nulls = {nulls}")
        # Check overlap with consensus nulls
        overlap = len(set(nulls) & CONSENSUS_NULLS)
        print(f"      Consensus overlap: {overlap}/17")

    # Try: null = positions at specific angular offsets from a reference bearing
    # Null = positions within ±angle of a reference direction
    print(f"\n  Directional null masks (positions near a reference bearing):")
    for ref_name, ref_bearing in bearings.items():
        # Select positions whose angle is within ±45° of the bearing
        for half_width in [15, 22.5, 30, 45]:
            nulls = []
            for i in range(CT_LEN):
                pos_angle = i * 360.0 / CT_LEN
                diff = abs(pos_angle - ref_bearing)
                if diff > 180:
                    diff = 360 - diff
                if diff <= half_width:
                    nulls.append(i)
            if len(nulls) == 24:
                valid, detail = check_mask(nulls)
                if valid:
                    print(f"    VALID: ±{half_width}° of {ref_name} ({ref_bearing:.1f}°)")
                    overlap = len(set(nulls) & CONSENSUS_NULLS)
                    print(f"      Nulls: {sorted(nulls)}")
                    print(f"      Consensus overlap: {overlap}/17")

    return sectors, crib_sectors


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: GRID GEOMETRY — BEARING-DEFINED READ PATHS
# ══════════════════════════════════════════════════════════════════════════════

def section_2_grid_read_paths():
    print("\n" + "=" * 80)
    print("SECTION 2: GRID GEOMETRY — BEARING-DEFINED READ PATHS")
    print("=" * 80)

    # K4 occupies rows 24-27, cols 0-30 (plus partial row 24 at cols 27-30)
    # Row 24: K4[0..3]   (4 chars, cols 27-30)
    # Row 25: K4[4..34]  (31 chars, cols 0-30)
    # Row 26: K4[35..65] (31 chars, cols 0-30)
    # Row 27: K4[66..96] (31 chars, cols 0-30)

    # Build a 2D grid of K4 positions
    grid = {}
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        grid[(r, c)] = (i, CT[i])

    print(f"\n  K4 grid layout:")
    for row in range(24, 28):
        chars = []
        for col in range(31):
            if (row, col) in grid:
                idx, ch = grid[(row, col)]
                chars.append(f"{ch}")
            else:
                chars.append(".")
        print(f"    Row {row}: {''.join(chars)}")

    # Key bearings from the installation
    key_bearings = {
        'LOOMIS→K2':     bearing_deg(POINTS['LOOMIS'], POINTS['K2_TARGET']),
        'LOOMIS→KRYPTOS': bearing_deg(POINTS['LOOMIS'], POINTS['KRYPTOS']),
        'LODESTONE→K2':  bearing_deg(POINTS['LODESTONE'], POINTS['K2_TARGET']),
        'KRYPTOS→K2':    bearing_deg(POINTS['KRYPTOS'], POINTS['K2_TARGET']),
        'K2→LODESTONE':  bearing_deg(POINTS['K2_TARGET'], POINTS['LODESTONE']),
    }

    print(f"\n  Key bearings:")
    for name, b in key_bearings.items():
        print(f"    {name:25s}: {b:7.2f}°")

    # For each bearing, trace a line through the K4 grid
    # The grid has rows going DOWN (south) and cols going RIGHT (east)
    # A bearing of θ means: dx = sin(θ), dy = cos(θ) in N-E coords
    # In grid coords: row increases south (−dy), col increases east (+dx)
    # So: drow/step = −cos(θ), dcol/step = sin(θ)

    results = []
    print(f"\n  Bearing-guided read paths through K4 grid:")
    for name, bearing in key_bearings.items():
        rad = math.radians(bearing)
        dcol = math.sin(rad)  # east component
        drow = -math.cos(rad)  # south component (negative because bearing 0=north=up)

        # Actually in our grid, row increases downward, so positive bearing = east-ish
        # Row increases = going south = negative of north bearing
        # Bearing 0° = north = row decreasing
        # Bearing 90° = east = col increasing
        # So: drow = cos(bearing) but inverted for grid, dcol = sin(bearing)
        # Wait, careful: bearing is from north, clockwise
        # North = row decreasing: drow = -cos(θ), dcol = sin(θ)

        # Trace from multiple starting points
        for start_row in range(24, 28):
            for start_col in range(0, 31, 5):
                if (start_row, start_col) not in grid and start_row == 24:
                    continue
                path = []
                visited = set()
                # Follow the line, snapping to nearest grid cell
                for step in range(-50, 50):
                    r = start_row + drow * step
                    c = start_col + dcol * step
                    ri, ci = round(r), round(c)
                    if (ri, ci) in grid and (ri, ci) not in visited:
                        idx, ch = grid[(ri, ci)]
                        path.append(idx)
                        visited.add((ri, ci))

                if len(path) >= 20:
                    text = ''.join(CT[p] for p in path)
                    sc = score_free_fast(text)
                    if sc > 0:
                        results.append((sc, name, start_row, start_col, path, text))

    if results:
        results.sort(key=lambda x: -x[0])
        print(f"\n  Read paths with free-crib hits:")
        for sc, name, sr, sc_, path, text in results[:10]:
            print(f"    Score {sc}: {name} from ({sr},{sc_}): {text[:50]}...")
    else:
        print(f"  No bearing-guided read paths produced crib matches")

    # Alternative: use bearing to define a PERMUTATION of the 97 positions
    # Sort positions by their projected distance along the bearing direction
    print(f"\n  Bearing-projected permutations:")
    perm_results = []
    for name, bearing in key_bearings.items():
        rad = math.radians(bearing)
        # Project each position onto the bearing direction
        projections = []
        for i in range(CT_LEN):
            r, c = K4_GRID[i]
            # Project (r, c) onto direction (sin(bearing), -cos(bearing))
            proj = c * math.sin(rad) + r * (-math.cos(rad))
            projections.append((proj, i))

        # Sort by projection = reading order along the bearing
        projections.sort()
        perm = [idx for _, idx in projections]
        reordered = ''.join(CT[p] for p in perm)

        # Test the reordered text
        sc = score_free_fast(reordered)
        if sc > 0:
            perm_results.append((sc, name, reordered))

        # Also test with substitution
        best_sub = test_substitutions(reordered, f"bearing-perm({name})")
        if best_sub[0] > 0:
            perm_results.append((best_sub[0], f"{name}+{best_sub[1]}", best_sub[2]))

        # Also: the permutation itself might be the null mask
        # Take the first/last 24 positions in projection order as nulls
        for end in ['first', 'last']:
            if end == 'first':
                nulls = perm[:24]
            else:
                nulls = perm[-24:]
            valid, detail = check_mask(nulls)
            if valid:
                text_73 = extract_73(nulls)
                best_sub = test_substitutions(text_73, f"proj-mask-{end}({name})")
                if best_sub[0] > 0:
                    perm_results.append((best_sub[0], f"mask-{end}({name})+{best_sub[1]}", best_sub[2]))
                    print(f"    VALID mask ({end} 24 of {name}): consensus overlap = "
                          f"{len(set(nulls) & CONSENSUS_NULLS)}/17")

    if perm_results:
        perm_results.sort(key=lambda x: -x[0])
        print(f"\n  Best bearing-projection results:")
        for sc, method, text in perm_results[:10]:
            print(f"    Score {sc}: {method}: {text[:60]}...")
    else:
        print(f"  No bearing-projection results")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: POLAR COORDINATES — POSITION SEQUENCES FROM ANGLES/RADII
# ══════════════════════════════════════════════════════════════════════════════

def section_3_polar_coordinates():
    print("\n" + "=" * 80)
    print("SECTION 3: POLAR COORDINATES — POSITION SEQUENCES")
    print("=" * 80)

    # For each reference point, compute polar coords to all other points
    ref_lat, ref_lon = POINTS['LOOMIS']  # use LOOMIS as origin

    point_coords = {}
    for name, (lat, lon) in POINTS.items():
        dx, dy = to_local_meters(ref_lat, ref_lon, lat, lon)
        r = math.sqrt(dx*dx + dy*dy)
        theta = math.degrees(math.atan2(dx, dy)) % 360
        point_coords[name] = (dx, dy, r, theta)

    print(f"  Polar coordinates from LOOMIS:")
    for name, (dx, dy, r, theta) in point_coords.items():
        print(f"    {name:12s}: ({dx:8.2f}m E, {dy:8.2f}m N) → r={r:7.2f}m, θ={theta:7.2f}°")

    # Generate position sequences by taking mod values
    print(f"\n  Position sequences from polar values (mod 97, mod 26):")
    sequences = {}
    for name, (dx, dy, r, theta) in point_coords.items():
        if name == 'LOOMIS':
            continue
        vals = {
            'r_mod97': round(r) % 97,
            'theta_mod97': round(theta) % 97,
            'r_mod26': round(r) % 26,
            'theta_mod26': round(theta) % 26,
            'dx_mod97': round(abs(dx)) % 97,
            'dy_mod97': round(abs(dy)) % 97,
            'r*theta_mod97': round(r * theta) % 97,
            'round_r': round(r),
            'round_theta': round(theta),
        }
        sequences[name] = vals
        print(f"    {name}: {vals}")

    # Try using the angular relationships between points as step sizes for reading
    print(f"\n  Angular step sequences:")
    angles = []
    names_list = [n for n in POINTS if n != 'LOOMIS']
    for n in names_list:
        _, _, _, theta = point_coords[n]
        angles.append((n, theta))
    angles.sort(key=lambda x: x[1])

    print(f"  Sorted angles from LOOMIS: {[(n, f'{a:.1f}°') for n, a in angles]}")

    # Angular differences between consecutive points
    diffs = []
    for i in range(len(angles)):
        j = (i + 1) % len(angles)
        diff = (angles[j][1] - angles[i][1]) % 360
        diffs.append(diff)
        print(f"    {angles[i][0]} → {angles[j][0]}: Δ={diff:.2f}°")

    # Use the angular diffs as step sizes on the 97-char circle
    # Convert: step = round(diff * 97 / 360)
    steps = [round(d * CT_LEN / 360) for d in diffs]
    print(f"  Angular diffs as CT positions: {steps}")

    # Generate a read sequence by stepping around the circle
    for start in range(CT_LEN):
        for step_set in [steps]:
            visited = []
            pos = start
            used_indices = set()
            step_idx = 0
            for _ in range(CT_LEN):
                if pos not in used_indices:
                    visited.append(pos)
                    used_indices.add(pos)
                pos = (pos + step_set[step_idx % len(step_set)]) % CT_LEN
                step_idx += 1
            if len(visited) >= 73:
                text = ''.join(CT[p] for p in visited[:73])
                sc = score_free_fast(text)
                if sc > 0:
                    print(f"    HIT: start={start}, steps={step_set}: {text[:50]}...")

    # Polar from each reference point to grid positions
    print(f"\n  Polar from K2_TARGET to K4 grid positions:")
    k2_dx, k2_dy = point_coords['K2_TARGET'][:2]
    # K4 grid positions in meters from LOOMIS → convert to relative to K2
    # Actually, we need the grid positions in real-world coordinates
    # The grid is on the sculpture, so all positions are at KRYPTOS location
    # This approach doesn't map directly. Skip detailed polar-to-grid mapping.
    print(f"    (Grid positions are all at sculpture location, ~0.1m apart)")
    print(f"    (Polar from external points to individual chars not meaningful)")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: ROTATION/REFLECTION SYMMETRY
# ══════════════════════════════════════════════════════════════════════════════

def section_4_symmetry():
    print("\n" + "=" * 80)
    print("SECTION 4: ROTATION/REFLECTION SYMMETRY OPERATIONS")
    print("=" * 80)

    # The sculpture is an S-curve. What if the cipher involves:
    # (a) 180° rotation of half the text
    # (b) Reflection across the grid center
    # (c) Glide reflection (translate + reflect)

    print(f"\n  S-curve symmetry operations on K4:")

    # 4a: Reverse the entire text
    rev = CT[::-1]
    sc_rev = score_free_fast(rev)
    sc_rev_a = score_cribs(rev)
    print(f"    Reverse: free={sc_rev}, anchored={sc_rev_a}")
    sub = test_substitutions(rev, "reversed")
    print(f"    Reverse + best sub: {sub[0]}, {sub[1]}")

    # 4b: Reverse within blocks (the S reads left, then right, then left)
    # K4 spans 4 rows: row 24 (4 chars), rows 25-27 (31 each)
    # S-curve: even rows read left-to-right, odd rows read right-to-left (or vice versa)
    rows = [
        CT[0:4],     # row 24 (4 chars)
        CT[4:35],    # row 25 (31 chars)
        CT[35:66],   # row 26 (31 chars)
        CT[66:97],   # row 27 (31 chars)
    ]

    for pattern_name, reversal_pattern in [
        ("S-LRL",  [False, True, False, True]),
        ("S-RLR",  [True, False, True, False]),
        ("S-LRRL", [False, True, True, False]),
        ("S-RLLR", [True, False, False, True]),
    ]:
        s_text = ""
        for row_text, do_reverse in zip(rows, reversal_pattern):
            s_text += row_text[::-1] if do_reverse else row_text
        sc = score_free_fast(s_text)
        asc = score_cribs(s_text)
        sub = test_substitutions(s_text, pattern_name)
        print(f"    {pattern_name}: free={sc}, anchored={asc}, best_sub={sub[0]} ({sub[1]})")

    # 4c: 180° rotation of the full grid (rotate positions around center)
    # Position i → position (96 - i) for 0-indexed 97 chars
    rot180 = ''.join(CT[96 - i] for i in range(CT_LEN))
    sc = score_free_fast(rot180)
    asc = score_cribs(rot180)
    sub = test_substitutions(rot180, "rot180")
    print(f"    Rot180: free={sc}, anchored={asc}, best_sub={sub[0]} ({sub[1]})")

    # 4d: Reflection across the grid center column
    # In the 31-wide grid, reflect each row: col c → col (30 - c)
    reflected = [0] * CT_LEN
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        new_c = 30 - c
        # Find which K4 position has (r, new_c)
        for j in range(CT_LEN):
            rj, cj = K4_GRID[j]
            if rj == r and cj == new_c:
                reflected[j] = CT[i]
                break
    ref_text = ''.join(chr(c) if isinstance(c, int) else c for c in reflected if c != 0)
    if len(ref_text) == CT_LEN:
        sc = score_free_fast(ref_text)
        asc = score_cribs(ref_text)
        sub = test_substitutions(ref_text, "col-reflect")
        print(f"    Col-reflect: free={sc}, anchored={asc}, best_sub={sub[0]} ({sub[1]})")

    # 4e: Interleave top-half with bottom-half
    # Split CT into two halves and interleave
    mid = CT_LEN // 2  # 48
    h1 = CT[:mid]
    h2 = CT[mid:]
    for method_name, interleaved in [
        ("interleave-h1h2", ''.join(a + b for a, b in zip(h1, h2)) + (h2[-1] if len(h2) > len(h1) else '')),
        ("interleave-h2h1", ''.join(b + a for a, b in zip(h1, h2)) + (h2[-1] if len(h2) > len(h1) else '')),
    ]:
        sc = score_free_fast(interleaved)
        sub = test_substitutions(interleaved, method_name)
        print(f"    {method_name}: free={sc}, best_sub={sub[0]} ({sub[1]})")

    # 4f: Spiral reading order (start center, spiral outward)
    # K4's 4 rows × ~31 cols, spiral from center
    print(f"\n  Spiral reading orders:")
    # Build a small grid for K4
    k4_grid_arr = [[None] * 31 for _ in range(4)]
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        local_r = r - 24
        if 0 <= local_r < 4 and 0 <= c < 31:
            k4_grid_arr[local_r][c] = i

    # Clockwise spiral from center
    def spiral_order(nrows, ncols):
        """Generate spiral order indices for nrows x ncols grid."""
        result = []
        top, bottom, left, right = 0, nrows - 1, 0, ncols - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                result.append((top, c))
            top += 1
            for r in range(top, bottom + 1):
                result.append((r, right))
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    result.append((bottom, c))
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    result.append((r, left))
                left += 1
        return result

    spiral = spiral_order(4, 31)
    spiral_indices = []
    for r, c in spiral:
        if k4_grid_arr[r][c] is not None:
            spiral_indices.append(k4_grid_arr[r][c])

    if len(spiral_indices) == CT_LEN:
        spiral_text = ''.join(CT[i] for i in spiral_indices)
        sc = score_free_fast(spiral_text)
        sub = test_substitutions(spiral_text, "spiral-CW")
        print(f"    Spiral CW: free={sc}, best_sub={sub[0]} ({sub[1]})")

        # Counter-clockwise
        ccw_text = ''.join(CT[i] for i in reversed(spiral_indices))
        sc = score_free_fast(ccw_text)
        sub = test_substitutions(ccw_text, "spiral-CCW")
        print(f"    Spiral CCW: free={sc}, best_sub={sub[0]} ({sub[1]})")

    # Inward spiral (start from edges)
    spiral_in = spiral_order(4, 31)[::-1]
    spiral_in_indices = []
    for r, c in spiral_in:
        if k4_grid_arr[r][c] is not None:
            spiral_in_indices.append(k4_grid_arr[r][c])
    if len(spiral_in_indices) == CT_LEN:
        spiral_in_text = ''.join(CT[i] for i in spiral_in_indices)
        sc = score_free_fast(spiral_in_text)
        sub = test_substitutions(spiral_in_text, "spiral-inward")
        print(f"    Spiral inward: free={sc}, best_sub={sub[0]} ({sub[1]})")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: TRIANGULATION AS NULL MASK
# ══════════════════════════════════════════════════════════════════════════════

def section_5_triangulation_mask():
    print("\n" + "=" * 80)
    print("SECTION 5: TRIANGULATION AS NULL MASK")
    print("=" * 80)

    # Map the installation triangle onto the K4 grid
    # Triangle vertices: KRYPTOS, LODESTONE, K2_TARGET (or LOOMIS)
    # Normalize to grid coordinates

    ref = POINTS['LOOMIS']  # use LOOMIS as origin
    coords = {}
    for name, pt in POINTS.items():
        dx, dy = to_local_meters(ref[0], ref[1], pt[0], pt[1])
        coords[name] = (dx, dy)

    print(f"  Installation points (meters from LOOMIS):")
    for name, (dx, dy) in coords.items():
        print(f"    {name:12s}: ({dx:8.2f}, {dy:8.2f})")

    # Scale and map to K4 grid (4 rows × 31 cols)
    # The grid spans ~0-30 in columns, 0-3 in rows
    # Map the bounding box of installation points to the grid

    all_x = [v[0] for v in coords.values()]
    all_y = [v[1] for v in coords.values()]
    min_x, max_x = min(all_x), max(all_x)
    min_y, max_y = min(all_y), max(all_y)

    def map_to_grid(dx, dy, ncols=31, nrows=4):
        """Map real-world coords to grid coords."""
        if max_x == min_x or max_y == min_y:
            return 0, 0
        gc = (dx - min_x) / (max_x - min_x) * (ncols - 1)
        gr = (1 - (dy - min_y) / (max_y - min_y)) * (nrows - 1)  # flip y
        return gr, gc

    grid_coords = {}
    for name, (dx, dy) in coords.items():
        gr, gc = map_to_grid(dx, dy)
        grid_coords[name] = (gr, gc)
        print(f"    {name} → grid ({gr:.2f}, {gc:.2f})")

    # Define triangles and test which K4 positions fall inside
    def point_in_triangle(px, py, v1, v2, v3):
        """Barycentric method to check if point is inside triangle."""
        def sign(p1x, p1y, p2x, p2y, p3x, p3y):
            return (p1x - p3x) * (p2y - p3y) - (p2x - p3x) * (p1y - p3y)
        d1 = sign(px, py, v1[0], v1[1], v2[0], v2[1])
        d2 = sign(px, py, v2[0], v2[1], v3[0], v3[1])
        d3 = sign(px, py, v3[0], v3[1], v1[0], v1[1])
        has_neg = (d1 < 0) or (d2 < 0) or (d3 < 0)
        has_pos = (d1 > 0) or (d2 > 0) or (d3 > 0)
        return not (has_neg and has_pos)

    triangles = [
        ("KRYPTOS-LODESTONE-K2", ['KRYPTOS', 'LODESTONE', 'K2_TARGET']),
        ("KRYPTOS-LOOMIS-K2", ['KRYPTOS', 'LOOMIS', 'K2_TARGET']),
        ("LODESTONE-LOOMIS-K2", ['LODESTONE', 'LOOMIS', 'K2_TARGET']),
        ("KRYPTOS-LODESTONE-LOOMIS", ['KRYPTOS', 'LODESTONE', 'LOOMIS']),
    ]

    for tri_name, vertices in triangles:
        v1 = grid_coords[vertices[0]]
        v2 = grid_coords[vertices[1]]
        v3 = grid_coords[vertices[2]]

        inside = []
        outside = []
        for i in range(CT_LEN):
            r, c = K4_GRID[i]
            local_r = r - 24  # 0-3
            # Check if (local_r, c) is inside the triangle mapped to grid
            if point_in_triangle(local_r, c, v1, v2, v3):
                inside.append(i)
            else:
                outside.append(i)

        print(f"\n  Triangle {tri_name}:")
        print(f"    Inside: {len(inside)}, Outside: {len(outside)}")

        # Try inside as nulls
        if len(inside) == 24:
            valid, detail = check_mask(inside)
            print(f"    Inside=nulls: {detail}")
            if valid:
                text_73 = extract_73(inside)
                sub = test_substitutions(text_73, f"tri-in({tri_name})")
                print(f"    Best sub: {sub[0]} ({sub[1]})")

        # Try outside as nulls
        if len(outside) == 24:
            valid, detail = check_mask(outside)
            print(f"    Outside=nulls: {detail}")
            if valid:
                text_73 = extract_73(outside)
                sub = test_substitutions(text_73, f"tri-out({tri_name})")
                print(f"    Best sub: {sub[0]} ({sub[1]})")

    # Also try: use real-world triangle (not mapped to grid)
    # Position i is "inside" if its angle from center falls within the triangle's angular span
    print(f"\n  Angular triangulation (positions by bearing sector):")
    # Center = centroid of triangle
    cx = sum(coords[v][0] for v in ['KRYPTOS', 'LODESTONE', 'K2_TARGET']) / 3
    cy = sum(coords[v][1] for v in ['KRYPTOS', 'LODESTONE', 'K2_TARGET']) / 3

    # Bearings from center to vertices
    vertex_bearings = []
    for v in ['KRYPTOS', 'LODESTONE', 'K2_TARGET']:
        dx, dy = coords[v][0] - cx, coords[v][1] - cy
        b = math.degrees(math.atan2(dx, dy)) % 360
        vertex_bearings.append(b)
    vertex_bearings.sort()
    print(f"    Vertex bearings from centroid: {[f'{b:.1f}°' for b in vertex_bearings]}")

    # Map K4 positions to angular sectors based on triangle
    for i in range(CT_LEN):
        pos_angle = i * 360.0 / CT_LEN
        # Check if pos_angle falls between any two vertex bearings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6: ANGULAR SPACING OF CRIBS
# ══════════════════════════════════════════════════════════════════════════════

def section_6_angular_spacing():
    print("\n" + "=" * 80)
    print("SECTION 6: ANGULAR SPACING OF CRIBS ON THE CIRCLE")
    print("=" * 80)

    # On a circle of 97, position i has angle i * 360/97 degrees
    # ENE: positions 21-33 (13 chars)
    # BC: positions 63-73 (11 chars)

    print(f"\n  Crib angular positions:")
    for pos in sorted(CRIB_POSITIONS):
        angle = pos * 360.0 / CT_LEN
        crib_ch = CRIB_DICT[pos]
        print(f"    pos {pos:2d} '{crib_ch}': {angle:7.3f}°")

    # Angular span of each crib block
    ene_start_angle = 21 * 360.0 / CT_LEN
    ene_end_angle = 33 * 360.0 / CT_LEN
    bc_start_angle = 63 * 360.0 / CT_LEN
    bc_end_angle = 73 * 360.0 / CT_LEN

    ene_span = ene_end_angle - ene_start_angle
    bc_span = bc_end_angle - bc_start_angle

    print(f"\n  ENE span: {ene_start_angle:.2f}° to {ene_end_angle:.2f}° ({ene_span:.2f}°)")
    print(f"  BC span:  {bc_start_angle:.2f}° to {bc_end_angle:.2f}° ({bc_span:.2f}°)")

    # Gap between end of ENE and start of BC
    gap_after_ene = bc_start_angle - ene_end_angle
    print(f"  Gap (ENE end → BC start): {gap_after_ene:.2f}°")

    # Gap between end of BC and start of ENE (going around)
    gap_after_bc = (ene_start_angle + 360) - bc_end_angle
    print(f"  Gap (BC end → ENE start): {gap_after_bc:.2f}°")

    # Midpoints
    ene_mid_angle = (ene_start_angle + ene_end_angle) / 2
    bc_mid_angle = (bc_start_angle + bc_end_angle) / 2
    mid_separation = bc_mid_angle - ene_mid_angle
    print(f"\n  Midpoint separation: {mid_separation:.2f}°")
    print(f"  Supplementary: {360 - mid_separation:.2f}°")

    # Compare to installation angles
    bearings = {
        'LOOMIS→KRYPTOS': bearing_deg(POINTS['LOOMIS'], POINTS['KRYPTOS']),
        'LOOMIS→LODESTONE': bearing_deg(POINTS['LOOMIS'], POINTS['LODESTONE']),
        'LOOMIS→K2': bearing_deg(POINTS['LOOMIS'], POINTS['K2_TARGET']),
        'KRYPTOS→K2': bearing_deg(POINTS['KRYPTOS'], POINTS['K2_TARGET']),
        'KRYPTOS→LODESTONE': bearing_deg(POINTS['KRYPTOS'], POINTS['LODESTONE']),
        'LODESTONE→K2': bearing_deg(POINTS['LODESTONE'], POINTS['K2_TARGET']),
        'K2→KRYPTOS': bearing_deg(POINTS['K2_TARGET'], POINTS['KRYPTOS']),
    }
    angles_at = {
        'at LOOMIS (K-K2)': angle_at_vertex(POINTS['KRYPTOS'], POINTS['LOOMIS'], POINTS['K2_TARGET']),
        'at KRYPTOS (LOD-K2)': angle_at_vertex(POINTS['LODESTONE'], POINTS['KRYPTOS'], POINTS['K2_TARGET']),
        'at K2 (K-LOD)': angle_at_vertex(POINTS['KRYPTOS'], POINTS['K2_TARGET'], POINTS['LODESTONE']),
        'at LOOMIS (K-LOD)': angle_at_vertex(POINTS['KRYPTOS'], POINTS['LOOMIS'], POINTS['LODESTONE']),
    }

    print(f"\n  Comparison of crib angular gap ({gap_after_ene:.2f}°) to bearings:")
    for name, b in sorted(bearings.items(), key=lambda x: abs(x[1] - gap_after_ene)):
        diff = abs(b - gap_after_ene)
        if diff > 180:
            diff = 360 - diff
        mark = " *** CLOSE" if diff < 5 else ""
        print(f"    {name:25s}: {b:7.2f}°  diff={diff:.2f}°{mark}")

    print(f"\n  Comparison of crib midpoint separation ({mid_separation:.2f}°) to angles:")
    for name, a in sorted(angles_at.items(), key=lambda x: abs(x[1] - mid_separation)):
        diff = abs(a - mid_separation)
        mark = " *** CLOSE" if diff < 5 else ""
        print(f"    {name:30s}: {a:7.2f}°  diff={diff:.2f}°{mark}")

    # Key ratio: 13/97 and 11/97 of the circle
    ene_frac = 13 / 97
    bc_frac = 11 / 97
    print(f"\n  ENE occupies {ene_frac*100:.2f}% of circle ({ene_frac*360:.2f}°)")
    print(f"  BC occupies {bc_frac*100:.2f}% of circle ({bc_frac*360:.2f}°)")
    print(f"  Together: {(ene_frac+bc_frac)*100:.2f}% ({(ene_frac+bc_frac)*360:.2f}°)")
    print(f"  24/97 = {24/97*100:.2f}% ({24/97*360:.2f}°)")

    # The angle 24/97 * 360 = 89.07° ≈ 90° (right angle!)
    crib_angle = 24.0 / 97 * 360
    print(f"\n  *** 24 crib positions span {crib_angle:.2f}° of the 97-circle ***")
    print(f"  This is {crib_angle:.2f}° ≈ {round(crib_angle)}° (near right angle!)")

    # The complementary 73 positions span 360 - 89.07 = 270.93°
    non_crib_angle = 73.0 / 97 * 360
    print(f"  73 non-crib positions span {non_crib_angle:.2f}° ≈ 3/4 of circle")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7: COMPASS ROSE GEOMETRY (32-POINT)
# ══════════════════════════════════════════════════════════════════════════════

def section_7_compass_rose():
    print("\n" + "=" * 80)
    print("SECTION 7: COMPASS ROSE GEOMETRY (32-POINT)")
    print("=" * 80)

    # A 32-point compass divides 360° into 11.25° sectors
    # The lodestone deflects the compass from true north
    # Kryptos compass rose at the entrance

    n_points = 32
    sector_size = 360.0 / n_points

    # Map 97 positions to 32-point compass sectors
    compass_sectors = defaultdict(list)
    compass_names_32 = [
        'N', 'NbE', 'NNE', 'NEbN', 'NE', 'NEbE', 'ENE', 'EbN',
        'E', 'EbS', 'ESE', 'SEbE', 'SE', 'SEbS', 'SSE', 'SbE',
        'S', 'SbW', 'SSW', 'SWbS', 'SW', 'SWbW', 'WSW', 'WbS',
        'W', 'WbN', 'WNW', 'NWbW', 'NW', 'NWbN', 'NNW', 'NbW',
    ]

    for i in range(CT_LEN):
        angle = i * 360.0 / CT_LEN
        sector = int(angle / sector_size) % n_points
        compass_sectors[sector].append(i)

    print(f"\n  97 positions mapped to 32-point compass:")
    for s in range(n_points):
        positions = compass_sectors[s]
        name = compass_names_32[s]
        angle_start = s * sector_size
        crib_in = [p for p in positions if p in CRIB_POSITIONS]
        marker = f" CRIB({len(crib_in)})" if crib_in else ""
        print(f"    {s:2d} {name:5s} ({angle_start:6.2f}°): "
              f"{len(positions)} pos = {positions}{marker}")

    # The ENE compass direction = 67.5° = sector 6
    ene_sector_idx = 6  # compass_names_32[6] = 'ENE'
    print(f"\n  ENE sector ({compass_names_32[ene_sector_idx]}, 67.5°):")
    print(f"    Positions: {compass_sectors[ene_sector_idx]}")
    print(f"    These positions contain K4 chars: "
          f"{''.join(CT[p] for p in compass_sectors[ene_sector_idx])}")

    # Lodestone deflection: the lodestone at LOOMIS deflects compass readings
    # If lodestone points ENE (67.5°), it would shift compass readings
    # This could create a mapping between compass sectors and positions

    # Compass rose with deflection
    lodestone_bearing = bearing_deg(POINTS['KRYPTOS'], POINTS['LODESTONE'])
    print(f"\n  Lodestone bearing from KRYPTOS: {lodestone_bearing:.2f}°")
    print(f"  Deflection from north: positions shifted by {lodestone_bearing:.1f}°")

    # Apply deflection: shift all position angles by lodestone bearing
    deflected_sectors = defaultdict(list)
    for i in range(CT_LEN):
        raw_angle = i * 360.0 / CT_LEN
        deflected_angle = (raw_angle + lodestone_bearing) % 360
        sector = int(deflected_angle / sector_size) % n_points
        deflected_sectors[sector].append(i)

    print(f"\n  Deflected compass mapping:")
    for s in range(n_points):
        positions = deflected_sectors[s]
        name = compass_names_32[s]
        if len(positions) > 0:
            crib_in = [p for p in positions if p in CRIB_POSITIONS]
            marker = f" CRIB({len(crib_in)})" if crib_in else ""
            print(f"    {s:2d} {name:5s}: {len(positions)} pos = {positions}{marker}")

    # Which sectors sum to 24 positions? (for null mask)
    print(f"\n  Sector combinations summing to 24 (deflected):")
    sector_sizes = {s: len(deflected_sectors[s]) for s in range(n_points) if deflected_sectors[s]}
    # Small search: try combinations of sectors
    found_compass_masks = 0
    for n_secs in range(1, 10):
        for combo in combinations(sector_sizes.keys(), n_secs):
            total = sum(sector_sizes[s] for s in combo)
            if total == 24:
                nulls = []
                for s in combo:
                    nulls.extend(deflected_sectors[s])
                valid, detail = check_mask(nulls)
                if valid:
                    found_compass_masks += 1
                    sec_names = [compass_names_32[s] for s in combo]
                    overlap = len(set(nulls) & CONSENSUS_NULLS)
                    if found_compass_masks <= 5:
                        print(f"    VALID: sectors {sec_names}: overlap w/consensus = {overlap}/17")
                        text_73 = extract_73(nulls)
                        sub = test_substitutions(text_73, f"compass-mask")
                        if sub[0] > 0:
                            print(f"      Best sub: {sub[0]} ({sub[1]})")

    print(f"  Total valid compass-sector masks: {found_compass_masks}")

    # Key insight: 32 sectors, but 97 is prime → positions don't divide evenly
    # 97 / 32 = 3.03125 → each sector gets ~3 positions
    # 32 * 3 = 96, so 31 sectors get 3 and 1 sector gets 4
    # Wait, let's recount
    sizes_deflected = [len(deflected_sectors[s]) for s in range(n_points)]
    print(f"\n  Deflected sector sizes: {sizes_deflected}")
    print(f"  Sum: {sum(sizes_deflected)}")

    # 16-point compass (main directions)
    print(f"\n  16-point compass (22.5° sectors):")
    compass16_sectors = defaultdict(list)
    compass16_names = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE',
                       'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW']
    for i in range(CT_LEN):
        angle = (i * 360.0 / CT_LEN + lodestone_bearing) % 360
        sector = int(angle / 22.5) % 16
        compass16_sectors[sector].append(i)

    for s in range(16):
        positions = compass16_sectors[s]
        name = compass16_names[s]
        crib_in = [p for p in positions if p in CRIB_POSITIONS]
        marker = f" CRIB({len(crib_in)})" if crib_in else ""
        print(f"    {name:4s}: {len(positions)} positions{marker}")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8: HAND-EXECUTABLE GEOMETRIC OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def section_8_hand_executable():
    print("\n" + "=" * 80)
    print("SECTION 8: HAND-EXECUTABLE GEOMETRIC OPERATIONS")
    print("=" * 80)

    # The answer must be hand-executable. What geometric operations can you
    # do with pencil, paper, ruler, and compass?

    # 8a: Diagonal reading of grid (ruler at an angle)
    print(f"\n  8a: Diagonal reading orders")
    # Read the 4-row K4 grid diagonally (like a slash or backslash)
    # For a 4×31 grid (adjusting for the short first row)

    # Forward diagonal: row decreases, col increases
    # Antidiagonals: sets of positions where (row + col) = constant
    antidiags = defaultdict(list)
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        antidiags[r + c].append(i)

    diag_text = []
    for d in sorted(antidiags.keys()):
        for idx in antidiags[d]:
            diag_text.append(CT[idx])
    diag_str = ''.join(diag_text)
    sc = score_free_fast(diag_str)
    sub = test_substitutions(diag_str, "antidiag-read")
    print(f"    Antidiagonal read: free={sc}, best_sub={sub[0]} ({sub[1]})")

    # Main diagonals: (row - col) = constant
    maindiags = defaultdict(list)
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        maindiags[r - c].append(i)

    diag_text2 = []
    for d in sorted(maindiags.keys()):
        for idx in maindiags[d]:
            diag_text2.append(CT[idx])
    diag_str2 = ''.join(diag_text2)
    sc = score_free_fast(diag_str2)
    sub = test_substitutions(diag_str2, "maindiag-read")
    print(f"    Main diagonal read: free={sc}, best_sub={sub[0]} ({sub[1]})")

    # 8b: Column-first reading (read down columns instead of across rows)
    print(f"\n  8b: Column-first reading")
    # Read K4 grid column by column (left to right, top to bottom)
    k4_by_col = defaultdict(list)
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        k4_by_col[c].append((r, i))

    col_text = []
    for c in range(31):
        for r, idx in sorted(k4_by_col[c]):
            col_text.append(CT[idx])
    col_str = ''.join(col_text)
    sc = score_free_fast(col_str)
    sub = test_substitutions(col_str, "col-first-read")
    print(f"    Column-first (L→R): free={sc}, best_sub={sub[0]} ({sub[1]})")

    # Right to left columns
    col_text_rl = []
    for c in range(30, -1, -1):
        for r, idx in sorted(k4_by_col[c]):
            col_text_rl.append(CT[idx])
    col_str_rl = ''.join(col_text_rl)
    sc = score_free_fast(col_str_rl)
    sub = test_substitutions(col_str_rl, "col-first-R→L")
    print(f"    Column-first (R→L): free={sc}, best_sub={sub[0]} ({sub[1]})")

    # 8c: Every N-th position (ruler markings at regular intervals)
    print(f"\n  8c: Every N-th position selections")
    for step in range(2, 50):
        for offset in range(step):
            selected = list(range(offset, CT_LEN, step))
            if len(selected) == 73:
                text = ''.join(CT[p] for p in selected)
                sc = score_free_fast(text)
                if sc > 0:
                    print(f"    HIT: every {step} from {offset} (73 chars): free={sc}")
                sub = test_substitutions(text, f"every-{step}-from-{offset}")
                if sub[0] > 0:
                    print(f"      Sub: {sub[0]} ({sub[1]})")

            if len(selected) == 24:
                valid, detail = check_mask(selected)
                if valid:
                    text_73 = extract_73(selected)
                    sc = score_free_fast(text_73)
                    if sc > 0:
                        print(f"    HIT: every {step} from {offset} (24 nulls): free={sc}")

    # 8d: Grid-based geometric selection — cross pattern, diamond, etc.
    print(f"\n  8d: Grid-based geometric patterns as null masks")

    patterns = {}

    # Diamond pattern centered at grid center
    center_r = 25.5  # center of rows 24-27
    center_c = 15.0  # center of cols 0-30
    for radius in range(1, 20):
        nulls = []
        for i in range(CT_LEN):
            r, c = K4_GRID[i]
            manhattan = abs(r - center_r) + abs(c - center_c)
            if manhattan <= radius:
                nulls.append(i)
        if len(nulls) == 24:
            patterns[f"diamond-r{radius}"] = nulls

    # Checkerboard
    for phase in [0, 1]:
        nulls = [i for i in range(CT_LEN) if (K4_GRID[i][0] + K4_GRID[i][1]) % 2 == phase]
        if len(nulls) == 24:
            patterns[f"checker-{phase}"] = nulls

    # Border positions (first/last in each row)
    border = []
    for row in range(24, 28):
        row_positions = [(i, c) for i, (r, c) in enumerate(K4_GRID) if r == row]
        if row_positions:
            border.append(row_positions[0][0])
            if len(row_positions) > 1:
                border.append(row_positions[-1][0])
    if len(border) < 24:
        # Not enough border positions for full mask
        pass

    for name, nulls in patterns.items():
        valid, detail = check_mask(nulls)
        if valid:
            text_73 = extract_73(nulls)
            sub = test_substitutions(text_73, name)
            print(f"    {name}: valid mask, best_sub={sub[0]} ({sub[1]})")

    # 8e: Modular clock arithmetic (Weltzeituhr)
    print(f"\n  8e: Clock arithmetic — position mod 24")
    # Each position maps to an hour on the 24-hour clock
    clock_hour = defaultdict(list)
    for i in range(CT_LEN):
        hour = i % 24
        clock_hour[hour].append(i)

    print(f"  Positions by clock hour (mod 24):")
    for h in range(24):
        positions = clock_hour[h]
        chars = ''.join(CT[p] for p in positions)
        crib_in = [p for p in positions if p in CRIB_POSITIONS]
        marker = f" CRIB({len(crib_in)})" if crib_in else ""
        print(f"    Hour {h:2d}: {positions} = {chars}{marker}")

    # Hours 0-23 each have either 4 or 5 positions
    # 97 = 24*4 + 1, so one hour has 5 positions
    # That hour is hour 0 (positions 0, 24, 48, 72, 96)
    # Select specific hours as nulls
    hours_with_5 = [h for h in range(24) if len(clock_hour[h]) == 5]
    hours_with_4 = [h for h in range(24) if len(clock_hour[h]) == 4]
    print(f"\n  Hours with 5 positions: {hours_with_5}")
    print(f"  Hours with 4 positions: {hours_with_4}")

    # Try: 6 hours as nulls (6*4 = 24)
    valid_clock_masks = 0
    for combo in combinations(hours_with_4, 6):
        nulls = []
        for h in combo:
            nulls.extend(clock_hour[h])
        valid, detail = check_mask(nulls)
        if valid:
            valid_clock_masks += 1
            if valid_clock_masks <= 3:
                overlap = len(set(nulls) & CONSENSUS_NULLS)
                text_73 = extract_73(nulls)
                sub = test_substitutions(text_73, f"clock-hours-{combo}")
                print(f"    Clock hours {combo}: valid, consensus overlap={overlap}/17, "
                      f"best_sub={sub[0]} ({sub[1]})")

    # Also try: 5*4 + 1*4 = 24 (5 hours of 4 + part of one 5-hour)
    # Or: 4 hours of 4 + 2 positions from a 5-hour → no, too complex for hand

    print(f"  Total valid 6-hour masks: {valid_clock_masks}")

    # 8f: The "embarrassingly simple" test — what if nulls are just
    # positions 0-23 (first 24) or 73-96 (last 24)?
    print(f"\n  8f: Trivially simple masks")
    for name, nulls in [
        ("first 24", list(range(24))),
        ("last 24", list(range(73, 97))),
        ("middle 24", list(range(37, 61))),  # centered
        ("even positions", [i for i in range(0, CT_LEN, 2)][:24]),
        ("odd positions", [i for i in range(1, CT_LEN, 2)][:24]),
        ("first+last 12", list(range(12)) + list(range(85, 97))),
    ]:
        if len(nulls) != 24:
            continue
        valid, detail = check_mask(nulls)
        if valid:
            text_73 = extract_73(nulls)
            sub = test_substitutions(text_73, name)
            sc_f = score_free_fast(text_73)
            print(f"    '{name}': VALID, free={sc_f}, best_sub={sub[0]} ({sub[1]})")
        else:
            print(f"    '{name}': {detail}")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9: CONSENSUS NULL ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def section_9_consensus_analysis():
    print("\n" + "=" * 80)
    print("SECTION 9: GEOMETRIC PATTERNS IN CONSENSUS NULL POSITIONS")
    print("=" * 80)

    # The 17 consensus null positions from DEFECTOR:AZ_beau+col7
    print(f"\n  Consensus nulls (17/24): {sorted(CONSENSUS_NULLS)}")

    # Map to grid coordinates
    print(f"\n  Grid coordinates of consensus nulls:")
    null_grid = []
    for p in sorted(CONSENSUS_NULLS):
        r, c = K4_GRID[p]
        null_grid.append((p, r, c))
        print(f"    pos {p:2d}: row {r}, col {c:2d}, char '{CT[p]}'")

    # Row distribution
    row_counts = defaultdict(list)
    for p, r, c in null_grid:
        row_counts[r].append(c)
    print(f"\n  Row distribution:")
    for r in sorted(row_counts.keys()):
        cols = sorted(row_counts[r])
        print(f"    Row {r}: {len(cols)} nulls at cols {cols}")

    # Column distribution
    col_counts = defaultdict(list)
    for p, r, c in null_grid:
        col_counts[c].append(r)
    print(f"\n  Column distribution:")
    for c in sorted(col_counts.keys()):
        rows = sorted(col_counts[c])
        print(f"    Col {c:2d}: {len(rows)} nulls in rows {rows}")

    # Check for diagonal patterns
    print(f"\n  Diagonal patterns in consensus nulls:")
    antidiag_vals = [r + c for _, r, c in null_grid]
    maindiag_vals = [r - c for _, r, c in null_grid]
    print(f"    Antidiagonal (r+c): {sorted(antidiag_vals)}")
    print(f"    Main diagonal (r-c): {sorted(maindiag_vals)}")

    # Check modular patterns
    print(f"\n  Modular patterns:")
    positions = sorted(CONSENSUS_NULLS)
    for mod in range(2, 25):
        residues = [p % mod for p in positions]
        unique_res = sorted(set(residues))
        if len(unique_res) <= mod // 2:  # concentrated in fewer than half the residues
            print(f"    mod {mod:2d}: residues {unique_res} "
                  f"({len(unique_res)}/{mod} classes)")

    # Differences between consecutive nulls
    diffs = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
    print(f"\n  Consecutive differences: {diffs}")
    print(f"  Mean diff: {sum(diffs)/len(diffs):.2f}")
    print(f"  Median diff: {sorted(diffs)[len(diffs)//2]}")

    # Do the W positions among the consensus nulls form a pattern?
    w_in_consensus = sorted(CONSENSUS_NULLS & set(W_POSITIONS))
    print(f"\n  W positions in consensus: {w_in_consensus} (4/5)")
    w_not_in = [w for w in W_POSITIONS if w not in CONSENSUS_NULLS]
    print(f"  W not in consensus: {w_not_in}")

    # Angular positions on the 97-circle
    print(f"\n  Consensus null angles on 97-circle:")
    for p in sorted(CONSENSUS_NULLS):
        angle = p * 360.0 / CT_LEN
        sector_24 = int(angle / 15)
        print(f"    pos {p:2d}: {angle:7.2f}° (sector {sector_24})")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10: NOVEL GEOMETRIC HYPOTHESES
# ══════════════════════════════════════════════════════════════════════════════

def section_10_novel():
    print("\n" + "=" * 80)
    print("SECTION 10: NOVEL GEOMETRIC HYPOTHESES")
    print("=" * 80)

    # 10a: Wrap text on a cylinder (the sculpture IS an S-shaped curve)
    # K4 on a 7-column cylinder (97 = 7*13 + 6)
    print(f"\n  10a: Cylinder wrapping")
    for circumference in [7, 8, 11, 13, 14, 24, 31]:
        height = (CT_LEN + circumference - 1) // circumference
        print(f"\n    Cylinder circumference {circumference} (height {height}):")

        # Build cylinder grid
        cyl = [[None] * circumference for _ in range(height)]
        for i in range(CT_LEN):
            r = i // circumference
            c = i % circumference
            cyl[r][c] = i

        # Helical reading: start at a position, spiral up/down
        for helix_step in range(1, circumference):
            path = []
            visited = set()
            pos = 0
            for _ in range(CT_LEN * 2):
                r = pos // circumference
                c = pos % circumference
                if pos < CT_LEN and pos not in visited:
                    path.append(pos)
                    visited.add(pos)
                # Move: next row, shift by helix_step
                next_r = r + 1
                next_c = (c + helix_step) % circumference
                pos = next_r * circumference + next_c
                if pos >= CT_LEN:
                    break

            if len(path) >= 50:
                text = ''.join(CT[p] for p in path)
                sc = score_free_fast(text)
                if sc > 0:
                    print(f"      Helix step {helix_step}: {len(path)} chars, free={sc}")

        # Vertical (column) reading
        col_text = []
        for c in range(circumference):
            for r in range(height):
                if cyl[r][c] is not None:
                    col_text.append(CT[cyl[r][c]])
        col_str = ''.join(col_text)
        sc = score_free_fast(col_str)
        if sc > 0:
            print(f"      Column read: free={sc}")

    # 10b: Route cipher paths
    print(f"\n  10b: Route cipher through K4 grid (4 rows × varied cols)")
    # Route: zigzag down columns
    k4_local = [[None] * 31 for _ in range(4)]
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        k4_local[r - 24][c] = i

    # Zigzag: column 0 top-to-bottom, column 1 bottom-to-top, etc.
    zigzag = []
    for c in range(31):
        if c % 2 == 0:
            for r in range(4):
                if k4_local[r][c] is not None:
                    zigzag.append(k4_local[r][c])
        else:
            for r in range(3, -1, -1):
                if k4_local[r][c] is not None:
                    zigzag.append(k4_local[r][c])

    if len(zigzag) == CT_LEN:
        zigzag_text = ''.join(CT[p] for p in zigzag)
        sc = score_free_fast(zigzag_text)
        sub = test_substitutions(zigzag_text, "zigzag-route")
        print(f"    Zigzag route: free={sc}, best_sub={sub[0]} ({sub[1]})")

    # 10c: Position ↔ angle duality on mod-97 circle
    # What if the "key" is an angle, and encryption = rotation on the circle?
    print(f"\n  10c: Circular rotation of positions (modular shift)")
    best_rotation = (0, 0, "")
    for shift in range(1, CT_LEN):
        rotated = ''.join(CT[(i + shift) % CT_LEN] for i in range(CT_LEN))
        sc = score_cribs(rotated)
        if sc > best_rotation[0]:
            best_rotation = (sc, shift, rotated)
    print(f"    Best circular rotation: shift={best_rotation[1]}, anchored_score={best_rotation[0]}")

    # 10d: Interleave by geometric ratio (golden, sqrt(2), etc.)
    print(f"\n  10d: Golden ratio / sqrt(2) based selections")
    phi = (1 + math.sqrt(5)) / 2
    sqrt2 = math.sqrt(2)

    for ratio_name, ratio in [("phi", phi), ("1/phi", 1/phi), ("sqrt2", sqrt2),
                               ("pi/4", math.pi/4), ("e/3", math.e/3)]:
        # Generate positions by: floor(i * ratio) mod 97
        positions = []
        seen = set()
        for i in range(CT_LEN):
            p = int(i * ratio * CT_LEN) % CT_LEN
            if p not in seen:
                positions.append(p)
                seen.add(p)

        if len(positions) >= 73:
            text = ''.join(CT[p] for p in positions[:73])
            sc = score_free_fast(text)
            if sc > 0:
                print(f"    {ratio_name} ({ratio:.6f}): free={sc}")

        # First 24 as nulls
        if len(positions) >= 24:
            nulls = positions[:24]
            valid, detail = check_mask(nulls)
            if valid:
                text_73 = extract_73(nulls)
                sub = test_substitutions(text_73, f"{ratio_name}-mask")
                if sub[0] > 0:
                    print(f"    {ratio_name} mask: best_sub={sub[0]} ({sub[1]})")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 80)
    print("COMPREHENSIVE GEOMETRIC ANALYSIS OF KRYPTOS K4")
    print("=" * 80)
    print(f"CT ({CT_LEN} chars): {CT}")
    print(f"Cribs: pos 21-33 = EASTNORTHEAST, pos 63-73 = BERLINCLOCK")
    print()

    # Compute and display key installation geometry
    print("── Installation Geometry ──")
    for n1, p1 in POINTS.items():
        for n2, p2 in POINTS.items():
            if n1 >= n2:
                continue
            b = bearing_deg(p1, p2)
            d = distance_m(p1, p2)
            print(f"  {n1:12s} → {n2:12s}: bearing {b:7.2f}°, dist {d:7.1f}m, "
                  f"b%26={round(b)%26:2d}={ALPH[round(b)%26]}, "
                  f"d%26={round(d)%26:2d}={ALPH[round(d)%26]}")

    # Key triangle angles
    for v_name in POINTS:
        others = [n for n in POINTS if n != v_name]
        for i in range(len(others)):
            for j in range(i+1, len(others)):
                a = angle_at_vertex(POINTS[others[i]], POINTS[v_name], POINTS[others[j]])
                if 20 <= a <= 90 or a in [11, 13, 24, 73, 97]:
                    print(f"  Angle at {v_name} ({others[i]}-{others[j]}): {a:.2f}°")

    # Run all sections
    section_1_circle_geometry()
    section_2_grid_read_paths()
    section_3_polar_coordinates()
    section_4_symmetry()
    section_5_triangulation_mask()
    section_6_angular_spacing()
    section_7_compass_rose()
    section_8_hand_executable()
    section_9_consensus_analysis()
    section_10_novel()

    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)


if __name__ == '__main__':
    main()
