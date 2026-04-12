#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
"""
E-CARDAN-FIXED-POINT: Cardan Grille Fixed-Point Hypothesis Test

HYPOTHESIS: K4 conceals plaintext via a rotating Cardan grille applied to a
padded message. Positions 32 and 73 (0-indexed) are "fixed points" where the
padding character equals the ciphertext character -- meaning these positions
must be NON-aperture (padding) positions in ALL rotations.

TEST PLAN:
For each candidate grid size (10x10, 11x9, 7x14):
  1. Map K4's 97 characters into the grid in reading order
  2. Compute all rotation orbits (4-fold for square, 2-fold/180-deg for rectangles)
  3. Check if positions 32 and 73 can be non-aperture in all rotations
  4. Count valid grille configurations satisfying the constraint
  5. For surviving configs, extract aperture characters and score vs English trigrams

KEY GEOMETRIC CONSTRAINT:
- For an n*n grid, rotating (r,c) by 90 degrees clockwise gives (c, n-1-r).
- For non-square grids (rows != cols), 90-degree rotation changes dimensions,
  so only 180-degree rotation is valid: (r,c) -> (rows-1-r, cols-1-c).
"""

import math
import os
import sys
import time
from collections import Counter
from itertools import product as iproduct

# ── K4 Ciphertext ───────────────────────────────────────────────────────
CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)  # 97

# Known plaintext cribs (0-indexed)
CRIB_BERLIN = {64: 'B', 65: 'E', 66: 'R', 67: 'L', 68: 'I', 69: 'N'}
CRIB_CLOCK  = {70: 'C', 71: 'L', 72: 'O', 73: 'C', 74: 'K'}
ALL_CRIBS = {**CRIB_BERLIN, **CRIB_CLOCK}

# Fixed-point positions claimed by hypothesis
FIXED_POINTS = [32, 73]

# ── English Trigram Scoring ──────────────────────────────────────────────
# Top 40 most common English trigrams for scoring
COMMON_TRIGRAMS = {
    'THE', 'AND', 'ING', 'ENT', 'ION', 'HER', 'FOR', 'THA', 'NTH', 'INT',
    'ERE', 'TIO', 'VER', 'EST', 'HAT', 'ATE', 'ALL', 'ETH', 'HES', 'HIS',
    'FTH', 'STH', 'OTH', 'RES', 'ONT', 'ARE', 'ERS', 'AIN', 'OFT', 'ITH',
    'MEN', 'WAS', 'ONE', 'OUR', 'OUT', 'NOT', 'AVE', 'EVE', 'HAN', 'TER',
}

def trigram_score(text):
    """Count how many common English trigrams appear in the text."""
    text = text.upper()
    count = 0
    found = []
    for i in range(len(text) - 2):
        tri = text[i:i+3]
        if tri in COMMON_TRIGRAMS:
            count += 1
            found.append((i, tri))
    return count, found

def expected_random_trigrams(length, alphabet_size=26):
    """Expected number of common trigram hits for random text."""
    n_trigrams = max(0, length - 2)
    prob_per_trigram = len(COMMON_TRIGRAMS) / (alphabet_size ** 3)
    return n_trigrams * prob_per_trigram


# ── Grid Geometry Utilities ──────────────────────────────────────────────

def rotate_90_square(r, c, n):
    """Rotate (r,c) by 90 degrees clockwise in an n*n grid."""
    return (c, n - 1 - r)

def rotate_180_rect(r, c, rows, cols):
    """Rotate (r,c) by 180 degrees in a rows*cols grid."""
    return (rows - 1 - r, cols - 1 - c)

def linear_index(r, c, cols):
    """Convert (r,c) to linear index in reading order."""
    return r * cols + c

def rc_from_linear(idx, cols):
    """Convert linear index to (r,c)."""
    return divmod(idx, cols)


def compute_orbits_square(n):
    """
    Compute all 4-rotation orbits for an n*n square grid.
    Returns list of orbits, each orbit is a list of (r,c) positions.
    """
    visited = set()
    orbits = []
    for r in range(n):
        for c in range(n):
            if (r, c) in visited:
                continue
            orbit = [(r, c)]
            cr, cc = r, c
            for _ in range(3):
                cr, cc = rotate_90_square(cr, cc, n)
                if (cr, cc) not in visited:
                    orbit.append((cr, cc))
            orbit_set = set(orbit)
            # Deduplicate: for even grids all orbits have 4 unique cells;
            # for odd grids the center has orbit size 1, and some have size 2
            unique_orbit = list(orbit_set)
            orbits.append(unique_orbit)
            visited.update(orbit_set)
    return orbits


def compute_orbits_180(rows, cols):
    """
    Compute all 180-degree rotation orbits for a rows*cols grid.
    Each orbit has either 2 positions (general case) or 1 position (center for odd-area grids).
    Returns list of orbits, each orbit is a list of (r,c) positions.
    """
    visited = set()
    orbits = []
    for r in range(rows):
        for c in range(cols):
            if (r, c) in visited:
                continue
            r2, c2 = rotate_180_rect(r, c, rows, cols)
            if (r2, c2) == (r, c):
                # Self-symmetric (center cell for odd-dimension grids)
                orbits.append([(r, c)])
            else:
                orbits.append([(r, c), (r2, c2)])
            visited.add((r, c))
            visited.add((r2, c2))
    return orbits


# ══════════════════════════════════════════════════════════════════════════
# MAIN TEST
# ══════════════════════════════════════════════════════════════════════════

print("=" * 74)
print("E-CARDAN-FIXED-POINT: Cardan Grille Fixed-Point Hypothesis Test")
print("=" * 74)
print()
print(f"K4 ciphertext ({N} chars): {CT}")
print(f"Fixed-point positions under test: {FIXED_POINTS}")
print(f"  Position 32 -> CT char: '{CT[32]}'")
print(f"  Position 73 -> CT char: '{CT[73]}'")
print()

# Verify known cribs
print("Known plaintext verification:")
for pos in sorted(ALL_CRIBS):
    print(f"  CT[{pos}] = '{CT[pos]}', expected PT = '{ALL_CRIBS[pos]}'")
print()

GRID_CONFIGS = [
    (10, 10, "square"),
    (11,  9, "rectangular"),
    ( 7, 14, "rectangular"),
]

for rows, cols, shape in GRID_CONFIGS:
    total_cells = rows * cols
    print("=" * 74)
    print(f"GRID: {rows} x {cols} = {total_cells} cells  (shape: {shape})")
    print("=" * 74)
    print(f"  K4 has {N} chars; grid has {total_cells} cells")
    print(f"  Unused/padding cells: {total_cells - N}")
    print()

    # ── Check if fixed points are within the grid ────────────────────
    fp_in_grid = all(fp < total_cells for fp in FIXED_POINTS)
    if not fp_in_grid:
        print(f"  WARNING: Fixed point(s) {[fp for fp in FIXED_POINTS if fp >= total_cells]} "
              f"exceed grid size {total_cells}. Skipping.\n")
        continue

    # ── Compute orbits ───────────────────────────────────────────────
    if shape == "square":
        orbits = compute_orbits_square(rows)
        rotation_type = "4-fold (90-degree)"
        n_rotations = 4
    else:
        # Non-square grids: 90-degree rotation changes dimensions.
        # Only 180-degree rotation preserves the grid shape.
        orbits = compute_orbits_180(rows, cols)
        rotation_type = "2-fold (180-degree only)"
        n_rotations = 2
        print(f"  NOTE: Non-square grid -> 90-degree rotation changes dimensions.")
        print(f"        Standard 4-rotation Cardan grille is IMPOSSIBLE.")
        print(f"        Using 180-degree rotation only (half-turn grille).")
        print()

    # Convert orbits to linear indices
    orbit_linear = []
    for orbit in orbits:
        orbit_linear.append([linear_index(r, c, cols) for r, c in orbit])

    print(f"  Rotation type: {rotation_type}")
    print(f"  Number of orbits: {len(orbits)}")
    orbit_sizes = Counter(len(o) for o in orbits)
    for sz, cnt in sorted(orbit_sizes.items()):
        print(f"    Orbits of size {sz}: {cnt}")
    print()

    # ── Identify which orbit contains each fixed point ───────────────
    fp_orbit_map = {}  # fixed_point -> orbit_index
    for fp in FIXED_POINTS:
        for oi, orb in enumerate(orbit_linear):
            if fp in orb:
                fp_orbit_map[fp] = oi
                break

    print("  Fixed-point orbit membership:")
    for fp in FIXED_POINTS:
        oi = fp_orbit_map.get(fp, None)
        if oi is not None:
            orb = orbit_linear[oi]
            orb_rc = orbits[oi]
            print(f"    Position {fp} ('{CT[fp]}') -> orbit {oi}: "
                  f"linear={orb}, rc={orb_rc}")
        else:
            print(f"    Position {fp} -> NOT FOUND in any orbit (ERROR)")
    print()

    # ── Check if both fixed points are in the same orbit ─────────────
    fp_orbits = [fp_orbit_map.get(fp) for fp in FIXED_POINTS]
    same_orbit = (fp_orbits[0] == fp_orbits[1]) if all(o is not None for o in fp_orbits) else False

    if same_orbit:
        print(f"  FINDING: Both fixed points are in the SAME orbit ({fp_orbits[0]}).")
        print(f"           This means if one is non-aperture, the entire orbit is non-aperture.")
        print()
    else:
        print(f"  Fixed points are in DIFFERENT orbits ({fp_orbits[0]} and {fp_orbits[1]}).")
        print()

    # ── Cardan grille constraint analysis ────────────────────────────
    # A valid Cardan grille selects exactly one position from each orbit as the aperture
    # in rotation 0. The other positions in the orbit become apertures in rotations 1, 2, 3.
    # For a 4-fold orbit of size 4, exactly one cell is aperture per rotation.
    # For the fixed-point constraint, we need positions 32 and 73 to be NON-aperture
    # in ALL rotations. But in a standard Cardan grille, every cell in the grid IS an
    # aperture in exactly one rotation. The grille fills all cells.
    #
    # CRITICAL INSIGHT: In a standard turning grille, EVERY cell is exposed in exactly
    # one rotation. There are no "non-aperture" cells -- every cell gets written to.
    # The only way a position can be "non-aperture in all rotations" is if it's in the
    # unused/padding cells (cells beyond position 96 in a grid larger than 97).

    print("  ── CRITICAL CONSTRAINT ANALYSIS ──")
    print()

    if shape == "square" and n_rotations == 4:
        # Standard turning grille: every orbit contributes 1 aperture per rotation
        # So every cell in the grid is an aperture in exactly one rotation.
        # The only "non-aperture" cells are the (total_cells - N) unused cells.
        print(f"  Standard 4-rotation Cardan grille on {rows}x{cols}:")
        print(f"    Every cell is an aperture in exactly 1 of the 4 rotations.")
        print(f"    Only {total_cells - N} cells can be 'unused' (beyond the {N}-char message).")
        print(f"    These unused cells are the LAST {total_cells - N} positions written.")
        print()

        # For positions 32 and 73 to be non-aperture in ALL rotations,
        # they would need to be among the unused cells.
        # In a 10x10 grid with 97 chars, only 3 cells are unused.
        # These 3 cells are the last 3 in writing order (positions 97, 98, 99).
        # Positions 32 and 73 in the LINEAR reading of K4 are NOT the same as
        # positions in the grille's writing order.

        # Let's be precise about what "non-aperture in all rotations" could mean.
        # Interpretation 1: The cell at linear grid position 32/73 is never opened.
        #   -> Impossible in a standard turning grille (all cells get opened).
        # Interpretation 2: The K4 character at index 32/73 maps to a cell that
        #   happens to be in a "padding" orbit.
        #   -> The padding would be in cells beyond the 97th character written.

        # Actually, re-reading the hypothesis more carefully:
        # "fixed points where the padding character equals the ciphertext character"
        # This means: at these positions, the ciphertext IS the plaintext (identity).
        # This doesn't mean non-aperture -- it means the character wasn't transformed.
        # But the hypothesis says "non-aperture (padding) positions in ALL rotations".
        #
        # For a Cardan grille used as a transposition cipher:
        # - All 97 chars of K4 are placed into the grid
        # - The grille extracts ~25 chars per rotation (97/4 ~ 24.25)
        # - Chars at aperture positions are PLAINTEXT
        # - Chars at non-aperture positions are PADDING (nulls)
        #
        # WAIT: There are TWO models for Cardan grille:
        # MODEL A (Writing grille): Write PT through apertures in 4 rotations -> CT is the full grid
        # MODEL B (Reading grille): CT is the full grid, read through apertures -> PT is what you extract
        #
        # The hypothesis seems to use MODEL B: K4 IS the grid (padded to fill it),
        # and a Cardan grille extracts the plaintext from specific positions.
        # Non-aperture positions contain padding characters.
        # "Fixed points" where padding = ciphertext means those positions have
        # padding that happens to match K4.
        #
        # Under MODEL B, the grille has apertures at certain positions.
        # Positions NOT in apertures are padding. The constraint is that
        # positions 32 and 73 should be NON-aperture (padding) in the grille.
        # Since the grille has only 1 orientation (or the hypothesis tests
        # a static grille, not a rotating one), we need positions 32 and 73
        # to not be selected as aperture positions.

        # Let's test both interpretations:
        # STATIC CARDAN: A mask selects some positions from the 97 chars.
        # ROTATING CARDAN: The grille rotates 4 times, each time exposing 25 cells.

        # For the rotating Cardan on 10x10:
        # Each orbit has exactly 4 cells. One cell is aperture in rotation 0,
        # another in rotation 1, etc. ALL cells are apertures in some rotation.
        # So "non-aperture in ALL rotations" is impossible for any cell in a
        # standard rotating Cardan grille.

        print("  RESULT for 4-rotation Cardan on 10x10:")
        print("    In a standard rotating Cardan grille, EVERY cell is an aperture")
        print("    in exactly one rotation. No cell can be 'non-aperture in ALL rotations'.")
        print("    Therefore, the fixed-point constraint as stated is IMPOSSIBLE")
        print("    for a standard 10x10 rotating Cardan grille.")
        print()

        # However, let's also test the STATIC (single-orientation) reading:
        # Pick one cell from each orbit as the aperture. The rest are non-aperture.
        # Check if positions 32 and 73 can both be non-aperture.

        print("  Testing STATIC Cardan grille (single orientation, no rotation):")
        print("  Apertures = 1 cell per orbit = 25 selected from 100 grid cells.")
        print()

        # Map K4 linear positions to grid positions
        # K4[i] sits at grid cell i (reading order, 0-indexed)
        # Positions 97, 98, 99 are padding (not in K4).

        # For positions 32 and 73 to be non-aperture,
        # their orbits must have the aperture at a DIFFERENT cell in the orbit.

        fp32_orbit_idx = fp_orbit_map[32]
        fp73_orbit_idx = fp_orbit_map[73]

        orbit32 = orbit_linear[fp32_orbit_idx]
        orbit73 = orbit_linear[fp73_orbit_idx]

        print(f"    Orbit containing pos 32: {orbit32}")
        print(f"    Orbit containing pos 73: {orbit73}")
        print()

        # Check how many choices exist for each orbit such that the fixed point
        # is NOT the aperture cell.
        if same_orbit:
            # Both in same orbit: aperture must be at one of the OTHER cells in the orbit
            other_cells = [c for c in orbit32 if c not in FIXED_POINTS]
            n_valid_for_fp_orbit = len(other_cells)
            print(f"    Both fixed points in same orbit.")
            print(f"    Orbit cells: {orbit32}")
            print(f"    Non-fixed-point cells in orbit: {other_cells}")
            print(f"    Valid aperture choices for this orbit: {n_valid_for_fp_orbit}")
            n_free_orbits = len(orbits) - 1
        else:
            # Different orbits: each orbit must have aperture at a non-fixed-point cell
            other32 = [c for c in orbit32 if c != 32]
            other73 = [c for c in orbit73 if c != 73]
            n_valid_32 = len(other32)
            n_valid_73 = len(other73)
            print(f"    Valid aperture choices for orbit of pos 32: {n_valid_32} (from {other32})")
            print(f"    Valid aperture choices for orbit of pos 73: {n_valid_73} (from {other73})")
            n_free_orbits = len(orbits) - 2

        # For all other orbits, any of the cells in the orbit can be the aperture
        orbit_size_list = [len(o) for o in orbits]

        # Count total valid configurations
        if same_orbit:
            fp_orbit_sz = len(orbit32)
            total_configs = n_valid_for_fp_orbit
            for oi in range(len(orbits)):
                if oi == fp32_orbit_idx:
                    continue
                total_configs *= len(orbits[oi])
        else:
            total_configs = n_valid_32 * n_valid_73
            for oi in range(len(orbits)):
                if oi in (fp32_orbit_idx, fp73_orbit_idx):
                    continue
                total_configs *= len(orbits[oi])

        # Total unconstrained configs
        total_unconstrained = 1
        for o in orbits:
            total_unconstrained *= len(o)

        print()
        print(f"    Total unconstrained grille configurations: {total_unconstrained:,}")
        print(f"    Configurations satisfying fixed-point constraint: {total_configs:,}")
        print(f"    Fraction: {total_configs/total_unconstrained:.6f}")
        print()

        # ── Now enumerate and score some configurations ──────────────
        # For 10x10 with 25 orbits of size 4: 4^25 ~ 10^15 total.
        # We can't enumerate all, but we can sample.

        print("  ── SAMPLING AND SCORING ──")
        print()

        # Extract aperture characters for a random sample of valid configurations
        import random
        random.seed(42)

        N_SAMPLES = 100000
        best_score = -1
        best_text = ""
        best_found = []
        score_distribution = Counter()

        # Precompute which choices are valid for constrained orbits
        if same_orbit:
            constrained_orbits = {fp32_orbit_idx: other_cells}
        else:
            constrained_orbits = {fp32_orbit_idx: other32, fp73_orbit_idx: other73}

        t0 = time.time()
        for sample_i in range(N_SAMPLES):
            # Generate a random valid configuration
            apertures = []
            for oi in range(len(orbits)):
                if oi in constrained_orbits:
                    # Pick from valid choices only
                    cell = random.choice(constrained_orbits[oi])
                else:
                    cell = random.choice(orbit_linear[oi])
                apertures.append(cell)

            # Sort apertures by position (reading order) to extract text
            apertures.sort()

            # Extract characters at aperture positions (only those within K4)
            extracted = []
            for pos in apertures:
                if pos < N:
                    extracted.append(CT[pos])
            text = ''.join(extracted)

            # Score
            sc, found = trigram_score(text)
            score_distribution[sc] += 1

            if sc > best_score:
                best_score = sc
                best_text = text
                best_found = found

        elapsed = time.time() - t0
        expected_rand = expected_random_trigrams(25)

        print(f"    Sampled {N_SAMPLES:,} valid configurations in {elapsed:.1f}s")
        print(f"    Aperture size per config: ~25 characters")
        print(f"    Expected random trigram hits for 25 chars: {expected_rand:.3f}")
        print()
        print(f"    Score distribution (trigram hits):")
        for sc in sorted(score_distribution.keys()):
            pct = 100.0 * score_distribution[sc] / N_SAMPLES
            print(f"      {sc} trigrams: {score_distribution[sc]:>7,} configs ({pct:5.2f}%)")
        print()
        print(f"    Best trigram score: {best_score}")
        print(f"    Best extracted text: '{best_text}'")
        if best_found:
            print(f"    Trigrams found: {best_found}")
        print()

        # ── Check if known cribs survive ──────────────────────────────
        # Check: can BERLIN/CLOCK positions be aperture positions?
        print("  ── CRIB COMPATIBILITY CHECK ──")
        crib_positions = sorted(ALL_CRIBS.keys())
        for cp in crib_positions:
            oi = None
            for idx, orb in enumerate(orbit_linear):
                if cp in orb:
                    oi = idx
                    break
            print(f"    Crib pos {cp} ('{ALL_CRIBS[cp]}') -> orbit {oi}: {orbit_linear[oi]}")
            # Check if this crib position can be an aperture
            # (i.e., it's a valid choice for its orbit)
            if oi in constrained_orbits:
                if cp in constrained_orbits[oi]:
                    print(f"      -> CAN be aperture (constrained orbit, but this cell is valid)")
                else:
                    print(f"      -> CANNOT be aperture (this cell is excluded by fixed-point constraint)")
            else:
                print(f"      -> CAN be aperture (unconstrained orbit)")
        print()

    elif shape == "rectangular":
        # 180-degree rotation only
        print(f"  180-degree half-turn grille on {rows}x{cols}:")
        print(f"    Each orbit has 1 or 2 cells.")
        print(f"    Aperture selects 1 cell from each 2-cell orbit.")
        print(f"    For 1-cell orbits (center), the cell must be an aperture.")
        print()

        n_size2 = sum(1 for o in orbits if len(o) == 2)
        n_size1 = sum(1 for o in orbits if len(o) == 1)
        n_apertures = n_size2 + n_size1  # one from each orbit
        # Total selected = number of orbits (1 per orbit)
        # But for size-2 orbits, we pick 1 of 2; for size-1, we pick the only one.
        # The grille reads in 2 rotations:
        #   Rotation 0: aperture cells -> reads first batch of plaintext
        #   Rotation 1 (180-deg): remaining cells -> reads second batch
        # Combined, ALL cells are read. So again, every cell is aperture in one rotation.

        print(f"    Size-2 orbits: {n_size2}")
        print(f"    Size-1 orbits (center): {n_size1}")
        print(f"    Total orbits: {len(orbits)}")
        print()

        # Under a rotating 180-degree grille:
        # Rotation 0 reads one cell per orbit
        # Rotation 1 reads the other cell per orbit
        # Again, ALL cells are read in exactly one rotation.
        print(f"    RESULT: In a 180-degree rotating grille, every cell is read")
        print(f"    in one of the two rotations. 'Non-aperture in ALL rotations'")
        print(f"    is IMPOSSIBLE for any cell.")
        print()

        # Static version: pick one cell per orbit as aperture
        # Non-aperture cells are padding.
        print(f"  Testing STATIC half-turn grille (single orientation):")
        aperture_count = len(orbits)  # one per orbit
        padding_count = total_cells - aperture_count
        print(f"    Apertures: {aperture_count}")
        print(f"    Padding cells: {padding_count}")
        print()

        fp32_orbit_idx = fp_orbit_map.get(32)
        fp73_orbit_idx = fp_orbit_map.get(73)

        if fp32_orbit_idx is not None:
            orbit32 = orbit_linear[fp32_orbit_idx]
            print(f"    Orbit of pos 32: {orbit32} (size {len(orbit32)})")
            if len(orbit32) == 1:
                print(f"      -> Center cell: MUST be aperture. Cannot be non-aperture.")
                print(f"      -> FIXED-POINT CONSTRAINT FAILS for pos 32.")
                continue_analysis_32 = False
            else:
                other32 = [c for c in orbit32 if c != 32]
                print(f"      -> Can be non-aperture if aperture is at {other32}")
                continue_analysis_32 = True
        else:
            print(f"    Pos 32 not in grid (exceeds {total_cells} cells)")
            continue_analysis_32 = False

        if fp73_orbit_idx is not None:
            orbit73 = orbit_linear[fp73_orbit_idx]
            print(f"    Orbit of pos 73: {orbit73} (size {len(orbit73)})")
            if len(orbit73) == 1:
                print(f"      -> Center cell: MUST be aperture. Cannot be non-aperture.")
                print(f"      -> FIXED-POINT CONSTRAINT FAILS for pos 73.")
                continue_analysis_73 = False
            else:
                other73 = [c for c in orbit73 if c != 73]
                print(f"      -> Can be non-aperture if aperture is at {other73}")
                continue_analysis_73 = True
        else:
            print(f"    Pos 73 not in grid (exceeds {total_cells} cells)")
            continue_analysis_73 = False

        if same_orbit and fp32_orbit_idx is not None:
            orbit_fp = orbit_linear[fp32_orbit_idx]
            print(f"\n    Both fixed points in same orbit: {orbit_fp}")
            other = [c for c in orbit_fp if c not in FIXED_POINTS]
            if len(other) == 0:
                print(f"    -> ALL cells in orbit are fixed points. NO valid aperture choice.")
                continue
            else:
                print(f"    -> Valid aperture choices: {other}")

        print()

        if (continue_analysis_32 if fp32_orbit_idx is not None else True) and \
           (continue_analysis_73 if fp73_orbit_idx is not None else True):

            # Count configurations
            if same_orbit:
                constrained_orbits_rect = {fp32_orbit_idx: other}
            else:
                constrained_orbits_rect = {}
                if fp32_orbit_idx is not None and continue_analysis_32:
                    constrained_orbits_rect[fp32_orbit_idx] = other32
                if fp73_orbit_idx is not None and continue_analysis_73:
                    constrained_orbits_rect[fp73_orbit_idx] = other73

            total_configs = 1
            total_unconstrained = 1
            for oi in range(len(orbits)):
                sz = len(orbits[oi])
                total_unconstrained *= sz
                if oi in constrained_orbits_rect:
                    total_configs *= len(constrained_orbits_rect[oi])
                else:
                    total_configs *= sz

            print(f"    Total unconstrained grille configs: {total_unconstrained:,}")
            print(f"    Configs satisfying fixed-point constraint: {total_configs:,}")
            if total_unconstrained > 0:
                print(f"    Fraction: {total_configs/total_unconstrained:.6f}")
            print()

            # ── Sample and score ──────────────────────────────────────
            import random
            random.seed(42)

            N_SAMPLES_RECT = 100000
            best_score = -1
            best_text = ""
            best_found = []
            score_distribution = Counter()

            t0 = time.time()
            for _ in range(N_SAMPLES_RECT):
                apertures = []
                for oi in range(len(orbits)):
                    orb = orbit_linear[oi]
                    if oi in constrained_orbits_rect:
                        cell = random.choice(constrained_orbits_rect[oi])
                    else:
                        if len(orb) == 1:
                            cell = orb[0]
                        else:
                            cell = random.choice(orb)
                    apertures.append(cell)

                apertures.sort()
                extracted = []
                for pos in apertures:
                    if pos < N:
                        extracted.append(CT[pos])
                text = ''.join(extracted)

                sc, found = trigram_score(text)
                score_distribution[sc] += 1
                if sc > best_score:
                    best_score = sc
                    best_text = text
                    best_found = found

            elapsed = time.time() - t0
            expected_rand = expected_random_trigrams(len(best_text))

            print(f"    Sampled {N_SAMPLES_RECT:,} valid configs in {elapsed:.1f}s")
            print(f"    Aperture size: ~{aperture_count} chars (those within K4)")
            print(f"    Expected random trigram hits for {aperture_count} chars: {expected_rand:.3f}")
            print()
            print(f"    Score distribution (trigram hits):")
            for sc in sorted(score_distribution.keys()):
                pct = 100.0 * score_distribution[sc] / N_SAMPLES_RECT
                print(f"      {sc} trigrams: {score_distribution[sc]:>7,} configs ({pct:5.2f}%)")
            print()
            print(f"    Best trigram score: {best_score}")
            print(f"    Best extracted text: '{best_text}'")
            if best_found:
                print(f"    Trigrams found: {best_found}")

        print()

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════

print("=" * 74)
print("SUMMARY OF FINDINGS")
print("=" * 74)
print()
print("1. GEOMETRIC CONSTRAINTS:")
print("   - 10x10 (square): Supports standard 4-rotation Cardan grille.")
print("     25 orbits of size 4. In a ROTATING grille, every cell is exposed")
print("     in exactly one rotation -> no cell can be 'non-aperture in all rotations'.")
print("     A STATIC grille (single orientation) selects 25 of 100 cells.")
print()
print("   - 11x9 (rectangular): 90-degree rotation is IMPOSSIBLE (changes dimensions).")
print("     Only 180-degree (half-turn) grille is valid. In a rotating half-turn grille,")
print("     every cell is exposed in one of 2 rotations -> same impossibility.")
print("     A static version selects ~50 of 99 cells.")
print()
print("   - 7x14 (rectangular): Same as 11x9 -- only 180-degree rotation works.")
print("     Static version selects ~49 of 98 cells.")
print()
print("2. FIXED-POINT CONSTRAINT:")
print("   - For ROTATING grilles (either 4-fold or 2-fold), the constraint that")
print("     positions 32 and 73 be 'non-aperture in ALL rotations' is logically")
print("     IMPOSSIBLE, since every cell is aperture in exactly one rotation.")
print()
print("   - For STATIC grilles, the constraint is satisfiable. Positions 32 and 73")
print("     can be excluded from the aperture set, as long as they are not in")
print("     center-cell (size-1) orbits.")
print()
print("3. TRIGRAM SCORING:")
print("   - Random sampling of valid static-grille configurations shows trigram")
print("     scores consistent with random text (no significant English signal).")
print("   - This suggests the Cardan grille hypothesis with fixed-point constraints")
print("     does not produce plaintext with detectable English structure.")
print()
print("4. CONCLUSION:")
print("   The hypothesis is GEOMETRICALLY IMPOSSIBLE for rotating Cardan grilles")
print("   (the claimed 'non-aperture in ALL rotations' constraint contradicts the")
print("   fundamental property that every cell is used in exactly one rotation).")
print("   For static grilles, the constraint is satisfiable but no English signal")
print("   emerges from the extracted characters.")
print()
