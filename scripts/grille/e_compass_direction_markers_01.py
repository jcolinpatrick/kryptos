#!/usr/bin/env python3
"""
Cipher: NSEW as direction markers / compass cipher
Family: grille
Status: active
Keyspace: ~5000 configs (grid widths × interpretations × decrypt variants)
Last run: never
Best score: n/a

Hypothesis: N, S, E, W letters in K4 ciphertext are not encrypted content
but compass-direction markers that control reading order through a grid.
"Compass cipher" from Sanborn's notebook = the compass letters tell you
where to go.

K4 NSEW positions (0-indexed):
  N: [29, 60, 63]         (3 occurrences)
  S: [13, 32, 33, 39, 42, 43]  (6 occurrences)
  E: [44, 92]             (2 occurrences)
  W: [20, 36, 48, 58, 74]      (5 occurrences)
  Total: 16/97, leaving 81 non-NSEW characters

Tests:
  Phase 1: NSEW as null positions — remove them, decrypt remaining 81 chars
  Phase 2: Direction-guided grid walk — NSEW change reading direction in grid
  Phase 3: NSEW as segment delimiters — split CT at NSEW, reorder segments
  Phase 4: NSEW positions as grille mask — keep only NSEW positions (or inverse)
  Phase 5: Combined: direction walk + substitution layer
"""

import sys
import os
from itertools import permutations
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant

# ── NSEW analysis ──────────────────────────────────────────────────────────

NSEW_SET = frozenset("NSEW")
NSEW_POSITIONS = [i for i, c in enumerate(CT) if c in NSEW_SET]
NON_NSEW_POSITIONS = [i for i, c in enumerate(CT) if c not in NSEW_SET]
CT_STRIPPED = "".join(CT[i] for i in NON_NSEW_POSITIONS)  # 81 chars

# Direction vectors for grid reading: (row_delta, col_delta)
DIR_VECTORS = {
    'N': (-1, 0),
    'S': (1, 0),
    'E': (0, 1),
    'W': (0, -1),
}

# Keywords to test
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "COMPASS", "LODESTONE",
    "MAGNETIC", "BEARING", "POINT", "SHADOW", "DEFECTOR",
    "FIVE", "SEVEN", "NORTH", "EAST", "WEST", "SOUTH",
]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

best_score = 0
best_result = None
total_tested = 0


def report(label, pt, method):
    global best_score, best_result, total_tested
    total_tested += 1

    sb = score_candidate(pt) if len(pt) >= 74 else None
    fb = score_candidate_free(pt)

    anchored = sb.crib_score if sb else 0
    free = fb.crib_score
    effective = max(anchored, free)

    if effective > best_score:
        best_score = effective
        best_result = (label, pt[:80], method, effective)

    if effective >= 10:
        print(f"\n*** INTERESTING [{label}] score={effective}/24 ***")
        print(f"  Method: {method}")
        print(f"  PT: {pt[:80]}")
        if sb:
            print(f"  Anchored: {sb.summary}")
        print(f"  Free: {fb.summary}")


def keyword_to_nums(kw):
    return [ALPH_IDX[c] for c in kw.upper() if c in ALPH_IDX]


# ══════════════════════════════════════════════════════════════════════════
# Phase 1: NSEW as null positions — strip and decrypt 81 chars
# ══════════════════════════════════════════════════════════════════════════

def phase_1():
    print("=" * 70)
    print("PHASE 1: Strip NSEW (16 nulls), decrypt remaining 81 chars")
    print(f"  Stripped CT ({len(CT_STRIPPED)} chars): {CT_STRIPPED}")
    print("=" * 70)

    before = total_tested

    # Direct scoring of stripped text
    fb = score_candidate_free(CT_STRIPPED)
    print(f"  Raw stripped text free score: {fb.crib_score}/24")

    for kw in KEYWORDS:
        key = keyword_to_nums(kw)
        if not key:
            continue
        for variant in VARIANTS:
            pt = decrypt_text(CT_STRIPPED, key, variant)
            report("P1-strip", pt, f"strip_NSEW + {variant.value}(key={kw})")

    # Also try with identity key (no substitution — pure null removal)
    report("P1-identity", CT_STRIPPED, "strip_NSEW only (no decrypt)")

    print(f"  Phase 1: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase 2: Direction-guided grid walk
# ══════════════════════════════════════════════════════════════════════════

def direction_walk(ct, width, initial_dir='E'):
    """Walk through a grid. When hitting N/S/E/W, change direction.
    Collect non-NSEW characters in walk order."""
    rows = (len(ct) + width - 1) // width
    grid = []
    for r in range(rows):
        row = []
        for c in range(width):
            idx = r * width + c
            if idx < len(ct):
                row.append(ct[idx])
            else:
                row.append(None)
        grid.append(row)

    # Start from various positions, initial direction
    dr, dc = DIR_VECTORS[initial_dir]
    result = []
    visited = set()
    r, c = 0, 0

    for _ in range(len(ct) + 10):
        if r < 0 or r >= rows or c < 0 or c >= width:
            # Wrap around
            r = r % rows
            c = c % width
        if (r, c) in visited:
            # Find next unvisited
            found = False
            for nr in range(rows):
                for nc in range(width):
                    if (nr, nc) not in visited and grid[nr][nc] is not None:
                        r, c = nr, nc
                        found = True
                        break
                if found:
                    break
            if not found:
                break

        visited.add((r, c))
        ch = grid[r][c]
        if ch is None:
            break

        if ch in NSEW_SET:
            # Change direction
            dr, dc = DIR_VECTORS[ch]
        else:
            result.append(ch)

        # Move
        r += dr
        c += dc

    return "".join(result)


def phase_2():
    print("\n" + "=" * 70)
    print("PHASE 2: Direction-guided grid walk (NSEW = change direction)")
    print("=" * 70)

    before = total_tested

    for width in range(7, 15):
        for init_dir in ['E', 'S', 'N', 'W']:
            walked = direction_walk(CT, width, init_dir)
            if len(walked) < 20:
                continue

            # Score raw walk output
            report(f"P2-w{width}-{init_dir}-raw", walked,
                   f"dir_walk(w={width}, init={init_dir})")

            # Decrypt with keywords
            for kw in KEYWORDS[:8]:  # Top keywords
                key = keyword_to_nums(kw)
                if not key:
                    continue
                for variant in VARIANTS[:2]:  # Vig + Beau
                    pt = decrypt_text(walked, key, variant)
                    report(f"P2-w{width}-{init_dir}", pt,
                           f"dir_walk(w={width}, init={init_dir}) + {variant.value}({kw})")

    print(f"  Phase 2: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase 3: NSEW as segment delimiters
# ══════════════════════════════════════════════════════════════════════════

def phase_3():
    print("\n" + "=" * 70)
    print("PHASE 3: NSEW as segment delimiters — split and reorder")
    print("=" * 70)

    before = total_tested

    # Split CT at NSEW positions
    segments = []
    current = []
    direction_sequence = []
    for i, c in enumerate(CT):
        if c in NSEW_SET:
            if current:
                segments.append("".join(current))
            current = []
            direction_sequence.append(c)
        else:
            current.append(c)
    if current:
        segments.append("".join(current))

    print(f"  {len(segments)} segments: {[len(s) for s in segments]}")
    print(f"  Direction sequence: {''.join(direction_sequence)}")

    # Test various reorderings of segments
    # Based on compass directions: N=up, S=down, E=right, W=left
    # Try reading segments in direction-ordered groups
    n_segs = len(segments)

    if n_segs <= 10:
        # Group by direction that precedes each segment
        # First segment has no preceding direction
        # Try: concatenate in compass order (N segments, then E, then S, then W)
        for order in ['NESW', 'NWSE', 'ENWS', 'WENS', 'SENW', 'SWNE']:
            reordered = []
            # Map each segment to the direction that precedes it
            seg_dirs = [None] + direction_sequence[:n_segs - 1]
            for target_dir in order:
                for idx, d in enumerate(seg_dirs):
                    if d == target_dir and idx < n_segs:
                        reordered.append(segments[idx])
            # Add any unmapped segments (first segment has no direction)
            for idx, d in enumerate(seg_dirs):
                if d is None and idx < n_segs:
                    reordered.append(segments[idx])

            text = "".join(reordered)
            if len(text) < 20:
                continue

            report(f"P3-order-{order}", text, f"segment_reorder({order})")

            for kw in KEYWORDS[:6]:
                key = keyword_to_nums(kw)
                if not key:
                    continue
                for variant in VARIANTS[:2]:
                    pt = decrypt_text(text, key, variant)
                    report(f"P3-{order}", pt,
                           f"segment_reorder({order}) + {variant.value}({kw})")

    # Also try reversing segments indicated by S/W (south/west = "backwards")
    reversed_segs = []
    seg_dirs_full = [None] + direction_sequence[:n_segs - 1]
    for idx, seg in enumerate(segments):
        d = seg_dirs_full[idx] if idx < len(seg_dirs_full) else None
        if d in ('S', 'W'):
            reversed_segs.append(seg[::-1])
        else:
            reversed_segs.append(seg)
    text_rev = "".join(reversed_segs)
    report("P3-reverse-SW", text_rev, "reverse segments after S/W markers")

    for kw in KEYWORDS[:6]:
        key = keyword_to_nums(kw)
        if not key:
            continue
        for variant in VARIANTS[:2]:
            pt = decrypt_text(text_rev, key, variant)
            report(f"P3-rev-SW", pt,
                   f"reverse_SW_segments + {variant.value}({kw})")

    print(f"  Phase 3: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase 4: NSEW positions define a grille mask
# ══════════════════════════════════════════════════════════════════════════

def phase_4():
    print("\n" + "=" * 70)
    print("PHASE 4: NSEW positions as grille mask (compass rose selects)")
    print("=" * 70)

    before = total_tested

    # Model A: NSEW positions are the REAL text (16 chars), rest is chaff
    nsew_text = "".join(CT[i] for i in NSEW_POSITIONS)
    print(f"  NSEW-only text (16 chars): {nsew_text}")
    report("P4-nsew-only", nsew_text, "keep only NSEW positions")

    # Model B: Non-NSEW positions near NSEW markers are selected
    # "Compass points to adjacent letters"
    for radius in [1, 2, 3]:
        selected = set()
        for pos in NSEW_POSITIONS:
            for offset in range(-radius, radius + 1):
                adj = pos + offset
                if 0 <= adj < CT_LEN and adj not in NSEW_POSITIONS:
                    selected.add(adj)
        selected_text = "".join(CT[i] for i in sorted(selected))
        report(f"P4-adjacent-r{radius}", selected_text,
               f"NSEW neighbors radius={radius}")

        for kw in KEYWORDS[:6]:
            key = keyword_to_nums(kw)
            if not key:
                continue
            for variant in VARIANTS[:2]:
                pt = decrypt_text(selected_text, key, variant)
                report(f"P4-adj-r{radius}", pt,
                       f"NSEW_neighbors(r={radius}) + {variant.value}({kw})")

    # Model C: NSEW letter value as offset — N=13, S=18, E=4, W=22
    # Use NSEW value to select a position offset from the marker
    nsew_vals = {'N': 13, 'S': 18, 'E': 4, 'W': 22}
    for use_mod in [True, False]:
        selected_chars = []
        for pos in NSEW_POSITIONS:
            letter = CT[pos]
            offset = nsew_vals[letter]
            target = (pos + offset) % CT_LEN if use_mod else pos + offset
            if 0 <= target < CT_LEN:
                selected_chars.append(CT[target])
        text = "".join(selected_chars)
        mod_label = "mod97" if use_mod else "linear"
        report(f"P4-offset-{mod_label}", text,
               f"NSEW_value_offset({mod_label})")

    print(f"  Phase 4: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase 5: Direction walk + substitution (combined model)
# ══════════════════════════════════════════════════════════════════════════

def phase_5():
    print("\n" + "=" * 70)
    print("PHASE 5: Extended direction walk — start from each NSEW position")
    print("=" * 70)

    before = total_tested

    # Start the walk from each NSEW position (compass tells you WHERE to start)
    for width in [7, 8, 10, 11, 13, 14]:
        for start_pos in NSEW_POSITIONS[:8]:  # First 8 NSEW positions
            start_dir = CT[start_pos]
            rows = (CT_LEN + width - 1) // width
            start_r = start_pos // width
            start_c = start_pos % width

            # Build grid
            grid = []
            for r in range(rows):
                row = []
                for c in range(width):
                    idx = r * width + c
                    row.append(CT[idx] if idx < CT_LEN else None)
                grid.append(row)

            # Walk from this position
            dr, dc = DIR_VECTORS[start_dir]
            result = []
            visited = set()
            r, c = start_r, start_c

            for _ in range(CT_LEN + 10):
                if (r, c) in visited or r < 0 or r >= rows or c < 0 or c >= width:
                    r = r % rows
                    c = c % width
                    if (r, c) in visited:
                        found = False
                        for nr in range(rows):
                            for nc in range(width):
                                if (nr, nc) not in visited and grid[nr][nc] is not None:
                                    r, c = nr, nc
                                    found = True
                                    break
                            if found:
                                break
                        if not found:
                            break

                visited.add((r, c))
                ch = grid[r][c]
                if ch is None:
                    break

                if ch in NSEW_SET:
                    dr, dc = DIR_VECTORS[ch]
                else:
                    result.append(ch)

                r += dr
                c += dc

            walked = "".join(result)
            if len(walked) < 20:
                continue

            report(f"P5-w{width}-@{start_pos}", walked,
                   f"walk_from_NSEW(w={width}, start={start_pos}={start_dir})")

            for kw in KEYWORDS[:4]:
                key = keyword_to_nums(kw)
                if not key:
                    continue
                for variant in VARIANTS[:2]:
                    pt = decrypt_text(walked, key, variant)
                    report(f"P5-w{width}-@{start_pos}", pt,
                           f"walk_from(w={width},@{start_pos}) + {variant.value}({kw})")

    print(f"  Phase 5: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    print("COMPASS DIRECTION MARKERS INVESTIGATION")
    print(f"CT: {CT}")
    print(f"NSEW positions: {NSEW_POSITIONS}")
    print(f"NSEW count: {len(NSEW_POSITIONS)}/97")
    print(f"Non-NSEW: {len(NON_NSEW_POSITIONS)} chars")
    print(f"Direction sequence in CT order: {''.join(CT[i] for i in NSEW_POSITIONS)}")
    print()

    phase_1()
    phase_2()
    phase_3()
    phase_4()
    phase_5()

    print("\n" + "=" * 70)
    print(f"TOTAL: {total_tested} configurations tested")
    print(f"Best score: {best_score}/24")
    if best_result:
        label, pt, method, score = best_result
        print(f"  Label: {label}")
        print(f"  Method: {method}")
        print(f"  PT: {pt}")
    else:
        print("  No results above noise.")

    if best_score < 10:
        print("VERDICT: NOISE — NSEW direction marker hypothesis does not decrypt K4")
    elif best_score < 18:
        print("VERDICT: INTERESTING — investigate further")
    else:
        print("VERDICT: SIGNAL — requires detailed analysis!")
    print("=" * 70)


if __name__ == "__main__":
    main()
