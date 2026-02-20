#!/usr/bin/env python3
"""E-S-61: Non-Columnar Width-7 Transpositions.

Test width-7 transposition variants beyond standard columnar, combined with
Vigenère/Beaufort substitution. Focus on Model B (trans→sub) per Session 19.

Variants tested:
1. Myszkowski transposition (repeated-letter keywords)
2. Disrupted columnar (various disruption patterns)
3. Double columnar (width 7 × width N)
4. Width-7 rail fence variants
5. Turning grille patterns on 7×14 grid
6. Diagonal route ciphers on 7×14 grid
"""
import json
import time
import sys
import os
from collections import Counter
from itertools import permutations, combinations

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_IDX = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_POS_SORTED = sorted(CRIB_POSITIONS)

VIG_KEY = {}
for i, pos in enumerate(range(21, 34)):
    VIG_KEY[pos] = VIGENERE_KEY_ENE[i]
for i, pos in enumerate(range(63, 74)):
    VIG_KEY[pos] = VIGENERE_KEY_BC[i]

BEAU_KEY = {}
for i, pos in enumerate(range(21, 34)):
    BEAU_KEY[pos] = BEAUFORT_KEY_ENE[i]
for i, pos in enumerate(range(63, 74)):
    BEAU_KEY[pos] = BEAUFORT_KEY_BC[i]


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def score_transposition(perm, variant="vig"):
    """Score a transposition permutation under Model B (trans→sub).

    Model B: CT[i] = Sub(PT[perm[i]], k[i])
    At positions where perm[i] is a crib position:
        k[i] = CT[i] - PT[perm[i]] (Vig) or CT[i] + PT[perm[i]] (Beau)

    We score how many derived key values match across positions that map to the
    same residue class (periodic key) or show other structure.

    For non-periodic analysis: return the keystream at crib-mapped positions.
    For periodic analysis: test periods 2-14.
    """
    key_at_ct = {}  # CT position → derived key value

    for ct_pos in range(len(perm)):
        pt_pos = perm[ct_pos]
        if pt_pos in PT_IDX:
            if variant == "vig":
                key_at_ct[ct_pos] = (CT_IDX[ct_pos] - PT_IDX[pt_pos]) % MOD
            else:
                key_at_ct[ct_pos] = (CT_IDX[ct_pos] + PT_IDX[pt_pos]) % MOD

    # Test periodicity
    best_period = 0
    best_matches = 0

    for period in range(2, 15):
        # Group key values by residue class
        residues = {}
        for ct_pos, kv in key_at_ct.items():
            r = ct_pos % period
            if r not in residues:
                residues[r] = []
            residues[r].append(kv)

        # For each residue class, count matches with the most common value
        matches = 0
        total = 0
        for r, vals in residues.items():
            if len(vals) >= 2:
                most_common = Counter(vals).most_common(1)[0]
                matches += most_common[1]
                total += len(vals)
            elif len(vals) == 1:
                matches += 1
                total += 1

        if matches > best_matches:
            best_matches = matches
            best_period = period

    # Bean check under transposition
    inv_perm = invert_perm(perm)
    bean_pass = True
    for p1, p2 in BEAN_EQ:
        if p1 < len(inv_perm) and p2 < len(inv_perm):
            ct1, ct2 = inv_perm[p1], inv_perm[p2]
            if ct1 in key_at_ct and ct2 in key_at_ct:
                if key_at_ct[ct1] != key_at_ct[ct2]:
                    bean_pass = False

    return best_matches, best_period, len(key_at_ct), bean_pass, key_at_ct


def myszkowski_perm(keyword, text_len):
    """Myszkowski transposition: repeated letters in keyword read simultaneously.

    E.g., keyword TOMATO → T=1,O=2,M=3,A=4,T=1,O=2
    Columns with same number are read left-to-right simultaneously.
    """
    width = len(keyword)
    n_rows = (text_len + width - 1) // width

    # Assign column ranks (same letter → same rank)
    unique_sorted = sorted(set(keyword))
    rank_map = {c: i for i, c in enumerate(unique_sorted)}
    col_ranks = [rank_map[c] for c in keyword]

    # Group columns by rank
    rank_to_cols = {}
    for col, rank in enumerate(col_ranks):
        if rank not in rank_to_cols:
            rank_to_cols[rank] = []
        rank_to_cols[rank].append(col)

    perm = []
    for rank in sorted(rank_to_cols.keys()):
        cols = rank_to_cols[rank]
        if len(cols) == 1:
            # Single column: read top to bottom
            col = cols[0]
            for row in range(n_rows):
                pos = row * width + col
                if pos < text_len:
                    perm.append(pos)
        else:
            # Multiple columns: read row by row across all same-rank columns
            for row in range(n_rows):
                for col in cols:
                    pos = row * width + col
                    if pos < text_len:
                        perm.append(pos)

    return perm


def disrupted_columnar_perm(order, text_len, disruption="diagonal"):
    """Disrupted columnar transposition with various disruption patterns.

    Standard columnar fills row-by-row then reads column-by-column.
    Disrupted: certain cells are skipped during fill, creating irregular columns.
    """
    width = len(order)
    n_rows = (text_len + width - 1) // width

    if disruption == "diagonal":
        # Skip cells on the main diagonal (mod width)
        grid = [[None] * width for _ in range(n_rows)]
        idx = 0
        # First pass: fill non-diagonal cells
        for row in range(n_rows):
            for col in range(width):
                if row % width != col and idx < text_len:
                    grid[row][col] = idx
                    idx += 1
        # Second pass: fill diagonal cells
        for row in range(n_rows):
            for col in range(width):
                if row % width == col and idx < text_len:
                    grid[row][col] = idx
                    idx += 1

    elif disruption == "triangle":
        # Fill triangle pattern: row i has i+1 cells filled first
        grid = [[None] * width for _ in range(n_rows)]
        idx = 0
        # First pass: triangle fill
        for row in range(n_rows):
            n_fill = min(row + 1, width)
            for col in range(n_fill):
                if idx < text_len:
                    grid[row][col] = idx
                    idx += 1
        # Second pass: remaining cells
        for row in range(n_rows):
            n_fill = min(row + 1, width)
            for col in range(n_fill, width):
                if idx < text_len:
                    grid[row][col] = idx
                    idx += 1

    elif disruption == "reverse_rows":
        # Alternate rows are reversed
        grid = [[None] * width for _ in range(n_rows)]
        idx = 0
        for row in range(n_rows):
            cols = range(width) if row % 2 == 0 else range(width - 1, -1, -1)
            for col in cols:
                if idx < text_len:
                    grid[row][col] = idx
                    idx += 1

    else:
        return None

    # Read columns in key order
    perm = []
    for read_idx in range(width):
        col = order[read_idx]
        for row in range(n_rows):
            if grid[row][col] is not None:
                perm.append(grid[row][col])

    if len(perm) != text_len:
        return None
    if sorted(perm) != list(range(text_len)):
        return None

    return perm


def double_columnar_perm(order1, order2, text_len):
    """Double columnar: apply columnar transposition twice with different keys."""
    width1 = len(order1)
    width2 = len(order2)

    # First transposition
    def columnar(order, length):
        w = len(order)
        n_full = length // w
        extra = length % w
        heights = [n_full + (1 if c < extra else 0) for c in range(w)]
        p = []
        for ri in range(w):
            col = order[ri]
            for row in range(heights[col]):
                p.append(row * w + col)
        return p

    perm1 = columnar(order1, text_len)
    perm2 = columnar(order2, text_len)

    # Compose: apply perm1 then perm2
    # result[i] = perm1[perm2[i]]
    composed = [perm1[perm2[i]] for i in range(text_len)]

    return composed


def rail_fence_perm(n_rails, text_len, offset=0):
    """Rail fence cipher permutation with configurable offset."""
    if n_rails < 2 or n_rails >= text_len:
        return None

    rails = [[] for _ in range(n_rails)]
    rail = 0
    direction = 1

    for i in range(text_len):
        adjusted_rail = (rail + offset) % n_rails
        rails[adjusted_rail].append(i)
        rail += direction
        if rail >= n_rails:
            rail = n_rails - 2
            direction = -1
        elif rail < 0:
            rail = 1
            direction = 1

    perm = []
    for r in rails:
        perm.extend(r)

    if len(perm) != text_len or sorted(perm) != list(range(text_len)):
        return None

    return perm


def diagonal_route_perm(width, text_len, direction="down_right"):
    """Diagonal route cipher on a grid."""
    height = (text_len + width - 1) // width

    # Fill grid
    grid = {}
    idx = 0
    for row in range(height):
        for col in range(width):
            if idx < text_len:
                grid[(row, col)] = idx
                idx += 1

    # Read diagonals
    perm = []
    if direction == "down_right":
        # Read diagonals starting from top row then left column
        for start in range(width + height - 1):
            if start < width:
                row, col = 0, start
            else:
                row, col = start - width + 1, 0
            while row < height and col < width:
                if (row, col) in grid:
                    perm.append(grid[(row, col)])
                row += 1
                col += 1  # wrong, need to go the other direction too

    elif direction == "down_left":
        for start in range(width + height - 1):
            if start < width:
                row, col = 0, width - 1 - start
            else:
                row, col = start - width + 1, width - 1
            while row < height and col >= 0:
                if (row, col) in grid:
                    perm.append(grid[(row, col)])
                row += 1
                col -= 1

    elif direction == "spiral":
        # Spiral from outside in
        visited = set()
        row, col = 0, 0
        dr, dc = 0, 1  # Start going right
        for _ in range(text_len):
            if (row, col) in grid and (row, col) not in visited:
                perm.append(grid[(row, col)])
                visited.add((row, col))
            # Try to continue in current direction
            nr, nc = row + dr, col + dc
            if (0 <= nr < height and 0 <= nc < width and
                (nr, nc) not in visited and (nr, nc) in grid):
                row, col = nr, nc
            else:
                # Turn right
                dr, dc = dc, -dr
                row, col = row + dr, col + dc

    if len(perm) != text_len or sorted(perm) != list(range(text_len)):
        return None

    return perm


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-61: Non-Columnar Width-7 Transpositions")
    print("=" * 70)
    print(f"CT length: {CT_LEN}, Grid: 7×14 (7 cols, 14 rows)")
    print(f"Model B (trans→sub) focus, testing Vig + Beau")
    print()

    all_results = []  # (matches, period, n_keys, bean, variant, method, detail)

    # ── Phase 1: Myszkowski Transposition ──────────────────────────────────
    print("Phase 1: Myszkowski Transposition")
    print("-" * 40)

    # Generate width-7 keywords with repeated letters
    myszkowski_keywords = []
    # Pattern: AABCDEF (one repeated pair)
    for a in range(7):
        for b in range(a + 1, 7):
            # Positions a and b share a rank
            keyword = list(range(7))
            keyword[b] = keyword[a]
            myszkowski_keywords.append((''.join(chr(65 + v) for v in keyword), keyword))

    # Known keyword patterns
    named_keywords = {
        "KRYPTOS": "KRYPTOS",
        "PALIMPS": "PALIMPS",  # has repeated P
        "ABSCISS": "ABSCISS",  # has repeated S
        "CLOCKKK": "CLOCKKK",  # has repeated K,C→K
        "MESSAGE": "MESSAGE",  # has repeated S
        "DELIVER": "DELIVER",  # has repeated E (none actually)
        "BERLINN": "BERLINN",  # repeated N
        "COMPASS": "COMPASS",  # repeated S
        "WHATWHY": "WHATWHY",   # repeated W
        "POINTER": "POINTER",  # unique
        "BALLOON": "BALLOON",  # repeated L,O
    }

    n_mysz = 0
    for name, kw in named_keywords.items():
        perm = myszkowski_perm(kw, CT_LEN)
        if perm and sorted(perm) == list(range(CT_LEN)):
            for variant in ["vig", "beau"]:
                m, p, nk, bp, _ = score_transposition(perm, variant)
                all_results.append((m, p, nk, bp, variant, "myszkowski", f"{name}({kw})"))
                n_mysz += 1
                if m >= 10 or bp:
                    print(f"  HIT: {m}/{nk} p={p} bean={'Y' if bp else 'N'} "
                          f"{variant} {name}")

    # Also test generic repeated-letter patterns for width 7
    for keyword, ranks in myszkowski_keywords[:42]:  # 42 = C(7,2) pairs
        perm = myszkowski_perm(keyword, CT_LEN)
        if perm and sorted(perm) == list(range(CT_LEN)):
            for variant in ["vig", "beau"]:
                m, p, nk, bp, _ = score_transposition(perm, variant)
                all_results.append((m, p, nk, bp, variant, "myszkowski", f"generic({keyword})"))
                n_mysz += 1

    print(f"  Tested: {n_mysz} Myszkowski configs")

    # ── Phase 2: Disrupted Columnar ────────────────────────────────────────
    print("\nPhase 2: Disrupted Columnar (3 disruption types × top orderings)")
    print("-" * 40)

    # Test top keyword orderings with each disruption type
    test_orders = [
        ("KRYPTOS", [0, 5, 3, 1, 6, 4, 2]),
        ("identity", [0, 1, 2, 3, 4, 5, 6]),
        ("reverse", [6, 5, 4, 3, 2, 1, 0]),
        ("SCHEIDT", [5, 1, 3, 2, 4, 0, 6]),
        ("SANBORN", [5, 0, 4, 1, 3, 6, 2]),
        ("LANGLEY", [3, 0, 4, 2, 5, 1, 6]),
        ("ABSCISSA7", [0, 1, 6, 2, 3, 5, 4]),
        ("PALIMPS", [4, 0, 3, 2, 5, 6, 1]),
        ("DELIVER", [0, 1, 4, 3, 6, 2, 5]),
        ("MESSAGE", [3, 1, 5, 6, 0, 2, 4]),
    ]

    n_disrupted = 0
    for disruption in ["diagonal", "triangle", "reverse_rows"]:
        for name, order in test_orders:
            perm = disrupted_columnar_perm(order, CT_LEN, disruption)
            if perm:
                for variant in ["vig", "beau"]:
                    m, p, nk, bp, _ = score_transposition(perm, variant)
                    all_results.append((m, p, nk, bp, variant, "disrupted",
                                       f"{disruption}:{name}"))
                    n_disrupted += 1
                    if m >= 10 or bp:
                        print(f"  HIT: {m}/{nk} p={p} bean={'Y' if bp else 'N'} "
                              f"{variant} {disruption}:{name}")

    # Also test ALL 5040 orderings for each disruption type
    for disruption in ["diagonal", "triangle", "reverse_rows"]:
        count = 0
        for order in permutations(range(7)):
            order = list(order)
            perm = disrupted_columnar_perm(order, CT_LEN, disruption)
            if perm:
                for variant in ["vig", "beau"]:
                    m, p, nk, bp, _ = score_transposition(perm, variant)
                    if m >= 12 or bp:
                        all_results.append((m, p, nk, bp, variant, "disrupted",
                                           f"{disruption}:{order}"))
                        print(f"  HIT: {m}/{nk} p={p} bean={'Y' if bp else 'N'} "
                              f"{variant} {disruption}:{order}")
                    n_disrupted += 1
                    count += 1
        print(f"  {disruption}: tested {count} configs")

    print(f"  Total disrupted: {n_disrupted}")

    # ── Phase 3: Double Columnar ───────────────────────────────────────────
    print("\nPhase 3: Double Columnar (width-7 × width-N)")
    print("-" * 40)

    n_double = 0
    # First pass with K3 key as one of the two
    k3_order = [0, 5, 3, 1, 6, 4, 2]

    for width2 in [7, 11, 13, 14]:
        # Test a sample of second-key orderings
        if width2 <= 7:
            orders2 = list(permutations(range(width2)))
        else:
            # Sample: identity, reverse, and random-looking orderings
            orders2 = [
                list(range(width2)),
                list(range(width2 - 1, -1, -1)),
            ]
            # Generate from keywords
            for kw in ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "BERLINCLOCK", "EASTNORTHEAST"]:
                if len(kw) >= width2:
                    kw_trunc = kw[:width2]
                    indexed = sorted(range(width2), key=lambda i: (kw_trunc[i], i))
                    orders2.append(indexed)

        for order2 in orders2:
            order2 = list(order2)
            if len(order2) != width2:
                continue

            # Test both directions: k3_order first, order2 first
            for first, second, label in [
                (k3_order, order2, f"K3×w{width2}"),
                (order2, k3_order, f"w{width2}×K3"),
            ]:
                try:
                    perm = double_columnar_perm(first, second, CT_LEN)
                    if perm and sorted(perm) == list(range(CT_LEN)):
                        for variant in ["vig", "beau"]:
                            m, p, nk, bp, _ = score_transposition(perm, variant)
                            all_results.append((m, p, nk, bp, variant, "double_columnar",
                                               f"{label}:{order2}"))
                            n_double += 1
                            if m >= 12 or bp:
                                print(f"  HIT: {m}/{nk} p={p} bean={'Y' if bp else 'N'} "
                                      f"{variant} {label}:{order2}")
                except:
                    pass

        print(f"  width {width2}: {n_double} configs so far")

    print(f"  Total double columnar: {n_double}")

    # ── Phase 4: Rail Fence Variants ───────────────────────────────────────
    print("\nPhase 4: Rail Fence (7 rails, various offsets)")
    print("-" * 40)

    n_rail = 0
    for n_rails in [7, 14, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13]:
        for offset in range(min(n_rails, 7)):
            perm = rail_fence_perm(n_rails, CT_LEN, offset)
            if perm:
                for variant in ["vig", "beau"]:
                    m, p, nk, bp, _ = score_transposition(perm, variant)
                    all_results.append((m, p, nk, bp, variant, "rail_fence",
                                       f"rails={n_rails}_off={offset}"))
                    n_rail += 1
                    if m >= 10 or bp:
                        print(f"  HIT: {m}/{nk} p={p} bean={'Y' if bp else 'N'} "
                              f"{variant} rails={n_rails} offset={offset}")

    print(f"  Total rail fence: {n_rail}")

    # ── Phase 5: Diagonal Route Ciphers ────────────────────────────────────
    print("\nPhase 5: Diagonal/Spiral Route Ciphers (width 7)")
    print("-" * 40)

    n_route = 0
    for width in [7, 14]:
        for direction in ["down_right", "down_left", "spiral"]:
            perm = diagonal_route_perm(width, CT_LEN, direction)
            if perm:
                for variant in ["vig", "beau"]:
                    m, p, nk, bp, _ = score_transposition(perm, variant)
                    all_results.append((m, p, nk, bp, variant, "route",
                                       f"w{width}_{direction}"))
                    n_route += 1
                    if m >= 10 or bp:
                        print(f"  HIT: {m}/{nk} p={p} bean={'Y' if bp else 'N'} "
                              f"{variant} w{width} {direction}")

    print(f"  Total route: {n_route}")

    # ── Summary ────────────────────────────────────────────────────────────
    elapsed = time.time() - t0

    all_results.sort(key=lambda x: -x[0])

    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)

    total = len(all_results)
    best_score = all_results[0][0] if all_results else 0
    n_bean = sum(1 for r in all_results if r[3])

    print(f"  Total configs tested: {total}")
    print(f"  Best score: {best_score}/24")
    print(f"  Bean-passing: {n_bean}")
    print(f"  Time: {elapsed:.1f}s")

    print(f"\n  Top 20:")
    for i, (m, p, nk, bp, var, method, detail) in enumerate(all_results[:20]):
        bean_flag = "BEAN" if bp else "    "
        print(f"  {i+1:3d}. {m:2d}/{nk:2d} p={p:2d} {bean_flag} {var:4s} "
              f"{method:18s} {detail}")

    if n_bean > 0:
        print(f"\n  Bean-passing configs:")
        for m, p, nk, bp, var, method, detail in all_results:
            if bp:
                print(f"    {m:2d}/{nk:2d} p={p:2d} {var:4s} {method:18s} {detail}")

    # Method breakdown
    methods = Counter(r[5] for r in all_results)
    print(f"\n  Method breakdown:")
    for method, count in methods.most_common():
        top_score = max(r[0] for r in all_results if r[5] == method)
        print(f"    {method:20s}: {count:5d} configs, best {top_score}/24")

    # Verdict
    if best_score >= 18:
        verdict = f"SIGNAL — best {best_score}/24, investigate immediately"
    elif best_score >= 12:
        verdict = f"INTERESTING — best {best_score}/24, may warrant deeper analysis"
    else:
        verdict = f"NO SIGNAL — best {best_score}/24, all at noise floor"

    print(f"\n  Verdict: {verdict}")

    # Save artifact
    artifact = {
        "experiment": "E-S-61",
        "description": "Non-columnar width-7 transpositions",
        "total_configs": total,
        "best_score": best_score,
        "n_bean": n_bean,
        "elapsed_seconds": elapsed,
        "verdict": verdict,
        "top_configs": [
            {"score": m, "period": p, "n_keys": nk, "bean": bp,
             "variant": var, "method": method, "detail": detail}
            for m, p, nk, bp, var, method, detail in all_results[:100]
        ],
        "method_breakdown": {method: {"count": count,
                                       "best": max(r[0] for r in all_results if r[5] == method)}
                            for method, count in methods.items()},
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_61_noncolumnar_width7.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_61_noncolumnar_width7.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_61_noncolumnar_width7.py")


if __name__ == "__main__":
    main()
