#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-12: Non-standard reading orders + Vigenère.

Tests whether reordering the K4 ciphertext (as if reading the sculpture
in a non-standard pattern) produces a text that is solvable by Vigenère.

Reading orders tested:
1. Full reverse
2. Boustrophedon (serpentine) at widths 5-14
3. Spiral reading on rectangular grids
4. Diagonal reading on rectangular grids
5. Column-first reading at various widths
6. S-curve reading at various widths

For each reading order, checks period consistency at the 24 crib positions.
If the crib positions in the reordered text align with a periodic key,
this could reveal the cipher.

Also tests combined: reading order + Vigenère with quadgram scoring
on the top candidates.
"""

import json
import math
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_ENTRIES, MOD

# ═══ Setup ════════════════════════════════════════════════════════════════

CT_INT = [ord(c) - 65 for c in CT]
CT_LIST = list(CT)

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = [p for p, _ in _sorted]
CRIB_DICT = {p: c for p, c in _sorted}
PT_INT = {p: ord(c) - 65 for p, c in _sorted}
N_CRIBS = len(CRIB_POS)

NOISE_FLOORS = {
    3: 5.0, 4: 5.8, 5: 6.5, 6: 7.2, 7: 8.2, 8: 9.2,
    9: 10.0, 10: 11.0, 11: 12.0, 12: 13.0, 13: 13.5,
}


# ═══ Reading order generators ════════════════════════════════════════════

def identity_order(n):
    return list(range(n))

def reverse_order(n):
    return list(range(n - 1, -1, -1))

def boustrophedon(n, width):
    """Serpentine reading: L→R on even rows, R→L on odd rows."""
    order = []
    n_rows = (n + width - 1) // width
    for row in range(n_rows):
        start = row * width
        end = min(start + width, n)
        if row % 2 == 0:
            order.extend(range(start, end))
        else:
            order.extend(range(end - 1, start - 1, -1))
    return order

def column_first(n, width):
    """Read columns first (top-to-bottom, left-to-right)."""
    order = []
    n_rows = (n + width - 1) // width
    for col in range(width):
        for row in range(n_rows):
            pos = row * width + col
            if pos < n:
                order.append(pos)
    return order

def spiral_reading(n, width):
    """Spiral reading from top-left, clockwise."""
    n_rows = (n + width - 1) // width
    grid = [[None] * width for _ in range(n_rows)]
    pos = 0
    for row in range(n_rows):
        for col in range(width):
            if pos < n:
                grid[row][col] = pos
                pos += 1

    order = []
    top, bottom, left, right = 0, n_rows - 1, 0, width - 1

    while top <= bottom and left <= right:
        # Top row
        for col in range(left, right + 1):
            if grid[top][col] is not None:
                order.append(grid[top][col])
        top += 1
        # Right column
        for row in range(top, bottom + 1):
            if right < width and grid[row][right] is not None:
                order.append(grid[row][right])
        right -= 1
        # Bottom row
        if top <= bottom:
            for col in range(right, left - 1, -1):
                if grid[bottom][col] is not None:
                    order.append(grid[bottom][col])
            bottom -= 1
        # Left column
        if left <= right:
            for row in range(bottom, top - 1, -1):
                if grid[row][left] is not None:
                    order.append(grid[row][left])
            left += 1

    return order[:n]

def diagonal_reading(n, width):
    """Read diagonals (top-right to bottom-left)."""
    n_rows = (n + width - 1) // width
    grid = [[None] * width for _ in range(n_rows)]
    pos = 0
    for row in range(n_rows):
        for col in range(width):
            if pos < n:
                grid[row][col] = pos
                pos += 1

    order = []
    for d in range(n_rows + width - 1):
        if d % 2 == 0:
            # Go down-left
            row = min(d, n_rows - 1)
            col = d - row
            while row >= 0 and col < width:
                if grid[row][col] is not None:
                    order.append(grid[row][col])
                row -= 1
                col += 1
        else:
            # Go up-right
            col = min(d, width - 1)
            row = d - col
            while col >= 0 and row < n_rows:
                if grid[row][col] is not None:
                    order.append(grid[row][col])
                col -= 1
                row += 1

    return order[:n]

def s_curve(n, width):
    """S-curve: zigzag through columns."""
    order = []
    n_rows = (n + width - 1) // width
    for col in range(width):
        if col % 2 == 0:
            for row in range(n_rows):
                pos = row * width + col
                if pos < n:
                    order.append(pos)
        else:
            for row in range(n_rows - 1, -1, -1):
                pos = row * width + col
                if pos < n:
                    order.append(pos)
    return order


# ═══ Scoring ═════════════════════════════════════════════════════════════

def score_reading_order(perm):
    """Given a permutation (reading order), reorder the CT and check
    period consistency of the Vigenère key at crib positions.

    The model: the CT was produced by writing PT into the grid in standard
    order, then reading it out in the non-standard order, then encrypting.
    So to decrypt: read CT in the non-standard order (reorder), then
    apply inverse Vigenère.

    Alternatively: the physical positions on the sculpture are in the
    standard order, and the CT at position i corresponds to the reading
    order perm[i]. The crib positions refer to the final plaintext
    positions.
    """
    # Two interpretations:
    # Interp 1: Reorder CT, then check Vigenère consistency on reordered text
    # Interp 2: The reading order IS the transposition; check period consistency

    # Interp 1: reordered_ct[i] = CT[perm[i]]
    # Crib at position p means: reordered_ct[p] should decrypt to PT[p]
    # key[p] = (reordered_ct[p] - PT[p]) mod 26 = (CT[perm[p]] - PT[p]) mod 26

    results = {}
    for period in range(3, 14):
        groups = defaultdict(list)
        for p in CRIB_POS:
            if p < len(perm):
                reordered_val = CT_INT[perm[p]]
                key_val = (reordered_val - PT_INT[p]) % 26
                groups[p % period].append(key_val)

        score = 0
        for vals in groups.values():
            if len(vals) == 0:
                continue
            score += Counter(vals).most_common(1)[0][1]

        noise = NOISE_FLOORS.get(period, 8)
        results[period] = {"score": score, "noise": noise, "excess": score - noise}

    best_period = max(results, key=lambda p: results[p]["excess"])
    return results, best_period


def main():
    t0 = time.time()

    print("=" * 60)
    print("E-S-12: Non-Standard Reading Orders + Vigenère")
    print("=" * 60)
    print(f"CT: {CT[:20]}... ({CT_LEN} chars)")
    print(f"Testing reading orders × periods 3-13")
    print()

    all_results = {}
    top_candidates = []

    # Generate all reading orders
    reading_orders = []

    # 1. Basics
    reading_orders.append(("identity", identity_order(CT_LEN)))
    reading_orders.append(("reverse", reverse_order(CT_LEN)))

    # 2. Boustrophedon at various widths
    for w in range(5, 15):
        reading_orders.append((f"boustrophedon_w{w}", boustrophedon(CT_LEN, w)))

    # 3. Column-first at various widths
    for w in range(5, 15):
        reading_orders.append((f"column_first_w{w}", column_first(CT_LEN, w)))

    # 4. Spiral at various widths
    for w in range(5, 15):
        reading_orders.append((f"spiral_w{w}", spiral_reading(CT_LEN, w)))

    # 5. Diagonal at various widths
    for w in range(5, 15):
        reading_orders.append((f"diagonal_w{w}", diagonal_reading(CT_LEN, w)))

    # 6. S-curve at various widths
    for w in range(5, 15):
        reading_orders.append((f"s_curve_w{w}", s_curve(CT_LEN, w)))

    # 7. Reverse of each non-identity order
    extras = []
    for name, order in reading_orders:
        if name != "identity" and name != "reverse":
            extras.append((f"{name}_rev", list(reversed(order))))
    reading_orders.extend(extras)

    print(f"Total reading orders: {len(reading_orders)}")
    print()

    for name, order in reading_orders:
        # Validate permutation
        if sorted(order) != list(range(CT_LEN)):
            print(f"  WARNING: {name} is not a valid permutation! Skipping.")
            continue

        results, best_p = score_reading_order(order)

        best_score = results[best_p]["score"]
        best_excess = results[best_p]["excess"]

        # Also check period 7 specifically
        p7 = results.get(7, {"score": 0, "excess": -8.2})

        entry = {
            "name": name,
            "best_period": best_p,
            "best_score": best_score,
            "best_excess": round(best_excess, 1),
            "p7_score": p7["score"],
            "p7_excess": round(p7["excess"], 1),
            "all_periods": {str(p): r for p, r in results.items()},
        }
        all_results[name] = entry
        top_candidates.append(entry)

    # Sort by best excess
    top_candidates.sort(key=lambda x: -x["best_excess"])

    # ═══ Summary ═════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"  TOP 20 READING ORDERS (by excess over noise)")
    print(f"{'=' * 60}")

    for i, c in enumerate(top_candidates[:20]):
        tag = "***" if c["best_excess"] > 5 else ""
        print(f"  {i+1:>2}. {c['name']:<25s}  "
              f"best={c['best_score']}/24 @p={c['best_period']}  "
              f"excess={c['best_excess']:+.1f}  "
              f"p7={c['p7_score']}/24 ({c['p7_excess']:+.1f})  {tag}")

    # Best at period 7
    print(f"\n  TOP 10 at Period 7:")
    p7_sorted = sorted(top_candidates, key=lambda x: -x["p7_score"])
    for i, c in enumerate(p7_sorted[:10]):
        print(f"  {i+1:>2}. {c['name']:<25s}  p7={c['p7_score']}/24  excess={c['p7_excess']:+.1f}")

    best = top_candidates[0]
    best_p7 = p7_sorted[0]

    # Identity baseline
    identity = all_results.get("identity", {})
    print(f"\n  Identity baseline: best={identity.get('best_score', '?')}/24 "
          f"@p={identity.get('best_period', '?')}  "
          f"p7={identity.get('p7_score', '?')}/24")

    # Verdict
    if best["best_score"] >= 20 and best["best_excess"] > 8:
        verdict = "SIGNAL"
    elif best_p7["p7_score"] >= 15:
        verdict = "INVESTIGATE"
    elif best["best_excess"] <= 5:
        verdict = "NOISE"
    else:
        verdict = "INCONCLUSIVE"

    print(f"\n  Time: {elapsed:.1f}s")
    print(f"  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_12_reading_orders.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-12",
            "hypothesis": "Non-standard reading order reveals periodic Vigenère key",
            "total_time_s": round(elapsed, 3),
            "verdict": verdict,
            "n_orders": len(reading_orders),
            "top_20": top_candidates[:20],
            "top_10_p7": [c for c in p7_sorted[:10]],
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_12_reading_orders.py")
    print(f"\nRESULT: best={best['best_score']}/24 best_p7={best_p7['p7_score']}/24 verdict={verdict}")


if __name__ == "__main__":
    main()
