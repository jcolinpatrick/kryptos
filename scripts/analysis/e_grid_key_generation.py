#!/usr/bin/env python3
"""
Phase 4: Grid Key Generation / Backward Propagation (OQ-5)

Tests whether the 5-wide KA Polybius grid generates the keystream.
If key values come from reading the grid in some order, the keystream
would naturally be biased toward palette columns (explaining CxS-1).

Tests:
  1. Grid reading orders as running key (L->R, T->B, column-major, etc.)
  2. f(row, col) mod 26 key functions on CT letter grid coordinates
  3. Mechanism family survival analysis

Output: results/grid_key_generation.json
"""
import sys, os, json
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_POSITIONS, CRIB_DICT, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, BEAUFORT_KEYSTREAM_AT_CRIBS, NULL_PALETTE,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
GRID_WIDTH = 5
GRID_HEIGHT = 6  # ceil(26/5) = 6, last row has 1 letter (Z)

# Build 5-wide KA Polybius grid
KA_GRID = []
for row in range(GRID_HEIGHT):
    row_letters = []
    for col in range(GRID_WIDTH):
        idx = row * GRID_WIDTH + col
        if idx < 26:
            row_letters.append(KA[idx])
        else:
            row_letters.append(None)
    KA_GRID.append(row_letters)

# Letter -> (row, col) in the grid
KA_GRID_POS = {}
for row in range(GRID_HEIGHT):
    for col in range(GRID_WIDTH):
        idx = row * GRID_WIDTH + col
        if idx < 26:
            KA_GRID_POS[KA[idx]] = (row, col)

# Target keystream
KS_EXPECTED = [ALPH_IDX[c] for c in BEAUFORT_KEYSTREAM_AT_CRIBS]
CRIB_POS_SORTED = sorted(CRIB_POSITIONS)

results = {
    "experiment": "e_grid_key_generation",
    "date": datetime.now(timezone.utc).isoformat(),
}


# ── Test 1: Grid reading orders as running key ───────────────────────────
def test_grid_reading_orders():
    """Generate key sequences by reading the KA grid in various orders, apply as Beaufort running key."""
    # Generate reading orders
    orders = {}

    # Left-to-right, top-to-bottom (standard)
    orders["ltr_ttb"] = [KA[i] for i in range(26)]

    # Right-to-left, top-to-bottom
    orders["rtl_ttb"] = []
    for row in range(GRID_HEIGHT):
        for col in range(GRID_WIDTH - 1, -1, -1):
            idx = row * GRID_WIDTH + col
            if idx < 26:
                orders["rtl_ttb"].append(KA[idx])

    # Top-to-bottom, left-to-right (column-major)
    orders["col_major"] = []
    for col in range(GRID_WIDTH):
        for row in range(GRID_HEIGHT):
            idx = row * GRID_WIDTH + col
            if idx < 26:
                orders["col_major"].append(KA[idx])

    # Bottom-to-top, left-to-right
    orders["col_major_rev"] = []
    for col in range(GRID_WIDTH):
        for row in range(GRID_HEIGHT - 1, -1, -1):
            idx = row * GRID_WIDTH + col
            if idx < 26:
                orders["col_major_rev"].append(KA[idx])

    # Serpentine (row boustrophedon)
    orders["serpentine_row"] = []
    for row in range(GRID_HEIGHT):
        cols = range(GRID_WIDTH) if row % 2 == 0 else range(GRID_WIDTH - 1, -1, -1)
        for col in cols:
            idx = row * GRID_WIDTH + col
            if idx < 26:
                orders["serpentine_row"].append(KA[idx])

    # Diagonal (NW->SE)
    orders["diagonal_nw_se"] = []
    for d in range(GRID_HEIGHT + GRID_WIDTH - 1):
        for row in range(min(d, GRID_HEIGHT - 1), max(-1, d - GRID_WIDTH), -1):
            col = d - row
            if 0 <= col < GRID_WIDTH:
                idx = row * GRID_WIDTH + col
                if idx < 26:
                    orders["diagonal_nw_se"].append(KA[idx])

    # Spiral clockwise from top-left
    orders["spiral_cw"] = []
    visited = set()
    r, c, dr, dc = 0, 0, 0, 1
    for _ in range(26):
        idx = r * GRID_WIDTH + c
        if idx < 26:
            orders["spiral_cw"].append(KA[idx])
        visited.add((r, c))
        nr, nc = r + dr, c + dc
        if not (0 <= nr < GRID_HEIGHT and 0 <= nc < GRID_WIDTH and (nr, nc) not in visited):
            dr, dc = dc, -dr  # turn right
            nr, nc = r + dr, c + dc
        r, c = nr, nc

    # Reversed versions
    for name in list(orders.keys()):
        orders[name + "_rev"] = list(reversed(orders[name]))

    # Test each reading order at each offset as a Beaufort running key
    best_overall = {"order": None, "offset": -1, "score": 0}
    order_results = {}

    for order_name, key_seq in orders.items():
        if len(key_seq) < 26:
            continue  # skip incomplete orders
        best_for_order = {"offset": -1, "score": 0}

        for offset in range(len(key_seq)):
            # Generate running key for all 97 positions
            key_at = [(ALPH_IDX[key_seq[(offset + p) % len(key_seq)]]) for p in range(CT_LEN)]

            # Beaufort decrypt at crib positions and check
            score = 0
            for i, cp in enumerate(CRIB_POS_SORTED):
                ks_val = (ALPH_IDX[CT[cp]] + ALPH_IDX[CRIB_DICT[cp]]) % MOD  # Beaufort keystream
                if key_at[cp] == ks_val:
                    score += 1

            if score > best_for_order["score"]:
                best_for_order = {"offset": offset, "score": score}
            if score > best_overall["score"]:
                best_overall = {"order": order_name, "offset": offset, "score": score}

        order_results[order_name] = best_for_order

    return {
        "test": "grid_reading_orders",
        "orders_tested": len(orders),
        "offsets_per_order": 26,
        "total_configs": len(orders) * 26,
        "best_overall": {**best_overall, "score_str": f"{best_overall['score']}/24"},
        "top_orders": sorted(
            [{"order": k, **v} for k, v in order_results.items()],
            key=lambda x: -x["score"]
        )[:10],
        "verdict": "MATCH" if best_overall["score"] >= 20 else "NO_MATCH",
    }


# ── Test 2: f(row, col) mod 26 key functions ────────────────────────────
def test_grid_coordinate_functions():
    """Test key = f(grid_row, grid_col) of CT letter at each position."""
    # For each CT position, map CT letter to its (row, col) in the KA grid
    ct_grid_coords = []
    for p in range(CT_LEN):
        r, c = KA_GRID_POS[CT[p]]
        ct_grid_coords.append((r, c))

    best = {"a": 0, "b": 0, "c_val": 0, "score": 0}
    tested = 0

    # Test: key[p] = (a * row_of_CT[p] + b * col_of_CT[p] + c) mod 26
    for a in range(MOD):
        for b in range(MOD):
            for c_val in range(MOD):
                score = 0
                for i, cp in enumerate(CRIB_POS_SORTED):
                    r, c_coord = ct_grid_coords[cp]
                    predicted_key = (a * r + b * c_coord + c_val) % MOD
                    if predicted_key == KS_EXPECTED[i]:
                        score += 1
                tested += 1
                if score > best["score"]:
                    best = {"a": a, "b": b, "c_val": c_val, "score": score}

    # Also test: key[p] = Polybius_value (row*5 + col)
    polybius_score = 0
    for i, cp in enumerate(CRIB_POS_SORTED):
        r, c_coord = ct_grid_coords[cp]
        pv = (r * GRID_WIDTH + c_coord) % MOD
        if pv == KS_EXPECTED[i]:
            polybius_score += 1

    return {
        "test": "grid_coordinate_functions",
        "formula": "key = (a * row + b * col + c) mod 26",
        "configs_tested": tested,
        "best": {**best, "score_str": f"{best['score']}/24"},
        "polybius_value_score": f"{polybius_score}/24",
        "verdict": "MATCH" if best["score"] >= 20 else "NO_MATCH",
    }


# ── Test 3: Mechanism survival analysis ──────────────────────────────────
def test_mechanism_survival():
    """Which mechanism families can produce palette-biased keystream?"""
    palette_nums = {ALPH_IDX[c] for c in NULL_PALETTE}
    ks_palette_count = sum(1 for v in KS_EXPECTED if v in palette_nums)
    ap_set = {ALPH_IDX['G'], ALPH_IDX['K'], ALPH_IDX['O']}
    ks_ap_count = sum(1 for v in KS_EXPECTED if v in ap_set)

    families = {
        "periodic_polyalphabetic": {
            "can_produce_palette_bias": False,
            "reason": "Periodic keys produce uniform output; also eliminated by HC-4",
            "status": "ELIMINATED"
        },
        "pt_autokey": {
            "can_produce_palette_bias": False,
            "reason": "Structurally impossible (crib-to-crib proof)",
            "status": "ELIMINATED"
        },
        "ct_autokey": {
            "can_produce_palette_bias": False,
            "reason": "All configs produce 0/24",
            "status": "ELIMINATED"
        },
        "running_key_english": {
            "can_produce_palette_bias": False,
            "reason": "English+English cannot produce palette-biased sum; 60K texts tested",
            "status": "ELIMINATED"
        },
        "running_key_non_english": {
            "can_produce_palette_bias": True,
            "reason": "Non-English source could have any distribution",
            "status": "OPEN (untestable without source)"
        },
        "polybius_grid_lookup": {
            "can_produce_palette_bias": True,
            "reason": "Reading from 5-wide grid naturally biases toward certain columns",
            "status": "OPEN"
        },
        "otp_manual_key": {
            "can_produce_palette_bias": True,
            "reason": "Hand-selected from grid could naturally produce palette bias",
            "status": "OPEN (non-computational)"
        },
        "bespoke_grid_based": {
            "can_produce_palette_bias": True,
            "reason": "Any grid-reading process on 5-wide KA grid could produce palette bias",
            "status": "OPEN"
        },
    }

    return {
        "test": "mechanism_survival",
        "keystream_palette_count": f"{ks_palette_count}/24",
        "keystream_ap_count": f"{ks_ap_count}/24",
        "families": families,
        "surviving": [k for k, v in families.items() if v["status"].startswith("OPEN")],
        "eliminated": [k for k, v in families.items() if v["status"] == "ELIMINATED"],
    }


if __name__ == "__main__":
    print("=" * 72)
    print("Phase 4: Grid Key Generation / Backward Propagation (OQ-5)")
    print("=" * 72)

    print("\nKA Polybius Grid (5-wide):")
    for row in KA_GRID:
        print("  ", " ".join(c if c else '.' for c in row))

    for test_func in [test_grid_reading_orders, test_grid_coordinate_functions, test_mechanism_survival]:
        result = test_func()
        results[result["test"]] = result
        print(f"\n{'─' * 60}")
        print(f"  {result['test']}")
        print(f"    Verdict: {result.get('verdict', 'N/A')}")
        if "best_overall" in result:
            print(f"    Best: {result['best_overall']}")
        if "best" in result and isinstance(result["best"], dict):
            print(f"    Best: {result['best']}")
        if "surviving" in result:
            print(f"    Surviving families: {result['surviving']}")

    out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'grid_key_generation.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results: {out_path}")
