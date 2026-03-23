#!/usr/bin/env python3
"""
e_polybius_split_coordinate.py — Split-coordinate Polybius hypothesis.

HYPOTHESIS: K4's "two systems" correspond to the two Polybius coordinates:
  - System 1 (stego/columns): determines null vs real (columns 0,3 = null)
  - System 2 (cipher/rows): carries the actual encryption

If this is true, the cipher only needs to manipulate ROW values (0-5),
not full alphabet values (0-25). This reduces cipher complexity from
26-ary to 6-ary — simple enough for a math-averse artist.

ANALYSIS:
  1. Compute row and column coordinates for CT and PT at crib positions
  2. Derive the "row key" and "col key" separately
  3. Check if row-key or col-key has recognizable structure
  4. Test whether row-only operations with simple keys produce crib matches
  5. Check cross-coordinate relationships (does row-key depend on col-PT?)
"""

import sys
import os
import json
import time
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    CONSENSUS_NULL_POSITIONS, KRYPTOS_ALPHABET, ALPH,
    BEAUFORT_KEYSTREAM_AT_CRIBS,
)

# ── Grid setup ──────────────────────────────────────────────────────────

GRID_COLS = 5
GRID_ROWS = 6

def build_grid(alphabet):
    """Build letter → (row, col) mapping for 5-wide grid."""
    ltr_to_rc = {}
    rc_to_ltr = {}
    for i, ch in enumerate(alphabet):
        r, c = divmod(i, GRID_COLS)
        ltr_to_rc[ch] = (r, c)
        rc_to_ltr[(r, c)] = ch
    return ltr_to_rc, rc_to_ltr

KA_LTR, KA_RC = build_grid(KRYPTOS_ALPHABET)
AZ_LTR, AZ_RC = build_grid(ALPH)


def main():
    print("=" * 70)
    print("SPLIT-COORDINATE POLYBIUS ANALYSIS")
    print("=" * 70)

    # ── Step 1: Compute coordinates at crib positions ───────────────────

    print("\n--- Step 1: Coordinates at crib positions ---\n")

    crib_positions = sorted(CRIB_DICT.keys())

    print(f"{'Pos':>3} {'CT':>2} {'PT':>2} │ {'CT_r':>4} {'CT_c':>4} {'PT_r':>4} {'PT_c':>4} │ "
          f"{'Δrow':>4} {'Δcol':>4} │ {'BKey':>4} {'BKey_r':>5} {'BKey_c':>5}")
    print("─" * 80)

    row_keys = []
    col_keys = []
    ct_rows = []
    ct_cols = []
    pt_rows = []
    pt_cols = []
    bk_rows = []
    bk_cols = []

    for i, pos in enumerate(crib_positions):
        ct_ch = CT[pos]
        pt_ch = CRIB_DICT[pos]
        bk_ch = BEAUFORT_KEYSTREAM_AT_CRIBS[i]

        ct_r, ct_c = KA_LTR[ct_ch]
        pt_r, pt_c = KA_LTR[pt_ch]
        bk_r, bk_c = KA_LTR[bk_ch]

        # Row key: what operation on row produces CT_row from PT_row?
        # Beaufort row: (CT_row + PT_row) mod 6
        row_key_beau = (ct_r + pt_r) % GRID_ROWS
        # Vigenere row: (CT_row - PT_row) mod 6
        row_key_vig = (ct_r - pt_r) % GRID_ROWS

        # Col key similarly
        col_key_beau = (ct_c + pt_c) % GRID_COLS
        col_key_vig = (ct_c - pt_c) % GRID_COLS

        row_keys.append((row_key_beau, row_key_vig))
        col_keys.append((col_key_beau, col_key_vig))

        ct_rows.append(ct_r)
        ct_cols.append(ct_c)
        pt_rows.append(pt_r)
        pt_cols.append(pt_c)
        bk_rows.append(bk_r)
        bk_cols.append(bk_c)

        # Delta (Beaufort-style on each coord independently)
        dr_beau = (ct_r + pt_r) % GRID_ROWS
        dc_beau = (ct_c + pt_c) % GRID_COLS

        print(f"{pos:3d} {ct_ch:>2} {pt_ch:>2} │ {ct_r:4d} {ct_c:4d} {pt_r:4d} {pt_c:4d} │ "
              f"{dr_beau:4d} {dc_beau:4d} │ {bk_ch:>4} {bk_r:5d} {bk_c:5d}")

    # ── Step 2: Analyze row keys ─────────────────────────────────────────

    print("\n--- Step 2: Row key analysis ---\n")

    beau_row_keys = [rk[0] for rk in row_keys]
    vig_row_keys = [rk[1] for rk in row_keys]

    print(f"Beaufort row keys (CT_r + PT_r) % 6: {beau_row_keys}")
    print(f"Vigenère row keys (CT_r - PT_r) % 6: {vig_row_keys}")
    print(f"Beaufort row key distribution: {dict(Counter(beau_row_keys))}")
    print(f"Vigenère row key distribution: {dict(Counter(vig_row_keys))}")

    # Check periodicity
    for period in range(2, 13):
        beau_consistent = True
        vig_consistent = True
        for i in range(len(beau_row_keys)):
            for j in range(i + 1, len(beau_row_keys)):
                if (crib_positions[i] % period) == (crib_positions[j] % period):
                    if beau_row_keys[i] != beau_row_keys[j]:
                        beau_consistent = False
                    if vig_row_keys[i] != vig_row_keys[j]:
                        vig_consistent = False
        if beau_consistent or vig_consistent:
            tag = []
            if beau_consistent:
                tag.append("Beau")
            if vig_consistent:
                tag.append("Vig")
            print(f"  Period {period}: row-key consistent under {', '.join(tag)}")

    # ── Step 3: Analyze col keys ─────────────────────────────────────────

    print("\n--- Step 3: Column key analysis ---\n")

    beau_col_keys = [ck[0] for ck in col_keys]
    vig_col_keys = [ck[1] for ck in col_keys]

    print(f"Beaufort col keys (CT_c + PT_c) % 5: {beau_col_keys}")
    print(f"Vigenère col keys (CT_c - PT_c) % 5: {vig_col_keys}")
    print(f"Beaufort col key distribution: {dict(Counter(beau_col_keys))}")
    print(f"Vigenère col key distribution: {dict(Counter(vig_col_keys))}")

    for period in range(2, 13):
        beau_consistent = True
        vig_consistent = True
        for i in range(len(beau_col_keys)):
            for j in range(i + 1, len(beau_col_keys)):
                if (crib_positions[i] % period) == (crib_positions[j] % period):
                    if beau_col_keys[i] != beau_col_keys[j]:
                        beau_consistent = False
                    if vig_col_keys[i] != vig_col_keys[j]:
                        vig_consistent = False
        if beau_consistent or vig_consistent:
            tag = []
            if beau_consistent:
                tag.append("Beau")
            if vig_consistent:
                tag.append("Vig")
            print(f"  Period {period}: col-key consistent under {', '.join(tag)}")

    # ── Step 4: Beaufort keystream rows vs split-coordinate keys ──────────

    print("\n--- Step 4: Keystream row/col vs split keys ---\n")

    print(f"Beaufort keystream:     {BEAUFORT_KEYSTREAM_AT_CRIBS}")
    print(f"Keystream rows (KA):    {bk_rows}")
    print(f"Keystream cols (KA):    {bk_cols}")
    print(f"Split Beau row keys:    {beau_row_keys}")
    print(f"Split Beau col keys:    {beau_col_keys}")
    print(f"Row keys == KS rows?    {beau_row_keys == bk_rows}")
    print(f"Col keys == KS cols?    {beau_col_keys == bk_cols}")

    # Check if row keys are a simple function of keystream rows
    print("\n  Relationship between keystream rows and split row keys:")
    for i in range(min(12, len(bk_rows))):
        diff = (beau_row_keys[i] - bk_rows[i]) % GRID_ROWS
        print(f"    pos {crib_positions[i]:3d}: KS_row={bk_rows[i]}, split_row={beau_row_keys[i]}, diff={diff}")

    # ── Step 5: Can row-only or col-only simple keys produce matches? ────

    print("\n--- Step 5: Simple row/col key sweep ---\n")

    # Try: for each row-key sequence that is periodic (period 1-12),
    # compute what CT would be at crib positions using split-coordinate Beaufort.
    # CT_r = (key_r - PT_r) % 6, CT_c = (key_c - PT_c) % 5
    # Then CT_letter = grid[CT_r][CT_c]
    # Check if this matches actual CT.

    best_score = 0
    best_config = None

    for row_period in range(1, 13):
        for col_period in range(1, 8):
            # Try all possible row key values (0-5) for each residue class
            # This is 6^row_period * 5^col_period configs
            # For row_period=1, col_period=1: 6*5=30
            # For row_period=2, col_period=2: 36*25=900
            # Cap at manageable size
            if 6**row_period * 5**col_period > 500000:
                continue

            # Generate all row key patterns
            def gen_keys(n_values, period):
                if period == 0:
                    yield ()
                    return
                if period == 1:
                    for v in range(n_values):
                        yield (v,)
                    return
                for sub in gen_keys(n_values, period - 1):
                    for v in range(n_values):
                        yield sub + (v,)

            for rk_pattern in gen_keys(GRID_ROWS, row_period):
                for ck_pattern in gen_keys(GRID_COLS, col_period):
                    score = 0
                    for idx, pos in enumerate(crib_positions):
                        pt_ch = CRIB_DICT[pos]
                        pt_r, pt_c = KA_LTR[pt_ch]

                        # Split-coordinate Beaufort:
                        # CT_r = (row_key - PT_r) % 6
                        # CT_c = (col_key - PT_c) % 5
                        rk = rk_pattern[pos % row_period]
                        ck = ck_pattern[pos % col_period]

                        ct_r = (rk - pt_r) % GRID_ROWS
                        ct_c = (ck - pt_c) % GRID_COLS

                        ct_ch_predicted = KA_RC.get((ct_r, ct_c), "?")
                        if ct_ch_predicted == CT[pos]:
                            score += 1

                    if score > best_score:
                        best_score = score
                        best_config = {
                            "row_period": row_period,
                            "col_period": col_period,
                            "row_key": rk_pattern,
                            "col_key": ck_pattern,
                            "score": score,
                        }

    print(f"  Best split-coordinate periodic: {best_score}/24")
    if best_config:
        print(f"  Config: row_period={best_config['row_period']}, "
              f"col_period={best_config['col_period']}, "
              f"row_key={best_config['row_key']}, "
              f"col_key={best_config['col_key']}")

    # ── Step 6: Row clustering quantification ─────────────────────────────

    print("\n--- Step 6: Row clustering at crib positions ---\n")

    same_row_ct = sum(1 for i in range(len(ct_rows) - 1) if ct_rows[i] == ct_rows[i + 1])
    same_col_ct = sum(1 for i in range(len(ct_cols) - 1) if ct_cols[i] == ct_cols[i + 1])
    same_row_pt = sum(1 for i in range(len(pt_rows) - 1) if pt_rows[i] == pt_rows[i + 1])
    same_col_pt = sum(1 for i in range(len(pt_cols) - 1) if pt_cols[i] == pt_cols[i + 1])
    same_row_bk = sum(1 for i in range(len(bk_rows) - 1) if bk_rows[i] == bk_rows[i + 1])
    same_col_bk = sum(1 for i in range(len(bk_cols) - 1) if bk_cols[i] == bk_cols[i + 1])

    expected_row = 23 * (1.0 / GRID_ROWS)
    expected_col = 23 * (1.0 / GRID_COLS)

    print(f"  Same-row consecutive pairs (expected {expected_row:.1f} / {expected_col:.1f}):")
    print(f"    CT rows:       {same_row_ct}/23")
    print(f"    PT rows:       {same_row_pt}/23")
    print(f"    Keystream rows: {same_row_bk}/23")
    print(f"  Same-col consecutive pairs:")
    print(f"    CT cols:       {same_col_ct}/23")
    print(f"    PT cols:       {same_col_pt}/23")
    print(f"    Keystream cols: {same_col_bk}/23")

    # ── Step 7: Cross-coordinate check ────────────────────────────────────

    print("\n--- Step 7: Cross-coordinate dependency ---\n")

    # Does the row key depend on the PT column? (or vice versa)
    # If CT_r = f(PT_r, PT_c, key_r, key_c), then there's cross-coordinate dependency
    # Under pure split-coordinate, CT_r should depend ONLY on PT_r and key_r

    # Check: for positions with same PT_r, do they have the same row_key?
    # (Only meaningful if row_key is position-independent, which it isn't for non-periodic)
    pt_r_groups = {}
    for i, pos in enumerate(crib_positions):
        pt_r = pt_rows[i]
        if pt_r not in pt_r_groups:
            pt_r_groups[pt_r] = []
        pt_r_groups[pt_r].append((pos, ct_rows[i], beau_row_keys[i]))

    print("  Positions grouped by PT row:")
    for pt_r in sorted(pt_r_groups):
        entries = pt_r_groups[pt_r]
        print(f"    PT_row={pt_r}: {[(pos, f'CT_r={ct_r}, rk={rk}') for pos, ct_r, rk in entries]}")

    # ── Results summary ───────────────────────────────────────────────────

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    results = {
        "experiment": "e_polybius_split_coordinate",
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "beaufort_row_keys": beau_row_keys,
        "beaufort_col_keys": beau_col_keys,
        "vigenere_row_keys": vig_row_keys,
        "vigenere_col_keys": vig_col_keys,
        "keystream_rows": bk_rows,
        "keystream_cols": bk_cols,
        "best_periodic_split": best_config,
        "row_clustering": {
            "ct": same_row_ct, "pt": same_row_pt, "ks": same_row_bk,
            "expected": round(expected_row, 1),
        },
        "col_clustering": {
            "ct": same_col_ct, "pt": same_col_pt, "ks": same_col_bk,
            "expected": round(expected_col, 1),
        },
    }

    out_path = os.path.join(_ROOT, "results", "e_polybius_split_coordinate.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Results: {out_path}")


if __name__ == "__main__":
    main()
