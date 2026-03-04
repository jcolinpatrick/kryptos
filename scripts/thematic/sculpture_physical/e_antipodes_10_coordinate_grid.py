#!/usr/bin/env python3
"""
Cipher: physical/coordinate
Family: thematic/sculpture_physical
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-ANTIPODES-10: Coordinate Grid / Battleship Cipher

HYPOTHESIS: ABSCISSA (K2 keyword) literally means "x-coordinate." X and Y
characters in K4 ciphertext aren't encrypted letters — they're coordinate
markers. K4 contains 2 X's (positions 6, 79) and 1 Y (position 64).

The different justification between Kryptos (ragged right) and Antipodes
(full justified) creates different physical grids. Characters are read by
looking up (x, y) coordinates on a board.

ANGLES:
1. Adjacent letter pairs as (row, col) coordinates into the KA tableau
2. X/Y as delimiters splitting the CT into coordinate groups
3. K4 laid out on physical grids (Kryptos layout vs Antipodes layout),
   reading at specific coordinate positions
4. Every pair of CT characters = a coordinate lookup
5. X/Y mark the boundaries between coordinate and content regions
6. Letter frequency of X (rare) and Y as structural markers

COST: Fast — mostly combinatorial, <30 sec.
"""

import json
import os
import sys
import time
from typing import List, Dict, Tuple, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

# ── X and Y positions in K4 ─────────────────────────────────────────────

X_POS = [i for i, c in enumerate(CT) if c == 'X']  # [6, 79]
Y_POS = [i for i, c in enumerate(CT) if c == 'Y']  # [64]
XY_POS = sorted(X_POS + Y_POS)  # [6, 64, 79]

print(f"CT: {CT}")
print(f"X at: {X_POS}, Y at: {Y_POS}")
print(f"XY markers at: {XY_POS}")
print(f"Segments between markers: ", end="")
boundaries = [-1] + XY_POS + [CT_LEN]
for i in range(len(boundaries) - 1):
    seg = CT[boundaries[i]+1:boundaries[i+1]]
    print(f"[{boundaries[i]+1}:{boundaries[i+1]}]={len(seg)} ", end="")
print()


def tableau_lookup(row: int, col: int) -> str:
    """Look up character in KA Vigenère tableau."""
    return KRYPTOS_ALPHABET[(row + col) % 26]


def tableau_lookup_az(row: int, col: int) -> str:
    """Look up character in standard A-Z tableau."""
    return ALPH[(row + col) % 26]


def pairs_to_text_tableau(pairs: List[Tuple[int, int]], ka: bool = True) -> str:
    """Convert (row, col) pairs to text via tableau lookup."""
    if ka:
        return "".join(KRYPTOS_ALPHABET[(r + c) % 26] for r, c in pairs)
    else:
        return "".join(ALPH[(r + c) % 26] for r, c in pairs)


def char_to_coord(ch: str, use_ka: bool = True) -> int:
    """Convert character to coordinate value."""
    if use_ka:
        return KA_IDX[ch]
    return ord(ch) - 65


def main():
    t0 = time.time()
    print("\n" + "=" * 70)
    print("E-ANTIPODES-10: Coordinate Grid / Battleship Cipher")
    print("=" * 70)

    best_score = 0
    best_result = None
    total_configs = 0
    above_noise = []

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 1: Adjacent pairs as (row, col) tableau coordinates
    # ══════════════════════════════════════════════════════════════════════
    print("\n--- ANGLE 1: Adjacent pairs as tableau coordinates ---")

    # Strip X and Y, use remaining letters as coordinate pairs
    ct_no_xy = "".join(c for c in CT if c not in 'XY')
    print(f"CT without X/Y: {len(ct_no_xy)} chars = {len(ct_no_xy)//2} coordinate pairs")

    for use_ka in [True, False]:
        alpha_name = "KA" if use_ka else "AZ"

        # Method A: consecutive pairs (c0,c1), (c2,c3), ...
        pairs = []
        for i in range(0, len(ct_no_xy) - 1, 2):
            r = char_to_coord(ct_no_xy[i], use_ka)
            c = char_to_coord(ct_no_xy[i+1], use_ka)
            pairs.append((r, c))

        # Try different tableau operations
        for op_name, op in [
            ("add", lambda r, c: KRYPTOS_ALPHABET[(r + c) % 26] if use_ka else ALPH[(r + c) % 26]),
            ("sub", lambda r, c: KRYPTOS_ALPHABET[(r - c) % 26] if use_ka else ALPH[(r - c) % 26]),
            ("row_only", lambda r, c: KRYPTOS_ALPHABET[r] if use_ka else ALPH[r]),
            ("col_only", lambda r, c: KRYPTOS_ALPHABET[c] if use_ka else ALPH[c]),
            ("xor", lambda r, c: KRYPTOS_ALPHABET[(r ^ c) % 26] if use_ka else ALPH[(r ^ c) % 26]),
        ]:
            total_configs += 1
            pt = "".join(op(r, c) for r, c in pairs)
            sc = score_cribs(pt) if len(pt) >= 74 else 0

            if sc > best_score:
                best_score = sc
                best_result = {
                    "angle": 1, "method": "pairs_no_xy",
                    "alpha": alpha_name, "op": op_name,
                    "plaintext": pt, "crib_score": sc,
                }
                if sc > NOISE_FLOOR:
                    print(f"  NEW BEST: {sc}/24, {alpha_name} {op_name}")
                    print(f"  PT: {pt[:50]}...")

        # Method B: ALL characters as pairs (including X/Y)
        for i in range(0, CT_LEN - 1, 2):
            pass  # handled below

        pairs_full = []
        for i in range(0, CT_LEN - 1, 2):
            r = char_to_coord(CT[i], use_ka)
            c = char_to_coord(CT[i+1], use_ka)
            pairs_full.append((r, c))

        for op_name, op in [
            ("add", lambda r, c: KRYPTOS_ALPHABET[(r + c) % 26] if use_ka else ALPH[(r + c) % 26]),
            ("sub", lambda r, c: KRYPTOS_ALPHABET[(r - c) % 26] if use_ka else ALPH[(r - c) % 26]),
        ]:
            total_configs += 1
            pt = "".join(op(r, c) for r, c in pairs_full)
            sc = score_cribs(pt) if len(pt) >= 74 else 0

            if sc > best_score:
                best_score = sc
                best_result = {
                    "angle": 1, "method": "pairs_full",
                    "alpha": alpha_name, "op": op_name,
                    "plaintext": pt, "crib_score": sc,
                }
                if sc > NOISE_FLOOR:
                    print(f"  NEW BEST: {sc}/24, full pairs {alpha_name} {op_name}")

        # Method C: offset by 1 — (c1,c2), (c3,c4), ...
        for offset in [1]:
            pairs_off = []
            for i in range(offset, CT_LEN - 1, 2):
                r = char_to_coord(CT[i], use_ka)
                c = char_to_coord(CT[i+1], use_ka)
                pairs_off.append((r, c))

            for op_name, op in [
                ("add", lambda r, c: KRYPTOS_ALPHABET[(r + c) % 26] if use_ka else ALPH[(r + c) % 26]),
                ("sub", lambda r, c: KRYPTOS_ALPHABET[(r - c) % 26] if use_ka else ALPH[(r - c) % 26]),
            ]:
                total_configs += 1
                pt = "".join(op(r, c) for r, c in pairs_off)

    print(f"  Angle 1: {total_configs} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 2: X/Y as delimiters — segments are coordinate sequences
    # ══════════════════════════════════════════════════════════════════════
    print("\n--- ANGLE 2: X/Y as segment delimiters ---")

    # Split CT at X and Y positions
    # Segments: CT[0:6], CT[7:64], CT[65:79], CT[80:97]
    segments = []
    prev = 0
    for p in XY_POS:
        segments.append(CT[prev:p])
        prev = p + 1
    segments.append(CT[prev:])

    print(f"  Segments: {[f'{len(s)}:{s[:10]}...' for s in segments]}")

    # What if alternate segments are x-coords and y-coords?
    # Seg0 (6 chars) = x-coordinates, Seg1 (57 chars) = data, etc.
    # Or: Seg0 + Seg2 = x-coords, Seg1 + Seg3 = y-coords

    for use_ka in [True, False]:
        alpha_name = "KA" if use_ka else "AZ"

        # Try: even segments = row coords, odd segments = col coords
        x_chars = "".join(segments[i] for i in range(0, len(segments), 2))
        y_chars = "".join(segments[i] for i in range(1, len(segments), 2))

        min_len = min(len(x_chars), len(y_chars))
        if min_len > 0:
            pairs = [(char_to_coord(x_chars[i], use_ka),
                       char_to_coord(y_chars[i], use_ka))
                      for i in range(min_len)]

            for op_name in ["add", "sub"]:
                total_configs += 1
                if op_name == "add":
                    pt = "".join(
                        (KRYPTOS_ALPHABET if use_ka else ALPH)[(r + c) % 26]
                        for r, c in pairs
                    )
                else:
                    pt = "".join(
                        (KRYPTOS_ALPHABET if use_ka else ALPH)[(r - c) % 26]
                        for r, c in pairs
                    )

                sc = score_cribs(pt) if len(pt) >= 74 else 0
                if sc > best_score:
                    best_score = sc
                    best_result = {
                        "angle": 2, "method": "even_x_odd_y",
                        "alpha": alpha_name, "op": op_name,
                        "plaintext": pt, "crib_score": sc,
                    }
                    if sc > NOISE_FLOOR:
                        print(f"  NEW BEST: {sc}/24, even/odd segments {alpha_name} {op_name}")

        # Try reversed: odd = x, even = y
        x_chars2 = "".join(segments[i] for i in range(1, len(segments), 2))
        y_chars2 = "".join(segments[i] for i in range(0, len(segments), 2))
        min_len2 = min(len(x_chars2), len(y_chars2))
        if min_len2 > 0:
            pairs2 = [(char_to_coord(x_chars2[i], use_ka),
                        char_to_coord(y_chars2[i], use_ka))
                       for i in range(min_len2)]
            for op_name in ["add", "sub"]:
                total_configs += 1
                if op_name == "add":
                    pt = "".join(
                        (KRYPTOS_ALPHABET if use_ka else ALPH)[(r + c) % 26]
                        for r, c in pairs2
                    )
                else:
                    pt = "".join(
                        (KRYPTOS_ALPHABET if use_ka else ALPH)[(r - c) % 26]
                        for r, c in pairs2
                    )
                sc = score_cribs(pt) if len(pt) >= 74 else 0
                if sc > best_score:
                    best_score = sc
                    best_result = {
                        "angle": 2, "method": "odd_x_even_y",
                        "alpha": alpha_name, "op": op_name,
                        "crib_score": sc,
                    }

    print(f"  Angle 2: {total_configs} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 3: K4 on a grid — read coordinates from the physical layout
    # ══════════════════════════════════════════════════════════════════════
    print("\n--- ANGLE 3: K4 laid out on grids of various widths ---")

    for width in range(5, 20):
        # Lay K4 into a grid
        n_rows = (CT_LEN + width - 1) // width
        grid = []
        for r in range(n_rows):
            row = CT[r*width:(r+1)*width]
            grid.append(row)

        # Where do X and Y fall in this grid?
        for p in X_POS:
            r, c = divmod(p, width)
            # The X character at (r, c) — what if r and c are coordinates?
            pass

        # Read specific cells: use X positions as row indicators, Y as column
        # For each width, extract the (row, col) of X and Y characters
        x_coords = [(p // width, p % width) for p in X_POS]
        y_coords = [(p // width, p % width) for p in Y_POS]

        # Try: X row + Y col = target cell
        for xr, xc in x_coords:
            for yr, yc in y_coords:
                # Several interpretations:
                targets = [
                    (xr, yc),  # X's row, Y's column
                    (yr, xc),  # Y's row, X's column
                    (xc, yc),  # X's col, Y's col
                    (xr, yr),  # X's row, Y's row
                ]
                for tr, tc in targets:
                    if 0 <= tr < n_rows and 0 <= tc < width:
                        pos = tr * width + tc
                        if pos < CT_LEN:
                            total_configs += 1

        # More interesting: each character's (row, col) in the grid
        # becomes the coordinate pair for a tableau lookup
        for use_ka in [True, False]:
            alpha_name = "KA" if use_ka else "AZ"
            total_configs += 1

            pt_chars = []
            for i in range(CT_LEN):
                r = i // width
                c = i % width
                # The character at position i has grid coordinates (r, c)
                # Look up in tableau
                ch = (KRYPTOS_ALPHABET if use_ka else ALPH)[(r + c) % 26]
                pt_chars.append(ch)

            # This gives us a position-dependent key
            pos_key = [((i // width) + (i % width)) % 26 for i in range(CT_LEN)]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT,
                           CipherVariant.VAR_BEAUFORT]:
                total_configs += 1
                pt = decrypt_text(CT, pos_key, variant)
                sc = score_cribs(pt)

                if sc > best_score:
                    best_score = sc
                    best_result = {
                        "angle": 3, "width": width,
                        "alpha": alpha_name,
                        "method": "grid_position_key",
                        "variant": variant.value,
                        "plaintext": pt,
                        "crib_score": sc,
                    }
                    if sc > NOISE_FLOOR:
                        print(f"  NEW BEST: {sc}/24, w={width} grid-pos key {variant.value}")

            # Also try: key[i] = r * some_factor + c
            for factor in [1, 2, 3, 5, 7, 13, 26]:
                pos_key2 = [((i // width) * factor + (i % width)) % 26 for i in range(CT_LEN)]
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT,
                               CipherVariant.VAR_BEAUFORT]:
                    total_configs += 1
                    pt = decrypt_text(CT, pos_key2, variant)
                    sc = score_cribs(pt)

                    if sc > best_score:
                        best_score = sc
                        best_result = {
                            "angle": 3, "width": width, "factor": factor,
                            "variant": variant.value,
                            "method": "grid_factor_key",
                            "plaintext": pt,
                            "crib_score": sc,
                        }
                        if sc > NOISE_FLOOR:
                            print(f"  NEW BEST: {sc}/24, w={width} factor={factor} "
                                  f"{variant.value}")

    print(f"  Angle 3: {total_configs} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 4: Polybius-style — pairs of CT chars are coordinates into
    # a lookup table (not necessarily 5x5)
    # ══════════════════════════════════════════════════════════════════════
    print("\n--- ANGLE 4: Full 26x26 Polybius (char pairs → single char) ---")

    # For each pair interpretation, convert CT to half-length PT
    for use_ka in [True, False]:
        alpha = KRYPTOS_ALPHABET if use_ka else ALPH
        alpha_name = "KA" if use_ka else "AZ"
        idx = KA_IDX if use_ka else ALPH_IDX

        for offset in [0, 1]:
            for pair_op in ["lookup", "add", "sub", "mul"]:
                total_configs += 1
                pt_chars = []
                for i in range(offset, CT_LEN - 1, 2):
                    r = idx[CT[i]]
                    c = idx[CT[i+1]]
                    if pair_op == "lookup":
                        pt_chars.append(alpha[(r + c) % 26])
                    elif pair_op == "add":
                        pt_chars.append(alpha[(r + c) % 26])
                    elif pair_op == "sub":
                        pt_chars.append(alpha[(r - c) % 26])
                    elif pair_op == "mul":
                        pt_chars.append(alpha[(r * c) % 26])

                pt = "".join(pt_chars)
                # Since PT is ~48 chars, cribs at positions 21-33 and 63-73
                # would need to be at half those positions
                # Check for crib words at any position
                for word, wlen in [("EASTNORTHEAST", 13), ("BERLINCLOCK", 11),
                                     ("NORTHEAST", 9), ("BERLIN", 6), ("CLOCK", 5)]:
                    for j in range(len(pt) - wlen + 1):
                        if pt[j:j+wlen] == word:
                            print(f"  FOUND '{word}' at pos {j} in Polybius "
                                  f"{alpha_name} offset={offset} op={pair_op}!")
                            print(f"  Full PT: {pt}")
                            above_noise.append({
                                "angle": 4, "alpha": alpha_name,
                                "offset": offset, "op": pair_op,
                                "word": word, "pos": j,
                            })

    print(f"  Angle 4: {total_configs} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 5: X/Y mark "read here" positions — extract chars AT X/Y
    # coordinates from the tableau or from other grid layouts
    # ══════════════════════════════════════════════════════════════════════
    print("\n--- ANGLE 5: Characters adjacent to X/Y as coordinate values ---")

    # What if the chars before and after each X/Y are coordinates?
    # X at 6: before=O, after=O → (O, O) → tableau lookup
    # X at 79: before=Z, after=T → (Z, T) → tableau lookup
    # Y at 64: before=N, after=P → (N, P) → tableau lookup

    for use_ka in [True, False]:
        alpha = KRYPTOS_ALPHABET if use_ka else ALPH
        alpha_name = "KA" if use_ka else "AZ"
        idx = KA_IDX if use_ka else ALPH_IDX

        results_xy = []
        for p in XY_POS:
            if p > 0 and p < CT_LEN - 1:
                before = idx[CT[p-1]]
                after = idx[CT[p+1]]
                # Various lookups
                results_xy.append({
                    "pos": p, "marker": CT[p],
                    "before": CT[p-1], "after": CT[p+1],
                    "before_idx": before, "after_idx": after,
                    "add": alpha[(before + after) % 26],
                    "sub": alpha[(before - after) % 26],
                    "tab_rc": alpha[(before + after) % 26],  # same as add for std tableau
                })

        print(f"  {alpha_name} coordinate lookups:")
        for r in results_xy:
            print(f"    {r['marker']} at {r['pos']}: ({r['before']},{r['after']}) → "
                  f"add={r['add']}, sub={r['sub']}")
        total_configs += 1

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 6: Abscissa-Ordinate grid — CT chars as x-values on a
    # coordinate plane, with the KA alphabet providing y-values
    # ══════════════════════════════════════════════════════════════════════
    print("\n--- ANGLE 6: Abscissa (x) / Ordinate (y) grid mapping ---")

    # What if each CT character provides an x-coordinate (abscissa),
    # and the position provides the y-coordinate (ordinate)?
    # The plaintext is read from the intersection on a grid.

    for use_ka in [True, False]:
        alpha = KRYPTOS_ALPHABET if use_ka else ALPH
        alpha_name = "KA" if use_ka else "AZ"
        idx = KA_IDX if use_ka else ALPH_IDX

        # Grid: 26 columns (abscissa = CT char value)
        #        97 rows (ordinate = position in CT)
        # But we need to map 97 rows to 26 somehow
        for row_mod in [26, 7, 13, 97]:
            total_configs += 1
            pt_chars = []
            for i in range(CT_LEN):
                x = idx[CT[i]]       # abscissa from ciphertext
                y = i % row_mod      # ordinate from position
                pt_chars.append(alpha[(x + y) % 26])
            pt = "".join(pt_chars)
            sc = score_cribs(pt)

            if sc > best_score:
                best_score = sc
                best_result = {
                    "angle": 6, "alpha": alpha_name,
                    "row_mod": row_mod,
                    "method": "abscissa_ordinate",
                    "plaintext": pt, "crib_score": sc,
                }
                if sc > NOISE_FLOOR:
                    print(f"  NEW BEST: {sc}/24, {alpha_name} row_mod={row_mod}")

            # Also subtract
            total_configs += 1
            pt_chars2 = []
            for i in range(CT_LEN):
                x = idx[CT[i]]
                y = i % row_mod
                pt_chars2.append(alpha[(x - y) % 26])
            pt2 = "".join(pt_chars2)
            sc2 = score_cribs(pt2)

            if sc2 > best_score:
                best_score = sc2
                best_result = {
                    "angle": 6, "alpha": alpha_name,
                    "row_mod": row_mod, "op": "sub",
                    "plaintext": pt2, "crib_score": sc2,
                }
                if sc2 > NOISE_FLOOR:
                    print(f"  NEW BEST: {sc2}/24, {alpha_name} row_mod={row_mod} sub")

    print(f"  Angle 6: {total_configs} configs, best={best_score}")

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Best crib score: {best_score}/24")
    if best_result:
        for k, v in best_result.items():
            if k != "plaintext":
                print(f"  {k}: {v}")
        if best_score >= STORE_THRESHOLD and "plaintext" in best_result:
            print(f"Best plaintext: {best_result['plaintext']}")
    print(f"Above-noise results: {len(above_noise)}")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Write results ─────────────────────────────────────────────────────
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_antipodes_10')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-ANTIPODES-10",
        "hypothesis": "Coordinate grid / Battleship cipher (X/Y as coordinate markers)",
        "total_configs": total_configs,
        "best_score": best_score,
        "best_result": {k: v for k, v in (best_result or {}).items() if k != "plaintext"},
        "above_noise_count": len(above_noise),
        "x_positions": X_POS,
        "y_positions": Y_POS,
        "elapsed_seconds": elapsed,
    }
    with open(os.path.join(outdir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\nResults written to {outdir}/")


if __name__ == "__main__":
    main()
