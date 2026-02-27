#!/usr/bin/env python3
"""E-TEAM-PHYSICAL-TRANSPOSITIONS: Test ~200 physically-derived permutations for K4.

Generates permutations from grid reads (spiral, serpentine, diagonal),
rail fence, interleave, reversal, and block reversal patterns. For each,
tests raw crib matching, position-free matching, and all 3 cipher variants
with shifts 0-25.

Results saved to results/e_team_physical_transpositions.json.
"""
import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order,
    spiral_perm, serpentine_perm, rail_fence_perm, validate_perm,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]


# ── Diagonal reading order ────────────────────────────────────────────────

def diagonal_perm(rows: int, cols: int, length: int = 97, direction: str = "tl_br") -> list[int]:
    """Diagonal reading of a grid.

    direction:
      'tl_br': top-left to bottom-right diagonals (NW-SE)
      'tr_bl': top-right to bottom-left diagonals (NE-SW)
    """
    diags: dict[int, list[int]] = {}
    for r in range(rows):
        for c in range(cols):
            pos = r * cols + c
            if pos >= length:
                continue
            if direction == "tl_br":
                key = r + c  # NW-SE diagonals
            else:
                key = r + (cols - 1 - c)  # NE-SW diagonals
            if key not in diags:
                diags[key] = []
            diags[key].append(pos)
    perm = []
    for k in sorted(diags.keys()):
        perm.extend(diags[k])
    return perm


def antidiag_perm(rows: int, cols: int, length: int = 97) -> list[int]:
    """Anti-diagonal reading (bottom-left to top-right diagonals)."""
    diags: dict[int, list[int]] = {}
    for r in range(rows):
        for c in range(cols):
            pos = r * cols + c
            if pos >= length:
                continue
            key = (rows - 1 - r) + c
            if key not in diags:
                diags[key] = []
            diags[key].append(pos)
    perm = []
    for k in sorted(diags.keys()):
        perm.extend(diags[k])
    return perm


# ── Column-first reading ─────────────────────────────────────────────────

def column_first_perm(rows: int, cols: int, length: int = 97) -> list[int]:
    """Read grid column-by-column (left to right, top to bottom within each)."""
    perm = []
    for c in range(cols):
        for r in range(rows):
            pos = r * cols + c
            if pos < length:
                perm.append(pos)
    return perm


def column_first_rev_perm(rows: int, cols: int, length: int = 97) -> list[int]:
    """Read grid column-by-column (right to left)."""
    perm = []
    for c in range(cols - 1, -1, -1):
        for r in range(rows):
            pos = r * cols + c
            if pos < length:
                perm.append(pos)
    return perm


# ── Block reversal ────────────────────────────────────────────────────────

def block_reverse_perm(length: int, block_size: int) -> list[int]:
    """Reverse each block of size B."""
    perm = []
    for start in range(0, length, block_size):
        end = min(start + block_size, length)
        perm.extend(range(end - 1, start - 1, -1))
    return perm


# ── Spiral from different corners ─────────────────────────────────────────

def spiral_from_corner(rows: int, cols: int, length: int, corner: str, clockwise: bool) -> list[int]:
    """Spiral read starting from a specific corner.

    corner: 'TL' (top-left), 'TR' (top-right), 'BL' (bottom-left), 'BR' (bottom-right)
    """
    # Generate spiral from TL, then remap coordinates
    visited = [[False] * cols for _ in range(rows)]

    if corner == "TL":
        r, c = 0, 0
        dirs = [(0,1),(1,0),(0,-1),(-1,0)] if clockwise else [(1,0),(0,1),(-1,0),(0,-1)]
    elif corner == "TR":
        r, c = 0, cols - 1
        dirs = [(1,0),(0,-1),(-1,0),(0,1)] if clockwise else [(0,-1),(1,0),(0,1),(-1,0)]
    elif corner == "BL":
        r, c = rows - 1, 0
        dirs = [(0,1),(-1,0),(0,-1),(1,0)] if clockwise else [(-1,0),(0,1),(1,0),(0,-1)]
    elif corner == "BR":
        r, c = rows - 1, cols - 1
        dirs = [(-1,0),(0,-1),(1,0),(0,1)] if clockwise else [(0,-1),(-1,0),(0,1),(1,0)]
    else:
        return []

    perm = []
    d = 0
    for _ in range(rows * cols):
        pos = r * cols + c
        if pos < length:
            perm.append(pos)
        visited[r][c] = True
        nr, nc = r + dirs[d][0], c + dirs[d][1]
        if 0 <= nr < rows and 0 <= nc < cols and not visited[nr][nc]:
            r, c = nr, nc
        else:
            d = (d + 1) % 4
            nr, nc = r + dirs[d][0], c + dirs[d][1]
            if 0 <= nr < rows and 0 <= nc < cols and not visited[nr][nc]:
                r, c = nr, nc
            else:
                break
    return perm


# ── S-curve (boustrophedon with row displacement) ─────────────────────────

def scurve_perm(rows: int, cols: int, length: int = 97, displacement: int = 0) -> list[int]:
    """S-curve: serpentine with optional row displacement (shift alternating rows)."""
    perm = []
    for r in range(rows):
        if r % 2 == 0:
            row_positions = [r * cols + c for c in range(cols)]
        else:
            row_positions = [r * cols + c for c in range(cols - 1, -1, -1)]
        # Apply displacement: shift odd rows by displacement positions
        if displacement > 0 and r % 2 == 1:
            row_positions = row_positions[displacement:] + row_positions[:displacement]
        for pos in row_positions:
            if pos < length:
                perm.append(pos)
    return perm


# ── Weltzeituhr-inspired block reads ─────────────────────────────────────

def weltzeituhr_block_perm(length: int = 97, block_order: list[int] = None) -> list[int]:
    """Read CT in 4 blocks of 24 + 1 remainder, reordered by block_order."""
    if block_order is None:
        block_order = [0, 1, 2, 3]
    perm = []
    for b in block_order:
        start = b * 24
        end = min(start + 24, length)
        perm.extend(range(start, end))
    # Remainder (position 96)
    if 96 not in perm and 96 < length:
        perm.append(96)
    return perm


# ── Layer-two interleave variants ─────────────────────────────────────────

def layer_two_interleave(length: int = 97, n_layers: int = 2, read_order: str = "forward") -> list[int]:
    """Multi-layer interleave: split text into n_layers, interleave or concatenate."""
    layers = [[] for _ in range(n_layers)]
    for i in range(length):
        layers[i % n_layers].append(i)
    if read_order == "forward":
        return [p for layer in layers for p in layer]
    elif read_order == "reverse":
        return [p for layer in reversed(layers) for p in layer]
    elif read_order == "alternate":
        perm = []
        for i, layer in enumerate(layers):
            perm.extend(layer if i % 2 == 0 else list(reversed(layer)))
        return perm
    return [p for layer in layers for p in layer]


# ── Main experiment ───────────────────────────────────────────────────────

def main():
    start_time = time.time()
    results = []
    best_score = 0
    best_result = None
    configs_tested = 0
    perms_generated = 0

    # Collect all permutations with labels
    all_perms: list[tuple[str, str, list[int]]] = []

    # ── 1. Grid-based permutations ────────────────────────────────────────
    GRID_DIMS = [
        (7, 14), (8, 13), (9, 11), (10, 10), (11, 9), (13, 8), (14, 7),
        (4, 25), (5, 20), (6, 17), (16, 7), (17, 6), (19, 6), (20, 5),
        (25, 4), (97, 1), (1, 97),
        (32, 33),  # Antipodes tableau dimensions
        (33, 32),  # Antipodes transposed
        (3, 33),   # 3-row wide grid (97 = 3*32 + 1)
    ]

    print("=" * 70)
    print("Generating permutations...")
    print("=" * 70)

    for rows, cols in GRID_DIMS:
        label = f"{rows}x{cols}"

        # Spiral CW/CCW
        try:
            p = spiral_perm(rows, cols, CT_LEN, True)
            if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                all_perms.append((f"spiral_CW_{label}", "spiral", p))
        except Exception:
            pass
        try:
            p = spiral_perm(rows, cols, CT_LEN, False)
            if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                all_perms.append((f"spiral_CCW_{label}", "spiral", p))
        except Exception:
            pass

        # Serpentine H/V
        try:
            p = serpentine_perm(rows, cols, CT_LEN, False)
            if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                all_perms.append((f"serpentine_H_{label}", "serpentine", p))
        except Exception:
            pass
        try:
            p = serpentine_perm(rows, cols, CT_LEN, True)
            if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                all_perms.append((f"serpentine_V_{label}", "serpentine", p))
        except Exception:
            pass

        # Diagonal (NW-SE and NE-SW)
        p = diagonal_perm(rows, cols, CT_LEN, "tl_br")
        if len(p) == CT_LEN and validate_perm(p, CT_LEN):
            all_perms.append((f"diag_NWSE_{label}", "diagonal", p))
        p = diagonal_perm(rows, cols, CT_LEN, "tr_bl")
        if len(p) == CT_LEN and validate_perm(p, CT_LEN):
            all_perms.append((f"diag_NESW_{label}", "diagonal", p))

        # Anti-diagonal
        p = antidiag_perm(rows, cols, CT_LEN)
        if len(p) == CT_LEN and validate_perm(p, CT_LEN):
            all_perms.append((f"antidiag_{label}", "diagonal", p))

        # Column-first
        p = column_first_perm(rows, cols, CT_LEN)
        if len(p) == CT_LEN and validate_perm(p, CT_LEN):
            all_perms.append((f"col_first_{label}", "column", p))
        p = column_first_rev_perm(rows, cols, CT_LEN)
        if len(p) == CT_LEN and validate_perm(p, CT_LEN):
            all_perms.append((f"col_first_rev_{label}", "column", p))

    # ── 2. Rail fence ─────────────────────────────────────────────────────
    for depth in range(2, 11):
        p = rail_fence_perm(CT_LEN, depth)
        if len(p) == CT_LEN and validate_perm(p, CT_LEN):
            all_perms.append((f"rail_fence_d{depth}", "rail_fence", p))

    # ── 3. Even/odd interleave ────────────────────────────────────────────
    p = list(range(0, CT_LEN, 2)) + list(range(1, CT_LEN, 2))
    all_perms.append(("even_odd_interleave", "interleave", p))

    # Odd then even
    p = list(range(1, CT_LEN, 2)) + list(range(0, CT_LEN, 2))
    all_perms.append(("odd_even_interleave", "interleave", p))

    # ── 4. Reverse ────────────────────────────────────────────────────────
    p = list(range(CT_LEN - 1, -1, -1))
    all_perms.append(("full_reverse", "reverse", p))

    # ── 5. Block reversal ─────────────────────────────────────────────────
    for bs in [4, 7, 8, 9, 11, 13, 24, 48]:
        p = block_reverse_perm(CT_LEN, bs)
        if validate_perm(p, CT_LEN):
            all_perms.append((f"block_rev_B{bs}", "block_reverse", p))

    # ── 6. Rotations (cyclic shift of entire text) ────────────────────────
    for shift in [1, 7, 13, 24, 48, 96]:
        p = [(i + shift) % CT_LEN for i in range(CT_LEN)]
        all_perms.append((f"rotate_{shift}", "rotation", p))

    # ── 7. Spiral from all 4 corners ────────────────────────────────────
    SPIRAL_GRIDS = [(7,14), (8,13), (9,11), (10,10), (11,9), (13,8), (14,7)]
    for rows, cols in SPIRAL_GRIDS:
        label = f"{rows}x{cols}"
        for corner in ["TL", "TR", "BL", "BR"]:
            for cw in [True, False]:
                d = "CW" if cw else "CCW"
                p = spiral_from_corner(rows, cols, CT_LEN, corner, cw)
                if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                    all_perms.append((f"spiral_{corner}_{d}_{label}", "spiral_corner", p))

    # ── 8. S-curve with boustrophedon displacement ──────────────────────
    for rows, cols in [(7,14), (8,13), (9,11), (10,10), (11,9), (13,8), (14,7)]:
        label = f"{rows}x{cols}"
        for disp in range(0, min(cols, 6)):
            p = scurve_perm(rows, cols, CT_LEN, disp)
            if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                all_perms.append((f"scurve_d{disp}_{label}", "scurve", p))

    # ── 9. Weltzeituhr-inspired block reads ─────────────────────────────
    import itertools
    # All 24 permutations of 4 blocks
    for perm_order in itertools.permutations([0, 1, 2, 3]):
        p = weltzeituhr_block_perm(CT_LEN, list(perm_order))
        if len(p) == CT_LEN and validate_perm(p, CT_LEN):
            name = "".join(str(x) for x in perm_order)
            all_perms.append((f"welt_blk_{name}", "weltzeituhr", p))

    # ── 10. Layer-two interleave variants ───────────────────────────────
    for n_layers in [2, 3, 4, 7, 8, 13]:
        for order in ["forward", "reverse", "alternate"]:
            p = layer_two_interleave(CT_LEN, n_layers, order)
            if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                all_perms.append((f"layer{n_layers}_{order}", "layer_interleave", p))

    # ── 11. Two-pass reads (first half, second half swapped) ────────────
    mid = CT_LEN // 2
    p = list(range(mid, CT_LEN)) + list(range(mid))
    all_perms.append(("swap_halves", "two_pass", p))
    # Thirds
    t = CT_LEN // 3
    for order in [(1,2,0), (2,0,1), (2,1,0), (0,2,1), (1,0,2)]:
        p = []
        for idx in order:
            start = idx * t
            end = start + t if idx < 2 else CT_LEN
            p.extend(range(start, end))
        if len(p) == CT_LEN and validate_perm(p, CT_LEN):
            name = "".join(str(x) for x in order)
            all_perms.append((f"thirds_{name}", "two_pass", p))

    perms_generated = len(all_perms)
    print(f"Generated {perms_generated} permutations")
    print()
    sys.stdout.flush()

    # ── Test each permutation ─────────────────────────────────────────────

    def process_perm(name: str, category: str, perm: list[int]):
        nonlocal configs_tested, best_score, best_result

        inv = invert_perm(perm)
        intermediate = apply_perm(CT, inv)  # Undo transposition

        # 1. Raw score (no decryption — is the transposed CT already readable?)
        configs_tested += 1
        sc_raw = score_candidate(intermediate)
        raw_entry = {
            "perm_name": name,
            "category": category,
            "mode": "raw",
            "variant": "none",
            "shift": -1,
            "crib_score": sc_raw.crib_score,
            "ic": round(sc_raw.ic_value, 4),
            "classification": sc_raw.crib_classification,
            "plaintext_preview": intermediate[:40],
        }
        if sc_raw.crib_score >= 6:
            results.append(raw_entry)
            print(f"  [RAW ABOVE NOISE] {name}: {sc_raw.summary}")
        if sc_raw.crib_score > best_score:
            best_score = sc_raw.crib_score
            best_result = raw_entry

        # 2. Position-free score
        configs_tested += 1
        sc_free = score_candidate_free(intermediate)
        if sc_free.crib_score >= 11:
            free_entry = {
                "perm_name": name,
                "category": category,
                "mode": "free",
                "variant": "none",
                "crib_score": sc_free.crib_score,
                "ic": round(sc_free.ic_value, 4),
                "classification": sc_free.crib_classification,
                "plaintext_preview": intermediate[:40],
            }
            results.append(free_entry)
            print(f"  [FREE MATCH] {name}: {sc_free.summary}")

        # 3. Try all shifts + variants
        for variant in VARIANTS:
            for shift in range(26):
                configs_tested += 1
                key_list = [shift] * CT_LEN
                pt = decrypt_text(intermediate, key_list, variant)
                sc = score_candidate(pt)

                if sc.crib_score >= 6:
                    entry = {
                        "perm_name": name,
                        "category": category,
                        "mode": "shift",
                        "variant": variant.value,
                        "shift": shift,
                        "crib_score": sc.crib_score,
                        "ic": round(sc.ic_value, 4),
                        "classification": sc.crib_classification,
                        "plaintext_preview": pt[:40],
                    }
                    results.append(entry)
                    print(f"  [ABOVE NOISE] {name}/shift{shift}/{variant.value}: {sc.summary}")

                if sc.crib_score > best_score:
                    best_score = sc.crib_score
                    best_result = entry if sc.crib_score >= 6 else {
                        "perm_name": name,
                        "category": category,
                        "mode": "shift",
                        "variant": variant.value,
                        "shift": shift,
                        "crib_score": sc.crib_score,
                    }
                    if sc.crib_score >= 10:
                        print(f"  ** STORE-WORTHY: {name}/shift{shift}/{variant.value}: {sc.summary}")

    for i, (name, cat, perm) in enumerate(all_perms):
        if i % 50 == 0:
            print(f"  Processing perm {i+1}/{perms_generated}...")
            sys.stdout.flush()
        process_perm(name, cat, perm)

    # ── Summary ───────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"FINAL SUMMARY — E-TEAM-PHYSICAL-TRANSPOSITIONS")
    print("=" * 70)
    print(f"Permutations generated: {perms_generated}")
    print(f"Total configs tested: {configs_tested}")
    above_noise = [r for r in results if r['crib_score'] >= 6]
    print(f"Above noise (>=6): {len(above_noise)}")
    store_worthy = [r for r in results if r['crib_score'] >= 10]
    print(f"Store-worthy (>=10): {len(store_worthy)}")
    signal = [r for r in results if r['crib_score'] >= 18]
    print(f"Signal (>=18): {len(signal)}")
    print(f"Best score: {best_score}/24")
    if best_result:
        print(f"Best config: {best_result.get('perm_name', '?')} / {best_result.get('variant', '?')} / shift {best_result.get('shift', '?')}")
        if 'plaintext_preview' in best_result:
            print(f"Best PT preview: {best_result['plaintext_preview']}")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Save ──────────────────────────────────────────────────────────────
    output = {
        "experiment": "e_team_physical_transpositions",
        "perms_generated": perms_generated,
        "configs_tested": configs_tested,
        "above_noise": len(above_noise),
        "store_worthy": len(store_worthy),
        "best_score": best_score,
        "best_result": best_result,
        "elapsed_seconds": round(elapsed, 1),
        "all_above_noise": sorted(results, key=lambda x: -x["crib_score"]),
    }

    out_path = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_physical_transpositions.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")

    # Verdict
    if best_score >= 18:
        print("\n*** SIGNAL DETECTED — investigate immediately ***")
    elif best_score >= 10:
        print("\n** INTERESTING — worth further analysis **")
    else:
        print("\nVerdict: NOISE — no physical transposition produces meaningful crib matches")


if __name__ == "__main__":
    main()
