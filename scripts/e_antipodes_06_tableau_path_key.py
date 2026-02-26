#!/usr/bin/env python3
"""
E-ANTIPODES-06: Tableau Path as Running Key

HYPOTHESIS: The Kryptos/Antipodes tableau serves as both encryption tool AND
key source. A path through the 26x26 tableau (diagonal, spiral, knight's move,
etc.) generates a 97-character running key. The extra L on Kryptos indicates
where the path deviates.

WHY ANTIPODES: The Antipodes tableau is PERFECT (human-verified, zero anomalies).
Sanborn is a sculptor, not a mathematician — "not a math solution" could mean a
PHYSICAL procedure: follow a path through the tableau, read off key values.

METHOD:
1. Model tableau as 26x26 grid: cell[r][c] = KA_alphabet[(r + c) mod 26]
2. Path families:
   - Linear diagonal: start (r0,c0), step (dr,dc) with wrap
   - Spiral: from corners/center, CW and CCW
   - Knight's move: (2,1), (1,2) steps and variants
   - Row-then-column alternating
   - PT-autokey path: next position determined by decrypted letter
3. For each path, extract 97 key values, decrypt K4, score

COST: ~15K paths × 3 variants ≈ 45K. Under 15 sec.
"""

import json
import os
import sys
import time
from typing import List, Tuple, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constraints.bean import verify_bean_simple

# ── Build KA tableau ─────────────────────────────────────────────────────

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

def build_tableau() -> List[List[int]]:
    """Build 26x26 KA tableau as numeric values.
    cell[r][c] = (r + c) mod 26, indexing into KRYPTOS_ALPHABET.
    """
    return [[(r + c) % 26 for c in range(26)] for r in range(26)]

TABLEAU = build_tableau()

def tableau_char(r: int, c: int) -> str:
    return KRYPTOS_ALPHABET[(r + c) % 26]

def tableau_num(r: int, c: int) -> int:
    return (r + c) % 26

# ── Path generators ──────────────────────────────────────────────────────

def gen_linear_paths(length: int = CT_LEN):
    """Linear paths: start (r0,c0), step (dr,dc) with wrap."""
    steps = []
    for dr in range(-5, 6):
        for dc in range(-5, 6):
            if dr == 0 and dc == 0:
                continue
            steps.append((dr, dc))

    for r0 in range(26):
        for c0 in range(26):
            for dr, dc in steps:
                path = []
                r, c = r0, c0
                for _ in range(length):
                    path.append(tableau_num(r, c))
                    r = (r + dr) % 26
                    c = (c + dc) % 26
                yield f"linear_r{r0}c{c0}_d{dr}d{dc}", path


def gen_spiral_paths(length: int = CT_LEN):
    """Spiral paths from corners and center."""
    starts = [(0, 0), (0, 25), (25, 0), (25, 25), (13, 13)]
    for sr, sc in starts:
        for cw in [True, False]:
            # Spiral outward
            dirs_cw = [(0, 1), (1, 0), (0, -1), (-1, 0)]
            dirs_ccw = [(1, 0), (0, 1), (-1, 0), (0, -1)]
            dirs = dirs_cw if cw else dirs_ccw

            visited = set()
            path = []
            r, c = sr, sc
            d = 0

            for _ in range(26 * 26):
                rw, cw_ = r % 26, c % 26
                if (rw, cw_) in visited:
                    # Try next direction
                    found = False
                    for dd in range(4):
                        nd = (d + dd) % 4
                        nr = (r + dirs[nd][0]) % 26
                        nc = (c + dirs[nd][1]) % 26
                        if (nr, nc) not in visited:
                            d = nd
                            r, c = nr, nc
                            found = True
                            break
                    if not found:
                        break
                    rw, cw_ = r % 26, c % 26

                visited.add((rw, cw_))
                path.append(tableau_num(rw, cw_))

                if len(path) >= length:
                    break

                # Try to continue in same direction
                nr = (r + dirs[d][0]) % 26
                nc = (c + dirs[d][1]) % 26
                if (nr, nc) not in visited:
                    r, c = nr, nc
                else:
                    # Turn
                    d = (d + 1) % 4
                    nr = (r + dirs[d][0]) % 26
                    nc = (c + dirs[d][1]) % 26
                    r, c = nr, nc

            if len(path) >= length:
                label = f"spiral_r{sr}c{sc}_{'cw' if cw else 'ccw'}"
                yield label, path[:length]


def gen_knight_paths(length: int = CT_LEN):
    """Knight's move paths (chess knight)."""
    knight_moves = [(2, 1), (1, 2), (-1, 2), (-2, 1),
                    (-2, -1), (-1, -2), (1, -2), (2, -1)]

    for r0 in range(26):
        for c0 in range(26):
            for dr, dc in knight_moves:
                path = []
                r, c = r0, c0
                for _ in range(length):
                    path.append(tableau_num(r % 26, c % 26))
                    r = (r + dr) % 26
                    c = (c + dc) % 26
                yield f"knight_r{r0}c{c0}_d{dr}d{dc}", path


def gen_row_col_alternating(length: int = CT_LEN):
    """Alternate reading row r then column c."""
    for r0 in range(26):
        for c0 in range(26):
            path = []
            r, c = r0, c0
            reading_row = True
            pos = 0
            while len(path) < length:
                if reading_row:
                    for j in range(26):
                        path.append(tableau_num(r, (c + j) % 26))
                        if len(path) >= length:
                            break
                    r = (r + 1) % 26
                else:
                    for j in range(26):
                        path.append(tableau_num((r + j) % 26, c))
                        if len(path) >= length:
                            break
                    c = (c + 1) % 26
                reading_row = not reading_row
            yield f"rowcol_r{r0}c{c0}", path[:length]


def gen_diagonal_wrap(length: int = CT_LEN):
    """Diagonals with various strides, wrapping around the 26x26 grid."""
    for r0 in range(26):
        for stride in range(1, 26):
            path = []
            for i in range(length):
                r = (r0 + i) % 26
                c = (i * stride) % 26
                path.append(tableau_num(r, c))
            yield f"diagwrap_r{r0}_s{stride}", path


DECRYPT_FNS = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-ANTIPODES-06: Tableau Path as Running Key")
    print("=" * 70)

    best_score = 0
    best_result = None
    total_configs = 0
    above_noise = []

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    # ── Phase 1: Linear diagonal paths ───────────────────────────────────
    print("\n--- Phase 1: Linear diagonal paths ---")
    phase1_count = 0
    # Limit: 26 starts × 26 cols × ~100 steps = ~67K. Sample to ~15K.
    for r0 in range(26):
        for c0 in range(0, 26, 2):  # Every other column to reduce
            for dr in range(-3, 4):
                for dc in range(-3, 4):
                    if dr == 0 and dc == 0:
                        continue
                    path = []
                    r, c = r0, c0
                    for _ in range(CT_LEN):
                        path.append(tableau_num(r, c))
                        r = (r + dr) % 26
                        c = (c + dc) % 26

                    for variant in variants:
                        total_configs += 1
                        phase1_count += 1
                        pt = decrypt_text(CT, path, variant)
                        sc = score_cribs(pt)

                        if sc > best_score:
                            best_score = sc
                            best_result = {
                                "path_type": "linear",
                                "r0": r0, "c0": c0,
                                "dr": dr, "dc": dc,
                                "variant": variant.value,
                                "plaintext": pt,
                                "crib_score": sc,
                            }
                            if sc > NOISE_FLOOR:
                                print(f"  NEW BEST: {sc}/24, linear ({r0},{c0})+({dr},{dc}), "
                                      f"{variant.value}")

                        if sc > NOISE_FLOOR:
                            above_noise.append({
                                "path_type": "linear",
                                "r0": r0, "c0": c0, "dr": dr, "dc": dc,
                                "variant": variant.value,
                                "crib_score": sc,
                            })

    print(f"  Phase 1: {phase1_count:,} configs, best={best_score}")

    # ── Phase 2: Knight's move paths ─────────────────────────────────────
    print("\n--- Phase 2: Knight's move paths ---")
    phase2_count = 0
    knight_moves = [(2, 1), (1, 2), (-1, 2), (-2, 1),
                    (-2, -1), (-1, -2), (1, -2), (2, -1)]

    for r0 in range(26):
        for c0 in range(0, 26, 2):
            for dr, dc in knight_moves:
                path = []
                r, c = r0, c0
                for _ in range(CT_LEN):
                    path.append(tableau_num(r, c))
                    r = (r + dr) % 26
                    c = (c + dc) % 26

                for variant in variants:
                    total_configs += 1
                    phase2_count += 1
                    pt = decrypt_text(CT, path, variant)
                    sc = score_cribs(pt)

                    if sc > best_score:
                        best_score = sc
                        best_result = {
                            "path_type": "knight",
                            "r0": r0, "c0": c0,
                            "dr": dr, "dc": dc,
                            "variant": variant.value,
                            "plaintext": pt,
                            "crib_score": sc,
                        }
                        if sc > NOISE_FLOOR:
                            print(f"  NEW BEST: {sc}/24, knight ({r0},{c0})+({dr},{dc}), "
                                  f"{variant.value}")

                    if sc > NOISE_FLOOR:
                        above_noise.append({
                            "path_type": "knight",
                            "r0": r0, "c0": c0, "dr": dr, "dc": dc,
                            "variant": variant.value,
                            "crib_score": sc,
                        })

    print(f"  Phase 2: {phase2_count:,} configs, best={best_score}")

    # ── Phase 3: Diagonal wrap paths ─────────────────────────────────────
    print("\n--- Phase 3: Diagonal wrap paths ---")
    phase3_count = 0
    for r0 in range(26):
        for stride in range(1, 26):
            path = []
            for i in range(CT_LEN):
                r = (r0 + i) % 26
                c = (i * stride) % 26
                path.append(tableau_num(r, c))

            for variant in variants:
                total_configs += 1
                phase3_count += 1
                pt = decrypt_text(CT, path, variant)
                sc = score_cribs(pt)

                if sc > best_score:
                    best_score = sc
                    best_result = {
                        "path_type": "diagwrap",
                        "r0": r0, "stride": stride,
                        "variant": variant.value,
                        "plaintext": pt,
                        "crib_score": sc,
                    }
                    if sc > NOISE_FLOOR:
                        print(f"  NEW BEST: {sc}/24, diagwrap r0={r0} stride={stride}, "
                              f"{variant.value}")

                if sc > NOISE_FLOOR:
                    above_noise.append({
                        "path_type": "diagwrap",
                        "r0": r0, "stride": stride,
                        "variant": variant.value,
                        "crib_score": sc,
                    })

    print(f"  Phase 3: {phase3_count:,} configs, best={best_score}")

    # ── Phase 4: Row-column alternating ──────────────────────────────────
    print("\n--- Phase 4: Row-column alternating ---")
    phase4_count = 0
    for r0 in range(26):
        for c0 in range(26):
            path = []
            r, c = r0, c0
            reading_row = True
            while len(path) < CT_LEN:
                if reading_row:
                    for j in range(26):
                        path.append(tableau_num(r, (c + j) % 26))
                        if len(path) >= CT_LEN:
                            break
                    r = (r + 1) % 26
                else:
                    for j in range(26):
                        path.append(tableau_num((r + j) % 26, c))
                        if len(path) >= CT_LEN:
                            break
                    c = (c + 1) % 26
                reading_row = not reading_row

            key = path[:CT_LEN]
            for variant in variants:
                total_configs += 1
                phase4_count += 1
                pt = decrypt_text(CT, key, variant)
                sc = score_cribs(pt)

                if sc > best_score:
                    best_score = sc
                    best_result = {
                        "path_type": "rowcol",
                        "r0": r0, "c0": c0,
                        "variant": variant.value,
                        "plaintext": pt,
                        "crib_score": sc,
                    }
                    if sc > NOISE_FLOOR:
                        print(f"  NEW BEST: {sc}/24, rowcol ({r0},{c0}), {variant.value}")

                if sc > NOISE_FLOOR:
                    above_noise.append({
                        "path_type": "rowcol",
                        "r0": r0, "c0": c0,
                        "variant": variant.value,
                        "crib_score": sc,
                    })

    print(f"  Phase 4: {phase4_count:,} configs, best={best_score}")

    # ── Phase 5: Spiral paths ────────────────────────────────────────────
    print("\n--- Phase 5: Spiral paths ---")
    phase5_count = 0
    for label, path in gen_spiral_paths():
        if len(path) < CT_LEN:
            continue
        key = path[:CT_LEN]
        for variant in variants:
            total_configs += 1
            phase5_count += 1
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)

            if sc > best_score:
                best_score = sc
                best_result = {
                    "path_type": "spiral",
                    "label": label,
                    "variant": variant.value,
                    "plaintext": pt,
                    "crib_score": sc,
                }
                if sc > NOISE_FLOOR:
                    print(f"  NEW BEST: {sc}/24, {label}, {variant.value}")

            if sc > NOISE_FLOOR:
                above_noise.append({
                    "path_type": "spiral",
                    "label": label,
                    "variant": variant.value,
                    "crib_score": sc,
                })

    print(f"  Phase 5: {phase5_count:,} configs, best={best_score}")

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Best crib score: {best_score}/24")
    if best_result:
        for k, v in best_result.items():
            if k != "plaintext":
                print(f"  {k}: {v}")
        if best_score >= STORE_THRESHOLD:
            print(f"Best plaintext: {best_result.get('plaintext')}")
    print(f"Above-noise results: {len(above_noise)}")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Write results ─────────────────────────────────────────────────────
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_antipodes_06')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-ANTIPODES-06",
        "hypothesis": "Tableau path (diagonal/spiral/knight/rowcol) as running key",
        "total_configs": total_configs,
        "best_score": best_score,
        "best_result": {k: v for k, v in best_result.items() if k != "plaintext"} if best_result else None,
        "above_noise_count": len(above_noise),
        "elapsed_seconds": elapsed,
    }
    with open(os.path.join(outdir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    if above_noise:
        above_noise.sort(key=lambda x: x["crib_score"], reverse=True)
        with open(os.path.join(outdir, 'above_noise.json'), 'w') as f:
            json.dump(above_noise[:100], f, indent=2)

    print(f"\nResults written to {outdir}/")
    if best_score <= NOISE_FLOOR:
        print("\nCONCLUSION: NOISE — Tableau path key hypothesis not supported.")
    else:
        print(f"\nCONCLUSION: Score {best_score}/24 — "
              f"{'investigate!' if best_score >= STORE_THRESHOLD else 'likely noise.'}")


if __name__ == "__main__":
    main()
