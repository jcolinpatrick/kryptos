#!/usr/bin/env python3
"""
Cipher: K3-method extension
Family: k3_continuity
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-119: K3-derived grid rotation tests for K4.

K3 uses a 42×8 grid rotation. K4 has 97 chars (prime).
With terminal Q (from K3 boundary): 98 = 7×14 = 2×49.

Tests:
  (a) Write K4 CT (97 chars) into various grids, rotate, read off → score
  (b) Same with Q prepended (98 chars) → 7×14 is clean
  (c) Apply Vigenère/Beaufort with known keywords after rotation
  (d) Test all 4 rotations (0°, 90°, 180°, 270°) × both read directions

Stage 3 of Progressive Solve Plan.
"""
import json
import itertools
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, KRYPTOS_ALPHABET,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic


def grid_write_read(text, rows, cols, write_dir='row', read_dir='col',
                    write_serpentine=False, read_serpentine=False):
    """Write text into grid in one direction, read in another.

    write_dir: 'row' (left-to-right, top-to-bottom) or 'col' (top-to-bottom, left-to-right)
    read_dir: 'row' or 'col'
    """
    grid_size = rows * cols
    padded = text + "X" * (grid_size - len(text)) if len(text) < grid_size else text[:grid_size]

    # Build grid
    grid = [[' '] * cols for _ in range(rows)]

    # Write phase
    idx = 0
    if write_dir == 'row':
        for r in range(rows):
            row_range = range(cols) if not write_serpentine or r % 2 == 0 else range(cols-1, -1, -1)
            for c in row_range:
                if idx < len(padded):
                    grid[r][c] = padded[idx]
                    idx += 1
    else:  # col
        for c in range(cols):
            col_range = range(rows) if not write_serpentine or c % 2 == 0 else range(rows-1, -1, -1)
            for r in col_range:
                if idx < len(padded):
                    grid[r][c] = padded[idx]
                    idx += 1

    # Read phase
    result = []
    if read_dir == 'row':
        for r in range(rows):
            row_range = range(cols) if not read_serpentine or r % 2 == 0 else range(cols-1, -1, -1)
            for c in row_range:
                result.append(grid[r][c])
    else:  # col
        for c in range(cols):
            col_range = range(rows) if not read_serpentine or c % 2 == 0 else range(rows-1, -1, -1)
            for r in col_range:
                result.append(grid[r][c])

    return "".join(result)[:len(text)]


def rotate_grid_90cw(grid, rows, cols):
    """Rotate grid 90° clockwise. Returns new grid, new_rows, new_cols."""
    new_rows, new_cols = cols, rows
    new_grid = [[' '] * new_cols for _ in range(new_rows)]
    for r in range(rows):
        for c in range(cols):
            new_grid[c][rows - 1 - r] = grid[r][c]
    return new_grid, new_rows, new_cols


def text_to_grid(text, rows, cols):
    """Write text into rows×cols grid row-major."""
    grid_size = rows * cols
    padded = text + "X" * (grid_size - len(text)) if len(text) < grid_size else text[:grid_size]
    grid = []
    for r in range(rows):
        row = []
        for c in range(cols):
            idx = r * cols + c
            row.append(padded[idx] if idx < len(padded) else 'X')
        grid.append(row)
    return grid


def grid_to_text(grid, rows, cols, max_len=None):
    """Read grid row-major."""
    text = ""
    for r in range(rows):
        for c in range(cols):
            text += grid[r][c]
    if max_len:
        text = text[:max_len]
    return text


def test_grid_rotation(text, rows, cols, n_rotations, original_len):
    """Write text into grid, rotate n times (90° CW each), read off."""
    grid = text_to_grid(text, rows, cols)
    cur_rows, cur_cols = rows, cols
    for _ in range(n_rotations):
        grid, cur_rows, cur_cols = rotate_grid_90cw(grid, cur_rows, cur_cols)
    return grid_to_text(grid, cur_rows, cur_cols, original_len)


def make_keyword_key(keyword):
    """Convert keyword to numeric key (A=0)."""
    return [ALPH_IDX[c] for c in keyword.upper()]


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-119: K3-Derived Grid Rotation Tests for K4")
    print("=" * 70)

    # Known keywords for substitution testing
    keywords = {
        "KRYPTOS": make_keyword_key("KRYPTOS"),
        "PALIMPCEST": make_keyword_key("PALIMPCEST"),
        "ABSCISSA": make_keyword_key("ABSCISSA"),
        "COORD_MOD26": [v % MOD for v in [38, 57, 6, 5, 77, 8, 44]],
    }

    # Test texts: original CT (97) and Q+CT (98)
    test_texts = {
        "CT97": CT,
        "QCT98": "Q" + CT,  # Terminal Q prepended
        "CTQ98": CT + "Q",  # Terminal Q appended
    }

    # Grid dimensions to test
    grid_dims = [
        (7, 14),   # 98 = 7×14 (needs Q for clean fit)
        (14, 7),   # 98 = 14×7
        (7, 14),   # Try with 97 too (1 pad)
        (14, 7),
        (10, 10),  # 100 (3 pad)
        (8, 13),   # 104 (7 pad)
        (13, 8),   # 104
        (11, 9),   # 99 (2 pad)
        (9, 11),   # 99
    ]

    results = []
    best_overall = 0
    best_overall_cfg = None
    total_tested = 0

    # Phase 1: Pure rotation (no substitution) — check if rotation alone
    # moves crib characters into position
    print("\n--- Phase 1: Pure grid rotation (no substitution) ---")
    for text_name, text in test_texts.items():
        text_len = len(text)
        for rows, cols in grid_dims:
            grid_size = rows * cols
            if grid_size < text_len:
                continue
            for n_rot in [1, 2, 3]:  # 90°, 180°, 270°
                result_text = test_grid_rotation(text, rows, cols, n_rot, text_len)
                sc = score_cribs(result_text[:CT_LEN] if text_name != "CT97" else result_text)
                ic_val = ic(result_text[:CT_LEN] if text_name != "CT97" else result_text)
                total_tested += 1

                if sc > NOISE_FLOOR or ic_val > 0.050:
                    results.append({
                        "phase": "pure_rotation",
                        "text": text_name,
                        "grid": f"{rows}x{cols}",
                        "rotation": n_rot * 90,
                        "score": sc,
                        "ic": round(ic_val, 4),
                    })

                if sc > best_overall:
                    best_overall = sc
                    best_overall_cfg = f"pure_rot {text_name} {rows}x{cols} rot{n_rot*90}"

        # Also test write-row/read-col and write-col/read-row (columnar-like)
        for rows, cols in grid_dims:
            grid_size = rows * cols
            if grid_size < text_len:
                continue
            for write_d, read_d in [('row', 'col'), ('col', 'row')]:
                for ws in [False, True]:
                    for rs in [False, True]:
                        result_text = grid_write_read(text, rows, cols,
                                                       write_d, read_d, ws, rs)
                        sc = score_cribs(result_text[:CT_LEN] if text_name != "CT97" else result_text)
                        ic_val = ic(result_text[:CT_LEN] if text_name != "CT97" else result_text)
                        total_tested += 1

                        if sc > NOISE_FLOOR or ic_val > 0.050:
                            results.append({
                                "phase": "grid_rw",
                                "text": text_name,
                                "grid": f"{rows}x{cols}",
                                "write": write_d + ("_serp" if ws else ""),
                                "read": read_d + ("_serp" if rs else ""),
                                "score": sc,
                                "ic": round(ic_val, 4),
                            })

                        if sc > best_overall:
                            best_overall = sc
                            best_overall_cfg = f"grid_rw {text_name} {rows}x{cols} w={write_d}{'_s' if ws else ''} r={read_d}{'_s' if rs else ''}"

    print(f"  Tested {total_tested} pure rotation/grid-rw configs")
    print(f"  Best pure rotation score: {best_overall}/24")

    # Phase 2: Rotation + substitution
    print("\n--- Phase 2: Grid rotation + keyword substitution ---")
    phase2_best = 0
    phase2_tested = 0

    for text_name, text in test_texts.items():
        text_len = len(text)
        for rows, cols in [(7, 14), (14, 7)]:  # Focus on 7-related grids
            grid_size = rows * cols
            if grid_size < text_len:
                continue
            for n_rot in [0, 1, 2, 3]:
                if n_rot == 0:
                    # No rotation, just grid read/write
                    for write_d, read_d in [('row', 'col'), ('col', 'row')]:
                        intermediate = grid_write_read(text, rows, cols, write_d, read_d)
                        for kw_name, kw_key in keywords.items():
                            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                                pt = decrypt_text(intermediate[:CT_LEN], kw_key, variant)
                                sc = score_cribs(pt)
                                phase2_tested += 1

                                if sc > phase2_best:
                                    phase2_best = sc

                                if sc > NOISE_FLOOR:
                                    results.append({
                                        "phase": "rot_sub",
                                        "text": text_name,
                                        "grid": f"{rows}x{cols}",
                                        "transposition": f"w={write_d}_r={read_d}",
                                        "keyword": kw_name,
                                        "variant": variant.value,
                                        "score": sc,
                                    })
                else:
                    intermediate = test_grid_rotation(text, rows, cols, n_rot, text_len)
                    for kw_name, kw_key in keywords.items():
                        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                            pt = decrypt_text(intermediate[:CT_LEN], kw_key, variant)
                            sc = score_cribs(pt)
                            phase2_tested += 1

                            if sc > phase2_best:
                                phase2_best = sc

                            if sc > NOISE_FLOOR:
                                results.append({
                                    "phase": "rot_sub",
                                    "text": text_name,
                                    "grid": f"{rows}x{cols}",
                                    "rotation": n_rot * 90,
                                    "keyword": kw_name,
                                    "variant": variant.value,
                                    "score": sc,
                                })

    if phase2_best > best_overall:
        best_overall = phase2_best
    total_tested += phase2_tested
    print(f"  Tested {phase2_tested} rotation+substitution configs")
    print(f"  Best rotation+substitution score: {phase2_best}/24")

    # Phase 3: K3-style rotation at K3 dimensions scaled for K4
    # K3: 42×8 grid, skip-192. For K4: what skip value / dimension would apply?
    print("\n--- Phase 3: K3-style decimation (every Nth character) ---")
    phase3_best = 0
    phase3_tested = 0

    for text_name, text in test_texts.items():
        text_len = len(text)
        # Test various skip values
        for skip in range(2, text_len):
            # Read every skip-th character, wrapping
            reordered = ""
            pos = 0
            visited = set()
            while len(reordered) < text_len:
                if pos not in visited:
                    reordered += text[pos]
                    visited.add(pos)
                pos = (pos + skip) % text_len
                if pos in visited:
                    # Find next unvisited
                    found = False
                    for p in range(text_len):
                        if p not in visited:
                            pos = p
                            found = True
                            break
                    if not found:
                        break

            if len(reordered) != text_len:
                continue

            # Score directly
            sc_direct = score_cribs(reordered[:CT_LEN])
            phase3_tested += 1
            if sc_direct > phase3_best:
                phase3_best = sc_direct

            if sc_direct > NOISE_FLOOR:
                results.append({
                    "phase": "decimation",
                    "text": text_name,
                    "skip": skip,
                    "score": sc_direct,
                    "sub": "none",
                })

            # Also with keyword substitution
            for kw_name, kw_key in keywords.items():
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(reordered[:CT_LEN], kw_key, variant)
                    sc = score_cribs(pt)
                    phase3_tested += 1
                    if sc > phase3_best:
                        phase3_best = sc
                    if sc > NOISE_FLOOR:
                        results.append({
                            "phase": "decimation_sub",
                            "text": text_name,
                            "skip": skip,
                            "keyword": kw_name,
                            "variant": variant.value,
                            "score": sc,
                        })

    if phase3_best > best_overall:
        best_overall = phase3_best
    total_tested += phase3_tested
    print(f"  Tested {phase3_tested} decimation configs")
    print(f"  Best decimation score: {phase3_best}/24")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {total_tested}")
    print(f"Global best score: {best_overall}/24")
    print(f"Results above noise: {len(results)}")

    if results:
        print("\nTop results (above noise):")
        for r in sorted(results, key=lambda x: -x["score"])[:20]:
            print(f"  score={r['score']}/24 {r}")

    verdict = "SIGNAL" if best_overall >= 18 else ("STORE" if best_overall > NOISE_FLOOR else "NOISE")
    print(f"\nVERDICT: {verdict}")

    # Write artifacts
    artifact = {
        "experiment_id": "e_s_119",
        "stage": 3,
        "hypothesis": "K3-derived grid dimensions (esp. 7×14) produce K4 transposition",
        "parameters_source": "K3",
        "total_tested": total_tested,
        "best_score": best_overall,
        "above_noise": results,
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_119_k3_grid_k4.py",
    }

    out_path = "artifacts/progressive_solve/stage3/k3_grid_k4_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
