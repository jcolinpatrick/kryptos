#!/usr/bin/env python3
"""
Cipher: physical/coordinate
Family: thematic/sculpture_physical
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-117: Coordinate-derived key tests for K4.

Tests K2 coordinates [38, 57, 6, 5, 77, 8, 44] as K4 key material.

Key derivations:
  (a) mod 26 → [12, 5, 6, 5, 25, 8, 18] — period-7 key
  (b) Concatenated digits → Gronsfeld-like key
  (c) Degree values → various numeric extractions
  (d) Bearing from sculpture → SE bearing parameter

Tests each with:
  - Direct application (no transposition) — all 3 cipher variants
  - Width-7 columnar transposition — all 5040 orderings × 3 variants
  - Grid rotation transpositions (7×14, 14×7, etc.)

Stage 2 of Progressive Solve Plan.
"""
import json
import itertools
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, recover_key_at_positions,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm,
)
from kryptos.kernel.scoring.crib_score import score_cribs

# ── K2 Coordinates ──────────────────────────────────────────────────────
COORDS_RAW = [38, 57, 6, 5, 77, 8, 44]  # 7 numbers from K2 plaintext
# 38°57'6.5"N, 77°8'44"W

# ── Key Derivations ─────────────────────────────────────────────────────

def derive_keys():
    """Generate all coordinate-derived key candidates."""
    keys = {}

    # (a) Raw mod 26
    keys["raw_mod26"] = [v % MOD for v in COORDS_RAW]  # [12, 5, 6, 5, 25, 8, 18]

    # (b) Include the .5 → [38, 57, 6, 5, 77, 8, 44] with 6.5 split
    coords_with_half = [38, 57, 6, 5, 77, 8, 44]
    keys["raw_mod26_v2"] = [v % MOD for v in coords_with_half]

    # (c) Concatenated digits: 38576577844 → individual digits mod 26
    digit_str = "".join(str(v) for v in COORDS_RAW)
    keys["digits_raw"] = [int(d) for d in digit_str]  # Single digits, no mod needed

    # (d) Digit pairs from concatenation
    if len(digit_str) % 2 == 1:
        digit_str_padded = digit_str + "0"
    else:
        digit_str_padded = digit_str
    keys["digit_pairs_mod26"] = [int(digit_str_padded[i:i+2]) % MOD
                                  for i in range(0, len(digit_str_padded), 2)]

    # (e) Degree-minute-second as single numbers
    lat = 38 + 57/60 + 6.5/3600  # 38.9518°
    lon = 77 + 8/60 + 44/3600    # 77.1456°
    keys["lat_digits"] = [int(d) for d in f"{lat:.4f}".replace(".", "")]
    keys["lon_digits"] = [int(d) for d in f"{lon:.4f}".replace(".", "")]

    # (f) Lat/lon interleaved
    lat_d = [int(d) for d in f"{lat:.4f}".replace(".", "")]
    lon_d = [int(d) for d in f"{lon:.4f}".replace(".", "")]
    interleaved = []
    for i in range(max(len(lat_d), len(lon_d))):
        if i < len(lat_d):
            interleaved.append(lat_d[i])
        if i < len(lon_d):
            interleaved.append(lon_d[i])
    keys["latlon_interleaved"] = interleaved

    # (g) DMS components: [3,8,5,7,0,6,5,7,7,0,8,4,4] — all digits
    dms_digits = []
    for v in COORDS_RAW:
        for d in str(v):
            dms_digits.append(int(d))
    keys["dms_digits"] = dms_digits

    # (h) SE bearing ≈ 135° → [1,3,5] or [13,5] mod 26
    keys["bearing_135"] = [1, 3, 5]
    keys["bearing_135_pairs"] = [13, 5]

    # (i) ENE bearing = 67.5° → [6,7,5] or [6,7,5,0]
    keys["bearing_ene_675"] = [6, 7, 5]
    keys["bearing_ene_6750"] = [6, 7, 5, 0]

    # (j) Ordinal values of key coordinate words
    # "ABSCISSA" → [0,1,18,2,8,18,18,0]
    keys["abscissa_ordinals"] = [ALPH_IDX[c] for c in "ABSCISSA"]

    # (k) Combined: coordinate key XOR'd with ABSCISSA ordinals (truncated to 7)
    absc = [ALPH_IDX[c] for c in "ABSCISSA"]
    raw_m26 = [v % MOD for v in COORDS_RAW]
    keys["coords_xor_abscissa"] = [(raw_m26[i] + absc[i % len(absc)]) % MOD
                                    for i in range(7)]

    return keys


def test_direct(key_name, key, results):
    """Test key directly (no transposition) against K4 CT."""
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        pt = decrypt_text(CT, key, variant)
        sc = score_cribs(pt)
        if sc > NOISE_FLOOR:
            results.append({
                "key_name": key_name,
                "key": key,
                "variant": variant.value,
                "transposition": "direct",
                "score": sc,
                "pt_snippet": pt[:40],
            })
        if sc > results[0]["best_direct"] if results else 0:
            pass
    # Always record best for this key
    best = 0
    best_var = None
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        pt = decrypt_text(CT, key, variant)
        sc = score_cribs(pt)
        if sc > best:
            best = sc
            best_var = variant.value
    return best, best_var


def test_w7_columnar(key_name, key, all_results, orderings_to_test=None):
    """Test key with width-7 columnar transposition (Model B: undo trans then sub)."""
    best_score = 0
    best_config = None
    tested = 0

    if orderings_to_test is None:
        orderings_to_test = itertools.permutations(range(7))

    for col_order in orderings_to_test:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        # Model B: CT was transposed AFTER substitution
        # To decrypt: undo transposition first, then undo substitution
        ct_untransposed = apply_perm(CT, inv)

        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(ct_untransposed, key, variant)
            sc = score_cribs(pt)
            tested += 1

            if sc > best_score:
                best_score = sc
                best_config = {
                    "key_name": key_name,
                    "key": key,
                    "variant": variant.value,
                    "col_order": list(col_order),
                    "score": sc,
                }

            if sc > NOISE_FLOOR:
                all_results.append({
                    "key_name": key_name,
                    "key": key,
                    "variant": variant.value,
                    "transposition": f"w7_col_{list(col_order)}",
                    "score": sc,
                })

    return best_score, best_config, tested


def grid_rotation_perm(rows, cols, length, rotation=90):
    """Generate permutation for grid rotation.

    Write text into rows×cols grid (row-major), rotate, read off (row-major).
    rotation: 90 (CW), 180, 270 (CCW)
    Returns perm where output[i] = input[perm[i]].
    """
    # Build grid positions
    perm = []
    if rotation == 90:
        # After 90° CW rotation: new grid is cols×rows
        # new[c][rows-1-r] = old[r][c]
        # Reading new grid row-major: for new_r in range(cols), new_c in range(rows)
        # new[new_r][new_c] corresponds to old[rows-1-new_c][new_r]
        for new_r in range(cols):
            for new_c in range(rows):
                old_r = rows - 1 - new_c
                old_c = new_r
                old_pos = old_r * cols + old_c
                if old_pos < length and len(perm) < length:
                    perm.append(old_pos)
    elif rotation == 270:
        # 270° CW = 90° CCW
        # new[cols-1-c][r] = old[r][c]
        for new_r in range(cols):
            for new_c in range(rows):
                old_r = new_c
                old_c = cols - 1 - new_r
                old_pos = old_r * cols + old_c
                if old_pos < length and len(perm) < length:
                    perm.append(old_pos)
    elif rotation == 180:
        for new_r in range(rows):
            for new_c in range(cols):
                old_r = rows - 1 - new_r
                old_c = cols - 1 - new_c
                old_pos = old_r * cols + old_c
                if old_pos < length and len(perm) < length:
                    perm.append(old_pos)
    return perm


def test_grid_rotations(key_name, key, all_results):
    """Test key with various grid rotation transpositions."""
    best_score = 0
    best_config = None
    tested = 0

    # Grid dimensions to test (rows × cols where rows*cols >= CT_LEN)
    grids = [
        (14, 7, 98),   # 7×14 with padding (98 = 7×14, needs 1 pad char)
        (7, 14, 98),   # 14×7 with padding
        (10, 10, 100), # 10×10 with padding
        (13, 8, 104),  # 8×13 with padding
        (8, 13, 104),  # 13×8 with padding
    ]

    for rows, cols, grid_size in grids:
        for rotation in [90, 180, 270]:
            # Pad CT if needed
            ct_padded = CT + "A" * (grid_size - CT_LEN)
            perm = grid_rotation_perm(rows, cols, grid_size, rotation)
            if len(perm) < CT_LEN:
                continue
            # Truncate perm to CT_LEN
            perm = perm[:CT_LEN]
            if len(set(perm)) != CT_LEN or max(perm) >= grid_size:
                continue

            try:
                inv = invert_perm(perm)
            except Exception:
                continue

            ct_unrotated = apply_perm(ct_padded[:len(perm)], inv)

            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                pt = decrypt_text(ct_unrotated, key, variant)
                sc = score_cribs(pt[:CT_LEN])
                tested += 1

                if sc > best_score:
                    best_score = sc
                    best_config = {
                        "key_name": key_name,
                        "key": key,
                        "variant": variant.value,
                        "grid": f"{rows}x{cols}",
                        "rotation": rotation,
                        "score": sc,
                    }

                if sc > NOISE_FLOOR:
                    all_results.append({
                        "key_name": key_name,
                        "key": key,
                        "variant": variant.value,
                        "transposition": f"grid_{rows}x{cols}_rot{rotation}",
                        "score": sc,
                    })

    return best_score, best_config, tested


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-117: Coordinate-Derived Key Tests")
    print("=" * 70)

    keys = derive_keys()
    print(f"\nDerived {len(keys)} key candidates from K2 coordinates:")
    for name, key in keys.items():
        print(f"  {name}: {key} (len={len(key)})")

    above_noise = []
    summary = {}

    # ── Phase 1: Direct application ──────────────────────────────────────
    print("\n--- Phase 1: Direct application (no transposition) ---")
    for name, key in keys.items():
        best = 0
        best_var = None
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            if sc > best:
                best = sc
                best_var = variant.value
            if sc > NOISE_FLOOR:
                above_noise.append({
                    "key_name": name, "key": key, "variant": variant.value,
                    "transposition": "direct", "score": sc,
                    "pt_snippet": pt[:40],
                })
        summary[f"direct_{name}"] = {"best_score": best, "best_variant": best_var}
        print(f"  {name}: best={best}/24 ({best_var})")

    # ── Phase 2: Width-7 columnar (all 5040 orderings) ──────────────────
    # Only test the primary coordinate key (period-7 mod 26)
    print("\n--- Phase 2: Width-7 columnar (5040 orderings × 3 variants) ---")
    primary_keys = {
        "raw_mod26": keys["raw_mod26"],
        "coords_xor_abscissa": keys["coords_xor_abscissa"],
        "abscissa_ordinals": keys["abscissa_ordinals"],
    }

    for name, key in primary_keys.items():
        best_sc, best_cfg, tested = test_w7_columnar(name, key, above_noise)
        summary[f"w7col_{name}"] = {
            "best_score": best_sc,
            "best_config": best_cfg,
            "tested": tested,
        }
        print(f"  {name}: best={best_sc}/24 ({tested} configs tested)")

    # ── Phase 3: Grid rotation transpositions ────────────────────────────
    print("\n--- Phase 3: Grid rotation transpositions ---")
    for name, key in keys.items():
        best_sc, best_cfg, tested = test_grid_rotations(name, key, above_noise)
        summary[f"grid_{name}"] = {
            "best_score": best_sc,
            "best_config": best_cfg,
            "tested": tested,
        }
        if best_sc > 0:
            print(f"  {name}: best={best_sc}/24 ({tested} configs)")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")

    # Global best
    global_best = 0
    global_best_cfg = None
    for k, v in summary.items():
        sc = v.get("best_score", 0)
        if sc > global_best:
            global_best = sc
            global_best_cfg = v

    print(f"Global best score: {global_best}/24")
    if global_best_cfg:
        print(f"Best config: {global_best_cfg}")
    print(f"Results above noise (>{NOISE_FLOOR}): {len(above_noise)}")

    if above_noise:
        print("\nAbove-noise results:")
        for r in sorted(above_noise, key=lambda x: -x["score"])[:20]:
            print(f"  score={r['score']}/24 key={r['key_name']} var={r['variant']} trans={r['transposition']}")

    # Verdict
    if global_best >= 18:
        verdict = "SIGNAL"
    elif global_best > NOISE_FLOOR:
        verdict = "STORE"
    else:
        verdict = "NOISE"
    print(f"\nVERDICT: {verdict}")
    print(f"Coordinate-derived keys {'show signal' if verdict != 'NOISE' else 'are at noise floor'} for K4.")

    # ── Write artifacts ──────────────────────────────────────────────────
    artifact = {
        "experiment_id": "e_s_117",
        "stage": 2,
        "hypothesis": "K2 coordinates provide period-7 key for K4",
        "parameters_source": "K2",
        "keys_tested": {name: key for name, key in keys.items()},
        "summary": summary,
        "above_noise": above_noise,
        "verdict": verdict,
        "global_best_score": global_best,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_117_coordinate_keys.py",
    }

    out_path = "artifacts/progressive_solve/stage2/coordinate_keys.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
