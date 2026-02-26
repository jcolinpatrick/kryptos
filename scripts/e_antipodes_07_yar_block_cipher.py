#!/usr/bin/env python3
"""
E-ANTIPODES-07: YAR-Parameterized Block Cipher

HYPOTHESIS: YAR (superscript at K3/K4 boundary, absent from Antipodes) encodes
cipher parameters: Y=24 (block size), A=0 (offset), R=17 (rotation/shift).
K4 is encrypted with a block cipher using 24-char blocks with rotation 17.

WHY ANTIPODES: YAR is absent from Antipodes (= K4-specific clue). Y=24 matches
the Berlin Clock's 24-hour display. R=17 matches structural counts.

METHOD:
1. Split K4 into blocks: various block sizes (including YAR-parameterized)
2. For each block arrangement:
   - Apply intra-block rotation
   - Apply columnar transposition / Mengenlehreuhr transform
   - After transposition: decrypt with Vig/Beau/VarBeau and various keys
3. Berlin Clock time structure as reading order within blocks

COST: ~5K block arrangements × 3 variants × ~100 key sources ≈ 1.5M. Under 3 min.
"""

import json
import os
import sys
import time
import itertools
from typing import List, Dict, Tuple
from multiprocessing import Pool, cpu_count

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm, keyword_to_order, validate_perm,
    BLOCK_SIZE, MENGEN_BANDS, make_mengen_route, apply_rotation,
    apply_reflection, unmask_block_transposition,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constraints.bean import verify_bean_simple

# ── YAR-derived parameters ───────────────────────────────────────────────

# Y=24 (or Y=25, 0-indexed letter position for Y), A=0, R=17
# Also try: letter values in KA alphabet
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
YAR_PARAMS = {
    "Y_AZ": ord('Y') - 65,   # 24
    "A_AZ": ord('A') - 65,   # 0
    "R_AZ": ord('R') - 65,   # 17
    "Y_KA": KA_IDX['Y'],     # position in KA
    "A_KA": KA_IDX['A'],
    "R_KA": KA_IDX['R'],
}

# Block sizes to test: YAR-derived + Berlin Clock + factors near 97
BLOCK_SIZES = sorted(set([
    24,                          # Y=24, Berlin Clock
    YAR_PARAMS["Y_KA"],         # Y in KA
    YAR_PARAMS["R_AZ"],         # R=17
    YAR_PARAMS["R_KA"],         # R in KA
    8, 12, 16, 20,              # Even divisors near 24
    7, 9, 11, 13,               # Small primes / factors
    97,                          # Full-text as single block
]))
BLOCK_SIZES = [b for b in BLOCK_SIZES if 2 <= b <= 97]

# Rotation amounts to test
ROTATIONS = sorted(set([
    0, 1,
    YAR_PARAMS["R_AZ"],         # 17
    YAR_PARAMS["R_KA"],
    YAR_PARAMS["A_AZ"],         # 0
    YAR_PARAMS["Y_AZ"],         # 24
    7, 13, 24,
    YAR_PARAMS["Y_AZ"] - YAR_PARAMS["R_AZ"],  # Y-R
]))
ROTATIONS = [r for r in ROTATIONS if 0 <= r < 97]

# Keywords for substitution layer
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "SANBORN",
    "SCHEIDT", "YAR", "SHADOW", "ENIGMA", "CLOCK",
]


def rotate_block(text: str, block_size: int, rotation: int) -> str:
    """Apply intra-block rotation. Each block is cyclically shifted."""
    out = []
    for i in range(0, len(text), block_size):
        block = text[i:i+block_size]
        if len(block) == block_size:
            r = rotation % block_size
            rotated = block[r:] + block[:r]
            out.append(rotated)
        else:
            out.append(block)  # Remainder block: no rotation
    return "".join(out)


def berlin_clock_reading_order(block_size: int = 24) -> List[int]:
    """Berlin Clock time structure as reading order within a 24-element block.

    Mengenlehreuhr layout:
    - Band A: 1 indicator (seconds)
    - Band B: 4 indicators (5-hour blocks)
    - Band C: 4 indicators (1-hour blocks)
    - Band D: 11 indicators (5-minute blocks)
    - Band E: 4 indicators (1-minute blocks)

    Various reading orders through these bands.
    """
    if block_size != 24:
        return list(range(block_size))
    # Standard: top-to-bottom, left-to-right
    return list(range(24))


def columnar_within_block(text: str, block_size: int, width: int, col_order: Tuple[int, ...]) -> str:
    """Apply columnar transposition within each block."""
    out = []
    for i in range(0, len(text), block_size):
        block = text[i:i+block_size]
        if len(block) < width:
            out.append(block)
            continue
        # Build columnar perm for this block
        perm = columnar_perm(width, col_order, len(block))
        inv_p = invert_perm(perm)
        out.append(apply_perm(block, inv_p))
    return "".join(out)


def make_key(keyword: str, length: int) -> List[int]:
    """Convert keyword to repeating numeric key."""
    kw_nums = [ord(c) - 65 for c in keyword.upper()]
    return [kw_nums[i % len(kw_nums)] for i in range(length)]


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-ANTIPODES-07: YAR-Parameterized Block Cipher")
    print("=" * 70)
    print(f"YAR parameters: {YAR_PARAMS}")
    print(f"Block sizes: {BLOCK_SIZES}")
    print(f"Rotations: {ROTATIONS}")

    best_score = 0
    best_result = None
    total_configs = 0
    above_noise = []

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    # ── Phase 1: Block rotation + keyword Vigenère ───────────────────────
    print("\n--- Phase 1: Block rotation + keyword Vigenère ---")

    for block_size in BLOCK_SIZES:
        for rotation in ROTATIONS:
            if rotation >= block_size:
                continue
            # Rotate blocks
            rotated = rotate_block(CT, block_size, rotation)

            for keyword in KEYWORDS:
                key = make_key(keyword, CT_LEN)
                for variant in variants:
                    total_configs += 1
                    pt = decrypt_text(rotated, key, variant)
                    sc = score_cribs(pt)

                    if sc > best_score:
                        best_score = sc
                        best_result = {
                            "phase": 1,
                            "block_size": block_size,
                            "rotation": rotation,
                            "keyword": keyword,
                            "variant": variant.value,
                            "plaintext": pt,
                            "crib_score": sc,
                        }
                        if sc > NOISE_FLOOR:
                            print(f"  NEW BEST: {sc}/24, bs={block_size}, rot={rotation}, "
                                  f"kw={keyword}, {variant.value}")

                    if sc > NOISE_FLOOR:
                        above_noise.append({
                            "phase": 1,
                            "block_size": block_size,
                            "rotation": rotation,
                            "keyword": keyword,
                            "variant": variant.value,
                            "crib_score": sc,
                        })

    print(f"  Phase 1: {total_configs:,} configs, best={best_score}")

    # ── Phase 2: Mengenlehreuhr routes + rotation ────────────────────────
    print("\n--- Phase 2: Mengenlehreuhr routes + rotation ---")
    phase2_start = total_configs

    routes = ["identity", "band_boustro", "all_forward", "all_reversed", "reverse_bands"]
    for route_name in routes:
        for boustro in range(2):
            try:
                route = make_mengen_route(route_name, boustro)
            except ValueError:
                continue

            for rot in ROTATIONS:
                if rot >= BLOCK_SIZE:
                    continue
                rotated_route = apply_rotation(route, rot)

                # Also test reflected
                for reflect in [False, True]:
                    if reflect:
                        test_route = apply_reflection(rotated_route)
                    else:
                        test_route = rotated_route

                    # Apply block transposition
                    for cycle_boustro in [False, True]:
                        intermediate = unmask_block_transposition(CT, test_route, cycle_boustro)

                        for keyword in KEYWORDS:
                            key = make_key(keyword, CT_LEN)
                            for variant in variants:
                                total_configs += 1
                                pt = decrypt_text(intermediate, key, variant)
                                sc = score_cribs(pt)

                                if sc > best_score:
                                    best_score = sc
                                    best_result = {
                                        "phase": 2,
                                        "route": route_name,
                                        "boustro_parity": boustro,
                                        "rotation": rot,
                                        "reflected": reflect,
                                        "cycle_boustro": cycle_boustro,
                                        "keyword": keyword,
                                        "variant": variant.value,
                                        "plaintext": pt,
                                        "crib_score": sc,
                                    }
                                    if sc > NOISE_FLOOR:
                                        print(f"  NEW BEST: {sc}/24, route={route_name}, "
                                              f"rot={rot}, kw={keyword}, {variant.value}")

                                if sc > NOISE_FLOOR:
                                    above_noise.append({
                                        "phase": 2,
                                        "route": route_name,
                                        "rotation": rot,
                                        "keyword": keyword,
                                        "variant": variant.value,
                                        "crib_score": sc,
                                    })

    print(f"  Phase 2: {total_configs - phase2_start:,} configs, best={best_score}")

    # ── Phase 3: Block rotation + columnar within block ──────────────────
    print("\n--- Phase 3: Block rotation + columnar within block ---")
    phase3_start = total_configs

    for block_size in [24, 12, 8]:
        for rotation in [0, 17, 7, 13, 24]:
            if rotation >= block_size:
                continue
            rotated = rotate_block(CT, block_size, rotation)

            # Columnar within each block
            for width in range(3, min(block_size, 9)):
                for kw in ["KRYPTOS", "YAR", "BERLIN", "CLOCK"]:
                    order = keyword_to_order(kw, width)
                    if order is None:
                        continue

                    intermediate = columnar_within_block(rotated, block_size, width, order)

                    for sub_kw in KEYWORDS[:5]:
                        key = make_key(sub_kw, CT_LEN)
                        for variant in variants:
                            total_configs += 1
                            pt = decrypt_text(intermediate, key, variant)
                            sc = score_cribs(pt)

                            if sc > best_score:
                                best_score = sc
                                best_result = {
                                    "phase": 3,
                                    "block_size": block_size,
                                    "rotation": rotation,
                                    "col_width": width,
                                    "col_keyword": kw,
                                    "sub_keyword": sub_kw,
                                    "variant": variant.value,
                                    "plaintext": pt,
                                    "crib_score": sc,
                                }
                                if sc > NOISE_FLOOR:
                                    print(f"  NEW BEST: {sc}/24, bs={block_size}, "
                                          f"rot={rotation}, cw={width}, {variant.value}")

                            if sc > NOISE_FLOOR:
                                above_noise.append({
                                    "phase": 3,
                                    "block_size": block_size,
                                    "rotation": rotation,
                                    "col_width": width,
                                    "variant": variant.value,
                                    "crib_score": sc,
                                })

    print(f"  Phase 3: {total_configs - phase3_start:,} configs, best={best_score}")

    # ── Phase 4: Berlin Clock time structure ─────────────────────────────
    print("\n--- Phase 4: Berlin Clock time structure reading ---")
    phase4_start = total_configs

    # Berlin Clock: read positions as time values
    # 5-hour band: positions [1,2,3,4], each = 5 hours
    # 1-hour band: positions [5,6,7,8], each = 1 hour
    # 5-min band: positions [9..19], each = 5 min
    # 1-min band: positions [20..23], each = 1 min
    # Try reading in various band orders

    band_orders = list(itertools.permutations(range(5)))  # 120 orderings of 5 bands
    for band_perm in band_orders:
        route = []
        bands = list(MENGEN_BANDS)
        for bi in band_perm:
            route.extend(bands[bi])
        if len(route) != BLOCK_SIZE:
            continue

        for rot in [0, 17, 7]:
            test_route = apply_rotation(route, rot)
            intermediate = unmask_block_transposition(CT, test_route)

            for keyword in KEYWORDS[:5]:
                key = make_key(keyword, CT_LEN)
                for variant in variants:
                    total_configs += 1
                    pt = decrypt_text(intermediate, key, variant)
                    sc = score_cribs(pt)

                    if sc > best_score:
                        best_score = sc
                        best_result = {
                            "phase": 4,
                            "band_order": list(band_perm),
                            "rotation": rot,
                            "keyword": keyword,
                            "variant": variant.value,
                            "plaintext": pt,
                            "crib_score": sc,
                        }
                        if sc > NOISE_FLOOR:
                            print(f"  NEW BEST: {sc}/24, band_order={band_perm}, "
                                  f"rot={rot}, kw={keyword}, {variant.value}")

                    if sc > NOISE_FLOOR:
                        above_noise.append({
                            "phase": 4,
                            "band_order": list(band_perm),
                            "rotation": rot,
                            "keyword": keyword,
                            "variant": variant.value,
                            "crib_score": sc,
                        })

    print(f"  Phase 4: {total_configs - phase4_start:,} configs, best={best_score}")

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
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_antipodes_07')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-ANTIPODES-07",
        "hypothesis": "YAR-parameterized block cipher (block rotation + Mengenlehreuhr)",
        "total_configs": total_configs,
        "best_score": best_score,
        "best_result": {k: v for k, v in best_result.items() if k != "plaintext"} if best_result else None,
        "above_noise_count": len(above_noise),
        "yar_params": YAR_PARAMS,
        "block_sizes_tested": BLOCK_SIZES,
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
        print("\nCONCLUSION: NOISE — YAR block cipher hypothesis not supported.")
    else:
        print(f"\nCONCLUSION: Score {best_score}/24 — "
              f"{'investigate!' if best_score >= STORE_THRESHOLD else 'likely noise.'}")


if __name__ == "__main__":
    main()
