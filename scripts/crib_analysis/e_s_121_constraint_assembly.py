#!/usr/bin/env python3
"""
Cipher: crib-based constraint
Family: crib_analysis
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-121: Full constraint assembly pipeline — ALL K0-K3 parameters × ALL models.

Combines every parameter extracted from K0–K3 into a constrained product space:
  Substitution: {KRYPTOS, PALIMPCEST, ABSCISSA, COORD_MOD26, EQUAL, CQUAE, YAR,
                  ENE ordinals, compass bearing, various combinations}
  Transposition: {identity, w5/w7/w8 columnar (sampled), 7×14 grid rotation,
                  serpentine, rail fence, T=19 offset, block-24 rotation}
  Layer order: {sub-then-trans (Model A), trans-then-sub (Model B)}

Stage 4 of Progressive Solve Plan — FULL SWEEP.
"""
import json
import itertools
import os
import sys
import time
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm,
    rail_fence_perm, serpentine_perm, spiral_perm,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic


def make_key(text):
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


def grid_rotation_perm(rows, cols, length, rotation=90):
    """Generate permutation for grid rotation (CW)."""
    perm = []
    if rotation == 90:
        for new_r in range(cols):
            for new_c in range(rows):
                old_r = rows - 1 - new_c
                old_c = new_r
                old_pos = old_r * cols + old_c
                if old_pos < length and len(perm) < length:
                    perm.append(old_pos)
    elif rotation == 270:
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


def main():
    t0 = time.time()
    random.seed(121)
    print("=" * 70)
    print("E-S-121: Full Constraint Assembly Pipeline")
    print("=" * 70)

    # ── Substitution key candidates ──────────────────────────────────────
    sub_keys = {
        "KRYPTOS": make_key("KRYPTOS"),
        "PALIMPCEST": make_key("PALIMPCEST"),
        "ABSCISSA": make_key("ABSCISSA"),
        "COORD_MOD26": [v % MOD for v in [38, 57, 6, 5, 77, 8, 44]],
        "EQUAL": make_key("EQUAL"),
        "CQUAE": make_key("CQUAE"),
        "YAR": [24, 0, 17],
        "ENE_ordinals": [4, 13, 4],
        "ENE_675": [6, 7, 5],
        "SHADOWFORCES": make_key("SHADOWFORCES"),
        "LUCIDMEMORY": make_key("LUCIDMEMORY"),
        "VIRTUALLYINVISIBLE": make_key("VIRTUALLYINVISIBLE"),
        "TISYOURPOSITION": make_key("TISYOURPOSITION"),
        "ALLYENVY": make_key("ALLYENVY"),
        "COORD_XOR_ABSC": [(([38,57,6,5,77,8,44][i] % 26) + make_key("ABSCISSA")[i % 8]) % 26 for i in range(7)],
        "BERLINCLOCK": make_key("BERLINCLOCK"),
        "EASTNORTHEAST": make_key("EASTNORTHEAST"),
        "PALIMPSEST": make_key("PALIMPSEST"),  # Corrected spelling
        "DESPARATLY": make_key("DESPARATLY"),
    }

    # ── Transposition candidates ─────────────────────────────────────────
    # Precompute transposition permutations
    trans_perms = {}

    # Identity (no transposition)
    trans_perms["identity"] = list(range(CT_LEN))

    # Width-7 columnar: sample 500 orderings
    w7_orderings = [tuple(random.sample(range(7), 7)) for _ in range(500)]
    w7_orderings.extend([tuple(range(7)), tuple(range(6,-1,-1))])
    # Add KRYPTOS-derived ordering
    kw = "KRYPTOS"
    indexed = sorted(range(7), key=lambda i: kw[i])
    kryptos_order = [0]*7
    for rank, idx in enumerate(indexed):
        kryptos_order[idx] = rank
    w7_orderings.append(tuple(kryptos_order))
    # ABSCISSA-derived (width 8)
    kw8 = "ABSCISSA"
    indexed8 = sorted(range(8), key=lambda i: (kw8[i], i))
    abscissa_order = [0]*8
    for rank, idx in enumerate(indexed8):
        abscissa_order[idx] = rank
    # Width-5 orderings (for DESPARATLY connection)
    w5_orderings = [tuple(random.sample(range(5), 5)) for _ in range(120)]

    for col_order in w7_orderings:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        trans_perms[f"w7_{list(col_order)}"] = perm

    for col_order in w5_orderings:
        perm = columnar_perm(5, list(col_order), CT_LEN)
        trans_perms[f"w5_{list(col_order)}"] = perm

    # Width-8 (ABSCISSA is period 8)
    w8_orderings = [tuple(random.sample(range(8), 8)) for _ in range(200)]
    w8_orderings.append(tuple(abscissa_order))
    for col_order in w8_orderings:
        perm = columnar_perm(8, list(col_order), CT_LEN)
        trans_perms[f"w8_{list(col_order)}"] = perm

    # Grid rotations (7×14 with padding)
    for rows, cols in [(7, 14), (14, 7)]:
        for rot in [90, 180, 270]:
            ct_padded = CT + "X"  # 98 chars
            perm = grid_rotation_perm(rows, cols, 98, rot)
            if len(perm) >= CT_LEN:
                trans_perms[f"grid_{rows}x{cols}_rot{rot}"] = perm[:CT_LEN]

    # Rail fence
    for depth in [3, 5, 7, 10, 14]:
        perm = rail_fence_perm(CT_LEN, depth)
        trans_perms[f"railfence_{depth}"] = perm

    # Serpentine
    for rows, cols in [(7, 14), (14, 7), (10, 10)]:
        if rows * cols >= CT_LEN:
            perm = serpentine_perm(rows, cols, CT_LEN, vertical=False)
            if len(perm) == CT_LEN:
                trans_perms[f"serp_{rows}x{cols}_h"] = perm
            perm = serpentine_perm(rows, cols, CT_LEN, vertical=True)
            if len(perm) == CT_LEN:
                trans_perms[f"serp_{rows}x{cols}_v"] = perm

    # T=19 rotation (cyclic shift)
    for offset in [19, 20, 17, 24]:
        perm = [(i + offset) % CT_LEN for i in range(CT_LEN)]
        trans_perms[f"rotate_{offset}"] = perm

    print(f"Substitution keys: {len(sub_keys)}")
    print(f"Transposition permutations: {len(trans_perms)}")
    print(f"Cipher variants: 3")
    print(f"Layer orders: 2")
    total_combos = len(sub_keys) * len(trans_perms) * 3 * 2
    print(f"Total combinations: {total_combos}")

    results = []
    best_overall = 0
    best_config = None
    total_tested = 0
    above_noise_count = 0

    # ── Main sweep ───────────────────────────────────────────────────────
    print("\nRunning full sweep...")

    for trans_name, perm in trans_perms.items():
        if len(perm) != CT_LEN or len(set(perm)) != CT_LEN:
            continue
        if max(perm) >= CT_LEN + 2:  # Allow small padding
            continue

        try:
            inv = invert_perm(perm)
        except Exception:
            continue

        for layer_order in ["model_b", "model_a"]:
            if layer_order == "model_b":
                # Model B: CT = Trans(Sub(PT)) → undo trans first, then sub
                try:
                    ct_intermediate = apply_perm(CT, inv)
                except (IndexError, KeyError):
                    continue
            else:
                # Model A: CT = Sub(Trans(PT)) → undo sub first, then trans
                ct_intermediate = CT  # Sub is applied first in decryption

            for key_name, key in sub_keys.items():
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                    if layer_order == "model_b":
                        pt = decrypt_text(ct_intermediate, key, variant)
                    else:
                        # Model A: decrypt sub first, then undo trans
                        pt_sub = decrypt_text(CT, key, variant)
                        pt = apply_perm(pt_sub, inv)

                    sc = score_cribs(pt)
                    total_tested += 1

                    if sc > best_overall:
                        best_overall = sc
                        best_config = {
                            "trans": trans_name,
                            "key": key_name,
                            "variant": variant.value,
                            "layer": layer_order,
                            "score": sc,
                        }

                    if sc > NOISE_FLOOR:
                        above_noise_count += 1
                        if sc >= STORE_THRESHOLD:
                            results.append({
                                "trans": trans_name,
                                "key": key_name,
                                "variant": variant.value,
                                "layer": layer_order,
                                "score": sc,
                                "pt_snippet": pt[:30],
                            })

        if total_tested % 100000 == 0:
            print(f"  {total_tested} tested, best={best_overall}/24, above_noise={above_noise_count}")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {total_tested}")
    print(f"Global best score: {best_overall}/24")
    print(f"Best config: {best_config}")
    print(f"Above noise (>{NOISE_FLOOR}): {above_noise_count}")
    print(f"Above store (>{STORE_THRESHOLD}): {len(results)}")

    if results:
        print("\nTop results (score ≥ STORE):")
        for r in sorted(results, key=lambda x: -x["score"])[:20]:
            print(f"  score={r['score']}/24 trans={r['trans']} key={r['key']} var={r['variant']} layer={r['layer']}")

    verdict = "SIGNAL" if best_overall >= 18 else ("STORE" if best_overall > NOISE_FLOOR else "NOISE")
    print(f"\nVERDICT: {verdict}")

    # Expected noise baseline for this many tests
    expected_max = min(24, 6 + round(1.5 * (total_tested / 10000) ** 0.1))
    print(f"Expected max from random at {total_tested} tests: ~{expected_max}/24")
    if best_overall <= expected_max:
        print("Best score is CONSISTENT WITH NOISE — no signal detected.")
    else:
        print("Best score EXCEEDS noise expectation — investigate!")

    artifact = {
        "experiment_id": "e_s_121",
        "stage": 4,
        "hypothesis": "K0-K3 constrained parameters combined produce K4 signal",
        "variant_graph": "A+B (both layer orders tested)",
        "parameters_source": "K0+K1+K2+K3+physical",
        "sub_keys_count": len(sub_keys),
        "trans_perms_count": len(trans_perms),
        "total_tested": total_tested,
        "best_score": best_overall,
        "best_config": best_config,
        "above_noise_count": above_noise_count,
        "top_results": sorted(results, key=lambda x: -x["score"])[:50],
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_121_constraint_assembly.py",
    }

    out_path = "artifacts/progressive_solve/stage4/constraint_assembly.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
