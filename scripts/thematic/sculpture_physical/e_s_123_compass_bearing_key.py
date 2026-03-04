#!/usr/bin/env python3
"""
Cipher: physical/coordinate
Family: thematic/sculpture_physical
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-123: Compass bearing + YAR superscript key tests for K4.

Tests:
  (a) ENE bearing 67.5° → various numeric derivations as keys
  (b) YAR superscript [Y=24, A=0, R=17] as key/offset/block parameters
  (c) "T IS YOUR POSITION" → T=19 as starting offset
  (d) Combined compass + YAR + T-position parameters

Stage 4 of Progressive Solve Plan.
"""
import json
import os
import sys
import time
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm,
)
from kryptos.kernel.scoring.crib_score import score_cribs


def make_key(letters):
    return [ALPH_IDX[c] for c in letters.upper()]


def rotate_text(text, offset):
    """Rotate text by offset positions (read starting at offset, wrapping)."""
    n = len(text)
    return text[offset % n:] + text[:offset % n]


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-123: Compass Bearing + YAR Key Tests")
    print("=" * 70)

    results = []
    best_overall = 0
    total_tested = 0

    # ── Key derivations ──────────────────────────────────────────────────

    # Compass bearing derivations
    bearing_keys = {
        "ENE_675_digits": [6, 7, 5],
        "ENE_6750_digits": [6, 7, 5, 0],
        "ENE_ordinals": [ALPH_IDX['E'], ALPH_IDX['N'], ALPH_IDX['E']],  # [4,13,4]
        "ENE_word": make_key("ENE"),  # Same as ordinals
        "EASTNORTHEAST_key": make_key("EASTNORTHEAST"),
        "bearing_67": [6, 7],
        "bearing_675_frac": [6, 7, 5, 0],  # 67.50
        "bearing_mod26": [67 % 26],  # [15] = P
        "bearing_135_SE": [1, 3, 5],  # SE bearing to K2 coords
    }

    # YAR derivations
    yar_keys = {
        "YAR_ordinals": [24, 0, 17],  # Y=24, A=0, R=17
        "YAR_key": make_key("YAR"),  # Same
        "YAR_reversed": [17, 0, 24],  # RAY
        "RAY_key": make_key("RAY"),
        "YAR_sum_mod26": [(24 + 0 + 17) % 26],  # [15] = P
        "YAR_as_offset_triple": [24, 0, 17],
    }

    # T position derivations
    t_keys = {
        "T_ordinal": [19],  # T=19 (A=0)
        "T_ordinal_1idx": [20],  # T=20 (A=1)
        "TPOSITION": make_key("TPOSITION"),
        "T_IS_YOUR_POSITION": make_key("TISYOURPOSITION"),
    }

    # Combined derivations
    combined_keys = {
        "ENE_YAR": [4, 13, 4, 24, 0, 17],  # ENE + YAR ordinals
        "YAR_ENE": [24, 0, 17, 4, 13, 4],
        "compass_coords": [6, 7, 5, 12, 5, 6, 5, 25, 8, 18],  # bearing + coord mod26
        "T_plus_coord": [19] + [v % MOD for v in [38, 57, 6, 5, 77, 8, 44]],  # T + coords
        "YAR_24block_17rot": [17],  # Use in conjunction with block=24
    }

    all_keys = {}
    all_keys.update(bearing_keys)
    all_keys.update(yar_keys)
    all_keys.update(t_keys)
    all_keys.update(combined_keys)

    print(f"\n{len(all_keys)} key derivations to test")

    # ── Phase 1: Direct substitution ─────────────────────────────────────
    print("\n--- Phase 1: Direct substitution ---")
    for key_name, key in all_keys.items():
        key_best = 0
        key_best_var = ""
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > key_best:
                key_best = sc
                key_best_var = variant.value
            if sc > NOISE_FLOOR:
                results.append({
                    "key_name": key_name, "key": key, "variant": variant.value,
                    "transposition": "direct", "score": sc,
                })
        if sc > best_overall:
            best_overall = max(best_overall, key_best)
        print(f"  {key_name}: best={key_best}/24 ({key_best_var})")

    # ── Phase 2: T=19 offset rotation ────────────────────────────────────
    print("\n--- Phase 2: Text rotation (T IS YOUR POSITION) ---")
    for offset in [19, 20, 18, 17, 24, 0]:
        ct_rotated = rotate_text(CT, offset)
        offset_best = 0
        for key_name, key in all_keys.items():
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_rotated, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > offset_best:
                    offset_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "key_name": key_name, "variant": variant.value,
                        "rotation_offset": offset, "score": sc,
                    })
        if offset_best > best_overall:
            best_overall = offset_best
        print(f"  Offset {offset}: best={offset_best}/24")

    # ── Phase 3: YAR as block parameters ─────────────────────────────────
    print("\n--- Phase 3: YAR block parameters (block=24, offset=0, rotation=17) ---")
    # Use 24-char blocks, rotate each by 17
    ct_list = list(CT)
    for block_size in [24, 17, 41]:
        for rotation in [17, 24, 7, 0]:
            reordered = []
            for block_start in range(0, CT_LEN, block_size):
                block = ct_list[block_start:block_start + block_size]
                blen = len(block)
                rotated = block[rotation % blen:] + block[:rotation % blen]
                reordered.extend(rotated)
            ct_var = "".join(reordered[:CT_LEN])

            for key_name, key in [("KRYPTOS", make_key("KRYPTOS")),
                                  ("ABSCISSA", make_key("ABSCISSA")),
                                  ("COORD", [v % MOD for v in [38,57,6,5,77,8,44]]),
                                  ("identity", [0])]:
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(ct_var, key, variant)
                    sc = score_cribs(pt)
                    total_tested += 1
                    if sc > best_overall:
                        best_overall = sc
                    if sc > NOISE_FLOOR:
                        results.append({
                            "method": "block_rotation",
                            "block_size": block_size, "rotation": rotation,
                            "key_name": key_name, "variant": variant.value,
                            "score": sc,
                        })

    print(f"  Block rotation best so far: {best_overall}/24")

    # ── Phase 4: Sampled w7 columnar with all keys ───────────────────────
    print("\n--- Phase 4: w7 columnar + all keys (sampled) ---")
    random.seed(123)
    w7_sample = [tuple(random.sample(range(7), 7)) for _ in range(500)]
    w7_sample.append(tuple(range(7)))
    w7_sample.append(tuple(range(6, -1, -1)))

    phase4_best = 0
    for col_order in w7_sample:
        perm = columnar_perm(7, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for key_name, key in all_keys.items():
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase4_best:
                    phase4_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "key_name": key_name, "variant": variant.value,
                        "col_order": list(col_order),
                        "transposition": "w7_columnar",
                        "score": sc,
                    })

    if phase4_best > best_overall:
        best_overall = phase4_best
    print(f"  w7 columnar best: {phase4_best}/24")

    # ── Phase 5: Compass bearing as starting column in Vigenère tableau ──
    print("\n--- Phase 5: Tableau column selection ---")
    # "T IS YOUR POSITION" → use column T (=19) of the Kryptos tableau
    # The Kryptos tableau: row i starts at KRYPTOS_ALPHABET shifted by i
    kryptos_alph = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    ka_idx = {c: i for i, c in enumerate(kryptos_alph)}

    for start_col_letter in ['T', 'E', 'K', 'Y', 'A', 'R']:
        start_col = ka_idx.get(start_col_letter, ALPH_IDX.get(start_col_letter, 0))
        # Use the column as a monoalphabetic substitution
        # Each CT letter → look up in column start_col of tableau
        mono_key = [(start_col)] * CT_LEN  # constant key = monoalphabetic
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            pt = decrypt_text(CT, mono_key, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > best_overall:
                best_overall = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "method": "tableau_column",
                    "column": start_col_letter,
                    "variant": variant.value,
                    "score": sc,
                })
            print(f"  Column {start_col_letter} ({variant.value}): {sc}/24")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {total_tested}")
    print(f"Global best score: {best_overall}/24")
    print(f"Results above noise: {len(results)}")

    if results:
        print("\nTop results:")
        for r in sorted(results, key=lambda x: -x["score"])[:10]:
            print(f"  score={r['score']}/24 {r}")

    verdict = "SIGNAL" if best_overall >= 18 else ("STORE" if best_overall > NOISE_FLOOR else "NOISE")
    print(f"\nVERDICT: {verdict}")

    artifact = {
        "experiment_id": "e_s_123",
        "stage": 4,
        "hypothesis": "Compass bearing and YAR superscript encode K4 parameters",
        "parameters_source": "Physical installation (compass, YAR, T position)",
        "total_tested": total_tested,
        "best_score": best_overall,
        "above_noise": results[:50],
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_123_compass_bearing_key.py",
    }

    out_path = "artifacts/progressive_solve/stage4/compass_bearing_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
