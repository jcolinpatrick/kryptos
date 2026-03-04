#!/usr/bin/env python3
"""
Cipher: crib-based constraint
Family: crib_analysis
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-125: Positional misalignment test for K4.

Sanborn said K4 CT is "fairly accurate" — NOT perfectly accurate.
If ONE letter was changed during physical cutting, ALL cipher attacks break.

Tests:
  (a) Single-letter substitution: for each of 97 positions, try all 25 alternatives
  (b) Single-letter deletion: for each of 97 positions, delete that char
  (c) Single-letter insertion: at each of 98 positions, insert each of 26 letters
  (d) ? boundary: test K4 as 96 chars (? removed) and 98 chars (? prepended/appended)

For each variant CT, tests best models:
  - Direct Vigenère/Beaufort with coordinate key [12,5,6,5,25,8,18]
  - Width-7 columnar (sampled orderings) + periodic key

Stage 4 of Progressive Solve Plan. HIGHEST LEVERAGE TEST.
"""
import json
import itertools
import os
import sys
import time
import random

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
from kryptos.kernel.scoring.ic import ic


def make_keyword_key(keyword):
    return [ALPH_IDX[c] for c in keyword.upper()]


# Key models to test each CT variant against
COORD_KEY = [v % MOD for v in [38, 57, 6, 5, 77, 8, 44]]  # [12,5,6,5,25,8,18]
KRYPTOS_KEY = make_keyword_key("KRYPTOS")
ABSCISSA_KEY = make_keyword_key("ABSCISSA")
PALIMPCEST_KEY = make_keyword_key("PALIMPCEST")

# Precompute sampled w7 orderings
random.seed(125)
W7_ORDERINGS = [tuple(random.sample(range(7), 7)) for _ in range(500)]
W7_ORDERINGS.append(tuple(range(7)))
W7_ORDERINGS.append(tuple(range(6, -1, -1)))
# Add KRYPTOS-derived ordering
kryptos_order = [0] * 7
kw = "KRYPTOS"
indexed = sorted(range(7), key=lambda i: kw[i])
for rank, idx in enumerate(indexed):
    kryptos_order[idx] = rank
W7_ORDERINGS.append(tuple(kryptos_order))


def test_ct_variant(ct_var, label, key_models, w7_orderings, results_list):
    """Test a CT variant against multiple models. Returns best score."""
    best = 0
    ct_len = len(ct_var)

    # Direct substitution (no transposition)
    for key_name, key in key_models.items():
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(ct_var, key, variant)
            sc = score_cribs(pt)
            if sc > best:
                best = sc
            if sc > NOISE_FLOOR:
                results_list.append({
                    "ct_label": label,
                    "transposition": "direct",
                    "key": key_name,
                    "variant": variant.value,
                    "score": sc,
                })

    # Width-7 columnar + key models (sampled orderings)
    for col_order in w7_orderings:
        try:
            perm = columnar_perm(7, list(col_order), ct_len)
            inv = invert_perm(perm)
            ct_untrans = apply_perm(ct_var, inv)
        except Exception:
            continue

        for key_name, key in key_models.items():
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs(pt)
                if sc > best:
                    best = sc
                if sc > STORE_THRESHOLD:
                    results_list.append({
                        "ct_label": label,
                        "transposition": f"w7_{list(col_order)}",
                        "key": key_name,
                        "variant": variant.value,
                        "score": sc,
                    })

    return best


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-125: Positional Misalignment Test")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")

    key_models = {
        "COORD_MOD26": COORD_KEY,
        "KRYPTOS": KRYPTOS_KEY,
        "ABSCISSA": ABSCISSA_KEY,
        "PALIMPCEST": PALIMPCEST_KEY,
    }

    results = []
    total_tested = 0

    # ── Baseline: original CT ────────────────────────────────────────────
    print("\n--- Baseline: original CT ---")
    baseline_best = test_ct_variant(CT, "original", key_models, W7_ORDERINGS, results)
    n_models = len(key_models) * 3 + len(W7_ORDERINGS) * len(key_models) * 2
    total_tested += n_models
    print(f"  Baseline best: {baseline_best}/24 ({n_models} configs)")

    # ── Phase 1: Single-letter substitution ──────────────────────────────
    print("\n--- Phase 1: Single-letter substitution (97 × 25 = 2425 variants) ---")
    sub_best = 0
    sub_best_pos = -1
    sub_best_letter = ""
    sub_improvements = []  # Positions that improve over baseline

    for pos in range(CT_LEN):
        original_letter = CT[pos]
        pos_best = 0
        pos_best_letter = ""

        for letter in ALPH:
            if letter == original_letter:
                continue

            ct_var = CT[:pos] + letter + CT[pos+1:]
            assert len(ct_var) == CT_LEN

            # Quick test: direct with all keys
            quick_best = 0
            for key_name, key in key_models.items():
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(ct_var, key, variant)
                    sc = score_cribs(pt)
                    total_tested += 1
                    if sc > quick_best:
                        quick_best = sc

            if quick_best > pos_best:
                pos_best = quick_best
                pos_best_letter = letter

            # If promising (>= baseline), do full test with w7
            if quick_best > baseline_best:
                detail_results = []
                full_best = test_ct_variant(ct_var, f"sub_{pos}_{letter}",
                                            key_models, W7_ORDERINGS[:100], detail_results)
                total_tested += 100 * len(key_models) * 2
                if full_best > sub_best:
                    sub_best = full_best
                    sub_best_pos = pos
                    sub_best_letter = letter
                results.extend(detail_results)

        if pos_best > baseline_best:
            sub_improvements.append({
                "position": pos,
                "original": original_letter,
                "best_replacement": pos_best_letter,
                "score": pos_best,
                "improvement": pos_best - baseline_best,
            })

        if pos % 10 == 0:
            print(f"  Position {pos}/97: pos_best={pos_best}/24 (overall sub_best={sub_best}/24)")

    print(f"  Single-sub best: {sub_best}/24 (pos={sub_best_pos}, letter={sub_best_letter})")
    print(f"  Positions improving over baseline ({baseline_best}): {len(sub_improvements)}")
    if sub_improvements:
        for imp in sorted(sub_improvements, key=lambda x: -x["score"])[:10]:
            print(f"    pos={imp['position']} {imp['original']}→{imp['best_replacement']}: {imp['score']}/24 (+{imp['improvement']})")

    # ── Phase 2: Single-letter deletion ──────────────────────────────────
    print("\n--- Phase 2: Single-letter deletion (97 variants, length 96) ---")
    del_best = 0
    del_best_pos = -1

    for pos in range(CT_LEN):
        ct_var = CT[:pos] + CT[pos+1:]
        assert len(ct_var) == CT_LEN - 1

        # Direct test only (different length invalidates w7 columnar positions)
        for key_name, key in key_models.items():
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_var, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > del_best:
                    del_best = sc
                    del_best_pos = pos
                if sc > NOISE_FLOOR:
                    results.append({
                        "ct_label": f"del_{pos}",
                        "transposition": "direct",
                        "key": key_name,
                        "variant": variant.value,
                        "score": sc,
                    })

    print(f"  Deletion best: {del_best}/24 (pos={del_best_pos})")

    # ── Phase 3: ? boundary tests ────────────────────────────────────────
    print("\n--- Phase 3: ? boundary variants ---")
    boundary_variants = {
        "Q_prepended": "Q" + CT,       # 98 chars
        "Q_appended": CT + "Q",         # 98 chars
        "CT_no_last": CT[:-1],          # 96 chars (drop last)
        "CT_no_first": CT[1:],          # 96 chars (drop first)
    }

    boundary_best = 0
    for bv_name, ct_var in boundary_variants.items():
        bv_results = []
        bv_best = test_ct_variant(ct_var, bv_name, key_models, W7_ORDERINGS[:200], bv_results)
        total_tested += 200 * len(key_models) * 2 + len(key_models) * 3
        if bv_best > boundary_best:
            boundary_best = bv_best
        results.extend(bv_results)
        print(f"  {bv_name} (len={len(ct_var)}): best={bv_best}/24")

    # ── Phase 4: Single insertion (most promising positions only) ─────────
    print("\n--- Phase 4: Single-letter insertion (targeted) ---")
    # Test insertion at positions around crib boundaries
    insert_positions = list(range(18, 36)) + list(range(60, 76)) + [0, CT_LEN]
    ins_best = 0
    ins_best_detail = None

    for pos in insert_positions:
        for letter in ALPH:
            ct_var = CT[:pos] + letter + CT[pos:]
            assert len(ct_var) == CT_LEN + 1

            for key_name, key in key_models.items():
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(ct_var, key, variant)
                    sc = score_cribs(pt)
                    total_tested += 1
                    if sc > ins_best:
                        ins_best = sc
                        ins_best_detail = f"pos={pos} letter={letter} key={key_name} var={variant.value}"
                    if sc > NOISE_FLOOR:
                        results.append({
                            "ct_label": f"ins_{pos}_{letter}",
                            "transposition": "direct",
                            "key": key_name,
                            "variant": variant.value,
                            "score": sc,
                        })

    print(f"  Insertion best: {ins_best}/24 ({ins_best_detail})")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    global_best = max(baseline_best, sub_best, del_best, boundary_best, ins_best)

    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {total_tested}")
    print(f"Baseline (original CT): {baseline_best}/24")
    print(f"Best single-sub: {sub_best}/24")
    print(f"Best deletion: {del_best}/24")
    print(f"Best boundary: {boundary_best}/24")
    print(f"Best insertion: {ins_best}/24")
    print(f"Global best: {global_best}/24")
    print(f"Above-noise results: {len(results)}")

    if sub_improvements:
        print(f"\nPositions where substitution improves over baseline:")
        for imp in sorted(sub_improvements, key=lambda x: -x["score"])[:5]:
            print(f"  pos {imp['position']}: {imp['original']}→{imp['best_replacement']} = {imp['score']}/24")

    verdict = "SIGNAL" if global_best >= 18 else ("STORE" if global_best > NOISE_FLOOR else "NOISE")
    print(f"\nVERDICT: {verdict}")

    if global_best > baseline_best + 3:
        print("*** SIGNIFICANT IMPROVEMENT over baseline — possible transcription error! ***")
    else:
        print("No evidence of transcription error in K4 CT.")

    # Write artifacts
    artifact = {
        "experiment_id": "e_s_125",
        "stage": 4,
        "hypothesis": "K4 CT has a transcription error",
        "parameters_source": "K4 CT + exhaustive single-char mutations",
        "baseline_best": baseline_best,
        "sub_best": sub_best,
        "sub_best_pos": sub_best_pos,
        "sub_improvements": sub_improvements,
        "del_best": del_best,
        "boundary_best": boundary_best,
        "ins_best": ins_best,
        "global_best": global_best,
        "total_tested": total_tested,
        "above_noise": [r for r in results if r.get("score", 0) > NOISE_FLOOR][:100],
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_125_positional_misalignment.py",
    }

    out_path = "artifacts/progressive_solve/stage4/misalignment_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
