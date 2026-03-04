#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-129: Checkpoint Charlie 'C' insertion hypothesis.

HYPOTHESIS: K4's true ciphertext is 98 characters. The letter 'C' was
omitted from the copper inscription, leaving us with 97 chars.

KEY STRUCTURAL ARGUMENT: 98 = 14 × 7 exactly. The current 97-char CT
gives an irregular 13+6/7 columnar grid, but 98 chars fills a PERFECT
14×7 grid. This is arguably the strongest argument for a missing char.

CONVERGENCE ON POSITION 13 (1-indexed):
  1. Berlin's Weltzeituhr facet index = 13
  2. Checkpoint Charlie longitude ≈ 13°E
  3. UTC+1 offset from UTC-12 = 13 steps
  ("What's the point?" → Checkpoint Charlie → NATO 'C')

CRIB REFERENCE FRAME:
  Sanborn's cribs (ENE@22, BC@64, 1-indexed) refer to the INSCRIBED
  97-char text. Empirically confirmed: CT[21]='Q'→PT='E', CT[63]='N'→PT='B'.
  For insertion at 0-indexed position P:
    - If P ≤ 21: ENE shifts to 22-34, BC shifts to 64-74 (0-indexed)
    - If 21 < P ≤ 63: only BC shifts to 64-74
    - If P > 73: neither crib shifts

Tests:
  Phase 1: 'C' at position 12 (0-idx) + ALL 5040 w7 orderings (priority)
  Phase 2: 'C' at all 98 positions × sampled w7 orderings
  Phase 3: All 26 letters at position 12 × sampled w7 orderings
  Phase 4: Position 12 + w14, w2, direct, and other transpositions
  Phase 5: Position 12 + period-7 keys (not just w7 columnar)
"""
import json
import itertools
import os
import sys
import time as time_mod
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm,
)
from kryptos.kernel.scoring.ic import ic


def make_key(text):
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


def augment_ct(ct, insert_pos, insert_char='C'):
    """Insert a character into CT at 0-indexed position.
    Returns augmented CT string of length len(ct)+1.
    """
    return ct[:insert_pos] + insert_char + ct[insert_pos:]


def shifted_crib_dict(insert_pos):
    """Return crib dict with positions shifted for insertion at insert_pos.

    Original cribs (0-indexed in 97-char text):
      ENE: positions 21-33
      BC:  positions 63-73

    For insertion at 0-indexed position P:
      All crib positions >= P shift by +1.
    """
    original_cribs = {
        21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
        28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
        63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N',
        69: 'C', 70: 'L', 71: 'O', 72: 'C', 73: 'K',
    }
    shifted = {}
    for pos, ch in original_cribs.items():
        new_pos = pos + 1 if pos >= insert_pos else pos
        shifted[new_pos] = ch
    return shifted


def score_cribs_augmented(text, crib_dict):
    """Score cribs against augmented text using shifted crib dict."""
    return sum(
        1 for pos, ch in crib_dict.items()
        if pos < len(text) and text[pos] == ch
    )


def main():
    t0 = time_mod.time()
    random.seed(129)
    print("=" * 70)
    print("E-S-129: Checkpoint Charlie 'C' Insertion Hypothesis")
    print("=" * 70)
    print(f"Original CT: {CT_LEN} chars (prime)")
    print(f"Augmented CT: 98 chars = 14 × 7 (PERFECT width-7 grid)")
    print(f"Insert char: 'C' (Checkpoint Charlie → NATO phonetic)")
    print(f"Priority position: 13 (1-indexed) = 12 (0-indexed)")
    print(f"  Berlin facet=13, Checkpoint Charlie lon≈13°E, UTC+1 offset=13")
    print()

    # Verify the 98 = 14×7 property
    assert 98 == 14 * 7, "98 must equal 14×7"
    assert 97 != 0 and all(97 % d != 0 for d in range(2, 97)), "97 must be prime"

    # ── Substitution keys ─────────────────────────────────────────────────
    sub_keys = {
        "KRYPTOS": make_key("KRYPTOS"),
        "PALIMPCEST": make_key("PALIMPCEST"),
        "ABSCISSA": make_key("ABSCISSA"),
        "BERLINCLOCK": make_key("BERLINCLOCK"),
        "WELTZEITUHR": make_key("WELTZEITUHR"),
        "CHECKPOINT": make_key("CHECKPOINT"),
        "CHARLIE": make_key("CHARLIE"),
        "COORD_MOD26": [v % MOD for v in [38, 57, 6, 5, 77, 8, 44]],
        "identity": [0],
    }

    results = []
    best_overall = 0
    best_config = None
    total_tested = 0

    # ── Phase 1: 'C' at position 12 (0-idx) + ALL 5040 w7 orderings ──────
    print("--- Phase 1: 'C' at position 12 × ALL 5040 w7 orderings ---")
    phase1_best = 0
    phase1_best_config = None

    insert_pos = 12  # 0-indexed (= 1-indexed position 13)
    aug_ct = augment_ct(CT, insert_pos, 'C')
    aug_len = len(aug_ct)
    crib_dict = shifted_crib_dict(insert_pos)

    print(f"  Augmented CT: {aug_ct[:20]}...{aug_ct[-10:]} ({aug_len} chars)")
    print(f"  Inserted 'C' at 0-idx {insert_pos}: ...{aug_ct[max(0,insert_pos-3):insert_pos+4]}...")
    print(f"  Crib positions shifted: ENE@{min(p for p in crib_dict if crib_dict[p]=='E' and p < 40)}-"
          f"{max(p for p in crib_dict if p < 40)}, "
          f"BC@{min(p for p in crib_dict if p > 40)}-{max(p for p in crib_dict)}")

    # Verify cribs in augmented CT (they should NOT match directly — that would mean no cipher)
    direct_score = score_cribs_augmented(aug_ct, crib_dict)
    print(f"  Direct crib score (no decryption): {direct_score}/24")

    # IC of augmented CT
    print(f"  Augmented CT IC: {ic(aug_ct):.4f}")

    all_w7 = list(itertools.permutations(range(7)))

    for col_order in all_w7:
        perm = columnar_perm(7, list(col_order), aug_len)
        if len(perm) != aug_len or len(set(perm)) != aug_len:
            continue
        inv = invert_perm(perm)

        for model in ["B", "A"]:
            if model == "B":
                # Model B: CT = Trans(Sub(PT)) → undo trans, then sub
                ct_untrans = apply_perm(aug_ct, inv)
            # Model A handled inside the key loop

            for key_name, key in sub_keys.items():
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                    if model == "B":
                        pt = decrypt_text(ct_untrans, key, variant)
                    else:
                        # Model A: CT = Sub(Trans(PT)) → undo sub, then trans
                        pt_sub = decrypt_text(aug_ct, key, variant)
                        pt = apply_perm(pt_sub, inv)

                    sc = score_cribs_augmented(pt, crib_dict)
                    total_tested += 1

                    if sc > phase1_best:
                        phase1_best = sc
                        phase1_best_config = {
                            "insert_pos": insert_pos,
                            "insert_char": "C",
                            "col_order": list(col_order),
                            "key": key_name,
                            "variant": variant.value,
                            "model": model,
                            "score": sc,
                            "pt_snippet": pt[:40] if sc >= STORE_THRESHOLD else "",
                        }

                    if sc >= STORE_THRESHOLD:
                        results.append({
                            "phase": 1,
                            "insert_pos": insert_pos,
                            "col_order": list(col_order),
                            "key": key_name,
                            "variant": variant.value,
                            "model": model,
                            "score": sc,
                            "pt_snippet": pt[:50],
                        })

    if phase1_best > best_overall:
        best_overall = phase1_best
        best_config = phase1_best_config
    print(f"  Phase 1 best: {phase1_best}/24")
    if phase1_best_config and phase1_best >= STORE_THRESHOLD:
        print(f"  Config: {phase1_best_config}")

    # ── Phase 2: 'C' at ALL 98 positions × sampled w7 orderings ──────────
    print("\n--- Phase 2: 'C' at all 98 positions × 500 sampled w7 orderings ---")
    phase2_best = 0
    phase2_best_pos = -1

    w7_sample = [tuple(random.sample(range(7), 7)) for _ in range(500)]
    w7_sample.append(tuple(range(7)))
    w7_sample.append(tuple(range(6, -1, -1)))

    # Test position 12 first with the sample (it was already fully tested above)
    # Now test all OTHER positions
    for insert_p in range(98):
        aug = augment_ct(CT, insert_p, 'C')
        if len(aug) != 98:
            continue
        cd = shifted_crib_dict(insert_p)

        pos_best = 0
        for col_order in w7_sample:
            perm = columnar_perm(7, list(col_order), 98)
            if len(perm) != 98 or len(set(perm)) != 98:
                continue
            inv = invert_perm(perm)
            ct_untrans = apply_perm(aug, inv)

            for key_name in ["KRYPTOS", "ABSCISSA", "BERLINCLOCK", "COORD_MOD26", "identity"]:
                key = sub_keys[key_name]
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(ct_untrans, key, variant)
                    sc = score_cribs_augmented(pt, cd)
                    total_tested += 1
                    if sc > pos_best:
                        pos_best = sc
                    if sc >= STORE_THRESHOLD:
                        results.append({
                            "phase": 2,
                            "insert_pos": insert_p,
                            "col_order": list(col_order),
                            "key": key_name,
                            "variant": variant.value,
                            "model": "B",
                            "score": sc,
                        })

        if pos_best > phase2_best:
            phase2_best = pos_best
            phase2_best_pos = insert_p

        if pos_best >= STORE_THRESHOLD:
            print(f"  *** Position {insert_p} (0-idx): {pos_best}/24 ***")

    if phase2_best > best_overall:
        best_overall = phase2_best
    print(f"  Phase 2 best: {phase2_best}/24 at position {phase2_best_pos} (0-idx)")

    # ── Phase 3: All 26 letters at position 12 × sampled w7 ───────────────
    print("\n--- Phase 3: All 26 letters at position 12 × 500 w7 orderings ---")
    phase3_best = 0
    phase3_best_char = ""

    cd_12 = shifted_crib_dict(12)

    for ch in ALPH:
        aug = augment_ct(CT, 12, ch)
        ch_best = 0

        for col_order in w7_sample:
            perm = columnar_perm(7, list(col_order), 98)
            if len(perm) != 98 or len(set(perm)) != 98:
                continue
            inv = invert_perm(perm)
            ct_untrans = apply_perm(aug, inv)

            for key_name in ["KRYPTOS", "ABSCISSA", "BERLINCLOCK", "COORD_MOD26", "identity"]:
                key = sub_keys[key_name]
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(ct_untrans, key, variant)
                    sc = score_cribs_augmented(pt, cd_12)
                    total_tested += 1
                    if sc > ch_best:
                        ch_best = sc
                    if sc >= STORE_THRESHOLD:
                        results.append({
                            "phase": 3,
                            "insert_char": ch,
                            "insert_pos": 12,
                            "col_order": list(col_order),
                            "key": key_name,
                            "variant": variant.value,
                            "score": sc,
                        })

        if ch_best > phase3_best:
            phase3_best = ch_best
            phase3_best_char = ch

    if phase3_best > best_overall:
        best_overall = phase3_best
    print(f"  Phase 3 best: {phase3_best}/24 (char='{phase3_best_char}')")

    # ── Phase 4: Position 12 + other transposition widths ─────────────────
    print("\n--- Phase 4: Position 12 + widths 2,7,14,49 and direct ---")
    phase4_best = 0

    aug_12 = augment_ct(CT, 12, 'C')

    # Width 14 (98 = 7 × 14 — also exact!)
    w14_sample = [tuple(random.sample(range(14), 14)) for _ in range(500)]
    w14_sample.append(tuple(range(14)))
    w14_sample.append(tuple(range(13, -1, -1)))

    for col_order in w14_sample:
        perm = columnar_perm(14, list(col_order), 98)
        if len(perm) != 98 or len(set(perm)) != 98:
            continue
        inv = invert_perm(perm)
        ct_untrans = apply_perm(aug_12, inv)

        for key_name in ["KRYPTOS", "ABSCISSA", "BERLINCLOCK", "COORD_MOD26", "identity"]:
            key = sub_keys[key_name]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs_augmented(pt, cd_12)
                total_tested += 1
                if sc > phase4_best:
                    phase4_best = sc
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "phase": 4,
                        "width": 14,
                        "col_order": list(col_order),
                        "key": key_name,
                        "variant": variant.value,
                        "score": sc,
                    })

    # Width 2 (98 = 2 × 49)
    for col_order in [(0,1), (1,0)]:
        perm = columnar_perm(2, list(col_order), 98)
        if len(perm) != 98 or len(set(perm)) != 98:
            continue
        inv = invert_perm(perm)
        ct_untrans = apply_perm(aug_12, inv)
        for key_name, key in sub_keys.items():
            for variant in CipherVariant:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs_augmented(pt, cd_12)
                total_tested += 1
                if sc > phase4_best:
                    phase4_best = sc

    # Width 49 (98 = 49 × 2)
    w49_sample = [tuple(random.sample(range(49), 49)) for _ in range(200)]
    for col_order in w49_sample:
        perm = columnar_perm(49, list(col_order), 98)
        if len(perm) != 98 or len(set(perm)) != 98:
            continue
        inv = invert_perm(perm)
        ct_untrans = apply_perm(aug_12, inv)
        for key_name in ["KRYPTOS", "ABSCISSA", "identity"]:
            key = sub_keys[key_name]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs_augmented(pt, cd_12)
                total_tested += 1
                if sc > phase4_best:
                    phase4_best = sc

    # Direct (no transposition) — just 'C' inserted + substitution
    for key_name, key in sub_keys.items():
        for variant in CipherVariant:
            pt = decrypt_text(aug_12, key, variant)
            sc = score_cribs_augmented(pt, cd_12)
            total_tested += 1
            if sc > phase4_best:
                phase4_best = sc

    if phase4_best > best_overall:
        best_overall = phase4_best
    print(f"  Phase 4 best: {phase4_best}/24")

    # ── Phase 5: Position 12, 'C', exhaustive w7 + CHECKPOINT/CHARLIE keys ─
    print("\n--- Phase 5: Position 12 + thematic keys × ALL 5040 w7 ---")
    phase5_best = 0

    thematic_keys = {
        "CHECKPOINT": make_key("CHECKPOINT"),
        "CHARLIE": make_key("CHARLIE"),
        "CHECKPOINTCHARLIE": make_key("CHECKPOINTCHARLIE"),
        "WHATSTHEPOINT": make_key("WHATSTHEPOINT"),
        "THEPOINT": make_key("THEPOINT"),
        "POINT": make_key("POINT"),
    }

    for col_order in all_w7:
        perm = columnar_perm(7, list(col_order), 98)
        if len(perm) != 98 or len(set(perm)) != 98:
            continue
        inv = invert_perm(perm)
        ct_untrans = apply_perm(aug_12, inv)

        for key_name, key in thematic_keys.items():
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs_augmented(pt, cd_12)
                total_tested += 1
                if sc > phase5_best:
                    phase5_best = sc
                if sc >= STORE_THRESHOLD:
                    results.append({
                        "phase": 5,
                        "key": key_name,
                        "col_order": list(col_order),
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase5_best > best_overall:
        best_overall = phase5_best
    print(f"  Phase 5 best: {phase5_best}/24")

    # ── Noise baseline: random insertion position + random w7 ─────────────
    print("\n--- Noise baseline: random pos × random w7 × random key ---")
    baseline_scores = []
    for _ in range(5000):
        rp = random.randint(0, 97)
        aug = augment_ct(CT, rp, random.choice(ALPH))
        cd = shifted_crib_dict(rp)
        col_order = tuple(random.sample(range(7), 7))
        perm = columnar_perm(7, list(col_order), 98)
        if len(perm) != 98 or len(set(perm)) != 98:
            continue
        inv = invert_perm(perm)
        ct_untrans = apply_perm(aug, inv)
        variant = random.choice(list(CipherVariant))
        key = sub_keys[random.choice(["KRYPTOS", "ABSCISSA", "identity"])]
        pt = decrypt_text(ct_untrans, key, variant)
        sc = score_cribs_augmented(pt, cd)
        baseline_scores.append(sc)
        total_tested += 1

    if baseline_scores:
        baseline_mean = sum(baseline_scores) / len(baseline_scores)
        baseline_max = max(baseline_scores)
        print(f"  Baseline: mean={baseline_mean:.2f}, max={baseline_max}/24 (from {len(baseline_scores)} random)")
    else:
        baseline_mean = 0
        baseline_max = 0

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time_mod.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {total_tested}")
    print(f"Global best score: {best_overall}/24")
    print(f"Random baseline max: {baseline_max}/24 (mean={baseline_mean:.2f})")

    if results:
        print(f"\nTop results (score ≥ {STORE_THRESHOLD}):")
        for r in sorted(results, key=lambda x: -x["score"])[:20]:
            print(f"  score={r['score']}/24 phase={r['phase']} pos={r.get('insert_pos',12)} "
                  f"char={r.get('insert_char','C')} key={r.get('key','')} "
                  f"var={r.get('variant','')}")
    else:
        print(f"\nNo results above store threshold ({STORE_THRESHOLD})")

    # Verdict
    if best_overall >= SIGNAL_THRESHOLD:
        verdict = "SIGNAL"
        print(f"\n*** SIGNAL at {best_overall}/24 — investigate! ***")
    elif best_overall > NOISE_FLOOR:
        # Check if position 12 specifically is better than other positions
        if phase1_best > phase2_best:
            verdict = "STORE_POS13_FAVORED"
            print(f"\nPosition 13 ({phase1_best}/24) outperforms other positions ({phase2_best}/24)")
        else:
            verdict = "STORE"
            print(f"\nMarginal results — position 13 does NOT outperform other positions")
    else:
        verdict = "NOISE"
        print(f"\n'C' insertion hypothesis produces NOISE across all tests")

    # Key structural observation
    print(f"\n  98 = 14 × 7 (perfect grid) vs 97 (prime, irregular grid)")
    print(f"  This property is shared by ANY single-char insertion, not just 'C' at pos 13")
    print(f"  Phase 2 tested all 98 positions: best at pos {phase2_best_pos} = {phase2_best}/24")

    artifact = {
        "experiment_id": "e_s_129",
        "hypothesis": "K4 is 98 chars with 'C' omitted at position 13 (Checkpoint Charlie)",
        "motivation": {
            "whats_the_point": "Checkpoint Charlie → NATO 'C'",
            "convergence_on_13": [
                "Berlin Weltzeituhr facet index = 13",
                "Checkpoint Charlie longitude ≈ 13°E",
                "UTC+1 offset from UTC-12 = 13 steps",
            ],
            "structural": "98 = 14 × 7 (perfect width-7 grid)",
        },
        "total_tested": total_tested,
        "best_score": best_overall,
        "best_config": best_config,
        "phase_results": {
            "phase1_pos12_all_w7": phase1_best,
            "phase2_all_positions": phase2_best,
            "phase2_best_position": phase2_best_pos,
            "phase3_all_letters_pos12": phase3_best,
            "phase3_best_letter": phase3_best_char,
            "phase4_other_widths": phase4_best,
            "phase5_thematic_keys": phase5_best,
        },
        "baseline": {
            "mean": round(baseline_mean, 2),
            "max": baseline_max,
        },
        "above_store": [r for r in results if r["score"] >= STORE_THRESHOLD][:50],
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_129_charlie_insertion.py",
    }

    out_path = "artifacts/progressive_solve/stage4/charlie_insertion_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
