#!/usr/bin/env python3
"""
Cipher: Berlin clock
Family: thematic/berlin_clock
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-127: Urania Weltzeituhr (World Time Clock) tests for K4.

The BERLINCLOCK in K4 plaintext refers to the Urania Weltzeituhr at
Alexanderplatz, Berlin — NOT the Mengenlehreuhr. Confirmed by Sanborn.

Sanborn: "You'd better delve into that particular clock"
         "There's a lot of fodder there"

Structure:
  - 24-sided column (regular icositetragon), one face per UTC time zone
  - 148 cities engraved across the 24 faces
  - Compass rose / wind rose at the base (mirrors Kryptos)
  - Rotating hour ring (numbers 1-24 revolve around outside)
  - Solar system model on top rotates once per minute

Key properties:
  - Berlin = UTC+1 (CET), Langley/DC = UTC-5 (EST) → offset = 6 hours
  - 24 faces × ~6 cities per face = 148 cities
  - 97 = 4×24 + 1 (K4 wraps around the clock 4 times + 1 extra char)

Tests:
  (a) 24-face block transpositions with time-zone-based permutations
  (b) Berlin→DC offset (6) as key parameter
  (c) Clock-face reading orders (CW, CCW, starting at various faces)
  (d) Wrapping K4 CT around the 24 faces, reading off in various orders
  (e) Time zone numbers as numeric key
  (f) The 24-face / 24-crib correspondence

Stage 4 of Progressive Solve Plan (corrected).
"""
import json
import itertools
import os
import sys
import time as time_mod
import random
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR, CRIB_DICT,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic


def make_key(text):
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


# ── Weltzeituhr structural constants ────────────────────────────────────

N_FACES = 24
BERLIN_TZ = 1     # UTC+1 (CET)
DC_TZ = -5        # UTC-5 (EST) → face 19 (if face 1 = UTC+1)
BERLIN_DC_OFFSET = 6  # hours between Berlin and DC

# Face numbering: face 0 = UTC-12 (IDL), face 12 = UTC+0 (GMT), face 13 = UTC+1 (Berlin)
# OR: face 1 = the "1" on the rotating ring
# The hour ring shows 1-24, where the number under a face = current hour there

# Standard UTC offset for each face (0-indexed, face 0 = UTC-12)
UTC_OFFSETS = list(range(-12, 12))  # [-12, -11, ..., 11]

# Berlin face index (UTC+1)
BERLIN_FACE = 13  # UTC+1 is 13th from UTC-12

# DC face index (UTC-5)
DC_FACE = 7  # UTC-5 is 7th from UTC-12


def wrap_around_clock(text, n_faces=24, start_face=0, direction=1):
    """Write text around clock faces, return list of strings per face.

    text is distributed across faces sequentially.
    direction: 1=CW, -1=CCW
    """
    faces = [[] for _ in range(n_faces)]
    for i, ch in enumerate(text):
        face_idx = (start_face + direction * i) % n_faces
        faces[face_idx].append(ch)
    return faces


def clock_face_perm(n_faces, text_len, start_face=0, direction=1, read_order=None):
    """Generate permutation from clock-face reading order.

    Write text sequentially (row-major into faces), then read faces
    in the specified order.

    read_order: list of face indices to read, or None for sequential.
    """
    if read_order is None:
        read_order = [(start_face + direction * i) % n_faces for i in range(n_faces)]

    # Distribute characters across faces
    faces = [[] for _ in range(n_faces)]
    for i in range(text_len):
        face_idx = i % n_faces
        faces[face_idx].append(i)

    # Read in specified face order
    perm = []
    for face_idx in read_order:
        perm.extend(faces[face_idx])

    return perm[:text_len]


def columnar_on_clock(text, n_faces=24, col_order=None):
    """Treat clock faces as columns of width n_faces.

    Write text row-by-row across faces, read column-by-column in col_order.
    This is essentially columnar transposition with width 24.
    """
    if col_order is None:
        col_order = list(range(n_faces))
    perm = columnar_perm(n_faces, col_order, len(text))
    return perm


def time_zone_based_orders():
    """Generate reading orders based on time zone relationships."""
    orders = {}

    # 1. Start at Berlin (UTC+1), go CW (increasing UTC)
    orders["berlin_cw"] = [(BERLIN_FACE + i) % 24 for i in range(24)]

    # 2. Start at Berlin, go CCW
    orders["berlin_ccw"] = [(BERLIN_FACE - i) % 24 for i in range(24)]

    # 3. Start at DC (UTC-5), go CW
    orders["dc_cw"] = [(DC_FACE + i) % 24 for i in range(24)]

    # 4. Start at DC, go CCW
    orders["dc_ccw"] = [(DC_FACE - i) % 24 for i in range(24)]

    # 5. Start at GMT (UTC+0), face 12
    orders["gmt_cw"] = [(12 + i) % 24 for i in range(24)]
    orders["gmt_ccw"] = [(12 - i) % 24 for i in range(24)]

    # 6. Start at IDL (UTC-12), face 0
    orders["idl_cw"] = list(range(24))
    orders["idl_ccw"] = list(range(23, -1, -1))

    # 7. Berlin → DC path (shortest: 6 steps CW or 18 steps CCW)
    # Alternate: read faces along Berlin→DC path, then remaining
    berlin_to_dc_cw = [(BERLIN_FACE + i) % 24 for i in range(BERLIN_DC_OFFSET + 1)]
    remaining = [f for f in range(24) if f not in berlin_to_dc_cw]
    orders["berlin_to_dc_cw"] = berlin_to_dc_cw + remaining

    # Berlin → DC CCW (the long way around)
    berlin_to_dc_ccw = [(BERLIN_FACE - i) % 24 for i in range(24 - BERLIN_DC_OFFSET)]
    remaining2 = [f for f in range(24) if f not in berlin_to_dc_ccw]
    orders["berlin_to_dc_ccw"] = berlin_to_dc_ccw + remaining2

    # 8. Alternating: Berlin, DC, Berlin+1, DC+1, ...
    alt = []
    for i in range(12):
        alt.append((BERLIN_FACE + i) % 24)
        alt.append((DC_FACE + i) % 24)
    # Deduplicate while preserving order
    seen = set()
    alt_dedup = []
    for f in alt:
        if f not in seen:
            seen.add(f)
            alt_dedup.append(f)
    for f in range(24):
        if f not in seen:
            alt_dedup.append(f)
            seen.add(f)
    orders["berlin_dc_alternating"] = alt_dedup

    # 9. Opposite faces: 0-12, 1-13, 2-14, ... (antipodal pairs)
    antipodal = []
    for i in range(12):
        antipodal.append(i)
        antipodal.append(i + 12)
    orders["antipodal_pairs"] = antipodal

    # 10. Skip-6 (Berlin-DC offset as skip): 0, 6, 12, 18, 0+1, 7, 13, 19, ...
    skip6 = []
    for start in range(6):
        for step in range(4):
            skip6.append((start + step * 6) % 24)
    orders["skip_6"] = skip6

    return orders


def main():
    t0 = time_mod.time()
    random.seed(127)
    print("=" * 70)
    print("E-S-127: Urania Weltzeituhr (World Time Clock) Tests")
    print("=" * 70)
    print(f"24 faces, Berlin=face {BERLIN_FACE} (UTC+1), DC=face {DC_FACE} (UTC-5)")
    print(f"Berlin↔DC offset: {BERLIN_DC_OFFSET} hours")
    print(f"K4 CT: {CT_LEN} chars = 4×24 + 1")

    # Substitution keys from prior stages
    sub_keys = {
        "KRYPTOS": make_key("KRYPTOS"),
        "PALIMPCEST": make_key("PALIMPCEST"),
        "ABSCISSA": make_key("ABSCISSA"),
        "COORD_MOD26": [v % MOD for v in [38, 57, 6, 5, 77, 8, 44]],
        "BERLINCLOCK": make_key("BERLINCLOCK"),
        "BERLIN": make_key("BERLIN"),
        "CLOCK": make_key("CLOCK"),
        "WELTZEITUHR": make_key("WELTZEITUHR"),
        "URANIA": make_key("URANIA"),
        "ALEXANDERPLATZ": make_key("ALEXANDERPLATZ"),
        "identity": [0],
    }

    # Additional keys derived from the clock structure
    clock_keys = {
        # Berlin-DC offset as key element
        "offset_6": [6],
        "offset_6_repeat": [6] * 24,
        # Time zone numbers for Berlin face cities
        "tz_berlin_1": [1],
        # UTC offsets as key: -12 to +11 mapped to 0-23
        "utc_offsets_mod26": [(o + 12) % MOD for o in range(-12, 12)],
        # Clock hours 1-24 as key
        "hours_1_24": list(range(1, 25)),
        "hours_1_24_mod26": [h % MOD for h in range(1, 25)],
        # 24 as period (one rotation)
        "period_24": [i % MOD for i in range(24)],
    }
    sub_keys.update(clock_keys)

    results = []
    best_overall = 0
    total_tested = 0

    # ── Phase 1: Width-24 columnar with time-zone-based orderings ────────
    print("\n--- Phase 1: Width-24 columnar with TZ-based orderings ---")
    tz_orders = time_zone_based_orders()
    print(f"  {len(tz_orders)} time-zone-based reading orders")

    phase1_best = 0
    for order_name, order in tz_orders.items():
        if len(set(order)) != 24 or len(order) != 24:
            print(f"  SKIP {order_name}: invalid order (len={len(order)}, unique={len(set(order))})")
            continue

        perm = columnar_on_clock(CT, 24, order)
        if len(perm) != CT_LEN or len(set(perm)) != CT_LEN:
            continue

        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        # Test with all substitution keys
        for key_name, key in sub_keys.items():
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase1_best:
                    phase1_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "phase": "w24_tz",
                        "order": order_name,
                        "key": key_name,
                        "variant": variant.value,
                        "score": sc,
                    })

        # Also Model A (sub first, then trans)
        for key_name, key in sub_keys.items():
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt_sub = decrypt_text(CT, key, variant)
                pt = apply_perm(pt_sub, inv)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase1_best:
                    phase1_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "phase": "w24_tz_modelA",
                        "order": order_name,
                        "key": key_name,
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase1_best > best_overall:
        best_overall = phase1_best
    print(f"  Best: {phase1_best}/24")

    # ── Phase 2: Clock-face reading permutations ─────────────────────────
    print("\n--- Phase 2: Clock-face reading permutations ---")
    phase2_best = 0

    for order_name, order in tz_orders.items():
        if len(set(order)) != 24:
            continue

        # Clock face perm: distribute chars across 24 faces, read in order
        perm = clock_face_perm(24, CT_LEN, read_order=order)
        if len(perm) != CT_LEN or len(set(perm)) != CT_LEN:
            continue

        inv = invert_perm(perm)
        ct_reordered = apply_perm(CT, inv)

        for key_name, key in sub_keys.items():
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_reordered, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase2_best:
                    phase2_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "phase": "clockface_read",
                        "order": order_name,
                        "key": key_name,
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase2_best > best_overall:
        best_overall = phase2_best
    print(f"  Best: {phase2_best}/24")

    # ── Phase 3: Offset-6 as key component ───────────────────────────────
    print("\n--- Phase 3: Berlin-DC offset (6) as structural parameter ---")
    phase3_best = 0

    # Width-6 columnar (Berlin↔DC offset)
    for col_order in itertools.permutations(range(6)):
        perm = columnar_perm(6, list(col_order), CT_LEN)
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for key_name in ["KRYPTOS", "ABSCISSA", "BERLINCLOCK", "COORD_MOD26", "WELTZEITUHR"]:
            key = sub_keys[key_name]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase3_best:
                    phase3_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "phase": "w6_offset",
                        "col_order": list(col_order),
                        "key": key_name,
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase3_best > best_overall:
        best_overall = phase3_best
    print(f"  Width-6 columnar best: {phase3_best}/24 ({math.factorial(6)} orderings)")

    # ── Phase 4: Combined w24 + w7 (clock structure + lag-7) ─────────────
    print("\n--- Phase 4: Combined clock structure + lag-7 ---")
    phase4_best = 0

    # First undo w24 TZ ordering, then undo w7 columnar
    w7_sample = [tuple(random.sample(range(7), 7)) for _ in range(200)]
    w7_sample.append(tuple(range(7)))

    top_tz_orders = ["berlin_cw", "dc_cw", "gmt_cw", "skip_6", "berlin_to_dc_cw", "antipodal_pairs"]

    for tz_name in top_tz_orders:
        order = tz_orders[tz_name]
        if len(set(order)) != 24:
            continue

        perm24 = columnar_on_clock(CT, 24, order)
        if len(perm24) != CT_LEN or len(set(perm24)) != CT_LEN:
            continue
        inv24 = invert_perm(perm24)
        ct_after_24 = apply_perm(CT, inv24)

        for col_order in w7_sample:
            perm7 = columnar_perm(7, list(col_order), CT_LEN)
            inv7 = invert_perm(perm7)
            ct_after_both = apply_perm(ct_after_24, inv7)

            for key_name in ["KRYPTOS", "ABSCISSA", "BERLINCLOCK", "COORD_MOD26"]:
                key = sub_keys[key_name]
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(ct_after_both, key, variant)
                    sc = score_cribs(pt)
                    total_tested += 1
                    if sc > phase4_best:
                        phase4_best = sc
                    if sc > NOISE_FLOOR:
                        results.append({
                            "phase": "w24_w7_combined",
                            "tz_order": tz_name,
                            "w7_order": list(col_order),
                            "key": key_name,
                            "variant": variant.value,
                            "score": sc,
                        })

    if phase4_best > best_overall:
        best_overall = phase4_best
    print(f"  Combined w24+w7 best: {phase4_best}/24")

    # ── Phase 5: Cyclic rotation by clock-related offsets ────────────────
    print("\n--- Phase 5: Cyclic rotation by clock-related offsets ---")
    phase5_best = 0

    for offset in [1, 6, 7, 12, 13, 19, 24, 97 % 24]:
        ct_rotated = CT[offset:] + CT[:offset]
        for key_name, key in sub_keys.items():
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_rotated, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase5_best:
                    phase5_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "phase": "cyclic_rotation",
                        "offset": offset,
                        "key": key_name,
                        "variant": variant.value,
                        "score": sc,
                    })

    if phase5_best > best_overall:
        best_overall = phase5_best
    print(f"  Cyclic rotation best: {phase5_best}/24")

    # ── Phase 6: Random w24 orderings (to calibrate) ─────────────────────
    print("\n--- Phase 6: Random w24 orderings (baseline calibration) ---")
    phase6_best = 0
    random_orderings = [list(random.sample(range(24), 24)) for _ in range(200)]

    for col_order in random_orderings:
        perm = columnar_on_clock(CT, 24, col_order)
        if len(perm) != CT_LEN or len(set(perm)) != CT_LEN:
            continue
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for key_name in ["KRYPTOS", "BERLINCLOCK", "COORD_MOD26", "identity"]:
            key = sub_keys[key_name]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, key, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase6_best:
                    phase6_best = sc

    print(f"  Random w24 baseline: {phase6_best}/24 (expected high due to underdetermination at w24)")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time_mod.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {total_tested}")
    print(f"Global best score: {best_overall}/24")
    print(f"Random w24 baseline: {phase6_best}/24")
    print(f"Results above noise: {len(results)}")

    # Check if TZ-based orders beat random
    if best_overall > phase6_best:
        print(f"*** TZ-based orders BEAT random baseline by {best_overall - phase6_best} ***")
    else:
        print(f"TZ-based orders do NOT beat random baseline — no signal.")

    if results:
        print("\nTop results:")
        for r in sorted(results, key=lambda x: -x["score"])[:15]:
            print(f"  score={r['score']}/24 phase={r['phase']} key={r.get('key','')} var={r.get('variant','')}")

    # NOTE: w24 is HIGHLY underdetermined (period 24 → expected ~19.2/24 random)
    # So scores up to ~19 are noise at width 24
    print(f"\n⚠ WARNING: Width-24 is HIGHLY underdetermined (expected random ~19.2/24)")
    print(f"  Only scores >20/24 would be meaningful at this width")

    verdict = "SIGNAL" if best_overall >= 20 else ("STORE" if best_overall > NOISE_FLOOR else "NOISE")
    print(f"\nVERDICT: {verdict}")

    artifact = {
        "experiment_id": "e_s_127",
        "stage": 4,
        "hypothesis": "Urania Weltzeituhr 24-face structure generates K4 transposition",
        "parameters_source": "K4 plaintext (BERLINCLOCK) + Sanborn confirmation",
        "clock": "Urania Weltzeituhr (NOT Mengenlehreuhr)",
        "total_tested": total_tested,
        "best_score": best_overall,
        "random_w24_baseline": phase6_best,
        "above_noise": results[:50],
        "tz_orders_tested": list(tz_orders.keys()),
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "note": "Width-24 is severely underdetermined. Expected random ~19.2/24. Only >20 meaningful.",
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_127_weltzeituhr.py",
    }

    out_path = "artifacts/progressive_solve/stage4/weltzeituhr_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
