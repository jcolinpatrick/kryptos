#!/usr/bin/env python3
"""
E-ANTIPODES-09: "LAYER TWO" as Instruction — Trimmed Stream

HYPOTHESIS: "XLAYERTWO" at the end of K2 is metadata (an instruction to the
decryptor), not enciphered narrative content. If we trim it from K2's ciphertext
before constructing the Antipodes stream, the stream length changes and all
position-dependent computations shift.

FURTHER: The X delimiters in K2 plaintext mark structural boundaries. The
corresponding ciphertext characters may be padding/separators that should be
excluded from K4's transposition grid.

ALSO TESTS: What if K4 is encrypted with the same method as K2 but "layer two"
means a second application? I.e., K4 = layer1(layer2(plaintext)), and we need
to peel off both layers.

ANGLES:
1. Trim "LAYERTWO" (last 8 chars) or "XLAYERTWO" (last 9) from K2 CT, rebuild stream
2. K2 section lengths with X-delimiters removed
3. K4 = double-encrypted with K2's method (Vigenère ABSCISSA, KA alphabet)
4. POINT as a position indicator — test specific grid positions/coordinates
"""

import json
import os
import sys
import time
import itertools
from typing import List, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm, keyword_to_order, validate_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, encrypt_text,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.alphabet import keyword_mixed_alphabet, Alphabet, KA, AZ

# ══════════════════════════════════════════════════════════════════════════
# Section ciphertexts
# ══════════════════════════════════════════════════════════════════════════

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)
K4_CT = CT

# K2 plaintext sections (between X delimiters):
# "IT WAS TOTALLY INVISIBLE HOW'S THAT POSSIBLE" X
# "THEY USED THE EARTH'S MAGNETIC FIELD..." X
# "DOES LANGLEY KNOW ABOUT THIS..." X
# "WHO KNOWS THE EXACT LOCATION ONLY WW..." X
# "THIRTY EIGHT DEGREES..." X
# "LAYER TWO"

# "LAYERTWO" = last 8 chars of K2 plaintext
# "XLAYERTWO" = last 9 chars
# The corresponding CT chars would be the last 8/9 chars of K2_CT

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}


def make_key(keyword: str, length: int) -> List[int]:
    return [ord(c) - 65 for c in (keyword.upper() * ((length // len(keyword)) + 1))[:length]]


def make_key_ka(keyword: str, length: int) -> List[int]:
    kw_nums = [KA_IDX[c] for c in keyword.upper()]
    return [kw_nums[i % len(kw_nums)] for i in range(length)]


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-ANTIPODES-09: 'LAYER TWO' as Instruction — Trimmed Stream")
    print("=" * 70)
    print(f"K2 CT length: {len(K2_CT)}")
    print(f"K2 CT last 15 chars: ...{K2_CT[-15:]}")

    best_score = 0
    best_result = None
    total_configs = 0
    above_noise = []

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 1: Trim "LAYERTWO" from K2, rebuild Antipodes stream
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("ANGLE 1: Trimmed K2 streams")
    print("=" * 70)

    trim_amounts = [0, 8, 9, 18, 28]  # 0=full, 8=LAYERTWO, 9=XLAYERTWO,
    # 18=coordinates+LAYERTWO, 28=more

    for trim in trim_amounts:
        k2_trimmed = K2_CT[:len(K2_CT) - trim] if trim > 0 else K2_CT

        # Build streams in both orderings
        antipodes_stream = K3_CT + K4_CT + K1_CT + k2_trimmed
        kryptos_stream = K1_CT + k2_trimmed + K3_CT + K4_CT

        for stream_name, stream, k4_start in [
            (f"Antipodes_trim{trim}", antipodes_stream, len(K3_CT)),
            (f"Kryptos_trim{trim}", kryptos_stream, len(K1_CT) + len(k2_trimmed) + len(K3_CT)),
        ]:
            stream_len = len(stream)
            print(f"\n  {stream_name}: {stream_len} chars, K4 at {k4_start}")

            for width in range(6, 38):
                kw_list = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "POINT",
                           "EASTNORTHEAST", "BERLINCLOCK", "SANBORN", "SCHEIDT"]
                # For widths > keyword length, also try identity and reverse
                extra_orders = [tuple(range(width)), tuple(range(width-1, -1, -1))]
                all_orders = []
                for kw in kw_list:
                    col_order = keyword_to_order(kw, width)
                    if col_order is not None:
                        all_orders.append((kw, col_order))
                for eo in extra_orders:
                    all_orders.append(("identity" if eo[0] == 0 else "reverse", eo))
                seen_orders = set()
                for kw, col_order in all_orders:
                    if col_order in seen_orders:
                        continue
                    seen_orders.add(col_order)
                    perm = columnar_perm(width, col_order, stream_len)
                    if not validate_perm(perm, stream_len):
                        continue
                    inv_p = invert_perm(perm)
                    detransposed = apply_perm(stream, inv_p)

                    k4_portion = detransposed[k4_start:k4_start + CT_LEN]
                    if len(k4_portion) < CT_LEN:
                        continue

                    # Check cribs directly
                    sc = score_cribs(k4_portion)
                    total_configs += 1

                    if sc > best_score:
                        best_score = sc
                        best_result = {
                            "angle": 1,
                            "stream": stream_name,
                            "width": width,
                            "keyword": kw,
                            "crib_score": sc,
                        }
                        if sc > NOISE_FLOOR:
                            print(f"    NEW BEST: {sc}/24, w={width} kw={kw}")

                    # Also with Vig decrypt
                    for sub_kw in ["KRYPTOS", "ABSCISSA"]:
                        for variant in VARIANTS:
                            for key_fn_name, key_fn in [("AZ", make_key), ("KA", make_key_ka)]:
                                key = key_fn(sub_kw, CT_LEN)
                                pt = decrypt_text(k4_portion, key, variant)
                                sc2 = score_cribs(pt)
                                total_configs += 1

                                if sc2 > best_score:
                                    best_score = sc2
                                    best_result = {
                                        "angle": 1,
                                        "stream": stream_name,
                                        "width": width,
                                        "trans_kw": kw,
                                        "sub_kw": sub_kw,
                                        "variant": variant.value,
                                        "numbering": key_fn_name,
                                        "plaintext": pt,
                                        "crib_score": sc2,
                                    }
                                    if sc2 > NOISE_FLOOR:
                                        print(f"    NEW BEST: {sc2}/24, w={width} "
                                              f"+{sub_kw}({key_fn_name}) {variant.value}")

                                if sc2 > NOISE_FLOOR:
                                    above_noise.append({
                                        "angle": 1, "stream": stream_name,
                                        "width": width, "crib_score": sc2,
                                    })

    print(f"\n  Angle 1: {total_configs:,} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 2: Double encryption — K4 = K2_method(K2_method(PT))
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("ANGLE 2: K4 = double application of K2's method")
    print("=" * 70)

    # K2 was encrypted with Vigenère, keyword ABSCISSA, KA alphabet
    # "Layer two" might mean: decrypt K4 with ABSCISSA first, then again
    # Or: K1/K2 method (PALIMPSEST/ABSCISSA) applied twice

    layer_keywords = [
        ("ABSCISSA", "ABSCISSA"),     # K2 method twice
        ("PALIMPSEST", "ABSCISSA"),   # K1 then K2
        ("ABSCISSA", "PALIMPSEST"),   # K2 then K1
        ("PALIMPSEST", "PALIMPSEST"), # K1 method twice
        ("KRYPTOS", "ABSCISSA"),      # K3-style then K2
        ("KRYPTOS", "KRYPTOS"),       # K3 method twice
        ("ABSCISSA", "KRYPTOS"),      # K2 then K3
        ("KRYPTOS", "PALIMPSEST"),    # K3 then K1
    ]

    for kw1, kw2 in layer_keywords:
        for v1 in VARIANTS:
            for v2 in VARIANTS:
                for k1_fn_name, k1_fn in [("AZ", make_key), ("KA", make_key_ka)]:
                    for k2_fn_name, k2_fn in [("AZ", make_key), ("KA", make_key_ka)]:
                        total_configs += 1
                        key1 = k1_fn(kw1, CT_LEN)
                        key2 = k2_fn(kw2, CT_LEN)

                        # Peel layer 1 (outer)
                        intermediate = decrypt_text(CT, key1, v1)
                        # Peel layer 2 (inner)
                        pt = decrypt_text(intermediate, key2, v2)
                        sc = score_cribs(pt)

                        if sc > best_score:
                            best_score = sc
                            best_result = {
                                "angle": 2,
                                "layer1": f"{kw1}({k1_fn_name})",
                                "layer2": f"{kw2}({k2_fn_name})",
                                "v1": v1.value,
                                "v2": v2.value,
                                "plaintext": pt,
                                "crib_score": sc,
                            }
                            if sc > NOISE_FLOOR:
                                print(f"  NEW BEST: {sc}/24, L1={kw1}({k1_fn_name}+{v1.value}) "
                                      f"L2={kw2}({k2_fn_name}+{v2.value})")
                                if sc >= STORE_THRESHOLD:
                                    print(f"  PT: {pt}")

                        if sc > NOISE_FLOOR:
                            above_noise.append({
                                "angle": 2,
                                "layer1": f"{kw1}({k1_fn_name})",
                                "layer2": f"{kw2}({k2_fn_name})",
                                "v1": v1.value, "v2": v2.value,
                                "crib_score": sc,
                            })

    # Also: double Vig with transposition between layers
    print("\n  --- Double Vig with transposition between layers ---")
    for kw1, kw2 in [("ABSCISSA", "ABSCISSA"), ("KRYPTOS", "ABSCISSA"),
                       ("PALIMPSEST", "ABSCISSA")]:
        for width in range(6, 14):
            for trans_kw in ["KRYPTOS", "ABSCISSA", "PALIMPSEST"]:
                col_order = keyword_to_order(trans_kw, width)
                if col_order is None:
                    continue
                perm = columnar_perm(width, col_order, CT_LEN)
                if not validate_perm(perm, CT_LEN):
                    continue
                inv_p = invert_perm(perm)

                for v1 in VARIANTS:
                    for v2 in VARIANTS:
                        total_configs += 1
                        key1 = make_key_ka(kw1, CT_LEN)
                        key2 = make_key_ka(kw2, CT_LEN)

                        # Layer 1: Vig decrypt
                        step1 = decrypt_text(CT, key1, v1)
                        # Layer 1.5: undo transposition
                        step2 = apply_perm(step1, inv_p)
                        # Layer 2: Vig decrypt
                        pt = decrypt_text(step2, key2, v2)
                        sc = score_cribs(pt)

                        if sc > best_score:
                            best_score = sc
                            best_result = {
                                "angle": "2b",
                                "layer1": f"{kw1}(KA)",
                                "trans": f"w{width}_{trans_kw}",
                                "layer2": f"{kw2}(KA)",
                                "v1": v1.value, "v2": v2.value,
                                "plaintext": pt,
                                "crib_score": sc,
                            }
                            if sc > NOISE_FLOOR:
                                print(f"  NEW BEST: {sc}/24, "
                                      f"L1={kw1}+trans(w{width},{trans_kw})+L2={kw2}")

                        if sc > NOISE_FLOOR:
                            above_noise.append({
                                "angle": "2b", "crib_score": sc,
                            })

    print(f"\n  Angle 2: {total_configs:,} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 3: "POINT" as position indicator
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("ANGLE 3: POINT as position/coordinate indicator")
    print("=" * 70)

    # Sanborn's clue "POINT" could mean:
    # - A specific position in the text/tableau
    # - POINT as a keyword for the cipher
    # - The decimal point in the K2 coordinates
    # - A starting point for a procedure

    # Test POINT as keyword in various combinations
    point_combos = [
        ("POINT", "KRYPTOS"),
        ("KRYPTOS", "POINT"),
        ("POINT", "ABSCISSA"),
        ("POINT", "PALIMPSEST"),
        ("POINT", "POINT"),
        ("POINT", "BERLIN"),
        ("POINT", "CLOCK"),
        ("BERLINCLOCK", "POINT"),
    ]

    for kw1, kw2 in point_combos:
        for v1 in VARIANTS:
            for v2 in VARIANTS:
                for k_fn_name, k_fn in [("AZ", make_key), ("KA", make_key_ka)]:
                    total_configs += 1
                    key1 = k_fn(kw1, CT_LEN)
                    key2 = k_fn(kw2, CT_LEN)
                    intermediate = decrypt_text(CT, key1, v1)
                    pt = decrypt_text(intermediate, key2, v2)
                    sc = score_cribs(pt)

                    if sc > best_score:
                        best_score = sc
                        best_result = {
                            "angle": 3,
                            "kw1": kw1, "kw2": kw2,
                            "numbering": k_fn_name,
                            "v1": v1.value, "v2": v2.value,
                            "plaintext": pt,
                            "crib_score": sc,
                        }
                        if sc > NOISE_FLOOR:
                            print(f"  NEW BEST: {sc}/24, {kw1}+{kw2} "
                                  f"({k_fn_name}) {v1.value}/{v2.value}")

    # POINT as columnar keyword
    for width in range(5, 6):  # POINT is 5 chars
        col_order = keyword_to_order("POINT", width)
        if col_order:
            perm = columnar_perm(width, col_order, CT_LEN)
            inv_p = invert_perm(perm)
            intermediate = apply_perm(CT, inv_p)

            for kw in ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "BERLIN", "POINT"]:
                for variant in VARIANTS:
                    for k_fn_name, k_fn in [("AZ", make_key), ("KA", make_key_ka)]:
                        total_configs += 1
                        key = k_fn(kw, CT_LEN)
                        pt = decrypt_text(intermediate, key, variant)
                        sc = score_cribs(pt)

                        if sc > best_score:
                            best_score = sc
                            best_result = {
                                "angle": 3,
                                "trans": "POINT_columnar",
                                "keyword": kw,
                                "numbering": k_fn_name,
                                "variant": variant.value,
                                "plaintext": pt,
                                "crib_score": sc,
                            }
                            if sc > NOISE_FLOOR:
                                print(f"  NEW BEST: {sc}/24, POINT trans + {kw}")

    print(f"\n  Angle 3: {total_configs:,} configs, best={best_score}")

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
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
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_antipodes_09')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-ANTIPODES-09",
        "hypothesis": "LAYERTWO as instruction (trim K2), double encryption, POINT clue",
        "total_configs": total_configs,
        "best_score": best_score,
        "best_result": {k: v for k, v in (best_result or {}).items() if k != "plaintext"},
        "above_noise_count": len(above_noise),
        "elapsed_seconds": elapsed,
    }
    with open(os.path.join(outdir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\nResults written to {outdir}/")


if __name__ == "__main__":
    main()
