#!/usr/bin/env python3
"""
E-ANTIPODES-08: K4 in Antipodes Stream Context

HYPOTHESIS: All prior experiments treat K4 as an isolated 97-char block.
But Antipodes shows Sanborn thinks of K4 as embedded in a continuous stream:
K3→K4→K1→K2. The encryption method may operate on this larger context.

KEY INSIGHT: "I know they are the same but they are not arranged the same."
The Antipodes arrangement changes K4's positional context. If the cipher uses
position-dependent keys (running key, autokey, or full-stream transposition),
the Antipodes ordering produces different results than the Kryptos ordering.

ANGLES:
1. Full-stream columnar transposition at Antipodes row widths (32-36)
2. Crib positions relative to Antipodes stream (K4 starts at pos 336)
3. Cross-section key bleeding: K3 sets up the key state for K4
4. Block reordering (K1K2K3K4 → K3K4K1K2) as outer transposition layer
5. Antipodes physical row layout as the transposition grid
6. K3 Vigenère key (KRYPTOS) continuing into K4 at stream-relative offset

COST: Moderate — mostly algebraic, <5 min total.
"""

import json
import os
import sys
import time
import itertools
from typing import List, Dict, Tuple, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm, keyword_to_order, validate_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constraints.bean import verify_bean_simple

# ══════════════════════════════════════════════════════════════════════════
# Section ciphertexts (public facts)
# ══════════════════════════════════════════════════════════════════════════

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K1_LEN = len(K1_CT)  # 63

K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K2_LEN = len(K2_CT)  # 369

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)
K3_LEN = len(K3_CT)  # 336

K4_CT = CT
K4_LEN = CT_LEN  # 97

# ── Stream orderings ─────────────────────────────────────────────────────

# Kryptos ordering (left to right on sculpture)
KRYPTOS_STREAM = K1_CT + K2_CT + K3_CT + K4_CT
K4_START_KRYPTOS = K1_LEN + K2_LEN + K3_LEN  # 768

# Antipodes ordering (as carved)
ANTIPODES_STREAM = K3_CT + K4_CT + K1_CT + K2_CT
K4_START_ANTIPODES = K3_LEN  # 336

# Double pass (as Antipodes actually wraps)
ANTIPODES_DOUBLE = ANTIPODES_STREAM * 2  # truncated in reality but test full

# Known plaintexts
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOROFDARKNESS"
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFJPASSAGEDEBABORETURNST"
    "OTHEEARLIESTTASKWASENTALANTSANDHOWTESIDWALLSITTWASFORCED"
    "HEWALLSLOWLYWERECAVINGINTHEYWEREONLYABLETONOTREADITVERYC"
    "LEARLYWASTHEREACHAROOMBEYONDTHECHAMBERQCANYOUSEEANYTHINGQ"
)

# Antipodes physical row widths (from reconstruction)
ANTIPODES_ROW_WIDTHS = [
    34, 33, 35, 34, 34, 34, 34, 35, 33, 33,  # rows 1-10
    34, 35, 33, 34, 33, 32, 33, 34, 34, 33,  # rows 11-20
    34, 34, 33, 33, 33, 33, 35, 33, 34, 34,  # rows 21-30
    34, 34, 35, 36, 33, 33, 34, 34, 34, 34,  # rows 31-40
    32, 32, 33, 34, 34, 33, 35,              # rows 41-47
]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
KEY_RECOVER = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}
DECRYPT_FN = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}


def score_at_k4_positions(full_pt: str, k4_start: int) -> int:
    """Score cribs at K4 positions within a larger plaintext."""
    count = 0
    for pos, expected in CRIB_DICT.items():
        abs_pos = k4_start + pos
        if abs_pos < len(full_pt) and full_pt[abs_pos] == expected:
            count += 1
    return count


def score_cribs_anywhere(text: str, min_run: int = 5) -> List[Dict]:
    """Search for crib words at ANY position in text, not just expected K4 positions."""
    hits = []
    words = [("EASTNORTHEAST", 13), ("BERLINCLOCK", 11),
             ("NORTHEAST", 9), ("BERLIN", 6), ("CLOCK", 5),
             ("EAST", 4), ("NORTH", 5)]
    for word, wlen in words:
        if wlen < min_run:
            continue
        for i in range(len(text) - wlen + 1):
            if text[i:i+wlen] == word:
                hits.append({"word": word, "position": i, "length": wlen})
    return hits


def make_key(keyword: str, length: int) -> List[int]:
    kw_nums = [ord(c) - 65 for c in keyword.upper()]
    return [kw_nums[i % len(kw_nums)] for i in range(length)]


def make_key_ka(keyword: str, length: int) -> List[int]:
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    kw_nums = [ka_idx[c] for c in keyword.upper()]
    return [kw_nums[i % len(kw_nums)] for i in range(length)]


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-ANTIPODES-08: K4 in Antipodes Stream Context")
    print("=" * 70)
    print(f"K1: {K1_LEN} chars, K2: {K2_LEN} chars, K3: {K3_LEN} chars, K4: {K4_LEN} chars")
    print(f"Antipodes stream: {len(ANTIPODES_STREAM)} chars, K4 starts at pos {K4_START_ANTIPODES}")
    print(f"Kryptos stream: {len(KRYPTOS_STREAM)} chars, K4 starts at pos {K4_START_KRYPTOS}")

    best_score = 0
    best_result = None
    total_configs = 0
    above_noise = []

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 1: Full-stream transposition at Antipodes row widths
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("ANGLE 1: Full-stream columnar transposition at Antipodes row widths")
    print("=" * 70)

    # The Antipodes rows are 32-36 chars wide.  If the full stream was written
    # into a grid of that width and read off by columns, we can reverse it.
    test_widths = sorted(set(ANTIPODES_ROW_WIDTHS + [32, 33, 34, 35, 36]))

    for stream_name, stream, k4_start in [
        ("Antipodes", ANTIPODES_STREAM, K4_START_ANTIPODES),
        ("Kryptos", KRYPTOS_STREAM, K4_START_KRYPTOS),
    ]:
        stream_len = len(stream)
        print(f"\n--- {stream_name} stream ({stream_len} chars) ---")

        for width in test_widths:
            # Try all keyword-based column orderings
            keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "SANBORN",
                        "SCHEIDT", "SHADOW", "ENIGMA", "CLOCK", "CARTER",
                        "EAST", "NORTH", "POINT"]
            # Also identity (no column reorder)
            identity_order = tuple(range(width))

            orders_to_test = [identity_order]
            for kw in keywords:
                order = keyword_to_order(kw, width)
                if order is not None and order not in orders_to_test:
                    orders_to_test.append(order)

            for col_order in orders_to_test:
                perm = columnar_perm(width, col_order, stream_len)
                if not validate_perm(perm, stream_len):
                    continue
                inv_p = invert_perm(perm)
                detransposed = apply_perm(stream, inv_p)

                # Extract K4 portion and check cribs directly
                k4_portion = detransposed[k4_start:k4_start + K4_LEN]
                if len(k4_portion) < K4_LEN:
                    continue

                sc = score_cribs(k4_portion)
                total_configs += 1

                if sc > best_score:
                    best_score = sc
                    best_result = {
                        "angle": 1,
                        "stream": stream_name,
                        "width": width,
                        "col_order": list(col_order)[:10],
                        "k4_start": k4_start,
                        "k4_portion": k4_portion,
                        "crib_score": sc,
                    }
                    if sc > NOISE_FLOOR:
                        print(f"  NEW BEST: {sc}/24, {stream_name} w={width}")

                if sc > NOISE_FLOOR:
                    above_noise.append({
                        "angle": 1, "stream": stream_name,
                        "width": width, "crib_score": sc,
                    })

                # Also try: detranspose full stream, then decrypt K4 with Vig
                for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                    for variant in VARIANTS:
                        for offset in range(len(kw)):
                            key = make_key(kw, K4_LEN)
                            # Shift key by stream-relative offset
                            stream_offset = (k4_start + offset) % len(kw)
                            key_shifted = make_key(kw[stream_offset:] + kw[:stream_offset], K4_LEN)
                            pt = decrypt_text(k4_portion, key_shifted, variant)
                            sc2 = score_cribs(pt)
                            total_configs += 1

                            if sc2 > best_score:
                                best_score = sc2
                                best_result = {
                                    "angle": 1,
                                    "stream": stream_name,
                                    "width": width,
                                    "sub_keyword": kw,
                                    "variant": variant.value,
                                    "stream_offset": stream_offset,
                                    "plaintext": pt,
                                    "crib_score": sc2,
                                }
                                if sc2 > NOISE_FLOOR:
                                    print(f"  NEW BEST: {sc2}/24, {stream_name} "
                                          f"w={width} + {kw} off={stream_offset}")

                            if sc2 > NOISE_FLOOR:
                                above_noise.append({
                                    "angle": 1, "stream": stream_name,
                                    "width": width, "keyword": kw,
                                    "variant": variant.value, "crib_score": sc2,
                                })

    print(f"  Angle 1: {total_configs:,} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 2: K3 key continuation with stream-relative offset
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("ANGLE 2: K3 Vigenère key continuing into K4 at stream-relative offset")
    print("=" * 70)

    # K3 uses KRYPTOS (length 7). In the Antipodes stream, K4 starts at
    # position 336. So the key offset at K4 start = 336 mod 7 = 0.
    # In the Kryptos stream, K4 starts at position 768. 768 mod 7 = 5.
    # These are DIFFERENT starting offsets!

    for stream_name, k4_start in [
        ("Antipodes", K4_START_ANTIPODES),
        ("Kryptos", K4_START_KRYPTOS),
    ]:
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "KRYPTOSPALIMPSEST",
                    "KRYPTOSABSCISSA", "BERLIN", "SANBORN"]:
            kw_len = len(kw)
            stream_offset = k4_start % kw_len

            for variant in VARIANTS:
                for numbering_name, key_fn in [("AZ", make_key), ("KA", make_key_ka)]:
                    total_configs += 1
                    # Key starts at stream_offset into the keyword
                    full_key = key_fn(kw, k4_start + K4_LEN)
                    k4_key = full_key[k4_start:k4_start + K4_LEN]
                    pt = decrypt_text(CT, k4_key, variant)
                    sc = score_cribs(pt)

                    if sc > best_score:
                        best_score = sc
                        best_result = {
                            "angle": 2,
                            "stream": stream_name,
                            "keyword": kw,
                            "stream_offset": stream_offset,
                            "variant": variant.value,
                            "numbering": numbering_name,
                            "plaintext": pt,
                            "crib_score": sc,
                        }
                        if sc > NOISE_FLOOR:
                            print(f"  NEW BEST: {sc}/24, {stream_name} kw={kw} "
                                  f"off={stream_offset} {variant.value} {numbering_name}")

                    if sc > NOISE_FLOOR:
                        above_noise.append({
                            "angle": 2, "stream": stream_name,
                            "keyword": kw, "variant": variant.value,
                            "crib_score": sc,
                        })

    print(f"  Angle 2 cumulative: {total_configs:,} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 3: Block reordering as outer transposition
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("ANGLE 3: Section reordering as block transposition")
    print("=" * 70)

    # K1K2K3K4 → K3K4K1K2 is a block permutation.
    # Try all 24 permutations of 4 sections as an outer transposition.
    sections = [("K1", K1_CT), ("K2", K2_CT), ("K3", K3_CT), ("K4", K4_CT)]

    for perm_order in itertools.permutations(range(4)):
        reordered = "".join(sections[i][1] for i in perm_order)
        # Find where K4 ends up in this reordering
        k4_idx = list(perm_order).index(3)
        k4_offset = sum(len(sections[perm_order[j]][1]) for j in range(k4_idx))
        k4_text = reordered[k4_offset:k4_offset + K4_LEN]
        assert k4_text == CT, f"K4 text mismatch in perm {perm_order}"

        order_name = "".join(f"K{i+1}" for i in perm_order)

        # Now apply columnar transposition to the full reordered stream
        for width in [33, 34, 35]:
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                col_order = keyword_to_order(kw, width)
                if col_order is None:
                    continue
                perm = columnar_perm(width, col_order, len(reordered))
                if not validate_perm(perm, len(reordered)):
                    continue
                inv_p = invert_perm(perm)
                detransposed = apply_perm(reordered, inv_p)

                # What falls at K4's positions after detransposition?
                k4_after = detransposed[k4_offset:k4_offset + K4_LEN]
                sc_direct = score_cribs(k4_after)
                total_configs += 1

                if sc_direct > best_score:
                    best_score = sc_direct
                    best_result = {
                        "angle": 3,
                        "block_order": order_name,
                        "width": width,
                        "trans_keyword": kw,
                        "k4_after_detrans": k4_after,
                        "crib_score": sc_direct,
                    }
                    if sc_direct > NOISE_FLOOR:
                        print(f"  NEW BEST: {sc_direct}/24, {order_name} w={width} kw={kw}")

                if sc_direct > NOISE_FLOOR:
                    above_noise.append({
                        "angle": 3, "block_order": order_name,
                        "width": width, "crib_score": sc_direct,
                    })

                # Also try Vig decrypt after detransposition
                for sub_kw in ["KRYPTOS", "PALIMPSEST"]:
                    for variant in VARIANTS:
                        key = make_key(sub_kw, K4_LEN)
                        pt = decrypt_text(k4_after, key, variant)
                        sc2 = score_cribs(pt)
                        total_configs += 1

                        if sc2 > best_score:
                            best_score = sc2
                            best_result = {
                                "angle": 3,
                                "block_order": order_name,
                                "width": width,
                                "trans_keyword": kw,
                                "sub_keyword": sub_kw,
                                "variant": variant.value,
                                "plaintext": pt,
                                "crib_score": sc2,
                            }
                            if sc2 > NOISE_FLOOR:
                                print(f"  NEW BEST: {sc2}/24, {order_name} "
                                      f"w={width} + {sub_kw} {variant.value}")

                        if sc2 > NOISE_FLOOR:
                            above_noise.append({
                                "angle": 3, "block_order": order_name,
                                "width": width, "variant": variant.value,
                                "crib_score": sc2,
                            })

    print(f"  Angle 3 cumulative: {total_configs:,} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 4: Antipodes ROW layout as transposition grid
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("ANGLE 4: Read Antipodes columns instead of rows")
    print("=" * 70)

    # The Antipodes text is laid out in rows of varying width (32-36).
    # What if you read it by columns instead? Or diagonally?

    # Reconstruct the Antipodes grid (use double pass for full 47 rows)
    stream = ANTIPODES_DOUBLE[:sum(ANTIPODES_ROW_WIDTHS)]
    max_width = max(ANTIPODES_ROW_WIDTHS)
    grid = []
    pos = 0
    for rw in ANTIPODES_ROW_WIDTHS:
        row = stream[pos:pos + rw]
        pos += rw
        grid.append(row)
        if pos >= len(stream):
            break

    n_rows = len(grid)
    print(f"  Grid: {n_rows} rows, widths {min(ANTIPODES_ROW_WIDTHS)}-{max_width}")

    # Read by columns (top to bottom, left to right)
    for col_dir in ["down", "up", "boustrophedon"]:
        col_text = []
        for c in range(max_width):
            if col_dir == "down":
                row_range = range(n_rows)
            elif col_dir == "up":
                row_range = range(n_rows - 1, -1, -1)
            else:  # boustrophedon
                row_range = range(n_rows) if c % 2 == 0 else range(n_rows - 1, -1, -1)

            for r in row_range:
                if c < len(grid[r]):
                    col_text.append(grid[r][c])

        col_stream = "".join(col_text)
        total_configs += 1

        # Search for cribs anywhere in the column-read text
        hits = score_cribs_anywhere(col_stream)
        if hits:
            print(f"  Column read ({col_dir}): Found crib words: {hits}")
            above_noise.append({
                "angle": 4, "read_dir": col_dir,
                "crib_hits": hits,
            })

        # Also: extract what falls at K4-equivalent positions
        # K4 is rows 11-13 (pass 1). In column reading, those chars scatter.
        # Instead, try decrypting the column-read text with standard keys
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for variant in VARIANTS:
                key = make_key(kw, len(col_stream))
                pt = decrypt_text(col_stream, key, variant)
                total_configs += 1

                # Search for ANY crib words in the full decrypted stream
                hits = score_cribs_anywhere(pt)
                if hits:
                    print(f"  Column ({col_dir}) + {kw} {variant.value}: "
                          f"Found: {hits}")
                    above_noise.append({
                        "angle": 4, "read_dir": col_dir,
                        "keyword": kw, "variant": variant.value,
                        "crib_hits": hits,
                    })

    # Also read diagonals
    for diag_dir in ["down_right", "down_left"]:
        diag_text = []
        # Main diagonals
        for start_r in range(n_rows):
            r, c = start_r, 0 if diag_dir == "down_right" else max_width - 1
            while r < n_rows and 0 <= c < max_width:
                if c < len(grid[r]):
                    diag_text.append(grid[r][c])
                r += 1
                c += 1 if diag_dir == "down_right" else -1
        for start_c in range(1, max_width):
            r = 0
            c = start_c if diag_dir == "down_right" else max_width - 1 - start_c
            while r < n_rows and 0 <= c < max_width:
                if c < len(grid[r]):
                    diag_text.append(grid[r][c])
                r += 1
                c += 1 if diag_dir == "down_right" else -1

        diag_stream = "".join(diag_text)
        total_configs += 1
        hits = score_cribs_anywhere(diag_stream)
        if hits:
            print(f"  Diagonal ({diag_dir}): Found crib words: {hits}")

    print(f"  Angle 4 cumulative: {total_configs:,} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 5: Cross-section key bleeding via autokey
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("ANGLE 5: Cross-section autokey (K3 PT seeds K4 decryption)")
    print("=" * 70)

    k3_pt_clean = "".join(c for c in K3_PT.upper() if c.isalpha())

    # PT-autokey: seed from K3 plaintext, continues into K4
    for seed_len in [7, 13, 26, 50, 97, len(k3_pt_clean)]:
        actual_seed_len = min(seed_len, len(k3_pt_clean))
        seed = [ord(c) - 65 for c in k3_pt_clean[-actual_seed_len:]]

        for variant in VARIANTS:
            total_configs += 1
            decrypt_fn = DECRYPT_FN[variant]

            # PT-autokey: k[i] = PT[i-1] after seed exhausted
            pt_nums = []
            key = list(seed)
            for i in range(K4_LEN):
                c = ord(CT[i]) - 65
                if i < len(key):
                    k = key[i]
                else:
                    k = pt_nums[-1]
                p = decrypt_fn(c, k)
                pt_nums.append(p)

            pt = "".join(chr(p + 65) for p in pt_nums)
            sc = score_cribs(pt)

            if sc > best_score:
                best_score = sc
                best_result = {
                    "angle": 5,
                    "mode": "pt_autokey",
                    "seed_len": actual_seed_len,
                    "variant": variant.value,
                    "plaintext": pt,
                    "crib_score": sc,
                }
                if sc > NOISE_FLOOR:
                    print(f"  NEW BEST: {sc}/24, PT-autokey seed={actual_seed_len} "
                          f"{variant.value}")

            # CT-autokey: k[i] = CT_stream[i-1] (using Antipodes stream context)
            total_configs += 1
            pt_nums2 = []
            for i in range(K4_LEN):
                c = ord(CT[i]) - 65
                if i < len(seed):
                    k = seed[i]
                else:
                    # Use the Antipodes stream CT at the position before K4
                    stream_pos = K4_START_ANTIPODES + i - len(seed)
                    if 0 <= stream_pos < len(ANTIPODES_STREAM):
                        k = ord(ANTIPODES_STREAM[stream_pos]) - 65
                    else:
                        k = 0
                p = decrypt_fn(c, k)
                pt_nums2.append(p)

            pt2 = "".join(chr(p + 65) for p in pt_nums2)
            sc2 = score_cribs(pt2)

            if sc2 > best_score:
                best_score = sc2
                best_result = {
                    "angle": 5,
                    "mode": "ct_autokey_stream",
                    "seed_len": actual_seed_len,
                    "variant": variant.value,
                    "plaintext": pt2,
                    "crib_score": sc2,
                }
                if sc2 > NOISE_FLOOR:
                    print(f"  NEW BEST: {sc2}/24, CT-autokey-stream seed={actual_seed_len} "
                          f"{variant.value}")

    # ── Angle 5b: Running key from Antipodes stream (CT as its own key) ──
    print("\n  --- Running key: surrounding CT as key for K4 ---")
    for stream_name, stream, k4_start in [
        ("Antipodes", ANTIPODES_STREAM, K4_START_ANTIPODES),
        ("Kryptos", KRYPTOS_STREAM, K4_START_KRYPTOS),
    ]:
        # Key = the CT characters SURROUNDING K4 in the stream
        # Try: key = stream[k4_start - 97 : k4_start] (text before K4)
        for key_offset in range(-200, 200, 1):
            key_start = k4_start + key_offset
            if key_start < 0 or key_start + K4_LEN > len(stream):
                continue
            if key_offset == 0:
                continue  # Skip: that's K4 itself

            key_text = stream[key_start:key_start + K4_LEN]
            key = [ord(c) - 65 for c in key_text]

            for variant in VARIANTS:
                total_configs += 1
                pt = decrypt_text(CT, key, variant)
                sc = score_cribs(pt)

                if sc > best_score:
                    best_score = sc
                    best_result = {
                        "angle": "5b",
                        "stream": stream_name,
                        "key_offset": key_offset,
                        "variant": variant.value,
                        "plaintext": pt,
                        "crib_score": sc,
                    }
                    if sc > NOISE_FLOOR:
                        print(f"  NEW BEST: {sc}/24, {stream_name} "
                              f"key_offset={key_offset} {variant.value}")

                if sc > NOISE_FLOOR:
                    above_noise.append({
                        "angle": "5b", "stream": stream_name,
                        "key_offset": key_offset,
                        "variant": variant.value, "crib_score": sc,
                    })

    print(f"  Angle 5 cumulative: {total_configs:,} configs, best={best_score}")

    # ══════════════════════════════════════════════════════════════════════
    # ANGLE 6: Crib relocation — search for cribs at stream-relative positions
    # ══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("ANGLE 6: Do cribs appear at stream-relative positions?")
    print("=" * 70)

    # What if positions 21-33 and 63-73 refer to the STREAM, not K4?
    for stream_name, stream, k4_start in [
        ("Antipodes", ANTIPODES_STREAM, K4_START_ANTIPODES),
        ("Kryptos", KRYPTOS_STREAM, K4_START_KRYPTOS),
    ]:
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for variant in VARIANTS:
                key = make_key(kw, len(stream))
                pt_stream = decrypt_text(stream, key, variant)
                total_configs += 1

                # Check for crib words at K4-internal positions
                k4_pt = pt_stream[k4_start:k4_start + K4_LEN]
                sc = score_cribs(k4_pt)

                # Also check: do cribs appear at ABSOLUTE positions 21-33, 63-73?
                abs_hits = 0
                for pos, ch in CRIB_DICT.items():
                    if pos < len(pt_stream) and pt_stream[pos] == ch:
                        abs_hits += 1

                # Check: do cribs appear at stream-offset positions?
                stream_hits = 0
                for pos, ch in CRIB_DICT.items():
                    spos = k4_start + pos
                    if spos < len(pt_stream) and pt_stream[spos] == ch:
                        stream_hits += 1

                max_sc = max(sc, abs_hits, stream_hits)
                if max_sc > best_score:
                    best_score = max_sc
                    best_result = {
                        "angle": 6,
                        "stream": stream_name,
                        "keyword": kw,
                        "variant": variant.value,
                        "k4_cribs": sc,
                        "absolute_cribs": abs_hits,
                        "stream_cribs": stream_hits,
                        "crib_score": max_sc,
                    }
                    if max_sc > NOISE_FLOOR:
                        print(f"  NEW BEST: {max_sc}/24, {stream_name} {kw} "
                              f"{variant.value} (k4={sc}, abs={abs_hits}, "
                              f"stream={stream_hits})")

                # Search for any crib words anywhere in decrypted stream
                all_hits = score_cribs_anywhere(pt_stream, min_run=6)
                if all_hits:
                    for h in all_hits:
                        print(f"  FOUND '{h['word']}' at pos {h['position']} "
                              f"in {stream_name}+{kw}+{variant.value}")
                    above_noise.append({
                        "angle": 6, "stream": stream_name,
                        "keyword": kw, "variant": variant.value,
                        "crib_hits": all_hits,
                    })

    print(f"  Angle 6 cumulative: {total_configs:,} configs, best={best_score}")

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Best crib score: {best_score}/24")
    if best_result:
        for k, v in best_result.items():
            if k not in ("plaintext", "k4_portion", "k4_after_detrans"):
                print(f"  {k}: {v}")
        if best_score >= STORE_THRESHOLD and "plaintext" in best_result:
            print(f"Best plaintext: {best_result['plaintext']}")
    print(f"Above-noise results: {len(above_noise)}")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Write results ─────────────────────────────────────────────────────
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_antipodes_08')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-ANTIPODES-08",
        "hypothesis": "K4 decryption depends on Antipodes stream context (not isolated K4)",
        "total_configs": total_configs,
        "best_score": best_score,
        "best_result": {k: v for k, v in (best_result or {}).items()
                        if k not in ("plaintext", "k4_portion", "k4_after_detrans")},
        "above_noise_count": len(above_noise),
        "elapsed_seconds": elapsed,
        "angles_tested": [
            "1: Full-stream columnar transposition",
            "2: K3 key continuation at stream offset",
            "3: Section reordering as block transposition",
            "4: Antipodes column/diagonal reading",
            "5: Cross-section autokey + surrounding CT as key",
            "6: Crib relocation to stream positions",
        ],
    }
    with open(os.path.join(outdir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    if above_noise:
        with open(os.path.join(outdir, 'above_noise.json'), 'w') as f:
            json.dump(above_noise[:100], f, indent=2, default=str)

    print(f"\nResults written to {outdir}/")


if __name__ == "__main__":
    main()
