#!/usr/bin/env python3
"""
Cipher: WSW compass deflection reframe
Family: grille
Status: active
Keyspace: ~25000 configs
Last run: never
Best score: n/a

Hypothesis: The community has been reading the wrong end of the Kryptos
compass needle. The north-seeking (red/transparent) end points TOWARD
the lodestone = WSW (~247.5 degrees), not ENE. Prior compass scripts
tested ENE-derived parameters; this tests WSW-derived ones.

WSW = 247.5 degrees. Key derivations:
  - 247 mod 26 = 13 (N), 248 mod 26 = 14 (O)
  - 247 mod 97 = 53, 248 mod 97 = 54
  - WESTSOUTHWEST = 14 letters (keyword or key length)
  - WSW ordinals: W=22, S=18, W=22
  - Complement: 360 - 247.5 = 112.5 (ESE)

Also tests: if each of three installations gives a different bearing,
the three bearings together parameterize a multi-step cipher.
Estimated Arlington deflection: ~330-345 (NNW), mod 26 = 18-7.
"""

import sys
import os
from itertools import product

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.transforms.transposition import columnar_perm, apply_perm, invert_perm

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

best_score = 0
best_result = None
total_tested = 0


def keyword_to_nums(kw):
    return [ALPH_IDX[c] for c in kw.upper() if c in ALPH_IDX]


def report(label, pt, method):
    global best_score, best_result, total_tested
    total_tested += 1

    sb = score_candidate(pt) if len(pt) >= 74 else None
    fb = score_candidate_free(pt)

    anchored = sb.crib_score if sb else 0
    free = fb.crib_score
    effective = max(anchored, free)

    if effective > best_score:
        best_score = effective
        best_result = (label, pt[:80], method, effective)

    if effective >= 10:
        print(f"\n*** INTERESTING [{label}] score={effective}/24 ***")
        print(f"  Method: {method}")
        print(f"  PT: {pt[:80]}")
        if sb:
            print(f"  Anchored: {sb.summary}")
        print(f"  Free: {fb.summary}")

    if effective >= 18:
        print(f"\n{'='*70}")
        print(f"!!! SIGNAL [{label}] score={effective}/24 !!!")
        print(f"  {method}")
        print(f"  PT: {pt}")
        print(f"{'='*70}")


def rotate_text(text, offset):
    n = len(text)
    offset = offset % n
    return text[offset:] + text[:offset]


# ── WSW-derived parameters ─────────────────────────────────────────────

# Bearing-derived numeric keys
WSW_KEYS = {
    # Core WSW derivations
    "WSW_ordinals": [22, 18, 22],                    # W=22 S=18 W=22
    "WESTSOUTHWEST": keyword_to_nums("WESTSOUTHWEST"),  # 14-letter keyword
    "WSW_bearing_248": [2, 4, 8],                    # 248 as digits
    "WSW_bearing_2475": [2, 4, 7, 5],                # 247.5 as digits
    "WSW_mod26_NO": [13, 14],                        # 247%26=13(N), 248%26=14(O)
    "WSW_mod26_N": [13],                             # 247 mod 26 = N
    "WSW_mod26_O": [14],                             # 248 mod 26 = O

    # Complement: ESE = 112.5
    "ESE_ordinals": [4, 18, 4],                      # E=4 S=18 E=4
    "EASTSOUTHEAST": keyword_to_nums("EASTSOUTHEAST"),
    "ESE_bearing_113": [1, 1, 3],
    "ESE_mod26": [112 % 26],                         # 112%26 = 8 (I)

    # Three-installation model (estimated bearings)
    # Kryptos: WSW ~248, Arlington: NNW ~338, Bethesda: unknown (~?)
    "CIA_ARL_pair": [248 % 26, 338 % 26],            # [14, 0] = O, A
    "CIA_ARL_digits": [2, 4, 8, 3, 3, 8],
    "three_mod26_est": [248 % 26, 338 % 26, 315 % 26],  # estimate Bethesda NW ~315

    # Standard thematic keywords combined with WSW offset
    "KRYPTOS": keyword_to_nums("KRYPTOS"),
    "PALIMPSEST": keyword_to_nums("PALIMPSEST"),
    "ABSCISSA": keyword_to_nums("ABSCISSA"),
    "COMPASS": keyword_to_nums("COMPASS"),
    "LODESTONE": keyword_to_nums("LODESTONE"),
    "MAGNETIC": keyword_to_nums("MAGNETIC"),
    "SHADOW": keyword_to_nums("SHADOW"),
    "POINT": keyword_to_nums("POINT"),
    "DEFECTOR": keyword_to_nums("DEFECTOR"),
    "MISDIRECTION": keyword_to_nums("MISDIRECTION"),
    "INVISIBLE": keyword_to_nums("INVISIBLE"),
    "FORCES": keyword_to_nums("FORCES"),
}

# WSW-derived position offsets (for rotation, start position)
WSW_OFFSETS = [
    247 % 97,   # 53
    248 % 97,   # 54
    112 % 97,   # 15 (ESE complement)
    113 % 97,   # 16
    22,         # W in AZ
    18,         # S in AZ
    14,         # 248 mod 26 = O position
    13,         # 247 mod 26 = N position
    # Three-installation offsets combined
    (248 + 338) % 97,       # 586 % 97 = 3
    (248 + 338 + 315) % 97, # 901 % 97 = 28
    (248 * 338) % 97,       # mod 97
    # WSW as single value
    248 % 97,   # 54
    # Difference between WSW and ENE
    (248 - 68) % 97,  # 180 % 97 = 83
    180 % 97,   # 83 (half turn)
    180 % 26,   # 24
]
WSW_OFFSETS = sorted(set(WSW_OFFSETS))

# Columnar widths to test with WSW keys
WIDTHS = [7, 8, 10, 11, 13, 14]


# ══════════════════════════════════════════════════════════════════════════
# Phase 1: WSW-derived keys, direct decrypt
# ══════════════════════════════════════════════════════════════════════════

def phase_1():
    print("=" * 70)
    print("PHASE 1: WSW-derived keys — direct substitution on CT")
    print("=" * 70)

    before = total_tested

    for key_name, key in WSW_KEYS.items():
        if not key:
            continue
        for variant in VARIANTS:
            pt = decrypt_text(CT, key, variant)
            report("P1", pt, f"{variant.value}(key={key_name})")

    print(f"  Phase 1: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase 2: WSW rotation offsets + keyword decrypt
# ══════════════════════════════════════════════════════════════════════════

def phase_2():
    print("\n" + "=" * 70)
    print("PHASE 2: Rotate CT by WSW-derived offsets, then decrypt")
    print("=" * 70)

    before = total_tested

    for offset in WSW_OFFSETS:
        rotated = rotate_text(CT, offset)
        for key_name, key in WSW_KEYS.items():
            if not key:
                continue
            for variant in VARIANTS[:2]:  # Vig + Beau
                pt = decrypt_text(rotated, key, variant)
                report(f"P2-rot{offset}", pt,
                       f"rotate({offset}) + {variant.value}(key={key_name})")

    print(f"  Phase 2: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase 3: WSW + columnar transposition
# ══════════════════════════════════════════════════════════════════════════

def phase_3():
    print("\n" + "=" * 70)
    print("PHASE 3: Columnar transposition (WSW-derived widths) + decrypt")
    print("=" * 70)

    before = total_tested

    # WESTSOUTHWEST has 13 letters — test width 13 with keyword-derived column order
    wsw_word = "WESTSOUTHWEST"
    # Derive column order from keyword: alphabetical ranking of letters
    def keyword_col_order(kw):
        indexed = sorted(range(len(kw)), key=lambda i: (kw[i], i))
        order = [0] * len(kw)
        for rank, orig_idx in enumerate(indexed):
            order[orig_idx] = rank
        return order

    wsw_col_order = keyword_col_order(wsw_word)
    print(f"  WESTSOUTHWEST ({len(wsw_word)} letters) column order: {wsw_col_order}")

    # Test WESTSOUTHWEST as columnar keyword
    for width, col_order_source in [
        (len(wsw_word), wsw_col_order),
    ]:
        perm = columnar_perm(width, col_order_source, CT_LEN)
        inv = invert_perm(perm)

        for direction, p in [("undo", inv), ("apply", perm)]:
            unscrambled = apply_perm(CT, p)

            # Raw score
            report(f"P3-w{width}-{direction}", unscrambled,
                   f"columnar(w={width}, key=WESTSOUTHWEST, {direction})")

            for key_name in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "COMPASS",
                             "LODESTONE", "WSW_ordinals", "WSW_mod26_NO",
                             "WESTSOUTHWEST", "MAGNETIC", "SHADOW"]:
                key = WSW_KEYS.get(key_name)
                if not key:
                    continue
                for variant in VARIANTS[:2]:
                    pt = decrypt_text(unscrambled, key, variant)
                    report(f"P3-w{width}-{direction}", pt,
                           f"columnar(w={width},WESTSOUTHWEST,{direction}) + {variant.value}({key_name})")

    # Also test standard widths with WSW-specific keys
    for width in WIDTHS:
        # Simple sequential column order
        for col_order in [list(range(width)), list(range(width - 1, -1, -1))]:
            perm = columnar_perm(width, col_order, CT_LEN)
            inv = invert_perm(perm)
            unscrambled = apply_perm(CT, inv)

            for key_name in ["WSW_ordinals", "WSW_mod26_NO", "WESTSOUTHWEST",
                             "WSW_bearing_248", "ESE_ordinals"]:
                key = WSW_KEYS.get(key_name)
                if not key:
                    continue
                for variant in VARIANTS[:2]:
                    pt = decrypt_text(unscrambled, key, variant)
                    report(f"P3-w{width}", pt,
                           f"columnar(w={width}) + {variant.value}({key_name})")

    print(f"  Phase 3: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase 4: Multiplicative permutation by WSW-derived multipliers
# ══════════════════════════════════════════════════════════════════════════

def phase_4():
    print("\n" + "=" * 70)
    print("PHASE 4: Multiplicative permutations (WSW multipliers mod 97)")
    print("=" * 70)

    before = total_tested

    # Since 97 is prime, any multiplier 1-96 gives a valid permutation
    wsw_multipliers = [
        248 % 97,   # 54
        247 % 97,   # 53
        112 % 97,   # 15
        113 % 97,   # 16
        22,         # W
        18,         # S
        14,         # O (248 mod 26)
        13,         # N (247 mod 26)
        # Products of bearings mod 97
        (22 * 18) % 97,   # 396 % 97 = 8
        (22 * 18 * 22) % 97,  # WSW product
    ]
    wsw_multipliers = sorted(set(m for m in wsw_multipliers if 1 <= m <= 96))

    for mult in wsw_multipliers:
        perm = [(i * mult) % CT_LEN for i in range(CT_LEN)]
        inv = invert_perm(perm)

        for p, direction in [(perm, "gather"), (inv, "scatter")]:
            unscrambled = apply_perm(CT, p)

            # Raw score
            report(f"P4-mult{mult}-{direction}", unscrambled,
                   f"mult_perm({mult},{direction})")

            for key_name in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "COMPASS",
                             "LODESTONE", "WESTSOUTHWEST", "WSW_ordinals",
                             "MAGNETIC", "SHADOW", "INVISIBLE", "FORCES"]:
                key = WSW_KEYS.get(key_name)
                if not key:
                    continue
                for variant in VARIANTS[:2]:
                    pt = decrypt_text(unscrambled, key, variant)
                    report(f"P4-m{mult}-{direction}", pt,
                           f"mult({mult},{direction}) + {variant.value}({key_name})")

    print(f"  Phase 4: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase 5: WESTSOUTHWEST as running key
# ══════════════════════════════════════════════════════════════════════════

def phase_5():
    print("\n" + "=" * 70)
    print("PHASE 5: Extended WSW keywords as running-key-length keys")
    print("=" * 70)

    before = total_tested

    # Build longer keys by repeating/extending compass words
    long_keys = {
        "WESTSOUTHWEST_x7": keyword_to_nums("WESTSOUTHWEST" * 8)[:97],
        "EASTNORTHEAST_x8": keyword_to_nums("EASTNORTHEAST" * 8)[:97],
        "WSW_ENE_alt": keyword_to_nums("WESTSOUTHWESTEASTNORTHEAST" * 4)[:97],
        "NSEW_x25": keyword_to_nums("NSEW" * 25)[:97],
        "NWSE_x25": keyword_to_nums("NWSE" * 25)[:97],
        "SENW_x25": keyword_to_nums("SENW" * 25)[:97],
        "COMPASS_POINTS_16": keyword_to_nums(
            "NNNEENEESESESSSWSWWWNWNW" * 5)[:97],
        # Cardinal only
        "CARDINAL_x25": keyword_to_nums("NEWS" * 25)[:97],
        # Three installation keywords combined
        "KRYPTOS_INVISIBLE_LODESTONE": keyword_to_nums(
            "KRYPTOSINVISIBLEFORCESLODESTONE" * 4)[:97],
        "INVISIBLE_FORCES": keyword_to_nums("INVISIBLEFORCES" * 7)[:97],
        "FIND_THE_LODESTONE": keyword_to_nums("FINDTHELODESTONE" * 7)[:97],
    }

    for key_name, key in long_keys.items():
        if not key or len(key) < 97:
            key = (key * (97 // len(key) + 1))[:97] if key else None
        if not key:
            continue
        for variant in VARIANTS:
            pt = decrypt_text(CT, key, variant)
            report("P5", pt, f"{variant.value}(key={key_name})")

    print(f"  Phase 5: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase 6: Reverse CT (WSW = "look the other way") + WSW keys
# ══════════════════════════════════════════════════════════════════════════

def phase_6():
    print("\n" + "=" * 70)
    print("PHASE 6: Reversed CT + WSW-derived keys")
    print("=" * 70)

    before = total_tested
    rev_ct = CT[::-1]

    for key_name in ["WSW_ordinals", "WESTSOUTHWEST", "WSW_mod26_NO",
                     "WSW_bearing_248", "KRYPTOS", "PALIMPSEST", "ABSCISSA",
                     "COMPASS", "LODESTONE", "MAGNETIC", "INVISIBLE", "FORCES",
                     "ESE_ordinals", "EASTSOUTHEAST"]:
        key = WSW_KEYS.get(key_name)
        if not key:
            continue
        for variant in VARIANTS:
            pt = decrypt_text(rev_ct, key, variant)
            report("P6-rev", pt, f"reverse(CT) + {variant.value}({key_name})")

    # Also reverse + rotate by WSW offsets
    for offset in [53, 54, 83, 24]:
        rotated_rev = rotate_text(rev_ct, offset)
        for key_name in ["KRYPTOS", "WESTSOUTHWEST", "WSW_ordinals", "COMPASS"]:
            key = WSW_KEYS.get(key_name)
            if not key:
                continue
            for variant in VARIANTS[:2]:
                pt = decrypt_text(rotated_rev, key, variant)
                report(f"P6-rev-rot{offset}", pt,
                       f"reverse+rotate({offset}) + {variant.value}({key_name})")

    print(f"  Phase 6: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    print("WSW COMPASS REFRAME INVESTIGATION")
    print("=" * 70)
    print("Hypothesis: North-seeking (red) needle points TOWARD lodestone = WSW")
    print("            Community ENE reading was the wrong (south-seeking) end")
    print(f"CT: {CT}")
    print(f"WSW offsets to test: {WSW_OFFSETS}")
    print(f"WSW keys: {len(WSW_KEYS)}")
    print()

    phase_1()
    phase_2()
    phase_3()
    phase_4()
    phase_5()
    phase_6()

    print("\n" + "=" * 70)
    print(f"TOTAL: {total_tested} configurations tested")
    print(f"Best score: {best_score}/24")
    if best_result:
        label, pt, method, score = best_result
        print(f"  Label: {label}")
        print(f"  Method: {method}")
        print(f"  PT: {pt}")
    else:
        print("  No results above noise.")

    if best_score < 10:
        print("VERDICT: NOISE — WSW reframe does not directly decrypt K4")
        print("  (Does not rule out WSW as one parameter of a multi-layer system)")
    elif best_score < 18:
        print("VERDICT: INTERESTING — investigate further")
    else:
        print("VERDICT: SIGNAL — requires detailed analysis!")
    print("=" * 70)


if __name__ == "__main__":
    main()
