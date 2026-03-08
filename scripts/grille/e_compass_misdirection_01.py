#!/usr/bin/env python3
"""Test computational hypotheses from compass rose misdirection analysis.

Cipher: Vigenere/Beaufort/VarBeaufort + rotation/offset
Family: grille
Status: active
Keyspace: ~50K configs (rotations × keywords × variants × alphabets)
Last run: never
Best score: n/a

The compass rose on Kryptos shows the lodestone deflecting the needle.
The white (south-seeking) end points toward the lodestone; the dark
(north-seeking) end settles at ~67.5 degrees (ENE). This suggests:
  1. Misdirection: the apparent text order is not the true order
  2. Specific numeric parameters embedded in the deflection angle
  3. W (the lodestone's cardinal direction) as a key parameter
  4. Reversal/inversion as a cipher operation

This script tests:
  Phase A: Cyclic rotation of CT by compass-derived offsets, then Vig/Beau decrypt
  Phase B: W-parameterized offsets (pos 22 in AZ, pos 25 in KA)
  Phase C: Inverted permutation direction (scatter vs gather) with keyword decryption
  Phase D: Deflection angle (67/68) as starting position for route reads
  Phase E: Reverse the CT, then decrypt (literal "things are backwards")
"""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
)
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.transforms.transposition import apply_perm, invert_perm
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.scoring.ic import ic

# ── Candidate keywords ──────────────────────────────────────────────────

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX",
    "COLOPHON", "SHADOW", "VERDIGRIS", "COMPASS", "LODESTONE",
    "MAGNETIC", "POINT", "NEEDLE", "DEFLECT", "BEARING",
    "WESTERLY", "MISDIRECT", "WHATSTHEPOINT",
    # Short thematic
    "WEST", "ENE", "WSW", "NORTH", "SOUTH", "EAST",
    # From FIVE discovery
    "FIVE", "DYAR", "DYARO",
]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

# Compass-derived offsets to test
COMPASS_OFFSETS = [
    # Deflection angle
    67, 68,              # 67.5 degrees ENE
    # W position in alphabets
    22,                  # W in standard AZ (0-indexed)
    25,                  # W in KA
    # Complementary angles
    30, 29,              # 97 - 67 = 30, 97 - 68 = 29
    # Berlin bearing from Langley
    46, 47, 48, 49, 50,  # great circle ~46-50 degrees
    # Supplement: 180 - 67.5
    112 % 97,            # = 15
    # Other compass divisions
    8,                   # 8 principal compass points; also FRAC Bean period
    16,                  # 16 compass points
    # 67.5 / 360 * 97 ≈ 18.2
    18, 19,              # angle-to-position mapping
    # FIVE-related
    5,
]
# Deduplicate
COMPASS_OFFSETS = sorted(set(COMPASS_OFFSETS))

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

best_score = 0
best_result = None
total_tested = 0


def report(label: str, pt: str, method: str):
    """Score and report if above noise."""
    global best_score, best_result, total_tested
    total_tested += 1

    # Anchored scoring
    sb = score_candidate(pt)
    # Free scoring
    fb = score_candidate_free(pt)

    effective_score = max(sb.crib_score, fb.crib_score)

    if effective_score > best_score:
        best_score = effective_score
        best_result = (label, pt, method, sb, fb)

    if effective_score >= 10:
        print(f"\n*** INTERESTING [{label}] ***")
        print(f"  Method: {method}")
        print(f"  PT: {pt}")
        print(f"  Anchored: {sb.summary}")
        print(f"  Free: {fb.summary}")

    if sb.is_breakthrough or fb.is_breakthrough:
        print(f"\n{'='*70}")
        print(f"!!! BREAKTHROUGH [{label}] !!!")
        print(f"  Method: {method}")
        print(f"  PT: {pt}")
        print(f"  Anchored: {sb.summary}")
        print(f"  Free: {fb.summary}")
        print(f"{'='*70}")


def keyword_to_nums(kw: str, use_ka: bool = False) -> list[int]:
    """Convert keyword to numeric key values."""
    idx = KA_IDX if use_ka else ALPH_IDX
    return [idx[c] for c in kw.upper() if c in idx]


def rotate_text(text: str, offset: int) -> str:
    """Cyclic rotation: shift text by offset positions."""
    n = len(text)
    offset = offset % n
    return text[offset:] + text[:offset]


# ══════════════════════════════════════════════════════════════════════════
# Phase A: Cyclic rotation by compass-derived offsets, then decrypt
# ══════════════════════════════════════════════════════════════════════════

def phase_a():
    print("=" * 70)
    print("PHASE A: Rotate CT by compass-derived offsets, then decrypt")
    print("=" * 70)

    for offset in COMPASS_OFFSETS:
        rotated = rotate_text(CT, offset)
        for kw in KEYWORDS:
            key_nums = keyword_to_nums(kw)
            if not key_nums:
                continue
            for variant in VARIANTS:
                pt = decrypt_text(rotated, key_nums, variant)
                label = f"A-rot{offset}"
                method = f"rotate({offset}) + {variant.value}(key={kw})"
                report(label, pt, method)

            # Also try KA-indexed keys
            key_ka = keyword_to_nums(kw, use_ka=True)
            for variant in VARIANTS:
                pt = decrypt_text(rotated, key_ka, variant)
                label = f"A-rot{offset}-KA"
                method = f"rotate({offset}) + {variant.value}(key={kw}, KA-indexed)"
                report(label, pt, method)

    print(f"  Phase A: {total_tested} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase B: W-parameterized start positions
# ══════════════════════════════════════════════════════════════════════════

def phase_b():
    print("\n" + "=" * 70)
    print("PHASE B: W as start offset (AZ=22, KA=25), read from there")
    print("=" * 70)

    before = total_tested
    # W in AZ = 22, W in KA = 25
    for w_offset in [22, 25]:
        # Route 1: Read starting at position W, wrapping around
        rotated = rotate_text(CT, w_offset)

        for kw in KEYWORDS:
            key_nums = keyword_to_nums(kw)
            if not key_nums:
                continue
            for variant in VARIANTS:
                pt = decrypt_text(rotated, key_nums, variant)
                label = f"B-W{w_offset}"
                method = f"start@W(offset={w_offset}) + {variant.value}(key={kw})"
                report(label, pt, method)

        # Route 2: Every W-th letter (period extraction)
        for step in [22, 25]:
            extracted = ""
            for i in range(CT_LEN):
                extracted += CT[(i * step) % CT_LEN]

            # Check if extraction produces anything interesting (only works if 97 is prime and step != 97)
            if len(set(range(CT_LEN))) == CT_LEN:  # step coprime to 97 (always true since 97 is prime and step < 97)
                for kw in KEYWORDS:
                    key_nums = keyword_to_nums(kw)
                    if not key_nums:
                        continue
                    for variant in VARIANTS:
                        pt = decrypt_text(extracted, key_nums, variant)
                        label = f"B-step{step}"
                        method = f"every-{step}th-letter + {variant.value}(key={kw})"
                        report(label, pt, method)

    print(f"  Phase B: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase C: Inverted permutation direction
# ══════════════════════════════════════════════════════════════════════════

def phase_c():
    print("\n" + "=" * 70)
    print("PHASE C: Scatter vs gather — test both permutation directions")
    print("=" * 70)

    before = total_tested

    # Build permutations from compass offsets
    # For each offset, create a cyclic permutation and its inverse
    for offset in COMPASS_OFFSETS:
        # Cyclic permutation: perm[i] = (i + offset) % 97
        perm_gather = [(i + offset) % CT_LEN for i in range(CT_LEN)]
        perm_scatter = invert_perm(perm_gather)

        for perm, direction in [(perm_gather, "gather"), (perm_scatter, "scatter")]:
            unscrambled = apply_perm(CT, perm)

            for kw in KEYWORDS:
                key_nums = keyword_to_nums(kw)
                if not key_nums:
                    continue
                for variant in VARIANTS:
                    pt = decrypt_text(unscrambled, key_nums, variant)
                    label = f"C-{direction}-{offset}"
                    method = f"cyclic_perm({offset},{direction}) + {variant.value}(key={kw})"
                    report(label, pt, method)

    # Also try multiplicative permutations: perm[i] = (i * multiplier) % 97
    # Since 97 is prime, any multiplier 1-96 gives a valid permutation
    MULTIPLIERS = [22, 25, 46, 47, 48, 49, 50, 67, 68, 5, 8, 16]
    for mult in MULTIPLIERS:
        perm_gather = [(i * mult) % CT_LEN for i in range(CT_LEN)]
        perm_scatter = invert_perm(perm_gather)

        for perm, direction in [(perm_gather, "gather"), (perm_scatter, "scatter")]:
            unscrambled = apply_perm(CT, perm)

            for kw in KEYWORDS:
                key_nums = keyword_to_nums(kw)
                if not key_nums:
                    continue
                for variant in VARIANTS:
                    pt = decrypt_text(unscrambled, key_nums, variant)
                    label = f"C-mult{mult}-{direction}"
                    method = f"mult_perm({mult},{direction}) + {variant.value}(key={kw})"
                    report(label, pt, method)

    print(f"  Phase C: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase D: Route reads starting from deflection angle position
# ══════════════════════════════════════════════════════════════════════════

def phase_d():
    print("\n" + "=" * 70)
    print("PHASE D: Route reads from position 67/68 (deflection angle)")
    print("=" * 70)

    before = total_tested

    # Spiral-like reads starting from position 67
    for start in [67, 68]:
        # Forward from start, wrapping
        fwd = rotate_text(CT, start)
        # Backward from start, wrapping
        bwd = CT[start::-1] + CT[:start:-1][::-1]
        bwd = bwd[:CT_LEN]  # ensure length
        # Alternating: one forward, one backward from start
        alt = []
        for step in range(CT_LEN):
            if step % 2 == 0:
                pos = (start + step // 2) % CT_LEN
            else:
                pos = (start - (step + 1) // 2) % CT_LEN
            alt.append(CT[pos])
        alt_text = "".join(alt)

        for text, route_name in [(fwd, "fwd"), (bwd, "bwd"), (alt_text, "alt")]:
            for kw in KEYWORDS:
                key_nums = keyword_to_nums(kw)
                if not key_nums:
                    continue
                for variant in VARIANTS:
                    pt = decrypt_text(text, key_nums, variant)
                    label = f"D-{route_name}{start}"
                    method = f"route_{route_name}(start={start}) + {variant.value}(key={kw})"
                    report(label, pt, method)

    print(f"  Phase D: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase E: Reverse CT then decrypt ("things are backwards")
# ══════════════════════════════════════════════════════════════════════════

def phase_e():
    print("\n" + "=" * 70)
    print("PHASE E: Reverse CT, then decrypt (misdirection = literal reversal)")
    print("=" * 70)

    before = total_tested
    reversed_ct = CT[::-1]

    for kw in KEYWORDS:
        key_nums = keyword_to_nums(kw)
        if not key_nums:
            continue
        for variant in VARIANTS:
            pt = decrypt_text(reversed_ct, key_nums, variant)
            label = "E-rev"
            method = f"reverse(CT) + {variant.value}(key={kw})"
            report(label, pt, method)

        # Also KA-indexed
        key_ka = keyword_to_nums(kw, use_ka=True)
        for variant in VARIANTS:
            pt = decrypt_text(reversed_ct, key_ka, variant)
            label = "E-rev-KA"
            method = f"reverse(CT) + {variant.value}(key={kw}, KA-indexed)"
            report(label, pt, method)

    # Reverse + rotate combinations
    for offset in [22, 25, 67, 68, 5]:
        rotated_rev = rotate_text(reversed_ct, offset)
        for kw in KEYWORDS[:10]:  # top keywords only
            key_nums = keyword_to_nums(kw)
            if not key_nums:
                continue
            for variant in VARIANTS:
                pt = decrypt_text(rotated_rev, key_nums, variant)
                label = f"E-rev-rot{offset}"
                method = f"reverse+rotate({offset}) + {variant.value}(key={kw})"
                report(label, pt, method)

    print(f"  Phase E: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Phase F: "Two readings" — decrypt BOTH rotations, look for dual signal
# ══════════════════════════════════════════════════════════════════════════

def phase_f():
    print("\n" + "=" * 70)
    print("PHASE F: Two readings — north-end vs south-end give different texts")
    print("         (complementary rotation: offset vs 97-offset)")
    print("=" * 70)

    before = total_tested
    dual_hits = []

    for offset in COMPASS_OFFSETS:
        complement = CT_LEN - offset
        text_north = rotate_text(CT, offset)
        text_south = rotate_text(CT, complement)

        for kw in KEYWORDS:
            key_nums = keyword_to_nums(kw)
            if not key_nums:
                continue
            for variant in VARIANTS:
                pt_n = decrypt_text(text_north, key_nums, variant)
                pt_s = decrypt_text(text_south, key_nums, variant)

                sb_n = score_candidate_free(pt_n)
                sb_s = score_candidate_free(pt_s)

                combined = sb_n.crib_score + sb_s.crib_score

                if combined >= 13:
                    dual_hits.append({
                        'offset': offset,
                        'keyword': kw,
                        'variant': variant.value,
                        'score_north': sb_n.crib_score,
                        'score_south': sb_s.crib_score,
                        'combined': combined,
                        'pt_n': pt_n,
                        'pt_s': pt_s,
                    })

                report(f"F-north-{offset}", pt_n, f"north_read({offset}) + {variant.value}(key={kw})")
                report(f"F-south-{offset}", pt_s, f"south_read({complement}) + {variant.value}(key={kw})")

    if dual_hits:
        print(f"\n  DUAL SIGNAL HITS:")
        dual_hits.sort(key=lambda h: -h['combined'])
        for h in dual_hits[:10]:
            print(f"    offset={h['offset']} {h['variant']} key={h['keyword']}"
                  f"  north={h['score_north']} south={h['score_south']}"
                  f"  combined={h['combined']}")

    print(f"  Phase F: {total_tested - before} configs tested")


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    print("COMPASS MISDIRECTION INVESTIGATION")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Compass offsets to test: {COMPASS_OFFSETS}")
    print(f"Keywords: {len(KEYWORDS)}")
    print(f"Variants: {len(VARIANTS)}")
    print()

    phase_a()
    phase_b()
    phase_c()
    phase_d()
    phase_e()
    phase_f()

    print("\n" + "=" * 70)
    print(f"TOTAL: {total_tested} configurations tested")
    print(f"Best score: {best_score}")
    if best_result:
        label, pt, method, sb, fb = best_result
        print(f"  Label: {label}")
        print(f"  Method: {method}")
        print(f"  PT: {pt}")
        print(f"  Anchored: {sb.summary}")
        print(f"  Free: {fb.summary}")
    else:
        print("  No results above noise.")
    print("=" * 70)


if __name__ == "__main__":
    main()
