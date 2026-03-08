#!/usr/bin/env python3
"""
# Cipher:       Segment-rearrangement (W-delimiter hypothesis)
# Family:       grille
# Status:       active
# Keyspace:     ~30,240 (720 perms x 7 keywords x 3 variants x 2 modes)
# Last run:     2026-03-07
# Best score:   TBD

Hypothesis: The 5 W's in K4 at positions [20,36,48,58,74] are delimiters.
The 6 segments should be rearranged before Vigenere/Beaufort decryption.

Mode 1: Keep all 97 chars, rearrange segments (W included).
Mode 2: Strip leading W from segments 1-5, giving 92 chars.

All 720 permutations tested x 7 keywords x 3 cipher variants.
"""
import sys
import os
import itertools
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, ALPH_IDX
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant,
)
from kryptos.kernel.scoring.free_crib import score_free_fast, score_free


# ── Segments split on W at positions [20, 36, 48, 58, 74] ─────────────────
SEGMENTS_WITH_W = [
    CT[0:20],    # Seg 0: OBKRUOXOGHULBSOLIFBB  (20 chars, no leading W)
    CT[20:36],   # Seg 1: WFLRVQQPRNGKSSOT      (16 chars, starts with W)
    CT[36:48],   # Seg 2: WTQSJQSSEKZZ          (12 chars, starts with W)
    CT[48:58],   # Seg 3: WATJKLUDIA             (10 chars, starts with W)
    CT[58:74],   # Seg 4: WINFBNYPVTTMZFPK       (16 chars, starts with W)
    CT[74:97],   # Seg 5: WGDKZXTJCDIGKUHUAUEKCAR (23 chars, starts with W)
]

SEGMENTS_NO_W = [
    SEGMENTS_WITH_W[0],          # Seg 0: no leading W (20 chars)
    SEGMENTS_WITH_W[1][1:],      # Seg 1: strip W -> FLRVQQPRNGKSSOT (15 chars)
    SEGMENTS_WITH_W[2][1:],      # Seg 2: strip W -> TQSJQSSEKZZ (11 chars)
    SEGMENTS_WITH_W[3][1:],      # Seg 3: strip W -> ATJKLUDIA (9 chars)
    SEGMENTS_WITH_W[4][1:],      # Seg 4: strip W -> INFBNYPVTTMZFPK (15 chars)
    SEGMENTS_WITH_W[5][1:],      # Seg 5: strip W -> GDKZXTJCDIGKUHUAUEKCAR (22 chars)
]

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX", "COLOPHON", "SHADOW"]

VARIANTS = [
    (CipherVariant.VIGENERE, "Vig"),
    (CipherVariant.BEAUFORT, "Beau"),
    (CipherVariant.VAR_BEAUFORT, "VBeau"),
]

# Named orderings to also test explicitly
NAMED_ORDERINGS = {
    "identity":      (0, 1, 2, 3, 4, 5),
    "reverse":       (5, 4, 3, 2, 1, 0),
    "crib_v1":       (1, 4, 0, 2, 3, 5),
    "crib_v2":       (4, 1, 0, 2, 3, 5),
    "interleaved":   (0, 5, 1, 4, 2, 3),
}


def keyword_to_nums(kw: str) -> list:
    return [ALPH_IDX[c] for c in kw.upper()]


def try_all_permutations(segments, mode_name, results):
    """Try all 720 permutations of 6 segments with all keywords and variants."""
    total = 0
    for perm in itertools.permutations(range(6)):
        assembled = "".join(segments[i] for i in perm)
        for kw in KEYWORDS:
            key_nums = keyword_to_nums(kw)
            for variant, vname in VARIANTS:
                pt = decrypt_text(assembled, key_nums, variant)
                sc = score_free_fast(pt)
                total += 1
                if sc > 0:
                    # Get full diagnostics for any non-zero
                    fcr = score_free(pt)
                    results.append((sc, pt, f"{mode_name} perm={perm} kw={kw} var={vname} len={len(assembled)}", fcr))
                    if sc >= 11:
                        print(f"  *** SIGNAL: score={sc} perm={perm} kw={kw} var={vname}")
                        print(f"      PT: {pt[:60]}...")
    return total


def main():
    print("=" * 80)
    print("W-DELIMITER SEGMENT REARRANGEMENT EXPERIMENT")
    print("=" * 80)

    # Verify segments
    reassembled = "".join(SEGMENTS_WITH_W)
    assert reassembled == CT, f"Segment reassembly mismatch!"
    print(f"\nCT verified: {CT}")
    print(f"CT length: {len(CT)}")
    print()

    for i, seg in enumerate(SEGMENTS_WITH_W):
        print(f"  Seg {i} (with W): [{len(seg):2d} chars] {seg}")
    print(f"  Total: {sum(len(s) for s in SEGMENTS_WITH_W)} chars")
    print()

    for i, seg in enumerate(SEGMENTS_NO_W):
        print(f"  Seg {i} (no W):   [{len(seg):2d} chars] {seg}")
    print(f"  Total: {sum(len(s) for s in SEGMENTS_NO_W)} chars")
    print()

    print(f"Keywords: {KEYWORDS}")
    print(f"Variants: Vigenere, Beaufort, Variant Beaufort")
    print(f"Permutations: 720")
    print(f"Total configs per mode: 720 x {len(KEYWORDS)} x {len(VARIANTS)} = {720 * len(KEYWORDS) * len(VARIANTS)}")
    print()

    results = []
    t0 = time.time()

    # ── Mode 1: With W (97 chars) ─────────────────────────────────────────
    print("=" * 60)
    print("MODE 1: Segments WITH leading W (97 chars)")
    print("=" * 60)
    n1 = try_all_permutations(SEGMENTS_WITH_W, "WITH_W", results)
    t1 = time.time()
    print(f"  Tested {n1} configs in {t1-t0:.1f}s")
    print()

    # ── Mode 2: Without W (92 chars) ──────────────────────────────────────
    print("=" * 60)
    print("MODE 2: Segments WITHOUT leading W (92 chars)")
    print("=" * 60)
    n2 = try_all_permutations(SEGMENTS_NO_W, "NO_W", results)
    t2 = time.time()
    print(f"  Tested {n2} configs in {t2-t1:.1f}s")
    print()

    # ── Named orderings with IC check ─────────────────────────────────────
    print("=" * 60)
    print("NAMED ORDERINGS (IC diagnostics)")
    print("=" * 60)
    from kryptos.kernel.scoring.ic import ic
    for name, perm in NAMED_ORDERINGS.items():
        for mode_name, segs in [("WITH_W", SEGMENTS_WITH_W), ("NO_W", SEGMENTS_NO_W)]:
            assembled = "".join(segs[i] for i in perm)
            ic_val = ic(assembled)
            print(f"  {name:15s} {mode_name:6s} len={len(assembled):2d} IC={ic_val:.4f} text={assembled[:40]}...")
            for kw in KEYWORDS:
                key_nums = keyword_to_nums(kw)
                for variant, vname in VARIANTS:
                    pt = decrypt_text(assembled, key_nums, variant)
                    pt_ic = ic(pt)
                    sc = score_free_fast(pt)
                    if sc > 0 or pt_ic > 0.060:
                        print(f"    kw={kw:12s} var={vname:5s} IC={pt_ic:.4f} score={sc} PT={pt[:50]}...")
    print()

    # ── Also try: segments reversed internally ────────────────────────────
    print("=" * 60)
    print("BONUS: Each segment reversed internally, then permuted")
    print("=" * 60)
    segs_rev = [s[::-1] for s in SEGMENTS_WITH_W]
    n3 = try_all_permutations(segs_rev, "REV_SEGS", results)
    t3 = time.time()
    print(f"  Tested {n3} configs in {t3-t2:.1f}s")
    print()

    # ── Summary ────────────────────────────────────────────────────────────
    total_time = time.time() - t0
    total_configs = n1 + n2 + n3

    print("=" * 80)
    print(f"RESULTS SUMMARY")
    print(f"=" * 80)
    print(f"Total configs tested: {total_configs}")
    print(f"Total time: {total_time:.1f}s")
    print(f"Non-zero scores found: {len(results)}")
    print()

    if results:
        # Sort by score descending, then by IC
        results.sort(key=lambda x: (-x[0], -x[3].score))

        print("TOP 20 RESULTS:")
        print("-" * 80)
        for i, (sc, pt, desc, fcr) in enumerate(results[:20]):
            from kryptos.kernel.scoring.ic import ic as ic_fn
            pt_ic = ic_fn(pt)
            print(f"  #{i+1:2d}  score={sc:2d}  IC={pt_ic:.4f}  {desc}")
            print(f"       PT: {pt[:70]}{'...' if len(pt) > 70 else ''}")
            if fcr.ene_found:
                print(f"       ENE found at: {fcr.ene_offsets}")
            if fcr.bc_found:
                print(f"       BC found at: {fcr.bc_offsets}")
            if fcr.ene_fragments:
                top_frags = fcr.ene_fragments[:3]
                print(f"       ENE fragments: {top_frags}")
            if fcr.bc_fragments:
                top_frags = fcr.bc_fragments[:3]
                print(f"       BC fragments: {top_frags}")
            print()

        # Score distribution
        from collections import Counter
        score_dist = Counter(r[0] for r in results)
        print("SCORE DISTRIBUTION (non-zero only):")
        for sc in sorted(score_dist.keys(), reverse=True):
            print(f"  score={sc}: {score_dist[sc]} configs")
    else:
        print("No non-zero scores found in any configuration.")
        print("All 720 permutations x 7 keywords x 3 variants x 2-3 modes = noise.")

    print()
    print("CONCLUSION:")
    if any(r[0] >= 11 for r in results):
        print("  SIGNAL DETECTED - investigate further!")
    elif any(r[0] > 0 for r in results):
        print("  Some partial matches found but no full crib hits.")
        print("  W-delimiter hypothesis shows weak/no signal.")
    else:
        print("  ZERO signal. W-delimiter hypothesis is not supported by this test.")


if __name__ == "__main__":
    main()
