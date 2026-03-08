#!/usr/bin/env python3
"""Diagnostic: WHY can't POINT coexist with known cribs under periodic substitution?

For each candidate POINT position × variant, show:
  - Whether it conflicts at an overlap position (same position, different PT)
  - At which periods it fails consistency
  - The minimum number of constraint violations

Also: search for POINT fragments (3+ chars) and related words
in the 903 keyword decryptions.
"""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from collections import Counter
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT
from kryptos.kernel.transforms.vigenere import (
    vig_recover_key, beau_recover_key, varbeau_recover_key,
    decrypt_text, CipherVariant,
)

POINT = "POINT"
POINT_LEN = len(POINT)
MAX_START = CT_LEN - POINT_LEN


def main():
    ct_nums = [ALPH_IDX[c] for c in CT]
    point_nums = [ALPH_IDX[c] for c in POINT]

    recover_fns = {
        'vigenere': vig_recover_key,
        'beaufort': beau_recover_key,
        'var_beaufort': varbeau_recover_key,
    }

    # ── Part A: Overlap analysis ──────────────────────────────────────
    print("=" * 70)
    print("PART A: Overlap conflicts (POINT chars vs known crib chars)")
    print("=" * 70)

    crib_positions = set(CRIB_DICT.keys())  # 21-33, 63-73

    for start in range(MAX_START + 1):
        point_positions = set(range(start, start + POINT_LEN))
        overlap = point_positions & crib_positions
        if overlap:
            # Check character conflicts
            conflicts = []
            for pos in sorted(overlap):
                pt_from_crib = CRIB_DICT[pos]
                pt_from_point = POINT[pos - start]
                if pt_from_crib != pt_from_point:
                    conflicts.append(f"  pos {pos}: crib='{pt_from_crib}' vs POINT='{pt_from_point}'")
            if conflicts:
                print(f"POINT@{start:2d}: overlaps {sorted(overlap)}, CONFLICTS:")
                for c in conflicts:
                    print(c)
            else:
                print(f"POINT@{start:2d}: overlaps {sorted(overlap)}, NO conflict (chars match!)")

    # ── Part B: Period analysis for non-overlapping positions ─────────
    print("\n" + "=" * 70)
    print("PART B: Period consistency (non-overlapping positions only)")
    print("        For each POINT position × variant, shortest consistent period")
    print("=" * 70)

    for variant_name, recover_fn in recover_fns.items():
        print(f"\n--- {variant_name.upper()} ---")

        # Crib-derived keys
        crib_keys = {}
        for pos, pt_ch in CRIB_DICT.items():
            crib_keys[pos] = recover_fn(ct_nums[pos], ALPH_IDX[pt_ch])

        results_by_pos = {}

        for start in range(MAX_START + 1):
            # Skip if overlap conflict
            point_positions = set(range(start, start + POINT_LEN))
            overlap = point_positions & crib_positions
            has_conflict = False
            for pos in overlap:
                if CRIB_DICT[pos] != POINT[pos - start]:
                    has_conflict = True
                    break
            if has_conflict:
                continue

            # POINT-derived keys
            point_keys = {}
            for i, pt_num in enumerate(point_nums):
                pos = start + i
                if pos not in crib_keys:  # Don't duplicate overlapping positions
                    point_keys[pos] = recover_fn(ct_nums[pos], pt_num)

            all_keys = {**crib_keys, **point_keys}

            # Find shortest consistent period
            shortest = None
            for period in range(1, 27):
                residue_vals: dict[int, int] = {}
                ok = True
                for pos, kval in all_keys.items():
                    r = pos % period
                    if r in residue_vals:
                        if residue_vals[r] != kval:
                            ok = False
                            break
                    else:
                        residue_vals[r] = kval
                if ok:
                    shortest = period
                    break

            results_by_pos[start] = shortest

        # Summary
        period_counts = Counter(results_by_pos.values())
        print(f"  Valid (non-conflicting) POINT positions: {len(results_by_pos)}")
        for period in sorted(period_counts.keys()):
            print(f"  Shortest consistent period = {period}: {period_counts[period]} positions")

        # Show specific examples at interesting periods
        for start, period in sorted(results_by_pos.items()):
            if period and period <= 10:
                # Build the key
                point_keys = {}
                for i, pt_num in enumerate(point_nums):
                    pos = start + i
                    point_keys[pos] = recover_fn(ct_nums[pos], pt_num)
                all_keys = {**crib_keys, **point_keys}

                residues: dict[int, int] = {}
                for pos, kval in all_keys.items():
                    r = pos % period
                    residues[r] = kval

                kw_chars = []
                for i in range(period):
                    if i in residues:
                        kw_chars.append(ALPH[residues[i]])
                    else:
                        kw_chars.append('?')
                kw_str = ''.join(kw_chars)
                n_known = sum(1 for c in kw_str if c != '?')
                print(f"    POINT@{start:2d} period={period:2d} key={kw_str} ({n_known}/{period} known)")

    # ── Part C: Fragment and related word search ─────────────────────
    print("\n" + "=" * 70)
    print("PART C: Searching for POINT fragments and related words")
    print("=" * 70)

    kw_path = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords.txt')
    keywords = []
    with open(kw_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                keywords.append(line.upper())
    extras = ["POINT", "POINTER", "COMPASS", "LODESTONE", "MAGNETIC",
              "HOROLOGE", "DEFECTOR", "PARALLAX", "COLOPHON", "URANIA", "QUARTZ"]
    for w in extras:
        if w not in keywords:
            keywords.append(w)

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    # Search targets
    targets = ["POINT", "POIN", "OINT", "INT", "THEPOINT", "COMPASS",
               "LODESTONE", "NEEDLE", "ARROW", "BEARING", "HEADING",
               "NORTH", "SOUTH", "WEST", "EAST", "DIRECTION",
               "POSITION", "LOCATION", "POWER", "SECRET", "RESIDE"]

    hits = {t: [] for t in targets}

    for kw in keywords:
        key_nums = [ALPH_IDX[c] for c in kw]
        for variant in variants:
            pt = decrypt_text(CT, key_nums, variant)
            for target in targets:
                if target in pt:
                    hits[target].append((kw, variant.value, pt.index(target)))

    for target in targets:
        h = hits[target]
        if h:
            print(f"\n  '{target}' found in {len(h)} decryptions:")
            for kw, var, pos in h[:5]:
                print(f"    {kw:20s} {var:15s} @{pos}")
            if len(h) > 5:
                print(f"    ... and {len(h) - 5} more")
        else:
            print(f"  '{target}': 0 hits")


if __name__ == "__main__":
    main()
