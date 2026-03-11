#!/usr/bin/env python3
# Cipher:     Two-system (null removal + periodic substitution)
# Family:     two_system
# Status:     active
# Keyspace:   ~500 (a,b) pairs x 36 periods x 3 variants x 2 alphabets = ~108K
# Last run:
# Best score:
#
# E-TWO-SYS-01: FAST PROOF — periodic consistency on 73-char reduced text.
#
# Model A: 24 nulls removed from non-crib positions in [0-20], [34-62], [74-96].
# After removal, ENE crib positions shift left by `a` (nulls before pos 21),
# and BC crib positions shift left by `a+b` (nulls before pos 63).
#
# For periodic substitution with period T on the 73-char reduced text:
#   All crib positions sharing the same (reduced_pos % T) must produce
#   the same key value. This is a pure consistency check — no decryption needed.
#
# Key insight: nulls can only be at NON-crib positions, which fall into 3 zones:
#   Zone A: [0, 20] — 21 slots, `a` nulls here
#   Zone B: [34, 62] — 29 slots, `b` nulls here
#   Zone C: [74, 96] — 23 slots, `c` = 24-a-b nulls here
#
# After removing nulls, ALL 13 ENE positions shift by the same offset `a`,
# and ALL 11 BC positions shift by the same offset `a+b`.
#
# Search space: ~500 (a,b) pairs x 36 periods x 6 variants = ~108K checks.
# Runtime: < 1 second.
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, KRYPTOS_ALPHABET,
)

# ── Setup ─────────────────────────────────────────────────────────────────

REDUCED_LEN = 73
N_NULLS = 24

# Crib positions in original 97-char text
ENE_START, ENE_WORD = CRIB_WORDS[0]  # 21, "EASTNORTHEAST"
BC_START, BC_WORD = CRIB_WORDS[1]    # 63, "BERLINCLOCK"
ENE_LEN = len(ENE_WORD)  # 13
BC_LEN = len(BC_WORD)    # 11

# Zone boundaries for null placement (non-crib positions only)
ZONE_A_MAX = 21   # positions [0, 20]: 21 slots
ZONE_B_MAX = 29   # positions [34, 62]: 29 slots
ZONE_C_MAX = 23   # positions [74, 96]: 23 slots

# Key recovery functions: (CT_char, PT_char) → key value
def vig_key(c: int, p: int) -> int:
    return (c - p) % MOD

def beau_key(c: int, p: int) -> int:
    return (c + p) % MOD

def vbeau_key(c: int, p: int) -> int:
    return (p - c) % MOD

VARIANTS = [
    ("Vigenere", vig_key),
    ("Beaufort", beau_key),
    ("VarBeau", vbeau_key),
]

ALPHABETS = [
    ("AZ", ALPH, {c: i for i, c in enumerate(ALPH)}),
    ("KA", KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
]

MAX_PERIOD = 36  # test periods 1-36


def check_periodic_consistency(
    ene_reduced_start: int,
    bc_reduced_start: int,
    period: int,
    key_fn,
    ct_idx: dict,
) -> tuple:
    """Check if cribs are periodically consistent at given reduced positions.

    For period T, all crib positions with the same (reduced_pos % T)
    must yield the same key value.

    Returns (consistent: bool, key_values: dict[residue, key_val] or None).
    """
    residue_keys = {}  # residue -> key value

    # Check ENE crib: positions ene_reduced_start .. ene_reduced_start+12
    for i in range(ENE_LEN):
        orig_pos = ENE_START + i
        reduced_pos = ene_reduced_start + i
        c_num = ct_idx[CT[orig_pos]]
        p_num = ct_idx[ENE_WORD[i]]
        k_val = key_fn(c_num, p_num)
        residue = reduced_pos % period

        if residue in residue_keys:
            if residue_keys[residue] != k_val:
                return False, None
        else:
            residue_keys[residue] = k_val

    # Check BC crib: positions bc_reduced_start .. bc_reduced_start+10
    for i in range(BC_LEN):
        orig_pos = BC_START + i
        reduced_pos = bc_reduced_start + i
        c_num = ct_idx[CT[orig_pos]]
        p_num = ct_idx[BC_WORD[i]]
        k_val = key_fn(c_num, p_num)
        residue = reduced_pos % period

        if residue in residue_keys:
            if residue_keys[residue] != k_val:
                return False, None
        else:
            residue_keys[residue] = k_val

    return True, residue_keys


def main():
    t0 = time.time()
    print("=" * 78)
    print("E-TWO-SYS-01: Periodic consistency proof for Model A (null removal)")
    print("=" * 78)
    print(f"\nCT ({CT_LEN} chars): {CT}")
    print(f"Reduced length: {REDUCED_LEN}")
    print(f"Null zones: A=[0,20] (max {ZONE_A_MAX}), B=[34,62] (max {ZONE_B_MAX}), "
          f"C=[74,96] (max {ZONE_C_MAX})")
    print(f"Periods: 1-{MAX_PERIOD}")
    print(f"Variants: {', '.join(v[0] for v in VARIANTS)}")
    print(f"Alphabets: {', '.join(a[0] for a in ALPHABETS)}")
    print()
    sys.stdout.flush()

    survivors = []
    total_checks = 0

    for a in range(ZONE_A_MAX + 1):  # 0..21
        b_max = min(ZONE_B_MAX, N_NULLS - a)
        for b in range(b_max + 1):
            c = N_NULLS - a - b
            if c < 0 or c > ZONE_C_MAX:
                continue

            # After removing `a` nulls from zone A, ENE starts at 21-a
            # After removing `a+b` nulls from zones A+B, BC starts at 63-a-b
            ene_reduced = ENE_START - a
            bc_reduced = BC_START - a - b

            # Sanity: reduced positions must be non-negative and fit in 73
            if ene_reduced < 0 or bc_reduced < 0:
                continue
            if ene_reduced + ENE_LEN > REDUCED_LEN or bc_reduced + BC_LEN > REDUCED_LEN:
                continue

            for period in range(1, MAX_PERIOD + 1):
                for alph_name, alph_str, alph_idx in ALPHABETS:
                    for var_name, key_fn in VARIANTS:
                        total_checks += 1
                        consistent, key_map = check_periodic_consistency(
                            ene_reduced, bc_reduced, period, key_fn, alph_idx
                        )
                        if consistent:
                            # Count how many residues are constrained
                            n_constrained = len(key_map)
                            n_residues = min(period, REDUCED_LEN)
                            n_free = n_residues - n_constrained

                            survivors.append({
                                "a": a, "b": b, "c": c,
                                "period": period,
                                "variant": var_name,
                                "alphabet": alph_name,
                                "ene_reduced_start": ene_reduced,
                                "bc_reduced_start": bc_reduced,
                                "n_constrained": n_constrained,
                                "n_free": n_free,
                                "key_residues": key_map,
                            })

    elapsed = time.time() - t0

    # ── Results ────────────────────────────────────────────────────────────
    print(f"Total consistency checks: {total_checks:,}")
    print(f"Survivors (periodically consistent): {len(survivors)}")
    print(f"Elapsed: {elapsed:.3f}s")
    print()

    if not survivors:
        print("=" * 78)
        print("PROOF COMPLETE: Model A + periodic substitution is IMPOSSIBLE")
        print("for ALL (a,b) null distributions and ALL periods 1-36.")
        print("No (a,b,T,variant,alphabet) tuple produces crib-consistent keystream.")
        print("=" * 78)
        return

    # Analyze survivors
    # Group by period
    from collections import Counter
    period_counts = Counter(s["period"] for s in survivors)

    print("=" * 78)
    print(f"SURVIVORS BY PERIOD:")
    print("=" * 78)
    for period in sorted(period_counts.keys()):
        count = period_counts[period]
        period_survivors = [s for s in survivors if s["period"] == period]
        # Show underdetermination: how many residues are free?
        avg_free = sum(s["n_free"] for s in period_survivors) / len(period_survivors)
        avg_constrained = sum(s["n_constrained"] for s in period_survivors) / len(period_survivors)
        print(f"  Period {period:2d}: {count:5d} survivors "
              f"(avg {avg_constrained:.1f}/{period} residues constrained, "
              f"{avg_free:.1f} free)")

    # Separate genuinely constrained survivors (all residues constrained)
    fully_constrained = [s for s in survivors if s["n_free"] == 0]
    print(f"\nFully constrained survivors (0 free residues): {len(fully_constrained)}")

    if fully_constrained:
        print("\n  These have a UNIQUE keyword for the constrained residues:")
        for s in fully_constrained[:50]:
            key_str = "".join(
                ALPH[s["key_residues"].get(r, 0)]
                for r in range(s["period"])
            )
            print(f"    a={s['a']:2d} b={s['b']:2d} c={s['c']:2d} | "
                  f"T={s['period']:2d} {s['variant']:8s}/{s['alphabet']} | "
                  f"ENE@{s['ene_reduced_start']} BC@{s['bc_reduced_start']} | "
                  f"key={key_str}")

    # Show low-period survivors (most constraining)
    low_period = [s for s in survivors if s["period"] <= 7]
    print(f"\nLow-period survivors (T <= 7): {len(low_period)}")
    for s in sorted(low_period, key=lambda x: (x["period"], x["a"], x["b"]))[:50]:
        key_parts = []
        for r in range(s["period"]):
            if r in s["key_residues"]:
                key_parts.append(ALPH[s["key_residues"][r]])
            else:
                key_parts.append("?")
        key_str = "".join(key_parts)
        print(f"    a={s['a']:2d} b={s['b']:2d} c={s['c']:2d} | "
              f"T={s['period']:2d} {s['variant']:8s}/{s['alphabet']} | "
              f"ENE@{s['ene_reduced_start']} BC@{s['bc_reduced_start']} | "
              f"key={key_str} ({s['n_constrained']}/{s['period']} constrained)")

    print(f"\n{'=' * 78}")
    print(f"DONE. {total_checks:,} checks, {len(survivors)} survivors, {elapsed:.3f}s")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
