#!/usr/bin/env python3
"""
# ── Metadata ──────────────────────────────────────────────────────────────
# Cipher:     Constraint-satisfaction null mask search
# Family:     grille
# Status:     active
# Keyspace:   36 (a1,a2) configs × 19 widths × 19 periods × 3 variants = 39,096
# Last run:   2026-03-24
# Best score: TBD
# ──────────────────────────────────────────────────────────────────────────
#
# APPROACH: Instead of "guess cipher, test against CT," we ask:
# "Which null masks make a periodic cipher POSSIBLE?"
#
# We know the keystream at 24 crib positions. If the real CT (after null
# removal) was columnar-transposed and then encrypted with a periodic key
# of period P, then crib positions mapping to the same residue class
# (mod P in pre-transposition space) must have identical keystream values.
#
# The (a1, a2) collapse: compressed crib positions depend only on how many
# additional nulls fall in each segment between crib blocks, NOT on which
# specific positions are nulled. Only 36 valid (a1, a2, a3) triples exist
# for 7 additional nulls across 3 segments.
#
# Prior art: e_constrained_mask_search.py proved periodic-only (no
# transposition) is dead for ALL masks at periods 1-23. This script
# adds the TRANSPOSITION dimension, which fundamentally changes which
# crib positions share residue classes.
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

from __future__ import annotations

import sys
import os
import time
import json
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)

# ═══════════════════════════════════════════════════════════════════════════
# KEYSTREAM VALUES AT CRIB POSITIONS (variant-indexed)
# ═══════════════════════════════════════════════════════════════════════════

# Build keystream lookup: orig_position → keystream_value for each variant
KEYSTREAM = {
    'vig': {},
    'beau': {},
    'varbeau': {},
}

for i, pos in enumerate(range(21, 34)):  # ENE crib
    KEYSTREAM['vig'][pos] = VIGENERE_KEY_ENE[i]
    KEYSTREAM['beau'][pos] = BEAUFORT_KEY_ENE[i]
    # Variant Beaufort: K = (PT - CT) mod 26
    pt_idx = ALPH_IDX[CRIB_DICT[pos]]
    ct_idx = ALPH_IDX[CT[pos]]
    KEYSTREAM['varbeau'][pos] = (pt_idx - ct_idx) % 26

for i, pos in enumerate(range(63, 74)):  # BC crib
    KEYSTREAM['vig'][pos] = VIGENERE_KEY_BC[i]
    KEYSTREAM['beau'][pos] = BEAUFORT_KEY_BC[i]
    pt_idx = ALPH_IDX[CRIB_DICT[pos]]
    ct_idx = ALPH_IDX[CT[pos]]
    KEYSTREAM['varbeau'][pos] = (pt_idx - ct_idx) % 26


# ═══════════════════════════════════════════════════════════════════════════
# SEGMENT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

# The 97 positions split into segments by crib blocks:
#   Segment 1: positions 0-20  (21 positions, pre-ENE)
#   Crib ENE:  positions 21-33 (13 positions, FIXED — never null)
#   Segment 2: positions 34-62 (29 positions, between cribs)
#   Crib BC:   positions 63-73 (11 positions, FIXED — never null)
#   Segment 3: positions 74-96 (23 positions, post-BC)

# Count consensus nulls in each segment
SEG1_NULLS = len([p for p in CONSENSUS_NULL_POSITIONS if p < 21])       # positions 0-20
SEG2_NULLS = len([p for p in CONSENSUS_NULL_POSITIONS if 34 <= p <= 62]) # positions 34-62
SEG3_NULLS = len([p for p in CONSENSUS_NULL_POSITIONS if p >= 74])       # positions 74-96

# Available non-null, non-crib positions in each segment for additional nulls
SEG1_AVAIL = 21 - SEG1_NULLS   # positions in seg1 not already null
SEG2_AVAIL = 29 - SEG2_NULLS   # positions in seg2 not already null
SEG3_AVAIL = 23 - SEG3_NULLS   # positions in seg3 not already null

TOTAL_CONSENSUS = len(CONSENSUS_NULL_POSITIONS)  # 17
ADDITIONAL_NEEDED = 24 - TOTAL_CONSENSUS          # 7


# ═══════════════════════════════════════════════════════════════════════════
# COLUMNAR TRANSPOSITION
# ═══════════════════════════════════════════════════════════════════════════

def columnar_perm_identity(length, width):
    """Generate the columnar transposition permutation for identity column order.

    Text is written into rows of `width`, then read column by column.
    Returns perm where output[i] = input[perm[i]] (gather convention).
    """
    n_full_rows = length // width
    remainder = length % width

    perm = []
    for col in range(width):
        col_length = n_full_rows + (1 if col < remainder else 0)
        for row in range(col_length):
            perm.append(row * width + col)

    return perm


def invert_perm(perm):
    """Invert a permutation: if perm[i] = j, then inv[j] = i."""
    inv = [0] * len(perm)
    for i, j in enumerate(perm):
        inv[j] = i
    return inv


# ═══════════════════════════════════════════════════════════════════════════
# CONSISTENCY CHECK
# ═══════════════════════════════════════════════════════════════════════════

def check_consistency(
    ene_start: int,
    bc_start: int,
    inv_perm: list[int],
    period: int,
    variant: str,
    ct_len_extracted: int = 73,
) -> tuple[bool, int, dict]:
    """Check if crib keystream values are consistent with a periodic key
    after applying inverse columnar transposition.

    Returns (is_consistent, n_determined_residues, residue_to_key).
    """
    residue_to_key: dict[int, int] = {}

    # ENE crib: 13 positions starting at ene_start in compressed text
    for i in range(13):
        compressed_pos = ene_start + i
        if compressed_pos >= ct_len_extracted:
            return False, 0, {}

        # Apply inverse transposition to get pre-transposition position
        pre_trans_pos = inv_perm[compressed_pos]
        residue = pre_trans_pos % period
        key_val = KEYSTREAM[variant][21 + i]

        if residue in residue_to_key:
            if residue_to_key[residue] != key_val:
                return False, 0, {}
        else:
            residue_to_key[residue] = key_val

    # BC crib: 11 positions starting at bc_start in compressed text
    for j in range(11):
        compressed_pos = bc_start + j
        if compressed_pos >= ct_len_extracted:
            return False, 0, {}

        pre_trans_pos = inv_perm[compressed_pos]
        residue = pre_trans_pos % period
        key_val = KEYSTREAM[variant][63 + j]

        if residue in residue_to_key:
            if residue_to_key[residue] != key_val:
                return False, 0, {}
        else:
            residue_to_key[residue] = key_val

    return True, len(residue_to_key), residue_to_key


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("CONSTRAINT-SATISFACTION NULL MASK SEARCH")
    print("Which (mask, transposition, period, variant) tuples are crib-consistent?")
    print("=" * 78)
    print()

    # Segment info
    print(f"Consensus nulls: {TOTAL_CONSENSUS} (need {ADDITIONAL_NEEDED} more for 24 total)")
    print(f"Segment 1 (pos 0-20):  {SEG1_NULLS} consensus nulls, {SEG1_AVAIL} available")
    print(f"Segment 2 (pos 34-62): {SEG2_NULLS} consensus nulls, {SEG2_AVAIL} available")
    print(f"Segment 3 (pos 74-96): {SEG3_NULLS} consensus nulls, {SEG3_AVAIL} available")
    print()

    # Also test with NO transposition (width=1 equivalent = identity permutation)
    WIDTHS = list(range(2, 21)) + [0]  # 0 = no transposition (identity)
    PERIODS = list(range(2, 37))  # test up to period 36
    VARIANTS = ['vig', 'beau', 'varbeau']
    CT_LEN_EXTRACTED = 73

    # Enumerate valid (a1, a2, a3) triples
    configs = []
    for a1 in range(min(ADDITIONAL_NEEDED, SEG1_AVAIL) + 1):
        for a2 in range(min(ADDITIONAL_NEEDED - a1, SEG2_AVAIL) + 1):
            a3 = ADDITIONAL_NEEDED - a1 - a2
            if 0 <= a3 <= SEG3_AVAIL:
                configs.append((a1, a2, a3))

    print(f"Valid (a1, a2, a3) configurations: {len(configs)}")
    print(f"Widths: {len(WIDTHS)} (2-20 + identity)")
    print(f"Periods: {len(PERIODS)} (2-36)")
    print(f"Variants: {len(VARIANTS)}")
    total_checks = len(configs) * len(WIDTHS) * len(PERIODS) * len(VARIANTS)
    print(f"Total checks: {total_checks:,}")
    print()

    # Precompute transposition inverse permutations
    inv_perms = {}
    for w in WIDTHS:
        if w == 0:
            inv_perms[0] = list(range(CT_LEN_EXTRACTED))  # identity
        else:
            perm = columnar_perm_identity(CT_LEN_EXTRACTED, w)
            inv_perms[w] = invert_perm(perm)

    # ── Sweep ──
    t0 = time.time()
    survivors = []
    checks_done = 0

    for a1, a2, a3 in configs:
        # Compressed crib positions
        # ENE starts at: 21 - (consensus_nulls_before_21 + a1)
        nulls_before_ene = SEG1_NULLS + a1
        ene_start = 21 - nulls_before_ene

        # BC starts at: 63 - (total_nulls_before_63)
        # nulls before 63 = seg1_nulls + a1 + seg2_nulls + a2
        nulls_before_bc = SEG1_NULLS + a1 + SEG2_NULLS + a2
        bc_start = 63 - nulls_before_bc

        for w in WIDTHS:
            inv_perm = inv_perms[w]

            for period in PERIODS:
                for variant in VARIANTS:
                    consistent, n_determined, key_map = check_consistency(
                        ene_start, bc_start, inv_perm, period, variant,
                        CT_LEN_EXTRACTED,
                    )
                    checks_done += 1

                    if consistent:
                        # Compute determination ratio
                        determination = n_determined / period

                        survivors.append({
                            'a1': a1, 'a2': a2, 'a3': a3,
                            'width': w if w > 0 else 'none',
                            'period': period,
                            'variant': variant,
                            'determined': n_determined,
                            'determination_ratio': round(determination, 3),
                            'key_map': {str(k): v for k, v in sorted(key_map.items())},
                            'ene_start': ene_start,
                            'bc_start': bc_start,
                        })

    elapsed = time.time() - t0

    print(f"Checks completed: {checks_done:,} in {elapsed:.2f}s")
    print(f"Total survivors: {len(survivors)}")
    print()

    # ── Analyze survivors ──

    # Group by determination ratio
    by_det = defaultdict(list)
    for s in survivors:
        by_det[s['determination_ratio']].append(s)

    # High-determination survivors are the interesting ones
    print("=" * 78)
    print("SURVIVORS BY DETERMINATION RATIO")
    print("(higher = more constrained = more meaningful)")
    print("=" * 78)

    for det_ratio in sorted(by_det.keys(), reverse=True):
        group = by_det[det_ratio]
        if det_ratio < 0.5:
            print(f"\n  det={det_ratio:.3f}: {len(group)} survivors (underdetermined, skipping detail)")
            continue

        print(f"\n  det={det_ratio:.3f}: {len(group)} survivors")
        # Show details for high-determination hits
        for s in sorted(group, key=lambda x: (x['period'], str(x['width'])))[:30]:
            w_str = f"w={s['width']}" if s['width'] != 'none' else "no_trans"
            print(f"    ({s['a1']},{s['a2']},{s['a3']}) {w_str} P={s['period']} "
                  f"{s['variant']} det={s['determined']}/{s['period']} "
                  f"key={list(s['key_map'].values())}")

    # ── Focus on discriminating periods ──
    print()
    print("=" * 78)
    print("SURVIVORS AT DISCRIMINATING PERIODS (P <= 10)")
    print("=" * 78)

    discriminating = [s for s in survivors if s['period'] <= 10]
    if discriminating:
        for s in sorted(discriminating, key=lambda x: (x['period'], -x['determination_ratio'])):
            w_str = f"w={s['width']}" if s['width'] != 'none' else "no_trans"
            print(f"  ({s['a1']},{s['a2']},{s['a3']}) {w_str} P={s['period']} "
                  f"{s['variant']} det={s['determined']}/{s['period']} "
                  f"ratio={s['determination_ratio']:.3f}")
    else:
        print("  NONE — all discriminating periods eliminated!")

    # ── Survivors with transposition vs without ──
    print()
    with_trans = [s for s in survivors if s['width'] != 'none']
    without_trans = [s for s in survivors if s['width'] == 'none']
    print(f"Survivors WITH transposition: {len(with_trans)}")
    print(f"Survivors WITHOUT transposition: {len(without_trans)}")

    # Transposition-only survivors (not present without transposition)
    trans_only_periods = set()
    no_trans_periods = set((s['period'], s['variant']) for s in without_trans)
    for s in with_trans:
        key = (s['period'], s['variant'])
        if key not in no_trans_periods:
            trans_only_periods.add(key)

    if trans_only_periods:
        print(f"\nPeriod/variant combos ONLY possible with transposition:")
        for p, v in sorted(trans_only_periods):
            matching = [s for s in with_trans if s['period'] == p and s['variant'] == v]
            print(f"  P={p} {v}: {len(matching)} configs")
            for s in matching[:5]:
                print(f"    ({s['a1']},{s['a2']},{s['a3']}) w={s['width']} "
                      f"det={s['determined']}/{s['period']}")

    # ── Save results ──
    result_path = os.path.join(_ROOT, "results", "null_mask_csp_01.json")
    os.makedirs(os.path.dirname(result_path), exist_ok=True)
    result_data = {
        'experiment': 'e_null_mask_csp_01',
        'approach': 'Constraint-satisfaction: which (mask, transposition, period) are crib-consistent',
        'configs_a1a2a3': len(configs),
        'widths_tested': len(WIDTHS),
        'periods_tested': len(PERIODS),
        'variants_tested': len(VARIANTS),
        'total_checks': checks_done,
        'elapsed_s': round(elapsed, 2),
        'total_survivors': len(survivors),
        'discriminating_survivors': len(discriminating),
        'survivors_with_transposition': len(with_trans),
        'survivors_without_transposition': len(without_trans),
        'trans_only_period_variants': sorted(list(trans_only_periods)),
        'top_survivors': sorted(survivors, key=lambda x: -x['determination_ratio'])[:50],
    }
    with open(result_path, 'w') as f:
        json.dump(result_data, f, indent=2)
    print(f"\nResults saved to {result_path}")

    # ── Verdict ──
    print()
    if discriminating:
        print(f"*** SIGNAL: {len(discriminating)} survivors at discriminating periods — INVESTIGATE ***")
    elif trans_only_periods:
        print(f"INTERESTING: {len(trans_only_periods)} period/variant combos only possible "
              f"with transposition — worth investigating")
    else:
        print("NOISE: No new constraints beyond known periodic elimination. "
              "The transposition + periodic model adds no new survivors at "
              "discriminating periods.")

    return len(discriminating)


if __name__ == "__main__":
    main()
