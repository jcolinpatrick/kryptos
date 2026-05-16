#!/usr/bin/env python3
"""E0b exploration: verify Bean's KRYPTOS-letter CT-proximity signal,
characterize per-variant keystreams, and check whether E0b is a usable
non-crib filter.

Goal (per /goal "exploit any cryptographic signal, no matter how small"):
- Verify E0b is real (replicate Bean's 1/5520)
- Decide if E0b is a global cipher property or a coincidence at cribs
- Identify what cipher classes could produce E0b GLOBALLY

This is scratch / exploratory. No claims emitted to ledger.
"""
import os
import sys
import random
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH,
)

KRYPTOS_SET = set('KRYPTOS')
CRIB_POSITIONS = sorted(CRIB_DICT.keys())


def minor_diff(a, b):
    """Circular distance in [0, 13]."""
    d = abs(ord(a) - ord(b))
    return min(d, 26 - d)


def signed_diff(c, p):
    """Signed CT-PT in [-13, 12]."""
    d = (ord(c) - ord(p)) % 26
    if d > 13:
        d -= 26
    return d


def vig_keystream(ct, pt_at_cribs):
    """Vig keystream: K = CT - PT mod 26."""
    return {pos: (ord(ct[pos]) - ord(pt)) % 26 for pos, pt in pt_at_cribs.items()}


def beau_keystream(ct, pt_at_cribs):
    """Beau keystream: K = CT + PT mod 26."""
    return {pos: (ord(ct[pos]) + ord(pt)) % 26 for pos, pt in pt_at_cribs.items()}


def varbeau_keystream(ct, pt_at_cribs):
    """VarBeau keystream: K = PT - CT mod 26."""
    return {pos: (ord(pt) - ord(ct[pos])) % 26 for pos, pt in pt_at_cribs.items()}


def per_variant_e0b(name, k_at_cribs):
    """Compute |K| distribution at KRYPTOS-set vs non-KRYPTOS-set crib positions
    for a given variant keystream."""
    kset_vals = []
    nonk_vals = []
    for pos in CRIB_POSITIONS:
        pt = CRIB_DICT[pos]
        k = k_at_cribs[pos]
        # signed magnitude
        mag = min(k, 26 - k)
        if pt in KRYPTOS_SET:
            kset_vals.append((pos, pt, CT[pos], k, mag))
        else:
            nonk_vals.append((pos, pt, CT[pos], k, mag))
    return kset_vals, nonk_vals


def print_e0b_table(name, kset, nonk):
    print(f"\n=== {name} keystream ===")
    print(f"  KRYPTOS-set PT positions ({len(kset)}):")
    print(f"    {'pos':>4} {'PT':>3} {'CT':>3} {'K':>4} {'|K|':>4}")
    for pos, pt, ct, k, mag in kset:
        print(f"    {pos:>4} {pt:>3} {ct:>3} {k:>4} {mag:>4}")
    if kset:
        mean_k = sum(m for _, _, _, _, m in kset) / len(kset)
        print(f"  Mean |K| at K-set: {mean_k:.2f}")

    print(f"  Non-KRYPTOS-set PT positions ({len(nonk)}):")
    print(f"    {'pos':>4} {'PT':>3} {'CT':>3} {'K':>4} {'|K|':>4}")
    for pos, pt, ct, k, mag in nonk:
        print(f"    {pos:>4} {pt:>3} {ct:>3} {k:>4} {mag:>4}")
    if nonk:
        mean_n = sum(m for _, _, _, _, m in nonk) / len(nonk)
        print(f"  Mean |K| at non-K-set: {mean_n:.2f}")

    ratio = (sum(m for _, _, _, _, m in nonk) / max(len(nonk), 1)) / \
            max(sum(m for _, _, _, _, m in kset) / max(len(kset), 1), 0.0001)
    print(f"  Ratio (non-K mean / K mean): {ratio:.2f}x")


def materna_stat(ct_text):
    """Sum of minor diffs for KRYPTOS-set PT positions."""
    total = 0
    for pos in CRIB_POSITIONS:
        pt = CRIB_DICT[pos]
        if pt in KRYPTOS_SET:
            total += minor_diff(pt, ct_text[pos])
    return total


def materna_p_value(n_trials=1_000_000, seed=42):
    """Quick MC p-value for Materna statistic."""
    rng = random.Random(seed)
    observed = materna_stat(CT)
    ct_list = list(CT)
    count = 0
    for _ in range(n_trials):
        rng.shuffle(ct_list)
        if materna_stat(''.join(ct_list)) <= observed:
            count += 1
    p = (count + 1) / (n_trials + 1)
    return observed, count, n_trials, p


def main():
    print("=" * 72)
    print("E0b EXPLORATION — KRYPTOS-set PT proximity")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"Crib positions: {CRIB_POSITIONS}")
    print(f"KRYPTOS-set: {sorted(KRYPTOS_SET)}")

    # PART 1: Verify E0b for all 3 variants
    pt_at_cribs = {pos: CRIB_DICT[pos] for pos in CRIB_POSITIONS}

    for name, fn in [
        ('Vigenere', vig_keystream),
        ('Beaufort', beau_keystream),
        ('Variant Beaufort', varbeau_keystream),
    ]:
        k = fn(CT, pt_at_cribs)
        kset, nonk = per_variant_e0b(name, k)
        print_e0b_table(name, kset, nonk)

    # PART 2: Materna p-value
    print("\n" + "=" * 72)
    print("MATERNA STATISTIC (Vigenere convention, |K| sum)")
    print("=" * 72)
    obs, cnt, n, p = materna_p_value(n_trials=1_000_000)
    print(f"  Observed sum of |K| at K-set crib positions: {obs}")
    print(f"  MC trials (CT shuffle): {n:,}")
    print(f"  Count of shuffles with sum ≤ {obs}: {cnt:,}")
    print(f"  p (raw) = {p:.2e}")
    print(f"  1/p = {1/p:,.0f}")
    print(f"  Bean reported: 1 in 5,520")

    # PART 3: Non-crib KRYPTOS-set positions in CT
    print("\n" + "=" * 72)
    print("NON-CRIB POSITIONS — E0b extrapolation feasibility")
    print("=" * 72)

    # Letters within minor_diff 2 of each KRYPTOS-set letter
    forbidden_for_kset_pt = set()
    allowed_for_kset_pt = set()
    for ct_letter in ALPH:
        # Can this CT letter be the encoding of a KRYPTOS-set PT under |K|<=2?
        has_kset_within_2 = any(
            minor_diff(ct_letter, k_letter) <= 2
            for k_letter in 'KRYPTOS'
        )
        if has_kset_within_2:
            allowed_for_kset_pt.add(ct_letter)
        else:
            forbidden_for_kset_pt.add(ct_letter)

    print(f"  Letters within minor_diff <= 2 of any KRYPTOS-set letter:")
    print(f"    Allowed CT letters ({len(allowed_for_kset_pt)}): {sorted(allowed_for_kset_pt)}")
    print(f"    Forbidden CT letters ({len(forbidden_for_kset_pt)}): {sorted(forbidden_for_kset_pt)}")

    # Count non-crib positions whose CT is in forbidden set
    non_crib_positions = [i for i in range(CT_LEN) if i not in set(CRIB_POSITIONS)]
    n_constrained = 0
    constrained_positions = []
    for i in non_crib_positions:
        if CT[i] in forbidden_for_kset_pt:
            n_constrained += 1
            constrained_positions.append((i, CT[i]))

    print(f"\n  Non-crib positions ({len(non_crib_positions)}): cannot have KRYPTOS-set PT under E0b global:")
    print(f"    Count: {n_constrained}")
    print(f"    Positions: {[p for p, _ in constrained_positions]}")
    if constrained_positions:
        ct_dist = Counter(c for _, c in constrained_positions)
        print(f"    CT letter distribution: {dict(ct_dist)}")

    # PART 4: Per-position K-set candidate PT letters
    print("\n" + "=" * 72)
    print("PER-POSITION KRYPTOS-SET PT CANDIDATES (|K|<=2)")
    print("=" * 72)
    print(f"  {'pos':>4} {'CT':>3} {'candidates':>30}")
    for i in non_crib_positions[:20]:  # first 20
        candidates = sorted(
            c for c in 'KRYPTOS'
            if minor_diff(c, CT[i]) <= 2
        )
        print(f"  {i:>4} {CT[i]:>3} {','.join(candidates) if candidates else '(none)':>30}")
    print(f"  ... ({len(non_crib_positions)-20} more positions omitted)")


if __name__ == '__main__':
    main()
