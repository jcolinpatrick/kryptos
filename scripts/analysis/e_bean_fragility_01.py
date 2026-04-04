#!/usr/bin/env python3
"""
Bean Constraint Fragility Analysis
===================================
Test how sensitive the Bean constraints (1 equality + 242 inequalities)
are to single-letter ciphertext errors.

For each of the 97 CT positions, for each of 25 alternative letters:
  - Create mutated CT
  - Recompute keystream at all 24 crib positions under Beaufort (K = (CT+PT) mod 26)
  - Check Bean equality (k[27] == k[65])
  - Count Bean inequality violations
  - Record whether mutation BREAKS or PRESERVES the constraint structure

ID: e_bean_fragility_01
Family: analysis
Status: active
"""

import sys, os
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'src'))

import string
from multiprocessing import Pool, cpu_count
from collections import Counter

from kryptos.kernel.constants import CT, CRIB_POSITIONS, BEAN_EQ, BEAN_INEQ

# Build crib map: position -> plaintext letter
CRIBS = [
    (21, "EASTNORTHEAST"),  # positions 21-33
    (63, "BERLINCLOCK"),    # positions 63-73
]

CRIB_MAP = {}  # pos -> PT letter
for start, word in CRIBS:
    for i, ch in enumerate(word):
        CRIB_MAP[start + i] = ch

CRIB_POS_SET = frozenset(CRIB_MAP.keys())
assert CRIB_POS_SET == CRIB_POSITIONS, f"Crib positions mismatch: {CRIB_POS_SET} vs {CRIB_POSITIONS}"

def char_to_num(c):
    return ord(c) - ord('A')

def compute_keystream_beaufort(ct_str):
    """Compute keystream at crib positions under Beaufort: K = (CT + PT) mod 26."""
    ks = {}
    for pos, pt_char in CRIB_MAP.items():
        ct_val = char_to_num(ct_str[pos])
        pt_val = char_to_num(pt_char)
        ks[pos] = (ct_val + pt_val) % 26
    return ks

def check_bean(ks):
    """Check Bean constraints on sparse keystream dict.
    Returns (eq_pass: bool, ineq_violations: int, ineq_total_checkable: int)
    """
    eq_pass = True
    for a, b in BEAN_EQ:
        if a in ks and b in ks:
            if ks[a] != ks[b]:
                eq_pass = False

    ineq_violations = 0
    ineq_checkable = 0
    for a, b in BEAN_INEQ:
        if a in ks and b in ks:
            ineq_checkable += 1
            if ks[a] == ks[b]:
                ineq_violations += 1

    return eq_pass, ineq_violations, ineq_checkable

# Baseline
baseline_ks = compute_keystream_beaufort(CT)
baseline_eq, baseline_ineq_viol, baseline_ineq_checkable = check_bean(baseline_ks)
print(f"=== BASELINE (original CT) ===")
print(f"  Bean equality (k[27]==k[65]): {'PASS' if baseline_eq else 'FAIL'}")
print(f"  k[27] = {baseline_ks[27]}, k[65] = {baseline_ks[65]}")
print(f"  Bean inequalities: {baseline_ineq_viol} violations out of {baseline_ineq_checkable} checkable")
print()

def test_mutation(args):
    """Test a single CT mutation. Returns result dict."""
    pos, new_char = args
    if CT[pos] == new_char:
        return None  # skip identity

    mutated = CT[:pos] + new_char + CT[pos+1:]
    ks = compute_keystream_beaufort(mutated)
    eq_pass, ineq_viol, ineq_checkable = check_bean(ks)

    return {
        'pos': pos,
        'orig': CT[pos],
        'new': new_char,
        'eq_pass': eq_pass,
        'ineq_violations': ineq_viol,
        'ineq_checkable': ineq_checkable,
        'is_crib_pos': pos in CRIB_POS_SET,
    }

def main():
    # Generate all mutation tasks
    tasks = []
    for pos in range(len(CT)):
        for ch in string.ascii_uppercase:
            if ch != CT[pos]:
                tasks.append((pos, ch))

    print(f"Total mutations to test: {len(tasks)}")
    print(f"  97 positions x 25 alternatives = {97*25}")
    print()

    workers = max(1, cpu_count() - 2)
    print(f"Running with {workers} workers...")

    with Pool(workers) as pool:
        raw_results = pool.map(test_mutation, tasks, chunksize=100)

    results = [r for r in raw_results if r is not None]
    print(f"Results collected: {len(results)}")
    print()

    # === Analysis ===

    # 1. How many mutations break the Bean equality?
    eq_broken = [r for r in results if not r['eq_pass']]
    eq_preserved = [r for r in results if r['eq_pass']]
    print("=" * 70)
    print("1. BEAN EQUALITY (k[27] == k[65])")
    print("=" * 70)
    print(f"  Mutations that BREAK equality:    {len(eq_broken)} / {len(results)}")
    print(f"  Mutations that PRESERVE equality:  {len(eq_preserved)} / {len(results)}")
    print()

    # Which positions break equality?
    eq_break_positions = Counter(r['pos'] for r in eq_broken)
    print("  Positions where ANY mutation breaks equality:")
    for pos in sorted(eq_break_positions.keys()):
        count = eq_break_positions[pos]
        marker = " [CRIB]" if pos in CRIB_POS_SET else ""
        print(f"    pos {pos:2d} ({CT[pos]}): {count}/25 mutations break it{marker}")
    print()

    # 2. Inequality violations distribution
    print("=" * 70)
    print("2. BEAN INEQUALITY VIOLATIONS DISTRIBUTION")
    print("=" * 70)
    viol_counts = Counter(r['ineq_violations'] for r in results)
    print(f"  {'Violations':>12} | {'Count':>8} | {'Pct':>7}")
    print(f"  {'-'*12}-+-{'-'*8}-+-{'-'*7}")
    for v in sorted(viol_counts.keys()):
        pct = 100 * viol_counts[v] / len(results)
        print(f"  {v:12d} | {viol_counts[v]:8d} | {pct:6.2f}%")
    print()

    # 3. Crib vs non-crib position comparison
    print("=" * 70)
    print("3. CRIB vs NON-CRIB POSITION COMPARISON")
    print("=" * 70)
    crib_results = [r for r in results if r['is_crib_pos']]
    noncrib_results = [r for r in results if not r['is_crib_pos']]

    crib_eq_break = sum(1 for r in crib_results if not r['eq_pass'])
    noncrib_eq_break = sum(1 for r in noncrib_results if not r['eq_pass'])
    print(f"  Crib positions ({len(CRIB_POS_SET)} pos, {len(crib_results)} mutations):")
    print(f"    Equality breaks: {crib_eq_break}")
    print(f"    Avg inequality violations: {sum(r['ineq_violations'] for r in crib_results)/max(1,len(crib_results)):.3f}")
    print()
    print(f"  Non-crib positions ({97 - len(CRIB_POS_SET)} pos, {len(noncrib_results)} mutations):")
    print(f"    Equality breaks: {noncrib_eq_break}")
    print(f"    Avg inequality violations: {sum(r['ineq_violations'] for r in noncrib_results)/max(1,len(noncrib_results)):.3f}")
    print()

    # 4. Mutations that satisfy MORE constraints than original
    print("=" * 70)
    print("4. MUTATIONS THAT SATISFY MORE CONSTRAINTS THAN ORIGINAL")
    print("=" * 70)
    # Original has 0 equality failures and baseline_ineq_viol inequality violations
    # A mutation is "better" if it has fewer total constraint failures
    orig_total_failures = (0 if baseline_eq else 1) + baseline_ineq_viol

    better = [r for r in results if
              (0 if r['eq_pass'] else 1) + r['ineq_violations'] < orig_total_failures]
    same = [r for r in results if
            (0 if r['eq_pass'] else 1) + r['ineq_violations'] == orig_total_failures]
    worse = [r for r in results if
             (0 if r['eq_pass'] else 1) + r['ineq_violations'] > orig_total_failures]

    print(f"  Original total failures: {orig_total_failures} (eq: {'PASS' if baseline_eq else 'FAIL'}, ineq violations: {baseline_ineq_viol})")
    print(f"  Mutations BETTER than original: {len(better)}")
    print(f"  Mutations SAME as original:     {len(same)}")
    print(f"  Mutations WORSE than original:   {len(worse)}")
    print()

    if better:
        print("  BETTER mutations (potential CT defect indicators):")
        for r in sorted(better, key=lambda x: (0 if x['eq_pass'] else 1) + x['ineq_violations']):
            total_f = (0 if r['eq_pass'] else 1) + r['ineq_violations']
            print(f"    pos {r['pos']:2d}: {r['orig']}->{r['new']}  eq={'PASS' if r['eq_pass'] else 'FAIL'}  ineq_viol={r['ineq_violations']}  total_failures={total_f}")
    print()

    # 5. Per-position fragility summary
    print("=" * 70)
    print("5. PER-POSITION FRAGILITY SUMMARY")
    print("=" * 70)
    print(f"  {'Pos':>4} {'CT':>3} {'Crib':>5} {'EqBreak':>8} {'AvgIneqViol':>12} {'MaxIneqViol':>12}")
    print(f"  {'-'*4} {'-'*3} {'-'*5} {'-'*8} {'-'*12} {'-'*12}")

    for pos in range(len(CT)):
        pos_results = [r for r in results if r['pos'] == pos]
        if not pos_results:
            continue
        eq_breaks = sum(1 for r in pos_results if not r['eq_pass'])
        avg_ineq = sum(r['ineq_violations'] for r in pos_results) / len(pos_results)
        max_ineq = max(r['ineq_violations'] for r in pos_results)
        is_crib = "YES" if pos in CRIB_POS_SET else ""
        print(f"  {pos:4d} {CT[pos]:>3} {is_crib:>5} {eq_breaks:8d} {avg_ineq:12.2f} {max_ineq:12d}")

    # 6. Bean equality mechanism analysis
    print()
    print("=" * 70)
    print("6. BEAN EQUALITY MECHANISM")
    print("=" * 70)
    print(f"  Equality: k[27] == k[65]")
    print(f"  Under Beaufort: k[i] = (CT[i] + PT[i]) mod 26")
    print(f"  k[27] = (CT[27] + PT[27]) mod 26 = ({CT[27]}={char_to_num(CT[27])} + R={char_to_num('R')}) mod 26 = {baseline_ks[27]}")
    print(f"  k[65] = (CT[65] + PT[65]) mod 26 = ({CT[65]}={char_to_num(CT[65])} + R={char_to_num('R')}) mod 26 = {baseline_ks[65]}")
    print()
    print(f"  The equality holds iff CT[27] == CT[65] (since PT[27]==PT[65]=='R').")
    print(f"  CT[27] = {CT[27]}, CT[65] = {CT[65]} -> {'SAME' if CT[27] == CT[65] else 'DIFFERENT'}")
    print()
    print(f"  Therefore only mutations at pos 27 or 65 can break equality.")
    print(f"  A mutation at pos 27 breaks equality iff new_char != CT[65] = {CT[65]}")
    print(f"  A mutation at pos 65 breaks equality iff new_char != CT[27] = {CT[27]}")
    print()

    # 7. Inequality structure: which position pairs are most constraining?
    print("=" * 70)
    print("7. MOST-VIOLATED INEQUALITY PAIRS")
    print("=" * 70)
    # For mutations that introduce violations, which pairs are violated?
    pair_viol_count = Counter()
    for r in results:
        if r['ineq_violations'] > 0:
            # Recompute to find which pairs
            pos, new_char = r['pos'], r['new']
            mutated = CT[:pos] + new_char + CT[pos+1:]
            ks = compute_keystream_beaufort(mutated)
            for a, b in BEAN_INEQ:
                if a in ks and b in ks:
                    if ks[a] == ks[b]:
                        pair_viol_count[(a, b)] += 1

    print(f"  Top 20 most frequently violated inequality pairs:")
    for (a, b), count in pair_viol_count.most_common(20):
        pt_a = CRIB_MAP.get(a, '?')
        pt_b = CRIB_MAP.get(b, '?')
        print(f"    k[{a}] != k[{b}]  (PT: {pt_a}, {pt_b})  violated in {count} mutations")

if __name__ == '__main__':
    main()
