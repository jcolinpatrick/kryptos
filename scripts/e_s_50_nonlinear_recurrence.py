#!/usr/bin/env python3
"""
E-S-50: Non-Linear Recurrence Keystream Search

MOTIVATION: Sessions 4-10 eliminated LINEAR recurrences of orders 1-8.
But non-linear recurrences (multiplicative, quadratic, power) were never tested.
These are compatible with the K5 position-dependent constraint (keystream is
a fixed sequence independent of plaintext).

Tests (all mod 26, both Vigenère and Beaufort sign conventions):

FAMILY A — Order 2, non-linear:
  A1: k[n] = k[n-1] * k[n-2] mod 26
  A2: k[n] = k[n-1]² + k[n-2] mod 26
  A3: k[n] = k[n-1]² + k[n-1]*k[n-2] mod 26
  A4: k[n] = (k[n-1] + k[n-2])² mod 26
  A5: k[n] = k[n-1]*k[n-2] + c mod 26 (c in 0-25)

FAMILY B — Order 1, non-linear:
  B1: k[n] = k[n-1]² mod 26
  B2: k[n] = k[n-1]² + c mod 26 (c in 0-25)
  B3: k[n] = a*k[n-1]² + b mod 26 (a,b in 0-25)

FAMILY C — Order 3, non-linear:
  C1: k[n] = k[n-1]*k[n-2] + k[n-3] mod 26
  C2: k[n] = k[n-1]*k[n-2]*k[n-3] mod 26
  C3: k[n] = k[n-1]² + k[n-2] + k[n-3] mod 26

FAMILY D — Famous sequences:
  D1: Fibonacci mod 26 (with offset + scale)
  D2: Tribonacci mod 26 (with offset + scale)
  D3: Padovan mod 26
  D4: Catalan mod 26 (precomputed)
  D5: Digit sequences (pi, e, sqrt2, phi) mod 26

FAMILY E — Parametric order 2:
  E1: k[n] = a*k[n-1]² + b*k[n-2] mod 26 (a,b in 0-25, k0,k1 in 0-25)
      Space: 26^4 = 456,976 — exhaustive

For each candidate: compute sequence through position 73 minimum, check all 24
crib-derived key values. Report any candidate with ≥ 10/24 matches.

Output: results/e_s_50_nonlinear_recurrence.json
"""

import json
import sys
import os
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX

N = CT_LEN
CT_IDX = [ALPH_IDX[c] for c in CT]

# Known keystream values (Vigenère: k = (CT - PT) mod 26)
VIG_KEY = {}
BEAU_KEY = {}
for pos, pt_char in sorted(CRIB_DICT.items()):
    ct_val = CT_IDX[pos]
    pt_val = ALPH_IDX[pt_char]
    VIG_KEY[pos] = (ct_val - pt_val) % 26
    BEAU_KEY[pos] = (ct_val + pt_val) % 26  # Beaufort: k = (CT + PT) mod 26...
    # Actually Beaufort: CT = (K - PT) mod 26 → K = (CT + PT) mod 26
    BEAU_KEY[pos] = (ct_val + pt_val) % 26

CRIB_POSITIONS = sorted(CRIB_DICT.keys())
MAX_POS = max(CRIB_POSITIONS)  # 73

print(f"Crib positions: {CRIB_POSITIONS}")
print(f"Max position needed: {MAX_POS}")
print(f"Vig key at cribs: {[VIG_KEY[p] for p in CRIB_POSITIONS]}")
print(f"Beau key at cribs: {[BEAU_KEY[p] for p in CRIB_POSITIONS]}")
print()


def check_sequence(seq, target_key):
    """Check how many crib positions match."""
    matches = 0
    for pos in CRIB_POSITIONS:
        if pos < len(seq) and seq[pos] == target_key[pos]:
            matches += 1
    return matches


def generate_sequence(recurrence_fn, initial_values, length):
    """Generate sequence using given recurrence function and initial values."""
    seq = list(initial_values)
    try:
        for n in range(len(initial_values), length):
            val = recurrence_fn(seq, n) % 26
            seq.append(val)
    except (ZeroDivisionError, ValueError, OverflowError):
        # Some recurrences may fail; pad with -1
        while len(seq) < length:
            seq.append(-1)
    return seq


def run_family(name, desc, generator, total_configs):
    """Run a family of recurrence tests."""
    print(f"\n{'='*60}")
    print(f"Family {name}: {desc}")
    print(f"  Configs: {total_configs:,}")
    print(f"{'='*60}")

    t0 = time.time()
    best_vig = (0, None, None)
    best_beau = (0, None, None)
    n_tested = 0
    hits = []  # configs with >= 10 matches

    for config_label, seq in generator():
        n_tested += 1

        vig_matches = check_sequence(seq, VIG_KEY)
        beau_matches = check_sequence(seq, BEAU_KEY)

        if vig_matches > best_vig[0]:
            best_vig = (vig_matches, config_label, seq[:MAX_POS+1])
        if beau_matches > best_beau[0]:
            best_beau = (beau_matches, config_label, seq[:MAX_POS+1])

        if vig_matches >= 10 or beau_matches >= 10:
            hits.append({
                'config': config_label,
                'vig_matches': vig_matches,
                'beau_matches': beau_matches,
                'seq_prefix': seq[:10],
            })

        if n_tested % 100000 == 0:
            elapsed = time.time() - t0
            print(f"  Tested {n_tested:,}/{total_configs:,} "
                  f"best_vig={best_vig[0]} best_beau={best_beau[0]} "
                  f"[{elapsed:.1f}s]", flush=True)

    elapsed = time.time() - t0
    print(f"  Done: {n_tested:,} configs in {elapsed:.1f}s")
    print(f"  Best Vig: {best_vig[0]}/24 — {best_vig[1]}")
    print(f"  Best Beau: {best_beau[0]}/24 — {best_beau[1]}")
    if hits:
        print(f"  HITS (≥10): {len(hits)}")
        for h in hits[:5]:
            print(f"    {h['config']}: vig={h['vig_matches']} beau={h['beau_matches']}")

    return {
        'family': name,
        'description': desc,
        'configs_tested': n_tested,
        'best_vig': best_vig[0],
        'best_vig_config': best_vig[1],
        'best_beau': best_beau[0],
        'best_beau_config': best_beau[1],
        'hits': hits,
        'time': round(elapsed, 2),
    }


def family_a1():
    """k[n] = k[n-1] * k[n-2] mod 26"""
    for k0 in range(26):
        for k1 in range(26):
            seq = [k0, k1]
            for n in range(2, MAX_POS + 1):
                seq.append((seq[n-1] * seq[n-2]) % 26)
            yield f"A1(k0={k0},k1={k1})", seq


def family_a2():
    """k[n] = k[n-1]² + k[n-2] mod 26"""
    for k0 in range(26):
        for k1 in range(26):
            seq = [k0, k1]
            for n in range(2, MAX_POS + 1):
                seq.append((seq[n-1]**2 + seq[n-2]) % 26)
            yield f"A2(k0={k0},k1={k1})", seq


def family_a3():
    """k[n] = k[n-1]² + k[n-1]*k[n-2] mod 26"""
    for k0 in range(26):
        for k1 in range(26):
            seq = [k0, k1]
            for n in range(2, MAX_POS + 1):
                seq.append((seq[n-1]**2 + seq[n-1]*seq[n-2]) % 26)
            yield f"A3(k0={k0},k1={k1})", seq


def family_a4():
    """k[n] = (k[n-1] + k[n-2])² mod 26"""
    for k0 in range(26):
        for k1 in range(26):
            seq = [k0, k1]
            for n in range(2, MAX_POS + 1):
                seq.append(((seq[n-1] + seq[n-2])**2) % 26)
            yield f"A4(k0={k0},k1={k1})", seq


def family_a5():
    """k[n] = k[n-1]*k[n-2] + c mod 26"""
    for c in range(26):
        for k0 in range(26):
            for k1 in range(26):
                seq = [k0, k1]
                for n in range(2, MAX_POS + 1):
                    seq.append((seq[n-1]*seq[n-2] + c) % 26)
                yield f"A5(c={c},k0={k0},k1={k1})", seq


def family_b():
    """Order-1 non-linear: k[n] = a*k[n-1]² + b mod 26"""
    for a in range(26):
        for b in range(26):
            for k0 in range(26):
                seq = [k0]
                for n in range(1, MAX_POS + 1):
                    seq.append((a * seq[n-1]**2 + b) % 26)
                yield f"B(a={a},b={b},k0={k0})", seq


def family_c():
    """Order-3 non-linear variants"""
    # C1: k[n] = k[n-1]*k[n-2] + k[n-3] mod 26
    for k0 in range(26):
        for k1 in range(26):
            for k2 in range(26):
                seq = [k0, k1, k2]
                for n in range(3, MAX_POS + 1):
                    seq.append((seq[n-1]*seq[n-2] + seq[n-3]) % 26)
                yield f"C1(k0={k0},k1={k1},k2={k2})", seq

    # C2: k[n] = k[n-1]*k[n-2]*k[n-3] mod 26
    for k0 in range(26):
        for k1 in range(26):
            for k2 in range(26):
                seq = [k0, k1, k2]
                for n in range(3, MAX_POS + 1):
                    seq.append((seq[n-1]*seq[n-2]*seq[n-3]) % 26)
                yield f"C2(k0={k0},k1={k1},k2={k2})", seq


def family_d():
    """Famous mathematical sequences mod 26 (with scale + offset)"""
    # D1: Fibonacci with scale a and offset b
    for a in range(1, 26):
        for b in range(26):
            fib = [0, 1]
            for n in range(2, MAX_POS + 1):
                fib.append(fib[n-1] + fib[n-2])
            seq = [(a * fib[n] + b) % 26 for n in range(MAX_POS + 1)]
            yield f"D1_fib(a={a},b={b})", seq

    # D2: Tribonacci with scale + offset
    for a in range(1, 26):
        for b in range(26):
            tri = [0, 0, 1]
            for n in range(3, MAX_POS + 1):
                tri.append(tri[n-1] + tri[n-2] + tri[n-3])
            seq = [(a * tri[n] + b) % 26 for n in range(MAX_POS + 1)]
            yield f"D2_tri(a={a},b={b})", seq

    # D3: Padovan sequence
    for a in range(1, 26):
        for b in range(26):
            pad = [1, 1, 1]
            for n in range(3, MAX_POS + 1):
                pad.append(pad[n-2] + pad[n-3])
            seq = [(a * pad[n] + b) % 26 for n in range(MAX_POS + 1)]
            yield f"D3_pad(a={a},b={b})", seq

    # D4: Powers of integers mod 26
    for base in range(2, 26):
        for offset in range(26):
            seq = [(pow(base, n, 26*1000) + offset) % 26 for n in range(MAX_POS + 1)]
            yield f"D4_pow(base={base},off={offset})", seq

    # D5: Pi digits mod 26
    pi_digits = "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679"
    if len(pi_digits) >= MAX_POS + 1:
        for offset in range(26):
            seq = [(int(pi_digits[n]) + offset) % 26 for n in range(MAX_POS + 1)]
            yield f"D5_pi(off={offset})", seq

    # D6: e digits mod 26
    e_digits = "27182818284590452353602874713526624977572470936999595749669676277240766303535475945713821785251664274"
    if len(e_digits) >= MAX_POS + 1:
        for offset in range(26):
            seq = [(int(e_digits[n]) + offset) % 26 for n in range(MAX_POS + 1)]
            yield f"D6_e(off={offset})", seq


def family_e():
    """Parametric order-2: k[n] = a*k[n-1]² + b*k[n-2] mod 26"""
    for a in range(26):
        for b in range(26):
            for k0 in range(26):
                for k1 in range(26):
                    seq = [k0, k1]
                    for n in range(2, MAX_POS + 1):
                        seq.append((a * seq[n-1]**2 + b * seq[n-2]) % 26)
                    yield f"E1(a={a},b={b},k0={k0},k1={k1})", seq


def main():
    print("=" * 70)
    print("E-S-50: Non-Linear Recurrence Keystream Search")
    print("=" * 70)

    t0_global = time.time()
    all_results = {'experiment': 'E-S-50', 'families': []}

    # Family A: Order-2 non-linear (4 forms × 676 + 1 form × 17576)
    r = run_family("A1", "k[n]=k[n-1]*k[n-2]", family_a1, 676)
    all_results['families'].append(r)

    r = run_family("A2", "k[n]=k[n-1]²+k[n-2]", family_a2, 676)
    all_results['families'].append(r)

    r = run_family("A3", "k[n]=k[n-1]²+k[n-1]*k[n-2]", family_a3, 676)
    all_results['families'].append(r)

    r = run_family("A4", "k[n]=(k[n-1]+k[n-2])²", family_a4, 676)
    all_results['families'].append(r)

    r = run_family("A5", "k[n]=k[n-1]*k[n-2]+c", family_a5, 17576)
    all_results['families'].append(r)

    # Family B: Order-1 non-linear
    r = run_family("B", "k[n]=a*k[n-1]²+b", family_b, 17576)
    all_results['families'].append(r)

    # Family C: Order-3 non-linear (2 forms × 17576)
    r = run_family("C", "Order-3 non-linear (C1+C2)", family_c, 35152)
    all_results['families'].append(r)

    # Family D: Famous sequences
    d_count = 25*26*3 + 24*26 + 26*2  # fib+tri+pad + powers + pi+e
    r = run_family("D", "Famous sequences (Fibonacci, Tribonacci, etc.)", family_d, d_count)
    all_results['families'].append(r)

    # Family E: Parametric order-2 (exhaustive 26^4)
    r = run_family("E1", "k[n]=a*k[n-1]²+b*k[n-2] (exhaustive)", family_e, 456976)
    all_results['families'].append(r)

    elapsed = time.time() - t0_global

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")

    max_vig = 0
    max_beau = 0
    total_configs = 0
    total_hits = 0

    for r in all_results['families']:
        print(f"  {r['family']:6s}: best_vig={r['best_vig']}/24 best_beau={r['best_beau']}/24 "
              f"hits={len(r['hits'])} ({r['configs_tested']:,} configs, {r['time']:.1f}s)")
        max_vig = max(max_vig, r['best_vig'])
        max_beau = max(max_beau, r['best_beau'])
        total_configs += r['configs_tested']
        total_hits += len(r['hits'])

    # Expected random: 24 positions, each with 1/26 chance → expected 24/26 ≈ 0.92
    print(f"\n  Overall: max_vig={max_vig}/24 max_beau={max_beau}/24")
    print(f"  Total configs: {total_configs:,}")
    print(f"  Total hits (≥10): {total_hits}")
    print(f"  Expected random: ~0.9/24")

    if max_vig >= 10 or max_beau >= 10:
        verdict = "INVESTIGATE — signal above noise"
    elif max_vig >= 5 or max_beau >= 5:
        verdict = "MARGINAL — slightly above random but likely noise"
    else:
        verdict = "ELIMINATED — non-linear recurrences produce noise"

    all_results['verdict'] = verdict
    all_results['max_vig'] = max_vig
    all_results['max_beau'] = max_beau
    all_results['total_configs'] = total_configs
    all_results['elapsed_seconds'] = round(elapsed, 1)

    print(f"  Verdict: {verdict}")
    print(f"  Total time: {elapsed:.1f}s")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_50_nonlinear_recurrence.json", "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"  Artifact: results/e_s_50_nonlinear_recurrence.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_50_nonlinear_recurrence.py")


if __name__ == "__main__":
    main()
