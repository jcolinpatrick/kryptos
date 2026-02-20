#!/usr/bin/env python3
"""E-FRAC-50: Running Key + ALL Remaining Structured Transposition Families

Extends E-FRAC-49 (columnar widths 6,8,9) to cover ALL structured transposition
families that were previously tested with periodic keys:

1. Identity (no transposition) — sanity check
2. Cyclic shifts: σ(i) = (i+k) mod 97, k=1..96
3. Reverse: σ(i) = 96-i
4. Affine: σ(i) = (a*i+b) mod 97, a=2..96, b=0..96 (97 is prime)
5. Rail fence: depth 2-20
6. Block reversal: reverse blocks of size B=2..48
7. Double columnar: Bean-compatible width pairs (w6×w6, w6×w8, etc.)

Each is tested with running key from 7 reference texts × 3 cipher variants.

Information theory predicts ZERO false positives for any structured family
(E-FRAC-44: expected FP = N_perms × 10^-34 ≈ 0 for N < 10^30).
"""
import json
import math
import os
import sys
import time
import numpy as np
from itertools import permutations
import random as rng

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_ENTRIES, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = np.array([ALPH_IDX[c] for c in CT], dtype=np.int8)
N = CT_LEN  # 97

CRIB_POS = np.array([pos for pos, _ in CRIB_ENTRIES], dtype=np.int32)
CRIB_PT = np.array([ALPH_IDX[ch] for _, ch in CRIB_ENTRIES], dtype=np.int8)

BEAN_EQ_PAIRS = list(BEAN_EQ)
BEAN_INEQ_PAIRS = list(BEAN_INEQ)

VARIANTS = ['vigenere', 'beaufort', 'variant_beaufort']


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean_transposition(inv_perm):
    for eq_a, eq_b in BEAN_EQ_PAIRS:
        if CT_NUM[inv_perm[eq_a]] != CT_NUM[inv_perm[eq_b]]:
            return False
    return True


def compute_required_key(inv_perm, variant):
    required = {}
    for i in range(N_CRIBS):
        pos = int(CRIB_POS[i])
        pt_val = int(CRIB_PT[i])
        ct_val = int(CT_NUM[inv_perm[pos]])
        if variant == 'vigenere':
            key_val = (ct_val - pt_val) % MOD
        elif variant == 'beaufort':
            key_val = (ct_val + pt_val) % MOD
        elif variant == 'variant_beaufort':
            key_val = (pt_val - ct_val) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        required[pos] = key_val
    return required


def check_bean_ineq_on_key(required_key):
    for a, b in BEAN_INEQ_PAIRS:
        if required_key.get(a) is not None and required_key.get(b) is not None:
            if required_key[a] == required_key[b]:
                return False
    return True


def load_text_as_nums(filepath):
    with open(filepath, 'r', errors='replace') as f:
        raw = f.read().upper()
    nums = [ALPH_IDX[c] for c in raw if c in ALPH_IDX]
    return np.array(nums, dtype=np.int8)


def scan_text_for_matches(source, crib_positions, required_values):
    n_offsets = len(source) - N + 1
    if n_offsets <= 0:
        return []
    mask = np.ones(n_offsets, dtype=bool)
    for pos, val in zip(crib_positions, required_values):
        mask &= (source[pos:pos + n_offsets] == val)
        if not mask.any():
            return []
    return np.where(mask)[0].tolist()


def filter_and_scan(perms, family_name, texts, results):
    """Filter permutations by Bean, scan texts, return hit count."""
    bean_passing = []

    for perm in perms:
        inv = invert_perm(perm)
        if not check_bean_transposition(inv):
            continue

        for variant in VARIANTS:
            required_key = compute_required_key(inv, variant)
            if not check_bean_ineq_on_key(required_key):
                continue
            bean_passing.append((perm, inv, variant, required_key))

    total_hits = 0
    total_scans = 0

    for text_name, source in texts.items():
        for perm, inv, variant, required_key in bean_passing:
            positions = np.array(sorted(required_key.keys()), dtype=np.int32)
            values = np.array([required_key[p] for p in positions], dtype=np.int8)
            hits = scan_text_for_matches(source, positions, values)
            total_scans += 1

            for offset in hits:
                total_hits += 1
                results['hits'].append({
                    'family': family_name,
                    'variant': variant,
                    'text': text_name,
                    'offset': offset,
                    'perm_sample': perm[:10],
                })
                print(f"  *** MATCH: {family_name}, {variant}, {text_name}, offset={offset} ***")

    return len(perms), len(bean_passing), total_scans, total_hits


# ── Transposition generators ────────────────────────────────────────

def gen_identity():
    """Identity permutation (no transposition)."""
    return [list(range(N))]


def gen_cyclic():
    """Cyclic shifts: σ(i) = (i+k) mod 97, k=1..96."""
    perms = []
    for k in range(1, N):
        perms.append([(i + k) % N for i in range(N)])
    return perms


def gen_reverse():
    """Reverse: σ(i) = 96-i."""
    return [list(range(N - 1, -1, -1))]


def gen_affine():
    """Affine: σ(i) = (a*i+b) mod 97, a=2..96, b=0..96.
    97 is prime so all a=2..96 give valid permutations."""
    perms = []
    for a in range(2, N):
        for b in range(N):
            perms.append([(a * i + b) % N for i in range(N)])
    return perms


def gen_rail_fence():
    """Rail fence with depth 2-20."""
    perms = []
    for depth in range(2, 21):
        # Generate rail fence permutation
        rails = [[] for _ in range(depth)]
        rail = 0
        direction = 1
        for i in range(N):
            rails[rail].append(i)
            if rail == 0:
                direction = 1
            elif rail == depth - 1:
                direction = -1
            rail += direction
        perm = []
        for r in rails:
            perm.extend(r)
        if len(perm) == N:
            perms.append(perm)
    return perms


def gen_block_reversal():
    """Block reversal: reverse blocks of size B=2..48."""
    perms = []
    for B in range(2, 49):
        perm = []
        for start in range(0, N, B):
            end = min(start + B, N)
            perm.extend(range(end - 1, start - 1, -1))
        if len(perm) == N:
            perms.append(perm)
    return perms


def gen_columnar(width):
    """Generate all columnar permutations for given width."""
    perms = []
    nrows = (N + width - 1) // width
    full_cols = N - (nrows - 1) * width

    for col_order in permutations(range(width)):
        perm = []
        for col in col_order:
            if col < full_cols:
                rows = nrows
            else:
                rows = nrows - 1
            for row in range(rows):
                pos = row * width + col
                if pos < N:
                    perm.append(pos)
        perms.append(perm)
    return perms


def gen_double_columnar_sampled(w1, w2, n_samples=500):
    """Generate sampled double columnar compositions σ₁∘σ₂."""
    perms = []
    # Generate a pool of orderings for each width
    all_w1 = gen_columnar(w1)
    all_w2 = gen_columnar(w2)

    if len(all_w1) <= n_samples:
        pool1 = all_w1
    else:
        pool1 = rng.sample(all_w1, n_samples)

    if len(all_w2) <= n_samples:
        pool2 = all_w2
    else:
        pool2 = rng.sample(all_w2, n_samples)

    for p1 in pool1:
        for p2 in pool2:
            # Compose: first apply p2, then p1
            composed = [p1[p2[i]] for i in range(N)]
            perms.append(composed)

    return perms


def main():
    t_start = time.time()
    rng.seed(42)

    print("=" * 70)
    print("E-FRAC-50: Running Key + ALL Structured Transposition Families")
    print("=" * 70)

    # Load reference texts
    ref_dir = os.path.join(os.path.dirname(__file__), '..', 'reference')
    rk_dir = os.path.join(ref_dir, 'running_key_texts')

    text_files = [
        ('Carter Gutenberg', os.path.join(ref_dir, 'carter_gutenberg.txt')),
        ('Carter Vol1', os.path.join(ref_dir, 'carter_vol1_extract.txt')),
        ('CIA Charter', os.path.join(rk_dir, 'cia_charter.txt')),
        ('JFK Berlin', os.path.join(rk_dir, 'jfk_berlin.txt')),
        ('NSA Act 1947', os.path.join(rk_dir, 'nsa_act_1947.txt')),
        ('Reagan Berlin', os.path.join(rk_dir, 'reagan_berlin.txt')),
        ('UDHR', os.path.join(rk_dir, 'udhr.txt')),
    ]

    texts = {}
    for name, path in text_files:
        if os.path.exists(path):
            texts[name] = load_text_as_nums(path)
            print(f"  {name}: {len(texts[name])} chars")

    total_text_chars = sum(len(t) for t in texts.values())
    total_offsets = sum(max(0, len(t) - N + 1) for t in texts.values())
    print(f"  Total: {total_text_chars} chars, {total_offsets} offsets")
    print()

    results = {
        'experiment': 'E-FRAC-50',
        'description': 'Running key + ALL structured transposition families',
        'variants': VARIANTS,
        'texts': {name: len(nums) for name, nums in texts.items()},
        'families': {},
        'total_perms': 0,
        'total_bean_passing': 0,
        'total_scans': 0,
        'total_hits': 0,
        'hits': [],
    }

    # Define all families to test
    families = [
        ('Identity', gen_identity),
        ('Cyclic shifts (96)', gen_cyclic),
        ('Reverse', gen_reverse),
        ('Affine (9,120)', gen_affine),
        ('Rail fence (2-20)', gen_rail_fence),
        ('Block reversal (2-48)', gen_block_reversal),
    ]

    # Double columnar: Bean-compatible width pairs (from E-FRAC-46)
    dc_pairs = [(6, 6), (6, 8), (8, 6), (6, 9), (9, 6),
                (8, 8), (8, 9), (9, 8), (9, 9)]

    for name, gen_func in families:
        print(f"\n--- {name} ---")
        t0 = time.time()
        perms = gen_func()
        n_perms, n_bean, n_scans, n_hits = filter_and_scan(perms, name, texts, results)
        elapsed = time.time() - t0
        results['families'][name] = {
            'total_perms': n_perms,
            'bean_passing': n_bean,
            'scans': n_scans,
            'hits': n_hits,
            'runtime': round(elapsed, 1),
        }
        results['total_perms'] += n_perms
        results['total_bean_passing'] += n_bean
        results['total_scans'] += n_scans
        results['total_hits'] += n_hits
        print(f"  Perms: {n_perms}, Bean-passing: {n_bean}, Scans: {n_scans}, Hits: {n_hits} [{elapsed:.1f}s]")

    # Double columnar (sampled)
    for w1, w2 in dc_pairs:
        name = f'Double columnar w{w1}×w{w2}'
        print(f"\n--- {name} ---")
        t0 = time.time()
        perms = gen_double_columnar_sampled(w1, w2, n_samples=200)
        n_perms, n_bean, n_scans, n_hits = filter_and_scan(perms, name, texts, results)
        elapsed = time.time() - t0
        results['families'][name] = {
            'total_perms': n_perms,
            'bean_passing': n_bean,
            'scans': n_scans,
            'hits': n_hits,
            'runtime': round(elapsed, 1),
        }
        results['total_perms'] += n_perms
        results['total_bean_passing'] += n_bean
        results['total_scans'] += n_scans
        results['total_hits'] += n_hits
        print(f"  Perms: {n_perms}, Bean-passing: {n_bean}, Scans: {n_scans}, Hits: {n_hits} [{elapsed:.1f}s]")

    # Summary
    t_total = time.time() - t_start
    results['runtime_seconds'] = round(t_total, 1)

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")

    # Print per-family summary
    print(f"\n{'Family':<35} {'Perms':>8} {'Bean':>8} {'Scans':>8} {'Hits':>5}")
    print("-" * 70)
    for name, data in results['families'].items():
        print(f"{name:<35} {data['total_perms']:>8} {data['bean_passing']:>8} "
              f"{data['scans']:>8} {data['hits']:>5}")
    print("-" * 70)
    print(f"{'TOTAL':<35} {results['total_perms']:>8} {results['total_bean_passing']:>8} "
          f"{results['total_scans']:>8} {results['total_hits']:>5}")

    print(f"\nRuntime: {t_total:.1f}s")
    print(f"Reference texts: {len(texts)} ({total_text_chars} chars)")

    # Info-theoretic context
    total_checks = results['total_bean_passing'] * total_offsets
    prob_per_check = (1.0 / 26) ** 24
    expected_fp = total_checks * prob_per_check
    print(f"\nInformation-theoretic context:")
    print(f"  Total (config × offset) checks: {total_checks:,.0f}")
    print(f"  P(random match) per check: {prob_per_check:.2e}")
    print(f"  Expected false positives: {expected_fp:.2e}")

    if results['total_hits'] == 0:
        verdict = 'ELIMINATED'
        print(f"\nVERDICT: ELIMINATED — ALL structured transposition families + running key "
              f"from {len(texts)} reference texts produce ZERO matches.")
    else:
        verdict = 'SIGNAL'
        print(f"\n*** {results['total_hits']} HITS FOUND ***")

    results['verdict'] = verdict
    print(f"\nRESULT: best={'24/24' if results['total_hits'] > 0 else '0/24'} "
          f"configs={results['total_bean_passing']} verdict={verdict}")

    # Save
    out_dir = os.path.join(os.path.dirname(__file__), '..', 'results', 'frac')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'e_frac_50_running_key_all_families.json')
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
