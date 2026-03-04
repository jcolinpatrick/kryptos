#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-15: Linear/Polynomial Key Model Test

E-FRAC-14 found that k[i] = 4i + 20 (mod 26) matches 7/24 crib positions
(~3σ above random). This quick experiment:
1. Tests top linear key models for both Vigenere and Beaufort
2. Decrypts full CT with each and checks for readable plaintext
3. Tests quadratic and cubic models
4. Comprehensive test of ALL (a,b) with match count ≥ 5
"""

import json
import random
import time
from pathlib import Path
from collections import Counter

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD, ALPH_IDX, CRIB_DICT,
    BEAN_EQ, BEAN_INEQ,
)


def letter_to_num(text: str) -> list[int]:
    return [ALPH_IDX[c] for c in text]


def num_to_letter(nums: list[int]) -> str:
    return ''.join(ALPH[n % 26] for n in nums)


def compute_ic(text: str) -> float:
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def score_crib_match(key_func, variant: str) -> tuple[int, list[int]]:
    """Score a key function against the 24 crib positions.
    Returns (match_count, list of matching positions).
    """
    matches = []
    for pos, pt_char in CRIB_DICT.items():
        ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[pt_char]
        k = key_func(pos) % 26

        if variant == 'vigenere':
            expected_k = (ct_val - pt_val) % 26
        elif variant == 'beaufort':
            expected_k = (ct_val + pt_val) % 26
        elif variant == 'variant_beaufort':
            expected_k = (pt_val - ct_val) % 26
        else:
            raise ValueError(f"Unknown variant: {variant}")

        if k == expected_k:
            matches.append(pos)

    return len(matches), matches


def decrypt(key_func, variant: str) -> str:
    """Decrypt CT using the given key function and variant."""
    ct_nums = letter_to_num(CT)
    pt_nums = []
    for i, ct_val in enumerate(ct_nums):
        k = key_func(i) % 26
        if variant == 'vigenere':
            pt_val = (ct_val - k) % 26
        elif variant == 'beaufort':
            pt_val = (k - ct_val) % 26
        elif variant == 'variant_beaufort':
            pt_val = (ct_val + k) % 26
        else:
            raise ValueError
        pt_nums.append(pt_val)
    return num_to_letter(pt_nums)


def check_bean(key_func) -> tuple[bool, bool]:
    """Check Bean constraints for a key function.
    Returns (eq_pass, full_pass).
    """
    for eq_a, eq_b in BEAN_EQ:
        if key_func(eq_a) % 26 != key_func(eq_b) % 26:
            return False, False
    for ineq_a, ineq_b in BEAN_INEQ:
        if key_func(ineq_a) % 26 == key_func(ineq_b) % 26:
            return True, False
    return True, True


def has_common_words(text: str) -> tuple[int, list[str]]:
    """Check for common English words (length >= 3) in text."""
    common = ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL',
              'CAN', 'HAD', 'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'HAS',
              'HIS', 'HOW', 'MAN', 'NEW', 'NOW', 'OLD', 'SEE', 'WAY',
              'WHO', 'DID', 'GET', 'HIM', 'LET', 'SAY', 'SHE', 'TOO',
              'USE', 'THAT', 'WITH', 'HAVE', 'THIS', 'WILL', 'YOUR',
              'FROM', 'THEY', 'BEEN', 'HAVE', 'MANY', 'SOME', 'THEM',
              'THAN', 'EACH', 'MAKE', 'LIKE', 'JUST', 'OVER', 'SUCH',
              'EAST', 'NORTH', 'SOUTH', 'WEST', 'BERLIN', 'CLOCK',
              'POINT', 'SECRET', 'HIDDEN', 'BURIED', 'UNDERGROUND',
              'LAYER', 'BETWEEN', 'SUBTLE', 'SHADOW', 'FORCES',
              'VIRTUALLY', 'INVISIBLE', 'SLOWLY', 'DESPERATELY',
              'ILLUSION', 'TIME', 'PLACE', 'TOMB', 'EGYPT', 'CARTER',
              ]
    found = []
    for word in common:
        if word in text:
            found.append(word)
    return len(found), found


def main():
    start_time = time.time()
    results = {}

    print("=" * 70)
    print("E-FRAC-15: Linear/Polynomial Key Model Test")
    print("=" * 70)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 1: Exhaustive linear search — all (a, b) × 3 variants
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 1: All linear key models k[i] = a*i + b (mod 26) ---")

    linear_hits = []
    for variant in ['vigenere', 'beaufort', 'variant_beaufort']:
        for a in range(26):
            for b in range(26):
                key_fn = lambda i, a=a, b=b: (a * i + b) % 26
                n_match, positions = score_crib_match(key_fn, variant)
                if n_match >= 5:
                    pt = decrypt(key_fn, variant)
                    ic = compute_ic(pt)
                    bean_eq, bean_full = check_bean(key_fn)
                    n_words, words = has_common_words(pt)
                    linear_hits.append({
                        'a': a, 'b': b, 'variant': variant,
                        'matches': n_match, 'positions': positions,
                        'plaintext': pt, 'ic': ic,
                        'bean_eq': bean_eq, 'bean_full': bean_full,
                        'n_words': n_words, 'words': words,
                    })

    # Sort by match count
    linear_hits.sort(key=lambda x: (-x['matches'], -x['n_words']))

    print(f"  Total (a,b) pairs with ≥5 matches: {len(linear_hits)}")
    print(f"\n  Top 10 by crib matches:")
    for hit in linear_hits[:10]:
        bean_str = "BEAN✓" if hit['bean_full'] else ("BEQ✓" if hit['bean_eq'] else "BEAN✗")
        word_str = f", words: {hit['words']}" if hit['words'] else ""
        print(f"    k={hit['a']}i+{hit['b']} {hit['variant']:18s}: "
              f"{hit['matches']}/24 matches, IC={hit['ic']:.4f}, {bean_str}{word_str}")
        print(f"      PT: {hit['plaintext'][:50]}...")

    # Any Bean passes?
    bean_passes = [h for h in linear_hits if h['bean_eq']]
    print(f"\n  Bean equality passes: {len(bean_passes)}")
    for hit in bean_passes[:5]:
        print(f"    k={hit['a']}i+{hit['b']} {hit['variant']}: {hit['matches']}/24, "
              f"full Bean: {hit['bean_full']}")

    # Any with English words?
    word_hits = [h for h in linear_hits if h['n_words'] > 0]
    print(f"\n  Results with English words: {len(word_hits)}")
    for hit in word_hits[:10]:
        print(f"    k={hit['a']}i+{hit['b']} {hit['variant']}: {hit['matches']}/24, "
              f"words: {hit['words']}")
        print(f"      PT: {hit['plaintext'][:60]}...")

    results['part1_linear'] = {
        'total_ge5': len(linear_hits),
        'max_matches': linear_hits[0]['matches'] if linear_hits else 0,
        'bean_eq_passes': len(bean_passes),
        'word_hits': len(word_hits),
        'top5': [
            {'a': h['a'], 'b': h['b'], 'variant': h['variant'],
             'matches': h['matches'], 'pt_prefix': h['plaintext'][:50]}
            for h in linear_hits[:5]
        ],
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 2: Quadratic models k[i] = a*i² + b*i + c (mod 26)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 2: Quadratic key models k[i] = a*i² + b*i + c (mod 26) ---")

    quad_hits = []
    for variant in ['vigenere', 'beaufort']:
        for a in range(26):
            for b in range(26):
                for c in range(26):
                    key_fn = lambda i, a=a, b=b, c=c: (a * i * i + b * i + c) % 26
                    n_match, positions = score_crib_match(key_fn, variant)
                    if n_match >= 8:
                        pt = decrypt(key_fn, variant)
                        ic = compute_ic(pt)
                        bean_eq, bean_full = check_bean(key_fn)
                        n_words, words = has_common_words(pt)
                        quad_hits.append({
                            'a': a, 'b': b, 'c': c, 'variant': variant,
                            'matches': n_match, 'plaintext': pt, 'ic': ic,
                            'bean_eq': bean_eq, 'bean_full': bean_full,
                            'n_words': n_words, 'words': words,
                        })

    quad_hits.sort(key=lambda x: (-x['matches'], -x['n_words']))

    print(f"  Total (a,b,c) triples with ≥8 matches: {len(quad_hits)}")
    if quad_hits:
        print(f"\n  Top 5:")
        for hit in quad_hits[:5]:
            bean_str = "BEAN✓" if hit['bean_full'] else ("BEQ✓" if hit['bean_eq'] else "BEAN✗")
            word_str = f", words: {hit['words']}" if hit['words'] else ""
            print(f"    k={hit['a']}i²+{hit['b']}i+{hit['c']} {hit['variant']}: "
                  f"{hit['matches']}/24 matches, IC={hit['ic']:.4f}, {bean_str}{word_str}")
            print(f"      PT: {hit['plaintext'][:50]}...")

    results['part2_quadratic'] = {
        'total_ge8': len(quad_hits),
        'max_matches': quad_hits[0]['matches'] if quad_hits else 0,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 3: Modular exponential: k[i] = a * b^i (mod 26)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 3: Exponential key models k[i] = a * b^i (mod 26) ---")

    exp_hits = []
    for variant in ['vigenere', 'beaufort']:
        for a in range(1, 26):
            for base in range(2, 26):
                # Precompute b^i mod 26 for i=0..96
                powers = [1]
                for _ in range(96):
                    powers.append((powers[-1] * base) % 26)
                key_fn = lambda i, a=a, powers=powers: (a * powers[i]) % 26
                n_match, _ = score_crib_match(key_fn, variant)
                if n_match >= 6:
                    pt = decrypt(key_fn, variant)
                    bean_eq, bean_full = check_bean(key_fn)
                    n_words, words = has_common_words(pt)
                    exp_hits.append({
                        'a': a, 'base': base, 'variant': variant,
                        'matches': n_match, 'plaintext': pt,
                        'bean_eq': bean_eq, 'bean_full': bean_full,
                        'n_words': n_words, 'words': words,
                    })

    exp_hits.sort(key=lambda x: -x['matches'])
    print(f"  Total with ≥6 matches: {len(exp_hits)}")
    if exp_hits:
        print(f"  Top 5:")
        for hit in exp_hits[:5]:
            print(f"    k={hit['a']}*{hit['base']}^i {hit['variant']}: "
                  f"{hit['matches']}/24, words: {hit.get('words', [])}")

    results['part3_exponential'] = {
        'total_ge6': len(exp_hits),
        'max_matches': exp_hits[0]['matches'] if exp_hits else 0,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 4: Fibonacci/recurrence-like: k[i] = k[i-1] + k[i-2] (mod 26)
    # with various seeds
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 4: Fibonacci-like recurrence keys ---")

    fib_hits = []
    for variant in ['vigenere', 'beaufort']:
        for s0 in range(26):
            for s1 in range(26):
                keys = [s0, s1]
                for _ in range(95):
                    keys.append((keys[-1] + keys[-2]) % 26)
                key_fn = lambda i, keys=keys: keys[i]
                n_match, _ = score_crib_match(key_fn, variant)
                if n_match >= 6:
                    pt = decrypt(key_fn, variant)
                    bean_eq, bean_full = check_bean(key_fn)
                    n_words, words = has_common_words(pt)
                    fib_hits.append({
                        'seed': (s0, s1), 'variant': variant,
                        'matches': n_match, 'plaintext': pt,
                        'bean_eq': bean_eq, 'bean_full': bean_full,
                        'n_words': n_words, 'words': words,
                    })

    fib_hits.sort(key=lambda x: -x['matches'])
    print(f"  Total with ≥6 matches: {len(fib_hits)}")
    if fib_hits:
        print(f"  Top 5:")
        for hit in fib_hits[:5]:
            print(f"    seeds={hit['seed']} {hit['variant']}: "
                  f"{hit['matches']}/24, Bean_eq={hit['bean_eq']}, words: {hit.get('words', [])}")

    # Also test generalized: k[i] = a*k[i-1] + b*k[i-2] (mod 26) — Gromark/Vimark-like
    print("\n  Generalized: k[i] = a*k[i-1] + b*k[i-2] (mod 26)")
    gen_fib_hits = []
    for variant in ['vigenere', 'beaufort']:
        for mult_a in range(1, 6):  # small multipliers
            for mult_b in range(1, 6):
                for s0 in range(26):
                    for s1 in range(26):
                        keys = [s0, s1]
                        for _ in range(95):
                            keys.append((mult_a * keys[-1] + mult_b * keys[-2]) % 26)
                        key_fn = lambda i, keys=keys: keys[i]
                        n_match, _ = score_crib_match(key_fn, variant)
                        if n_match >= 8:
                            pt = decrypt(key_fn, variant)
                            bean_eq, bean_full = check_bean(key_fn)
                            n_words, words = has_common_words(pt)
                            gen_fib_hits.append({
                                'mult_a': mult_a, 'mult_b': mult_b,
                                'seed': (s0, s1), 'variant': variant,
                                'matches': n_match, 'plaintext': pt,
                                'bean_eq': bean_eq, 'bean_full': bean_full,
                                'n_words': n_words, 'words': words,
                            })

    gen_fib_hits.sort(key=lambda x: -x['matches'])
    print(f"  Total with ≥8 matches: {len(gen_fib_hits)}")
    if gen_fib_hits:
        print(f"  Top 5:")
        for hit in gen_fib_hits[:5]:
            print(f"    k[i]={hit['mult_a']}*k[i-1]+{hit['mult_b']}*k[i-2], "
                  f"seeds={hit['seed']} {hit['variant']}: "
                  f"{hit['matches']}/24, Bean_eq={hit['bean_eq']}")
            print(f"      PT: {hit['plaintext'][:50]}...")

    results['part4_recurrence'] = {
        'fib_total_ge6': len(fib_hits),
        'fib_max': fib_hits[0]['matches'] if fib_hits else 0,
        'gen_total_ge8': len(gen_fib_hits),
        'gen_max': gen_fib_hits[0]['matches'] if gen_fib_hits else 0,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 5: Monte Carlo baseline — what do random keys achieve?
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 5: Random baseline ---")

    N_MC = 100_000
    random.seed(42)
    mc_max_matches = []
    for _ in range(N_MC):
        keys = [random.randint(0, 25) for _ in range(CT_LEN)]
        key_fn = lambda i, keys=keys: keys[i]
        n_match, _ = score_crib_match(key_fn, 'vigenere')
        mc_max_matches.append(n_match)

    mc_counts = Counter(mc_max_matches)
    mc_mean = sum(mc_max_matches) / len(mc_max_matches)
    mc_std = (sum((x - mc_mean) ** 2 for x in mc_max_matches) / len(mc_max_matches)) ** 0.5
    print(f"  Random 97-key: mean crib matches = {mc_mean:.2f} ± {mc_std:.2f}")
    print(f"  Distribution:")
    for k in sorted(mc_counts.keys()):
        pct = mc_counts[k] / N_MC * 100
        if pct >= 0.01:
            print(f"    {k}/24: {pct:.2f}%")

    results['part5_random'] = {
        'mean': mc_mean, 'std': mc_std,
        'distribution': {str(k): v / N_MC for k, v in mc_counts.items()},
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Summary
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    runtime = time.time() - start_time

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    best_linear = linear_hits[0] if linear_hits else None
    best_quad = quad_hits[0] if quad_hits else None

    print(f"\n  Linear: best {best_linear['matches']}/24 (k={best_linear['a']}i+{best_linear['b']}, {best_linear['variant']})" if best_linear else "  Linear: no hits")
    print(f"  Quadratic: best {best_quad['matches']}/24" if best_quad else "  Quadratic: no hits ≥8")
    print(f"  Exponential: best {exp_hits[0]['matches']}/24" if exp_hits else "  Exponential: no hits ≥6")
    print(f"  Fibonacci: best {fib_hits[0]['matches']}/24" if fib_hits else "  Fibonacci: no hits ≥6")
    print(f"  Gen. recurrence: best {gen_fib_hits[0]['matches']}/24" if gen_fib_hits else "  Gen. recurrence: no hits ≥8")
    print(f"  Random baseline: {mc_mean:.2f} ± {mc_std:.2f}")

    # Check if anything is above noise
    all_best = []
    if best_linear:
        all_best.append(('linear', best_linear['matches']))
    if best_quad:
        all_best.append(('quadratic', best_quad['matches']))
    if exp_hits:
        all_best.append(('exponential', exp_hits[0]['matches']))
    if gen_fib_hits:
        all_best.append(('gen_recurrence', gen_fib_hits[0]['matches']))

    any_signal = any(m >= 10 for _, m in all_best)
    if any_signal:
        print(f"\n  *** SIGNAL: Some models score ≥10/24 — worth investigating ***")
    else:
        print(f"\n  All functional key models are within noise range (≤{max(m for _, m in all_best) if all_best else 0}/24)")
        print(f"  → Key is NOT a simple polynomial, exponential, or recurrence function of position")

    print(f"\nRuntime: {runtime:.1f}s")

    verdict = "NOISE" if not any_signal else "SIGNAL"
    print(f"RESULT: best={max(m for _, m in all_best) if all_best else 0}/24 verdict={verdict}")

    results['summary'] = {
        'best_by_family': {k: v for k, v in all_best},
        'any_signal': any_signal,
        'verdict': verdict,
        'runtime': runtime,
    }

    # Save
    out_dir = Path("results/frac")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "e_frac_15_linear_key.json"
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
