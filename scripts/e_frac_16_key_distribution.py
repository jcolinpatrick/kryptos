#!/usr/bin/env python3
"""E-FRAC-16: Key Value Distribution Analysis

The Beaufort key at crib positions has value K(=10) at 5 out of 24 positions
(28, 30, 31, 32, 70), including a run of three consecutive positions (30-31-32).
Under Vigenere, the max value frequency is 3.

This tests:
1. Is the Beaufort key concentration statistically significant?
2. Does this differentiate Beaufort from Vigenere as the cipher variant?
3. What does the key distribution look like under each variant?
4. Is there any pattern in which key values appear at which positions?
"""

import json
import random
import time
from collections import Counter
from pathlib import Path

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD, ALPH_IDX, CRIB_DICT,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
)


def main():
    start_time = time.time()
    random.seed(42)
    results = {}

    print("=" * 70)
    print("E-FRAC-16: Key Value Distribution Analysis")
    print("=" * 70)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 1: Key value distributions under each variant
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 1: Key value frequency analysis ---")

    # Build complete key value arrays
    crib_positions = sorted(CRIB_DICT.keys())

    variants = {}
    for variant_name, ene_key, bc_key in [
        ('vigenere', VIGENERE_KEY_ENE, VIGENERE_KEY_BC),
        ('beaufort', BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC),
    ]:
        key_vals = []
        for i, pos in enumerate(range(21, 34)):
            key_vals.append((pos, ene_key[i]))
        for i, pos in enumerate(range(63, 74)):
            key_vals.append((pos, bc_key[i]))

        val_counts = Counter(v for _, v in key_vals)
        max_count = max(val_counts.values())
        max_val = [v for v, c in val_counts.items() if c == max_count]

        print(f"\n  {variant_name.upper()} key values:")
        print(f"    Values: {' '.join(f'{ALPH[v]}' for _, v in key_vals)}")
        print(f"    Nums:   {' '.join(f'{v:2d}' for _, v in key_vals)}")
        print(f"    Max frequency: {max_count} (value{'s' if len(max_val)>1 else ''}: {', '.join(f'{ALPH[v]}={v}' for v in max_val)})")
        print(f"    Positions with max value:")
        for mv in max_val:
            positions = [pos for pos, v in key_vals if v == mv]
            print(f"      {ALPH[mv]}={mv}: positions {positions}")

        # Distribution summary
        print(f"    Full distribution:")
        for v in sorted(val_counts.keys()):
            positions = [pos for pos, val in key_vals if val == v]
            print(f"      {ALPH[v]}={v:2d}: count={val_counts[v]:2d} at positions {positions}")

        # Check for consecutive runs
        sorted_pairs = sorted(key_vals, key=lambda x: x[0])
        max_run = 1
        cur_run = 1
        cur_val = sorted_pairs[0][1]
        run_info = []
        for i in range(1, len(sorted_pairs)):
            if sorted_pairs[i][1] == cur_val and sorted_pairs[i][0] == sorted_pairs[i-1][0] + 1:
                cur_run += 1
            else:
                if cur_run >= 2:
                    run_info.append((cur_val, cur_run, sorted_pairs[i-cur_run][0]))
                cur_run = 1
                cur_val = sorted_pairs[i][1]
        if cur_run >= 2:
            run_info.append((cur_val, cur_run, sorted_pairs[len(sorted_pairs)-cur_run][0]))

        print(f"    Consecutive runs (length ≥2):")
        for val, length, start_pos in run_info:
            print(f"      {ALPH[val]} (={val}) × {length} starting at position {start_pos}")
            max_run = max(max_run, length)

        variants[variant_name] = {
            'key_vals': key_vals,
            'val_counts': dict(val_counts),
            'max_count': max_count,
            'max_val': max_val,
            'max_consecutive_run': max_run,
            'runs': [(v, l, s) for v, l, s in run_info],
        }

    results['part1_distributions'] = {k: {kk: vv for kk, vv in v.items() if kk != 'key_vals'}
                                      for k, v in variants.items()}

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 2: Statistical significance — Monte Carlo
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 2: Monte Carlo significance tests ---")
    N_MC = 500_000

    # Test 1: Max frequency among 24 random uniform values from {0..25}
    mc_max_freq = []
    mc_max_run = []
    for _ in range(N_MC):
        vals = [random.randint(0, 25) for _ in range(24)]
        counts = Counter(vals)
        mc_max_freq.append(max(counts.values()))

        # Max consecutive run in sorted positions (simulating crib positions)
        # Use the actual crib positions
        key_at_crib = [(pos, random.randint(0, 25)) for pos in crib_positions]
        key_at_crib.sort()
        max_r = 1
        cur_r = 1
        for i in range(1, len(key_at_crib)):
            if (key_at_crib[i][1] == key_at_crib[i-1][1] and
                key_at_crib[i][0] == key_at_crib[i-1][0] + 1):
                cur_r += 1
                max_r = max(max_r, cur_r)
            else:
                cur_r = 1
        mc_max_run.append(max_r)

    # Beaufort: max freq = 5
    beau_max_freq = variants['beaufort']['max_count']
    vig_max_freq = variants['vigenere']['max_count']

    p_beau_freq = sum(1 for x in mc_max_freq if x >= beau_max_freq) / N_MC
    p_vig_freq = sum(1 for x in mc_max_freq if x >= vig_max_freq) / N_MC

    mc_freq_dist = Counter(mc_max_freq)
    print(f"  Max frequency distribution (24 random values from 26):")
    for k in sorted(mc_freq_dist.keys()):
        pct = mc_freq_dist[k] / N_MC * 100
        print(f"    Max freq = {k}: {pct:.2f}%")

    print(f"\n  Beaufort max freq = {beau_max_freq}: p = {p_beau_freq:.4f}")
    print(f"  Vigenere max freq = {vig_max_freq}: p = {p_vig_freq:.4f}")

    # Test 2: Max consecutive run
    beau_max_run = variants['beaufort']['max_consecutive_run']
    vig_max_run = variants['vigenere']['max_consecutive_run']

    p_beau_run = sum(1 for x in mc_max_run if x >= beau_max_run) / N_MC
    p_vig_run = sum(1 for x in mc_max_run if x >= vig_max_run) / N_MC

    mc_run_dist = Counter(mc_max_run)
    print(f"\n  Max consecutive run distribution (at actual crib positions):")
    for k in sorted(mc_run_dist.keys()):
        pct = mc_run_dist[k] / N_MC * 100
        if pct >= 0.1:
            print(f"    Max run = {k}: {pct:.2f}%")

    print(f"\n  Beaufort max run = {beau_max_run}: p = {p_beau_run:.4f}")
    print(f"  Vigenere max run = {vig_max_run}: p = {p_vig_run:.4f}")

    results['part2_significance'] = {
        'beaufort_max_freq': beau_max_freq,
        'beaufort_max_freq_p': p_beau_freq,
        'vigenere_max_freq': vig_max_freq,
        'vigenere_max_freq_p': p_vig_freq,
        'beaufort_max_run': beau_max_run,
        'beaufort_max_run_p': p_beau_run,
        'vigenere_max_run': vig_max_run,
        'vigenere_max_run_p': p_vig_run,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 3: Does the Beaufort key have structure the Vigenere key lacks?
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 3: Key value entropy comparison ---")

    for variant_name in ['vigenere', 'beaufort']:
        val_counts = variants[variant_name]['val_counts']
        total = sum(val_counts.values())

        # Shannon entropy
        import math
        entropy = -sum((c/total) * math.log2(c/total) for c in val_counts.values())
        max_entropy = math.log2(26)  # uniform over 26 values
        entropy_ratio = entropy / max_entropy

        # Unique values
        n_unique = len(val_counts)

        # Chi-squared vs uniform
        expected = total / 26
        chi2 = sum((val_counts.get(v, 0) - expected) ** 2 / expected for v in range(26))

        print(f"\n  {variant_name.upper()}: {n_unique} unique values, entropy = {entropy:.3f} bits "
              f"({entropy_ratio:.1%} of max), chi2 = {chi2:.2f}")

    # Monte Carlo for entropy
    mc_entropy_vig = []
    mc_entropy_beau = []
    for _ in range(100_000):
        vals = [random.randint(0, 25) for _ in range(24)]
        counts = Counter(vals)
        total = sum(counts.values())
        e = -sum((c/total) * math.log2(c/total) for c in counts.values())
        mc_entropy_vig.append(e)  # Same for both since it's random

    import math
    beau_entropy = -sum((c/24) * math.log2(c/24) for c in variants['beaufort']['val_counts'].values())
    vig_entropy = -sum((c/24) * math.log2(c/24) for c in variants['vigenere']['val_counts'].values())

    beau_e_pctile = sum(1 for x in mc_entropy_vig if x <= beau_entropy) / len(mc_entropy_vig)
    vig_e_pctile = sum(1 for x in mc_entropy_vig if x <= vig_entropy) / len(mc_entropy_vig)

    print(f"\n  Entropy percentiles (lower = more concentrated):")
    print(f"    Beaufort: {beau_entropy:.3f} bits, {beau_e_pctile*100:.1f}th percentile")
    print(f"    Vigenere: {vig_entropy:.3f} bits, {vig_e_pctile*100:.1f}th percentile")

    results['part3_entropy'] = {
        'beaufort_entropy': beau_entropy,
        'beaufort_pctile': beau_e_pctile,
        'vigenere_entropy': vig_entropy,
        'vigenere_pctile': vig_e_pctile,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 4: The Kryptos connection — key value K
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 4: The 'K' connection ---")

    # Under Beaufort, the most common key value is K (=10)
    # K is the first letter of KRYPTOS
    # Is there a pattern where the key is KRYPTOS-related?

    kryptos = "KRYPTOS"
    kryptos_vals = [ALPH_IDX[c] for c in kryptos]
    print(f"  KRYPTOS letter values: {kryptos_vals}")

    # Check if key values match KRYPTOS cycling
    for variant_name in ['vigenere', 'beaufort']:
        key_vals = variants[variant_name]['key_vals']
        for offset in range(7):  # KRYPTOS has 7 letters
            matches = sum(1 for pos, val in key_vals
                         if val == kryptos_vals[(pos + offset) % 7])
            if matches >= 3:
                print(f"  {variant_name}, KRYPTOS offset {offset}: {matches}/24 matches")

    # Check if key values at specific positions spell something
    print(f"\n  Key values as letters (Beaufort):")
    beau_key_letters = ''.join(ALPH[v] for _, v in variants['beaufort']['key_vals'])
    print(f"    ENE: {beau_key_letters[:13]}")
    print(f"    BC:  {beau_key_letters[13:]}")

    vig_key_letters = ''.join(ALPH[v] for _, v in variants['vigenere']['key_vals'])
    print(f"\n  Key values as letters (Vigenere):")
    print(f"    ENE: {vig_key_letters[:13]}")
    print(f"    BC:  {vig_key_letters[13:]}")

    results['part4_kryptos'] = {
        'beaufort_key_letters': beau_key_letters,
        'vigenere_key_letters': vig_key_letters,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 5: Self-encrypting positions analysis
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n--- Part 5: Self-encrypting positions ---")

    # Positions where CT[i] == PT[i] (self-encrypting)
    for pos, pt_char in CRIB_DICT.items():
        if CT[pos] == pt_char:
            ct_val = ALPH_IDX[CT[pos]]
            vig_k = (ct_val - ALPH_IDX[pt_char]) % 26
            beau_k = (ct_val + ALPH_IDX[pt_char]) % 26
            print(f"  Position {pos}: CT=PT='{CT[pos]}' → Vig key=0 ({ALPH[0]}), "
                  f"Beau key={beau_k} ({ALPH[beau_k]})")

    # Under Vigenere, self-encrypting means key = 0 (identity)
    # Under Beaufort, self-encrypting means key = 2*letter_value
    print(f"\n  Under Vigenere: self-encrypting positions have key = A (0)")
    print(f"  Under Beaufort: self-encrypting means key = 2 × letter_value (mod 26)")
    print(f"    pos 32 (S=18): key = 2×18 mod 26 = 10 = K")
    print(f"    pos 73 (K=10): key = 2×10 mod 26 = 20 = U")
    print(f"    Under Beaufort, self-encrypting S → key K, self-encrypting K → key U")

    # How many self-encrypting positions expected in random 97-char pairs?
    # P(CT[i] == PT[i]) = 1/26 for random → expected ~97/26 ≈ 3.7
    # We have 2 self-encrypting among 24 known → 2/24 = 8.3% vs expected 3.8%
    print(f"\n  2/24 known positions are self-encrypting")
    print(f"  Expected under random: 24/26 = 0.92 (P(2+) = {1 - (25/26)**24 * (1 + 24/26):.3f})")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Summary
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    runtime = time.time() - start_time

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(f"\n1. Beaufort key value K(=10) appears at 5/24 positions: p = {p_beau_freq:.4f}")
    if p_beau_freq < 0.05:
        print(f"   *** Marginally significant (p < 0.05) ***")
    else:
        print(f"   Not significant (p ≥ 0.05)")

    print(f"\n2. Beaufort key has consecutive run of {beau_max_run}: p = {p_beau_run:.4f}")
    if p_beau_run < 0.05:
        print(f"   *** Significant consecutive run ***")
    else:
        print(f"   Not significant")

    print(f"\n3. Beaufort entropy: {beau_e_pctile*100:.1f}th percentile (lower = more concentrated)")
    print(f"   Vigenere entropy: {vig_e_pctile*100:.1f}th percentile")

    if p_beau_freq < 0.05 or p_beau_run < 0.05:
        print(f"\n   → Beaufort key shows MORE structure than Vigenere key")
        print(f"   → This is weak evidence for Beaufort variant (not conclusive)")
    else:
        print(f"\n   → Neither variant's key shows significant concentration")

    print(f"\nRuntime: {runtime:.1f}s")
    print(f"RESULT: Key distribution analysis complete")

    results['summary'] = {
        'beaufort_more_structured': p_beau_freq < p_vig_freq,
        'beaufort_freq_p': p_beau_freq,
        'beaufort_run_p': p_beau_run,
        'runtime': runtime,
    }

    # Save
    out_dir = Path("results/frac")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "e_frac_16_key_distribution.json"
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
