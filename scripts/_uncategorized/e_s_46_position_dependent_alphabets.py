#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-46: Position-Dependent Alphabet Analysis

Ed Scheidt said there was a deliberate "change in methodology" from K3→K4 and
hinted at "changing the language base." This experiment tests whether K4 uses
position-dependent cipher alphabets rather than a single Vigenère tableau.

Approach:
1. Test progressive alphabet: each position uses a shifted/rotated version of
   a keyword alphabet (e.g., KRYPTOS-keyed alphabet shifted by position)
2. Test Quagmire IV / progressive key: multiple mixed alphabets keyed by
   different keywords
3. Test alphabet derived from sculpture features (coordinates, clock positions)
4. For each model, evaluate against cribs to check feasibility

Key insight: If each position uses a DIFFERENT mixed alphabet, the effective
keystream becomes position-dependent even with a short keyword — potentially
explaining the non-periodic key we observe.

Output: results/e_s_46_position_alphabets.json
"""

import json
import sys
import os
import time
from collections import defaultdict
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

N = CT_LEN


def make_keyword_alphabet(keyword):
    """Create a mixed alphabet from a keyword (standard deduplication)."""
    seen = set()
    result = []
    for c in keyword.upper():
        if c in ALPH and c not in seen:
            seen.add(c)
            result.append(c)
    for c in ALPH:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return ''.join(result)


def shift_alphabet(alphabet, n):
    """Shift an alphabet by n positions."""
    n = n % 26
    return alphabet[n:] + alphabet[:n]


def decrypt_with_alphabets(ct, pt_alphabets, ct_alphabets):
    """Decrypt using position-dependent alphabets.

    For each position i:
    CT[i] is found in ct_alphabets[i], giving index j
    PT[i] = pt_alphabets[i][j]
    """
    pt = []
    for i in range(len(ct)):
        c = ct[i]
        ct_alph = ct_alphabets[i % len(ct_alphabets)] if isinstance(ct_alphabets, list) else ct_alphabets(i)
        pt_alph = pt_alphabets[i % len(pt_alphabets)] if isinstance(pt_alphabets, list) else pt_alphabets(i)
        j = ct_alph.index(c)
        pt.append(pt_alph[j])
    return ''.join(pt)


def score_against_cribs(pt):
    """Count how many crib positions match."""
    matches = 0
    for pos, expected in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == expected:
            matches += 1
    return matches


def test_progressive_shift(base_keyword, key_keyword, description):
    """Test: CT alphabet = keyword_alphabet shifted by key_keyword[i%len]."""
    base_alph = make_keyword_alphabet(base_keyword)

    best_score = 0
    best_config = None
    configs_tested = 0

    # For each starting position in the key keyword
    for key_start in range(len(key_keyword)):
        for direction in [1, -1]:  # shift direction
            pt = []
            for i in range(N):
                key_idx = ALPH_IDX[key_keyword[(key_start + i) % len(key_keyword)]]
                ct_alph = shift_alphabet(base_alph, key_idx * direction)
                j = ct_alph.index(CT[i])
                pt.append(ALPH[j])
            pt = ''.join(pt)
            score = score_against_cribs(pt)
            configs_tested += 1
            if score > best_score:
                best_score = score
                best_config = {
                    'base': base_keyword,
                    'key': key_keyword,
                    'key_start': key_start,
                    'direction': direction,
                    'score': score,
                    'pt_sample': pt[:30],
                }

    return best_score, best_config, configs_tested


def test_quagmire_models():
    """Test Quagmire I-IV with various keyword combinations."""
    print("\n--- Quagmire Models (Position-Dependent) ---")

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
        "EASTNORTHEAST", "BERLINCLOCK", "SHADOW", "POINT",
        "DYAR", "SANBORN", "SCHEIDT", "LANGLEY", "IQLUSION",
        "VIRTUALLY", "INVISIBLE", "ILLUSION", "DIGETAL",
        "UNDERGRUUND", "DESPERATELY", "TUTANKHAMUN", "CARTER",
        "EGYPT", "NILE", "VALLEY", "KINGS",
    ]

    results = {}
    total_configs = 0
    best_overall = 0

    for pt_key in keywords:
        for ct_key in keywords:
            if pt_key == ct_key:
                # Standard Quagmire I/II: same keyword for PT and CT
                pt_alph = make_keyword_alphabet(pt_key)
                ct_alph = make_keyword_alphabet(ct_key)

                for period_key in keywords[:10]:
                    for period in range(len(period_key)):
                        pt_result = []
                        for i in range(N):
                            k = ALPH_IDX[period_key[(period + i) % len(period_key)]]
                            # Quagmire I: shift PT alphabet
                            shifted = shift_alphabet(pt_alph, k)
                            j = ALPH.index(CT[i])
                            if j < 26:
                                pt_result.append(shifted[j])
                            else:
                                pt_result.append('?')
                        pt_str = ''.join(pt_result)
                        score = score_against_cribs(pt_str)
                        total_configs += 1
                        if score > best_overall:
                            best_overall = score
                            results[f"{pt_key}_{period_key}_{period}"] = {
                                'model': 'quagmire_I',
                                'pt_keyword': pt_key,
                                'period_keyword': period_key,
                                'start': period,
                                'score': score,
                            }
            else:
                # Quagmire IV: different keywords for PT and CT alphabets
                pt_alph = make_keyword_alphabet(pt_key)
                ct_alph = make_keyword_alphabet(ct_key)

                for period_key in [pt_key, ct_key, "KRYPTOS"]:
                    for period in range(min(len(period_key), 3)):  # limit starts
                        pt_result = []
                        for i in range(N):
                            k = ALPH_IDX[period_key[(period + i) % len(period_key)]]
                            shifted_ct = shift_alphabet(ct_alph, k)
                            j = shifted_ct.index(CT[i])
                            pt_result.append(pt_alph[j])
                        pt_str = ''.join(pt_result)
                        score = score_against_cribs(pt_str)
                        total_configs += 1
                        if score > best_overall:
                            best_overall = score
                            results[f"Q4_{pt_key}_{ct_key}_{period_key}_{period}"] = {
                                'model': 'quagmire_IV',
                                'pt_keyword': pt_key,
                                'ct_keyword': ct_key,
                                'period_keyword': period_key,
                                'start': period,
                                'score': score,
                            }

            if total_configs % 10000 == 0:
                print(f"    [{total_configs:,} configs, best={best_overall}/24]")

    print(f"  Total configs: {total_configs:,}, best score: {best_overall}/24")
    return results, total_configs, best_overall


def test_progressive_models():
    """Test progressive alphabet models — alphabet changes with position."""
    print("\n--- Progressive Alphabet Models ---")

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
        "BERLINCLOCK", "SHADOW", "POINT", "SANBORN", "SCHEIDT",
        "LANGLEY", "TUTANKHAMUN", "CARTER", "EGYPT",
    ]

    results = {}
    total_configs = 0
    best_overall = 0

    for base_key in keywords:
        base_alph = make_keyword_alphabet(base_key)

        # Model 1: Alphabet shifts by position (progressive Vigenère with mixed alphabet)
        for shift_rate in range(1, 26):
            pt = []
            for i in range(N):
                shifted = shift_alphabet(base_alph, (i * shift_rate) % 26)
                j = shifted.index(CT[i])
                pt.append(ALPH[j])
            pt = ''.join(pt)
            score = score_against_cribs(pt)
            total_configs += 1
            if score > best_overall:
                best_overall = score
                results[f"prog_{base_key}_rate{shift_rate}"] = {
                    'model': 'progressive_shift',
                    'keyword': base_key,
                    'shift_rate': shift_rate,
                    'score': score,
                }

        # Model 2: Position-modulated keyword
        for key_keyword in keywords[:8]:
            score, config, nc = test_progressive_shift(base_key, key_keyword,
                f"{base_key}+{key_keyword}")
            total_configs += nc
            if score > best_overall:
                best_overall = score
                results[f"modulated_{base_key}_{key_keyword}"] = config

        if total_configs % 5000 == 0:
            print(f"    [{total_configs:,} configs, best={best_overall}/24]")

    print(f"  Total configs: {total_configs:,}, best score: {best_overall}/24")
    return results, total_configs, best_overall


def test_beaufort_variants():
    """Test Beaufort and Variant Beaufort with position-dependent alphabets."""
    print("\n--- Beaufort Variants with Mixed Alphabets ---")

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
        "BERLINCLOCK", "SHADOW", "POINT", "SANBORN", "SCHEIDT",
    ]

    results = {}
    total_configs = 0
    best_overall = 0

    for base_key in keywords:
        base_alph = make_keyword_alphabet(base_key)
        base_idx = {c: i for i, c in enumerate(base_alph)}

        for key_keyword in keywords[:8]:
            for key_start in range(len(key_keyword)):
                for variant in ['beaufort', 'variant_beaufort']:
                    pt = []
                    for i in range(N):
                        k_val = base_idx.get(key_keyword[(key_start + i) % len(key_keyword)], 0)
                        ct_val = base_idx.get(CT[i], 0)

                        if variant == 'beaufort':
                            pt_val = (k_val - ct_val) % 26
                        else:
                            pt_val = (ct_val - k_val) % 26

                        pt.append(base_alph[pt_val])

                    pt_str = ''.join(pt)
                    score = score_against_cribs(pt_str)
                    total_configs += 1
                    if score > best_overall:
                        best_overall = score
                        results[f"beau_{variant}_{base_key}_{key_keyword}_{key_start}"] = {
                            'model': variant,
                            'base_keyword': base_key,
                            'key_keyword': key_keyword,
                            'key_start': key_start,
                            'score': score,
                        }

            if total_configs % 10000 == 0:
                print(f"    [{total_configs:,} configs, best={best_overall}/24]")

    print(f"  Total configs: {total_configs:,}, best score: {best_overall}/24")
    return results, total_configs, best_overall


def test_autokey_mixed_alphabet():
    """Test autokey with mixed alphabet (eliminated for standard, untested for mixed)."""
    print("\n--- Autokey with Mixed Alphabets ---")

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "BERLINCLOCK",
        "SHADOW", "POINT", "SANBORN", "SCHEIDT", "CARTER",
    ]

    results = {}
    total_configs = 0
    best_overall = 0

    for base_key in keywords:
        base_alph = make_keyword_alphabet(base_key)
        base_idx = {c: i for i, c in enumerate(base_alph)}

        for primer_key in keywords[:6]:
            for primer_start in range(min(len(primer_key), 3)):
                # PT-autokey: key[i] = primer[i] for i < len(primer), then PT[i-len(primer)]
                pt = []
                key = list(primer_key[primer_start:] + primer_key[:primer_start])

                for i in range(N):
                    if i < len(key):
                        k_val = base_idx.get(key[i], 0)
                    else:
                        k_val = base_idx.get(pt[i - len(key)], 0)

                    ct_val = base_idx.get(CT[i], 0)
                    pt_val = (ct_val - k_val) % 26
                    pt.append(base_alph[pt_val])

                pt_str = ''.join(pt)
                score = score_against_cribs(pt_str)
                total_configs += 1
                if score > best_overall:
                    best_overall = score
                    results[f"autokey_{base_key}_{primer_key}_{primer_start}"] = {
                        'model': 'pt_autokey_mixed',
                        'base_keyword': base_key,
                        'primer': primer_key,
                        'start': primer_start,
                        'score': score,
                    }

    print(f"  Total configs: {total_configs:,}, best score: {best_overall}/24")
    return results, total_configs, best_overall


def main():
    print("=" * 70)
    print("E-S-46: Position-Dependent Alphabet Analysis")
    print("=" * 70)

    t0 = time.time()
    all_results = {}
    total_configs = 0

    # Test 1: Quagmire models
    quag_results, quag_configs, quag_best = test_quagmire_models()
    all_results['quagmire'] = {'best': quag_best, 'configs': quag_configs}
    total_configs += quag_configs

    # Test 2: Progressive models
    prog_results, prog_configs, prog_best = test_progressive_models()
    all_results['progressive'] = {'best': prog_best, 'configs': prog_configs}
    total_configs += prog_configs

    # Test 3: Beaufort variants
    beau_results, beau_configs, beau_best = test_beaufort_variants()
    all_results['beaufort_mixed'] = {'best': beau_best, 'configs': beau_configs}
    total_configs += beau_configs

    # Test 4: Autokey with mixed alphabets
    auto_results, auto_configs, auto_best = test_autokey_mixed_alphabet()
    all_results['autokey_mixed'] = {'best': auto_best, 'configs': auto_configs}
    total_configs += auto_configs

    elapsed = time.time() - t0

    # Summary
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Total configs tested: {total_configs:,}")
    print(f"  Results by model:")
    for name, data in sorted(all_results.items()):
        print(f"    {name}: best={data['best']}/24, configs={data['configs']:,}")

    overall_best = max(d['best'] for d in all_results.values())
    expected_random = 24 / 26  # ~0.92/24
    print(f"\n  Overall best: {overall_best}/24")
    print(f"  Expected random: {expected_random:.1f}/24")

    if overall_best <= 6:
        verdict = "NOISE"
    elif overall_best <= 14:
        verdict = "WEAK — below signal threshold"
    else:
        verdict = "INVESTIGATE"

    print(f"  Verdict: {verdict}")

    results = {
        'experiment': 'E-S-46',
        'total_configs': total_configs,
        'results_by_model': all_results,
        'overall_best': overall_best,
        'verdict': verdict,
        'elapsed_seconds': round(elapsed, 1),
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_46_position_alphabets.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n  Time: {elapsed:.1f}s")
    print(f"  Artifact: results/e_s_46_position_alphabets.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_46_position_alphabets.py")


if __name__ == "__main__":
    main()
