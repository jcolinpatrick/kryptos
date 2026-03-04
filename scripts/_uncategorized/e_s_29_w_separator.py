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
E-S-29: W-Separator Segmentation Analysis

Tests the hypothesis (from glthr/K4nundrum) that the letter 'W' acts as a
separator in K4, splitting the CT into segments with alternating A|B patterns
and matching frequency distributions within groups.

If true, this would be a segmenting-and-recombining technique that defeats
standard cryptanalytic approaches.

Tests:
1. Locate W positions and compute segment sizes
2. Compare frequency distributions of alternating groups (A=0,2,4 vs B=1,3,5)
3. Chi-squared test for same-distribution hypothesis
4. Test recombinations: A-only, B-only, interleaved, reversed
5. IC and autocorrelation of recombined texts
6. Vigenère/Beaufort on recombined segments

Output: results/e_s_29_w_separator.json
"""

import json
import sys
import os
from collections import Counter, defaultdict
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

def ic(nums):
    """Index of coincidence."""
    n = len(nums)
    if n < 2:
        return 0.0
    counts = Counter(nums)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def chi_sq_uniform(nums):
    """Chi-squared vs uniform distribution."""
    n = len(nums)
    expected = n / 26.0
    counts = Counter(nums)
    return sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(26))


def autocorr(nums, lag):
    """Count matches at given lag."""
    return sum(1 for i in range(len(nums) - lag) if nums[i] == nums[i + lag])


def main():
    print("=" * 60)
    print("E-S-29: W-Separator Segmentation Analysis")
    print("=" * 60)

    # Step 1: Find W positions and segments
    w_pos = [i for i, c in enumerate(CT) if c == 'W']
    print(f"\nW positions (0-indexed): {w_pos}")
    print(f"Number of W's: {len(w_pos)}")

    # Build segments (between W's)
    segments = []
    prev = 0
    for wp in w_pos:
        seg = CT[prev:wp]
        segments.append({
            'start': prev,
            'end': wp - 1,
            'text': seg,
            'nums': [ALPH_IDX[c] for c in seg],
            'len': len(seg),
        })
        prev = wp + 1
    # Last segment (after final W)
    seg = CT[prev:]
    segments.append({
        'start': prev,
        'end': len(CT) - 1,
        'text': seg,
        'nums': [ALPH_IDX[c] for c in seg],
        'len': len(seg),
    })

    print(f"\nSegments ({len(segments)}):")
    for i, s in enumerate(segments):
        group = 'A' if i % 2 == 0 else 'B'
        # Check which cribs fall in this segment
        cribs_in = [p for p in CRIB_POS if s['start'] <= p <= s['end']]
        crib_text = ""
        if cribs_in:
            crib_text = f"  [cribs: {cribs_in[0]}-{cribs_in[-1]}]"
        print(f"  Seg {i} ({group}): pos {s['start']:2d}-{s['end']:2d}"
              f"  len={s['len']:2d}  IC={ic(s['nums']):.4f}"
              f"  text={s['text']}{crib_text}")

    # Step 2: Group into A (even) and B (odd)
    group_a_nums = []
    group_b_nums = []
    group_a_text = ""
    group_b_text = ""
    for i, s in enumerate(segments):
        if i % 2 == 0:
            group_a_nums.extend(s['nums'])
            group_a_text += s['text']
        else:
            group_b_nums.extend(s['nums'])
            group_b_text += s['text']

    print(f"\nGroup A (even segments): {len(group_a_nums)} chars")
    print(f"  Text: {group_a_text}")
    print(f"  IC: {ic(group_a_nums):.4f}")
    print(f"  Chi² (uniform): {chi_sq_uniform(group_a_nums):.1f}")

    print(f"\nGroup B (odd segments): {len(group_b_nums)} chars")
    print(f"  Text: {group_b_text}")
    print(f"  IC: {ic(group_b_nums):.4f}")
    print(f"  Chi² (uniform): {chi_sq_uniform(group_b_nums):.1f}")

    # Step 3: Compare frequency distributions
    print(f"\nFrequency comparison (A vs B):")
    count_a = Counter(group_a_nums)
    count_b = Counter(group_b_nums)
    freq_a = {i: count_a.get(i, 0) / len(group_a_nums) for i in range(26)}
    freq_b = {i: count_b.get(i, 0) / len(group_b_nums) for i in range(26)}

    # Chi-squared test for same distribution
    chi2_ab = 0.0
    for i in range(26):
        na = count_a.get(i, 0)
        nb = count_b.get(i, 0)
        expected = (na + nb) / 2.0
        if expected > 0:
            chi2_ab += (na - expected) ** 2 / expected + (nb - expected) ** 2 / expected
    print(f"  Chi² (A vs B same dist): {chi2_ab:.1f} (25 df, p<0.05 if >37.7)")

    # Correlation between A and B frequency vectors
    mean_a = sum(freq_a.values()) / 26
    mean_b = sum(freq_b.values()) / 26
    cov = sum((freq_a[i] - mean_a) * (freq_b[i] - mean_b) for i in range(26))
    std_a = math.sqrt(sum((freq_a[i] - mean_a) ** 2 for i in range(26)))
    std_b = math.sqrt(sum((freq_b[i] - mean_b) ** 2 for i in range(26)))
    corr_ab = cov / (std_a * std_b) if std_a > 0 and std_b > 0 else 0
    print(f"  Correlation(freq_A, freq_B): {corr_ab:.3f}")

    # Step 4: Autocorrelation of full CT vs recombined groups
    print(f"\nAutocorrelation at key lags:")
    for text_name, nums in [("Full CT", CT_NUM),
                             ("Group A", group_a_nums),
                             ("Group B", group_b_nums)]:
        acorrs = []
        for lag in range(1, min(20, len(nums))):
            matches = autocorr(nums, lag)
            expected = (len(nums) - lag) / 26
            z = (matches - expected) / math.sqrt(expected * 25 / 26) if expected > 0 else 0
            if abs(z) > 1.5:
                acorrs.append(f"lag={lag}:z={z:.2f}")
        print(f"  {text_name}: {', '.join(acorrs) if acorrs else 'no significant lags'}")

    # Step 5: Test recombinations
    print(f"\nRecombination tests:")
    recombinations = {
        'A_then_B': group_a_nums + group_b_nums,
        'B_then_A': group_b_nums + group_a_nums,
        'interleave_AB': [],
        'reverse_A_then_B': list(reversed(group_a_nums)) + list(reversed(group_b_nums)),
    }

    # Interleave character by character
    interleaved = []
    ia, ib = 0, 0
    for i in range(len(CT_NUM)):
        if i < len(group_a_nums) + len(group_b_nums):
            if i % 2 == 0 and ia < len(group_a_nums):
                interleaved.append(group_a_nums[ia])
                ia += 1
            elif ib < len(group_b_nums):
                interleaved.append(group_b_nums[ib])
                ib += 1
            elif ia < len(group_a_nums):
                interleaved.append(group_a_nums[ia])
                ia += 1
    recombinations['interleave_AB'] = interleaved

    for name, nums in recombinations.items():
        if len(nums) < 4:
            continue
        ic_val = ic(nums)
        # Crib test: try as direct Vigenère decode with known keystream
        # Check if any period has consistent keys
        for p in [7, 5, 6, 8, 13]:
            from collections import defaultdict as dd
            residue_keys = dd(set)
            consistent = True
            for pos in CRIB_POS:
                if pos < len(nums):
                    k = (nums[pos] - CRIB_PT[pos]) % 26
                    residue_keys[pos % p].add(k)
            n_consistent = sum(1 for r, ks in residue_keys.items() if len(ks) == 1)
            n_total = len(residue_keys)
            if n_consistent == n_total and n_total > 0:
                print(f"  {name}: IC={ic_val:.4f}, p={p} ALL {n_total}/{n_total} consistent!")
        print(f"  {name}: IC={ic_val:.4f}")

    # Step 6: Check where cribs fall relative to segments
    print(f"\nCrib analysis:")
    for pos in CRIB_POS:
        for i, s in enumerate(segments):
            if s['start'] <= pos <= s['end']:
                group = 'A' if i % 2 == 0 else 'B'
                print(f"  pos {pos:2d} (PT={CRIB_DICT[pos]}) → Seg {i} ({group})")
                break

    # Step 7: What if W's aren't separators but mark something else?
    print(f"\n--- Alternative W analysis ---")
    # Positions relative to cribs
    print(f"  W positions: {w_pos}")
    print(f"  ENE crib: 21-33, BC crib: 63-73")
    print(f"  W at 20 is JUST BEFORE ENE crib")
    print(f"  W at 36 is just after: CT[34:37] = '{CT[34:37]}'")

    # Distances between W's
    w_diffs = [w_pos[i+1] - w_pos[i] for i in range(len(w_pos) - 1)]
    print(f"  W-to-W distances: {w_diffs}")
    print(f"  Sum of distances: {sum(w_diffs)}")

    # Step 8: What if we remove all W's and test?
    no_w = [CT_NUM[i] for i in range(CT_LEN) if CT[i] != 'W']
    print(f"\n  CT without W's: {len(no_w)} chars, IC={ic(no_w):.4f}")

    # Save results
    results = {
        "experiment": "E-S-29",
        "w_positions": w_pos,
        "n_segments": len(segments),
        "segment_lengths": [s['len'] for s in segments],
        "group_a_len": len(group_a_nums),
        "group_b_len": len(group_b_nums),
        "group_a_ic": ic(group_a_nums),
        "group_b_ic": ic(group_b_nums),
        "full_ct_ic": ic(CT_NUM),
        "chi2_a_vs_b": chi2_ab,
        "freq_correlation_ab": corr_ab,
        "w_distances": w_diffs,
        "verdict": "TBD",
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_29_w_separator.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nArtifact: results/e_s_29_w_separator.json")
    print(f"Repro: PYTHONPATH=src python3 -u scripts/e_s_29_w_separator.py")


if __name__ == "__main__":
    main()
