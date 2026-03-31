#!/usr/bin/env python3
"""Task 3: Unconstrained brute-force of 7 remaining null positions.

C(56,7) = 231,917,400 masks evaluated with multiprocessing.
Model: extract 73 -> inv_col7 -> DEFECTOR:AZ_beau autokey -> score cribs.

Uses 24 worker processes (leaves 4 cores for system/run_lean).
Partitions by first element of the 7-combination.
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, time, json, os
from itertools import combinations
from multiprocessing import Pool, Manager
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT

CT97 = CT
N = 97; N_PT = 73; N_NULLS = 24

CONSENSUS_17 = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
C17_BEFORE_21 = 8   # count of consensus nulls before pos 21
C17_BEFORE_63 = 12  # count of consensus nulls before pos 63

# Candidate pool: all positions not in consensus_17 and not in cribs
crib_pos = set()
for start, word in [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]:
    for j in range(len(word)):
        crib_pos.add(start + j)
CANDIDATE_POOL = tuple(p for p in range(97) if p not in CONSENSUS_17 and p not in crib_pos)
N_CAND = len(CANDIDATE_POOL)  # 56

# Pre-compute col7 inverse permutation
def columnar_perm(n, width):
    grid = []
    for row in range((n + width - 1) // width):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(len(grid)):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = tuple(reverse_perm(columnar_perm(N_PT, 7)))
CT97_NUM = tuple(ord(c) - 65 for c in CT97)
DEFECTOR_KW = tuple(ord(c) - 65 for c in "DEFECTOR")
ENE_NUMS = tuple(ord(c) - 65 for c in "EASTNORTHEAST")
BCL_NUMS = tuple(ord(c) - 65 for c in "BERLINCLOCK")

# Pre-compute: for each position, whether it's < 21 or < 63
POS_LT_21 = tuple(1 if p < 21 else 0 for p in CANDIDATE_POOL)
POS_LT_63 = tuple(1 if p < 63 else 0 for p in CANDIDATE_POOL)

# Build index mapping: CANDIDATE_POOL[idx] = position
POOL_IDX = {p: i for i, p in enumerate(CANDIDATE_POOL)}

# Pre-build the non-null indices for each possible null set
# This is too large, so we'll compute inline

def worker_func(args):
    """Process a batch of combinations starting with a fixed first element index."""
    first_idx, pool, threshold = args

    local_best = 0
    local_best_data = []
    local_above = []
    local_dist = {}
    local_count = 0

    consensus = CONSENSUS_17
    perm = PERM_COL7
    ct_num = CT97_NUM
    def_kw = DEFECTOR_KW
    ene_n = ENE_NUMS
    bcl_n = BCL_NUMS

    first_pos = pool[first_idx]
    remaining = pool[first_idx + 1:]

    for combo6 in combinations(remaining, 6):
        combo = (first_pos,) + combo6
        ns = consensus | frozenset(combo)

        # Extract 73 chars
        ct73 = []
        for i in range(97):
            if i not in ns:
                ct73.append(ct_num[i])

        # Apply inverse col7
        ct73_t = [ct73[perm[i]] for i in range(73)]

        # Beaufort autokey with DEFECTOR
        pt = [0] * 73
        for i in range(8):
            pt[i] = (def_kw[i] - ct73_t[i]) % 26
        for i in range(8, 73):
            pt[i] = (pt[i - 8] - ct73_t[i]) % 26

        # Crib shift
        eb21 = sum(1 for p in combo if p < 21)
        eb63 = sum(1 for p in combo if p < 63)
        ene_s = 21 - 8 - eb21
        bcl_s = 63 - 12 - eb63

        # Score
        total = 0
        for j in range(13):
            pos = ene_s + j
            if pos < 73 and pt[pos] == ene_n[j]:
                total += 1
        for j in range(11):
            pos = bcl_s + j
            if pos < 73 and pt[pos] == bcl_n[j]:
                total += 1

        local_count += 1
        local_dist[total] = local_dist.get(total, 0) + 1

        if total > local_best:
            local_best = total
            pt_str = ''.join(chr(p + 65) for p in pt)
            local_best_data = [{'score': total, 'varying': list(combo),
                                 'mask': sorted(ns), 'pt': pt_str}]
        elif total == local_best and total >= threshold:
            pt_str = ''.join(chr(p + 65) for p in pt)
            local_best_data.append({'score': total, 'varying': list(combo),
                                     'mask': sorted(ns), 'pt': pt_str})

        if total > 15:
            pt_str = ''.join(chr(p + 65) for p in pt)
            local_above.append({'score': total, 'varying': list(combo),
                                 'mask': sorted(ns), 'pt': pt_str})

    return {
        'first_idx': first_idx,
        'first_pos': first_pos,
        'count': local_count,
        'best': local_best,
        'best_data': local_best_data[:100],  # cap
        'above15': local_above,
        'dist': local_dist,
    }


if __name__ == '__main__':
    from math import comb

    print("=" * 70)
    print("TASK 3: UNCONSTRAINED BRUTE-FORCE (C(56,7) = 231,917,400)")
    print("=" * 70)
    print(f"CT97 = {CT97}")
    print(f"Consensus 17 = {sorted(CONSENSUS_17)}")
    print(f"Candidate pool ({N_CAND}): {CANDIDATE_POOL}")
    print(f"Total combinations: {comb(N_CAND, 7):,}")
    print()

    # Partition: each worker handles all combos starting with pool[i]
    # combo = (pool[i], ... choose 6 from pool[i+1:])
    # Number of combos for first_idx=i: C(N_CAND - 1 - i, 6)
    N_WORKERS = 24

    tasks = []
    total_expected = 0
    for i in range(N_CAND - 6):  # first element can be pool[0] to pool[49]
        n_combos = comb(N_CAND - 1 - i, 6)
        tasks.append((i, CANDIDATE_POOL, 14))
        total_expected += n_combos

    print(f"Partitioned into {len(tasks)} tasks ({total_expected:,} total combos)")
    print(f"Using {N_WORKERS} worker processes")
    print()

    t0 = time.time()

    # Run in parallel
    global_dist = {}
    global_best = 0
    global_best_data = []
    global_above15 = []
    total_count = 0
    completed = 0

    with Pool(N_WORKERS) as pool:
        for result in pool.imap_unordered(worker_func, tasks):
            completed += 1
            total_count += result['count']

            # Merge distributions
            for sc, cnt in result['dist'].items():
                global_dist[sc] = global_dist.get(sc, 0) + cnt

            # Track best
            if result['best'] > global_best:
                global_best = result['best']
                global_best_data = result['best_data']
                elapsed = time.time() - t0
                rate = total_count / elapsed if elapsed > 0 else 0
                print(f"  NEW GLOBAL BEST: {global_best}/24 at first_pos={result['first_pos']} "
                      f"[{completed}/{len(tasks)} tasks, {total_count:,} masks, "
                      f"{rate:.0f}/s, {elapsed:.1f}s]")
                for d in result['best_data'][:3]:
                    print(f"    varying={d['varying']} PT={d['pt'][:40]}...")
                sys.stdout.flush()
            elif result['best'] == global_best and global_best >= 14:
                global_best_data.extend(result['best_data'])

            # Track above-15
            if result['above15']:
                global_above15.extend(result['above15'])
                for d in result['above15']:
                    print(f"  *** ABOVE 15: {d['score']}/24 varying={d['varying']} ***")
                    print(f"      PT={d['pt']}")
                sys.stdout.flush()

            # Progress
            if completed % 5 == 0 or completed == len(tasks):
                elapsed = time.time() - t0
                rate = total_count / elapsed if elapsed > 0 else 0
                remaining = (total_expected - total_count) / rate if rate > 0 else 0
                print(f"  Progress: {completed}/{len(tasks)} tasks, {total_count:,}/{total_expected:,} "
                      f"({total_count / total_expected * 100:.1f}%), "
                      f"rate={rate:.0f}/s, best={global_best}/24, "
                      f"ETA={remaining:.0f}s ({remaining / 60:.1f}m)")
                sys.stdout.flush()

    total_elapsed = time.time() - t0

    print()
    print("=" * 70)
    print("TASK 3 RESULTS")
    print("=" * 70)
    print(f"Total masks evaluated: {total_count:,}")
    print(f"Elapsed: {total_elapsed:.1f}s ({total_elapsed / 60:.1f}m)")
    print(f"Rate: {total_count / total_elapsed:.0f} masks/sec")
    print()

    print("Score Distribution:")
    for sc in sorted(global_dist.keys(), reverse=True):
        pct = global_dist[sc] / total_count * 100
        print(f"  {sc:2d}/24: {global_dist[sc]:>12,} masks ({pct:7.4f}%)")

    print(f"\nGlobal Best: {global_best}/24")
    if global_best >= 15:
        print(f"Number of {global_best}/24 masks: {len(global_best_data)}")
        for d in sorted(global_best_data, key=lambda x: x['varying'])[:50]:
            print(f"  varying={d['varying']} mask={d['mask']}")
            print(f"  PT={d['pt']}")
    elif global_best_data:
        print(f"Number of {global_best}/24 masks: {len(global_best_data)}")
        for d in global_best_data[:20]:
            print(f"  varying={d['varying']}")
            if 'pt' in d:
                print(f"  PT={d['pt']}")

    if global_above15:
        print(f"\n*** MASKS ABOVE 15/24: {len(global_above15)} ***")
        for d in global_above15:
            print(f"  {d['score']}/24 varying={d['varying']} mask={d['mask']}")
            print(f"  PT={d['pt']}")
    else:
        print("\nNo masks above 15/24 found.")

    if global_best > 15:
        print("\n*** CEILING BROKEN! ***")
    elif global_best == 15:
        print("\n15/24 ceiling CONFIRMED across EXHAUSTIVE unconstrained search of 232M masks.")
    else:
        print(f"\nDid NOT reach 15/24 in unconstrained search (best = {global_best}/24).")

    # Task 4: variant testing on top masks
    print()
    print("=" * 70)
    print("TASK 4: VARIANT TESTING ON TOP MASKS FROM TASK 3")
    print("=" * 70)

    KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    KA_IDX = {c: i for i, c in enumerate(KA_STR)}
    AZ_TO_KA = [KA_IDX[chr(i + 65)] for i in range(26)]

    def eval_variant(null_set, keyword, alphabet, cipher, width):
        ct73_raw = [CT97_NUM[i] for i in range(97) if i not in null_set]
        if width > 0:
            perm_v = tuple(reverse_perm(columnar_perm(N_PT, width)))
            ct73_t = [ct73_raw[perm_v[i]] for i in range(73)]
        else:
            ct73_t = ct73_raw
        if alphabet == 'KA':
            ct_alph = [AZ_TO_KA[c] for c in ct73_t]
            kw_nums = [KA_IDX[c] for c in keyword.upper()]
        else:
            ct_alph = ct73_t
            kw_nums = [ord(c) - 65 for c in keyword.upper()]
        L = len(kw_nums)
        pt_n = [0] * 73
        for i in range(73):
            ki = kw_nums[i] if i < L else pt_n[i - L]
            if cipher == 'beau':
                pt_n[i] = (ki - ct_alph[i]) % 26
            elif cipher == 'vig':
                pt_n[i] = (ct_alph[i] - ki) % 26
            else:
                pt_n[i] = (ct_alph[i] + ki) % 26
        if alphabet == 'KA':
            pt_str = ''.join(KA_STR[p] for p in pt_n)
        else:
            pt_str = ''.join(chr(p + 65) for p in pt_n)
        n1 = sum(1 for p in null_set if p < 21)
        n2 = sum(1 for p in null_set if p < 63)
        ene_s = 21 - n1; bcl_s = 63 - n2
        e = sum(1 for j in range(13) if ene_s + j < 73 and pt_str[ene_s + j] == "EASTNORTHEAST"[j])
        b = sum(1 for j in range(11) if bcl_s + j < 73 and pt_str[bcl_s + j] == "BERLINCLOCK"[j])
        return e + b, e, b, pt_str

    variants = [
        ('DEFECTOR', 'AZ', 'beau', 7),
        ('DEFECTOR', 'AZ', 'vig', 7),
        ('DEFECTOR', 'AZ', 'beau', 5),
        ('DEFECTOR', 'AZ', 'beau', 0),
        ('KRYPTOS', 'KA', 'vig', 7),
        ('KRYPTOS', 'KA', 'beau', 7),
        ('KOMPASS', 'KA', 'beau', 7),
        ('KRYPTOS', 'KA', 'vig', 0),
        ('KRYPTOS', 'KA', 'beau', 0),
        ('DEFECTOR', 'AZ', 'beau', 6),
        ('DEFECTOR', 'AZ', 'beau', 8),
        ('DEFECTOR', 'AZ', 'beau', 9),
        ('DEFECTOR', 'AZ', 'beau', 11),
        ('DEFECTOR', 'AZ', 'beau', 13),
        ('ABSCISSA', 'KA', 'vig', 7),
        ('COLOPHON', 'KA', 'vig', 7),
        ('PARALLAX', 'KA', 'vig', 7),
    ]

    # Deduplicate masks at global_best
    seen = set()
    unique_top = []
    for d in global_best_data:
        key = tuple(d['mask'])
        if key not in seen:
            seen.add(key)
            unique_top.append(d)

    print(f"Testing {len(unique_top)} unique top masks across {len(variants)} variants...")

    t4_best = 0
    t4_results = []

    for mi, mask_info in enumerate(unique_top[:200]):  # cap at 200
        null_set = frozenset(mask_info['mask'])
        for kw, alph, cipher, width in variants:
            sc, e, b, pt = eval_variant(null_set, kw, alph, cipher, width)
            label = f"{kw}:{alph}_{cipher}:col{width}"
            if sc >= 14:
                t4_results.append({
                    'score': sc, 'ene': e, 'bcl': b,
                    'variant': label, 'varying': mask_info.get('varying', []),
                    'mask': mask_info['mask'], 'pt': pt
                })
            if sc > t4_best:
                t4_best = sc
                print(f"  T4 new best: {sc}/24 {label} varying={mask_info.get('varying', [])}")
                if sc > 15:
                    print(f"  *** ABOVE 15: PT={pt} ***")

    print(f"\nTask 4 best: {t4_best}/24")
    if t4_results:
        print(f"All >= 14 ({len(t4_results)}):")
        for r in sorted(t4_results, key=lambda x: -x['score'])[:30]:
            print(f"  {r['score']}/24 {r['variant']} e={r['ene']} b={r['bcl']} varying={r['varying']}")

    # Save all results
    results = {
        'task3': {
            'total_masks': total_count,
            'elapsed_s': total_elapsed,
            'rate_per_sec': total_count / total_elapsed,
            'global_best': global_best,
            'n_at_best': len(global_best_data),
            'above_15': global_above15,
            'score_dist': {str(k): v for k, v in sorted(global_dist.items())},
            'top_masks': [d for d in global_best_data[:100]],
        },
        'task4': {
            'best': t4_best,
            'results_14plus': t4_results[:100],
        },
        'consensus_17': sorted(CONSENSUS_17),
        'candidate_pool': list(CANDIDATE_POOL),
    }

    with open('results/bruteforce_7remaining_task3.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved results/bruteforce_7remaining_task3.json")

    print()
    print("=" * 70)
    print("FINAL VERDICT")
    print("=" * 70)
    overall = max(global_best, t4_best)
    print(f"Task 3 (232M masks, DEFECTOR:AZ_beau+col7): best {global_best}/24")
    print(f"Task 4 (variants on top masks): best {t4_best}/24")
    if overall > 15:
        print("*** CEILING BROKEN! ***")
    elif overall == 15:
        print("15/24 CEILING CONFIRMED across 232M exhaustive unconstrained masks.")
    else:
        print(f"Best {overall}/24 -- 15/24 ceiling NOT reached outside cluster region.")
