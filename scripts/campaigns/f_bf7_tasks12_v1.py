#!/usr/bin/env python3
"""Tasks 1-2: Brute-force 7 remaining null positions (cluster-constrained + wider).
Fast enough in pure Python (~12K masks total).
"""
import sys, time, json
from itertools import combinations
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97 = CT
N = 97; N_PT = 73; N_NULLS = 24
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63

CONSENSUS_17 = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
CLUSTER_A = [38,39,40,41,42,43,44,45]
CLUSTER_B = [55,56]
CLUSTER_C = [87,88]
CLUSTER_D = [93,94,95,96]
CLUSTER_UNION = sorted(set(CLUSTER_A + CLUSTER_B + CLUSTER_C + CLUSTER_D))

# Col7 inverse permutation
def columnar_perm(n, width):
    grid = []
    for row in range((n + width - 1) // width):
        start = row * width
        grid.append(list(range(start, min(start+width, n))))
    perm = []
    for col in range(width):
        for row in range(len(grid)):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0]*len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = tuple(reverse_perm(columnar_perm(N_PT, 7)))
CT97_NUM = tuple(ord(c)-65 for c in CT97)
DEFECTOR_KW = tuple(ord(c)-65 for c in "DEFECTOR")
ENE_NUMS = tuple(ord(c)-65 for c in ENE_WORD)
BCL_NUMS = tuple(ord(c)-65 for c in BCL_WORD)

# Pre-count consensus nulls before 21 and 63
C17_BEFORE_21 = sum(1 for p in CONSENSUS_17 if p < 21)  # 8
C17_BEFORE_63 = sum(1 for p in CONSENSUS_17 if p < 63)  # 12

def eval_mask(varying_tuple):
    """Evaluate mask = consensus_17 + varying_tuple (7 positions)."""
    ns = CONSENSUS_17 | frozenset(varying_tuple)

    # Extract 73 chars
    ct73 = [CT97_NUM[i] for i in range(97) if i not in ns]
    # Inv col7
    ct73_t = [ct73[PERM_COL7[i]] for i in range(73)]
    # Beaufort autokey DEFECTOR
    pt = [0]*73
    for i in range(8):
        pt[i] = (DEFECTOR_KW[i] - ct73_t[i]) % 26
    for i in range(8, 73):
        pt[i] = (pt[i-8] - ct73_t[i]) % 26

    # Shifted crib positions
    extra_b21 = sum(1 for p in varying_tuple if p < 21)
    extra_b63 = sum(1 for p in varying_tuple if p < 63)
    ene_s = 21 - C17_BEFORE_21 - extra_b21
    bcl_s = 63 - C17_BEFORE_63 - extra_b63

    e = sum(1 for j in range(13) if ene_s+j < 73 and pt[ene_s+j] == ENE_NUMS[j])
    b = sum(1 for j in range(11) if bcl_s+j < 73 and pt[bcl_s+j] == BCL_NUMS[j])

    pt_str = ''.join(chr(p+65) for p in pt)
    return e+b, e, b, pt_str

# Verify known seeds
print("="*70)
print("VERIFICATION OF KNOWN 15/24 SEEDS")
print("="*70)

SEEDS_15 = [
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95],
    [0,1,2,5,8,12,14,20,36,39,41,42,52,55,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,38,39,45,52,56,58,59,74,75,78,84,85,87,93,95],
    [0,1,2,5,8,12,14,20,36,41,42,44,52,55,58,59,74,75,78,84,85,88,93,96],
]

for i, mask in enumerate(SEEDS_15):
    varying = tuple(p for p in mask if p not in CONSENSUS_17)
    sc, e, b, pt = eval_mask(varying)
    status = "OK" if sc == 15 else f"FAIL (expected 15)"
    print(f"  Seed {i}: {sc}/24 ene={e}/13 bcl={b}/11 varying={sorted(varying)} [{status}]")

print()

# ======================================================================
# TASK 1
# ======================================================================
print("="*70)
print("TASK 1: CLUSTER-CONSTRAINED (C(8,3)*C(2,1)*C(2,1)*C(4,2) = 1,344)")
print("="*70)

t1_start = time.time()
score_dist = {}
results_14plus = []
best_score = 0
best_masks = []

for a in combinations(CLUSTER_A, 3):
    for b in combinations(CLUSTER_B, 1):
        for c in combinations(CLUSTER_C, 1):
            for d in combinations(CLUSTER_D, 2):
                varying = a + b + c + d
                sc, e, b_sc, pt = eval_mask(varying)
                score_dist[sc] = score_dist.get(sc, 0) + 1

                if sc >= 14:
                    results_14plus.append({
                        'score': sc, 'ene': e, 'bcl': b_sc,
                        'pt': pt, 'varying': sorted(varying)
                    })
                if sc > best_score:
                    best_score = sc
                    best_masks = [{'score': sc, 'ene': e, 'bcl': b_sc,
                                   'pt': pt, 'varying': sorted(varying)}]
                elif sc == best_score:
                    best_masks.append({'score': sc, 'ene': e, 'bcl': b_sc,
                                       'pt': pt, 'varying': sorted(varying)})

t1_elapsed = time.time() - t1_start
total_t1 = sum(score_dist.values())

print(f"\nEvaluated {total_t1} masks in {t1_elapsed:.2f}s")
print(f"\nScore Distribution:")
for sc in sorted(score_dist.keys(), reverse=True):
    bar = '#' * (score_dist[sc] * 40 // max(score_dist.values()))
    print(f"  {sc:2d}/24: {score_dist[sc]:5d} ({score_dist[sc]/total_t1*100:5.1f}%) {bar}")

print(f"\nBest: {best_score}/24 ({len(best_masks)} masks)")
if best_score >= 16:
    print("*** BREAKTHROUGH: EXCEEDS 15/24! ***")

for m in sorted(best_masks, key=lambda x: (-x['score'], x['varying']))[:20]:
    print(f"  {m['score']}/24 e={m['ene']}/13 b={m['bcl']}/11 varying={m['varying']}")
    print(f"       PT={m['pt']}")

if results_14plus:
    print(f"\nAll >= 14/24 ({len(results_14plus)} masks):")
    for m in sorted(results_14plus, key=lambda x: (-x['score'], x['varying']))[:40]:
        print(f"  {m['score']}/24 e={m['ene']}/13 b={m['bcl']}/11 varying={m['varying']}")

print()

# ======================================================================
# TASK 2
# ======================================================================
print("="*70)
print(f"TASK 2: ANY 7 FROM CLUSTER UNION (C(16,7) = 11,440)")
print("="*70)

t2_start = time.time()
score_dist2 = {}
results2_14plus = []
best_score2 = 0
best_masks2 = []

for combo in combinations(CLUSTER_UNION, 7):
    ns = CONSENSUS_17 | frozenset(combo)
    if len(ns) != 24:
        continue
    sc, e, b_sc, pt = eval_mask(combo)
    score_dist2[sc] = score_dist2.get(sc, 0) + 1

    if sc >= 14:
        results2_14plus.append({
            'score': sc, 'ene': e, 'bcl': b_sc,
            'pt': pt, 'varying': sorted(combo)
        })
    if sc > best_score2:
        best_score2 = sc
        best_masks2 = [{'score': sc, 'ene': e, 'bcl': b_sc,
                         'pt': pt, 'varying': sorted(combo)}]
    elif sc == best_score2:
        best_masks2.append({'score': sc, 'ene': e, 'bcl': b_sc,
                             'pt': pt, 'varying': sorted(combo)})

t2_elapsed = time.time() - t2_start
total_t2 = sum(score_dist2.values())

print(f"\nEvaluated {total_t2} masks in {t2_elapsed:.2f}s")
print(f"\nScore Distribution:")
for sc in sorted(score_dist2.keys(), reverse=True):
    bar = '#' * (score_dist2[sc] * 40 // max(score_dist2.values()))
    print(f"  {sc:2d}/24: {score_dist2[sc]:5d} ({score_dist2[sc]/total_t2*100:5.1f}%) {bar}")

print(f"\nBest: {best_score2}/24 ({len(best_masks2)} masks)")
if best_score2 >= 16:
    print("*** BREAKTHROUGH: EXCEEDS 15/24! ***")

for m in sorted(best_masks2, key=lambda x: (-x['score'], x['varying']))[:20]:
    print(f"  {m['score']}/24 e={m['ene']}/13 b={m['bcl']}/11 varying={m['varying']}")
    print(f"       PT={m['pt']}")

if results2_14plus:
    print(f"\nAll >= 14/24 ({len(results2_14plus)} masks):")
    for m in sorted(results2_14plus, key=lambda x: (-x['score'], x['varying']))[:40]:
        print(f"  {m['score']}/24 e={m['ene']}/13 b={m['bcl']}/11 varying={m['varying']}")

# Task 4 variant testing on the best masks from Tasks 1 + 2
print()
print("="*70)
print("TASK 4 (partial): VARIANT TESTING ON MASKS >= 14/24")
print("="*70)

KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[chr(i+65)] for i in range(26)]

def eval_variant(varying, keyword, alphabet, cipher, width):
    ns = CONSENSUS_17 | frozenset(varying)
    ct73_raw = [CT97_NUM[i] for i in range(97) if i not in ns]

    if width > 0:
        perm = tuple(reverse_perm(columnar_perm(N_PT, width)))
        ct73_t = [ct73_raw[perm[i]] for i in range(73)]
    else:
        ct73_t = ct73_raw

    if alphabet == 'KA':
        ct_alph = [AZ_TO_KA[c] for c in ct73_t]
        kw_nums = [KA_IDX[c] for c in keyword.upper()]
    else:
        ct_alph = ct73_t
        kw_nums = [ord(c)-65 for c in keyword.upper()]

    L = len(kw_nums)
    pt = [0]*73
    for i in range(73):
        ki = kw_nums[i] if i < L else pt[i - L]
        if cipher == 'beau':
            pt[i] = (ki - ct_alph[i]) % 26
        elif cipher == 'vig':
            pt[i] = (ct_alph[i] - ki) % 26
        else:
            pt[i] = (ct_alph[i] + ki) % 26

    if alphabet == 'KA':
        pt_str = ''.join(KA_STR[p] for p in pt)
    else:
        pt_str = ''.join(chr(p+65) for p in pt)

    extra_b21 = sum(1 for p in varying if p < 21)
    extra_b63 = sum(1 for p in varying if p < 63)
    ene_s = 21 - C17_BEFORE_21 - extra_b21
    bcl_s = 63 - C17_BEFORE_63 - extra_b63

    e = sum(1 for j in range(13) if ene_s+j < 73 and pt_str[ene_s+j] == ENE_WORD[j])
    b = sum(1 for j in range(11) if bcl_s+j < 73 and pt_str[bcl_s+j] == BCL_WORD[j])
    return e+b, e, b, pt_str

variants = [
    ('DEFECTOR', 'AZ', 'beau', 7),
    ('DEFECTOR', 'AZ', 'vig', 7),
    ('DEFECTOR', 'AZ', 'beau', 5),
    ('DEFECTOR', 'AZ', 'beau', 0),
    ('KRYPTOS',  'KA', 'vig', 7),
    ('KRYPTOS',  'KA', 'beau', 7),
    ('KOMPASS',  'KA', 'beau', 7),
    ('KRYPTOS',  'KA', 'vig', 0),
    ('KRYPTOS',  'KA', 'beau', 0),
    ('DEFECTOR', 'AZ', 'beau', 6),
    ('DEFECTOR', 'AZ', 'beau', 8),
    ('DEFECTOR', 'AZ', 'beau', 9),
    ('DEFECTOR', 'AZ', 'beau', 11),
    ('DEFECTOR', 'AZ', 'beau', 13),
    ('ABSCISSA', 'KA', 'vig', 7),
    ('COLOPHON', 'KA', 'vig', 7),
    ('PARALLAX', 'KA', 'vig', 7),
]

all_14_masks = set()
for r in results_14plus + results2_14plus:
    all_14_masks.add(tuple(sorted(r['varying'])))

t4_best = 0
t4_results = []

for varying in all_14_masks:
    for kw, alph, cipher, width in variants:
        sc, e, b_sc, pt = eval_variant(varying, kw, alph, cipher, width)
        label = f"{kw}:{alph}_{cipher}:col{width}"
        if sc >= 14:
            t4_results.append({
                'score': sc, 'ene': e, 'bcl': b_sc,
                'variant': label, 'varying': sorted(varying), 'pt': pt
            })
        if sc > t4_best:
            t4_best = sc
            print(f"  New best: {sc}/24 {label} varying={sorted(varying)}")
            if sc > 15:
                print(f"  *** ABOVE 15: PT={pt} ***")

print(f"\nTask 4 best: {t4_best}/24")
if t4_results:
    print(f"All >= 14 ({len(t4_results)}):")
    for r in sorted(t4_results, key=lambda x: -x['score'])[:30]:
        print(f"  {r['score']}/24 {r['variant']} e={r['ene']} b={r['bcl']} varying={r['varying']}")

# ======================================================================
# SUMMARY
# ======================================================================
print()
print("="*70)
print("TASKS 1+2+4 SUMMARY")
print("="*70)
print(f"Task 1 (1,344 cluster masks): best {best_score}/24")
print(f"Task 2 (11,440 wider masks): best {best_score2}/24")
print(f"Task 4 (variants): best {t4_best}/24")
gmax = max(best_score, best_score2, t4_best)
print(f"GLOBAL BEST = {gmax}/24")
if gmax > 15:
    print("*** CEILING BROKEN ***")
elif gmax == 15:
    print("15/24 ceiling CONFIRMED within cluster-constrained and wider search")
else:
    print(f"DID NOT reach 15/24 within cluster searches")

total_time = time.time() - t1_start
print(f"Total time: {total_time:.1f}s")

# Save
results_all = {
    'task1': {'count': total_t1, 'best': best_score, 'score_dist': score_dist,
              'results_14plus': results_14plus, 'best_masks': best_masks[:20]},
    'task2': {'count': total_t2, 'best': best_score2, 'score_dist': score_dist2,
              'results_14plus': results2_14plus, 'best_masks': best_masks2[:20]},
    'task4': {'best': t4_best, 'results_14plus': t4_results},
    'global_best': gmax,
    'elapsed_s': total_time,
}
with open('results/bruteforce_7remaining_tasks12.json', 'w') as f:
    json.dump(results_all, f, indent=2, default=str)
print("Saved results/bruteforce_7remaining_tasks12.json")
