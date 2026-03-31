#!/usr/bin/env python3
"""Brute-force the 7 remaining null positions (17 consensus fixed).

TASK 1: Cluster-constrained (1,344 masks)
  Cluster A: {38..45} pick 3, B: {55,56} pick 1, C: {87,88} pick 1, D: {93..96} pick 2
TASK 2: Any 7 from 16-position cluster union (11,440 masks)
TASK 3: Any 7 from all non-consensus non-crib positions (~232M masks)
TASK 4: Variant testing on best masks from Tasks 1-3

Model: extract 73 -> inv col7 -> DEFECTOR:AZ_beau autokey -> score cribs
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, time, json
from itertools import combinations
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97     = CT
N        = 97
N_NULLS  = 24
N_PT     = 73
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START= 21
BCL_START = 63
NON_CRIB = sorted(i for i in range(N) if i not in CRIB_POSITIONS)
NC_SET   = frozenset(NON_CRIB)

CONSENSUS_17 = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})

# Clusters from SA variation analysis
CLUSTER_A = [38,39,40,41,42,43,44,45]  # pick 3
CLUSTER_B = [55,56]                      # pick 1
CLUSTER_C = [87,88]                      # pick 1
CLUSTER_D = [93,94,95,96]               # pick 2
CLUSTER_UNION = sorted(set(CLUSTER_A + CLUSTER_B + CLUSTER_C + CLUSTER_D))

# Pre-compute col7 inverse permutation for 73-char text
def columnar_perm(n, width):
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start+width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0]*len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = reverse_perm(columnar_perm(N_PT, 7))

# Pre-compute CT as numeric array
CT97_NUM = [ord(c)-65 for c in CT97]

# DEFECTOR keyword
DEFECTOR_KW = [ord(c)-65 for c in "DEFECTOR"]
DEF_LEN = len(DEFECTOR_KW)

def eval_mask(null_set):
    """Evaluate a null mask: extract 73, inv col7, DEFECTOR:AZ_beau autokey, score cribs."""
    # Extract 73 chars (numeric)
    ct73 = [CT97_NUM[i] for i in range(N) if i not in null_set]

    # Apply inverse col7 transposition
    ct73_t = [ct73[PERM_COL7[i]] for i in range(N_PT)]

    # Beaufort autokey decrypt with DEFECTOR
    pt = []
    for i, ci in enumerate(ct73_t):
        ki = DEFECTOR_KW[i] if i < DEF_LEN else pt[i - DEF_LEN]
        pi = (ki - ci) % 26
        pt.append(pi)

    # Count nulls before crib starts for position shifting
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2

    # Score against cribs
    ene_nums = [ord(c)-65 for c in ENE_WORD]
    bcl_nums = [ord(c)-65 for c in BCL_WORD]

    e = sum(1 for j in range(len(ENE_WORD)) if ene_s+j < N_PT and pt[ene_s+j] == ene_nums[j])
    b = sum(1 for j in range(len(BCL_WORD)) if bcl_s+j < N_PT and pt[bcl_s+j] == bcl_nums[j])

    total = e + b
    pt_str = ''.join(chr(p+65) for p in pt)
    return total, e, b, pt_str

def eval_mask_fast(null_set_frozen):
    """Same as eval_mask but takes frozen set."""
    return eval_mask(null_set_frozen)

# Also build variant evaluators for Task 4
AZ_IDX = {c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ")}
KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}

def eval_mask_variant(null_set, keyword, alphabet, cipher_variant, width):
    """Evaluate with different keyword/alphabet/cipher/transposition width."""
    # Extract 73 chars
    ct73_raw = [CT97_NUM[i] for i in range(N) if i not in null_set]

    if width > 0:
        perm = reverse_perm(columnar_perm(N_PT, width))
        ct73_t = [ct73_raw[perm[i]] for i in range(N_PT)]
    else:
        ct73_t = ct73_raw  # no transposition

    # Convert to target alphabet if KA
    if alphabet == 'KA':
        AZ_TO_KA = [KA_IDX[chr(i+65)] for i in range(26)]
        ct_alph = [AZ_TO_KA[c] for c in ct73_t]
        kw_nums = [KA_IDX[c] for c in keyword.upper()]
    else:
        ct_alph = ct73_t
        kw_nums = [ord(c)-65 for c in keyword.upper()]

    L = len(kw_nums)

    # Autokey decrypt
    pt_nums = []
    for i, ci in enumerate(ct_alph):
        ki = kw_nums[i] if i < L else pt_nums[i - L]
        if cipher_variant == 'beau':
            pi = (ki - ci) % 26
        elif cipher_variant == 'vig':
            pi = (ci - ki) % 26
        else:  # vbeau
            pi = (ci + ki) % 26
        pt_nums.append(pi)

    # Convert back to letters
    if alphabet == 'KA':
        pt_str = ''.join(KA_STR[p] for p in pt_nums)
    else:
        pt_str = ''.join(chr(p+65) for p in pt_nums)

    # Score
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2

    e = sum(1 for j, c in enumerate(ENE_WORD) if ene_s+j < N_PT and pt_str[ene_s+j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD) if bcl_s+j < N_PT and pt_str[bcl_s+j] == c)

    return e+b, e, b, pt_str


print("="*70)
print("BRUTE FORCE 7 REMAINING NULL POSITIONS")
print("="*70)
print(f"CT97 = {CT97}")
print(f"Consensus 17 = {sorted(CONSENSUS_17)}")
print(f"Model: extract 73 -> inv_col7 -> DEFECTOR:AZ_beau autokey -> cribs")
print()

# Verify known seeds first
SEEDS_15 = [
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95],
    [0,1,2,5,8,12,14,20,36,39,41,42,52,55,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,38,39,45,52,56,58,59,74,75,78,84,85,87,93,95],
    [0,1,2,5,8,12,14,20,36,41,42,44,52,55,58,59,74,75,78,84,85,88,93,96],
]

print("=== Seed Verification ===")
for i, mask in enumerate(SEEDS_15):
    sc, e, b, pt = eval_mask(frozenset(mask))
    print(f"  Seed {i}: {sc}/24 ene={e}/13 bcl={b}/11")
    if sc != 15:
        print(f"  *** WARNING: Seed {i} gives {sc}/24, expected 15/24 ***")
print()

# ======================================================================
# TASK 1: Cluster-constrained search (1,344 masks)
# ======================================================================
print("="*70)
print("TASK 1: CLUSTER-CONSTRAINED SEARCH")
print(f"  A={CLUSTER_A} pick 3 -> C(8,3)=56")
print(f"  B={CLUSTER_B} pick 1 -> C(2,1)=2")
print(f"  C={CLUSTER_C} pick 1 -> C(2,1)=2")
print(f"  D={CLUSTER_D} pick 2 -> C(4,2)=6")
print(f"  Total: 56*2*2*6 = 1,344 masks")
print("="*70)

t1_start = time.time()
score_dist = {}
best_score = 0
best_masks = []
all_results = []

count = 0
for a_combo in combinations(CLUSTER_A, 3):
    for b_combo in combinations(CLUSTER_B, 1):
        for c_combo in combinations(CLUSTER_C, 1):
            for d_combo in combinations(CLUSTER_D, 2):
                varying = frozenset(a_combo + b_combo + c_combo + d_combo)
                null_set = CONSENSUS_17 | varying
                assert len(null_set) == 24, f"Expected 24, got {len(null_set)}"

                sc, e, b_sc, pt = eval_mask(null_set)
                count += 1

                score_dist[sc] = score_dist.get(sc, 0) + 1

                if sc >= 14:
                    mask_sorted = sorted(null_set)
                    all_results.append({
                        'score': sc, 'ene': e, 'bcl': b_sc,
                        'pt': pt, 'mask': mask_sorted,
                        'varying': sorted(varying)
                    })

                if sc > best_score:
                    best_score = sc
                    best_masks = [{'score': sc, 'ene': e, 'bcl': b_sc,
                                   'pt': pt, 'mask': sorted(null_set),
                                   'varying': sorted(varying)}]
                elif sc == best_score:
                    best_masks.append({'score': sc, 'ene': e, 'bcl': b_sc,
                                       'pt': pt, 'mask': sorted(null_set),
                                       'varying': sorted(varying)})

t1_elapsed = time.time() - t1_start

print(f"\nTask 1 complete: {count} masks evaluated in {t1_elapsed:.1f}s")
print(f"\n--- Score Distribution ---")
for sc in sorted(score_dist.keys(), reverse=True):
    pct = score_dist[sc] / count * 100
    print(f"  {sc:2d}/24: {score_dist[sc]:5d} masks ({pct:5.1f}%)")

print(f"\n--- Best Score: {best_score}/24 ({len(best_masks)} masks) ---")
for i, m in enumerate(best_masks[:20]):
    print(f"  [{i}] {m['score']}/24 ene={m['ene']}/13 bcl={m['bcl']}/11 varying={m['varying']}")
    print(f"      PT={m['pt']}")

if best_score >= 16:
    print("\n*** BREAKTHROUGH: SCORE EXCEEDS 15/24 CEILING! ***")
elif best_score >= 15:
    print(f"\n--- All masks scoring >= 15/24 ---")
    for m in [r for r in all_results if r['score'] >= 15]:
        print(f"  {m['score']}/24 ene={m['ene']}/13 bcl={m['bcl']}/11 varying={m['varying']} mask={m['mask']}")
        print(f"  PT={m['pt']}")

if all_results:
    print(f"\n--- All masks scoring >= 14/24 ({len(all_results)} masks) ---")
    for m in sorted(all_results, key=lambda x: -x['score'])[:30]:
        print(f"  {m['score']}/24 ene={m['ene']}/13 bcl={m['bcl']}/11 varying={m['varying']}")

print()

# ======================================================================
# TASK 2: Wider search - any 7 from 16-position cluster union (11,440)
# ======================================================================
print("="*70)
print("TASK 2: ANY 7 FROM 16-POSITION CLUSTER UNION")
print(f"  Union = {CLUSTER_UNION}")
print(f"  C(16,7) = 11,440 masks")
print("="*70)

t2_start = time.time()
score_dist2 = {}
best_score2 = 0
best_masks2 = []
all_results2 = []
count2 = 0

for combo in combinations(CLUSTER_UNION, 7):
    varying = frozenset(combo)
    null_set = CONSENSUS_17 | varying
    if len(null_set) != 24:
        continue  # shouldn't happen but safety check

    sc, e, b_sc, pt = eval_mask(null_set)
    count2 += 1

    score_dist2[sc] = score_dist2.get(sc, 0) + 1

    if sc >= 14:
        all_results2.append({
            'score': sc, 'ene': e, 'bcl': b_sc,
            'pt': pt, 'mask': sorted(null_set),
            'varying': sorted(varying)
        })

    if sc > best_score2:
        best_score2 = sc
        best_masks2 = [{'score': sc, 'ene': e, 'bcl': b_sc,
                         'pt': pt, 'mask': sorted(null_set),
                         'varying': sorted(varying)}]
    elif sc == best_score2:
        best_masks2.append({'score': sc, 'ene': e, 'bcl': b_sc,
                             'pt': pt, 'mask': sorted(null_set),
                             'varying': sorted(varying)})

t2_elapsed = time.time() - t2_start

print(f"\nTask 2 complete: {count2} masks evaluated in {t2_elapsed:.1f}s")
print(f"\n--- Score Distribution ---")
for sc in sorted(score_dist2.keys(), reverse=True):
    pct = score_dist2[sc] / count2 * 100
    print(f"  {sc:2d}/24: {score_dist2[sc]:5d} masks ({pct:5.1f}%)")

print(f"\n--- Best Score: {best_score2}/24 ({len(best_masks2)} masks) ---")
for i, m in enumerate(best_masks2[:20]):
    print(f"  [{i}] {m['score']}/24 ene={m['ene']}/13 bcl={m['bcl']}/11 varying={m['varying']}")
    print(f"      PT={m['pt']}")

if best_score2 >= 16:
    print("\n*** BREAKTHROUGH: SCORE EXCEEDS 15/24 CEILING! ***")

if all_results2:
    print(f"\n--- All masks scoring >= 14/24 ({len(all_results2)} masks) ---")
    for m in sorted(all_results2, key=lambda x: -x['score'])[:30]:
        print(f"  {m['score']}/24 ene={m['ene']}/13 bcl={m['bcl']}/11 varying={m['varying']}")

print()

# ======================================================================
# TASK 3: Unconstrained search - any 7 from all valid positions
# ======================================================================
print("="*70)
print("TASK 3: UNCONSTRAINED SEARCH — any 7 from all valid positions")

# Valid positions: not in consensus 17, not in crib positions
# Crib positions: 21-33 and 63-73
crib_pos = set()
for start, word in [(21, ENE_WORD), (63, BCL_WORD)]:
    for j in range(len(word)):
        crib_pos.add(start + j)

# Candidates: all 97 positions minus consensus 17 minus crib 24
# But consensus 17 already excludes crib positions (no overlap)
candidate_pool = sorted(p for p in range(N) if p not in CONSENSUS_17 and p not in crib_pos)
n_cand = len(candidate_pool)
from math import comb
total_combos = comb(n_cand, 7)
print(f"  Candidate pool: {n_cand} positions, C({n_cand},7) = {total_combos:,} masks")
print("="*70)

# For ~232M, we need to optimize heavily
# Strategy: fully inline everything with pre-computed arrays

# Pre-compute which CT positions correspond to each null mask selection
# The inner loop needs to be as fast as possible

t3_start = time.time()
score_dist3 = {}
best_score3 = 0
best_masks3 = []
count3 = 0
above15_masks = []

# Pre-compute ENE/BCL numeric
ENE_NUMS = tuple(ord(c)-65 for c in ENE_WORD)
BCL_NUMS = tuple(ord(c)-65 for c in BCL_WORD)

# For fast iteration, pre-compute the consensus mask as a sorted list
# and work with position arrays
CONSENSUS_LIST = sorted(CONSENSUS_17)
CT97_TUPLE = tuple(CT97_NUM)
PERM_COL7_TUPLE = tuple(PERM_COL7)
DEF_TUPLE = tuple(DEFECTOR_KW)

# Milestone tracking
milestone_interval = 5_000_000
next_milestone = milestone_interval

def eval_mask_inline(null_set_sorted):
    """Fully inlined evaluation for speed."""
    # null_set_sorted is a sorted list of 24 positions
    ns = set(null_set_sorted)

    # Extract 73 chars
    ct73 = []
    for i in range(97):
        if i not in ns:
            ct73.append(CT97_TUPLE[i])

    # Apply inverse col7
    ct73_t = [ct73[PERM_COL7_TUPLE[i]] for i in range(73)]

    # Beaufort autokey with DEFECTOR
    pt = [0]*73
    for i in range(73):
        ci = ct73_t[i]
        ki = DEF_TUPLE[i] if i < 8 else pt[i-8]
        pt[i] = (ki - ci) % 26

    # Count nulls before crib starts
    n1 = 0
    for p in null_set_sorted:
        if p < 21:
            n1 += 1
        else:
            break
    n2 = 0
    for p in null_set_sorted:
        if p < 63:
            n2 += 1

    ene_s = 21 - n1
    bcl_s = 63 - n2

    # Score ENE
    total = 0
    for j in range(13):
        pos = ene_s + j
        if pos < 73 and pt[pos] == ENE_NUMS[j]:
            total += 1
    # Score BCL
    for j in range(11):
        pos = bcl_s + j
        if pos < 73 and pt[pos] == BCL_NUMS[j]:
            total += 1

    return total

print(f"\nStarting exhaustive search of {total_combos:,} masks...")
print(f"Estimated time: {total_combos * 5e-6:.0f}s at 200K masks/sec")
sys.stdout.flush()

# The consensus_17 null count before pos 21 and pos 63
c17_before_21 = sum(1 for p in CONSENSUS_LIST if p < 21)  # {0,1,2,5,8,12,14,20} = 8
c17_before_63 = sum(1 for p in CONSENSUS_LIST if p < 63)  # add {36,52,58,59} = 12

for combo in combinations(candidate_pool, 7):
    # Build full null set (sorted)
    # Merge consensus_17 and combo (both sorted)
    # Fast merge
    null_24 = sorted(CONSENSUS_LIST + list(combo))

    # Count additional nulls before 21 and 63
    extra_before_21 = sum(1 for p in combo if p < 21)
    extra_before_63 = sum(1 for p in combo if p < 63)
    n1 = c17_before_21 + extra_before_21
    n2 = c17_before_63 + extra_before_63

    # Extract 73 chars inline
    ns = set(null_24)
    ct73 = [CT97_TUPLE[i] for i in range(97) if i not in ns]

    # Apply inverse col7
    ct73_t = [ct73[PERM_COL7_TUPLE[i]] for i in range(73)]

    # Beaufort autokey with DEFECTOR
    pt = [0]*73
    for i in range(8):
        pt[i] = (DEF_TUPLE[i] - ct73_t[i]) % 26
    for i in range(8, 73):
        pt[i] = (pt[i-8] - ct73_t[i]) % 26

    ene_s = 21 - n1
    bcl_s = 63 - n2

    # Score
    total = 0
    for j in range(13):
        pos = ene_s + j
        if pos < 73 and pt[pos] == ENE_NUMS[j]:
            total += 1
    for j in range(11):
        pos = bcl_s + j
        if pos < 73 and pt[pos] == BCL_NUMS[j]:
            total += 1

    count3 += 1
    score_dist3[total] = score_dist3.get(total, 0) + 1

    if total > best_score3:
        best_score3 = total
        pt_str = ''.join(chr(p+65) for p in pt)
        best_masks3 = [{'score': total, 'mask': null_24, 'varying': list(combo), 'pt': pt_str,
                        'n1': n1, 'n2': n2}]
        print(f"  NEW BEST: {total}/24 at combo {combo} [{count3:,}/{total_combos:,}]")
        sys.stdout.flush()
    elif total == best_score3 and total >= 15:
        pt_str = ''.join(chr(p+65) for p in pt)
        best_masks3.append({'score': total, 'mask': null_24, 'varying': list(combo), 'pt': pt_str,
                            'n1': n1, 'n2': n2})

    if total > 15:
        pt_str = ''.join(chr(p+65) for p in pt)
        above15_masks.append({'score': total, 'mask': null_24, 'varying': list(combo), 'pt': pt_str})
        print(f"  *** ABOVE 15: {total}/24 mask={null_24} ***")
        sys.stdout.flush()

    if count3 >= next_milestone:
        elapsed = time.time() - t3_start
        rate = count3 / elapsed
        remaining = (total_combos - count3) / rate
        print(f"  Progress: {count3:,}/{total_combos:,} ({count3/total_combos*100:.1f}%) "
              f"rate={rate:.0f}/s best={best_score3}/24 "
              f"ETA={remaining:.0f}s ({remaining/60:.1f}m)")
        sys.stdout.flush()
        next_milestone += milestone_interval

t3_elapsed = time.time() - t3_start

print(f"\nTask 3 complete: {count3:,} masks evaluated in {t3_elapsed:.1f}s ({count3/t3_elapsed:.0f}/s)")
print(f"\n--- Score Distribution ---")
for sc in sorted(score_dist3.keys(), reverse=True):
    pct = score_dist3[sc] / count3 * 100
    print(f"  {sc:2d}/24: {score_dist3.get(sc, 0):>10,} masks ({pct:6.3f}%)")

print(f"\n--- Best Score: {best_score3}/24 ({len(best_masks3)} masks) ---")
for i, m in enumerate(best_masks3[:50]):
    print(f"  [{i}] {m['score']}/24 varying={m['varying']} mask={m['mask']}")
    if 'pt' in m:
        print(f"      PT={m['pt']}")

if best_score3 >= 16:
    print("\n*** BREAKTHROUGH: SCORE EXCEEDS 15/24 CEILING! ***")
    print(f"*** {len(above15_masks)} masks above 15/24 ***")
    for m in above15_masks:
        print(f"  {m['score']}/24 mask={m['mask']} PT={m['pt']}")

print()

# ======================================================================
# TASK 4: Variant testing on best masks
# ======================================================================
print("="*70)
print("TASK 4: VARIANT TESTING ON BEST MASKS")
print("="*70)

# Collect all masks scoring >= 14 from all tasks
all_good_masks = []
for r in all_results:
    if r['score'] >= 14:
        all_good_masks.append(r)
for r in all_results2:
    if r['score'] >= 14:
        all_good_masks.append(r)
for r in best_masks3:
    if r['score'] >= 14:
        all_good_masks.append(r)

# Deduplicate by mask
seen_masks = set()
unique_good = []
for r in all_good_masks:
    key = tuple(sorted(r['mask']))
    if key not in seen_masks:
        seen_masks.add(key)
        unique_good.append(r)

print(f"\nTesting {len(unique_good)} unique masks (score >= 14) across variants...")

variants = [
    ('DEFECTOR', 'AZ', 'beau', 7),   # baseline
    ('DEFECTOR', 'AZ', 'vig', 7),
    ('DEFECTOR', 'AZ', 'beau', 5),
    ('DEFECTOR', 'AZ', 'beau', 0),    # no transposition
    ('KRYPTOS',  'KA', 'vig', 7),
    ('KRYPTOS',  'KA', 'beau', 7),
    ('KOMPASS',  'KA', 'beau', 7),
    ('KRYPTOS',  'KA', 'vig', 0),     # no transposition
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

task4_results = []
task4_best = 0

for mi, mask_info in enumerate(unique_good):
    mask = frozenset(mask_info['mask'])
    for kw, alph, cipher, width in variants:
        sc, e, b, pt = eval_mask_variant(mask, kw, alph, cipher, width)
        label = f"{kw}:{alph}_{cipher}:col{width}"

        if sc >= 14:
            task4_results.append({
                'score': sc, 'ene': e, 'bcl': b,
                'pt': pt, 'mask': sorted(mask),
                'variant': label,
                'varying': mask_info.get('varying', [])
            })

        if sc > task4_best:
            task4_best = sc
            print(f"  Task4 new best: {sc}/24 {label} mask_idx={mi} varying={mask_info.get('varying', [])}")
            if sc > 15:
                print(f"  *** ABOVE 15: PT={pt} ***")
            sys.stdout.flush()

print(f"\nTask 4 complete. Best = {task4_best}/24")
if task4_results:
    print(f"\n--- All Task 4 results >= 14/24 ({len(task4_results)}) ---")
    for r in sorted(task4_results, key=lambda x: -x['score'])[:50]:
        print(f"  {r['score']}/24 {r['variant']} ene={r['ene']} bcl={r['bcl']} varying={r['varying']}")

if task4_best >= 16:
    print("\n*** BREAKTHROUGH: VARIANT TESTING EXCEEDS 15/24! ***")
    for r in task4_results:
        if r['score'] >= 16:
            print(f"  {r['score']}/24 {r['variant']} mask={r['mask']} PT={r['pt']}")

# ======================================================================
# SUMMARY
# ======================================================================
print("\n" + "="*70)
print("FINAL SUMMARY")
print("="*70)
print(f"Task 1 (cluster-constrained, {count} masks): best {best_score}/24")
print(f"Task 2 (wider cluster, {count2} masks): best {best_score2}/24")
print(f"Task 3 (unconstrained, {count3:,} masks): best {best_score3}/24")
print(f"Task 4 (variants on best masks): best {task4_best}/24")
global_best = max(best_score, best_score2, best_score3, task4_best)
print(f"\nGLOBAL BEST = {global_best}/24")
if global_best > 15:
    print("*** CEILING BROKEN! ***")
elif global_best == 15:
    print("15/24 ceiling CONFIRMED across exhaustive search")
else:
    print(f"Did NOT reach 15/24 (best = {global_best}/24)")

total_elapsed = time.time() - t1_start
print(f"\nTotal elapsed: {total_elapsed:.1f}s ({total_elapsed/60:.1f}m)")

# Save results
results = {
    'task1': {
        'count': count,
        'best_score': best_score,
        'score_dist': {str(k): v for k, v in score_dist.items()},
        'best_masks': best_masks[:10],
        'all_14plus': [r for r in all_results if r['score'] >= 14][:50],
        'elapsed_s': t1_elapsed,
    },
    'task2': {
        'count': count2,
        'best_score': best_score2,
        'score_dist': {str(k): v for k, v in score_dist2.items()},
        'best_masks': best_masks2[:10],
        'all_14plus': [r for r in all_results2 if r['score'] >= 14][:50],
        'elapsed_s': t2_elapsed,
    },
    'task3': {
        'count': count3,
        'best_score': best_score3,
        'score_dist': {str(k): v for k, v in score_dist3.items()},
        'best_masks': best_masks3[:50],
        'above15': above15_masks,
        'elapsed_s': t3_elapsed,
    },
    'task4_best': task4_best,
    'task4_results_14plus': sorted(task4_results, key=lambda x: -x['score'])[:50],
    'global_best': global_best,
    'total_elapsed_s': total_elapsed,
    'consensus_17': sorted(CONSENSUS_17),
    'candidate_pool': candidate_pool,
    'n_candidates': n_cand,
}

with open('results/bruteforce_7remaining.json', 'w') as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to results/bruteforce_7remaining.json")
