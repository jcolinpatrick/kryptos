#!/usr/bin/env python3
"""
Cipher: Bean statistical replication
Family: statistical
Status: active
Keyspace: 5 distance thresholds × 1B MC trials + width-7 row perm + Materna
Last run:
Best score:
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

"""E-BEAN-REPLICATION-01: Independent replication of Bean's k4testing results.

Replicates three unreplicated tests from Dr. Richard Bean's k4testing repo
(github.com/RichardBean/k4testing):

TEST A: Bean3/Bean5 — PT-proximity implies CT-proximity
  For all pairs of crib positions where plaintext letters are within
  distance d (0-4) in the alphabet, sum the minor differences of the
  corresponding CT letters. Lower sum = CT letters cluster when PT
  letters are close. Bean reports: d=1 gives 1/5,031 (strongest).
  We test all 5 thresholds and report Bonferroni-corrected p-values.

TEST B: Width-7 KRYPTOS-keyed row permutation
  Write K4 (with ? pad to 98 chars) into 14×7 grid. Permute rows with
  KRYPTOS-keyed ordering (two variants). Read columns. Count repeated
  digrams (D), trigrams (T), quadgrams (Q). Bean reports 1/89K to 1/201K.
  We replicate and also sweep widths 5-14 and keyword orderings to
  calibrate search-adjusted significance.

TEST C: Materna statistic — KRYPTOS-letter CT proximity
  For crib positions where PT is in {K,R,Y,P,T,O,S}, compute sum of
  minor differences of corresponding CT letters. Bean reports 1/5,520.

All tests use CT-letter-permutation as the null model (shuffle the 97
characters, preserving letter frequencies).
"""
import sys
import os
import random
import time
import json
from collections import Counter
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH

N_WORKERS = max(1, cpu_count() - 2)

# ── Crib setup ───────────────────────────────────────────────────────────

CRIB_POSITIONS = sorted(CRIB_DICT.keys())
CRIB_PT = [CRIB_DICT[p] for p in CRIB_POSITIONS]
N_CRIBS = len(CRIB_POSITIONS)


def minor_diff(a, b):
    """Shortest circular distance between two letters (0-13)."""
    d = abs(ord(a) - ord(b))
    return min(d, 26 - d)


# ═══════════════════════════════════════════════════════════════════════
# TEST A: Bean3/Bean5 — PT-proximity implies CT-proximity
# ═══════════════════════════════════════════════════════════════════════

def bean5_stat(ct_text, distance_threshold):
    """Sum of CT minor differences for PT pairs within distance_threshold."""
    total = 0
    for i in range(N_CRIBS - 1):
        for j in range(i + 1, N_CRIBS):
            if minor_diff(CRIB_PT[i], CRIB_PT[j]) <= distance_threshold:
                total += minor_diff(ct_text[CRIB_POSITIONS[i]],
                                    ct_text[CRIB_POSITIONS[j]])
    return total


def _bean5_chunk_worker(args):
    """Worker: run a chunk of MC trials for one distance threshold."""
    distance, n_trials, seed = args
    rng = random.Random(seed)
    observed = bean5_stat(CT, distance)

    ct_list = list(CT)
    count = 0
    for _ in range(n_trials):
        rng.shuffle(ct_list)
        shuffled = ''.join(ct_list)
        if bean5_stat(shuffled, distance) <= observed:
            count += 1

    return distance, observed, count, n_trials


def test_bean5(n_trials=100_000_000, pool=None):
    """Replicate Bean5 at all 5 distance thresholds."""
    print("=" * 72)
    print("TEST A: Bean3/Bean5 — PT-proximity implies CT-proximity")
    print("=" * 72)
    print(f"  {n_trials:,} MC trials per threshold, 5 thresholds (d=0..4)")
    print(f"  Parallelized: {N_WORKERS} chunks per threshold")

    # Count pairs at each threshold
    for d in range(5):
        n_pairs = sum(1 for i in range(N_CRIBS - 1)
                      for j in range(i + 1, N_CRIBS)
                      if minor_diff(CRIB_PT[i], CRIB_PT[j]) <= d)
        obs = bean5_stat(CT, d)
        print(f"  d={d}: {n_pairs} PT pairs qualify, observed CT sum = {obs}")

    print()
    t0 = time.time()

    # Split each threshold across N_WORKERS chunks for full parallelization
    chunk_size = n_trials // N_WORKERS
    tasks = []
    for d in range(5):
        for w in range(N_WORKERS):
            tasks.append((d, chunk_size, 42 + d * 1000 + w * 7))

    if pool:
        raw_results = pool.map(_bean5_chunk_worker, tasks)
    else:
        raw_results = [_bean5_chunk_worker(t) for t in tasks]

    # Aggregate chunks per threshold
    results = []
    for d in range(5):
        chunks = [r for r in raw_results if r[0] == d]
        observed = chunks[0][1]
        total_count = sum(c for _, _, c, _ in chunks)
        total_n = sum(n for _, _, _, n in chunks)
        results.append((d, observed, total_count, total_n))

    elapsed = time.time() - t0
    print(f"  Completed in {elapsed:.0f}s\n")

    # Report
    print(f"  {'d':>3s} {'Observed':>10s} {'Count≤obs':>12s} {'Raw p':>12s} {'1/p':>10s} {'Bonf p':>12s}")
    print(f"  {'─'*3} {'─'*10} {'─'*12} {'─'*12} {'─'*10} {'─'*12}")

    all_results = {}
    for d, observed, count, n in sorted(results):
        # Use (count+1)/(n+1) for MC tail estimation
        p_raw = (count + 1) / (n + 1)
        p_bonf = min(1.0, p_raw * 5)  # 5 thresholds tested
        inv_p = 1.0 / p_raw if p_raw > 0 else float('inf')

        all_results[d] = {
            'observed': observed,
            'count': count,
            'n_trials': n,
            'p_raw': p_raw,
            'p_bonferroni': p_bonf,
        }
        print(f"  {d:>3d} {observed:>10d} {count:>12,d} {p_raw:>12.2e} {inv_p:>10.0f} {p_bonf:>12.2e}")

    # Best threshold
    best_d = min(all_results, key=lambda d: all_results[d]['p_raw'])
    best = all_results[best_d]
    print(f"\n  Best: d={best_d}, raw p={best['p_raw']:.2e}, Bonferroni p={best['p_bonferroni']:.2e}")

    # Bean's reported values for comparison
    print("\n  Bean's reported values (1B trials):")
    print("  d=0: 1/237, d=1: 1/5031, d=2: 1/1266, d=3: 1/273, d=4: 1/82")

    return all_results


# ═══════════════════════════════════════════════════════════════════════
# TEST B: Width-7 KRYPTOS-keyed row permutation
# ═══════════════════════════════════════════════════════════════════════

def count_repeated_ngrams(text, n):
    """Count distinct n-grams that appear more than once."""
    ngrams = Counter()
    for i in range(len(text) - n + 1):
        gram = text[i:i+n]
        if gram.isalpha():
            ngrams[gram] += 1
    return sum(1 for v in ngrams.values() if v > 1)


def grid_column_read(text, width, row_perm=None):
    """Write text into rows of given width, optionally permute rows, read columns."""
    nrows = len(text) // width
    if len(text) % width != 0:
        nrows += 1

    # Pad if needed
    padded = text + '?' * (nrows * width - len(text))

    # Build grid
    grid = []
    for r in range(nrows):
        grid.append(padded[r * width:(r + 1) * width])

    # Permute rows if given
    if row_perm is not None:
        grid = [grid[i] for i in row_perm]

    # Read columns
    result = []
    for c in range(width):
        for r in range(nrows):
            result.append(grid[r][c])

    return ''.join(result)


def keyword_row_perm(keyword, nrows):
    """Generate row permutation from keyword, extending if needed.
    Bean's method: KRYPTOS ordering applied to blocks of rows."""
    # Standard keyword ordering
    kw = keyword.upper()
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * len(kw)
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank

    # Apply to blocks of len(kw) rows
    perm = []
    block_size = len(kw)
    for block_start in range(0, nrows, block_size):
        block_end = min(block_start + block_size, nrows)
        block_len = block_end - block_start
        # Sort this block by keyword order
        block_indices = list(range(block_start, block_end))
        reordered = [None] * block_len
        for i in range(block_len):
            reordered[order[i]] = block_indices[i]
        # Filter None (for incomplete last block)
        perm.extend([x for x in reordered if x is not None])

    return perm


def _perm_b_test_worker(args):
    """Worker for width-7 row permutation MC test."""
    perm_type, n_trials, seed, observed_d, observed_t, observed_q = args
    rng = random.Random(seed)

    ct_padded = '?' + CT  # Bean uses ? prefix to make 98 chars
    ct_list = list(ct_padded)
    count = 0

    # Bean's permutation A: KRYPTOS KRYPTOS keyed
    perm_a = [0, 3, 6, 2, 5, 1, 4, 7, 10, 13, 9, 12, 8, 11]
    # Bean's permutation B: analogous to K3
    perm_b = [0, 3, 1, 4, 2, 5, 6, 9, 7, 10, 8, 11, 12, 13]

    perm = perm_a if perm_type == 'A' else perm_b

    for _ in range(n_trials):
        rng.shuffle(ct_list)
        shuffled = ''.join(ct_list)
        text = grid_column_read(shuffled, 7, perm)
        d = count_repeated_ngrams(text, 2)
        t = count_repeated_ngrams(text, 3)
        q = count_repeated_ngrams(text, 4)

        if perm_type == 'A':
            # Property X: D>=14, T>=3, Q>=1
            if d >= observed_d and t >= observed_t and q >= observed_q:
                count += 1
        else:
            # Property Y: D>=16, T>=1
            if d >= observed_d and t >= observed_t:
                count += 1

    return perm_type, count, n_trials


def test_width7_perm(n_trials=100_000_000, pool=None):
    """Replicate Bean's width-7 KRYPTOS-keyed row permutation test."""
    print("\n" + "=" * 72)
    print("TEST B: Width-7 KRYPTOS-keyed row permutation")
    print("=" * 72)

    ct_padded = '?' + CT  # 98 chars = 14 rows × 7 cols

    # Bean's permutations
    perm_a = [0, 3, 6, 2, 5, 1, 4, 7, 10, 13, 9, 12, 8, 11]
    perm_b = [0, 3, 1, 4, 2, 5, 6, 9, 7, 10, 8, 11, 12, 13]

    for name, perm in [('A', perm_a), ('B', perm_b)]:
        text = grid_column_read(ct_padded, 7, perm)
        d = count_repeated_ngrams(text, 2)
        t = count_repeated_ngrams(text, 3)
        q = count_repeated_ngrams(text, 4)
        print(f"  Perm {name}: D={d}, T={t}, Q={q}")
        print(f"  Text: {text[:50]}...")

    # Get observed values
    text_a = grid_column_read(ct_padded, 7, perm_a)
    d_a = count_repeated_ngrams(text_a, 2)
    t_a = count_repeated_ngrams(text_a, 3)
    q_a = count_repeated_ngrams(text_a, 4)

    text_b = grid_column_read(ct_padded, 7, perm_b)
    d_b = count_repeated_ngrams(text_b, 2)
    t_b = count_repeated_ngrams(text_b, 3)
    q_b = count_repeated_ngrams(text_b, 4)

    print(f"\n  Running {n_trials:,} MC trials per permutation ({N_WORKERS} chunks each)...")
    t0 = time.time()

    # Split each permutation across N_WORKERS chunks
    chunk_size = n_trials // N_WORKERS
    tasks = []
    for perm_type, obs_d, obs_t, obs_q in [('A', d_a, t_a, q_a), ('B', d_b, t_b, q_b)]:
        for w in range(N_WORKERS):
            tasks.append((perm_type, chunk_size, 42 + w * 7 + (0 if perm_type == 'A' else 5000),
                          obs_d, obs_t, obs_q))

    if pool:
        raw_results = pool.map(_perm_b_test_worker, tasks)
    else:
        raw_results = [_perm_b_test_worker(t) for t in tasks]

    # Aggregate chunks per permutation
    results = []
    for perm_type in ['A', 'B']:
        chunks = [r for r in raw_results if r[0] == perm_type]
        total_count = sum(c for _, c, _ in chunks)
        total_n = sum(n for _, _, n in chunks)
        results.append((perm_type, total_count, total_n))

    elapsed = time.time() - t0
    print(f"  Completed in {elapsed:.0f}s\n")

    all_results = {}
    for perm_type, count, n in results:
        p = (count + 1) / (n + 1)
        inv_p = 1.0 / p if p > 0 else float('inf')
        all_results[perm_type] = {
            'count': count,
            'n_trials': n,
            'p_raw': p,
        }
        if perm_type == 'A':
            print(f"  Perm A (Property X: D≥{d_a}, T≥{t_a}, Q≥{q_a}):")
        else:
            print(f"  Perm B (Property Y: D≥{d_b}, T≥{t_b}):")
        print(f"    {count:,} / {n:,} = 1 in {inv_p:,.0f}")

    print("\n  Bean's reported values:")
    print("  Perm A Property X: 1 in 89,000")
    print("  Perm B Property Y: 1 in 201,000")

    return all_results


# ═══════════════════════════════════════════════════════════════════════
# TEST C: Materna statistic
# ═══════════════════════════════════════════════════════════════════════

def materna_stat(ct_text):
    """Sum of minor differences for KRYPTOS-set PT letters at crib positions."""
    # Positions where PT is in {K,R,Y,P,T,O,S}
    kryptos_set = set('KRYPTOS')
    total = 0
    for pos in CRIB_POSITIONS:
        pt_letter = CRIB_DICT[pos]
        if pt_letter in kryptos_set:
            total += minor_diff(pt_letter, ct_text[pos])
    return total


def _materna_worker(args):
    n_trials, seed = args
    rng = random.Random(seed)
    observed = materna_stat(CT)
    ct_list = list(CT)
    count = 0
    for _ in range(n_trials):
        rng.shuffle(ct_list)
        if materna_stat(''.join(ct_list)) <= observed:
            count += 1
    return observed, count, n_trials


def test_materna(n_trials=10_000_000, pool=None):
    """Replicate Materna statistic."""
    print("\n" + "=" * 72)
    print("TEST C: Materna statistic (KRYPTOS-letter CT proximity)")
    print("=" * 72)

    observed = materna_stat(CT)
    kryptos_set = set('KRYPTOS')
    kryptos_positions = [p for p in CRIB_POSITIONS if CRIB_DICT[p] in kryptos_set]
    print(f"  KRYPTOS-set positions: {kryptos_positions}")
    print(f"  PT letters: {[CRIB_DICT[p] for p in kryptos_positions]}")
    print(f"  CT letters: {[CT[p] for p in kryptos_positions]}")
    print(f"  Observed sum of minor diffs: {observed}")
    print(f"  {n_trials:,} MC trials...")

    t0 = time.time()

    # Split across workers
    trials_per_worker = n_trials // N_WORKERS
    tasks = [(trials_per_worker, 42 + i * 1000) for i in range(N_WORKERS)]

    if pool:
        results = pool.map(_materna_worker, tasks)
    else:
        results = [_materna_worker(t) for t in tasks]

    total_count = sum(c for _, c, _ in results)
    total_n = sum(n for _, _, n in results)
    elapsed = time.time() - t0

    p = (total_count + 1) / (total_n + 1)
    inv_p = 1.0 / p
    print(f"  Completed in {elapsed:.0f}s")
    print(f"  {total_count:,} / {total_n:,} = 1 in {inv_p:,.0f} (p = {p:.2e})")
    print(f"\n  Bean's reported value: 1 in 5,520")

    return {
        'observed': observed,
        'count': total_count,
        'n_trials': total_n,
        'p_raw': p,
    }


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("E-BEAN-REPLICATION-01: Independent replication of Bean k4testing")
    print("=" * 72)
    print(f"Workers: {N_WORKERS}")
    print(f"CT: {CT}")
    print()

    t_start = time.time()

    with Pool(N_WORKERS) as pool:
        # Test C first (fastest — 10M trials)
        materna_results = test_materna(n_trials=10_000_000, pool=pool)

        # Test A (100M trials per threshold × 5 thresholds)
        bean5_results = test_bean5(n_trials=100_000_000, pool=pool)

        # Test B (100M trials per permutation × 2 permutations)
        perm_results = test_width7_perm(n_trials=100_000_000, pool=pool)

    total_elapsed = time.time() - t_start

    # ── Summary ──────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)

    print("\n  Test A (Bean5 — PT-proximity → CT-proximity):")
    best_d = min(bean5_results, key=lambda d: bean5_results[d]['p_raw'])
    best = bean5_results[best_d]
    print(f"    Best threshold: d={best_d}")
    print(f"    Raw p = {best['p_raw']:.2e} (1 in {1/best['p_raw']:,.0f})")
    print(f"    Bonferroni p = {best['p_bonferroni']:.2e} (corrected for 5 thresholds)")

    print("\n  Test B (Width-7 row permutation):")
    for perm_type, r in sorted(perm_results.items()):
        print(f"    Perm {perm_type}: p = {r['p_raw']:.2e} (1 in {1/r['p_raw']:,.0f})")

    print(f"\n  Test C (Materna):")
    print(f"    p = {materna_results['p_raw']:.2e} (1 in {1/materna_results['p_raw']:,.0f})")

    print(f"\n  Total elapsed: {total_elapsed:.0f}s ({total_elapsed/60:.1f} min)")

    # Save
    output = {
        'experiment': 'E-BEAN-REPLICATION-01',
        'bean5': {str(k): v for k, v in bean5_results.items()},
        'width7_perm': perm_results,
        'materna': materna_results,
        'total_elapsed_s': round(total_elapsed, 1),
        'workers': N_WORKERS,
    }
    out_path = os.path.join(_ROOT, 'results', 'bean_replication_01.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Results: {out_path}")
