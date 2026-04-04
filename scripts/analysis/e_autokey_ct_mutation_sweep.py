#!/usr/bin/env python3
"""
Cipher: autokey
Family: analysis
Status: active
Keyspace: 97*25*4*~7700 primers = ~7.4B decryptions
Last run:
Best score:
"""
"""E-AUTOKEY-MUTATION: Single-letter CT mutation vs autokey structural ceiling.

The structural proof that autokey achieves at most 21/24 on K4 depends on
specific keystream values derived from the ciphertext. If one CT letter is
a transcription error, the keystream changes and the structural contradictions
that create the ceiling might disappear.

For each of 97 CT positions, for each of 25 alternative letters (2,425 mutations):
  - Test all 4 autokey variants (PT-vig, PT-beau, CT-vig, CT-beau)
  - Test primer lengths 1-8 (exhaustive for L=1,2; sampled for L=3+)
  - Score against 24 crib positions
  - Record best score per mutation

Key question: Does ANY single-letter mutation achieve > 21/24?
"""

import itertools
import json
import os
import random
import sys
import time
from collections import Counter, defaultdict
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT, CRIB_POSITIONS, N_CRIBS, MOD

# ── Constants ───────────────────────────────────────────────────────────────

CT_VALS = [ord(c) - 65 for c in CT]
N = len(CT)  # 97
CRIB_POS_SORTED = sorted(CRIB_DICT.keys())
PT_TARGETS = {pos: ord(CRIB_DICT[pos]) - 65 for pos in CRIB_POS_SORTED}

VARIANTS = ['pt_vig', 'pt_beau', 'ct_vig', 'ct_beau']

# Primer config: (length, n_primers). For L=1,2 exhaustive; L=3+ sampled.
PRIMER_CONFIG = [
    (1, None),   # 26 exhaustive
    (2, None),   # 676 exhaustive
    (3, 1000),
    (4, 1000),
    (5, 1000),
    (6, 1000),
    (7, 1000),
    (8, 1000),
]

# Pre-generate primer lists (shared across workers via fork)
PRIMER_LISTS = {}
_rng = random.Random(12345)
for plen, n_samples in PRIMER_CONFIG:
    if n_samples is None:
        # Exhaustive
        PRIMER_LISTS[plen] = list(itertools.product(range(26), repeat=plen))
    else:
        PRIMER_LISTS[plen] = [
            tuple(_rng.randint(0, 25) for _ in range(plen))
            for _ in range(n_samples)
        ]

TOTAL_PRIMERS_PER_VARIANT = sum(len(v) for v in PRIMER_LISTS.values())
# = 26 + 676 + 6*1000 = 6702


def decrypt_and_score(ct_vals, variant, primer):
    """Decrypt ct_vals with given autokey variant and primer, return crib match count."""
    plen = len(primer)
    n = len(ct_vals)
    pt = [0] * n
    matches = 0

    if variant == 'pt_vig':
        for i in range(n):
            k = primer[i] if i < plen else pt[i - plen]
            pt[i] = (ct_vals[i] - k) % 26
            if i in PT_TARGETS and pt[i] == PT_TARGETS[i]:
                matches += 1
    elif variant == 'pt_beau':
        for i in range(n):
            k = primer[i] if i < plen else pt[i - plen]
            pt[i] = (k - ct_vals[i]) % 26
            if i in PT_TARGETS and pt[i] == PT_TARGETS[i]:
                matches += 1
    elif variant == 'ct_vig':
        for i in range(n):
            k = primer[i] if i < plen else ct_vals[i - plen]
            pt[i] = (ct_vals[i] - k) % 26
            if i in PT_TARGETS and pt[i] == PT_TARGETS[i]:
                matches += 1
    elif variant == 'ct_beau':
        for i in range(n):
            k = primer[i] if i < plen else ct_vals[i - plen]
            pt[i] = (k - ct_vals[i]) % 26
            if i in PT_TARGETS and pt[i] == PT_TARGETS[i]:
                matches += 1

    return matches


def evaluate_mutation(args):
    """Evaluate one mutation (pos, new_val). Returns dict with best results."""
    pos, new_val = args
    original_val = CT_VALS[pos]

    # Create mutated CT
    mut_ct = CT_VALS[:]
    mut_ct[pos] = new_val

    original_letter = chr(original_val + 65)
    new_letter = chr(new_val + 65)

    best_score = 0
    best_variant = None
    best_plen = None
    best_primer = None

    for variant in VARIANTS:
        for plen, primers in PRIMER_LISTS.items():
            for primer in primers:
                score = decrypt_and_score(mut_ct, variant, primer)
                if score > best_score:
                    best_score = score
                    best_variant = variant
                    best_plen = plen
                    best_primer = primer

    return {
        'pos': pos,
        'original': original_letter,
        'mutated': new_letter,
        'best_score': best_score,
        'best_variant': best_variant,
        'best_plen': best_plen,
        'best_primer': ''.join(chr(v + 65) for v in best_primer) if best_primer else '',
    }


def evaluate_original():
    """Evaluate the original (unmutated) CT for baseline."""
    best_score = 0
    best_variant = None
    best_plen = None
    best_primer = None

    for variant in VARIANTS:
        for plen, primers in PRIMER_LISTS.items():
            for primer in primers:
                score = decrypt_and_score(CT_VALS, variant, primer)
                if score > best_score:
                    best_score = score
                    best_variant = variant
                    best_plen = plen
                    best_primer = primer

    return {
        'best_score': best_score,
        'best_variant': best_variant,
        'best_plen': best_plen,
        'best_primer': ''.join(chr(v + 65) for v in best_primer) if best_primer else '',
    }


def main():
    start = time.time()
    print("=" * 70)
    print("E-AUTOKEY-MUTATION: Single-letter CT Mutation vs Autokey Ceiling")
    print("=" * 70)
    print(f"CT length: {N}")
    print(f"Mutations: {N} positions x 25 alternatives = {N * 25}")
    print(f"Variants: {VARIANTS}")
    print(f"Primers per variant: {TOTAL_PRIMERS_PER_VARIANT} "
          f"(L1={len(PRIMER_LISTS[1])}, L2={len(PRIMER_LISTS[2])}, "
          f"L3-8={len(PRIMER_LISTS[3])} each)")
    print(f"Total decryptions per mutation: {len(VARIANTS) * TOTAL_PRIMERS_PER_VARIANT}")
    print(f"Total decryptions: {N * 25 * len(VARIANTS) * TOTAL_PRIMERS_PER_VARIANT:,}")

    n_workers = max(1, cpu_count() - 2)
    print(f"Workers: {n_workers}")

    # Phase 0: Original CT baseline
    print(f"\n--- Baseline (original CT) ---")
    baseline = evaluate_original()
    print(f"  Original CT best: {baseline['best_score']}/24 "
          f"({baseline['best_variant']}, L={baseline['best_plen']}, "
          f"primer={baseline['best_primer']})")

    # Phase 1: Generate all mutation tasks
    tasks = []
    for pos in range(N):
        original_val = CT_VALS[pos]
        for new_val in range(26):
            if new_val == original_val:
                continue
            tasks.append((pos, new_val))

    print(f"\nTotal tasks: {len(tasks)}")
    print(f"Estimated time: ~{len(tasks) * 0.15 / n_workers:.0f}s "
          f"(rough estimate)")
    print(f"\nStarting sweep...\n")

    # Phase 2: Run all mutations in parallel
    results = []
    done = 0
    with Pool(n_workers) as pool:
        for result in pool.imap_unordered(evaluate_mutation, tasks, chunksize=5):
            results.append(result)
            done += 1
            if done % 100 == 0 or done == len(tasks):
                elapsed = time.time() - start
                rate = done / elapsed
                eta = (len(tasks) - done) / rate if rate > 0 else 0
                best_so_far = max(r['best_score'] for r in results)
                print(f"  [{done}/{len(tasks)}] {elapsed:.0f}s "
                      f"({rate:.1f}/s, ETA {eta:.0f}s) "
                      f"best_so_far={best_so_far}/24")

    elapsed = time.time() - start

    # Phase 3: Analysis
    print(f"\n{'='*70}")
    print("RESULTS")
    print(f"{'='*70}")

    # Sort by score
    results.sort(key=lambda r: r['best_score'], reverse=True)

    # Score distribution
    score_dist = Counter(r['best_score'] for r in results)
    print(f"\nScore distribution across {len(results)} mutations:")
    for score in sorted(score_dist.keys(), reverse=True):
        count = score_dist[score]
        bar = '#' * min(count, 60)
        print(f"  {score:2d}/24: {count:5d} {bar}")

    # Key question
    above_21 = [r for r in results if r['best_score'] > 21]
    print(f"\n*** Mutations scoring > 21/24: {len(above_21)} ***")
    if above_21:
        print("  THIS IS SIGNAL — the structural ceiling is fragile to mutation!")
        for r in above_21[:20]:
            print(f"    pos={r['pos']:2d} ({r['original']}->{r['mutated']}) "
                  f"score={r['best_score']}/24 variant={r['best_variant']} "
                  f"L={r['best_plen']} primer={r['best_primer']}")
    else:
        print("  The structural ceiling at 21/24 holds for ALL single-letter mutations.")

    # Top 20
    print(f"\nTop 20 mutations:")
    for i, r in enumerate(results[:20]):
        print(f"  {i+1:2d}. pos={r['pos']:2d} ({r['original']}->{r['mutated']}) "
              f"score={r['best_score']}/24 variant={r['best_variant']} "
              f"L={r['best_plen']} primer={r['best_primer']}")

    # Variant breakdown
    print(f"\nVariant breakdown (among top 100):")
    variant_counts = Counter(r['best_variant'] for r in results[:100])
    for v, c in variant_counts.most_common():
        print(f"  {v}: {c}")

    # Position sensitivity: which positions yield highest scores when mutated?
    pos_best = defaultdict(int)
    for r in results:
        pos_best[r['pos']] = max(pos_best[r['pos']], r['best_score'])
    pos_ranked = sorted(pos_best.items(), key=lambda x: x[1], reverse=True)
    print(f"\nMost sensitive positions (best score when mutated):")
    for pos, score in pos_ranked[:15]:
        is_crib = pos in CRIB_POSITIONS
        crib_marker = f" [CRIB={CRIB_DICT[pos]}]" if is_crib else ""
        print(f"  pos={pos:2d} (CT={CT[pos]}) -> best={score}/24{crib_marker}")

    # Mutations at crib positions vs non-crib positions
    crib_mutations = [r for r in results if r['pos'] in CRIB_POSITIONS]
    noncrib_mutations = [r for r in results if r['pos'] not in CRIB_POSITIONS]
    crib_max = max(r['best_score'] for r in crib_mutations) if crib_mutations else 0
    noncrib_max = max(r['best_score'] for r in noncrib_mutations) if noncrib_mutations else 0
    crib_mean = sum(r['best_score'] for r in crib_mutations) / len(crib_mutations) if crib_mutations else 0
    noncrib_mean = sum(r['best_score'] for r in noncrib_mutations) / len(noncrib_mutations) if noncrib_mutations else 0
    print(f"\nCrib-position mutations: max={crib_max}/24, mean={crib_mean:.2f} (n={len(crib_mutations)})")
    print(f"Non-crib mutations:     max={noncrib_max}/24, mean={noncrib_mean:.2f} (n={len(noncrib_mutations)})")

    # Summary
    overall_max = results[0]['best_score'] if results else 0
    verdict = "CEILING_BROKEN" if overall_max > 21 else "CEILING_HOLDS"

    print(f"\n{'='*70}")
    print(f"VERDICT: {verdict}")
    print(f"  Original CT baseline: {baseline['best_score']}/24")
    print(f"  Best mutation score:  {overall_max}/24")
    print(f"  Mutations > 21/24:    {len(above_21)}")
    print(f"  Runtime: {elapsed:.0f}s ({n_workers} workers)")
    print(f"{'='*70}")

    # Save results
    outpath = os.path.join(_ROOT, 'results', 'e_autokey_ct_mutation_sweep.json')
    summary = {
        'experiment': 'E-AUTOKEY-MUTATION',
        'title': 'Single-letter CT Mutation vs Autokey Structural Ceiling',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'runtime_seconds': round(elapsed, 1),
        'n_workers': n_workers,
        'n_mutations': len(results),
        'primers_per_variant': TOTAL_PRIMERS_PER_VARIANT,
        'total_decryptions': N * 25 * len(VARIANTS) * TOTAL_PRIMERS_PER_VARIANT,
        'baseline': baseline,
        'verdict': verdict,
        'overall_max': overall_max,
        'n_above_21': len(above_21),
        'score_distribution': {str(k): v for k, v in sorted(score_dist.items())},
        'top_20': results[:20],
        'above_21': above_21,
    }
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults saved: {outpath}")
    print(f"RESULT: {verdict}")


if __name__ == '__main__':
    main()
