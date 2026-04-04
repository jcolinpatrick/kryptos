#!/usr/bin/env python3
"""Accelerated monoalphabetic + transposition brute force sweep.

Cipher: mono substitution + columnar transposition (two-layer)
Family: analysis
Status: active
Keyspace: ~26! × width! per width (SA-sampled, not exhaustive)
Last run: never
Best score: n/a

Uses Numba-accelerated kernels + multiprocessing on 28 cores.
This is the first script to exploit the new accel.py module for
production-grade sweep throughput.

Strategy:
  For each columnar width in [7,8,10,11,13,14]:
    1. Generate column orderings via SA on n-gram score (fast thanks to Numba)
    2. For each good transposition, do SA on mono substitution key
    3. Score against cribs

This targets the OPEN multi-layer attack surface (Mono+Trans is
underdetermined per E-FRAC-54 briefing note).
"""
import sys
import os
import time
import random
import math
import json
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

import numpy as np
from kryptos.kernel.constants import CT, CT_LEN, MOD
from kryptos.kernel.accel import (
    HAS_NUMBA, text_to_int8, int8_to_text,
    fast_decrypt_beaufort, fast_score_cribs, fast_quadgram_score,
    fast_decrypt_and_score, fast_bean_simple,
    build_quadgram_table, _build_crib_arrays, _build_bean_arrays,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

# Precompute arrays (module-level for multiprocessing fork inheritance)
CT_NUMS = text_to_int8(CT)
CRIB_POS, CRIB_VALS = _build_crib_arrays()
EQ_A, EQ_B, INEQ_A, INEQ_B = _build_bean_arrays()
QG_TABLE = None  # Will be built after fork


def build_tables():
    """Build quadgram table (called in each worker after fork)."""
    global QG_TABLE
    if QG_TABLE is None:
        QG_TABLE = build_quadgram_table()


def mono_sa_on_transposed(args):
    """Run SA on mono substitution for a given transposition.

    args: (width, col_order, n_restarts, variant_id)
    Returns best result dict.
    """
    build_tables()

    width, col_order, n_restarts, variant_id = args
    rng = random.Random(hash(tuple(col_order)))

    # Apply transposition
    perm = columnar_perm(width, list(col_order), CT_LEN)
    inv = invert_perm(perm)
    unscrambled = apply_perm(CT, inv)
    ct_trans = text_to_int8(unscrambled)

    best_score = 0
    best_key = None
    best_pt = None

    for restart in range(n_restarts):
        # Random initial key
        key = np.array(rng.sample(range(26), 26), dtype=np.int8)

        # Map the key: for each CT letter, the key value at that position
        # is key[CT_letter]. This is a monoalphabetic substitution.
        # Build the full 97-position key
        full_key = np.array([key[ct_trans[i]] for i in range(CT_LEN)], dtype=np.int8)

        if variant_id == 1:  # Beaufort
            pt = np.array([(full_key[i] - ct_trans[i]) % 26 for i in range(CT_LEN)], dtype=np.int8)
        else:  # Vigenere
            pt = np.array([(ct_trans[i] - full_key[i]) % 26 for i in range(CT_LEN)], dtype=np.int8)

        current_score = fast_quadgram_score(pt, QG_TABLE)
        crib = int(fast_score_cribs(pt, CRIB_POS, CRIB_VALS))

        # SA parameters
        T = 1.0
        T_min = 0.001
        alpha = 0.995

        while T > T_min:
            # Swap two random positions in the key
            i, j = rng.sample(range(26), 2)
            key[i], key[j] = key[j], key[i]

            full_key = np.array([key[ct_trans[k]] for k in range(CT_LEN)], dtype=np.int8)

            if variant_id == 1:
                new_pt = np.array([(full_key[k] - ct_trans[k]) % 26 for k in range(CT_LEN)], dtype=np.int8)
            else:
                new_pt = np.array([(ct_trans[k] - full_key[k]) % 26 for k in range(CT_LEN)], dtype=np.int8)

            new_score = fast_quadgram_score(new_pt, QG_TABLE)

            delta = new_score - current_score
            if delta > 0 or rng.random() < math.exp(delta / T):
                current_score = new_score
                pt = new_pt
                new_crib = int(fast_score_cribs(new_pt, CRIB_POS, CRIB_VALS))
                if new_crib > crib:
                    crib = new_crib
            else:
                key[i], key[j] = key[j], key[i]  # revert

            T *= alpha

        if crib > best_score:
            best_score = crib
            best_key = key.copy()
            best_pt = int8_to_text(pt)

    return {
        "width": width,
        "col_order": list(col_order),
        "variant": "beaufort" if variant_id == 1 else "vigenere",
        "best_crib": best_score,
        "best_pt": best_pt[:80] if best_pt else "",
        "n_restarts": n_restarts,
    }


def generate_column_orders(width, n_samples, seed=42):
    """Generate random column orderings for a given width."""
    rng = random.Random(seed)
    orders = set()
    base = list(range(width))
    # Always include identity and reverse
    orders.add(tuple(base))
    orders.add(tuple(reversed(base)))
    while len(orders) < n_samples:
        order = list(base)
        rng.shuffle(order)
        orders.add(tuple(order))
    return list(orders)


def main():
    workers = max(1, cpu_count() - 2)
    print("=" * 70)
    print("ACCELERATED MONO + TRANSPOSITION SA SWEEP")
    print(f"Using Numba: {HAS_NUMBA} | Workers: {workers}")
    print("=" * 70)
    print(f"CT: {CT[:50]}...")
    print()

    WIDTHS = [7, 8, 10, 11, 13, 14]
    N_ORDERS_PER_WIDTH = 200
    N_RESTARTS = 5

    # Build work items
    tasks = []
    for width in WIDTHS:
        orders = generate_column_orders(width, N_ORDERS_PER_WIDTH)
        for order in orders:
            for variant_id in [0, 1]:  # vigenere, beaufort
                tasks.append((width, order, N_RESTARTS, variant_id))

    print(f"Total tasks: {len(tasks)} ({len(WIDTHS)} widths × "
          f"{N_ORDERS_PER_WIDTH} orders × 2 variants × {N_RESTARTS} SA restarts each)")

    t0 = time.time()
    all_results = []
    global_best = 0

    with Pool(workers) as pool:
        for i, result in enumerate(pool.imap_unordered(mono_sa_on_transposed, tasks, chunksize=4)):
            all_results.append(result)
            if result["best_crib"] > global_best:
                global_best = result["best_crib"]
                print(f"  NEW BEST: {result['best_crib']}/24 — w={result['width']} "
                      f"{result['variant']} order={result['col_order']}")
                if result["best_pt"]:
                    print(f"    PT: {result['best_pt']}")

            if (i + 1) % 100 == 0:
                elapsed = time.time() - t0
                rate = (i + 1) / elapsed
                eta = (len(tasks) - i - 1) / rate if rate > 0 else 0
                print(f"  [{i+1}/{len(tasks)}] best={global_best}/24 "
                      f"rate={rate:.1f}/s ETA={eta:.0f}s", flush=True)

    elapsed = time.time() - t0

    # Sort by score
    all_results.sort(key=lambda x: -x["best_crib"])

    print(f"\n{'=' * 70}")
    print(f"COMPLETE: {len(tasks)} tasks in {elapsed:.1f}s ({len(tasks)/elapsed:.1f} tasks/s)")
    print(f"Best score: {global_best}/24")
    print()

    if global_best >= 6:
        print("Top results:")
        for r in all_results[:20]:
            if r["best_crib"] >= 4:
                print(f"  {r['best_crib']}/24 — w={r['width']} {r['variant']} "
                      f"order={r['col_order']}")

    # Score distribution
    from collections import Counter
    dist = Counter(r["best_crib"] for r in all_results)
    print("\nScore distribution:")
    for s in sorted(dist.keys()):
        print(f"  Score {s:2d}: {dist[s]:5d} tasks")

    if global_best < 10:
        print("\nVERDICT: NOISE")
    elif global_best < 18:
        print("\nVERDICT: INTERESTING — investigate further")
    else:
        print("\nVERDICT: SIGNAL")

    # Save
    outpath = os.path.join(_ROOT, "results", "accel_mono_trans_sweep.json")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "accel_mono_trans_sweep",
            "widths": WIDTHS,
            "n_orders_per_width": N_ORDERS_PER_WIDTH,
            "n_restarts": N_RESTARTS,
            "total_tasks": len(tasks),
            "elapsed_s": elapsed,
            "best_score": global_best,
            "top_10": all_results[:10],
        }, f, indent=2)
    print(f"\nResults saved: {outpath}")


if __name__ == "__main__":
    main()
