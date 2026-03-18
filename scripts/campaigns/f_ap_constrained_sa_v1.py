#!/usr/bin/env python3 -u
"""
=================================================================
AP-CONSTRAINED SIMULATED ANNEALING DECRYPTION v1
=================================================================
Cipher:     Model B Beaufort (key on raw CT97 or null-extracted CT73)
Family:     campaigns
Status:     active
Keyspace:   ~3^25 x 26^24 (AP-constrained) vs 26^49 (unconstrained)
Last run:   never
Best score: --

HYPOTHESIS
----------
The Model B Beaufort keystream at 24 crib positions has AP {G,K,O}
at 12/24 (p~4e-6). If ~50% of ALL key positions use {G,K,O}, the
effective search space shrinks by ~10^15. This script exploits that
by AP-biasing SA mutations while optimizing plaintext quality.

Three SA modes:
  A. PT-optimized on CT73 with AP bias (primary)
  B. PT-optimized on CT73 without AP bias (control)
  C. PT-optimized on CT97 with AP bias (Model B direct)

Each mode: 500 restarts x 200K steps x 28 cores.
=================================================================
"""

import json
import sys
import os
import time
import math
import random
from collections import Counter
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT

# ── Quadgram table ─────────────────────────────────────────────────────

QG_PATH = os.path.join(_ROOT, "data", "english_quadgrams.json")
print(f"Loading quadgrams...", flush=True)
with open(QG_PATH) as f:
    _qg_raw = json.load(f)
QG_FLOOR = min(_qg_raw.values()) - 1.0
QG_TABLE = [QG_FLOOR] * (26 ** 4)
for gram, logp in _qg_raw.items():
    if len(gram) == 4:
        a, b, c, d = [ord(ch) - 65 for ch in gram]
        QG_TABLE[a * 17576 + b * 676 + c * 26 + d] = logp
del _qg_raw
print(f"  Loaded {sum(1 for x in QG_TABLE if x != QG_FLOOR)} quadgrams", flush=True)


def qg_score(arr):
    """Quadgram log-prob per char for int array."""
    n = len(arr)
    if n < 4:
        return QG_FLOOR
    total = 0.0
    for i in range(n - 3):
        total += QG_TABLE[arr[i] * 17576 + arr[i+1] * 676 + arr[i+2] * 26 + arr[i+3]]
    return total / (n - 3)


# ── Constants ──────────────────────────────────────────────────────────

CONSENSUS_NULLS = frozenset(
    {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
)
REF_VARYING = [38, 39, 40, 55, 87, 93, 94]
ALL_NULLS = CONSENSUS_NULLS | set(REF_VARYING)
NONNULL_97 = sorted(set(range(CT_LEN)) - ALL_NULLS)  # 73 positions
assert len(NONNULL_97) == 73

# CT73: null-extracted ciphertext
CT73_STR = "".join(CT[i] for i in NONNULL_97)
CT73_ARR = [ALPH_IDX[c] for c in CT73_STR]
CT97_ARR = [ALPH_IDX[c] for c in CT]

# Crib positions in CT97 and their CT73 indices
CRIB_POS_97 = sorted(CRIB_DICT.keys())
CRIB_CT73_IDX = [NONNULL_97.index(p) for p in CRIB_POS_97]

# Beaufort key values at crib positions (Model B on raw CT97)
CRIB_KEYS_97 = {}
for pos in CRIB_POS_97:
    CRIB_KEYS_97[pos] = (ALPH_IDX[CT[pos]] + ALPH_IDX[CRIB_DICT[pos]]) % MOD

# Same values at CT73 crib positions
CRIB_KEYS_73 = {}
for i, pos97 in enumerate(CRIB_POS_97):
    ct73_idx = CRIB_CT73_IDX[i]
    CRIB_KEYS_73[ct73_idx] = CRIB_KEYS_97[pos97]

# Free positions (not crib-pinned)
FREE_73 = sorted(set(range(73)) - set(CRIB_KEYS_73.keys()))
FREE_97 = sorted(set(range(97)) - set(CRIB_KEYS_97.keys()))

# AP values
AP_VALUES = [6, 10, 14]  # G, K, O in AZ

# Verify AP rate in known keystream
ap_count = sum(1 for v in CRIB_KEYS_73.values() if v in AP_VALUES)
print(f"\nAP {{G,K,O}} in known keystream: {ap_count}/24 = {ap_count/24:.1%}", flush=True)
print(f"Known key: {''.join(ALPH[CRIB_KEYS_73[CRIB_CT73_IDX[i]]] for i in range(24))}", flush=True)
print(f"Free positions: {len(FREE_73)} (CT73), {len(FREE_97)} (CT97)", flush=True)

# ── SA Core ────────────────────────────────────────────────────────────

def beaufort_decrypt_arr(ct_arr, key_arr):
    """Beaufort decrypt: PT[i] = (KEY[i] - CT[i]) mod 26."""
    return [(key_arr[i] - ct_arr[i]) % MOD for i in range(len(ct_arr))]


def sa_worker(args):
    """Generic SA worker. Returns best result dict."""
    (restart_id, seed, ct_arr, pinned, free_pos, n_steps,
     ap_bias, mode_name) = args

    rng = random.Random(seed)
    n = len(ct_arr)

    # Initialize key
    key = [0] * n
    for pos, val in pinned.items():
        key[pos] = val

    # AP-biased initialization
    for pos in free_pos:
        if ap_bias and rng.random() < 0.5:
            key[pos] = rng.choice(AP_VALUES)
        else:
            key[pos] = rng.randint(0, 25)

    # Initial score
    pt = beaufort_decrypt_arr(ct_arr, key)
    cur_score = qg_score(pt)
    best_score = cur_score
    best_key = key[:]
    best_pt = pt[:]

    T_start = 2.0
    T_end = 0.005
    log_ratio = math.log(T_end / T_start)
    n_free = len(free_pos)

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)

        # Pick random free position
        pos = free_pos[rng.randint(0, n_free - 1)]
        old_val = key[pos]

        # AP-biased mutation
        if ap_bias and rng.random() < 0.4:
            new_val = rng.choice(AP_VALUES)
        else:
            new_val = rng.randint(0, 25)
        if new_val == old_val:
            new_val = (old_val + rng.randint(1, 25)) % 26

        # Update key and recompute score
        key[pos] = new_val
        pt_new = beaufort_decrypt_arr(ct_arr, key)
        new_score = qg_score(pt_new)

        delta = new_score - cur_score
        if delta > 0 or (T > 0.001 and rng.random() < math.exp(delta / T)):
            pt = pt_new
            cur_score = new_score
            if new_score > best_score:
                best_score = new_score
                best_key = key[:]
                best_pt = pt[:]
        else:
            key[pos] = old_val

    # Compute stats on best key
    ap_rate = sum(1 for v in best_key if v in AP_VALUES) / n
    key_ic = sum(c * (c-1) for c in Counter(best_key).values()) / (n * (n-1))
    pt_str = "".join(ALPH[v] for v in best_pt)
    key_str = "".join(ALPH[v] for v in best_key)

    return {
        "restart": restart_id,
        "mode": mode_name,
        "score": best_score,
        "ap_rate": ap_rate,
        "key_ic": key_ic,
        "pt": pt_str,
        "key": key_str,
    }


# ── Phase runners ──────────────────────────────────────────────────────

def run_phase(name, ct_arr, pinned, free_pos, n_restarts, n_steps,
              ap_bias, n_workers=None):
    if n_workers is None:
        n_workers = min(cpu_count(), 28)

    base_seed = hash(name) % (2**31)
    tasks = [
        (i, base_seed + i, ct_arr, pinned, free_pos, n_steps,
         ap_bias, name)
        for i in range(n_restarts)
    ]

    results = []
    t0 = time.time()

    with Pool(n_workers) as pool:
        for r in pool.imap_unordered(sa_worker, tasks, chunksize=5):
            results.append(r)
            if len(results) % 50 == 0:
                best_so_far = max(results, key=lambda x: x["score"])
                print(
                    f"  [{len(results):>4}/{n_restarts}] best={best_so_far['score']:.3f} "
                    f"AP={best_so_far['ap_rate']:.1%} IC={best_so_far['key_ic']:.4f}",
                    flush=True,
                )

    elapsed = time.time() - t0
    results.sort(key=lambda x: -x["score"])

    print(f"\n  Phase {name} complete: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"  Best score: {results[0]['score']:.4f}")
    print(f"  Best PT:    {results[0]['pt']}")
    print(f"  Best KEY:   {results[0]['key']}")
    print(f"  AP rate:    {results[0]['ap_rate']:.1%}")
    print(f"  Key IC:     {results[0]['key_ic']:.4f}")

    # Top 5
    print(f"\n  Top 5:")
    for r in results[:5]:
        print(f"    score={r['score']:.4f} AP={r['ap_rate']:.1%} PT={r['pt'][:40]}...")

    return results


# ── Main ───────────────────────────────────────────────────────────────

def main():
    t_start = time.time()
    n_restarts = 500
    n_steps = 200_000

    print("=" * 70)
    print("AP-Constrained SA Decryption v1")
    print("=" * 70)
    print(f"Restarts: {n_restarts}, Steps: {n_steps:,}")
    print(f"Workers: {min(cpu_count(), 28)}")
    print(f"CT73: {CT73_STR}")
    print(f"AP values: {[ALPH[v] for v in AP_VALUES]} = {AP_VALUES}")

    all_results = {}

    # Phase A: CT73 with AP bias (primary attack)
    print(f"\n{'='*70}")
    print("Phase A: CT73 + AP bias (primary)")
    print(f"{'='*70}")
    results_a = run_phase(
        "A_ct73_ap", CT73_ARR, CRIB_KEYS_73, FREE_73,
        n_restarts, n_steps, ap_bias=True,
    )
    all_results["A_ct73_ap"] = results_a

    # Phase B: CT73 without AP bias (control)
    print(f"\n{'='*70}")
    print("Phase B: CT73 no AP bias (control)")
    print(f"{'='*70}")
    results_b = run_phase(
        "B_ct73_noap", CT73_ARR, CRIB_KEYS_73, FREE_73,
        n_restarts, n_steps, ap_bias=False,
    )
    all_results["B_ct73_noap"] = results_b

    # Phase C: CT97 with AP bias (Model B direct)
    print(f"\n{'='*70}")
    print("Phase C: CT97 + AP bias (Model B direct)")
    print(f"{'='*70}")
    results_c = run_phase(
        "C_ct97_ap", CT97_ARR, CRIB_KEYS_97, FREE_97,
        n_restarts, n_steps, ap_bias=True,
    )
    all_results["C_ct97_ap"] = results_c

    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    for phase_name, results in all_results.items():
        best = results[0]
        scores = [r["score"] for r in results]
        ap_rates = [r["ap_rate"] for r in results]
        print(f"\n  {phase_name}:")
        print(f"    Best: {best['score']:.4f}, Mean: {sum(scores)/len(scores):.4f}")
        print(f"    AP rate: best={best['ap_rate']:.1%}, mean={sum(ap_rates)/len(ap_rates):.1%}")
        print(f"    Best PT: {best['pt'][:60]}...")

    # English threshold
    print(f"\n  Reference: English text ~ -4.2 per char, random ~ -6.5 per char")
    all_best = max(
        (r for results in all_results.values() for r in results),
        key=lambda x: x["score"],
    )
    if all_best["score"] > -4.5:
        print(f"\n  *** POTENTIAL BREAKTHROUGH: {all_best['score']:.4f} approaches English! ***")
    elif all_best["score"] > -5.0:
        print(f"\n  ** MODERATE SIGNAL: {all_best['score']:.4f} between random and English **")
    else:
        print(f"\n  Best {all_best['score']:.4f} is in noise range")

    # Save results
    output_path = os.path.join(_ROOT, "results", "f_ap_constrained_sa_v1.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    save_data = {
        "experiment": "AP_constrained_SA_v1",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "n_restarts": n_restarts,
        "n_steps": n_steps,
        "ap_values": AP_VALUES,
    }
    for phase_name, results in all_results.items():
        save_data[phase_name] = {
            "top10": results[:10],
            "score_stats": {
                "max": results[0]["score"],
                "mean": sum(r["score"] for r in results) / len(results),
                "min": results[-1]["score"],
            },
        }
    with open(output_path, "w") as f:
        json.dump(save_data, f, indent=2)
    print(f"\n  Results: {output_path}")

    elapsed = time.time() - t_start
    print(f"\n  Total: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print("=" * 70)


if __name__ == "__main__":
    main()
