#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
scripts/blitz_strip_route_fast.py
Optimized exhaustive columnar search for K4 unscrambling.

Key optimization: constraint-based crib checking using precomputed
required-real-CT patterns. Instead of decrypting all positions, only
checks the 13-char (ENE) or 11-char (BC) windows against known requirements.

Speedup: ~10x over the sliding_window_view approach.

Usage: PYTHONPATH=src python3 -u scripts/blitz_strip_route_fast.py
"""

import numpy as np
import json, os, sys, time
import multiprocessing as mp
from itertools import permutations

sys.path.insert(0, 'src')
os.makedirs('blitz_results/strip_route', exist_ok=True)
RESULTS_DIR = 'blitz_results/strip_route'

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N  = 97
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
ENE = "EASTNORTHEAST"
BC  = "BERLINCLOCK"

ct_np  = np.array([ord(c)-65 for c in K4],  dtype=np.int32)
ene_np = np.array([ord(c)-65 for c in ENE], dtype=np.int32)
bc_np  = np.array([ord(c)-65 for c in BC],  dtype=np.int32)

KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
            'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA']

# ─── QUADGRAMS ────────────────────────────────────────────────────────────────
QG = {}
for p in ['data/english_quadgrams.json']:
    if os.path.exists(p):
        with open(p) as f: QG = json.load(f)
        break

def qscore(t):
    return sum(QG.get(t[i:i+4], -10.0) for i in range(len(t)-3)) if QG else 0.0

# ─── PRECOMPUTED REQUIRED PATTERNS ────────────────────────────────────────────
def build_required_patterns():
    """
    For each (crib, crib_pos, keyword, alpha, cipher) combo, precompute
    the required real-CT characters that must appear at positions
    crib_pos..crib_pos+len(crib)-1.

    Returns:
      ene_patterns: (n_ene_combos, len(ENE)) int array of required real-CT chars
      ene_positions: (n_ene_combos,) int array of crib start positions
      ene_meta: list of (keyword, alpha, cipher) for each combo
      bc_patterns, bc_positions, bc_meta: same for BERLINCLOCK
    """
    ene_pats, ene_pos, ene_meta = [], [], []
    bc_pats,  bc_pos,  bc_meta  = [], [], []

    for kw in KEYWORDS:
        for alpha_name, alpha_str in [('AZ', AZ), ('KA', KA)]:
            idx = {c: i for i, c in enumerate(alpha_str)}
            kw_ints = [idx[kw[i % len(kw)]] for i in range(N)]

            for j in range(N - len(ENE) + 1):
                # Vig: PT = (real_CT - key) % 26  → real_CT = (PT + key) % 26
                req_vig  = np.array([(ene_np[k] + kw_ints[j+k]) % 26 for k in range(len(ENE))], dtype=np.int32)
                # Beau: PT = (key - real_CT) % 26 → real_CT = (key - PT) % 26
                req_beau = np.array([(kw_ints[j+k] - ene_np[k]) % 26 for k in range(len(ENE))], dtype=np.int32)
                ene_pats.append(req_vig);  ene_pos.append(j); ene_meta.append((kw, alpha_name, 'vig'))
                ene_pats.append(req_beau); ene_pos.append(j); ene_meta.append((kw, alpha_name, 'beau'))

            for j in range(N - len(BC) + 1):
                req_vig  = np.array([(bc_np[k] + kw_ints[j+k]) % 26 for k in range(len(BC))], dtype=np.int32)
                req_beau = np.array([(kw_ints[j+k] - bc_np[k]) % 26 for k in range(len(BC))], dtype=np.int32)
                bc_pats.append(req_vig);  bc_pos.append(j); bc_meta.append((kw, alpha_name, 'vig'))
                bc_pats.append(req_beau); bc_pos.append(j); bc_meta.append((kw, alpha_name, 'beau'))

    return (np.array(ene_pats, dtype=np.int32), np.array(ene_pos, dtype=np.int32), ene_meta,
            np.array(bc_pats,  dtype=np.int32), np.array(bc_pos,  dtype=np.int32), bc_meta)

# Precompute globally
print("Building required patterns ...", flush=True)
t0 = time.time()
ENE_PATS, ENE_POS, ENE_META, BC_PATS, BC_POS, BC_META = build_required_patterns()
print(f"  ENE patterns: {len(ENE_PATS):,}  BC patterns: {len(BC_PATS):,}  ({time.time()-t0:.1f}s)", flush=True)

# ─── DECODE (for verification after hit) ─────────────────────────────────────
def decode_verify(real_ct_str):
    """Full decode of a candidate real CT."""
    hits = []
    for kw in KEYWORDS:
        for alpha_name, alpha_str in [('AZ', AZ), ('KA', KA)]:
            idx = {c: i for i, c in enumerate(alpha_str)}
            kw_ints = [idx[kw[i % len(kw)]] for i in range(N)]
            for cipher_name, fn in [
                ('vig',  lambda ct, ki: [(ord(c)-65 - ki[i]) % 26 for i, c in enumerate(ct)]),
                ('beau', lambda ct, ki: [(ki[i] - (ord(c)-65)) % 26 for i, c in enumerate(ct)]),
            ]:
                pt_ints = fn(real_ct_str, kw_ints)
                pt = ''.join(chr(v+65) for v in pt_ints)
                ep = pt.find(ENE)
                bp = pt.find(BC)
                if ep >= 0 or bp >= 0:
                    sc = qscore(pt)
                    hits.append({'kw': kw, 'alpha': alpha_name, 'cipher': cipher_name,
                                 'pt': pt, 'score': sc, 'ene': ep, 'bc': bp})
    return hits

# ─── COLUMNAR PERMUTATION BUILDER ────────────────────────────────────────────
def build_perm_batch(col_orders_arr, W, convention=1):
    """
    Build permutation arrays for a batch of column orderings.
    col_orders_arr: (B, W) int32 array
    Returns: perm (B, N) int32 array where perm[b, p] = carved_CT position for real_CT[p]
    """
    B = col_orders_arr.shape[0]
    R     = (N + W - 1) // W
    extra = N % W
    if extra == 0: extra = W

    if convention == 1:
        # Short cols = rightmost natural cols
        col_len_nat = np.array([R if c < extra else R-1 for c in range(W)], dtype=np.int32)
        ordered_lengths = col_len_nat[col_orders_arr]  # (B, W)
    else:
        # Short cols = last key-positions
        col_len_key = np.array([R if i < extra else R-1 for i in range(W)], dtype=np.int32)
        ordered_lengths = np.tile(col_len_key, (B, 1))  # (B, W)

    starts_carved = np.zeros((B, W), dtype=np.int32)
    if W > 1:
        starts_carved[:, 1:] = np.cumsum(ordered_lengths[:, :-1], axis=1)

    rank = np.argsort(col_orders_arr, axis=1)  # (B, W)
    start_nat = np.take_along_axis(starts_carved, rank, axis=1)  # (B, W)

    col_of_pos = np.arange(N, dtype=np.int32) % W
    row_of_pos = np.arange(N, dtype=np.int32) // W
    perm = start_nat[:, col_of_pos] + row_of_pos  # (B, N)
    return np.clip(perm, 0, N-1)

# ─── FAST BATCH CHECK (constraint-based) ─────────────────────────────────────
def fast_batch_check(col_orders_list, W,
                     ene_pats, ene_pos_arr, ene_meta,
                     bc_pats,  bc_pos_arr,  bc_meta,
                     convention=1):
    """
    For each batch of col_orders, check if any (crib_pos, keyword) constraint is satisfied.
    Returns list of hit dicts.

    Optimization: instead of full decryption, only extract the 13-char or 11-char
    windows from the unscrambled CT and compare against precomputed requirements.
    """
    if not col_orders_list:
        return []

    B = len(col_orders_list)
    col_orders_arr = np.array(col_orders_list, dtype=np.int32)
    perm = build_perm_batch(col_orders_arr, W, convention)  # (B, N)

    # Unscramble all B items
    unscrambled = ct_np[perm]  # (B, N)

    hits = []

    # ── ENE check ──────────────────────────────────────────────────────────────
    L_ene = len(ENE)
    # For each unique crib position j, extract (B, L_ene) window and check against all combos at position j
    unique_ene_positions = sorted(set(ene_pos_arr.tolist()))
    # Group pattern indices by position
    ene_by_pos = {}
    for i, j in enumerate(ene_pos_arr.tolist()):
        if j not in ene_by_pos: ene_by_pos[j] = []
        ene_by_pos[j].append(i)

    for j in unique_ene_positions:
        window = unscrambled[:, j:j+L_ene]  # (B, L_ene)
        pat_indices = ene_by_pos[j]
        pats_at_j = ene_pats[np.array(pat_indices)]  # (n_pats_j, L_ene)

        # Check all patterns at this position against all batch items
        # match[b, p] = True if window[b] == pats_at_j[p]
        # Broadcasting: (B, 1, L_ene) vs (1, n_pats_j, L_ene)
        match = np.all(window[:, np.newaxis, :] == pats_at_j[np.newaxis, :, :], axis=2)  # (B, n_pats_j)
        hit_b, hit_p = np.where(match)
        for b_idx, p_local in zip(hit_b, hit_p):
            g_idx = pat_indices[p_local]
            kw, alpha, cipher = ene_meta[g_idx]
            # Verify with full decode
            if convention == 1:
                real_ct = ''.join(K4[perm[b_idx, pos]] for pos in range(N))
            else:
                real_ct = ''.join(K4[perm[b_idx, pos]] for pos in range(N))
            verified = decode_verify(real_ct)
            for v in verified:
                hits.append({
                    'W': W, 'conv': convention,
                    'col_order': tuple(col_orders_list[b_idx]),
                    'crib': 'ENE', 'pos': j,
                    **v
                })

    # ── BC check ───────────────────────────────────────────────────────────────
    L_bc = len(BC)
    bc_by_pos = {}
    for i, j in enumerate(bc_pos_arr.tolist()):
        if j not in bc_by_pos: bc_by_pos[j] = []
        bc_by_pos[j].append(i)

    for j in sorted(set(bc_pos_arr.tolist())):
        window = unscrambled[:, j:j+L_bc]  # (B, L_bc)
        pat_indices = bc_by_pos[j]
        pats_at_j = bc_pats[np.array(pat_indices)]  # (n_pats_j, L_bc)
        match = np.all(window[:, np.newaxis, :] == pats_at_j[np.newaxis, :, :], axis=2)
        hit_b, hit_p = np.where(match)
        for b_idx, p_local in zip(hit_b, hit_p):
            g_idx = pat_indices[p_local]
            kw, alpha, cipher = bc_meta[g_idx]
            real_ct = ''.join(K4[perm[b_idx, pos]] for pos in range(N))
            verified = decode_verify(real_ct)
            for v in verified:
                hits.append({
                    'W': W, 'conv': convention,
                    'col_order': tuple(col_orders_list[b_idx]),
                    'crib': 'BC', 'pos': j,
                    **v
                })

    return hits

# ─── WORKER ────────────────────────────────────────────────────────────────────
def _worker(args):
    W, prefix_tuple, batch_size = args

    prefix   = list(prefix_tuple)
    remaining = [c for c in range(W) if c not in prefix]

    # Rebuild patterns in worker (avoids pickling large arrays)
    ene_p, ene_pos_a, ene_m, bc_p, bc_pos_a, bc_m = build_required_patterns()

    all_hits = []
    batch = []
    count = 0

    for rest in permutations(remaining):
        batch.append(prefix + list(rest))
        count += 1
        if len(batch) >= batch_size:
            for conv in [1, 2]:
                h = fast_batch_check(batch, W, ene_p, ene_pos_a, ene_m,
                                              bc_p, bc_pos_a, bc_m, conv)
                all_hits.extend(h)
            if all_hits:
                print(f"  [W{W} pfx={prefix_tuple}] {len(all_hits)} hits!", flush=True)
            batch = []

    if batch:
        for conv in [1, 2]:
            h = fast_batch_check(batch, W, ene_p, ene_pos_a, ene_m,
                                          bc_p, bc_pos_a, bc_m, conv)
            all_hits.extend(h)

    return all_hits, count

# ─── EXHAUSTIVE SEARCH ─────────────────────────────────────────────────────────
def exhaustive(W, batch_size=8000):
    total = 1
    for i in range(1, W+1): total *= i
    print(f"\n=== Exhaustive W{W}: {total:,} perms × 2 conventions ===", flush=True)
    t0 = time.time()

    # Split by prefix of length 2
    prefixes = [(i, j) for i in range(W) for j in range(W) if i != j]
    n_cores = min(mp.cpu_count(), len(prefixes))
    print(f"  {len(prefixes)} tasks → {n_cores} cores, batch={batch_size}", flush=True)

    args = [(W, p, batch_size) for p in prefixes]
    with mp.Pool(n_cores, maxtasksperchild=1) as pool:
        results = pool.map(_worker, args)

    all_hits, total_count = [], 0
    for hits, cnt in results:
        all_hits.extend(hits)
        total_count += cnt

    elapsed = time.time() - t0
    print(f"  Done: {total_count:,} perms in {elapsed:.1f}s ({total_count/max(elapsed,0.001):.0f}/s)",
          flush=True)
    print(f"  Hits: {len(all_hits)}", flush=True)

    for h in all_hits:
        msg = (f"\n{'='*65}\n*** CRIB HIT W{W} ***\n"
               f"ColOrder: {h['col_order']}\nConvention: {h['conv']}\n"
               f"KW/Alpha/Cipher: {h['kw']}/{h['alpha']}/{h['cipher']}\n"
               f"ENE@{h['ene']}  BC@{h['bc']}\n"
               f"PT: {h['pt']}\nScore: {h['score']:.2f}\n")
        print(msg, flush=True)
        with open(f'{RESULTS_DIR}/HITS_fast.txt', 'a') as f:
            f.write(msg)

    return all_hits

# ─── BENCHMARK ────────────────────────────────────────────────────────────────
def benchmark():
    """Time the batch check for B=8000, W=11 on one core."""
    W = 11
    import random
    batch = [list(np.random.permutation(W)) for _ in range(8000)]
    ene_p, ene_pos_a, ene_m, bc_p, bc_pos_a, bc_m = build_required_patterns()
    t0 = time.time()
    fast_batch_check(batch, W, ene_p, ene_pos_a, ene_m, bc_p, bc_pos_a, bc_m, 1)
    elapsed = time.time() - t0
    rate = 8000 / elapsed
    print(f"Benchmark: B=8000, W=11 → {elapsed:.3f}s ({rate:.0f} perms/s per core)", flush=True)
    print(f"Est. W11 total ({40e6:.0f} perms / {mp.cpu_count()} cores × {rate:.0f} /s) = "
          f"{40e6 / mp.cpu_count() / rate:.1f}s", flush=True)
    print(f"Est. W12 total ({479e6:.0f} perms / {mp.cpu_count()} cores × {rate:.0f} /s) = "
          f"{479e6 / mp.cpu_count() / rate:.1f}s", flush=True)

# ─── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(f"K4 Fast Strip/Route | N={N} | CPUs={mp.cpu_count()}")
    print(f"K4: {K4}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    benchmark()

    t_start = time.time()

    for W in [11, 12]:
        hits = exhaustive(W, batch_size=8000)
        if hits:
            print(f"\n*** {len(hits)} HITS FOR W={W} ***")
            for h in hits:
                print(f"  {h}")

    print(f"\nDONE. Total time: {time.time()-t_start:.1f}s")
    print(f"Check {RESULTS_DIR}/HITS_fast.txt for any hits.")
