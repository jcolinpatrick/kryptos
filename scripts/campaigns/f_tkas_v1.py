#!/usr/bin/env python3 -u
"""
=================================================================
TRANSPOSITION-KEYSTREAM ALIGNMENT SEARCH (TKAS) v1
=================================================================
Cipher:     Two-system model (substitution + stego/transposition)
Family:     campaigns
Status:     active
Keyspace:   ~4.5M transpositions x 3 cipher variants x 13 periods
Last run:   never
Best score: --

HYPOTHESIS
----------
The "periodic sub impossible on null-extracted CT73" proof assumes
the 73 real characters maintain their original order (S2=identity).
If System 2 includes a transposition S2 within the non-null chars,
the proof does NOT apply. The 24 Model B keystream values are fixed
(determined by CT97 and cribs), but their POSITIONS in the key array
depend on S2. A correct S2 could make them periodic.

KEY OPTIMIZATION
----------------
For the standard (3,1,1,2) null mask partition, the CT73 indices of
all 24 crib positions are FIXED regardless of which specific nulls
are chosen within each cluster (crib range 21-73 does not overlap
varying ranges 38-45/55-56/87-88/93-96 for INDEX counting purposes).
Scoring is mask-independent: we test transpositions x variants x periods.

PHASES
------
1. K3-style double rotation (72 and 73 chars, all factor pairs)
2. Single rotation CW/CCW (72 and 73 chars)
3. Columnar (widths 2-10 exhaustive, 11-31 SA-sampled, on 73 chars)
4. Route ciphers (serpentine, spiral on all rectangles for 72 and 73)
5. Rail fence (depths 2-36, on 73 chars)
6. Fleissner 180 turning grille SA (72 chars, 1000 restarts x 5000 steps)
=================================================================
"""

import sys
import os
import json
import time
import itertools
import random
from collections import Counter
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_ENTRIES, N_CRIBS, CRIB_DICT,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, serpentine_perm, spiral_perm, rail_fence_perm,
    invert_perm,
)

# ── Constants ──────────────────────────────────────────────────────────

CONSENSUS_NULLS = frozenset(
    {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
)
CLUSTER_A = list(range(38, 46))   # {38,...,45}
CLUSTER_B = [55, 56]
CLUSTER_C = [87, 88]
CLUSTER_D = [93, 94, 95, 96]

CRIB_POS_CT97 = sorted(CRIB_DICT.keys())  # 24 positions in CT97

# Build 3 keystream variants (24 values each)
def _build_keystream(variant):
    keys = []
    for pos in CRIB_POS_CT97:
        ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[CRIB_DICT[pos]]
        if variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        elif variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "variant_beaufort":
            k = (pt_val - ct_val) % MOD
        else:
            raise ValueError(variant)
        keys.append(k)
    return keys

KEYSTREAMS = {
    "beaufort": _build_keystream("beaufort"),
    "vigenere": _build_keystream("vigenere"),
    "variant_beaufort": _build_keystream("variant_beaufort"),
}

# Compute CT73 crib indices (mask-independent for 3+1+1+2 partition)
_REF_VARYING = [38, 39, 40, 55, 87, 93, 94]   # arbitrary representative
_REF_NULLS = CONSENSUS_NULLS | set(_REF_VARYING)
_REF_NONNULL = sorted(set(range(CT_LEN)) - _REF_NULLS)  # 73 positions
assert len(_REF_NONNULL) == 73

CRIB_CT73_IDX = [_REF_NONNULL.index(pos) for pos in CRIB_POS_CT97]
# ENE: CT73 indices 13-25, BCL: CT73 indices 47-57

# For 72-char case (delimiter removed): CT72 = CT73 minus last char
# All crib CT73 indices < 72, so CRIB_CT72_IDX = CRIB_CT73_IDX
CRIB_CT72_IDX = CRIB_CT73_IDX[:]
assert all(idx < 72 for idx in CRIB_CT72_IDX)

MAX_PERIOD = 13
REPORT_THRESHOLD = 16  # report everything >= 16 at any period

# ── Scoring ────────────────────────────────────────────────────────────

def score_period(epos_list, key_values, period):
    """Count cribs consistent with a periodic key at given period."""
    residue_key = {}
    score = 0
    for epos, kv in zip(epos_list, key_values):
        r = epos % period
        if r not in residue_key:
            residue_key[r] = kv
            score += 1
        elif residue_key[r] == kv:
            score += 1
    return score


def score_transposition(s2_perm, crib_indices, max_period=MAX_PERIOD):
    """Score a transposition across all variants and periods.

    Returns list of (variant, period, score) for scores >= REPORT_THRESHOLD,
    plus (best_variant, best_period, best_score) overall.
    """
    n = len(s2_perm)
    epos = [s2_perm[idx] for idx in crib_indices if idx < n]
    if len(epos) != 24:
        return [], ("", 0, 0)

    hits = []
    best = ("", 0, 0)
    for variant, kv in KEYSTREAMS.items():
        for p in range(1, max_period + 1):
            s = score_period(epos, kv, p)
            if s > best[2]:
                best = (variant, p, s)
            if s >= REPORT_THRESHOLD:
                hits.append((variant, p, s))
    return hits, best


def compute_ic(values):
    n = len(values)
    if n < 2:
        return 0.0
    freq = Counter(values)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


# ── Transposition generators ──────────────────────────────────────────

def get_factor_pairs(n, min_dim=2):
    """All (rows, cols) with rows*cols=n, rows>=min_dim, cols>=min_dim."""
    pairs = []
    for r in range(min_dim, n + 1):
        if n % r == 0:
            c = n // r
            if c >= min_dim:
                pairs.append((r, c))
    return pairs


def double_rotation_perm(n, r1, c1, r2, c2):
    """K3-style double rotation: write r1xc1 → rotate CW → read → write r2xc2 → rotate CW → read.
    Returns gather perm: output[k] = input[perm[k]]."""
    if r1 * c1 != n or r2 * c2 != n:
        return None
    # First rotation
    inter = [0] * n
    for i in range(n):
        row, col = divmod(i, c1)
        j = col * r1 + (r1 - 1 - row)
        if j < n:
            inter[j] = i
    # Second rotation
    perm = [0] * n
    for j in range(n):
        row, col = divmod(j, c2)
        k = col * r2 + (r2 - 1 - row)
        if k < n:
            perm[k] = inter[j]
    return perm


def single_rotation_perm(n, rows, cols):
    """Single CW rotation on rows x cols grid."""
    if rows * cols != n:
        return None
    perm = [0] * n
    for i in range(n):
        row, col = divmod(i, cols)
        j = col * rows + (rows - 1 - row)
        if j < n:
            perm[j] = i
    return perm


def columnar_perm_fast(width, col_order, length):
    """Optimized columnar permutation: write row-by-row, read by column order."""
    full_rows, remainder = divmod(length, width)
    rank_to_col = [0] * width
    for col_idx, rank in enumerate(col_order):
        rank_to_col[rank] = col_idx
    perm = []
    for rank in range(width):
        col_idx = rank_to_col[rank]
        col_len = full_rows + (1 if col_idx < remainder else 0)
        for r in range(col_len):
            perm.append(r * width + col_idx)
    return perm


def fleissner_180_perm(n, choices):
    """Fleissner 180-degree turning grille permutation.
    n must be even. choices[i] selects which of pair (i, n-1-i) is read first.
    Pass 1: read selected cells in position order.
    Pass 2: read remaining cells in position order.
    """
    n_pairs = n // 2
    pass1 = []
    pass2 = []
    for i in range(n_pairs):
        partner = n - 1 - i
        if choices[i]:
            pass1.append(i)
            pass2.append(partner)
        else:
            pass1.append(partner)
            pass2.append(i)
    pass1.sort()
    pass2.sort()
    return pass1 + pass2


# ── Phase runners ──────────────────────────────────────────────────────

def run_phase_double_rotation():
    """Phase 1: K3-style double rotation on 72 and 73 chars."""
    results = []
    seen = set()
    for n, crib_idx, label in [(72, CRIB_CT72_IDX, "72"), (73, CRIB_CT73_IDX, "73")]:
        fps = get_factor_pairs(n)
        count = 0
        for r1, c1 in fps:
            for r2, c2 in fps:
                perm = double_rotation_perm(n, r1, c1, r2, c2)
                if perm is None:
                    continue
                pk = tuple(perm)
                if pk in seen:
                    continue
                seen.add(pk)
                count += 1
                hits, best = score_transposition(perm, crib_idx)
                for variant, period, score in hits:
                    results.append({
                        "phase": 1,
                        "family": "double_rotation",
                        "n": n,
                        "desc": f"drot_{r1}x{c1}_{r2}x{c2}_n{label}",
                        "variant": variant,
                        "period": period,
                        "score": score,
                    })
        print(f"  n={n}: {count} unique double rotations tested")
    return results


def run_phase_single_rotation():
    """Phase 2: Single CW rotation on 72 and 73 chars."""
    results = []
    seen = set()
    for n, crib_idx, label in [(72, CRIB_CT72_IDX, "72"), (73, CRIB_CT73_IDX, "73")]:
        fps = get_factor_pairs(n)
        count = 0
        for r, c in fps:
            perm = single_rotation_perm(n, r, c)
            if perm is None:
                continue
            pk = tuple(perm)
            if pk in seen:
                continue
            seen.add(pk)
            count += 1
            hits, best = score_transposition(perm, crib_idx)
            for variant, period, score in hits:
                results.append({
                    "phase": 2,
                    "family": "single_rotation",
                    "n": n,
                    "desc": f"srot_{r}x{c}_n{label}",
                    "variant": variant,
                    "period": period,
                    "score": score,
                })
        print(f"  n={n}: {count} unique single rotations tested")
    return results


def _score_col_batch(args):
    """Worker for columnar scoring. Returns hits."""
    width, ordering_batch, n, crib_idx = args
    hits = []
    for col_order in ordering_batch:
        perm = columnar_perm_fast(width, col_order, n)
        if len(perm) != n:
            continue
        epos_cache = {}
        for variant, kv in KEYSTREAMS.items():
            epos_key = id(perm)  # reuse across variants
            if epos_key not in epos_cache:
                epos_cache[epos_key] = [perm[idx] for idx in crib_idx if idx < n]
            epos = epos_cache[epos_key]
            if len(epos) != 24:
                continue
            for p in range(1, MAX_PERIOD + 1):
                s = score_period(epos, kv, p)
                if s >= REPORT_THRESHOLD:
                    hits.append({
                        "phase": 3,
                        "family": f"columnar_w{width}",
                        "n": n,
                        "desc": f"col_w{width}",
                        "col_order": list(col_order),
                        "variant": variant,
                        "period": p,
                        "score": s,
                    })
    return hits


def run_phase_columnar(n=73, exhaustive_max=10, sa_samples=10000, n_workers=None):
    """Phase 3: Columnar transposition, widths 2-31."""
    if n_workers is None:
        n_workers = min(cpu_count(), 28)
    results = []
    crib_idx = CRIB_CT73_IDX if n == 73 else CRIB_CT72_IDX

    total_orderings = 0
    for w in range(2, min(32, n)):
        t0 = time.time()
        if w <= exhaustive_max:
            # Exhaustive: generate all orderings, batch them for multiprocessing
            all_orderings = list(itertools.permutations(range(w)))
            n_ord = len(all_orderings)
            total_orderings += n_ord

            batch_size = max(1, n_ord // (n_workers * 4))
            batches = []
            for i in range(0, n_ord, batch_size):
                batches.append((w, all_orderings[i:i + batch_size], n, crib_idx))

            if n_ord > 1000 and n_workers > 1:
                with Pool(n_workers) as pool:
                    batch_results = pool.map(_score_col_batch, batches)
                for br in batch_results:
                    results.extend(br)
            else:
                for batch in batches:
                    results.extend(_score_col_batch(batch))

            elapsed = time.time() - t0
            print(f"  w={w}: {n_ord:,} orderings (exhaustive) [{elapsed:.1f}s]")
        else:
            # SA-sampled
            orderings = []
            seen = set()
            for _ in range(sa_samples):
                o = list(range(w))
                random.shuffle(o)
                ot = tuple(o)
                if ot not in seen:
                    seen.add(ot)
                    orderings.append(ot)
            n_ord = len(orderings)
            total_orderings += n_ord

            batch_size = max(1, n_ord // (n_workers * 4))
            batches = []
            for i in range(0, n_ord, batch_size):
                batches.append((w, orderings[i:i + batch_size], n, crib_idx))

            if n_workers > 1:
                with Pool(n_workers) as pool:
                    batch_results = pool.map(_score_col_batch, batches)
                for br in batch_results:
                    results.extend(br)
            else:
                for batch in batches:
                    results.extend(_score_col_batch(batch))

            elapsed = time.time() - t0
            print(f"  w={w}: {n_ord:,} orderings (sampled) [{elapsed:.1f}s]")

    print(f"  Total columnar orderings: {total_orderings:,}")
    return results


def run_phase_routes():
    """Phase 4: Serpentine and spiral on all rectangles for 72 and 73 chars."""
    results = []
    seen = set()
    for n, crib_idx, label in [(72, CRIB_CT72_IDX, "72"), (73, CRIB_CT73_IDX, "73")]:
        fps = get_factor_pairs(n)
        count = 0
        for r, c in fps:
            for vertical in [False, True]:
                perm = serpentine_perm(r, c, n, vertical=vertical)
                if len(perm) == n:
                    pk = (n, "serp", tuple(perm))
                    if pk not in seen:
                        seen.add(pk)
                        count += 1
                        hits, _ = score_transposition(perm, crib_idx)
                        v_str = "v" if vertical else "h"
                        for variant, period, score in hits:
                            results.append({
                                "phase": 4,
                                "family": "serpentine",
                                "n": n,
                                "desc": f"serp_{r}x{c}_{v_str}_n{label}",
                                "variant": variant,
                                "period": period,
                                "score": score,
                            })

            for cw in [True, False]:
                perm = spiral_perm(r, c, n, clockwise=cw)
                if len(perm) == n:
                    pk = (n, "spiral", tuple(perm))
                    if pk not in seen:
                        seen.add(pk)
                        count += 1
                        hits, _ = score_transposition(perm, crib_idx)
                        d_str = "cw" if cw else "ccw"
                        for variant, period, score in hits:
                            results.append({
                                "phase": 4,
                                "family": "spiral",
                                "n": n,
                                "desc": f"spiral_{r}x{c}_{d_str}_n{label}",
                                "variant": variant,
                                "period": period,
                                "score": score,
                            })
        print(f"  n={n}: {count} unique route perms tested")
    return results


def run_phase_rail_fence(n=73):
    """Phase 5: Rail fence at depths 2-36."""
    results = []
    crib_idx = CRIB_CT73_IDX
    count = 0
    for d in range(2, 37):
        perm = rail_fence_perm(n, d)
        if len(perm) != n:
            continue
        count += 1
        hits, _ = score_transposition(perm, crib_idx)
        for variant, period, score in hits:
            results.append({
                "phase": 5,
                "family": "rail_fence",
                "n": n,
                "desc": f"rail_d{d}",
                "variant": variant,
                "period": period,
                "score": score,
            })
    print(f"  {count} rail fence depths tested")
    return results


def _fleissner_sa_worker(args):
    """SA worker for Fleissner 180 search on 72 chars."""
    restart_id, n_steps, crib_idx, seed = args
    rng = random.Random(seed)
    n = 72
    n_pairs = n // 2

    # Random initial grille
    choices = [rng.randint(0, 1) for _ in range(n_pairs)]
    perm = fleissner_180_perm(n, choices)

    def _score_perm(p):
        epos = [p[idx] for idx in crib_idx if idx < n]
        if len(epos) != 24:
            return 0
        best = 0
        for kv in KEYSTREAMS.values():
            for period in range(2, MAX_PERIOD + 1):
                s = score_period(epos, kv, period)
                if s > best:
                    best = s
        return best

    current_score = _score_perm(perm)
    best_score = current_score
    best_choices = choices[:]
    best_perm = perm[:]

    T = 3.0
    T_min = 0.01
    cooling = (T_min / T) ** (1.0 / max(n_steps, 1))

    for step in range(n_steps):
        flip = rng.randint(0, n_pairs - 1)
        choices[flip] = 1 - choices[flip]
        new_perm = fleissner_180_perm(n, choices)
        new_score = _score_perm(new_perm)

        delta = new_score - current_score
        if delta > 0 or rng.random() < (2.718 ** (delta / T) if T > 0.001 else 0):
            perm = new_perm
            current_score = new_score
            if current_score > best_score:
                best_score = current_score
                best_choices = choices[:]
                best_perm = perm[:]
        else:
            choices[flip] = 1 - choices[flip]  # revert

        T *= cooling

    # Identify which variant/period produced the best score
    hits = []
    if best_score >= REPORT_THRESHOLD:
        epos = [best_perm[idx] for idx in crib_idx if idx < n]
        for variant, kv in KEYSTREAMS.items():
            for period in range(2, MAX_PERIOD + 1):
                s = score_period(epos, kv, period)
                if s >= REPORT_THRESHOLD:
                    hits.append({
                        "phase": 6,
                        "family": "fleissner_180",
                        "n": n,
                        "desc": f"fleissner_r{restart_id}",
                        "variant": variant,
                        "period": period,
                        "score": s,
                        "choices": best_choices,
                    })

    return best_score, hits


def run_phase_fleissner(n_restarts=1000, n_steps=5000, n_workers=None):
    """Phase 6: Fleissner 180 turning grille via SA on 72 chars."""
    if n_workers is None:
        n_workers = min(cpu_count(), 28)

    crib_idx = CRIB_CT72_IDX
    base_seed = 20260318

    tasks = [
        (i, n_steps, crib_idx, base_seed + i)
        for i in range(n_restarts)
    ]

    results = []
    best_global = 0

    if n_workers > 1:
        with Pool(n_workers) as pool:
            for best_score, hits in pool.imap_unordered(_fleissner_sa_worker, tasks, chunksize=10):
                results.extend(hits)
                if best_score > best_global:
                    best_global = best_score
    else:
        for task in tasks:
            best_score, hits = _fleissner_sa_worker(task)
            results.extend(hits)
            if best_score > best_global:
                best_global = best_score

    print(f"  {n_restarts} SA restarts x {n_steps} steps, best={best_global}")
    return results


# ── Verification ───────────────────────────────────────────────────────

def verify_mask_independence():
    """Verify CT73 crib indices are mask-independent for all (3,1,1,2) masks."""
    from itertools import combinations
    count = 0
    for a in combinations(CLUSTER_A, 3):
        for b in CLUSTER_B:
            for c in CLUSTER_C:
                for d in combinations(CLUSTER_D, 2):
                    varying = list(a) + [b, c] + list(d)
                    nulls = CONSENSUS_NULLS | set(varying)
                    nonnull = sorted(set(range(CT_LEN)) - nulls)
                    indices = [nonnull.index(pos) for pos in CRIB_POS_CT97]
                    if indices != CRIB_CT73_IDX:
                        return -1  # failure
                    count += 1
    return count


def verify_known_keystream():
    """Cross-check computed keystreams against constants.py values."""
    beau_ene = list(BEAUFORT_KEY_ENE)
    beau_bc = list(BEAUFORT_KEY_BC)
    computed = KEYSTREAMS["beaufort"]
    assert computed[:13] == beau_ene, f"ENE Beaufort mismatch: {computed[:13]} vs {beau_ene}"
    assert computed[13:] == beau_bc, f"BC Beaufort mismatch: {computed[13:]} vs {beau_bc}"

    vig_ene = list(VIGENERE_KEY_ENE)
    vig_bc = list(VIGENERE_KEY_BC)
    computed_v = KEYSTREAMS["vigenere"]
    assert computed_v[:13] == vig_ene, f"ENE Vigenere mismatch"
    assert computed_v[13:] == vig_bc, f"BC Vigenere mismatch"
    return True


# ── Reporting ──────────────────────────────────────────────────────────

def expected_random_score(period, n_cribs=24):
    """Monte Carlo estimate of expected random score at given period."""
    rng = random.Random(42)
    total = 0
    trials = 10000
    for _ in range(trials):
        positions = [rng.randint(0, 72) for _ in range(n_cribs)]
        values = [rng.randint(0, 25) for _ in range(n_cribs)]
        total += score_period(positions, values, period)
    return total / trials


def report_results(all_results, output_path=None):
    """Print summary and write results."""
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)

    if not all_results:
        print("  NO configs scored >= {REPORT_THRESHOLD}")
        return

    # Deduplicate
    seen = set()
    unique = []
    for r in all_results:
        key = (r["family"], r.get("desc", ""), r["variant"], r["period"], r["score"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    # Sort by score descending
    unique.sort(key=lambda x: -x["score"])

    print(f"\n  Total hits >= {REPORT_THRESHOLD}: {len(unique)}")
    print(f"\n  {'Score':>5}  {'Period':>6}  {'Variant':>16}  {'Family':>20}  Description")
    print(f"  {'─'*5}  {'─'*6}  {'─'*16}  {'─'*20}  {'─'*30}")

    for r in unique[:100]:  # Top 100
        print(
            f"  {r['score']:>5}  {r['period']:>6}  {r['variant']:>16}  "
            f"{r['family']:>20}  {r.get('desc', '')}"
        )

    # Compute expected baselines for context
    print(f"\n  Expected random baselines:")
    for p in [3, 5, 7, 10, 13]:
        exp = expected_random_score(p)
        print(f"    period {p:>2}: {exp:.1f}/24")

    # Check for breakthrough
    max_score = unique[0]["score"] if unique else 0
    if max_score >= 24:
        print(f"\n  *** BREAKTHROUGH: score 24/24 found! ***")
    elif max_score >= 20:
        print(f"\n  *** STRONG SIGNAL: score {max_score}/24 found! ***")
    elif max_score >= 18:
        print(f"\n  ** POTENTIAL SIGNAL: score {max_score}/24 found **")
    else:
        print(f"\n  Best score: {max_score}/24 (below signal threshold 18)")

    # Write JSON results
    if output_path is None:
        output_path = os.path.join(_ROOT, "results", "f_tkas_v1.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "experiment": "TKAS_v1",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "report_threshold": REPORT_THRESHOLD,
            "max_period": MAX_PERIOD,
            "n_hits": len(unique),
            "max_score": max_score,
            "hits": unique,
            "keystream_beaufort": KEYSTREAMS["beaufort"],
            "keystream_vigenere": KEYSTREAMS["vigenere"],
            "crib_ct73_indices": CRIB_CT73_IDX,
        }, f, indent=2)
    print(f"\n  Results written to: {output_path}")


# ── Main ───────────────────────────────────────────────────────────────

def main():
    t_start = time.time()
    random.seed(20260318)

    print("=" * 70)
    print("TKAS v1 — Transposition-Keystream Alignment Search")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"Crib positions (CT97): {CRIB_POS_CT97}")
    print(f"Crib CT73 indices:     {CRIB_CT73_IDX}")
    print(f"Beaufort keystream:    {KEYSTREAMS['beaufort']}")
    print(f"  = {''.join(ALPH[k] for k in KEYSTREAMS['beaufort'])}")
    print(f"Report threshold: {REPORT_THRESHOLD}/24")
    print(f"Workers: {min(cpu_count(), 28)}")

    # Verification
    print(f"\n{'─'*70}")
    print("Phase 0: Verification")
    print(f"{'─'*70}")

    assert verify_known_keystream(), "Keystream verification failed!"
    print("  Keystream values verified against constants.py")

    n_masks = verify_mask_independence()
    if n_masks < 0:
        print("  ERROR: Mask independence FAILED!")
        sys.exit(1)
    print(f"  Mask independence verified across {n_masks} masks")

    # Phase 1: K3-style double rotation
    print(f"\n{'─'*70}")
    print("Phase 1: K3-style double rotation")
    print(f"{'─'*70}")
    results_1 = run_phase_double_rotation()

    # Phase 2: Single rotation
    print(f"\n{'─'*70}")
    print("Phase 2: Single rotation CW")
    print(f"{'─'*70}")
    results_2 = run_phase_single_rotation()

    # Phase 3: Columnar
    print(f"\n{'─'*70}")
    print("Phase 3: Columnar transposition (widths 2-31)")
    print(f"{'─'*70}")
    results_3 = run_phase_columnar(n=73, exhaustive_max=10, sa_samples=10000)

    # Phase 4: Route ciphers
    print(f"\n{'─'*70}")
    print("Phase 4: Route ciphers (serpentine + spiral)")
    print(f"{'─'*70}")
    results_4 = run_phase_routes()

    # Phase 5: Rail fence
    print(f"\n{'─'*70}")
    print("Phase 5: Rail fence")
    print(f"{'─'*70}")
    results_5 = run_phase_rail_fence(n=73)

    # Phase 6: Fleissner 180 SA
    print(f"\n{'─'*70}")
    print("Phase 6: Fleissner 180-degree SA (72 chars)")
    print(f"{'─'*70}")
    results_6 = run_phase_fleissner(n_restarts=1000, n_steps=5000)

    # Report
    all_results = results_1 + results_2 + results_3 + results_4 + results_5 + results_6
    report_results(all_results)

    elapsed = time.time() - t_start
    print(f"\n  Total elapsed: {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print("=" * 70)


if __name__ == "__main__":
    main()
