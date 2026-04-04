#!/usr/bin/env python3
"""
Cipher:   Stego mechanism (palette controls)
Family:   stego_mechanism
Status:   active
Keyspace: ~300 SA campaigns across 4 control experiments
Last run:
Best score:

PURPOSE: Four controls to determine whether the BGIKOWZ palette convergence
result is specific to this palette and to K4, or a generic property of
palette-constrained optimization.

PRIOR RESULT: Under BGIKOWZ constraint, cross-model Jaccard rises from
0.160 (unconstrained) to 0.676 (palette top-24). This is a CONDITIONAL
result until these controls are run.

CONTROLS:
  1. RANDOM PALETTES: 100+ random 7-letter palettes with >=24 qualifying
     positions. Run SA under 3 variants. Compare Jaccard distribution to
     BGIKOWZ's 0.429 (top-17) / 0.676 (top-24).

  2. NEAR-NEIGHBOR PALETTES: All 1-swap neighbors of BGIKOWZ (swap 1 letter
     out, 1 in). Tests whether the effect is specific to these exact 7
     letters or broadly shared.

  3. SHUFFLED-K4: Run BGIKOWZ-constrained SA on shuffled CTs (letter
     positions randomized, frequencies preserved). If convergence persists,
     it's methodological. If it collapses, it's K4 structure.

  4. OBJECTIVE SENSITIVITY: Re-score the exhaustive C(31,24) masks with
     periodic crib scoring instead of autokey. Checks if 12/72 optimum
     is scoring-dependent.

VERDICT CRITERIA:
  - BGIKOWZ Jaccard is an outlier (>95th percentile) among random palettes
    with comparable qualifying-position counts → palette IS special
  - BGIKOWZ Jaccard is typical → palette constraint is generically useful
    but BGIKOWZ is not privileged
  - Shuffled CTs show similar convergence → result is methodological
  - Shuffled CTs collapse → result reflects K4 structure
"""

import sys
import os
import random
import math
import time
import json
from collections import Counter
from itertools import combinations
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_POSITIONS, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
)

# ── Constants ────────────────────────────────────────────────────────────────

N = CT_LEN  # 97
N_NULLS = 24
N_PT = N - N_NULLS  # 73
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63
NON_CRIB = sorted(i for i in range(N) if i not in CRIB_POSITIONS)
NC_SET = frozenset(NON_CRIB)

KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
KA_MOD = 26

KW_IDX = tuple(KA_IDX[c] for c in "KRYPTOS")
KW_LEN = len(KW_IDX)

REFERENCE_PALETTE = frozenset(NULL_PALETTE)  # {B,G,I,K,O,W,Z}
N_WORKERS = max(1, cpu_count() - 2)

# SA parameters (reduced for speed — enough for consensus)
SA_RESTARTS = int(os.environ.get('PC_RESTARTS', '50'))
SA_STEPS = int(os.environ.get('PC_STEPS', '50000'))
SCORE_THRESHOLD = 8
TARGET_RANDOM = int(os.environ.get('PC_RANDOM', '100'))
N_SHUFFLES = int(os.environ.get('PC_SHUFFLES', '30'))


# ── Autokey decrypt (reused from sweep) ──────────────────────────────────────

def _autokey_decrypt(ct_str, keyword_idx, variant_id):
    """Autokey decrypt on KA. variant_id: 0=beau, 1=vig, 2=vbeau."""
    klen = len(keyword_idx)
    pt_indices = []
    for i, c in enumerate(ct_str):
        ci = KA_IDX[c]
        ki = keyword_idx[i] if i < klen else pt_indices[i - klen]
        if variant_id == 0:
            pi = (ki - ci) % KA_MOD
        elif variant_id == 1:
            pi = (ci - ki) % KA_MOD
        else:
            pi = (ci + ki) % KA_MOD
        pt_indices.append(pi)
    return ''.join(KA_STR[p] for p in pt_indices)


def _count_crib_hits(pt_str, ene_s, bcl_s):
    n = len(pt_str)
    e = sum(1 for j, c in enumerate(ENE_WORD) if ene_s + j < n and pt_str[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD) if bcl_s + j < n and pt_str[bcl_s + j] == c)
    return e + b


def score_mask_variant(null_set, variant_id, ct_source=CT):
    """Score a mask under one variant. Returns crib hits (0-24)."""
    ct_inner = ''.join(ct_source[i] for i in range(len(ct_source)) if i not in null_set)
    if len(ct_inner) != N_PT:
        return 0.0
    n_before_ene = sum(1 for p in null_set if p < ENE_START)
    n_before_bcl = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n_before_ene
    bcl_s = BCL_START - n_before_bcl
    pt_str = _autokey_decrypt(ct_inner, KW_IDX, variant_id)
    return float(_count_crib_hits(pt_str, ene_s, bcl_s))


# ── SA engine ────────────────────────────────────────────────────────────────

def sa_run(palette_positions_list, variant_id, seed, ct_source=CT,
           steps=SA_STEPS, T0=0.5, Tf=0.01):
    """One SA restart. Returns (best_score, best_mask_sorted)."""
    rng = random.Random(seed)
    pal_set = frozenset(palette_positions_list)

    null_set = set(rng.sample(palette_positions_list, N_NULLS))
    pal_in = set(null_set)
    pal_out = set(pal_set) - pal_in

    score = score_mask_variant(frozenset(null_set), variant_id, ct_source)
    best_sc = score
    best_null = frozenset(null_set)

    for step in range(steps):
        T = T0 * (Tf / T0) ** (step / steps)
        if not pal_in or not pal_out:
            break
        out_pos = rng.choice(list(pal_in))
        in_pos = rng.choice(list(pal_out))

        null_set.discard(out_pos)
        null_set.add(in_pos)

        new_sc = score_mask_variant(frozenset(null_set), variant_id, ct_source)
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / max(T, 1e-10)):
            score = new_sc
            pal_in.discard(out_pos)
            pal_in.add(in_pos)
            pal_out.discard(in_pos)
            pal_out.add(out_pos)
            if score > best_sc:
                best_sc = score
                best_null = frozenset(null_set)
        else:
            null_set.discard(in_pos)
            null_set.add(out_pos)

    return best_sc, sorted(best_null)


# ── Worker and consensus ─────────────────────────────────────────────────────

def _sa_worker(args):
    pal_pos_list, variant_id, seed, ct_source = args
    return sa_run(pal_pos_list, variant_id, seed, ct_source)


def build_consensus_masks(pal_pos_list, ct_source, pool, n_restarts=SA_RESTARTS):
    """Run SA under 3 variants, build consensus, return pairwise Jaccards."""
    results_by_variant = {}

    for vid in range(3):
        tasks = [(pal_pos_list, vid, i * 53 + vid * 9999, ct_source)
                 for i in range(n_restarts)]
        results = pool.map(_sa_worker, tasks)

        freq = Counter()
        scores = []
        for sc, mask in results:
            scores.append(sc)
            if sc >= SCORE_THRESHOLD:
                for p in mask:
                    freq[p] += 1

        # Fallback if too few qualify
        if sum(1 for sc, _ in results if sc >= SCORE_THRESHOLD) < 5:
            freq = Counter()
            max_sc = max(scores) if scores else 0
            for sc, mask in results:
                if sc >= max_sc - 2:
                    for p in mask:
                        freq[p] += 1

        top24 = frozenset(p for p, _ in freq.most_common(N_NULLS))
        top17 = frozenset(p for p, _ in freq.most_common(17))
        results_by_variant[vid] = {
            'top24': top24, 'top17': top17,
            'score_max': max(scores) if scores else 0,
            'score_mean': sum(scores) / len(scores) if scores else 0,
        }

    # Pairwise Jaccard
    def jaccard(a, b):
        if not a and not b:
            return 1.0
        union = a | b
        return len(a & b) / len(union) if union else 0.0

    j17_01 = jaccard(results_by_variant[0]['top17'], results_by_variant[1]['top17'])
    j17_02 = jaccard(results_by_variant[0]['top17'], results_by_variant[2]['top17'])
    j17_12 = jaccard(results_by_variant[1]['top17'], results_by_variant[2]['top17'])
    j24_01 = jaccard(results_by_variant[0]['top24'], results_by_variant[1]['top24'])
    j24_02 = jaccard(results_by_variant[0]['top24'], results_by_variant[2]['top24'])
    j24_12 = jaccard(results_by_variant[1]['top24'], results_by_variant[2]['top24'])

    return {
        'mean_jaccard_17': (j17_01 + j17_02 + j17_12) / 3,
        'mean_jaccard_24': (j24_01 + j24_02 + j24_12) / 3,
        'jaccards_17': (j17_01, j17_02, j17_12),
        'jaccards_24': (j24_01, j24_02, j24_12),
        'score_maxes': [results_by_variant[v]['score_max'] for v in range(3)],
        'variants': results_by_variant,
    }


# ── Periodic scoring (for Control 4) ────────────────────────────────────────

def score_mask_periodic(null_set, variant_id, ct_source=CT, keyword="KRYPTOS"):
    """Score mask using periodic (non-autokey) cipher. Returns crib hits."""
    ct_inner = ''.join(ct_source[i] for i in range(len(ct_source)) if i not in null_set)
    if len(ct_inner) != N_PT:
        return 0.0
    n_before_ene = sum(1 for p in null_set if p < ENE_START)
    n_before_bcl = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n_before_ene
    bcl_s = BCL_START - n_before_bcl

    kw_idx = [KA_IDX[c] for c in keyword]
    klen = len(kw_idx)
    pt = []
    for i, c in enumerate(ct_inner):
        ci = KA_IDX[c]
        ki = kw_idx[i % klen]
        if variant_id == 0:
            pi = (ki - ci) % KA_MOD
        elif variant_id == 1:
            pi = (ci - ki) % KA_MOD
        else:
            pi = (ci + ki) % KA_MOD
        pt.append(KA_STR[pi])
    pt_str = ''.join(pt)
    return float(_count_crib_hits(pt_str, ene_s, bcl_s))


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_palette_positions(palette_set, ct_source=CT):
    """Get sorted list of non-crib positions where CT has palette letters."""
    return sorted(i for i in NON_CRIB if ct_source[i] in palette_set)


def shuffle_ct(rng, ct_str=CT):
    """Shuffle CT letter positions (preserve frequencies, crib letters fixed)."""
    chars = list(ct_str)
    # Only shuffle non-crib positions
    nc_chars = [chars[i] for i in NON_CRIB]
    rng.shuffle(nc_chars)
    for idx, pos in enumerate(NON_CRIB):
        chars[pos] = nc_chars[idx]
    return ''.join(chars)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 78)
    print("PALETTE CONTROLS: 4-Part Specificity Test")
    print("=" * 78)
    print(f"Workers: {N_WORKERS}  SA: {SA_RESTARTS} restarts × {SA_STEPS:,} steps")
    print(f"Reference palette: {sorted(REFERENCE_PALETTE)}")
    print()

    t_total_start = time.time()
    rng = random.Random(20260401)

    # BGIKOWZ baseline
    bgikowz_pos = get_palette_positions(REFERENCE_PALETTE)
    print(f"BGIKOWZ qualifying positions: {len(bgikowz_pos)}")

    # ══════════════════════════════════════════════════════════════════════════
    # CONTROL 1: RANDOM PALETTES
    # ══════════════════════════════════════════════════════════════════════════

    print(f"\n{'='*78}")
    print("CONTROL 1: RANDOM PALETTES")
    print(f"{'='*78}")

    # Generate random palettes with >= 24 qualifying positions
    random_palettes = []
    attempts = 0
    while len(random_palettes) < TARGET_RANDOM and attempts < 5000:
        pal = frozenset(rng.sample(list(ALPH), 7))
        positions = get_palette_positions(pal)
        if len(positions) >= N_NULLS:
            random_palettes.append({
                'palette': pal,
                'positions': positions,
                'n_positions': len(positions),
                'letters': ''.join(sorted(pal)),
            })
        attempts += 1

    print(f"Generated {len(random_palettes)} viable random palettes "
          f"(from {attempts} attempts)")
    print(f"Position counts: {min(r['n_positions'] for r in random_palettes)}-"
          f"{max(r['n_positions'] for r in random_palettes)} "
          f"(BGIKOWZ={len(bgikowz_pos)})")

    # Run SA for each random palette
    random_results = []
    with Pool(N_WORKERS) as pool:
        # First, run BGIKOWZ baseline with same SA parameters
        print(f"\n  Running BGIKOWZ baseline...")
        t0 = time.time()
        bgikowz_result = build_consensus_masks(bgikowz_pos, CT, pool)
        print(f"    Jaccard-17={bgikowz_result['mean_jaccard_17']:.3f}, "
              f"Jaccard-24={bgikowz_result['mean_jaccard_24']:.3f} "
              f"({time.time()-t0:.1f}s)")

        for i, rpal in enumerate(random_palettes):
            t0 = time.time()
            result = build_consensus_masks(rpal['positions'], CT, pool)
            rpal['jaccard_17'] = result['mean_jaccard_17']
            rpal['jaccard_24'] = result['mean_jaccard_24']
            rpal['score_maxes'] = result['score_maxes']
            random_results.append(rpal)
            if (i + 1) % 10 == 0 or i + 1 == len(random_palettes):
                print(f"\r  Random palettes: {i+1}/{len(random_palettes)} "
                      f"({time.time()-t_total_start:.0f}s)", end='', flush=True)

    print()

    # Analysis
    j17_vals = [r['jaccard_17'] for r in random_results]
    j24_vals = [r['jaccard_24'] for r in random_results]
    bgikowz_j17 = bgikowz_result['mean_jaccard_17']
    bgikowz_j24 = bgikowz_result['mean_jaccard_24']

    rank_17 = sum(1 for v in j17_vals if v >= bgikowz_j17)
    rank_24 = sum(1 for v in j24_vals if v >= bgikowz_j24)
    percentile_17 = 100 * (1 - rank_17 / len(j17_vals))
    percentile_24 = 100 * (1 - rank_24 / len(j24_vals))

    print(f"\n  BGIKOWZ Jaccard-17: {bgikowz_j17:.3f} "
          f"(rank {rank_17+1}/{len(j17_vals)+1}, percentile {percentile_17:.1f}%)")
    print(f"  BGIKOWZ Jaccard-24: {bgikowz_j24:.3f} "
          f"(rank {rank_24+1}/{len(j24_vals)+1}, percentile {percentile_24:.1f}%)")
    print(f"  Random Jaccard-17: mean={sum(j17_vals)/len(j17_vals):.3f}, "
          f"max={max(j17_vals):.3f}, min={min(j17_vals):.3f}")
    print(f"  Random Jaccard-24: mean={sum(j24_vals)/len(j24_vals):.3f}, "
          f"max={max(j24_vals):.3f}, min={min(j24_vals):.3f}")

    # Conditioned on similar n_positions (28-34, bracketing BGIKOWZ=31)
    comparable = [r for r in random_results if 28 <= r['n_positions'] <= 34]
    if comparable:
        cj17 = [r['jaccard_17'] for r in comparable]
        cj24 = [r['jaccard_24'] for r in comparable]
        crank_17 = sum(1 for v in cj17 if v >= bgikowz_j17)
        crank_24 = sum(1 for v in cj24 if v >= bgikowz_j24)
        print(f"\n  Conditioned on n_positions 28-34 ({len(comparable)} palettes):")
        print(f"    BGIKOWZ rank: {crank_17+1}/{len(comparable)+1} (J17), "
              f"{crank_24+1}/{len(comparable)+1} (J24)")
        print(f"    Mean J17={sum(cj17)/len(cj17):.3f}, Mean J24={sum(cj24)/len(cj24):.3f}")

    # Top 5 random palettes by Jaccard-24
    top5 = sorted(random_results, key=lambda r: -r['jaccard_24'])[:5]
    print(f"\n  Top 5 random palettes by Jaccard-24:")
    for r in top5:
        print(f"    {r['letters']} n={r['n_positions']} J17={r['jaccard_17']:.3f} J24={r['jaccard_24']:.3f}")

    # ══════════════════════════════════════════════════════════════════════════
    # CONTROL 2: NEAR-NEIGHBOR PALETTES
    # ══════════════════════════════════════════════════════════════════════════

    print(f"\n{'='*78}")
    print("CONTROL 2: NEAR-NEIGHBOR PALETTES (1-swap from BGIKOWZ)")
    print(f"{'='*78}")

    neighbors = []
    ref_letters = sorted(REFERENCE_PALETTE)
    other_letters = sorted(set(ALPH) - REFERENCE_PALETTE)

    for remove in ref_letters:
        for add in other_letters:
            pal = (REFERENCE_PALETTE - {remove}) | {add}
            positions = get_palette_positions(pal)
            if len(positions) >= N_NULLS:
                neighbors.append({
                    'palette': pal,
                    'positions': positions,
                    'n_positions': len(positions),
                    'letters': ''.join(sorted(pal)),
                    'removed': remove,
                    'added': add,
                })

    print(f"Viable 1-swap neighbors: {len(neighbors)}/{len(ref_letters)*len(other_letters)}")

    neighbor_results = []
    with Pool(N_WORKERS) as pool:
        for i, nbr in enumerate(neighbors):
            result = build_consensus_masks(nbr['positions'], CT, pool)
            nbr['jaccard_17'] = result['mean_jaccard_17']
            nbr['jaccard_24'] = result['mean_jaccard_24']
            nbr['score_maxes'] = result['score_maxes']
            neighbor_results.append(nbr)
            if (i + 1) % 20 == 0 or i + 1 == len(neighbors):
                print(f"\r  Neighbors: {i+1}/{len(neighbors)} "
                      f"({time.time()-t_total_start:.0f}s)", end='', flush=True)

    print()

    nj17 = [r['jaccard_17'] for r in neighbor_results]
    nj24 = [r['jaccard_24'] for r in neighbor_results]
    better_17 = sum(1 for v in nj17 if v > bgikowz_j17)
    better_24 = sum(1 for v in nj24 if v > bgikowz_j24)

    print(f"\n  BGIKOWZ J17={bgikowz_j17:.3f}, J24={bgikowz_j24:.3f}")
    print(f"  Neighbors better (J17): {better_17}/{len(nj17)}")
    print(f"  Neighbors better (J24): {better_24}/{len(nj24)}")
    print(f"  Neighbor J17: mean={sum(nj17)/len(nj17):.3f}, max={max(nj17):.3f}")
    print(f"  Neighbor J24: mean={sum(nj24)/len(nj24):.3f}, max={max(nj24):.3f}")

    # Effect of removing each letter
    print(f"\n  Effect of removing each BGIKOWZ letter (mean J24 of neighbors):")
    for letter in ref_letters:
        subset = [r for r in neighbor_results if r['removed'] == letter]
        if subset:
            mean_j24 = sum(r['jaccard_24'] for r in subset) / len(subset)
            delta = mean_j24 - bgikowz_j24
            print(f"    Remove {letter}: mean J24={mean_j24:.3f} (delta={delta:+.3f}, n={len(subset)})")

    # ══════════════════════════════════════════════════════════════════════════
    # CONTROL 3: SHUFFLED K4
    # ══════════════════════════════════════════════════════════════════════════

    print(f"\n{'='*78}")
    print("CONTROL 3: SHUFFLED K4 UNDER BGIKOWZ CONSTRAINT")
    print(f"{'='*78}")

    shuffle_results = []

    with Pool(N_WORKERS) as pool:
        for i in range(N_SHUFFLES):
            shuffled_ct = shuffle_ct(random.Random(i * 7 + 42))
            # Recompute palette positions for shuffled CT
            shuf_positions = sorted(
                p for p in NON_CRIB if shuffled_ct[p] in REFERENCE_PALETTE
            )
            if len(shuf_positions) < N_NULLS:
                shuffle_results.append({
                    'shuffle_idx': i,
                    'n_positions': len(shuf_positions),
                    'jaccard_17': 0.0,
                    'jaccard_24': 0.0,
                    'skipped': True,
                })
                continue

            result = build_consensus_masks(shuf_positions, shuffled_ct, pool)
            shuffle_results.append({
                'shuffle_idx': i,
                'n_positions': len(shuf_positions),
                'jaccard_17': result['mean_jaccard_17'],
                'jaccard_24': result['mean_jaccard_24'],
                'score_maxes': result['score_maxes'],
                'skipped': False,
            })
            if (i + 1) % 5 == 0 or i + 1 == N_SHUFFLES:
                print(f"\r  Shuffles: {i+1}/{N_SHUFFLES} "
                      f"({time.time()-t_total_start:.0f}s)", end='', flush=True)

    print()

    valid_shuffles = [r for r in shuffle_results if not r.get('skipped')]
    if valid_shuffles:
        sj17 = [r['jaccard_17'] for r in valid_shuffles]
        sj24 = [r['jaccard_24'] for r in valid_shuffles]
        print(f"\n  Valid shuffles: {len(valid_shuffles)}/{N_SHUFFLES}")
        print(f"  K4 real J17={bgikowz_j17:.3f}, J24={bgikowz_j24:.3f}")
        print(f"  Shuffled J17: mean={sum(sj17)/len(sj17):.3f}, "
              f"max={max(sj17):.3f}, min={min(sj17):.3f}")
        print(f"  Shuffled J24: mean={sum(sj24)/len(sj24):.3f}, "
              f"max={max(sj24):.3f}, min={min(sj24):.3f}")
        k4_rank_17 = sum(1 for v in sj17 if v >= bgikowz_j17)
        k4_rank_24 = sum(1 for v in sj24 if v >= bgikowz_j24)
        print(f"  K4 rank among shuffles: {k4_rank_17+1}/{len(sj17)+1} (J17), "
              f"{k4_rank_24+1}/{len(sj24)+1} (J24)")
    else:
        print("  No valid shuffles (all had <24 palette positions)")

    # ══════════════════════════════════════════════════════════════════════════
    # CONTROL 4: OBJECTIVE SENSITIVITY
    # ══════════════════════════════════════════════════════════════════════════

    print(f"\n{'='*78}")
    print("CONTROL 4: OBJECTIVE SENSITIVITY (periodic vs autokey)")
    print(f"{'='*78}")

    # Exhaustive sweep of C(31,24) with periodic scoring
    from math import comb
    total_masks = comb(len(bgikowz_pos), len(bgikowz_pos) - N_NULLS)
    print(f"Exhaustive sweep: {total_masks:,} masks, periodic scoring")

    pal_set = frozenset(bgikowz_pos)

    # Score all masks under periodic
    periodic_joint_best = 0
    periodic_best_mask = None
    autokey_joint_best = 0
    autokey_best_mask = None

    periodic_hist = Counter()
    autokey_hist = Counter()

    CT_KA = tuple(KA_IDX[c] for c in CT)
    ENE_KA = tuple(KA_IDX[c] for c in ENE_WORD)
    BCL_KA = tuple(KA_IDX[c] for c in BCL_WORD)

    t0 = time.time()
    count = 0
    for excl in combinations(bgikowz_pos, len(bgikowz_pos) - N_NULLS):
        null_pos = sorted(pal_set - frozenset(excl))
        null_set = frozenset(null_pos)

        # Autokey scoring (from previous sweep)
        a_total = 0
        for vid in range(3):
            a_total += score_mask_variant(null_set, vid)

        # Periodic scoring
        p_total = 0
        for vid in range(3):
            p_total += score_mask_periodic(null_set, vid)

        autokey_hist[int(a_total)] += 1
        periodic_hist[int(p_total)] += 1

        if a_total > autokey_joint_best:
            autokey_joint_best = a_total
            autokey_best_mask = null_pos
        if p_total > periodic_joint_best:
            periodic_joint_best = p_total
            periodic_best_mask = null_pos

        count += 1
        if count % 500_000 == 0:
            print(f"\r  Exhaustive: {count:,}/{total_masks:,} ({time.time()-t0:.0f}s)",
                  end='', flush=True)

    print(f"\r  Exhaustive: {count:,}/{total_masks:,} ({time.time()-t0:.1f}s)")

    print(f"\n  Autokey joint optimum: {autokey_joint_best:.0f}/72")
    print(f"    Mask: {autokey_best_mask}")
    print(f"  Periodic joint optimum: {periodic_joint_best:.0f}/72")
    print(f"    Mask: {periodic_best_mask}")

    # Check if same mask
    if autokey_best_mask and periodic_best_mask:
        overlap = len(set(autokey_best_mask) & set(periodic_best_mask))
        j = overlap / len(set(autokey_best_mask) | set(periodic_best_mask))
        print(f"  Mask overlap: {overlap}/{N_NULLS}, Jaccard: {j:.3f}")

    # ══════════════════════════════════════════════════════════════════════════
    # VERDICTS
    # ══════════════════════════════════════════════════════════════════════════

    print(f"\n{'='*78}")
    print("VERDICTS")
    print(f"{'='*78}")

    # Control 1
    print(f"\n  CONTROL 1 — Random Palettes:")
    if percentile_17 >= 95:
        print(f"    BGIKOWZ is an OUTLIER (J17 percentile={percentile_17:.1f}%)")
        print(f"    → Palette convergence is SPECIFIC to BGIKOWZ")
    elif percentile_17 >= 75:
        print(f"    BGIKOWZ is ABOVE AVERAGE but not extreme (J17 percentile={percentile_17:.1f}%)")
        print(f"    → Palette is somewhat special but not uniquely so")
    else:
        print(f"    BGIKOWZ is TYPICAL (J17 percentile={percentile_17:.1f}%)")
        print(f"    → Convergence is a GENERIC property of palette-constrained SA")

    # Control 2
    print(f"\n  CONTROL 2 — Near Neighbors:")
    if better_24 == 0:
        print(f"    NO neighbor has higher J24 than BGIKOWZ")
        print(f"    → BGIKOWZ is a LOCAL OPTIMUM for convergence")
    elif better_24 <= 5:
        print(f"    Only {better_24}/{len(nj24)} neighbors beat BGIKOWZ")
        print(f"    → BGIKOWZ is NEAR a local optimum")
    else:
        print(f"    {better_24}/{len(nj24)} neighbors beat BGIKOWZ")
        print(f"    → BGIKOWZ is NOT special among its neighbors")

    # Control 3
    print(f"\n  CONTROL 3 — Shuffled K4:")
    if valid_shuffles:
        shuffle_mean_24 = sum(sj24) / len(sj24)
        if bgikowz_j24 > shuffle_mean_24 + 0.15:
            print(f"    K4 convergence ({bgikowz_j24:.3f}) >> shuffled mean ({shuffle_mean_24:.3f})")
            print(f"    → Convergence reflects K4 STRUCTURE, not just methodology")
        elif bgikowz_j24 > shuffle_mean_24 + 0.05:
            print(f"    K4 convergence ({bgikowz_j24:.3f}) > shuffled mean ({shuffle_mean_24:.3f})")
            print(f"    → SUGGESTIVE of K4 structure but not definitive")
        else:
            print(f"    K4 convergence ({bgikowz_j24:.3f}) ≈ shuffled mean ({shuffle_mean_24:.3f})")
            print(f"    → Convergence is METHODOLOGICAL, not K4-specific")

    # Control 4
    print(f"\n  CONTROL 4 — Objective Sensitivity:")
    if autokey_best_mask and periodic_best_mask:
        if j >= 0.8:
            print(f"    Autokey and periodic produce SAME optimal mask (Jaccard={j:.3f})")
            print(f"    → Optimum is ROBUST across objectives")
        elif j >= 0.4:
            print(f"    Partial overlap (Jaccard={j:.3f})")
            print(f"    → Optimum is PARTIALLY objective-dependent")
        else:
            print(f"    Low overlap (Jaccard={j:.3f})")
            print(f"    → Optimum is OBJECTIVE-SPECIFIC")

    print(f"\nTotal time: {time.time()-t_total_start:.0f}s")

    # ── Save results ─────────────────────────────────────────────────────────

    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'config': {
            'sa_restarts': SA_RESTARTS,
            'sa_steps': SA_STEPS,
            'n_workers': N_WORKERS,
            'n_random_palettes': len(random_palettes),
            'n_neighbors': len(neighbors),
            'n_shuffles': N_SHUFFLES,
        },
        'bgikowz_baseline': {
            'n_positions': len(bgikowz_pos),
            'jaccard_17': round(bgikowz_j17, 4),
            'jaccard_24': round(bgikowz_j24, 4),
        },
        'control_1_random': {
            'n_tested': len(random_results),
            'bgikowz_percentile_17': round(percentile_17, 1),
            'bgikowz_percentile_24': round(percentile_24, 1),
            'random_mean_j17': round(sum(j17_vals)/len(j17_vals), 4),
            'random_mean_j24': round(sum(j24_vals)/len(j24_vals), 4),
            'random_max_j17': round(max(j17_vals), 4),
            'random_max_j24': round(max(j24_vals), 4),
            'top5': [{'letters': r['letters'], 'n_pos': r['n_positions'],
                       'j17': round(r['jaccard_17'], 4), 'j24': round(r['jaccard_24'], 4)}
                      for r in top5],
        },
        'control_2_neighbors': {
            'n_tested': len(neighbor_results),
            'better_j17': better_17,
            'better_j24': better_24,
            'mean_j17': round(sum(nj17)/len(nj17), 4),
            'mean_j24': round(sum(nj24)/len(nj24), 4),
            'max_j17': round(max(nj17), 4),
            'max_j24': round(max(nj24), 4),
        },
        'control_3_shuffled': {
            'n_valid': len(valid_shuffles),
            'mean_j17': round(sum(sj17)/len(sj17), 4) if valid_shuffles else None,
            'mean_j24': round(sum(sj24)/len(sj24), 4) if valid_shuffles else None,
            'k4_rank_j17': k4_rank_17 + 1 if valid_shuffles else None,
            'k4_rank_j24': k4_rank_24 + 1 if valid_shuffles else None,
        },
        'control_4_sensitivity': {
            'autokey_optimum': autokey_joint_best,
            'periodic_optimum': periodic_joint_best,
            'mask_jaccard': round(j, 3) if autokey_best_mask and periodic_best_mask else None,
            'autokey_mask': autokey_best_mask,
            'periodic_mask': periodic_best_mask,
        },
    }

    outpath = os.path.join(_ROOT, 'results', 'palette_controls_01.json')
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outpath}")


if __name__ == '__main__':
    main()
