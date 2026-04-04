#!/usr/bin/env python3
"""
Cipher:   Stego mechanism (exhaustive palette mask sweep)
Family:   stego_mechanism
Status:   active
Keyspace: C(31,24) = C(31,7) = 2,629,575 masks (EXACT, COMPLETE)
Last run:
Best score:

PURPOSE: Deterministic enumeration of ALL palette-constrained null masks.
Replaces stochastic SA with provably complete search.

PRIOR RESULT: The model-invariance sweep (e_model_invariance_sweep_01.py)
showed that palette constraint {B,G,I,K,O,W,Z} improves cross-model
convergence from Jaccard 0.160 to 0.429 (top-17) / 0.676 (top-24).
SA found joint scores up to 12/72 (palette) vs 20/72 (free).

THIS TEST: Score every single palette-constrained mask under all 3 autokey
variants (Beaufort, Vigenere, Variant Beaufort on KA with keyword KRYPTOS).
Find the TRUE joint optimum — no stochastic uncertainty.

KEY INSIGHT: C(31,24) = C(31,7) — we enumerate which 7 of 31 palette
positions to EXCLUDE from the null set; the remaining 24 are the nulls.

DELIVERABLES:
  - Provably optimal joint mask (max sum of all 3 variant scores)
  - Provably optimal per-variant masks (max score under each variant)
  - Complete score distribution (percentiles, shape)
  - Position frequency analysis (which positions appear in top masks)
  - Cross-variant agreement at each rank level
"""

import sys
import os
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

KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
KA_MOD = 26

# Precompute keyword indices
KW_IDX = tuple(KA_IDX[c] for c in "KRYPTOS")
KW_LEN = len(KW_IDX)

# All non-crib positions where CT letter is in the palette
PALETTE_POSITIONS = sorted(
    i for i in range(N) if i not in CRIB_POSITIONS and CT[i] in NULL_PALETTE
)
N_PAL = len(PALETTE_POSITIONS)  # 31

# Precompute CT as KA indices for speed
CT_KA = tuple(KA_IDX[c] for c in CT)

# Precompute crib targets in KA
ENE_KA = tuple(KA_IDX[c] for c in ENE_WORD)
BCL_KA = tuple(KA_IDX[c] for c in BCL_WORD)

N_WORKERS = max(1, cpu_count() - 2)

# Total masks
from math import comb
TOTAL_MASKS = comb(N_PAL, N_PAL - N_NULLS)  # C(31,7) = 2,629,575

# Reference
REFERENCE_CONSENSUS = frozenset(CONSENSUS_NULL_POSITIONS)
REFERENCE_PALETTE = frozenset(NULL_PALETTE)


# ── Optimized scoring ────────────────────────────────────────────────────────

def score_mask_all_variants(null_positions):
    """Score one mask under all 3 variants. Returns (beau, vig, vbeau, joint).

    Optimized: single CT extraction shared across variants,
    integer arithmetic throughout, no string operations.
    """
    null_set = frozenset(null_positions)

    # Extract CT_inner as KA indices (avoiding string ops)
    ct_inner = []
    for i in range(N):
        if i not in null_set:
            ct_inner.append(CT_KA[i])
    # Should be exactly N_PT = 73
    n_inner = len(ct_inner)

    # Compute shifted crib positions
    n_before_ene = sum(1 for p in null_positions if p < ENE_START)
    n_before_bcl = sum(1 for p in null_positions if p < BCL_START)
    ene_s = ENE_START - n_before_ene
    bcl_s = BCL_START - n_before_bcl

    scores = []
    for variant_id in range(3):
        # Autokey decrypt
        pt_indices = []
        for i in range(n_inner):
            ci = ct_inner[i]
            ki = KW_IDX[i] if i < KW_LEN else pt_indices[i - KW_LEN]
            if variant_id == 0:    # Beaufort: P = (K - C) mod 26
                pi = (ki - ci) % KA_MOD
            elif variant_id == 1:  # Vigenere: P = (C - K) mod 26
                pi = (ci - ki) % KA_MOD
            else:                  # Var Beau: P = (C + K) mod 26
                pi = (ci + ki) % KA_MOD
            pt_indices.append(pi)

        # Count crib hits
        hits = 0
        for j in range(13):  # ENE has 13 chars
            pos = ene_s + j
            if pos < n_inner and pt_indices[pos] == ENE_KA[j]:
                hits += 1
        for j in range(11):  # BCL has 11 chars
            pos = bcl_s + j
            if pos < n_inner and pt_indices[pos] == BCL_KA[j]:
                hits += 1
        scores.append(hits)

    return (scores[0], scores[1], scores[2], scores[0] + scores[1] + scores[2])


# ── Chunk worker ─────────────────────────────────────────────────────────────

def _process_chunk(args):
    """Process a chunk of exclusion sets. Returns top results and statistics."""
    chunk_idx, exclusions_list = args

    # Track top results per variant and joint
    TOP_K = 50
    top_beau = []   # (score, mask)
    top_vig = []
    top_vbeau = []
    top_joint = []

    # Score distribution bins
    joint_hist = Counter()  # joint_score -> count
    beau_hist = Counter()
    vig_hist = Counter()
    vbeau_hist = Counter()

    # Position frequency in top masks
    pos_freq_joint = Counter()
    pos_freq_beau = Counter()
    pos_freq_vig = Counter()
    pos_freq_vbeau = Counter()

    pal_set = frozenset(PALETTE_POSITIONS)

    for excl in exclusions_list:
        excl_set = frozenset(excl)
        null_pos = sorted(pal_set - excl_set)
        b, v, vb, j = score_mask_all_variants(null_pos)

        joint_hist[j] += 1
        beau_hist[b] += 1
        vig_hist[v] += 1
        vbeau_hist[vb] += 1

        # Maintain top-K lists
        mask_tuple = tuple(null_pos)
        for top_list, score, freq in [
            (top_beau, b, pos_freq_beau),
            (top_vig, v, pos_freq_vig),
            (top_vbeau, vb, pos_freq_vbeau),
            (top_joint, j, pos_freq_joint),
        ]:
            if len(top_list) < TOP_K or score > top_list[-1][0]:
                top_list.append((score, b, v, vb, j, mask_tuple))
                top_list.sort(key=lambda x: -x[0])
                if len(top_list) > TOP_K:
                    top_list.pop()
                # Track position freq for current top-K
                if score >= top_list[-1][0]:
                    for p in null_pos:
                        freq[p] += 1

    return {
        'chunk_idx': chunk_idx,
        'n_evaluated': len(exclusions_list),
        'top_beau': top_beau,
        'top_vig': top_vig,
        'top_vbeau': top_vbeau,
        'top_joint': top_joint,
        'joint_hist': dict(joint_hist),
        'beau_hist': dict(beau_hist),
        'vig_hist': dict(vig_hist),
        'vbeau_hist': dict(vbeau_hist),
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 78)
    print("EXHAUSTIVE PALETTE-CONSTRAINED MASK SWEEP")
    print("=" * 78)
    print(f"Palette positions: {N_PAL} → {PALETTE_POSITIONS}")
    print(f"Null positions needed: {N_NULLS}")
    print(f"Exclusion size: {N_PAL - N_NULLS} (choosing which 7 to exclude)")
    print(f"Total masks: C({N_PAL},{N_PAL - N_NULLS}) = {TOTAL_MASKS:,}")
    print(f"Workers: {N_WORKERS}")
    print(f"Variants: Beaufort, Vigenere, Variant Beaufort (KA autokey, kw=KRYPTOS)")
    print()

    # Generate all exclusion sets and chunk them
    t0 = time.time()
    CHUNK_SIZE = 50_000
    all_exclusions = list(combinations(PALETTE_POSITIONS, N_PAL - N_NULLS))
    assert len(all_exclusions) == TOTAL_MASKS, f"Expected {TOTAL_MASKS}, got {len(all_exclusions)}"

    chunks = []
    for i in range(0, len(all_exclusions), CHUNK_SIZE):
        chunks.append((i // CHUNK_SIZE, all_exclusions[i:i + CHUNK_SIZE]))

    print(f"Generated {len(all_exclusions):,} exclusion sets in {len(chunks)} chunks "
          f"({time.time() - t0:.1f}s)")
    print()

    # Process all chunks in parallel
    t_start = time.time()
    with Pool(N_WORKERS) as pool:
        results = []
        for i, result in enumerate(pool.imap_unordered(_process_chunk, chunks)):
            results.append(result)
            elapsed = time.time() - t_start
            done = sum(r['n_evaluated'] for r in results)
            rate = done / elapsed if elapsed > 0 else 0
            eta = (TOTAL_MASKS - done) / rate if rate > 0 else 0
            print(f"\r  Progress: {done:>10,}/{TOTAL_MASKS:,} "
                  f"({100*done/TOTAL_MASKS:.1f}%) "
                  f"Rate: {rate:,.0f}/s  ETA: {eta:.0f}s", end='', flush=True)

    t_total = time.time() - t_start
    print(f"\n\nComplete: {TOTAL_MASKS:,} masks evaluated in {t_total:.1f}s "
          f"({TOTAL_MASKS/t_total:,.0f} masks/s)")

    # ── Merge results across chunks ──────────────────────────────────────────

    TOP_K = 50

    def merge_top(lists, key_idx=0):
        merged = []
        for lst in lists:
            merged.extend(lst)
        merged.sort(key=lambda x: -x[key_idx])
        return merged[:TOP_K]

    top_beau = merge_top([r['top_beau'] for r in results])
    top_vig = merge_top([r['top_vig'] for r in results])
    top_vbeau = merge_top([r['top_vbeau'] for r in results])
    top_joint = merge_top([r['top_joint'] for r in results])

    # Merge histograms
    joint_hist = Counter()
    beau_hist = Counter()
    vig_hist = Counter()
    vbeau_hist = Counter()
    for r in results:
        for k, v in r['joint_hist'].items():
            joint_hist[k] += v
        for k, v in r['beau_hist'].items():
            beau_hist[k] += v
        for k, v in r['vig_hist'].items():
            vig_hist[k] += v
        for k, v in r['vbeau_hist'].items():
            vbeau_hist[k] += v

    # ── Analysis ─────────────────────────────────────────────────────────────

    print("\n" + "=" * 78)
    print("RESULTS")
    print("=" * 78)

    # Score distributions
    print("\n── SCORE DISTRIBUTIONS ────────────────────────────────────────────")
    for name, hist in [("Beaufort", beau_hist), ("Vigenere", vig_hist),
                       ("Var Beaufort", vbeau_hist), ("Joint (sum)", joint_hist)]:
        total = sum(hist.values())
        max_sc = max(hist.keys())
        min_sc = min(hist.keys())
        mean_sc = sum(k * v for k, v in hist.items()) / total
        print(f"\n  {name}:")
        print(f"    Range: {min_sc} – {max_sc}   Mean: {mean_sc:.2f}")
        # Show distribution for top scores
        for sc in sorted(hist.keys(), reverse=True)[:12]:
            bar = "#" * min(50, hist[sc] * 50 // max(hist.values()))
            pct = 100 * hist[sc] / total
            print(f"    {sc:>3d}: {hist[sc]:>8,} ({pct:>6.2f}%) {bar}")

    # Top masks per variant
    print("\n── TOP MASKS BY VARIANT ───────────────────────────────────────────")
    for name, top_list in [("BEAUFORT", top_beau), ("VIGENERE", top_vig),
                            ("VAR BEAUFORT", top_vbeau), ("JOINT", top_joint)]:
        print(f"\n  {name} (top 10):")
        print(f"  {'#':>3s} {'Opt':>4s} {'B':>4s} {'V':>4s} {'VB':>4s} {'Jnt':>4s}  Mask")
        for i, (sc, b, v, vb, j, mask) in enumerate(top_list[:10]):
            marker = " ★" if i == 0 else ""
            print(f"  {i+1:>3d} {sc:>4d} {b:>4d} {v:>4d} {vb:>4d} {j:>4d}  "
                  f"{list(mask)}{marker}")

    # Best joint mask detailed analysis
    print("\n── BEST JOINT MASK ANALYSIS ───────────────────────────────────────")
    best = top_joint[0]
    best_mask = set(best[5])
    ref = REFERENCE_CONSENSUS

    print(f"  Mask: {sorted(best_mask)}")
    print(f"  Scores: B={best[1]}, V={best[2]}, VB={best[3]}, Joint={best[4]}")
    print(f"  Letters: {''.join(sorted(CT[p] for p in best_mask))}")
    print(f"  Distinct letters: {len(set(CT[p] for p in best_mask))}")

    overlap_ref = best_mask & ref
    print(f"  Overlap with consensus-17: {len(overlap_ref)}/17 → {sorted(overlap_ref)}")
    only_here = best_mask - ref
    only_ref = ref - best_mask
    print(f"  In best but not consensus: {sorted(only_here)}")
    print(f"  In consensus but not best: {sorted(only_ref)}")

    # Jaccard with consensus
    j_ref = len(best_mask & ref) / len(best_mask | ref) if best_mask | ref else 0
    print(f"  Jaccard with consensus-17: {j_ref:.3f}")

    # Cross-variant agreement at top ranks
    print("\n── CROSS-VARIANT AGREEMENT ────────────────────────────────────────")
    for rank_cutoff in [1, 5, 10, 25, 50]:
        beau_masks = [set(t[5]) for t in top_beau[:rank_cutoff]]
        vig_masks = [set(t[5]) for t in top_vig[:rank_cutoff]]
        vbeau_masks = [set(t[5]) for t in top_vbeau[:rank_cutoff]]

        # Check if any mask appears in top-N of ALL variants
        beau_frozen = set(frozenset(m) for m in beau_masks)
        vig_frozen = set(frozenset(m) for m in vig_masks)
        vbeau_frozen = set(frozenset(m) for m in vbeau_masks)
        all_three = beau_frozen & vig_frozen & vbeau_frozen
        any_two = ((beau_frozen & vig_frozen) |
                    (beau_frozen & vbeau_frozen) |
                    (vig_frozen & vbeau_frozen))

        print(f"  Top-{rank_cutoff:>2d}: in all 3 variants: {len(all_three):>3d}, "
              f"in any 2: {len(any_two):>3d}")

    # Position frequency in top-50 joint masks
    print("\n── POSITION FREQUENCY IN TOP-50 JOINT MASKS ──────────────────────")
    pos_freq = Counter()
    for _, _, _, _, _, mask in top_joint:
        for p in mask:
            pos_freq[p] += 1

    print(f"  {'Pos':>4s} {'CT':>3s} {'Freq':>5s} {'In ref':>6s}")
    for pos, freq in pos_freq.most_common():
        in_ref = "✓" if pos in ref else " "
        print(f"  {pos:>4d}   {CT[pos]}  {freq:>5d}    {in_ref}")

    # Min score per variant for best joint mask
    print("\n── BALANCE ANALYSIS ───────────────────────────────────────────────")
    print("  Top 10 joint masks by min(B,V,VB) [most balanced]:")
    balanced = sorted(top_joint, key=lambda x: (min(x[1], x[2], x[3]), x[4]), reverse=True)
    print(f"  {'#':>3s} {'min':>4s} {'B':>4s} {'V':>4s} {'VB':>4s} {'Jnt':>4s}")
    for i, (sc, b, v, vb, j, mask) in enumerate(balanced[:10]):
        print(f"  {i+1:>3d} {min(b,v,vb):>4d} {b:>4d} {v:>4d} {vb:>4d} {j:>4d}")

    # ── Save results ─────────────────────────────────────────────────────────

    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'config': {
            'n_palette_positions': N_PAL,
            'palette_positions': PALETTE_POSITIONS,
            'n_nulls': N_NULLS,
            'total_masks': TOTAL_MASKS,
            'n_workers': N_WORKERS,
            'elapsed_seconds': round(t_total, 1),
            'masks_per_second': round(TOTAL_MASKS / t_total),
        },
        'distributions': {
            'joint': {str(k): v for k, v in sorted(joint_hist.items())},
            'beaufort': {str(k): v for k, v in sorted(beau_hist.items())},
            'vigenere': {str(k): v for k, v in sorted(vig_hist.items())},
            'var_beaufort': {str(k): v for k, v in sorted(vbeau_hist.items())},
        },
        'optima': {
            'joint': {
                'score': top_joint[0][4],
                'beau': top_joint[0][1],
                'vig': top_joint[0][2],
                'vbeau': top_joint[0][3],
                'mask': list(top_joint[0][5]),
                'letters': ''.join(sorted(CT[p] for p in top_joint[0][5])),
                'consensus_overlap': len(set(top_joint[0][5]) & ref),
                'jaccard_consensus': round(j_ref, 3),
            },
            'beaufort': {
                'score': top_beau[0][1],
                'joint': top_beau[0][4],
                'mask': list(top_beau[0][5]),
            },
            'vigenere': {
                'score': top_vig[0][2],
                'joint': top_vig[0][4],
                'mask': list(top_vig[0][5]),
            },
            'var_beaufort': {
                'score': top_vbeau[0][3],
                'joint': top_vbeau[0][4],
                'mask': list(top_vbeau[0][5]),
            },
        },
        'top_50_joint': [
            {
                'rank': i + 1,
                'beau': t[1], 'vig': t[2], 'vbeau': t[3], 'joint': t[4],
                'mask': list(t[5]),
            }
            for i, t in enumerate(top_joint)
        ],
        'top_10_beaufort': [
            {'rank': i+1, 'beau': t[1], 'vig': t[2], 'vbeau': t[3],
             'joint': t[4], 'mask': list(t[5])}
            for i, t in enumerate(top_beau[:10])
        ],
        'top_10_vigenere': [
            {'rank': i+1, 'beau': t[1], 'vig': t[2], 'vbeau': t[3],
             'joint': t[4], 'mask': list(t[5])}
            for i, t in enumerate(top_vig[:10])
        ],
        'top_10_var_beaufort': [
            {'rank': i+1, 'beau': t[1], 'vig': t[2], 'vbeau': t[3],
             'joint': t[4], 'mask': list(t[5])}
            for i, t in enumerate(top_vbeau[:10])
        ],
        'position_frequency_top50_joint': {
            str(pos): freq for pos, freq in pos_freq.most_common()
        },
    }

    outpath = os.path.join(_ROOT, 'results', 'exhaustive_palette_mask_01.json')
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outpath}")


if __name__ == '__main__':
    main()
