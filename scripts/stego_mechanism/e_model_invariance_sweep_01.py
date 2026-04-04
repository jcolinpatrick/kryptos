#!/usr/bin/env python3
"""
Cipher:   Stego mechanism (model-invariance sweep)
Family:   stego_mechanism
Status:   active
Keyspace: 8 campaigns × 200 SA restarts × 300K steps = 480M SA evaluations
Last run:
Best score:

PURPOSE: Determine whether ANY null mask scores well under ALL three additive
cipher variants simultaneously (Beaufort, Vigenere, Variant Beaufort).

PRIOR RESULT: Per-model SA optimization produces masks with Jaccard ~0.161
overlap (model-conditional). But that only proves per-model optima diverge.
This test asks the JOINT question: does a mask exist that works under all
three variants?

DESIGN:
  8 SA campaigns, each with 200 restarts × 300K steps:

  A. Individual variant optimization (3 campaigns, unconstrained):
     A1: KA autokey Beaufort
     A2: KA autokey Vigenere
     A3: KA autokey Variant Beaufort

  B. Individual variant optimization (3 campaigns, palette-constrained):
     B1-B3: Same as A1-A3, but null positions must contain only palette letters

  C. Joint optimization (unconstrained):
     Objective = score_beau + score_vig + score_vbeau

  D. Joint optimization (palette-constrained):
     Same as C but with palette hard constraint

  All use KA alphabet with keyword KRYPTOS, autokey decryption.

ANALYSIS:
  - Pairwise Jaccard similarity of top masks across variants
  - Joint score distribution: can any mask score >50% of max under ALL variants?
  - Palette-constrained vs unconstrained convergence comparison
  - Best joint masks: do they share positions?

VERDICT CRITERIA:
  - If joint-optimal masks score ≥60% of individual-variant optima → stego layer
    is approximately model-invariant (decouplable)
  - If joint maximum is <40% of individual optima → layers are fundamentally entangled
  - If palette constraint improves convergence → palette is a real decoupling feature
"""

import sys
import os
import random
import math
import time
import json
from collections import Counter
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
ENE_START = 21  # 0-indexed position in CT97
BCL_START = 63
NON_CRIB = sorted(i for i in range(N) if i not in CRIB_POSITIONS)
NC_SET = frozenset(NON_CRIB)

KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
KA_MOD = len(KA_STR)  # 26

N_WORKERS = max(1, cpu_count() - 2)
N_RESTARTS = int(os.environ.get('MIS_RESTARTS', '100'))
N_STEPS = int(os.environ.get('MIS_STEPS', '100000'))
SCORE_THRESHOLD = 10  # Minimum crib hits to count as "qualifying"

PALETTE_SET = frozenset(NULL_PALETTE)  # {B, G, I, K, O, W, Z}

# Positions where palette letters appear in CT (sorted lists for fast sampling)
PALETTE_POSITIONS_LIST = sorted(i for i in NON_CRIB if CT[i] in PALETTE_SET)
PALETTE_POSITIONS = frozenset(PALETTE_POSITIONS_LIST)
NON_PALETTE_NONCRIB = sorted(i for i in NON_CRIB if CT[i] not in PALETTE_SET)


# ── Autokey decryption under 3 variants ──────────────────────────────────────

def _autokey_decrypt(ct_str, keyword_idx, variant):
    """Autokey decrypt on KA alphabet.

    variant: 'beau', 'vig', 'vbeau'

    Beaufort:         P = (K - C) mod 26
    Vigenere:         P = (C - K) mod 26
    Variant Beaufort: P = (C + K) mod 26
    """
    klen = len(keyword_idx)
    pt_indices = []
    for i, c in enumerate(ct_str):
        ci = KA_IDX[c]
        ki = keyword_idx[i] if i < klen else pt_indices[i - klen]
        if variant == 'beau':
            pi = (ki - ci) % KA_MOD
        elif variant == 'vig':
            pi = (ci - ki) % KA_MOD
        elif variant == 'vbeau':
            pi = (ci + ki) % KA_MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        pt_indices.append(pi)
    return pt_indices, ''.join(KA_STR[p] for p in pt_indices)


# Precompute keyword indices
KW_IDX = tuple(KA_IDX[c] for c in "KRYPTOS")


def _count_crib_hits(pt_str, ene_shifted, bcl_shifted):
    """Count crib character matches at shifted positions."""
    n = len(pt_str)
    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_shifted + j < n and pt_str[ene_shifted + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_shifted + j < n and pt_str[bcl_shifted + j] == c)
    return e + b


def score_mask_variant(null_set, variant):
    """Score a null mask under one cipher variant. Returns crib hits (0-24)."""
    ct_inner = ''.join(CT[i] for i in range(N) if i not in null_set)
    if len(ct_inner) != N_PT:
        return 0.0

    n_before_ene = sum(1 for p in null_set if p < ENE_START)
    n_before_bcl = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n_before_ene
    bcl_s = BCL_START - n_before_bcl

    _, pt_str = _autokey_decrypt(ct_inner, KW_IDX, variant)
    return float(_count_crib_hits(pt_str, ene_s, bcl_s))


def score_mask_joint(null_set):
    """Joint score = sum of crib hits under all 3 variants."""
    ct_inner = ''.join(CT[i] for i in range(N) if i not in null_set)
    if len(ct_inner) != N_PT:
        return 0.0, (0.0, 0.0, 0.0)

    n_before_ene = sum(1 for p in null_set if p < ENE_START)
    n_before_bcl = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n_before_ene
    bcl_s = BCL_START - n_before_bcl

    scores = []
    for v in ('beau', 'vig', 'vbeau'):
        _, pt_str = _autokey_decrypt(ct_inner, KW_IDX, v)
        scores.append(float(_count_crib_hits(pt_str, ene_s, bcl_s)))

    return sum(scores), tuple(scores)


# ── SA engine ────────────────────────────────────────────────────────────────

def sa_run_single(variant, seed, palette_constrained=False,
                  steps=N_STEPS, T0=0.5, Tf=0.01):
    """One SA restart optimizing a single variant's score.

    Returns dict with best_score, best_mask, variant_scores, etc.
    """
    rng = random.Random(seed)

    if palette_constrained:
        # Start with random palette positions as nulls
        null_set = set(rng.sample(PALETTE_POSITIONS_LIST, N_NULLS))
        # Track palette positions in/out of null set for efficient move generation
        pal_in_null = set(null_set)  # palette positions currently null
        pal_not_null = set(PALETTE_POSITIONS) - pal_in_null  # palette positions currently not null
    else:
        null_set = set(rng.sample(NON_CRIB, N_NULLS))

    non_null = set(NC_SET) - null_set

    score = score_mask_variant(frozenset(null_set), variant)
    best_sc = score
    best_null = frozenset(null_set)

    for step in range(steps):
        T = T0 * (Tf / T0) ** (step / steps)

        if palette_constrained:
            # Only propose swaps within palette positions (guaranteed valid)
            if not pal_in_null or not pal_not_null:
                break
            out_pos = rng.choice(list(pal_in_null))
            in_pos = rng.choice(list(pal_not_null))
        else:
            cands = list(null_set)
            nn_list = list(non_null)
            if not cands or not nn_list:
                break
            out_pos = rng.choice(cands)
            in_pos = rng.choice(nn_list)

        null_set.discard(out_pos)
        null_set.add(in_pos)
        non_null.discard(in_pos)
        non_null.add(out_pos)

        new_sc = score_mask_variant(frozenset(null_set), variant)
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / max(T, 1e-10)):
            score = new_sc
            if palette_constrained:
                pal_in_null.discard(out_pos)
                pal_in_null.add(in_pos)
                pal_not_null.discard(in_pos)
                pal_not_null.add(out_pos)
            if score > best_sc:
                best_sc = score
                best_null = frozenset(null_set)
        else:
            null_set.discard(in_pos)
            null_set.add(out_pos)
            non_null.discard(out_pos)
            non_null.add(in_pos)

    # Compute all 3 variant scores for the best mask
    bm = best_null
    s_beau = score_mask_variant(bm, 'beau')
    s_vig = score_mask_variant(bm, 'vig')
    s_vbeau = score_mask_variant(bm, 'vbeau')
    letters = sorted(set(CT[p] for p in bm))

    return {
        'seed': seed,
        'optimized_variant': variant,
        'palette_constrained': palette_constrained,
        'best_score': best_sc,
        'best_mask': sorted(bm),
        'variant_scores': {'beau': s_beau, 'vig': s_vig, 'vbeau': s_vbeau},
        'joint_score': s_beau + s_vig + s_vbeau,
        'n_distinct_letters': len(letters),
        'letters': ''.join(letters),
    }


def sa_run_joint(seed, palette_constrained=False,
                 steps=N_STEPS, T0=0.5, Tf=0.01):
    """One SA restart optimizing joint (sum of all 3 variants) score.

    Returns dict with best_score, best_mask, per-variant breakdown.
    """
    rng = random.Random(seed)

    if palette_constrained:
        null_set = set(rng.sample(PALETTE_POSITIONS_LIST, N_NULLS))
        pal_in_null = set(null_set)
        pal_not_null = set(PALETTE_POSITIONS) - pal_in_null
    else:
        null_set = set(rng.sample(NON_CRIB, N_NULLS))

    non_null = set(NC_SET) - null_set

    score, _ = score_mask_joint(frozenset(null_set))
    best_sc = score
    best_null = frozenset(null_set)
    best_breakdown = (0.0, 0.0, 0.0)

    for step in range(steps):
        T = T0 * (Tf / T0) ** (step / steps)

        if palette_constrained:
            if not pal_in_null or not pal_not_null:
                break
            out_pos = rng.choice(list(pal_in_null))
            in_pos = rng.choice(list(pal_not_null))
        else:
            cands = list(null_set)
            nn_list = list(non_null)
            if not cands or not nn_list:
                break
            out_pos = rng.choice(cands)
            in_pos = rng.choice(nn_list)

        null_set.discard(out_pos)
        null_set.add(in_pos)
        non_null.discard(in_pos)
        non_null.add(out_pos)

        new_sc, breakdown = score_mask_joint(frozenset(null_set))
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / max(T, 1e-10)):
            score = new_sc
            if palette_constrained:
                pal_in_null.discard(out_pos)
                pal_in_null.add(in_pos)
                pal_not_null.discard(in_pos)
                pal_not_null.add(out_pos)
            if score > best_sc:
                best_sc = score
                best_null = frozenset(null_set)
                best_breakdown = breakdown
        else:
            null_set.discard(in_pos)
            null_set.add(out_pos)
            non_null.discard(out_pos)
            non_null.add(in_pos)

    # Final scoring of best mask
    _, final_breakdown = score_mask_joint(best_null)
    letters = sorted(set(CT[p] for p in best_null))

    return {
        'seed': seed,
        'optimized_variant': 'joint',
        'palette_constrained': palette_constrained,
        'best_score': best_sc,
        'best_mask': sorted(best_null),
        'variant_scores': {
            'beau': final_breakdown[0],
            'vig': final_breakdown[1],
            'vbeau': final_breakdown[2],
        },
        'joint_score': best_sc,
        'n_distinct_letters': len(letters),
        'letters': ''.join(letters),
    }


# ── Worker functions (must be top-level for multiprocessing) ─────────────────

def _worker_single(args):
    variant, seed, pal_constrained = args
    return sa_run_single(variant, seed, palette_constrained=pal_constrained)


def _worker_joint(args):
    seed, pal_constrained = args
    return sa_run_joint(seed, palette_constrained=pal_constrained)


# ── Analysis functions ───────────────────────────────────────────────────────

def build_consensus(results, threshold=SCORE_THRESHOLD):
    """Build consensus top-N positions from SA results."""
    freq = Counter()
    qualifying = 0
    for r in results:
        if r['best_score'] >= threshold:
            qualifying += 1
            for p in r['best_mask']:
                freq[p] += 1
    # Fallback: use all results if too few qualify
    if qualifying < 10:
        freq = Counter()
        max_sc = max(r['best_score'] for r in results)
        for r in results:
            if r['best_score'] >= max_sc - 2:
                qualifying += 1
                for p in r['best_mask']:
                    freq[p] += 1
    top24 = frozenset(p for p, _ in freq.most_common(N_NULLS))
    top17 = frozenset(p for p, _ in freq.most_common(17))
    return top24, top17, freq, qualifying


def jaccard(set_a, set_b):
    """Jaccard similarity between two sets."""
    if not set_a and not set_b:
        return 1.0
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


def analyze_campaign(name, results):
    """Analyze one campaign's results."""
    scores = [r['best_score'] for r in results]
    joint_scores = [r['joint_score'] for r in results]
    top24, top17, freq, n_qual = build_consensus(results)

    letters_at_top17 = set(CT[p] for p in top17)
    palette_overlap = letters_at_top17 & PALETTE_SET

    # Per-variant score distributions for all masks
    beau_scores = [r['variant_scores']['beau'] for r in results]
    vig_scores = [r['variant_scores']['vig'] for r in results]
    vbeau_scores = [r['variant_scores']['vbeau'] for r in results]

    # Find the single best mask by joint score
    best_joint_idx = max(range(len(results)), key=lambda i: results[i]['joint_score'])
    best_joint = results[best_joint_idx]

    return {
        'name': name,
        'n_results': len(results),
        'n_qualifying': n_qual,
        'score_mean': sum(scores) / len(scores),
        'score_max': max(scores),
        'score_min': min(scores),
        'joint_mean': sum(joint_scores) / len(joint_scores),
        'joint_max': max(joint_scores),
        'beau_max': max(beau_scores),
        'vig_max': max(vig_scores),
        'vbeau_max': max(vbeau_scores),
        'beau_mean': sum(beau_scores) / len(beau_scores),
        'vig_mean': sum(vig_scores) / len(vig_scores),
        'vbeau_mean': sum(vbeau_scores) / len(vbeau_scores),
        'top24': top24,
        'top17': top17,
        'n_distinct_at_top17': len(letters_at_top17),
        'letters_at_top17': sorted(letters_at_top17),
        'palette_overlap': len(palette_overlap),
        'consensus_vs_reference_jaccard': jaccard(top17, CONSENSUS_NULL_POSITIONS),
        'best_joint_mask': best_joint,
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 78)
    print("MODEL-INVARIANCE SWEEP: Cross-Variant Null Mask Convergence Test")
    print("=" * 78)
    print(f"Workers: {N_WORKERS}  |  Restarts: {N_RESTARTS}  |  Steps: {N_STEPS:,}")
    print(f"Palette positions available: {len(PALETTE_POSITIONS)}")
    print(f"Non-crib positions: {len(NON_CRIB)}")
    print(f"Reference palette: {sorted(PALETTE_SET)}")
    print(f"Reference consensus: {sorted(CONSENSUS_NULL_POSITIONS)}")
    print()

    t_total_start = time.time()

    # ── Campaign definitions ─────────────────────────────────────────────────

    campaigns = {
        # Individual variants, unconstrained
        'A1_beau_free': ('single', 'beau', False),
        'A2_vig_free': ('single', 'vig', False),
        'A3_vbeau_free': ('single', 'vbeau', False),
        # Individual variants, palette-constrained
        'B1_beau_pal': ('single', 'beau', True),
        'B2_vig_pal': ('single', 'vig', True),
        'B3_vbeau_pal': ('single', 'vbeau', True),
        # Joint, unconstrained
        'C_joint_free': ('joint', None, False),
        # Joint, palette-constrained
        'D_joint_pal': ('joint', None, True),
    }

    all_results = {}

    with Pool(N_WORKERS) as pool:
        for cname, (mode, variant, pal_const) in campaigns.items():
            t0 = time.time()
            constraint_str = "palette-constrained" if pal_const else "unconstrained"
            if mode == 'single':
                desc = f"{variant.upper()} autokey, {constraint_str}"
                tasks = [(variant, i * 53 + hash(cname) % 99991, pal_const)
                         for i in range(N_RESTARTS)]
                results = pool.map(_worker_single, tasks)
            else:
                desc = f"JOINT (beau+vig+vbeau), {constraint_str}"
                tasks = [(i * 53 + hash(cname) % 99991, pal_const)
                         for i in range(N_RESTARTS)]
                results = pool.map(_worker_joint, tasks)

            elapsed = time.time() - t0
            all_results[cname] = results

            # Quick summary
            scores = [r['best_score'] for r in results]
            joint_scores = [r['joint_score'] for r in results]
            print(f"Campaign {cname}: {desc}")
            print(f"  Time: {elapsed:.1f}s  |  Score: {min(scores):.0f}-{max(scores):.0f} "
                  f"(mean {sum(scores)/len(scores):.1f})  |  Joint: {max(joint_scores):.0f}")
            sys.stdout.flush()

    t_total = time.time() - t_total_start
    print(f"\nAll campaigns complete in {t_total:.1f}s")

    # ── Full analysis ────────────────────────────────────────────────────────

    print("\n" + "=" * 78)
    print("ANALYSIS")
    print("=" * 78)

    analyses = {}
    for cname in campaigns:
        analyses[cname] = analyze_campaign(cname, all_results[cname])

    # ── Per-campaign summary ─────────────────────────────────────────────────

    print(f"\n{'Campaign':<20s} {'OptMax':>7s} {'JntMax':>7s} {'B':>5s} {'V':>5s} {'VB':>5s} "
          f"{'Dist17':>6s} {'PalOvl':>6s} {'J(ref)':>7s}")
    print("-" * 78)
    for cname, a in analyses.items():
        print(f"{cname:<20s} {a['score_max']:>7.0f} {a['joint_max']:>7.0f} "
              f"{a['beau_max']:>5.0f} {a['vig_max']:>5.0f} {a['vbeau_max']:>5.0f} "
              f"{a['n_distinct_at_top17']:>6d} {a['palette_overlap']:>6d} "
              f"{a['consensus_vs_reference_jaccard']:>7.3f}")

    # ── Pairwise Jaccard of consensus masks ──────────────────────────────────

    print(f"\n{'─'*78}")
    print("PAIRWISE JACCARD (consensus top-17 positions)")
    print(f"{'─'*78}")

    camp_names = list(campaigns.keys())
    print(f"{'':>20s}", end='')
    for cn in camp_names:
        print(f" {cn[:8]:>8s}", end='')
    print()
    for cn1 in camp_names:
        print(f"{cn1:<20s}", end='')
        for cn2 in camp_names:
            j = jaccard(analyses[cn1]['top17'], analyses[cn2]['top17'])
            print(f" {j:>8.3f}", end='')
        print()

    # Also top-24
    print(f"\nPAIRWISE JACCARD (consensus top-24 positions)")
    print(f"{'':>20s}", end='')
    for cn in camp_names:
        print(f" {cn[:8]:>8s}", end='')
    print()
    for cn1 in camp_names:
        print(f"{cn1:<20s}", end='')
        for cn2 in camp_names:
            j = jaccard(analyses[cn1]['top24'], analyses[cn2]['top24'])
            print(f" {j:>8.3f}", end='')
        print()

    # ── Cross-variant performance of per-variant optima ──────────────────────

    print(f"\n{'─'*78}")
    print("CROSS-VARIANT PERFORMANCE (mean scores of per-variant-optimal masks)")
    print(f"{'─'*78}")

    print(f"{'Campaign':<20s} {'Beau mean':>10s} {'Vig mean':>10s} {'VBeau mean':>10s} {'Joint mean':>10s}")
    for cname, a in analyses.items():
        print(f"{cname:<20s} {a['beau_mean']:>10.2f} {a['vig_mean']:>10.2f} "
              f"{a['vbeau_mean']:>10.2f} {a['joint_mean']:>10.2f}")

    # ── Model-invariance verdict ─────────────────────────────────────────────

    print(f"\n{'='*78}")
    print("VERDICT: MODEL INVARIANCE")
    print(f"{'='*78}")

    # Compare joint-optimal scores to individual optima
    indiv_beau_max = max(analyses['A1_beau_free']['beau_max'],
                         analyses['B1_beau_pal']['beau_max'])
    indiv_vig_max = max(analyses['A2_vig_free']['vig_max'],
                        analyses['B2_vig_pal']['vig_max'])
    indiv_vbeau_max = max(analyses['A3_vbeau_free']['vbeau_max'],
                          analyses['B3_vbeau_pal']['vbeau_max'])
    indiv_sum_max = indiv_beau_max + indiv_vig_max + indiv_vbeau_max

    joint_free = analyses['C_joint_free']
    joint_pal = analyses['D_joint_pal']
    best_joint_score = max(joint_free['joint_max'], joint_pal['joint_max'])

    print(f"\n  Individual variant maxima:")
    print(f"    Beaufort:   {indiv_beau_max:.0f}/24")
    print(f"    Vigenere:   {indiv_vig_max:.0f}/24")
    print(f"    Var Beau:   {indiv_vbeau_max:.0f}/24")
    print(f"    Sum ceiling: {indiv_sum_max:.0f}/72")

    print(f"\n  Joint optimization maxima:")
    print(f"    Unconstrained: {joint_free['joint_max']:.0f}/72 "
          f"(B={joint_free['best_joint_mask']['variant_scores']['beau']:.0f}, "
          f"V={joint_free['best_joint_mask']['variant_scores']['vig']:.0f}, "
          f"VB={joint_free['best_joint_mask']['variant_scores']['vbeau']:.0f})")
    print(f"    Palette-const: {joint_pal['joint_max']:.0f}/72 "
          f"(B={joint_pal['best_joint_mask']['variant_scores']['beau']:.0f}, "
          f"V={joint_pal['best_joint_mask']['variant_scores']['vig']:.0f}, "
          f"VB={joint_pal['best_joint_mask']['variant_scores']['vbeau']:.0f})")

    ratio_free = best_joint_score / indiv_sum_max if indiv_sum_max > 0 else 0
    print(f"\n  Joint/individual ratio: {ratio_free:.3f} ({best_joint_score:.0f}/{indiv_sum_max:.0f})")

    if ratio_free >= 0.60:
        verdict = "APPROXIMATELY MODEL-INVARIANT — stego layer may be decouplable"
    elif ratio_free >= 0.40:
        verdict = "PARTIALLY MODEL-DEPENDENT — some convergence but significant loss"
    else:
        verdict = "MODEL-DEPENDENT — layers appear fundamentally entangled"
    print(f"\n  *** VERDICT: {verdict} ***")

    # ── Palette constraint effect ────────────────────────────────────────────

    print(f"\n{'─'*78}")
    print("PALETTE CONSTRAINT EFFECT")
    print(f"{'─'*78}")

    for variant in ('beau', 'vig', 'vbeau'):
        free_key = f"A{1 if variant=='beau' else 2 if variant=='vig' else 3}_{variant}_free"
        pal_key = f"B{1 if variant=='beau' else 2 if variant=='vig' else 3}_{variant}_pal"
        free_a = analyses[free_key]
        pal_a = analyses[pal_key]
        j = jaccard(free_a['top17'], pal_a['top17'])
        print(f"  {variant.upper():>6s}: free max={free_a['score_max']:.0f}, "
              f"pal max={pal_a['score_max']:.0f}, "
              f"Jaccard(top17)={j:.3f}")

    j_joint = jaccard(joint_free['top17'], joint_pal['top17'])
    print(f"  {'JOINT':>6s}: free max={joint_free['joint_max']:.0f}, "
          f"pal max={joint_pal['joint_max']:.0f}, "
          f"Jaccard(top17)={j_joint:.3f}")

    # ── Convergence: do palette-constrained variants agree more? ──────────

    print(f"\n{'─'*78}")
    print("CONVERGENCE COMPARISON: Free vs Palette-Constrained")
    print(f"{'─'*78}")

    # Free pairwise Jaccard among A1, A2, A3
    j_free_12 = jaccard(analyses['A1_beau_free']['top17'], analyses['A2_vig_free']['top17'])
    j_free_13 = jaccard(analyses['A1_beau_free']['top17'], analyses['A3_vbeau_free']['top17'])
    j_free_23 = jaccard(analyses['A2_vig_free']['top17'], analyses['A3_vbeau_free']['top17'])
    mean_free = (j_free_12 + j_free_13 + j_free_23) / 3

    # Palette pairwise Jaccard among B1, B2, B3
    j_pal_12 = jaccard(analyses['B1_beau_pal']['top17'], analyses['B2_vig_pal']['top17'])
    j_pal_13 = jaccard(analyses['B1_beau_pal']['top17'], analyses['B3_vbeau_pal']['top17'])
    j_pal_23 = jaccard(analyses['B2_vig_pal']['top17'], analyses['B3_vbeau_pal']['top17'])
    mean_pal = (j_pal_12 + j_pal_13 + j_pal_23) / 3

    print(f"  Free variants pairwise Jaccard:    {j_free_12:.3f}, {j_free_13:.3f}, {j_free_23:.3f}  mean={mean_free:.3f}")
    print(f"  Palette variants pairwise Jaccard: {j_pal_12:.3f}, {j_pal_13:.3f}, {j_pal_23:.3f}  mean={mean_pal:.3f}")

    if mean_pal > mean_free + 0.05:
        print("  → Palette constraint IMPROVES cross-model convergence")
    elif mean_pal < mean_free - 0.05:
        print("  → Palette constraint REDUCES cross-model convergence (unexpected)")
    else:
        print("  → Palette constraint has NEGLIGIBLE effect on convergence")

    # ── Best joint masks detail ──────────────────────────────────────────────

    print(f"\n{'─'*78}")
    print("BEST JOINT MASKS (top 5 by joint score, each campaign)")
    print(f"{'─'*78}")

    for cname in ('C_joint_free', 'D_joint_pal'):
        results = all_results[cname]
        results_sorted = sorted(results, key=lambda r: -r['joint_score'])[:5]
        print(f"\n  {cname}:")
        for i, r in enumerate(results_sorted):
            vs = r['variant_scores']
            print(f"    #{i+1}: joint={r['joint_score']:.0f} "
                  f"(B={vs['beau']:.0f}, V={vs['vig']:.0f}, VB={vs['vbeau']:.0f}) "
                  f"dist={r['n_distinct_letters']} letters={r['letters']}")
            if i == 0:
                print(f"         mask={r['best_mask']}")

    # ── Save results ─────────────────────────────────────────────────────────

    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'config': {
            'n_restarts': N_RESTARTS,
            'n_steps': N_STEPS,
            'n_workers': N_WORKERS,
            'score_threshold': SCORE_THRESHOLD,
        },
        'campaigns': {},
        'verdicts': {
            'joint_individual_ratio': round(ratio_free, 3),
            'verdict': verdict,
            'mean_free_convergence': round(mean_free, 3),
            'mean_palette_convergence': round(mean_pal, 3),
            'individual_maxima': {
                'beau': indiv_beau_max,
                'vig': indiv_vig_max,
                'vbeau': indiv_vbeau_max,
            },
            'joint_maxima': {
                'free': joint_free['joint_max'],
                'palette': joint_pal['joint_max'],
            },
        },
    }

    for cname, a in analyses.items():
        output['campaigns'][cname] = {
            'score_max': a['score_max'],
            'score_mean': round(a['score_mean'], 2),
            'joint_max': a['joint_max'],
            'joint_mean': round(a['joint_mean'], 2),
            'beau_max': a['beau_max'],
            'vig_max': a['vig_max'],
            'vbeau_max': a['vbeau_max'],
            'n_distinct_at_top17': a['n_distinct_at_top17'],
            'palette_overlap': a['palette_overlap'],
            'consensus_vs_reference_jaccard': a['consensus_vs_reference_jaccard'],
            'top17': sorted(a['top17']),
            'top24': sorted(a['top24']),
            'letters_at_top17': a['letters_at_top17'],
        }

    outpath = os.path.join(_ROOT, 'results', 'model_invariance_sweep_01.json')
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outpath}")

    print(f"\nTotal time: {time.time() - t_total_start:.1f}s")


if __name__ == '__main__':
    main()
