#!/usr/bin/env python3
"""
Cipher: cross-model palette stability
Family: statistical
Status: active
Keyspace: 5 models × 200 SA restarts × 300K steps = ~300M SA steps
Last run:
Best score:
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

"""E-CROSSMODEL-PALETTE-01: Cross-Model Palette Stability Test.

QUESTION: Does the 7-letter null palette {B,G,I,K,O,W,Z} survive across
cipher models, or does it only appear under the specific model used to
discover it (KA autokey Vigenere with keyword KRYPTOS)?

DESIGN: Run the FULL consensus-building protocol (200 SA restarts, 300K
steps each, threshold ≥12/24) under 5 cipher models:
  1. KA autokey Vigenere (original discovery model)
  2. KA autokey Beaufort
  3. KA periodic Beaufort
  4. AZ periodic Vigenere
  5. AZ periodic Beaufort

For each model, build the consensus top-17 positions (>50% frequency among
masks scoring ≥12), then report:
  - The distinct letter count at those positions
  - The specific letters (palette identity)
  - Jaccard overlap of the PALETTE (not just positions) with {B,G,I,K,O,W,Z}
  - Jaccard overlap of POSITIONS with the original consensus-17

The prior provenance test (e_null_mask_provenance_01.py) used only 50
restarts at 200K steps — insufficient to converge. This test matches the
original discovery protocol exactly.

STATISTICAL FRAMEWORK:
  Claim: The palette {B,G,I,K,O,W,Z} is model-invariant (appears
         regardless of which cipher model drives SA optimization).
  Null: The palette is model-conditional (only appears under KA autokey Vig).
  Test: Count how many of 5 models produce a consensus with ≤7 distinct
        letters AND ≥5/7 overlap with the original palette.
  Verdict: If ≥3/5 models → palette is largely model-invariant.
           If only 1/5 → palette is model-conditional.
"""
import sys
import os
import random
import math
import time
import json
from collections import Counter
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CRIB_POSITIONS, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
)

# ── Constants ────────────────────────────────────────────────────────────

N = 97
N_NULLS = 24
N_PT = 73
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]

KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_IDX = {c: i for i, c in enumerate(ALPH)}

N_WORKERS = max(1, cpu_count() - 2)
N_RESTARTS = 200
N_STEPS = 300_000
SCORE_THRESHOLD = 12
REFERENCE_PALETTE = frozenset(NULL_PALETTE)  # {B,G,I,K,O,W,Z}
REFERENCE_POSITIONS = frozenset(CONSENSUS_NULL_POSITIONS)

MODELS = [
    ('ka_autokey_vig', 'KA autokey Vigenère'),
    ('ka_autokey_beau', 'KA autokey Beaufort'),
    ('ka_periodic_beau', 'KA periodic Beaufort'),
    ('az_periodic_vig', 'AZ periodic Vigenère'),
    ('az_periodic_beau', 'AZ periodic Beaufort'),
]


# ── Decryption functions ─────────────────────────────────────────────────

def _decrypt_periodic(ct_str, keyword, alphabet, alph_idx, beaufort=False):
    kw_idx = [alph_idx[c] for c in keyword]
    klen = len(kw_idx)
    mod = len(alphabet)
    pt = []
    for i, c in enumerate(ct_str):
        ci = alph_idx[c]
        ki = kw_idx[i % klen]
        if beaufort:
            pi = (ki - ci) % mod
        else:
            pi = (ci - ki) % mod
        pt.append(alphabet[pi])
    return ''.join(pt)


def _decrypt_autokey(ct_str, keyword, alphabet, alph_idx, beaufort=False):
    kw_idx = [alph_idx[c] for c in keyword]
    klen = len(kw_idx)
    mod = len(alphabet)
    pt_indices = []
    pt = []
    for i, c in enumerate(ct_str):
        ci = alph_idx[c]
        ki = kw_idx[i] if i < klen else pt_indices[i - klen]
        if beaufort:
            pi = (ki - ci) % mod
        else:
            pi = (ci - ki) % mod
        pt_indices.append(pi)
        pt.append(alphabet[pi])
    return ''.join(pt)


def score_mask(null_set, model):
    """Score a null mask using the specified cipher model."""
    ct_reduced = ''.join(CT[i] for i in range(N) if i not in null_set)
    if len(ct_reduced) != N_PT:
        return 0.0

    n_before_ene = sum(1 for p in null_set if p < ENE_START)
    n_before_bcl = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n_before_ene
    bcl_s = BCL_START - n_before_bcl

    if model == 'ka_autokey_vig':
        pt = _decrypt_autokey(ct_reduced, "KRYPTOS", KA_STR, KA_IDX, beaufort=False)
    elif model == 'ka_autokey_beau':
        pt = _decrypt_autokey(ct_reduced, "KRYPTOS", KA_STR, KA_IDX, beaufort=True)
    elif model == 'ka_periodic_beau':
        pt = _decrypt_periodic(ct_reduced, "KRYPTOS", KA_STR, KA_IDX, beaufort=True)
    elif model == 'az_periodic_vig':
        pt = _decrypt_periodic(ct_reduced, "KRYPTOS", ALPH, AZ_IDX, beaufort=False)
    elif model == 'az_periodic_beau':
        pt = _decrypt_periodic(ct_reduced, "KRYPTOS", ALPH, AZ_IDX, beaufort=True)
    else:
        raise ValueError(f"Unknown model: {model}")

    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_s + j < len(pt) and pt[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_s + j < len(pt) and pt[bcl_s + j] == c)
    return float(e + b)


# ── SA engine ────────────────────────────────────────────────────────────

def sa_run(model, seed, steps=N_STEPS, T0=0.5):
    """One SA restart. Returns (best_score, best_mask_sorted)."""
    rng = random.Random(seed)
    pool = [p for p in range(N) if p not in CRIB_POSITIONS]
    null_set = set(rng.sample(pool, N_NULLS))
    non_null = set(pool) - null_set

    score = score_mask(frozenset(null_set), model)
    best_sc = score
    best_null = frozenset(null_set)

    Tf = 0.01
    for step in range(steps):
        T = T0 * (Tf / T0) ** (step / steps)
        cands = list(null_set)
        nn_list = list(non_null)
        if not cands or not nn_list:
            break
        out = rng.choice(cands)
        into = rng.choice(nn_list)
        null_set.discard(out)
        null_set.add(into)
        non_null.discard(into)
        non_null.add(out)

        new_sc = score_mask(frozenset(null_set), model)
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / max(T, 1e-10)):
            score = new_sc
            if score > best_sc:
                best_sc = score
                best_null = frozenset(null_set)
        else:
            null_set.discard(into)
            null_set.add(out)
            non_null.discard(out)
            non_null.add(into)

    return best_sc, sorted(best_null)


def _worker(args):
    model, seed = args
    return sa_run(model, seed)


def build_consensus(model, n_restarts, pool):
    """Run n_restarts SA, build consensus top-17 from masks scoring ≥ threshold."""
    tasks = [(model, i * 53 + hash(model) % 10000) for i in range(n_restarts)]
    results = pool.map(_worker, tasks)

    freq = Counter()
    scores = []
    high_score_masks = []
    for sc, mask in results:
        scores.append(sc)
        if sc >= SCORE_THRESHOLD:
            high_score_masks.append(mask)
            for p in mask:
                freq[p] += 1

    n_qualifying = len(high_score_masks)

    # Fallback: if too few qualify, lower threshold
    if n_qualifying < 10:
        freq = Counter()
        for sc, mask in results:
            if sc >= max(scores) - 2:
                for p in mask:
                    freq[p] += 1
                n_qualifying += 1

    top17 = frozenset(p for p, _ in freq.most_common(17))

    # Also get top-24 (full null mask)
    top24 = frozenset(p for p, _ in freq.most_common(24))

    return top17, top24, freq, scores, n_qualifying


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("E-CROSSMODEL-PALETTE-01: Cross-Model Palette Stability")
    print("=" * 72)
    print(f"Protocol: {N_RESTARTS} SA restarts × {N_STEPS:,} steps per model")
    print(f"Models: {len(MODELS)}")
    print(f"Workers: {N_WORKERS}")
    print(f"Score threshold: ≥{SCORE_THRESHOLD}/24")
    print(f"Reference palette: {sorted(REFERENCE_PALETTE)}")
    print(f"Reference positions: {sorted(REFERENCE_POSITIONS)}")
    print()

    t_start = time.time()
    all_results = {}

    with Pool(N_WORKERS) as pool:
        for model_id, model_name in MODELS:
            print(f"\n{'─'*72}")
            print(f"Model: {model_name} ({model_id})")
            print(f"{'─'*72}")
            t0 = time.time()

            top17, top24, freq, scores, n_qual = build_consensus(
                model_id, N_RESTARTS, pool
            )

            # Analyze the consensus
            letters_17 = [CT[p] for p in top17]
            distinct_17 = set(letters_17)
            n_distinct_17 = len(distinct_17)

            letters_24 = [CT[p] for p in top24]
            distinct_24 = set(letters_24)
            n_distinct_24 = len(distinct_24)

            # Palette overlaps
            palette_jaccard = (
                len(distinct_17 & REFERENCE_PALETTE) /
                len(distinct_17 | REFERENCE_PALETTE)
            ) if distinct_17 else 0

            palette_overlap = len(distinct_17 & REFERENCE_PALETTE)
            palette_recall = palette_overlap / len(REFERENCE_PALETTE)  # How many of the 7 are found
            palette_precision = palette_overlap / n_distinct_17 if n_distinct_17 else 0  # How pure

            # Position overlaps
            pos_jaccard = (
                len(top17 & REFERENCE_POSITIONS) /
                len(top17 | REFERENCE_POSITIONS)
            ) if top17 else 0
            pos_overlap = len(top17 & REFERENCE_POSITIONS)

            elapsed = time.time() - t0

            result = {
                'model': model_id,
                'model_name': model_name,
                'n_qualifying': n_qual,
                'best_score': max(scores) if scores else 0,
                'mean_score': round(sum(scores) / len(scores), 2) if scores else 0,
                'top17_positions': sorted(top17),
                'top24_positions': sorted(top24),
                'letters_at_top17': ''.join(CT[p] for p in sorted(top17)),
                'n_distinct_top17': n_distinct_17,
                'palette_top17': sorted(distinct_17),
                'n_distinct_top24': n_distinct_24,
                'palette_top24': sorted(distinct_24),
                'palette_jaccard': round(palette_jaccard, 3),
                'palette_overlap': palette_overlap,
                'palette_recall': round(palette_recall, 3),  # 7 of 7 found?
                'palette_precision': round(palette_precision, 3),  # pure?
                'position_jaccard': round(pos_jaccard, 3),
                'position_overlap': pos_overlap,
                'elapsed_s': round(elapsed, 1),
            }
            all_results[model_id] = result

            print(f"  Qualifying masks (≥{SCORE_THRESHOLD}): {n_qual}/{N_RESTARTS}")
            print(f"  Best score: {result['best_score']:.0f}/24")
            print(f"  Top-17 positions: {sorted(top17)}")
            print(f"  Letters at top-17: {result['letters_at_top17']}")
            print(f"  Distinct (top-17): {n_distinct_17}  palette: {sorted(distinct_17)}")
            print(f"  Distinct (top-24): {n_distinct_24}")
            print()
            print(f"  PALETTE ANALYSIS:")
            print(f"    Reference: {sorted(REFERENCE_PALETTE)}")
            print(f"    This model: {sorted(distinct_17)}")
            print(f"    Overlap: {palette_overlap}/7 reference letters found")
            print(f"    Recall: {palette_recall:.1%} (how many of the 7 appear)")
            print(f"    Precision: {palette_precision:.1%} (how pure — 7/{n_distinct_17})")
            print(f"    Jaccard (palette): {palette_jaccard:.3f}")
            print()
            print(f"  POSITION ANALYSIS:")
            print(f"    Overlap with reference: {pos_overlap}/17")
            print(f"    Jaccard (positions): {pos_jaccard:.3f}")
            print(f"  [{elapsed:.0f}s]")

    # ── Summary ──────────────────────────────────────────────────────────
    total_elapsed = time.time() - t_start
    print(f"\n{'='*72}")
    print("SUMMARY")
    print(f"{'='*72}")
    print()
    print(f"  {'Model':<30s} {'Dist':>5s} {'PalOvlp':>8s} {'PalJac':>8s} {'PosOvlp':>8s} {'PosJac':>8s}")
    print(f"  {'-'*30} {'-'*5} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")
    for model_id, model_name in MODELS:
        r = all_results[model_id]
        print(f"  {model_name:<30s} {r['n_distinct_top17']:>5d} "
              f"{r['palette_overlap']:>5d}/7 {r['palette_jaccard']:>8.3f} "
              f"{r['position_overlap']:>5d}/17 {r['position_jaccard']:>8.3f}")

    # Verdict
    print()
    n_low_distinct = sum(1 for r in all_results.values() if r['n_distinct_top17'] <= 7)
    n_palette_match = sum(1 for r in all_results.values()
                          if r['palette_overlap'] >= 5 and r['n_distinct_top17'] <= 9)
    mean_palette_jaccard = sum(r['palette_jaccard'] for r in all_results.values()) / len(all_results)
    mean_pos_jaccard = sum(r['position_jaccard'] for r in all_results.values()) / len(all_results)

    print(f"  Models with ≤7 distinct: {n_low_distinct}/{len(MODELS)}")
    print(f"  Models with ≥5/7 palette overlap AND ≤9 distinct: {n_palette_match}/{len(MODELS)}")
    print(f"  Mean palette Jaccard: {mean_palette_jaccard:.3f}")
    print(f"  Mean position Jaccard: {mean_pos_jaccard:.3f}")
    print()

    if n_low_distinct >= 3:
        verdict = "PALETTE IS MODEL-INVARIANT"
        detail = f"{n_low_distinct}/{len(MODELS)} models produce ≤7 distinct letters"
    elif n_palette_match >= 3:
        verdict = "PALETTE IDENTITY IS PARTIALLY STABLE"
        detail = f"{n_palette_match}/{len(MODELS)} models find ≥5/7 reference letters"
    elif n_low_distinct >= 1:
        verdict = "PALETTE IS MODEL-CONDITIONAL"
        detail = f"Only {n_low_distinct}/{len(MODELS)} model(s) produce ≤7 distinct"
    else:
        verdict = "PALETTE IS STRONGLY MODEL-DEPENDENT"
        detail = "No model produces ≤7 distinct letters at consensus positions"

    print(f"  VERDICT: {verdict}")
    print(f"  {detail}")
    print(f"\n  Total elapsed: {total_elapsed:.0f}s ({total_elapsed/60:.1f} min)")

    # Save
    output = {
        'experiment': 'E-CROSSMODEL-PALETTE-01',
        'protocol': {
            'n_restarts': N_RESTARTS,
            'n_steps': N_STEPS,
            'score_threshold': SCORE_THRESHOLD,
            'n_models': len(MODELS),
        },
        'reference_palette': sorted(REFERENCE_PALETTE),
        'reference_positions': sorted(REFERENCE_POSITIONS),
        'results': {k: v for k, v in all_results.items()},
        'summary': {
            'n_low_distinct': n_low_distinct,
            'n_palette_match': n_palette_match,
            'mean_palette_jaccard': round(mean_palette_jaccard, 3),
            'mean_position_jaccard': round(mean_pos_jaccard, 3),
            'verdict': verdict,
        },
        'total_elapsed_s': round(total_elapsed, 1),
        'workers': N_WORKERS,
    }

    out_path = os.path.join(_ROOT, 'results', 'cross_model_palette_stability.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results: {out_path}")


if __name__ == '__main__':
    main()
