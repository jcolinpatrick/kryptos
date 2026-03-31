#!/usr/bin/env python3
"""
Cipher:   Analysis (null mask provenance)
Family:   analysis
Status:   active
Keyspace: 500 shuffled CTs × 50 SA restarts + 5 cipher models × 50 restarts
Last run:
Best score: N/A (diagnostic, not a decrypt attack)

PURPOSE: Test whether the null mask palette restriction (≤7 distinct letters
at the 17 consensus positions) is a property of K4 specifically, or an
artifact of the SA optimization mechanics.

TWO TESTS:

TEST 1 — Shuffled-CT SA:
  For each of 500 random letter-permutations of K4 (preserving letter
  frequencies, shuffling positions), run 50 SA restarts using the same
  KA-autokey objective as f_consensus_null_v1.py. Build a consensus
  mask for each shuffled CT (top-17 positions by frequency in ≥12/24
  masks). Count distinct letters at those 17 positions. Compare the
  distribution of distinct-letter-counts against the real K4 result (7).

  If shuffled CTs routinely produce ≤7 distinct letters → the finding
  is an SA artifact. If they almost never do → the finding is specific
  to K4's letter arrangement.

TEST 2 — Cipher-agnostic consensus:
  Run the SA on the REAL K4 ciphertext using 5 different scoring models:
    (a) KA autokey Vigenère, keyword KRYPTOS  (the original model)
    (b) KA periodic Beaufort, keyword KRYPTOS
    (c) AZ periodic Vigenère, keyword KRYPTOS
    (d) AZ periodic Beaufort, keyword KRYPTOS
    (e) Pure geometric (no decryption — score = number of crib positions
        that land on the correct CT letters after null removal, exploiting
        the two self-encrypting positions CT[32]=PT[32]=S, CT[73]=PT[73]=K)

  For each model, build consensus-17 from 50 SA restarts. Report:
    - Which positions appear in the consensus
    - Jaccard similarity with the original 17-position consensus
    - Distinct letter count at the consensus positions

  If the same 17 positions emerge regardless of cipher model → positions
  are intrinsic to K4. If they shift → positions are model-dependent.

PARALLELIZATION: Uses multiprocessing.Pool with N_WORKERS cores.
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


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

# ── Constants ────────────────────────────────────────────────────────────────

N = 97
N_NULLS = 24
N_PT = 73
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]
NC_SET = frozenset(NON_CRIB)

KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_IDX = {c: i for i, c in enumerate(ALPH)}

N_WORKERS = max(1, cpu_count() - 2)  # Leave 2 cores free

# ── Scoring functions ────────────────────────────────────────────────────────

def _decrypt_periodic(ct_str, keyword, alphabet, alph_idx, beaufort=False):
    """Periodic Vigenère or Beaufort decryption."""
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
    """Autokey Vigenère or Beaufort decryption."""
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


def score_mask(null_set, ct_text, model='ka_autokey_vig'):
    """Score a null mask against a ciphertext using the specified model."""
    ct_reduced = ''.join(ct_text[i] for i in range(N) if i not in null_set)
    if len(ct_reduced) != N_PT:
        return 0.0

    n_before_ene = sum(1 for p in null_set if p < ENE_START)
    n_before_bcl = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n_before_ene
    bcl_s = BCL_START - n_before_bcl

    if model == 'ka_autokey_vig':
        pt = _decrypt_autokey(ct_reduced, "KRYPTOS", KA_STR, KA_IDX, beaufort=False)
    elif model == 'ka_periodic_beau':
        pt = _decrypt_periodic(ct_reduced, "KRYPTOS", KA_STR, KA_IDX, beaufort=True)
    elif model == 'az_periodic_vig':
        pt = _decrypt_periodic(ct_reduced, "KRYPTOS", ALPH, AZ_IDX, beaufort=False)
    elif model == 'az_periodic_beau':
        pt = _decrypt_periodic(ct_reduced, "KRYPTOS", ALPH, AZ_IDX, beaufort=True)
    elif model == 'geometric':
        score = 0.0
        for orig_pos, expected_ct in [(32, 'S'), (73, 'K')]:
            n_before = sum(1 for p in null_set if p < orig_pos)
            reduced_pos = orig_pos - n_before
            if reduced_pos < len(ct_reduced) and ct_reduced[reduced_pos] == expected_ct:
                score += 1.0
        for j, c in enumerate(ENE_WORD):
            orig = ENE_START + j
            n_before = sum(1 for p in null_set if p < orig)
            rp = orig - n_before
            if rp < len(ct_reduced) and ct_reduced[rp] == CT[orig]:
                score += 0.5
        for j, c in enumerate(BCL_WORD):
            orig = BCL_START + j
            n_before = sum(1 for p in null_set if p < orig)
            rp = orig - n_before
            if rp < len(ct_reduced) and ct_reduced[rp] == CT[orig]:
                score += 0.5
        return score
    else:
        raise ValueError(f"Unknown model: {model}")

    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_s + j < len(pt) and pt[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_s + j < len(pt) and pt[bcl_s + j] == c)
    return float(e + b)


# ── SA engine ────────────────────────────────────────────────────────────────

def sa_run(ct_text, model, seed, steps=200_000, T0=0.5):
    """Run one SA restart. Returns best mask and score."""
    rng = random.Random(seed)
    pool = [p for p in range(N) if p not in CRIB_POSITIONS]
    null_set = set(rng.sample(pool, N_NULLS))
    non_null = set(pool) - null_set

    score = score_mask(frozenset(null_set), ct_text, model)
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

        new_sc = score_mask(frozenset(null_set), ct_text, model)
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


# ── Parallel worker for a single SA restart ──────────────────────────────────

def _sa_worker(args):
    """Worker function for multiprocessing. Returns (score, mask)."""
    ct_text, model, seed = args
    sc, mask = sa_run(ct_text, model, seed)
    return sc, mask


def build_consensus_parallel(ct_text, model, n_restarts=50, threshold=10,
                             seed_base=0, pool=None):
    """Run n_restarts SA runs in parallel, build consensus top-17 positions."""
    tasks = [(ct_text, model, seed_base + i * 53) for i in range(n_restarts)]

    if pool is not None:
        results = pool.map(_sa_worker, tasks)
    else:
        results = [_sa_worker(t) for t in tasks]

    freq = Counter()
    scores = []
    for sc, mask in results:
        scores.append(sc)
        if sc >= threshold:
            for p in mask:
                freq[p] += 1

    if not freq:
        for sc, mask in results:
            for p in mask:
                freq[p] += 1

    top17 = frozenset(p for p, _ in freq.most_common(17))
    return top17, freq, scores


# ── Worker for a single shuffled-CT trial ────────────────────────────────────

def _shuffle_trial_worker(args):
    """Process one shuffled CT: run SA restarts, build consensus, measure diversity."""
    trial_idx, n_restarts = args
    rng = random.Random(42 + trial_idx)
    ct_list = list(CT)
    rng.shuffle(ct_list)
    shuffled_ct = ''.join(ct_list)

    # Run SA restarts sequentially within this worker
    freq = Counter()
    scores = []
    for i in range(n_restarts):
        sc, mask = sa_run(shuffled_ct, 'ka_autokey_vig',
                          seed=trial_idx * 1000 + i * 53)
        scores.append(sc)
        if sc >= 8:
            for p in mask:
                freq[p] += 1

    if not freq:
        # Use all masks if none reached threshold
        for sc, mask in zip(scores, [sa_run(shuffled_ct, 'ka_autokey_vig',
                                            seed=trial_idx * 1000 + i * 53)[1]
                                     for i in range(n_restarts)]):
            for p in mask:
                freq[p] += 1

    top17 = frozenset(p for p, _ in freq.most_common(17))
    letters = [shuffled_ct[p] for p in top17 if p < len(shuffled_ct)]
    n_distinct = len(set(letters))
    return trial_idx, n_distinct, max(scores) if scores else 0


# ═══════════════════════════════════════════════════════════════════════════
# TEST 2: Cipher-agnostic consensus (faster, run first)
# ═══════════════════════════════════════════════════════════════════════════

def test_cipher_agnostic(n_restarts=50, mp_pool=None):
    """Run SA with different cipher models, compare consensus positions."""
    print("=" * 70)
    print("TEST 2: CIPHER-AGNOSTIC — Are the 17 positions model-dependent?")
    print("=" * 70)
    print(f"  {n_restarts} SA restarts per model, 5 models")
    print()

    models = [
        ('ka_autokey_vig', 'KA autokey Vigenère (original)'),
        ('ka_periodic_beau', 'KA periodic Beaufort'),
        ('az_periodic_vig', 'AZ periodic Vigenère'),
        ('az_periodic_beau', 'AZ periodic Beaufort'),
        ('geometric', 'Pure geometric (no decryption)'),
    ]

    reference = CONSENSUS_NULL_POSITIONS
    results = {}

    for model_id, model_name in models:
        print(f"  Model: {model_name}")
        t0 = time.time()

        top17, freq, scores = build_consensus_parallel(
            CT, model_id, n_restarts=n_restarts,
            threshold=8, seed_base=hash(model_id) % 10000,
            pool=mp_pool,
        )

        letters = [CT[p] for p in top17]
        n_distinct = len(set(letters))
        jaccard = len(top17 & reference) / len(top17 | reference) if top17 else 0
        overlap = len(top17 & reference)
        best_score = max(scores) if scores else 0
        elapsed = time.time() - t0

        results[model_id] = {
            'positions': sorted(top17),
            'distinct': n_distinct,
            'palette': sorted(set(letters)),
            'jaccard': round(jaccard, 3),
            'overlap': overlap,
            'best_score': best_score,
        }

        print(f"    Positions: {sorted(top17)}")
        print(f"    Distinct letters: {n_distinct}  palette: {sorted(set(letters))}")
        print(f"    Overlap with consensus: {overlap}/17  Jaccard: {jaccard:.3f}")
        print(f"    Best SA score: {best_score:.1f}  ({elapsed:.1f}s)")
        print()

    # Summary
    print("  SUMMARY:")
    print(f"  {'Model':<35s} {'Distinct':>8s} {'Overlap':>8s} {'Jaccard':>8s}")
    print(f"  {'-'*35} {'-'*8} {'-'*8} {'-'*8}")
    for model_id, model_name in models:
        r = results[model_id]
        print(f"  {model_name:<35s} {r['distinct']:>8d} {r['overlap']:>5d}/17 {r['jaccard']:>8.3f}")
    print()

    jaccards = [results[m]['jaccard'] for m, _ in models]
    mean_j = sum(jaccards) / len(jaccards)
    print(f"  Mean Jaccard similarity: {mean_j:.3f}")
    if mean_j > 0.7:
        print("  → STRONG: Positions are largely model-independent (intrinsic to K4)")
    elif mean_j > 0.4:
        print("  → MODERATE: Some model dependence, but substantial core overlap")
    else:
        print("  → WEAK: Positions are heavily model-dependent (may be SA artifact)")
    print()

    return results


# ═══════════════════════════════════════════════════════════════════════════
# TEST 1: Shuffled-CT SA (parallelized across shuffled CTs)
# ═══════════════════════════════════════════════════════════════════════════

def test_shuffled_ct(n_shuffles=500, n_restarts=30, mp_pool=None):
    """Run SA on shuffled ciphertexts, measure palette diversity."""
    print("=" * 70)
    print("TEST 1: SHUFFLED-CT SA — Is the palette restriction K4-specific?")
    print("=" * 70)
    print(f"  {n_shuffles} shuffled CTs × {n_restarts} SA restarts each")
    print(f"  Model: ka_autokey_vig (same as original discovery)")
    print(f"  Workers: {N_WORKERS}")
    print()

    # Baseline: real K4
    real_top17 = CONSENSUS_NULL_POSITIONS
    real_letters = [CT[p] for p in real_top17]
    real_distinct = len(set(real_letters))
    print(f"  Real K4: {real_distinct} distinct letters at consensus positions")
    print(f"  Letters: {real_letters}")
    print(f"  Palette: {sorted(set(real_letters))}")
    print()

    t0 = time.time()
    tasks = [(trial, n_restarts) for trial in range(n_shuffles)]

    # Parallel map across shuffled CTs
    if mp_pool is not None:
        # Process in chunks to report progress
        chunk_size = 50
        distinct_counts = []
        le7_count = 0
        for chunk_start in range(0, n_shuffles, chunk_size):
            chunk = tasks[chunk_start:chunk_start + chunk_size]
            results = mp_pool.map(_shuffle_trial_worker, chunk)
            for trial_idx, n_distinct, best_sc in results:
                distinct_counts.append(n_distinct)
                if n_distinct <= 7:
                    le7_count += 1
            elapsed = time.time() - t0
            done = chunk_start + len(chunk)
            rate = done / max(elapsed, 1)
            eta = (n_shuffles - done) / max(rate, 0.01)
            print(f"  Done {done:4d}/{n_shuffles}  (≤7 so far: {le7_count})  "
                  f"[{elapsed:.0f}s elapsed, ~{eta:.0f}s remaining]")
    else:
        distinct_counts = []
        le7_count = 0
        for trial in range(n_shuffles):
            _, n_distinct, _ = _shuffle_trial_worker((trial, n_restarts))
            distinct_counts.append(n_distinct)
            if n_distinct <= 7:
                le7_count += 1
            if trial % 50 == 0:
                elapsed = time.time() - t0
                rate = (trial + 1) / max(elapsed, 1)
                eta = (n_shuffles - trial - 1) / max(rate, 0.01)
                print(f"  Trial {trial:4d}/{n_shuffles}: distinct={n_distinct:2d}  "
                      f"(≤7 so far: {le7_count})  "
                      f"[{elapsed:.0f}s elapsed, ~{eta:.0f}s remaining]")

    elapsed = time.time() - t0
    print()
    print(f"  Completed {n_shuffles} shuffled CTs in {elapsed:.1f}s")
    print()

    # Results
    print("  RESULTS:")
    print(f"  Real K4 distinct count: {real_distinct}")
    print(f"  Shuffled distinct counts: mean={sum(distinct_counts)/len(distinct_counts):.1f}, "
          f"min={min(distinct_counts)}, max={max(distinct_counts)}")
    print(f"  Shuffled trials with ≤7 distinct: {le7_count}/{n_shuffles} "
          f"= {le7_count/n_shuffles:.6f}")
    if le7_count > 0:
        print(f"  → p ≈ {le7_count/n_shuffles:.2e} (shuffled-CT null)")
    else:
        print(f"  → p < {1/n_shuffles:.2e} (zero hits in {n_shuffles} trials)")
    print()

    # Distribution histogram
    hist = Counter(distinct_counts)
    print("  Distribution of distinct-letter counts (shuffled CTs):")
    for k in sorted(hist.keys()):
        bar = '#' * (hist[k] * 40 // max(hist.values()))
        marker = " ← REAL K4" if k == real_distinct else ""
        print(f"    {k:2d}: {hist[k]:4d} {bar}{marker}")
    print()

    return distinct_counts, le7_count


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("E-NULL-MASK-PROVENANCE-01: Null Mask Provenance Analysis")
    print("=" * 70)
    print(f"CT = {CT}")
    print(f"Consensus null positions: {sorted(CONSENSUS_NULL_POSITIONS)}")
    print(f"Consensus palette: {sorted(NULL_PALETTE)}")
    print(f"Workers: {N_WORKERS} (of {cpu_count()} cores)")
    print()

    t_start = time.time()

    with Pool(processes=N_WORKERS) as mp_pool:
        # Run Test 2 first (faster — 5 models × 50 restarts)
        cipher_results = test_cipher_agnostic(n_restarts=50, mp_pool=mp_pool)

        # Run Test 1 (heavier — 500 shuffled CTs × 30 restarts each)
        shuffle_counts, le7 = test_shuffled_ct(
            n_shuffles=500, n_restarts=30, mp_pool=mp_pool
        )

    # ── Final summary ────────────────────────────────────────────────────
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print()
    print("Test 1 (Shuffled-CT):")
    if le7 == 0:
        print(f"  0/{len(shuffle_counts)} shuffled CTs produced ≤7 distinct letters")
        print(f"  → Palette restriction is SPECIFIC to K4, not an SA artifact")
        print(f"  → p < {1/len(shuffle_counts):.2e} under shuffled-CT null")
    else:
        p = le7 / len(shuffle_counts)
        print(f"  {le7}/{len(shuffle_counts)} shuffled CTs produced ≤7 distinct letters")
        print(f"  → p ≈ {p:.2e} under shuffled-CT null")
        if p < 0.01:
            print(f"  → Still significant: palette restriction mostly specific to K4")
        else:
            print(f"  → NOT significant: palette restriction may be an SA artifact")
    print()

    print("Test 2 (Cipher-agnostic):")
    jaccards = [v['jaccard'] for v in cipher_results.values()]
    mean_j = sum(jaccards) / len(jaccards)
    model_independent = sum(1 for v in cipher_results.values() if v['overlap'] >= 12)
    print(f"  Mean Jaccard: {mean_j:.3f}")
    print(f"  Models with ≥12/17 overlap: {model_independent}/5")
    if model_independent >= 3:
        print(f"  → Positions are LARGELY MODEL-INDEPENDENT")
    else:
        print(f"  → Positions are MODEL-DEPENDENT")
    print()

    total_elapsed = time.time() - t_start
    print(f"Total elapsed: {total_elapsed:.0f}s ({total_elapsed/60:.1f} min)")
    print()

    # Save results
    output = {
        'test1_shuffled_ct': {
            'n_shuffles': len(shuffle_counts),
            'n_restarts_per': 30,
            'le7_count': le7,
            'p_value': le7 / len(shuffle_counts) if le7 > 0 else f"<{1/len(shuffle_counts):.2e}",
            'mean_distinct': round(sum(shuffle_counts) / len(shuffle_counts), 2),
            'min_distinct': min(shuffle_counts),
            'max_distinct': max(shuffle_counts),
            'distribution': dict(Counter(shuffle_counts)),
        },
        'test2_cipher_agnostic': {
            model_id: {
                'positions': r['positions'],
                'distinct': r['distinct'],
                'palette': r['palette'],
                'overlap': r['overlap'],
                'jaccard': r['jaccard'],
            }
            for model_id, r in cipher_results.items()
        },
        'reference_consensus': sorted(CONSENSUS_NULL_POSITIONS),
        'reference_palette': sorted(NULL_PALETTE),
        'workers': N_WORKERS,
        'total_elapsed_s': round(total_elapsed, 1),
    }

    out_path = os.path.join(_ROOT, 'results', 'null_mask_provenance_01.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to: {out_path}")

    print()
    print("verdict:", json.dumps({
        "test1_verdict": "K4-specific" if le7 == 0 else "needs_investigation",
        "test2_verdict": "model-independent" if model_independent >= 3 else "model-dependent",
        "test1_p": le7 / len(shuffle_counts) if le7 > 0 else 0,
        "test2_mean_jaccard": round(mean_j, 3),
        "workers": N_WORKERS,
        "elapsed_min": round(total_elapsed / 60, 1),
    }))
