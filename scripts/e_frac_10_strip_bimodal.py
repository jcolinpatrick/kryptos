#!/usr/bin/env python3
"""E-FRAC-10: Strip Manipulation + Periodic Substitution Scoring.

Following E-FRAC-09's finding that strip manipulation is bimodal-compatible
(while columnar, route, and rail fence are not), this experiment:

1. Generates strip manipulation permutations at widths 5-20
2. Pre-filters with the bimodal fingerprint
3. Pre-filters with Bean constraints
4. Scores surviving candidates against periodic substitution (periods 2-7)
5. Computes noise floor via random bimodal-compatible permutations

Strip manipulation model:
- Write plaintext left-to-right on strips of width W
- Physically rearrange and optionally flip strips
- Read off the result as ciphertext

This is what Sanborn described doing — "strip manipulation" from the
Smithsonian archives. It produces non-columnar transpositions.
"""
import itertools
import json
import math
import os
import random
import time
from collections import Counter

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.aggregate import score_candidate

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
random.seed(42)


def bimodal_check(perm, ene_tolerance=5, bc_max_identity=4):
    """Standard bimodal check."""
    for i in range(22, 31):
        if i < CT_LEN:
            if abs(perm[i] - i) > ene_tolerance:
                return False
    bc_identity = 0
    for i in range(64, min(75, CT_LEN)):
        if abs(perm[i] - i) <= 2:
            bc_identity += 1
    return bc_identity <= bc_max_identity


def check_bean(perm, variant="vigenere"):
    """Check Bean equality and inequality constraints."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i

    # Key derivation depends on variant
    def key_at(pt_pos):
        ct_pos = inv[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            return (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            return (ct_val + pt_val) % MOD
        else:  # variant_beaufort
            return (pt_val - ct_val) % MOD

    # Bean equality
    for eq_a, eq_b in BEAN_EQ:
        if key_at(eq_a) != key_at(eq_b):
            return False

    # Bean inequalities
    for ineq_a, ineq_b in BEAN_INEQ:
        if key_at(ineq_a) == key_at(ineq_b):
            return False

    return True


def strip_perm(n, strip_width, strip_order, flips):
    """Generate a strip manipulation permutation.

    strip_order[i] = which original strip goes to position i
    flips[i] = whether to flip strip strip_order[i]

    Returns perm where perm[ct_pos] = pt_pos (gather convention).
    """
    n_strips = math.ceil(n / strip_width)

    # Build strips: strip j contains PT positions [j*W, j*W+1, ..., j*W+W-1]
    strips = []
    for s in range(n_strips):
        start = s * strip_width
        end = min(start + strip_width, n)
        strips.append(list(range(start, end)))

    # Rearrange and flip
    perm = []
    for i in range(n_strips):
        s_idx = strip_order[i]
        strip = strips[s_idx]
        if flips[i]:
            strip = list(reversed(strip))
        perm.extend(strip)

    return perm[:n]


def score_perm_periodic(perm, periods=(2, 3, 4, 5, 6, 7),
                        variants=("vigenere", "beaufort", "variant_beaufort")):
    """Score a permutation under periodic substitution models.

    For each crib position p with known PT[p]:
    - perm[ct_pos] = p means CT[ct_pos] came from PT position p
    - Under periodic substitution with period P:
      key[ct_pos] depends on ct_pos mod P (model B: trans then sub)
      OR key[p] depends on p mod P (model A: sub then trans)

    Returns: (best_score, best_config)
    """
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i

    best_score = 0
    best_config = None

    for period in periods:
        for variant in variants:
            for model in ("A", "B"):
                # Derive key values at crib positions
                residue_keys = {}  # residue -> set of implied key values
                consistent = True
                matches = 0

                for pt_pos in sorted(CRIB_SET):
                    ct_pos = inv[pt_pos]
                    ct_val = CT_NUM[ct_pos]
                    pt_val = CRIB_PT_NUM[pt_pos]

                    if variant == "vigenere":
                        k = (ct_val - pt_val) % MOD
                    elif variant == "beaufort":
                        k = (ct_val + pt_val) % MOD
                    else:
                        k = (pt_val - ct_val) % MOD

                    if model == "A":
                        residue = pt_pos % period
                    else:
                        residue = ct_pos % period

                    if residue not in residue_keys:
                        residue_keys[residue] = k
                        matches += 1
                    elif residue_keys[residue] == k:
                        matches += 1
                    # else: conflict, don't count

                if matches > best_score:
                    best_score = matches
                    best_config = {
                        "period": period,
                        "variant": variant,
                        "model": model,
                        "matches": matches,
                    }

    return best_score, best_config


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-10: Strip Manipulation + Periodic Substitution Scoring")
    print("=" * 70)
    print()

    results = {}
    all_top = []

    for strip_width in [5, 7, 8, 9, 10, 11, 13, 14, 16, 20]:
        print(f"\n{'='*60}")
        print(f"Strip Width = {strip_width}")
        print(f"{'='*60}")

        n_strips = math.ceil(CT_LEN / strip_width)
        total_configs = math.factorial(n_strips) * (2 ** n_strips)
        print(f"  Strips: {n_strips}, total configs: {total_configs:,.0f}")

        # Determine sampling strategy
        if total_configs <= 500_000:
            exhaustive = True
            n_tested = 0
        else:
            exhaustive = False
            n_target = 200_000

        bimodal_pass = 0
        bean_pass = {"vigenere": 0, "beaufort": 0, "variant_beaufort": 0}
        bimodal_and_bean = 0
        score_dist = Counter()
        top_results = []

        if exhaustive:
            # Enumerate all permutations of strips and all flip combinations
            for order in itertools.permutations(range(n_strips)):
                for flip_bits in range(2 ** n_strips):
                    flips = [(flip_bits >> i) & 1 for i in range(n_strips)]
                    perm = strip_perm(CT_LEN, strip_width, list(order), flips)
                    n_tested += 1

                    if not bimodal_check(perm):
                        continue
                    bimodal_pass += 1

                    # Check Bean for all variants
                    any_bean = False
                    for v in ("vigenere", "beaufort", "variant_beaufort"):
                        if check_bean(perm, v):
                            bean_pass[v] += 1
                            any_bean = True

                    if not any_bean:
                        continue
                    bimodal_and_bean += 1

                    # Score
                    score, config = score_perm_periodic(perm)
                    score_dist[score] += 1

                    if score >= 10:
                        top_results.append({
                            "strip_width": strip_width,
                            "order": list(order),
                            "flips": flips,
                            "score": score,
                            "config": config,
                        })

            mode = "exhaustive"
        else:
            # Random sampling
            n_tested = 0
            for _ in range(n_target):
                order = list(range(n_strips))
                random.shuffle(order)
                flips = [random.randint(0, 1) for _ in range(n_strips)]
                perm = strip_perm(CT_LEN, strip_width, order, flips)
                n_tested += 1

                if not bimodal_check(perm):
                    continue
                bimodal_pass += 1

                any_bean = False
                for v in ("vigenere", "beaufort", "variant_beaufort"):
                    if check_bean(perm, v):
                        bean_pass[v] += 1
                        any_bean = True

                if not any_bean:
                    continue
                bimodal_and_bean += 1

                score, config = score_perm_periodic(perm)
                score_dist[score] += 1

                if score >= 10:
                    top_results.append({
                        "strip_width": strip_width,
                        "order": list(order),
                        "flips": flips,
                        "score": score,
                        "config": config,
                    })

            mode = f"sampled ({n_target:,})"

        pct_bimodal = 100 * bimodal_pass / n_tested if n_tested > 0 else 0
        print(f"  Tested: {n_tested:,} ({mode})")
        print(f"  Bimodal pass: {bimodal_pass:,} ({pct_bimodal:.2f}%)")
        for v in ("vigenere", "beaufort", "variant_beaufort"):
            print(f"  Bean ({v[:4]}): {bean_pass[v]:,}")
        print(f"  Bimodal + Bean (any): {bimodal_and_bean:,}")

        if score_dist:
            print(f"  Score distribution (bimodal + Bean candidates):")
            for s in sorted(score_dist.keys(), reverse=True):
                print(f"    score={s:2d}: {score_dist[s]:,}")

        if top_results:
            top_results.sort(key=lambda x: -x["score"])
            print(f"  Top results (score >= 10):")
            for r in top_results[:5]:
                print(f"    score={r['score']}, order={r['order']}, "
                      f"flips={r['flips']}, config={r['config']}")

        results[strip_width] = {
            "n_tested": n_tested,
            "mode": mode,
            "bimodal_pass": bimodal_pass,
            "bean_pass": dict(bean_pass),
            "bimodal_and_bean": bimodal_and_bean,
            "score_dist": {str(k): v for k, v in score_dist.items()},
            "top_results": top_results[:20],
        }
        all_top.extend(top_results)

    # ── Random bimodal baseline ──────────────────────────────────────
    print()
    print("=" * 60)
    print("RANDOM BIMODAL-COMPATIBLE BASELINE")
    print("=" * 60)
    print("Generating random permutations that pass bimodal, then scoring...")

    random_bimodal_scores = Counter()
    n_random_bimodal = 0
    random_attempts = 0

    # Need bimodal-compatible random perms — these are rare (~0/1M from E-FRAC-09)
    # Use the local-swap method to generate them (since we know that works)
    while n_random_bimodal < 1000 and random_attempts < 10_000_000:
        # Use 30-50 local swaps with dist 3-10 to generate bimodal-ish perms
        n_swaps = random.randint(20, 50)
        max_dist = random.randint(3, 10)
        perm = list(range(CT_LEN))
        for _ in range(n_swaps):
            i = random.randint(0, CT_LEN - 1)
            j_min = max(0, i - max_dist)
            j_max = min(CT_LEN - 1, i + max_dist)
            j = random.randint(j_min, j_max)
            perm[i], perm[j] = perm[j], perm[i]
        random_attempts += 1

        if not bimodal_check(perm):
            continue

        # Check Bean for any variant
        bean_ok = False
        for v in ("vigenere", "beaufort", "variant_beaufort"):
            if check_bean(perm, v):
                bean_ok = True
                break
        if not bean_ok:
            continue

        score, _ = score_perm_periodic(perm)
        random_bimodal_scores[score] += 1
        n_random_bimodal += 1

        if n_random_bimodal % 200 == 0:
            print(f"  [{n_random_bimodal:,}] attempts={random_attempts:,}")

    print(f"\n  Generated {n_random_bimodal:,} bimodal+Bean random perms "
          f"(from {random_attempts:,} attempts)")
    if random_bimodal_scores:
        scores = []
        for s, c in random_bimodal_scores.items():
            scores.extend([s] * c)
        scores.sort()
        mean_score = sum(scores) / len(scores)
        max_score = max(scores)
        print(f"  Score distribution (random bimodal+Bean baseline):")
        for s in sorted(random_bimodal_scores.keys(), reverse=True):
            print(f"    score={s:2d}: {random_bimodal_scores[s]:,}")
        print(f"  Mean: {mean_score:.1f}, Max: {max_score}")

    # ── Grand summary ────────────────────────────────────────────────
    elapsed = time.time() - t0
    print()
    print("=" * 70)
    print("GRAND SUMMARY")
    print("=" * 70)

    if all_top:
        all_top.sort(key=lambda x: -x["score"])
        print(f"\nOverall top results across all strip widths (score >= 10):")
        for r in all_top[:20]:
            print(f"  w={r['strip_width']:2d}, score={r['score']}, "
                  f"order={r['order']}, flips={r['flips']}, "
                  f"config={r['config']}")
    else:
        print("\n  No results with score >= 10")

    # Noise floor
    if random_bimodal_scores:
        max_random = max(random_bimodal_scores.keys())
        print(f"\n  Random bimodal+Bean noise floor: max={max_random}/24, "
              f"mean={mean_score:.1f}/24")
        if all_top:
            best_strip = all_top[0]["score"]
            if best_strip > max_random:
                print(f"  SIGNAL: best strip score ({best_strip}) > noise floor ({max_random})")
            else:
                print(f"  NOISE: best strip score ({best_strip}) <= noise floor ({max_random})")

    print(f"\nTotal time: {elapsed:.1f}s")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-10",
        "description": "Strip manipulation + periodic substitution scoring",
        "results_by_width": {str(k): v for k, v in results.items()},
        "random_baseline": {
            "n_bimodal_bean": n_random_bimodal,
            "n_attempts": random_attempts,
            "score_dist": {str(k): v for k, v in random_bimodal_scores.items()},
        },
        "top_results": [r for r in all_top[:50]],
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_10_strip_bimodal.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
