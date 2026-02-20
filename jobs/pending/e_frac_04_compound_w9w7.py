#!/usr/bin/env python3
"""E-FRAC-04: Width-9 × Width-7 Compound Transposition.

Tests compound transpositions: apply two columnar transpositions in sequence.
- Model 1: σ = σ_7 ∘ σ_9 (first write into 9-wide grid, read columns,
  then write result into 7-wide grid, read columns)
- Model 2: σ = σ_9 ∘ σ_7 (7-wide first, then 9-wide)

The combined permutation is checked against periodic substitution at
periods 2-7 (only meaningful discriminators per CLAUDE.md).

Search space: 9! × 7! = 362,880 × 5,040 = 1.83 billion — too large
for exhaustive search. Strategy:
1. For width-9: sample 10,000 random orderings
2. For each width-9: test ALL 5,040 width-7 orderings
3. Bean pre-filter on combined permutation
4. Periodic consistency check at periods 2-7 only
5. Also test keyword-derived orderings from known Kryptos words

Total: 10,000 × 5,040 × 2 models × 3 variants × 6 periods = ~1.8 billion checks
With Bean filter: much less (~1.3-4% pass rate)

Usage: PYTHONPATH=src python3 -u jobs/pending/e_frac_04_compound_w9w7.py [--workers N]
"""
import argparse
import itertools
import json
import os
import random
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}


def build_columnar_perm(width, order):
    """Build gather permutation for columnar transposition of given width."""
    n_rows = CT_LEN // width
    remainder = CT_LEN % width
    col_heights = [n_rows + 1 if j < remainder else n_rows for j in range(width)]

    perm = []
    for c in range(width):
        col = order[c]
        height = col_heights[col]
        for row in range(height):
            perm.append(row * width + col)
    return perm


def compose_perms(perm_outer, perm_inner):
    """Compose two permutations: result[i] = perm_outer[perm_inner[i]]."""
    return [perm_outer[perm_inner[i]] for i in range(len(perm_inner))]


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean(combined_perm, variant):
    """Check Bean constraints on combined permutation, Model B."""
    inv = invert_perm(combined_perm)
    ct_27 = inv[27]
    ct_65 = inv[65]
    pt27 = CRIB_PT_NUM[27]
    pt65 = CRIB_PT_NUM[65]

    if variant == 0:
        k27 = (CT_NUM[ct_27] - pt27) % MOD
        k65 = (CT_NUM[ct_65] - pt65) % MOD
    elif variant == 1:
        k27 = (CT_NUM[ct_27] + pt27) % MOD
        k65 = (CT_NUM[ct_65] + pt65) % MOD
    else:
        k27 = (pt27 - CT_NUM[ct_27]) % MOD
        k65 = (pt65 - CT_NUM[ct_65]) % MOD

    if k27 != k65:
        return False

    for a, b in BEAN_INEQ:
        if a in CRIB_SET and b in CRIB_SET:
            ct_a = inv[a]
            ct_b = inv[b]
            if variant == 0:
                ka = (CT_NUM[ct_a] - CRIB_PT_NUM[a]) % MOD
                kb = (CT_NUM[ct_b] - CRIB_PT_NUM[b]) % MOD
            elif variant == 1:
                ka = (CT_NUM[ct_a] + CRIB_PT_NUM[a]) % MOD
                kb = (CT_NUM[ct_b] + CRIB_PT_NUM[b]) % MOD
            else:
                ka = (CRIB_PT_NUM[a] - CT_NUM[ct_a]) % MOD
                kb = (CRIB_PT_NUM[b] - CT_NUM[ct_b]) % MOD
            if ka == kb:
                return False
    return True


def strict_periodic_check(combined_perm, period, variant, model):
    """STRICT periodic check: ALL key values in each residue class must agree.

    Returns (all_consistent, n_constrained, n_conflicts).
    """
    residue_groups = defaultdict(set)

    for i, src in enumerate(combined_perm):
        if src in CRIB_SET:
            pt_val = CRIB_PT_NUM[src]
            ct_val = CT_NUM[i]
            if variant == 0:
                k = (ct_val - pt_val) % MOD
            elif variant == 1:
                k = (ct_val + pt_val) % MOD
            else:
                k = (pt_val - ct_val) % MOD

            if model == 0:  # A: key at PT position
                residue_groups[src % period].add(k)
            else:           # B: key at CT position
                residue_groups[i % period].add(k)

    n_constrained = sum(1 for vals in residue_groups.values() if vals)
    n_conflicts = sum(1 for vals in residue_groups.values() if len(vals) > 1)
    all_consistent = (n_conflicts == 0)

    return all_consistent, n_constrained, n_conflicts


def majority_score(combined_perm, period, variant, model):
    """Majority-voting score."""
    residue_groups = defaultdict(list)
    for i, src in enumerate(combined_perm):
        if src in CRIB_SET:
            pt_val = CRIB_PT_NUM[src]
            ct_val = CT_NUM[i]
            if variant == 0:
                k = (ct_val - pt_val) % MOD
            elif variant == 1:
                k = (ct_val + pt_val) % MOD
            else:
                k = (pt_val - ct_val) % MOD
            if model == 0:
                residue_groups[src % period].append(k)
            else:
                residue_groups[i % period].append(k)

    n_consistent = 0
    for vals in residue_groups.values():
        if vals:
            counts = Counter(vals)
            n_consistent += counts.most_common(1)[0][1]
    return n_consistent


def process_w9_batch(w9_orderings_batch):
    """Process a batch of width-9 orderings.

    For each, test all 5040 width-7 orderings in both composition orders.
    """
    VARIANT_NAMES = ["vigenere", "beaufort", "variant_beaufort"]
    PERIODS = list(range(2, 8))  # Only 2-7 (meaningful discriminators)
    w7_orderings = list(itertools.permutations(range(7)))

    batch_results = []
    batch_best = {"score": 0}

    for w9_order in w9_orderings_batch:
        w9_perm = build_columnar_perm(9, w9_order)

        for w7_order in w7_orderings:
            w7_perm = build_columnar_perm(7, w7_order)

            for composition in range(2):
                if composition == 0:
                    combined = compose_perms(w9_perm, w7_perm)  # σ9(σ7(x))
                else:
                    combined = compose_perms(w7_perm, w9_perm)  # σ7(σ9(x))

                for variant in range(3):
                    # Bean filter
                    if not check_bean(combined, variant):
                        continue

                    # Test periods 2-7 (strict check first)
                    for period in PERIODS:
                        for model in range(2):
                            passed, n_const, n_conf = strict_periodic_check(
                                combined, period, variant, model)

                            if passed and n_const >= 3:
                                # Also compute majority score
                                sc = majority_score(combined, period, variant, model)
                                if sc >= 12:  # Only record notable results
                                    result = {
                                        "w9": list(w9_order),
                                        "w7": list(w7_order),
                                        "comp": "w9(w7)" if composition == 0 else "w7(w9)",
                                        "variant": VARIANT_NAMES[variant],
                                        "period": period,
                                        "model": "A" if model == 0 else "B",
                                        "score": sc,
                                        "strict_pass": True,
                                        "n_constrained": n_const,
                                    }
                                    batch_results.append(result)
                                    if sc > batch_best["score"]:
                                        batch_best = result.copy()

                            elif n_conf <= 1:
                                # Near-pass: only 1 conflict
                                sc = majority_score(combined, period, variant, model)
                                if sc >= 14:
                                    result = {
                                        "w9": list(w9_order),
                                        "w7": list(w7_order),
                                        "comp": "w9(w7)" if composition == 0 else "w7(w9)",
                                        "variant": VARIANT_NAMES[variant],
                                        "period": period,
                                        "model": "A" if model == 0 else "B",
                                        "score": sc,
                                        "strict_pass": False,
                                        "n_conflicts": n_conf,
                                        "n_constrained": n_const,
                                    }
                                    batch_results.append(result)
                                    if sc > batch_best["score"]:
                                        batch_best = result.copy()

    return batch_results, batch_best


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--n-w9-samples", type=int, default=5000,
                        help="Number of random width-9 orderings to sample")
    parser.add_argument("--fast", action="store_true",
                        help="Sample 500 width-9 orderings for quick test")
    args = parser.parse_args()

    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-04: Width-9 × Width-7 Compound Transposition")
    print("=" * 70)

    n_w9 = 500 if args.fast else args.n_w9_samples
    print(f"Width-9 samples: {n_w9}")
    print(f"Width-7 orderings: 5,040 (exhaustive)")
    print(f"Compositions: 2 (σ9∘σ7 and σ7∘σ9)")
    print(f"Variants: 3, Models: 2, Periods: 2-7")
    print(f"Total checks (before Bean filter): "
          f"{n_w9 * 5040 * 2 * 3 * 2 * 6:,}")
    print(f"Workers: {args.workers}")
    print()

    # Generate width-9 orderings
    random.seed(42)
    all_w9 = list(itertools.permutations(range(9)))
    random.shuffle(all_w9)
    w9_samples = [all_w9[i] for i in range(n_w9)]

    # Also include keyword-derived orderings for width-9
    w9_keywords = ["KRYPTOSSA", "BERLINCLO", "PALIMPSST", "EASTNORTH",
                   "CLOCKWORK", "NORTHWEST", "NORTHEAST", "SOUTHEAST",
                   "SOUTHWEST", "LABYRINTR"]  # Padded to 9 chars
    for kw in w9_keywords:
        kw = kw[:9]
        if len(kw) < 9:
            continue
        order = tuple(sorted(range(9), key=lambda i: (kw[i], i)))
        if order not in set(w9_samples):
            w9_samples.append(order)

    print(f"Total w9 orderings (incl. keywords): {len(w9_samples)}")

    # Batch for parallel processing
    batch_size = max(1, len(w9_samples) // (args.workers * 10))
    batches = []
    for i in range(0, len(w9_samples), batch_size):
        batches.append(w9_samples[i:i + batch_size])

    all_results = []
    overall_best = {"score": 0}
    completed = 0
    last_report = t0

    if args.workers <= 1:
        for batch in batches:
            results, best = process_w9_batch(batch)
            all_results.extend(results)
            if best["score"] > overall_best.get("score", 0):
                overall_best = best
            completed += 1
            now = time.time()
            if now - last_report > 30:
                pct = 100 * completed / len(batches)
                elapsed = now - t0
                rate = completed / elapsed
                eta = (len(batches) - completed) / rate if rate > 0 else 0
                print(f"  [{pct:5.1f}%] {completed}/{len(batches)} batches, "
                      f"results={len(all_results)}, best={overall_best.get('score',0)}/24, "
                      f"ETA={eta:.0f}s")
                last_report = now
    else:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(process_w9_batch, batch): i
                       for i, batch in enumerate(batches)}
            for future in as_completed(futures):
                results, best = future.result()
                all_results.extend(results)
                if best.get("score", 0) > overall_best.get("score", 0):
                    overall_best = best
                completed += 1
                now = time.time()
                if now - last_report > 30:
                    pct = 100 * completed / len(batches)
                    elapsed = now - t0
                    rate = completed / elapsed
                    eta = (len(batches) - completed) / rate if rate > 0 else 0
                    print(f"  [{pct:5.1f}%] {completed}/{len(batches)} batches, "
                          f"results={len(all_results)}, best={overall_best.get('score',0)}/24, "
                          f"ETA={eta:.0f}s")
                    last_report = now

    elapsed = time.time() - t0

    # ── Results ──────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"Total w9 orderings sampled: {len(w9_samples)}")
    print(f"Total compound configs tested: {len(w9_samples) * 5040 * 2:,}")
    print(f"Results above threshold: {len(all_results)}")
    print(f"Time: {elapsed:.1f}s")
    print()

    if not all_results:
        print("NO results above threshold.")
        print("VERDICT: ELIMINATED — compound w9×w7 shows no signal at periods 2-7")
    else:
        all_results.sort(key=lambda r: r["score"], reverse=True)

        print("BEST OVERALL:")
        for k, v in overall_best.items():
            print(f"  {k}: {v}")
        print()

        # Distribution
        score_dist = Counter(r["score"] for r in all_results)
        print("SCORE DISTRIBUTION:")
        for sc in sorted(score_dist.keys(), reverse=True)[:10]:
            print(f"  {sc:2d}/24: {score_dist[sc]:,}")
        print()

        # Strict passes
        strict_results = [r for r in all_results if r.get("strict_pass")]
        print(f"STRICT PASSES (all residue classes consistent): {len(strict_results)}")
        for r in strict_results[:10]:
            print(f"  score={r['score']}/24 w9={r['w9']} w7={r['w7']} "
                  f"{r['comp']} p={r['period']} {r['variant']} "
                  f"model {r['model']}")
        print()

        # Top 10
        print("TOP 10:")
        for i, r in enumerate(all_results[:10]):
            print(f"  #{i+1}: {r['score']}/24 w9={r['w9']} w7={r['w7']} "
                  f"{r['comp']} p={r['period']} {r['variant']} "
                  f"model {r['model']} strict={r.get('strict_pass')}")

        # Verdict
        best_score = overall_best.get("score", 0)
        # At period <= 7, noise floor is ~8.2/24
        if best_score >= 18:
            verdict = "SIGNAL — investigate further"
        elif best_score >= 12:
            verdict = f"STORE — best {best_score}/24, interesting but not definitive"
        else:
            verdict = f"NOISE — best {best_score}/24, within expected range"
        print(f"\nVERDICT: {verdict}")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-04",
        "description": "Width-9 × width-7 compound transposition",
        "n_w9_samples": len(w9_samples),
        "n_w7": 5040,
        "n_results": len(all_results),
        "best_overall": overall_best if overall_best.get("score", 0) > 0 else None,
        "top_results": all_results[:100] if all_results else [],
        "elapsed_seconds": round(elapsed, 1),
    }
    if all_results:
        artifact["verdict"] = verdict
        artifact["score_distribution"] = dict(score_dist)

    path = "results/frac/e_frac_04_compound_w9w7.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")

    best = overall_best.get("score", 0)
    print(f"\nRESULT: best={best}/24 configs={len(w9_samples)*5040*2:,} "
          f"verdict={'SIGNAL' if best >= 18 else 'ELIMINATED' if best <= 8 else 'STORE'}")


if __name__ == "__main__":
    main()
