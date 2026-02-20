#!/usr/bin/env python3
"""E-FRAC-26: Exhaustive Width-9 Columnar with Quadgram Scoring.

Bridges BESPOKE's quadgram methodology (E-BESPOKE-28) with FRAC's exhaustive
width-9 coverage (E-FRAC-12). BESPOKE found that width-7 systematically fails
Bean among the top quadgram scorers. This experiment tests whether width-9 has
the same property — or shows better Bean compatibility.

For all 362,880 width-9 orderings × 3 variants × 5 periods (3-7):
1. Undo columnar transposition
2. Derive majority-vote periodic key from 24 crib positions
3. Decrypt all 97 characters using that key
4. Score plaintext with English quadgrams
5. Check Bean equality + 21 inequality constraints

Compared against width-7 exhaustive (5,040 orderings) for direct comparison.
"""
import itertools
import json
import math
import os
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

# ── Constants ─────────────────────────────────────────────────────────
CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
N_CRIB = len(CRIB_POS)  # 24


def load_quadgrams(path="data/english_quadgrams.json"):
    """Load quadgram log-probabilities. Returns dict and floor value."""
    with open(path) as f:
        qgrams = json.load(f)
    # Floor for unseen quadgrams: min observed - 1
    floor = min(qgrams.values()) - 1.0
    return qgrams, floor


QGRAMS, QFLOOR = load_quadgrams()


def quadgram_score(text):
    """Score a text string by average log-probability per character."""
    if len(text) < 4:
        return QFLOOR
    total = 0.0
    n = 0
    for i in range(len(text) - 3):
        qg = text[i:i + 4]
        total += QGRAMS.get(qg, QFLOOR)
        n += 1
    return total / n if n > 0 else QFLOOR


# ── Columnar transposition ───────────────────────────────────────────

def build_col_heights(width, length):
    """Column heights for incomplete last row."""
    n_rows = length // width
    remainder = length % width
    return [n_rows + 1 if j < remainder else n_rows for j in range(width)]


def build_columnar_perm(order, width, col_heights):
    """Build the permutation for columnar transposition decryption.

    Convention: perm[i] = position in CT that maps to PT position i.
    So PT[i] = CT[perm[i]].
    """
    # Columnar encryption: write PT row-by-row, read column-by-column in order.
    # perm[i] means: CT position i came from PT position perm[i].
    # For decryption we need the inverse.
    #
    # Actually, let's think carefully:
    # Encryption: PT written on grid row-by-row, columns read off in `order`.
    # CT[k] = PT[read_order[k]] where read_order gives column-order traversal.
    #
    # To undo: PT[read_order[k]] = CT[k], i.e., PT = apply inverse perm to CT.

    # Build the read-order permutation (encryption perm)
    enc_perm = []
    for c in order:
        height = col_heights[c]
        for row in range(height):
            enc_perm.append(row * width + c)

    # enc_perm[k] = PT position that was written to CT position k
    # So CT[k] = PT[enc_perm[k]]
    # To decrypt: PT[enc_perm[k]] = CT[k]
    # => PT[j] = CT[inv_enc[j]] where inv_enc is the inverse of enc_perm
    inv_perm = [0] * len(enc_perm)
    for k, pt_pos in enumerate(enc_perm):
        inv_perm[pt_pos] = k
    # inv_perm[j] = CT position that maps to PT position j
    # PT[j] = CT[inv_perm[j]]
    return inv_perm


def derive_key_and_decrypt(inv_perm, variant, period):
    """Derive periodic key from cribs via majority vote, then decrypt.

    Returns (crib_score, key, plaintext_string, bean_pass).
    """
    # Compute key value at each crib position
    residue_keys = defaultdict(list)
    residue_positions = defaultdict(list)

    for pt_pos in CRIB_POS:
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]

        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        else:  # variant_beaufort
            k = (pt_val - ct_val) % MOD

        residue = pt_pos % period
        residue_keys[residue].append(k)
        residue_positions[residue].append(pt_pos)

    # Majority vote per residue
    key = [0] * period
    crib_score = 0
    for r in range(period):
        keys = residue_keys.get(r, [])
        if not keys:
            key[r] = 0
            continue
        counts = Counter(keys)
        best_val, best_count = counts.most_common(1)[0]
        key[r] = best_val
        crib_score += best_count

    # Decrypt all 97 characters
    pt_nums = [0] * CT_LEN
    for j in range(CT_LEN):
        ct_pos = inv_perm[j]
        ct_val = CT_NUM[ct_pos]
        k = key[j % period]

        if variant == "vigenere":
            pt_nums[j] = (ct_val - k) % MOD
        elif variant == "beaufort":
            pt_nums[j] = (k - ct_val) % MOD
        else:  # variant_beaufort
            pt_nums[j] = (ct_val + k) % MOD

    pt_text = "".join(ALPH[v] for v in pt_nums)

    # Bean check using the derived key at crib positions
    def key_at_crib(pt_pos):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            return (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            return (ct_val + pt_val) % MOD
        else:
            return (pt_val - ct_val) % MOD

    bean_pass = True
    for eq_a, eq_b in BEAN_EQ:
        if key_at_crib(eq_a) != key_at_crib(eq_b):
            bean_pass = False
            break

    if bean_pass:
        for ineq_a, ineq_b in BEAN_INEQ:
            if key_at_crib(ineq_a) == key_at_crib(ineq_b):
                bean_pass = False
                break

    return crib_score, key, pt_text, bean_pass


def evaluate_ordering(inv_perm, variants, periods):
    """Evaluate one ordering across all variants × periods.

    Returns list of result dicts, sorted by quadgram score descending.
    """
    results = []
    for variant in variants:
        for period in periods:
            crib_score, key, pt_text, bean_pass = derive_key_and_decrypt(
                inv_perm, variant, period
            )
            q_score = quadgram_score(pt_text)
            results.append({
                "variant": variant,
                "period": period,
                "crib_score": crib_score,
                "quadgram": q_score,
                "bean_pass": bean_pass,
                "key": key,
                "plaintext": pt_text,
            })
    results.sort(key=lambda r: -r["quadgram"])
    return results


def run_width(width, max_orderings=None, sample_seed=None):
    """Run exhaustive (or sampled) search for a given width.

    Returns (all_results, stats) where all_results is a list of the top
    results and stats is a summary dict.
    """
    variants = ["vigenere", "beaufort", "variant_beaufort"]
    periods = [3, 4, 5, 6, 7]
    col_heights = build_col_heights(width, CT_LEN)

    n_perms = math.factorial(width)
    exhaustive = max_orderings is None or max_orderings >= n_perms

    if exhaustive:
        orderings = itertools.permutations(range(width))
        n_total = n_perms
    else:
        rng = random.Random(sample_seed or 42)
        orderings_list = []
        for _ in range(max_orderings):
            order = list(range(width))
            rng.shuffle(order)
            orderings_list.append(tuple(order))
        orderings = orderings_list
        n_total = max_orderings

    # Track top results
    top_any = []       # top by quadgram, any constraint status
    top_bean = []      # top by quadgram with Bean pass
    top_crib = []      # top by crib score

    # Statistics
    n_tested = 0
    n_bean_pass = 0
    crib_dist = Counter()
    bean_quadgrams = []
    all_quadgrams = []

    t0 = time.time()
    last_report = t0

    for order in orderings:
        order = tuple(order)
        inv_perm = build_columnar_perm(order, width, col_heights)
        results = evaluate_ordering(inv_perm, variants, periods)
        n_tested += 1

        # Best quadgram result for this ordering
        best = results[0]  # sorted by quadgram desc
        all_quadgrams.append(best["quadgram"])

        # Best crib result
        best_crib = max(results, key=lambda r: r["crib_score"])
        crib_dist[best_crib["crib_score"]] += 1

        # Track Bean-passing results
        for r in results:
            if r["bean_pass"]:
                n_bean_pass += 1
                bean_quadgrams.append(r["quadgram"])
                # Keep top 100 Bean-passing
                top_bean.append({
                    "order": list(order),
                    "variant": r["variant"],
                    "period": r["period"],
                    "crib_score": r["crib_score"],
                    "quadgram": round(r["quadgram"], 4),
                    "plaintext": r["plaintext"][:50],
                    "key": r["key"],
                })
                if len(top_bean) > 200:
                    top_bean.sort(key=lambda x: -x["quadgram"])
                    top_bean = top_bean[:100]

        # Track top any
        top_any.append({
            "order": list(order),
            "variant": best["variant"],
            "period": best["period"],
            "crib_score": best["crib_score"],
            "quadgram": round(best["quadgram"], 4),
            "bean_pass": best["bean_pass"],
            "plaintext": best["plaintext"][:50],
        })
        if len(top_any) > 200:
            top_any.sort(key=lambda x: -x["quadgram"])
            top_any = top_any[:100]

        # Track top crib
        top_crib.append({
            "order": list(order),
            "variant": best_crib["variant"],
            "period": best_crib["period"],
            "crib_score": best_crib["crib_score"],
            "quadgram": round(best_crib["quadgram"], 4),
            "bean_pass": best_crib["bean_pass"],
        })
        if len(top_crib) > 200:
            top_crib.sort(key=lambda x: -x["crib_score"])
            top_crib = top_crib[:100]

        now = time.time()
        if now - last_report > 30:
            pct = 100 * n_tested / n_total
            best_q = max(all_quadgrams)
            print(f"  w={width} [{pct:5.1f}%] tested={n_tested:,}/{n_total:,}, "
                  f"best_q={best_q:.3f}, bean_pass={n_bean_pass:,}")
            last_report = now

    elapsed = time.time() - t0

    # Finalize
    top_any.sort(key=lambda x: -x["quadgram"])
    top_any = top_any[:50]
    top_bean.sort(key=lambda x: -x["quadgram"])
    top_bean = top_bean[:50]
    top_crib.sort(key=lambda x: -x["crib_score"])
    top_crib = top_crib[:50]

    all_quadgrams.sort(reverse=True)
    bean_quadgrams.sort(reverse=True)

    stats = {
        "width": width,
        "n_tested": n_tested,
        "exhaustive": exhaustive,
        "n_configs": n_tested * len(variants) * len(periods),
        "n_bean_pass": n_bean_pass,
        "bean_pass_rate": round(n_bean_pass / (n_tested * len(variants) * len(periods)), 6),
        "best_quadgram_any": round(all_quadgrams[0], 4) if all_quadgrams else None,
        "best_quadgram_bean": round(bean_quadgrams[0], 4) if bean_quadgrams else None,
        "mean_quadgram": round(sum(all_quadgrams) / len(all_quadgrams), 4) if all_quadgrams else None,
        "mean_bean_quadgram": round(sum(bean_quadgrams) / len(bean_quadgrams), 4) if bean_quadgrams else None,
        "best_crib_score": max(crib_dist.keys()) if crib_dist else 0,
        "crib_dist": {str(k): v for k, v in sorted(crib_dist.items(), reverse=True)},
        "elapsed_seconds": round(elapsed, 1),
    }

    return top_any, top_bean, top_crib, stats


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-26: Exhaustive Width-9 Columnar with Quadgram Scoring")
    print("=" * 70)
    print()
    print("Extends BESPOKE's quadgram methodology (E-BESPOKE-28) to width-9.")
    print("BESPOKE found: width-7 produces ZERO Bean-passing results in top 15")
    print("by quadgram. Does width-9 show better Bean compatibility?")
    print()

    # ── Part 1: Exhaustive width-9 ─────────────────────────────────
    print("Part 1: Exhaustive Width-9 (362,880 orderings × 3 variants × 5 periods)")
    print("-" * 60)
    top_any_9, top_bean_9, top_crib_9, stats_9 = run_width(9)

    print(f"\n  Width-9 results:")
    print(f"    Configs: {stats_9['n_configs']:,}")
    print(f"    Best quadgram (any): {stats_9['best_quadgram_any']}")
    print(f"    Best quadgram (Bean): {stats_9['best_quadgram_bean']}")
    print(f"    Mean quadgram: {stats_9['mean_quadgram']}")
    print(f"    Bean-passing configs: {stats_9['n_bean_pass']:,} ({100*stats_9['bean_pass_rate']:.2f}%)")
    print(f"    Best crib score: {stats_9['best_crib_score']}")
    print(f"    Time: {stats_9['elapsed_seconds']}s")

    print(f"\n  Top 15 by quadgram (any):")
    for i, r in enumerate(top_any_9[:15]):
        bean_str = "PASS" if r.get("bean_pass") else "FAIL"
        print(f"    {i+1:2d}. q={r['quadgram']:.4f} crib={r['crib_score']:2d}/24 "
              f"Bean={bean_str} {r['variant'][:4]} p={r['period']} "
              f"order={r['order']}")
        print(f"        PT: {r['plaintext']}")

    print(f"\n  Top 15 by quadgram (Bean-passing only):")
    if top_bean_9:
        for i, r in enumerate(top_bean_9[:15]):
            print(f"    {i+1:2d}. q={r['quadgram']:.4f} crib={r['crib_score']:2d}/24 "
                  f"{r['variant'][:4]} p={r['period']} "
                  f"order={r['order']}")
            print(f"        PT: {r['plaintext']}")
    else:
        print("    (no Bean-passing results)")

    # ── Part 2: Exhaustive width-7 (for comparison) ───────────────
    print()
    print("Part 2: Exhaustive Width-7 (5,040 orderings × 3 variants × 5 periods)")
    print("-" * 60)
    top_any_7, top_bean_7, top_crib_7, stats_7 = run_width(7)

    print(f"\n  Width-7 results:")
    print(f"    Configs: {stats_7['n_configs']:,}")
    print(f"    Best quadgram (any): {stats_7['best_quadgram_any']}")
    print(f"    Best quadgram (Bean): {stats_7['best_quadgram_bean']}")
    print(f"    Mean quadgram: {stats_7['mean_quadgram']}")
    print(f"    Bean-passing configs: {stats_7['n_bean_pass']:,} ({100*stats_7['bean_pass_rate']:.2f}%)")
    print(f"    Best crib score: {stats_7['best_crib_score']}")
    print(f"    Time: {stats_7['elapsed_seconds']}s")

    print(f"\n  Top 15 by quadgram (any):")
    for i, r in enumerate(top_any_7[:15]):
        bean_str = "PASS" if r.get("bean_pass") else "FAIL"
        print(f"    {i+1:2d}. q={r['quadgram']:.4f} crib={r['crib_score']:2d}/24 "
              f"Bean={bean_str} {r['variant'][:4]} p={r['period']} "
              f"order={r['order']}")

    print(f"\n  Top 15 by quadgram (Bean-passing only):")
    if top_bean_7:
        for i, r in enumerate(top_bean_7[:15]):
            print(f"    {i+1:2d}. q={r['quadgram']:.4f} crib={r['crib_score']:2d}/24 "
                  f"{r['variant'][:4]} p={r['period']} "
                  f"order={r['order']}")
    else:
        print("    (no Bean-passing results)")

    # ── Part 3: Width comparison ──────────────────────────────────
    print()
    print("Part 3: Width-7 vs Width-9 Comparison")
    print("-" * 60)

    print(f"\n  {'Metric':<35s}  {'Width-7':>12s}  {'Width-9':>12s}")
    print(f"  {'-'*35}  {'-'*12}  {'-'*12}")
    print(f"  {'Orderings tested':<35s}  {stats_7['n_tested']:>12,}  {stats_9['n_tested']:>12,}")
    print(f"  {'Total configs':<35s}  {stats_7['n_configs']:>12,}  {stats_9['n_configs']:>12,}")
    print(f"  {'Bean-passing configs':<35s}  {stats_7['n_bean_pass']:>12,}  {stats_9['n_bean_pass']:>12,}")
    print(f"  {'Bean pass rate':<35s}  {100*stats_7['bean_pass_rate']:>11.2f}%  {100*stats_9['bean_pass_rate']:>11.2f}%")
    print(f"  {'Best quadgram (any)':<35s}  {stats_7['best_quadgram_any']:>12.4f}  {stats_9['best_quadgram_any']:>12.4f}")
    bq7 = stats_7['best_quadgram_bean']
    bq9 = stats_9['best_quadgram_bean']
    bq7_str = f"{bq7:.4f}" if bq7 is not None else "N/A"
    bq9_str = f"{bq9:.4f}" if bq9 is not None else "N/A"
    print(f"  {'Best quadgram (Bean-passing)':<35s}  {bq7_str:>12s}  {bq9_str:>12s}")
    print(f"  {'Mean quadgram':<35s}  {stats_7['mean_quadgram']:>12.4f}  {stats_9['mean_quadgram']:>12.4f}")
    mq7 = stats_7.get('mean_bean_quadgram')
    mq9 = stats_9.get('mean_bean_quadgram')
    mq7_str = f"{mq7:.4f}" if mq7 is not None else "N/A"
    mq9_str = f"{mq9:.4f}" if mq9 is not None else "N/A"
    print(f"  {'Mean Bean quadgram':<35s}  {mq7_str:>12s}  {mq9_str:>12s}")
    print(f"  {'Best crib score':<35s}  {stats_7['best_crib_score']:>12d}  {stats_9['best_crib_score']:>12d}")

    # Bean in top-N analysis
    for n_top in [15, 50]:
        n_bean_7 = sum(1 for r in top_any_7[:n_top] if r.get("bean_pass"))
        n_bean_9 = sum(1 for r in top_any_9[:n_top] if r.get("bean_pass"))
        print(f"  {'Bean passes in top-' + str(n_top) + ' by quadgram':<35s}  {n_bean_7:>12d}  {n_bean_9:>12d}")

    # ── Part 4: Random baseline ───────────────────────────────────
    print()
    print("Part 4: Random Permutation Baseline")
    print("-" * 60)

    variants = ["vigenere", "beaufort", "variant_beaufort"]
    periods = [3, 4, 5, 6, 7]
    rng = random.Random(42)
    N_RANDOM = 10_000
    random_quadgrams = []
    random_bean_quadgrams = []
    n_random_bean = 0

    for trial in range(N_RANDOM):
        perm = list(range(CT_LEN))
        rng.shuffle(perm)
        # perm is a random permutation. Use it as inv_perm (PT[j] = CT[perm[j]])
        results = evaluate_ordering(perm, variants, periods)
        best = results[0]
        random_quadgrams.append(best["quadgram"])
        for r in results:
            if r["bean_pass"]:
                n_random_bean += 1
                random_bean_quadgrams.append(r["quadgram"])

        if (trial + 1) % 2000 == 0:
            print(f"  Random: {trial+1}/{N_RANDOM}")

    random_quadgrams.sort(reverse=True)
    random_bean_quadgrams.sort(reverse=True)

    p95 = random_quadgrams[int(0.05 * len(random_quadgrams))]
    p99 = random_quadgrams[int(0.01 * len(random_quadgrams))]
    rand_mean = sum(random_quadgrams) / len(random_quadgrams)

    print(f"\n  Random baseline (N={N_RANDOM:,}):")
    print(f"    Best quadgram: {random_quadgrams[0]:.4f}")
    print(f"    95th percentile: {p95:.4f}")
    print(f"    99th percentile: {p99:.4f}")
    print(f"    Mean: {rand_mean:.4f}")
    print(f"    Bean-passing configs: {n_random_bean:,}")
    if random_bean_quadgrams:
        print(f"    Best Bean quadgram: {random_bean_quadgrams[0]:.4f}")

    # p-values
    bq9_val = stats_9['best_quadgram_any']
    n_rand_better = sum(1 for q in random_quadgrams if q >= bq9_val)
    pval_any = n_rand_better / N_RANDOM
    print(f"\n  p-value (width-9 best vs random): {pval_any:.4f} "
          f"({n_rand_better}/{N_RANDOM} random >= {bq9_val:.4f})")

    if bq9 is not None and random_bean_quadgrams:
        n_bean_better = sum(1 for q in random_bean_quadgrams if q >= bq9)
        pval_bean = n_bean_better / len(random_bean_quadgrams) if random_bean_quadgrams else 1.0
        print(f"  p-value (width-9 Bean best vs random Bean): {pval_bean:.4f}")

    # ── Verdict ───────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("VERDICT")
    print("=" * 70)

    # Determine verdict
    if bq9 is not None and bq9 > -6.0:
        verdict = "SIGNAL"
        verdict_detail = (f"Width-9 Bean-passing quadgram {bq9:.4f} exceeds "
                         f"-6.0 threshold")
    elif bq9 is not None and bq9 > -7.0:
        verdict = "STORE"
        verdict_detail = (f"Width-9 Bean-passing quadgram {bq9:.4f} is marginal "
                         f"(between -7.0 and -6.0)")
    elif bq9 is None:
        verdict = "ELIMINATED"
        verdict_detail = "Width-9 produces ZERO Bean-passing results"
    else:
        verdict = "ELIMINATED"
        verdict_detail = (f"Width-9 Bean-passing quadgram {bq9:.4f} is below "
                         f"-7.0 threshold (noise)")

    print(f"\n  {verdict}: {verdict_detail}")
    print()

    # Bean-in-top comparison summary
    n_bean_top15_7 = sum(1 for r in top_any_7[:15] if r.get("bean_pass"))
    n_bean_top15_9 = sum(1 for r in top_any_9[:15] if r.get("bean_pass"))
    if n_bean_top15_9 > n_bean_top15_7:
        print(f"  Width-9 has MORE Bean passes in top-15 quadgram ({n_bean_top15_9} vs {n_bean_top15_7}).")
        print(f"  Width-9 shows better Bean-quadgram compatibility than width-7.")
    elif n_bean_top15_9 == n_bean_top15_7:
        print(f"  Width-9 and width-7 have EQUAL Bean passes in top-15 quadgram ({n_bean_top15_9}).")
    else:
        print(f"  Width-9 has FEWER Bean passes in top-15 quadgram ({n_bean_top15_9} vs {n_bean_top15_7}).")
        print(f"  Width-9 shows WORSE Bean-quadgram compatibility than width-7.")

    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")

    # ── Save artifacts ────────────────────────────────────────────
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-26",
        "description": "Exhaustive width-9 columnar with quadgram scoring, compared to width-7",
        "width_9": {
            "stats": stats_9,
            "top_any_15": top_any_9[:15],
            "top_bean_15": top_bean_9[:15],
            "top_crib_10": top_crib_9[:10],
        },
        "width_7": {
            "stats": stats_7,
            "top_any_15": top_any_7[:15],
            "top_bean_15": top_bean_7[:15],
            "top_crib_10": top_crib_7[:10],
        },
        "random_baseline": {
            "n_samples": N_RANDOM,
            "best_quadgram": round(random_quadgrams[0], 4),
            "p95": round(p95, 4),
            "p99": round(p99, 4),
            "mean": round(rand_mean, 4),
            "n_bean_pass": n_random_bean,
            "best_bean_quadgram": round(random_bean_quadgrams[0], 4) if random_bean_quadgrams else None,
        },
        "comparison": {
            "bean_top15_w7": n_bean_top15_7,
            "bean_top15_w9": n_bean_top15_9,
            "pval_w9_any": round(pval_any, 4),
        },
        "verdict": verdict,
        "verdict_detail": verdict_detail,
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_26_w9_quadgram.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")
    print(f"\nRESULT: best_bean_q={bq9} best_any_q={stats_9['best_quadgram_any']} "
          f"bean_configs={stats_9['n_bean_pass']} verdict={verdict}")


if __name__ == "__main__":
    main()
