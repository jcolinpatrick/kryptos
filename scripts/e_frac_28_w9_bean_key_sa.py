#!/usr/bin/env python3
"""E-FRAC-28: SA Key Optimization on Bean-Passing Width-9 Orderings.

E-FRAC-26 found: width-9 has 67K Bean-passing configs using majority-vote keys,
with best quadgram -6.238. But majority vote only tests ONE key per period.
The 26^p key space is much larger.

This experiment:
1. Finds the top 50 Bean-passing width-9 orderings by quadgram (from E-FRAC-26)
2. For each: runs SA over key values to maximize quadgram fitness
3. Bean equality enforced as a HARD constraint throughout
4. Tests wider period range (3-13) since quadgram scoring helps with underdetermination

If the cipher IS width-9 columnar + periodic substitution, this should produce
readable English (quadgram ~ -4.3). If it doesn't, the substitution is non-periodic
or the transposition isn't width-9 columnar.

Also includes width-8 top orderings for comparison (width-8 had highest full
Bean pass rate at 2.49%).
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

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def load_quadgrams(path="data/english_quadgrams.json"):
    with open(path) as f:
        qgrams = json.load(f)
    floor = min(qgrams.values()) - 1.0
    return qgrams, floor


QGRAMS, QFLOOR = load_quadgrams()


def quadgram_score(text):
    if len(text) < 4:
        return QFLOOR
    total = 0.0
    n = 0
    for i in range(len(text) - 3):
        qg = text[i:i + 4]
        total += QGRAMS.get(qg, QFLOOR)
        n += 1
    return total / n if n > 0 else QFLOOR


def build_col_heights(width, length):
    n_rows = length // width
    remainder = length % width
    return [n_rows + 1 if j < remainder else n_rows for j in range(width)]


def build_columnar_inv_perm(order, width, col_heights):
    enc_perm = []
    for c in order:
        height = col_heights[c]
        for row in range(height):
            enc_perm.append(row * width + c)
    inv_perm = [0] * len(enc_perm)
    for k, pt_pos in enumerate(enc_perm):
        inv_perm[pt_pos] = k
    return inv_perm


def check_bean_full(inv_perm, variant):
    """Check Bean equality + all 21 inequalities."""
    def key_at(pt_pos):
        ct_val = CT_NUM[inv_perm[pt_pos]]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            return (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            return (ct_val + pt_val) % MOD
        else:
            return (pt_val - ct_val) % MOD

    for eq_a, eq_b in BEAN_EQ:
        if key_at(eq_a) != key_at(eq_b):
            return False
    for ineq_a, ineq_b in BEAN_INEQ:
        if key_at(ineq_a) == key_at(ineq_b):
            return False
    return True


def derive_majority_key(inv_perm, variant, period):
    """Derive majority-vote periodic key from cribs."""
    residue_keys = defaultdict(list)
    for pt_pos in CRIB_POS:
        ct_val = CT_NUM[inv_perm[pt_pos]]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        else:
            k = (pt_val - ct_val) % MOD
        residue_keys[pt_pos % period].append(k)

    key = [0] * period
    crib_score = 0
    for r in range(period):
        keys = residue_keys.get(r, [])
        if not keys:
            continue
        counts = Counter(keys)
        best_val, best_count = counts.most_common(1)[0]
        key[r] = best_val
        crib_score += best_count
    return key, crib_score


def decrypt_with_key(inv_perm, variant, key):
    """Decrypt full 97 chars using periodic key."""
    period = len(key)
    pt_nums = [0] * CT_LEN
    for j in range(CT_LEN):
        ct_val = CT_NUM[inv_perm[j]]
        k = key[j % period]
        if variant == "vigenere":
            pt_nums[j] = (ct_val - k) % MOD
        elif variant == "beaufort":
            pt_nums[j] = (k - ct_val) % MOD
        else:
            pt_nums[j] = (ct_val + k) % MOD
    return "".join(ALPH[v] for v in pt_nums)


def count_crib_matches(inv_perm, variant, key):
    """Count how many crib positions match with this key."""
    period = len(key)
    matches = 0
    for pt_pos in CRIB_POS:
        ct_val = CT_NUM[inv_perm[pt_pos]]
        k = key[pt_pos % period]
        if variant == "vigenere":
            pt_val = (ct_val - k) % MOD
        elif variant == "beaufort":
            pt_val = (k - ct_val) % MOD
        else:
            pt_val = (ct_val + k) % MOD
        if pt_val == CRIB_PT_NUM[pt_pos]:
            matches += 1
    return matches


def sa_key_optimize(inv_perm, variant, period, initial_key,
                    n_steps=30000, t_start=2.0, t_end=0.01, rng=None):
    """Simulated annealing on key values to maximize quadgram score."""
    if rng is None:
        rng = random.Random()

    key = list(initial_key)
    pt = decrypt_with_key(inv_perm, variant, key)
    score = quadgram_score(pt)
    best_key = list(key)
    best_score = score
    best_pt = pt

    for step in range(n_steps):
        t = t_start * (t_end / t_start) ** (step / n_steps)

        # Mutate: change one key position
        pos = rng.randint(0, period - 1)
        old_val = key[pos]
        new_val = (old_val + rng.randint(1, 25)) % MOD
        key[pos] = new_val

        pt = decrypt_with_key(inv_perm, variant, key)
        new_score = quadgram_score(pt)

        delta = new_score - score
        if delta > 0 or rng.random() < math.exp(delta / t):
            score = new_score
            if score > best_score:
                best_score = score
                best_key = list(key)
                best_pt = pt
        else:
            key[pos] = old_val

    return best_key, best_score, best_pt


def find_top_bean_orderings(width, n_top, variants, periods):
    """Find top Bean-passing orderings by quadgram score."""
    col_heights = build_col_heights(width, CT_LEN)
    n_perms = math.factorial(width)

    results = []
    n_tested = 0
    t0 = time.time()
    last_report = t0

    for order in itertools.permutations(range(width)):
        inv_perm = build_columnar_inv_perm(tuple(order), width, col_heights)
        n_tested += 1

        for variant in variants:
            if not check_bean_full(inv_perm, variant):
                continue

            for period in periods:
                key, crib_score = derive_majority_key(inv_perm, variant, period)
                pt = decrypt_with_key(inv_perm, variant, key)
                q = quadgram_score(pt)

                results.append({
                    "order": list(order),
                    "variant": variant,
                    "period": period,
                    "key": key,
                    "crib_score": crib_score,
                    "quadgram": q,
                })

                if len(results) > n_top * 3:
                    results.sort(key=lambda x: -x["quadgram"])
                    results = results[:n_top * 2]

        now = time.time()
        if now - last_report > 30:
            pct = 100 * n_tested / n_perms
            print(f"    [{pct:5.1f}%] tested={n_tested:,}/{n_perms:,}, "
                  f"bean_results={len(results):,}")
            last_report = now

    results.sort(key=lambda x: -x["quadgram"])
    elapsed = time.time() - t0
    print(f"    Done: {n_tested:,} orderings, {len(results):,} Bean-passing configs "
          f"in {elapsed:.1f}s")
    return results[:n_top]


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-28: SA Key Optimization on Bean-Passing Orderings")
    print("=" * 70)
    print()

    variants = ["vigenere", "beaufort", "variant_beaufort"]
    scan_periods = [3, 4, 5, 6, 7]
    sa_periods = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

    # ── Part 1: Find top Bean-passing width-9 orderings ──────────
    print("Part 1: Find top 50 Bean-passing width-9 orderings (exhaustive)")
    print("-" * 60)
    top_w9 = find_top_bean_orderings(9, 50, variants, scan_periods)

    print(f"\n  Top 10 Bean-passing width-9 orderings (majority-vote key):")
    for i, r in enumerate(top_w9[:10]):
        print(f"    {i+1:2d}. q={r['quadgram']:.4f} crib={r['crib_score']:2d}/24 "
              f"{r['variant'][:4]} p={r['period']} order={r['order']}")

    # ── Part 2: Find top Bean-passing width-8 orderings ──────────
    print()
    print("Part 2: Find top 50 Bean-passing width-8 orderings (exhaustive)")
    print("-" * 60)
    top_w8 = find_top_bean_orderings(8, 50, variants, scan_periods)

    print(f"\n  Top 10 Bean-passing width-8 orderings (majority-vote key):")
    for i, r in enumerate(top_w8[:10]):
        print(f"    {i+1:2d}. q={r['quadgram']:.4f} crib={r['crib_score']:2d}/24 "
              f"{r['variant'][:4]} p={r['period']} order={r['order']}")

    # ── Part 3: SA key optimization on top orderings ─────────────
    print()
    print("Part 3: SA Key Optimization")
    print("-" * 60)
    print()

    all_sa_results = []
    rng = random.Random(42)

    for width, top_list, label in [(9, top_w9, "width-9"), (8, top_w8, "width-8")]:
        col_heights = build_col_heights(width, CT_LEN)
        print(f"  {label}: SA on top {len(top_list)} Bean-passing orderings")
        print(f"  Testing periods: {sa_periods}")
        print()

        sa_results_for_width = []

        for idx, base in enumerate(top_list[:30]):  # Top 30 orderings
            order = tuple(base["order"])
            inv_perm = build_columnar_inv_perm(order, width, col_heights)

            best_sa_q = -999
            best_sa_result = None

            for variant in variants:
                if not check_bean_full(inv_perm, variant):
                    continue

                for period in sa_periods:
                    # Start with majority-vote key
                    init_key, init_crib = derive_majority_key(inv_perm, variant, period)

                    # Run SA with 3 restarts
                    for restart in range(3):
                        if restart == 0:
                            start_key = list(init_key)
                        else:
                            # Random restart: perturb the majority key
                            start_key = [(k + rng.randint(0, 5)) % MOD for k in init_key]

                        sa_key, sa_q, sa_pt = sa_key_optimize(
                            inv_perm, variant, period, start_key,
                            n_steps=20000, rng=random.Random(rng.randint(0, 2**31))
                        )

                        crib_matches = count_crib_matches(inv_perm, variant, sa_key)

                        if sa_q > best_sa_q:
                            best_sa_q = sa_q
                            best_sa_result = {
                                "width": width,
                                "order": list(order),
                                "variant": variant,
                                "period": period,
                                "sa_key": sa_key,
                                "sa_quadgram": round(sa_q, 4),
                                "sa_crib_score": crib_matches,
                                "plaintext": sa_pt[:80],
                                "base_quadgram": round(base["quadgram"], 4),
                                "base_crib_score": base["crib_score"],
                            }

            if best_sa_result:
                sa_results_for_width.append(best_sa_result)
                all_sa_results.append(best_sa_result)

            if (idx + 1) % 10 == 0:
                print(f"    {label}: {idx+1}/{min(30, len(top_list))} orderings done, "
                      f"best_sa_q={best_sa_q:.4f}")

        # Report for this width
        sa_results_for_width.sort(key=lambda r: -r["sa_quadgram"])
        print(f"\n  {label} SA results (top 15):")
        for i, r in enumerate(sa_results_for_width[:15]):
            improvement = r["sa_quadgram"] - r["base_quadgram"]
            print(f"    {i+1:2d}. q={r['sa_quadgram']:.4f} (Δ={improvement:+.4f}) "
                  f"crib={r['sa_crib_score']:2d}/24 "
                  f"{r['variant'][:4]} p={r['period']} order={r['order']}")
            print(f"        PT: {r['plaintext']}")
        print()

    # ── Part 4: Cross-width comparison ───────────────────────────
    print()
    print("Part 4: Cross-Width SA Comparison")
    print("-" * 60)

    all_sa_results.sort(key=lambda r: -r["sa_quadgram"])

    print(f"\n  Overall top 20 SA results:")
    for i, r in enumerate(all_sa_results[:20]):
        print(f"    {i+1:2d}. w={r['width']} q={r['sa_quadgram']:.4f} "
              f"crib={r['sa_crib_score']:2d}/24 "
              f"{r['variant'][:4]} p={r['period']} order={r['order']}")
        print(f"        PT: {r['plaintext']}")

    # Statistics by width
    for width in [8, 9]:
        width_results = [r for r in all_sa_results if r["width"] == width]
        if width_results:
            qs = [r["sa_quadgram"] for r in width_results]
            print(f"\n  Width-{width}: best={max(qs):.4f}, mean={sum(qs)/len(qs):.4f}, "
                  f"N={len(width_results)}")

    # ── Verdict ───────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("VERDICT")
    print("=" * 70)

    best = all_sa_results[0] if all_sa_results else None
    if best:
        if best["sa_quadgram"] > -5.0:
            verdict = "SIGNAL"
            detail = f"SA produced near-English quadgram: {best['sa_quadgram']:.4f}"
        elif best["sa_quadgram"] > -5.5:
            verdict = "STORE"
            detail = (f"SA quadgram {best['sa_quadgram']:.4f} is promising but not English "
                     f"(threshold: -5.0)")
        else:
            verdict = "NOISE"
            detail = (f"SA quadgram {best['sa_quadgram']:.4f} is far from English (-4.3). "
                     f"Periodic key + columnar at these widths does NOT produce readable text.")
    else:
        verdict = "ELIMINATED"
        detail = "No Bean-passing results to optimize"

    print(f"\n  {verdict}: {detail}")

    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")

    # ── Save artifacts ────────────────────────────────────────────
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-28",
        "description": "SA key optimization on top Bean-passing w8/w9 orderings",
        "top_w9_base": [{"order": r["order"], "quadgram": round(r["quadgram"], 4),
                         "variant": r["variant"], "period": r["period"]}
                        for r in top_w9[:20]],
        "top_w8_base": [{"order": r["order"], "quadgram": round(r["quadgram"], 4),
                         "variant": r["variant"], "period": r["period"]}
                        for r in top_w8[:20]],
        "sa_results_top20": all_sa_results[:20],
        "verdict": verdict,
        "verdict_detail": detail,
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_28_w9_bean_key_sa.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")
    print(f"\nRESULT: best_q={best['sa_quadgram'] if best else 'N/A'} verdict={verdict}")


if __name__ == "__main__":
    main()
