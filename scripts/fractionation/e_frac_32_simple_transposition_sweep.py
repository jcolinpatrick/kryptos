#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-32: Simple Transposition Family Sweep.

Tests the simplest possible transposition families against periodic substitution
at discriminating periods (2-7). These are transpositions a non-mathematician
sculptor might use: cyclic shifts, text reversal, block reversal, rail fence,
single swaps, and affine permutations.

Families tested:
1. Cyclic shift: σ(i) = (i+k) mod 97, k=1..96 → 96 perms
2. Reverse: σ(i) = 96-i → 1 perm
3. Affine: σ(i) = (a*i+b) mod 97, a=1..96, b=0..96 → 9,312 perms
   (97 is prime, so all a=1..96 give valid permutations)
4. Block reversal: reverse blocks of size B, B=2..48 → 47 perms
5. Rail fence: standard rail fence depth 2-20 → 19 perms
6. Single swap: swap exactly 2 positions → C(97,2) = 4,656 perms
7. Pair swaps: swap adjacent pairs (a,a+1) throughout → 1 perm per stride

Total: ~14,131 distinct permutations × 3 variants × 2 models × 6 periods ≈ 508K configs

For each, compute:
- Strict periodic score at periods 2-7
- Bean equality check
- Full Bean constraint check (if eq passes)

Compare best scores to random baseline (from E-FRAC-31: max 15/24 from 500K random).
"""
import json
import os
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN  # 97


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean_eq_only(inv_perm):
    """Check ONLY Bean equality (variant-independent: CT[inv(27)] = CT[inv(65)])."""
    for eq_a, eq_b in BEAN_EQ:
        if CT_NUM[inv_perm[eq_a]] != CT_NUM[inv_perm[eq_b]]:
            return False
    return True


def check_bean_full(inv_perm, variant="vigenere"):
    """Check Bean equality + all 21 inequalities."""
    def key_at(pt_pos):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
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


def strict_periodic_score(inv_perm, period, variant, model):
    """Strict period-consistency scoring: majority vote per residue class."""
    residue_keys = defaultdict(list)
    for pt_pos in sorted(CRIB_SET):
        ct_pos = inv_perm[pt_pos]
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
        residue_keys[residue].append(k)

    total = 0
    for keys in residue_keys.values():
        if len(keys) == 1:
            total += 1
        else:
            total += Counter(keys).most_common(1)[0][1]
    return total


# ---- Permutation Generators ----

def gen_cyclic_shifts():
    """σ(i) = (i+k) mod N, k=1..N-1."""
    perms = []
    for k in range(1, N):
        perm = [(i + k) % N for i in range(N)]
        perms.append(("cyclic", f"k={k}", perm))
    return perms


def gen_reverse():
    """σ(i) = N-1-i."""
    perm = [N - 1 - i for i in range(N)]
    return [("reverse", "full", perm)]


def gen_affine():
    """σ(i) = (a*i+b) mod N, a=1..N-1, b=0..N-1.
    N=97 is prime, so all a!=0 give valid permutations.
    Skip a=1,b=0 (identity) and a=1,b=k (cyclic shifts, already tested).
    """
    perms = []
    for a in range(2, N):  # skip a=1 (covered by cyclic/identity)
        for b in range(N):
            perm = [(a * i + b) % N for i in range(N)]
            perms.append(("affine", f"a={a},b={b}", perm))
    return perms


def gen_block_reversal():
    """Reverse non-overlapping blocks of size B, B=2..48."""
    perms = []
    for B in range(2, 49):
        perm = list(range(N))
        for start in range(0, N - B + 1, B):
            end = min(start + B, N)
            perm[start:end] = perm[start:end][::-1]
        if perm != list(range(N)):  # skip identity
            perms.append(("block_reversal", f"B={B}", perm))
    return perms


def gen_rail_fence():
    """Standard rail fence cipher, depth 2-20."""
    perms = []
    for depth in range(2, 21):
        # Build the rail fence reading order
        rails = [[] for _ in range(depth)]
        direction = 1
        rail = 0
        for i in range(N):
            rails[rail].append(i)
            if rail == 0:
                direction = 1
            elif rail == depth - 1:
                direction = -1
            rail += direction
        # Reading order: concatenate rails
        reading_order = []
        for r in rails:
            reading_order.extend(r)
        # Encryption perm: ct_pos -> pt_pos
        # reading_order[ct_pos] = pt_pos
        perm = reading_order
        perms.append(("rail_fence", f"depth={depth}", perm))
    return perms


def gen_single_swaps():
    """Swap exactly two positions: all C(97,2) = 4,656 pairs."""
    perms = []
    for a in range(N):
        for b in range(a + 1, N):
            perm = list(range(N))
            perm[a], perm[b] = perm[b], perm[a]
            perms.append(("single_swap", f"swap({a},{b})", perm))
    return perms


def gen_adjacent_pair_swaps():
    """Swap all adjacent pairs: (0,1), (2,3), ... — global pair swap."""
    perm = list(range(N))
    for i in range(0, N - 1, 2):
        perm[i], perm[i + 1] = perm[i + 1], perm[i]
    return [("pair_swap", "stride=2", perm)]


# ---- Main ----

def score_all_perms(perms, variants, models, periods):
    """Score all permutations and return results summary."""
    results = {
        "family_scores": {},
        "top_results": [],
        "bean_eq_passes": 0,
        "bean_full_passes": {v: 0 for v in variants},
        "score_dist": Counter(),
        "n_tested": 0,
    }

    for family, label, perm in perms:
        inv_perm = invert_perm(perm)
        results["n_tested"] += 1

        eq_pass = check_bean_eq_only(inv_perm)
        if eq_pass:
            results["bean_eq_passes"] += 1

        best_score = 0
        best_cfg = None

        for period in periods:
            for variant in variants:
                for model in models:
                    score = strict_periodic_score(inv_perm, period, variant, model)
                    if score > best_score:
                        best_score = score
                        best_cfg = (period, variant, model)

        results["score_dist"][best_score] += 1

        if family not in results["family_scores"]:
            results["family_scores"][family] = {
                "n_perms": 0, "max_score": 0, "best_label": "",
                "best_cfg": None, "bean_eq": 0, "bean_full": {v: 0 for v in variants},
                "score_dist": Counter(),
            }

        fs = results["family_scores"][family]
        fs["n_perms"] += 1
        fs["score_dist"][best_score] += 1
        if eq_pass:
            fs["bean_eq"] += 1

        if best_score > fs["max_score"]:
            fs["max_score"] = best_score
            fs["best_label"] = label
            fs["best_cfg"] = best_cfg

        # Check full Bean for Bean-eq passing perms
        if eq_pass:
            for variant in variants:
                if check_bean_full(inv_perm, variant):
                    results["bean_full_passes"][variant] += 1
                    fs["bean_full"][variant] += 1

        # Track top results
        if best_score >= 10:
            results["top_results"].append({
                "family": family, "label": label,
                "score": best_score, "cfg": best_cfg,
                "bean_eq": eq_pass,
            })

    return results


def run_random_baseline(n_samples, variants, models, periods):
    """Random permutation baseline for comparison."""
    score_dist = Counter()
    max_score = 0
    for _ in range(n_samples):
        perm = list(range(N))
        random.shuffle(perm)
        inv_perm = invert_perm(perm)

        best = 0
        for period in periods:
            for variant in variants:
                for model in models:
                    s = strict_periodic_score(inv_perm, period, variant, model)
                    if s > best:
                        best = s
        score_dist[best] += 1
        if best > max_score:
            max_score = best

    mean_score = sum(s * c for s, c in score_dist.items()) / n_samples
    return {"max": max_score, "mean": round(mean_score, 3), "dist": dict(score_dist), "n": n_samples}


def main():
    t0 = time.time()
    random.seed(42)
    variants = ["vigenere", "beaufort", "variant_beaufort"]
    models = ["A", "B"]
    periods = [2, 3, 4, 5, 6, 7]

    print("=" * 70)
    print("E-FRAC-32: Simple Transposition Family Sweep")
    print("=" * 70)
    print(f"CT length: {N}")
    print(f"Crib positions: {len(CRIB_SET)}")
    print(f"Periods: {periods}")
    print(f"Variants: {variants}")
    print(f"Models: {models}")
    print()

    # Generate all permutations
    print("Generating permutation families...")
    all_perms = []

    families = [
        ("Cyclic shifts", gen_cyclic_shifts),
        ("Reverse", gen_reverse),
        ("Affine", gen_affine),
        ("Block reversal", gen_block_reversal),
        ("Rail fence", gen_rail_fence),
        ("Single swaps", gen_single_swaps),
        ("Adjacent pair swaps", gen_adjacent_pair_swaps),
    ]

    for name, gen_fn in families:
        perms = gen_fn()
        print(f"  {name}: {len(perms)} permutations")
        all_perms.extend(perms)

    total_perms = len(all_perms)
    total_configs = total_perms * len(variants) * len(models) * len(periods)
    print(f"\nTotal permutations: {total_perms}")
    print(f"Total configs: {total_configs}")
    print()

    # Score all permutations
    print("Scoring all permutations at discriminating periods (2-7)...")
    t_score = time.time()
    results = score_all_perms(all_perms, variants, models, periods)
    t_scored = time.time() - t_score
    print(f"Scoring complete in {t_scored:.1f}s")
    print()

    # Print family-level results
    print("=" * 70)
    print("RESULTS BY FAMILY")
    print("=" * 70)
    for family_name, fs in sorted(results["family_scores"].items()):
        print(f"\n  {family_name}: {fs['n_perms']} perms")
        print(f"    Max score: {fs['max_score']}/24")
        if fs['best_label']:
            print(f"    Best perm: {fs['best_label']}")
        if fs['best_cfg']:
            print(f"    Best config: period={fs['best_cfg'][0]}, "
                  f"variant={fs['best_cfg'][1]}, model={fs['best_cfg'][2]}")
        print(f"    Bean eq passes: {fs['bean_eq']}/{fs['n_perms']} "
              f"({100*fs['bean_eq']/fs['n_perms']:.2f}%)")
        bean_full_str = ", ".join(f"{v}:{fs['bean_full'][v]}" for v in variants)
        print(f"    Bean full passes: {bean_full_str}")
        dist_str = ", ".join(f"{s}:{c}" for s, c in sorted(fs['score_dist'].items(), reverse=True)[:5])
        print(f"    Score distribution (top 5): {dist_str}")

    # Overall summary
    print()
    print("=" * 70)
    print("OVERALL SUMMARY")
    print("=" * 70)
    print(f"Total permutations tested: {results['n_tested']}")
    print(f"Total configs: {total_configs}")
    print(f"Global max score: {max(results['score_dist'].keys())}/24")
    print(f"Bean eq passes: {results['bean_eq_passes']}/{results['n_tested']} "
          f"({100*results['bean_eq_passes']/results['n_tested']:.2f}%)")
    bean_full_str = ", ".join(f"{v}:{results['bean_full_passes'][v]}" for v in variants)
    print(f"Bean full passes: {bean_full_str}")
    print()

    # Top results
    if results["top_results"]:
        print("TOP RESULTS (score >= 10):")
        top_sorted = sorted(results["top_results"], key=lambda x: -x["score"])[:20]
        for r in top_sorted:
            print(f"  {r['score']}/24 — {r['family']} {r['label']} "
                  f"(p={r['cfg'][0]}, {r['cfg'][1]}, {r['cfg'][2]}) "
                  f"Bean={'PASS' if r['bean_eq'] else 'FAIL'}")
    else:
        print("No results scored >= 10/24")
    print()

    # Random baseline (smaller since we already have E-FRAC-31 data)
    print("Running random baseline (50K samples)...")
    t_base = time.time()
    baseline = run_random_baseline(50_000, variants, models, periods)
    t_based = time.time() - t_base
    print(f"Baseline complete in {t_based:.1f}s")
    print(f"  Random max: {baseline['max']}/24, mean: {baseline['mean']}")
    print()

    # Statistical comparison
    global_max = max(results['score_dist'].keys())
    # What fraction of random baseline reaches or exceeds global_max?
    random_at_max = sum(c for s, c in baseline['dist'].items() if s >= global_max)
    p_raw = random_at_max / baseline['n']
    p_corrected = 1 - (1 - p_raw) ** total_perms if p_raw < 1 else 1.0
    print(f"Statistical comparison:")
    print(f"  Best structured score: {global_max}/24")
    print(f"  Random P(>={global_max}): {p_raw:.6f}")
    print(f"  Corrected p ({total_perms} trials): {p_corrected:.6f}")
    print()

    # Verdict
    if global_max >= 18:
        verdict = "SIGNAL"
        print(f"VERDICT: {verdict} — score {global_max}/24 needs QA validation!")
    elif p_corrected > 0.05:
        verdict = "NOISE"
        print(f"VERDICT: {verdict} — best score {global_max}/24 is within random expectation "
              f"(corrected p={p_corrected:.3f})")
    else:
        verdict = "MARGINAL"
        print(f"VERDICT: {verdict} — best score {global_max}/24 corrected p={p_corrected:.3f}")

    total_time = time.time() - t0
    print(f"\nTotal runtime: {total_time:.1f}s")

    # Save results
    out_dir = "results/frac"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "e_frac_32_simple_transposition_sweep.json")

    output = {
        "experiment": "E-FRAC-32",
        "title": "Simple Transposition Family Sweep",
        "total_perms": total_perms,
        "total_configs": total_configs,
        "global_max_score": global_max,
        "verdict": verdict,
        "runtime_seconds": round(total_time, 1),
        "families": {},
        "top_results": results["top_results"][:50],
        "baseline": baseline,
        "bean_eq_passes": results["bean_eq_passes"],
        "bean_full_passes": dict(results["bean_full_passes"]),
        "p_raw": round(p_raw, 6),
        "p_corrected": round(p_corrected, 6),
        "score_distribution": {str(k): v for k, v in sorted(results["score_dist"].items())},
    }

    for family_name, fs in results["family_scores"].items():
        output["families"][family_name] = {
            "n_perms": fs["n_perms"],
            "max_score": fs["max_score"],
            "best_label": fs["best_label"],
            "best_cfg": list(fs["best_cfg"]) if fs["best_cfg"] else None,
            "bean_eq": fs["bean_eq"],
            "bean_full": dict(fs["bean_full"]),
            "score_dist": {str(k): v for k, v in sorted(fs["score_dist"].items())},
        }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")

    print(f"\nRESULT: best={global_max}/24 configs={total_configs} verdict={verdict}")


if __name__ == "__main__":
    main()
