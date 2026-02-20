#!/usr/bin/env python3
"""E-FRAC-47: Myszkowski Transposition — Comprehensive Test.

Myszkowski transposition is listed as Tier 4 (never properly tested) in
elimination_tiers.md. Prior test E-S-39 tested "47K orderings" but used
underdetermined periods and lacked Bean constraint analysis.

Myszkowski differs from standard columnar in that columns with the SAME
keyword letter are read row-by-row ACROSS the tied columns, rather than
column-by-column. This creates a qualitatively different permutation space.

Methodology (matching E-FRAC-12/29/30/32):
  1. Generate unique Myszkowski permutations at widths 5-13
  2. Score at discriminating periods ONLY (2-7)
  3. Check Bean constraints
  4. Compare against random baseline
  5. Apply multiple-testing correction

For width w, the number of distinct Myszkowski permutations equals the
Fubini number (ordered Bell number). We use the "rank pattern" approach:
two keywords produce the same permutation iff they have the same rank
pattern (e.g., "ABBA" and "CDDC" both have pattern (0,1,1,0)).

Widths 5-7: exhaustive enumeration of all rank patterns
Widths 8-9: sample 50K random keywords, deduplicate to unique permutations
Widths 10-13: sample 50K random keywords, deduplicate
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
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}


# ═══════════════════════════════════════════════════════════════
# Myszkowski permutation generation
# ═══════════════════════════════════════════════════════════════

def rank_pattern_to_perm(pattern, length=97):
    """Convert a rank pattern (tuple of ints) to a Myszkowski permutation.

    Pattern example: (0, 1, 1, 0, 2) means columns 0,3 are tied at rank 0,
    columns 1,2 are tied at rank 1, column 4 is rank 2.
    """
    width = len(pattern)
    nrows = math.ceil(length / width)

    # Group columns by rank
    rank_to_cols = defaultdict(list)
    for col_idx, rank in enumerate(pattern):
        rank_to_cols[rank].append(col_idx)

    # Build column position lists
    cols = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)

    # Read in rank order, with Myszkowski tie-breaking
    perm = []
    for rank in sorted(rank_to_cols):
        tied_cols = rank_to_cols[rank]
        if len(tied_cols) == 1:
            perm.extend(cols[tied_cols[0]])
        else:
            # Myszkowski: read row-by-row across tied columns
            for row in range(nrows):
                for c in tied_cols:
                    pos = row * width + c
                    if pos < length:
                        perm.append(pos)

    return perm


def generate_all_rank_patterns(width):
    """Generate all distinct rank patterns of given width.

    A rank pattern is a tuple of non-negative integers where:
    - values are consecutive starting from 0
    - the first occurrence of each value appears in order

    This enumerates all set partitions with all orderings,
    giving Fubini(width) total patterns.
    """
    patterns = set()

    def backtrack(pos, pattern, next_rank, used_ranks):
        if pos == width:
            patterns.add(tuple(pattern))
            return

        # Option 1: assign an existing rank
        for rank in used_ranks:
            pattern.append(rank)
            backtrack(pos + 1, pattern, next_rank, used_ranks)
            pattern.pop()

        # Option 2: assign a new rank
        pattern.append(next_rank)
        used_ranks.add(next_rank)
        backtrack(pos + 1, pattern, next_rank + 1, used_ranks)
        used_ranks.remove(next_rank)
        pattern.pop()

    backtrack(0, [], 0, set())
    return sorted(patterns)


def sample_rank_patterns(width, n_samples):
    """Sample random rank patterns by generating random keywords."""
    patterns = set()
    max_ranks = min(width, 26)  # At most 26 distinct letters

    for _ in range(n_samples * 5):  # Oversample to get enough unique
        if len(patterns) >= n_samples:
            break
        # Generate random keyword of given width from a-z
        n_distinct = random.randint(1, max_ranks)
        alphabet = list(range(n_distinct))
        keyword_ranks = [random.choice(alphabet) for _ in range(width)]

        # Normalize to canonical rank pattern
        mapping = {}
        next_rank = 0
        pattern = []
        for r in keyword_ranks:
            if r not in mapping:
                mapping[r] = next_rank
                next_rank += 1
            pattern.append(mapping[r])
        patterns.add(tuple(pattern))

    return sorted(patterns)


def classify_pattern(pattern):
    """Classify a rank pattern by its tie structure."""
    rank_counts = Counter(pattern)
    n_distinct = len(rank_counts)
    n_tied = sum(1 for c in rank_counts.values() if c > 1)
    max_tie = max(rank_counts.values())
    width = len(pattern)

    if n_distinct == width:
        return "standard_columnar"  # All distinct = standard columnar
    elif n_distinct == 1:
        return "all_tied"  # All same rank = identity-like
    else:
        return f"ties_{n_tied}_max_{max_tie}"


# ═══════════════════════════════════════════════════════════════
# Scoring functions (same as E-FRAC-12/29/30)
# ═══════════════════════════════════════════════════════════════

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean_eq(perm, variant="vigenere"):
    inv = invert_perm(perm)

    def key_at(pt_pos):
        ct_pos = inv[pt_pos]
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
    return True


def check_bean_full(perm, variant="vigenere"):
    inv = invert_perm(perm)

    def key_at(pt_pos):
        ct_pos = inv[pt_pos]
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


def strict_periodic_score(perm, period, variant, model):
    inv = invert_perm(perm)
    residue_keys = defaultdict(list)

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

        residue_keys[residue].append(k)

    total = 0
    for keys in residue_keys.values():
        if len(keys) == 1:
            total += 1
        else:
            counts = Counter(keys)
            total += counts.most_common(1)[0][1]

    return total


def best_score_across_configs(perm):
    best = 0
    best_config = None
    for period in [2, 3, 5, 7]:
        for variant in ["vigenere", "beaufort"]:
            for model in ["A", "B"]:
                s = strict_periodic_score(perm, period, variant, model)
                if s > best:
                    best = s
                    best_config = (period, variant, model)
    return best, best_config


# ═══════════════════════════════════════════════════════════════
# Main experiment
# ═══════════════════════════════════════════════════════════════

def test_width(width, patterns, label):
    """Test all Myszkowski permutations for a given width."""
    print(f"\n{'='*60}")
    print(f"Width {width}: {len(patterns)} unique rank patterns ({label})")
    print(f"{'='*60}")

    score_dist = defaultdict(int)
    bean_eq_count = 0
    bean_full_count = 0
    top_results = []
    best_score = 0
    n_standard = 0  # Count standard columnar (all distinct ranks)
    n_myszkowski_only = 0  # Count patterns with ties
    t0 = time.time()

    for i, pattern in enumerate(patterns):
        perm = rank_pattern_to_perm(pattern, CT_LEN)

        if len(perm) != CT_LEN or set(perm) != set(range(CT_LEN)):
            continue  # Skip invalid permutations

        is_standard = (len(set(pattern)) == width)
        if is_standard:
            n_standard += 1
        else:
            n_myszkowski_only += 1

        score, config = best_score_across_configs(perm)
        score_dist[score] += 1

        if score > best_score:
            best_score = score

        # Check Bean on higher scores
        bean_eq_v = check_bean_eq(perm, "vigenere")
        bean_eq_b = check_bean_eq(perm, "beaufort")
        if bean_eq_v or bean_eq_b:
            bean_eq_count += 1
            bean_full_v = check_bean_full(perm, "vigenere") if bean_eq_v else False
            bean_full_b = check_bean_full(perm, "beaufort") if bean_eq_b else False
            if bean_full_v or bean_full_b:
                bean_full_count += 1

            if score >= 10:
                top_results.append({
                    "width": width,
                    "pattern": pattern,
                    "is_standard_columnar": is_standard,
                    "score": score,
                    "config": {"period": config[0], "variant": config[1], "model": config[2]},
                    "bean_eq_vig": bean_eq_v,
                    "bean_eq_beau": bean_eq_b,
                    "bean_full_vig": bean_full_v if bean_eq_v else False,
                    "bean_full_beau": bean_full_b if bean_eq_b else False,
                })

        elif score >= 12:
            top_results.append({
                "width": width,
                "pattern": pattern,
                "is_standard_columnar": is_standard,
                "score": score,
                "config": {"period": config[0], "variant": config[1], "model": config[2]},
                "bean_eq_vig": False,
                "bean_eq_beau": False,
                "bean_full_vig": False,
                "bean_full_beau": False,
            })

        if (i + 1) % 10000 == 0:
            elapsed = time.time() - t0
            print(f"  {i+1}/{len(patterns)} ({100*(i+1)/len(patterns):.1f}%) "
                  f"best={best_score}/24 rate={i/elapsed:.0f}/s")

    elapsed = time.time() - t0
    n_valid = n_standard + n_myszkowski_only

    top_results.sort(key=lambda x: x["score"], reverse=True)

    result = {
        "width": width,
        "label": label,
        "n_patterns": len(patterns),
        "n_valid_perms": n_valid,
        "n_standard_columnar": n_standard,
        "n_myszkowski_only": n_myszkowski_only,
        "best_score": best_score,
        "score_distribution": {str(k): v for k, v in sorted(score_dist.items())},
        "bean_eq_count": bean_eq_count,
        "bean_eq_rate": bean_eq_count / n_valid if n_valid > 0 else 0,
        "bean_full_count": bean_full_count,
        "bean_full_rate": bean_full_count / n_valid if n_valid > 0 else 0,
        "top_results": top_results[:20],
        "elapsed_seconds": elapsed,
    }

    print(f"  Width {width}: {n_valid} valid perms ({n_standard} standard + {n_myszkowski_only} Myszkowski-only)")
    print(f"  Best: {best_score}/24")
    print(f"  Scores (≥8): {', '.join(f'{k}:{v}' for k, v in sorted(score_dist.items()) if k >= 8)}")
    print(f"  Bean eq: {bean_eq_count}/{n_valid} ({100*result['bean_eq_rate']:.2f}%)")
    print(f"  Bean full: {bean_full_count}/{n_valid} ({100*result['bean_full_rate']:.2f}%)")
    if top_results:
        best = top_results[0]
        mysk_in_top = sum(1 for r in top_results[:10] if not r["is_standard_columnar"])
        print(f"  Top 10: {mysk_in_top} Myszkowski-only (rest are standard columnar)")
        bean_in_top = sum(1 for r in top_results[:20] if r.get("bean_full_vig") or r.get("bean_full_beau"))
        print(f"  Bean-passing in top 20: {bean_in_top}")
    print(f"  Time: {elapsed:.1f}s")

    return result


def random_baseline(n_samples=50000):
    """Score random permutations as baseline."""
    print(f"\n{'='*60}")
    print(f"Random baseline: {n_samples:,} random permutations")
    print(f"{'='*60}")

    score_dist = defaultdict(int)
    best_score = 0
    t0 = time.time()

    for _ in range(n_samples):
        perm = list(range(CT_LEN))
        random.shuffle(perm)
        score, _ = best_score_across_configs(perm)
        score_dist[score] += 1
        if score > best_score:
            best_score = score

    elapsed = time.time() - t0
    print(f"  Random baseline: best={best_score}/24")
    print(f"  Distribution (≥8): {', '.join(f'{k}:{v}' for k, v in sorted(score_dist.items()) if k >= 8)}")
    print(f"  Time: {elapsed:.1f}s")

    return {
        "n_samples": n_samples,
        "best_score": best_score,
        "score_distribution": {str(k): v for k, v in sorted(score_dist.items())},
        "elapsed_seconds": elapsed,
    }


def main():
    print("=" * 60)
    print("E-FRAC-47: Myszkowski Transposition — Comprehensive Test")
    print("=" * 60)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print()

    random.seed(42)
    t_start = time.time()

    # ── Phase 0: Random baseline ──
    baseline = random_baseline(50000)

    results = {
        "experiment": "E-FRAC-47",
        "baseline": baseline,
        "widths": {},
    }

    # ── Phase 1: Exhaustive widths 5-7 ──
    for width in [5, 6, 7]:
        print(f"\nGenerating all rank patterns for width {width}...")
        t = time.time()
        patterns = generate_all_rank_patterns(width)
        print(f"  {len(patterns)} patterns in {time.time()-t:.1f}s")

        # Fubini numbers for reference: 5→541, 6→4683, 7→47293
        result = test_width(width, patterns, "exhaustive")
        results["widths"][str(width)] = result

    # ── Phase 2: Sampled widths 8-13 ──
    for width in [8, 9, 10, 11, 12, 13]:
        n_target = 50000
        print(f"\nSampling rank patterns for width {width} (target: {n_target})...")
        t = time.time()
        patterns = sample_rank_patterns(width, n_target)
        print(f"  {len(patterns)} unique patterns in {time.time()-t:.1f}s")

        result = test_width(width, patterns, f"sampled_{n_target}")
        results["widths"][str(width)] = result

    # ── Phase 3: Summary ──
    total_elapsed = time.time() - t_start

    print(f"\n{'='*60}")
    print(f"SUMMARY — E-FRAC-47: Myszkowski Transposition")
    print(f"{'='*60}")
    print(f"\nRandom baseline: best={baseline['best_score']}/24")
    print(f"\n{'Width':<8} {'N perms':>10} {'Std col':>8} {'Mysz-only':>10} {'Best':>6} {'Bean eq%':>10} {'Bean full%':>10}")
    print("-" * 70)

    global_best = 0
    total_perms = 0
    total_myszkowski_only = 0
    myszkowski_best = 0

    for width in [5, 6, 7, 8, 9, 10, 11, 12, 13]:
        r = results["widths"][str(width)]
        n = r["n_valid_perms"]
        total_perms += n
        total_myszkowski_only += r["n_myszkowski_only"]
        if r["best_score"] > global_best:
            global_best = r["best_score"]

        # Check best score among Myszkowski-only patterns
        for tr in r.get("top_results", []):
            if not tr["is_standard_columnar"] and tr["score"] > myszkowski_best:
                myszkowski_best = tr["score"]

        print(f"w={width:<5} {n:>10,} {r['n_standard_columnar']:>8,} {r['n_myszkowski_only']:>10,} "
              f"{r['best_score']:>5}/24 {100*r['bean_eq_rate']:>9.2f}% {100*r['bean_full_rate']:>9.2f}%")

    # Statistical comparison
    baseline_max = baseline["best_score"]
    baseline_scores = baseline["score_distribution"]
    n_at_or_above = sum(v for k, v in baseline_scores.items() if int(k) >= global_best)
    p_per_trial = n_at_or_above / baseline["n_samples"] if baseline["n_samples"] > 0 else 0
    p_corrected = 1 - (1 - p_per_trial) ** total_perms if p_per_trial < 1 else 1.0

    underperforms = global_best < baseline_max

    print(f"\nTotal permutations: {total_perms:,}")
    print(f"  Standard columnar: {total_perms - total_myszkowski_only:,}")
    print(f"  Myszkowski-only (with ties): {total_myszkowski_only:,}")
    print(f"Global best (all): {global_best}/24")
    print(f"Myszkowski-only best: {myszkowski_best}/24")
    print(f"Random baseline best: {baseline_max}/24")
    print(f"p(random ≥ {global_best}): {p_per_trial:.6f}")
    print(f"Corrected p (for {total_perms:,} trials): {p_corrected:.6f}")
    print(f"Underperforms random: {underperforms}")

    # Check if Myszkowski-only patterns ever beat standard columnar
    print(f"\nKey question: Do Myszkowski tie patterns produce DIFFERENT results from standard columnar?")
    print(f"  Standard columnar patterns are a SUBSET of the patterns tested here.")
    print(f"  If the best scores come from standard columnar patterns,")
    print(f"  then Myszkowski offers no advantage over what E-FRAC-12/29/30 already tested.")

    # Verdict
    if global_best >= 18:
        verdict = "SIGNAL"
    elif global_best > baseline_max:
        verdict = "STORE"
    elif underperforms:
        verdict = "NOISE_UNDERPERFORMS"
    else:
        verdict = "NOISE"

    print(f"\nVERDICT: {verdict}")
    print(f"Total runtime: {total_elapsed:.1f}s")

    results["summary"] = {
        "global_best": global_best,
        "myszkowski_only_best": myszkowski_best,
        "baseline_best": baseline_max,
        "total_permutations": total_perms,
        "total_myszkowski_only": total_myszkowski_only,
        "p_per_trial": p_per_trial,
        "p_corrected": p_corrected,
        "underperforms_random": underperforms,
        "verdict": verdict,
        "total_runtime_seconds": total_elapsed,
    }

    # Save results
    os.makedirs("results/frac", exist_ok=True)
    with open("results/frac/e_frac_47_myszkowski.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to results/frac/e_frac_47_myszkowski.json")

    print(f"\nRESULT: best={global_best}/24 configs={total_perms} verdict={verdict}")


if __name__ == "__main__":
    main()
