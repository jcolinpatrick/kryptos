#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-34: Multi-Objective Oracle Design for JTS.

E-FRAC-33 showed hill-climbing reaches false 24/24 at all discriminating periods.
This experiment characterizes those false positives to design a multi-objective
oracle that JTS can use to filter them out.

For each false 24/24 permutation found by hill-climbing:
1. Extract the periodic key from crib positions
2. Decrypt the FULL 97-char ciphertext
3. Compute plaintext quality metrics:
   - Quadgram fitness (log-prob per char)
   - IC of plaintext
   - Longest English word found
   - Fraction of plaintext covered by English words (≥3 chars)
4. Compare to benchmarks:
   - Random 97-char text (expected quadgram/IC)
   - Real English text (expected quadgram/IC)
   - The known partial plaintext (EASTNORTHEAST + BERLINCLOCK)

The result: recommended multi-objective thresholds for JTS.
"""
import json
import math
import os
import random
import time
from collections import Counter, defaultdict
from pathlib import Path

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, ALPH, MOD,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.ngram import NgramScorer

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN  # 97


# ══════════════════════════════════════════════════════════════════
# Wordlist loading
# ══════════════════════════════════════════════════════════════════

def load_wordset(min_len=3, max_len=20):
    """Load English words for substring matching."""
    wordlist_path = Path("wordlists/english.txt")
    if not wordlist_path.exists():
        wordlist_path = Path("data/wordlists/english.txt")
    words = set()
    if wordlist_path.exists():
        with open(wordlist_path) as f:
            for line in f:
                w = line.strip().upper()
                if min_len <= len(w) <= max_len and w.isalpha():
                    words.add(w)
    return words


# ══════════════════════════════════════════════════════════════════
# Permutation utilities
# ══════════════════════════════════════════════════════════════════

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def random_swap(perm):
    new_perm = list(perm)
    a, b = random.sample(range(len(perm)), 2)
    new_perm[a], new_perm[b] = new_perm[b], new_perm[a]
    return new_perm


# ══════════════════════════════════════════════════════════════════
# Crib scoring (from E-FRAC-33)
# ══════════════════════════════════════════════════════════════════

def strict_periodic_score(inv_perm, period, variant, model):
    """Majority-vote crib scoring. Returns (score, key_dict)."""
    residue_keys = defaultdict(list)
    for pt_pos in sorted(CRIB_SET):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        else:  # variant_beaufort
            k = (pt_val - ct_val) % MOD
        if model == "A":
            residue = pt_pos % period
        else:
            residue = ct_pos % period
        residue_keys[residue].append(k)

    total = 0
    key_dict = {}
    for res, keys in residue_keys.items():
        majority_key = Counter(keys).most_common(1)[0]
        total += majority_key[1]
        key_dict[res] = majority_key[0]
    return total, key_dict


def best_config_with_key(inv_perm, periods, variants, models):
    """Best config with key extraction."""
    best_score = 0
    best_info = None
    for p in periods:
        for v in variants:
            for m in models:
                s, kd = strict_periodic_score(inv_perm, p, v, m)
                if s > best_score:
                    best_score = s
                    best_info = {"period": p, "variant": v, "model": m, "key_dict": kd}
    return best_score, best_info


# ══════════════════════════════════════════════════════════════════
# Full plaintext derivation
# ══════════════════════════════════════════════════════════════════

def derive_plaintext(perm, inv_perm, period, variant, model, key_dict):
    """Derive full 97-char plaintext from a permutation and periodic key.

    For positions where the residue class has no crib-derived key,
    uses key=0 (effectively identity substitution).
    """
    plaintext = []
    for pt_pos in range(N):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]

        if model == "A":
            residue = pt_pos % period
        else:
            residue = ct_pos % period

        k = key_dict.get(residue, 0)  # default to 0 if no crib for this residue

        if variant == "vigenere":
            pt_val = (ct_val - k) % MOD
        elif variant == "beaufort":
            pt_val = (k - ct_val) % MOD
        else:  # variant_beaufort
            pt_val = (ct_val + k) % MOD

        plaintext.append(ALPH[pt_val])
    return "".join(plaintext)


def count_undetermined_residues(period, model, inv_perm):
    """Count residue classes that have no crib-derived key."""
    residues_with_cribs = set()
    for pt_pos in CRIB_SET:
        if model == "A":
            residue = pt_pos % period
        else:
            residue = inv_perm[pt_pos] % period
        residues_with_cribs.add(residue)
    return period - len(residues_with_cribs)


# ══════════════════════════════════════════════════════════════════
# English word detection
# ══════════════════════════════════════════════════════════════════

def find_english_words(text, wordset, min_len=3):
    """Find all English words as substrings. Returns (longest, total_coverage, word_list)."""
    found_words = []
    covered = [False] * len(text)

    # Search from longest to shortest to prioritize longer matches
    for length in range(min(20, len(text)), min_len - 1, -1):
        for start in range(len(text) - length + 1):
            substr = text[start:start + length]
            if substr in wordset:
                # Check if this overlaps with already-covered positions
                new_coverage = sum(1 for i in range(start, start + length) if not covered[i])
                if new_coverage > 0:
                    found_words.append((start, substr))
                    for i in range(start, start + length):
                        covered[i] = True

    longest = max((w for _, w in found_words), key=len, default="")
    total_covered = sum(covered)
    return longest, total_covered / len(text) if len(text) > 0 else 0, found_words


# ══════════════════════════════════════════════════════════════════
# Hill-climbing with collection of high-scoring permutations
# ══════════════════════════════════════════════════════════════════

def hill_climb_collect(n_climbs, max_steps, periods, variants, models,
                       collect_threshold=20, target_24=True):
    """Run hill-climbing and collect permutations that reach high scores.

    Returns list of dicts with {perm, inv_perm, score, config, step}.
    """
    collected = []

    for climb_idx in range(n_climbs):
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)
        current_score, current_info = best_config_with_key(inv, periods, variants, models)

        for step in range(max_steps):
            candidate = random_swap(perm)
            cand_inv = invert_perm(candidate)
            cand_score, cand_info = best_config_with_key(cand_inv, periods, variants, models)

            if cand_score >= current_score:
                perm = candidate
                inv = cand_inv
                current_score = cand_score
                current_info = cand_info

                if current_score >= collect_threshold:
                    collected.append({
                        "perm": list(perm),
                        "inv_perm": list(inv),
                        "score": current_score,
                        "config": current_info,
                        "climb_idx": climb_idx,
                        "step": step,
                    })

            if target_24 and current_score >= 24:
                break

        if (climb_idx + 1) % 10 == 0:
            print(f"  Climb {climb_idx+1}/{n_climbs}: "
                  f"final={current_score}/24, collected={len(collected)} solutions")

    return collected


# ══════════════════════════════════════════════════════════════════
# Main experiment
# ══════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()
    random.seed(2024)
    variants = ["vigenere", "beaufort", "variant_beaufort"]
    models = ["A", "B"]
    periods = [2, 3, 4, 5, 6, 7]

    print("=" * 70)
    print("E-FRAC-34: Multi-Objective Oracle Design for JTS")
    print("=" * 70)
    print()

    # Load resources
    print("Loading quadgram scorer...")
    scorer = NgramScorer.from_file("data/english_quadgrams.json", n=4)

    print("Loading English wordlist...")
    wordset = load_wordset(min_len=3)
    print(f"  Loaded {len(wordset)} words (3-20 chars)")

    # ================================================================
    # Phase 1: Establish benchmarks
    # ================================================================
    print("\n--- Phase 1: Establishing benchmarks ---")

    # Benchmark 1: Real English text quality
    english_samples = [
        "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3,
        "EASTNORTHEASTERLYWINDSBLOWINGACROSSTHEBERLINCLOCKTOWERATMIDNIGHT" * 2,
        "ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASX",
    ]
    english_metrics = []
    for sample in english_samples:
        sample = sample[:97].upper()
        if len(sample) < 97:
            sample += "X" * (97 - len(sample))
        qg = scorer.score_per_char(sample)
        ic_val = ic(sample)
        longest, coverage, _ = find_english_words(sample, wordset)
        english_metrics.append({
            "quadgram_per_char": round(qg, 4),
            "ic": round(ic_val, 4),
            "longest_word": longest,
            "word_coverage": round(coverage, 4),
        })

    mean_english_qg = sum(m["quadgram_per_char"] for m in english_metrics) / len(english_metrics)
    mean_english_ic = sum(m["ic"] for m in english_metrics) / len(english_metrics)
    mean_english_cov = sum(m["word_coverage"] for m in english_metrics) / len(english_metrics)

    print(f"  English benchmark (mean of {len(english_samples)} samples):")
    print(f"    Quadgram/char: {mean_english_qg:.4f}")
    print(f"    IC: {mean_english_ic:.4f}")
    print(f"    Word coverage: {mean_english_cov:.4f}")

    # Benchmark 2: Random 97-char text quality
    n_random = 5000
    random_qgs = []
    random_ics = []
    random_covs = []
    for _ in range(n_random):
        rand_text = "".join(random.choice(ALPH) for _ in range(97))
        random_qgs.append(scorer.score_per_char(rand_text))
        random_ics.append(ic(rand_text))
        _, cov, _ = find_english_words(rand_text, wordset, min_len=4)
        random_covs.append(cov)

    mean_random_qg = sum(random_qgs) / len(random_qgs)
    mean_random_ic = sum(random_ics) / len(random_ics)
    mean_random_cov = sum(random_covs) / len(random_covs)

    print(f"\n  Random text benchmark ({n_random} samples):")
    print(f"    Quadgram/char: mean={mean_random_qg:.4f}, "
          f"std={math.sqrt(sum((x - mean_random_qg)**2 for x in random_qgs) / len(random_qgs)):.4f}")
    print(f"    IC: mean={mean_random_ic:.4f}")
    print(f"    Word coverage (≥4 chars): mean={mean_random_cov:.4f}")

    # Benchmark 3: K4 CT itself (identity permutation, various keys)
    print("\n  K4 CT metrics (no transposition):")
    ct_qg = scorer.score_per_char(CT)
    ct_ic = ic(CT)
    ct_longest, ct_cov, ct_words = find_english_words(CT, wordset, min_len=4)
    print(f"    Quadgram/char: {ct_qg:.4f}")
    print(f"    IC: {ct_ic:.4f}")
    print(f"    Longest word (≥4): {ct_longest}")
    print(f"    Word coverage (≥4): {ct_cov:.4f}")

    # ================================================================
    # Phase 2: Collect false positive permutations via hill-climbing
    # ================================================================
    print("\n--- Phase 2: Collecting false positive permutations ---")

    # Phase 2a: Hill-climbing at best period (same as E-FRAC-33 but collecting perms)
    print("\n  2a: Hill-climbing (best period), 50 climbs × 10K steps...")
    best_period_solutions = hill_climb_collect(
        n_climbs=50, max_steps=10000,
        periods=periods, variants=variants, models=models,
        collect_threshold=20, target_24=True,
    )

    # Phase 2b: Hill-climbing at period 5 only (hardest discriminating period)
    print("\n  2b: Hill-climbing (period 5 only), 50 climbs × 10K steps...")
    p5_solutions = hill_climb_collect(
        n_climbs=50, max_steps=10000,
        periods=[5], variants=variants, models=models,
        collect_threshold=18, target_24=True,
    )

    # Phase 2c: Hill-climbing at period 2 only (most constrained)
    print("\n  2c: Hill-climbing (period 2 only), 50 climbs × 10K steps...")
    p2_solutions = hill_climb_collect(
        n_climbs=50, max_steps=10000,
        periods=[2], variants=variants, models=models,
        collect_threshold=16, target_24=True,
    )

    print(f"\n  Solutions collected:")
    print(f"    Best-period: {len(best_period_solutions)} (≥20/24)")
    print(f"    Period-5: {len(p5_solutions)} (≥18/24)")
    print(f"    Period-2: {len(p2_solutions)} (≥16/24)")

    # ================================================================
    # Phase 3: Evaluate plaintext quality of false positives
    # ================================================================
    print("\n--- Phase 3: Evaluating plaintext quality ---")

    def evaluate_solutions(solutions, label):
        """Evaluate plaintext quality metrics for a set of solutions."""
        if not solutions:
            print(f"\n  {label}: No solutions to evaluate.")
            return []

        # Deduplicate by score level, keeping unique permutations
        by_score = defaultdict(list)
        seen_perms = set()
        for sol in solutions:
            perm_key = tuple(sol["perm"])
            if perm_key not in seen_perms:
                seen_perms.add(perm_key)
                by_score[sol["score"]].append(sol)

        print(f"\n  {label}: {len(seen_perms)} unique permutations")
        for score in sorted(by_score.keys(), reverse=True):
            print(f"    Score {score}/24: {len(by_score[score])} unique permutations")

        results = []
        for sol in solutions:
            perm = sol["perm"]
            inv = sol["inv_perm"]
            score = sol["score"]
            cfg = sol["config"]

            if cfg is None:
                continue

            period = cfg["period"]
            variant = cfg["variant"]
            model = cfg["model"]
            key_dict = cfg["key_dict"]

            # Count undetermined residues
            n_undet = count_undetermined_residues(period, model, inv)

            # Derive plaintext
            pt = derive_plaintext(perm, inv, period, variant, model, key_dict)

            # Quality metrics
            qg = scorer.score_per_char(pt)
            ic_val = ic(pt)
            longest, word_cov, words = find_english_words(pt, wordset, min_len=4)

            # Check if known crib text is actually present
            ene_match = pt[21:34] == "EASTNORTHEAST"
            bc_match = pt[63:74] == "BERLINCLOCK"

            results.append({
                "score": score,
                "period": period,
                "variant": variant,
                "model": model,
                "undetermined_residues": n_undet,
                "quadgram_per_char": round(qg, 4),
                "ic": round(ic_val, 4),
                "longest_word_4plus": longest,
                "word_coverage_4plus": round(word_cov, 4),
                "ene_in_plaintext": ene_match,
                "bc_in_plaintext": bc_match,
                "plaintext_preview": pt[:40] + "...",
                "climb_idx": sol["climb_idx"],
            })

        return results

    bp_results = evaluate_solutions(best_period_solutions, "Best-period")
    p5_results = evaluate_solutions(p5_solutions, "Period-5")
    p2_results = evaluate_solutions(p2_solutions, "Period-2")

    # ================================================================
    # Phase 4: Statistical analysis of false positive quality
    # ================================================================
    print("\n--- Phase 4: Statistical analysis ---")

    def analyze_results(results, label):
        if not results:
            print(f"\n  {label}: No results to analyze.")
            return {}

        # Group by score
        by_score = defaultdict(list)
        for r in results:
            by_score[r["score"]].append(r)

        print(f"\n  {label}:")
        analysis = {}
        for score in sorted(by_score.keys(), reverse=True):
            group = by_score[score]
            qgs = [r["quadgram_per_char"] for r in group]
            ics = [r["ic"] for r in group]
            covs = [r["word_coverage_4plus"] for r in group]
            periods = Counter(r["period"] for r in group)
            variants = Counter(r["variant"] for r in group)
            ene_count = sum(1 for r in group if r["ene_in_plaintext"])
            bc_count = sum(1 for r in group if r["bc_in_plaintext"])

            mean_qg = sum(qgs) / len(qgs)
            mean_ic = sum(ics) / len(ics)
            mean_cov = sum(covs) / len(covs)
            best_qg = max(qgs)
            best_ic = max(ics)

            print(f"    Score {score}/24 ({len(group)} results):")
            print(f"      Quadgram/char: mean={mean_qg:.4f}, best={best_qg:.4f}")
            print(f"      IC: mean={mean_ic:.4f}, best={best_ic:.4f}")
            print(f"      Word coverage: mean={mean_cov:.4f}")
            print(f"      ENE in plaintext: {ene_count}/{len(group)}")
            print(f"      BC in plaintext: {bc_count}/{len(group)}")
            print(f"      Periods: {dict(periods)}")
            print(f"      Variants: {dict(variants)}")
            if group:
                # Show best quadgram example
                best_idx = qgs.index(best_qg)
                print(f"      Best plaintext: {group[best_idx]['plaintext_preview']}")

            analysis[score] = {
                "count": len(group),
                "quadgram_mean": round(mean_qg, 4),
                "quadgram_best": round(best_qg, 4),
                "quadgram_all": sorted([round(q, 4) for q in qgs]),
                "ic_mean": round(mean_ic, 4),
                "ic_best": round(best_ic, 4),
                "word_coverage_mean": round(mean_cov, 4),
                "ene_in_plaintext": ene_count,
                "bc_in_plaintext": bc_count,
                "periods": dict(periods),
                "variants": dict(variants),
            }

        return analysis

    bp_analysis = analyze_results(bp_results, "Best-period")
    p5_analysis = analyze_results(p5_results, "Period-5")
    p2_analysis = analyze_results(p2_results, "Period-2")

    # ================================================================
    # Phase 5: Recommended multi-objective thresholds
    # ================================================================
    print("\n--- Phase 5: Recommended multi-objective thresholds ---")

    # Collect all false positive quadgram scores at 24/24
    all_fp_24_qgs = []
    for results in [bp_results, p5_results, p2_results]:
        for r in results:
            if r["score"] >= 24:
                all_fp_24_qgs.append(r["quadgram_per_char"])

    # Collect all false positive quadgram scores at ≥20/24
    all_fp_20plus_qgs = []
    for results in [bp_results, p5_results, p2_results]:
        for r in results:
            if r["score"] >= 20:
                all_fp_20plus_qgs.append(r["quadgram_per_char"])

    if all_fp_24_qgs:
        fp_24_best_qg = max(all_fp_24_qgs)
        fp_24_mean_qg = sum(all_fp_24_qgs) / len(all_fp_24_qgs)
        print(f"\n  False positive 24/24 quadgram scores:")
        print(f"    N = {len(all_fp_24_qgs)}")
        print(f"    Mean: {fp_24_mean_qg:.4f}")
        print(f"    Best: {fp_24_best_qg:.4f}")
        print(f"    All: {sorted(all_fp_24_qgs)[:20]}...")
    else:
        fp_24_best_qg = None
        print("\n  No false 24/24 solutions found in this run.")

    print(f"\n  Benchmarks for comparison:")
    print(f"    Real English: ~{mean_english_qg:.4f}/char")
    print(f"    Random text:  ~{mean_random_qg:.4f}/char")
    print(f"    K4 CT:         {ct_qg:.4f}/char")

    # Calculate recommended thresholds
    print(f"\n  === RECOMMENDED MULTI-OBJECTIVE THRESHOLDS FOR JTS ===")
    print(f"  A candidate solution should satisfy ALL of:")
    print(f"    1. Crib score = 24/24")
    print(f"    2. Bean constraint PASS")
    print(f"    3. Quadgram/char > {-5.0:.1f} (English ≈ {mean_english_qg:.2f}, "
          f"random ≈ {mean_random_qg:.2f})")
    print(f"    4. IC > 0.055 (English ≈ 0.067, random ≈ 0.038)")
    print(f"    5. At least one word ≥6 chars in plaintext")

    gap_exists = (fp_24_best_qg is not None and
                  fp_24_best_qg < mean_english_qg * 0.85)  # 85% of English quality

    if gap_exists:
        print(f"\n  GAP ANALYSIS: False positives have quadgram ≤ {fp_24_best_qg:.4f}, "
              f"real English ≈ {mean_english_qg:.4f}")
        print(f"  The gap is {mean_english_qg - fp_24_best_qg:.4f} per char — "
              f"quadgram alone should discriminate.")
    else:
        print(f"\n  WARNING: Gap may be insufficient — multi-objective ESSENTIAL.")

    # ================================================================
    # Phase 6: Per-period false positive density
    # ================================================================
    print("\n--- Phase 6: Per-period false positive density ---")
    for period in [2, 3, 5, 7]:
        count_24 = 0
        count_20plus = 0
        for results in [bp_results, p5_results, p2_results]:
            for r in results:
                if r["period"] == period:
                    if r["score"] >= 24:
                        count_24 += 1
                    if r["score"] >= 20:
                        count_20plus += 1
        print(f"  Period {period}: {count_24} false 24/24, {count_20plus} false ≥20/24")

    # ================================================================
    # Save results
    # ================================================================
    total_time = time.time() - t0

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Total false positives collected: "
          f"{len(best_period_solutions) + len(p5_solutions) + len(p2_solutions)}")
    print(f"  Best-period: {len(best_period_solutions)}")
    print(f"  Period-5: {len(p5_solutions)}")
    print(f"  Period-2: {len(p2_solutions)}")
    if all_fp_24_qgs:
        print(f"Unique 24/24 false positives: {len(all_fp_24_qgs)}")
        print(f"False positive quadgram range: [{min(all_fp_24_qgs):.4f}, {max(all_fp_24_qgs):.4f}]")
    print(f"English quadgram benchmark: {mean_english_qg:.4f}")
    print(f"Random quadgram benchmark: {mean_random_qg:.4f}")
    print(f"Quadgram GAP (English - FP): "
          f"{mean_english_qg - (max(all_fp_24_qgs) if all_fp_24_qgs else mean_random_qg):.4f}")
    print(f"Runtime: {total_time:.1f}s")

    out_dir = "results/frac"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "e_frac_34_multi_objective_oracle.json")

    output = {
        "experiment": "E-FRAC-34",
        "title": "Multi-Objective Oracle Design for JTS",
        "runtime_seconds": round(total_time, 1),
        "benchmarks": {
            "english": {
                "quadgram_per_char": round(mean_english_qg, 4),
                "ic": round(mean_english_ic, 4),
                "word_coverage": round(mean_english_cov, 4),
            },
            "random": {
                "quadgram_per_char": round(mean_random_qg, 4),
                "ic": round(mean_random_ic, 4),
                "word_coverage": round(mean_random_cov, 4),
                "n_samples": n_random,
            },
            "k4_ct": {
                "quadgram_per_char": round(ct_qg, 4),
                "ic": round(ct_ic, 4),
                "word_coverage": round(ct_cov, 4),
            },
        },
        "false_positives": {
            "best_period": {
                "n_collected": len(best_period_solutions),
                "analysis": bp_analysis,
            },
            "period_5": {
                "n_collected": len(p5_solutions),
                "analysis": p5_analysis,
            },
            "period_2": {
                "n_collected": len(p2_solutions),
                "analysis": p2_analysis,
            },
        },
        "false_positive_24_quadgrams": sorted(all_fp_24_qgs) if all_fp_24_qgs else [],
        "recommended_thresholds": {
            "crib_score": 24,
            "bean_pass": True,
            "quadgram_per_char_min": -5.0,
            "ic_min": 0.055,
            "min_word_length": 6,
            "note": "All thresholds must be satisfied simultaneously. "
                    "Quadgram alone should discriminate if gap > 0.5/char.",
        },
        "gap_analysis": {
            "fp_best_quadgram": round(max(all_fp_24_qgs), 4) if all_fp_24_qgs else None,
            "english_mean_quadgram": round(mean_english_qg, 4),
            "gap_per_char": round(mean_english_qg - (max(all_fp_24_qgs)
                                  if all_fp_24_qgs else mean_random_qg), 4),
            "gap_sufficient": gap_exists,
        },
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")

    verdict = "ORACLE_DESIGNED" if gap_exists else "ORACLE_UNCERTAIN"
    print(f"\nRESULT: verdict={verdict} "
          f"fp_24={len(all_fp_24_qgs)} "
          f"gap={'sufficient' if gap_exists else 'uncertain'}")


if __name__ == "__main__":
    main()
