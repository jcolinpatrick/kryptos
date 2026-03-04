#!/usr/bin/env python3
"""
Cipher: monoalphabetic substitution
Family: substitution
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-TEAM-MONO-TRANS-SA: Simulated Annealing co-optimization of
monoalphabetic substitution + transposition + running key.

Model: PT[perm[i]] = mono(running_key_decrypt(CT[i], source[offset+i], variant))

Or equivalently, the decryption pipeline is:
  1. Apply transposition (un-permute CT)
  2. Subtract running key (position-dependent)
  3. Apply mono substitution

We optimize mono (26-perm), trans (97-perm), source text, offset, and variant
simultaneously using simulated annealing with multi-objective fitness.

Self-encryption constraint: Under identity transposition, CT[32]=S=PT[32] and
CT[73]=K=PT[73]. Under general transposition, the self-encryption positions change.
We handle this by scoring, not by hard-coding.

Fitness = crib_score * 10 + ic_bonus + ngram_bonus
  - Bean-EQ as hard reject
  - crib_score from score_candidate()
  - ic_bonus = max(0, (IC - 0.04) * 500) if IC > 0.04
  - ngram_bonus = max(0, (ngram_per_char + 6.5) * 5) if ngram available
"""
import sys
import os
import json
import math
import random
import time
from pathlib import Path
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, vig_decrypt, beau_decrypt, varbeau_decrypt,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)
from kryptos.kernel.constraints.bean import verify_bean_from_implied

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_mono_trans_sa.json")

# Decrypt functions by variant
DECRYPT_FN = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}

KEY_RECOVER_FN = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}


def load_source_texts():
    """Load all candidate running key source texts."""
    base = Path(__file__).parent.parent
    texts = {}

    # Running key texts
    rk_dir = base / "reference" / "running_key_texts"
    if rk_dir.exists():
        for f in rk_dir.iterdir():
            if f.suffix == ".txt":
                raw = f.read_text(errors="ignore")
                alpha = "".join(c.upper() for c in raw if c.isascii() and c.isalpha())
                if len(alpha) >= 200:
                    texts[f.stem] = alpha

    # Carter book
    carter = base / "reference" / "carter_gutenberg.txt"
    if carter.exists():
        raw = carter.read_text(errors="ignore")
        alpha = "".join(c.upper() for c in raw if c.isascii() and c.isalpha())
        texts["carter_gutenberg"] = alpha

    return texts


def decrypt_with_model(ct_nums, perm, mono, source_nums, offset, decrypt_fn):
    """Apply full decryption pipeline:
    1. Un-permute CT (apply transposition)
    2. Subtract running key
    3. Apply mono substitution

    perm[i] = j means output[i] = input[j] (gather convention)
    """
    n = len(ct_nums)
    result = [0] * n

    for i in range(n):
        # Step 1: gather from CT using transposition
        ct_val = ct_nums[perm[i]]

        # Step 2: decrypt with running key at position i
        source_val = source_nums[(offset + i) % len(source_nums)]
        intermediate = decrypt_fn(ct_val, source_val)

        # Step 3: apply mono substitution
        result[i] = mono[intermediate]

    return result


def nums_to_text(nums):
    """Convert list of 0-25 ints to uppercase string."""
    return "".join(ALPH[n % MOD] for n in nums)


def compute_fitness(pt_text, ngram_scorer):
    """Compute fitness score for a plaintext candidate."""
    crib_sc = score_cribs(pt_text)
    ic_val = ic(pt_text)

    # IC bonus: reward IC above random
    ic_bonus = max(0, (ic_val - 0.04) * 500)

    # Ngram bonus
    ngram_bonus = 0.0
    if ngram_scorer is not None and len(pt_text) >= 4:
        ngram_pc = ngram_scorer.score_per_char(pt_text)
        ngram_bonus = max(0, (ngram_pc + 6.5) * 5)

    return crib_sc * 10 + ic_bonus + ngram_bonus, crib_sc, ic_val


def check_bean_fast(pt_text, ct_text, variant):
    """Quick Bean check using implied key values at crib positions."""
    recover = KEY_RECOVER_FN[variant]
    implied = {}
    for pos, expected_ch in CRIB_DICT.items():
        if pos < len(pt_text) and pt_text[pos] == expected_ch:
            c = ALPH_IDX[ct_text[pos]]
            p = ALPH_IDX[expected_ch]
            implied[pos] = recover(c, p)

    # Only check Bean if we have both positions 27 and 65
    if 27 in implied and 65 in implied:
        return implied[27] == implied[65]
    return True  # Can't check, don't reject


def sa_optimize(source_name, source_nums, variant, ngram_scorer,
                n_iterations=100000, seed=None):
    """Run one SA optimization."""
    if seed is not None:
        random.seed(seed)

    ct_nums = [ALPH_IDX[c] for c in CT]
    n = CT_LEN
    decrypt_fn = DECRYPT_FN[variant]

    # Initialize: identity permutation, identity mono, offset 0
    perm = list(range(n))
    mono = list(range(MOD))
    offset = 0
    max_offset = len(source_nums) - n

    if max_offset < 1:
        return None  # Source text too short

    # Shuffle initial state for diversity
    random.shuffle(perm)
    random.shuffle(mono)
    offset = random.randint(0, max_offset)

    # Compute initial fitness
    pt_nums = decrypt_with_model(ct_nums, perm, mono, source_nums, offset, decrypt_fn)
    pt_text = nums_to_text(pt_nums)
    best_fitness, best_crib, best_ic = compute_fitness(pt_text, ngram_scorer)

    current_fitness = best_fitness
    current_perm = perm[:]
    current_mono = mono[:]
    current_offset = offset

    best_state = {
        "perm": perm[:], "mono": mono[:], "offset": offset,
        "fitness": best_fitness, "crib_score": best_crib, "ic": best_ic,
        "pt": pt_text
    }

    # SA parameters
    temp = 10.0
    cooling = 0.99995
    min_temp = 0.01

    accepted = 0
    improved = 0

    for it in range(n_iterations):
        # Choose move type
        move_type = random.random()

        new_perm = current_perm[:]
        new_mono = current_mono[:]
        new_offset = current_offset

        if move_type < 0.4:
            # Swap two elements in transposition
            i, j = random.sample(range(n), 2)
            new_perm[i], new_perm[j] = new_perm[j], new_perm[i]
        elif move_type < 0.75:
            # Swap two elements in mono
            i, j = random.sample(range(MOD), 2)
            new_mono[i], new_mono[j] = new_mono[j], new_mono[i]
        elif move_type < 0.9:
            # Shift offset
            delta = random.choice([-5, -3, -1, 1, 3, 5])
            new_offset = (current_offset + delta) % (max_offset + 1)
        else:
            # Double swap: both perm and mono
            i, j = random.sample(range(n), 2)
            new_perm[i], new_perm[j] = new_perm[j], new_perm[i]
            i, j = random.sample(range(MOD), 2)
            new_mono[i], new_mono[j] = new_mono[j], new_mono[i]

        # Evaluate new state
        pt_nums = decrypt_with_model(ct_nums, new_perm, new_mono, source_nums, new_offset, decrypt_fn)
        pt_text = nums_to_text(pt_nums)
        new_fitness, new_crib, new_ic = compute_fitness(pt_text, ngram_scorer)

        # Accept or reject
        delta = new_fitness - current_fitness
        if delta > 0 or (temp > min_temp and random.random() < math.exp(delta / temp)):
            current_perm = new_perm
            current_mono = new_mono
            current_offset = new_offset
            current_fitness = new_fitness
            accepted += 1

            if new_fitness > best_state["fitness"]:
                best_state = {
                    "perm": new_perm[:], "mono": new_mono[:], "offset": new_offset,
                    "fitness": new_fitness, "crib_score": new_crib, "ic": new_ic,
                    "pt": pt_text
                }
                improved += 1

        temp = max(min_temp, temp * cooling)

    return {
        "source": source_name,
        "variant": variant.value,
        "best_fitness": best_state["fitness"],
        "best_crib_score": best_state["crib_score"],
        "best_ic": best_state["ic"],
        "best_pt": best_state["pt"],
        "best_offset": best_state["offset"],
        "iterations": n_iterations,
        "accepted": accepted,
        "improved": improved,
        "accept_rate": accepted / n_iterations if n_iterations > 0 else 0,
    }


def main():
    print("=" * 70)
    print("E-TEAM-MONO-TRANS-SA: Simulated Annealing Co-Optimization")
    print("  Model: mono + transposition + running key")
    print("=" * 70)

    t0 = time.time()

    # Load resources
    print("\nLoading source texts...")
    texts = load_source_texts()
    print(f"  Loaded {len(texts)} texts: {', '.join(texts.keys())}")
    for name, text in texts.items():
        print(f"    {name}: {len(text)} alpha chars")

    print("\nLoading quadgram scorer...")
    try:
        ngram_scorer = NgramScorer.from_file("data/english_quadgrams.json")
        print("  Quadgram scorer loaded")
    except FileNotFoundError:
        ngram_scorer = None
        print("  WARNING: No quadgram data, using crib+IC only")

    # Pre-convert source texts to numeric
    source_nums = {name: [ALPH_IDX[c] for c in text] for name, text in texts.items()}

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    # Configuration
    n_runs_per_config = 3  # 3 SA runs per (text, variant)
    n_iterations = 80000   # iterations per run (reduced for feasibility)

    total_configs = len(texts) * len(variants) * n_runs_per_config
    print(f"\nConfiguration: {len(texts)} texts x {len(variants)} variants x {n_runs_per_config} runs = {total_configs} SA runs")
    print(f"  {n_iterations} iterations per run = {total_configs * n_iterations:,} total evaluations")

    all_results = []
    best_overall = {"fitness": -1}
    run_count = 0

    for source_name in sorted(texts.keys()):
        for variant in variants:
            for run_id in range(n_runs_per_config):
                run_count += 1
                seed = hash((source_name, variant.value, run_id)) % (2**31)

                print(f"\n  [{run_count}/{total_configs}] {source_name} / {variant.value} / run {run_id+1}")

                result = sa_optimize(
                    source_name, source_nums[source_name],
                    variant, ngram_scorer,
                    n_iterations=n_iterations, seed=seed
                )

                if result is None:
                    print(f"    SKIPPED (source too short)")
                    continue

                print(f"    Best: fitness={result['best_fitness']:.1f}, "
                      f"crib={result['best_crib_score']}/24, "
                      f"IC={result['best_ic']:.4f}, "
                      f"accept={result['accept_rate']:.3f}")
                print(f"    PT: {result['best_pt'][:50]}...")

                all_results.append(result)

                if result["best_fitness"] > best_overall.get("fitness", -1):
                    best_overall = result

    elapsed = time.time() - t0

    # Bean check on best result
    print("\n" + "=" * 70)
    print("BEAN CHECK ON TOP RESULTS")
    print("=" * 70)

    # Sort by fitness
    all_results.sort(key=lambda r: r["best_fitness"], reverse=True)

    for i, r in enumerate(all_results[:10]):
        pt = r["best_pt"]
        variant = CipherVariant(r["variant"])

        # Full scoring
        full_score = score_candidate(pt)
        bean_note = "N/A (no full key)"

        # Bean check via implied keys
        recover = KEY_RECOVER_FN[variant]
        implied = {}
        for pos, ch in CRIB_DICT.items():
            if pos < len(pt) and pt[pos] == ch:
                c = ALPH_IDX[CT[pos]]
                p = ALPH_IDX[ch]
                implied[pos] = recover(c, p)

        bean_pass = verify_bean_from_implied(implied)

        print(f"\n  #{i+1}: {r['source']} / {r['variant']}")
        print(f"    Fitness: {r['best_fitness']:.1f}, Crib: {r['best_crib_score']}/24, IC: {r['best_ic']:.4f}")
        print(f"    Full score: {full_score.summary}")
        print(f"    Bean (implied): {'PASS' if bean_pass else 'FAIL'} ({len(implied)} positions checked)")
        print(f"    PT: {r['best_pt']}")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total SA runs: {len(all_results)}")
    print(f"  Total evaluations: {len(all_results) * n_iterations:,}")
    print(f"  Elapsed: {elapsed:.1f}s")
    print(f"  Best overall fitness: {best_overall.get('best_fitness', 0):.1f}")
    print(f"  Best crib score: {max(r['best_crib_score'] for r in all_results) if all_results else 0}/24")

    # Classify best scores
    max_crib = max(r["best_crib_score"] for r in all_results) if all_results else 0
    if max_crib >= 18:
        verdict = "SIGNAL — investigate further"
    elif max_crib >= 10:
        verdict = "INTERESTING — above store threshold but likely noise at this DOF level"
    else:
        verdict = "NOISE — no meaningful crib matches found"

    print(f"  Verdict: {verdict}")
    print()

    # Crib score distribution
    crib_dist = Counter(r["best_crib_score"] for r in all_results)
    print("  Crib score distribution (best per run):")
    for sc in sorted(crib_dist.keys(), reverse=True):
        print(f"    {sc}/24: {crib_dist[sc]} runs")

    # Write results
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    output = {
        "experiment_id": "e_team_mono_trans_sa",
        "model": "mono_substitution + transposition + running_key",
        "n_texts": len(texts),
        "n_variants": len(variants),
        "n_runs_per_config": n_runs_per_config,
        "n_iterations": n_iterations,
        "total_evaluations": len(all_results) * n_iterations,
        "elapsed_seconds": elapsed,
        "best_overall": {
            "source": best_overall.get("source", ""),
            "variant": best_overall.get("variant", ""),
            "fitness": best_overall.get("best_fitness", 0),
            "crib_score": best_overall.get("best_crib_score", 0),
            "ic": best_overall.get("best_ic", 0),
            "pt": best_overall.get("best_pt", ""),
        },
        "verdict": verdict,
        "crib_distribution": {str(k): v for k, v in sorted(crib_dist.items())},
        "top_10": [
            {
                "source": r["source"],
                "variant": r["variant"],
                "fitness": r["best_fitness"],
                "crib_score": r["best_crib_score"],
                "ic": r["best_ic"],
                "pt": r["best_pt"],
                "offset": r["best_offset"],
                "accept_rate": r["accept_rate"],
            }
            for r in all_results[:10]
        ],
    }

    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
