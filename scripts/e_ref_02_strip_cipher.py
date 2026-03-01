#!/usr/bin/env python3
"""
E-REF-02: Physical Strip Cipher Model

Sanborn repeatedly describes working with physical strips:
  - "I took the text... and cut it into strips in sentences" (oral history)
  - "I rearranged them all in a different order" (showing PT to CIA analysts)
  - "Two systems of enciphering the bottom text" (dedication speech)
  - Scheidt: "systems that didn't necessarily depend on mathematics"

Hypothesis: K4 was encrypted by:
  1. Writing plaintext on N physical strips of equal or varying lengths
  2. Rearranging the strips in a different order (physical transposition)
  3. Applying Vigenère/Beaufort from the tableau (second system)

This differs from standard columnar transposition because:
  - Strips may be of UNEQUAL length (Sanborn cut "in sentences")
  - The "column" reading direction might vary per strip
  - Strips could be read alternately forward/backward
  - The key might be applied BEFORE strip rearrangement

This script models several strip configurations:
  Model A: Equal-length strips (≈ columnar), all permutations
  Model B: "Sentence-like" strips (unequal, 7-15 chars each)
  Model C: Strips from an 8-row grid read in various directions
  Model D: Interleaved strips (deal cards into N piles)

For each model, strips are permuted and Vig/Beau consistency is checked.

Output: results/e_ref_02_strip_cipher.json
"""

import json
import sys
import os
import time
import random
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

BEAN_EQ = (27, 65)


def score_transposition(perm, variant="vig"):
    """Score a transposition permutation combined with crib constraints.

    perm: CT[i] was produced from PT[perm[i]]
    To decrypt: PT[perm[i]] = f(CT[i], key[perm[i]])

    For each crib position j (known PT[j]):
      Find CT position where perm[ct_pos] = j, i.e., ct_pos = perm_inv[j]
      Then: key[j] = (CT[perm_inv[j]] ± PT[j]) mod 26

    Check periodic key consistency across crib positions.
    """
    # Build inverse: pt_pos -> ct_pos
    perm_inv = [0] * N
    for i in range(N):
        perm_inv[perm[i]] = i

    keys = {}
    for j in CRIB_POS:
        ct_pos = perm_inv[j]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT[j]

        if variant == "vig":
            keys[j] = (ct_val - pt_val) % MOD
        elif variant == "beau":
            keys[j] = (ct_val + pt_val) % MOD
        else:
            keys[j] = (pt_val - ct_val) % MOD

    # Bean equality
    bean_eq = keys.get(BEAN_EQ[0]) == keys.get(BEAN_EQ[1])

    # Quick Bean filter: if not equal, skip expensive period search
    if not bean_eq:
        return 0, False

    # Best periodic score — only periods 1-7 are meaningful discriminators
    # (~8.2/24 expected random). Periods >= 8 are underdetermined.
    best_score = 0
    for period in range(1, 8):
        score = 0
        residues = {}
        for j in CRIB_POS:
            r = j % period
            if r not in residues:
                residues[r] = keys[j]
                score += 1
            elif residues[r] == keys[j]:
                score += 1
        best_score = max(best_score, score)

    return best_score, bean_eq


def strips_to_perm(strips):
    """Convert a list of strips (each a list of original positions) to a perm.

    The ciphertext was produced by concatenating strips in the given order.
    CT[0..len(strip0)-1] = encrypted(PT[strip0[0]], PT[strip0[1]], ...)
    CT[len(strip0)..] = encrypted(PT[strip1[0]], ...)

    So: perm[ct_pos] = pt_pos, where ct_pos is the position in concatenated output.
    """
    perm = []
    for strip in strips:
        perm.extend(strip)
    return perm


def generate_equal_strips(n, num_strips):
    """Generate equal-length strips (standard columnar model).

    Write positions row-by-row into a grid with num_strips columns,
    then each column is a strip.
    """
    width = num_strips
    rows = (n + width - 1) // width
    n_long = n % width
    if n_long == 0:
        n_long = width

    strips = []
    for col in range(width):
        strip = []
        for row in range(rows):
            pos = row * width + col
            if pos < n:
                strip.append(pos)
        strips.append(strip)
    return strips


def generate_interleaved_strips(n, num_strips):
    """Deal positions round-robin into strips (like dealing cards).

    Position 0 → strip 0, position 1 → strip 1, ..., position num_strips → strip 0, etc.
    """
    strips = [[] for _ in range(num_strips)]
    for i in range(n):
        strips[i % num_strips].append(i)
    return strips


def generate_block_strips(n, block_sizes):
    """Generate strips of specified sizes as contiguous blocks.

    E.g., block_sizes = [13, 13, 13, 13, 13, 13, 13, 6]
    Strip 0 = positions [0..12], strip 1 = [13..25], etc.
    """
    strips = []
    pos = 0
    for size in block_sizes:
        strip = list(range(pos, min(pos + size, n)))
        if strip:
            strips.append(strip)
        pos += size
    return strips


def generate_reverse_strips(strips):
    """Generate variant where alternating strips are reversed."""
    new_strips = []
    for i, strip in enumerate(strips):
        if i % 2 == 1:
            new_strips.append(list(reversed(strip)))
        else:
            new_strips.append(strip)
    return new_strips


def main():
    print("=" * 60)
    print("E-REF-02: Physical Strip Cipher Model")
    print("=" * 60)
    print('  "I took the text and cut it into strips" — Sanborn')
    print()

    t0 = time.time()
    all_results = []
    total_configs = 0
    random.seed(42)

    variants = ["vig", "beau", "varbeau"]

    # ========================================================
    # Model A: Equal-length strips (N strips of width W)
    # This is columnar transposition but framed as strips
    # ========================================================
    print("MODEL A: Equal-width strips (columnar equivalent)")
    print("-" * 50)

    for num_strips in [7, 8, 9, 10, 11, 5, 6]:
        strips_base = generate_equal_strips(N, num_strips)
        n_perms = 1
        for i in range(2, num_strips + 1):
            n_perms *= i

        if n_perms > 5_000_000:
            print(f"  {num_strips} strips: {n_perms:,} perms — sampling 500K")
            sample_size = 500_000
            orderings = []
            base_order = list(range(num_strips))
            orderings.append(tuple(base_order))
            orderings.append(tuple(range(num_strips - 1, -1, -1)))
            for _ in range(sample_size - 2):
                random.shuffle(base_order)
                orderings.append(tuple(base_order))
            orderings = list(set(orderings))
        else:
            orderings = list(permutations(range(num_strips)))
            print(f"  {num_strips} strips: {len(orderings):,} perms (exhaustive)")

        best_score = 0
        hits = 0

        for order in orderings:
            ordered_strips = [strips_base[i] for i in order]

            # Test forward and serpentine (alternating reverse)
            for strip_variant_name, sv_strips in [
                ("fwd", ordered_strips),
                ("serp", generate_reverse_strips(ordered_strips))
            ]:
                perm = strips_to_perm(sv_strips)

                for variant in variants:
                    total_configs += 1
                    score, bean_eq = score_transposition(perm, variant)

                    if score > best_score:
                        best_score = score

                    if score >= 18 and bean_eq:
                        hits += 1
                        result = {
                            "model": "A_equal",
                            "num_strips": num_strips,
                            "order": list(order),
                            "strip_variant": strip_variant_name,
                            "cipher_variant": variant,
                            "score": score,
                            "bean_eq": True,
                        }
                        all_results.append(result)
                        print(f"    HIT: n={num_strips} {variant} {strip_variant_name} "
                              f"order={list(order)} score={score}/24")

        print(f"  {num_strips} strips: best={best_score}/24, hits≥18+Bean={hits}")
        elapsed = time.time() - t0
        print(f"    [{elapsed:.0f}s] {total_configs:,} total", flush=True)

    # ========================================================
    # Model B: Interleaved strips (card-dealing model)
    # ========================================================
    print(f"\nMODEL B: Interleaved strips (card-dealing)")
    print("-" * 50)

    for num_strips in [7, 8, 9, 10, 11, 5, 6]:
        strips_base = generate_interleaved_strips(N, num_strips)
        n_perms = 1
        for i in range(2, num_strips + 1):
            n_perms *= i

        if n_perms > 5_000_000:
            print(f"  {num_strips} strips: sampling 500K of {n_perms:,}")
            sample_size = 500_000
            orderings = set()
            base_order = list(range(num_strips))
            while len(orderings) < sample_size:
                random.shuffle(base_order)
                orderings.add(tuple(base_order))
            orderings = list(orderings)
        else:
            orderings = list(permutations(range(num_strips)))
            print(f"  {num_strips} strips: {len(orderings):,} perms (exhaustive)")

        best_score = 0
        hits = 0

        for order in orderings:
            ordered_strips = [strips_base[i] for i in order]

            for strip_variant_name, sv_strips in [
                ("fwd", ordered_strips),
                ("serp", generate_reverse_strips(ordered_strips))
            ]:
                perm = strips_to_perm(sv_strips)
                for variant in variants:
                    total_configs += 1
                    score, bean_eq = score_transposition(perm, variant)

                    if score > best_score:
                        best_score = score

                    if score >= 18 and bean_eq:
                        hits += 1
                        result = {
                            "model": "B_interleaved",
                            "num_strips": num_strips,
                            "order": list(order),
                            "strip_variant": strip_variant_name,
                            "cipher_variant": variant,
                            "score": score,
                            "bean_eq": True,
                        }
                        all_results.append(result)
                        print(f"    HIT: n={num_strips} {variant} {strip_variant_name} "
                              f"order={list(order)} score={score}/24")

        print(f"  {num_strips} strips: best={best_score}/24, hits≥18+Bean={hits}")

    # ========================================================
    # Model C: Block strips (contiguous, "sentence-like")
    # ========================================================
    print(f"\nMODEL C: Contiguous block strips (sentence-like cuts)")
    print("-" * 50)

    # Generate various "sentence-like" partitions of 97
    # These simulate cutting text into sentence-sized strips
    block_configs = [
        # 8 rows matching "8 Lines" hypothesis
        [13, 13, 13, 13, 13, 13, 13, 6],   # 7×13 + 1×6 = 97
        [12, 12, 12, 12, 12, 12, 12, 13],  # 7×12 + 1×13 = 97
        [13, 12, 13, 12, 13, 12, 13, 9],   # alternating 13/12 + 9
        # Various "natural" sentence lengths
        [10, 10, 10, 10, 10, 10, 10, 10, 9, 8],  # 10 strips
        [15, 14, 13, 12, 11, 10, 9, 8, 5],  # decreasing
        [8, 10, 12, 14, 12, 10, 8, 12, 11],  # wave
        [11, 11, 11, 11, 11, 11, 11, 11, 9],  # 9 strips
        [14, 14, 14, 14, 14, 14, 13],  # 7 strips
        [16, 16, 16, 16, 16, 17],  # 6 strips
        [19, 20, 19, 20, 19],  # 5 strips
        # Specific to K4 structure
        [21, 13, 29, 11, 23],  # crib-boundary aligned
        [21, 42, 34],  # three blocks (pre-crib, mid, post-crib)
    ]

    for block_sizes in block_configs:
        if sum(block_sizes) != N:
            # Adjust last block
            block_sizes = list(block_sizes)
            diff = N - sum(block_sizes)
            block_sizes[-1] += diff
            if block_sizes[-1] <= 0:
                continue

        strips = generate_block_strips(N, block_sizes)
        num_strips = len(strips)
        n_perms = 1
        for i in range(2, num_strips + 1):
            n_perms *= i

        if n_perms > 5_000_000:
            print(f"  Blocks {block_sizes}: {n_perms:,} perms — sampling 500K")
            orderings = set()
            base_order = list(range(num_strips))
            while len(orderings) < min(500_000, n_perms):
                random.shuffle(base_order)
                orderings.add(tuple(base_order))
            orderings = list(orderings)
        else:
            orderings = list(permutations(range(num_strips)))
            print(f"  Blocks {block_sizes}: {len(orderings):,} perms")

        best_score = 0
        hits = 0

        for order in orderings:
            ordered_strips = [strips[i] for i in order]
            for sv_name, sv_strips in [
                ("fwd", ordered_strips),
                ("serp", generate_reverse_strips(ordered_strips))
            ]:
                perm = strips_to_perm(sv_strips)
                for variant in variants:
                    total_configs += 1
                    score, bean_eq = score_transposition(perm, variant)

                    if score > best_score:
                        best_score = score

                    if score >= 18 and bean_eq:
                        hits += 1
                        result = {
                            "model": "C_block",
                            "block_sizes": block_sizes,
                            "order": list(order),
                            "strip_variant": sv_name,
                            "cipher_variant": variant,
                            "score": score,
                            "bean_eq": True,
                        }
                        all_results.append(result)
                        print(f"    HIT: blocks={block_sizes} {variant} "
                              f"order={list(order)} score={score}/24")

        print(f"  Blocks {block_sizes}: best={best_score}/24, hits≥18+Bean={hits}")

    # ========================================================
    # Model D: Random strip partitions (Monte Carlo exploration)
    # ========================================================
    print(f"\nMODEL D: Random strip partitions (Monte Carlo)")
    print("-" * 50)

    mc_samples = 1_000_000
    best_mc_score = 0
    mc_hits = 0

    for _ in range(mc_samples):
        # Generate random partition of 97 into 3-12 strips
        num_strips = random.randint(3, 12)
        # Random breakpoints
        breaks = sorted(random.sample(range(1, N), num_strips - 1))
        block_sizes = []
        prev = 0
        for b in breaks:
            block_sizes.append(b - prev)
            prev = b
        block_sizes.append(N - prev)

        strips = generate_block_strips(N, block_sizes)

        # Random ordering
        order = list(range(num_strips))
        random.shuffle(order)
        ordered_strips = [strips[i] for i in order]

        # Random forward/reverse per strip
        for i in range(len(ordered_strips)):
            if random.random() < 0.5:
                ordered_strips[i] = list(reversed(ordered_strips[i]))

        perm = strips_to_perm(ordered_strips)

        for variant in variants:
            total_configs += 1
            score, bean_eq = score_transposition(perm, variant)

            if score > best_mc_score:
                best_mc_score = score

            if score >= 18 and bean_eq:
                mc_hits += 1
                result = {
                    "model": "D_random",
                    "block_sizes": block_sizes,
                    "order": order,
                    "cipher_variant": variant,
                    "score": score,
                    "bean_eq": True,
                }
                all_results.append(result)
                print(f"    HIT: blocks={block_sizes} {variant} "
                      f"order={order} score={score}/24")

    print(f"  {mc_samples:,} random partitions × 3 variants: "
          f"best={best_mc_score}/24, hits≥18+Bean={mc_hits}")

    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total configs: {total_configs:,}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Hits ≥18 + Bean PASS: {len(all_results)}")

    if all_results:
        all_results.sort(key=lambda r: -r['score'])
        for r in all_results[:10]:
            model = r.get('model', '?')
            print(f"    {model}: score={r['score']}/24 {r.get('cipher_variant', '?')}")

    verdict = "SIGNAL" if any(r['score'] >= 18 and r.get('bean_eq') for r in all_results) else "NOISE"
    print(f"\n  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment": "E-REF-02",
        "description": "Physical strip cipher model from Sanborn oral history",
        "hypothesis": "K4 encrypted via physical strip rearrangement + Vigenère",
        "models": ["A_equal", "B_interleaved", "C_block", "D_random"],
        "total_configs": total_configs,
        "hits": len(all_results),
        "verdict": verdict,
        "top_results": all_results[:20],
        "elapsed_seconds": round(elapsed, 1),
    }
    with open("results/e_ref_02_strip_cipher.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_ref_02_strip_cipher.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_ref_02_strip_cipher.py")


if __name__ == "__main__":
    main()
