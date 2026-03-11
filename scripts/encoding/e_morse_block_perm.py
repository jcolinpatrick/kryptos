#!/usr/bin/env python3
"""
Cipher: encoding/transposition
Family: encoding
Status: active
Keyspace: ~10^12 (variable-width block permutations, greedy optimization)
Last run:
Best score:
"""
"""Attack #1: Morse E-Group Block Permutation on K4.

Hypothesis: The 26 extra E's in Kryptos Morse code (K0) appear in groups of
sizes [2,1,5,1,3,2,2,5,3,1,1]. These define variable-width transposition
blocks for K4. Apply them cyclically as block boundaries to the 97-char CT,
permute within each block, then try Vigenere/Beaufort decryption.

Also tests word-length partitions from the K0 decoded messages.

Uses greedy block-by-block optimization to handle the large search space.
"""

import sys
import os
import json
import math
import time
import random
from itertools import permutations, product
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH_IDX, ALPH, MOD
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant,
)
from kryptos.kernel.scoring.free_crib import score_free, CRIB_ENE, CRIB_BC
from kryptos.kernel.scoring.ngram import NgramScorer


# ── Constants ─────────────────────────────────────────────────────────────

E_GROUP_SIZES = [2, 1, 5, 1, 3, 2, 2, 5, 3, 1, 1]  # sum=26
K0_WORD_SIZES = [9, 9, 7, 13, 6, 6, 5, 6, 1, 2, 4, 8, 3, 2]  # sum=81

KEYWORDS = ["KRYPTOS", "KOMPASS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "COLOPHON"]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

QUADGRAM_PATH = os.path.join(
    os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json'
)


# ── Helpers ───────────────────────────────────────────────────────────────

def keyword_to_nums(kw: str) -> list:
    """Convert keyword string to numeric key."""
    return [ord(c) - 65 for c in kw.upper()]


def partition_into_blocks(text: str, block_sizes: list) -> list:
    """Partition text into blocks using sizes applied cyclically.

    Returns list of (start_idx, block_string) tuples.
    """
    blocks = []
    pos = 0
    size_idx = 0
    while pos < len(text):
        bsize = block_sizes[size_idx % len(block_sizes)]
        end = min(pos + bsize, len(text))
        blocks.append((pos, text[pos:end]))
        pos = end
        size_idx += 1
    return blocks


def apply_block_permutation(text: str, blocks: list, perm_per_block: list) -> str:
    """Apply a permutation to each block and reconstruct the text.

    blocks: list of (start_idx, block_str)
    perm_per_block: list of tuples, one per block. perm[i] = tuple of indices
        representing the permutation for that block.
    """
    result = list(text)
    for (start, block_str), perm in zip(blocks, perm_per_block):
        for out_pos, src_pos in enumerate(perm):
            result[start + out_pos] = block_str[src_pos]
    return "".join(result)


def check_crib(text: str) -> tuple:
    """Quick check for crib substrings. Returns (ene_found, bc_found, ene_pos, bc_pos)."""
    ene_pos = text.find(CRIB_ENE)
    bc_pos = text.find(CRIB_BC)
    return (ene_pos >= 0, bc_pos >= 0, ene_pos, bc_pos)


def get_all_perms_for_size(n: int) -> list:
    """Get all permutations for a block of size n."""
    return list(permutations(range(n)))


def get_sampled_perms_for_size(n: int, count: int = 1000) -> list:
    """Get a random sample of permutations for block of size n."""
    if math.factorial(n) <= count:
        return list(permutations(range(n)))
    seen = set()
    result = [tuple(range(n))]  # always include identity
    seen.add(result[0])
    while len(result) < count:
        p = list(range(n))
        random.shuffle(p)
        tp = tuple(p)
        if tp not in seen:
            seen.add(tp)
            result.append(tp)
    return result


# ── Greedy Block Optimization ────────────────────────────────────────────

def greedy_optimize(text: str, blocks: list, key_nums: list,
                    variant: CipherVariant, scorer: NgramScorer,
                    max_rounds: int = 5) -> tuple:
    """Greedy optimization: iterate over blocks, finding best perm for each
    while holding others fixed. Repeat for max_rounds or until no improvement.

    Returns (best_score, best_plaintext, best_perms, method_str).
    """
    n_blocks = len(blocks)

    # Start with identity permutation for all blocks
    current_perms = [tuple(range(len(b))) for _, b in blocks]

    # Precompute candidate permutations for each block
    block_perm_options = []
    for _, block_str in blocks:
        bsize = len(block_str)
        if bsize <= 5:
            block_perm_options.append(get_all_perms_for_size(bsize))
        elif bsize <= 9:
            block_perm_options.append(get_sampled_perms_for_size(bsize, 1000))
        else:
            block_perm_options.append(get_sampled_perms_for_size(bsize, 500))

    # Score initial (identity) configuration
    reordered = apply_block_permutation(text, blocks, current_perms)
    pt = decrypt_text(reordered, key_nums, variant)
    best_score = scorer.score_per_char(pt)
    best_pt = pt
    best_perms = list(current_perms)

    for round_num in range(max_rounds):
        improved = False
        for bi in range(n_blocks):
            if len(blocks[bi][1]) <= 1:
                continue  # size-1 blocks: identity is the only option

            best_block_score = best_score
            best_block_perm = current_perms[bi]

            for perm in block_perm_options[bi]:
                trial_perms = list(current_perms)
                trial_perms[bi] = perm
                reordered = apply_block_permutation(text, blocks, trial_perms)
                pt = decrypt_text(reordered, key_nums, variant)
                sc = scorer.score_per_char(pt)

                # Check cribs
                ene_found, bc_found, ene_pos, bc_pos = check_crib(pt)
                if ene_found or bc_found:
                    print(f"  *** CRIB HIT *** ENE={ene_found}@{ene_pos} BC={bc_found}@{bc_pos}")
                    print(f"      PT: {pt}")
                    print(f"      Score: {sc:.4f}")

                if sc > best_block_score:
                    best_block_score = sc
                    best_block_perm = perm

            if best_block_perm != current_perms[bi]:
                current_perms[bi] = best_block_perm
                best_score = best_block_score
                reordered = apply_block_permutation(text, blocks, current_perms)
                best_pt = decrypt_text(reordered, key_nums, variant)
                improved = True

        if not improved:
            break

    return best_score, best_pt, current_perms, round_num + 1


# ── Exhaustive Small-Config Search ───────────────────────────────────────

def exhaustive_search(text: str, blocks: list, key_nums: list,
                      variant: CipherVariant, scorer: NgramScorer,
                      keyword: str, variant_name: str,
                      partition_name: str, top_results: list,
                      max_configs: int = 500_000) -> int:
    """Exhaustive search when total config space is small enough.

    For each block, generate all permutations (size <=5) or sampled perms.
    Use itertools.product for total enumeration.

    Returns number of configs tested.
    """
    # Precompute candidate permutations for each block
    block_perm_options = []
    total_space = 1
    for _, block_str in blocks:
        bsize = len(block_str)
        if bsize <= 1:
            perms = [tuple(range(bsize))]
        elif bsize <= 5:
            perms = get_all_perms_for_size(bsize)
        else:
            perms = get_sampled_perms_for_size(bsize, 200)
        block_perm_options.append(perms)
        total_space *= len(perms)

    if total_space > max_configs:
        return -1  # too large for exhaustive; caller should use greedy

    configs_tested = 0
    for combo in product(*block_perm_options):
        reordered = apply_block_permutation(text, blocks, list(combo))
        pt = decrypt_text(reordered, key_nums, variant)
        sc = scorer.score_per_char(pt)

        # Check cribs
        ene_found, bc_found, ene_pos, bc_pos = check_crib(pt)
        if ene_found or bc_found:
            print(f"  *** CRIB HIT *** ENE={ene_found}@{ene_pos} BC={bc_found}@{bc_pos}")
            print(f"      PT: {pt}")
            print(f"      Score: {sc:.4f}")
            print(f"      Method: {partition_name} | {keyword} | {variant_name}")

        # Track top results
        method = f"{partition_name} | {keyword} | {variant_name}"
        if len(top_results) < 20 or sc > top_results[-1][0]:
            top_results.append((sc, pt, method))
            top_results.sort(key=lambda x: -x[0])
            if len(top_results) > 20:
                top_results.pop()

        configs_tested += 1
        if configs_tested % 10000 == 0:
            print(f"  [{partition_name}|{keyword}|{variant_name}] "
                  f"{configs_tested}/{total_space} configs... "
                  f"best so far: {top_results[0][0]:.4f}")

    return configs_tested


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 78)
    print("ATTACK #1: Morse E-Group Block Permutation on K4")
    print("=" * 78)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"E-group sizes: {E_GROUP_SIZES} (sum={sum(E_GROUP_SIZES)})")
    print(f"K0 word sizes: {K0_WORD_SIZES} (sum={sum(K0_WORD_SIZES)})")
    print(f"Keywords: {KEYWORDS}")
    print(f"Cipher variants: Vigenere, Beaufort, Variant Beaufort")
    print()

    # Load quadgram scorer
    print(f"Loading quadgram data from {QUADGRAM_PATH}...")
    scorer = NgramScorer.from_file(QUADGRAM_PATH)
    print("Quadgram scorer loaded.")
    print()

    # Define partition schemes
    partitions = {
        "E-groups (cyclic)": E_GROUP_SIZES,
        "E-groups (reversed cyclic)": list(reversed(E_GROUP_SIZES)),
        "K0 words": K0_WORD_SIZES,
        "K0 words (reversed)": list(reversed(K0_WORD_SIZES)),
    }

    top_results = []  # (score, plaintext, method)
    total_configs = 0
    total_greedy_runs = 0
    crib_hits = []

    t_start = time.time()

    for part_name, block_sizes in partitions.items():
        print(f"\n{'─' * 70}")
        print(f"Partition: {part_name}")
        print(f"Block sizes: {block_sizes}")

        blocks = partition_into_blocks(CT, block_sizes)
        print(f"Number of blocks: {len(blocks)}")
        block_lengths = [len(b) for _, b in blocks]
        print(f"Actual block lengths: {block_lengths}")

        # Compute total exhaustive space
        total_space = 1
        for _, block_str in blocks:
            bsize = len(block_str)
            if bsize <= 1:
                total_space *= 1
            elif bsize <= 5:
                total_space *= math.factorial(bsize)
            else:
                total_space *= min(math.factorial(bsize), 1000)
        print(f"Total permutation space (capped): {total_space:,}")

        for keyword in KEYWORDS:
            key_nums = keyword_to_nums(keyword)

            for variant in VARIANTS:
                variant_name = variant.value
                method_prefix = f"{part_name} | {keyword} | {variant_name}"

                # Decide: exhaustive or greedy
                if total_space <= 500_000:
                    # Exhaustive search
                    print(f"\n  [EXHAUSTIVE] {method_prefix} ({total_space:,} configs)")
                    n_tested = exhaustive_search(
                        CT, blocks, key_nums, variant, scorer,
                        keyword, variant_name, part_name,
                        top_results, max_configs=500_000
                    )
                    if n_tested > 0:
                        total_configs += n_tested
                        print(f"  Done: {n_tested:,} configs tested")
                else:
                    # Greedy optimization
                    print(f"\n  [GREEDY] {method_prefix} (space too large: {total_space:,})")
                    best_sc, best_pt, best_perms, rounds = greedy_optimize(
                        CT, blocks, key_nums, variant, scorer, max_rounds=5
                    )
                    total_greedy_runs += 1

                    method = f"{part_name} | {keyword} | {variant_name} [greedy-{rounds}r]"
                    if len(top_results) < 20 or best_sc > top_results[-1][0]:
                        top_results.append((best_sc, best_pt, method))
                        top_results.sort(key=lambda x: -x[0])
                        if len(top_results) > 20:
                            top_results.pop()

                    print(f"  Greedy result: {best_sc:.4f} | {best_pt[:50]}...")

                    # Check cribs on greedy result
                    ene_found, bc_found, ene_pos, bc_pos = check_crib(best_pt)
                    if ene_found or bc_found:
                        print(f"  *** CRIB HIT *** ENE={ene_found}@{ene_pos} BC={bc_found}@{bc_pos}")
                        crib_hits.append((best_sc, best_pt, method))

                    # Also do random restarts for greedy
                    n_restarts = 10
                    for restart_i in range(n_restarts):
                        # Random initial permutation
                        init_perms = []
                        for _, block_str in blocks:
                            bsize = len(block_str)
                            if bsize <= 1:
                                init_perms.append((0,))
                            else:
                                p = list(range(bsize))
                                random.shuffle(p)
                                init_perms.append(tuple(p))

                        # Set as starting point and optimize
                        # (Manually set initial perms in greedy)
                        n_blocks = len(blocks)
                        current_perms = list(init_perms)

                        block_perm_options = []
                        for _, block_str in blocks:
                            bsize = len(block_str)
                            if bsize <= 5:
                                block_perm_options.append(get_all_perms_for_size(bsize))
                            elif bsize <= 9:
                                block_perm_options.append(get_sampled_perms_for_size(bsize, 500))
                            else:
                                block_perm_options.append(get_sampled_perms_for_size(bsize, 200))

                        reordered = apply_block_permutation(CT, blocks, current_perms)
                        pt = decrypt_text(reordered, key_nums, variant)
                        cur_score = scorer.score_per_char(pt)

                        for _ in range(3):  # 3 rounds
                            improved = False
                            for bi in range(n_blocks):
                                if len(blocks[bi][1]) <= 1:
                                    continue
                                best_bi_score = cur_score
                                best_bi_perm = current_perms[bi]
                                for perm in block_perm_options[bi]:
                                    trial_perms = list(current_perms)
                                    trial_perms[bi] = perm
                                    reordered = apply_block_permutation(CT, blocks, trial_perms)
                                    pt = decrypt_text(reordered, key_nums, variant)
                                    sc = scorer.score_per_char(pt)

                                    ef, bf, ep, bp = check_crib(pt)
                                    if ef or bf:
                                        print(f"  *** CRIB HIT (restart {restart_i}) *** "
                                              f"ENE={ef}@{ep} BC={bf}@{bp}")
                                        print(f"      PT: {pt}")
                                        crib_hits.append((sc, pt, method + f" restart-{restart_i}"))

                                    if sc > best_bi_score:
                                        best_bi_score = sc
                                        best_bi_perm = perm

                                if best_bi_perm != current_perms[bi]:
                                    current_perms[bi] = best_bi_perm
                                    cur_score = best_bi_score
                                    improved = True
                            if not improved:
                                break

                        reordered = apply_block_permutation(CT, blocks, current_perms)
                        pt = decrypt_text(reordered, key_nums, variant)

                        if len(top_results) < 20 or cur_score > top_results[-1][0]:
                            rmethod = f"{method} restart-{restart_i}"
                            top_results.append((cur_score, pt, rmethod))
                            top_results.sort(key=lambda x: -x[0])
                            if len(top_results) > 20:
                                top_results.pop()

    elapsed = time.time() - t_start

    # ── Also try: no decryption, just permutation (maybe CT is already substituted) ──
    print(f"\n{'─' * 70}")
    print("Testing permutation-only (no decryption layer)")
    for part_name, block_sizes in partitions.items():
        blocks = partition_into_blocks(CT, block_sizes)

        # Compute space
        total_space = 1
        for _, block_str in blocks:
            bsize = len(block_str)
            if bsize <= 1:
                total_space *= 1
            elif bsize <= 5:
                total_space *= math.factorial(bsize)
            else:
                total_space *= min(math.factorial(bsize), 1000)

        if total_space <= 500_000:
            print(f"\n  [EXHAUSTIVE] {part_name} | no-decrypt ({total_space:,} configs)")
            block_perm_options = []
            for _, block_str in blocks:
                bsize = len(block_str)
                if bsize <= 1:
                    block_perm_options.append([tuple(range(bsize))])
                elif bsize <= 5:
                    block_perm_options.append(get_all_perms_for_size(bsize))
                else:
                    block_perm_options.append(get_sampled_perms_for_size(bsize, 200))

            configs_tested = 0
            for combo in product(*block_perm_options):
                reordered = apply_block_permutation(CT, blocks, list(combo))
                sc = scorer.score_per_char(reordered)

                ene_found, bc_found, ene_pos, bc_pos = check_crib(reordered)
                if ene_found or bc_found:
                    print(f"  *** CRIB HIT (no decrypt) *** ENE={ene_found}@{ene_pos} "
                          f"BC={bc_found}@{bc_pos}")
                    print(f"      Text: {reordered}")
                    crib_hits.append((sc, reordered, f"{part_name} | no-decrypt"))

                method = f"{part_name} | no-decrypt"
                if len(top_results) < 20 or sc > top_results[-1][0]:
                    top_results.append((sc, reordered, method))
                    top_results.sort(key=lambda x: -x[0])
                    if len(top_results) > 20:
                        top_results.pop()

                configs_tested += 1
                if configs_tested % 10000 == 0:
                    print(f"  [{part_name}|no-decrypt] {configs_tested}/{total_space} configs...")

            total_configs += configs_tested
            print(f"  Done: {configs_tested:,} configs tested")
        else:
            print(f"\n  [GREEDY] {part_name} | no-decrypt (space: {total_space:,})")
            # Greedy without decryption
            n_blocks = len(blocks)
            current_perms = [tuple(range(len(b))) for _, b in blocks]

            block_perm_options = []
            for _, block_str in blocks:
                bsize = len(block_str)
                if bsize <= 5:
                    block_perm_options.append(get_all_perms_for_size(bsize))
                elif bsize <= 9:
                    block_perm_options.append(get_sampled_perms_for_size(bsize, 500))
                else:
                    block_perm_options.append(get_sampled_perms_for_size(bsize, 200))

            reordered = apply_block_permutation(CT, blocks, current_perms)
            best_score = scorer.score_per_char(reordered)

            for _ in range(5):
                improved = False
                for bi in range(n_blocks):
                    if len(blocks[bi][1]) <= 1:
                        continue
                    best_bi_sc = best_score
                    best_bi_p = current_perms[bi]
                    for perm in block_perm_options[bi]:
                        trial = list(current_perms)
                        trial[bi] = perm
                        reordered = apply_block_permutation(CT, blocks, trial)
                        sc = scorer.score_per_char(reordered)

                        ef, bf, ep, bp = check_crib(reordered)
                        if ef or bf:
                            print(f"  *** CRIB HIT (no-decrypt, greedy) ***")
                            print(f"      Text: {reordered}")
                            crib_hits.append((sc, reordered, f"{part_name} | no-decrypt | greedy"))

                        if sc > best_bi_sc:
                            best_bi_sc = sc
                            best_bi_p = perm
                    if best_bi_p != current_perms[bi]:
                        current_perms[bi] = best_bi_p
                        best_score = best_bi_sc
                        improved = True
                if not improved:
                    break

            reordered = apply_block_permutation(CT, blocks, current_perms)
            method = f"{part_name} | no-decrypt | greedy"
            if len(top_results) < 20 or best_score > top_results[-1][0]:
                top_results.append((best_score, reordered, method))
                top_results.sort(key=lambda x: -x[0])
                if len(top_results) > 20:
                    top_results.pop()
            print(f"  Greedy result: {best_score:.4f} | {reordered[:50]}...")

    elapsed_total = time.time() - t_start

    # ── Report ────────────────────────────────────────────────────────────
    print()
    print("=" * 78)
    print("FINAL RESULTS")
    print("=" * 78)
    print(f"Total exhaustive configs tested: {total_configs:,}")
    print(f"Total greedy runs: {total_greedy_runs}")
    print(f"Total time: {elapsed_total:.1f}s")
    print()

    if crib_hits:
        print("CRIB HITS FOUND:")
        for sc, pt, method in crib_hits:
            print(f"  Score: {sc:.4f} | {pt[:60]}...")
            print(f"  Method: {method}")
            free_result = score_free(pt)
            print(f"  Free crib: {free_result.summary}")
        print()
    else:
        print("No crib hits found.")
        print()

    print("TOP 20 BY QUADGRAM SCORE:")
    print(f"{'Rank':>4}  {'Score':>8}  {'Method':<55}  Plaintext")
    print("-" * 130)
    for i, (sc, pt, method) in enumerate(top_results[:20], 1):
        print(f"{i:4d}  {sc:8.4f}  {method:<55}  {pt[:40]}...")
        if i <= 5:
            # Full free crib analysis for top 5
            free_result = score_free(pt)
            print(f"      Free crib: {free_result.summary}")

    print()
    print("Done.")


if __name__ == "__main__":
    random.seed(42)
    main()
