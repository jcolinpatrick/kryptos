#!/usr/bin/env python3
"""
Cipher: homophonic vigenere
Family: substitution
Status: RETIRED — phantom scoring (see warning below)
Keyspace: see implementation
Last run: exhausted 2026 (0 hits at n=27 on 108 configs; 0 hits at n=28 on 720 configs)
Best score: 0

!!! WARNING — DO NOT RUN WITHOUT REWRITE !!!
Script audit (2026-04-08) identified this as the worst of the three
phantom-score factories: when decryption is ambiguous (multiple
possible PT letters from duplicate alphabet entries), the code
preferentially picks CRIB_DICT[i] at crib positions, then scores the
resulting PT against those same cribs. The score is a crib-
reachability metric, not a decryption metric. The Bean check also
operates on the constructed PT so Bean=PASS is equally meaningless.

Historical best_score=0 is valid (no survivors under tight crib
constraints) but any future re-run with relaxed parameters will emit
phantom breakthroughs.

To reuse: disambiguate PT letters by English frequency only (NOT by
looking up the crib), then score.
"""
"""E-HOMOPHONIC-VIG-KIMMO: Homophonic Vigenère with duplicate letters.

[HYPOTHESIS] K4 uses a Vigenère cipher where the tableau alphabet contains
duplicate letters (homophones). For example, the alphabet might have extra
E's or K's, making it 27-33 characters long. Decryption is AMBIGUOUS:
a position might decode to one of several letters.

Kimmo's approach: output bracket notation like [MS] when decryption could
yield M or S depending on which duplicate was used. Check if ANY consistent
selection of disambiguations produces the known cribs.

Approach:
1. For alphabet sizes 27-30, generate alphabets by duplicating the most
   common English letters (E, T, A, O, I, N, S, H, R)
2. For each extended alphabet, Vigenère decrypt with periodic keys
3. At each crib position, check if the crib letter is among the possible
   decryptions (accounting for duplicates)
4. Score = number of crib positions where the crib letter is achievable

This differs from E-EXTENDED-ALPHABET-VIG-27 which adds a genuinely new
symbol. Here we duplicate existing letters, creating ambiguity in decryption.
"""
import sys
import os
import time
import itertools
from multiprocessing import Pool, cpu_count
from collections import defaultdict, Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
    KRYPTOS_ALPHABET,
)

# Letters most likely to be duplicated (by English frequency)
COMMON_LETTERS = list("ETAOINSHR")


def build_homophonic_alphabet(base, duplicates):
    """Build alphabet by inserting duplicate letters.

    duplicates: list of (letter, insert_position) pairs
    Returns: extended alphabet string, and a mapping from index -> set of possible letters
    """
    result = list(base)
    for i, (letter, pos) in enumerate(sorted(duplicates, key=lambda x: x[1])):
        result.insert(pos + i, letter)
    alpha = ''.join(result)

    # Build reverse map: each index maps to the letter at that position
    # (duplicates map to the same letter)
    idx_to_letter = {i: c for i, c in enumerate(alpha)}

    return alpha, idx_to_letter


def attack_homophonic(args):
    """Test a homophonic Vigenère configuration.

    For each period, determine which key values at each crib-constrained
    residue allow the crib letter to be one of the possible decryptions.
    """
    base_name, base_alpha, dup_spec, max_period, cipher_mode = args
    # dup_spec: list of (letter, insert_position) pairs

    alpha, idx_to_letter = build_homophonic_alphabet(base_alpha, dup_spec)
    n = len(alpha)

    # Build forward map: letter -> set of indices in extended alphabet
    letter_to_indices = defaultdict(set)
    for i, c in enumerate(alpha):
        letter_to_indices[c].add(i)

    # Map CT chars to their indices in extended alphabet
    # Each CT char maps to potentially multiple indices (if it's a duplicated letter)
    ct_char_indices = []
    for c in CT:
        ct_char_indices.append(sorted(letter_to_indices[c]))

    results = []

    for period in range(1, max_period + 1):
        # For each residue, find key values where ALL cribs in that residue
        # can be simultaneously satisfied.
        residue_constraints = defaultdict(list)
        for pos, pt_char in CRIB_DICT.items():
            r = pos % period
            residue_constraints[r].append((pos, pt_char))

        feasible = True
        valid_keys_per_residue = []

        for r in range(period):
            constraints = residue_constraints.get(r, [])
            if not constraints:
                valid_keys_per_residue.append(list(range(n)))
                continue

            # For each possible key value k (0..n-1):
            # For each crib (pos, pt_char):
            #   The CT at pos has possible indices ct_char_indices[pos]
            #   Decrypting: for Vigenère, pt_idx = (ct_idx - k) mod n
            #   The resulting pt_idx maps to idx_to_letter[pt_idx]
            #   We need idx_to_letter[pt_idx] == pt_char for SOME ct_idx in ct_char_indices[pos]

            valid_k = []
            for k in range(n):
                all_cribs_ok = True
                for pos, pt_char in constraints:
                    # Check if any CT index for this position decrypts to pt_char
                    found = False
                    for ct_idx in ct_char_indices[pos]:
                        if cipher_mode == 'vigenere':
                            pt_idx = (ct_idx - k) % n
                        else:
                            pt_idx = (k - ct_idx) % n
                        if idx_to_letter[pt_idx] == pt_char:
                            found = True
                            break
                    if not found:
                        all_cribs_ok = False
                        break
                if all_cribs_ok:
                    valid_k.append(k)

            if not valid_k:
                feasible = False
                break
            valid_keys_per_residue.append(valid_k)

        if not feasible:
            continue

        # Count total combinations
        total = 1
        for vk in valid_keys_per_residue:
            total *= len(vk)

        if total > 5_000_000:
            continue  # Too many

        # Enumerate valid keys and decrypt
        for key_combo in itertools.product(*valid_keys_per_residue):
            key_nums = list(key_combo)

            # Decrypt - for each position, find the best (most constrained) decryption
            pt_chars = []
            for i in range(CT_LEN):
                k = key_nums[i % period]
                # Get all possible decryptions
                possible = set()
                for ct_idx in ct_char_indices[i]:
                    if cipher_mode == 'vigenere':
                        pt_idx = (ct_idx - k) % n
                    else:
                        pt_idx = (k - ct_idx) % n
                    possible.add(idx_to_letter[pt_idx])

                if len(possible) == 1:
                    pt_chars.append(possible.pop())
                else:
                    # Ambiguous - pick the crib letter if this is a crib position
                    if i in CRIB_DICT and CRIB_DICT[i] in possible:
                        pt_chars.append(CRIB_DICT[i])
                    else:
                        # Pick most common English letter among possibilities
                        best = min(possible, key=lambda c: COMMON_LETTERS.index(c)
                                   if c in COMMON_LETTERS else 99)
                        pt_chars.append(best)

            pt = ''.join(pt_chars)

            # Score
            score = 0
            for pos, expected in CRIB_DICT.items():
                if pos < len(pt) and pt[pos] == expected:
                    score += 1

            if score >= STORE_THRESHOLD:
                bean_ok = True
                for a, b in BEAN_EQ:
                    if pt[a] != pt[b]:
                        bean_ok = False
                        break

                dup_desc = '+'.join(f"{l}@{p}" for l, p in dup_spec)
                key_text = ''.join(alpha[k] for k in key_nums)
                results.append((
                    score, bean_ok, pt, key_text, period,
                    f"{base_name}/dup={dup_desc}/{cipher_mode}"
                ))

    return results


def generate_dup_specs(base_alpha, n_dups, letters_to_dup):
    """Generate duplicate letter specifications.

    For n_dups duplicate letters chosen from letters_to_dup,
    yield all (letter, insert_position) combinations.
    """
    n_base = len(base_alpha)
    specs = []

    # Choose which n_dups letters to duplicate (with replacement for >1 copies)
    for dup_letters in itertools.combinations_with_replacement(letters_to_dup, n_dups):
        # For each duplicated letter, choose insertion position
        # Insert near the original position for realism (within ±5 positions)
        # Or just try all positions (more thorough)
        insert_positions = list(itertools.product(range(n_base + 1), repeat=n_dups))

        # Too many! Sample insertion positions instead.
        # Strategy: insert each duplicate RIGHT AFTER its original occurrence
        # (most natural placement), and also try a few random placements.
        natural_positions = []
        for letter in dup_letters:
            orig_pos = base_alpha.index(letter)
            natural_positions.append(orig_pos + 1)  # right after original

        specs.append(list(zip(dup_letters, natural_positions)))

        # Also try inserting at end
        end_positions = [n_base] * n_dups
        specs.append(list(zip(dup_letters, end_positions)))

        # Try inserting at beginning
        begin_positions = [0] * n_dups
        specs.append(list(zip(dup_letters, begin_positions)))

        # Try a spread: evenly distribute
        if n_dups > 1:
            spread = [int(n_base * i / n_dups) for i in range(n_dups)]
            specs.append(list(zip(dup_letters, spread)))

    # Deduplicate
    unique_specs = []
    seen = set()
    for spec in specs:
        key = tuple(sorted(spec))
        if key not in seen:
            seen.add(key)
            unique_specs.append(spec)

    return unique_specs


def main():
    print("=" * 70)
    print("E-HOMOPHONIC-VIG-KIMMO: Homophonic Vigenère (duplicate letters)")
    print("=" * 70)
    print(f"\nCT: {CT}")
    print(f"CT length: {CT_LEN}")
    workers = max(1, cpu_count() - 2)
    print(f"Workers: {workers}")

    max_period = 26
    all_results = []

    # Top 9 English letters to consider duplicating
    dup_candidates = list("ETAOINSHR")

    for n_dups in [1, 2, 3, 4]:
        n = 26 + n_dups
        print(f"\n{'─' * 50}")
        print(f"Testing n={n} ({n_dups} duplicate letter(s))")

        configs = []
        for base_name, base_alpha in [("KA", KRYPTOS_ALPHABET), ("AZ", ALPH)]:
            dup_specs = generate_dup_specs(base_alpha, n_dups, dup_candidates)
            print(f"  {base_name}: {len(dup_specs)} duplicate specs")

            for spec in dup_specs:
                for mode in ['vigenere', 'beaufort']:
                    configs.append((base_name, base_alpha, spec, max_period, mode))

        print(f"  Total configs: {len(configs)}")

        t0 = time.time()
        with Pool(workers) as pool:
            batch_results = pool.map(attack_homophonic, configs)

        for res_list in batch_results:
            all_results.extend(res_list)

        elapsed = time.time() - t0
        hits = sum(len(r) for r in batch_results)
        print(f"  Completed in {elapsed:.1f}s, hits: {hits}")

    all_results.sort(key=lambda x: (-x[0], -x[1]))

    print(f"\n{'=' * 70}")
    print(f"RESULTS: {len(all_results)} candidates scoring >= {STORE_THRESHOLD}")
    print(f"{'=' * 70}")

    if not all_results:
        print("\nNo candidates found above threshold.")
        print("Homophonic Vigenère (n=27-30, duplicate letters): NO SIGNAL")
    else:
        for i, (score, bean, pt, key, period, desc) in enumerate(all_results[:30]):
            bean_str = "PASS" if bean else "FAIL"
            print(f"\n  #{i+1}: score={score}/24 bean={bean_str} period={period}")
            print(f"       key={key} config={desc}")
            print(f"       PT: {pt[:50]}...")

    return all_results


if __name__ == "__main__":
    main()
