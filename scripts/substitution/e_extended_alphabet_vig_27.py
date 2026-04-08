#!/usr/bin/env python3
"""
Cipher: extended alphabet vigenere
Family: substitution
Status: RETIRED — phantom scoring (see warning below)
Keyspace: 26 extra_positions × 26 mappings × ~27^L keywords (L=3..14)
Last run: exhausted 2026 (0 survivors under tight crib constraints)
Best score: 0

!!! WARNING — DO NOT RUN WITHOUT REWRITE !!!
Script audit (2026-04-08) identified this as a phantom-score factory:
the residue-constraint filter retains only keys that decrypt each crib
position to the correct crib letter, then scores the resulting PT
against those same cribs. Any surviving config scores 24/24 by
construction, NOT by cryptanalytic signal.

Historical exhaustion (best_score=0) is valid because the crib filter
eliminated all configs — the phantom branch was never entered. But if
re-run with relaxed constraints, wider parameters, or as a subroutine
in a larger sweep, this script will emit phantom breakthrough scores.

To reuse: either reclassify as a crib-admissibility enumerator (do not
emit score/24) or rescore surviving configs with score_candidate_free
on an ngram-based metric that is NOT aware of crib positions during
disambiguation.
"""
"""E-EXTENDED-ALPHABET-VIG-27: 27-letter alphabet Vigenère attack.

[HYPOTHESIS] K4 uses a Vigenère-style cipher with a 27-letter alphabet.
One extra symbol (represented as '1') is inserted at some position in the
base alphabet (KA or AZ). The extra symbol maps back to one of the 26
standard letters during decoding, allowing frequency-flattening.

Approach (Kimmo's method):
1. Fix base alphabet (KA or AZ)
2. Insert one extra character '1' at each of 27 possible positions (0..26)
3. For each insertion position, '1' decodes to one of 26 letters
4. Keywords are drawn from the 27-symbol alphabet (A-Z + '1')
5. Vigenère decrypt with 27×27 tableau, then map '1' back to its letter
6. Score against known cribs

For keyword length L, there are 27^L keyword possibilities.
With 27 insertion positions × 26 mappings = 702 alphabet configurations,
and keyword lengths 3-8, the full space is:
  702 × (27^3 + 27^4 + ... + 27^8) ≈ 702 × 289 billion = huge

Strategy: Use crib constraints to filter. At each crib position, the
decrypted letter must match. This constrains the keyword character at
that position modulo the period. For short periods, this is very restrictive.
"""
import sys
import os
import time
import itertools
from multiprocessing import Pool, cpu_count
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
    KRYPTOS_ALPHABET,
)


def build_27_alphabet(base, insert_pos, extra_char_label='1'):
    """Insert extra character at position insert_pos in base alphabet."""
    return base[:insert_pos] + extra_char_label + base[insert_pos:]


def decrypt_27_vigenere(ct_nums, key_nums, n):
    """Vigenère decrypt in mod-n arithmetic. Returns list of ints."""
    period = len(key_nums)
    return [(ct_nums[i] - key_nums[i % period]) % n for i in range(len(ct_nums))]


def decrypt_27_beaufort(ct_nums, key_nums, n):
    """Beaufort decrypt in mod-n arithmetic. Returns list of ints."""
    period = len(key_nums)
    return [(key_nums[i % period] - ct_nums[i]) % n for i in range(len(ct_nums))]


def text_to_nums_27(text, alpha_map):
    """Convert text to numbers using 27-char alphabet map."""
    return [alpha_map[c] for c in text]


def nums_to_text_27(nums, alpha):
    """Convert numbers back to text using 27-char alphabet."""
    return ''.join(alpha[n] for n in nums)


def decode_extra(text_27, extra_char_label, decode_to):
    """Map the extra character back to a standard letter."""
    return text_27.replace(extra_char_label, decode_to)


def score_against_cribs(plaintext):
    """Score plaintext against known cribs. Returns (score, details)."""
    if len(plaintext) < CT_LEN:
        return 0, "too short"
    score = 0
    matches = []
    for pos, expected in CRIB_DICT.items():
        if pos < len(plaintext) and plaintext[pos] == expected:
            score += 1
            matches.append(pos)
    return score, matches


def check_bean(plaintext):
    """Check Bean equality constraint."""
    for a, b in BEAN_EQ:
        if a < len(plaintext) and b < len(plaintext):
            if plaintext[a] != plaintext[b]:
                return False
    return True


def find_valid_key_chars_at_position(ct_char_idx, pt_char, n, mode='vigenere'):
    """Find which key values (0..n-1) produce the required PT char."""
    if mode == 'vigenere':
        # PT = (CT - K) mod n => K = (CT - PT) mod n
        return [(ct_char_idx - pt_char) % n]
    else:  # beaufort
        # PT = (K - CT) mod n => K = (PT + CT) mod n
        return [(pt_char + ct_char_idx) % n]


def attack_config(args):
    """Test a single (base_alphabet, insert_pos, decode_to) configuration.

    Uses crib constraints to determine valid key characters at each
    period residue, then enumerates only consistent keywords.
    """
    base_name, base_alpha, insert_pos, decode_to_letter, max_period, cipher_mode = args
    extra_label = '1'
    alpha_27 = build_27_alphabet(base_alpha, insert_pos, extra_label)
    n = len(alpha_27)  # 27

    # Build mapping
    alpha_map = {c: i for i, c in enumerate(alpha_27)}
    decode_to_idx = ALPH_IDX[decode_to_letter]

    # Convert CT to 27-alphabet numbers
    # CT uses standard A-Z letters. Map each to the 27-alphabet position.
    ct_nums = []
    for c in CT:
        if c in alpha_map:
            ct_nums.append(alpha_map[c])
        else:
            return []  # shouldn't happen since base contains all 26 letters

    results = []

    for period in range(1, max_period + 1):
        # For each residue class r (0..period-1), find which crib positions
        # fall in that class, and determine valid key values.
        residue_constraints = defaultdict(list)  # residue -> [(ct_num, pt_target_num)]

        for pos, pt_char in CRIB_DICT.items():
            r = pos % period
            ct_num = ct_nums[pos]
            # The PT char in the 27-alphabet: it's a standard letter
            pt_num = alpha_map[pt_char]
            residue_constraints[r].append((ct_num, pt_num))

        # For each residue, find key values consistent with ALL cribs in that residue
        valid_keys_per_residue = []
        feasible = True

        for r in range(period):
            constraints = residue_constraints.get(r, [])
            if not constraints:
                # No cribs constrain this residue — all 27 values are valid
                valid_keys_per_residue.append(list(range(n)))
                continue

            # Find key values that satisfy ALL constraints for this residue
            valid_k = []
            for k in range(n):
                ok = True
                for ct_num, pt_num in constraints:
                    if cipher_mode == 'vigenere':
                        decrypted = (ct_num - k) % n
                    else:
                        decrypted = (k - ct_num) % n
                    if decrypted != pt_num:
                        ok = False
                        break
                if ok:
                    valid_k.append(k)

            if not valid_k:
                feasible = False
                break
            valid_keys_per_residue.append(valid_k)

        if not feasible:
            continue

        # Count total combinations
        total_combos = 1
        for vk in valid_keys_per_residue:
            total_combos *= len(vk)

        if total_combos > 10_000_000:
            # Too many — skip (would need different approach)
            continue

        # Enumerate all valid key combinations
        for key_combo in itertools.product(*valid_keys_per_residue):
            key_nums = list(key_combo)

            # Decrypt
            if cipher_mode == 'vigenere':
                pt_nums = decrypt_27_vigenere(ct_nums, key_nums, n)
            else:
                pt_nums = decrypt_27_beaufort(ct_nums, key_nums, n)

            # Convert to 27-alphabet text
            pt_27 = nums_to_text_27(pt_nums, alpha_27)

            # Decode extra character back to standard letter
            pt_decoded = decode_extra(pt_27, extra_label, decode_to_letter)

            # Score
            score, matches = score_against_cribs(pt_decoded)

            if score >= STORE_THRESHOLD:
                # Check Bean
                bean_ok = check_bean(pt_decoded)
                key_text = nums_to_text_27(key_nums, alpha_27)
                results.append((
                    score, bean_ok, pt_decoded, key_text, period,
                    f"{base_name}/ins{insert_pos}/decode_{decode_to_letter}/{cipher_mode}"
                ))

    return results


def main():
    print("=" * 70)
    print("E-EXTENDED-ALPHABET-VIG-27: 27-letter alphabet Vigenère")
    print("=" * 70)
    print(f"\nCT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Crib positions: {sorted(CRIB_DICT.keys())}")
    print(f"Workers: {max(1, cpu_count() - 2)}")

    max_period = 26  # Test periods 1-26

    # Build all configurations
    configs = []
    for base_name, base_alpha in [("KA", KRYPTOS_ALPHABET), ("AZ", ALPH)]:
        for insert_pos in range(27):  # 0..26 = 27 positions
            for decode_to in ALPH:  # 26 letters
                for mode in ['vigenere', 'beaufort']:
                    configs.append((
                        base_name, base_alpha, insert_pos,
                        decode_to, max_period, mode
                    ))

    total_configs = len(configs)
    print(f"\nConfigurations: {total_configs}")
    print(f"  = 2 bases × 27 insert positions × 26 decode mappings × 2 modes")
    print(f"  = {2 * 27 * 26 * 2}")
    print(f"\nFor each config, testing periods 1-{max_period}")
    print(f"Using crib constraints to prune keyword space\n")

    t0 = time.time()
    all_results = []
    workers = max(1, cpu_count() - 2)

    # Process in batches for progress reporting
    batch_size = workers * 4
    processed = 0

    with Pool(workers) as pool:
        for batch_start in range(0, total_configs, batch_size):
            batch = configs[batch_start:batch_start + batch_size]
            batch_results = pool.map(attack_config, batch)

            for res_list in batch_results:
                for res in res_list:
                    all_results.append(res)

            processed += len(batch)
            elapsed = time.time() - t0
            if processed % (batch_size * 10) == 0 or processed == total_configs:
                print(f"  Progress: {processed}/{total_configs} configs "
                      f"({100*processed/total_configs:.1f}%) "
                      f"elapsed={elapsed:.1f}s "
                      f"hits={len(all_results)}")

    elapsed = time.time() - t0

    # Sort by score descending
    all_results.sort(key=lambda x: (-x[0], -x[1]))

    print(f"\n{'=' * 70}")
    print(f"RESULTS: {len(all_results)} candidates scoring >= {STORE_THRESHOLD}")
    print(f"Time: {elapsed:.1f}s")
    print(f"{'=' * 70}")

    if not all_results:
        print("\nNo candidates found above threshold.")
        print("27-letter extended alphabet Vigenère/Beaufort: NO SIGNAL")
    else:
        for i, (score, bean, pt, key, period, desc) in enumerate(all_results[:50]):
            bean_str = "PASS" if bean else "FAIL"
            print(f"\n  #{i+1}: score={score}/24 bean={bean_str} period={period}")
            print(f"       key={key}")
            print(f"       config={desc}")
            print(f"       PT: {pt}")

    # Summary statistics
    if all_results:
        scores = [r[0] for r in all_results]
        print(f"\nScore distribution: max={max(scores)}, "
              f"mean={sum(scores)/len(scores):.1f}, "
              f"count={len(scores)}")
        bean_pass = sum(1 for r in all_results if r[1])
        print(f"Bean PASS: {bean_pass}/{len(all_results)}")

    return all_results


if __name__ == "__main__":
    results = main()
