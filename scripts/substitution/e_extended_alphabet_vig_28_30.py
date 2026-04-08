#!/usr/bin/env python3
"""
Cipher: extended alphabet vigenere
Family: substitution
Status: RETIRED — phantom scoring (see warning below)
Keyspace: n=28..30 × insert_combos × decode_mappings × periods 1-26
Last run: exhausted 2026 (0 hits at n=27,28; only period-26 false positives at n=29,30)
Best score: 0

!!! WARNING — DO NOT RUN WITHOUT REWRITE !!!
Script audit (2026-04-08) identified this as a phantom-score factory:
the residue filter forces key values to match cribs by construction,
and line 270 default-replaces undecoded labels with 'E'. Every
surviving config scores 24/24 by construction, not cryptanalytic
signal. Period-26 "false positives" in the historical exhaustion log
are a symptom of this bug (at period=26 all residues are unconstrained,
so any feasible alphabet passes).

Historical best_score=0 at n=27,28 is valid (no survivors). The n=29,30
period-26 entries are phantom artifacts and should be ignored.

To reuse: reclassify as a crib-admissibility enumerator OR rescore
survivors with an ngram-based metric that is not crib-aware.
"""
"""E-EXTENDED-ALPHABET-VIG-28-30: Extended alphabet Vigenère for n=28,29,30.

[HYPOTHESIS] K4 uses a Vigenère-style cipher with a 28-30 letter alphabet.
Extension of the 27-letter test. For n extra characters (n=2,3,4), we:
1. Insert n extra symbols into the base alphabet at all C(27+n, n) positions
2. Each extra symbol decodes to one of 26 letters
3. Test all periodic Vigenère/Beaufort keys using crib constraints

For n=2 (28-letter): C(28,2)=378 insertion combos × 26^2=676 decode maps = 255,528 configs
For n=3 (29-letter): C(29,3)=3654 × 26^3=17,576 = enormous → sample
For n=4 (30-letter): Even larger → sample heavily

Strategy: Use crib constraints to prune. The extra alphabet width means
more possible key values per position (28-30 instead of 27), but the
crib constraints are just as tight. If period < ~8, typically only 0-1
key values work per residue.

Optimization: Instead of enumerating all insertion positions, note that
what matters is only the RELATIVE ordering of extra chars within the alphabet.
The crib constraints determine which key value is needed at each residue.
So we can iterate: for each period, find valid key values, then check if
any key value corresponds to an extra char that decodes to the right letter.

Actually, the simpler approach: for each period, compute what key value is
required at each crib-constrained residue. If the required key value falls
outside 0-25 (the standard range), it must be an extra character position.
We check if there's a consistent assignment of extra chars that works.
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


def build_extended_alphabet(base, insert_positions, extra_labels):
    """Insert multiple extra characters into base alphabet.

    insert_positions: sorted list of positions (0-indexed in final string)
    extra_labels: list of labels for extra chars
    """
    result = list(base)
    for i, (pos, label) in enumerate(sorted(zip(insert_positions, extra_labels))):
        result.insert(pos + i, label)  # +i because previous inserts shifted positions
    return ''.join(result)


def attack_extended(args):
    """Test extended alphabet configs for a given alphabet size n.

    For each period, use crib constraints to find valid key values.
    Then check if valid keys can be formed from the extended alphabet.
    """
    base_name, base_alpha, n_extra, max_period, cipher_mode = args
    n = 26 + n_extra  # alphabet size

    results = []

    # For each period, find required key values at each constrained residue
    for period in range(1, max_period + 1):
        residue_constraints = defaultdict(list)
        for pos, pt_char in CRIB_DICT.items():
            r = pos % period
            ct_idx = ALPH_IDX[CT[pos]]
            pt_idx = ALPH_IDX[pt_char]
            residue_constraints[r].append((ct_idx, pt_idx))

        # For each residue, find which key values (mod n) satisfy all cribs
        # In standard 26-letter Vigenère: k = (ct - pt) mod 26
        # In n-letter: k = (ct_in_n - pt_in_n) mod n
        # But ct and pt are standard letters, so their positions in the
        # extended alphabet depend on where the extra chars are inserted.

        # Key insight: we need to try all possible insertion positions for
        # the extra characters. But the crib constraint depends on the
        # POSITIONS of standard letters in the extended alphabet.

        # For a base alphabet B of 26 chars with n_extra chars inserted,
        # the position of standard letter L in the extended alphabet is:
        # original_pos(L) + (number of extra chars inserted before L)

        # Let's enumerate: for n_extra = 2, we have 2 extra chars.
        # They can be inserted at positions 0..26 (27 slots in the 26-char base).
        # The number of unordered insertion positions is C(26+n_extra, n_extra).

        # For efficiency with n_extra=2: C(28,2)=378. For each, compute the
        # position shifts and check crib constraints.

        # For n_extra=3: C(29,3)=3654. Still feasible.
        # For n_extra=4: C(30,4)=27,405. Getting big but still OK with pruning.

        # Actually, there's a smarter way. The standard letters maintain their
        # relative order. What changes is their absolute index in the extended
        # alphabet. If we insert k extra chars before position p in the base
        # alphabet, then all base chars at positions >= p get shifted by k.

        # For a given set of insertion slots (s1, s2, ..., s_{n_extra}) where
        # 0 <= s1 <= s2 <= ... <= s_{n_extra} <= 26, the index of base char
        # at original position j is: j + |{i : s_i <= j}|

        # This means for each insertion pattern, the Vigenère equation becomes:
        # For crib (pos, ct_char, pt_char):
        #   ct_idx_ext = ALPH_IDX[ct_char] + shifts_at[ALPH_IDX[ct_char]]  (for AZ base)
        #   pt_idx_ext = ALPH_IDX[pt_char] + shifts_at[ALPH_IDX[pt_char]]
        #   k_required = (ct_idx_ext - pt_idx_ext) % n  (Vigenère)
        # where shifts_at[j] = number of extra chars inserted at positions <= j

        pass  # We'll compute per insertion pattern below

    # Enumerate insertion patterns
    # slots: positions 0..26 where extra chars go (with replacement for same position)
    # Use combinations_with_replacement for unordered insertion
    insertion_patterns = list(itertools.combinations_with_replacement(range(27), n_extra))

    for pattern in insertion_patterns:
        # Compute shift for each base alphabet position
        # shifts[j] = number of insertions at positions <= j
        shifts = [0] * 26
        for j in range(26):
            shifts[j] = sum(1 for s in pattern if s <= j)

        # For each decode mapping of extra chars
        # We need to try all 26^n_extra decode mappings... but that's huge for n_extra >= 3
        # Instead, use crib constraints: for each period, find required key values,
        # then check if any consistent decode mapping exists.

        for period in range(1, max_period + 1):
            residue_constraints = defaultdict(list)
            for pos, pt_char in CRIB_DICT.items():
                r = pos % period
                if base_name == "KA":
                    ct_base_idx = KRYPTOS_ALPHABET.index(CT[pos])
                    pt_base_idx = KRYPTOS_ALPHABET.index(pt_char)
                else:
                    ct_base_idx = ALPH_IDX[CT[pos]]
                    pt_base_idx = ALPH_IDX[pt_char]

                ct_ext_idx = ct_base_idx + shifts[ct_base_idx]
                pt_ext_idx = pt_base_idx + shifts[pt_base_idx]

                residue_constraints[r].append((ct_ext_idx, pt_ext_idx))

            # Check consistency: for each residue, all crib pairs must give same key value
            feasible = True
            key_values = {}

            for r in range(period):
                constraints = residue_constraints.get(r, [])
                if not constraints:
                    continue

                # Find which key values work
                valid_k = set(range(n))
                for ct_e, pt_e in constraints:
                    if cipher_mode == 'vigenere':
                        k_required = (ct_e - pt_e) % n
                    else:
                        k_required = (pt_e + ct_e) % n
                    valid_k &= {k_required}

                if not valid_k:
                    feasible = False
                    break
                key_values[r] = valid_k.pop()

            if not feasible:
                continue

            # We have a valid key! Decrypt full CT and score.
            # Build the extended alphabet for decryption
            ext_alpha_chars = list(base_name == "KA" and KRYPTOS_ALPHABET or ALPH)
            extra_labels = [str(i+1) for i in range(n_extra)]
            for i, (slot, label) in enumerate(zip(sorted(pattern), extra_labels)):
                ext_alpha_chars.insert(slot + i, label)
            ext_alpha = ''.join(ext_alpha_chars)
            ext_map = {c: i for i, c in enumerate(ext_alpha)}

            ct_nums = [ext_map[c] for c in CT]

            # Build full key
            full_key = []
            for i in range(CT_LEN):
                r = i % period
                if r in key_values:
                    full_key.append(key_values[r])
                else:
                    # Unconstrained position - enumerate? Too many options.
                    # For now, try all n possibilities for unconstrained positions.
                    # But with period > #constrained residues, this could be large.
                    full_key.append(None)

            # Count unconstrained positions
            unconstrained = [i for i in range(period) if full_key[i] is None]
            if len(unconstrained) > 4:
                continue  # Too many free parameters

            # Enumerate unconstrained key values
            for free_vals in itertools.product(range(n), repeat=len(unconstrained)):
                key_nums = list(full_key[:period])
                for idx, val in zip(unconstrained, free_vals):
                    key_nums[idx] = val

                # Decrypt
                if cipher_mode == 'vigenere':
                    pt_nums = [(ct_nums[i] - key_nums[i % period]) % n
                               for i in range(CT_LEN)]
                else:
                    pt_nums = [(key_nums[i % period] - ct_nums[i]) % n
                               for i in range(CT_LEN)]

                pt_ext = ''.join(ext_alpha[p] for p in pt_nums)

                # Decode extra chars: try all 26 mappings for each
                # For scoring, we need the best possible decode
                # Since extra chars map to A-Z, find the decode that maximizes score

                # First, check how many extra chars appear in the PT
                extra_positions = [i for i, c in enumerate(pt_ext)
                                   if c in extra_labels]

                # For cribs: we already know crib positions are correct (by construction)
                # But extra chars AT crib positions would need to decode correctly
                crib_extra = [(i, CRIB_DICT[i]) for i in extra_positions
                              if i in CRIB_DICT]

                label_required = {}
                if crib_extra:
                    # Extra chars at crib positions — check if decode is consistent
                    # Each extra char label must map to the required PT letter
                    conflict = False
                    for pos, required_pt in crib_extra:
                        label = pt_ext[pos]
                        if label in label_required:
                            if label_required[label] != required_pt:
                                conflict = True
                                break
                        else:
                            label_required[label] = required_pt
                    if conflict:
                        continue

                # Decode: replace extra labels with best guess
                pt_decoded = pt_ext
                for label in extra_labels:
                    if label in label_required:
                        pt_decoded = pt_decoded.replace(label, label_required[label])
                    else:
                        # Try most common English letter not yet used
                        pt_decoded = pt_decoded.replace(label, 'E')

                # Score
                score = 0
                for pos, expected in CRIB_DICT.items():
                    if pos < len(pt_decoded) and pt_decoded[pos] == expected:
                        score += 1

                if score >= STORE_THRESHOLD:
                    bean_ok = True
                    for a, b in BEAN_EQ:
                        if pt_decoded[a] != pt_decoded[b]:
                            bean_ok = False
                            break

                    key_text = ''.join(ext_alpha[k] for k in key_nums)
                    results.append((
                        score, bean_ok, pt_decoded, key_text, period,
                        f"{base_name}/n={n}/pattern={pattern}/{cipher_mode}"
                    ))

    return results


def main():
    print("=" * 70)
    print("E-EXTENDED-ALPHABET-VIG-28-30: Extended alphabets n=28,29,30")
    print("=" * 70)
    print(f"\nCT: {CT}")
    print(f"CT length: {CT_LEN}")
    workers = max(1, cpu_count() - 2)
    print(f"Workers: {workers}")

    max_period = 26
    all_results = []

    for n_extra in [2, 3, 4]:
        n = 26 + n_extra
        n_patterns = len(list(itertools.combinations_with_replacement(range(27), n_extra)))
        print(f"\n{'─' * 50}")
        print(f"Testing n={n} ({n_extra} extra chars)")
        print(f"Insertion patterns: {n_patterns}")

        configs = []
        for base_name in ["KA", "AZ"]:
            for mode in ['vigenere', 'beaufort']:
                configs.append((base_name, base_name == "KA" and KRYPTOS_ALPHABET or ALPH,
                                n_extra, max_period, mode))

        t0 = time.time()
        with Pool(workers) as pool:
            batch_results = pool.map(attack_extended, configs)

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
        print("Extended alphabet Vigenère/Beaufort (n=28-30): NO SIGNAL")
    else:
        for i, (score, bean, pt, key, period, desc) in enumerate(all_results[:30]):
            bean_str = "PASS" if bean else "FAIL"
            print(f"\n  #{i+1}: score={score}/24 bean={bean_str} period={period}")
            print(f"       key={key} config={desc}")
            print(f"       PT: {pt}")


if __name__ == "__main__":
    main()
