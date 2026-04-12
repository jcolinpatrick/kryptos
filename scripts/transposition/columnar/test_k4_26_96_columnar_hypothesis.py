#!/usr/bin/env python3
"""Test: columnar transposition of K4 positions 26-96 with Bean constraints.

Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation

HYPOTHESIS UNDER TEST:
Columnar transposition is applied ONLY to positions 26-96 (71 characters) of K4.
Column widths are derived from K2 coordinate digit groups.

TESTS:
1. Factual check: hypothesis claims "position ~26 where BERLIN begins" - is this correct?
2. Bean equality under transposition: what source positions map to positions 27 and 65?
3. Exhaustive columnar transposition for column counts 3-7 with Bean constraint checking.
4. IC of positions 26-96 (transposition preserves IC).
5. K2 coordinate digit group column widths that partition 71 characters.
"""
from __future__ import annotations

import itertools
import math
import sys
import os
from collections import Counter
from typing import Dict, List, Tuple, Optional

# ============================================================================
# CONSTANTS (self-contained, no external dependencies)
# ============================================================================

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
CT_LEN = 97
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH_IDX = {c: i for i, c in enumerate(ALPH)}
MOD = 26

# Cribs (0-indexed)
CRIB_WORDS = [
    (21, "EASTNORTHEAST"),   # positions 21-33
    (63, "BERLINCLOCK"),     # positions 63-73
]

CRIB_DICT: Dict[int, str] = {}
for start, word in CRIB_WORDS:
    for i, ch in enumerate(word):
        CRIB_DICT[start + i] = ch

# Bean constraints
BEAN_EQ = [(27, 65)]

# Self-encrypting positions
SELF_ENCRYPTING = {32: "S", 73: "K"}

# K2 coordinate digits
K2_DIGITS = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
K2_DIGIT_STRING = "38576577844"

# ============================================================================
# Derive Bean inequality set for reference
# ============================================================================
def derive_bean_ineq():
    positions = sorted(CRIB_DICT.keys())
    pairs = []
    for i in range(len(positions)):
        for j in range(i + 1, len(positions)):
            a, b = positions[i], positions[j]
            ca, pa = ALPH_IDX[CT[a]], ALPH_IDX[CRIB_DICT[a]]
            cb, pb = ALPH_IDX[CT[b]], ALPH_IDX[CRIB_DICT[b]]
            vig_eq = (ca - pa) % MOD == (cb - pb) % MOD
            beau_eq = (ca + pa) % MOD == (cb + pb) % MOD
            vbeau_eq = (pa - ca) % MOD == (pb - cb) % MOD
            if not vig_eq and not beau_eq and not vbeau_eq:
                pairs.append((a, b))
    return pairs

BEAN_INEQ = derive_bean_ineq()

# Derive Bean linear constraints
def derive_bean_linear():
    positions = sorted(CRIB_DICT.keys())
    n = len(positions)
    constraints = []
    for i in range(n):
        for j in range(i + 1, n):
            for k in range(j + 1, n):
                for l in range(k + 1, n):
                    a, b, c, d = positions[i], positions[j], positions[k], positions[l]
                    for p1, p2, p3, p4 in ((a, b, c, d), (a, c, b, d), (a, d, b, c)):
                        ca, pa = ALPH_IDX[CT[p1]], ALPH_IDX[CRIB_DICT[p1]]
                        cb, pb = ALPH_IDX[CT[p2]], ALPH_IDX[CRIB_DICT[p2]]
                        cc, pc = ALPH_IDX[CT[p3]], ALPH_IDX[CRIB_DICT[p3]]
                        cd, pd = ALPH_IDX[CT[p4]], ALPH_IDX[CRIB_DICT[p4]]
                        vig = ((ca - pa) - (cb - pb) - (cc - pc) + (cd - pd)) % MOD
                        beau = ((ca + pa) - (cb + pb) - (cc + pc) + (cd + pd)) % MOD
                        vbeau = ((pa - ca) - (pb - cb) - (pc - cc) + (pd - cd)) % MOD
                        if vig == 0 and beau == 0 and vbeau == 0:
                            constraints.append((p1, p2, p3, p4))
    return constraints

BEAN_LINEAR = derive_bean_linear()


# ============================================================================
# HELPER: Columnar transposition mapping
# ============================================================================

def columnar_encrypt_mapping(ncols: int, length: int, col_order: List[int]) -> List[int]:
    """Return mapping: output_pos -> source_pos for columnar encryption.

    Encryption: text is written row-by-row into a grid with `ncols` columns,
    then read column-by-column in the order specified by `col_order`.

    Returns a list where mapping[i] = j means output position i came from
    source position j.
    """
    nrows = math.ceil(length / ncols)
    # Build the grid positions
    # Text fills row-by-row: position k -> row k//ncols, col k%ncols
    # Read off column by column in col_order
    mapping = []
    for col in col_order:
        for row in range(nrows):
            pos = row * ncols + col
            if pos < length:
                mapping.append(pos)
    return mapping


def columnar_decrypt_mapping(ncols: int, length: int, col_order: List[int]) -> List[int]:
    """Return mapping: source_pos -> output_pos (inverse of encrypt).

    If encrypt maps output[i] = source[mapping[i]], then decrypt maps
    source[j] -> output position.
    """
    enc = columnar_encrypt_mapping(ncols, length, col_order)
    dec = [0] * length
    for out_pos, src_pos in enumerate(enc):
        dec[src_pos] = out_pos
    return dec


# ============================================================================
# TEST 1: FACTUAL CHECK
# ============================================================================

def test1_factual_check():
    print("=" * 80)
    print("TEST 1: FACTUAL CHECK - Where does BERLIN begin?")
    print("=" * 80)

    print(f"\nK4 ciphertext (0-indexed, {CT_LEN} chars):")
    print(CT)
    print()

    # Show position rulers
    tens =  "".join(str(i // 10) for i in range(CT_LEN))
    ones =  "".join(str(i % 10) for i in range(CT_LEN))
    print(tens)
    print(ones)
    print(CT)
    print()

    # Show what's at position 26
    print(f"CT[26] = '{CT[26]}'")
    print(f"CT[21:34] = '{CT[21:34]}' (positions 21-33)")
    print(f"CT[63:74] = '{CT[63:74]}' (positions 63-73)")
    print()

    # The crib positions
    print("EASTNORTHEAST crib: positions 21-33 (plaintext)")
    print("  Position 26 falls WITHIN the EASTNORTHEAST crib (it's the 'R' in 'NORTH')")
    print(f"  CRIB_DICT[26] = '{CRIB_DICT.get(26, 'NOT IN CRIB')}'")
    print()
    print("BERLINCLOCK crib: positions 63-73 (plaintext)")
    print(f"  BERLIN starts at position 63, NOT position 26")
    print()

    # The hypothesis claims positions 26-96
    print("HYPOTHESIS CLAIM: 'At position ~26 (where BERLIN begins)'")
    print("FACT: BERLIN begins at position 63. Position 26 is within EASTNORTHEAST.")
    print("VERDICT: The hypothesis is FACTUALLY INCORRECT about what starts at position 26.")
    print()

    # What IS at position 26?
    for pos in range(21, 34):
        crib_char = CRIB_DICT.get(pos, '?')
        ct_char = CT[pos]
        label = f"  pos {pos}: CT='{ct_char}', PT='{crib_char}'"
        if pos == 26:
            label += "  <-- POSITION 26 (hypothesis boundary)"
        print(label)
    print()


# ============================================================================
# TEST 2: Bean equality under transposition
# ============================================================================

def test2_bean_under_transposition():
    print("=" * 80)
    print("TEST 2: BEAN EQUALITY UNDER TRANSPOSITION (positions 26-96)")
    print("=" * 80)

    OFFSET = 26
    SUBLEN = 71  # positions 26-96 inclusive

    print(f"\nSubstring: CT[26:97] = '{CT[26:97]}'")
    print(f"Length: {SUBLEN}")
    print()

    # Bean positions relative to full CT
    bean_a, bean_b = 27, 65
    # Relative to offset
    rel_a = bean_a - OFFSET  # = 1
    rel_b = bean_b - OFFSET  # = 39
    print(f"Bean equality: k[{bean_a}] == k[{bean_b}]")
    print(f"Relative to offset {OFFSET}: rel positions {rel_a} and {rel_b}")
    print()

    # Under transposition model:
    # Ciphertext = Transpose(RunningKeyEncrypt(Plaintext))
    # Or equivalently: the CT at position i was encrypted at some other position
    # For Bean equality in the ORIGINAL CT coordinate space:
    # The keystream value at position 27 must equal keystream value at position 65
    print("Under transposition-then-substitution model:")
    print("  CT = Substitute(Transpose(PT), key)")
    print("  => CT[i] = PT[sigma(i)] + key[i]  (Vigenere)")
    print("  => key[i] = CT[i] - PT[sigma(i)]")
    print("  => Bean requires: CT[27]-PT[sigma(27)] == CT[65]-PT[sigma(65)] mod 26")
    print()
    print("Under substitution-then-transposition model:")
    print("  CT = Transpose(Substitute(PT, key))")
    print("  => CT[i] = Substitute(PT, key)[sigma_inv(i)]")
    print("  => CT[i] = PT[sigma_inv(i)] + key[sigma_inv(i)]")
    print("  => implied key at CT pos i is: CT[i] - PT[sigma_inv(i)]")
    print("  => Bean on CT positions: key[sigma_inv(27)] == key[sigma_inv(65)]")
    print("  => But this is a constraint on PRE-transposition positions, not CT positions")
    print()

    # The model matters. Let's analyze both:
    print("MODEL ANALYSIS:")
    print("-" * 60)
    print()
    print("Bean constraints are derived from the FINAL CT and KNOWN PT cribs.")
    print("They require: (CT[27] - PT[27]) mod 26 == (CT[65] - PT[65]) mod 26")
    print("This is a property of the CIPHERTEXT, not the intermediate text.")
    print()

    # Compute the implied key values at Bean positions under identity (no transposition)
    ct27, pt27 = ALPH_IDX[CT[27]], ALPH_IDX[CRIB_DICT[27]]
    ct65, pt65 = ALPH_IDX[CT[65]], ALPH_IDX[CRIB_DICT[65]]

    vig_k27 = (ct27 - pt27) % MOD
    vig_k65 = (ct65 - pt65) % MOD
    beau_k27 = (ct27 + pt27) % MOD
    beau_k65 = (ct65 + pt65) % MOD

    print(f"Position 27: CT='{CT[27]}'({ct27}), PT='{CRIB_DICT[27]}'({pt27})")
    print(f"  Vig key: ({ct27}-{pt27}) mod 26 = {vig_k27}")
    print(f"  Beau key: ({ct27}+{pt27}) mod 26 = {beau_k27}")
    print()
    print(f"Position 65: CT='{CT[65]}'({ct65}), PT='{CRIB_DICT[65]}'({pt65})")
    print(f"  Vig key: ({ct65}-{pt65}) mod 26 = {vig_k65}")
    print(f"  Beau key: ({ct65}+{pt65}) mod 26 = {beau_k65}")
    print()
    print(f"Bean equality (Vigenere):  {vig_k27} == {vig_k65} ? {vig_k27 == vig_k65}")
    print(f"Bean equality (Beaufort):  {beau_k27} == {beau_k65} ? {beau_k27 == beau_k65}")
    print()

    if vig_k27 == vig_k65:
        print("Bean equality holds under Vigenere with NO transposition (identity).")
    if beau_k27 == beau_k65:
        print("Bean equality holds under Beaufort with NO transposition (identity).")
    print()

    # KEY INSIGHT: If there IS a transposition, Bean equality on the FINAL CT
    # is only valid if the cribs are placed at FINAL CT positions.
    # But the cribs are placed at PLAINTEXT positions.
    # Under transposition, PT position 27 maps to some CT position p.
    # The crib letter at PT[27] appears at CT[p], NOT at CT[27].
    # Therefore, Bean constraints (which compare CT positions) are INVALIDATED
    # if a transposition moves crib letters away from their original positions.

    print("CRITICAL INSIGHT:")
    print("-" * 60)
    print("Bean constraints assume: CT[pos] = Encrypt(PT[pos], key[pos])")
    print("i.e., no transposition between PT and CT.")
    print()
    print("If a transposition is applied to positions 26-96:")
    print("  - PT position 27 (crib 'G' from EASTNORTHEAST) moves to some CT pos p")
    print("  - PT position 65 (crib 'L' from BERLINCLOCK) moves to some CT pos q")
    print("  - The standard Bean constraint compares CT[27] with CT[65]")
    print("  - But the crib letters are no longer at those CT positions!")
    print("  - Bean constraints in their standard form DO NOT APPLY under transposition")
    print()
    print("EXCEPTION: Transposition-then-substitution model where the key is")
    print("position-dependent on the CT coordinate (not the PT coordinate).")
    print("In that case, Bean must be RE-DERIVED for each transposition.")
    print()


# ============================================================================
# TEST 3: Exhaustive columnar transposition for 3-7 columns
# ============================================================================

def test3_exhaustive_columnar():
    print("=" * 80)
    print("TEST 3: EXHAUSTIVE COLUMNAR ON 71 CHARS (positions 26-96), columns 3-7")
    print("=" * 80)

    OFFSET = 26
    SUBLEN = 71
    substr = CT[OFFSET:OFFSET + SUBLEN]

    # Bean positions relative to offset
    bean_a_rel = 27 - OFFSET  # = 1
    bean_b_rel = 65 - OFFSET  # = 39

    print(f"\nSubstring length: {SUBLEN}")
    print(f"Bean positions (relative): {bean_a_rel}, {bean_b_rel}")
    print()

    # Crib positions within the range 26-96
    crib_in_range = {pos: ch for pos, ch in CRIB_DICT.items() if OFFSET <= pos < OFFSET + SUBLEN}
    crib_rel = {pos - OFFSET: ch for pos, ch in crib_in_range.items()}
    print(f"Crib positions in range (relative): {sorted(crib_rel.keys())}")
    print(f"  = original positions {sorted(crib_in_range.keys())}")
    print()

    for ncols in range(3, 8):
        nrows = math.ceil(SUBLEN / ncols)
        n_perms = math.factorial(ncols)
        print(f"\n--- {ncols} columns, {nrows} rows, {n_perms} permutations ---")

        # How many cells are empty in the last row?
        n_empty = nrows * ncols - SUBLEN
        print(f"  Grid: {nrows}x{ncols} = {nrows*ncols} cells, {n_empty} empty in last row")

        bean_eq_count = 0
        bean_full_pass_count = 0
        bean_eq_source_pairs = []

        for perm in itertools.permutations(range(ncols)):
            col_order = list(perm)

            # Get the encrypt mapping: output[i] = source[mapping[i]]
            enc_map = columnar_encrypt_mapping(ncols, SUBLEN, col_order)

            # Under ENCRYPTION: plaintext is written row-by-row, read by columns
            # enc_map[i] = source position that produces output position i
            # So output[i] = input[enc_map[i]]

            # Under DECRYPTION (what we care about - CT is the output):
            # If CT = ColEncrypt(intermediate), then intermediate[enc_map[i]] = CT[i]
            # Or equivalently: intermediate[j] = CT[inv_map[j]]
            # where inv_map is the inverse of enc_map

            # For Bean analysis under substitution-THEN-transposition:
            # CT[i] = intermediate[enc_map[i]] where intermediate = Encrypt(PT, key)
            # The "implied key" at CT position i depends on intermediate[enc_map[i]]
            # = Encrypt(PT[enc_map[i]], key[enc_map[i]])
            # So CT[i] = PT[enc_map[i]] + key[enc_map[i]]  (Vigenere)
            # And the implied key value that we'd infer at CT position i is:
            # key[enc_map[i]] = CT[i] - PT[enc_map[i]]

            # For Bean equality at CT positions bean_a_rel and bean_b_rel:
            # We need: key[enc_map[bean_a_rel]] == key[enc_map[bean_b_rel]]
            # which means the running key at the SOURCE positions must be equal.

            src_a = enc_map[bean_a_rel]
            src_b = enc_map[bean_b_rel]

            # Check if source positions have crib data
            # The crib positions (relative) that have known plaintext
            pt_src_a = crib_rel.get(src_a)
            pt_src_b = crib_rel.get(src_b)
            ct_a = substr[bean_a_rel]
            ct_b = substr[bean_b_rel]

            # For the Bean check, we need to check if the implied key values are equal
            # Under Vigenere: key = CT - PT, so key_a = CT[bean_a_rel] - PT[src_a]
            # But we need the actual crib letters at the SOURCE positions

            # Actually, let's think about this more carefully in full-CT coordinates.
            # The transposition only applies to positions 26-96.
            # Positions 0-25 are untouched.
            # So for the full CT, a transposition sigma on [26..96] means:
            #   Full_CT[i] = intermediate[i] for i < 26
            #   Full_CT[26+j] = intermediate[26 + enc_map[j]] for j = 0..70

            # Bean equality: at FULL positions 27 and 65
            # Full_CT[27] = intermediate[26 + enc_map[27-26]] = intermediate[26 + enc_map[1]]
            # Full_CT[65] = intermediate[26 + enc_map[65-26]] = intermediate[26 + enc_map[39]]

            # If intermediate = Encrypt(PT, key), then:
            # Full_CT[27] = PT[26+src_a] + key[26+src_a]
            # Full_CT[65] = PT[26+src_b] + key[26+src_b]

            # Bean says the implied keys at positions 27 and 65 of the final CT
            # must be equal. But the "implied key" at final CT position 27 is:
            # It depends on whether we define the key as position-dependent on
            # the CT coordinate or the PT coordinate.

            # Under CT-coordinate key (running key matched to CT position):
            # CT[27] = PT[src_full_a] + key_ct[27]
            # CT[65] = PT[src_full_b] + key_ct[65]
            # Bean: key_ct[27] == key_ct[65]
            # => CT[27]-PT[src_full_a] == CT[65]-PT[src_full_b]

            src_full_a = OFFSET + src_a
            src_full_b = OFFSET + src_b

            # Check Bean eq: do we have crib data at source positions?
            if src_full_a in CRIB_DICT and src_full_b in CRIB_DICT:
                pt_a = ALPH_IDX[CRIB_DICT[src_full_a]]
                pt_b = ALPH_IDX[CRIB_DICT[src_full_b]]
                ct_a_idx = ALPH_IDX[CT[27]]
                ct_b_idx = ALPH_IDX[CT[65]]

                vig_key_a = (ct_a_idx - pt_a) % MOD
                vig_key_b = (ct_b_idx - pt_b) % MOD
                beau_key_a = (ct_a_idx + pt_a) % MOD
                beau_key_b = (ct_b_idx + pt_b) % MOD

                vig_eq = vig_key_a == vig_key_b
                beau_eq = beau_key_a == beau_key_b

                if vig_eq or beau_eq:
                    bean_eq_count += 1
                    bean_eq_source_pairs.append((col_order, src_full_a, src_full_b, vig_eq, beau_eq))

                    # Now check full Bean constraints (all ineq + linear)
                    # Build implied keystream at all crib positions that are mapped
                    # For each crib position p (in full CT), the source is:
                    # If p >= 26: source = 26 + enc_map[p-26]
                    # If p < 26: source = p (no transposition)
                    implied_vig = {}
                    implied_beau = {}
                    all_have_crib = True
                    for crib_pos in sorted(CRIB_DICT.keys()):
                        if crib_pos < OFFSET:
                            # Not in transposed range
                            source = crib_pos
                        else:
                            rel = crib_pos - OFFSET
                            if rel < SUBLEN:
                                source = OFFSET + enc_map[rel]
                            else:
                                continue

                        if source in CRIB_DICT:
                            ct_val = ALPH_IDX[CT[crib_pos]]
                            pt_val = ALPH_IDX[CRIB_DICT[source]]
                            implied_vig[crib_pos] = (ct_val - pt_val) % MOD
                            implied_beau[crib_pos] = (ct_val + pt_val) % MOD
                        else:
                            all_have_crib = False

                    # Check full Bean on implied keys
                    if all_have_crib and len(implied_vig) == 24:
                        vig_pass = check_full_bean(implied_vig)
                        beau_pass = check_full_bean(implied_beau)
                        if vig_pass or beau_pass:
                            bean_full_pass_count += 1

        print(f"  Permutations satisfying Bean equality (where both sources have crib data): {bean_eq_count}")
        if bean_eq_source_pairs:
            print(f"  First few examples:")
            for entry in bean_eq_source_pairs[:5]:
                col_ord, s_a, s_b, v_eq, b_eq = entry
                print(f"    col_order={list(col_ord)}, sources=({s_a},{s_b}), vig_eq={v_eq}, beau_eq={b_eq}")
        print(f"  Permutations passing FULL Bean (eq+ineq+linear): {bean_full_pass_count}")


def check_full_bean(implied_keys: Dict[int, int]) -> bool:
    """Check all Bean constraints on implied key values."""
    for a, b in BEAN_EQ:
        if a in implied_keys and b in implied_keys:
            if implied_keys[a] != implied_keys[b]:
                return False
    for a, b in BEAN_INEQ:
        if a in implied_keys and b in implied_keys:
            if implied_keys[a] == implied_keys[b]:
                return False
    for a, b, c, d in BEAN_LINEAR:
        if (a in implied_keys and b in implied_keys
                and c in implied_keys and d in implied_keys):
            if (implied_keys[a] - implied_keys[b]
                    - implied_keys[c] + implied_keys[d]) % MOD != 0:
                return False
    return True


# ============================================================================
# TEST 4: IC of positions 26-96
# ============================================================================

def test4_ic():
    print("=" * 80)
    print("TEST 4: INDEX OF COINCIDENCE")
    print("=" * 80)

    def compute_ic(text):
        n = len(text)
        if n <= 1:
            return 0.0
        counts = Counter(text)
        ic = sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))
        return ic

    ic_full = compute_ic(CT)
    ic_0_25 = compute_ic(CT[:26])
    ic_26_96 = compute_ic(CT[26:])
    ic_random = 1.0 / 26
    ic_english = 0.0667

    print(f"\nIC of full K4 (97 chars):     {ic_full:.6f}")
    print(f"IC of positions 0-25 (26 chars): {ic_0_25:.6f}")
    print(f"IC of positions 26-96 (71 chars): {ic_26_96:.6f}")
    print(f"IC random:                     {ic_random:.6f}")
    print(f"IC English:                    {ic_english:.6f}")
    print()

    print("Analysis:")
    if ic_26_96 < ic_random:
        print(f"  IC[26-96] = {ic_26_96:.6f} is BELOW random ({ic_random:.6f})")
        print("  This is unusual. Transposition preserves IC, so the pre-transposition")
        print("  text would also have had this low IC.")
        print("  A simple substitution cipher on English text would give IC ~ 0.067.")
        print("  Running-key cipher gives IC ~ 0.045.")
        print("  Polyalphabetic with many alphabets gives IC ~ 0.038.")
    elif ic_26_96 < 0.045:
        print(f"  IC[26-96] = {ic_26_96:.6f} is between random and running-key levels")
    else:
        print(f"  IC[26-96] = {ic_26_96:.6f} is above random, consistent with substitution")
    print()

    # Letter frequency analysis
    print("Letter frequency of positions 26-96:")
    substr = CT[26:]
    counts = Counter(substr)
    total = len(substr)
    for ch in sorted(counts.keys(), key=lambda c: -counts[c]):
        freq = counts[ch] / total
        bar = "#" * int(freq * 200)
        print(f"  {ch}: {counts[ch]:2d} ({freq:.3f}) {bar}")
    print()


# ============================================================================
# TEST 5: K2 coordinate digit group column widths
# ============================================================================

def test5_k2_digit_groups():
    print("=" * 80)
    print("TEST 5: K2 COORDINATE DIGIT GROUPS AS COLUMN WIDTHS")
    print("=" * 80)

    target = 71  # positions 26-96
    digits_str = K2_DIGIT_STRING  # "38576577844"

    print(f"\nK2 coordinate digits: {K2_DIGITS}")
    print(f"Digit string: '{digits_str}'")
    print(f"Target length: {target}")
    print()

    # Hypothesis suggested groupings: "38, 57, 65, 77, 844"
    hyp_groups = [38, 57, 65, 77, 844]
    hyp_sum = sum(hyp_groups)
    print(f"Hypothesis suggested groups: {hyp_groups}, sum = {hyp_sum}")
    print(f"  Sum == 71? {hyp_sum == target}")
    print(f"  Sum == 97? {hyp_sum == 97}")
    print(f"  These are clearly NOT column widths (values too large for 71 chars)")
    print()

    # Enumerate all ways to partition the digit string into groups
    # where each group forms a number, and the numbers sum to target
    print(f"Searching for all partitions of '{digits_str}' into number groups summing to {target}...")
    print()

    def partition_digit_string(s, target_sum, max_val=None):
        """Find all ways to split digit string s into numbers that sum to target_sum."""
        results = []

        def backtrack(idx, current_groups, remaining):
            if idx == len(s):
                if remaining == 0 and len(current_groups) > 0:
                    results.append(list(current_groups))
                return

            for end in range(idx + 1, len(s) + 1):
                num_str = s[idx:end]
                if len(num_str) > 1 and num_str[0] == '0':
                    continue  # no leading zeros
                num = int(num_str)
                if num == 0:
                    continue  # no zero-width columns
                if num > remaining:
                    break  # remaining digits can't make up the difference
                if max_val and num > max_val:
                    continue
                current_groups.append(num)
                backtrack(end, current_groups, remaining - num)
                current_groups.pop()

        backtrack(0, [], target_sum)
        return results

    # All partitions summing to 71
    partitions_71 = partition_digit_string(digits_str, 71)
    print(f"Partitions summing to {target}: {len(partitions_71)} found")
    for p in partitions_71:
        ncols = len(p)
        print(f"  {p} ({ncols} columns, sum={sum(p)})")
    print()

    # Also check partitions summing to 97 (full CT)
    partitions_97 = partition_digit_string(digits_str, 97)
    print(f"Partitions summing to 97 (full CT): {len(partitions_97)} found")
    for p in partitions_97:
        ncols = len(p)
        print(f"  {p} ({ncols} columns, sum={sum(p)})")
    print()

    # For practical column widths (max ~30), also filter
    partitions_71_practical = partition_digit_string(digits_str, 71, max_val=30)
    print(f"Partitions summing to 71 with max column width 30: {len(partitions_71_practical)} found")
    for p in partitions_71_practical:
        print(f"  {p} ({len(p)} columns, widths sum={sum(p)})")
    print()

    # Try individual digits as column widths
    digit_sum = sum(K2_DIGITS)
    print(f"Individual digits as widths: {K2_DIGITS}, sum = {digit_sum}")
    print(f"  Sum == 71? {digit_sum == 71}")
    print(f"  Sum == 97? {digit_sum == 97}")
    print()

    # Also check: can we use the digits 3-7 (column counts mentioned)
    print("Column counts 3-7 with uniform widths:")
    for ncols in range(3, 8):
        width = target / ncols
        print(f"  {ncols} columns: width = {target}/{ncols} = {width:.2f} (integer? {target % ncols == 0})")
    print()

    # For irregular column widths from the digit groups, test Bean compatibility
    print("Testing Bean compatibility for digit-group partitions (71 chars)...")
    print()

    for partition in partitions_71:
        if len(partition) > 10:
            continue  # skip unreasonable column counts
        ncols = len(partition)
        widths = partition

        # Build the columnar mapping with IRREGULAR column widths
        # The grid has columns of different widths (which is unusual but let's test)
        # Actually, the "widths" here would mean the NUMBER of rows in each column
        # In standard columnar, all columns have the same width.
        # With irregular widths, it's more like a "route cipher" with specified lengths.

        # Interpretation 1: widths = number of characters in each column
        # Total chars = sum(widths) = 71, which checks out
        # Characters are written row by row into a grid where columns have different heights
        # But that doesn't make standard sense for columnar transposition.

        # Interpretation 2: the digit groups give the NUMBER of columns,
        # and we use standard columnar with that many columns.
        # Let's test this interpretation instead.
        pass

    # Let's focus on standard columnar with ncols from 3-7 and irregular
    # column assignment from digit-group partitions
    print("For irregular-width columnar (characters assigned to columns of varying lengths):")
    print()

    for partition in partitions_71_practical:
        widths = partition
        ncols = len(widths)

        if ncols > 10:
            continue

        print(f"  Partition {widths} ({ncols} columns):")

        # Build mapping: text is written into columns of given widths
        # Reading order tries all column permutations

        # "Encrypt": write text into columns left-to-right, each column gets width[i] chars
        # Then read off columns in permuted order
        def irregular_encrypt_mapping(widths, length, col_order):
            """Map for irregular columnar: columns have different numbers of characters."""
            mapping = []
            # Compute starting index of each column's characters
            col_starts = [0]
            for w in widths:
                col_starts.append(col_starts[-1] + w)

            for col in col_order:
                start = col_starts[col]
                end = col_starts[col + 1]
                for pos in range(start, min(end, length)):
                    mapping.append(pos)
            return mapping

        # But wait - this isn't really columnar transposition.
        # In columnar, text is written ROW by ROW and read COLUMN by COLUMN.
        # With irregular widths, the grid is rectangular with some short columns.

        # For a proper irregular columnar with specified column widths:
        # The grid has max_width = max(widths) rows... no, that's not right either.
        # Let me think about this differently.

        # Actually: "column widths" in the digit-group sense likely means
        # the column COUNT is the number of groups, and the widths specify
        # how many rows each column has. So a partition like [3,8,5,7,6,5,7,7,8,4,4]
        # would mean 11 columns with heights 3,8,5,7,6,5,7,7,8,4,4.

        # This is exactly the "columnar with nulls" or "incomplete columnar" concept.
        # Text fills row by row; some columns are shorter than others.

        # Actually, for standard columnar on 71 chars with ncols columns:
        # nrows = ceil(71/ncols), and the last row has (71 mod ncols) or ncols chars
        # The "short" columns have nrows-1 chars, "long" columns have nrows chars.

        # The digit partition gives EXPLICIT column heights.
        # This is equivalent to a specific arrangement of the incomplete grid.

        # For now, let's just test whether standard columnar (3-7 cols) works.
        # The digit partition tests are a stretch.

        n_perms = math.factorial(ncols)
        if n_perms > 100000:
            print(f"    Skipping: {n_perms} permutations too many")
            continue

        # For irregular columnar, check Bean eq
        bean_eq_count = 0
        OFFSET = 26
        bean_a_rel = 1   # position 27 - 26
        bean_b_rel = 39  # position 65 - 26

        for perm in itertools.permutations(range(ncols)):
            col_order = list(perm)
            enc_map = irregular_encrypt_mapping(widths, 71, col_order)

            if bean_a_rel < len(enc_map) and bean_b_rel < len(enc_map):
                src_a = enc_map[bean_a_rel]
                src_b = enc_map[bean_b_rel]
                src_full_a = OFFSET + src_a
                src_full_b = OFFSET + src_b

                if src_full_a in CRIB_DICT and src_full_b in CRIB_DICT:
                    pt_a = ALPH_IDX[CRIB_DICT[src_full_a]]
                    pt_b = ALPH_IDX[CRIB_DICT[src_full_b]]
                    ct_a_idx = ALPH_IDX[CT[27]]
                    ct_b_idx = ALPH_IDX[CT[65]]

                    vig_key_a = (ct_a_idx - pt_a) % MOD
                    vig_key_b = (ct_b_idx - pt_b) % MOD
                    beau_key_a = (ct_a_idx + pt_a) % MOD
                    beau_key_b = (ct_b_idx + pt_b) % MOD

                    if vig_key_a == vig_key_b or beau_key_a == beau_key_b:
                        bean_eq_count += 1

        print(f"    Bean eq hits: {bean_eq_count} / {n_perms}")
    print()


# ============================================================================
# BONUS: Summary of constraint interaction
# ============================================================================

def test_summary():
    print("=" * 80)
    print("SUMMARY: CONSTRAINT INTERACTION ANALYSIS")
    print("=" * 80)

    print()
    print("Bean constraints overview:")
    print(f"  Equality pairs: {len(BEAN_EQ)} -> {BEAN_EQ}")
    print(f"  Inequality pairs: {len(BEAN_INEQ)}")
    print(f"  Linear constraints: {len(BEAN_LINEAR)}")
    print()

    # Which Bean inequality pairs involve positions in range 26-96?
    ineq_in_range = [(a, b) for a, b in BEAN_INEQ if a >= 26 and b >= 26]
    ineq_cross = [(a, b) for a, b in BEAN_INEQ if (a < 26) != (b < 26)]
    ineq_outside = [(a, b) for a, b in BEAN_INEQ if a < 26 and b < 26]
    print(f"  Inequality pairs both in [26,96]: {len(ineq_in_range)}")
    print(f"  Inequality pairs crossing boundary: {len(ineq_cross)}")
    print(f"  Inequality pairs both in [0,25]: {len(ineq_outside)}")
    print()

    # Crib positions
    crib_below_26 = [p for p in sorted(CRIB_DICT.keys()) if p < 26]
    crib_above_26 = [p for p in sorted(CRIB_DICT.keys()) if p >= 26]
    print(f"  Crib positions below 26: {crib_below_26}")
    print(f"  Crib positions >= 26: {crib_above_26}")
    print()

    # If transposition only affects 26-96, then crib positions below 26 are fixed.
    # Those are positions 21,22,23,24,25 (EASTN from EASTNORTHEAST)
    print("  If transposition only affects positions 26-96:")
    print(f"    Fixed crib positions (< 26): {crib_below_26}")
    print(f"    These letters in CT remain at their original positions: ", end="")
    for p in crib_below_26:
        print(f"CT[{p}]='{CT[p]}'(PT='{CRIB_DICT[p]}') ", end="")
    print()
    print(f"    Transposed crib positions (>= 26): {crib_above_26}")
    print(f"    These {len(crib_above_26)} crib letters get shuffled by the transposition")
    print()

    # Under the transposition model, Bean eq/ineq would need to be re-derived
    # Count how many Bean constraints involve at least one position >= 26
    eq_affected = [(a, b) for a, b in BEAN_EQ if a >= 26 or b >= 26]
    ineq_affected = [(a, b) for a, b in BEAN_INEQ if a >= 26 or b >= 26]
    linear_affected = [(a, b, c, d) for a, b, c, d in BEAN_LINEAR
                       if a >= 26 or b >= 26 or c >= 26 or d >= 26]
    print(f"  Bean constraints affected by transposition of [26,96]:")
    print(f"    Equality: {len(eq_affected)} / {len(BEAN_EQ)}")
    print(f"    Inequality: {len(ineq_affected)} / {len(BEAN_INEQ)}")
    print(f"    Linear: {len(linear_affected)} / {len(BEAN_LINEAR)}")
    print()

    print("CONCLUSION:")
    print("-" * 60)
    print("1. The hypothesis is factually wrong: BERLIN starts at position 63, not ~26.")
    print("   Position 26 is within EASTNORTHEAST (the 'R' in NORTH).")
    print()
    print("2. Bean constraints in their standard form assume no transposition.")
    print("   If positions 26-96 are transposed, ALL Bean constraints involving those")
    print("   positions must be re-derived for each specific transposition.")
    print()
    print("3. The IC of positions 26-96 provides no additional discrimination")
    print("   since transposition preserves IC.")
    print()
    print("4. The K2 digit groups do not naturally partition into column widths")
    print("   summing to 71 in any simple way (see Test 5 results above).")
    print()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    test1_factual_check()
    print()
    test2_bean_under_transposition()
    print()
    test3_exhaustive_columnar()
    print()
    test4_ic()
    print()
    test5_k2_digit_groups()
    print()
    test_summary()
