#!/usr/bin/env python3
"""
E-SOLVE-11: Keyword-Modulated Feedback & Digraphic Pair Hypotheses

Two remaining OPEN hypotheses from bespoke cipher analysis:

H30: Keyword-modulated autokey
     k[i] = f(keyword[i%p], state[i]) where state is CT/PT feedback.
     Standard autokey (k=PT[i-1] or k=CT[i-1]) was eliminated by E-FRAC-37,
     but keyword + feedback hybrids were NOT tested.

H31: Digraphic pair operations (98 chars = 49 pairs)
     "Try both 97 and 98" — 98 = 49 pairs. The cipher may operate on
     pairs of letters, with a question mark as the 98th character.
     Standard Playfair/Bifid eliminated, but bespoke 26-letter digraphic
     operations were NOT tested.

H32: Keyword-modulated Beaufort feedback
     Like H30 but specifically exploiting the Beaufort structure finding.

H33: Tableau walk cipher
     Start at a row of the KA tableau. For each position, the current row
     determines the substitution. Move to next row based on keyword + output.
"""

import sys
sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

CT_VALS = [ALPH_IDX[c] for c in CT]

VIG_KEY = {}
for i, v in enumerate(VIGENERE_KEY_ENE):
    VIG_KEY[21 + i] = v
for i, v in enumerate(VIGENERE_KEY_BC):
    VIG_KEY[63 + i] = v

BEAU_KEY = {}
for i, v in enumerate(BEAUFORT_KEY_ENE):
    BEAU_KEY[21 + i] = v
for i, v in enumerate(BEAUFORT_KEY_BC):
    BEAU_KEY[63 + i] = v

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

print("E-SOLVE-11: Keyword-Modulated Feedback & Digraphic Hypotheses")
print(f"CT: {CT[:50]}...")
print()

total_tested = 0
above_noise = 0
best_score = 0
best_config = ""


def check_bean_key(key_arr):
    """Check Bean constraints on a 97-element key array."""
    for a, b in BEAN_EQ:
        if key_arr[a] != key_arr[b]:
            return False
    for a, b in BEAN_INEQ:
        if key_arr[a] == key_arr[b]:
            return False
    return True


def crib_matches(key_arr, mode="vig"):
    """Count crib matches."""
    ref = VIG_KEY if mode == "vig" else BEAU_KEY
    return sum(1 for pos, val in ref.items() if key_arr[pos] == val)


def ic(text):
    from collections import Counter
    n = len(text)
    if n < 2:
        return 0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


# ======================================================================
# H30: Keyword + CT-feedback autokey
# k[i] = (keyword[i%p] + CT[i-d]) mod 26, delay d=1..5
# k[i] = (keyword[i%p] + PT[i-d]) mod 26 (requires forward simulation)
# k[i] = (keyword[i%p] * CT[i-d]) mod 26 (multiplicative)
# ======================================================================
print("=" * 70)
print("TEST 1: Keyword + CT-Feedback Autokey")
print("=" * 70)

keywords_to_test = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN", "CLOCK",
    "MATRIX", "CIPHER", "SECRET", "HIDDEN", "LIGHT", "POINT",
    "EQUINOX", "VICTORIA", "SCHEIDT", "SANBORN", "LOOMIS",
    "K", "KR", "KRY",  # short keywords
]

t1_count = 0
t1_above = 0

for kw in keywords_to_test:
    kw_vals = [ALPH_IDX[c] for c in kw]
    p = len(kw)

    for delay in range(1, 6):
        for combine_name, combine_fn in [
            ("add", lambda a, b: (a + b) % MOD),
            ("sub", lambda a, b: (a - b) % MOD),
            ("add_beau", lambda a, b: (a + b) % MOD),  # Beaufort convention
        ]:
            for feedback_source in ["ct", "key_prev"]:
                # Build key array
                key = [0] * CT_LEN

                # Initialize first 'delay' positions with just keyword
                for i in range(min(delay, CT_LEN)):
                    key[i] = kw_vals[i % p]

                for i in range(delay, CT_LEN):
                    kw_val = kw_vals[i % p]
                    if feedback_source == "ct":
                        fb_val = CT_VALS[i - delay]
                    else:  # key_prev
                        fb_val = key[i - delay]
                    key[i] = combine_fn(kw_val, fb_val)

                # Score against both Vig and Beau
                for mode in ["vig", "beau"]:
                    score = crib_matches(key, mode)
                    t1_count += 1

                    if score > 6:
                        t1_above += 1
                        bean = check_bean_key(key)
                        if mode == "vig":
                            pt = "".join(ALPH[(CT_VALS[i] - key[i]) % MOD] for i in range(CT_LEN))
                        else:
                            pt = "".join(ALPH[(key[i] - CT_VALS[i]) % MOD] for i in range(CT_LEN))

                        print(f"  {kw} delay={delay} {combine_name} fb={feedback_source} "
                              f"({mode}): {score}/24, Bean={'PASS' if bean else 'FAIL'}")
                        if score >= 10:
                            print(f"    PT: {pt[:60]}...")

                        if score > best_score:
                            best_score = score
                            best_config = f"H30: {kw} d={delay} {combine_name} fb={feedback_source} ({mode})"

total_tested += t1_count
above_noise += t1_above
print(f"\n  CT-feedback autokey: {t1_count} tested, {t1_above} above noise\n")


# ======================================================================
# H30b: PT-feedback autokey (forward simulation)
# k[i] = (keyword[i%p] + PT[i-d]) mod 26
# This is trickier: PT[i] = (CT[i] - k[i]) mod 26 depends on k[i]
# which depends on PT[i-d]. Need to simulate forward.
# ======================================================================
print("=" * 70)
print("TEST 2: Keyword + PT-Feedback Autokey (Forward Simulation)")
print("=" * 70)

t2_count = 0
t2_above = 0

for kw in keywords_to_test:
    kw_vals = [ALPH_IDX[c] for c in kw]
    p = len(kw)

    for delay in range(1, 4):
        for combine_name, combine_fn in [
            ("add", lambda a, b: (a + b) % MOD),
            ("sub", lambda a, b: (a - b) % MOD),
        ]:
            for convention in ["vig", "beau"]:
                # Forward simulation
                key = [0] * CT_LEN
                pt = [0] * CT_LEN

                # First 'delay' positions: key = keyword only
                for i in range(min(delay, CT_LEN)):
                    key[i] = kw_vals[i % p]
                    if convention == "vig":
                        pt[i] = (CT_VALS[i] - key[i]) % MOD
                    else:
                        pt[i] = (key[i] - CT_VALS[i]) % MOD

                for i in range(delay, CT_LEN):
                    kw_val = kw_vals[i % p]
                    fb_val = pt[i - delay]
                    key[i] = combine_fn(kw_val, fb_val)
                    if convention == "vig":
                        pt[i] = (CT_VALS[i] - key[i]) % MOD
                    else:
                        pt[i] = (key[i] - CT_VALS[i]) % MOD

                score = crib_matches(key, convention)
                t2_count += 1

                if score > 6:
                    t2_above += 1
                    bean = check_bean_key(key)
                    pt_text = "".join(ALPH[v] for v in pt)
                    pt_ic = ic(pt_text)
                    print(f"  {kw} delay={delay} {combine_name} PT-fb ({convention}): "
                          f"{score}/24, Bean={'PASS' if bean else 'FAIL'}, IC={pt_ic:.4f}")
                    if score >= 10:
                        print(f"    PT: {pt_text[:60]}...")

                    if score > best_score:
                        best_score = score
                        best_config = f"H30b: {kw} d={delay} {combine_name} PT-fb ({convention})"

total_tested += t2_count
above_noise += t2_above
print(f"\n  PT-feedback autokey: {t2_count} tested, {t2_above} above noise\n")


# ======================================================================
# H30c: Accumulated state feedback
# state[0] = keyword[0]
# k[i] = (keyword[i%p] + state[i]) mod 26
# state[i+1] = (state[i] + CT[i]) mod 26  (or + PT[i], + key[i])
# ======================================================================
print("=" * 70)
print("TEST 3: Accumulated State Feedback")
print("=" * 70)

t3_count = 0
t3_above = 0

for kw in keywords_to_test:
    kw_vals = [ALPH_IDX[c] for c in kw]
    p = len(kw)

    for init_state in range(26):
        for state_update in ["ct", "key", "ct_plus_key"]:
            for convention in ["vig", "beau"]:
                key = [0] * CT_LEN
                pt = [0] * CT_LEN
                state = init_state

                for i in range(CT_LEN):
                    key[i] = (kw_vals[i % p] + state) % MOD
                    if convention == "vig":
                        pt[i] = (CT_VALS[i] - key[i]) % MOD
                    else:
                        pt[i] = (key[i] - CT_VALS[i]) % MOD

                    if state_update == "ct":
                        state = (state + CT_VALS[i]) % MOD
                    elif state_update == "key":
                        state = (state + key[i]) % MOD
                    else:  # ct_plus_key
                        state = (state + CT_VALS[i] + key[i]) % MOD

                score = crib_matches(key, convention)
                t3_count += 1

                if score > 6:
                    t3_above += 1
                    bean = check_bean_key(key)
                    pt_text = "".join(ALPH[v] for v in pt)
                    pt_ic = ic(pt_text)
                    print(f"  {kw} s0={init_state} upd={state_update} ({convention}): "
                          f"{score}/24, Bean={'PASS' if bean else 'FAIL'}, IC={pt_ic:.4f}")
                    if score >= 10:
                        print(f"    PT: {pt_text[:60]}...")

                    if score > best_score:
                        best_score = score
                        best_config = f"H30c: {kw} s0={init_state} upd={state_update} ({convention})"

total_tested += t3_count
above_noise += t3_above
print(f"\n  Accumulated state: {t3_count} tested, {t3_above} above noise\n")


# ======================================================================
# H33: Tableau walk cipher
# Current position in tableau determines substitution.
# Move rule: next_row = (keyword[i%p] + column_of_output) mod 26
# ======================================================================
print("=" * 70)
print("TEST 4: Tableau Walk Cipher")
print("=" * 70)

t4_count = 0
t4_above = 0

# Build KA tableau: row r is a cyclic shift of KA
KA_TABLEAU = []
for r in range(26):
    row = KRYPTOS_ALPHABET[r:] + KRYPTOS_ALPHABET[:r]
    KA_TABLEAU.append(row)

for kw in keywords_to_test[:15]:  # Limit for speed
    kw_vals = [ALPH_IDX[c] for c in kw]
    p = len(kw)

    for start_row in range(26):
        for move_rule in range(4):
            # move_rule 0: next_row = (kw[i%p] + ct_col) mod 26
            # move_rule 1: next_row = (kw[i%p] + pt_col) mod 26
            # move_rule 2: next_row = (current_row + kw[i%p]) mod 26
            # move_rule 3: next_row = (current_row + ct_val) mod 26

            key = [0] * CT_LEN
            pt = [0] * CT_LEN
            row = start_row

            for i in range(CT_LEN):
                # Current row of tableau gives the substitution alphabet
                tableau_row = KA_TABLEAU[row]

                # Decrypt: find CT[i] in the tableau row, PT = column header
                ct_char = CT[i]
                col = tableau_row.index(ct_char)  # position in this row
                pt_char = KRYPTOS_ALPHABET[col]  # column header = plaintext
                pt[i] = ALPH_IDX[pt_char]

                # Compute effective key for scoring
                key[i] = (CT_VALS[i] - pt[i]) % MOD

                # Move to next row
                if move_rule == 0:
                    row = (kw_vals[i % p] + col) % 26
                elif move_rule == 1:
                    row = (kw_vals[i % p] + pt[i]) % 26
                elif move_rule == 2:
                    row = (row + kw_vals[i % p]) % 26
                elif move_rule == 3:
                    row = (row + CT_VALS[i]) % 26

            score = crib_matches(key, "vig")
            t4_count += 1

            if score > 6:
                t4_above += 1
                bean = check_bean_key(key)
                pt_text = "".join(ALPH[v] for v in pt)
                pt_ic = ic(pt_text)
                print(f"  {kw} start={start_row} rule={move_rule}: "
                      f"{score}/24, Bean={'PASS' if bean else 'FAIL'}, IC={pt_ic:.4f}")
                if score >= 10:
                    print(f"    PT: {pt_text[:60]}...")

                if score > best_score:
                    best_score = score
                    best_config = f"H33: {kw} start={start_row} rule={move_rule}"

    # Also test with Beaufort-like tableau operation
    for start_row in range(26):
        key = [0] * CT_LEN
        pt = [0] * CT_LEN
        row = start_row

        for i in range(CT_LEN):
            # Beaufort-like: PT = row[CT_col] where CT_col = KA_IDX[CT[i]]
            ct_ka_pos = KA_IDX[CT[i]]
            pt_char = KA_TABLEAU[row][ct_ka_pos]
            pt[i] = ALPH_IDX[pt_char]
            key[i] = (CT_VALS[i] - pt[i]) % MOD

            # Move: simple keyword advance
            row = (row + kw_vals[i % p]) % 26

        score = crib_matches(key, "vig")
        t4_count += 1

        if score > 6:
            t4_above += 1
            bean = check_bean_key(key)
            pt_text = "".join(ALPH[v] for v in pt)
            print(f"  {kw} start={start_row} beau-tableau: "
                  f"{score}/24, Bean={'PASS' if bean else 'FAIL'}")

total_tested += t4_count
above_noise += t4_above
print(f"\n  Tableau walk: {t4_count} tested, {t4_above} above noise\n")


# ======================================================================
# H31: Digraphic pair operations
# Test 98-char interpretation (CT + ?/padding char)
# ======================================================================
print("=" * 70)
print("TEST 5: Digraphic Pair Operations (98 = 49 pairs)")
print("=" * 70)

t5_count = 0
t5_above = 0

# Extended CT: 97 chars + one padding char (try each letter)
for pad_pos in ["end", "start"]:
    for pad_char in range(26):
        if pad_pos == "end":
            ext_ct = CT_VALS + [pad_char]
        else:
            ext_ct = [pad_char] + CT_VALS

        # Pair the characters
        pairs = [(ext_ct[2*i], ext_ct[2*i+1]) for i in range(49)]

        # Test various pair operations
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW"]:
            kw_vals = [ALPH_IDX[c] for c in kw]
            p = len(kw)

            # Operation 1: Additive pair with dual keyword cycle
            pt_vals = []
            for pair_idx in range(49):
                a, b = pairs[pair_idx]
                ka = kw_vals[(2 * pair_idx) % p]
                kb = kw_vals[(2 * pair_idx + 1) % p]
                pt_vals.extend([(a - ka) % MOD, (b - kb) % MOD])

            # Remove padding and score
            if pad_pos == "end":
                pt_97 = pt_vals[:97]
            else:
                pt_97 = pt_vals[1:98]

            # Score
            matches = 0
            for pos, expected_pt in CRIB_DICT.items():
                if pt_97[pos] == ALPH_IDX[expected_pt]:
                    matches += 1

            t5_count += 1
            if matches > 6:
                t5_above += 1
                pt_text = "".join(ALPH[v] for v in pt_97)
                print(f"  pad={ALPH[pad_char]}@{pad_pos} kw={kw} additive: {matches}/24")

            # Operation 2: Swap within pair + keyword
            pt_vals = []
            for pair_idx in range(49):
                a, b = pairs[pair_idx]
                k = kw_vals[pair_idx % p]
                # Swap and shift
                pt_vals.extend([(b - k) % MOD, (a - k) % MOD])

            if pad_pos == "end":
                pt_97 = pt_vals[:97]
            else:
                pt_97 = pt_vals[1:98]

            matches = 0
            for pos, expected_pt in CRIB_DICT.items():
                if pt_97[pos] == ALPH_IDX[expected_pt]:
                    matches += 1

            t5_count += 1
            if matches > 6:
                t5_above += 1
                pt_text = "".join(ALPH[v] for v in pt_97)
                print(f"  pad={ALPH[pad_char]}@{pad_pos} kw={kw} swap+shift: {matches}/24")

            # Operation 3: Cross-addition (a+b mod 26 used as key)
            pt_vals = []
            for pair_idx in range(49):
                a, b = pairs[pair_idx]
                cross = (a + b) % MOD
                k = kw_vals[pair_idx % p]
                pt_vals.extend([(a - k - cross) % MOD, (b - k - cross) % MOD])

            if pad_pos == "end":
                pt_97 = pt_vals[:97]
            else:
                pt_97 = pt_vals[1:98]

            matches = 0
            for pos, expected_pt in CRIB_DICT.items():
                if pt_97[pos] == ALPH_IDX[expected_pt]:
                    matches += 1

            t5_count += 1
            if matches > 6:
                t5_above += 1

        # Operation 4: Polybius-like with 26 letters
        # Map each letter to (row, col) in a 2x13 grid
        for kw in ["KRYPTOS", "ABSCISSA"]:
            kw_vals = [ALPH_IDX[c] for c in kw]
            p = len(kw)

            pt_vals = []
            for pair_idx in range(49):
                a, b = pairs[pair_idx]
                # Interpret as coordinates: a=row (mod 2), b=col (mod 13)
                # Apply keyword shift to coordinates
                k = kw_vals[pair_idx % p]
                new_row = (a - k) % 2
                new_col = (b - k) % 13
                pt_vals.extend([new_row, new_col])

            if pad_pos == "end":
                pt_97 = pt_vals[:97]
            else:
                pt_97 = pt_vals[1:98]

            matches = 0
            for pos, expected_pt in CRIB_DICT.items():
                if pos < len(pt_97) and pt_97[pos] == ALPH_IDX[expected_pt]:
                    matches += 1
            t5_count += 1

        # Operation 5: Interleaved pairing — (pos 0, pos 49), (pos 1, pos 50), etc.
        if pad_pos == "end":
            for kw in ["KRYPTOS", "SHADOW"]:
                kw_vals = [ALPH_IDX[c] for c in kw]
                p = len(kw)

                # Interleaved pairs
                inter_pairs = [(ext_ct[i], ext_ct[i + 49]) for i in range(49)]

                pt_vals_first = [0] * 49
                pt_vals_second = [0] * 49

                for pair_idx in range(49):
                    a, b = inter_pairs[pair_idx]
                    k = kw_vals[pair_idx % p]
                    pt_vals_first[pair_idx] = (a - k) % MOD
                    pt_vals_second[pair_idx] = (b - k) % MOD

                # Reconstruct: deinterleave
                pt_97 = [0] * 98
                for i in range(49):
                    pt_97[i] = pt_vals_first[i]
                    pt_97[i + 49] = pt_vals_second[i]
                pt_97 = pt_97[:97]

                matches = 0
                for pos, expected_pt in CRIB_DICT.items():
                    if pt_97[pos] == ALPH_IDX[expected_pt]:
                        matches += 1

                t5_count += 1
                if matches > 6:
                    t5_above += 1
                    pt_text = "".join(ALPH[v] for v in pt_97)
                    print(f"  interleaved kw={kw}: {matches}/24")

total_tested += t5_count
above_noise += t5_above
print(f"\n  Digraphic pairs: {t5_count} tested, {t5_above} above noise\n")


# ======================================================================
# H34: Exhaustive primer search for autokey variants
# Instead of testing specific keywords, algebraically derive what
# the primer values MUST be for autokey to match cribs.
# For CT-autokey: k[i] = sum(CT[i-1], CT[i-2], ...) mod 26 + primer[i%p]
# The primer values at specific residues are determined by the cribs.
# ======================================================================
print("=" * 70)
print("TEST 6: Algebraic Autokey Primer Derivation")
print("=" * 70)

t6_count = 0
t6_above = 0

# For CT-autokey with period-p keyword:
# k[i] = keyword[i%p] + CT[i-1] (mod 26)
# At crib positions, we know k[i]. So:
# keyword[i%p] = k[i] - CT[i-1] (mod 26)
# This gives us the keyword value at residue (i%p) from each crib position.

for convention_name, known_key in [("vig", VIG_KEY), ("beau", BEAU_KEY)]:
    for delay in [1, 2]:
        for combine in ["add", "sub"]:
            for period in range(2, 20):
                # Derive keyword values from crib positions
                residue_vals = {}
                consistent = True

                for pos, kval in known_key.items():
                    if pos - delay < 0:
                        continue  # Can't look back before start
                    r = pos % period
                    ct_prev = CT_VALS[pos - delay]

                    if combine == "add":
                        kw_val = (kval - ct_prev) % MOD
                    else:
                        kw_val = (kval + ct_prev) % MOD

                    if r in residue_vals:
                        if residue_vals[r] != kw_val:
                            consistent = False
                            break
                    else:
                        residue_vals[r] = kw_val

                t6_count += 1

                if consistent and len(residue_vals) > 0:
                    # Build keyword
                    kw = [0] * period
                    for r, v in residue_vals.items():
                        kw[r] = v
                    kw_text = "".join(ALPH[v] for v in kw)
                    constrained = len(residue_vals)
                    free = period - constrained

                    # Build full key and decrypt
                    full_key = [0] * CT_LEN
                    for i in range(delay):
                        full_key[i] = kw[i % period]
                    for i in range(delay, CT_LEN):
                        ct_prev = CT_VALS[i - delay]
                        if combine == "add":
                            full_key[i] = (kw[i % period] + ct_prev) % MOD
                        else:
                            full_key[i] = (kw[i % period] - ct_prev) % MOD

                    # Verify crib score
                    score = crib_matches(full_key, convention_name)

                    if score >= 24:
                        bean = check_bean_key(full_key)
                        if convention_name == "vig":
                            pt_text = "".join(ALPH[(CT_VALS[i] - full_key[i]) % MOD] for i in range(CT_LEN))
                        else:
                            pt_text = "".join(ALPH[(full_key[i] - CT_VALS[i]) % MOD] for i in range(CT_LEN))
                        pt_ic = ic(pt_text)
                        vp = sum(1 for c in pt_text if c in "AEIOU") / CT_LEN * 100

                        t6_above += 1

                        if free <= 2 or bean or pt_ic > 0.05:
                            print(f"  *** {convention_name} delay={delay} {combine} period={period}: "
                                  f"{score}/24, Bean={'PASS' if bean else 'FAIL'}, "
                                  f"IC={pt_ic:.4f}, vowels={vp:.0f}%")
                            print(f"      Keyword: {kw_text} (free={free})")
                            print(f"      PT: {pt_text}")

                            if score > best_score or (score == best_score and bean):
                                best_score = score
                                best_config = f"H34: {convention_name} d={delay} {combine} p={period}"

total_tested += t6_count
above_noise += t6_above
print(f"\n  Algebraic autokey: {t6_count} tested, {t6_above} above noise\n")


# ======================================================================
# H35: Running state autokey (state = accumulated sum of CT or PT)
# k[i] = keyword[i%p] + sum(CT[0..i-1]) mod 26
# ======================================================================
print("=" * 70)
print("TEST 7: Running Sum Autokey")
print("=" * 70)

t7_count = 0
t7_above = 0

# Compute running sums
ct_running_sum = [0] * CT_LEN
s = 0
for i in range(CT_LEN):
    ct_running_sum[i] = s
    s = (s + CT_VALS[i]) % MOD

for convention_name, known_key in [("vig", VIG_KEY), ("beau", BEAU_KEY)]:
    for period in range(2, 20):
        # At crib positions: keyword[i%p] = known_key[i] - ct_running_sum[i] (mod 26)
        residue_vals = {}
        consistent = True

        for pos, kval in known_key.items():
            r = pos % period
            kw_val = (kval - ct_running_sum[pos]) % MOD

            if r in residue_vals:
                if residue_vals[r] != kw_val:
                    consistent = False
                    break
            else:
                residue_vals[r] = kw_val

        t7_count += 1

        if consistent:
            kw = [0] * period
            for r, v in residue_vals.items():
                kw[r] = v
            kw_text = "".join(ALPH[v] for v in kw)
            constrained = len(residue_vals)
            free = period - constrained

            # Build full key
            full_key = [(kw[i % period] + ct_running_sum[i]) % MOD for i in range(CT_LEN)]
            score = crib_matches(full_key, convention_name)

            if score >= 24:
                bean = check_bean_key(full_key)
                if convention_name == "vig":
                    pt_text = "".join(ALPH[(CT_VALS[i] - full_key[i]) % MOD] for i in range(CT_LEN))
                else:
                    pt_text = "".join(ALPH[(full_key[i] - CT_VALS[i]) % MOD] for i in range(CT_LEN))
                pt_ic = ic(pt_text)
                vp = sum(1 for c in pt_text if c in "AEIOU") / CT_LEN * 100

                t7_above += 1

                if free <= 2 or bean or pt_ic > 0.05:
                    print(f"  *** {convention_name} running_sum period={period}: "
                          f"{score}/24, Bean={'PASS' if bean else 'FAIL'}, "
                          f"IC={pt_ic:.4f}, vowels={vp:.0f}%")
                    print(f"      Keyword: {kw_text} (free={free})")
                    print(f"      PT: {pt_text}")

                    if score > best_score or (score == best_score and bean):
                        best_score = score
                        best_config = f"H35: {convention_name} running_sum p={period}"

total_tested += t7_count
above_noise += t7_above
print(f"\n  Running sum autokey: {t7_count} tested, {t7_above} above noise\n")


# ======================================================================
# H36: KA-tableau accumulated state
# Use KA alphabet instead of standard for all arithmetic
# ======================================================================
print("=" * 70)
print("TEST 8: KA-Space Accumulated State")
print("=" * 70)

t8_count = 0
t8_above = 0

CT_KA = [KA_IDX[c] for c in CT]

# KA running sum
ka_running_sum = [0] * CT_LEN
s = 0
for i in range(CT_LEN):
    ka_running_sum[i] = s
    s = (s + CT_KA[i]) % MOD

# Build KA-space crib key
CRIB_KA = {}
for pos, ch in CRIB_DICT.items():
    pt_ka = KA_IDX[ch]
    ct_ka = CT_KA[pos]
    CRIB_KA[pos] = (ct_ka - pt_ka) % MOD  # Vigenère in KA space

for period in range(2, 20):
    # In KA space: k_ka[i] = keyword_ka[i%p] + ka_running_sum[i] (mod 26)
    # keyword_ka[i%p] = crib_ka_key[i] - ka_running_sum[i] (mod 26)

    residue_vals = {}
    consistent = True

    for pos, kval in CRIB_KA.items():
        r = pos % period
        kw_val = (kval - ka_running_sum[pos]) % MOD

        if r in residue_vals:
            if residue_vals[r] != kw_val:
                consistent = False
                break
        else:
            residue_vals[r] = kw_val

    t8_count += 1

    if consistent:
        kw = [0] * period
        for r, v in residue_vals.items():
            kw[r] = v
        kw_text = "".join(KRYPTOS_ALPHABET[v] for v in kw)
        constrained = len(residue_vals)
        free = period - constrained

        # Full key in KA space
        full_ka_key = [(kw[i % period] + ka_running_sum[i]) % MOD for i in range(CT_LEN)]

        # Decrypt in KA space
        pt_ka_vals = [(CT_KA[i] - full_ka_key[i]) % MOD for i in range(CT_LEN)]
        pt_text = "".join(KRYPTOS_ALPHABET[v] for v in pt_ka_vals)
        pt_ic = ic(pt_text)
        vp = sum(1 for c in pt_text if c in "AEIOU") / CT_LEN * 100

        t8_above += 1

        if free <= 2 or pt_ic > 0.05:
            print(f"  *** KA running_sum period={period}: "
                  f"IC={pt_ic:.4f}, vowels={vp:.0f}%")
            print(f"      KA Keyword: {kw_text} (free={free})")
            print(f"      PT: {pt_text}")

total_tested += t8_count
above_noise += t8_above
print(f"\n  KA-space accumulated: {t8_count} tested, {t8_above} consistent\n")


# ======================================================================
# SUMMARY
# ======================================================================
print("\n" + "=" * 70)
print("E-SOLVE-11 COMPLETE")
print("=" * 70)
print(f"  Total configs tested: {total_tested}")
print(f"  Above noise: {above_noise}")
print(f"  Best score: {best_score}/24")
print(f"  Best config: {best_config}")
print()
