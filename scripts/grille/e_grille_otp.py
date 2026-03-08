#!/usr/bin/env python3
"""
Grille OTP Hypothesis: Test the Cardan grille extract as a full one-time-pad keystream.

Cipher: OTP / Vigenere-with-full-keystream
Family: grille
Status: active
Keyspace: ~2400 configs (windows x ciphers x alphabets x shifts x reversals x permutation)
Last run: never
Best score: n/a

Hypothesis: The 100-char (or 106-char old) grille extract IS the complete keystream,
not a clue to a short keyword. PT -> Vig/Beau/VarBeau encrypt with 97 non-repeating
key chars -> CT.

Tests:
  1. Direct grille extract as keystream (4 windows x 3 ciphers x 2 alphabets = 24)
  2. Old 106-char extract (10 windows x 3 ciphers x 2 alphabets = 60)
  3. Bean check on each window offset
  4. Reversed extracts
  5. KA-index interpretation of extract
  6. Grille extract as permutation + keyword decrypt
  7. Caesar shifts of extract (+1..+25) as keystream
  8. Critical diagnostic: check extract chars at crib positions
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_WORDS, BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GRILLE_EXTRACT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"
GRILLE_EXTRACT_OLD = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
KA = KRYPTOS_ALPHABET

assert len(GRILLE_EXTRACT) == 100, f"Expected 100, got {len(GRILLE_EXTRACT)}"
assert len(GRILLE_EXTRACT_OLD) == 106, f"Expected 106, got {len(GRILLE_EXTRACT_OLD)}"

AZ_IDX = {c: i for i, c in enumerate(ALPH)}
KA_IDX = {c: i for i, c in enumerate(KA)}

# Top keywords to try when using extract as permutation
KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE", "DEFECTOR", "PARALLAX", "COLOPHON"]


# ---------------------------------------------------------------------------
# Cipher operations
# ---------------------------------------------------------------------------

def vig_decrypt(ct_str, key_nums, alph_str, alph_idx):
    """Vigenere decrypt: PT[i] = (CT[i] - K[i]) mod 26 in given alphabet."""
    out = []
    for i, c in enumerate(ct_str):
        ct_val = alph_idx[c]
        pt_val = (ct_val - key_nums[i]) % 26
        out.append(alph_str[pt_val])
    return ''.join(out)


def beau_decrypt(ct_str, key_nums, alph_str, alph_idx):
    """Beaufort decrypt: PT[i] = (K[i] - CT[i]) mod 26 in given alphabet."""
    out = []
    for i, c in enumerate(ct_str):
        ct_val = alph_idx[c]
        pt_val = (key_nums[i] - ct_val) % 26
        out.append(alph_str[pt_val])
    return ''.join(out)


def varbeau_decrypt(ct_str, key_nums, alph_str, alph_idx):
    """Variant Beaufort decrypt: PT[i] = (CT[i] + K[i]) mod 26 in given alphabet."""
    out = []
    for i, c in enumerate(ct_str):
        ct_val = alph_idx[c]
        pt_val = (ct_val + key_nums[i]) % 26
        out.append(alph_str[pt_val])
    return ''.join(out)


def compute_ic(text):
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    ic = sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))
    return ic


def check_cribs(plaintext):
    """Check how many crib positions match. Returns (match_count, total, details)."""
    matches = 0
    details = []
    for pos, expected_char in CRIB_DICT.items():
        if pos < len(plaintext):
            actual = plaintext[pos]
            match = actual == expected_char
            if match:
                matches += 1
                details.append(f"  pos {pos}: CT={CT[pos]} -> PT={actual} == {expected_char} MATCH")
            # Only show non-matches if there are some matches
    return matches, len(CRIB_DICT), details


def check_bean(key_nums):
    """Check Bean constraints on keystream values."""
    # Equality: k[27] == k[65]
    eq_pass = True
    for a, b in BEAN_EQ:
        if a < len(key_nums) and b < len(key_nums):
            if key_nums[a] != key_nums[b]:
                eq_pass = False

    # Inequalities
    ineq_pass = 0
    ineq_total = 0
    for a, b in BEAN_INEQ:
        if a < len(key_nums) and b < len(key_nums):
            ineq_total += 1
            if key_nums[a] != key_nums[b]:
                ineq_pass += 1

    return eq_pass, ineq_pass, ineq_total


def extract_to_nums(extract_str, alph_idx):
    """Convert extract string to numeric key values using given alphabet ordering."""
    return [alph_idx[c] for c in extract_str]


def apply_permutation(ct_str, perm):
    """Apply permutation: output[i] = input[perm[i]] (gather convention)."""
    return ''.join(ct_str[perm[i]] for i in range(len(ct_str)))


def keyword_to_key_nums(keyword, alph_idx):
    """Convert keyword to repeating key numbers for CT length."""
    key_vals = [alph_idx[c] for c in keyword]
    return [key_vals[i % len(key_vals)] for i in range(CT_LEN)]


# ---------------------------------------------------------------------------
# Scoring helper
# ---------------------------------------------------------------------------

# English letter frequencies for a quick fitness score
ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074
}

def freq_score(text):
    """Chi-squared-like fitness: lower = more English-like."""
    n = len(text)
    if n == 0:
        return 999999
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    chi2 = 0
    for letter in ALPH:
        expected = n * ENGLISH_FREQ[letter] / 100.0
        observed = counts.get(letter, 0)
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

class ResultTracker:
    def __init__(self):
        self.results = []

    def add(self, test_name, plaintext, method, crib_matches, ic_val, freq,
            bean_eq=None, bean_ineq_str="", key_info=""):
        self.results.append({
            'test': test_name,
            'pt': plaintext,
            'method': method,
            'cribs': crib_matches,
            'ic': ic_val,
            'freq': freq,
            'bean_eq': bean_eq,
            'bean_ineq': bean_ineq_str,
            'key_info': key_info,
        })

    def print_top(self, n=30):
        # Sort by crib matches desc, then freq asc
        sorted_results = sorted(self.results, key=lambda r: (-r['cribs'], r['freq']))
        print(f"\n{'='*100}")
        print(f"TOP {n} RESULTS (out of {len(self.results)} total)")
        print(f"{'='*100}")
        for i, r in enumerate(sorted_results[:n]):
            bean_str = f"Bean EQ={'PASS' if r['bean_eq'] else 'FAIL'} {r['bean_ineq']}" if r['bean_eq'] is not None else ""
            print(f"\n#{i+1}: {r['test']}")
            print(f"  Method: {r['method']}")
            print(f"  Cribs: {r['cribs']}/24  IC: {r['ic']:.4f}  FreqScore: {r['freq']:.1f}  {bean_str}")
            print(f"  PT: {r['pt'][:97]}")
            if r['key_info']:
                print(f"  Key: {r['key_info']}")


tracker = ResultTracker()


# ===========================================================================
# TEST 8 (CRITICAL DIAGNOSTIC) - Run first as it's most informative
# ===========================================================================

def test8_crib_diagnostic():
    """Check what key chars the grille extract gives at crib positions."""
    print("\n" + "=" * 100)
    print("TEST 8: CRITICAL DIAGNOSTIC — Grille extract characters at crib positions")
    print("=" * 100)

    for extract_name, extract in [("Corrected (100)", GRILLE_EXTRACT), ("Old (106)", GRILLE_EXTRACT_OLD)]:
        max_offset = len(extract) - CT_LEN
        for offset in range(max_offset + 1):
            window = extract[offset:offset + CT_LEN]
            if len(window) < CT_LEN:
                continue

            print(f"\n--- {extract_name}, offset={offset} ---")

            for alph_name, alph_str, alph_idx in [("AZ", ALPH, AZ_IDX), ("KA", KA, KA_IDX)]:
                vig_matches = 0
                beau_matches = 0
                varbeau_matches = 0

                print(f"\n  Alphabet: {alph_name}")
                print(f"  {'Pos':>4} {'CT':>3} {'PT_exp':>7} {'Key_ch':>7} {'Vig_PT':>7} {'Beau_PT':>8} {'VarB_PT':>8} | {'Vig':>4} {'Beau':>5} {'VarB':>5}")

                for pos in sorted(CRIB_DICT.keys()):
                    ct_char = CT[pos]
                    pt_expected = CRIB_DICT[pos]
                    key_char = window[pos]

                    ct_val = alph_idx[ct_char]
                    key_val = alph_idx[key_char]

                    # Vigenere: PT = (CT - K) mod 26
                    vig_pt_val = (ct_val - key_val) % 26
                    vig_pt = alph_str[vig_pt_val]
                    vig_ok = vig_pt == pt_expected
                    if vig_ok:
                        vig_matches += 1

                    # Beaufort: PT = (K - CT) mod 26
                    beau_pt_val = (key_val - ct_val) % 26
                    beau_pt = alph_str[beau_pt_val]
                    beau_ok = beau_pt == pt_expected
                    if beau_ok:
                        beau_matches += 1

                    # Variant Beaufort: PT = (CT + K) mod 26
                    varbeau_pt_val = (ct_val + key_val) % 26
                    varbeau_pt = alph_str[varbeau_pt_val]
                    varbeau_ok = varbeau_pt == pt_expected
                    if varbeau_ok:
                        varbeau_matches += 1

                    vig_mark = "YES" if vig_ok else ""
                    beau_mark = "YES" if beau_ok else ""
                    varbeau_mark = "YES" if varbeau_ok else ""

                    print(f"  {pos:4d} {ct_char:>3} {pt_expected:>7} {key_char:>7} {vig_pt:>7} {beau_pt:>8} {varbeau_pt:>8} | {vig_mark:>4} {beau_mark:>5} {varbeau_mark:>5}")

                print(f"  TOTALS: Vig={vig_matches}/24  Beau={beau_matches}/24  VarBeau={varbeau_matches}/24")

                # What key chars WOULD be needed for Vigenere?
                if alph_name == "AZ" and offset == 0:
                    print(f"\n  Required Vigenere key at crib positions (AZ):")
                    needed = []
                    for pos in sorted(CRIB_DICT.keys()):
                        ct_val = AZ_IDX[CT[pos]]
                        pt_val = AZ_IDX[CRIB_DICT[pos]]
                        k_val = (ct_val - pt_val) % 26
                        k_char = ALPH[k_val]
                        actual_key = window[pos]
                        match = "MATCH" if k_char == actual_key else f"need {k_char}, got {actual_key}"
                        needed.append(f"    pos {pos}: {match}")
                        print(f"    pos {pos}: need key={k_char}({k_val}), have={actual_key}({AZ_IDX[actual_key]}) {'MATCH' if k_char == actual_key else 'MISS'}")


# ===========================================================================
# TEST 3: Bean check on grille extract windows
# ===========================================================================

def test3_bean_check():
    """Check Bean k[27]=k[65] for each window of each extract."""
    print("\n" + "=" * 100)
    print("TEST 3: Bean constraint check on grille extract windows")
    print("=" * 100)

    for extract_name, extract in [("Corrected (100)", GRILLE_EXTRACT), ("Old (106)", GRILLE_EXTRACT_OLD)]:
        max_offset = len(extract) - CT_LEN
        print(f"\n{extract_name}:")
        for offset in range(max_offset + 1):
            window = extract[offset:offset + CT_LEN]
            if len(window) < CT_LEN:
                continue

            for alph_name, alph_idx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
                key_nums = [alph_idx[c] for c in window]
                eq_pass, ineq_pass, ineq_total = check_bean(key_nums)

                status = "PASS" if eq_pass else "FAIL"
                k27 = window[27]
                k65 = window[65]

                print(f"  offset={offset} {alph_name}: k[27]={k27}({key_nums[27]}) k[65]={k65}({key_nums[65]}) "
                      f"EQ={status} | Inequalities: {ineq_pass}/{ineq_total} pass")


# ===========================================================================
# TEST 1: Direct grille extract as keystream (corrected, 100 chars)
# ===========================================================================

def test1_direct_keystream():
    """Try all 97-char windows of the corrected 100-char extract as OTP keystream."""
    print("\n" + "=" * 100)
    print("TEST 1: Corrected grille extract (100 chars) as direct keystream")
    print("=" * 100)

    for offset in range(len(GRILLE_EXTRACT) - CT_LEN + 1):
        window = GRILLE_EXTRACT[offset:offset + CT_LEN]

        for alph_name, alph_str, alph_idx in [("AZ", ALPH, AZ_IDX), ("KA", KA, KA_IDX)]:
            key_nums = extract_to_nums(window, alph_idx)
            eq_pass, ineq_pass, ineq_total = check_bean(key_nums)

            for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VarBeau", varbeau_decrypt)]:
                pt = decrypt_fn(CT, key_nums, alph_str, alph_idx)
                cribs, _, _ = check_cribs(pt)
                ic = compute_ic(pt)
                fs = freq_score(pt)

                method = f"Corrected extract offset={offset}, {cipher_name}, {alph_name}"
                bean_ineq_str = f"{ineq_pass}/{ineq_total}"
                tracker.add("T1-direct", pt, method, cribs, ic, fs, eq_pass, bean_ineq_str, window[:20]+"...")

                if cribs > 0:
                    print(f"  ** {method}: cribs={cribs}/24 IC={ic:.4f} freq={fs:.1f} Bean_EQ={'P' if eq_pass else 'F'}")
                    print(f"     PT: {pt}")


# ===========================================================================
# TEST 2: Old grille extract as keystream (106 chars)
# ===========================================================================

def test2_old_extract():
    """Try all 97-char windows of the old 106-char extract as OTP keystream."""
    print("\n" + "=" * 100)
    print("TEST 2: Old grille extract (106 chars) as direct keystream")
    print("=" * 100)

    for offset in range(len(GRILLE_EXTRACT_OLD) - CT_LEN + 1):
        window = GRILLE_EXTRACT_OLD[offset:offset + CT_LEN]

        for alph_name, alph_str, alph_idx in [("AZ", ALPH, AZ_IDX), ("KA", KA, KA_IDX)]:
            key_nums = extract_to_nums(window, alph_idx)
            eq_pass, ineq_pass, ineq_total = check_bean(key_nums)

            for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VarBeau", varbeau_decrypt)]:
                pt = decrypt_fn(CT, key_nums, alph_str, alph_idx)
                cribs, _, _ = check_cribs(pt)
                ic = compute_ic(pt)
                fs = freq_score(pt)

                method = f"Old extract offset={offset}, {cipher_name}, {alph_name}"
                bean_ineq_str = f"{ineq_pass}/{ineq_total}"
                tracker.add("T2-old", pt, method, cribs, ic, fs, eq_pass, bean_ineq_str, window[:20]+"...")

                if cribs > 0:
                    print(f"  ** {method}: cribs={cribs}/24 IC={ic:.4f} freq={fs:.1f} Bean_EQ={'P' if eq_pass else 'F'}")
                    print(f"     PT: {pt}")


# ===========================================================================
# TEST 4: Reversed extracts
# ===========================================================================

def test4_reversed():
    """Try reversed grille extracts as keystream."""
    print("\n" + "=" * 100)
    print("TEST 4: Reversed grille extracts as keystream")
    print("=" * 100)

    for extract_name, extract in [("Corrected-REV", GRILLE_EXTRACT[::-1]), ("Old-REV", GRILLE_EXTRACT_OLD[::-1])]:
        for offset in range(len(extract) - CT_LEN + 1):
            window = extract[offset:offset + CT_LEN]

            for alph_name, alph_str, alph_idx in [("AZ", ALPH, AZ_IDX), ("KA", KA, KA_IDX)]:
                key_nums = extract_to_nums(window, alph_idx)
                eq_pass, ineq_pass, ineq_total = check_bean(key_nums)

                for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VarBeau", varbeau_decrypt)]:
                    pt = decrypt_fn(CT, key_nums, alph_str, alph_idx)
                    cribs, _, _ = check_cribs(pt)
                    ic = compute_ic(pt)
                    fs = freq_score(pt)

                    method = f"{extract_name} offset={offset}, {cipher_name}, {alph_name}"
                    bean_ineq_str = f"{ineq_pass}/{ineq_total}"
                    tracker.add("T4-rev", pt, method, cribs, ic, fs, eq_pass, bean_ineq_str)

                    if cribs > 0:
                        print(f"  ** {method}: cribs={cribs}/24 IC={ic:.4f} freq={fs:.1f}")
                        print(f"     PT: {pt}")


# ===========================================================================
# TEST 5: KA-index interpretation
# ===========================================================================

def test5_ka_index():
    """Convert extract chars to KA-index numbers and use as shift values."""
    print("\n" + "=" * 100)
    print("TEST 5: KA-index / AZ-index interpretation of extract as key numbers")
    print("=" * 100)

    # The idea: instead of using AZ_IDX to convert key chars, use KA_IDX
    # but then decrypt with AZ alphabet (or vice versa, all combinations)

    combos = [
        ("key=KA_idx, cipher=AZ", KA_IDX, ALPH, AZ_IDX),  # key chars interpreted in KA order, decrypt in AZ
        ("key=AZ_idx, cipher=KA", AZ_IDX, KA, KA_IDX),     # key chars in AZ, decrypt in KA
        ("key=KA_idx, cipher=KA", KA_IDX, KA, KA_IDX),     # both KA
        ("key=AZ_idx, cipher=AZ", AZ_IDX, ALPH, AZ_IDX),   # both AZ (already tested in T1, but for completeness)
    ]

    for extract_name, extract in [("Corrected", GRILLE_EXTRACT), ("Old", GRILLE_EXTRACT_OLD)]:
        for offset in range(len(extract) - CT_LEN + 1):
            window = extract[offset:offset + CT_LEN]

            for combo_name, key_idx, cipher_alph, cipher_idx in combos:
                # Skip "both AZ" and "both KA" for corrected offset=0 — already tested in T1
                key_nums = [key_idx[c] for c in window]

                for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VarBeau", varbeau_decrypt)]:
                    pt = decrypt_fn(CT, key_nums, cipher_alph, cipher_idx)
                    cribs, _, _ = check_cribs(pt)
                    ic = compute_ic(pt)
                    fs = freq_score(pt)

                    method = f"{extract_name} off={offset}, {combo_name}, {cipher_name}"
                    tracker.add("T5-idx", pt, method, cribs, ic, fs)

                    if cribs > 0:
                        print(f"  ** {method}: cribs={cribs}/24 IC={ic:.4f} freq={fs:.1f}")
                        print(f"     PT: {pt}")


# ===========================================================================
# TEST 6: Grille extract as PERMUTATION
# ===========================================================================

def test6_permutation():
    """Use grille extract as permutation definition, then decrypt with keywords."""
    print("\n" + "=" * 100)
    print("TEST 6: Grille extract as permutation + keyword decryption")
    print("=" * 100)

    # Idea: convert 97 chars of extract to numbers, use as permutation indices
    # Since values are mod 26 (only 0-25), we need a mapping to 0-96.
    # Several strategies:

    for extract_name, extract in [("Corrected", GRILLE_EXTRACT), ("Old", GRILLE_EXTRACT_OLD)]:
        for offset in range(len(extract) - CT_LEN + 1):
            window = extract[offset:offset + CT_LEN]

            # Strategy A: Use the rank ordering of letters (stable sort) as permutation
            # Sort (char, original_index) by char, then the rank of each gives perm
            indexed = [(c, i) for i, c in enumerate(window)]
            sorted_indexed = sorted(indexed, key=lambda x: (x[0], x[1]))

            # perm[new_pos] = old_pos (gather: output[new_pos] = input[perm[new_pos]])
            perm_rank = [orig_idx for _, orig_idx in sorted_indexed]

            # Also try the inverse
            inv_perm_rank = [0] * CT_LEN
            for new_pos, old_pos in enumerate(perm_rank):
                inv_perm_rank[old_pos] = new_pos

            for perm_name, perm in [("rank", perm_rank), ("inv_rank", inv_perm_rank)]:
                # Apply permutation to CT
                try:
                    reordered = apply_permutation(CT, perm)
                except IndexError:
                    continue

                # Try plain (no keyword)
                cribs, _, _ = check_cribs(reordered)
                ic = compute_ic(reordered)
                fs = freq_score(reordered)
                method = f"{extract_name} off={offset} perm={perm_name}, no keyword"
                tracker.add("T6-perm", reordered, method, cribs, ic, fs)
                if cribs > 0:
                    print(f"  ** {method}: cribs={cribs}/24 IC={ic:.4f}")
                    print(f"     PT: {reordered}")

                # Try with keywords
                for keyword in KEYWORDS:
                    for alph_name, alph_str, alph_idx in [("AZ", ALPH, AZ_IDX), ("KA", KA, KA_IDX)]:
                        key_nums = keyword_to_key_nums(keyword, alph_idx)

                        for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                            pt = decrypt_fn(reordered, key_nums, alph_str, alph_idx)
                            cribs, _, _ = check_cribs(pt)
                            ic = compute_ic(pt)
                            fs = freq_score(pt)

                            method = f"{extract_name} off={offset} perm={perm_name}+{keyword}({cipher_name},{alph_name})"
                            tracker.add("T6-perm", pt, method, cribs, ic, fs)
                            if cribs > 1:  # Require 2+ for keyword combos (lots of configs)
                                print(f"  ** {method}: cribs={cribs}/24 IC={ic:.4f}")
                                print(f"     PT: {pt}")


# ===========================================================================
# TEST 7: Caesar shifts of extract as keystream
# ===========================================================================

def test7_caesar_shifts():
    """Shift entire extract by +1..+25 before using as keystream."""
    print("\n" + "=" * 100)
    print("TEST 7: Caesar-shifted grille extract as keystream")
    print("=" * 100)

    for extract_name, extract in [("Corrected", GRILLE_EXTRACT), ("Old", GRILLE_EXTRACT_OLD)]:
        for shift in range(1, 26):
            # Shift in AZ space
            shifted_az = ''.join(ALPH[(AZ_IDX[c] + shift) % 26] for c in extract)
            # Shift in KA space
            shifted_ka = ''.join(KA[(KA_IDX[c] + shift) % 26] for c in extract)

            for shift_alph_name, shifted in [("AZ-shift", shifted_az), ("KA-shift", shifted_ka)]:
                for offset in range(len(shifted) - CT_LEN + 1):
                    window = shifted[offset:offset + CT_LEN]

                    for alph_name, alph_str, alph_idx in [("AZ", ALPH, AZ_IDX), ("KA", KA, KA_IDX)]:
                        key_nums = [alph_idx[c] for c in window]

                        for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VarBeau", varbeau_decrypt)]:
                            pt = decrypt_fn(CT, key_nums, alph_str, alph_idx)
                            cribs, _, _ = check_cribs(pt)
                            ic = compute_ic(pt)
                            fs = freq_score(pt)

                            method = f"{extract_name} {shift_alph_name}+{shift} off={offset}, {cipher_name}, {alph_name}"
                            tracker.add("T7-shift", pt, method, cribs, ic, fs)

                            if cribs > 1:
                                print(f"  ** {method}: cribs={cribs}/24 IC={ic:.4f} freq={fs:.1f}")
                                print(f"     PT: {pt}")


# ===========================================================================
# BONUS: Systematic expected-key analysis
# ===========================================================================

def bonus_expected_key_analysis():
    """Determine what the OTP keystream MUST be at crib positions, and check extract."""
    print("\n" + "=" * 100)
    print("BONUS: Required keystream analysis at crib positions")
    print("=" * 100)

    print("\nFor Vigenere K = (CT - PT) mod 26 in AZ:")
    print(f"  ENE required key nums: {list(VIGENERE_KEY_ENE)}")
    print(f"  ENE required key chars: {''.join(ALPH[k] for k in VIGENERE_KEY_ENE)}")
    print(f"  BC  required key nums: {list(VIGENERE_KEY_BC)}")
    print(f"  BC  required key chars: {''.join(ALPH[k] for k in VIGENERE_KEY_BC)}")

    print("\nFor Beaufort K = (CT + PT) mod 26 in AZ:")
    # Beaufort encrypt: CT = (K - PT) mod 26, so K = (CT + PT) mod 26
    beau_ene = [(AZ_IDX[CT[pos]] + AZ_IDX[CRIB_DICT[pos]]) % 26 for pos in sorted(CRIB_DICT.keys()) if pos <= 33]
    beau_bc = [(AZ_IDX[CT[pos]] + AZ_IDX[CRIB_DICT[pos]]) % 26 for pos in sorted(CRIB_DICT.keys()) if pos >= 63]
    print(f"  ENE required key nums: {beau_ene}")
    print(f"  ENE required key chars: {''.join(ALPH[k] for k in beau_ene)}")
    print(f"  BC  required key nums: {beau_bc}")
    print(f"  BC  required key chars: {''.join(ALPH[k] for k in beau_bc)}")

    # Now check: does the extract at any offset contain these sequences?
    vig_ene_str = ''.join(ALPH[k] for k in VIGENERE_KEY_ENE)
    vig_bc_str = ''.join(ALPH[k] for k in VIGENERE_KEY_BC)
    beau_ene_str = ''.join(ALPH[k] for k in beau_ene)
    beau_bc_str = ''.join(ALPH[k] for k in beau_bc)

    print(f"\n  Vig  ENE key string: {vig_ene_str}")
    print(f"  Vig  BC  key string: {vig_bc_str}")
    print(f"  Beau ENE key string: {beau_ene_str}")
    print(f"  Beau BC  key string: {beau_bc_str}")

    # Search for these substrings in extracts
    for name, ext in [("Corrected", GRILLE_EXTRACT), ("Old", GRILLE_EXTRACT_OLD),
                       ("Corrected-REV", GRILLE_EXTRACT[::-1]), ("Old-REV", GRILLE_EXTRACT_OLD[::-1])]:
        for key_name, key_str in [("Vig_ENE", vig_ene_str), ("Vig_BC", vig_bc_str),
                                   ("Beau_ENE", beau_ene_str), ("Beau_BC", beau_bc_str)]:
            if key_str in ext:
                pos = ext.index(key_str)
                print(f"  *** FOUND {key_name} in {name} at position {pos}! ***")

    # Check partial matches: how many chars in the extract at pos 21 match Vig ENE key?
    print("\n  Checking extract positions 21-33 vs required Vig ENE key:")
    for ext_name, ext in [("Corrected", GRILLE_EXTRACT), ("Old", GRILLE_EXTRACT_OLD)]:
        for offset in range(len(ext) - CT_LEN + 1):
            window = ext[offset:offset + CT_LEN]
            ene_matches = sum(1 for i, pos in enumerate(range(21, 34))
                             if AZ_IDX[window[pos]] == VIGENERE_KEY_ENE[i])
            bc_matches = sum(1 for i, pos in enumerate(range(63, 74))
                            if pos < len(window) and AZ_IDX[window[pos]] == VIGENERE_KEY_BC[i])
            print(f"    {ext_name} offset={offset}: ENE key matches={ene_matches}/13, BC key matches={bc_matches}/11")

    # Also check Beaufort
    print("\n  Checking extract positions vs required Beaufort key:")
    for ext_name, ext in [("Corrected", GRILLE_EXTRACT), ("Old", GRILLE_EXTRACT_OLD)]:
        for offset in range(len(ext) - CT_LEN + 1):
            window = ext[offset:offset + CT_LEN]
            ene_matches = sum(1 for i, pos in enumerate(range(21, 34))
                             if AZ_IDX[window[pos]] == beau_ene[i])
            bc_matches = sum(1 for i, pos in enumerate(range(63, 74))
                            if pos < len(window) and AZ_IDX[window[pos]] == beau_bc[i])
            print(f"    {ext_name} offset={offset}: ENE key matches={ene_matches}/13, BC key matches={bc_matches}/11")


# ===========================================================================
# BONUS 2: Extract-to-extract comparison
# ===========================================================================

def bonus_extract_comparison():
    """Compare the two extracts character by character."""
    print("\n" + "=" * 100)
    print("BONUS: Character-by-character comparison of corrected vs old extract")
    print("=" * 100)

    print(f"  Corrected ({len(GRILLE_EXTRACT)}): {GRILLE_EXTRACT}")
    print(f"  Old       ({len(GRILLE_EXTRACT_OLD)}): {GRILLE_EXTRACT_OLD}")

    # IC of each
    print(f"\n  IC(corrected) = {compute_ic(GRILLE_EXTRACT):.4f}")
    print(f"  IC(old)       = {compute_ic(GRILLE_EXTRACT_OLD):.4f}")
    print(f"  IC(random)    = {1/26:.4f}")
    print(f"  IC(English)   = 0.0667")

    # Letter frequency in each
    for name, ext in [("Corrected", GRILLE_EXTRACT), ("Old", GRILLE_EXTRACT_OLD)]:
        counts = {}
        for c in ext:
            counts[c] = counts.get(c, 0) + 1
        present = sorted(counts.keys())
        missing = [c for c in ALPH if c not in counts]
        print(f"\n  {name} letter counts:")
        for c in ALPH:
            cnt = counts.get(c, 0)
            if cnt > 0:
                print(f"    {c}: {cnt}", end="")
        print()
        print(f"    Missing letters: {missing if missing else 'NONE (all 26 present)'}")
        print(f"    Freq score (chi2 vs English): {freq_score(ext):.1f}")


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    print("=" * 100)
    print("GRILLE OTP HYPOTHESIS: Testing Cardan grille extract as full keystream")
    print(f"K4 CT ({CT_LEN} chars): {CT}")
    print(f"Corrected extract ({len(GRILLE_EXTRACT)} chars): {GRILLE_EXTRACT}")
    print(f"Old extract ({len(GRILLE_EXTRACT_OLD)} chars): {GRILLE_EXTRACT_OLD}")
    print("=" * 100)

    # Run critical diagnostic first
    test8_crib_diagnostic()

    # Bean check
    test3_bean_check()

    # Bonus analyses
    bonus_expected_key_analysis()
    bonus_extract_comparison()

    # Direct keystream tests
    test1_direct_keystream()
    test2_old_extract()

    # Reversed
    test4_reversed()

    # Index interpretation
    test5_ka_index()

    # Permutation
    test6_permutation()

    # Caesar shifts
    test7_caesar_shifts()

    # Final summary
    tracker.print_top(30)

    # Print aggregate statistics
    total = len(tracker.results)
    with_cribs = sum(1 for r in tracker.results if r['cribs'] > 0)
    max_cribs = max(r['cribs'] for r in tracker.results) if tracker.results else 0

    print(f"\n{'='*100}")
    print(f"AGGREGATE: {total} total configs tested, {with_cribs} had >0 crib matches, max cribs = {max_cribs}/24")
    print(f"{'='*100}")

    if max_cribs >= 3:
        print("\n*** NOTABLE: 3+ crib matches found — investigate further ***")
    elif max_cribs == 0:
        print("\n*** NO crib matches at all — grille extract as direct OTP keystream is ELIMINATED ***")
    else:
        print(f"\n*** {max_cribs} crib match(es) found — likely noise (expected ~1 by chance) ***")


if __name__ == "__main__":
    main()
