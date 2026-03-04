#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Novel Method F: Chaocipher-like Evolving Alphabet.

Start with KRYPTOS alphabet, after each character mutate the alphabet
according to various rules. Also implements Nihilist-style numeric
encoding (Method H) and two-step visual method (Method G).
"""
import json
import sys
import os
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD, KRYPTOS_ALPHABET, ALPH
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results', 'novel_methods')
os.makedirs(RESULTS_DIR, exist_ok=True)

best_overall = {"score": 0, "method": "", "text": ""}
all_results = []


def check_candidate(text, method_name):
    global best_overall
    if not text or len(text) < 20:
        return 0
    text = text.upper()
    if not all(c.isalpha() for c in text):
        return 0
    sc = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            sc += 1
    if sc > best_overall["score"]:
        best_overall = {"score": sc, "method": method_name, "text": text}
    if sc > 2:
        all_results.append({"method": method_name, "score": sc, "text": text[:50] + "..."})
        print(f"  [ABOVE NOISE] {method_name}: {sc}/24")
    return sc


print("=" * 60)
print("NOVEL METHOD F: Chaocipher-like Evolving Alphabet")
print("=" * 60)

total_tested = 0


def rotate_left(alph, n):
    """Rotate alphabet left by n positions."""
    n = n % len(alph)
    return alph[n:] + alph[:n]


def permute_after_char(alph, ch):
    """Chaocipher-like: rotate alphabet so ch is at front, then shift right half."""
    idx = alph.index(ch)
    rotated = alph[idx:] + alph[:idx]
    # Move position 1 to position 13 (like Chaocipher right side)
    lst = list(rotated)
    if len(lst) > 13:
        char_to_move = lst.pop(1)
        lst.insert(13, char_to_move)
    return "".join(lst)


# Method F1: Simple rotation after each char
print("\n--- F1: Rotation after each character ---")
for start_alpha_name, start_alpha in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
    for rot_rule_name, rot_fn in [
        ("by_ct_val", lambda alph, ct_ch, pt_ch, pos: rotate_left(alph, ALPH_IDX.get(ct_ch, 0) + 1)),
        ("by_pt_val", lambda alph, ct_ch, pt_ch, pos: rotate_left(alph, ALPH_IDX.get(pt_ch, 0) + 1)),
        ("by_pos", lambda alph, ct_ch, pt_ch, pos: rotate_left(alph, pos + 1)),
        ("by_1", lambda alph, ct_ch, pt_ch, pos: rotate_left(alph, 1)),
        ("by_7", lambda alph, ct_ch, pt_ch, pos: rotate_left(alph, 7)),
        ("chaocipher_ct", lambda alph, ct_ch, pt_ch, pos: permute_after_char(alph, ct_ch)),
        ("chaocipher_pt", lambda alph, ct_ch, pt_ch, pos: permute_after_char(alph, pt_ch)),
    ]:
        for decrypt_mode in ["sub_lookup", "index_direct"]:
            alpha = start_alpha
            pt_chars = []
            for i in range(CT_LEN):
                ct_ch = CT[i]
                if decrypt_mode == "sub_lookup":
                    # Simple substitution: position in current alphabet = plaintext value
                    ct_idx = alpha.index(ct_ch) if ct_ch in alpha else 0
                    pt_ch = ALPH[ct_idx]
                else:
                    # Direct index mapping
                    ct_idx = ALPH_IDX[ct_ch]
                    pt_ch = alpha[ct_idx] if ct_idx < len(alpha) else "A"
                pt_chars.append(pt_ch)
                alpha = rot_fn(alpha, ct_ch, pt_ch, i)
            pt = "".join(pt_chars)
            method = f"evolving_{start_alpha_name}_{rot_rule_name}_{decrypt_mode}"
            check_candidate(pt, method)
            total_tested += 1

# Method F2: Dual evolving alphabets (like actual Chaocipher)
print("\n--- F2: Dual evolving alphabets ---")
for ct_alpha_name, ct_start in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
    for pt_alpha_name, pt_start in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
        ct_alpha = ct_start
        pt_alpha = pt_start
        pt_chars = []
        for i in range(CT_LEN):
            ch = CT[i]
            # Find ch in ct_alpha
            idx = ct_alpha.index(ch) if ch in ct_alpha else 0
            # Look up same index in pt_alpha
            pt_ch = pt_alpha[idx]
            pt_chars.append(pt_ch)
            # Evolve both alphabets
            ct_alpha = permute_after_char(ct_alpha, ch)
            pt_alpha = permute_after_char(pt_alpha, pt_ch)
        pt = "".join(pt_chars)
        method = f"dual_chaocipher_ct{ct_alpha_name}_pt{pt_alpha_name}"
        check_candidate(pt, method)
        total_tested += 1

# YAR-seeded evolution
print("\n--- F3: YAR-seeded evolution ---")
YAR = [24, 0, 17]
for start_alpha_name, start_alpha in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
    alpha = start_alpha
    # Pre-rotate by YAR values
    for yar_val in YAR:
        alpha = rotate_left(alpha, yar_val)
    pt_chars = []
    for i in range(CT_LEN):
        ch = CT[i]
        idx = alpha.index(ch) if ch in alpha else 0
        pt_chars.append(ALPH[idx])
        # Rotate by YAR cyclic
        alpha = rotate_left(alpha, YAR[i % 3] + 1)
    pt = "".join(pt_chars)
    method = f"yar_evolving_{start_alpha_name}"
    check_candidate(pt, method)
    total_tested += 1

print("\n" + "=" * 60)
print("NOVEL METHOD G: Two-Step Visual Method")
print("=" * 60)

# The sculpture text is laid out in rows. Try various row widths.
print("\n--- G1: Reverse rows then apply substitution ---")
for width in [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20, 86]:
    # Break CT into rows of given width
    rows = [CT[i:i+width] for i in range(0, CT_LEN, width)]

    # Reverse each row
    reversed_rows = "".join(row[::-1] for row in rows)
    check_candidate(reversed_rows[:CT_LEN], f"visual_reverse_rows_w{width}")
    total_tested += 1

    # Read bottom-to-top
    bottom_up = "".join(reversed(rows))
    check_candidate(bottom_up[:CT_LEN], f"visual_bottom_up_w{width}")
    total_tested += 1

    # Boustrophedon
    boustro = ""
    for i, row in enumerate(rows):
        if i % 2 == 0:
            boustro += row
        else:
            boustro += row[::-1]
    check_candidate(boustro[:CT_LEN], f"visual_boustro_w{width}")
    total_tested += 1

    # Read right-to-left, top-to-bottom
    rtl = "".join(row[::-1] for row in rows)
    check_candidate(rtl[:CT_LEN], f"visual_rtl_w{width}")
    total_tested += 1

    # Column-major read
    col_text = ""
    for c in range(width):
        for row in rows:
            if c < len(row):
                col_text += row[c]
    check_candidate(col_text[:CT_LEN], f"visual_colmajor_w{width}")
    total_tested += 1

    # Apply Caesar shifts to each visual reordering
    for reordered_name, reordered in [
        ("boustro", boustro[:CT_LEN]),
        ("colmajor", col_text[:CT_LEN]),
    ]:
        for shift in range(1, 26):
            shifted = "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in reordered if c.isalpha())
            check_candidate(shifted, f"visual_{reordered_name}_w{width}_caesar{shift}")
            total_tested += 1

print("\n" + "=" * 60)
print("NOVEL METHOD H: Nihilist-Style Numeric Encoding")
print("=" * 60)

# Build Polybius square (5x5, I/J merged — note: K4 uses all 26 letters, but try anyway)
# And a 6x6 variant that includes all 26 + digits
print("\n--- H1: Standard Polybius (5x5) with key ---")
def build_polybius(keyword=""):
    """Build 5x5 Polybius square with keyword."""
    seen = set()
    order = []
    for ch in keyword.upper() + ALPH:
        if ch == 'J':
            ch = 'I'
        if ch not in seen and ch.isalpha():
            seen.add(ch)
            order.append(ch)
    grid = {}
    reverse = {}
    for i, ch in enumerate(order[:25]):
        r, c = divmod(i, 5)
        grid[ch] = (r + 1, c + 1)  # 1-indexed
        reverse[(r + 1, c + 1)] = ch
    if 'J' not in grid:
        grid['J'] = grid.get('I', (2, 4))
    return grid, reverse


# Encode CT via Polybius, try subtracting various key sequences
for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "", "BERLIN"]:
    poly, rev_poly = build_polybius(kw)

    # CT -> pairs of digits
    ct_digits = []
    for ch in CT:
        c = ch if ch != 'J' else 'I'
        if c in poly:
            r, col = poly[c]
            ct_digits.extend([r, col])

    # Try subtracting various key sequences
    # Key from "KRYPTOS" repeated
    for key_text in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "EASTNORTHEAST"]:
        key_digits = []
        for ch in key_text:
            c = ch if ch != 'J' else 'I'
            if c in poly:
                r, col = poly[c]
                key_digits.extend([r, col])
        if not key_digits:
            continue
        key_full = (key_digits * ((len(ct_digits) // len(key_digits)) + 2))[:len(ct_digits)]

        for variant_name, op in [("sub", lambda a, b: ((a - b - 1) % 5) + 1),
                                  ("add", lambda a, b: ((a + b - 2) % 5) + 1)]:
            result_digits = [op(ct_digits[i], key_full[i]) for i in range(len(ct_digits))]
            # Convert back to text
            pt_chars = []
            for j in range(0, len(result_digits) - 1, 2):
                r, c = result_digits[j], result_digits[j + 1]
                if (r, c) in rev_poly:
                    pt_chars.append(rev_poly[(r, c)])
            pt = "".join(pt_chars)
            method = f"nihilist_poly{kw or 'std'}_key{key_text}_{variant_name}"
            check_candidate(pt, method)
            total_tested += 1

# Method H2: Direct numeric subtraction
print("\n--- H2: Direct numeric key subtraction ---")
# Key dates as numeric sequences
KEY_SEQS = {
    "1989_nov9": [1, 9, 8, 9, 1, 1, 0, 9],
    "kryptos_vals": [10, 17, 24, 15, 19, 14, 18],
    "yar": [24, 0, 17],
    "fibonacci": [],
    "primes": [2, 3, 5, 7, 11, 13, 17, 19, 23],
}
# Generate Fibonacci
a, b = 1, 1
fib = []
while len(fib) < 50:
    fib.append(a % 26)
    a, b = b, a + b
KEY_SEQS["fibonacci"] = fib

for seq_name, seq in KEY_SEQS.items():
    if not seq:
        continue
    key_full = (seq * ((CT_LEN // len(seq)) + 2))[:CT_LEN]
    for variant in ["sub", "add"]:
        pt_chars = []
        for i, ch in enumerate(CT):
            ct_val = ALPH_IDX[ch]
            if variant == "sub":
                pt_val = (ct_val - key_full[i]) % 26
            else:
                pt_val = (ct_val + key_full[i]) % 26
            pt_chars.append(chr(pt_val + 65))
        pt = "".join(pt_chars)
        method = f"numeric_key_{seq_name}_{variant}"
        check_candidate(pt, method)
        total_tested += 1

print(f"\nTotal evolving/visual/nihilist configs tested: {total_tested}")
print(f"Best: {best_overall['method']} -> {best_overall['score']}/24")
if best_overall['score'] > 0:
    print(f"  Text: {best_overall['text'][:60]}...")

with open(os.path.join(RESULTS_DIR, "chaocipher_visual_nihilist.json"), "w") as f:
    json.dump({
        "method": "chaocipher_visual_nihilist",
        "total_tested": total_tested,
        "best_score": best_overall["score"],
        "best_method": best_overall["method"],
        "best_text": best_overall["text"],
        "above_noise": all_results,
    }, f, indent=2)

print(f"\nResults saved to results/novel_methods/chaocipher_visual_nihilist.json")
