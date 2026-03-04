#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Novel Method C: Tableau as Physical Lookup Grid.

The Vigenere tableau is a 26x26 grid physically present on the sculpture.
Use CT letters as row/col indices with various column-selection methods.
Also use YAR (24, 0, 17) as coordinates or offsets.
"""
import json
import sys
import os
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, KRYPTOS_ALPHABET, ALPH, MOD
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results', 'novel_methods')
os.makedirs(RESULTS_DIR, exist_ok=True)

best_overall = {"score": 0, "method": "", "text": ""}
all_results = []

# YAR values
Y_VAL, A_VAL, R_VAL = 24, 0, 17

# Build standard Vigenere tableau
def build_tableau(alphabet):
    """Build a 26x26 Vigenere tableau from a given alphabet."""
    n = len(alphabet)
    tableau = []
    for i in range(n):
        row = alphabet[i:] + alphabet[:i]
        tableau.append(row)
    return tableau

# Standard and Kryptos tableaux
STD_TAB = build_tableau(ALPH)
KA_TAB = build_tableau(KRYPTOS_ALPHABET)
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}


def check_candidate(text, method_name):
    global best_overall
    if not text or len(text) < CT_LEN:
        return 0
    text = text[:CT_LEN].upper()
    if not all(c.isalpha() for c in text):
        return 0
    sc = score_cribs(text)
    if sc > best_overall["score"]:
        best_overall = {"score": sc, "method": method_name, "text": text}
    if sc > 2:
        detail = score_cribs_detailed(text)
        all_results.append({"method": method_name, "score": sc,
                           "ene": detail["ene_score"], "bc": detail["bc_score"],
                           "text": text[:50] + "..."})
        print(f"  [ABOVE NOISE] {method_name}: {sc}/24 (ENE={detail['ene_score']}, BC={detail['bc_score']})")
    return sc


print("=" * 60)
print("NOVEL METHOD C: Tableau as Physical Lookup Grid")
print("=" * 60)

total_tested = 0

# Method 1: CT[i] as row, various column selection
print("\n--- Method 1: CT as row index, various column methods ---")

for tab_name, tab, idx_fn in [("std", STD_TAB, ALPH_IDX), ("ka", KA_TAB, KA_IDX)]:
    for col_method_name, col_fn in [
        ("fixed_Y", lambda i: Y_VAL),
        ("fixed_A", lambda i: A_VAL),
        ("fixed_R", lambda i: R_VAL),
        ("cycle_YAR", lambda i: [Y_VAL, A_VAL, R_VAL][i % 3]),
        ("position_mod26", lambda i: i % 26),
        ("position_plus_Y", lambda i: (i + Y_VAL) % 26),
        ("ct_prev", lambda i: idx_fn.get(CT[i - 1], 0) if i > 0 else 0),
        ("reverse_ct", lambda i: idx_fn.get(CT[CT_LEN - 1 - i], 0) if CT_LEN - 1 - i >= 0 else 0),
    ]:
        pt_chars = []
        for i in range(CT_LEN):
            row = idx_fn[CT[i]]
            col = col_fn(i)
            pt_chars.append(tab[row][col])
        pt = "".join(pt_chars)
        method = f"tab_{tab_name}_row_ct_col_{col_method_name}"
        check_candidate(pt, method)
        total_tested += 1

# Method 2: CT[i] as column, various row selection
print("\n--- Method 2: CT as column index, various row methods ---")

for tab_name, tab, idx_fn in [("std", STD_TAB, ALPH_IDX), ("ka", KA_TAB, KA_IDX)]:
    for row_method_name, row_fn in [
        ("fixed_Y", lambda i: Y_VAL),
        ("fixed_A", lambda i: A_VAL),
        ("fixed_R", lambda i: R_VAL),
        ("cycle_YAR", lambda i: [Y_VAL, A_VAL, R_VAL][i % 3]),
        ("position_mod26", lambda i: i % 26),
    ]:
        pt_chars = []
        for i in range(CT_LEN):
            row = row_fn(i)
            col = idx_fn[CT[i]]
            pt_chars.append(tab[row][col])
        pt = "".join(pt_chars)
        method = f"tab_{tab_name}_col_ct_row_{row_method_name}"
        check_candidate(pt, method)
        total_tested += 1

# Method 3: Read tableau in non-standard order to generate a key
print("\n--- Method 3: Tableau read orders as key ---")
for tab_name, tab in [("std", STD_TAB), ("ka", KA_TAB)]:
    # Spiral read of tableau to generate key
    flat_spiral = []
    n = 26
    top, bottom, left, right = 0, n - 1, 0, n - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            flat_spiral.append(tab[top][c])
        top += 1
        for r in range(top, bottom + 1):
            flat_spiral.append(tab[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                flat_spiral.append(tab[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                flat_spiral.append(tab[r][left])
            left += 1

    # Use first 97 chars of spiral as Vigenere key
    key_spiral = flat_spiral[:CT_LEN]
    for variant_name, variant_fn in [
        ("vig", lambda ct, k: (ALPH_IDX[ct] - ALPH_IDX[k]) % 26),
        ("beaufort", lambda ct, k: (ALPH_IDX[k] - ALPH_IDX[ct]) % 26),
        ("additive", lambda ct, k: (ALPH_IDX[ct] + ALPH_IDX[k]) % 26),
    ]:
        pt = "".join(chr(variant_fn(CT[i], key_spiral[i]) + 65) for i in range(CT_LEN))
        method = f"tab_{tab_name}_spiral_key_{variant_name}"
        check_candidate(pt, method)
        total_tested += 1

    # Diagonal read of tableau as key
    diag_key = [tab[i][i] for i in range(26)]
    # Repeat to cover CT
    diag_key_full = (diag_key * ((CT_LEN // 26) + 1))[:CT_LEN]
    for variant_name, variant_fn in [
        ("vig", lambda ct, k: (ALPH_IDX[ct] - ALPH_IDX[k]) % 26),
        ("beaufort", lambda ct, k: (ALPH_IDX[k] - ALPH_IDX[ct]) % 26),
    ]:
        pt = "".join(chr(variant_fn(CT[i], diag_key_full[i]) + 65) for i in range(CT_LEN))
        method = f"tab_{tab_name}_diagonal_key_{variant_name}"
        check_candidate(pt, method)
        total_tested += 1

# Method 4: Abscissa — CT letter's x-coordinate in the tableau
print("\n--- Method 4: Abscissa coordinates ---")
# For each CT char, find its (row, col) in the tableau and extract the col index
for tab_name, tab, idx_fn in [("std", STD_TAB, ALPH_IDX), ("ka", KA_TAB, KA_IDX)]:
    # Build reverse lookup: char -> list of (row, col)
    for fixed_row in range(26):
        pt_chars = []
        for ch in CT:
            col = idx_fn[ch]
            # x-coordinate = column position of ch in row `fixed_row`
            # Find ch in this row
            found = False
            for c in range(26):
                if tab[fixed_row][c] == ch:
                    pt_chars.append(chr(c + 65))
                    found = True
                    break
            if not found:
                pt_chars.append("A")
        pt = "".join(pt_chars)
        method = f"abscissa_{tab_name}_row{fixed_row}"
        check_candidate(pt, method)
        total_tested += 1

# Method 5: Coordinate pairs from YAR as starting offsets
print("\n--- Method 5: YAR coordinate-based lookups ---")
for tab_name, tab in [("std", STD_TAB), ("ka", KA_TAB)]:
    for yr, yc in [(Y_VAL, A_VAL), (A_VAL, R_VAL), (R_VAL, Y_VAL), (Y_VAL, R_VAL)]:
        pt_chars = []
        for i, ch in enumerate(CT):
            r = (yr + i) % 26
            c = (yc + ALPH_IDX[ch]) % 26
            pt_chars.append(tab[r][c])
        pt = "".join(pt_chars)
        method = f"yar_coord_{tab_name}_r{yr}_c{yc}"
        check_candidate(pt, method)
        total_tested += 1

# Method 6: Autokey-like with tableau
print("\n--- Method 6: Autokey with tableau ---")
for tab_name, tab, idx_fn in [("std", STD_TAB, ALPH_IDX), ("ka", KA_TAB, KA_IDX)]:
    for seed in ["Y", "A", "R", "K", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "YAR"]:
        key = list(seed.upper())
        pt_chars = []
        for i in range(CT_LEN):
            if i < len(key):
                k = key[i]
            else:
                k = pt_chars[i - len(seed)]  # autokey from plaintext
            row = idx_fn.get(k, 0)
            col = idx_fn.get(CT[i], 0)
            # Decrypt: find the row where tab[row][col] would give CT[i]
            # Standard Vigenere decrypt
            pt_val = (idx_fn[CT[i]] - idx_fn.get(k, 0)) % 26
            pt_ch = ALPH[pt_val] if tab_name == "std" else KRYPTOS_ALPHABET[pt_val]
            pt_chars.append(pt_ch)
        pt = "".join(pt_chars)
        method = f"autokey_{tab_name}_seed_{seed}"
        check_candidate(pt, method)
        total_tested += 1

print(f"\nTotal tableau configs tested: {total_tested}")
print(f"Best: {best_overall['method']} -> {best_overall['score']}/24")
if best_overall['score'] > 0:
    print(f"  Text: {best_overall['text'][:60]}...")

with open(os.path.join(RESULTS_DIR, "tableau_physical.json"), "w") as f:
    json.dump({
        "method": "tableau_physical_lookup",
        "total_tested": total_tested,
        "best_score": best_overall["score"],
        "best_method": best_overall["method"],
        "best_text": best_overall["text"],
        "above_noise": all_results,
    }, f, indent=2)

print(f"\nResults saved to results/novel_methods/tableau_physical.json")
