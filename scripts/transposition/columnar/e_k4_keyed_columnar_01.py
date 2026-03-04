#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Test keyed columnar transposition on K4.

Tests:
1. KEYED columnar at widths 2-50 with keywords: KRYPTOS, PALIMPSEST, ABSCISSA, BERLINCLOCK
2. Both forward and reverse keyword orders
3. Combined with Vig/Beaufort decrypt (3 keywords × 2 alphabets)
4. Double keyed columnar (two layers)

Usage: PYTHONPATH=src python3 -u scripts/e_k4_keyed_columnar_01.py
"""
from itertools import combinations
from collections import Counter

K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

CRIBS = {
    "EASTNORTHEAST": 13,
    "BERLINCLOCK": 11,
    "SLOWLY": 6,
    "CHAMBER": 7,
    "CANDLE": 6,
    "MIST": 4,
}

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]


def keyword_to_column_order(keyword):
    """Convert keyword to column read order.
    
    E.g., KRYPTOS → [0, 3, 6, 2, 5, 1, 4]
    (K=0, R=3, Y=6, P=2, T=5, O=1, S=4 by alphabetic rank)
    """
    indexed = [(ch, i) for i, ch in enumerate(keyword)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    col_order = [0] * len(keyword)
    for rank, (_, pos) in enumerate(ranked):
        col_order[pos] = rank
    return col_order


def decrypt_keyed_columnar(ct, width, col_order):
    """Decrypt keyed columnar transposition.
    
    col_order[i] = rank (when column i is read).
    rank_to_col[r] = which original column has rank r.
    """
    if len(ct) != width * (len(ct) // width):
        # Incomplete last row
        return None
    
    n = len(ct)
    ncols = width
    nrows = n // ncols
    
    # rank_to_col: which original column has rank r?
    rank_to_col = [0] * ncols
    for col_idx, rank in enumerate(col_order):
        rank_to_col[rank] = col_idx
    
    # All columns have equal length (nrows)
    col_lengths = [nrows] * ncols
    
    # Distribute CT into columns in READ order
    columns = {}
    pos = 0
    for rank in range(ncols):
        col = rank_to_col[rank]
        length = col_lengths[col]
        columns[col] = ct[pos:pos + length]
        pos += length
    
    # Read off row by row
    plaintext = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(columns[col]):
                plaintext.append(columns[col][row])
    
    return ''.join(plaintext)


def vigenere_decrypt(ct, key, alphabet):
    """Decrypt Vigenère with given key and alphabet."""
    key_idx = {ch: i for i, ch in enumerate(alphabet)}
    alphabet_len = len(alphabet)
    pt = []
    key_pos = 0
    for ch in ct:
        if ch not in key_idx:
            pt.append(ch)
            continue
        ct_val = key_idx[ch]
        key_val = key_idx[key[key_pos % len(key)]]
        pt_val = (ct_val - key_val) % alphabet_len
        pt.append(alphabet[pt_val])
        key_pos += 1
    return ''.join(pt)


def beaufort_decrypt(ct, key, alphabet):
    """Decrypt Beaufort with given key and alphabet."""
    key_idx = {ch: i for i, ch in enumerate(alphabet)}
    alphabet_len = len(alphabet)
    pt = []
    key_pos = 0
    for ch in ct:
        if ch not in key_idx:
            pt.append(ch)
            continue
        ct_val = key_idx[ch]
        key_val = key_idx[key[key_pos % len(key)]]
        pt_val = (key_val - ct_val) % alphabet_len
        pt.append(alphabet[pt_val])
        key_pos += 1
    return ''.join(pt)


def count_crib_matches(text, crib_dict):
    """Count how many crib substrings appear anywhere in text."""
    count = 0
    for crib in crib_dict.keys():
        if crib in text:
            count += len(crib)  # Count characters matched
    return count


def score_text(text):
    """Simple score: crib matches + basic English-ness."""
    score = count_crib_matches(text, CRIBS)
    # Bonus for common bigrams (optional)
    return score


print("=" * 80)
print("K4 KEYED COLUMNAR TRANSPOSITION SEARCH")
print("=" * 80)
print(f"K4 CT: {K4_CT}")
print(f"Length: {len(K4_CT)}")
print()

results = []

# Test 1: Single keyed columnar
print("Testing single keyed columnar transposition...")
for width in range(2, min(51, len(K4_CT) // 2 + 1)):
    if len(K4_CT) % width != 0:
        continue  # Skip non-divisible widths
    
    for keyword in KEYWORDS:
        if len(keyword) != width:
            continue  # Keyword must match width
        
        col_order = keyword_to_column_order(keyword)
        
        # Forward and reverse
        for rev_label, col_ord in [("fwd", col_order), ("rev", list(reversed(col_order)))]:
            pt_untrans = decrypt_keyed_columnar(K4_CT, width, col_ord)
            if not pt_untrans:
                continue
            
            # Try Vig/Beaufort with 3 keywords on both alphabets
            for sub_keyword in KEYWORDS:
                for sub_alphabet in [AZ, KA]:
                    # Vigenère
                    pt_vig = vigenere_decrypt(pt_untrans, sub_keyword, sub_alphabet)
                    score_vig = score_text(pt_vig)
                    if score_vig > 0:
                        results.append({
                            "score": score_vig,
                            "method": f"Keyed({width},{keyword},{rev_label})+Vig({sub_keyword},{sub_alphabet[:3]})",
                            "plaintext": pt_vig[:60],
                        })
                    
                    # Beaufort
                    pt_beau = beaufort_decrypt(pt_untrans, sub_keyword, sub_alphabet)
                    score_beau = score_text(pt_beau)
                    if score_beau > 0:
                        results.append({
                            "score": score_beau,
                            "method": f"Keyed({width},{keyword},{rev_label})+Beau({sub_keyword},{sub_alphabet[:3]})",
                            "plaintext": pt_beau[:60],
                        })

print(f"Tested widths 2-50 with {len(KEYWORDS)} keywords each.")
print(f"Found {len(results)} candidate results.")
print()

if results:
    # Sort by score
    results.sort(key=lambda x: x["score"], reverse=True)
    print("=" * 80)
    print("TOP RESULTS (by crib score)")
    print("=" * 80)
    for i, res in enumerate(results[:20]):
        print(f"{i+1:2d}. Score={res['score']:3d}  Method: {res['method']}")
        print(f"     PT: {res['plaintext']}...")
        print()
else:
    print("No crib matches found in single keyed columnar tests.")
    print()

# Test 2: Double keyed columnar
print("=" * 80)
print("Testing DOUBLE keyed columnar transposition...")
print("=" * 80)

double_results = []

# Try all pairs of widths that divide 97 (only 1 and 97, or non-divisors with padding)
# For double-layer, we need both widths to divide evenly
# 97 is prime, so only pairs are (1,97) and (97,1) which are useless
# Let's instead try: width1 divides some rearrangement, then width2 on result

# More practical: try width1 that gives incomplete grid, then width2
for w1 in range(2, 50):
    for w2 in range(2, 50):
        if w1 * w2 > len(K4_CT):
            continue  # Too large
        
        # First untransposition with w1
        for k1 in KEYWORDS:
            if len(k1) != w1:
                continue
            
            col_order_1 = keyword_to_column_order(k1)
            pt_1 = decrypt_keyed_columnar(K4_CT, w1, col_order_1)
            if not pt_1 or len(pt_1) < w2:
                continue
            
            # Second untransposition with w2 on first result
            for k2 in KEYWORDS:
                if len(k2) != w2:
                    continue
                
                col_order_2 = keyword_to_column_order(k2)
                pt_2 = decrypt_keyed_columnar(pt_1, w2, col_order_2)
                if not pt_2:
                    continue
                
                # Score this
                score = count_crib_matches(pt_2, CRIBS)
                if score > 0:
                    double_results.append({
                        "score": score,
                        "method": f"Keyed({w1},{k1})+Keyed({w2},{k2})",
                        "plaintext": pt_2[:60],
                    })

if double_results:
    double_results.sort(key=lambda x: x["score"], reverse=True)
    print(f"Found {len(double_results)} double-keyed results with crib matches.")
    print()
    for i, res in enumerate(double_results[:15]):
        print(f"{i+1:2d}. Score={res['score']:3d}  Method: {res['method']}")
        print(f"     PT: {res['plaintext']}...")
        print()
else:
    print("No crib matches found in double keyed columnar tests.")
    print()

# Final summary
print("=" * 80)
print("SUMMARY")
print("=" * 80)
total_single = len(results)
total_double = len(double_results)
print(f"Single keyed columnar candidates: {total_single}")
print(f"Double keyed columnar candidates: {total_double}")

if total_single + total_double > 0:
    all_results = results + double_results
    all_results.sort(key=lambda x: x["score"], reverse=True)
    print()
    print("BEST OVERALL:")
    best = all_results[0]
    print(f"  Score: {best['score']}")
    print(f"  Method: {best['method']}")
    print(f"  PT: {best['plaintext']}")
else:
    print("No crib matches found in any keyed columnar tests.")

print()
