#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Enhanced K4 keyed columnar test with better diagnostics.

Tests:
1. Keyed columnar at all widths 2-97 (including non-divisors)
2. Substitution BEFORE and AFTER transposition
3. All keyword/alphabet combinations
4. Prints top candidates even without full cribs

Usage: PYTHONPATH=src python3 -u scripts/e_k4_keyed_columnar_02.py
"""
import sys

K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

CRIB_WORDS = ["EASTNORTHEAST", "BERLINCLOCK", "SLOWLY", "CHAMBER", "CANDLE", "MIST", "DESPARATLY"]

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]


def keyword_to_column_order(keyword):
    """Convert keyword to column read order."""
    indexed = [(ch, i) for i, ch in enumerate(keyword)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    col_order = [0] * len(keyword)
    for rank, (_, pos) in enumerate(ranked):
        col_order[pos] = rank
    return col_order


def decrypt_keyed_columnar_fixed_rows(ct, width):
    """Decrypt keyed columnar with fixed row count.
    
    Given CT and width, determine how many complete rows fit,
    then decrypt using column-major → row-major.
    Returns PT if width divides len(ct), else None.
    """
    if len(ct) % width != 0:
        return None
    
    n = len(ct)
    ncols = width
    nrows = n // ncols
    
    # Assume CT is written column-major (top-to-bottom, left-to-right)
    # and we want to read row-major (left-to-right, top-to-bottom)
    grid = []
    pos = 0
    for c in range(ncols):
        col = []
        for r in range(nrows):
            col.append(ct[pos])
            pos += 1
        grid.append(col)
    
    # Read row by row
    pt = []
    for r in range(nrows):
        for c in range(ncols):
            pt.append(grid[c][r])
    
    return ''.join(pt)


def decrypt_keyed_columnar_with_order(ct, width, col_order):
    """Decrypt keyed columnar with explicit column read order.
    
    col_order[col] = rank (when that column is read).
    rank_to_col[rank] = which original column position.
    """
    if len(ct) % width != 0:
        return None
    
    n = len(ct)
    nrows = n // width
    
    # rank_to_col[rank] = original column index
    rank_to_col = [0] * width
    for col_idx, rank in enumerate(col_order):
        rank_to_col[rank] = col_idx
    
    # Distribute CT into columns in READ order
    columns = {}
    pos = 0
    for rank in range(width):
        col = rank_to_col[rank]
        columns[col] = ct[pos:pos + nrows]
        pos += nrows
    
    # Read row by row
    pt = []
    for row in range(nrows):
        for col in range(width):
            if row < len(columns[col]):
                pt.append(columns[col][row])
    
    return ''.join(pt)


def vigenere_decrypt(ct, key, alphabet):
    """Decrypt Vigenère."""
    key_idx = {ch: i for i, ch in enumerate(alphabet)}
    pt = []
    key_pos = 0
    for ch in ct:
        if ch not in key_idx:
            pt.append(ch)
            continue
        ct_val = key_idx[ch]
        key_val = key_idx[key[key_pos % len(key)]]
        pt_val = (ct_val - key_val) % len(alphabet)
        pt.append(alphabet[pt_val])
        key_pos += 1
    return ''.join(pt)


def beaufort_decrypt(ct, key, alphabet):
    """Decrypt Beaufort."""
    key_idx = {ch: i for i, ch in enumerate(alphabet)}
    pt = []
    key_pos = 0
    for ch in ct:
        if ch not in key_idx:
            pt.append(ch)
            continue
        ct_val = key_idx[ch]
        key_val = key_idx[key[key_pos % len(key)]]
        pt_val = (key_val - ct_val) % len(alphabet)
        pt.append(alphabet[pt_val])
        key_pos += 1
    return ''.join(pt)


def count_crib_matches(text):
    """Count total characters matched by any crib."""
    count = 0
    for crib in CRIB_WORDS:
        if crib in text:
            count += len(crib)
    return count


print("=" * 80)
print("K4 KEYED COLUMNAR TRANSPOSITION (Enhanced)")
print("=" * 80)
print(f"K4 CT ({len(K4_CT)} chars): {K4_CT[:30]}...{K4_CT[-20:]}")
print(f"Crib words: {', '.join(CRIB_WORDS)}")
print()

results = []

# Test 1: Transposition THEN substitution
print("Testing: Transposition → Substitution...")
test_count = 0
for width in range(2, len(K4_CT) + 1):
    if len(K4_CT) % width != 0:
        continue  # Only exact divisions
    
    for keyword in KEYWORDS:
        if len(keyword) != width:
            continue
        
        col_order = keyword_to_column_order(keyword)
        pt_untrans = decrypt_keyed_columnar_with_order(K4_CT, width, col_order)
        if not pt_untrans:
            continue
        
        test_count += 1
        
        # Try substitution
        for sub_kw in KEYWORDS:
            for alphabet in [AZ, KA]:
                pt_vig = vigenere_decrypt(pt_untrans, sub_kw, alphabet)
                score = count_crib_matches(pt_vig)
                if score > 0:
                    results.append({
                        "score": score,
                        "method": f"KeyedCol({width},{keyword})+Vig({sub_kw},{alphabet[:3]})",
                        "pt": pt_vig,
                    })
                
                pt_beau = beaufort_decrypt(pt_untrans, sub_kw, alphabet)
                score = count_crib_matches(pt_beau)
                if score > 0:
                    results.append({
                        "score": score,
                        "method": f"KeyedCol({width},{keyword})+Beau({sub_kw},{alphabet[:3]})",
                        "pt": pt_beau,
                    })

print(f"  Tested {test_count} keyed columnar configurations")
print(f"  Found {len(results)} with crib matches")
print()

# Test 2: Substitution THEN transposition
print("Testing: Substitution → Transposition...")
sub_results = []
sub_test_count = 0

for sub_kw in KEYWORDS:
    for alphabet in [AZ, KA]:
        # Apply substitution to K4 CT
        pt_vig = vigenere_decrypt(K4_CT, sub_kw, alphabet)
        pt_beau = beaufort_decrypt(K4_CT, sub_kw, alphabet)
        
        for pt_sub in [pt_vig, pt_beau]:
            sub_type = "Vig" if pt_sub == pt_vig else "Beau"
            
            # Try transposition on substituted text
            for width in range(2, len(pt_sub) + 1):
                if len(pt_sub) % width != 0:
                    continue
                
                for keyword in KEYWORDS:
                    if len(keyword) != width:
                        continue
                    
                    col_order = keyword_to_column_order(keyword)
                    pt_untrans = decrypt_keyed_columnar_with_order(pt_sub, width, col_order)
                    if not pt_untrans:
                        continue
                    
                    sub_test_count += 1
                    score = count_crib_matches(pt_untrans)
                    if score > 0:
                        sub_results.append({
                            "score": score,
                            "method": f"{sub_type}({sub_kw},{alphabet[:3]})→KeyedCol({width},{keyword})",
                            "pt": pt_untrans,
                        })

print(f"  Tested {sub_test_count} substitution→transposition combinations")
print(f"  Found {len(sub_results)} with crib matches")
print()

# Combine results
all_results = results + sub_results
if all_results:
    all_results.sort(key=lambda x: x["score"], reverse=True)
    print("=" * 80)
    print("TOP RESULTS (by crib score)")
    print("=" * 80)
    for i, res in enumerate(all_results[:25]):
        print(f"{i+1:2d}. Score={res['score']:3d}  {res['method']}")
        print(f"     {res['pt'][:70]}")
        print()
else:
    print("=" * 80)
    print("No crib matches found in any keyed columnar tests.")
    print("=" * 80)
    print()
    print("Diagnostic: Testing if ANY keyed columnar untransposition is feasible...")
    
    # Quick check: just print first few untranspositions
    sample_count = 0
    for width in [7, 14, 21, 28]:
        if len(K4_CT) % width != 0:
            continue
        for keyword in KEYWORDS:
            if len(keyword) != width:
                continue
            col_order = keyword_to_column_order(keyword)
            pt = decrypt_keyed_columnar_with_order(K4_CT, width, col_order)
            if pt:
                print(f"  KeyedCol({width},{keyword}): {pt[:60]}...")
                sample_count += 1
                if sample_count >= 3:
                    break
        if sample_count >= 3:
            break

print()
print("=" * 80)
print("Script complete")
print("=" * 80)
