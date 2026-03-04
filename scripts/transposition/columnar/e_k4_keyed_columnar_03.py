#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""K4 keyed columnar with padding support.

Since 97 is prime, test by padding K4 to make it divisible by common widths.
"""

K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

CRIB_WORDS = ["EASTNORTHEAST", "BERLINCLOCK", "SLOWLY", "CHAMBER", "CANDLE", "MIST"]

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]


def keyword_to_column_order(keyword):
    """Convert keyword to column read order."""
    indexed = [(ch, i) for i, ch in enumerate(keyword)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    col_order = [0] * len(keyword)
    for rank, (_, pos) in enumerate(ranked):
        col_order[pos] = rank
    return col_order


def decrypt_keyed_columnar_with_order(ct, width, col_order):
    """Decrypt keyed columnar with explicit column read order."""
    if len(ct) % width != 0:
        return None
    
    n = len(ct)
    nrows = n // width
    
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
    matched_cribs = []
    for crib in CRIB_WORDS:
        if crib in text:
            count += len(crib)
            matched_cribs.append(crib)
    return count, matched_cribs


print("=" * 80)
print("K4 KEYED COLUMNAR (with padding)")
print("=" * 80)
print(f"K4 CT ({len(K4_CT)} chars): {K4_CT}")
print()

results = []

# Try padding to various widths
widths_to_test = [7, 14, 21, 28, 35, 42, 49, 56, 63, 70, 77, 84, 91]

print("Testing keyed columnar transposition with padding...")
for target_width in widths_to_test:
    # Pad K4 to nearest multiple of target_width
    padded_len = ((len(K4_CT) + target_width - 1) // target_width) * target_width
    padding_len = padded_len - len(K4_CT)
    
    # Try different padding strategies
    for pad_char in ['X', 'Z', 'A', '@']:
        padded_ct = K4_CT + (pad_char * padding_len)
        
        for keyword in KEYWORDS:
            if len(keyword) != target_width:
                continue
            
            col_order = keyword_to_column_order(keyword)
            pt_untrans = decrypt_keyed_columnar_with_order(padded_ct, target_width, col_order)
            if not pt_untrans:
                continue
            
            # Try substitution
            for sub_kw in KEYWORDS:
                for alphabet in [AZ, KA]:
                    pt_vig = vigenere_decrypt(pt_untrans, sub_kw, alphabet)
                    score, matched = count_crib_matches(pt_vig)
                    if score > 0:
                        results.append({
                            "score": score,
                            "matched_cribs": matched,
                            "method": f"KeyedCol({target_width},{keyword},pad={pad_char})+Vig({sub_kw},{alphabet[:3]})",
                            "pt": pt_vig[:97],  # Show only original K4 length
                            "full_pt": pt_vig,
                        })
                    
                    pt_beau = beaufort_decrypt(pt_untrans, sub_kw, alphabet)
                    score, matched = count_crib_matches(pt_beau)
                    if score > 0:
                        results.append({
                            "score": score,
                            "matched_cribs": matched,
                            "method": f"KeyedCol({target_width},{keyword},pad={pad_char})+Beau({sub_kw},{alphabet[:3]})",
                            "pt": pt_beau[:97],
                            "full_pt": pt_beau,
                        })

print(f"Tested {len(widths_to_test)} widths with 4 padding chars each")
print(f"Found {len(results)} results with crib matches")
print()

if results:
    results.sort(key=lambda x: x["score"], reverse=True)
    print("=" * 80)
    print("TOP RESULTS")
    print("=" * 80)
    for i, res in enumerate(results[:30]):
        print(f"{i+1:2d}. Score={res['score']:3d}  Cribs: {', '.join(res['matched_cribs'])}")
        print(f"     Method: {res['method']}")
        print(f"     PT: {res['pt'][:70]}")
        print()
else:
    print("No crib matches found.")
    print()
    print("Diagnostic: Sample transpositions without substitution...")
    for target_width in [7, 14, 21]:
        padded_len = ((len(K4_CT) + target_width - 1) // target_width) * target_width
        padding_len = padded_len - len(K4_CT)
        padded_ct = K4_CT + ('X' * padding_len)
        
        for keyword in KEYWORDS:
            if len(keyword) != target_width:
                continue
            col_order = keyword_to_column_order(keyword)
            pt = decrypt_keyed_columnar_with_order(padded_ct, target_width, col_order)
            if pt:
                print(f"  {target_width},{keyword}: {pt[:70]}")

