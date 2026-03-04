#!/usr/bin/env python3
"""K4 simple columnar transposition with various reading orders.

Test:
1. Write K4 CT row-major into grid of various widths
2. Read columns in different orders: LTR, RTL, spiral, serpentine, etc.
3. Combine with Vig/Beaufort
"""

K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

CRIB_WORDS = ["EASTNORTHEAST", "BERLINCLOCK", "SLOWLY", "CHAMBER", "CANDLE", "MIST"]

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]


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


def simple_columnar_ltr(ct, width):
    """Write row-major, read columns left-to-right."""
    if len(ct) % width != 0:
        return None
    nrows = len(ct) // width
    pt = []
    for col in range(width):
        for row in range(nrows):
            pt.append(ct[row * width + col])
    return ''.join(pt)


def simple_columnar_rtl(ct, width):
    """Write row-major, read columns right-to-left."""
    if len(ct) % width != 0:
        return None
    nrows = len(ct) // width
    pt = []
    for col in range(width - 1, -1, -1):
        for row in range(nrows):
            pt.append(ct[row * width + col])
    return ''.join(pt)


def simple_columnar_spiral(ct, width):
    """Write row-major, read columns in spiral (out from center)."""
    if len(ct) % width != 0:
        return None
    nrows = len(ct) // width
    
    # Spiral order: center outward
    center = width // 2
    spiral_cols = [center]
    for dist in range(1, width):
        if center + dist < width:
            spiral_cols.append(center + dist)
        if center - dist >= 0:
            spiral_cols.append(center - dist)
    
    pt = []
    for col in spiral_cols[:width]:
        for row in range(nrows):
            pt.append(ct[row * width + col])
    return ''.join(pt)


print("=" * 80)
print("K4 SIMPLE COLUMNAR TRANSPOSITION")
print("=" * 80)
print(f"K4 CT ({len(K4_CT)} chars): {K4_CT}")
print()

results = []

# Test all divisible widths
print("Testing simple columnar transposition...")
for width in range(2, min(50, len(K4_CT))):
    if len(K4_CT) % width != 0:
        continue
    
    for read_order, decrypt_func in [("LTR", simple_columnar_ltr), ("RTL", simple_columnar_rtl), ("spiral", simple_columnar_spiral)]:
        pt_untrans = decrypt_func(K4_CT, width)
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
                        "method": f"SimpleCol({width},{read_order})+Vig({sub_kw})",
                        "pt": pt_vig[:97],
                    })
                
                pt_beau = beaufort_decrypt(pt_untrans, sub_kw, alphabet)
                score, matched = count_crib_matches(pt_beau)
                if score > 0:
                    results.append({
                        "score": score,
                        "matched_cribs": matched,
                        "method": f"SimpleCol({width},{read_order})+Beau({sub_kw})",
                        "pt": pt_beau[:97],
                    })

print(f"Found {len(results)} results with crib matches")
print()

if results:
    results.sort(key=lambda x: x["score"], reverse=True)
    print("=" * 80)
    print("TOP RESULTS")
    print("=" * 80)
    for i, res in enumerate(results[:25]):
        print(f"{i+1:2d}. Score={res['score']:3d}  Cribs: {', '.join(res['matched_cribs'])}")
        print(f"     Method: {res['method']}")
        print(f"     PT: {res['pt']}")
        print()
else:
    print("=" * 80)
    print("No crib matches. Testing ALL widths 2-97 (with padding if needed)...")
    print("=" * 80)
    
    # Pad to test all widths
    all_results_padded = []
    for width in range(2, 98):
        padded_len = ((len(K4_CT) + width - 1) // width) * width
        padding = 'X' * (padded_len - len(K4_CT))
        padded_ct = K4_CT + padding
        
        for read_order, decrypt_func in [("LTR", simple_columnar_ltr), ("RTL", simple_columnar_rtl)]:
            pt_untrans = decrypt_func(padded_ct, width)
            if not pt_untrans:
                continue
            
            for sub_kw in KEYWORDS:
                for alphabet in [AZ, KA]:
                    pt_vig = vigenere_decrypt(pt_untrans, sub_kw, alphabet)
                    score, matched = count_crib_matches(pt_vig)
                    if score > 0:
                        all_results_padded.append({
                            "score": score,
                            "matched_cribs": matched,
                            "width": width,
                            "method": f"Col({width},{read_order})+Vig({sub_kw})",
                            "pt": pt_vig[:97],
                        })
    
    if all_results_padded:
        all_results_padded.sort(key=lambda x: x["score"], reverse=True)
        print(f"Found {len(all_results_padded)} with padding!")
        print()
        for i, res in enumerate(all_results_padded[:20]):
            print(f"{i+1:2d}. Width={res['width']:2d}  Score={res['score']:3d}  {', '.join(res['matched_cribs'])}")
            print(f"     {res['method']}: {res['pt']}")
            print()
    else:
        print("Still no matches. Listing some sample untranspositions...")
        for width in [7, 14, 21, 31]:
            padded_len = ((len(K4_CT) + width - 1) // width) * width
            padding = 'X' * (padded_len - len(K4_CT))
            padded_ct = K4_CT + padding
            pt = simple_columnar_ltr(padded_ct, width)
            if pt:
                print(f"  Col({width},LTR): {pt[:70]}")

