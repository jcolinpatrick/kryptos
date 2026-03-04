#!/usr/bin/env python3
"""
Cipher: YAR grille
Family: yar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Test the YAR Selective Substitution Theory.

HYPOTHESIS: At the 9 positions in K4 where Y, A, or R appear, the cipher character
is replaced by the tableau character visible through a grille hole. At the other 88
positions, cipher text passes through unchanged (or with transposition only).

K4 Y/A/R positions (0-indexed within K4):
  R: 3, 23, 28, 96
  A: 49, 57, 90, 95
  Y: 64
"""

import sys
sys.path.insert(0, 'src')

from kryptos.kernel.constants import CT, CRIB_WORDS

K4 = CT

# Convert CRIB_WORDS to (start, end, text) triples
CRIBS = [(start, start + len(word) - 1, word) for start, word in CRIB_WORDS]
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "EAST", "NORTH",
    "LIGHT", "ANTIPODES", "MEDUSA", "ENIGMA",
]

# KA Vigenère Tableau (28 rows × 31 cols)
TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",  # Row 0: header
    "AABCDEFGHIJLMNQUVWXZKRYPTOSABCD",  # Row 1: key=A
    "BBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",  # Row 2: key=B
    "CCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",  # Row 3: key=C
    "DDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",  # Row 4: key=D
    "EEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",  # Row 5: key=E
    "FFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",  # Row 6: key=F
    "GGHIJLMNQUVWXZKRYPTOSABCDEFGHIJ",  # Row 7: key=G
    "HHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",  # Row 8: key=H
    "IIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",  # Row 9: key=I
    "JJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",  # Row 10: key=J
    "KKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",  # Row 11: key=K
    "LLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",  # Row 12: key=L
    "MMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",  # Row 13: key=M
    "NNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",  # Row 14: key=N (extra L anomaly)
    "OOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",  # Row 15: key=O
    "PPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",  # Row 16: key=P
    "QQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",  # Row 17: key=Q
    "RRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",  # Row 18: key=R
    "SSABCDEFGHIJLMNQUVWXZKRYPTOSABC",  # Row 19: key=S
    "TTOSABCDEFGHIJLMNQUVWXZKRYPTOSA",  # Row 20: key=T
    "UUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",  # Row 21: key=U
    "VVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",  # Row 22: key=V
    "WWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",  # Row 23: key=W
    "XXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",  # Row 24: key=X
    "YYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",  # Row 25: key=Y
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",  # Row 26: key=Z
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",  # Row 27: footer
]

K4_GRID_START = 771  # K4 starts at position 771 in the full 868-char grid
GRID_WIDTH = 31

print("=" * 80)
print("YAR SELECTIVE SUBSTITUTION THEORY TEST")
print("=" * 80)

# Find Y, A, R positions in K4
yar_positions = {}
for i, ch in enumerate(K4):
    if ch in ('Y', 'A', 'R'):
        yar_positions.setdefault(ch, []).append(i)

print(f"\nK4: {K4}")
print(f"K4 length: {len(K4)}")
print(f"\nY/A/R positions in K4:")
total_yar = 0
for letter in ('Y', 'A', 'R'):
    positions = yar_positions.get(letter, [])
    total_yar += len(positions)
    print(f"  {letter}: {positions} ({len(positions)} occurrences)")
print(f"  Total: {total_yar} positions")

# Map K4 positions to grid coordinates and tableau characters
print(f"\n--- Tableau characters at YAR positions ---")
yar_map = {}
for i, ch in enumerate(K4):
    if ch in ('Y', 'A', 'R'):
        grid_pos = K4_GRID_START + i
        row = grid_pos // GRID_WIDTH
        col = grid_pos % GRID_WIDTH
        tab_char = TABLEAU_ROWS[row][col] if row < len(TABLEAU_ROWS) else '?'
        yar_map[i] = (ch, row, col, tab_char)
        print(f"  K4[{i:2d}] = '{ch}' → grid({row},{col:2d}) → tableau = '{tab_char}'")

# Build modified K4: replace YAR positions with tableau values
modified_k4 = list(K4)
for pos, (orig, row, col, tab_ch) in yar_map.items():
    modified_k4[pos] = tab_ch
modified_k4_str = ''.join(modified_k4)

print(f"\nOriginal K4:  {K4}")
print(f"Modified K4:  {modified_k4_str}")
print(f"Changes:      ", end="")
for i in range(len(K4)):
    if K4[i] != modified_k4_str[i]:
        print(f"^", end="")
    else:
        print(f" ", end="")
print()

# Highlight the differences
diffs = [(i, K4[i], modified_k4_str[i]) for i in range(len(K4)) if K4[i] != modified_k4_str[i]]
print(f"\n{len(diffs)} substitutions:")
for pos, orig, new in diffs:
    print(f"  pos {pos}: {orig} → {new}")

# ── Decrypt modified K4 with various keys ──

def vig_decrypt(ct, key, alphabet):
    """Vigenère decryption."""
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)]
        ci = alphabet.index(c)
        ki = alphabet.index(k)
        pi = (ci - ki) % len(alphabet)
        pt.append(alphabet[pi])
    return ''.join(pt)

def beau_decrypt(ct, key, alphabet):
    """Beaufort decryption (same as Beaufort encryption)."""
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)]
        ci = alphabet.index(c)
        ki = alphabet.index(k)
        pi = (ki - ci) % len(alphabet)
        pt.append(alphabet[pi])
    return ''.join(pt)

def varbeau_decrypt(ct, key, alphabet):
    """Variant Beaufort decryption."""
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)]
        ci = alphabet.index(c)
        ki = alphabet.index(k)
        pi = (ci + ki) % len(alphabet)
        pt.append(alphabet[pi])
    return ''.join(pt)

# Check if any known words appear
COMMON_WORDS = [
    "THE", "AND", "WAS", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "ANY",
    "HER", "HIS", "HAD", "HAS", "ITS", "ONE", "OUR", "OUT", "CAN", "WHO",
    "EAST", "NORTH", "BERLIN", "CLOCK", "SHADOW", "LIGHT", "TOMB",
    "UNDERGRUUND", "UNDERGROUND", "SLOWLY", "DESPERATELY", "WONDERFUL",
    "YES", "THINGS", "INVISIBLE", "BURIED",
    "BETWEEN", "SUBTLE", "SHADING", "ABSENCE",
]

def check_words(text, label=""):
    """Check for common English words in text."""
    found = []
    for w in COMMON_WORDS:
        if w in text:
            pos = text.index(w)
            found.append((w, pos))
    return found

print(f"\n{'='*80}")
print("TESTING MODIFIED K4 WITH KEYWORD DECRYPTIONS")
print(f"{'='*80}")

best_results = []

for ct_label, ct_text in [("MODIFIED", modified_k4_str), ("ORIGINAL", K4)]:
    print(f"\n--- {ct_label} K4 ---")
    for keyword in KEYWORDS:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt), ("VBEAU", varbeau_decrypt)]:
                pt = cipher_fn(ct_text, keyword, alph)
                words = check_words(pt)

                # Check cribs
                crib_hits = 0
                for crib_start, crib_end, crib_text in CRIBS:
                    if pt[crib_start:crib_end+1] == crib_text:
                        crib_hits += 1

                if words or crib_hits > 0:
                    print(f"  {cipher_name}/{keyword}/{alph_name}: {pt}")
                    if words:
                        print(f"    Words found: {words}")
                    if crib_hits:
                        print(f"    CRIB HITS: {crib_hits}")
                    best_results.append((ct_label, cipher_name, keyword, alph_name, pt, words, crib_hits))

if not best_results:
    print(f"\n  No word hits or crib matches found with direct decryption.")

# ── Also try: reverse YAR replacement (tableau→cipher instead of cipher→tableau) ──

print(f"\n{'='*80}")
print("REVERSE THEORY: Replace cipher chars AT YAR POSITIONS with tableau values")
print("(Already done above. Now trying: at non-YAR positions, use tableau values)")
print(f"{'='*80}")

# Theory B: At ALL positions, if the cell is a "hole", show tableau; else show cipher
# Try: holes = YAR positions, solid = everything else
# This is what we already tested above

# Theory C: What if we need to find which OTHER positions are also holes?
# For K4 region only: try all 2^9 subsets of which YAR positions to replace
from itertools import combinations

yar_pos_list = sorted(yar_map.keys())
print(f"\nYAR positions to permute: {yar_pos_list} ({len(yar_pos_list)} positions)")
print(f"Testing all 2^{len(yar_pos_list)} = {2**len(yar_pos_list)} subsets...")

best_subset_results = []
for subset_size in range(1, len(yar_pos_list) + 1):
    for subset in combinations(yar_pos_list, subset_size):
        mod_k4 = list(K4)
        for pos in subset:
            _, _, _, tab_ch = yar_map[pos]
            mod_k4[pos] = tab_ch
        mod_k4_s = ''.join(mod_k4)

        for keyword in KEYWORDS[:5]:  # Top 5 keywords
            for alph_name, alph in [("AZ", AZ)]:
                for cipher_name, cipher_fn in [("VIG", vig_decrypt), ("BEAU", beau_decrypt)]:
                    pt = cipher_fn(mod_k4_s, keyword, alph)
                    words = check_words(pt)

                    # Check cribs
                    crib_hits = 0
                    for crib_start, crib_end, crib_text in CRIBS:
                        if pt[crib_start:crib_end+1] == crib_text:
                            crib_hits += 1

                    if crib_hits > 0:
                        best_subset_results.append((subset, cipher_name, keyword, alph_name, pt, crib_hits))

if best_subset_results:
    print(f"\n  CRIB HITS FOUND:")
    for subset, cn, kw, an, pt, ch in sorted(best_subset_results, key=lambda x: -x[-1]):
        print(f"  Subset {subset}: {cn}/{kw}/{an}: {pt} (cribs: {ch})")
else:
    print(f"\n  No crib hits from subset search.")

# ── Broader test: what if the "replacement letters" come from elsewhere? ──

print(f"\n{'='*80}")
print("BROADER TEST: What if the replacement at YAR positions isn't from tableau?")
print(f"{'='*80}")

# For each YAR position, try ALL 26 possible replacements
# and check if ANY combination gives crib hits with Vig/KRYPTOS
# This is 26^9 ≈ 5.4 trillion — too many.
# But we can check: what MUST the replacement be for cribs to work?

# Under Vig/KRYPTOS/AZ:
# crib 1: positions 21-33 = EASTNORTHEAST
# crib 2: positions 63-73 = BERLINCLOCK
#
# YAR positions in K4: 3, 23, 28, 49, 57, 64, 90, 95, 96
# Which YAR positions are IN crib ranges?
# Crib 1: 21-33 → YAR at 23, 28 (R at both)
# Crib 2: 63-73 → YAR at 64 (Y)

print(f"\nYAR positions within crib ranges:")
for pos in yar_pos_list:
    in_crib = False
    for crib_start, crib_end, crib_text in CRIBS:
        if crib_start <= pos <= crib_end:
            offset = pos - crib_start
            expected_pt = crib_text[offset]
            k4_char = K4[pos]
            print(f"  K4[{pos}] = '{k4_char}' (expected PT = '{expected_pt}'), in crib at offset {offset}")
            in_crib = True
    if not in_crib:
        print(f"  K4[{pos}] = '{K4[pos]}' — NOT in any crib range")

# For the YAR positions in crib ranges, compute what the replacement
# character MUST be for the crib to decrypt correctly under Vig/KRYPTOS/AZ
print(f"\n--- Required CT values at YAR-in-crib positions for Vig/KRYPTOS ---")
keyword = "KRYPTOS"
for pos in yar_pos_list:
    for crib_start, crib_end, crib_text in CRIBS:
        if crib_start <= pos <= crib_end:
            offset = pos - crib_start
            expected_pt = crib_text[offset]
            key_char = keyword[pos % len(keyword)]
            # Vig: CT = (PT + KEY) mod 26 in AZ
            pi = AZ.index(expected_pt)
            ki = AZ.index(key_char)
            required_ci = (pi + ki) % 26
            required_ct = AZ[required_ci]
            actual_ct = K4[pos]
            tab_ch = yar_map[pos][3]
            print(f"  pos {pos}: actual='{actual_ct}', required='{required_ct}', "
                  f"tableau='{tab_ch}', key='{key_char}', "
                  f"match_required={'YES' if tab_ch == required_ct else 'NO'}")

# Same for Beaufort
print(f"\n--- Required CT values at YAR-in-crib positions for BEAU/KRYPTOS ---")
for pos in yar_pos_list:
    for crib_start, crib_end, crib_text in CRIBS:
        if crib_start <= pos <= crib_end:
            offset = pos - crib_start
            expected_pt = crib_text[offset]
            key_char = keyword[pos % len(keyword)]
            # Beau: PT = (KEY - CT) mod 26 → CT = (KEY - PT) mod 26
            pi = AZ.index(expected_pt)
            ki = AZ.index(key_char)
            required_ci = (ki - pi) % 26
            required_ct = AZ[required_ci]
            actual_ct = K4[pos]
            tab_ch = yar_map[pos][3]
            print(f"  pos {pos}: actual='{actual_ct}', required='{required_ct}', "
                  f"tableau='{tab_ch}', key='{key_char}', "
                  f"match_required={'YES' if tab_ch == required_ct else 'NO'}")

print(f"\n{'='*80}")
print("ANALYSIS COMPLETE")
print(f"{'='*80}")
print("""
KEY QUESTION: Do the tableau values at YAR positions match the REQUIRED CT values
for any keyword + cipher combination? If YES for all crib-overlapping YAR positions,
this theory has strong support. If NO, the replacement values come from somewhere else.
""")
