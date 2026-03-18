#!/usr/bin/env python3
"""
Experiment: Leetspeak Visual Resemblance — Null Palette Numbers as Cipher Key
===========================================================================

Cipher:       Multiple (Gronsfeld, Beaufort digit-key, running-key digit)
Family:       campaigns
Status:       active
Keyspace:     ~50K configs
Last run:     2026-03-16
Best score:   TBD

HYPOTHESIS: The 7-letter null palette {B,G,I,K,O,W,Z} encodes numbers via
visual resemblance (leetspeak). On copper cut-through letters with backlighting:
  B=8, G=6 or 9, I=1, K=|< (ambiguous), O=0, W=VV (ambiguous), Z=2 or 5

The 17 consensus null chars may encode a digit sequence that serves as cipher
key for the inner substitution layer. K1 PT: "Between subtle shading and the
absence of light lies the nuance of illusion" -- dual letter/number reading.

TESTS:
1. Extract digit sequences from null chars (multiple G/K/W interpretations)
2. Try as Gronsfeld key on CT73 (digit-based Vigenere, period = digit count)
3. Try as Beaufort key on CT73
4. Try as running key positions into alphabet
5. Check numerical coincidences (sums vs K2 numbers, etc.)
6. Try on raw CT97 with all positions
7. Check if digit sequence encodes coordinates or dates
"""

import sys
import os
import json
import itertools
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD
)

# ── Constants ─────────────────────────────────────────────────────────────

CONSENSUS_NULLS = sorted([0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85])
assert len(CONSENSUS_NULLS) == 17

PALETTE = set('BGIKOWZ')
CONSENSUS_CHARS = [CT[p] for p in CONSENSUS_NULLS]
CONSENSUS_STR = ''.join(CONSENSUS_CHARS)
# Verify: OBKOGBOWWKWIWGZIG
print(f"Consensus null chars: {CONSENSUS_STR}")
print(f"Palette: {sorted(PALETTE)}")

# Known 15/24 null mask (24 positions)
USER_MASK = sorted([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
MASK_SET = frozenset(USER_MASK)

# Null-extracted 73-char text
CT73 = ''.join(CT[i] for i in range(CT_LEN) if i not in MASK_SET)
assert len(CT73) == 73

# Map CT97 position -> CT73 position (for crib scoring)
def pos97_to_73(pos97):
    return pos97 - sum(1 for m in USER_MASK if m < pos97)

# ── Leetspeak Mapping ─────────────────────────────────────────────────────

# Standard mappings (clear visual resemblance)
LEET_CLEAR = {'B': 8, 'G': 6, 'I': 1, 'O': 0, 'Z': 2}

# Alternate G mapping
LEET_G9 = {'B': 8, 'G': 9, 'I': 1, 'O': 0, 'Z': 2}

# Z=5 variant (zigzag ambiguity)
LEET_Z5 = {'B': 8, 'G': 6, 'I': 1, 'O': 0, 'Z': 5}

# G=9, Z=5 variant
LEET_G9Z5 = {'B': 8, 'G': 9, 'I': 1, 'O': 0, 'Z': 5}

# Full A=0 leetspeak for all 26 letters where applicable
LEET_FULL = {
    'A': 4, 'B': 8, 'E': 3, 'G': 6, 'I': 1, 'L': 1,
    'O': 0, 'S': 5, 'T': 7, 'Z': 2
}

# K and W: try multiple interpretations
K_VALUES = [None, 11, 10, 7]   # None=skip, 11=|<, 10=KA index, 7=K7
W_VALUES = [None, 23, 22, 5]   # None=skip, 23=AZ index, 22=KA index, 5=VV

# ── Scoring ──────────────────────────────────────────────────────────────

def score_crib(plaintext, ct_text=CT, positions=None):
    """Score plaintext against known cribs. Returns (total, ene, bcl, details)."""
    if positions is None:
        # Standard CT97 positions
        crib_positions = CRIB_DICT
    else:
        crib_positions = positions

    total = 0
    ene = 0
    bcl = 0
    details = []
    for pos, expected_char in crib_positions.items():
        if pos < len(plaintext):
            actual = plaintext[pos]
            if actual == expected_char:
                total += 1
                if 21 <= pos <= 33:
                    ene += 1
                elif 63 <= pos <= 73:
                    bcl += 1
                details.append(f"  pos {pos}: {actual} == {expected_char} MATCH")
            else:
                details.append(f"  pos {pos}: {actual} != {expected_char}")
    return total, ene, bcl, details


def decrypt_beaufort(ct, key_nums, alphabet=ALPH):
    """Beaufort: PT[i] = (key[i%len(key)] - CT_num[i]) mod 26"""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    klen = len(key_nums)
    for i, c in enumerate(ct):
        ct_num = alph_idx.get(c, 0)
        k = key_nums[i % klen]
        pt_num = (k - ct_num) % 26
        pt.append(alphabet[pt_num])
    return ''.join(pt)


def decrypt_vigenere(ct, key_nums, alphabet=ALPH):
    """Vigenere: PT[i] = (CT_num[i] - key[i%len(key)]) mod 26"""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    klen = len(key_nums)
    for i, c in enumerate(ct):
        ct_num = alph_idx.get(c, 0)
        k = key_nums[i % klen]
        pt_num = (ct_num - k) % 26
        pt.append(alphabet[pt_num])
    return ''.join(pt)


def decrypt_gronsfeld(ct, digits, alphabet=ALPH):
    """Gronsfeld = Vigenere with digit key (0-9 only)"""
    return decrypt_vigenere(ct, digits, alphabet)


def col7_undo(text):
    """Undo columnar transposition width 7."""
    if len(text) == 0:
        return text
    w = 7
    n = len(text)
    nrows = (n + w - 1) // w
    full_cols = n % w if n % w != 0 else w
    grid = []
    idx = 0
    for col in range(w):
        col_len = nrows if col < full_cols else nrows - 1
        grid.append(text[idx:idx+col_len])
        idx += col_len
    result = []
    for row in range(nrows):
        for col in range(w):
            if row < len(grid[col]):
                result.append(grid[col][row])
    return ''.join(result)


results = {
    'experiment': 'leetspeak_palette_v1',
    'timestamp': datetime.now().isoformat(),
    'hypothesis': 'Null palette letters encode numbers via visual resemblance (leetspeak)',
    'consensus_nulls': CONSENSUS_NULLS,
    'consensus_chars': CONSENSUS_STR,
    'tests': [],
    'best_score': 0,
    'best_config': None,
}

# ══════════════════════════════════════════════════════════════════════════
# TEST 1: Extract digit sequences from consensus null chars
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 1: Digit extraction from consensus null characters")
print("="*70)

leet_maps = {
    'G6_Z2': LEET_CLEAR,
    'G9_Z2': LEET_G9,
    'G6_Z5': LEET_Z5,
    'G9_Z5': LEET_G9Z5,
}

digit_sequences = {}

for map_name, leet_map in leet_maps.items():
    digits = []
    digit_only = []
    for ch in CONSENSUS_STR:
        if ch in leet_map:
            digits.append(str(leet_map[ch]))
            digit_only.append(leet_map[ch])
        elif ch == 'K':
            digits.append('K')
        elif ch == 'W':
            digits.append('W')
        else:
            digits.append('?')

    digit_str = ''.join(digits)
    digit_sum = sum(digit_only)

    print(f"\n{map_name}: {digit_str}")
    print(f"  Digit-only values: {digit_only}")
    print(f"  Count: {len(digit_only)} digits (of 17 chars)")
    print(f"  Sum: {digit_sum}")
    print(f"  Distinct digits: {sorted(set(digit_only))}")

    digit_sequences[map_name] = {
        'full': digit_str,
        'digits_only': digit_only,
        'sum': digit_sum,
        'distinct': sorted(set(digit_only)),
    }

# Key coincidence checks
print("\n--- Numerical Coincidences ---")
for map_name, info in digit_sequences.items():
    s = info['sum']
    d = info['distinct']
    print(f"\n{map_name}:")
    print(f"  Sum = {s}")
    print(f"  Sum mod 26 = {s % 26} -> {ALPH[s % 26]}")
    print(f"  Sum mod 97 = {s % 97}")
    print(f"  Distinct digit count = {len(d)}, sum of distinct = {sum(d)}")
    if s == 38:
        print(f"  *** SUM = 38 = K2 latitude degrees! ***")
    if sum(d) == 17:
        print(f"  *** DISTINCT SUM = 17 = consensus null count! ***")
    if len(d) == 5:
        print(f"  *** 5 distinct digits (Polybius dimension)! ***")

results['tests'].append({
    'name': 'digit_extraction',
    'sequences': digit_sequences,
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 2: Gronsfeld cipher with digit sequences on CT73
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 2: Gronsfeld cipher (digit key on CT73)")
print("="*70)

test2_results = []
best_t2 = (0, '', '')

for map_name, info in digit_sequences.items():
    digits = info['digits_only']
    if not digits:
        continue

    for alph_name, alphabet in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        for trans in ['none', 'col7']:
            text = CT73
            if trans == 'col7':
                text = col7_undo(CT73)

            pt = decrypt_gronsfeld(text, digits, alphabet)
            score, ene, bcl, details = score_crib(pt, positions={
                pos97_to_73(p): ch for p, ch in CRIB_DICT.items()
                if p not in MASK_SET
            })

            config = f"Gronsfeld:{map_name}:{alph_name}:{trans}"
            if score > 0:
                print(f"  {config}: {score}/24 (ene={ene}, bcl={bcl})")
            if score > best_t2[0]:
                best_t2 = (score, pt[:50], config)

            test2_results.append({
                'config': config,
                'score': score,
                'ene': ene,
                'bcl': bcl,
                'pt_prefix': pt[:30],
            })

# Also try with K and W as various values
for map_name, leet_map in leet_maps.items():
    for k_val in K_VALUES:
        for w_val in W_VALUES:
            full_digits = []
            for ch in CONSENSUS_STR:
                if ch in leet_map:
                    full_digits.append(leet_map[ch])
                elif ch == 'K' and k_val is not None:
                    full_digits.append(k_val)
                elif ch == 'W' and w_val is not None:
                    full_digits.append(w_val)
                else:
                    continue  # skip this char

            if len(full_digits) < 5:
                continue

            for alph_name, alphabet in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
                for trans in ['none', 'col7']:
                    text = CT73
                    if trans == 'col7':
                        text = col7_undo(CT73)

                    # Vigenere with these digits mod 26
                    key_mod26 = [d % 26 for d in full_digits]
                    pt_v = decrypt_vigenere(text, key_mod26, alphabet)
                    score_v, ene_v, bcl_v, _ = score_crib(pt_v, positions={
                        pos97_to_73(p): ch for p, ch in CRIB_DICT.items()
                        if p not in MASK_SET
                    })

                    pt_b = decrypt_beaufort(text, key_mod26, alphabet)
                    score_b, ene_b, bcl_b, _ = score_crib(pt_b, positions={
                        pos97_to_73(p): ch for p, ch in CRIB_DICT.items()
                        if p not in MASK_SET
                    })

                    for cipher, sc, en, bc, pt in [
                        ('vig', score_v, ene_v, bcl_v, pt_v),
                        ('beau', score_b, ene_b, bcl_b, pt_b)
                    ]:
                        config = f"{cipher}:{map_name}:K={k_val}:W={w_val}:{alph_name}:{trans}"
                        if sc > 2:
                            print(f"  {config}: {sc}/24 (ene={en}, bcl={bc})")
                        if sc > best_t2[0]:
                            best_t2 = (sc, pt[:50], config)
                        test2_results.append({
                            'config': config,
                            'score': sc,
                            'ene': en,
                            'bcl': bc,
                        })

print(f"\nBest T2: {best_t2[0]}/24 = {best_t2[2]}")
print(f"  PT prefix: {best_t2[1]}")
results['tests'].append({
    'name': 'gronsfeld_ct73',
    'configs_tested': len(test2_results),
    'best_score': best_t2[0],
    'best_config': best_t2[2],
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 3: Digit sequence as cipher key on RAW CT97
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 3: Digit key on raw CT97 (direct)")
print("="*70)

test3_results = []
best_t3 = (0, '', '')

for map_name, leet_map in leet_maps.items():
    for k_val in K_VALUES:
        for w_val in W_VALUES:
            full_digits = []
            for ch in CONSENSUS_STR:
                if ch in leet_map:
                    full_digits.append(leet_map[ch])
                elif ch == 'K' and k_val is not None:
                    full_digits.append(k_val)
                elif ch == 'W' and w_val is not None:
                    full_digits.append(w_val)
                else:
                    continue

            if len(full_digits) < 5:
                continue

            key_mod26 = [d % 26 for d in full_digits]

            for alph_name, alphabet in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
                for cipher_name, decrypt_fn in [('vig', decrypt_vigenere), ('beau', decrypt_beaufort)]:
                    pt = decrypt_fn(CT, key_mod26, alphabet)
                    score, ene, bcl, _ = score_crib(pt)

                    config = f"raw97:{cipher_name}:{map_name}:K={k_val}:W={w_val}:{alph_name}"
                    if score > 2:
                        print(f"  {config}: {score}/24 (ene={ene}, bcl={bcl})")
                    if score > best_t3[0]:
                        best_t3 = (score, pt[:50], config)
                    test3_results.append({
                        'config': config,
                        'score': score,
                    })

print(f"\nBest T3: {best_t3[0]}/24 = {best_t3[2]}")
results['tests'].append({
    'name': 'digit_key_raw97',
    'configs_tested': len(test3_results),
    'best_score': best_t3[0],
    'best_config': best_t3[2],
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 4: Position-specific digit decryption
#   At each null position, use the leetspeak digit to shift the NEXT char
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 4: Positional digit application (null digits shift neighbors)")
print("="*70)

test4_results = []
best_t4 = (0, '', '')

for map_name, leet_map in leet_maps.items():
    for k_val in [None, 11, 10]:
        for w_val in [None, 23, 22]:
            # Build position->digit map
            pos_digit = {}
            for p in CONSENSUS_NULLS:
                ch = CT[p]
                if ch in leet_map:
                    pos_digit[p] = leet_map[ch]
                elif ch == 'K' and k_val is not None:
                    pos_digit[p] = k_val
                elif ch == 'W' and w_val is not None:
                    pos_digit[p] = w_val

            # Method A: null digit shifts the NEXT non-null char
            for alph_name, alphabet in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
                alph_idx = {c: i for i, c in enumerate(alphabet)}
                pt_list = list(CT)  # start with CT

                for null_pos in CONSENSUS_NULLS:
                    if null_pos not in pos_digit:
                        continue
                    digit = pos_digit[null_pos]
                    # Find next non-null position
                    next_pos = null_pos + 1
                    while next_pos < CT_LEN and next_pos in frozenset(CONSENSUS_NULLS):
                        next_pos += 1
                    if next_pos < CT_LEN:
                        ct_num = alph_idx[CT[next_pos]]
                        # Try both shift directions
                        pt_list[next_pos] = alphabet[(ct_num - digit) % 26]

                pt = ''.join(pt_list)
                score, ene, bcl, _ = score_crib(pt)
                config = f"shift_next:{map_name}:K={k_val}:W={w_val}:{alph_name}"
                if score > 2:
                    print(f"  {config}: {score}/24")
                if score > best_t4[0]:
                    best_t4 = (score, pt[:50], config)
                test4_results.append({'config': config, 'score': score})

                # Try adding instead of subtracting
                pt_list2 = list(CT)
                for null_pos in CONSENSUS_NULLS:
                    if null_pos not in pos_digit:
                        continue
                    digit = pos_digit[null_pos]
                    next_pos = null_pos + 1
                    while next_pos < CT_LEN and next_pos in frozenset(CONSENSUS_NULLS):
                        next_pos += 1
                    if next_pos < CT_LEN:
                        ct_num = alph_idx[CT[next_pos]]
                        pt_list2[next_pos] = alphabet[(ct_num + digit) % 26]

                pt2 = ''.join(pt_list2)
                score2, ene2, bcl2, _ = score_crib(pt2)
                config2 = f"shift_next_add:{map_name}:K={k_val}:W={w_val}:{alph_name}"
                if score2 > 2:
                    print(f"  {config2}: {score2}/24")
                if score2 > best_t4[0]:
                    best_t4 = (score2, pt2[:50], config2)
                test4_results.append({'config': config2, 'score': score2})

print(f"\nBest T4: {best_t4[0]}/24 = {best_t4[2]}")
results['tests'].append({
    'name': 'positional_digit_shift',
    'configs_tested': len(test4_results),
    'best_score': best_t4[0],
    'best_config': best_t4[2],
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 5: Full CT97 leetspeak conversion - letter/number dual reading
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 5: Full CT97 dual letter/number reading")
print("="*70)

# Which CT97 chars have clear leetspeak number equivalents?
full_leet = {
    'A': 4, 'B': 8, 'E': 3, 'G': 6, 'I': 1, 'L': 1, 'O': 0, 'S': 5, 'T': 7, 'Z': 2
}
for i, ch in enumerate(CT):
    has_leet = ch in full_leet
    is_null = i in frozenset(CONSENSUS_NULLS)
    is_crib = i in CRIB_POSITIONS
    tag = ""
    if is_null: tag += " [NULL]"
    if is_crib: tag += " [CRIB]"
    if has_leet: tag += f" -> {full_leet[ch]}"

# Count: how many null positions have leet mappings vs non-null?
null_leet_count = sum(1 for p in CONSENSUS_NULLS if CT[p] in full_leet)
nonnull_positions = [i for i in range(CT_LEN) if i not in frozenset(CONSENSUS_NULLS)]
nonnull_leet_count = sum(1 for p in nonnull_positions if CT[p] in full_leet)

print(f"\nNull positions with leet mapping: {null_leet_count}/{len(CONSENSUS_NULLS)} = {null_leet_count/len(CONSENSUS_NULLS)*100:.1f}%")
print(f"Non-null positions with leet mapping: {nonnull_leet_count}/{len(nonnull_positions)} = {nonnull_leet_count/len(nonnull_positions)*100:.1f}%")
print(f"Expected by chance (10 leet-able letters / 26): {10/26*100:.1f}%")

# Chi-square-like test
# Under null model, each position has P(leet) = fraction of leet-able letters in CT
ct_leet_chars = sum(1 for c in CT if c in full_leet)
p_leet = ct_leet_chars / CT_LEN
print(f"\nCT97 leet-able chars: {ct_leet_chars}/{CT_LEN} = {p_leet*100:.1f}%")
print(f"Expected nulls with leet: {p_leet * 17:.1f}")
print(f"Observed nulls with leet: {null_leet_count}")

# What ARE the non-palette-but-leet-eligible letters?
non_palette_leet = {c for c in full_leet if c not in PALETTE}
print(f"\nNon-palette letters with leet mappings: {sorted(non_palette_leet)}")
# A=4, E=3, L=1, S=5, T=7 -- these are in the ciphertext frequently

# Palette vs full-leet overlap
palette_leet = {c for c in PALETTE if c in full_leet}
print(f"Palette letters with leet mappings: {sorted(palette_leet)} = {len(palette_leet)}/{len(PALETTE)}")
palette_no_leet = PALETTE - palette_leet
print(f"Palette letters WITHOUT leet: {sorted(palette_no_leet)} = K, W")

results['tests'].append({
    'name': 'full_ct97_leet_analysis',
    'null_leet_frac': null_leet_count / len(CONSENSUS_NULLS),
    'nonnull_leet_frac': nonnull_leet_count / len(nonnull_positions),
    'palette_leet_count': len(palette_leet),
    'palette_no_leet': sorted(palette_no_leet),
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 6: K2 coordinate comparison
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 6: K2 coordinate number comparison")
print("="*70)

# K2 coordinates: 38 57 6.5 N, 77 8 44 W
k2_numbers = [38, 57, 6.5, 77, 8, 44]
k2_digits = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]

for map_name, info in digit_sequences.items():
    digits = info['digits_only']
    s = info['sum']
    print(f"\n{map_name}: digits = {digits}, sum = {s}")

    # Check if sum matches any K2 number
    for k2n in k2_numbers:
        if s == k2n:
            print(f"  *** SUM = {s} matches K2 number {k2n}! ***")
        if s == int(k2n):
            print(f"  *** SUM = {s} matches K2 integer {int(k2n)}! ***")

    # Check digit subsequences
    k2_str = ''.join(str(d) for d in k2_digits)
    digit_str = ''.join(str(d) for d in digits)

    # Find any overlapping subsequences >= 3 digits
    for length in range(min(len(digit_str), len(k2_str)), 2, -1):
        for start_d in range(len(digit_str) - length + 1):
            sub = digit_str[start_d:start_d+length]
            pos = k2_str.find(sub)
            if pos >= 0:
                print(f"  Match: '{sub}' (len {length}) found in K2 digits at pos {pos}")
                break
        else:
            continue
        break

    # Sum to 38 (latitude degrees)?
    if s == 38:
        print(f"  *** CRITICAL: Digit sum = 38 = K2 latitude degrees ***")

    # Digits as coordinate: first half / second half
    n_digits = len(digits)
    if n_digits >= 4:
        half = n_digits // 2
        first_half = digits[:half]
        second_half = digits[half:]
        print(f"  Split: {first_half} | {second_half}")
        print(f"  As integers: {int(''.join(str(d) for d in first_half))} | {int(''.join(str(d) for d in second_half))}")

results['tests'].append({
    'name': 'k2_coordinate_comparison',
    'k2_numbers': k2_numbers,
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 7: Digit sequence as autokey primer
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 7: Digit sequence as autokey primer")
print("="*70)

test7_results = []
best_t7 = (0, '', '')

for map_name, info in digit_sequences.items():
    digits = info['digits_only']
    primer = [d % 26 for d in digits]

    for alph_name, alphabet in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        alph_idx = {c: i for i, c in enumerate(alphabet)}

        for trans in ['none', 'col7']:
            text = CT73
            if trans == 'col7':
                text = col7_undo(CT73)

            # PT-autokey Beaufort
            pt_nums = []
            key = list(primer)
            for i, c in enumerate(text):
                ct_num = alph_idx[c]
                k = key[i % len(key)] if i < len(key) else key[-1]
                pt_num = (k - ct_num) % 26
                pt_nums.append(pt_num)
                if len(key) <= i:
                    key.append(pt_num)  # PT-autokey: extend with PT
                elif i >= len(primer):
                    key.append(pt_num)

            pt = ''.join(alphabet[n] for n in pt_nums)
            score, ene, bcl, _ = score_crib(pt, positions={
                pos97_to_73(p): ch for p, ch in CRIB_DICT.items()
                if p not in MASK_SET
            })

            config = f"autokey_beau:{map_name}:{alph_name}:{trans}"
            if score > 2:
                print(f"  {config}: {score}/24 (ene={ene}, bcl={bcl})")
            if score > best_t7[0]:
                best_t7 = (score, pt[:50], config)
            test7_results.append({'config': config, 'score': score})

            # PT-autokey Vigenere
            pt_nums_v = []
            key_v = list(primer)
            for i, c in enumerate(text):
                ct_num = alph_idx[c]
                k = key_v[i] if i < len(key_v) else key_v[-1]
                pt_num = (ct_num - k) % 26
                pt_nums_v.append(pt_num)
                if i >= len(primer):
                    key_v.append(pt_num)

            pt_v = ''.join(alphabet[n] for n in pt_nums_v)
            score_v, ene_v, bcl_v, _ = score_crib(pt_v, positions={
                pos97_to_73(p): ch for p, ch in CRIB_DICT.items()
                if p not in MASK_SET
            })

            config_v = f"autokey_vig:{map_name}:{alph_name}:{trans}"
            if score_v > 2:
                print(f"  {config_v}: {score_v}/24 (ene={ene_v}, bcl={bcl_v})")
            if score_v > best_t7[0]:
                best_t7 = (score_v, pt_v[:50], config_v)
            test7_results.append({'config': config_v, 'score': score_v})

# Also try with K/W values included
for map_name, leet_map in leet_maps.items():
    for k_val in [11, 10]:
        for w_val in [23, 22]:
            full_digits = []
            for ch in CONSENSUS_STR:
                if ch in leet_map:
                    full_digits.append(leet_map[ch])
                elif ch == 'K':
                    full_digits.append(k_val)
                elif ch == 'W':
                    full_digits.append(w_val)

            primer = [d % 26 for d in full_digits]

            for alph_name, alphabet in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
                alph_idx = {c: i for i, c in enumerate(alphabet)}
                for trans in ['none', 'col7']:
                    text = CT73
                    if trans == 'col7':
                        text = col7_undo(CT73)

                    # PT-autokey Beaufort with full 17-char primer
                    pt_nums = []
                    key = list(primer)
                    for i, c in enumerate(text):
                        ct_num = alph_idx[c]
                        k = key[i] if i < len(key) else pt_nums[i - len(primer)]
                        pt_num = (k - ct_num) % 26
                        pt_nums.append(pt_num)

                    pt = ''.join(alphabet[n] for n in pt_nums)
                    score, ene, bcl, _ = score_crib(pt, positions={
                        pos97_to_73(p): ch for p, ch in CRIB_DICT.items()
                        if p not in MASK_SET
                    })

                    config = f"autokey17_beau:{map_name}:K={k_val}:W={w_val}:{alph_name}:{trans}"
                    if score > 2:
                        print(f"  {config}: {score}/24")
                    if score > best_t7[0]:
                        best_t7 = (score, pt[:50], config)
                    test7_results.append({'config': config, 'score': score})

print(f"\nBest T7: {best_t7[0]}/24 = {best_t7[2]}")
results['tests'].append({
    'name': 'digit_autokey_primer',
    'configs_tested': len(test7_results),
    'best_score': best_t7[0],
    'best_config': best_t7[2],
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 8: Digit positions as selection/reordering indices
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 8: Digits as positional indices / selection keys")
print("="*70)

test8_results = []
best_t8 = (0, '', '')

for map_name, info in digit_sequences.items():
    digits = info['digits_only']

    # Use digits as positions into CT97 to extract chars
    if max(digits) < CT_LEN:
        extracted = ''.join(CT[d] for d in digits)
        print(f"\n{map_name}: Extract CT97[digits] = {extracted}")

    # Use digits as positions into ALPH to form a word
    word = ''.join(ALPH[d % 26] for d in digits)
    print(f"{map_name}: Digits as A=0 alphabet positions = {word}")

    word_ka = ''.join(KRYPTOS_ALPHABET[d % 26] for d in digits)
    print(f"{map_name}: Digits as KA positions = {word_ka}")

    # Use (position, digit) pairs: CT97[pos] shifted by digit
    for alph_name, alphabet in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        alph_idx = {c: i for i, c in enumerate(alphabet)}

        # Method: at null positions, the digit tells you how far to jump
        # to find the "real" char this null replaces
        replacements = {}
        digit_idx = 0
        for null_pos in CONSENSUS_NULLS:
            ch = CT[null_pos]
            if ch in info.get('_map', leet_maps.get(map_name, {})):
                d = info.get('_map', leet_maps.get(map_name, {}))[ch]
            elif ch == 'K' or ch == 'W':
                digit_idx += 1
                continue
            else:
                digit_idx += 1
                continue

            # Jump forward by d positions from null_pos
            target = (null_pos + d) % CT_LEN
            replacements[null_pos] = CT[target]
            digit_idx += 1

        # Build modified CT with replacements
        modified = list(CT)
        for pos, replacement in replacements.items():
            modified[pos] = replacement
        modified_str = ''.join(modified)

        # Score
        score, ene, bcl, _ = score_crib(modified_str)
        config = f"jump_replace:{map_name}:{alph_name}"
        if score > 2:
            print(f"  {config}: {score}/24")
        if score > best_t8[0]:
            best_t8 = (score, modified_str[:50], config)
        test8_results.append({'config': config, 'score': score})

print(f"\nBest T8: {best_t8[0]}/24 = {best_t8[2]}")
results['tests'].append({
    'name': 'digit_position_indices',
    'configs_tested': len(test8_results),
    'best_score': best_t8[0],
    'best_config': best_t8[2],
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 9: All 26 CT letters through leetspeak -- number/letter partition
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 9: All-position leetspeak partition analysis")
print("="*70)

# Letters with clear single-digit leetspeak equivalents
LEET_UNAMBIGUOUS = {'B': 8, 'G': 6, 'I': 1, 'O': 0, 'Z': 2}
LEET_EXTENDED = {'A': 4, 'B': 8, 'E': 3, 'G': 6, 'I': 1, 'L': 1, 'O': 0, 'S': 5, 'T': 7, 'Z': 2}

# Partition CT97 into "number-readable" and "letter-only" positions
for leet_name, leet_map in [('unambiguous', LEET_UNAMBIGUOUS), ('extended', LEET_EXTENDED)]:
    number_positions = [i for i in range(CT_LEN) if CT[i] in leet_map]
    letter_positions = [i for i in range(CT_LEN) if CT[i] not in leet_map]

    print(f"\n{leet_name} leetspeak: {len(number_positions)} number positions, {len(letter_positions)} letter positions")

    # Extract the "letter only" text (removing number-readable chars)
    letter_text = ''.join(CT[i] for i in letter_positions)
    print(f"  Letter-only text ({len(letter_text)} chars): {letter_text[:60]}...")

    # Is it 73?
    if len(letter_text) == 73:
        print(f"  *** CRITICAL: Letter-only text is EXACTLY 73 chars! ***")
    elif len(letter_positions) == 73:
        print(f"  *** CRITICAL: Exactly 73 non-number positions! ***")

    # Compare number positions to consensus nulls
    num_set = frozenset(number_positions)
    null_set = frozenset(CONSENSUS_NULLS)
    overlap = num_set & null_set
    print(f"  Overlap with consensus nulls: {len(overlap)}/{len(CONSENSUS_NULLS)}")

    # How many number positions are in the USER_MASK (24 nulls)?
    mask_overlap = num_set & MASK_SET
    print(f"  Overlap with 24-null mask: {len(mask_overlap)}/{len(USER_MASK)}")

    # Compute IC of letter-only text
    from collections import Counter
    freqs = Counter(letter_text)
    n = len(letter_text)
    ic = sum(f * (f-1) for f in freqs.values()) / (n * (n-1)) if n > 1 else 0
    print(f"  IC of letter-only text: {ic:.4f} (random={1/26:.4f}, English={0.0667:.4f})")

results['tests'].append({
    'name': 'all_position_leetspeak_partition',
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 10: Position (mod digit) patterns
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 10: (Position, Digit) pair analysis")
print("="*70)

for map_name, leet_map in [('G6_Z2', LEET_CLEAR), ('G9_Z2', LEET_G9)]:
    print(f"\n{map_name}:")
    pos_digit_pairs = []
    for p in CONSENSUS_NULLS:
        ch = CT[p]
        if ch in leet_map:
            d = leet_map[ch]
            pos_digit_pairs.append((p, d))

    print(f"  (Position, Digit) pairs: {pos_digit_pairs}")

    # Position + digit
    sums = [p + d for p, d in pos_digit_pairs]
    print(f"  Pos + Digit: {sums}")
    print(f"  (Pos + Digit) mod 26: {[s % 26 for s in sums]}")
    print(f"  As letters (AZ): {''.join(ALPH[s % 26] for s in sums)}")

    # Position * digit (skip zeros)
    products = [(p * d) % 26 for p, d in pos_digit_pairs if d > 0]
    print(f"  (Pos * Digit) mod 26 [d>0]: {products}")
    print(f"  As letters (AZ): {''.join(ALPH[p] for p in products)}")

    # Position XOR digit
    xors = [p ^ d for p, d in pos_digit_pairs]
    print(f"  Pos XOR Digit: {xors}")

    # (pos + digit) mod 97 as index into CT
    ct_chars = ''.join(CT[(p + d) % CT_LEN] for p, d in pos_digit_pairs)
    print(f"  CT[(pos+digit)%97]: {ct_chars}")

    # Sum of all pos*digit
    total_pd = sum(p * d for p, d in pos_digit_pairs)
    print(f"  Sum(pos*digit) = {total_pd}, mod 26 = {total_pd % 26} -> {ALPH[total_pd % 26]}")
    print(f"  Sum(pos*digit) mod 97 = {total_pd % 97}")

# ══════════════════════════════════════════════════════════════════════════
# TEST 11: Exhaustive search -- digit sequence as Gronsfeld with all offsets
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 11: Exhaustive Gronsfeld/Beaufort with digit keys at all offsets")
print("="*70)

test11_results = []
best_t11 = (0, '', '')
configs_t11 = 0

# For each leet mapping, try the digit sequence starting at each CT position
for map_name, leet_map in leet_maps.items():
    for k_val in [None, 11]:
        for w_val in [None, 23]:
            full_digits = []
            for ch in CONSENSUS_STR:
                if ch in leet_map:
                    full_digits.append(leet_map[ch])
                elif ch == 'K' and k_val is not None:
                    full_digits.append(k_val)
                elif ch == 'W' and w_val is not None:
                    full_digits.append(w_val)
                else:
                    continue

            if len(full_digits) < 3:
                continue

            key_mod26 = [d % 26 for d in full_digits]

            for alph_name, alphabet in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
                for cipher in ['vig', 'beau']:
                    for offset in range(len(key_mod26)):
                        # Rotate key by offset
                        rotated_key = key_mod26[offset:] + key_mod26[:offset]

                        if cipher == 'vig':
                            pt = decrypt_vigenere(CT, rotated_key, alphabet)
                        else:
                            pt = decrypt_beaufort(CT, rotated_key, alphabet)

                        score, ene, bcl, _ = score_crib(pt)
                        configs_t11 += 1

                        if score > 3:
                            config = f"{cipher}:{map_name}:K={k_val}:W={w_val}:{alph_name}:off={offset}"
                            print(f"  {config}: {score}/24")
                            test11_results.append({'config': config, 'score': score})

                        if score > best_t11[0]:
                            config = f"{cipher}:{map_name}:K={k_val}:W={w_val}:{alph_name}:off={offset}"
                            best_t11 = (score, pt[:50], config)

print(f"\nBest T11: {best_t11[0]}/24 = {best_t11[2]}")
print(f"Configs tested: {configs_t11}")
results['tests'].append({
    'name': 'exhaustive_gronsfeld_offsets',
    'configs_tested': configs_t11,
    'best_score': best_t11[0],
    'best_config': best_t11[2],
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 12: DEFECTOR:AZ_beau with leetspeak-derived mask modifications
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 12: DEFECTOR:AZ_beau + digit-informed mask modifications")
print("="*70)

test12_results = []
best_t12 = (0, '', '')

DEFECTOR_KEY = [ord(c) - 65 for c in 'DEFECTOR']

def defector_beau_col7_decrypt(ct73_text):
    """Apply col7 undo then Beaufort autokey with DEFECTOR primer."""
    text = col7_undo(ct73_text)
    pt_nums = []
    key = list(DEFECTOR_KEY)
    for i, c in enumerate(text):
        ct_num = ALPH_IDX[c]
        k = key[i] if i < len(key) else pt_nums[i - 8]
        pt_num = (k - ct_num) % 26
        pt_nums.append(pt_num)
    return ''.join(ALPH[n] for n in pt_nums)


# For each leet mapping, try using the digit values to modify which positions
# are in the null mask
for map_name, leet_map in leet_maps.items():
    for k_val in [None, 11]:
        for w_val in [None, 23]:
            # Get digit for each null position
            pos_digits = {}
            for p in CONSENSUS_NULLS:
                ch = CT[p]
                if ch in leet_map:
                    pos_digits[p] = leet_map[ch]
                elif ch == 'K' and k_val is not None:
                    pos_digits[p] = k_val
                elif ch == 'W' and w_val is not None:
                    pos_digits[p] = w_val

            # Hypothesis: the digit at each null position tells you how many
            # ADDITIONAL null positions to skip forward/backward
            # Try: null pos + digit = additional null
            extra_nulls_fwd = set()
            for p, d in pos_digits.items():
                target = p + d
                if 0 <= target < CT_LEN and target not in frozenset(CONSENSUS_NULLS):
                    extra_nulls_fwd.add(target)

            # Combined mask: consensus + digit-derived
            combined_mask = frozenset(CONSENSUS_NULLS) | extra_nulls_fwd
            if len(combined_mask) == 24:
                ct73_new = ''.join(CT[i] for i in range(CT_LEN) if i not in combined_mask)
                if len(ct73_new) == 73:
                    pt = defector_beau_col7_decrypt(ct73_new)
                    score, ene, bcl, _ = score_crib(pt, positions={
                        pos97_to_73(p): ch for p, ch in CRIB_DICT.items()
                        if p not in combined_mask
                    })
                    config = f"digit_fwd_mask:{map_name}:K={k_val}:W={w_val}"
                    if score > 0:
                        print(f"  {config}: {score}/24 (mask size {len(combined_mask)})")
                    if score > best_t12[0]:
                        best_t12 = (score, pt[:50], config)
                    test12_results.append({'config': config, 'score': score, 'mask': sorted(combined_mask)})

            # Try backward
            extra_nulls_bwd = set()
            for p, d in pos_digits.items():
                target = p - d
                if 0 <= target < CT_LEN and target not in frozenset(CONSENSUS_NULLS):
                    extra_nulls_bwd.add(target)

            combined_bwd = frozenset(CONSENSUS_NULLS) | extra_nulls_bwd
            if len(combined_bwd) == 24:
                ct73_new = ''.join(CT[i] for i in range(CT_LEN) if i not in combined_bwd)
                if len(ct73_new) == 73:
                    pt = defector_beau_col7_decrypt(ct73_new)
                    # Recalc crib positions for this mask
                    crib73 = {}
                    for p, ch in CRIB_DICT.items():
                        if p not in combined_bwd:
                            new_pos = p - sum(1 for m in sorted(combined_bwd) if m < p)
                            crib73[new_pos] = ch
                    score, ene, bcl, _ = score_crib(pt, positions=crib73)
                    config = f"digit_bwd_mask:{map_name}:K={k_val}:W={w_val}"
                    if score > 0:
                        print(f"  {config}: {score}/24 (mask size {len(combined_bwd)})")
                    if score > best_t12[0]:
                        best_t12 = (score, pt[:50], config)
                    test12_results.append({'config': config, 'score': score, 'mask': sorted(combined_bwd)})

print(f"\nBest T12: {best_t12[0]}/24 = {best_t12[2]}")
results['tests'].append({
    'name': 'defector_digit_mask',
    'configs_tested': len(test12_results),
    'best_score': best_t12[0],
    'best_config': best_t12[2],
})

# ══════════════════════════════════════════════════════════════════════════
# TEST 13: Monte Carlo — is the palette's leetspeak-amenability significant?
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("TEST 13: Monte Carlo — leetspeak amenability of null palette")
print("="*70)

import random
random.seed(20260316)

# How many of the 7 palette letters have UNAMBIGUOUS single-digit leetspeak?
# B=8, G=6, I=1, O=0, Z=2 → 5 of 7 (71.4%)
# K and W are ambiguous → only 5 clear mappings

# MC: pick 7 random letters from 26, count how many have unambiguous leet mappings
UNAMBIGUOUS_LEET_LETTERS = set('BGIOSZ')  # 6 letters (note: we debated, let's include S here)
# Actually be precise: B=8, G=6, I=1, O=0, Z=2, S=5 are the clear digit resemblances
# But the palette has K and W, not S. So palette has 5/7 unambiguous.
# Let's count: which of the 26 letters have CLEAR single-digit leetspeak?
# Standard: B=8, G=6/9, I=1, O=0, Z=2/5, S=5, T=7, E=3, A=4, L=1
# "Clear" (no ambiguity, immediate visual): B=8, I=1, O=0 → 3 letters
# "Moderate" (widely recognized): + G=6, Z=2, S=5, T=7, E=3, A=4 → 9
# "Stretched" (requires imagination): + L=1, R=? → 10

# Let's test: among the 7 palette letters, 5 have at least "moderate" leet.
# How often does a random 7-letter subset of 26 have >= 5 moderate-leet letters?
MODERATE_LEET = set('ABEGIOSTZ')  # 9 letters with moderate-quality leet mappings
palette_moderate = len(PALETTE & MODERATE_LEET)
print(f"Palette letters with moderate leet: {sorted(PALETTE & MODERATE_LEET)} = {palette_moderate}/7")

MC_TRIALS = 200000
hits = 0
for _ in range(MC_TRIALS):
    sample = set(random.sample(list(ALPH), 7))
    if len(sample & MODERATE_LEET) >= palette_moderate:
        hits += 1

p_value = hits / MC_TRIALS
print(f"\nMC (200K trials): P(random 7-letter subset has >= {palette_moderate}/7 moderate-leet) = {p_value:.4f}")
print(f"  = 1 in {1/p_value:.0f}" if p_value > 0 else "  = < 1/200K")

# Stricter: letters with UNAMBIGUOUS single-digit leet (B=8, I=1, O=0 only)
STRICT_LEET = set('BIO')
palette_strict = len(PALETTE & STRICT_LEET)
print(f"\nPalette letters with strict leet (B=8,I=1,O=0): {sorted(PALETTE & STRICT_LEET)} = {palette_strict}/7")
hits2 = 0
for _ in range(MC_TRIALS):
    sample = set(random.sample(list(ALPH), 7))
    if len(sample & STRICT_LEET) >= palette_strict:
        hits2 += 1
p_value2 = hits2 / MC_TRIALS
print(f"MC: P(>= {palette_strict}/7 strict-leet) = {p_value2:.4f} = 1 in {1/p_value2:.0f}" if p_value2 > 0 else "< 1/200K")

results['tests'].append({
    'name': 'mc_leet_amenability',
    'palette_moderate_count': palette_moderate,
    'p_moderate': p_value,
    'palette_strict_count': palette_strict,
    'p_strict': p_value2,
})

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "="*70)
print("SUMMARY")
print("="*70)

all_scores = []
for test in results['tests']:
    if 'best_score' in test:
        all_scores.append((test['best_score'], test['name'], test.get('best_config', '')))
        print(f"  {test['name']}: best {test['best_score']}/24 ({test.get('configs_tested', '?')} configs)")

overall_best = max(all_scores, key=lambda x: x[0]) if all_scores else (0, 'none', '')
results['best_score'] = overall_best[0]
results['best_config'] = overall_best[2]

total_configs = sum(t.get('configs_tested', 0) for t in results['tests'] if 'configs_tested' in t)
results['total_configs'] = total_configs

print(f"\nOverall best: {overall_best[0]}/24 from {overall_best[1]} ({overall_best[2]})")
print(f"Total configs tested: {total_configs}")
print(f"Noise floor: {NOISE_FLOOR}/24")

if overall_best[0] <= NOISE_FLOOR:
    results['verdict'] = 'NOISE - Leetspeak digit encoding does not produce cipher signal'
    print(f"\nVERDICT: NOISE. All scores <= {NOISE_FLOOR}/24.")
    print("The leetspeak visual resemblance hypothesis produces NO cipher signal.")
elif overall_best[0] < STORE_THRESHOLD:
    results['verdict'] = 'WEAK - Above noise but below store threshold'
    print(f"\nVERDICT: WEAK. Best = {overall_best[0]}/24, below store threshold ({STORE_THRESHOLD}).")
else:
    results['verdict'] = f'INTERESTING - Best {overall_best[0]}/24 warrants investigation'
    print(f"\nVERDICT: INTERESTING. Best = {overall_best[0]}/24.")

# Save results
output_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'e_leetspeak_palette_v1.json')
with open(output_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nResults saved to: {output_path}")
