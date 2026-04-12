#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort with antipodal coordinate key
Family: polyalphabetic
Status: active
Keyspace: 7 digit modes x 3 cipher variants x 3 W-handling modes = 63+ combos
Last run: 2026-04-11
Best score: pending
"""
"""
HYPOTHESIS: K4 uses a Vigenere or Beaufort cipher keyed by digits extracted from
the geographic ANTIPODE of the K2 coordinates (38 57'6.5"N, 77 8'44"W).

The antipode is: 38 57'6.5"S, 102 51'16"E

'W' characters in the ciphertext allegedly mark segment boundaries where
the numeric key resets (key index returns to 0).

This script exhaustively tests ALL combinations of:
  - 7+ digit extraction conventions from the antipodal coordinates
  - 3 cipher variants (Vigenere, Beaufort, Variant Beaufort)
  - 3 W-handling modes (key_reset_w_enciphered, key_reset_w_null, no_reset)
  - Plus variations (strip zeros, no decimals, etc.)

Evaluation: crib matching, keystream constraints (Bean equalities),
English trigram frequency scoring, and explicit kill criteria.
"""

import json
import math
import os
import sys
import time
from collections import Counter
from pathlib import Path

# Add source tree
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, N_CRIBS,
    BEAN_EQ,
)

# ============================================================================
# Constants
# ============================================================================
K4 = CT
assert len(K4) == 97

# Known cribs (from canonical constants)
# EASTNORTHEAST at 21-33, BERLINCLOCK at 63-73
CRIB_ENE_START = 21
CRIB_ENE = "EASTNORTHEAST"
CRIB_BC_START = 63
CRIB_BC = "BERLINCLOCK"

# Also check the user-specified positions (26-36, 64-74) as alternate crib placements
ALT_CRIB_BC_START = 26
ALT_CRIB_BC = "BERLINCLOCK"
ALT_CRIB_NE_START = 64
ALT_CRIB_NE = "NORTHEAST"

# K2 coordinates
K2_LAT_DEG = 38
K2_LAT_MIN = 57
K2_LAT_SEC = 6.5
K2_LON_DEG = 77
K2_LON_MIN = 8
K2_LON_SEC = 44.0

# Antipodal coordinates
ANT_LAT_DEG = 38
ANT_LAT_MIN = 57
ANT_LAT_SEC = 6.5
ANT_LON_DEG = 102
ANT_LON_MIN = 51
ANT_LON_SEC = 16.0

# W positions in K4
W_POSITIONS = [i for i, c in enumerate(K4) if c == 'W']

# ============================================================================
# Load quadgram scorer
# ============================================================================
QUADGRAMS = {}
QG_FLOOR = -10.0
qg_path = Path(__file__).resolve().parent.parent.parent / "data" / "english_quadgrams.json"
if qg_path.exists():
    with open(qg_path) as f:
        QUADGRAMS = json.load(f)
    if "logp" in QUADGRAMS:
        QUADGRAMS = QUADGRAMS["logp"]
    if QUADGRAMS:
        QG_FLOOR = min(QUADGRAMS.values())
    print(f"[INFO] Loaded {len(QUADGRAMS)} quadgrams from {qg_path}")
else:
    print(f"[WARN] Quadgram file not found at {qg_path}")

# English letter frequencies
ENGLISH_FREQ = {
    'A': 0.0817, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}

# Common English trigrams (top 50)
COMMON_TRIGRAMS = set([
    "THE", "AND", "ING", "HER", "HAT", "HIS", "THA", "ERE", "FOR", "ENT",
    "ION", "TER", "WAS", "YOU", "ITH", "VER", "ALL", "WIT", "THI", "TIO",
    "NDE", "HAS", "NCE", "EDT", "TIS", "OFT", "STH", "MEN", "BLE", "ATE",
    "ONA", "OUS", "EAR", "EST", "INT", "ANT", "OUR", "ERS", "NOT", "IVE",
    "RES", "STA", "EVE", "ARE", "HEN", "COM", "PRO", "ONE", "TED", "INE",
])


# ============================================================================
# Scoring Functions
# ============================================================================
def quadgram_score(text):
    """Quadgram log-probability score (higher = more English-like)."""
    t = text.upper()
    if len(t) < 4:
        return QG_FLOOR * max(1, len(t) - 3)
    total = 0.0
    for i in range(len(t) - 3):
        gram = t[i:i+4]
        total += QUADGRAMS.get(gram, QG_FLOOR)
    return total


def quadgram_score_per_char(text):
    t = text.upper()
    n = len(t) - 3
    if n <= 0:
        return QG_FLOOR
    return quadgram_score(t) / n


def trigram_score(text):
    """Count how many consecutive 3-letter sequences appear in common English trigrams."""
    t = text.upper()
    count = 0
    for i in range(len(t) - 2):
        if t[i:i+3] in COMMON_TRIGRAMS:
            count += 1
    return count


def english_unigram_logprob(text):
    """Log-likelihood under English unigram model."""
    t = text.upper()
    return sum(math.log(ENGLISH_FREQ.get(c, 0.0001)) for c in t if c.isalpha())


def chi_squared_english(text):
    """Chi-squared vs English letter frequencies (lower = more English-like)."""
    n = len(text)
    if n == 0:
        return float('inf')
    counts = Counter(text.upper())
    chi2 = 0.0
    for c in ALPH:
        expected = ENGLISH_FREQ[c] * n
        observed = counts.get(c, 0)
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2


# ============================================================================
# Coordinate Digit Extraction
# ============================================================================
def dms_to_decimal(deg, min_, sec):
    """Convert DMS to decimal degrees."""
    return deg + min_ / 60.0 + sec / 3600.0


def extract_digits(s):
    """Extract all digit characters from a string, return as list of ints."""
    return [int(c) for c in str(s) if c.isdigit()]


def compute_digit_keys():
    """Compute all digit key sequences from the antipodal coordinates.

    Returns dict: mode_name -> list of int digits
    """
    keys = {}

    # Antipode: 38 57'6.5"S, 102 51'16"E
    lat_str = "38 57 6.5"
    lon_str = "102 51 16"

    # 1. dms_lat_lon: concatenate all digits from DMS, latitude first
    # 38 57'6.5"S, 102 51'16"E -> 3,8,5,7,6,5,1,0,2,5,1,1,6
    dms_lat_digits = extract_digits(lat_str)
    dms_lon_digits = extract_digits(lon_str)
    keys["dms_lat_lon"] = dms_lat_digits + dms_lon_digits

    # 2. dms_lon_lat: longitude digits first then latitude
    keys["dms_lon_lat"] = dms_lon_digits + dms_lat_digits

    # 3. decimal_4dp: -38.9518, 102.8544
    ant_lat_dec = dms_to_decimal(ANT_LAT_DEG, ANT_LAT_MIN, ANT_LAT_SEC)
    ant_lon_dec = dms_to_decimal(ANT_LON_DEG, ANT_LON_MIN, ANT_LON_SEC)

    lat_4dp = f"{ant_lat_dec:.4f}"
    lon_4dp = f"{ant_lon_dec:.4f}"
    keys["decimal_4dp"] = extract_digits(lat_4dp) + extract_digits(lon_4dp)

    # 4. decimal_6dp
    lat_6dp = f"{ant_lat_dec:.6f}"
    lon_6dp = f"{ant_lon_dec:.6f}"
    keys["decimal_6dp"] = extract_digits(lat_6dp) + extract_digits(lon_6dp)

    # 5. decimal_8dp
    lat_8dp = f"{ant_lat_dec:.8f}"
    lon_8dp = f"{ant_lon_dec:.8f}"
    keys["decimal_8dp"] = extract_digits(lat_8dp) + extract_digits(lon_8dp)

    # 6. min_sec_only: only minutes and seconds digits
    # 57, 6.5 and 51, 16 -> 5,7,6,5,5,1,1,6
    min_sec_lat = extract_digits("57 6.5")
    min_sec_lon = extract_digits("51 16")
    keys["min_sec_only"] = min_sec_lat + min_sec_lon

    # 7. degrees_only: only the degree numbers
    # 38 and 102 -> 3,8,1,0,2
    keys["degrees_only"] = extract_digits("38") + extract_digits("102")

    # ---- Variations ----

    # Strip zeros from dms_lat_lon
    keys["dms_lat_lon_no_zeros"] = [d for d in keys["dms_lat_lon"] if d != 0]

    # Strip zeros from dms_lon_lat
    keys["dms_lon_lat_no_zeros"] = [d for d in keys["dms_lon_lat"] if d != 0]

    # decimal without the fractional part digits (just integer parts)
    keys["decimal_int_parts_only"] = extract_digits(str(int(ant_lat_dec))) + extract_digits(str(int(ant_lon_dec)))

    # DMS without decimal seconds (drop the .5 from 6.5)
    lat_nodec = "38 57 6"
    lon_nodec = "102 51 16"
    keys["dms_lat_lon_no_decimal"] = extract_digits(lat_nodec) + extract_digits(lon_nodec)
    keys["dms_lon_lat_no_decimal"] = extract_digits(lon_nodec) + extract_digits(lat_nodec)

    # Concatenated raw numbers (no spaces): "385765" + "1025116"
    keys["dms_raw_concat"] = extract_digits("385765" + "1025116")

    # Individual coordinate components as concatenated numbers
    keys["components_lat_first"] = [3, 8, 5, 7, 0, 6, 5]  # deg min sec (with leading 0 for sec<10)
    keys["components_lon_first"] = [1, 0, 2, 5, 1, 1, 6, 3, 8, 5, 7, 0, 6, 5]

    # Decimal degrees stripped of period, zeros removed
    dec4_nozero_lat = [d for d in extract_digits(lat_4dp) if d != 0]
    dec4_nozero_lon = [d for d in extract_digits(lon_4dp) if d != 0]
    keys["decimal_4dp_no_zeros"] = dec4_nozero_lat + dec4_nozero_lon

    return keys


# ============================================================================
# Cipher Operations
# ============================================================================
def decrypt_vigenere(ct_char_idx, key_digit):
    """Vigenere decrypt: P = (C - K) mod 26. Key is a digit 0-9 used as shift."""
    return (ct_char_idx - key_digit) % 26


def decrypt_beaufort(ct_char_idx, key_digit):
    """Beaufort decrypt: P = (K - C) mod 26."""
    return (key_digit - ct_char_idx) % 26


def decrypt_variant_beaufort(ct_char_idx, key_digit):
    """Variant Beaufort (additive): P = (C + K) mod 26."""
    return (ct_char_idx + key_digit) % 26


CIPHER_VARIANTS = {
    "vigenere": decrypt_vigenere,
    "beaufort": decrypt_beaufort,
    "variant_beaufort": decrypt_variant_beaufort,
}


def apply_cipher(ciphertext, digit_key, cipher_func, w_mode):
    """Apply a cipher variant with a digit key and W-handling mode.

    Args:
        ciphertext: string of uppercase letters
        digit_key: list of int digits (0-9)
        cipher_func: one of decrypt_vigenere, decrypt_beaufort, decrypt_variant_beaufort
        w_mode: 'key_reset_w_enciphered', 'key_reset_w_null', 'no_reset'

    Returns:
        tuple: (plaintext_string, keystream_values_list)
    """
    plaintext = []
    keystream = []
    key_idx = 0
    key_len = len(digit_key)

    if key_len == 0:
        return ciphertext, [0] * len(ciphertext)

    for i, c in enumerate(ciphertext):
        c_idx = ALPH_IDX[c]

        if c == 'W' and w_mode != 'no_reset':
            if w_mode == 'key_reset_w_null':
                # W is passed through as-is, key resets
                plaintext.append('W')
                keystream.append(-1)  # sentinel: W passed through
                key_idx = 0
                continue
            elif w_mode == 'key_reset_w_enciphered':
                # W is decrypted normally, then key resets
                k = digit_key[key_idx % key_len]
                p_idx = cipher_func(c_idx, k)
                plaintext.append(ALPH[p_idx])
                keystream.append(k)
                key_idx = 0
                continue

        # Normal decryption
        k = digit_key[key_idx % key_len]
        p_idx = cipher_func(c_idx, k)
        plaintext.append(ALPH[p_idx])
        keystream.append(k)
        key_idx += 1

    return ''.join(plaintext), keystream


# ============================================================================
# Evaluation Functions
# ============================================================================
def check_crib_at_position(plaintext, crib, start_pos):
    """Check if crib appears at the given position in plaintext."""
    if start_pos + len(crib) > len(plaintext):
        return False
    return plaintext[start_pos:start_pos + len(crib)] == crib


def count_crib_matches(plaintext):
    """Count how many individual crib character positions match."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(plaintext) and plaintext[pos] == ch:
            matches += 1
    return matches


def check_bean_equalities(keystream):
    """Check Bean equality constraints on keystream.

    Bean equality: k[27] == k[65]
    Also check: k[32] == k[73] and both == 0 (mod 26)
    """
    results = {}

    # k[27] == k[65]
    if len(keystream) > 65:
        k27 = keystream[27]
        k65 = keystream[65]
        # Handle sentinel values for W-null mode
        if k27 == -1 or k65 == -1:
            results['k27_eq_k65'] = None  # indeterminate (W passed through)
        else:
            results['k27_eq_k65'] = (k27 == k65)
            results['k27'] = k27
            results['k65'] = k65

    # k[32] == k[73]
    if len(keystream) > 73:
        k32 = keystream[32]
        k73 = keystream[73]
        if k32 == -1 or k73 == -1:
            results['k32_eq_k73'] = None
        else:
            results['k32_eq_k73'] = (k32 == k73)
            results['k32_= k73_= 0'] = (k32 % 26 == 0 and k73 % 26 == 0)
            results['k32'] = k32
            results['k73'] = k73

    return results


def evaluate_decryption(plaintext, keystream, digit_mode, cipher_name, w_mode, digit_key):
    """Evaluate a single decryption attempt.

    Returns a dict with all scores and diagnostic info.
    """
    result = {
        'digit_mode': digit_mode,
        'cipher': cipher_name,
        'w_mode': w_mode,
        'key': digit_key,
        'key_str': ''.join(str(d) for d in digit_key),
        'plaintext': plaintext,
    }

    # Crib checks (canonical positions)
    result['ene_at_21'] = check_crib_at_position(plaintext, CRIB_ENE, CRIB_ENE_START)
    result['bc_at_63'] = check_crib_at_position(plaintext, CRIB_BC, CRIB_BC_START)

    # Alternative crib positions from hypothesis
    result['bc_at_26'] = check_crib_at_position(plaintext, ALT_CRIB_BC, ALT_CRIB_BC_START)
    result['ne_at_64'] = check_crib_at_position(plaintext, ALT_CRIB_NE, ALT_CRIB_NE_START)

    # Substring search for cribs anywhere
    result['ene_found'] = CRIB_ENE in plaintext
    result['bc_found'] = CRIB_BC in plaintext
    result['ne_found'] = "NORTHEAST" in plaintext
    result['berlin_found'] = "BERLIN" in plaintext
    result['clock_found'] = "CLOCK" in plaintext

    # Individual crib character matches
    result['crib_matches'] = count_crib_matches(plaintext)

    # Bean equality checks
    bean = check_bean_equalities(keystream)
    result['bean'] = bean

    # Scoring
    if QUADGRAMS:
        result['qg_score'] = quadgram_score(plaintext)
        result['qg_score_pc'] = quadgram_score_per_char(plaintext)
    else:
        result['qg_score'] = 0.0
        result['qg_score_pc'] = 0.0

    result['trigram_count'] = trigram_score(plaintext)
    result['chi2'] = chi_squared_english(plaintext)
    result['unigram_logprob'] = english_unigram_logprob(plaintext)

    # Composite score for ranking (higher = better)
    # Weight: quadgram score (primary), trigram count, crib matches
    result['composite'] = (
        result['qg_score_pc'] * 10.0 +
        result['trigram_count'] * 2.0 +
        result['crib_matches'] * 50.0
    )

    # Kill flags
    result['any_crib_hit'] = any([
        result['ene_at_21'], result['bc_at_63'],
        result['bc_at_26'], result['ne_at_64'],
        result['ene_found'], result['bc_found'],
        result['ne_found'], result['berlin_found'],
        result['clock_found'],
    ])

    return result


# ============================================================================
# Main Execution
# ============================================================================
def main():
    t_start = time.time()

    print("=" * 80)
    print("ANTIPODE VIGENERE/BEAUFORT HYPOTHESIS TEST")
    print("=" * 80)

    print(f"\nK4 ciphertext ({len(K4)} chars):")
    print(f"  {K4}")

    # Show W positions
    print(f"\nW positions in K4 (0-indexed): {W_POSITIONS}")
    print(f"  Count: {len(W_POSITIONS)}")
    for wp in W_POSITIONS:
        ctx_start = max(0, wp - 3)
        ctx_end = min(len(K4), wp + 4)
        ctx = K4[ctx_start:ctx_end]
        marker = ' ' * (wp - ctx_start) + '^'
        print(f"  Position {wp}: ...{ctx}...  {marker}")

    # Compute coordinate conversions
    print(f"\n{'=' * 80}")
    print("COORDINATE CONVERSIONS")
    print(f"{'=' * 80}")

    ant_lat_dec = dms_to_decimal(ANT_LAT_DEG, ANT_LAT_MIN, ANT_LAT_SEC)
    ant_lon_dec = dms_to_decimal(ANT_LON_DEG, ANT_LON_MIN, ANT_LON_SEC)

    print(f"\nK2 coordinates:    38 57'6.5\"N, 77 8'44\"W")
    print(f"Antipode:          38 57'6.5\"S, 102 51'16\"E")
    print(f"Antipode decimal:  {ant_lat_dec:.8f}S, {ant_lon_dec:.8f}E")
    print(f"                   -{ant_lat_dec:.8f}, {ant_lon_dec:.8f}")

    # Compute digit keys
    digit_keys = compute_digit_keys()

    print(f"\n{'=' * 80}")
    print("DIGIT KEY SEQUENCES")
    print(f"{'=' * 80}")

    for name, digits in sorted(digit_keys.items()):
        digit_str = ','.join(str(d) for d in digits)
        print(f"  {name:30s} [{len(digits):2d} digits]: {digit_str}")

    # Enumerate all combinations
    print(f"\n{'=' * 80}")
    print("EXHAUSTIVE CIPHER TESTING")
    print(f"{'=' * 80}")

    w_modes = ['key_reset_w_enciphered', 'key_reset_w_null', 'no_reset']

    n_digit_modes = len(digit_keys)
    n_cipher_variants = len(CIPHER_VARIANTS)
    n_w_modes = len(w_modes)
    total_combos = n_digit_modes * n_cipher_variants * n_w_modes

    print(f"\n  Digit modes:     {n_digit_modes}")
    print(f"  Cipher variants: {n_cipher_variants}")
    print(f"  W-handling modes:{n_w_modes}")
    print(f"  Total combos:    {total_combos}")

    all_results = []
    tested = 0

    for digit_mode, digit_key in digit_keys.items():
        for cipher_name, cipher_func in CIPHER_VARIANTS.items():
            for w_mode in w_modes:
                tested += 1

                pt, ks = apply_cipher(K4, digit_key, cipher_func, w_mode)
                result = evaluate_decryption(
                    pt, ks, digit_mode, cipher_name, w_mode, digit_key
                )
                all_results.append(result)

    print(f"\n  Tested: {tested} combinations")

    # ====================================================================
    # Report: Kill Criteria
    # ====================================================================
    print(f"\n{'=' * 80}")
    print("KILL CRITERIA CHECK")
    print(f"{'=' * 80}")

    # Check 1: Any exact crib match at canonical positions
    exact_crib_hits = [r for r in all_results if r['ene_at_21'] or r['bc_at_63']]
    print(f"\n  1. Exact EASTNORTHEAST at pos 21-33:  {sum(1 for r in all_results if r['ene_at_21'])} hits")
    print(f"     Exact BERLINCLOCK at pos 63-73:    {sum(1 for r in all_results if r['bc_at_63'])} hits")

    # Check alternate positions
    alt_hits = [r for r in all_results if r['bc_at_26'] or r['ne_at_64']]
    print(f"     Exact BERLINCLOCK at pos 26-36:    {sum(1 for r in all_results if r['bc_at_26'])} hits")
    print(f"     Exact NORTHEAST at pos 64-72:      {sum(1 for r in all_results if r['ne_at_64'])} hits")

    # Check 2: Cribs found ANYWHERE in plaintext
    any_crib = [r for r in all_results if r['any_crib_hit']]
    print(f"\n  2. Any crib substring found anywhere: {len(any_crib)} combos")
    if any_crib:
        for r in any_crib:
            print(f"     >>> {r['digit_mode']} / {r['cipher']} / {r['w_mode']}")
            if r['ene_found']:
                pos = r['plaintext'].find(CRIB_ENE)
                print(f"         EASTNORTHEAST found at pos {pos}")
            if r['bc_found']:
                pos = r['plaintext'].find(CRIB_BC)
                print(f"         BERLINCLOCK found at pos {pos}")
            if r['ne_found']:
                pos = r['plaintext'].find("NORTHEAST")
                print(f"         NORTHEAST found at pos {pos}")
            if r['berlin_found']:
                pos = r['plaintext'].find("BERLIN")
                print(f"         BERLIN found at pos {pos}")
            if r['clock_found']:
                pos = r['plaintext'].find("CLOCK")
                print(f"         CLOCK found at pos {pos}")

    # Check 3: Bean equality k[27]==k[65]
    bean_pass = [r for r in all_results if r['bean'].get('k27_eq_k65') is True]
    bean_fail = [r for r in all_results if r['bean'].get('k27_eq_k65') is False]
    bean_na = [r for r in all_results if r['bean'].get('k27_eq_k65') is None]
    print(f"\n  3. Bean equality k[27]==k[65]:")
    print(f"     PASS: {len(bean_pass)}  FAIL: {len(bean_fail)}  N/A (W-null): {len(bean_na)}")

    # Check 4: k[32]==k[73] and both == 0 mod 26
    k32_k73_eq = [r for r in all_results if r['bean'].get('k32_eq_k73') is True]
    k32_k73_zero = [r for r in all_results if r['bean'].get('k32_= k73_= 0') is True]
    print(f"\n  4. k[32]==k[73]:                      {len(k32_k73_eq)} pass")
    print(f"     k[32]==k[73]==0 (mod 26):          {len(k32_k73_zero)} pass")

    # Check 5: Best individual crib character matches
    max_crib = max(r['crib_matches'] for r in all_results)
    print(f"\n  5. Max individual crib matches:        {max_crib}/{N_CRIBS}")
    best_crib_results = [r for r in all_results if r['crib_matches'] >= max(max_crib - 2, 4)]
    if best_crib_results:
        best_crib_results.sort(key=lambda r: -r['crib_matches'])
        for r in best_crib_results[:10]:
            print(f"     {r['crib_matches']:2d}/{N_CRIBS}  {r['digit_mode']:30s} {r['cipher']:18s} {r['w_mode']}")

    # ====================================================================
    # Report: Top 10 by composite score
    # ====================================================================
    print(f"\n{'=' * 80}")
    print("TOP 10 BY COMPOSITE SCORE")
    print(f"{'=' * 80}")

    all_results.sort(key=lambda r: -r['composite'])

    hdr = (f"{'#':>3} {'Composite':>10} {'QG/ch':>7} {'Tri':>4} {'Crb':>4} "
           f"{'Bean27=65':>10} {'Digit Mode':>30s} {'Cipher':>18s} {'W-Mode':>25s}")
    print(f"\n{hdr}")
    print("-" * len(hdr))

    for rank, r in enumerate(all_results[:10], 1):
        bean_str = str(r['bean'].get('k27_eq_k65', 'N/A'))
        print(f"{rank:3d} {r['composite']:10.2f} {r['qg_score_pc']:7.3f} {r['trigram_count']:4d} "
              f"{r['crib_matches']:4d} {bean_str:>10s} {r['digit_mode']:>30s} "
              f"{r['cipher']:>18s} {r['w_mode']:>25s}")

    # Show plaintext for top 10
    print(f"\nPlaintexts for top 10:")
    for rank, r in enumerate(all_results[:10], 1):
        print(f"\n  #{rank} [{r['digit_mode']} / {r['cipher']} / {r['w_mode']}]")
        print(f"     Key: {r['key_str']}")
        print(f"     PT:  {r['plaintext']}")
        print(f"     QG/ch: {r['qg_score_pc']:.3f}  Trigrams: {r['trigram_count']}  "
              f"Crib matches: {r['crib_matches']}/{N_CRIBS}  Chi2: {r['chi2']:.1f}")

    # ====================================================================
    # Report: Top 10 by quadgram score per character
    # ====================================================================
    print(f"\n{'=' * 80}")
    print("TOP 10 BY QUADGRAM SCORE PER CHARACTER")
    print(f"{'=' * 80}")

    all_results.sort(key=lambda r: -r['qg_score_pc'])

    for rank, r in enumerate(all_results[:10], 1):
        bean_str = str(r['bean'].get('k27_eq_k65', 'N/A'))
        print(f"\n  #{rank}  QG/ch={r['qg_score_pc']:.4f}  Trigrams={r['trigram_count']}  "
              f"CribMatch={r['crib_matches']}/{N_CRIBS}  Chi2={r['chi2']:.1f}")
        print(f"       {r['digit_mode']} / {r['cipher']} / {r['w_mode']}")
        print(f"       Key: {r['key_str']}")
        print(f"       PT:  {r['plaintext']}")
        print(f"       Bean k27=k65: {bean_str}")

    # ====================================================================
    # Report: Top 10 by trigram count
    # ====================================================================
    print(f"\n{'=' * 80}")
    print("TOP 10 BY TRIGRAM COUNT")
    print(f"{'=' * 80}")

    all_results.sort(key=lambda r: (-r['trigram_count'], -r['qg_score_pc']))

    for rank, r in enumerate(all_results[:10], 1):
        print(f"  #{rank}  Tri={r['trigram_count']}  QG/ch={r['qg_score_pc']:.4f}  "
              f"Crb={r['crib_matches']}/{N_CRIBS}  "
              f"{r['digit_mode']} / {r['cipher']} / {r['w_mode']}")
        print(f"       PT: {r['plaintext']}")

    # ====================================================================
    # Report: Top 10 by crib matches
    # ====================================================================
    print(f"\n{'=' * 80}")
    print("TOP 10 BY CRIB CHARACTER MATCHES")
    print(f"{'=' * 80}")

    all_results.sort(key=lambda r: (-r['crib_matches'], -r['qg_score_pc']))

    for rank, r in enumerate(all_results[:10], 1):
        print(f"  #{rank}  CribMatch={r['crib_matches']}/{N_CRIBS}  QG/ch={r['qg_score_pc']:.4f}  "
              f"Tri={r['trigram_count']}  "
              f"{r['digit_mode']} / {r['cipher']} / {r['w_mode']}")
        print(f"       Key: {r['key_str']}")
        print(f"       PT:  {r['plaintext']}")
        # Show which crib positions match
        matches = []
        for pos in sorted(CRIB_DICT.keys()):
            if pos < len(r['plaintext']) and r['plaintext'][pos] == CRIB_DICT[pos]:
                matches.append(f"{pos}:{CRIB_DICT[pos]}")
        print(f"       Matching positions: {', '.join(matches)}")

    # ====================================================================
    # Report: Bean equality analysis
    # ====================================================================
    print(f"\n{'=' * 80}")
    print("BEAN EQUALITY ANALYSIS")
    print(f"{'=' * 80}")

    print(f"\nFor each digit key and cipher variant, the key values at positions 27 and 65")
    print(f"depend on the W-handling mode (since W at pos 20, 35, 46 affect key indexing).")
    print()

    # Show bean details for top results
    all_results.sort(key=lambda r: -r['composite'])
    for rank, r in enumerate(all_results[:15], 1):
        bean = r['bean']
        k27 = bean.get('k27', '?')
        k65 = bean.get('k65', '?')
        k32 = bean.get('k32', '?')
        k73 = bean.get('k73', '?')
        eq_27_65 = bean.get('k27_eq_k65', 'N/A')
        eq_32_73 = bean.get('k32_eq_k73', 'N/A')
        zero_32_73 = bean.get('k32_= k73_= 0', 'N/A')

        print(f"  #{rank:2d} k[27]={k27} k[65]={k65} eq={eq_27_65}  "
              f"k[32]={k32} k[73]={k73} eq={eq_32_73} zero={zero_32_73}  "
              f"{r['digit_mode']} / {r['cipher']} / {r['w_mode']}")

    # ====================================================================
    # Report: Summary Statistics
    # ====================================================================
    print(f"\n{'=' * 80}")
    print("SUMMARY STATISTICS ACROSS ALL COMBINATIONS")
    print(f"{'=' * 80}")

    qg_scores = [r['qg_score_pc'] for r in all_results]
    tri_scores = [r['trigram_count'] for r in all_results]
    crib_scores = [r['crib_matches'] for r in all_results]
    chi2_scores = [r['chi2'] for r in all_results]

    print(f"\n  Quadgram score/char:  min={min(qg_scores):.4f}  max={max(qg_scores):.4f}  "
          f"mean={sum(qg_scores)/len(qg_scores):.4f}")
    print(f"  Trigram count:        min={min(tri_scores)}  max={max(tri_scores)}  "
          f"mean={sum(tri_scores)/len(tri_scores):.1f}")
    print(f"  Crib matches:         min={min(crib_scores)}  max={max(crib_scores)}  "
          f"mean={sum(crib_scores)/len(crib_scores):.1f}")
    print(f"  Chi-squared:          min={min(chi2_scores):.1f}  max={max(chi2_scores):.1f}  "
          f"mean={sum(chi2_scores)/len(chi2_scores):.1f}")

    # English-like baseline for comparison
    print(f"\n  Reference quadgram score/char: English text ~ -2.0 to -2.5")
    print(f"  Reference quadgram score/char: Random text  ~ -4.5 to -5.0")
    print(f"  Reference chi-squared:         English ~ 20-40,  Random ~ 100-300")

    # ====================================================================
    # Full Detailed Table
    # ====================================================================
    print(f"\n{'=' * 80}")
    print("FULL RESULTS TABLE (ALL COMBINATIONS)")
    print(f"{'=' * 80}")

    all_results.sort(key=lambda r: -r['composite'])

    hdr = (f"{'#':>3} {'QG/ch':>7} {'Tri':>4} {'Crb':>4} {'Chi2':>7} "
           f"{'B27=65':>7} {'Digit Mode':>30s} {'Cipher':>18s} {'W-Mode':>25s}")
    print(f"\n{hdr}")
    print("-" * len(hdr))

    for rank, r in enumerate(all_results, 1):
        bean_str = "Y" if r['bean'].get('k27_eq_k65') is True else "N" if r['bean'].get('k27_eq_k65') is False else "-"
        print(f"{rank:3d} {r['qg_score_pc']:7.3f} {r['trigram_count']:4d} "
              f"{r['crib_matches']:4d} {r['chi2']:7.1f} "
              f"{bean_str:>7s} {r['digit_mode']:>30s} "
              f"{r['cipher']:>18s} {r['w_mode']:>25s}")

    # ====================================================================
    # Final Verdict
    # ====================================================================
    print(f"\n{'=' * 80}")
    print("FINAL VERDICT")
    print(f"{'=' * 80}")

    # Kill criterion 1: No exact crib at any position
    kill_exact_crib = len(exact_crib_hits) == 0 and len(alt_hits) == 0
    # Kill criterion 2: No crib substring found anywhere
    kill_any_crib = len(any_crib) == 0
    # Kill criterion 3: Best quadgram score still in random-text range
    best_qg = max(r['qg_score_pc'] for r in all_results)
    kill_qg = best_qg < -3.5  # well below English threshold
    # Kill criterion 4: Max crib matches close to random baseline
    # Random baseline: ~24 * (1/26) = ~0.92 matches expected
    kill_crib_count = max_crib <= 3  # only slightly above random expectation

    print(f"""
  Kill Criterion 1: Exact crib at canonical positions
    EASTNORTHEAST at 21-33 or BERLINCLOCK at 63-73: {'NO HITS' if kill_exact_crib else 'HIT FOUND'}
    {'KILLED' if kill_exact_crib else 'NOT KILLED'}

  Kill Criterion 2: Any crib substring found anywhere in plaintext
    EASTNORTHEAST, BERLINCLOCK, NORTHEAST, BERLIN, or CLOCK: {'NO HITS' if kill_any_crib else 'HIT FOUND'}
    {'KILLED' if kill_any_crib else 'NOT KILLED'}

  Kill Criterion 3: Best quadgram score indicates English
    Best QG/char: {best_qg:.4f}  (English ~ -2.5, Random ~ -4.5)
    {'KILLED (score in random range)' if kill_qg else 'NOT KILLED (score above random)'}

  Kill Criterion 4: Max individual crib character matches
    Best: {max_crib}/{N_CRIBS}  (random baseline ~ 1/{N_CRIBS})
    {'KILLED (near random baseline)' if kill_crib_count else 'NOT KILLED'}

  Bean Equality k[27]==k[65]:
    Passing combos: {len(bean_pass)} / {total_combos}
    Note: Since the digit key repeats cyclically, Bean equality depends
    on whether the key length divides (65-27)=38 or if W resets align.

  Bean k[32]==k[73]==0:
    Passing combos: {len(k32_k73_zero)} / {total_combos}
""")

    killed = sum([kill_exact_crib, kill_any_crib, kill_qg, kill_crib_count])

    if killed >= 3:
        verdict = "ELIMINATED"
        verdict_detail = "Multiple kill criteria triggered. The hypothesis is not supported."
    elif killed >= 2:
        verdict = "WEAK"
        verdict_detail = "Two kill criteria triggered. The hypothesis is unlikely."
    elif killed >= 1:
        verdict = "INCONCLUSIVE"
        verdict_detail = "One kill criterion triggered. Needs further investigation."
    else:
        verdict = "POSSIBLE"
        verdict_detail = "No kill criteria triggered. Warrants deeper analysis."

    print(f"  OVERALL VERDICT: {verdict}")
    print(f"  {verdict_detail}")
    print(f"  Kill criteria triggered: {killed}/4")

    elapsed = time.time() - t_start
    print(f"\n  Total runtime: {elapsed:.2f}s")
    print(f"  Combinations tested: {tested}")
    print("=" * 80)


if __name__ == '__main__':
    main()
