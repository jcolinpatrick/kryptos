#!/usr/bin/env python3
"""
Cipher: Vigenere overlay (two-layer)
Family: polyalphabetic
Status: active
Keyspace: Vigenere keys length 4-7 on positions 0-63
Last run: 2026-04-11
Best score: pending
"""
"""E-K4-VIG-OVERLAY: Two-Layer Encryption Hypothesis Test

HYPOTHESIS: K4 uses two layers:
  1. A base cipher applied to the full 97-char ciphertext
  2. A short Vigenere overlay applied ONLY to positions 0-63 (pre-ENE segment)

That is, what we observe at positions 0-63 is:
    CT_obs[i] = Vigenere_encrypt(CT_base[i], key[i % L])
  where CT_base[i] is the output of the base cipher.

Positions 64-96 (ENE segment proper through end) are UNMODIFIED by the overlay.

KNOWN CONSTRAINTS:
  - Bean equality: CT_obs[27] = CT_obs[65] = 'P'
    - Position 65 is outside the overlay window (positions 0-63).
    - Position 27 IS inside the overlay window.
    - Bean equality requires CT_base[27] = CT_base[65] = 'P'
    - CT_obs[27] = 'P' (observed), so Vigenere_enc('P', key[27 % L]) = 'P'
    - => key[27 % L] = 0 (zero shift = 'A', no shift)
    - This FIXES one key position for every key length L.

  - EASTNORTHEAST crib: positions 21-33 (within overlay window)
  - BERLINCLOCK crib: positions 63-73 (straddles boundary)
    - Pos 63 is last byte of overlay, pos 64-73 unmodified

KILL CRITERIA:
  Kill 1: Bean constraint — key[27%L]=0 required. Trivially satisfiable by construction.
  Kill 2: No Vigenere key of length 4-7 equalizes IC(pre_decrypted) ~ IC(post).
           Criterion: min |IC_diff| > equalization tolerance.
  Kill 3: No base cipher recovery of intermediate text yields cribs.

IC EQUALIZATION LOGIC:
  If the overlay hides extra structure from the pre-ENE, removing it should bring
  IC(decrypted_pre) closer to IC(post). Tolerance: |IC_pre_dec - IC_post| < 0.005

NOTE ON KEY COUNT SCALE: The equalization tolerance is loose relative to the
  IC difference (pre - post = 0.006). Expect O(10^4 - 10^5) keys to "pass" at
  each length. Section 5 caps recovery at the TOP 20 best-equalizing keys.
"""

import os
import sys
import time
import math
import heapq
import itertools
from collections import Counter
from typing import List, Tuple, Optional, Dict, Any

# Add the source tree to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    IC_ENGLISH, IC_RANDOM,
    CRIB_DICT,
)

# ── Constants ─────────────────────────────────────────────────────────────────

K4 = CT  # 97-char K4 ciphertext

# Overlay applies to [0, OVERLAY_END), post-ENE is [OVERLAY_END, 97)
OVERLAY_END = 64   # exclusive, so positions 0..63

PRE_ENE  = K4[:OVERLAY_END]          # 64 chars under overlay
POST_ENE = K4[OVERLAY_END:]          # 33 chars, untouched

# Bean equality positions
BEAN_EQ_POS_INNER = 27   # inside overlay
BEAN_EQ_POS_OUTER = 65   # outside overlay

assert K4[BEAN_EQ_POS_INNER] == 'P', f"K4[27] should be P, got {K4[BEAN_EQ_POS_INNER]}"
assert K4[BEAN_EQ_POS_OUTER] == 'P', f"K4[65] should be P, got {K4[BEAN_EQ_POS_OUTER]}"

EQUALIZATION_TOL = 0.005

# How many top keys to retain per search phase (memory control)
TOP_K = 20

# English letter frequencies for chi-squared scoring
ENGLISH_FREQ = {
    'A': 0.0817, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}


# ── Core functions ─────────────────────────────────────────────────────────────

def compute_ic(text: str) -> float:
    """Compute Index of Coincidence."""
    n = len(text)
    if n <= 1:
        return 0.0
    counts = Counter(text.upper())
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))


def vigenere_decrypt_partial(text: str, key: List[int]) -> str:
    """Decrypt text using Vigenere: P = (C - K) mod 26, key repeating."""
    L = len(key)
    result = []
    for i, c in enumerate(text):
        c_val = ord(c) - 65
        p_val = (c_val - key[i % L]) % MOD
        result.append(chr(p_val + 65))
    return ''.join(result)


def chi_squared_english(text: str) -> float:
    """Chi-squared statistic against English letter frequencies (lower = more English-like)."""
    n = len(text)
    if n == 0:
        return float('inf')
    counts = Counter(text.upper())
    chi2 = 0.0
    for c in ALPH:
        expected = ENGLISH_FREQ[c] * n
        observed = counts.get(c, 0)
        chi2 += (observed - expected) ** 2 / expected
    return chi2


def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypt text with a Caesar shift."""
    return ''.join(ALPH[(ord(c) - 65 - shift) % MOD] for c in text.upper())


def try_columnar_transposition(text: str, width: int) -> List[str]:
    """Try all column orderings of columnar transposition (read by rows, write by cols)."""
    n = len(text)
    nrows = math.ceil(n / width)

    # Fill grid row by row
    grid = []
    idx = 0
    for r in range(nrows):
        row = []
        for c in range(width):
            if idx < n:
                row.append(text[idx])
                idx += 1
            else:
                row.append(None)
        grid.append(row)

    results = []
    if width <= 8:
        for col_order in itertools.permutations(range(width)):
            out = []
            for col in col_order:
                for row in range(nrows):
                    if grid[row][col] is not None:
                        out.append(grid[row][col])
            results.append(''.join(out))
    return results


def check_crib(text: str, crib: str) -> List[int]:
    """Find all start positions where crib appears as substring in text."""
    positions = []
    crib = crib.upper()
    text = text.upper()
    for i in range(len(text) - len(crib) + 1):
        if text[i:i + len(crib)] == crib:
            positions.append(i)
    return positions


def count_crib_matches_at_known(text: str) -> int:
    """Count how many known crib positions in the text match the expected plaintext."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            matches += 1
    return matches


def try_base_cipher_recovery(pre_dec: str) -> List[str]:
    """Given a decrypted pre-ENE segment, try to recover the base cipher.

    Returns a list of hit descriptions (empty if nothing found).
    """
    intermediate = pre_dec + POST_ENE  # 97 chars
    CRIBS = ["BERLINCLOCK", "EASTNORTHEAST", "NORTHEAST", "BERLIN", "CLOCK"]

    results = []

    # (a) Direct crib substring search
    for crib in CRIBS:
        pos = check_crib(intermediate, crib)
        if pos:
            results.append(f"DIRECT: '{crib}' at pos {pos}")

    # (b) All 26 Caesar shifts on intermediate
    for shift in range(26):
        shifted = caesar_decrypt(intermediate, shift)
        for crib in CRIBS:
            pos = check_crib(shifted, crib)
            if pos:
                results.append(f"Caesar(shift={shift},'{ALPH[shift]}'): '{crib}' at {pos}")
        n_match = count_crib_matches_at_known(shifted)
        if n_match >= 8:
            results.append(f"Caesar(shift={shift}): {n_match}/24 known crib position matches")

    # (c) Reverse reading + Caesar
    rev = intermediate[::-1]
    for crib in CRIBS:
        pos = check_crib(rev, crib)
        if pos:
            results.append(f"REVERSE: '{crib}' at pos {pos}")
    for shift in range(26):
        shifted_rev = caesar_decrypt(rev, shift)
        for crib in ["BERLINCLOCK", "EASTNORTHEAST"]:
            pos = check_crib(shifted_rev, crib)
            if pos:
                results.append(f"Reverse+Caesar({shift}): '{crib}' at {pos}")

    # (d) Simple columnar transposition (widths 2-8)
    for width in range(2, 9):
        try:
            variants = try_columnar_transposition(intermediate, width)
            for variant in variants:
                for crib in ["BERLINCLOCK", "EASTNORTHEAST"]:
                    pos = check_crib(variant, crib)
                    if pos:
                        results.append(
                            f"Columnar(w={width}): '{crib}' at {pos} -> {variant[:40]}..."
                        )
        except Exception:
            pass

    return results


# ── Section 1: Baseline ICs ───────────────────────────────────────────────────

def section_1_baseline_ics() -> Dict[str, Any]:
    print("\n" + "=" * 70)
    print("SECTION 1: BASELINE INDEX OF COINCIDENCE ANALYSIS")
    print("=" * 70)

    ic_full = compute_ic(K4)
    ic_pre  = compute_ic(PRE_ENE)
    ic_post = compute_ic(POST_ENE)

    print(f"\n  K4 ciphertext: {K4}")
    print(f"  Length: {len(K4)} chars")
    print(f"  Overlay window (pre-ENE): positions 0-{OVERLAY_END-1} ({OVERLAY_END} chars)")
    print(f"                            {PRE_ENE}")
    print(f"  Post-ENE:                 positions {OVERLAY_END}-96 ({97 - OVERLAY_END} chars)")
    print(f"                            {POST_ENE}")

    print(f"\n  IC(full K4):  {ic_full:.6f}  [random=0.0385, English=0.0667]")
    print(f"  IC(pre-ENE):  {ic_pre:.6f}")
    print(f"  IC(post-ENE): {ic_post:.6f}")
    print(f"  IC diff (pre - post): {ic_pre - ic_post:+.6f}")

    if ic_pre > ic_post:
        print(f"\n  Pre-ENE IC IS HIGHER than post-ENE by {ic_pre - ic_post:.6f}")
        if ic_pre - ic_post > EQUALIZATION_TOL:
            print(f"  Exceeds equalization tolerance ({EQUALIZATION_TOL}): hypothesis has IC motivation.")
            ic_anomaly = True
        else:
            print(f"  Difference ({ic_pre - ic_post:.6f}) < tolerance ({EQUALIZATION_TOL}): marginal.")
            ic_anomaly = False
    else:
        print(f"\n  Pre-ENE IC is NOT higher than post-ENE. Hypothesis lacks IC motivation.")
        ic_anomaly = False

    print(f"\n  Bean equality: K4[{BEAN_EQ_POS_INNER}]={K4[BEAN_EQ_POS_INNER]!r} "
          f"== K4[{BEAN_EQ_POS_OUTER}]={K4[BEAN_EQ_POS_OUTER]!r}: "
          f"{'PASS' if K4[BEAN_EQ_POS_INNER] == K4[BEAN_EQ_POS_OUTER] else 'FAIL'}")

    chi2_pre  = chi_squared_english(PRE_ENE)
    chi2_post = chi_squared_english(POST_ENE)
    print(f"\n  Chi-squared vs English: pre-ENE={chi2_pre:.2f}, post-ENE={chi2_post:.2f}")
    print(f"  (Lower chi2 = more English-like distribution. Both segments are far from English.)")

    # Frequency table for pre-ENE
    pre_counts = Counter(PRE_ENE)
    print(f"\n  Pre-ENE letter counts (sorted):")
    row = "  " + " ".join(f"{c}:{pre_counts.get(c,0):2d}" for c in ALPH)
    print(row)

    return {
        'ic_full': ic_full,
        'ic_pre': ic_pre,
        'ic_post': ic_post,
        'pre_higher': ic_pre > ic_post,
        'ic_anomaly': ic_anomaly,
        'ic_diff': ic_pre - ic_post,
        'chi2_pre': chi2_pre,
        'chi2_post': chi2_post,
    }


# ── Section 2: Bean Constraint Analysis ───────────────────────────────────────

def section_2_bean_constraint() -> Dict[str, Any]:
    print("\n" + "=" * 70)
    print("SECTION 2: BEAN CONSTRAINT ANALYSIS")
    print("=" * 70)

    print(f"\n  Bean equality: K4[27] = K4[65] = 'P'")
    print(f"\n  Under the overlay hypothesis:")
    print(f"    - Position 65 is OUTSIDE the overlay (pos >= {OVERLAY_END}).")
    print(f"      So CT_base[65] = K4[65] = 'P' (unchanged by overlay).")
    print(f"    - Position 27 IS inside the overlay.")
    print(f"      CT_obs[27] = Vig_enc(CT_base[27], key[27 % L])")
    print(f"    - Bean equality requires CT_base[27] = CT_base[65] = 'P'")
    print(f"    - We observe CT_obs[27] = 'P', so:")
    print(f"        Vig_enc('P', key[27%L]) = 'P'")
    print(f"        (ord('P')-65 + key[27%L]) mod 26 = ord('P')-65")
    print(f"        key[27%L] = 0  (i.e., 'A' shift, no shift at all)")

    print(f"\n  CONSEQUENCE: For any Vigenere key of length L, key[27 mod L] MUST = 0.")
    print(f"  This FIXES exactly one byte of the key per key length.")

    print(f"\n  Per key length:")
    for L in range(4, 8):
        fixed_pos = 27 % L
        free = [i for i in range(L) if i != fixed_pos]
        n_keys = 26 ** len(free)
        print(f"    L={L}: key[{fixed_pos}]=0 fixed.  Free positions={free}.  Keyspace=26^{len(free)}={n_keys:,}")

    print(f"\n  NOTE: Position 27 is NOT shifted by the overlay at all.")
    print(f"  This means K4[27]='P' is already the base-cipher value at pos 27,")
    print(f"  consistent with K4[65]='P'. The Bean constraint is trivially satisfiable.")

    # Additional: check what ENE/BC crib constraints say about the base cipher
    print(f"\n  ENE crib (positions 21-33) is WITHIN the overlay window.")
    print(f"  If the overlay has key K, then CT_base[21:34] = Vig_dec(K4[21:34], K).")
    print(f"  The base cipher must then map CT_base[21:34] -> EASTNORTHEAST.")
    print(f"\n  BERLINCLOCK crib (positions 63-73): pos 63 is the last overlay char,")
    print(f"  positions 64-73 are OUTSIDE the overlay (unmodified).")
    print(f"  If base cipher maps CT_base[63:74] -> BERLINCLOCK, then:")
    print(f"    - CT_base[63] = Vig_dec(K4[63], key[63%L])")
    print(f"    - CT_base[64..73] = K4[64..73] (unchanged)")
    print(f"    - This means K4[64..73] = BERLINCLOCK[1..10] = ERLINCLOCK")

    # Check if K4[64:74] matches ERLINCLOCK
    k4_64_74 = K4[64:74]
    expected = "ERLINCLOCK"
    print(f"\n  Check K4[64:74]: {k4_64_74}")
    print(f"  Expected (ERLINCLOCK): {expected}")
    print(f"  Match: {k4_64_74 == expected} (This would be required if BERLINCLOCK is a direct crib)")
    print(f"  [Note: K4[64:74]='YPVTTMZFPK', NOT 'ERLINCLOCK'.]")
    print(f"  => This means BERLINCLOCK at pos 63-73 is NOT a direct plaintext crib at the overlay level.")
    print(f"  => It is a crib for the BASE cipher, applied BEFORE the overlay.")

    return {
        'fixed_key_positions': {L: 27 % L for L in range(4, 8)},
        'keyspace_per_length': {L: 26 ** (L - 1) for L in range(4, 8)},
        'k4_64_74': k4_64_74,
    }


# ── Section 3: Exhaustive Search (lengths 4-5) ────────────────────────────────

def section_3_exhaustive_search(ic_post: float) -> Dict[int, Dict]:
    print("\n" + "=" * 70)
    print("SECTION 3: EXHAUSTIVE VIGENERE KEY SEARCH (lengths 4-5)")
    print("=" * 70)
    print(f"\n  Target: find keys where |IC(Vig_dec(pre, key)) - IC(post)| < {EQUALIZATION_TOL}")
    print(f"  IC(post) = {ic_post:.6f}")
    print(f"  Bean constraint: key[27%L] = 0 (fixed)")

    results_per_length = {}

    for key_len in [4, 5]:
        t0 = time.time()
        fixed_pos = 27 % key_len
        free_positions = [i for i in range(key_len) if i != fixed_pos]
        n_free = len(free_positions)
        n_keys = 26 ** n_free

        print(f"\n  Key length {key_len}: fixed key[{fixed_pos}]=0, free={free_positions}, {n_keys:,} keys")

        # Use a min-heap to track only top TOP_K keys (by smallest ic_diff)
        # heap entries: (ic_diff, key_str, ic_pre_dec, pre_dec_string)
        # We negate for max-heap: use positive ic_diff and keep the top-K smallest
        # Use a bounded list: if heap has TOP_K items and new ic_diff < max, replace
        TOP_HEAP = []  # (ic_diff, counter, key_list, ic_pre_dec, pre_dec)
        max_in_heap = float('inf')
        n_pass = 0
        n_checked = 0
        counter = 0

        for free_vals in itertools.product(range(26), repeat=n_free):
            key = [0] * key_len
            for idx, pos in enumerate(free_positions):
                key[pos] = free_vals[idx]

            n_checked += 1

            pre_dec = vigenere_decrypt_partial(PRE_ENE, key)
            ic_pre_dec = compute_ic(pre_dec)
            ic_diff = abs(ic_pre_dec - ic_post)

            if ic_diff < EQUALIZATION_TOL:
                n_pass += 1

            # Maintain TOP_K by smallest ic_diff using a max-heap (negate to get min behavior)
            if len(TOP_HEAP) < TOP_K:
                heapq.heappush(TOP_HEAP, (-ic_diff, counter, key[:], ic_pre_dec, pre_dec))
                max_in_heap = -TOP_HEAP[0][0]
                counter += 1
            elif ic_diff < max_in_heap:
                heapq.heapreplace(TOP_HEAP, (-ic_diff, counter, key[:], ic_pre_dec, pre_dec))
                max_in_heap = -TOP_HEAP[0][0]
                counter += 1

        elapsed = time.time() - t0

        # Extract and sort top keys
        top_keys = sorted(TOP_HEAP, key=lambda x: -x[0])  # smallest ic_diff first
        top_keys = [(abs(x[0]), x[2], x[3], x[4]) for x in top_keys]

        print(f"  Keys checked: {n_checked:,}")
        print(f"  Keys passing IC equalization (tol={EQUALIZATION_TOL}): {n_pass:,}")
        print(f"  Search time: {elapsed:.2f}s")

        print(f"\n  Top 5 keys by smallest |IC_pre_dec - IC_post|:")
        hdr = f"  {'Rank':>4}  {'Key':>12}  {'IC_pre_dec':>10}  {'IC_post':>8}  {'|diff|':>8}  {'Pass':>5}"
        sep = f"  {'----':>4}  {'---':>12}  {'----------':>10}  {'-------':>8}  {'------':>8}  {'----':>5}"
        print(hdr)
        print(sep)
        for rank, (ic_diff, key, ic_pre_dec, pre_dec) in enumerate(top_keys[:5], 1):
            key_str = ''.join(ALPH[k] for k in key)
            pass_str = "YES" if ic_diff < EQUALIZATION_TOL else "no"
            print(f"  {rank:4d}  {key_str:>12}  {ic_pre_dec:10.6f}  {ic_post:8.6f}  "
                  f"{ic_diff:8.6f}  {pass_str:>5}")

        results_per_length[key_len] = {
            'n_checked': n_checked,
            'n_pass': n_pass,
            'top_keys': top_keys,  # List of (ic_diff, key_list, ic_pre_dec, pre_dec_str)
        }

    return results_per_length


# ── Section 4: Heuristic Search (lengths 6-7) ─────────────────────────────────

def section_4_heuristic_search(ic_post: float) -> Dict[int, Dict]:
    print("\n" + "=" * 70)
    print("SECTION 4: HEURISTIC VIGENERE KEY SEARCH (lengths 6-7)")
    print("=" * 70)
    print(f"\n  Full search impractical (26^5 - 26^6 keys).")
    print(f"  Method: chi-squared frequency analysis to pick top 5 shifts per column,")
    print(f"  then evaluate all combinations of those top shifts.")

    results_per_length = {}

    for key_len in [6, 7]:
        t0 = time.time()
        fixed_pos = 27 % key_len
        free_positions = [i for i in range(key_len) if i != fixed_pos]

        print(f"\n  Key length {key_len}: fixed key[{fixed_pos}]=0, free={free_positions}")
        full_keyspace = 26 ** len(free_positions)
        print(f"  Full keyspace: 26^{len(free_positions)} = {full_keyspace:,} keys")

        # For each column, find best chi-squared shifts
        top_n = 5
        per_column_scores: Dict[int, List[Tuple[float, int]]] = {}
        for col in range(key_len):
            col_chars = ''.join(PRE_ENE[i] for i in range(col, len(PRE_ENE), key_len))
            col_results = []
            for shift in range(26):
                if col == fixed_pos and shift != 0:
                    continue  # Bean constraint enforced
                dec = caesar_decrypt(col_chars, shift)
                chi2 = chi_squared_english(dec)
                col_results.append((chi2, shift))
            col_results.sort()
            per_column_scores[col] = col_results[:top_n]

        print(f"\n  Top {top_n} chi-squared shifts per column (col, chars, best shifts):")
        for col in range(key_len):
            col_chars = ''.join(PRE_ENE[i] for i in range(col, len(PRE_ENE), key_len))
            best_str = ', '.join(f"{ALPH[sh]}(chi2={chi2:.1f})" for chi2, sh in per_column_scores[col][:3])
            print(f"    col={col}: chars={col_chars[:12]!r:>14}  top_shifts: {best_str}")

        # Evaluate all combinations
        candidate_keys = []
        col_shift_lists = [per_column_scores[c] for c in range(key_len)]
        for combo in itertools.product(*col_shift_lists):
            key = [sh for _, sh in combo]
            pre_dec = vigenere_decrypt_partial(PRE_ENE, key)
            ic_pre_dec = compute_ic(pre_dec)
            ic_diff = abs(ic_pre_dec - ic_post)
            candidate_keys.append((ic_diff, key[:], ic_pre_dec, pre_dec))

        candidate_keys.sort(key=lambda x: x[0])
        n_pass = sum(1 for k in candidate_keys if k[0] < EQUALIZATION_TOL)
        elapsed = time.time() - t0

        n_combos = 1
        for col in range(key_len):
            n_combos *= len(per_column_scores[col])

        print(f"\n  Heuristic combinations evaluated: {n_combos:,}")
        print(f"  Keys passing IC equalization: {n_pass:,}")
        print(f"  Search time: {elapsed:.2f}s")
        print(f"  Coverage: {n_combos/full_keyspace*100:.4f}% of full keyspace")

        print(f"\n  Top 5 candidates by |IC_pre_dec - IC_post|:")
        hdr = f"  {'Rank':>4}  {'Key':>14}  {'IC_pre_dec':>10}  {'IC_post':>8}  {'|diff|':>8}  {'Pass':>5}"
        sep = f"  {'----':>4}  {'---':>14}  {'----------':>10}  {'-------':>8}  {'------':>8}  {'----':>5}"
        print(hdr)
        print(sep)
        for rank, (ic_diff, key, ic_pre_dec, pre_dec) in enumerate(candidate_keys[:5], 1):
            key_str = ''.join(ALPH[k] for k in key)
            pass_str = "YES" if ic_diff < EQUALIZATION_TOL else "no"
            print(f"  {rank:4d}  {key_str:>14}  {ic_pre_dec:10.6f}  {ic_post:8.6f}  "
                  f"{ic_diff:8.6f}  {pass_str:>5}")

        results_per_length[key_len] = {
            'n_candidates': n_combos,
            'n_pass': n_pass,
            'top_keys': candidate_keys[:TOP_K],
        }

    return results_per_length


# ── Section 5: Base Cipher Recovery ────────────────────────────────────────────

def section_5_base_cipher_recovery(
    exhaustive_results: Dict[int, Dict],
    heuristic_results: Dict[int, Dict],
) -> Dict[str, Any]:
    print("\n" + "=" * 70)
    print("SECTION 5: BASE CIPHER RECOVERY ATTEMPTS")
    print("=" * 70)
    print(f"\n  NOTE: Equalization tolerance {EQUALIZATION_TOL} is loose relative to IC diff")
    print(f"  of 0.006. Hundreds of thousands of keys 'pass'. We analyze the TOP {TOP_K}.")

    # Collect top keys from all lengths (only keep best per length)
    all_top: List[Tuple] = []
    total_pass_all = 0

    all_results = {**exhaustive_results, **heuristic_results}
    for key_len, data in all_results.items():
        n_pass = data['n_pass']
        total_pass_all += n_pass
        for entry in data['top_keys']:
            ic_diff, key_list, ic_pre_dec, pre_dec = entry
            all_top.append((ic_diff, key_len, key_list, ic_pre_dec, pre_dec))

    all_top.sort(key=lambda x: x[0])
    top_n = all_top[:TOP_K]

    print(f"\n  Total passing keys (all lengths): {total_pass_all:,}")
    print(f"  Analyzing top {len(top_n)} keys (lowest IC equalization error):")

    recovery_results = []
    any_hits = False
    max_crib_matches = 0

    # Header for compact table
    print(f"\n  {'#':>3}  {'Key':>10}  {'L':>2}  {'IC_diff':>8}  {'Crb':>3}  Hits")
    print(f"  {'--':>3}  {'---':>10}  {'-':>2}  {'-------':>8}  {'---':>3}  ----")

    for rank, (ic_diff, key_len, key_list, ic_pre_dec, pre_dec) in enumerate(top_n, 1):
        key_str = ''.join(ALPH[k] for k in key_list)
        intermediate = pre_dec + POST_ENE

        hits = try_base_cipher_recovery(pre_dec)
        n_match = count_crib_matches_at_known(intermediate)
        max_crib_matches = max(max_crib_matches, n_match)

        if hits:
            any_hits = True
            print(f"\n  *** KEY #{rank} {key_str} (L={key_len}, IC_diff={ic_diff:.6f}) HAS HITS ***")
            print(f"  Intermediate: {intermediate}")
            for h in hits:
                print(f"    -> {h}")
            print(f"  Crib position matches: {n_match}/24")
        else:
            print(f"  {rank:3d}  {key_str:>10}  {key_len:2d}  {ic_diff:8.6f}  "
                  f"{n_match:3d}  no_hits  inter={intermediate[:30]}...")

        recovery_results.append({
            'rank': rank,
            'key': key_str,
            'key_len': key_len,
            'ic_diff': ic_diff,
            'intermediate': intermediate,
            'crib_matches': n_match,
            'has_hits': bool(hits),
            'hits': hits,
        })

    if not any_hits:
        print(f"\n  No crib hits found in any of the top {len(top_n)} keys.")
        print(f"  Maximum crib position matches seen: {max_crib_matches}/24")

    return {
        'recovery_results': recovery_results,
        'any_hits': any_hits,
        'total_pass_all': total_pass_all,
        'max_crib_matches': max_crib_matches,
    }


# ── Section 5b: Best-Key-Per-Length Recovery (regardless of IC equalization) ──

def section_5b_best_key_recovery(all_results: Dict[int, Dict]) -> Dict[int, Dict]:
    print("\n--- Sub-section 5b: Best key per length (even if IC_diff > tolerance) ---")

    best_per_length = {}
    for key_len in sorted(all_results.keys()):
        data = all_results[key_len]
        if not data['top_keys']:
            continue
        ic_diff, key_list, ic_pre_dec, pre_dec = data['top_keys'][0]
        key_str = ''.join(ALPH[k] for k in key_list)
        intermediate = pre_dec + POST_ENE
        hits = try_base_cipher_recovery(pre_dec)
        n_match = count_crib_matches_at_known(intermediate)

        print(f"\n  L={key_len}: best key={key_str}  IC_diff={ic_diff:.6f}  crb_match={n_match}/24")
        print(f"  Intermediate: {intermediate}")
        if hits:
            print(f"  *** HITS: ***")
            for h in hits:
                print(f"    -> {h}")
        else:
            print(f"  No crib hits.")

        best_per_length[key_len] = {
            'key': key_str,
            'ic_diff': ic_diff,
            'intermediate': intermediate,
            'hits': hits,
            'crib_matches': n_match,
        }

    return best_per_length


# ── Section 6: Kill Criteria Evaluation ────────────────────────────────────────

def section_6_kill_criteria(
    baseline: Dict[str, Any],
    exhaustive_results: Dict[int, Dict],
    heuristic_results: Dict[int, Dict],
    recovery: Dict[str, Any],
) -> Dict[str, Any]:
    print("\n" + "=" * 70)
    print("SECTION 6: KILL CRITERIA EVALUATION")
    print("=" * 70)

    all_results = {**exhaustive_results, **heuristic_results}
    total_pass = sum(d['n_pass'] for d in all_results.values())

    # Kill criterion 1: Bean constraint (always satisfiable by construction)
    print("\n  Kill Criterion 1: Bean equality — key[27%L]=0 required.")
    print("  This is AUTOMATICALLY satisfied by construction (we fix key[27%L]=0).")
    print("  No additional Bean constraint is imposed by the single equality at positions 27,65.")
    kill1 = False
    print(f"  Kill 1 Status: NOT KILLED (trivially satisfiable, {26**3:,} to {26**6:,} valid keys per length)")

    # Kill criterion 2: IC equalization
    print(f"\n  Kill Criterion 2: IC equalization within tolerance {EQUALIZATION_TOL}.")
    min_diff_per_len = {}
    for L, data in all_results.items():
        if data['top_keys']:
            min_diff_per_len[L] = data['top_keys'][0][0]
        else:
            min_diff_per_len[L] = float('inf')

    print(f"\n  IC(post-ENE) target = {baseline['ic_post']:.6f}")
    print(f"  IC(pre-ENE) baseline = {baseline['ic_pre']:.6f}")
    print(f"  Raw IC gap to close: {baseline['ic_diff']:+.6f}")
    print(f"\n  Minimum IC difference achieved per key length:")
    for L in sorted(min_diff_per_len):
        diff = min_diff_per_len[L]
        pct = diff / EQUALIZATION_TOL * 100
        print(f"    L={L}: min|IC_diff| = {diff:.6f}  ({pct:.1f}% of tolerance)  "
              f"{'PASS' if diff < EQUALIZATION_TOL else 'FAIL'}")

    global_min_diff = min(min_diff_per_len.values()) if min_diff_per_len else float('inf')

    if total_pass > 0:
        kill2 = False
        print(f"\n  {total_pass:,} keys achieve equalization. Kill 2 Status: NOT KILLED")
        print(f"  NOTE: This many keys passing suggests the tolerance is too loose to be")
        print(f"  discriminating. The IC test alone cannot validate the hypothesis.")
    else:
        kill2 = True
        print(f"\n  Global minimum IC diff = {global_min_diff:.6f} > {EQUALIZATION_TOL}")
        print(f"  Kill 2 Status: KILLED — No key achieves IC equalization within tolerance.")

    # Kill criterion 3: Crib recovery
    print("\n  Kill Criterion 3: Base cipher recovery yields crib hits.")
    any_hits = recovery['any_hits']
    max_crb = recovery['max_crib_matches']

    print(f"  Crib hits found: {'YES' if any_hits else 'NO'}")
    print(f"  Max crib position matches in any intermediate text: {max_crb}/24")

    if any_hits:
        kill3 = False
        print(f"  Kill 3 Status: NOT KILLED — crib hits found!")
    else:
        kill3 = True
        print(f"  Kill 3 Status: KILLED — no base cipher yields crib hits.")
        print(f"  (Best result: {max_crb}/24 known crib position matches, random baseline ~2-3/24)")

    # IC anomaly assessment
    print(f"\n  Pre-ENE IC anomaly check:")
    ic_anomaly = baseline['ic_anomaly']
    if ic_anomaly:
        print(f"  IC(pre)={baseline['ic_pre']:.6f} > IC(post)={baseline['ic_post']:.6f}, diff={baseline['ic_diff']:.6f}")
        print(f"  Pre-ENE IS higher than post-ENE and exceeds tolerance. IC motivation EXISTS.")
    else:
        if baseline['pre_higher']:
            print(f"  IC(pre)={baseline['ic_pre']:.6f} > IC(post)={baseline['ic_post']:.6f}, diff={baseline['ic_diff']:.6f}")
            print(f"  Diff < tolerance ({EQUALIZATION_TOL}). Marginal IC motivation.")
        else:
            print(f"  IC(pre)={baseline['ic_pre']:.6f} <= IC(post)={baseline['ic_post']:.6f}")
            print(f"  NO IC motivation for the hypothesis.")

    # Verdict
    print("\n" + "=" * 70)
    print("FINAL VERDICT")
    print("=" * 70)

    if kill2 and kill3:
        verdict = "ELIMINATED"
        print(f"\n  VERDICT: {verdict}")
        print(f"  Kill 2 (IC equalization) and Kill 3 (crib recovery) both FAILED.")
        print(f"  The hypothesis is not supported.")
    elif kill2:
        verdict = "KILLED_IC"
        print(f"\n  VERDICT: {verdict}")
        print(f"  IC equalization failed. Hypothesis is not supported by IC analysis.")
    elif kill3:
        verdict = "WEAK"
        print(f"\n  VERDICT: {verdict}")
        print(f"  IC equalization achieved by many keys (tolerance too loose), but")
        print(f"  no base cipher recovery yields crib hits. Hypothesis is not supported.")
        print(f"  The IC equalization is not discriminating with this tolerance.")
    else:
        verdict = "POSSIBLE"
        print(f"\n  VERDICT: {verdict}")
        print(f"  Both IC equalization and crib hits found. Warrants further investigation!")

    return {
        'kill1': kill1,
        'kill2': kill2,
        'kill3': kill3,
        'ic_anomaly': ic_anomaly,
        'verdict': verdict,
        'total_passing_keys': total_pass,
        'global_min_diff': global_min_diff,
        'max_crib_matches': max_crb,
    }


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    t_start = time.time()

    print("=" * 70)
    print("E-K4-VIG-OVERLAY: Two-Layer Encryption Hypothesis Test")
    print("=" * 70)
    print(f"\n  K4 ({len(K4)} chars): {K4}")
    print(f"  Overlay window:  positions 0-{OVERLAY_END-1} ({OVERLAY_END} chars)")
    print(f"  Post-ENE:        positions {OVERLAY_END}-96 ({97 - OVERLAY_END} chars)")
    print(f"  Bean equality:   K4[{BEAN_EQ_POS_INNER}]={K4[BEAN_EQ_POS_INNER]!r} == "
          f"K4[{BEAN_EQ_POS_OUTER}]={K4[BEAN_EQ_POS_OUTER]!r}")

    # Section 1: Baseline ICs
    baseline = section_1_baseline_ics()
    ic_post = baseline['ic_post']

    # Section 2: Bean constraint analysis
    section_2_bean_constraint()

    # Section 3: Exhaustive search (lengths 4-5)
    exhaustive_results = section_3_exhaustive_search(ic_post)

    # Section 4: Heuristic search (lengths 6-7)
    heuristic_results = section_4_heuristic_search(ic_post)

    # Section 5: Base cipher recovery on top passing keys
    recovery = section_5_base_cipher_recovery(exhaustive_results, heuristic_results)

    # Section 5b: Best key per length
    all_results = {**exhaustive_results, **heuristic_results}
    section_5b_best_key_recovery(all_results)

    # Section 6: Kill criteria
    kill_results = section_6_kill_criteria(baseline, exhaustive_results, heuristic_results, recovery)

    # Final summary table
    elapsed = time.time() - t_start
    print("\n" + "=" * 70)
    print("SUMMARY TABLE")
    print("=" * 70)

    def row(label, value):
        print(f"  {label:<50} {str(value):>18}")

    row("IC(full K4)", f"{baseline['ic_full']:.6f}")
    row("IC(pre-ENE, positions 0-63)", f"{baseline['ic_pre']:.6f}")
    row("IC(post-ENE, positions 64-96)", f"{baseline['ic_post']:.6f}")
    row("IC difference (pre - post)", f"{baseline['ic_diff']:+.6f}")
    row("Pre-ENE IC anomalously high? (diff > tol)", "YES" if baseline['ic_anomaly'] else "NO")
    row("Chi2-English pre-ENE (lower=better)", f"{baseline['chi2_pre']:.2f}")
    row("Chi2-English post-ENE (lower=better)", f"{baseline['chi2_post']:.2f}")
    print()
    n_checked = sum(d.get('n_checked', d.get('n_candidates', 0)) for d in all_results.values())
    row("Total keys evaluated (exhaustive+heuristic)", f"{n_checked:,}")
    row("Total keys passing IC equalization", f"{kill_results['total_passing_keys']:,}")
    row("Global minimum |IC_diff| achieved", f"{kill_results['global_min_diff']:.6f}")
    row("Equalization tolerance", f"{EQUALIZATION_TOL:.4f}")
    row("Max crib position matches (raw)", f"{kill_results['max_crib_matches']}/24")
    print()
    row("Kill 1 (Bean constraint)", "KILLED" if kill_results['kill1'] else "NOT KILLED")
    row("Kill 2 (IC equalization)", "KILLED" if kill_results['kill2'] else "NOT KILLED")
    row("Kill 3 (Crib recovery)", "KILLED" if kill_results['kill3'] else "NOT KILLED")
    print()
    print(f"  {'VERDICT':<50} {kill_results['verdict']:>18}")
    print(f"\n  Total runtime: {elapsed:.1f}s")
    print("=" * 70)


if __name__ == '__main__':
    main()
