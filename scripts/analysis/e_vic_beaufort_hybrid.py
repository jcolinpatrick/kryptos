#!/usr/bin/env python3
"""
VIC Key Derivation + Beaufort Substitution Hybrid Model for K4.

Cipher:  VIC key derivation → Beaufort/Vigenere substitution (NOT straddling checkerboard)
Family:  analysis
Status:  active
Keyspace: ~7 phrases × 5 dates × 5 PNs × 5 keywords × 2 alphabets × multiple transpositions ≈ 500K+ configs
Last run: never
Best score: N/A

HYPOTHESIS: Scheidt taught Sanborn VIC as a framework. Sanborn used the key
derivation (phrase + date + personal number → chain addition → derived keys)
but substituted Beaufort encryption for the straddling checkerboard. The narrative
link is DEFECTOR = Häyhänen, the VIC cipher defector who was Scheidt's era.

WHAT IS NEW vs prior VIC work:
- e_full_vic_pipeline_k4.py tested full VIC with straddling checkerboard (1.3M configs). ELIMINATED.
- e_vic_model.py tested letter-level CB parsing + columnar (130.7M configs). ELIMINATED.
- e_vic_lineh_k2_direct.py tested K2 digits as direct Line-H with checkerboard. ELIMINATED.
- e_vic_ndyar_keygroup.py tested NDYAHR as VIC keygroup with checkerboard. ELIMINATED.
- ALL prior VIC work used the straddling checkerboard substitution component.

THIS SCRIPT replaces the checkerboard with Beaufort/Vigenere polyalphabetic substitution:
  Model A: VIC-derived transposition key (Line-Q) as columnar → then Beaufort keyword decrypt
  Model B: VIC 50-digit K-P block as Beaufort running key (digits → letters) + col7
  Model C: Line-S (10-digit permutation) as periodic Beaufort key + optional col7
  Model D: VIC transposition + consensus null mask + Beaufort keyword
  Model E: VIC chain addition extended to 97 digits as Beaufort running key
"""

import sys
import os
import json
import time
import math
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, CRIB_DICT, N_CRIBS

# ========================================================================
# VIC KEY GENERATION — copied from e_full_vic_pipeline_k4.py
# ========================================================================

def rank10(items, is_letters=False):
    """Rank 10 items VIC-style: returns list of digits 1-9 and 0 (where 0=10th rank)."""
    assert len(items) == 10, f"rank10 requires exactly 10 items, got {len(items)}"
    if is_letters:
        indexed = [(items[i], i) for i in range(10)]
    else:
        indexed = [(items[i] if items[i] != 0 else 10, i) for i in range(10)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    result = [0] * 10
    for rank_idx, (_, orig_pos) in enumerate(ranked):
        result[orig_pos] = (rank_idx + 1) % 10
    return result


def rank_n(items):
    """Rank N items: returns list of integers 0..N-1. 0 treated as 10 for ordering."""
    indexed = [(items[i] if items[i] != 0 else 10, i) for i in range(len(items))]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    result = [0] * len(items)
    for new_rank, (_, orig_pos) in enumerate(ranked):
        result[orig_pos] = new_rank
    return result


def mod10_subtract(a, b):
    return [(a[i] - b[i]) % 10 for i in range(len(a))]


def mod10_add(a, b):
    return [(a[i] + b[i]) % 10 for i in range(min(len(a), len(b)))]


def chain_add(digits, target_len):
    result = list(digits)
    while len(result) < target_len:
        new_digit = (result[-2] + result[-1]) % 10
        result.append(new_digit)
    return result[:target_len]


def generate_vic_keys(phrase, date_digits, personal_number):
    """Full VIC key generation from phrase + date + personal number."""
    if len(phrase) < 20:
        return None
    phrase = phrase.upper()[:20]

    line_d = phrase[:20]
    line_e1 = rank10(list(line_d[:10]), is_letters=True)
    line_e2 = rank10(list(line_d[10:20]), is_letters=True)
    line_b = list(date_digits[:5])

    return {
        'phrase': phrase,
        'date': date_digits,
        'personal_number': personal_number,
        'line_d': line_d,
        'line_e1': line_e1,
        'line_e2': line_e2,
        'line_b': line_b,
    }


def complete_vic_keys(base_keys, keygroup):
    """Complete VIC key generation with a specific keygroup. Returns dict or None."""
    line_a = list(keygroup)
    line_b = base_keys['line_b']
    line_e1 = base_keys['line_e1']
    line_e2 = base_keys['line_e2']
    pn = base_keys['personal_number']

    line_c = mod10_subtract(line_a, line_b)
    line_f1 = chain_add(line_c, 10)
    line_g = mod10_add(line_e1, line_f1)

    line_h = []
    for d in line_g:
        idx = (d - 1) % 10
        line_h.append(line_e2[idx])

    line_j = rank10(line_h, is_letters=False)

    chain_60 = chain_add(line_h, 60)
    line_k = chain_60[10:20]
    line_l = chain_60[20:30]
    line_m = chain_60[30:40]
    line_n = chain_60[40:50]
    line_p = chain_60[50:60]

    last_two_neq = []
    for d in reversed(line_p):
        if len(last_two_neq) == 0:
            last_two_neq.append(d)
        elif d != last_two_neq[0]:
            last_two_neq.insert(0, d)
            break
    if len(last_two_neq) < 2:
        last_two_neq = [line_p[-2], line_p[-1]]

    raw_a = last_two_neq[0] if last_two_neq[0] != 0 else 10
    raw_b = last_two_neq[1] if last_two_neq[1] != 0 else 10
    a = raw_a + pn
    b = raw_b + pn

    if a < 3 or a > 25 or b < 3 or b > 25:
        return None

    kp_block = [line_k, line_l, line_m, line_n, line_p]

    col_order = []
    for rank in range(1, 11):
        target = rank % 10
        for ci in range(10):
            if line_j[ci] == target:
                col_order.append(ci)
                break

    transposed = []
    for ci in col_order:
        for row in range(5):
            transposed.append(kp_block[row][ci])

    if a + b > len(transposed):
        return None

    line_q_raw = transposed[:a]
    line_r_raw = transposed[a:a + b]

    trans1_key = rank_n(line_q_raw)
    trans2_key = rank_n(line_r_raw)

    line_s = rank10(line_p, is_letters=False)

    return {
        'a': a, 'b': b,
        'trans1_key': trans1_key,
        'trans2_key': trans2_key,
        'line_q_raw': line_q_raw,
        'line_r_raw': line_r_raw,
        'line_s': line_s,
        'line_h': line_h,
        'line_j': line_j,
        'line_k': line_k,
        'line_l': line_l,
        'line_m': line_m,
        'line_n': line_n,
        'line_p': line_p,
        'kp_block_transposed': transposed,
        'keygroup': keygroup,
    }


# ========================================================================
# COLUMNAR TRANSPOSITION
# ========================================================================

def col_order_from_key(key):
    return sorted(range(len(key)), key=lambda c: key[c])


def columnar_decrypt(text, key):
    """Inverse columnar transposition."""
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)
    short_cols_count = nrows * width - n

    col_len = {}
    for c in range(width):
        if c < width - short_cols_count:
            col_len[c] = nrows
        else:
            col_len[c] = nrows - 1 if short_cols_count > 0 else nrows

    order = col_order_from_key(key)
    cols = {}
    idx = 0
    for c in order:
        cl = col_len[c]
        cols[c] = list(text[idx:idx + cl])
        idx += cl

    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(cols.get(c, [])):
                result.append(cols[c][r])

    return ''.join(result) if isinstance(text, str) else result


def keyword_to_col_key(keyword):
    """Convert a keyword string to a columnar transposition key (0-indexed ranks)."""
    indexed = [(ord(c), i) for i, c in enumerate(keyword.upper())]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    result = [0] * len(keyword)
    for new_rank, (_, orig_pos) in enumerate(ranked):
        result[orig_pos] = new_rank
    return result


# ========================================================================
# BEAUFORT / VIGENERE SUBSTITUTION (integer-level, using kernel conventions)
# ========================================================================

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
KA_CHR = {i: c for i, c in enumerate(KRYPTOS_ALPHABET)}


def beaufort_decrypt_az(ct_str, key_nums):
    """Beaufort decrypt on AZ alphabet: PT[i] = (KEY[i] - CT[i]) mod 26."""
    result = []
    klen = len(key_nums)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = key_nums[i % klen]
        pi = (ki - ci) % 26
        result.append(ALPH[pi])
    return ''.join(result)


def vigenere_decrypt_az(ct_str, key_nums):
    """Vigenere decrypt on AZ alphabet: PT[i] = (CT[i] - KEY[i]) mod 26."""
    result = []
    klen = len(key_nums)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = key_nums[i % klen]
        pi = (ci - ki) % 26
        result.append(ALPH[pi])
    return ''.join(result)


def varbeau_decrypt_az(ct_str, key_nums):
    """Variant Beaufort decrypt on AZ alphabet: PT[i] = (CT[i] + KEY[i]) mod 26."""
    result = []
    klen = len(key_nums)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = key_nums[i % klen]
        pi = (ci + ki) % 26
        result.append(ALPH[pi])
    return ''.join(result)


def beaufort_decrypt_ka(ct_str, key_nums):
    """Beaufort decrypt on KA alphabet: PT[i] = (KEY[i] - CT[i]) mod 26."""
    result = []
    klen = len(key_nums)
    for i, c in enumerate(ct_str):
        ci = KA_IDX[c]
        ki = key_nums[i % klen]
        pi = (ki - ci) % 26
        result.append(KA_CHR[pi])
    return ''.join(result)


def vigenere_decrypt_ka(ct_str, key_nums):
    """Vigenere decrypt on KA alphabet: PT[i] = (CT[i] - KEY[i]) mod 26."""
    result = []
    klen = len(key_nums)
    for i, c in enumerate(ct_str):
        ci = KA_IDX[c]
        ki = key_nums[i % klen]
        pi = (ci - ki) % 26
        result.append(KA_CHR[pi])
    return ''.join(result)


DECRYPT_FNS = {
    ('AZ', 'beau'): beaufort_decrypt_az,
    ('AZ', 'vig'): vigenere_decrypt_az,
    ('AZ', 'vbeau'): varbeau_decrypt_az,
    ('KA', 'beau'): beaufort_decrypt_ka,
    ('KA', 'vig'): vigenere_decrypt_ka,
}


def keyword_to_key_nums(keyword, alphabet='AZ'):
    """Convert keyword string to numeric key values."""
    if alphabet == 'KA':
        return [KA_IDX[c] for c in keyword.upper()]
    else:
        return [ALPH_IDX[c] for c in keyword.upper()]


# ========================================================================
# SCORING — fixed-position crib scoring (canonical)
# ========================================================================

def score_pt_cribs(pt):
    """Score plaintext against fixed-position cribs. Returns (total, ene_score, bc_score)."""
    ene_score = 0
    bc_score = 0
    if len(pt) >= 34:
        for i, ch in enumerate("EASTNORTHEAST"):
            pos = 21 + i
            if pos < len(pt) and pt[pos] == ch:
                ene_score += 1
    if len(pt) >= 74:
        for i, ch in enumerate("BERLINCLOCK"):
            pos = 63 + i
            if pos < len(pt) and pt[pos] == ch:
                bc_score += 1
    return ene_score + bc_score, ene_score, bc_score


def score_pt_free_cribs(pt):
    """Search for cribs anywhere in plaintext."""
    free = 0
    ene_pos = pt.find("EASTNORTHEAST")
    bc_pos = pt.find("BERLINCLOCK")
    if ene_pos >= 0:
        free += 13
    if bc_pos >= 0:
        free += 11
    return free, ene_pos, bc_pos


# ========================================================================
# CONSENSUS NULL MASK
# ========================================================================

CONSENSUS_NULLS = [0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 48, 52, 58, 59, 74, 75, 78, 84, 85, 87, 88, 93, 95, 96]


def apply_null_mask(text, null_positions):
    """Remove characters at null positions, returning the non-null characters."""
    return ''.join(c for i, c in enumerate(text) if i not in set(null_positions))


# ========================================================================
# TEST PARAMETERS
# ========================================================================

PHRASES = [
    ("KA_20", "KRYPTOSABCDEFGHIJLMN"),
    ("K1_20", "BETWEENSUBTLESHADING"),
    ("K2_20", "ITWASTOTALLYINVISIBL"),
    ("K3_20", "SLOWLYDESPARATLYSLOW"),
    ("PAK", "PALIMPSESTABSCISSAKR"),
    ("DAP", "DEFECTORABSCISSAPALI"),
    ("CRIBS", "EASTNORTHEASTBERLINC"),
]

DATES = [
    ("BerlinDDMMYY", [0, 9, 1, 1, 8, 9]),
    ("BerlinMMDDYY", [1, 1, 0, 9, 8, 9]),
    ("AbelDDMMYY", [1, 0, 0, 2, 6, 2]),
    ("K2_385765", [3, 8, 5, 7, 6, 5]),
    ("K2_770844", [7, 7, 0, 8, 4, 4]),
]

PNS = [5, 6, 7, 0, 4]

KEYGROUPS_FIXED = [
    [0, 0, 0, 0, 0],
    [1, 2, 3, 4, 5],
    [3, 8, 5, 7, 6],
    [7, 3, 2, 4, 1],
]

# Beaufort keywords for substitution layer
SUB_KEYWORDS = ["DEFECTOR", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "KOMPASS"]

# Col7 key from KRYPTOS (standard known col7 that lifts DEFECTOR:AZ_beau to 15/24)
COL7_KEY = keyword_to_col_key("KRYPTOS")  # [2, 5, 6, 4, 3, 0, 1]

# Digits → letters mappings
def digits_to_letters_az(digits):
    """0→A, 1→B, ..., 9→J"""
    return [d % 26 for d in digits]


def digits_to_letters_ka(digits):
    """0→K, 1→R, ..., 9→H (first 10 of KA)"""
    return [d % 26 for d in digits]


def digits_to_letters_shifted(digits, shift):
    """(digit + shift) mod 26"""
    return [(d + shift) % 26 for d in digits]


# ========================================================================
# MAIN EXPERIMENT
# ========================================================================

def run():
    t0 = time.time()
    print("=" * 72)
    print("VIC KEY DERIVATION + BEAUFORT SUBSTITUTION HYBRID MODEL")
    print("=" * 72)
    print(f"CT: {CT} ({CT_LEN} chars)")
    print(f"Params: {len(PHRASES)} phrases, {len(DATES)} dates, {len(PNS)} PNs")
    print(f"  {len(SUB_KEYWORDS)} keywords, {len(KEYGROUPS_FIXED)} keygroups")
    print()

    top_results = []  # (score, config_dict)
    total_configs = 0
    phase_stats = {}

    def record(phase, score, ene, bc, free_score, config_info, pt):
        nonlocal total_configs
        total_configs += 1
        entry = {
            'phase': phase,
            'score': score,
            'ene': ene,
            'bc': bc,
            'free': free_score,
            'pt': pt[:80],
            **config_info,
        }
        if score >= 6 or free_score >= 11:
            top_results.append(entry)
            top_results.sort(key=lambda x: (x['score'], x.get('free', 0)), reverse=True)
            while len(top_results) > 50:
                top_results.pop()

    # ── KEY GENERATION: pre-compute all valid VIC key sets ────────────────
    print("Pre-computing VIC key sets...")
    all_keysets = []
    keys_ok = 0
    keys_fail = 0
    for phrase_name, phrase in PHRASES:
        for date_name, date_digits in DATES:
            for pn in PNS:
                base = generate_vic_keys(phrase, date_digits, pn)
                if base is None:
                    keys_fail += 1
                    continue
                for kg in KEYGROUPS_FIXED:
                    keys = complete_vic_keys(base, kg)
                    if keys is None:
                        keys_fail += 1
                        continue
                    keys_ok += 1
                    all_keysets.append({
                        'keys': keys,
                        'phrase': phrase_name,
                        'date': date_name,
                        'pn': pn,
                        'kg': kg,
                    })
    print(f"  {keys_ok} valid key sets, {keys_fail} failed")
    print()

    # ══════════════════════════════════════════════════════════════════════
    # MODEL A: VIC-derived transposition + Beaufort keyword
    # Undo columnar trans (using Line-Q as column order) → Beaufort decrypt
    # ══════════════════════════════════════════════════════════════════════
    print("MODEL A: VIC transposition (Line-Q) + Beaufort keyword decrypt")
    p_t = time.time()
    p_n = 0
    max_a = 0

    for ks in all_keysets:
        keys = ks['keys']
        t1_key = keys['trans1_key']
        t2_key = keys['trans2_key']

        for trans_label, trans_key in [("Q", t1_key), ("R", t2_key)]:
            try:
                intermediate = columnar_decrypt(CT, trans_key)
            except Exception:
                p_n += 1
                continue

            for kw_name in SUB_KEYWORDS:
                for alph in ['AZ', 'KA']:
                    for var in ['beau', 'vig']:
                        fn_key = (alph, var)
                        if fn_key not in DECRYPT_FNS:
                            continue
                        decrypt_fn = DECRYPT_FNS[fn_key]
                        kw_nums = keyword_to_key_nums(kw_name, alph)
                        pt = decrypt_fn(intermediate, kw_nums)
                        score, ene, bc = score_pt_cribs(pt)
                        free, _, _ = score_pt_free_cribs(pt)
                        max_a = max(max_a, score)
                        record('A', score, ene, bc, free, {
                            'phrase': ks['phrase'], 'date': ks['date'],
                            'pn': ks['pn'], 'trans': trans_label,
                            'keyword': kw_name, 'alph': alph, 'var': var,
                            'trans_width': len(trans_key),
                        }, pt)
                        p_n += 1

    phase_stats['A'] = {'configs': p_n, 'time': time.time() - p_t, 'max': max_a}
    print(f"  {p_n:,} configs, max {max_a}/24, {time.time()-p_t:.1f}s")

    # ══════════════════════════════════════════════════════════════════════
    # MODEL B: VIC 50-digit K-P block as Beaufort running key + col7
    # Convert digits to letter values, use as running key for Beaufort
    # ══════════════════════════════════════════════════════════════════════
    print("\nMODEL B: VIC K-P 50-digit block as Beaufort running key + col7")
    p_t = time.time()
    p_n = 0
    max_b = 0

    for ks in all_keysets:
        keys = ks['keys']
        # The 50-digit K-P block
        kp_50 = keys['line_k'] + keys['line_l'] + keys['line_m'] + keys['line_n'] + keys['line_p']
        # Extend to 97 via chain addition
        kp_97 = chain_add(kp_50, 97)

        for shift_label, shift in [("d2l_AZ", 0), ("d2l_shift5", 5), ("d2l_shift13", 13)]:
            key_nums_97 = [(d + shift) % 26 for d in kp_97]
            key_nums_50 = [(d + shift) % 26 for d in kp_50]

            for var in ['beau', 'vig', 'vbeau']:
                for alph in ['AZ']:
                    fn_key = (alph, var)
                    if fn_key not in DECRYPT_FNS:
                        continue
                    decrypt_fn = DECRYPT_FNS[fn_key]

                    # Direct: 97-digit running key
                    pt = decrypt_fn(CT, key_nums_97)
                    score, ene, bc = score_pt_cribs(pt)
                    free, _, _ = score_pt_free_cribs(pt)
                    max_b = max(max_b, score)
                    record('B_direct', score, ene, bc, free, {
                        'phrase': ks['phrase'], 'date': ks['date'],
                        'pn': ks['pn'], 'shift': shift_label,
                        'var': var, 'key_src': 'kp97',
                    }, pt)
                    p_n += 1

                    # With col7: undo col7 first, then running key
                    try:
                        ct_uncol7 = columnar_decrypt(CT, COL7_KEY)
                        pt = decrypt_fn(ct_uncol7, key_nums_97)
                        score, ene, bc = score_pt_cribs(pt)
                        free, _, _ = score_pt_free_cribs(pt)
                        max_b = max(max_b, score)
                        record('B_col7', score, ene, bc, free, {
                            'phrase': ks['phrase'], 'date': ks['date'],
                            'pn': ks['pn'], 'shift': shift_label,
                            'var': var, 'key_src': 'kp97+col7',
                        }, pt)
                        p_n += 1
                    except Exception:
                        p_n += 1

                    # 50-char periodic: use K-P as period-50 key
                    pt = decrypt_fn(CT, key_nums_50)
                    score, ene, bc = score_pt_cribs(pt)
                    free, _, _ = score_pt_free_cribs(pt)
                    max_b = max(max_b, score)
                    record('B_p50', score, ene, bc, free, {
                        'phrase': ks['phrase'], 'date': ks['date'],
                        'pn': ks['pn'], 'shift': shift_label,
                        'var': var, 'key_src': 'kp50_periodic',
                    }, pt)
                    p_n += 1

    phase_stats['B'] = {'configs': p_n, 'time': time.time() - p_t, 'max': max_b}
    print(f"  {p_n:,} configs, max {max_b}/24, {time.time()-p_t:.1f}s")

    # ══════════════════════════════════════════════════════════════════════
    # MODEL C: Line-S as periodic Beaufort key (10-digit → 10-letter)
    # Also try Line-H, Line-J as period-10 keys
    # ══════════════════════════════════════════════════════════════════════
    print("\nMODEL C: VIC Line-S / Line-H / Line-J as periodic Beaufort key")
    p_t = time.time()
    p_n = 0
    max_c = 0

    for ks in all_keysets:
        keys = ks['keys']
        key_sources = {
            'S': keys['line_s'],
            'H': keys['line_h'],
            'J': keys['line_j'],
        }

        for src_name, src_digits in key_sources.items():
            for shift_label, shift in [("s0", 0), ("s5", 5), ("s13", 13)]:
                key_nums = [(d + shift) % 26 for d in src_digits]

                for var in ['beau', 'vig']:
                    for alph in ['AZ', 'KA']:
                        fn_key = (alph, var)
                        if fn_key not in DECRYPT_FNS:
                            continue
                        decrypt_fn = DECRYPT_FNS[fn_key]

                        # Direct periodic
                        pt = decrypt_fn(CT, key_nums)
                        score, ene, bc = score_pt_cribs(pt)
                        free, _, _ = score_pt_free_cribs(pt)
                        max_c = max(max_c, score)
                        record('C', score, ene, bc, free, {
                            'phrase': ks['phrase'], 'date': ks['date'],
                            'pn': ks['pn'], 'line': src_name,
                            'shift': shift_label, 'var': var, 'alph': alph,
                        }, pt)
                        p_n += 1

                        # With col7
                        try:
                            ct_uncol7 = columnar_decrypt(CT, COL7_KEY)
                            pt = decrypt_fn(ct_uncol7, key_nums)
                            score, ene, bc = score_pt_cribs(pt)
                            free, _, _ = score_pt_free_cribs(pt)
                            max_c = max(max_c, score)
                            record('C_col7', score, ene, bc, free, {
                                'phrase': ks['phrase'], 'date': ks['date'],
                                'pn': ks['pn'], 'line': src_name,
                                'shift': shift_label, 'var': var, 'alph': alph,
                                'trans': 'col7',
                            }, pt)
                            p_n += 1
                        except Exception:
                            p_n += 1

    phase_stats['C'] = {'configs': p_n, 'time': time.time() - p_t, 'max': max_c}
    print(f"  {p_n:,} configs, max {max_c}/24, {time.time()-p_t:.1f}s")

    # ══════════════════════════════════════════════════════════════════════
    # MODEL D: VIC transposition + null mask + Beaufort keyword
    # Undo VIC transposition → apply null mask → Beaufort with keyword
    # ══════════════════════════════════════════════════════════════════════
    print("\nMODEL D: VIC transposition + consensus null mask + Beaufort keyword")
    p_t = time.time()
    p_n = 0
    max_d = 0

    null_set = set(CONSENSUS_NULLS)

    for ks in all_keysets:
        keys = ks['keys']
        t1_key = keys['trans1_key']
        t2_key = keys['trans2_key']

        for trans_label, trans_key in [("Q", t1_key), ("R", t2_key), ("col7", COL7_KEY)]:
            try:
                intermediate = columnar_decrypt(CT, trans_key)
            except Exception:
                continue

            # Apply null mask
            extracted = apply_null_mask(intermediate, CONSENSUS_NULLS)
            if len(extracted) != 73:
                # Null mask applied to already-transposed text may not give 73
                # But since null positions are fixed at carved-text positions and
                # we're undoing transposition first, the positions shift.
                # For Model D, try both orderings:
                # (a) Undo trans → remove nulls
                # (b) Remove nulls → undo trans on 73 chars
                pass

            for kw_name in SUB_KEYWORDS:
                for alph in ['AZ', 'KA']:
                    for var in ['beau', 'vig']:
                        fn_key = (alph, var)
                        if fn_key not in DECRYPT_FNS:
                            continue
                        decrypt_fn = DECRYPT_FNS[fn_key]

                        # Approach (a): trans then mask then sub on full 97
                        # Apply sub to intermediate (97), then mask
                        kw_nums = keyword_to_key_nums(kw_name, alph)
                        pt_full = decrypt_fn(intermediate, kw_nums)
                        pt_masked = apply_null_mask(pt_full, CONSENSUS_NULLS)
                        # Score the 73-char result with free cribs
                        free, ene_pos, bc_pos = score_pt_free_cribs(pt_masked)
                        # Also check fixed positions on the full 97-char intermediate
                        score, ene, bc = score_pt_cribs(pt_full)
                        max_d = max(max_d, score, free)
                        record('D_trans_sub_mask', score, ene, bc, free, {
                            'phrase': ks['phrase'], 'date': ks['date'],
                            'pn': ks['pn'], 'trans': trans_label,
                            'keyword': kw_name, 'alph': alph, 'var': var,
                        }, pt_full)
                        p_n += 1

                        # Approach (b): mask first (on raw CT), then trans, then sub
                        ct_masked = apply_null_mask(CT, CONSENSUS_NULLS)
                        # Undo trans on 73 chars (need compatible key width)
                        if len(trans_key) <= len(ct_masked):
                            try:
                                ct_untrans = columnar_decrypt(ct_masked, trans_key)
                                pt = decrypt_fn(ct_untrans, kw_nums)
                                free2, _, _ = score_pt_free_cribs(pt)
                                max_d = max(max_d, free2)
                                record('D_mask_trans_sub', 0, 0, 0, free2, {
                                    'phrase': ks['phrase'], 'date': ks['date'],
                                    'pn': ks['pn'], 'trans': trans_label,
                                    'keyword': kw_name, 'alph': alph, 'var': var,
                                }, pt)
                                p_n += 1
                            except Exception:
                                p_n += 1

    phase_stats['D'] = {'configs': p_n, 'time': time.time() - p_t, 'max': max_d}
    print(f"  {p_n:,} configs, max {max_d}/24, {time.time()-p_t:.1f}s")

    # ══════════════════════════════════════════════════════════════════════
    # MODEL E: VIC chain addition extended to 97 as running key
    # Use Line-H (10 digits) → chain-add to 97 → use as Beaufort running key
    # ══════════════════════════════════════════════════════════════════════
    print("\nMODEL E: VIC chain addition from Line-H → 97-digit running key")
    p_t = time.time()
    p_n = 0
    max_e = 0

    for ks in all_keysets:
        keys = ks['keys']
        # Chain-add Line-H to 97 digits
        h_97 = chain_add(keys['line_h'], 97)

        for shift_label, shift in [("s0", 0), ("s5", 5), ("s13", 13)]:
            key_nums = [(d + shift) % 26 for d in h_97]

            for var in ['beau', 'vig', 'vbeau']:
                for alph in ['AZ']:
                    fn_key = (alph, var)
                    if fn_key not in DECRYPT_FNS:
                        continue
                    decrypt_fn = DECRYPT_FNS[fn_key]

                    # Direct running key
                    pt = decrypt_fn(CT, key_nums)
                    score, ene, bc = score_pt_cribs(pt)
                    free, _, _ = score_pt_free_cribs(pt)
                    max_e = max(max_e, score)
                    record('E_direct', score, ene, bc, free, {
                        'phrase': ks['phrase'], 'date': ks['date'],
                        'pn': ks['pn'], 'shift': shift_label, 'var': var,
                        'key_src': 'lineH_chain97',
                    }, pt)
                    p_n += 1

                    # With col7
                    try:
                        ct_uncol7 = columnar_decrypt(CT, COL7_KEY)
                        pt = decrypt_fn(ct_uncol7, key_nums)
                        score, ene, bc = score_pt_cribs(pt)
                        free, _, _ = score_pt_free_cribs(pt)
                        max_e = max(max_e, score)
                        record('E_col7', score, ene, bc, free, {
                            'phrase': ks['phrase'], 'date': ks['date'],
                            'pn': ks['pn'], 'shift': shift_label, 'var': var,
                            'key_src': 'lineH_chain97+col7',
                        }, pt)
                        p_n += 1
                    except Exception:
                        p_n += 1

                    # With null mask
                    pt_full = decrypt_fn(CT, key_nums)
                    pt_masked = apply_null_mask(pt_full, CONSENSUS_NULLS)
                    free2, _, _ = score_pt_free_cribs(pt_masked)
                    max_e = max(max_e, free2)
                    record('E_mask', 0, 0, 0, free2, {
                        'phrase': ks['phrase'], 'date': ks['date'],
                        'pn': ks['pn'], 'shift': shift_label, 'var': var,
                        'key_src': 'lineH_chain97+mask',
                    }, pt_masked)
                    p_n += 1

    phase_stats['E'] = {'configs': p_n, 'time': time.time() - p_t, 'max': max_e}
    print(f"  {p_n:,} configs, max {max_e}/24, {time.time()-p_t:.1f}s")

    # ══════════════════════════════════════════════════════════════════════
    # MODEL F: VIC transposition + Beaufort keyword + col7 (double trans)
    # Undo col7 → undo VIC trans → Beaufort keyword
    # ══════════════════════════════════════════════════════════════════════
    print("\nMODEL F: Double transposition (VIC + col7) + Beaufort keyword")
    p_t = time.time()
    p_n = 0
    max_f = 0

    for ks in all_keysets:
        keys = ks['keys']
        t1_key = keys['trans1_key']
        t2_key = keys['trans2_key']

        for trans_label, trans_key in [("Q", t1_key), ("R", t2_key)]:
            # Order 1: undo col7 first, then undo VIC trans
            try:
                step1 = columnar_decrypt(CT, COL7_KEY)
                step2 = columnar_decrypt(step1, trans_key)
            except Exception:
                continue

            for kw_name in SUB_KEYWORDS:
                for alph in ['AZ', 'KA']:
                    for var in ['beau', 'vig']:
                        fn_key = (alph, var)
                        if fn_key not in DECRYPT_FNS:
                            continue
                        decrypt_fn = DECRYPT_FNS[fn_key]
                        kw_nums = keyword_to_key_nums(kw_name, alph)

                        pt = decrypt_fn(step2, kw_nums)
                        score, ene, bc = score_pt_cribs(pt)
                        free, _, _ = score_pt_free_cribs(pt)
                        max_f = max(max_f, score)
                        record('F_col7_vic', score, ene, bc, free, {
                            'phrase': ks['phrase'], 'date': ks['date'],
                            'pn': ks['pn'], 'trans': trans_label,
                            'keyword': kw_name, 'alph': alph, 'var': var,
                            'order': 'col7_then_vic',
                        }, pt)
                        p_n += 1

            # Order 2: undo VIC trans first, then undo col7
            try:
                step1b = columnar_decrypt(CT, trans_key)
                step2b = columnar_decrypt(step1b, COL7_KEY)
            except Exception:
                continue

            for kw_name in SUB_KEYWORDS:
                for alph in ['AZ', 'KA']:
                    for var in ['beau', 'vig']:
                        fn_key = (alph, var)
                        if fn_key not in DECRYPT_FNS:
                            continue
                        decrypt_fn = DECRYPT_FNS[fn_key]
                        kw_nums = keyword_to_key_nums(kw_name, alph)

                        pt = decrypt_fn(step2b, kw_nums)
                        score, ene, bc = score_pt_cribs(pt)
                        free, _, _ = score_pt_free_cribs(pt)
                        max_f = max(max_f, score)
                        record('F_vic_col7', score, ene, bc, free, {
                            'phrase': ks['phrase'], 'date': ks['date'],
                            'pn': ks['pn'], 'trans': trans_label,
                            'keyword': kw_name, 'alph': alph, 'var': var,
                            'order': 'vic_then_col7',
                        }, pt)
                        p_n += 1

    phase_stats['F'] = {'configs': p_n, 'time': time.time() - p_t, 'max': max_f}
    print(f"  {p_n:,} configs, max {max_f}/24, {time.time()-p_t:.1f}s")

    # ══════════════════════════════════════════════════════════════════════
    # MODEL G: VIC-derived key as AUTOKEY primer + Beaufort
    # Line-H chain-added to primer length, use as Beaufort autokey
    # ══════════════════════════════════════════════════════════════════════
    print("\nMODEL G: VIC-derived autokey primer + Beaufort/Vigenere")
    p_t = time.time()
    p_n = 0
    max_g = 0

    def autokey_decrypt_beau(ct_str, primer_nums):
        """Beaufort PT-autokey decrypt: key[0..p-1] = primer, key[p+i] = PT[i]."""
        result = []
        key = list(primer_nums)
        for i, c in enumerate(ct_str):
            ci = ALPH_IDX[c]
            ki = key[i]
            pi = (ki - ci) % 26
            result.append(ALPH[pi])
            key.append(pi)
        return ''.join(result)

    def autokey_decrypt_vig(ct_str, primer_nums):
        """Vigenere PT-autokey decrypt: key[0..p-1] = primer, key[p+i] = PT[i]."""
        result = []
        key = list(primer_nums)
        for i, c in enumerate(ct_str):
            ci = ALPH_IDX[c]
            ki = key[i]
            pi = (ci - ki) % 26
            result.append(ALPH[pi])
            key.append(pi)
        return ''.join(result)

    def autokey_decrypt_ct_beau(ct_str, primer_nums):
        """Beaufort CT-autokey decrypt: key[0..p-1] = primer, key[p+i] = CT[i]."""
        result = []
        key = list(primer_nums)
        for i, c in enumerate(ct_str):
            ci = ALPH_IDX[c]
            ki = key[i]
            pi = (ki - ci) % 26
            result.append(ALPH[pi])
            key.append(ci)
        return ''.join(result)

    def autokey_decrypt_ct_vig(ct_str, primer_nums):
        """Vigenere CT-autokey decrypt: key[0..p-1] = primer, key[p+i] = CT[i]."""
        result = []
        key = list(primer_nums)
        for i, c in enumerate(ct_str):
            ci = ALPH_IDX[c]
            ki = key[i]
            pi = (ci - ki) % 26
            result.append(ALPH[pi])
            key.append(ci)
        return ''.join(result)

    autokey_fns = {
        'pt_beau': autokey_decrypt_beau,
        'pt_vig': autokey_decrypt_vig,
        'ct_beau': autokey_decrypt_ct_beau,
        'ct_vig': autokey_decrypt_ct_vig,
    }

    for ks in all_keysets:
        keys = ks['keys']
        # Use Line-H (10 digits) and Line-S (10 digits) as primers
        # Also use Line-Q and Line-R directly
        primer_sources = {
            'H': keys['line_h'],
            'S': keys['line_s'],
            'Q': keys['line_q_raw'],
            'R': keys['line_r_raw'],
        }

        for src_name, src_digits in primer_sources.items():
            # Convert digits to letter values
            primer_nums = [d % 26 for d in src_digits]

            for ak_name, ak_fn in autokey_fns.items():
                # Direct on CT97
                pt = ak_fn(CT, primer_nums)
                score, ene, bc = score_pt_cribs(pt)
                free, _, _ = score_pt_free_cribs(pt)
                max_g = max(max_g, score)
                record('G', score, ene, bc, free, {
                    'phrase': ks['phrase'], 'date': ks['date'],
                    'pn': ks['pn'], 'primer_src': src_name,
                    'autokey': ak_name, 'primer_len': len(src_digits),
                }, pt)
                p_n += 1

                # With col7
                try:
                    ct_uncol7 = columnar_decrypt(CT, COL7_KEY)
                    pt = ak_fn(ct_uncol7, primer_nums)
                    score, ene, bc = score_pt_cribs(pt)
                    free, _, _ = score_pt_free_cribs(pt)
                    max_g = max(max_g, score)
                    record('G_col7', score, ene, bc, free, {
                        'phrase': ks['phrase'], 'date': ks['date'],
                        'pn': ks['pn'], 'primer_src': src_name,
                        'autokey': ak_name, 'primer_len': len(src_digits),
                        'trans': 'col7',
                    }, pt)
                    p_n += 1
                except Exception:
                    p_n += 1

    phase_stats['G'] = {'configs': p_n, 'time': time.time() - p_t, 'max': max_g}
    print(f"  {p_n:,} configs, max {max_g}/24, {time.time()-p_t:.1f}s")

    # ══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════
    total_time = time.time() - t0

    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configs: {total_configs:,}")
    for phase, stats in sorted(phase_stats.items()):
        print(f"  Model {phase}: {stats['configs']:,} configs, max {stats['max']}/24, {stats['time']:.1f}s")
    print(f"Total elapsed: {total_time:.1f}s")

    global_max = max(stats['max'] for stats in phase_stats.values())
    print(f"\nGLOBAL MAX SCORE: {global_max}/24")

    # Print top results
    above_noise = [r for r in top_results if r['score'] >= 6 or r.get('free', 0) >= 11]
    print(f"\nResults >= 6/24 fixed or >= 11 free: {len(above_noise)}")
    for i, r in enumerate(above_noise[:30]):
        print(f"  {i+1:3d}. {r['phase']:15s} fixed={r['score']:2d}/24 "
              f"(e={r['ene']},b={r['bc']}) free={r.get('free',0):2d} | "
              f"kw={r.get('keyword',''):<12s} {r.get('alph',''):<3s} {r.get('var',''):<6s} "
              f"p={r.get('phrase',''):<8s} d={r.get('date',''):<14s} "
              f"| PT: {r['pt'][:40]}")

    if global_max >= 18:
        verdict = "SIGNAL"
    elif global_max >= 10:
        verdict = "INTERESTING"
    elif global_max >= 6:
        verdict = "WEAK"
    else:
        verdict = "NOISE"

    print(f"\nVERDICT: {verdict}")

    # Save results
    out_path = Path(__file__).resolve().parents[2] / "results" / "vic_beaufort_hybrid.json"
    os.makedirs(out_path.parent, exist_ok=True)
    output = {
        'experiment': 'e_vic_beaufort_hybrid',
        'description': 'VIC key derivation + Beaufort/Vigenere substitution hybrid (no checkerboard)',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'keys_valid': keys_ok,
        'keys_failed': keys_fail,
        'elapsed_seconds': round(total_time, 1),
        'phases': {k: {'configs': v['configs'], 'time': round(v['time'], 1), 'max': v['max']}
                   for k, v in phase_stats.items()},
        'global_max': global_max,
        'verdict': verdict,
        'top_results': above_noise[:50],
        'elimination': (
            f"VIC key derivation + Beaufort/Vig hybrid ({total_configs:,} configs): "
            f"{len(PHRASES)} phrases x {len(DATES)} dates x {len(PNS)} PNs x "
            f"{len(SUB_KEYWORDS)} keywords. 7 models (A-G). "
            f"Max fixed={global_max}/24. VERDICT: {verdict}."
        ),
    }
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    run()
