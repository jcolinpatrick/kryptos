#!/usr/bin/env python3
"""
# Cipher: Period-6/Width-6 comprehensive attack on CT73
# Family: campaigns
# Status: active
# Keyspace: ~310M+ (exhaustive crib-constrained + col6 perms + autokey + SA)
# Last run: never
# Best score: n/a

Period-6 / Width-6 comprehensive attack on null-extracted CT73.

Two independent statistical tests point to period/width 6:
  - Autocorrelation lag-6: z=2.951 (p=0.011)
  - Column IC anomaly at width-6: p=0.032 (max col IC=0.1212)

Attack 1: Exhaustive crib-constrained period-6 consistency (6 variants x 2 alphabets)
Attack 2: Width-6 columnar transposition (720 perms) + period-N sub
Attack 3: Width-6 columnar + autokey (autokey proof may not apply here)
Attack 4: Quagmire II with period-6 keys
Attack 5: SA joint optimization (mask + col6 ordering + key)
"""

import sys
import os
import json
import time
import itertools
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, KEY_RECOVERY, DECRYPT_FN, decrypt_text
)
from kryptos.kernel.transforms.transposition import columnar_perm, invert_perm, apply_perm
from kryptos.kernel.transforms.autokey import autokey_decrypt


# ============================================================
# Setup: Extract CT73 from consensus mask
# ============================================================

CT97 = CT
MASK_24 = [0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 39, 40, 52, 55, 58, 59, 74, 75, 78, 84, 85, 88, 94, 96]
MASK_SET = set(MASK_24)

# Extract CT73
ct73_chars = []
ct73_to_ct97 = {}  # ct73 index -> ct97 index
for i in range(97):
    if i not in MASK_SET:
        ct73_to_ct97[len(ct73_chars)] = i
        ct73_chars.append(CT97[i])
CT73 = ''.join(ct73_chars)
assert len(CT73) == 73, f"CT73 length = {len(CT73)}, expected 73"

# Shifted crib positions in CT73 space
# Original: ENE at 21-33, BCL at 63-73 in CT97
# After null removal, map to CT73 positions
ENE_CT97 = list(range(21, 34))  # 13 chars
BCL_CT97 = list(range(63, 74))  # 11 chars
ENE_TEXT = "EASTNORTHEAST"
BCL_TEXT = "BERLINCLOCK"

# Map CT97 positions to CT73 positions
ct97_to_ct73 = {}
for ct73_idx, ct97_idx in ct73_to_ct97.items():
    ct97_to_ct73[ct97_idx] = ct73_idx

ENE_CT73 = [ct97_to_ct73[p] for p in ENE_CT97 if p in ct97_to_ct73]
BCL_CT73 = [ct97_to_ct73[p] for p in BCL_CT97 if p in ct97_to_ct73]

assert len(ENE_CT73) == 13, f"ENE positions in CT73: {len(ENE_CT73)}"
assert len(BCL_CT73) == 11, f"BCL positions in CT73: {len(BCL_CT73)}"

# Build crib dict in CT73 space
CRIB_CT73 = {}
for i, pos in enumerate(ENE_CT73):
    CRIB_CT73[pos] = ENE_TEXT[i]
for i, pos in enumerate(BCL_CT73):
    CRIB_CT73[pos] = BCL_TEXT[i]

assert len(CRIB_CT73) == 24

print(f"CT73 = {CT73}")
print(f"CT73 length = {len(CT73)}")
print(f"ENE in CT73: positions {ENE_CT73}")
print(f"BCL in CT73: positions {BCL_CT73}")
print()

# Build KA index tables
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


def score_crib_consistency(ct_text, crib_dict, period, variant, use_ka=False):
    """Check period-P consistency at crib positions.

    For each residue class mod P, all crib positions in that class
    must produce the same key value. Count how many crib positions
    are consistent.

    Returns (score, key_values, conflicts_per_residue)
    """
    recover = KEY_RECOVERY[variant]

    # Group crib positions by residue mod period
    residues = defaultdict(list)
    for pos, pt_ch in crib_dict.items():
        residues[pos % period].append((pos, pt_ch))

    total_consistent = 0
    key_values = {}
    conflicts = {}

    for r, positions in residues.items():
        # Recover key at each position
        keys_at_r = []
        for pos, pt_ch in positions:
            if use_ka:
                c_val = KA_IDX[ct_text[pos]]
                p_val = KA_IDX[pt_ch]
            else:
                c_val = ord(ct_text[pos]) - 65
                p_val = ord(pt_ch) - 65
            k = recover(c_val, p_val)
            keys_at_r.append((pos, k))

        # Find most common key value
        key_counts = defaultdict(int)
        for _, k in keys_at_r:
            key_counts[k] += 1

        best_k = max(key_counts, key=key_counts.get)
        n_consistent = key_counts[best_k]
        total_consistent += n_consistent
        key_values[r] = best_k
        conflicts[r] = len(keys_at_r) - n_consistent

    return total_consistent, key_values, conflicts


def full_key_from_cribs(ct_text, crib_dict, period, variant, use_ka=False):
    """Extract the full period-P key from crib positions.

    Returns (key_list, score, conflict_count) where key_list has P entries.
    """
    recover = KEY_RECOVERY[variant]

    residues = defaultdict(list)
    for pos, pt_ch in crib_dict.items():
        residues[pos % period].append((pos, pt_ch))

    key = [None] * period
    total_consistent = 0
    total_conflicts = 0

    for r in range(period):
        if r not in residues:
            # No crib constraint on this residue
            key[r] = 0  # placeholder
            continue

        positions = residues[r]
        keys_at_r = []
        for pos, pt_ch in positions:
            if use_ka:
                c_val = KA_IDX[ct_text[pos]]
                p_val = KA_IDX[pt_ch]
            else:
                c_val = ord(ct_text[pos]) - 65
                p_val = ord(pt_ch) - 65
            k = recover(c_val, p_val)
            keys_at_r.append(k)

        key_counts = defaultdict(int)
        for k in keys_at_r:
            key_counts[k] += 1

        best_k = max(key_counts, key=key_counts.get)
        key[r] = best_k
        total_consistent += key_counts[best_k]
        total_conflicts += len(keys_at_r) - key_counts[best_k]

    return key, total_consistent, total_conflicts


# ============================================================
# ATTACK 1: Period-6 direct on CT73 (crib-constrained)
# ============================================================

def attack1_period6_direct():
    """Exhaustive period-6 crib consistency check on CT73."""
    print("=" * 70)
    print("ATTACK 1: Period-6 crib-constrained consistency on CT73")
    print("=" * 70)

    results = []

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
    alphabets = [("AZ", False), ("KA", True)]

    for var in variants:
        for alph_name, use_ka in alphabets:
            score, key_vals, conflicts = score_crib_consistency(
                CT73, CRIB_CT73, 6, var, use_ka
            )

            key, _, total_conflicts = full_key_from_cribs(
                CT73, CRIB_CT73, 6, var, use_ka
            )

            # Decrypt with derived key
            if use_ka:
                # For KA, decrypt manually
                fn = DECRYPT_FN[var]
                pt = []
                for i, c in enumerate(CT73):
                    c_val = KA_IDX[c]
                    k_val = key[i % 6]
                    p_val = fn(c_val, k_val)
                    pt.append(KA[p_val])
                pt = ''.join(pt)
            else:
                pt = decrypt_text(CT73, key, var)

            result = {
                'variant': var.value,
                'alphabet': alph_name,
                'score': score,
                'total_conflicts': total_conflicts,
                'key': key,
                'key_letters': ''.join(chr(k + 65) for k in key),
                'conflicts_per_residue': {r: conflicts[r] for r in sorted(conflicts)},
                'plaintext': pt[:60],
            }
            results.append(result)

            status = "*** ZERO CONFLICTS ***" if total_conflicts == 0 else f"{total_conflicts} conflicts"
            print(f"  {var.value:15s} {alph_name}: score={score}/24, {status}, key={result['key_letters']}")
            if score >= 20:
                print(f"    *** HIGH SCORE: PT = {pt}")

            if total_conflicts == 0:
                print(f"    !!! PERFECT CONSISTENCY - POTENTIAL SOLUTION !!!")
                print(f"    Key: {key} = {result['key_letters']}")
                print(f"    PT:  {pt}")

    # Also test periods 2,3,12 (divisors of 6 and multiples)
    for period in [2, 3, 12]:
        for var in variants:
            for alph_name, use_ka in alphabets:
                score, _, conflicts = score_crib_consistency(
                    CT73, CRIB_CT73, period, var, use_ka
                )
                total_c = sum(conflicts.values())
                if score >= 18 or total_c == 0:
                    print(f"  [p={period}] {var.value:15s} {alph_name}: score={score}/24, conflicts={total_c}")

    print()
    return results


# ============================================================
# ATTACK 2: Width-6 columnar + period-N substitution
# ============================================================

def apply_columnar_inverse(text, width, col_order):
    """Apply INVERSE columnar transposition (undo the columnar reading).

    Columnar encrypt: fill by rows, read by columns.
    To undo: we have text that was read by columns,
    and we need to reconstruct the rows.
    """
    n = len(text)
    nrows = (n + width - 1) // width
    ncomplete = n - (nrows - 1) * width  # number of columns with nrows entries

    # Build column lengths
    col_lengths = []
    for rank in range(width):
        # Which column has this rank?
        col_idx = list(col_order).index(rank)
        if col_idx < ncomplete:
            col_lengths.append(nrows)
        else:
            col_lengths.append(nrows - 1)

    # Split text into columns (by rank order)
    columns_by_rank = {}
    pos = 0
    for rank in range(width):
        length = col_lengths[rank]
        columns_by_rank[rank] = text[pos:pos + length]
        pos += length

    # Reconstruct: map rank -> original column index
    columns_by_idx = {}
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        columns_by_idx[col_idx] = columns_by_rank[rank]

    # Read by rows
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(columns_by_idx[col]):
                result.append(columns_by_idx[col][row])

    return ''.join(result)


def map_cribs_through_transposition(crib_dict, width, col_order, text_len):
    """Map crib positions through inverse columnar transposition.

    If the model is: PT -> sub -> CT_intermediate -> columnar trans -> CT73
    Then to undo: CT73 -> inverse trans -> CT_intermediate -> sub^-1 -> PT

    We need to know where cribs land in CT_intermediate space.
    """
    perm = columnar_perm(width, col_order, text_len)
    inv = invert_perm(perm)

    # crib position p in CT73 -> maps to inv[p] in CT_intermediate
    mapped_cribs = {}
    for pos, ch in crib_dict.items():
        if pos < text_len:
            mapped_cribs[inv[pos]] = ch

    return mapped_cribs


def attack2_col6_sub(perm_tuple):
    """Test one col6 permutation with various substitutions.
    Returns list of (score, description, detail) tuples.
    """
    col_order = list(perm_tuple)
    results = []

    # Undo columnar transposition
    ct_intermediate = apply_columnar_inverse(CT73, 6, col_order)

    # Map cribs through the transposition
    mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, col_order, 73)

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    # Test various periods
    for period in [6, 7, 8, 10, 13]:
        for var in variants:
            for alph_name, use_ka in [("AZ", False), ("KA", True)]:
                score, key_vals, conflicts = score_crib_consistency(
                    ct_intermediate, mapped_cribs, period, var, use_ka
                )
                total_c = sum(conflicts.values())

                if score >= 12 or total_c == 0:
                    key, _, _ = full_key_from_cribs(
                        ct_intermediate, mapped_cribs, period, var, use_ka
                    )
                    results.append((
                        score,
                        f"col6_perm={perm_tuple}:{var.value}:{alph_name}:p{period}",
                        {
                            'perm': perm_tuple,
                            'variant': var.value,
                            'alphabet': alph_name,
                            'period': period,
                            'score': score,
                            'conflicts': total_c,
                            'key': key,
                        }
                    ))

    return results


def attack2_width6_columnar():
    """Width-6 columnar transposition + period-N substitution."""
    print("=" * 70)
    print("ATTACK 2: Width-6 columnar (720 perms) + period-N substitution")
    print("=" * 70)

    all_perms = list(itertools.permutations(range(6)))
    all_results = []

    with ProcessPoolExecutor(max_workers=28) as executor:
        futures = {executor.submit(attack2_col6_sub, p): p for p in all_perms}
        done = 0
        for future in as_completed(futures):
            done += 1
            try:
                results = future.result()
                all_results.extend(results)
            except Exception as e:
                print(f"  Error: {e}")
            if done % 100 == 0:
                print(f"  Progress: {done}/720 permutations done")

    # Sort by score
    all_results.sort(key=lambda x: x[0], reverse=True)

    print(f"\n  Total results >= 12: {len(all_results)}")
    for score, desc, detail in all_results[:20]:
        print(f"  Score {score}/24: {desc}")

    if all_results and all_results[0][0] == 24:
        print("\n  !!! BREAKTHROUGH - 24/24 FOUND !!!")

    print()
    return all_results[:50]


# ============================================================
# ATTACK 3: Width-6 columnar + autokey
# ============================================================

def check_autokey_feasibility(ct_text, crib_dict, primer_len, variant_str):
    """Check if autokey is consistent at crib positions for given text.

    For PT-autokey with primer of length L:
    key[i] = primer[i] for i < L
    key[i] = PT[i-L] for i >= L

    At crib positions we know PT, so we can check consistency.
    """
    sorted_positions = sorted(crib_dict.keys())

    # For each crib position i >= primer_len:
    #   key[i] = PT[i - primer_len]
    #   If i - primer_len is ALSO a crib position, we know PT[i-primer_len]
    #   So we can compute key[i] and check if it decrypts CT[i] to the expected PT[i]

    # Also: for positions within the primer (i < primer_len):
    #   key[i] = primer[i] (unknown)
    #   Each such position gives one constraint on primer[i]
    #   Multiple crib positions with i < primer_len and same i constrain the SAME primer char

    # Count constraints:
    primer_constraints = defaultdict(list)  # primer_pos -> [(ct_val, pt_val)]
    chain_constraints = []  # (pos, key_pos, expected_key_val)

    for pos, pt_ch in crib_dict.items():
        ct_val = ord(ct_text[pos]) - 65
        pt_val = ord(pt_ch) - 65

        if pos < primer_len:
            primer_constraints[pos].append((ct_val, pt_val))
        else:
            key_source_pos = pos - primer_len
            if key_source_pos in crib_dict:
                # We know PT[key_source_pos] -> that's the key
                key_val = ord(crib_dict[key_source_pos]) - 65
                chain_constraints.append((pos, key_source_pos, key_val, ct_val, pt_val))

    # Check chain constraints
    n_chain_ok = 0
    n_chain_total = len(chain_constraints)

    for pos, key_src, key_val, ct_val, pt_val in chain_constraints:
        # Check: does decrypt(ct_val, key_val) == pt_val?
        if variant_str == "vigenere":
            dec = (ct_val - key_val) % 26
        elif variant_str == "beaufort":
            dec = (key_val - ct_val) % 26
        elif variant_str == "var_beaufort":
            dec = (ct_val + key_val) % 26
        else:
            dec = -1

        if dec == pt_val:
            n_chain_ok += 1

    # Check primer consistency (within primer: each position should have unique key value)
    n_primer_conflicts = 0
    for ppos, constraints in primer_constraints.items():
        # All constraints at this primer position must agree on key value
        key_vals = set()
        for ct_val, pt_val in constraints:
            if variant_str == "vigenere":
                k = (ct_val - pt_val) % 26
            elif variant_str == "beaufort":
                k = (ct_val + pt_val) % 26
            elif variant_str == "var_beaufort":
                k = (pt_val - ct_val) % 26
            else:
                k = 0
            key_vals.add(k)
        if len(key_vals) > 1:
            n_primer_conflicts += 1

    return n_chain_ok, n_chain_total, n_primer_conflicts, len(primer_constraints)


def attack3_col6_autokey_worker(perm_tuple):
    """Test one col6 perm with autokey."""
    col_order = list(perm_tuple)
    results = []

    ct_intermediate = apply_columnar_inverse(CT73, 6, col_order)
    mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, col_order, 73)

    keywords = [
        "DEFECTOR", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN",
        "KOMPASS", "COLOPHON", "SHADOW", "SEVEN", "EAST",
    ]
    variants = ["vigenere", "beaufort", "var_beaufort"]

    for var_str in variants:
        # Test autokey feasibility at various primer lengths
        for primer_len in range(1, 21):
            chain_ok, chain_total, primer_conflicts, primer_count = check_autokey_feasibility(
                ct_intermediate, mapped_cribs, primer_len, var_str
            )

            total_ok = chain_ok
            # Primer positions count as consistent if no conflicts
            primer_ok = primer_count - primer_conflicts
            total_ok += primer_ok
            total_positions = chain_total + primer_count

            if total_positions > 0 and total_ok >= 12:
                results.append((
                    total_ok,
                    f"col6_perm={perm_tuple}:autokey_{var_str}:primer_len={primer_len}",
                    {
                        'perm': perm_tuple,
                        'variant': var_str,
                        'primer_len': primer_len,
                        'score': total_ok,
                        'chain_ok': chain_ok,
                        'chain_total': chain_total,
                        'primer_conflicts': primer_conflicts,
                        'total_positions': total_positions,
                    }
                ))

            # If chain is fully consistent, also test with actual keywords
            if chain_ok == chain_total and chain_total > 0 and primer_conflicts == 0:
                for kw in keywords:
                    if len(kw) >= primer_len:
                        primer = kw[:primer_len]
                        pt = autokey_decrypt(ct_intermediate, primer, var_str)

                        # Score against mapped cribs
                        crib_matches = 0
                        for pos, expected in mapped_cribs.items():
                            if pos < len(pt) and pt[pos] == expected:
                                crib_matches += 1

                        if crib_matches >= 12:
                            results.append((
                                crib_matches,
                                f"col6_perm={perm_tuple}:autokey_{var_str}:{primer}:crib={crib_matches}",
                                {
                                    'perm': perm_tuple,
                                    'variant': var_str,
                                    'primer': primer,
                                    'crib_matches': crib_matches,
                                    'plaintext': pt[:60],
                                }
                            ))

    return results


def attack3_col6_autokey():
    """Width-6 columnar + autokey."""
    print("=" * 70)
    print("ATTACK 3: Width-6 columnar (720 perms) + autokey")
    print("=" * 70)

    all_perms = list(itertools.permutations(range(6)))
    all_results = []

    with ProcessPoolExecutor(max_workers=28) as executor:
        futures = {executor.submit(attack3_col6_autokey_worker, p): p for p in all_perms}
        done = 0
        for future in as_completed(futures):
            done += 1
            try:
                results = future.result()
                all_results.extend(results)
            except Exception as e:
                print(f"  Error: {e}")
            if done % 100 == 0:
                print(f"  Progress: {done}/720 permutations done")

    all_results.sort(key=lambda x: x[0], reverse=True)

    print(f"\n  Total results >= 12: {len(all_results)}")
    for score, desc, detail in all_results[:20]:
        print(f"  Score {score}: {desc}")

    print()
    return all_results[:50]


# ============================================================
# ATTACK 4: Quagmire II with period-6
# ============================================================

def q2_decrypt(ct_text, keyword_nums, indicator_num, pt_alpha_str, ct_alpha_str):
    """Quagmire II decryption.

    Q2: PT alphabet = keyword-mixed, CT alphabet = standard
    Key specifies shift of CT alphabet relative to indicator position.

    For each position i:
      key_letter = keyword[i % len(keyword)]
      shift = pt_alpha.index(key_letter) - pt_alpha.index(indicator)
      PT[i] = pt_alpha[(ct_alpha.index(CT[i]) - shift) % 26]
    """
    pt_alpha = pt_alpha_str
    ct_alpha = ct_alpha_str
    pt_idx = {c: i for i, c in enumerate(pt_alpha)}
    ct_idx = {c: i for i, c in enumerate(ct_alpha)}

    klen = len(keyword_nums)
    result = []

    for i, c in enumerate(ct_text):
        k = keyword_nums[i % klen]
        shift = k - indicator_num
        p_num = (ct_idx[c] - shift) % 26
        result.append(pt_alpha[p_num])

    return ''.join(result)


def attack4_q2_period6():
    """Quagmire II with period-6 keys."""
    print("=" * 70)
    print("ATTACK 4: Quagmire II with period-6 keys on CT73")
    print("=" * 70)

    thematic_6letter = [
        "BERLIN", "DULLES", "SHADOW", "ENIGMA", "CIPHER", "MOSCOW",
        "AGENCY", "TUNNEL", "PRAGUE", "VIENNA", "LONDON", "SOVIET",
        "SIGNAL", "TWELVE", "TWENTY", "CRYPTO", "LANGLY", "GOLDEN",
    ]

    best_results = []

    # Q2: PT alphabet = keyword-mixed (KA or ABSCISSA etc.), CT alphabet = AZ
    # Test with several PT alphabets
    from kryptos.kernel.alphabet import keyword_mixed_alphabet

    pt_alphas = {
        "KA": KA,
        "ABSCISSA": keyword_mixed_alphabet("ABSCISSA"),
        "DEFECTOR": keyword_mixed_alphabet("DEFECTOR"),
        "PALIMPSEST": keyword_mixed_alphabet("PALIMPSEST"),
    }

    for pt_name, pt_alpha in pt_alphas.items():
        pt_idx = {c: i for i, c in enumerate(pt_alpha)}

        for indicator in range(26):
            for kw_text in thematic_6letter:
                if len(kw_text) != 6:
                    continue
                # keyword as numbers in PT alphabet
                try:
                    kw_nums = [pt_idx[c] for c in kw_text]
                except KeyError:
                    continue

                pt = q2_decrypt(CT73, kw_nums, indicator, pt_alpha, ALPH)

                # Score
                crib_matches = 0
                for pos, expected in CRIB_CT73.items():
                    if pos < len(pt) and pt[pos] == expected:
                        crib_matches += 1

                if crib_matches >= 10:
                    ind_letter = chr(indicator + 65)
                    best_results.append((
                        crib_matches,
                        f"Q2:{pt_name}:{kw_text}:ind={ind_letter}",
                        {'score': crib_matches, 'pt': pt[:60]}
                    ))

    best_results.sort(key=lambda x: x[0], reverse=True)
    print(f"  Total results >= 10: {len(best_results)}")
    for score, desc, detail in best_results[:10]:
        print(f"  Score {score}/24: {desc}")

    print()
    return best_results[:20]


# ============================================================
# ATTACK 5: Direct autokey on CT73 (no transposition)
# ============================================================

def attack5_direct_autokey():
    """Direct autokey on CT73 with various primers."""
    print("=" * 70)
    print("ATTACK 5: Direct autokey on CT73 (no transposition)")
    print("=" * 70)

    keywords = [
        "DEFECTOR", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN",
        "KOMPASS", "COLOPHON", "SHADOW", "SEVEN", "EAST", "CLOCK",
        "BERLINCLOCK", "EASTNORTHEAST", "SANBORN", "SCHEIDT",
        "D", "K", "P", "A", "B", "S", "E",  # single letter primers
    ]

    variants = ["vigenere", "beaufort", "var_beaufort"]
    best_results = []

    for var_str in variants:
        for kw in keywords:
            for primer_len in range(1, min(len(kw) + 1, 21)):
                primer = kw[:primer_len]
                pt = autokey_decrypt(CT73, primer, var_str)

                crib_matches = 0
                for pos, expected in CRIB_CT73.items():
                    if pos < len(pt) and pt[pos] == expected:
                        crib_matches += 1

                if crib_matches >= 8:
                    best_results.append((
                        crib_matches,
                        f"autokey_{var_str}:{primer}",
                        {'score': crib_matches, 'pt': pt[:60]}
                    ))

    # Also test all single-letter primers exhaustively
    for var_str in variants:
        for k in range(26):
            primer = chr(k + 65)
            pt = autokey_decrypt(CT73, primer, var_str)

            crib_matches = 0
            for pos, expected in CRIB_CT73.items():
                if pos < len(pt) and pt[pos] == expected:
                    crib_matches += 1

            if crib_matches >= 8:
                best_results.append((
                    crib_matches,
                    f"autokey_{var_str}:primer={primer}",
                    {'score': crib_matches, 'pt': pt[:60]}
                ))

    best_results.sort(key=lambda x: x[0], reverse=True)
    print(f"  Total results >= 8: {len(best_results)}")
    for score, desc, detail in best_results[:10]:
        print(f"  Score {score}/24: {desc}")

    print()
    return best_results[:20]


# ============================================================
# ATTACK 6: Period-6 exhaustive key on CT73 (all 26^6 keys)
# ============================================================

def attack6_chunk(args):
    """Process a chunk of keys for exhaustive period-6 search."""
    chunk_start, chunk_size, ct73, crib_dict, variant_str, use_ka = args

    best_score = 0
    best_results = []

    recover_fn_name = variant_str

    # Pre-compute crib values
    crib_data = []
    for pos, ch in crib_dict.items():
        if use_ka:
            c_val = KA_IDX[ct73[pos]]
            p_val = KA_IDX[ch]
        else:
            c_val = ord(ct73[pos]) - 65
            p_val = ord(ch) - 65

        if variant_str == "vigenere":
            required_k = (c_val - p_val) % 26
        elif variant_str == "beaufort":
            required_k = (c_val + p_val) % 26
        elif variant_str == "var_beaufort":
            required_k = (p_val - c_val) % 26

        crib_data.append((pos, pos % 6, required_k))

    # Group by residue
    residue_groups = defaultdict(list)
    for pos, r, req_k in crib_data:
        residue_groups[r].append(req_k)

    # For period 6, each residue class has some crib positions
    # Check: can ALL positions in each residue agree?
    # If so, the key is determined.

    # Actually, we can do this analytically:
    # For each residue r, find the set of required key values
    # If all are the same -> consistent
    # If not -> impossible

    total_consistent = 0
    total_conflicts = 0
    key = [0] * 6
    all_consistent = True

    for r in range(6):
        if r in residue_groups:
            vals = residue_groups[r]
            val_counts = defaultdict(int)
            for v in vals:
                val_counts[v] += 1
            best_val = max(val_counts, key=val_counts.get)
            key[r] = best_val
            consistent = val_counts[best_val]
            total_consistent += consistent
            conflicts = len(vals) - consistent
            total_conflicts += conflicts
            if conflicts > 0:
                all_consistent = False

    return total_consistent, total_conflicts, key, all_consistent


def attack6_period6_exhaustive():
    """Period-6 exhaustive: analytically check crib consistency.

    Since period 6 fully determines the key from crib positions,
    we don't need to enumerate 26^6 keys. We just check if the
    crib-derived key values are self-consistent for each residue mod 6.

    This is O(1) per (variant, alphabet) combo.
    """
    print("=" * 70)
    print("ATTACK 6: Period-6 analytical crib consistency (all variants)")
    print("=" * 70)

    variants = [
        ("vigenere", CipherVariant.VIGENERE),
        ("beaufort", CipherVariant.BEAUFORT),
        ("var_beaufort", CipherVariant.VAR_BEAUFORT),
    ]
    alphabets = [("AZ", False), ("KA", True)]

    results = []

    for var_str, var_enum in variants:
        for alph_name, use_ka in alphabets:
            score, key_vals, conflicts = score_crib_consistency(
                CT73, CRIB_CT73, 6, var_enum, use_ka
            )
            key, _, total_conflicts = full_key_from_cribs(
                CT73, CRIB_CT73, 6, var_enum, use_ka
            )

            # Decrypt
            if use_ka:
                fn = DECRYPT_FN[var_enum]
                pt = []
                for i, c in enumerate(CT73):
                    c_val = KA_IDX[c]
                    k_val = key[i % 6]
                    p_val = fn(c_val, k_val)
                    pt.append(KA[p_val])
                pt = ''.join(pt)
            else:
                pt = decrypt_text(CT73, key, var_enum)

            # Show residue detail
            residue_detail = {}
            recover = KEY_RECOVERY[var_enum]
            for r in range(6):
                positions = [(p, ch) for p, ch in CRIB_CT73.items() if p % 6 == r]
                keys_at_r = []
                for pos, ch in positions:
                    if use_ka:
                        c_val = KA_IDX[CT73[pos]]
                        p_val = KA_IDX[ch]
                    else:
                        c_val = ord(CT73[pos]) - 65
                        p_val = ord(ch) - 65
                    k = recover(c_val, p_val)
                    keys_at_r.append((pos, ch, k, chr(k + 65)))
                residue_detail[r] = keys_at_r

            is_perfect = total_conflicts == 0
            status = "PERFECT" if is_perfect else f"{total_conflicts} conflicts"
            key_str = ''.join(chr(k + 65) for k in key)

            print(f"\n  {var_str:15s} {alph_name}: score={score}/24, {status}, key={key_str}")

            # Print residue breakdown
            for r in range(6):
                entries = residue_detail[r]
                k_vals_str = ','.join(f"{e[3]}({e[0]})" for e in entries)
                unique_keys = set(e[2] for e in entries)
                marker = " OK" if len(unique_keys) <= 1 else f" CONFLICT ({len(unique_keys)} distinct)"
                print(f"    r={r}: {k_vals_str}{marker}")

            if is_perfect:
                print(f"    !!! ZERO CONFLICTS - THIS IS THE KEY !!!")
                print(f"    PT = {pt}")
            elif score >= 20:
                print(f"    HIGH SCORE! PT = {pt}")

            results.append({
                'variant': var_str,
                'alphabet': alph_name,
                'score': score,
                'conflicts': total_conflicts,
                'key': key,
                'key_str': key_str,
                'plaintext': pt,
                'is_perfect': is_perfect,
            })

    print()
    return results


# ============================================================
# ATTACK 7: Width-6 col trans + period-6 sub (simultaneous)
# ============================================================

def attack7_worker(perm_tuple):
    """For each col6 perm, check period-6 consistency after inverse transposition."""
    col_order = list(perm_tuple)
    results = []

    ct_intermediate = apply_columnar_inverse(CT73, 6, col_order)
    mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, col_order, 73)

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    for var in variants:
        for alph_name, use_ka in [("AZ", False), ("KA", True)]:
            score, key_vals, conflicts = score_crib_consistency(
                ct_intermediate, mapped_cribs, 6, var, use_ka
            )
            total_c = sum(conflicts.values())

            if score >= 16 or total_c == 0:
                key, _, _ = full_key_from_cribs(
                    ct_intermediate, mapped_cribs, 6, var, use_ka
                )

                # Decrypt
                if use_ka:
                    fn = DECRYPT_FN[var]
                    pt = []
                    for i, c in enumerate(ct_intermediate):
                        c_val = KA_IDX[c]
                        k_val = key[i % 6]
                        p_val = fn(c_val, k_val)
                        pt.append(KA[p_val])
                    pt = ''.join(pt)
                else:
                    pt = decrypt_text(ct_intermediate, key, var)

                key_str = ''.join(chr(k + 65) for k in key)

                results.append((
                    score,
                    f"col6+p6:{perm_tuple}:{var.value}:{alph_name}:key={key_str}",
                    {
                        'perm': perm_tuple,
                        'variant': var.value,
                        'alphabet': alph_name,
                        'score': score,
                        'conflicts': total_c,
                        'key': key,
                        'key_str': key_str,
                        'plaintext': pt[:60],
                        'is_perfect': total_c == 0,
                    }
                ))

                if total_c == 0:
                    # PERFECT - potential solution
                    results.append((
                        100,  # Sort to top
                        f"*** PERFECT *** col6+p6:{perm_tuple}:{var.value}:{alph_name}:key={key_str}",
                        {
                            'perm': perm_tuple,
                            'variant': var.value,
                            'alphabet': alph_name,
                            'score': score,
                            'conflicts': 0,
                            'key': key,
                            'key_str': key_str,
                            'plaintext': pt,
                            'is_perfect': True,
                        }
                    ))

    return results


def attack7_col6_period6():
    """Width-6 columnar + period-6 substitution (combined)."""
    print("=" * 70)
    print("ATTACK 7: Width-6 columnar + period-6 sub (all 720x6 combos)")
    print("=" * 70)

    all_perms = list(itertools.permutations(range(6)))
    all_results = []

    with ProcessPoolExecutor(max_workers=28) as executor:
        futures = {executor.submit(attack7_worker, p): p for p in all_perms}
        done = 0
        for future in as_completed(futures):
            done += 1
            try:
                results = future.result()
                all_results.extend(results)
            except Exception as e:
                print(f"  Error: {e}")
            if done % 100 == 0:
                print(f"  Progress: {done}/720 permutations done")

    all_results.sort(key=lambda x: x[0], reverse=True)

    # Filter out the placeholder 100-scores for display
    display_results = [r for r in all_results if r[0] <= 24]
    perfect_results = [r for r in all_results if r[0] == 100]

    if perfect_results:
        print(f"\n  !!! {len(perfect_results)} PERFECT (0-conflict) RESULTS FOUND !!!")
        for _, desc, detail in perfect_results:
            print(f"    {desc}")
            print(f"    PT: {detail['plaintext']}")

    print(f"\n  Top results (>= 16/24):")
    for score, desc, detail in display_results[:30]:
        print(f"  Score {score}/24: {desc}")

    print()
    return all_results[:50]


# ============================================================
# ATTACK 8: SA optimization of mask + col6 + period-6 key
# ============================================================

import random

def sa_evaluate(ct97, mask_positions, col_order, key_6, variant, crib_dict_97):
    """Score a configuration: extract CT73, apply inverse col6 trans,
    then period-6 sub, score against original CT97 cribs mapped to CT73."""
    mask_set = set(mask_positions)

    # Extract CT73
    ct73_chars = []
    ct97_to_73 = {}
    idx73 = 0
    for i in range(97):
        if i not in mask_set:
            ct97_to_73[i] = idx73
            ct73_chars.append(ct97[i])
            idx73 += 1

    if idx73 != 73:
        return -1, ""

    ct73_local = ''.join(ct73_chars)

    # Map cribs to CT73 space
    local_cribs = {}
    for pos, ch in crib_dict_97.items():
        if pos in ct97_to_73:
            local_cribs[ct97_to_73[pos]] = ch
        else:
            # Crib position is in the null mask - penalty
            return -1, ""

    # Apply inverse columnar transposition
    ct_int = apply_columnar_inverse(ct73_local, 6, list(col_order))

    # Map cribs through transposition
    perm = columnar_perm(6, col_order, 73)
    inv = invert_perm(perm)
    mapped_cribs = {}
    for pos, ch in local_cribs.items():
        if pos < 73:
            mapped_cribs[inv[pos]] = ch

    # Score period-6 consistency
    fn = DECRYPT_FN[variant]
    crib_matches = 0
    for pos, expected_ch in mapped_cribs.items():
        if pos < len(ct_int):
            c_val = ord(ct_int[pos]) - 65
            k_val = key_6[pos % 6]
            p_val = fn(c_val, k_val)
            if chr(p_val + 65) == expected_ch:
                crib_matches += 1

    # Also decrypt full text for quadgram scoring
    pt = ''
    for i, c in enumerate(ct_int):
        c_val = ord(c) - 65
        k_val = key_6[i % 6]
        p_val = fn(c_val, k_val)
        pt += chr(p_val + 65)

    return crib_matches, pt


def attack8_sa_joint():
    """SA joint optimization over mask + col6 ordering + period-6 key."""
    print("=" * 70)
    print("ATTACK 8: SA joint optimization (mask + col6 + period-6 key)")
    print("=" * 70)

    # Build CT97 crib dict
    crib_dict_97 = {}
    for start, word in [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]:
        for i, ch in enumerate(word):
            crib_dict_97[start + i] = ch

    variant = CipherVariant.BEAUFORT  # Best variant from prior work

    n_restarts = 50
    n_steps = 5000
    best_global = 0
    best_global_config = None

    # Start from consensus mask
    seed_mask = list(MASK_24)
    non_crib_positions = [i for i in range(97) if i not in set(crib_dict_97.keys())]

    for restart in range(n_restarts):
        # Initialize mask
        if restart == 0:
            current_mask = list(seed_mask)
        else:
            # Random perturbation of seed mask
            current_mask = list(seed_mask)
            n_swaps = random.randint(1, 5)
            for _ in range(n_swaps):
                # Pick a null position and swap with a non-null non-crib position
                null_idx = random.randint(0, 23)
                mask_set = set(current_mask)
                available = [p for p in non_crib_positions if p not in mask_set]
                if available:
                    new_pos = random.choice(available)
                    current_mask[null_idx] = new_pos
            current_mask = sorted(set(current_mask))[:24]

        # Initialize col order
        current_col_order = list(range(6))
        random.shuffle(current_col_order)

        # Initialize key (random or from crib constraints)
        current_key = [random.randint(0, 25) for _ in range(6)]

        current_score, current_pt = sa_evaluate(
            CT97, current_mask, tuple(current_col_order), current_key, variant, crib_dict_97
        )

        temp = 2.0
        for step in range(n_steps):
            temp = 2.0 * (1 - step / n_steps)

            # Choose move type
            move = random.random()

            new_mask = list(current_mask)
            new_col = list(current_col_order)
            new_key = list(current_key)

            if move < 0.3:
                # Swap a mask position
                null_idx = random.randint(0, 23)
                mask_set = set(new_mask)
                available = [p for p in non_crib_positions if p not in mask_set]
                if available:
                    new_mask[null_idx] = random.choice(available)
                    new_mask = sorted(set(new_mask))[:24]
            elif move < 0.5:
                # Swap two columns
                i, j = random.sample(range(6), 2)
                new_col[i], new_col[j] = new_col[j], new_col[i]
            else:
                # Mutate key
                idx = random.randint(0, 5)
                new_key[idx] = random.randint(0, 25)

            if len(set(new_mask)) != 24:
                continue

            new_score, new_pt = sa_evaluate(
                CT97, new_mask, tuple(new_col), new_key, variant, crib_dict_97
            )

            delta = new_score - current_score
            if delta > 0 or (temp > 0.01 and random.random() < (2.718 ** (delta / max(temp, 0.001)))):
                current_mask = new_mask
                current_col_order = new_col
                current_key = new_key
                current_score = new_score
                current_pt = new_pt

        if current_score > best_global:
            best_global = current_score
            best_global_config = {
                'mask': current_mask,
                'col_order': current_col_order,
                'key': current_key,
                'key_str': ''.join(chr(k + 65) for k in current_key),
                'score': current_score,
                'plaintext': current_pt,
                'restart': restart,
            }

        if restart % 10 == 0 or current_score >= 16:
            print(f"  Restart {restart}: score={current_score}/24 (global best={best_global})")

    print(f"\n  SA global best: {best_global}/24")
    if best_global_config:
        print(f"    Col order: {best_global_config['col_order']}")
        print(f"    Key: {best_global_config['key_str']}")
        print(f"    Mask: {best_global_config['mask']}")
        print(f"    PT: {best_global_config['plaintext'][:60]}")

    print()
    return best_global_config


# ============================================================
# MAIN
# ============================================================

def main():
    start_time = time.time()
    print(f"Period-6 Comprehensive Attack on CT73")
    print(f"Started: {datetime.now().isoformat()}")
    print(f"CT97 = {CT97}")
    print(f"Mask = {MASK_24}")
    print(f"CT73 = {CT73}")
    print()

    all_outputs = {}

    # Attack 6 (analytical, instant)
    r6 = attack6_period6_exhaustive()
    all_outputs['attack6_period6_analytical'] = r6

    # Attack 1 (same as 6 but with more periods)
    r1 = attack1_period6_direct()
    all_outputs['attack1_period6_direct'] = r1

    # Attack 5 (direct autokey, fast)
    r5 = attack5_direct_autokey()
    all_outputs['attack5_direct_autokey'] = [
        {'score': s, 'desc': d, 'detail': det} for s, d, det in (r5 or [])
    ]

    # Attack 7 (col6 + period-6, parallel)
    r7 = attack7_col6_period6()
    all_outputs['attack7_col6_period6'] = [
        {'score': s, 'desc': d, 'detail': det} for s, d, det in (r7 or [])
    ]

    # Attack 2 (col6 + various periods, parallel)
    r2 = attack2_width6_columnar()
    all_outputs['attack2_col6_sub'] = [
        {'score': s, 'desc': d, 'detail': det} for s, d, det in (r2 or [])
    ]

    # Attack 3 (col6 + autokey, parallel)
    r3 = attack3_col6_autokey()
    all_outputs['attack3_col6_autokey'] = [
        {'score': s, 'desc': d, 'detail': det} for s, d, det in (r3 or [])
    ]

    # Attack 4 (Q2, fast)
    r4 = attack4_q2_period6()
    all_outputs['attack4_q2_period6'] = [
        {'score': s, 'desc': d, 'detail': det} for s, d, det in (r4 or [])
    ]

    # Attack 8 (SA, takes a while)
    r8 = attack8_sa_joint()
    all_outputs['attack8_sa_joint'] = r8

    elapsed = time.time() - start_time

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Elapsed: {elapsed:.1f}s")

    # Find global best across all attacks
    global_best = 0
    global_desc = ""

    for attack_name, results in all_outputs.items():
        if results is None:
            continue
        if isinstance(results, dict):
            score = results.get('score', 0)
            if score > global_best:
                global_best = score
                global_desc = f"{attack_name}: score={score}"
        elif isinstance(results, list):
            for item in results:
                if isinstance(item, dict):
                    score = item.get('score', 0)
                    if isinstance(score, (int, float)) and score > global_best and score <= 24:
                        global_best = score
                        global_desc = f"{attack_name}: {item.get('desc', '')}"

    print(f"Global best: {global_best}/24 — {global_desc}")

    if global_best >= 16:
        print("*** ABOVE COL7 CEILING (15/24) - SIGNIFICANT ***")
    elif global_best == 24:
        print("*** BREAKTHROUGH - K4 SOLVED ***")
    else:
        print(f"Below col7 ceiling (15/24). Period-6 = {'NOISE' if global_best < 12 else 'INTERESTING but below ceiling'}.")

    # Save results
    output = {
        'timestamp': datetime.now().isoformat(),
        'elapsed_seconds': elapsed,
        'ct73': CT73,
        'mask': MASK_24,
        'ene_ct73_positions': ENE_CT73,
        'bcl_ct73_positions': BCL_CT73,
        'global_best_score': global_best,
        'global_best_desc': global_desc,
        'attacks': {}
    }

    for name, data in all_outputs.items():
        if data is None:
            output['attacks'][name] = None
        elif isinstance(data, list):
            # Serialize tuples/complex objects
            serializable = []
            for item in data:
                if isinstance(item, dict):
                    serializable.append(item)
                elif isinstance(item, (list, tuple)) and len(item) >= 3:
                    serializable.append({'score': item[0], 'desc': str(item[1]), 'detail': str(item[2])})
                else:
                    serializable.append(str(item))
            output['attacks'][name] = serializable[:20]
        elif isinstance(data, dict):
            # Make sure all values are serializable
            clean = {}
            for k, v in data.items():
                if isinstance(v, (list, dict, str, int, float, bool, type(None))):
                    clean[k] = v
                else:
                    clean[k] = str(v)
            output['attacks'][name] = clean

    results_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'f_period6_comprehensive_v1.json')
    with open(results_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\nResults saved to: {results_path}")


if __name__ == '__main__':
    main()
