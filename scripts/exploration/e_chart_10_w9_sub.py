#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-CHART-10: W9 orderings + keyword substitution (deep dive).

Tests best w9 column orderings from E-CHART-07 combined with keyword-based
substitution ciphers (Vigenere, Beaufort, Variant Beaufort) and autokey modes.

Phases:
  1. Top orderings + keywords (no insertion), models A and B
  2. YR@61 insertion + top orderings + keywords, models A and B
  3. CC@62 insertion + top orderings + keywords, models A and B
  4. Exhaustive 9! orderings with CHECKPOINT (Vigenere + Beaufort, models A+B)
"""
import json, itertools, os, sys, time
from collections import defaultdict

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, CRIB_DICT, N_CRIBS
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

# ── Cipher primitives ──────────────────────────────────────────────────

def columnar_decrypt(ct, width, order):
    """Decrypt columnar transposition. order[i] = which column is read i-th."""
    n = len(ct)
    nrows = (n + width - 1) // width
    ncols = width
    n_long = n - (nrows - 1) * ncols
    if n % ncols == 0:
        n_long = ncols

    col_lens = [0] * ncols
    for col in range(ncols):
        col_lens[col] = nrows if col < n_long else nrows - 1

    cols = {}
    pos = 0
    for rank in range(ncols):
        col_idx = order[rank]
        length = col_lens[col_idx]
        cols[col_idx] = ct[pos:pos+length]
        pos += length

    result = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(cols.get(col, '')):
                result.append(cols[col][row])
    return ''.join(result)


def columnar_encrypt(pt, width, order):
    """Encrypt columnar transposition. order[i] = which column is read i-th."""
    n = len(pt)
    nrows = (n + width - 1) // width
    ncols = width

    # Write PT into grid row by row
    grid = []
    for r in range(nrows):
        row = pt[r*ncols:(r+1)*ncols]
        grid.append(row)

    # Number of long columns
    n_long = n - (nrows - 1) * ncols
    if n % ncols == 0:
        n_long = ncols

    col_lens = [0] * ncols
    for col in range(ncols):
        col_lens[col] = nrows if col < n_long else nrows - 1

    # Read columns in the given order
    result = []
    for rank in range(ncols):
        col_idx = order[rank]
        for row in range(col_lens[col_idx]):
            result.append(grid[row][col_idx] if col_idx < len(grid[row]) else '')
    return ''.join(result)


def vig_decrypt(ct, key):
    """Vigenere decrypt: PT = (CT - K) mod 26"""
    pt = []
    kl = len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % kl]]
        pt.append(ALPH[(ci - ki) % 26])
    return ''.join(pt)


def vig_encrypt(pt, key):
    """Vigenere encrypt: CT = (PT + K) mod 26"""
    ct = []
    kl = len(key)
    for i, c in enumerate(pt):
        pi = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % kl]]
        ct.append(ALPH[(pi + ki) % 26])
    return ''.join(ct)


def beau_decrypt(ct, key):
    """Beaufort decrypt: PT = (K - CT) mod 26"""
    pt = []
    kl = len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % kl]]
        pt.append(ALPH[(ki - ci) % 26])
    return ''.join(pt)


def varbeau_decrypt(ct, key):
    """Variant Beaufort decrypt: PT = (CT + K) mod 26 (since encrypt is PT - K)"""
    pt = []
    kl = len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % kl]]
        pt.append(ALPH[(ci + ki) % 26])
    return ''.join(pt)


def autokey_pt_decrypt(ct, primer):
    """Autokey (plaintext feedback) decrypt.
    Key = primer || PT[0], PT[1], ...
    PT[i] = (CT[i] - K[i]) mod 26
    """
    n = len(ct)
    key = list(ALPH_IDX[c] for c in primer)
    pt = []
    for i in range(n):
        ci = ALPH_IDX[ct[i]]
        if i < len(key):
            ki = key[i]
        else:
            ki = ALPH_IDX[pt[i - len(primer)]]
        pi = (ci - ki) % 26
        pt.append(ALPH[pi])
    return ''.join(pt)


def autokey_ct_decrypt(ct, primer):
    """Autokey (ciphertext feedback) decrypt.
    Key = primer || CT[0], CT[1], ...
    PT[i] = (CT[i] - K[i]) mod 26
    """
    n = len(ct)
    key = list(ALPH_IDX[c] for c in primer)
    pt = []
    for i in range(n):
        ci = ALPH_IDX[ct[i]]
        if i < len(key):
            ki = key[i]
        else:
            ki = ALPH_IDX[ct[i - len(primer)]]
        pi = (ci - ki) % 26
        pt.append(ALPH[pi])
    return ''.join(pt)


def quick_crib_score(pt):
    """Fast crib scoring."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == ch:
            matches += 1
    return matches


def derive_keystream_vig(ct_str, pt_str):
    """Derive Vigenere keystream: K = (CT - PT) mod 26"""
    return [(ALPH_IDX[c] - ALPH_IDX[p]) % 26 for c, p in zip(ct_str, pt_str)]


def full_analysis(pt, config_str, results_list):
    """Run full score_candidate + Bean on a high-scoring candidate."""
    ks = derive_keystream_vig(CT[:len(pt)], pt[:len(CT)])
    bean = verify_bean(ks)
    sc = score_candidate(pt, bean_result=bean)
    print(f"  === FULL ANALYSIS: {config_str} ===")
    print(f"    {sc.summary}")
    print(f"    PT: {pt}")
    results_list.append({
        'config': config_str,
        'score': sc.crib_score,
        'ene': sc.ene_score,
        'bc': sc.bc_score,
        'ic': sc.ic_value,
        'bean': sc.bean_passed,
        'pt': pt,
    })
    return sc


# ── Configuration ──────────────────────────────────────────────────────

TOP_ORDERINGS = [
    [8,5,2,1,3,4,6,7,0],
    [0,7,2,8,3,5,1,6,4],
    [0,5,7,6,3,4,1,8,2],
    [2,4,7,8,3,5,1,6,0],
    [8,4,2,7,3,5,1,6,0],
]

KEYWORDS = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'HERBERT', 'STOPWATCH',
    'GOLD', 'CHARLIE', 'CHECKPOINT', 'CARTER', 'BERLIN',
    'BERLINCLOCK', 'EASTNORTHEAST', 'YAR', 'DYAR', 'HILL',
    'LAYERTWO', 'SANBORN', 'INVISIBLE', 'MAGNETIC', 'UNDERGROUND',
    'EVELYN', 'CARNARVON', 'TUTANKHAMUN', 'TANGO',
]

AUTOKEY_PRIMERS = (
    [chr(ord('A') + i) for i in range(26)] +
    ['YAR', 'KRYPTOS', 'HERBERT', 'PALIMPSEST', 'ABSCISSA']
)

FULL_ANALYSIS_THRESHOLD = 12

print("=" * 70)
print("E-CHART-10: W9 orderings + keyword substitution (deep dive)")
print("=" * 70)

all_results = []
high_results = []
global_best = 0
global_config = ""
t0 = time.time()
total_configs = 0


# ── Phase 1: Top orderings + keywords (no insertion) ──────────────────
print("\n--- Phase 1: Top orderings + keywords (models A and B) ---")
p1_best = 0
p1_count = 0

for order in TOP_ORDERINGS:
    for keyword in KEYWORDS:
        for variant_name, decrypt_fn in [('vig', vig_decrypt), ('beau', beau_decrypt), ('varbeau', varbeau_decrypt)]:
            # Model A: transpose first, then substitute
            # Encryption was: substitute(PT) -> transpose -> CT
            # Decryption: un-transpose(CT) -> un-substitute -> PT
            intermediate_a = columnar_decrypt(CT, 9, order)
            pt_a = decrypt_fn(intermediate_a, keyword)
            sc_a = quick_crib_score(pt_a)
            p1_count += 1

            if sc_a >= FULL_ANALYSIS_THRESHOLD:
                cfg = f"modelA/{variant_name}/{keyword}/order={order}"
                full_analysis(pt_a, cfg, high_results)
            elif sc_a > p1_best:
                p1_best = sc_a
                cfg = f"modelA/{variant_name}/{keyword}/order={order}"
                print(f"  NEW BEST: {sc_a}/24 -- {cfg}")
                if sc_a >= 8:
                    print(f"    PT: {pt_a[:60]}...")

            # Model B: substitute first, then transpose
            # Encryption was: transpose(PT) -> substitute -> CT
            # Decryption: un-substitute(CT) -> un-transpose -> PT
            intermediate_b = decrypt_fn(CT, keyword)
            pt_b = columnar_decrypt(intermediate_b, 9, order)
            sc_b = quick_crib_score(pt_b)
            p1_count += 1

            if sc_b >= FULL_ANALYSIS_THRESHOLD:
                cfg = f"modelB/{variant_name}/{keyword}/order={order}"
                full_analysis(pt_b, cfg, high_results)
            elif sc_b > p1_best:
                p1_best = sc_b
                cfg = f"modelB/{variant_name}/{keyword}/order={order}"
                print(f"  NEW BEST: {sc_b}/24 -- {cfg}")
                if sc_b >= 8:
                    print(f"    PT: {pt_b[:60]}...")

    # Autokey modes (only model A: un-transpose then un-autokey)
    for primer in AUTOKEY_PRIMERS:
        intermediate = columnar_decrypt(CT, 9, order)

        # PT-feedback autokey
        pt_ak_pt = autokey_pt_decrypt(intermediate, primer)
        sc = quick_crib_score(pt_ak_pt)
        p1_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"modelA/autokey_pt/{primer}/order={order}"
            full_analysis(pt_ak_pt, cfg, high_results)
        elif sc > p1_best:
            p1_best = sc
            cfg = f"modelA/autokey_pt/{primer}/order={order}"
            print(f"  NEW BEST: {sc}/24 -- {cfg}")
            if sc >= 8:
                print(f"    PT: {pt_ak_pt[:60]}...")

        # CT-feedback autokey
        pt_ak_ct = autokey_ct_decrypt(intermediate, primer)
        sc = quick_crib_score(pt_ak_ct)
        p1_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"modelA/autokey_ct/{primer}/order={order}"
            full_analysis(pt_ak_ct, cfg, high_results)
        elif sc > p1_best:
            p1_best = sc
            cfg = f"modelA/autokey_ct/{primer}/order={order}"
            print(f"  NEW BEST: {sc}/24 -- {cfg}")
            if sc >= 8:
                print(f"    PT: {pt_ak_ct[:60]}...")

    # Autokey model B: un-autokey CT, then un-transpose
    for primer in AUTOKEY_PRIMERS:
        intermediate_pt = autokey_pt_decrypt(CT, primer)
        pt_b_ak_pt = columnar_decrypt(intermediate_pt, 9, order)
        sc = quick_crib_score(pt_b_ak_pt)
        p1_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"modelB/autokey_pt/{primer}/order={order}"
            full_analysis(pt_b_ak_pt, cfg, high_results)
        elif sc > p1_best:
            p1_best = sc
            cfg = f"modelB/autokey_pt/{primer}/order={order}"
            print(f"  NEW BEST: {sc}/24 -- {cfg}")
            if sc >= 8:
                print(f"    PT: {pt_b_ak_pt[:60]}...")

        intermediate_ct = autokey_ct_decrypt(CT, primer)
        pt_b_ak_ct = columnar_decrypt(intermediate_ct, 9, order)
        sc = quick_crib_score(pt_b_ak_ct)
        p1_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"modelB/autokey_ct/{primer}/order={order}"
            full_analysis(pt_b_ak_ct, cfg, high_results)
        elif sc > p1_best:
            p1_best = sc
            cfg = f"modelB/autokey_ct/{primer}/order={order}"
            print(f"  NEW BEST: {sc}/24 -- {cfg}")
            if sc >= 8:
                print(f"    PT: {pt_b_ak_ct[:60]}...")

total_configs += p1_count
if p1_best > global_best:
    global_best = p1_best
print(f"  Phase 1 complete: {p1_count} configs, best {p1_best}/24, elapsed {time.time()-t0:.1f}s")


# ── Phase 2: YR@61 insertion + top orderings + keywords ───────────────
print("\n--- Phase 2: Insert YR@61 + top orderings + keywords ---")
p2_best = 0
p2_count = 0

ct_yr61 = CT[:61] + 'Y' + 'R' + CT[61:]
assert len(ct_yr61) == 99

for order in TOP_ORDERINGS:
    for keyword in KEYWORDS:
        for variant_name, decrypt_fn in [('vig', vig_decrypt), ('beau', beau_decrypt), ('varbeau', varbeau_decrypt)]:
            # Model A: un-transpose(extended CT), un-substitute, then remove inserted chars
            inter_a = columnar_decrypt(ct_yr61, 9, order)
            pt99_a = decrypt_fn(inter_a, keyword)
            # Remove YR from plaintext at position 61
            pt_a = pt99_a[:61] + pt99_a[63:]
            sc_a = quick_crib_score(pt_a)
            # Also score the 99-char version (maybe cribs are at same absolute positions)
            sc99_a = quick_crib_score(pt99_a)
            sc_best_a = max(sc_a, sc99_a)
            p2_count += 1

            if sc_best_a >= FULL_ANALYSIS_THRESHOLD:
                use_pt = pt_a if sc_a >= sc99_a else pt99_a[:97]
                cfg = f"YR@61/modelA/{variant_name}/{keyword}/order={order}"
                full_analysis(use_pt, cfg, high_results)
            elif sc_best_a > p2_best:
                p2_best = sc_best_a
                cfg = f"YR@61/modelA/{variant_name}/{keyword}/order={order}"
                print(f"  NEW BEST: {sc_best_a}/24 -- {cfg}")
                if sc_best_a >= 8:
                    print(f"    PT97: {pt_a[:60]}...")

            # Model B: un-substitute(extended CT), un-transpose, remove
            inter_b = decrypt_fn(ct_yr61, keyword)
            pt99_b = columnar_decrypt(inter_b, 9, order)
            pt_b = pt99_b[:61] + pt99_b[63:]
            sc_b = quick_crib_score(pt_b)
            sc99_b = quick_crib_score(pt99_b)
            sc_best_b = max(sc_b, sc99_b)
            p2_count += 1

            if sc_best_b >= FULL_ANALYSIS_THRESHOLD:
                use_pt = pt_b if sc_b >= sc99_b else pt99_b[:97]
                cfg = f"YR@61/modelB/{variant_name}/{keyword}/order={order}"
                full_analysis(use_pt, cfg, high_results)
            elif sc_best_b > p2_best:
                p2_best = sc_best_b
                cfg = f"YR@61/modelB/{variant_name}/{keyword}/order={order}"
                print(f"  NEW BEST: {sc_best_b}/24 -- {cfg}")
                if sc_best_b >= 8:
                    print(f"    PT97: {pt_b[:60]}...")

    # Autokey with YR insertion
    for primer in AUTOKEY_PRIMERS:
        # Model A
        inter = columnar_decrypt(ct_yr61, 9, order)
        pt99 = autokey_pt_decrypt(inter, primer)
        pt = pt99[:61] + pt99[63:]
        sc = max(quick_crib_score(pt), quick_crib_score(pt99))
        p2_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"YR@61/modelA/autokey_pt/{primer}/order={order}"
            full_analysis(pt, cfg, high_results)
        elif sc > p2_best:
            p2_best = sc
            print(f"  NEW BEST: {sc}/24 -- YR@61/modelA/autokey_pt/{primer}/order={order}")

        pt99 = autokey_ct_decrypt(inter, primer)
        pt = pt99[:61] + pt99[63:]
        sc = max(quick_crib_score(pt), quick_crib_score(pt99))
        p2_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"YR@61/modelA/autokey_ct/{primer}/order={order}"
            full_analysis(pt, cfg, high_results)
        elif sc > p2_best:
            p2_best = sc
            print(f"  NEW BEST: {sc}/24 -- YR@61/modelA/autokey_ct/{primer}/order={order}")

        # Model B
        inter_pt = autokey_pt_decrypt(ct_yr61, primer)
        pt99 = columnar_decrypt(inter_pt, 9, order)
        pt = pt99[:61] + pt99[63:]
        sc = max(quick_crib_score(pt), quick_crib_score(pt99))
        p2_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"YR@61/modelB/autokey_pt/{primer}/order={order}"
            full_analysis(pt, cfg, high_results)
        elif sc > p2_best:
            p2_best = sc
            print(f"  NEW BEST: {sc}/24 -- YR@61/modelB/autokey_pt/{primer}/order={order}")

        inter_ct = autokey_ct_decrypt(ct_yr61, primer)
        pt99 = columnar_decrypt(inter_ct, 9, order)
        pt = pt99[:61] + pt99[63:]
        sc = max(quick_crib_score(pt), quick_crib_score(pt99))
        p2_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"YR@61/modelB/autokey_ct/{primer}/order={order}"
            full_analysis(pt, cfg, high_results)
        elif sc > p2_best:
            p2_best = sc
            print(f"  NEW BEST: {sc}/24 -- YR@61/modelB/autokey_ct/{primer}/order={order}")

total_configs += p2_count
if p2_best > global_best:
    global_best = p2_best
print(f"  Phase 2 complete: {p2_count} configs, best {p2_best}/24, elapsed {time.time()-t0:.1f}s")


# ── Phase 3: CC@62 insertion + top orderings + keywords ───────────────
print("\n--- Phase 3: Insert CC@62 + top orderings + keywords ---")
p3_best = 0
p3_count = 0

ct_cc62 = CT[:62] + 'C' + 'C' + CT[62:]
assert len(ct_cc62) == 99

for order in TOP_ORDERINGS:
    for keyword in KEYWORDS:
        for variant_name, decrypt_fn in [('vig', vig_decrypt), ('beau', beau_decrypt), ('varbeau', varbeau_decrypt)]:
            # Model A
            inter_a = columnar_decrypt(ct_cc62, 9, order)
            pt99_a = decrypt_fn(inter_a, keyword)
            pt_a = pt99_a[:62] + pt99_a[64:]
            sc_a = quick_crib_score(pt_a)
            sc99_a = quick_crib_score(pt99_a)
            sc_best_a = max(sc_a, sc99_a)
            p3_count += 1

            if sc_best_a >= FULL_ANALYSIS_THRESHOLD:
                use_pt = pt_a if sc_a >= sc99_a else pt99_a[:97]
                cfg = f"CC@62/modelA/{variant_name}/{keyword}/order={order}"
                full_analysis(use_pt, cfg, high_results)
            elif sc_best_a > p3_best:
                p3_best = sc_best_a
                cfg = f"CC@62/modelA/{variant_name}/{keyword}/order={order}"
                print(f"  NEW BEST: {sc_best_a}/24 -- {cfg}")
                if sc_best_a >= 8:
                    print(f"    PT97: {pt_a[:60]}...")

            # Model B
            inter_b = decrypt_fn(ct_cc62, keyword)
            pt99_b = columnar_decrypt(inter_b, 9, order)
            pt_b = pt99_b[:62] + pt99_b[64:]
            sc_b = quick_crib_score(pt_b)
            sc99_b = quick_crib_score(pt99_b)
            sc_best_b = max(sc_b, sc99_b)
            p3_count += 1

            if sc_best_b >= FULL_ANALYSIS_THRESHOLD:
                use_pt = pt_b if sc_b >= sc99_b else pt99_b[:97]
                cfg = f"CC@62/modelB/{variant_name}/{keyword}/order={order}"
                full_analysis(use_pt, cfg, high_results)
            elif sc_best_b > p3_best:
                p3_best = sc_best_b
                cfg = f"CC@62/modelB/{variant_name}/{keyword}/order={order}"
                print(f"  NEW BEST: {sc_best_b}/24 -- {cfg}")
                if sc_best_b >= 8:
                    print(f"    PT97: {pt_b[:60]}...")

    # Autokey with CC insertion
    for primer in AUTOKEY_PRIMERS:
        # Model A
        inter = columnar_decrypt(ct_cc62, 9, order)
        pt99 = autokey_pt_decrypt(inter, primer)
        pt = pt99[:62] + pt99[64:]
        sc = max(quick_crib_score(pt), quick_crib_score(pt99))
        p3_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"CC@62/modelA/autokey_pt/{primer}/order={order}"
            full_analysis(pt, cfg, high_results)
        elif sc > p3_best:
            p3_best = sc
            print(f"  NEW BEST: {sc}/24 -- CC@62/modelA/autokey_pt/{primer}/order={order}")

        pt99 = autokey_ct_decrypt(inter, primer)
        pt = pt99[:62] + pt99[64:]
        sc = max(quick_crib_score(pt), quick_crib_score(pt99))
        p3_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"CC@62/modelA/autokey_ct/{primer}/order={order}"
            full_analysis(pt, cfg, high_results)
        elif sc > p3_best:
            p3_best = sc
            print(f"  NEW BEST: {sc}/24 -- CC@62/modelA/autokey_ct/{primer}/order={order}")

        # Model B
        inter_pt = autokey_pt_decrypt(ct_cc62, primer)
        pt99 = columnar_decrypt(inter_pt, 9, order)
        pt = pt99[:62] + pt99[64:]
        sc = max(quick_crib_score(pt), quick_crib_score(pt99))
        p3_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"CC@62/modelB/autokey_pt/{primer}/order={order}"
            full_analysis(pt, cfg, high_results)
        elif sc > p3_best:
            p3_best = sc
            print(f"  NEW BEST: {sc}/24 -- CC@62/modelB/autokey_pt/{primer}/order={order}")

        inter_ct = autokey_ct_decrypt(ct_cc62, primer)
        pt99 = columnar_decrypt(inter_ct, 9, order)
        pt = pt99[:62] + pt99[64:]
        sc = max(quick_crib_score(pt), quick_crib_score(pt99))
        p3_count += 1
        if sc >= FULL_ANALYSIS_THRESHOLD:
            cfg = f"CC@62/modelB/autokey_ct/{primer}/order={order}"
            full_analysis(pt, cfg, high_results)
        elif sc > p3_best:
            p3_best = sc
            print(f"  NEW BEST: {sc}/24 -- CC@62/modelB/autokey_ct/{primer}/order={order}")

total_configs += p3_count
if p3_best > global_best:
    global_best = p3_best
print(f"  Phase 3 complete: {p3_count} configs, best {p3_best}/24, elapsed {time.time()-t0:.1f}s")


# ── Phase 4: Exhaustive w9 orderings with CHECKPOINT ──────────────────
print("\n--- Phase 4: ALL 362,880 w9 orderings × CHECKPOINT (Vig+Beau, models A+B) ---")
p4_best = 0
p4_count = 0
CHECKPOINT_KEY = 'CHECKPOINT'

for order in itertools.permutations(range(9)):
    order = list(order)

    # Model A: un-transpose, then un-substitute
    inter_a = columnar_decrypt(CT, 9, order)
    pt_vig_a = vig_decrypt(inter_a, CHECKPOINT_KEY)
    sc = quick_crib_score(pt_vig_a)
    p4_count += 1
    if sc >= FULL_ANALYSIS_THRESHOLD:
        cfg = f"CHECKPOINT/modelA/vig/order={order}"
        full_analysis(pt_vig_a, cfg, high_results)
    elif sc > p4_best:
        p4_best = sc
        print(f"  NEW BEST: {sc}/24 -- modelA/vig/CHECKPOINT/order={order}")
        if sc >= 8:
            print(f"    PT: {pt_vig_a[:60]}...")

    pt_beau_a = beau_decrypt(inter_a, CHECKPOINT_KEY)
    sc = quick_crib_score(pt_beau_a)
    p4_count += 1
    if sc >= FULL_ANALYSIS_THRESHOLD:
        cfg = f"CHECKPOINT/modelA/beau/order={order}"
        full_analysis(pt_beau_a, cfg, high_results)
    elif sc > p4_best:
        p4_best = sc
        print(f"  NEW BEST: {sc}/24 -- modelA/beau/CHECKPOINT/order={order}")
        if sc >= 8:
            print(f"    PT: {pt_beau_a[:60]}...")

    # Model B: un-substitute, then un-transpose
    ct_vig_b = vig_decrypt(CT, CHECKPOINT_KEY)
    pt_vig_b = columnar_decrypt(ct_vig_b, 9, order)
    sc = quick_crib_score(pt_vig_b)
    p4_count += 1
    if sc >= FULL_ANALYSIS_THRESHOLD:
        cfg = f"CHECKPOINT/modelB/vig/order={order}"
        full_analysis(pt_vig_b, cfg, high_results)
    elif sc > p4_best:
        p4_best = sc
        print(f"  NEW BEST: {sc}/24 -- modelB/vig/CHECKPOINT/order={order}")
        if sc >= 8:
            print(f"    PT: {pt_vig_b[:60]}...")

    ct_beau_b = beau_decrypt(CT, CHECKPOINT_KEY)
    pt_beau_b = columnar_decrypt(ct_beau_b, 9, order)
    sc = quick_crib_score(pt_beau_b)
    p4_count += 1
    if sc >= FULL_ANALYSIS_THRESHOLD:
        cfg = f"CHECKPOINT/modelB/beau/order={order}"
        full_analysis(pt_beau_b, cfg, high_results)
    elif sc > p4_best:
        p4_best = sc
        print(f"  NEW BEST: {sc}/24 -- modelB/beau/CHECKPOINT/order={order}")
        if sc >= 8:
            print(f"    PT: {pt_beau_b[:60]}...")

    if p4_count % 200000 == 0:
        print(f"    ... {p4_count} configs checked, best {p4_best}/24, {time.time()-t0:.0f}s")

total_configs += p4_count
if p4_best > global_best:
    global_best = p4_best
print(f"  Phase 4 complete: {p4_count} configs, best {p4_best}/24, elapsed {time.time()-t0:.1f}s")


# ── Summary ────────────────────────────────────────────────────────────
elapsed = time.time() - t0
print(f"\n{'=' * 70}")
print(f"E-CHART-10 COMPLETE")
print(f"Total configs tested: {total_configs}")
print(f"Total time: {elapsed:.1f}s")
print(f"GLOBAL BEST: {global_best}/24")
print(f"High-scoring results (>={FULL_ANALYSIS_THRESHOLD}): {len(high_results)}")

if global_best <= 6:
    classification = "NOISE"
elif global_best <= 9:
    classification = "NOISE (marginal)"
elif global_best <= 17:
    classification = "STORE"
else:
    classification = "SIGNAL — INVESTIGATE!"

print(f"CLASSIFICATION: {classification}")
print(f"{'=' * 70}")

os.makedirs('results', exist_ok=True)
output = {
    'experiment': 'E-CHART-10',
    'description': 'W9 orderings + keyword substitution (deep dive)',
    'total_configs': total_configs,
    'global_best': global_best,
    'classification': classification,
    'elapsed_s': elapsed,
    'phases': {
        'phase1_no_insert': {'configs': p1_count, 'best': p1_best},
        'phase2_yr61': {'configs': p2_count, 'best': p2_best},
        'phase3_cc62': {'configs': p3_count, 'best': p3_best},
        'phase4_checkpoint_exhaustive': {'configs': p4_count, 'best': p4_best},
    },
    'high_results': high_results,
}
with open('results/e_chart_10_w9_sub.json', 'w') as f:
    json.dump(output, f, indent=2)
print(f"Artifact: results/e_chart_10_w9_sub.json")
