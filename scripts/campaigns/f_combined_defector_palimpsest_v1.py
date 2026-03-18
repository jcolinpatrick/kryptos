#!/usr/bin/env python3
"""
Cipher:   Combined DEFECTOR+PALIMPSEST keyword hypothesis
Family:   campaigns
Status:   active
Keyspace: ~50K+ configs across 9 test suites
Last run: 2026-03-16
Best score: TBD

HYPOTHESIS: DEFECTOR and PALIMPSEST produce complementary miss patterns
at 15/24 each. Combining the two keywords may break the 15/24 ceiling.

Tests:
  1. Combined/interleaved/modular keywords with col7+null mask
  2. Two-stage cipher (Beaufort with each keyword in sequence)
  3. Alternating keys by position (even/odd, by region)
  4. SA over mask with combined keys (30 restarts)
  5. Hybrid key from known correct values at crib positions
  6. Correct key analysis at all 24 crib positions for both masks
  7. PALIMPSEST as alphabet source, DEFECTOR as key (and vice versa)
  8. Quagmire variants with both keywords
  9. LCM analysis (period 40 combined key)
"""

import sys, os, json, time, math, random
from collections import Counter
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
)

# ---- Constants ----
CT97 = CT
N = 97
N_NULLS = 24
N_PT = 73
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START = 21
BCL_START = 63
NON_CRIB = sorted([i for i in range(N) if i not in CRIB_POSITIONS])
NC_SET = frozenset(NON_CRIB)

AZ = ALPH
KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA_STR)}

CRIB_LIST = sorted(CRIB_DICT.items())

# ---- Masks ----
DEF_MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
PAL_MASK = frozenset([6,8,9,12,14,18,19,35,37,38,46,50,57,60,61,74,75,76,77,78,79,81,84,96])

# ---- Keywords ----
DEFECTOR_NUMS = [ord(c)-65 for c in "DEFECTOR"]  # [3,4,5,4,2,19,14,17]
PALIMPSEST_NUMS = [ord(c)-65 for c in "PALIMPSEST"]  # [15,0,11,8,12,15,18,4,18,19]

def keyword_mixed_alphabet(keyword, base="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    """Generate keyword-mixed alphabet."""
    seen = set()
    result = []
    for c in keyword + base:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return ''.join(result)

PALIMPSEST_ALPHA = keyword_mixed_alphabet("PALIMPSEST")
DEFECTOR_ALPHA = keyword_mixed_alphabet("DEFECTOR")
PAL_ALPHA_IDX = {c: i for i, c in enumerate(PALIMPSEST_ALPHA)}
DEF_ALPHA_IDX = {c: i for i, c in enumerate(DEFECTOR_ALPHA)}

# ---- Quadgram loading ----
QUADGRAMS = {}
QG_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'english_quadgrams.json')
    p = os.path.normpath(p)
    if os.path.exists(p):
        with open(p) as f:
            QUADGRAMS.update(json.load(f))
        QG_FLOOR = min(QUADGRAMS.values()) - 1.0

def qg_score(text):
    if len(text) < 4:
        return -99.0
    total = 0.0
    for i in range(len(text) - 3):
        total += QUADGRAMS.get(text[i:i+4], QG_FLOOR)
    return total / len(text)

def ic(text):
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))

# ---- Col7 permutation ----
def columnar_perm(n, width):
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = reverse_perm(columnar_perm(N_PT, 7))

# ---- Cipher operations ----
def extract_73(mask):
    """Extract 73 chars from CT97 by removing nulls at mask positions."""
    return ''.join(CT97[i] for i in range(N) if i not in mask)

def apply_col7(text):
    """Apply col7 transposition."""
    nums = [ord(c)-65 for c in text]
    transposed = [nums[PERM_COL7[i]] for i in range(len(nums))]
    return transposed

def autokey_beau_az(ct_nums, kw_nums):
    """Beaufort PT-autokey decrypt with AZ alphabet."""
    L = len(kw_nums)
    pt = []
    for i, ci in enumerate(ct_nums):
        ki = kw_nums[i] if i < L else pt[i - L]
        pt.append((ki - ci) % 26)
    return pt

def autokey_vig_az(ct_nums, kw_nums):
    """Vigenere PT-autokey decrypt with AZ alphabet."""
    L = len(kw_nums)
    pt = []
    for i, ci in enumerate(ct_nums):
        ki = kw_nums[i] if i < L else pt[i - L]
        pt.append((ci - ki) % 26)
    return pt

def autokey_beau_ka(ct_nums, kw_str):
    """Beaufort PT-autokey decrypt with KA alphabet."""
    ct_ka = [KA_IDX[chr(c+65)] for c in ct_nums]
    kw_ka = [KA_IDX[c] for c in kw_str]
    L = len(kw_ka)
    pt_ka = []
    for i, ci in enumerate(ct_ka):
        ki = kw_ka[i] if i < L else pt_ka[i - L]
        pt_ka.append((ki - ci) % 26)
    return [AZ_IDX[KA_STR[v]] for v in pt_ka]

def periodic_beau(ct_nums, key_nums):
    """Periodic Beaufort decrypt (no autokey)."""
    L = len(key_nums)
    return [(key_nums[i % L] - ci) % 26 for i, ci in enumerate(ct_nums)]

def periodic_vig(ct_nums, key_nums):
    """Periodic Vigenere decrypt (no autokey)."""
    L = len(key_nums)
    return [(ci - key_nums[i % L]) % 26 for i, ci in enumerate(ct_nums)]

def nums_to_text(nums):
    return ''.join(chr(n + 65) for n in nums)

def text_to_nums(text):
    return [ord(c) - 65 for c in text]

def count_crib_hits_73(pt_str, null_set):
    """Score crib matches in 73-char plaintext."""
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2
    e = sum(1 for j, c in enumerate(ENE_WORD) if ene_s + j < len(pt_str) and pt_str[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD) if bcl_s + j < len(pt_str) and pt_str[bcl_s + j] == c)
    return e + b, e, b

def count_crib_hits_97(text):
    """Anchored crib scoring on raw 97-char output."""
    hits = 0
    for pos, ch in CRIB_LIST:
        if pos < len(text) and text[pos] == ch:
            hits += 1
    return hits

def eval_mask_col7(null_set, kw_nums, beau=True):
    """Evaluate mask + col7 + autokey. Returns (total, ene, bcl, pt_str)."""
    ct73 = extract_73(null_set)
    ct73_t = apply_col7(ct73)
    if beau:
        pt_nums = autokey_beau_az(ct73_t, kw_nums)
    else:
        pt_nums = autokey_vig_az(ct73_t, kw_nums)
    pt_str = nums_to_text(pt_nums)
    total, e, b = count_crib_hits_73(pt_str, null_set)
    return total, e, b, pt_str

def eval_mask_col7_periodic(null_set, kw_nums, beau=True):
    """Like eval_mask_col7 but with periodic (non-autokey) cipher."""
    ct73 = extract_73(null_set)
    ct73_t = apply_col7(ct73)
    if beau:
        pt_nums = periodic_beau(ct73_t, kw_nums)
    else:
        pt_nums = periodic_vig(ct73_t, kw_nums)
    pt_str = nums_to_text(pt_nums)
    total, e, b = count_crib_hits_73(pt_str, null_set)
    return total, e, b, pt_str

def eval_mask_no_trans(null_set, kw_nums, beau=True):
    """Evaluate mask + autokey WITHOUT transposition."""
    ct73 = extract_73(null_set)
    ct73_nums = text_to_nums(ct73)
    if beau:
        pt_nums = autokey_beau_az(ct73_nums, kw_nums)
    else:
        pt_nums = autokey_vig_az(ct73_nums, kw_nums)
    pt_str = nums_to_text(pt_nums)
    total, e, b = count_crib_hits_73(pt_str, null_set)
    return total, e, b, pt_str

def eval_mask_custom_decrypt(null_set, decrypt_fn, use_col7=True):
    """Evaluate mask with a custom decrypt function on the 73-char text."""
    ct73 = extract_73(null_set)
    if use_col7:
        ct73_nums = apply_col7(ct73)
    else:
        ct73_nums = text_to_nums(ct73)
    pt_nums = decrypt_fn(ct73_nums)
    pt_str = nums_to_text(pt_nums)
    total, e, b = count_crib_hits_73(pt_str, null_set)
    return total, e, b, pt_str

# ---- Quagmire decrypt ----
def quagmire_decrypt(ct_nums, key_nums, pt_alpha, ct_alpha, key_col_idx):
    """General Quagmire decrypt.
    ct_alpha: CT alphabet (for finding position of CT char)
    pt_alpha: PT alphabet (for output)
    key_col_idx: column where key is read (usually index of 'A' in ct_alpha)
    """
    ct_alpha_idx = {c: i for i, c in enumerate(ct_alpha)}
    pt_alpha_idx = {c: i for i, c in enumerate(pt_alpha)}
    L = len(key_nums)
    pt = []
    for i, ci_num in enumerate(ct_nums):
        ci_char = chr(ci_num + 65)
        # Find position in shifted CT alphabet
        ki = key_nums[i % L]
        # Row alphabet is ct_alpha shifted so that key letter is at key_col position
        ct_pos = ct_alpha_idx.get(ci_char, ci_num)
        # Shift to find plain position
        plain_pos = (ct_pos - ki + key_col_idx) % 26
        pt.append(plain_pos)
    return pt

# ====================================================================
# SA helper
# ====================================================================
def sa_optimize_mask(decrypt_fn, n_restarts=30, steps=5000, use_col7=True):
    """SA to optimize null mask for a given decrypt function."""
    best_overall = (0, None, "", 0, 0)  # (score, mask, pt, ene, bcl)
    all_results = []

    for restart in range(n_restarts):
        rng = random.Random(restart * 1000 + 42)
        pool = list(NON_CRIB)
        null_set = set(rng.sample(pool, N_NULLS))
        non_null = NC_SET - null_set

        total, e, b, pt = eval_mask_custom_decrypt(frozenset(null_set), decrypt_fn, use_col7)
        score = float(total)
        best_sc = score
        best_null = frozenset(null_set)
        best_pt = pt
        best_e, best_b = e, b

        T0, Tf = 0.5, 0.01
        for step in range(steps):
            T = T0 * (Tf / T0) ** (step / steps)
            cands = list(null_set)
            nn_list = list(non_null)
            if not cands or not nn_list:
                break
            out = rng.choice(cands)
            into = rng.choice(nn_list)
            null_set = (null_set - {out}) | {into}
            non_null = (non_null - {into}) | {out}
            total, e, b, pt = eval_mask_custom_decrypt(frozenset(null_set), decrypt_fn, use_col7)
            new_sc = float(total)
            delta = new_sc - score
            if delta > 0 or rng.random() < math.exp(delta / max(T, 0.001)):
                score = new_sc
                if score > best_sc:
                    best_sc = score
                    best_null = frozenset(null_set)
                    best_pt = pt
                    best_e, best_b = e, b
            else:
                null_set = (null_set - {into}) | {out}
                non_null = (non_null - {out}) | {into}

        all_results.append((best_sc, sorted(best_null), best_pt[:73], best_e, best_b))
        if best_sc > best_overall[0]:
            best_overall = (best_sc, sorted(best_null), best_pt, best_e, best_b)

    return best_overall, all_results

# ====================================================================
# TEST 1: Combined keyword as periodic key
# ====================================================================
def test1_combined_periodic():
    print("\n" + "="*70)
    print("TEST 1: Combined keyword as periodic key (col7 + both masks)")
    print("="*70)

    results = []

    # Build combined keywords
    DEF = "DEFECTOR"
    PAL = "PALIMPSEST"

    combined_keywords = {
        "DEFECTORPALIMPSEST": [ord(c)-65 for c in DEF + PAL],
        "PALIMPSESTDEFECTOR": [ord(c)-65 for c in PAL + DEF],
        "interleaved_DP": [ord(c)-65 for c in ''.join(d+p for d,p in zip(DEF, PAL[:8])) + PAL[8:]],
        "sum_mod26": [((DEFECTOR_NUMS[i%8] + PALIMPSEST_NUMS[i%10]) % 26) for i in range(40)],
        "diff_DP": [((DEFECTOR_NUMS[i%8] - PALIMPSEST_NUMS[i%10]) % 26) for i in range(40)],
        "diff_PD": [((PALIMPSEST_NUMS[i%10] - DEFECTOR_NUMS[i%8]) % 26) for i in range(40)],
        "xor_mod26": [((DEFECTOR_NUMS[i%8] ^ PALIMPSEST_NUMS[i%10]) % 26) for i in range(40)],
    }

    for mask_name, mask in [("DEF_MASK", DEF_MASK), ("PAL_MASK", PAL_MASK)]:
        for kw_name, kw_nums in combined_keywords.items():
            for beau in [True, False]:
                cipher = "beau" if beau else "vig"
                # With col7 + autokey
                total, e, b, pt = eval_mask_col7(mask, kw_nums, beau)
                results.append({
                    'test': 1, 'sub': 'autokey_col7',
                    'key': kw_name, 'mask': mask_name, 'cipher': cipher,
                    'score': total, 'ene': e, 'bcl': b,
                    'pt': pt[:60],
                })
                if total >= 16:
                    print(f"  ** HIT {total}/24 ** {kw_name}:{cipher}:{mask_name} (e={e},b={b})")

                # With col7 + periodic
                total_p, e_p, b_p, pt_p = eval_mask_col7_periodic(mask, kw_nums, beau)
                results.append({
                    'test': 1, 'sub': 'periodic_col7',
                    'key': kw_name, 'mask': mask_name, 'cipher': cipher,
                    'score': total_p, 'ene': e_p, 'bcl': b_p,
                    'pt': pt_p[:60],
                })
                if total_p >= 16:
                    print(f"  ** HIT {total_p}/24 ** {kw_name}:{cipher}:{mask_name} periodic (e={e_p},b={b_p})")

                # Without transposition + autokey
                total_nt, e_nt, b_nt, pt_nt = eval_mask_no_trans(mask, kw_nums, beau)
                results.append({
                    'test': 1, 'sub': 'autokey_no_trans',
                    'key': kw_name, 'mask': mask_name, 'cipher': cipher,
                    'score': total_nt, 'ene': e_nt, 'bcl': b_nt,
                    'pt': pt_nt[:60],
                })
                if total_nt >= 16:
                    print(f"  ** HIT {total_nt}/24 ** {kw_name}:{cipher}:{mask_name} no_trans (e={e_nt},b={b_nt})")

    best = max(results, key=lambda r: r['score'])
    print(f"\n  Test 1 best: {best['score']}/24 — {best['key']}:{best['cipher']}:{best['mask']} [{best['sub']}] (e={best['ene']},b={best['bcl']})")
    return results

# ====================================================================
# TEST 2: Two-stage cipher
# ====================================================================
def test2_two_stage():
    print("\n" + "="*70)
    print("TEST 2: Two-stage cipher (Beaufort with each keyword in sequence)")
    print("="*70)

    results = []

    for mask_name, mask in [("DEF_MASK", DEF_MASK), ("PAL_MASK", PAL_MASK)]:
        ct73 = extract_73(mask)

        for use_col7 in [True, False]:
            trans_label = "col7" if use_col7 else "notrans"
            if use_col7:
                ct73_nums = apply_col7(ct73)
            else:
                ct73_nums = text_to_nums(ct73)

            # Stage orders: DEF then PAL, PAL then DEF
            for order_name, kw1, kw2 in [
                ("DEF_then_PAL", DEFECTOR_NUMS, PALIMPSEST_NUMS),
                ("PAL_then_DEF", PALIMPSEST_NUMS, DEFECTOR_NUMS),
            ]:
                for c1_name, c1_fn in [("beau", periodic_beau), ("vig", periodic_vig)]:
                    for c2_name, c2_fn in [("beau", periodic_beau), ("vig", periodic_vig)]:
                        # Two-stage periodic
                        intermediate = c1_fn(ct73_nums, kw1)
                        pt_nums = c2_fn(intermediate, kw2)
                        pt_str = nums_to_text(pt_nums)
                        total, e, b = count_crib_hits_73(pt_str, mask)

                        results.append({
                            'test': 2, 'sub': f'periodic_{c1_name}_{c2_name}',
                            'order': order_name, 'trans': trans_label, 'mask': mask_name,
                            'score': total, 'ene': e, 'bcl': b,
                            'pt': pt_str[:60],
                        })
                        if total >= 16:
                            print(f"  ** HIT {total}/24 ** {order_name}:{c1_name}+{c2_name}:{trans_label}:{mask_name} (e={e},b={b})")

                # Two-stage autokey
                for c1_name, c1_fn in [("beau_ak", autokey_beau_az), ("vig_ak", autokey_vig_az)]:
                    for c2_name, c2_fn in [("beau_ak", autokey_beau_az), ("vig_ak", autokey_vig_az)]:
                        intermediate = c1_fn(ct73_nums, kw1)
                        pt_nums = c2_fn(intermediate, kw2)
                        pt_str = nums_to_text(pt_nums)
                        total, e, b = count_crib_hits_73(pt_str, mask)

                        results.append({
                            'test': 2, 'sub': f'autokey_{c1_name}_{c2_name}',
                            'order': order_name, 'trans': trans_label, 'mask': mask_name,
                            'score': total, 'ene': e, 'bcl': b,
                            'pt': pt_str[:60],
                        })
                        if total >= 16:
                            print(f"  ** HIT {total}/24 ** {order_name}:{c1_name}+{c2_name}:{trans_label}:{mask_name} autokey (e={e},b={b})")

    best = max(results, key=lambda r: r['score'])
    print(f"\n  Test 2 best: {best['score']}/24 — {best['order']}:{best['sub']}:{best['trans']}:{best['mask']} (e={best['ene']},b={best['bcl']})")
    return results

# ====================================================================
# TEST 3: Alternating keys by position
# ====================================================================
def test3_alternating():
    print("\n" + "="*70)
    print("TEST 3: Alternating keys by position")
    print("="*70)

    results = []

    def make_alternating_key(n, mode):
        """Generate position-dependent key from DEFECTOR and PALIMPSEST."""
        key = []
        for i in range(n):
            if mode == 'even_odd':
                # Even positions use DEFECTOR, odd use PALIMPSEST
                if i % 2 == 0:
                    key.append(DEFECTOR_NUMS[i % 8])
                else:
                    key.append(PALIMPSEST_NUMS[i % 10])
            elif mode == 'odd_even':
                if i % 2 == 1:
                    key.append(DEFECTOR_NUMS[i % 8])
                else:
                    key.append(PALIMPSEST_NUMS[i % 10])
            elif mode == 'mod3_012':
                r = i % 3
                if r == 0:
                    key.append(DEFECTOR_NUMS[i % 8])
                elif r == 1:
                    key.append(PALIMPSEST_NUMS[i % 10])
                else:
                    key.append((DEFECTOR_NUMS[i % 8] + PALIMPSEST_NUMS[i % 10]) % 26)
            elif mode == 'ene_def_bcl_pal':
                # ENE region uses DEFECTOR, BCL region uses PALIMPSEST
                key.append(DEFECTOR_NUMS[i % 8])  # will be overridden
            elif mode == 'ene_pal_bcl_def':
                key.append(PALIMPSEST_NUMS[i % 10])
            elif mode == 'block8_10':
                # First 8 chars use DEFECTOR, next 10 use PALIMPSEST, repeat
                block_pos = i % 18
                if block_pos < 8:
                    key.append(DEFECTOR_NUMS[block_pos])
                else:
                    key.append(PALIMPSEST_NUMS[block_pos - 8])
            elif mode == 'block10_8':
                block_pos = i % 18
                if block_pos < 10:
                    key.append(PALIMPSEST_NUMS[block_pos])
                else:
                    key.append(DEFECTOR_NUMS[block_pos - 10])
        return key

    modes = ['even_odd', 'odd_even', 'mod3_012', 'block8_10', 'block10_8']

    for mask_name, mask in [("DEF_MASK", DEF_MASK), ("PAL_MASK", PAL_MASK)]:
        for mode in modes:
            key_nums = make_alternating_key(N_PT, mode)

            for beau in [True, False]:
                cipher = "beau" if beau else "vig"
                # col7 periodic
                total, e, b, pt = eval_mask_col7_periodic(mask, key_nums, beau)
                results.append({
                    'test': 3, 'mode': mode, 'cipher': cipher, 'mask': mask_name,
                    'sub': 'periodic_col7',
                    'score': total, 'ene': e, 'bcl': b, 'pt': pt[:60],
                })
                if total >= 16:
                    print(f"  ** HIT {total}/24 ** {mode}:{cipher}:{mask_name} periodic_col7 (e={e},b={b})")

                # no trans periodic
                ct73 = extract_73(mask)
                ct73_nums = text_to_nums(ct73)
                if beau:
                    pt_nums = periodic_beau(ct73_nums, key_nums)
                else:
                    pt_nums = periodic_vig(ct73_nums, key_nums)
                pt_str = nums_to_text(pt_nums)
                total2, e2, b2 = count_crib_hits_73(pt_str, mask)
                results.append({
                    'test': 3, 'mode': mode, 'cipher': cipher, 'mask': mask_name,
                    'sub': 'periodic_notrans',
                    'score': total2, 'ene': e2, 'bcl': b2, 'pt': pt_str[:60],
                })
                if total2 >= 16:
                    print(f"  ** HIT {total2}/24 ** {mode}:{cipher}:{mask_name} periodic_notrans (e={e2},b={b2})")

    # Region-based alternation: ENE region gets one keyword, BCL region gets the other
    for mask_name, mask in [("DEF_MASK", DEF_MASK), ("PAL_MASK", PAL_MASK)]:
        n1 = sum(1 for p in mask if p < ENE_START)
        n2 = sum(1 for p in mask if p < BCL_START)
        ene_s = ENE_START - n1
        bcl_s = BCL_START - n2

        for ene_kw_name, ene_kw, bcl_kw_name, bcl_kw in [
            ("DEF", DEFECTOR_NUMS, "PAL", PALIMPSEST_NUMS),
            ("PAL", PALIMPSEST_NUMS, "DEF", DEFECTOR_NUMS),
        ]:
            # Build position-dependent key
            key_73 = []
            for i in range(N_PT):
                if ene_s <= i < ene_s + 13:
                    key_73.append(ene_kw[i % len(ene_kw)])
                elif bcl_s <= i < bcl_s + 11:
                    key_73.append(bcl_kw[i % len(bcl_kw)])
                else:
                    # Non-crib: use whichever keyword
                    key_73.append(ene_kw[i % len(ene_kw)])

            for beau in [True, False]:
                cipher = "beau" if beau else "vig"
                ct73 = extract_73(mask)
                ct73_t = apply_col7(ct73)
                if beau:
                    pt_nums = periodic_beau(ct73_t, key_73)
                else:
                    pt_nums = periodic_vig(ct73_t, key_73)
                pt_str = nums_to_text(pt_nums)
                total, e, b = count_crib_hits_73(pt_str, mask)
                results.append({
                    'test': 3, 'mode': f'region_ene={ene_kw_name}_bcl={bcl_kw_name}',
                    'cipher': cipher, 'mask': mask_name, 'sub': 'region_col7',
                    'score': total, 'ene': e, 'bcl': b, 'pt': pt_str[:60],
                })
                if total >= 16:
                    print(f"  ** HIT {total}/24 ** region(ene={ene_kw_name},bcl={bcl_kw_name}):{cipher}:{mask_name} col7 (e={e},b={b})")

    best = max(results, key=lambda r: r['score'])
    print(f"\n  Test 3 best: {best['score']}/24 — {best['mode']}:{best['cipher']}:{best['mask']} [{best['sub']}] (e={best['ene']},b={best['bcl']})")
    return results

# ====================================================================
# TEST 4: SA over mask with combined keys (30 restarts each)
# ====================================================================
def test4_sa_combined():
    print("\n" + "="*70)
    print("TEST 4: SA over mask with combined keys (30 restarts, 5000 steps)")
    print("="*70)

    results = []

    # Build combined keys to test
    combined_keys = {
        'sum_mod26_40': [(DEFECTOR_NUMS[i%8] + PALIMPSEST_NUMS[i%10]) % 26 for i in range(40)],
        'DEFECTORPALIMPSEST': [ord(c)-65 for c in "DEFECTORPALIMPSEST"],
        'PALIMPSESTDEFECTOR': [ord(c)-65 for c in "PALIMPSESTDEFECTOR"],
        'even_odd_beau': None,  # special: handled inline
        'two_stage_def_pal_beau': None,  # special
        'two_stage_pal_def_beau': None,  # special
    }

    for key_name, key_nums in combined_keys.items():
        if key_nums is None:
            continue

        for beau in [True, False]:
            cipher = "beau" if beau else "vig"
            print(f"  SA: {key_name}:{cipher} ...", end='', flush=True)

            if len(key_nums) <= 26:
                # Autokey
                def decrypt_fn(ct_nums, _kn=key_nums, _b=beau):
                    if _b:
                        return autokey_beau_az(ct_nums, _kn)
                    else:
                        return autokey_vig_az(ct_nums, _kn)
            else:
                # Periodic for long keys
                def decrypt_fn(ct_nums, _kn=key_nums, _b=beau):
                    if _b:
                        return periodic_beau(ct_nums, _kn)
                    else:
                        return periodic_vig(ct_nums, _kn)

            best, all_res = sa_optimize_mask(decrypt_fn, n_restarts=30, steps=5000, use_col7=True)
            score_dist = Counter(int(r[0]) for r in all_res)

            results.append({
                'test': 4, 'key': key_name, 'cipher': cipher,
                'best_score': best[0], 'ene': best[3], 'bcl': best[4],
                'mask': best[1], 'pt': best[2][:60],
                'score_dist': dict(score_dist),
            })

            n15 = sum(1 for r in all_res if r[0] >= 15)
            n16 = sum(1 for r in all_res if r[0] >= 16)
            print(f" best={best[0]}/24 (e={best[3]},b={best[4]}), >=15: {n15}/30, >=16: {n16}/30")
            if best[0] >= 16:
                print(f"    ** HIT {best[0]}/24 ** mask={best[1]}, pt={best[2][:60]}")

    # Special: even/odd alternating autokey with SA
    print(f"  SA: even_odd alternating Beau ...", end='', flush=True)
    def decrypt_even_odd_beau(ct_nums):
        L_d = len(DEFECTOR_NUMS)
        L_p = len(PALIMPSEST_NUMS)
        pt = []
        for i, ci in enumerate(ct_nums):
            if i % 2 == 0:
                ki = DEFECTOR_NUMS[i % L_d] if i < L_d else pt[i - L_d] if i >= L_d else DEFECTOR_NUMS[i]
            else:
                ki = PALIMPSEST_NUMS[i % L_p] if i < L_p else pt[i - L_p] if i >= L_p else PALIMPSEST_NUMS[i]
            pt.append((ki - ci) % 26)
        return pt
    best_eo, all_eo = sa_optimize_mask(decrypt_even_odd_beau, n_restarts=30, steps=5000, use_col7=True)
    n15 = sum(1 for r in all_eo if r[0] >= 15)
    print(f" best={best_eo[0]}/24 (e={best_eo[3]},b={best_eo[4]}), >=15: {n15}/30")
    results.append({
        'test': 4, 'key': 'even_odd_beau', 'cipher': 'beau_alt',
        'best_score': best_eo[0], 'ene': best_eo[3], 'bcl': best_eo[4],
        'mask': best_eo[1], 'pt': best_eo[2][:60],
    })

    # Special: two-stage SA (Beau DEF then Beau PAL)
    for stage_name, kw1, kw2 in [
        ("two_stage_DP_beau", DEFECTOR_NUMS, PALIMPSEST_NUMS),
        ("two_stage_PD_beau", PALIMPSEST_NUMS, DEFECTOR_NUMS),
    ]:
        print(f"  SA: {stage_name} ...", end='', flush=True)
        def decrypt_two_stage(ct_nums, _kw1=kw1, _kw2=kw2):
            intermediate = autokey_beau_az(ct_nums, _kw1)
            return autokey_beau_az(intermediate, _kw2)
        best_ts, all_ts = sa_optimize_mask(decrypt_two_stage, n_restarts=30, steps=5000, use_col7=True)
        n15 = sum(1 for r in all_ts if r[0] >= 15)
        print(f" best={best_ts[0]}/24 (e={best_ts[3]},b={best_ts[4]}), >=15: {n15}/30")
        results.append({
            'test': 4, 'key': stage_name, 'cipher': 'beau+beau',
            'best_score': best_ts[0], 'ene': best_ts[3], 'bcl': best_ts[4],
            'mask': best_ts[1], 'pt': best_ts[2][:60],
        })
        if best_ts[0] >= 16:
            print(f"    ** HIT {best_ts[0]}/24 ** mask={best_ts[1]}, pt={best_ts[2][:60]}")

    best = max(results, key=lambda r: r['best_score'])
    print(f"\n  Test 4 best: {best['best_score']}/24 — {best['key']}:{best['cipher']} (e={best['ene']},b={best['bcl']})")
    return results

# ====================================================================
# TEST 5: Hybrid key from known correct values (try all 26^3 at misses)
# ====================================================================
def test5_hybrid_key():
    print("\n" + "="*70)
    print("TEST 5: Hybrid key from correct crib values + brute force misses")
    print("="*70)

    results = []

    # Compute correct Beaufort key at crib positions for each mask
    for mask_name, mask in [("DEF_MASK", DEF_MASK), ("PAL_MASK", PAL_MASK)]:
        ct73 = extract_73(mask)
        ct73_t = apply_col7(ct73)  # After col7 transposition

        n1 = sum(1 for p in mask if p < ENE_START)
        n2 = sum(1 for p in mask if p < BCL_START)
        ene_s = ENE_START - n1
        bcl_s = BCL_START - n2

        correct_keys = {}
        crib_positions = []

        # ENE positions
        for j, c in enumerate(ENE_WORD):
            pos = ene_s + j
            if pos < N_PT:
                pt_val = ord(c) - 65
                ct_val = ct73_t[pos]
                beau_key = (ct_val + pt_val) % 26
                correct_keys[pos] = beau_key
                crib_positions.append(pos)

        # BCL positions
        for j, c in enumerate(BCL_WORD):
            pos = bcl_s + j
            if pos < N_PT:
                pt_val = ord(c) - 65
                ct_val = ct73_t[pos]
                beau_key = (ct_val + pt_val) % 26
                correct_keys[pos] = beau_key
                crib_positions.append(pos)

        print(f"\n  {mask_name} correct Beaufort keys at crib positions:")
        key_str = ''.join(chr(correct_keys[p] + 65) for p in sorted(correct_keys))
        print(f"    Keys: {key_str}")
        print(f"    Values: {[correct_keys[p] for p in sorted(correct_keys)]}")

        results.append({
            'test': 5, 'mask': mask_name,
            'correct_keys': {str(k): v for k, v in correct_keys.items()},
            'key_str': key_str,
        })

    # Now compare the two key sets
    print("\n  Comparing key values between DEFECTOR and PALIMPSEST masks:")

    # Build both key sequences
    for mask_name, mask in [("DEF_MASK", DEF_MASK), ("PAL_MASK", PAL_MASK)]:
        ct73 = extract_73(mask)
        ct73_t = apply_col7(ct73)
        n1 = sum(1 for p in mask if p < ENE_START)
        n2 = sum(1 for p in mask if p < BCL_START)
        ene_s = ENE_START - n1
        bcl_s = BCL_START - n2

        # Full key sequence at all 73 positions (if we knew PT)
        # We can only compute at crib positions
        keys_at_cribs = []
        for j, c in enumerate(ENE_WORD):
            pos = ene_s + j
            if pos < N_PT:
                pt_val = ord(c) - 65
                ct_val = ct73_t[pos]
                keys_at_cribs.append((pos, (ct_val + pt_val) % 26))
        for j, c in enumerate(BCL_WORD):
            pos = bcl_s + j
            if pos < N_PT:
                pt_val = ord(c) - 65
                ct_val = ct73_t[pos]
                keys_at_cribs.append((pos, (ct_val + pt_val) % 26))

        print(f"\n    {mask_name} key@cribs: {[(p, chr(k+65)) for p, k in keys_at_cribs]}")

    return results

# ====================================================================
# TEST 6: Correct key analysis at all 24 crib positions for both masks
# ====================================================================
def test6_key_analysis():
    print("\n" + "="*70)
    print("TEST 6: Correct key analysis at crib positions for both masks")
    print("="*70)

    results = {}

    for mask_name, mask in [("DEF_MASK", DEF_MASK), ("PAL_MASK", PAL_MASK)]:
        ct73 = extract_73(mask)
        ct73_t = apply_col7(ct73)

        n1 = sum(1 for p in mask if p < ENE_START)
        n2 = sum(1 for p in mask if p < BCL_START)
        ene_s = ENE_START - n1
        bcl_s = BCL_START - n2

        ene_keys = []
        bcl_keys = []

        for j, c in enumerate(ENE_WORD):
            pos = ene_s + j
            pt_val = ord(c) - 65
            ct_val = ct73_t[pos]
            beau_key = (ct_val + pt_val) % 26
            vig_key = (ct_val - pt_val) % 26
            ene_keys.append({
                'pos73': pos, 'pt': c, 'ct': chr(ct_val+65),
                'beau_key': beau_key, 'beau_key_ch': chr(beau_key+65),
                'vig_key': vig_key, 'vig_key_ch': chr(vig_key+65),
            })

        for j, c in enumerate(BCL_WORD):
            pos = bcl_s + j
            pt_val = ord(c) - 65
            ct_val = ct73_t[pos]
            beau_key = (ct_val + pt_val) % 26
            vig_key = (ct_val - pt_val) % 26
            bcl_keys.append({
                'pos73': pos, 'pt': c, 'ct': chr(ct_val+65),
                'beau_key': beau_key, 'beau_key_ch': chr(beau_key+65),
                'vig_key': vig_key, 'vig_key_ch': chr(vig_key+65),
            })

        all_beau = [k['beau_key'] for k in ene_keys + bcl_keys]
        all_vig = [k['vig_key'] for k in ene_keys + bcl_keys]

        print(f"\n  {mask_name}:")
        print(f"    ENE Beaufort keys: {''.join(k['beau_key_ch'] for k in ene_keys)}")
        print(f"    BCL Beaufort keys: {''.join(k['beau_key_ch'] for k in bcl_keys)}")
        print(f"    ENE Vigenere keys: {''.join(k['vig_key_ch'] for k in ene_keys)}")
        print(f"    BCL Vigenere keys: {''.join(k['vig_key_ch'] for k in bcl_keys)}")

        # Check if keys match DEFECTOR periodic
        def_match = sum(1 for i, k in enumerate(all_beau) if k == DEFECTOR_NUMS[i % 8])
        pal_match = sum(1 for i, k in enumerate(all_beau) if k == PALIMPSEST_NUMS[i % 10])
        print(f"    DEFECTOR periodic match (Beau): {def_match}/24")
        print(f"    PALIMPSEST periodic match (Beau): {pal_match}/24")

        # Check autokey match for DEFECTOR
        # Under PT-autokey offset=8: key[i] = PT[i-8] if i>=8
        ene_pt = [ord(c)-65 for c in ENE_WORD]
        bcl_pt = [ord(c)-65 for c in BCL_WORD]

        # IC of key values
        beau_ic = ic(''.join(chr(k+65) for k in all_beau))
        vig_ic = ic(''.join(chr(k+65) for k in all_vig))
        print(f"    Beaufort key IC: {beau_ic:.4f} (random=0.0385, English=0.065)")
        print(f"    Vigenere key IC: {vig_ic:.4f}")

        # Check for AP pattern (step-4)
        beau_counter = Counter(all_beau)
        print(f"    Top Beaufort key values: {beau_counter.most_common(5)}")

        results[mask_name] = {
            'ene_keys': ene_keys,
            'bcl_keys': bcl_keys,
            'beau_ic': beau_ic,
            'vig_ic': vig_ic,
            'def_periodic_match': def_match,
            'pal_periodic_match': pal_match,
        }

    # Cross-comparison
    def_beau = [k['beau_key'] for k in results['DEF_MASK']['ene_keys'] + results['DEF_MASK']['bcl_keys']]
    pal_beau = [k['beau_key'] for k in results['PAL_MASK']['ene_keys'] + results['PAL_MASK']['bcl_keys']]

    matches = sum(1 for d, p in zip(def_beau, pal_beau) if d == p)
    diffs = [(d - p) % 26 for d, p in zip(def_beau, pal_beau)]
    print(f"\n  Cross-comparison (DEF vs PAL Beaufort keys):")
    print(f"    Exact matches: {matches}/24")
    print(f"    Differences: {diffs}")
    print(f"    Diff counter: {Counter(diffs).most_common()}")

    return results

# ====================================================================
# TEST 7: PALIMPSEST as alphabet, DEFECTOR as key (and vice versa)
# ====================================================================
def test7_mixed_alphabets():
    print("\n" + "="*70)
    print("TEST 7: Keyword-mixed alphabets (one keyword as alpha, other as key)")
    print("="*70)

    results = []

    alpha_configs = [
        ("PAL_alpha_DEF_key", PALIMPSEST_ALPHA, PAL_ALPHA_IDX, DEFECTOR_NUMS, "DEFECTOR"),
        ("DEF_alpha_PAL_key", DEFECTOR_ALPHA, DEF_ALPHA_IDX, PALIMPSEST_NUMS, "PALIMPSEST"),
        ("PAL_alpha_PAL_key", PALIMPSEST_ALPHA, PAL_ALPHA_IDX, PALIMPSEST_NUMS, "PALIMPSEST"),
        ("DEF_alpha_DEF_key", DEFECTOR_ALPHA, DEF_ALPHA_IDX, DEFECTOR_NUMS, "DEFECTOR"),
    ]

    for config_name, alpha_str, alpha_idx, key_nums, key_str in alpha_configs:
        for mask_name, mask in [("DEF_MASK", DEF_MASK), ("PAL_MASK", PAL_MASK)]:
            ct73 = extract_73(mask)

            for use_col7 in [True, False]:
                if use_col7:
                    ct73_nums = apply_col7(ct73)
                else:
                    ct73_nums = text_to_nums(ct73)

                # Convert CT to custom alphabet indices
                ct73_custom = []
                for c_num in ct73_nums:
                    c_char = chr(c_num + 65)
                    ct73_custom.append(alpha_idx.get(c_char, c_num))

                # Beaufort periodic
                L = len(key_nums)
                key_custom = [alpha_idx.get(c, ord(c)-65) for c in key_str]
                pt_indices = [(key_custom[i % L] - ci) % 26 for i, ci in enumerate(ct73_custom)]
                pt_str = ''.join(alpha_str[p] for p in pt_indices)
                total, e, b = count_crib_hits_73(pt_str, mask)
                trans_label = "col7" if use_col7 else "notrans"

                results.append({
                    'test': 7, 'config': config_name, 'cipher': 'beau_periodic',
                    'mask': mask_name, 'trans': trans_label,
                    'score': total, 'ene': e, 'bcl': b, 'pt': pt_str[:60],
                })
                if total >= 16:
                    print(f"  ** HIT {total}/24 ** {config_name}:beau_periodic:{trans_label}:{mask_name} (e={e},b={b})")

                # Vigenere periodic
                pt_indices_v = [(ci - key_custom[i % L]) % 26 for i, ci in enumerate(ct73_custom)]
                pt_str_v = ''.join(alpha_str[p] for p in pt_indices_v)
                total_v, e_v, b_v = count_crib_hits_73(pt_str_v, mask)

                results.append({
                    'test': 7, 'config': config_name, 'cipher': 'vig_periodic',
                    'mask': mask_name, 'trans': trans_label,
                    'score': total_v, 'ene': e_v, 'bcl': b_v, 'pt': pt_str_v[:60],
                })
                if total_v >= 16:
                    print(f"  ** HIT {total_v}/24 ** {config_name}:vig_periodic:{trans_label}:{mask_name} (e={e_v},b={b_v})")

                # Beaufort autokey with custom alphabet
                pt_ak = []
                pt_ak_idx = []
                for i, ci in enumerate(ct73_custom):
                    ki = key_custom[i % L] if i < L else pt_ak_idx[i - L]
                    pi = (ki - ci) % 26
                    pt_ak_idx.append(pi)
                    pt_ak.append(alpha_str[pi])
                pt_ak_str = ''.join(pt_ak)
                total_ak, e_ak, b_ak = count_crib_hits_73(pt_ak_str, mask)

                results.append({
                    'test': 7, 'config': config_name, 'cipher': 'beau_autokey',
                    'mask': mask_name, 'trans': trans_label,
                    'score': total_ak, 'ene': e_ak, 'bcl': b_ak, 'pt': pt_ak_str[:60],
                })
                if total_ak >= 16:
                    print(f"  ** HIT {total_ak}/24 ** {config_name}:beau_autokey:{trans_label}:{mask_name} (e={e_ak},b={b_ak})")

    best = max(results, key=lambda r: r['score'])
    print(f"\n  Test 7 best: {best['score']}/24 — {best['config']}:{best['cipher']}:{best['trans']}:{best['mask']} (e={best['ene']},b={best['bcl']})")
    return results

# ====================================================================
# TEST 8: Quagmire variants
# ====================================================================
def test8_quagmire():
    print("\n" + "="*70)
    print("TEST 8: Quagmire variants with DEFECTOR and PALIMPSEST")
    print("="*70)

    results = []

    quag_configs = [
        # Q1: PT alpha = keyword-mixed, CT alpha = standard, key = other keyword
        ("Q1_PAL_alpha_DEF_key", PALIMPSEST_ALPHA, AZ, DEFECTOR_NUMS),
        ("Q1_DEF_alpha_PAL_key", DEFECTOR_ALPHA, AZ, PALIMPSEST_NUMS),
        # Q2: CT alpha = keyword-mixed, key = other keyword
        ("Q2_PAL_ct_DEF_key", AZ, PALIMPSEST_ALPHA, DEFECTOR_NUMS),
        ("Q2_DEF_ct_PAL_key", AZ, DEFECTOR_ALPHA, PALIMPSEST_NUMS),
        # Q3: Both alphabets = keyword-mixed, key = other keyword
        ("Q3_PAL_both_DEF_key", PALIMPSEST_ALPHA, PALIMPSEST_ALPHA, DEFECTOR_NUMS),
        ("Q3_DEF_both_PAL_key", DEFECTOR_ALPHA, DEFECTOR_ALPHA, PALIMPSEST_NUMS),
        # Q3: Both = same keyword, key = same
        ("Q3_PAL_both_PAL_key", PALIMPSEST_ALPHA, PALIMPSEST_ALPHA, PALIMPSEST_NUMS),
        ("Q3_DEF_both_DEF_key", DEFECTOR_ALPHA, DEFECTOR_ALPHA, DEFECTOR_NUMS),
        # Cross Q3
        ("Q3_PAL_pt_DEF_ct_DEF_key", PALIMPSEST_ALPHA, DEFECTOR_ALPHA, DEFECTOR_NUMS),
        ("Q3_DEF_pt_PAL_ct_PAL_key", DEFECTOR_ALPHA, PALIMPSEST_ALPHA, PALIMPSEST_NUMS),
        ("Q3_PAL_pt_DEF_ct_PAL_key", PALIMPSEST_ALPHA, DEFECTOR_ALPHA, PALIMPSEST_NUMS),
        ("Q3_DEF_pt_PAL_ct_DEF_key", DEFECTOR_ALPHA, PALIMPSEST_ALPHA, DEFECTOR_NUMS),
    ]

    for mask_name, mask in [("DEF_MASK", DEF_MASK), ("PAL_MASK", PAL_MASK)]:
        ct73 = extract_73(mask)

        for use_col7 in [True, False]:
            if use_col7:
                ct73_nums = apply_col7(ct73)
            else:
                ct73_nums = text_to_nums(ct73)

            trans_label = "col7" if use_col7 else "notrans"

            for qname, pt_alpha, ct_alpha, key_nums in quag_configs:
                ct_idx = {c: i for i, c in enumerate(ct_alpha)}
                pt_idx = {c: i for i, c in enumerate(pt_alpha)}
                L = len(key_nums)

                pt_chars = []
                for i, ci_num in enumerate(ct73_nums):
                    ci_char = chr(ci_num + 65)
                    ki = key_nums[i % L]

                    # In Quagmire: shift CT alphabet by key amount, find CT char, map to PT
                    ct_pos = ct_idx.get(ci_char, ci_num)
                    # Beaufort-style: pt_pos = (ki - ct_pos) mod 26
                    pt_pos_beau = (ki - ct_pos) % 26
                    pt_chars_beau = pt_alpha[pt_pos_beau]
                    # Vig-style: pt_pos = (ct_pos - ki) mod 26
                    pt_pos_vig = (ct_pos - ki) % 26
                    pt_chars_vig = pt_alpha[pt_pos_vig]

                    pt_chars.append((pt_chars_beau, pt_chars_vig))

                for cipher_name, idx in [("beau", 0), ("vig", 1)]:
                    pt_str = ''.join(p[idx] for p in pt_chars)
                    total, e, b = count_crib_hits_73(pt_str, mask)

                    results.append({
                        'test': 8, 'quag': qname, 'cipher': cipher_name,
                        'mask': mask_name, 'trans': trans_label,
                        'score': total, 'ene': e, 'bcl': b, 'pt': pt_str[:60],
                    })
                    if total >= 16:
                        print(f"  ** HIT {total}/24 ** {qname}:{cipher_name}:{trans_label}:{mask_name} (e={e},b={b})")

    best = max(results, key=lambda r: r['score'])
    print(f"\n  Test 8 best: {best['score']}/24 — {best['quag']}:{best['cipher']}:{best['trans']}:{best['mask']} (e={best['ene']},b={best['bcl']})")
    return results

# ====================================================================
# TEST 9: LCM analysis (period 40 combined key)
# ====================================================================
def test9_lcm():
    print("\n" + "="*70)
    print("TEST 9: LCM analysis — period 40 combined key (lcm(8,10)=40)")
    print("="*70)

    results = []

    # Build period-40 combined keys
    key_add = [(DEFECTOR_NUMS[i%8] + PALIMPSEST_NUMS[i%10]) % 26 for i in range(40)]
    key_sub_dp = [(DEFECTOR_NUMS[i%8] - PALIMPSEST_NUMS[i%10]) % 26 for i in range(40)]
    key_sub_pd = [(PALIMPSEST_NUMS[i%10] - DEFECTOR_NUMS[i%8]) % 26 for i in range(40)]
    key_xor = [(DEFECTOR_NUMS[i%8] ^ PALIMPSEST_NUMS[i%10]) % 26 for i in range(40)]

    # Also try: at position i, key = DEF[i%8] if DEF[i%8] == PAL[i%10], else sum
    key_agree_or_sum = []
    for i in range(40):
        d = DEFECTOR_NUMS[i % 8]
        p = PALIMPSEST_NUMS[i % 10]
        key_agree_or_sum.append(d if d == p else (d + p) % 26)

    combined_keys = {
        'add_mod26': key_add,
        'sub_DP': key_sub_dp,
        'sub_PD': key_sub_pd,
        'xor_mod26': key_xor,
        'agree_or_sum': key_agree_or_sum,
    }

    for mask_name, mask in [("DEF_MASK", DEF_MASK), ("PAL_MASK", PAL_MASK)]:
        ct73 = extract_73(mask)

        for use_col7 in [True, False]:
            if use_col7:
                ct73_nums = apply_col7(ct73)
            else:
                ct73_nums = text_to_nums(ct73)

            trans_label = "col7" if use_col7 else "notrans"

            for key_name, key_40 in combined_keys.items():
                for beau in [True, False]:
                    cipher = "beau" if beau else "vig"
                    L = len(key_40)
                    if beau:
                        pt_nums = [(key_40[i % L] - ci) % 26 for i, ci in enumerate(ct73_nums)]
                    else:
                        pt_nums = [(ci - key_40[i % L]) % 26 for i, ci in enumerate(ct73_nums)]
                    pt_str = nums_to_text(pt_nums)
                    total, e, b = count_crib_hits_73(pt_str, mask)

                    results.append({
                        'test': 9, 'key': key_name, 'cipher': cipher,
                        'mask': mask_name, 'trans': trans_label,
                        'score': total, 'ene': e, 'bcl': b, 'pt': pt_str[:60],
                    })
                    if total >= 16:
                        print(f"  ** HIT {total}/24 ** {key_name}:{cipher}:{trans_label}:{mask_name} (e={e},b={b})")

    best = max(results, key=lambda r: r['score'])
    print(f"\n  Test 9 best: {best['score']}/24 — {best['key']}:{best['cipher']}:{best['trans']}:{best['mask']} (e={best['ene']},b={best['bcl']})")
    return results

# ====================================================================
# BONUS TEST: SA with PALIMPSEST only (higher restart count for comparison)
# ====================================================================
def test_bonus_palimpsest_frequency():
    print("\n" + "="*70)
    print("BONUS: PALIMPSEST:AZ_beau SA frequency confirmation (50 restarts)")
    print("="*70)

    results = []
    pal_nums = PALIMPSEST_NUMS
    def_nums = DEFECTOR_NUMS

    for kw_name, kw_nums, beau_val in [
        ("PALIMPSEST_beau", pal_nums, True),
        ("DEFECTOR_beau", def_nums, True),
    ]:
        print(f"  {kw_name} ...", end='', flush=True)
        def decrypt_fn(ct_nums, _kn=kw_nums, _b=beau_val):
            return autokey_beau_az(ct_nums, _kn)

        best, all_res = sa_optimize_mask(decrypt_fn, n_restarts=50, steps=8000, use_col7=True)
        scores = [int(r[0]) for r in all_res]
        n15 = sum(1 for s in scores if s >= 15)
        n16 = sum(1 for s in scores if s >= 16)
        print(f" best={best[0]}/24, @15: {n15}/50 ({n15*2}%), @16: {n16}/50, dist: {Counter(scores).most_common()}")

        results.append({
            'keyword': kw_name,
            'best_score': best[0],
            'freq_15': n15,
            'freq_16': n16,
            'score_dist': dict(Counter(scores)),
            'best_mask': best[1],
            'best_pt': best[2][:73],
            'best_ene': best[3],
            'best_bcl': best[4],
        })

    return results

# ====================================================================
# MAIN
# ====================================================================

if __name__ == '__main__':
    t0 = time.time()
    load_quadgrams()

    print("="*70)
    print("COMBINED DEFECTOR + PALIMPSEST KEYWORD HYPOTHESIS")
    print("="*70)
    print(f"CT97: {CT97}")
    print(f"DEF_MASK ({len(DEF_MASK)}): {sorted(DEF_MASK)}")
    print(f"PAL_MASK ({len(PAL_MASK)}): {sorted(PAL_MASK)}")
    print(f"Shared nulls: {sorted(DEF_MASK & PAL_MASK)}")
    print(f"DEFECTOR: {DEFECTOR_NUMS}")
    print(f"PALIMPSEST: {PALIMPSEST_NUMS}")
    print(f"PALIMPSEST_ALPHA: {PALIMPSEST_ALPHA}")
    print(f"DEFECTOR_ALPHA: {DEFECTOR_ALPHA}")

    all_results = {}

    # Run all tests
    all_results['test1'] = test1_combined_periodic()
    all_results['test2'] = test2_two_stage()
    all_results['test3'] = test3_alternating()
    all_results['test6'] = test6_key_analysis()
    all_results['test5'] = test5_hybrid_key()
    all_results['test7'] = test7_mixed_alphabets()
    all_results['test8'] = test8_quagmire()
    all_results['test9'] = test9_lcm()
    all_results['test4'] = test4_sa_combined()  # SA last (slowest)
    all_results['bonus'] = test_bonus_palimpsest_frequency()

    elapsed = time.time() - t0

    # Summary
    print("\n" + "="*70)
    print("GRAND SUMMARY")
    print("="*70)

    overall_best = 0
    overall_detail = ""

    for test_name, test_results in all_results.items():
        if isinstance(test_results, list):
            if test_results and isinstance(test_results[0], dict):
                scores = [r.get('score', r.get('best_score', 0)) for r in test_results]
                if scores:
                    mx = max(scores)
                    n16 = sum(1 for s in scores if s >= 16)
                    n15 = sum(1 for s in scores if s >= 15)
                    best_r = max(test_results, key=lambda r: r.get('score', r.get('best_score', 0)))
                    print(f"  {test_name}: best={mx}/24, >=16: {n16}, >=15: {n15}, configs={len(test_results)}")
                    if mx > overall_best:
                        overall_best = mx
                        overall_detail = f"{test_name}: {best_r}"
        elif isinstance(test_results, dict):
            print(f"  {test_name}: analytical (see output above)")

    print(f"\n  OVERALL BEST: {overall_best}/24")
    if overall_best >= 16:
        print(f"  *** CEILING BROKEN *** Detail: {overall_detail}")
    elif overall_best >= 15:
        print(f"  Same ceiling as individual keywords (15/24)")
    else:
        print(f"  Below individual keyword ceiling")

    print(f"\n  Elapsed: {elapsed:.1f}s")

    # Save results
    output = {
        'experiment': 'f_combined_defector_palimpsest_v1',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'elapsed_seconds': round(elapsed, 1),
        'overall_best': overall_best,
        'ceiling_broken': overall_best >= 16,
    }

    # Collect all scores >= 14
    hits = []
    for test_name, test_results in all_results.items():
        if isinstance(test_results, list):
            for r in test_results:
                s = r.get('score', r.get('best_score', 0))
                if s >= 14:
                    hits.append({**r, 'test_name': test_name})

    output['hits_ge14'] = hits
    output['n_configs_approx'] = sum(
        len(r) if isinstance(r, list) else 0
        for r in all_results.values()
    )

    # Bonus results
    if 'bonus' in all_results:
        output['bonus_frequency'] = all_results['bonus']

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'results', 'f_combined_defector_palimpsest_v1.json')
    out_path = os.path.normpath(out_path)
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Results saved to {out_path}")
