#!/usr/bin/env python3
"""E-S-150: Howard Carter's tomb opening date (11/26/1922) as K4 key material.

K3 paraphrases Carter's journal from November 26, 1922. The DATE itself
has never been tested as cipher key material. Key properties:
- [1,1,2,6,1,9,2,2] as digits = period 8 (same as ABSCISSA)
- [11,26,19,22] as date components (month, day, century, year)
- 19 = T (A=0), 26 = alphabet size
- Ranked: [0,1,3,6,2,7,4,5] = width-8 transposition key

Tests:
1. Date digits as periodic Vigenere/Beaufort key (period 8)
2. Date digits as width-8 transposition key
3. Date combined with ABSCISSA (add/subtract mod 26)
4. Date combined with width-7 KRYPTOS transposition
5. Date as autokey primer
6. Multiple date formats (US, EU, ISO, year-only, day+year)
7. Date transposition + PALIMPSEST/ABSCISSA Vigenere (K3-style compound)
"""

import json
import os
import sys
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, NOISE_FLOOR,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN

def vig_dec(ct, key): return [(ct[i] - key[i % len(key)]) % MOD for i in range(len(ct))]
def beau_dec(ct, key): return [(key[i % len(key)] - ct[i]) % MOD for i in range(len(ct))]
def varbeau_dec(ct, key): return [(ct[i] + key[i % len(key)]) % MOD for i in range(len(ct))]

def nums_to_text(nums): return ''.join(ALPH[n % 26] for n in nums)

def score_cribs(text):
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(text) and text[pos] == ch)

def check_bean(pt_text):
    key = [(ALPH_IDX[CT[i]] - ALPH_IDX[pt_text[i]]) % MOD for i in range(N)]
    for a, b in BEAN_EQ:
        if key[a] != key[b]: return False
    for a, b in BEAN_INEQ:
        if key[a] == key[b]: return False
    return True

def rank_key(values):
    """Convert values to a permutation by ranking (ties broken left-to-right)."""
    indexed = sorted(enumerate(values), key=lambda x: (x[1], x[0]))
    perm = [0] * len(values)
    for rank, (orig_idx, _) in enumerate(indexed):
        perm[orig_idx] = rank
    return perm

def columnar_untranspose(ct_text, col_order, width):
    """Reverse columnar transposition."""
    n = len(ct_text)
    nrows = (n + width - 1) // width
    short_cols = width - (n % width) if n % width != 0 else 0

    col_lengths = []
    for c in range(width):
        if c < width - short_cols:
            col_lengths.append(nrows)
        else:
            col_lengths.append(nrows - 1)

    # Split CT into columns in col_order sequence
    columns = {}
    idx = 0
    for rank in range(width):
        col_idx = col_order.index(rank)
        clen = col_lengths[col_idx]
        columns[col_idx] = ct_text[idx:idx+clen]
        idx += clen

    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(columns.get(c, '')):
                result.append(columns[c][r])
    return ''.join(result)

def autokey_vig(ct_text, primer):
    ct_nums = [ALPH_IDX[c] for c in ct_text]
    pt = []
    for i in range(len(ct_nums)):
        k = primer[i] if i < len(primer) else pt[i - len(primer)]
        p = (ct_nums[i] - k) % MOD
        pt.append(p)
    return nums_to_text(pt)

def autokey_beau(ct_text, primer):
    ct_nums = [ALPH_IDX[c] for c in ct_text]
    pt = []
    for i in range(len(ct_nums)):
        k = primer[i] if i < len(primer) else pt[i - len(primer)]
        p = (k - ct_nums[i]) % MOD
        pt.append(p)
    return nums_to_text(pt)


# ═══════════════════════════════════════════════════════════════════════
# DATE REPRESENTATIONS
# ═══════════════════════════════════════════════════════════════════════

DATE_KEYS = {
    # Digit sequences
    "US_digits_11261922":       [1,1,2,6,1,9,2,2],    # 11/26/1922
    "EU_digits_26111922":       [2,6,1,1,1,9,2,2],    # 26/11/1922
    "ISO_digits_19221126":      [1,9,2,2,1,1,2,6],    # 19221126
    "year_digits_1922":         [1,9,2,2],             # 1922
    "day_year_261922":          [2,6,1,9,2,2],         # 26/1922 (6 digits)
    "month_day_1126":           [1,1,2,6],             # 11/26
    "century_year_1922":        [19,22],               # as two numbers
    "month_day_year_112619_22": [11,26,19,22],         # as four numbers
    "day_month_year_261119_22": [26,11,19,22],         # EU four numbers
    "year_month_day":           [19,22,11,26],         # ISO four numbers

    # Mod 26 variants of the four-number form
    "m_d_c_y_mod26":            [11,0,19,22],          # 26 mod 26 = 0
    "d_m_c_y_mod26":            [0,11,19,22],          # EU

    # Individual digits as letters (A=0): BBCGBJCC
    "digits_as_letters":        [1,1,2,6,1,9,2,2],    # same as US

    # Reversed
    "reversed_22911621":        [2,2,9,1,6,2,1,1],
    "reversed_components":      [22,19,26,11],
}

# Known keywords for combination
KEYWORDS = {
    "ABSCISSA":    [ALPH_IDX[c] for c in "ABSCISSA"],     # period 8
    "PALIMPSEST":  [ALPH_IDX[c] for c in "PALIMPSEST"],   # period 10
    "KRYPTOS":     [ALPH_IDX[c] for c in "KRYPTOS"],      # period 7
}

KRYPTOS_PERM = [3, 6, 5, 4, 2, 0, 1]  # KRYPTOS width-7 column order

best_score = 0
best_tag = ""
total = 0
above_noise = []

def test(tag, pt_text):
    global best_score, best_tag, total
    total += 1
    sc = score_cribs(pt_text[:N])
    if sc > best_score:
        best_score = sc
        best_tag = tag
        print(f"  NEW BEST: {sc}/{N_CRIBS} — {tag}")
        if sc >= 4:
            print(f"    PT: {pt_text[:60]}...")
            bean = check_bean(pt_text[:N]) if len(pt_text) >= N else False
            print(f"    Bean: {'PASS' if bean else 'FAIL'}")
    if sc > NOISE_FLOOR:
        above_noise.append({"tag": tag, "score": sc, "pt": pt_text[:50]})
    return sc


print("=" * 72)
print("E-S-150: Howard Carter Date (11/26/1922) as K4 Key Material")
print("=" * 72)
print(f"CT: {CT}")
print(f"Date: November 26, 1922 (K3 describes this day's events)")
print()

# ═══════════════════════════════════════════════════════════════════════
# TEST 1: Date as periodic substitution key
# ═══════════════════════════════════════════════════════════════════════
print("--- Test 1: Date digits as periodic Vigenere/Beaufort key ---")

for dname, dkey in DATE_KEYS.items():
    for vname, vfn in [('vig', vig_dec), ('beau', beau_dec), ('vb', varbeau_dec)]:
        pt_nums = vfn(CT_NUM, dkey)
        pt = nums_to_text(pt_nums)
        test(f"T1_{dname}_p{len(dkey)}_{vname}", pt)

print(f"  Test 1: {total} configs, best {best_score}/{N_CRIBS}\n")

# ═══════════════════════════════════════════════════════════════════════
# TEST 2: Date as transposition key (width-8 from US digits)
# ═══════════════════════════════════════════════════════════════════════
print("--- Test 2: Date as width-8 transposition key ---")

date_perms = {}
for dname, dkey in DATE_KEYS.items():
    if len(dkey) >= 2 and len(dkey) <= 26:
        perm = rank_key(dkey)
        perm_tuple = tuple(perm)
        if perm_tuple not in date_perms:
            date_perms[perm_tuple] = dname
            w = len(perm)

            # Untranspose
            try:
                ut = columnar_untranspose(CT, list(perm), w)
                test(f"T2_{dname}_w{w}_fwd", ut)

                # Also inverse
                inv_perm = [0] * w
                for i, p in enumerate(perm):
                    inv_perm[p] = i
                ut_inv = columnar_untranspose(CT, inv_perm, w)
                test(f"T2_{dname}_w{w}_inv", ut_inv)

                # Transposition + substitution with known keywords
                for kname, kkey in KEYWORDS.items():
                    for vname, vfn in [('vig', vig_dec), ('beau', beau_dec)]:
                        # Untranspose then decrypt
                        pt_nums = vfn([ALPH_IDX[c] for c in ut], kkey)
                        pt = nums_to_text(pt_nums)
                        test(f"T2_{dname}_w{w}_fwd_{kname}_{vname}", pt)

                        pt_nums_inv = vfn([ALPH_IDX[c] for c in ut_inv], kkey)
                        pt_inv = nums_to_text(pt_nums_inv)
                        test(f"T2_{dname}_w{w}_inv_{kname}_{vname}", pt_inv)
            except Exception as e:
                pass

print(f"  Test 2: {total} configs total, best {best_score}/{N_CRIBS}\n")

# ═══════════════════════════════════════════════════════════════════════
# TEST 3: Date combined with ABSCISSA (add/subtract)
# ═══════════════════════════════════════════════════════════════════════
print("--- Test 3: Date combined with ABSCISSA ---")

abscissa = KEYWORDS["ABSCISSA"]  # [0,1,18,2,8,18,18,0]
date8 = DATE_KEYS["US_digits_11261922"]  # [1,1,2,6,1,9,2,2]

combined_keys = {
    "ABS+date":   [(abscissa[i] + date8[i]) % MOD for i in range(8)],
    "ABS-date":   [(abscissa[i] - date8[i]) % MOD for i in range(8)],
    "date-ABS":   [(date8[i] - abscissa[i]) % MOD for i in range(8)],
    "ABS*date":   [(abscissa[i] * date8[i]) % MOD for i in range(8)],
    "ABS_xor_date": [(abscissa[i] ^ date8[i]) for i in range(8)],
}

print(f"  ABSCISSA:     {abscissa}")
print(f"  Date digits:  {date8}")
for cname, ckey in combined_keys.items():
    ckey_mod = [k % MOD for k in ckey]
    print(f"  {cname}: {ckey_mod}")
    for vname, vfn in [('vig', vig_dec), ('beau', beau_dec), ('vb', varbeau_dec)]:
        pt_nums = vfn(CT_NUM, ckey_mod)
        pt = nums_to_text(pt_nums)
        test(f"T3_{cname}_{vname}", pt)

# Also: ABSCISSA transposition + date Vigenere, and vice versa
abs_perm = rank_key(abscissa)
date_perm = rank_key(date8)
print(f"\n  ABSCISSA perm:  {abs_perm}")
print(f"  Date perm:      {date_perm}")

for tname, tperm in [("ABS", abs_perm), ("date", date_perm)]:
    for sname, skey in [("ABS", abscissa), ("date", date8)]:
        if tname == sname:
            continue  # skip same-same
        w = len(tperm)
        try:
            ut = columnar_untranspose(CT, tperm, w)
            for vname, vfn in [('vig', vig_dec), ('beau', beau_dec)]:
                pt_nums = vfn([ALPH_IDX[c] for c in ut], skey)
                pt = nums_to_text(pt_nums)
                test(f"T3_trans_{tname}_sub_{sname}_{vname}", pt)
        except:
            pass

print(f"  Test 3: {total} configs total, best {best_score}/{N_CRIBS}\n")

# ═══════════════════════════════════════════════════════════════════════
# TEST 4: Date + KRYPTOS width-7 transposition
# ═══════════════════════════════════════════════════════════════════════
print("--- Test 4: KRYPTOS w7 transposition + date substitution ---")

try:
    ut_kryptos = columnar_untranspose(CT, KRYPTOS_PERM, 7)
    for dname, dkey in DATE_KEYS.items():
        for vname, vfn in [('vig', vig_dec), ('beau', beau_dec)]:
            pt_nums = vfn([ALPH_IDX[c] for c in ut_kryptos], dkey)
            pt = nums_to_text(pt_nums)
            test(f"T4_KRYPTOS_w7_{dname}_{vname}", pt)
except Exception as e:
    print(f"  Error: {e}")

# Also: date transposition + KRYPTOS Vigenere
for dname, dkey in DATE_KEYS.items():
    if len(dkey) < 2 or len(dkey) > 26:
        continue
    dperm = rank_key(dkey)
    w = len(dperm)
    try:
        ut = columnar_untranspose(CT, dperm, w)
        kryptos_key = KEYWORDS["KRYPTOS"]
        for vname, vfn in [('vig', vig_dec), ('beau', beau_dec)]:
            pt_nums = vfn([ALPH_IDX[c] for c in ut], kryptos_key)
            pt = nums_to_text(pt_nums)
            test(f"T4_date_{dname}_w{w}_KRYPTOS_{vname}", pt)
    except:
        pass

print(f"  Test 4: {total} configs total, best {best_score}/{N_CRIBS}\n")

# ═══════════════════════════════════════════════════════════════════════
# TEST 5: Date as autokey primer
# ═══════════════════════════════════════════════════════════════════════
print("--- Test 5: Date as autokey primer ---")

for dname, dkey in DATE_KEYS.items():
    pt_v = autokey_vig(CT, dkey)
    test(f"T5_autokey_vig_{dname}", pt_v)
    pt_b = autokey_beau(CT, dkey)
    test(f"T5_autokey_beau_{dname}", pt_b)

print(f"  Test 5: {total} configs total, best {best_score}/{N_CRIBS}\n")

# ═══════════════════════════════════════════════════════════════════════
# TEST 6: K3-style compound (transposition + Vigenere) with date
# ═══════════════════════════════════════════════════════════════════════
print("--- Test 6: K3-style compound with date ---")
# K3 used: KRYPTOS transposition (w7) + PALIMPSEST Vigenere (p10)
# Test: date transposition (w8) + PALIMPSEST Vigenere (p10)
# And:  KRYPTOS transposition (w7) + date Vigenere (p8)
# And:  date transposition (w8) + ABSCISSA Vigenere (p8)
# And:  ABSCISSA transposition (w8) + date Vigenere (p8)

compound_configs = [
    # (trans_name, trans_perm, trans_width, sub_name, sub_key)
    ("date_US", rank_key(date8), 8, "PALIMPSEST", KEYWORDS["PALIMPSEST"]),
    ("date_US", rank_key(date8), 8, "ABSCISSA", KEYWORDS["ABSCISSA"]),
    ("date_US", rank_key(date8), 8, "KRYPTOS", KEYWORDS["KRYPTOS"]),
    ("KRYPTOS", KRYPTOS_PERM, 7, "date_US", date8),
    ("ABSCISSA", rank_key(abscissa), 8, "date_US", date8),
    ("date_EU", rank_key(DATE_KEYS["EU_digits_26111922"]), 8, "PALIMPSEST", KEYWORDS["PALIMPSEST"]),
    ("date_EU", rank_key(DATE_KEYS["EU_digits_26111922"]), 8, "ABSCISSA", KEYWORDS["ABSCISSA"]),
    ("date_ISO", rank_key(DATE_KEYS["ISO_digits_19221126"]), 8, "PALIMPSEST", KEYWORDS["PALIMPSEST"]),
    ("date_ISO", rank_key(DATE_KEYS["ISO_digits_19221126"]), 8, "ABSCISSA", KEYWORDS["ABSCISSA"]),
    ("date_rev", rank_key(DATE_KEYS["reversed_22911621"]), 8, "PALIMPSEST", KEYWORDS["PALIMPSEST"]),
]

for tname, tperm, tw, sname, skey in compound_configs:
    try:
        ut = columnar_untranspose(CT, tperm, tw)
        for vname, vfn in [('vig', vig_dec), ('beau', beau_dec), ('vb', varbeau_dec)]:
            pt_nums = vfn([ALPH_IDX[c] for c in ut], skey)
            pt = nums_to_text(pt_nums)
            test(f"T6_{tname}_w{tw}+{sname}_{vname}", pt)

        # Also inverse transposition
        inv_perm = [0] * tw
        for i, p in enumerate(tperm):
            inv_perm[p] = i
        ut_inv = columnar_untranspose(CT, inv_perm, tw)
        for vname, vfn in [('vig', vig_dec), ('beau', beau_dec)]:
            pt_nums = vfn([ALPH_IDX[c] for c in ut_inv], skey)
            pt = nums_to_text(pt_nums)
            test(f"T6_{tname}_w{tw}_inv+{sname}_{vname}", pt)
    except Exception as e:
        pass

# Also: sub first, then transpose
for tname, tperm, tw, sname, skey in compound_configs:
    try:
        for vname, vfn in [('vig', vig_dec), ('beau', beau_dec)]:
            pt_sub = nums_to_text(vfn(CT_NUM, skey))
            pt = columnar_untranspose(pt_sub, tperm, tw)
            test(f"T6_{sname}_{vname}_then_{tname}_w{tw}", pt)
    except:
        pass

print(f"  Test 6: {total} configs total, best {best_score}/{N_CRIBS}\n")

# ═══════════════════════════════════════════════════════════════════════
# TEST 7: Date + anomaly-derived width-7 keys
# ═══════════════════════════════════════════════════════════════════════
print("--- Test 7: Anomaly w7 keys + date substitution ---")

anomaly_w7 = {
    "anom_order1": [2, 5, 4, 6, 1, 0, 3],
    "anom_order2": [6, 1, 0, 2, 5, 4, 3],
    "anom_order3": [3, 2, 5, 4, 6, 1, 0],
}

for aname, aperm in anomaly_w7.items():
    try:
        # Build full permutation for width 7
        from kryptos.kernel.transforms.transposition import columnar_perm, invert_perm, apply_perm

        full_perm = columnar_perm(7, aperm, N)
        inv_full = invert_perm(full_perm)
        ut = apply_perm(CT, inv_full)

        for dname, dkey in [("US_date", date8), ("EU_date", DATE_KEYS["EU_digits_26111922"]),
                             ("year", DATE_KEYS["year_digits_1922"])]:
            for vname, vfn in [('vig', vig_dec), ('beau', beau_dec)]:
                pt_nums = vfn([ALPH_IDX[c] for c in ut], dkey)
                pt = nums_to_text(pt_nums)
                test(f"T7_{aname}+{dname}_{vname}", pt)
    except Exception as e:
        # Fallback: manual columnar
        pass

print(f"  Test 7: {total} configs total, best {best_score}/{N_CRIBS}\n")

# ═══════════════════════════════════════════════════════════════════════
# TEST 8: All width-8 column orderings + date Vigenere
# (5040 orderings × 3 variants = 15,120 configs — feasible)
# ═══════════════════════════════════════════════════════════════════════
print("--- Test 8: All width-8 orderings + date/ABSCISSA Vigenere ---")

t8_best = 0
for perm in itertools.permutations(range(8)):
    try:
        ut = columnar_untranspose(CT, list(perm), 8)
        ut_nums = [ALPH_IDX[c] for c in ut]
    except:
        continue

    for sname, skey in [("date_US", date8), ("ABSCISSA", abscissa)]:
        for vname, vfn in [('vig', vig_dec), ('beau', beau_dec)]:
            pt_nums = vfn(ut_nums, skey)
            pt = nums_to_text(pt_nums)
            sc = score_cribs(pt)
            total += 1
            if sc > t8_best:
                t8_best = sc
                tag = f"T8_w8_{list(perm)}_{sname}_{vname}"
                if sc > best_score:
                    best_score = sc
                    best_tag = tag
                    print(f"  NEW BEST: {sc}/{N_CRIBS} — {tag}")
                    if sc >= 6:
                        print(f"    PT: {pt[:60]}...")
            if sc > NOISE_FLOOR:
                above_noise.append({"tag": f"T8_w8_{list(perm)}_{sname}_{vname}", "score": sc})

print(f"  Test 8: {total} configs total, w8 best {t8_best}/{N_CRIBS}\n")


# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("FINAL SUMMARY")
print("=" * 72)
print(f"Total configurations: {total}")
print(f"Best score: {best_score}/{N_CRIBS} ({best_tag})")
print(f"Above noise ({NOISE_FLOOR}): {len(above_noise)}")

if above_noise:
    print("\nResults above noise floor:")
    for r in sorted(above_noise, key=lambda x: -x['score'])[:15]:
        print(f"  {r['score']}/{N_CRIBS}: {r['tag']}")

if best_score <= NOISE_FLOOR:
    print(f"\nVERDICT: ALL NOISE — Carter date produces no signal as K4 key material")
elif best_score < 18:
    print(f"\nVERDICT: STORED — some above-noise but below signal threshold")
else:
    print(f"\nVERDICT: SIGNAL — investigate!")

# Save
os.makedirs("artifacts/e_s_150", exist_ok=True)
with open("artifacts/e_s_150/results.json", "w") as f:
    json.dump({
        "experiment": "E-S-150",
        "description": "Carter date (11/26/1922) as K4 key material",
        "total_configs": total,
        "best_score": best_score,
        "best_tag": best_tag,
        "above_noise": above_noise,
    }, f, indent=2)
print(f"\nArtifact: artifacts/e_s_150/results.json")
