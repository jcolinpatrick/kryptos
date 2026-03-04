#!/usr/bin/env python3
"""
Cipher: K3-method extension
Family: k3_continuity
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-106: K3 as Outer Layer of a Two-Layer System.

HYPOTHESIS: K4 = K3_encrypt(inner_encrypt(PT))
If K4 uses K3's method as an OUTER layer, then:
  K3_decrypt(K4_CT) = inner_encrypt(PT)
And the inner cipher is something simple (the "change in methodology").

K3's method (PUBLIC FACT):
  Model B: Trans(width-7, keyword=KRYPTOS) → Vig(keyword=PALIMPSEST)
  Encrypt: CT[i] = (transposed[i] + PALIMPSEST_key[i%10]) % 26
  Decrypt: transposed[i] = (CT[i] - PALIMPSEST_key[i%10]) % 26; un-transpose

Tests:
  Phase A: K3 as outer, simple inner ciphers
    A1: K3_dec(CT), check cribs directly (sanity — already tested in E-S-63)
    A2: K3_dec(CT) + Caesar shift (s=0..25) — 26 tests
    A3: K3_dec(CT) + Atbash — 1 test
    A4: K3_dec(CT) + keyword Vig with K1-K3 keywords — ~50 tests
    A5: K3_dec(CT) + another w7 columnar (all orderings) — 5040 tests
    A6: K3_dec(CT) reversed + Caesar — 26 tests
    A7: K3_dec(CT) + Beaufort with K1-K3 keywords — ~50 tests

  Phase B: Simple outer, K3 as inner
    B1: Caesar_shift(CT, s) then K3_dec — 26 tests
    B2: Keyword_Vig(CT, kw) then K3_dec — ~50 tests
    B3: Atbash(CT) then K3_dec — 1 test
    B4: Reverse(CT) then K3_dec — 1 test

  Phase C: Variant K3 methods (Beaufort, VBeau, different keyword combos)
    C1: All 3 cipher variants × K3 keywords × simple inner — 3 × 26 tests
    C2: Beaufort K3 + w7 inner transposition — 3 × 5040 tests
    C3: All keyword pairs from {KRYPTOS, PALIMPSEST, ABSCISSA, SHADOW, BERLIN,
         SANBORN, MEDUSA, LUCIFER, ENIGMA, INVISIBLE, CLOCK, EAST, NORTH}
         as (trans_kw, sub_kw) × simple inner — keyword_pairs × 26

  Phase D: K3 outer + inner columnar with ALL w7 orderings + Caesar
    For each w7 ordering (inner trans) × Caesar shift:
      PT_candidate = Caesar(K3_dec(CT), s) then un-transpose
    5040 × 26 = 131K tests — tractable

Output: results/e_s_106_k3_outer_layer.json
"""
import json
import time
import sys
import os

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_AT_CRIB = {p: ALPH_IDX[ch] for p, ch in CRIB_DICT.items()}
CRIB_POS = sorted(CRIB_POSITIONS)
N = CT_LEN

# K3 method parameters
PALIMPSEST_KEY = [ALPH_IDX[c] for c in "PALIMPSEST"]  # [15,0,11,8,12,15,18,4,18,19]
PAL_PERIOD = len(PALIMPSEST_KEY)  # 10

# KRYPTOS keyword → column ordering
def keyword_to_order(keyword):
    return sorted(range(len(keyword)), key=lambda i: (keyword[i], i))

KRYPTOS_ORDER = keyword_to_order("KRYPTOS")  # [0,5,3,1,6,4,2]
WIDTH = 7

# Column lengths for 97 chars in width-7 grid
NROWS = N // WIDTH  # 13
EXTRA = N % WIDTH   # 6
COL_HEIGHTS = [NROWS + 1 if c < EXTRA else NROWS for c in range(WIDTH)]

# Thematic keywords for inner/outer cipher tests
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
    "SANBORN", "MEDUSA", "LUCIFER", "ENIGMA", "INVISIBLE",
    "CLOCK", "EAST", "NORTH", "EGYPT", "CARTER",
    "TUTANKHAMUN", "PHARAOH", "ILLUSION", "IQLUSION",
    "DESPARATLY", "MAGNETIC", "LANGLEY", "BURIED",
    "WHATSTHEPOINT", "DELIVERINGAMESSAGE",
]


def build_columnar_perm(order):
    """Build columnar transposition permutation (gather convention).
    perm[output_pos] = input_pos"""
    w = len(order)
    nf = N // w
    extra = N % w
    heights = [nf + (1 if c < extra else 0) for c in range(w)]
    perm = []
    for rank in range(w):
        col = order[rank]
        for row in range(heights[col]):
            perm.append(row * w + col)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def apply_perm(text_idx, perm):
    """output[i] = text[perm[i]] (gather)"""
    return [text_idx[perm[i]] for i in range(len(perm))]


def k3_encrypt(pt_idx):
    """K3 encrypt: columnar(KRYPTOS) then Vig(PALIMPSEST)."""
    perm = build_columnar_perm(KRYPTOS_ORDER)
    transposed = apply_perm(pt_idx, perm)
    ct = [(transposed[i] + PALIMPSEST_KEY[i % PAL_PERIOD]) % MOD for i in range(N)]
    return ct


def k3_decrypt(ct_idx):
    """K3 decrypt: un-Vig(PALIMPSEST) then un-columnar(KRYPTOS)."""
    transposed = [(ct_idx[i] - PALIMPSEST_KEY[i % PAL_PERIOD]) % MOD for i in range(N)]
    perm = build_columnar_perm(KRYPTOS_ORDER)
    inv_perm = invert_perm(perm)
    pt = apply_perm(transposed, inv_perm)
    return pt


def variant_decrypt(ct_idx, order, sub_key, variant="vig"):
    """Decrypt with columnar(order) + substitution(sub_key, variant)."""
    if variant == "vig":
        transposed = [(ct_idx[i] - sub_key[i % len(sub_key)]) % MOD for i in range(N)]
    elif variant == "beau":
        transposed = [(sub_key[i % len(sub_key)] - ct_idx[i]) % MOD for i in range(N)]
    elif variant == "vbeau":
        transposed = [(ct_idx[i] + sub_key[i % len(sub_key)]) % MOD for i in range(N)]
    else:
        raise ValueError(f"Unknown variant: {variant}")
    perm = build_columnar_perm(order)
    inv_perm = invert_perm(perm)
    pt = apply_perm(transposed, inv_perm)
    return pt


def caesar(text_idx, shift):
    return [(v + shift) % MOD for v in text_idx]


def atbash(text_idx):
    return [(25 - v) % MOD for v in text_idx]


def vig_decrypt(text_idx, key_idx):
    return [(text_idx[i] - key_idx[i % len(key_idx)]) % MOD for i in range(len(text_idx))]


def beau_decrypt(text_idx, key_idx):
    return [(key_idx[i % len(key_idx)] - text_idx[i]) % MOD for i in range(len(text_idx))]


def score_cribs(pt_idx):
    """Count matching crib positions."""
    matches = 0
    for pos, expected in PT_AT_CRIB.items():
        if pos < len(pt_idx) and pt_idx[pos] == expected:
            matches += 1
    return matches


def idx_to_text(idx_list):
    return ''.join(ALPH[v] for v in idx_list)


print("=" * 70)
print("E-S-106: K3 as Outer Layer of a Two-Layer System")
print("=" * 70)
t0 = time.time()

results = {}
best_overall = 0
best_config = ""

# ==========================================================================
# Phase A: K3 as outer layer, simple inner ciphers
# ==========================================================================
print("\n--- Phase A: K3 as outer layer, simple inner ciphers ---")

# A1: Direct K3 decrypt (sanity check)
intermediate_a = k3_decrypt(CT_IDX)
score_a1 = score_cribs(intermediate_a)
print(f"A1: Direct K3 decrypt: {score_a1}/24 cribs")
results["A1_direct"] = {"score": score_a1, "text_prefix": idx_to_text(intermediate_a[:30])}
if score_a1 > best_overall:
    best_overall, best_config = score_a1, "A1_direct"

# A2: K3 decrypt + Caesar shift (inner is Caesar)
print("A2: K3_dec + Caesar shift...", end=" ")
best_a2 = 0
for s in range(26):
    pt = caesar(intermediate_a, s)
    sc = score_cribs(pt)
    if sc > best_a2:
        best_a2, best_a2_s = sc, s
    if sc > best_overall:
        best_overall, best_config = sc, f"A2_caesar_s{s}"
print(f"best {best_a2}/24 (shift={best_a2_s})")
results["A2_caesar"] = {"best": best_a2, "best_shift": best_a2_s}

# A3: K3 decrypt + Atbash
pt_a3 = atbash(intermediate_a)
score_a3 = score_cribs(pt_a3)
print(f"A3: K3_dec + Atbash: {score_a3}/24 cribs")
results["A3_atbash"] = {"score": score_a3}
if score_a3 > best_overall:
    best_overall, best_config = score_a3, "A3_atbash"

# A4: K3 decrypt + keyword Vig (inner is Vig with known keyword)
print("A4: K3_dec + keyword Vig...", end=" ")
best_a4, best_a4_kw = 0, ""
for kw in KEYWORDS:
    kw_idx = [ALPH_IDX[c] for c in kw]
    pt = vig_decrypt(intermediate_a, kw_idx)
    sc = score_cribs(pt)
    if sc > best_a4:
        best_a4, best_a4_kw = sc, kw
    if sc > best_overall:
        best_overall, best_config = sc, f"A4_vig_{kw}"
print(f"best {best_a4}/24 ({best_a4_kw})")
results["A4_keyword_vig"] = {"best": best_a4, "best_keyword": best_a4_kw}

# A5: K3 decrypt + another w7 columnar (inner is a second transposition)
print("A5: K3_dec + w7 columnar inner...", end=" ", flush=True)
best_a5, best_a5_ord = 0, None
from itertools import permutations
for order in permutations(range(WIDTH)):
    perm = build_columnar_perm(list(order))
    inv_perm = invert_perm(perm)
    pt = apply_perm(intermediate_a, inv_perm)
    sc = score_cribs(pt)
    if sc > best_a5:
        best_a5, best_a5_ord = sc, list(order)
    if sc > best_overall:
        best_overall, best_config = sc, f"A5_inner_col_{list(order)}"
print(f"best {best_a5}/24 (order={best_a5_ord})")
results["A5_inner_columnar"] = {"best": best_a5, "best_order": best_a5_ord}

# A6: K3 decrypt reversed + Caesar
print("A6: K3_dec reversed + Caesar...", end=" ")
reversed_a = list(reversed(intermediate_a))
best_a6 = 0
for s in range(26):
    pt = caesar(reversed_a, s)
    sc = score_cribs(pt)
    if sc > best_a6:
        best_a6, best_a6_s = sc, s
    if sc > best_overall:
        best_overall, best_config = sc, f"A6_reverse_caesar_s{s}"
print(f"best {best_a6}/24 (shift={best_a6_s})")
results["A6_reverse_caesar"] = {"best": best_a6, "best_shift": best_a6_s}

# A7: K3 decrypt + keyword Beaufort
print("A7: K3_dec + keyword Beaufort...", end=" ")
best_a7, best_a7_kw = 0, ""
for kw in KEYWORDS:
    kw_idx = [ALPH_IDX[c] for c in kw]
    pt = beau_decrypt(intermediate_a, kw_idx)
    sc = score_cribs(pt)
    if sc > best_a7:
        best_a7, best_a7_kw = sc, kw
    if sc > best_overall:
        best_overall, best_config = sc, f"A7_beau_{kw}"
print(f"best {best_a7}/24 ({best_a7_kw})")
results["A7_keyword_beau"] = {"best": best_a7, "best_keyword": best_a7_kw}

# ==========================================================================
# Phase B: Simple outer, K3 as inner
# ==========================================================================
print("\n--- Phase B: Simple outer cipher, K3 as inner ---")

# B1: Caesar(CT) then K3 decrypt
print("B1: Caesar(CT) + K3_dec...", end=" ")
best_b1, best_b1_s = 0, 0
for s in range(26):
    mod_ct = caesar(CT_IDX, s)
    pt = k3_decrypt(mod_ct)
    sc = score_cribs(pt)
    if sc > best_b1:
        best_b1, best_b1_s = sc, s
    if sc > best_overall:
        best_overall, best_config = sc, f"B1_caesar_s{s}"
print(f"best {best_b1}/24 (shift={best_b1_s})")
results["B1_caesar_outer"] = {"best": best_b1, "best_shift": best_b1_s}

# B2: Keyword Vig(CT) then K3 decrypt
print("B2: Keyword_Vig(CT) + K3_dec...", end=" ")
best_b2, best_b2_kw = 0, ""
for kw in KEYWORDS:
    kw_idx = [ALPH_IDX[c] for c in kw]
    mod_ct = vig_decrypt(CT_IDX, kw_idx)
    pt = k3_decrypt(mod_ct)
    sc = score_cribs(pt)
    if sc > best_b2:
        best_b2, best_b2_kw = sc, kw
    if sc > best_overall:
        best_overall, best_config = sc, f"B2_vig_{kw}"
    # Also Beaufort
    mod_ct = beau_decrypt(CT_IDX, kw_idx)
    pt = k3_decrypt(mod_ct)
    sc = score_cribs(pt)
    if sc > best_b2:
        best_b2, best_b2_kw = sc, kw + "_beau"
    if sc > best_overall:
        best_overall, best_config = sc, f"B2_beau_{kw}"
print(f"best {best_b2}/24 ({best_b2_kw})")
results["B2_keyword_vig_outer"] = {"best": best_b2, "best_keyword": best_b2_kw}

# B3: Atbash(CT) then K3 decrypt
mod_ct = atbash(CT_IDX)
pt_b3 = k3_decrypt(mod_ct)
score_b3 = score_cribs(pt_b3)
print(f"B3: Atbash(CT) + K3_dec: {score_b3}/24")
results["B3_atbash_outer"] = {"score": score_b3}
if score_b3 > best_overall:
    best_overall, best_config = score_b3, "B3_atbash"

# B4: Reverse(CT) then K3 decrypt
rev_ct = list(reversed(CT_IDX))
pt_b4 = k3_decrypt(rev_ct)
score_b4 = score_cribs(pt_b4)
print(f"B4: Reverse(CT) + K3_dec: {score_b4}/24")
results["B4_reverse_outer"] = {"score": score_b4}
if score_b4 > best_overall:
    best_overall, best_config = score_b4, "B4_reverse"

# ==========================================================================
# Phase C: Variant K3 methods (all keyword pairs × 3 variants × Caesar inner)
# ==========================================================================
print("\n--- Phase C: Variant K3 (different keywords + variants) + Caesar inner ---")

TRANS_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
    "SANBORN", "MEDUSA", "LUCIFER", "ENIGMA", "CLOCK",
]
SUB_KEYWORDS = [
    "PALIMPSEST", "KRYPTOS", "ABSCISSA", "SHADOW", "BERLIN",
    "SANBORN", "MEDUSA", "LUCIFER", "ENIGMA", "INVISIBLE",
    "CLOCK", "EAST", "NORTH",
]

best_c, best_c_config = 0, ""
n_tested_c = 0
for tkw in TRANS_KEYWORDS:
    order = keyword_to_order(tkw)
    w = len(tkw)
    for skw in SUB_KEYWORDS:
        sub_key = [ALPH_IDX[c] for c in skw]
        for variant in ["vig", "beau", "vbeau"]:
            # Decrypt with this variant K3
            intermediate = variant_decrypt(CT_IDX, order, sub_key, variant)
            # Try Caesar shifts on the intermediate
            for s in range(26):
                pt = caesar(intermediate, s)
                sc = score_cribs(pt)
                n_tested_c += 1
                if sc > best_c:
                    best_c = sc
                    best_c_config = f"trans={tkw},sub={skw},var={variant},shift={s}"
                if sc > best_overall:
                    best_overall = sc
                    best_config = f"C_{best_c_config}"
            # Also try Atbash
            pt = atbash(intermediate)
            sc = score_cribs(pt)
            n_tested_c += 1
            if sc > best_c:
                best_c = sc
                best_c_config = f"trans={tkw},sub={skw},var={variant},atbash"
            if sc > best_overall:
                best_overall = sc
                best_config = f"C_{best_c_config}"

print(f"C: {n_tested_c} configs tested, best {best_c}/24 ({best_c_config})")
results["C_variant_k3"] = {"n_tested": n_tested_c, "best": best_c, "best_config": best_c_config}

# ==========================================================================
# Phase D: K3 outer + inner w7 columnar × Caesar (131K tests)
# ==========================================================================
print("\n--- Phase D: K3 outer + inner columnar + Caesar ---")
print("D: Testing K3_dec + w7_columnar + Caesar (5040 × 26)...", flush=True)

best_d, best_d_config = 0, ""
for i, order in enumerate(permutations(range(WIDTH))):
    order = list(order)
    perm = build_columnar_perm(order)
    inv_perm = invert_perm(perm)
    transposed = apply_perm(intermediate_a, inv_perm)
    for s in range(26):
        pt = caesar(transposed, s)
        sc = score_cribs(pt)
        if sc > best_d:
            best_d = sc
            best_d_config = f"order={order},shift={s}"
        if sc > best_overall:
            best_overall = sc
            best_config = f"D_{best_d_config}"
    if (i + 1) % 1000 == 0:
        print(f"  {i+1}/5040, best so far: {best_d}/24", flush=True)

print(f"D: best {best_d}/24 ({best_d_config})")
results["D_k3_inner_col_caesar"] = {"best": best_d, "best_config": best_d_config}

# ==========================================================================
# Phase E: K3 outer + inner Vig with EACH keyword + w7 columnar
# ==========================================================================
print("\n--- Phase E: K3 outer + inner keyword_Vig + w7 columnar ---")
print("E: Testing K3_dec → keyword_Vig_dec → un-columnar...", flush=True)

best_e, best_e_config = 0, ""
n_e = 0
for kw in KEYWORDS:
    kw_idx = [ALPH_IDX[c] for c in kw]
    # Apply Vig decrypt to K3 intermediate
    vig_dec = vig_decrypt(intermediate_a, kw_idx)
    # Then try all w7 orderings for un-transpose
    for order in permutations(range(WIDTH)):
        order = list(order)
        perm = build_columnar_perm(order)
        inv_perm = invert_perm(perm)
        pt = apply_perm(vig_dec, inv_perm)
        sc = score_cribs(pt)
        n_e += 1
        if sc > best_e:
            best_e = sc
            best_e_config = f"kw={kw},order={order}"
        if sc > best_overall:
            best_overall = sc
            best_config = f"E_{best_e_config}"
    # Also Beaufort
    beau_dec = beau_decrypt(intermediate_a, kw_idx)
    for order in permutations(range(WIDTH)):
        order = list(order)
        perm = build_columnar_perm(order)
        inv_perm = invert_perm(perm)
        pt = apply_perm(beau_dec, inv_perm)
        sc = score_cribs(pt)
        n_e += 1
        if sc > best_e:
            best_e = sc
            best_e_config = f"kw={kw}_beau,order={order}"
        if sc > best_overall:
            best_overall = sc
            best_config = f"E_{best_e_config}"

print(f"E: {n_e} configs, best {best_e}/24 ({best_e_config})")
results["E_k3_vig_col"] = {"n_tested": n_e, "best": best_e, "best_config": best_e_config}

# ==========================================================================
# Phase F: K3-like with ALL w7 orderings as outer trans + PALIMPSEST Vig
#           + Caesar inner (test if different outer ordering works)
# ==========================================================================
print("\n--- Phase F: All w7 outer orderings + PALIMPSEST Vig + Caesar inner ---")
print("F: Testing 5040 outer orderings × 26 Caesar shifts...", flush=True)

best_f, best_f_config = 0, ""
for i, order in enumerate(permutations(range(WIDTH))):
    order = list(order)
    # Decrypt: un-Vig(PALIMPSEST) then un-columnar(order)
    intermediate = variant_decrypt(CT_IDX, order, PALIMPSEST_KEY, "vig")
    for s in range(26):
        pt = caesar(intermediate, s)
        sc = score_cribs(pt)
        if sc > best_f:
            best_f = sc
            best_f_config = f"outer={order},shift={s}"
        if sc > best_overall:
            best_overall = sc
            best_config = f"F_{best_f_config}"
    if (i + 1) % 1000 == 0:
        print(f"  {i+1}/5040, best so far: {best_f}/24", flush=True)

# Also try Beaufort and VBeau
for variant in ["beau", "vbeau"]:
    for order in permutations(range(WIDTH)):
        order = list(order)
        intermediate = variant_decrypt(CT_IDX, order, PALIMPSEST_KEY, variant)
        for s in range(26):
            pt = caesar(intermediate, s)
            sc = score_cribs(pt)
            if sc > best_f:
                best_f = sc
                best_f_config = f"outer={order},var={variant},shift={s}"
            if sc > best_overall:
                best_overall = sc
                best_config = f"F_{best_f_config}"

print(f"F: best {best_f}/24 ({best_f_config})")
results["F_all_outer_pal_caesar"] = {"best": best_f, "best_config": best_f_config}

# ==========================================================================
# Summary
# ==========================================================================
elapsed = time.time() - t0
print(f"\n{'='*70}")
print(f"E-S-106 COMPLETE — elapsed: {elapsed:.1f}s")
print(f"OVERALL BEST: {best_overall}/24 — {best_config}")
print(f"{'='*70}")

results["best_overall"] = best_overall
results["best_config"] = best_config
results["elapsed_seconds"] = elapsed

os.makedirs("results", exist_ok=True)
with open("results/e_s_106_k3_outer_layer.json", "w") as f:
    json.dump({"experiment": "E-S-106", "description": "K3 as outer layer + simple inner ciphers",
               "results": results}, f, indent=2)

print(f"\nResults saved to results/e_s_106_k3_outer_layer.json")
