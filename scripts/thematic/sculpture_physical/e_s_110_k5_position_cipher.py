#!/usr/bin/env python3
"""
Cipher: physical/coordinate
Family: thematic/sculpture_physical
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-110: K5-Inspired Position-Dependent Cipher Analysis.

PUBLIC FACT: K5 exists (97 chars), shares coded words at same positions
as K4, and uses a "similar but not identical" coding system.

IMPLICATION: The cipher is POSITION-DEPENDENT (same position in K4 and K5
produces different outputs for the same input, but the STRUCTURE is shared).

This constrains the cipher to be:
1. A substitution where each position has a UNIQUE mapping
2. NOT purely transposition-based (positions are preserved)
3. The "coding charts" define position-specific alphabets

Model: CT[i] = T_i(PT[i]) where T_i is a bijection specific to position i.
If T_i = standard_shift(key[i]), this is Vigenère with a 97-length key.
If T_i = mixed_alphabet(key[i]), this is a keyed polyalphabetic cipher.

Key insight: if the cipher is purely substitution (no transposition), then:
- CT[i] directly corresponds to PT[i]
- The 24 cribs give us 24 mapping pairs: T_i(PT[i]) = CT[i]
- We can try to find structure in the 24 (position, PT, CT) triples

Tests:
  P1: Pure position-dependent cipher (NO transposition)
      - Derive key values at 24 crib positions
      - Analyze for: periodicity, polynomial fit, readability
      - What if there IS no transposition? IC = 0.036 would need explanation

  P2: Width-7 transposition + position-dependent cipher
      - For each w7 ordering: derive key at 24 CT positions
      - Key might depend on: CT position, PT position, grid (row,col), or row only

  P3: Tabular substitution where key[i] = f(i) for some function f
      - Test f = floor(i/7) (row-based), f = i mod something, etc.
      - Test f = i XOR something, f = (a*i+b) mod 26

  P4: Running-key Vigenère where the key is PT-derived (autokey)
      - Already tested and eliminated, but verify with new perspective

  P5: Keyword interleaving: key = KRYPTOS repeated but shifted by PALIMPSEST
      - key[i] = (KRYPTOS[i%7] + PALIMPSEST[i%10]) % 26

Output: results/e_s_110_k5_position_cipher.json
"""
import json
import math
import time
import sys
import os
from itertools import permutations
from collections import Counter

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_AT_CRIB = {p: ALPH_IDX[ch] for p, ch in CRIB_DICT.items()}
CRIB_POS = sorted(CRIB_POSITIONS)
N = CT_LEN
WIDTH = 7


def build_columnar_perm(order):
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


print("=" * 70)
print("E-S-110: K5-Inspired Position-Dependent Cipher Analysis")
print("=" * 70)
t0 = time.time()
results = {}

# ==========================================================================
# Phase 1: Pure position-dependent cipher (NO transposition)
# ==========================================================================
print("\n--- Phase 1: Pure position-dependent cipher (direct correspondence) ---")

# Derive Vigenère key at crib positions (direct: CT[i] = PT[i] + key[i])
vig_key = {}
beau_key = {}
for pos in CRIB_POS:
    pt_val = PT_AT_CRIB[pos]
    ct_val = CT_IDX[pos]
    vig_key[pos] = (ct_val - pt_val) % MOD
    beau_key[pos] = (ct_val + pt_val) % MOD

print("  Direct Vigenère keystream at crib positions:")
vig_vals = [vig_key[p] for p in CRIB_POS]
vig_text = ''.join(ALPH[v] for v in vig_vals)
print(f"    pos: {CRIB_POS}")
print(f"    key: {vig_vals}")
print(f"    text: {vig_text}")

print("\n  Direct Beaufort keystream at crib positions:")
beau_vals = [beau_key[p] for p in CRIB_POS]
beau_text = ''.join(ALPH[v] for v in beau_vals)
print(f"    key: {beau_vals}")
print(f"    text: {beau_text}")

# Check periodicity of direct keystream
print("\n  Periodicity check (direct Vig key):")
for p in range(2, 15):
    consistent = 0
    total = 0
    for i in range(len(CRIB_POS)):
        for j in range(i+1, len(CRIB_POS)):
            if (CRIB_POS[j] - CRIB_POS[i]) % p == 0:
                total += 1
                if vig_vals[i] == vig_vals[j]:
                    consistent += 1
    if total > 0:
        print(f"    period {p:2d}: {consistent}/{total} consistent")

# Check if key is a polynomial in position
print("\n  Polynomial fit (direct Vig key):")
# For degree d, need d+1 data points. Use least-squares mod 26.
# Actually, check if key[pos] = a*pos + b mod 26 for all cribs
for a in range(26):
    for b in range(26):
        match = 0
        for pos in CRIB_POS:
            if vig_key[pos] == (a * pos + b) % 26:
                match += 1
        if match >= 10:
            print(f"    linear a={a}, b={b}: {match}/24 matches")

# Quadratic: key[pos] = a*pos^2 + b*pos + c mod 26
best_quad = 0
best_quad_params = (0, 0, 0)
for a in range(26):
    for b in range(26):
        for c in range(26):
            match = 0
            for pos in CRIB_POS:
                if vig_key[pos] == (a * pos * pos + b * pos + c) % 26:
                    match += 1
            if match > best_quad:
                best_quad = match
                best_quad_params = (a, b, c)
            if match >= 10:
                print(f"    quadratic a={a}, b={b}, c={c}: {match}/24 matches")
print(f"    Best quadratic: {best_quad}/24 (params={best_quad_params})")

results["P1"] = {
    "vig_key_text": vig_text,
    "beau_key_text": beau_text,
    "vig_key_values": vig_vals,
    "best_quadratic": best_quad,
}

# ==========================================================================
# Phase 2: Keyword interleaving
# ==========================================================================
print("\n--- Phase 2: Keyword interleaving ---")

# key[i] = (KW1[i % p1] + KW2[i % p2]) % 26 for keyword pairs
KEYWORDS = {
    "KRYPTOS": [ALPH_IDX[c] for c in "KRYPTOS"],
    "PALIMPSEST": [ALPH_IDX[c] for c in "PALIMPSEST"],
    "ABSCISSA": [ALPH_IDX[c] for c in "ABSCISSA"],
    "SHADOW": [ALPH_IDX[c] for c in "SHADOW"],
    "BERLIN": [ALPH_IDX[c] for c in "BERLIN"],
    "SANBORN": [ALPH_IDX[c] for c in "SANBORN"],
    "MEDUSA": [ALPH_IDX[c] for c in "MEDUSA"],
    "LUCIFER": [ALPH_IDX[c] for c in "LUCIFER"],
    "ENIGMA": [ALPH_IDX[c] for c in "ENIGMA"],
    "INVISIBLE": [ALPH_IDX[c] for c in "INVISIBLE"],
}

best_p2, best_p2_config = 0, ""
for kw1_name, kw1 in KEYWORDS.items():
    for kw2_name, kw2 in KEYWORDS.items():
        if kw1_name == kw2_name:
            continue
        for variant in ["vig", "beau"]:
            # Test: key[i] = (kw1[i%p1] + kw2[i%p2]) % 26
            match = 0
            for pos in CRIB_POS:
                expected = (kw1[pos % len(kw1)] + kw2[pos % len(kw2)]) % MOD
                actual = vig_key[pos] if variant == "vig" else beau_key[pos]
                if expected == actual:
                    match += 1
            if match > best_p2:
                best_p2 = match
                best_p2_config = f"{kw1_name}+{kw2_name}({variant})"
            if match >= 10:
                print(f"  MATCH: {kw1_name}+{kw2_name} ({variant}): {match}/24")

            # Also: key[i] = (kw1[i%p1] - kw2[i%p2]) % 26
            match = 0
            for pos in CRIB_POS:
                expected = (kw1[pos % len(kw1)] - kw2[pos % len(kw2)]) % MOD
                actual = vig_key[pos] if variant == "vig" else beau_key[pos]
                if expected == actual:
                    match += 1
            if match > best_p2:
                best_p2 = match
                best_p2_config = f"{kw1_name}-{kw2_name}({variant})"
            if match >= 10:
                print(f"  MATCH: {kw1_name}-{kw2_name} ({variant}): {match}/24")

            # key[i] = kw1[i%p1] XOR kw2[i%p2] (mod 26)
            match = 0
            for pos in CRIB_POS:
                expected = (kw1[pos % len(kw1)] ^ kw2[pos % len(kw2)]) % MOD
                actual = vig_key[pos] if variant == "vig" else beau_key[pos]
                if expected == actual:
                    match += 1
            if match > best_p2:
                best_p2 = match
                best_p2_config = f"{kw1_name}^{kw2_name}({variant})"

print(f"  Best keyword interleaving: {best_p2}/24 ({best_p2_config})")
results["P2_interleave"] = {"best": best_p2, "config": best_p2_config}

# ==========================================================================
# Phase 3: Width-7 transposition + interleaved key
# ==========================================================================
print("\n--- Phase 3: Width-7 transposition + keyword interleaving ---")

best_p3, best_p3_config = 0, ""
n_tested = 0

for order in permutations(range(WIDTH)):
    order = list(order)
    perm = build_columnar_perm(order)
    inv = invert_perm(perm)

    # Derive key at CT positions
    ct_key_vig = {}
    for pt_pos in CRIB_POS:
        ct_pos = inv[pt_pos]
        pt_val = PT_AT_CRIB[pt_pos]
        ct_val = CT_IDX[ct_pos]
        ct_key_vig[ct_pos] = (ct_val - pt_val) % MOD

    # Test interleaved keys (keyed to CT position)
    for kw1_name, kw1 in KEYWORDS.items():
        for kw2_name, kw2 in KEYWORDS.items():
            if kw1_name >= kw2_name:
                continue  # avoid duplicates
            # key[ct_pos] = (kw1[ct_pos%p1] + kw2[ct_pos%p2]) % 26
            match = 0
            for ct_pos, actual_k in ct_key_vig.items():
                expected = (kw1[ct_pos % len(kw1)] + kw2[ct_pos % len(kw2)]) % MOD
                if expected == actual_k:
                    match += 1
            n_tested += 1
            if match > best_p3:
                best_p3 = match
                best_p3_config = f"order={order},{kw1_name}+{kw2_name}"
            if match >= 12:
                print(f"  HIT: order={order}, {kw1_name}+{kw2_name}: {match}/24")

            # Also subtraction
            match = 0
            for ct_pos, actual_k in ct_key_vig.items():
                expected = (kw1[ct_pos % len(kw1)] - kw2[ct_pos % len(kw2)]) % MOD
                if expected == actual_k:
                    match += 1
            n_tested += 1
            if match > best_p3:
                best_p3 = match
                best_p3_config = f"order={order},{kw1_name}-{kw2_name}"
            if match >= 12:
                print(f"  HIT: order={order}, {kw1_name}-{kw2_name}: {match}/24")

    # Also test: key depends on GRID POSITION (row + column keyword)
    # key[ct_pos] = kw_col[original_col] + kw_row[original_row] (mod 26)
    for kw_col_name, kw_col in KEYWORDS.items():
        if len(kw_col) != 7:
            continue
        for kw_row_name, kw_row in KEYWORDS.items():
            match = 0
            for pt_pos in CRIB_POS:
                ct_pos = inv[pt_pos]
                row = pt_pos // WIDTH
                col = pt_pos % WIDTH
                expected = (kw_col[col] + kw_row[row % len(kw_row)]) % MOD
                actual = ct_key_vig[ct_pos]
                if expected == actual:
                    match += 1
            n_tested += 1
            if match > best_p3:
                best_p3 = match
                best_p3_config = f"order={order},col={kw_col_name},row={kw_row_name}"
            if match >= 12:
                print(f"  HIT: order={order}, col={kw_col_name}, row={kw_row_name}: {match}/24")

print(f"  P3: {n_tested} configs tested, best {best_p3}/24 ({best_p3_config})")
results["P3_trans_interleave"] = {"n_tested": n_tested, "best": best_p3, "config": best_p3_config}

# ==========================================================================
# Phase 4: LCM-period keys (period = LCM(p1, p2) can be large but structured)
# ==========================================================================
print("\n--- Phase 4: LCM-period keys (direct, no transposition) ---")

# If key = kw1[i%7] + kw2[i%10], effective period = LCM(7,10) = 70
# With 97 > 70, there are at most 70 unique key values
# But the KEY values at 24 positions must all be consistent

best_p4, best_p4_config = 0, ""
for kw1_name, kw1 in KEYWORDS.items():
    p1 = len(kw1)
    for kw2_name, kw2 in KEYWORDS.items():
        p2 = len(kw2)
        if kw1_name >= kw2_name:
            continue
        # Check consistency with DIRECT (no transposition) Vig key
        for op in ["add", "sub"]:
            match = 0
            for pos in CRIB_POS:
                if op == "add":
                    expected = (kw1[pos % p1] + kw2[pos % p2]) % MOD
                else:
                    expected = (kw1[pos % p1] - kw2[pos % p2]) % MOD
                if expected == vig_key[pos]:
                    match += 1
            if match > best_p4:
                best_p4 = match
                best_p4_config = f"{kw1_name}{'+' if op=='add' else '-'}{kw2_name}"
            if match >= 12:
                print(f"  HIT: {kw1_name} {op} {kw2_name}: {match}/24")

        # Also: multiplication
        match = 0
        for pos in CRIB_POS:
            expected = (kw1[pos % p1] * kw2[pos % p2]) % MOD
            if expected == vig_key[pos]:
                match += 1
        if match > best_p4:
            best_p4 = match
            best_p4_config = f"{kw1_name}*{kw2_name}"

print(f"  P4: best {best_p4}/24 ({best_p4_config})")
results["P4_lcm_period"] = {"best": best_p4, "config": best_p4_config}

# ==========================================================================
# Phase 5: K1-K3 ciphertext as running key
# ==========================================================================
print("\n--- Phase 5: K1-K3 ciphertext as running key (direct) ---")

# K1 CT from the sculpture (first 63 chars of main encoded section)
# These are well-known
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT = "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK?DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH?DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFM"
K3_CT = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW"

for k_name, k_ct in [("K1", K1_CT), ("K2", K2_CT), ("K3", K3_CT)]:
    k_idx = []
    for c in k_ct:
        if c in ALPH_IDX:
            k_idx.append(ALPH_IDX[c])

    if len(k_idx) < N:
        print(f"  {k_name} CT too short ({len(k_idx)} < {N}), skipping")
        continue

    # Test as running key (Vig): key[i] = k_idx[i]
    for variant_name, keyfunc in [("vig", lambda pos: vig_key[pos]),
                                   ("beau", lambda pos: beau_key[pos])]:
        match = 0
        for pos in CRIB_POS:
            if pos < len(k_idx) and k_idx[pos] == keyfunc(pos):
                match += 1
        print(f"  {k_name} CT as direct running key ({variant_name}): {match}/24")

    # Also test with offsets
    best_offset = 0
    best_offset_val = 0
    for offset in range(len(k_idx) - N + 1):
        match = 0
        for pos in CRIB_POS:
            if k_idx[offset + pos] == vig_key[pos]:
                match += 1
        if match > best_offset:
            best_offset = match
            best_offset_val = offset
    print(f"  {k_name} CT best offset: {best_offset}/24 (offset={best_offset_val})")

# Combined K1+K2+K3
combined = []
for k_ct in [K1_CT, K2_CT, K3_CT]:
    for c in k_ct:
        if c in ALPH_IDX:
            combined.append(ALPH_IDX[c])
print(f"\n  Combined K1+K2+K3 CT length: {len(combined)}")
best_comb = 0
for offset in range(min(len(combined) - N + 1, 1000)):
    match = 0
    for pos in CRIB_POS:
        if combined[offset + pos] == vig_key[pos]:
            match += 1
    if match > best_comb:
        best_comb = match
        best_comb_offset = offset
print(f"  Combined best: {best_comb}/24 (offset={best_comb_offset})")

results["P5_k123_ct_key"] = {"best_combined": best_comb}

# ==========================================================================
# Summary
# ==========================================================================
elapsed = time.time() - t0

print(f"\n{'='*70}")
print(f"E-S-110 COMPLETE — elapsed: {elapsed:.1f}s")
print(f"P1 best quadratic: {best_quad}/24")
print(f"P2 best interleave: {best_p2}/24 ({best_p2_config})")
print(f"P3 best trans+interleave: {best_p3}/24")
print(f"P4 best LCM-period: {best_p4}/24")
print(f"{'='*70}")

results["elapsed_seconds"] = elapsed

os.makedirs("results", exist_ok=True)
with open("results/e_s_110_k5_position_cipher.json", "w") as f:
    json.dump({"experiment": "E-S-110",
               "description": "K5-inspired position-dependent cipher analysis",
               "results": results}, f, indent=2, default=str)

print(f"\nResults saved to results/e_s_110_k5_position_cipher.json")
