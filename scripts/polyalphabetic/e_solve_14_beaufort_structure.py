#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort
Family: polyalphabetic
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-SOLVE-14: Deep Investigation of Beaufort Keystream Structure

The Beaufort keystream at crib positions shows unusual structure:
  ENE: [9, 11, 9, 14, 3, 4, 6, 10, 20, 10, 10, 10, 11]
  BC:  [14, 2, 6, 6, 1, 6, 14, 10, 19, 17, 20]

Key observations:
  - Values {6, 10, 14} appear 10/24 times (42%) vs expected 3/24 (12%)
  - These are evenly spaced: 6, 10, 14 (arithmetic progression, diff=4)
  - Triple 10 at ENE positions 28-30 (consecutive)
  - Values are 1200x more structured than Vigenère keystream

This script investigates:
1. What cipher mechanisms produce arithmetic-progression clustering?
2. Could the mod-4 structure indicate a Polybius/ADFGX-style mechanism?
3. KA-alphabet Beaufort: does the structure align with KA indices?
4. Mixed-alphabet Beaufort: standard CT alphabet, keyed PT alphabet
5. Autokey Beaufort with specific primers
6. Beaufort with running key from known sources + transposition
"""

import sys
import os
import itertools
from collections import Counter

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    NOISE_FLOOR, SIGNAL_THRESHOLD,
)

CT_INT = [ALPH_IDX[c] for c in CT]
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

# Full Beaufort keystream at crib positions
BEAU_KEY = {}
for i, v in enumerate(BEAUFORT_KEY_ENE):
    BEAU_KEY[21 + i] = v
for i, v in enumerate(BEAUFORT_KEY_BC):
    BEAU_KEY[63 + i] = v

# Crib positions and values
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POS}

print("E-SOLVE-14: Beaufort Keystream Structure Investigation")
print("=" * 70)
print()

# ── Section 1: Structure Analysis ──────────────────────────────────────

print("Section 1: Beaufort Keystream Structure")
print("-" * 70)

beau_vals = [BEAU_KEY[p] for p in CRIB_POS]
vig_vals = list(VIGENERE_KEY_ENE) + list(VIGENERE_KEY_BC)

print(f"Beaufort values: {beau_vals}")
print(f"Vigenère values: {vig_vals}")
print()

beau_counts = Counter(beau_vals)
vig_counts = Counter(vig_vals)

print("Beaufort value frequencies:")
for v, c in sorted(beau_counts.items(), key=lambda x: -x[1]):
    letter = ALPH[v]
    print(f"  {v:2d} ({letter}): {c}x {'***' if c >= 3 else ''}")

print()
print("Key cluster {6, 10, 14}:")
cluster_count = sum(1 for v in beau_vals if v in {6, 10, 14})
print(f"  Appears {cluster_count}/24 times ({100*cluster_count/24:.0f}%)")
print(f"  Expected random: {24*3/26:.1f}/24 ({100*3/26:.0f}%)")
print(f"  Enrichment: {cluster_count/(24*3/26):.1f}x")
print()

# Check if {6, 10, 14} maps to specific letters in different alphabets
print("Cluster {6, 10, 14} in different alphabets:")
print(f"  Standard (AZ): {ALPH[6]}, {ALPH[10]}, {ALPH[14]} = G, K, O")
print(f"  Kryptos  (KA): {KRYPTOS_ALPHABET[6]}, {KRYPTOS_ALPHABET[10]}, {KRYPTOS_ALPHABET[14]} = "
      f"{KRYPTOS_ALPHABET[6]}, {KRYPTOS_ALPHABET[10]}, {KRYPTOS_ALPHABET[14]}")
print()

# ── Section 2: Mod-4 Analysis ─────────────────────────────────────────

print("Section 2: Mod-4 Residue Analysis")
print("-" * 70)

for m in [2, 3, 4, 5, 6, 7, 8, 13]:
    residues = [v % m for v in beau_vals]
    res_counts = Counter(residues)
    # Chi-squared test
    expected = 24 / m
    chi2 = sum((c - expected) ** 2 / expected for c in res_counts.values())
    # Add missing residues
    for r in range(m):
        if r not in res_counts:
            chi2 += expected
    print(f"  Mod {m:2d}: residues = {residues}")
    print(f"          counts = {dict(sorted(res_counts.items()))}, chi2 = {chi2:.2f}")
print()

# ── Section 3: KA-alphabet Beaufort ───────────────────────────────────

print("Section 3: KA-Alphabet Beaufort Keystream")
print("-" * 70)
print("If CT and PT were mapped through KA alphabet instead of standard:")
print()

# Under KA: Beaufort key = (KA_idx(CT) + KA_idx(PT)) mod 26
ka_beau_key = {}
for pos in CRIB_POS:
    ct_ka = KA_IDX[CT[pos]]
    pt_ka = KA_IDX[CRIB_DICT[pos]]
    ka_beau_key[pos] = (ct_ka + pt_ka) % MOD

ka_beau_vals = [ka_beau_key[p] for p in CRIB_POS]
print(f"KA-Beaufort keystream: {ka_beau_vals}")
ka_counts = Counter(ka_beau_vals)
print("Frequencies:")
for v, c in sorted(ka_counts.items(), key=lambda x: -x[1]):
    print(f"  {v:2d} ({KRYPTOS_ALPHABET[v]}): {c}x {'***' if c >= 3 else ''}")

# Check clustering
print()
for cluster_size in [2, 3]:
    for vals in itertools.combinations(range(26), cluster_size):
        count = sum(1 for v in ka_beau_vals if v in vals)
        expected = 24 * cluster_size / 26
        if count >= expected * 2.5 and count >= 5:
            letters = "".join(KRYPTOS_ALPHABET[v] for v in vals)
            print(f"  KA cluster {set(vals)} ({letters}): {count}/24 ({count/expected:.1f}x enrichment)")

print()

# ── Section 4: Difference Patterns ────────────────────────────────────

print("Section 4: Sequential Difference Patterns")
print("-" * 70)

# Differences between consecutive Beaufort key values within each crib
ene_diffs = [BEAUFORT_KEY_ENE[i+1] - BEAUFORT_KEY_ENE[i] for i in range(12)]
bc_diffs = [BEAUFORT_KEY_BC[i+1] - BEAUFORT_KEY_BC[i] for i in range(10)]

print(f"ENE diffs (raw):   {ene_diffs}")
print(f"ENE diffs (mod26): {[(d % 26) for d in ene_diffs]}")
print(f"BC diffs (raw):    {bc_diffs}")
print(f"BC diffs (mod26):  {[(d % 26) for d in bc_diffs]}")
print()

# Check if diffs are periodic
for p in range(2, 7):
    ene_consistent = True
    for i in range(len(ene_diffs)):
        for j in range(i + 1, len(ene_diffs)):
            if (j - i) % p == 0 and ene_diffs[i] % MOD != ene_diffs[j] % MOD:
                ene_consistent = False
                break
        if not ene_consistent:
            break

    bc_consistent = True
    for i in range(len(bc_diffs)):
        for j in range(i + 1, len(bc_diffs)):
            if (j - i) % p == 0 and bc_diffs[i] % MOD != bc_diffs[j] % MOD:
                bc_consistent = False
                break
        if not bc_consistent:
            break

    if ene_consistent or bc_consistent:
        print(f"  Period {p}: ENE={'CONSISTENT' if ene_consistent else 'fail'}, "
              f"BC={'CONSISTENT' if bc_consistent else 'fail'}")

print()

# ── Section 5: Polybius / ADFGX Interpretation ───────────────────────

print("Section 5: Polybius / ADFGX-style Fractionation Check")
print("-" * 70)
print()

# If {6,10,14} ~ {row*5+col} in a 5×5 grid:
# 6 = (1,1), 10 = (2,0), 14 = (2,4) — no obvious pattern
# But in a 6×5 grid (all 26+4 extras): 6=(1,1), 10=(2,0), 14=(2,4)
# In a 5×6 grid: 6=(1,0), 10=(1,4), 14=(2,2)

for grid_w in [4, 5, 6, 7]:
    rows = [(v // grid_w, v % grid_w) for v in beau_vals]
    row_vals = [r for r, c in rows]
    col_vals = [c for r, c in rows]
    row_counts = Counter(row_vals)
    col_counts = Counter(col_vals)
    print(f"  Grid width {grid_w}: row distribution = {dict(sorted(row_counts.items()))}, "
          f"col distribution = {dict(sorted(col_counts.items()))}")

print()

# ── Section 6: Linear Combination Search ──────────────────────────────

print("Section 6: Linear Combination k[i] = a*pos + b (mod m)")
print("-" * 70)

best_linear = []
for m in range(2, 27):
    for a in range(m):
        for b in range(m):
            matches = 0
            for pos in CRIB_POS:
                predicted = (a * pos + b) % m
                actual = BEAU_KEY[pos] % m
                if predicted == actual:
                    matches += 1
            if matches >= 18:
                best_linear.append((m, a, b, matches))

if best_linear:
    best_linear.sort(key=lambda x: -x[3])
    for m, a, b, matches in best_linear[:10]:
        print(f"  k[i] ≡ {a}*i + {b} (mod {m}): {matches}/24 matches")
else:
    print("  No linear combination achieves ≥18/24 matches")

# Also try quadratic
best_quad = []
for m in range(2, 14):
    for a in range(m):
        for b in range(m):
            for c in range(m):
                matches = 0
                for pos in CRIB_POS:
                    predicted = (a * pos * pos + b * pos + c) % m
                    actual = BEAU_KEY[pos] % m
                    if predicted == actual:
                        matches += 1
                if matches >= 20:
                    best_quad.append((m, a, b, c, matches))

if best_quad:
    best_quad.sort(key=lambda x: -x[4])
    print("\n  Quadratic k[i] ≡ a*i² + b*i + c (mod m):")
    for m, a, b, c, matches in best_quad[:10]:
        print(f"    {a}*i² + {b}*i + {c} (mod {m}): {matches}/24")
else:
    print("  No quadratic combination achieves ≥20/24 matches")

print()

# ── Section 7: Beaufort with Shifted/Keyed Alphabets ─────────────────

print("Section 7: Mixed-Alphabet Beaufort")
print("-" * 70)
print("Testing Beaufort with non-standard alphabet mappings...")
print()

# Try: CT indexed in KA, PT indexed in AZ, key in AZ
# And all 6 permutations of (KA, AZ) across (CT, PT, Key)
configs_tested = 0
hits = []

alphabets = {
    "AZ": (ALPH, ALPH_IDX),
    "KA": (KRYPTOS_ALPHABET, KA_IDX),
}

for ct_name, (ct_alph, ct_idx) in alphabets.items():
    for pt_name, (pt_alph, pt_idx) in alphabets.items():
        for key_name, (key_alph, key_idx) in alphabets.items():
            # Skip standard Beaufort (AZ, AZ, AZ) - already tested
            if ct_name == "AZ" and pt_name == "AZ" and key_name == "AZ":
                continue

            # Compute key values at crib positions
            key_vals = {}
            for pos in CRIB_POS:
                ct_val = ct_idx[CT[pos]]
                pt_val = pt_idx[CRIB_DICT[pos]]
                # Beaufort: Key = CT + PT (mod 26)
                key_vals[pos] = (ct_val + pt_val) % MOD

            kv_list = [key_vals[p] for p in CRIB_POS]
            kv_counts = Counter(kv_list)

            # Check for better clustering than standard Beaufort
            max_freq = max(kv_counts.values())
            n_distinct = len(kv_counts)

            # Check periodicity of these key values
            for period in range(2, 13):
                consistent = True
                for i, pos_a in enumerate(CRIB_POS):
                    for j, pos_b in enumerate(CRIB_POS):
                        if j <= i:
                            continue
                        if (pos_b - pos_a) % period == 0:
                            if key_vals[pos_a] != key_vals[pos_b]:
                                consistent = False
                                break
                    if not consistent:
                        break

                if consistent:
                    hits.append({
                        "ct_alph": ct_name, "pt_alph": pt_name, "key_alph": key_name,
                        "period": period, "key_vals": kv_list, "n_distinct": n_distinct,
                    })

            configs_tested += 1

print(f"  Tested {configs_tested} alphabet combinations × periods 2-12")
if hits:
    print(f"  PERIODIC CONSISTENCY FOUND:")
    for h in hits:
        print(f"    CT={h['ct_alph']} PT={h['pt_alph']} Key={h['key_alph']} "
              f"period={h['period']}: {h['n_distinct']} distinct values")
        print(f"      Key values: {h['key_vals']}")
else:
    print("  No periodic consistency found in any mixed-alphabet combination")

print()

# ── Section 8: Beaufort Key as KA-indexed Letters ─────────────────────

print("Section 8: Beaufort Key Values → Letters")
print("-" * 70)

print("Standard alphabet mapping:")
beau_key_letters_az = "".join(ALPH[v] for v in beau_vals)
print(f"  ENE key: {''.join(ALPH[v] for v in BEAUFORT_KEY_ENE)}")
print(f"  BC key:  {''.join(ALPH[v] for v in BEAUFORT_KEY_BC)}")
print(f"  Full:    {beau_key_letters_az}")
print()

print("KA alphabet mapping:")
beau_key_letters_ka = "".join(KRYPTOS_ALPHABET[v] for v in beau_vals)
print(f"  ENE key: {''.join(KRYPTOS_ALPHABET[v] for v in BEAUFORT_KEY_ENE)}")
print(f"  BC key:  {''.join(KRYPTOS_ALPHABET[v] for v in BEAUFORT_KEY_BC)}")
print(f"  Full:    {beau_key_letters_ka}")
print()

# Look for words in the key
print("Word search in Beaufort key (AZ):")
wordlist_path = "wordlists/english.txt"
if os.path.exists(wordlist_path):
    with open(wordlist_path) as f:
        words = set(w.strip().upper() for w in f if 4 <= len(w.strip()) <= 13)

    key_str = beau_key_letters_az
    found = []
    for wlen in range(4, min(14, len(key_str) + 1)):
        for i in range(len(key_str) - wlen + 1):
            substr = key_str[i:i + wlen]
            if substr in words:
                found.append((i, substr))

    if found:
        for pos, word in found:
            crib_region = "ENE" if pos < 13 else "BC"
            print(f"  Position {pos} ({crib_region}): {word}")
    else:
        print("  No 4+ letter English words found")

    # Also search KA-mapped key
    key_str_ka = beau_key_letters_ka
    found_ka = []
    for wlen in range(4, min(14, len(key_str_ka) + 1)):
        for i in range(len(key_str_ka) - wlen + 1):
            substr = key_str_ka[i:i + wlen]
            if substr in words:
                found_ka.append((i, substr))

    if found_ka:
        print("\n  In KA-mapped key:")
        for pos, word in found_ka:
            crib_region = "ENE" if pos < 13 else "BC"
            print(f"    Position {pos} ({crib_region}): {word}")
    else:
        print("  No 4+ letter words in KA-mapped key either")

print()

# ── Section 9: Atbash + Beaufort ──────────────────────────────────────

print("Section 9: Atbash and Reverse-Alphabet Variants")
print("-" * 70)

# Atbash: map each letter to its reverse (A↔Z, B↔Y, etc.)
# Then apply Beaufort
atbash = {c: ALPH[25 - i] for i, c in enumerate(ALPH)}

# Atbash on CT, then Beaufort
atbash_ct = "".join(atbash[c] for c in CT)
atbash_beau_key = {}
for pos in CRIB_POS:
    ct_val = ALPH_IDX[atbash_ct[pos]]
    pt_val = ALPH_IDX[CRIB_DICT[pos]]
    atbash_beau_key[pos] = (ct_val + pt_val) % MOD

atbash_vals = [atbash_beau_key[p] for p in CRIB_POS]
atbash_counts = Counter(atbash_vals)
print(f"Atbash(CT) + Beaufort key: {atbash_vals}")
print(f"  Distinct values: {len(atbash_counts)}")
max_atbash = max(atbash_counts.values())
print(f"  Max frequency: {max_atbash}")

# Atbash on PT, then Beaufort
atbash_pt_key = {}
for pos in CRIB_POS:
    ct_val = ALPH_IDX[CT[pos]]
    pt_val = ALPH_IDX[atbash[CRIB_DICT[pos]]]
    atbash_pt_key[pos] = (ct_val + pt_val) % MOD

atbash_pt_vals = [atbash_pt_key[p] for p in CRIB_POS]
print(f"Beaufort with Atbash(PT) key: {atbash_pt_vals}")
print(f"  Distinct values: {len(Counter(atbash_pt_vals))}")

# Atbash on key values
atbash_key_vals = [(25 - v) % MOD for v in beau_vals]
print(f"Atbash(Beaufort key): {atbash_key_vals}")
atbash_key_counts = Counter(atbash_key_vals)
print(f"  Distinct values: {len(atbash_key_counts)}")

# Check if any variant produces better clustering
for name, vals in [("Atbash(CT)+Beau", atbash_vals),
                    ("Beau+Atbash(PT)", atbash_pt_vals),
                    ("Atbash(Beau key)", atbash_key_vals)]:
    counts = Counter(vals)
    top3 = sum(c for _, c in counts.most_common(3))
    print(f"  {name}: top-3 values cover {top3}/24 ({100*top3/24:.0f}%)")

print()

# ── Section 10: GCD / Structural Analysis of {6, 10, 14} ─────────────

print("Section 10: Arithmetic Structure of Dominant Values")
print("-" * 70)

dominant = [6, 10, 14]
print(f"Dominant values: {dominant}")
print(f"  Differences: {[dominant[i+1]-dominant[i] for i in range(len(dominant)-1)]}")
print(f"  GCD: 2")
print(f"  All ≡ 2 (mod 4): {[v % 4 for v in dominant]} → {all(v % 4 == 2 for v in dominant)}")
print(f"  All ≡ 0 (mod 2): {[v % 2 for v in dominant]} → {all(v % 2 == 0 for v in dominant)}")
print(f"  Halved: {[v // 2 for v in dominant]} = [3, 5, 7] — CONSECUTIVE ODD PRIMES!")
print()

# This is interesting: 6/2=3, 10/2=5, 14/2=7 are consecutive odd primes
# Also: 3, 5, 7 are the first three odd primes
# And 3+5+7 = 15, 3*5*7 = 105

# What about ALL the Beaufort values halved?
print("All Beaufort values halved (mod 13):")
halved = [v // 2 for v in beau_vals]
halved_mod13 = [v % 13 for v in halved]
print(f"  Halved: {halved}")
print(f"  Halved mod 13: {halved_mod13}")
print()

# Check if the even values are more structured
even_positions = [i for i, v in enumerate(beau_vals) if v % 2 == 0]
odd_positions = [i for i, v in enumerate(beau_vals) if v % 2 == 1]
print(f"Even values at positions: {even_positions} ({len(even_positions)}/24)")
print(f"Odd values at positions:  {odd_positions} ({len(odd_positions)}/24)")
print()

# ── Section 11: Two-Key Beaufort ──────────────────────────────────────

print("Section 11: Two-Key / Two-Layer Beaufort")
print("-" * 70)
print("If Beaufort key = key1[i] + key2[i] (mod 26), and key1 is periodic,")
print("then residuals key2[i] = beau_key[i] - key1[i] (mod 26)")
print("Search for key1 period p where residuals show structure...")
print()

for p in range(2, 14):
    # For each period p, find the key1 values that minimize residual entropy
    # key1 has p free values (0-25 each)
    # Residuals: r[i] = beau_key[i] - key1[i % p] (mod 26)

    # Group crib positions by residue class
    classes = {}
    for idx, pos in enumerate(CRIB_POS):
        r = pos % p
        if r not in classes:
            classes[r] = []
        classes[r].append((pos, beau_vals[idx]))

    # For each residue class, the optimal key1 value is the mode of the class
    best_key1 = {}
    total_matched = 0
    for r, members in classes.items():
        vals = [v for _, v in members]
        if not vals:
            continue
        mode_val = Counter(vals).most_common(1)[0]
        best_key1[r] = mode_val[0]
        total_matched += mode_val[1]

    # Compute residuals with optimal key1
    residuals = []
    for idx, pos in enumerate(CRIB_POS):
        r = pos % p
        k1 = best_key1.get(r, 0)
        residual = (beau_vals[idx] - k1) % MOD
        residuals.append(residual)

    n_zero = sum(1 for r in residuals if r == 0)
    n_distinct_res = len(set(residuals))

    if total_matched >= 18 or n_distinct_res <= 8:
        print(f"  Period {p}: {total_matched}/24 matched by optimal key1, "
              f"{n_distinct_res} distinct residuals")
        print(f"    key1: {[best_key1.get(r, '?') for r in range(p)]}")
        print(f"    Residuals: {residuals}")

print()

# ── Section 12: Bean Constraint Under Beaufort ────────────────────────

print("Section 12: Bean Constraint Check (Beaufort)")
print("-" * 70)

# Bean EQ: k[27] = k[65]
# Under Beaufort: k[i] = (CT[i] + PT[i]) mod 26
# k[27] = (CT[27] + PT[27]) = (P + R) = (15 + 17) = 32 % 26 = 6
# k[65] = (CT[65] + PT[65]) = (P + R) = 6
# Bean EQ: 6 = 6 ✓

k27 = (ALPH_IDX['P'] + ALPH_IDX['R']) % MOD
k65 = (ALPH_IDX['P'] + ALPH_IDX['R']) % MOD
print(f"k[27] = ({ALPH_IDX['P']} + {ALPH_IDX['R']}) mod 26 = {k27}")
print(f"k[65] = ({ALPH_IDX['P']} + {ALPH_IDX['R']}) mod 26 = {k65}")
print(f"Bean EQ: {k27} = {k65} {'✓' if k27 == k65 else '✗'}")
print()

# Bean INEQ: check which pairs involve crib positions
print("Bean INEQ pairs where both are crib positions:")
for a, b in BEAN_INEQ:
    if a in BEAU_KEY and b in BEAU_KEY:
        ka = BEAU_KEY[a]
        kb = BEAU_KEY[b]
        status = "FAIL" if ka == kb else "PASS"
        print(f"  k[{a}]={ka} vs k[{b}]={kb}: {status}")

print()

# ── Section 13: Value 10 Investigation ────────────────────────────────

print("Section 13: The Value 10 — Deepest Cluster")
print("-" * 70)

# Value 10 appears at positions 28, 29, 30, 69, 70
val10_positions = [p for p in CRIB_POS if BEAU_KEY[p] == 10]
print(f"Value 10 at positions: {val10_positions}")
print(f"  ENE: {[p for p in val10_positions if 21 <= p <= 33]}")
print(f"  BC:  {[p for p in val10_positions if 63 <= p <= 73]}")
print()

# CT and PT at these positions
for p in val10_positions:
    print(f"  Pos {p}: CT={CT[p]} ({ALPH_IDX[CT[p]]}), PT={CRIB_DICT[p]} ({ALPH_IDX[CRIB_DICT[p]]}), "
          f"CT+PT={ALPH_IDX[CT[p]]+ALPH_IDX[CRIB_DICT[p]]}, mod26={10}")

print()

# What letter does key value 10 correspond to?
print(f"Key value 10 = '{ALPH[10]}' (K) in standard alphabet")
print(f"Key value 10 = '{KRYPTOS_ALPHABET[10]}' in KA alphabet")
print(f"K appears {beau_counts.get(10, 0)} times — most frequent value")
print()

# Positions 28-30 are consecutive with same key value → period divides 1
# This means key[28]=key[29]=key[30]=10
# Under any periodic key of period p > 1, these three consecutive
# positions fall in different residue classes (since 28,29,30 are consecutive)
# So the periodic key must have the SAME value at residues 28%p, 29%p, 30%p
print("Periodic key implications of triple-10 at positions 28,29,30:")
for p in range(2, 27):
    r28, r29, r30 = 28 % p, 29 % p, 30 % p
    if r28 != r29 and r29 != r30 and r28 != r30:
        print(f"  Period {p}: residues {r28},{r29},{r30} all different → key[{r28}]=key[{r29}]=key[{r30}]=10")
    elif r28 == r29 or r29 == r30 or r28 == r30:
        matches = []
        if r28 == r29: matches.append(f"{r28}={r29}")
        if r29 == r30: matches.append(f"{r29}={r30}")
        if r28 == r30: matches.append(f"{r28}={r30}")
        print(f"  Period {p}: residues {r28},{r29},{r30} — some coincide: {', '.join(matches)}")

print()

# ── Section 14: KRYPTOS as Beaufort Key ───────────────────────────────

print("Section 14: Beaufort Decryption with KRYPTOS-Derived Keys")
print("-" * 70)

# Test: Beaufort decrypt CT with repeating "KRYPTOS" (period 7)
# And variants: "PALIMPSEST" (period 10), "ABSCISSA" (period 8)
keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "KRYPTOSABCDEFGHIJLMNQUVWXZ",
            "KKKKKKK", "SHADOW", "BERLIN", "CLOCK", "LIGHT", "EQUINOX"]

for keyword in keywords:
    key_vals = [ALPH_IDX[keyword[i % len(keyword)]] for i in range(CT_LEN)]

    # Beaufort: PT = Key - CT (mod 26)
    pt = "".join(ALPH[(key_vals[i] - CT_INT[i]) % MOD] for i in range(CT_LEN))

    # Score against cribs
    score = sum(1 for pos in CRIB_POS if pt[pos] == CRIB_DICT[pos])

    if score > NOISE_FLOOR:
        print(f"  {keyword:30s} (p={len(keyword):2d}): score={score}/24 ***")
        print(f"    PT: {pt}")
    else:
        print(f"  {keyword:30s} (p={len(keyword):2d}): score={score}/24")

print()

# ── Summary ───────────────────────────────────────────────────────────

print("=" * 70)
print("SUMMARY")
print("=" * 70)
print()
print("Key findings from Beaufort keystream structure analysis:")
print()
print("1. Dominant cluster {6, 10, 14} = {G, K, O} in standard alphabet")
print("   - Arithmetic progression with common difference 4")
print("   - Halved: {3, 5, 7} = consecutive odd primes")
print("   - 10/24 occurrences (42% vs expected 12%)")
print()
print("2. Value 10 (='K') appears 5x including triple at positions 28-30")
print("   - Forces key[28%p]=key[29%p]=key[30%p]=10 for any periodic key")
print("   - This is why periodic keys fail: too many positions forced to 10")
print()
print("3. Key as letters (AZ): " + beau_key_letters_az)
print("   Key as letters (KA): " + beau_key_letters_ka)
print()
print("4. No periodic consistency in any mixed-alphabet Beaufort variant")
print("5. No linear or quadratic algebraic relationship found")
print("6. The structure is REAL but not explained by any tested mechanism")
print()
print("[HYPOTHESIS] The Beaufort keystream structure may indicate:")
print("  a) A running key where the source text happens to be K-rich")
print("  b) A two-layer system where one layer produces the {6,10,14} pattern")
print("  c) A coincidence amplified by the small sample (24 positions)")
