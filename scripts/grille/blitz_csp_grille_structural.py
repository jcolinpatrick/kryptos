#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
CSP + Structural Analysis: Find the unique permutation by combining
crib constraints with grille structural hypotheses.

KEY INSIGHT: For KRYPTOS/AZ/Vig, σ(29)=64 is FORCED (only Y in K4 at 64).
             Other positions are partly constrained.

This script:
1. Enumerates ALL valid 24-pos partial σ assignments for KRYPTOS/AZ/Vig
2. For each, tries to extend using every "structural formula" for the 73 free pos
3. Also checks: does the valid partial assignment correspond to specific grille holes?
4. Specifically tests: which formulas give σ(i) = pos where K4[pos] = expected_CT[i]
   for ALL 24 crib positions simultaneously?
5. NEW: Tries grille-hole mod-97 subsets (choose 97 from 114 holes)
6. NEW: Tests period-based formulas σ(i) = (a*i + b*GE[i]) mod 97
7. NEW: Prints the STRUCTURE of any valid full permutation found
"""

import json, sys, os, math, itertools
from collections import defaultdict

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
N = 97
assert len(K4) == N and len(GE) == 106

AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}
GE_AZ = [AZ_IDX[c] for c in GE]
GE_KA = [KA_IDX[c] for c in GE]

QG_PATH = 'data/english_quadgrams.json'
with open(QG_PATH) as f: qg = json.load(f)
def qgscore(text): return sum(qg.get(text[i:i+4], -10.) for i in range(len(text)-3))
def qgscore_pc(text): n=len(text)-3; return qgscore(text)/n if n>0 else -10.

def vig_dec(ct, key, alpha=AZ):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[ct[i]] - idx[key[i%len(key)]]) % n] for i in range(len(ct)))
def beau_dec(ct, key, alpha=AZ):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[key[i%len(key)]] - idx[ct[i]]) % n] for i in range(len(ct)))

def apply_perm(text, perm):
    return ''.join(text[perm[i]] for i in range(len(perm)))

def is_valid(perm, n=N):
    return len(perm) == n and len(set(perm)) == n and all(0 <= v < n for v in perm)

RESULTS = []
BEST_SCORE = -9999.
TRIED = set()
COUNT = 0

def try_perm(perm, label):
    global COUNT, BEST_SCORE
    key = tuple(perm)
    if key in TRIED: return
    TRIED.add(key); COUNT += 1
    real_ct = apply_perm(K4, perm)
    for kw in ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN',
               'SCHEIDT','BERLIN','CLOCK','EAST','NORTH','LIGHT']:
        for aname, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(real_ct, kw, alpha)
                sc = qgscore(pt)
                ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    if sc > -550:  # only genuine hits
                        print(f"\n{'!'*70}")
                        print(f"*** GENUINE HIT? *** {label} {kw}/{cname}/{aname}")
                        print(f"  ENE@{ene} BC@{bc} score={sc:.2f}")
                        print(f"  PT: {pt}")
                        print(f"{'!'*70}\n")
                        RESULTS.append({'label': label, 'kw': kw, 'cipher': cname,
                                        'alpha': aname, 'pt': pt, 'score': sc})
                if sc > BEST_SCORE:
                    BEST_SCORE = sc
                    print(f"  [best] {sc:.2f}  {label}  {kw}/{cname}/{aname}  {pt[:40]}")

# ── Parse grille holes ────────────────────────────────────────────────────────

MASK_ROWS = [
    "000000001010100000000010000000001~~",
    "100000000010000001000100110000011~~",
    "000000000000001000000000000000011~~",
    "00000000000000000000100000010011~~",
    "00000001000000001000010000000011~~",
    "000000001000000000000000000000011~",
    "100000000000000000000000000000011",
    "00000000000000000000000100000100~~",
    "0000000000000000000100000001000~~",
    "0000000000000000000000000000100~~",
    "000000001000000000000000000000~~",
    "00000110000000000000000000000100~~",
    "00000000000000100010000000000001~~",
    "00000000000100000000000000001000~~",
    "000110100001000000000000001000010~~",
    "00001010000000000000000001000001~~",
    "001001000010010000000000000100010~~",
    "00000000000100000000010000010001~~",
    "000000000000010001001000000010001~~",
    "00000000000000001001000000000100~~",
    "000000001100000010100100010001001~~",
    "000000000000000100001010100100011~",
    "00000000100000000000100001100001~~~",
    "100000000000000000001000001000010~",
    "10000001000001000000100000000001~~",
    "000010000000000000010000100000011",
    "0000000000000000000100001000000011",
    "00000000000000100000001010000001~~",
]

# 1=HOLE, 0=SOLID
holes = []
for r, row in enumerate(MASK_ROWS):
    for c, ch in enumerate(row):
        if c < 33 and ch == '1':
            holes.append((r, c))

print(f"Total 1-holes (c<33): {len(holes)}")
print(f"Hole positions (first 20): {holes[:20]}")

# ── Crib setup for KRYPTOS/AZ/Vig ────────────────────────────────────────────

CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]

def compute_expected_ct(kw, alpha, ctype):
    idx = {c: i for i, c in enumerate(alpha)}
    exp = {}
    for cstart, ctxt in CRIBS:
        for j, pt_ch in enumerate(ctxt):
            pos = cstart + j
            ki = idx[kw[pos % len(kw)]]
            pi = idx[pt_ch]
            exp[pos] = alpha[(pi + ki) % 26] if ctype == "vig" else alpha[(ki - pi) % 26]
    return exp

def k4_positions_of(char):
    return [i for i, c in enumerate(K4) if c == char]

def backtrack_csp(crib_positions, expected, partial=None, used=None, limit=10000):
    if partial is None: partial = {}
    if used is None: used = set()
    if not crib_positions:
        return [dict(partial)]
    pos = crib_positions[0]
    rest = crib_positions[1:]
    char = expected[pos]
    candidates = [p for p in k4_positions_of(char) if p not in used]
    results = []
    for k4p in candidates:
        partial[pos] = k4p; used.add(k4p)
        results.extend(backtrack_csp(rest, expected, partial, used, limit))
        del partial[pos]; used.remove(k4p)
        if len(results) >= limit: break
    return results

# Compute expected CT for KRYPTOS/AZ/Vig
exp_kryptos_az_vig = compute_expected_ct("KRYPTOS", AZ, "vig")
print("\nExpected real_CT for KRYPTOS/AZ/Vig at crib positions:")
for pos in sorted(exp_kryptos_az_vig.keys()):
    ch = exp_kryptos_az_vig[pos]
    k4_pos = k4_positions_of(ch)
    print(f"  σ({pos:2d}) → K4 has '{ch}' at positions {k4_pos}")

print("\nFORCED ASSIGNMENTS (unique):")
for pos in sorted(exp_kryptos_az_vig.keys()):
    ch = exp_kryptos_az_vig[pos]
    k4_pos = k4_positions_of(ch)
    if len(k4_pos) == 1:
        print(f"  σ({pos}) = {k4_pos[0]} FORCED ('{ch}' only at {k4_pos})")
    elif len(k4_pos) == 2:
        print(f"  σ({pos}) ∈ {k4_pos} (2 choices)")

# ── Approach 1: Grille holes → K4 via mod-97 disambiguation ──────────────────

print("\n" + "="*70)
print("APPROACH 1: GRILLE HOLES → K4 via MODULAR DISAMBIGUATION")
print("="*70)

# For each formula f(r,c), compute values mod 97 for all 114 holes.
# Find which values appear once and which appear multiple times.
# Enumerate valid 97-subsets and test them.

count_app1 = 0

for formula_name, formula in [
    ("r33c", lambda r, c: (r * 33 + c) % N),
    ("r32c", lambda r, c: (r * 32 + c) % N),
    ("r31c", lambda r, c: (r * 31 + c) % N),
    ("r30c", lambda r, c: (r * 30 + c) % N),
    ("r29c", lambda r, c: (r * 29 + c) % N),
    ("r28c", lambda r, c: (r * 28 + c) % N),
    ("cr33", lambda r, c: (c * 33 + r) % N),
    ("cr28", lambda r, c: (c * 28 + r) % N),
    ("rc", lambda r, c: (r + c * N) % N),   # c-major
    ("rxc", lambda r, c: (r * c) % N),
    ("r2c", lambda r, c: (r * r + c) % N),
    ("rc2", lambda r, c: (r + c * c) % N),
    ("rpc", lambda r, c: (r + c) % N),
    ("rmc", lambda r, c: (r - c) % N),
    ("primr", lambda r, c: (97 - r * 33 - c) % N),
]:
    vals = [formula(r, c) for r, c in holes]
    # Check distribution
    val_count = defaultdict(list)
    for i, v in enumerate(vals):
        val_count[v].append(i)

    # Count unique vs doubled
    unique_vals = {v: idxs for v, idxs in val_count.items() if len(idxs) == 1}
    multi_vals = {v: idxs for v, idxs in val_count.items() if len(idxs) > 1}
    missing_vals = [v for v in range(N) if v not in val_count]

    if missing_vals:
        continue  # Not all values 0..96 are covered → can't form 97-subset covering all

    # Number of ambiguous choices = product of len(idxs)-1 for each multi_val
    # But actually we just need to pick ONE hole per value
    ambig_vals = list(multi_vals.keys())
    if len(ambig_vals) > 15:
        continue  # Too many ambiguous values to enumerate

    # Sort holes in reading order for the formula
    # Build permutation: σ(i) = K4 position of i-th hole after sorting
    # Actually we need: sigma[real_ct_position] = K4_position
    # If the holes in reading order define σ, then hole #i maps to real_CT position i

    # First, check if current order (holes sorted by formula value) forms a valid perm
    hole_by_val = {}
    for i, v in enumerate(vals):
        if v not in hole_by_val:
            hole_by_val[v] = i  # first hole with this value
    sigma = [hole_by_val[v] for v in range(N) if v in hole_by_val]
    if len(sigma) == N:
        # sigma[v] = hole_index that maps to real_CT position v
        # actual perm: for real_CT position v, which K4 position? → hole_index
        # But we don't have a direct mapping from hole_index to K4 position
        # WITHOUT knowing K4's layout in the grille
        pass

    total_ambig = 2 ** len(ambig_vals)
    if total_ambig <= 1024:
        # Enumerate all combinations
        for bits in range(total_ambig):
            sigma_hole_indices = {}
            for i, v in enumerate(ambig_vals):
                choice = (bits >> i) & 1
                sigma_hole_indices[v] = multi_vals[v][choice]
            for v, idxs in unique_vals.items():
                sigma_hole_indices[v] = idxs[0]

            # sigma_hole_indices: value (0..96) → hole_index
            # Sorting holes by formula value gives the reading order
            # If reading order i → K4 position i: then sigma(i) = i (identity, boring)
            # More interesting: holes in reading order → sigma(reading_order_rank) = formula_value

            # Reading order of holes: left-to-right, top-to-bottom = default holes list
            # The formula maps hole at position (r,c) to value v = formula(r,c)
            # σ: real_CT position v → K4 position = reading_order_rank_of_hole_with_value_v

            # σ(v) = rank of the chosen hole with value v in reading order (left-to-right, top-to-bottom)
            sigma_perm = [sigma_hole_indices[v] for v in range(N)]
            if is_valid(sigma_perm):
                try_perm(sigma_perm, f"A1_{formula_name}_bits{bits:04b}")
                count_app1 += 1

print(f"Approach 1: {count_app1} perms tested")

# ── Approach 2: Grille holes reading order → K4 position via simple offset ────

print("\n" + "="*70)
print("APPROACH 2: HOLE READING ORDER → K4 POS VIA OFFSET/FORMULA")
print("="*70)

# The 114 holes in reading order: holes[0], holes[1], ..., holes[113]
# We need to select 97 of them and map each to a K4 position.
# Simplest: skip first 9, take holes[9..105] → 97 holes
# Then: σ(i) = i (reading order IS real_CT order, identity perm of selected holes)
# But real_CT positions are 0..96 and K4 positions are 0..96...
# If σ(i) = i, that's the identity and was tried. But with selected holes as source:
# real_CT[i] = K4[holes[i+offset]_linear_position]
# where "linear position" = some mapping from (r,c) to K4 index

count_app2 = 0

# Map hole (r,c) to K4 position using K4's physical arrangement in the sculpture
# K4 is in CT_LINES rows 24-27 (0-indexed), specifically:
#   Row 24 cols 27-30: K4[0..3]   (4 chars: O,B,K,R)
#   Row 25 cols 0-30: K4[4..34]  (31 chars)
#   Row 26 cols 0-30: K4[35..65] (31 chars)
#   Row 27 cols 0-30: K4[66..96] (31 chars)

def hole_to_k4_pos_ctlines(r, c):
    """Map grille hole (r,c) to K4 position using CT_LINES layout.
    Returns -1 if not in K4 region."""
    if r == 24 and 27 <= c <= 30:
        return c - 27  # K4[0..3]
    elif r == 25 and 0 <= c <= 30:
        return 4 + c   # K4[4..34]
    elif r == 26 and 0 <= c <= 30:
        return 35 + c  # K4[35..65]
    elif r == 27 and 0 <= c <= 30:
        return 66 + c  # K4[66..96]
    return -1

k4_holes = [(r, c, hole_to_k4_pos_ctlines(r, c)) for r, c in holes
            if hole_to_k4_pos_ctlines(r, c) >= 0]
print(f"Holes on K4 (CT_LINES layout): {len(k4_holes)}")
print(f"K4 positions covered: {[k for r,c,k in k4_holes]}")

# Only 8 K4 holes! Not enough for a 97-element permutation.
# But let's check these 8 against the crib constraints.
print("\nChecking K4 holes against crib constraints (KRYPTOS/AZ/Vig):")
for r, c, k4_pos in k4_holes:
    if k4_pos in range(N):
        char = K4[k4_pos]
        hole_rank = holes.index((r, c))
        exp_char = exp_kryptos_az_vig.get(hole_rank, None)
        print(f"  Hole #{hole_rank:3d} at ({r:2d},{c:2d}) → K4[{k4_pos:2d}]='{char}'"
              f"  (expected CT at real_CT[{hole_rank}]: {exp_char})")

# ── Approach 3: Period-8 formula σ(i) = (i * k + d) mod 97 ───────────────────

print("\n" + "="*70)
print("APPROACH 3: PERIODIC FORMULA σ(i) = (a*i + b*GE[i%period]) mod 97")
print("="*70)

count_app3 = 0

# With 97 prime and period 8: try all a, b combos with crib constraint satisfaction
# For σ(29) = 64: 64 ≡ a*29 + b*GE[29%8] mod 97
# GE[29%8] = GE[5] = AZ['C'] = 2 (or KA)
GE_AZ_vals = GE_AZ
GE_KA_vals = GE_KA

for period in [7, 8, 10]:
    for alpha_name, ge_vals in [("AZ", GE_AZ_vals), ("KA", GE_KA_vals)]:
        # For each (a, b), check if the formula σ(i) = (a*i + b*ge[i%period]) mod 97
        # satisfies σ(29) = 64 (the forced constraint)
        # ge[29 % period]:
        ge_29 = ge_vals[29 % period]

        for a in range(1, N):
            for b in range(0, N):
                # Check if σ(29) = (a*29 + b*ge_29) % N == 64
                if (a * 29 + b * ge_29) % N != 64:
                    continue
                # Also check σ(21) is an O position
                ge_21 = ge_vals[21 % period]
                sig21 = (a * 21 + b * ge_21) % N
                if K4[sig21] != exp_kryptos_az_vig[21]:
                    continue
                # Check σ(22) is an R position
                ge_22 = ge_vals[22 % period]
                sig22 = (a * 22 + b * ge_22) % N
                if K4[sig22] != exp_kryptos_az_vig[22]:
                    continue
                # Check σ(63) is an L position
                ge_63 = ge_vals[63 % period]
                sig63 = (a * 63 + b * ge_63) % N
                if K4[sig63] != exp_kryptos_az_vig[63]:
                    continue
                # Check σ(73) is a Z position
                ge_73 = ge_vals[73 % period]
                sig73 = (a * 73 + b * ge_73) % N
                if K4[sig73] != exp_kryptos_az_vig[73]:
                    continue

                # Build full permutation and validate
                perm = [(a * i + b * ge_vals[i % period]) % N for i in range(N)]
                if is_valid(perm):
                    # Verify all 24 crib constraints
                    crib_ok = all(K4[perm[pos]] == exp_kryptos_az_vig[pos]
                                  for pos in exp_kryptos_az_vig)
                    if crib_ok:
                        print(f"  STRUCTURAL MATCH! a={a}, b={b}, period={period}, {alpha_name}")
                        try_perm(perm, f"A3_affinegk_a{a}_b{b}_p{period}_{alpha_name}")
                        count_app3 += 1

print(f"Approach 3: {count_app3} perms")

# ── Approach 4: σ(i) = (a*GE[i] + b*i + c*GE[i%8]) mod 97 ───────────────────

print("\n" + "="*70)
print("APPROACH 4: σ(i) = (a*GE[i] + b*GE[i%8] + c*i) mod 97 — SEARCH")
print("="*70)

count_app4 = 0

for alpha_name, ge_vals in [("AZ", GE_AZ_vals), ("KA", GE_KA_vals)]:
    ge97 = ge_vals[:97]
    ge8  = [ge_vals[i % 8] for i in range(N)]

    # Constraint: σ(29) = 64
    # 64 ≡ a*ge97[29] + b*ge8[29] + c*29 mod 97
    # ge97[29] = GE_AZ[29]
    g29 = ge97[29]; g8_29 = ge8[29]

    for a in range(N):
        for b in range(N):
            # Find c such that a*g29 + b*g8_29 + c*29 ≡ 64 (mod 97)
            # c*29 ≡ 64 - a*g29 - b*g8_29 (mod 97)
            rhs = (64 - a * g29 - b * g8_29) % N
            # Find c: c ≡ rhs * 29^{-1} (mod 97)
            inv29 = pow(29, N - 2, N)  # 29^{-1} mod 97 (97 is prime)
            c = (rhs * inv29) % N

            # Quick check for σ(21) = O-position
            sig21 = (a * ge97[21] + b * ge8[21] + c * 21) % N
            if K4[sig21] != exp_kryptos_az_vig[21]: continue
            sig22 = (a * ge97[22] + b * ge8[22] + c * 22) % N
            if K4[sig22] != exp_kryptos_az_vig[22]: continue
            sig25 = (a * ge97[25] + b * ge8[25] + c * 25) % N
            if K4[sig25] != exp_kryptos_az_vig[25]: continue

            perm = [(a * ge97[i] + b * ge8[i] + c * i) % N for i in range(N)]
            if not is_valid(perm): continue

            crib_ok = all(K4[perm[pos]] == exp_kryptos_az_vig[pos]
                         for pos in exp_kryptos_az_vig)
            if crib_ok:
                print(f"  MATCH! a={a}, b={b}, c={c}, {alpha_name}")
                try_perm(perm, f"A4_triple_a{a}b{b}c{c}_{alpha_name}")
                count_app4 += 1

print(f"Approach 4: {count_app4} perms")

# ── Approach 5: Exhaustive CSP with grille-consistent extension ───────────────

print("\n" + "="*70)
print("APPROACH 5: EXHAUSTIVE CSP — VALID PARTIAL ASSIGNMENTS")
print("           Extended via GE-rank for remaining positions")
print("="*70)

count_app5 = 0

# Enumerate valid 24-pos partial assignments for KRYPTOS/AZ/Vig
crib_pos_sorted = sorted(exp_kryptos_az_vig.keys())
assignments = backtrack_csp(crib_pos_sorted, exp_kryptos_az_vig, limit=100)
print(f"  Found {len(assignments)} valid partial assignments (first 100)")

# For the BEST assignments (by GE-rank consistency), try extending
for ae_name, ae_vals in [("AZ", GE_AZ_vals), ("KA", GE_KA_vals)]:
    for assign in assignments[:50]:  # test first 50
        used_k4 = set(assign.values())
        available_k4 = sorted([k for k in range(N) if k not in used_k4],
                               key=lambda k: (ae_vals[k % 106], k))

        non_crib = sorted([i for i in range(N) if i not in assign])
        non_crib_by_ge = sorted(non_crib, key=lambda i: (ae_vals[i % 106], i))

        perm = [0] * N
        for pos, k4p in assign.items():
            perm[pos] = k4p
        for j, real_ct_pos in enumerate(non_crib_by_ge):
            perm[real_ct_pos] = available_k4[j]

        if is_valid(perm):
            real_ct = apply_perm(K4, perm)
            pt = vig_dec(real_ct, "KRYPTOS", AZ)
            sc = qgscore(pt)
            ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
            # These WILL have both cribs by construction, but is surrounding text good?
            non_crib_pt = ''.join(pt[i] for i in range(N) if i not in set(range(21,34)) | set(range(63,74)))
            nc_score = qgscore(non_crib_pt) / max(1, len(non_crib_pt) - 3)
            if nc_score > -7.0:  # surprisingly good non-crib text
                print(f"\n  INTERESTING: nc_score={nc_score:.2f}  {ae_name}")
                print(f"  PT: {pt}")
                RESULTS.append({'label': f"A5_nc_{ae_name}", 'score': sc, 'pt': pt})
            count_app5 += 1

print(f"Approach 5: {count_app5} perms")

# ── Approach 6: Grille-derived period-8 permutation matrix ───────────────────

print("\n" + "="*70)
print("APPROACH 6: PERIOD-8 PERMUTATION MATRIX FROM GRILLE HOLE PATTERN")
print("="*70)

count_app6 = 0

# For each period-8 group (residue class mod 8): positions 0,8,16,...; 1,9,17,...; etc.
# The grille has 28 rows. Map rows to period-8 groups:
# Row r corresponds to group r % 8
# Holes in row r contribute to group r%8

# For group g (g=0..7): collect all hole column positions from rows with r%8==g
group_holes = defaultdict(list)
for r, c in holes:
    group_holes[r % 8].append((r, c))

print("Holes per period-8 group (row r mod 8):")
for g in range(8):
    print(f"  Group {g}: {len(group_holes[g])} holes  cols={sorted(c for r,c in group_holes[g])}")

# Build permutation:
# K4 positions with index ≡ g (mod 8) are assigned to group g
# Within each group, the column order of holes defines the ordering
for sort_by in ["col_asc", "col_desc", "row_then_col"]:
    perm = [0] * N
    ok = True
    for g in range(8):
        k4_group_positions = sorted([i for i in range(N) if i % 8 == g])
        # Sort holes in this group
        if sort_by == "col_asc":
            grp_holes_sorted = sorted(group_holes[g], key=lambda x: (x[1], x[0]))
        elif sort_by == "col_desc":
            grp_holes_sorted = sorted(group_holes[g], key=lambda x: (-x[1], x[0]))
        else:
            grp_holes_sorted = sorted(group_holes[g], key=lambda x: (x[0], x[1]))

        # Take first len(k4_group_positions) holes
        n_needed = len(k4_group_positions)
        if len(grp_holes_sorted) < n_needed:
            ok = False; break

        # Each real_CT position in k4_group_positions maps to:
        # real_CT[k4_group_positions[j]] = K4[grp_holes_sorted[j].col_as_k4_pos?]
        # But we don't have a direct hole → K4 mapping yet.
        # Alternative: the column index of the j-th hole in the group IS the K4 intra-group offset
        # σ(k4_group_positions[j]) = k4_group_positions[col_rank]
        for j, (r, c) in enumerate(grp_holes_sorted[:n_needed]):
            # k4 intra-group position = rank by column within the group
            perm[k4_group_positions[j]] = k4_group_positions[c % len(k4_group_positions)]

    if ok and is_valid(perm):
        try_perm(perm, f"A6_period8_{sort_by}")
        count_app6 += 1

print(f"Approach 6: {count_app6} perms")

# ── Approach 7: Crib-consistency scores for ALL valid CSP assignments ─────────

print("\n" + "="*70)
print("APPROACH 7: RATE ALL 5760 VALID ASSIGNMENTS BY CONSISTENCY METRICS")
print("="*70)

# Run full backtrack to get all assignments
all_assignments = backtrack_csp(crib_pos_sorted, exp_kryptos_az_vig, limit=10000)
print(f"  Total valid assignments (capped at 10000): {len(all_assignments)}")

# Consistency metric: for each assignment, check:
# 1. Are σ(i) values geometrically ordered (e.g., monotone increasing in some sense)?
# 2. Do they match any GE-based formula?

# Score each assignment by how "structured" the σ values are
def grille_consistency(assign):
    """Score a partial assignment by geometric consistency.
    Higher = more consistent with grille reading order."""
    crib_pos_ordered = sorted(assign.keys())
    k4_vals = [assign[p] for p in crib_pos_ordered]

    # Check if k4_vals are monotone in reading order
    n_asc = sum(1 for i in range(len(k4_vals)-1) if k4_vals[i] < k4_vals[i+1])
    n_desc = sum(1 for i in range(len(k4_vals)-1) if k4_vals[i] > k4_vals[i+1])

    # Check period-8 structure
    period8_score = 0
    for j, pos in enumerate(crib_pos_ordered):
        expected_group = pos % 8
        actual_group = assign[pos] % 8
        if expected_group == actual_group:
            period8_score += 1

    # Check if k4 values are near GE-rank order
    ge_ranks = sorted(range(N), key=lambda i: (GE_AZ[i], i))
    ge_rank_inv = [0]*N
    for rank, pos in enumerate(ge_ranks): ge_rank_inv[pos] = rank

    rank_monotone = 0
    for j in range(len(crib_pos_ordered)-1):
        pos1, pos2 = crib_pos_ordered[j], crib_pos_ordered[j+1]
        rank1 = ge_rank_inv[assign[pos1]] if assign[pos1] < N else N
        rank2 = ge_rank_inv[assign[pos2]] if assign[pos2] < N else N
        if rank1 < rank2: rank_monotone += 1

    return {
        'n_asc': n_asc, 'n_desc': n_desc,
        'period8': period8_score, 'rank_mono': rank_monotone,
    }

# Analyze consistency of all assignments
scores = [grille_consistency(a) for a in all_assignments]
max_p8 = max(s['period8'] for s in scores)
max_rm = max(s['rank_mono'] for s in scores)
max_asc = max(s['n_asc'] for s in scores)
print(f"  Max period8 consistency: {max_p8}/24")
print(f"  Max rank-monotone: {max_rm}/23")
print(f"  Max ascending: {max_asc}/23")

# Find assignment with best period8 consistency
best_p8_assigns = [(all_assignments[i], scores[i]) for i in range(len(all_assignments))
                    if scores[i]['period8'] == max_p8]
print(f"\n  {len(best_p8_assigns)} assignments with max period8={max_p8}")

# For the best period8 assignments, try extending
if best_p8_assigns:
    for ae_name, ae_vals in [("AZ", GE_AZ_vals)]:
        for assign, sc_info in best_p8_assigns[:5]:
            used_k4 = set(assign.values())
            available = sorted([k for k in range(N) if k not in used_k4],
                               key=lambda k: (k % 8, ae_vals[k % 106], k))
            nc = sorted([i for i in range(N) if i not in assign])
            # Sort non-crib positions by their period-8 group then GE rank
            nc_by_group = sorted(nc, key=lambda i: (i % 8, ae_vals[i % 106], i))

            perm = [0] * N
            for pos, k4p in assign.items():
                perm[pos] = k4p
            for j, rcpos in enumerate(nc_by_group):
                perm[rcpos] = available[j] if j < len(available) else 0

            if is_valid(perm):
                real_ct = apply_perm(K4, perm)
                pt = vig_dec(real_ct, "KRYPTOS", AZ)
                sc = qgscore_pc(pt)
                if sc > BEST_SCORE:
                    BEST_SCORE = sc
                    print(f"  [A7 best] sc={sc:.4f} p8={sc_info['period8']}  {pt[:50]}")
                count_app6 += 1

print(f"Approach 7: {count_app6} total additional perms")

# ── SUMMARY ───────────────────────────────────────────────────────────────────

print("\n" + "="*70)
print("FINAL SUMMARY")
print(f"  Total permutations tested: {COUNT}")
print(f"  Genuine crib hits (score > -550): {len(RESULTS)}")
print(f"  Best quadgram score: {BEST_SCORE:.4f}")
print("="*70)

if RESULTS:
    print("\n🎉 RESULTS:")
    for r in RESULTS:
        print(f"  [{r['label']}] score={r['score']:.2f}  {r['pt']}")
else:
    print("No genuine crib hits. All approaches gave noise-level results.")

os.makedirs("results/blitz_csp_structural", exist_ok=True)
with open("results/blitz_csp_structural/results.json", "w") as f:
    json.dump({'total': COUNT, 'hits': RESULTS, 'best_score': BEST_SCORE}, f, indent=2)
print("Saved results.")
